import { formatSessionHistoryMarkdown } from "../session/session-history-format";
/** The advisor's tool-I/O redaction, sharing one batch's regex secret values. */
export function advisorToolIOTransform(obfuscator, sharedRegexSecretValues) {
    const transform = text => obfuscator.obfuscate(text, sharedRegexSecretValues);
    if (obfuscator.redactionPrefixEnd) {
        transform.redactionPrefixEnd = (text, limit) => obfuscator.redactionPrefixEnd(text, limit, sharedRegexSecretValues);
    }
    return transform;
}
/** Render options shared by the advisor single-block and multi-message paths. */
export const ADVISOR_RENDER_OPTIONS = {
    includeToolIntent: true,
    watchedRoles: true,
    expandPrimaryContext: true,
    expandEditDiffs: true,
    expandToolIO: true,
};
export function renderAdvisorDeltaChunks(delta, opts) {
    if (delta.length === 0)
        return null;
    const resultsByCallId = new Map();
    for (const msg of delta) {
        if (msg.role === "toolResult")
            resultsByCallId.set(msg.toolCallId, msg);
    }
    const consumed = new Set();
    const watchedRoleState = { lastLabel: undefined };
    const renderChunk = (chunk) => formatSessionHistoryMarkdown(chunk, {
        ...ADVISOR_RENDER_OPTIONS,
        includeThinking: opts.includeThinking,
        toolResultIndex: resultsByCallId,
        consumedToolCallIds: consumed,
        watchedRoleState,
        transformExpandedToolIO: opts.obfuscator
            ? advisorToolIOTransform(opts.obfuscator, opts.advisorRegexSecretValues)
            : undefined,
    });
    const heading = "### Session update";
    // Concrete local chunk type: content blocks are minted here, so the WIP
    // marker append below is a plain field access (no double-cast).
    const chunks = [];
    for (let i = 0; i < delta.length; i++) {
        const text = renderChunk([delta[i]]);
        if (!text.trim())
            continue;
        chunks.push({ role: "user", content: [{ type: "text", text }], timestamp: Date.now() });
    }
    if (chunks.length === 0)
        return null;
    if (opts.obfuscator) {
        const fullText = chunks.map(chunk => chunk.content[0].text).join("\n");
        const individuallyObfuscated = chunks.map(chunk => opts.obfuscator.obfuscate(chunk.content[0].text, opts.advisorRegexSecretValues));
        if (opts.obfuscator.obfuscate(fullText, opts.advisorRegexSecretValues) !== individuallyObfuscated.join("\n")) {
            return null;
        }
        for (let i = 0; i < chunks.length; i++)
            chunks[i].content[0].text = individuallyObfuscated[i];
    }
    chunks[0].content[0].text = `${heading}\n\n${chunks[0].content[0].text}`;
    if (opts.wip) {
        const last = chunks[chunks.length - 1];
        last.content[0].text += `\n\n---\n\n[in progress — more steps follow]`;
    }
    return chunks;
}
