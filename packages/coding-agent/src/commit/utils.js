export function extractToolCall(message, name) {
    return message.content.find(content => content.type === "toolCall" && content.name === name);
}
export function extractTextContent(message) {
    return message.content
        .filter(content => content.type === "text")
        .map(content => content.text)
        .join("")
        .trim();
}
export function parseJsonPayload(text) {
    const trimmed = text.trim();
    if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
        return JSON.parse(trimmed);
    }
    const match = trimmed.match(/\{[\s\S]*\}/);
    if (!match) {
        throw new Error("No JSON payload found in response");
    }
    return JSON.parse(match[0]);
}
export function normalizeAnalysis(parsed) {
    return {
        type: parsed.type,
        scope: parsed.scope?.trim() || null,
        details: parsed.details.map(detail => ({
            text: detail.text.trim(),
            changelogCategory: detail.user_visible ? detail.changelog_category : undefined,
            userVisible: detail.user_visible ?? false,
        })),
        issueRefs: parsed.issue_refs ?? [],
    };
}
export function normalizeDetails(details) {
    return details.map(detail => ({
        text: detail.text.trim(),
        changelogCategory: detail.user_visible ? detail.changelog_category : undefined,
        userVisible: detail.user_visible ?? false,
    }));
}
/** Render numstat entries as `git diff --stat`-style text. */
export function renderStat(entries) {
    if (entries.length === 0)
        return "";
    let insertions = 0;
    let deletions = 0;
    const lines = entries.map(entry => {
        const added = entry.added ?? 0;
        const removed = entry.removed ?? 0;
        insertions += added;
        deletions += removed;
        return ` ${entry.path} | ${added + removed} ${"+".repeat(Math.min(added, 40))}${"-".repeat(Math.min(removed, 40))}`;
    });
    lines.push(` ${entries.length} file${entries.length === 1 ? "" : "s"} changed, ${insertions} insertion${insertions === 1 ? "" : "s"}(+), ${deletions} deletion${deletions === 1 ? "" : "s"}(-)`);
    return `${lines.join("\n")}\n`;
}
