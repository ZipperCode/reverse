import { prompt, Snowflake } from "@rva/utils";
import btwUserPrompt from "../prompts/system/btw-user.md" with { type: "text" };
import { getBtwTurns } from "./btw-history";
/** Start a new topic, or append a follow-up turn to `previous`. */
export function beginBtwTurn(question, leafId, previous) {
    const now = Date.now();
    const turn = { question, answer: "", status: "running", createdAt: now, updatedAt: now };
    const record = previous
        ? { ...previous, followUps: [...(previous.followUps ?? []), turn] }
        : { ...turn, id: Snowflake.next(), leafId };
    const history = previous ? getBtwTurns(previous) : undefined;
    // A cancelled/failed transport may still be unwinding. Start a fresh
    // lineage after that boundary, while successful follow-ups share one.
    const transportEpoch = (history?.findLastIndex(item => item.status !== "complete") ?? -1) + 1;
    return { record, history, conversationKey: `btw:${record.id}:${transportEpoch}` };
}
/** Patch the record's latest turn (the last follow-up, else the record itself). */
export function patchLatestBtwTurn(record, patch) {
    const followUps = record.followUps;
    if (followUps?.length) {
        return { ...record, followUps: [...followUps.slice(0, -1), { ...followUps[followUps.length - 1], ...patch }] };
    }
    return { ...record, ...patch };
}
/**
 * Run one `/btw` question as an ephemeral turn; earlier turns of its topic are replayed as context.
 * Not `async`: returns the session's own promise so callers settle on the same tick as the turn.
 */
export function runBtwTurn(session, args) {
    const model = session.model;
    if (!model)
        throw new Error("No active model available for /btw.");
    const history = [];
    for (const turn of args.history ?? []) {
        history.push({
            role: "user",
            content: [{ type: "text", text: prompt.render(btwUserPrompt, { question: turn.question }) }],
            attribution: "agent",
            timestamp: turn.createdAt,
        });
        if (!turn.answer)
            continue;
        // Saved BTW history contains visible text, not provider-native reasoning
        // or replay signatures. These are context messages, not new billed turns.
        history.push({
            role: "assistant",
            content: [{ type: "text", text: turn.answer }],
            api: model.api,
            provider: model.provider,
            model: model.id,
            usage: {
                input: 0,
                output: 0,
                cacheRead: 0,
                cacheWrite: 0,
                totalTokens: 0,
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
            },
            stopReason: "stop",
            timestamp: turn.updatedAt,
        });
    }
    return session.runEphemeralTurn({
        promptText: prompt.render(btwUserPrompt, { question: args.question }),
        history,
        conversationKey: args.conversationKey,
        // /btw answers are read in full and saved to history: keep the
        // repeated-line collapse, but not the 4 KiB cap meant for one-liners.
        replyMaxBytes: Number.POSITIVE_INFINITY,
        onTextDelta: args.onTextDelta,
        signal: args.signal,
    });
}
