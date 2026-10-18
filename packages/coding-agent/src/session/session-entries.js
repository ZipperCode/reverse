export const CURRENT_SESSION_VERSION = 3;
export const SESSION_TITLE_SLOT_BYTES = 256;
export const SESSION_TITLE_SLOT_ENTRY_TYPE = "title";
export const TITLE_CHANGE_ENTRY_TYPE = "title_change";
export const EPHEMERAL_MODEL_CHANGE_ROLE = "fallback";
/** Leaf selected when replaying one entry; late usage restores its captured active leaf. */
export function sessionEntryLeafId(entry) {
    return entry.type === "model_usage" && entry.activeLeafId !== undefined ? entry.activeLeafId : entry.id;
}
/** Newest entry that selects itself on replay; skips late-usage markers. */
export function lastSelfSelectedLeafId(entries) {
    for (let index = entries.length - 1; index >= 0; index--) {
        const entry = entries[index];
        if (sessionEntryLeafId(entry) === entry.id)
            return entry.id;
    }
    return null;
}
/**
 * Active leaf after replaying entries in file order; an empty or cleared session has no leaf.
 * A captured leaf that no longer exists (rollback, rewrite) falls back to the newest self-selecting entry.
 */
export function resolveSessionLeafId(entries) {
    const last = entries.at(-1);
    if (!last)
        return null;
    const leafId = sessionEntryLeafId(last);
    if (leafId === null || leafId === last.id || entries.some(entry => entry.id === leafId))
        return leafId;
    return lastSelfSelectedLeafId(entries);
}
/**
 * True when a raw JSONL line is a complete `message` record carrying an
 * assistant role. Parses the line, so valid JSON whitespace (`"role" :
 * "assistant"`, tabs, newlines-in-string excluded by line framing) classifies
 * correctly — unlike substring checks for exact serializations. Malformed or
 * partial lines (mid-write truncation) return false.
 */
export function isAssistantMessageLine(line) {
    if (line.length === 0 || line.charCodeAt(0) !== 123)
        return false;
    let record;
    try {
        record = JSON.parse(line);
    }
    catch {
        return false;
    }
    return record.type === "message" && record.message?.role === "assistant";
}
