export const MEMORY_RECALL_ENTRY_TYPE = "memory_recall";
/**
 * Hidden message reporting what changed in a reused recall's memories. Its details
 * ({@link MemoryRecallChangesDetails}) carry the memories still current, so the
 * report and its bookkeeping reach the transcript together, only once delivered.
 */
export const MEMORY_RECALL_CHANGES_MESSAGE_TYPE = "memory-recall-changes";
function isRecalledMemories(value) {
    return (Array.isArray(value) &&
        value.every(memory => typeof memory === "object" &&
            memory !== null &&
            "id" in memory &&
            typeof memory.id === "string" &&
            "text" in memory &&
            typeof memory.text === "string" &&
            (!("cut" in memory) || memory.cut === true)));
}
function isMemoryRecallEntryData(data) {
    return (typeof data === "object" &&
        data !== null &&
        "version" in data &&
        data.version === 1 &&
        "scope" in data &&
        typeof data.scope === "string" &&
        "text" in data &&
        typeof data.text === "string" &&
        "memories" in data &&
        isRecalledMemories(data.memories));
}
function isMemoryRecallChangesDetails(details) {
    return (typeof details === "object" &&
        details !== null &&
        "scope" in details &&
        typeof details.scope === "string" &&
        "memories" in details &&
        isRecalledMemories(details.memories));
}
/**
 * The latest recall for `scope` on the current branch that a turn followed, with the
 * memories still current per the latest change report delivered after it. Undefined
 * when the branch needs a fresh recall: none was recorded since the last context
 * reset, or no turn followed one (a branch that edits the first prompt asks a
 * different question).
 */
export function findPersistedRecall(sessionManager, scope) {
    const entries = sessionManager.getBranch();
    let turnFollowed = false;
    let reported;
    for (let index = entries.length - 1; index >= 0; index--) {
        const entry = entries[index];
        if (entry.type === "reset_boundary")
            return undefined;
        if (entry.type === "message") {
            turnFollowed = true;
        }
        else if (entry.type === "custom_message" && entry.customType === MEMORY_RECALL_CHANGES_MESSAGE_TYPE) {
            if (reported === undefined && isMemoryRecallChangesDetails(entry.details) && entry.details.scope === scope) {
                reported = entry.details.memories;
            }
        }
        else if (turnFollowed &&
            entry.type === "custom" &&
            entry.customType === MEMORY_RECALL_ENTRY_TYPE &&
            isMemoryRecallEntryData(entry.data) &&
            entry.data.scope === scope) {
            return { text: entry.data.text, memories: reported ?? entry.data.memories };
        }
    }
    return undefined;
}
/** Records a fresh recall. */
export function persistRecall(sessionManager, scope, recall) {
    sessionManager.appendCustomEntry(MEMORY_RECALL_ENTRY_TYPE, {
        version: 1,
        scope,
        text: recall.text,
        memories: recall.memories,
    });
}
