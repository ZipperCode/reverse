import { Snowflake } from "@rva/utils";
import { CURRENT_SESSION_VERSION } from "./session-entries";
/** Generate a unique short ID (8 hex chars, collision-checked) */
export function generateId(byId) {
    for (let i = 0; i < 100; i++) {
        const id = crypto.randomUUID().slice(-8);
        if (!byId.has(id))
            return id;
    }
    return Snowflake.next(); // fallback to full snowflake id
}
/** Migrate v1 → v2: add id/parentId tree structure. Mutates in place. */
function migrateV1ToV2(entries) {
    const ids = new Set();
    let prevId = null;
    for (const entry of entries) {
        if (entry.type === "session") {
            entry.version = 2;
            continue;
        }
        entry.id = generateId(ids);
        entry.parentId = prevId;
        prevId = entry.id;
        // Convert firstKeptEntryIndex to firstKeptEntryId for compaction
        if (entry.type === "compaction") {
            const comp = entry;
            if (typeof comp.firstKeptEntryIndex === "number") {
                const targetEntry = entries[comp.firstKeptEntryIndex];
                if (targetEntry && targetEntry.type !== "session") {
                    comp.firstKeptEntryId = targetEntry.id;
                }
                delete comp.firstKeptEntryIndex;
            }
        }
    }
}
/** Migrate v2 → v3: rename hookMessage role to custom. Mutates in place. */
function migrateV2ToV3(entries) {
    for (const entry of entries) {
        if (entry.type === "session") {
            entry.version = 3;
            continue;
        }
        if (entry.type === "message") {
            const msg = entry.message;
            if (msg.role === "hookMessage") {
                entry.message.role = "custom";
            }
        }
    }
}
/**
 * Run all necessary migrations to bring entries to current version.
 * Mutates entries in place. Returns true if any migration was applied.
 */
export function migrateToCurrentVersion(entries) {
    const header = entries.find(e => e.type === "session");
    const version = header?.version ?? 1;
    if (version >= CURRENT_SESSION_VERSION)
        return false;
    if (version < 2)
        migrateV1ToV2(entries);
    if (version < 3)
        migrateV2ToV3(entries);
    return true;
}
/** Exported for testing */
export function migrateSessionEntries(entries) {
    migrateToCurrentVersion(entries);
}
