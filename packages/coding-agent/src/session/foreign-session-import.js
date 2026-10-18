import { directoryExists } from "@rva/utils";
import { ClaudeSessionStore } from "./claude-session-store";
import { CodexSessionStore } from "./codex-session-store";
/** Construct the importer for a supported foreign session source. */
export function createForeignSessionStore(source) {
    return source === "claude" ? new ClaudeSessionStore() : new CodexSessionStore();
}
/** Display name for a supported foreign session source. */
export function foreignSessionSourceName(source) {
    return source === "claude" ? "Claude" : "Codex";
}
/** Convert lightweight foreign metadata for the existing session picker. */
export function foreignSessionInfoToSessionInfo(info) {
    const firstMessage = info.firstMessage ?? "(no messages)";
    return {
        path: info.path,
        id: info.id,
        cwd: info.cwd,
        title: info.title,
        created: info.created,
        modified: info.modified,
        messageCount: info.messageCount ?? 0,
        size: 0,
        firstMessage,
        allMessagesText: firstMessage,
    };
}
/** Import and persist one foreign session under a fresh OMP session identity. */
export async function persistForeignSession(store, info, options) {
    const imported = await store.load(info);
    imported.appendCustomEntry("foreign_session_import", {
        source: info.source,
        sourceId: info.id,
        sourcePath: info.path,
        sourceCwd: info.cwd,
    });
    if (options?.fallbackCwd && !(await directoryExists(imported.getCwd()))) {
        await imported.moveTo(options.fallbackCwd);
    }
    return await imported.persistCopy(options);
}
