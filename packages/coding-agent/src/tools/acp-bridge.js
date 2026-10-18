/**
 * Shared ACP client bridge routing for file-write sites.
 *
 * When an ACP client (e.g. Zed) advertises the `fs.writeTextFile` capability,
 * all write-mode tools must route through it so the editor's open buffer is
 * updated immediately. Internal artifacts ('/Users/theo/.omp/agent/sessions/-Projects-oh-my-pi/2026-06-10T09-11-41-506Z_019eb0cd-3ec2-7000-92aa-1b82aa4d78f0/local' plan files, other scheme
 * URLs) are always written directly to disk — those are OMP-owned and should
 * never be pushed into the editor.
 */
import { InternalUrlRouter } from "../internal-urls";
import { FileChangeType, notifyWorkspaceWatchedFiles } from "../lsp/client";
import { invalidateFsScanAfterWrite } from "./fs-cache-invalidation";
import { resolvePlanPath, targetsLocalSandbox } from "./plan-mode-guard";
import { ToolError } from "@rva/tui/tools/tool-errors";
/**
 * Return `true` when an ACP client bridge write is appropriate for this path.
 *
 * Returns `false` for internal-URL paths (e.g. `'/Users/theo/.omp/agent/sessions/-Projects-oh-my-pi/2026-06-10T09-11-41-506Z_019eb0cd-3ec2-7000-92aa-1b82aa4d78f0/local/PLAN.md'`) and for the
 * active plan file while plan mode is enabled — both are OMP-internal artifacts
 * that must stay off the editor's buffer.
 */
export async function shouldRouteWriteThroughBridge(session, requestedPath, absolutePath) {
    const router = InternalUrlRouter.instance();
    if (router.canHandle(requestedPath))
        return false;
    // OMP-owned session artifacts (plan files, scratch notes) must stay off the
    // editor buffer even when addressed by their absolute sandbox path — e.g.
    // after tag-based path recovery rebinds a bare `plan.md#tag` onto the
    // `local://` artifact, `requestedPath` is the absolute path, not the URL.
    if (await targetsLocalSandbox(session, absolutePath))
        return false;
    const state = session.getPlanModeState?.();
    if (!state?.enabled || !router.canHandle(state.planFilePath))
        return true;
    return absolutePath !== (await resolvePlanPath(session, state.planFilePath));
}
/**
 * Try to route a file write through the ACP client bridge.
 *
 * Performs the full guard check, bridge call (wrapped in {@link ToolError}),
 * a post-write read-back to detect client-side transformation (e.g.
 * format-on-save), FS-scan cache invalidation, and session mutation-version
 * bump.
 *
 * Returns `undefined` when the bridge is unavailable or the path should not
 * be routed through it — the caller must fall back to the writethrough path.
 * Returns a {@link BridgeWriteResult} when the bridge was used; callers MUST
 * use `result.text` (not the content they requested) for any snapshot, hash,
 * or tag derived from this write.
 */
export async function routeWriteThroughBridge(session, requestedPath, absolutePath, content, signal) {
    const bridge = session.getClientBridge?.();
    if (!bridge?.capabilities.writeTextFile || !bridge.writeTextFile)
        return undefined;
    if (!(await shouldRouteWriteThroughBridge(session, requestedPath, absolutePath)))
        return undefined;
    const changeType = (await Bun.file(absolutePath).exists()) ? FileChangeType.Changed : FileChangeType.Created;
    // The ACP protocol has no cancellation for fs writes; the most we can do is
    // refuse to start one after the tool was aborted. Racing the promise would
    // report failure while the editor still applies the write.
    signal?.throwIfAborted();
    try {
        await bridge.writeTextFile({ path: absolutePath, content });
    }
    catch (error) {
        throw new ToolError(error instanceof Error ? error.message : String(error));
    }
    if (session.enableLsp ?? true) {
        await notifyWorkspaceWatchedFiles(session.cwd, [{ filePath: absolutePath, type: changeType }], signal);
    }
    invalidateFsScanAfterWrite(absolutePath);
    session.bumpFileMutationVersion?.(absolutePath);
    // Best-effort verification: the client already flushed the write (that's
    // the whole point of `fs/write_text_file`), so the file on disk reflects
    // whatever the client actually persisted, formatter and all. If the
    // read-back itself fails, fall back to trusting `content` rather than
    // failing an otherwise-successful write. This is a best-effort signal,
    // not a guarantee: ACP defines no ordering between a client acking the
    // write and its own async format-on-save settling, so a client that acks
    // before its formatter runs will look verbatim here. That degrades to
    // the pre-fix behavior for THIS write, but never corrupts state: the
    // next `readText` still observes whatever the client eventually settles
    // on, and a real desync there surfaces as an honest stale-tag error
    // instead of a silently wrong tag.
    let actualText = content;
    try {
        actualText = await Bun.file(absolutePath).text();
    }
    catch {
        // Unreadable right after a reported-successful write; nothing more we
        // can verify here.
    }
    return { text: actualText, driftedFromRequest: actualText !== content };
}
