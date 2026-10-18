/**
 * Signal-safe session teardown: persists the in-progress editor draft, then
 * disposes the session (which emits `session_shutdown`, cancels the session's
 * background async jobs, and closes the session manager). Shared by the TUI
 * Ctrl+C/Ctrl+D/`/exit` keypress path in `InteractiveMode.shutdown()` and by
 * the postmortem `SIGINT`/`SIGTERM`/`SIGHUP`/`uncaughtException` handlers so a
 * real kernel signal executes the exact same teardown as a keypress exit.
 *
 * Extracted (rather than inlined into `InteractiveMode`) so the callback body
 * is directly unit-testable without instantiating the full TUI stack.
 */
import { logger } from "@rva/utils";
/**
 * Build a promise-memoized teardown function. The first call snapshots the
 * draft text, marks the session disposing synchronously, runs `saveDraft`
 * (draft-loss protection for `--resume`), then `disposeSession`; subsequent
 * calls await the same settled promise, so the keypress
 * `InteractiveMode.shutdown()` path and the postmortem signal callback cannot
 * double-emit `session_shutdown`, double-dispose the session's async-job
 * manager, or race each other.
 *
 * The postmortem callback forwards its `Reason` so the persisted
 * `session_exit` diagnostic carries the real trigger (`sigterm`, `sighup`,
 * `uncaught_exception`, …) instead of the generic `"dispose"` that plain
 * programmatic disposal records. First call wins: a signal arriving after a
 * keypress-initiated teardown awaits the in-flight promise and its reason is
 * dropped — by then the exit entry is already being written as a normal exit.
 *
 * `saveDraft` failures are logged but never abort the disposal chain — a
 * draft-write error must not leak background bash/task jobs or skip the
 * extension `session_shutdown` event.
 */
export function createSessionTeardown(deps) {
    let pending;
    const run = async (reason) => {
        const draftText = deps.getDraftText();
        deps.beginDispose();
        try {
            await deps.saveDraft(draftText);
        }
        catch (err) {
            logger.warn("Failed to save session draft during teardown", { error: String(err) });
        }
        await deps.disposeSession(reason);
    };
    return (reason) => {
        if (!pending)
            pending = run(reason);
        return pending;
    };
}
