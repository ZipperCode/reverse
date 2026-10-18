/** Synthetic status op emitted when a bridge call leaves the cell runtime. */
export const EVAL_TIMEOUT_PAUSE_OP = "timeout-pause";
/** Synthetic status op emitted when a bridge call returns control to the runtime. */
export const EVAL_TIMEOUT_RESUME_OP = "timeout-resume";
/** Whether a status event is pure eval-timeout control and should not render. */
export function isEvalTimeoutControlEvent(event) {
    return event.op === EVAL_TIMEOUT_PAUSE_OP || event.op === EVAL_TIMEOUT_RESUME_OP;
}
/**
 * Run {@link operation} while suspending the eval watchdog through
 * {@link emitStatus}. A no-op wrapper when no status sink is wired.
 */
export async function withBridgeTimeoutPause(emitStatus, operation, options) {
    if (!emitStatus)
        return operation();
    emitStatus(options?.deferExternalAbort
        ? { op: EVAL_TIMEOUT_PAUSE_OP, deferExternalAbort: true }
        : { op: EVAL_TIMEOUT_PAUSE_OP });
    try {
        return await operation();
    }
    finally {
        emitStatus(options?.deferExternalAbort
            ? { op: EVAL_TIMEOUT_RESUME_OP, deferExternalAbort: true }
            : { op: EVAL_TIMEOUT_RESUME_OP });
    }
}
