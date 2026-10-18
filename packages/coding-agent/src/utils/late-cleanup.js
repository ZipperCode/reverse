import { logger } from "@rva/utils";
const pendingCleanups = new Set();
/** Keep timed-out cleanup reachable until its resources really settle. */
export function trackLateCleanup(work, context) {
    const tracked = work
        .catch(error => {
        logger.warn("Deferred cleanup failed", {
            ...context,
            error: error instanceof Error ? error.message : String(error),
        });
    })
        .finally(() => pendingCleanups.delete(tracked));
    pendingCleanups.add(tracked);
}
