import { isRecord } from "@rva/utils";
/** Session event channel for editor-anchored judgment progress. */
export const JUDGMENT_BATCH_PROGRESS_EVENT_CHANNEL = "eval:judgment-batch-progress";
function isNonNegativeInteger(value) {
    return typeof value === "number" && Number.isInteger(value) && value >= 0;
}
/** Validate an untyped event-bus payload before rendering it. */
export function isJudgmentBatchProgress(value) {
    if (!isRecord(value))
        return false;
    const progress = value;
    if (typeof progress.id !== "string" ||
        progress.id.length === 0 ||
        typeof progress.intent !== "string" ||
        progress.intent.trim().length === 0 ||
        !isNonNegativeInteger(progress.done) ||
        !isNonNegativeInteger(progress.total) ||
        !isNonNegativeInteger(progress.failed) ||
        typeof progress.cost !== "number" ||
        !Number.isFinite(progress.cost) ||
        progress.cost < 0 ||
        typeof progress.running !== "boolean" ||
        (progress.error !== undefined && typeof progress.error !== "string")) {
        return false;
    }
    return progress.done <= progress.total && progress.failed <= progress.done;
}
