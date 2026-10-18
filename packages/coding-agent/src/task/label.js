/**
 * Tiny-model UI labels for spawned subagents.
 */
import { logger, prompt } from "@rva/utils";
import taskLabelSystemPrompt from "../prompts/system/task-label.md" with { type: "text" };
import { generateSessionTitle } from "../utils/title-generator";
const TASK_LABEL_SYSTEM_PROMPT = prompt.render(taskLabelSystemPrompt);
/** True when a generated label is just the spawn handle, including `Name-2`. */
export function labelEchoesHandle(handle, label) {
    if (!handle)
        return false;
    if (label.localeCompare(handle, undefined, { sensitivity: "accent" }) === 0)
        return true;
    const separator = handle.lastIndexOf("-");
    if (separator <= 0)
        return false;
    const prefix = handle.slice(0, separator);
    const suffix = handle.slice(separator + 1);
    return /^\d+$/.test(suffix) && prefix.localeCompare(label, undefined, { sensitivity: "accent" }) === 0;
}
/** Compresses a delegated assignment into a one-sentence UI label via the tiny title model — fired by the executor spawn path because the task wire schema no longer carries a `description`; null on empty input or failure. */
export async function generateTaskLabel(assignment, registry, settings, sessionId, signal) {
    const text = assignment.trim();
    if (!text)
        return null;
    try {
        const label = await generateSessionTitle(text, registry, settings, sessionId, undefined, undefined, TASK_LABEL_SYSTEM_PROMPT, signal);
        if (!label || labelEchoesHandle(sessionId, label))
            return null;
        return label;
    }
    catch (err) {
        logger.debug("task-label: generation failed", {
            sessionId,
            error: err instanceof Error ? err.message : String(err),
        });
        return null;
    }
}
