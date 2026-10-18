import { modelsAreEqual } from "@rva/catalog/models";
/**
 * Decide how to reconcile the active model with the resolved `plan` role.
 *
 * @param currentModel - The session's active model, or `undefined` before one is set.
 * @param resolved - The `plan` role resolved against the available models.
 * @param isStreaming - Whether the session is mid-turn (forces a deferred switch).
 */
export function resolvePlanModelTransition(currentModel, resolved, isStreaming) {
    if (!resolved.model)
        return { kind: "none" };
    const planThinkingLevel = resolved.explicitThinkingLevel ? resolved.thinkingLevel : undefined;
    if (modelsAreEqual(currentModel, resolved.model)) {
        return planThinkingLevel ? { kind: "thinking", thinkingLevel: planThinkingLevel } : { kind: "none" };
    }
    return { kind: "apply", model: resolved.model, thinkingLevel: planThinkingLevel, deferred: isStreaming };
}
