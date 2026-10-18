import { formatModelSelectorValue, parseModelString } from "@rva/tui/overlays/model-selector";
import { extractExplicitThinkingSelector, getModelMatchPreferences, resolveModelRoleValue, } from "../config/model-resolver";
/** Formats a role assignment while preserving its explicit thinking selector. */
export function formatRoleModelValue(settings, modelRegistry, role, model, selectorOverride, thinkingLevelOverride) {
    const modelKey = selectorOverride ?? `${model.provider}/${model.id}`;
    if (thinkingLevelOverride !== undefined)
        return formatModelSelectorValue(modelKey, thinkingLevelOverride);
    const existingRoleValue = settings.getModelRole(role);
    if (!existingRoleValue)
        return modelKey;
    const thinkingLevel = extractExplicitThinkingSelector(existingRoleValue, settings, {
        isLiteralModelId: (provider, id) => {
            if (provider !== undefined)
                return modelRegistry.find(provider, id) !== undefined;
            const lowerId = id.toLowerCase();
            return modelRegistry.getAll("all").some(candidate => candidate.id.toLowerCase() === lowerId);
        },
    });
    return formatModelSelectorValue(modelKey, thinkingLevel);
}
/** Resolves a configured model target relative to the current provider. */
export function resolveConfiguredModelTarget(configuredTarget, currentModel, availableModels) {
    const trimmedTarget = configuredTarget?.trim();
    if (!trimmedTarget)
        return undefined;
    const parsed = parseModelString(trimmedTarget, {
        allowMaxSuffix: true,
        allowAutoAlias: true,
        isLiteralModelId: (provider, id) => availableModels.some(model => model.provider === provider && model.id === id),
    });
    if (parsed) {
        const explicitModel = availableModels.find(model => model.provider === parsed.provider && model.id === parsed.id);
        if (explicitModel)
            return explicitModel;
    }
    return availableModels.find(model => model.provider === currentModel.provider && model.id === trimmedTarget);
}
/** Resolves a model's configured context-promotion target. */
export function resolveContextPromotionConfiguredTarget(currentModel, availableModels) {
    return resolveConfiguredModelTarget(currentModel.contextPromotionTarget, currentModel, availableModels);
}
/** Resolves a model's configured compaction target. */
export function resolveCompactionConfiguredTarget(currentModel, availableModels) {
    return resolveConfiguredModelTarget(currentModel.compactionModel, currentModel, availableModels);
}
/** Resolves a model role and its explicit thinking selection. */
export function resolveRoleModelFull(settings, role, availableModels, currentModel) {
    const roleModelStr = role === "default"
        ? (settings.getModelRole("default") ??
            (currentModel ? `${currentModel.provider}/${currentModel.id}` : undefined))
        : settings.getModelRole(role);
    if (!roleModelStr) {
        return { model: undefined, thinkingLevel: undefined, explicitThinkingLevel: false, warning: undefined };
    }
    return resolveModelRoleValue(roleModelStr, availableModels, {
        settings,
        matchPreferences: getModelMatchPreferences(settings),
    });
}
