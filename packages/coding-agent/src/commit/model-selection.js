import { getModelMatchPreferences, parseModelPattern, resolveModelRoleValue, resolveRoleSelection, } from "../config/model-resolver";
import { CHAT_MODEL_ROLE_IDS } from "../config/model-roles";
import MODEL_PRIO from "../priority.json" with { type: "json" };
import { concreteThinkingLevel } from "@rva/tui/thinking";
export async function resolvePrimaryModel(override, settings, modelRegistry) {
    const available = modelRegistry.getAvailable();
    const matchPreferences = getModelMatchPreferences(settings);
    const resolved = override
        ? resolveModelRoleValue(override, available, { settings, matchPreferences })
        : resolveRoleSelection(["commit", "smol", ...CHAT_MODEL_ROLE_IDS], settings, available);
    const model = resolved?.model;
    if (!model) {
        throw new Error("No model available for commit generation");
    }
    const apiKey = await modelRegistry.getApiKey(model);
    if (!apiKey) {
        throw new Error(`No API key available for model ${model.provider}/${model.id}`);
    }
    return {
        model,
        apiKey: modelRegistry.resolver(model),
        thinkingLevel: concreteThinkingLevel(resolved?.thinkingLevel),
    };
}
export async function resolveSmolModel(settings, modelRegistry, fallbackModel, fallbackApiKey) {
    const available = modelRegistry.getAvailable();
    const resolvedSmol = resolveRoleSelection(["smol"], settings, available);
    if (resolvedSmol?.model) {
        const apiKey = await modelRegistry.getApiKey(resolvedSmol.model);
        if (apiKey) {
            return {
                model: resolvedSmol.model,
                apiKey: modelRegistry.resolver(resolvedSmol.model),
                thinkingLevel: concreteThinkingLevel(resolvedSmol.thinkingLevel),
            };
        }
    }
    const matchPreferences = getModelMatchPreferences(settings);
    for (const pattern of MODEL_PRIO.smol) {
        const candidate = parseModelPattern(pattern, available, matchPreferences).model;
        if (!candidate)
            continue;
        const apiKey = await modelRegistry.getApiKey(candidate);
        if (apiKey) {
            return {
                model: candidate,
                apiKey: modelRegistry.resolver(candidate),
            };
        }
    }
    return { model: fallbackModel, apiKey: fallbackApiKey };
}
