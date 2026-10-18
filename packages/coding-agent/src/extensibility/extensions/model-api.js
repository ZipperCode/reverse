import { getModelMatchPreferences, resolveModelRoleValue } from "../../config/model-resolver";
/**
 * Build the `ctx.models` facade. `getModel` is read lazily so `current()` always
 * reflects the live session model (it can change mid-session via `/model`).
 */
export function createExtensionModelQuery(modelRegistry, settings, getModel) {
    return {
        list: () => modelRegistry.getAvailable(),
        current: () => getModel(),
        // resolveModelRoleValue expands a role alias (`@slow`) to its full configured
        // priority list and tries each pattern — the same path core selection uses — so a
        // fallback model lower in the list still resolves. Plain model strings pass through
        // as a single pattern.
        resolve: (spec) => resolveModelRoleValue(spec, modelRegistry.getAvailable(), {
            settings,
            matchPreferences: getModelMatchPreferences(settings),
        }).model,
        family: (model) => model.identity.class === "unknown" ? model.provider.toLowerCase() : model.identity.class,
    };
}
