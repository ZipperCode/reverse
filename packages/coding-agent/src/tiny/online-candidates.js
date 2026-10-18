import { formatModelStringWithRouting, resolveModelOverride, resolveRoleSelection } from "../config/model-resolver";
import { expandDefaultRetryFallbackChains, findRetryFallbackCandidates, resolveRetryFallbackChainKey, } from "../session/retry-fallback-chains";
import { cfgRetryFallbackChains, cfgRetryModelFallback } from "../session/settings";
function modelKey(model) {
    return `${model.provider}/${model.id}`;
}
/** Dedup key that keeps distinct `@upstream` routes as separate candidates. */
function candidateKey(model) {
    return formatModelStringWithRouting(model);
}
function createFallbackContext(chains, settings, availableModels) {
    return {
        chains,
        getModelRole: role => settings.getModelRole(role),
        modelLookup: {
            find: (provider, id) => availableModels.find(model => model.provider === provider && model.id === id),
            hasProvider: provider => availableModels.some(model => model.provider === provider),
        },
    };
}
/**
 * Transitively expand retry fallback candidates from seed models into `out`.
 * Callers choose whether `context.chains` already merged role defaults.
 */
function expandFallbackCandidates(seeds, context, settings, availableModels, seen, out) {
    const add = (role, model) => {
        const key = candidateKey(model);
        if (seen.has(key))
            return false;
        seen.add(key);
        out.push({ role, model });
        return true;
    };
    const registryShim = { getAvailable: () => availableModels };
    const queue = [...seeds];
    const expanded = new Set();
    while (queue.length > 0) {
        const { role, model, selector, roleHint } = queue.shift();
        const chainKey = resolveRetryFallbackChainKey(context, selector, model, roleHint);
        if (!chainKey)
            continue;
        // Resolved provider/id is the chain primary: bare/fuzzy role selectors and
        // `@upstream` routing suffixes must not empty the chain or poison wildcards.
        const primarySelector = modelKey(model);
        const expandKey = `${chainKey}\0${candidateKey(model)}`;
        if (expanded.has(expandKey))
            continue;
        expanded.add(expandKey);
        for (const candidate of findRetryFallbackCandidates(context, chainKey, primarySelector, model, {
            allowMissingPrimary: true,
        })) {
            // Resolve raw selectors (including `@upstream` / fuzzy) the same way
            // turn-recovery does, instead of exact (provider, id) lookup only.
            const resolved = resolveModelOverride([candidate.raw], registryShim, settings);
            const fallback = resolved.model ?? context.modelLookup.find(candidate.provider, candidate.id);
            if (!fallback)
                continue;
            if (!add(role, fallback))
                continue;
            // After landing on this fallback, consult its own chain key so configs
            // like `tiny: [B]` + `B: [C]` reach C (session recovery does the same).
            queue.push({
                role,
                model: fallback,
                selector: formatModelStringWithRouting(fallback),
            });
        }
    }
}
/**
 * Collect unique online models for lightweight background tasks.
 *
 * Order: each requested role's primary, then canonical retry fallback chains
 * traversed transitively (so a hop onto B also consults B's own chain).
 * Disabling model fallback restricts attempts to the first resolvable primary,
 * unless `tryAllRoles` asks for the explicit role chain without configured
 * retry-chain expansion.
 */
export function collectOnlineTinyCandidates(roles, settings, availableModels, options) {
    const seen = new Set();
    const out = [];
    const addPrimary = (role, model) => {
        const key = candidateKey(model);
        if (seen.has(key))
            return false;
        seen.add(key);
        out.push({ role, model });
        return true;
    };
    // Retain every role even if primaries coincide: their fallback chains can differ.
    const fallbackEnabled = cfgRetryModelFallback.get(settings) !== false;
    const primaries = [];
    for (const role of roles) {
        const resolved = resolveRoleSelection([role], settings, availableModels);
        if (!resolved?.model)
            continue;
        addPrimary(resolved.role, resolved.model);
        if (!fallbackEnabled && !options?.tryAllRoles)
            return out;
        if (fallbackEnabled)
            primaries.push({ role: resolved.role, model: resolved.model });
    }
    if (!fallbackEnabled)
        return out;
    const configuredChains = cfgRetryFallbackChains.get(settings);
    if (!configuredChains || typeof configuredChains !== "object")
        return out;
    const context = createFallbackContext(expandDefaultRetryFallbackChains(configuredChains, roles), settings, availableModels);
    expandFallbackCandidates(primaries.map(({ role, model }) => ({
        role,
        model,
        selector: settings.getModelRole(role) ?? modelKey(model),
        roleHint: role,
    })), context, settings, availableModels, seen, out);
    return out;
}
/**
 * Expand one model's own `retry.fallbackChains` transitively.
 *
 * Does not merge role/`default` chains into the seed via
 * `expandDefaultRetryFallbackChains` — title generation appends the active
 * session model separately from tiny/commit/smol role collection, so its
 * recovery path must consult only the configured model-keyed / wildcard /
 * matching-role keys that `resolveRetryFallbackChainKey` already selects.
 */
export function expandOnlineTinyModelFallbacks(model, settings, availableModels) {
    const seen = new Set([candidateKey(model)]);
    const out = [{ role: "current", model }];
    if (cfgRetryModelFallback.get(settings) === false)
        return [model];
    const configuredChains = cfgRetryFallbackChains.get(settings);
    if (!configuredChains || typeof configuredChains !== "object")
        return [model];
    const context = createFallbackContext(configuredChains, settings, availableModels);
    expandFallbackCandidates([
        {
            role: "current",
            model,
            selector: formatModelStringWithRouting(model),
        },
    ], context, settings, availableModels, seen, out);
    return out.map(candidate => candidate.model);
}
