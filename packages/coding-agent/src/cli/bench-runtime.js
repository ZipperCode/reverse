import { buildModelProviderPriorityRank } from "@rva/catalog/identity";
import { getProjectDir, logger } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { ModelRegistry } from "../config/model-registry";
import { formatModelString, getModelMatchPreferences, resolveCliModel } from "../config/model-resolver";
import { Settings } from "../config/settings";
import { discoverAuthStorage, loadCliExtensionProviders } from "../sdk";
import { concreteThinkingLevel, resolveThinkingLevelForModel } from "@rva/tui/thinking";
/** Open the auth vault, settings, and model registry for a benchmark run. */
export async function createDefaultBenchRuntime() {
    const cwd = getProjectDir();
    const settings = await Settings.init({ cwd });
    const authStorage = await discoverAuthStorage(undefined, { settings });
    try {
        const modelRegistry = new ModelRegistry(authStorage);
        await modelRegistry.hydrateCredentialScopedModelCaches();
        await loadCliExtensionProviders(modelRegistry, settings, cwd);
        return {
            modelRegistry,
            settings,
            close: () => authStorage.close(),
        };
    }
    catch (error) {
        authStorage.close();
        throw error;
    }
}
/** Highest-priority provider variant: native/OAuth transports outrank mirrors. */
function pickHighestPriorityProvider(models, providerOrder) {
    if (models.length <= 1)
        return models[0];
    const priority = buildModelProviderPriorityRank(providerOrder);
    return [...models].sort((a, b) => {
        const aRank = priority.get(a.provider.toLowerCase()) ?? Number.POSITIVE_INFINITY;
        const bRank = priority.get(b.provider.toLowerCase()) ?? Number.POSITIVE_INFINITY;
        return aRank - bRank;
    })[0];
}
/**
 * Benchmarks resolve selectors against the entire catalog (credentials are
 * ignored), so an ambiguous id shared by several providers can land on one the
 * user never authenticated. For non-pinned selectors, redirect to an equivalent
 * model under a provider with configured auth. An explicit `provider/id`
 * selector is honored verbatim — even unauthenticated — so forced benchmarking
 * keeps working.
 */
function resolveAuthenticatedAlternative(selector, model, modelRegistry, providerOrder) {
    if (!modelRegistry.hasConfiguredAuth)
        return undefined;
    // A pinned `provider/...` selector is authoritative; never redirect off it.
    if (selector.trim().toLowerCase().startsWith(`${model.provider.toLowerCase()}/`))
        return undefined;
    if (modelRegistry.hasConfiguredAuth(model))
        return undefined;
    const seen = new Set();
    const authenticated = [];
    const consider = (candidate) => {
        const key = `${candidate.provider}/${candidate.id}`;
        if (seen.has(key))
            return;
        seen.add(key);
        if (modelRegistry.hasConfiguredAuth?.(candidate))
            authenticated.push(candidate);
    };
    // Same-id fallback for equivalent entries under providers with configured auth.
    for (const candidate of modelRegistry.getAll()) {
        if (candidate.id === model.id)
            consider(candidate);
    }
    return pickHighestPriorityProvider(authenticated, providerOrder);
}
/**
 * Resolve every selector to a concrete model + thinking level, warning on
 * stderr when a selector was redirected to an authenticated provider. When any
 * selector misses the hydrated catalog, awaits one cache-aware discovery pass
 * and re-resolves every selector from the refreshed catalog before failing:
 * discovery-backed providers (models.yml discovery, ollama, llama.cpp,
 * lm-studio) ship no static models, and cached rows whose `Authorization`
 * header cannot be re-derived from config (#5780) drop every model of that
 * provider until a live probe runs. A refresh replaces the rows of every
 * touched discovery provider, so only a full re-resolve keeps all targets on
 * the same snapshot. Same lazy fallback the session boot path applies (issues
 * #6114, #6162) — the common path, where every selector resolves, never pays
 * for a fetch.
 *
 * @throws when any selector cannot be resolved; the message lists all failures.
 */
export async function resolveBenchTargets(selectors, modelRegistry, settings, writeStderr) {
    const preferences = getModelMatchPreferences(settings);
    // Resolution runs up to two passes (initial + post-refresh), and refresh
    // can change how an already-resolved selector redirects, so only the
    // final pass's warnings are real: each pass rebuilds the buffer, and it
    // is flushed once, so a warning that no longer applies is never printed.
    const warnings = new Map();
    const warn = (selector, kind, text) => {
        warnings.set(`${selector}\u0000${kind}`, text);
    };
    const resolvePass = () => {
        warnings.clear();
        return selectors.map(selector => resolveOne(selector));
    };
    const resolveOne = (selector) => {
        // Benchmarks intentionally resolve against the full catalog first, then
        // apply the exact-id credential fallback below. Using the CLI resolver's
        // authenticated default here would silently redirect non-equivalent bare
        // ids and suppress the warning for equivalent cross-provider models.
        const result = resolveCliModel({
            cliModel: selector,
            modelRegistry,
            availableModels: modelRegistry.getAll(),
            settings,
            preferences,
        });
        if (result.error)
            return `${selector}: ${result.error}`;
        if (!result.model)
            return `${selector}: model not found`;
        if (result.warning)
            warn(selector, "resolver", result.warning);
        let model = result.model;
        const authSelector = result.configuredPatterns?.[result.configuredPatternIndex ?? 0] ?? selector;
        const authenticated = resolveAuthenticatedAlternative(authSelector, model, modelRegistry, preferences.providerOrder);
        if (authenticated) {
            warn(selector, "redirect", `no credentials for "${model.provider}"; benchmarking ${formatModelString(authenticated)} instead. Pin "${formatModelString(model)}" to force it.`);
            model = authenticated;
        }
        return {
            selector,
            model,
            thinking: resolveThinkingLevelForModel(model, concreteThinkingLevel(result.thinkingLevel)),
        };
    };
    let outcomes = resolvePass();
    if (outcomes.some(outcome => typeof outcome === "string") &&
        modelRegistry.refresh &&
        (modelRegistry.getDiscoverableProviders?.().length ?? 0) > 0) {
        await logger.time("resolveBenchTargetsDiscoveryFallback", () => modelRegistry.refresh());
        // Refresh replaces the catalog rows of every touched discovery provider,
        // so re-resolve every selector — not just the misses — to keep all
        // targets on the same snapshot.
        outcomes = resolvePass();
    }
    for (const text of warnings.values())
        writeStderr(`${chalk.yellow(`Warning: ${text}`)}\n`);
    const errors = outcomes.filter((outcome) => typeof outcome === "string");
    if (errors.length > 0) {
        throw new Error(`Could not resolve ${errors.length === 1 ? "model" : "models"}:\n${errors.join("\n")}`);
    }
    return outcomes;
}
