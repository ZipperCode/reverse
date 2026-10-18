/** Ordered automatic context-maintenance methods and their settings metadata. */
import { shouldUseProviderNativeCompaction, } from "@rva/agent/compaction";
/** Choices presented by the ordered compaction-method setting. */
export const COMPACTION_METHOD_CHOICES = [
    {
        value: "remote",
        label: "Server compaction",
        description: "Use provider-native server compaction (OpenAI Responses compact, Anthropic compaction beta) when the active route supports it",
    },
    {
        value: "snapcompact",
        label: "Snapcompact",
        description: "Archive history onto dense bitmap images the active vision model reads back; no LLM call",
    },
    {
        value: "handoff",
        label: "Handoff",
        description: "Generate a handoff document and continue from it as the compaction summary",
    },
    {
        value: "soft",
        label: "Soft compaction",
        description: "Summarize in place with a compaction model without using server compaction",
    },
    {
        value: "shake",
        label: "Shake",
        description: "Drop recoverable heavy content in place without an LLM call",
    },
];
/** Default fallback order: server-native first, portable summary last. */
export const DEFAULT_COMPACTION_METHOD_ORDER = [
    "remote",
    "snapcompact",
    "handoff",
    "shake",
    "soft",
];
const COMPACTION_METHODS = {
    remote: true,
    snapcompact: true,
    handoff: true,
    soft: true,
    shake: true,
};
/** Whether an unknown configuration value names a supported compaction method. */
export function isCompactionMethod(value) {
    return typeof value === "string" && Object.hasOwn(COMPACTION_METHODS, value);
}
/**
 * Filter malformed entries and preserve first occurrence order from a configured
 * compaction-method preference list.
 */
export function resolveCompactionMethodOrder(value) {
    if (!Array.isArray(value))
        return [];
    const methods = [];
    for (const method of value) {
        if (isCompactionMethod(method) && !methods.includes(method))
            methods.push(method);
    }
    return methods;
}
const STRATEGY_BY_COMPACTION_METHOD = {
    remote: "context-full",
    snapcompact: "snapcompact",
    handoff: "handoff",
    soft: "context-full",
    shake: "shake",
};
/**
 * Convert the selected preference into the engine's compact operation flags.
 * The engine intentionally remains usable by SDK consumers that do not expose
 * the coding agent's preference list.
 */
export function resolveMethodSettings(settings, method) {
    return {
        ...settings,
        strategy: STRATEGY_BY_COMPACTION_METHOD[method],
        remoteEnabled: method === "remote",
    };
}
/** Whether server compaction has either a configured endpoint or an active native route. */
export function canUseRemoteCompaction(model, settings) {
    return ((typeof settings.remoteEndpoint === "string" && settings.remoteEndpoint.length > 0) ||
        (model !== null && model !== undefined && shouldUseProviderNativeCompaction(model, settings)));
}
/**
 * First configured method a threshold pass would run, or undefined when it is
 * local (snapcompact/shake) — local methods are effectively instant, so there
 * is nothing to speculate. Shared by the maintenance loop's speculation gate
 * and the status line's annotated context gauge (speculation marker).
 * `skipRemote` passes over native compaction, e.g. after it failed for good.
 */
export function resolveSpeculationMethod(model, settings, { skipRemote = false } = {}) {
    for (const candidate of resolveCompactionMethodOrder(settings.methodOrder)) {
        if (skipRemote && candidate === "remote")
            continue;
        const available = candidate === "remote"
            ? canUseRemoteCompaction(model, resolveMethodSettings(settings, candidate))
            : candidate === "snapcompact"
                ? model?.input?.includes("image") === true
                : true;
        if (!available)
            continue;
        return candidate === "remote" || candidate === "handoff" || candidate === "soft" ? candidate : undefined;
    }
    return undefined;
}
