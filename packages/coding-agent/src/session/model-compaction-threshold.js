import { resolveThresholdTokens } from "@rva/agent/compaction";
import { isRecord } from "@rva/utils";
import { applyCompactionThresholdPair, applyModelCompactionThreshold, formatCompactionPointInput, matchModelCompactionThreshold, parseCompactionPointInput, parseModelCompactionEntry, } from "../config/compaction-threshold";
import { cfgCompaction, cfgCompactionModelThresholds, cfgCompactionModelThresholdsEnabled, cfgExtendedContext, } from "./context-settings";
/** The compaction policy in force for `model`: the configured policy with its `compaction.modelThresholds` entry applied. */
export function resolveModelCompactionSettings(scope, model) {
    const thresholds = cfgCompactionModelThresholdsEnabled.get(scope)
        ? cfgCompactionModelThresholds.get(scope)
        : undefined;
    return applyModelCompactionThreshold(cfgCompaction.get(scope), thresholds, model);
}
/** Where auto-compaction triggers for `model` and which setting decides it, for the model hub preview. */
export function describeModelCompactionPoint(scope, model) {
    const configured = cfgCompaction.get(scope);
    const thresholds = cfgCompactionModelThresholdsEnabled.get(scope)
        ? cfgCompactionModelThresholds.get(scope)
        : undefined;
    const match = matchModelCompactionThreshold(thresholds, model);
    const settings = applyModelCompactionThreshold(configured, thresholds, model);
    const contextWindow = model.contextWindow ?? 0;
    const trigger = settings.enabled && contextWindow > 0 ? resolveTrigger(settings, contextWindow) : undefined;
    return {
        tokens: trigger?.tokens,
        basis: trigger && formatBasis(trigger),
        source: match?.key ?? (configured.thresholdTokens > 0 || configured.thresholdPercent > 0 ? "global" : "default"),
        draft: match?.key === `${model.provider}/${model.id}` ? formatCompactionPointInput(match.threshold) : undefined,
    };
}
/** A window size as the hub's one-line notices show it: `272K`, `1.05M`. */
function formatWindow(tokens) {
    return tokens.toLocaleString("en-US", { notation: "compact", maximumFractionDigits: 2 });
}
function resolveTrigger(settings, window) {
    const tokens = resolveThresholdTokens(window, settings);
    if (settings.thresholdTokens > 0) {
        // Capped exactly when `resolveThresholdTokens` lowered it, whatever its boundary.
        return tokens < settings.thresholdTokens
            ? { kind: "fixed", tokens, cappedFrom: settings.thresholdTokens }
            : { kind: "fixed", tokens };
    }
    const base = settings.baseWindowTokens;
    const fromBase = base !== undefined && base > 0 && base < window;
    const scaledFrom = fromBase ? base : window;
    // Mirrors `resolveThresholdTokens`' clamp of a configured percentage.
    const share = settings.thresholdPercent > 0
        ? Math.min(99, Math.max(1, settings.thresholdPercent))
        : (tokens / scaledFrom) * 100;
    return { kind: "scaled", tokens, share, scaledFrom, fromBase };
}
/** Why a trigger sits where it does, in a few words: `fixed`, `fixed 300K, capped by window`, `85% of 400K base`, `12.5% of window`. */
function formatBasis(trigger) {
    if (trigger.kind === "fixed") {
        return trigger.cappedFrom === undefined ? "fixed" : `fixed ${formatWindow(trigger.cappedFrom)}, capped by window`;
    }
    const share = `${trigger.share.toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;
    return trigger.fromBase ? `${share} of ${formatWindow(trigger.scaledFrom)} base` : `${share} of window`;
}
/**
 * Plan `entry` (as `parseCompactionPointInput` persists it) for `model`, decoded
 * and applied exactly as the runtime does ({@link parseModelCompactionEntry},
 * {@link applyCompactionThresholdPair}). With no entry, the model falls back to
 * whatever else matches it: a `…*` prefix entry, else the configured policy.
 */
function planModelCompactionEntry(settings, model, entry, tiers) {
    const configured = cfgCompaction.get(settings);
    let threshold;
    if (entry !== undefined) {
        threshold = parseModelCompactionEntry(entry);
    }
    else if (cfgCompactionModelThresholdsEnabled.get(settings)) {
        const { [`${model.provider}/${model.id}`]: _removed, ...others } = cfgCompactionModelThresholds.get(settings);
        threshold = matchModelCompactionThreshold(others, model)?.threshold;
    }
    const applied = threshold ? applyCompactionThresholdPair(configured, threshold) : configured;
    const tokens = threshold && threshold.thresholdTokens > 0 ? threshold.thresholdTokens : undefined;
    const fixed = threshold?.fixed === true;
    // A base stands in for the window, so it needs a window at least that large;
    // a fixed trigger needs room above it.
    const opensExtended = tiers !== undefined && tokens !== undefined && (fixed ? tokens >= tiers.standard : tokens > tiers.standard);
    const window = tiers
        ? opensExtended || cfgExtendedContext.get(settings)
            ? tiers.extended
            : tiers.standard
        : (model.contextWindow ?? undefined);
    const ceiling = tiers?.extended ?? model.contextWindow;
    let error;
    if (entry !== undefined && tokens !== undefined && ceiling !== null && ceiling !== undefined) {
        const max = tiers ? "max " : "";
        if (fixed && tokens >= ceiling)
            error = `Must be below the ${formatWindow(ceiling)} ${max}window`;
        if (!fixed && tokens > ceiling)
            error = `Must not exceed the ${formatWindow(ceiling)} ${max}window`;
    }
    return { settings: applied, window, opensExtended: entry !== undefined && opensExtended, error };
}
/** A model entry in words, for the save message: `400,000-token base`, `fixed at 400,000 tokens`, `80% of the window`. */
function describeModelCompactionEntry(threshold) {
    if (threshold.thresholdTokens <= 0)
        return `${threshold.thresholdPercent}% of the window`;
    const tokens = threshold.thresholdTokens.toLocaleString("en-US");
    return threshold.fixed ? `fixed at ${tokens} tokens` : `${tokens}-token base`;
}
/** Where the plan compacts; undefined when auto-compaction is off or the window is unknown. */
function planTrigger(plan) {
    if (!plan.settings.enabled || plan.window === undefined || plan.window <= 0)
        return undefined;
    return resolveTrigger(plan.settings, plan.window);
}
/** Where the plan compacts, as one short line: `compacts at 340K · 85% of 400K base`. */
function summarizePlan(plan) {
    if (!plan.settings.enabled)
        return "auto-compaction is off";
    const trigger = planTrigger(plan);
    if (!trigger)
        return undefined;
    if (trigger.kind === "fixed" && trigger.cappedFrom === undefined) {
        return `compacts at exactly ${formatWindow(trigger.tokens)}`;
    }
    return `compacts at ${formatWindow(trigger.tokens)} · ${formatBasis(trigger)}`;
}
/** Parse and plan typed hub input; undefined when it does not parse or fit. */
function planInput(settings, model, input, tiers) {
    let entry;
    try {
        entry = parseCompactionPointInput(input);
    }
    catch {
        return undefined;
    }
    const plan = planModelCompactionEntry(settings, model, entry ?? undefined, tiers);
    return plan.error ? undefined : { reset: entry === null, plan };
}
/**
 * What a typed compaction limit would do to `model`: the window it runs on and
 * where it compacts (`trigger` undefined when auto-compaction is off), or with
 * no entry for empty input (`reset`). Undefined for input that does not parse
 * or fit, which {@link setModelCompactionPoint} reports on submit.
 */
export function planModelCompactionPoint(settings, model, input, tiers) {
    const planned = planInput(settings, model, input, tiers);
    if (!planned)
        return undefined;
    return { reset: planned.reset, window: planned.plan.window, trigger: planTrigger(planned.plan) };
}
/**
 * Live preview line of a typed compaction limit for the hub field
 * ({@link planModelCompactionPoint} in words): `compacts at 340K · 85% of 400K
 * base`, prefixed `resets:` for empty input.
 */
export function previewModelCompactionPoint(settings, model, input, tiers) {
    const planned = planInput(settings, model, input, tiers);
    if (!planned)
        return undefined;
    const summary = summarizePlan(planned.plan);
    return planned.reset && summary ? `resets: ${summary}` : summary;
}
/**
 * Persist `input` (see {@link parseCompactionPointInput}) as `model`'s own
 * `compaction.modelThresholds` entry in the global config; empty input removes
 * it. A token count is the base the compaction policy scales (it stands in for
 * the window), so it may not exceed the largest window `model` can run with
 * (`tiers.extended`, else its current window); a fixed trigger (`f400k`) must
 * stay below it. Throws on unparseable or too-large input, and when a project
 * or higher-priority layer sets the same key, which would leave the global
 * write without effect.
 *
 * A base past `tiers.standard`, or a fixed trigger at or past it, opts the
 * model into its extended window (see `ModelRegistry.contextWindowTiers`);
 * unless extended context is already on, it is written only once `confirmed`,
 * and otherwise returns the warning to show.
 */
export function setModelCompactionPoint(settings, model, input, options = {}) {
    const entry = parseCompactionPointInput(input) ?? undefined;
    const key = `${model.provider}/${model.id}`;
    const projectThresholds = settings.getProjectSettings().compaction;
    if (isRecord(projectThresholds) &&
        isRecord(projectThresholds.modelThresholds) &&
        Object.hasOwn(projectThresholds.modelThresholds, key)) {
        throw new Error(`${key} is set in the project config; edit compaction.modelThresholds there`);
    }
    const { tiers } = options;
    const plan = planModelCompactionEntry(settings, model, entry, tiers);
    if (plan.error)
        throw new Error(plan.error);
    if (tiers && plan.opensExtended && !options.confirmed && !cfgExtendedContext.get(settings)) {
        // Pricing follows where compaction actually triggers: the fixed point, or the policy scaled from the base.
        const trigger = resolveThresholdTokens(tiers.extended, plan.settings);
        const threshold = model.cost.longContext?.inputThreshold;
        const premiumFrom = threshold !== undefined && trigger > threshold ? threshold : undefined;
        const pricing = premiumFrom !== undefined ? `; >${formatWindow(premiumFrom)} costs more` : "";
        // Kept short: the hub shows it on one line beside the input field.
        return {
            kind: "confirm",
            message: `Opens ${formatWindow(tiers.extended)} window${pricing}`,
            extendedWindow: tiers.extended,
            ...(premiumFrom !== undefined ? { premiumFrom } : {}),
        };
    }
    cfgCompactionModelThresholds.setEntry(settings, key, entry);
    const effective = cfgCompactionModelThresholds.get(settings)[key] ?? undefined;
    if (effective !== entry) {
        throw new Error(`${key} is overridden by a higher-priority config layer; the global entry was saved but has no effect`);
    }
    const threshold = entry === undefined ? undefined : parseModelCompactionEntry(entry);
    return {
        kind: "saved",
        entry,
        described: threshold ? describeModelCompactionEntry(threshold) : "reset",
        trigger: planTrigger(plan),
        summary: summarizePlan(plan),
    };
}
