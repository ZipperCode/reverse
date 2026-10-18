import { isRecord } from "@rva/utils";
const PERCENT_PATTERN = /^(\d+(?:\.\d+)?)%$/;
const FIXED_ENTRY_PATTERN = /^f(\d+)$/i;
const TOKEN_INPUT_PATTERN = /^(f)?(\d+)([kmb])?$/i;
const TOKEN_SUFFIX_SCALE = { k: 1000, m: 1000000, b: 1000000000 };
function parseThresholdEntry(entry, allowFixed) {
    if (typeof entry === "number") {
        if (Number.isSafeInteger(entry) && entry > 0)
            return { thresholdPercent: -1, thresholdTokens: entry };
    }
    else if (typeof entry === "string") {
        const text = entry.trim();
        const fixed = allowFixed ? FIXED_ENTRY_PATTERN.exec(text) : null;
        if (fixed) {
            const tokens = Number(fixed[1]);
            if (Number.isSafeInteger(tokens) && tokens > 0)
                return { thresholdPercent: -1, thresholdTokens: tokens, fixed: true };
            return undefined;
        }
        const match = PERCENT_PATTERN.exec(text);
        const percent = match ? Number(match[1]) : Number.NaN;
        if (percent > 0 && percent <= 100)
            return { thresholdPercent: percent, thresholdTokens: -1 };
    }
    return undefined;
}
/** Validate a `key → entry` threshold map and normalize each entry to both threshold fields. */
function validateThresholdMap(settingId, keyNoun, value, options) {
    if (value === undefined || value === null)
        return {};
    if (!isRecord(value)) {
        const received = Array.isArray(value) ? "an array" : `a ${typeof value}`;
        throw new Error(`Invalid ${settingId}: expected a map of ${keyNoun} to token count or percentage, got ${received}.`);
    }
    const thresholds = {};
    for (const [key, entry] of Object.entries(value)) {
        const keyError = options.checkKey?.(key);
        if (keyError)
            throw new Error(`Invalid ${settingId} key "${key}": ${keyError}.`);
        if (entry === null)
            continue;
        const threshold = parseThresholdEntry(entry, options.allowFixed);
        if (!threshold) {
            const received = Array.isArray(entry) ? "an array" : typeof entry === "string" ? `"${entry}"` : String(entry);
            const forms = options.allowFixed
                ? `a positive integer token count (e.g. 90000), a fixed trigger (e.g. "f90000") or a percentage in (0, 100] (e.g. "80%")`
                : `a positive integer token count (e.g. 90000) or a percentage in (0, 100] (e.g. "80%")`;
            throw new Error(`Invalid ${settingId}.${key}: expected ${forms}, got ${received}.`);
        }
        thresholds[key] = threshold;
    }
    return thresholds;
}
/** Validate the exact-agent compaction threshold map and normalize each entry to both threshold fields. */
export function validateAgentCompactionThresholdOverrides(value) {
    return validateThresholdMap("task.agentCompactionThresholdOverrides", "agent name", value, { allowFixed: false });
}
function checkModelThresholdKey(key) {
    const star = key.indexOf("*");
    if (star !== -1 && star !== key.length - 1)
        return "`*` is only allowed as the last character";
    const slash = key.indexOf("/");
    if (slash <= 0 || slash === key.length - 1)
        return "expected `provider/model-id` or a `provider/…*` prefix";
    return undefined;
}
/**
 * Validate `compaction.modelThresholds`: keys are an exact `provider/model-id`
 * or a `*`-terminated prefix of one (`deepseek/*`, `openrouter/anthropic/*`).
 */
export function validateModelCompactionThresholds(value) {
    return validateThresholdMap("compaction.modelThresholds", "model selector", value, {
        checkKey: checkModelThresholdKey,
        allowFixed: true,
    });
}
const parsedModelThresholds = new WeakMap();
function modelThresholdsOf(raw) {
    if (!isRecord(raw))
        return {};
    let parsed = parsedModelThresholds.get(raw);
    if (!parsed) {
        parsed = validateModelCompactionThresholds(raw);
        parsedModelThresholds.set(raw, parsed);
    }
    return parsed;
}
/**
 * The `compaction.modelThresholds` entry for `model`: an exact `provider/model-id`
 * key wins, else the longest `*`-terminated prefix matching it.
 */
export function matchModelCompactionThreshold(raw, model) {
    const thresholds = modelThresholdsOf(raw);
    const selector = `${model.provider}/${model.id}`;
    if (Object.hasOwn(thresholds, selector))
        return { key: selector, threshold: thresholds[selector] };
    let best;
    for (const key in thresholds) {
        if (!key.endsWith("*") || !selector.startsWith(key.slice(0, -1)))
            continue;
        if (!best || key.length > best.key.length)
            best = { key, threshold: thresholds[key] };
    }
    return best;
}
const appliedThresholds = new WeakMap();
/** One persisted `compaction.modelThresholds` value (`400000`, `"f400000"`, `"80%"`) as its threshold pair. */
export function parseModelCompactionEntry(entry) {
    return parseThresholdEntry(entry, true);
}
/**
 * `settings` with one model entry applied. A token entry is the base the
 * configured policy scales (`baseWindowTokens`, standing in for the window:
 * `thresholdPercent` of it, else it minus the reserve) and drops a global fixed
 * `thresholdTokens`; a fixed entry (`"f90000"`) is the exact trigger; a
 * percentage entry replaces both threshold fields.
 */
export function applyCompactionThresholdPair(settings, threshold) {
    const { thresholdPercent, thresholdTokens, fixed } = threshold;
    return thresholdTokens > 0 && !fixed
        ? { ...settings, thresholdTokens: -1, baseWindowTokens: thresholdTokens }
        : { ...settings, thresholdPercent, thresholdTokens };
}
/**
 * `settings` with the `compaction.modelThresholds` entry governing `model`
 * applied ({@link applyCompactionThresholdPair}); the same object when no entry
 * applies. Results are cached per settings snapshot so hot paths allocate once
 * per entry.
 */
export function applyModelCompactionThreshold(settings, raw, model) {
    if (!model)
        return settings;
    const match = matchModelCompactionThreshold(raw, model);
    if (!match)
        return settings;
    let byKey = appliedThresholds.get(settings);
    if (!byKey) {
        byKey = new Map();
        appliedThresholds.set(settings, byKey);
    }
    const cached = byKey.get(match.key);
    if (cached?.threshold === match.threshold)
        return cached.applied;
    const applied = applyCompactionThresholdPair(settings, match.threshold);
    byKey.set(match.key, { threshold: match.threshold, applied });
    return applied;
}
/**
 * Parse a typed compaction point into its persisted entry: an integer token
 * count with an optional `k`/`m`/`b` suffix (any case) becomes a number (the
 * base), the same with an `f` prefix becomes a fixed trigger `"fN"`, a
 * percentage stays `"N%"`, and empty input is `null` (reset). Throws on
 * anything else.
 */
export function parseCompactionPointInput(input) {
    const text = input.trim();
    if (text.length === 0)
        return null;
    if (text.endsWith("%")) {
        if (parseThresholdEntry(text, false))
            return text;
        throw new Error(`Invalid compaction point "${text}": percentage must be in (0, 100]`);
    }
    const match = TOKEN_INPUT_PATTERN.exec(text);
    if (match) {
        const scale = match[3] ? TOKEN_SUFFIX_SCALE[match[3].toLowerCase()] : 1;
        const tokens = Number(match[2]) * scale;
        if (parseThresholdEntry(tokens, false))
            return match[1] ? `f${tokens}` : tokens;
    }
    throw new Error(`Invalid compaction point "${text}": use a token count (90000, 90k, 1m), a fixed trigger (f400k) or a percentage (80%)`);
}
/** A threshold pair as text {@link parseCompactionPointInput} reads back: `90k`, `f1500k`, `123456`, `80%`. */
export function formatCompactionPointInput(threshold) {
    if (threshold.thresholdTokens > 0) {
        return `${threshold.fixed ? "f" : ""}${formatTokenCount(threshold.thresholdTokens)}`;
    }
    return `${threshold.thresholdPercent}%`;
}
function formatTokenCount(tokens) {
    for (const suffix of ["b", "m", "k"]) {
        const scale = TOKEN_SUFFIX_SCALE[suffix];
        if (tokens % scale === 0)
            return `${tokens / scale}${suffix}`;
    }
    return String(tokens);
}
