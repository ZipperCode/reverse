/** Calculate age in seconds from an ISO date string. Returns undefined on invalid input. */
export function dateToAgeSeconds(dateStr) {
    if (!dateStr)
        return undefined;
    try {
        const date = new Date(dateStr);
        if (Number.isNaN(date.getTime()))
            return undefined;
        return Math.floor((Date.now() - date.getTime()) / 1000);
    }
    catch {
        return undefined;
    }
}
/** Clamp a result count to [1, maxVal], returning defaultVal when value is absent or NaN. */
export function clampNumResults(value, defaultVal, maxVal) {
    if (!value || Number.isNaN(value))
        return defaultVal;
    return Math.min(maxVal, Math.max(1, value));
}
