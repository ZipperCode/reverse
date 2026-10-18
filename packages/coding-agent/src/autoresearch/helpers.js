import * as vcs from "@rva/natives/vcs";
export const METRIC_LINE_PREFIX = "METRIC";
export const ASI_LINE_PREFIX = "ASI";
export const EXPERIMENT_MAX_LINES = 10;
export const EXPERIMENT_MAX_BYTES = 4 * 1024;
const DENIED_KEY_NAMES = new Set(["__proto__", "constructor", "prototype"]);
const METRIC_LINE_PATTERN = `^${METRIC_LINE_PREFIX}\\s+([\\w.µ-]+)=(\\S+)\\s*$`;
const ASI_LINE_PATTERN = `^${ASI_LINE_PREFIX}\\s+([\\w.-]+)=(.+)\\s*$`;
/** Characters `^`/`$` treat as line boundaries under the `m` flag. */
const LINE_TERMINATOR_RE = /[\n\r\u2028\u2029]/g;
const NON_WHITESPACE_RE = /\S/g;
function indexOfPattern(re, text, from) {
    re.lastIndex = from;
    return re.exec(text)?.index ?? -1;
}
/**
 * Streaming equivalent of {@link parseMetricLines} + {@link parseAsiLines}: feed output
 * chunks with {@link append}, then {@link finish}. Only the unfinished trailing line (or a
 * prefix line still awaiting its `name=value` continuation) is buffered, so memory stays
 * O(line) instead of O(output) while yielding the same results as parsing the full text.
 */
export class ExperimentOutputScanner {
    #carry = "";
    #metrics = new Map();
    #asi = {};
    #metricRe = new RegExp(METRIC_LINE_PATTERN, "my");
    #asiRe = new RegExp(ASI_LINE_PATTERN, "my");
    append(chunk) {
        if (!chunk)
            return;
        this.#carry += chunk;
        this.#scan(false);
    }
    finish() {
        this.#scan(true);
        return { metrics: this.#metrics, asi: Object.keys(this.#asi).length > 0 ? this.#asi : null };
    }
    #scan(final) {
        const carry = this.#carry;
        let pos = 0;
        while (pos < carry.length) {
            const lineEnd = indexOfPattern(LINE_TERMINATOR_RE, carry, pos);
            if (lineEnd < 0 && !final)
                break;
            const prefixLength = carry.startsWith(METRIC_LINE_PREFIX, pos)
                ? METRIC_LINE_PREFIX.length
                : carry.startsWith(ASI_LINE_PREFIX, pos)
                    ? ASI_LINE_PREFIX.length
                    : 0;
            if (prefixLength > 0) {
                // `\s+` after the prefix may span lines: wait until the first non-blank
                // continuation line is terminated before matching.
                const valueStart = indexOfPattern(NON_WHITESPACE_RE, carry, pos + prefixLength);
                const valueLineEnd = valueStart < 0 ? -1 : indexOfPattern(LINE_TERMINATOR_RE, carry, valueStart);
                if (valueLineEnd < 0 && !final)
                    break;
                this.#matchAt(carry, pos);
            }
            if (lineEnd < 0) {
                pos = carry.length;
                break;
            }
            pos = lineEnd + 1;
        }
        this.#carry = pos === 0 ? carry : carry.slice(pos);
    }
    #matchAt(text, pos) {
        this.#metricRe.lastIndex = pos;
        const metric = this.#metricRe.exec(text);
        if (metric && !DENIED_KEY_NAMES.has(metric[1])) {
            const value = Number(metric[2]);
            if (Number.isFinite(value))
                this.#metrics.set(metric[1], value);
        }
        this.#asiRe.lastIndex = pos;
        const asi = this.#asiRe.exec(text);
        if (asi && !DENIED_KEY_NAMES.has(asi[1]))
            this.#asi[asi[1]] = parseAsiValue(asi[2]);
    }
}
export function parseMetricLines(output) {
    const metrics = new Map();
    const regex = new RegExp(METRIC_LINE_PATTERN, "gm");
    let match = regex.exec(output);
    while (match !== null) {
        const name = match[1];
        if (!DENIED_KEY_NAMES.has(name)) {
            const value = Number(match[2]);
            if (Number.isFinite(value)) {
                metrics.set(name, value);
            }
        }
        match = regex.exec(output);
    }
    return metrics;
}
export function parseAsiLines(output) {
    const asi = {};
    const regex = new RegExp(ASI_LINE_PATTERN, "gm");
    let match = regex.exec(output);
    while (match !== null) {
        const key = match[1];
        if (!DENIED_KEY_NAMES.has(key)) {
            asi[key] = parseAsiValue(match[2]);
        }
        match = regex.exec(output);
    }
    return Object.keys(asi).length > 0 ? asi : null;
}
function parseAsiValue(raw) {
    const value = raw.trim();
    if (value === "true")
        return true;
    if (value === "false")
        return false;
    if (value === "null")
        return null;
    if (/^-?\d+(?:\.\d+)?$/.test(value)) {
        const numberValue = Number(value);
        if (Number.isFinite(numberValue))
            return numberValue;
    }
    if (value.startsWith("{") || value.startsWith("[") || value.startsWith('"')) {
        try {
            const parsed = JSON.parse(value);
            return parsed;
        }
        catch {
            return value;
        }
    }
    return value;
}
export function mergeAsi(base, override) {
    if (!base && !override)
        return undefined;
    return {
        ...base,
        ...override,
    };
}
export function killTree(pid, signal = "SIGTERM") {
    try {
        process.kill(-pid, signal);
    }
    catch {
        try {
            process.kill(pid, signal);
        }
        catch {
            // Process already exited.
        }
    }
}
export function inferMetricUnitFromName(name) {
    if (name.endsWith("µs") || name.endsWith("_µs"))
        return "µs";
    if (name.endsWith("ms") || name.endsWith("_ms"))
        return "ms";
    if (name.endsWith("_s") || name.endsWith("_sec") || name.endsWith("_secs"))
        return "s";
    if (name.endsWith("_kb") || name.endsWith("kb"))
        return "kb";
    if (name.endsWith("_mb") || name.endsWith("mb"))
        return "mb";
    return "";
}
export function normalizePathSpec(value) {
    const trimmed = value.trim().replaceAll("\\", "/");
    if (trimmed === "" || trimmed === "." || trimmed === "./")
        return ".";
    const collapsed = trimmed.replace(/^\.\/+/, "").replace(/\/+$/, "");
    return collapsed.length === 0 ? "." : collapsed;
}
export function pathMatchesSpec(pathValue, specValue) {
    const normalizedPath = normalizePathSpec(pathValue);
    const normalizedSpec = normalizePathSpec(specValue);
    if (normalizedSpec === ".")
        return true;
    return normalizedPath === normalizedSpec || normalizedPath.startsWith(`${normalizedSpec}/`);
}
export function dedupeStrings(values) {
    const out = [];
    const seen = new Set();
    for (const value of values) {
        const trimmed = value.trim();
        if (trimmed.length === 0 || seen.has(trimmed))
            continue;
        seen.add(trimmed);
        out.push(trimmed);
    }
    return out;
}
export function ensureNumericMetricMap(value) {
    if (!value)
        return {};
    const out = {};
    for (const [key, entryValue] of Object.entries(value)) {
        if (DENIED_KEY_NAMES.has(key))
            continue;
        if (typeof entryValue === "number" && Number.isFinite(entryValue)) {
            out[key] = entryValue;
        }
    }
    return out;
}
export function sanitizeAsi(value) {
    if (!value)
        return undefined;
    const result = {};
    for (const [key, entryValue] of Object.entries(value)) {
        if (DENIED_KEY_NAMES.has(key))
            continue;
        const sanitized = sanitizeAsiValue(entryValue);
        if (sanitized !== undefined) {
            result[key] = sanitized;
        }
    }
    return Object.keys(result).length > 0 ? result : undefined;
}
function sanitizeAsiValue(value) {
    if (value === null)
        return null;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
        return value;
    if (Array.isArray(value)) {
        const items = value
            .map(item => sanitizeAsiValue(item))
            .filter((item) => item !== undefined);
        return items;
    }
    if (typeof value === "object") {
        const objectValue = value;
        const result = {};
        for (const [key, entryValue] of Object.entries(objectValue)) {
            if (DENIED_KEY_NAMES.has(key))
                continue;
            const sanitized = sanitizeAsiValue(entryValue);
            if (sanitized !== undefined) {
                result[key] = sanitized;
            }
        }
        return result;
    }
    return undefined;
}
export async function tryGitStatus(cwd) {
    try {
        return await vcs.require(cwd).statusPorcelain({ untracked: "all", nulTerminated: true });
    }
    catch {
        return "";
    }
}
export async function tryGitPrefix(cwd) {
    try {
        return vcs.require(cwd).prefixOf(cwd) ?? "";
    }
    catch {
        return "";
    }
}
