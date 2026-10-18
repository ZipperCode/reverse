function canonicalize(value) {
    if (Array.isArray(value))
        return value.map(canonicalize);
    if (!value || typeof value !== "object")
        return value;
    const record = value;
    const result = {};
    for (const key of Object.keys(record).sort()) {
        const item = record[key];
        if (item !== undefined)
            result[key] = canonicalize(item);
    }
    return result;
}
export function canonicalSecurityJson(value) {
    return JSON.stringify(canonicalize(value));
}
function normalizeFingerprintPath(value) {
    return value.replaceAll("\\", "/").replace(/^\.\//, "");
}
function compareNormalizedLocationValues(left, right) {
    if (left === right)
        return 0;
    if (left === undefined)
        return -1;
    if (right === undefined)
        return 1;
    if (typeof left === "number" && typeof right === "number") {
        const leftNaN = Number.isNaN(left);
        const rightNaN = Number.isNaN(right);
        if (leftNaN || rightNaN)
            return leftNaN ? (rightNaN ? 0 : -1) : 1;
        return left - right;
    }
    return String(left) < String(right) ? -1 : 1;
}
const NORMALIZED_LOCATION_SORT_KEYS = ["path", "startLine", "endLine", "startColumn", "endColumn", "role"];
function normalizedLocations(locations) {
    return locations
        .map(location => ({
        path: normalizeFingerprintPath(location.path),
        startLine: location.startLine,
        endLine: location.endLine,
        startColumn: location.startColumn,
        endColumn: location.endColumn,
        role: location.role,
    }))
        .sort((left, right) => {
        for (const key of NORMALIZED_LOCATION_SORT_KEYS) {
            const comparison = compareNormalizedLocationValues(left[key], right[key]);
            if (comparison !== 0)
                return comparison;
        }
        return 0;
    });
}
export function createSecurityFindingFingerprint(input) {
    const digest = Bun.SHA256.hash(canonicalSecurityJson({
        ruleId: input.ruleId.trim().toLowerCase(),
        category: input.category.trim().toLowerCase(),
        anchor: input.anchor?.trim().toLowerCase() || undefined,
        locations: normalizedLocations(input.locations),
    }), "hex");
    return `omp-security/v1:sha256:${digest}`;
}
export function createSecurityFindingId(fingerprint) {
    return `secf_${Bun.SHA256.hash(fingerprint, "hex").slice(0, 24)}`;
}
export function createSecurityOccurrenceId(fingerprint, locations) {
    const material = canonicalSecurityJson({ fingerprint, locations: normalizedLocations(locations) });
    return `seco_${Bun.SHA256.hash(material, "hex").slice(0, 24)}`;
}
export function createSecurityEvidenceId(fingerprint, label, ordinal) {
    return `sece_${Bun.SHA256.hash(canonicalSecurityJson({ fingerprint, label, ordinal }), "hex").slice(0, 24)}`;
}
export function createSecurityScanId(randomUuid = () => Bun.randomUUIDv7()) {
    return `secscan_${randomUuid().replaceAll("-", "")}`;
}
export function createSecurityPlanId(fingerprint) {
    return `secplan_${Bun.SHA256.hash(fingerprint, "hex").slice(0, 24)}`;
}
export function encodeSecurityProjectKey(repositoryRoot) {
    const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
    const readable = normalized
        .replace(/^\//, "")
        .replace(/[^a-zA-Z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(-80);
    return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}
