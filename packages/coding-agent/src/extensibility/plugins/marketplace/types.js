/**
 * Marketplace plugin system types.
 *
 * Two registries:
 *   - MarketplacesRegistry: which marketplace catalogs the user has added (config)
 *   - InstalledPluginsRegistry: which plugins are installed (data, Claude Code-compatible)
 *
 * The installed registry MUST pass `parseClaudePluginsRegistry()` validation —
 * it uses `version: 2` (numeric) and `plugins: Record<string, ...[]>`.
 */
// ── Plugin ID helpers ────────────────────────────────────────────────
const NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;
const MAX_NAME_LENGTH = 64;
const MAX_ID_LENGTH = 128;
/** Validate a plugin or marketplace name segment. */
export function isValidNameSegment(s) {
    return s.length > 0 && s.length <= MAX_NAME_LENGTH && NAME_RE.test(s);
}
/** Return the case-insensitive key used to detect cache-path name collisions. */
export function nameSegmentCollisionKey(s) {
    return s.toLowerCase();
}
/** Build canonical plugin ID: `"name@marketplace"`. Both segments are validated. */
export function buildPluginId(name, marketplace) {
    if (!isValidNameSegment(name)) {
        throw new Error(`Invalid plugin name: "${name}"`);
    }
    if (!isValidNameSegment(marketplace)) {
        throw new Error(`Invalid marketplace name: "${marketplace}"`);
    }
    const id = `${name}@${marketplace}`;
    if (id.length > MAX_ID_LENGTH) {
        throw new Error(`Plugin ID exceeds ${MAX_ID_LENGTH} characters: "${id}"`);
    }
    return id;
}
/** Parse `"name@marketplace"` → `{ name, marketplace }` or `null`. */
export function parsePluginId(id) {
    const atIndex = id.lastIndexOf("@");
    if (atIndex <= 0 || atIndex === id.length - 1)
        return null;
    const name = id.slice(0, atIndex);
    const marketplace = id.slice(atIndex + 1);
    if (!isValidNameSegment(name) || !isValidNameSegment(marketplace))
        return null;
    return { name, marketplace };
}
