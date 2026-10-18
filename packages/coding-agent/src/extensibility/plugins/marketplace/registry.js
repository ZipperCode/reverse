/**
 * Registry read/write operations for the marketplace plugin system.
 *
 * Two registries:
 *   - marketplaces.json at getMarketplacesRegistryPath() — which catalogs the user has added
 *   - installed_plugins.json under getPluginsDir() — which plugins are installed
 *
 * Read/write functions accept explicit file paths so callers control the
 * location. Path helpers compute the default paths from the dir singleton.
 *
 * Both use atomic write (tmp + rename). On Windows, rename over existing file
 * can fail with EPERM — fallback: unlink target then rename.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getPluginsDir, isEnoent, logger, tryParseJson } from "@rva/utils";
export { getMarketplacesRegistryPath } from "@rva/utils";
import { nameSegmentCollisionKey } from "./types";
export function getInstalledPluginsRegistryPath() {
    return path.join(getPluginsDir(), "installed_plugins.json");
}
export function getMarketplacesCacheDir() {
    return path.join(getPluginsDir(), "cache", "marketplaces");
}
export function getPluginsCacheDir() {
    return path.join(getPluginsDir(), "cache", "plugins");
}
// ── Atomic write ─────────────────────────────────────────────────────
async function atomicWriteJson(filePath, data) {
    const content = `${JSON.stringify(data, null, 2)}\n`;
    const tmpPath = `${filePath}.tmp`;
    await Bun.write(tmpPath, content);
    try {
        await fs.rename(tmpPath, filePath);
    }
    catch (err) {
        // Windows EPERM fallback: unlink target, then rename
        if (err.code === "EPERM") {
            try {
                await fs.unlink(filePath);
            }
            catch {
                // Target may not exist — that's fine
            }
            await fs.rename(tmpPath, filePath);
        }
        else {
            // Clean up tmp on unexpected errors
            try {
                await fs.unlink(tmpPath);
            }
            catch {
                // Best effort
            }
            throw err;
        }
    }
}
// ── Marketplaces registry ────────────────────────────────────────────
function emptyMarketplacesRegistry() {
    return { version: 1, marketplaces: [] };
}
export async function readMarketplacesRegistry(filePath) {
    try {
        const content = await Bun.file(filePath).text();
        const data = tryParseJson(content);
        if (!data || typeof data !== "object" || data.version !== 1 || !Array.isArray(data.marketplaces)) {
            logger.warn("Invalid marketplaces registry, returning empty", { path: filePath });
            return emptyMarketplacesRegistry();
        }
        return data;
    }
    catch (err) {
        if (isEnoent(err))
            return emptyMarketplacesRegistry();
        throw err;
    }
}
export async function writeMarketplacesRegistry(filePath, reg) {
    await atomicWriteJson(filePath, reg);
}
// ── Installed plugins registry ───────────────────────────────────────
function emptyInstalledPluginsRegistry() {
    return { version: 2, plugins: {} };
}
export async function readInstalledPluginsRegistry(filePath) {
    try {
        const content = await Bun.file(filePath).text();
        const data = tryParseJson(content);
        if (!data ||
            typeof data !== "object" ||
            typeof data.version !== "number" ||
            !data.plugins ||
            typeof data.plugins !== "object" ||
            Array.isArray(data.plugins)) {
            logger.warn("Invalid installed plugins registry, returning empty", { path: filePath });
            return emptyInstalledPluginsRegistry();
        }
        // Accept any numeric version — forward compatible reads
        return { ...data, version: 2 };
    }
    catch (err) {
        if (isEnoent(err))
            return emptyInstalledPluginsRegistry();
        throw err;
    }
}
export async function writeInstalledPluginsRegistry(filePath, reg) {
    await atomicWriteJson(filePath, reg);
}
// ── Marketplace CRUD ─────────────────────────────────────────────────
// Pure functions that transform registry state. Caller is responsible for
// reading, mutating, and writing back.
export function addMarketplaceEntry(reg, entry) {
    const key = nameSegmentCollisionKey(entry.name);
    const existing = reg.marketplaces.find(m => nameSegmentCollisionKey(m.name) === key);
    if (existing) {
        if (existing.name === entry.name) {
            throw new Error(`Marketplace "${entry.name}" already exists`);
        }
        throw new Error(`Marketplace "${entry.name}" conflicts with existing marketplace "${existing.name}" on case-insensitive filesystems`);
    }
    return { ...reg, marketplaces: [...reg.marketplaces, entry] };
}
export function removeMarketplaceEntry(reg, name) {
    const filtered = reg.marketplaces.filter(m => m.name !== name);
    if (filtered.length === reg.marketplaces.length) {
        throw new Error(`Marketplace "${name}" not found`);
    }
    return { ...reg, marketplaces: filtered };
}
export function getMarketplaceEntry(reg, name) {
    return reg.marketplaces.find(m => m.name === name);
}
// ── Installed plugin CRUD ────────────────────────────────────────────
export function addInstalledPlugin(reg, id, entry) {
    const existing = reg.plugins[id] ?? [];
    return {
        ...reg,
        plugins: { ...reg.plugins, [id]: [...existing, entry] },
    };
}
export function removeInstalledPlugin(reg, id) {
    if (!(id in reg.plugins)) {
        throw new Error(`Plugin "${id}" not found in registry`);
    }
    const { [id]: _, ...rest } = reg.plugins;
    return { ...reg, plugins: rest };
}
export function getInstalledPlugin(reg, id) {
    return reg.plugins[id];
}
/**
 * Collect all installPath values referenced by any of the provided registries.
 * Use this before deleting a cached plugin directory to verify it is not still
 * referenced by another scope's registry.
 */
export function collectReferencedPaths(...registries) {
    return new Set(registries.flatMap(r => Object.values(r.plugins)
        .flat()
        .map(e => e.installPath)));
}
