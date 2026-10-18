/**
 * MarketplaceManager — orchestrates registry, fetcher, resolver, and cache.
 *
 * Constructor takes explicit paths for testability (same pattern as registry.ts).
 * The `clearPluginRootsCache` dependency is injected so callers can provide
 * the real `clearClaudePluginRootsCache` while tests supply a counter stub.
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { isEnoent, logger, pathIsWithin } from "@rva/utils";
import { expandTilde } from "../../../tools/path-utils";
import { normalizePluginRuntimeConfig } from "../runtime-config";
import { cachePlugin, getCachedPluginPath, isValidVersionForCache } from "./cache";
import { classifySource, fetchMarketplace, parseMarketplaceCatalog, promoteCloneToCache } from "./fetcher";
import { addInstalledPlugin, addMarketplaceEntry, collectReferencedPaths, getInstalledPlugin, getMarketplaceEntry, readInstalledPluginsRegistry, readMarketplacesRegistry, removeInstalledPlugin, removeMarketplaceEntry, writeInstalledPluginsRegistry, writeMarketplacesRegistry, } from "./registry";
import { resolvePluginSource, validatePluginSource } from "./source-resolver";
import { buildPluginId, nameSegmentCollisionKey, parsePluginId } from "./types";
const RUNTIME_PACKAGE_NAME_RE = /^(?:@[a-zA-Z0-9][a-zA-Z0-9._~-]*\/)?[a-zA-Z0-9][a-zA-Z0-9._~-]*$/;
const MAX_RUNTIME_PACKAGE_NAME_LENGTH = 214;
function assertRuntimePackageName(name) {
    if (name.length > MAX_RUNTIME_PACKAGE_NAME_LENGTH || !RUNTIME_PACKAGE_NAME_RE.test(name)) {
        throw new Error(`Invalid marketplace plugin package name: ${JSON.stringify(name)}`);
    }
    return name;
}
export class MarketplaceManager {
    #opts;
    constructor(options) {
        this.#opts = options;
    }
    // Invalidate fs caches for all registry paths the manager writes, then clear plugin roots.
    #clearCache() {
        const extra = this.#opts.projectInstalledRegistryPath
            ? [this.#opts.projectInstalledRegistryPath]
            : undefined;
        this.#opts.clearPluginRootsCache?.(extra);
    }
    // ── Marketplace lifecycle ─────────────────────────────────────────────────
    async addMarketplace(source) {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        const { catalog, clonePath } = await fetchMarketplace(source, this.#opts.marketplacesCacheDir);
        const catalogKey = nameSegmentCollisionKey(catalog.name);
        const existingName = reg.marketplaces.find(m => nameSegmentCollisionKey(m.name) === catalogKey)?.name;
        if (existingName) {
            if (clonePath) {
                await fs.rm(clonePath, { recursive: true, force: true }).catch(() => { });
            }
            if (existingName === catalog.name) {
                throw new Error(`Marketplace "${catalog.name}" already exists`);
            }
            throw new Error(`Marketplace "${catalog.name}" conflicts with existing marketplace "${existingName}" on case-insensitive filesystems`);
        }
        // Promote the temp clone to its final cache location now that we know it's not a duplicate.
        if (clonePath) {
            await promoteCloneToCache(clonePath, this.#opts.marketplacesCacheDir, catalog.name);
        }
        const sourceType = classifySource(source);
        const normalizedSource = sourceType === "local" ? path.resolve(expandTilde(source)) : source;
        const catalogPath = path.resolve(expandTilde(path.join(this.#opts.marketplacesCacheDir, catalog.name, "marketplace.json")));
        // Persist the fetched catalog so subsequent reads don't require re-fetching.
        await Bun.write(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
        const now = new Date().toISOString();
        const entry = {
            name: catalog.name,
            sourceType,
            sourceUri: normalizedSource,
            catalogPath,
            addedAt: now,
            updatedAt: now,
        };
        const updated = addMarketplaceEntry(reg, entry);
        await writeMarketplacesRegistry(this.#opts.marketplacesRegistryPath, updated);
        logger.debug("Marketplace added", { name: catalog.name, sourceType });
        return entry;
    }
    async removeMarketplace(name) {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        // removeMarketplaceEntry throws if not found — propagate to caller.
        const updated = removeMarketplaceEntry(reg, name);
        await writeMarketplacesRegistry(this.#opts.marketplacesRegistryPath, updated);
        await fs.rm(path.join(this.#opts.marketplacesCacheDir, name), {
            recursive: true,
            force: true,
        });
        logger.debug("Marketplace removed", { name });
    }
    async updateMarketplace(name) {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        const existing = getMarketplaceEntry(reg, name);
        if (!existing) {
            throw new Error(`Marketplace "${name}" not found`);
        }
        const { catalog, clonePath } = await fetchMarketplace(existing.sourceUri, this.#opts.marketplacesCacheDir);
        // Guard against upstream catalog silently renaming itself — the registry
        // entry is keyed by name, so a drift would corrupt the entry on next read.
        if (catalog.name !== name) {
            if (clonePath) {
                await fs.rm(clonePath, { recursive: true, force: true }).catch(() => { });
            }
            throw new Error(`Marketplace catalog name changed from "${name}" to "${catalog.name}". ` +
                `Remove and re-add the marketplace to update.`);
        }
        // Promote the temp clone to its final cache location now that drift check passed.
        if (clonePath) {
            await promoteCloneToCache(clonePath, this.#opts.marketplacesCacheDir, catalog.name);
        }
        // Overwrite the cached catalog and migrate legacy home-relative registry entries.
        const catalogPath = path.resolve(expandTilde(existing.catalogPath));
        await Bun.write(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
        const updatedEntry = {
            ...existing,
            catalogPath,
            updatedAt: new Date().toISOString(),
        };
        const updatedReg = {
            ...reg,
            marketplaces: reg.marketplaces.map(m => (m.name === name ? updatedEntry : m)),
        };
        await writeMarketplacesRegistry(this.#opts.marketplacesRegistryPath, updatedReg);
        logger.debug("Marketplace updated", { name });
        return updatedEntry;
    }
    async updateAllMarketplaces() {
        const marketplaces = await this.listMarketplaces();
        const results = [];
        for (const m of marketplaces) {
            const updated = await this.updateMarketplace(m.name);
            results.push(updated);
        }
        return results;
    }
    async listMarketplaces() {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        return reg.marketplaces;
    }
    // ── Plugin discovery ──────────────────────────────────────────────────────
    async listAvailablePlugins(marketplace) {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        if (marketplace !== undefined) {
            const entry = reg.marketplaces.find(m => m.name === marketplace);
            if (!entry) {
                throw new Error(`Marketplace "${marketplace}" not found`);
            }
            const catalog = await this.#readCatalog(entry);
            return catalog.plugins;
        }
        const all = [];
        for (const entry of reg.marketplaces) {
            const catalog = await this.#readCatalog(entry);
            all.push(...catalog.plugins);
        }
        return all;
    }
    async getPluginInfo(name, marketplace) {
        const plugins = await this.listAvailablePlugins(marketplace);
        return plugins.find(p => p.name === name) ?? null;
    }
    // ── Install / uninstall ───────────────────────────────────────────────────
    async #validateInstall(name, marketplace, options) {
        const force = options?.force ?? false;
        const scope = options?.scope ?? "user";
        const registryPath = this.#registryPath(scope);
        const mktReg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        const mktEntry = getMarketplaceEntry(mktReg, marketplace);
        if (!mktEntry) {
            throw new Error(`Marketplace "${marketplace}" not found`);
        }
        const catalog = await this.#readCatalog(mktEntry);
        const pluginEntry = catalog.plugins.find(p => p.name === name);
        if (!pluginEntry) {
            throw new Error(`Plugin "${name}" not found in marketplace "${marketplace}"`);
        }
        if (typeof pluginEntry.version === "string" &&
            pluginEntry.version.length > 0 &&
            !isValidVersionForCache(pluginEntry.version)) {
            throw new Error(`Invalid version for cache: "${pluginEntry.version}"`);
        }
        const marketplaceClonePath = this.#resolveMarketplaceRoot(mktEntry);
        if (mktEntry.sourceType === "url" && typeof pluginEntry.source === "string") {
            throw new Error(`Plugin "${name}" uses a relative source path but marketplace "${marketplace}" was added via URL. ` +
                `Relative sources require a git or local marketplace. Re-add the marketplace using its git URL.`);
        }
        const sourcePath = await validatePluginSource(pluginEntry, {
            marketplaceClonePath,
            catalogMetadata: catalog.metadata,
        });
        await this.#validateEmbeddedConfigPaths(pluginEntry, sourcePath);
        const pluginId = buildPluginId(name, marketplace);
        const instReg = await readInstalledPluginsRegistry(registryPath);
        const existing = getInstalledPlugin(instReg, pluginId);
        if (existing && existing.length > 0 && !force) {
            throw new Error(`Plugin "${pluginId}" is already installed. Use force option to reinstall.`);
        }
        return { force, scope, registryPath, catalog, marketplaceClonePath, pluginEntry, pluginId, existing };
    }
    async validateInstallPlugin(name, marketplace, options) {
        await this.#validateInstall(name, marketplace, options);
    }
    async installPlugin(name, marketplace, options) {
        const { scope, registryPath, catalog, marketplaceClonePath, pluginEntry, pluginId, existing } = await this.#validateInstall(name, marketplace, options);
        // 4. Resolve source path.
        const { dir: sourcePath, tempCloneRoot } = await resolvePluginSource(pluginEntry, {
            marketplaceClonePath,
            catalogMetadata: catalog.metadata,
            tmpDir: os.tmpdir(),
        });
        // The cache is keyed by marketplace/plugin/version and shared across scopes,
        // so a forced reinstall replaces the copy the OTHER scope also references.
        // Capture that scope's current runtime names from the cache before it is
        // replaced, so a manifest rename can migrate its link/lockfile key too.
        const otherScope = scope === "user" ? "project" : "user";
        const otherRegistryPath = otherScope === "project" ? this.#opts.projectInstalledRegistryPath : this.#opts.installedRegistryPath;
        const otherScopeOldNames = new Map();
        // 5. Resolve registration identity before replacing an active cache. A
        // forced reinstall can reuse the same cache key, so validation after
        // cachePlugin would already have destroyed the prior contents on failure.
        let version;
        let cachePath;
        let packageName;
        let previousPackageNames;
        let otherScopeEntries = [];
        try {
            // Inspecting the other scope reads its manifest and can throw on a
            // malformed package.json; keep it inside the cleanup guard so the temp
            // clone created by resolvePluginSource is still removed on failure.
            otherScopeEntries = otherRegistryPath
                ? (getInstalledPlugin(await readInstalledPluginsRegistry(otherRegistryPath), pluginId) ?? [])
                : [];
            for (const entry of otherScopeEntries) {
                otherScopeOldNames.set(entry.installPath, await this.#resolvePluginPackageName(entry.installPath, name));
            }
            version = (await this.#resolveCatalogVersion(pluginEntry, sourcePath)) ?? "0.0.0";
            packageName = await this.#resolvePluginPackageName(sourcePath, name);
            // Resolve the runtime names this plugin id currently owns BEFORE cachePlugin
            // can overwrite the existing cache. A forced reinstall reuses the same cache
            // key, so reading afterward would see only the new name and strand the old
            // runtime link and lockfile key (e.g. a case-only rename Foo → foo).
            previousPackageNames = await this.#resolveInstalledPackageNames(existing ?? [], name);
            const targetReg = await readInstalledPluginsRegistry(registryPath);
            await this.#assertRuntimePackageNameAvailable(scope, packageName, targetReg, pluginId, previousPackageNames);
            // The cache dir is keyed by marketplace/name/version. On case-insensitive
            // filesystems a different plugin id whose cache path differs only by case
            // (e.g. an old "Foo" still installed after a catalog rename to "foo")
            // resolves to the same dir, so cachePlugin would clobber it. Reject before
            // replacing the cache, checking both scopes' installed registries.
            const prospectiveCachePath = getCachedPluginPath(this.#opts.pluginsCacheDir, marketplace, name, version);
            const registriesToCheck = otherRegistryPath && otherRegistryPath !== registryPath
                ? [targetReg, await readInstalledPluginsRegistry(otherRegistryPath)]
                : [targetReg];
            this.#assertCachePathAvailable(prospectiveCachePath, pluginId, registriesToCheck);
            cachePath = await cachePlugin(sourcePath, this.#opts.pluginsCacheDir, marketplace, name, version);
            await this.#writeEmbeddedLspConfig(pluginEntry, cachePath);
            await this.#writeEmbeddedDapConfig(pluginEntry, cachePath);
        }
        finally {
            // Clean up temp clone dirs created by resolvePluginSource; leave user-supplied local dirs alone
            if (tempCloneRoot) {
                await fs.rm(tempCloneRoot, { recursive: true, force: true }).catch(() => { });
            }
        }
        // Only now clean up old entries — new cache succeeded, so it is safe to remove old ones.
        if (existing && existing.length > 0) {
            // Remove from scope-appropriate registry first, then cross-check refs before disk deletion.
            const prunedReg = removeInstalledPlugin(await readInstalledPluginsRegistry(registryPath), pluginId);
            await writeInstalledPluginsRegistry(registryPath, prunedReg);
            // Read both registries AFTER removal — only delete paths no longer referenced by either.
            const [userReg, projectReg] = await Promise.all([
                readInstalledPluginsRegistry(this.#opts.installedRegistryPath),
                this.#opts.projectInstalledRegistryPath
                    ? readInstalledPluginsRegistry(this.#opts.projectInstalledRegistryPath)
                    : Promise.resolve({ version: 2, plugins: {} }),
            ]);
            const referenced = collectReferencedPaths(userReg, projectReg);
            for (const entry of existing) {
                if (entry.installPath !== cachePath && !referenced.has(entry.installPath)) {
                    await fs.rm(entry.installPath, { recursive: true, force: true });
                }
            }
        }
        // 6. Build and register the entry, preserving enabled state from previous install
        const now = new Date().toISOString();
        // Carry over enabled flag from existing entry — a disabled plugin must stay disabled after upgrade
        const wasDisabled = existing?.some(e => e.enabled === false);
        const installedEntry = {
            scope,
            installPath: cachePath,
            version,
            installedAt: now,
            lastUpdated: now,
            ...(wasDisabled ? { enabled: false } : {}),
        };
        const freshInstReg = await readInstalledPluginsRegistry(registryPath);
        const newInstReg = addInstalledPlugin(freshInstReg, pluginId, installedEntry);
        await writeInstalledPluginsRegistry(registryPath, newInstReg);
        // Carry the renamed-from key's runtime state (feature selection + settings)
        // so a case-only rename preserves the user's configuration.
        let carried;
        for (const previousPackageName of previousPackageNames) {
            if (previousPackageName !== packageName) {
                const removed = await this.#removeRuntimePlugin(scope, previousPackageName);
                carried ??= removed;
            }
        }
        await this.#registerRuntimePlugin(scope, packageName, cachePath, version, wasDisabled ? false : undefined, carried);
        // If this reinstall renamed the runtime key and the other scope references
        // the same (now-replaced) cache, migrate that scope's link and lockfile key
        // too, so it does not resolve the new cache content under the stale name.
        for (const entry of otherScopeEntries) {
            if (entry.installPath !== cachePath)
                continue;
            const oldName = otherScopeOldNames.get(entry.installPath);
            if (oldName === undefined || oldName === packageName)
                continue;
            const removed = await this.#removeRuntimePlugin(otherScope, oldName);
            await this.#registerRuntimePlugin(otherScope, packageName, cachePath, entry.version, entry.enabled === false ? false : undefined, removed);
        }
        this.#clearCache();
        logger.debug("Plugin installed", { pluginId, version, cachePath });
        return installedEntry;
    }
    async #validateEmbeddedConfigPaths(entry, sourcePath) {
        if (!sourcePath)
            return;
        await this.#validateEmbeddedConfigPath(entry, sourcePath, "lspServers", entry.lspServers);
        await this.#validateEmbeddedConfigPath(entry, sourcePath, "dapAdapters", entry.dapAdapters);
    }
    async #validateEmbeddedConfigPath(entry, sourcePath, field, value) {
        if (typeof value !== "string" || value.length === 0)
            return;
        const resolved = path.resolve(sourcePath, value);
        if (!pathIsWithin(sourcePath, resolved)) {
            throw new Error(`Plugin "${entry.name}" ${field} path escapes the plugin directory`);
        }
        try {
            const stat = await fs.stat(resolved);
            if (!stat.isFile())
                throw new Error("not a file");
        }
        catch {
            throw new Error(`Plugin "${entry.name}" ${field} file does not exist`);
        }
    }
    async #writeEmbeddedLspConfig(entry, cachePath) {
        const lspServers = entry.lspServers;
        if (!lspServers)
            return;
        const targetPath = path.join(cachePath, ".lsp.json");
        if (typeof lspServers === "string") {
            const sourcePath = path.resolve(cachePath, lspServers);
            if (!pathIsWithin(cachePath, sourcePath)) {
                throw new Error(`Plugin "${entry.name}" lspServers path escapes the plugin directory`);
            }
            const content = await Bun.file(sourcePath).text();
            await Bun.write(targetPath, content);
            return;
        }
        await Bun.write(targetPath, `${JSON.stringify({ servers: lspServers }, null, 2)}\n`);
    }
    async #writeEmbeddedDapConfig(entry, cachePath) {
        const dapAdapters = entry.dapAdapters;
        if (!dapAdapters)
            return;
        if (typeof dapAdapters === "string") {
            const sourcePath = path.resolve(cachePath, dapAdapters);
            if (!pathIsWithin(cachePath, sourcePath)) {
                throw new Error(`Plugin "${entry.name}" dapAdapters path escapes the plugin directory`);
            }
            const extension = path.extname(sourcePath).toLowerCase();
            const targetFilename = extension === ".yaml" || extension === ".yml" ? `.dap${extension}` : ".dap.json";
            const targetPath = path.join(cachePath, targetFilename);
            const content = await Bun.file(sourcePath).text();
            await Bun.write(targetPath, content);
            return;
        }
        const targetPath = path.join(cachePath, ".dap.json");
        await Bun.write(targetPath, `${JSON.stringify({ adapters: dapAdapters }, null, 2)}\n`);
    }
    /**
     * Resolve the version a catalog entry publishes, so install and {@link checkForUpdates}
     * agree. Relative sources (files in the marketplace clone) use Claude Code's precedence:
     * 1. Plugin manifest (`.claude-plugin/plugin.json`, then Agent Plugins root `plugin.json`)
     * 2. Catalog entry `version`
     * 3. `package.json` version
     * 4. Pinned git SHA from the source definition (truncated to 7 chars)
     *
     * Remote sources are readable only after cloning, so an update check sees the catalog
     * entry alone (`pluginDir` undefined): installs put the entry's version first and checks
     * resolve nothing else, or a manifest/SHA mismatch would report an update forever.
     * `undefined` when nothing declares a version.
     */
    async #resolveCatalogVersion(entry, pluginDir) {
        if (typeof entry.source !== "string" && entry.version)
            return entry.version;
        if (!pluginDir)
            return undefined;
        const readVersion = async (file) => {
            try {
                const content = await Bun.file(path.join(pluginDir, file)).json();
                return typeof content?.version === "string" && content.version ? content.version : undefined;
            }
            catch {
                // Missing or invalid — try next source
                return undefined;
            }
        };
        const manifestVersion = (await readVersion(path.join(".claude-plugin", "plugin.json"))) ?? (await readVersion("plugin.json"));
        if (manifestVersion)
            return manifestVersion;
        if (entry.version)
            return entry.version;
        const packageVersion = await readVersion("package.json");
        if (packageVersion)
            return packageVersion;
        if (typeof entry.source === "object" && "sha" in entry.source && entry.source.sha) {
            return entry.source.sha.slice(0, 7);
        }
        return undefined;
    }
    /** Validates and removes a marketplace plugin, or only validates when `dryRun` is set. */
    async uninstallPlugin(pluginId, scope, options) {
        const parsed = parsePluginId(pluginId);
        if (!parsed) {
            throw new Error(`Invalid plugin ID format: "${pluginId}". Expected "name@marketplace".`);
        }
        const { userEntries, projectEntries, userReg, projectReg } = await this.#findInBothRegistries(pluginId);
        const inUser = userEntries && userEntries.length > 0;
        const inProject = projectEntries && projectEntries.length > 0;
        if (!inUser && !inProject) {
            throw new Error(`Plugin "${pluginId}" is not installed`);
        }
        // Disambiguation: if installed in both scopes and no explicit scope, require one.
        let targetScope;
        if (inUser && inProject) {
            if (!scope) {
                throw new Error(`Plugin "${pluginId}" is installed in both user and project scope. Use --scope user or --scope project to specify which to remove.`);
            }
            targetScope = scope;
        }
        else if (inProject) {
            if (scope === "user") {
                throw new Error(`Plugin "${pluginId}" is not installed in user scope`);
            }
            targetScope = "project";
        }
        else {
            if (scope === "project") {
                throw new Error(`Plugin "${pluginId}" is not installed in project scope`);
            }
            targetScope = "user";
        }
        const targetEntries = targetScope === "project" ? projectEntries : userEntries;
        const targetReg = targetScope === "project" ? projectReg : userReg;
        const registryPath = this.#registryPath(targetScope);
        const packageNames = await this.#resolveInstalledPackageNames(targetEntries, parsed.name);
        if (options?.dryRun) {
            return;
        }
        const updatedReg = removeInstalledPlugin(targetReg, pluginId);
        await writeInstalledPluginsRegistry(registryPath, updatedReg);
        // Read both registries AFTER removal — only delete paths no longer referenced by either.
        const [freshUserReg, freshProjectReg] = await Promise.all([
            readInstalledPluginsRegistry(this.#opts.installedRegistryPath),
            this.#opts.projectInstalledRegistryPath
                ? readInstalledPluginsRegistry(this.#opts.projectInstalledRegistryPath)
                : Promise.resolve({ version: 2, plugins: {} }),
        ]);
        const referenced = collectReferencedPaths(freshUserReg, freshProjectReg);
        for (const entry of targetEntries) {
            if (!referenced.has(entry.installPath)) {
                await fs.rm(entry.installPath, { recursive: true, force: true });
            }
        }
        for (const packageName of packageNames) {
            await this.#removeRuntimePlugin(targetScope, packageName);
        }
        this.#clearCache();
        logger.debug("Plugin uninstalled", { pluginId, scope: targetScope });
    }
    // ── Plugin state ──────────────────────────────────────────────────────────
    async listInstalledPlugins() {
        const userReg = await readInstalledPluginsRegistry(this.#opts.installedRegistryPath);
        const projectReg = this.#opts.projectInstalledRegistryPath
            ? await readInstalledPluginsRegistry(this.#opts.projectInstalledRegistryPath)
            : null;
        // Only enabled project installs shadow user installs — a disabled project copy leaves
        // the user entry as the active one and must not be reported as shadowed.
        const activeProjectIds = new Set(projectReg
            ? Object.entries(projectReg.plugins)
                .filter(([, entries]) => entries.length > 0 && entries[0].enabled !== false)
                .map(([id]) => id)
            : []);
        const results = [];
        // Project entries first
        if (projectReg) {
            for (const [id, entries] of Object.entries(projectReg.plugins)) {
                results.push({ id, scope: "project", entries });
            }
        }
        // User entries (shadow-marked if overridden by project)
        for (const [id, entries] of Object.entries(userReg.plugins)) {
            results.push({
                id,
                scope: "user",
                entries,
                ...(activeProjectIds.has(id) ? { shadowedBy: "project" } : {}),
            });
        }
        return results;
    }
    async setPluginEnabled(pluginId, enabled, scope) {
        const { userEntries, projectEntries, userReg, projectReg } = await this.#findInBothRegistries(pluginId);
        const inUser = userEntries && userEntries.length > 0;
        const inProject = projectEntries && projectEntries.length > 0;
        if (!inUser && !inProject) {
            throw new Error(`Plugin "${pluginId}" is not installed`);
        }
        // Disambiguation: if installed in both scopes and no explicit scope, require one.
        let targetScope;
        if (inUser && inProject) {
            if (!scope) {
                throw new Error(`Plugin "${pluginId}" is installed in both user and project scope. Use --scope user or --scope project to specify which to modify.`);
            }
            targetScope = scope;
        }
        else if (inProject) {
            if (scope === "user") {
                throw new Error(`Plugin "${pluginId}" is not installed in user scope`);
            }
            targetScope = "project";
        }
        else {
            if (scope === "project") {
                throw new Error(`Plugin "${pluginId}" is not installed in project scope`);
            }
            targetScope = "user";
        }
        const reg = targetScope === "project" ? projectReg : userReg;
        const entries = targetScope === "project" ? projectEntries : userEntries;
        const registryPath = this.#registryPath(targetScope);
        const updated = {
            ...reg,
            plugins: {
                ...reg.plugins,
                [pluginId]: entries.map(e => ({ ...e, enabled })),
            },
        };
        await writeInstalledPluginsRegistry(registryPath, updated);
        const fallbackName = parsePluginId(pluginId)?.name ?? pluginId;
        const packageNames = await this.#resolveInstalledPackageNames(entries, fallbackName);
        for (const packageName of packageNames) {
            await this.#setRuntimePluginEnabled(targetScope, packageName, enabled);
        }
        this.#clearCache();
        logger.debug("Plugin enabled state changed", { pluginId, enabled, scope: targetScope });
    }
    // ── Update / upgrade ─────────────────────────────────────────────────────
    // Refresh marketplace catalogs that haven't been updated in more than 24 h.
    // Per-marketplace failures are silently swallowed — offline is fine.
    async refreshStaleMarketplaces() {
        const reg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        const staleMs = 24 * 60 * 60 * 1000;
        for (const entry of reg.marketplaces) {
            if (Date.now() - Date.parse(entry.updatedAt) >= staleMs) {
                try {
                    await this.updateMarketplace(entry.name);
                }
                catch {
                    // Network or parse failure — leave stale, try next time.
                }
            }
        }
    }
    // Compare installed plugin versions against the version each catalog entry currently publishes
    // (see #resolveCatalogVersion). Returns one entry per (pluginId, scope) pair that is outdated.
    // Plugins whose catalog side declares no version are skipped.
    async checkForUpdates() {
        const mktReg = await readMarketplacesRegistry(this.#opts.marketplacesRegistryPath);
        const updates = [];
        // Keyed by (path, scope) so each scope is checked independently.
        // A plugin current in user scope but stale in project scope must still appear.
        const registryEntries = [[this.#opts.installedRegistryPath, "user"]];
        if (this.#opts.projectInstalledRegistryPath) {
            registryEntries.push([this.#opts.projectInstalledRegistryPath, "project"]);
        }
        for (const [regPath, scope] of registryEntries) {
            const instReg = await readInstalledPluginsRegistry(regPath);
            for (const [pluginId, entries] of Object.entries(instReg.plugins)) {
                const parsed = parsePluginId(pluginId);
                if (!parsed)
                    continue;
                const installed = entries[0];
                if (!installed)
                    continue;
                const mktEntry = mktReg.marketplaces.find(m => m.name === parsed.marketplace);
                if (!mktEntry)
                    continue;
                let catalogVersion;
                try {
                    const catalog = await this.#readCatalog(mktEntry);
                    const pluginEntry = catalog.plugins.find(p => p.name === parsed.name);
                    if (!pluginEntry)
                        continue;
                    // Relative sources resolve into the marketplace clone, whose manifests
                    // `updateMarketplace` refreshes; remote sources yield no local dir.
                    const pluginDir = await validatePluginSource(pluginEntry, {
                        marketplaceClonePath: this.#resolveMarketplaceRoot(mktEntry),
                        catalogMetadata: catalog.metadata,
                    });
                    catalogVersion = await this.#resolveCatalogVersion(pluginEntry, pluginDir);
                }
                catch {
                    continue;
                }
                if (!catalogVersion || catalogVersion === installed.version)
                    continue;
                // Treat newer semver as an update; fall back to inequality for non-semver tags.
                let isNewer;
                try {
                    isNewer = Bun.semver.order(catalogVersion, installed.version) > 0;
                }
                catch {
                    isNewer = catalogVersion !== installed.version;
                }
                if (isNewer) {
                    updates.push({ pluginId, scope, from: installed.version, to: catalogVersion });
                }
            }
        }
        return updates;
    }
    // Re-install a specific plugin at the latest catalog version (force-overwrites).
    async upgradePlugin(pluginId, scope) {
        const parsed = parsePluginId(pluginId);
        if (!parsed) {
            throw new Error(`Invalid plugin ID: "${pluginId}". Expected "name@marketplace".`);
        }
        const { userEntries, projectEntries } = await this.#findInBothRegistries(pluginId);
        const inUser = userEntries && userEntries.length > 0;
        const inProject = projectEntries && projectEntries.length > 0;
        if (!inUser && !inProject) {
            throw new Error(`Plugin "${pluginId}" is not installed`);
        }
        let resolvedScope;
        if (inUser && inProject) {
            if (!scope) {
                throw new Error(`Plugin "${pluginId}" is installed in both user and project scope. Use --scope user or --scope project to specify which to upgrade.`);
            }
            resolvedScope = scope;
        }
        else if (inProject) {
            if (scope === "user")
                throw new Error(`Plugin "${pluginId}" is not installed in user scope`);
            resolvedScope = "project";
        }
        else {
            if (scope === "project")
                throw new Error(`Plugin "${pluginId}" is not installed in project scope`);
            resolvedScope = "user";
        }
        return this.installPlugin(parsed.name, parsed.marketplace, { force: true, scope: resolvedScope });
    }
    // Upgrade a plugin across all scopes where it is installed.
    // Returns one entry per scope upgraded (0–2 entries).
    async upgradePluginAcrossScopes(pluginId) {
        const parsed = parsePluginId(pluginId);
        if (!parsed) {
            throw new Error(`Invalid plugin ID: "${pluginId}". Expected "name@marketplace".`);
        }
        const { userEntries, projectEntries } = await this.#findInBothRegistries(pluginId);
        const inUser = userEntries && userEntries.length > 0;
        const inProject = projectEntries && projectEntries.length > 0;
        if (!inUser && !inProject) {
            throw new Error(`Plugin "${pluginId}" is not installed`);
        }
        const results = [];
        if (inProject) {
            const entry = await this.installPlugin(parsed.name, parsed.marketplace, { force: true, scope: "project" });
            results.push(entry);
        }
        if (inUser) {
            const entry = await this.installPlugin(parsed.name, parsed.marketplace, { force: true, scope: "user" });
            results.push(entry);
        }
        return results;
    }
    // Upgrade every (pluginId, scope) pair that checkForUpdates reports as outdated.
    // Only stale scopes are touched; a current user install is not re-installed when only
    // the project scope is stale. Per-entry failures are skipped — partial success is returned.
    async upgradeAllPlugins() {
        const updates = await this.checkForUpdates();
        const results = [];
        for (const update of updates) {
            try {
                const entry = await this.upgradePlugin(update.pluginId, update.scope);
                results.push({ pluginId: update.pluginId, scope: update.scope, from: update.from, to: entry.version });
            }
            catch {
                // Skip this entry; partial upgrades are better than none.
            }
        }
        return results;
    }
    // ── Private helpers ───────────────────────────────────────────────────────
    #runtimeRoot(scope) {
        return path.dirname(this.#registryPath(scope));
    }
    #nodeModulesPath(scope) {
        return path.join(this.#runtimeRoot(scope), "node_modules");
    }
    #runtimeLockPath(scope) {
        return path.join(this.#runtimeRoot(scope), "omp-plugins.lock.json");
    }
    async #loadRuntimeConfig(scope) {
        try {
            return normalizePluginRuntimeConfig(await Bun.file(this.#runtimeLockPath(scope)).json());
        }
        catch (err) {
            if (isEnoent(err))
                return normalizePluginRuntimeConfig({});
            logger.warn("Failed to load marketplace plugin runtime config", {
                path: this.#runtimeLockPath(scope),
                error: String(err),
            });
            return normalizePluginRuntimeConfig({});
        }
    }
    async #writeRuntimeConfig(scope, config) {
        await Bun.write(this.#runtimeLockPath(scope), JSON.stringify(config, null, 2));
    }
    async #resolvePluginPackageName(installPath, fallbackName) {
        try {
            const pkg = await Bun.file(path.join(installPath, "package.json")).json();
            const name = typeof pkg.name === "string" && pkg.name.length > 0 ? pkg.name : fallbackName;
            return assertRuntimePackageName(name);
        }
        catch (err) {
            if (isEnoent(err))
                return assertRuntimePackageName(fallbackName);
            throw err;
        }
    }
    #runtimePackagePath(scope, packageName) {
        const nodeModules = path.resolve(this.#nodeModulesPath(scope));
        const linkPath = path.resolve(nodeModules, assertRuntimePackageName(packageName));
        const relative = path.relative(nodeModules, linkPath);
        if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
            throw new Error(`Marketplace plugin package path escapes node_modules: ${JSON.stringify(packageName)}`);
        }
        return linkPath;
    }
    /**
     * Reject when the prospective cache dir case-collides with a different plugin
     * id's installed cache path. On case-insensitive filesystems those paths are
     * the same directory, so cachePlugin would clobber the other plugin's cache
     * while its registry entry and runtime link keep pointing at it.
     */
    #assertCachePathAvailable(cachePath, pluginId, registries) {
        const key = cachePath.toLowerCase();
        for (const registry of registries) {
            for (const installedPluginId in registry.plugins) {
                if (installedPluginId === pluginId)
                    continue;
                for (const entry of registry.plugins[installedPluginId]) {
                    if (entry.installPath.toLowerCase() === key) {
                        throw new Error(`Plugin cache path for "${pluginId}" case-collides with installed plugin "${installedPluginId}" ` +
                            `on case-insensitive filesystems. Uninstall "${installedPluginId}" first.`);
                    }
                }
            }
        }
    }
    async #assertRuntimePackageNameAvailable(scope, packageName, registry, pluginId, targetScopeOwnNames) {
        const key = packageName.toLowerCase();
        // Marketplace plugins recorded in this scope's installed registry (keyed by plugin id).
        for (const installedPluginId in registry.plugins) {
            if (installedPluginId === pluginId)
                continue;
            const fallbackName = parsePluginId(installedPluginId)?.name ?? installedPluginId;
            const installedNames = await this.#resolveInstalledPackageNames(registry.plugins[installedPluginId], fallbackName);
            for (const installedName of installedNames) {
                if (installedName.toLowerCase() === key) {
                    throw new Error(`Runtime package name "${packageName}" conflicts with installed plugin "${installedPluginId}"`);
                }
            }
        }
        // Names this plugin id already owns in the target scope, so a forced reinstall
        // — including a case-only rename of its own runtime key — is never a
        // self-collision below. Names owned only in the other scope are excluded:
        // that scope has a separate runtime root and node_modules, so they never
        // alias a package in this scope's tree.
        const owned = new Set();
        for (const ownName of targetScopeOwnNames)
            owned.add(ownName.toLowerCase());
        // Ordinary npm plugins (package.json dependencies) and linked plugins
        // (runtime-config entries with no dependency or installed_plugins record)
        // would still have their node_modules link clobbered by registration on a
        // case-insensitive filesystem. Other marketplace plugins also appear in the
        // runtime config but were already rejected by the registry scan above.
        const runtimeNames = await this.#readRuntimeDependencyNames(scope);
        const config = await this.#loadRuntimeConfig(scope);
        for (const configuredName in config.plugins)
            runtimeNames.add(configuredName);
        for (const runtimeName of runtimeNames) {
            const runtimeKey = runtimeName.toLowerCase();
            if (runtimeKey === key && !owned.has(runtimeKey)) {
                throw new Error(`Runtime package name "${packageName}" conflicts with installed package "${runtimeName}"`);
            }
        }
    }
    async #readRuntimeDependencyNames(scope) {
        const names = new Set();
        try {
            const pkg = await Bun.file(path.join(this.#runtimeRoot(scope), "package.json")).json();
            if (pkg.dependencies && typeof pkg.dependencies === "object") {
                for (const dep in pkg.dependencies)
                    names.add(dep);
            }
        }
        catch (err) {
            if (!isEnoent(err))
                throw err;
        }
        return names;
    }
    async #resolveInstalledPackageNames(entries, fallbackName) {
        const packageNames = new Set();
        for (const entry of entries) {
            packageNames.add(await this.#resolvePluginPackageName(entry.installPath, fallbackName));
        }
        return packageNames;
    }
    async #registerRuntimePlugin(scope, packageName, cachePath, version, enabled, carry) {
        const linkPath = this.#runtimePackagePath(scope, packageName);
        await fs.mkdir(path.dirname(linkPath), { recursive: true });
        await fs.rm(linkPath, { recursive: true, force: true });
        await fs.symlink(cachePath, linkPath, process.platform === "win32" ? "junction" : "dir");
        const config = await this.#loadRuntimeConfig(scope);
        const previous = config.plugins[packageName];
        config.plugins[packageName] = {
            version,
            // Carry the renamed-from key's feature/enabled selection so a case-only
            // rename does not silently reset them; an existing entry under the new
            // key still wins.
            enabledFeatures: previous?.enabledFeatures ?? carry?.state?.enabledFeatures ?? null,
            enabled: enabled ?? previous?.enabled ?? carry?.state?.enabled ?? true,
        };
        if (carry?.settings !== undefined && config.settings[packageName] === undefined) {
            config.settings[packageName] = carry.settings;
        }
        await this.#writeRuntimeConfig(scope, config);
    }
    async #removeRuntimePlugin(scope, packageName) {
        await fs.rm(this.#runtimePackagePath(scope, packageName), { recursive: true, force: true });
        const config = await this.#loadRuntimeConfig(scope);
        const state = config.plugins[packageName];
        const settings = config.settings[packageName];
        delete config.plugins[packageName];
        delete config.settings[packageName];
        await this.#writeRuntimeConfig(scope, config);
        return { state, settings };
    }
    async #setRuntimePluginEnabled(scope, packageName, enabled) {
        const config = await this.#loadRuntimeConfig(scope);
        const previous = config.plugins[packageName];
        if (!previous)
            return;
        config.plugins[packageName] = { ...previous, enabled };
        await this.#writeRuntimeConfig(scope, config);
    }
    #registryPath(scope) {
        if (scope === "project") {
            if (!this.#opts.projectInstalledRegistryPath) {
                throw new Error("project-scoped install requires running inside a project directory");
            }
            return this.#opts.projectInstalledRegistryPath;
        }
        return this.#opts.installedRegistryPath;
    }
    async #findInBothRegistries(pluginId) {
        const [userReg, projectReg] = await Promise.all([
            readInstalledPluginsRegistry(this.#opts.installedRegistryPath),
            this.#opts.projectInstalledRegistryPath
                ? readInstalledPluginsRegistry(this.#opts.projectInstalledRegistryPath)
                : Promise.resolve({ version: 2, plugins: {} }),
        ]);
        return {
            userEntries: getInstalledPlugin(userReg, pluginId),
            projectEntries: getInstalledPlugin(projectReg, pluginId),
            userReg,
            projectReg,
        };
    }
    async #readCatalog(entry) {
        const catalogPath = path.resolve(expandTilde(entry.catalogPath));
        try {
            const content = await Bun.file(catalogPath).text();
            return parseMarketplaceCatalog(content, catalogPath);
        }
        catch (err) {
            if (isEnoent(err)) {
                throw new Error(`Marketplace catalog not found at ${catalogPath}. Try: /marketplace update ${entry.name}`);
            }
            throw err;
        }
    }
    /**
     * Compute the marketplace root directory for source resolution.
     *
     * For local sources: sourceUri IS the local path, so resolve it directly.
     * This gives the directory containing `.claude-plugin/marketplace.json`,
     * which is what resolvePluginSource expects as `marketplaceClonePath`.
     *
     * For remote sources (git/github/url): the catalog was cloned into
     * `<marketplacesCacheDir>/<name>/`, so the root is the parent of catalogPath.
     */
    #resolveMarketplaceRoot(entry) {
        if (entry.sourceType === "local") {
            return path.resolve(expandTilde(entry.sourceUri));
        }
        // For git/github/url sources, the catalog lives at <cloneDir>/marketplace.json
        // under marketplacesCacheDir/<name>/; parent = <marketplacesCacheDir>/<name>/
        return path.dirname(path.resolve(expandTilde(entry.catalogPath)));
    }
}
