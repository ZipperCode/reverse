import * as fs from "node:fs";
import * as path from "node:path";
import { $which, isRecord, logger, pathIsWithin } from "@rva/utils";
import { YAML } from "bun";
import { configFileSources, readConfigFile, } from "../utils/config-file-sources";
import { BiomeClient } from "./clients/biome-client";
import { SwiftLintClient } from "./clients/swiftlint-client";
import DEFAULTS from "./defaults.json" with { type: "json" };
// =============================================================================
// Default Server Configuration Loading
// =============================================================================
const PID_TOKEN = "$PID";
/** Parse a config file as YAML (`.yaml`/`.yml`) or JSON. */
export function parseConfigContent(content, filePath) {
    const extension = path.extname(filePath).toLowerCase();
    if (extension === ".yaml" || extension === ".yml") {
        return YAML.parse(content);
    }
    return JSON.parse(content);
}
function normalizeConfig(value) {
    if (!isRecord(value))
        return null;
    const idleTimeoutMs = typeof value.idleTimeoutMs === "number" ? value.idleTimeoutMs : undefined;
    const rawServers = value.servers;
    if (isRecord(rawServers)) {
        return { servers: rawServers, idleTimeoutMs };
    }
    const servers = Object.fromEntries(Object.entries(value).filter(([key]) => key !== "idleTimeoutMs"));
    return { servers, idleTimeoutMs };
}
function normalizeStringArray(value) {
    if (!Array.isArray(value))
        return null;
    const items = value.filter((entry) => typeof entry === "string" && entry.length > 0);
    return items.length > 0 ? items : null;
}
function normalizeExtensionToFileTypes(value) {
    if (!isRecord(value))
        return null;
    const extensions = Object.keys(value).filter(extension => extension.length > 0);
    return extensions.length > 0 ? extensions : null;
}
function normalizeServerConfig(name, config) {
    const command = typeof config.command === "string" && config.command.length > 0 ? config.command : null;
    const fileTypes = normalizeStringArray(config.fileTypes) ?? normalizeExtensionToFileTypes(config.extensionToLanguage);
    const rootMarkers = normalizeStringArray(config.rootMarkers) ?? (config.extensionToLanguage ? ["."] : null);
    const languageId = typeof config.languageId === "string" && config.languageId.length > 0 ? config.languageId : undefined;
    if (!command || !fileTypes || !rootMarkers) {
        logger.warn("Ignoring invalid LSP server config (missing required fields).", { name });
        return null;
    }
    const args = Array.isArray(config.args)
        ? config.args.filter((entry) => typeof entry === "string")
        : undefined;
    const initOptions = isRecord(config.initOptions)
        ? config.initOptions
        : isRecord(config.initializationOptions)
            ? config.initializationOptions
            : undefined;
    return {
        ...config,
        command,
        args,
        fileTypes,
        rootMarkers,
        languageId,
        ...(initOptions ? { initOptions } : {}),
    };
}
const adaptConfig = (content, filePath) => normalizeConfig(parseConfigContent(content, filePath));
function coerceServerConfigs(servers) {
    const result = {};
    for (const [name, config] of Object.entries(servers)) {
        const normalized = normalizeServerConfig(name, config);
        if (normalized) {
            result[name] = normalized;
        }
    }
    return result;
}
function mergeServers(base, overrides) {
    const merged = { ...base };
    for (const [name, config] of Object.entries(overrides)) {
        if (merged[name]) {
            const candidate = { ...merged[name], ...config };
            const normalized = normalizeServerConfig(name, candidate);
            if (normalized) {
                merged[name] = normalized;
            }
            else {
                logger.warn("Ignoring invalid LSP overrides (keeping previous config).", { name });
            }
        }
        else {
            const normalized = normalizeServerConfig(name, config);
            if (normalized) {
                merged[name] = normalized;
            }
        }
    }
    return merged;
}
function applyRuntimeDefaults(servers) {
    const updated = { ...servers };
    if (updated.biome) {
        updated.biome = { ...updated.biome, createClient: BiomeClient.create };
    }
    if (updated.swiftlint) {
        updated.swiftlint = { ...updated.swiftlint, createClient: SwiftLintClient.create };
    }
    if (updated.omnisharp?.args) {
        const args = updated.omnisharp.args.map(arg => (arg === PID_TOKEN ? String(process.pid) : arg));
        updated.omnisharp = { ...updated.omnisharp, args };
    }
    return updated;
}
// =============================================================================
// Configuration Loading
// =============================================================================
/**
 * Check if any root marker file exists in the directory
 */
export function hasRootMarkers(cwd, markers) {
    let entries = null;
    for (const marker of markers) {
        // Handle glob-like patterns (e.g., "*.cabal"). Root markers live at the
        // project root, so a one-level readdir is sufficient — and avoids
        // Bun.Glob descending into node_modules for patterns like "**/*.cabal".
        if (marker.includes("*")) {
            if (entries === null) {
                try {
                    entries = fs.readdirSync(cwd);
                }
                catch {
                    entries = [];
                    logger.warn("Failed to list directory for glob root marker.", { marker, cwd });
                }
            }
            const glob = new Bun.Glob(marker);
            for (const entry of entries) {
                if (glob.match(entry)) {
                    return true;
                }
            }
            continue;
        }
        const filePath = path.join(cwd, marker);
        if (fs.existsSync(filePath)) {
            return true;
        }
    }
    return false;
}
/**
 * Check whether any ancestor directory of a file is an LSP project root.
 */
export function hasRootMarkerAncestor(filePath, markers) {
    if (markers.length === 0)
        return false;
    let dir = path.dirname(path.resolve(filePath));
    while (true) {
        if (hasRootMarkers(dir, markers))
            return true;
        const parent = path.dirname(dir);
        if (parent === dir)
            return false;
        dir = parent;
    }
}
// =============================================================================
// Local Binary Resolution
// =============================================================================
/**
 * Local bin directories to check before $PATH, ordered by priority.
 * Each entry maps a root marker to the bin directory to check.
 */
const PYTHON_ROOT_MARKERS = [
    "pyproject.toml",
    "ty.toml",
    "requirements.txt",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "pyrightconfig.json",
    "ruff.toml",
    ".ruff.toml",
];
const LOCAL_BIN_PATHS = [
    // Node.js - check node_modules/.bin/
    { markers: ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"], binDir: "node_modules/.bin" },
    // Python - check virtual environment bin directories
    { markers: PYTHON_ROOT_MARKERS, binDir: ".venv/bin" },
    { markers: PYTHON_ROOT_MARKERS, binDir: ".venv/Scripts" },
    { markers: PYTHON_ROOT_MARKERS, binDir: "venv/bin" },
    { markers: PYTHON_ROOT_MARKERS, binDir: "venv/Scripts" },
    { markers: PYTHON_ROOT_MARKERS, binDir: ".env/bin" },
    { markers: PYTHON_ROOT_MARKERS, binDir: ".env/Scripts" },
    // Ruby - check vendor bundle and binstubs
    { markers: ["Gemfile", "Gemfile.lock"], binDir: "vendor/bundle/bin" },
    { markers: ["Gemfile", "Gemfile.lock"], binDir: "bin" },
    // Go - check project-local bin
    { markers: ["go.mod", "go.sum", "go.work"], binDir: "bin" },
];
const WINDOWS_LOCAL_EXECUTABLE_EXTENSIONS = [".exe", ".cmd", ".bat"];
function resolveLocalCommand(basePath) {
    if (fs.existsSync(basePath))
        return basePath;
    if (process.platform !== "win32")
        return null;
    // Package managers write Windows launchers with executable suffixes in node_modules/.bin.
    for (const extension of WINDOWS_LOCAL_EXECUTABLE_EXTENSIONS) {
        const candidate = `${basePath}${extension}`;
        if (fs.existsSync(candidate))
            return candidate;
    }
    return null;
}
function resolveCommandFromLocalRoot(command, cwd) {
    for (const { markers, binDir } of LOCAL_BIN_PATHS) {
        if (!hasRootMarkers(cwd, markers))
            continue;
        const resolved = resolveLocalCommand(path.join(cwd, binDir, command));
        if (resolved)
            return resolved;
    }
    return null;
}
/**
 * Resolve a command to an executable path.
 * Checks project-local bin directories first, then falls back to $PATH.
 *
 * @param command - The command name (e.g., "typescript-language-server")
 * @param cwd - Working directory to search from
 * @returns Absolute path to the executable, or null if not found
 */
export function resolveCommand(command, cwd, options) {
    if (options?.localRoots) {
        for (const root of options.localRoots) {
            const resolved = resolveCommandFromLocalRoot(command, root);
            if (resolved)
                return resolved;
        }
    }
    else {
        const resolved = resolveCommandFromLocalRoot(command, cwd);
        if (resolved)
            return resolved;
    }
    if (!options)
        return $which(command);
    return $which(command, { cache: options.cache, PATH: options.PATH });
}
// =============================================================================
// TypeScript Server Selection
// =============================================================================
/**
 * Directory of the package that owns a resolved `tsc`/`tsgo` launcher, or null
 * when the layout is not a recognizable npm install.
 */
function typescriptPackageDir(tscPath) {
    let realPath = tscPath;
    try {
        realPath = fs.realpathSync(tscPath);
    }
    catch { }
    const binDir = path.dirname(tscPath);
    const candidates = [
        // <pkg>/bin/tsc: symlinked node_modules/.bin and global installs
        ...(path.basename(path.dirname(realPath)) === "bin" ? [path.dirname(path.dirname(realPath))] : []),
        // node_modules/.bin/tsc.cmd on Windows
        path.join(binDir, "..", "typescript"),
        // npm global prefix on Windows
        path.join(binDir, "node_modules", "typescript"),
    ];
    for (const dir of candidates) {
        if (fs.existsSync(path.join(dir, "package.json")))
            return dir;
    }
    return null;
}
/**
 * Whether the `tsc` at `tscPath` speaks LSP itself. TypeScript 7 dropped the JS
 * `lib/tsserver.js` that typescript-language-server wraps and exposes
 * `tsc --lsp --stdio` from its native binary instead; older releases reject the
 * flag with TS5023.
 */
function typescriptSpeaksLsp(tscPath) {
    const packageDir = typescriptPackageDir(tscPath);
    return packageDir !== null && !fs.existsSync(path.join(packageDir, "lib", "tsserver.js"));
}
/**
 * Keep exactly one TypeScript server. `typescript-language-server` needs
 * `lib/tsserver.js`, which a TypeScript 7 workspace no longer ships, so it fails
 * at initialize there; `tsc --lsp` exits on older TypeScript. Pick by inspecting
 * the resolved `tsc` install rather than spawning both.
 */
function selectTypescriptServer(servers) {
    const native = servers["typescript-native"];
    if (!native?.resolvedCommand)
        return;
    if (typescriptSpeaksLsp(native.resolvedCommand)) {
        delete servers["typescript-language-server"];
    }
    else {
        delete servers["typescript-native"];
    }
}
function readMarketplaceLspConfig(root) {
    const catalogPaths = [
        path.resolve(root.path, "..", "..", "marketplace.json"),
        path.resolve(root.path, "..", "..", ".claude-plugin", "marketplace.json"),
    ];
    for (const catalogPath of catalogPaths) {
        try {
            const catalog = JSON.parse(fs.readFileSync(catalogPath, "utf-8"));
            if (!isRecord(catalog) || !Array.isArray(catalog.plugins))
                continue;
            for (const plugin of catalog.plugins) {
                if (!isRecord(plugin) || plugin.name !== root.plugin)
                    continue;
                const lspServers = plugin.lspServers;
                if (typeof lspServers === "string") {
                    const configPath = path.resolve(root.path, lspServers);
                    if (!pathIsWithin(root.path, configPath))
                        return null;
                    return readConfigFile(configPath, adaptConfig);
                }
                if (isRecord(lspServers)) {
                    return normalizeConfig({ servers: lspServers });
                }
                return null;
            }
        }
        catch { }
    }
    return null;
}
function marketplaceConfigSource(root) {
    return {
        read: () => readMarketplaceLspConfig(root),
    };
}
/**
 * Load LSP configuration.
 *
 * Priority (highest to lowest):
 * 1. Project root: lsp.json/.lsp.json/lsp.yml/.lsp.yml/lsp.yaml/.lsp.yaml
 * 2. Project config dirs: .omp/lsp.*, .pi/lsp.*, .claude/lsp.* (+ hidden variants)
 * 3. User config dirs: ~/.omp/agent/lsp.*, ~/.pi/agent/lsp.*, ~/.claude/lsp.* (+ hidden variants)
 * 4. User home root: ~/lsp.*, ~/.lsp.*
 * 5. Auto-detect from project markers + available binaries
 *
 * Config files are merged from lowest to highest priority; later files override earlier settings.
 *
 * Config file format (JSON or YAML):
 * ```json
 * {
 *   "servers": {
 *     "typescript-language-server": {
 *       "command": "typescript-language-server",
 *       "args": ["--stdio", "--log-level", "4"],
 *       "disabled": false
 *     },
 *     "my-custom-server": {
 *       "command": "/path/to/server",
 *       "args": ["--stdio"],
 *       "fileTypes": [".xyz"],
 *       "languageId": "xyz",
 *       "rootMarkers": [".xyz-project"]
 *     }
 *   }
 * }
 * ```
 */
export function loadConfig(cwd) {
    let mergedServers = coerceServerConfigs(DEFAULTS);
    const configSources = configFileSources("lsp", cwd, adaptConfig, {
        pluginRootSource: marketplaceConfigSource,
    }).reverse();
    let idleTimeoutMs;
    for (const source of configSources) {
        const parsed = source.read();
        if (!parsed)
            continue;
        mergedServers = mergeServers(mergedServers, parsed.servers);
        if (parsed.idleTimeoutMs !== undefined) {
            idleTimeoutMs = parsed.idleTimeoutMs;
        }
    }
    // Filter to servers whose project markers exist and whose binary resolves (local or $PATH)
    const servers = {};
    const candidates = applyRuntimeDefaults(mergedServers);
    for (const name in candidates) {
        const config = candidates[name];
        if (config.disabled)
            continue;
        if (!hasRootMarkers(cwd, config.rootMarkers))
            continue;
        const resolved = resolveCommand(config.command, cwd);
        if (!resolved)
            continue;
        servers[name] = { ...config, resolvedCommand: resolved };
    }
    selectTypescriptServer(servers);
    return { servers, idleTimeoutMs };
}
// Cache config per cwd to avoid repeated file I/O
export const configCache = new Map();
export function getConfig(cwd) {
    let config = configCache.get(cwd);
    if (!config) {
        config = loadConfig(cwd);
        configCache.set(cwd, config);
    }
    return config;
}
// =============================================================================
// Server Selection
// =============================================================================
/**
 * Find all servers that can handle a file based on extension.
 * Returns servers sorted with primary (non-linter) servers first.
 */
export function getServersForFile(config, filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const extNoDot = ext.startsWith(".") ? ext.slice(1) : ext;
    const fileName = path.basename(filePath).toLowerCase();
    const matches = [];
    for (const [name, serverConfig] of Object.entries(config.servers)) {
        const supportsFile = serverConfig.fileTypes.some(fileType => {
            // Accept both `.ts` and `ts` forms in user config / fixtures so a
            // missing dot in `fileTypes` doesn't silently exclude the server
            // from extension-based routing (e.g. rename_file's relevance filter).
            const normalized = fileType.toLowerCase();
            const normalizedNoDot = normalized.startsWith(".") ? normalized.slice(1) : normalized;
            return (normalized === ext ||
                normalized === fileName ||
                normalizedNoDot === extNoDot ||
                normalizedNoDot === fileName);
        });
        if (supportsFile) {
            matches.push([name, serverConfig]);
        }
    }
    // Sort: primary servers (non-linters) first, then linters
    return matches.sort((a, b) => {
        const aIsLinter = a[1].isLinter ? 1 : 0;
        const bIsLinter = b[1].isLinter ? 1 : 0;
        return aIsLinter - bIsLinter;
    });
}
/**
 * Find the primary server for a file (prefers type-checkers over linters).
 * Used for operations like definition, hover, references that need type intelligence.
 */
export function getServerForFile(config, filePath) {
    const servers = getServersForFile(config, filePath);
    return servers.length > 0 ? servers[0] : null;
}
/**
 * Check if a server has a specific capability
 */
export function hasCapability(config, capability) {
    return config.capabilities?.[capability] === true;
}
