import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isRecord, logger, WhichCachePolicy } from "@rva/utils";
import { hasRootMarkers, parseConfigContent, resolveCommand } from "../lsp/config";
import { configFileSources } from "../utils/config-file-sources";
import DEFAULTS from "./defaults.json" with { type: "json" };
const EXTENSIONLESS_DEBUGGER_ORDER = ["gdb", "lldb-dap"];
const JS_DEBUG_SERVER_ENV = "JS_DEBUG_DAP_SERVER";
const DAP_PORT_ARGUMENT = "$" + "{port}";
function normalizeConfig(value) {
    if (!isRecord(value))
        return null;
    if (isRecord(value.adapters))
        return { adapters: value.adapters };
    return { adapters: value };
}
function normalizeStringArray(value) {
    if (!Array.isArray(value))
        return [];
    return value.filter((entry) => typeof entry === "string" && entry.length > 0);
}
function normalizeObject(value) {
    return isRecord(value) ? { ...value } : {};
}
function normalizeAdapterConfig(config) {
    if (!isRecord(config))
        return null;
    if (typeof config.command !== "string" || config.command.length === 0)
        return null;
    const connectMode = config.connectMode === "socket" || config.connectMode === "tcp" ? config.connectMode : undefined;
    return {
        command: config.command,
        args: normalizeStringArray(config.args),
        languages: normalizeStringArray(config.languages),
        fileTypes: normalizeStringArray(config.fileTypes).map(entry => entry.toLowerCase()),
        rootMarkers: normalizeStringArray(config.rootMarkers),
        launchDefaults: normalizeObject(config.launchDefaults),
        attachDefaults: normalizeObject(config.attachDefaults),
        acceptsDirectoryProgram: config.acceptsDirectoryProgram === true,
        ...(connectMode ? { connectMode } : {}),
    };
}
const adaptConfig = (content, filePath) => normalizeConfig(parseConfigContent(content, filePath));
function getDefaults() {
    const adapters = {};
    for (const [name, config] of Object.entries(DEFAULTS)) {
        const normalized = normalizeAdapterConfig(config);
        if (normalized) {
            adapters[name] = normalized;
        }
    }
    return adapters;
}
const DEFAULT_ADAPTERS = getDefaults();
function mergeAdapters(base, overrides) {
    const merged = { ...base };
    for (const [name, config] of Object.entries(overrides)) {
        const existing = merged[name];
        const candidate = isRecord(existing) && isRecord(config)
            ? {
                ...existing,
                ...config,
                launchDefaults: isRecord(existing.launchDefaults) || isRecord(config.launchDefaults)
                    ? { ...existing.launchDefaults, ...normalizeObject(config.launchDefaults) }
                    : undefined,
                attachDefaults: isRecord(existing.attachDefaults) || isRecord(config.attachDefaults)
                    ? { ...existing.attachDefaults, ...normalizeObject(config.attachDefaults) }
                    : undefined,
            }
            : config;
        const normalized = normalizeAdapterConfig(candidate);
        if (normalized) {
            merged[name] = normalized;
        }
        else if (merged[name]) {
            logger.warn("Ignoring invalid DAP adapter override (keeping previous config).", { name });
        }
        else {
            logger.warn("Ignoring invalid DAP adapter config.", { name });
        }
    }
    return merged;
}
function loadAdapterConfigs(cwd) {
    let adapters = { ...DEFAULT_ADAPTERS };
    for (const source of configFileSources("dap", cwd, adaptConfig).reverse()) {
        const parsed = source.read();
        if (!parsed)
            continue;
        adapters = mergeAdapters(adapters, parsed.adapters);
    }
    return adapters;
}
export function getAdapterConfigs(cwd) {
    return cwd ? loadAdapterConfigs(cwd) : { ...DEFAULT_ADAPTERS };
}
function normalizeCommandForCwd(command, cwd) {
    if (path.isAbsolute(command))
        return command;
    if (command.startsWith("./") ||
        command.startsWith("../") ||
        command.startsWith(".\\") ||
        command.startsWith("..\\")) {
        return path.resolve(cwd, command);
    }
    return command;
}
function resolveJsDebugServerPath(cwd) {
    const configured = process.env[JS_DEBUG_SERVER_ENV];
    const dataHome = process.env.XDG_DATA_HOME ?? path.join(os.homedir(), ".local", "share");
    const candidates = [
        ...(configured ? [path.resolve(cwd, configured)] : []),
        path.join(dataHome, "nvim", "mason", "packages", "js-debug-adapter", "js-debug", "src", "dapDebugServer.js"),
        path.join(os.homedir(), ".local", "opt", "js-debug", "src", "dapDebugServer.js"),
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate))
            return candidate;
    }
    return null;
}
function resolveDefaultJsDebugAdapter(adapterName, config, cwd, localRoots) {
    if (adapterName !== "js-debug-adapter" || config.command !== "js-debug-adapter") {
        return undefined;
    }
    const serverPath = resolveJsDebugServerPath(cwd);
    if (!serverPath)
        return null;
    const nodeCommand = resolveCommand("node", cwd, {
        cache: WhichCachePolicy.Fresh,
        PATH: process.env.PATH,
        localRoots,
    });
    const resolvedCommand = nodeCommand ?? process.execPath;
    return {
        name: adapterName,
        command: nodeCommand ? "node" : "bun",
        args: [serverPath, DAP_PORT_ARGUMENT, "127.0.0.1"],
        resolvedCommand,
        languages: config.languages ?? [],
        fileTypes: config.fileTypes ?? [],
        rootMarkers: config.rootMarkers ?? [],
        launchDefaults: config.launchDefaults ?? {},
        attachDefaults: config.attachDefaults ?? {},
        connectMode: "tcp",
        acceptsDirectoryProgram: config.acceptsDirectoryProgram === true,
    };
}
function resolveAdapterFromConfig(adapterName, configs, cwd, localRoots) {
    const config = configs[adapterName];
    if (!config)
        return null;
    const jsDebugAdapter = resolveDefaultJsDebugAdapter(adapterName, config, cwd, localRoots);
    if (jsDebugAdapter !== undefined)
        return jsDebugAdapter;
    const normalizedCommand = normalizeCommandForCwd(config.command, cwd);
    const commandIsBare = !path.isAbsolute(config.command) && !config.command.includes("/") && !config.command.includes("\\");
    const resolvedCommand = resolveCommand(normalizedCommand, cwd, {
        cache: WhichCachePolicy.Fresh,
        PATH: process.env.PATH,
        localRoots: commandIsBare ? localRoots : undefined,
    });
    if (!resolvedCommand)
        return null;
    return {
        name: adapterName,
        command: config.command,
        args: config.args ?? [],
        resolvedCommand,
        languages: config.languages ?? [],
        fileTypes: config.fileTypes ?? [],
        rootMarkers: config.rootMarkers ?? [],
        launchDefaults: config.launchDefaults ?? {},
        attachDefaults: config.attachDefaults ?? {},
        connectMode: config.connectMode ?? "stdio",
        acceptsDirectoryProgram: config.acceptsDirectoryProgram === true,
    };
}
export function resolveAdapter(adapterName, cwd) {
    return resolveAdapterFromConfig(adapterName, getAdapterConfigs(cwd), cwd);
}
export function getAvailableAdapters(cwd) {
    const configs = getAdapterConfigs(cwd);
    return Object.keys(configs)
        .map(name => resolveAdapterFromConfig(name, configs, cwd))
        .filter((adapter) => adapter !== null);
}
function findRootMarkerInLaunchAncestry(program, cwd, markers, programKind) {
    if (markers.length === 0)
        return null;
    let dir = programKind === "directory" ? path.resolve(cwd, program) : path.dirname(path.resolve(cwd, program));
    while (true) {
        if (hasRootMarkers(dir, markers))
            return dir;
        const parent = path.dirname(dir);
        if (parent === dir)
            return null;
        dir = parent;
    }
}
function resolveAdapterForLaunch(adapterName, configs, cwd, rootDir) {
    const localRoots = rootDir && rootDir !== cwd ? [rootDir, cwd] : undefined;
    return resolveAdapterFromConfig(adapterName, configs, cwd, localRoots);
}
function unavailableAdapter(candidate, configs) {
    const config = configs[candidate.name];
    if (!config)
        return { kind: "none" };
    return { kind: "unavailable", adapterName: candidate.name, command: config.command };
}
function selectAutomaticLaunchAdapter(program, cwd, programKind, configs) {
    const extension = path.extname(program).toLowerCase();
    if (extension) {
        const configured = [];
        const available = [];
        for (const name in configs) {
            const config = configs[name];
            if (!config || !(config.fileTypes ?? []).includes(extension))
                continue;
            const rootDir = findRootMarkerInLaunchAncestry(program, cwd, config.rootMarkers ?? [], programKind);
            configured.push({ name, rootDir });
            const adapter = resolveAdapterForLaunch(name, configs, cwd, rootDir);
            if (adapter)
                available.push(adapter);
        }
        const selected = sortAdaptersForLaunch(program, cwd, programKind, available)[0];
        if (selected)
            return { kind: "adapter", adapter: selected };
        const rootMatch = configured.find(candidate => candidate.rootDir !== null);
        const unavailable = rootMatch ?? configured[0];
        if (unavailable)
            return unavailableAdapter(unavailable, configs);
    }
    const available = [];
    const rootMatches = [];
    const directoryMatches = [];
    for (const name in configs) {
        const config = configs[name];
        if (!config)
            continue;
        const rootDir = findRootMarkerInLaunchAncestry(program, cwd, config.rootMarkers ?? [], programKind);
        const candidate = { name, rootDir };
        if (rootDir) {
            rootMatches.push(candidate);
            if (config.acceptsDirectoryProgram === true)
                directoryMatches.push(candidate);
        }
        if (!EXTENSIONLESS_DEBUGGER_ORDER.includes(name) && !rootDir)
            continue;
        const adapter = resolveAdapterForLaunch(name, configs, cwd, rootDir);
        if (adapter)
            available.push(adapter);
    }
    if (programKind === "directory" && directoryMatches.length > 0) {
        const matchingNames = new Set(directoryMatches.map(candidate => candidate.name));
        const directoryAdapters = available.filter(adapter => adapter.acceptsDirectoryProgram && matchingNames.has(adapter.name));
        const selected = sortAdaptersForLaunch(program, cwd, programKind, directoryAdapters)[0];
        if (selected)
            return { kind: "adapter", adapter: selected };
        const unavailable = directoryMatches[0];
        return unavailable ? unavailableAdapter(unavailable, configs) : { kind: "none" };
    }
    const directoryAdapters = programKind === "directory" ? available.filter(adapter => adapter.acceptsDirectoryProgram) : available;
    const candidates = directoryAdapters.length > 0 ? directoryAdapters : available;
    const selected = sortAdaptersForLaunch(program, cwd, programKind, candidates)[0];
    if (selected)
        return { kind: "adapter", adapter: selected };
    const unavailable = rootMatches[0];
    return unavailable ? unavailableAdapter(unavailable, configs) : { kind: "none" };
}
function sortAdaptersForLaunch(program, cwd, programKind, adapters) {
    const extension = path.extname(program).toLowerCase();
    const rootAware = adapters.map(adapter => ({
        adapter,
        hasExtensionMatch: extension.length > 0 && adapter.fileTypes.includes(extension),
        hasRootMatch: findRootMarkerInLaunchAncestry(program, cwd, adapter.rootMarkers, programKind) !== null,
    }));
    rootAware.sort((left, right) => {
        if (left.hasExtensionMatch !== right.hasExtensionMatch) {
            return left.hasExtensionMatch ? -1 : 1;
        }
        if (left.hasRootMatch !== right.hasRootMatch) {
            return left.hasRootMatch ? -1 : 1;
        }
        const leftRank = EXTENSIONLESS_DEBUGGER_ORDER.indexOf(left.adapter.name);
        const rightRank = EXTENSIONLESS_DEBUGGER_ORDER.indexOf(right.adapter.name);
        const normalizedLeftRank = leftRank === -1 ? Number.MAX_SAFE_INTEGER : leftRank;
        const normalizedRightRank = rightRank === -1 ? Number.MAX_SAFE_INTEGER : rightRank;
        const rankDelta = normalizedLeftRank - normalizedRightRank;
        if (rankDelta !== 0)
            return rankDelta;
        return left.adapter.name.localeCompare(right.adapter.name);
    });
    return rootAware.map(entry => entry.adapter);
}
/** Selects a launch adapter or reports why matching configuration cannot run. */
export function selectLaunchAdapter(program, cwd, adapterName, programKind = "file") {
    const configs = getAdapterConfigs(cwd);
    if (adapterName) {
        const config = configs[adapterName];
        if (!config)
            return { kind: "none" };
        const rootDir = findRootMarkerInLaunchAncestry(program, cwd, config.rootMarkers ?? [], programKind);
        const adapter = resolveAdapterForLaunch(adapterName, configs, cwd, rootDir);
        return adapter ? { kind: "adapter", adapter } : { kind: "unavailable", adapterName, command: config.command };
    }
    return selectAutomaticLaunchAdapter(program, cwd, programKind, configs);
}
export function selectAttachAdapter(cwd, adapterName, port) {
    if (adapterName) {
        return resolveAdapter(adapterName, cwd);
    }
    const available = getAvailableAdapters(cwd);
    if (port !== undefined) {
        const debugpy = available.find(adapter => adapter.name === "debugpy");
        if (debugpy)
            return debugpy;
    }
    for (const preferred of EXTENSIONLESS_DEBUGGER_ORDER) {
        const match = available.find(adapter => adapter.name === preferred);
        if (match)
            return match;
    }
    return available[0] ?? null;
}
/** Compute adapter-specific launch arguments that depend on the resolved
 *  program. Returned values are spread over `adapter.launchDefaults` so they
 *  take precedence over the static defaults but can still be overridden by
 *  the fields `DapSessionManager.launch` sets explicitly (program, cwd, args).
 *
 *  Currently scoped to dlv, where `mode` selects how the program path is
 *  interpreted: directories and `.go` source files debug as a Go package
 *  (`mode=debug`), anything else is treated as a compiled binary (`mode=exec`).
 */
export function resolveLaunchOverrides(adapter, program, programKind) {
    if (adapter.name === "dlv") {
        const extension = path.extname(program).toLowerCase();
        if (programKind === "directory" || extension === ".go") {
            return { mode: "debug" };
        }
        if (programKind === "file") {
            return { mode: "exec" };
        }
    }
    return {};
}
