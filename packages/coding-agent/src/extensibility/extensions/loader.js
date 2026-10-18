import * as fs from "node:fs/promises";
import * as path from "node:path";
import { type } from "@rva/omptype";
import * as zod from "@rva/omptype/zod";
import { isBuiltinComposerStyle } from "@rva/tui";
import { hasFsCode, isEacces, isEnoent, logger } from "@rva/utils";
import { extensionModuleCapability } from "../../capability/extension-module";
import { hookCapability } from "../../capability/hook";
import { isServiceTierFamily, isServiceTierForFamily } from "../../config/service-tier";
import { loadCapability } from "../../discovery";
import { getExtensionNameFromPath } from "../../discovery/helpers";
import { execCommand } from "../../exec/exec";
// Runtime self-reference: dereference this namespace only inside loader functions to keep the index.ts cycle safe.
import * as PiCodingAgent from "../../index";
import { isFilesystemSourcePath } from "../../tools/path-utils";
import { EventBus } from "../../utils/event-bus";
import * as TypeBox from "../legacy-typebox";
import { resolveExtensionDirectory } from "./directory-resolution";
import { installLegacyPiSpecifierShim, loadLegacyPiModule } from "../plugins/legacy-pi-compat";
import { getAllPluginExtensionPaths } from "../plugins/loader";
import { resolvePath, withHostGuard } from "../utils";
installLegacyPiSpecifierShim();
function getExtensionFactory(module) {
    const candidate = typeof module === "function" ? module : module.default;
    return typeof candidate === "function" ? candidate : null;
}
/**
 * Upstream-shaped provenance for an extension-registered tool. Consumers that
 * read `sourceInfo` off `getAllRegisteredTools()` (e.g. pi-fabric) receive an
 * absolute on-disk path: the tool's own `sourcePath` when it is filesystem-
 * absolute, otherwise the extension's resolved entry (`fallbackPath`). A tool
 * with no absolute origin at all falls back to the synthetic `<extension:name>`.
 */
export function extensionToolSourceInfo(definition, fallbackPath) {
    const sourcePath = definition.sourcePath;
    const path = sourcePath && isFilesystemSourcePath(sourcePath)
        ? sourcePath
        : isFilesystemSourcePath(fallbackPath)
            ? fallbackPath
            : `<extension:${definition.name}>`;
    return { path, source: "extension", scope: "temporary", origin: "top-level" };
}
export class ExtensionRuntimeNotInitializedError extends Error {
    constructor() {
        super("Extension runtime not initialized. Action methods cannot be called during extension loading.");
    }
}
/**
 * Extension runtime with throwing stubs for action methods.
 * These are replaced with real implementations during initialization.
 */
export class ExtensionRuntime {
    flagValues = new Map();
    pendingProviderRegistrations = [];
    registerProvider(name, config, sourceId) {
        this.pendingProviderRegistrations.push({ name, config, sourceId });
    }
    unregisterProvider(name) {
        const remaining = this.pendingProviderRegistrations.filter(registration => registration.name !== name);
        this.pendingProviderRegistrations.splice(0, this.pendingProviderRegistrations.length, ...remaining);
    }
    sendMessage() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    sendUserMessage() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    appendEntry() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setLabel() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getActiveTools() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getAllTools() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setActiveTools() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getCommands() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setModel() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getThinkingLevel() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setThinkingLevel() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getServiceTiers() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setServiceTier() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    getSessionName() {
        throw new ExtensionRuntimeNotInitializedError();
    }
    setSessionName() {
        throw new ExtensionRuntimeNotInitializedError();
    }
}
/**
 * ExtensionAPI implementation for an extension.
 * Registration methods write to the extension object.
 * Action methods delegate to the shared runtime.
 */
class ConcreteExtensionAPI {
    pi;
    extension;
    runtime;
    cwd;
    events;
    logger = logger;
    typebox = TypeBox;
    arktype = type;
    zod = zod;
    flagValues = new Map();
    pendingProviderRegistrations = [];
    constructor(pi, extension, runtime, cwd, events) {
        this.pi = pi;
        this.extension = extension;
        this.runtime = runtime;
        this.cwd = cwd;
        this.events = events;
        // Extensions destructure `pi.on` or forward API methods as callbacks, so every
        // prototype method must keep its receiver when detached. Walk the prototype
        // rather than listing methods: a new method is bound without touching this.
        const prototype = ConcreteExtensionAPI.prototype;
        for (const name of Object.getOwnPropertyNames(prototype)) {
            if (name === "constructor")
                continue;
            const descriptor = Object.getOwnPropertyDescriptor(prototype, name);
            if (typeof descriptor?.value !== "function")
                continue;
            Object.defineProperty(this, name, { value: descriptor.value.bind(this), writable: true, configurable: true });
        }
    }
    on(event, handler) {
        const list = this.extension.handlers.get(event) ?? [];
        list.push(handler);
        this.extension.handlers.set(event, list);
    }
    registerTool(tool) {
        const registered = {
            definition: tool,
            extensionPath: this.extension.path,
            sourceInfo: extensionToolSourceInfo(tool, this.extension.resolvedPath),
        };
        this.extension.tools.set(tool.name, registered);
        for (const listener of this.extension.toolRegistrationListeners ?? [])
            listener(tool.name);
    }
    registerFileWriteFallback(handler) {
        this.extension.fileWriteFallbackHandlers.push(handler);
    }
    registerFileDeleteFallback(handler) {
        this.extension.fileDeleteFallbackHandlers.push(handler);
    }
    registerCommand(name, options) {
        this.extension.commands.set(name, { name, ...options });
    }
    setLabel(label) {
        this.extension.label = label;
    }
    registerShortcut(shortcut, options) {
        this.extension.shortcuts.set(shortcut, { shortcut, extensionPath: this.extension.path, ...options });
    }
    registerFlag(name, options) {
        this.extension.flags.set(name, { name, extensionPath: this.extension.path, ...options });
        if (options.default !== undefined) {
            this.runtime.flagValues.set(name, options.default);
        }
    }
    registerMessageRenderer(customType, renderer) {
        this.extension.messageRenderers.set(customType, renderer);
    }
    registerAssistantThinkingRenderer(renderer) {
        this.extension.assistantThinkingRenderers.push(renderer);
    }
    registerComposerShape(definition) {
        const id = definition.style.id;
        if (id.length === 0 || id !== id.trim()) {
            throw new TypeError("Composer shape id must be a non-empty trimmed string");
        }
        if (definition.label.trim().length === 0) {
            throw new TypeError(`Composer shape "${id}" must have a label`);
        }
        if (isBuiltinComposerStyle(id)) {
            throw new Error(`Cannot replace built-in composer shape "${id}"`);
        }
        this.extension.composerShapes.set(id, definition);
    }
    getFlag(name) {
        if (!this.extension.flags.has(name))
            return undefined;
        return this.runtime.flagValues.get(name);
    }
    sendMessage(message, options) {
        this.runtime.sendMessage(message, options);
    }
    sendUserMessage(content, options) {
        this.runtime.sendUserMessage(content, options);
    }
    appendEntry(customType, data) {
        this.runtime.appendEntry(customType, data);
    }
    exec(command, args, options) {
        return execCommand(command, args, options?.cwd ?? this.cwd, options);
    }
    getActiveTools() {
        return this.runtime.getActiveTools();
    }
    getAllTools() {
        return this.runtime.getAllTools();
    }
    setActiveTools(toolNames) {
        return this.runtime.setActiveTools(toolNames);
    }
    getCommands() {
        return this.runtime.getCommands();
    }
    setModel(model) {
        return this.runtime.setModel(model);
    }
    getThinkingLevel() {
        return this.runtime.getThinkingLevel();
    }
    setThinkingLevel(level, persist) {
        this.runtime.setThinkingLevel(level, persist);
    }
    getServiceTiers() {
        return { ...this.runtime.getServiceTiers() };
    }
    setServiceTier(family, tier) {
        if (!isServiceTierFamily(family) || (tier !== undefined && !isServiceTierForFamily(family, tier))) {
            throw new TypeError(`Invalid service tier "${String(tier)}" for family "${String(family)}"`);
        }
        this.runtime.setServiceTier(family, tier);
    }
    getSessionName() {
        return this.runtime.getSessionName();
    }
    setSessionName(name) {
        return this.runtime.setSessionName(name);
    }
    registerProvider(name, config) {
        this.runtime.registerProvider(name, config, this.extension.path);
    }
    unregisterProvider(name) {
        this.runtime.unregisterProvider(name, this.extension.path);
    }
}
/**
 * Create an Extension object with empty collections.
 */
function createExtension(extensionPath, resolvedPath) {
    return {
        path: extensionPath,
        resolvedPath,
        handlers: new Map(),
        tools: new Map(),
        toolRegistrationListeners: new Set(),
        assistantThinkingRenderers: [],
        fileWriteFallbackHandlers: [],
        fileDeleteFallbackHandlers: [],
        messageRenderers: new Map(),
        composerShapes: new Map(),
        commands: new Map(),
        flags: new Map(),
        shortcuts: new Map(),
    };
}
/**
 * Runs an extension factory with provider registration rollback on failure.
 * Restores the complete registration queue when the factory throws because an
 * extension may unregister entries queued by an earlier extension.
 */
async function runExtensionFactory(factory, api, runtime) {
    const providerRegistrationCheckpoint = [...runtime.pendingProviderRegistrations];
    try {
        await factory(api);
    }
    catch (error) {
        runtime.pendingProviderRegistrations.splice(0, runtime.pendingProviderRegistrations.length, ...providerRegistrationCheckpoint);
        throw error;
    }
}
async function importExtensionModule(extensionPath, cwd) {
    const resolvedPath = resolvePath(extensionPath, cwd);
    try {
        const module = (await withHostGuard(() => loadLegacyPiModule(resolvedPath)));
        const factory = getExtensionFactory(module);
        if (typeof factory !== "function") {
            return {
                path: extensionPath,
                factory: null,
                resolvedPath,
                error: `Extension does not export a valid factory function: ${extensionPath}`,
            };
        }
        return { path: extensionPath, factory, resolvedPath, error: null };
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { path: extensionPath, factory: null, resolvedPath, error: `Failed to load extension: ${message}` };
    }
}
async function bindExtension(extensionPath, imported, cwd, eventBus, runtime) {
    const factory = imported.factory;
    if (imported.error !== null || factory === null) {
        return { extension: null, error: imported.error };
    }
    try {
        const extension = createExtension(extensionPath, imported.resolvedPath);
        const api = new ConcreteExtensionAPI(PiCodingAgent, extension, runtime, cwd, eventBus);
        await withHostGuard(() => runExtensionFactory(factory, api, runtime));
        return { extension, error: null };
    }
    catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { extension: null, error: `Failed to load extension: ${message}` };
    }
}
/**
 * Create an Extension from an inline factory function.
 */
export async function loadExtensionFromFactory(factory, cwd, eventBus, runtime, name = "<inline>") {
    const extension = createExtension(name, name);
    const api = new ConcreteExtensionAPI(PiCodingAgent, extension, runtime, cwd, eventBus);
    await runExtensionFactory(factory, api, runtime);
    return extension;
}
/**
 * Load extensions from paths.
 *
 * Module import (the dominant cold-start cost — file I/O plus module
 * evaluation) runs concurrently across extensions; factory binding then runs
 * sequentially in the original path order, so registration semantics
 * (last-wins collisions, shared runtime flag defaults) stay deterministic.
 */
export async function loadExtensions(paths, cwd, eventBus) {
    const preparedExtensions = await Promise.all(paths.map(extPath => importExtensionModule(extPath, cwd)));
    return bindPreparedExtensions(preparedExtensions, cwd, eventBus);
}
/** Bind previously imported extension factories to a fresh session runtime. */
export async function bindPreparedExtensions(preparedExtensions, cwd, eventBus) {
    const extensions = [];
    const errors = [];
    const resolvedEventBus = eventBus ?? new EventBus();
    const runtime = new ExtensionRuntime();
    for (const prepared of preparedExtensions) {
        const { extension, error } = await bindExtension(prepared.path, prepared, cwd, resolvedEventBus, runtime);
        if (error) {
            errors.push({ path: prepared.path, error });
            continue;
        }
        if (extension) {
            extensions.push(extension);
        }
    }
    return {
        extensions,
        errors,
        runtime,
        preparedExtensions: [...preparedExtensions],
    };
}
function isExtensionFile(name) {
    return name.endsWith(".ts") || name.endsWith(".js");
}
const CONFIGURED_EXTENSION_DIRECTORY_OPTIONS = {
    indexNames: ["index.ts", "index.js"],
    isScanFile: isExtensionFile,
    throwUnexpectedStatErrors: true,
    onReadError: (filePath, error) => {
        logger.warn("Failed to resolve extension directory", { path: filePath, error: String(error) });
    },
};
async function discoverHooksInPackageRoot(root) {
    const hooks = [];
    for (const hookType of ["pre", "post"]) {
        const hookDir = path.join(root, "hooks", hookType);
        let entries;
        try {
            entries = await fs.readdir(hookDir, { withFileTypes: true });
        }
        catch (err) {
            if (isEnoent(err) || isEacces(err) || hasFsCode(err, "ENOTDIR") || hasFsCode(err, "EPERM"))
                continue;
            throw err;
        }
        for (const entry of entries) {
            if ((entry.isFile() || entry.isSymbolicLink()) && isExtensionFile(entry.name)) {
                hooks.push(path.join(hookDir, entry.name));
            }
        }
    }
    return hooks;
}
export async function discoverExtensionPaths(configuredPaths, cwd, disabledExtensionIds, options = {}) {
    const allPaths = [];
    const seen = new Set();
    const disabled = new Set(disabledExtensionIds ?? []);
    const loadOptions = disabledExtensionIds ? { cwd, disabledExtensions: disabledExtensionIds } : { cwd };
    const isDisabledName = (name) => disabled.has(`extension-module:${name}`);
    const addPath = (extPath) => {
        const resolved = path.resolve(extPath);
        if (!seen.has(resolved)) {
            seen.add(resolved);
            allPaths.push(extPath);
        }
    };
    const addPaths = (paths) => {
        for (const extPath of paths) {
            if (isDisabledName(getExtensionNameFromPath(extPath)))
                continue;
            addPath(extPath);
        }
    };
    const ambient = options.ambient !== false;
    if (ambient) {
        // 1. Discover extension modules via capability API (native .omp/.pi only).
        // Scope the load to the native provider — the extension-module capability
        // also has claude/codex/gemini/opencode providers, and their items were
        // discarded here anyway (see #4198). The provider filter skips the walk
        // entirely instead of running four foreign directory scans and dropping
        // the results.
        const discovered = await loadCapability(extensionModuleCapability.id, {
            ...loadOptions,
            providers: ["native"],
        });
        for (const ext of discovered.items) {
            addPath(ext.path);
        }
    }
    // 2. Discover JS/TS hook factories and bind them through the extension
    // runner, which owns the current runtime event bus. Non-ambient discovery
    // scans only this invocation's configured package roots; it must not consult
    // settings, installed packages, or process-global CLI injection state.
    if (ambient) {
        if (options.includeAmbientHooks !== false) {
            const hooks = await loadCapability(hookCapability.id, loadOptions);
            for (const hookPath of hooks.items
                .map(hook => hook.path)
                .filter(hookPath => isExtensionFile(path.basename(hookPath)))) {
                addPath(hookPath);
            }
        }
    }
    else {
        for (const configuredPath of configuredPaths) {
            addPaths(await discoverHooksInPackageRoot(resolvePath(configuredPath, cwd)));
        }
    }
    // 3. Discover extension entry points from installed plugins.
    if (ambient) {
        addPaths(await getAllPluginExtensionPaths(cwd));
    }
    // 4. Explicitly configured paths
    for (const configuredPath of configuredPaths) {
        const resolved = resolvePath(configuredPath, cwd);
        let stat = null;
        try {
            stat = await fs.stat(resolved);
        }
        catch (err) {
            if (!isEnoent(err))
                throw err;
        }
        if (stat?.isDirectory()) {
            addPaths(resolveExtensionDirectory(resolved, CONFIGURED_EXTENSION_DIRECTORY_OPTIONS).files);
            continue;
        }
        addPath(resolved);
    }
    return allPaths;
}
/**
 * Discover and load extensions from standard locations. Composed of
 * {@link discoverExtensionPaths} (FS scan) + {@link loadExtensions}
 * (per-session binding).
 */
export async function discoverAndLoadExtensions(configuredPaths, cwd, eventBus, disabledExtensionIds, options = {}) {
    const paths = await discoverExtensionPaths(configuredPaths, cwd, disabledExtensionIds, options);
    return loadExtensions(paths, cwd, eventBus);
}
