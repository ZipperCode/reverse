import * as fs from "node:fs";
import { createRequire, isBuiltin } from "node:module";
import * as path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as vm from "node:vm";
import { collectModuleSourceSpecifiers, stripTypeScriptSyntax } from "./rewrite-imports";
const LOCAL_MODULE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".ts", ".tsx", ".mts"]);
export class LocalModuleLoader {
    #context;
    #sessionTag;
    #moduleMtimes = new Map();
    #moduleDeps = new Map();
    #moduleParents = new Map();
    #moduleVersions = new Map();
    #moduleEntries = new Map();
    #moduleBuilds = new Map();
    #externalModules = new Map();
    #requireCache = new Map();
    #modulePaths = new WeakMap();
    #packageRoot;
    #linkChain = Promise.resolve();
    constructor(sessionId) {
        this.#context = vm.createContext(globalThis);
        this.#sessionTag = Bun.hash(sessionId).toString(16);
    }
    setPackageRoot(packageRoot) {
        const normalized = packageRoot ? path.resolve(packageRoot) : undefined;
        if (normalized === this.#packageRoot)
            return;
        this.#packageRoot = normalized;
        this.#requireCache.clear();
    }
    async resolveForRun(baseDir, source) {
        this.#refreshTrackedLocalModules();
        return await this.#resolveFromBase(baseDir, source);
    }
    async resolveForModule(moduleUrl, source, cwd) {
        this.#refreshTrackedLocalModules();
        const modulePath = this.filenameForUrl(moduleUrl);
        const baseDir = modulePath ? path.dirname(modulePath) : cwd;
        return await this.#resolveFromBase(baseDir, source);
    }
    requireForFile(moduleUrlOrPath, cwd) {
        const basePath = this.filenameForUrl(moduleUrlOrPath) ?? path.join(cwd, "[eval]");
        let cached = this.#requireCache.get(basePath);
        if (!cached) {
            cached = buildRequire(basePath, this.#packageRoot);
            this.#requireCache.set(basePath, cached);
        }
        return cached;
    }
    filenameForUrl(moduleUrlOrPath) {
        if (!moduleUrlOrPath)
            return null;
        if (moduleUrlOrPath.startsWith("file://"))
            return fileURLToPath(moduleUrlOrPath);
        return path.isAbsolute(moduleUrlOrPath) ? moduleUrlOrPath : null;
    }
    dirnameForUrl(moduleUrlOrPath, cwd) {
        const filename = this.filenameForUrl(moduleUrlOrPath);
        return filename ? path.dirname(filename) : cwd;
    }
    async #resolveFromBase(baseDir, source) {
        const resolved = resolveImportSpecifier(baseDir, source, this.#packageRoot);
        if (isLocalPathSpecifier(source) && isManagedLocalModulePath(resolved)) {
            const module = await this.#loadLocalModule(resolved);
            return { mode: "local", value: module.namespace };
        }
        return { mode: "external", target: normalizeImportTarget(resolved) };
    }
    async #ensureLocalModule(modulePath) {
        const existing = this.#moduleEntries.get(modulePath);
        if (existing)
            return existing;
        const building = this.#moduleBuilds.get(modulePath);
        if (building)
            return await building;
        const buildPromise = this.#buildLocalModule(modulePath).finally(() => {
            if (this.#moduleBuilds.get(modulePath) === buildPromise)
                this.#moduleBuilds.delete(modulePath);
        });
        this.#moduleBuilds.set(modulePath, buildPromise);
        return await buildPromise;
    }
    // Construct (parse + register) a local module WITHOUT linking or evaluating it.
    // Linking and evaluation are driven once from the graph root in `#linkAndEvaluate`;
    // doing them per-module inside the recursive linker re-enters Bun's node:vm linker
    // mid-instantiation, which segfaults JSC (getImportedModule on a null record) whenever
    // the local graph contains an import cycle.
    async #buildLocalModule(modulePath) {
        const rawSource = fs.readFileSync(modulePath, "utf8");
        const stripped = stripTypeScriptSyntax(rawSource, {
            force: isTypeScriptModulePath(modulePath),
            loader: stripLoaderForPath(modulePath),
        });
        const moduleDir = path.dirname(modulePath);
        const localDeps = new Set();
        for (const specifier of await collectModuleSourceSpecifiers(stripped)) {
            const resolved = resolveImportSpecifier(moduleDir, specifier, this.#packageRoot);
            if (isLocalPathSpecifier(specifier) && isManagedLocalModulePath(resolved)) {
                localDeps.add(resolved);
            }
        }
        this.#setModuleDependencies(modulePath, localDeps);
        this.#moduleMtimes.set(modulePath, fs.statSync(modulePath).mtimeMs);
        const version = this.#moduleVersions.get(modulePath) ?? 1;
        this.#moduleVersions.set(modulePath, version);
        const fileUrl = pathToFileURL(modulePath).href;
        const identifier = `${fileUrl}?omp-session=${this.#sessionTag}&v=${version}`;
        const wrappedSource = buildModuleSource(stripped, modulePath);
        const module = new vm.SourceTextModule(wrappedSource, {
            context: this.#context,
            identifier,
            initializeImportMeta: meta => {
                meta.url = fileUrl;
                meta.path = modulePath;
                meta.dir = moduleDir;
            },
            importModuleDynamically: async (specifier) => {
                return await this.#resolveDynamicImport(modulePath, String(specifier));
            },
        });
        this.#modulePaths.set(module, modulePath);
        const entry = { version, identifier, module };
        this.#moduleEntries.set(modulePath, entry);
        return entry;
    }
    // Construct (if needed) then link+evaluate a local module as a graph root, returning
    // the evaluated module. Link and evaluate run exactly once over the whole reachable
    // graph; the static linker only constructs dependencies, letting node:vm instantiate
    // cyclic graphs in a single pass.
    async #loadLocalModule(modulePath) {
        const entry = await this.#ensureLocalModule(modulePath);
        entry.loaded ??= this.#linkAndEvaluate(entry, modulePath);
        await entry.loaded;
        return entry.module;
    }
    async #linkAndEvaluate(entry, modulePath) {
        const { module } = entry;
        try {
            // Serialize the link phase across every graph root. Bun's node:vm linker
            // segfaults (getImportedModule on a null record) when two link passes
            // instantiate overlapping module instances concurrently — e.g.
            // Promise.all([import("./a"), import("./b")]) over a graph that shares
            // dependencies. Holding the lock for the whole module.link() (including its
            // async resolver callbacks) guarantees the linker is never re-entered
            // mid-instantiation. The lock is released before evaluate(), so a dynamic
            // import during evaluation can re-acquire it without deadlock.
            await this.#serializeLink(async () => {
                if (module.status === "unlinked")
                    await module.link(this.#linkResolve);
            });
            if (module.status === "linked")
                await module.evaluate();
        }
        catch (error) {
            this.#invalidateFailedLoad(modulePath);
            throw error;
        }
        if (module.status === "errored") {
            this.#invalidateFailedLoad(modulePath);
            throw module.error;
        }
    }
    // Promise-chain mutex serializing node:vm link passes (see #linkAndEvaluate).
    // #linkChain is kept non-rejecting so a failed link never wedges the queue.
    #serializeLink(run) {
        const result = this.#linkChain.then(run);
        this.#linkChain = result.then(() => undefined, () => undefined);
        return result;
    }
    // Shared static-link resolver for `module.link()`. node:vm passes the referencing
    // module and reuses this one resolver for the entire graph, so the referrer path is
    // recovered from `#modulePaths`. Local dependencies are constructed but NOT linked or
    // evaluated here (the root drives that); externals are loaded eagerly — they carry no
    // imports and cannot participate in a cycle.
    #linkResolve = async (specifier, referencingModule) => {
        const referrerPath = this.#modulePaths.get(referencingModule);
        if (referrerPath === undefined) {
            throw new Error(`local module loader: unknown referrer while linking "${specifier}"`);
        }
        const resolved = resolveImportSpecifier(path.dirname(referrerPath), specifier, this.#packageRoot);
        if (isLocalPathSpecifier(specifier) && isManagedLocalModulePath(resolved)) {
            return (await this.#ensureLocalModule(resolved)).module;
        }
        return await this.#ensureExternalModule(normalizeImportTarget(resolved));
    };
    // Resolver for runtime `import()` inside evaluated module code: the result must be a
    // fully linked+evaluated module, so local targets are loaded as graph roots.
    async #resolveDynamicImport(referrerPath, specifier) {
        const resolved = resolveImportSpecifier(path.dirname(referrerPath), specifier, this.#packageRoot);
        if (isLocalPathSpecifier(specifier) && isManagedLocalModulePath(resolved)) {
            return await this.#loadLocalModule(resolved);
        }
        return await this.#ensureExternalModule(normalizeImportTarget(resolved));
    }
    // A failed link/evaluate can leave a partial graph cached. Drop every reachable module
    // that is not fully evaluated so the next attempt reconstructs it; fully evaluated
    // modules keep valid namespaces and stay cached.
    #invalidateFailedLoad(rootPath) {
        const stack = [rootPath];
        const seen = new Set();
        while (stack.length > 0) {
            const current = stack.pop();
            if (current === undefined || seen.has(current))
                continue;
            seen.add(current);
            const entry = this.#moduleEntries.get(current);
            if (entry && entry.module.status === "evaluated")
                continue;
            this.#moduleEntries.delete(current);
            this.#moduleBuilds.delete(current);
            const deps = this.#moduleDeps.get(current);
            if (deps)
                for (const dep of deps)
                    stack.push(dep);
        }
    }
    async #ensureExternalModule(target) {
        const existing = this.#externalModules.get(target);
        if (existing)
            return await existing;
        const loadPromise = (async () => {
            const namespace = await import(target);
            const exportNames = Object.keys(namespace);
            const module = new vm.SyntheticModule(exportNames, function () {
                for (const name of exportNames) {
                    this.setExport(name, namespace[name]);
                }
            }, { context: this.#context, identifier: target });
            await module.link(() => {
                throw new Error("Synthetic external modules have no dependencies");
            });
            await module.evaluate();
            return module;
        })();
        this.#externalModules.set(target, loadPromise);
        try {
            return await loadPromise;
        }
        catch (error) {
            if (this.#externalModules.get(target) === loadPromise)
                this.#externalModules.delete(target);
            throw error;
        }
    }
    #refreshTrackedLocalModules() {
        const changed = [];
        for (const [modulePath, previousMtime] of this.#moduleMtimes.entries()) {
            let nextMtime;
            try {
                nextMtime = fs.statSync(modulePath).mtimeMs;
            }
            catch {
                nextMtime = undefined;
            }
            if (nextMtime === previousMtime)
                continue;
            if (nextMtime === undefined)
                this.#moduleMtimes.delete(modulePath);
            else
                this.#moduleMtimes.set(modulePath, nextMtime);
            changed.push(modulePath);
        }
        for (const modulePath of changed) {
            this.#invalidateModuleAndParents(modulePath, new Set());
        }
    }
    #invalidateModuleAndParents(modulePath, seen) {
        if (seen.has(modulePath))
            return;
        seen.add(modulePath);
        this.#moduleEntries.delete(modulePath);
        this.#moduleBuilds.delete(modulePath);
        this.#moduleVersions.set(modulePath, (this.#moduleVersions.get(modulePath) ?? 1) + 1);
        const parents = [...(this.#moduleParents.get(modulePath) ?? [])];
        for (const parent of parents)
            this.#invalidateModuleAndParents(parent, seen);
    }
    #setModuleDependencies(modulePath, deps) {
        const previousDeps = this.#moduleDeps.get(modulePath);
        if (previousDeps) {
            for (const dep of previousDeps) {
                const parents = this.#moduleParents.get(dep);
                if (!parents)
                    continue;
                parents.delete(modulePath);
                if (parents.size === 0)
                    this.#moduleParents.delete(dep);
            }
        }
        this.#moduleDeps.set(modulePath, new Set(deps));
        for (const dep of deps) {
            const parents = this.#moduleParents.get(dep) ?? new Set();
            parents.add(modulePath);
            this.#moduleParents.set(dep, parents);
        }
    }
}
function buildRequire(fromPath, packageRoot) {
    const basePath = path.extname(fromPath) ? fromPath : path.join(fromPath, "[eval]");
    const primary = createRequire(pathToFileURL(basePath).href);
    if (!packageRoot)
        return primary;
    const fallback = createRequire(pathToFileURL(path.join(packageRoot, "package.json")).href);
    const requireWithFallback = ((id) => {
        if (!isBareSpecifier(id))
            return primary(id);
        let primaryResolutionError;
        try {
            primary.resolve(id);
        }
        catch (error) {
            primaryResolutionError = error;
        }
        if (!primaryResolutionError)
            return primary(id);
        try {
            fallback.resolve(id);
        }
        catch (fallbackError) {
            throw packageFallbackError(primaryResolutionError, fallbackError, packageRoot);
        }
        return fallback(id);
    });
    const resolve = ((id, options) => {
        try {
            return primary.resolve(id, options);
        }
        catch (primaryError) {
            if (!isBareSpecifier(id))
                throw primaryError;
            try {
                return fallback.resolve(id, options);
            }
            catch (fallbackError) {
                throw packageFallbackError(primaryError, fallbackError, packageRoot);
            }
        }
    });
    resolve.paths = request => primary.resolve.paths(request);
    Object.defineProperties(requireWithFallback, {
        resolve: { value: resolve },
        cache: { value: primary.cache },
        extensions: { value: primary.extensions },
        main: { value: primary.main },
    });
    return requireWithFallback;
}
function buildModuleSource(source, modulePath) {
    const moduleDir = path.dirname(modulePath);
    return [
        `const require = globalThis.__omp_get_require__(${JSON.stringify(pathToFileURL(modulePath).href)});`,
        `const __filename = ${JSON.stringify(modulePath)};`,
        `const __dirname = ${JSON.stringify(moduleDir)};`,
        source,
    ].join("\n");
}
function resolveImportSpecifier(baseDir, source, packageRoot) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(source) || isBuiltin(source))
        return source;
    if (!isBareSpecifier(source))
        return Bun.resolveSync(source, baseDir);
    let projectError;
    try {
        return resolveBareSpecifierWithinProject(source, baseDir);
    }
    catch (error) {
        projectError = error;
    }
    if (packageRoot) {
        try {
            return resolveBareSpecifierWithinProject(source, packageRoot);
        }
        catch (fallbackError) {
            throw packageFallbackError(projectError, fallbackError, packageRoot);
        }
    }
    throw projectError;
}
function resolveBareSpecifierWithinProject(source, baseDir) {
    const resolved = Bun.resolveSync(source, baseDir);
    if (!path.isAbsolute(resolved)) {
        throw new Error(`Refusing non-file resolution ${JSON.stringify(resolved)} for bare package ${JSON.stringify(source)} from ${baseDir}`);
    }
    const segments = source.split("/");
    const packageName = source.startsWith("@") ? segments.slice(0, 2) : segments.slice(0, 1);
    const target = path.resolve(resolved);
    let ancestor = path.resolve(baseDir);
    for (;;) {
        if (fs.existsSync(path.join(ancestor, "node_modules", ...packageName)))
            return resolved;
        const parent = path.dirname(ancestor);
        if (parent !== ancestor && fs.existsSync(path.join(ancestor, "package.json")) && pathIsWithin(ancestor, target)) {
            return resolved;
        }
        if (parent === ancestor)
            break;
        ancestor = parent;
    }
    throw new Error(`Refusing package ${JSON.stringify(source)} resolved outside the importing project's ancestry: ${resolved}`);
}
function pathIsWithin(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
function packageFallbackError(projectError, fallbackError, packageRoot) {
    const projectMessage = projectError instanceof Error ? projectError.message : String(projectError);
    const fallbackMessage = fallbackError instanceof Error ? fallbackError.message : String(fallbackError);
    return new Error(`${projectMessage}\nJS package environment fallback ${packageRoot} also failed: ${fallbackMessage}\n` +
        "Install the missing dependency with %bun add (select %environment project only to modify the project).", { cause: projectError });
}
function isBareSpecifier(source) {
    return !isLocalPathSpecifier(source) && !/^[a-z][a-z0-9+.-]*:/i.test(source) && !isBuiltin(source);
}
function isLocalPathSpecifier(source) {
    return (source.startsWith("./") ||
        source.startsWith("../") ||
        source === "." ||
        source === ".." ||
        source.startsWith("/") ||
        source.startsWith("~/") ||
        /^[a-zA-Z]:[\\/]/.test(source));
}
function isTypeScriptModulePath(modulePath) {
    const ext = path.extname(modulePath);
    return ext === ".ts" || ext === ".tsx" || ext === ".mts";
}
function stripLoaderForPath(modulePath) {
    return path.extname(modulePath) === ".tsx" ? "tsx" : "ts";
}
function isManagedLocalModulePath(target) {
    return (path.isAbsolute(target) &&
        LOCAL_MODULE_EXTENSIONS.has(path.extname(target)) &&
        !target.includes(`${path.sep}node_modules${path.sep}`));
}
function normalizeImportTarget(target) {
    if (path.isAbsolute(target))
        return pathToFileURL(target).href;
    return target;
}
