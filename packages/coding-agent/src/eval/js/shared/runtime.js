import { AsyncLocalStorage } from "node:async_hooks";
import { Console } from "node:console";
import * as fs from "node:fs";
import { createRequire } from "node:module";
import * as path from "node:path";
import { Writable } from "node:stream";
import * as util from "node:util";
import * as vm from "node:vm";
// Subpath imports only: the computer worker's readiness graph includes this runtime and must not
// load pi_natives (verified under `--no-addons`); the `@rva/utils` barrel loads it eagerly.
import * as logger from "@rva/utils/logger";
import { isRecord } from "@rva/utils/type-guards";
import { evalImageMetadata } from "../../types";
import { createHelpers } from "./helpers";
import { awaitMaybePromise, indirectEval } from "./indirect-eval";
import { LocalModuleLoader } from "./local-module-loader";
import { JAVASCRIPT_PRELUDE_SOURCE } from "./prelude";
import { diagnoseCellSyntaxError, wrapCode } from "./rewrite-imports";
/**
 * Bridged tool results carry image blocks as a base64 `images` array that no
 * cell code consumes. Emit each block as an image display output so the model
 * receives real image content — matching the direct tool path — and replace
 * the payload with a note so echoing the result cannot flood the transcript
 * with base64.
 */
function surfaceBridgedToolImages(value, hooks) {
    if (!isRecord(value))
        return value;
    const { images, ...rest } = value;
    if (!Array.isArray(images) || images.length === 0)
        return value;
    let displayed = 0;
    for (const image of images) {
        if (!isRecord(image))
            continue;
        const { data, mimeType } = image;
        if (typeof data !== "string" || typeof mimeType !== "string")
            continue;
        hooks.onDisplay({ type: "image", data, mimeType, ...evalImageMetadata(image) });
        displayed++;
    }
    if (displayed === 0)
        return value;
    return { ...rest, images: `(${displayed} image${displayed === 1 ? "" : "s"} displayed)` };
}
// Strict base64: characters from the standard alphabet plus optional `=` padding, and a
// length that is a multiple of four. URL-safe base64 and embedded whitespace are not
// accepted — the Anthropic API only honors strict base64 in image sources.
const BASE64_STRICT_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const DECIMAL_CSV_RE = /^\d{1,3}(?:,\d{1,3})*$/;
const PRELUDE_GLOBAL_KEYS = [
    "__omp_js_prelude_loaded__",
    "__omp_tools__",
    "console",
    "print",
    "display",
    "tool",
    "completion",
    "output",
    "agent",
    "wait",
    "AgentHandle",
    "CompletionHandle",
    "judge",
    "judgeBatch",
    "JudgmentBatch",
    "JudgmentItem",
    "workpool",
    "WorkPool",
    "log",
    "phase",
    "__omp_with_call_site__",
    "budget",
    "read",
    "write",
    "env",
];
export function shadowSnapshotDigest(snapshot) {
    // Intrinsic-identity flags participate: an async `globalThis.String = null` that
    // lands after planning changes no value and bumps no revision, so a
    // values-only digest would still match at verify time while projections made
    // against the builtin no longer describe the cell. The template conversion
    // avoids the mutable `String` global this function itself must survive.
    return `${Bun.hash(JSON.stringify({ values: snapshot.values, initialGlobals: snapshot.initialGlobals }))}`;
}
const SHADOW_SNAPSHOT_MAX_DEPTH = 16;
const SHADOW_SNAPSHOT_MAX_NODES = 2000;
const SHADOW_SNAPSHOT_MAX_STRING_BYTES = 8 * 1024 * 1024;
function copyShadowValue(value, depth, state) {
    if (depth > SHADOW_SNAPSHOT_MAX_DEPTH || ++state.nodes > SHADOW_SNAPSHOT_MAX_NODES)
        return undefined;
    if (value === null || typeof value === "boolean")
        return value;
    if (typeof value === "number")
        return Number.isFinite(value) ? value : undefined;
    if (typeof value === "string") {
        state.bytes += Buffer.byteLength(value);
        return state.bytes <= SHADOW_SNAPSHOT_MAX_STRING_BYTES ? value : undefined;
    }
    if (typeof value !== "object" || util.types.isProxy(value) || state.seen.has(value))
        return undefined;
    state.seen.add(value);
    try {
        if (Array.isArray(value)) {
            const keys = Reflect.ownKeys(value);
            if (keys.length !== value.length + 1 || !keys.includes("length"))
                return undefined;
            const copied = [];
            for (let index = 0; index < value.length; index++) {
                const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
                if (!descriptor || !("value" in descriptor))
                    return undefined;
                const next = copyShadowValue(descriptor.value, depth + 1, state);
                if (next === undefined)
                    return undefined;
                copied.push(next);
            }
            return copied;
        }
        if (Object.getPrototypeOf(value) !== Object.prototype)
            return undefined;
        const keys = Object.keys(value);
        if (Reflect.ownKeys(value).length !== keys.length)
            return undefined;
        const copied = {};
        for (const key of keys) {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (!descriptor || !("value" in descriptor))
                return undefined;
            const next = copyShadowValue(descriptor.value, depth + 1, state);
            if (next === undefined)
                return undefined;
            copied[key] = next;
        }
        return copied;
    }
    finally {
        state.seen.delete(value);
    }
}
function isStrictBase64(s) {
    if (s.length === 0 || s.length % 4 !== 0)
        return false;
    return BASE64_STRICT_RE.test(s);
}
/**
 * Normalize the `data` field of an `{ type: "image", data, mimeType }` display payload
 * into strict base64. Accepts:
 *   - already-valid base64 strings (passed through verbatim)
 *   - `Uint8Array` / `Buffer` / `ArrayBuffer` / typed array views
 *   - `{ type: "Buffer", data: number[] }` (the shape Node serializes Buffers to via
 *     `JSON.stringify`)
 *   - decimal-CSV byte strings (the output of `uint8array.toString("base64")`, which
 *     silently ignores the encoding argument and returns `Array.prototype.toString` —
 *     a footgun for callers expecting `Buffer.toString` semantics)
 * Returns `null` if no recovery is possible.
 */
function coerceImageBase64(data) {
    if (typeof data === "string") {
        if (isStrictBase64(data))
            return data;
        if (DECIMAL_CSV_RE.test(data)) {
            const parts = data.split(",");
            const bytes = new Uint8Array(parts.length);
            for (let i = 0; i < parts.length; i++) {
                const n = Number(parts[i]);
                if (!Number.isInteger(n) || n < 0 || n > 255)
                    return null;
                bytes[i] = n;
            }
            return Buffer.from(bytes).toString("base64");
        }
        return null;
    }
    if (data instanceof Uint8Array)
        return Buffer.from(data).toString("base64");
    if (data instanceof ArrayBuffer)
        return Buffer.from(data).toString("base64");
    if (ArrayBuffer.isView(data)) {
        const view = data;
        return Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString("base64");
    }
    if (data && typeof data === "object") {
        const obj = data;
        if (obj.type === "Buffer" && Array.isArray(obj.data)) {
            const arr = obj.data;
            const bytes = new Uint8Array(arr.length);
            for (let i = 0; i < arr.length; i++) {
                const n = arr[i];
                if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 255)
                    return null;
                bytes[i] = n;
            }
            return Buffer.from(bytes).toString("base64");
        }
    }
    return null;
}
function describeDataType(data) {
    if (data === null)
        return "null";
    if (data instanceof Uint8Array)
        return "Uint8Array";
    if (data instanceof ArrayBuffer)
        return "ArrayBuffer";
    if (ArrayBuffer.isView(data))
        return data.constructor.name;
    if (typeof data === "string")
        return `string(${data.length})`;
    return typeof data;
}
/** Compiles `source` as a global script without running it (matches indirect eval semantics). */
function compiles(source) {
    try {
        new vm.Script(source);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Shared JS runtime for the eval worker and the browser tab worker. Owns the prelude,
 * helper bag, console bridge, and indirect-eval execution. Emits text/display/tool-call
 * back through `RuntimeHooks` that the embedder supplies — wire format is the embedder's
 * concern.
 */
export class JsRuntime {
    #globalOwner = Symbol("JsRuntime globals");
    #ownedGlobalKeys = new Set();
    #reservedGlobalKeys = new Set();
    #installedPreludes = new Map();
    #disposed = false;
    #runHookResolver = () => this.#als.getStore()?.hooks;
    #ownGlobal(key) {
        if (this.#ownedGlobalKeys.has(key))
            return;
        claimGlobalKey(key, this.#globalOwner);
        this.#ownedGlobalKeys.add(key);
    }
    #releaseGlobal(key) {
        if (!this.#ownedGlobalKeys.delete(key))
            return;
        releaseGlobalKey(key, this.#globalOwner);
    }
    #activateGlobals(action) {
        if (this.#disposed)
            throw new Error(`Cannot ${action} on a disposed JS runtime`);
        activateGlobalOwner(this.#globalOwner, this.#ownedGlobalKeys, action);
    }
    /**
     * Capture the current values of every owned global back into this owner's
     * global stack. A cell may rebind a reserved injected global (e.g.
     * `var fs = await import("node:fs/promises")`); without this, the next
     * `activateGlobalOwner` would restore the install-time value and silently
     * clobber the reassignment. Called after each run so bindings persist across
     * cells like the eval persistence contract promises.
     */
    #recordGlobals() {
        for (const key of this.#ownedGlobalKeys)
            recordGlobalValue(key, this.#globalOwner);
    }
    helpers;
    #cwd;
    #session;
    sessionId;
    #env;
    #als = new AsyncLocalStorage();
    #callSiteAls = new AsyncLocalStorage();
    #moduleLoader;
    #localRoots;
    #namespaceRevision = 0;
    #initialGlobalKeys = new Set();
    #initialIntrinsics = {
        String: globalThis.String,
        JSON: globalThis.JSON,
        stringify: globalThis.JSON.stringify,
        arrayJoin: Array.prototype.join,
        objectToString: Object.prototype.toString,
    };
    #installedCallTool;
    snapshotUserGlobals() {
        this.#activateGlobals("snapshot user globals");
        const values = {};
        const snapshotState = { nodes: 0, bytes: 0, seen: new Set() };
        for (const key of Object.getOwnPropertyNames(globalThis)) {
            if (this.#ownedGlobalKeys.has(key) || this.#initialGlobalKeys.has(key))
                continue;
            const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
            if (!descriptor || !("value" in descriptor))
                continue;
            const copied = copyShadowValue(descriptor.value, 0, snapshotState);
            if (copied !== undefined)
                values[key] = copied;
        }
        // A retained cell may replace these without leaving any snapshot trace
        // (functions are never JSON-safe, and `delete` removes the key entirely),
        // so record their identity explicitly. The `JSON` short-circuit guards the
        // property access when a prior cell nulled the whole object.
        const currentJSON = globalThis.JSON;
        const initialGlobals = {
            String: globalThis.String === this.#initialIntrinsics.String,
            JSON: currentJSON === this.#initialIntrinsics.JSON,
            "JSON.stringify": typeof currentJSON === "object" &&
                currentJSON !== null &&
                currentJSON === this.#initialIntrinsics.JSON &&
                currentJSON.stringify === this.#initialIntrinsics.stringify,
            "Array.prototype.join": Array.prototype.join === this.#initialIntrinsics.arrayJoin,
            "Object.prototype.toString": Object.prototype.toString === this.#initialIntrinsics.objectToString,
            __omp_call_tool__: globalThis.__omp_call_tool__ === this.#installedCallTool,
        };
        return Object.freeze({
            revision: this.#namespaceRevision,
            values: Object.freeze(values),
            initialGlobals: Object.freeze(initialGlobals),
        });
    }
    constructor(opts) {
        this.#cwd = opts.initialCwd;
        this.#session = { cwd: opts.initialCwd, sessionId: opts.sessionId };
        this.sessionId = opts.sessionId;
        this.#env = new Map();
        this.#moduleLoader = new LocalModuleLoader(this.sessionId);
        this.#moduleLoader.setPackageRoot(opts.packageRoot);
        this.#localRoots = opts.localRoots ?? {};
        this.helpers = createHelpers({
            cwd: () => this.#activeCwd(),
            env: this.#env,
            localRoots: () => this.#als.getStore()?.localRoots ?? this.#localRoots,
            emitStatus: event => this.#activeHooks("emitStatus")?.onDisplay({ type: "status", event }),
        });
        this.#initialGlobalKeys = new Set(Object.getOwnPropertyNames(globalThis));
        this.#install(opts.extraGlobals);
    }
    get cwd() {
        return this.#cwd;
    }
    setCwd(cwd) {
        if (this.#disposed)
            throw new Error("Cannot set cwd on a disposed JS runtime");
        // Always stamp the runtime and session state: WorkerCore/browser/cmux call
        // setCwd from init and pre-run paths that may race another same-realm
        // runtime, and a throw here used to escape the harness microtask path as
        // a fatal unhandledRejection that killed the whole session.
        // #session is the same object saved in this owner's global stack entry,
        // so the new cwd survives deferred activation and is visible to this
        // runtime's next run; run()/setRunScope still assert exclusive ownership.
        this.#cwd = cwd;
        this.#session.cwd = cwd;
        if (activeGlobalRunOwner === null || activeGlobalRunOwner === this.#globalOwner) {
            this.#activateGlobals("set cwd");
        }
    }
    setPackageRoot(packageRoot) {
        if (this.#disposed)
            throw new Error("Cannot set package root on a disposed JS runtime");
        this.#moduleLoader.setPackageRoot(packageRoot);
    }
    /** The session's internal-URL roots move with it (a re-adopted session has a new artifacts dir). */
    setLocalRoots(localRoots) {
        this.#localRoots = localRoots ?? {};
    }
    /**
     * Install per-run globals. Intended for run-scoped state (browser's `tab`, `display`
     * overrides, etc.). Overwrites previous assignments — caller is responsible for any
     * cleanup it wants.
     */
    setRunScope(scope) {
        this.#activateGlobals("set run scope");
        for (const key in scope) {
            this.#ownGlobal(key);
            globalThis[key] = scope[key];
            recordGlobalValue(key, this.#globalOwner);
        }
    }
    /**
     * Synchronize enabled capability snippets before an ordinary eval cell.
     * Unchanged sources retain their objects; removed or replaced definitions
     * release every declared global before replacement source runs.
     */
    syncPreludes(preludes) {
        if (preludes.length === 0 && this.#installedPreludes.size === 0)
            return;
        this.#activateGlobals("sync eval preludes");
        const desired = new Map();
        const exportOwners = new Map();
        for (const prelude of preludes) {
            if (desired.has(prelude.name))
                throw new Error(`Duplicate eval prelude name: ${prelude.name}`);
            for (const name of prelude.exports) {
                if (this.#reservedGlobalKeys.has(name)) {
                    throw new Error(`Eval prelude ${prelude.name} cannot replace reserved global ${name}`);
                }
                const owner = exportOwners.get(name);
                if (owner)
                    throw new Error(`Eval preludes ${owner} and ${prelude.name} both export ${name}`);
                exportOwners.set(name, prelude.name);
            }
            desired.set(prelude.name, prelude);
        }
        for (const [name, installed] of this.#installedPreludes) {
            const next = desired.get(name);
            if (next &&
                next.source === installed.source &&
                next.exports.length === installed.exports.length &&
                next.exports.every((value, index) => value === installed.exports[index])) {
                continue;
            }
            for (const exported of installed.exports)
                this.#releaseGlobal(exported);
            this.#installedPreludes.delete(name);
        }
        for (const [name, prelude] of desired) {
            if (this.#installedPreludes.has(name))
                continue;
            for (const exported of prelude.exports)
                this.#ownGlobal(exported);
            try {
                indirectEval(prelude.source, `[eval-prelude:${name}]`);
                for (const exported of prelude.exports)
                    recordGlobalValue(exported, this.#globalOwner);
                this.#installedPreludes.set(name, {
                    name,
                    exports: [...prelude.exports],
                    source: prelude.source,
                });
            }
            catch (error) {
                for (const exported of prelude.exports)
                    this.#releaseGlobal(exported);
                throw error;
            }
        }
    }
    /** Read a prelude-owned global from this runtime's active global set. */
    getGlobal(name) {
        this.#activateGlobals("read runtime global");
        return Reflect.get(globalThis, name);
    }
    /** Invoke a callback inside this runtime's async run context. */
    async runCallback(runId, hooks, callback) {
        this.#activateGlobals("run callback");
        const leaveRun = enterGlobalRun(this.#globalOwner, "run callback");
        const context = {
            runId,
            hooks,
            cwd: this.#cwd,
            localRoots: this.#localRoots,
            finalExpressionSet: false,
            finalExpressionValue: undefined,
            callOccurrences: new Map(),
        };
        try {
            return await this.#als.run(context, callback);
        }
        finally {
            this.#recordGlobals();
            leaveRun();
        }
    }
    async run(code, filename, hooks, options = {}) {
        this.#activateGlobals("run code");
        this.#namespaceRevision++;
        const leaveRun = enterGlobalRun(this.#globalOwner, "run code");
        const context = {
            runId: options.runId ?? crypto.randomUUID(),
            hooks,
            cwd: options.cwd ?? this.#cwd,
            localRoots: options.localRoots ?? this.#localRoots,
            filename,
            finalExpressionSet: false,
            finalExpressionValue: undefined,
            callOccurrences: new Map(),
        };
        try {
            return await this.#als.run(context, async () => {
                const wrapped = await wrapCode(code);
                let value;
                hooks.onEvaluate?.();
                try {
                    value = indirectEval(wrapped.source, filename);
                }
                catch (error) {
                    // The engine's own compile SyntaxError has no usable cell position; surface Babel's.
                    // Sync cells run inside indirectEval, so a SyntaxError may also be a runtime one
                    // (e.g. JSON.parse); only diagnose when the source itself fails to compile as a script.
                    if (error instanceof SyntaxError && !compiles(wrapped.source)) {
                        throw (await diagnoseCellSyntaxError(code)) ?? error;
                    }
                    throw error;
                }
                if (wrapped.finalExpressionReturned) {
                    const awaited = await awaitMaybePromise(value);
                    if (context.finalExpressionSet) {
                        const finalValue = context.finalExpressionValue;
                        context.finalExpressionSet = false;
                        context.finalExpressionValue = undefined;
                        return await awaitMaybePromise(finalValue);
                    }
                    return awaited;
                }
                return await awaitMaybePromise(value);
            });
        }
        finally {
            this.#recordGlobals();
            leaveRun();
        }
    }
    displayValue(value, hooks = this.#als.getStore()?.hooks) {
        if (value === undefined)
            return;
        if (!hooks) {
            logger.warn("js runtime display called outside an active run");
            return;
        }
        if (value && typeof value === "object") {
            const record = isRecord(value) ? value : {};
            if (record.type === "image" && typeof record.mimeType === "string") {
                const data = coerceImageBase64(record.data);
                if (data !== null) {
                    hooks.onDisplay({ type: "image", data, mimeType: record.mimeType, ...evalImageMetadata(record) });
                    return;
                }
                logger.warn("js displayValue: dropping image with unrecognized data shape", {
                    mimeType: record.mimeType,
                    dataType: describeDataType(record.data),
                });
                hooks.onText(`[display: image dropped — \`data\` must be a base64 string, Uint8Array/Buffer, or ArrayBuffer; got ${describeDataType(record.data)}]\n`);
                return;
            }
            try {
                hooks.onDisplay({ type: "json", data: structuredClone(value) });
            }
            catch (err) {
                logger.debug("js displayValue: value is not structured-cloneable, falling back to text", {
                    error: err instanceof Error ? err.message : String(err),
                });
                hooks.onText(`${Object.prototype.toString.call(value)}\n`);
            }
            return;
        }
        hooks.onText(`${String(value)}\n`);
    }
    #activeCwd() {
        return this.#als.getStore()?.cwd ?? this.#cwd;
    }
    #activeFilename() {
        const filename = this.#als.getStore()?.filename;
        return filename && path.isAbsolute(filename) ? filename : undefined;
    }
    #activeHooks(action) {
        const hooks = this.#als.getStore()?.hooks;
        if (!hooks) {
            logger.warn("js runtime helper called outside an active run", { action });
        }
        return hooks;
    }
    #activeRequire(moduleUrlOrPath) {
        return this.#moduleLoader.requireForFile(moduleUrlOrPath ?? this.#activeFilename(), this.#activeCwd());
    }
    #moduleFilename(moduleUrlOrPath) {
        return (this.#moduleLoader.filenameForUrl(moduleUrlOrPath ?? this.#activeFilename()) ??
            path.join(this.#activeCwd(), "[eval]"));
    }
    #moduleDirname(moduleUrlOrPath) {
        return this.#moduleLoader.dirnameForUrl(moduleUrlOrPath ?? this.#activeFilename(), this.#activeCwd());
    }
    #buildDynamicRequire() {
        const dynamicRequire = ((id) => this.#activeRequire()(id));
        const resolve = ((id, options) => this.#activeRequire().resolve(id, options));
        resolve.paths = request => this.#activeRequire().resolve.paths(request);
        Object.defineProperties(dynamicRequire, {
            resolve: { value: resolve, configurable: true },
            cache: { get: () => this.#activeRequire().cache, configurable: true },
            extensions: { get: () => this.#activeRequire().extensions, configurable: true },
            main: { get: () => this.#activeRequire().main, configurable: true },
        });
        return dynamicRequire;
    }
    #install(extraGlobals) {
        // Constructing a runtime while another same-realm runtime is mid-run would
        // silently replace the live runtime's globals (Object.assign + prelude eval
        // below). Fail before any global/stack mutation; WorkerCore reports it as
        // init-failed instead of corrupting the active run.
        assertCanUseGlobalOwner(this.#globalOwner, "initialize a JS runtime");
        const injected = {
            __omp_session__: this.#session,
            __omp_helpers__: this.helpers,
            __omp_with_call_site__: (siteId, action) => {
                const context = this.#als.getStore();
                if (!context)
                    return action();
                const occurrence = context.callOccurrences.get(siteId) ?? 0;
                context.callOccurrences.set(siteId, occurrence + 1);
                return this.#callSiteAls.run({ siteId, occurrence }, action);
            },
            __omp_call_tool__: async (name, args) => {
                const hooks = this.#activeHooks("tool");
                if (!hooks)
                    return undefined;
                return surfaceBridgedToolImages(await hooks.callTool(name, args, this.#callSiteAls.getStore()), hooks);
            },
            __omp_prelude__: async (name, parameters) => {
                const hooks = this.#activeHooks("prelude");
                if (!hooks)
                    return undefined;
                const payload = { name, parameters };
                return surfaceBridgedToolImages(await hooks.callTool("__prelude__", payload), hooks);
            },
            __omp_import__: async (source, options) => {
                const filename = this.#activeFilename();
                const baseDir = filename ? path.dirname(filename) : this.#activeCwd();
                const resolved = await this.#moduleLoader.resolveForRun(baseDir, source);
                if (resolved.mode === "local")
                    return resolved.value;
                const target = resolved.target;
                return options !== undefined ? await import(target, options) : await import(target);
            },
            __omp_import_from__: async (moduleUrl, source, options) => {
                const resolved = await this.#moduleLoader.resolveForModule(moduleUrl, source, this.#activeCwd());
                if (resolved.mode === "local")
                    return resolved.value;
                const target = resolved.target;
                return options !== undefined ? await import(target, options) : await import(target);
            },
            __omp_get_require__: (moduleUrl) => this.#activeRequire(moduleUrl),
            __omp_get_filename__: (moduleUrl) => this.#moduleFilename(moduleUrl),
            __omp_get_dirname__: (moduleUrl) => this.#moduleDirname(moduleUrl),
            __omp_emit_status__: (op, data = {}) => {
                const event = { op, ...data };
                this.#activeHooks("emitStatus")?.onDisplay({ type: "status", event });
            },
            __omp_log__: (level, ...args) => {
                const prefix = level === "error" ? "[error] " : level === "warn" ? "[warn] " : "";
                const text = `${prefix}${formatConsoleArgs(args)}`;
                this.#activeHooks("log")?.onText(text.endsWith("\n") ? text : `${text}\n`);
            },
            __omp_table__: (...args) => {
                const hooks = this.#activeHooks("table");
                if (!hooks)
                    return;
                let buffer = "";
                const stream = new Writable({
                    write(chunk, _enc, cb) {
                        buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
                        cb();
                    },
                });
                const tableConsole = new Console({ stdout: stream, colorMode: false });
                // `table` is missing from some @types/node Console shapes, but the
                // Node runtime always provides it.
                const tableCapable = tableConsole;
                tableCapable.table(...args);
                hooks.onText(buffer.endsWith("\n") ? buffer : `${buffer}\n`);
            },
            __omp_display__: (value) => this.displayValue(value),
            __omp_set_final_expr__: (value) => {
                const context = this.#als.getStore();
                if (!context) {
                    logger.warn("js runtime final expression set outside an active run");
                    return;
                }
                context.finalExpressionSet = true;
                context.finalExpressionValue = value;
            },
            webcrypto: crypto,
            // `process` is intentionally not overridden — user code gets the host worker's real
            // `process` object. Subsetting it caused segfaults in workers that share state with
            // puppeteer/worker_threads internals.
            require: this.#buildDynamicRequire(),
            createRequire,
            fs,
        };
        const allGlobalKeys = new Set([
            ...Object.keys(injected),
            ...Object.keys(extraGlobals ?? {}),
            ...PRELUDE_GLOBAL_KEYS,
        ]);
        this.#reservedGlobalKeys = allGlobalKeys;
        for (const key of allGlobalKeys) {
            this.#ownGlobal(key);
        }
        Object.assign(globalThis, injected, extraGlobals ?? {});
        // Prelude assigns console bridge + short aliases (`read`, `write`, `tool`, `display`, ...)
        // onto globalThis. Must run after helpers are in place.
        indirectEval(JAVASCRIPT_PRELUDE_SOURCE);
        for (const key of allGlobalKeys)
            recordGlobalValue(key, this.#globalOwner);
        // Capture the installed bridge dispatcher for the snapshot identity
        // flag below. The prelude tool proxy resolves `__omp_call_tool__` per
        // call, so the flag must track this binding. (Steady-state retained
        // replacements self-heal: owned-global activation restores the recorded
        // value before any observation. The `tool` binding itself needs no
        // flag: the prelude declares it as a lexical const, which shadows any
        // `globalThis.tool` replacement for bare references.)
        this.#installedCallTool = globalThis.__omp_call_tool__;
        RUN_HOOK_RESOLVERS.add(this.#runHookResolver);
        patchStdioOnce();
    }
    dispose() {
        if (this.#disposed)
            return;
        this.#disposed = true;
        RUN_HOOK_RESOLVERS.delete(this.#runHookResolver);
        for (const key of this.#ownedGlobalKeys)
            releaseGlobalKey(key, this.#globalOwner);
        this.#ownedGlobalKeys.clear();
        this.#reservedGlobalKeys.clear();
        this.#installedPreludes.clear();
    }
}
// Same-realm harnesses and cmux tabs can create multiple JsRuntime instances in one Bun realm.
// Track reserved helper globals by owner so disposing one runtime restores the next active
// owner (or the original process global after the last owner), not a stale snapshot.
const GLOBAL_STACKS = new Map();
function snapshotGlobal(key) {
    return {
        exists: key in globalThis,
        value: globalThis[key],
    };
}
function restoreGlobal(key, state) {
    if (state.exists) {
        globalThis[key] = state.value;
    }
    else {
        delete globalThis[key];
    }
}
function claimGlobalKey(key, owner) {
    let stack = GLOBAL_STACKS.get(key);
    if (!stack) {
        stack = { base: snapshotGlobal(key), entries: [] };
        GLOBAL_STACKS.set(key, stack);
    }
    stack.entries.push({ owner, value: globalThis[key] });
}
function recordGlobalValue(key, owner) {
    const stack = GLOBAL_STACKS.get(key);
    const entry = stack?.entries.findLast(item => item.owner === owner);
    if (entry)
        entry.value = globalThis[key];
}
function releaseGlobalKey(key, owner) {
    const stack = GLOBAL_STACKS.get(key);
    if (!stack)
        return;
    const index = stack.entries.findIndex(entry => entry.owner === owner);
    if (index === -1)
        return;
    const wasTop = index === stack.entries.length - 1;
    stack.entries.splice(index, 1);
    if (!wasTop)
        return;
    const next = stack.entries.at(-1);
    if (next) {
        globalThis[key] = next.value;
        return;
    }
    restoreGlobal(key, stack.base);
    GLOBAL_STACKS.delete(key);
}
// Plain globalThis cannot safely serve two different runtimes at the same instant:
// helpers dereference reserved globals on every call. Sequential cmux tab revisits
// re-activate their owner stack; overlapping cross-runtime runs fail explicitly.
let activeGlobalRunOwner = null;
let activeGlobalRunDepth = 0;
function assertCanUseGlobalOwner(owner, action) {
    if (activeGlobalRunOwner === null || activeGlobalRunOwner === owner)
        return;
    throw new Error(`Cannot ${action} while another same-realm JS runtime is running`);
}
function activateGlobalOwner(owner, keys, action) {
    assertCanUseGlobalOwner(owner, action);
    for (const key of keys) {
        const stack = GLOBAL_STACKS.get(key);
        const index = stack?.entries.findIndex(entry => entry.owner === owner) ?? -1;
        if (!stack || index === -1)
            throw new Error(`Cannot ${action} on a disposed JS runtime`);
        const entry = stack.entries[index];
        stack.entries.splice(index, 1);
        stack.entries.push(entry);
        globalThis[key] = entry.value;
    }
}
function enterGlobalRun(owner, action) {
    assertCanUseGlobalOwner(owner, action);
    activeGlobalRunOwner = owner;
    activeGlobalRunDepth++;
    let left = false;
    return () => {
        if (left)
            return;
        left = true;
        activeGlobalRunDepth--;
        if (activeGlobalRunDepth === 0)
            activeGlobalRunOwner = null;
    };
}
/** Resolvers for each live runtime's active-run hooks (one per JsRuntime instance). */
const RUN_HOOK_RESOLVERS = new Set();
/** Streams whose `write` the runtime has already wrapped (patch-once guard). */
const PATCHED_STDIO_STREAMS = new WeakSet();
/** Hooks for whichever registered runtime currently has an active run, if any. */
function activeRunHooks() {
    for (const resolve of RUN_HOOK_RESOLVERS) {
        const hooks = resolve();
        if (hooks)
            return hooks;
    }
    return undefined;
}
/**
 * Wrap `process.stdout` / `process.stderr` `write` exactly once per process so
 * user `process.stdout.write(...)` lands in the active run's text sink. Models
 * reach for it out of Node habit, but `process` is intentionally the host
 * worker's real object (see {@link JsRuntime} `#install`), so unrouted writes
 * escape to the worker's own stdio and never reach the cell — and `write()`
 * returns a boolean, so a cell ending in `process.stdout.write("x")` captured
 * `true` while losing the text. Patch only the `write` method (never replace
 * `process`), preserve exact bytes (no trailing newline), and fall through to
 * the real stream when no run is active so the worker's own logging is intact.
 */
function patchStdioOnce() {
    const streams = [process.stdout, process.stderr];
    for (const stream of streams) {
        if (!stream || PATCHED_STDIO_STREAMS.has(stream))
            continue;
        PATCHED_STDIO_STREAMS.add(stream);
        const original = stream.write.bind(stream);
        const routed = (chunk, encoding, callback) => {
            const hooks = activeRunHooks();
            if (!hooks)
                return original(chunk, encoding, callback);
            const cb = typeof encoding === "function" ? encoding : callback;
            const enc = typeof encoding === "string" ? encoding : undefined;
            hooks.onText(chunkToString(chunk, enc));
            if (typeof cb === "function")
                cb();
            return true;
        };
        stream.write = routed;
    }
}
/** Coerce a `write()` chunk to text, honoring an explicit encoding for byte chunks. */
function chunkToString(chunk, encoding) {
    if (typeof chunk === "string")
        return chunk;
    if (chunk instanceof Uint8Array)
        return Buffer.from(chunk).toString(encoding ?? "utf8");
    return String(chunk);
}
function formatConsoleArgs(args) {
    return args
        .map(arg => (typeof arg === "string" ? arg : util.inspect(arg, { depth: 6, colors: false, breakLength: 120 })))
        .join(" ");
}
