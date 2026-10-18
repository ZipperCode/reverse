import { ToolError } from "@rva/tui/tools/tool-errors";
import { JsRuntime, shadowSnapshotDigest } from "./shared/runtime";
function isKernelToolSpec(value) {
    if (value === null || typeof value !== "object")
        return false;
    return (typeof Reflect.get(value, "name") === "string" &&
        typeof Reflect.get(value, "fn") === "function" &&
        typeof Reflect.get(value, "description") === "string" &&
        Reflect.get(value, "parameters") !== null &&
        typeof Reflect.get(value, "parameters") === "object");
}
/** Finished-cell filenames retained for attributing rejections that surface after the run settled. */
const RECENT_CELL_FILES_MAX = 256;
function errorPayload(error) {
    if (error instanceof Error) {
        return {
            name: error.name,
            message: error.message,
            stack: error.stack,
            isAbort: error.name === "AbortError" || error.name === "ToolAbortError",
            isToolError: error.name === "ToolError" || error instanceof ToolError,
        };
    }
    return { message: String(error) };
}
function errorFromPayload(payload) {
    const ctor = payload.isToolError ? ToolError : Error;
    const error = new ctor(payload.message);
    if (payload.name)
        error.name = payload.name;
    if (payload.stack)
        error.stack = payload.stack;
    return error;
}
/**
 * Fold rejections floated by cell code into the run result: an otherwise
 * successful run fails with the first floating rejection (an unawaited promise
 * failing is a cell failure, not a success with noise); the rest surface as
 * output text so nothing is silently dropped.
 */
function foldFloatingRejections(active, result, hooks) {
    const rejections = active.floatingRejections;
    if (rejections.length === 0)
        return result;
    let folded = result;
    let reported = rejections;
    if (result.ok) {
        const error = errorPayload(rejections[0]);
        error.message = `Unhandled rejection (missing await?): ${error.message}`;
        folded = { type: "result", runId: active.runId, ok: false, error };
        reported = rejections.slice(1);
    }
    for (const reason of reported) {
        const payload = errorPayload(reason);
        hooks.onText(`[unhandled rejection] ${payload.name ?? "Error"}: ${payload.message}\n`);
    }
    return folded;
}
export class WorkerCore {
    #transport;
    #runtime = null;
    #runs = new Map();
    #pendingTools = new Map();
    #recentCellFiles = new Set();
    #unsubscribe;
    #uninstallRejectionGuard;
    #options;
    constructor(transport, options) {
        this.#transport = transport;
        this.#options = options;
        this.#unsubscribe = transport.onMessage(msg => this.#handle(msg));
        this.#uninstallRejectionGuard = this.#installRejectionGuard();
    }
    /**
     * Capture unhandled rejections floated by eval-cell code (unawaited async
     * calls) so they fail the owning run instead of tearing down the worker or —
     * via the global postmortem handler — the whole session. On the main thread
     * (same-realm unit harness) only cell-attributable rejections are consumed;
     * in the dedicated worker realm a rejection during a live run is cell activity even
     * without a usable stack, while anything else keeps its default fatality.
     */
    #installRejectionGuard() {
        if (this.#options.interceptUnhandledRejections) {
            return this.#options.interceptUnhandledRejections(reason => this.#consumeRejection(reason));
        }
        const onRejection = (reason) => {
            if (this.#consumeRejection(reason))
                return;
            // Not cell-attributable: restore default fatality. Rethrowing from a
            // timer surfaces it as an uncaught exception, which reaches the host
            // as a worker `error` event exactly like an unhandled rejection did
            // before this listener existed.
            setTimeout(() => {
                throw reason;
            }, 0);
        };
        process.on("unhandledRejection", onRejection);
        return () => {
            process.off("unhandledRejection", onRejection);
        };
    }
    /**
     * Attribute an unhandled rejection to eval-cell code. Live runs are stashed
     * on the run (folded into its result after the settle drain); finished cells
     * downgrade to a host-side warn log. Returns false when the rejection is not
     * cell activity and must keep the default fatal path.
     */
    #consumeRejection(reason) {
        const stack = reason instanceof Error && typeof reason.stack === "string" ? reason.stack : undefined;
        if (stack) {
            // The stack can name several cells (helper defined by an earlier cell,
            // called from the live one); the outermost matching frame is the caller
            // that owns the floating promise.
            let owner;
            let ownerIndex = -1;
            for (const run of this.#runs.values()) {
                const index = stack.lastIndexOf(run.filename);
                if (index > ownerIndex) {
                    ownerIndex = index;
                    owner = run;
                }
            }
            if (owner) {
                owner.floatingRejections.push(reason);
                return true;
            }
            let recent;
            let recentIndex = -1;
            for (const filename of this.#recentCellFiles) {
                const index = stack.lastIndexOf(filename);
                if (index > recentIndex) {
                    recentIndex = index;
                    recent = filename;
                }
            }
            if (recent) {
                this.#transport.send({
                    type: "log",
                    level: "warn",
                    msg: "Unhandled rejection from a finished eval cell (missing await?)",
                    meta: { filename: recent, error: errorPayload(reason) },
                });
                return true;
            }
        }
        if (this.#options.mode === "isolated" && this.#runs.size > 0) {
            // Dedicated eval worker: during a live run, a rejection without a cell
            // frame (e.g. `Promise.reject("msg")` or a library-created reason) is
            // still cell activity — nothing else runs user code in this realm.
            if (this.#runs.size === 1) {
                const only = this.#runs.values().next().value;
                only?.floatingRejections.push(reason);
                return true;
            }
            this.#transport.send({
                type: "log",
                level: "warn",
                msg: "Unhandled rejection during concurrent eval runs; cannot attribute to a cell",
                meta: { error: errorPayload(reason) },
            });
            return true;
        }
        return false;
    }
    #handle(msg) {
        switch (msg.type) {
            case "init":
                try {
                    this.#ensureRuntime(msg.snapshot);
                    this.#transport.send({ type: "ready" });
                }
                catch (error) {
                    // Same-realm harnesses deliver messages on a microtask. A sync throw
                    // from ensureRuntime/setCwd would otherwise become a process-fatal
                    // unhandledRejection on the main thread.
                    this.#transport.send({ type: "init-failed", error: errorPayload(error) });
                }
                return;
            case "run":
                void this.#runOne(msg.runId, msg.code, msg.filename, msg.snapshot);
                return;
            case "tool":
                void this.#invokeTool(msg);
                return;
            case "shadow-snapshot": {
                if (this.#runs.size > 0) {
                    this.#transport.send({
                        type: "shadow-snapshot",
                        id: msg.id,
                        eligible: false,
                        reason: "runtime is busy",
                    });
                    return;
                }
                try {
                    const runtime = this.#ensureRuntime(msg.snapshot);
                    this.#transport.send({
                        type: "shadow-snapshot",
                        id: msg.id,
                        eligible: true,
                        snapshot: runtime.snapshotUserGlobals(),
                    });
                }
                catch (error) {
                    this.#transport.send({
                        type: "shadow-snapshot",
                        id: msg.id,
                        eligible: false,
                        reason: error instanceof Error ? error.message : String(error),
                    });
                }
                return;
            }
            case "run-if-snapshot-matches": {
                if (this.#runs.size > 0) {
                    this.#transport.send({ type: "shadow-run", id: msg.id, eligible: false, reason: "runtime is busy" });
                    return;
                }
                try {
                    const runtime = this.#ensureRuntime(msg.snapshot);
                    const current = runtime.snapshotUserGlobals();
                    if (current.revision !== msg.expectedRevision || shadowSnapshotDigest(current) !== msg.expectedDigest) {
                        this.#transport.send({ type: "shadow-run", id: msg.id, eligible: false, reason: "snapshot changed" });
                        return;
                    }
                    this.#transport.send({ type: "shadow-run", id: msg.id, eligible: true });
                    void this.#runOne(msg.runId, msg.code, msg.filename, msg.snapshot);
                }
                catch (error) {
                    this.#transport.send({
                        type: "shadow-run",
                        id: msg.id,
                        eligible: false,
                        reason: error instanceof Error ? error.message : String(error),
                    });
                }
                return;
            }
            case "tool-reply":
                this.#deliverToolReply(msg.id, msg.reply);
                return;
            case "close":
                this.#close();
                return;
        }
    }
    #ensureRuntime(snapshot, currentRunId) {
        this.#syncProcessCwd(snapshot.cwd, currentRunId);
        if (this.#runtime) {
            this.#runtime.setCwd(snapshot.cwd);
            this.#runtime.setPackageRoot(snapshot.packageRoot);
            this.#runtime.setLocalRoots(snapshot.localRoots);
            return this.#runtime;
        }
        this.#runtime = new JsRuntime({
            initialCwd: snapshot.cwd,
            sessionId: snapshot.sessionId,
            localRoots: snapshot.localRoots,
            packageRoot: snapshot.packageRoot,
        });
        return this.#runtime;
    }
    #syncProcessCwd(cwd, currentRunId) {
        if (this.#options.mode !== "isolated" || !this.#options.chdir)
            return;
        try {
            if (process.cwd() === cwd)
                return;
        }
        catch {
            // The current cwd was deleted; the chdir below is the recovery.
        }
        // Process cwd is realm-wide state. Moving it while another cell is mid-run
        // would silently redirect that cell's `process.cwd()`, relative fs access,
        // and child spawns, so keep it in place; this run still resolves against
        // its own virtual cwd, and the next cell to start alone lands the move.
        for (const runId of this.#runs.keys()) {
            if (runId === currentRunId)
                continue;
            this.#transport.send({
                type: "log",
                level: "warn",
                msg: "JS eval subprocess kept its process cwd: other cells are mid-run",
                meta: { cwd },
            });
            return;
        }
        try {
            this.#options.chdir(cwd);
        }
        catch (error) {
            // `process.chdir` throws when the session cwd no longer exists; keep
            // the cell on the runtime's virtual cwd instead of failing the run.
            this.#transport.send({
                type: "log",
                level: "warn",
                msg: "JS eval subprocess could not enter the session cwd",
                meta: { cwd, error: errorPayload(error) },
            });
        }
    }
    async #runOne(runId, code, filename, snapshot) {
        const active = { runId, filename, floatingRejections: [] };
        this.#runs.set(runId, active);
        const hooks = {
            onText: chunk => this.#transport.send({ type: "text", runId, chunk }),
            onDisplay: output => this.#transport.send({ type: "display", runId, output }),
            callTool: (name, args, identity) => this.#callTool(active, name, args, identity),
        };
        let result;
        try {
            const runtime = this.#ensureRuntime(snapshot, runId);
            runtime.setCwd(snapshot.cwd);
            runtime.syncPreludes(snapshot.preludes ?? []);
            const value = await runtime.run(code, filename, hooks, {
                runId,
                cwd: snapshot.cwd,
                localRoots: snapshot.localRoots ?? {},
            });
            runtime.displayValue(value, hooks);
            result = { type: "result", runId, ok: true };
        }
        catch (error) {
            result = { type: "result", runId, ok: false, error: errorPayload(error) };
        }
        try {
            // One event-loop turn so rejections the cell already floated surface
            // while this run can still own them (rejection callbacks run before
            // timers fire).
            await Bun.sleep(0);
            result = foldFloatingRejections(active, result, hooks);
        }
        finally {
            this.#runs.delete(runId);
            this.#rememberCellFile(filename);
            this.#transport.send(result);
        }
    }
    async #invokeTool(msg) {
        const active = {
            runId: msg.runId,
            filename: `tool-${msg.runId}`,
            floatingRejections: [],
        };
        this.#runs.set(msg.runId, active);
        const hooks = {
            onText: chunk => this.#transport.send({ type: "text", runId: msg.runId, chunk }),
            onDisplay: output => this.#transport.send({ type: "display", runId: msg.runId, output }),
            callTool: (name, args) => this.#callTool(active, name, args),
        };
        try {
            const runtime = this.#runtime;
            if (!runtime)
                throw new ToolError("JavaScript kernel is not running");
            const rawRegistry = runtime.getGlobal("__omp_tools__");
            const tools = new Map();
            if (rawRegistry instanceof Map) {
                for (const [name, value] of rawRegistry) {
                    if (typeof name === "string" && isKernelToolSpec(value))
                        tools.set(name, value);
                }
            }
            let envelope;
            if (msg.op === "describe") {
                const names = msg.names.length > 0 ? msg.names : [...tools.keys()];
                envelope = {
                    ok: true,
                    tools: names.flatMap(name => {
                        const spec = tools.get(name);
                        return spec ? [{ name: spec.name, description: spec.description, parameters: spec.parameters }] : [];
                    }),
                    missing: names.filter(name => !tools.has(name)),
                };
            }
            else {
                const spec = tools.get(msg.name);
                if (!spec)
                    throw new ToolError(`tool ${JSON.stringify(msg.name)} is not defined`);
                const value = await runtime.runCallback(msg.runId, hooks, () => spec.fn(msg.args ?? {}));
                let cloneable;
                try {
                    cloneable = structuredClone(value);
                }
                catch {
                    cloneable = String(value);
                }
                envelope = { ok: true, value: cloneable };
            }
            this.#transport.send({ type: "display", runId: msg.runId, output: { type: "json", data: envelope } });
            this.#transport.send({ type: "result", runId: msg.runId, ok: true });
        }
        catch (error) {
            this.#transport.send({ type: "result", runId: msg.runId, ok: false, error: errorPayload(error) });
        }
        finally {
            this.#runs.delete(msg.runId);
            this.#rememberCellFile(active.filename);
        }
    }
    #rememberCellFile(filename) {
        this.#recentCellFiles.delete(filename);
        this.#recentCellFiles.add(filename);
        if (this.#recentCellFiles.size > RECENT_CELL_FILES_MAX) {
            const oldest = this.#recentCellFiles.values().next().value;
            if (oldest !== undefined)
                this.#recentCellFiles.delete(oldest);
        }
    }
    async #callTool(active, name, args, identity) {
        const id = `tc-${active.runId}-${crypto.randomUUID()}`;
        const { promise, resolve, reject } = Promise.withResolvers();
        this.#pendingTools.set(id, { resolve, reject });
        try {
            this.#transport.send({ type: "tool-call", id, runId: active.runId, name, args, identity });
        }
        catch (error) {
            // Non-serializable args (DataCloneError from postMessage / IPC send).
            // No reply will ever arrive; fail this call instead of stranding a
            // pending entry until close.
            this.#pendingTools.delete(id);
            reject(error);
        }
        return await promise;
    }
    #deliverToolReply(id, reply) {
        const pending = this.#pendingTools.get(id);
        if (!pending)
            return;
        this.#pendingTools.delete(id);
        if (reply.ok)
            pending.resolve(reply.value);
        else
            pending.reject(errorFromPayload(reply.error));
    }
    #close() {
        for (const pending of this.#pendingTools.values()) {
            pending.reject(new ToolError("JS worker closed"));
        }
        this.#pendingTools.clear();
        this.#runs.clear();
        this.#runtime?.dispose?.();
        this.#runtime = null;
        this.#transport.send({ type: "closed" });
        this.#uninstallRejectionGuard();
        this.#unsubscribe();
        this.#transport.close();
    }
    dispose() {
        for (const pending of this.#pendingTools.values()) {
            pending.reject(new ToolError("JS worker closed"));
        }
        this.#pendingTools.clear();
        this.#runs.clear();
        this.#runtime?.dispose?.();
        this.#runtime = null;
        this.#uninstallRejectionGuard();
        this.#unsubscribe();
        try {
            this.#transport.close();
        }
        catch {
            // Ignore
        }
    }
}
