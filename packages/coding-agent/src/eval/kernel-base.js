import { logger, readLines, Snowflake } from "@rva/utils";
import { renderKernelDisplay } from "./py/display";
const STARTUP_CONTROL_TIMEOUT_MS = 5000;
async function raceControlTimeout(promise, timeoutMs, reason) {
    const signal = AbortSignal.timeout(timeoutMs);
    const { promise: timeout, reject } = Promise.withResolvers();
    const onAbort = () => reject(new Error(reason));
    signal.addEventListener("abort", onAbort, { once: true });
    try {
        return await Promise.race([promise, timeout]);
    }
    finally {
        signal.removeEventListener("abort", onAbort);
    }
}
export function getRemainingTimeMs(deadlineMs) {
    if (deadlineMs === undefined)
        return undefined;
    return Math.max(0, deadlineMs - Date.now());
}
/**
 * True when `pid` is safe to use as a process-group target for `kill(2)`.
 *
 * `process.kill(-pid, …)` is a group signal, and the degenerate targets are
 * catastrophic rather than merely useless: `-0` signals *our own* process group
 * (omp would kill itself along with the whole terminal job) and `-1` signals
 * every process the user is permitted to signal. Both must be rejected before
 * the negation is applied.
 */
export function isSignalableProcessGroup(pid) {
    return typeof pid === "number" && Number.isInteger(pid) && pid > 1;
}
/**
 * Signal the whole process group led by `pid`, returning true when a signal was
 * actually delivered.
 *
 * Kernels are spawned with `detached: true` on POSIX (see `shouldDetachKernel`),
 * so each runner calls `setsid()` and becomes the leader of its own session and
 * process group. Signalling only the direct PID therefore leaves anything the
 * runner itself spawned behind, and those orphans keep the kernel's pipes open
 * for the remainder of the omp process lifetime (#7714).
 *
 * Windows has no process groups, so this is a no-op there and callers keep
 * relying on the direct-PID kill.
 */
export function killProcessGroup(pid, signal) {
    if (process.platform === "win32")
        return false;
    if (!isSignalableProcessGroup(pid))
        return false;
    try {
        process.kill(-pid, signal);
        return true;
    }
    catch {
        // ESRCH: the group is already gone, which is the outcome we wanted anyway.
        // EPERM: not ours to signal. Neither is worth failing a shutdown over.
        return false;
    }
}
export function createAbortError(name, message) {
    const err = new Error(message);
    err.name = name;
    return err;
}
export function throwIfAborted(signal, fallbackReason) {
    if (!signal?.aborted)
        return;
    const reason = signal.reason;
    if (reason instanceof Error)
        throw reason;
    throw createAbortError("AbortError", typeof reason === "string" ? reason : fallbackReason);
}
export function isTimeoutReason(reason) {
    if (reason instanceof DOMException)
        return reason.name === "TimeoutError";
    if (reason instanceof Error)
        return reason.name === "TimeoutError";
    return false;
}
/**
 * Shared subprocess-backed kernel machinery for the language runners. Each
 * language subclasses this, supplying its binary/runner via a static `start()`
 * and its wire protocol via {@link BaseKernelOptions.buildPayload}. The IPC loop
 * speaks NDJSON: the runner emits one JSON {@link Frame} per line; outbound
 * requests are serialized by `buildPayload` (which may itself be NDJSON or any
 * other line-delimited encoding).
 *
 * `TExecuteOptions` is the language's own execute-options type so each runner's
 * `buildPayload` sees its precise option shape (e.g. environment-map variants).
 */
export class BaseKernel {
    id;
    #proc = null;
    #stdin = null;
    #alive = true;
    #disposed = false;
    #shutdownConfirmed = false;
    #shutdownInFlight = null;
    #exitedPromise = null;
    #pending = new Map();
    #pendingControls = new Map();
    #options;
    constructor(id, options) {
        this.id = id;
        this.#options = options;
    }
    setProcess(proc) {
        this.#proc = proc;
        this.#stdin = proc.stdin;
        this.#exitedPromise = proc.exited;
        void this.#exitedPromise.then(code => {
            this.#alive = false;
            this.#abortPendingExecutions(`${this.#options.languageName} kernel exited with code ${code}`, {
                kernelKilled: true,
            });
        });
        this.#startReader(proc.stdout);
        this.#startStderrDrain(proc.stderr);
    }
    isAlive() {
        return this.#alive && !this.#disposed;
    }
    async execute(code, options) {
        const msgId = options?.id ?? Snowflake.next();
        return await this.#submit(msgId, this.#options.buildPayload(code, msgId, options), options, true);
    }
    /** Submit a raw runner request without sending SIGINT when its caller cancels. */
    async submitRequest(msgId, payload, options) {
        return await this.#submit(msgId, payload, options, false);
    }
    async #submit(msgId, payload, options, interruptOnCancel) {
        if (!this.isAlive()) {
            throw new Error(`${this.#options.languageName} kernel is not running`);
        }
        const { promise, resolve } = Promise.withResolvers();
        const pending = {
            resolve,
            options,
            status: "ok",
            cancelled: false,
            timedOut: false,
            stdinRequested: false,
            settled: false,
            kernelKilled: false,
        };
        this.#pending.set(msgId, pending);
        const finalize = () => {
            if (pending.settled)
                return;
            pending.settled = true;
            this.#pending.delete(msgId);
            cleanup();
            resolve({
                status: pending.status,
                executionCount: pending.executionCount,
                error: pending.error,
                cancelled: pending.cancelled,
                timedOut: pending.timedOut,
                stdinRequested: pending.stdinRequested,
                admissionRejected: pending.admissionRejected,
                kernelKilled: pending.kernelKilled,
            });
        };
        let requestWritten = false;
        const requestCancel = () => {
            if (pending.settled || pending.escalationTimer)
                return;
            if (!requestWritten || !interruptOnCancel) {
                finalize();
                return;
            }
            void this.interrupt();
            const escalation = setTimeout(() => {
                if (pending.settled)
                    return;
                logger.warn(`${this.#options.languageName} runner did not respond to SIGINT; terminating subprocess`, {
                    kernelId: this.id,
                });
                pending.kernelKilled = true;
                void this.shutdown();
            }, this.#options.interruptEscalationMs);
            escalation.unref?.();
            pending.escalationTimer = escalation;
        };
        const onAbort = () => {
            pending.cancelled = true;
            pending.timedOut = pending.timedOut || isTimeoutReason(options?.signal?.reason);
            requestCancel();
        };
        const timeoutId = typeof options?.timeoutMs === "number" && options.timeoutMs > 0
            ? setTimeout(() => {
                pending.timedOut = true;
                pending.cancelled = true;
                requestCancel();
            }, options.timeoutMs)
            : undefined;
        const cleanup = () => {
            clearTimeout(timeoutId);
            clearTimeout(pending.escalationTimer);
            pending.escalationTimer = undefined;
            options?.signal?.removeEventListener("abort", onAbort);
        };
        if (options?.signal) {
            if (options.signal.aborted) {
                onAbort();
            }
            else {
                options.signal.addEventListener("abort", onAbort, { once: true });
                if (options.signal.aborted) {
                    options.signal.removeEventListener("abort", onAbort);
                    onAbort();
                }
            }
        }
        pending.finalize = finalize;
        if (pending.settled) {
            return promise;
        }
        requestWritten = true;
        const transportFailed = (err) => {
            if (!pending.settled) {
                pending.status = "error";
                pending.cancelled = true;
                // The kernel is retired below and a partial write may have run code: completion is uncertain.
                pending.kernelKilled = true;
                pending.error = {
                    name: "TransportError",
                    value: err instanceof Error ? err.message : String(err),
                    traceback: [],
                };
                finalize();
            }
            // A broken stdin pipe is terminal even if this request already settled (e.g. aborted first):
            // retire the kernel so the session starts a fresh one.
            void this.shutdown();
        };
        try {
            await this.#writeLine(payload, transportFailed);
        }
        catch (err) {
            transportFailed(err);
        }
        return promise;
    }
    async requestControl(payload, id = Snowflake.next(), timeoutMs = STARTUP_CONTROL_TIMEOUT_MS) {
        if (!this.isAlive())
            throw new Error(`${this.#options.languageName} kernel is not running`);
        const deferred = Promise.withResolvers();
        this.#pendingControls.set(id, deferred);
        try {
            // A broken stdin pipe is terminal: fail this control request and retire the kernel.
            await this.#writeLine(payload, err => {
                deferred.reject(err);
                void this.shutdown();
            });
            return await raceControlTimeout(deferred.promise, timeoutMs, `${this.#options.languageName} control request timed out`);
        }
        finally {
            this.#pendingControls.delete(id);
        }
    }
    async interrupt() {
        if (!this.#proc || this.#disposed)
            return;
        try {
            this.#proc.kill("SIGINT");
        }
        catch (err) {
            logger.warn(`Failed to interrupt ${this.#options.languageName.toLowerCase()} runner`, {
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }
    /**
     * Concurrent calls (e.g. several in-flight requests hitting the same broken pipe) share one
     * shutdown sequence. An unconfirmed shutdown clears the slot so a later call can retry.
     */
    shutdown(options) {
        if (this.#shutdownConfirmed)
            return Promise.resolve({ confirmed: true });
        this.#shutdownInFlight ??= this.#shutdown(options).finally(() => {
            this.#shutdownInFlight = null;
        });
        return this.#shutdownInFlight;
    }
    async #shutdown(options) {
        this.#alive = false;
        this.#abortPendingExecutions(`${this.#options.languageName} kernel shutdown`, { kernelKilled: true });
        const timeoutMs = options?.timeoutMs ?? this.#options.shutdownGraceMs;
        const proc = this.#proc;
        if (!proc) {
            this.#shutdownConfirmed = true;
            this.#disposed = true;
            return { confirmed: true };
        }
        try {
            await this.#writeLine(this.#options.exitPayload).catch(() => { });
        }
        catch {
            /* writer may already be closed */
        }
        try {
            this.#stdin?.end();
        }
        catch {
            /* ignore */
        }
        const exited = this.#waitForExitWithTimeout(timeoutMs);
        let result = await exited;
        if (result === null) {
            try {
                proc.kill("SIGTERM");
            }
            catch {
                /* ignore */
            }
            // The runner leads its own process group (setsid), so the direct-PID
            // signal above never reaches anything it spawned. Sweep the group too.
            killProcessGroup(proc.pid, "SIGTERM");
            result = await this.#waitForExitWithTimeout(timeoutMs);
            if (result === null) {
                try {
                    proc.kill("SIGKILL");
                }
                catch {
                    /* ignore */
                }
            }
        }
        // A confirmed leader exit does not prove its descendants exited, even
        // when the runner honored the shutdown request without any signals.
        killProcessGroup(proc.pid, "SIGKILL");
        if (result === null)
            result = await this.#waitForExitWithTimeout(timeoutMs);
        const confirmed = result !== null;
        if (!confirmed) {
            // Nothing acknowledged the exit. Record the pid so an operator can find
            // the survivor; the group SIGKILL above is our last automatic recourse.
            logger.warn(`${this.#options.languageName} kernel did not confirm exit after SIGKILL`, {
                kernelId: this.id,
                pid: proc.pid,
            });
        }
        this.#shutdownConfirmed = confirmed;
        this.#disposed = true;
        return { confirmed };
    }
    #abortPendingExecutions(reason, options) {
        for (const pending of this.#pendingControls.values()) {
            pending.reject(new Error(reason));
        }
        this.#pendingControls.clear();
        if (this.#pending.size === 0)
            return;
        const pending = Array.from(this.#pending.values());
        this.#pending.clear();
        const kernelKilledDefault = options?.kernelKilled ?? false;
        for (const entry of pending) {
            if (entry.settled)
                continue;
            entry.settled = true;
            void entry.options?.onChunk?.(`[kernel] ${reason}\n`);
            entry.resolve({
                status: "error",
                cancelled: true,
                timedOut: entry.timedOut,
                stdinRequested: entry.stdinRequested,
                executionCount: entry.executionCount,
                error: entry.error,
                kernelKilled: entry.kernelKilled || kernelKilledDefault,
            });
        }
    }
    async #writeLine(line, onWriteFailed) {
        if (!this.#stdin) {
            throw new Error(`${this.#options.languageName} kernel stdin is not open`);
        }
        if (this.#options.traceIpc) {
            logger.debug(`${this.#options.languageName}Kernel send`, { preview: line.slice(0, 120) });
        }
        // Not awaited: callers' timeouts start after this returns, so a wedged pipe must not block here.
        // A failed write (sync throw or rejection) is reported through onWriteFailed; the kernel may stay
        // alive without an exit event.
        const stdin = this.#stdin;
        const write = Promise.try(() => stdin.write(`${line}\n`));
        void write.catch(() => { });
        void Promise.all([write, Promise.try(() => stdin.flush())]).catch(err => {
            logger.debug(`${this.#options.languageName} kernel stdin write failed`, { error: String(err) });
            onWriteFailed?.(err);
        });
    }
    #startReader(stream) {
        const decoder = new TextDecoder();
        const loop = async () => {
            try {
                for await (const bytes of readLines(stream)) {
                    const line = decoder.decode(bytes);
                    if (!line.trim())
                        continue;
                    let frame;
                    try {
                        frame = JSON.parse(line);
                    }
                    catch (err) {
                        logger.warn(`${this.#options.languageName} runner emitted invalid JSON`, {
                            line: line.slice(0, 200),
                            error: err instanceof Error ? err.message : String(err),
                        });
                        continue;
                    }
                    if (this.#options.traceIpc) {
                        logger.debug(`${this.#options.languageName}Kernel recv`, { type: frame.type, id: frame.id });
                    }
                    await this.#handleFrame(frame);
                }
            }
            catch (err) {
                logger.warn(`${this.#options.languageName} kernel reader failed`, {
                    error: err instanceof Error ? err.message : String(err),
                });
            }
        };
        void loop();
    }
    #startStderrDrain(stream) {
        const reader = stream.getReader();
        const decoder = new TextDecoder();
        const loop = async () => {
            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done)
                        break;
                    const text = decoder.decode(value);
                    if (text.trim()) {
                        logger.warn(`${this.#options.languageName} runner stderr`, { text });
                    }
                }
            }
            catch {
                /* ignore */
            }
            finally {
                try {
                    reader.releaseLock();
                }
                catch {
                    /* ignore */
                }
            }
        };
        void loop();
    }
    async #handleFrame(frame) {
        const rid = frame.id;
        if (!rid)
            return;
        const control = this.#pendingControls.get(rid);
        if (control) {
            control.resolve(frame);
            return;
        }
        const pending = this.#pending.get(rid);
        if (!pending)
            return;
        switch (frame.type) {
            case "started":
                return;
            case "stdout":
            case "stderr": {
                const text = frame.data ?? "";
                if (text && pending.options?.onChunk) {
                    await pending.options.onChunk(text);
                }
                return;
            }
            case "display":
            case "result": {
                const bundle = frame.bundle ?? {};
                const { text, outputs } = await renderKernelDisplay(bundle);
                if (text && pending.options?.onChunk) {
                    await pending.options.onChunk(text);
                }
                if (outputs.length > 0 && pending.options?.onDisplay) {
                    for (const output of outputs) {
                        await pending.options.onDisplay(output);
                    }
                }
                return;
            }
            case "error": {
                const traceback = Array.isArray(frame.traceback) ? frame.traceback.map(String) : [];
                pending.status = "error";
                pending.error = {
                    name: String(frame.ename ?? "Error"),
                    value: String(frame.evalue ?? ""),
                    traceback,
                };
                const message = traceback.length > 0 ? `${traceback.join("\n")}\n` : `${pending.error.name}: ${pending.error.value}\n`;
                if (pending.options?.onChunk) {
                    await pending.options.onChunk(message);
                }
                return;
            }
            case "done": {
                if (typeof frame.executionCount === "number") {
                    pending.executionCount = frame.executionCount;
                }
                if (frame.status === "error" && pending.status === "ok") {
                    pending.status = "error";
                }
                if (frame.cancelled) {
                    pending.cancelled = true;
                }
                if (frame.admissionRejected) {
                    pending.admissionRejected = true;
                }
                pending.finalize?.();
                return;
            }
        }
    }
    async executeWithBudget(code, signal, timeoutMs, label) {
        const controller = new AbortController();
        const cleanups = [];
        if (signal) {
            if (signal.aborted) {
                controller.abort(signal.reason);
            }
            else {
                const onAbort = () => controller.abort(signal.reason);
                signal.addEventListener("abort", onAbort, { once: true });
                cleanups.push(() => signal.removeEventListener("abort", onAbort));
            }
        }
        const timer = timeoutMs > 0
            ? setTimeout(() => controller.abort(createAbortError("TimeoutError", `${label} timed out`)), timeoutMs)
            : undefined;
        if (timer)
            cleanups.push(() => clearTimeout(timer));
        try {
            throwIfAborted(controller.signal, label);
            const result = await this.execute(code, {
                signal: controller.signal,
                silent: true,
                storeHistory: false,
            });
            if (result.cancelled) {
                throw createAbortError(result.timedOut ? "TimeoutError" : "AbortError", `${label} cancelled`);
            }
            if (result.status === "error") {
                const reason = result.error?.value ?? `${this.#options.languageName} kernel init failed`;
                throw new Error(`${label} failed: ${reason}`);
            }
        }
        finally {
            for (const cleanup of cleanups)
                cleanup();
        }
    }
    #waitForExitWithTimeout(timeoutMs) {
        if (!this.#exitedPromise)
            return Promise.resolve(0);
        const exitedPromise = this.#exitedPromise;
        const timeout = new Promise(resolve => {
            const timer = setTimeout(() => resolve(null), Math.max(0, timeoutMs));
            timer.unref?.();
        });
        return Promise.race([exitedPromise.then(code => code), timeout]);
    }
}
