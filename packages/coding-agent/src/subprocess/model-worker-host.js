import { logger } from "@rva/utils";
import { ModelDownloadActivity } from "../downloads/model-downloads";
import { tinyModelEnvKey } from "../tiny/title-client";
import { safeSend } from "../utils/ipc";
import { createUnavailableWorker, createWorkerHandle, logWorkerMessage, spawnWorkerOrUnavailable, } from "./worker-client";
/** Wrap a spawned subprocess as a ref-counted handle sending over `safeSend`. */
export function wrapRefCountedSubprocess(spawned, label) {
    const { proc } = spawned;
    return {
        ...createWorkerHandle(spawned, message => safeSend(proc, message, label)),
        ref() {
            try {
                proc.ref();
            }
            catch {
                // Already gone.
            }
        },
        unref() {
            try {
                proc.unref();
            }
            catch {
                // Already gone.
            }
        },
    };
}
/** Spawn a ref-counted worker, degrading to an inline unavailable stub when the subprocess cannot start. */
export function spawnRefCountedWorker(createSubprocess, label, warnMessage) {
    return spawnWorkerOrUnavailable(() => wrapRefCountedSubprocess(createSubprocess(), label), error => ({ ...createUnavailableWorker(error), ref() { }, unref() { } }), warnMessage);
}
function isDownloadRequest(request) {
    return request.kind === "download";
}
export class ModelWorkerHost {
    /** In-flight correlated requests by id; any entry keeps the worker referenced. */
    pending = new Map();
    #worker = null;
    #unsubscribe = [];
    #progressListeners = new Set();
    #downloads;
    #nextRequestId = 0;
    #refed = false;
    /** {@link tinyModelEnvKey} the current worker was spawned under. */
    #workerEnvKey;
    #options;
    constructor(options) {
        this.#options = options;
        this.#downloads = new ModelDownloadActivity(options.modelLabel);
    }
    nextId() {
        return String(++this.#nextRequestId);
    }
    onProgress(listener) {
        this.#progressListeners.add(listener);
        return () => this.#progressListeners.delete(listener);
    }
    emitProgress(event, error) {
        this.#downloads.observe(event, error);
        for (const listener of this.#progressListeners)
            listener(event);
    }
    ensureWorker() {
        const envKey = tinyModelEnvKey();
        if (this.#worker) {
            if (this.#workerEnvKey === envKey || this.pending.size > 0 || this.#options.hasStreams?.())
                return this.#worker;
            // Device/dtype changed while idle: retire the worker so the respawn uses the new env.
            void this.terminate();
        }
        const worker = this.#options.spawnWorker();
        this.#worker = worker;
        this.#workerEnvKey = envKey;
        this.#unsubscribe = [
            worker.onMessage(message => this.#handleMessage(message)),
            worker.onError(error => this.#handleWorkerError(error)),
        ];
        return worker;
    }
    /** Register a pending request and keep the worker referenced while work is in flight. */
    addPending(id, request) {
        this.pending.set(id, request);
        this.syncWorkerRef();
    }
    /** Drop a pending request and unref the worker once nothing is in flight. */
    deletePending(id) {
        if (this.pending.delete(id))
            this.syncWorkerRef();
    }
    /**
     * Workers start unreferenced so an idle warm model never blocks exit. A
     * short-lived command (`omp say`, STT setup/download) awaiting IPC would
     * otherwise let Bun drain the event loop and exit before the reply arrives,
     * so the worker is `ref`'d exactly while a request or stream is active.
     */
    syncWorkerRef() {
        const worker = this.#worker;
        if (!worker)
            return;
        const shouldRef = this.pending.size > 0 || (this.#options.hasStreams?.() ?? false);
        if (shouldRef === this.#refed)
            return;
        this.#refed = shouldRef;
        if (shouldRef)
            worker.ref();
        else
            worker.unref();
    }
    /**
     * Send one correlated request and await its settlement. The request stays
     * registered (keeping the worker referenced) until it settles; an abort
     * unregisters it and settles it through `onAbort`.
     */
    async request(signal, message, pending, onAbort) {
        const worker = this.ensureWorker();
        const id = this.nextId();
        const { promise, resolve, reject } = Promise.withResolvers();
        this.addPending(id, pending(resolve, reject));
        const abort = () => {
            if (!this.pending.has(id))
                return;
            this.deletePending(id);
            onAbort(resolve, reject);
        };
        signal?.addEventListener("abort", abort, { once: true });
        try {
            worker.send(message(id));
            return await promise;
        }
        finally {
            signal?.removeEventListener("abort", abort);
            this.deletePending(id);
        }
    }
    async downloadModel(modelKey, options = {}) {
        if (options.signal?.aborted)
            return { ok: false };
        const unsubscribe = options.onProgress ? this.onProgress(options.onProgress) : undefined;
        try {
            return await this.request(options.signal, 
            // Every model worker's Inbound union carries this `download` request; the generic cannot prove it.
            id => ({ type: "download", id, modelKey }), resolve => ({ kind: "download", modelKey, resolve }), resolve => resolve({ ok: false }));
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            logger.debug(`${this.#options.name}: local model download failed`, { modelKey, error: message });
            return { ok: false, error: message };
        }
        finally {
            unsubscribe?.();
        }
    }
    async terminate() {
        const worker = this.#worker;
        this.#worker = null;
        for (const unsubscribe of this.#unsubscribe)
            unsubscribe();
        this.#unsubscribe = [];
        this.#failAll(new Error(`${this.#options.name} worker terminated`), true);
        this.#refed = false;
        try {
            await worker?.terminate();
        }
        catch {
            // Already gone.
        }
    }
    #handleMessage(message) {
        if (message.type === "log") {
            // `log` is the only Outbound member with this discriminant; the generic cannot prove it.
            const log = message;
            logWorkerMessage(log);
            return;
        }
        if (message.type === "progress") {
            if (message.event)
                this.emitProgress(message.event);
            return;
        }
        if (message.type === "pong")
            return;
        if (message.type === "downloaded" && message.id !== undefined) {
            const request = this.pending.get(message.id);
            if (!request)
                return;
            this.deletePending(message.id);
            if (isDownloadRequest(request))
                request.resolve({ ok: true });
            return;
        }
        this.#options.handleMessage(message);
    }
    /** Emit an error progress event for and settle every pending request, then fail streams. */
    #failAll(error, terminated) {
        for (const request of this.pending.values()) {
            this.emitProgress({ modelKey: request.modelKey, status: "error" }, error.message);
            if (isDownloadRequest(request)) {
                request.resolve(terminated ? { ok: false } : { ok: false, error: error.message });
            }
            else {
                this.#options.failRequest(request, error, terminated);
            }
        }
        this.pending.clear();
        this.#options.failStreams?.(error);
    }
    #handleWorkerError(error) {
        logger.warn(`${this.#options.name}: worker error`, { error: error.message });
        this.#failAll(error, false);
        void this.terminate();
    }
}
