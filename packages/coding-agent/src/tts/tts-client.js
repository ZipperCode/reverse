import { logger } from "@rva/utils";
import { ModelWorkerHost, spawnRefCountedWorker, wrapRefCountedSubprocess, } from "../subprocess/model-worker-host";
import { createWorkerSubprocess, resolveWorkerSpawnCmd, SMOKE_TEST_TIMEOUT_MS, smokeTestWorker, } from "../subprocess/worker-client";
import { tinyWorkerEnv } from "../tiny/title-client";
import { getTtsLocalModelSpec, isTtsLocalModelKey } from "./models";
/**
 * Single-producer/single-consumer async queue bridging the worker's IPC
 * `audio-chunk` messages to an async iterator. Chunks pushed while no consumer
 * is awaiting are buffered in order; {@link close} ends the iterator and
 * {@link fail} surfaces an error to the awaiting (or next) consumer.
 */
class AudioChunkChannel {
    #queue = [];
    #waiters = [];
    #error = null;
    #settled = false;
    #onSettle;
    constructor(onSettle) {
        this.#onSettle = onSettle;
    }
    push(chunk) {
        if (this.#settled)
            return;
        const waiter = this.#waiters.shift();
        if (waiter)
            waiter.resolve({ value: chunk, done: false });
        else
            this.#queue.push(chunk);
    }
    close() {
        this.#settle(null);
    }
    fail(error) {
        this.#settle(error);
    }
    #settle(error) {
        if (this.#settled)
            return;
        this.#settled = true;
        this.#error = error;
        for (const waiter of this.#waiters) {
            if (error)
                waiter.reject(error);
            else
                waiter.resolve({ value: undefined, done: true });
        }
        this.#waiters = [];
        this.#onSettle?.();
    }
    async *iterator() {
        while (true) {
            const buffered = this.#queue.shift();
            if (buffered) {
                yield buffered;
                continue;
            }
            if (this.#error)
                throw this.#error;
            if (this.#settled)
                return;
            const { promise, resolve, reject } = Promise.withResolvers();
            this.#waiters.push({ resolve, reject });
            const result = await promise;
            if (result.done)
                return;
            yield result.value;
        }
    }
}
/**
 * Hidden subcommand on the main CLI that boots the TTS worker in the spawned
 * subprocess. Kept in sync with the dispatch in `cli.ts` (Main-owned).
 */
export const TTS_WORKER_ARG = "__rva_worker_tts";
/**
 * Spawn the TTS worker as a subprocess. Exported for tests and the smoke probe;
 * production callers go through {@link spawnTtsWorker}.
 */
export function createTtsSubprocess() {
    return createWorkerSubprocess({
        spawnCommand: resolveWorkerSpawnCmd(TTS_WORKER_ARG),
        env: tinyWorkerEnv(),
        exitLabel: "tts subprocess",
    });
}
function spawnTtsWorker() {
    return spawnRefCountedWorker(createTtsSubprocess, "tts", "TTS worker spawn failed; local TTS disabled");
}
export class TtsClient {
    #host;
    constructor(spawnWorker = spawnTtsWorker) {
        this.#host = new ModelWorkerHost({
            name: "tts",
            spawnWorker,
            modelLabel: modelKey => getTtsLocalModelSpec(modelKey)?.label ?? modelKey,
            handleMessage: message => this.#handleMessage(message),
            failRequest: (request, error, terminated) => {
                if (request.kind === "synthesize")
                    request.resolve(null);
                else if (terminated)
                    request.channel.close();
                else
                    request.channel.fail(error);
            },
        });
    }
    onProgress(listener) {
        return this.#host.onProgress(listener);
    }
    async synthesize(modelKey, text, options = {}) {
        if (!isTtsLocalModelKey(modelKey))
            return null;
        if (options.signal?.aborted)
            return null;
        try {
            return await this.#host.request(options.signal, (id) => ({
                type: "synthesize",
                id,
                modelKey,
                text,
                ...(options.voice ? { voice: options.voice } : {}),
                ...(options.speed !== undefined ? { speed: options.speed } : {}),
            }), resolve => ({ kind: "synthesize", modelKey, resolve }), resolve => resolve(null));
        }
        catch (error) {
            logger.debug("tts: local synthesis failed", {
                modelKey,
                error: error instanceof Error ? error.message : String(error),
            });
            return null;
        }
    }
    /**
     * Open a streaming-synthesis session. Complete speakable segments are fed
     * through the returned handle's `push`/`end`; audio is emitted one segment
     * at a time via `chunks`, so playback can begin before the full text is
     * known. Returns an inert handle (immediately-ended `chunks`) for unknown
     * models or an already-aborted signal, and fails the iterator if the worker
     * cannot spawn.
     */
    synthesizeStream(modelKey, options = {}) {
        if (!isTtsLocalModelKey(modelKey) || options.signal?.aborted) {
            const channel = new AudioChunkChannel();
            channel.close();
            return { push: () => { }, end: () => { }, chunks: channel.iterator() };
        }
        let worker;
        try {
            worker = this.#host.ensureWorker();
        }
        catch (error) {
            logger.debug("tts: stream synthesis failed to start", {
                modelKey,
                error: error instanceof Error ? error.message : String(error),
            });
            const channel = new AudioChunkChannel();
            channel.fail(error instanceof Error ? error : new Error(String(error)));
            return { push: () => { }, end: () => { }, chunks: channel.iterator() };
        }
        const id = this.#host.nextId();
        const signal = options.signal;
        let closed = false;
        let ended = false;
        const abort = () => {
            if (closed)
                return;
            closed = true;
            ended = true;
            if (!this.#host.pending.has(id))
                return;
            this.#host.deletePending(id);
            worker.send({ type: "stream-cancel", id });
            channel.close();
        };
        const channel = new AudioChunkChannel(() => signal?.removeEventListener("abort", abort));
        this.#host.addPending(id, { kind: "stream", modelKey, channel });
        signal?.addEventListener("abort", abort, { once: true });
        const start = {
            type: "stream-start",
            id,
            modelKey,
            ...(options.voice ? { voice: options.voice } : {}),
            ...(options.speed !== undefined ? { speed: options.speed } : {}),
        };
        worker.send(start);
        return {
            push: (text) => {
                if (!closed && !ended)
                    worker.send({ type: "stream-push", id, text });
            },
            end: () => {
                if (closed || ended)
                    return;
                ended = true;
                worker.send({ type: "stream-end", id });
            },
            chunks: channel.iterator(),
        };
    }
    async downloadModel(modelKey, options = {}) {
        if (!isTtsLocalModelKey(modelKey))
            return false;
        return (await this.#host.downloadModel(modelKey, options)).ok;
    }
    terminate() {
        return this.#host.terminate();
    }
    #handleMessage(message) {
        const pending = this.#host.pending.get(message.id);
        if (!pending)
            return;
        // Streaming chunks are non-terminal: keep the session registered until
        // `stream-done` (or an error) so later chunks still route to its channel.
        if (message.type === "audio-chunk") {
            if (pending.kind === "stream") {
                pending.channel.push({
                    index: message.index,
                    text: message.text,
                    pcm: message.pcm,
                    sampleRate: message.sampleRate,
                });
            }
            return;
        }
        this.#host.deletePending(message.id);
        if (message.type === "stream-done") {
            if (pending.kind === "stream")
                pending.channel.close();
            return;
        }
        if (message.type === "audio") {
            if (pending.kind === "synthesize")
                pending.resolve({ pcm: message.pcm, sampleRate: message.sampleRate });
            return;
        }
        logger.debug("tts: worker returned error", { error: message.error });
        this.#host.emitProgress({ modelKey: pending.modelKey, status: "error" }, message.error);
        if (pending.kind === "synthesize")
            pending.resolve(null);
        else if (pending.kind === "download")
            pending.resolve({ ok: false, error: message.error });
        else
            pending.channel.fail(new Error(message.error));
        void this.terminate();
    }
}
export const ttsClient = new TtsClient();
export async function shutdownTtsClient() {
    await ttsClient.terminate();
}
export async function smokeTestTtsWorker({ timeoutMs = SMOKE_TEST_TIMEOUT_MS, } = {}) {
    await smokeTestWorker(wrapRefCountedSubprocess(createTtsSubprocess(), "tts"), "tts worker", timeoutMs);
}
