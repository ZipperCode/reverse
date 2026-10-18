/**
 * Client for the per-model tiny-model workers.
 *
 * Each local model is served by one worker process on the machine — the ONNX
 * worker (`worker.ts`) or, with `PI_TINY_DEVICE=mlx`, the MLX worker
 * (`mlx-server.py`) — that owns a socket named after the model. This client
 * connects to it, spawning it detached when it is not running, and lets it
 * die on its own once idle. Prompt construction and title extraction live
 * here so both workers only ever see message-level `chat` requests.
 */
import { $env, getTinyWorkerRuntimeDir, logger, prompt } from "@rva/utils";
import packageJson from "../../package.json" with { type: "json" };
import { isSettingsInitialized, settings } from "../config/settings";
import { stageRunnerScript } from "../eval/runner-cache";
import { ModelDownloadActivity } from "../downloads/model-downloads";
import titleSystemPrompt from "../prompts/system/title-system.md" with { type: "text" };
import { connectSharedWorker, LazyWorkerHandle, smokeTestSharedWorker, spawnDetached, WORKER_CONNECTION_CLOSED, } from "../subprocess/shared-worker";
import { inferenceWorkerEnv, resolveWorkerSpawnCmd, SMOKE_TEST_TIMEOUT_MS, } from "../subprocess/worker-client";
import { MLX_DEVICE, resolveTinyModelDevicePreference, tinyMlxSupported, tinyModelDeviceSettingToEnv } from "./device";
import { tinyModelDtypeSettingToEnv } from "./dtype";
import { formatTitleUserMessage } from "./message-preproc";
import { ensureTinyMlxRuntime, getTinyMlxModelDir, MLX_LM_VERSION } from "./mlx-runtime";
import MLX_SERVER_SCRIPT from "./mlx-server.py" with { type: "text" };
import { getTinyLocalModelSpec, isTinyLocalModelKey } from "./models";
import { normalizeGeneratedTitle } from "./text";
import { TINY_WORKER_ARG, TINY_WORKER_IDLE_MS_ENV, TINY_WORKER_MODEL_ENV, TINY_WORKER_SOCKET_ENV, TINY_WORKER_TAG_ENV, tinyWorkerName, } from "./title-protocol";
import { cfgProvidersTinyModelDevice, cfgProvidersTinyModelDtype } from "../session/settings";
const TITLE_PREFILL = "<title>";
const TITLE_CLOSE = "</title>";
const TITLE_MAX_NEW_TOKENS = 20;
const COMPLETION_DEFAULT_MAX_NEW_TOKENS = 256;
const COMPLETION_MAX_NEW_TOKENS = 1024;
const TINY_TITLE_SYSTEM_PROMPT = prompt.render(titleSystemPrompt);
const MLX_IDLE_SECONDS = 15 * 60;
function normalizeTinyTitleGenerateOptions(options) {
    if (!options)
        return {};
    if ("aborted" in options && "addEventListener" in options)
        return { signal: options };
    return options;
}
// ── Device / dtype resolution ────────────────────────────────────────
/** Setting value (its env var included); only the env var when settings are uninitialized (e.g. `omp --smoke-test`). */
function readTinyModelSetting(setting) {
    return isSettingsInitialized() ? setting.get(settings) : setting.envValue();
}
/**
 * Map the resolved `providers.tinyModelDevice` / `providers.tinyModelDtype`
 * values onto the `PI_TINY_DEVICE` / `PI_TINY_DTYPE` vars a worker should run
 * with. Only resolved keys are returned — never the default sentinel — so the
 * worker's built-in defaults apply for anything absent. Pure for testability;
 * see {@link tinyModelEnv} for the settings glue.
 * @internal
 */
export function tinyWorkerEnvOverlay(deviceSetting, dtypeSetting) {
    const overlay = {};
    const device = tinyModelDeviceSettingToEnv(deviceSetting);
    if (device)
        overlay.PI_TINY_DEVICE = device;
    const dtype = tinyModelDtypeSettingToEnv(dtypeSetting);
    if (dtype)
        overlay.PI_TINY_DTYPE = dtype;
    return overlay;
}
/** Resolved device/dtype vars for this process. */
function tinyModelEnv() {
    return tinyWorkerEnvOverlay(readTinyModelSetting(cfgProvidersTinyModelDevice), readTinyModelSetting(cfgProvidersTinyModelDtype));
}
/** Identity of the resolved device/dtype; a worker started under a different key is stale. */
export function tinyModelEnvKey() {
    const env = tinyModelEnv();
    return `${env.PI_TINY_DEVICE ?? ""}|${env.PI_TINY_DTYPE ?? ""}`;
}
/**
 * Env for an ONNX inference subprocess with the resolved device/dtype —
 * used for the tiny worker and reused verbatim by the STT and TTS workers,
 * which share the same device/dtype resolution.
 */
export function tinyWorkerEnv() {
    return inferenceWorkerEnv(tinyModelEnv());
}
/** Set once the mlx-lm bootstrap fails in this process; later workers fall back to ONNX. */
let mlxUnavailable = false;
/** Whether a worker started now would run the MLX backend (device resolves to `mlx` on Apple silicon). */
export function tinyWorkerUsesMlx() {
    return (!mlxUnavailable &&
        tinyMlxSupported() &&
        resolveTinyModelDevicePreference(tinyModelEnv().PI_TINY_DEVICE).device === MLX_DEVICE);
}
/** How to start the ONNX worker for `modelKey` with the resolved device/dtype env. @internal */
export function onnxLaunch(modelKey, modelEnv) {
    const tag = `${packageJson.version}|onnx|${modelEnv.PI_TINY_DEVICE ?? ""}|${modelEnv.PI_TINY_DTYPE ?? ""}`;
    return {
        label: `tiny onnx worker for ${modelKey}`,
        backend: "onnx",
        tag,
        spawn(endpoint, logPath) {
            const command = resolveWorkerSpawnCmd(TINY_WORKER_ARG);
            const env = inferenceWorkerEnv({
                ...modelEnv,
                [TINY_WORKER_SOCKET_ENV]: endpoint,
                [TINY_WORKER_MODEL_ENV]: modelKey,
                [TINY_WORKER_TAG_ENV]: tag,
            });
            return Promise.resolve(spawnDetached(command.cmd, command.cwd, env, logPath));
        },
    };
}
function mlxLaunch(modelKey, emitProgress) {
    const spec = getTinyLocalModelSpec(modelKey);
    if (!spec)
        throw new Error(`Unknown tiny local model: ${modelKey}`);
    const tag = `mlx|${MLX_LM_VERSION}|${Bun.hash.crc32(MLX_SERVER_SCRIPT).toString(16)}`;
    return {
        label: `tiny mlx worker for ${modelKey}`,
        backend: "mlx",
        tag,
        async spawn(endpoint, logPath) {
            const python = await ensureTinyMlxRuntime(phase => emitProgress({ modelKey, status: phase, name: `mlx-lm@${MLX_LM_VERSION}` }));
            const script = await stageRunnerScript("omp-tiny-mlx", "py", MLX_SERVER_SCRIPT);
            const env = inferenceWorkerEnv({
                PYTHONUNBUFFERED: "1",
                PYTHONIOENCODING: "utf-8",
                TRANSFORMERS_VERBOSITY: "error",
                HF_HUB_DISABLE_PROGRESS_BARS: "1",
                TOKENIZERS_PARALLELISM: "false",
            });
            const idleSeconds = Number($env[TINY_WORKER_IDLE_MS_ENV]) / 1000 || MLX_IDLE_SECONDS;
            const cmd = [
                python,
                "-u",
                script,
                "--socket",
                endpoint,
                "--tag",
                tag,
                "--model-key",
                modelKey,
                "--repo",
                spec.mlxRepo,
                "--dir",
                getTinyMlxModelDir(spec.mlxRepo),
                "--idle-seconds",
                String(idleSeconds),
            ];
            return spawnDetached(cmd, undefined, env, logPath);
        },
    };
}
/** Connect to the machine-shared worker serving `modelKey` on `launch.backend`, spawning or replacing it as needed. */
export function connectTinyWorker(launch, modelKey, runtimeDir = getTinyWorkerRuntimeDir()) {
    return connectSharedWorker(launch, runtimeDir, tinyWorkerName(modelKey, launch.backend));
}
// ── Prompt construction / output parsing ─────────────────────────────
function buildTitleMessages(message, systemPrompt) {
    return [
        { role: "system", content: systemPrompt?.trim() || TINY_TITLE_SYSTEM_PROMPT },
        { role: "user", content: formatTitleUserMessage(message) },
    ];
}
function buildCompletionMessages(promptText, systemPrompt) {
    const userMessage = { role: "user", content: promptText };
    const system = systemPrompt?.trim();
    return system ? [{ role: "system", content: system }, userMessage] : [userMessage];
}
function extractTinyTitle(text, sourceText) {
    const titleStart = text.lastIndexOf(TITLE_PREFILL);
    const withoutPrefix = titleStart >= 0 ? text.slice(titleStart + TITLE_PREFILL.length) : text;
    // Self-closing tag: <title/> or <title /> (only when the prefill is present).
    if (titleStart >= 0 && /^\s*\/>/.test(withoutPrefix))
        return null;
    const closeIndex = withoutPrefix.indexOf(TITLE_CLOSE);
    const withoutClose = closeIndex >= 0 ? withoutPrefix.slice(0, closeIndex) : withoutPrefix;
    const tagIndex = withoutClose.indexOf("<");
    const withoutTag = tagIndex >= 0 ? withoutClose.slice(0, tagIndex) : withoutClose;
    return normalizeGeneratedTitle(withoutTag, sourceText);
}
/**
 * Per-model worker connections. Device/dtype settings are read at use time: a
 * connection made under a different device/dtype is replaced on its next idle
 * use, and the launch-tag probe then swaps the machine-wide worker.
 */
export class TinyTitleClient {
    #workers = new Map();
    #pending = new Map();
    /** Models whose load/generation failed, keyed to the device/dtype they failed under. */
    #failedModels = new Map();
    #progressListeners = new Set();
    #downloads = new ModelDownloadActivity(modelKey => getTinyLocalModelSpec(modelKey)?.label ?? modelKey);
    #nextRequestId = 0;
    #connect;
    constructor(connect) {
        this.#connect = connect ?? (modelKey => this.#connectDefault(modelKey));
    }
    async #connectDefault(modelKey) {
        if (tinyWorkerUsesMlx()) {
            try {
                return await connectTinyWorker(mlxLaunch(modelKey, event => this.#emitProgress(event)), modelKey);
            }
            catch (error) {
                mlxUnavailable = true;
                const message = error instanceof Error ? error.message : String(error);
                logger.warn("tiny-title: MLX worker unavailable; falling back to ONNX CPU", { modelKey, error: message });
                // Ends a visible `mlx-lm` install row; the ONNX fallback tracks its own load.
                this.#downloads.observe({ modelKey, status: "error" }, `MLX unavailable: ${message}`);
            }
        }
        return connectTinyWorker(onnxLaunch(modelKey, tinyModelEnv()), modelKey);
    }
    onProgress(listener) {
        this.#progressListeners.add(listener);
        return () => this.#progressListeners.delete(listener);
    }
    /**
     * Reach the model's worker ahead of first use without loading anything, so
     * the first {@link generate} finds a live connection instead of paying the
     * probe/spawn latency on the submit hot path (issue #6462). No-ops for
     * online / non-local keys and for models already marked failed.
     */
    prewarm(modelKey) {
        if (!isTinyLocalModelKey(modelKey) || this.#hasFailed(modelKey))
            return;
        try {
            this.#ensureWorker(modelKey).handle.send({ type: "ping", id: String(++this.#nextRequestId) });
        }
        catch (error) {
            logger.debug("tiny-title: prewarm failed", {
                modelKey,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    async generate(modelKey, message, optionsOrSignal) {
        const options = normalizeTinyTitleGenerateOptions(optionsOrSignal);
        if (!isTinyLocalModelKey(modelKey))
            return null;
        if (options.signal?.aborted || this.#hasFailed(modelKey))
            return null;
        const { promise, resolve } = Promise.withResolvers();
        const request = {
            type: "chat",
            id: String(++this.#nextRequestId),
            messages: buildTitleMessages(message, options.systemPrompt),
            prefill: TITLE_PREFILL,
            stop: TITLE_CLOSE,
            maxNewTokens: TITLE_MAX_NEW_TOKENS,
        };
        return this.#run(request, { kind: "title", modelKey, source: message, resolve }, promise, options.signal, () => resolve(null));
    }
    async chat(modelKey, messages, options = {}) {
        if (!isTinyLocalModelKey(modelKey))
            return null;
        if (options.signal?.aborted || this.#hasFailed(modelKey))
            return null;
        const requested = options.maxTokens ?? COMPLETION_DEFAULT_MAX_NEW_TOKENS;
        const { promise, resolve } = Promise.withResolvers();
        const request = {
            type: "chat",
            id: String(++this.#nextRequestId),
            messages,
            maxNewTokens: Math.min(Math.max(1, requested), COMPLETION_MAX_NEW_TOKENS),
        };
        return this.#run(request, { kind: "chat", modelKey, resolve }, promise, options.signal, () => resolve(null));
    }
    async complete(modelKey, promptText, options = {}) {
        return this.chat(modelKey, buildCompletionMessages(promptText, options.systemPrompt), options);
    }
    async downloadModel(modelKey, options = {}) {
        if (!isTinyLocalModelKey(modelKey))
            return { ok: false };
        if (options.signal?.aborted)
            return { ok: false };
        const unsubscribe = options.onProgress ? this.onProgress(options.onProgress) : undefined;
        try {
            const { promise, resolve } = Promise.withResolvers();
            const request = { type: "load", id: String(++this.#nextRequestId) };
            return await this.#run(request, { kind: "load", modelKey, resolve }, promise, options.signal, () => resolve({ ok: false }));
        }
        finally {
            unsubscribe?.();
        }
    }
    /**
     * Register `pending`, send `request` to the model's worker, and hand back
     * `promise` (settled by the correlated reply, a worker error, `onAbort`, or
     * a send failure) with the bookkeeping detached once it settles.
     */
    #run(request, pending, promise, signal, onAbort) {
        const abort = () => {
            if (!this.#pending.delete(request.id))
                return;
            this.#syncWorkerRef(pending.modelKey);
            onAbort();
        };
        try {
            const worker = this.#ensureWorker(pending.modelKey);
            this.#pending.set(request.id, pending);
            this.#syncWorkerRef(pending.modelKey);
            signal?.addEventListener("abort", abort, { once: true });
            worker.handle.send(request);
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            logger.debug("tiny-title: local request failed", {
                modelKey: pending.modelKey,
                kind: pending.kind,
                error: message,
            });
            this.#pending.delete(request.id);
            this.#fail(pending, message);
        }
        return promise.finally(() => {
            signal?.removeEventListener("abort", abort);
            if (this.#pending.delete(request.id))
                this.#syncWorkerRef(pending.modelKey);
        });
    }
    async terminate() {
        const workers = [...this.#workers.values()];
        this.#workers.clear();
        for (const pending of this.#pending.values())
            this.#fail(pending, undefined);
        this.#pending.clear();
        for (const worker of workers) {
            worker.unsubscribe();
            try {
                await worker.handle.terminate();
            }
            catch {
                // Already gone.
            }
        }
    }
    #ensureWorker(modelKey) {
        const envKey = tinyModelEnvKey();
        const existing = this.#workers.get(modelKey);
        if (existing) {
            // Device/dtype changed since connecting: reconnect once idle so in-flight
            // requests finish on the old worker.
            if (existing.envKey === envKey || this.#hasPending(modelKey))
                return existing;
            this.#workers.delete(modelKey);
            existing.unsubscribe();
            void existing.handle.terminate();
        }
        const handle = new LazyWorkerHandle(() => this.#connect(modelKey));
        const unsubscribeMessage = handle.onMessage(message => this.#handleMessage(modelKey, message));
        const unsubscribeError = handle.onError(error => this.#handleWorkerError(modelKey, error));
        const worker = {
            handle,
            refed: false,
            envKey,
            unsubscribe: () => {
                unsubscribeMessage();
                unsubscribeError();
            },
        };
        this.#workers.set(modelKey, worker);
        return worker;
    }
    /**
     * Keep the socket referenced only while a request for that model is in
     * flight, so idle TUI sessions can exit while short-lived CLI downloads
     * are not starved by Bun draining the event loop first.
     */
    #syncWorkerRef(modelKey) {
        const worker = this.#workers.get(modelKey);
        if (!worker)
            return;
        const inFlight = this.#hasPending(modelKey);
        if (inFlight === worker.refed)
            return;
        worker.refed = inFlight;
        if (inFlight)
            worker.handle.ref();
        else
            worker.handle.unref();
    }
    #handleMessage(modelKey, message) {
        if (message.type === "pong")
            return;
        if (message.type === "progress") {
            this.#emitProgress(message.event);
            return;
        }
        // Any answer settles the model's load, even for an abandoned request;
        // MLX `chat` loads send no `ready` of their own.
        if (message.type === "error")
            this.#downloads.observe({ modelKey, status: "error" }, message.error);
        else
            this.#downloads.observe({ modelKey, status: "ready" });
        const pending = this.#pending.get(message.id);
        if (!pending)
            return;
        this.#pending.delete(message.id);
        this.#syncWorkerRef(modelKey);
        if (message.type === "error") {
            logger.debug("tiny-title: worker returned error", { modelKey, error: message.error });
            this.#markFailedModel(pending);
            this.#fail(pending, message.error);
            // One worker serves one model: a failed load/generation leaves nothing
            // worth staying connected to. Sibling requests for the model fault too.
            this.#dropWorker(modelKey, message.error);
            return;
        }
        if (message.type === "text") {
            if (pending.kind === "title")
                pending.resolve(extractTinyTitle(message.text, pending.source));
            else if (pending.kind === "chat")
                pending.resolve(message.text.trim() || null);
            return;
        }
        if (pending.kind === "load")
            pending.resolve({ ok: true });
    }
    #hasPending(modelKey) {
        for (const pending of this.#pending.values()) {
            if (pending.modelKey === modelKey)
                return true;
        }
        return false;
    }
    #hasFailed(modelKey) {
        return this.#failedModels.get(modelKey) === tinyModelEnvKey();
    }
    #fail(pending, error) {
        this.#emitProgress({ modelKey: pending.modelKey, status: "error" }, error);
        if (pending.kind === "load")
            pending.resolve(error === undefined ? { ok: false } : { ok: false, error });
        else
            pending.resolve(null);
    }
    #markFailedModel(pending) {
        if (pending.kind !== "load")
            this.#failedModels.set(pending.modelKey, tinyModelEnvKey());
    }
    #emitProgress(event, error) {
        this.#downloads.observe(event, error);
        for (const listener of this.#progressListeners)
            listener(event);
    }
    /** Forget the model's connection and fail every request still in flight for it. Returns how many failed. */
    #dropWorker(modelKey, error) {
        const worker = this.#workers.get(modelKey);
        if (worker) {
            this.#workers.delete(modelKey);
            worker.unsubscribe();
            void worker.handle.terminate();
        }
        this.#downloads.observe({ modelKey, status: "error" }, error);
        let failed = 0;
        for (const [id, pending] of this.#pending) {
            if (pending.modelKey !== modelKey)
                continue;
            this.#pending.delete(id);
            this.#fail(pending, error);
            failed += 1;
        }
        return failed;
    }
    /** The model's worker went away or could not be reached. */
    #handleWorkerError(modelKey, error) {
        const failed = this.#dropWorker(modelKey, error.message);
        // A worker exiting on its own while idle is routine; losing requests is not.
        if (failed === 0 && error.message.startsWith(WORKER_CONNECTION_CLOSED)) {
            logger.debug("tiny-title: worker went away while idle", { modelKey });
        }
        else {
            logger.warn("tiny-title: worker error", { modelKey, error: error.message, failedRequests: failed });
        }
    }
}
export const tinyTitleClient = new TinyTitleClient();
/** Alias for the shared tiny-model worker client (titles + generic chat completions). */
export const tinyModelClient = tinyTitleClient;
/** Drop this process's worker connections; the workers themselves keep serving others until idle. */
export async function shutdownTinyTitleClient() {
    await tinyTitleClient.terminate();
}
/** Exercise ONNX worker startup and the tagged ping handshake for distribution smoke tests. */
export async function smokeTestTinyTitleWorker({ timeoutMs = SMOKE_TEST_TIMEOUT_MS, } = {}) {
    const modelKey = "lfm2.5-230m";
    await smokeTestSharedWorker(onnxLaunch(modelKey, {}), getTinyWorkerRuntimeDir(), tinyWorkerName(modelKey, "onnx"), timeoutMs);
}
