/**
 * Wire protocol between `TinyTitleClient` and a tiny-model worker.
 *
 * One worker per local model: the ONNX worker (`worker.ts`, the omp binary
 * re-entered with {@link TINY_WORKER_ARG}) or the MLX worker (`mlx-server.py`)
 * owns a Unix socket / named pipe named after the model, serves every omp
 * process on the machine over newline-delimited JSON, and exits on its own
 * once idle. Requests are message-level so both workers render the chat
 * template with their own tokenizer; the client owns prompt construction and
 * title extraction.
 */
/**
 * Hidden subcommand on the main CLI that boots the ONNX tiny-model worker.
 * Kept in sync with the dispatch in `cli.ts`.
 */
export const TINY_WORKER_ARG = "__rva_worker_tiny_inference";
/** Env var carrying the endpoint the ONNX worker must own. */
export const TINY_WORKER_SOCKET_ENV = "RVA_TINY_WORKER_SOCKET";
/** Env var naming the single local model the ONNX worker serves. */
export const TINY_WORKER_MODEL_ENV = "RVA_TINY_WORKER_MODEL";
/** Env var carrying the launch tag the worker echoes in `pong` so stale workers get replaced. */
export const TINY_WORKER_TAG_ENV = "RVA_TINY_WORKER_TAG";
/** Env var overriding the idle exit window (milliseconds); for tests. */
export const TINY_WORKER_IDLE_MS_ENV = "RVA_TINY_WORKER_IDLE_MS";
/** Idle window (nothing in flight, no request received) after which a worker exits to free model memory. */
export const TINY_WORKER_IDLE_MS = 15 * 60 * 1000;
/**
 * Shared-worker name of one (model, backend) worker under the tiny runtime dir:
 * its socket is `<name>.sock`, its log `<name>.log` (see `shared-worker.ts`).
 */
export function tinyWorkerName(modelKey, backend) {
    return `${modelKey}-${backend}`;
}
