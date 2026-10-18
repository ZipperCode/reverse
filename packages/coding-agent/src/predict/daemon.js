/**
 * Server half of the machine-global text-prediction daemon (worker selector
 * `__omp_worker_text_predict`, started through the `text-predict` global broker).
 *
 * Lazily opens one `TextPredictor` per requested engine, keeps each learning
 * engine current with `history.db` (rows past a persisted row-id cursor, on
 * open and on every `sync`), persists on a 5-minute debounce and on exit, and exits
 * after an idle window. A learning engine that starts from empty state first
 * learns the Claude Code and Codex prompt histories (`foreign-history.ts`).
 * `smollm` requests are answered by SmolLM and ngram together (`blend.ts`).
 * Engine state that fails to load is wiped and rebuilt the same way.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { TextPredictor } from "@rva/natives";
import { getHistoryDbPath, getPredictStateDir, isEnoent, logger, VERSION } from "@rva/utils";
import { JsonLineServer } from "../subprocess/jsonl-server";
import { openSqliteReadConnection } from "../tools/sqlite-reader";
import { blendPredictions } from "./blend";
import { readForeignPrompts } from "./foreign-history";
import { TEXT_PREDICT_AGENT_DIR_ENV, TEXT_PREDICT_SOCKET_ENV, textPredictReadyBanner, } from "./protocol";
import { getSmolLmModelDir, smolLmWeightsReady } from "./smollm-weights";
/** Exit after this long without a request; clients restart the daemon on demand. */
const IDLE_EXIT_MS = 15 * 60000;
/**
 * Persist learned state once changes have been quiet this long. Each persist
 * rewrites the whole engine snapshot (~1 MB for ngram) plus `cursor.json`, so
 * typing must not trigger one every few seconds. Durability trade-off: a crash
 * loses only accept/reject feedback since the last persist; prompts are
 * re-learned on the next open by ingesting `history.db` rows past the persisted
 * cursor. Idle exit and shutdown still persist (`onStop`).
 */
const PERSIST_DEBOUNCE_MS = 5 * 60000;
/** Persist at the latest this long after the first unpersisted change, even while changes keep arriving. */
const PERSIST_MAX_DIRTY_MS = 15 * 60000;
/** History rows per `observe` batch during ingestion. */
const INGEST_BATCH = 1000;
/** After an engine fails to open, requests for it fail fast for this long before a retry. */
const OPEN_RETRY_MS = 60000;
/** While SmolLM weights are missing (composer still fetching), recheck the marker at most this often. */
const WEIGHTS_RECHECK_MS = 5000;
const CURSOR_FILE = "cursor.json";
/** Persisted history cursor, or `undefined` when the engine has no persisted state yet. */
async function readCursor(stateDir) {
    try {
        const raw = await Bun.file(path.join(stateDir, CURSOR_FILE)).json();
        if (typeof raw === "object" && raw !== null && "historyId" in raw && typeof raw.historyId === "number") {
            return raw.historyId;
        }
        return 0;
    }
    catch (error) {
        if (isEnoent(error))
            return undefined;
        logger.warn("text-predict: unreadable history cursor; re-ingesting", { stateDir, error: String(error) });
        return 0;
    }
}
/** SmolLM was requested before its weights exist; not a load failure, so no retry backoff. */
class SmolLmWeightsMissingError extends Error {
    constructor() {
        super("SmolLM weights are not downloaded yet (the editor fetches them on first use, or run `omp tiny-models download smollm`)");
    }
}
/**
 * Trailing debounce capped by a maximum dirty age: each change pushes the
 * flush to `debounceMs` after it, but never past `maxDirtyMs` after the first
 * unflushed change. Consecutive flushes are therefore at least `debounceMs`
 * apart, and a steady stream of changes still flushes every `maxDirtyMs`.
 */
export class PersistCadence {
    #debounceMs;
    #maxDirtyMs;
    #flush;
    #timer;
    #dirtySince;
    constructor(debounceMs, maxDirtyMs, flush) {
        this.#debounceMs = debounceMs;
        this.#maxDirtyMs = maxDirtyMs;
        this.#flush = flush;
    }
    /** Record a change and (re)arm the flush. */
    touch() {
        const now = Date.now();
        this.#dirtySince ??= now;
        const delay = Math.max(0, Math.min(this.#debounceMs, this.#dirtySince + this.#maxDirtyMs - now));
        clearTimeout(this.#timer);
        this.#timer = setTimeout(() => {
            this.#timer = undefined;
            this.#dirtySince = undefined;
            this.#flush();
        }, delay);
    }
    /** Drop a pending flush (the caller persists on stop instead). */
    cancel() {
        clearTimeout(this.#timer);
        this.#timer = undefined;
        this.#dirtySince = undefined;
    }
}
/** One open engine plus the history position its persisted state covers. */
class Engine {
    method;
    stateDir;
    predictor;
    /** Highest `history.id` fed to `observe`. */
    cursor;
    /** Foreign prompt histories still owed to empty state (see {@link readForeignPrompts}). */
    #seed;
    /** Cursor value covered by the last successful persist. */
    #persistedCursor;
    #dirty = false;
    #ingesting = Promise.resolve(0);
    constructor(method, stateDir, predictor, cursor) {
        this.method = method;
        this.stateDir = stateDir;
        this.predictor = predictor;
        this.cursor = cursor ?? 0;
        this.#persistedCursor = this.cursor;
        this.#seed = cursor === undefined;
    }
    get dirty() {
        return this.#dirty || this.cursor !== this.#persistedCursor;
    }
    markDirty() {
        this.#dirty = true;
    }
    /**
     * Feed history rows past the cursor through `observe`, one ingestion at a
     * time; empty state first learns the foreign prompt histories.
     */
    ingest(historyDbPath) {
        // `apple` only wraps the system dictionary; it learns nothing.
        if (this.method === "apple")
            return Promise.resolve(0);
        const run = () => this.#ingestNow(historyDbPath);
        this.#ingesting = this.#ingesting.then(run, run);
        return this.#ingesting;
    }
    async persist() {
        if (!this.dirty)
            return;
        const cursor = this.cursor;
        this.#dirty = false;
        try {
            await this.predictor.persist();
            await Bun.write(path.join(this.stateDir, CURSOR_FILE), JSON.stringify({ historyId: cursor }));
            this.#persistedCursor = cursor;
        }
        catch (error) {
            this.#dirty = true;
            throw error;
        }
    }
    async #ingestNow(historyDbPath) {
        let ingested = 0;
        if (this.#seed) {
            const prompts = await readForeignPrompts();
            for (let at = 0; at < prompts.length; at += INGEST_BATCH) {
                await this.predictor.observe(prompts.slice(at, at + INGEST_BATCH));
            }
            this.#seed = false;
            if (prompts.length > 0)
                this.markDirty();
            ingested += prompts.length;
        }
        let db;
        try {
            db = await openSqliteReadConnection(historyDbPath);
        }
        catch (error) {
            // No history yet (fresh install) is not an error.
            if (!isEnoent(error))
                logger.debug("text-predict: history unavailable", { error: String(error) });
            return ingested;
        }
        try {
            const page = db.query("SELECT id, prompt FROM history WHERE id > ? ORDER BY id LIMIT ?");
            for (;;) {
                const rows = page.all(this.cursor, INGEST_BATCH);
                if (rows.length === 0)
                    break;
                await this.predictor.observe(rows.map(row => row.prompt));
                this.cursor = rows.at(-1)?.id ?? this.cursor;
                ingested += rows.length;
                if (rows.length < INGEST_BATCH)
                    break;
            }
        }
        finally {
            db.close();
        }
        return ingested;
    }
}
/** Serves every connection; engines open lazily on their first request. */
class TextPredictDaemon {
    #agentDir;
    #historyDbPath;
    #engines = new Map();
    #failedAt = new Map();
    /** Engines whose weights were missing, keyed to when that was observed. */
    #missingAt = new Map();
    #persistCadence = new PersistCadence(PERSIST_DEBOUNCE_MS, PERSIST_MAX_DIRTY_MS, () => void this.#persistAll());
    #server = new JsonLineServer({
        name: "text-predict",
        cleanupLabel: "text-predict-daemon",
        idleMs: IDLE_EXIT_MS,
        banner: textPredictReadyBanner,
        onRequest: (request, reply) => void this.#server.busy(() => this.#dispatch(request)).then(response => reply.send(response)),
        beforeStop: () => this.#persistCadence.cancel(),
        onStop: () => this.#persistAll(),
    });
    constructor(agentDir) {
        this.#agentDir = agentDir;
        this.#historyDbPath = getHistoryDbPath(agentDir);
    }
    /** Bind `endpoint` and serve until idle exit or `shutdown`. */
    serve(endpoint) {
        return this.#server.serve(endpoint);
    }
    async #dispatch(request) {
        try {
            return await this.#handle(request);
        }
        catch (error) {
            return { id: request.id, ok: false, error: error instanceof Error ? error.message : String(error) };
        }
    }
    async #handle(request) {
        switch (request.op) {
            case "ping":
                return {
                    id: request.id,
                    ok: true,
                    op: "ping",
                    version: VERSION,
                    pid: process.pid,
                    engines: [...this.#engines.keys()],
                };
            case "complete": {
                const suggestion = request.method === "smollm"
                    ? await this.#blend(request.before, request.prefix)
                    : await (await this.#engine(request.method)).predictor.complete(request.before, request.prefix);
                return { id: request.id, ok: true, op: "complete", suggestion };
            }
            case "feedback": {
                const engine = await this.#engine(request.method);
                await engine.predictor.feedback(request.before, request.prefix, request.suggestion, request.accepted);
                engine.markDirty();
                this.#persistCadence.touch();
                return { id: request.id, ok: true, op: "feedback" };
            }
            case "sync": {
                let ingested = 0;
                for (const pending of this.#engines.values()) {
                    const engine = await pending.catch(() => undefined);
                    if (engine)
                        ingested += await engine.ingest(this.#historyDbPath);
                }
                if (ingested > 0)
                    this.#persistCadence.touch();
                return { id: request.id, ok: true, op: "sync", ingested };
            }
            case "shutdown":
                setImmediate(() => this.#server.exit("shutdown requested"));
                return { id: request.id, ok: true, op: "shutdown" };
        }
    }
    /**
     * The `smollm` setting: SmolLM's and ngram's answers blended
     * ({@link blendPredictions}). Until SmolLM loads (weights still
     * downloading) or while it cannot, ngram answers alone through the blend.
     */
    async #blend(before, prefix) {
        const [ngram, smollm] = await Promise.all([
            this.#engine("ngram").then(engine => engine.predictor.complete(before, prefix)),
            this.#engine("smollm").then(engine => engine.predictor.complete(before, prefix), () => null),
        ]);
        return blendPredictions(ngram, smollm);
    }
    #engine(method) {
        const now = Date.now();
        const failedAt = this.#failedAt.get(method);
        if (failedAt !== undefined && now - failedAt >= OPEN_RETRY_MS) {
            this.#failedAt.delete(method);
            this.#engines.delete(method);
        }
        const missingAt = this.#missingAt.get(method);
        if (missingAt !== undefined && now - missingAt >= WEIGHTS_RECHECK_MS) {
            this.#missingAt.delete(method);
            this.#engines.delete(method);
        }
        let pending = this.#engines.get(method);
        if (!pending) {
            pending = this.#open(method);
            this.#engines.set(method, pending);
            pending.catch(error => {
                if (error instanceof SmolLmWeightsMissingError) {
                    // Rechecked after WEIGHTS_RECHECK_MS: the composer is fetching them.
                    this.#missingAt.set(method, Date.now());
                    return;
                }
                this.#failedAt.set(method, Date.now());
                logger.warn("text-predict: engine unavailable", { method, error: String(error) });
            });
        }
        return pending;
    }
    async #open(method) {
        let modelDir;
        if (method === "smollm") {
            if (!(await smolLmWeightsReady()))
                throw new SmolLmWeightsMissingError();
            modelDir = getSmolLmModelDir();
        }
        const stateDir = getPredictStateDir(this.#agentDir, method);
        await fs.mkdir(stateDir, { recursive: true });
        const startedAt = performance.now();
        // SmolLM only serves the blend, which gates on its own score.
        const showThreshold = method === "smollm" ? 0 : undefined;
        let predictor = new TextPredictor({ method, stateDir, modelDir, showThreshold });
        let cursor;
        try {
            await predictor.ready();
            cursor = await readCursor(stateDir);
        }
        catch (error) {
            // Unloadable state (corrupt, or from an incompatible engine version):
            // start over and rebuild it like a fresh install.
            logger.warn("text-predict: engine state failed to load; rebuilding", { method, error: String(error) });
            await fs.rm(stateDir, { recursive: true, force: true });
            await fs.mkdir(stateDir, { recursive: true });
            predictor = new TextPredictor({ method, stateDir, modelDir, showThreshold });
            await predictor.ready();
            cursor = undefined;
        }
        const engine = new Engine(method, stateDir, predictor, cursor);
        const ingested = await engine.ingest(this.#historyDbPath);
        if (ingested > 0)
            this.#persistCadence.touch();
        logger.debug("text-predict: engine ready", {
            method,
            ingested,
            ms: Math.round(performance.now() - startedAt),
        });
        return engine;
    }
    async #persistAll() {
        for (const pending of this.#engines.values()) {
            const engine = await pending.catch(() => undefined);
            if (!engine)
                continue;
            try {
                await engine.persist();
            }
            catch (error) {
                logger.warn("text-predict: persist failed", { method: engine.method, error: String(error) });
            }
        }
    }
}
/** Worker entry: serve the endpoint and agent directory named by the broker spec environment. */
export async function startTextPredictDaemonFromEnvironment() {
    const endpoint = Bun.env[TEXT_PREDICT_SOCKET_ENV];
    const agentDir = Bun.env[TEXT_PREDICT_AGENT_DIR_ENV];
    if (!endpoint || !agentDir) {
        throw new Error(`${TEXT_PREDICT_SOCKET_ENV} and ${TEXT_PREDICT_AGENT_DIR_ENV} must be set`);
    }
    await new TextPredictDaemon(agentDir).serve(endpoint);
}
