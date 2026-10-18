import { isRecord, logger, Snowflake } from "@rva/utils";
import { formatCost } from "@rva/tui/overlays/agent-hub-renderer";
import { MAIN_AGENT_ID } from "../registry/agent-registry";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { withBridgeTimeoutPause } from "./bridge-timeout";
import { EVAL_HANDLE_CONCURRENCY, evalRequestSlots } from "./completion-bridge";
import { JUDGMENT_BATCH_PROGRESS_EVENT_CHANNEL } from "./judgment-batch-events";
import { loadEvalJudgmentImages, parseQuestions, parseState, sessionJudge, toEvalJudgmentResult, } from "./judgment-bridge";
/** Synthetic bridge name reserved for the `judge_batch()` helper across both runtimes. */
export const EVAL_JUDGMENT_BATCH_BRIDGE_NAME = "__judge_batch__";
/** Default per-item retry budget; a retry re-walks the whole judge chain. */
const DEFAULT_RETRIES = 1;
/** Progress is reported to the async job at most this often. */
const PROGRESS_INTERVAL_MS = 1000;
/**
 * Once a waiting drain sees its first item, it holds this long for more.
 * Fan-out workers settle one at a time, so returning on the first would cost
 * one bridge round-trip (and one runtime wakeup) per item.
 */
const DRAIN_COALESCE_MS = 100;
/** Live UI snapshots are coalesced to at most four emissions per second. */
const EVENT_PROGRESS_INTERVAL_MS = 250;
/** Intent used when the caller does not describe the batch. */
const DEFAULT_INTENT = "Judging";
function invalid(detail) {
    return new ToolError(`judge_batch() received invalid arguments: ${detail}`);
}
function isBatchKey(value) {
    return (typeof value === "string" && value.length > 0) || (typeof value === "number" && Number.isFinite(value));
}
function parseItems(value) {
    if (!Array.isArray(value))
        throw invalid("items must be an array of { key, state }");
    if (value.length === 0)
        throw invalid("items must not be empty");
    const seen = new Set();
    return value.map((entry, index) => {
        if (!isRecord(entry) || !isBatchKey(entry.key))
            throw invalid(`item ${index} needs a string or number key`);
        if (seen.has(entry.key))
            throw invalid(`duplicate item key ${JSON.stringify(entry.key)}`);
        seen.add(entry.key);
        const input = { key: entry.key, state: parseState(entry.state) };
        if (Object.hasOwn(entry, "images")) {
            if (Array.isArray(entry.images)) {
                input.imageSources = entry.images;
            }
            else {
                input.imageSourceError = `images for input ${JSON.stringify(String(entry.key))} must be an array of paths or image attachments`;
            }
        }
        return input;
    });
}
function parseCount(value, name, fallback, max = Number.POSITIVE_INFINITY) {
    if (value === undefined)
        return fallback;
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
        throw invalid(`${name} must be a non-negative integer`);
    }
    return Math.min(value, max);
}
function parseBatchOptions(args, total) {
    const concurrency = parseCount(args.concurrency, "concurrency", EVAL_HANDLE_CONCURRENCY, EVAL_HANDLE_CONCURRENCY);
    return {
        concurrency: concurrency > 0 ? concurrency : EVAL_HANDLE_CONCURRENCY,
        retries: parseCount(args.retries, "retries", DEFAULT_RETRIES),
        minOk: parseCount(args.minOk, "minOk", 1, total),
    };
}
function parseIntent(value) {
    if (value === undefined)
        return DEFAULT_INTENT;
    if (typeof value !== "string" || value.trim().length === 0) {
        throw invalid("intent must be a non-empty string");
    }
    return value;
}
function ownerOf(session) {
    return session.getAgentId?.() ?? MAIN_AGENT_ID;
}
/** A host-owned bulk judgment run with a single pull cursor. */
export class JudgmentBatch {
    id;
    ownerId;
    intent;
    total;
    #inputs;
    #questions;
    #options;
    #session;
    #controller = new AbortController();
    #settled = [];
    #waiters = [];
    #startedAt = Date.now();
    #finished = Promise.withResolvers();
    #cursor = 0;
    #failed = 0;
    #cost = 0;
    #model;
    #running = true;
    #error;
    #lastProgressAt = 0;
    #lastEventAt = 0;
    #eventTimer;
    constructor(session, inputs, questions, options, intent) {
        this.id = `jdgb-${Snowflake.next()}`;
        this.ownerId = ownerOf(session);
        this.intent = intent;
        this.total = inputs.length;
        this.#inputs = inputs;
        this.#questions = questions;
        this.#options = options;
        this.#session = session;
    }
    /**
     * Kick off the fan-out and register the async job; returns once registered,
     * not once done. Without a job manager (or at the running-job limit) the run
     * still proceeds — only auto-delivery and `hub` addressing are lost.
     */
    start() {
        this.#emitProgressEvent();
        const manager = this.#session.asyncJobManager;
        if (manager) {
            try {
                manager.register("eval", this.intent, async ({ signal, reportProgress }) => {
                    const onAbort = () => {
                        this.cancel();
                    };
                    if (signal.aborted)
                        onAbort();
                    else
                        signal.addEventListener("abort", onAbort, { once: true });
                    try {
                        await this.#run(reportProgress);
                    }
                    finally {
                        signal.removeEventListener("abort", onAbort);
                    }
                    if (this.#error)
                        throw new Error(this.#error);
                    return this.#summary();
                }, { id: this.id, ownerId: this.ownerId });
                return;
            }
            catch (error) {
                logger.debug("judge_batch: running without an async job", {
                    id: this.id,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }
        void this.#run(undefined);
    }
    status() {
        return {
            id: this.id,
            intent: this.intent,
            total: this.total,
            done: this.#settled.length,
            failed: this.#failed,
            cost: this.#cost,
            running: this.#running,
            ...(this.#model === undefined ? {} : { model: this.#model }),
            elapsedS: Math.round((Date.now() - this.#startedAt) / 100) / 10,
            ...(this.#error === undefined ? {} : { error: this.#error }),
        };
    }
    /**
     * Items settled since the previous drain. Waits up to `timeoutMs` for at
     * least one new item, then up to {@link DRAIN_COALESCE_MS} more (never past
     * `timeoutMs`) so near-simultaneous settles return together; returns `[]` on
     * timeout. Once the cursor is exhausted on a run that died wholesale, throws
     * that error.
     */
    async drain(timeoutMs, signal) {
        if (this.#cursor === this.#settled.length && this.#running) {
            const deadline = timeoutMs === undefined ? Number.POSITIVE_INFINITY : Date.now() + timeoutMs;
            await this.#wait(timeoutMs, signal, { untilSettle: true });
            const linger = Math.min(DRAIN_COALESCE_MS, deadline - Date.now());
            if (this.#running && this.#cursor < this.#settled.length && linger > 0) {
                await this.#wait(linger, signal);
            }
        }
        if (this.#cursor < this.#settled.length) {
            const items = this.#settled.slice(this.#cursor);
            this.#cursor = this.#settled.length;
            return items;
        }
        if (!this.#running && this.#error !== undefined)
            throw new ToolError(this.#error);
        return [];
    }
    results() {
        const out = {};
        for (const item of this.#settled)
            if (item.answers)
                out[String(item.key)] = item.answers;
        return out;
    }
    failed() {
        const out = {};
        for (const item of this.#settled)
            if (item.error !== undefined)
                out[String(item.key)] = item.error;
        return out;
    }
    /** Abort in-flight items, settle everything unstarted as cancelled, and cancel the async job. */
    cancel() {
        if (!this.#running || this.#controller.signal.aborted)
            return false;
        this.#controller.abort(new ToolError("judge_batch cancelled"));
        this.#session.asyncJobManager?.cancel(this.id, { ownerId: this.ownerId });
        return true;
    }
    /**
     * Resolve on `timeoutMs`, run completion, or — with `untilSettle` — the next
     * settled item. Rejects when `signal` aborts.
     */
    async #wait(timeoutMs, signal, options) {
        const settled = Promise.withResolvers();
        const wake = () => settled.resolve();
        if (options?.untilSettle)
            this.#waiters.push(wake);
        let timer;
        if (timeoutMs !== undefined) {
            timer = setTimeout(wake, timeoutMs);
            timer.unref?.();
        }
        const onAbort = () => settled.reject(signal?.reason ?? new ToolError("judge_batch drain aborted"));
        if (signal?.aborted)
            onAbort();
        else
            signal?.addEventListener("abort", onAbort, { once: true });
        try {
            await Promise.race([settled.promise, this.#finished.promise]);
        }
        finally {
            clearTimeout(timer);
            signal?.removeEventListener("abort", onAbort);
            const index = this.#waiters.indexOf(wake);
            if (index >= 0)
                this.#waiters.splice(index, 1);
        }
    }
    #settle(item) {
        this.#settled.push(item);
        if (item.error !== undefined)
            this.#failed++;
        if (item.model !== undefined)
            this.#model = item.model;
        for (const wake of this.#waiters.splice(0))
            wake();
        this.#emitProgressEvent();
    }
    async #run(reportProgress) {
        try {
            await this.#judgeAll(reportProgress);
        }
        catch (error) {
            this.#error = error instanceof Error ? error.message : String(error);
        }
        finally {
            this.#running = false;
            this.#emitProgressEvent(true);
            this.#finished.resolve();
            for (const wake of this.#waiters.splice(0))
                wake();
        }
        await this.#reportProgress(reportProgress, true);
    }
    async #judgeAll(reportProgress) {
        const signal = this.#controller.signal;
        let judge;
        try {
            judge = sessionJudge({ session: this.#session }, "judge_batch", usage => {
                this.#cost += usage.usage.cost.total;
            });
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            for (const input of this.#inputs)
                this.#settle({ key: input.key, error: message });
            this.#error = message;
            return;
        }
        // Workers pull from a shared index so completion order follows the
        // backend, not the input order; the cursor exposes items as they land.
        let next = 0;
        const worker = async () => {
            while (next < this.#inputs.length) {
                const input = this.#inputs[next++];
                this.#settle(signal.aborted ? { key: input.key, error: "cancelled" } : await this.#judgeItem(judge, input, signal));
                await this.#reportProgress(reportProgress, false);
            }
        };
        await Promise.all(Array.from({ length: Math.min(this.#options.concurrency, this.total) }, worker));
        const ok = this.#settled.length - this.#failed;
        if (signal.aborted)
            this.#error = "judge_batch cancelled";
        else if (ok < this.#options.minOk) {
            this.#error = `judge_batch: only ${ok}/${this.total} item(s) judged (min_ok=${this.#options.minOk}); last error: ${this.#lastError() ?? "unknown"}`;
        }
    }
    async #judgeItem(judge, input, signal) {
        if (signal.aborted)
            return { key: input.key, error: "cancelled" };
        if (input.imageSourceError)
            return { key: input.key, error: input.imageSourceError };
        try {
            await evalRequestSlots.acquire(signal);
        }
        catch {
            return { key: input.key, error: "cancelled" };
        }
        try {
            if (signal.aborted)
                return { key: input.key, error: "cancelled" };
            let images;
            try {
                images = await loadEvalJudgmentImages(input.imageSources, this.#session.cwd);
            }
            catch (error) {
                return { key: input.key, error: error instanceof Error ? error.message : String(error) };
            }
            let lastError;
            for (let attempt = 0; attempt <= this.#options.retries; attempt++) {
                if (signal.aborted)
                    return { key: input.key, error: "cancelled" };
                try {
                    const result = toEvalJudgmentResult(await judge.judge({
                        state: input.state,
                        questions: this.#questions,
                        ...(images === undefined ? {} : { images }),
                    }, { signal }));
                    return { key: input.key, answers: result.answers, model: result.model };
                }
                catch (error) {
                    lastError = error;
                }
            }
            if (signal.aborted)
                return { key: input.key, error: "cancelled" };
            return {
                key: input.key,
                error: lastError instanceof Error ? lastError.message : String(lastError),
            };
        }
        finally {
            evalRequestSlots.release();
        }
    }
    #lastError() {
        for (let index = this.#settled.length - 1; index >= 0; index--) {
            const error = this.#settled[index].error;
            if (error !== undefined && error !== "cancelled")
                return error;
        }
        return undefined;
    }
    #emitProgressEvent(final = false) {
        if (final && this.#eventTimer) {
            clearTimeout(this.#eventTimer);
            this.#eventTimer = undefined;
        }
        const eventBus = this.#session.eventBus;
        if (!eventBus)
            return;
        const now = Date.now();
        const elapsed = now - this.#lastEventAt;
        if (!final && elapsed < EVENT_PROGRESS_INTERVAL_MS) {
            if (!this.#eventTimer) {
                this.#eventTimer = setTimeout(() => {
                    this.#eventTimer = undefined;
                    this.#emitProgressEvent();
                }, EVENT_PROGRESS_INTERVAL_MS - elapsed);
                this.#eventTimer.unref?.();
            }
            return;
        }
        this.#lastEventAt = now;
        const { id, intent, done, total, failed, cost, running, error } = this.status();
        const progress = {
            id,
            intent,
            done,
            total,
            failed,
            cost,
            running,
            ...(error === undefined ? {} : { error }),
        };
        eventBus.emit(JUDGMENT_BATCH_PROGRESS_EVENT_CHANNEL, progress);
    }
    async #reportProgress(report, final) {
        if (!report)
            return;
        const now = Date.now();
        if (!final && now - this.#lastProgressAt < PROGRESS_INTERVAL_MS)
            return;
        this.#lastProgressAt = now;
        await report(this.#summary());
    }
    #summary() {
        const { done, failed, cost, model, elapsedS } = this.status();
        const state = this.#running ? "judging" : this.#controller.signal.aborted ? "cancelled" : "judged";
        return `${state} ${done}/${this.total}${failed ? ` · ${failed} failed` : ""}${cost > 0 ? ` · ${formatCost(cost)}` : ""}${model ? ` · ${model}` : ""} · ${elapsedS}s`;
    }
}
const batches = new Map();
/** Resolve a batch owned by the calling session. */
export function getJudgmentBatch(id, session) {
    const batch = batches.get(id);
    return batch && batch.ownerId === ownerOf(session) ? batch : undefined;
}
/** Cancel and forget every batch owned by an agent session. */
export function releaseJudgmentBatches(ownerId) {
    for (const [id, batch] of batches) {
        if (batch.ownerId !== ownerId)
            continue;
        batch.cancel();
        batches.delete(id);
    }
}
function requireBatch(args, session) {
    if (typeof args.id !== "string" || args.id.length === 0)
        throw invalid("op requires a batch id");
    const batch = getJudgmentBatch(args.id, session);
    if (!batch)
        throw new ToolError(`unknown judge_batch "${args.id}"`);
    return batch;
}
/** Create or operate a host-owned bulk judgment run. */
export async function runEvalJudgmentBatch(args, options) {
    if (!isRecord(args) || typeof args.op !== "string")
        throw invalid("expected { op, … }");
    const { session } = options;
    switch (args.op) {
        case "create": {
            if (Object.hasOwn(args, "images"))
                throw invalid("images must be provided on each item");
            const items = parseItems(args.items);
            const questions = parseQuestions(args.questions);
            const batch = new JudgmentBatch(session, items, questions, parseBatchOptions(args, items.length), parseIntent(args.intent));
            batches.set(batch.id, batch);
            batch.start();
            return batch.status();
        }
        case "attach":
            return requireBatch(args, session).status();
        case "status":
            return requireBatch(args, session).status();
        case "drain": {
            const batch = requireBatch(args, session);
            const timeoutMs = args.timeoutMs;
            if (timeoutMs !== undefined &&
                (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 0)) {
                throw invalid("timeoutMs must be a non-negative finite number");
            }
            const items = await withBridgeTimeoutPause(options.emitStatus, () => batch.drain(timeoutMs, options.signal));
            return { items };
        }
        case "results":
            return { results: requireBatch(args, session).results() };
        case "failed":
            return { failed: requireBatch(args, session).failed() };
        case "cancel": {
            const batch = requireBatch(args, session);
            const cancelled = batch.cancel();
            return { cancelled };
        }
        case "close": {
            const batch = requireBatch(args, session);
            batch.cancel();
            batches.delete(batch.id);
            return { closed: true };
        }
        default:
            throw invalid(`unknown op "${args.op}"`);
    }
}
