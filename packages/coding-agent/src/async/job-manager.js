import { logger } from "@rva/utils";
const DELIVERY_RETRY_BASE_MS = 500;
const DELIVERY_RETRY_MAX_MS = 30000;
const DELIVERY_RETRY_JITTER_MS = 200;
const DEFAULT_RETENTION_MS = 5 * 60 * 1000;
/**
 * A settled job row whose result was already consumed — auto-delivered to its
 * sink, or recovered by a foreground `wait` snapshot — has
 * served its inspectability purpose: the model holds the result, and later
 * job snapshots listing it for the full retention window is exactly the
 * "background jobs hang around after they complete" complaint. Evict shortly
 * after consumption instead; the short grace still covers a follow-up
 * `agent://<id>` read of the just-delivered pointer. Unconsumed rows
 * (dead-lettered deliveries, still-retrying sinks, watch-suppressed jobs
 * nobody polled) keep the full {@link DEFAULT_RETENTION_MS} window.
 */
const CONSUMED_RESULT_EVICTION_MS = 30000;
/**
 * Extra delay after an `async-result` delivery settles (its `ASIDE_MESSAGE_COMMIT`
 * hook fires, resolving `enqueueWithReceipt()`) before retained artifacts are
 * removed. The commit hook fires when the follow-up is inserted into the
 * transcript, not after the model's next provider call has actually read it —
 * this window gives that round trip time to complete before the backing
 * `<id>.md`/`.json` files disappear out from under an advertised `agent://` URL.
 */
const RETAINED_ARTIFACTS_CLEANUP_GRACE_MS = 60000;
/**
 * Upper bound on how long retained-artifacts cleanup waits for a hung
 * delivery sink before giving up and running cleanup anyway. Without this,
 * a sink that never settles (e.g. a yield-queue receipt whose owning
 * session is gone) would leak the temp directory for the process lifetime
 * (PR #10625 review). Matches {@link DEFAULT_RETENTION_MS}: by the time a
 * job would have been evicted anyway, there is no realistic path left for
 * the model to still read the advertised `agent://` pointer.
 */
const RETAINED_ARTIFACTS_CLEANUP_MAX_WAIT_MS = DEFAULT_RETENTION_MS;
const DEFAULT_MAX_RUNNING_JOBS = 15;
/** Abort reason used only when the owning session shuts down the entire manager. */
export const ASYNC_JOB_MANAGER_SHUTDOWN_REASON = Symbol("AsyncJobManager shutdown");
/**
 * Job-body failure that still carries the run's structured output, so a
 * strict-mode schema violation fails the job without dropping the parsed
 * (invalid) payload.
 */
export class AsyncJobError extends Error {
    structured;
    constructor(message, structured) {
        super(message);
        this.structured = structured;
    }
}
export class AsyncJobManager {
    static #instance;
    /** Legacy pointer to the first live root; child routing uses the parent's scoped manager instead. */
    static instance() {
        return AsyncJobManager.#instance;
    }
    /** Install or clear the process-global instance. */
    static setInstance(value) {
        AsyncJobManager.#instance = value;
    }
    /** Reset the process-global instance. Test-only. */
    static resetForTests() {
        AsyncJobManager.#instance = undefined;
    }
    #jobs = new Map();
    #deliveries = [];
    #inFlightDeliveries = [];
    #suppressedDeliveries = new Set();
    #watchedJobs = new Set();
    #consumedJobResults = new Set();
    #evictionTimers = new Map();
    #releasedForegroundJobs = new Set();
    #nextAutoId = 1;
    #deliverySinks = new Map();
    #onJobComplete;
    #maxRunningJobsOption;
    #retentionMs;
    #retainedArtifactsCleanupGraceMs;
    #retainedArtifactsCleanupMaxWaitMs;
    #consumedResultEvictionMs;
    #deliveryLoop;
    #deliveryQueueChanged = Promise.withResolvers();
    #disposed = false;
    #filterJobs(jobs, filter) {
        if (!filter)
            return Array.from(jobs);
        const out = [];
        for (const job of jobs) {
            if (job.ownerId === filter.ownerId)
                out.push(job);
        }
        return out;
    }
    #visibleJobs(filter) {
        return this.#filterJobs(this.#jobs.values(), filter).filter(job => !job.foreground);
    }
    constructor(options) {
        this.#onJobComplete = options.onJobComplete;
        this.#maxRunningJobsOption = options.maxRunningJobs;
        this.#retentionMs = Math.max(0, Math.floor(options.retentionMs ?? DEFAULT_RETENTION_MS));
        this.#retainedArtifactsCleanupGraceMs = Math.max(0, Math.floor(options.retainedArtifactsCleanupGraceMs ?? RETAINED_ARTIFACTS_CLEANUP_GRACE_MS));
        this.#retainedArtifactsCleanupMaxWaitMs = Math.max(0, Math.floor(options.retainedArtifactsCleanupMaxWaitMs ?? RETAINED_ARTIFACTS_CLEANUP_MAX_WAIT_MS));
        this.#consumedResultEvictionMs = Math.max(0, Math.floor(options.consumedResultEvictionMs ?? CONSUMED_RESULT_EVICTION_MS));
    }
    /** Effective running-job cap (at least 1), resolved at check time. */
    get #maxRunningJobs() {
        const option = this.#maxRunningJobsOption;
        const value = typeof option === "function" ? option() : option;
        return Math.max(1, Math.floor(value ?? DEFAULT_MAX_RUNNING_JOBS));
    }
    /** True when the running-job count has reached the configured cap. */
    get atCapacity() {
        if (this.#disposed)
            return true;
        // Mirror register(): queued jobs hold no execution slot.
        let activeCount = 0;
        for (const job of this.#jobs.values()) {
            if (job.status === "running" && !job.queued)
                activeCount++;
        }
        return activeCount >= this.#maxRunningJobs;
    }
    register(type, label, run, options) {
        if (this.#disposed) {
            throw new Error("Async job manager is disposed");
        }
        // Queued jobs hold no execution slot yet — only count jobs that are
        // actually running so a large parked batch cannot starve registration.
        let activeCount = 0;
        for (const existing of this.#jobs.values()) {
            if (existing.status === "running" && !existing.queued)
                activeCount++;
        }
        const maxRunningJobs = this.#maxRunningJobs;
        if (activeCount >= maxRunningJobs) {
            throw new Error(`Background job limit reached (${maxRunningJobs}). Wait for running jobs to finish or cancel one.`);
        }
        const id = this.#resolveJobId(options?.id);
        this.#suppressedDeliveries.delete(id);
        this.#consumedJobResults.delete(id);
        this.#releasedForegroundJobs.delete(id);
        if (options?.foreground)
            this.#suppressedDeliveries.add(id);
        const abortController = new AbortController();
        const startTime = Date.now();
        const job = {
            id,
            type,
            status: "running",
            startTime,
            label,
            abortController,
            promise: Promise.resolve(),
            ownerId: options?.ownerId,
            agentId: options?.agentId,
            process: options?.process,
            queued: options?.queued === true,
            ...(options?.foreground ? { foreground: true } : {}),
        };
        const reportProgress = async (text, details) => {
            job.progressText = text;
            if (details)
                job.latestDetails = details;
            if (!options?.onProgress)
                return;
            try {
                await options.onProgress(text, details);
            }
            catch (error) {
                logger.warn("Async job progress callback failed", {
                    jobId: id,
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        };
        job.promise = (async () => {
            try {
                const outcome = await run({
                    jobId: id,
                    signal: abortController.signal,
                    reportProgress,
                    markRunning: () => {
                        job.queued = false;
                    },
                });
                job.endTime = Date.now();
                const text = typeof outcome === "string" ? outcome : outcome.text;
                const structured = typeof outcome === "string" ? undefined : outcome.structured;
                if (structured)
                    job.structured = structured;
                if (job.status === "cancelled") {
                    job.resultText = text;
                }
                else {
                    job.status = "completed";
                    job.resultText = text;
                    this.#enqueueDelivery(id, text);
                }
            }
            catch (error) {
                job.endTime = Date.now();
                if (error instanceof AsyncJobError && error.structured)
                    job.structured = error.structured;
                const errorText = error instanceof Error ? error.message : String(error);
                job.errorText = errorText;
                if (job.status !== "cancelled") {
                    job.status = "failed";
                    this.#enqueueDelivery(id, errorText);
                }
            }
            if (this.#releasedForegroundJobs.has(id))
                this.#discardForegroundJob(id);
            else
                this.#scheduleEviction(id);
        })();
        this.#jobs.set(id, job);
        return id;
    }
    /**
     * Cancel a single job by id. When a filter is given and its owner does not
     * match the job's owner, the call is treated as not-found (returns false)
     * so cross-agent cancellation is rejected at the manager level.
     */
    cancel(id, filter) {
        const job = this.#jobs.get(id);
        if (!job)
            return false;
        if (filter && job.ownerId !== filter.ownerId)
            return false;
        if (job.status !== "running")
            return false;
        job.status = "cancelled";
        job.abortController.abort();
        return true;
    }
    getJob(id) {
        return this.#jobs.get(id);
    }
    /** Running background jobs; foreground-backed jobs stay hidden until promoted. */
    getRunningJobs(filter) {
        return this.#visibleJobs(filter).filter(job => job.status === "running");
    }
    /** Settled background jobs, newest first; foreground-backed jobs stay hidden. */
    getRecentJobs(limit = 10, filter) {
        return this.#visibleJobs(filter)
            .filter(job => job.status !== "running")
            .sort((a, b) => b.startTime - a.startTime)
            .slice(0, limit);
    }
    /** Every background job row; foreground-backed jobs stay hidden until promoted. */
    getAllJobs(filter) {
        return this.#visibleJobs(filter);
    }
    /**
     * Promote a foreground-backed job to a real background job: it becomes
     * visible to listings and its completion is delivered (re-enqueued when it
     * already settled during the foreground wait). Returns false for unknown ids.
     */
    backgroundJob(jobId) {
        const job = this.#jobs.get(jobId);
        if (!job)
            return false;
        if (!job.foreground)
            return true;
        job.foreground = undefined;
        this.#suppressedDeliveries.delete(jobId);
        if (job.status === "completed" || job.status === "failed") {
            this.#enqueueDelivery(jobId, job.status === "completed" ? (job.resultText ?? "") : (job.errorText ?? ""));
        }
        return true;
    }
    /**
     * Drop a foreground-backed job whose result the foreground call already
     * returned (or whose call aborted). The row is discarded as soon as its run
     * settles and never surfaces as a background job.
     */
    releaseForegroundJob(jobId) {
        const job = this.#jobs.get(jobId);
        if (!job?.foreground)
            return;
        if (job.endTime !== undefined)
            this.#discardForegroundJob(jobId);
        else
            this.#releasedForegroundJobs.add(jobId);
    }
    getDeliveryState(filter) {
        const deliveries = this.#filterDeliveries(filter);
        const inFlightDeliveries = this.#filterInFlightDeliveries(filter);
        const nextRetryAt = deliveries.reduce((next, delivery) => {
            if (next === undefined)
                return delivery.nextAttemptAt;
            return Math.min(next, delivery.nextAttemptAt);
        }, undefined);
        return {
            queued: deliveries.length + inFlightDeliveries.length,
            delivering: inFlightDeliveries.length > 0 || (this.#deliveryLoop !== undefined && deliveries.length > 0),
            nextRetryAt,
            pendingJobIds: deliveries.concat(inFlightDeliveries).map(delivery => delivery.jobId),
        };
    }
    hasPendingDeliveries(filter) {
        return this.getDeliveryState(filter).queued > 0;
    }
    watchJobs(jobIds) {
        const uniqueJobIds = Array.from(new Set(jobIds.map(id => id.trim()).filter(id => id.length > 0)));
        for (const jobId of uniqueJobIds) {
            this.#watchedJobs.add(jobId);
        }
        this.#notifyDeliveryQueueChanged();
        return uniqueJobIds.length;
    }
    /**
     * Stop watching jobs. Settled jobs whose delivery was skipped while watched
     * and not consumed are re-enqueued.
     */
    unwatchJobs(jobIds) {
        const uniqueJobIds = Array.from(new Set(jobIds.map(id => id.trim()).filter(id => id.length > 0)));
        let removed = 0;
        for (const jobId of uniqueJobIds) {
            if (!this.#watchedJobs.delete(jobId))
                continue;
            removed += 1;
            const job = this.#jobs.get(jobId);
            if (!job || (job.status !== "completed" && job.status !== "failed"))
                continue;
            if (this.isDeliverySuppressed(jobId) || this.#consumedJobResults.has(jobId))
                continue;
            const queued = this.#deliveries.some(delivery => delivery.jobId === jobId) ||
                this.#inFlightDeliveries.some(delivery => delivery.jobId === jobId);
            if (!queued) {
                this.#enqueueDelivery(jobId, job.status === "completed" ? (job.resultText ?? "") : (job.errorText ?? ""));
            }
        }
        return removed;
    }
    acknowledgeDeliveries(jobIds) {
        const uniqueJobIds = Array.from(new Set(jobIds.map(id => id.trim()).filter(id => id.length > 0)));
        if (uniqueJobIds.length === 0)
            return 0;
        for (const jobId of uniqueJobIds) {
            this.#suppressedDeliveries.add(jobId);
        }
        const before = this.#deliveries.length;
        this.#deliveries.splice(0, this.#deliveries.length, ...this.#deliveries.filter(delivery => !this.isDeliverySuppressed(delivery.jobId)));
        this.#notifyDeliveryQueueChanged();
        return before - this.#deliveries.length;
    }
    /**
     * Mark settled job results as recovered by a foreground snapshot.
     *
     * Suppresses queued delivery and marks retained bodies as consumed so later
     * snapshots report execution state without replaying the same result.
     */
    consumeJobResults(jobIds) {
        const uniqueJobIds = Array.from(new Set(jobIds.map(id => id.trim()).filter(id => id.length > 0)));
        this.acknowledgeDeliveries(uniqueJobIds);
        let consumed = 0;
        for (const jobId of uniqueJobIds) {
            if (this.#consumeJobResult(jobId))
                consumed += 1;
        }
        return consumed;
    }
    /** True once a result was auto-delivered or recovered by a foreground snapshot. */
    isJobResultConsumed(jobId) {
        return this.#consumedJobResults.has(jobId);
    }
    /**
     * Cancel running jobs. With a filter, cancels only jobs the matching owner
     * registered; with no filter, cancels every running job
     * (used by `dispose()` to nuke the manager's state).
     *
     * `reason` is forwarded to each job's `AbortController.abort`, so a session
     * teardown can tag its owned jobs with {@link ASYNC_JOB_MANAGER_SHUTDOWN_REASON}
     * before `dispose()` runs — the task executor reads it to park (not
     * tombstone) a subagent interrupted purely by process shutdown.
     */
    cancelAll(filter, reason) {
        this.#cancelJobs(filter, reason);
    }
    #cancelJobs(filter, reason) {
        for (const job of this.#filterJobs(this.#jobs.values(), filter)) {
            if (job.status !== "running")
                continue;
            job.status = "cancelled";
            job.abortController.abort(reason);
        }
    }
    /**
     * Immediately evict completed and failed jobs matching the filter instead of
     * waiting for retention expiry, dropping every queued delivery so a prior
     * session's result can never be injected into a later transcript. Returns the
     * number of jobs evicted.
     *
     * A delivery whose sink call is already in flight (or drained onto a caller's
     * yield queue) is guarded by the owner's delivery generation, not the per-id
     * suppression marker — that marker is cleared when the id is reused.
     */
    evictCompletedJobs(filter) {
        let evicted = 0;
        for (const job of this.#filterJobs(this.#jobs.values(), filter)) {
            if (job.status !== "completed" && job.status !== "failed")
                continue;
            this.acknowledgeDeliveries([job.id]);
            if (this.#evictJob(job.id))
                evicted += 1;
        }
        return evicted;
    }
    async waitForAll() {
        await Promise.all(Array.from(this.#jobs.values()).map(job => job.promise));
    }
    /**
     * Route completions for jobs owned by `ownerId` to `sink`. Sessions register
     * their own sink at construction and unregister on dispose. Owned deliveries
     * with no live sink are dead-lettered — `onJobComplete` serves only unowned
     * deliveries.
     *
     * Last registration wins for an owner id; the returned unregister clears the
     * mapping only while it still points at `sink`, so a revived session's fresh
     * registration survives its parked predecessor's late cleanup.
     */
    registerDeliverySink(ownerId, sink) {
        this.#deliverySinks.set(ownerId, sink);
        return () => {
            if (this.#deliverySinks.get(ownerId) === sink)
                this.#deliverySinks.delete(ownerId);
        };
    }
    /**
     * Wait until every job owned by `ownerId` has settled — its run promise
     * resolved, which for cancelled jobs means the underlying process actually
     * exited. Jobs registered while waiting (e.g. by a follow-up turn) are
     * awaited too. Returns false when `timeoutMs` elapses first.
     *
     * `excludeSuppressed` skips jobs whose delivery is suppressed (acknowledged
     * or `wait`-watched): those can never re-wake a run, so quiescence barriers
     * pass it to share one contract with the pending-async-wake predicate.
     * Teardown reaps omit it — worktree safety concerns every owner process.
     */
    async waitForOwnerJobs(ownerId, options) {
        const deadline = options?.timeoutMs === undefined ? Number.POSITIVE_INFINITY : Date.now() + Math.max(0, options.timeoutMs);
        const awaited = new Set();
        for (;;) {
            const pending = this.#filterJobs(this.#jobs.values(), { ownerId }).filter(job => !awaited.has(job.id) && (options?.excludeSuppressed !== true || !this.isDeliverySuppressed(job.id)));
            if (pending.length === 0)
                return true;
            for (const job of pending)
                awaited.add(job.id);
            const settled = await this.#waitForDeliveryPromise(Promise.all(pending.map(job => job.promise)).then(() => { }), deadline);
            if (!settled)
                return false;
        }
    }
    /**
     * Cancel every job owned by `ownerId`, then wait only until `deadlineAt`.
     * The returned completion keeps waiting for actual process settlement when
     * the deadline expires, so callers can move that cleanup out of the
     * user-visible Task wait without losing ownership of the live work.
     */
    async cancelAndReapOwnerJobs(ownerId, deadlineAt) {
        this.cancelAll({ ownerId });
        const timeoutMs = Math.max(0, deadlineAt - Date.now());
        const settled = await this.waitForOwnerJobs(ownerId, { timeoutMs });
        if (settled) {
            return { settled: true, pendingJobIds: [], completion: Promise.resolve() };
        }
        const pendingJobIds = this.#filterJobs(this.#jobs.values(), { ownerId })
            .filter(job => job.status === "running" || job.status === "cancelled")
            .map(job => job.id);
        const completion = this.waitForOwnerJobs(ownerId).then(() => { });
        return { settled: false, pendingJobIds, completion };
    }
    async #waitForAllUntil(deadline) {
        const promises = Array.from(this.#jobs.values()).map(job => job.promise);
        if (promises.length === 0)
            return true;
        if (deadline === Number.POSITIVE_INFINITY) {
            await Promise.all(promises);
            return true;
        }
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0)
            return false;
        const timeout = Promise.withResolvers();
        const timer = setTimeout(() => timeout.resolve("timeout"), remainingMs);
        timer.unref();
        try {
            const result = await Promise.race([Promise.all(promises).then(() => "settled"), timeout.promise]);
            return result === "settled";
        }
        finally {
            clearTimeout(timer);
        }
    }
    async drainDeliveries(options) {
        const timeoutMs = options?.timeoutMs;
        const filter = options?.filter;
        const hasDeadline = timeoutMs !== undefined;
        const deadline = hasDeadline ? Date.now() + Math.max(timeoutMs, 0) : Number.POSITIVE_INFINITY;
        while (this.hasPendingDeliveries(filter)) {
            if (filter) {
                const delivered = await this.#deliverNextFiltered(filter, deadline);
                if (delivered)
                    continue;
                return false;
            }
            const inFlightDeliveries = this.#filterInFlightDeliveries();
            if (inFlightDeliveries.length > 0 && this.#filterDeliveries().length === 0) {
                const delivered = await this.#waitForDeliveryPromise(inFlightDeliveries[0]?.promise, deadline);
                if (delivered)
                    continue;
                return false;
            }
            this.#ensureDeliveryLoop();
            const loop = this.#deliveryLoop;
            if (!loop) {
                continue;
            }
            if (!hasDeadline) {
                await loop;
                continue;
            }
            const remainingMs = deadline - Date.now();
            if (remainingMs <= 0) {
                return false;
            }
            await Promise.race([loop, Bun.sleep(remainingMs)]);
            if (Date.now() >= deadline && this.hasPendingDeliveries(filter)) {
                return false;
            }
        }
        return true;
    }
    async dispose(options) {
        this.#disposed = true;
        this.#clearEvictionTimers();
        this.#cancelJobs(undefined, ASYNC_JOB_MANAGER_SHUTDOWN_REASON);
        const timeoutMs = Math.max(options?.timeoutMs ?? 3000, 0);
        const deadline = Date.now() + timeoutMs;
        const jobsSettled = await this.#waitForAllUntil(deadline);
        const drained = await this.drainDeliveries({ timeoutMs: Math.max(deadline - Date.now(), 0) });
        this.#clearEvictionTimers();
        // Bypass the grace-period sleep: dispose has already drained/cancelled
        // deliveries above, so there is nothing left for the model to read via
        // `agent://<id>` — sleeping the retention window here would only leak
        // temp dirs for up to `retainedArtifactsCleanupGraceMs` (or past
        // process exit, since dispose does not await these cleanups).
        for (const job of this.#jobs.values())
            this.#runRetainedArtifactsCleanup(job, { bypassGrace: true });
        this.#jobs.clear();
        this.#deliveries.length = 0;
        this.#notifyDeliveryQueueChanged();
        this.#inFlightDeliveries.length = 0;
        this.#suppressedDeliveries.clear();
        this.#watchedJobs.clear();
        this.#consumedJobResults.clear();
        this.#releasedForegroundJobs.clear();
        this.#deliverySinks.clear();
        return jobsSettled && drained;
    }
    #consumeJobResult(jobId) {
        const job = this.#jobs.get(jobId);
        if (!job || job.status === "running" || this.#consumedJobResults.has(jobId))
            return false;
        if (job.resultText === undefined && job.errorText === undefined)
            return false;
        this.#consumedJobResults.add(jobId);
        // The result reached its consumer (sink delivery or foreground snapshot):
        // the row no longer needs to outlive the full retention window. Re-arm the
        // eviction timer with the short consumed grace — but only when no delivery
        // for this job is still queued or in flight. An in-flight delivery is an
        // async-result entry parked on the owner's yield queue, and the foreground
        // snapshot that consumed this result suppressed exactly that entry via
        // #suppressedDeliveries; evicting now would clear that marker (#evictJob)
        // before the queue's isStale check drains it, letting the already-consumed
        // result inject a duplicate async-result follow-up. A parked entry keeps
        // the row until its delivery settles (see #scheduleEviction), which then
        // arms the consumed grace. Clamping inside #scheduleEviction keeps a
        // shorter configured retention the effective cap.
        const deliveryPending = this.#deliveries.some(delivery => delivery.jobId === jobId) ||
            this.#inFlightDeliveries.some(delivery => delivery.jobId === jobId);
        if (!deliveryPending) {
            this.#scheduleEviction(jobId, this.#consumedResultEvictionMs);
        }
        return true;
    }
    /**
     * Evict a released foreground job and, when it holds the newest auto id,
     * return that id to the counter: it was never listed or delivered, so the
     * next background job reuses it without gaps or ambiguity.
     */
    #discardForegroundJob(jobId) {
        this.#releasedForegroundJobs.delete(jobId);
        this.#evictJob(jobId);
        if (jobId === `bg_${this.#nextAutoId - 1}`)
            this.#nextAutoId -= 1;
    }
    #resolveJobId(preferredId) {
        preferredId = preferredId?.trim();
        if (!preferredId) {
            // Monotonic for the manager's lifetime: evicted ids are never recycled,
            // so `bg_N` names one job for the whole session.
            while (true) {
                const id = `bg_${this.#nextAutoId}`;
                this.#nextAutoId += 1;
                if (!this.#jobs.has(id))
                    return id;
            }
        }
        const base = preferredId.trim();
        if (!this.#jobs.has(base))
            return base;
        let suffix = 2;
        let candidate = `${base}-${suffix}`;
        while (this.#jobs.has(candidate)) {
            suffix += 1;
            candidate = `${base}-${suffix}`;
        }
        return candidate;
    }
    /**
     * Fire a retained temporary artifacts cleanup exactly once, deferred
     * until this job's `async-result` delivery has settled (delivered,
     * dead-lettered, or given up retrying) plus a grace period. Job-row
     * eviction happens on its own timer independent of delivery — a still-
     * streaming owner session can leave a delivery in flight (its sink
     * awaits `yieldQueue.enqueueWithReceipt()`) well past the retention
     * window, and deleting the retained directory before that receipt
     * settles would advertise an `agent://` URL whose backing files are
     * already gone.
     * The receipt itself resolves at `ASIDE_MESSAGE_COMMIT` — when the
     * follow-up is inserted into the transcript, but *before* the next
     * provider call that actually shows it to the model (agent-loop fires
     * the commit hook, then starts the call). Running cleanup immediately
     * on settlement would delete the artifacts before the model's very next
     * turn has any chance to read the pointer via a tool call, so a grace
     * period covers that round trip.
     * Errors are logged, not thrown — a failed disposal must not block job
     * eviction or manager teardown.
     */
    #runRetainedArtifactsCleanup(job, options) {
        const cleanup = job.retainedArtifactsCleanup;
        if (!cleanup)
            return;
        job.retainedArtifactsCleanup = undefined;
        const jobId = job.id;
        const bypassGrace = options?.bypassGrace === true;
        void this.#waitForJobDeliverySettledBounded(jobId)
            .then(() => !bypassGrace && this.#retainedArtifactsCleanupGraceMs > 0
            ? Bun.sleep(this.#retainedArtifactsCleanupGraceMs)
            : undefined)
            .then(cleanup)
            .catch(error => {
            logger.warn("Async job retained artifacts cleanup failed", {
                jobId,
                error: error instanceof Error ? error.message : String(error),
            });
        });
    }
    /**
     * Bounded variant of {@link #waitForJobDeliverySettled}: gives up and
     * resolves after {@link #retainedArtifactsCleanupMaxWaitMs} even if the
     * delivery sink never settles (e.g. a yield-queue receipt whose owning
     * session is gone) so a hung sink cannot leak the retained temp
     * directory for the process lifetime (PR #10625 review). The unbounded
     * wait keeps running in the background after the bound trips; it is
     * harmless once orphaned since cleanup no longer depends on it.
     */
    async #waitForJobDeliverySettledBounded(jobId) {
        const timedOut = Promise.withResolvers();
        const timer = setTimeout(() => timedOut.resolve(true), this.#retainedArtifactsCleanupMaxWaitMs);
        timer.unref();
        try {
            const timedOutFirst = await Promise.race([
                this.#waitForJobDeliverySettled(jobId).then(() => false),
                timedOut.promise,
            ]);
            if (timedOutFirst) {
                logger.warn("Async job delivery did not settle before the retained artifacts cleanup bound; running cleanup anyway", {
                    jobId,
                    maxWaitMs: this.#retainedArtifactsCleanupMaxWaitMs,
                });
            }
        }
        finally {
            clearTimeout(timer);
        }
    }
    /**
     * Resolve once no delivery for `jobId` is queued or in flight. Loops
     * because a failed in-flight attempt may requeue itself for retry;
     * terminates once the delivery succeeds, is dead-lettered (no live
     * sink), or stops retrying (job already evicted from `#jobs`).
     */
    async #waitForJobDeliverySettled(jobId) {
        for (;;) {
            const inFlight = this.#inFlightDeliveries.find(delivery => delivery.jobId === jobId);
            if (inFlight) {
                await inFlight.promise?.catch(() => { });
                continue;
            }
            const queued = this.#deliveries.find(delivery => delivery.jobId === jobId);
            if (!queued)
                return;
            this.#ensureDeliveryLoop();
            await this.#waitForDeliveryQueueChange(Math.max(50, queued.nextAttemptAt - Date.now()));
        }
    }
    #evictJob(jobId) {
        clearTimeout(this.#evictionTimers.get(jobId));
        this.#evictionTimers.delete(jobId);
        this.#suppressedDeliveries.delete(jobId);
        this.#watchedJobs.delete(jobId);
        this.#consumedJobResults.delete(jobId);
        const job = this.#jobs.get(jobId);
        if (job)
            this.#runRetainedArtifactsCleanup(job);
        return this.#jobs.delete(jobId);
    }
    /**
     * Arm (or re-arm) this job's eviction timer. The default delay is the full
     * retention window; a consumed result passes the shorter
     * {@link #consumedResultEvictionMs}. The delay is clamped to the configured
     * retention so an explicit short retention always stays the effective cap.
     * A timer that fires while a suppressed job's delivery is in flight (its
     * async-result entry parked on a busy owner's yield queue) evicts only once
     * that attempt settles: the parked entry's isStale check resolves through
     * the suppression marker #evictJob clears, so evicting mid-park would
     * re-inject a result a foreground snapshot already consumed. Unsuppressed
     * in-flight deliveries keep the bounded lifecycle, so a receipt that never
     * settles cannot pin the row and its retained artifacts.
     */
    #scheduleEviction(jobId, delayMs = this.#retentionMs) {
        if (this.#disposed)
            return;
        if (this.#retentionMs <= 0) {
            this.#evictJob(jobId);
            return;
        }
        const delay = Math.max(0, Math.min(this.#retentionMs, delayMs));
        clearTimeout(this.#evictionTimers.get(jobId));
        const timer = setTimeout(() => {
            const inFlight = this.#inFlightDeliveries.find(delivery => delivery.jobId === jobId)?.promise;
            if (!inFlight || !this.isDeliverySuppressed(jobId)) {
                this.#evictJob(jobId);
                return;
            }
            // The settled attempt may re-arm this job's timer (consumed grace);
            // only evict when nothing replaced this one in the meantime.
            void inFlight.then(() => {
                if (this.#evictionTimers.get(jobId) === timer)
                    this.#evictJob(jobId);
            });
        }, delay);
        timer.unref();
        this.#evictionTimers.set(jobId, timer);
    }
    #clearEvictionTimers() {
        for (const timer of this.#evictionTimers.values()) {
            clearTimeout(timer);
        }
        this.#evictionTimers.clear();
    }
    #filterDeliveries(filter) {
        return this.#deliveries.filter(delivery => (!filter || delivery.ownerId === filter.ownerId) && !this.isDeliverySuppressed(delivery.jobId));
    }
    #filterInFlightDeliveries(filter) {
        return this.#inFlightDeliveries.filter(delivery => (!filter || delivery.ownerId === filter.ownerId) && !this.isDeliverySuppressed(delivery.jobId));
    }
    async #deliverNextFiltered(filter, deadline) {
        while (true) {
            let selected;
            for (const delivery of this.#deliveries) {
                if (delivery.ownerId !== filter.ownerId)
                    continue;
                if (this.isDeliverySuppressed(delivery.jobId))
                    continue;
                if (!selected || delivery.nextAttemptAt < selected.nextAttemptAt) {
                    selected = delivery;
                }
            }
            if (!selected) {
                const inFlight = this.#filterInFlightDeliveries(filter);
                if (inFlight.length === 0)
                    return true;
                return this.#waitForDeliveryPromise(inFlight[0]?.promise, deadline);
            }
            const now = Date.now();
            if (selected.nextAttemptAt > now) {
                if (selected.nextAttemptAt > deadline)
                    return false;
                await this.#waitForDeliveryQueueChange(selected.nextAttemptAt - now);
                continue;
            }
            const index = this.#deliveries.indexOf(selected);
            if (index === -1)
                continue;
            this.#deliveries.splice(index, 1);
            this.#notifyDeliveryQueueChanged();
            if (this.isDeliverySuppressed(selected.jobId))
                continue;
            return this.#waitForDeliveryPromise(this.#deliverDelivery(selected), deadline);
        }
    }
    isDeliverySuppressed(jobId) {
        return this.#suppressedDeliveries.has(jobId) || this.#watchedJobs.has(jobId);
    }
    #enqueueDelivery(jobId, text) {
        // Skip delivery if already acknowledged
        if (this.isDeliverySuppressed(jobId)) {
            return;
        }
        const job = this.#jobs.get(jobId);
        this.#queueDelivery({
            jobId,
            text,
            attempt: 0,
            nextAttemptAt: Date.now(),
            ownerId: job?.ownerId,
            jobSnapshot: job
                ? {
                    type: job.type,
                    status: job.status,
                    startTime: job.startTime,
                    endTime: job.endTime,
                    label: job.label,
                    structured: job.structured,
                    agentId: job.agentId,
                    latestDetails: job.latestDetails,
                }
                : undefined,
        });
        this.#ensureDeliveryLoop();
    }
    #ensureDeliveryLoop() {
        if (this.#deliveryLoop) {
            return;
        }
        this.#deliveryLoop = this.#runDeliveryLoop()
            .catch(error => {
            logger.error("Async job delivery loop crashed", { error: String(error) });
        })
            .finally(() => {
            this.#deliveryLoop = undefined;
            if (this.#deliveries.length > 0) {
                this.#ensureDeliveryLoop();
            }
        });
    }
    async #runDeliveryLoop() {
        while (this.#deliveries.length > 0) {
            const delivery = this.#deliveries[0];
            if (this.isDeliverySuppressed(delivery.jobId)) {
                this.#deliveries.shift();
                continue;
            }
            const waitMs = delivery.nextAttemptAt - Date.now();
            if (waitMs > 0) {
                await this.#waitForDeliveryQueueChange(waitMs);
                continue;
            }
            if (this.#deliveries[0] !== delivery) {
                continue;
            }
            if (this.isDeliverySuppressed(delivery.jobId)) {
                this.#deliveries.shift();
                continue;
            }
            this.#deliveries.shift();
            void this.#deliverDelivery(delivery);
        }
    }
    /**
     * Resolve the sink for one delivery attempt: owned deliveries route ONLY to
     * their owner's registered sink (a missing sink dead-letters — never the
     * default, which would misroute a dead owner's result into another
     * session); unowned deliveries use the constructor default. Resolved per
     * attempt so a sink registered between retries (e.g. a revived session)
     * picks up the retry.
     */
    #resolveDeliverySink(ownerId) {
        if (ownerId !== undefined)
            return this.#deliverySinks.get(ownerId);
        return this.#onJobComplete;
    }
    #deliverDelivery(delivery) {
        const sink = this.#resolveDeliverySink(delivery.ownerId);
        if (!sink) {
            // Dead-letter: owned delivery with no live sink (session disposed or
            // parked), or unowned delivery with no default sink. Drop it — the
            // job row keeps its result/error text until retention eviction, so
            // the outcome stays inspectable via job queries and agent:// reads.
            logger.warn("Async job delivery dead-lettered: no delivery sink", {
                jobId: delivery.jobId,
                ownerId: delivery.ownerId,
            });
            delivery.promise = Promise.resolve();
            return delivery.promise;
        }
        const promise = (async () => {
            this.#inFlightDeliveries.push(delivery);
            let delivered = false;
            try {
                await sink(delivery.jobId, delivery.text, this.#jobs.get(delivery.jobId) ?? this.#reconstructEvictedJob(delivery));
                delivered = true;
                // A foreground snapshot may have consumed this result while the
                // sink receipt was parked. The receipt has now settled, so the
                // suppression tombstone no longer needs the full retention window.
                if (this.#consumedJobResults.has(delivery.jobId) && this.#jobs.has(delivery.jobId)) {
                    this.#scheduleEviction(delivery.jobId, this.#consumedResultEvictionMs);
                }
            }
            catch (error) {
                delivery.attempt += 1;
                delivery.lastError = error instanceof Error ? error.message : String(error);
                delivery.nextAttemptAt = Date.now() + this.#getRetryDelay(delivery.attempt);
                if (!this.isDeliverySuppressed(delivery.jobId) && this.#jobs.has(delivery.jobId)) {
                    this.#queueDelivery(delivery);
                }
                logger.warn("Async job completion delivery failed", {
                    jobId: delivery.jobId,
                    attempt: delivery.attempt,
                    nextRetryAt: delivery.nextAttemptAt,
                    error: delivery.lastError,
                });
            }
            finally {
                const index = this.#inFlightDeliveries.indexOf(delivery);
                if (index !== -1)
                    this.#inFlightDeliveries.splice(index, 1);
                if (this.#deliveries.length > 0)
                    this.#ensureDeliveryLoop();
            }
            // A normally delivered result is consumed only after the attempt left
            // #inFlightDeliveries, so it can arm the short eviction grace.
            if (delivered && !this.#consumedJobResults.has(delivery.jobId)) {
                this.#consumeJobResult(delivery.jobId);
            }
        })();
        delivery.promise = promise;
        return promise;
    }
    /**
     * Rebuild a minimal {@link AsyncJob} from a delivery's enqueue-time
     * snapshot when the live job row was already evicted by the time this
     * delivery attempt runs (retention elapsed while delivery kept retrying).
     * Lets the sink still render `type`/`label`/`structured` instead of
     * silently losing them, matching what `job.resultText` would have carried
     * had the row survived.
     */
    #reconstructEvictedJob(delivery) {
        const snapshot = delivery.jobSnapshot;
        if (!snapshot)
            return undefined;
        return {
            id: delivery.jobId,
            type: snapshot.type,
            status: snapshot.status,
            startTime: snapshot.startTime,
            endTime: snapshot.endTime,
            label: snapshot.label,
            abortController: new AbortController(),
            promise: Promise.resolve(),
            resultText: delivery.text,
            structured: snapshot.structured,
            agentId: snapshot.agentId,
            latestDetails: snapshot.latestDetails,
        };
    }
    #queueDelivery(delivery) {
        const index = this.#deliveries.findIndex(candidate => candidate.nextAttemptAt > delivery.nextAttemptAt);
        if (index === -1)
            this.#deliveries.push(delivery);
        else
            this.#deliveries.splice(index, 0, delivery);
        this.#notifyDeliveryQueueChanged();
    }
    async #waitForDeliveryQueueChange(delayMs) {
        const timerElapsed = Promise.withResolvers();
        const timer = setTimeout(timerElapsed.resolve, delayMs);
        timer.unref();
        try {
            await Promise.race([timerElapsed.promise, this.#deliveryQueueChanged.promise]);
        }
        finally {
            clearTimeout(timer);
        }
    }
    #notifyDeliveryQueueChanged() {
        this.#deliveryQueueChanged.resolve();
        this.#deliveryQueueChanged = Promise.withResolvers();
    }
    async #waitForDeliveryPromise(promise, deadline) {
        if (!promise)
            return true;
        if (deadline === Number.POSITIVE_INFINITY) {
            await promise;
            return true;
        }
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0)
            return false;
        let timedOut = false;
        await Promise.race([
            promise,
            Bun.sleep(remainingMs).then(() => {
                timedOut = true;
            }),
        ]);
        return !timedOut;
    }
    #getRetryDelay(attempt) {
        const exp = Math.min(Math.max(attempt - 1, 0), 8);
        const backoffMs = DELIVERY_RETRY_BASE_MS * 2 ** exp;
        const jitterMs = Math.floor(Math.random() * DELIVERY_RETRY_JITTER_MS);
        return Math.min(DELIVERY_RETRY_MAX_MS, backoffMs + jitterMs);
    }
}
