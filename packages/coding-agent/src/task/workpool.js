import { isRecord, logger, prompt } from "@rva/utils";
import workpoolBatchTemplate from "../prompts/tools/workpool-batch.md" with { type: "text" };
import workpoolTurnResultTemplate from "../prompts/tools/workpool-turn-result.md" with { type: "text" };
import { AgentRegistry, MAIN_AGENT_ID } from "../registry/agent-registry";
import { AgentLifecycleManager } from "../registry/agent-lifecycle";
import { isIrcEnabled } from "../irc/messaging";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { isCompletionProbeEnabled } from "./completion-probe";
import { runSubagentFollowUpTurn } from "./executor";
import { reserveStructuredSubagentId, runStructuredSubagent, } from "./structured-subagent";
import { oneLineLabel } from "@rva/tui/tools/task";
import { buildWorkPoolOutputSchema } from "./workpool-yield";
import { cfgEvalWorkpoolFreshAgents } from "../eval/settings";
import { cfgTaskMaxConcurrency, cfgTaskMaxRuntimeMs } from "./settings";
const DELIVERY_OUTPUT_LIMIT = 6000;
/** Dispatches queued items across keep-alive subagents under one aggregate job. */
export class WorkPool {
    name;
    ownerId;
    session;
    policy;
    context;
    customTools;
    freshAgents;
    agents = [];
    items = [];
    batches = [];
    closed = false;
    rrCursor = 0;
    #nextSeq = 1;
    #nextAgentIndex = 1;
    #lastCardTs = 0;
    #dispatchChain = Promise.resolve();
    #poolJobStarted = false;
    #drainWaiters = [];
    #freshQueue = [];
    constructor(session, options) {
        this.name = options.name;
        this.ownerId = session.getAgentId?.() ?? MAIN_AGENT_ID;
        this.session = session;
        this.policy = options.policy;
        this.context = options.context;
        this.customTools = options.customTools ?? [];
        this.freshAgents = cfgEvalWorkpoolFreshAgents.get(session.settings);
        if (!session.asyncJobManager) {
            throw new ToolError("workpool() needs the session's async job manager; unavailable here");
        }
        if (session.asyncJobManager.getJob(this.name)) {
            throw new ToolError(`workpool job id "${this.name}" already exists`);
        }
    }
    /** Current worker ceiling from the live `task.maxConcurrency` setting. */
    limit() {
        const configured = cfgTaskMaxConcurrency.get(this.session.settings);
        return configured > 0 ? configured : Infinity;
    }
    /** Queue items and start the aggregate pool job on the first non-empty push. */
    push(texts) {
        if (this.closed)
            throw new ToolError(`workpool ${this.name} is closed`);
        if (texts.length === 0)
            return [];
        const queued = [];
        for (const text of texts) {
            const seq = this.#nextSeq++;
            const item = { id: `${this.name}#${seq}`, seq, text, status: "queued" };
            this.items.push(item);
            queued.push(item);
        }
        this.#ensurePoolJob();
        for (const item of queued)
            this.#queueDispatch(item);
        return queued.map(item => item.id);
    }
    #ensurePoolJob() {
        if (this.#poolJobStarted)
            return;
        const manager = this.session.asyncJobManager;
        if (!manager)
            throw new ToolError("workpool() needs the session's async job manager; unavailable here");
        if (manager.getJob(this.name))
            throw new ToolError(`workpool job id "${this.name}" already exists`);
        this.#poolJobStarted = true;
        const id = manager.register("task", this.name, async ({ signal }) => {
            const onAbort = () => {
                this.close();
                for (const batch of this.batches)
                    manager.cancel(batch.jobId, { ownerId: this.ownerId });
            };
            if (signal.aborted)
                onAbort();
            else
                signal.addEventListener("abort", onAbort, { once: true });
            try {
                await this.#waitForDrain();
                const batchIds = this.batches.map(batch => batch.jobId);
                await Promise.allSettled(batchIds.flatMap(batchId => {
                    const job = manager.getJob(batchId);
                    return job ? [job.promise] : [];
                }));
                manager.consumeJobResults(batchIds);
                manager.unwatchJobs(batchIds);
                this.closed = true;
                const summary = `Pool \`${this.name}\` drained: ${this.items.length} item(s), ${this.batches.length} batch(es).`;
                this.#card(signal.aborted ? "cancelled" : "completed", this.ownerId, summary);
                return this.#renderAggregateResult();
            }
            finally {
                signal.removeEventListener("abort", onAbort);
            }
        }, { id: this.name, ownerId: this.ownerId, queued: true });
        if (id !== this.name) {
            manager.cancel(id, { ownerId: this.ownerId });
            throw new ToolError(`workpool job id "${this.name}" is unavailable`);
        }
    }
    async #waitForDrain() {
        if (this.#isDrained())
            return;
        const waiter = Promise.withResolvers();
        this.#drainWaiters.push(waiter);
        await waiter.promise;
    }
    #isDrained() {
        return !this.items.some(item => item.status === "queued" || item.status === "running");
    }
    #notifyDrained() {
        if (!this.#isDrained())
            return;
        for (const waiter of this.#drainWaiters.splice(0))
            waiter.resolve();
    }
    #queueDispatch(item) {
        this.#dispatchChain = this.#dispatchChain
            .then(() => this.#dispatch(item))
            .catch(error => {
            if (item.status === "queued")
                item.status = "failed";
            logger.warn("workpool: item dispatch failed", {
                pool: this.name,
                item: item.id,
                error: error instanceof Error ? error.message : String(error),
            });
            this.#notifyDrained();
        });
    }
    #contextLoad(agent) {
        const tokens = agent.contextTokens ?? 0;
        const window = agent.contextWindow;
        return window !== undefined && window > 0 ? tokens / window : tokens;
    }
    #leastLoadedIdle() {
        let selected;
        let selectedLoad = Infinity;
        for (const agent of this.agents) {
            if (agent.state !== "idle")
                continue;
            const load = this.#contextLoad(agent);
            if (load >= selectedLoad)
                continue;
            selected = agent;
            selectedLoad = load;
        }
        return selected;
    }
    async #dispatch(item) {
        if (this.closed || item.status !== "queued")
            return;
        if (this.freshAgents) {
            if (this.agents.length < this.limit()) {
                await this.#spawn(item);
            }
            else {
                this.#freshQueue.push(item);
                this.#card("queued", this.name, `[${item.id}] ${item.text}`);
            }
            return;
        }
        const idle = this.#leastLoadedIdle();
        if (idle) {
            item.agentId = idle.id;
            idle.queue.push(item);
            this.#card("dispatched", idle.id, `[${item.id}] ${item.text}`);
            this.#drain(idle);
            return;
        }
        if (this.agents.length < this.limit()) {
            await this.#spawn(item);
            return;
        }
        const busy = this.#nextBusy();
        if (!busy) {
            await this.#spawn(item);
            return;
        }
        item.agentId = busy.id;
        busy.queue.push(item);
        this.#card("queued", busy.id, `[${item.id}] ${item.text}`);
    }
    async #spawn(item) {
        const index = this.#nextAgentIndex++;
        const id = await reserveStructuredSubagentId(this.session, { label: `${this.name}-${index}` });
        if (this.closed || item.status !== "queued")
            return;
        const agent = { id, index, state: "running", queue: [item], turns: 0 };
        item.agentId = id;
        this.agents.push(agent);
        this.#card("spawned", id, `[${item.id}] ${item.text}`);
        this.#drain(agent);
    }
    #nextBusy() {
        if (this.agents.length === 0)
            return undefined;
        for (let offset = 0; offset < this.agents.length; offset++) {
            const index = (this.rrCursor + offset) % this.agents.length;
            const agent = this.agents[index];
            if (agent?.state === "running") {
                this.rrCursor = (index + 1) % this.agents.length;
                return agent;
            }
        }
        return undefined;
    }
    #drain(agent) {
        if (agent.queue.length === 0) {
            agent.state = "idle";
            this.#notifyDrained();
            return;
        }
        const items = agent.queue.splice(0);
        const id = `${agent.id}-b${agent.turns + 1}`;
        const batch = {
            id,
            agentId: agent.id,
            items,
            jobId: id,
            startedAt: Date.now(),
            status: "running",
        };
        for (const item of items) {
            item.status = "running";
            item.agentId = agent.id;
            item.batchId = batch.id;
        }
        agent.state = "running";
        agent.jobId = batch.jobId;
        this.batches.push(batch);
        const message = this.#batchMessage(batch);
        if (agent.turns > 0)
            this.#card("batch", agent.id, message);
        this.#startTurn(agent, batch, message);
    }
    #batchMessage(batch) {
        return prompt.render(workpoolBatchTemplate, {
            pool: this.name,
            batch: batch.id,
            items: batch.items.map((item, index) => ({ id: item.id, index: index + 1, text: item.text })),
        });
    }
    #startTurn(agent, batch, message) {
        const manager = this.session.asyncJobManager;
        if (!manager)
            throw new ToolError("workpool() needs the session's async job manager; unavailable here");
        const workPoolYieldItems = batch.items.map((item, index) => ({
            id: item.id,
            index: index + 1,
        }));
        const outputSchema = buildWorkPoolOutputSchema(workPoolYieldItems);
        const jobId = manager.register("task", batch.id, async ({ signal, reportProgress, markRunning }) => {
            markRunning();
            const onProgress = (progress) => {
                if (progress.contextTokens !== undefined)
                    agent.contextTokens = progress.contextTokens;
                if (progress.contextWindow !== undefined)
                    agent.contextWindow = progress.contextWindow;
                const details = {
                    projectAgentsDir: null,
                    results: [],
                    totalDurationMs: Date.now() - batch.startedAt,
                    progress: [progress],
                };
                void reportProgress(`Running agent ${agent.id}...`, { ...details });
            };
            let result;
            try {
                if (agent.turns === 0) {
                    const execution = await runStructuredSubagent({
                        session: this.session,
                        invocationKind: "eval",
                        assignment: message,
                        ...(this.context ? { context: this.context } : {}),
                        agent: this.policy.agentName,
                        identity: { id: agent.id },
                        customTools: this.customTools,
                        outputSchema,
                        schemaMode: "strict",
                        workPoolYieldItems,
                        keepAlive: true,
                        retainArtifacts: true,
                        enableIrc: isIrcEnabled(this.session.settings, this.session.taskDepth ?? 0),
                        signal,
                        onProgress,
                    });
                    result = execution.result;
                }
                else {
                    result = await runSubagentFollowUpTurn({
                        id: agent.id,
                        agent: this.policy.agent,
                        message,
                        outputSchema,
                        outputSchemaMode: "strict",
                        outputSchemaSource: "caller",
                        workPoolYieldItems,
                        signal,
                        onProgress,
                        eventBus: this.session.eventBus,
                        subagentEventBus: this.session.subagentEventBus,
                        artifactsDir: this.session.getSessionFile()?.slice(0, -6),
                        maxRuntimeMs: cfgTaskMaxRuntimeMs.get(this.session.settings),
                        completionProbe: isCompletionProbeEnabled(this.session.settings, this.session.taskDepth ?? 0),
                    });
                }
            }
            catch (error) {
                const output = error instanceof Error ? error.message : String(error);
                return this.#settleTurn(agent, batch, { exitCode: 1, output, error: output });
            }
            return this.#settleTurn(agent, batch, result);
        }, { id: batch.id, agentId: agent.id, ownerId: this.ownerId });
        batch.jobId = jobId;
        agent.jobId = jobId;
        manager.watchJobs([jobId]);
    }
    async #settleTurn(agent, batch, result) {
        await this.#finishTurn(agent, batch, result);
        const delivery = this.#renderTurnResult(agent, batch, result);
        if (batch.status !== "completed")
            throw new Error(delivery);
        return delivery;
    }
    async #finishTurn(agent, batch, result) {
        batch.status = result.aborted ? "cancelled" : result.exitCode !== 0 || result.error ? "failed" : "completed";
        batch.output = result.output;
        const failedItems = new Set();
        for (const yielded of result.extractedToolData?.yield ?? []) {
            if (!isRecord(yielded) || yielded.status !== "success" || typeof yielded.error !== "string")
                continue;
            if (Array.isArray(yielded.type) && yielded.type.length === 1 && typeof yielded.type[0] === "string") {
                failedItems.add(yielded.type[0]);
            }
        }
        for (const item of batch.items)
            item.status = batch.status === "completed" && failedItems.has(item.id) ? "failed" : batch.status;
        agent.turns++;
        agent.jobId = undefined;
        const ref = AgentRegistry.global().get(agent.id);
        // Retained idle workers can wake through IRC, so clear the runtime schema and cached inline declaration together.
        // A refresh failure must not strand the pool in #waitForDrain(): items are
        // already terminal, so keep the turn result, drop the worker instead of
        // reusing it with a stale keyed declaration, and still notify drain.
        let yieldCleared = true;
        try {
            await ref?.session?.setWorkPoolYieldItems([]);
        }
        catch (error) {
            yieldCleared = false;
            logger.warn("workpool: failed to clear yield contract", {
                pool: this.name,
                agent: agent.id,
                batch: batch.id,
                error: error instanceof Error ? error.message : String(error),
            });
            // The runtime already flipped to the ordinary schema while the prompt
            // still advertises the keyed one. The worker must not survive as a
            // messageable session: release the lifecycle adoption (guarded by the
            // registry ref so a newer same-id ref is never taken down) so neither
            // pool reuse nor an IRC wake can reach the inconsistent contract. The
            // tombstone keeps the ref terminal so a later persisted-agent scan
            // cannot resurrect the transcript as parked with a stale pooled
            // declaration and an empty runtime set.
            if (ref) {
                try {
                    await AgentLifecycleManager.global().release(agent.id, ref, { tombstone: true });
                }
                catch (releaseError) {
                    logger.warn("workpool: failed to release worker after yield clear failure", {
                        pool: this.name,
                        agent: agent.id,
                        batch: batch.id,
                        error: releaseError instanceof Error ? releaseError.message : String(releaseError),
                    });
                }
            }
        }
        if (this.freshAgents) {
            agent.state = "dead";
            const index = this.agents.indexOf(agent);
            if (index !== -1)
                this.agents.splice(index, 1);
            const next = this.#freshQueue.shift();
            if (next)
                this.#queueDispatch(next);
            this.#notifyDrained();
            return;
        }
        if (yieldCleared && ref && (ref.status === "idle" || ref.status === "parked")) {
            this.#drain(agent);
        }
        else {
            agent.state = "dead";
            const stranded = agent.queue.splice(0);
            const index = this.agents.indexOf(agent);
            if (index !== -1)
                this.agents.splice(index, 1);
            for (const item of stranded) {
                item.agentId = undefined;
                item.batchId = undefined;
                this.#queueDispatch(item);
            }
        }
        this.#notifyDrained();
    }
    #renderAggregateResult() {
        const lines = [
            `Pool \`${this.name}\` completed (${this.items.length} item(s), ${this.batches.length} batch(es)).`,
        ];
        for (const batch of this.batches) {
            lines.push("", `## ${batch.id} · agent \`${batch.agentId}\` · ${batch.status}`);
            for (const item of batch.items) {
                lines.push(`- [${item.id}] ${item.status} — ${oneLineLabel(item.text)}`);
            }
            const output = batch.output?.trim();
            if (output)
                lines.push("", output);
            lines.push(`Transcript: history://${batch.agentId} · full output: agent://${batch.agentId}`);
        }
        lines.push("", "Pool queue drained.");
        return lines.join("\n");
    }
    #renderTurnResult(agent, batch, result) {
        const remaining = this.items.filter(item => item.status === "queued" || item.status === "running").length;
        const output = result.output.trim() || result.error || result.abortReason || "(no output)";
        const renderedOutput = output.length <= DELIVERY_OUTPUT_LIMIT
            ? output
            : `${output.slice(0, DELIVERY_OUTPUT_LIMIT)}\n[output truncated to ${DELIVERY_OUTPUT_LIMIT} characters]`;
        return prompt.render(workpoolTurnResultTemplate, {
            pool: this.name,
            agent: agent.id,
            batch: batch.id,
            status: batch.status,
            count: batch.items.length,
            multiple: batch.items.length !== 1,
            items: batch.items.map(item => ({ id: item.id, status: item.status, text: oneLineLabel(item.text) })),
            output: renderedOutput,
            remaining,
        });
    }
    /** Return current workers, item counts, and context usage. */
    status() {
        const counts = { queued: 0, running: 0, completed: 0, failed: 0, cancelled: 0 };
        for (const item of this.items)
            counts[item.status]++;
        return {
            name: this.name,
            agent: this.policy.agentName,
            limit: this.limit(),
            closed: this.closed,
            freshAgents: this.freshAgents,
            agents: this.agents.map(agent => ({
                id: agent.id,
                state: agent.state,
                queued: agent.queue.length,
                turns: agent.turns,
                ...(agent.contextTokens !== undefined ? { contextTokens: agent.contextTokens } : {}),
                ...(agent.contextWindow !== undefined ? { contextWindow: agent.contextWindow } : {}),
                ...(agent.jobId ? { current: agent.jobId } : {}),
            })),
            items: counts,
            batches: this.batches.length,
        };
    }
    /** Return batch results without consuming the aggregate job delivery. */
    peek() {
        return {
            batches: this.batches.map(batch => ({
                id: batch.id,
                agent: batch.agentId,
                items: batch.items.map(item => item.id),
                status: batch.status,
                ...(batch.output !== undefined ? { output: batch.output } : {}),
            })),
            pending: this.items.filter(item => item.status === "queued" || item.status === "running").length,
        };
    }
    /** Stop accepting work and cancel items not yet assigned to a turn. */
    close() {
        this.closed = true;
        const dropped = [];
        for (const item of this.items) {
            if (item.status !== "queued")
                continue;
            item.status = "cancelled";
            dropped.push(item.id);
        }
        for (const agent of this.agents)
            agent.queue.splice(0);
        this.#freshQueue.splice(0);
        this.#notifyDrained();
        return { dropped };
    }
    #card(mode, agentId, body) {
        const timestamp = Math.max(Date.now(), this.#lastCardTs + 1);
        this.#lastCardTs = timestamp;
        const record = {
            role: "custom",
            customType: "irc:workpool",
            content: `[pool ${this.name} → ${agentId}]\n\n${body}`,
            display: true,
            details: { pool: this.name, from: `pool:${this.name}`, to: agentId, body, mode },
            attribution: "agent",
            timestamp,
        };
        try {
            AgentRegistry.global().get(this.ownerId)?.session?.emitIrcRelayObservation(record);
        }
        catch (error) {
            logger.debug("workpool: card emission failed", {
                pool: this.name,
                agent: agentId,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
}
/** Process-local workpool registry scoped by owner id and pool name. */
export class WorkPoolRegistry {
    static #instance;
    /** Return the process-global workpool registry. */
    static global() {
        WorkPoolRegistry.#instance ??= new WorkPoolRegistry();
        return WorkPoolRegistry.#instance;
    }
    /** Replace the global registry with an empty instance for tests. */
    static resetForTests() {
        WorkPoolRegistry.#instance = new WorkPoolRegistry();
    }
    #pools = new Map();
    #key(ownerId, name) {
        return `${ownerId}\0${name}`;
    }
    /** Create a uniquely named pool for the session owner. */
    create(session, options) {
        const ownerId = session.getAgentId?.() ?? MAIN_AGENT_ID;
        const key = this.#key(ownerId, options.name);
        if (this.#pools.has(key))
            throw new ToolError(`workpool "${options.name}" already exists`);
        const pool = new WorkPool(session, options);
        this.#pools.set(key, pool);
        return pool;
    }
    /** Find one pool without creating it. */
    get(ownerId, name) {
        return this.#pools.get(this.#key(ownerId, name));
    }
    /** Close and forget every pool owned by an ending session. */
    releaseOwner(ownerId) {
        for (const [key, pool] of this.#pools) {
            if (pool.ownerId !== ownerId)
                continue;
            pool.close();
            this.#pools.delete(key);
        }
    }
}
