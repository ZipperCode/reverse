import { escapeXmlText, prompt, Snowflake } from "@rva/utils";
import goalBudgetLimitPrompt from "../prompts/goals/goal-budget-limit.md" with { type: "text" };
import goalContinuationPrompt from "../prompts/goals/goal-continuation.md" with { type: "text" };
import goalModeActivePrompt from "../prompts/goals/goal-mode-active.md" with { type: "text" };
function cloneGoal(goal) {
    return { ...goal };
}
function cloneState(state) {
    return { ...state, goal: cloneGoal(state.goal) };
}
function budgetValue(goal) {
    return goal.tokenBudget === undefined ? "none" : String(goal.tokenBudget);
}
function remainingValue(goal) {
    return goal.tokenBudget === undefined ? "unbounded" : String(Math.max(0, goal.tokenBudget - goal.tokensUsed));
}
export function remainingTokens(goal) {
    if (!goal || goal.tokenBudget === undefined)
        return null;
    return Math.max(0, goal.tokenBudget - goal.tokensUsed);
}
export function renderTrustedObjective(objective) {
    return `<objective>\n${escapeXmlText(objective)}\n</objective>`;
}
export function goalTokenDelta(current, baseline) {
    // Diverges from codex-rs: codex omits cache creation because its target providers
    // do not bill cache writes distinctly through the token-usage stream. Pi receives
    // cacheWrite separately on Anthropic/Bedrock; rotating a 1h ephemeral cache or
    // re-anchoring a changed system prompt can write 100K+ tokens, which the goal
    // budget must account for. cacheRead is excluded because it is reused prefix,
    // not new work consumed by the goal.
    return (Math.max(0, current.input - baseline.input) +
        Math.max(0, current.cacheWrite - baseline.cacheWrite) +
        Math.max(0, current.output - baseline.output));
}
export function renderGoalPrompt(kind, goal) {
    const template = kind === "active"
        ? goalModeActivePrompt
        : kind === "continuation"
            ? goalContinuationPrompt
            : goalBudgetLimitPrompt;
    return prompt.render(template, {
        objective: escapeXmlText(goal.objective),
        tokensUsed: String(goal.tokensUsed),
        tokenBudget: budgetValue(goal),
        remainingTokens: remainingValue(goal),
        timeUsedSeconds: String(goal.timeUsedSeconds),
    });
}
export function completionBudgetReport(goal) {
    const parts = [];
    if (goal.tokenBudget !== undefined) {
        parts.push(`tokens used: ${goal.tokensUsed} of ${goal.tokenBudget}`);
    }
    if (goal.timeUsedSeconds > 0) {
        parts.push(`time used: ${goal.timeUsedSeconds} seconds`);
    }
    if (parts.length === 0)
        return null;
    return `Goal achieved. Report final budget usage to the user: ${parts.join("; ")}.`;
}
function validateTokenBudget(tokenBudget) {
    if (tokenBudget !== undefined && (!Number.isInteger(tokenBudget) || tokenBudget <= 0)) {
        throw new Error("goal token_budget must be a positive integer when provided");
    }
}
function isAccountingStatus(goal) {
    return goal.status === "active" || goal.status === "budget-limited";
}
export class GoalRuntime {
    #host;
    #turnSnapshot;
    #wallClock;
    #budgetReportedFor;
    #accountingTail = Promise.resolve();
    constructor(host) {
        this.#host = host;
        this.#wallClock = { lastAccountedAt: this.#now() };
    }
    get snapshot() {
        return {
            turnSnapshot: this.#turnSnapshot
                ? { ...this.#turnSnapshot, baselineUsage: { ...this.#turnSnapshot.baselineUsage } }
                : undefined,
            wallClock: { ...this.#wallClock },
            budgetReportedFor: this.#budgetReportedFor,
        };
    }
    #now() {
        return this.#host.now?.() ?? Date.now();
    }
    #hasAccountingState() {
        const state = this.#host.getState();
        return Boolean(state?.enabled && isAccountingStatus(state.goal));
    }
    async #withAccounting(fn) {
        const previous = this.#accountingTail;
        const { promise, resolve } = Promise.withResolvers();
        this.#accountingTail = previous.then(() => promise, () => promise);
        await previous.catch(() => { });
        try {
            return await fn();
        }
        finally {
            resolve();
        }
    }
    #getStateClone() {
        const state = this.#host.getState();
        return state ? cloneState(state) : undefined;
    }
    async #commitState(state, options) {
        this.#host.setState(state ? cloneState(state) : undefined);
        if (options?.persist) {
            this.#host.persist(options.persist, state);
        }
        if (options?.emit !== false) {
            await this.#host.emit({ type: "goal_updated", goal: state ? cloneGoal(state.goal) : null, state });
        }
    }
    #markActiveAccounting(goal, resetWallClock = false) {
        if (resetWallClock || this.#wallClock.activeGoalId !== goal.id) {
            this.#wallClock = { lastAccountedAt: this.#now(), activeGoalId: goal.id };
        }
        if (this.#turnSnapshot) {
            this.#turnSnapshot.activeGoalId = goal.id;
            this.#turnSnapshot.baselineUsage = { ...this.#host.getCurrentUsage() };
        }
    }
    #clearActiveAccounting() {
        this.#wallClock = { lastAccountedAt: this.#now() };
        if (this.#turnSnapshot) {
            this.#turnSnapshot.activeGoalId = undefined;
        }
    }
    clearAccounting() {
        this.#turnSnapshot = undefined;
        this.#clearActiveAccounting();
        this.#budgetReportedFor = undefined;
    }
    onTurnStart(turnId, baselineUsage) {
        this.#turnSnapshot = { turnId, baselineUsage: { ...baselineUsage } };
        const state = this.#host.getState();
        if (state?.enabled && isAccountingStatus(state.goal)) {
            this.#turnSnapshot.activeGoalId = state.goal.id;
            if (this.#wallClock.activeGoalId !== state.goal.id) {
                this.#wallClock = { lastAccountedAt: this.#now(), activeGoalId: state.goal.id };
            }
        }
    }
    async onToolCompleted(toolName) {
        if (toolName === "goal")
            return;
        if (!this.#hasAccountingState())
            return;
        await this.flushUsage("allowed");
    }
    async onGoalToolCompleted() {
        if (!this.#hasAccountingState())
            return;
        await this.flushUsage("suppressed");
    }
    /**
     * `currentUsage` may be a thunk: it is read synchronously (before any await)
     * only when goal accounting is active, so idle sessions skip the usage walk.
     */
    async onAgentEnd(options) {
        if (!this.#hasAccountingState()) {
            this.#turnSnapshot = undefined;
            return;
        }
        const currentUsage = options?.currentUsage;
        await this.flushUsage("suppressed", typeof currentUsage === "function" ? currentUsage() : currentUsage);
        this.#turnSnapshot = undefined;
    }
    async onTaskAborted(options) {
        const state = this.#host.getState();
        const needsAccounting = state?.enabled && isAccountingStatus(state.goal);
        const needsPause = options?.reason === "interrupted" && state?.enabled && state.goal.status === "active";
        if (!needsAccounting && !needsPause) {
            this.#turnSnapshot = undefined;
            return;
        }
        await this.#withAccounting(async () => {
            await this.#flushUsageLocked("suppressed", undefined, options?.reason === "internal");
            this.#turnSnapshot = undefined;
            if (options?.reason !== "interrupted")
                return;
            const cloned = this.#getStateClone();
            if (!cloned?.enabled || cloned.goal.status !== "active")
                return;
            cloned.enabled = false;
            cloned.goal.status = "paused";
            cloned.goal.updatedAt = this.#now();
            this.#clearActiveAccounting();
            this.#budgetReportedFor = undefined;
            await this.#commitState(cloned, { persist: "goal_paused" });
        });
    }
    async onThreadResumed(options) {
        const state = this.#getStateClone();
        if (!state)
            return undefined;
        if (options?.preserveActiveGoal && state.enabled && state.goal.status === "active") {
            this.#markActiveAccounting(state.goal, true);
            await this.#commitState(state, { emit: true });
            return state;
        }
        if (state.goal.status === "active") {
            state.enabled = false;
            state.goal.status = "paused";
            state.goal.updatedAt = this.#now();
            this.#clearActiveAccounting();
            this.#budgetReportedFor = undefined;
            await this.#commitState(state, { persist: "goal_paused" });
            return state;
        }
        if (state.enabled && isAccountingStatus(state.goal)) {
            this.#markActiveAccounting(state.goal);
        }
        else {
            this.#clearActiveAccounting();
        }
        await this.#commitState(state, { emit: true });
        return state;
    }
    async onBudgetMutated(newBudget) {
        validateTokenBudget(newBudget);
        return await this.#withAccounting(async () => {
            this.#budgetReportedFor = undefined;
            await this.#flushUsageLocked("suppressed");
            const state = this.#getStateClone();
            if (!state?.goal)
                return undefined;
            state.goal.tokenBudget = newBudget;
            state.goal.updatedAt = this.#now();
            let shouldSteer = false;
            if (newBudget !== undefined && state.goal.tokensUsed >= newBudget) {
                if (state.goal.status === "active") {
                    state.goal.status = "budget-limited";
                    shouldSteer = true;
                }
            }
            else if (state.goal.status === "budget-limited") {
                state.goal.status = "active";
                state.enabled = true;
                this.#markActiveAccounting(state.goal);
            }
            await this.#commitState(state, { persist: state.enabled ? "goal" : "goal_paused" });
            if (shouldSteer) {
                await this.#sendBudgetLimitSteer(state.goal);
            }
            return state;
        });
    }
    /** `currentUsage` defaults to the host's live totals, read only once a token delta is needed. */
    async #flushUsageLocked(steering, currentUsage, persistWallClock = false) {
        const state = this.#getStateClone();
        if (!state?.enabled || !isAccountingStatus(state.goal))
            return;
        if (this.#turnSnapshot?.activeGoalId !== state.goal.id && this.#wallClock.activeGoalId !== state.goal.id)
            return;
        let usage;
        let tokenDelta = 0;
        if (this.#turnSnapshot?.activeGoalId === state.goal.id) {
            usage = currentUsage ?? this.#host.getCurrentUsage();
            tokenDelta = goalTokenDelta(usage, this.#turnSnapshot.baselineUsage);
        }
        const wallSeconds = this.#wallClock.activeGoalId === state.goal.id
            ? Math.max(0, Math.floor((this.#now() - this.#wallClock.lastAccountedAt) / 1000))
            : 0;
        if (tokenDelta <= 0 && wallSeconds <= 0)
            return;
        state.goal.tokensUsed += tokenDelta;
        state.goal.timeUsedSeconds += wallSeconds;
        state.goal.updatedAt = this.#now();
        const flippedToBudgetLimited = state.goal.tokenBudget !== undefined &&
            state.goal.tokensUsed >= state.goal.tokenBudget &&
            state.goal.status === "active";
        if (flippedToBudgetLimited) {
            state.goal.status = "budget-limited";
        }
        if (usage && this.#turnSnapshot?.activeGoalId === state.goal.id) {
            this.#turnSnapshot.baselineUsage = { ...usage };
        }
        if (this.#wallClock.activeGoalId === state.goal.id && wallSeconds > 0) {
            this.#wallClock.lastAccountedAt += wallSeconds * 1000;
        }
        // Persisting wall-clock-only accounting on every tool event bloats /goal sessions with full
        // objective snapshots. Keep normal tool flushes in memory/UI only, but make wall-clock
        // usage durable before internal session switches because the active runtime is leaving.
        const shouldPersistUsage = tokenDelta > 0 || flippedToBudgetLimited || (persistWallClock && wallSeconds > 0);
        await this.#commitState(state, { persist: shouldPersistUsage ? "goal" : undefined });
        if (state.goal.status !== "budget-limited") {
            this.#budgetReportedFor = undefined;
        }
        if (steering === "allowed" && flippedToBudgetLimited && this.#budgetReportedFor !== state.goal.id) {
            await this.#sendBudgetLimitSteer(state.goal);
        }
    }
    async flushUsage(steering, currentUsage) {
        await this.#withAccounting(() => this.#flushUsageLocked(steering, currentUsage));
    }
    #createGoalState(objective, tokenBudget) {
        const now = this.#now();
        const goal = {
            id: String(Snowflake.next()),
            objective,
            status: "active",
            tokenBudget,
            tokensUsed: 0,
            timeUsedSeconds: 0,
            createdAt: now,
            updatedAt: now,
        };
        return { enabled: true, mode: "active", goal };
    }
    async createGoal(input) {
        const objective = input.objective.trim();
        if (!objective)
            throw new Error("objective is required when op=create");
        validateTokenBudget(input.tokenBudget);
        return await this.#withAccounting(async () => {
            const existing = this.#host.getState();
            if (existing?.goal && existing.goal.status !== "dropped" && existing.goal.status !== "complete") {
                throw new Error("cannot create a new goal because this session already has a goal");
            }
            const state = this.#createGoalState(objective, input.tokenBudget);
            this.#budgetReportedFor = undefined;
            this.#markActiveAccounting(state.goal);
            await this.#commitState(state, { persist: "goal" });
            return state;
        });
    }
    async replaceGoal(input) {
        const objective = input.objective.trim();
        if (!objective)
            throw new Error("objective is required when op=replace");
        validateTokenBudget(input.tokenBudget);
        return await this.#withAccounting(async () => {
            const existing = this.#host.getState();
            if (!existing?.enabled || !isAccountingStatus(existing.goal)) {
                throw new Error("cannot replace goal because no goal is active");
            }
            await this.#flushUsageLocked("suppressed");
            const state = this.#createGoalState(objective, input.tokenBudget);
            this.#budgetReportedFor = undefined;
            this.#markActiveAccounting(state.goal);
            await this.#commitState(state, { persist: "goal" });
            return state;
        });
    }
    async resumeGoal() {
        return await this.#withAccounting(async () => {
            const state = this.#getStateClone();
            if (!state?.goal)
                throw new Error("No paused goal.");
            if (state.goal.status === "complete")
                throw new Error("Goal is already complete.");
            state.enabled = true;
            state.mode = "active";
            state.reason = undefined;
            state.goal.status = "active";
            state.goal.updatedAt = this.#now();
            this.#budgetReportedFor = undefined;
            this.#markActiveAccounting(state.goal);
            await this.#commitState(state, { persist: "goal" });
            return state;
        });
    }
    async pauseGoal() {
        return await this.#withAccounting(async () => {
            await this.#flushUsageLocked("suppressed");
            const state = this.#getStateClone();
            if (!state?.goal)
                return undefined;
            state.enabled = false;
            state.mode = "active";
            state.reason = undefined;
            if (state.goal.status === "active" || state.goal.status === "budget-limited") {
                state.goal.status = "paused";
            }
            state.goal.updatedAt = this.#now();
            this.#clearActiveAccounting();
            this.#budgetReportedFor = undefined;
            await this.#commitState(state, { persist: "goal_paused" });
            return state;
        });
    }
    async dropGoal() {
        return await this.#withAccounting(async () => {
            await this.#flushUsageLocked("suppressed");
            const state = this.#getStateClone();
            if (!state?.goal)
                return undefined;
            const dropped = { ...state.goal, status: "dropped", updatedAt: this.#now() };
            this.#clearActiveAccounting();
            this.#budgetReportedFor = undefined;
            await this.#host.emit({
                type: "goal_updated",
                goal: dropped,
                state: { ...state, enabled: false, goal: dropped },
            });
            await this.#commitState(undefined, { persist: "none", emit: false });
            return dropped;
        });
    }
    async completeGoalFromTool() {
        return await this.#withAccounting(async () => {
            await this.#flushUsageLocked("suppressed");
            const state = this.#getStateClone();
            if (!state?.goal) {
                throw new Error("cannot complete goal because no goal is active");
            }
            if (state.goal.status === "complete") {
                throw new Error("goal is already complete");
            }
            if (state.goal.status === "dropped") {
                throw new Error("cannot complete a dropped goal");
            }
            state.enabled = false;
            state.goal.status = "complete";
            state.goal.updatedAt = this.#now();
            state.mode = "exiting";
            state.reason = "completed";
            this.#clearActiveAccounting();
            this.#budgetReportedFor = undefined;
            await this.#commitState(state, { persist: "goal" });
            return state.goal;
        });
    }
    buildActivePrompt() {
        const state = this.#host.getState();
        return state?.enabled && state.goal && state.goal.status === "active"
            ? renderGoalPrompt("active", state.goal)
            : undefined;
    }
    buildContinuationPrompt() {
        const state = this.#host.getState();
        return state?.enabled && state.goal.status === "active"
            ? renderGoalPrompt("continuation", state.goal)
            : undefined;
    }
    async #sendBudgetLimitSteer(goal) {
        if (this.#budgetReportedFor === goal.id)
            return;
        this.#budgetReportedFor = goal.id;
        await this.#host.sendHiddenMessage({
            customType: "goal-budget-limit",
            content: renderGoalPrompt("budget-limit", goal),
            deliverAs: "steer",
        });
    }
}
