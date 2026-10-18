import { logger } from "@rva/utils";
// Server-directed timing is clamped to the same bounds Claude Code applies.
const DEFAULT_RETRY_AFTER_MS = 20000;
const MIN_RETRY_AFTER_MS = 5000;
const MAX_RETRY_AFTER_MS = 600000;
const DEFAULT_MAX_WAIT_MS = 1200000;
const MIN_MAX_WAIT_MS = 60000;
const MAX_MAX_WAIT_MS = 21600000;
/** After giving up on capacity, don't re-offer the lane for this long. */
const MAX_WAIT_COOLOFF_MS = 10 * 60000;
/** The 5-hour reset must move this far past the accepted window to count as a new window. */
const RESET_GRACE_SEC = 60;
/** ±30% jitter keeps concurrent waiters from retrying in lockstep. */
const RETRY_JITTER = 0.3;
/** Upper bound on a budget-exhausted block (8 days) when the reset header is absurd. */
const MAX_BUDGET_BLOCK_SEC = 691200;
/** Resets further out than this show a weekday, not just the time. */
const SAME_DAY_RESET_MS = 20 * 3600000;
/** Local wall-clock `HH:MM` for an epoch-seconds reset, with a weekday when it is not today-ish. */
export function formatSlowModeResetClock(resetsAtSec, now = Date.now()) {
    const at = new Date(resetsAtSec * 1000);
    return resetsAtSec * 1000 - now > SAME_DAY_RESET_MS
        ? at.toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" })
        : at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
/** TUI status-line label for a usage-limit state. */
export function formatUsageLimitLabel(status, now = Date.now()) {
    if (status?.stage === "low_priority") {
        return `low priority until ${formatSlowModeResetClock(status.resetsAtSec, now)}${status.allowanceLeftPercent === undefined ? "" : ` · ${status.allowanceLeftPercent}% left`}`;
    }
    if (!status)
        return undefined;
    if (status.extraUsage)
        return "limit reached · wrap-up, then extra usage";
    return `limit reached · wrapping up${status.resetsAtSec === undefined ? "" : ` · resets ${formatSlowModeResetClock(status.resetsAtSec, now)}`}`;
}
const END_NOTICES = {
    reset: { level: "info", message: "Claude session limit reset — low priority ended." },
    user: undefined,
    weekly: {
        level: "warning",
        message: "Low priority ended: the weekly Claude limit is reached.",
    },
    budget: {
        level: "warning",
        message: "Low priority ended: this week's low-priority allowance is used up.",
    },
    off: { level: "warning", message: "Low priority ended: Anthropic turned it off for this account." },
    ineligible: { level: "warning", message: "Low priority ended: this account is no longer eligible." },
    wall: { level: "warning", message: "Low priority ended: Anthropic stopped serving the slow lane." },
    max_wait: {
        level: "warning",
        message: "Low priority paused for 10 minutes after waiting too long for spare capacity.",
    },
    extra_usage: { level: "info", message: "Low priority ended: extra usage is now serving requests." },
};
/** Slow-mode state machine for one Claude account lane; see the module docs. */
export class AnthropicSlowModeController {
    #phase = { kind: "idle" };
    /** Latest `treatment` offer seen on a session-limit 429, keyed by its reset. */
    #offerResetsAtSec;
    /** Reset of the window the user explicitly stopped; allows `/slow on` to resume it. */
    #stoppedResetsAtSec;
    #coolingOffUntilMs;
    /** Weekly limit or spent allowance: no re-entry until the reported reset. */
    #blocked;
    #budgetUtilization;
    #retryAfterMs = DEFAULT_RETRY_AFTER_MS;
    #maxWaitMs = DEFAULT_MAX_WAIT_MS;
    #wrapUp;
    #wrapUpEpoch = 0;
    /** Whether requests currently carry the slow header. Expires the window once its limit resets. */
    isActive(now = Date.now()) {
        const phase = this.#phase;
        if (phase.kind !== "active")
            return false;
        if (now >= (phase.resetsAtSec + RESET_GRACE_SEC) * 1000) {
            this.stop("reset");
            return false;
        }
        return true;
    }
    /** Reset time (epoch seconds) of the active window, if any. */
    activeResetsAtSec(now = Date.now()) {
        return this.isActive(now) && this.#phase.kind === "active" ? this.#phase.resetsAtSec : undefined;
    }
    /** Percent of the weekly slow-lane allowance still available, when the server reported it. */
    allowanceLeftPercent() {
        const used = this.#budgetUtilization;
        return used === undefined ? undefined : Math.min(100, Math.max(0, 100 - Math.round(used * 100)));
    }
    /** The open wrap-up window, if any. Expires it once its limit resets. */
    #currentWrapUp(now) {
        const wrapUp = this.#wrapUp;
        if (wrapUp?.resetsAtSec !== undefined && now >= wrapUp.resetsAtSec * 1000)
            this.#wrapUp = undefined;
        return this.#wrapUp;
    }
    /** Whether the low-priority lane could still pick up once the wrap-up allowance is spent. */
    #laneCanFollow(wrapUp, now) {
        if (wrapUp.zone === "seven_day")
            return false;
        if (this.#blocked !== undefined && now < this.#blocked.untilSec * 1000)
            return false;
        if (this.#coolingOffUntilMs !== undefined && now < this.#coolingOffUntilMs)
            return false;
        return this.#stoppedResetsAtSec === undefined || this.#stoppedResetsAtSec * 1000 <= now;
    }
    /**
     * Key of the open wrap-up window when the model should be told to wrap up,
     * else undefined: no window, extra usage takes over, the lane already
     * serves, or (with `lowPriority`) the lane can still pick up the work.
     * Sessions hint once per key.
     */
    wrapUpHintKey(lowPriority, now = Date.now()) {
        const wrapUp = this.#currentWrapUp(now);
        if (!wrapUp || wrapUp.extraUsage)
            return undefined;
        if (lowPriority && (this.isActive(now) || this.#laneCanFollow(wrapUp, now)))
            return undefined;
        return wrapUp.epoch;
    }
    /** Structured usage-limit state, or `undefined` outside wrap-up and low priority. */
    status(now = Date.now(), lowPriority = true) {
        const resetsAtSec = lowPriority ? this.activeResetsAtSec(now) : undefined;
        if (resetsAtSec !== undefined) {
            const allowanceLeftPercent = this.allowanceLeftPercent();
            return {
                stage: "low_priority",
                resetsAtSec,
                ...(allowanceLeftPercent === undefined ? {} : { allowanceLeftPercent }),
            };
        }
        const wrapUp = this.#currentWrapUp(now);
        if (!wrapUp)
            return undefined;
        return {
            stage: "wrap_up",
            ...(wrapUp.resetsAtSec === undefined ? {} : { resetsAtSec: wrapUp.resetsAtSec }),
            extraUsage: wrapUp.extraUsage,
        };
    }
    /** Whether the slow lane can be entered now, and on which window. */
    availability(now = Date.now()) {
        if (this.isActive(now))
            return { kind: "unavailable", reason: "Low priority is already on." };
        const blocked = this.#blocked;
        if (blocked !== undefined && now < blocked.untilSec * 1000) {
            return {
                kind: "unavailable",
                reason: blocked.reason === "budget"
                    ? "This week's low-priority allowance is used up. It is offered again after your weekly limit resets."
                    : `Your weekly Claude limit is reached; low priority is unavailable until it resets at ${formatSlowModeResetClock(blocked.untilSec, now)}.`,
            };
        }
        if (this.#coolingOffUntilMs !== undefined && now < this.#coolingOffUntilMs) {
            return {
                kind: "unavailable",
                reason: `Low priority is taking a break until ${formatSlowModeResetClock(Math.ceil(this.#coolingOffUntilMs / 1000), now)} after waiting too long for spare capacity.`,
            };
        }
        const stopped = this.#stoppedResetsAtSec;
        if (stopped !== undefined && stopped * 1000 > now)
            return { kind: "available", resetsAtSec: stopped, resume: true };
        const offer = this.#offerResetsAtSec;
        if (offer !== undefined && offer * 1000 > now)
            return { kind: "available", resetsAtSec: offer, resume: false };
        return {
            kind: "unavailable",
            reason: "Low priority isn't available right now. Anthropic offers it after a Claude subscription reaches its session limit.",
        };
    }
    /** Enter the slow lane if {@link availability} allows it. */
    accept(now = Date.now()) {
        const availability = this.availability(now);
        if (availability.kind === "available")
            this.#activate(availability.resetsAtSec, now);
        return availability;
    }
    /** End the active window. Returns false when nothing was active. */
    stop(reason, now = Date.now()) {
        const phase = this.#phase;
        if (phase.kind !== "active") {
            if (reason !== "user")
                this.#stoppedResetsAtSec = undefined;
            return false;
        }
        if (reason === "max_wait")
            this.#coolingOffUntilMs = now + MAX_WAIT_COOLOFF_MS;
        // Only a user stop or a capacity cool-off keeps the window's offer usable;
        // every server-driven end needs a fresh offer before the lane reopens.
        if (reason !== "user" && reason !== "max_wait")
            this.#offerResetsAtSec = undefined;
        this.#stoppedResetsAtSec = reason === "user" ? phase.resetsAtSec : undefined;
        this.#phase = { kind: "idle" };
        return true;
    }
    /** Test seam: drop all state. */
    reset() {
        this.#phase = { kind: "idle" };
        this.#offerResetsAtSec = undefined;
        this.#stoppedResetsAtSec = undefined;
        this.#coolingOffUntilMs = undefined;
        this.#blocked = undefined;
        this.#budgetUtilization = undefined;
        this.#retryAfterMs = DEFAULT_RETRY_AFTER_MS;
        this.#maxWaitMs = DEFAULT_MAX_WAIT_MS;
        this.#wrapUp = undefined;
        this.#wrapUpEpoch = 0;
    }
    #activate(resetsAtSec, now) {
        this.#stoppedResetsAtSec = undefined;
        this.#phase = { kind: "active", resetsAtSec, acceptedAtMs: now, requestsServed: 0, requestsStandard: 0 };
    }
    #end(reason, options) {
        if (!this.stop(reason))
            return;
        const notice = END_NOTICES[reason];
        if (notice)
            options.notify?.(notice.level, notice.message);
    }
    /** Adopt server-stated retry pacing and allowance usage. */
    #applyTiming(signal) {
        if (!signal)
            return;
        if (signal.retryAfterMs !== undefined) {
            this.#retryAfterMs = Math.min(MAX_RETRY_AFTER_MS, Math.max(MIN_RETRY_AFTER_MS, Math.round(signal.retryAfterMs)));
        }
        if (signal.maxWaitMs !== undefined) {
            this.#maxWaitMs = Math.min(MAX_MAX_WAIT_MS, Math.max(MIN_MAX_WAIT_MS, Math.round(signal.maxWaitMs)));
        }
        if (signal.budgetUtilization !== undefined)
            this.#budgetUtilization = signal.budgetUtilization;
    }
    /** Track the wrap-up window from a response's unified-limit headers. */
    #observeWrapUp(signal, options, now) {
        const grace = signal.graceUtilization;
        if (!grace)
            return;
        if (Math.max(grace.fiveHour, grace.sevenDay) <= 0) {
            this.#wrapUp = undefined;
            return;
        }
        // Past resets are stale; drop them.
        const fiveHourReset = signal.fiveHourResetAtSec !== undefined && signal.fiveHourResetAtSec * 1000 > now
            ? signal.fiveHourResetAtSec
            : undefined;
        const weeklyReset = signal.weeklyResetAtSec !== undefined && signal.weeklyResetAtSec * 1000 > now
            ? signal.weeklyResetAtSec
            : undefined;
        // Same zone pick as Claude Code: the weekly zone unless the 5-hour
        // allowance is in use and outlasts the weekly reset.
        const zone = grace.sevenDay > 0 &&
            !(grace.fiveHour > 0 &&
                fiveHourReset !== undefined &&
                (weeklyReset === undefined || fiveHourReset > weeklyReset))
            ? "seven_day"
            : "five_hour";
        const previous = this.#currentWrapUp(now);
        const wrapUp = {
            zone,
            resetsAtSec: zone === "seven_day" ? weeklyReset : fiveHourReset,
            extraUsage: signal.overageInUse || signal.overageAllowed === true,
            epoch: previous?.epoch ?? ++this.#wrapUpEpoch,
        };
        this.#wrapUp = wrapUp;
        if (previous)
            return;
        const resets = wrapUp.resetsAtSec === undefined ? "" : ` (resets ${formatSlowModeResetClock(wrapUp.resetsAtSec, now)})`;
        const lowPriority = options.lowPriority?.() ?? true;
        options.notify?.("info", wrapUp.extraUsage
            ? `Claude usage limit reached${resets} — a short wrap-up allowance runs first, then extra usage.`
            : lowPriority && this.#laneCanFollow(wrapUp, now)
                ? `Claude usage limit reached${resets} — finishing on a short wrap-up allowance from your weekly limit; low priority takes over if Anthropic offers it.`
                : `Claude usage limit reached${resets} — finishing on a short wrap-up allowance from your weekly limit; the agent will wrap up its current step.`);
    }
    /** Observe a successful response's slow-lane and wrap-up headers on this lane. */
    observe(signal, options) {
        this.#observeWrapUp(signal, options, Date.now());
        const phase = this.#phase;
        if (phase.kind !== "active")
            return;
        if (signal.fiveHourResetAtSec !== undefined && signal.fiveHourResetAtSec >= phase.resetsAtSec + RESET_GRACE_SEC) {
            this.#end("reset", options);
            return;
        }
        if (signal.status === "active") {
            this.#applyTiming(signal);
            phase.requestsServed++;
        }
        else if (signal.status === "not_needed") {
            this.#applyTiming(signal);
            phase.requestsStandard++;
        }
        else if (signal.status === "ineligible" && signal.overageInUse) {
            this.#end("extra_usage", options);
        }
    }
    /** Map a 429 slow status to the reason the window must end, or null to keep going. */
    #endReasonFor(signal) {
        switch (signal?.status) {
            case "weekly_limit":
                return "weekly";
            case "budget_exhausted":
                return "budget";
            case "off":
                return "off";
            case "ineligible":
                return signal.overageInUse ? "extra_usage" : "ineligible";
            case "slot_busy":
                return null;
            default:
                return signal?.unifiedLimitClaim ? "wall" : null;
        }
    }
    /** Decide how to react to a pre-content failure on this lane (see {@link AnthropicSlowModeHooks.onFailure}). */
    async onFailure(failure, options) {
        const now = Date.now();
        const signal = failure.signal;
        const rateLimited = failure.httpStatus === 429;
        if (!failure.sentSlow) {
            if (!rateLimited)
                return undefined;
            // A session-limit wall closes the wrap-up window: its allowance is spent.
            const afterWrapUp = this.#currentWrapUp(now) !== undefined;
            if (signal?.unifiedLimitClaim || signal?.offer !== undefined)
                this.#wrapUp = undefined;
            const lowPriority = options.lowPriority?.() ?? true;
            // Another request activated the lane while this one was in flight.
            if (this.isActive(now))
                return lowPriority ? { delayMs: 0, capacityWait: false } : undefined;
            if (signal?.offer !== "treatment" || signal.unifiedResetAtSec === undefined)
                return undefined;
            if (signal.unifiedResetAtSec * 1000 <= now)
                return undefined;
            // Record the offer even with `/slow off`, so a later `/slow on` enters it right away.
            this.#offerResetsAtSec = signal.unifiedResetAtSec;
            if (!lowPriority)
                return undefined;
            // An explicit `/slow off` stop holds for the rest of that window.
            if (this.#stoppedResetsAtSec === signal.unifiedResetAtSec)
                return undefined;
            if (this.availability(now).kind !== "available")
                return undefined;
            if (options.canAutoAccept && !(await options.canAutoAccept()))
                return undefined;
            // A concurrent request may have taken the lane during the await.
            if (this.isActive())
                return { delayMs: 0, capacityWait: false };
            if (this.accept().kind !== "available")
                return undefined;
            this.#applyTiming(signal);
            const until = formatSlowModeResetClock(signal.unifiedResetAtSec, now);
            options.notify?.("info", `${afterWrapUp ? "Wrap-up allowance used" : "Claude session limit reached"} — continuing at low priority until ${until}. Your weekly limit still applies and responses may pause while waiting for spare capacity. Run /slow off to stop.`);
            return { delayMs: 0, capacityWait: false };
        }
        if (!this.isActive(now))
            return undefined;
        if (rateLimited) {
            const endReason = this.#endReasonFor(signal);
            if (endReason !== null) {
                if (endReason === "budget" || endReason === "weekly") {
                    // Block re-entry until the reported reset; stale offers must not revive the lane.
                    const resetSec = endReason === "budget"
                        ? (signal?.budgetResetAtSec ?? signal?.weeklyResetAtSec)
                        : (signal?.weeklyResetAtSec ?? signal?.unifiedResetAtSec);
                    this.#blocked = {
                        reason: endReason,
                        untilSec: resetSec !== undefined && resetSec > 0
                            ? Math.round(Math.min(resetSec, now / 1000 + MAX_BUDGET_BLOCK_SEC))
                            : Math.round(now / 1000 + MAX_BUDGET_BLOCK_SEC),
                    };
                }
                this.#end(endReason, options);
                return undefined;
            }
        }
        this.#applyTiming(signal);
        const slotBusy = rateLimited && signal?.status === "slot_busy";
        const capacityBusy = failure.overloaded && (signal?.status === undefined || signal.status === "active");
        if (!slotBusy && !capacityBusy)
            return undefined;
        const remainingMs = this.#maxWaitMs - failure.waitedMs;
        if (remainingMs <= 0) {
            this.#end("max_wait", options);
            return undefined;
        }
        // Never sleep past the server's max-wait budget; the next failure after
        // a clamped wait ends the lane instead.
        const jitter = 1 + (Math.random() * 2 - 1) * RETRY_JITTER;
        const delayMs = Math.min(remainingMs, Math.round(this.#retryAfterMs * jitter));
        if (failure.attempts === 0) {
            options.notify?.("info", `Working at low priority — waiting for spare capacity (next try in ${Math.max(1, Math.round(delayMs / 1000))}s).`);
        }
        return { delayMs, capacityWait: true };
    }
}
/**
 * Slow-lane state keyed by Claude account (`cred:<id>` / `key:<hash>`, see
 * {@link AnthropicSlowModeHooks}): one account's wall, offer, and waits never
 * leak into requests served by another. Process-wide so the main agent,
 * subagents, and advisors on the same account share one lane.
 */
export class AnthropicSlowModeLanes {
    #lanes = new Map();
    /** The lane for `key`, created on first use. */
    lane(key) {
        let lane = this.#lanes.get(key);
        if (!lane) {
            lane = new AnthropicSlowModeController();
            this.#lanes.set(key, lane);
        }
        return lane;
    }
    /**
     * Build provider hooks for one request. `options` scopes auto-accept gating
     * and notices to the requesting session; `onLane` reports which account
     * lane served it so the session's `/slow` and status line follow it.
     */
    hooks(options) {
        return {
            isActive: lane => (options.lowPriority?.() ?? true) && this.lane(lane).isActive(),
            observe: (signal, lane) => {
                options.onLane?.(lane);
                this.lane(lane).observe(signal, options);
            },
            onFailure: failure => {
                options.onLane?.(failure.lane);
                return this.lane(failure.lane).onFailure(failure, options);
            },
        };
    }
}
/** The process-wide lane registry shared by every session in this process. */
export const anthropicSlowModeLanes = new AnthropicSlowModeLanes();
/**
 * Auto-accept gate: take the slow lane only when no sibling Claude OAuth
 * account has full-speed headroom. With one account there is nothing to
 * rotate to; with several, turn recovery's credential rotation wins while any
 * other account is still healthy. A failed health probe accepts — the user
 * opted in and the alternative is waiting for the reset.
 */
export async function anthropicSlowModeHasNoSiblingHeadroom(authStorage, model, sessionId) {
    const oauthAccounts = authStorage.credentials
        .list(model.provider)
        .filter(entry => entry.credential.type === "oauth").length;
    if (oauthAccounts <= 1)
        return true;
    try {
        const health = await authStorage.health.model(model.provider, {
            modelId: model.id,
            sessionId,
            baseUrl: model.baseUrl,
            reserveFraction: 0,
            signal: AbortSignal.timeout(5000),
        });
        return !health.accounts.some(account => account.selected !== true && account.state === "healthy");
    }
    catch (error) {
        logger.debug("anthropic slow mode: sibling health probe failed", { error: String(error) });
        return true;
    }
}
