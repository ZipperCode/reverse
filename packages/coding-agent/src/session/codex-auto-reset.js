import { reportMatchesActiveAccount } from "../slash-commands/helpers/active-oauth-account";
/** A chat window counts as exhausted at `usedFraction >= 0.999` (used_percent >= 99.9). */
export const WINDOW_EXHAUSTED_MIN_FRACTION = 0.999;
/** A weekly reset can never be more than one window length (7d) away; +1h slack for skew. */
export const MAX_PLAUSIBLE_WEEKLY_REMAINING_MS = 7 * 24 * 3600000 + 60 * 60000;
/** A 5h reset can never be more than one window length (5h) away; +1h slack for skew. */
export const MAX_PLAUSIBLE_PRIMARY_REMAINING_MS = 5 * 3600000 + 60 * 60000;
/** Shared last-chance expiry horizon; bypasses salvage usage thresholds, non-terminal deferrals and, with no prompt UI, unset consent; never cooldown. */
export const IMMINENT_RESET_EXPIRY_MS = 5 * 60000;
/** Below this usage on BOTH chat windows, non-imminent salvage restores too little to bother. */
export const SALVAGE_MIN_USED_FRACTION = 0.25;
/** Retry spacing after a non-terminal consume outcome, except during imminent-expiry salvage. */
export const REDEEM_RETRY_DEFER_MS = 30 * 60000;
/** Report must be no older than the 5-min usage cache TTL plus slack. */
export const REPORT_FRESHNESS_MS = 10 * 60000;
/** Per-account cooldown that catches attempt-key drift across a minute boundary. */
export const ATTEMPT_COOLDOWN_MS = 60000;
/** Minute bucket for attempt keys, absorbing `reset_after_seconds`/expiry jitter. */
export const DEBOUNCE_BUCKET_MS = 60000;
/** Floor between salvage sweeps; dedupe keys make sweeps idempotent, this just avoids useless re-planning. */
export const SWEEP_MIN_INTERVAL_MS = 60000;
export function shouldEvaluateCodexAutoRedeem(mode) {
    return mode !== "no";
}
export function shouldPromptCodexAutoRedeem(mode) {
    return mode === "unset";
}
/**
 * Planned spends a host with no prompt UI may make while auto-redeem is unset:
 * only a credit expiring within {@link IMMINENT_RESET_EXPIRY_MS} qualifies,
 * whether a salvage or a restore spends it, since nobody can be asked before it
 * is lost. The approved target names that credit, so redeem cannot pick a later one.
 */
export function headlessApprovedResetActions(actions) {
    const approved = [];
    for (const action of actions) {
        if (action.expiresInMs === undefined || action.expiresInMs > IMMINENT_RESET_EXPIRY_MS)
            continue;
        approved.push(action.creditId ? { ...action, target: { ...action.target, creditId: action.creditId } } : action);
    }
    return approved;
}
/** Planner settings from a provider's `codexResets.*` or `claudeResets.*` group. */
export function resetPlanSettings(cfg) {
    return {
        enabled: shouldEvaluateCodexAutoRedeem(cfg.autoRedeem),
        minBlockedMinutes: Math.max(0, cfg.minBlockedMinutes),
        keepCredits: Math.max(0, Math.trunc(cfg.keepCredits)),
        salvageHorizonMs: Math.max(0, cfg.salvageHorizonHours) * 3600000,
    };
}
/** Soonest future-expiring available credit, or undefined. */
function soonestAvailableCredit(credits, nowMs) {
    let soonest;
    for (const credit of credits ?? []) {
        if ((credit.status ?? "available") !== "available")
            continue;
        if (!credit.expiresAt)
            continue;
        const expiry = Date.parse(credit.expiresAt);
        if (Number.isNaN(expiry) || expiry <= nowMs)
            continue;
        if (soonest === undefined || expiry < soonest.expiresAtMs)
            soonest = { id: credit.id, expiresAtMs: expiry };
    }
    return soonest;
}
function classifyChatWindow(limit, fallback) {
    const durationMs = limit.window?.durationMs;
    if (durationMs !== undefined && Number.isFinite(durationMs)) {
        if (Math.abs(durationMs - 7 * 24 * 3600000) <= 60000)
            return "weekly";
        if (Math.abs(durationMs - 5 * 3600000) <= 60000)
            return "5h";
    }
    const windowId = limit.window?.id.toLowerCase();
    const scopeWindowId = limit.scope.windowId?.toLowerCase();
    if (windowId === "7d" || scopeWindowId === "7d")
        return "weekly";
    if (windowId === "5h" || scopeWindowId === "5h")
        return "5h";
    return fallback;
}
function snapshotChatWindow(limit, fallback) {
    const window = classifyChatWindow(limit, fallback);
    return {
        limit,
        window,
        usedFraction: limit.amount.usedFraction,
        resetsAt: limit.window?.resetsAt,
        plausibleMs: window === "weekly" ? MAX_PLAUSIBLE_WEEKLY_REMAINING_MS : MAX_PLAUSIBLE_PRIMARY_REMAINING_MS,
    };
}
/** The 5h and weekly chat windows, selected by their stable limit ids. */
function codexChatWindows(report) {
    const primary = report.limits.find(l => l.id === "openai-codex:primary");
    const weekly = report.limits.find(l => l.id === "openai-codex:secondary");
    const windows = [];
    if (primary)
        windows.push(snapshotChatWindow(primary, "5h"));
    if (weekly)
        windows.push(snapshotChatWindow(weekly, "weekly"));
    return windows;
}
/** The fullest chat window with known usage: the one a salvage redeem restores. */
function fullestChatWindow(windows) {
    let fullest;
    for (const window of windows) {
        if (window.usedFraction !== undefined &&
            window.usedFraction >= 0 &&
            (!fullest || window.usedFraction > (fullest.usedFraction ?? 0))) {
            fullest = window;
        }
    }
    return fullest;
}
/** The chat window the `expiring-credit` rule measures for one Codex usage report. */
export function fullestCodexChatWindow(report) {
    return fullestChatWindow(codexChatWindows(report));
}
function usedFractionForWindow(snapshot, window) {
    let fullest;
    for (const entry of snapshot.windows) {
        if (entry.window !== window || entry.usedFraction === undefined)
            continue;
        if (fullest === undefined || entry.usedFraction > fullest)
            fullest = entry.usedFraction;
    }
    return fullest;
}
/**
 * Plan which saved Codex resets to spend right now. Pure: a function of the
 * snapshot inputs only. Callers execute the returned actions in order,
 * re-checking `attemptedKeys` immediately before each consume.
 */
export function planCodexResetRedemptions(input) {
    const { nowMs, settings } = input;
    const skipped = [];
    if (!settings.enabled)
        return { actions: [], skipped: [{ accountKey: "*", rule: "account", reason: "disabled" }] };
    // Rule-wide gates for `blocked-account`: a redeem can only unblock the turn
    // when the turn is actually on Codex, and it is unknown whether a credit
    // resets the separate Spark meter.
    let blockedRuleActive = input.trigger === "blocked";
    if (blockedRuleActive && input.provider !== "openai-codex") {
        blockedRuleActive = false;
        skipped.push({ accountKey: "*", rule: "blocked-account", reason: "wrong-provider" });
    }
    if (blockedRuleActive && input.modelId.includes("-spark")) {
        blockedRuleActive = false;
        skipped.push({ accountKey: "*", rule: "blocked-account", reason: "spark-model" });
    }
    const snapshots = [];
    for (const report of input.reports ?? []) {
        if (report.provider !== "openai-codex")
            continue;
        const accountIdValue = report.metadata?.accountId;
        const emailValue = report.metadata?.email;
        const orgIdValue = report.metadata?.orgId;
        const credentialIdValue = report.metadata?.resetCreditCredentialId;
        const accountId = typeof accountIdValue === "string" && accountIdValue.trim() ? accountIdValue : undefined;
        const email = typeof emailValue === "string" && emailValue.trim() ? emailValue : undefined;
        const orgId = typeof orgIdValue === "string" && orgIdValue.trim() ? orgIdValue : undefined;
        const credentialId = typeof credentialIdValue === "number" && Number.isInteger(credentialIdValue) ? credentialIdValue : undefined;
        if (credentialId === undefined) {
            skipped.push({ accountKey: "*", rule: "account", reason: "credits-unknown" });
            continue;
        }
        const accountKey = `openai-codex|${orgId?.trim().toLowerCase() ?? "-"}|${credentialId}`;
        const isActive = report.metadata?.resetCreditActive === true || reportMatchesActiveAccount(report, input.identity);
        if (nowMs - report.fetchedAt > REPORT_FRESHNESS_MS) {
            skipped.push({ accountKey, rule: "account", reason: "stale-report" });
            continue;
        }
        const available = report.resetCredits?.availableCount;
        // Can't verify availability from the snapshot → don't spend (precision over recall).
        if (available === undefined) {
            skipped.push({ accountKey, rule: "account", reason: "credits-unknown" });
            continue;
        }
        if (available < 1) {
            skipped.push({ accountKey, rule: "account", reason: "no-credits" });
            continue;
        }
        const windows = codexChatWindows(report);
        const baseLabel = email ?? accountId ?? accountKey;
        const label = orgId && orgId !== baseLabel ? `${baseLabel} (${orgId})` : baseLabel;
        const soonestCredit = soonestAvailableCredit(report.resetCredits?.credits, nowMs);
        snapshots.push({
            accountKey,
            target: {
                provider: "openai-codex",
                credentialId,
                accountId,
                email,
                ...(orgId ? { orgId } : {}),
            },
            label,
            active: isActive,
            availableCount: available,
            windows,
            limitReached: report.metadata?.limitReached === true,
            creditExpiresAtMs: soonestCredit?.expiresAtMs,
            creditId: soonestCredit?.id,
        });
    }
    const cooledDown = (accountKey) => {
        const lastAt = input.lastAttemptAtByAccount.get(accountKey);
        return lastAt !== undefined && nowMs - lastAt < ATTEMPT_COOLDOWN_MS;
    };
    // --- blocked-account: pick ONE restore candidate; one open lane is enough,
    // the next block re-plans on live data.
    let restore;
    if (blockedRuleActive) {
        const candidates = [];
        for (const snapshot of snapshots) {
            const rule = "blocked-account";
            const skip = (reason) => skipped.push({ accountKey: snapshot.accountKey, rule, reason });
            // Restoring an account the session may not use cannot unblock it.
            if (input.permitsCredential && !input.permitsCredential(snapshot.target.credentialId)) {
                skip("outside-account-pool");
                continue;
            }
            // Live evidence: the 429 that triggered this pass names the active
            // account directly, outranking a possibly pre-block report snapshot.
            const liveUnblockAtMs = snapshot.active ? input.activeBlockUnblockAtMs : undefined;
            // The wire's own blocked flag must confirm the 429 for THIS account,
            // unless the live block evidence already does.
            if (!snapshot.limitReached && liveUnblockAtMs === undefined) {
                skip("not-limit-reached");
                continue;
            }
            // Identify the exact exhausted window(s) via usedFraction — never
            // `status` (see the Decision-2 trap in the module docs). Either
            // window qualifies: a banked reset also clears a 5h-only block
            // (openai/codex#28525).
            const exhausted = [];
            for (const window of snapshot.windows) {
                if (window.usedFraction !== undefined && window.usedFraction >= WINDOW_EXHAUSTED_MIN_FRACTION) {
                    exhausted.push(window);
                }
            }
            let unblockAtMs;
            let blockedWindows;
            if (exhausted.length > 0) {
                // Blocked until EVERY exhausted window rolls over — the unblock is
                // the latest reset among them. A missing or implausible reset on any
                // of them means the unblock time is unknown; stay conservative.
                let latest = Number.NEGATIVE_INFINITY;
                let invalid;
                for (const entry of exhausted) {
                    if (entry.resetsAt === undefined) {
                        invalid = "no-reset-time";
                        break;
                    }
                    if (entry.resetsAt - nowMs > entry.plausibleMs) {
                        invalid = "reset-implausible";
                        break;
                    }
                    if (entry.resetsAt > latest)
                        latest = entry.resetsAt;
                }
                if (invalid) {
                    skip(invalid);
                    continue;
                }
                unblockAtMs = latest;
                blockedWindows = exhausted.map(e => e.window);
            }
            else if (liveUnblockAtMs !== undefined) {
                // The report's windows look healthy but the live 429 says otherwise:
                // the snapshot predates the block. Trust the provider's own hint for
                // the unblock horizon, classifying the window by its scale.
                if (liveUnblockAtMs - nowMs > MAX_PLAUSIBLE_WEEKLY_REMAINING_MS) {
                    skip("reset-implausible");
                    continue;
                }
                unblockAtMs = liveUnblockAtMs;
                blockedWindows = [liveUnblockAtMs - nowMs > MAX_PLAUSIBLE_PRIMARY_REMAINING_MS ? "weekly" : "5h"];
            }
            else {
                skip("no-exhausted-window");
                continue;
            }
            const remainingMs = unblockAtMs - nowMs;
            // Anti-waste: too close to the natural unblock — let it roll over.
            if (remainingMs < settings.minBlockedMinutes * 60000) {
                skip("reset-too-soon");
                continue;
            }
            if ((snapshot.availableCount ?? 0) - Math.max(0, Math.trunc(settings.keepCredits)) < 1) {
                skip("reserve");
                continue;
            }
            if (input.attemptedKeys.has(blockedAttemptKey(snapshot.accountKey, unblockAtMs))) {
                skip("already-attempted");
                continue;
            }
            const deferredUntil = input.deferredUntilByKey.get(blockedAttemptKey(snapshot.accountKey, unblockAtMs));
            if (deferredUntil !== undefined && nowMs < deferredUntil) {
                skip("deferred");
                continue;
            }
            if (cooledDown(snapshot.accountKey)) {
                skip("cooldown");
                continue;
            }
            candidates.push({ snapshot, remainingMs, unblockAtMs, blockedWindows });
        }
        candidates.sort((a, b) => {
            // Active account first: the sticky session credential stays usable.
            if (a.snapshot.active !== b.snapshot.active)
                return a.snapshot.active ? -1 : 1;
            // Then spend the credit that dies soonest.
            const aExpiry = a.snapshot.creditExpiresAtMs ?? Number.POSITIVE_INFINITY;
            const bExpiry = b.snapshot.creditExpiresAtMs ?? Number.POSITIVE_INFINITY;
            if (aExpiry !== bExpiry)
                return aExpiry - bExpiry;
            // Then the deepest bank, then the longest natural wait (most value).
            const aCount = a.snapshot.availableCount ?? 0;
            const bCount = b.snapshot.availableCount ?? 0;
            if (aCount !== bCount) {
                return bCount - aCount;
            }
            return b.remainingMs - a.remainingMs;
        });
        const best = candidates[0];
        if (best) {
            restore = {
                reason: "blocked-account",
                target: best.snapshot.target,
                accountKey: best.snapshot.accountKey,
                attemptKey: blockedAttemptKey(best.snapshot.accountKey, best.unblockAtMs),
                label: best.snapshot.label,
                availableCount: best.snapshot.availableCount,
                weeklyUsedFraction: usedFractionForWindow(best.snapshot, "weekly"),
                remainingMs: best.remainingMs,
                expiresInMs: best.snapshot.creditExpiresAtMs === undefined ? undefined : best.snapshot.creditExpiresAtMs - nowMs,
                creditId: best.snapshot.creditId,
                blockedWindows: best.blockedWindows,
                active: best.snapshot.active,
            };
        }
    }
    // --- expiring-credit: salvage every credit that would otherwise die.
    const salvages = [];
    for (const snapshot of snapshots) {
        if (snapshot.accountKey === restore?.accountKey)
            continue; // restore already spends its soonest credit
        const rule = "expiring-credit";
        const skip = (reason) => skipped.push({ accountKey: snapshot.accountKey, rule, reason });
        const expiresAtMs = snapshot.creditExpiresAtMs;
        const imminent = expiresAtMs !== undefined && expiresAtMs > nowMs && expiresAtMs - nowMs <= IMMINENT_RESET_EXPIRY_MS;
        if (expiresAtMs === undefined ||
            (!imminent && !(settings.salvageHorizonMs > 0 && expiresAtMs - nowMs <= settings.salvageHorizonMs))) {
            skip("no-expiring-credit");
            continue;
        }
        // Broader salvage needs meaningful usage in either chat window. In the
        // last five minutes, live credit eligibility outranks zero/unknown usage:
        // let the provider decide whether there is anything left to restore.
        const fullestWindow = fullestChatWindow(snapshot.windows);
        const salvageUsedFraction = fullestWindow?.usedFraction;
        if (!imminent && (salvageUsedFraction === undefined || salvageUsedFraction < SALVAGE_MIN_USED_FRACTION)) {
            skip("window-mostly-free");
            continue;
        }
        const attemptKey = salvageAttemptKey(snapshot.accountKey, expiresAtMs);
        if (input.attemptedKeys.has(attemptKey)) {
            skip("already-attempted");
            continue;
        }
        const deferredUntil = input.deferredUntilByKey.get(attemptKey);
        if (!imminent && deferredUntil !== undefined && nowMs < deferredUntil) {
            skip("deferred");
            continue;
        }
        if (cooledDown(snapshot.accountKey)) {
            skip("cooldown");
            continue;
        }
        salvages.push({
            reason: "expiring-credit",
            target: snapshot.target,
            accountKey: snapshot.accountKey,
            attemptKey,
            label: snapshot.label,
            availableCount: snapshot.availableCount,
            weeklyUsedFraction: usedFractionForWindow(snapshot, "weekly"),
            salvageWindow: fullestWindow?.window,
            salvageUsedFraction,
            expiresInMs: expiresAtMs - nowMs,
            creditId: snapshot.creditId,
            active: snapshot.active,
        });
    }
    salvages.sort((a, b) => (a.expiresInMs ?? 0) - (b.expiresInMs ?? 0));
    const actions = restore ? [restore, ...salvages] : salvages;
    return { actions, skipped };
}
/**
 * Fence saved-reset spending by upstream provider, organization, and account,
 * never by a credential row id that another store may reuse.
 */
export function resetAccountLockKey(identity) {
    const account = (identity.accountId ?? identity.email)?.trim().toLowerCase();
    if (!account)
        return undefined;
    return `${identity.provider}|${identity.orgId?.trim().toLowerCase() ?? "-"}|${account}`;
}
/** One attempt per (account, weekly-reset-minute) block episode. */
export function blockedAttemptKey(accountKey, weeklyResetsAtMs) {
    return `block|${accountKey}|${Math.round(weeklyResetsAtMs / DEBOUNCE_BUCKET_MS)}`;
}
/** One attempt per (account, credit-expiry-minute) salvage episode. */
export function salvageAttemptKey(accountKey, creditExpiresAtMs) {
    return `salvage|${accountKey}|${Math.round(creditExpiresAtMs / DEBOUNCE_BUCKET_MS)}`;
}
/**
 * Overlay LIVE per-account credit state (from the dedicated
 * `rate-limit-reset-credits` route) onto usage reports before a blocked pass.
 *
 * `/wham/usage` credit counts can be stale or pre-feature, and the usage
 * provider only consults the live detail endpoint when the usage payload
 * already reports a POSITIVE count — a stale ZERO is never corrected there.
 * Live data replaces the report's credit block wholesale; accounts with no
 * live row get the block stripped. For blocked recovery, the active live row
 * may synthesize a minimal report carrying its durable credential id when
 * usage is missing/stale; the 429 supplies timing, never credit eligibility.
 */
export function overlayLiveResetCredits(reports, statuses, options) {
    const merged = (reports ?? []).map(report => {
        if (report.provider !== "openai-codex")
            return report;
        const status = statuses.find(s => {
            if (s.provider !== "openai-codex")
                return false;
            const statusOrg = s.orgId?.trim().toLowerCase();
            const reportOrg = typeof report.metadata?.orgId === "string" ? report.metadata.orgId.trim().toLowerCase() : undefined;
            if (statusOrg !== reportOrg)
                return false;
            if (s.accountId && typeof report.metadata?.accountId === "string") {
                return s.accountId === report.metadata.accountId;
            }
            return !!s.email && s.email === report.metadata?.email;
        });
        if (!status || status.error)
            return { ...report, resetCredits: undefined };
        return {
            ...report,
            metadata: { ...report.metadata, resetCreditCredentialId: status.credentialId },
            resetCredits: {
                availableCount: status.availableCount,
                credits: status.credits
                    .filter(credit => (credit.status ?? "available") === "available")
                    .map(credit => ({
                    id: credit.id,
                    grantedAt: credit.grantedAt,
                    expiresAt: credit.expiresAt,
                    status: credit.status,
                })),
            },
        };
    });
    if (options?.synthesizeActive) {
        const nowMs = options.nowMs ?? Date.now();
        const active = statuses.find(status => status.provider === "openai-codex" && status.active && !status.error && status.availableCount > 0);
        const hasFreshActive = active !== undefined &&
            merged.some(report => report.provider === "openai-codex" &&
                report.metadata?.resetCreditCredentialId === active.credentialId &&
                nowMs - report.fetchedAt <= REPORT_FRESHNESS_MS);
        if (active && !hasFreshActive) {
            merged.push({
                provider: "openai-codex",
                fetchedAt: nowMs,
                limits: [],
                metadata: {
                    accountId: active.accountId,
                    email: active.email,
                    orgId: active.orgId,
                    limitReached: true,
                    resetCreditCredentialId: active.credentialId,
                    resetCreditActive: true,
                },
                resetCredits: {
                    availableCount: active.availableCount,
                    credits: active.credits
                        .filter(credit => (credit.status ?? "available") === "available")
                        .map(credit => ({
                        id: credit.id,
                        grantedAt: credit.grantedAt,
                        expiresAt: credit.expiresAt,
                        status: credit.status,
                    })),
                },
            });
        }
    }
    return reports || merged.length > 0 ? merged : null;
}
/**
 * Whether a consume outcome permanently settles its episode. Terminal codes
 * either spent the credit (`reset`), or prove this credit can never be spent
 * (`already_redeemed`, `no_credit` — a live listing that really had nothing).
 * Everything else — `nothing_to_reset` (limits not constrained enough right
 * now), `credit_list_failed` (flaky listing), thrown transport failures,
 * unknown codes — leaves the credit banked: the executor releases the attempt
 * key and
 * defers the episode by {@link REDEEM_RETRY_DEFER_MS} instead of burying a
 * live credit for the rest of the process.
 */
export function isTerminalRedeemOutcome(code) {
    return code === "reset" || code === "already_redeemed" || code === "no_credit";
}
/** Fresh, empty coordinator: backs the process-wide default; inject one per test for isolation. */
export function createCodexAutoRedeemCoordinator() {
    return {
        attemptedKeys: new Set(),
        deferredUntilByKey: new Map(),
        lastAttemptAtByAccount: new Map(),
        inFlightByAccount: new Map(),
        sweepInFlight: false,
        lastSweepAt: 0,
        sweepPromise: undefined,
        notifiedKeys: new Set(),
    };
}
export const defaultCodexAutoRedeemCoordinator = createCodexAutoRedeemCoordinator();
