import { resolveUsedFraction, } from "@rva/ai";
import { claudeRankingStrategy } from "@rva/ai/usage/claude";
import { ATTEMPT_COOLDOWN_MS, DEBOUNCE_BUCKET_MS, IMMINENT_RESET_EXPIRY_MS, REPORT_FRESHNESS_MS, SALVAGE_MIN_USED_FRACTION, } from "./codex-auto-reset";
const CLAUDE_PROVIDER = "anthropic";
const JUNIPER_PROGRAM = "juniper_tide";
const CEDAR_PROGRAM = "cedar_ember";
const FIVE_HOUR_LIMIT_ID = "anthropic:5h";
const MAX_PLAUSIBLE_FIVE_HOUR_MS = 6 * 3600000;
const MAX_PLAUSIBLE_WEEKLY_MS = 8 * 24 * 3600000;
function normalized(value) {
    return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : undefined;
}
/** Whether a usage report belongs to a stored account: the organization gates, then account id, else email. */
export function reportMatchesStatus(report, status) {
    if (report.provider !== status.provider)
        return false;
    const reportOrgId = normalized(report.metadata?.orgId);
    const statusOrgId = normalized(status.orgId);
    if (reportOrgId !== statusOrgId)
        return false;
    const reportAccountId = normalized(report.metadata?.accountId) ?? normalized(report.metadata?.account_id);
    const reportEmail = normalized(report.metadata?.email);
    const accountId = normalized(status.accountId);
    const email = normalized(status.email);
    if (accountId && reportAccountId)
        return accountId === reportAccountId;
    return !!email && email === reportEmail;
}
/**
 * Each stored account's Cedar/Juniper status from the inventory on its usage
 * report, which the report fetch discovered, so a background sweep finds
 * salvage candidates without listing. The inventory can be carried over a
 * failed probe, so a spend re-plans from a live listing. An account whose
 * report carries no inventory is unknown, never empty.
 */
export function claudeResetStatusesFromReports(accounts, reports) {
    const stored = accounts.map((account) => ({
        ...account,
        provider: CLAUDE_PROVIDER,
        availableCount: 0,
        credits: [],
    }));
    return stored.map(base => {
        let status = base;
        let report = reports.find(candidate => reportMatchesStatus(candidate, base));
        if (!report && !base.orgId) {
            // Discovery stamps the organization it resolves for a credential stored
            // without one, as a live listing does on its status. A report another
            // stored credential's identity matches is that credential's.
            const adoptable = [];
            for (const candidate of reports) {
                const orgId = candidate.metadata?.orgId;
                if (typeof orgId !== "string" || stored.some(other => reportMatchesStatus(candidate, other)))
                    continue;
                const adopted = { ...base, orgId, report: candidate };
                if (reportMatchesStatus(candidate, adopted))
                    adoptable.push(adopted);
            }
            if (adoptable.length === 1) {
                status = adoptable[0];
                report = status.report;
            }
        }
        const inventory = report?.resetCredits;
        if (!report || !inventory)
            return { ...status, error: "Usage report has no saved-reset inventory" };
        const credits = inventory.credits?.filter((credit) => typeof credit.id === "string");
        return { ...status, ...inventory, credits: credits ?? [], report };
    });
}
function creditExpiryMs(credit) {
    if (!credit.expiresAt)
        return undefined;
    const parsed = Date.parse(credit.expiresAt);
    return Number.isNaN(parsed) ? Number.NaN : parsed;
}
function isExhausted(limit) {
    if (limit.status === "exhausted")
        return true;
    const used = resolveUsedFraction(limit);
    return used !== undefined && used >= 0.999;
}
function maxPlausibleRemainingMs(limitId, limit) {
    const duration = limit?.window?.durationMs;
    if (duration !== undefined && Number.isFinite(duration) && duration > 0)
        return duration + 3600000;
    return limitId === FIVE_HOUR_LIMIT_ID ? MAX_PLAUSIBLE_FIVE_HOUR_MS : MAX_PLAUSIBLE_WEEKLY_MS;
}
/** Limits a grant restores: the ones it clears, and only the 5h window for a Juniper grant. */
export function claudeCoveredLimits(limits, credit) {
    const clears = new Set(credit.clears ?? []);
    return limits.filter(limit => clears.has(limit.id) && (credit.program !== JUNIPER_PROGRAM || limit.id === FIVE_HOUR_LIMIT_ID));
}
/** The fullest covered limit by the report's or the grant's own used fraction: what a salvage spend restores. */
export function fullestClaudeLimit(covered, credit) {
    let fullest;
    for (const limit of covered) {
        const resolved = resolveUsedFraction(limit);
        const observed = resolved === undefined || !Number.isFinite(resolved) ? 0 : Math.max(0, resolved);
        const server = credit.usedFractions?.[limit.id];
        const used = Math.max(observed, typeof server === "number" && Number.isFinite(server) ? server : 0);
        if (!fullest || used > fullest.used)
            fullest = { limit, used };
    }
    return fullest;
}
function claudeBlockedAttemptKey(accountKey, creditId, remainingCount, blockers, unblockAtMs) {
    return `block|${accountKey}|${creditId}|${remainingCount}|${[...blockers].sort().join(",")}|${Math.round(unblockAtMs / DEBOUNCE_BUCKET_MS)}`;
}
function claudeSalvageAttemptKey(accountKey, creditId, remainingCount, expiresAtMs) {
    return `salvage|${accountKey}|${creditId}|${remainingCount}|${Math.round(expiresAtMs / DEBOUNCE_BUCKET_MS)}`;
}
function skipForEpisode(input, accountKey, attemptKey, { imminent = false } = {}) {
    if (input.attemptedKeys.has(attemptKey))
        return "already-attempted";
    if (!imminent) {
        const blockedPrefix = `block|${accountKey}|`;
        const salvagePrefix = `salvage|${accountKey}|`;
        for (const [key, until] of input.deferredUntilByKey) {
            if (until > input.nowMs && (key.startsWith(blockedPrefix) || key.startsWith(salvagePrefix)))
                return "deferred";
        }
    }
    const lastAttemptAt = input.lastAttemptAtByAccount.get(accountKey);
    if (lastAttemptAt !== undefined && input.nowMs - lastAttemptAt < ATTEMPT_COOLDOWN_MS)
        return "cooldown";
    return undefined;
}
/**
 * Pure Claude Cedar/Juniper auto-spend planner. The live listing is the sole
 * authority for eligibility and grant selection: an absent/failed status never
 * falls back to a cached report or guesses a different grant.
 */
export function planClaudeResetRedemptions(input) {
    const skipped = [];
    if (!input.settings.enabled) {
        return { actions: [], skipped: [{ accountKey: "*", rule: "account", reason: "disabled" }] };
    }
    if (input.trigger === "blocked" && input.provider !== CLAUDE_PROVIDER) {
        return { actions: [], skipped: [{ accountKey: "*", rule: "blocked-account", reason: "wrong-provider" }] };
    }
    const snapshots = [];
    for (const status of input.statuses) {
        if (status.provider !== CLAUDE_PROVIDER)
            continue;
        const accountKey = Number.isInteger(status.credentialId)
            ? `${CLAUDE_PROVIDER}|${normalized(status.orgId) ?? "-"}|${status.credentialId}`
            : undefined;
        if (!accountKey) {
            skipped.push({ accountKey: "*", rule: "account", reason: "no-identity" });
            continue;
        }
        const skip = (reason) => skipped.push({ accountKey, rule: "account", reason });
        if (status.error) {
            skip("credits-unknown");
            continue;
        }
        if (status.eligible !== true) {
            skip("ineligible");
            continue;
        }
        if (status.cooldownUntil) {
            const cooldownUntil = Date.parse(status.cooldownUntil);
            if (!Number.isNaN(cooldownUntil) && cooldownUntil > input.nowMs) {
                skip("provider-cooldown");
                continue;
            }
        }
        if (status.availableCount < 1 || (status.redeemableCount !== undefined && status.redeemableCount < 1)) {
            skip("no-credits");
            continue;
        }
        const selectedId = status.nextCreditId;
        const credit = selectedId ? status.credits.find(candidate => candidate.id === selectedId) : undefined;
        if (!selectedId || !credit) {
            skip("no-selected-credit");
            continue;
        }
        if (credit.usable !== true ||
            (credit.status !== undefined && credit.status !== "available") ||
            credit.remainingCount === undefined ||
            credit.remainingCount < 1) {
            skip("credit-unusable");
            continue;
        }
        if (credit.program !== CEDAR_PROGRAM && credit.program !== JUNIPER_PROGRAM) {
            skip("unsupported-program");
            continue;
        }
        const expiresAtMs = creditExpiryMs(credit);
        if (expiresAtMs !== undefined && (!Number.isFinite(expiresAtMs) || expiresAtMs <= input.nowMs)) {
            skip("credit-expired");
            continue;
        }
        const imminent = expiresAtMs !== undefined && expiresAtMs - input.nowMs <= IMMINENT_RESET_EXPIRY_MS;
        if (!imminent && status.availableCount - Math.max(0, Math.trunc(input.settings.keepCredits)) < 1) {
            skip("reserve");
            continue;
        }
        const report = status.report && reportMatchesStatus(status.report, status)
            ? status.report
            : input.reports?.find(candidate => reportMatchesStatus(candidate, status));
        if (!report) {
            skip("no-report");
            continue;
        }
        if (input.nowMs - report.fetchedAt > REPORT_FRESHNESS_MS) {
            skip("stale-report");
            continue;
        }
        // A blocked retry has an exact request-model scope. A background salvage
        // has no such request context, so consider every reported scope rather
        // than accidentally treating an unrelated current model as authoritative.
        const limits = input.trigger === "blocked"
            ? (claudeRankingStrategy.scopeLimitsForReserve?.(report, { modelId: input.modelId }) ?? report.limits)
            : report.limits;
        const baseLabel = status.email ?? status.accountId ?? status.orgId ?? accountKey;
        const organizationLabel = status.orgName ?? status.orgId;
        const label = organizationLabel && organizationLabel !== baseLabel ? `${baseLabel} (${organizationLabel})` : baseLabel;
        snapshots.push({
            accountKey,
            target: {
                provider: CLAUDE_PROVIDER,
                creditId: selectedId,
                credentialId: status.credentialId,
                accountId: status.accountId,
                email: status.email,
                orgId: status.orgId,
            },
            label,
            active: status.active,
            availableCount: status.availableCount,
            credit,
            limits,
        });
    }
    let restore;
    if (input.trigger === "blocked") {
        const candidates = [];
        for (const snapshot of snapshots) {
            const skip = (reason) => skipped.push({ accountKey: snapshot.accountKey, rule: "blocked-account", reason });
            // Restoring an account the session may not use cannot unblock it.
            if (input.permitsCredential && !input.permitsCredential(snapshot.target.credentialId)) {
                skip("outside-account-pool");
                continue;
            }
            if (snapshot.availableCount - Math.max(0, Math.trunc(input.settings.keepCredits)) < 1) {
                skip("reserve");
                continue;
            }
            const clears = new Set(snapshot.credit.clears ?? []);
            const reportedBlockers = snapshot.limits
                .filter(limit => isExhausted(limit) || (snapshot.credit.usedFractions?.[limit.id] ?? 0) >= 0.999)
                .map(limit => limit.id);
            const serverBlockers = snapshot.credit.blocking ?? [];
            const blockers = [...new Set([...reportedBlockers, ...serverBlockers])];
            if (blockers.length === 0) {
                skip("no-blocked-window");
                continue;
            }
            if (blockers.some(id => !snapshot.limits.some(limit => limit.id === id))) {
                skip("unsupported-window");
                continue;
            }
            if (blockers.some(id => !clears.has(id))) {
                skip("incomplete-coverage");
                continue;
            }
            if (snapshot.credit.program === JUNIPER_PROGRAM &&
                (blockers.length !== 1 || blockers[0] !== FIVE_HOUR_LIMIT_ID)) {
                skip("incomplete-coverage");
                continue;
            }
            let unblockAtMs = Number.NEGATIVE_INFINITY;
            let invalid;
            for (const blocker of blockers) {
                const limit = snapshot.limits.find(candidate => candidate.id === blocker);
                const resetsAt = limit?.window?.resetsAt;
                if (resetsAt === undefined || !Number.isFinite(resetsAt)) {
                    invalid = "no-reset-time";
                    break;
                }
                if (resetsAt - input.nowMs > maxPlausibleRemainingMs(blocker, limit)) {
                    invalid = "reset-implausible";
                    break;
                }
                if (resetsAt > unblockAtMs)
                    unblockAtMs = resetsAt;
            }
            if (invalid === "no-reset-time" && snapshot.active && input.activeBlockUnblockAtMs !== undefined) {
                unblockAtMs = input.activeBlockUnblockAtMs;
                invalid = undefined;
                const onlyFiveHour = blockers.every(id => id === FIVE_HOUR_LIMIT_ID);
                const plausible = onlyFiveHour ? MAX_PLAUSIBLE_FIVE_HOUR_MS : MAX_PLAUSIBLE_WEEKLY_MS;
                if (unblockAtMs - input.nowMs > plausible)
                    invalid = "reset-implausible";
            }
            if (invalid) {
                skip(invalid);
                continue;
            }
            const remainingMs = unblockAtMs - input.nowMs;
            if (remainingMs < input.settings.minBlockedMinutes * 60000) {
                skip("reset-too-soon");
                continue;
            }
            const attemptKey = claudeBlockedAttemptKey(snapshot.accountKey, snapshot.credit.id, snapshot.credit.remainingCount ?? 0, blockers, unblockAtMs);
            const episodeSkip = skipForEpisode(input, snapshot.accountKey, attemptKey);
            if (episodeSkip) {
                skip(episodeSkip);
                continue;
            }
            candidates.push({ snapshot, blockers, remainingMs, unblockAtMs });
        }
        candidates.sort((left, right) => {
            if (left.snapshot.active !== right.snapshot.active)
                return left.snapshot.active ? -1 : 1;
            const leftExpiry = creditExpiryMs(left.snapshot.credit) ?? Number.POSITIVE_INFINITY;
            const rightExpiry = creditExpiryMs(right.snapshot.credit) ?? Number.POSITIVE_INFINITY;
            if (leftExpiry !== rightExpiry)
                return leftExpiry - rightExpiry;
            return right.remainingMs - left.remainingMs;
        });
        const best = candidates[0];
        if (best) {
            const expiresAtMs = creditExpiryMs(best.snapshot.credit);
            restore = {
                reason: "blocked-account",
                target: best.snapshot.target,
                accountKey: best.snapshot.accountKey,
                attemptKey: claudeBlockedAttemptKey(best.snapshot.accountKey, best.snapshot.credit.id, best.snapshot.credit.remainingCount ?? 0, best.blockers, best.unblockAtMs),
                label: best.snapshot.label,
                availableCount: best.snapshot.availableCount,
                remainingMs: best.remainingMs,
                blockedWindows: best.blockers,
                expiresInMs: expiresAtMs === undefined ? undefined : expiresAtMs - input.nowMs,
                active: best.snapshot.active,
                program: best.snapshot.credit.program ?? "",
                title: best.snapshot.credit.title,
                requiresLimit: best.snapshot.credit.requiresLimit === true,
            };
        }
    }
    const salvages = [];
    for (const snapshot of snapshots) {
        if (snapshot.accountKey === restore?.accountKey)
            continue;
        const skip = (reason) => skipped.push({ accountKey: snapshot.accountKey, rule: "expiring-credit", reason });
        const expiresAtMs = creditExpiryMs(snapshot.credit);
        const imminent = expiresAtMs !== undefined &&
            Number.isFinite(expiresAtMs) &&
            expiresAtMs > input.nowMs &&
            expiresAtMs - input.nowMs <= IMMINENT_RESET_EXPIRY_MS;
        // The last-chance window is independent of the configured savings horizon.
        if (!imminent && input.settings.salvageHorizonMs <= 0)
            continue;
        if (!imminent && snapshot.credit.program !== CEDAR_PROGRAM) {
            skip("unsupported-program");
            continue;
        }
        if (expiresAtMs === undefined ||
            !Number.isFinite(expiresAtMs) ||
            expiresAtMs <= input.nowMs ||
            (!imminent && expiresAtMs - input.nowMs > input.settings.salvageHorizonMs)) {
            skip("no-expiring-credit");
            continue;
        }
        const clears = new Set(snapshot.credit.clears ?? []);
        const serverBlockers = snapshot.credit.blocking ?? [];
        if (serverBlockers.some(id => !snapshot.limits.some(limit => limit.id === id))) {
            skip("unsupported-window");
            continue;
        }
        const exhausted = [
            ...new Set([...snapshot.limits.filter(isExhausted).map(limit => limit.id), ...serverBlockers]),
        ];
        if (exhausted.some(id => !clears.has(id)) ||
            (snapshot.credit.program === JUNIPER_PROGRAM && exhausted.some(id => id !== FIVE_HOUR_LIMIT_ID))) {
            skip("incomplete-coverage");
            continue;
        }
        const covered = claudeCoveredLimits(snapshot.limits, snapshot.credit);
        if (covered.length === 0) {
            skip("unsupported-window");
            continue;
        }
        const fullest = fullestClaudeLimit(covered, snapshot.credit);
        if (!fullest || (!imminent && fullest.used < SALVAGE_MIN_USED_FRACTION)) {
            skip("window-mostly-free");
            continue;
        }
        if (snapshot.credit.requiresLimit === true && serverBlockers.length === 0 && !covered.some(isExhausted)) {
            skip("no-blocked-window");
            continue;
        }
        const attemptKey = claudeSalvageAttemptKey(snapshot.accountKey, snapshot.credit.id, snapshot.credit.remainingCount ?? 0, expiresAtMs);
        const episodeSkip = skipForEpisode(input, snapshot.accountKey, attemptKey, { imminent });
        if (episodeSkip) {
            skip(episodeSkip);
            continue;
        }
        salvages.push({
            reason: "expiring-credit",
            target: snapshot.target,
            accountKey: snapshot.accountKey,
            attemptKey,
            label: snapshot.label,
            availableCount: snapshot.availableCount,
            expiresInMs: expiresAtMs - input.nowMs,
            salvageWindow: fullest.limit.id,
            salvageUsedFraction: fullest.used,
            active: snapshot.active,
            program: snapshot.credit.program ?? "",
            title: snapshot.credit.title,
            requiresLimit: snapshot.credit.requiresLimit === true,
        });
    }
    salvages.sort((left, right) => (left.expiresInMs ?? 0) - (right.expiresInMs ?? 0));
    return { actions: restore ? [restore, ...salvages] : salvages, skipped };
}
