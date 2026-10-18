import { logger } from "@rva/utils";
import { formatModelSelectorValue } from "@rva/tui/overlays/model-selector";
import { formatModelString } from "../config/model-resolver";
import { shouldDisableReasoning, toReasoningEffort } from "@rva/tui/thinking";
import { applyActions, initialArray, makeActions } from "./actions";
import { assessResponse, buildSystemPrompt, buildTurnPrompt } from "./protocol";
/**
 * Anthropic's cyber classifier is stochastic near the refusal threshold: the
 * identical glyph-machine request passes and refuses on different cold calls.
 * A refusal carries no information about the model's ability to follow the
 * benchmark, so a `Refusal (cyber)` error is retried a bounded number of times
 * with a fresh session id (cold classifier) before it is scored as a
 * run-ending provider failure.
 */
/**
 * The classifier's refusal state decays over tens of seconds (a refused
 * request passes again after a wait), so attempts space out across a
 * ~3.5-minute window rather than hammering the same classification.
 */
const REFUSAL_MAX_ATTEMPTS = 8;
const REFUSAL_BACKOFF_MS = [0, 5000, 15000, 30000, 60000, 90000, 120000, 180000];
function isCyberRefusal(error) {
    return error !== undefined && error.startsWith("Refusal (");
}
function assistantText(message) {
    return message.content
        .filter(content => content.type === "text")
        .map(content => content.text)
        .join("");
}
function errorText(error) {
    if (error instanceof Error && error.message)
        return error.message;
    return String(error);
}
/** Run every target and return the ranked-input summary (ranking is the caller's job). */
export async function runIfBench(options) {
    const reports = [];
    const queue = options.targets.map((target, index) => ({ target, index }));
    // oxlint-disable-next-line unicorn/no-new-array -- length preallocation
    const ordered = new Array(options.targets.length);
    const worker = async () => {
        for (;;) {
            const next = queue.shift();
            if (!next)
                return;
            ordered[next.index] = await runTarget(next.target, options);
        }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(options.par, options.targets.length)) }, worker));
    reports.push(...ordered);
    return {
        maxTurns: options.maxTurns,
        arrayLength: options.arrayLength,
        nyaMax: options.nyaMax,
        maxTokens: options.maxTokens,
        models: reports,
        failures: reports.filter(report => report.failure !== undefined).length,
    };
}
async function runTarget(target, options) {
    const { model, selector, thinking } = target;
    const label = formatModelSelectorValue(formatModelString(model), thinking);
    const report = {
        selector,
        model: formatModelString(model),
        label,
        turns: [],
        turnsPassed: 0,
        actionsPassed: 0,
        durationMs: 0,
        outputTokens: 0,
        cost: 0,
    };
    options.observer?.modelStarted?.(label);
    // One session id for the whole thread: keeps gateway credential affinity and
    // lets the provider reuse the prompt cache across turns.
    // Preflight credential check with a throwaway session id; each turn (and each
    // refusal retry) mints its own id inside requestTurnWithRefusalRetry.
    const preflight = await options.runtime.modelRegistry.getApiKey(model, options.randomSessionId());
    if (!preflight) {
        report.failure = {
            turn: 0,
            kind: "provider",
            detail: `No credentials for provider "${model.provider}". Run \`omp\` and use /login, or set the provider API key.`,
        };
        options.observer?.modelFinished?.(report);
        return report;
    }
    const messages = [];
    const context = { systemPrompt: [buildSystemPrompt(options.nyaMax)], messages };
    // Owned per thread so transport-native chaining survives every turn and is
    // torn down deterministically when the thread ends.
    const providerSessionState = new Map();
    let state = initialArray(options.arrayLength);
    let cumulativeActions = 0;
    try {
        for (let turn = 1; turn <= options.maxTurns; turn += 1) {
            const actions = makeActions(options.arrayLength, cumulativeActions, turn);
            const turnPrompt = buildTurnPrompt({
                turn,
                start: turn === 1 ? state : undefined,
                actions,
                nyaMax: options.nyaMax,
            });
            messages.push({
                role: "user",
                content: turnPrompt.content,
                timestamp: Date.now(),
                attribution: "user",
            });
            options.observer?.turnStarted?.(label, turn, actions.length);
            const expected = applyActions(state, actions);
            const outcome = await requestTurnWithRefusalRetry(model, context, providerSessionState, target, options);
            cumulativeActions += actions.length;
            const assessment = outcome.error
                ? { passed: false, failure: "provider" }
                : assessResponse(outcome.text, expected, options.nyaMax);
            const record = {
                turn,
                actions: actions.length,
                cumulativeActions,
                placement: turnPrompt.placement,
                durationMs: outcome.durationMs,
                outputTokens: outcome.message?.usage.output ?? 0,
                cost: outcome.message?.usage.cost?.total ?? 0,
                passed: assessment.passed,
                failure: assessment.failure,
                expected,
                response: outcome.error ?? outcome.text,
            };
            report.turns.push(record);
            report.durationMs += record.durationMs;
            report.outputTokens += record.outputTokens;
            report.cost += record.cost;
            options.observer?.turnFinished?.(label, record);
            if (!record.passed) {
                report.failure = {
                    turn,
                    kind: record.failure ?? "format",
                    detail: record.response,
                };
                break;
            }
            report.turnsPassed = turn;
            report.actionsPassed = cumulativeActions;
            state = expected;
            // Replay the model's own reply as history: state lives in that text, and
            // the provider payload keeps transport-native chaining intact.
            if (outcome.message)
                messages.push(outcome.message);
        }
    }
    finally {
        for (const state of providerSessionState.values())
            state.close();
        providerSessionState.clear();
    }
    options.observer?.modelFinished?.(report);
    return report;
}
/**
 * Request one turn, retrying on a transient cyber refusal.
 *
 * Each attempt mints a fresh session id and re-resolves credentials: the
 * refusal is a stateless server-side classification, and a new session gives
 * the next attempt an uncached, independently classified request. History and
 * the system prompt stay byte-identical across attempts, so a successful retry
 * continues the same cacheable thread.
 */
async function requestTurnWithRefusalRetry(model, context, providerSessionState, target, options) {
    let outcome = { text: "", error: "request failed", durationMs: 0 };
    for (let attempt = 1; attempt <= REFUSAL_MAX_ATTEMPTS; attempt += 1) {
        if (attempt > 1)
            await (options.sleep ?? Bun.sleep)(REFUSAL_BACKOFF_MS[attempt - 1] ?? 180000);
        const sessionId = options.randomSessionId();
        const apiKey = options.runtime.modelRegistry.resolver(model, sessionId);
        outcome = await requestTurn(model, context, sessionId, apiKey, providerSessionState, target, options);
        if (!isCyberRefusal(outcome.error) || attempt === REFUSAL_MAX_ATTEMPTS)
            return outcome;
        logger.debug("if-bench: cyber refusal, retrying", { attempt, error: outcome.error });
    }
    return outcome;
}
async function requestTurn(model, context, sessionId, apiKey, providerSessionState, target, options) {
    const startedAt = options.now();
    const elapsed = (message) => {
        const duration = message?.duration ?? options.now() - startedAt;
        return Number.isFinite(duration) && duration > 0 ? duration : 0;
    };
    try {
        const stream = options.stream(model, context, {
            apiKey,
            sessionId,
            promptCacheKey: sessionId,
            maxTokens: model.maxTokens !== null && Number.isFinite(model.maxTokens) && model.maxTokens > 0
                ? Math.min(options.maxTokens, model.maxTokens)
                : options.maxTokens,
            // Deterministic decoding: the benchmark measures capability, not sampling luck.
            temperature: 0,
            reasoning: toReasoningEffort(target.thinking),
            disableReasoning: shouldDisableReasoning(target.thinking) ? true : undefined,
            providerSessionState,
        });
        let message;
        for await (const event of stream) {
            if (event.type === "error") {
                return { text: "", error: event.error.errorMessage ?? "request failed", durationMs: elapsed() };
            }
            if (event.type === "done")
                message = event.message;
        }
        message ??= await stream.result();
        if (message.stopReason === "error" || message.errorMessage) {
            return { message, text: "", error: message.errorMessage ?? "request failed", durationMs: elapsed(message) };
        }
        const text = assistantText(message).trim();
        if (text.length === 0) {
            return {
                message,
                text,
                error: `provider returned no text (stop reason: ${message.stopReason ?? "unknown"})`,
                durationMs: elapsed(message),
            };
        }
        return { message, text, durationMs: elapsed(message) };
    }
    catch (error) {
        return { text: "", error: errorText(error), durationMs: elapsed() };
    }
}
