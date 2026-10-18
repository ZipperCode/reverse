import * as os from "node:os";
import * as path from "node:path";
import { createToolScopedAbortReason, } from "@rva/agent";
import { logger, prompt, relativePathWithinRoot, withTimeout } from "@rva/utils";
import { judgeRules, } from "../export/ttsr";
import ttsrInterruptTemplate from "../prompts/system/ttsr-interrupt.md" with { type: "text" };
import ttsrToolReminderTemplate from "../prompts/system/ttsr-tool-reminder.md" with { type: "text" };
import ttsrWarningTemplate from "../prompts/system/ttsr-warning.md" with { type: "text" };
import { TtsrToolInspector } from "./ttsr-outputs";
/** How long a finishing run waits for in-flight judgments; later verdicts still arrive as asides. */
const JUDGED_SETTLE_TIMEOUT_MS = 5000;
/** Mid-stream checks may defer conditions that can span lines; the stream's end settles them. */
const PARTIAL_CHECK = { final: false };
const FINAL_CHECK = { final: true };
/** Coordinates TTSR stream matching, interruption, injection, and resume gates. */
export class TtsrCoordinator {
    #host;
    #manager;
    #inspector;
    #pendingInjections = [];
    #perToolInjections = new Map();
    #deferredReservations = new Map();
    #nextDeferredDeliveryId = 0;
    #abortPending = false;
    #retryToken = 0;
    #resumePromise;
    #resumeResolve;
    /** Rule names already announced per stream key: a delta match re-confirmed
     *  at finalization must not emit a second `ttsr_triggered` (#12184). */
    #emittedTriggerRules = new Map();
    /** In-flight judged-rule checks, each already guarded against rejection. */
    #pendingJudgments = new Set();
    constructor(host, manager) {
        this.#host = host;
        this.#manager = manager;
        this.#inspector = new TtsrToolInspector(() => host.agent.state.tools, () => host.sessionManager.getCwd());
    }
    /** Configured TTSR manager, when stream rules are enabled. */
    get manager() {
        return this.#manager;
    }
    /** Whether a TTSR-triggered stream abort is awaiting its continuation. */
    get abortPending() {
        return this.#abortPending;
    }
    /** Current resume gate awaited by post-prompt recovery. */
    get resumeGate() {
        return this.#resumePromise;
    }
    /** Resets stream buffers at turn start. */
    onTurnStart() {
        this.#manager?.resetBuffer();
    }
    /**
     * Resets stream buffers when an assistant message begins. The agent loop
     * turns the first provider `start` of every response into `message_start`,
     * so this is the boundary between two responses inside one turn (an aborted
     * response and its retry, or a continuation after an interruption); without
     * it, text from the earlier response would combine with the later one.
     */
    onAssistantMessageStart() {
        this.#manager?.resetBuffer();
    }
    /** Advances repeat-after-gap tracking at turn end. */
    onTurnEnd() {
        this.#manager?.incrementMessageCount();
        this.#emittedTriggerRules.clear();
    }
    /** Checks one streamed message update and reports whether TTSR consumed it by aborting. */
    async checkMessageUpdate(event) {
        if (event.type !== "message_update" || !this.#manager?.hasRules())
            return false;
        const assistantEvent = event.assistantMessageEvent;
        // A later `start` inside one response restarts its partial; the buffers
        // describe the discarded attempt and must not survive it.
        if (assistantEvent.type === "start") {
            this.#manager.resetBuffer();
            return false;
        }
        let matchContext;
        let streamingToolCall;
        let delta;
        let isFinal = false;
        if (assistantEvent.type === "text_delta") {
            matchContext = { source: "text" };
            delta = assistantEvent.delta;
        }
        else if (assistantEvent.type === "thinking_delta") {
            matchContext = { source: "thinking" };
            delta = assistantEvent.delta;
        }
        else if (assistantEvent.type === "toolcall_delta") {
            streamingToolCall = this.#getStreamingToolCallBlock(event.message, assistantEvent.contentIndex);
            matchContext = this.#inspector.matchContext(streamingToolCall, assistantEvent.contentIndex);
            delta = assistantEvent.delta;
        }
        else if (assistantEvent.type === "toolcall_end") {
            streamingToolCall = assistantEvent.toolCall;
            matchContext = this.#inspector.matchContext(streamingToolCall, assistantEvent.contentIndex);
            delta = "";
            isFinal = true;
        }
        else if ((assistantEvent.type === "text_end" || assistantEvent.type === "thinking_end") &&
            // An empty block streamed nothing; a pending TTSR abort already discards this response.
            assistantEvent.content.length > 0 &&
            !this.#abortPending) {
            matchContext = { source: assistantEvent.type === "text_end" ? "text" : "thinking" };
            delta = "";
            isFinal = true;
        }
        if (!matchContext || delta === undefined)
            return false;
        const targetMessageTimestamp = event.message.role === "assistant" ? event.message.timestamp : undefined;
        const matches = this.#checkStream(delta, matchContext, streamingToolCall, isFinal);
        if (matches.length > 0 && this.#handleMatches(matches, matchContext, targetMessageTimestamp))
            return true;
        return false;
    }
    /** AST parsing runs once on finalized arguments, before execution, not in
     * fire-and-forget stream listeners or on partial deltas. */
    async beforeToolCall(ctx) {
        if (!this.#manager?.hasAstRules())
            return undefined;
        const toolCall = { ...ctx.toolCall, arguments: ctx.args };
        const matchContext = this.#inspector.matchContext(toolCall, 0);
        const matches = await this.#checkAstStream(matchContext, toolCall);
        if (matches.length > 0 && this.#handleMatches(matches, matchContext, ctx.assistantMessage.timestamp)) {
            // Generation already ended: stop the tool turn before TTSR recovery retries it.
            const reason = this.#formatAbortReason(matches);
            ctx.assistantMessage.stopReason = "aborted";
            ctx.assistantMessage.errorMessage = reason;
            return { block: true, reason };
        }
        return undefined;
    }
    /** Checks finalized arguments for a tool call issued through eval or another non-loop bridge. */
    async beforeBridgedToolCall(toolCallId, tool, args) {
        if (!this.#manager?.hasRules())
            return undefined;
        const toolCall = { type: "toolCall", id: toolCallId, name: tool.name, arguments: args };
        const matchContext = this.#inspector.matchContext(toolCall, 0);
        let matches;
        try {
            matches = [
                ...this.#checkStream("", matchContext, toolCall, true),
                ...(await this.#checkAstStream(matchContext, toolCall)),
            ].filter((rule, index, all) => all.findIndex(candidate => candidate.name === rule.name) === index);
        }
        finally {
            if (matchContext.streamKey)
                this.#manager.clearStream(matchContext.streamKey);
        }
        if (matches.length === 0)
            return undefined;
        this.#emitTriggerOnce(matchContext, matches);
        if (!this.#shouldInterrupt(matches, matchContext)) {
            this.#addPerToolInjections(toolCallId, matches, { markInjected: false });
            return undefined;
        }
        const reminder = matches
            .map(rule => prompt.render(ttsrInterruptTemplate, {
            name: rule.name,
            path: this.#displayRulePath(rule.path),
            content: rule.content,
        }))
            .join("\n\n");
        this.#markInjected(matches.map(rule => rule.name));
        return { block: true, reason: this.#formatAbortReason(matches) + "\n" + reminder };
    }
    /** Settles the previous resume gate, queues any deferred injection, and starts judged-rule checks. */
    onAssistantMessageEnd(message) {
        // Gate on abortPending, not stopReason: unrelated aborts have no TTSR continuation.
        if (!this.#abortPending)
            this.resolveResume();
        this.#queueDeferredInjectionIfNeeded(message);
        this.#judgeCompletedMessage(message);
    }
    /**
     * Waits (bounded) for in-flight judged-rule checks. The session runs this
     * before the agent yields, so warnings about the final output join the run
     * as asides instead of reopening an idle session.
     */
    async settleJudgments() {
        if (this.#pendingJudgments.size === 0)
            return;
        try {
            await withTimeout(Promise.all(this.#pendingJudgments), JUDGED_SETTLE_TIMEOUT_MS, "judged rules still pending");
        }
        catch (error) {
            logger.debug("TTSR judged rules unsettled at yield", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    /** Marks names persisted with a delivered TTSR injection as injected. */
    markInjectedFromDetails(details) {
        if (!details || typeof details !== "object" || Array.isArray(details))
            return;
        const rules = "rules" in details ? details.rules : undefined;
        if (!Array.isArray(rules))
            return;
        const ruleNames = rules.filter((ruleName) => typeof ruleName === "string");
        this.#markInjected(ruleNames);
        this.releaseDeferredReservationFromDetails(details);
    }
    /** Releases a queued delivery that was discarded before persistence. */
    releaseDeferredReservationFromDetails(details) {
        if (!details || typeof details !== "object" || Array.isArray(details))
            return;
        const rules = "rules" in details ? details.rules : undefined;
        const deliveryId = "deliveryId" in details ? details.deliveryId : undefined;
        if (!Array.isArray(rules) || typeof deliveryId !== "number")
            return;
        const ruleNames = rules.filter((ruleName) => typeof ruleName === "string");
        this.#releaseDeferredReservation(deliveryId, ruleNames);
    }
    /** Delivers per-tool reminders through the trusted passive-context channel. */
    afterToolCall(ctx) {
        const reminder = this.#buildToolReminder(ctx.toolCall.id);
        return reminder ? { additionalContext: reminder } : undefined;
    }
    /**
     * Bridged calls (Cursor exec handlers, eval) bypass the agent loop's `afterToolCall`. When the caller
     * installed a passive-context sink the reminder goes there and the result stays untouched; without one
     * (eval-bridged calls) it is folded into the result as a leading block, the only channel left.
     */
    afterBridgedToolCall(toolCallId, result, context) {
        const reminder = this.#buildToolReminder(toolCallId);
        if (!reminder)
            return undefined;
        if (context?.addAdditionalContext) {
            context.addAdditionalContext(reminder);
            return undefined;
        }
        return { ...result, content: [{ type: "text", text: reminder }, ...result.content] };
    }
    cancelBridgedToolCall(toolCallId) {
        this.#perToolInjections.delete(toolCallId);
    }
    #buildToolReminder(toolCallId) {
        const rules = this.#perToolInjections.get(toolCallId);
        if (!rules || rules.length === 0)
            return undefined;
        this.#perToolInjections.delete(toolCallId);
        const reminder = rules
            .map(rule => prompt.render(ttsrToolReminderTemplate, {
            name: rule.name,
            path: this.#displayRulePath(rule.path),
            content: rule.content,
        }))
            .join("\n\n");
        const ruleNames = rules.map(rule => rule.name.trim()).filter(name => name.length > 0);
        if (ruleNames.length > 0)
            this.#markInjected(ruleNames);
        return reminder;
    }
    /** Resolves and clears the current resume gate. */
    resolveResume() {
        if (!this.#resumeResolve)
            return;
        this.#resumeResolve();
        this.#resumeResolve = undefined;
        this.#resumePromise = undefined;
    }
    #ensureResumePromise() {
        if (this.#resumePromise)
            return;
        const { promise, resolve } = Promise.withResolvers();
        this.#resumePromise = promise;
        this.#resumeResolve = resolve;
    }
    #formatAbortReason(rules) {
        const label = rules.length === 1 ? "rule" : "rules";
        return `TTSR matched ${label}: ${rules.map(rule => rule.name).join(", ")}`;
    }
    #getInjectionContent() {
        if (this.#pendingInjections.length === 0)
            return undefined;
        const rules = this.#pendingInjections;
        const content = rules
            .map(rule => prompt.render(ttsrInterruptTemplate, {
            name: rule.name,
            path: this.#displayRulePath(rule.path),
            content: rule.content,
        }))
            .join("\n\n");
        this.#pendingInjections = [];
        return { content, rules };
    }
    #displayRulePath(rulePath) {
        const cwd = this.#host.sessionManager.getCwd();
        const cwdRelative = relativePathWithinRoot(cwd, rulePath) ?? this.#displayPathWithinRoot(cwd, rulePath);
        if (cwdRelative)
            return cwdRelative;
        const homeRelative = relativePathWithinRoot(os.homedir(), rulePath);
        if (homeRelative)
            return `~/${homeRelative}`;
        return rulePath;
    }
    #displayPathWithinRoot(root, candidate) {
        const relative = path.relative(path.resolve(root), path.resolve(candidate));
        return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : null;
    }
    #addPendingInjections(rules) {
        const seen = new Set(this.#pendingInjections.map(rule => rule.name));
        for (const rule of rules) {
            if (seen.has(rule.name) || this.#deferredReservations.has(rule.name))
                continue;
            this.#pendingInjections.push(rule);
            seen.add(rule.name);
        }
    }
    #reserveDeferredInjection(rules) {
        const deliveryId = ++this.#nextDeferredDeliveryId;
        for (const rule of rules)
            this.#deferredReservations.set(rule.name, deliveryId);
        return deliveryId;
    }
    #releaseDeferredReservation(deliveryId, ruleNames) {
        for (const ruleName of ruleNames) {
            if (this.#deferredReservations.get(ruleName) === deliveryId)
                this.#deferredReservations.delete(ruleName);
        }
    }
    #extractToolCallId(matchContext) {
        if (matchContext.source !== "tool")
            return undefined;
        const key = matchContext.streamKey;
        if (typeof key !== "string" || !key.startsWith("toolcall:"))
            return undefined;
        const id = key.slice("toolcall:".length);
        return id.length > 0 ? id : undefined;
    }
    #addPerToolInjections(toolCallId, rules, { markInjected = true } = {}) {
        const bucket = this.#perToolInjections.get(toolCallId) ?? [];
        const seen = new Set(bucket.map(rule => rule.name));
        const claimedElsewhere = new Set();
        for (const [otherId, otherBucket] of this.#perToolInjections) {
            if (otherId === toolCallId)
                continue;
            for (const rule of otherBucket)
                claimedElsewhere.add(rule.name);
        }
        const newlyAdded = [];
        for (const rule of rules) {
            if (seen.has(rule.name) || claimedElsewhere.has(rule.name))
                continue;
            bucket.push(rule);
            seen.add(rule.name);
            newlyAdded.push(rule.name);
        }
        if (bucket.length === 0)
            return;
        this.#perToolInjections.set(toolCallId, bucket);
        if (markInjected && newlyAdded.length > 0)
            this.#manager?.markInjectedByNames(newlyAdded);
    }
    #markInjected(ruleNames) {
        const uniqueRuleNames = Array.from(new Set(ruleNames.map(ruleName => ruleName.trim()).filter(ruleName => ruleName.length > 0)));
        if (uniqueRuleNames.length === 0)
            return;
        this.#manager?.markInjectedByNames(uniqueRuleNames);
        this.#host.sessionManager.appendTtsrInjection(uniqueRuleNames);
    }
    /**
     * Announce a trigger unless this stream already announced these rules.
     * A delta match re-confirmed at `toolcall_end` evaluates the same buffer
     * twice before the message_end cooldown commits; subscribers must see one
     * event per violation, not one per evaluation.
     */
    #emitTriggerOnce(matchContext, matches) {
        const key = matchContext.streamKey;
        if (key) {
            let seen = this.#emittedTriggerRules.get(key);
            if (matches.every(match => seen?.has(match.name)))
                return;
            if (!seen) {
                seen = new Set();
                this.#emittedTriggerRules.set(key, seen);
            }
            for (const match of matches)
                seen.add(match.name);
        }
        this.#host.emitSessionEvent({ type: "ttsr_triggered", rules: matches }).catch(() => { });
    }
    #findAssistantIndex(targetTimestamp) {
        const messages = this.#host.agent.state.messages;
        for (let index = messages.length - 1; index >= 0; index--) {
            const message = messages[index];
            if (message.role === "assistant" && (targetTimestamp === undefined || message.timestamp === targetTimestamp)) {
                return index;
            }
        }
        return -1;
    }
    #shouldInterrupt(matches, matchContext) {
        const globalMode = this.#manager?.getSettings().interruptMode ?? "always";
        for (const rule of matches) {
            const mode = rule.interruptMode ?? globalMode;
            if (mode === "never")
                continue;
            if (mode === "prose-only" && (matchContext.source === "text" || matchContext.source === "thinking")) {
                return true;
            }
            if (mode === "tool-only" && matchContext.source === "tool")
                return true;
            if (mode === "always")
                return true;
        }
        return false;
    }
    #queueDeferredInjectionIfNeeded(message) {
        if (message.stopReason === "aborted" || message.stopReason === "error")
            this.#perToolInjections.clear();
        if (this.#abortPending || this.#pendingInjections.length === 0)
            return;
        if (message.stopReason === "aborted" || message.stopReason === "error") {
            this.#pendingInjections = [];
            return;
        }
        const injection = this.#getInjectionContent();
        if (!injection)
            return;
        const ruleNames = injection.rules.map(rule => rule.name);
        const deliveryId = this.#reserveDeferredInjection(injection.rules);
        try {
            this.#host.agent.followUp({
                role: "custom",
                customType: "ttsr-injection",
                content: injection.content,
                display: false,
                details: { rules: ruleNames, deliveryId },
                attribution: "agent",
                timestamp: Date.now(),
            });
        }
        catch (error) {
            this.#releaseDeferredReservation(deliveryId, ruleNames);
            throw error;
        }
        this.#ensureResumePromise();
        const releaseReservation = () => {
            this.#releaseDeferredReservation(deliveryId, ruleNames);
            this.resolveResume();
        };
        this.#host.scheduleAgentContinue({
            source: "ttsr-injection",
            delayMs: 1,
            generation: this.#host.promptGeneration(),
            onSkip: reason => {
                if (reason !== "should-continue-false")
                    releaseReservation();
            },
            shouldContinue: () => {
                // A running agent may already have taken the queued message. In that
                // case message_end remains the authority for committing the cooldown.
                if (this.#host.agent.state.isStreaming) {
                    this.resolveResume();
                    return false;
                }
                if (!this.#host.agent.hasQueuedMessages()) {
                    releaseReservation();
                    return false;
                }
                return true;
            },
            onError: releaseReservation,
        });
    }
    /**
     * Asks the judge about each completed output of `message` in the background.
     * Aborted and failed messages are skipped: their output never took effect.
     */
    #judgeCompletedMessage(message) {
        if (!this.#manager?.hasJudgedRules() || message.stopReason === "aborted" || message.stopReason === "error") {
            return;
        }
        const generation = this.#host.sessionGeneration();
        for (const output of this.#inspector.outputs(message)) {
            const pending = this.#judgeOutput(output, generation)
                .catch(error => {
                logger.warn("TTSR judged rule check failed", {
                    subject: output.subject,
                    error: error instanceof Error ? error.message : String(error),
                });
            })
                .finally(() => this.#pendingJudgments.delete(pending));
            this.#pendingJudgments.add(pending);
        }
    }
    /** One judge request per output: every eligible rule's question shares the billed state. */
    async #judgeOutput(output, generation) {
        const manager = this.#manager;
        if (!manager)
            return;
        const candidates = await manager.judgedCandidates(output.content, output.context);
        if (candidates.length === 0)
            return;
        const judge = this.#host.ruleJudge();
        if (!judge)
            return;
        const flagged = await judgeRules(judge, output, candidates);
        if (flagged.length === 0 || this.#host.sessionGeneration() !== generation)
            return;
        const rules = manager.claim(flagged);
        if (rules.length === 0)
            return;
        this.#host.emitSessionEvent({ type: "ttsr_triggered", rules }).catch(() => { });
        const warning = rules
            .map(rule => prompt.render(ttsrWarningTemplate, {
            name: rule.name,
            path: this.#displayRulePath(rule.path),
            subject: output.subject,
            content: rule.content,
        }))
            .join("\n\n");
        await this.#host.deliverRuleWarning(warning, rules.map(rule => rule.name));
    }
    #getStreamingToolCallBlock(message, contentIndex) {
        if (message.role !== "assistant")
            return undefined;
        const content = message.content;
        if (!Array.isArray(content) || contentIndex < 0 || contentIndex >= content.length)
            return undefined;
        const block = content[contentIndex];
        return block && typeof block === "object" && block.type === "toolCall" ? block : undefined;
    }
    #checkStream(delta, matchContext, toolCall, isFinal = false) {
        if (!this.#manager)
            return [];
        const options = isFinal ? FINAL_CHECK : PARTIAL_CHECK;
        const entries = this.#inspector.entries(toolCall);
        if (entries) {
            const matches = [];
            for (const entry of entries) {
                matches.push(...this.#manager.checkSnapshot(entry.digest, this.#inspector.perFileContext(matchContext, entry.path), options));
            }
            return matches;
        }
        const digest = this.#inspector.digest(toolCall);
        if (digest !== undefined)
            return this.#manager.checkSnapshot(digest, matchContext, options);
        // Tools without matcher hooks accumulate raw argument deltas. Providers
        // that emit toolcall_start -> toolcall_end with no intermediate deltas
        // (Cursor exec synthesis, OpenAI lossy-proxy fallback) leave that buffer
        // empty, so the finalized arguments must seed the snapshot themselves.
        const finalArgs = isFinal ? toolCall?.arguments : undefined;
        if (finalArgs !== undefined && finalArgs !== null) {
            const snapshot = typeof finalArgs === "string" ? finalArgs : JSON.stringify(finalArgs);
            return this.#manager.checkSnapshot(snapshot, matchContext);
        }
        return this.#manager.checkDelta(delta, matchContext, options);
    }
    async #checkAstStream(matchContext, toolCall) {
        if (!this.#manager)
            return [];
        const entries = this.#inspector.entries(toolCall);
        if (entries) {
            const matches = [];
            for (const entry of entries) {
                matches.push(...(await this.#manager.checkAstSnapshot(entry.digest, this.#inspector.perFileContext(matchContext, entry.path))));
            }
            return matches;
        }
        const digest = this.#inspector.digest(toolCall);
        return digest === undefined ? [] : this.#manager.checkAstSnapshot(digest, matchContext);
    }
    #handleMatches(matches, matchContext, targetTimestamp) {
        const shouldInterrupt = this.#shouldInterrupt(matches, matchContext);
        const matchedToolId = this.#extractToolCallId(matchContext);
        const perToolId = shouldInterrupt ? undefined : matchedToolId;
        if (perToolId) {
            this.#addPerToolInjections(perToolId, matches);
            this.#emitTriggerOnce(matchContext, matches);
            return false;
        }
        this.#addPendingInjections(matches);
        if (!shouldInterrupt)
            return false;
        this.#abortPending = true;
        this.#ensureResumePromise();
        const abortReason = this.#formatAbortReason(matches);
        this.#host.agent.abort(matchedToolId
            ? createToolScopedAbortReason(abortReason, { [matchedToolId]: abortReason }, "TTSR interrupt on another tool call")
            : abortReason);
        this.#emitTriggerOnce(matchContext, matches);
        const retryToken = ++this.#retryToken;
        const generation = this.#host.promptGeneration();
        this.#host.schedulePostPromptTask(async () => {
            if (this.#retryToken !== retryToken) {
                this.resolveResume();
                return;
            }
            const targetAssistantIndex = this.#findAssistantIndex(targetTimestamp);
            if (!this.#abortPending || this.#host.promptGeneration() !== generation || targetAssistantIndex === -1) {
                this.#abortPending = false;
                this.#pendingInjections = [];
                this.#perToolInjections.clear();
                this.resolveResume();
                return;
            }
            this.#abortPending = false;
            this.#perToolInjections.clear();
            if (this.#manager?.getSettings().contextMode === "discard") {
                this.#host.agent.replaceMessages(this.#host.agent.state.messages.slice(0, targetAssistantIndex));
            }
            const injection = this.#getInjectionContent();
            if (injection) {
                const details = { rules: injection.rules.map(rule => rule.name) };
                this.#host.agent.appendMessage({
                    role: "custom",
                    customType: "ttsr-injection",
                    content: injection.content,
                    display: false,
                    details,
                    attribution: "agent",
                    timestamp: Date.now(),
                });
                this.#host.sessionManager.appendCustomMessageEntry("ttsr-injection", injection.content, false, details, "agent");
                this.#markInjected(details.rules);
            }
            this.#host.scheduleAgentContinue({
                source: "ttsr-interrupt",
                generation,
                onSkip: () => this.resolveResume(),
                onError: () => this.resolveResume(),
            });
        }, { delayMs: 50 });
        return true;
    }
}
