import {
	type AfterToolCallContext,
	type AfterToolCallResult,
	type Agent,
	type AgentEvent,
	type AgentMessage,
	type AgentTool,
	type AgentToolResult,
	type AgentTurnEndContext,
	type BeforeToolCallContext,
	type BeforeToolCallResult,
	createToolScopedAbortReason,
} from "@reverse/agent";
import type { AssistantMessage, AssistantMessageEvent, Model, ToolCall } from "@reverse/ai";
import { GeminiHeaderRunDetector } from "@reverse/ai/utils/thinking-loop";
import {
	type DeterministicDispatchFailure,
	normalizeDeterministicDispatchFailure,
	type RepeatedDispatchFailureDetection,
	type RepeatedToolCallDetection,
	ToolCallLoopGuard,
} from "@reverse/ai/utils/tool-call-loop-guard";
import { logger, prompt } from "@reverse/utils";
import type { Settings } from "../config/settings";
import geminiToolReminderTemplate from "../prompts/system/gemini-tool-call-reminder.md" with { type: "text" };
import streamingEditRecoveryTemplate from "../prompts/system/streaming-edit-recovery.md" with { type: "text" };
import type { CustomMessage } from "./messages";
import type { SessionManager } from "./session-manager";
import {
	dispatchFailureRedirectDetails,
	renderDispatchFailureRedirect,
	renderToolCallLoopRedirect,
	TOOL_CALL_LOOP_DISPATCH_FAILURE_REDIRECT_TYPE,
	TOOL_CALL_LOOP_REDIRECT_TYPE,
	toolCallLoopRedirectDetails,
} from "./tool-call-loop-redirect";

import { cfgEditStreamingAbort } from "../edit/settings";
import {
	cfgModelLoopGuardEnabled,
	cfgModelLoopGuardToolCallReminder,
	cfgModelToolCallLoopGuardEnabled,
	cfgModelToolCallLoopGuardExemptTools,
	cfgModelToolCallLoopGuardThreshold,
} from "./settings";

const GEMINI_HEADER_INTERRUPT_REASON = "Interrupted: emit a tool call instead of more planning";
const GEMINI_TOOL_REMINDER_TYPE = "gemini-tool-call-reminder";
/** Abort reason (and aborted-message `errorMessage`) for a failed streamed edit preview. */
const STREAMING_EDIT_ABORT_REASON = "Streaming edit preview failed";
const STREAMING_EDIT_RECOVERY_TYPE = "streaming-edit-recovery";
/**
 * Recovery continuations allowed per user prompt. Each failed preview spends
 * one; when the budget is spent the guard stops and warns instead of looping
 * on a patch the model keeps re-emitting.
 */
const STREAMING_EDIT_RECOVERY_LIMIT = 2;
/** Notice `source` label for streaming-edit guard messages. */
const STREAMING_EDIT_NOTICE_SOURCE = "streaming-edit";
// Prefix of the native no-op diagnostic emitted by the Rust edit engine when a
// preview produces byte-identical content. Kept in sync with
// crates/pi-edit/src/modes/replace.rs and crates/pi-edit/src/hashline/preview.rs
// ("No changes would be made to <path>..."). Prefix match (not equality)
// because the Rust messages append the path and mode-specific suffixes.
const NO_CHANGES_PREVIEW_PREFIX = "No changes would be made";
/** Bridged tool names remembered between a bridge pre-dispatch check and its result. */
const BRIDGED_TOOL_NAME_LIMIT = 256;
/** Native blocked call ids remembered until their synthetic result is normalized. */
const BLOCKED_TOOL_CALL_LIMIT = 16;

/**
 * Reads a tool's pure dispatch precondition verdict. Core's optional
 * `AgentTool.getDispatchFailure` is the only source; absent means the call
 * would dispatch. A throwing validator is a tool bug and must never block
 * legitimate work, so it degrades to "would dispatch".
 */
function readToolDispatchFailure(tool: AgentTool, args: unknown): DeterministicDispatchFailure | undefined {
	if (!tool.getDispatchFailure) return undefined;
	try {
		return normalizeDeterministicDispatchFailure(tool.getDispatchFailure(args));
	} catch {
		return undefined;
	}
}

/**
 * Block reason for a reissued deterministic rejection. Names the producer's
 * correction message instead of claiming identical arguments: a reworded
 * request can carry the same broken precondition.
 */
function dispatchFailureBlockReason(failure: RepeatedDispatchFailureDetection): string {
	return `Not executed: \`${failure.toolName}\` still cannot dispatch for the same reason it was rejected ${failure.count} times (${failure.code}): ${failure.message} Correct what that message reports before calling it again.`;
}

/** Capabilities borrowed by the session's streaming and loop guards. */
export interface StreamGuardsHost {
	agent: Agent;
	settings: Settings;
	sessionManager: SessionManager;
	model(): Model | undefined;
	isDisposed(): boolean;
	promptGeneration(): number;
	/** Monotonic per-prompt counter; changes on each user/agent prompt start. */
	promptSequence(): number;
	emitNotice(level: "info" | "warning" | "error", message: string, source?: string): void;
	schedulePostPromptTask(task: (signal: AbortSignal) => Promise<void>): void;
	discardAssistantTurn(message: AssistantMessage): void;
}

/** Guards streamed edit calls against invalid final previews. */
export class StreamingEditGuard {
	readonly #host: StreamGuardsHost;
	#abortTriggered = false;
	/** Prompt sequence the recovery budget below belongs to. */
	#recoverySequence = -1;
	/** Recovery continuations already spent for {@link #recoverySequence}. */
	#recoveryCount = 0;

	constructor(host: StreamGuardsHost) {
		this.#host = host;
	}

	/** Whether the current turn was aborted by streaming edit validation. */
	get abortTriggered(): boolean {
		return this.#abortTriggered;
	}

	/** Clears all turn-scoped streaming edit state. */
	reset(): void {
		this.#abortTriggered = false;
	}

	/** Aborts an edit when the native engine's final preview reports an error. */
	maybeAbort(event: AgentEvent): void {
		if (
			!cfgEditStreamingAbort.get(this.#host.settings) ||
			this.#abortTriggered ||
			event.type !== "tool_stream_update" ||
			event.toolName !== "edit"
		) {
			return;
		}
		const update = event.update;
		if (
			update === null ||
			typeof update !== "object" ||
			!("streaming" in update) ||
			update.streaming !== false ||
			!("files" in update) ||
			!Array.isArray(update.files)
		) {
			return;
		}
		const files: unknown[] = update.files;
		const failed = files.find(
			(file): file is { path: string; error: string } =>
				file !== null &&
				typeof file === "object" &&
				"path" in file &&
				typeof file.path === "string" &&
				"error" in file &&
				typeof file.error === "string" &&
				file.error.length > 0 &&
				!file.error.startsWith(NO_CHANGES_PREVIEW_PREFIX),
		);
		if (failed) this.#abortPatch({ toolCallId: event.toolCallId, filePath: failed.path, error: failed.error });
	}

	#abortPatch(opts: { toolCallId: string; filePath: string; error: string }): void {
		const { toolCallId, filePath, error } = opts;
		this.#abortTriggered = true;
		logger.warn("Streaming edit aborted due to patch preview failure", { toolCallId, path: filePath, error });
		const diagnostic = `${STREAMING_EDIT_ABORT_REASON} for ${filePath}: ${error}`;
		this.#host.agent.abort(
			createToolScopedAbortReason(
				STREAMING_EDIT_ABORT_REASON,
				{ [toolCallId]: diagnostic },
				STREAMING_EDIT_ABORT_REASON,
			),
		);
		this.#scheduleRecovery({ diagnostic });
	}

	/**
	 * Re-drives the run after a failed streamed edit preview so the model can
	 * correct the patch instead of losing the turn. One recovery message (with
	 * the preview diagnostic) is appended per failure; the budget is shared per
	 * user prompt and a spent budget stops with a warning instead of looping.
	 */
	#scheduleRecovery(opts: { diagnostic: string }): void {
		const sequence = this.#host.promptSequence();
		if (this.#recoverySequence !== sequence) {
			this.#recoverySequence = sequence;
			this.#recoveryCount = 0;
		}
		this.#recoveryCount++;
		if (this.#recoveryCount > STREAMING_EDIT_RECOVERY_LIMIT) {
			logger.warn("Streaming edit recovery budget exhausted", {
				sequence,
				recoveries: this.#recoveryCount - 1,
			});
			this.#host.emitNotice(
				"warning",
				`Streaming edit preview failed ${this.#recoveryCount} times; stopped auto-recovery for this prompt.`,
				STREAMING_EDIT_NOTICE_SOURCE,
			);
			return;
		}
		const diagnostic = opts.diagnostic;
		const attempt = this.#recoveryCount;
		const generation = this.#host.promptGeneration();
		this.#host.schedulePostPromptTask(async signal => {
			if (signal.aborted || this.#host.isDisposed()) return;
			if (this.#host.promptGeneration() !== generation || this.#host.promptSequence() !== sequence) return;
			await this.#host.agent.waitForIdle();
			if (signal.aborted || this.#host.isDisposed()) return;
			if (this.#host.promptGeneration() !== generation || this.#host.promptSequence() !== sequence) return;
			const content = prompt.render(streamingEditRecoveryTemplate, { diagnostic });
			this.#host.agent.appendMessage({
				role: "custom",
				customType: STREAMING_EDIT_RECOVERY_TYPE,
				content,
				display: false,
				attribution: "agent",
				timestamp: Date.now(),
			});
			this.#host.sessionManager.appendCustomMessageEntry(STREAMING_EDIT_RECOVERY_TYPE, content, false);
			this.#host.emitNotice(
				"info",
				`Streaming edit preview failed; retrying with the error context (attempt ${attempt}/${STREAMING_EDIT_RECOVERY_LIMIT}).`,
				STREAMING_EDIT_NOTICE_SOURCE,
			);
			try {
				await this.#host.agent.continue();
			} catch (error) {
				logger.warn("streaming edit recovery continue failed", { error: String(error) });
			}
		});
	}
}

/** Detects cross-turn tool loops and Gemini reasoning-header runaways. */
export class LoopGuards {
	readonly #host: StreamGuardsHost;
	#geminiHeaderDetector: GeminiHeaderRunDetector | undefined;
	#toolCallLoopGuard: ToolCallLoopGuard | undefined;
	#toolCallLoopGuardSettingsKey: string | undefined;
	/** Prompt sequence the loop guard state belongs to; a new prompt resets it. */
	#loopGuardPromptSequence: number | undefined;
	/** Session id the loop guard state belongs to; switching sessions resets it too. */
	#loopGuardSessionId: string | undefined;
	/** Bridged call id → tool name, so the bridge result hook can clear/count without one. */
	#bridgedToolNames = new Map<string, string>();
	/** Native calls this guard blocked, so their synthetic results carry observable metadata. */
	#blockedToolCallIds = new Set<string>();
	/** The turn's batch was stopped before dispatch; its synthetic turn earns no new warning. */
	#blockedTurnPending = false;

	constructor(host: StreamGuardsHost) {
		this.#host = host;
	}

	/**
	 * Native pre-dispatch gate. Blocks a call whose deterministic precondition
	 * already failed at the threshold, or a batch reproducing the last warned
	 * identical repetition, before `tool_execution_start`, approval, and child
	 * spawn; `stopTurn` then yields without another provider request.
	 */
	beforeToolCall(ctx: BeforeToolCallContext): BeforeToolCallResult | undefined {
		const guard = this.#activeToolCallLoopGuard();
		if (!guard) return undefined;
		// Compare against the arguments that would actually run: validation
		// normalization or an extension revision may already have repaired the
		// call, which must never be blocked by the model's stale arguments.
		guard.recordDispatchedArgs(ctx.toolCall.id, ctx.args);
		// The tool's own precondition verdict is authoritative for structured
		// rejections: `undefined` after a configuration fix unlocks the same
		// arguments even if they also matched a warned identical batch.
		const failure = readToolDispatchFailure(ctx.tool, ctx.args);
		const toolCalls = ctx.assistantMessage.content.filter((part): part is ToolCall => part.type === "toolCall");
		// Exact repetition is judged only on the last prepared call of the batch:
		// every call's final (post-revision) arguments must be known, otherwise a
		// later extension repair would be pre-empted by a stale raw match. A call
		// that never prepares (invalid schema / extension block) leaves the exact
		// stop unavailable for that batch; semantic checks still run per call.
		const repeatedBatch = guard.hasAllDispatchedArgs(toolCalls) ? guard.blockedRepeatedBatch(toolCalls) : null;
		if (repeatedBatch) {
			logger.warn("blocked repeated tool-call batch after a loop redirect", {
				toolName: repeatedBatch.toolName,
				count: repeatedBatch.count,
			});
			this.#rememberBlockedToolCall(ctx.toolCall.id);
			this.#blockedTurnPending = true;
			return {
				block: true,
				stopTurn: true,
				reason: `Not executed: \`${repeatedBatch.toolName}\` was already called ${repeatedBatch.count} times in a row with the same arguments. Change the arguments or the approach instead of resending that batch.`,
			};
		}
		const blocked = guard.blockedDispatchFailure(ctx.tool.name, failure);
		if (!blocked) return undefined;
		logger.warn("blocked repeated deterministic tool dispatch failure", {
			toolName: blocked.toolName,
			code: blocked.code,
			count: blocked.count,
		});
		this.#rememberBlockedToolCall(ctx.toolCall.id);
		this.#blockedTurnPending = true;
		return { block: true, stopTurn: true, reason: dispatchFailureBlockReason(blocked) };
	}

	/**
	 * Native post-execution observation: normalizes a result this guard blocked
	 * (observable `toolCallLoopGuard.blocked` metadata, never a dispatch
	 * failure), clears a tool's history on success, and counts a deterministic
	 * rejection.
	 */
	afterToolCall(ctx: AfterToolCallContext): AfterToolCallResult | undefined {
		if (this.#blockedToolCallIds.delete(ctx.toolCall.id)) {
			const previousDetails = ctx.result.details;
			const base =
				previousDetails && typeof previousDetails === "object" && !Array.isArray(previousDetails)
					? previousDetails
					: {};
			return {
				details: { ...base, unexecuted: true, executed: false, toolCallLoopGuard: { blocked: true } },
				isError: true,
			};
		}
		this.#activeToolCallLoopGuard()?.observeToolResult({
			toolCallId: ctx.toolCall.id,
			toolName: ctx.toolCall.name,
			isError: ctx.isError,
			details: ctx.result.details,
		});
		return undefined;
	}

	/**
	 * Bridge (eval / extension wrapper) pre-dispatch gate. Bridge hooks return a
	 * plain `{ block, reason }`; the host must preserve the blocked result and
	 * stop the turn before the next provider request when `stopTurn` is set.
	 */
	beforeBridgedToolCall(toolCallId: string, tool: AgentTool, args: unknown): BeforeToolCallResult | undefined {
		const guard = this.#activeToolCallLoopGuard();
		if (!guard) return undefined;
		const failure = guard.blockedDispatchFailure(tool.name, readToolDispatchFailure(tool, args));
		if (failure) {
			logger.warn("blocked repeated deterministic tool dispatch failure (bridge)", {
				toolName: failure.toolName,
				code: failure.code,
				count: failure.count,
			});
			return { block: true, stopTurn: true, reason: dispatchFailureBlockReason(failure) };
		}
		if (this.#bridgedToolNames.size >= BRIDGED_TOOL_NAME_LIMIT) {
			const oldest = this.#bridgedToolNames.keys().next().value;
			if (oldest !== undefined) this.#bridgedToolNames.delete(oldest);
		}
		this.#bridgedToolNames.set(toolCallId, tool.name);
		return undefined;
	}

	/** Bridge post-execution observation for the tool name remembered at dispatch. */
	afterBridgedToolCall(toolCallId: string, result: AgentToolResult<unknown>): void {
		const toolName = this.#bridgedToolNames.get(toolCallId);
		if (toolName === undefined) return;
		this.#bridgedToolNames.delete(toolCallId);
		this.#activeToolCallLoopGuard()?.observeToolResult({
			toolCallId,
			toolName,
			isError: result.isError === true,
			details: result.details,
		});
	}

	/** Drops the remembered bridge dispatch (blocked, cancelled, or never executed). */
	cancelBridgedToolCall(toolCallId: string): void {
		this.#bridgedToolNames.delete(toolCallId);
	}

	/** Records a completed turn and injects a redirect when calls repeat. */
	recordTurn(messages: AgentMessage[], context: AgentTurnEndContext | undefined): void {
		if (context?.message.role !== "assistant") return;
		const guard = this.#activeToolCallLoopGuard();
		if (!guard) return;
		const stoppedBeforeDispatch = this.#blockedTurnPending;
		this.#blockedTurnPending = false;
		const detection = stoppedBeforeDispatch
			? null
			: guard.recordTurn({
					message: context.message,
					toolResults: context.toolResults,
					injectedContext: (context.additionalMessages?.length ?? 0) > 0,
				});
		if (detection) this.#injectToolCallLoopRedirect(messages, detection);
		for (const warning of guard.drainDispatchFailureWarnings()) {
			this.#injectDispatchFailureRedirect(messages, warning);
		}
	}

	/** Feeds a streamed assistant event to the Gemini header-runaway detector. */
	onAssistantEvent(message: AssistantMessage, event: AssistantMessageEvent): void {
		if (event.type === "thinking_start") {
			this.#geminiHeaderDetector = this.#geminiHeaderGuardActive() ? new GeminiHeaderRunDetector() : undefined;
			return;
		}
		const detector = this.#geminiHeaderDetector;
		if (!detector) return;
		if (event.type === "thinking_delta") {
			if (detector.push(event.delta)) this.#interruptGeminiHeaderRunaway(detector.count, message.timestamp);
			return;
		}
		if (event.type === "text_start" || event.type === "toolcall_start") detector.reset();
	}

	#activeToolCallLoopGuard(): ToolCallLoopGuard | undefined {
		// A new prompt is a true boundary: accumulated repetitions and
		// deterministic-failure buckets from the previous prompt cannot block a
		// fresh request. A session switch changes the id and resets too.
		const sequence = this.#host.promptSequence();
		const sessionId = this.#host.sessionManager.getSessionId();
		if (this.#loopGuardPromptSequence !== sequence || this.#loopGuardSessionId !== sessionId) {
			this.#loopGuardPromptSequence = sequence;
			this.#loopGuardSessionId = sessionId;
			this.#toolCallLoopGuard?.reset();
			this.#bridgedToolNames.clear();
			this.#blockedToolCallIds.clear();
			this.#blockedTurnPending = false;
		}
		if (cfgModelToolCallLoopGuardEnabled.get(this.#host.settings) !== true) {
			this.#toolCallLoopGuard = undefined;
			this.#toolCallLoopGuardSettingsKey = undefined;
			return undefined;
		}
		const threshold = cfgModelToolCallLoopGuardThreshold.get(this.#host.settings);
		const exemptTools = cfgModelToolCallLoopGuardExemptTools
			.get(this.#host.settings)
			.filter((tool): tool is string => typeof tool === "string" && tool.length > 0);
		const settingsKey = `${threshold}:${JSON.stringify(exemptTools)}`;
		if (!this.#toolCallLoopGuard || this.#toolCallLoopGuardSettingsKey !== settingsKey) {
			this.#toolCallLoopGuard = new ToolCallLoopGuard({ threshold, exemptTools });
			this.#toolCallLoopGuardSettingsKey = settingsKey;
		}
		return this.#toolCallLoopGuard;
	}

	#rememberBlockedToolCall(toolCallId: string): void {
		if (this.#blockedToolCallIds.size >= BLOCKED_TOOL_CALL_LIMIT) {
			const oldest = this.#blockedToolCallIds.values().next().value;
			if (oldest !== undefined) this.#blockedToolCallIds.delete(oldest);
		}
		this.#blockedToolCallIds.add(toolCallId);
	}

	#injectToolCallLoopRedirect(messages: AgentMessage[], detection: RepeatedToolCallDetection): void {
		logger.warn("cross-turn tool-call loop detected", { toolName: detection.toolName, count: detection.count });
		const content = renderToolCallLoopRedirect(detection);
		const details = toolCallLoopRedirectDetails(detection);
		const redirectMessage: CustomMessage = {
			role: "custom",
			customType: TOOL_CALL_LOOP_REDIRECT_TYPE,
			content,
			display: false,
			details,
			attribution: "agent",
			timestamp: Date.now(),
		};
		messages.push(redirectMessage);
		if (this.#host.agent.state.messages !== messages) this.#host.agent.appendMessage(redirectMessage);
		this.#host.sessionManager.appendCustomMessageEntry(
			TOOL_CALL_LOOP_REDIRECT_TYPE,
			content,
			false,
			details,
			"agent",
		);
	}

	#injectDispatchFailureRedirect(messages: AgentMessage[], detection: RepeatedDispatchFailureDetection): void {
		logger.warn("deterministic tool dispatch failure loop detected", {
			toolName: detection.toolName,
			code: detection.code,
			count: detection.count,
		});
		const content = renderDispatchFailureRedirect(detection);
		const details = dispatchFailureRedirectDetails(detection);
		const redirectMessage: CustomMessage = {
			role: "custom",
			customType: TOOL_CALL_LOOP_DISPATCH_FAILURE_REDIRECT_TYPE,
			content,
			display: false,
			details,
			attribution: "agent",
			timestamp: Date.now(),
		};
		messages.push(redirectMessage);
		if (this.#host.agent.state.messages !== messages) this.#host.agent.appendMessage(redirectMessage);
		this.#host.sessionManager.appendCustomMessageEntry(
			TOOL_CALL_LOOP_DISPATCH_FAILURE_REDIRECT_TYPE,
			content,
			false,
			details,
			"agent",
		);
	}

	#geminiHeaderGuardActive(): boolean {
		const model = this.#host.model();
		return (
			cfgModelLoopGuardEnabled.get(this.#host.settings) === true &&
			cfgModelLoopGuardToolCallReminder.get(this.#host.settings) === true &&
			model !== undefined &&
			model.identity.class === "gemini"
		);
	}

	#interruptGeminiHeaderRunaway(headerCount: number, targetTimestamp: number): void {
		const model = this.#host.model();
		logger.warn("Gemini reasoning-header runaway; interrupting to require a tool call", {
			model: model?.id,
			provider: model?.provider,
			headers: headerCount,
		});
		this.#host.emitNotice(
			"warning",
			`Interrupted ${headerCount} planning headers with no tool call; reminded the model to issue one.`,
			"loop-guard",
		);
		this.#host.agent.abort(GEMINI_HEADER_INTERRUPT_REASON);
		const generation = this.#host.promptGeneration();
		this.#host.schedulePostPromptTask(async signal => {
			if (signal.aborted || this.#host.isDisposed() || this.#host.promptGeneration() !== generation) return;
			await this.#host.agent.waitForIdle();
			if (signal.aborted || this.#host.isDisposed() || this.#host.promptGeneration() !== generation) return;
			const aborted = this.#host.agent.state.messages.findLast(
				(message): message is AssistantMessage =>
					message.role === "assistant" && message.timestamp === targetTimestamp,
			);
			if (aborted) this.#host.discardAssistantTurn(aborted);
			const content = prompt.render(geminiToolReminderTemplate, { count: headerCount });
			const details = { headers: headerCount };
			this.#host.agent.appendMessage({
				role: "custom",
				customType: GEMINI_TOOL_REMINDER_TYPE,
				content,
				display: false,
				details,
				attribution: "agent",
				timestamp: Date.now(),
			});
			this.#host.sessionManager.appendCustomMessageEntry(
				GEMINI_TOOL_REMINDER_TYPE,
				content,
				false,
				details,
				"agent",
			);
			try {
				await this.#host.agent.continue();
			} catch (error) {
				logger.warn("gemini tool-call reminder continue failed", { error: String(error) });
			}
		});
	}
}
