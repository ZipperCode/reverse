import type { Agent, AgentMessage, AgentTool } from "@reverse/agent";
import type { Message, Model, ToolChoice } from "@reverse/ai";
import { isRecord, logger, prompt, stringProperty } from "@reverse/utils";
import type { Settings } from "../config/settings";
import eagerTaskPrompt from "../prompts/system/eager-task.md" with { type: "text" };
import eagerTodoPrompt from "../prompts/system/eager-todo.md" with { type: "text" };
import midRunTodoNudgePrompt from "../prompts/system/mid-run-todo-nudge.md" with { type: "text" };
import {
	cloneTodoPhases,
	evaluateToolSemanticOutcome,
	extractBranchToolExecutions,
	getLatestTodoPhasesFromEntries,
	isTodoPhase,
	matchesToolTargetCriterion,
	maxTodoGeneration,
	nextActionableTask,
	type ObservedToolExecutionResult,
	reconcileAndValidateTodoPhases,
	TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE,
	type TodoCompletionValidation,
	validateTodoTaskCompletion,
} from "../tools/todo";
import {
	type TodoEvidenceRecord,
	type TodoFailureRecord,
	type TodoItem,
	type TodoPhase,
} from "@reverse/tui/tools/todo";
import { buildNamedToolChoice } from "../utils/tool-choice";
import type { AgentSessionEvent } from "./agent-session-events";
import type { SessionManager } from "./session-manager";

import { cfgTaskBatch, cfgTaskEager } from "../task/settings";
import { cfgTodoEager, cfgTodoEnabled, cfgTodoReminders, cfgTodoRemindersMax } from "../tools/settings";

const MID_RUN_NUDGE_MUTATION_THRESHOLD = 12;
const MID_RUN_NUDGE_MAX_PER_CYCLE = 2;
const MUTATING_TOOLS: Record<string, true> = {
	bash: true,
	eval: true,
	edit: true,
	write: true,
	ast_edit: true,
};
const MID_RUN_NUDGE_MESSAGE_TYPE = "mid-run-todo-nudge";
/** Message type of the hidden first-turn reminder {@link TodoTracker.createEagerTodoPrelude} builds. */
export const EAGER_TODO_PRELUDE_MESSAGE_TYPE = "eager-todo-prelude";

/** Capabilities the todo tracker borrows from its owning session. */
export interface TodoTrackerHost {
	agent: Agent;
	sessionManager: SessionManager;
	settings: Settings;
	model(): Model | undefined;
	agentKind(): "main" | "sub";
	emitSessionEvent(event: AgentSessionEvent): Promise<void>;
	scheduleAgentContinue(options: { source: string; generation?: number }): void;
	promptGeneration(): number;
	hasPendingAsyncWake(): boolean;
	getActiveToolNames(): string[];
	getEnabledToolNames(): string[];
	toolRegistry(): Map<string, AgentTool>;
	planModeEnabled(): boolean;
	/** Whether prewalk will hand off after its plan nudge owns todo creation. */
	prewalkWillHandoff(): boolean;
	consumeLastServedToolChoiceLabel(): string | undefined;
}

/** Owns canonical todo state, eager preludes, and completion reminders. */
interface ToolCallReservation {
	toolName: string;
	args?: unknown;
	activeTaskContent?: string;
	generation: number;
}

const BENIGN_EXPLORATORY_TOOLS: Record<string, true> = {
	read: true,
	glob: true,
	grep: true,
	todo: true,
};

const MAX_RECENT_EXECUTIONS = 128;

/** Owns canonical todo state, eager preludes, and completion reminders. */
export class TodoTracker {
	readonly #host: TodoTrackerHost;
	#phases: TodoPhase[] = [];
	#reminderCount = 0;
	#reminderAwaitingProgress = false;
	#mutationsSinceLastTouch = 0;
	#midRunNudgeCount = 0;
	#callReservations = new Map<string, ToolCallReservation>();
	#recordedCallIds = new Set<string>();
	#recentExecutions: ObservedToolExecutionResult[] = [];
	#allBlockedReminderSent = false;
	#touchedWorkflowIds = new Set<string>();
	constructor(host: TodoTrackerHost) {
		this.#host = host;
	}

	/** Returns a defensive clone of the current todo phases. */
	get phases(): TodoPhase[] {
		return cloneTodoPhases(this.#phases);
	}

	/** Replaces todo phases with a defensive clone, preserving immutable acceptance metadata. */
	setPhases(phases: TodoPhase[]): void {
		if (phases.length === 0) {
			this.#phases = [];
			this.#midRunNudgeCount = 0;
			return;
		}
		const { phases: reconciled, errors } = reconcileAndValidateTodoPhases(
			this.#phases,
			phases,
			this.#allObservedExecutions(),
			this.#host.sessionManager.getCwd(),
		);
		if (errors.length > 0) {
			throw new Error(errors.join("; "));
		}
		this.#phases = reconciled;
		// Every state write lands here — the native tool, a Cursor sync, or a
		// bridged call — so the nudge budget re-arms on the progress it
		// rations. Views, failed batches, and unchanged reads never arrive.
		this.#midRunNudgeCount = 0;
	}

	/** Validates whether a task may transition to completed against observed session tool executions. */
	validateCompletion(
		task: TodoItem,
		phases: readonly TodoPhase[] = this.#phases,
		citedCallIds?: readonly string[],
	): TodoCompletionValidation {
		return validateTodoTaskCompletion(
			task,
			phases,
			this.#allObservedExecutions(),
			citedCallIds,
			this.#host.sessionManager.getCwd(),
		);
	}

	/** Rehydrates todo phases from the current transcript branch. */
	syncFromBranch(): void {
		const branch = this.#host.sessionManager.getBranch();
		this.#callReservations.clear();
		this.#recordedCallIds.clear();
		this.#recentExecutions = extractBranchToolExecutions(branch).slice(-MAX_RECENT_EXECUTIONS);
		for (const exec of this.#recentExecutions) {
			this.#recordedCallIds.add(exec.toolCallId);
		}
		this.#phases = cloneTodoPhases(getLatestTodoPhasesFromEntries(branch));
		this.#midRunNudgeCount = 0;
	}

	/** Returns a defensive clone suitable for snapshots and branch state. */
	clonePhases(phases: TodoPhase[]): TodoPhase[] {
		return cloneTodoPhases(phases);
	}

	/** Resets per-prompt reminder and mutation budgets. */
	resetCycle(): void {
		this.#reminderCount = 0;
		this.#reminderAwaitingProgress = false;
		this.#mutationsSinceLastTouch = 0;
		this.#midRunNudgeCount = 0;
		this.#callReservations.clear();
		this.#allBlockedReminderSent = false;
		this.#touchedWorkflowIds.clear();
	}

	/** Records an active workflow ID touched during the current prompt cycle. */
	recordTouchedWorkflowId(id: string): void {
		if (typeof id === "string" && id.trim().length > 0) {
			this.#touchedWorkflowIds.add(id.trim());
		}
	}

	/** Returns workflow IDs touched in the current prompt cycle (reconstructing from recent branch if empty). */
	getTouchedWorkflowIds(): string[] {
		if (this.#touchedWorkflowIds.size > 0) {
			return Array.from(this.#touchedWorkflowIds);
		}
		const branch = this.#host.sessionManager.getBranch();
		for (let i = branch.length - 1; i >= 0; i--) {
			const entry = branch[i];
			if (entry.type === "message") {
				if (entry.message.role === "user") break;
				if (entry.message.role === "toolResult" && entry.message.isError !== true && entry.message.details) {
					for (const id of extractWorkflowIdsFromDetails(entry.message.details, entry.message.toolName)) {
						this.#touchedWorkflowIds.add(id);
					}
				}
			}
		}
		return Array.from(this.#touchedWorkflowIds);
	}

	/**
	 * Captures the active todo task and plan generation at tool-call dispatch time,
	 * before concurrent `todo` mutations in the same batch can advance the pointer.
	 */
	beforeToolCall(toolCallId: string, toolName: string, args: unknown): void {
		if (!toolCallId || toolName === "todo") return;
		const existing = this.#callReservations.get(toolCallId);
		if (existing) {
			// Non-loop nested xd:// dispatch reuses the outer write toolCallId; preserve
			// the call-start active task and generation while refining the inner tool/args.
			existing.toolName = toolName;
			existing.args = args;
			return;
		}
		if (this.#callReservations.size >= MAX_RECENT_EXECUTIONS) {
			const oldest = this.#callReservations.keys().next().value;
			if (oldest !== undefined) this.#callReservations.delete(oldest);
		}
		this.#callReservations.set(toolCallId, {
			toolName,
			args,
			activeTaskContent: nextActionableTask(this.#phases)?.content,
			generation: maxTodoGeneration(this.#phases),
		});
	}

	/** Removes a call-start reservation when a tool call is blocked or cancelled before completion. */
	cancelToolCall(toolCallId: string): void {
		this.#callReservations.delete(toolCallId);
	}

	/** Records completion of a bridged tool call (eval / extension wrapper preflight). */
	onBridgedToolResult(
		toolCallId: string,
		result: { content?: unknown; details?: unknown; isError?: boolean; useless?: boolean },
	): void {
		const reservation = this.#callReservations.get(toolCallId);
		this.#callReservations.delete(toolCallId);
		if (!reservation) return;
		const isError = Boolean(result.isError);
		if (!isError && MUTATING_TOOLS[reservation.toolName]) {
			this.#mutationsSinceLastTouch++;
		}
		this.#reminderAwaitingProgress = false;
		if (!isError && result.details) {
			for (const wfId of extractWorkflowIdsFromDetails(result.details, reservation.toolName)) {
				this.#touchedWorkflowIds.add(wfId);
			}
		}
		this.#recordObservedToolOutcome({
			toolCallId,
			toolName: reservation.toolName,
			args: reservation.args,
			details: result.details,
			isError,
			useless: result.useless,
			activeTaskContent: reservation.activeTaskContent,
			generation: reservation.generation,
		});
	}

	/** Records a completed tool result before asynchronous event processing begins. */
	onToolResult(
		toolName: string,
		isError: boolean,
		message?: {
			toolCallId?: string;
			toolName?: string;
			details?: unknown;
			content?: unknown;
			isError?: boolean;
			useless?: boolean;
			timestamp?: number;
		},
	): void {
		if (toolName === "todo") {
			this.#mutationsSinceLastTouch = 0;
		} else if (!isError && MUTATING_TOOLS[toolName]) {
			this.#mutationsSinceLastTouch++;
		}
		this.#reminderAwaitingProgress = false;
		if (!isError && message?.details) {
			for (const wfId of extractWorkflowIdsFromDetails(message.details, message.toolName ?? toolName)) {
				this.#touchedWorkflowIds.add(wfId);
			}
		}
		if (toolName === "todo" || !message) return;

		const toolCallId = typeof message.toolCallId === "string" ? message.toolCallId : undefined;
		if (!toolCallId) return;
		const reservation = this.#callReservations.get(toolCallId);
		this.#callReservations.delete(toolCallId);

		const resolvedArgs = reservation?.args ?? this.#findToolCallArgsInMessages(toolCallId);
		const activeTaskContent = reservation?.activeTaskContent ?? nextActionableTask(this.#phases)?.content;
		const generation = reservation?.generation ?? maxTodoGeneration(this.#phases);

		this.#recordObservedToolOutcome({
			toolCallId,
			toolName: message.toolName ?? toolName,
			args: resolvedArgs,
			details: message.details,
			isError: Boolean(message.isError ?? isError),
			useless: message.useless,
			timestamp: message.timestamp,
			activeTaskContent,
			generation,
		});
	}

	/** Detects whether a successful todo result came from an init operation. */
	onTodoResultDetails(details: Record<string, unknown>, toolCallId: string | undefined): boolean {
		const phases = details.phases;
		if (!Array.isArray(phases) || !phases.every(isTodoPhase)) return false;
		const detailOp = stringProperty(details, "op");
		if (detailOp) return detailOp === "init";
		if (!toolCallId) return false;
		for (let index = this.#host.agent.state.messages.length - 1; index >= 0; index--) {
			const message = this.#host.agent.state.messages[index];
			if (!message) continue;
			const op = toolCallOpFromMessage(message, toolCallId);
			if (op) return op === "init";
		}
		return false;
	}

	/** Builds the first-turn eager todo prelude and optional forced tool choice. */
	createEagerTodoPrelude(
		promptText: string | undefined,
	): { message: AgentMessage; toolChoice?: ToolChoice } | undefined {
		const mode = cfgTodoEager.get(this.#host.settings);
		if (mode === "default" || !cfgTodoEnabled.get(this.#host.settings)) return undefined;
		if (this.#host.planModeEnabled() || this.#phases.length > 0) return undefined;
		// An actionable prewalk drives todo creation in a plan-first-then-todo order;
		// the forced eager prelude's "call todo first this turn" contradicts it (#10510).
		if (this.#host.prewalkWillHandoff()) return undefined;
		if (promptText !== undefined) {
			if (this.#host.agent.state.messages.some(message => message.role === "user")) return undefined;
			const trimmedPromptText = promptText.trimEnd();
			if (trimmedPromptText.endsWith("?") || trimmedPromptText.endsWith("!")) return undefined;
		}
		const activeToolNames = this.#host.getActiveToolNames();
		if (!activeToolNames.includes("todo")) {
			logger.warn("Eager todo enforcement skipped because todo is not active", { activeToolNames });
			return undefined;
		}
		const message: AgentMessage = {
			role: "custom",
			customType: EAGER_TODO_PRELUDE_MESSAGE_TYPE,
			content: prompt.render(eagerTodoPrompt, { ...this.#buildEagerPreludeContext(), forced: mode === "always" }),
			display: false,
			attribution: "agent",
			timestamp: Date.now(),
		};
		if (promptText === undefined || mode === "preferred") return { message };
		const model = this.#host.model();
		const toolChoice = buildNamedToolChoice("todo", model);
		if (!toolChoice) {
			logger.warn(
				"Eager todo proceeding with the reminder only because the current model does not support a forced todo tool_choice",
				{ modelApi: model?.api, modelId: model?.id },
			);
			return { message };
		}
		return { message, toolChoice };
	}

	/** Builds the first-turn eager task-delegation prelude. */
	createEagerTaskPrelude(promptText: string | undefined): AgentMessage | undefined {
		if (cfgTaskEager.get(this.#host.settings) !== "always") return undefined;
		if (this.#host.agentKind() === "sub" || this.#host.planModeEnabled()) return undefined;
		if (promptText !== undefined) {
			if (this.#host.agent.state.messages.some(message => message.role === "user")) return undefined;
			const trimmed = promptText.trimEnd();
			if (trimmed.endsWith("?") || trimmed.endsWith("!")) return undefined;
		}
		if (!this.#host.getEnabledToolNames().includes("task")) return undefined;
		return {
			role: "custom",
			customType: "eager-task-prelude",
			content: prompt.render(eagerTaskPrompt, this.#buildEagerPreludeContext()),
			display: false,
			attribution: "agent",
			timestamp: Date.now(),
		};
	}

	/** Builds reminder-only eager preludes after compaction. */
	buildPostCompactionEagerNudges(): AgentMessage[] {
		const nudges: AgentMessage[] = [];
		const todo = this.createEagerTodoPrelude(undefined);
		if (todo) nudges.push(todo.message);
		const task = this.createEagerTaskPrelude(undefined);
		if (task) nudges.push(task);
		return nudges;
	}

	/** 根据待办状态安排有界续推，不依赖助手正文。 */
	async checkCompletion(): Promise<boolean> {
		if (this.#host.consumeLastServedToolChoiceLabel() === "user-force") return false;
		if (this.#host.planModeEnabled()) return false;
		if (this.#host.hasPendingAsyncWake()) {
			logger.debug("Todo completion: async jobs in flight will re-wake the loop; skipping reminder");
			return false;
		}
		if (this.#reminderAwaitingProgress) {
			logger.debug("Todo completion: prior reminder still awaiting agent action; staying silent", {
				attempt: this.#reminderCount,
			});
			return false;
		}
		if (
			!cfgTodoReminders.get(this.#host.settings) ||
			!cfgTodoEnabled.get(this.#host.settings) ||
			!this.#host.getActiveToolNames().includes("todo")
		) {
			this.#reminderCount = 0;
			this.#reminderAwaitingProgress = false;
			return false;
		}
		const remindersMax = cfgTodoRemindersMax.get(this.#host.settings);
		if (this.#reminderCount >= remindersMax) {
			logger.debug("Todo completion: max reminders reached", { count: this.#reminderCount });
			return false;
		}
		const phases = this.phases;
		if (phases.length === 0) {
			this.#reminderCount = 0;
			this.#reminderAwaitingProgress = false;
			return false;
		}
		const incompleteByPhase = phases
			.map(phase => ({
				name: phase.name,
				tasks: phase.tasks
					.filter(
						(task): task is TodoItem & { status: "pending" | "in_progress" } =>
							task.status === "pending" || task.status === "in_progress",
					)
					.map(task => ({ content: task.content, status: task.status })),
			}))
			.filter(phase => phase.tasks.length > 0);
		const actionable = incompleteByPhase.flatMap(phase => phase.tasks);

		if (actionable.length > 0) {
			this.#reminderCount++;
			const todoList = incompleteByPhase
				.map(phase => `- ${phase.name}\n${phase.tasks.map(task => `  - ${task.content}`).join("\n")}`)
				.join("\n");
			const reminder =
				`<system-reminder>\n` +
				`You stopped with ${actionable.length} incomplete todo item(s):\n${todoList}\n\n` +
				`Please continue working on these tasks or mark them complete if finished.\n` +
				`(Reminder ${this.#reminderCount}/${remindersMax})\n` +
				`</system-reminder>`;
			logger.debug("Todo completion: sending reminder", {
				incomplete: actionable.length,
				attempt: this.#reminderCount,
			});
			await this.#host.emitSessionEvent({
				type: "todo_reminder",
				todos: actionable,
				attempt: this.#reminderCount,
				maxAttempts: remindersMax,
			});
			const reminderMessage: Message = {
				role: "developer",
				content: [{ type: "text", text: reminder }],
				attribution: "agent",
				timestamp: Date.now(),
			};
			this.#mutationsSinceLastTouch = 0;
			this.#reminderAwaitingProgress = true;
			this.#host.agent.appendMessage(reminderMessage);
			this.#host.sessionManager.appendMessage(reminderMessage);
			this.#host.scheduleAgentContinue({
				source: "todo-reminder",
				generation: this.#host.promptGeneration(),
			});
			return true;
		}

		const allTasks = phases.flatMap(phase => phase.tasks);
		const blocked = allTasks.filter((task): task is TodoItem & { status: "blocked" } => task.status === "blocked");

		if (blocked.length > 0) {
			if (!this.#allBlockedReminderSent && this.#reminderCount < remindersMax) {
				this.#allBlockedReminderSent = true;
				this.#reminderCount++;
				this.#mutationsSinceLastTouch = 0;
				this.#reminderAwaitingProgress = true;

				const blockedList = blocked
					.map(task => `- ${task.content}${task.blocker ? ` (阻塞原因: ${task.blocker})` : ""}`)
					.join("\n");
				const reminder =
					`<system-reminder>\n` +
					`当前所有未完成待办项 (${blocked.length} 项) 均处于阻塞状态 (blocked):\n${blockedList}\n\n` +
					`若存在你可自主执行的解阻措施，请继续执行；若确实需要外部决策、授权或环境支持，请明确向用户报告具体阻塞原因，不得虚标完成或假定任务已成功。\n` +
					`(纠偏提醒 ${this.#reminderCount}/${remindersMax})\n` +
					`</system-reminder>`;

				logger.debug("Todo completion: sending all-blocked correction reminder", {
					blocked: blocked.length,
					attempt: this.#reminderCount,
				});
				await this.#host.emitSessionEvent({
					type: "todo_reminder",
					todos: blocked,
					attempt: this.#reminderCount,
					maxAttempts: remindersMax,
				});
				const reminderMessage: Message = {
					role: "developer",
					content: [{ type: "text", text: reminder }],
					attribution: "agent",
					timestamp: Date.now(),
				};
				this.#host.agent.appendMessage(reminderMessage);
				this.#host.sessionManager.appendMessage(reminderMessage);
				this.#host.scheduleAgentContinue({
					source: "todo-reminder",
					generation: this.#host.promptGeneration(),
				});
				return true;
			}
			return false;
		}

		this.#reminderCount = 0;
		this.#reminderAwaitingProgress = false;
		return false;
	}

	/** Takes the next hidden mid-run reconciliation nudge, if its budget and guards allow. */
	takeMidRunNudge(): AgentMessage | null {
		if (this.#mutationsSinceLastTouch < MID_RUN_NUDGE_MUTATION_THRESHOLD) return null;
		if (this.#midRunNudgeCount >= MID_RUN_NUDGE_MAX_PER_CYCLE) return null;
		if (!cfgTodoEnabled.get(this.#host.settings) || !cfgTodoReminders.get(this.#host.settings)) return null;
		if (this.#host.planModeEnabled() || !this.#host.getActiveToolNames().includes("todo")) return null;
		const incomplete = this.#phases
			.flatMap(phase => phase.tasks)
			.filter(task => task.status === "pending" || task.status === "in_progress");
		if (incomplete.length === 0) return null;
		this.#mutationsSinceLastTouch = 0;
		this.#midRunNudgeCount++;
		const { toolRefs } = this.#buildEagerPreludeContext();
		const reminder = prompt.render(midRunTodoNudgePrompt, {
			toolRefs,
			incompleteCount: incomplete.length,
			plural: incomplete.length !== 1,
		});
		logger.debug("Mid-run todo nudge fired", {
			incomplete: incomplete.length,
			nudge: this.#midRunNudgeCount,
		});
		return {
			role: "custom",
			customType: MID_RUN_NUDGE_MESSAGE_TYPE,
			content: reminder,
			display: false,
			attribution: "agent",
			timestamp: Date.now(),
		};
	}

	#buildEagerPreludeContext(): { toolRefs: Record<string, string>; taskBatch: boolean } {
		const wireName = (name: string): string => {
			const tool = this.#host.toolRegistry().get(name);
			return typeof tool?.customWireName === "string" ? tool.customWireName : name;
		};
		return {
			toolRefs: { task: wireName("task"), todo: wireName("todo") },
			taskBatch: cfgTaskBatch.get(this.#host.settings),
		};
	}

	#allObservedExecutions(): ObservedToolExecutionResult[] {
		const branchExecs = extractBranchToolExecutions(this.#host.sessionManager.getBranch());
		if (this.#recentExecutions.length === 0) return branchExecs;
		const byId = new Map<string, ObservedToolExecutionResult>();
		for (const exec of branchExecs) byId.set(exec.toolCallId, exec);
		for (const exec of this.#recentExecutions) byId.set(exec.toolCallId, exec);
		return [...byId.values()];
	}

	#findToolCallArgsInMessages(toolCallId: string): Record<string, unknown> | undefined {
		const messages = this.#host.agent.state.messages;
		for (let i = messages.length - 1; i >= 0; i--) {
			const msg = messages[i];
			if (!msg || msg.role !== "assistant" || !Array.isArray(msg.content)) continue;
			for (const block of msg.content) {
				if (!isRecord(block) || block.type !== "toolCall" || block.id !== toolCallId) continue;
				return isRecord(block.arguments) ? block.arguments : undefined;
			}
		}
		return undefined;
	}

	#recordObservedToolOutcome(input: {
		toolCallId: string;
		toolName: string;
		args?: unknown;
		details?: unknown;
		isError: boolean;
		useless?: boolean;
		timestamp?: number;
		activeTaskContent?: string;
		generation: number;
	}): void {
		if (this.#recordedCallIds.has(input.toolCallId)) return;
		const outcome = evaluateToolSemanticOutcome(
			input.toolName,
			input.details,
			input.isError,
			input.args,
			input.useless,
		);
		if (outcome.ignored) return;

		if (this.#recordedCallIds.size >= MAX_RECENT_EXECUTIONS) {
			const oldestCallId = this.#recordedCallIds.values().next().value;
			if (oldestCallId !== undefined) this.#recordedCallIds.delete(oldestCallId);
		}
		this.#recordedCallIds.add(input.toolCallId);
		const observed: ObservedToolExecutionResult = {
			toolCallId: input.toolCallId,
			toolName: input.toolName,
			effectiveToolName: outcome.effectiveToolName,
			action: outcome.action,
			target: outcome.target,
			args: outcome.effectiveArgs,
			details: input.details,
			isError: input.isError,
			semanticSuccess: outcome.semanticSuccess,
			isReadinessFailure: outcome.isReadinessFailure,
			failureReason: outcome.failureReason,
			timestamp: input.timestamp ?? Date.now(),
			generation: input.generation,
			activeTaskContent: input.activeTaskContent,
		};
		if (this.#recentExecutions.length >= MAX_RECENT_EXECUTIONS) {
			this.#recentExecutions.shift();
		}
		this.#recentExecutions.push(observed);

		if (this.#phases.length === 0) return;

		let mutatedPhases = false;
		const nextPhases = cloneTodoPhases(this.#phases);
		// Work executed under a fallback task belongs to that fallback, never to the task it
		// substitutes for: it can neither clear the original's failures nor satisfy its acceptance.
		const fallbackOfByContent = new Map<string, string>();
		for (const phase of nextPhases) {
			for (const candidate of phase.tasks) {
				if (candidate.fallbackOf !== undefined) fallbackOfByContent.set(candidate.content, candidate.fallbackOf);
			}
		}
		for (const phase of nextPhases) {
			for (const task of phase.tasks) {
				if (
					input.activeTaskContent !== undefined &&
					input.activeTaskContent !== task.content &&
					fallbackOfByContent.has(input.activeTaskContent)
				) {
					continue;
				}
				const cwd = this.#host.sessionManager.getCwd();
				const isActiveTask = input.activeTaskContent !== undefined && task.content === input.activeTaskContent;
				const matchingAcceptance = (task.acceptance ?? []).filter(criterion =>
					matchesToolTargetCriterion(criterion, observed, cwd),
				);

				if (!outcome.semanticSuccess) {
					const expectsError =
						matchingAcceptance.length > 0 &&
						matchingAcceptance.every(c => c.expectedOutcome === "expected_error");
					if (expectsError) {
						const evRecord: TodoEvidenceRecord = {
							toolCallId: observed.toolCallId,
							tool: observed.effectiveToolName,
							semanticSuccess: false,
							isError: observed.isError,
							timestamp: observed.timestamp,
							generation: observed.generation,
						};
						if (observed.action !== undefined) evRecord.action = observed.action;
						if (observed.target !== undefined) evRecord.target = observed.target;
						task.evidence = [
							...(task.evidence ?? []).filter(e => e.toolCallId !== evRecord.toolCallId),
							evRecord,
						];
						mutatedPhases = true;
						continue;
					}

					const isSubstantiveFailure =
						outcome.isReadinessFailure ||
						matchingAcceptance.length > 0 ||
						!BENIGN_EXPLORATORY_TOOLS[outcome.effectiveToolName];

					if ((isActiveTask && isSubstantiveFailure) || matchingAcceptance.length > 0) {
						const failureRec: TodoFailureRecord = {
							toolCallId: observed.toolCallId,
							tool: observed.effectiveToolName,
							reason: outcome.failureReason ?? "tool execution failed",
							isReadinessFailure: outcome.isReadinessFailure,
							timestamp: observed.timestamp,
							generation: observed.generation,
						};
						if (observed.action !== undefined) failureRec.action = observed.action;
						if (observed.target !== undefined) failureRec.target = observed.target;
						const existingFailures = task.unresolvedFailures ?? [];
						if (!existingFailures.some(f => f.toolCallId === failureRec.toolCallId)) {
							task.unresolvedFailures = [...existingFailures, failureRec];
							mutatedPhases = true;
						}
						// A new failure for the same tool/action/target supersedes prior positive evidence on that target.
						if (task.evidence && task.evidence.length > 0) {
							const filteredEv = task.evidence.filter(
								ev =>
									!matchesToolTargetCriterion(
										{ tool: ev.tool, action: ev.action, target: ev.target },
										observed,
										cwd,
									),
							);
							if (filteredEv.length !== task.evidence.length) {
								task.evidence = filteredEv.length > 0 ? filteredEv : undefined;
								mutatedPhases = true;
							}
						}
					}
				} else {
					// Semantic success: check if it resolves any unresolvedFailures on this task.
					if (task.unresolvedFailures && task.unresolvedFailures.length > 0) {
						const remainingFailures = task.unresolvedFailures.filter(
							f =>
								!matchesToolTargetCriterion(
									{ tool: f.tool, action: f.action, target: f.target },
									observed,
									cwd,
								),
						);
						if (remainingFailures.length !== task.unresolvedFailures.length) {
							task.unresolvedFailures = remainingFailures.length > 0 ? remainingFailures : undefined;
							const evRecord: TodoEvidenceRecord = {
								toolCallId: observed.toolCallId,
								tool: observed.effectiveToolName,
								semanticSuccess: true,
								timestamp: observed.timestamp,
								generation: observed.generation,
							};
							if (observed.action !== undefined) evRecord.action = observed.action;
							if (observed.target !== undefined) evRecord.target = observed.target;
							task.evidence = [
								...(task.evidence ?? []).filter(e => e.toolCallId !== evRecord.toolCallId),
								evRecord,
							];
							mutatedPhases = true;
						}
					}
					// Also record evidence if it satisfies a positive acceptance criterion on this task.
					if (matchingAcceptance.some(c => (c.expectedOutcome ?? "success") === "success")) {
						const evRecord: TodoEvidenceRecord = {
							toolCallId: observed.toolCallId,
							tool: observed.effectiveToolName,
							semanticSuccess: true,
							timestamp: observed.timestamp,
							generation: observed.generation,
						};
						if (observed.action !== undefined) evRecord.action = observed.action;
						if (observed.target !== undefined) evRecord.target = observed.target;
						task.evidence = [
							...(task.evidence ?? []).filter(e => e.toolCallId !== evRecord.toolCallId),
							evRecord,
						];
						mutatedPhases = true;
					}
				}
			}
		}

		if (mutatedPhases) {
			this.#phases = nextPhases;
		}
		// Persist durable execution snapshot when phases mutated or when a bridged/active tool ran under an active todo plan.
		if (mutatedPhases || input.activeTaskContent !== undefined) {
			this.#host.sessionManager.appendCustomEntry(TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE, {
				phases: cloneTodoPhases(this.#phases),
				execution: observed,
			});
		}
	}
}

function toolCallOpFromMessage(message: AgentMessage, toolCallId: string): string | undefined {
	if (message.role !== "assistant" || !Array.isArray(message.content)) return undefined;
	for (const block of message.content) {
		if (!isRecord(block) || block.type !== "toolCall" || block.id !== toolCallId) continue;
		return isRecord(block.arguments) ? stringProperty(block.arguments, "op") : undefined;
	}
	return undefined;
}

const DOMAIN_WORKFLOW_TOOLS: Record<string, true> = {
	reverse_workflow: true,
	reverse_workspace: true,
	reverse_runtime_session: true,
};

/**
 * Extracts reverse engineering workflow IDs from tool result details (including xdev.inner wrapper).
 * Only domain workflow tools (reverse_workflow, reverse_workspace, reverse_runtime_session)
 * or explicit xd:// dispatches to these tools are trusted into the active workflow scope.
 */
export function extractWorkflowIdsFromDetails(details: unknown, toolName?: string): string[] {
	if (!isRecord(details)) return [];
	let effectiveTool = toolName;
	let effective = details;

	if (isRecord(details.xdev)) {
		if (typeof details.xdev.tool === "string") {
			effectiveTool = details.xdev.tool;
		}
		if (isRecord(details.xdev.inner)) {
			effective = details.xdev.inner as Record<string, unknown>;
		}
	}

	if (!effectiveTool || !DOMAIN_WORKFLOW_TOOLS[effectiveTool]) {
		return [];
	}

	const ids = new Set<string>();
	if (
		isRecord(effective.workflow) &&
		typeof effective.workflow.id === "string" &&
		effective.workflow.id.trim().length > 0
	) {
		ids.add(effective.workflow.id.trim());
	}
	if (
		isRecord(effective.step) &&
		typeof effective.step.workflow_id === "string" &&
		effective.step.workflow_id.trim().length > 0
	) {
		ids.add(effective.step.workflow_id.trim());
	}
	if (typeof effective.workflow_id === "string" && effective.workflow_id.trim().length > 0) {
		ids.add(effective.workflow_id.trim());
	}
	return Array.from(ids);
}
