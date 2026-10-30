import {
	type TodoStatus,
	type TodoOperation,
	type TodoExpectedOutcome,
	type TodoAcceptanceTarget,
	type TodoEvidenceRecord,
	type TodoFailureRecord,
	type TodoItem,
	type TodoPhase,
	type TodoCompletionTransition,
	type TodoToolDetails,
} from "@reverse/tui/tools/todo";
import { stripXdUrlPrefix } from "@reverse/tui/tools/xd-url";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback } from "@reverse/agent";

import { isRecord, prompt } from "@reverse/utils";
import todoDescription from "../prompts/tools/todo.md" with { type: "text" };
import type { ToolSession } from "../sdk";
import type { SessionEntry } from "../session/session-entries";

import { normalizePathLikeInput, resolveToCwd } from "./path-utils";

/** Whether an unknown value is a persisted todo phase. */
export function isTodoPhase(value: unknown): value is TodoPhase {
	if (!isRecord(value) || typeof value.name !== "string" || !Array.isArray(value.tasks)) return false;
	return value.tasks.every(
		task =>
			isRecord(task) &&
			typeof task.content === "string" &&
			(task.status === "pending" ||
				task.status === "in_progress" ||
				task.status === "completed" ||
				task.status === "abandoned" ||
				task.status === "blocked"),
	);
}

/**
 * Phases a successful, state-changing `todo` result committed, or undefined
 * for errors and pure `view` reads. A direct call lands these on the branch
 * through its own toolResult entry; a caller that produces no `todo`
 * toolResult (the eval bridge) must persist them itself or the next branch
 * rehydration (resume, rewind, fork, /btw) silently reverts the change.
 */
export function committedTodoPhases(result: AgentToolResult): TodoPhase[] | undefined {
	if (result.isError || !isRecord(result.details)) return undefined;
	const { op, phases } = result.details;
	if (op === "view" || !Array.isArray(phases) || !phases.every(isTodoPhase)) return undefined;
	return phases;
}

// =============================================================================
// Schema
// =============================================================================

const TodoOp = type('"init" | "start" | "done" | "rm" | "drop" | "block" | "unblock" | "append" | "view"');

const TodoAcceptanceTargetSchema = type({
	"kind?": type('"tool_callable"'),
	tool: type("string").atLeastLength(1),
	"action?": type("string"),
	"target?": type("string"),
	"expectedOutcome?": type('"success" | "expected_error"'),
});

const TodoTaskEntrySchema = type("string").or(
	type({
		content: type("string").atLeastLength(1),
		"acceptance?": TodoAcceptanceTargetSchema.or(TodoAcceptanceTargetSchema.array()),
		"fallback_of?": type("string"),
	}),
);

const InitListEntry = type({
	phase: type("string"),
	items: TodoTaskEntrySchema.array().atLeastLength(1),
});

const todoSchema = type({
	op: TodoOp,
	"list?": InitListEntry.array().describe("phases for init"),
	"task?": type("string").describe("verbatim task content"),
	"phase?": type("string"),
	// No `atLeastLength(1)` here: `items` is only meaningful for `init`/`append`,
	// and both enforce non-empty with op-specific errors. A stray `items: []` on
	// an op that ignores it (e.g. `view`) must not be a hard schema rejection.
	"items?": TodoTaskEntrySchema.array().describe("tasks for flat init or append"),
	"reason?": type("string").describe("blocker note for block"),
	"acceptance?": TodoAcceptanceTargetSchema.or(TodoAcceptanceTargetSchema.array()).describe(
		"immutable tool-callable acceptance requirement(s) for init/append",
	),
	"call_id?": type("string").describe("toolCallId providing verification evidence for done"),
	"call_ids?": type("string").array().describe("toolCallIds providing verification evidence for done"),
	"fallback_of?": type("string").describe("original task content when appending a fallback task"),
});

export type TodoParams = TodoSchema;
type TodoSchema = typeof todoSchema.infer;
/** A single todo op entry (the params object itself). */
type TodoOpEntryValue = TodoParams;
type RawTaskEntry = typeof TodoTaskEntrySchema.infer;

// =============================================================================
// State helpers
// =============================================================================

function findTaskByContent(phases: TodoPhase[], content: string): { task: TodoItem; phase: TodoPhase } | undefined {
	for (const phase of phases) {
		const task = phase.tasks.find(t => t.content === content);
		if (task) return { task, phase };
	}
	return undefined;
}

function findPhaseByName(phases: TodoPhase[], name: string): TodoPhase | undefined {
	return phases.find(phase => phase.name === name);
}

function cloneAcceptanceTarget(target: TodoAcceptanceTarget): TodoAcceptanceTarget {
	const cloned: TodoAcceptanceTarget = { kind: "tool_callable", tool: target.tool };
	if (target.action !== undefined) cloned.action = target.action;
	if (target.target !== undefined) cloned.target = target.target;
	if (target.expectedOutcome !== undefined) cloned.expectedOutcome = target.expectedOutcome;
	return cloned;
}

function cloneEvidenceRecord(record: TodoEvidenceRecord): TodoEvidenceRecord {
	const cloned: TodoEvidenceRecord = {
		toolCallId: record.toolCallId,
		tool: record.tool,
		semanticSuccess: record.semanticSuccess,
	};
	if (record.entryId !== undefined) cloned.entryId = record.entryId;
	if (record.action !== undefined) cloned.action = record.action;
	if (record.target !== undefined) cloned.target = record.target;
	if (record.isError !== undefined) cloned.isError = record.isError;
	if (record.timestamp !== undefined) cloned.timestamp = record.timestamp;
	if (record.generation !== undefined) cloned.generation = record.generation;
	if (record.summary !== undefined) cloned.summary = record.summary;
	return cloned;
}

function cloneFailureRecord(record: TodoFailureRecord): TodoFailureRecord {
	const cloned: TodoFailureRecord = {
		toolCallId: record.toolCallId,
		tool: record.tool,
		reason: record.reason,
	};
	if (record.entryId !== undefined) cloned.entryId = record.entryId;
	if (record.action !== undefined) cloned.action = record.action;
	if (record.target !== undefined) cloned.target = record.target;
	if (record.isReadinessFailure !== undefined) cloned.isReadinessFailure = record.isReadinessFailure;
	if (record.timestamp !== undefined) cloned.timestamp = record.timestamp;
	if (record.generation !== undefined) cloned.generation = record.generation;
	return cloned;
}

/** Deep-clone a single todo item, preserving acceptance, evidence, and failure metadata. */
export function cloneTodoTask(task: TodoItem): TodoItem {
	const cloned: TodoItem = { content: task.content, status: task.status };
	if (task.blocker !== undefined) cloned.blocker = task.blocker;
	if (task.details !== undefined) cloned.details = task.details;
	if (task.notes !== undefined) cloned.notes = [...task.notes];
	if (task.acceptance !== undefined && task.acceptance.length > 0) {
		cloned.acceptance = task.acceptance.map(cloneAcceptanceTarget);
	}
	if (task.evidence !== undefined && task.evidence.length > 0) {
		cloned.evidence = task.evidence.map(cloneEvidenceRecord);
	}
	if (task.unresolvedFailures !== undefined && task.unresolvedFailures.length > 0) {
		cloned.unresolvedFailures = task.unresolvedFailures.map(cloneFailureRecord);
	}
	if (task.fallbackOf !== undefined) cloned.fallbackOf = task.fallbackOf;
	if (task.generation !== undefined) cloned.generation = task.generation;
	return cloned;
}

/** Deep-clone todo phases, preserving all task metadata. */
export function cloneTodoPhases(phases: readonly TodoPhase[]): TodoPhase[] {
	return phases.map(phase => ({ name: phase.name, tasks: phase.tasks.map(cloneTodoTask) }));
}

const clonePhases = cloneTodoPhases;

function todoTransitionKey(phase: string, content: string): string {
	return `${phase}\u0000${content}`;
}

function getCompletionTransitions(previous: TodoPhase[], updated: TodoPhase[]): TodoCompletionTransition[] {
	const previousStatuses = new Map<string, TodoStatus>();
	for (const phase of previous) {
		for (const task of phase.tasks) {
			previousStatuses.set(todoTransitionKey(phase.name, task.content), task.status);
		}
	}

	const transitions: TodoCompletionTransition[] = [];
	for (const phase of updated) {
		for (const task of phase.tasks) {
			if (task.status !== "completed") continue;
			const previousStatus = previousStatuses.get(todoTransitionKey(phase.name, task.content));
			if (previousStatus && previousStatus !== "completed") {
				transitions.push({ phase: phase.name, content: task.content });
			}
		}
	}
	return transitions;
}

function normalizeInProgressTask(phases: TodoPhase[]): void {
	const orderedTasks = phases.flatMap(phase => phase.tasks);
	if (orderedTasks.length === 0) return;

	const inProgressTasks = orderedTasks.filter(task => task.status === "in_progress");
	if (inProgressTasks.length > 1) {
		for (const task of inProgressTasks.slice(1)) {
			task.status = "pending";
		}
	}

	if (inProgressTasks.length > 0) return;

	const firstPendingTask = orderedTasks.find(task => task.status === "pending");
	if (firstPendingTask) firstPendingTask.status = "in_progress";
}

/** Return the active todo task, preferring an in-progress item over the first pending item. */
export function nextActionableTask(phases: readonly TodoPhase[]): TodoItem | undefined {
	let firstPending: TodoItem | undefined;
	for (const phase of phases) {
		for (const task of phase.tasks) {
			if (task.status === "in_progress") return task;
			if (!firstPending && task.status === "pending") firstPending = task;
		}
	}
	return firstPending;
}

export const USER_TODO_EDIT_CUSTOM_TYPE = "user_todo_edit";

/** Durable canonical todo snapshot emitted when tool execution updates active-task failure/evidence state. */
export const TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE = "todo_execution_snapshot";

export const TODO_HUD_STATE_CUSTOM_TYPE = "todo_hud_state";

export type TodoHudVisibility = "dismissed" | "revealed";

export interface TodoSnapshotIdentity {
	sourceEntryId: string;
	fingerprint: string;
}

export interface TodoHudStateEntryData extends TodoSnapshotIdentity {
	visibility: TodoHudVisibility;
}

function todoPhasesFingerprint(phases: readonly TodoPhase[]): string {
	return JSON.stringify(
		phases.map(phase => ({
			name: phase.name,
			tasks: phase.tasks.map(task => {
				const out: Record<string, unknown> = { content: task.content, status: task.status };
				if (task.blocker !== undefined) out.blocker = task.blocker;
				if (task.acceptance !== undefined && task.acceptance.length > 0) out.acceptance = task.acceptance;
				if (task.evidence !== undefined && task.evidence.length > 0) out.evidence = task.evidence;
				if (task.unresolvedFailures !== undefined && task.unresolvedFailures.length > 0) {
					out.unresolvedFailures = task.unresolvedFailures;
				}
				if (task.fallbackOf !== undefined) out.fallbackOf = task.fallbackOf;
				if (task.generation !== undefined) out.generation = task.generation;
				return out;
			}),
		})),
	);
}

function canonicalTodoPhases(entry: SessionEntry): TodoPhase[] | undefined {
	if (
		entry.type === "custom" &&
		(entry.customType === USER_TODO_EDIT_CUSTOM_TYPE || entry.customType === TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE)
	) {
		const phases = (entry.data as { phases?: unknown } | undefined)?.phases;
		return Array.isArray(phases) ? (phases as TodoPhase[]) : undefined;
	}
	if (entry.type !== "message") return undefined;
	const message = entry.message as {
		role?: string;
		toolName?: string;
		details?: { op?: unknown; phases?: unknown };
		isError?: boolean;
	};
	if (message.role !== "toolResult" || message.toolName !== "todo" || message.isError) return undefined;
	if (message.details?.op === "view") return undefined;
	const phases = message.details?.phases;
	return Array.isArray(phases) ? (phases as TodoPhase[]) : undefined;
}

/** Identify the latest durable canonical todo snapshot on the active branch. */
export function getLatestTodoSnapshotIdentity(entries: SessionEntry[]): TodoSnapshotIdentity | undefined {
	let latest: TodoPhase[] | undefined;
	let sourceEntryId: string | undefined;
	for (let i = entries.length - 1; i >= 0; i--) {
		const phases = canonicalTodoPhases(entries[i]);
		if (phases) {
			latest = phases;
			sourceEntryId = entries[i].id;
			break;
		}
	}
	if (!latest || !sourceEntryId) return undefined;
	return { sourceEntryId, fingerprint: todoPhasesFingerprint(latest) };
}

/** Return the persisted HUD choice only when it targets the current canonical snapshot exactly. */
export function getTodoHudVisibility(
	entries: SessionEntry[],
	phases: readonly TodoPhase[],
): TodoHudVisibility | undefined {
	const snapshot = getLatestTodoSnapshotIdentity(entries);
	if (!snapshot || snapshot.fingerprint !== todoPhasesFingerprint(phases)) return undefined;
	for (let i = entries.length - 1; i >= 0; i--) {
		const entry = entries[i];
		if (entry.type !== "custom" || entry.customType !== TODO_HUD_STATE_CUSTOM_TYPE) continue;
		const data = entry.data as Partial<TodoHudStateEntryData> | undefined;
		if (
			data?.sourceEntryId === snapshot.sourceEntryId &&
			data.fingerprint === snapshot.fingerprint &&
			(data.visibility === "dismissed" || data.visibility === "revealed")
		) {
			return data.visibility;
		}
	}
	return undefined;
}

/** Build persisted HUD metadata only for phases matching the latest durable canonical snapshot. */
export function createTodoHudStateData(
	entries: SessionEntry[],
	phases: readonly TodoPhase[],
	visibility: TodoHudVisibility,
): TodoHudStateEntryData | undefined {
	const snapshot = getLatestTodoSnapshotIdentity(entries);
	if (!snapshot || snapshot.fingerprint !== todoPhasesFingerprint(phases)) return undefined;
	return { ...snapshot, visibility };
}

export function getLatestTodoPhasesFromEntries(entries: SessionEntry[]): TodoPhase[] {
	for (let i = entries.length - 1; i >= 0; i--) {
		const phases = canonicalTodoPhases(entries[i]);
		if (phases) return clonePhases(phases);
	}
	return [];
}

function resolveTaskOrError(
	phases: TodoPhase[],
	content: string | undefined,
	errors: string[],
): { task: TodoItem; phase: TodoPhase } | undefined {
	if (!content) {
		errors.push("Missing task content");
		return undefined;
	}
	const hit = findTaskByContent(phases, content);
	if (!hit) {
		if (/^task-\d+$/.test(content)) {
			errors.push(
				`Task "${content}" not found. Tasks are referenced by content, not by IDs — pass the task's full text from the previous result.`,
			);
		} else {
			const totalTasks = phases.reduce((sum, phase) => sum + phase.tasks.length, 0);
			const hint = totalTasks === 0 ? " (todo list is empty — was it replaced or not yet created?)" : "";
			errors.push(`Task "${content}" not found${hint}`);
		}
	}
	return hit;
}

function resolvePhaseOrError(phases: TodoPhase[], name: string | undefined, errors: string[]): TodoPhase | undefined {
	if (!name) {
		errors.push("Missing phase name");
		return undefined;
	}
	const phase = findPhaseByName(phases, name);
	if (!phase) errors.push(`Phase "${name}" not found`);
	return phase;
}

function getTaskTargets(phases: TodoPhase[], entry: TodoOpEntryValue, errors: string[]): TodoItem[] {
	if (entry.task) {
		const hit = resolveTaskOrError(phases, entry.task, errors);
		return hit ? [hit.task] : [];
	}
	if (entry.phase) {
		const phase = resolvePhaseOrError(phases, entry.phase, errors);
		return phase ? [...phase.tasks] : [];
	}
	return phases.flatMap(phase => phase.tasks);
}

// =============================================================================
// Semantic Tool Outcome & Evidence Evaluation
// =============================================================================

export interface ObservedToolExecutionResult {
	toolCallId: string;
	entryId?: string;
	toolName: string;
	effectiveToolName: string;
	action?: string;
	target?: string;
	args?: Record<string, unknown>;
	details?: unknown;
	isError: boolean;
	semanticSuccess: boolean;
	isReadinessFailure: boolean;
	ignored?: boolean;
	failureReason?: string;
	timestamp?: number;
	generation: number;
	activeTaskContent?: string;
}

const stripXdPrefix = stripXdUrlPrefix;
function extractActionFromRecord(rec: Record<string, unknown> | undefined): string | undefined {
	if (!rec) return undefined;
	for (const key of ["action", "mode", "op", "operation", "command"]) {
		const val = rec[key];
		if (typeof val === "string" && val.trim().length > 0) return val.trim();
	}
	return undefined;
}

function extractTargetFromRecord(rec: Record<string, unknown> | undefined): string | undefined {
	if (!rec) return undefined;
	for (const key of ["target", "path", "targetPath", "capability", "id", "binary", "file", "package"]) {
		const val = rec[key];
		if (typeof val === "string" && val.trim().length > 0) return val.trim();
	}
	return undefined;
}

/**
 * Evaluate whether a tool call succeeded semantically, unwrapping `xd://` device
 * dispatch metadata (`details.xdev`) and checking structured readiness fields.
 */
export function evaluateToolSemanticOutcome(
	rawToolName: string,
	details: unknown,
	isError?: boolean,
	rawArgs?: unknown,
	useless?: boolean,
): {
	effectiveToolName: string;
	action?: string;
	target?: string;
	effectiveArgs?: Record<string, unknown>;
	semanticSuccess: boolean;
	isReadinessFailure: boolean;
	ignored?: boolean;
	failureReason?: string;
} {
	const outerArgs = isRecord(rawArgs) ? rawArgs : undefined;
	const detailsRec = isRecord(details) ? details : undefined;
	const xdev = detailsRec && isRecord(detailsRec.xdev) ? detailsRec.xdev : undefined;

	// `read xd://<tool>` / `read xd://` are documentation or listing reads, never executions:
	// counting them would let a docs lookup satisfy a tool-callable acceptance criterion.
	if (
		rawToolName === "read" &&
		outerArgs &&
		typeof outerArgs.path === "string" &&
		outerArgs.path.startsWith("xd://")
	) {
		return { effectiveToolName: "read", semanticSuccess: true, isReadinessFailure: false, ignored: true };
	}

	// Pending async acks (a background job/service that merely started) are not verification:
	// only a settled execution may bind evidence or record a capability failure.
	if (detailsRec) {
		const asyncState = isRecord(detailsRec.async) ? detailsRec.async.state : undefined;
		if (asyncState === "running" || asyncState === "queued" || asyncState === "starting") {
			return {
				effectiveToolName: stripXdPrefix(rawToolName),
				semanticSuccess: true,
				isReadinessFailure: false,
				ignored: true,
			};
		}
		const serviceState = isRecord(detailsRec.service) ? detailsRec.service.state : undefined;
		if (serviceState === "starting" || serviceState === "stopping") {
			return {
				effectiveToolName: stripXdPrefix(rawToolName),
				semanticSuccess: true,
				isReadinessFailure: false,
				ignored: true,
			};
		}
	}

	// Help lookups via `write xd://<tool>` with `?` are documentation reads, not executions.
	if (xdev && xdev.mode === "help") {
		const helpTool = typeof xdev.tool === "string" ? stripXdPrefix(xdev.tool) : stripXdPrefix(rawToolName);
		return {
			effectiveToolName: helpTool,
			semanticSuccess: true,
			isReadinessFailure: false,
			ignored: true,
		};
	}

	// WaitPollGuard no-op bash / unchanged agent:// read redirects are neither capability failures nor smoke proofs.
	if (
		detailsRec &&
		(detailsRec.unexecuted === true ||
			(isRecord(detailsRec.waitPollGuard) && detailsRec.waitPollGuard.intercepted === true) ||
			useless === true)
	) {
		return {
			effectiveToolName: stripXdPrefix(rawToolName),
			semanticSuccess: !isError,
			isReadinessFailure: false,
			ignored: true,
		};
	}

	let effectiveToolName = stripXdPrefix(rawToolName);
	let effectiveArgs = outerArgs;
	if (xdev && typeof xdev.tool === "string" && xdev.tool.trim().length > 0) {
		effectiveToolName = stripXdPrefix(xdev.tool.trim());
		if (isRecord(xdev.args)) {
			effectiveArgs = xdev.args;
		}
	} else if (
		(rawToolName === "write" || rawToolName === "read") &&
		outerArgs &&
		typeof outerArgs.path === "string" &&
		outerArgs.path.startsWith("xd://")
	) {
		const targetDevice = stripXdPrefix(outerArgs.path).split(/[/?#]/)[0]?.trim();
		if (targetDevice) {
			effectiveToolName = targetDevice;
			if (typeof outerArgs.content === "string") {
				const trimmedContent = outerArgs.content.trim();
				if (trimmedContent === "?" || trimmedContent === "help" || trimmedContent === "--help") {
					return {
						effectiveToolName,
						semanticSuccess: true,
						isReadinessFailure: false,
						ignored: true,
					};
				}
				try {
					const parsed = JSON.parse(trimmedContent);
					if (isRecord(parsed)) effectiveArgs = parsed;
				} catch {
					// Keep outerArgs if content is not valid JSON.
				}
			}
		}
	}

	const innerDetails = xdev && "inner" in xdev && isRecord(xdev.inner) ? xdev.inner : detailsRec;
	const action = extractActionFromRecord(effectiveArgs) ?? extractActionFromRecord(innerDetails);
	const target = extractTargetFromRecord(effectiveArgs) ?? extractTargetFromRecord(innerDetails);

	if (isError) {
		const errReason =
			(innerDetails && typeof innerDetails.reason === "string" && innerDetails.reason) ||
			(innerDetails && typeof innerDetails.error === "string" && innerDetails.error) ||
			"tool execution error";
		const isReadiness =
			Boolean(innerDetails && innerDetails.deterministicFailure === true) ||
			Boolean(innerDetails && innerDetails.status === "blocked_prerequisite") ||
			Boolean(innerDetails && innerDetails.status === "missing_dependency");
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: isReadiness,
			failureReason: errReason,
		};
	}

	if (!innerDetails) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: true,
			isReadinessFailure: false,
		};
	}

	if (
		innerDetails.status === "missing_dependency" ||
		innerDetails.status === "blocked_prerequisite" ||
		innerDetails.deterministicFailure === true
	) {
		const reason =
			(typeof innerDetails.reason === "string" && innerDetails.reason) ||
			(typeof innerDetails.error === "string" && innerDetails.error) ||
			String(innerDetails.status ?? "missing dependency");
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: reason,
		};
	}

	if (innerDetails.installed === false) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "tool not installed / not available (installed: false)",
		};
	}

	if (innerDetails.available === false) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "tool/service not available (available: false)",
		};
	}

	if (innerDetails.canStart === false) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "tool prerequisite missing (canStart: false)",
		};
	}

	// Probe-only readiness: an explicit `status`/`resolve`/`get` probe reporting ready:false is
	// an availability verdict; an ordinary call that merely carries `ready` is not.
	if (innerDetails.ready === false && (action === "status" || action === "resolve" || action === "get")) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "tool/environment not ready (ready: false)",
		};
	}

	// `elf_inspect` status probe reports `lief.available: false` when LIEF is missing.
	if (
		(effectiveToolName === "elf_inspect" || action === "status") &&
		isRecord(innerDetails.lief) &&
		innerDetails.lief.available === false
	) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "LIEF not available (lief.available: false)",
		};
	}

	// `reverse_capability` resolve/get reports capability status in `details.capability` or `details.capabilities`.
	if (effectiveToolName === "reverse_capability" && (action === "resolve" || action === "get")) {
		const singleCap = isRecord(innerDetails.capability) ? innerDetails.capability : undefined;
		const capsList = Array.isArray(innerDetails.capabilities) ? innerDetails.capabilities.filter(isRecord) : [];
		const evaluatedCaps = singleCap ? [singleCap] : target ? capsList : [];
		for (const cap of evaluatedCaps) {
			if (cap.ready === false || cap.status === "missing") {
				const capId = typeof cap.id === "string" ? cap.id : (target ?? "capability");
				return {
					effectiveToolName,
					action,
					target: typeof cap.id === "string" ? cap.id : target,
					effectiveArgs,
					semanticSuccess: false,
					isReadinessFailure: true,
					failureReason: `capability '${capId}' not ready (status: ${String(cap.status ?? "missing")}, ready: false)`,
				};
			}
		}
	}

	if (isRecord(innerDetails.dependency) && innerDetails.dependency.available === false) {
		return {
			effectiveToolName,
			action,
			target,
			effectiveArgs,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "required dependency not available (dependency.available: false)",
		};
	}

	return {
		effectiveToolName,
		action,
		target,
		effectiveArgs,
		semanticSuccess: true,
		isReadinessFailure: false,
	};
}

/** Max generation across all tasks in `phases` (0 when empty). */
export function maxTodoGeneration(phases: readonly TodoPhase[]): number {
	let max = 0;
	for (const phase of phases) {
		for (const task of phase.tasks) {
			if (typeof task.generation === "number" && task.generation > max) {
				max = task.generation;
			}
		}
	}
	return max;
}

/** `customType` of the async-result delivery follow-up (stable wire string). */
const ASYNC_RESULT_CUSTOM_TYPE = "async-result";

interface PendingAsyncCall {
	callId: string;
	toolName: string;
	generation: number;
}

/**
 * Settle a background job's reported state into a verification outcome.
 *
 * A bash job body re-enters the failure path on a non-zero exit, so
 * `status: "completed"` already means exit 0 and BashToolDetails only carries
 * `exitCode` when it is non-zero; a completed bash job therefore needs no
 * separate exit code to count as verified. An explicitly reported non-zero
 * code still fails, so a settled snapshot can never be read as success.
 */
function settledAsyncOutcome(job: Record<string, unknown>): {
	settled: boolean;
	semanticSuccess: boolean;
	reason?: string;
} {
	const status = typeof job.status === "string" ? job.status : undefined;
	if (status !== "completed" && status !== "failed" && status !== "cancelled") {
		return { settled: false, semanticSuccess: false };
	}
	const exitCode = typeof job.exitCode === "number" ? job.exitCode : undefined;
	if (status !== "completed") return { settled: true, semanticSuccess: false, reason: `job ${status}` };
	if (exitCode !== undefined && exitCode !== 0) {
		return { settled: true, semanticSuccess: false, reason: `job exited with code ${exitCode}` };
	}
	return { settled: true, semanticSuccess: true };
}

/**
 * Extract observed tool executions from branch entries in chronological order.
 *
 * The plan generation and active task are those in force when the call was
 * DISPATCHED, never when its result happened to be persisted: a result entry
 * can land after a later `todo` mutation. Executions captured live carry a
 * `todo_execution_snapshot` entry whose recorded generation/attribution wins
 * over whatever the replayed result would infer.
 */
export function extractBranchToolExecutions(entries: readonly SessionEntry[]): ObservedToolExecutionResult[] {
	const callArgsById = new Map<string, { toolName: string; args?: Record<string, unknown>; generation: number }>();
	const pendingAsyncByJobId = new Map<string, PendingAsyncCall>();
	const results: ObservedToolExecutionResult[] = [];
	const seenCallIds = new Set<string>();
	let generation = 0;

	const upsert = (observed: ObservedToolExecutionResult, authoritative?: ObservedToolExecutionResult): void => {
		const existingIdx = seenCallIds.has(observed.toolCallId)
			? results.findIndex(r => r.toolCallId === observed.toolCallId)
			: -1;
		const prior = existingIdx === -1 ? undefined : results[existingIdx];
		const merged: ObservedToolExecutionResult = {
			...observed,
			generation: authoritative?.generation ?? prior?.generation ?? observed.generation,
		};
		const active = authoritative?.activeTaskContent ?? prior?.activeTaskContent;
		if (active !== undefined) merged.activeTaskContent = active;
		if (prior) {
			results[existingIdx] = merged;
		} else {
			seenCallIds.add(observed.toolCallId);
			results.push(merged);
		}
	};

	for (const entry of entries) {
		if (entry.type === "custom" || entry.type === "custom_message") {
			// Todo snapshots/edits are appended as `custom` entries; a delivery follow-up
			// (`async-result`) is persisted as a `custom_message` entry, so both carriers count.
			const rawPayload: unknown = entry.type === "custom" ? entry.data : entry.details;
			const data = isRecord(rawPayload) ? rawPayload : undefined;
			const customType = entry.customType;
			if (customType === USER_TODO_EDIT_CUSTOM_TYPE || customType === TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE) {
				const phases = data?.phases;
				if (Array.isArray(phases) && phases.every(isTodoPhase)) {
					const maxGen = maxTodoGeneration(phases);
					if (maxGen > generation) generation = maxGen;
				}
				if (customType === TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE && isRecord(data?.execution)) {
					const exec = data.execution as unknown as ObservedToolExecutionResult;
					if (typeof exec.toolCallId === "string" && typeof exec.effectiveToolName === "string") {
						upsert({ ...exec }, exec);
					}
				}
				continue;
			}
			if (customType === ASYNC_RESULT_CUSTOM_TYPE && Array.isArray(data?.jobs)) {
				// Delivery frame: settle the originating call from the reported job state, exactly as a
				// `wait` snapshot would. A completed bash job already implies exit 0 (non-zero re-enters
				// the job's failure path), so the frame need not repeat the code.
				for (const job of data.jobs) {
					if (!isRecord(job)) continue;
					const jobId =
						typeof job.jobId === "string" ? job.jobId : typeof job.id === "string" ? job.id : undefined;
					if (!jobId) continue;
					const pending = pendingAsyncByJobId.get(jobId);
					if (!pending || seenCallIds.has(pending.callId)) continue;
					const settled = settledAsyncOutcome(job);
					if (!settled.settled) continue;
					const baseMeta = callArgsById.get(pending.callId);
					const baseOutcome = evaluateToolSemanticOutcome(
						pending.toolName,
						undefined,
						!settled.semanticSuccess,
						baseMeta?.args,
					);
					upsert({
						toolCallId: pending.callId,
						entryId: entry.id,
						toolName: pending.toolName,
						effectiveToolName: baseOutcome.effectiveToolName,
						action: baseOutcome.action,
						target: baseOutcome.target,
						args: baseOutcome.effectiveArgs,
						details: job,
						isError: !settled.semanticSuccess,
						semanticSuccess: settled.semanticSuccess,
						isReadinessFailure: false,
						failureReason: settled.reason,
						generation: pending.generation,
					});
					pendingAsyncByJobId.delete(jobId);
				}
				continue;
			}
			continue;
		}
		if (entry.type !== "message") continue;
		const msg = entry.message as {
			role?: string;
			content?: unknown;
			toolCallId?: string;
			toolName?: string;
			details?: unknown;
			isError?: boolean;
			useless?: boolean;
			timestamp?: number;
		};
		if (msg.role === "assistant" && Array.isArray(msg.content)) {
			for (const block of msg.content) {
				if (!isRecord(block) || block.type !== "toolCall" || typeof block.id !== "string") continue;
				const name = typeof block.name === "string" ? block.name : "";
				const args = isRecord(block.arguments) ? block.arguments : undefined;
				callArgsById.set(block.id, { toolName: name, args, generation });
			}
			continue;
		}
		if (msg.role !== "toolResult" || typeof msg.toolName !== "string") continue;
		if (msg.toolName === "todo") {
			if (!msg.isError && isRecord(msg.details)) {
				const phases = msg.details.phases;
				if (Array.isArray(phases) && phases.every(isTodoPhase)) {
					const maxGen = maxTodoGeneration(phases);
					if (maxGen > generation) generation = maxGen;
				}
			}
			continue;
		}
		const callId = typeof msg.toolCallId === "string" ? msg.toolCallId : entry.id;
		const callMeta = callArgsById.get(callId);
		const dispatchGeneration = callMeta?.generation ?? generation;
		const detailsRec = isRecord(msg.details) ? msg.details : undefined;

		// A background-job start ack only reserves the originating call; it is never evidence.
		if (detailsRec && isRecord(detailsRec.async)) {
			const jobId = typeof detailsRec.async.jobId === "string" ? detailsRec.async.jobId : undefined;
			const state = detailsRec.async.state;
			if (jobId && (state === "running" || state === "queued" || state === "starting")) {
				pendingAsyncByJobId.set(jobId, {
					callId,
					toolName: callMeta?.toolName ?? msg.toolName,
					generation: dispatchGeneration,
				});
				continue;
			}
		}

		// A `wait` snapshot settles previously acknowledged background calls with real job state.
		if (detailsRec && Array.isArray(detailsRec.jobs)) {
			for (const job of detailsRec.jobs) {
				if (!isRecord(job) || typeof job.id !== "string") continue;
				const pending = pendingAsyncByJobId.get(job.id);
				if (!pending || seenCallIds.has(pending.callId)) continue;
				const settled = settledAsyncOutcome(job);
				if (!settled.settled) continue;
				const baseMeta = callArgsById.get(pending.callId);
				const baseOutcome = evaluateToolSemanticOutcome(
					pending.toolName,
					undefined,
					!settled.semanticSuccess,
					baseMeta?.args,
				);
				upsert({
					toolCallId: pending.callId,
					entryId: entry.id,
					toolName: pending.toolName,
					effectiveToolName: baseOutcome.effectiveToolName,
					action: baseOutcome.action,
					target: baseOutcome.target,
					args: baseOutcome.effectiveArgs,
					details: job,
					isError: !settled.semanticSuccess,
					semanticSuccess: settled.semanticSuccess,
					isReadinessFailure: false,
					failureReason: settled.reason,
					timestamp: msg.timestamp,
					generation: pending.generation,
				});
				pendingAsyncByJobId.delete(job.id);
			}
		}

		const outcome = evaluateToolSemanticOutcome(
			msg.toolName,
			msg.details,
			Boolean(msg.isError),
			callMeta?.args,
			msg.useless,
		);
		if (outcome.ignored) continue;
		upsert({
			toolCallId: callId,
			entryId: entry.id,
			toolName: msg.toolName,
			effectiveToolName: outcome.effectiveToolName,
			action: outcome.action,
			target: outcome.target,
			args: outcome.effectiveArgs,
			details: msg.details,
			isError: Boolean(msg.isError),
			semanticSuccess: outcome.semanticSuccess,
			isReadinessFailure: outcome.isReadinessFailure,
			failureReason: outcome.failureReason,
			timestamp: msg.timestamp,
			generation: dispatchGeneration,
		});
	}
	return results;
}

function canonicalTargetValue(raw: string, cwd: string | undefined): string {
	const trimmed = raw.trim();
	if (!cwd || !trimmed || /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) return trimmed;
	if (trimmed.includes("/") || trimmed.includes("\\") || trimmed.startsWith(".")) {
		try {
			return resolveToCwd(normalizePathLikeInput(trimmed), cwd);
		} catch {
			return trimmed;
		}
	}
	return trimmed;
}

export function matchesToolTargetCriterion(
	criterion: { tool: string; action?: string; target?: string },
	observed: { effectiveToolName: string; toolName?: string; action?: string; target?: string },
	cwd?: string,
): boolean {
	const reqTool = stripXdPrefix(criterion.tool.trim());
	const obsEffective = stripXdPrefix(observed.effectiveToolName.trim());
	const obsRaw = observed.toolName ? stripXdPrefix(observed.toolName.trim()) : "";
	if (reqTool !== obsEffective && reqTool !== obsRaw) return false;
	if (criterion.action !== undefined && criterion.action.trim().length > 0) {
		const reqAction = criterion.action.trim();
		const obsAction = (observed.action ?? "").trim();
		if (reqAction !== obsAction) return false;
	}
	if (criterion.target !== undefined && criterion.target.trim().length > 0) {
		const reqTarget = criterion.target.trim();
		const obsTarget = (observed.target ?? "").trim();
		if (!obsTarget) return false;
		if (reqTarget !== obsTarget && canonicalTargetValue(reqTarget, cwd) !== canonicalTargetValue(obsTarget, cwd)) {
			return false;
		}
	}
	return true;
}

function outcomeMatchesExpected(
	expected: TodoExpectedOutcome | undefined,
	observed: { semanticSuccess: boolean; isError?: boolean },
): boolean {
	if (expected === "expected_error") {
		return !observed.semanticSuccess || Boolean(observed.isError);
	}
	return observed.semanticSuccess && !observed.isError;
}

export interface TodoCompletionValidation {
	ok: boolean;
	error?: string;
	evidence?: TodoEvidenceRecord[];
}

/**
 * Validate whether `task` is allowed to transition to `completed` given its
 * immutable `acceptance` criteria, recorded `unresolvedFailures`, and the
 * session's observed tool executions.
 */
export function validateTodoTaskCompletion(
	task: TodoItem,
	allPhases: readonly TodoPhase[],
	observedExecutions: readonly ObservedToolExecutionResult[],
	citedCallIds?: readonly string[],
	cwd?: string,
): TodoCompletionValidation {
	const minGeneration = task.generation ?? 0;

	// Fallback work cannot close the original task: neither its recorded evidence IDs nor
	// executions attributed to a fallback task count here (an unfinished fallback has no
	// evidence yet, so attribution is checked independently of evidence).
	const fallbackTasks = allPhases
		.flatMap(phase => phase.tasks)
		.filter(candidate => candidate.fallbackOf === task.content);
	const fallbackContents = new Set(fallbackTasks.map(candidate => candidate.content));
	const fallbackEvidenceCallIds = new Set<string>();
	for (const fb of fallbackTasks) {
		for (const ev of fb.evidence ?? []) {
			fallbackEvidenceCallIds.add(ev.toolCallId);
		}
	}
	const isFallbackAttributed = (obs: ObservedToolExecutionResult): boolean =>
		obs.activeTaskContent !== undefined &&
		obs.activeTaskContent !== task.content &&
		fallbackContents.has(obs.activeTaskContent);

	// Index observed executions strictly from journal/live tracker records (never self-asserted task.evidence).
	const byCallId = new Map<string, ObservedToolExecutionResult>();
	for (const obs of observedExecutions) {
		byCallId.set(obs.toolCallId, obs);
	}
	// Validate any explicitly cited call IDs first.
	const explicitRecords: ObservedToolExecutionResult[] = [];
	if (citedCallIds && citedCallIds.length > 0) {
		for (const rawId of citedCallIds) {
			const callId = rawId.trim();
			if (!callId) continue;
			if (fallbackEvidenceCallIds.has(callId)) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: call_id "${callId}" belongs to fallback task "${fallbackTasks.map(f => f.content).join(", ")}" and cannot close the original task.`,
				};
			}
			const obs = byCallId.get(callId);
			if (!obs) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: cited call_id "${callId}" was not found in the session tool execution history.`,
				};
			}
			if (isFallbackAttributed(obs)) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: cited call_id "${callId}" was executed under fallback task "${obs.activeTaskContent}" and cannot close the original task.`,
				};
			}
			if (obs.generation < minGeneration) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: cited call_id "${callId}" is from a prior todo plan generation (${obs.generation} < ${minGeneration}).`,
				};
			}
			explicitRecords.push(obs);
		}
	}

	const currentGenExecutions = observedExecutions.filter(
		obs =>
			obs.generation >= minGeneration && !fallbackEvidenceCallIds.has(obs.toolCallId) && !isFallbackAttributed(obs),
	);

	const collectedEvidence: TodoEvidenceRecord[] = [];
	const addEvidence = (obs: ObservedToolExecutionResult) => {
		if (collectedEvidence.some(e => e.toolCallId === obs.toolCallId)) return;
		const rec: TodoEvidenceRecord = {
			toolCallId: obs.toolCallId,
			tool: obs.effectiveToolName,
			semanticSuccess: obs.semanticSuccess,
		};
		if (obs.entryId !== undefined) rec.entryId = obs.entryId;
		if (obs.action !== undefined) rec.action = obs.action;
		if (obs.target !== undefined) rec.target = obs.target;
		if (obs.isError) rec.isError = true;
		if (obs.timestamp !== undefined) rec.timestamp = obs.timestamp;
		rec.generation = obs.generation;
		collectedEvidence.push(rec);
	};

	// 1. Check explicit immutable acceptance criteria (`task.acceptance`).
	if (task.acceptance && task.acceptance.length > 0) {
		for (const criterion of task.acceptance) {
			const expected = criterion.expectedOutcome ?? "success";
			const matchingInGen = currentGenExecutions.filter(obs => matchesToolTargetCriterion(criterion, obs, cwd));

			// Also check task.unresolvedFailures for failures recorded directly on the task.
			const matchingTaskFailures = (task.unresolvedFailures ?? []).filter(
				f =>
					(f.generation ?? minGeneration) >= minGeneration &&
					matchesToolTargetCriterion(
						criterion,
						{
							effectiveToolName: f.tool,
							action: f.action,
							target: f.target,
						},
						cwd,
					),
			);

			const latestInGen = matchingInGen.at(-1);
			const criterionDesc = `${criterion.tool}${criterion.action ? ` (${criterion.action})` : ""}${criterion.target ? ` [${criterion.target}]` : ""}`;

			// If explicit call_id(s) were supplied, one of them must match this criterion.
			if (explicitRecords.length > 0) {
				const matchingExplicit = explicitRecords.find(obs => matchesToolTargetCriterion(criterion, obs, cwd));
				if (!matchingExplicit) {
					return {
						ok: false,
						error: `Cannot mark task "${task.content}" as done: cited call_id (${explicitRecords.map(r => r.toolCallId).join(", ")}) does not match required acceptance target "${criterionDesc}".`,
					};
				}
				if (!outcomeMatchesExpected(expected, matchingExplicit)) {
					return {
						ok: false,
						error: `Cannot mark task "${task.content}" as done: cited call_id "${matchingExplicit.toolCallId}" for "${criterionDesc}" did not satisfy expected outcome "${expected}" (${matchingExplicit.failureReason ?? "failed"}).`,
					};
				}
				// Ensure a newer call for the same target did not subsequently fail and invalidate readiness.
				if (
					latestInGen &&
					latestInGen.toolCallId !== matchingExplicit.toolCallId &&
					!outcomeMatchesExpected(expected, latestInGen)
				) {
					return {
						ok: false,
						error: `Cannot mark task "${task.content}" as done: later call "${latestInGen.toolCallId}" for "${criterionDesc}" failed (${latestInGen.failureReason ?? "unavailable"}), superseding earlier call "${matchingExplicit.toolCallId}".`,
					};
				}
				addEvidence(matchingExplicit);
				continue;
			}

			if (!latestInGen) {
				const failHint =
					matchingTaskFailures.length > 0
						? ` Observed ${matchingTaskFailures.length} failure(s): ${matchingTaskFailures.at(-1)?.reason}.`
						: " No execution of this tool/action was recorded in the current plan generation.";
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: acceptance requirement "${criterionDesc}" is not satisfied.${failHint} Use op: "block" with a reason if the tool is unavailable.`,
				};
			}

			if (!outcomeMatchesExpected(expected, latestInGen)) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: latest execution "${latestInGen.toolCallId}" for required "${criterionDesc}" failed (${latestInGen.failureReason ?? "unavailable"}). Use op: "block" with a reason or resolve the tool failure first.`,
				};
			}

			addEvidence(latestInGen);
		}
	}

	// 2. Check unresolved failures recorded on the task (covers plain-string tasks like session Q fixture).
	if (task.unresolvedFailures && task.unresolvedFailures.length > 0) {
		for (const failure of task.unresolvedFailures) {
			if ((failure.generation ?? minGeneration) < minGeneration) continue;
			const criterion = { tool: failure.tool, action: failure.action, target: failure.target };
			const matchingCalls = currentGenExecutions.filter(obs => matchesToolTargetCriterion(criterion, obs, cwd));
			const latestMatch = matchingCalls.at(-1);
			const resolvedByLatest =
				latestMatch !== undefined &&
				latestMatch.semanticSuccess &&
				!latestMatch.isError &&
				latestMatch.toolCallId !== failure.toolCallId;
			// For non-readiness operational errors (e.g. corrected path/command), allow an explicitly cited
			// verification call_id of the same tool that succeeded in the current generation.
			const citedResolution = !failure.isReadinessFailure
				? explicitRecords.find(
						obs =>
							obs.toolCallId !== failure.toolCallId &&
							obs.semanticSuccess &&
							!obs.isError &&
							matchesToolTargetCriterion({ tool: failure.tool, action: failure.action }, obs, cwd),
					)
				: undefined;
			if (!resolvedByLatest && !citedResolution) {
				const targetLabel = `${failure.tool}${failure.action ? ` (${failure.action})` : ""}${failure.target ? ` [${failure.target}]` : ""}`;
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: unresolved tool failure on "${targetLabel}" (call_id: ${failure.toolCallId}, reason: ${failure.reason}). Unrelated tool successes or fallbacks do not clear this failure; verify "${targetLabel}" succeeds or use op: "block" with reason.`,
				};
			}
			if (latestMatch && resolvedByLatest) addEvidence(latestMatch);
			else if (citedResolution) addEvidence(citedResolution);
		}
	}

	// 3. If explicit call_ids were passed on a plain task, verify they succeeded (unless covered by expected_error acceptance above).
	if (!task.acceptance?.length && explicitRecords.length > 0) {
		for (const obs of explicitRecords) {
			if (!obs.semanticSuccess || obs.isError) {
				return {
					ok: false,
					error: `Cannot mark task "${task.content}" as done: cited call_id "${obs.toolCallId}" (${obs.effectiveToolName}) failed (${obs.failureReason ?? "error"}).`,
				};
			}
			addEvidence(obs);
		}
	}

	return {
		ok: true,
		evidence: collectedEvidence.length > 0 ? collectedEvidence : task.evidence?.map(cloneEvidenceRecord),
	};
}

function normalizeAcceptanceInput(
	raw: typeof TodoAcceptanceTargetSchema.infer | Array<typeof TodoAcceptanceTargetSchema.infer> | undefined,
): TodoAcceptanceTarget[] | undefined {
	if (!raw) return undefined;
	const arr = Array.isArray(raw) ? raw : [raw];
	if (arr.length === 0) return undefined;
	return arr.map(item => {
		const target: TodoAcceptanceTarget = {
			kind: "tool_callable",
			tool: stripXdPrefix(item.tool.trim()),
		};
		if (item.action !== undefined && item.action.trim().length > 0) target.action = item.action.trim();
		if (item.target !== undefined && item.target.trim().length > 0) target.target = item.target.trim();
		if (item.expectedOutcome !== undefined) target.expectedOutcome = item.expectedOutcome;
		return target;
	});
}

function acceptanceTargetsEqual(a: readonly TodoAcceptanceTarget[], b: readonly TodoAcceptanceTarget[]): boolean {
	if (a.length !== b.length) return false;
	return a.every((item, idx) => {
		const other = b[idx];
		if (!other) return false;
		return (
			item.kind === other.kind &&
			item.tool === other.tool &&
			(item.action ?? undefined) === (other.action ?? undefined) &&
			(item.target ?? undefined) === (other.target ?? undefined) &&
			(item.expectedOutcome ?? "success") === (other.expectedOutcome ?? "success")
		);
	});
}

function normalizeRawTaskEntry(
	raw: RawTaskEntry,
	defaultAcceptance: TodoAcceptanceTarget[] | undefined,
	defaultFallbackOf: string | undefined,
	generation: number,
): TodoItem {
	if (typeof raw === "string") {
		const item: TodoItem = { content: raw, status: "pending", generation };
		if (defaultAcceptance && defaultAcceptance.length > 0) {
			item.acceptance = defaultAcceptance.map(cloneAcceptanceTarget);
		}
		if (defaultFallbackOf) item.fallbackOf = defaultFallbackOf;
		return item;
	}
	const itemAcceptance = normalizeAcceptanceInput(raw.acceptance) ?? defaultAcceptance;
	const item: TodoItem = { content: raw.content, status: "pending", generation };
	if (itemAcceptance && itemAcceptance.length > 0) {
		item.acceptance = itemAcceptance.map(cloneAcceptanceTarget);
	}
	const fallbackOf = raw.fallback_of?.trim() || defaultFallbackOf;
	if (fallbackOf) item.fallbackOf = fallbackOf;
	return item;
}

/**
 * Reconcile incoming `nextPhases` against `previousPhases` so immutable
 * `acceptance`, `unresolvedFailures`, `fallbackOf`, and `generation` cannot be
 * silently stripped by external setters (`/todo`, RPC `set_todos`, Cursor sync,
 * markdown import), and any task flipped to `completed` without satisfying its
 * completion gate stays in its prior open/blocked state.
 */
export function reconcileAndValidateTodoPhases(
	previousPhases: readonly TodoPhase[],
	nextPhases: readonly TodoPhase[],
	observedExecutions: readonly ObservedToolExecutionResult[] = [],
	cwd?: string,
): { phases: TodoPhase[]; errors: string[] } {
	const errors: string[] = [];
	const prevByContent = new Map<string, TodoItem>();
	for (const phase of previousPhases) {
		for (const task of phase.tasks) {
			prevByContent.set(task.content, task);
		}
	}
	const incomingEvidenceByContent = new Map<string, string[]>();
	const cloned = cloneTodoPhases(nextPhases);
	for (const phase of cloned) {
		for (const task of phase.tasks) {
			const prev = prevByContent.get(task.content);
			if (task.evidence && task.evidence.length > 0 && prev?.status !== "completed") {
				incomingEvidenceByContent.set(
					task.content,
					task.evidence.map(e => e.toolCallId),
				);
			}
			// Never trust caller-forged `task.evidence` on incoming phases; only retain verified evidence from prior state.
			task.evidence =
				prev?.evidence && prev.evidence.length > 0 ? prev.evidence.map(cloneEvidenceRecord) : undefined;
			if (!prev) continue;
			// Preserve immutable acceptance criteria from prior task state.
			if (prev.acceptance && prev.acceptance.length > 0) {
				if (
					task.acceptance &&
					task.acceptance.length > 0 &&
					!acceptanceTargetsEqual(prev.acceptance, task.acceptance)
				) {
					errors.push(`Cannot modify immutable acceptance criteria on task "${task.content}"`);
				}
				task.acceptance = prev.acceptance.map(cloneAcceptanceTarget);
			}
			// Generation and fallback linkage are part of a task's identity: a setter cannot forge a
			// newer generation or unlink a fallback (which would let its evidence be reused).
			if (prev.generation !== undefined) {
				task.generation = prev.generation;
			}
			if (prev.fallbackOf !== undefined) {
				task.fallbackOf = prev.fallbackOf;
			} else {
				delete task.fallbackOf;
			}
			// Unresolved failures are authoritative from previous state: an incoming missing or
			// empty array (RPC set_todos, /todo import, Cursor mirror) cannot erase them. Only a
			// later successful execution of the same operation resolves one.
			if (prev.unresolvedFailures && prev.unresolvedFailures.length > 0) {
				task.unresolvedFailures = prev.unresolvedFailures.map(cloneFailureRecord);
			} else if (task.unresolvedFailures && task.unresolvedFailures.length === 0) {
				task.unresolvedFailures = undefined;
			}
			if (task.status === "blocked" && task.blocker === undefined && prev.blocker !== undefined) {
				task.blocker = prev.blocker;
			}
		}
	}

	// Validate any task transitioning to `completed` (or an already-completed task invalidated by new failures).
	for (const phase of cloned) {
		for (const task of phase.tasks) {
			if (task.status !== "completed") continue;
			const prev = prevByContent.get(task.content);
			const citedIds = incomingEvidenceByContent.get(task.content);
			// Fast path: plain task with no acceptance, no unresolved failures, and no caller-asserted evidence IDs.
			if (!task.acceptance?.length && !task.unresolvedFailures?.length && !citedIds?.length) continue;
			// Already-completed task from prior state stays valid unless new unresolvedFailures were recorded on it.
			if (prev?.status === "completed" && !task.unresolvedFailures?.length) continue;
			const validation = validateTodoTaskCompletion(task, cloned, observedExecutions, citedIds, cwd);
			if (!validation.ok) {
				errors.push(validation.error ?? `Task "${task.content}" cannot be marked completed`);
				task.status = prev && prev.status !== "completed" ? prev.status : "blocked";
				if (task.status === "blocked" && !task.blocker) {
					task.blocker =
						prev?.blocker ?? task.unresolvedFailures?.at(-1)?.reason ?? "acceptance criteria not yet satisfied";
				}
			} else if (validation.evidence && validation.evidence.length > 0) {
				task.evidence = validation.evidence;
				task.unresolvedFailures = undefined;
			}
		}
	}
	return { phases: cloned, errors };
}

/** Phase name for `init` given a flat `items` list with no explicit `phase`. */
const DEFAULT_INIT_PHASE = "Tasks";

function initPhases(previousPhases: readonly TodoPhase[], entry: TodoOpEntryValue, errors: string[]): TodoPhase[] {
	// Models routinely flatten the single-phase init into `{op:"init", items:[...]}`
	// (optionally with a bare `phase`) instead of the canonical
	// `list: [{phase, items}]`. Accept that shape by synthesizing a one-phase list
	// so a common, recoverable mistake isn't a hard error. Models also fill unused
	// params with `[]`, so an empty `list` must not shadow non-empty `items`.
	const flat =
		entry.items && entry.items.length > 0
			? [{ phase: entry.phase ?? DEFAULT_INIT_PHASE, items: entry.items }]
			: undefined;
	const list = entry.list?.length ? entry.list : (flat ?? entry.list);
	if (!list) {
		errors.push("Missing list for init operation");
		return [];
	}
	const nextGeneration = maxTodoGeneration(previousPhases) + 1;
	const defaultAcceptance = normalizeAcceptanceInput(entry.acceptance);
	const defaultFallbackOf = entry.fallback_of?.trim() || undefined;

	const prevByContent = new Map<string, TodoItem>();
	for (const phase of previousPhases) {
		for (const task of phase.tasks) {
			prevByContent.set(task.content, task);
		}
	}

	// Duplicate phase names / task contents would be permanently unaddressable
	// (every targeting op resolves the first match), so reject them up front.
	const seenPhases = new Set<string>();
	const seenTasks = new Set<string>();
	for (const listEntry of list) {
		if (seenPhases.has(listEntry.phase)) {
			errors.push(`Duplicate phase "${listEntry.phase}" in init list`);
		}
		seenPhases.add(listEntry.phase);
		for (const rawItem of listEntry.items) {
			const content = typeof rawItem === "string" ? rawItem : rawItem.content;
			if (seenTasks.has(content)) {
				errors.push(`Duplicate task "${content}" in init list`);
			}
			seenTasks.add(content);
		}
	}

	// Prevent re-initializing around an existing unsatisfied immutable acceptance task.
	for (const prevTask of prevByContent.values()) {
		if (prevTask.status === "completed") continue;
		if (prevTask.acceptance && prevTask.acceptance.length > 0 && !seenTasks.has(prevTask.content)) {
			errors.push(
				`Cannot re-initialize todo list and drop task "${prevTask.content}" while its immutable acceptance criteria remain unsatisfied; keep "${prevTask.content}" in the list (or mark it blocked).`,
			);
		}
	}

	return list.map(listEntry => ({
		name: listEntry.phase,
		tasks: listEntry.items.map<TodoItem>(rawItem => {
			const task = normalizeRawTaskEntry(
				rawItem,
				listEntry.items.length === 1 ? defaultAcceptance : undefined,
				defaultFallbackOf,
				nextGeneration,
			);
			const prev = prevByContent.get(task.content);
			if (prev) {
				if (prev.acceptance && prev.acceptance.length > 0) {
					if (
						task.acceptance &&
						task.acceptance.length > 0 &&
						!acceptanceTargetsEqual(prev.acceptance, task.acceptance)
					) {
						errors.push(`Cannot overwrite immutable acceptance criteria on task "${task.content}"`);
					}
					task.acceptance = prev.acceptance.map(cloneAcceptanceTarget);
				}
				if (prev.unresolvedFailures && prev.unresolvedFailures.length > 0) {
					task.unresolvedFailures = prev.unresolvedFailures.map(f => ({
						...cloneFailureRecord(f),
						generation: nextGeneration,
					}));
				}
				// Fallback linkage survives a replan: relinking an existing task would let a
				// fallback's evidence close the original.
				if (prev.fallbackOf !== undefined) {
					task.fallbackOf = prev.fallbackOf;
				} else {
					delete task.fallbackOf;
				}
				if (prev.status === "blocked") {
					task.status = "blocked";
					task.blocker = prev.blocker;
				}
			}
			return task;
		}),
	}));
}

function appendItems(phases: TodoPhase[], entry: TodoOpEntryValue, errors: string[]): TodoPhase[] {
	if (!entry.phase) {
		errors.push("Missing phase name for append operation");
		return phases;
	}
	if (!entry.items || entry.items.length === 0) {
		errors.push("Missing items for append operation");
		return phases;
	}

	// Validate the whole batch before mutating so a failing op reports every
	// duplicate and leaves nothing half-applied.
	const seen = new Set<string>();
	let hasDuplicate = false;
	for (const rawItem of entry.items) {
		const content = typeof rawItem === "string" ? rawItem : rawItem.content;
		if (seen.has(content) || findTaskByContent(phases, content)) {
			errors.push(`Task "${content}" already exists`);
			hasDuplicate = true;
		}
		seen.add(content);
	}
	if (hasDuplicate) return phases;

	const fallbackOf = entry.fallback_of?.trim() || undefined;
	if (fallbackOf) {
		const originalHit = findTaskByContent(phases, fallbackOf);
		if (!originalHit) {
			errors.push(`Fallback target task "${fallbackOf}" not found`);
			return phases;
		}
		// Ensure original task remains blocked/open when a fallback is introduced.
		if (originalHit.task.status !== "blocked" && originalHit.task.status !== "completed") {
			const firstFallbackContent =
				typeof entry.items[0] === "string" ? entry.items[0] : (entry.items[0]?.content ?? "fallback task");
			originalHit.task.status = "blocked";
			originalHit.task.blocker =
				originalHit.task.blocker ??
				originalHit.task.unresolvedFailures?.at(-1)?.reason ??
				`blocked; fallback task: ${firstFallbackContent}`;
		}
	}

	let phase = findPhaseByName(phases, entry.phase);
	if (!phase) {
		phase = { name: entry.phase, tasks: [] };
		phases.push(phase);
	}

	const currentGen = maxTodoGeneration(phases);
	const defaultAcceptance = normalizeAcceptanceInput(entry.acceptance);
	for (const rawItem of entry.items) {
		const task = normalizeRawTaskEntry(
			rawItem,
			entry.items.length === 1 ? defaultAcceptance : undefined,
			fallbackOf,
			currentGen,
		);
		if (task.fallbackOf && !fallbackOf) {
			const orig = findTaskByContent(phases, task.fallbackOf);
			if (!orig) {
				errors.push(`Fallback target task "${task.fallbackOf}" not found`);
				return phases;
			}
			if (orig.task.status !== "blocked" && orig.task.status !== "completed") {
				orig.task.status = "blocked";
				orig.task.blocker =
					orig.task.blocker ??
					orig.task.unresolvedFailures?.at(-1)?.reason ??
					`blocked; fallback task: ${task.content}`;
			}
		}
		phase.tasks.push(task);
	}
	return phases;
}

function removeTasks(phases: TodoPhase[], entry: TodoOpEntryValue, errors: string[]): TodoPhase[] {
	if (entry.task) {
		const hit = resolveTaskOrError(phases, entry.task, errors);
		if (!hit) return phases;
		if (hit.task.acceptance && hit.task.acceptance.length > 0 && hit.task.status !== "completed") {
			errors.push(
				`Cannot remove task "${hit.task.content}" while its immutable acceptance criteria remain unsatisfied; mark it blocked with a reason instead.`,
			);
			return phases;
		}
		hit.phase.tasks = hit.phase.tasks.filter(candidate => candidate !== hit.task);
		return phases;
	}
	if (entry.phase) {
		const phase = resolvePhaseOrError(phases, entry.phase, errors);
		if (!phase) return phases;
		const locked = phase.tasks.find(t => t.acceptance && t.acceptance.length > 0 && t.status !== "completed");
		if (locked) {
			errors.push(
				`Cannot remove phase "${phase.name}" because task "${locked.content}" has unsatisfied immutable acceptance criteria.`,
			);
			return phases;
		}
		phase.tasks = [];
		return phases;
	}
	for (const phase of phases) {
		phase.tasks = [];
	}
	return phases;
}

function applyEntry(
	phases: TodoPhase[],
	entry: TodoOpEntryValue,
	errors: string[],
	observedExecutions: readonly ObservedToolExecutionResult[] = [],
	cwd?: string,
): TodoPhase[] {
	switch (entry.op) {
		case "init":
			return initPhases(phases, entry, errors);
		case "start": {
			const hit = resolveTaskOrError(phases, entry.task, errors);
			if (!hit) return phases;
			for (const phase of phases) {
				for (const candidate of phase.tasks) {
					if (candidate.status === "in_progress" && candidate !== hit.task) {
						candidate.status = "pending";
					}
				}
			}
			hit.task.status = "in_progress";
			return phases;
		}
		case "done": {
			const citedCallIds: string[] = [];
			if (typeof entry.call_id === "string" && entry.call_id.trim()) {
				citedCallIds.push(entry.call_id.trim());
			}
			if (Array.isArray(entry.call_ids)) {
				for (const id of entry.call_ids) {
					if (typeof id === "string" && id.trim()) citedCallIds.push(id.trim());
				}
			}
			for (const task of getTaskTargets(phases, entry, errors)) {
				const validation = validateTodoTaskCompletion(
					task,
					phases,
					observedExecutions,
					citedCallIds.length > 0 ? citedCallIds : undefined,
					cwd,
				);
				if (!validation.ok) {
					errors.push(validation.error ?? `Task "${task.content}" cannot be marked done`);
					continue;
				}
				task.status = "completed";
				task.blocker = undefined;
				task.unresolvedFailures = undefined;
				if (validation.evidence && validation.evidence.length > 0) {
					task.evidence = validation.evidence;
				}
			}
			return phases;
		}
		case "drop": {
			for (const task of getTaskTargets(phases, entry, errors)) {
				if (task.acceptance && task.acceptance.length > 0 && task.status !== "completed") {
					errors.push(
						`Cannot drop task "${task.content}" while its immutable acceptance criteria remain unsatisfied; use op: "block" with a reason if blocked.`,
					);
					continue;
				}
				task.status = "abandoned";
			}
			return phases;
		}
		case "block": {
			if (!entry.task && !entry.phase) {
				errors.push("block requires a task or phase target");
				return phases;
			}
			// Collapse whitespace runs (incl. newlines) to single spaces: a blocker
			// note rides on one Markdown checklist line (as a trailing HTML comment)
			// and one HUD/summary line, so an embedded newline from a multi-line
			// external error or user question would corrupt the round-trip parse and
			// the rendered line. Normalizing here keeps every consumer one-line-safe.
			const reason = entry.reason?.replace(/\s+/g, " ").trim() || undefined;
			for (const task of getTaskTargets(phases, entry, errors)) {
				// Only actionable open work can be blocked: blocking a phase must not
				// reopen completed/abandoned tasks or erase finished progress. An
				// already-blocked task stays eligible so a later block can refine its
				// blocker note (e.g. first blocked without a reason, then with one).
				if (task.status !== "pending" && task.status !== "in_progress" && task.status !== "blocked") continue;
				task.status = "blocked";
				task.blocker = reason;
			}
			return phases;
		}
		case "unblock": {
			if (!entry.task && !entry.phase) {
				errors.push("unblock requires a task or phase target");
				return phases;
			}
			for (const task of getTaskTargets(phases, entry, errors)) {
				if (task.status === "blocked") {
					task.status = "pending";
					task.blocker = undefined;
				}
			}
			return phases;
		}
		case "rm":
			return removeTasks(phases, entry, errors);
		case "append":
			return appendItems(phases, entry, errors);
		case "view":
			return phases;
	}
}

/**
 * Infer a missing `op` from the raw argument shape. Only unambiguous shapes
 * are inferred:
 * - `list` → `init` (list is init-only)
 * - `items` + `phase` → `append` (lazily creates the phase, so the result
 *   matches a single-phase init when nothing exists yet)
 * - bare `items` with no existing todos → `init` (nothing to overwrite)
 * Targeting args alone (`task`/`phase`) map to several ops and stay an error.
 */
function inferTodoOp(args: Record<string, unknown>, hasExistingPhases: boolean): TodoOperation | undefined {
	if (Array.isArray(args.list) && args.list.length > 0) return "init";
	if (Array.isArray(args.items) && args.items.length > 0) {
		if (typeof args.phase === "string" && args.phase) return "append";
		if (!hasExistingPhases) return "init";
	}
	return undefined;
}

/**
 * Validate execute-time arguments, repairing an omitted `op`. The tool sets
 * `lenientArgValidation`, so the agent loop hands `execute()` the raw
 * arguments when schema validation fails; the only failure repaired here is
 * a missing `op` alongside an unambiguous payload (models routinely send
 * `{list:[...]}` with no op). Anything else returns the schema error text
 * for a normal model retry.
 */
function resolveTodoParams(raw: unknown, hasExistingPhases: boolean): TodoOpEntryValue | string {
	const direct = todoSchema(raw);
	if (!(direct instanceof type.errors)) return direct;
	if (isRecord(raw) && raw.op === undefined) {
		const inferred = inferTodoOp(raw, hasExistingPhases);
		if (inferred) {
			const repaired = todoSchema({ ...raw, op: inferred });
			if (!(repaired instanceof type.errors)) return repaired;
		}
	}
	return `Invalid todo arguments: ${direct.summary}`;
}

function applyParams(
	phases: TodoPhase[],
	params: TodoOpEntryValue,
	observedExecutions: readonly ObservedToolExecutionResult[] = [],
	cwd?: string,
): { phases: TodoPhase[]; errors: string[] } {
	const errors: string[] = [];
	const next = applyEntry(phases, params, errors, observedExecutions, cwd);
	normalizeInProgressTask(next);
	return { phases: next, errors };
}

/** Apply an array of `todo`-style ops to existing phases. Used by /todo slash command. */
export function applyOpsToPhases(
	currentPhases: TodoPhase[],
	ops: TodoOpEntryValue[],
	observedExecutions: readonly ObservedToolExecutionResult[] = [],
	cwd?: string,
): { phases: TodoPhase[]; errors: string[] } {
	const errors: string[] = [];
	let next = clonePhases(currentPhases);
	for (const op of ops) {
		next = applyEntry(next, op, errors, observedExecutions, cwd);
	}
	normalizeInProgressTask(next);
	return { phases: next, errors };
}

// =============================================================================
// Markdown round-trip
// =============================================================================

const STATUS_TO_MARKER: Record<TodoStatus, string> = {
	pending: " ",
	in_progress: "/",
	completed: "x",
	abandoned: "-",
	blocked: "!",
};

export function resolveTodoMarkdownPath(input: string, cwd: string): string {
	const raw = normalizePathLikeInput(input) || "TODO.md";
	return resolveToCwd(raw, cwd);
}

interface SerializedTodoMeta {
	acceptance?: TodoAcceptanceTarget[];
	evidence?: TodoEvidenceRecord[];
	unresolvedFailures?: TodoFailureRecord[];
	fallbackOf?: string;
	generation?: number;
}

function serializeTaskMetaComment(task: TodoItem): string {
	const meta: SerializedTodoMeta = {};
	let hasMeta = false;
	if (task.acceptance && task.acceptance.length > 0) {
		meta.acceptance = task.acceptance;
		hasMeta = true;
	}
	if (task.evidence && task.evidence.length > 0) {
		meta.evidence = task.evidence;
		hasMeta = true;
	}
	if (task.unresolvedFailures && task.unresolvedFailures.length > 0) {
		meta.unresolvedFailures = task.unresolvedFailures;
		hasMeta = true;
	}
	if (task.fallbackOf !== undefined) {
		meta.fallbackOf = task.fallbackOf;
		hasMeta = true;
	}
	if (task.generation !== undefined && task.generation > 0) {
		meta.generation = task.generation;
		hasMeta = true;
	}
	if (!hasMeta) return "";
	return ` <!-- todo-meta: ${JSON.stringify(meta).replace(/-->/g, "--\\u003e")} -->`;
}

/** Render todo phases as a Markdown checklist suitable for editing/copying. */
export function phasesToMarkdown(phases: TodoPhase[]): string {
	if (phases.length === 0) return "# Todos\n";
	const out: string[] = [];
	for (let i = 0; i < phases.length; i++) {
		if (i > 0) out.push("");
		out.push(`# ${phases[i].name}`);
		for (const task of phases[i].tasks) {
			// A blocked task's reason rides in a trailing HTML comment: invisible in
			// rendered markdown, unambiguous to parse back (task content can't
			// contain the comment delimiters), so the note survives `/todo edit` and
			// export/import round-trips.
			const blockerNote = task.status === "blocked" && task.blocker ? ` <!-- blocker: ${task.blocker} -->` : "";
			const metaComment = serializeTaskMetaComment(task);
			out.push(`- [${STATUS_TO_MARKER[task.status]}] ${task.content}${blockerNote}${metaComment}`);
		}
	}
	return `${out.join("\n")}\n`;
}

const MARKER_TO_STATUS: Record<string, TodoStatus> = {
	" ": "pending",
	"": "pending",
	x: "completed",
	X: "completed",
	"/": "in_progress",
	">": "in_progress",
	"-": "abandoned",
	"~": "abandoned",
	"!": "blocked",
};

/** Parse a Markdown checklist back into todo phases. */
export function markdownToPhases(md: string): { phases: TodoPhase[]; errors: string[] } {
	const errors: string[] = [];
	const phases: TodoPhase[] = [];
	let currentPhase: TodoPhase | undefined;

	const lines = md.split(/\r?\n/);
	for (let lineNum = 0; lineNum < lines.length; lineNum++) {
		const raw = lines[lineNum];

		const trimmed = raw.trim();
		if (!trimmed) continue;

		const headingMatch = /^#{1,6}\s+(.+?)\s*$/.exec(trimmed);
		if (headingMatch) {
			currentPhase = { name: headingMatch[1].trim(), tasks: [] };
			phases.push(currentPhase);
			continue;
		}

		// Tolerate backslash-escaped brackets (`- \[x\]`): some editors and
		// markdown serializers escape `[` (and `]`) when round-tripping, yet the
		// line still renders as a normal `[x]` checkbox. Accept either form.
		const taskMatch = /^[-*+]\s*\\?\[(.?)\\?\]\s+(.+?)\s*$/.exec(trimmed);
		if (taskMatch) {
			if (!currentPhase) {
				currentPhase = { name: "Todos", tasks: [] };
				phases.push(currentPhase);
			}
			const marker = taskMatch[1];
			const status = MARKER_TO_STATUS[marker];
			if (!status) {
				errors.push(`Line ${lineNum + 1}: unknown status marker "[${marker}]" (use [ ], [x], [/], [-], [!])`);
				continue;
			}
			let rawContent = taskMatch[2].trim();
			let parsedMeta: SerializedTodoMeta | undefined;
			const metaMatch = /^(.*?)\s*<!--\s*todo-meta:\s*(.*?)\s*-->$/.exec(rawContent);
			if (metaMatch) {
				rawContent = metaMatch[1].trim();
				try {
					const rawJson = metaMatch[2].replace(/--\\u003e/g, "-->");
					const parsed = JSON.parse(rawJson);
					if (isRecord(parsed)) parsedMeta = parsed as SerializedTodoMeta;
				} catch {
					// Ignore malformed meta comment.
				}
			}
			const blockerMatch = /^(.*?)\s*<!--\s*blocker:\s*(.*?)\s*-->$/.exec(rawContent);
			const item: TodoItem =
				status === "blocked" && blockerMatch
					? { content: blockerMatch[1].trim(), status, blocker: blockerMatch[2].trim() }
					: { content: rawContent, status };
			if (parsedMeta) {
				if (Array.isArray(parsedMeta.acceptance) && parsedMeta.acceptance.length > 0) {
					item.acceptance = parsedMeta.acceptance.map(cloneAcceptanceTarget);
				}
				if (Array.isArray(parsedMeta.evidence) && parsedMeta.evidence.length > 0) {
					item.evidence = parsedMeta.evidence.map(cloneEvidenceRecord);
				}
				if (Array.isArray(parsedMeta.unresolvedFailures) && parsedMeta.unresolvedFailures.length > 0) {
					item.unresolvedFailures = parsedMeta.unresolvedFailures.map(cloneFailureRecord);
				}
				if (typeof parsedMeta.fallbackOf === "string" && parsedMeta.fallbackOf) {
					item.fallbackOf = parsedMeta.fallbackOf;
				}
				if (typeof parsedMeta.generation === "number") {
					item.generation = parsedMeta.generation;
				}
			}
			currentPhase.tasks.push(item);
			continue;
		}

		errors.push(`Line ${lineNum + 1}: unrecognized syntax "${trimmed}"`);
	}

	normalizeInProgressTask(phases);
	return { phases, errors };
}

function formatSummary(phases: TodoPhase[], errors: string[], readOnly = false): string {
	const tasks = phases.flatMap(phase => phase.tasks);
	if (tasks.length === 0) {
		if (errors.length > 0) return `Errors: ${errors.join("; ")}`;
		return readOnly ? "Todo list is empty." : "Todo list cleared.";
	}

	const remainingByPhase = phases
		.map(phase => ({
			name: phase.name,
			tasks: phase.tasks.filter(task => task.status === "pending" || task.status === "in_progress"),
		}))
		.filter(phase => phase.tasks.length > 0);
	const remainingTasks = remainingByPhase.flatMap(phase => phase.tasks.map(task => ({ ...task, phase: phase.name })));
	const blockedTasks = phases.flatMap(phase =>
		phase.tasks.filter(task => task.status === "blocked").map(task => ({ ...task, phase: phase.name })),
	);

	let currentIdx = phases.findIndex(phase =>
		phase.tasks.some(task => task.status === "pending" || task.status === "in_progress"),
	);
	if (currentIdx === -1) {
		currentIdx = phases.findIndex(phase => phase.tasks.some(task => task.status === "blocked"));
	}
	if (currentIdx === -1) currentIdx = phases.length - 1;
	const current = phases[currentIdx];
	const done = current.tasks.filter(task => task.status === "completed").length;

	const lines: string[] = [];
	if (errors.length > 0) lines.push(`Errors: ${errors.join("; ")}`);
	if (remainingTasks.length === 0) {
		if (blockedTasks.length > 0) {
			lines.push(`Remaining items: none (${blockedTasks.length} blocked).`);
		} else {
			lines.push("Remaining items: none.");
		}
	} else {
		lines.push(`Remaining items (${remainingTasks.length}):`);
		for (const task of remainingTasks) {
			lines.push(`  - ${task.content} [${task.status}] (${task.phase})`);
		}
	}
	// Count only completed tasks as `done`; dropped (abandoned) and blocked tasks are reported separately.
	const completedAll = tasks.filter(task => task.status === "completed").length;
	const blockedAll = blockedTasks.length;
	const droppedAll = tasks.filter(task => task.status === "abandoned").length;
	const workedAhead = phases.some(
		(phase, idx) =>
			idx > currentIdx && phase.tasks.some(task => task.status === "completed" || task.status === "abandoned"),
	);
	lines.push(
		`Overall: ${completedAll}/${tasks.length} done, ${remainingTasks.length} open${blockedAll > 0 ? `, ${blockedAll} blocked` : ""}${droppedAll > 0 ? `, ${droppedAll} dropped` : ""}.`,
	);
	lines.push(
		`Active phase ${currentIdx + 1}/${phases.length} "${current.name}" (${done}/${current.tasks.length})${
			workedAhead
				? " — earliest phase with open tasks; the in-progress pointer auto-advances to the earliest open task on each completion, so it can sit behind out-of-order work (nothing was un-completed)."
				: "."
		}`,
	);
	for (const phase of phases) {
		lines.push(`  ${phase.name}:`);
		for (const task of phase.tasks) {
			const checkbox = task.status === "completed" ? "[X]" : "[ ]";
			const statusTag =
				task.status === "in_progress"
					? " (in progress)"
					: task.status === "abandoned"
						? " (dropped)"
						: task.status === "blocked"
							? task.blocker
								? ` (blocked: ${task.blocker})`
								: " (blocked)"
							: "";
			const evidenceTag =
				task.status === "completed" && task.evidence && task.evidence.length > 0
					? ` [evidence: ${task.evidence.map(e => e.toolCallId).join(", ")}]`
					: "";
			const fallbackTag = task.fallbackOf ? ` (fallback for: ${task.fallbackOf})` : "";
			lines.push(`    - ${checkbox} ${task.content}${statusTag}${fallbackTag}${evidenceTag}`);
		}
	}
	return lines.join("\n");
}

// =============================================================================
// Tool Class
// =============================================================================

export class TodoTool implements AgentTool<typeof todoSchema, TodoToolDetails> {
	readonly name = "todo";
	readonly approval = "read" as const;
	readonly label = "Todo";
	readonly summary = "Write a structured todo list to track progress within a session";
	readonly description: string;
	readonly parameters = todoSchema;
	readonly concurrency = "exclusive";
	readonly strict = true;
	// Raw args reach execute() on schema failure; resolveTodoParams re-validates
	// and repairs the one recoverable shape (missing `op`, unambiguous payload).
	readonly lenientArgValidation = true;

	readonly loadMode = "discoverable";
	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(todoDescription);
	}

	async execute(
		_toolCallId: string,
		params: TodoParams,
		_signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<TodoToolDetails>,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<TodoToolDetails>> {
		const previousPhases = clonePhases(this.session.getTodoPhases?.() ?? []);
		const storage = this.session.getSessionFile() ? "session" : "memory";
		const resolved = resolveTodoParams(params, previousPhases.length > 0);
		if (typeof resolved === "string") {
			return {
				content: [{ type: "text", text: resolved }],
				details: { phases: previousPhases, storage },
				isError: true,
			};
		}
		const entry = resolved;
		const op = entry.op;
		// Pure-view calls are reads: no normalization, no state write.
		const readOnly = op === "view";
		const branchEntries = this.session.sessionManager?.getBranch?.() ?? [];
		const observedExecutions = readOnly ? [] : extractBranchToolExecutions(branchEntries);
		const { phases: updated, errors } = readOnly
			? { phases: previousPhases, errors: [] as string[] }
			: applyParams(clonePhases(previousPhases), entry, observedExecutions, this.session.cwd);
		// half-applied batch makes the natural retry hit "already exists" for
		// the ops that did land. State and rendered summary stay at previous.
		const failed = errors.length > 0;
		const effective = failed ? previousPhases : updated;
		const completedTasks = readOnly || failed ? [] : getCompletionTransitions(previousPhases, updated);
		if (!readOnly && !failed) this.session.setTodoPhases?.(updated);
		const details: TodoToolDetails = { op, phases: effective, storage };
		if (completedTasks.length > 0) details.completedTasks = completedTasks;

		return {
			content: [{ type: "text", text: formatSummary(effective, errors, readOnly) }],
			details,
			isError: errors.length > 0 ? true : undefined,
		};
	}
}
