import { INTENT_FIELD } from "@reverse/wire";
import type { AssistantMessage, ToolCall, ToolResultMessage } from "../types";

const LEGACY_INTENT_FIELD = "__intent";
const RESULT_SUMMARY_LIMIT = 200;
const ARGUMENT_SUMMARY_LIMIT = 400;
/** Distinct deterministic preconditions tracked per guard before the oldest is dropped. */
const DISPATCH_FAILURE_LIMIT = 64;
/** Tool results remembered so the native after-hook and the turn-end sweep never count one twice. */
const OBSERVED_RESULT_LIMIT = 256;
/** Warnings held for the next turn-end injection. */
const PENDING_WARNING_LIMIT = 16;
/** Identical batches already warned about; reissued until the sequence moves on. */
const BLOCKED_BATCH_LIMIT = 4;
/** Prepared-call argument records kept for exact-batch comparisons. */
const DISPATCHED_ARGS_LIMIT = 1024;

/** Runtime settings for cross-turn tool-call repetition detection. */
export interface ToolCallLoopGuardOptions {
	readonly threshold: number;
	readonly exemptTools: readonly string[];
}

/** A completed assistant turn plus the tool results it produced. */
export interface ToolCallLoopTurn {
	readonly message: AssistantMessage;
	readonly toolResults: readonly ToolResultMessage[];
	/** The turn also delivered context outside its tool results (extension `additionalContext`). */
	readonly injectedContext?: boolean;
}

/** Details needed to steer the model away from a repeated tool call. */
export interface RepeatedToolCallDetection {
	readonly kind: "repeated_tool_call";
	readonly toolName: string;
	readonly count: number;
	readonly resultSummary: string;
	readonly argumentsSummary: string;
}

/**
 * A tool-owned deterministic rejection: the call could never dispatch, and no
 * child, worker, or provider request was launched for it.
 *
 * `code` identifies the kind of rejection, `key` is the stable semantic
 * precondition (independent of task prose, session text, and tool-call ids),
 * and `message` tells the model what to correct. The guard counts `key` so a
 * reworded request with the same broken precondition keeps accumulating.
 */
export interface DeterministicDispatchFailure {
	readonly code: string;
	readonly key: string;
	readonly message: string;
}

/** One executed tool result, read for success clearing or a deterministic rejection. */
export interface ToolCallObservation {
	readonly toolCallId: string;
	readonly toolName: string;
	readonly isError: boolean;
	/** Tool result details; a deterministic rejection lives at `details.dispatchFailure`. */
	readonly details: unknown;
}

/** A deterministic precondition that already failed at the threshold and is now blocked. */
export interface RepeatedDispatchFailureDetection {
	readonly kind: "repeated_dispatch_failure";
	readonly toolName: string;
	readonly count: number;
	readonly code: string;
	readonly key: string;
	readonly message: string;
}

/** The warned identical batch a fresh tool batch reproduces. */
export interface RepeatedToolCallBlock {
	readonly toolName: string;
	readonly count: number;
}

interface DispatchFailureBucket {
	toolName: string;
	code: string;
	key: string;
	message: string;
	count: number;
	warned: boolean;
}

interface BlockedBatch {
	hash: string;
	toolName: string;
	count: number;
	/**
	 * Any call in this batch returned a deterministic rejection (not just the
	 * reported call). Such a batch is owned by the semantic path: once the
	 * precondition no longer fails, the same calls must be allowed even though
	 * they are byte-identical.
	 */
	hasDispatchFailure: boolean;
}

function canonicalizeToolCallValue(value: unknown): unknown {
	if (Array.isArray(value)) {
		return value.map(item => canonicalizeToolCallValue(item));
	}
	if (!value || typeof value !== "object") {
		return value;
	}

	const input = value as Record<string, unknown>;
	const output: Record<string, unknown> = {};
	for (const key of Object.keys(input).sort()) {
		if (key === INTENT_FIELD || key === LEGACY_INTENT_FIELD) continue;
		output[key] = canonicalizeToolCallValue(input[key]);
	}
	return output;
}

function canonicalTurn(
	toolCalls: readonly ToolCall[],
	dispatchedArgs?: (toolCall: ToolCall) => string | undefined,
): string {
	return JSON.stringify(
		toolCalls
			.map(tc => {
				const resolved = dispatchedArgs?.(tc);
				return `${tc.name}\u0000${resolved ?? JSON.stringify(canonicalizeToolCallValue(tc.arguments))}`;
			})
			.sort(),
	);
}

function summarizeText(text: string, limit: number): string {
	let summary = text.replace(/\s+/g, " ").trim();
	if (summary.length > limit) {
		summary = `${summary.slice(0, limit)}…`;
	}
	return summary;
}

function summarizeToolResult(toolResults: readonly ToolResultMessage[], toolCallId: string): string {
	const result = toolResults.find(candidate => candidate.toolCallId === toolCallId);
	if (!result) return "";

	const textParts: string[] = [];
	for (const block of result.content) {
		if (block.type === "text") {
			textParts.push(block.text);
		}
	}
	return summarizeText(textParts.join("\n"), RESULT_SUMMARY_LIMIT);
}

/**
 * Boundary validation for an externally produced dispatch failure. Only a
 * record of three non-empty strings is trusted; anything else is treated as an
 * absent (transient) failure rather than a deterministic one.
 */
export function normalizeDeterministicDispatchFailure(value: unknown): DeterministicDispatchFailure | undefined {
	if (!value || typeof value !== "object") return undefined;
	if (!("code" in value) || typeof value.code !== "string" || value.code.length === 0) return undefined;
	if (!("key" in value) || typeof value.key !== "string" || value.key.length === 0) return undefined;
	if (!("message" in value) || typeof value.message !== "string" || value.message.length === 0) return undefined;
	return { code: value.code, key: value.key, message: value.message };
}

/** Reads the tool-owned rejection a failed result carries at `details.dispatchFailure`. */
export function readDeterministicDispatchFailure(details: unknown): DeterministicDispatchFailure | undefined {
	if (!details || typeof details !== "object" || !("dispatchFailure" in details)) return undefined;
	return normalizeDeterministicDispatchFailure(details.dispatchFailure);
}

/**
 * Detects repeated tool calls across model turns: byte-identical batches
 * (after canonicalizing key order and harness intent fields) and reissues of a
 * deterministic dispatch failure tracked by its semantic key.
 */
export class ToolCallLoopGuard {
	#threshold: number;
	#exemptTools: ReadonlySet<string>;
	#lastHash: string | undefined;
	#count = 0;
	#blockedBatches: BlockedBatch[] = [];
	/** Batch a pre-dispatch block already handled; its synthetic turn is not a new repetition. */
	#expectedBlockedHash: string | undefined;
	#dispatchFailures = new Map<string, DispatchFailureBucket>();
	#pendingWarnings = new Map<string, RepeatedDispatchFailureDetection>();
	#observedResults = new Set<string>();
	/** Final arguments each prepared call would dispatch, keyed by tool-call id. */
	#dispatchedArgs = new Map<string, string>();

	constructor(options: ToolCallLoopGuardOptions) {
		this.#threshold = Math.max(1, Math.trunc(options.threshold));
		this.#exemptTools = new Set(options.exemptTools);
	}

	/** Clears every turn, batch, and precondition record (prompt/session boundary). */
	reset(): void {
		this.#lastHash = undefined;
		this.#count = 0;
		this.#blockedBatches = [];
		this.#expectedBlockedHash = undefined;
		this.#dispatchFailures.clear();
		this.#pendingWarnings.clear();
		this.#observedResults.clear();
		this.#dispatchedArgs.clear();
	}

	/**
	 * Stores the final arguments a prepared call will execute with (validated
	 * defaults, normalization, extension revision). Repetition detection uses
	 * these instead of the raw model arguments, so a repair or the validator's
	 * own normalization can never be mistaken for an identical resend.
	 */
	recordDispatchedArgs(toolCallId: string, args: unknown): void {
		if (this.#dispatchedArgs.size >= DISPATCHED_ARGS_LIMIT) {
			const oldest = this.#dispatchedArgs.keys().next().value;
			if (oldest !== undefined) this.#dispatchedArgs.delete(oldest);
		}
		this.#dispatchedArgs.set(toolCallId, JSON.stringify(canonicalizeToolCallValue(args)));
	}

	/**
	 * Whether every call in the batch has its final arguments recorded. Exact
	 * repetition is only judged on the last prepared call: an earlier call can
	 * still be repaired by its extension hook, so checking the raw batch early
	 * would stop the turn before the repair lands.
	 */
	hasAllDispatchedArgs(toolCalls: readonly ToolCall[]): boolean {
		return toolCalls.every(toolCall => this.#dispatchedArgs.has(toolCall.id));
	}

	/**
	 * Records one completed turn and reports repetitions at or beyond the
	 * threshold. Deterministic dispatch failures counted here are surfaced
	 * separately via {@link drainDispatchFailureWarnings}.
	 */
	recordTurn(turn: ToolCallLoopTurn): RepeatedToolCallDetection | null {
		for (const result of turn.toolResults) {
			this.observeToolResult({
				toolCallId: result.toolCallId,
				toolName: result.toolName,
				isError: result.isError,
				details: result.details,
			});
		}

		const toolCalls = turn.message.content.filter((part): part is ToolCall => part.type === "toolCall");
		if (toolCalls.length === 0) {
			this.#lastHash = undefined;
			this.#count = 0;
			return null;
		}
		if (toolCalls.every(tc => this.#exemptTools.has(tc.name))) {
			// An exempt poll its tool flagged useless (a wait that elapsed or found
			// nothing to wait for) is skipped, so alternating it with a repeated call
			// cannot hide the loop. Any other exempt turn, failures included, may have
			// changed state (finished jobs, a message, injected context), so it ends
			// the repetition.
			const idle =
				!turn.injectedContext &&
				toolCalls.every(tc => turn.toolResults.find(result => result.toolCallId === tc.id)?.useless === true);
			if (!idle) {
				this.#lastHash = undefined;
				this.#count = 0;
			}
			return null;
		}

		const turnHash = canonicalTurn(toolCalls, tc => this.#dispatchedArgs.get(tc.id));
		if (this.#expectedBlockedHash !== undefined) {
			const blocked = this.#expectedBlockedHash;
			this.#expectedBlockedHash = undefined;
			if (turnHash === blocked) {
				// The batch was stopped before dispatch: no new repetition happened,
				// and no model step followed, so no second redirect is earned.
				this.#lastHash = undefined;
				this.#count = 0;
				return null;
			}
		}
		if (turnHash === this.#lastHash) {
			this.#count++;
		} else {
			// Only the batch immediately following the warning is blocked; once the
			// model moves to another batch, state may have changed and a later
			// return to the old calls starts a fresh count.
			this.#blockedBatches = [];
			this.#lastHash = turnHash;
			this.#count = 1;
		}

		if (this.#count < this.#threshold) return null;
		const reportCall = toolCalls.find(tc => !this.#exemptTools.has(tc.name)) ?? toolCalls[0]!;
		// Any non-exempt call in the batch may be the structured rejection: a
		// leading successful call must not hide a later deterministic failure.
		const hasDispatchFailure = toolCalls.some(call => {
			if (this.#exemptTools.has(call.name)) return false;
			const result = turn.toolResults.find(candidate => candidate.toolCallId === call.id);
			return result?.isError === true && readDeterministicDispatchFailure(result.details) !== undefined;
		});
		this.#rememberBlockedBatch(turnHash, reportCall.name, this.#count, hasDispatchFailure);
		return {
			kind: "repeated_tool_call",
			toolName: reportCall.name,
			count: this.#count,
			resultSummary: summarizeToolResult(turn.toolResults, reportCall.id),
			argumentsSummary: summarizeText(
				this.#dispatchedArgs.get(reportCall.id) ?? JSON.stringify(canonicalizeToolCallValue(reportCall.arguments)),
				ARGUMENT_SUMMARY_LIMIT,
			),
		};
	}

	/**
	 * Records one executed result. A success clears that tool's deterministic
	 * failure history; a failure only counts when its details carry a valid
	 * `dispatchFailure` (transient child/provider errors never do).
	 */
	observeToolResult(observation: ToolCallObservation): void {
		// Configured exempt tools may repeat by contract (wait/job polls); their
		// deterministic rejections must not earn a semantic hard stop either.
		if (this.#exemptTools.has(observation.toolName)) return;
		const observedKey = `${observation.toolName}\u0000${observation.toolCallId}`;
		if (this.#observedResults.has(observedKey)) return;
		this.#observedResults.add(observedKey);
		if (this.#observedResults.size > OBSERVED_RESULT_LIMIT) {
			const oldest = this.#observedResults.values().next().value;
			if (oldest !== undefined) this.#observedResults.delete(oldest);
		}

		if (!observation.isError) {
			this.#clearTool(observation.toolName);
			return;
		}
		const failure = readDeterministicDispatchFailure(observation.details);
		if (!failure) return;

		const bucketKey = `${observation.toolName}\u0000${failure.code}\u0000${failure.key}`;
		const existing = this.#dispatchFailures.get(bucketKey);
		// Re-insert so eviction stays least-recently-failed first.
		this.#dispatchFailures.delete(bucketKey);
		const bucket: DispatchFailureBucket = existing ?? {
			toolName: observation.toolName,
			code: failure.code,
			key: failure.key,
			message: failure.message,
			count: 0,
			warned: false,
		};
		bucket.count++;
		bucket.message = failure.message;
		this.#dispatchFailures.set(bucketKey, bucket);
		if (this.#dispatchFailures.size > DISPATCH_FAILURE_LIMIT) {
			const oldest = this.#dispatchFailures.keys().next().value;
			if (oldest !== undefined) this.#dispatchFailures.delete(oldest);
		}
		if (bucket.warned || bucket.count < this.#threshold) return;

		bucket.warned = true;
		this.#pendingWarnings.set(bucketKey, {
			kind: "repeated_dispatch_failure",
			toolName: bucket.toolName,
			count: bucket.count,
			code: bucket.code,
			key: bucket.key,
			message: bucket.message,
		});
		if (this.#pendingWarnings.size > PENDING_WARNING_LIMIT) {
			const oldest = this.#pendingWarnings.keys().next().value;
			if (oldest !== undefined) this.#pendingWarnings.delete(oldest);
		}
	}

	/** Warnings earned since the last drain, for injection at the completed turn boundary. */
	drainDispatchFailureWarnings(): RepeatedDispatchFailureDetection[] {
		const warnings = [...this.#pendingWarnings.values()];
		this.#pendingWarnings.clear();
		return warnings;
	}

	/**
	 * A candidate call whose own deterministic precondition already failed at
	 * the threshold and was warned. A corrected call reports undefined or a
	 * different key, so it never matches here.
	 */
	blockedDispatchFailure(
		toolName: string,
		failure: DeterministicDispatchFailure | undefined,
	): RepeatedDispatchFailureDetection | null {
		if (!failure || this.#exemptTools.has(toolName)) return null;
		const bucketKey = `${toolName}\u0000${failure.code}\u0000${failure.key}`;
		const bucket = this.#dispatchFailures.get(bucketKey);
		if (!bucket || !bucket.warned || bucket.count < this.#threshold) return null;
		// The block supersedes any warning not injected yet: the turn stops here.
		this.#pendingWarnings.delete(bucketKey);
		return {
			kind: "repeated_dispatch_failure",
			toolName: bucket.toolName,
			count: bucket.count,
			code: bucket.code,
			key: bucket.key,
			message: bucket.message,
		};
	}

	/**
	 * A batch that reproduces the exact calls of the last warned repetition.
	 * Calls are compared by the arguments they will actually dispatch. Only
	 * call this once {@link hasAllDispatchedArgs} is true, so every call's
	 * final (possibly extension-revised) arguments are known.
	 */
	blockedRepeatedBatch(toolCalls: readonly ToolCall[]): RepeatedToolCallBlock | null {
		if (this.#blockedBatches.length === 0) return null;
		const active = toolCalls.filter(tc => !this.#exemptTools.has(tc.name));
		if (active.length === 0) return null;
		const hash = canonicalTurn(toolCalls, tc => this.#dispatchedArgs.get(tc.id));
		const blocked = this.#blockedBatches.find(candidate => candidate.hash === hash);
		if (!blocked) return null;
		// A batch that repeated a deterministic rejection is owned by the
		// semantic check: a fixed configuration (or a different rejection) must
		// let the identical calls dispatch. Only plain repeated calls hard-stop
		// on the exact-argument path.
		if (blocked.hasDispatchFailure) return null;
		this.#expectedBlockedHash = hash;
		this.#lastHash = undefined;
		this.#count = 0;
		return { toolName: blocked.toolName, count: blocked.count };
	}

	#rememberBlockedBatch(hash: string, toolName: string, count: number, hasDispatchFailure: boolean): void {
		if (this.#blockedBatches.some(candidate => candidate.hash === hash)) return;
		this.#blockedBatches.push({ hash, toolName, count, hasDispatchFailure });
		if (this.#blockedBatches.length > BLOCKED_BATCH_LIMIT) this.#blockedBatches.shift();
	}

	#clearTool(toolName: string): void {
		for (const [bucketKey, bucket] of this.#dispatchFailures) {
			if (bucket.toolName === toolName) this.#dispatchFailures.delete(bucketKey);
		}
		for (const [bucketKey, warning] of this.#pendingWarnings) {
			if (warning.toolName === toolName) this.#pendingWarnings.delete(bucketKey);
		}
		// A working call proves the tool's environment recovered; an exact
		// repetition from before the fix must not stop a later legitimate batch.
		this.#blockedBatches = this.#blockedBatches.filter(candidate => candidate.toolName !== toolName);
	}
}
