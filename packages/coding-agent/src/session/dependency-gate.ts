/**
 * Session-scoped deterministic prerequisite gate.
 *
 * Enforces:
 * 1. Single-flight prerequisite probing across concurrent tool fanout so identical
 *    missing-dependency checks execute at most once per readiness fingerprint.
 * 2. Readiness-fingerprinted failure memory that blocks repeated backend dispatch
 *    while interpreter and site-packages state remain unchanged, and automatically
 *    invalidates when environment or filesystem readiness changes.
 * 3. Journal provenance linking (`sourceToolCallId` and `sourceEntryId` from
 *    `SessionManager.getBranch()`) that survives context compaction and shake elision
 *    via structured `ToolResultMessage.details` without parsing natural-language prose.
 */

// No agent-loop hook imports needed; gate is invoked directly by tools and shared via ToolSession
import { isRecord } from "@reverse/utils";
import type { SessionEntry } from "./session-entries";

export type PrerequisiteFailureKind = "missing_module" | "missing_interpreter";

export interface DeterministicPrerequisiteBlock {
	deterministicFailure: true;
	toolName: string;
	action: string;
	missingDependency: string;
	failureKind: PrerequisiteFailureKind;
	setupCommand: string;
	blockedByGate: boolean;
	sourceToolCallId: string;
	sourceEntryId?: string;
	readinessFingerprint: string;
	attemptCount: number;
	reason: string;
}

export interface DependencyGateRecord {
	toolName: string;
	action: string;
	missingDependency: string;
	failureKind: PrerequisiteFailureKind;
	setupCommand: string;
	sourceToolCallId: string;
	sourceEntryId?: string;
	readinessFingerprint: string;
	attemptCount: number;
	reason: string;
	recordedAt: number;
}

export interface DependencyGateSessionLike {
	cwd?: string;
	getSessionId?: () => string | null | undefined;
	getSessionFile?: () => string | null | undefined;
	sessionManager?: {
		getSessionId?: () => string | null | undefined;
		getBranch?: () => SessionEntry[];
	};
}

function extractPrerequisiteBlockFromDetails(details: unknown): DeterministicPrerequisiteBlock | undefined {
	if (!isRecord(details)) return undefined;
	if (isRecord(details.prerequisiteBlock) && details.prerequisiteBlock.deterministicFailure === true) {
		const pb = details.prerequisiteBlock;
		if (
			typeof pb.toolName === "string" &&
			typeof pb.missingDependency === "string" &&
			typeof pb.setupCommand === "string" &&
			typeof pb.sourceToolCallId === "string" &&
			typeof pb.readinessFingerprint === "string"
		) {
			return {
				deterministicFailure: true,
				toolName: pb.toolName,
				action: typeof pb.action === "string" ? pb.action : "query",
				missingDependency: pb.missingDependency,
				failureKind: pb.failureKind === "missing_interpreter" ? "missing_interpreter" : "missing_module",
				setupCommand: pb.setupCommand,
				blockedByGate: Boolean(pb.blockedByGate),
				sourceToolCallId: pb.sourceToolCallId,
				sourceEntryId: typeof pb.sourceEntryId === "string" ? pb.sourceEntryId : undefined,
				readinessFingerprint: pb.readinessFingerprint,
				attemptCount: typeof pb.attemptCount === "number" ? pb.attemptCount : 1,
				reason: typeof pb.reason === "string" ? pb.reason : "",
			};
		}
	}
	if (isRecord(details.xdev) && "inner" in details.xdev) {
		return extractPrerequisiteBlockFromDetails(details.xdev.inner);
	}
	return undefined;
}
function isDependencySatisfiedInDetails(details: unknown, missingDependency: string): boolean {
	if (!isRecord(details)) return false;
	if (isRecord(details.xdev) && "inner" in details.xdev) {
		return isDependencySatisfiedInDetails(details.xdev.inner, missingDependency);
	}
	if (missingDependency === "lief") {
		if (details.action === "query" && details.isError !== true && details.status !== "blocked_prerequisite") {
			return true;
		}
		if (details.action === "status" && isRecord(details.lief) && details.lief.available === true) {
			return true;
		}
		if (details.action === "repair" && details.candidateValid === true) {
			return true;
		}
	}
	return false;
}

export class DependencyGate {
	readonly #session?: DependencyGateSessionLike;
	readonly #records = new Map<string, DependencyGateRecord>();
	readonly #clearedAtEntryId = new Map<string, string>();
	readonly #inFlight = new Map<
		string,
		Promise<
			| { status: "available"; value: unknown; fingerprint: string }
			| { status: "deterministic_missing"; fingerprint: string }
			| { status: "probe_failed"; error: string; fingerprint: string }
		>
	>();

	constructor(session?: DependencyGateSessionLike) {
		this.#session = session;
	}

	/** Reset all cached prerequisite blocks (e.g. on session switch). */
	reset(): void {
		this.#records.clear();
		this.#clearedAtEntryId.clear();
		this.#inFlight.clear();
	}

	/** Clear a specific dependency block after explicit status verification or installation. */
	clearDependency(missingDependency: string): void {
		this.#records.delete(missingDependency);
		const branch = this.#session?.sessionManager?.getBranch?.();
		const leafId = branch && branch.length > 0 ? branch[branch.length - 1]?.id : undefined;
		this.#clearedAtEntryId.set(missingDependency, leafId ?? "__cleared_in_memory__");
	}

	/** Inspect active record for a dependency, if any. */
	getRecord(missingDependency: string): DependencyGateRecord | undefined {
		return this.#records.get(missingDependency);
	}

	/**
	 * Synchronize provenance (`sourceEntryId`) or rehydrate deterministic prerequisite blocks
	 * from the active session branch when a toolResult entry has landed in the journal.
	 */
	#syncWithBranch(missingDependency: string, currentFingerprint: string): void {
		const branch = this.#session?.sessionManager?.getBranch?.();
		if (!branch || branch.length === 0) return;

		const existing = this.#records.get(missingDependency);
		if (existing) {
			if (!existing.sourceEntryId) {
				for (let i = branch.length - 1; i >= 0; i--) {
					const entry = branch[i];
					if (entry.type !== "message" || !isRecord(entry.message)) continue;
					if (entry.message.role === "toolResult" && entry.message.toolCallId === existing.sourceToolCallId) {
						existing.sourceEntryId = entry.id;
						break;
					}
				}
			}
			return;
		}

		const clearedMarker = this.#clearedAtEntryId.get(missingDependency);
		if (clearedMarker === "__cleared_in_memory__") return;

		// 从当前分支历史逆序扫描：若先遇到已恢复成功的记录或显式清除位点，则停止回溯，防止恢复旧的阻塞状态
		for (let i = branch.length - 1; i >= 0; i--) {
			const entry = branch[i];
			if (clearedMarker && entry.id === clearedMarker) break;
			if (entry.type !== "message" || !isRecord(entry.message)) continue;
			const msg = entry.message;
			if (msg.role !== "toolResult") continue;
			if (msg.isError !== true && isDependencySatisfiedInDetails(msg.details, missingDependency)) {
				break;
			}
			const block = extractPrerequisiteBlockFromDetails(msg.details);
			if (!block || block.missingDependency !== missingDependency) continue;
			if (block.readinessFingerprint !== currentFingerprint) break;

			let originEntryId = block.sourceEntryId ?? entry.id;
			for (let j = 0; j <= i; j++) {
				const earlier = branch[j];
				if (earlier.type !== "message" || !isRecord(earlier.message)) continue;
				if (earlier.message.role === "toolResult" && earlier.message.toolCallId === block.sourceToolCallId) {
					originEntryId = earlier.id;
					break;
				}
			}

			this.#records.set(missingDependency, {
				toolName: block.toolName,
				action: block.action,
				missingDependency: block.missingDependency,
				failureKind: block.failureKind,
				setupCommand: block.setupCommand,
				sourceToolCallId: block.sourceToolCallId,
				sourceEntryId: originEntryId,
				readinessFingerprint: block.readinessFingerprint,
				attemptCount: block.attemptCount,
				reason: block.reason,
				recordedAt: Date.now(),
			});
			break;
		}
	}

	/**
	 * Return an already-recorded deterministic block for the current readiness fingerprint
	 * without probing. Callers use it to skip expensive backend work (e.g. SoFixer runs)
	 * once the prerequisite is known missing.
	 */
	blockIfKnown(options: {
		toolName: string;
		action: string;
		missingDependency: string;
		getReadinessFingerprint: () => string;
	}): DeterministicPrerequisiteBlock | undefined {
		const key = options.missingDependency;
		const currentFingerprint = options.getReadinessFingerprint();
		this.#syncWithBranch(key, currentFingerprint);
		return this.#matchExistingBlock(key, currentFingerprint, options);
	}

	#matchExistingBlock(
		key: string,
		currentFingerprint: string,
		options: { toolName: string; action: string },
	): DeterministicPrerequisiteBlock | undefined {
		const existing = this.#records.get(key);
		if (!existing) return undefined;
		if (existing.readinessFingerprint !== currentFingerprint) {
			// 环境或解释器/site-packages 指纹已变化，清除旧门禁以便重新探测
			this.#records.delete(key);
			return undefined;
		}
		existing.attemptCount += 1;
		this.#syncWithBranch(key, currentFingerprint);
		return {
			deterministicFailure: true,
			toolName: options.toolName,
			action: options.action,
			missingDependency: existing.missingDependency,
			failureKind: existing.failureKind,
			setupCommand: existing.setupCommand,
			blockedByGate: true,
			sourceToolCallId: existing.sourceToolCallId,
			sourceEntryId: existing.sourceEntryId,
			readinessFingerprint: existing.readinessFingerprint,
			attemptCount: existing.attemptCount,
			reason: existing.reason,
		};
	}

	async acquireOrProbe<TResult>(options: {
		toolName: string;
		action: string;
		missingDependency: string;
		setupCommand: string;
		toolCallId: string;
		getReadinessFingerprint: () => string;
		runProbe: (fingerprint: string) => Promise<
			| { status: "available"; value: TResult; fingerprint: string }
			| {
					status: "deterministic_missing";
					failureKind: PrerequisiteFailureKind;
					reason: string;
					fingerprint: string;
			  }
			| { status: "probe_failed"; error: string; fingerprint: string }
		>;
	}): Promise<
		| { status: "available"; value: TResult }
		| { status: "blocked"; block: DeterministicPrerequisiteBlock }
		| { status: "probe_failed"; error: string; fingerprint: string }
	> {
		const key = options.missingDependency;

		// 若已有同依赖的并发探测正在进行，等待其完成以共享单飞结果（Single-flight）
		const activeFlight = this.#inFlight.get(key);
		if (activeFlight) {
			const flightResult = await activeFlight;
			if (flightResult.status === "available") {
				return { status: "available", value: flightResult.value as TResult };
			}
			if (flightResult.status === "probe_failed") {
				return {
					status: "probe_failed",
					error: flightResult.error,
					fingerprint: flightResult.fingerprint,
				};
			}
		}

		const currentFingerprint = options.getReadinessFingerprint();
		this.#syncWithBranch(key, currentFingerprint);

		const existingBlock = this.#matchExistingBlock(key, currentFingerprint, options);
		if (existingBlock) {
			return { status: "blocked", block: existingBlock };
		}

		type FlightOutcome =
			| { status: "available"; value: unknown; fingerprint: string }
			| { status: "deterministic_missing"; fingerprint: string }
			| { status: "probe_failed"; error: string; fingerprint: string };
		const { promise: flightPromise, resolve: resolveFlight } = Promise.withResolvers<FlightOutcome>();
		this.#inFlight.set(key, flightPromise);

		let settledFlight:
			| { status: "available"; value: unknown; fingerprint: string }
			| { status: "deterministic_missing"; fingerprint: string }
			| { status: "probe_failed"; error: string; fingerprint: string } = {
			status: "probe_failed",
			error: "Probe aborted",
			fingerprint: currentFingerprint,
		};

		try {
			const probeOutcome = await options.runProbe(currentFingerprint);
			if (probeOutcome.status === "available") {
				this.clearDependency(key);
				settledFlight = {
					status: "available",
					value: probeOutcome.value,
					fingerprint: probeOutcome.fingerprint,
				};
				return { status: "available", value: probeOutcome.value };
			}
			if (probeOutcome.status === "probe_failed") {
				// 瞬态或子进程探针运行异常不得缓存为缺失依赖门禁
				settledFlight = {
					status: "probe_failed",
					error: probeOutcome.error,
					fingerprint: probeOutcome.fingerprint,
				};
				return {
					status: "probe_failed",
					error: probeOutcome.error,
					fingerprint: probeOutcome.fingerprint,
				};
			}

			const record: DependencyGateRecord = {
				toolName: options.toolName,
				action: options.action,
				missingDependency: key,
				failureKind: probeOutcome.failureKind,
				setupCommand: options.setupCommand,
				sourceToolCallId: options.toolCallId,
				sourceEntryId: undefined,
				readinessFingerprint: probeOutcome.fingerprint,
				attemptCount: 1,
				reason: probeOutcome.reason,
				recordedAt: Date.now(),
			};
			this.#clearedAtEntryId.delete(key);
			this.#records.set(key, record);
			this.#syncWithBranch(key, probeOutcome.fingerprint);
			settledFlight = {
				status: "deterministic_missing",
				fingerprint: probeOutcome.fingerprint,
			};

			return {
				status: "blocked",
				block: {
					deterministicFailure: true,
					toolName: options.toolName,
					action: options.action,
					missingDependency: record.missingDependency,
					failureKind: record.failureKind,
					setupCommand: record.setupCommand,
					blockedByGate: false,
					sourceToolCallId: record.sourceToolCallId,
					sourceEntryId: record.sourceEntryId,
					readinessFingerprint: record.readinessFingerprint,
					attemptCount: record.attemptCount,
					reason: record.reason,
				},
			};
		} finally {
			this.#inFlight.delete(key);
			resolveFlight(settledFlight);
		}
	}
	// End of DependencyGate methods
}

interface ScopedDependencyGateEntry {
	sessionId?: string | null;
	sessionFile?: string | null;
	gate: DependencyGate;
}

const sessionGates = new WeakMap<object, ScopedDependencyGateEntry>();

/**
 * Retrieve or create the canonical session-scoped DependencyGate.
 * Uses `session.sessionManager ?? session` as WeakMap key so direct tool calls,
 * `write xd://<tool>`, and `eval` JS bridge invocations share the same gate instance,
 * while session switches (`sessionId` / `sessionFile` changes) automatically isolate state.
 */
export function getSessionDependencyGate(session: DependencyGateSessionLike): DependencyGate {
	const keyObj: object =
		session.sessionManager && typeof session.sessionManager === "object" ? session.sessionManager : session;
	const currentId = session.sessionManager?.getSessionId?.() ?? session.getSessionId?.() ?? null;
	const currentFile = session.getSessionFile?.() ?? null;

	const existing = sessionGates.get(keyObj);
	if (existing && existing.sessionId === currentId && existing.sessionFile === currentFile) {
		return existing.gate;
	}

	const gate = new DependencyGate(session);
	sessionGates.set(keyObj, {
		sessionId: currentId,
		sessionFile: currentFile,
		gate,
	});
	return gate;
}
