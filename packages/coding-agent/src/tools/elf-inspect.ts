/**
 * Native ELF deep inspection, controlled runtime memory dumping, and SoFixer reconstruction tool.
 *
 * Integrates:
 * 1. Deep LIEF inspection for segments, dynamic tables, relocations, constructors, and address mapping.
 * 2. Controlled module memory dumping via Frida, preserving virtual address layout and PT_LOAD holes,
 *    persisting provenance manifests.
 * 3. External SoFixer reconstruction for memory-dumped ELFs with structural LIEF validation.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import elfInspectDescription from "../prompts/tools/elf-inspect.md" with { type: "text" };
import {
	computeLiefReadinessFingerprint,
	type LiefDetailedProbeResult,
	type LiefProbeResult,
	type LiefRequirementDeps,
	resolveLiefPythonDetailed,
} from "../extensibility/lief-install";
import { normalizeSoFixerArch, resolveSoFixer } from "../extensibility/sofixer-toolchain";
import {
	type DependencyGate,
	type DeterministicPrerequisiteBlock,
	getSessionDependencyGate,
	type PrerequisiteFailureKind,
} from "../session/dependency-gate";
import { appendArtifactReference, saveArtifactText } from "./gh-common";
import type { ToolSession } from "./index";
import { resolveReadPath, resolveToCwd } from "./path-utils";
import { type ReversePythonOptions, type ReversePythonResult, runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";
import { getFileMetadata, runSafeSubprocess, safePublishArtifact } from "./vmp-common";
import { executeModuleDump, type MemoryRangeInfo, type UnmappedGapInfo } from "./elf-dump-helper";

// Staged text asset for ELF LIEF Python worker
import elfInspectWorkerSource from "./elf-inspect-worker.py" with { type: "text" };

const MAX_QUERY_FILE_SIZE = 1024 * 1024 * 1024; // 1 GiB
const EM_ARM = 0x28; // 40 (ARM 32-bit)
const EM_AARCH64 = 0xb7; // 183 (ARM64)

// ============================================================================
// Parameter Schema
// ============================================================================

export const elfInspectSchema = type({
	action: type
		.enumerated("status", "query", "dump", "repair", "dump_and_repair")
		.describe(
			"Action to perform: 'status' (probe LIEF and SoFixer availability), 'query' (deep LIEF inspection of local ELF binary), 'dump' (controlled module memory dump from running process via Frida), 'repair' (reconstruct memory-dumped ELF using external SoFixer tool and validate with LIEF), or 'dump_and_repair' (combined dump, SoFixer repair, and validation pipeline)",
		),
	"path?": type("string").describe(
		"Path to target ELF binary (shared object .so, executable, or object file). Required for 'query'",
	),
	"query_type?": type
		.enumerated(
			"info",
			"segments",
			"dynamic",
			"constructors",
			"relocations",
			"sections",
			"symbols",
			"address_map",
			"all",
		)
		.describe(
			"Inspection query type for action 'query': 'info' (header and high-level summary, default), 'segments' (PT_LOAD and program headers), 'dynamic' (dynamic table DT_* entries and needed libraries), 'constructors' (init functions, .init_array pointers, and dtors), 'relocations' (dynamic and PLT relocations), 'sections' (section headers), 'symbols' (exported and imported symbols), 'address_map' (virtual address to file offset translation), or 'all' (comprehensive multi-view analysis)",
		),
	"filter?": type("string").describe(
		"Optional case-insensitive substring filter for symbol, section, library, or relocation names",
	),
	"limit?": type("number.integer >= 1").describe("Maximum items to return for paged queries (default 50, max 500)"),
	"offset?": type("number.integer >= 0").describe("Pagination offset for paged queries (default 0)"),
	"address?": type("string | number").describe(
		"Virtual memory address (VA or RVA, e.g. '0x1234' or number) for query_type 'address_map' to translate into file offset",
	),
	"file_offset?": type("string | number").describe(
		"File offset (e.g. '0x1234' or number) for query_type 'address_map' to translate into virtual address",
	),
	"pid?": type("string | number").describe(
		"Target process ID for memory dump (decimal integer or hex string). Required for 'dump' and 'dump_and_repair'",
	),
	"module?": type("string").describe(
		"Target module name to dump from process memory (e.g. 'libnative-lib.so'). Required for 'dump' and 'dump_and_repair'",
	),
	"device?": type("string").describe("Frida device identifier or serial for remote/USB target"),
	"usb?": type("boolean").describe("Target USB device/emulator via Frida"),
	"host?": type("string").describe("Target remote Frida server host (e.g. '192.168.1.5:27042')"),
	"max_bytes?": type("number.integer >= 1").describe("Maximum module bytes to dump (default 64MB, max 256MB)"),
	"chunk_size?": type("number.integer >= 1").describe("Memory read chunk size in bytes (default 64KB, max 1MB)"),
	"dump_path?": type("string").describe("Path to memory-dumped ELF binary on disk. Required for 'repair'"),
	"base_address?": type("string | number").describe(
		"Module memory load base address in hex form (e.g. '0x7f12340000'). Required for 'repair' if not in manifest",
	),
	"arch?": type("string").describe(
		"Target architecture for SoFixer repair ('arm', 'arm64', '32', or '64'). Inferred from dump header if omitted",
	),
	"output_path?": type("string").describe(
		"Optional safe destination path to publish verified candidate output file (refuses to overwrite existing files)",
	),
	"timeout?": type("number.integer >= 1").describe("Execution timeout in seconds (default 60, max 300)"),
});

export type ElfInspectParams = typeof elfInspectSchema.infer;

// ============================================================================
// Output Models
// ============================================================================

export interface DumpManifest {
	pid: string;
	device?: string;
	module: string;
	modulePath?: string;
	base: string;
	moduleSize: number;
	totalReadable: number;
	unmappedBytes: number;
	readableRanges: MemoryRangeInfo[];
	unmappedGaps: UnmappedGapInfo[];
	sha256: string;
	abi: "arm" | "arm64";
	timestamp: string;
}

export interface ElfStatusDetails {
	action: "status";
	ready: boolean;
	lief: {
		available: boolean;
		status?: "available" | "missing_module" | "missing_interpreter" | "probe_failed";
		pythonBin: string | null;
		version: string | null;
		modulePath?: string | null;
		probeError?: string;
		readinessFingerprint?: string;
		installHint: string;
	};
	sofixer: {
		available: boolean;
		binaries: {
			arch32: string | null;
			arch64: string | null;
		};
		installHint: string;
	};
}

export interface ElfQueryDetails {
	action: "query";
	path: string;
	queryType: string;
	fileSize: number;
	data: unknown;
	artifactId?: string;
}

/** SoFixer output preserved when LIEF structural validation cannot run. */
export interface ElfRepairCandidatePreservation {
	dumpPath: string;
	baseAddress: string;
	arch: "32" | "64";
	sofixerPath: string;
	candidatePath: string;
	candidateSha256: string;
	candidateBytes: number;
	manifestVerified: boolean;
}

export interface ElfPrerequisiteBlockedDetails {
	action: "query" | "dump" | "repair" | "dump_and_repair";
	isError: true;
	status: "blocked_prerequisite";
	deterministicFailure: true;
	missingDependency: "lief";
	failureKind: PrerequisiteFailureKind;
	setupCommand: "reverse setup reverse lief";
	blockedByGate: boolean;
	sourceToolCallId: string;
	sourceEntryId?: string;
	readinessFingerprint: string;
	attemptCount: number;
	reason: string;
	path?: string;
	queryType?: string;
	/** Preserved SoFixer candidate; never reported as a successful repair. */
	candidate?: ElfRepairCandidatePreservation;
	dump?: ElfDumpDetails;
	prerequisiteBlock: DeterministicPrerequisiteBlock;
}

export interface ElfProbeFailedDetails {
	action: "query" | "repair" | "dump_and_repair";
	isError: true;
	status: "probe_failed";
	deterministicFailure: false;
	probeError: string;
	readinessFingerprint: string;
	path?: string;
	queryType?: string;
	/** Preserved SoFixer candidate; never reported as a successful repair. */
	candidate?: ElfRepairCandidatePreservation;
	dump?: ElfDumpDetails;
}

export interface ElfDumpDetails {
	action: "dump";
	success: boolean;
	pid: string;
	module: string;
	baseAddress: string;
	moduleSize: number;
	totalReadableBytes: number;
	unmappedGapBytes: number;
	unmappedGapsCount: number;
	sha256: string;
	rangesCount: number;
	dumpArtifactId?: string;
	dumpPath?: string;
	manifestPath?: string;
	publishedPath?: string;
}

export interface ElfRepairDetails {
	action: "repair";
	success: boolean;
	dumpPath: string;
	baseAddress: string;
	arch: "32" | "64";
	sofixerPath: string;
	candidatePath?: string;
	candidateSha256?: string;
	candidateBytes?: number;
	candidateValid: boolean;
	isAnalyzable: boolean;
	isRunnable: boolean;
	analyzableNotice: string;
	validationRisks: string[];
	validationDetails?: unknown;
	manifestVerified?: boolean;
	publishedPath?: string;
	repairArtifactId?: string;
}

export interface ElfDumpAndRepairDetails {
	action: "dump_and_repair";
	dump: ElfDumpDetails;
	repair: ElfRepairDetails;
}

export type ElfInspectDetails =
	| ElfStatusDetails
	| ElfQueryDetails
	| ElfPrerequisiteBlockedDetails
	| ElfProbeFailedDetails
	| ElfDumpDetails
	| ElfRepairDetails
	| ElfDumpAndRepairDetails;

export interface ElfWorkerPayload {
	status: string;
	result?: unknown;
	error?: string;
}

export interface ElfInspectToolDeps {
	liefOptions?: LiefRequirementDeps;
	resolveLiefDetailed?: (options?: LiefRequirementDeps) => LiefDetailedProbeResult | Promise<LiefDetailedProbeResult>;
	computeFingerprint?: (options?: LiefRequirementDeps) => string;
	runWorker?: (options: ReversePythonOptions) => Promise<ReversePythonResult<ElfWorkerPayload>>;
	gate?: DependencyGate;
}

function isPrerequisiteFailureDetails(
	details: ElfRepairDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails,
): details is ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails {
	return "status" in details;
}

const LIEF_SETUP_COMMAND = "reverse setup reverse lief" as const;
const LIEF_UNAVAILABLE_BASE_MESSAGE =
	"LIEF Python library is not available. Deep ELF inspection requires LIEF. Run 'reverse setup reverse lief' to install.";

// ============================================================================
// Tool Implementation
// ============================================================================

export class ElfInspectTool implements AgentTool<typeof elfInspectSchema, ElfInspectDetails> {
	readonly name = "elf_inspect";
	readonly label = "ELF Inspect";
	readonly parameters = elfInspectSchema;
	readonly description: string;
	readonly tier: ToolTier = "read";
	readonly #gate: DependencyGate;

	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = args.action;
			if (action === "status" || action === "query") {
				return "read";
			}
		}
		// 'dump', 'repair', and 'dump_and_repair' attach to processes or execute native binaries
		return "exec";
	};

	constructor(
		private readonly session: ToolSession,
		private readonly deps?: ElfInspectToolDeps,
	) {
		this.description = prompt.render(elfInspectDescription);
		this.#gate = deps?.gate ?? getSessionDependencyGate(session);
		this.session.registerSessionChangeCallback?.(() => {
			this.#gate.reset();
		});
	}

	#getLiefOptions(): LiefRequirementDeps {
		return {
			cwd: this.session.cwd,
			...this.deps?.liefOptions,
		};
	}

	#computeLiefFingerprint(): string {
		const opts = this.#getLiefOptions();
		return this.deps?.computeFingerprint ? this.deps.computeFingerprint(opts) : computeLiefReadinessFingerprint(opts);
	}

	async #resolveLiefDetailed(): Promise<LiefDetailedProbeResult> {
		const opts = this.#getLiefOptions();
		return this.deps?.resolveLiefDetailed
			? await this.deps.resolveLiefDetailed(opts)
			: resolveLiefPythonDetailed(opts);
	}

	/**
	 * Build the blocked-prerequisite result shared by query/repair surfaces so the
	 * structured record (never a successful repair) is identical on every path.
	 */
	#buildBlockedFailure(
		action: "query" | "repair",
		block: DeterministicPrerequisiteBlock,
		extra: { path?: string; queryType?: string; candidate?: ElfRepairCandidatePreservation },
	): AgentToolResult<ElfPrerequisiteBlockedDetails> & { details: ElfPrerequisiteBlockedDetails } {
		const provenanceSuffix = block.blockedByGate
			? ` [Blocked by session prerequisite gate: attempt #${block.attemptCount}, first recorded at call ${block.sourceToolCallId}${block.sourceEntryId ? ` (entry ${block.sourceEntryId})` : ""}; do not retry until '${block.setupCommand}' completes or status readiness changes.]`
			: "";
		const candidateSuffix = extra.candidate
			? ` SoFixer candidate preserved at '${extra.candidate.candidatePath}' — it is UNVALIDATED and is not a successful repair; re-run after LIEF is available to validate it.`
			: "";
		const details: ElfPrerequisiteBlockedDetails = {
			action,
			isError: true,
			status: "blocked_prerequisite",
			deterministicFailure: true,
			missingDependency: "lief",
			failureKind: block.failureKind,
			setupCommand: LIEF_SETUP_COMMAND,
			blockedByGate: block.blockedByGate,
			sourceToolCallId: block.sourceToolCallId,
			sourceEntryId: block.sourceEntryId,
			readinessFingerprint: block.readinessFingerprint,
			attemptCount: block.attemptCount,
			reason: block.reason,
			path: extra.path,
			queryType: extra.queryType,
			candidate: extra.candidate,
			prerequisiteBlock: block,
		};
		return {
			content: [{ type: "text", text: `${LIEF_UNAVAILABLE_BASE_MESSAGE}${candidateSuffix}${provenanceSuffix}` }],
			details,
			isError: true,
		};
	}

	#buildProbeFailedFailure(
		action: "query" | "repair",
		probeError: string,
		fingerprint: string,
		extra: { path?: string; queryType?: string; candidate?: ElfRepairCandidatePreservation },
	): AgentToolResult<ElfProbeFailedDetails> & { details: ElfProbeFailedDetails } {
		const candidateSuffix = extra.candidate
			? ` SoFixer candidate preserved at '${extra.candidate.candidatePath}' — unvalidated and not a successful repair.`
			: "";
		const probeText = `LIEF environment probe failed to execute (${probeError}). This indicates an interpreter or subprocess runner failure rather than a confirmed missing LIEF package. Re-run 'elf_inspect' with action 'status' or inspect the Python runtime environment before attempting installation.${candidateSuffix}`;
		const details: ElfProbeFailedDetails = {
			action,
			isError: true,
			status: "probe_failed",
			deterministicFailure: false,
			probeError,
			readinessFingerprint: fingerprint,
			path: extra.path,
			queryType: extra.queryType,
			candidate: extra.candidate,
		};
		return {
			content: [{ type: "text", text: probeText }],
			details,
			isError: true,
		};
	}

	async #acquireLiefForAction(
		action: "query" | "repair",
		toolCallId: string,
	): Promise<
		| { status: "available"; value: LiefProbeResult }
		| { status: "blocked"; block: DeterministicPrerequisiteBlock }
		| { status: "probe_failed"; error: string; fingerprint: string }
	> {
		return this.#gate.acquireOrProbe<LiefProbeResult>({
			toolName: this.name,
			action,
			missingDependency: "lief",
			setupCommand: LIEF_SETUP_COMMAND,
			toolCallId,
			getReadinessFingerprint: () => this.#computeLiefFingerprint(),
			runProbe: async () => {
				const detailed = await this.#resolveLiefDetailed();
				if (detailed.status === "available" && detailed.pythonBin) {
					return {
						status: "available",
						value: {
							pythonBin: detailed.pythonBin,
							version: detailed.version ?? "1.0.0",
							modulePath: detailed.modulePath ?? "",
						},
						fingerprint: detailed.readinessFingerprint,
					};
				}
				if (detailed.status === "probe_failed") {
					return {
						status: "probe_failed",
						error: detailed.error ?? "LIEF subprocess probe failed",
						fingerprint: detailed.readinessFingerprint,
					};
				}
				return {
					status: "deterministic_missing",
					failureKind: detailed.status === "missing_interpreter" ? "missing_interpreter" : "missing_module",
					reason: LIEF_UNAVAILABLE_BASE_MESSAGE,
					fingerprint: detailed.readinessFingerprint,
				};
			},
		});
	}

	async execute(
		toolCallId: string,
		params: ElfInspectParams,
		signal?: AbortSignal,
		_updateCallback?: AgentToolUpdateCallback,
	): Promise<AgentToolResult<ElfInspectDetails> & { details: ElfInspectDetails }> {
		throwIfAborted(signal);

		// Plan Mode guard: dump, repair, and dump_and_repair execute native binaries or attach to processes
		const planMode = this.session.getPlanModeState?.();
		if (planMode?.enabled && params.action !== "status" && params.action !== "query") {
			throw new ToolError(
				"Plan mode: Memory dumping and SoFixer reconstruction execute native binaries and write session artifacts. Only 'status' and 'query' are permitted in plan mode.",
			);
		}

		switch (params.action) {
			case "status":
				return this.handleStatus(signal);
			case "query":
				return this.handleQuery(toolCallId, params, signal);
			case "dump":
				return this.handleDump(params, signal);
			case "repair":
				return this.handleRepair(toolCallId, params, signal);
			case "dump_and_repair":
				return this.handleDumpAndRepair(toolCallId, params, signal);
			default:
				throw new ToolError(`Unsupported action: ${String(params.action)}`);
		}
	}

	// --------------------------------------------------------------------------
	// Action: status
	// --------------------------------------------------------------------------

	private async handleStatus(
		signal?: AbortSignal,
	): Promise<AgentToolResult<ElfStatusDetails> & { details: ElfStatusDetails }> {
		throwIfAborted(signal);

		// 显式 status 探测始终直接执行实时探针，并在探测通过后解除会话级前置依赖门禁
		const liefDetailed = await this.#resolveLiefDetailed();
		if (liefDetailed.available) {
			this.#gate.clearDependency("lief");
		}
		const sofixer32 = resolveSoFixer({ arch: "32", cwd: this.session.cwd });
		const sofixer64 = resolveSoFixer({ arch: "64", cwd: this.session.cwd });

		const details: ElfStatusDetails = {
			action: "status",
			ready: liefDetailed.available,
			lief: {
				available: liefDetailed.available,
				status: liefDetailed.status,
				pythonBin: liefDetailed.pythonBin,
				version: liefDetailed.version,
				modulePath: liefDetailed.modulePath,
				...(liefDetailed.status === "probe_failed" && liefDetailed.error ? { probeError: liefDetailed.error } : {}),
				readinessFingerprint: liefDetailed.readinessFingerprint,
				installHint:
					liefDetailed.status === "probe_failed"
						? `LIEF probe failed to execute (${liefDetailed.error ?? "runner error"}). Verify Python interpreter execution or environment before installing.`
						: "Run 'reverse setup reverse lief' to install LIEF in a managed Python environment.",
			},
			sofixer: {
				available: sofixer32 !== null || sofixer64 !== null,
				binaries: {
					arch32: sofixer32?.path ?? null,
					arch64: sofixer64?.path ?? null,
				},
				installHint: "Run 'reverse setup reverse sofixer' to build/install native SoFixer32 and SoFixer64.",
			},
		};

		const liefStatusLabel = details.lief.available
			? "AVAILABLE"
			: details.lief.status === "probe_failed"
				? "NOT AVAILABLE (PROBE FAILED)"
				: "NOT AVAILABLE";

		const textLines = [
			"ELF Engine Environment Status:",
			`• LIEF (Deep ELF Analysis): ${liefStatusLabel}`,
			details.lief.available
				? `  - Interpreter: ${details.lief.pythonBin}\n  - Version: ${details.lief.version}`
				: details.lief.status === "probe_failed"
					? `  - Probe Error: ${details.lief.probeError}\n  - Hint: ${details.lief.installHint}`
					: `  - Hint: ${details.lief.installHint}`,
			`• SoFixer (ELF Memory Dump Repair): ${details.sofixer.available ? "AVAILABLE" : "NOT AVAILABLE"}`,
			`  - 64-bit ARM64 (aarch64): ${details.sofixer.binaries.arch64 ?? "Missing"}`,
			`  - 32-bit ARM32 (armv7/armeabi): ${details.sofixer.binaries.arch32 ?? "Missing"}`,
			details.sofixer.available ? "" : `  - Hint: ${details.sofixer.installHint}`,
		]
			.filter(Boolean)
			.join("\n");

		return {
			content: [{ type: "text", text: textLines }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Action: query
	// --------------------------------------------------------------------------

	private async handleQuery(
		toolCallId: string,
		params: ElfInspectParams,
		signal?: AbortSignal,
	): Promise<
		AgentToolResult<ElfQueryDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails> & {
			details: ElfQueryDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails;
		}
	> {
		throwIfAborted(signal);

		if (!params.path) {
			throw new ToolError("Parameter 'path' is required for action 'query'");
		}

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);
		let fileSize = 0;
		try {
			const st = await fs.stat(resolvedPath);
			if (!st.isFile()) {
				throw new ToolError(`Target path is not a regular file: ${resolvedPath}`);
			}
			if (st.size > MAX_QUERY_FILE_SIZE) {
				throw new ToolError(
					`File exceeds maximum query limit of 1 GiB (${st.size.toLocaleString()} bytes): ${resolvedPath}`,
				);
			}
			fileSize = st.size;
		} catch (err) {
			if (err instanceof ToolError) throw err;
			throw new ToolError(
				`Failed to access target file: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (typeof params.address === "number" && !Number.isSafeInteger(params.address)) {
			throw new ToolError(`Address number ${params.address} is not a safe integer. Please provide a hex string.`);
		}

		const queryType = params.query_type ?? "info";
		const liefGateOutcome = await this.#acquireLiefForAction("query", toolCallId);
		if (liefGateOutcome.status === "blocked") {
			return this.#buildBlockedFailure("query", liefGateOutcome.block, { path: resolvedPath, queryType });
		}

		if (liefGateOutcome.status === "probe_failed") {
			return this.#buildProbeFailedFailure("query", liefGateOutcome.error, liefGateOutcome.fingerprint, {
				path: resolvedPath,
				queryType,
			});
		}

		const liefRes = liefGateOutcome.value;
		const boundedLimit = Math.min(Math.max(params.limit ?? 50, 1), 500);
		const boundedTimeout = Math.min(Math.max(params.timeout ?? 60, 1), 300);
		const pyRes = this.deps?.runWorker
			? await this.deps.runWorker({
					cwd: this.session.cwd,
					sources: {
						"elf-inspect-worker.py": elfInspectWorkerSource,
					},
					entry: "elf-inspect-worker.py",
					request: {
						action: "query",
						path: resolvedPath,
						query_type: queryType,
						filter: params.filter,
						limit: boundedLimit,
						offset: params.offset ?? 0,
						address: params.address,
						file_offset: params.file_offset,
					},
					pythonPath: liefRes.pythonBin,
					signal,
					timeoutMs: boundedTimeout * 1000,
				})
			: await runReversePython<ElfWorkerPayload>({
					cwd: this.session.cwd,
					sources: {
						"elf-inspect-worker.py": elfInspectWorkerSource,
					},
					entry: "elf-inspect-worker.py",
					request: {
						action: "query",
						path: resolvedPath,
						query_type: queryType,
						filter: params.filter,
						limit: boundedLimit,
						offset: params.offset ?? 0,
						address: params.address,
						file_offset: params.file_offset,
					},
					pythonPath: liefRes.pythonBin,
					signal,
					timeoutMs: boundedTimeout * 1000,
				});

		if (pyRes.status === "missing_dependency") {
			throw new ToolError(`LIEF execution missing dependency: ${pyRes.error}`);
		}

		if (pyRes.status !== "ok" || !pyRes.result) {
			throw new ToolError(`LIEF query worker failed: ${pyRes.error || pyRes.stderr || "Unknown worker error"}`);
		}

		if (pyRes.result.status === "error") {
			throw new ToolError(`LIEF query failed: ${pyRes.result.error}`);
		}

		const queryResult = pyRes.result.result as Record<string, unknown>;
		const rawJson = JSON.stringify(queryResult, null, 2);

		let text = `ELF Deep Inspection (${queryType}): ${path.basename(resolvedPath)}\n\n\`\`\`json\n${
			rawJson.length <= 4096 ? rawJson : rawJson.slice(0, 4096) + "\n... (data truncated, see artifact)"
		}\n\`\`\``;

		let artifactId: string | undefined;
		if (rawJson.length > 4096) {
			artifactId = await saveArtifactText(this.session, "elf-query", rawJson);
			if (artifactId) {
				text = appendArtifactReference(text, artifactId, "Complete ELF query data");
			}
		}

		const details: ElfQueryDetails = {
			action: "query",
			path: resolvedPath,
			queryType,
			fileSize,
			data: queryResult,
			artifactId,
		};

		return {
			content: [{ type: "text", text }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Action: dump
	// --------------------------------------------------------------------------

	private async handleDump(
		params: ElfInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ElfDumpDetails> & { details: ElfDumpDetails }> {
		throwIfAborted(signal);

		if (params.pid === undefined || params.pid === null) {
			throw new ToolError("Parameter 'pid' is required for action 'dump'");
		}
		if (!params.module) {
			throw new ToolError("Parameter 'module' is required for action 'dump'");
		}

		const pidStr = String(params.pid).trim();
		const moduleName = params.module.trim();
		const boundedTimeout = Math.min(Math.max(params.timeout ?? 60, 1), 300);

		const dumpRes = await executeModuleDump({
			pid: pidStr,
			module: moduleName,
			device: params.device,
			usb: params.usb,
			host: params.host,
			maxBytes: params.max_bytes,
			chunkSize: params.chunk_size,
			timeoutSeconds: boundedTimeout,
			cwd: this.session.cwd,
			signal,
		});

		// Save original dump to private session artifact or secure mkdtemp
		const { path: artifactPath, id: artifactId } = (await this.session.allocateOutputArtifact?.("elf-dump")) ?? {};

		let dumpFilePath = artifactPath;
		if (!dumpFilePath) {
			const dumpDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-elf-dump-"));
			dumpFilePath = path.join(dumpDir, `${path.basename(moduleName)}.dump`);
		}
		await fs.writeFile(dumpFilePath, dumpRes.dumpBuffer, { mode: 0o600 });

		// Read dump header byte to determine ABI for manifest
		const is64 = dumpRes.dumpBuffer.length >= 5 && dumpRes.dumpBuffer[4] === 2;
		const abi: "arm" | "arm64" = is64 ? "arm64" : "arm";

		// Persist companion provenance manifest JSON alongside dump
		const manifestPath = `${dumpFilePath}.manifest.json`;
		const manifest: DumpManifest = {
			pid: pidStr,
			device: params.device,
			module: moduleName,
			base: dumpRes.baseAddress,
			moduleSize: dumpRes.moduleSize,
			totalReadable: dumpRes.totalReadable,
			unmappedBytes: dumpRes.unmappedBytes,
			readableRanges: dumpRes.ranges,
			unmappedGaps: dumpRes.unmappedGaps,
			sha256: dumpRes.sha256,
			abi,
			timestamp: new Date().toISOString(),
		};
		await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), "utf-8");

		let publishedPath: string | undefined;
		if (params.output_path) {
			const resolvedDest = resolveToCwd(params.output_path, this.session.cwd);
			const published = await safePublishArtifact(dumpFilePath, resolvedDest);
			publishedPath = published.path;
			// 伴随清单同样拒绝覆盖文件或符号链接，发布失败须向调用方报告。
			await safePublishArtifact(manifestPath, `${resolvedDest}.manifest.json`);
		}

		const details: ElfDumpDetails = {
			action: "dump",
			success: true,
			pid: pidStr,
			module: moduleName,
			baseAddress: dumpRes.baseAddress,
			moduleSize: dumpRes.moduleSize,
			totalReadableBytes: dumpRes.totalReadable,
			unmappedGapBytes: dumpRes.unmappedBytes,
			unmappedGapsCount: dumpRes.unmappedGaps.length,
			sha256: dumpRes.sha256,
			rangesCount: dumpRes.ranges.length,
			dumpArtifactId: artifactId,
			dumpPath: dumpFilePath,
			manifestPath,
			publishedPath,
		};

		let text = [
			`Module Memory Dump Successful: ${moduleName}`,
			`• Target PID: ${pidStr}`,
			`• Base Address: ${dumpRes.baseAddress}`,
			`• Virtual Image Size: ${dumpRes.moduleSize.toLocaleString()} bytes`,
			`• Readable Segments: ${dumpRes.totalReadable.toLocaleString()} bytes across ${dumpRes.ranges.length} mapped chunks`,
			`• Unmapped Virtual Gaps: ${dumpRes.unmappedBytes.toLocaleString()} bytes across ${dumpRes.unmappedGaps.length} gaps (zero-filled for PT_LOAD alignment)`,
			`• SHA-256 Provenance: ${dumpRes.sha256}`,
			`• Original Dump Artifact: ${dumpFilePath}`,
			`• Provenance Manifest: ${manifestPath}`,
			publishedPath ? `• Published File: ${publishedPath}` : "",
			"",
			"Note: Raw memory dump containing relocated pointers, displaced section headers, and unlinked dynamic tables. Output is an analyzable candidate; use action 'repair' to reconstruct headers with SoFixer.",
		]
			.filter(Boolean)
			.join("\n");

		if (artifactId) {
			text = appendArtifactReference(text, artifactId, "Original dumped memory artifact");
		}

		return {
			content: [{ type: "text", text }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Action: repair
	// --------------------------------------------------------------------------

	private async handleRepair(
		toolCallId: string,
		params: ElfInspectParams,
		signal?: AbortSignal,
	): Promise<
		AgentToolResult<ElfRepairDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails> & {
			details: ElfRepairDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails;
		}
	> {
		throwIfAborted(signal);

		if (!params.dump_path) {
			throw new ToolError("Parameter 'dump_path' is required for action 'repair'");
		}

		const resolvedDumpPath = resolveReadPath(params.dump_path, this.session.cwd);
		const dumpMeta = await getFileMetadata(resolvedDumpPath);
		if (!dumpMeta) {
			throw new ToolError(`Dump file not accessible or empty: ${resolvedDumpPath}`);
		}

		// Look for companion provenance manifest alongside dump
		let manifest: DumpManifest | null = null;
		let manifestVerified = false;
		const companionManifestPath = `${resolvedDumpPath}.manifest.json`;
		try {
			const mData = await fs.readFile(companionManifestPath, "utf-8");
			manifest = JSON.parse(mData) as DumpManifest;
			if (manifest && manifest.sha256) {
				if (manifest.sha256 !== dumpMeta.sha256) {
					throw new ToolError(
						`Dump file integrity mismatch: manifest declares SHA-256 ${manifest.sha256}, but file has ${dumpMeta.sha256}. Original dump was modified.`,
					);
				}
				manifestVerified = true;
			}
		} catch (e) {
			if (e instanceof ToolError) throw e;
			// manifest optional for external dumps
		}

		// Determine base address: use parameter or manifest
		let baseAddrInput = params.base_address;
		if (baseAddrInput === undefined || baseAddrInput === null) {
			if (manifest?.base) {
				baseAddrInput = manifest.base;
			} else {
				throw new ToolError(
					"Parameter 'base_address' is required for action 'repair' when companion manifest is absent",
				);
			}
		}

		const baseAddrStr = this.formatHexBase(baseAddrInput);
		if (manifest && manifest.base) {
			const manifestBase = this.formatHexBase(manifest.base);
			if (baseAddrStr !== manifestBase) {
				throw new ToolError(
					`Base address mismatch: manifest specifies ${manifestBase}, but parameter 'base_address' was given as ${baseAddrStr}.`,
				);
			}
		}

		// Read and validate ELF header: must be ELF, LSB, ARM or AARCH64
		let detectedArch: "32" | "64" = "64";
		let dumpMachine = 0;
		let dumpEndian = 1;
		let dumpClass = 2;
		try {
			const fd = await fs.open(resolvedDumpPath, "r");
			const headerBuf = Buffer.alloc(52);
			const readBytes = await fd.read(headerBuf, 0, 52, 0);
			await fd.close();

			if (readBytes.bytesRead < 20) {
				throw new ToolError(`Dump file is too small to contain an ELF header (${readBytes.bytesRead} bytes)`);
			}

			if (headerBuf[0] !== 0x7f || headerBuf[1] !== 0x45 || headerBuf[2] !== 0x4c || headerBuf[3] !== 0x46) {
				throw new ToolError(
					`Target dump file is not an ELF binary (missing 0x7f'ELF' magic at offset 0): ${resolvedDumpPath}. Memory dump must start at virtual offset 0.`,
				);
			}

			dumpClass = headerBuf[4]; // 1 = 32-bit, 2 = 64-bit
			if (dumpClass !== 1 && dumpClass !== 2) {
				throw new ToolError(`Invalid ELF class (${dumpClass}) in dump file: ${resolvedDumpPath}`);
			}
			detectedArch = dumpClass === 1 ? "32" : "64";

			dumpEndian = headerBuf[5]; // 1 = LSB, 2 = MSB
			if (dumpEndian !== 1) {
				throw new ToolError(
					"Unsupported big-endian ELF dump. Upstream SoFixer exclusively supports little-endian (LSB) ARM/ARM64 ELF binaries.",
				);
			}

			dumpMachine = headerBuf.readUInt16LE(18);
			if (dumpMachine !== EM_ARM && dumpMachine !== EM_AARCH64) {
				throw new ToolError(
					`Unsupported machine architecture (0x${dumpMachine.toString(16)}). Upstream SoFixer only supports Android ARM (armeabi-v7a / 0x28) and ARM64 (arm64-v8a / 0xb7) relocation reconstruction.`,
				);
			}

			if (params.arch) {
				const requestedArch = normalizeSoFixerArch(params.arch);
				if (requestedArch !== detectedArch) {
					throw new ToolError(
						`Architecture mismatch: target dump file is a ${detectedArch}-bit ELF, but explicit arch '${params.arch}' was requested. Please use matching architecture or omit parameter to infer automatically.`,
					);
				}
			}
		} catch (err) {
			if (err instanceof ToolError) throw err;
			throw new ToolError(`Failed to read dump file header: ${err instanceof Error ? err.message : String(err)}`);
		}

		const sofixer = resolveSoFixer({ arch: detectedArch, cwd: this.session.cwd });
		if (!sofixer) {
			throw new ToolError(
				`SoFixer binary for architecture '${detectedArch}' is not available. Run 'reverse setup reverse sofixer' to install.`,
			);
		}

		// 已登记的确定性缺失前提：直接返回阻塞，不重复执行 SoFixer 后端
		const knownBlock = this.#gate.blockIfKnown({
			toolName: this.name,
			action: "repair",
			missingDependency: "lief",
			getReadinessFingerprint: () => this.#computeLiefFingerprint(),
		});
		if (knownBlock) {
			return this.#buildBlockedFailure("repair", knownBlock, { path: resolvedDumpPath });
		}

		// Allocate private temporary directory with secure mkdtemp to prevent symlink/collision attacks
		const tempCandidateDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-sofixer-"));
		const tempCandidatePath = path.join(tempCandidateDir, `fixed-${path.basename(resolvedDumpPath)}`);

		// Run SoFixer: sofixer -s <source> -o <target> -m <base>
		const boundedTimeout = Math.min(Math.max(params.timeout ?? 60, 1), 300);
		const runResult = await runSafeSubprocess({
			binary: sofixer.path,
			args: ["-s", resolvedDumpPath, "-o", tempCandidatePath, "-m", baseAddrStr],
			cwd: this.session.cwd,
			timeoutMs: boundedTimeout * 1000,
			maxBytes: 16 * 1024 * 1024,
			signal,
		});

		if (runResult.exitCode !== 0) {
			throw new ToolError(
				`SoFixer process failed (exit code ${runResult.exitCode}): ${runResult.stderr || runResult.stdout.slice(0, 500)}`,
			);
		}

		const candidateMeta = await getFileMetadata(tempCandidatePath);
		if (!candidateMeta) {
			throw new ToolError(`SoFixer completed but candidate output file was not produced: ${tempCandidatePath}`);
		}

		// Verify candidate header matches input machine/class/endianness
		try {
			const candFd = await fs.open(tempCandidatePath, "r");
			const candHdr = Buffer.alloc(20);
			await candFd.read(candHdr, 0, 20, 0);
			await candFd.close();

			const candClass = candHdr[4];
			const candEndian = candHdr[5];
			const candMachine = candHdr.readUInt16LE(18);

			if (candClass !== dumpClass || candEndian !== dumpEndian || candMachine !== dumpMachine) {
				throw new ToolError(
					`SoFixer reconstructed output header altered original binary traits (machine: 0x${candMachine.toString(16)} vs 0x${dumpMachine.toString(16)}, class: ${candClass} vs ${dumpClass})`,
				);
			}
		} catch (err) {
			if (err instanceof ToolError) throw err;
			throw new ToolError(`Failed to verify candidate header: ${err instanceof Error ? err.message : String(err)}`);
		}

		// Structural validation of candidate via LIEF (defaults to false until validated)
		const liefGateOutcome = await this.#acquireLiefForAction("repair", toolCallId);
		// 已生成的 SoFixer 候选先保留并在结构化失败中显式暴露，绝不作为成功修复返回
		const preservation: ElfRepairCandidatePreservation = {
			dumpPath: resolvedDumpPath,
			baseAddress: baseAddrStr,
			arch: detectedArch,
			sofixerPath: sofixer.path,
			candidatePath: tempCandidatePath,
			candidateSha256: candidateMeta.sha256,
			candidateBytes: candidateMeta.bytes,
			manifestVerified,
		};
		if (liefGateOutcome.status === "blocked") {
			return this.#buildBlockedFailure("repair", liefGateOutcome.block, {
				path: resolvedDumpPath,
				candidate: preservation,
			});
		}
		if (liefGateOutcome.status === "probe_failed") {
			return this.#buildProbeFailedFailure("repair", liefGateOutcome.error, liefGateOutcome.fingerprint, {
				path: resolvedDumpPath,
				candidate: preservation,
			});
		}
		const liefRes = liefGateOutcome.value;
		let validationResult: {
			candidate_valid: boolean;
			is_analyzable: boolean;
			is_runnable: boolean;
			analyzable_notice: string;
			risks: string[];
			header?: unknown;
		} = {
			candidate_valid: false,
			is_analyzable: false,
			is_runnable: false,
			analyzable_notice: "Unvalidated candidate. LIEF structural validation was unavailable or failed to execute.",
			risks: ["LIEF structural validation failed to execute"],
		};

		if (liefRes) {
			const valPy = this.deps?.runWorker
				? await this.deps.runWorker({
						cwd: this.session.cwd,
						sources: {
							"elf-inspect-worker.py": elfInspectWorkerSource,
						},
						entry: "elf-inspect-worker.py",
						request: {
							action: "validate",
							path: tempCandidatePath,
						},
						pythonPath: liefRes.pythonBin,
						signal,
						timeoutMs: 30000,
					})
				: await runReversePython<ElfWorkerPayload>({
						cwd: this.session.cwd,
						sources: {
							"elf-inspect-worker.py": elfInspectWorkerSource,
						},
						entry: "elf-inspect-worker.py",
						request: {
							action: "validate",
							path: tempCandidatePath,
						},
						pythonPath: liefRes.pythonBin,
						signal,
						timeoutMs: 30000,
					});

			if (valPy.status === "ok" && valPy.result?.status === "ok" && valPy.result.result) {
				validationResult = valPy.result.result as typeof validationResult;
			} else {
				validationResult.risks.push(valPy.error || valPy.stderr || "Worker validation error");
			}
		}

		let publishedPath: string | undefined;
		if (params.output_path) {
			if (!validationResult.candidate_valid) {
				throw new ToolError(
					`Refusing to publish candidate to '${params.output_path}': candidate failed structural LIEF validation. Risks: ${validationResult.risks.join("; ")}`,
				);
			}
			const resolvedDest = resolveToCwd(params.output_path, this.session.cwd);
			const published = await safePublishArtifact(tempCandidatePath, resolvedDest);
			publishedPath = published.path;
		}

		const details: ElfRepairDetails = {
			action: "repair",
			success: true,
			dumpPath: resolvedDumpPath,
			baseAddress: baseAddrStr,
			arch: detectedArch,
			sofixerPath: sofixer.path,
			candidatePath: tempCandidatePath,
			candidateSha256: candidateMeta.sha256,
			candidateBytes: candidateMeta.bytes,
			candidateValid: validationResult.candidate_valid,
			isAnalyzable: validationResult.is_analyzable,
			isRunnable: false,
			analyzableNotice: validationResult.analyzable_notice,
			validationRisks: validationResult.risks,
			validationDetails: validationResult,
			manifestVerified,
			publishedPath,
		};

		const text = [
			`SoFixer ELF Reconstruction Completed:`,
			`• Original Dump: ${resolvedDumpPath} (${dumpMeta.bytes.toLocaleString()} bytes, sha256: ${dumpMeta.sha256})`,
			`• Provenance Manifest: ${manifestVerified ? `VERIFIED (${companionManifestPath})` : "None"}`,
			`• Memory Base Address: ${baseAddrStr}`,
			`• Architecture: ${detectedArch}-bit (${sofixer.path})`,
			`• Candidate Artifact: ${tempCandidatePath} (${candidateMeta.bytes.toLocaleString()} bytes)`,
			`• Candidate SHA-256: ${candidateMeta.sha256}`,
			publishedPath ? `• Published Candidate: ${publishedPath}` : "",
			"",
			`Structural Validation (LIEF):`,
			`• Structural Consistency: ${validationResult.candidate_valid ? "VALID" : "RISKS DETECTED / FAILED"}`,
			`• Analyzable for Static Inspection: ${validationResult.is_analyzable ? "YES (Ghidra, IDA, radare2, LIEF)" : "NO"}`,
			`• Runnable Execution Status: NOT CERTIFIED (${validationResult.analyzable_notice})`,
			validationResult.risks.length > 0
				? `• Structural Risks / Warnings:\n  - ${validationResult.risks.join("\n  - ")}`
				: "• No structural anomalies or page alignment violations detected.",
		]
			.filter(Boolean)
			.join("\n");

		return {
			content: [{ type: "text", text }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Action: dump_and_repair
	// --------------------------------------------------------------------------

	private async handleDumpAndRepair(
		toolCallId: string,
		params: ElfInspectParams,
		signal?: AbortSignal,
	): Promise<
		AgentToolResult<ElfDumpAndRepairDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails> & {
			details: ElfDumpAndRepairDetails | ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails;
		}
	> {
		throwIfAborted(signal);

		// Step 1: Dump (reserve output_path exclusively for final repaired candidate)
		const dumpRes = await this.handleDump({ ...params, output_path: undefined }, signal);

		// Step 2: Repair using the dumped artifact and its companion manifest
		const repairRes = await this.handleRepair(
			toolCallId,
			{
				...params,
				action: "repair",
				dump_path: dumpRes.details.dumpPath,
				base_address: dumpRes.details.baseAddress,
				arch: params.arch,
				output_path: params.output_path,
			},
			signal,
		);

		const dumpText = dumpRes.content[0]?.type === "text" ? dumpRes.content[0].text : "";
		const repairText = repairRes.content[0]?.type === "text" ? repairRes.content[0].text : "";

		// 修复阶段的前置依赖失败必须原样上抛，不能折叠为成功的 dump_and_repair
		const repairDetailsOrFailure = repairRes.details;
		if (isPrerequisiteFailureDetails(repairDetailsOrFailure)) {
			const details: ElfPrerequisiteBlockedDetails | ElfProbeFailedDetails = {
				...repairDetailsOrFailure,
				action: "dump_and_repair",
				dump: dumpRes.details,
			};
			return {
				content: [
					{
						type: "text",
						text: [dumpText, "\n" + "=".repeat(60) + "\n", repairText].join("\n"),
					},
				],
				details,
				isError: true,
			};
		}
		const repairDetails = repairDetailsOrFailure;

		const details: ElfDumpAndRepairDetails = {
			action: "dump_and_repair",
			dump: dumpRes.details,
			repair: repairDetails,
		};

		const text = [dumpText, "\n" + "=".repeat(60) + "\n", repairText].join("\n");

		return {
			content: [{ type: "text", text }],
			details,
		};
	}

	// --------------------------------------------------------------------------
	// Formatting Helpers
	// --------------------------------------------------------------------------

	private formatHexBase(baseInput: string | number): string {
		if (typeof baseInput === "number") {
			if (!Number.isSafeInteger(baseInput) || baseInput < 0) {
				throw new ToolError(`Base address number ${baseInput} must be a non-negative safe integer`);
			}
			return `0x${BigInt(baseInput).toString(16).toLowerCase()}`;
		}
		const trimmed = baseInput.trim();
		if (!trimmed) {
			throw new ToolError("Base address string must not be empty");
		}
		try {
			const b = BigInt(trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed : `0x${trimmed}`);
			return `0x${b.toString(16).toLowerCase()}`;
		} catch {
			throw new ToolError(`Invalid hex base address string: '${baseInput}'`);
		}
	}
}
