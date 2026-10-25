/**
 * Offline Dalvik CodeItem restoration and DEX reconstruction from FART runtime method dumps.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import dexRepairDescription from "../prompts/tools/dex-repair.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";

// Staged text assets for Python runner
import dexRepairWorkerSource from "./dex-repair-worker.py" with { type: "text" };
import dexutilSource from "./dexutil.py" with { type: "text" };

// ============================================================================
// Parameter Schema
// ============================================================================

export const dexRepairSchema = type({
	action: type
		.enumerated("status", "repair")
		.describe("Operation: 'status' (readiness and census) or 'repair' (FART offline CodeItem restoration)"),
	"path?": type("string").describe("Path to target DEX or APK/ZIP file"),
	"target?": type("string").describe("Alias for path"),
	"entry?": type("string").describe("Archive member name when target is an APK/ZIP (default 'classes.dex')"),
	"records?": type("string").describe(
		"Path to FART *_ins.bin file, directory containing .bin dumps, or raw dump text records",
	),
	"dump?": type("string").describe("Alias for records"),
	"bins?": type("string").describe("Alias for records"),
	"dry_run?": type("boolean").describe(
		"When action is 'repair', preview changes without writing to disk (default true)",
	),
	"out?": type("string").describe("Output DEX file path (required when dry_run is false)"),
});

export type DexRepairParams = typeof dexRepairSchema.infer;

export interface DexRepairRecord {
	method_idx: number;
	class: string;
	name: string;
	desc?: string;
	old_code_off: number;
	new_code_off: number;
	old_insns_size: number;
	new_insns_size: number;
	relocated: boolean;
}

export interface DexRepairDetails {
	action: "status" | "repair";
	status: "ok" | "missing_dependency" | "error";
	target?: string;
	entry?: string;
	dry_run?: boolean;
	total_methods?: number;
	records_count?: number;
	repaired_count?: number;
	skipped_count?: number;
	repairs?: DexRepairRecord[];
	skipped?: Array<{ method_idx: number; name?: string; reason: string }>;
	header_change?: {
		before_checksum: string;
		after_checksum: string;
		before_signature: string;
		after_signature: string;
		old_file_size: number;
		new_file_size: number;
	};
	validation?: {
		check_clean: boolean;
		problems: string[];
		checksum_verified: boolean;
		signature_verified: boolean;
	};
	out_path?: string | null;
	out_sha256?: string;
	target_info?: Record<string, unknown>;
	records_info?: Record<string, unknown>;
	target_error?: string;
	records_error?: string;
	lineage?: Record<string, unknown>;
	error?: string;
}

interface WorkerResponse {
	ok: boolean;
	action?: "status" | "repair";
	error?: string;
	target?: string;
	entry?: string;
	dry_run?: boolean;
	total_methods?: number;
	records_count?: number;
	repaired_count?: number;
	skipped_count?: number;
	repairs?: DexRepairRecord[];
	skipped?: Array<{ method_idx: number; name?: string; reason: string }>;
	header_change?: {
		before_checksum: string;
		after_checksum: string;
		before_signature: string;
		after_signature: string;
		old_file_size: number;
		new_file_size: number;
	};
	validation?: {
		check_clean: boolean;
		problems: string[];
		checksum_verified: boolean;
		signature_verified: boolean;
	};
	out_path?: string | null;
	out_sha256?: string;
	target_info?: Record<string, unknown>;
	records_info?: Record<string, unknown>;
	target_error?: string;
	records_error?: string;
	lineage?: Record<string, unknown>;
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class DexRepairTool implements AgentTool<typeof dexRepairSchema, DexRepairDetails> {
	readonly name = "dex_repair";
	readonly label = "DEX Repair";
	readonly summary = "Offline Dalvik CodeItem restoration and DEX reconstruction from FART runtime method dumps.";
	readonly description: string;
	readonly parameters = dexRepairSchema;
	readonly strict = true;
	readonly loadMode = "discoverable" as const;

	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "status") {
				return "read";
			}
			if (action === "repair") {
				if ("dry_run" in args) {
					return args.dry_run === false ? "write" : "read";
				}
				return "read";
			}
		}
		return "write";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(dexRepairDescription);
	}

	async execute(
		_toolCallId: string,
		params: DexRepairParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DexRepairDetails> & { details: DexRepairDetails }> {
		throwIfAborted(signal);

		const action = params.action ?? "repair";
		const rawTarget = params.path ?? params.target;
		let resolvedTarget: string | undefined;
		let inputStat: fs.Stats | undefined;

		if (rawTarget) {
			resolvedTarget = resolveReadPath(rawTarget, this.session.cwd);
			if (!fs.existsSync(resolvedTarget)) {
				throw new ToolError(`Target file not found: ${resolvedTarget}`);
			}
			inputStat = fs.statSync(resolvedTarget);
			if (inputStat.isDirectory()) {
				throw new ToolError(`Target path is a directory, not a DEX/APK file: ${resolvedTarget}`);
			}
		}

		if (action === "repair" && !resolvedTarget) {
			throw new ToolError("Action 'repair' requires parameter 'path' (or 'target')");
		}

		const rawRecords = params.records ?? params.dump ?? params.bins;
		let resolvedRecords = rawRecords;
		if (rawRecords && typeof rawRecords === "string") {
			const candidatePath = resolveReadPath(rawRecords, this.session.cwd);
			if (fs.existsSync(candidatePath)) {
				resolvedRecords = candidatePath;
			}
		}

		if (action === "repair" && !resolvedRecords) {
			throw new ToolError(
				"Action 'repair' requires parameter 'records' (or 'dump'/'bins') containing FART CodeItem records",
			);
		}

		let resolvedOut: string | undefined;
		const dryRun = params.dry_run !== false;

		if (action === "repair" && !dryRun) {
			if (!params.out || !params.out.trim()) {
				throw new ToolError("Parameter 'out' is required for writes (dry_run: false)");
			}
			resolvedOut = path.resolve(this.session.cwd, params.out.trim());

			if (resolvedTarget && resolvedTarget === resolvedOut) {
				throw new ToolError(
					`Input and output paths point to the exact same file (${resolvedTarget}). In-place modification is disallowed; provide a fresh distinct output path.`,
				);
			}

			// Check symlink aliasing hazard
			if (resolvedTarget) {
				try {
					const realInput = fs.realpathSync(resolvedTarget);
					const outDir = path.dirname(resolvedOut);
					if (fs.existsSync(outDir)) {
						const realOutDir = fs.realpathSync(outDir);
						const prospectiveOutReal = path.join(realOutDir, path.basename(resolvedOut));
						if (prospectiveOutReal === realInput) {
							throw new ToolError(
								`Output path resolves to the same filesystem inode as the input file via symlink (${realInput}). Overwriting input is rejected.`,
							);
						}
					}
				} catch {
					// Fall through if path components do not exist yet
				}
			}

			const outLstat = fs.lstatSync(resolvedOut, { throwIfNoEntry: false });
			if (outLstat !== undefined) {
				throw new ToolError(
					`Output path already exists (or is a dangling symlink): ${resolvedOut}. DexRepairTool requires an explicit fresh output path to prevent accidental overwrites.`,
				);
			}
		}

		const workerRequest = {
			action,
			path: resolvedTarget,
			entry: params.entry,
			records: resolvedRecords,
			dry_run: dryRun,
			out: resolvedOut,
		};

		const pyRes = await runReversePython<WorkerResponse>({
			cwd: this.session.cwd,
			sources: {
				"dexutil.py": dexutilSource,
				"dex-repair-worker.py": dexRepairWorkerSource,
			},
			entry: "dex-repair-worker.py",
			request: workerRequest,
			signal,
		});

		if (pyRes.status === "missing_dependency") {
			throw new ToolError(
				`Python dependency missing: ${pyRes.error}. Run 'reverse setup reverse python' to install Python 3.9+.`,
			);
		}

		if (pyRes.status === "error" || !pyRes.result) {
			throw new ToolError(pyRes.error ?? "DEX repair worker failed without error detail");
		}

		// Ensure source file remained completely untouched on writes
		if (resolvedTarget && inputStat) {
			const postStat = fs.statSync(resolvedTarget);
			if (
				postStat.mtimeMs !== inputStat.mtimeMs ||
				postStat.size !== inputStat.size ||
				postStat.ino !== inputStat.ino
			) {
				throw new ToolError("FATAL: Source file was modified during repair execution");
			}
		}

		if (resolvedTarget && inputStat && resolvedOut && fs.existsSync(resolvedOut)) {
			const outStat = fs.statSync(resolvedOut);
			if (outStat.dev === inputStat.dev && outStat.ino === inputStat.ino) {
				throw new ToolError("FATAL: Output file is a hardlink alias of the input file");
			}
		}

		const resp = pyRes.result;
		if (!resp.ok) {
			throw new ToolError(String(resp.error ?? "DEX repair operation failed"));
		}

		if (action === "status") {
			const hasError = Boolean(resp.target_error || resp.records_error);
			const lines = [`// DEX Repair Engine Status`, `Action: status`, `Status: ${hasError ? "error" : "ok"}`];
			if (resp.target_error) {
				lines.push("");
				lines.push(`Target Diagnostic Error: ${resp.target_error}`);
			}
			if (resp.records_error) {
				lines.push("");
				lines.push(`Records Diagnostic Error: ${resp.records_error}`);
			}
			if (resp.target_info) {
				const ti = resp.target_info;
				lines.push("");
				lines.push(`Target: ${ti.path ?? resolvedTarget}${ti.entry ? ` [entry: ${ti.entry}]` : ""}`);
				lines.push(
					`Methods: ${ti.method_ids_size ?? 0} total, ${ti.methods_with_code ?? 0} with code, ${ti.methods_empty_or_stripped ?? 0} empty/stripped`,
				);
				lines.push(
					`Checksum: ${ti.checksum_valid ? "valid" : "invalid"} | Signature: ${ti.signature_valid ? "valid" : "invalid"}`,
				);
				lines.push(`Needs Repair: ${ti.needs_repair ? "YES (stripped methods detected)" : "no"}`);
			}
			if (resp.records_info) {
				const ri = resp.records_info;
				lines.push("");
				lines.push(`Records: ${ri.records_count ?? 0} FART code items parsed`);
			}

			const details: DexRepairDetails = {
				action: "status",
				status: hasError ? "error" : "ok",
				target: resolvedTarget,
				entry: params.entry,
				target_info: resp.target_info,
				records_info: resp.records_info,
				target_error: resp.target_error,
				records_error: resp.records_error,
				error: resp.target_error ?? resp.records_error,
			};

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		// Action === "repair"
		const lines = [
			`// FART Offline DEX CodeItem Repair`,
			`Target: ${resolvedTarget}${resp.entry ? ` [entry: ${resp.entry}]` : ""}`,
			`Mode: ${dryRun ? "dry-run (preview only)" : "write (restored DEX written to disk)"}`,
			`Repairs: ${resp.repaired_count ?? 0} methods restored | Skipped: ${resp.skipped_count ?? 0}`,
		];

		if (resp.repairs && resp.repairs.length > 0) {
			lines.push("");
			lines.push("### Restored Methods");
			for (const r of resp.repairs) {
				lines.push(
					`- [idx:${r.method_idx}] ${r.class}->${r.name}${r.desc ?? ""}: old_code_off=0x${r.old_code_off.toString(16)} -> new_code_off=0x${r.new_code_off.toString(16)} (insns: ${r.old_insns_size} -> ${r.new_insns_size} units, relocated=${r.relocated})`,
				);
			}
		}

		if (resp.skipped && resp.skipped.length > 0) {
			lines.push("");
			lines.push("### Skipped / Mismatched Records");
			for (const s of resp.skipped) {
				lines.push(`- [idx:${s.method_idx}] ${s.name ? `${s.name}: ` : ""}${s.reason}`);
			}
		}

		if (resp.header_change) {
			lines.push("");
			lines.push("### DEX Header Updates");
			lines.push(
				`- Adler-32 Checksum: ${resp.header_change.before_checksum} -> ${resp.header_change.after_checksum}`,
			);
			lines.push(
				`- SHA-1 Signature: ${resp.header_change.before_signature.slice(0, 16)}... -> ${resp.header_change.after_signature.slice(0, 16)}...`,
			);
			lines.push(`- File Size: ${resp.header_change.old_file_size} -> ${resp.header_change.new_file_size} bytes`);
		}

		if (resp.validation) {
			lines.push("");
			lines.push(`### Validation: ${resp.validation.check_clean ? "CLEAN" : "WARNINGS DETECTED"}`);
			lines.push(`- Checksum Verified: ${resp.validation.checksum_verified ? "PASS" : "FAIL"}`);
			lines.push(`- Signature Verified: ${resp.validation.signature_verified ? "PASS" : "FAIL"}`);
			if (resp.validation.problems && resp.validation.problems.length > 0) {
				for (const prob of resp.validation.problems) {
					lines.push(`  * ${prob}`);
				}
			}
		}

		if (!dryRun && resp.out_path) {
			lines.push("");
			lines.push(`Output: ${resp.out_path}`);
			if (resp.out_sha256) {
				lines.push(`SHA-256: ${resp.out_sha256}`);
			}
		}

		const details: DexRepairDetails = {
			action: "repair",
			status: "ok",
			target: resolvedTarget,
			entry: resp.entry,
			dry_run: dryRun,
			total_methods: resp.total_methods,
			records_count: resp.records_count,
			repaired_count: resp.repaired_count,
			skipped_count: resp.skipped_count,
			repairs: resp.repairs,
			skipped: resp.skipped,
			header_change: resp.header_change,
			validation: resp.validation,
			out_path: resp.out_path,
			out_sha256: resp.out_sha256,
			lineage: resp.lineage,
		};

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}
}
