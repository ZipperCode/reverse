/**
 * Native Dalvik DEX bytecode inspection, structural validation, and guarded equal-length byte patching.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import dexPatchDescription from "../prompts/tools/dex-patch.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";

// Staged text assets for Python runner
import dexutilSource from "./dexutil.py" with { type: "text" };
import dexPatchWorkerSource from "./dex-patch-worker.py" with { type: "text" };

// ============================================================================
// Parameter Schema
// ============================================================================

const dexPatchSpecSchema = type({
	"name?": type("string").describe("Human-readable label for this patch"),
	"reason?": type("string").describe("Why this patch is being applied"),
	class: type("string").describe("Target class FQCN or descriptor (e.g. 'Lcom/example/Gate;' or 'com.example.Gate')"),
	method: type("string").describe("Target method name"),
	"desc?": type("string").describe("Target method prototype descriptor (e.g. '()Z' or '(Ljava/lang/String;)V')"),
	match: type({
		"kind?": type("string").describe(
			"Instruction kind (e.g. 'if-test', 'if-testz', 'invoke', 'const4', 'return', 'move-result', 'nop', or opcode name)",
		),
		"target_reg?": type("number.integer >= 0").describe("Branch or source register number"),
		"target_reads_field_of?": type("string").describe("Class whose field is read by the target instruction"),
		"target_field?": type("string").describe("Field name read by the target instruction"),
		"target_class?": type("string").describe("Invoked target class"),
		"target_method?": type("string").describe("Invoked target method"),
		"literal?": type("number.integer").describe("Literal value for const4"),
		"bytes?": type("string").describe("Exact raw instruction hex bytes"),
		"ordinal?": type("number.integer >= 0").describe("Zero-based index if multiple instructions match"),
	}).describe("Selection criteria for the instruction to patch"),
	"expect_next?": type({
		"kind?": type("string").describe("Expected successor instruction kind"),
		"target_reg?": type("number.integer >= 0"),
		"target_reads_field_of?": type("string"),
		"target_field?": type("string"),
		"target_class?": type("string"),
		"target_method?": type("string"),
		"literal?": type("number.integer"),
		"bytes?": type("string"),
	}).describe("Polarity check: assertion on the immediate successor instruction"),
	replace: type({
		kind: type
			.enumerated("nops", "bytes")
			.describe(
				"Replacement type: 'nops' (fills instruction with 0x0000 nops) or 'bytes' (equal-length custom hex)",
			),
		"bytes?": type("string").describe("Hex-encoded replacement bytes (required when kind is 'bytes')"),
	}).describe("Bytecode replacement definition"),
});

const dexPatchSchema = type({
	action: type
		.enumerated("inspect", "validate", "patch")
		.describe(
			"Operation: inspect (decode method bytecode and CFG), validate (limited structural verifier and census), or patch (semantic equal-length byte patching)",
		),
	"path?": type("string").describe("Path to target DEX or APK/ZIP file"),
	"target?": type("string").describe("Alias for path"),
	"entry?": type("string").describe("Archive member name when target is an APK/ZIP (default 'classes.dex')"),
	"class?": type("string").describe("Target class FQCN or filter (e.g. 'Lcom/example/Main;' or 'com.example.Main')"),
	"method?": type("string").describe("Target method name (required for inspect)"),
	"desc?": type("string").describe("Target method prototype descriptor"),
	"dry_run?": type("boolean").describe("Whether to simulate patch without writing output (default true)"),
	"out?": type("string").describe(
		"Output DEX file path (required for patch when dry_run is false; must be a fresh non-existing file)",
	),
	"specs?": type(dexPatchSpecSchema).array().describe("Array of patch specifications (required for patch)"),
});

export type DexPatchParams = typeof dexPatchSchema.infer;
export type DexPatchSpec = typeof dexPatchSpecSchema.infer;

// ============================================================================
// Detail Models
// ============================================================================

export interface DexInstructionDetail {
	off: number;
	offset_hex: string;
	op: number;
	op_hex: string;
	units: number;
	name: string;
	raw_hex: string;
	disassembly: string;
	branch_target?: number;
	branch_target_hex?: string;
	is_branch_target: boolean;
}

export interface DexMethodDetail {
	class: string;
	name: string;
	desc?: string;
	section?: string;
	method_idx?: number;
	code_off: number;
	code_off_hex?: string;
	registers?: number;
	ins?: number;
	outs?: number;
	tries?: number;
	insns_size?: number;
	insns_off?: number;
	insns_off_hex?: string;
	instruction_count?: number;
	clean_decode?: boolean;
	expected_end_hex?: string;
	branch_targets?: number[];
	verifier_violations?: Array<{
		branch_off: number;
		target_off: number;
		branch_op: string;
		is_conditional: boolean;
	}>;
	instructions: DexInstructionDetail[];
}

export interface DexByteDiff {
	offset: number;
	offset_hex: string;
	length: number;
	old_bytes: string;
	new_bytes: string;
	method: string;
	old_disassembly: string;
	new_disassembly: string;
}

export interface DexPatchReportEntry {
	name: string;
	class: string;
	method: string;
	desc?: string;
	site_off: number;
	site_off_hex: string;
	old_bytes: string;
	new_bytes: string;
	old_text: string;
	new_text: string;
	expect_next_ok: boolean;
	before: string[];
	after: string[];
}

export interface DexPatchDetails {
	action: "inspect" | "validate" | "patch";
	path: string;
	entry?: string;
	status: "ok" | "error";
	inspect?: {
		method: DexMethodDetail;
	};
	validate?: {
		verifier_scope: string;
		header: {
			valid: boolean;
			checksum_ok: boolean;
			signature_ok: boolean;
			file_size: number;
			problems: string[];
		};
		summary: {
			total_classes: number;
			total_methods: number;
			methods_with_code: number;
			unclean_decodes: number;
			verifier_violations: number;
		};
		violations: Array<{
			class: string;
			method: string;
			desc?: string;
			branch_off: number;
			target_off: number;
			branch_op: string;
			is_conditional: boolean;
			detail?: string;
		}>;
		unclean_methods: Array<{
			class: string;
			method: string;
			desc?: string;
			code_off: number;
			expected_end: number;
		}>;
	};
	patch?: {
		dry_run: boolean;
		output_path?: string | null;
		patches_count: number;
		patches: DexPatchReportEntry[];
		header_change?: {
			before_checksum: string;
			after_checksum: string;
			before_signature: string;
			after_signature: string;
		};
		byte_diffs: DexByteDiff[];
		verifier_notice: string;
	};
	error?: string;
}

interface WorkerBaseResponse {
	ok: boolean;
	error?: string;
}

interface WorkerInspectResponse extends WorkerBaseResponse {
	action: "inspect";
	method: DexMethodDetail;
}

interface WorkerValidateResponse extends WorkerBaseResponse {
	action: "validate";
	verifier_scope: string;
	header: {
		valid: boolean;
		checksum_ok: boolean;
		signature_ok: boolean;
		file_size: number;
		problems: string[];
	};
	summary: {
		total_classes: number;
		total_methods: number;
		methods_with_code: number;
		unclean_decodes: number;
		verifier_violations: number;
	};
	violations: Array<{
		class: string;
		method: string;
		desc?: string;
		branch_off: number;
		target_off: number;
		branch_op: string;
		is_conditional: boolean;
		detail?: string;
	}>;
	unclean_methods: Array<{
		class: string;
		method: string;
		desc?: string;
		code_off: number;
		expected_end: number;
	}>;
}

interface WorkerPatchResponse extends WorkerBaseResponse {
	action: "patch";
	dry_run: boolean;
	output_path?: string | null;
	patches_count: number;
	patches: DexPatchReportEntry[];
	header_change?: {
		before_checksum: string;
		after_checksum: string;
		before_signature: string;
		after_signature: string;
	};
	byte_diffs: DexByteDiff[];
	verifier_notice: string;
}

type WorkerResponse = WorkerInspectResponse | WorkerValidateResponse | WorkerPatchResponse;

// ============================================================================
// Tool Implementation
// ============================================================================

export class DexPatchTool implements AgentTool<typeof dexPatchSchema, DexPatchDetails> {
	readonly name = "dex_patch";
	readonly label = "DEX Patch";
	readonly summary =
		"Native semantic Dalvik DEX bytecode inspection, structural validation, and guarded equal-length byte patching";
	readonly description: string;
	readonly parameters = dexPatchSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	/**
	 * Action-based read/write approvals:
	 * - inspect & validate: read tier
	 * - patch (dry_run !== false): read tier
	 * - patch (dry_run === false): write tier
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "inspect" || action === "validate") {
				return "read";
			}
			if (action === "patch") {
				if ("dry_run" in args) {
					return args.dry_run === false ? "write" : "read";
				}
				return "read";
			}
		}
		return "write";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(dexPatchDescription);
	}

	async execute(
		_toolCallId: string,
		params: DexPatchParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DexPatchDetails> & { details: DexPatchDetails }> {
		throwIfAborted(signal);

		const targetPath = params.path ?? params.target;
		if (!targetPath) {
			throw new ToolError("Missing required parameter 'path' (or alias 'target')");
		}

		const resolvedInput = resolveReadPath(targetPath, this.session.cwd);
		if (!fs.existsSync(resolvedInput)) {
			throw new ToolError(`Target file not found: ${resolvedInput}`);
		}

		const inputStat = fs.statSync(resolvedInput);
		if (inputStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a DEX/APK file: ${resolvedInput}`);
		}

		// Validation rules specific to action 'patch'
		let resolvedOut: string | undefined;
		const dryRun = params.dry_run !== false;

		if (params.action === "patch") {
			if (!params.specs || !Array.isArray(params.specs) || params.specs.length === 0) {
				throw new ToolError("Action 'patch' requires a non-empty array of patch specifications ('specs')");
			}

			if (!dryRun) {
				if (!params.out || !params.out.trim()) {
					throw new ToolError("Parameter 'out' is required for writes (dry_run: false)");
				}
				resolvedOut = path.resolve(this.session.cwd, params.out.trim());

				// Enforce distinct files & anti-aliasing
				if (resolvedInput === resolvedOut) {
					throw new ToolError(
						`Input and output paths point to the exact same file (${resolvedInput}). In-place modification is disallowed; provide a fresh distinct output path.`,
					);
				}

				// Check symlink aliasing hazard
				try {
					const realInput = fs.realpathSync(resolvedInput);
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

				// Enforce fresh output: prevent accidental overwrites of existing files or dangling symlinks
				const outLstat = fs.lstatSync(resolvedOut, { throwIfNoEntry: false });
				if (outLstat !== undefined) {
					throw new ToolError(
						`Output path already exists (or is a dangling symlink): ${resolvedOut}. DexPatchTool requires an explicit fresh output path to prevent accidental overwrites.`,
					);
				}
			}
		}

		if (params.action === "inspect") {
			if (!params.class || !params.class.trim()) {
				throw new ToolError("Action 'inspect' requires parameter 'class'");
			}
			if (!params.method || !params.method.trim()) {
				throw new ToolError("Action 'inspect' requires parameter 'method'");
			}
		}

		// Prepare Python worker request payload
		const workerRequest = {
			action: params.action,
			path: resolvedInput,
			entry: params.entry,
			class: params.class,
			method: params.method,
			desc: params.desc,
			dry_run: dryRun,
			out: resolvedOut,
			specs: params.specs,
		};

		const pyRes = await runReversePython<WorkerResponse>({
			cwd: this.session.cwd,
			sources: {
				"dexutil.py": dexutilSource,
				"dex-patch-worker.py": dexPatchWorkerSource,
			},
			entry: "dex-patch-worker.py",
			request: workerRequest,
			signal,
		});

		if (pyRes.status === "missing_dependency") {
			throw new ToolError(`Python dependency missing: ${pyRes.error}`);
		}

		if (pyRes.status === "error" || !pyRes.result) {
			throw new ToolError(pyRes.error ?? "DEX patch worker failed without error detail");
		}

		// Ensure source file remained completely untouched
		const postStat = fs.statSync(resolvedInput);
		if (
			postStat.mtimeMs !== inputStat.mtimeMs ||
			postStat.size !== inputStat.size ||
			postStat.ino !== inputStat.ino
		) {
			throw new ToolError("FATAL: Source file was modified during patch execution");
		}

		if (resolvedOut && fs.existsSync(resolvedOut)) {
			const outStat = fs.statSync(resolvedOut);
			if (outStat.dev === inputStat.dev && outStat.ino === inputStat.ino) {
				throw new ToolError("FATAL: Output file is a hardlink alias of the input file");
			}
		}

		const resp = pyRes.result;
		if (!resp.ok) {
			throw new ToolError(String(resp.error ?? "DEX patch operation failed"));
		}
		// Format result according to action
		if (resp.action === "inspect") {
			const methodData = resp.method;
			const lines = [
				`// DEX Method Bytecode Inspection`,
				`Target: ${resolvedInput}${params.entry ? ` [entry: ${params.entry}]` : ""}`,
				`Method: ${methodData.class}->${methodData.name}${methodData.desc ?? ""} (${methodData.section ?? "code"})`,
				`Code Offset: ${methodData.code_off_hex ?? `0x${methodData.code_off.toString(16)}`}`,
				`Registers: ${methodData.registers ?? 0} | In: ${methodData.ins ?? 0} | Out: ${methodData.outs ?? 0}`,
				`Instruction Count: ${methodData.instructions?.length ?? 0} units | Clean Decode: ${methodData.clean_decode ? "Yes" : "NO (suspect offsets)"}`,
			];

			if (methodData.branch_targets && methodData.branch_targets.length > 0) {
				lines.push(`Branch Targets: ${methodData.branch_targets.map(t => `0x${t.toString(16)}`).join(", ")}`);
			}

			if (methodData.verifier_violations && methodData.verifier_violations.length > 0) {
				lines.push(`Verifier Violations (${methodData.verifier_violations.length}):`);
				for (const v of methodData.verifier_violations) {
					lines.push(
						`  • Branch at 0x${v.branch_off.toString(16)} targets move-result at 0x${v.target_off.toString(16)} (${v.branch_op})`,
					);
				}
			}

			lines.push(`Disassembly Listing:`);
			for (const insn of methodData.instructions ?? []) {
				const targetMark = insn.is_branch_target ? "  <== branch target" : "";
				lines.push(`  ${insn.disassembly}${targetMark}`);
			}

			const details: DexPatchDetails = {
				action: "inspect",
				path: resolvedInput,
				entry: params.entry,
				status: "ok",
				inspect: {
					method: methodData,
				},
			};

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		if (resp.action === "validate") {
			const valData = resp;
			const lines = [
				`// DEX Structural & Verifier Validation`,
				`Target: ${resolvedInput}${params.entry ? ` [entry: ${params.entry}]` : ""}`,
				`Verifier Scope: Limited structural verifier, never full ART verification`,
				`Header Integrity: ${valData.header.valid ? "VALID" : "INVALID"} (${valData.header.file_size} bytes)`,
				`  • Checksum (Adler-32): ${valData.header.checksum_ok ? "OK" : "MISMATCH"}`,
				`  • Signature (SHA-1): ${valData.header.signature_ok ? "OK" : "MISMATCH"}`,
			];

			if (valData.header.problems && valData.header.problems.length > 0) {
				lines.push(`Header Structural Issues:`);
				for (const p of valData.header.problems) {
					lines.push(`  - ${p}`);
				}
			}

			lines.push(`Analysis Summary:`);
			lines.push(`  • Total Classes: ${valData.summary.total_classes}`);
			lines.push(`  • Methods with Code: ${valData.summary.methods_with_code}`);
			lines.push(`  • Unclean Decodes: ${valData.summary.unclean_decodes}`);
			lines.push(`  • Verifier Violations: ${valData.summary.verifier_violations}`);

			if (valData.violations && valData.violations.length > 0) {
				lines.push(`Verifier Violations (${valData.violations.length}):`);
				for (const v of valData.violations.slice(0, 10)) {
					const descStr =
						v.detail ??
						`branch 0x${v.branch_off.toString(16)} -> 0x${v.target_off.toString(16)} (${v.branch_op})`;
					lines.push(`  • ${v.class}->${v.method}${v.desc ?? ""}: ${descStr}`);
				}
				if (valData.violations.length > 10) {
					lines.push(`  ... (${valData.violations.length - 10} more omitted)`);
				}
			}

			const details: DexPatchDetails = {
				action: "validate",
				path: resolvedInput,
				entry: params.entry,
				status: "ok",
				validate: valData,
			};

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		if (resp.action === "patch") {
			const patchData = resp;
			const isDry = patchData.dry_run;
			const lines = [
				`// DEX Bytecode Patching ${isDry ? "[DRY RUN - No Output Written]" : "[PUBLISHED]"}`,
				`Input: ${resolvedInput}${params.entry ? ` [entry: ${params.entry}]` : ""}`,
				`Patches Applied: ${patchData.patches_count}`,
				`Verifier Notice: ${patchData.verifier_notice}`,
			];

			if (!isDry && patchData.output_path) {
				lines.push(`Output: ${patchData.output_path}`);
				if (patchData.header_change) {
					lines.push(
						`Header Recomputed: checksum ${patchData.header_change.before_checksum} -> ${patchData.header_change.after_checksum}, signature updated`,
					);
				}
			}

			lines.push(`\nPatch Summaries:`);
			for (const p of patchData.patches) {
				lines.push(`  • [${p.name}] ${p.class}->${p.method}${p.desc ?? ""}`);
				lines.push(`    Site: 0x${p.site_off.toString(16)} | Old: ${p.old_bytes} -> New: ${p.new_bytes}`);
				lines.push(`    Disassembly: ${p.old_text}  -->  ${p.new_text}`);
				if (p.expect_next_ok) {
					lines.push(`    Polarity Check: expect_next verified`);
				}
			}

			if (patchData.byte_diffs && patchData.byte_diffs.length > 0) {
				lines.push(`\nByte Differences:`);
				for (const d of patchData.byte_diffs) {
					lines.push(
						`  • Offset ${d.offset_hex} (${d.length} bytes): ${d.old_bytes} -> ${d.new_bytes} (${d.method})`,
					);
				}
			}

			const details: DexPatchDetails = {
				action: "patch",
				path: resolvedInput,
				entry: params.entry,
				status: "ok",
				patch: patchData,
			};
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		throw new ToolError("Unrecognized action response from worker");
	}
}
