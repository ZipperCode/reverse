import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import apkArtifactDescription from "../prompts/tools/apk-artifact.md" with { type: "text" };
import apkArtifactWorkerPy from "./apk-artifact/worker.py" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath, resolveToCwd } from "./path-utils";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";
import {
	accumulatePatches,
	hashFileSha256,
	resolveActiveWorkflowBaseline,
	verifyActivePatches,
	verifySourceOriginalBytes,
	type PatchStatus,
} from "../reverse-workflow";
import { EvidenceStore, evaluateEvidenceSupport } from "../evidence";
// ============================================================================
// Parameter Schema
// ============================================================================

export const apkArtifactSchema = type({
	action: type
		.enumerated("diff", "repack", "sign", "verify", "install_verify")
		.describe(
			"Action to perform: 'diff' (entry-level SHA256 & layout comparison), 'repack' (replace DEX entries, preserve META-INF/services, 16KiB .so alignment), 'sign' (zipalign + apksigner cryptographic signing), 'verify' (container integrity, alignment, and signature verification), or 'install_verify' (adb install, installed hash verification, and launch stability check).",
		),
	"path?": type("string").describe("Target APK path (used as input for repack/sign/verify, or original APK for diff)"),
	"original_path?": type("string").describe("Alias/explicit path to original APK for diff action"),
	"modified_path?": type("string").describe("Path to modified APK for diff action"),
	"output_path?": type("string").describe("Output destination path for repacked or signed APK artifact"),
	"dex_files?": type("unknown").describe(
		"Map of APK entry names (e.g. 'classes.dex', 'classes2.dex') to local replacement DEX file paths on disk",
	),
	"dex_path?": type("string").describe("Shorthand local path to replace 'classes.dex'"),
	"replace_files?": type("unknown").describe(
		"Map of arbitrary APK entry names (e.g. 'lib/arm64-v8a/libnative.so') to replacement file paths on disk for multi-component repack or deterministic replay",
	),
	"strip_signatures?": type("boolean").describe(
		"Whether to strip signature metadata (META-INF/*.SF, *.RSA, *.DSA, *.EC, MANIFEST.MF) while preserving services/resources during repack (default true)",
	),
	"sign?": type("boolean").describe("Whether to immediately sign the repacked APK artifact (default false)"),
	"page_align_so?": type("boolean").describe(
		"Whether to align uncompressed native .so libraries to 16KiB page boundaries for Android 15+ embedded loading (default true)",
	),
	"keystore_path?": type("string").describe("Path to existing keystore file for signing"),
	"key_alias?": type("string").describe("Key alias inside the keystore"),
	"ks_pass_env?": type("string").describe(
		"Name of the environment variable holding the keystore password (preferred, avoids plaintext passwords)",
	),
	"ks_pass_file?": type("string").describe("Path to protected file containing the keystore password"),
	"key_pass_env?": type("string").describe(
		"Name of the environment variable holding the key password (if different from keystore password)",
	),
	"key_pass_file?": type("string").describe("Path to protected file containing the key password"),
	"min_sdk_version?": type("number.integer >= 1").describe(
		"Explicit minimum Android SDK version passed to apksigner (default 21)",
	),
	"max_sdk_version?": type("number.integer >= 1").describe("Explicit maximum Android SDK version passed to apksigner"),
	"apksigner_path?": type("string").describe("Explicit path to apksigner executable or apksigner.jar"),
	"zipalign_path?": type("string").describe("Explicit path to zipalign executable"),
	"java_path?": type("string").describe("Explicit path to java executable (used when apksigner is a jar)"),
	"filter?": type("string").describe("Regex pattern to filter entry names in diff action"),
	"max_entries?": type("number.integer >= 1").describe(
		"Maximum entries returned in diff action sections (default 200)",
	),
	"package?": type("string").describe("Application package name for install_verify action (e.g. 'com.example.app')"),
	"package_name?": type("string").describe("Alias for package"),
	"activity?": type("string").describe(
		"Launch activity for install_verify action (e.g. '.MainActivity' or fully qualified)",
	),
	"serial?": type("string").describe("Explicit ADB device serial for install_verify (mandatory for install_verify)"),
	"output_dir?": type("string").describe(
		"Fresh output directory to store screenshot and process-scoped logcat files during install_verify",
	),
	"screenshot_path?": type("string").describe(
		"Local destination path to capture an on-device screenshot during install_verify",
	),
	"grant_permissions?": type("string[]").describe("Optional list of Android permissions to grant upon install"),
	"wait_seconds?": type("number.integer >= 1").describe(
		"Seconds to wait between the two PID stability checks in install_verify (default 10)",
	),
	"workflow_id?": type("string").describe(
		"Explicit reverse workflow ID to link this artifact build to; automatically discovered from sample if omitted",
	),
	"register_derivative?": type("boolean").describe(
		"Whether to automatically record and verify the derivative artifact in the active reverse workflow lineage (default true when linked to an active workflow)",
	),
	"build_id?": type("string").describe(
		"Explicit build identifier for the derivative artifact record in the workflow lineage",
	),
	"patches?": type("unknown").describe(
		"Optional list of patch records introduced in this build revision (e.g. [{ patch_id, member_path, offset, original_bytes, expected_bytes }])",
	),
	"runtime_evidence_ids?": type("string[]").describe(
		"Optional list of verified runtime evidence IDs bound to this exact artifact output SHA256",
	),
});

export type ApkArtifactParams = typeof apkArtifactSchema.infer;
export type ApkArtifactAction = ApkArtifactParams["action"];

// ============================================================================
// Details & Result Interfaces
// ============================================================================

export interface ApkContainerInfo {
	path: string;
	size: number;
	sha256: string;
	entry_count?: number;
}

export interface ApkDiffItem {
	name: string;
	classification: string;
	original_size: number;
	modified_size: number;
	original_sha256: string;
	modified_sha256: string;
	same_size: boolean;
	original_compress_type: number;
	modified_compress_type: number;
}

export interface ApkDiffResult {
	action: "diff";
	status: "ok";
	original: ApkContainerInfo;
	modified: ApkContainerInfo;
	summary: {
		original_entries: number;
		modified_entries: number;
		added_count: number;
		removed_count: number;
		changed_count: number;
		same_size_changed_count: number;
		identical_count: number;
		signature_noise_count: number;
		has_differences: boolean;
	};
	added: Array<{ name: string; size: number; sha256: string; classification: string }>;
	removed: Array<{ name: string; size: number; sha256: string; classification: string }>;
	changed: ApkDiffItem[];
	truncated: {
		added: boolean;
		removed: boolean;
		changed: boolean;
	};
}

export interface ApkRepackResult {
	action: "repack";
	status: "ok";
	output_path: string;
	size: number;
	sha256: string;
	signed: boolean;
	replaced_entries: string[];
	preserved_entries_count: number;
	dropped_signatures: string[];
	alignment: {
		ok: boolean;
		issues: string[];
		checked_entries: Array<{
			name: string;
			stored: boolean;
			offset: number;
			aligned: boolean;
			alignment_required: number;
		}>;
	};
	signature_details?: ApkSignResult;
	workflow_id?: string;
	build_id?: string;
	parent_sha256?: string;
	original_sha256?: string;
	baseline_promoted?: boolean;
	lineage_verification?: {
		status: string;
		active_patches_count: number;
		checked_patches_count: number;
	};
}

export interface ApkSignResult {
	action: "sign";
	status: "ok";
	output_path: string;
	size: number;
	sha256: string;
	signed: boolean;
	v1_signed: boolean;
	v2_signed: boolean;
	v3_signed: boolean;
	cert_fingerprints: string[];
	verify_output: string;
	workflow_id?: string;
	build_id?: string;
	parent_sha256?: string;
	original_sha256?: string;
	baseline_promoted?: boolean;
	lineage_verification?: {
		status: string;
		active_patches_count: number;
		checked_patches_count: number;
	};
}

export interface ApkVerifyResult {
	action: "verify";
	status: "ok" | "unverified_or_failed" | "corrupt_archive";
	path: string;
	size: number;
	sha256: string;
	entry_count?: number;
	error?: string;
	alignment?: {
		ok: boolean;
		issues: string[];
		checked_entries: Array<{
			name: string;
			stored: boolean;
			offset: number;
			aligned: boolean;
			alignment_required: number;
		}>;
	};
	signing_block_present?: boolean;
	signature?: {
		tool_available: boolean;
		verified: boolean;
		v1_scheme: boolean;
		v2_scheme: boolean;
		v3_scheme: boolean;
		v4_scheme: boolean;
		cert_fingerprints: string[];
		tool_output?: string | null;
		notice?: string | null;
	};
	verified: boolean;
	lineage_verification?: {
		status: string;
		active_patches_count: number;
		checked_patches_count: number;
		workflow_id?: string;
		baseline_build_id?: string;
	};
}

export interface ApkInstallVerifyResult {
	action: "install_verify";
	status: "ok" | "launch_failed_or_crashed";
	package: string;
	activity: string;
	device_serial?: string | null;
	installed_apk_sha256: string;
	hash_verified: boolean;
	launch_status: "stable" | "crash_on_launch" | "crash_loop";
	pid_sample_1?: string | null;
	pid_sample_2?: string | null;
	focus?: string;
	fatal_signatures: string[];
	screenshot_path?: string | null;
	log_path?: string | null;
	feature_verified: false;
	notice: string;
}

export interface ApkArtifactDetails {
	action: ApkArtifactAction;
	status: "ok" | "error" | "unverified_or_failed" | "launch_failed_or_crashed" | "corrupt_archive";
	summary?: string;
	error?: string;
	diff?: ApkDiffResult;
	repack?: ApkRepackResult;
	sign?: ApkSignResult;
	verify?: ApkVerifyResult;
	install_verify?: ApkInstallVerifyResult;
}

// ============================================================================
// Tool Implementation
// ============================================================================

interface PatchDeclaration {
	patch_id: string;
	member_path?: string;
	offset: number;
	original_bytes: string;
	expected_bytes: string;
	status?: PatchStatus;
	retirement_reason?: string;
	evidence_id?: string;
}

function parsePatchDeclarations(raw: unknown): PatchDeclaration[] {
	if (!Array.isArray(raw)) return [];
	const result: PatchDeclaration[] = [];
	for (const item of raw) {
		if (item && typeof item === "object" && "patch_id" in item && typeof item.patch_id === "string") {
			const candidate = item as Record<string, unknown>;
			result.push({
				patch_id: item.patch_id,
				member_path: typeof candidate.member_path === "string" ? candidate.member_path : undefined,
				offset: typeof candidate.offset === "number" ? candidate.offset : 0,
				original_bytes: typeof candidate.original_bytes === "string" ? candidate.original_bytes : "",
				expected_bytes: typeof candidate.expected_bytes === "string" ? candidate.expected_bytes : "",
				status: candidate.status === "retired" ? "retired" : "active",
				retirement_reason:
					typeof candidate.retirement_reason === "string" ? candidate.retirement_reason : undefined,
				evidence_id: typeof candidate.evidence_id === "string" ? candidate.evidence_id : undefined,
			});
		}
	}
	return result;
}

function normalizeEntryName(name: string): string {
	const clean = name.trim().replace(/\\/g, "/").replace(/^\/+/, "");
	if (!clean) {
		throw new ToolError(`Entry name cannot be empty: '${name}'`);
	}
	const parts = clean.split("/");
	if (parts.some(p => p === "" || p === "." || p === "..")) {
		throw new ToolError(`Invalid path traversal or empty segment in entry name: '${name}'`);
	}
	return clean;
}

function parseReplaceFilesMap(raw: unknown, cwd: string): Record<string, string> {
	const map: Record<string, string> = {};
	if (raw !== undefined) {
		if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
			throw new ToolError("Parameter 'replace_files' must be an object mapping entry names to file paths");
		}
		for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
			if (typeof v !== "string" || !v.trim()) {
				throw new ToolError(`Invalid entry in replace_files map for key '${k}': path must be a non-empty string`);
			}
			const normKey = normalizeEntryName(k);
			if (normKey in map) {
				throw new ToolError(
					`Duplicate replacement entry '${normKey}' declared in replace_files map (normalized from '${k}')`,
				);
			}
			map[normKey] = resolveReadPath(v.trim(), cwd);
		}
	}
	return map;
}
async function publishExclusive(srcPath: string, destPath: string): Promise<void> {
	const destDir = path.dirname(destPath);
	await fs.mkdir(destDir, { recursive: true });

	try {
		await fs.link(srcPath, destPath);
	} catch (err: unknown) {
		const nodeErr = err as { code?: string };
		if (nodeErr.code === "EEXIST") {
			throw new ToolError(
				`Output destination already exists: ${destPath}. Overwriting existing files is not permitted.`,
			);
		}
		if (nodeErr.code === "EXDEV") {
			try {
				await fs.copyFile(srcPath, destPath, fs.constants.COPYFILE_EXCL);
			} catch (copyErr: unknown) {
				const copyNodeErr = copyErr as { code?: string };
				if (copyNodeErr.code === "EEXIST") {
					throw new ToolError(
						`Output destination already exists: ${destPath}. Overwriting existing files is not permitted.`,
					);
				}
				throw copyErr;
			}
		} else {
			throw err;
		}
	} finally {
		await fs.unlink(srcPath).catch(() => undefined);
	}
}
export class ApkArtifactTool implements AgentTool<typeof apkArtifactSchema, ApkArtifactDetails> {
	readonly name = "apk_artifact";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args && typeof args.action === "string") {
			const action = args.action;
			if (action === "diff" || action === "verify") {
				return "read";
			}
		}
		return "write";
	};
	readonly label = "APK Artifact Management";
	readonly summary =
		"First-class Android APK artifact manipulation: content-level diffing, surgical repacking with preserved services, 16KiB native library alignment, zipalign+apksigner signing, and on-device install validation.";
	readonly description: string;
	readonly parameters = apkArtifactSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(apkArtifactDescription);
	}

	async execute(
		_toolCallId: string,
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		throwIfAborted(signal);

		const action = params.action;
		switch (action) {
			case "diff":
				return this.handleDiff(params, signal);
			case "repack":
				return this.handleRepack(params, signal);
			case "sign":
				return this.handleSign(params, signal);
			case "verify":
				return this.handleVerify(params, signal);
			case "install_verify":
				return this.handleInstallVerify(params, signal);
			default: {
				const unexpected: never = action;
				throw new ToolError(`Unsupported action: ${String(unexpected)}`);
			}
		}
	}

	// --------------------------------------------------------------------------
	// Action: diff
	// --------------------------------------------------------------------------
	private async handleDiff(
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		const rawA = params.original_path ?? params.path;
		const rawB = params.modified_path;

		if (!rawA || !rawB) {
			throw new ToolError("Action 'diff' requires both 'original_path' (or path) and 'modified_path'");
		}

		const resolvedA = resolveReadPath(rawA, this.session.cwd);
		const resolvedB = resolveReadPath(rawB, this.session.cwd);

		try {
			await fs.stat(resolvedA);
		} catch (err) {
			throw new ToolError(
				`Original APK not found: ${resolvedA} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		try {
			await fs.stat(resolvedB);
		} catch (err) {
			throw new ToolError(
				`Modified APK not found: ${resolvedB} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		const workerResult = await runReversePython<ApkDiffResult>({
			cwd: this.session.cwd,
			sources: { "worker.py": apkArtifactWorkerPy },
			entry: "worker.py",
			request: {
				action: "diff",
				params: {
					original_path: resolvedA,
					modified_path: resolvedB,
					filter: params.filter,
					max_entries: params.max_entries ?? 200,
				},
			},
			signal,
		});

		if (workerResult.status === "missing_dependency") {
			throw new ToolError(`Python 3.9+ runtime required for apk_artifact diff: ${workerResult.error}`);
		}
		if (workerResult.status === "error" || !workerResult.result) {
			throw new ToolError(
				`apk_artifact diff failed: ${workerResult.error ?? workerResult.stderr ?? "Unknown error"}`,
			);
		}

		const diff = workerResult.result;
		const lines = [
			"// Android APK Binary Entry Diff",
			`Original: ${diff.original.path} (${diff.original.size} bytes, SHA256: ${diff.original.sha256})`,
			`Modified: ${diff.modified.path} (${diff.modified.size} bytes, SHA256: ${diff.modified.sha256})`,
			"",
			`Summary:`,
			`  • Content Differences: ${diff.summary.has_differences ? "DETECTED" : "None (archives identical)"}`,
			`  • Content Changed: ${diff.summary.changed_count} entries`,
			`  • Same-Size Changed: ${diff.summary.same_size_changed_count} entries (critical: same length, different hash!)`,
			`  • Added in Modified: ${diff.summary.added_count} entries`,
			`  • Removed in Modified: ${diff.summary.removed_count} entries`,
			`  • Identical Entries: ${diff.summary.identical_count}`,
			`  • Signature Artifact Noise: ${diff.summary.signature_noise_count} entries`,
		];

		if (diff.changed.length > 0) {
			lines.push("", "=== CHANGED ENTRIES ===");
			for (const c of diff.changed) {
				const tag = c.same_size ? " [SAME SIZE REPLACEMENT]" : "";
				const ctype =
					c.original_compress_type !== c.modified_compress_type
						? ` (compression ${c.original_compress_type} -> ${c.modified_compress_type})`
						: "";
				lines.push(
					`  ~ ${c.name} [${c.classification}]${tag}${ctype}: ${c.original_size}B (${c.original_sha256.slice(0, 16)}...) -> ${c.modified_size}B (${c.modified_sha256.slice(0, 16)}...)`,
				);
			}
			if (diff.truncated.changed) {
				lines.push("  ... (more changed entries omitted)");
			}
		}

		if (diff.added.length > 0) {
			lines.push("", "=== ADDED ENTRIES (potential injection candidates) ===");
			for (const a of diff.added) {
				lines.push(`  + ${a.name} [${a.classification}] ${a.size}B (${a.sha256.slice(0, 16)}...)`);
			}
			if (diff.truncated.added) {
				lines.push("  ... (more added entries omitted)");
			}
		}

		if (diff.removed.length > 0) {
			lines.push("", "=== REMOVED ENTRIES ===");
			for (const r of diff.removed) {
				lines.push(`  - ${r.name} [${r.classification}] ${r.size}B (${r.sha256.slice(0, 16)}...)`);
			}
			if (diff.truncated.removed) {
				lines.push("  ... (more removed entries omitted)");
			}
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "diff",
				status: "ok",
				summary: `Diff between ${path.basename(resolvedA)} and ${path.basename(resolvedB)}: ${diff.summary.changed_count} changed (${diff.summary.same_size_changed_count} same-size), ${diff.summary.added_count} added, ${diff.summary.removed_count} removed`,
				diff,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: repack
	// --------------------------------------------------------------------------
	private async handleRepack(
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		const rawIn = params.path;
		const rawOut = params.output_path;

		if (!rawIn) {
			throw new ToolError("Action 'repack' requires parameter 'path' (input APK)");
		}
		if (!rawOut) {
			throw new ToolError("Action 'repack' requires parameter 'output_path'");
		}

		const resolvedIn = resolveReadPath(rawIn, this.session.cwd);
		const resolvedOut = resolveToCwd(rawOut, this.session.cwd);

		try {
			await fs.stat(resolvedIn);
		} catch (err) {
			throw new ToolError(
				`Input APK not found: ${resolvedIn} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		// Anti-aliasing check
		if (path.resolve(resolvedIn) === path.resolve(resolvedOut)) {
			throw new ToolError("Output path cannot be identical to input APK path (anti-aliasing safety violation)");
		}
		const realIn = await fs.realpath(resolvedIn);
		const realOut = await fs.realpath(resolvedOut).catch(() => null);
		if (realOut && realIn === realOut) {
			throw new ToolError("Output path resolves to the same filesystem entity as input APK");
		}

		// Strict no-overwrite rule
		const existingOut = await fs.stat(resolvedOut).catch(() => null);
		if (existingOut) {
			throw new ToolError(
				`Output destination already exists at ${resolvedOut}. Overwriting existing files is not permitted.`,
			);
		}

		// Resolve input SHA-256 and link to active workflow/baseline
		const inputSha256 = await hashFileSha256(resolvedIn);
		const baselineInfo = await resolveActiveWorkflowBaseline(this.session.cwd, {
			workflowId: params.workflow_id,
			targetPath: resolvedIn,
			targetSha256: inputSha256,
		});

		// Resolve dex_files and replace_files
		const dexFilesMap: Record<string, string> = {};
		if (params.dex_files !== undefined) {
			if (typeof params.dex_files !== "object" || params.dex_files === null || Array.isArray(params.dex_files)) {
				throw new ToolError("Parameter 'dex_files' must be an object mapping entry names to file paths");
			}
			for (const [k, v] of Object.entries(params.dex_files)) {
				if (typeof v !== "string" || !v.trim()) {
					throw new ToolError(`Invalid entry in dex_files map for key '${k}': path must be a non-empty string`);
				}
				const normKey = normalizeEntryName(k);
				if (normKey in dexFilesMap) {
					throw new ToolError(
						`Duplicate replacement entry '${normKey}' declared in dex_files map (normalized from '${k}')`,
					);
				}
				dexFilesMap[normKey] = resolveReadPath(v.trim(), this.session.cwd);
			}
		}
		if (params.dex_path) {
			if ("classes.dex" in dexFilesMap) {
				throw new ToolError(
					"Conflicting DEX replacement: both 'dex_path' and 'dex_files[\"classes.dex\"]' were provided",
				);
			}
			dexFilesMap["classes.dex"] = resolveReadPath(params.dex_path, this.session.cwd);
		}
		const replaceFilesMap = parseReplaceFilesMap(params.replace_files, this.session.cwd);

		// Reject overlapping replacements between dex_files and replace_files
		for (const k of Object.keys(replaceFilesMap)) {
			if (k in dexFilesMap) {
				throw new ToolError(
					`Overlapping replacement entry '${k}' declared in both dex_files and replace_files. Duplicate replacement definitions are rejected.`,
				);
			}
		}

		const patchDeclarations = parsePatchDeclarations(params.patches);

		const secretEnv: Record<string, string> = {};
		if (params.ks_pass_env && process.env[params.ks_pass_env] !== undefined) {
			secretEnv[params.ks_pass_env] = process.env[params.ks_pass_env]!;
		}
		if (params.key_pass_env && process.env[params.key_pass_env] !== undefined) {
			secretEnv[params.key_pass_env] = process.env[params.key_pass_env]!;
		}

		// Stage in private directory so unverified or failing outputs are never published
		const outDir = path.dirname(resolvedOut);
		await fs.mkdir(outDir, { recursive: true });
		const stageDir = await fs.mkdtemp(path.join(outDir, ".apk_repack_stage_"));
		const stagedOut = path.join(stageDir, path.basename(resolvedOut));

		let repack: ApkRepackResult;
		try {
			const workerResult = await runReversePython<ApkRepackResult>({
				cwd: this.session.cwd,
				sources: { "worker.py": apkArtifactWorkerPy },
				entry: "worker.py",
				env: secretEnv,
				request: {
					action: "repack",
					params: {
						path: resolvedIn,
						output_path: stagedOut,
						dex_files: dexFilesMap,
						replace_files: replaceFilesMap,
						strip_signatures: params.strip_signatures ?? true,
						page_align_so: params.page_align_so ?? true,
						sign: params.sign ?? false,
						keystore_path: params.keystore_path
							? resolveReadPath(params.keystore_path, this.session.cwd)
							: undefined,
						key_alias: params.key_alias,
						ks_pass_env: params.ks_pass_env,
						ks_pass_file: params.ks_pass_file
							? resolveReadPath(params.ks_pass_file, this.session.cwd)
							: undefined,
						key_pass_env: params.key_pass_env,
						key_pass_file: params.key_pass_file
							? resolveReadPath(params.key_pass_file, this.session.cwd)
							: undefined,
						min_sdk_version: params.min_sdk_version,
						max_sdk_version: params.max_sdk_version,
						apksigner_path: params.apksigner_path
							? resolveReadPath(params.apksigner_path, this.session.cwd)
							: undefined,
						zipalign_path: params.zipalign_path
							? resolveReadPath(params.zipalign_path, this.session.cwd)
							: undefined,
						java_path: params.java_path ? resolveReadPath(params.java_path, this.session.cwd) : undefined,
					},
				},
				signal,
			});

			if (workerResult.status === "missing_dependency") {
				throw new ToolError(`Python 3.9+ runtime required for apk_artifact repack: ${workerResult.error}`);
			}
			if (workerResult.status === "error" || !workerResult.result) {
				throw new ToolError(
					`apk_artifact repack failed: ${workerResult.error ?? workerResult.stderr ?? "Unknown error"}`,
				);
			}

			repack = workerResult.result;
			const stagedSha256 = await hashFileSha256(stagedOut);

			// Prevalidate source original_bytes against input APK before publication
			if (patchDeclarations.length > 0) {
				await verifySourceOriginalBytes(resolvedIn, patchDeclarations);
			}

			// Prevalidate cumulative patch arithmetic before publication
			const baseCumulative = baselineInfo.baseline?.cumulative_patches ?? [];
			const allRetirements = [
				...(baselineInfo.workflow?.retired_patches_audit?.map(a => ({ patch_id: a.patch_id, reason: a.reason })) ??
					[]),
			];
			const cumulativePatches = accumulatePatches(
				baseCumulative,
				patchDeclarations.length > 0 ? patchDeclarations : undefined,
				allRetirements,
				params.build_id ?? "staged_validate",
			);

			// Prevalidate runtime evidence against staged output hash before publication using canonical evaluator
			if (params.runtime_evidence_ids && params.runtime_evidence_ids.length > 0) {
				const evidenceStore = new EvidenceStore({ repositoryRoot: this.session.cwd });
				const evalRes = await evaluateEvidenceSupport(evidenceStore, params.runtime_evidence_ids, {
					requiredTargetSha256: stagedSha256,
					requiredKinds: ["conclusion"],
				});
				if (!evalRes.valid) {
					throw new ToolError(
						`Runtime evidence prevalidation failed for repack artifact: ${evalRes.reason}. Prior revision runtime evidence cannot be inherited by a new revision.`,
					);
				}
			}

			// Verify all active cumulative patches in staged artifact BEFORE publication
			let lineageVerification:
				| { status: string; active_patches_count: number; checked_patches_count: number }
				| undefined;
			if (baselineInfo.baseline) {
				const activeCumulative = cumulativePatches.filter(p => p.status === "active");
				if (activeCumulative.length > 0) {
					const verification = await verifyActivePatches(stagedOut, activeCumulative);
					if (verification.status !== "verified") {
						throw new ToolError(
							`apk_artifact repack rejected: Active baseline patch '${verification.failed_patch_id}' was dropped or mismatched in output artifact: ${verification.failure_reason}. When repacking from clean original base or earlier derivative, all active cumulative patches must be preserved (replay A+B) or explicitly retired. Staged output discarded without publication to '${resolvedOut}'.`,
						);
					}
					lineageVerification = {
						status: "verified",
						active_patches_count: activeCumulative.length,
						checked_patches_count: verification.checked_patches_count,
					};
				} else {
					lineageVerification = {
						status: "verified",
						active_patches_count: 0,
						checked_patches_count: 0,
					};
				}
			}

			// Atomic exclusive publication via hard link (or COPYFILE_EXCL fallback)
			const stagedStat = await fs.stat(stagedOut);
			const expectedIno = stagedStat.ino;
			const expectedDev = stagedStat.dev;

			await publishExclusive(stagedOut, resolvedOut);

			const actualStat = await fs.stat(resolvedOut);
			const checkSha = await hashFileSha256(resolvedOut);
			if (checkSha.toLowerCase() !== stagedSha256.toLowerCase()) {
				throw new ToolError(
					`Integrity violation: Published artifact at '${resolvedOut}' was modified concurrently (expected SHA-256 '${stagedSha256}', found '${checkSha}'). Publication aborted.`,
				);
			}
			const actualOutputSha256 = stagedSha256;
			repack.output_path = resolvedOut;
			repack.size = actualStat.size;
			repack.sha256 = actualOutputSha256;
			if (lineageVerification) {
				repack.lineage_verification = lineageVerification;
			}

			// Record derivative in ReverseWorkflowStore if linked
			if (baselineInfo.workflow && params.register_derivative !== false) {
				const isParentBaseline = baselineInfo.baseline?.output_sha256.toLowerCase() === inputSha256.toLowerCase();
				const parentBuildId = isParentBaseline
					? baselineInfo.baseline?.build_id
					: baselineInfo.workflow.build_lineage?.find(
							b => b.output_sha256.toLowerCase() === inputSha256.toLowerCase(),
						)?.build_id;

				const sigDetails = repack.signature_details;
				const signatureStatus = repack.signed ? "signed" : "unsigned";
				const signatureScheme = sigDetails?.v3_signed
					? "v3"
					: sigDetails?.v2_signed
						? "v2"
						: sigDetails?.v1_signed
							? "v1"
							: undefined;
				const certFp = sigDetails?.cert_fingerprints?.[0];

				try {
					const derivativeRecord = await baselineInfo.store.registerDerivative(baselineInfo.workflow.id, {
						build_id: params.build_id,
						target_path: path.relative(this.session.cwd, resolvedOut) || resolvedOut,
						output_sha256: actualOutputSha256,
						original_sha256: baselineInfo.baseTargetSha256,
						parent_sha256: inputSha256,
						...(parentBuildId ? { parent_build_id: parentBuildId } : {}),
						patches: patchDeclarations.length > 0 ? patchDeclarations : undefined,
						signature: {
							status: signatureStatus,
							scheme: signatureScheme,
							fingerprint: certFp,
						},
						runtime_evidence_ids: params.runtime_evidence_ids,
					});

					repack.workflow_id = baselineInfo.workflow.id;
					repack.build_id = derivativeRecord.build_id;
					repack.parent_sha256 = inputSha256;
					repack.original_sha256 = baselineInfo.baseTargetSha256;
					repack.baseline_promoted = true;
				} catch (regErr) {
					// Rollback: unlink resolvedOut ONLY if file strictly matches staged identity & hash
					try {
						const currentStat = await fs.stat(resolvedOut).catch(() => null);
						if (currentStat) {
							const isSameIdentity =
								expectedIno !== 0 && currentStat.ino === expectedIno && currentStat.dev === expectedDev;
							const checkDiskHash = await hashFileSha256(resolvedOut).catch(() => null);
							if (checkDiskHash && checkDiskHash.toLowerCase() === stagedSha256.toLowerCase()) {
								if (isSameIdentity || expectedIno === 0) {
									await fs.unlink(resolvedOut).catch(() => undefined);
								}
							}
						}
					} catch {
						// ignore rollback error
					}
					throw new ToolError(
						`Artifact repacked successfully but failed workflow derivative registration: ${regErr instanceof Error ? regErr.message : String(regErr)}. Rolled back published output.`,
					);
				}
			}
		} finally {
			await fs.rm(stageDir, { recursive: true, force: true }).catch(() => undefined);
		}

		const lines = [
			"// Android APK Repack Artifact",
			`Output Artifact: ${repack.output_path}`,
			`Size: ${repack.size} bytes`,
			`SHA256: ${repack.sha256}`,
			`Signature State: ${repack.signed ? "SIGNED (v1/v2/v3 verified)" : "UNSIGNED (raw repacked artifact)"}`,
			"",
			`Changes Applied:`,
			`  • Replaced DEX Entries: ${repack.replaced_entries.join(", ") || "none"}`,
			`  • Preserved Non-Signature Entries: ${repack.preserved_entries_count}`,
			`  • Dropped Signature Metadata: ${repack.dropped_signatures.length} files (${repack.dropped_signatures.slice(0, 5).join(", ")}${repack.dropped_signatures.length > 5 ? "..." : ""})`,
			"",
			`Alignment & Storage Validation:`,
			`  • Status: ${repack.alignment.ok ? "PASS" : "FAIL"}`,
		];

		for (const it of repack.alignment.checked_entries) {
			lines.push(
				`  • ${it.name}: ${it.stored ? "STORED" : "COMPRESSED"}, offset=0x${it.offset.toString(16)}, ${it.aligned ? `aligned to ${it.alignment_required}B` : `MISALIGNED (needs ${it.alignment_required}B)`}`,
			);
		}
		if (repack.alignment.issues.length > 0) {
			lines.push(`  • Alignment Issues:`);
			for (const iss of repack.alignment.issues) {
				lines.push(`    ! ${iss}`);
			}
		}

		if (repack.lineage_verification) {
			lines.push(
				"",
				`Workflow Lineage Verification:`,
				`  • Status: PASS (${repack.lineage_verification.checked_patches_count} active baseline patches verified)`,
			);
		}
		if (repack.workflow_id && repack.build_id) {
			lines.push(
				`  • Workflow: ${repack.workflow_id}`,
				`  • Build ID: ${repack.build_id} (promoted to active baseline)`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "repack",
				status: "ok",
				summary: `Repacked APK written to ${repack.output_path} (${repack.size} bytes, SHA256: ${repack.sha256})`,
				repack,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: sign
	// --------------------------------------------------------------------------
	private async handleSign(
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		const rawIn = params.path;
		const rawOut = params.output_path;

		if (!rawIn) {
			throw new ToolError("Action 'sign' requires parameter 'path' (unsigned APK)");
		}
		if (!rawOut) {
			throw new ToolError(
				"Action 'sign' requires parameter 'output_path' (cannot default to input or overwrite in-place)",
			);
		}

		const resolvedIn = resolveReadPath(rawIn, this.session.cwd);
		const resolvedOut = resolveToCwd(rawOut, this.session.cwd);

		try {
			await fs.stat(resolvedIn);
		} catch (err) {
			throw new ToolError(
				`Input APK not found: ${resolvedIn} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (!params.keystore_path) {
			throw new ToolError("Action 'sign' requires parameter 'keystore_path'");
		}
		if (!params.key_alias) {
			throw new ToolError("Action 'sign' requires parameter 'key_alias'");
		}
		if (!params.ks_pass_env && !params.ks_pass_file) {
			throw new ToolError(
				"Action 'sign' requires keystore password via environment variable ('ks_pass_env') or protected password file ('ks_pass_file'). Plaintext passwords are not permitted.",
			);
		}

		const resolvedKs = resolveReadPath(params.keystore_path, this.session.cwd);
		const resolvedPf = params.ks_pass_file ? resolveReadPath(params.ks_pass_file, this.session.cwd) : undefined;
		const resolvedKeyPf = params.key_pass_file ? resolveReadPath(params.key_pass_file, this.session.cwd) : undefined;

		// Strict no-overwrite rule
		const existingSignOut = await fs.stat(resolvedOut).catch(() => null);
		if (existingSignOut) {
			throw new ToolError(
				`Output destination already exists at ${resolvedOut}. Overwriting existing files is not permitted.`,
			);
		}

		const inputSha256 = await hashFileSha256(resolvedIn);
		const baselineInfo = await resolveActiveWorkflowBaseline(this.session.cwd, {
			workflowId: params.workflow_id,
			targetPath: resolvedIn,
			targetSha256: inputSha256,
		});

		const secretEnv: Record<string, string> = {};
		if (params.ks_pass_env && process.env[params.ks_pass_env] !== undefined) {
			secretEnv[params.ks_pass_env] = process.env[params.ks_pass_env]!;
		}
		if (params.key_pass_env && process.env[params.key_pass_env] !== undefined) {
			secretEnv[params.key_pass_env] = process.env[params.key_pass_env]!;
		}

		const outDir = path.dirname(resolvedOut);
		await fs.mkdir(outDir, { recursive: true });
		const stageDir = await fs.mkdtemp(path.join(outDir, ".apk_sign_stage_"));
		const stagedOut = path.join(stageDir, path.basename(resolvedOut));

		let sign: ApkSignResult;
		try {
			const workerResult = await runReversePython<ApkSignResult>({
				cwd: this.session.cwd,
				sources: { "worker.py": apkArtifactWorkerPy },
				entry: "worker.py",
				env: secretEnv,
				request: {
					action: "sign",
					params: {
						path: resolvedIn,
						output_path: stagedOut,
						keystore_path: resolvedKs,
						key_alias: params.key_alias,
						ks_pass_env: params.ks_pass_env,
						ks_pass_file: resolvedPf,
						key_pass_env: params.key_pass_env,
						key_pass_file: resolvedKeyPf,
						min_sdk_version: params.min_sdk_version,
						max_sdk_version: params.max_sdk_version,
						apksigner_path: params.apksigner_path
							? resolveReadPath(params.apksigner_path, this.session.cwd)
							: undefined,
						zipalign_path: params.zipalign_path
							? resolveReadPath(params.zipalign_path, this.session.cwd)
							: undefined,
						java_path: params.java_path ? resolveReadPath(params.java_path, this.session.cwd) : undefined,
						page_align_so: params.page_align_so ?? true,
					},
				},
				signal,
			});

			if (workerResult.status === "missing_dependency") {
				throw new ToolError(`Python 3.9+ runtime required for apk_artifact sign: ${workerResult.error}`);
			}
			if (workerResult.status === "error" || !workerResult.result) {
				throw new ToolError(
					`apk_artifact sign failed: ${workerResult.error ?? workerResult.stderr ?? "Unknown error"}`,
				);
			}

			sign = workerResult.result;

			const stagedSha256 = await hashFileSha256(stagedOut);

			// Prevalidate runtime evidence against staged output hash before publication using canonical evaluator
			if (params.runtime_evidence_ids && params.runtime_evidence_ids.length > 0) {
				const evidenceStore = new EvidenceStore({ repositoryRoot: this.session.cwd });
				const evalRes = await evaluateEvidenceSupport(evidenceStore, params.runtime_evidence_ids, {
					requiredTargetSha256: stagedSha256,
					requiredKinds: ["conclusion"],
				});
				if (!evalRes.valid) {
					throw new ToolError(
						`Runtime evidence prevalidation failed for signed artifact: ${evalRes.reason}. Prior revision runtime evidence cannot be inherited by a new revision.`,
					);
				}
			}

			// Verify baseline active patches in signed output
			let lineageVerification:
				| { status: string; active_patches_count: number; checked_patches_count: number }
				| undefined;
			if (baselineInfo.baseline) {
				if (baselineInfo.activePatches.length > 0) {
					const verification = await verifyActivePatches(stagedOut, baselineInfo.activePatches);
					if (verification.status !== "verified") {
						throw new ToolError(
							`apk_artifact sign rejected: Active baseline patch '${verification.failed_patch_id}' was dropped or corrupted in signed output: ${verification.failure_reason}. Staged signed output discarded without publication to '${resolvedOut}'.`,
						);
					}
					lineageVerification = {
						status: "verified",
						active_patches_count: baselineInfo.activePatches.length,
						checked_patches_count: verification.checked_patches_count,
					};
				} else {
					lineageVerification = {
						status: "verified",
						active_patches_count: 0,
						checked_patches_count: 0,
					};
				}
			}

			// Atomic exclusive publication via hard link (or COPYFILE_EXCL fallback)
			const stagedStat = await fs.stat(stagedOut);
			const expectedIno = stagedStat.ino;
			const expectedDev = stagedStat.dev;

			await publishExclusive(stagedOut, resolvedOut);

			const actualStat = await fs.stat(resolvedOut);
			const checkSha = await hashFileSha256(resolvedOut);
			if (checkSha.toLowerCase() !== stagedSha256.toLowerCase()) {
				throw new ToolError(
					`Integrity violation: Published artifact at '${resolvedOut}' was modified concurrently (expected SHA-256 '${stagedSha256}', found '${checkSha}'). Publication aborted.`,
				);
			}
			const actualOutputSha256 = stagedSha256;
			sign.output_path = resolvedOut;
			sign.size = actualStat.size;
			sign.sha256 = actualOutputSha256;
			if (lineageVerification) {
				sign.lineage_verification = lineageVerification;
			}

			if (baselineInfo.workflow && params.register_derivative !== false) {
				const isParentBaseline = baselineInfo.baseline?.output_sha256.toLowerCase() === inputSha256.toLowerCase();
				const parentBuildId = isParentBaseline
					? baselineInfo.baseline?.build_id
					: baselineInfo.workflow.build_lineage?.find(
							b => b.output_sha256.toLowerCase() === inputSha256.toLowerCase(),
						)?.build_id;

				const scheme = sign.v3_signed ? "v3" : sign.v2_signed ? "v2" : sign.v1_signed ? "v1" : undefined;
				const certFp = sign.cert_fingerprints[0];

				try {
					const derivativeRecord = await baselineInfo.store.registerDerivative(baselineInfo.workflow.id, {
						build_id: params.build_id,
						target_path: path.relative(this.session.cwd, resolvedOut) || resolvedOut,
						output_sha256: actualOutputSha256,
						original_sha256: baselineInfo.baseTargetSha256,
						parent_sha256: inputSha256,
						...(parentBuildId ? { parent_build_id: parentBuildId } : {}),
						signature: {
							status: "signed",
							scheme,
							fingerprint: certFp,
						},
						runtime_evidence_ids: params.runtime_evidence_ids,
					});

					sign.workflow_id = baselineInfo.workflow.id;
					sign.build_id = derivativeRecord.build_id;
					sign.parent_sha256 = inputSha256;
					sign.original_sha256 = baselineInfo.baseTargetSha256;
					sign.baseline_promoted = true;
				} catch (regErr) {
					// Rollback: unlink resolvedOut ONLY if file strictly matches staged identity & hash
					try {
						const currentStat = await fs.stat(resolvedOut).catch(() => null);
						if (currentStat) {
							const isSameIdentity =
								expectedIno !== 0 && currentStat.ino === expectedIno && currentStat.dev === expectedDev;
							const checkDiskHash = await hashFileSha256(resolvedOut).catch(() => null);
							if (checkDiskHash && checkDiskHash.toLowerCase() === stagedSha256.toLowerCase()) {
								if (isSameIdentity || expectedIno === 0) {
									await fs.unlink(resolvedOut).catch(() => undefined);
								}
							}
						}
					} catch {
						// ignore rollback error
					}
					throw new ToolError(
						`Artifact signed successfully but failed workflow derivative registration: ${regErr instanceof Error ? regErr.message : String(regErr)}. Rolled back published output.`,
					);
				}
			}
		} finally {
			await fs.rm(stageDir, { recursive: true, force: true }).catch(() => undefined);
		}

		const lines = [
			"// Android APK Signing Verification",
			`Signed Artifact: ${sign.output_path}`,
			`Size: ${sign.size} bytes`,
			`SHA256: ${sign.sha256}`,
			`Cryptographic Status: SIGNED & VERIFIED`,
			`Signature Schemes:`,
			`  • v1 (JAR Signature): ${sign.v1_signed ? "Verified" : "Not enabled/verified"}`,
			`  • v2 (APK Signature Scheme v2): ${sign.v2_signed ? "Verified" : "Not enabled/verified"}`,
			`  • v3 (APK Signature Scheme v3): ${sign.v3_signed ? "Verified" : "Not enabled/verified"}`,
			`Certificate SHA-256 Fingerprints:`,
		];

		for (const fp of sign.cert_fingerprints) {
			lines.push(`  • ${fp}`);
		}

		if (sign.lineage_verification) {
			lines.push(
				"",
				`Workflow Lineage Verification:`,
				`  • Status: PASS (${sign.lineage_verification.checked_patches_count} active baseline patches verified)`,
			);
		}
		if (sign.workflow_id && sign.build_id) {
			lines.push(
				`  • Workflow: ${sign.workflow_id}`,
				`  • Build ID: ${sign.build_id} (promoted to active baseline)`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "sign",
				status: "ok",
				summary: `Signed APK written to ${sign.output_path} (SHA256: ${sign.sha256})`,
				sign,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: verify
	// --------------------------------------------------------------------------
	private async handleVerify(
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		const rawIn = params.path;
		if (!rawIn) {
			throw new ToolError("Action 'verify' requires parameter 'path' (target APK)");
		}

		const resolvedIn = resolveReadPath(rawIn, this.session.cwd);
		try {
			await fs.stat(resolvedIn);
		} catch (err) {
			throw new ToolError(
				`Target APK not found: ${resolvedIn} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		const workerResult = await runReversePython<ApkVerifyResult>({
			cwd: this.session.cwd,
			sources: { "worker.py": apkArtifactWorkerPy },
			entry: "worker.py",
			request: {
				action: "verify",
				params: {
					path: resolvedIn,
					min_sdk_version: params.min_sdk_version ?? 21,
					max_sdk_version: params.max_sdk_version ?? 34,
					apksigner_path: params.apksigner_path
						? resolveReadPath(params.apksigner_path, this.session.cwd)
						: undefined,
					zipalign_path: params.zipalign_path
						? resolveReadPath(params.zipalign_path, this.session.cwd)
						: undefined,
					java_path: params.java_path ? resolveReadPath(params.java_path, this.session.cwd) : undefined,
					page_align_so: params.page_align_so ?? true,
				},
			},
			signal,
		});

		if (workerResult.status === "missing_dependency") {
			throw new ToolError(`Python 3.9+ runtime required for apk_artifact verify: ${workerResult.error}`);
		}
		if (workerResult.status === "error" || !workerResult.result) {
			throw new ToolError(
				`apk_artifact verify failed: ${workerResult.error ?? workerResult.stderr ?? "Unknown error"}`,
			);
		}

		const verify = workerResult.result;
		const inputSha256 = await hashFileSha256(resolvedIn);
		const baselineInfo = await resolveActiveWorkflowBaseline(this.session.cwd, {
			workflowId: params.workflow_id,
			targetPath: resolvedIn,
			targetSha256: inputSha256,
		});

		if (baselineInfo.baseline) {
			const lineageVer = await verifyActivePatches(resolvedIn, baselineInfo.activePatches);
			verify.lineage_verification = {
				status: lineageVer.status,
				active_patches_count: baselineInfo.activePatches.length,
				checked_patches_count: lineageVer.checked_patches_count,
				workflow_id: baselineInfo.workflow?.id,
				baseline_build_id: baselineInfo.baseline.build_id,
			};
		}
		const lines = [
			"// Android APK Container & Signature Verification",
			`Target: ${verify.path}`,
			`Size: ${verify.size} bytes`,
			`SHA256: ${verify.sha256}`,
			`Total Entries: ${verify.entry_count ?? 0}`,
			"",
			`Storage & Alignment Gates:`,
			`  • Status: ${verify.alignment?.ok ? "PASS" : "FAIL / MISALIGNED"}`,
		];

		if (verify.alignment?.checked_entries) {
			for (const e of verify.alignment.checked_entries) {
				lines.push(
					`  • ${e.name}: ${e.stored ? "STORED" : "COMPRESSED"}, offset=0x${e.offset.toString(16)}, ${e.aligned ? "ALIGNED" : "MISALIGNED"} (required: ${e.alignment_required}B)`,
				);
			}
		}
		if (verify.alignment?.issues && verify.alignment.issues.length > 0) {
			for (const iss of verify.alignment.issues) {
				lines.push(`    ! ${iss}`);
			}
		}

		lines.push("", `Cryptographic Signature Status:`);
		lines.push(`  • APK Signing Block (v2/v3): ${verify.signing_block_present ? "Present" : "Missing"}`);
		lines.push(
			`  • Verification Tool: ${verify.signature?.tool_available ? "Active" : "UNAVAILABLE (apksigner/jarsigner missing)"}`,
		);
		lines.push(`  • Cryptographically Verified: ${verify.signature?.verified ? "YES" : "NO"}`);

		if (verify.signature?.tool_available) {
			lines.push(`  • v1 Scheme: ${verify.signature.v1_scheme ? "Valid" : "Not valid / missing"}`);
			lines.push(`  • v2 Scheme: ${verify.signature.v2_scheme ? "Valid" : "Not valid / missing"}`);
			lines.push(`  • v3 Scheme: ${verify.signature.v3_scheme ? "Valid" : "Not valid / missing"}`);
			if (verify.signature.cert_fingerprints.length > 0) {
				lines.push(`  • Signer Certificate Fingerprints:`);
				for (const fp of verify.signature.cert_fingerprints) {
					lines.push(`    - ${fp}`);
				}
			}
		} else if (verify.signature?.notice) {
			lines.push(`  ! Notice: ${verify.signature.notice}`);
		}
		if (verify.lineage_verification) {
			lines.push("", `Workflow Baseline Lineage Verification:`);
			lines.push(
				`  • Status: ${verify.lineage_verification.status === "verified" ? "PASS" : "FAIL (active baseline patch dropped or corrupted)"}`,
				`  • Verified Patches: ${verify.lineage_verification.checked_patches_count} / ${verify.lineage_verification.active_patches_count} active patches`,
			);
			if (verify.lineage_verification.status !== "verified") {
				verify.verified = false;
				verify.status = "unverified_or_failed";
			}
		}

		lines.push("", `Final Verdict: ${verify.verified ? "VERIFIED VALID" : "UNVERIFIED OR FAILING"}`);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "verify",
				status: verify.status,
				summary: `Verification of ${path.basename(verify.path)}: alignment=${verify.alignment?.ok ? "pass" : "fail"}, signature=${verify.signature?.verified ? "verified" : "unverified"}`,
				verify,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: install_verify
	// --------------------------------------------------------------------------
	private async handleInstallVerify(
		params: ApkArtifactParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ApkArtifactDetails> & { details: ApkArtifactDetails }> {
		const rawIn = params.path;
		const pkg = params.package ?? params.package_name;
		const act = params.activity;
		const ser = params.serial;

		if (!rawIn) {
			throw new ToolError("Action 'install_verify' requires parameter 'path' (APK file path)");
		}
		if (!pkg) {
			throw new ToolError("Action 'install_verify' requires parameter 'package' (application package name)");
		}
		if (!act) {
			throw new ToolError("Action 'install_verify' requires parameter 'activity' (launch activity component)");
		}
		if (!ser) {
			throw new ToolError(
				"Action 'install_verify' requires explicit parameter 'serial' (selecting an implicit device is not permitted)",
			);
		}
		const resolvedIn = resolveReadPath(rawIn, this.session.cwd);
		try {
			await fs.stat(resolvedIn);
		} catch (err) {
			throw new ToolError(
				`Local APK not found: ${resolvedIn} (${err instanceof Error ? err.message : String(err)})`,
			);
		}
		const inputSha256 = await hashFileSha256(resolvedIn);
		const baselineInfo = await resolveActiveWorkflowBaseline(this.session.cwd, {
			workflowId: params.workflow_id,
			targetPath: resolvedIn,
			targetSha256: inputSha256,
		});

		if (baselineInfo.baseline && baselineInfo.activePatches.length > 0) {
			const verification = await verifyActivePatches(resolvedIn, baselineInfo.activePatches);
			if (verification.status !== "verified") {
				throw new ToolError(
					`apk_artifact install_verify rejected: Target APK drops active baseline patch '${verification.failed_patch_id}': ${verification.failure_reason}. Installation/promotion of unverified or broken artifacts is forbidden.`,
				);
			}
		}

		const resolvedDir = params.output_dir ? resolveToCwd(params.output_dir, this.session.cwd) : undefined;
		const resolvedShot = params.screenshot_path ? resolveToCwd(params.screenshot_path, this.session.cwd) : undefined;

		if (resolvedShot) {
			const existingShot = await fs.stat(resolvedShot).catch(() => null);
			if (existingShot) {
				throw new ToolError(
					`Screenshot destination file already exists at ${resolvedShot}. Overwriting existing files is not permitted.`,
				);
			}
		}
		const workerResult = await runReversePython<ApkInstallVerifyResult>({
			cwd: this.session.cwd,
			sources: { "worker.py": apkArtifactWorkerPy },
			entry: "worker.py",
			request: {
				action: "install_verify",
				params: {
					path: resolvedIn,
					package: pkg,
					activity: act,
					serial: ser,
					output_dir: resolvedDir,
					screenshot_path: resolvedShot,
					grant_permissions: params.grant_permissions ?? [],
					wait_seconds: params.wait_seconds ?? 10,
				},
			},
			signal,
		});

		if (workerResult.status === "missing_dependency") {
			throw new ToolError(`Python 3.9+ runtime required for apk_artifact install_verify: ${workerResult.error}`);
		}
		if (workerResult.status === "error" || !workerResult.result) {
			throw new ToolError(
				`apk_artifact install_verify failed: ${workerResult.error ?? workerResult.stderr ?? "Unknown error"}`,
			);
		}

		const iv = workerResult.result;
		const lines = [
			"// Android On-Device Installation & Launch Verification",
			`Package: ${iv.package}`,
			`Activity: ${iv.activity}`,
			`Device Serial: ${iv.device_serial ?? "(default connected device)"}`,
			`Local APK SHA256: ${iv.installed_apk_sha256}`,
			`Installed Build Identity: ${iv.hash_verified ? "CONFIRMED (device APK SHA256 matches local artifact exactly)" : "MISMATCH"}`,
			"",
			`Launch & Process Stability:`,
			`  • Status: ${iv.launch_status}`,
			`  • PID Sample 1 (t=+3s): ${iv.pid_sample_1 ?? "(dead / not found)"}`,
			`  • PID Sample 2 (t=+${params.wait_seconds ?? 10}s): ${iv.pid_sample_2 ?? "(dead / not found)"}`,
			`  • Current Window Focus: ${iv.focus || "(none)"}`,
		];

		if (iv.fatal_signatures.length > 0) {
			lines.push("", "Fatal Logcat Signatures Detected:");
			for (const fatal of iv.fatal_signatures) {
				lines.push(`  ! ${fatal}`);
			}
		} else {
			lines.push(`  • Logcat Fatal Signatures: None observed`);
		}

		if (iv.screenshot_path) {
			lines.push(`  • Screenshot Captured: ${iv.screenshot_path}`);
		}
		if (iv.log_path) {
			lines.push(`  • Process Log Captured: ${iv.log_path}`);
		}
		lines.push(
			"",
			`IMPORTANT NOTICE:`,
			`  • ${iv.notice}`,
			`  • Feature Verified: NO (automated launch check proves process stability only; manual/functional verification of modified feature logic is mandatory)`,
		);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "install_verify",
				status: iv.status,
				summary: `Install verification for ${iv.package}: launch=${iv.launch_status}, hash_verified=${iv.hash_verified}`,
				install_verify: iv,
			},
		};
	}
}
