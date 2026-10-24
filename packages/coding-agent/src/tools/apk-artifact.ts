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

		// Resolve dex_files paths
		const dexFilesMap: Record<string, string> = {};
		if (params.dex_files !== undefined) {
			if (typeof params.dex_files !== "object" || params.dex_files === null || Array.isArray(params.dex_files)) {
				throw new ToolError("Parameter 'dex_files' must be an object mapping entry names to file paths");
			}
			for (const [k, v] of Object.entries(params.dex_files)) {
				if (typeof v !== "string" || !v.trim()) {
					throw new ToolError(`Invalid entry in dex_files map for key '${k}': path must be a non-empty string`);
				}
				dexFilesMap[k] = resolveReadPath(v.trim(), this.session.cwd);
			}
		}
		if (params.dex_path) {
			dexFilesMap["classes.dex"] = resolveReadPath(params.dex_path, this.session.cwd);
		}

		const secretEnv: Record<string, string> = {};
		if (params.ks_pass_env && process.env[params.ks_pass_env] !== undefined) {
			secretEnv[params.ks_pass_env] = process.env[params.ks_pass_env]!;
		}
		if (params.key_pass_env && process.env[params.key_pass_env] !== undefined) {
			secretEnv[params.key_pass_env] = process.env[params.key_pass_env]!;
		}

		const workerResult = await runReversePython<ApkRepackResult>({
			cwd: this.session.cwd,
			sources: { "worker.py": apkArtifactWorkerPy },
			entry: "worker.py",
			env: secretEnv,
			request: {
				action: "repack",
				params: {
					path: resolvedIn,
					output_path: resolvedOut,
					dex_files: dexFilesMap,
					strip_signatures: params.strip_signatures ?? true,
					page_align_so: params.page_align_so ?? true,
					sign: params.sign ?? false,
					keystore_path: params.keystore_path
						? resolveReadPath(params.keystore_path, this.session.cwd)
						: undefined,
					key_alias: params.key_alias,
					ks_pass_env: params.ks_pass_env,
					ks_pass_file: params.ks_pass_file ? resolveReadPath(params.ks_pass_file, this.session.cwd) : undefined,
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

		const repack = workerResult.result;
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

		const secretEnv: Record<string, string> = {};
		if (params.ks_pass_env && process.env[params.ks_pass_env] !== undefined) {
			secretEnv[params.ks_pass_env] = process.env[params.ks_pass_env]!;
		}
		if (params.key_pass_env && process.env[params.key_pass_env] !== undefined) {
			secretEnv[params.key_pass_env] = process.env[params.key_pass_env]!;
		}

		const workerResult = await runReversePython<ApkSignResult>({
			cwd: this.session.cwd,
			sources: { "worker.py": apkArtifactWorkerPy },
			entry: "worker.py",
			env: secretEnv,
			request: {
				action: "sign",
				params: {
					path: resolvedIn,
					output_path: resolvedOut,
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

		const sign = workerResult.result;
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
