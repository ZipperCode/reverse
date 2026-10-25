// SPDX-License-Identifier: MIT
/**
 * Multi-Engine Reverse Engineering Deobfuscation Tool.
 *
 * Provides status probing and bounded deobfuscation execution across:
 * - jadx: Arsylk/jadx-string-decrypt plugin (constant folding, string decryption, reflection de-indirection)
 * - d810-ng: IDA Pro 9+ Hex-Rays microcode MBA rules and control-flow unflatteners
 * - simplify: CalebFenton/simplify Dalvik virtual execution with bounded method/instruction visits
 * - msynth: mrphrazer/msynth MBA AST synthesis and formal Z3 SMT equivalence verification
 * - blackdex: ZhengHaiPeng dynamic ART unpacker APK deployment, execution launch, and DEX retrieval
 *
 * Research-only references (D810G, vmp-devirt) are intentionally kept separate from production execution.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type {
	AgentTool,
	AgentToolContext,
	AgentToolResult,
	AgentToolUpdateCallback,
	ToolApprovalDecision,
} from "@reverse/agent";
import { type } from "@reverse/reversetype";
import type { OutputMeta } from "@reverse/tui/tools/output-meta";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { $which, prompt, WhichCachePolicy } from "@reverse/utils";
import deobfuscateDescription from "../prompts/tools/deobfuscate.md" with { type: "text" };
import { resolveProtectionTool } from "../extensibility/protection-toolchain";
import { parseAxml, ZipParser } from "./android-package-inspect";
import { appendArtifactReference, saveArtifactText } from "./gh-common";
import type { ToolSession } from "./index";
import { resolveReadPath, resolveToCwd } from "./path-utils";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";
import { toolResult } from "./tool-result";
import {
	computeStreamingHash,
	getFileMetadata,
	runSafeSubprocess,
	safePublishArtifact,
	type ArtifactMetadata,
} from "./vmp-common";

// Text assets for Python workers
import msynthWorkerSource from "./deobfuscate-msynth-worker.py" with { type: "text" };
import d810WorkerSource from "./deobfuscate-d810-worker.py" with { type: "text" };

// ============================================================================
// Parameter Schema
// ============================================================================

const deobfuscateSchema = type({
	action: type
		.enumerated("status", "analyze")
		.describe("Action: 'status' to probe engine availability and environments; 'analyze' to execute deobfuscation"),
	"backend?": type
		.enumerated("jadx", "d810-ng", "simplify", "msynth", "blackdex")
		.describe(
			"Deobfuscation backend engine: 'jadx' (jadx-string-decrypt), 'd810-ng' (IDA 9+ Hex-Rays), 'simplify' (Dalvik virtual execution), 'msynth' (MBA AST synthesis & SMT equivalence), or 'blackdex' (Android device dynamic DEX unpacker). Required for 'analyze'",
		),
	"path?": type("string").describe("Path to target APK, DEX, native binary, or IDB database file on disk"),
	"out?": type("string").describe("Destination directory or file path for deobfuscated artifacts and report"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 120, max 600)"),

	// msynth parameters
	"expression?": type("string").describe(
		"msynth: MBA mathematical/bitwise expression string to simplify (e.g. '(x ^ y) + 2 * (x & y)'). Safe parser, no eval",
	),
	"bit_width?": type("number.integer").describe(
		"msynth: explicit bit-width for variables (8, 16, 32, 64; default 32)",
	),
	"variables?": type("string[]").describe("msynth: variable names present in the expression (e.g. ['x', 'y'])"),
	"mode?": type
		.enumerated("ast", "synthesis")
		.describe(
			"msynth: 'ast' for rule-based/oracle subtree simplification; 'synthesis' for stochastic program synthesis (default 'ast')",
		),
	"verify_smt?": type("boolean").describe("msynth: verify semantic equivalence using Z3 SMT solver (default true)"),

	// d810-ng parameters
	"function?": type("string | number").describe(
		"d810-ng: target function address in hex (e.g. '0x401000') or symbol name",
	),
	"rules?": type("string[]").describe(
		"d810-ng: microcode rules or categories to activate (e.g. ['mba', 'ollvm', 'cst_simplification', 'predicates'])",
	),
	"unflattener?": type
		.enumerated("ollvm", "tigress", "approov", "hodur", "generic", "none")
		.describe("d810-ng: control flow unflattener to activate (default 'ollvm')"),
	"config_json?": type("string").describe("d810-ng: optional JSON rule configuration string or config file path"),

	// simplify parameters
	"include_types?": type("string[]").describe(
		"simplify: type/class regex or prefix filter to deobfuscate (e.g. ['Lcom/example/.*'])",
	),
	"exclude_types?": type("string[]").describe("simplify: type/class regex or prefix filter to exclude"),
	"max_address_visits?": type("number.integer >= 1").describe(
		"simplify: max visits per instruction address (default 10000)",
	),
	"max_method_visits?": type("number.integer >= 1").describe("simplify: max visits per method (default 1000)"),
	"max_call_depth?": type("number.integer >= 1").describe("simplify: max call stack depth (default 50)"),

	// jadx parameters
	"class_filter?": type("string").describe("jadx: target class FQCN or pattern to decompile"),
	"fold_consts?": type("boolean").describe(
		"jadx string-decrypt: fold opaque compile-time numeric/boolean constants (default true)",
	),
	"fold_helper_calls?": type("boolean").describe("jadx string-decrypt: fold pure helper calls (default true)"),
	"decrypt_strings?": type("boolean").describe(
		"jadx string-decrypt: decrypt resolvable cipher string calls (default true)",
	),
	"deindirect_reflection?": type("boolean").describe(
		"jadx string-decrypt: resolve reflective calls to direct calls (default true)",
	),
	"cleanup_reflection?": type("boolean").describe(
		"jadx string-decrypt: clean dead reflective scaffolding (default true)",
	),
	"comments?": type("boolean").describe(
		"jadx string-decrypt: add method comments listing decrypted strings (default true)",
	),
	"cipher?": type("string").describe(
		"jadx string-decrypt: JCE cipher transformation (default 'AES/ECB/PKCS5Padding')",
	),
	"key_tail_len?": type("number.integer >= 0").describe(
		"jadx string-decrypt: trailing key bytes appended to ciphertext (default 16)",
	),
	"decryptor_class?": type("string").describe("jadx string-decrypt: restrict decryptor to specific class name"),
	"decryptor_desc?": type("string").describe(
		"jadx string-decrypt: descriptor decryptor must match (default '([B)Ljava/lang/String;')",
	),
	"max_table_size?": type("number.integer >= 1").describe(
		"jadx string-decrypt: cap on reconstructed static array size (default 4000000)",
	),

	// blackdex parameters
	"blackdex_action?": type
		.enumerated("auto", "install", "launch", "collect")
		.describe(
			"blackdex: lifecycle action: 'auto' (install->launch->poll/collect), 'install', 'launch', or 'collect' (retrieve dumped DEX)",
		),
	"package_name?": type("string").describe("blackdex: target application package name on device to unpack"),
	"device?": type("string").describe("blackdex: ADB target device serial"),
	"wait_timeout_seconds?": type("number.integer >= 5").describe(
		"blackdex: seconds to wait for user interaction and DEX dump generation (default 60)",
	),
	"auto_launch?": type("boolean").describe(
		"blackdex: attempt to launch BlackDex / target package via ADB (default true)",
	),
	"apk_path?": type("string").describe("blackdex: local path to BlackDex APK to install if missing from device"),
});

export type DeobfuscateParams = typeof deobfuscateSchema.infer;
export type DeobfuscateBackend = NonNullable<DeobfuscateParams["backend"]>;

// ============================================================================
// Result Details Interfaces
// ============================================================================

export interface BackendStatusInfo {
	backend: DeobfuscateBackend;
	installed: boolean;
	compatible: boolean;
	canStart: boolean;
	version?: string;
	path?: string;
	setupCommand: string;
	details: Record<string, unknown>;
	missingDependencies: string[];
}

export interface DeobfuscateStatusDetails {
	action: "status";
	platform: NodeJS.Platform;
	backends: Record<DeobfuscateBackend, BackendStatusInfo>;
	meta?: OutputMeta;
}

export interface DeobfuscateAnalyzeDetails {
	action: "analyze";
	backend: DeobfuscateBackend;
	success: boolean;
	inputPath?: string;
	inputHash?: string;
	inputBytes?: number;
	durationMs: number;
	artifacts: ArtifactMetadata[];
	metadata: Record<string, unknown>;
	interventionRequired?: boolean;
	userInstructions?: string;
	meta?: OutputMeta;
	semanticVerification?: {
		verified: boolean;
		equivalent: boolean | null;
		solver?: string;
		notes?: string;
	};
	complexityReduction?: {
		metric: string;
		before: number;
		after: number;
		reductionRatio: number;
	};
}

export type DeobfuscateDetails = DeobfuscateStatusDetails | DeobfuscateAnalyzeDetails;

// ============================================================================
// Path & Destination Validation Helpers
// ============================================================================

function validateDestinationPath(destPath: string, inputPath?: string): string {
	const resolvedDest = path.resolve(destPath);
	if (inputPath && resolvedDest === path.resolve(inputPath)) {
		throw new ToolError(`Destination path cannot be the same as input target: ${destPath}`);
	}
	if (fs.existsSync(resolvedDest)) {
		throw new ToolError(`Destination path already exists, refusing to overwrite: ${destPath}`);
	}
	return resolvedDest;
}

function checkDexMagic(headBuf: Buffer | Uint8Array): boolean {
	if (headBuf.length < 4) return false;
	return (
		headBuf[0] === 0x64 && // 'd'
		headBuf[1] === 0x65 && // 'e'
		headBuf[2] === 0x78 && // 'x'
		headBuf[3] === 0x0a // '\n'
	);
}
async function ensureJadxPluginRegistered(
	jadxBin: string,
	pluginJarPath: string,
	cwd: string,
	signal?: AbortSignal,
): Promise<boolean> {
	const isStringDecryptActive = (out: string | null | undefined): boolean => {
		if (!out) return false;
		const lines = out.split(/\r?\n/);
		return lines.some(l => {
			const lower = l.toLowerCase();
			return lower.includes("string-decrypt") && !lower.includes("(disabled)");
		});
	};

	// 1. Check if plugin is ALREADY recognized by JADX (prevent duplicate plugin collision)
	const initialCheck = await runSafeSubprocess({
		binary: jadxBin,
		args: ["plugins", "--list-all"],
		cwd,
		timeoutMs: 10000,
		signal,
	}).catch(() => null);

	if (initialCheck && initialCheck.exitCode === 0 && isStringDecryptActive(initialCheck.stdout)) {
		return true;
	}

	// 2. Try registering cleanly via JADX CLI plugin installer
	const installRes = await runSafeSubprocess({
		binary: jadxBin,
		args: ["plugins", "--install-jar", pluginJarPath],
		cwd,
		timeoutMs: 15000,
		signal,
	}).catch(() => null);

	if (installRes && (installRes.exitCode === 0 || isStringDecryptActive(installRes.stdout))) {
		const verifyRes = await runSafeSubprocess({
			binary: jadxBin,
			args: ["plugins", "--list-all"],
			cwd,
			timeoutMs: 10000,
			signal,
		}).catch(() => null);
		if (verifyRes && verifyRes.exitCode === 0 && isStringDecryptActive(verifyRes.stdout)) {
			return true;
		}
	}

	// 3. Fallback: only deploy to dropin directories if CLI registration did not load it
	const candidateDropinDirs = [
		path.join(os.homedir(), "Library", "Application Support", "jadx", "plugins", "dropins"),
		path.join(os.homedir(), ".config", "jadx", "plugins", "dropins"),
		path.join(os.homedir(), ".local", "share", "jadx", "plugins", "dropins"),
		path.join(process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming"), "jadx", "plugins", "dropins"),
		path.join(
			process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming"),
			"skylot",
			"jadx",
			"plugins",
			"dropins",
		),
	];

	for (const dDir of candidateDropinDirs) {
		try {
			await fs.promises.mkdir(dDir, { recursive: true });
			const targetJar = path.join(dDir, path.basename(pluginJarPath));
			if (!fs.existsSync(targetJar)) {
				await fs.promises.copyFile(pluginJarPath, targetJar);
			}
		} catch {}
	}

	const recheckRes = await runSafeSubprocess({
		binary: jadxBin,
		args: ["plugins", "--list-all"],
		cwd,
		timeoutMs: 10000,
		signal,
	}).catch(() => null);

	return Boolean(recheckRes && recheckRes.exitCode === 0 && isStringDecryptActive(recheckRes.stdout));
}

function hasExactPackage(pmOutput: string, pkgName: string): boolean {
	const lines = pmOutput.split(/\r?\n/);
	return lines.some(l => l.trim() === `package:${pkgName}` || l.trim() === pkgName);
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class DeobfuscateTool implements AgentTool<typeof deobfuscateSchema, DeobfuscateDetails> {
	readonly name = "deobfuscate";
	readonly label = "Deobfuscate";
	readonly summary = "Multi-engine deobfuscation for DEX, native microcode, and MBA expressions";
	readonly description: string;
	readonly parameters = deobfuscateSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	readonly approval = (args: unknown): ToolApprovalDecision => {
		if (typeof args === "object" && args !== null && "action" in args) {
			const act = (args as { action?: unknown }).action;
			if (typeof act === "string" && act === "status") {
				return "read";
			}
		}
		return "exec";
	};

	readonly formatApprovalDetails = (args: unknown): string[] => {
		const lines: string[] = [];
		if (typeof args === "object" && args !== null) {
			if ("action" in args && typeof args.action === "string") {
				lines.push(`Action: ${args.action}`);
			}
			if ("backend" in args && typeof args.backend === "string") {
				lines.push(`Backend: ${args.backend}`);
			}
			if ("path" in args && typeof args.path === "string") {
				lines.push(`Target: ${args.path}`);
			}
			if ("expression" in args && typeof args.expression === "string") {
				lines.push(`Expression: ${args.expression}`);
			}
			if ("function" in args && typeof args.function === "string") {
				lines.push(`Function: ${args.function}`);
			}
			if ("package_name" in args && typeof args.package_name === "string") {
				lines.push(`Package: ${args.package_name}`);
			}
		}
		return lines;
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(deobfuscateDescription);
	}

	async execute(
		_toolCallId: string,
		params: DeobfuscateParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<DeobfuscateDetails>,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		throwIfAborted(signal);

		if (params.action === "status") {
			return this.executeStatus(params, signal);
		}

		if (!params.backend) {
			throw new ToolError("Parameter 'backend' is required for action 'analyze'.");
		}

		// Plan Mode Check for 'analyze' action
		const planMode = this.session.getPlanModeState?.();
		if (planMode?.enabled) {
			throw new ToolError(
				"Plan mode: deobfuscate 'analyze' executes external reverse-engineering tools and transforms binaries. Status checks are allowed in plan mode.",
			);
		}

		switch (params.backend) {
			case "msynth":
				return this.executeMsynth(params, signal);
			case "jadx":
				return this.executeJadx(params, signal);
			case "d810-ng":
				return this.executeD810(params, signal);
			case "simplify":
				return this.executeSimplify(params, signal);
			case "blackdex":
				return this.executeBlackDex(params, signal);
			default:
				throw new ToolError(`Unsupported deobfuscation backend: ${String(params.backend)}`);
		}
	}

	// ========================================================================
	// Status Probing
	// ========================================================================

	private async executeStatus(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		const which = (cmd: string) => $which(cmd, { cache: WhichCachePolicy.Bypass });
		const platform = process.platform;
		const targetBackend = params.backend;

		const probeJadx = async (): Promise<BackendStatusInfo> => {
			const jadxResolved = resolveProtectionTool("jadx-string-decrypt");
			const jadxHostBin = which("jadx");
			const pluginJar = jadxResolved?.path ?? null;
			let pluginLoaded = false;
			if (jadxHostBin && pluginJar && fs.existsSync(pluginJar)) {
				const listRes = await runSafeSubprocess({
					binary: jadxHostBin,
					args: ["plugins", "--list-all"],
					cwd: this.session.cwd,
					timeoutMs: 5000,
					signal,
				}).catch(() => null);
				const lower = listRes?.stdout.toLowerCase();
				pluginLoaded = Boolean(
					lower && lower.includes("string-decrypt") && !lower.includes("string-decrypt (disabled)"),
				);
			}
			const pluginInstalled = (jadxResolved?.installed ?? false) || pluginLoaded;
			const cliInstalled = jadxHostBin !== null;
			const canStart = pluginInstalled && cliInstalled;
			return {
				backend: "jadx",
				installed: canStart,
				compatible: true,
				canStart,
				version: jadxResolved?.version ?? "1.14.0",
				path: jadxResolved?.path ?? jadxHostBin ?? undefined,
				setupCommand: "reverse setup reverse jadx-string-decrypt --execute",
				details: {
					jadxCli: jadxHostBin ?? "not_in_path",
					pluginJar: pluginJar ?? "not_resolved",
					pluginLoaded,
					pluginInstalled,
					cliInstalled,
				},
				missingDependencies: [
					...(cliInstalled ? [] : ["jadx CLI"]),
					...(pluginInstalled ? [] : ["jadx-string-decrypt plugin JAR"]),
				],
			};
		};

		const probeD810 = async (): Promise<BackendStatusInfo> => {
			const d810Resolved = resolveProtectionTool("d810-ng");
			const idat64Bin = which("idat64") ?? which("idat") ?? which("ida64");
			const d810Installed = d810Resolved?.installed ?? false;
			return {
				backend: "d810-ng",
				installed: d810Installed,
				compatible: platform !== "win32" || true,
				canStart: d810Installed && idat64Bin !== null,
				version: d810Resolved?.version ?? "0.6.6",
				path: d810Resolved?.path,
				setupCommand: "reverse setup reverse d810-ng --execute",
				details: {
					idaBinary: idat64Bin ?? "not_in_path (IDA Pro 9+ required)",
					d810Package: d810Resolved?.path ?? "not_installed",
					packageDir: d810Resolved?.metadata?.packageDir,
				},
				missingDependencies: [
					...(idat64Bin ? [] : ["idat64/ida (IDA Pro 9+)"]),
					...(d810Installed ? [] : ["d810-ng Python package"]),
				],
			};
		};

		const probeSimplify = async (): Promise<BackendStatusInfo> => {
			const simplifyResolved = resolveProtectionTool("simplify");
			const javaBin = which("java");
			let javaVersion: string | undefined;
			let hasValidJava = false;
			if (javaBin) {
				const check = await runSafeSubprocess({
					binary: javaBin,
					args: ["-version"],
					timeoutMs: 3000,
					signal,
				}).catch(() => null);
				if (check && check.exitCode === 0) {
					const verOut = check.stderr || check.stdout;
					javaVersion = verOut.split("\n")[0]?.trim();
					hasValidJava = Boolean(javaVersion);
				}
			}
			const actualJarPath =
				(simplifyResolved?.metadata?.jarPath as string | undefined) ??
				(simplifyResolved?.path.endsWith(".jar") ? simplifyResolved.path : undefined);
			const simplifyInstalled = Boolean(actualJarPath && fs.existsSync(actualJarPath));
			return {
				backend: "simplify",
				installed: simplifyInstalled && hasValidJava,
				compatible: true,
				canStart: simplifyInstalled && hasValidJava,
				version: simplifyResolved?.version ?? "1.3.0",
				path: actualJarPath ?? simplifyResolved?.path,
				setupCommand: "reverse setup reverse simplify --execute",
				details: {
					javaRuntime: javaBin ?? "not_in_path",
					javaVersion: javaVersion ?? "unreachable_or_stub",
					jarPath: actualJarPath ?? "not_installed",
				},
				missingDependencies: [
					...(hasValidJava ? [] : ["java (JRE/JDK 8+)"]),
					...(simplifyInstalled ? [] : ["simplify.jar"]),
				],
			};
		};

		const probeMsynth = async (): Promise<BackendStatusInfo> => {
			const msynthResolved = resolveProtectionTool("msynth");
			const hostPy = which("python3") ?? which("python");
			const msynthInstalled = msynthResolved?.installed ?? false;
			return {
				backend: "msynth",
				installed: msynthInstalled,
				compatible: true,
				canStart: msynthInstalled,
				version: msynthResolved?.version ?? "0.1.0",
				path: msynthResolved?.path ?? hostPy ?? undefined,
				setupCommand: "reverse setup reverse msynth --execute",
				details: {
					python: msynthResolved?.path ?? hostPy ?? "not_in_path",
					managedVenv: msynthResolved?.installed ?? false,
				},
				missingDependencies: [
					...(hostPy ? [] : ["python3"]),
					...(msynthInstalled ? [] : ["msynth managed environment (miasm + z3)"]),
				],
			};
		};

		const probeBlackdex = async (): Promise<BackendStatusInfo> => {
			const blackdexResolved = resolveProtectionTool("blackdex");
			const adbBin = which("adb");
			let adbDevices: string[] = [];
			if (adbBin) {
				const check = await runSafeSubprocess({
					binary: adbBin,
					args: ["devices"],
					timeoutMs: 5000,
					signal,
				}).catch(() => null);
				if (check && check.exitCode === 0) {
					const lines = check.stdout.split("\n").slice(1);
					adbDevices = lines
						.map(l => l.trim())
						.filter(l => l && !l.startsWith("*") && l.includes("\tdevice"))
						.map(l => l.split("\t")[0]!);
				}
			}
			const blackdexApkInstalled = blackdexResolved?.installed ?? false;
			return {
				backend: "blackdex",
				installed: blackdexApkInstalled,
				compatible: true,
				canStart: blackdexApkInstalled && adbBin !== null && adbDevices.length > 0,
				version: blackdexResolved?.version ?? "3.2.0",
				path: blackdexResolved?.path,
				setupCommand: "reverse setup reverse blackdex --execute",
				details: {
					adb: adbBin ?? "not_in_path",
					apkPath: blackdexResolved?.path ?? "not_installed",
					connectedDevices: adbDevices,
					deviceConnected: adbDevices.length > 0,
				},
				missingDependencies: [
					...(adbBin ? [] : ["adb (Android Platform Tools)"]),
					...(blackdexApkInstalled ? [] : ["BlackDex APK asset"]),
					...(adbDevices.length > 0 ? [] : ["connected Android device or emulator"]),
				],
			};
		};

		const backends: Record<DeobfuscateBackend, BackendStatusInfo> = {} as Record<
			DeobfuscateBackend,
			BackendStatusInfo
		>;

		if (targetBackend) {
			switch (targetBackend) {
				case "jadx":
					backends.jadx = await probeJadx();
					break;
				case "d810-ng":
					backends["d810-ng"] = await probeD810();
					break;
				case "simplify":
					backends.simplify = await probeSimplify();
					break;
				case "msynth":
					backends.msynth = await probeMsynth();
					break;
				case "blackdex":
					backends.blackdex = await probeBlackdex();
					break;
			}
		} else {
			backends.jadx = await probeJadx();
			backends["d810-ng"] = await probeD810();
			backends.simplify = await probeSimplify();
			backends.msynth = await probeMsynth();
			backends.blackdex = await probeBlackdex();
		}

		const details: DeobfuscateStatusDetails = {
			action: "status",
			platform,
			backends,
		};

		const selected = targetBackend ? backends[targetBackend] : null;

		let summaryText = `# Deobfuscate Engine Status (${platform})\n\n`;
		if (selected) {
			summaryText += `## Backend: ${selected.backend}\n`;
			summaryText += `- Installed: ${selected.installed ? "Yes" : "No"}\n`;
			summaryText += `- Ready to Start: ${selected.canStart ? "Yes" : "No"}\n`;
			summaryText += `- Version: ${selected.version ?? "N/A"}\n`;
			summaryText += `- Primary Path: ${selected.path ?? "(none)"}\n`;
			if (selected.missingDependencies.length > 0) {
				summaryText += `- Missing: ${selected.missingDependencies.join(", ")}\n`;
				summaryText += `- Setup Command: \`${selected.setupCommand}\`\n`;
			}
		} else {
			for (const b of Object.values(backends)) {
				const statusBadge = b.canStart ? "READY" : b.installed ? "PARTIAL" : "MISSING";
				summaryText += `### [${statusBadge}] ${b.backend} (v${b.version ?? "?"})\n`;
				summaryText += `- Path: ${b.path ?? "(none)"}\n`;
				if (b.missingDependencies.length > 0) {
					summaryText += `- Missing: ${b.missingDependencies.join(", ")} (Run \`${b.setupCommand}\`)\n`;
				}
			}
		}
		return toolResult(details).text(summaryText).done();
	}

	// ========================================================================
	// msynth MBA Simplification
	// ========================================================================

	private async executeMsynth(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		const expression = params.expression?.trim();
		if (!expression) {
			throw new ToolError("msynth requires parameter 'expression' containing the MBA expression to simplify.");
		}

		const bitWidth = params.bit_width ?? 32;
		if (![8, 16, 32, 64].includes(bitWidth)) {
			throw new ToolError(`msynth bit_width must be 8, 16, 32, or 64 (got ${bitWidth})`);
		}

		const startTime = Date.now();
		const timeoutSec = Math.min(Math.max(params.timeout ?? 60, 5), 300);

		// Resolve msynth Python interpreter if managed
		const msynthResolved = resolveProtectionTool("msynth");
		const pyPath = msynthResolved?.installed ? msynthResolved.path : undefined;

		const pyRes = await runReversePython({
			cwd: this.session.cwd,
			sources: {
				"msynth_worker.py": msynthWorkerSource,
			},
			entry: "msynth_worker.py",
			request: {
				expression,
				bit_width: bitWidth,
				variables: params.variables,
				mode: params.mode ?? "ast",
				verify_smt: params.verify_smt ?? true,
			},
			pythonPath: pyPath,
			signal,
			timeoutMs: timeoutSec * 1000,
		});

		const durationMs = Date.now() - startTime;

		if (pyRes.status !== "ok" || !pyRes.result) {
			const err = pyRes.error || pyRes.stderr || "msynth execution failed";
			throw new ToolError(`msynth execution failed: ${err}`);
		}

		if (typeof pyRes.result !== "object" || pyRes.result === null) {
			throw new ToolError("msynth worker returned non-object payload");
		}

		const res = pyRes.result as {
			status?: string;
			error?: string;
			original?: string;
			simplified?: string;
			bit_width?: number;
			variables?: string[];
			complexity_reduction?: {
				original_nodes: number;
				simplified_nodes: number;
				nodes_eliminated: number;
				reduction_ratio: number;
			};
			smt_verification?: {
				verified: boolean;
				equivalent: boolean | null;
				solver?: string;
				counterexample?: Record<string, string> | null;
				reason?: string;
			};
			backend?: Record<string, unknown>;
		};

		if (res.status === "missing_dependency") {
			throw new ToolError(
				res.error ?? "Required msynth engine dependency missing. Run 'reverse setup reverse msynth --execute'.",
			);
		}
		if (res.status !== "ok" || !res.original || !res.simplified) {
			throw new ToolError(`msynth simplification error: ${res.error ?? "unknown error"}`);
		}
		const artifacts: ArtifactMetadata[] = [];
		const reportContent = JSON.stringify(res, null, 2);

		if (params.out) {
			const resolvedOut = path.resolve(resolveToCwd(params.out, this.session.cwd));
			const tempOutDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "msynth_out_"));
			const tempOutFile = path.join(tempOutDir, "msynth_report.json");
			await fs.promises.writeFile(tempOutFile, reportContent, "utf-8");
			try {
				const publishedMeta = await safePublishArtifact(tempOutFile, resolvedOut);
				artifacts.push(publishedMeta);
			} finally {
				await fs.promises.rm(tempOutDir, { recursive: true, force: true }).catch(() => null);
			}
		}

		const artifactId = await saveArtifactText(this.session, "deobfuscate_msynth", reportContent).catch(
			() => undefined,
		);

		const details: DeobfuscateAnalyzeDetails = {
			action: "analyze",
			backend: "msynth",
			success: true,
			durationMs,
			artifacts,
			metadata: {
				original: res.original,
				simplified: res.simplified,
				bitWidth: res.bit_width ?? bitWidth,
				variables: res.variables ?? [],
				engine: res.backend?.engine ?? "unknown",
			},
			semanticVerification: {
				verified: res.smt_verification?.verified ?? false,
				equivalent: res.smt_verification?.equivalent ?? null,
				solver: res.smt_verification?.solver,
				notes: res.smt_verification?.reason,
			},
			complexityReduction: res.complexity_reduction
				? {
						metric: "ast_nodes",
						before: res.complexity_reduction.original_nodes,
						after: res.complexity_reduction.simplified_nodes,
						reductionRatio: res.complexity_reduction.reduction_ratio,
					}
				: undefined,
		};

		let text = `# msynth MBA Simplification Report\n\n`;
		text += `- **Original**: \`${res.original}\`\n`;
		text += `- **Simplified**: \`${res.simplified}\`\n`;
		text += `- **Bit Width**: ${res.bit_width ?? bitWidth}-bit\n`;
		text += `- **Variables**: ${res.variables?.join(", ") || "(none)"}\n`;
		text += `- **Engine**: ${String(res.backend?.engine ?? "unknown")}\n`;
		if (res.complexity_reduction) {
			text += `- **Complexity Reduction**: ${res.complexity_reduction.original_nodes} nodes -> ${res.complexity_reduction.simplified_nodes} nodes (${res.complexity_reduction.nodes_eliminated} eliminated, ratio ${res.complexity_reduction.reduction_ratio})\n`;
		}

		if (res.smt_verification) {
			if (res.smt_verification.verified && res.smt_verification.equivalent === true) {
				text += `- **SMT Equivalence**: PROVEN EQUIVALENT via ${res.smt_verification.solver} (unsat)\n`;
			} else if (res.smt_verification.verified && res.smt_verification.equivalent === false) {
				text += `- **SMT Equivalence**: NOT EQUIVALENT! Counterexample: ${JSON.stringify(res.smt_verification.counterexample)}\n`;
			} else {
				text += `- **SMT Equivalence**: Inconclusive (${res.smt_verification.reason ?? "solver not installed"})\n`;
			}
		}

		if (artifactId) {
			text = appendArtifactReference(text, artifactId, "msynth Simplification JSON Report");
		}
		return toolResult(details).text(text).done();
	}

	// ========================================================================
	// jadx-string-decrypt
	// ========================================================================

	private async executeJadx(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		if (!params.path) {
			throw new ToolError("jadx backend requires 'path' specifying target APK or DEX file.");
		}

		const resolvedTarget = resolveReadPath(params.path, this.session.cwd);
		const stat = await fs.promises.stat(resolvedTarget).catch((err: unknown) => {
			const msg = err instanceof Error ? err.message : String(err);
			throw new ToolError(`Target APK/DEX file not found: ${resolvedTarget} (${msg})`);
		});
		if (!stat.isFile() || stat.size === 0) {
			throw new ToolError(`Target is not a valid non-empty file: ${resolvedTarget}`);
		}
		const outDir = params.out
			? resolveToCwd(params.out, this.session.cwd)
			: path.join(this.session.cwd, "artifacts", "deobfuscate", `jadx_${Date.now()}`);

		validateDestinationPath(outDir, resolvedTarget);
		const inputHashRes = await computeStreamingHash(resolvedTarget);

		const jadxBin = $which("jadx", { cache: WhichCachePolicy.Bypass });
		if (!jadxBin) {
			throw new ToolError(
				"jadx executable not found in PATH. Please install jadx via 'brew install jadx' or 'reverse setup reverse jadx --execute'.",
			);
		}

		const jadxPluginResolved = resolveProtectionTool("jadx-string-decrypt");
		const pluginJarPath = jadxPluginResolved?.installed ? jadxPluginResolved.path : null;
		if (!pluginJarPath) {
			throw new ToolError(
				"jadx-string-decrypt plugin JAR not resolved. Please run 'reverse setup reverse jadx-string-decrypt --execute'.",
			);
		}

		const stageDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "jadx_stage_"));
		// Ensure JADX dropins directory has the plugin and verify active registration
		const isRegistered = await ensureJadxPluginRegistered(jadxBin, pluginJarPath, this.session.cwd, signal);
		if (!isRegistered) {
			throw new ToolError(
				`Failed to load jadx-string-decrypt plugin into JADX. Please run 'jadx plugins --install-jar ${pluginJarPath}'.`,
			);
		}
		const timeoutSec = Math.min(Math.max(params.timeout ?? 180, 5), 600);
		const startTime = Date.now();

		const jadxArgs: string[] = ["-d", stageDir];

		// Plugin options
		jadxArgs.push("-P", `string-decrypt.enabled=true`);
		jadxArgs.push("-P", `string-decrypt.fold-consts=${params.fold_consts ?? true}`);
		jadxArgs.push("-P", `string-decrypt.fold-helper-calls=${params.fold_helper_calls ?? true}`);
		jadxArgs.push("-P", `string-decrypt.decrypt-strings=${params.decrypt_strings ?? true}`);
		jadxArgs.push("-P", `string-decrypt.deindirect-reflection=${params.deindirect_reflection ?? true}`);
		jadxArgs.push("-P", `string-decrypt.cleanup-reflection=${params.cleanup_reflection ?? true}`);
		jadxArgs.push("-P", `string-decrypt.comments=${params.comments ?? true}`);

		if (params.cipher) jadxArgs.push("-P", `string-decrypt.cipher=${params.cipher}`);
		if (params.key_tail_len !== undefined) jadxArgs.push("-P", `string-decrypt.key-tail-len=${params.key_tail_len}`);
		if (params.decryptor_class) jadxArgs.push("-P", `string-decrypt.decryptor-class=${params.decryptor_class}`);
		if (params.decryptor_desc) jadxArgs.push("-P", `string-decrypt.decryptor-desc=${params.decryptor_desc}`);
		if (params.max_table_size) jadxArgs.push("-P", `string-decrypt.max-table-size=${params.max_table_size}`);

		if (params.class_filter) {
			jadxArgs.push("--single-class", params.class_filter);
		}
		jadxArgs.push(resolvedTarget);

		const subRes = await runSafeSubprocess({
			binary: jadxBin,
			args: jadxArgs,
			cwd: this.session.cwd,
			timeoutMs: timeoutSec * 1000,
			signal,
		});

		const durationMs = Date.now() - startTime;

		if (subRes.exitCode !== 0) {
			throw new ToolError(
				`jadx execution failed with exit code ${subRes.exitCode}: ${subRes.stderr || subRes.stdout}`,
			);
		}

		// Collect generated source artifacts
		// Collect generated source artifacts in staging
		const stagedArtifacts: ArtifactMetadata[] = [];
		let javaFilesCount = 0;

		async function scanDir(dir: string) {
			const entries = await fs.promises.readdir(dir, { withFileTypes: true });
			for (const entry of entries) {
				const full = path.join(dir, entry.name);
				if (entry.isDirectory()) {
					await scanDir(full);
				} else if (entry.isFile() && entry.name.endsWith(".java")) {
					javaFilesCount++;
					const meta = await getFileMetadata(full);
					if (meta) stagedArtifacts.push(meta);
				}
			}
		}
		const artifacts: ArtifactMetadata[] = [];
		try {
			await scanDir(stageDir);

			if (javaFilesCount === 0) {
				throw new ToolError(
					`jadx execution completed but produced no decompiled .java source files in staging. Stderr: ${subRes.stderr}`,
				);
			}

			// Atomically publish using safePublishArtifact with COPYFILE_EXCL
			await fs.promises.mkdir(outDir, { recursive: true });
			for (const sArt of stagedArtifacts) {
				const rel = path.relative(stageDir, sArt.path);
				const destPath = path.join(outDir, rel);
				await fs.promises.mkdir(path.dirname(destPath), { recursive: true });
				const pubMeta = await safePublishArtifact(sArt.path, destPath, new Set([`${stat.dev}:${stat.ino}`]));
				if (artifacts.length < 50) artifacts.push(pubMeta);
			}
		} finally {
			await fs.promises.rm(stageDir, { recursive: true, force: true }).catch(() => null);
		}
		const details: DeobfuscateAnalyzeDetails = {
			action: "analyze",
			backend: "jadx",
			success: true,
			inputPath: resolvedTarget,
			inputHash: inputHashRes.sha256,
			inputBytes: stat.size,
			durationMs,
			artifacts,
			metadata: {
				outDir,
				javaFilesCount,
				pluginUsed: true,
				exitCode: subRes.exitCode,
			},
		};

		let text = `# JADX Constant Deobfuscation & String Decrypt Report\n\n`;
		text += `- **Input**: \`${resolvedTarget}\` (${stat.size} bytes, SHA-256: \`${inputHashRes.sha256.slice(0, 16)}...\`)\n`;
		text += `- **Output Directory**: \`${outDir}\`\n`;
		text += `- **Decompiled Java Files**: ${javaFilesCount}\n`;
		text += `- **Plugin Active**: \`${path.basename(pluginJarPath)}\`\n`;
		text += `- **Duration**: ${(durationMs / 1000).toFixed(2)}s\n`;
		return toolResult(details).text(text).done();
	}

	// ========================================================================
	// d810-ng IDA Microcode Optimization
	// ========================================================================

	private async executeD810(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		if (!params.path) {
			throw new ToolError("d810-ng backend requires 'path' specifying target binary or IDA database (.idb/.i64).");
		}
		if (!params.function) {
			throw new ToolError(
				"d810-ng backend requires 'function' specifying target function address (e.g. '0x401000') or name.",
			);
		}

		const resolvedTarget = resolveReadPath(params.path, this.session.cwd);
		const stat = await fs.promises.stat(resolvedTarget).catch((err: unknown) => {
			const msg = err instanceof Error ? err.message : String(err);
			throw new ToolError(`Target binary/IDB file not found: ${resolvedTarget} (${msg})`);
		});
		if (!stat.isFile() || stat.size === 0) {
			throw new ToolError(`Target is not a valid regular file: ${resolvedTarget}`);
		}
		const inputHashRes = await computeStreamingHash(resolvedTarget);

		const idat64Bin = $which("idat64", { cache: WhichCachePolicy.Bypass }) ?? $which("idat") ?? $which("ida64");
		if (!idat64Bin) {
			throw new ToolError(
				"IDA Pro 9+ batch executable ('idat64' / 'ida64') not found in PATH. IDA 9+ with Hex-Rays decompiler is required for d810-ng headless microcode deobfuscation.",
			);
		}
		const d810Resolved = resolveProtectionTool("d810-ng");
		const sitePackages = d810Resolved?.metadata?.sitePackages as string | undefined;

		const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "d810_deobf_"));
		const reportPath = path.join(tempDir, "d810_report.json");
		const configPath = path.join(tempDir, "d810_config.json");
		const scriptPath = path.join(tempDir, "d810_worker.py");

		try {
			await fs.promises.writeFile(scriptPath, d810WorkerSource, "utf-8");

			const configData = {
				function: params.function,
				rules: params.rules ?? ["mba", "ollvm", "cst_simplification", "predicates"],
				unflattener: params.unflattener ?? "ollvm",
				config_json: params.config_json,
				site_packages: sitePackages,
				output_path: reportPath,
			};
			await fs.promises.writeFile(configPath, JSON.stringify(configData, null, 2), "utf-8");

			const timeoutSec = Math.min(Math.max(params.timeout ?? 120, 5), 600);
			const startTime = Date.now();

			const stagedTarget = path.join(tempDir, path.basename(resolvedTarget));
			await fs.promises.copyFile(resolvedTarget, stagedTarget);
			const idaArgs = ["-A", `-S${scriptPath} ${configPath}`, stagedTarget];

			const subRes = await runSafeSubprocess({
				binary: idat64Bin,
				args: idaArgs,
				cwd: this.session.cwd,
				env: sitePackages ? { PYTHONPATH: sitePackages } : undefined,
				timeoutMs: timeoutSec * 1000,
				signal,
			});

			const durationMs = Date.now() - startTime;

			if (!fs.existsSync(reportPath)) {
				throw new ToolError(
					`d810-ng headless execution completed without generating report JSON: ${subRes.stderr || subRes.stdout}`,
				);
			}

			const reportRaw = await fs.promises.readFile(reportPath, "utf-8");
			let parsedReport: unknown;
			try {
				parsedReport = JSON.parse(reportRaw);
			} catch {
				throw new ToolError(`Failed to parse d810-ng report JSON from ${reportPath}`);
			}

			if (typeof parsedReport !== "object" || parsedReport === null) {
				throw new ToolError("d810-ng returned invalid non-object report");
			}

			const report = parsedReport as {
				status?: string;
				error?: string;
				function_name?: string;
				resolved_ea?: string;
				d810_available?: boolean;
				applied_rules?: string[];
				unflattener?: string;
				complexity_reduction?: {
					lines_before: number;
					lines_after: number;
					lines_reduced: number;
					reduction_ratio: number;
				};
			};

			if (report.status !== "ok") {
				throw new ToolError(`d810-ng analysis failed: ${report.error ?? "unknown error"}`);
			}

			const artifacts: ArtifactMetadata[] = [];
			if (params.out) {
				const resolvedOut = validateDestinationPath(resolveToCwd(params.out, this.session.cwd), resolvedTarget);
				await fs.promises.mkdir(path.dirname(resolvedOut), { recursive: true });
				await fs.promises.writeFile(resolvedOut, reportRaw, { encoding: "utf-8", flag: "wx" });
				const meta = await getFileMetadata(resolvedOut);
				if (meta) artifacts.push(meta);
			}

			const artifactId = await saveArtifactText(this.session, "deobfuscate_d810", reportRaw).catch(() => undefined);

			const details: DeobfuscateAnalyzeDetails = {
				action: "analyze",
				backend: "d810-ng",
				success: true,
				inputPath: resolvedTarget,
				inputHash: inputHashRes.sha256,
				inputBytes: stat.size,
				durationMs,
				artifacts,
				metadata: {
					functionName: report.function_name,
					resolvedEa: report.resolved_ea,
					d810Available: report.d810_available,
					appliedRules: report.applied_rules ?? [],
					unflattener: report.unflattener,
				},
				complexityReduction: report.complexity_reduction
					? {
							metric: "pseudocode_lines",
							before: report.complexity_reduction.lines_before,
							after: report.complexity_reduction.lines_after,
							reductionRatio: report.complexity_reduction.reduction_ratio,
						}
					: undefined,
			};

			let text = `# d810-ng IDA 9+ Microcode Deobfuscation Report\n\n`;
			text += `- **Target**: \`${resolvedTarget}\`\n`;
			text += `- **Function**: ${report.function_name ?? "unknown"} (\`${report.resolved_ea ?? params.function}\`)\n`;
			text += `- **Unflattener**: \`${report.unflattener ?? "ollvm"}\`\n`;
			text += `- **Rules Applied**: ${report.applied_rules?.join(", ") || "(none)"}\n`;
			if (report.complexity_reduction) {
				text += `- **Pseudocode Lines**: ${report.complexity_reduction.lines_before} -> ${report.complexity_reduction.lines_after} (${report.complexity_reduction.lines_reduced} lines reduced, ratio ${report.complexity_reduction.reduction_ratio})\n`;
			}
			text += `- **Duration**: ${(durationMs / 1000).toFixed(2)}s\n`;

			if (artifactId) {
				text = appendArtifactReference(text, artifactId, "d810-ng Before/After Pseudocode Report");
			}
			return toolResult(details).text(text).done();
		} finally {
			try {
				await fs.promises.rm(tempDir, { recursive: true, force: true });
			} catch {}
		}
	}

	// ========================================================================
	// simplify Dalvik Virtual Execution
	// ========================================================================

	private async executeSimplify(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		if (!params.path) {
			throw new ToolError("simplify backend requires 'path' specifying target APK or DEX file.");
		}

		const resolvedTarget = resolveReadPath(params.path, this.session.cwd);
		const stat = await fs.promises.stat(resolvedTarget).catch((err: unknown) => {
			const msg = err instanceof Error ? err.message : String(err);
			throw new ToolError(`Target APK/DEX file not found: ${resolvedTarget} (${msg})`);
		});
		if (!stat.isFile() || stat.size === 0) {
			throw new ToolError(`Target is not a valid regular file: ${resolvedTarget}`);
		}
		const inputHashRes = await computeStreamingHash(resolvedTarget);

		const javaBin = $which("java", { cache: WhichCachePolicy.Bypass });
		if (!javaBin) {
			throw new ToolError("Java runtime ('java') not found in PATH. Java 8+ is required to execute Simplify.");
		}

		const simplifyResolved = resolveProtectionTool("simplify");
		const simplifyJar =
			(simplifyResolved?.metadata?.jarPath as string | undefined) ??
			(simplifyResolved?.path.endsWith(".jar") ? simplifyResolved.path : undefined) ??
			process.env.SIMPLIFY_JAR;
		if (!simplifyJar || !fs.existsSync(simplifyJar)) {
			throw new ToolError(
				"Simplify JAR not found. Please install Simplify via 'reverse setup reverse simplify --execute'.",
			);
		}

		const outDexPath = params.out
			? resolveToCwd(params.out, this.session.cwd)
			: path.join(this.session.cwd, "artifacts", "deobfuscate", `simplify_${Date.now()}.dex`);

		validateDestinationPath(outDexPath, resolvedTarget);
		const tempStageDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "simplify_stage_"));
		const stagedDexPath = path.join(tempStageDir, "output.dex");
		// Stage isolated DEX if input is APK to avoid Simplify Launcher ZIP-output alias bug
		let effectiveDexInput = resolvedTarget;
		let tempDexDir: string | null = null;
		let origDexHash = inputHashRes.sha256;
		let origDexBytes = stat.size;
		let isMultidex = false;

		if (resolvedTarget.endsWith(".apk")) {
			if (stat.size > 500 * 1024 * 1024) {
				throw new ToolError(`Input APK exceeds 500MB safety limit (${stat.size} bytes): ${resolvedTarget}`);
			}
			tempDexDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "simplify_apk_dex_"));
			const apkBuf = await fs.promises.readFile(resolvedTarget);
			const zip = new ZipParser(apkBuf);
			isMultidex = zip.entries.some(e => /^classes\d+\.dex$/.test(e.name));

			const dexEntry = zip.getEntry("classes.dex");
			const dexBuf = dexEntry ? zip.readFile(dexEntry, 100 * 1024 * 1024) : null;
			if (!dexBuf) {
				throw new ToolError(`No classes.dex found in APK: ${resolvedTarget}`);
			}
			origDexHash = crypto.createHash("sha256").update(dexBuf).digest("hex");
			origDexBytes = dexBuf.length;

			effectiveDexInput = path.join(tempDexDir, "classes.dex");
			await fs.promises.writeFile(effectiveDexInput, dexBuf);
		}
		const timeoutSec = Math.min(Math.max(params.timeout ?? 180, 5), 600);
		const startTime = Date.now();

		const javaCheck = await runSafeSubprocess({
			binary: javaBin,
			args: ["-version"],
			timeoutMs: 3000,
			signal,
		}).catch(() => null);

		const verText = javaCheck ? javaCheck.stderr || javaCheck.stdout : "";
		const vMatch =
			verText.match(/(?:version|openjdk version|java version)\s+"(?:1\.)?(\d+)/i) ?? verText.match(/"(?:1\.)?(\d+)/);
		const javaMajor = vMatch && vMatch[1] ? parseInt(vMatch[1], 10) : 8;

		const simplifyArgs: string[] = ["-Xmx2g"];
		if (javaMajor >= 9) {
			simplifyArgs.push(
				"--add-opens",
				"java.base/java.lang=ALL-UNNAMED",
				"--add-opens",
				"java.base/java.util=ALL-UNNAMED",
			);
		}
		simplifyArgs.push(
			"-jar",
			simplifyJar,
			effectiveDexInput,
			"--output",
			stagedDexPath,
			"--max-address-visits",
			String(params.max_address_visits ?? 10000),
			"--max-method-visits",
			String(params.max_method_visits ?? 1000),
			"--max-call-depth",
			String(params.max_call_depth ?? 50),
		);

		if (params.include_types && params.include_types.length > 0) {
			const combined =
				params.include_types.length > 1 ? `(?:${params.include_types.join("|")})` : params.include_types[0]!;
			simplifyArgs.push("-it", combined);
		}
		if (params.exclude_types && params.exclude_types.length > 0) {
			const combined =
				params.exclude_types.length > 1 ? `(?:${params.exclude_types.join("|")})` : params.exclude_types[0]!;
			simplifyArgs.push("-et", combined);
		}

		let subRes;
		try {
			subRes = await runSafeSubprocess({
				binary: javaBin,
				args: simplifyArgs,
				cwd: this.session.cwd,
				timeoutMs: timeoutSec * 1000,
				signal,
			});
		} finally {
			if (tempDexDir) {
				try {
					await fs.promises.rm(tempDexDir, { recursive: true, force: true });
				} catch {}
			}
		}

		const durationMs = Date.now() - startTime;

		if (subRes.exitCode !== 0) {
			throw new ToolError(
				`Simplify execution failed with exit code ${subRes.exitCode}: ${subRes.stderr || subRes.stdout}`,
			);
		}

		if (!fs.existsSync(stagedDexPath)) {
			throw new ToolError(
				`Simplify execution did not produce expected output DEX. Subprocess output: ${subRes.stderr || subRes.stdout}`,
			);
		}

		// Validate DEX magic header and declared file size on staged output
		const headBuf = Buffer.alloc(36);
		const fd = await fs.promises.open(stagedDexPath, "r");
		await fd.read(headBuf, 0, 36, 0);
		await fd.close();

		const validDex = checkDexMagic(headBuf);
		if (!validDex) {
			throw new ToolError(`Generated file lacks valid Dalvik DEX magic header ('dex\\n035').`);
		}
		const declaredSize = headBuf.readUInt32LE(0x20);
		const stagedStat = await fs.promises.stat(stagedDexPath);
		if (stagedStat.size !== declaredSize && stagedStat.size < declaredSize) {
			throw new ToolError(
				`Generated DEX is truncated: file size ${stagedStat.size} does not match header declared size ${declaredSize}.`,
			);
		}

		// Atomically publish using safePublishArtifact with COPYFILE_EXCL
		let outMeta: ArtifactMetadata;
		try {
			outMeta = await safePublishArtifact(stagedDexPath, outDexPath, new Set([`${stat.dev}:${stat.ino}`]));
		} finally {
			await fs.promises.rm(tempStageDir, { recursive: true, force: true }).catch(() => null);
		}
		const artifacts: ArtifactMetadata[] = [outMeta];

		const ratio = origDexBytes > 0 ? Math.round((outMeta.bytes / origDexBytes) * 10000) / 10000 : 1.0;

		const details: DeobfuscateAnalyzeDetails = {
			action: "analyze",
			backend: "simplify",
			success: true,
			inputPath: resolvedTarget,
			inputHash: inputHashRes.sha256,
			inputBytes: stat.size,
			durationMs,
			artifacts,
			metadata: {
				outDex: outDexPath,
				outHash: outMeta.sha256,
				outBytes: outMeta.bytes,
				effectiveInputDexHash: origDexHash,
				effectiveInputDexBytes: origDexBytes,
				hashChanged: outMeta.sha256 !== origDexHash,
				multidexDetected: isMultidex,
				multidexNote: isMultidex
					? "Target APK contains multidex (classes2.dex+). Simplify operates on a single DEX item; primary classes.dex was deobfuscated."
					: undefined,
				maxAddressVisits: params.max_address_visits ?? 10000,
				maxMethodVisits: params.max_method_visits ?? 1000,
			},
			complexityReduction: {
				metric: "dex_bytes",
				before: origDexBytes,
				after: outMeta.bytes,
				reductionRatio: ratio,
			},
		};

		let text = `# Simplify Virtual Execution Deobfuscation Report\n\n`;
		text += `- **Input DEX/APK**: \`${resolvedTarget}\` (${stat.size} bytes, SHA-256: \`${inputHashRes.sha256.slice(0, 16)}...\`)\n`;
		text += `- **Output Deobfuscated DEX**: \`${outDexPath}\` (${outMeta.bytes} bytes, SHA-256: \`${outMeta.sha256.slice(0, 16)}...\`)\n`;
		text += `- **Hash Modified**: ${outMeta.sha256 !== origDexHash ? "Yes (DEX bytecode transformed)" : "No"}\n`;
		if (isMultidex) {
			text += `- **Multidex Notice**: Target APK contains multidex (classes2.dex+); primary classes.dex was deobfuscated.\n`;
		}
		text += `- **Execution Bounds**: max_address_visits=${params.max_address_visits ?? 10000}, max_method_visits=${params.max_method_visits ?? 1000}\n`;
		text += `- **Duration**: ${(durationMs / 1000).toFixed(2)}s\n`;
		return toolResult(details).text(text).done();
	}

	// ========================================================================
	// blackdex Android Dynamic DEX Unpacker
	// ========================================================================

	private async executeBlackDex(
		params: DeobfuscateParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DeobfuscateDetails>> {
		let targetPackage = params.package_name?.trim();
		let targetAbi: "arm64-v8a" | "armeabi-v7a" | "universal" = "universal";

		// ABI and package discovery from APK path if provided
		if (params.path) {
			const resolvedPath = resolveReadPath(params.path, this.session.cwd);
			const apkStat = await fs.promises.stat(resolvedPath).catch(() => null);
			if (apkStat && apkStat.isFile() && resolvedPath.endsWith(".apk")) {
				if (apkStat.size > 500 * 1024 * 1024) {
					throw new ToolError(`Target APK exceeds 500MB safety limit (${apkStat.size} bytes): ${resolvedPath}`);
				}
				try {
					const apkBuf = await fs.promises.readFile(resolvedPath);
					const zip = new ZipParser(apkBuf);
					const mEntry = zip.getEntry("AndroidManifest.xml");
					const mBuf = mEntry ? zip.readFile(mEntry, 10 * 1024 * 1024) : null;
					if (mBuf) {
						const parsedManifest = parseAxml(mBuf, zip);
						if (parsedManifest?.package && !targetPackage) {
							targetPackage = parsedManifest.package;
						}
					}
					// Inspect native library architectures
					const has64 = zip.entries.some(e => e.name.startsWith("lib/arm64-v8a/"));
					const has32 = zip.entries.some(e => e.name.startsWith("lib/armeabi-v7a/"));
					if (has64 && !has32) targetAbi = "arm64-v8a";
					else if (has32 && !has64) targetAbi = "armeabi-v7a";
				} catch {}
			}
		}

		if (!targetPackage) {
			throw new ToolError(
				"blackdex backend requires parameter 'package_name' or a valid APK path under 'path' to discover package name.",
			);
		}

		const adbBin = $which("adb", { cache: WhichCachePolicy.Bypass });
		if (!adbBin) {
			throw new ToolError(
				"Android Debug Bridge ('adb') not found in PATH. Install adb via 'reverse setup reverse adb --execute'.",
			);
		}
		// Check connected devices
		const devRes = await runSafeSubprocess({
			binary: adbBin,
			args: ["devices"],
			cwd: this.session.cwd,
			timeoutMs: 10000,
			signal,
		});
		const devLines = devRes.stdout.split("\n").slice(1);
		const connected = devLines
			.map(l => l.trim())
			.filter(l => l && !l.startsWith("*") && l.includes("\tdevice"))
			.map(l => l.split("\t")[0]!);

		if (connected.length === 0) {
			throw new ToolError(
				"No Android devices or emulators connected via ADB. Please connect a device or start an emulator.",
			);
		}

		const targetDevice = params.device ?? connected[0]!;
		if (!connected.includes(targetDevice)) {
			throw new ToolError(
				`Requested device '${targetDevice}' is not connected. Connected devices: ${connected.join(", ")}`,
			);
		}

		const adbExec = (args: string[], timeoutMs = 15000) =>
			runSafeSubprocess({
				binary: adbBin,
				args: ["-s", targetDevice, ...args],
				cwd: this.session.cwd,
				timeoutMs,
				signal,
			});

		// Check Android SDK level: Android 5.0 (API 21) to Android 12 (API 32)
		const sdkRes = await adbExec(["shell", "getprop", "ro.build.version.sdk"]);
		const sdkInt = parseInt(sdkRes.stdout.trim(), 10);
		if (!Number.isNaN(sdkInt) && sdkInt < 21) {
			throw new ToolError(
				`BlackDex requires Android 5.0+ (API level >= 21). Connected device is API level ${sdkInt}.`,
			);
		}

		// Device architecture
		const abiRes = await adbExec(["shell", "getprop", "ro.product.cpu.abi"]);
		const deviceAbi = abiRes.stdout.trim();

		// If ABI was not discovered from APK, query target package primaryCpuAbi on device
		if (targetAbi === "universal") {
			try {
				const dumpSysRes = await adbExec(["shell", "dumpsys", "package", targetPackage]);
				const mAbi = dumpSysRes.stdout.match(/primaryCpuAbi=([^\r\n]+)/);
				if (mAbi && mAbi[1]) {
					const appAbi = mAbi[1].trim();
					if (appAbi.includes("64")) {
						targetAbi = "arm64-v8a";
					} else if (appAbi.includes("arm") || appAbi.includes("v7a") || appAbi.includes("32")) {
						targetAbi = "armeabi-v7a";
					}
				}
			} catch {}
		}

		// Resolve appropriate BlackDex APK and package name
		const blackdexResolved = resolveProtectionTool("blackdex");
		const is64Bit = targetAbi === "arm64-v8a" || (targetAbi === "universal" && deviceAbi.includes("64"));

		// Detect installed BlackDex package variant on device
		const pkgListRes = await adbExec(["shell", "pm", "list", "packages"]);
		const installedPkgs = pkgListRes.stdout;

		// Architecture-strict package priority: never pick 32-bit package for 64-bit target or vice-versa
		const preferredPackages = is64Bit
			? ["top.niunaijun.blackdexa64", "com.zhenghaipeng.blackdex64", "com.zhenghaipeng.blackdex"]
			: ["top.niunaijun.blackdexa32", "com.zhenghaipeng.blackdex32", "com.zhenghaipeng.blackdex"];

		let blackdexPkg = preferredPackages[0]!;
		let blackdexInstalledOnDevice = false;

		for (const kPkg of preferredPackages) {
			if (hasExactPackage(installedPkgs, kPkg)) {
				blackdexPkg = kPkg;
				blackdexInstalledOnDevice = true;
				break;
			}
		}

		let chosenApk: string | null = null;
		if (is64Bit && blackdexResolved?.metadata?.apk64 && fs.existsSync(blackdexResolved.metadata.apk64 as string)) {
			chosenApk = blackdexResolved.metadata.apk64 as string;
		} else if (
			!is64Bit &&
			blackdexResolved?.metadata?.apk32 &&
			fs.existsSync(blackdexResolved.metadata.apk32 as string)
		) {
			chosenApk = blackdexResolved.metadata.apk32 as string;
		} else if (blackdexResolved?.installed && blackdexResolved.path.endsWith(".apk")) {
			try {
				const fStat = await fs.promises.stat(blackdexResolved.path);
				if (fStat.size <= 500 * 1024 * 1024) {
					const fBuf = await fs.promises.readFile(blackdexResolved.path);
					const fZip = new ZipParser(fBuf);
					const has64 = fZip.entries.some(e => e.name.startsWith("lib/arm64-v8a/"));
					const has32 = fZip.entries.some(e => e.name.startsWith("lib/armeabi-v7a/"));
					if ((is64Bit && has64) || (!is64Bit && has32) || (!has64 && !has32)) {
						chosenApk = blackdexResolved.path;
					}
				}
			} catch {}
		}

		if (params.apk_path && fs.existsSync(params.apk_path)) {
			try {
				const cStat = await fs.promises.stat(params.apk_path).catch(() => null);
				if (cStat && cStat.size <= 500 * 1024 * 1024) {
					const cBuf = await fs.promises.readFile(params.apk_path);
					const cZip = new ZipParser(cBuf);
					const cEntry = cZip.getEntry("AndroidManifest.xml");
					const cMbuf = cEntry ? cZip.readFile(cEntry, 10 * 1024 * 1024) : null;
					if (cMbuf) {
						const cManifest = parseAxml(cMbuf, cZip);
						if (cManifest?.package) {
							const has64 = cZip.entries.some(e => e.name.startsWith("lib/arm64-v8a/"));
							const has32 = cZip.entries.some(e => e.name.startsWith("lib/armeabi-v7a/"));
							if (is64Bit && !has64 && has32) {
								throw new ToolError(
									`Custom BlackDex APK '${params.apk_path}' is 32-bit (armeabi-v7a), but target package '${targetPackage}' or device requires 64-bit (arm64-v8a).`,
								);
							}
							if (!is64Bit && has64 && !has32) {
								throw new ToolError(
									`Custom BlackDex APK '${params.apk_path}' is 64-bit (arm64-v8a), but target package '${targetPackage}' or device requires 32-bit (armeabi-v7a).`,
								);
							}
							chosenApk = params.apk_path;
							blackdexPkg = cManifest.package;
							blackdexInstalledOnDevice = hasExactPackage(installedPkgs, cManifest.package);
						}
					}
				}
			} catch (err: unknown) {
				if (err instanceof ToolError) throw err;
			}
		}
		const requestedAction = params.blackdex_action ?? "auto";

		// Lifecycle Action: INSTALL
		if (!blackdexInstalledOnDevice || requestedAction === "install") {
			if (!chosenApk || !fs.existsSync(chosenApk)) {
				throw new ToolError(
					`BlackDex (${is64Bit ? "64-bit" : "32-bit"}) is not installed on device '${targetDevice}' and local APK was not resolved. Run 'reverse setup reverse blackdex --execute'.`,
				);
			}

			const installRes = await adbExec(["install", "-r", chosenApk], 60000);
			if (installRes.exitCode !== 0) {
				throw new ToolError(
					`Failed to install BlackDex APK onto device: ${installRes.stderr || installRes.stdout}`,
				);
			}
			blackdexInstalledOnDevice = true;

			if (requestedAction === "install") {
				const details: DeobfuscateAnalyzeDetails = {
					action: "analyze",
					backend: "blackdex",
					success: true,
					durationMs: 0,
					artifacts: [],
					metadata: {
						lifecycleAction: "install",
						installedApk: chosenApk,
						packageOnDevice: blackdexPkg,
						device: targetDevice,
					},
				};
				return toolResult(details)
					.text(
						`# BlackDex Installation Complete\n\n- Installed APK: \`${chosenApk}\`\n- Package on device: \`${blackdexPkg}\`\n- Device: \`${targetDevice}\``,
					)
					.done();
			}
		}

		// Ensure target app exists on device using exact package matching
		const targetPkgCheck = await adbExec(["shell", "pm", "list", "packages", targetPackage]);
		if (!hasExactPackage(targetPkgCheck.stdout, targetPackage)) {
			throw new ToolError(`Target package '${targetPackage}' is not installed on device '${targetDevice}'.`);
		}

		// Candidate dump directories matching upstream CodingGay/BlackDex defaults:
		// Android R+ (API >= 30): /sdcard/Download/dexDump/<targetPackage>
		// Pre-R (API < 30): /sdcard/Android/data/<blackdexPkg>/dump/<targetPackage>
		const candidateRemoteDirs = [
			`/sdcard/Download/dexDump/${targetPackage}`,
			`/sdcard/Android/data/${blackdexPkg}/dump/${targetPackage}`,
			`/sdcard/Download/BlackDex/${targetPackage}`,
			`/sdcard/Android/data/${blackdexPkg}/files/dump/${targetPackage}`,
			`/sdcard/Android/data/top.niunaijun.blackdexa64/dump/${targetPackage}`,
			`/sdcard/Android/data/top.niunaijun.blackdexa32/dump/${targetPackage}`,
		];

		const outDir = params.out
			? resolveToCwd(params.out, this.session.cwd)
			: path.join(this.session.cwd, "artifacts", "deobfuscate", `blackdex_${Date.now()}`);

		validateDestinationPath(outDir, params.path);

		const startTime = Date.now();
		const waitTimeoutSec = Math.min(Math.max(params.timeout ?? params.wait_timeout_seconds ?? 60, 5), 600);
		const deadline = startTime + waitTimeoutSec * 1000;
		const pollIntervalMs = 2000;

		const getRemoteSignatures = async (dir: string, perCallTimeoutMs = 1500): Promise<Map<string, string>> => {
			const sigs = new Map<string, string>();
			if (Date.now() >= deadline) return sigs;

			// 1. Stat mtime and size (%Y:%s)
			const statBudget = Math.min(perCallTimeoutMs, Math.max(200, deadline - Date.now()));
			const statRes = await adbExec(["shell", "stat", "-c", "'%Y:%s %n'", `${dir}/*.dex`], statBudget).catch(
				() => null,
			);
			if (statRes && statRes.exitCode === 0 && !statRes.stdout.includes("No such file")) {
				for (const line of statRes.stdout.split(/\r?\n/)) {
					const parts = line.trim().split(/\s+/);
					if (parts.length >= 2 && parts[1]?.endsWith(".dex")) {
						const fname = path.basename(parts[1]);
						sigs.set(fname, parts[0]!);
					}
				}
			}

			if (Date.now() >= deadline) return sigs;

			// 2. Combine with sha256sum for content identity
			const sumBudget = Math.min(perCallTimeoutMs, Math.max(200, deadline - Date.now()));
			const sumRes = await adbExec(["shell", "sha256sum", `${dir}/*.dex`], sumBudget).catch(() => null);
			if (sumRes && sumRes.exitCode === 0 && !sumRes.stdout.includes("No such file")) {
				for (const line of sumRes.stdout.split(/\r?\n/)) {
					const parts = line.trim().split(/\s+/);
					if (parts.length >= 2 && parts[1]?.endsWith(".dex")) {
						const fname = path.basename(parts[1]);
						const mtimePart = sigs.get(fname) ?? "";
						sigs.set(fname, `${mtimePart}_${parts[0]}`);
					}
				}
			}

			return sigs;
		};

		// Record pre-existing files with cryptographic/timestamp signatures (NEVER delete user files on device!)
		const preExistingFiles = new Map<string, string>();
		for (const rDir of candidateRemoteDirs) {
			if (Date.now() >= deadline) break;
			const dirSigs = await getRemoteSignatures(rDir, 1000);
			for (const [fname, sig] of dirSigs) {
				preExistingFiles.set(`${rDir}/${fname}`, sig);
			}
		}

		// Lifecycle Action: LAUNCH (Honors auto_launch: false)
		const shouldLaunch = params.auto_launch !== false && (requestedAction === "launch" || requestedAction === "auto");
		if (shouldLaunch) {
			// Launch BlackDex via Android monkey runner to launch default launcher activity without guessing component names
			const monkeyRes = await adbExec([
				"shell",
				"monkey",
				"-p",
				blackdexPkg,
				"-c",
				"android.intent.category.LAUNCHER",
				"1",
			]);
			if (
				monkeyRes.exitCode !== 0 ||
				monkeyRes.stdout.includes("No activities found") ||
				monkeyRes.stderr.includes("monkey aborted")
			) {
				throw new ToolError(
					`Failed to launch BlackDex (${blackdexPkg}) on device: ${monkeyRes.stderr || monkeyRes.stdout}`,
				);
			}

			if (requestedAction === "launch") {
				const details: DeobfuscateAnalyzeDetails = {
					action: "analyze",
					backend: "blackdex",
					success: true,
					durationMs: 0,
					artifacts: [],
					interventionRequired: true,
					userInstructions: `BlackDex launched on device screen. Select '${targetPackage}' in BlackDex UI to dump DEX files, then call deobfuscate with blackdex_action: 'collect'.`,
					metadata: {
						lifecycleAction: "launch",
						packageOnDevice: blackdexPkg,
						targetPackage,
						device: targetDevice,
					},
				};
				return toolResult(details)
					.text(
						`# BlackDex Application Launched\n\n- Package: \`${blackdexPkg}\`\n- Target Package: \`${targetPackage}\`\n- State: User intervention required on device screen to confirm/select target app.\n- Follow-up: Once selected, invoke \`deobfuscate({ action: "analyze", backend: "blackdex", package_name: "${targetPackage}", blackdex_action: "collect" })\` to retrieve DEX files.`,
					)
					.done();
			}
		}

		// Polling for dumped DEX files (Action: "collect" or "auto") with real elapsed deadline

		let activeRemoteDumpDir: string | null = null;
		let dumpedFilesFound: string[] = [];

		while (Date.now() < deadline) {
			throwIfAborted(signal);

			for (const rDir of candidateRemoteDirs) {
				const currentSigs = await getRemoteSignatures(rDir);
				const freshFiles: string[] = [];
				for (const [fname, sig] of currentSigs) {
					const key = `${rDir}/${fname}`;
					const prevSig = preExistingFiles.get(key);
					if (!prevSig || prevSig !== sig) {
						freshFiles.push(fname);
					}
				}
				if (freshFiles.length > 0) {
					activeRemoteDumpDir = rDir;
					dumpedFilesFound = freshFiles;
					break;
				} else if (requestedAction === "collect" && currentSigs.size > 0) {
					activeRemoteDumpDir = rDir;
					dumpedFilesFound = Array.from(currentSigs.keys());
					break;
				}
			}

			if (dumpedFilesFound.length > 0) break;
			if (requestedAction === "collect") break;

			const sleepMs = Math.min(pollIntervalMs, Math.max(0, deadline - Date.now()));
			if (sleepMs <= 0) break;

			const { promise, resolve } = Promise.withResolvers<void>();
			setTimeout(resolve, sleepMs);
			await promise;
		}

		const durationMs = Date.now() - startTime;

		if (dumpedFilesFound.length === 0 || !activeRemoteDumpDir) {
			const details: DeobfuscateAnalyzeDetails = {
				action: "analyze",
				backend: "blackdex",
				success: false,
				durationMs,
				artifacts: [],
				interventionRequired: true,
				userInstructions: `BlackDex requires user selection on device screen. Select '${targetPackage}' in BlackDex UI to dump DEX files, then call deobfuscate with blackdex_action: 'collect'.`,
				metadata: {
					targetPackage,
					targetDevice,
					waitedSeconds: waitTimeoutSec,
					dumpDirsChecked: candidateRemoteDirs,
				},
			};
			return toolResult(details)
				.text(
					`# BlackDex Unpacking - User Interaction Required\n\n` +
						`- Target Package: \`${targetPackage}\`\n` +
						`- Device: \`${targetDevice}\` (API level ${sdkInt})\n` +
						`- Waited: ${waitTimeoutSec}s\n` +
						`BlackDex did not automatically find dumped DEX files in remote directories.\n` +
						`**Next Step**: On the Android device screen, locate and tap '${targetPackage}' inside the BlackDex UI to initiate unpacking. Once completed, re-run with \`blackdex_action: "collect"\`.`,
				)
				.done();
		}

		// Pull dumped DEX files individually into private staging directory
		const stagingDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "blackdex_stage_"));
		try {
			for (const dFile of dumpedFilesFound) {
				const remoteFile = `${activeRemoteDumpDir}/${dFile}`;
				const stagedDest = path.join(stagingDir, dFile);
				const pullRes = await adbExec(["pull", remoteFile, stagedDest], 60000);
				if (pullRes.exitCode !== 0) {
					throw new ToolError(
						`Failed to pull dumped DEX file '${remoteFile}': ${pullRes.stderr || pullRes.stdout}`,
					);
				}
			}

			// Validate magic headers + file_size header field in staging
			const stagedValid: string[] = [];
			for (const dFile of dumpedFilesFound) {
				const stagedPath = path.join(stagingDir, dFile);
				if (fs.existsSync(stagedPath)) {
					try {
						const lstat = await fs.promises.stat(stagedPath);
						if (lstat.isFile() && lstat.size >= 0x70) {
							const headBuf = Buffer.alloc(36);
							const fd = await fs.promises.open(stagedPath, "r");
							await fd.read(headBuf, 0, 36, 0);
							await fd.close();
							const declaredSize = headBuf.readUInt32LE(0x20);
							if (checkDexMagic(headBuf) && (lstat.size === declaredSize || lstat.size >= declaredSize)) {
								stagedValid.push(stagedPath);
							}
						}
					} catch {}
				}
			}

			if (stagedValid.length === 0) {
				const details: DeobfuscateAnalyzeDetails = {
					action: "analyze",
					backend: "blackdex",
					success: false,
					durationMs,
					artifacts: [],
					interventionRequired: true,
					userInstructions: `BlackDex did not produce valid, fully written Dalvik DEX files. Ensure '${targetPackage}' was selected and unpacked in the BlackDex UI on device.`,
					metadata: {
						targetPackage,
						targetDevice,
					},
				};
				return toolResult(details)
					.text(
						`# BlackDex Unpacking - No Valid DEX Files Found\n\n- Target Package: \`${targetPackage}\`\n- Device: \`${targetDevice}\`\n- Status: Dumped files did not contain valid Dalvik DEX headers or had incomplete file sizes.\n- Ensure '${targetPackage}' was selected and dumped in the BlackDex UI on device, then run with \`blackdex_action: "collect"\`.`,
					)
					.done();
			}

			// Atomically publish valid DEX files using safePublishArtifact with COPYFILE_EXCL
			const artifacts: ArtifactMetadata[] = [];
			await fs.promises.mkdir(outDir, { recursive: true });
			for (const sPath of stagedValid) {
				const finalDest = path.join(outDir, path.basename(sPath));
				const pubMeta = await safePublishArtifact(sPath, finalDest);
				artifacts.push(pubMeta);
			}

			const details: DeobfuscateAnalyzeDetails = {
				action: "analyze",
				backend: "blackdex",
				success: true,
				durationMs,
				artifacts,
				metadata: {
					targetPackage,
					targetDevice,
					remoteDumpDir: activeRemoteDumpDir,
					outDir,
					dumpedFilesCount: artifacts.length,
				},
			};

			let text = `# BlackDex Dynamic Unpacking Report\n\n`;
			text += `- **Target Package**: \`${targetPackage}\`\n`;
			text += `- **Device**: \`${targetDevice}\` (API level ${sdkInt})\n`;
			text += `- **Dumped DEX Files**: ${artifacts.length}\n`;
			for (const art of artifacts) {
				text += `  - \`${path.basename(art.path)}\` (${art.bytes} bytes, SHA-256: \`${art.sha256.slice(0, 16)}...\`)\n`;
			}
			text += `- **Local Output Directory**: \`${outDir}\`\n`;
			text += `- **Duration**: ${(durationMs / 1000).toFixed(2)}s\n`;

			return toolResult(details).text(text).done();
		} finally {
			await fs.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => null);
		}
	}
}
