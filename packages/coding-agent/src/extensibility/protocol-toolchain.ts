/**
 * 协议格式解析与可执行能力识别可选工具链解析与受管安装器：
 * - kaitai-struct-compiler: 官方 JVM 编译器（v0.11，GPL-3.0-or-later），校验 Java 运行时、版本兼容与 --read-pos 支持
 * - kaitaistruct: Python 运行时库（0.11，MIT），在实际选定的 Python 环境或受管虚拟环境中校验导入与版本兼容
 * - capa: Mandiant 可解释能力识别引擎与官方规则库（v10.0.0，Apache-2.0），同时校验可执行程序与有效规则目录
 * - mitmproxy: 复用现有目录项，按动作区分离线 HAR/差分与 .mitm 依赖
 */
import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy, type WhichOptions } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import type { Settings } from "../config/settings";
import { enumeratePythonRuntimes, resolveExplicitPythonRuntime } from "../eval/py/runtime";
import { cfgPythonInterpreter } from "../eval/settings";
import { findRealDarwinJdk, type SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";
import { runSubprocess } from "./triton-source-install";

// ============================================================================
// 上游版本、下载地址、校验摘要与许可证固定常量
// ============================================================================

export const KAITAI_COMPILER_VERSION = "0.11";
export const KAITAI_COMPILER_MIN_VERSION = "0.9";
export const KAITAI_COMPILER_LICENSE = "GPL-3.0-or-later";
export const KAITAI_COMPILER_UPSTREAM_URL = "https://github.com/kaitai-io/kaitai_struct_compiler";
export const KAITAI_COMPILER_ZIP_URL = `https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/${KAITAI_COMPILER_VERSION}/kaitai-struct-compiler-${KAITAI_COMPILER_VERSION}.zip`;
export const KAITAI_COMPILER_ZIP_SHA256 = "ff89389d9dc9e770d78a24af328763cb1f8e7b31ce7766c9edf10669a060f2a2";

export const KAITAISTRUCT_VERSION = "0.11";
export const KAITAISTRUCT_MIN_VERSION = "0.9";
export const KAITAISTRUCT_PYPI_PACKAGE = `kaitaistruct==${KAITAISTRUCT_VERSION}`;
export const KAITAISTRUCT_LICENSE = "MIT";
export const KAITAISTRUCT_UPSTREAM_URL = "https://github.com/kaitai-io/kaitai_struct_python_runtime";

export const CAPA_VERSION = "10.0.0";
export const CAPA_TAG = `v${CAPA_VERSION}`;
export const CAPA_LICENSE = "Apache-2.0";
export const CAPA_UPSTREAM_URL = "https://github.com/mandiant/capa";

export const CAPA_RULES_VERSION = "10.0.0";
export const CAPA_RULES_TAG = `v${CAPA_RULES_VERSION}`;
export const CAPA_RULES_LICENSE = "Apache-2.0";
export const CAPA_RULES_UPSTREAM_URL = "https://github.com/mandiant/capa-rules";
export const CAPA_RULES_ARCHIVE_URL = `https://github.com/mandiant/capa-rules/archive/refs/tags/${CAPA_RULES_TAG}.tar.gz`;

export const CAPA_RELEASE_ASSETS = {
	darwin_arm64: {
		url: `https://github.com/mandiant/capa/releases/download/${CAPA_TAG}/capa-${CAPA_TAG}-macos-arm64.zip`,
		sha256: "04a827aef9517da045403da6927721c6489263a4a7e3846cc7da05f745062b73",
	},
	darwin_x64: {
		url: `https://github.com/mandiant/capa/releases/download/${CAPA_TAG}/capa-${CAPA_TAG}-macos.zip`,
		sha256: "566617317a46a7c7c215a2004d55cf0175a0a9ec31419dfeb6a0b4c2aff8b5da",
	},
	linux_arm64: {
		url: `https://github.com/mandiant/capa/releases/download/${CAPA_TAG}/capa-${CAPA_TAG}-linux-arm64.zip`,
		sha256: "1da5512f75220c79e2f9f59609673af7329828f91b1d020ada60b859221d9793",
	},
	linux_x64: {
		url: `https://github.com/mandiant/capa/releases/download/${CAPA_TAG}/capa-${CAPA_TAG}-linux.zip`,
		sha256: "96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca",
	},
	win32_x64: {
		url: `https://github.com/mandiant/capa/releases/download/${CAPA_TAG}/capa-${CAPA_TAG}-windows.zip`,
		sha256: "8712991044321dbb2a5b0d60f7a5327a50c9c30a295e7ddb5c1088cb17fb59df",
	},
} as const;

export const MAX_PROTOCOL_ARCHIVE_BYTES = 150 * 1024 * 1024;
const DEFAULT_PROBE_TIMEOUT_MS = 20_000;
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_RULE_SCAN_DEPTH = 16;
const DEFAULT_MAX_RULE_SCAN_FILES = 10_000;
const DEFAULT_MAX_RULE_FILE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_RULE_TOTAL_BYTES = 100 * 1024 * 1024;
const RULE_READINESS_SAMPLE_LIMIT = 64;

// ============================================================================
// 公共类型定义
// ============================================================================

export type SubprocessExecutor = (
	argv: readonly string[],
	options?: {
		cwd?: string;
		env?: Record<string, string | undefined>;
		onChunk?: (chunk: string) => void;
		signal?: AbortSignal;
		timeoutMs?: number;
	},
) => Promise<{ exitCode: number; stdout: string; stderr: string }>;

export interface ProtocolProbeBaseDeps {
	env?: Record<string, string | undefined>;
	which?: SkillRequirementWhich;
	agentDir?: string;
	platform?: SkillToolPlatform;
	cwd?: string;
	settings?: Settings;
	timeoutMs?: number;
}

export interface KaitaiCompilerResolveOptions extends ProtocolProbeBaseDeps {
	compilerPath?: string;
}

export interface KaitaiCompilerProbeResult {
	available: boolean;
	binaryFound: boolean;
	javaReady: boolean;
	compatible: boolean;
	supportsReadPos: boolean;
	path: string | null;
	version: string | null;
	javaPath: string | null;
	secondaryMissing: string[];
	error?: string;
}

export interface KaitaiCompilerInstallOptions extends ProtocolProbeBaseDeps {
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	fetch?: typeof globalThis.fetch;
	/** 测试专用预期归档摘要；未指定时强制校验固定上游 SHA-256。 */
	expectedSha256?: string;
}

export interface KaitaiCompilerInstallResult {
	success: boolean;
	installDir: string;
	executablePath: string | null;
	version?: string;
	message: string;
	error?: string;
}

export interface KaitaiStructProbeResult {
	pythonBin: string;
	version: string;
	apiVersion?: string;
	modulePath: string;
}

export type KaitaiStructProbeFailureKind =
	| "missing_interpreter"
	| "missing_module"
	| "incompatible_version"
	| "probe_failed";

export interface KaitaiStructDetailedProbeResult {
	status: "available" | KaitaiStructProbeFailureKind;
	available: boolean;
	deterministic: boolean;
	pythonBin: string | null;
	version: string | null;
	apiVersion: string | null;
	modulePath: string | null;
	error?: string;
	readinessFingerprint: string;
	checkedCandidates: string[];
}

export interface KaitaiStructRequirementDeps extends ProtocolProbeBaseDeps {
	/** 调用方显式选定的 Python 解释器；传入时仅探测该解释器，不回退到其他环境。 */
	pythonPath?: string;
}

export interface KaitaiStructInstallOptions extends ProtocolProbeBaseDeps {
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	executor?: SubprocessExecutor;
}

export interface KaitaiStructInstallResult {
	success: boolean;
	pythonPath: string | null;
	venvDir: string;
	message: string;
	version?: string;
	error?: string;
}

export interface KaitaiToolchainReadiness {
	ready: boolean;
	compatible: boolean;
	compiler: KaitaiCompilerProbeResult;
	runtime: KaitaiStructDetailedProbeResult;
	missingRequirements: string[];
	incompatibilityReason?: string;
	setupCommands: string[];
}

export interface CapaRulesScanOptions {
	maxDepth?: number;
	maxFiles?: number;
	maxFileBytes?: number;
	maxTotalBytes?: number;
}

export interface CapaRulesValidationResult {
	valid: boolean;
	rulesPath: string;
	ruleCount: number;
	sampleRuleFiles: string[];
	error?: string;
}

export interface CapaRulesManifest {
	rulesPath: string;
	ruleCount: number;
	manifestSha256: string;
	files: Array<{ path: string; sha256: string; sizeBytes: number }>;
}

export interface CapaResolveOptions extends ProtocolProbeBaseDeps {
	capaPath?: string;
	rulesPath?: string;
}

export interface CapaProbeResult {
	available: boolean;
	engineReady: boolean;
	rulesReady: boolean;
	path: string | null;
	version: string | null;
	rulesPath: string | null;
	ruleCount: number;
	secondaryMissing: string[];
	error?: string;
}

export interface CapaInstallOptions extends ProtocolProbeBaseDeps {
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	fetch?: typeof globalThis.fetch;
	arch?: string;
	/** 测试专用预期引擎归档摘要；未指定时强制校验固定上游 SHA-256。 */
	expectedEngineSha256?: string;
	/** 可选预期规则包摘要；指定时一并强制校验。 */
	expectedRulesSha256?: string;
}

export interface CapaInstallResult {
	success: boolean;
	installDir: string;
	executablePath: string | null;
	rulesPath: string | null;
	version?: string;
	ruleCount?: number;
	rulesSha256?: string;
	message: string;
	error?: string;
}

export interface MitmproxyResolveResult {
	available: boolean;
	path: string | null;
	mitmdumpPath: string | null;
	mitmproxyPath: string | null;
}

export type ProtocolToolName = "app_experiment" | "format_inspect" | "capability_inspect";

export interface ProtocolActionDependencyQuery extends ProtocolProbeBaseDeps {
	toolName: ProtocolToolName | string;
	action: string;
	captureFormat?: "har" | "mitm" | string;
	capturePath?: string;
	requiresCompile?: boolean;
	pythonPath?: string;
	rulesPath?: string;
	compilerPath?: string;
	capaPath?: string;
}

export interface ProtocolActionDependencyResult {
	ready: boolean;
	requiredTools: string[];
	missingTools: string[];
	setupCommands: string[];
	reason?: string;
	details?: {
		kaitai?: KaitaiToolchainReadiness;
		capa?: CapaProbeResult;
		mitmproxy?: MitmproxyResolveResult;
	};
}

// ============================================================================
// 基础环境、路径与归档辅助函数
// ============================================================================

function normalizePlatform(platform?: SkillToolPlatform | NodeJS.Platform): SkillToolPlatform {
	const raw = platform ?? process.platform;
	return raw === "darwin" || raw === "win32" ? raw : "linux";
}

function isExplicitCallerEnv(options?: ProtocolProbeBaseDeps): boolean {
	return options?.env !== undefined && options.env !== process.env;
}

function getEffectiveProbeEnv(options?: ProtocolProbeBaseDeps): Record<string, string | undefined> {
	const isSyntheticWhich = options?.which !== undefined && options.which !== $which;
	if (!isExplicitCallerEnv(options)) {
		return isSyntheticWhich ? {} : process.env;
	}
	const callerEnv = options!.env!;
	if (
		(isSyntheticWhich || (options?.agentDir && options.agentDir !== getAgentDir())) &&
		callerEnv.REVERSE_TOOL_PATHS === process.env.REVERSE_TOOL_PATHS &&
		process.env.REVERSE_TOOL_PATHS !== undefined
	) {
		const { REVERSE_TOOL_PATHS: _ignored, ...rest } = callerEnv;
		return rest;
	}
	return callerEnv;
}

function shouldCheckManagedAgentDir(options?: ProtocolProbeBaseDeps): boolean {
	if (options?.agentDir) {
		return true;
	}
	if (isExplicitCallerEnv(options)) {
		return Boolean(options?.env?.REVERSE_CODING_AGENT_DIR);
	}
	return options?.which === undefined || options.which === $which;
}

function isExecutableFile(filePath: string, platform: SkillToolPlatform): boolean {
	try {
		if (!filePath || !fs.existsSync(filePath)) return false;
		const st = fs.statSync(filePath);
		if (!st.isFile()) return false;
		if (platform === "win32" || process.platform === "win32") return true;
		fs.accessSync(filePath, fs.constants.X_OK);
		return true;
	} catch {
		return false;
	}
}

function buildCleanProbeEnv(env?: Record<string, string | undefined>): NodeJS.ProcessEnv {
	const source = env !== undefined ? env : process.env;
	const clean: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(source)) {
		if (typeof value === "string") {
			clean[key] = value;
		}
	}
	delete clean.PYTHONPATH;
	delete clean.PYTHONHOME;
	return clean;
}

function statSignature(targetPath: string): string {
	try {
		const st = fs.statSync(targetPath);
		return `${targetPath}:${st.isFile() ? "f" : st.isDirectory() ? "d" : "o"}:${st.size}:${Math.trunc(st.mtimeMs)}`;
	} catch {
		return `${targetPath}:missing`;
	}
}

function spawnProbeCommand(
	binaryPath: string,
	args: readonly string[],
	env: NodeJS.ProcessEnv,
	platform: SkillToolPlatform,
	timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
): child_process.SpawnSyncReturns<string> {
	const lower = binaryPath.toLowerCase();
	const useWinShell =
		(platform === "win32" || process.platform === "win32") && (lower.endsWith(".bat") || lower.endsWith(".cmd"));
	return child_process.spawnSync(binaryPath, [...args], {
		cwd: os.tmpdir(),
		timeout: timeoutMs,
		stdio: ["ignore", "pipe", "pipe"],
		env,
		encoding: "utf8",
		windowsHide: true,
		...(useWinShell ? { shell: true } : {}),
	});
}

async function fetchBoundedBytes(
	url: string,
	options?: {
		fetch?: typeof globalThis.fetch;
		signal?: AbortSignal;
		timeoutMs?: number;
		maxBytes?: number;
		onChunk?: (chunk: string) => void;
	},
): Promise<{ ok: true; bytes: Buffer } | { ok: false; error: string }> {
	const fetchFn = options?.fetch ?? globalThis.fetch;
	const maxBytes = options?.maxBytes ?? MAX_PROTOCOL_ARCHIVE_BYTES;
	const timeoutMs = options?.timeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS;

	const controller = new AbortController();
	let timer: NodeJS.Timeout | undefined;
	if (timeoutMs > 0) {
		timer = setTimeout(
			() => controller.abort(new Error(`Download timed out after ${timeoutMs}ms: ${url}`)),
			timeoutMs,
		);
	}
	const onParentAbort = () => controller.abort(options?.signal?.reason);
	options?.signal?.addEventListener("abort", onParentAbort, { once: true });

	try {
		options?.onChunk?.(`[reverse] Downloading ${url}...\n`);
		const res = await fetchFn(url, { signal: controller.signal });
		if (!res.ok) {
			return { ok: false, error: `Failed to download ${url}: HTTP ${res.status} ${res.statusText}` };
		}
		const contentLength = res.headers.get("content-length");
		if (contentLength && Number.parseInt(contentLength, 10) > maxBytes) {
			return {
				ok: false,
				error: `Archive Content-Length (${contentLength}) exceeds safety limit of ${maxBytes} bytes.`,
			};
		}
		if (!res.body) {
			const buf = Buffer.from(await res.arrayBuffer());
			if (buf.byteLength > maxBytes) {
				return { ok: false, error: `Downloaded payload exceeded safety limit of ${maxBytes} bytes.` };
			}
			return { ok: true, bytes: buf };
		}

		const reader = res.body.getReader();
		const chunks: Uint8Array[] = [];
		let totalBytes = 0;
		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (value) {
					totalBytes += value.byteLength;
					if (totalBytes > maxBytes) {
						await reader.cancel();
						return { ok: false, error: `Downloaded stream exceeded safety limit of ${maxBytes} bytes.` };
					}
					chunks.push(value);
				}
			}
		} finally {
			reader.releaseLock();
		}
		return { ok: true, bytes: Buffer.concat(chunks) };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	} finally {
		clearTimeout(timer);
		options?.signal?.removeEventListener("abort", onParentAbort);
	}
}

function flattenSingleRootSubdirectory(targetDir: string, markerSubpath?: string): void {
	const entries = fs.readdirSync(targetDir, { withFileTypes: true });
	const subdirs = entries.filter(e => e.isDirectory());
	const files = entries.filter(e => e.isFile());
	if (subdirs.length !== 1 || files.length > 0) return;
	const nestedDir = path.join(targetDir, subdirs[0].name);
	if (markerSubpath && !fs.existsSync(path.join(nestedDir, markerSubpath))) {
		return;
	}
	for (const child of fs.readdirSync(nestedDir)) {
		fs.renameSync(path.join(nestedDir, child), path.join(targetDir, child));
	}
	try {
		fs.rmdirSync(nestedDir);
	} catch {}
}

export function resolveCapaReleaseAsset(
	platform: SkillToolPlatform,
	arch: string = process.arch,
): { url: string; sha256: string } {
	if (platform === "darwin") {
		return arch === "arm64" ? CAPA_RELEASE_ASSETS.darwin_arm64 : CAPA_RELEASE_ASSETS.darwin_x64;
	}
	if (platform === "linux") {
		return arch === "arm64" ? CAPA_RELEASE_ASSETS.linux_arm64 : CAPA_RELEASE_ASSETS.linux_x64;
	}
	return CAPA_RELEASE_ASSETS.win32_x64;
}

// ============================================================================
// 版本解析与 Kaitai 编译器/运行时兼容性判断
// ============================================================================

export function parseMajorMinorVersion(
	raw: string | null | undefined,
): { major: number; minor: number; patch: number } | null {
	if (!raw) return null;
	const match = String(raw)
		.trim()
		.match(/v?(\d+)\.(\d+)(?:\.(\d+))?/i);
	if (!match) return null;
	const major = Number.parseInt(match[1], 10);
	const minor = Number.parseInt(match[2], 10);
	const patch = match[3] ? Number.parseInt(match[3], 10) : 0;
	if (Number.isNaN(major) || Number.isNaN(minor) || Number.isNaN(patch)) return null;
	return { major, minor, patch };
}

/**
 * 校验 kaitai-struct-compiler 与 Python kaitaistruct 运行时的真实版本兼容性。
 * 0.11+ 编译器生成的代码检查 API_VERSION >= (0, 11)，旧版 0.10 运行时无法加载。
 */
export function checkKaitaiVersionCompatibility(
	compilerVersion: string | null | undefined,
	runtimeVersion: string | null | undefined,
	runtimeApiVersion?: string | null,
): { compatible: boolean; reason?: string } {
	const comp = parseMajorMinorVersion(compilerVersion);
	if (!comp) {
		return {
			compatible: false,
			reason: `Unable to parse kaitai-struct-compiler version (${String(compilerVersion ?? "unknown")}).`,
		};
	}
	const rt = parseMajorMinorVersion(runtimeVersion);
	if (!rt) {
		return {
			compatible: false,
			reason: `Unable to parse kaitaistruct Python runtime version (${String(runtimeVersion ?? "unknown")}).`,
		};
	}
	if (comp.major === 0 && comp.minor < 9) {
		return {
			compatible: false,
			reason: `kaitai-struct-compiler ${compilerVersion} is unsupported; >= ${KAITAI_COMPILER_MIN_VERSION} is required.`,
		};
	}
	if (rt.major === 0 && rt.minor < 9) {
		return {
			compatible: false,
			reason: `kaitaistruct Python runtime ${runtimeVersion} is unsupported; >= ${KAITAISTRUCT_MIN_VERSION} is required.`,
		};
	}
	if (comp.major !== rt.major) {
		return {
			compatible: false,
			reason: `Major version mismatch between kaitai-struct-compiler (${compilerVersion}) and kaitaistruct runtime (${runtimeVersion}).`,
		};
	}
	if (comp.major === 0 && comp.minor >= 11) {
		const api = parseMajorMinorVersion(runtimeApiVersion) ?? rt;
		if (api.major === 0 && api.minor < comp.minor) {
			return {
				compatible: false,
				reason: `kaitai-struct-compiler ${compilerVersion} requires kaitaistruct Python runtime >= ${comp.major}.${comp.minor}, but selected Python environment has ${runtimeVersion}.`,
			};
		}
	}
	return { compatible: true };
}

// ============================================================================
// Kaitai Struct Compiler (JVM + --read-pos) 解析与安装
// ============================================================================

export function resolveJavaForKaitai(options?: ProtocolProbeBaseDeps): string | null {
	const platform = normalizePlatform(options?.platform);
	const env = getEffectiveProbeEnv(options);
	const whichFn = options?.which ?? $which;
	const isSyntheticWhich = options?.which !== undefined && options.which !== $which;
	const javaExe = platform === "win32" ? "java.exe" : "java";

	const javaHome = env.JAVA_HOME;
	if (javaHome) {
		const fromHome = path.join(javaHome, "bin", javaExe);
		if (isExecutableFile(fromHome, platform)) {
			return fromHome;
		}
	}

	const toolPaths = env.REVERSE_TOOL_PATHS;
	if (toolPaths) {
		for (const dir of toolPaths.split(path.delimiter).filter(Boolean)) {
			const cand = path.join(dir, javaExe);
			if (isExecutableFile(cand, platform)) {
				return cand;
			}
		}
	}

	const whichOpts: WhichOptions = {
		PATH: env.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	let found = whichFn("java", whichOpts);
	if (found === "/usr/bin/java" && (platform === "darwin" || process.platform === "darwin") && !isSyntheticWhich) {
		found = findRealDarwinJdk(env);
	}
	if (!found && platform === "darwin" && !isSyntheticWhich) {
		found = findRealDarwinJdk(env);
	}
	if (!found) return null;
	if (isSyntheticWhich) return found;
	return isExecutableFile(found, platform) ? found : null;
}

function locateKaitaiCompilerBinary(options?: KaitaiCompilerResolveOptions): string | null {
	const platform = normalizePlatform(options?.platform);
	const env = getEffectiveProbeEnv(options);
	const whichFn = options?.which ?? $which;
	const names =
		platform === "win32"
			? ["kaitai-struct-compiler.bat", "ksc.bat", "kaitai-struct-compiler.cmd", "kaitai-struct-compiler", "ksc"]
			: ["kaitai-struct-compiler", "ksc"];

	const checkTarget = (raw: string | undefined): string | null => {
		if (!raw) return null;
		if (isExecutableFile(raw, platform)) return path.resolve(raw);
		try {
			if (fs.existsSync(raw) && fs.statSync(raw).isDirectory()) {
				for (const name of names) {
					const inBin = path.join(raw, "bin", name);
					if (isExecutableFile(inBin, platform)) return path.resolve(inBin);
					const direct = path.join(raw, name);
					if (isExecutableFile(direct, platform)) return path.resolve(direct);
				}
			}
		} catch {}
		return null;
	};

	const fromExplicit = checkTarget(options?.compilerPath);
	if (fromExplicit) return fromExplicit;

	const fromEnv = checkTarget(env.KAITAI_STRUCT_COMPILER) ?? checkTarget(env.KSC_PATH);
	if (fromEnv) return fromEnv;

	if (shouldCheckManagedAgentDir(options)) {
		try {
			const agentDir = options?.agentDir ?? env.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
			const fromManaged = checkTarget(path.join(agentDir, "tools", "kaitai-struct-compiler"));
			if (fromManaged) return fromManaged;
		} catch {}
	}

	const toolPaths = env.REVERSE_TOOL_PATHS;
	if (toolPaths) {
		for (const dir of toolPaths.split(path.delimiter).filter(Boolean)) {
			const hit = checkTarget(dir) ?? checkTarget(path.join(dir, "kaitai-struct-compiler"));
			if (hit) return hit;
		}
	}

	const whichOpts: WhichOptions = {
		PATH: env.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	for (const name of names) {
		try {
			const cand = whichFn(name, whichOpts);
			if (cand && isExecutableFile(cand, platform)) {
				return cand;
			}
		} catch {}
	}

	return null;
}

/**
 * 解析并真实校验 kaitai-struct-compiler：验证 Java 运行时、--version 版本号（>= 0.9）及 --read-pos 参数支持。
 */
export function resolveKaitaiCompiler(options?: KaitaiCompilerResolveOptions): KaitaiCompilerProbeResult {
	const platform = normalizePlatform(options?.platform);
	const compilerBin = locateKaitaiCompilerBinary(options);
	const javaPath = resolveJavaForKaitai(options);

	if (!compilerBin) {
		return {
			available: false,
			binaryFound: false,
			javaReady: Boolean(javaPath),
			compatible: false,
			supportsReadPos: false,
			path: null,
			version: null,
			javaPath,
			secondaryMissing: javaPath ? ["kaitai-struct-compiler"] : ["kaitai-struct-compiler", "java"],
			error: "kaitai-struct-compiler executable not found.",
		};
	}

	if (!javaPath) {
		return {
			available: false,
			binaryFound: true,
			javaReady: false,
			compatible: false,
			supportsReadPos: false,
			path: compilerBin,
			version: null,
			javaPath: null,
			secondaryMissing: ["java"],
			error: "Java runtime (JRE/JDK) is required to run kaitai-struct-compiler.",
		};
	}

	const probeEnv = buildCleanProbeEnv(options?.env);
	const javaBinDir = path.dirname(javaPath);
	probeEnv.PATH = [javaBinDir, probeEnv.PATH ?? ""].filter(Boolean).join(path.delimiter);
	if (!probeEnv.JAVA_HOME && path.basename(javaBinDir).toLowerCase() === "bin") {
		probeEnv.JAVA_HOME = path.dirname(javaBinDir);
	}

	const timeoutMs = options?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
	const verProc = spawnProbeCommand(compilerBin, ["--version"], probeEnv, platform, timeoutMs);
	const verText = `${verProc.stdout ?? ""}\n${verProc.stderr ?? ""}`.trim();

	if (verProc.error || verProc.status !== 0) {
		const detail =
			verProc.error?.message ||
			verText ||
			(verProc.signal ? `terminated by ${verProc.signal}` : `exit status ${String(verProc.status)}`);
		return {
			available: false,
			binaryFound: true,
			javaReady: true,
			compatible: false,
			supportsReadPos: false,
			path: compilerBin,
			version: null,
			javaPath,
			secondaryMissing: ["kaitai-compiler-compatible"],
			error: `kaitai-struct-compiler failed '--version' check: ${detail}`,
		};
	}

	const verMatch = verText.match(/kaitai-struct-compiler\s+v?(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9._-]+)?)/i);
	const version = verMatch?.[1] ?? null;
	const parsedVer = parseMajorMinorVersion(version);
	if (!version || !parsedVer || (parsedVer.major === 0 && parsedVer.minor < 9)) {
		return {
			available: false,
			binaryFound: true,
			javaReady: true,
			compatible: false,
			supportsReadPos: false,
			path: compilerBin,
			version,
			javaPath,
			secondaryMissing: ["kaitai-compiler-compatible"],
			error: version
				? `kaitai-struct-compiler version ${version} is incompatible (requires >= ${KAITAI_COMPILER_MIN_VERSION}).`
				: `kaitai-struct-compiler '--version' did not report a valid compiler version (${verText || "empty output"}).`,
		};
	}

	const helpProc = spawnProbeCommand(compilerBin, ["--help"], probeEnv, platform, timeoutMs);
	const helpText = `${helpProc.stdout ?? ""}\n${helpProc.stderr ?? ""}`;
	const supportsReadPos = helpProc.status === 0 && helpText.includes("--read-pos");
	if (!supportsReadPos) {
		return {
			available: false,
			binaryFound: true,
			javaReady: true,
			compatible: false,
			supportsReadPos: false,
			path: compilerBin,
			version,
			javaPath,
			secondaryMissing: ["kaitai-compiler-compatible"],
			error: `kaitai-struct-compiler ${version} at ${compilerBin} does not support required '--read-pos' position tracking.`,
		};
	}

	return {
		available: true,
		binaryFound: true,
		javaReady: true,
		compatible: true,
		supportsReadPos: true,
		path: compilerBin,
		version,
		javaPath,
		secondaryMissing: [],
	};
}

export function probeKaitaiCompilerRequirement(
	deps?: KaitaiCompilerResolveOptions,
): { path: string; secondaryMissing?: string[]; adapterError?: string } | null {
	const res = resolveKaitaiCompiler(deps);
	if (!res.binaryFound || !res.path) return null;
	if (!res.available) {
		const nonJavaMissing = res.secondaryMissing.filter(id => id !== "java");
		return {
			path: res.path,
			...(nonJavaMissing.length > 0 ? { secondaryMissing: nonJavaMissing } : {}),
			adapterError: res.error,
		};
	}
	return { path: res.path };
}

/**
 * 下载并安装固定版本 Kaitai Struct Compiler 通用发行包到 <agentDir>/tools/kaitai-struct-compiler。
 * 强制校验 SHA-256、JAR/启动脚本完整性与 --read-pos 执行能力，失败时回滚。
 */
export async function installKaitaiCompiler(
	options: KaitaiCompilerInstallOptions = {},
): Promise<KaitaiCompilerInstallResult> {
	const platform = normalizePlatform(options.platform);
	const agentDir = options.agentDir ?? options.env?.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
	const baseToolsDir = path.join(agentDir, "tools");
	const installDir = path.join(baseToolsDir, "kaitai-struct-compiler");

	const javaPath = resolveJavaForKaitai(options);
	if (!javaPath) {
		const msg =
			"Java runtime (JRE/JDK) is required before installing kaitai-struct-compiler. Run 'reverse setup reverse java' first.";
		return { success: false, installDir, executablePath: null, message: msg, error: msg };
	}

	const existing = resolveKaitaiCompiler({ ...options, agentDir, platform });
	if (existing.available && existing.path && existing.path.startsWith(installDir)) {
		return {
			success: true,
			installDir,
			executablePath: existing.path,
			version: existing.version ?? KAITAI_COMPILER_VERSION,
			message: `kaitai-struct-compiler ${existing.version ?? KAITAI_COMPILER_VERSION} is already installed and verified in ${installDir}.`,
		};
	}

	fs.mkdirSync(baseToolsDir, { recursive: true });
	const stageDir = fs.mkdtempSync(path.join(baseToolsDir, ".stage-kaitai-compiler-"));
	let backupDir: string | null = null;

	try {
		const dl = await fetchBoundedBytes(KAITAI_COMPILER_ZIP_URL, {
			fetch: options.fetch,
			signal: options.signal,
			onChunk: options.onChunk,
		});
		if (!dl.ok) {
			return { success: false, installDir, executablePath: null, message: dl.error, error: dl.error };
		}

		const expectedSha256 = options.expectedSha256 ?? KAITAI_COMPILER_ZIP_SHA256;
		const digest = crypto.createHash("sha256").update(dl.bytes).digest("hex");
		if (digest.toLowerCase() !== expectedSha256.toLowerCase()) {
			const errMsg = `Checksum verification failed for kaitai-struct-compiler-${KAITAI_COMPILER_VERSION}.zip: expected ${expectedSha256}, got ${digest}`;
			return { success: false, installDir, executablePath: null, message: errMsg, error: errMsg };
		}

		await extractArchive({ bytes: dl.bytes, format: "zip" }, stageDir);
		flattenSingleRootSubdirectory(stageDir, "bin");

		const stageBinDir = path.join(stageDir, "bin");
		const stageLibDir = path.join(stageDir, "lib");
		const launcherUnix = path.join(stageBinDir, "kaitai-struct-compiler");
		const launcherWin = path.join(stageBinDir, "kaitai-struct-compiler.bat");

		const hasLibJar =
			fs.existsSync(stageLibDir) &&
			fs
				.readdirSync(stageLibDir)
				.some(entry => entry.toLowerCase().endsWith(".jar") && fs.statSync(path.join(stageLibDir, entry)).isFile());
		if (!hasLibJar || (!fs.existsSync(launcherUnix) && !fs.existsSync(launcherWin))) {
			const errMsg =
				"Downloaded kaitai-struct-compiler archive is missing required bin/kaitai-struct-compiler launcher or lib/*.jar files.";
			return { success: false, installDir, executablePath: null, message: errMsg, error: errMsg };
		}

		if (fs.existsSync(launcherUnix)) {
			fs.chmodSync(launcherUnix, 0o755);
		}

		const receipt = {
			id: "kaitai-struct-compiler",
			version: KAITAI_COMPILER_VERSION,
			sha256: digest,
			license: KAITAI_COMPILER_LICENSE,
			upstreamUrl: KAITAI_COMPILER_UPSTREAM_URL,
			downloadUrl: KAITAI_COMPILER_ZIP_URL,
			installedAt: new Date().toISOString(),
		};
		fs.writeFileSync(path.join(stageDir, "manifest.json"), JSON.stringify(receipt, null, 2));
		fs.writeFileSync(
			path.join(stageDir, "LICENSE-NOTICE.txt"),
			`Tool: kaitai-struct-compiler v${KAITAI_COMPILER_VERSION}\nLicense: ${KAITAI_COMPILER_LICENSE} (external standalone tool, not bundled)\nUpstream: ${KAITAI_COMPILER_UPSTREAM_URL}\n`,
		);

		if (fs.existsSync(installDir)) {
			backupDir = path.join(baseToolsDir, `.backup-kaitai-compiler-${process.pid}-${Date.now()}`);
			fs.renameSync(installDir, backupDir);
		}
		fs.renameSync(stageDir, installDir);

		const verified = resolveKaitaiCompiler({
			...options,
			agentDir,
			platform,
			compilerPath: installDir,
			timeoutMs: options.timeoutMs ?? 30_000,
		});
		if (!verified.available || !verified.path) {
			try {
				fs.rmSync(installDir, { recursive: true, force: true });
			} catch {}
			if (backupDir && fs.existsSync(backupDir)) {
				fs.renameSync(backupDir, installDir);
			}
			const errMsg =
				verified.error ??
				`Installed kaitai-struct-compiler into ${installDir}, but post-install verification failed.`;
			return { success: false, installDir, executablePath: null, message: errMsg, error: errMsg };
		}

		if (backupDir && fs.existsSync(backupDir)) {
			try {
				fs.rmSync(backupDir, { recursive: true, force: true });
			} catch {}
		}

		options.onChunk?.(
			`[kaitai-struct-compiler] Verified kaitai-struct-compiler ${verified.version} (--read-pos ready) in ${installDir}\n`,
		);
		return {
			success: true,
			installDir,
			executablePath: verified.path,
			version: verified.version ?? KAITAI_COMPILER_VERSION,
			message: `Successfully installed kaitai-struct-compiler ${verified.version ?? KAITAI_COMPILER_VERSION} into ${installDir}`,
		};
	} catch (err) {
		if (!fs.existsSync(installDir) && backupDir && fs.existsSync(backupDir)) {
			try {
				fs.renameSync(backupDir, installDir);
			} catch {}
		}
		const errMsg = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			installDir,
			executablePath: null,
			message: `Failed to install kaitai-struct-compiler: ${errMsg}`,
			error: errMsg,
		};
	} finally {
		if (fs.existsSync(stageDir)) {
			try {
				fs.rmSync(stageDir, { recursive: true, force: true });
			} catch {}
		}
	}
}

// ============================================================================
// Kaitai Struct Python Runtime (kaitaistruct) 探测与受管虚拟环境安装
// ============================================================================

const KAITAI_RUNTIME_PROBE_SCRIPT = [
	"import sys",
	"if sys.version_info < (3, 9):",
	"    print('KAITAI_UNSUPPORTED_PYTHON:' + sys.version.split()[0])",
	"    sys.exit(44)",
	"try:",
	"    import kaitaistruct",
	"    from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO",
	"except ModuleNotFoundError as exc:",
	"    missing_name = getattr(exc, 'name', '') or ''",
	"    if missing_name == 'kaitaistruct' or missing_name.startswith('kaitaistruct.') or 'kaitaistruct' in str(exc):",
	"        print('KAITAI_MISSING_MODULE:' + str(exc))",
	"        sys.exit(42)",
	"    print('KAITAI_IMPORT_ERROR:' + str(exc))",
	"    sys.exit(43)",
	"except Exception as exc:",
	"    print('KAITAI_IMPORT_ERROR:' + type(exc).__name__ + ': ' + str(exc))",
	"    sys.exit(43)",
	"if not hasattr(KaitaiStream, 'pos') or not hasattr(KaitaiStream, 'seek'):",
	"    print('KAITAI_IMPORT_ERROR:KaitaiStream missing required stream position methods')",
	"    sys.exit(43)",
	"ver = getattr(kaitaistruct, '__version__', None)",
	"if not ver:",
	"    try:",
	"        from importlib.metadata import version as _pkg_version",
	"        ver = _pkg_version('kaitaistruct')",
	"    except Exception:",
	"        ver = ''",
	"api_ver = getattr(kaitaistruct, 'API_VERSION', None)",
	"api_str = f'{api_ver[0]}.{api_ver[1]}' if isinstance(api_ver, tuple) and len(api_ver) >= 2 else str(ver or '')",
	"print('KAITAI_OK')",
	"print(str(ver or ''))",
	"print(api_str)",
	"print(str(getattr(kaitaistruct, '__file__', '')))",
].join("\n");

function isRunnablePython39(pythonPath: string, env: NodeJS.ProcessEnv, timeoutMs: number): boolean {
	try {
		if (!pythonPath || !fs.existsSync(pythonPath) || !fs.statSync(pythonPath).isFile()) return false;
		if (process.platform !== "win32") fs.accessSync(pythonPath, fs.constants.X_OK);
		const proc = child_process.spawnSync(
			pythonPath,
			["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"],
			{ cwd: os.tmpdir(), timeout: timeoutMs, stdio: ["ignore", "ignore", "ignore"], env, windowsHide: true },
		);
		return proc.status === 0;
	} catch {
		return false;
	}
}

function resolveKaitaiCandidateInterpreters(options?: KaitaiStructRequirementDeps): {
	env: Record<string, string | undefined>;
	platform: SkillToolPlatform;
	agentDir: string;
	candidates: Array<{ path: string; isolatedOnly: boolean }>;
	rawConfiguredPaths: string[];
} {
	const env = getEffectiveProbeEnv(options);
	const platform = normalizePlatform(options?.platform);
	const agentDir = options?.agentDir ?? env.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
	const cwd = options?.cwd ?? process.cwd();
	const whichFn = options?.which ?? $which;
	const isSyntheticWhich = options?.which !== undefined && options.which !== $which;
	const venvExe = platform === "win32" ? "Scripts/python.exe" : "bin/python";
	const managedVenvPython = path.join(agentDir, "tools", "kaitaistruct-venv", venvExe);
	const cleanEnv = buildCleanProbeEnv(env);

	const explicitSelected = options?.pythonPath?.trim() || env.KAITAI_PYTHON?.trim();
	if (explicitSelected) {
		const resolvedExplicit = resolveExplicitPythonRuntime(explicitSelected, cwd, env).pythonPath;
		return {
			env,
			platform,
			agentDir,
			candidates: [{ path: resolvedExplicit, isolatedOnly: false }],
			rawConfiguredPaths: [resolvedExplicit],
		};
	}

	const candidates: Array<{ path: string; isolatedOnly: boolean }> = [];
	const seen = new Set<string>();
	const addCandidate = (p: string | null | undefined, isolatedOnly: boolean) => {
		if (!p) return;
		const norm = path.resolve(p);
		if (seen.has(norm)) return;
		seen.add(norm);
		candidates.push({ path: norm, isolatedOnly });
	};

	if (shouldCheckManagedAgentDir(options) && fs.existsSync(managedVenvPython)) {
		addCandidate(managedVenvPython, true);
	}

	let configuredSettingsInterp = "";
	try {
		configuredSettingsInterp = options?.settings ? cfgPythonInterpreter.get(options.settings).trim() : "";
	} catch {}

	if (configuredSettingsInterp) {
		const resolvedConfigured = resolveExplicitPythonRuntime(configuredSettingsInterp, cwd, env).pythonPath;
		addCandidate(resolvedConfigured, false);
		return {
			env,
			platform,
			agentDir,
			candidates,
			rawConfiguredPaths: [managedVenvPython, resolvedConfigured],
		};
	}

	const generalCandidates: string[] = [];
	const pushGeneral = (p: string | null | undefined) => {
		if (!p) return;
		const norm = path.resolve(p);
		if (!generalCandidates.includes(norm)) generalCandidates.push(norm);
	};

	if (env.VIRTUAL_ENV) {
		pushGeneral(
			path.join(
				env.VIRTUAL_ENV,
				platform === "win32" ? "Scripts" : "bin",
				platform === "win32" ? "python.exe" : "python",
			),
		);
	}

	const whichOpts: WhichOptions = {
		PATH: env.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	if (!isSyntheticWhich) {
		try {
			for (const rt of enumeratePythonRuntimes(cwd, env)) {
				pushGeneral(rt.pythonPath);
			}
		} catch {}
	}
	for (const bin of ["python3", "python"]) {
		try {
			const resolved = whichFn(bin, whichOpts);
			if (resolved) pushGeneral(resolved);
		} catch {}
	}

	const selectedGeneral =
		generalCandidates.find(cand => isRunnablePython39(cand, cleanEnv, options?.timeoutMs ?? 2500)) ??
		generalCandidates[0] ??
		null;
	if (selectedGeneral) {
		addCandidate(selectedGeneral, false);
	}

	return {
		env,
		platform,
		agentDir,
		candidates,
		rawConfiguredPaths: [
			env.KAITAI_PYTHON ?? "",
			managedVenvPython,
			configuredSettingsInterp,
			env.VIRTUAL_ENV ?? "",
			env.CONDA_PREFIX ?? "",
		],
	};
}

export function computeKaitaiStructReadinessFingerprint(options?: KaitaiStructRequirementDeps): string {
	const { env, platform, agentDir, candidates, rawConfiguredPaths } = resolveKaitaiCandidateInterpreters(options);
	const parts: string[] = [
		`platform:${platform}`,
		`agentDir:${agentDir}`,
		`pythonPath:${options?.pythonPath ?? ""}`,
		`KAITAI_PYTHON:${env.KAITAI_PYTHON ?? ""}`,
		`VIRTUAL_ENV:${env.VIRTUAL_ENV ?? ""}`,
		`CONDA_PREFIX:${env.CONDA_PREFIX ?? ""}`,
		`PATH:${env.PATH ?? ""}`,
	];
	for (const raw of rawConfiguredPaths) {
		if (raw) parts.push(`cfg:${statSignature(raw)}`);
	}
	for (const cand of candidates) {
		parts.push(`bin:${statSignature(cand.path)}`);
	}
	return parts.join("|");
}

export function probePythonForKaitaiStructDetailed(
	pythonPath: string,
	env?: Record<string, string | undefined>,
	options?: { timeoutMs?: number; isolatedOnly?: boolean },
): {
	status: "available" | KaitaiStructProbeFailureKind;
	result: KaitaiStructProbeResult | null;
	error?: string;
} {
	try {
		if (!pythonPath || !fs.existsSync(pythonPath) || !fs.statSync(pythonPath).isFile()) {
			return {
				status: "missing_interpreter",
				result: null,
				error: `Python interpreter does not exist: ${pythonPath}`,
			};
		}
		if (process.platform !== "win32") {
			try {
				fs.accessSync(pythonPath, fs.constants.X_OK);
			} catch {
				return {
					status: "missing_interpreter",
					result: null,
					error: `Python interpreter is not executable: ${pythonPath}`,
				};
			}
		}

		const probeEnv = buildCleanProbeEnv(env);
		const timeout = options?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
		const flagModes = options?.isolatedOnly ? [["-I"]] : [["-I"], ["-E"]];

		let sawMissingModule = false;
		let lastMissingError: string | undefined;
		let lastProbeError: string | undefined;

		for (const flags of flagModes) {
			const proc = child_process.spawnSync(pythonPath, [...flags, "-c", KAITAI_RUNTIME_PROBE_SCRIPT], {
				cwd: os.tmpdir(),
				timeout,
				stdio: ["ignore", "pipe", "pipe"],
				env: probeEnv,
				encoding: "utf8",
				windowsHide: true,
			});

			const stdout = typeof proc.stdout === "string" ? proc.stdout : "";
			const stderr = typeof proc.stderr === "string" ? proc.stderr : "";

			if (proc.error) {
				lastProbeError = `Subprocess probe failed for '${pythonPath}': ${proc.error.message}`;
				break;
			}
			if (proc.status === 44 || stdout.includes("KAITAI_UNSUPPORTED_PYTHON:")) {
				return {
					status: "incompatible_version",
					result: null,
					error: `Python interpreter '${pythonPath}' is older than required Python 3.9.`,
				};
			}
			if (proc.status === 0 && stdout.includes("KAITAI_OK")) {
				const lines = stdout.split("\n").map(l => l.trim());
				const okIdx = lines.indexOf("KAITAI_OK");
				const version = lines[okIdx + 1] || "";
				const apiVersion = lines[okIdx + 2] || version;
				const modulePath = lines[okIdx + 3] || "";
				const parsed = parseMajorMinorVersion(version);
				if (!parsed || (parsed.major === 0 && parsed.minor < 9)) {
					return {
						status: "incompatible_version",
						result: null,
						error: version
							? `kaitaistruct version ${version} in '${pythonPath}' is incompatible (requires >= ${KAITAISTRUCT_MIN_VERSION}).`
							: `kaitaistruct module in '${pythonPath}' did not expose a valid package version.`,
					};
				}
				return {
					status: "available",
					result: { pythonBin: pythonPath, version, apiVersion, modulePath },
				};
			}
			if (proc.status === 42 || stdout.includes("KAITAI_MISSING_MODULE:")) {
				sawMissingModule = true;
				const markerLine = stdout
					.split("\n")
					.map(l => l.trim())
					.find(l => l.startsWith("KAITAI_MISSING_MODULE:"));
				lastMissingError = markerLine
					? markerLine.slice("KAITAI_MISSING_MODULE:".length).trim()
					: "No module named 'kaitaistruct'";
				continue;
			}

			const detail =
				stdout.trim() ||
				stderr.trim() ||
				(proc.signal ? `terminated by signal ${proc.signal}` : `exited with status ${String(proc.status)}`);
			lastProbeError = `Probe runner failed on '${pythonPath}': ${detail}`;
			break;
		}

		if (lastProbeError) return { status: "probe_failed", result: null, error: lastProbeError };
		if (sawMissingModule) {
			return { status: "missing_module", result: null, error: lastMissingError ?? "No module named 'kaitaistruct'" };
		}
		return { status: "probe_failed", result: null, error: `Unknown kaitaistruct probe failure for '${pythonPath}'` };
	} catch (err) {
		return { status: "probe_failed", result: null, error: err instanceof Error ? err.message : String(err) };
	}
}

export function probePythonForKaitaiStruct(
	pythonPath: string,
	env?: Record<string, string | undefined>,
): KaitaiStructProbeResult | null {
	return probePythonForKaitaiStructDetailed(pythonPath, env).result;
}

export function resolveKaitaiStructPythonDetailed(
	options?: KaitaiStructRequirementDeps,
): KaitaiStructDetailedProbeResult {
	const { env, candidates } = resolveKaitaiCandidateInterpreters(options);
	const readinessFingerprint = computeKaitaiStructReadinessFingerprint(options);
	const checkedCandidates: string[] = [];
	let sawMissingModule = false;
	let lastMissingError: string | undefined;
	let incompatibleError: string | undefined;
	const probeErrors: string[] = [];

	for (const candidate of candidates) {
		if (!fs.existsSync(candidate.path)) continue;
		checkedCandidates.push(candidate.path);
		const detailed = probePythonForKaitaiStructDetailed(candidate.path, env, {
			timeoutMs: options?.timeoutMs,
			isolatedOnly: candidate.isolatedOnly,
		});
		if (detailed.status === "available" && detailed.result) {
			return {
				status: "available",
				available: true,
				deterministic: true,
				pythonBin: detailed.result.pythonBin,
				version: detailed.result.version,
				apiVersion: detailed.result.apiVersion ?? detailed.result.version,
				modulePath: detailed.result.modulePath,
				readinessFingerprint,
				checkedCandidates,
			};
		}
		if (detailed.status === "incompatible_version") {
			incompatibleError = detailed.error;
		} else if (detailed.status === "missing_module") {
			sawMissingModule = true;
			lastMissingError = detailed.error;
		} else if (detailed.status === "probe_failed" && detailed.error) {
			probeErrors.push(detailed.error);
		}
	}

	if (incompatibleError) {
		return {
			status: "incompatible_version",
			available: false,
			deterministic: true,
			pythonBin: checkedCandidates[0] ?? null,
			version: null,
			apiVersion: null,
			modulePath: null,
			error: incompatibleError,
			readinessFingerprint,
			checkedCandidates,
		};
	}
	if (probeErrors.length > 0) {
		return {
			status: "probe_failed",
			available: false,
			deterministic: false,
			pythonBin: checkedCandidates[0] ?? null,
			version: null,
			apiVersion: null,
			modulePath: null,
			error: probeErrors.join("; "),
			readinessFingerprint,
			checkedCandidates,
		};
	}
	if (sawMissingModule) {
		return {
			status: "missing_module",
			available: false,
			deterministic: true,
			pythonBin: checkedCandidates[0] ?? null,
			version: null,
			apiVersion: null,
			modulePath: null,
			error: lastMissingError ?? "No module named 'kaitaistruct'",
			readinessFingerprint,
			checkedCandidates,
		};
	}
	return {
		status: "missing_interpreter",
		available: false,
		deterministic: true,
		pythonBin: null,
		version: null,
		apiVersion: null,
		modulePath: null,
		error:
			options?.pythonPath || env.KAITAI_PYTHON
				? `Selected Python interpreter does not exist or is not runnable: ${options?.pythonPath ?? env.KAITAI_PYTHON}`
				: "No runnable Python 3.9+ interpreter found in managed kaitaistruct-venv or selected Python environment.",
		readinessFingerprint,
		checkedCandidates,
	};
}

export function resolveKaitaiStructPython(options?: KaitaiStructRequirementDeps): KaitaiStructProbeResult | null {
	const detailed = resolveKaitaiStructPythonDetailed(options);
	if (detailed.status !== "available" || !detailed.pythonBin) return null;
	return {
		pythonBin: detailed.pythonBin,
		version: detailed.version ?? KAITAISTRUCT_VERSION,
		apiVersion: detailed.apiVersion ?? detailed.version ?? KAITAISTRUCT_VERSION,
		modulePath: detailed.modulePath ?? "",
	};
}

export function probeKaitaiStructRequirement(
	deps?: KaitaiStructRequirementDeps,
): { path: string; secondaryMissing?: string[]; adapterError?: string } | null {
	const detailed = resolveKaitaiStructPythonDetailed(deps);
	if (!detailed.available || !detailed.pythonBin) {
		if (detailed.status === "incompatible_version" && detailed.pythonBin) {
			return {
				path: detailed.pythonBin,
				secondaryMissing: ["kaitaistruct-compatible"],
				adapterError: detailed.error,
			};
		}
		return null;
	}

	const compiler = resolveKaitaiCompiler(deps);
	if (compiler.available && compiler.version) {
		const compat = checkKaitaiVersionCompatibility(compiler.version, detailed.version, detailed.apiVersion);
		if (!compat.compatible) {
			return {
				path: detailed.pythonBin,
				secondaryMissing: ["kaitai-version-compatible"],
				adapterError: compat.reason,
			};
		}
	}
	return { path: detailed.pythonBin };
}

/**
 * 在受管目录 <agentDir>/tools/kaitaistruct-venv 创建隔离虚拟环境并安装 kaitaistruct==0.11。
 */
export async function installKaitaiStructVenv(
	options: KaitaiStructInstallOptions = {},
): Promise<KaitaiStructInstallResult> {
	const platform = normalizePlatform(options.platform);
	const agentDir = options.agentDir ?? options.env?.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
	const baseToolsDir = path.join(agentDir, "tools");
	const venvDir = path.join(baseToolsDir, "kaitaistruct-venv");
	const venvPython =
		platform === "win32" ? path.join(venvDir, "Scripts", "python.exe") : path.join(venvDir, "bin", "python");

	if (fs.existsSync(venvPython)) {
		const existing = probePythonForKaitaiStructDetailed(venvPython, options.env, { isolatedOnly: true });
		if (existing.status === "available" && existing.result) {
			return {
				success: true,
				pythonPath: venvPython,
				venvDir,
				message: `kaitaistruct is already installed and verified in ${venvDir} (${existing.result.version}).`,
				version: existing.result.version,
			};
		}
	}

	const whichFn = options.which ?? $which;
	const whichOptions: WhichOptions = {
		PATH: options.env?.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	let hostPython: string | null = null;
	for (const bin of ["python3", "python"]) {
		try {
			const p = whichFn(bin, whichOptions);
			if (p && fs.existsSync(p)) {
				const check = child_process.spawnSync(
					p,
					["-c", "import sys, venv; sys.exit(0 if sys.version_info >= (3, 9) else 1)"],
					{ timeout: 2500, windowsHide: true },
				);
				if (check.status === 0) {
					hostPython = p;
					break;
				}
			}
		} catch {}
	}

	if (!hostPython) {
		const msg =
			"Python 3.9+ interpreter with venv module not found. Run 'reverse setup reverse python' before installing kaitaistruct.";
		return { success: false, pythonPath: null, venvDir, message: msg, error: msg };
	}

	const execFn: SubprocessExecutor = options.executor ?? runSubprocess;
	fs.mkdirSync(baseToolsDir, { recursive: true });
	let backupDir: string | null = null;
	if (fs.existsSync(venvDir)) {
		backupDir = path.join(baseToolsDir, `.backup-kaitaistruct-venv-${process.pid}-${Date.now()}`);
		fs.renameSync(venvDir, backupDir);
	}

	try {
		options.onChunk?.(`[kaitaistruct] Creating isolated virtual environment in ${venvDir}...\n`);
		const venvRes = await execFn([hostPython, "-m", "venv", venvDir], {
			onChunk: options.onChunk,
			signal: options.signal,
			timeoutMs: 60_000,
			env: options.env,
		});
		if (venvRes.exitCode !== 0 || !fs.existsSync(venvPython)) {
			throw new Error(
				`Failed to create virtual environment: ${venvRes.stderr || venvRes.stdout || `exit code ${venvRes.exitCode}`}`,
			);
		}

		options.onChunk?.(`[kaitaistruct] Installing ${KAITAISTRUCT_PYPI_PACKAGE} into ${venvDir}...\n`);
		const pipRes = await execFn([venvPython, "-m", "pip", "install", "--upgrade", KAITAISTRUCT_PYPI_PACKAGE], {
			onChunk: options.onChunk,
			signal: options.signal,
			timeoutMs: 180_000,
			env: options.env,
		});
		if (pipRes.exitCode !== 0) {
			throw new Error(`pip install ${KAITAISTRUCT_PYPI_PACKAGE} failed: ${pipRes.stderr || pipRes.stdout}`);
		}

		const probed = probePythonForKaitaiStructDetailed(venvPython, options.env, { isolatedOnly: true });
		if (probed.status !== "available" || !probed.result) {
			throw new Error(probed.error ?? `kaitaistruct was installed into ${venvDir}, but import verification failed.`);
		}

		if (backupDir && fs.existsSync(backupDir)) {
			try {
				fs.rmSync(backupDir, { recursive: true, force: true });
			} catch {}
		}

		options.onChunk?.(`[kaitaistruct] Verified kaitaistruct ${probed.result.version} in ${venvDir}\n`);
		return {
			success: true,
			pythonPath: venvPython,
			venvDir,
			message: `Successfully installed kaitaistruct ${probed.result.version} into ${venvDir}`,
			version: probed.result.version,
		};
	} catch (err) {
		try {
			if (fs.existsSync(venvDir)) fs.rmSync(venvDir, { recursive: true, force: true });
		} catch {}
		if (backupDir && fs.existsSync(backupDir)) {
			try {
				fs.renameSync(backupDir, venvDir);
			} catch {}
		}
		const errMsg = err instanceof Error ? err.message : String(err);
		return { success: false, pythonPath: null, venvDir, message: errMsg, error: errMsg };
	}
}

export function resolveKaitaiToolchainReadiness(
	options?: KaitaiStructRequirementDeps & KaitaiCompilerResolveOptions,
): KaitaiToolchainReadiness {
	const compiler = resolveKaitaiCompiler(options);
	const runtime = resolveKaitaiStructPythonDetailed(options);
	const missingRequirements: string[] = [];
	const setupCommands: string[] = [];

	if (!compiler.javaReady) {
		missingRequirements.push("java");
		setupCommands.push("reverse setup reverse java");
	}
	if (!compiler.available) {
		missingRequirements.push("kaitai-struct-compiler");
		setupCommands.push("reverse setup reverse kaitai-struct-compiler --execute");
	}
	if (runtime.status === "missing_interpreter") {
		missingRequirements.push("python");
		setupCommands.push("reverse setup reverse python");
	}
	if (!runtime.available) {
		missingRequirements.push("kaitaistruct");
		setupCommands.push("reverse setup reverse kaitaistruct --execute");
	}

	let compatible = compiler.available && runtime.available;
	let incompatibilityReason: string | undefined;
	if (compiler.available && runtime.available) {
		const verCompat = checkKaitaiVersionCompatibility(compiler.version, runtime.version, runtime.apiVersion);
		compatible = verCompat.compatible;
		if (!verCompat.compatible) {
			incompatibilityReason = verCompat.reason;
			missingRequirements.push("kaitai-version-compatible");
			if (!setupCommands.includes("reverse setup reverse kaitaistruct --execute")) {
				setupCommands.push("reverse setup reverse kaitaistruct --execute");
			}
		}
	}

	return {
		ready: compiler.available && runtime.available && compatible,
		compatible,
		compiler,
		runtime,
		missingRequirements: [...new Set(missingRequirements)],
		...(incompatibilityReason ? { incompatibilityReason } : {}),
		setupCommands: [...new Set(setupCommands)],
	};
}

// ============================================================================
// capa 引擎与官方 capa-rules 规则库校验与安装
// ============================================================================

function looksLikeCapaRuleContent(content: string): boolean {
	return /^\s*rule\s*:/m.test(content) && /^\s*meta\s*:/m.test(content) && /^\s*features\s*:/m.test(content);
}

interface ScannedCapaRuleFile {
	absPath: string;
	relPath: string;
	sizeBytes: number;
}

function scanCapaRulesTreeStrict(
	rulesDir: string,
	options?: CapaRulesScanOptions,
):
	| { ok: true; rulesPath: string; files: ScannedCapaRuleFile[]; totalBytes: number }
	| { ok: false; rulesPath: string; error: string } {
	const maxDepth = options?.maxDepth ?? DEFAULT_MAX_RULE_SCAN_DEPTH;
	const maxFiles = options?.maxFiles ?? DEFAULT_MAX_RULE_SCAN_FILES;
	const maxFileBytes = options?.maxFileBytes ?? DEFAULT_MAX_RULE_FILE_BYTES;
	const maxTotalBytes = options?.maxTotalBytes ?? DEFAULT_MAX_RULE_TOTAL_BYTES;

	try {
		if (!rulesDir || !fs.existsSync(rulesDir)) {
			return {
				ok: false,
				rulesPath: rulesDir,
				error: `capa rules directory does not exist: ${rulesDir}`,
			};
		}
		const rootLstat = fs.lstatSync(rulesDir);
		if (rootLstat.isSymbolicLink()) {
			return {
				ok: false,
				rulesPath: rulesDir,
				error: `capa rules path must not be a symbolic link: ${rulesDir}`,
			};
		}
		const realDir = fs.realpathSync(rulesDir);
		if (!fs.statSync(realDir).isDirectory()) {
			return {
				ok: false,
				rulesPath: realDir,
				error: `capa rules path is not a directory: ${realDir}`,
			};
		}

		const files: ScannedCapaRuleFile[] = [];
		let totalBytes = 0;

		const visit = (dir: string, depth: number): string | null => {
			let entries: fs.Dirent[];
			try {
				entries = fs.readdirSync(dir, { withFileTypes: true });
			} catch (err) {
				return `Failed to read capa rules directory '${dir}': ${err instanceof Error ? err.message : String(err)}`;
			}
			entries.sort((a, b) => a.name.localeCompare(b.name));
			for (const entry of entries) {
				const full = path.join(dir, entry.name);
				if (entry.isSymbolicLink()) {
					return `Symbolic link is not allowed in capa rules directory: ${full}`;
				}
				if (entry.name === ".git" || entry.name === ".github" || entry.name === ".DS_Store") {
					continue;
				}
				if (entry.isDirectory()) {
					if (depth + 1 > maxDepth) {
						return `capa rules directory exceeds maximum nesting depth (${maxDepth}) at '${full}'.`;
					}
					const childErr = visit(full, depth + 1);
					if (childErr) return childErr;
				} else if (entry.isFile()) {
					const lower = entry.name.toLowerCase();
					if (!lower.endsWith(".yml") && !lower.endsWith(".yaml")) {
						continue;
					}
					if (files.length + 1 > maxFiles) {
						return `capa rules directory exceeds maximum rule file count (${maxFiles}).`;
					}
					let st: fs.Stats;
					try {
						st = fs.statSync(full);
					} catch (err) {
						return `Failed to stat capa rule file '${full}': ${err instanceof Error ? err.message : String(err)}`;
					}
					if (st.size > maxFileBytes) {
						return `capa rule file '${full}' (${st.size} bytes) exceeds per-file limit (${maxFileBytes} bytes).`;
					}
					totalBytes += st.size;
					if (totalBytes > maxTotalBytes) {
						return `capa rules directory total size (${totalBytes} bytes) exceeds aggregate limit (${maxTotalBytes} bytes).`;
					}
					files.push({
						absPath: full,
						relPath: path.relative(realDir, full).split(path.sep).join("/"),
						sizeBytes: st.size,
					});
				}
			}
			return null;
		};

		const walkErr = visit(realDir, 0);
		if (walkErr) {
			return { ok: false, rulesPath: realDir, error: walkErr };
		}
		files.sort((a, b) => a.relPath.localeCompare(b.relPath));
		return { ok: true, rulesPath: realDir, files, totalBytes };
	} catch (err) {
		return {
			ok: false,
			rulesPath: rulesDir,
			error: err instanceof Error ? err.message : String(err),
		};
	}
}

export function validateCapaRulesDir(rulesDir: string, options?: CapaRulesScanOptions): CapaRulesValidationResult {
	const scan = scanCapaRulesTreeStrict(rulesDir, options);
	if (!scan.ok) {
		return {
			valid: false,
			rulesPath: scan.rulesPath,
			ruleCount: 0,
			sampleRuleFiles: [],
			error: scan.error,
		};
	}
	if (scan.files.length === 0) {
		return {
			valid: false,
			rulesPath: scan.rulesPath,
			ruleCount: 0,
			sampleRuleFiles: [],
			error: `No .yml/.yaml rule files found in capa rules directory: ${scan.rulesPath}`,
		};
	}

	const validSamples: string[] = [];
	const sampleCount = Math.min(scan.files.length, RULE_READINESS_SAMPLE_LIMIT);
	for (let i = 0; i < sampleCount; i++) {
		const item = scan.files[i];
		let content: string;
		try {
			content = fs.readFileSync(item.absPath, "utf8");
		} catch (err) {
			return {
				valid: false,
				rulesPath: scan.rulesPath,
				ruleCount: 0,
				sampleRuleFiles: [],
				error: `Failed to read capa rule file '${item.absPath}': ${err instanceof Error ? err.message : String(err)}`,
			};
		}
		if (looksLikeCapaRuleContent(content)) {
			validSamples.push(item.relPath);
			if (validSamples.length >= 3) break;
		}
	}

	if (validSamples.length === 0) {
		return {
			valid: false,
			rulesPath: scan.rulesPath,
			ruleCount: 0,
			sampleRuleFiles: [],
			error: `Directory '${scan.rulesPath}' contains YAML files, but none match valid capa rule structure (rule/meta/features).`,
		};
	}

	return {
		valid: true,
		rulesPath: scan.rulesPath,
		ruleCount: scan.files.length,
		sampleRuleFiles: validSamples,
	};
}

export function computeCapaRulesManifest(rulesDir: string, options?: CapaRulesScanOptions): CapaRulesManifest | null {
	const maxFileBytes = options?.maxFileBytes ?? DEFAULT_MAX_RULE_FILE_BYTES;
	const maxTotalBytes = options?.maxTotalBytes ?? DEFAULT_MAX_RULE_TOTAL_BYTES;
	const scan = scanCapaRulesTreeStrict(rulesDir, options);
	if (!scan.ok || scan.files.length === 0) return null;

	const entries: Array<{ path: string; sha256: string; sizeBytes: number }> = [];
	let totalBytes = 0;
	let sawRuleStructure = false;

	for (let i = 0; i < scan.files.length; i++) {
		const item = scan.files[i];
		let raw: Buffer;
		try {
			raw = fs.readFileSync(item.absPath);
		} catch {
			return null;
		}
		if (raw.byteLength > maxFileBytes) {
			return null;
		}
		totalBytes += raw.byteLength;
		if (totalBytes > maxTotalBytes) {
			return null;
		}
		if (!sawRuleStructure && i < RULE_READINESS_SAMPLE_LIMIT && looksLikeCapaRuleContent(raw.toString("utf8"))) {
			sawRuleStructure = true;
		}
		const sha256 = crypto.createHash("sha256").update(raw).digest("hex");
		entries.push({ path: item.relPath, sha256, sizeBytes: raw.byteLength });
	}

	if (!sawRuleStructure) return null;

	const aggregate = crypto.createHash("sha256");
	for (const entry of entries) {
		aggregate.update(`${entry.path}:${entry.sha256}:${entry.sizeBytes}\n`);
	}

	return {
		rulesPath: scan.rulesPath,
		ruleCount: entries.length,
		manifestSha256: aggregate.digest("hex"),
		files: entries,
	};
}

function locateCapaBinary(options?: CapaResolveOptions): string | null {
	const platform = normalizePlatform(options?.platform);
	const env = getEffectiveProbeEnv(options);
	const whichFn = options?.which ?? $which;
	const names = platform === "win32" ? ["capa.exe", "capa.cmd", "capa.bat", "capa"] : ["capa"];

	const checkTarget = (raw: string | undefined): string | null => {
		if (!raw) return null;
		if (isExecutableFile(raw, platform)) return path.resolve(raw);
		try {
			if (fs.existsSync(raw) && fs.statSync(raw).isDirectory()) {
				for (const name of names) {
					const inBin = path.join(raw, "bin", name);
					if (isExecutableFile(inBin, platform)) return path.resolve(inBin);
					const direct = path.join(raw, name);
					if (isExecutableFile(direct, platform)) return path.resolve(direct);
				}
			}
		} catch {}
		return null;
	};

	const fromExplicit = checkTarget(options?.capaPath);
	if (fromExplicit) return fromExplicit;

	const fromEnv = checkTarget(env.CAPA_PATH) ?? checkTarget(env.CAPA_BIN);
	if (fromEnv) return fromEnv;

	if (shouldCheckManagedAgentDir(options)) {
		try {
			const agentDir = options?.agentDir ?? env.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
			const fromManaged = checkTarget(path.join(agentDir, "tools", "capa"));
			if (fromManaged) return fromManaged;
		} catch {}
	}

	const toolPaths = env.REVERSE_TOOL_PATHS;
	if (toolPaths) {
		for (const dir of toolPaths.split(path.delimiter).filter(Boolean)) {
			const hit = checkTarget(dir) ?? checkTarget(path.join(dir, "capa"));
			if (hit) return hit;
		}
	}

	const whichOpts: WhichOptions = {
		PATH: env.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	for (const name of names) {
		try {
			const cand = whichFn(name, whichOpts);
			if (cand && isExecutableFile(cand, platform)) return cand;
		} catch {}
	}
	return null;
}

/**
 * 解析并真实校验 capa 引擎及规则库：仅存在二进制而缺少有效规则时返回 rulesReady: false。
 */
export function resolveCapa(options?: CapaResolveOptions): CapaProbeResult {
	const platform = normalizePlatform(options?.platform);
	const env = getEffectiveProbeEnv(options);
	const capaBin = locateCapaBinary(options);

	if (!capaBin) {
		return {
			available: false,
			engineReady: false,
			rulesReady: false,
			path: null,
			version: null,
			rulesPath: null,
			ruleCount: 0,
			secondaryMissing: ["capa"],
			error: "capa executable not found.",
		};
	}

	const probeEnv = buildCleanProbeEnv(options?.env);
	const timeoutMs = options?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS;
	const verProc = spawnProbeCommand(capaBin, ["--version"], probeEnv, platform, timeoutMs);
	const verText = `${verProc.stdout ?? ""}\n${verProc.stderr ?? ""}`.trim();

	if (verProc.error || verProc.status !== 0) {
		const detail =
			verProc.error?.message ||
			verText ||
			(verProc.signal ? `terminated by ${verProc.signal}` : `exit status ${String(verProc.status)}`);
		return {
			available: false,
			engineReady: false,
			rulesReady: false,
			path: capaBin,
			version: null,
			rulesPath: null,
			ruleCount: 0,
			secondaryMissing: ["capa-engine"],
			error: `capa binary failed '--version' execution check: ${detail}`,
		};
	}

	const verMatch =
		verText.match(/\bcapa\s+v?(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9._-]+)?)/i) ??
		verText.match(/^v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)$/m);
	const version = verMatch?.[1] ?? null;
	if (!version) {
		return {
			available: false,
			engineReady: false,
			rulesReady: false,
			path: capaBin,
			version: null,
			rulesPath: null,
			ruleCount: 0,
			secondaryMissing: ["capa-engine"],
			error: `capa '--version' output did not contain a valid capa version (${verText || "empty output"}).`,
		};
	}

	const explicitRulesPath = options?.rulesPath?.trim() || env.CAPA_RULES_PATH?.trim() || env.CAPA_RULES_DIR?.trim();
	if (explicitRulesPath) {
		const checked = validateCapaRulesDir(explicitRulesPath);
		if (!checked.valid) {
			return {
				available: false,
				engineReady: true,
				rulesReady: false,
				path: capaBin,
				version,
				rulesPath: null,
				ruleCount: 0,
				secondaryMissing: ["capa-rules"],
				error: checked.error ?? `Configured capa rules directory is invalid: ${explicitRulesPath}`,
			};
		}
		return {
			available: true,
			engineReady: true,
			rulesReady: true,
			path: capaBin,
			version,
			rulesPath: checked.rulesPath,
			ruleCount: checked.ruleCount,
			secondaryMissing: [],
		};
	}

	const candidateRuleDirs: string[] = [];
	const pushRuleDir = (dir: string | undefined) => {
		if (!dir) return;
		const norm = path.resolve(dir);
		if (!candidateRuleDirs.includes(norm)) candidateRuleDirs.push(norm);
	};

	if (shouldCheckManagedAgentDir(options)) {
		try {
			const agentDir = options?.agentDir ?? env.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
			pushRuleDir(path.join(agentDir, "tools", "capa", "rules"));
		} catch {}
	}

	const addAdjacentRuleDirs = (binFile: string) => {
		const binDir = path.dirname(binFile);
		pushRuleDir(path.join(binDir, "rules"));
		pushRuleDir(path.join(binDir, "..", "rules"));
		pushRuleDir(path.join(binDir, "..", "share", "capa", "rules"));
	};
	addAdjacentRuleDirs(capaBin);
	try {
		const realBin = fs.realpathSync(capaBin);
		if (realBin !== capaBin) addAdjacentRuleDirs(realBin);
	} catch {}

	for (const ruleDir of candidateRuleDirs) {
		const checked = validateCapaRulesDir(ruleDir);
		if (checked.valid) {
			return {
				available: true,
				engineReady: true,
				rulesReady: true,
				path: capaBin,
				version,
				rulesPath: checked.rulesPath,
				ruleCount: checked.ruleCount,
				secondaryMissing: [],
			};
		}
	}

	return {
		available: false,
		engineReady: true,
		rulesReady: false,
		path: capaBin,
		version,
		rulesPath: null,
		ruleCount: 0,
		secondaryMissing: ["capa-rules"],
		error: "capa binary is runnable, but no valid capa rules directory (.yml rules) was found. Run 'reverse setup reverse capa --execute' or set CAPA_RULES_PATH.",
	};
}

export function probeCapaRequirement(
	deps?: CapaResolveOptions,
): { path: string; secondaryMissing?: string[]; adapterError?: string } | null {
	const res = resolveCapa(deps);
	if (!res.path) return null;
	if (!res.available) {
		return {
			path: res.path,
			secondaryMissing: res.secondaryMissing.length > 0 ? res.secondaryMissing : ["capa-rules"],
			adapterError: res.error,
		};
	}
	return { path: res.path };
}

function findExtractedCapaExecutable(dir: string, platform: SkillToolPlatform): string | null {
	const targetNames = platform === "win32" ? ["capa.exe", "capa"] : ["capa"];
	const visit = (current: string, depth: number): string | null => {
		if (depth > 3) return null;
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(current, { withFileTypes: true });
		} catch {
			return null;
		}
		for (const entry of entries) {
			if (entry.isFile() && targetNames.includes(entry.name.toLowerCase())) {
				return path.join(current, entry.name);
			}
		}
		for (const entry of entries) {
			if (entry.isDirectory() && !entry.name.startsWith(".")) {
				const nested = visit(path.join(current, entry.name), depth + 1);
				if (nested) return nested;
			}
		}
		return null;
	};
	return visit(dir, 0);
}

/**
 * 安装固定版本 Mandiant capa 引擎与官方 capa-rules 规则库至 <agentDir>/tools/capa。
 * 强制校验引擎发行包 SHA-256、进程可执行能力与规则目录完整性，失败时回滚。
 */
export async function installCapa(options: CapaInstallOptions = {}): Promise<CapaInstallResult> {
	const platform = normalizePlatform(options.platform);
	const agentDir = options.agentDir ?? options.env?.REVERSE_CODING_AGENT_DIR ?? getAgentDir();
	const baseToolsDir = path.join(agentDir, "tools");
	const installDir = path.join(baseToolsDir, "capa");

	const existing = resolveCapa({ ...options, agentDir, platform });
	if (existing.available && existing.path && existing.rulesPath && existing.path.startsWith(installDir)) {
		return {
			success: true,
			installDir,
			executablePath: existing.path,
			rulesPath: existing.rulesPath,
			version: existing.version ?? CAPA_VERSION,
			ruleCount: existing.ruleCount,
			message: `capa ${existing.version ?? CAPA_VERSION} and capa-rules (${existing.ruleCount} rules) are already installed in ${installDir}.`,
		};
	}

	fs.mkdirSync(baseToolsDir, { recursive: true });
	const stageDir = fs.mkdtempSync(path.join(baseToolsDir, ".stage-capa-"));
	let backupDir: string | null = null;

	try {
		const stageBinDir = path.join(stageDir, "bin");
		const stageRulesDir = path.join(stageDir, "rules");
		fs.mkdirSync(stageBinDir, { recursive: true });
		fs.mkdirSync(stageRulesDir, { recursive: true });

		const rulesDl = await fetchBoundedBytes(CAPA_RULES_ARCHIVE_URL, {
			fetch: options.fetch,
			signal: options.signal,
			onChunk: options.onChunk,
		});
		if (!rulesDl.ok) {
			return {
				success: false,
				installDir,
				executablePath: null,
				rulesPath: null,
				message: rulesDl.error,
				error: rulesDl.error,
			};
		}
		if (options.expectedRulesSha256) {
			const rulesDigest = crypto.createHash("sha256").update(rulesDl.bytes).digest("hex");
			if (rulesDigest.toLowerCase() !== options.expectedRulesSha256.toLowerCase()) {
				const errMsg = `Checksum verification failed for capa-rules archive: expected ${options.expectedRulesSha256}, got ${rulesDigest}`;
				return {
					success: false,
					installDir,
					executablePath: null,
					rulesPath: null,
					message: errMsg,
					error: errMsg,
				};
			}
		}

		const rulesFormat = rulesDl.bytes[0] === 0x50 && rulesDl.bytes[1] === 0x4b ? "zip" : "tar.gz";
		await extractArchive({ bytes: rulesDl.bytes, format: rulesFormat }, stageRulesDir);
		flattenSingleRootSubdirectory(stageRulesDir);

		const rulesCheck = validateCapaRulesDir(stageRulesDir);
		if (!rulesCheck.valid) {
			const errMsg = rulesCheck.error ?? "Downloaded capa-rules archive did not contain valid capa .yml rules.";
			return { success: false, installDir, executablePath: null, rulesPath: null, message: errMsg, error: errMsg };
		}

		const releaseAsset = resolveCapaReleaseAsset(platform, options.arch ?? process.arch);
		const engineDl = await fetchBoundedBytes(releaseAsset.url, {
			fetch: options.fetch,
			signal: options.signal,
			onChunk: options.onChunk,
		});
		if (!engineDl.ok) {
			return {
				success: false,
				installDir,
				executablePath: null,
				rulesPath: null,
				message: engineDl.error,
				error: engineDl.error,
			};
		}

		const expectedEngineSha256 = options.expectedEngineSha256 ?? releaseAsset.sha256;
		const engineDigest = crypto.createHash("sha256").update(engineDl.bytes).digest("hex");
		if (engineDigest.toLowerCase() !== expectedEngineSha256.toLowerCase()) {
			const errMsg = `Checksum verification failed for capa release archive: expected ${expectedEngineSha256}, got ${engineDigest}`;
			return { success: false, installDir, executablePath: null, rulesPath: null, message: errMsg, error: errMsg };
		}

		const extractEngineDir = path.join(stageDir, ".engine-extract");
		fs.mkdirSync(extractEngineDir, { recursive: true });
		const engineFormat = engineDl.bytes[0] === 0x50 && engineDl.bytes[1] === 0x4b ? "zip" : "tar.gz";
		await extractArchive({ bytes: engineDl.bytes, format: engineFormat }, extractEngineDir);
		const extractedExe = findExtractedCapaExecutable(extractEngineDir, platform);
		if (!extractedExe) {
			const errMsg = "Downloaded capa archive did not contain a capa executable.";
			return { success: false, installDir, executablePath: null, rulesPath: null, message: errMsg, error: errMsg };
		}

		const targetBin = path.join(stageBinDir, platform === "win32" ? "capa.exe" : "capa");
		fs.copyFileSync(extractedExe, targetBin);
		if (platform !== "win32") {
			fs.chmodSync(targetBin, 0o755);
		}
		fs.rmSync(extractEngineDir, { recursive: true, force: true });

		const manifest = computeCapaRulesManifest(stageRulesDir);
		const receipt = {
			id: "capa",
			version: CAPA_VERSION,
			engineSha256: engineDigest,
			rulesVersion: CAPA_RULES_VERSION,
			license: CAPA_LICENSE,
			rulesLicense: CAPA_RULES_LICENSE,
			upstreamUrl: CAPA_UPSTREAM_URL,
			rulesUpstreamUrl: CAPA_RULES_UPSTREAM_URL,
			ruleCount: manifest?.ruleCount ?? rulesCheck.ruleCount,
			rulesSha256: manifest?.manifestSha256 ?? null,
			installedAt: new Date().toISOString(),
		};
		fs.writeFileSync(path.join(stageDir, "manifest.json"), JSON.stringify(receipt, null, 2));
		fs.writeFileSync(
			path.join(stageDir, "LICENSE-NOTICE.txt"),
			`Tool: capa v${CAPA_VERSION} + capa-rules v${CAPA_RULES_VERSION}\nLicense: ${CAPA_LICENSE}\nUpstream: ${CAPA_UPSTREAM_URL} / ${CAPA_RULES_UPSTREAM_URL}\n`,
		);

		if (fs.existsSync(installDir)) {
			backupDir = path.join(baseToolsDir, `.backup-capa-${process.pid}-${Date.now()}`);
			fs.renameSync(installDir, backupDir);
		}
		fs.renameSync(stageDir, installDir);

		const verified = resolveCapa({
			...options,
			agentDir,
			platform,
			capaPath: installDir,
			rulesPath: path.join(installDir, "rules"),
			timeoutMs: options.timeoutMs ?? 30_000,
		});
		if (!verified.available || !verified.path || !verified.rulesPath) {
			try {
				fs.rmSync(installDir, { recursive: true, force: true });
			} catch {}
			if (backupDir && fs.existsSync(backupDir)) {
				fs.renameSync(backupDir, installDir);
			}
			const errMsg =
				verified.error ?? `capa staged into ${installDir}, but post-install engine/rules verification failed.`;
			return { success: false, installDir, executablePath: null, rulesPath: null, message: errMsg, error: errMsg };
		}

		if (backupDir && fs.existsSync(backupDir)) {
			try {
				fs.rmSync(backupDir, { recursive: true, force: true });
			} catch {}
		}

		options.onChunk?.(`[capa] Verified capa ${verified.version} and ${verified.ruleCount} rules in ${installDir}\n`);
		return {
			success: true,
			installDir,
			executablePath: verified.path,
			rulesPath: verified.rulesPath,
			version: verified.version ?? CAPA_VERSION,
			ruleCount: verified.ruleCount,
			rulesSha256: manifest?.manifestSha256,
			message: `Successfully installed capa ${verified.version ?? CAPA_VERSION} with ${verified.ruleCount} rules into ${installDir}`,
		};
	} catch (err) {
		if (!fs.existsSync(installDir) && backupDir && fs.existsSync(backupDir)) {
			try {
				fs.renameSync(backupDir, installDir);
			} catch {}
		}
		const errMsg = err instanceof Error ? err.message : String(err);
		return {
			success: false,
			installDir,
			executablePath: null,
			rulesPath: null,
			message: `Failed to install capa: ${errMsg}`,
			error: errMsg,
		};
	} finally {
		if (fs.existsSync(stageDir)) {
			try {
				fs.rmSync(stageDir, { recursive: true, force: true });
			} catch {}
		}
	}
}

// ============================================================================
// mitmproxy 解析与按动作精确门禁评估
// ============================================================================

export function resolveMitmproxy(options?: ProtocolProbeBaseDeps): MitmproxyResolveResult {
	const platform = normalizePlatform(options?.platform);
	const env = getEffectiveProbeEnv(options);
	const whichFn = options?.which ?? $which;
	const isSyntheticWhich = options?.which !== undefined && options.which !== $which;

	const extraDirs: string[] = [];
	const toolPaths = env.REVERSE_TOOL_PATHS;
	if (toolPaths) {
		for (const d of toolPaths.split(path.delimiter).filter(Boolean)) extraDirs.push(d);
	}
	if (!isSyntheticWhich && platform !== "win32") {
		extraDirs.push("/usr/local/bin", "/opt/homebrew/bin", path.join(os.homedir(), ".local", "bin"), "/snap/bin");
	}
	const searchPath = [env.PATH ?? "", ...extraDirs].filter(Boolean).join(platform === "win32" ? ";" : path.delimiter);
	const whichOpts: WhichOptions = {
		PATH: searchPath || undefined,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};

	const checkBin = (name: string): string | null => {
		const found = whichFn(name, whichOpts);
		if (!found) return null;
		return isSyntheticWhich || isExecutableFile(found, platform) ? found : null;
	};

	const mitmdumpPath = checkBin("mitmdump");
	const mitmproxyPath = checkBin("mitmproxy") ?? checkBin("mitmweb");
	const primary = mitmdumpPath ?? mitmproxyPath;
	return { available: primary !== null, path: primary, mitmdumpPath, mitmproxyPath };
}

export function evaluateProtocolToolActionDependencies(
	query: ProtocolActionDependencyQuery,
): ProtocolActionDependencyResult {
	const toolName = query.toolName.trim().toLowerCase();
	const action = query.action.trim().toLowerCase();

	if (action === "status") {
		return {
			ready: true,
			requiredTools: [],
			missingTools: [],
			setupCommands: [],
			details: {
				...(toolName === "format_inspect" ? { kaitai: resolveKaitaiToolchainReadiness(query) } : {}),
				...(toolName === "capability_inspect" ? { capa: resolveCapa(query) } : {}),
				...(toolName === "app_experiment" ? { mitmproxy: resolveMitmproxy(query) } : {}),
			},
		};
	}

	if (toolName === "app_experiment") {
		if (action === "network_compare" || action === "network_replay") {
			return { ready: true, requiredTools: [], missingTools: [], setupCommands: [] };
		}
		if (action === "network_import") {
			const fmt = (query.captureFormat ?? "").trim().toLowerCase();
			const inferredMitm =
				fmt === "mitm" || (!fmt && Boolean(query.capturePath?.trim().toLowerCase().endsWith(".mitm")));
			if (!inferredMitm) {
				return { ready: true, requiredTools: [], missingTools: [], setupCommands: [] };
			}
			const mitm = resolveMitmproxy(query);
			if (!mitm.available) {
				return {
					ready: false,
					requiredTools: ["mitmproxy"],
					missingTools: ["mitmproxy"],
					setupCommands: ["reverse setup reverse mitmproxy"],
					reason:
						"Importing .mitm flow captures requires mitmproxy (mitmdump) FlowReader; HAR imports work without mitmproxy.",
					details: { mitmproxy: mitm },
				};
			}
			return {
				ready: true,
				requiredTools: ["mitmproxy"],
				missingTools: [],
				setupCommands: [],
				details: { mitmproxy: mitm },
			};
		}
		if (action === "mitm_capture") {
			const mitm = resolveMitmproxy(query);
			if (!mitm.available) {
				return {
					ready: false,
					requiredTools: ["mitmproxy"],
					missingTools: ["mitmproxy"],
					setupCommands: ["reverse setup reverse mitmproxy"],
					reason: "Live MITM proxy capture requires mitmproxy (mitmdump).",
					details: { mitmproxy: mitm },
				};
			}
			return {
				ready: true,
				requiredTools: ["mitmproxy"],
				missingTools: [],
				setupCommands: [],
				details: { mitmproxy: mitm },
			};
		}
	}

	if (toolName === "capability_inspect") {
		if (action === "import") {
			return { ready: true, requiredTools: [], missingTools: [], setupCommands: [] };
		}
		if (action === "detect") {
			const capa = resolveCapa(query);
			if (!capa.available) {
				return {
					ready: false,
					requiredTools: ["capa"],
					missingTools: capa.engineReady ? ["capa", "capa-rules"] : ["capa"],
					setupCommands: ["reverse setup reverse capa --execute"],
					reason: capa.error,
					details: { capa },
				};
			}
			return { ready: true, requiredTools: ["capa"], missingTools: [], setupCommands: [], details: { capa } };
		}
	}

	if (toolName === "format_inspect") {
		if (action === "compile") {
			const compiler = resolveKaitaiCompiler(query);
			const runtime = resolveKaitaiStructPythonDetailed(query);
			const missing: string[] = [];
			const setupCommands: string[] = [];
			if (!compiler.javaReady) {
				missing.push("java");
				setupCommands.push("reverse setup reverse java");
			}
			if (!compiler.available) {
				missing.push("kaitai-struct-compiler");
				setupCommands.push("reverse setup reverse kaitai-struct-compiler --execute");
			}
			return {
				ready: compiler.available,
				requiredTools: ["java", "kaitai-struct-compiler"],
				missingTools: missing,
				setupCommands,
				...(compiler.error ? { reason: compiler.error } : {}),
				details: {
					kaitai: {
						ready: compiler.available,
						compatible: compiler.compatible,
						compiler,
						runtime,
						missingRequirements: missing,
						setupCommands,
					},
				},
			};
		}

		if (action === "parse" || action === "validate") {
			if (query.requiresCompile === true) {
				const kaitai = resolveKaitaiToolchainReadiness(query);
				return {
					ready: kaitai.ready,
					requiredTools: ["java", "kaitai-struct-compiler", "python", "kaitaistruct"],
					missingTools: kaitai.missingRequirements,
					setupCommands: kaitai.setupCommands,
					reason: kaitai.incompatibilityReason ?? kaitai.compiler.error ?? kaitai.runtime.error,
					details: { kaitai },
				};
			}

			const runtime = resolveKaitaiStructPythonDetailed(query);
			if (!runtime.available) {
				const missing = runtime.status === "missing_interpreter" ? ["python", "kaitaistruct"] : ["kaitaistruct"];
				const setupCommands =
					runtime.status === "missing_interpreter"
						? ["reverse setup reverse python", "reverse setup reverse kaitaistruct --execute"]
						: ["reverse setup reverse kaitaistruct --execute"];
				return {
					ready: false,
					requiredTools: ["python", "kaitaistruct"],
					missingTools: missing,
					setupCommands,
					reason: runtime.error,
				};
			}
			return { ready: true, requiredTools: ["python", "kaitaistruct"], missingTools: [], setupCommands: [] };
		}
	}

	return { ready: true, requiredTools: [], missingTools: [], setupCommands: [] };
}
