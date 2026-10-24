/**
 * Local IDA Pro install detection. IDA features (`read` views, the `ida` tool) are only
 * exposed when {@link cfgIdaAvailable} finds an install shipping idalib.
 *
 * Detection is synchronous because tool gating and prompt rendering are synchronous; it runs
 * once per settings input change (memoized by the registry), never per call.
 */
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $env, $which, getMCPConfigPath, getProjectDir, logger, type WhichOptions } from "@reverse/utils";
import { combine } from "../config/registry";
import type { Settings } from "../config/settings";
import {
	enumeratePythonRuntimes,
	filterEnv,
	type PythonRuntime,
	resolveExplicitPythonRuntime,
} from "../eval/py/runtime";
import { cfgIdaEnabled, cfgIdaInstallDir, cfgIdaPython } from "./settings";

export interface LocateIdaOptions {
	env?: Record<string, string | undefined>;
	platform?: NodeJS.Platform;
	which?: (cmd: string, options?: WhichOptions) => string | null;
	requireIdalib?: boolean;
	settings?: Settings;
	installDir?: string;
	python?: string;
	cwd?: string;
}
const IDA_BINARIES: Record<string, readonly string[]> = {
	win32: ["ida.exe", "idat.exe", "ida64.exe", "idat64.exe", "idaq.exe", "idaq64.exe", "idalib.dll"],
	darwin: ["ida", "ida64", "idat", "idat64", "libidalib.dylib"],
	linux: ["ida", "ida64", "idat", "idat64", "libidalib.so"],
};

const IDA_GUI_BINARIES: Record<string, readonly string[]> = {
	win32: ["ida.exe", "idat.exe", "ida64.exe", "idat64.exe", "idaq.exe", "idaq64.exe"],
	darwin: ["ida", "ida64", "idat", "idat64"],
	linux: ["ida", "ida64", "idat", "idat64"],
};

export function hasIdaGuiBinary(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const bins = IDA_GUI_BINARIES[platform] ?? IDA_GUI_BINARIES.linux;
	for (const b of bins) {
		try {
			const candidate = path.join(dir, b);
			if (fs.existsSync(candidate) && !fs.statSync(candidate).isDirectory()) {
				return true;
			}
		} catch {}
	}
	return false;
}
export function hasIdalib(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const idalib = platform === "darwin" ? "libidalib.dylib" : platform === "win32" ? "idalib.dll" : "libidalib.so";
	return fs.existsSync(path.join(dir, idalib));
}

export function hasIdaBinary(dir: string, platform: NodeJS.Platform = process.platform): boolean {
	const bins = IDA_BINARIES[platform] ?? IDA_BINARIES.linux;
	for (const b of bins) {
		try {
			const candidate = path.join(dir, b);
			if (fs.existsSync(candidate) && !fs.statSync(candidate).isDirectory()) {
				return true;
			}
		} catch {}
	}
	return false;
}

let memoizedRegistryDirs: string[] | null = null;

export function readRegistryIdaDirs(): string[] {
	if (process.platform !== "win32") return [];
	if (memoizedRegistryDirs !== null) return memoizedRegistryDirs;
	const dirs: string[] = [];
	const regQueries = [
		["query", "HKCU\\Software\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\WOW6432Node\\Hex-Rays\\IDA Pro", "/v", "InstallDir"],
		["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ida.exe"],
		["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ida.exe"],
		["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro_is1", "/v", "InstallLocation"],
		["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro_is1", "/v", "InstallLocation"],
	];
	for (const args of regQueries) {
		try {
			const res = execFileSync("reg.exe", args, {
				encoding: "utf8",
				timeout: 1000,
				stdio: ["ignore", "pipe", "ignore"],
			});
			for (const line of res.split(/\r?\n/)) {
				const match = line.match(/(?:InstallDir|InstallLocation|Path|\(Default\))\s+REG_\w+\s+([^\r\n]+)/i);
				if (match && match[1]) {
					let candidate = match[1].trim().replace(/^["']+|["']+$/g, "");
					if (candidate.toLowerCase().endsWith(".exe") || candidate.toLowerCase().endsWith(".bat")) {
						candidate = path.dirname(candidate);
					}
					if (candidate && !dirs.includes(candidate)) {
						dirs.push(candidate);
					}
				}
			}
		} catch {}
	}
	memoizedRegistryDirs = dirs;
	return dirs;
}

/** `Paths.ida-install-dir` from each `ida-config.json` idalib itself would consult, in order. */
function configuredInstallDirs(
	env: Record<string, string | undefined> = process.env,
	platform: NodeJS.Platform = process.platform,
): string[] {
	const idausr = env.IDAUSR ?? $env.IDAUSR ?? "";
	const userDirs = idausr.split(path.delimiter).filter(Boolean);
	const homedir = env.HOME ?? env.USERPROFILE ?? os.homedir();
	userDirs.push(
		platform === "win32"
			? path.join(env.APPDATA ?? path.join(homedir, "AppData", "Roaming"), "Hex-Rays", "IDA Pro")
			: path.join(homedir, ".idapro"),
	);
	const dirs: string[] = [];
	for (const userDir of userDirs) {
		try {
			const config: { Paths?: { "ida-install-dir"?: unknown } } = JSON.parse(
				fs.readFileSync(path.join(userDir, "ida-config.json"), "utf8"),
			);
			const dir = config.Paths?.["ida-install-dir"];
			if (typeof dir === "string" && dir) dirs.push(dir);
		} catch {
			// Missing or malformed config: idalib ignores it too.
		}
	}
	return dirs;
}

/** Children of `parent` whose names start with `prefix` (case-insensitive), newest version first. */
function childDirs(parent: string, prefix: string, suffix = ""): string[] {
	let names: string[];
	try {
		names = fs.readdirSync(parent);
	} catch {
		return [];
	}
	return names
		.filter(name => name.toLowerCase().startsWith(prefix))
		.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
		.map(name => path.join(parent, name, suffix));
}

/** Standard install locations per platform across drives. */
function defaultInstallDirs(
	platform: NodeJS.Platform = process.platform,
	env: Record<string, string | undefined> = process.env,
): string[] {
	switch (platform) {
		case "darwin":
			return [
				...childDirs("/Applications", "ida", "Contents/MacOS"),
				...childDirs(path.join(os.homedir(), "Applications"), "ida", "Contents/MacOS"),
			];
		case "win32": {
			const dirs: string[] = [];
			const progFiles = [
				env.ProgramFiles ?? "C:\\Program Files",
				env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
				env.ProgramW6432,
				"D:\\Program Files",
				"D:\\Program Files (x86)",
				"E:\\Program Files",
				"E:\\Program Files (x86)",
			].filter((d): d is string => typeof d === "string" && Boolean(d));

			for (const pf of progFiles) {
				dirs.push(...childDirs(pf, "ida"));
			}
			for (const drive of ["C:\\", "D:\\", "E:\\"]) {
				dirs.push(...childDirs(drive, "ida"));
			}
			if (env.LOCALAPPDATA) {
				dirs.push(...childDirs(path.join(env.LOCALAPPDATA, "Programs"), "ida"));
			}
			return dirs;
		}
		default:
			return [...childDirs(os.homedir(), "ida"), ...childDirs("/opt", "ida")];
	}
}

/**
 * Directory of a local IDA install that ships idalib, or undefined when none exists.
 * An explicit `configured` directory is authoritative: when it lacks idalib, nothing else is tried.
 * Otherwise checks `$IDADIR`, `ida-config.json`, then standard install locations.
 */
export function locateIdaInstall(configured?: string, options: LocateIdaOptions = {}): string | undefined {
	const targetPlatform = options.platform ?? process.platform;
	const env = options.env ?? process.env;
	const requireIdalib = options.requireIdalib ?? false;

	let effectiveConfigured = configured?.trim() || undefined;
	if (!effectiveConfigured && options.settings) {
		effectiveConfigured = cfgIdaInstallDir.get(options.settings)?.trim() || undefined;
	}

	if (effectiveConfigured) {
		if (hasIdalib(effectiveConfigured, targetPlatform)) {
			return effectiveConfigured;
		}
		if (!requireIdalib && hasIdaBinary(effectiveConfigured, targetPlatform)) {
			return effectiveConfigured;
		}
		logger.warn("ida.installDir has no idalib; IDA features stay hidden", {
			installDir: effectiveConfigured,
		});
		return undefined;
	}

	const whichFn = options.which ?? $which;
	const pathDirs: string[] = [];
	const bins =
		targetPlatform === "win32"
			? ["ida.exe", "ida", "ida64.exe", "ida64", "idat.exe", "idat"]
			: ["ida", "ida64", "idat"];
	for (const b of bins) {
		try {
			const found = whichFn(b);
			if (found && fs.existsSync(found)) {
				pathDirs.push(path.dirname(found));
				if (found.endsWith(".bat") || found.endsWith(".cmd")) {
					try {
						const content = fs.readFileSync(found, "utf8");
						const match =
							content.match(/"([^"]*ida(?:64|t|t64|q|q64)?\.exe)"/i) ||
							content.match(/([A-Za-z]:\\[^"'\r\n;]*ida(?:64|t|t64|q|q64)?\.exe)/i);
						if (match && match[1]) {
							const targetDir = path.dirname(match[1].trim());
							if (!pathDirs.includes(targetDir)) pathDirs.push(targetDir);
						}
					} catch {}
				}
				try {
					const real = fs.realpathSync(found);
					const realDir = path.dirname(real);
					if (!pathDirs.includes(realDir)) pathDirs.push(realDir);
				} catch {}
			}
		} catch {}
	}

	const registryDirs = targetPlatform === "win32" ? readRegistryIdaDirs() : [];
	const candidates = [
		options.env?.IDADIR ?? $env.IDADIR,
		...configuredInstallDirs(env, targetPlatform),
		...registryDirs,
		...pathDirs,
		...defaultInstallDirs(targetPlatform, env),
	].filter((dir): dir is string => typeof dir === "string" && dir.length > 0 && fs.existsSync(dir));

	const withIdalib = candidates.find(dir => hasIdalib(dir, targetPlatform));
	if (withIdalib) return withIdalib;

	if (requireIdalib) return undefined;

	return candidates.find(dir => hasIdaBinary(dir, targetPlatform));
}

/**
 * Probe IDA tool presence for the skill tool catalog (setup reverse / CLI).
 * First checks for an idalib-enabled installation via {@link locateIdaInstall}.
 * If absent, checks whether IDA GUI/CLI executables exist in candidate install paths
 * or on PATH via launcher scripts (e.g. ida.bat / ida.exe).
 */
export function probeIdaTool(options: LocateIdaOptions = {}): string | null {
	const idalibInstall = locateIdaInstall(undefined, options);
	if (idalibInstall) return idalibInstall;

	const targetPlatform = options.platform ?? process.platform;
	const env = options.env ?? process.env;

	if (options.which) {
		const bins =
			targetPlatform === "win32"
				? ["ida.exe", "ida", "ida64.exe", "ida64", "idat.exe", "idat"]
				: ["ida", "ida64", "idat"];
		for (const b of bins) {
			const found = options.which(b);
			if (found && fs.existsSync(found)) {
				return found;
			}
		}
	}

	const registryDirs = targetPlatform === "win32" ? readRegistryIdaDirs() : [];
	const candidates = [
		options.env?.IDADIR ?? $env.IDADIR,
		...configuredInstallDirs(env, targetPlatform),
		...registryDirs,
		...defaultInstallDirs(targetPlatform, env),
	].filter((dir): dir is string => typeof dir === "string" && dir.length > 0 && fs.existsSync(dir));

	return candidates.find(dir => hasIdaBinary(dir, targetPlatform)) ?? null;
}

export type IdaAdapterErrorType = "missing_package" | "import_error" | "unsupported_python" | "interpreter_unavailable";

export interface IdaPythonCandidateDiagnostic {
	pythonPath: string;
	version?: string;
	supportedVersion?: boolean;
	idaproImported?: boolean;
	domainImported?: boolean;
	missingPackages?: string[];
	errorType?: IdaAdapterErrorType;
	error?: string;
}

export interface IdaPythonProbeResult {
	success: boolean;
	runtime?: {
		pythonPath: string;
		env: Record<string, string>;
	};
	targetPython?: string;
	selectedCandidate?: IdaPythonCandidateDiagnostic;
	candidates: IdaPythonCandidateDiagnostic[];
	repairCommand?: {
		pythonPath: string;
		command: string;
		argv: string[];
	};
	errorReason?: string;
}

// 探测脚本说明（关键设计与调用语义）：
// 1. 标准输出重定向隔离：idalib/idapro 在初始化底层 C++ 库时可能会向 fd 1 输出各类版权与诊断 banner，
//    若直接使用 print 输出 JSON，会导致 banner 混入 stdout 进而使 JSON 解析崩溃。
//    因此预先将真正的 stdout (fd 1) 复制到私有句柄 _proto，并将 fd 1 重定向至 fd 2 (stderr)。
// 2. 严格按 worker.py 语义依序导入：worker.py 在启动时必须先 import idapro（加载 libidalib），
//    配置好信号拦截后才能 import ida_domain。颠倒顺序或仅检查 spec 会产生误报或导入失败。
// 3. 真实记录导入标志：必须在 Python 内部实际 try...import 成功后才置为 True，严禁在客户端根据 spec 状态捏造导入结果。
const PROBE_CODE = `
import os, sys, json, importlib.util

_proto = os.fdopen(os.dup(1), "w", encoding="utf-8")
os.dup2(2, 1)
v = sys.version_info
supported = (v.major > 3) or (v.major == 3 and v.minor >= 10)
ver_str = f"{v.major}.{v.minor}.{v.micro}"

spec_idapro = bool(importlib.util.find_spec("idapro"))
spec_domain = bool(importlib.util.find_spec("ida_domain"))

missing = []
if not spec_idapro:
    missing.append("idapro")
if not spec_domain:
    missing.append("ida-domain")

err = None
err_type = None
idapro_imported = False
domain_imported = False

if not supported:
    err_type = "unsupported_python"
    err = f"Python {ver_str} is unsupported; ida-domain requires Python >= 3.10 and IDA >= 9.1"
elif missing:
    err_type = "missing_package"
    missing_str = ", ".join(missing)
    err = f"Missing required Python adapter package(s): {missing_str}"
else:
    try:
        import idapro
        idapro_imported = True
        try:
            import ida_domain
            domain_imported = True
        except Exception as e:
            err_type = "import_error"
            err = f"Failed to import ida_domain: {e}"
    except Exception as e:
        err_type = "import_error"
        err = f"Failed to import idapro: {e}"

res = {
    "version": ver_str,
    "supported_version": supported,
    "has_idapro_spec": spec_idapro,
    "has_domain_spec": spec_domain,
    "idapro_imported": idapro_imported,
    "domain_imported": domain_imported,
    "missing_packages": missing,
    "error_type": err_type,
    "error": err,
    "ready": err_type is None and idapro_imported and domain_imported
}
_proto.write(json.dumps(res) + "\\n")
_proto.flush()
`;

function probeSingleCandidate(candidate: PythonRuntime, installDir: string, cwd: string): IdaPythonCandidateDiagnostic {
	const probeEnv: Record<string, string> = {};
	for (const key in candidate.env) {
		const val = candidate.env[key];
		if (typeof val === "string") probeEnv[key] = val;
	}
	probeEnv.PYTHONUNBUFFERED = "1";
	probeEnv.PYTHONIOENCODING = "utf-8";
	probeEnv.IDADIR = installDir;
	if ($env.IDAUSR) probeEnv.IDAUSR = $env.IDAUSR;

	try {
		const res = spawnSync(candidate.pythonPath, ["-c", PROBE_CODE], {
			cwd,
			env: probeEnv,
			timeout: 3000,
			encoding: "utf-8",
			windowsHide: true,
		});
		if (res.error || res.status !== 0 || res.signal) {
			const errOutput =
				res.error?.message ||
				(res.signal
					? `Process terminated with signal ${res.signal}`
					: res.stderr?.trim() || `Process exited with code ${res.status}`);
			return {
				pythonPath: candidate.pythonPath,
				errorType: "interpreter_unavailable",
				error: errOutput,
				missingPackages: [],
			};
		}
		const stdout = res.stdout?.trim();
		if (stdout) {
			try {
				const parsed = JSON.parse(stdout);
				return {
					pythonPath: candidate.pythonPath,
					version: parsed.version,
					supportedVersion: Boolean(parsed.supported_version),
					idaproImported: Boolean(parsed.idapro_imported),
					domainImported: Boolean(parsed.domain_imported),
					missingPackages: Array.isArray(parsed.missing_packages) ? parsed.missing_packages : [],
					errorType: parsed.error_type ?? undefined,
					error: parsed.error ?? undefined,
				};
			} catch {}
		}
		const errOutput = res.stderr?.trim() || `Process exited with code ${res.status}`;
		return {
			pythonPath: candidate.pythonPath,
			errorType: "interpreter_unavailable",
			error: errOutput,
			missingPackages: [],
		};
	} catch (e) {
		return {
			pythonPath: candidate.pythonPath,
			errorType: "interpreter_unavailable",
			error: e instanceof Error ? e.message : String(e),
			missingPackages: [],
		};
	}
}

export function probeIdaPythonEnvironment(options: {
	python?: string;
	installDir: string;
	cwd?: string;
	env?: Record<string, string | undefined>;
	settings?: Settings;
}): IdaPythonProbeResult {
	const cwd = options.cwd ?? getProjectDir();
	// 使用原生工作进程的环境，避免项目 dotenv 中的 Python 路径造成就绪误报。
	const baseEnv = filterEnv(options.env ?? options.settings?.getShellConfig().env ?? process.env);
	const python =
		options.python?.trim() ||
		(options.settings ? cfgIdaPython.get(options.settings)?.trim() : undefined) ||
		undefined;

	const candidates: PythonRuntime[] = python
		? [resolveExplicitPythonRuntime(python, cwd, baseEnv)]
		: enumeratePythonRuntimes(cwd, baseEnv);
	if (candidates.length === 0) {
		return {
			success: false,
			candidates: [],
			errorReason: "No Python interpreter found on PATH or virtual environments.",
		};
	}

	const diagnostics: IdaPythonCandidateDiagnostic[] = [];
	let readyCandidate: PythonRuntime | undefined;
	let readyDiagnostic: IdaPythonCandidateDiagnostic | undefined;

	for (const candidate of candidates) {
		const diag = probeSingleCandidate(candidate, options.installDir, cwd);
		diagnostics.push(diag);
		if (!diag.errorType) {
			readyCandidate = candidate;
			readyDiagnostic = diag;
			break;
		}
	}

	if (readyCandidate && readyDiagnostic) {
		const runtimeEnv: Record<string, string> = {};
		for (const key in readyCandidate.env) {
			const val = readyCandidate.env[key];
			if (typeof val === "string") runtimeEnv[key] = val;
		}
		runtimeEnv.PYTHONUNBUFFERED = "1";
		runtimeEnv.PYTHONIOENCODING = "utf-8";
		runtimeEnv.IDADIR = options.installDir;
		if ($env.IDAUSR) runtimeEnv.IDAUSR = $env.IDAUSR;

		return {
			success: true,
			runtime: {
				pythonPath: readyCandidate.pythonPath,
				env: runtimeEnv,
			},
			targetPython: readyCandidate.pythonPath,
			selectedCandidate: readyDiagnostic,
			candidates: diagnostics,
		};
	}

	const primary = diagnostics[0];
	const targetPython = primary.pythonPath;
	let repairCommand: { pythonPath: string; command: string; argv: string[] } | undefined;
	if (primary.supportedVersion && primary.errorType === "missing_package") {
		repairCommand = {
			pythonPath: targetPython,
			command: `${targetPython} -m pip install ida-domain==0.5.1`,
			argv: [targetPython, "-m", "pip", "install", "ida-domain==0.5.1"],
		};
	}

	return {
		success: false,
		targetPython,
		selectedCandidate: primary,
		candidates: diagnostics,
		repairCommand,
		errorReason: primary.error ?? "No Python candidate could import idapro and ida_domain.",
	};
}

export function probeIdaRequirement(
	options: LocateIdaOptions = {},
): string | { path: string; secondaryMissing?: string[]; adapterError?: string } | null {
	const idalibInstall = locateIdaInstall(options.installDir, { ...options, requireIdalib: true });
	if (idalibInstall) {
		const pyProbe = probeIdaPythonEnvironment({
			python: options.python,
			installDir: idalibInstall,
			cwd: options.cwd,
			env: options.env,
			settings: options.settings,
		});
		if (pyProbe.success) {
			return idalibInstall;
		}
		let secondaryMissing: string[];
		const errType = pyProbe.selectedCandidate?.errorType;
		if (errType === "missing_package") {
			const missing = pyProbe.selectedCandidate?.missingPackages;
			secondaryMissing = missing && missing.length > 0 ? [...missing] : ["ida-domain"];
		} else if (errType === "unsupported_python") {
			secondaryMissing = ["python>=3.10"];
		} else if (errType === "import_error") {
			secondaryMissing = ["ida-python-adapter"];
		} else if (errType === "interpreter_unavailable") {
			secondaryMissing = ["python"];
		} else {
			secondaryMissing = ["ida-python-adapter"];
		}
		return {
			path: idalibInstall,
			secondaryMissing,
			adapterError: pyProbe.selectedCandidate?.error ?? pyProbe.errorReason,
		};
	}

	const guiCandidate = probeIdaTool(options);
	if (guiCandidate) {
		return {
			path: guiCandidate,
			secondaryMissing: ["idalib"],
		};
	}

	return null;
}

/** IDA install directory when `ida.enabled` is on and an install is found; undefined otherwise. */
export const cfgIdaInstall = combine(
	{ enabled: cfgIdaEnabled, installDir: cfgIdaInstallDir },
	({ enabled, installDir }) =>
		enabled ? locateIdaInstall(installDir?.trim() || undefined, { requireIdalib: true }) : undefined,
);

/** Whether IDA features (`read` views, the `ida` tool) are exposed. */
export const cfgIdaAvailable = cfgIdaInstall.map(dir => dir !== undefined);

export interface IdaBackendStatus {
	guiAvailable: boolean;
	guiPath?: string;
	idalibAvailable: boolean;
	idalibPath?: string;
	localDatabaseRecognized: boolean;
	localDatabaseBackendAvailable: boolean;
	localDatabaseSupported: boolean;
	pythonPath?: string;
	pythonVersion?: string;
	pythonSupported?: boolean;
	pythonAdapterReady?: boolean;
	missingPackages?: string[];
	adapterErrorType?: IdaAdapterErrorType;
	adapterError?: string;
	mcpBridgeConfigured: boolean;
	mcpBridgeConnected: boolean;
	bridgeAbsentReason?: string;
}

export function getIdaBackendStatus(
	options: LocateIdaOptions & {
		mcpManager?: {
			getConnectionStatus(name: string): string;
			getAllServerNames(): string[];
		};
		cwd?: string;
		agentDir?: string;
		readMcpConfig?: (path: string) => unknown;
	} = {},
): IdaBackendStatus {
	const targetPlatform = options.platform ?? process.platform;
	const idalibPath = locateIdaInstall(options.installDir, { ...options, requireIdalib: true });
	const idalibAvailable = Boolean(idalibPath);

	const rawGuiCandidate =
		locateIdaInstall(options.installDir, { ...options, requireIdalib: false }) ??
		(options.installDir ? undefined : probeIdaTool(options));
	const guiPath = rawGuiCandidate && hasIdaGuiBinary(rawGuiCandidate, targetPlatform) ? rawGuiCandidate : undefined;
	const guiAvailable = Boolean(guiPath);

	const localDatabaseRecognized = true;
	let pythonAdapterReady = false;
	let pythonPath: string | undefined;
	let pythonVersion: string | undefined;
	let pythonSupported: boolean | undefined;
	let missingPackages: string[] | undefined;
	let adapterErrorType: IdaAdapterErrorType | undefined;
	let adapterError: string | undefined;

	if (idalibAvailable && idalibPath) {
		const pyProbe = probeIdaPythonEnvironment({
			python: options.python,
			installDir: idalibPath,
			cwd: options.cwd,
			env: options.env,
			settings: options.settings,
		});
		pythonAdapterReady = pyProbe.success;
		const selected = pyProbe.selectedCandidate;
		pythonPath = pyProbe.targetPython ?? selected?.pythonPath;
		pythonVersion = selected?.version;
		pythonSupported = selected?.supportedVersion;
		if (selected?.missingPackages && selected.missingPackages.length > 0) {
			missingPackages = selected.missingPackages;
		}
		adapterErrorType =
			selected?.errorType ?? (pyProbe.candidates.length === 0 ? "interpreter_unavailable" : undefined);
		adapterError = selected?.error ?? pyProbe.errorReason;
	} else if (options.installDir) {
		adapterError = "No idalib library found in specified IDA install directory.";
	}

	const localDatabaseBackendAvailable = idalibAvailable && pythonAdapterReady;
	const localDatabaseSupported = idalibAvailable && pythonAdapterReady;
	let mcpBridgeConfigured = false;
	let mcpBridgeConnected = false;

	if (options.mcpManager) {
		const allNames = options.mcpManager.getAllServerNames();
		const matchedName = allNames.find(n => n.toLowerCase() === "ida-mcp" || n.toLowerCase() === "ida");
		if (matchedName) {
			mcpBridgeConfigured = true;
			mcpBridgeConnected = options.mcpManager.getConnectionStatus(matchedName) === "connected";
		}
	}

	if (!mcpBridgeConfigured) {
		try {
			const cwd = options.cwd ?? getProjectDir();
			const userConfigPath = options.agentDir
				? path.join(options.agentDir, "mcp.json")
				: getMCPConfigPath("user", cwd);
			const configPaths = [getMCPConfigPath("project", cwd), userConfigPath];
			const readFn =
				options.readMcpConfig ??
				(p => {
					try {
						return JSON.parse(fs.readFileSync(p, "utf8"));
					} catch {
						return null;
					}
				});
			for (const p of configPaths) {
				const cfg = readFn(p) as { mcpServers?: Record<string, unknown> } | null;
				if (cfg?.mcpServers && (cfg.mcpServers["ida-mcp"] || cfg.mcpServers["ida"])) {
					mcpBridgeConfigured = true;
					break;
				}
			}
		} catch {}
	}

	let bridgeAbsentReason: string | undefined;
	if (!mcpBridgeConfigured) {
		bridgeAbsentReason =
			"Direct MCP bridge 'ida-mcp' is not configured in mcp.json; IDA GUI and idalib operate independently when installed.";
	} else if (!mcpBridgeConnected) {
		bridgeAbsentReason = "Direct MCP bridge 'ida-mcp' is configured but not connected to an active IDA session.";
	}

	return {
		guiAvailable,
		guiPath,
		idalibAvailable,
		idalibPath: idalibPath ?? undefined,
		localDatabaseRecognized,
		localDatabaseBackendAvailable,
		localDatabaseSupported,
		pythonPath,
		pythonVersion,
		pythonSupported,
		pythonAdapterReady,
		...(missingPackages && missingPackages.length > 0 ? { missingPackages } : {}),
		...(adapterErrorType ? { adapterErrorType } : {}),
		...(adapterError ? { adapterError } : {}),
		mcpBridgeConfigured,
		mcpBridgeConnected,
		...(bridgeAbsentReason ? { bridgeAbsentReason } : {}),
	};
}
