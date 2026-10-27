/**
 * LIEF (Library to Instrument Executable Formats) Detection and Environment Resolver.
 *
 * Provides authoritative Python package discovery and managed isolated environment for LIEF:
 * - Detects LIEF via Python import (`import lief`) rather than assuming a PATH CLI exists
 * - Pinned version: 1.0.0 (Apache-2.0, official stable release supporting Python 3.9-3.12)
 * - Managed virtual environment installer (<agentDir>/tools/lief-venv) prevents global environment mutation
 * - Resolves exact Python runtime containing LIEF via a single combined subprocess probe
 * - Streams output and respects AbortSignal cancellation via runSubprocess
 */
import * as child_process from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy, type WhichOptions } from "@reverse/utils";
import { runSubprocess } from "./triton-source-install";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";

export const LIEF_VERSION = "1.0.0";
export const LIEF_PYPI_PACKAGE = "lief==1.0.0";
export const LIEF_LICENSE = "Apache-2.0";

export interface LiefProbeResult {
	pythonBin: string;
	version: string;
	modulePath: string;
}

export type LiefProbeFailureKind = "missing_interpreter" | "missing_module" | "probe_failed";

export interface LiefDetailedProbeResult {
	status: "available" | LiefProbeFailureKind;
	available: boolean;
	deterministic: boolean;
	pythonBin: string | null;
	version: string | null;
	modulePath: string | null;
	error?: string;
	readinessFingerprint: string;
	checkedCandidates: string[];
}

export interface LiefRequirementDeps {
	env?: Record<string, string | undefined>;
	which?: SkillRequirementWhich;
	agentDir?: string;
	platform?: SkillToolPlatform;
	cwd?: string;
	timeoutMs?: number;
}

function buildCleanProbeEnv(env?: Record<string, string | undefined>): NodeJS.ProcessEnv {
	const source = env !== undefined ? env : process.env;
	const clean: NodeJS.ProcessEnv = {};
	for (const [key, value] of Object.entries(source)) {
		if (typeof value === "string") {
			clean[key] = value;
		}
	}
	// 显式删除键而非赋值为 undefined，防止子进程环境变量被序列化为字符串 "undefined"
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

const USER_SITE_VERSION_RE = /^(?:python)?\d+(?:\.\d+)?$/i;

function appendSiteDirectorySignatures(siteDir: string, signatures: string[]): void {
	// 缺失目录记录为稳定 "missing" 标记，pip --user 创建后签名随之改变
	signatures.push(`sp:${statSignature(siteDir)}`);
	try {
		for (const entry of fs.readdirSync(siteDir)) {
			const lower = entry.toLowerCase();
			if (lower.startsWith("lief") || lower.startsWith("_lief")) {
				signatures.push(`lief-entry:${statSignature(path.join(siteDir, entry))}`);
			}
		}
	} catch {}
}

function collectUserSiteDirectories(
	env: Record<string, string | undefined>,
	pythonVersions: readonly string[],
): Set<string> {
	const siteDirs = new Set<string>();
	const home = env.HOME ?? env.USERPROFILE ?? os.homedir();
	const bases: Array<{ base: string; layout: "darwin" | "posix" | "win" }> = [
		{ base: path.join(home, "Library", "Python"), layout: "darwin" },
		{ base: path.join(home, ".local", "lib"), layout: "posix" },
	];
	if (env.APPDATA) bases.push({ base: path.join(env.APPDATA, "Python"), layout: "win" });
	if (env.LOCALAPPDATA) bases.push({ base: path.join(env.LOCALAPPDATA, "Python"), layout: "win" });
	if (env.PYTHONUSERBASE) {
		bases.push({ base: path.join(env.PYTHONUSERBASE, "lib"), layout: "posix" });
		bases.push({ base: env.PYTHONUSERBASE, layout: "win" });
	}

	// 有界列举：仅匹配版本命名条目，不递归用户目录树
	for (const { base, layout } of bases) {
		let entries: string[];
		try {
			entries = fs.readdirSync(base);
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (!USER_SITE_VERSION_RE.test(entry)) continue;
			const version = entry.replace(/^python/i, "");
			if (layout === "darwin") {
				siteDirs.add(path.join(base, entry, "lib", "python", "site-packages"));
			} else if (layout === "posix") {
				siteDirs.add(path.join(base, `python${version}`, "site-packages"));
				siteDirs.add(path.join(base, `python${version}`, "dist-packages"));
			} else {
				const winEntry = entry.startsWith("Python") ? entry : `Python${version.replace(/\./g, "")}`;
				siteDirs.add(path.join(base, winEntry, "site-packages"));
			}
		}
	}

	// pip --user 在无既有版本目录时仍会落到默认位置，故按已发现的解释器版本补充候选
	for (const version of pythonVersions) {
		siteDirs.add(path.join(home, ".local", "lib", `python${version}`, "site-packages"));
		siteDirs.add(path.join(home, ".local", "lib", `python${version}`, "dist-packages"));
		siteDirs.add(path.join(home, "Library", "Python", version, "lib", "python", "site-packages"));
	}

	return siteDirs;
}

function collectCandidateSitePackagesSignatures(pythonBin: string, env: Record<string, string | undefined>): string[] {
	const signatures: string[] = [];
	const candidateDirs = new Set<string>();
	const pythonVersions = new Set<string>();
	const binDir = path.dirname(pythonBin);
	const prefixDir =
		path.basename(binDir).toLowerCase() === "bin" || path.basename(binDir).toLowerCase() === "scripts"
			? path.dirname(binDir)
			: binDir;

	candidateDirs.add(path.join(prefixDir, "Lib", "site-packages"));
	candidateDirs.add(path.join(prefixDir, "site-packages"));

	for (const libSub of ["lib", "lib64"]) {
		const libRoot = path.join(prefixDir, libSub);
		try {
			for (const entry of fs.readdirSync(libRoot)) {
				if (!entry.toLowerCase().startsWith("python")) continue;
				const version = entry.replace(/^python/i, "");
				if (version) pythonVersions.add(version);
				candidateDirs.add(path.join(libRoot, entry, "site-packages"));
				candidateDirs.add(path.join(libRoot, entry, "dist-packages"));
			}
		} catch {}
	}

	for (const siteDir of collectUserSiteDirectories(env, [...pythonVersions])) {
		candidateDirs.add(siteDir);
	}

	for (const siteDir of candidateDirs) {
		appendSiteDirectorySignatures(siteDir, signatures);
	}

	return signatures;
}

function resolveCandidateInterpreters(options?: LiefRequirementDeps): {
	env: Record<string, string | undefined>;
	platform: SkillToolPlatform;
	agentDir: string;
	candidates: Array<{ path: string; isolatedOnly: boolean }>;
	rawConfiguredPaths: string[];
} {
	const env = (options?.env !== undefined ? options.env : process.env) as Record<string, string | undefined>;
	const platform =
		options?.platform ??
		(process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
	const agentDir = options?.agentDir ?? getAgentDir();
	const whichFn = options?.which ?? $which;
	const whichOptions: WhichOptions = {
		PATH: env?.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};

	const candidates: Array<{ path: string; isolatedOnly: boolean }> = [];
	const seen = new Set<string>();
	const addCandidate = (p: string | null | undefined, isolatedOnly: boolean) => {
		if (!p) return;
		const norm = path.resolve(p);
		if (seen.has(norm)) return;
		seen.add(norm);
		candidates.push({ path: norm, isolatedOnly });
	};

	if (env.LIEF_PYTHON) {
		addCandidate(env.LIEF_PYTHON, false);
	}

	const venvExecutable = platform === "win32" ? "Scripts/python.exe" : "bin/python";
	const managedVenvPython = path.join(agentDir, "tools", "lief-venv", venvExecutable);
	addCandidate(managedVenvPython, true);

	for (const bin of ["python3", "python"]) {
		try {
			const resolved = whichFn(bin, whichOptions);
			if (resolved) addCandidate(resolved, false);
		} catch {}
	}

	return {
		env,
		platform,
		agentDir,
		candidates,
		rawConfiguredPaths: [env.LIEF_PYTHON ?? "", managedVenvPython, env.VIRTUAL_ENV ?? "", env.CONDA_PREFIX ?? ""],
	};
}

/**
 * Cheap synchronous filesystem readiness fingerprint for LIEF candidate interpreters and site-packages.
 * Used to bound cached missing-prerequisite blocks without spawning subprocesses on every blocked check.
 */
export function computeLiefReadinessFingerprint(options?: LiefRequirementDeps): string {
	const { env, platform, agentDir, candidates, rawConfiguredPaths } = resolveCandidateInterpreters(options);
	const parts: string[] = [
		`platform:${platform}`,
		`agentDir:${agentDir}`,
		`LIEF_PYTHON:${env.LIEF_PYTHON ?? ""}`,
		`VIRTUAL_ENV:${env.VIRTUAL_ENV ?? ""}`,
		`CONDA_PREFIX:${env.CONDA_PREFIX ?? ""}`,
		`PATH:${env.PATH ?? ""}`,
	];
	for (const rawPath of rawConfiguredPaths) {
		if (rawPath) parts.push(`cfg:${statSignature(rawPath)}`);
	}
	for (const candidate of candidates) {
		parts.push(`bin:${statSignature(candidate.path)}`);
		for (const spSig of collectCandidateSitePackagesSignatures(candidate.path, env)) {
			parts.push(spSig);
		}
	}
	return parts.join("|");
}

const LIEF_PROBE_SCRIPT = [
	"import sys",
	"try:",
	"    import lief",
	"except ModuleNotFoundError as exc:",
	"    missing_name = getattr(exc, 'name', '') or ''",
	"    if missing_name == 'lief' or missing_name.startswith('lief.') or 'lief' in str(exc):",
	"        print('LIEF_MISSING_MODULE:' + str(exc))",
	"        sys.exit(42)",
	"    print('LIEF_IMPORT_ERROR:' + str(exc))",
	"    sys.exit(43)",
	"except Exception as exc:",
	"    print('LIEF_IMPORT_ERROR:' + type(exc).__name__ + ': ' + str(exc))",
	"    sys.exit(43)",
	"print('LIEF_OK')",
	"print(str(getattr(lief, '__version__', '1.0.0')))",
	"print(str(getattr(lief, '__file__', '')))",
].join("\n");

/**
 * Detailed single-interpreter LIEF probe distinguishing confirmed ModuleNotFoundError
 * from interpreter/subprocess execution failures.
 */
export function probePythonForLiefDetailed(
	pythonPath: string,
	env?: Record<string, string | undefined>,
	options?: { timeoutMs?: number; isolatedOnly?: boolean },
): {
	status: "available" | "missing_interpreter" | "missing_module" | "probe_failed";
	result: LiefProbeResult | null;
	error?: string;
} {
	try {
		if (!pythonPath || !fs.existsSync(pythonPath)) {
			return {
				status: "missing_interpreter",
				result: null,
				error: `Python interpreter does not exist: ${pythonPath}`,
			};
		}
		const stat = fs.statSync(pythonPath);
		if (!stat.isFile()) {
			return {
				status: "missing_interpreter",
				result: null,
				error: `Python interpreter path is not a file: ${pythonPath}`,
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
		const timeout = options?.timeoutMs ?? 4000;
		const flagModes = options?.isolatedOnly ? [["-I"]] : [["-I"], ["-E"]];

		let sawMissingModule = false;
		let lastMissingError: string | undefined;
		let lastProbeError: string | undefined;

		for (const flags of flagModes) {
			const proc = child_process.spawnSync(pythonPath, [...flags, "-c", LIEF_PROBE_SCRIPT], {
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

			if (proc.status === 0 && stdout.includes("LIEF_OK")) {
				const lines = stdout
					.split("\n")
					.map(l => l.trim())
					.filter(Boolean);
				const okIdx = lines.indexOf("LIEF_OK");
				return {
					status: "available",
					result: {
						pythonBin: pythonPath,
						version: lines[okIdx + 1] ?? LIEF_VERSION,
						modulePath: lines[okIdx + 2] ?? "",
					},
				};
			}

			if (proc.status === 42 || stdout.includes("LIEF_MISSING_MODULE:")) {
				sawMissingModule = true;
				const markerLine = stdout
					.split("\n")
					.map(l => l.trim())
					.find(l => l.startsWith("LIEF_MISSING_MODULE:"));
				lastMissingError = markerLine
					? markerLine.slice("LIEF_MISSING_MODULE:".length).trim()
					: "No module named 'lief'";
				continue;
			}

			const detail =
				stdout.trim() ||
				stderr.trim() ||
				(proc.signal ? `terminated by signal ${proc.signal}` : `exited with status ${String(proc.status)}`);
			lastProbeError = `Probe runner failed on '${pythonPath}': ${detail}`;
			break;
		}

		if (lastProbeError) {
			return {
				status: "probe_failed",
				result: null,
				error: lastProbeError,
			};
		}

		if (sawMissingModule) {
			return {
				status: "missing_module",
				result: null,
				error: lastMissingError ?? "No module named 'lief'",
			};
		}

		return {
			status: "probe_failed",
			result: null,
			error: `Unknown probe failure for '${pythonPath}'`,
		};
	} catch (err) {
		return {
			status: "probe_failed",
			result: null,
			error: err instanceof Error ? err.message : String(err),
		};
	}
}

export interface LiefInstallOptions {
	agentDir?: string;
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
}

export interface LiefInstallResult {
	success: boolean;
	pythonPath: string | null;
	venvDir: string;
	message: string;
	version?: string;
}

/**
 * Single combined subprocess probe: verifies import and extracts version + module path in one call.
 */
export function probePythonForLief(
	pythonPath: string,
	env?: Record<string, string | undefined>,
): LiefProbeResult | null {
	return probePythonForLiefDetailed(pythonPath, env).result;
}

/**
 * Probes whether a python executable contains the LIEF library.
 */
export function isLiefPython(pythonPath: string, env?: Record<string, string | undefined>): boolean {
	return probePythonForLief(pythonPath, env) !== null;
}

/**
 * Detailed resolution across candidate Python interpreters, distinguishing:
 * - 'available': LIEF imported and verified
 * - 'missing_module': Python interpreter(s) ran and confirmed ModuleNotFoundError for lief (deterministic)
 * - 'missing_interpreter': No runnable Python interpreter found on host (deterministic)
 * - 'probe_failed': Candidate interpreter existed but subprocess probe timed out / crashed / failed (transient/environmental)
 */
export function resolveLiefPythonDetailed(options?: LiefRequirementDeps): LiefDetailedProbeResult {
	const { env, candidates } = resolveCandidateInterpreters(options);
	const readinessFingerprint = computeLiefReadinessFingerprint(options);
	const checkedCandidates: string[] = [];
	let sawMissingModule = false;
	let lastMissingError: string | undefined;
	const probeErrors: string[] = [];

	for (const candidate of candidates) {
		if (!fs.existsSync(candidate.path)) continue;
		checkedCandidates.push(candidate.path);
		const detailed = probePythonForLiefDetailed(candidate.path, env, {
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
				modulePath: detailed.result.modulePath,
				readinessFingerprint,
				checkedCandidates,
			};
		}
		if (detailed.status === "missing_module") {
			sawMissingModule = true;
			lastMissingError = detailed.error;
		} else if (detailed.status === "probe_failed" && detailed.error) {
			probeErrors.push(detailed.error);
		}
	}

	if (probeErrors.length > 0) {
		return {
			status: "probe_failed",
			available: false,
			deterministic: false,
			pythonBin: checkedCandidates[0] ?? null,
			version: null,
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
			modulePath: null,
			error: lastMissingError ?? "No module named 'lief'",
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
		modulePath: null,
		error: "No runnable Python 3 interpreter found in LIEF_PYTHON, managed lief-venv, or PATH.",
		readinessFingerprint,
		checkedCandidates,
	};
}

/**
 * Resolve managed or host Python interpreter providing LIEF.
 * Single combined check per candidate; avoids duplicated subprocess invocations.
 */
export function resolveLiefPython(options?: LiefRequirementDeps): LiefProbeResult | null {
	const detailed = resolveLiefPythonDetailed(options);
	if (detailed.status !== "available" || !detailed.pythonBin) return null;
	return {
		pythonBin: detailed.pythonBin,
		version: detailed.version ?? LIEF_VERSION,
		modulePath: detailed.modulePath ?? "",
	};
}

/**
 * Probe function matching SkillToolDescriptor.probe signature for LIEF.
 */
export function probeLiefRequirement(
	deps?: LiefRequirementDeps,
): { path: string; version?: string; modulePath?: string } | null {
	const res = resolveLiefPython(deps);
	if (!res) return null;
	return {
		path: res.pythonBin,
		version: res.version,
		modulePath: res.modulePath,
	};
}

/**
 * Install LIEF into a managed isolated virtual environment in the agent directory.
 * Never mutates user global environments.
 */
export async function installLiefVenv(options: LiefInstallOptions = {}): Promise<LiefInstallResult> {
	const platform =
		options.platform ?? (process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
	const agentDir = options.agentDir ?? getAgentDir();
	const venvDir = path.join(agentDir, "tools", "lief-venv");
	const venvPython =
		platform === "win32" ? path.join(venvDir, "Scripts", "python.exe") : path.join(venvDir, "bin", "python");

	// Check if already satisfied in managed venv
	if (fs.existsSync(venvPython)) {
		const existing = probePythonForLief(venvPython, options.env);
		if (existing) {
			return {
				success: true,
				pythonPath: venvPython,
				venvDir,
				message: `LIEF is already installed and verified in ${venvDir} (${existing.version}).`,
				version: existing.version,
			};
		}
	}

	// Locate host python 3.9+ with venv module capability
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
					{ timeout: 2000, windowsHide: true },
				);
				if (check.status === 0) {
					hostPython = p;
					break;
				}
			}
		} catch {}
	}

	if (!hostPython) {
		return {
			success: false,
			pythonPath: null,
			venvDir,
			message:
				"Python 3.9+ interpreter with venv module not found. Please install Python 3.9+ before installing LIEF.",
		};
	}

	options.onChunk?.(`[lief] Creating isolated virtual environment in ${venvDir}...\n`);
	fs.mkdirSync(path.dirname(venvDir), { recursive: true });

	if (!fs.existsSync(venvPython)) {
		const venvRes = await runSubprocess([hostPython, "-m", "venv", venvDir], {
			onChunk: options.onChunk,
			signal: options.signal,
			timeoutMs: 60000,
		});
		if (venvRes.exitCode !== 0 || !fs.existsSync(venvPython)) {
			return {
				success: false,
				pythonPath: null,
				venvDir,
				message: `Failed to create virtual environment: ${venvRes.stderr || venvRes.stdout}`,
			};
		}
	}

	options.onChunk?.(`[lief] Installing ${LIEF_PYPI_PACKAGE} into virtual environment...\n`);
	const pipRes = await runSubprocess([venvPython, "-m", "pip", "install", "--upgrade", LIEF_PYPI_PACKAGE], {
		onChunk: options.onChunk,
		signal: options.signal,
		timeoutMs: 180000,
	});

	if (pipRes.exitCode !== 0) {
		return {
			success: false,
			pythonPath: null,
			venvDir,
			message: `pip install ${LIEF_PYPI_PACKAGE} failed: ${pipRes.stderr || pipRes.stdout}`,
		};
	}

	const probed = probePythonForLief(venvPython, options.env);
	if (!probed) {
		return {
			success: false,
			pythonPath: venvPython,
			venvDir,
			message: `LIEF was installed into ${venvDir}, but import verification failed.`,
		};
	}

	options.onChunk?.(`[lief] Successfully verified LIEF ${probed.version} in ${venvDir}\n`);
	return {
		success: true,
		pythonPath: venvPython,
		venvDir,
		message: `Successfully installed LIEF ${probed.version} into ${venvDir}`,
		version: probed.version,
	};
}
