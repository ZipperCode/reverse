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

export interface LiefRequirementDeps {
	env?: Record<string, string | undefined>;
	which?: SkillRequirementWhich;
	agentDir?: string;
	platform?: SkillToolPlatform;
	cwd?: string;
	timeoutMs?: number;
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
	try {
		if (!pythonPath || !fs.existsSync(pythonPath)) return null;
		const stat = fs.statSync(pythonPath);
		if (!stat.isFile()) return null;
		if (process.platform !== "win32") {
			try {
				fs.accessSync(pythonPath, fs.constants.X_OK);
			} catch {
				return null;
			}
		}

		const probeCode =
			"import sys, lief; print('LIEF_OK'); print(str(getattr(lief, '__version__', '1.0.0'))); print(str(getattr(lief, '__file__', '')))";
		const proc = child_process.spawnSync(pythonPath, ["-I", "-c", probeCode], {
			cwd: os.tmpdir(),
			timeout: 2500,
			stdio: ["ignore", "pipe", "pipe"],
			env: {
				...(env ?? process.env),
				PYTHONPATH: undefined,
				PYTHONHOME: undefined,
			},
			encoding: "utf8",
		});

		if (proc.status === 0 && proc.stdout.includes("LIEF_OK")) {
			const lines = proc.stdout
				.split("\n")
				.map(l => l.trim())
				.filter(Boolean);
			return {
				pythonBin: pythonPath,
				version: lines[1] ?? LIEF_VERSION,
				modulePath: lines[2] ?? "",
			};
		}
		return null;
	} catch {
		return null;
	}
}

/**
 * Probes whether a python executable contains the LIEF library.
 */
export function isLiefPython(pythonPath: string, env?: Record<string, string | undefined>): boolean {
	return probePythonForLief(pythonPath, env) !== null;
}

/**
 * Resolve managed or host Python interpreter providing LIEF.
 * Single combined check per candidate; avoids duplicated subprocess invocations.
 */
export function resolveLiefPython(options?: LiefRequirementDeps): LiefProbeResult | null {
	const env = options?.env !== undefined ? options.env : process.env;
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

	// 1. LIEF_PYTHON env var
	if (env.LIEF_PYTHON && fs.existsSync(env.LIEF_PYTHON)) {
		const probed = probePythonForLief(env.LIEF_PYTHON, env);
		if (probed) return probed;
	}

	// 2. Managed virtual environment: <agentDir>/tools/lief-venv
	const venvExecutable = platform === "win32" ? "Scripts/python.exe" : "bin/python";
	const managedVenvPython = path.join(agentDir, "tools", "lief-venv", venvExecutable);
	if (fs.existsSync(managedVenvPython)) {
		const probed = probePythonForLief(managedVenvPython, env);
		if (probed) return probed;
	}

	// 3. System python candidates
	for (const bin of ["python3", "python"]) {
		const resolved = whichFn(bin, whichOptions);
		if (resolved && fs.existsSync(resolved)) {
			const probed = probePythonForLief(resolved, env);
			if (probed) return probed;
		}
	}

	return null;
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
