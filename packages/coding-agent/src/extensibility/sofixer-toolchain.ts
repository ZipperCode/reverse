/**
 * SoFixer ELF Memory Dump Repair Toolchain Resolver and Installer.
 *
 * Upstream: F8LEFT/SoFixer (commit 75b8b63, tag v2.1.7, BSD-3-Clause).
 * Builds and resolves native 32-bit and 64-bit SoFixer executables:
 * - SoFixer64 (or sofixer64, sofixer): rebuilt with -DSO_64=ON for 64-bit ELF (.so)
 * - SoFixer32 (or sofixer32): rebuilt for 32-bit ELF (.so)
 * - Sets -DCMAKE_POLICY_VERSION_MINIMUM=3.5 to support modern CMake >= 3.30
 * - Strict user-declared architecture matching (never returns 64-bit binary when 32-bit is requested)
 * - Resolves from agent tools directory, SOFIXER_HOME, REVERSE_TOOL_PATHS, and system PATH
 * - Streams build output via runSubprocess with AbortSignal cancellation support
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy } from "@reverse/utils";
import { runSubprocess } from "./triton-source-install";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";

export const SOFIXER_VERSION = "2.1.7";
export const SOFIXER_RELEASE_TAG = "v2.1.7";
export const SOFIXER_COMMIT = "75b8b63fdb4da6b7a60ee514de2cf9d203979deb";
export const SOFIXER_REPO_URL = "https://github.com/F8LEFT/SoFixer.git";
export const SOFIXER_TAR_URL = `https://github.com/F8LEFT/SoFixer/archive/${SOFIXER_COMMIT}.tar.gz`;
export const SOFIXER_LICENSE = "BSD-3-Clause";

export interface SoFixerResolveOptions {
	/** Requested architecture: '32' | '64' | 'arm' | 'arm64' | etc. Defaults to '64'. */
	arch?: "arm" | "arm64" | "32" | "64" | string;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	agentDir?: string;
	cwd?: string;
}

export interface SoFixerResolved {
	path: string;
	arch: "32" | "64";
	version: string;
}

export interface SoFixerBuildOptions {
	agentDir?: string;
	sourceDir?: string;
	onLog?: (message: string) => void;
	signal?: AbortSignal;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	timeoutMs?: number;
}

export interface SoFixerBuildResult {
	success: boolean;
	installDir: string;
	binaries: string[];
	error?: string;
}

/**
 * Normalizes user-declared architecture string to '32' or '64'.
 */
export function normalizeSoFixerArch(arch?: string): "32" | "64" {
	if (!arch) return "64";
	const raw = String(arch).trim().toLowerCase();
	if (
		raw === "32" ||
		raw === "arm" ||
		raw === "armeabi" ||
		raw === "armeabi-v7a" ||
		raw === "armv7" ||
		raw === "x86" ||
		raw === "i386" ||
		raw === "i686"
	) {
		return "32";
	}
	return "64";
}

/**
 * Check if a file exists, is regular, and executable.
 */
function isExecutableFile(filePath: string, platform: SkillToolPlatform): boolean {
	try {
		if (!fs.existsSync(filePath)) return false;
		const stat = fs.statSync(filePath);
		if (!stat.isFile()) return false;
		if (platform === "win32") {
			return true;
		}
		fs.accessSync(filePath, fs.constants.X_OK);
		return true;
	} catch {
		return false;
	}
}

/**
 * Resolve SoFixer executable strictly matching the requested architecture (32 or 64).
 */
export function resolveSoFixer(options?: SoFixerResolveOptions): SoFixerResolved | null {
	const platform =
		options?.platform ??
		(process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
	const whichFn = options?.which ?? $which;
	const requestedArch = normalizeSoFixerArch(options?.arch);
	const ext = platform === "win32" ? ".exe" : "";

	const candidateNames =
		requestedArch === "32"
			? [`sofixer32${ext}`, `SoFixer32${ext}`, `sofixer_32${ext}`, `SoFixer_32${ext}`]
			: [
					`sofixer64${ext}`,
					`SoFixer64${ext}`,
					`sofixer_64${ext}`,
					`SoFixer_64${ext}`,
					`sofixer${ext}`,
					`SoFixer${ext}`,
				];

	const candidateDirs: string[] = [];

	// 1. Agent tools directory
	try {
		const agentDir = options?.agentDir ?? getAgentDir();
		candidateDirs.push(path.join(agentDir, "tools", "sofixer", "bin"));
		candidateDirs.push(path.join(agentDir, "tools", "sofixer"));
	} catch {}

	// 2. SOFIXER_HOME / SOFIXER_PATH
	const envHome = options?.env?.SOFIXER_HOME ?? process.env.SOFIXER_HOME;
	if (envHome) {
		candidateDirs.push(path.join(envHome, "bin"));
		candidateDirs.push(envHome);
	}
	// Check dedicated SOFIXER32_PATH / SOFIXER_32_PATH if 32-bit requested
	const envPath32 =
		options?.env?.SOFIXER32_PATH ??
		options?.env?.SOFIXER_32_PATH ??
		process.env.SOFIXER32_PATH ??
		process.env.SOFIXER_32_PATH;
	if (requestedArch === "32" && envPath32 && isExecutableFile(envPath32, platform)) {
		return { path: envPath32, arch: "32", version: SOFIXER_VERSION };
	}

	const envPath = options?.env?.SOFIXER_PATH ?? process.env.SOFIXER_PATH;
	if (envPath) {
		if (isExecutableFile(envPath, platform)) {
			// If pointed directly to executable, verify if naming or arch matches
			const baseName = path.basename(envPath).toLowerCase();
			if (requestedArch === "32" && baseName.includes("32")) {
				return { path: envPath, arch: "32", version: SOFIXER_VERSION };
			}
			// Generic (sofixer) or explicit 64-bit naming resolves only for 64-bit
			if (requestedArch === "64" && !baseName.includes("32")) {
				return { path: envPath, arch: "64", version: SOFIXER_VERSION };
			}
		} else {
			candidateDirs.push(envPath);
		}
	}

	// 3. REVERSE_TOOL_PATHS
	const toolPaths = options?.env?.REVERSE_TOOL_PATHS ?? process.env.REVERSE_TOOL_PATHS;
	if (toolPaths) {
		for (const d of toolPaths.split(path.delimiter).filter(Boolean)) {
			candidateDirs.push(d);
			candidateDirs.push(path.join(d, "sofixer", "bin"));
			candidateDirs.push(path.join(d, "sofixer"));
		}
	}

	// Check directories
	for (const dir of candidateDirs) {
		for (const name of candidateNames) {
			const cand = path.join(dir, name);
			if (isExecutableFile(cand, platform)) {
				return { path: cand, arch: requestedArch, version: SOFIXER_VERSION };
			}
		}
	}

	// Check PATH via whichFn
	for (const name of candidateNames) {
		try {
			const found = whichFn(name, { PATH: options?.env?.PATH, cache: WhichCachePolicy.Bypass });
			if (found && isExecutableFile(found, platform)) {
				return { path: found, arch: requestedArch, version: SOFIXER_VERSION };
			}
		} catch {}
	}

	return null;
}

/**
 * Check whether build prerequisites (cmake, C++ compiler) are present to build SoFixer.
 */
export function canBuildSoFixer(deps?: {
	which?: SkillRequirementWhich;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
}): {
	supported: boolean;
	missingPrereqs: string[];
	tools: { cmake: string | null; compiler: string | null };
} {
	const whichFn = deps?.which ?? $which;
	const whichOpts = { PATH: deps?.env?.PATH, cache: WhichCachePolicy.Bypass };
	const cmake = whichFn("cmake", whichOpts);
	const compiler =
		whichFn("clang++", whichOpts) ??
		whichFn("g++", whichOpts) ??
		whichFn("c++", whichOpts) ??
		(deps?.platform === "win32" ? whichFn("cl", whichOpts) : null);
	const missing: string[] = [];
	if (!cmake) missing.push("cmake");
	if (!compiler) missing.push("C++ compiler (clang++ or g++)");

	return {
		supported: missing.length === 0,
		missingPrereqs: missing,
		tools: { cmake, compiler },
	};
}

/**
 * Build SoFixer from source for both 32-bit and 64-bit, and install into the agent tools directory.
 */
export async function buildAndInstallSoFixer(options: SoFixerBuildOptions): Promise<SoFixerBuildResult> {
	const platform =
		options.platform ?? (process.platform === "win32" ? "win32" : process.platform === "darwin" ? "darwin" : "linux");
	const prereqs = canBuildSoFixer({ which: options.which, env: options.env, platform });
	if (!prereqs.supported) {
		return {
			success: false,
			installDir: "",
			binaries: [],
			error: `Cannot build SoFixer: missing required build tools: ${prereqs.missingPrereqs.join(", ")}. Please install them first.`,
		};
	}

	const agentDir = options.agentDir ?? getAgentDir();
	const installDir = path.join(agentDir, "tools", "sofixer");
	const binDir = path.join(installDir, "bin");
	const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), "reverse-sofixer-build-"));
	const stageSourceDir = path.join(stageDir, "source");

	try {
		if (options.sourceDir && fs.existsSync(options.sourceDir)) {
			// Copy user-provided source into private stage to avoid mutating user files
			options.onLog?.(`[sofixer] Staging source from ${options.sourceDir}...\n`);
			fs.cpSync(options.sourceDir, stageSourceDir, { recursive: true });
		} else {
			options.onLog?.(`[sofixer] Cloning upstream F8LEFT/SoFixer...\n`);
			const cloneRes = await runSubprocess(["git", "clone", SOFIXER_REPO_URL, stageSourceDir], {
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 60000,
			});
			if (cloneRes.exitCode !== 0) {
				return {
					success: false,
					installDir,
					binaries: [],
					error: `Failed to clone SoFixer repository: ${cloneRes.stderr || cloneRes.stdout}`,
				};
			}

			options.onLog?.(`[sofixer] Checking out pinned commit ${SOFIXER_COMMIT.slice(0, 8)}...\n`);
			const checkoutRes = await runSubprocess(["git", "checkout", SOFIXER_COMMIT], {
				cwd: stageSourceDir,
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 15000,
			});
			if (checkoutRes.exitCode !== 0) {
				return {
					success: false,
					installDir,
					binaries: [],
					error: `Failed to checkout SoFixer commit ${SOFIXER_COMMIT}: ${checkoutRes.stderr || checkoutRes.stdout}`,
				};
			}
		}

		fs.mkdirSync(binDir, { recursive: true });
		const ext = platform === "win32" ? ".exe" : "";

		// 1. Build 64-bit SoFixer
		options.onLog?.(`[sofixer] Compiling 64-bit SoFixer (-DSO_64=ON)...\n`);
		const build64Dir = path.join(stageDir, "build64");
		const cmake64 = await runSubprocess(
			["cmake", "-B", build64Dir, "-DSO_64=ON", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", stageSourceDir],
			{
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 120000,
			},
		);
		if (cmake64.exitCode !== 0) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `CMake configuration failed for 64-bit SoFixer: ${cmake64.stderr || cmake64.stdout}`,
			};
		}
		const make64 = await runSubprocess(["cmake", "--build", build64Dir, "--config", "Release"], {
			onChunk: options.onLog,
			signal: options.signal,
			timeoutMs: 180000,
		});
		if (make64.exitCode !== 0) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `Build failed for 64-bit SoFixer: ${make64.stderr || make64.stdout}`,
			};
		}

		// Locate built 64-bit binary
		const cand64 = [
			path.join(build64Dir, `SoFixer64${ext}`),
			path.join(build64Dir, `sofixer64${ext}`),
			path.join(build64Dir, `SoFixer${ext}`),
			path.join(build64Dir, `sofixer${ext}`),
			path.join(build64Dir, "Release", `SoFixer64${ext}`),
			path.join(build64Dir, "Release", `sofixer64${ext}`),
			path.join(build64Dir, "Release", `SoFixer${ext}`),
		].find(p => fs.existsSync(p));

		if (!cand64) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `64-bit SoFixer binary not found after build in ${build64Dir}`,
			};
		}

		// 2. Build 32-bit SoFixer
		options.onLog?.(`[sofixer] Compiling 32-bit SoFixer...\n`);
		const build32Dir = path.join(stageDir, "build32");
		const cmake32 = await runSubprocess(
			["cmake", "-B", build32Dir, "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", stageSourceDir],
			{
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 120000,
			},
		);
		if (cmake32.exitCode !== 0) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `CMake configuration failed for 32-bit SoFixer: ${cmake32.stderr || cmake32.stdout}`,
			};
		}
		const make32 = await runSubprocess(["cmake", "--build", build32Dir, "--config", "Release"], {
			onChunk: options.onLog,
			signal: options.signal,
			timeoutMs: 180000,
		});
		if (make32.exitCode !== 0) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `Build failed for 32-bit SoFixer: ${make32.stderr || make32.stdout}`,
			};
		}

		// Locate built 32-bit binary
		const cand32 = [
			path.join(build32Dir, `SoFixer32${ext}`),
			path.join(build32Dir, `sofixer32${ext}`),
			path.join(build32Dir, `SoFixer${ext}`),
			path.join(build32Dir, `sofixer${ext}`),
			path.join(build32Dir, "Release", `SoFixer32${ext}`),
			path.join(build32Dir, "Release", `sofixer32${ext}`),
			path.join(build32Dir, "Release", `SoFixer${ext}`),
		].find(p => fs.existsSync(p));

		if (!cand32) {
			return {
				success: false,
				installDir,
				binaries: [],
				error: `32-bit SoFixer binary not found after build in ${build32Dir}`,
			};
		}

		// Copy into binDir
		const target64 = path.join(binDir, `sofixer64${ext}`);
		const target32 = path.join(binDir, `sofixer32${ext}`);
		const targetDefault = path.join(binDir, `sofixer${ext}`);

		fs.copyFileSync(cand64, target64);
		fs.copyFileSync(cand32, target32);
		fs.copyFileSync(cand64, targetDefault);

		if (platform !== "win32") {
			fs.chmodSync(target64, 0o755);
			fs.chmodSync(target32, 0o755);
			fs.chmodSync(targetDefault, 0o755);
		}

		options.onLog?.(`[sofixer] Successfully built and installed SoFixer 32/64 to ${binDir}\n`);

		return {
			success: true,
			installDir,
			binaries: [`sofixer64${ext}`, `sofixer32${ext}`, `sofixer${ext}`],
		};
	} catch (err: unknown) {
		return {
			success: false,
			installDir,
			binaries: [],
			error: err instanceof Error ? err.message : String(err),
		};
	} finally {
		try {
			fs.rmSync(stageDir, { recursive: true, force: true });
		} catch {}
	}
}
