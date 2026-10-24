/**
 * Native Triton Binary Analysis Source-Build and Managed Toolchain Helper.
 *
 * Provides an isolated source compilation path for platforms without
 * official PyPI binary wheels (notably macOS arm64 / Apple Silicon):
 * - Pinned Triton GitHub commit & SHA256 (JonathanSalwan/Triton)
 * - Pinned native dependencies (capstone==5.0.9, z3-solver==5.3.1.0)
 * - Streaming archive download with cumulative 100 MiB safety cap and SHA256 check
 * - Relocatable dylib & RPATH configuration (@loader_path / $ORIGIN)
 * - Safe subprocess execution with gated process-tree termination and stream progress
 */
import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { $which } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import { filterEnv } from "../eval/py/runtime";

// Authoritative Triton release & source pin constants
export const TRITON_VERSION = "1.0.0rc4";
export const TRITON_SOURCE_VERSION = "1.0.0";
export const TRITON_PYPI_PACKAGE = "triton-library==1.0.0rc4";
export const TRITON_SOURCE_COMMIT = "bc84cf745e99768e07d51dcd734eba35c59f1b3e";
export const TRITON_SOURCE_RECEIPT_VERSION = `1.0.0+source.${TRITON_SOURCE_COMMIT.slice(0, 8)}`;
export const TRITON_SOURCE_URL = `https://github.com/JonathanSalwan/Triton/archive/${TRITON_SOURCE_COMMIT}.tar.gz`;
export const TRITON_SOURCE_SHA256 = "6d1dd43cb3c71c403c448140026d2f3f9d179e543089231c9f6d1269ea9b6bfb";

// Pinned build & solver wheel dependencies
export const TRITON_PINNED_CAPSTONE = "capstone==5.0.9";
export const TRITON_PINNED_Z3_SOLVER = "z3-solver==5.3.1.0";

// Safety limits
export const MAX_SOURCE_ARCHIVE_BYTES = 100 * 1024 * 1024; // 100 MiB limit
export const DEFAULT_BUILD_TIMEOUT_MS = 600_000; // 10 minutes

export interface TritonSourceBuildOptions {
	/** Working staging directory for extracting source and building artifacts. */
	stageDir: string;
	/** Target Python virtual environment directory. */
	venvDir: string;
	/** Selected python executable path inside the target venv. */
	pythonBin: string;
	/** Optional abort signal for user cancellation or lifecycle shutdown. */
	signal?: AbortSignal;
	/** Optional progress streaming callback. */
	onChunk?: (chunk: string) => void;
	/** Optional external subprocess executor to reuse shared runners. */
	executor?: (
		argv: readonly string[],
		options?: {
			cwd?: string;
			env?: Record<string, string | undefined>;
			onChunk?: (chunk: string) => void;
			signal?: AbortSignal;
		},
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
	/** Optional fetch override. */
	fetch?: (
		input: Parameters<typeof globalThis.fetch>[0],
		init?: Parameters<typeof globalThis.fetch>[1],
	) => Promise<Response>;
	/** Target platform (defaults to process.platform). */
	platform?: NodeJS.Platform;
	/** Target architecture (defaults to process.arch). */
	arch?: string;
	/** Optional custom which binary locator. */
	which?: (binary: string) => string | null;
	/** Environment variable overrides. */
	env?: Record<string, string | undefined>;
	/** Maximum timeout in milliseconds for the complete build step. */
	timeoutMs?: number;
}

export interface TritonSourceBuildResult {
	success: boolean;
	version: string;
	sourceCommit: string;
	modulePath?: string;
	error?: string;
	logs?: string[];
	llvmSupported?: boolean;
	z3Supported?: boolean;
}

export interface TritonSourcePrereqCheck {
	supported: boolean;
	reason?: string;
	missingPrereqs: string[];
	tools: {
		cmake: string | null;
		ninja: string | null;
		compiler: string | null;
		python: string | null;
	};
}

export function buildSubprocessEnv(customEnv?: Record<string, string | undefined>): NodeJS.ProcessEnv {
	const filtered = filterEnv({ ...process.env, ...customEnv });
	for (const key of ["CC", "CXX", "CMAKE_PREFIX_PATH", "SDKROOT", "DEVELOPER_DIR"] as const) {
		const val = customEnv?.[key] ?? process.env[key];
		if (val !== undefined) filtered[key] = val;
	}
	filtered.PYTHONNOUSERSITE = "1";
	delete filtered.PYTHONPATH;
	delete filtered.PYTHONHOME;
	return filtered as NodeJS.ProcessEnv;
}

/**
 * Downloads a remote archive stream up to maxBytes, enforcing cumulative size capping.
 */
export type FetchFunction = NonNullable<TritonSourceBuildOptions["fetch"]>;

/**
 * Downloads a remote archive stream up to maxBytes, enforcing cumulative size capping.
 */
async function fetchBoundedArchive(
	url: string,
	maxBytes: number,
	fetchFn: FetchFunction,
	signal?: AbortSignal,
): Promise<{ ok: true; bytes: Buffer } | { ok: false; error: string }> {
	const res = await fetchFn(url, { signal });
	if (!res.ok) {
		return { ok: false, error: `HTTP ${res.status} ${res.statusText}` };
	}
	const cl = res.headers.get("content-length");
	if (cl && Number.parseInt(cl, 10) > maxBytes) {
		return { ok: false, error: `Content-Length header ${cl} exceeds maximum limit of ${maxBytes} bytes.` };
	}
	if (!res.body) {
		return { ok: false, error: "Response body stream is empty." };
	}

	const reader = res.body.getReader();
	const chunks: Uint8Array[] = [];
	let receivedBytes = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				receivedBytes += value.byteLength;
				if (receivedBytes > maxBytes) {
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
}

/**
 * Executes a subprocess with bounded output capture, streaming chunks,
 * timeout, and gated process-tree termination before settlement.
 */
export async function runSubprocess(
	argv: readonly string[],
	options?: {
		cwd?: string;
		env?: Record<string, string | undefined>;
		onChunk?: (chunk: string) => void;
		signal?: AbortSignal;
		timeoutMs?: number;
	},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	const timeout = options?.timeoutMs ?? DEFAULT_BUILD_TIMEOUT_MS;
	const isWindows = process.platform === "win32";

	if (options?.signal?.aborted) {
		return { exitCode: 130, stdout: "", stderr: "Subprocess execution cancelled before launch." };
	}

	const { promise, resolve } = Promise.withResolvers<{ exitCode: number; stdout: string; stderr: string }>();
	let stdout = "";
	let stderr = "";
	let settled = false;
	let abortReason: { code: number; msg: string } | null = null;

	const maxCaptureBytes = 4 * 1024 * 1024;
	let child: child_process.ChildProcess | null = null;
	try {
		child = child_process.spawn(argv[0], argv.slice(1), {
			cwd: options?.cwd,
			env: buildSubprocessEnv(options?.env),
			stdio: ["ignore", "pipe", "pipe"],
			detached: !isWindows,
		});
	} catch (err) {
		return { exitCode: 1, stdout: "", stderr: `Failed to spawn ${argv[0]}: ${(err as Error).message}` };
	}

	let escalationTimer: NodeJS.Timeout | undefined;

	const terminateProcessTree = () => {
		if (!child || child.killed || child.pid === undefined) return;
		try {
			if (isWindows) {
				child_process.spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
			} else {
				process.kill(-child.pid, "SIGTERM");
				escalationTimer = setTimeout(() => {
					try {
						if (child && !child.killed && child.pid !== undefined) {
							process.kill(-child.pid, "SIGKILL");
						}
					} catch {}
				}, 500);
			}
		} catch {
			try {
				child.kill("SIGKILL");
			} catch {}
		}
	};

	const cleanup = () => {
		clearTimeout(timeoutTimer);
		clearTimeout(escalationTimer);
		if (options?.signal) options.signal.removeEventListener("abort", onAbort);
	};

	const onTimeout = () => {
		if (settled) return;
		abortReason = {
			code: 124,
			msg: `Command execution timed out after ${Math.round(timeout / 1000)}s: ${argv.join(" ")}`,
		};
		terminateProcessTree();
	};

	const onAbort = () => {
		if (settled) return;
		abortReason = { code: 130, msg: "Execution cancelled by signal." };
		terminateProcessTree();
	};

	const timeoutTimer = setTimeout(onTimeout, timeout);
	if (options?.signal) {
		options.signal.addEventListener("abort", onAbort, { once: true });
	}

	child.stdout?.on("data", chunk => {
		const text = String(chunk);
		stdout = stdout.length + text.length > maxCaptureBytes ? (stdout + text).slice(-maxCaptureBytes) : stdout + text;
		options?.onChunk?.(text);
	});

	child.stderr?.on("data", chunk => {
		const text = String(chunk);
		stderr = stderr.length + text.length > maxCaptureBytes ? (stderr + text).slice(-maxCaptureBytes) : stderr + text;
		options?.onChunk?.(text);
	});

	child.on("close", code => {
		if (!settled) {
			settled = true;
			cleanup();
			if (abortReason) {
				resolve({ exitCode: abortReason.code, stdout, stderr: `${stderr}\n${abortReason.msg}` });
			} else {
				resolve({ exitCode: code ?? 1, stdout, stderr });
			}
		}
	});

	child.on("error", err => {
		if (!settled) {
			settled = true;
			cleanup();
			resolve({ exitCode: 1, stdout, stderr: `${stderr}\n${err.message}` });
		}
	});

	return promise;
}

/**
 * Checks whether the current host satisfies native Triton source-build prerequisites.
 */
export function canBuildTritonFromSource(
	platform: NodeJS.Platform = process.platform,
	arch: string = process.arch,
	whichFn: (bin: string) => string | null = $which,
	pythonBin?: string,
): TritonSourcePrereqCheck {
	const missingPrereqs: string[] = [];

	const cmake = whichFn("cmake");
	if (!cmake) missingPrereqs.push("cmake");

	const ninja = whichFn("ninja");
	const make = platform === "win32" ? null : whichFn("make");
	if (!ninja && !make) missingPrereqs.push("ninja");

	let compiler: string | null = null;
	if (platform === "win32") {
		compiler = whichFn("cl") || whichFn("clang-cl") || whichFn("clang++");
		if (!compiler) missingPrereqs.push("cl / clang-cl (MSVC Build Tools)");
	} else if (platform === "darwin") {
		compiler = whichFn("clang++") || whichFn("c++") || whichFn("g++");
		if (!compiler) missingPrereqs.push("clang++ (Xcode Command Line Tools: xcode-select --install)");
	} else {
		compiler = whichFn("g++") || whichFn("clang++") || whichFn("c++");
		if (!compiler) missingPrereqs.push("g++ / clang++ (build-essential)");
	}

	const python = pythonBin && fs.existsSync(pythonBin) ? pythonBin : whichFn("python3") || whichFn("python");
	if (!python) missingPrereqs.push("python3 (>= 3.8)");

	const supported = missingPrereqs.length === 0;
	let reason: string | undefined;

	if (!supported) {
		reason = `Missing required build toolchain components for Triton source build: ${missingPrereqs.join(", ")}.`;
	} else if (platform === "darwin" && arch === "arm64") {
		reason =
			"Official triton-library PyPI wheels do not support macOS arm64. Ready to build natively from pinned source.";
	}

	return {
		supported,
		reason,
		missingPrereqs,
		tools: { cmake, ninja: ninja || make, compiler, python },
	};
}

/**
 * Resolves the primary site-packages directory for a given Python executable.
 */
export async function findSitePackagesDir(
	pythonBin: string,
	executor: (argv: readonly string[]) => Promise<{ exitCode: number; stdout: string; stderr: string }>,
): Promise<string | null> {
	const res = await executor([pythonBin, "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"]);
	if (res.exitCode === 0 && res.stdout.trim()) {
		const purelib = res.stdout.trim().split("\n")[0].trim();
		if (fs.existsSync(purelib)) return purelib;
	}

	const venvDir = path.dirname(path.dirname(pythonBin));
	if (process.platform === "win32") {
		const libSite = path.join(venvDir, "Lib", "site-packages");
		if (fs.existsSync(libSite)) return libSite;
	} else {
		const libDir = path.join(venvDir, "lib");
		if (fs.existsSync(libDir)) {
			try {
				for (const entry of fs.readdirSync(libDir)) {
					if (entry.startsWith("python")) {
						const site = path.join(libDir, entry, "site-packages");
						if (fs.existsSync(site)) return site;
					}
				}
			} catch {}
		}
	}
	return null;
}

/**
 * Finds Capstone include directory and library file inside Python site-packages.
 */
export function findCapstoneArtifacts(
	sitePackagesDir: string,
	platform: NodeJS.Platform,
): { includeDir: string; libraryPath: string } | null {
	const capstoneDir = path.join(sitePackagesDir, "capstone");
	if (!fs.existsSync(capstoneDir)) return null;

	let includeDir: string | null = null;
	for (const cand of [path.join(capstoneDir, "include"), capstoneDir]) {
		if (fs.existsSync(path.join(cand, "capstone.h")) || fs.existsSync(path.join(cand, "capstone", "capstone.h"))) {
			includeDir = cand;
			break;
		}
	}
	if (!includeDir) return null;

	const libDir = path.join(capstoneDir, "lib");
	const candNames =
		platform === "darwin"
			? ["libcapstone.dylib", "libcapstone.5.dylib"]
			: platform === "win32"
				? ["capstone.dll", "libcapstone.dll"]
				: ["libcapstone.so", "libcapstone.so.5"];

	let libraryPath: string | null = null;
	for (const name of candNames) {
		const p = path.join(libDir, name);
		if (fs.existsSync(p)) {
			libraryPath = p;
			break;
		}
	}
	if (!libraryPath) {
		for (const name of candNames) {
			const p = path.join(capstoneDir, name);
			if (fs.existsSync(p)) {
				libraryPath = p;
				break;
			}
		}
	}
	if (!libraryPath) return null;

	if (platform === "darwin") {
		const targetSymlink = path.join(path.dirname(libraryPath), "libcapstone.5.dylib");
		if (!fs.existsSync(targetSymlink)) {
			try {
				fs.symlinkSync(path.basename(libraryPath), targetSymlink);
			} catch {}
		}
	}

	return { includeDir, libraryPath };
}

/**
 * Finds Z3 include directory and library file inside Python site-packages.
 */
export function findZ3Artifacts(
	sitePackagesDir: string,
	platform: NodeJS.Platform,
): { includeDir: string; libraryPath: string } | null {
	const z3Dir = path.join(sitePackagesDir, "z3");
	if (!fs.existsSync(z3Dir)) return null;

	const includeDir = path.join(z3Dir, "include");
	if (
		!fs.existsSync(includeDir) ||
		!fs.existsSync(path.join(includeDir, "z3.h")) ||
		!fs.existsSync(path.join(includeDir, "z3_version.h"))
	) {
		return null;
	}

	const libDir = path.join(z3Dir, "lib");
	const candNames =
		platform === "darwin"
			? ["libz3.dylib", "libz3.5.3.dylib"]
			: platform === "win32"
				? ["libz3.dll", "z3.dll"]
				: ["libz3.so", "libz3.so.5"];

	let libraryPath: string | null = null;
	for (const name of candNames) {
		const p = path.join(libDir, name);
		if (fs.existsSync(p)) {
			libraryPath = p;
			break;
		}
	}
	if (!libraryPath) {
		for (const name of candNames) {
			const p = path.join(z3Dir, name);
			if (fs.existsSync(p)) {
				libraryPath = p;
				break;
			}
		}
	}
	if (!libraryPath) return null;

	return { includeDir, libraryPath };
}

/**
 * Configures Mach-O or ELF dependent library paths and RPATHs
 * so the installed triton extension is 100% relocatable when the staged venv is published.
 */
export async function configureRelocatableDylibs(
	tritonModulePath: string,
	sitePackagesDir: string,
	platform: NodeJS.Platform,
	exec: (argv: readonly string[]) => Promise<{ exitCode: number; stdout: string; stderr: string }>,
	whichFn: (bin: string) => string | null,
): Promise<void> {
	if (platform === "darwin") {
		const installNameTool = whichFn("install_name_tool");
		const otool = whichFn("otool");
		if (!installNameTool || !fs.existsSync(tritonModulePath)) return;

		await exec([installNameTool, "-id", "@rpath/triton.so", tritonModulePath]);

		if (otool) {
			const loadRes = await exec([otool, "-l", tritonModulePath]);
			if (loadRes.exitCode === 0) {
				const rpathMatches = [...loadRes.stdout.matchAll(/cmd\s+LC_RPATH[\s\S]*?path\s+([^\s]+)/g)];
				for (const match of rpathMatches) {
					const rpathVal = match[1];
					if (
						rpathVal.startsWith("/") &&
						(rpathVal.includes("stage") || rpathVal.includes(".stage") || rpathVal.includes("/tmp/"))
					) {
						await exec([installNameTool, "-delete_rpath", rpathVal, tritonModulePath]);
					}
				}
			}
		}

		const relativeRpaths = [
			"@loader_path/capstone/lib",
			"@loader_path/z3/lib",
			"@loader_path/../capstone/lib",
			"@loader_path/../z3/lib",
		];
		for (const rpathEntry of relativeRpaths) {
			await exec([installNameTool, "-add_rpath", rpathEntry, tritonModulePath]);
		}

		await exec([
			installNameTool,
			"-change",
			"@rpath/libcapstone.5.dylib",
			"@rpath/libcapstone.dylib",
			tritonModulePath,
		]);

		const capLibDir = path.join(sitePackagesDir, "capstone", "lib");
		if (fs.existsSync(capLibDir)) {
			const dylib = path.join(capLibDir, "libcapstone.dylib");
			const dylib5 = path.join(capLibDir, "libcapstone.5.dylib");
			if (fs.existsSync(dylib) && !fs.existsSync(dylib5)) {
				try {
					fs.symlinkSync("libcapstone.dylib", dylib5);
				} catch {}
			} else if (fs.existsSync(dylib5) && !fs.existsSync(dylib)) {
				try {
					fs.symlinkSync("libcapstone.5.dylib", dylib);
				} catch {}
			}
		}
	} else if (platform === "linux") {
		const patchelf = whichFn("patchelf");
		if (patchelf && fs.existsSync(tritonModulePath)) {
			await exec([
				patchelf,
				"--set-rpath",
				"$ORIGIN/capstone/lib:$ORIGIN/z3/lib:$ORIGIN/../capstone/lib:$ORIGIN/../z3/lib",
				tritonModulePath,
			]);
		}
	}
}

/**
 * Downloads, compiles, and installs Triton from pinned source into the target venv.
 */
export async function buildAndInstallTritonFromSource(
	options: TritonSourceBuildOptions,
): Promise<TritonSourceBuildResult> {
	const platform = options.platform ?? process.platform;
	const arch = options.arch ?? process.arch;
	const whichFn = options.which ?? $which;
	const logs: string[] = [];

	const log = (msg: string) => {
		logs.push(msg);
		options.onChunk?.(msg.endsWith("\n") ? msg : `${msg}\n`);
	};

	// 1. Upfront prerequisite verification
	const prereq = canBuildTritonFromSource(platform, arch, whichFn, options.pythonBin);
	if (!prereq.supported) {
		const err = `Triton native source build prerequisites missing: ${prereq.missingPrereqs.join(", ")}. ${prereq.reason ?? ""}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	const overallTimeoutMs = options.timeoutMs ?? DEFAULT_BUILD_TIMEOUT_MS;
	const timeoutSignal = AbortSignal.timeout(overallTimeoutMs);
	const activeSignal = options.signal ? AbortSignal.any([options.signal, timeoutSignal]) : timeoutSignal;

	const exec = (argv: readonly string[], execOpts?: { cwd?: string; env?: Record<string, string | undefined> }) => {
		const stepEnv = { ...options.env, ...execOpts?.env };
		if (options.executor) {
			return options.executor(argv, {
				cwd: execOpts?.cwd,
				env: stepEnv,
				onChunk: options.onChunk,
				signal: activeSignal,
			});
		}
		return runSubprocess(argv, {
			cwd: execOpts?.cwd,
			env: stepEnv,
			onChunk: options.onChunk,
			signal: activeSignal,
		});
	};

	// 2. Discover venv site-packages directory
	log(`[triton-src] Resolving site-packages in virtual environment: ${options.venvDir}...`);
	const sitePackages = await findSitePackagesDir(options.pythonBin, exec);
	if (!sitePackages) {
		const err = `Failed to locate site-packages directory for virtual environment Python: ${options.pythonBin}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}
	log(`[triton-src] Target site-packages: ${sitePackages}`);

	// 3. Install pinned Python dependencies into venv (capstone, z3-solver)
	log(`[triton-src] Installing pinned dependencies (${TRITON_PINNED_CAPSTONE}, ${TRITON_PINNED_Z3_SOLVER})...`);
	const pipDepsRes = await exec([
		options.pythonBin,
		"-m",
		"pip",
		"install",
		"--no-input",
		TRITON_PINNED_CAPSTONE,
		TRITON_PINNED_Z3_SOLVER,
	]);
	if (pipDepsRes.exitCode !== 0) {
		const err = `Failed to install required Python build dependencies into venv: ${pipDepsRes.stderr || pipDepsRes.stdout}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	// 4. Locate Capstone and Z3 native headers and libraries inside the managed venv
	const capstone = findCapstoneArtifacts(sitePackages, platform);
	if (!capstone) {
		const err = `Could not locate Capstone headers or native library in ${sitePackages}/capstone.`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}
	log(`[triton-src] Found Capstone include: ${capstone.includeDir}, lib: ${capstone.libraryPath}`);

	const z3 = findZ3Artifacts(sitePackages, platform);
	if (!z3) {
		const err = `Could not locate Z3 headers or native library in ${sitePackages}/z3.`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}
	log(`[triton-src] Found Z3 include: ${z3.includeDir}, lib: ${z3.libraryPath}`);

	// 5. Download and verify pinned Triton source archive via bounded stream
	const sourceExtractDir = path.join(options.stageDir, "triton-source");
	const buildDir = path.join(options.stageDir, "triton-build");
	fs.mkdirSync(sourceExtractDir, { recursive: true });
	fs.mkdirSync(buildDir, { recursive: true });

	log(`[triton-src] Fetching pinned Triton source archive: ${TRITON_SOURCE_URL}...`);
	const fetchFn = options.fetch ?? globalThis.fetch;
	const archiveFetch = await fetchBoundedArchive(TRITON_SOURCE_URL, MAX_SOURCE_ARCHIVE_BYTES, fetchFn, activeSignal);
	if (!archiveFetch.ok) {
		const err = `Failed to download Triton source: ${archiveFetch.error}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	const buf = archiveFetch.bytes;
	const sha = crypto.createHash("sha256").update(buf).digest("hex");
	if (sha.toLowerCase() !== TRITON_SOURCE_SHA256.toLowerCase()) {
		const err = `Triton source archive SHA256 mismatch: expected ${TRITON_SOURCE_SHA256}, got ${sha}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}
	log(`[triton-src] Verified source archive SHA256 integrity: ${sha}`);

	// 6. Extract source archive
	log(`[triton-src] Extracting source archive...`);
	await extractArchive({ bytes: buf, format: "tar.gz" }, sourceExtractDir);

	let sourceRoot = sourceExtractDir;
	try {
		const entries = fs.readdirSync(sourceExtractDir);
		if (entries.length === 1 && fs.statSync(path.join(sourceExtractDir, entries[0])).isDirectory()) {
			sourceRoot = path.join(sourceExtractDir, entries[0]);
		}
	} catch {}

	if (!fs.existsSync(path.join(sourceRoot, "CMakeLists.txt"))) {
		const err = `Extracted source is missing CMakeLists.txt in ${sourceRoot}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	// 7. Configure CMake build
	const cmakeBin = prereq.tools.cmake!;
	const generator = whichFn("ninja") ? ["-G", "Ninja"] : [];

	const cmakeArgs = [
		cmakeBin,
		sourceRoot,
		...generator,
		`-DPYTHON_EXECUTABLE=${options.pythonBin}`,
		"-DPYTHON_BINDINGS=ON",
		"-DBUILD_EXAMPLES=OFF",
		"-DENABLE_TEST=OFF",
		"-DCMAKE_BUILD_TYPE=Release",
		"-DZ3_INTERFACE=ON",
		`-DZ3_INCLUDE_DIRS=${z3.includeDir}`,
		`-DZ3_LIBRARIES=${z3.libraryPath}`,
		`-DCAPSTONE_INCLUDE_DIRS=${capstone.includeDir}`,
		`-DCAPSTONE_LIBRARIES=${capstone.libraryPath}`,
		"-DLLVM_INTERFACE=OFF",
		"-DBITWUZLA_INTERFACE=OFF",
		"-DBOOST_INTERFACE=OFF",
		"-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON",
		platform === "darwin"
			? "-DCMAKE_INSTALL_RPATH=@loader_path/capstone/lib;@loader_path/z3/lib;@loader_path/../capstone/lib;@loader_path/../z3/lib"
			: "-DCMAKE_INSTALL_RPATH=$ORIGIN/capstone/lib;$ORIGIN/z3/lib;$ORIGIN/../capstone/lib;$ORIGIN/../z3/lib",
	];

	log(`[triton-src] Configuring CMake project...`);
	const cmakeConfigRes = await exec(cmakeArgs, { cwd: buildDir });
	if (cmakeConfigRes.exitCode !== 0) {
		const err = `CMake configuration failed:\n${cmakeConfigRes.stderr || cmakeConfigRes.stdout}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	// 8. Build target python-triton
	log(`[triton-src] Compiling target 'python-triton' (Release)...`);
	const buildArgs = [cmakeBin, "--build", ".", "--config", "Release", "--target", "python-triton"];
	const buildRes = await exec(buildArgs, { cwd: buildDir });
	if (buildRes.exitCode !== 0) {
		const err = `Triton compilation failed:\n${buildRes.stderr || buildRes.stdout}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	// 9. Target output is triton.so (Unix) or triton.pyd (Windows) in src/libtriton
	const extSuffix = platform === "win32" ? ".pyd" : ".so";
	const builtModule = path.join(buildDir, "src", "libtriton", `triton${extSuffix}`);
	if (!fs.existsSync(builtModule) || !fs.statSync(builtModule).isFile()) {
		const err = `Compilation finished but expected extension not found at: ${builtModule}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}
	log(`[triton-src] Successfully verified compiled extension: ${builtModule}`);

	// 10. Install module into venv site-packages
	const destModule = path.join(sitePackages, `triton${extSuffix}`);
	fs.copyFileSync(builtModule, destModule);

	const extSuffixRes = await exec([
		options.pythonBin,
		"-I",
		"-c",
		"import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX') or '')",
	]);
	if (extSuffixRes.exitCode === 0 && extSuffixRes.stdout.trim()) {
		const specificSuffix = extSuffixRes.stdout.trim().split("\n")[0].trim();
		if (specificSuffix && specificSuffix !== extSuffix) {
			const specificDest = path.join(sitePackages, `triton${specificSuffix}`);
			try {
				if (fs.existsSync(specificDest)) fs.unlinkSync(specificDest);
				fs.copyFileSync(builtModule, specificDest);
			} catch {}
		}
	}

	// 11. Configure relocatable RPATHs and dependencies
	log(`[triton-src] Configuring relocatable RPATHs on installed module...`);
	await configureRelocatableDylibs(destModule, sitePackages, platform, exec, whichFn);

	// 12. Write metadata and retain Apache-2.0 license
	const distInfoDir = path.join(sitePackages, `triton_library-${TRITON_VERSION}.dist-info`);
	fs.mkdirSync(distInfoDir, { recursive: true });

	const metadataContent = [
		"Metadata-Version: 2.1",
		"Name: triton-library",
		`Version: ${TRITON_VERSION}`,
		"Summary: Triton is a dynamic binary analysis library",
		"License: Apache-2.0",
		"Author: Jonathan Salwan",
		`Project-URL: Source, ${TRITON_SOURCE_URL}`,
		"",
	].join("\n");
	fs.writeFileSync(path.join(distInfoDir, "METADATA"), metadataContent);
	fs.writeFileSync(path.join(distInfoDir, "INSTALLER"), "reverse-source-build\n");
	fs.writeFileSync(path.join(distInfoDir, "top_level.txt"), "triton\n");

	const sourceLicense = path.join(sourceRoot, "LICENSE.txt");
	if (fs.existsSync(sourceLicense)) {
		fs.copyFileSync(sourceLicense, path.join(distInfoDir, "LICENSE.txt"));
		const toolsVmpDir = path.dirname(options.venvDir);
		try {
			fs.copyFileSync(sourceLicense, path.join(toolsVmpDir, "TRITON-LICENSE.txt"));
		} catch {}
	}

	const stubFile = path.join(buildDir, "doc", "triton_autocomplete", "triton.pyi");
	if (fs.existsSync(stubFile)) {
		try {
			fs.copyFileSync(stubFile, path.join(sitePackages, "triton.pyi"));
		} catch {}
	}

	// 13. Validate installed module with isolated execution
	log(`[triton-src] Validating installed Triton module with isolated interpreter...`);
	const probeRes = await exec([
		options.pythonBin,
		"-I",
		"-c",
		"from triton import TritonContext, ARCH; ctx = TritonContext(ARCH.X86_64); print('TRITON_OK')",
	]);
	if (probeRes.exitCode !== 0 || !probeRes.stdout.includes("TRITON_OK")) {
		const err = `Triton installation probe failed: ${probeRes.stderr || probeRes.stdout}`;
		log(`[triton-src] ERROR: ${err}`);
		return { success: false, version: TRITON_VERSION, sourceCommit: TRITON_SOURCE_COMMIT, error: err, logs };
	}

	let z3Supported = false;
	let llvmSupported = false;

	// Actual operational verification: AST construction and SMT model solution
	const solverTestRes = await exec([
		options.pythonBin,
		"-I",
		"-c",
		"from triton import TritonContext, ARCH; ctx = TritonContext(ARCH.X86_64); ast = ctx.getAstContext(); x = ctx.newSymbolicVariable(32, 'x'); eq = ast.equal(ast.variable(x), ast.bv(42, 32)); model = ctx.getModel(eq); print('SOLVER_MODEL_SOLVED:', len(model) == 1)",
	]);
	if (solverTestRes.exitCode === 0 && solverTestRes.stdout.includes("SOLVER_MODEL_SOLVED: True")) {
		z3Supported = true;
	}
	// Actual operational verification: LLVM IR lifting attempt (gracefully classifying expected TypeError when not built with LLVM)
	const llvmProbeScript = [
		"from triton import TritonContext, ARCH",
		"ctx = TritonContext(ARCH.X86_64)",
		"ast = ctx.getAstContext()",
		"ok = False",
		"if hasattr(ctx, 'liftToLLVM'):",
		"    try:",
		"        ok = ctx.liftToLLVM(ast.bv(1, 32)) is not None",
		"    except (TypeError, Exception):",
		"        ok = False",
		"print('LLVM_AVAILABLE:', ok)",
	].join("\n");

	const llvmTestRes = await exec([options.pythonBin, "-I", "-c", llvmProbeScript]);
	if (llvmTestRes.exitCode === 0 && llvmTestRes.stdout.includes("LLVM_AVAILABLE: True")) {
		llvmSupported = true;
	}

	log(
		`[triton-src] Successfully built and verified Triton ${TRITON_SOURCE_RECEIPT_VERSION} (commit ${TRITON_SOURCE_COMMIT.slice(0, 8)})!`,
	);
	log(`[triton-src] Capabilities: Z3 solver = ${z3Supported}, LLVM lifter = ${llvmSupported}`);

	return {
		success: true,
		version: TRITON_SOURCE_RECEIPT_VERSION,
		sourceCommit: TRITON_SOURCE_COMMIT,
		modulePath: destModule,
		logs,
		z3Supported,
		llvmSupported,
	};
}
