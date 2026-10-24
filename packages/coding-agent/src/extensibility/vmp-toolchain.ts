/**
 * VMP Reverse Engineering Toolchain Resolver and Managed Environment Installer.
 *
 * Provides shared, authoritative resolution, platform-guard validation, and isolated
 * environment management for:
 * - Triton: Dynamic binary analysis, concolic execution, and taint analysis (triton-library, Apache-2.0).
 *   Resolved via managed Python virtual environment or canonical TRITON_PYTHON after probing
 *   triton.TritonContext (strictly distinguishing from NVIDIA triton).
 * - VMPDump: Dynamic memory dumper and PE repair for VMProtect-packed Windows processes (GPL-3.0).
 *   Strictly Windows-only (uses Win32 debugging APIs).
 * - Mergen: VMProtect x86-64 bytecode lifter to LLVM IR (GPL-3.0).
 * - NoVmp: Static devirtualizer for legacy VMProtect 3.0-3.5 x86-64 routines (GPL-3.0).
 *
 * Platform guards:
 * - Windows PE binaries are never pretended to be natively runnable on macOS or Linux.
 * - Unix native binaries require executable permissions (X_OK) and matching ELF / Mach-O or #! script headers.
 * - Windows binaries are validated for valid PE signature and AMD64 machine architecture.
 * - Non-supported platforms report precise reasons without attempting process execution.
 */
import * as child_process from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, getAgentDir, WhichCachePolicy, type WhichOptions, withFileLock } from "@reverse/utils";
import {
	TRITON_VERSION,
	TRITON_PYPI_PACKAGE,
	TRITON_SOURCE_COMMIT,
	TRITON_SOURCE_URL,
	TRITON_SOURCE_SHA256,
	canBuildTritonFromSource,
	buildAndInstallTritonFromSource,
	buildSubprocessEnv,
	runSubprocess,
} from "./triton-source-install";

export {
	TRITON_VERSION,
	TRITON_PYPI_PACKAGE,
	TRITON_SOURCE_COMMIT,
	TRITON_SOURCE_URL,
	TRITON_SOURCE_SHA256,
	canBuildTritonFromSource,
	buildAndInstallTritonFromSource,
};
export type VmpToolId = "triton" | "vmpdump" | "mergen" | "novmp";

export interface VmpResolveOptions {
	env?: Record<string, string | undefined>;
	platform?: NodeJS.Platform;
	agentDir?: string;
	which?: (binary: string, options?: WhichOptions) => string | null;
}

export interface TritonInstallOptions {
	agentDir?: string;
	pythonPath?: string;
	onChunk?: (chunk: string) => void;
	signal?: AbortSignal;
	env?: Record<string, string | undefined>;
	which?: (binary: string) => string | null;
	platform?: NodeJS.Platform;
}

export interface TritonInstallResult {
	success: boolean;
	pythonPath: string | null;
	venvDir: string;
	message: string;
	llvmSupported?: boolean;
}

export const VMP_TOOL_ASSETS = {
	vmpdump: {
		version: "1.2",
		url: "https://github.com/0xnobody/vmpdump/releases/download/v1.2/VMPDump.zip",
		sha256: "3232aa702f2af8b0cc6a967defc525537317fab9dc2512418911326e50551097",
		filename: "VMPDump.zip",
		targetExecutable: "VMPDump.exe",
		license: "GPL-3.0",
		platforms: ["win32"] as const,
	},
	mergen: {
		version: "0.7",
		url: "https://github.com/NaC-L/Mergen/releases/download/v0.7/lifter-windows-iced.exe",
		sha256: "6dc014b100d0ce2f8d5c6156c2a3786783a8014f8bf4cc20faafad5ce9d366b6",
		filename: "lifter-windows-iced.exe",
		targetExecutable: "lifter-windows-iced.exe",
		license: "GPL-3.0",
		platforms: ["win32"] as const,
	},
	novmp: {
		version: "1.0.6",
		url: "https://github.com/can1357/NoVmp/releases/download/v1.0.6/NoVmp.exe",
		sha256: "545788e150e9fab8f16fc157669ee42fe7c636b2a7cb0b8b8e0622af3455401c",
		filename: "NoVmp.exe",
		targetExecutable: "NoVmp.exe",
		license: "GPL-3.0",
		platforms: ["win32"] as const,
	},
} as const;

/**
 * Validates whether a file is a valid Windows PE AMD64 (x86-64) binary.
 * Reads MZ header, e_lfanew offset, PE\0\0 signature, and Machine field (0x8664).
 */
export function validatePeAmd64(filePath: string): boolean {
	try {
		if (!fs.existsSync(filePath)) return false;
		const stat = fs.statSync(filePath);
		if (!stat.isFile() || stat.size < 256) return false;

		const fd = fs.openSync(filePath, "r");
		const headerBuf = Buffer.alloc(64);
		const read1 = fs.readSync(fd, headerBuf, 0, 64, 0);
		if (read1 < 64 || headerBuf[0] !== 0x4d || headerBuf[1] !== 0x5a) {
			fs.closeSync(fd);
			return false; // Not MZ
		}

		const peOffset = headerBuf.readInt32LE(0x3c);
		if (peOffset < 64 || peOffset > stat.size - 24) {
			fs.closeSync(fd);
			return false;
		}

		const peBuf = Buffer.alloc(24);
		const read2 = fs.readSync(fd, peBuf, 0, 24, peOffset);
		fs.closeSync(fd);
		if (read2 < 24) return false;

		// Verify PE signature: 'P', 'E', 0x00, 0x00
		if (peBuf[0] !== 0x50 || peBuf[1] !== 0x45 || peBuf[2] !== 0x00 || peBuf[3] !== 0x00) {
			return false;
		}

		// Machine field at peBuf[4..5] (IMAGE_FILE_MACHINE_AMD64 = 0x8664)
		const machine = peBuf.readUInt16LE(4);
		return machine === 0x8664;
	} catch {
		return false;
	}
}

/**
 * Validates whether a file is a runnable Unix executable (Mach-O on Darwin, ELF on Linux, or #! script).
 * Strictly rejects Windows PE binaries (MZ).
 */
export function validateUnixExecutable(filePath: string, platform: NodeJS.Platform): boolean {
	try {
		if (!fs.existsSync(filePath)) return false;
		const stat = fs.statSync(filePath);
		if (!stat.isFile() || stat.size < 4) return false;

		// Verify execute permission
		try {
			fs.accessSync(filePath, fs.constants.X_OK);
		} catch {
			return false;
		}

		const fd = fs.openSync(filePath, "r");
		const magic = Buffer.alloc(4);
		const bytesRead = fs.readSync(fd, magic, 0, 4, 0);
		fs.closeSync(fd);
		if (bytesRead < 4) return false;

		// Strictly reject Windows PE
		if (magic[0] === 0x4d && magic[1] === 0x5a) {
			return false;
		}

		// Script wrapper (#!)
		if (magic[0] === 0x23 && magic[1] === 0x21) {
			return true;
		}

		if (platform === "darwin") {
			// Mach-O magic numbers
			const u32BE = magic.readUInt32BE(0);
			const u32LE = magic.readUInt32LE(0);
			const machOMagics = new Set([
				0xfeedface, // Mach-O 32-bit BE
				0xcefaedfe, // Mach-O 32-bit LE
				0xfeedfacf, // Mach-O 64-bit BE
				0xcffaedfe, // Mach-O 64-bit LE
				0xcafebabe, // Universal binary BE
				0xbebafeca, // Universal binary LE
			]);
			return machOMagics.has(u32BE) || machOMagics.has(u32LE);
		}

		if (platform === "linux") {
			// ELF magic: 0x7F, 'E', 'L', 'F'
			return magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46;
		}

		return false;
	} catch {
		return false;
	}
}

/**
 * Validates executable based on current host platform constraints.
 */
function isBinaryValidForPlatform(filePath: string, platform: NodeJS.Platform): boolean {
	if (platform === "win32") {
		return validatePeAmd64(filePath);
	}
	return validateUnixExecutable(filePath, platform);
}

/**
 * Probes whether a python executable contains the binary analysis Triton library
 * (from triton import TritonContext), strictly rejecting NVIDIA triton compiler.
 * Honors options.env, purges PYTHONPATH/PYTHONHOME, and enforces clean subprocess execution.
 */
export function isTritonPython(pythonPath: string, env?: Record<string, string | undefined>): boolean {
	try {
		if (!fs.existsSync(pythonPath)) return false;
		const stat = fs.statSync(pythonPath);
		if (!stat.isFile()) return false;
		try {
			fs.accessSync(pythonPath, fs.constants.X_OK);
		} catch {
			return false;
		}

		const probeEnv = buildSubprocessEnv(env);

		const probeCode = "from triton import TritonContext, ARCH; ctx = TritonContext(ARCH.X86_64); print('TRITON_OK')";
		const proc = child_process.spawnSync(pythonPath, ["-I", "-c", probeCode], {
			cwd: os.tmpdir(),
			timeout: 3000,
			stdio: ["ignore", "pipe", "pipe"],
			env: probeEnv,
		});

		return proc.status === 0 && proc.stdout.toString().includes("TRITON_OK");
	} catch {
		return false;
	}
}

/**
 * Resolve managed or host Python interpreter providing Triton binary analysis.
 */
function resolveTritonPython(options?: VmpResolveOptions): string | null {
	const env = options?.env !== undefined ? options.env : process.env;
	const platform = options?.platform ?? process.platform;
	const agentDir = options?.agentDir ?? getAgentDir();
	const whichFn = options?.which ?? $which;
	// 1. Canonical environment variable override: TRITON_PYTHON
	if (env.TRITON_PYTHON && fs.existsSync(env.TRITON_PYTHON) && isTritonPython(env.TRITON_PYTHON, env)) {
		return env.TRITON_PYTHON;
	}

	// 2. Canonical managed virtual environment in agent directory: <agentDir>/tools/vmp/triton-venv
	const venvExecutable = platform === "win32" ? "Scripts/python.exe" : "bin/python";
	const managedVenvPython = path.join(agentDir, "tools", "vmp", "triton-venv", venvExecutable);
	if (fs.existsSync(managedVenvPython) && isTritonPython(managedVenvPython, env)) {
		return managedVenvPython;
	}

	// 3. System python candidates (only if Triton is installed and validated in them)
	const systemCandidates = ["python3", "python"];
	const whichOptions: WhichOptions = {
		PATH: env?.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	for (const bin of systemCandidates) {
		const resolved = whichFn(bin, whichOptions);
		if (resolved && fs.existsSync(resolved) && isTritonPython(resolved, env)) {
			return resolved;
		}
	}

	return null;
}

/**
 * Resolve native VMP tool executable (vmpdump, mergen, novmp).
 */
function resolveNativeVmpBinary(id: "vmpdump" | "mergen" | "novmp", options?: VmpResolveOptions): string | null {
	const platform = options?.platform ?? process.platform;

	// VMPDump is strictly Windows-only (Win32 debugging APIs)
	if (id === "vmpdump" && platform !== "win32") {
		return null;
	}

	const env = options?.env !== undefined ? options.env : process.env;
	const agentDir = options?.agentDir ?? getAgentDir();
	const whichFn = options?.which ?? $which;
	// 1. Canonical environment variable override
	const envKey = `${id.toUpperCase()}_PATH`;
	const envVal = env[envKey];
	if (envVal && fs.existsSync(envVal) && isBinaryValidForPlatform(envVal, platform)) {
		return envVal;
	}

	// 2. Candidate filenames
	const binaryCandidates: Record<"vmpdump" | "mergen" | "novmp", string[]> = {
		vmpdump: ["VMPDump.exe", "vmpdump.exe", "vmpdump"],
		mergen: ["lifter-windows-iced.exe", "mergen.exe", "mergen", "lifter"],
		novmp: ["NoVmp.exe", "novmp.exe", "novmp"],
	};
	const names = binaryCandidates[id];

	// 3. Managed tool directories in agent tools: both tools/vmp/<id> and tools/<id>
	const searchDirs: string[] = [
		path.join(agentDir, "tools", "vmp", id),
		path.join(agentDir, "tools", id),
		path.join(agentDir, "tools", "vmp"),
	];

	const extraDirs = (env.REVERSE_TOOL_PATHS ?? env.VMP_TOOLS_DIR ?? "")
		.split(platform === "win32" ? ";" : ":")
		.map(d => d.trim())
		.filter(Boolean);
	for (const d of extraDirs) {
		searchDirs.push(d, path.join(d, id), path.join(d, "vmp", id));
	}

	for (const dir of searchDirs) {
		for (const name of names) {
			const candidate = path.join(dir, name);
			if (fs.existsSync(candidate) && isBinaryValidForPlatform(candidate, platform)) {
				return candidate;
			}
		}
	}

	// 4. System PATH / which lookup with cache bypass
	const whichOptions: WhichOptions = {
		PATH: env?.PATH,
		cache: WhichCachePolicy.Bypass,
		requireAbsolutePaths: true,
	};
	for (const name of names) {
		const candidate = whichFn(name, whichOptions);
		if (candidate && fs.existsSync(candidate) && isBinaryValidForPlatform(candidate, platform)) {
			return candidate;
		}
	}

	return null;
}

/**
 * Authoritative resolver for VMP toolchain components.
 *
 * @param id Tool identifier: "triton" | "vmpdump" | "mergen" | "novmp"
 * @param options Lookup options (env, platform, agentDir, which)
 * @returns Absolute path to managed Python interpreter (for triton) or native executable (others), or null.
 */
export function resolveVmpTool(
	id: "triton" | "vmpdump" | "mergen" | "novmp",
	options?: VmpResolveOptions,
): string | null {
	if (id === "triton") {
		return resolveTritonPython(options);
	}
	return resolveNativeVmpBinary(id, options);
}

/**
 * Returns whether a VMP tool is supported on the target platform.
 */
export function isVmpToolSupportedOnPlatform(id: VmpToolId, platform: NodeJS.Platform): boolean {
	if (id === "triton") {
		return true; // Supported cross-platform with Python 3.8+
	}
	return platform === "win32"; // Prebuilt assets for VMPDump, Mergen, NoVmp are Windows x64
}

/**
 * Returns an honest, precise reason when a tool cannot be automatically installed
 * on the target platform.
 */
export function getVmpToolUnsupportedReason(id: VmpToolId, platform: NodeJS.Platform): string | null {
	if (isVmpToolSupportedOnPlatform(id, platform)) {
		return null;
	}
	switch (id) {
		case "vmpdump":
			return `VMPDump is a Windows x64 dynamic memory dumper requiring Win32 debugging APIs. Automated installation is not supported on ${platform}.`;
		case "mergen":
			return `Mergen official prebuilt binaries are only available for Windows x64. On ${platform}, building from source requires the Rust toolchain.`;
		case "novmp":
			return `NoVmp official prebuilt binaries are only available for Windows x64 and require x86 intrinsics. Automated installation is not supported on ${platform}.`;
		default:
			return `Tool ${id} is not supported on ${platform}.`;
	}
}

/**
 * Finds a suitable host Python interpreter (>= 3.8) for bootstrapping a virtual environment.
 */
function findHostPython(options?: TritonInstallOptions): string | null {
	const whichFn = options?.which ?? $which;
	if (options?.pythonPath && fs.existsSync(options.pythonPath)) {
		return options.pythonPath;
	}

	const candidates = [
		"/opt/homebrew/bin/python3.12",
		"/opt/homebrew/bin/python3.11",
		"/opt/homebrew/bin/python3.10",
		"/usr/local/bin/python3.10",
		"/usr/local/bin/python3",
		"python3.12",
		"python3.11",
		"python3.10",
		"python3.9",
		"python3",
		"python",
	];
	const filterEnv = buildSubprocessEnv();

	for (const cand of candidates) {
		const resolved = path.isAbsolute(cand) ? (fs.existsSync(cand) ? cand : null) : whichFn(cand);
		if (resolved && fs.existsSync(resolved)) {
			try {
				const check = child_process.spawnSync(
					resolved,
					["-I", "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"],
					{ cwd: os.tmpdir(), timeout: 2500, stdio: ["ignore", "pipe", "pipe"], env: filterEnv },
				);
				if (check.status === 0) {
					return resolved;
				}
			} catch {}
		}
	}
	return null;
}

/**
 * Installs and validates Triton symbolic execution library in an isolated virtual environment.
 * Staged with atomic publication and rollback on failure.
 */
/**
 * Determines whether an official prebuilt wheel is available on PyPI for triton-library 1.0.0rc4.
 */
export function isTritonWheelAvailable(
	platform: NodeJS.Platform = process.platform,
	arch: string = process.arch,
	minorVersion?: number,
): boolean {
	const isX64 = arch === "x64" || arch === "amd64";
	if (platform === "win32" && isX64) {
		return minorVersion === undefined || (minorVersion >= 8 && minorVersion <= 14);
	}
	if (platform === "linux" && isX64) {
		return minorVersion === undefined || (minorVersion >= 8 && minorVersion <= 14);
	}
	if (platform === "darwin" && isX64) {
		return minorVersion !== undefined && minorVersion >= 8 && minorVersion <= 10;
	}
	return false;
}

export async function installTritonVenv(options: TritonInstallOptions = {}): Promise<TritonInstallResult> {
	const platform = options.platform ?? process.platform;
	const agentDir = options.agentDir ?? getAgentDir();
	const baseToolsDir = path.join(agentDir, "tools");
	const vmpDir = path.join(baseToolsDir, "vmp");
	const venvDir = path.join(vmpDir, "triton-venv");
	const venvPython =
		platform === "win32" ? path.join(venvDir, "Scripts", "python.exe") : path.join(venvDir, "bin", "python");

	// 1. Locate host Python 3.8+
	const hostPython = findHostPython(options);
	if (!hostPython) {
		return {
			success: false,
			pythonPath: null,
			venvDir,
			message: "Python 3.8+ interpreter not found. Please install Python 3.8+ before setting up Triton.",
		};
	}

	fs.mkdirSync(vmpDir, { recursive: true });
	const lockPath = path.join(baseToolsDir, ".triton-venv.lock");

	return await withFileLock(
		lockPath,
		async () => {
			options.signal?.throwIfAborted();
			// Re-check if venv already satisfies Triton probe
			if (fs.existsSync(venvPython) && isTritonPython(venvPython, options.env)) {
				return {
					success: true,
					pythonPath: venvPython,
					venvDir,
					message: `Triton binary analysis is already installed and verified in ${venvDir}.`,
				};
			}

			options.signal?.throwIfAborted();
			options.onChunk?.(`[triton] Using host Python interpreter: ${hostPython}\n`);
			// Atomic backup of existing venv before modification
			let backupDir: string | null = null;
			if (fs.existsSync(venvDir)) {
				backupDir = path.join(vmpDir, `.backup-triton-venv-${process.pid}-${Date.now()}`);
				try {
					fs.renameSync(venvDir, backupDir);
				} catch (backupErr) {
					return {
						success: false,
						pythonPath: null,
						venvDir,
						message: `Failed to back up existing virtual environment: ${(backupErr as Error).message}`,
					};
				}
			}

			try {
				const cleanEnv = buildSubprocessEnv(options.env);
				options.onChunk?.(`[triton] Creating isolated virtual environment in ${venvDir}...\n`);
				const venvRes = await runSubprocess([hostPython, "-m", "venv", venvDir], {
					signal: options.signal,
					onChunk: options.onChunk,
					env: cleanEnv,
				});

				if (venvRes.exitCode !== 0 || !fs.existsSync(venvPython)) {
					throw new Error(`Failed to create virtual environment: ${venvRes.stderr || "unknown error"}`);
				}

				// Determine installation mode upfront based on PyPI wheel compatibility
				let hostMinor: number | undefined;
				try {
					const verRes = child_process.spawnSync(
						hostPython,
						["-I", "-c", "import sys; print(sys.version_info.minor)"],
						{ cwd: os.tmpdir(), timeout: 2500, stdio: ["ignore", "pipe", "pipe"], env: cleanEnv },
					);
					if (verRes.status === 0) {
						hostMinor = Number.parseInt(verRes.stdout.toString().trim(), 10);
					}
				} catch {}

				const buildMode: "wheel" | "source" = isTritonWheelAvailable(platform, process.arch, hostMinor)
					? "wheel"
					: "source";

				if (buildMode === "wheel") {
					options.onChunk?.(`[triton] Installing pinned wheel ${TRITON_PYPI_PACKAGE}...\n`);
					const pipRes = await runSubprocess(
						[venvPython, "-m", "pip", "install", "--no-input", TRITON_PYPI_PACKAGE],
						{
							signal: options.signal,
							onChunk: options.onChunk,
							env: cleanEnv,
						},
					);

					if (pipRes.exitCode !== 0) {
						throw new Error(
							`Pip wheel installation failed (${pipRes.exitCode}): ${pipRes.stderr || pipRes.stdout}`,
						);
					}
				} else {
					options.onChunk?.(`[triton] Native source build mode selected for ${platform}-${process.arch}...\n`);
					const prereqs = canBuildTritonFromSource(platform, process.arch, options.which ?? $which, hostPython);
					if (!prereqs.supported) {
						throw new Error(
							prereqs.reason ??
								`Native source build prerequisites missing: ${prereqs.missingPrereqs.join(", ")}`,
						);
					}

					const srcRes = await buildAndInstallTritonFromSource({
						stageDir: vmpDir,
						venvDir,
						pythonBin: venvPython,
						signal: options.signal,
						onChunk: options.onChunk,
						which: options.which,
						platform,
						arch: process.arch,
						env: cleanEnv,
					});

					if (!srcRes.success) {
						throw new Error(srcRes.error ?? "Triton native source build failed.");
					}
				}

				// 5. Post-install validation
				if (!isTritonPython(venvPython, options.env)) {
					throw new Error(
						"Triton installation finished, but post-install validation (from triton import TritonContext) failed.",
					);
				}

				// Probe optional LLVM lifting support
				let llvmSupported = false;
				try {
					const llvmProbeCode = [
						"from triton import TritonContext, ARCH",
						"ctx = TritonContext(ARCH.X86_64)",
						"ast = ctx.getAstContext()",
						"try:",
						"    node = ast.bv(1, 32)",
						"    ir = ctx.liftToLLVM(node)",
						"    print('LLVM_OK' if ir else 'NO_LLVM')",
						"except Exception:",
						"    print('NO_LLVM')",
					].join("\n");
					const llvmRes = child_process.spawnSync(venvPython, ["-I", "-c", llvmProbeCode], {
						cwd: os.tmpdir(),
						timeout: 3000,
						stdio: ["ignore", "pipe", "pipe"],
						env: cleanEnv,
					});
					llvmSupported = llvmRes.status === 0 && llvmRes.stdout.toString().includes("LLVM_OK");
				} catch {}

				// Write managed install receipt
				try {
					const receiptPath = path.join(vmpDir, "triton-receipt.json");
					fs.writeFileSync(
						receiptPath,
						JSON.stringify(
							{
								package: TRITON_PYPI_PACKAGE,
								version: TRITON_VERSION,
								installedAt: new Date().toISOString(),
								pythonPath: venvPython,
								llvmSupported,
								buildMode,
							},
							null,
							2,
						),
					);
				} catch {}

				// Installation succeeded! Clean up backup
				if (backupDir && fs.existsSync(backupDir)) {
					try {
						fs.rmSync(backupDir, { recursive: true, force: true });
					} catch {}
				}

				options.onChunk?.(
					`[triton] Triton verified successfully! (LLVM lifting support: ${llvmSupported ? "yes" : "no"})\n`,
				);

				return {
					success: true,
					pythonPath: venvPython,
					venvDir,
					message: `Triton dynamic binary analysis installed and validated successfully in ${venvDir}.`,
					llvmSupported,
				};
			} catch (err) {
				// Rollback on failure
				if (fs.existsSync(venvDir)) {
					try {
						fs.rmSync(venvDir, { recursive: true, force: true });
					} catch {}
				}
				if (backupDir && fs.existsSync(backupDir)) {
					try {
						fs.renameSync(backupDir, venvDir);
					} catch {}
				}

				return {
					success: false,
					pythonPath: null,
					venvDir,
					message: `Triton installation failed: ${(err as Error).message}`,
				};
			}
		},
		{ signal: options.signal },
	);
}
