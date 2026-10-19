#!/usr/bin/env bun
/**
 * Local standalone installer and manager for the `reverse` binary.
 *
 * Installs the compiled standalone `reverse` binary into `~/.local/bin` (or a
 * user-specified directory via `--bin-dir` or `--prefix`), validates the binary
 * `--version` output as an identity sanity check before installation with a strict
 * timeout and bounded output, creates atomic installs with chmod 0755, creates
 * collision backups that never overwrite prior backups, verifies reverse
 * ownership before uninstalling, and never alters shell profile files or requires
 * root privileges. Note: --version verification is an identity sanity guard, not
 * a cryptographic authenticity or signature check.
 *
 * Options:
 *   --binary <path>      Path to existing standalone binary (default: packages/coding-agent/dist/reverse[.exe])
 *   --bin-dir <path>     Directory to install binary into (default: ~/.local/bin or %USERPROFILE%\.local\bin)
 *   --prefix <path>      Install to <prefix>/bin
 *   --dry-run            Report actions without modifying filesystem or building
 *   --check              Verify current installation in the destination directory
 *   --uninstall          Remove reverse binary from target directory
 *   --overwrite          Overwrite existing destination binary
 *   --no-backup          Skip creating .bak backup when overwriting existing binary
 *   --force              Force action (e.g. force uninstall unverified target)
 *   --build              Force build if source binary does not exist
 *   --no-build           Do not build if binary is missing (default)
 *   -h, --help           Show help
 */

import type { Subprocess } from "bun";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

const REPO_ROOT = path.resolve(import.meta.dir, "..");

export const MAX_VERSION_OUTPUT_BYTES = 64 * 1024;
export const DEFAULT_VERIFY_TIMEOUT_MS = 5000;

export interface InstallOptions {
	binary?: string;
	binDir?: string;
	prefix?: string;
	dryRun?: boolean;
	check?: boolean;
	uninstall?: boolean;
	overwrite?: boolean;
	backup?: boolean;
	force?: boolean;
	build?: boolean;
	noBuild?: boolean;
	platform?: NodeJS.Platform;
	verifyTimeoutMs?: number;
}

export function resolveBinaryName(platform: NodeJS.Platform = process.platform): string {
	return platform === "win32" ? "reverse.exe" : "reverse";
}

export function resolveTargetBinDir(options: { binDir?: string; prefix?: string; platform?: NodeJS.Platform }): string {
	if (options.binDir) {
		return path.resolve(options.binDir);
	}
	if (options.prefix) {
		return path.resolve(options.prefix, "bin");
	}
	const platform = options.platform ?? process.platform;
	if (platform === "win32") {
		const userDir = process.env.USERPROFILE || process.env.HOME || os.homedir();
		return path.join(userDir, ".local", "bin");
	}
	return path.join(os.homedir(), ".local", "bin");
}

export function resolveDefaultSourceBinary(
	repoRoot: string = REPO_ROOT,
	platform: NodeJS.Platform = process.platform,
): string {
	const binaryName = resolveBinaryName(platform);
	return path.join(repoRoot, "packages", "coding-agent", "dist", binaryName);
}

export async function fileExists(filePath: string): Promise<boolean> {
	try {
		await fs.access(filePath);
		return true;
	} catch {
		return false;
	}
}

export async function findNonCollidingBackupPath(targetPath: string): Promise<string> {
	const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
	let candidate = `${targetPath}.bak.${timestamp}`;
	let counter = 1;
	while (await fileExists(candidate)) {
		candidate = `${targetPath}.bak.${timestamp}.${counter}`;
		counter++;
	}
	return candidate;
}

export function validateBinaryVersionOutput(stdout: string): { ok: boolean; version?: string; error?: string } {
	const trimmed = stdout.trim();
	const firstLine = trimmed.split("\n")[0]?.trim() ?? "";
	// Accept "reverse/18.11.2", "reverse v18.11.2", "reverse 18.11.2"
	const match = firstLine.match(/^reverse(?:[/ ]v?|[ ]+)([0-9a-zA-Z._-]+)/i);
	if (!match) {
		return {
			ok: false,
			error: `Binary output does not have a valid reverse version signature. Received: "${firstLine.slice(0, 100)}"`,
		};
	}
	return { ok: true, version: match[1] };
}

export async function readBounded(stream: ReadableStream<Uint8Array>, maxBytes: number): Promise<string> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;
	try {
		while (totalBytes < maxBytes) {
			const { done, value } = await reader.read();
			if (done || !value) break;
			chunks.push(value);
			totalBytes += value.byteLength;
		}
	} finally {
		reader.cancel().catch(() => {});
	}
	const combined = new Uint8Array(Math.min(totalBytes, maxBytes));
	let offset = 0;
	for (const chunk of chunks) {
		const toCopy = Math.min(chunk.byteLength, maxBytes - offset);
		combined.set(chunk.subarray(0, toCopy), offset);
		offset += toCopy;
		if (offset >= maxBytes) break;
	}
	return new TextDecoder().decode(combined);
}

export async function verifyExecutable(
	binaryPath: string,
	timeoutMs: number = DEFAULT_VERIFY_TIMEOUT_MS,
): Promise<{ ok: boolean; version?: string; error?: string }> {
	let proc: Subprocess | undefined;
	let timer: Timer | undefined;
	let timedOut = false;

	try {
		proc = Bun.spawn([binaryPath, "--version"], {
			stdout: "pipe",
			stderr: "pipe",
		});

		const timeoutPromise = new Promise<never>((_, reject) => {
			timer = setTimeout(() => {
				timedOut = true;
				try {
					proc?.kill();
				} catch {}
				reject(new Error(`Binary verification timed out after ${timeoutMs}ms`));
			}, timeoutMs);
		});

		const readPromise = Promise.all([
			readBounded(proc.stdout, MAX_VERSION_OUTPUT_BYTES),
			readBounded(proc.stderr, MAX_VERSION_OUTPUT_BYTES),
			proc.exited,
		]);

		const [stdoutText, stderrText, exitCode] = await Promise.race([readPromise, timeoutPromise]);
		clearTimeout(timer);

		if (exitCode !== 0) {
			return {
				ok: false,
				error: `Binary execution exited with code ${exitCode}. Error output: ${stderrText.trim().slice(0, 300)}`,
			};
		}
		return validateBinaryVersionOutput(stdoutText);
	} catch (err) {
		clearTimeout(timer);
		if (timedOut) {
			return {
				ok: false,
				error: `Binary verification timed out after ${timeoutMs}ms`,
			};
		}
		return {
			ok: false,
			error: `Failed to execute binary at "${binaryPath}": ${err instanceof Error ? err.message : String(err)}`,
		};
	} finally {
		clearTimeout(timer);
	}
}

export function isDirectoryInPath(dir: string, envPath: string = process.env.PATH || ""): boolean {
	const normalizedDir = path.resolve(dir);
	const delimiter = process.platform === "win32" ? ";" : ":";
	const entries = envPath
		.split(delimiter)
		.filter(Boolean)
		.map(e => path.resolve(e));
	return entries.includes(normalizedDir);
}

export async function runLocalInstall(options: InstallOptions = {}): Promise<{
	success: boolean;
	targetPath?: string;
	version?: string;
	backupPath?: string;
	message: string;
}> {
	const platform = options.platform ?? process.platform;
	const binaryName = resolveBinaryName(platform);
	const targetDir = resolveTargetBinDir({ binDir: options.binDir, prefix: options.prefix, platform });
	const targetPath = path.join(targetDir, binaryName);
	const timeoutMs = options.verifyTimeoutMs ?? DEFAULT_VERIFY_TIMEOUT_MS;

	// Handle --check
	if (options.check) {
		const exists = await fileExists(targetPath);
		if (!exists) {
			return {
				success: false,
				targetPath,
				message: `reverse is not installed at ${targetPath}`,
			};
		}
		const verify = await verifyExecutable(targetPath, timeoutMs);
		if (!verify.ok) {
			return {
				success: false,
				targetPath,
				message: `Installed binary at ${targetPath} is invalid: ${verify.error}`,
			};
		}
		const inPath = isDirectoryInPath(targetDir);
		return {
			success: true,
			targetPath,
			version: verify.version,
			message: `reverse ${verify.version} is installed at ${targetPath} (${inPath ? "directory is in PATH" : "directory is NOT in PATH"})`,
		};
	}

	// Handle --uninstall
	if (options.uninstall) {
		const exists = await fileExists(targetPath);
		if (!exists) {
			return {
				success: true,
				targetPath,
				message: `No binary found at ${targetPath}. Nothing to uninstall.`,
			};
		}
		// Verify target is an owned reverse binary before deleting
		const verify = await verifyExecutable(targetPath, timeoutMs);
		if (!verify.ok && !options.force) {
			return {
				success: false,
				targetPath,
				message: `Refusing to uninstall "${targetPath}": target file does not have a verified reverse signature (${verify.error}). Use --force to remove unverified file.`,
			};
		}
		if (options.dryRun) {
			return {
				success: true,
				targetPath,
				message: `[dry-run] Would remove binary at ${targetPath} (verified: reverse ${verify.version ?? "unknown"})`,
			};
		}
		await fs.rm(targetPath, { force: true });
		return {
			success: true,
			targetPath,
			message: `Successfully uninstalled reverse ${verify.version ? `v${verify.version} ` : ""}from ${targetPath}`,
		};
	}

	// Resolve source binary
	const sourceBinary = options.binary ? path.resolve(options.binary) : resolveDefaultSourceBinary(REPO_ROOT, platform);
	let sourceExists = await fileExists(sourceBinary);

	if (!sourceExists) {
		if (options.build) {
			if (options.dryRun) {
				// in dry run, just note that build would be executed
			} else {
				console.log(`Source binary not found at ${sourceBinary}. Building standalone binary...`);
				const buildProc = Bun.spawn(["bun", "--cwd=packages/coding-agent", "run", "build"], {
					cwd: REPO_ROOT,
					stdout: "inherit",
					stderr: "inherit",
				});
				const buildExit = await buildProc.exited;
				if (buildExit !== 0) {
					return {
						success: false,
						message: `Failed to build reverse standalone binary (build exited with code ${buildExit})`,
					};
				}
				sourceExists = await fileExists(sourceBinary);
				if (!sourceExists) {
					return {
						success: false,
						message: `Build completed but output binary not found at ${sourceBinary}`,
					};
				}
			}
		} else {
			return {
				success: false,
				message: `Source binary not found at "${sourceBinary}".\nProvide an existing binary via --binary <path>, or build it first via "bun run build".`,
			};
		}
	}

	// Validate source binary before modifying anything
	if (!options.dryRun || sourceExists) {
		const verify = await verifyExecutable(sourceBinary, timeoutMs);
		if (!verify.ok) {
			return {
				success: false,
				message: `Source binary validation failed: ${verify.error}.\nRefusing to install an unverified binary.`,
			};
		}
		const validatedVersion = verify.version;

		// Check collision and handle backup
		let backupPath: string | undefined;
		const targetExists = await fileExists(targetPath);
		if (targetExists) {
			const shouldBackup = options.backup !== false;
			if (shouldBackup) {
				backupPath = await findNonCollidingBackupPath(targetPath);
			}
		}

		if (options.dryRun) {
			return {
				success: true,
				targetPath,
				version: validatedVersion,
				backupPath,
				message:
					`[dry-run] Validated source binary: ${sourceBinary} (version: ${validatedVersion})\n` +
					`[dry-run] Target location: ${targetPath}\n` +
					(targetExists && backupPath ? `[dry-run] Would backup existing binary to: ${backupPath}\n` : "") +
					`[dry-run] Would install atomically with mode 0755`,
			};
		}

		// Ensure target directory exists
		await fs.mkdir(targetDir, { recursive: true });

		// Perform backup if destination exists without clobbering prior backups
		if (targetExists && backupPath) {
			await fs.copyFile(targetPath, backupPath);
		}

		// Atomic copy: write to unique temp file in the same directory, chmod, then atomic rename
		const tempPath = path.join(
			targetDir,
			`.${binaryName}.tmp.${Date.now()}.${Math.random().toString(36).slice(2, 8)}`,
		);
		try {
			await fs.copyFile(sourceBinary, tempPath);
			if (platform !== "win32") {
				await fs.chmod(tempPath, 0o755);
			}
			await fs.rename(tempPath, targetPath);
		} catch (err) {
			await fs.rm(tempPath, { force: true }).catch(() => {});
			throw err;
		}

		// Verify installed binary in place
		const installedVerify = await verifyExecutable(targetPath, timeoutMs);
		if (!installedVerify.ok) {
			return {
				success: false,
				targetPath,
				message: `Installed binary at ${targetPath} failed in-place verification: ${installedVerify.error}`,
			};
		}

		const inPath = isDirectoryInPath(targetDir);
		let pathAdvice = "";
		if (!inPath) {
			pathAdvice =
				`\n\nNotice: "${targetDir}" is not currently in your PATH.\n` +
				`To run "reverse" directly, add it to your PATH in your shell configuration:\n` +
				`  export PATH="${targetDir}:$PATH"`;
		}

		return {
			success: true,
			targetPath,
			version: installedVerify.version,
			backupPath,
			message: `Successfully installed reverse ${installedVerify.version} to ${targetPath}${backupPath ? `\n(Existing binary backed up to ${backupPath})` : ""}${pathAdvice}`,
		};
	}

	return {
		success: true,
		targetPath,
		message: `[dry-run] Operation would install to ${targetPath}`,
	};
}

export function parseCliArgs(argv: string[]): InstallOptions {
	const options: InstallOptions = {};
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--binary") {
			options.binary = argv[++i];
		} else if (arg.startsWith("--binary=")) {
			options.binary = arg.slice("--binary=".length);
		} else if (arg === "--bin-dir") {
			options.binDir = argv[++i];
		} else if (arg.startsWith("--bin-dir=")) {
			options.binDir = arg.slice("--bin-dir=".length);
		} else if (arg === "--prefix") {
			options.prefix = argv[++i];
		} else if (arg.startsWith("--prefix=")) {
			options.prefix = arg.slice("--prefix=".length);
		} else if (arg === "--dry-run") {
			options.dryRun = true;
		} else if (arg === "--check") {
			options.check = true;
		} else if (arg === "--uninstall") {
			options.uninstall = true;
		} else if (arg === "--overwrite") {
			options.overwrite = true;
		} else if (arg === "--no-backup") {
			options.backup = false;
		} else if (arg === "--force") {
			options.force = true;
		} else if (arg === "--build") {
			options.build = true;
		} else if (arg === "--no-build") {
			options.noBuild = true;
		} else if (arg === "-h" || arg === "--help") {
			printUsage();
			process.exit(0);
		} else {
			console.error(`Unknown option: ${arg}\n`);
			printUsage();
			process.exit(1);
		}
	}
	return options;
}

function printUsage(): void {
	console.log(`reverse Local Standalone Installer

Usage:
  bun run install:local [options]
  bun scripts/install-local.ts [options]

Options:
  --binary <path>    Path to compiled reverse standalone binary
                     (default: packages/coding-agent/dist/reverse)
  --bin-dir <path>   Directory to install binary into
                     (default: ~/.local/bin or %USERPROFILE%\\.local\\bin)
  --prefix <path>    Base directory prefix (installs to <prefix>/bin)
  --dry-run          Simulate installation without making filesystem changes
  --check            Check whether reverse is installed and functional in target dir
  --uninstall        Remove installed reverse binary from target dir
  --no-backup        Do not create a timestamped backup when replacing an existing binary
  --force            Force uninstallation even if binary signature is unverified
  --build            Build binary with "bun run build" if source binary is missing
  -h, --help         Show this help message

Examples:
  # Install default compiled binary to ~/.local/bin
  bun run install:local

  # Install a specific pre-built binary
  bun run install:local --binary ./packages/coding-agent/dist/reverse

  # Install to custom directory (e.g. for testing)
  bun run install:local --bin-dir /tmp/test-bin

  # Dry-run inspection
  bun run install:local --dry-run

  # Check existing installation
  bun run install:local --check
`);
}

async function main(): Promise<void> {
	const options = parseCliArgs(process.argv.slice(2));
	try {
		const result = await runLocalInstall(options);
		console.log(result.message);
		if (!result.success) {
			process.exit(1);
		}
	} catch (err) {
		console.error(`Installation failed: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(1);
	}
}

if (import.meta.main) {
	await main();
}
