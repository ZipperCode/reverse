/**
 * Shared Python worker runner for reverse engineering capabilities.
 *
 * Staging model:
 * - Detects Python 3.9+ using existing enumeratePythonRuntimes discovery.
 * - Probes candidate interpreters with bounded timeout and abort signal support.
 * - Stages provided in-memory Python sources into a private temporary directory.
 * - Safely checks path containment using path.relative.
 * - Installs timers and abort signals immediately upon spawn.
 * - Streams bounded stdout (16 MiB) and stderr (1 MiB), killing process on overflow.
 * - Dispatches request JSON over stdin, collects structured JSON from stdout.
 * - Merges explicit allowlisted environment variables without leaking secrets.
 * - Redirects logging to stderr.
 * - Terminates full subprocess tree on timeout or cancellation.
 * - Cleans temporary directory completely upon completion.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { enumeratePythonRuntimes, filterEnv } from "../eval/py/runtime";

export interface ReversePythonOptions {
	cwd: string;
	sources: Record<string, string>;
	entry: string;
	request: unknown;
	signal?: AbortSignal;
	timeoutMs?: number;
	env?: Record<string, string>;
	pythonPath?: string;
	requiredPackage?: string;
}

export interface ReversePythonResult<T> {
	status: "ok" | "missing_dependency" | "error";
	result?: T;
	error?: string;
	stdout?: string;
	stderr?: string;
	exitCode?: number;
}

interface PythonProbeResult {
	available: boolean;
	pythonPath?: string;
	error?: string;
	installHint?: string;
}

const DEFAULT_PROBE_TIMEOUT_MS = 3000;
const DEFAULT_EXECUTION_TIMEOUT_MS = 60000;
const MAX_STDOUT_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_STDERR_BYTES = 1 * 1024 * 1024; // 1 MiB

function killProcessTree(pid: number, signal: NodeJS.Signals | number = "SIGKILL"): void {
	if (!pid || pid <= 0) return;
	if (process.platform === "win32") {
		try {
			Bun.spawnSync(["taskkill", "/F", "/T", "/PID", String(pid)]);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	} else {
		try {
			process.kill(-pid, signal);
		} catch {
			try {
				process.kill(pid, signal);
			} catch {}
		}
	}
}

function getPlatformInstallHint(): string {
	return "Run 'reverse setup reverse python' to install or configure a Python 3.9+ runtime.";
}

/**
 * Read stream up to maxBytes, notifying overflow callback and terminating if budget exceeded.
 */
async function readBoundedStream(
	stream: ReadableStream<Uint8Array>,
	maxBytes: number,
	onOverflow: () => void,
): Promise<{ text: string; overflowed: boolean }> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let totalBytes = 0;
	let overflowed = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value) {
				totalBytes += value.byteLength;
				if (totalBytes > maxBytes) {
					overflowed = true;
					onOverflow();
					break;
				}
				chunks.push(value);
			}
		}
	} finally {
		reader.releaseLock();
	}

	const merged = new Uint8Array(chunks.reduce((acc, c) => acc + c.byteLength, 0));
	let offset = 0;
	for (const c of chunks) {
		merged.set(c, offset);
		offset += c.byteLength;
	}
	return { text: new TextDecoder().decode(merged), overflowed };
}

/**
 * Probe a candidate python binary to verify it is Python 3.9+ with bounded timeout.
 */
async function probeCandidate(
	candidatePath: string,
	signal?: AbortSignal,
	timeoutMs: number = DEFAULT_PROBE_TIMEOUT_MS,
	requiredPackage?: string,
): Promise<boolean> {
	if (signal?.aborted) return false;
	try {
		if (!fs.existsSync(candidatePath)) {
			return false;
		}

		const checkScript = requiredPackage
			? `import sys\nif not ((sys.version_info[0] == 3 and sys.version_info[1] >= 9) or sys.version_info[0] > 3):\n    sys.exit(1)\ntry:\n    __import__(${JSON.stringify(requiredPackage)})\nexcept Exception:\n    sys.exit(2)\nsys.exit(0)`
			: "import sys; sys.exit(0 if (sys.version_info[0] == 3 and sys.version_info[1] >= 9) or sys.version_info[0] > 3 else 1)";

		const proc = Bun.spawn([candidatePath, "-c", checkScript], {
			stdout: "ignore",
			stderr: "ignore",
			stdin: "ignore",
			env: filterEnv(process.env as Record<string, string | undefined>),
			detached: process.platform !== "win32",
		});

		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			killProcessTree(proc.pid);
		}, timeoutMs);

		const onAbort = () => {
			killProcessTree(proc.pid);
		};
		signal?.addEventListener("abort", onAbort, { once: true });

		const exitCode = await proc.exited;
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);

		return !timedOut && exitCode === 0;
	} catch {
		return false;
	}
}

/**
 * Discover Python 3.9+ runtime using existing enumeratePythonRuntimes discovery.
 */
export async function discoverPython39(
	cwd: string,
	signal?: AbortSignal,
	requiredPackage?: string,
): Promise<PythonProbeResult> {
	if (signal?.aborted) {
		return { available: false, error: "Discovery cancelled by abort signal" };
	}

	const baseEnv = filterEnv(process.env as Record<string, string | undefined>);
	const runtimes = enumeratePythonRuntimes(cwd, baseEnv);

	for (const runtime of runtimes) {
		if (await probeCandidate(runtime.pythonPath, signal, DEFAULT_PROBE_TIMEOUT_MS, requiredPackage)) {
			return { available: true, pythonPath: runtime.pythonPath };
		}
	}

	return {
		available: false,
		error: requiredPackage
			? `No Python 3.9+ interpreter with package '${requiredPackage}' found across ${runtimes.length} candidates.`
			: `No working Python 3.9+ interpreter found across ${runtimes.length} candidates.`,
		installHint: getPlatformInstallHint(),
	};
}

/**
 * Execute a staged Python script with structured JSON stdin/stdout.
 */
export async function runReversePython<T>(options: ReversePythonOptions): Promise<ReversePythonResult<T>> {
	if (options.signal?.aborted) {
		return {
			status: "error",
			error: "Operation cancelled before execution",
		};
	}

	let pythonPath: string;
	if (options.pythonPath) {
		const valid = await probeCandidate(
			options.pythonPath,
			options.signal,
			DEFAULT_PROBE_TIMEOUT_MS,
			options.requiredPackage,
		);
		if (!valid) {
			return {
				status: "missing_dependency",
				error: `Specified Python interpreter '${options.pythonPath}' is invalid or missing required package '${options.requiredPackage ?? ""}'.`,
			};
		}
		pythonPath = options.pythonPath;
	} else {
		const probe = await discoverPython39(options.cwd, options.signal, options.requiredPackage);
		if (!probe.available || !probe.pythonPath) {
			return {
				status: "missing_dependency",
				error: `${probe.error ?? "Python 3.9+ not found"}. Install hint: ${probe.installHint ?? getPlatformInstallHint()}`,
			};
		}
		pythonPath = probe.pythonPath;
	}

	// Create fresh private temporary staging directory
	const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "reverse-python-"));

	try {
		// Stage all sources into private temp
		for (const [relPath, content] of Object.entries(options.sources)) {
			const targetPath = path.resolve(tempDir, relPath);
			// Validate directory containment using path.relative
			const rel = path.relative(tempDir, targetPath);
			if (rel.startsWith("..") || path.isAbsolute(rel)) {
				return {
					status: "error",
					error: `Invalid relative source path outside temp directory: ${relPath}`,
				};
			}
			await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
			await fs.promises.writeFile(targetPath, content, "utf-8");
		}

		const entryPath = path.resolve(tempDir, options.entry);
		const entryRel = path.relative(tempDir, entryPath);
		if (entryRel.startsWith("..") || !fs.existsSync(entryPath)) {
			return {
				status: "error",
				error: `Entry script not found in staged sources: ${options.entry}`,
			};
		}

		const childEnv: Record<string, string | undefined> = {
			...filterEnv(process.env as Record<string, string | undefined>),
			PYTHONUNBUFFERED: "1",
			PYTHONDONTWRITEBYTECODE: "1",
			...options.env,
		};

		const child = Bun.spawn([pythonPath, "-u", entryPath], {
			cwd: options.cwd,
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
			env: childEnv,
			detached: process.platform !== "win32",
		});

		// Install timers and cancellation handlers immediately upon spawn
		let timer: NodeJS.Timeout | number | undefined;
		let timedOut = false;
		let overflowError: string | null = null;

		const onAbort = () => {
			killProcessTree(child.pid);
		};

		if (options.signal?.aborted) {
			killProcessTree(child.pid);
			await child.exited.catch(() => {});
			return {
				status: "error",
				error: "Execution cancelled by abort signal",
			};
		}
		options.signal?.addEventListener("abort", onAbort, { once: true });

		const timeoutMs = options.timeoutMs ?? DEFAULT_EXECUTION_TIMEOUT_MS;
		if (timeoutMs > 0) {
			timer = setTimeout(() => {
				timedOut = true;
				killProcessTree(child.pid);
			}, timeoutMs);
		}

		let stdoutRes = { text: "", overflowed: false };
		let stderrRes = { text: "", overflowed: false };
		let exitCode: number | undefined;

		try {
			// Write request JSON to stdin
			const requestJson = typeof options.request === "string" ? options.request : JSON.stringify(options.request);

			const stdinWriter = child.stdin;
			try {
				stdinWriter.write(new TextEncoder().encode(requestJson));
				await stdinWriter.end();
			} catch {
				// Subprocess may have exited early; child.exited will report the error
			}
			[stdoutRes, stderrRes, exitCode] = await Promise.all([
				readBoundedStream(child.stdout, MAX_STDOUT_BYTES, () => {
					overflowError = "stdout exceeded 16 MiB budget";
					killProcessTree(child.pid);
				}),
				readBoundedStream(child.stderr, MAX_STDERR_BYTES, () => {
					overflowError = "stderr exceeded 1 MiB budget";
					killProcessTree(child.pid);
				}),
				child.exited,
			]);
		} finally {
			clearTimeout(timer);
			options.signal?.removeEventListener("abort", onAbort);
			// Guarantee child and all descendants are terminated
			killProcessTree(child.pid);
			await child.exited.catch(() => {});
		}

		if (overflowError) {
			return {
				status: "error",
				error: `Process output limit exceeded: ${overflowError}`,
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode,
			};
		}

		if (timedOut) {
			return {
				status: "error",
				error: `Execution timed out after ${timeoutMs}ms`,
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode,
			};
		}

		if (options.signal?.aborted) {
			return {
				status: "error",
				error: "Execution cancelled by abort signal",
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode,
			};
		}

		const trimmedStdout = stdoutRes.text.trim();

		if (exitCode !== 0) {
			if (trimmedStdout.startsWith("{")) {
				try {
					const parsed = JSON.parse(trimmedStdout);
					if (parsed && typeof parsed === "object" && "error" in parsed) {
						return {
							status: "error",
							error: String(parsed.error),
							stdout: stdoutRes.text,
							stderr: stderrRes.text,
							exitCode,
						};
					}
				} catch {
					// Fall through to stderr
				}
			}
			return {
				status: "error",
				error: stderrRes.text.trim() || `Python process exited with code ${exitCode}`,
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode,
			};
		}

		if (!trimmedStdout) {
			return {
				status: "error",
				error: "Python process produced empty stdout output",
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode: 0,
			};
		}

		try {
			const result = JSON.parse(trimmedStdout) as T;
			return {
				status: "ok",
				result,
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode: 0,
			};
		} catch (parseError) {
			return {
				status: "error",
				error: `Failed to parse Python worker JSON response: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
				stdout: stdoutRes.text,
				stderr: stderrRes.text,
				exitCode: 0,
			};
		}
	} catch (err) {
		return {
			status: "error",
			error: err instanceof Error ? err.message : String(err),
		};
	} finally {
		// Clean up private staging directory
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	}
}
