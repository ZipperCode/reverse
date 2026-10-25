/**
 * Unidbg Emulation Process Lifecycle & SSE / MCP Session Manager
 *
 * Manages spawning, deterministic classpath resolution, SSE health probing, in-memory session MCP mounting,
 * process supervision, and automatic teardown for Unidbg harnesses.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { MCPManager } from "../mcp/manager";
import type { MCPServerConfig } from "../mcp/types";
import { resolveStdioSpawnCommand } from "../mcp/transports/stdio";
import { validateJdk8 } from "./unidbg-builder";
import { inspectUnidbg } from "./unidbg-detect";
import { generateAndroidProbeHarness, type UnidbgEnvProfile } from "./unidbg-harness";
import { sha256File } from "../utils/file-hash";

export interface UnidbgProcessInfo {
	pid: number;
	port: number;
	serverName: string;
	type?: "jni" | "ipa";
	targetPath?: string;
	arch: 32 | 64;
	backend: "unicorn2" | "dynarmic";
	harnessPath?: string;
	harnessClass?: string;
	sseUrl: string;
	ready: boolean;
	startTime: number;
	process: ChildProcess;
	mcpManager?: MCPManager;
	owner?: unknown;
	logs?: string[];
	lastOutput?: string;
}

export interface UnidbgLaunchOptions {
	type?: "jni" | "ipa";
	harnessPath?: string;
	harnessClass?: string;
	unidbgHome?: string;
	javaHome?: string;
	port?: number;
	targetPath?: string;
	arch?: 32 | 64 | "32" | "64";
	backend?: "unicorn2" | "dynarmic";
	mcpManager?: MCPManager;
	owner?: unknown;
	timeoutMs?: number;
	onLog?: (text: string) => void;
	signal?: AbortSignal;
}

// In-memory active process map keyed by port
const activeHarnesses = new Map<number, UnidbgProcessInfo>();

function isProcessAlive(proc: ChildProcess): boolean {
	return proc.exitCode === null && proc.signalCode === null;
}

function delay(ms: number): Promise<void> {
	const { promise, resolve } = Promise.withResolvers<void>();
	setTimeout(resolve, ms);
	return promise;
}

// Ensure all spawned harnesses are killed if reverse exits
process.once("exit", () => {
	for (const h of activeHarnesses.values()) {
		try {
			if (isProcessAlive(h.process)) {
				h.process.kill("SIGKILL");
			}
		} catch {}
	}
});

export function getActiveUnidbgHarnesses(owner?: unknown): UnidbgProcessInfo[] {
	const filterByOwner = arguments.length > 0;
	return Array.from(activeHarnesses.values()).filter(h => {
		if (!isProcessAlive(h.process)) return false;
		if (filterByOwner) {
			return h.owner === owner;
		}
		return true;
	});
}

export function getActiveUnidbgHarness(owner?: unknown, port?: number): UnidbgProcessInfo | null {
	if (port !== undefined) {
		const found = activeHarnesses.get(port);
		if (found && isProcessAlive(found.process)) {
			if (arguments.length > 0 && found.owner !== owner) {
				return null;
			}
			return found;
		}
		return null;
	}
	const list = arguments.length > 0 ? getActiveUnidbgHarnesses(owner) : getActiveUnidbgHarnesses();
	return list.length > 0 ? list[0] : null;
}

async function stopProcess(harness: UnidbgProcessInfo): Promise<void> {
	harness.ready = false;

	if (harness.mcpManager) {
		try {
			await harness.mcpManager.disconnectServer(harness.serverName);
		} catch {}
	}

	const child = harness.process;
	if (isProcessAlive(child)) {
		const { promise: exitPromise, resolve: resolveExit } = Promise.withResolvers<void>();
		let done = false;
		const onExit = () => {
			if (!done) {
				done = true;
				clearTimeout(killTimer);
				resolveExit();
			}
		};

		child.once("close", onExit);
		child.once("exit", onExit);

		try {
			child.kill("SIGTERM");
		} catch {
			onExit();
			return;
		}

		const killTimer = setTimeout(() => {
			if (isProcessAlive(child)) {
				try {
					child.kill("SIGKILL");
				} catch {}
			}
			setTimeout(onExit, 300);
		}, 2000);

		await exitPromise;
	}

	if (activeHarnesses.get(harness.port) === harness) {
		activeHarnesses.delete(harness.port);
	}
}

/**
 * Stop running harness on given port and disconnect from session MCP.
 * Awaits actual process exit, escalates from SIGTERM to SIGKILL, and guards session ownership.
 * Stopping without a port stops ALL harnesses belonging to the specified owner.
 */
export async function stopUnidbgHarness(owner?: unknown, port?: number): Promise<boolean> {
	if (port !== undefined) {
		const harness = activeHarnesses.get(port);
		if (!harness) return false;
		if (arguments.length > 0 && harness.owner !== owner) {
			return false;
		}
		await stopProcess(harness);
		return true;
	}

	const owned = Array.from(activeHarnesses.values()).filter(h => {
		if (arguments.length > 0) {
			return h.owner === owner;
		}
		return true;
	});

	if (owned.length === 0) return false;

	for (const h of owned) {
		await stopProcess(h);
	}
	return true;
}

/**
 * Poll SSE endpoint until it responds with 200 or timeout is reached.
 * Automatically cancels the streaming response body so connection handles do not leak.
 */
async function waitForSseEndpoint(
	port: number,
	child: ChildProcess,
	timeoutMs = 30_000,
	signal?: AbortSignal,
): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	const sseUrl = `http://localhost:${port}/sse`;

	while (Date.now() < deadline) {
		if (signal?.aborted) return false;
		if (!isProcessAlive(child)) return false;

		try {
			const controller = new AbortController();
			const timeoutTimer = setTimeout(() => controller.abort(), 1200);
			const resp = await fetch(sseUrl, {
				headers: { Accept: "text/event-stream" },
				signal: controller.signal,
			});
			clearTimeout(timeoutTimer);
			if (resp.status === 200 || resp.ok) {
				void resp.body?.cancel().catch(() => {});
				return true;
			}
			void resp.body?.cancel().catch(() => {});
		} catch {
			// Retry after small backoff
		}

		if (!isProcessAlive(child)) return false;
		await delay(100);
	}
	return false;
}

/**
 * Resolve deterministic Maven classpath for the module.
 * Checks for pre-emitted `target/unidbg-classpath.txt`, or runs `mvn dependency:build-classpath` once to emit it.
 */
async function resolveModuleClasspath(unidbgDir: string, isIos: boolean, javaHome?: string): Promise<string> {
	const moduleName = isIos ? "unidbg-ios" : "unidbg-android";
	const moduleDir = path.join(unidbgDir, moduleName);
	const classpathFile = path.join(moduleDir, "target", "unidbg-classpath.txt");

	if (fs.existsSync(classpathFile)) {
		try {
			const content = fs.readFileSync(classpathFile, "utf8").trim();
			if (content.length > 0) return content;
		} catch {}
	}

	const isWin = process.platform === "win32";
	const wrapperName = isWin ? "mvnw.cmd" : "mvnw";
	const wrapperPath = path.join(unidbgDir, wrapperName);
	const mavenBin = fs.existsSync(wrapperPath) ? wrapperPath : "mvn";

	const env: NodeJS.ProcessEnv = {
		...process.env,
		JAVA_HOME: javaHome,
		PATH: javaHome ? `${path.join(javaHome, "bin")}${path.delimiter}${process.env.PATH || ""}` : process.env.PATH,
	};

	try {
		const resolvedCmd = await resolveStdioSpawnCommand(
			{
				type: "stdio",
				command: mavenBin,
				args: [
					"-f",
					path.join(moduleDir, "pom.xml"),
					"dependency:build-classpath",
					"-DincludeScope=test",
					"-Dmdep.outputFile=target/unidbg-classpath.txt",
					"-DskipTests",
				],
			},
			{ cwd: unidbgDir, env, platform: process.platform },
		);

		const comp = spawnSync(resolvedCmd.cmd[0], resolvedCmd.cmd.slice(1), {
			cwd: unidbgDir,
			env,
			windowsVerbatimArguments: resolvedCmd.windowsVerbatimArguments,
			windowsHide: resolvedCmd.windowsHide,
			encoding: "utf8",
		});

		if (comp.status !== 0) {
			throw new Error(
				`Failed to generate Unidbg dependency classpath via Maven (exit code ${comp.status}): ${comp.stderr || comp.stdout}`,
			);
		}

		if (fs.existsSync(classpathFile)) {
			const content = fs.readFileSync(classpathFile, "utf8").trim();
			if (content.length > 0) return content;
		}

		throw new Error(`Maven dependency classpath file was not generated at ${classpathFile}`);
	} catch (err: unknown) {
		if (err instanceof Error) throw err;
		throw new Error(`Unexpected error resolving Unidbg module classpath: ${String(err)}`);
	}
}

/**
 * Build complete classpath from reactor classes, jars, and dependency classpath.
 */
async function assembleUnidbgClasspath(
	unidbgDir: string,
	isIos: boolean,
	extraDir?: string,
	javaHome?: string,
): Promise<string> {
	const parts: string[] = [];
	if (extraDir && fs.existsSync(extraDir)) {
		parts.push(extraDir);
	}

	const modules = [
		path.join(unidbgDir, "unidbg-api"),
		path.join(unidbgDir, isIos ? "unidbg-ios" : "unidbg-android"),
		path.join(unidbgDir, "backend", "unicorn2"),
		path.join(unidbgDir, "backend", "dynarmic"),
	];

	for (const m of modules) {
		const targetClasses = path.join(m, "target", "classes");
		if (fs.existsSync(targetClasses)) parts.push(targetClasses);
		const targetTestClasses = path.join(m, "target", "test-classes");
		if (fs.existsSync(targetTestClasses)) parts.push(targetTestClasses);

		const targetDir = path.join(m, "target");
		if (fs.existsSync(targetDir)) {
			try {
				const entries = fs.readdirSync(targetDir);
				for (const entry of entries) {
					if (entry.endsWith(".jar") && !entry.endsWith("-sources.jar") && !entry.endsWith("-javadoc.jar")) {
						parts.push(path.join(targetDir, entry));
					}
				}
			} catch {}
		}
	}

	const resolvedDeps = await resolveModuleClasspath(unidbgDir, isIos, javaHome);
	if (resolvedDeps) {
		parts.push(resolvedDeps);
	}

	return parts.join(path.delimiter);
}

/**
 * Static non-executing check for Unidbg classpath and reactor launch prerequisites.
 * Verifies that the required reactor modules, classes/jars, and classpath file / maven command exist.
 */
export function checkUnidbgLaunchPrerequisites(
	unidbgDir: string,
	isIos = false,
	env: NodeJS.ProcessEnv = process.env,
): { ok: boolean; reason?: string } {
	if (!fs.existsSync(unidbgDir)) {
		return { ok: false, reason: `Unidbg directory does not exist at ${unidbgDir}` };
	}

	const apiModule = path.join(unidbgDir, "unidbg-api");
	const targetModule = path.join(unidbgDir, isIos ? "unidbg-ios" : "unidbg-android");
	const hasApi = fs.existsSync(apiModule);
	const hasTarget = fs.existsSync(targetModule);
	const hasTargetPom = fs.existsSync(path.join(targetModule, "pom.xml"));

	if (!hasTarget || !hasTargetPom) {
		return {
			ok: false,
			reason: `Unidbg directory found at ${unidbgDir}, but ${isIos ? "unidbg-ios" : "unidbg-android"} module or pom.xml is missing.`,
		};
	}

	const checkModuleCompiled = (dir: string): boolean => {
		const target = path.join(dir, "target");
		if (!fs.existsSync(target)) return false;
		if (fs.existsSync(path.join(target, "classes")) || fs.existsSync(path.join(target, "test-classes"))) return true;
		try {
			return fs
				.readdirSync(target)
				.some(f => f.endsWith(".jar") && !f.endsWith("-sources.jar") && !f.endsWith("-javadoc.jar"));
		} catch {
			return false;
		}
	};

	if (!hasApi || !checkModuleCompiled(apiModule) || !checkModuleCompiled(targetModule)) {
		return {
			ok: false,
			reason: `Unidbg reactor at ${unidbgDir} is missing compiled classes or jars for unidbg-api / ${isIos ? "unidbg-ios" : "unidbg-android"}.`,
		};
	}

	const unicornModule = path.join(unidbgDir, "backend", "unicorn2");
	const dynarmicModule = path.join(unidbgDir, "backend", "dynarmic");
	const classpathFile = path.join(targetModule, "target", "unidbg-classpath.txt");
	let classpathEntries: string[] = [];
	try {
		classpathEntries = fs.readFileSync(classpathFile, "utf8").trim().split(path.delimiter).filter(Boolean);
	} catch {}
	const hasValidClasspathFile = classpathEntries.length > 0 && classpathEntries.every(entry => fs.existsSync(entry));
	const hasClasspathBackend =
		hasValidClasspathFile && classpathEntries.some(entry => /(?:unicorn2|dynarmic)/i.test(entry));

	const hasBackend =
		hasClasspathBackend ||
		(fs.existsSync(unicornModule) && checkModuleCompiled(unicornModule)) ||
		(fs.existsSync(dynarmicModule) && checkModuleCompiled(dynarmicModule));

	if (!hasBackend) {
		return {
			ok: false,
			reason: `Unidbg reactor at ${unidbgDir} is missing compiled backend CPU emulation module (backend/unicorn2 or backend/dynarmic).`,
		};
	}

	const isWin = process.platform === "win32";
	const wrapperPath = path.join(unidbgDir, isWin ? "mvnw.cmd" : "mvnw");
	const hasMaven =
		fs.existsSync(wrapperPath) ||
		fs.existsSync(path.join(unidbgDir, "mvnw")) ||
		Boolean(
			env.PATH && env.PATH.split(path.delimiter).some(p => fs.existsSync(path.join(p, isWin ? "mvn.cmd" : "mvn"))),
		);

	if (!hasValidClasspathFile && !hasMaven) {
		return {
			ok: false,
			reason: `Cannot resolve Unidbg module classpath: target/unidbg-classpath.txt is empty or missing and Maven wrapper / mvn executable not found.`,
		};
	}

	return { ok: true };
}

/**
 * Compile a .java harness source file against the unidbg classpath using validated JDK 8 javac.
 */
async function compileHarnessSource(
	javaSourcePath: string,
	unidbgDir: string,
	isIos: boolean,
	javaHome?: string,
): Promise<{ outDir: string; className: string }> {
	const outDir = path.join(path.dirname(javaSourcePath), "out_classes");
	fs.mkdirSync(outDir, { recursive: true });

	const javacExe = process.platform === "win32" ? "javac.exe" : "javac";
	const javacBin = javaHome ? path.join(javaHome, "bin", javacExe) : javacExe;
	const classpath = await assembleUnidbgClasspath(unidbgDir, isIos, outDir, javaHome);

	const comp = spawnSync(javacBin, ["-encoding", "UTF-8", "-cp", classpath, "-d", outDir, javaSourcePath], {
		env: { ...process.env, JAVA_HOME: javaHome },
		encoding: "utf8",
	});

	if (comp.status !== 0) {
		throw new Error(`javac compilation failed: ${comp.stderr || comp.stdout}`);
	}

	const content = fs.readFileSync(javaSourcePath, "utf8");
	const pkgMatch = content.match(/package\s+([a-zA-Z0-9_.]+);/);
	const clsMatch = content.match(/public\s+class\s+([a-zA-Z0-9_]+)/);

	const pkg = pkgMatch ? pkgMatch[1] : "";
	const cls = clsMatch ? clsMatch[1] : path.basename(javaSourcePath, ".java");
	const fullClassName = pkg ? `${pkg}.${cls}` : cls;

	return { outDir, className: fullClassName };
}

function detectIsIos(options: UnidbgLaunchOptions): boolean {
	if (options.type === "ipa") return true;
	if (options.type === "jni") return false;
	if (options.targetPath && options.targetPath.toLowerCase().endsWith(".ipa")) return true;
	if (options.harnessPath && fs.existsSync(options.harnessPath)) {
		try {
			const content = fs.readFileSync(options.harnessPath, "utf8");
			if (content.includes("com.github.unidbg.ios") || content.includes("IpaLoader")) {
				return true;
			}
		} catch {}
	}
	return false;
}

/**
 * Launch Unidbg harness process, monitor port health, and attach to active MCP session.
 */
export async function launchUnidbgHarness(options: UnidbgLaunchOptions): Promise<UnidbgProcessInfo> {
	const jdk = validateJdk8(options.javaHome);
	if (!jdk.valid) {
		throw new Error(jdk.error ?? "Invalid JDK 8 installation for Unidbg.");
	}

	const inspected = inspectUnidbg({ dir: options.unidbgHome });
	if (!inspected.unidbgDir) {
		throw new Error("Unidbg repository or installation not found. Run 'reverse unidbg build' first.");
	}
	const unidbgDir = inspected.unidbgDir;
	const prerequisites = checkUnidbgLaunchPrerequisites(unidbgDir, detectIsIos(options));
	if (!prerequisites.ok) throw new Error(prerequisites.reason);
	const requestedPort = options.port ?? 9239;
	const arch = String(options.arch ?? "64") === "32" ? 32 : 64;
	const backend = options.backend ?? "unicorn2";
	const isIos = detectIsIos(options);
	const owner = options.owner ?? options.mcpManager;

	if (options.port !== undefined) {
		const existing = activeHarnesses.get(options.port);
		if (existing && isProcessAlive(existing.process)) {
			if (existing.owner !== owner) {
				throw new Error(
					`Port ${options.port} is already in use by an active Unidbg harness owned by another session.`,
				);
			}
			await stopProcess(existing);
		}
	}

	let targetClassName = options.harnessClass;
	let extraClasspathDir: string | undefined;

	if (options.harnessPath && fs.existsSync(options.harnessPath)) {
		if (options.harnessPath.endsWith(".java")) {
			options.onLog?.(`Compiling harness source: ${options.harnessPath}...\n`);
			const compiled = await compileHarnessSource(options.harnessPath, unidbgDir, isIos, jdk.javaHome);
			targetClassName = compiled.className;
			extraClasspathDir = compiled.outDir;
		}
	}

	if (!targetClassName) {
		throw new Error("No harness class name or source file specified for launch.");
	}

	const isWin = process.platform === "win32";
	const javaExe = isWin ? "java.exe" : "java";
	const javaBin = jdk.javaBin ?? (jdk.javaHome ? path.join(jdk.javaHome, "bin", javaExe) : "java");
	const classpath = await assembleUnidbgClasspath(unidbgDir, isIos, extraClasspathDir, jdk.javaHome);

	const env: NodeJS.ProcessEnv = {
		...process.env,
		JAVA_HOME: jdk.javaHome,
		PATH: jdk.javaHome
			? `${path.join(jdk.javaHome, "bin")}${path.delimiter}${process.env.PATH || ""}`
			: process.env.PATH,
	};

	const javaArgs: string[] = [
		"-cp",
		classpath,
		`-Dunidbg.port=${requestedPort}`,
		`-Dunidbg.arch=${arch}`,
		`-Dunidbg.backend=${backend}`,
		`-Dunidbg.type=${isIos ? "ipa" : "jni"}`,
	];
	if (options.targetPath) {
		javaArgs.push(`-Dunidbg.target=${options.targetPath}`);
	}
	javaArgs.push(targetClassName);

	options.onLog?.(`Launching harness via Java: ${targetClassName} on port ${requestedPort}...\n`);

	const logs: string[] = [];
	const MAX_LOG_ENTRIES = 200;
	const MAX_LOG_BYTES = 512 * 1024;
	let totalLogBytes = 0;
	let currentLastOutput = "";

	function appendLog(line: string) {
		logs.push(line);
		totalLogBytes += line.length;
		while (logs.length > MAX_LOG_ENTRIES || totalLogBytes > MAX_LOG_BYTES) {
			const shifted = logs.shift();
			if (shifted) totalLogBytes -= shifted.length;
		}
	}

	let stdoutStartupBuffer = "";
	let portResolved = false;
	const {
		promise: actualPortPromise,
		resolve: resolveActualPort,
		reject: rejectActualPort,
	} = Promise.withResolvers<number>();

	let child: ChildProcess;
	try {
		child = spawn(javaBin, javaArgs, {
			cwd: unidbgDir,
			env,
			stdio: ["pipe", "pipe", "pipe"],
		});
	} catch (err: unknown) {
		throw new Error(`Failed to spawn Java harness process: ${err instanceof Error ? err.message : String(err)}`);
	}

	child.on("error", (err: Error) => {
		if (!portResolved) {
			portResolved = true;
			rejectActualPort(new Error(`Unidbg harness process error before port announcement: ${err.message}`));
		}
		options.onLog?.(`Unidbg harness process error: ${err.message}\n`);
	});

	child.once("close", (code: number | null, signal: NodeJS.Signals | null) => {
		if (!portResolved) {
			portResolved = true;
			rejectActualPort(
				new Error(
					`Unidbg harness process exited with code ${code ?? "unknown"}, signal ${signal ?? "none"} before announcing MCP server port.`,
				),
			);
		}
	});

	child.stdout?.on("data", (chunk: unknown) => {
		const text = typeof chunk === "string" ? chunk : Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
		options.onLog?.(text);
		appendLog(text);

		const lines = text
			.split("\n")
			.map(l => l.trim())
			.filter(Boolean);
		if (lines.length > 0) {
			currentLastOutput = lines[lines.length - 1].slice(0, 4096);
		}

		if (!portResolved) {
			stdoutStartupBuffer += text;
			if (stdoutStartupBuffer.length > 65536) {
				stdoutStartupBuffer = stdoutStartupBuffer.slice(-32768);
			}
			const match = stdoutStartupBuffer.match(/MCP server started on port\s+(\d+)/i);
			if (match) {
				portResolved = true;
				resolveActualPort(Number.parseInt(match[1], 10));
			}
		}
	});

	child.stderr?.on("data", (chunk: unknown) => {
		const text = typeof chunk === "string" ? chunk : Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
		options.onLog?.(text);
		appendLog(`[stderr] ${text}`);
	});

	const portTimeoutMs = Math.min(options.timeoutMs ?? 30_000, 30_000);
	const portTimer = setTimeout(() => {
		if (!portResolved) {
			portResolved = true;
			rejectActualPort(
				new Error(
					`Timed out waiting for Unidbg harness to start MCP server after ${portTimeoutMs}ms (PID: ${child.pid}).`,
				),
			);
		}
	}, portTimeoutMs);

	let actualPort: number;
	try {
		if (options.signal?.aborted) {
			throw new Error("Launch aborted before port announcement.");
		}
		actualPort = await actualPortPromise;
	} catch (err: unknown) {
		clearTimeout(portTimer);
		try {
			child.kill("SIGKILL");
		} catch {}
		throw err;
	} finally {
		clearTimeout(portTimer);
	}

	if (!isProcessAlive(child)) {
		throw new Error(`Unidbg harness process (PID: ${child.pid}) died immediately after port announcement.`);
	}

	const existingHarness = activeHarnesses.get(actualPort);
	if (existingHarness && isProcessAlive(existingHarness.process)) {
		if (existingHarness.owner !== owner) {
			try {
				child.kill("SIGKILL");
			} catch {}
			throw new Error(
				`MCP server port ${actualPort} is already owned by an active harness belonging to another session.`,
			);
		}
		await stopProcess(existingHarness);
	}

	const serverName = `unidbg-mcp-${actualPort}`;

	if (options.mcpManager) {
		const existingConn = options.mcpManager.getConnection(serverName);
		if (existingConn) {
			try {
				child.kill("SIGKILL");
			} catch {}
			throw new Error(
				`Cannot attach Unidbg MCP server: server name '${serverName}' is already registered in MCP manager.`,
			);
		}
	}

	const sseUrl = `http://localhost:${actualPort}/sse`;
	const processInfo: UnidbgProcessInfo = {
		pid: child.pid ?? 0,
		port: actualPort,
		serverName,
		type: isIos ? "ipa" : "jni",
		targetPath: options.targetPath,
		arch,
		backend,
		harnessPath: options.harnessPath,
		harnessClass: targetClassName,
		sseUrl,
		ready: false,
		startTime: Date.now(),
		process: child,
		mcpManager: options.mcpManager,
		owner,
		logs,
		get lastOutput(): string {
			return currentLastOutput;
		},
		set lastOutput(val: string | undefined) {
			currentLastOutput = val ?? "";
		},
	};

	activeHarnesses.set(actualPort, processInfo);

	// Guarded close listener: compare reference identity so old process does not clean up a replacement
	child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
		processInfo.ready = false;
		options.onLog?.(`Unidbg harness process (PID: ${processInfo.pid}) exited with code ${code}, signal ${signal}\n`);
		if (activeHarnesses.get(actualPort) === processInfo) {
			if (processInfo.mcpManager) {
				void processInfo.mcpManager.disconnectServer(serverName).catch(() => {});
			}
			activeHarnesses.delete(actualPort);
		}
	});

	child.on("error", (err: Error) => {
		processInfo.ready = false;
		options.onLog?.(`Unidbg harness process error: ${err.message}\n`);
		if (activeHarnesses.get(actualPort) === processInfo) {
			if (processInfo.mcpManager) {
				void processInfo.mcpManager.disconnectServer(serverName).catch(() => {});
			}
			activeHarnesses.delete(actualPort);
		}
	});

	options.onLog?.(`Waiting for Unidbg SSE endpoint at ${sseUrl}...\n`);
	const endpointReady = await waitForSseEndpoint(actualPort, child, options.timeoutMs ?? 30_000, options.signal);

	const isAlive = isProcessAlive(child);
	if (!endpointReady || !isAlive) {
		await stopProcess(processInfo);
		throw new Error(
			`Unidbg harness failed to initialize (PID: ${child.pid}, alive: ${isAlive}). SSE endpoint did not respond successfully.`,
		);
	}

	if (options.mcpManager) {
		options.onLog?.(`Connecting ${serverName} to active session in-memory...\n`);
		const serverConfig: MCPServerConfig = {
			type: "sse",
			url: sseUrl,
			timeout: options.timeoutMs ?? 30_000,
		};

		try {
			const loadResult = await options.mcpManager.connectServers(
				{ [serverName]: serverConfig },
				{
					[serverName]: {
						provider: "reverse",
						providerName: "unidbg",
						path: "in-memory",
						level: "native",
					},
				},
				undefined,
				0,
			);

			const serverErr = loadResult.errors.get(serverName);
			if (serverErr) {
				await stopProcess(processInfo);
				throw new Error(`Failed to mount ${serverName} into session: ${serverErr}`);
			}

			let isConnected = loadResult.connectedServers.includes(serverName);
			let tools = options.mcpManager.getTools().filter(t => t.mcpServerName === serverName);

			if (!isConnected || tools.length === 0) {
				try {
					const status = await options.mcpManager.waitForStartup(5000);
					isConnected = status.connected.includes(serverName);
					tools = options.mcpManager.getTools().filter(t => t.mcpServerName === serverName);
				} catch {}
			}

			if (!isConnected && tools.length === 0) {
				await stopProcess(processInfo);
				throw new Error(`Failed to mount ${serverName} into session: tools not discovered`);
			}

			options.onLog?.(
				`Session MCP connection established: ${serverName} active with ${tools.length} published debugger tools.\n`,
			);
		} catch (err: unknown) {
			await stopProcess(processInfo);
			throw err;
		}
	}

	processInfo.ready = true;
	options.onLog?.(`Unidbg harness is fully ready at ${sseUrl}\n`);
	return processInfo;
}

export interface UnidbgProbeLaunchOptions {
	targetPath: string;
	apkPath?: string;
	apiLevel?: number;
	arch?: 32 | 64 | "32" | "64";
	backend?: "unicorn2" | "dynarmic";
	callOnLoad?: boolean;
	envProfile?: UnidbgEnvProfile | string;
	outPath?: string;
	unidbgHome?: string;
	javaHome?: string;
	timeoutMs?: number;
	onLog?: (text: string) => void;
	signal?: AbortSignal;
}

export interface UnidbgProbeRecord {
	className: string;
	methodName: string;
	signature: string;
	moduleName: string;
	moduleBase?: string;
	functionAddress: string;
	moduleOffset?: string;
	status: "confirmed";
	source: "unidbg";
	sampleSha256?: string;
}

export interface UnidbgProbeResult {
	success: boolean;
	targetPath: string;
	sampleSha256?: string;
	events: Array<Record<string, unknown>>;
	records: UnidbgProbeRecord[];
	totalEvents: number;
	artifactPath?: string;
	output: string;
	error?: string;
}

export async function probeUnidbgRegisterNatives(options: UnidbgProbeLaunchOptions): Promise<UnidbgProbeResult> {
	const targetPath = options.targetPath;
	if (!fs.existsSync(targetPath)) {
		return {
			success: false,
			targetPath,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: `Target binary not found: ${targetPath}`,
		};
	}

	let stat: fs.Stats;
	try {
		stat = fs.statSync(targetPath);
	} catch (e) {
		return {
			success: false,
			targetPath,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: `Failed to stat target file: ${e instanceof Error ? e.message : String(e)}`,
		};
	}

	if (!stat.isFile()) {
		return {
			success: false,
			targetPath,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: `Target is not a regular file: ${targetPath}`,
		};
	}

	if (stat.size <= 0 || stat.size > 256 * 1024 * 1024) {
		return {
			success: false,
			targetPath,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: `Invalid target binary size (${stat.size} bytes): ${targetPath}`,
		};
	}

	let sampleSha256: string;
	try {
		sampleSha256 = await sha256File(targetPath);
	} catch (err) {
		return {
			success: false,
			targetPath,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: `Failed to stream SHA-256 for target: ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	// Detect ELF architecture (ELFCLASS32 / EM_ARM vs ELFCLASS64 / EM_AARCH64)
	let detectedArch: 32 | 64 | undefined;
	try {
		const elfHeader = Buffer.alloc(18);
		const fd = fs.openSync(targetPath, "r");
		fs.readSync(fd, elfHeader, 0, 18, 0);
		fs.closeSync(fd);
		if (
			elfHeader[0] === 0x7f &&
			elfHeader[1] === 0x45 &&
			elfHeader[2] === 0x4c &&
			elfHeader[3] === 0x46 // 0x7F 'E' 'L' 'F'
		) {
			const elfClass = elfHeader[4];
			const eMachine = elfHeader.readUInt16LE(16);
			if (elfClass === 1 || eMachine === 40) {
				detectedArch = 32;
			} else if (elfClass === 2 || eMachine === 183) {
				detectedArch = 64;
			}
		}
	} catch {}

	let effectiveArch: 32 | 64;
	if (options.arch) {
		const req = String(options.arch) === "32" ? 32 : 64;
		if (detectedArch !== undefined && req !== detectedArch) {
			return {
				success: false,
				targetPath,
				sampleSha256,
				events: [],
				records: [],
				totalEvents: 0,
				output: "",
				error: `Target ELF architecture mismatch: binary is ${detectedArch}-bit, but ${req}-bit was requested.`,
			};
		}
		effectiveArch = req;
	} else {
		effectiveArch = detectedArch ?? 64;
	}

	const jdk = validateJdk8(options.javaHome);
	if (!jdk.valid) {
		return {
			success: false,
			targetPath,
			sampleSha256,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: jdk.error ?? "Invalid JDK 8 installation for Unidbg probe.",
		};
	}

	const inspected = inspectUnidbg({ dir: options.unidbgHome });
	if (!inspected.unidbgDir) {
		return {
			success: false,
			targetPath,
			sampleSha256,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: "Unidbg repository or installation not found. Run 'reverse unidbg build' first.",
		};
	}
	const unidbgDir = inspected.unidbgDir;

	const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "unidbg-probe-"));
	const probeSourcePath = path.join(tempDir, "UnidbgProbe.java");

	let child: ChildProcess | undefined;
	let abortListener: (() => void) | undefined;

	try {
		const code = generateAndroidProbeHarness({
			targetPath,
			apkPath: options.apkPath,
			apiLevel: options.apiLevel,
			arch: effectiveArch,
			backend: options.backend,
			callOnLoad: options.callOnLoad,
			envProfile: options.envProfile,
			harnessClassName: "UnidbgProbe",
		});
		fs.writeFileSync(probeSourcePath, code, "utf8");

		const { outDir, className } = await compileHarnessSource(probeSourcePath, unidbgDir, false, jdk.javaHome);
		const classpath = await assembleUnidbgClasspath(unidbgDir, false, outDir, jdk.javaHome);

		const isWin = process.platform === "win32";
		const javaExe = isWin ? "java.exe" : "java";
		const javaBin = jdk.javaBin ?? (jdk.javaHome ? path.join(jdk.javaHome, "bin", javaExe) : "java");

		const javaArgs = [
			"-Dfile.encoding=UTF-8",
			"-cp",
			classpath,
			className,
			targetPath,
			options.callOnLoad !== false ? "true" : "false",
		];

		const timeoutMs = options.timeoutMs ?? 60_000;
		child = spawn(javaBin, javaArgs, {
			cwd: unidbgDir,
			env: {
				...process.env,
				JAVA_HOME: jdk.javaHome,
				PATH: jdk.javaHome
					? `${path.join(jdk.javaHome, "bin")}${path.delimiter}${process.env.PATH || ""}`
					: process.env.PATH,
			},
		});

		const MAX_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MB cap
		let stdout = "";
		let stderr = "";
		let stdoutTruncated = false;
		let stderrTruncated = false;

		child.stdout?.on("data", chunk => {
			if (stdout.length < MAX_OUTPUT_BYTES) {
				const text = chunk.toString("utf8");
				stdout += text;
				options.onLog?.(text);
			} else if (!stdoutTruncated) {
				stdoutTruncated = true;
				stdout += "\n[stdout buffer limit reached, truncated]\n";
			}
		});

		child.stderr?.on("data", chunk => {
			if (stderr.length < MAX_OUTPUT_BYTES) {
				const text = chunk.toString("utf8");
				stderr += text;
				options.onLog?.(text);
			} else if (!stderrTruncated) {
				stderrTruncated = true;
				stderr += "\n[stderr buffer limit reached, truncated]\n";
			}
		});

		const killProcessTree = () => {
			if (!child || child.killed) return;
			try {
				child.kill("SIGTERM");
				setTimeout(() => {
					try {
						if (child && child.exitCode === null && child.signalCode === null) {
							child.kill("SIGKILL");
						}
					} catch {}
				}, 1500);
			} catch {}
		};

		if (options.signal) {
			abortListener = () => {
				killProcessTree();
			};
			options.signal.addEventListener("abort", abortListener, { once: true });
		}

		const { promise: exitPromise, resolve: resolveExit } = Promise.withResolvers<number>();
		child.on("exit", code => resolveExit(code ?? 0));
		child.on("error", () => resolveExit(1));

		const timer = setTimeout(() => {
			killProcessTree();
			resolveExit(-1);
		}, timeoutMs);

		const exitCode = await exitPromise;
		clearTimeout(timer);

		const events: Array<Record<string, unknown>> = [];
		const records: UnidbgProbeRecord[] = [];
		const eventRegex = /__UNIDBG_PROBE_EVENT_START__([\s\S]*?)__UNIDBG_PROBE_EVENT_END__/g;
		let match: RegExpExecArray | null;
		const MAX_PROBE_EVENTS = 500;

		while ((match = eventRegex.exec(stdout)) !== null && events.length < MAX_PROBE_EVENTS) {
			try {
				const ev = JSON.parse(match[1]) as Record<string, unknown>;
				events.push(ev);
				// Crucial: only confirm when retval is strictly numeric 0 and status is confirmed
				const isConfirmed = ev.status === "confirmed" && typeof ev.retval === "number" && ev.retval === 0;
				if (isConfirmed && Array.isArray(ev.methods)) {
					const clsName = String(ev.class || "UnknownClass");
					for (const m of ev.methods) {
						if (m && typeof m === "object" && !("error" in m)) {
							const methodObj = m as Record<string, unknown>;
							records.push({
								className: clsName,
								methodName: String(methodObj.name || ""),
								signature: String(methodObj.signature || ""),
								moduleName: String(methodObj.module || path.basename(targetPath)),
								moduleBase: typeof methodObj.base === "string" ? methodObj.base : undefined,
								functionAddress: String(methodObj.fnPtr || "0x0"),
								moduleOffset: typeof methodObj.offset === "string" ? methodObj.offset : undefined,
								status: "confirmed",
								source: "unidbg",
								sampleSha256,
							});
						}
					}
				}
			} catch {}
		}

		let artifactPath = options.outPath;
		if (!artifactPath && records.length > 0) {
			const baseName = path.basename(targetPath, path.extname(targetPath));
			artifactPath = path.join(process.cwd(), "artifacts", `unidbg-probe-${baseName}-${Date.now()}.json`);
		}
		if (artifactPath) {
			const resolvedArtifact = path.isAbsolute(artifactPath)
				? artifactPath
				: path.resolve(process.cwd(), artifactPath);
			if (fs.existsSync(resolvedArtifact)) {
				const lstat = fs.lstatSync(resolvedArtifact);
				if (lstat.isSymbolicLink()) {
					throw new Error(`Refusing to write artifact over symbolic link at '${resolvedArtifact}'`);
				}
			}
			fs.mkdirSync(path.dirname(resolvedArtifact), { recursive: true });
			const stagePath = `${resolvedArtifact}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}.tmp`;
			const payload = JSON.stringify(
				{
					targetPath,
					sampleSha256,
					arch: effectiveArch,
					backend: options.backend ?? "unicorn2",
					apiLevel: options.apiLevel ?? 23,
					events,
					records,
					totalEvents: events.length,
					confirmedMethods: records.length,
					timestamp: new Date().toISOString(),
				},
				null,
				2,
			);
			fs.writeFileSync(stagePath, payload, { encoding: "utf8", mode: 0o644 });
			fs.renameSync(stagePath, resolvedArtifact);
			artifactPath = resolvedArtifact;
		}

		return {
			success: exitCode === 0,
			targetPath,
			sampleSha256,
			events,
			records,
			totalEvents: events.length,
			artifactPath,
			output: stdout,
			error: exitCode !== 0 ? stderr.trim() || `Probe exited with code ${exitCode}` : undefined,
		};
	} catch (err: unknown) {
		return {
			success: false,
			targetPath,
			sampleSha256,
			events: [],
			records: [],
			totalEvents: 0,
			output: "",
			error: err instanceof Error ? err.message : String(err),
		};
	} finally {
		if (options.signal && abortListener) {
			options.signal.removeEventListener("abort", abortListener);
		}
		try {
			fs.rmSync(tempDir, { recursive: true, force: true });
		} catch {}
	}
}
