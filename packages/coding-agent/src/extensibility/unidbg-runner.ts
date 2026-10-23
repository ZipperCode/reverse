/**
 * Unidbg Emulation Process Lifecycle & SSE / MCP Session Manager
 *
 * Manages spawning, deterministic classpath resolution, SSE health probing, in-memory session MCP mounting,
 * process supervision, and automatic teardown for Unidbg harnesses.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import type { MCPManager } from "../mcp/manager";
import type { MCPServerConfig } from "../mcp/types";
import { resolveStdioSpawnCommand } from "../mcp/transports/stdio";
import { validateJdk8 } from "./unidbg-builder";
import { inspectUnidbg } from "./unidbg-detect";

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
	const javaBin = jdk.javaHome ? path.join(jdk.javaHome, "bin", javaExe) : "java";
	const classpath = await assembleUnidbgClasspath(unidbgDir, isIos, extraClasspathDir, jdk.javaHome);

	const env: NodeJS.ProcessEnv = {
		...process.env,
		JAVA_HOME: jdk.javaHome,
		PATH: jdk.javaHome ? `${path.join(jdk.javaHome, "bin")}${path.delimiter}${process.env.PATH || ""}` : process.env.PATH,
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
	const { promise: actualPortPromise, resolve: resolveActualPort, reject: rejectActualPort } =
		Promise.withResolvers<number>();

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

		const lines = text.split("\n").map(l => l.trim()).filter(Boolean);
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
