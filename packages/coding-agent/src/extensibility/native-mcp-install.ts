/**
 * Managed Native MCP Services Installer
 *
 * Provides isolated, per-profile installation of:
 * - x64dbg-mcp: Python bridge (x64dbg_automate[mcp]==0.9.2) in managed venv, with optional
 *   managed portable x64dbg debugger + ghost_fungus plugin on Windows.
 * - ghidra-mcp: Verified LaurieWired GhidraMCP 2.0 release (wheel + nested extension JAR)
 *   in managed venv with headless pyghidra support, without requiring backend execution for MCP handshake.
 * - r2mcp: radare2 MCP stdio server plugin verification, config persistence, and live session refresh.
 */
import { spawn } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { $which, getAgentDir, getMCPConfigPath } from "@reverse/utils";
import { withFileLock } from "@reverse/utils/file-lock";
import { openArchive } from "@reverse/utils/ar";
import { connectToServer, disconnectServer, listTools } from "../mcp/client";
import { readMCPConfigFile, writeMCPConfigFile } from "../mcp/config-writer";
import type { MCPConfigFile, MCPServerConfig, MCPServerConnection, MCPStdioServerConfig } from "../mcp/types";
import { resolveStdioSpawnCommand } from "../mcp/transports/stdio";

export type NativeMcpService = "x64dbg" | "ghidra" | "radare2";

/** Canonical MCP server key under `mcpServers`. */
export const NATIVE_MCP_SERVER_NAMES: Record<NativeMcpService, string> = {
	x64dbg: "x64dbg",
	ghidra: "ghidra",
	radare2: "radare2",
};

/** Pinned upstream package specifications & verified release hashes. */
export const X64DBG_AUTOMATE_PIP_SPEC = "x64dbg_automate[mcp]==0.9.2";
export const X64DBG_AUTOMATE_VERSION = "0.9.2";

export const GHIDRA_MCP_VERSION = "2.0.0";
export const GHIDRA_MCP_RELEASE_TAG = "2.0";
export const GHIDRA_MCP_RELEASE_COMMIT = "1e980252087b2479a21b9ca6d82d5829538651a7";
export const GHIDRA_MCP_RELEASE_URL =
	"https://github.com/LaurieWired/GhidraMCP/releases/download/2.0/GhidraMCP-release-2-0.zip";
export const GHIDRA_MCP_RELEASE_SHA256 = "ebf904fd6782e429e95a60a24fe0724b20c0acb2dedb304135a5281f6b5f2e72";
export const GHIDRA_MCP_RELEASE_SIZE = 238526;

// Verified x64dbg snapshot & ghost_fungus plugin assets (for Windows portable installation)
export const X64DBG_SNAPSHOT_VERSION = "2026.05.27";
export const X64DBG_SNAPSHOT_URL =
	"https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/snapshot_2026-05-27_12-11.zip";
export const X64DBG_SNAPSHOT_SHA256 = "d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697";
export const X64DBG_SNAPSHOT_SIZE = 31526833;

export const X64DBG_PLUGIN_VERSION = "0.8.1-ghost_fungus";
export const X64DBG_PLUGIN_64_URL =
	"https://github.com/dariushoule/x64dbg-automate/releases/download/v0.8.1-ghost_fungus/release64-0.8.1-ghost_fungus.zip";
export const X64DBG_PLUGIN_64_SHA256 = "942cd81d2dd02141deacb848846b8a8a26b5f4de1731142a4df6f44581b0597b";
export const X64DBG_PLUGIN_64_SIZE = 3561074;

export const X64DBG_PLUGIN_32_URL =
	"https://github.com/dariushoule/x64dbg-automate/releases/download/v0.8.1-ghost_fungus/release32-0.8.1-ghost_fungus.zip";
export const X64DBG_PLUGIN_32_SHA256 = "9e7e64aa7cdfde5783c7414cf6bc42f97e7ec7d012c894ca5c7f1756f44e7d9a";
export const X64DBG_PLUGIN_32_SIZE = 3371532;

/** Subdirectory names within agent tools directory. */
export const NATIVE_MCP_VENV_SUBDIR = "native-mcp-venv";
export const GHIDRA_MCP_SUBDIR = "ghidramcp";
export const X64DBG_SUBDIR = "x64dbg";

/** Resolve isolated Python virtualenv directory for a specific native service. */
export function getServiceVenvDir(service: "x64dbg" | "ghidra", agentDir?: string): string {
	const base = agentDir ?? getAgentDir();
	return path.join(base, "tools", `${service}-venv`);
}

/** Resolve the fallback/shared Python virtualenv directory. */
export function getNativeMcpVenvDir(agentDir?: string): string {
	const base = agentDir ?? getAgentDir();
	return path.join(base, "tools", NATIVE_MCP_VENV_SUBDIR);
}

/** Resolve the managed GhidraMCP extraction directory (storing wheel, extension JAR and metadata). */
export function getGhidraMcpInstallDir(agentDir?: string): string {
	const base = agentDir ?? getAgentDir();
	return path.join(base, "tools", GHIDRA_MCP_SUBDIR);
}

/** Resolve the managed x64dbg portable directory on Windows. */
export function getX64dbgInstallDir(agentDir?: string): string {
	const base = agentDir ?? getAgentDir();
	return path.join(base, "tools", X64DBG_SUBDIR);
}

/** Resolve venv bin or Scripts directory. */
export function getVenvBinDir(venvDir: string, platform: NodeJS.Platform = process.platform): string {
	return platform === "win32" ? path.join(venvDir, "Scripts") : path.join(venvDir, "bin");
}

/** Resolve python executable inside the managed virtual environment. */
export function getVenvPythonPath(venvDir: string, platform: NodeJS.Platform = process.platform): string {
	const binDir = getVenvBinDir(venvDir, platform);
	return path.join(binDir, platform === "win32" ? "python.exe" : "python");
}

/** Resolve managed binary path inside the virtual environment. */
export function getVenvBinaryPath(
	venvDir: string,
	binaryName: string,
	platform: NodeJS.Platform = process.platform,
): string {
	const binDir = getVenvBinDir(venvDir, platform);
	const exeName = platform === "win32" ? `${binaryName}.exe` : binaryName;
	return path.join(binDir, exeName);
}

/** Parse Python version string into major, minor, micro components. */
export function parsePythonVersion(raw: string): { major: number; minor: number; micro: number } | null {
	const match = raw.trim().match(/Python\s+(\d+)\.(\d+)\.(\d+)/i) || raw.trim().match(/^v?(\d+)\.(\d+)\.(\d+)/);
	if (!match) return null;
	return {
		major: Number.parseInt(match[1], 10),
		minor: Number.parseInt(match[2], 10),
		micro: Number.parseInt(match[3], 10),
	};
}

/**
 * Validate that host Python satisfies pyghidra and x64dbg-automate requirements.
 * pyghidra >= 3.1 (Ghidra headless bridge) and x64dbg_automate strictly require Python 3.10-3.13.
 */
export function checkPythonCompatibility(versionStr: string): {
	compatible: boolean;
	major: number;
	minor: number;
	error?: string;
} {
	const parsed = parsePythonVersion(versionStr);
	if (!parsed) {
		return {
			compatible: false,
			major: 0,
			minor: 0,
			error: `Invalid or unrecognized Python version output: "${versionStr.trim()}".`,
		};
	}
	const { major, minor } = parsed;
	// pyghidra 3.1+ 及 x64dbg_automate 支持 Python >= 3.10
	if (major === 3 && minor >= 10) {
		return { compatible: true, major, minor };
	}
	return {
		compatible: false,
		major,
		minor,
		error: `Python version ${versionStr.trim()} is not supported. Native MCP services (ghidra-mcp / x64dbg-mcp) require Python >= 3.10.`,
	};
}

/**
 * Semantically compare two MCPServerConfigs for identical launch behavior.
 * Normalizes default `enabled: true`, default `type: "stdio"`, and empty envs.
 * Detects differences in command executable, argv arguments, environment variables, or disabled state.
 */
export function isServerConfigIdentical(a: MCPServerConfig | undefined, b: MCPServerConfig | undefined): boolean {
	if (!a || !b) return false;
	if (a.enabled === false || b.enabled === false) {
		return a.enabled === b.enabled;
	}

	const aType = a.type ?? "stdio";
	const bType = b.type ?? "stdio";
	if (aType !== bType) return false;

	if (aType === "stdio" && bType === "stdio") {
		const aStdio = a as MCPStdioServerConfig;
		const bStdio = b as MCPStdioServerConfig;

		if (path.normalize(aStdio.command) !== path.normalize(bStdio.command)) {
			return false;
		}

		const aArgs = aStdio.args ?? [];
		const bArgs = bStdio.args ?? [];
		if (aArgs.length !== bArgs.length) return false;
		for (let i = 0; i < aArgs.length; i++) {
			if (aArgs[i] !== bArgs[i]) return false;
		}

		const aEnv = aStdio.env ?? {};
		const bEnv = bStdio.env ?? {};
		const aKeys = Object.keys(aEnv).filter(k => aEnv[k] !== undefined);
		const bKeys = Object.keys(bEnv).filter(k => bEnv[k] !== undefined);
		if (aKeys.length !== bKeys.length) return false;
		for (const key of aKeys) {
			if (aEnv[key] !== bEnv[key]) return false;
		}

		if ((aStdio.cwd ?? undefined) !== (bStdio.cwd ?? undefined)) {
			return false;
		}

		return true;
	}

	return Bun.deepEquals(a, b);
}

/** Verify SHA256 checksum of an in-memory buffer. */
export function verifySha256(buf: Buffer, expectedHash: string): boolean {
	const actual = crypto.createHash("sha256").update(buf).digest("hex");
	return actual.toLowerCase() === expectedHash.toLowerCase();
}

export interface NativeMcpInspectResult {
	installed: boolean;
	version?: string;
	missing: string[];
	command?: string;
	extensionJar?: string;
	details?: Record<string, unknown>;
}

/**
 * Synchronous, filesystem-only probe for native MCP service installation status.
 * Never executes subprocesses or initiates network requests.
 */
export function inspectNativeMcp(
	service: NativeMcpService,
	options?: { agentDir?: string; env?: Record<string, string | undefined> },
): NativeMcpInspectResult {
	const agentDir = options?.agentDir ?? getAgentDir();

	switch (service) {
		case "x64dbg": {
			const venvDir = getServiceVenvDir("x64dbg", agentDir);
			const venvPy = getVenvPythonPath(venvDir);
			const binPath = getVenvBinaryPath(venvDir, "x64dbg-automate-mcp");
			const isBridgeInstalled = fs.existsSync(venvPy) && fs.existsSync(binPath);
			const missing: string[] = [];
			if (!isBridgeInstalled) {
				missing.push("x64dbg_automate[mcp]");
			}

			const details: Record<string, unknown> = {
				venvDir,
				isBridgeInstalled,
			};

			if (process.platform === "win32") {
				const x64dbgDir = getX64dbgInstallDir(agentDir);
				const managedExe = path.join(x64dbgDir, "release", "x64", "x64dbg.exe");
				const snapMarker = path.join(x64dbgDir, `.snapshot-${X64DBG_SNAPSHOT_VERSION}.ready`);
				const hasManagedExe = fs.existsSync(managedExe) && fs.existsSync(snapMarker);
				const customExe = options?.env?.X64DBG_PATH;
				const effectiveExe =
					customExe && fs.existsSync(customExe) ? customExe : hasManagedExe ? managedExe : undefined;
				const pluginPath = effectiveExe
					? path.join(path.dirname(effectiveExe), "plugins", "x64dbg-automate.dp64")
					: undefined;
				const p64Marker = effectiveExe
					? path.join(path.dirname(effectiveExe), "plugins", `.x64-plugin-${X64DBG_PLUGIN_VERSION}.ready`)
					: undefined;
				const hasPlugin = pluginPath
					? fs.existsSync(pluginPath) &&
						(effectiveExe === customExe || Boolean(p64Marker && fs.existsSync(p64Marker)))
					: false;
				details.x64dbgExe = effectiveExe;
				details.pluginInstalled = hasPlugin;
			}
			return {
				installed: isBridgeInstalled,
				version: isBridgeInstalled ? X64DBG_AUTOMATE_VERSION : undefined,
				missing,
				command: isBridgeInstalled ? binPath : undefined,
				details,
			};
		}

		case "ghidra": {
			const venvDir = getServiceVenvDir("ghidra", agentDir);
			const venvPy = getVenvPythonPath(venvDir);
			const binPath = getVenvBinaryPath(venvDir, "ghidra-mcp");
			const isBridgeInstalled = fs.existsSync(venvPy) && fs.existsSync(binPath);

			const ghidraDir = getGhidraMcpInstallDir(agentDir);
			const jarPath = path.join(ghidraDir, "extension", "GhidraMCP.jar");
			const isJarPresent = fs.existsSync(jarPath);

			const missing: string[] = [];
			if (!isBridgeInstalled) missing.push("ghidra_mcp");
			if (!isJarPresent) missing.push("GhidraMCP.jar");

			const metadataPath = path.join(ghidraDir, "metadata.json");
			let metadata: Record<string, unknown> | undefined;
			if (fs.existsSync(metadataPath)) {
				try {
					metadata = JSON.parse(fs.readFileSync(metadataPath, "utf-8")) as Record<string, unknown>;
				} catch {}
			}

			// GhidraMCP 整体就绪需要同时具备 python bridge 脚本与受管 extension JAR
			const installed = isBridgeInstalled && isJarPresent;
			return {
				installed,
				version: installed ? GHIDRA_MCP_VERSION : undefined,
				missing,
				command: isBridgeInstalled ? binPath : undefined,
				extensionJar: isJarPresent ? jarPath : undefined,
				details: {
					venvDir,
					ghidraDir,
					metadata,
				},
			};
		}

		case "radare2": {
			const r2Bin = $which("r2");
			const r2pmBin = $which("r2pm");

			// 检查 radare2 插件目录及标准候选路径
			// 检查 radare2 插件目录及标准候选路径 (包括 R2PM_PREFIX / R2PM_BINDIR 环境变量)
			const r2mcpLocations: string[] = [];
			const envR2pmBin = options?.env?.R2PM_BINDIR ?? process.env.R2PM_BINDIR;
			if (envR2pmBin) r2mcpLocations.push(path.join(envR2pmBin, "r2mcp"));
			const envR2pmPrefix = options?.env?.R2PM_PREFIX ?? process.env.R2PM_PREFIX;
			if (envR2pmPrefix) r2mcpLocations.push(path.join(envR2pmPrefix, "bin", "r2mcp"));

			const home = process.env.HOME || process.env.USERPROFILE || "";
			if (home) {
				r2mcpLocations.push(
					path.join(home, ".local", "share", "radare2", "prefix", "bin", "r2mcp"),
					path.join(home, ".local", "share", "radare2", "plugins", "r2mcp"),
					path.join(home, ".local", "share", "radare2", "plugins", "bin", "r2mcp"),
					path.join(home, ".local", "share", "radare2", "r2pm", "git", "radare2-mcp", "r2mcp"),
				);
				if (process.platform === "win32") {
					r2mcpLocations.push(
						path.join(home, "AppData", "Local", "radare2", "prefix", "bin", "r2mcp.exe"),
						path.join(home, "AppData", "Local", "radare2", "plugins", "r2mcp.exe"),
					);
				}
			}
			const whichR2mcp = $which("r2mcp");
			if (whichR2mcp) r2mcpLocations.unshift(whichR2mcp);

			const foundPlugin = r2mcpLocations.find(loc => fs.existsSync(loc));
			const missing: string[] = [];
			if (!r2Bin) missing.push("radare2");
			if (!r2pmBin) missing.push("r2pm");
			if (!foundPlugin) missing.push("r2mcp");

			const installed = Boolean(r2Bin && r2pmBin && foundPlugin);
			return {
				installed,
				missing,
				command: r2pmBin ?? "r2pm",
				details: {
					r2Path: r2Bin ?? undefined,
					r2pmPath: r2pmBin ?? undefined,
					pluginPath: foundPlugin,
				},
			};
		}
	}
}

export interface NativeMcpServerOptions {
	agentDir?: string;
	target?: string;
	projectDir?: string;
	ghidraInstallDir?: string;
	backendUrl?: string;
	x64dbgPath?: string;
	timeoutMs?: number;
	env?: Record<string, string | undefined>;
}
function compactEnv(env?: Record<string, string | undefined>): Record<string, string> | undefined {
	if (!env) return undefined;
	const result: Record<string, string> = {};
	for (const [key, value] of Object.entries(env)) {
		if (value !== undefined) {
			result[key] = value;
		}
	}
	return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * Generate MCP stdio server configuration for a native MCP service.
 * Pure configuration constructor: never initiates network requests or downloads.
 */
export function getNativeMcpServer(service: NativeMcpService, options?: NativeMcpServerOptions): MCPStdioServerConfig {
	const agentDir = options?.agentDir ?? getAgentDir();

	switch (service) {
		case "radare2": {
			// 上游 r2pm 启动参数固定为 -r r2mcp，目标样本由运行时工具 open_file 绑定，不通过命令行参数注入
			return {
				type: "stdio",
				command: "r2pm",
				args: ["-r", "r2mcp"],
				env: compactEnv(options?.env),
			};
		}

		case "x64dbg": {
			const venvDir = getServiceVenvDir("x64dbg", agentDir);
			const venvPy = getVenvPythonPath(venvDir);
			const env: Record<string, string | undefined> = { ...options?.env };
			if (options?.x64dbgPath) {
				env.X64DBG_PATH = options.x64dbgPath;
			} else if (process.platform === "win32") {
				// 若未显式传入自定义路径，在 Windows 上自动绑定已安装的受管便携 x64dbg
				const managedExe = path.join(getX64dbgInstallDir(agentDir), "release", "x64", "x64dbg.exe");
				if (fs.existsSync(managedExe)) {
					env.X64DBG_PATH = managedExe;
				}
			}
			return {
				type: "stdio",
				command: venvPy,
				args: ["-c", "from x64dbg_automate.mcp_server import main; main()"],
				env: compactEnv(env),
			};
		}

		case "ghidra": {
			const venvDir = getServiceVenvDir("ghidra", agentDir);
			const venvPy = getVenvPythonPath(venvDir);
			const ghidraDir = getGhidraMcpInstallDir(agentDir);
			const installedJar = path.join(ghidraDir, "extension", "GhidraMCP.jar");

			let args: string[];
			if (options?.target) {
				// 无头持久化项目模式：使用目标样本、项目目录与受管 extension JAR
				const projectDir = options.projectDir ?? path.join(ghidraDir, "projects", "default");
				args = [
					"--headless",
					"--binary",
					options.target,
					"--project",
					projectDir,
					"--save",
					"--extension-jar",
					installedJar,
				];
				if (options.ghidraInstallDir) {
					args.push("--ghidra-install-dir", options.ghidraInstallDir);
				}
			} else {
				// GUI 模式：连接至后台后端端口（默认 http://127.0.0.1:8080/）
				const backendUrl = options?.backendUrl ?? "http://127.0.0.1:8080/";
				args = ["--ghidra-server", backendUrl];
			}

			return {
				type: "stdio",
				command: venvPy,
				args: [
					"-c",
					"import sys; from ghidra_mcp.cli import main; sys.argv[0] = 'ghidra-mcp'; sys.exit(main())",
					...args,
				],
				env: compactEnv(options?.env),
			};
		}
	}
}

async function defaultExecCommand(
	cmd: string,
	args: string[],
	options?: {
		cwd?: string;
		env?: Record<string, string | undefined>;
		signal?: AbortSignal;
		onChunk?: (chunk: string) => void;
	},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	options?.signal?.throwIfAborted();
	const { promise, resolve, reject } = Promise.withResolvers<{ exitCode: number; stdout: string; stderr: string }>();
	let stdout = "";
	let stderr = "";
	let settled = false;

	const cwd = options?.cwd ?? process.cwd();
	const resolved = await resolveStdioSpawnCommand(
		{ type: "stdio", command: cmd, args },
		{ cwd, env: options?.env ?? process.env, platform: process.platform },
	);
	options?.signal?.throwIfAborted();
	const child = spawn(resolved.cmd[0], resolved.cmd.slice(1), {
		cwd,
		stdio: ["ignore", "pipe", "pipe"],
		env: options?.env ?? process.env,
		windowsHide: resolved.windowsHide,
		windowsVerbatimArguments: resolved.windowsVerbatimArguments,
	});

	const onAbort = () => {
		if (!settled) {
			settled = true;
			child.kill("SIGTERM");
			reject(options?.signal?.reason ?? new Error("Operation aborted"));
		}
	};

	if (options?.signal) {
		options.signal.addEventListener("abort", onAbort, { once: true });
	}

	child.stdout?.on("data", chunk => {
		const text = String(chunk);
		stdout += text;
		options?.onChunk?.(text);
	});

	child.stderr?.on("data", chunk => {
		const text = String(chunk);
		stderr += text;
		options?.onChunk?.(text);
	});

	child.on("close", code => {
		if (!settled) {
			settled = true;
			if (options?.signal) {
				options.signal.removeEventListener("abort", onAbort);
			}
			resolve({ exitCode: code ?? 1, stdout, stderr });
		}
	});

	child.on("error", err => {
		if (!settled) {
			settled = true;
			if (options?.signal) {
				options.signal.removeEventListener("abort", onAbort);
			}
			resolve({ exitCode: 1, stdout, stderr: err.message });
		}
	});

	return promise;
}

export interface NativeMcpInstallOptions {
	cwd?: string;
	agentDir?: string;
	scope?: "user" | "project";
	signal?: AbortSignal;
	onChunk?: (text: string) => void;
	pythonPath?: string;
	x64dbgPath?: string;
	fetch?: (
		input: Parameters<typeof globalThis.fetch>[0],
		init?: Parameters<typeof globalThis.fetch>[1],
	) => Promise<Response>;
	execCommand?: (
		cmd: string,
		args: string[],
		options?: {
			cwd?: string;
			env?: Record<string, string | undefined>;
			signal?: AbortSignal;
			onChunk?: (chunk: string) => void;
		},
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
	mcpConnect?: typeof connectToServer;
	mcpListTools?: typeof listTools;
	mcpDisconnect?: typeof disconnectServer;
}

export interface NativeMcpInstallResult {
	configPath: string;
	serverName: string;
	server: MCPServerConfig;
	tools: string[];
	installed: boolean;
}

/**
 * Find a suitable host Python binary matching version constraint 3.10-3.13.
 */
export async function findCompatibleHostPython(options?: {
	pythonPath?: string;
	signal?: AbortSignal;
	exec?: (cmd: string, args: string[]) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
}): Promise<string> {
	const exec = options?.exec ?? ((cmd, args) => defaultExecCommand(cmd, args, { signal: options?.signal }));

	const candidates: string[] = [];
	if (options?.pythonPath) candidates.push(options.pythonPath);

	const envPy = process.env.PYTHON;
	if (envPy) candidates.push(envPy);

	// 搜索特定版本号与常规可执行名
	for (const name of ["python3.12", "python3.11", "python3.13", "python3.10", "python3", "python"]) {
		const resolved = $which(name);
		if (resolved && !candidates.includes(resolved)) {
			candidates.push(resolved);
		}
	}

	// 针对 macOS / Linux / Windows 常见安装位置
	if (process.platform === "darwin") {
		for (const p of [
			"/opt/homebrew/bin/python3.12",
			"/opt/homebrew/bin/python3.11",
			"/usr/local/bin/python3.12",
			"/usr/local/bin/python3.11",
		]) {
			if (fs.existsSync(p) && !candidates.includes(p)) candidates.push(p);
		}
	} else if (process.platform === "win32") {
		const localApp = process.env.LOCALAPPDATA;
		if (localApp) {
			for (const sub of ["Python312", "Python311", "Python310"]) {
				const candidate = path.join(localApp, "Programs", "Python", sub, "python.exe");
				if (fs.existsSync(candidate) && !candidates.includes(candidate)) candidates.push(candidate);
			}
		}
	}

	let lastError = "No Python executable found on PATH.";
	for (const candidate of candidates) {
		options?.signal?.throwIfAborted();
		try {
			const res = await exec(candidate, ["-V"]);
			if (res.exitCode === 0) {
				const raw = res.stdout || res.stderr;
				const check = checkPythonCompatibility(raw);
				if (check.compatible) {
					return candidate;
				}
				lastError = check.error ?? `Incompatible Python version at ${candidate}`;
			}
		} catch (err) {
			lastError = err instanceof Error ? err.message : String(err);
		}
	}

	throw new Error(`Failed to find compatible Python 3.10-3.13 interpreter: ${lastError}`);
}

/**
 * Safely extract wheel and nested extension JAR from LaurieWired GhidraMCP release ZIP.
 */
export async function extractGhidraMcpRelease(
	zipBuf: Buffer,
	targetDir: string,
): Promise<{ wheelPath: string; jarPath: string }> {
	await fs.promises.mkdir(targetDir, { recursive: true, mode: 0o700 });
	const extDir = path.join(targetDir, "extension");
	await fs.promises.mkdir(extDir, { recursive: true, mode: 0o700 });

	// 1. 读取外层 ZIP (GhidraMCP-release-2-0.zip)
	const outerArchive = await openArchive({ bytes: zipBuf, format: "zip" });

	const wheelMember = "GhidraMCP-release-2-0/ghidra_mcp-2.0.0-py3-none-any.whl";
	const wheelFile = await outerArchive.readFile(wheelMember);
	const targetWheelPath = path.join(targetDir, "ghidra_mcp-2.0.0-py3-none-any.whl");
	await fs.promises.writeFile(targetWheelPath, wheelFile.bytes);

	const nestedZipMember = "GhidraMCP-release-2-0/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip";
	const nestedZipFile = await outerArchive.readFile(nestedZipMember);

	// 2. 读取内嵌 Ghidra 扩展 ZIP 并安全解压受信任成员
	const innerArchive = await openArchive({ bytes: nestedZipFile.bytes, format: "zip" });

	const jarMember = "GhidraMCP/lib/GhidraMCP.jar";
	const jarFile = await innerArchive.readFile(jarMember);
	const targetJarPath = path.join(extDir, "GhidraMCP.jar");
	await fs.promises.writeFile(targetJarPath, jarFile.bytes);

	// 保存扩展元数据文件
	for (const metaName of ["extension.properties", "Module.manifest"]) {
		try {
			const metaFile = await innerArchive.readFile(`GhidraMCP/${metaName}`);
			await fs.promises.writeFile(path.join(extDir, metaName), metaFile.bytes);
		} catch {}
	}

	// 记录受管版本元数据
	const metadata = {
		version: GHIDRA_MCP_VERSION,
		commit: GHIDRA_MCP_RELEASE_COMMIT,
		ghidraVersion: "12.1.4",
		sha256: GHIDRA_MCP_RELEASE_SHA256,
		date: "2026-10-10",
		jarPath: targetJarPath,
		wheelPath: targetWheelPath,
	};
	await fs.promises.writeFile(path.join(targetDir, "metadata.json"), JSON.stringify(metadata, null, 2), "utf-8");

	return { wheelPath: targetWheelPath, jarPath: targetJarPath };
}

/**
 * Install a native MCP service into the managed profile, perform live verification handshake,
 * and persist configuration.
 */
export async function installNativeMcpService(
	service: NativeMcpService,
	options: NativeMcpInstallOptions = {},
): Promise<NativeMcpInstallResult> {
	options.signal?.throwIfAborted();
	const scope = options.scope ?? "user";
	const serverName = NATIVE_MCP_SERVER_NAMES[service];

	const cwd = options.cwd ?? process.cwd();
	const userConfigPath = options.agentDir ? path.join(options.agentDir, "mcp.json") : getMCPConfigPath("user", cwd);
	const projectConfigPath = getMCPConfigPath("project", cwd);
	const targetConfigPath = scope === "user" ? userConfigPath : projectConfigPath;

	// 1. 检查既有配置冲突
	const [userConfig, projectConfig] = await Promise.all([
		readMCPConfigFile(userConfigPath),
		readMCPConfigFile(projectConfigPath),
	]);

	if (userConfig.disabledServers?.includes(serverName)) {
		throw new Error(
			`MCP server "${serverName}" is currently disabled in ${userConfigPath}. Re-enable it or remove it from disabledServers before installing.`,
		);
	}
	if (projectConfig.disabledServers?.includes(serverName)) {
		throw new Error(
			`MCP server "${serverName}" is currently disabled in ${projectConfigPath}. Re-enable it or remove it from disabledServers before installing.`,
		);
	}

	const exec = options.execCommand ?? defaultExecCommand;
	const fetchFn = options.fetch ?? globalThis.fetch;
	const agentDir = options.agentDir ?? getAgentDir();

	const targetServerConfig = getNativeMcpServer(service, {
		agentDir,
		x64dbgPath: options.x64dbgPath,
	});

	const targetExisting = (scope === "user" ? userConfig : projectConfig).mcpServers?.[serverName];
	if (targetExisting && !isServerConfigIdentical(targetExisting, targetServerConfig)) {
		throw new Error(
			`Server "${serverName}" already exists in ${targetConfigPath} with a different configuration. Existing configurations will not be overwritten.`,
		);
	}

	const otherScopePath = scope === "user" ? projectConfigPath : userConfigPath;
	const otherExisting = (scope === "user" ? projectConfig : userConfig).mcpServers?.[serverName];
	if (otherExisting && !isServerConfigIdentical(otherExisting, targetServerConfig)) {
		throw new Error(
			`Server "${serverName}" already exists in ${otherScopePath} with a conflicting configuration. Remove or rename the existing server first.`,
		);
	}

	// 2. 根据服务类型执行受管环境与包安装
	if (service === "radare2") {
		// radare2 MCP: 验证 r2/r2pm，执行 r2pm -Uci r2mcp 并校验二进制
		const r2Bin = $which("r2");
		const r2pmBin = $which("r2pm");
		if (!r2Bin || !r2pmBin) {
			throw new Error("radare2 and r2pm must be installed before installing r2mcp.");
		}

		options.onChunk?.(`[r2mcp] Installing radare2 MCP plugin via "${r2pmBin} -Uci r2mcp"...\n`);
		const installRes = await exec(r2pmBin, ["-Uci", "r2mcp"], {
			cwd,
			signal: options.signal,
			onChunk: options.onChunk,
		});
		if (installRes.exitCode !== 0) {
			throw new Error(
				`r2pm install failed with exit code ${installRes.exitCode}: ${installRes.stderr || installRes.stdout}`,
			);
		}

		// 验证插件已成功编译并安装
		const postInspect = inspectNativeMcp("radare2", { agentDir });
		if (!postInspect.installed) {
			throw new Error(
				`r2mcp installation completed but plugin binary was not found in radare2 plugin paths. Check r2pm build logs.`,
			);
		}
	} else {
		// x64dbg 或 ghidra: 需要管理各自独立的 Python >= 3.10 虚拟环境
		const venvDir = getServiceVenvDir(service, agentDir);
		const venvPy = getVenvPythonPath(venvDir);

		if (!fs.existsSync(venvPy)) {
			// 解析兼容的宿主 Python 3.10-3.13 解释器
			const hostPy = await findCompatibleHostPython({
				pythonPath: options.pythonPath,
				signal: options.signal,
				exec: (cmd, args) => exec(cmd, args, { signal: options.signal }),
			});

			options.onChunk?.(`[native-mcp] Creating managed Python virtual environment in ${venvDir}...\n`);
			await fs.promises.mkdir(path.dirname(venvDir), { recursive: true, mode: 0o700 });

			const venvRes = await exec(hostPy, ["-m", "venv", venvDir], {
				cwd: path.dirname(venvDir),
				signal: options.signal,
				onChunk: options.onChunk,
			});
			if (venvRes.exitCode !== 0 || !fs.existsSync(venvPy)) {
				throw new Error(
					`Failed to create virtual environment via "${hostPy} -m venv ${venvDir}": ${venvRes.stderr || venvRes.stdout}`,
				);
			}
		}

		if (service === "x64dbg") {
			// 安装 x64dbg_automate[mcp]==0.9.2
			const inspection = inspectNativeMcp("x64dbg", { agentDir, env: process.env });
			if (!inspection.installed) {
				options.onChunk?.(
					`[x64dbg-mcp] Installing ${X64DBG_AUTOMATE_PIP_SPEC} into managed venv (${venvDir})...\n`,
				);
				const pipRes = await exec(
					venvPy,
					["-m", "pip", "install", "--quiet", "--disable-pip-version-check", X64DBG_AUTOMATE_PIP_SPEC],
					{
						cwd: venvDir,
						signal: options.signal,
						onChunk: options.onChunk,
					},
				);
				if (pipRes.exitCode !== 0) {
					throw new Error(
						`pip install ${X64DBG_AUTOMATE_PIP_SPEC} failed with exit code ${pipRes.exitCode}: ${pipRes.stderr || pipRes.stdout}`,
					);
				}
			}

			// Windows 平台可选安装受管便携 x64dbg 与 ghost_fungus 插件
			if (process.platform === "win32") {
				const x64dbgDir = getX64dbgInstallDir(agentDir);
				const x64Exe = path.join(x64dbgDir, "release", "x64", "x64dbg.exe");
				const x32Exe = path.join(x64dbgDir, "release", "x32", "x32dbg.exe");
				const snapshotMarker = path.join(x64dbgDir, `.snapshot-${X64DBG_SNAPSHOT_VERSION}.ready`);

				if (!fs.existsSync(x64Exe) || !fs.existsSync(x32Exe) || !fs.existsSync(snapshotMarker)) {
					options.onChunk?.(`[x64dbg] Fetching verified portable x64dbg snapshot ${X64DBG_SNAPSHOT_VERSION}...\n`);
					const snapRes = await fetchFn(X64DBG_SNAPSHOT_URL, { signal: options.signal });
					if (!snapRes.ok) {
						throw new Error(`Failed to download x64dbg snapshot: HTTP ${snapRes.status}`);
					}
					const snapBuf = Buffer.from(await snapRes.arrayBuffer());
					if (!verifySha256(snapBuf, X64DBG_SNAPSHOT_SHA256)) {
						throw new Error("SHA256 mismatch on downloaded x64dbg snapshot archive.");
					}

					await fs.promises.mkdir(x64dbgDir, { recursive: true, mode: 0o700 });
					const snapArchive = await openArchive({ bytes: snapBuf, format: "zip" });
					for (const entry of snapArchive.indexEntries()) {
						if (entry.isDirectory) continue;
						const file = await snapArchive.readFile(entry.path);
						const dest = path.join(x64dbgDir, entry.path);
						await fs.promises.mkdir(path.dirname(dest), { recursive: true });
						await fs.promises.writeFile(dest, file.bytes);
					}

					if (!fs.existsSync(x64Exe) || !fs.existsSync(x32Exe)) {
						throw new Error("Extracted x64dbg snapshot is missing required x64dbg.exe or x32dbg.exe.");
					}
					await fs.promises.writeFile(snapshotMarker, `ready ${X64DBG_SNAPSHOT_VERSION}\n`, "utf-8");
				}

				// 独立校验并修复 x64 插件
				const p64DestPath = path.join(x64dbgDir, "release", "x64", "plugins", "x64dbg-automate.dp64");
				const p64Marker = path.join(
					x64dbgDir,
					"release",
					"x64",
					"plugins",
					`.x64-plugin-${X64DBG_PLUGIN_VERSION}.ready`,
				);
				if (!fs.existsSync(p64DestPath) || !fs.existsSync(p64Marker)) {
					options.onChunk?.(`[x64dbg] Fetching ghost_fungus x64 plugin...\n`);
					const p64Res = await fetchFn(X64DBG_PLUGIN_64_URL, { signal: options.signal });
					if (!p64Res.ok) {
						throw new Error(`Failed to download x64dbg x64 plugin: HTTP ${p64Res.status}`);
					}
					const p64Buf = Buffer.from(await p64Res.arrayBuffer());
					if (!verifySha256(p64Buf, X64DBG_PLUGIN_64_SHA256)) {
						throw new Error("SHA256 mismatch on downloaded x64dbg x64 plugin archive.");
					}
					const p64Archive = await openArchive({ bytes: p64Buf, format: "zip" });
					const p64DestDir = path.join(x64dbgDir, "release", "x64", "plugins");
					await fs.promises.mkdir(p64DestDir, { recursive: true });
					for (const entry of p64Archive.indexEntries()) {
						if (entry.isDirectory) continue;
						const norm = entry.path.replace(/\\/g, "/");
						if (norm.startsWith("Release/") || norm.endsWith(".dp64") || norm.endsWith(".dll")) {
							const file = await p64Archive.readFile(entry.path);
							await fs.promises.writeFile(path.join(p64DestDir, path.basename(entry.path)), file.bytes);
						}
					}
					if (!fs.existsSync(p64DestPath)) {
						throw new Error("Extracted x64dbg plugin is missing required x64dbg-automate.dp64.");
					}
					await fs.promises.writeFile(p64Marker, `ready ${X64DBG_PLUGIN_VERSION}\n`, "utf-8");
				}

				// 独立校验并修复 x32 插件
				const p32DestPath = path.join(x64dbgDir, "release", "x32", "plugins", "x64dbg-automate.dp32");
				const p32Marker = path.join(
					x64dbgDir,
					"release",
					"x32",
					"plugins",
					`.x32-plugin-${X64DBG_PLUGIN_VERSION}.ready`,
				);
				if (!fs.existsSync(p32DestPath) || !fs.existsSync(p32Marker)) {
					options.onChunk?.(`[x64dbg] Fetching ghost_fungus x32 plugin...\n`);
					const p32Res = await fetchFn(X64DBG_PLUGIN_32_URL, { signal: options.signal });
					if (!p32Res.ok) {
						throw new Error(`Failed to download x64dbg x32 plugin: HTTP ${p32Res.status}`);
					}
					const p32Buf = Buffer.from(await p32Res.arrayBuffer());
					if (!verifySha256(p32Buf, X64DBG_PLUGIN_32_SHA256)) {
						throw new Error("SHA256 mismatch on downloaded x64dbg x32 plugin archive.");
					}
					const p32Archive = await openArchive({ bytes: p32Buf, format: "zip" });
					const p32DestDir = path.join(x64dbgDir, "release", "x32", "plugins");
					await fs.promises.mkdir(p32DestDir, { recursive: true });
					for (const entry of p32Archive.indexEntries()) {
						if (entry.isDirectory) continue;
						const norm = entry.path.replace(/\\/g, "/");
						if (norm.startsWith("Release/") || norm.endsWith(".dp32") || norm.endsWith(".dll")) {
							const file = await p32Archive.readFile(entry.path);
							await fs.promises.writeFile(path.join(p32DestDir, path.basename(entry.path)), file.bytes);
						}
					}
					if (!fs.existsSync(p32DestPath)) {
						throw new Error("Extracted x64dbg plugin is missing required x64dbg-automate.dp32.");
					}
					await fs.promises.writeFile(p32Marker, `ready ${X64DBG_PLUGIN_VERSION}\n`, "utf-8");
				}
			}
		} else if (service === "ghidra") {
			// 下载、哈希校验并安装 GhidraMCP 2.0 release
			const ghidraDir = getGhidraMcpInstallDir(agentDir);
			const jarPath = path.join(ghidraDir, "extension", "GhidraMCP.jar");

			let wheelPath = path.join(ghidraDir, "ghidra_mcp-2.0.0-py3-none-any.whl");
			if (!fs.existsSync(jarPath) || !fs.existsSync(wheelPath)) {
				options.onChunk?.(`[ghidra-mcp] Downloading verified GhidraMCP ${GHIDRA_MCP_VERSION} release archive...\n`);
				const zipRes = await fetchFn(GHIDRA_MCP_RELEASE_URL, { signal: options.signal });
				if (!zipRes.ok) {
					throw new Error(
						`Failed to download GhidraMCP release from ${GHIDRA_MCP_RELEASE_URL}: HTTP ${zipRes.status} ${zipRes.statusText}`,
					);
				}
				const zipBuf = Buffer.from(await zipRes.arrayBuffer());
				if (!verifySha256(zipBuf, GHIDRA_MCP_RELEASE_SHA256)) {
					throw new Error(
						`SHA256 verification failed for GhidraMCP release archive (expected: ${GHIDRA_MCP_RELEASE_SHA256}).`,
					);
				}

				const extracted = await extractGhidraMcpRelease(zipBuf, ghidraDir);
				wheelPath = extracted.wheelPath;
			}

			// 在虚拟环境中以 [headless] extra 安装本地 wheel (支持 pyghidra >= 3.1)
			options.onChunk?.(`[ghidra-mcp] Installing ${wheelPath}[headless] into managed venv...\n`);
			const pipWheelRes = await exec(
				venvPy,
				["-m", "pip", "install", "--quiet", "--disable-pip-version-check", `${wheelPath}[headless]`],
				{
					cwd: venvDir,
					signal: options.signal,
					onChunk: options.onChunk,
				},
			);
			if (pipWheelRes.exitCode !== 0) {
				throw new Error(
					`pip install for ghidra_mcp wheel failed with exit code ${pipWheelRes.exitCode}: ${pipWheelRes.stderr || pipWheelRes.stdout}`,
				);
			}
		}
	}

	// 3. 校验文件系统状态
	const postInspection = inspectNativeMcp(service, { agentDir, env: process.env });
	if (!postInspection.installed) {
		throw new Error(
			`Installation finished but inspection failed for service "${service}". Missing: ${postInspection.missing.join(", ")}`,
		);
	}

	// 4. 执行真实 MCP stdio 握手测试（确认服务正常启动并暴露工具，无需连接实际调试目标或后端）
	const connect = options.mcpConnect ?? connectToServer;
	const getTools = options.mcpListTools ?? listTools;
	const disconnect = options.mcpDisconnect ?? disconnectServer;

	let connection: MCPServerConnection | undefined;
	let toolNames: string[] = [];

	try {
		connection = await connect(serverName, targetServerConfig, { signal: options.signal });
		const tools = await getTools(connection, { signal: options.signal });
		if (!tools || tools.length === 0) {
			throw new Error(`MCP server '${serverName}' connected successfully but exposed zero tools.`);
		}
		toolNames = tools.map(t => t.name);
	} finally {
		if (connection) {
			await disconnect(connection).catch(() => {});
		}
	}

	options.signal?.throwIfAborted();

	// 5. 握手成功后在目标配置文件锁内原子重读与落盘配置，防止 TOCTOU 并发污染
	await fs.promises.mkdir(path.dirname(targetConfigPath), { recursive: true, mode: 0o700 });
	await withFileLock(targetConfigPath, async () => {
		const [freshUserConfig, freshProjectConfig] = await Promise.all([
			readMCPConfigFile(userConfigPath),
			readMCPConfigFile(projectConfigPath),
		]);

		if (
			freshUserConfig.disabledServers?.includes(serverName) ||
			freshProjectConfig.disabledServers?.includes(serverName)
		) {
			throw new Error(
				`MCP server "${serverName}" was disabled during installation. Aborting configuration write to respect user intent.`,
			);
		}

		const freshTargetConfig = scope === "user" ? freshUserConfig : freshProjectConfig;
		const freshTargetExisting = freshTargetConfig.mcpServers?.[serverName];
		if (freshTargetExisting && !isServerConfigIdentical(freshTargetExisting, targetServerConfig)) {
			throw new Error(
				`Server "${serverName}" was concurrently modified in ${targetConfigPath}. Aborting configuration write to prevent overwrite.`,
			);
		}

		const updated: MCPConfigFile = {
			...freshTargetConfig,
			mcpServers: {
				...freshTargetConfig.mcpServers,
				[serverName]: targetServerConfig,
			},
		};
		await writeMCPConfigFile(targetConfigPath, updated);
	});

	return {
		configPath: targetConfigPath,
		serverName,
		server: targetServerConfig,
		tools: toolNames,
		installed: true,
	};
}
