/**
 * Managed jshook MCP Installer
 *
 * Provides isolated, per-profile installation of @jshookmcp/jshook and webcrack
 * into ~/.reverse/agent/tools/jshookmcp without modifying project or global dependencies.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { $which, getAgentDir, getMCPConfigPath } from "@reverse/utils";
import { callTool, connectToServer, disconnectServer, listTools } from "../mcp/client";
import { addMCPServer, readMCPConfigFile } from "../mcp/config-writer";
import type { MCPServerConfig, MCPServerConnection, MCPStdioServerConfig } from "../mcp/types";
import { resolveStdioSpawnCommand } from "../mcp/transports/stdio";

/** Canonical MCP server key under `mcpServers`. */
export const JSHOOK_MCP_SERVER_NAME = "jshook";

/** Pinned package version for @jshookmcp/jshook. */
export const JSHOOK_PACKAGE_NAME = "@jshookmcp/jshook";
export const JSHOOK_PACKAGE_VERSION = "0.4.2";

/** Pinned package version for webcrack (AST deobfuscator). */
export const WEBCRACK_PACKAGE_NAME = "webcrack";
export const WEBCRACK_PACKAGE_VERSION = "2.16.0";

/** Subdirectory name within agent tools directory. */
export const JSHOOK_TOOLS_SUBDIR = "jshookmcp";

/**
 * Resolve the managed installation directory for jshook MCP.
 * Defaults to `path.join(agentDir ?? getAgentDir(), "tools", "jshookmcp")`.
 */
export function getJshookInstallDir(agentDir?: string): string {
	const base = agentDir ?? getAgentDir();
	return path.join(base, "tools", JSHOOK_TOOLS_SUBDIR);
}

/** Relative entry path to dist/index.mjs under the managed install directory. */
export const JSHOOK_ENTRY_RELATIVE_PATH = path.join("node_modules", "@jshookmcp", "jshook", "dist", "index.mjs");
export const WEBCRACK_DIR_RELATIVE_PATH = path.join("node_modules", "webcrack");
/**
 * Result of inspecting a managed jshook MCP installation.
 */
export interface JshookMcpInspection {
	installed: boolean;
	installDir: string;
	version?: string;
}

/**
 * Synchronous, filesystem-only probe for managed jshook MCP installation.
 * Never executes subprocesses or initiates network requests.
 */
export function inspectJshookMcp(options?: { agentDir?: string; installDir?: string }): JshookMcpInspection {
	const installDir = options?.installDir ?? getJshookInstallDir(options?.agentDir);
	const entryPath = path.join(installDir, JSHOOK_ENTRY_RELATIVE_PATH);
	const pkgPath = path.join(installDir, "node_modules", "@jshookmcp", "jshook", "package.json");
	const webcrackDir = path.join(installDir, WEBCRACK_DIR_RELATIVE_PATH);
	const webcrackPkgPath = path.join(installDir, "node_modules", "webcrack", "package.json");

	// Both entrypoint and webcrack must be present for a complete installation
	if (
		!fs.existsSync(entryPath) ||
		!fs.existsSync(pkgPath) ||
		!fs.existsSync(webcrackDir) ||
		!fs.existsSync(webcrackPkgPath)
	) {
		return {
			installed: false,
			installDir,
		};
	}

	try {
		const jshookRaw = fs.readFileSync(pkgPath, "utf-8");
		const jshookPkg = JSON.parse(jshookRaw) as { version?: string };
		if (jshookPkg.version !== JSHOOK_PACKAGE_VERSION) {
			return {
				installed: false,
				installDir,
			};
		}

		const webcrackRaw = fs.readFileSync(webcrackPkgPath, "utf-8");
		const webcrackPkg = JSON.parse(webcrackRaw) as { version?: string };
		if (webcrackPkg.version !== WEBCRACK_PACKAGE_VERSION) {
			return {
				installed: false,
				installDir,
			};
		}

		return {
			installed: true,
			installDir,
			version: jshookPkg.version,
		};
	} catch {
		return {
			installed: false,
			installDir,
		};
	}
}

/**
 * Generate the MCP stdio server configuration for the managed jshook installation.
 * Configured with search profile and vector embeddings disabled to avoid context
 * explosion and external model downloads.
 */
export function getJshookMcpServer(options?: {
	agentDir?: string;
	installDir?: string;
	nodePath?: string;
}): MCPStdioServerConfig {
	const installDir = options?.installDir ?? getJshookInstallDir(options?.agentDir);
	const entryPath = path.join(installDir, JSHOOK_ENTRY_RELATIVE_PATH);
	const nodeBin = options?.nodePath ?? $which("node") ?? "node";

	return {
		type: "stdio",
		command: nodeBin,
		args: [entryPath],
		cwd: installDir,
		env: {
			MCP_TRANSPORT: "stdio",
			MCP_TOOL_PROFILE: "search",
			SEARCH_VECTOR_ENABLED: "false",
		},
	};
}

export interface NodeVersionCheck {
	compatible: boolean;
	version: string;
	major: number;
	minor: number;
	error?: string;
}

/** Parse `vXX.YY.ZZ` into major/minor/patch numbers. */
export function parseNodeVersion(raw: string): { major: number; minor: number; patch: number } | null {
	const match = raw.trim().match(/^v?(\d+)\.(\d+)\.(\d+)/);
	if (!match) return null;
	return {
		major: Number.parseInt(match[1], 10),
		minor: Number.parseInt(match[2], 10),
		patch: Number.parseInt(match[3], 10),
	};
}

/**
 * Validate that Node.js runtime satisfies both jshook and webcrack constraints.
 * Upstream webcrack (AST deobfuscator) strictly requires Node.js 22 (>= 22.12) or 24.x.
 */
export function checkNodeCompatibility(versionStr: string): NodeVersionCheck {
	const parsed = parseNodeVersion(versionStr);
	if (!parsed) {
		return {
			compatible: false,
			version: versionStr,
			major: 0,
			minor: 0,
			error: `Invalid Node.js version string "${versionStr}".`,
		};
	}
	const { major, minor, patch } = parsed;
	// Upstream intersection: jshook (^22.22.2 || ^24.15.0 || >=26.0.0) and webcrack (22.12+ or 24.x)
	// => Node 22 (>= 22.22.2) or Node 24 (>= 24.15.0).
	if (major === 22) {
		if (minor > 22 || (minor === 22 && patch >= 2)) {
			return { compatible: true, version: versionStr, major, minor };
		}
		return {
			compatible: false,
			version: versionStr,
			major,
			minor,
			error: `Node.js version ${versionStr.trim()} is too old. jshookmcp requires Node.js >= 22.22.2 (or >= 24.15.0).`,
		};
	}
	if (major === 24) {
		if (minor >= 15) {
			return { compatible: true, version: versionStr, major, minor };
		}
		return {
			compatible: false,
			version: versionStr,
			major,
			minor,
			error: `Node.js version ${versionStr.trim()} is too old. jshookmcp requires Node.js >= 24.15.0.`,
		};
	}
	return {
		compatible: false,
		version: versionStr,
		major,
		minor,
		error: `Node.js version ${versionStr.trim()} is not supported. Upstream requirements intersect at Node.js >= 22.22.2 or 24.15.x.`,
	};
}

/** Check exact canonical structural equality between two MCPServerConfigs. */
export function isServerConfigIdentical(a: MCPServerConfig | undefined, b: MCPServerConfig): boolean {
	if (!a || a.enabled === false) return false;
	return Bun.deepEquals(a, b);
}

async function defaultExecCommand(
	cmd: string,
	args: string[],
	options?: { cwd?: string; signal?: AbortSignal; onChunk?: (chunk: string) => void },
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	options?.signal?.throwIfAborted();
	const { promise, resolve, reject } = Promise.withResolvers<{ exitCode: number; stdout: string; stderr: string }>();
	let stdout = "";
	let stderr = "";
	let settled = false;

	// npm 在 Windows 通常是 .cmd；复用 MCP 的安全解析，保留参数边界。
	const cwd = options?.cwd ?? process.cwd();
	const resolved = await resolveStdioSpawnCommand(
		{ type: "stdio", command: cmd, args },
		{ cwd, env: process.env, platform: process.platform },
	);
	options?.signal?.throwIfAborted();
	const child = spawn(resolved.cmd[0], resolved.cmd.slice(1), {
		cwd,
		stdio: ["ignore", "pipe", "pipe"],
		env: process.env,
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

export interface InstallJshookMcpOptions {
	cwd: string;
	scope?: "user" | "project";
	signal?: AbortSignal;
	onChunk?: (text: string) => void;
	agentDir?: string;
	installDir?: string;
	nodePath?: string;
	npmPath?: string;
	// Testability dependency injection
	execCommand?: (
		cmd: string,
		args: string[],
		options?: { cwd?: string; signal?: AbortSignal; onChunk?: (chunk: string) => void },
	) => Promise<{ exitCode: number; stdout: string; stderr: string }>;
	mcpConnect?: typeof connectToServer;
	mcpListTools?: typeof listTools;
	mcpDisconnect?: typeof disconnectServer;
	mcpCallTool?: typeof callTool;
}

export interface InstallJshookMcpResult {
	configPath: string;
	serverName: string;
	server: MCPServerConfig;
	tools: string[];
	installed: boolean;
}

/**
 * Install pinned @jshookmcp/jshook and webcrack into managed profile tools directory,
 * perform live MCP handshake to verify exposed tools, and persist server configuration.
 */
export async function installJshookMcp(options: InstallJshookMcpOptions): Promise<InstallJshookMcpResult> {
	options.signal?.throwIfAborted();
	const scope = options.scope ?? "user";
	const userConfigPath = options.agentDir
		? path.join(options.agentDir, "mcp.json")
		: getMCPConfigPath("user", options.cwd);
	const projectConfigPath = getMCPConfigPath("project", options.cwd);
	const targetConfigPath = scope === "user" ? userConfigPath : projectConfigPath;

	// 1. 检查既有配置：跨 user 与 project 双作用域校验禁用与冲突，避免不安全覆盖
	const [userConfig, projectConfig] = await Promise.all([
		readMCPConfigFile(userConfigPath),
		readMCPConfigFile(projectConfigPath),
	]);

	if (userConfig.disabledServers?.includes(JSHOOK_MCP_SERVER_NAME)) {
		throw new Error(
			`MCP server "${JSHOOK_MCP_SERVER_NAME}" is currently disabled in ${userConfigPath}. Re-enable it or remove it from disabledServers before installing.`,
		);
	}
	if (projectConfig.disabledServers?.includes(JSHOOK_MCP_SERVER_NAME)) {
		throw new Error(
			`MCP server "${JSHOOK_MCP_SERVER_NAME}" is currently disabled in ${projectConfigPath}. Re-enable it or remove it from disabledServers before installing.`,
		);
	}

	const exec = options.execCommand ?? defaultExecCommand;

	// 2. 运行时兼容性校验：检查 Node.js 与 npm 是否可用且满足交集版本要求
	const nodeBin = options.nodePath ?? $which("node") ?? "node";
	const nodeCheckRes = await exec(nodeBin, ["-v"], { signal: options.signal });
	if (nodeCheckRes.exitCode !== 0) {
		throw new Error(`Failed to execute Node.js via "${nodeBin}": ${nodeCheckRes.stderr || nodeCheckRes.stdout}`);
	}
	const nodeCheck = checkNodeCompatibility(nodeCheckRes.stdout);
	if (!nodeCheck.compatible) {
		throw new Error(nodeCheck.error ?? `Node.js version "${nodeCheckRes.stdout.trim()}" is not supported.`);
	}

	const npmBin = options.npmPath ?? $which("npm") ?? "npm";
	const npmCheckRes = await exec(npmBin, ["-v"], { signal: options.signal });
	if (npmCheckRes.exitCode !== 0) {
		throw new Error(`npm binary was not found or failed to execute: ${npmCheckRes.stderr || npmCheckRes.stdout}`);
	}

	const installDir = options.installDir ?? getJshookInstallDir(options.agentDir);
	const serverConfig = getJshookMcpServer({
		installDir,
		agentDir: options.agentDir,
		nodePath: nodeBin,
	});

	// 检查目标作用域既有配置
	const targetExisting = (scope === "user" ? userConfig : projectConfig).mcpServers?.[JSHOOK_MCP_SERVER_NAME];
	if (targetExisting && !isServerConfigIdentical(targetExisting, serverConfig)) {
		throw new Error(
			`Server "${JSHOOK_MCP_SERVER_NAME}" already exists in ${targetConfigPath} with a different configuration or is explicitly disabled. Existing configurations will not be overwritten.`,
		);
	}

	// 检查反向作用域的有效冲突配置（例如 project 配置遮蔽 user 配置）
	const otherScopePath = scope === "user" ? projectConfigPath : userConfigPath;
	const otherExisting = (scope === "user" ? projectConfig : userConfig).mcpServers?.[JSHOOK_MCP_SERVER_NAME];
	if (otherExisting && !isServerConfigIdentical(otherExisting, serverConfig)) {
		throw new Error(
			`Server "${JSHOOK_MCP_SERVER_NAME}" already exists in ${otherScopePath} with a conflicting configuration. Remove or rename the existing server first.`,
		);
	}

	// 3. 幂等安装：若本地已具备完全一致的受管包和入口，跳过 npm 网络下载
	const initialInspection = inspectJshookMcp({ installDir });
	if (!initialInspection.installed) {
		await fs.promises.mkdir(installDir, { recursive: true, mode: 0o700 });

		const installArgs = [
			"install",
			"--prefix",
			installDir,
			"--save-exact",
			"--omit=dev",
			"--omit=optional",
			"--no-audit",
			"--no-fund",
			`${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION}`,
			`${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION}`,
		];

		options.onChunk?.(
			`Installing ${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION} and ${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION} into ${installDir}...\n`,
		);

		const installRes = await exec(npmBin, installArgs, {
			cwd: installDir,
			signal: options.signal,
			onChunk: options.onChunk,
		});

		if (installRes.exitCode !== 0) {
			throw new Error(
				`npm install failed with exit code ${installRes.exitCode}: ${installRes.stderr || installRes.stdout}`,
			);
		}

		// 4. 文件系统校验安装结果完整性与版本精确性
		const postInspection = inspectJshookMcp({ installDir });
		if (!postInspection.installed) {
			throw new Error(
				`Installation finished but failed verification: exact pinned package versions or entry missing in ${installDir}`,
			);
		}
	} else {
		options.onChunk?.(
			`Managed packages ${JSHOOK_PACKAGE_NAME}@${JSHOOK_PACKAGE_VERSION} and ${WEBCRACK_PACKAGE_NAME}@${WEBCRACK_PACKAGE_VERSION} are already installed in ${installDir}.\n`,
		);
	}

	// 5. 真实 MCP 握手测试：通过 stdio 握手并读取 tools 列表，确认暴露有效工具后再落盘
	const connect = options.mcpConnect ?? connectToServer;
	const getTools = options.mcpListTools ?? listTools;
	const disconnect = options.mcpDisconnect ?? disconnectServer;

	let connection: MCPServerConnection | undefined;
	let toolNames: string[] = [];

	try {
		connection = await connect(JSHOOK_MCP_SERVER_NAME, serverConfig, { signal: options.signal });
		const tools = await getTools(connection, { signal: options.signal });
		if (!tools || tools.length === 0) {
			throw new Error("MCP server 'jshook' connected successfully but exposed zero tools.");
		}
		toolNames = tools.map(t => t.name);

		// 搜索与调用元工具均须可用，才能按轻量 profile 完成后续发现与分派。
		if (!["search_tools", "describe_tool", "call_tool"].every(name => toolNames.includes(name))) {
			throw new Error("MCP server 'jshook' is missing required search profile tools.");
		}

		// MCP 失败通常通过 isError/内容返回，不能把 JSON-RPC 请求成功误当分析引擎可用。
		const call = options.mcpCallTool ?? callTool;
		const verification = await call(
			connection,
			"call_tool",
			{
				name: "webcrack_unpack",
				arguments: JSON.stringify({ code: "globalThis.__reverseInstallProbe = 1 + 2;", unpack: false }),
			},
			{ signal: options.signal },
		);
		const text = verification.content
			.filter(part => part.type === "text")
			.map(part => part.text)
			.join("\n");
		let output: { success?: boolean; code?: string };
		try {
			output = JSON.parse(text);
		} catch {
			throw new Error(`jshookmcp deobfuscation verification returned invalid output: ${text}`);
		}
		if (verification.isError || output.success !== true || !output.code?.includes("__reverseInstallProbe = 3")) {
			throw new Error(`jshookmcp deobfuscation verification failed: ${text}`);
		}
	} finally {
		if (connection) {
			await disconnect(connection).catch(() => {});
		}
	}

	// 6. 配置文件持久化：若已有相同配置则跳过写入避免并发冲突；未配置时使用 addMCPServer 保证并发安全
	options.signal?.throwIfAborted();
	if (!targetExisting) {
		await addMCPServer(targetConfigPath, JSHOOK_MCP_SERVER_NAME, serverConfig);
	}

	return {
		configPath: targetConfigPath,
		serverName: JSHOOK_MCP_SERVER_NAME,
		server: serverConfig,
		tools: toolNames,
		installed: true,
	};
}
