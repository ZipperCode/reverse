import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { getAgentDir, logger } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import nativeMcpSessionDescription from "../prompts/tools/native-mcp-session.md" with { type: "text" };
import { inspectNativeMcp, getNativeMcpServer, type NativeMcpService } from "../extensibility/native-mcp-install";
import type { MCPManager } from "../mcp/manager";
import { callTool } from "../mcp/client";
import type { MCPServerConfig, MCPServerConnection, MCPToolCallResult } from "../mcp/types";
import { setMcpTargetBinding, getMcpServerRuntimeState } from "../extensibility/capability-state";
import {
	ReverseRuntimeSessionStore,
	type RuntimeSessionRecord,
	type RuntimeSessionKind,
	createRuntimeSessionId,
} from "../reverse-runtime-session";
import { type UniversalDynamicEvent, formatDynamicLocator } from "../reverse-runtime-session/dynamic-events";
import { EvidenceStore, type AddFactInput } from "../evidence";
import {
	type CanonicalJniMethodRecord,
	type JniEnrichSummary,
	canonicalizeRegisterNativesEvent,
	previewJniEnrichment,
	parseElfMetadataForJni,
	type ElfJniMetadata,
} from "./jni-enrichment";
export const nativeMcpSessionSchema = type({
	action: type
		.enumerated("connect", "status", "list", "disconnect", "locate", "jni_enrich")
		.describe(
			"Action to perform: 'connect' (launch or connect service, bootstrap target, mount upstream tools), 'status' (inspect session/target state), 'list' (list active native sessions), 'disconnect' (detach and cleanly unmount owned session), 'locate' (dynamic-to-static address mapping with BigInt arithmetic), 'jni_enrich' (apply confirmed dynamic RegisterNatives JNI symbols and prototypes to active session)",
		),
	"service?": type
		.enumerated("x64dbg", "ghidra", "radare2")
		.describe(
			"Target native reverse service: 'x64dbg' (Windows/remote dynamic debugger), 'ghidra' (headless/GUI decompiler), 'radare2' (r2mcp disassembly/analysis). Required for 'connect'",
		),
	"session_id?": type("string").describe(
		"Session identifier (e.g. 'native_x64dbg_...'). Required for 'disconnect', optional filter for 'status' and 'locate'",
	),
	"target?": type("string").describe("Target binary path or sample executable to debug, decompile, or analyze"),
	"project_dir?": type("string").describe(
		"Ghidra persistent project directory outside /tmp (default: sample-derived hash directory in agent storage)",
	),
	"backend_url?": type("string").describe("Ghidra GUI backend server URL (default: 'http://127.0.0.1:8080/')"),
	"x64dbg_path?": type("string").describe(
		"Local x64dbg installation path (x96dbg.exe, x64dbg.exe, or x32dbg.exe). Falls back to X64DBG_PATH env var",
	),
	"session_pid?": type("number.integer >= 1").describe("PID of an existing x64dbg instance to attach to"),
	"cmdline?": type("string").describe("Optional command-line arguments to pass when starting a target under x64dbg"),
	"current_dir?": type("string").describe("Optional working directory for target execution in x64dbg"),
	"host?": type("string").describe(
		"Remote host or IP address for remote x64dbg automation (requires trusted channel / SSH tunnel)",
	),
	"req_rep_port?": type("1 <= number.integer <= 65535").describe(
		"Remote x64dbg plugin REQ/REP port (default usually 31337 or as configured in x64dbg.ini)",
	),
	"pub_sub_port?": type("1 <= number.integer <= 65535").describe("Remote x64dbg plugin PUB/SUB port"),
	"timeout_ms?": type("number.integer >= 1000").describe(
		"Connection and bootstrap timeout in milliseconds (default: 30000)",
	),
	"workflow_id?": type("string").describe("Optional reverse_workflow ID to link session and evidence with"),
	"step_id?": type("string").describe("Optional reverse_workflow step ID to link session and evidence with"),
	"runtime_address?": type("string").describe(
		"Dynamic runtime address (hex string, e.g. '0x7ff6a0001000' or '0x401000') for 'locate' action",
	),
	"module_base?": type("string").describe(
		"Runtime module base address (hex string, e.g. '0x7ff6a0000000') for 'locate' action",
	),
	"static_base?": type("string").describe(
		"Static image base address from Ghidra/PE/ELF header (hex string, e.g. '0x140000000') for 'locate' action",
	),
	"module_name?": type("string").describe("Optional module name (e.g. 'main.exe') for locator attribution"),
	"records?": type("unknown[]").describe("Array of CanonicalJniMethodRecord objects to enrich"),
	"events?": type("unknown").describe("Raw RegisterNatives event or array of events from dynamic tracing"),
	"events_path?": type("string").describe(
		"Path to an on-disk JSON artifact containing RegisterNatives events (e.g. from Frida or Unidbg)",
	),
	"preview?": type("boolean").describe(
		"When true (default), previews JNI enrichment without modifying session. Set false to apply changes",
	),
	"decompile?": type("boolean").describe(
		"When true (default), re-decompiles functions after applying symbols and prototypes",
	),
	"batch_size?": type("number.integer >= 1").describe(
		"Maximum number of functions to enrich in this batch (default 20, max 100)",
	),
	"is_static_map?": type("unknown").describe("Mapping of method keys to boolean for DEX ACC_STATIC confirmation"),
});

export type NativeMcpSessionParams = typeof nativeMcpSessionSchema.infer;

export interface VerifiedTargetInfo {
	name?: string;
	path?: string;
	sha256?: string;
	md5?: string;
	baseAddress?: string;
	format?: string;
	arch?: string;
	bits?: number;
}

export interface OwnedNativeSession {
	sessionId: string;
	serverName: string;
	service: NativeMcpService;
	target?: string;
	targetMatched: boolean;
	verifiedTarget?: VerifiedTargetInfo;
	connectedAt: number;
	config: MCPServerConfig;
	status: "connected" | "disconnected" | "failed";
	runtimeSessionId?: string;
	projectDir?: string;
	backendUrl?: string;
	x64dbgPath?: string;
	sessionPid?: number;
	remote?: { host: string; reqPort: number; pubPort?: number };
	events: UniversalDynamicEvent[];
	discoveredTools: string[];
	eventSeq: number;
	workflowId?: string;
	stepId?: string;
}

export interface AddressMappingResult {
	source: "supplied";
	computation: "arithmetic";
	evidence_verified: false;
	runtime_address: string;
	module_base: string;
	module_offset: string;
	rva: string;
	static_base?: string;
	static_address?: string;
	module_name: string;
	evidence_locator: string;
}

export interface NativeMcpSessionResult {
	action: "connect" | "status" | "list" | "disconnect" | "locate" | "jni_enrich";
	session?: OwnedNativeSession;
	sessions?: OwnedNativeSession[];
	mapping?: AddressMappingResult;
	enrichment?: JniEnrichSummary;
	decompilations?: Array<{ name: string; address: string; code: string }>;
	reused?: boolean;
	message?: string;
	services?: Array<{
		id: NativeMcpService;
		installed: boolean;
		version?: string;
		missing: string[];
	}>;
}

interface SessionScopedState {
	sessions: Map<string, OwnedNativeSession>;
}

/** Strictly session-scoped ownership state via WeakMap. No cross-session leakage. */
const SESSION_SCOPES = new WeakMap<object, SessionScopedState>();

function getSessionScopedState(sessionKey: object): SessionScopedState {
	let scope = SESSION_SCOPES.get(sessionKey);
	if (!scope) {
		scope = { sessions: new Map<string, OwnedNativeSession>() };
		SESSION_SCOPES.set(sessionKey, scope);
	}
	return scope;
}

export interface GhidraProjectLock {
	projectDir: string;
	ownerKey: object;
	sessionId: string;
}

/** Process-level tracker of locked Ghidra persistent project realpaths (prevents OS file lock crashes) */
export const ACTIVE_GHIDRA_PROJECTS = new Map<string, GhidraProjectLock>();

export function getActiveGhidraProjectLock(projectDir: string, cwd?: string): GhidraProjectLock | undefined {
	const resolved = cwd ? path.resolve(cwd, projectDir) : path.resolve(projectDir);
	try {
		const canonical = fs.realpathSync(resolved);
		return ACTIVE_GHIDRA_PROJECTS.get(canonical) ?? ACTIVE_GHIDRA_PROJECTS.get(resolved);
	} catch {
		return ACTIVE_GHIDRA_PROJECTS.get(resolved);
	}
}
/** Extract combined text content from an MCP tool call result */
function getToolCallText(result: MCPToolCallResult): string {
	const texts: string[] = [];
	for (const block of result.content) {
		if (block.type === "text") {
			texts.push(block.text);
		}
	}
	return texts.join("\n").trim();
}

/** Extract text content and enforce error-free tool execution */
function requireToolCallSuccess(result: MCPToolCallResult, toolName: string): string {
	const text = getToolCallText(result);
	if (result.isError) {
		throw new Error(`Tool '${toolName}' execution failed: ${text || "unknown tool error"}`);
	}
	if (/^(?:Error:|Failed\b|No active connection\b|No debuggee\b)/i.test(text)) {
		throw new Error(`Tool '${toolName}' reported error: ${text}`);
	}
	return text;
}

/** Parse non-negative BigInt from a hex string or decimal string, validating boundaries */
function parseBigIntAddress(value: unknown, fieldName: string): bigint {
	if (typeof value !== "string" || !value.trim()) {
		throw new ToolError(`Missing or empty ${fieldName}: expected hex address string (e.g. '0x140000000')`);
	}
	const trimmed = value.trim();
	if (trimmed.startsWith("-") || trimmed.startsWith("+")) {
		throw new ToolError(`Invalid ${fieldName}: negative or signed address '${value}' is not permitted`);
	}
	if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+|[a-fA-F0-9]*[a-fA-F][a-fA-F0-9]*)$/.test(trimmed)) {
		throw new ToolError(
			`Invalid ${fieldName}: '${value}' must be a valid non-negative hexadecimal or numeric address`,
		);
	}
	try {
		const parsed =
			trimmed.startsWith("0x") || trimmed.startsWith("0X")
				? BigInt(trimmed)
				: /[a-fA-F]/.test(trimmed)
					? BigInt(`0x${trimmed}`)
					: BigInt(trimmed);
		if (parsed < 0n) {
			throw new ToolError(`Invalid ${fieldName}: address cannot be negative`);
		}
		return parsed;
	} catch {
		throw new ToolError(`Invalid ${fieldName}: '${value}' cannot be parsed as a valid numeric address`);
	}
}

/** Calculate SHA256 of a local file using streaming reads to avoid allocating full buffers */
async function computeFileSha256Async(filePath: string): Promise<string | undefined> {
	try {
		if (!fs.existsSync(filePath)) return undefined;
		const hash = crypto.createHash("sha256");
		const stream = fs.createReadStream(filePath);
		for await (const chunk of stream) {
			hash.update(chunk);
		}
		return hash.digest("hex");
	} catch {
		return undefined;
	}
}

export class NativeMcpSessionTool implements AgentTool<typeof nativeMcpSessionSchema, NativeMcpSessionResult> {
	readonly name = "native_mcp_session";
	readonly label = "Native MCP Session Manager";
	readonly summary =
		"Manage persistent native reverse engineering MCP sessions (x64dbg, Ghidra, radare2) with dynamic tool mounting and address mapping.";
	readonly description = nativeMcpSessionDescription;
	readonly parameters = nativeMcpSessionSchema;
	readonly strict = true;
	readonly loadMode = "discoverable" as const;
	/**
	 * Tiered approvals:
	 * - read: status, list, locate (pure inspect / calculation)
	 * - exec: connect (launches/attaches processes), disconnect (detaches processes)
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = args.action;
			const preview = "preview" in args ? args.preview : undefined;
			if (
				action === "status" ||
				action === "list" ||
				action === "locate" ||
				(action === "jni_enrich" && preview !== false)
			) {
				return "read";
			}
			return "exec";
		}
		return "exec";
	};

	constructor(private readonly session: ToolSession) {}

	get #sessionKey(): object {
		return this.session.sessionManager ?? this.session;
	}

	get #mcpManager(): MCPManager {
		// 严密隔离会话：要求 ToolSession 显式持有 mcpManager，绝不退化为进程全局单例
		if (!this.session.mcpManager) {
			throw new ToolError(
				"No active session MCP manager available; session isolation requires an active MCP manager.",
			);
		}
		return this.session.mcpManager;
	}
	get #agentDir(): string {
		const s = this.session.settings;
		if (s && "getAgentDir" in s && typeof s.getAgentDir === "function") {
			return s.getAgentDir();
		}
		return getAgentDir();
	}

	get #ownedSessions(): Map<string, OwnedNativeSession> {
		return getSessionScopedState(this.#sessionKey).sessions;
	}

	async execute(
		_toolCallId: string,
		params: NativeMcpSessionParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<NativeMcpSessionResult>> {
		throwIfAborted(signal);

		switch (params.action) {
			case "connect":
				return this.handleConnect(params, signal);
			case "status":
				return this.handleStatus(params);
			case "list":
				return this.handleList(params);
			case "disconnect":
				return this.handleDisconnect(params);
			case "locate":
				return this.handleLocate(params);
			case "jni_enrich":
				return this.handleJniEnrich(params, signal);
			default: {
				const unknownAction =
					typeof params === "object" && params !== null && "action" in params ? String(params.action) : "unknown";
				throw new ToolError(`Unknown native_mcp_session action: '${unknownAction}'`);
			}
		}
	}

	private async handleConnect(
		params: NativeMcpSessionParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<NativeMcpSessionResult>> {
		if (!params.service) {
			throw new ToolError("Parameter 'service' ('x64dbg' | 'ghidra' | 'radare2') is required for 'connect' action");
		}
		const service = params.service;
		const agentDir = this.#agentDir;

		// 1. 检验外部工具依赖状态；如果未安装，绝不进行静默自动下载，而是引导用户执行受信的 setup 指令
		const inspect = inspectNativeMcp(service, { agentDir });
		if (!inspect.installed) {
			const catalogId = service === "x64dbg" ? "x64dbg-mcp" : service === "ghidra" ? "ghidra-mcp" : "r2mcp";
			const missingDetail = inspect.missing.length > 0 ? inspect.missing.join(", ") : "required backend";
			throw new ToolError(
				`Native MCP service "${service}" is not installed (missing: ${missingDetail}). ` +
					`Please run 'reverse setup reverse ${catalogId}' or open the interactive setup menu to install dependencies.`,
			);
		}

		// 2. 检查现有会话复用：严格比对所有稳定规范参数（target, project_dir, backend_url, x64dbg_path, session_pid, remote host/ports）
		for (const existing of this.#ownedSessions.values()) {
			if (
				existing.status === "connected" &&
				existing.service === service &&
				existing.target === (params.target ? path.resolve(params.target) : undefined) &&
				existing.projectDir === (params.project_dir ? path.resolve(params.project_dir) : existing.projectDir) &&
				existing.backendUrl === params.backend_url &&
				existing.x64dbgPath === params.x64dbg_path &&
				existing.sessionPid === params.session_pid &&
				existing.remote?.host === params.host &&
				existing.remote?.reqPort === params.req_rep_port &&
				existing.remote?.pubPort === params.pub_sub_port
			) {
				const status = this.#mcpManager.getConnectionStatus(existing.serverName);
				if (status === "connected") {
					return {
						content: [
							{
								type: "text",
								text: `Reusing active native MCP session '${existing.sessionId}' for service '${service}'.`,
							},
						],
						details: {
							action: "connect",
							reused: true,
							session: existing,
							message: "Active session reused safely without creating duplicate processes.",
						},
					};
				}
			}
		}

		// 3. Ghidra 专属约束：同一样本工程目录禁止被两个独立 Java 进程并发打开，避免项目元数据损坏
		let resolvedProjectDir: string | undefined;
		let canonicalProjectKey: string | undefined;
		if (service === "ghidra") {
			if (params.target) {
				const targetPath = path.resolve(params.target);
				if (params.project_dir) {
					resolvedProjectDir = path.resolve(params.project_dir);
				} else {
					const sampleSha256 =
						(await computeFileSha256Async(targetPath)) ??
						crypto.createHash("sha256").update(targetPath).digest("hex");
					const baseName = path.basename(targetPath).replace(/[^a-zA-Z0-9._-]/g, "_");
					resolvedProjectDir = path.join(agentDir, "ghidra-projects", `${baseName}-${sampleSha256.slice(0, 16)}`);
				}

				try {
					canonicalProjectKey = fs.existsSync(resolvedProjectDir)
						? fs.realpathSync(resolvedProjectDir)
						: resolvedProjectDir;
				} catch {
					canonicalProjectKey = resolvedProjectDir;
				}

				const existingLock = ACTIVE_GHIDRA_PROJECTS.get(canonicalProjectKey);
				if (existingLock) {
					const lockSession = this.#ownedSessions.get(existingLock.sessionId);
					if (lockSession && lockSession.status === "connected") {
						throw new ToolError(
							`Ghidra project directory '${resolvedProjectDir}' is already locked by active session '${existingLock.sessionId}'. ` +
								"Headless Ghidra does not permit concurrent locks on the same project.",
						);
					}
					ACTIVE_GHIDRA_PROJECTS.delete(canonicalProjectKey);
				}
			}
		}

		// 4. 构建独占的 MCP 服务名与配置，隔离各目标会话
		const uniqueId = crypto.randomUUID().slice(0, 8);
		const serverName = `native_${service}_${uniqueId}`;
		const sessionId = serverName;

		const serverConfig = getNativeMcpServer(service, {
			agentDir,
			target: params.target ? path.resolve(params.target) : undefined,
			projectDir: resolvedProjectDir,
			backendUrl: params.backend_url,
			x64dbgPath: params.x64dbg_path,
			timeoutMs: params.timeout_ms ?? 30_000,
		});

		// 声明 source 元数据，便于 tool-bridge 与能力系统做归因判定
		const sourceMeta = {
			provider: "reverse",
			providerName: service,
			path: "native-mcp",
			level: "native" as const,
		};

		let connection: MCPServerConnection | undefined;
		let discoveredTools: string[] = [];

		try {
			throwIfAborted(signal);

			// 5. 挂载至宿主 MCPManager
			const loadResult = await this.#mcpManager.connectServers(
				{ [serverName]: serverConfig },
				{ [serverName]: sourceMeta },
				undefined,
				params.timeout_ms ?? 30_000,
			);

			const connectErr = loadResult.errors.get(serverName);
			if (connectErr) {
				await this.#mcpManager.disconnectServer(serverName).catch(() => {});
				throw new ToolError(`Failed to establish native MCP server connection '${serverName}': ${connectErr}`);
			}

			connection = this.#mcpManager.getConnection(serverName);
			if (!connection) {
				await this.#mcpManager.disconnectServer(serverName).catch(() => {});
				throw new ToolError(`Connection '${serverName}' not found in active MCP manager.`);
			}

			// 获取上游服务端暴露的原生工具名称
			if (connection.tools && connection.tools.length > 0) {
				discoveredTools = connection.tools.map(t => t.name);
			} else {
				discoveredTools = this.#mcpManager
					.getTools()
					.filter(t => t.mcpServerName === serverName)
					.map(t => t.mcpToolName ?? t.name);
			}

			// 6. 执行上游启动引导与目标真实性校验 (Bootstrap & Verification)
			let targetMatched = false;
			let verifiedTarget: VerifiedTargetInfo | undefined;
			let bootstrapSummary = "";

			const cwd = this.session.cwd ?? process.cwd();
			const targetPath = params.target ? path.resolve(cwd, params.target) : undefined;

			if (service === "x64dbg") {
				// x64dbg: 区分远程主机、已有 PID 附加与新建启动
				if (params.host && params.req_rep_port) {
					const bootRes = await callTool(connection, "connect_remote", {
						host: params.host,
						req_rep_port: params.req_rep_port,
						pub_sub_port: params.pub_sub_port ?? 31338,
					});
					bootstrapSummary = requireToolCallSuccess(bootRes, "connect_remote");
				} else if (params.session_pid) {
					const bootRes = await callTool(connection, "connect_to_session", {
						x64dbg_path: params.x64dbg_path ?? "",
						session_pid: params.session_pid,
					});
					bootstrapSummary = requireToolCallSuccess(bootRes, "connect_to_session");
				} else if (targetPath) {
					const bootRes = await callTool(connection, "start_session", {
						x64dbg_path: params.x64dbg_path ?? "",
						target_exe: targetPath,
						cmdline: params.cmdline ?? "",
						current_dir: params.current_dir ?? "",
					});
					bootstrapSummary = requireToolCallSuccess(bootRes, "start_session");
				}

				// 查询 consolidated status，验证调试器底层健康
				const statusRes = await callTool(connection, "get_debugger_status", {});
				const statusText = requireToolCallSuccess(statusRes, "get_debugger_status");
				const hasDebuggee = /^Has debuggee:\s*True$/im.test(statusText);

				// x64dbg get_debugger_status 仅返回 PID，不含可执行文件路径；若存在被调试进程，通过模块映射验证完整归一化路径
				if (targetPath && hasDebuggee) {
					try {
						const mapRes = await callTool(connection, "get_memory_map", { mem_type: "image", limit: 50 });
						if (!mapRes.isError) {
							const mapText = getToolCallText(mapRes);
							const normalizedTarget = targetPath.toLowerCase();
							for (const line of mapText.split("\n")) {
								const lowerLine = line.toLowerCase();
								if (lowerLine.includes(normalizedTarget)) {
									targetMatched = true;
									const addrMatch = line.match(/^0x[0-9a-fA-F]+/);
									verifiedTarget = {
										path: targetPath,
										name: path.basename(targetPath),
										baseAddress: addrMatch ? addrMatch[0] : undefined,
									};
									break;
								}
							}
						}
					} catch {}
				}
			} else if (service === "ghidra") {
				// Ghidra: 调用 get_program_info 获取真实打开的程序信息
				const infoRes = await callTool(connection, "get_program_info", {});
				const rawText = requireToolCallSuccess(infoRes, "get_program_info");

				let programInfo: Record<string, unknown> | null = null;
				if (infoRes.structuredContent && typeof infoRes.structuredContent === "object") {
					programInfo = infoRes.structuredContent;
				} else {
					try {
						programInfo = JSON.parse(rawText);
					} catch {}
				}

				if (programInfo) {
					const infoName = String(programInfo.name ?? "");
					const infoExecPath = String(programInfo.executable_path ?? "");
					const infoSha256 = String(programInfo.sha256 ?? "");
					const infoMd5 = String(programInfo.md5 ?? "");
					const imageBase = String(programInfo.image_base ?? "");

					verifiedTarget = {
						name: infoName,
						path: infoExecPath ? path.resolve(cwd, infoExecPath) : targetPath,
						sha256: infoSha256,
						md5: infoMd5,
						baseAddress: imageBase,
					};

					// 校验目标哈希；防止上游 Ghidra 无头模式打开了工程中同名的旧样本
					if (targetPath) {
						const expectedSha256 = await computeFileSha256Async(targetPath);
						if (expectedSha256 && infoSha256 && expectedSha256.toLowerCase() === infoSha256.toLowerCase()) {
							targetMatched = true;
						} else if (
							expectedSha256 &&
							infoSha256 &&
							expectedSha256.toLowerCase() !== infoSha256.toLowerCase()
						) {
							throw new Error(
								`Target hash mismatch in Ghidra project: existing project has SHA256 '${infoSha256}', but requested target has '${expectedSha256}'. Disconnecting to prevent analyzing wrong sample.`,
							);
						} else {
							targetMatched = false;
						}
					}
					bootstrapSummary = `Ghidra loaded '${infoName}' (SHA256: ${infoSha256.slice(0, 16)}..., base: ${imageBase})`;
				} else if (targetPath) {
					targetMatched = false;
				}
			} else if (service === "radare2") {
				// radare2 (r2mcp): 上游规范入参为 file_path
				if (targetPath) {
					const openRes = await callTool(connection, "open_file", { file_path: targetPath });
					const openText = requireToolCallSuccess(openRes, "open_file");
					if (!/File opened successfully/i.test(openText)) {
						throw new Error(`radare2 failed to open file '${targetPath}': ${openText}`);
					}

					// 获取二进制基础信息
					const infoRes = await callTool(connection, "show_info", {});
					const infoSummary = requireToolCallSuccess(infoRes, "show_info");

					targetMatched = true;
					verifiedTarget = {
						path: targetPath,
						name: path.basename(targetPath),
						format: infoSummary.includes("format") ? "binary" : undefined,
					};
					bootstrapSummary = `radare2 opened '${path.basename(targetPath)}'`;
				}
			}

			// 7. 更新运行时能力状态与目标绑定 (Capability State)
			setMcpTargetBinding(
				serverName,
				{
					targetMatched,
					target: targetMatched && targetPath ? targetPath : undefined,
				},
				this.#sessionKey,
				connection,
			);

			// 8. 登记至项目持久化运行时会话存储 (ReverseRuntimeSessionStore)
			const runtimeSessionStore = ReverseRuntimeSessionStore.forSession(cwd);
			const runtimeSessionKind: RuntimeSessionKind = service === "ghidra" ? "ghidra" : "generic";
			const runtimeSessionId = createRuntimeSessionId(runtimeSessionKind);

			const sessionRecord: RuntimeSessionRecord = {
				id: runtimeSessionId,
				name: `${service.toUpperCase()} Native Session`,
				kind: runtimeSessionKind,
				status: "active",
				target_summary: targetPath ? path.basename(targetPath) : `${service}-unattached`,
				target_details: {
					target: targetPath,
					service,
					serverName,
					projectDir: resolvedProjectDir,
				},
				connection: {
					service,
					serverName,
					host: params.host,
					port: params.req_rep_port,
				},
				recovery_hints: {
					restore_tool: "native_mcp_session",
					restore_action: "connect",
					restore_params: {
						service,
						target: targetPath,
						project_dir: resolvedProjectDir,
						host: params.host,
						req_rep_port: params.req_rep_port,
					},
					instructions: [`Reconnect to ${service} via native_mcp_session(action: 'connect')`],
				},
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
				last_heartbeat_at: new Date().toISOString(),
				heartbeat_count: 1,
				stale_timeout_sec: 300,
				status_source: "registered",
				workflow_id: params.workflow_id,
				step_id: params.step_id,
			};

			await runtimeSessionStore.save(sessionRecord).catch(err => {
				logger.warn(`Failed to save runtime session record: ${err}`);
			});

			// 9. 格式化通用动态遥测事件，计入环形事件缓冲区
			const initialEvent: UniversalDynamicEvent = {
				id: `evt_${crypto.randomUUID()}`,
				source: "custom",
				sessionId,
				seq: 1,
				timestamp: new Date().toISOString(),
				kind: "lifecycle",
				channel: "bootstrap",
				target: params.target,
				payload: {
					service,
					targetMatched,
					discoveredToolsCount: discoveredTools.length,
				},
				raw: bootstrapSummary || `Connected to ${service} MCP session`,
			};

			// 10. 如关联工作流，则添加客观事实证据（不自动确认结论）
			if (params.workflow_id || params.step_id) {
				try {
					const evidenceStore = new EvidenceStore({ repositoryRoot: cwd });
					const factInput: AddFactInput = {
						kind: "fact",
						sourceTool: "native_mcp_session",
						locator: formatDynamicLocator(sessionId, 1),
						title: `${service} Native Session Initialized`,
						target: params.target ? path.basename(params.target) : undefined,
						content: `Established native MCP connection for ${service} (tools: ${discoveredTools.length}, targetMatched: ${targetMatched}).`,
						tags: [service, "mcp", "session"],
					};
					await evidenceStore.addFact(factInput);
				} catch (err) {
					logger.warn(`Failed to record fact in evidence store: ${err}`);
				}
			}

			// 11. 建立本会话专属记录与工程锁
			const ownedSession: OwnedNativeSession = {
				sessionId,
				serverName,
				service,
				target: params.target ? path.resolve(params.target) : undefined,
				targetMatched,
				verifiedTarget,
				connectedAt: Date.now(),
				config: serverConfig,
				status: "connected",
				runtimeSessionId,
				projectDir: resolvedProjectDir,
				backendUrl: params.backend_url,
				x64dbgPath: params.x64dbg_path,
				sessionPid: params.session_pid,
				remote:
					params.host && params.req_rep_port
						? { host: params.host, reqPort: params.req_rep_port, pubPort: params.pub_sub_port }
						: undefined,
				events: [initialEvent],
				discoveredTools,
				eventSeq: 1,
				workflowId: params.workflow_id,
				stepId: params.step_id,
			};

			this.#ownedSessions.set(sessionId, ownedSession);
			if (canonicalProjectKey) {
				ACTIVE_GHIDRA_PROJECTS.set(canonicalProjectKey, {
					projectDir: canonicalProjectKey,
					ownerKey: this.#sessionKey,
					sessionId,
				});
			}

			const lines: string[] = [
				`### Native MCP Session Connected: \`${sessionId}\``,
				`- **Service**: ${service}`,
				`- **Status**: connected`,
				`- **Target Matched**: ${targetMatched ? "true" : "false"}`,
			];
			if (params.target) {
				lines.push(`- **Target**: \`${params.target}\``);
			}
			if (verifiedTarget?.baseAddress) {
				lines.push(`- **Image Base**: \`${verifiedTarget.baseAddress}\``);
			}
			if (verifiedTarget?.sha256) {
				lines.push(`- **Target SHA256**: \`${verifiedTarget.sha256}\``);
			}
			lines.push(
				`- **Discovered Tools (${discoveredTools.length})**: ${discoveredTools.slice(0, 15).join(", ")}${discoveredTools.length > 15 ? "..." : ""}`,
			);
			if (bootstrapSummary) {
				lines.push(`- **Bootstrap**: ${bootstrapSummary}`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "connect",
					session: ownedSession,
				},
			};
		} catch (err: unknown) {
			// 发生连接或引导错误时，彻底清理独占连接并释放资源锁
			if (canonicalProjectKey) {
				ACTIVE_GHIDRA_PROJECTS.delete(canonicalProjectKey);
			}
			await this.#mcpManager.disconnectServer(serverName).catch(() => {});
			const message = err instanceof Error ? err.message : String(err);
			throw new ToolError(`Failed to initialize native MCP session for '${service}': ${message}`);
		}
	}

	private async handleStatus(params: NativeMcpSessionParams): Promise<AgentToolResult<NativeMcpSessionResult>> {
		if (params.session_id) {
			const session = this.#ownedSessions.get(params.session_id);
			if (!session) {
				throw new ToolError(
					`Native MCP session '${params.session_id}' not found in this session's active native sessions.`,
				);
			}
			const connStatus = this.#mcpManager.getConnectionStatus(session.serverName);
			const runtimeState = getMcpServerRuntimeState(session.serverName, this.#sessionKey);

			const lines: string[] = [
				`### Native MCP Session Status: \`${session.sessionId}\``,
				`- **Service**: ${session.service}`,
				`- **Manager Status**: ${connStatus}`,
				`- **Session Status**: ${session.status}`,
				`- **Target Matched**: ${session.targetMatched ? "true" : "false"}`,
				`- **Target**: ${session.target ?? "none"}`,
				`- **Tools Published**: ${session.discoveredTools.length}`,
				`- **Executions Recorded**: ${runtimeState?.executionCount ?? 0}`,
			];
			if (session.verifiedTarget?.baseAddress) {
				lines.push(`- **Base Address**: ${session.verifiedTarget.baseAddress}`);
			}
			if (session.verifiedTarget?.sha256) {
				lines.push(`- **Verified SHA256**: ${session.verifiedTarget.sha256}`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "status",
					session,
				},
			};
		}

		// 列出本 ToolSession 所有会话的状态摘要
		const filtered = Array.from(this.#ownedSessions.values()).filter(
			s => !params.service || s.service === params.service,
		);

		const lines: string[] = [`### Active Native MCP Sessions (${filtered.length})`, ""];
		for (const s of filtered) {
			lines.push(`- **\`${s.sessionId}\`** [${s.service}]`);
			lines.push(`  - Status: ${s.status} (targetMatched: ${s.targetMatched})`);
			lines.push(`  - Target: ${s.target ?? "unattached"}`);
			lines.push(`  - Tools: ${s.discoveredTools.length} published`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				sessions: filtered,
			},
		};
	}

	private async handleList(params: NativeMcpSessionParams): Promise<AgentToolResult<NativeMcpSessionResult>> {
		const agentDir = this.#agentDir;
		const allSessions = Array.from(this.#ownedSessions.values()).filter(
			s => !params.service || s.service === params.service,
		);

		const services: Array<{ id: NativeMcpService; installed: boolean; version?: string; missing: string[] }> = [
			{ id: "x64dbg", ...inspectNativeMcp("x64dbg", { agentDir }) },
			{ id: "ghidra", ...inspectNativeMcp("ghidra", { agentDir }) },
			{ id: "radare2", ...inspectNativeMcp("radare2", { agentDir }) },
		];

		const lines: string[] = [`### Native MCP Services & Active Sessions`, "", `#### Host Service Availability:`];
		for (const s of services) {
			const badge = s.installed ? "INSTALLED" : "MISSING";
			lines.push(
				`- **\`${s.id}\`**: [${badge}] ${s.version ?? ""}${s.missing.length > 0 ? ` (missing: ${s.missing.join(", ")})` : ""}`,
			);
		}

		lines.push("", `#### Active Managed Sessions (${allSessions.length}):`);
		if (allSessions.length === 0) {
			lines.push("No active native MCP sessions for this session. Use 'connect' to start one.");
		} else {
			for (const sess of allSessions) {
				lines.push(
					`- **\`${sess.sessionId}\`** (${sess.service}): target=${sess.target ?? "none"}, status=${sess.status}`,
				);
			}
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "list",
				sessions: allSessions,
				services,
			},
		};
	}

	private async handleDisconnect(params: NativeMcpSessionParams): Promise<AgentToolResult<NativeMcpSessionResult>> {
		if (!params.session_id) {
			throw new ToolError("Parameter 'session_id' is required for 'disconnect' action");
		}
		const session = this.#ownedSessions.get(params.session_id);
		if (!session) {
			throw new ToolError(`Session '${params.session_id}' not found in active native sessions for this session.`);
		}

		let detachOk = true;
		let detachNotice = "";

		// 对 x64dbg 执行友好 detach，绝不调用 terminate_session 误杀宿主调试器或目标被调试程序
		if (session.service === "x64dbg") {
			try {
				const connection = this.#mcpManager.getConnection(session.serverName);
				if (connection) {
					const detachRes = await callTool(connection, "disconnect", {});
					if (detachRes.isError) {
						detachOk = false;
						detachNotice = "Debugger detach returned error, transport unmount proceeded.";
					}
				}
			} catch (err) {
				detachOk = false;
				detachNotice = `Debugger detach unverified: ${err}`;
				logger.warn(`Notice: x64dbg upstream detach returned: ${err}`);
			}
		}

		// 卸载与清理 MCPManager 连接；若失败则保留持有状态与工程锁，并抛出错误
		try {
			await this.#mcpManager.disconnectServer(session.serverName);
		} catch (unmountErr) {
			throw new ToolError(
				`Failed to unmount native MCP server '${session.serverName}': ${unmountErr instanceof Error ? unmountErr.message : String(unmountErr)}. ` +
					"Session ownership and locks remain active.",
			);
		}

		// 释放 Ghidra 工程锁
		if (session.projectDir) {
			let canonicalProjectKey: string;
			try {
				canonicalProjectKey = fs.existsSync(session.projectDir)
					? fs.realpathSync(session.projectDir)
					: session.projectDir;
			} catch {
				canonicalProjectKey = session.projectDir;
			}
			const existingLock = ACTIVE_GHIDRA_PROJECTS.get(canonicalProjectKey);
			if (existingLock && existingLock.sessionId === session.sessionId) {
				ACTIVE_GHIDRA_PROJECTS.delete(canonicalProjectKey);
			}
		}

		// 清理会话状态
		session.status = "disconnected";
		this.#ownedSessions.delete(params.session_id);

		// 更新运行时持久化记录状态为 closed
		if (session.runtimeSessionId) {
			const cwd = this.session.cwd ?? process.cwd();
			const store = ReverseRuntimeSessionStore.forSession(cwd);
			try {
				const record = await store.get(session.runtimeSessionId);
				if (record) {
					record.status = "closed";
					record.status_source = "closed";
					record.updated_at = new Date().toISOString();
					await store.save(record);
				}
			} catch {}
		}

		// 解绑目标
		setMcpTargetBinding(session.serverName, { targetMatched: false }, this.#sessionKey);

		const detachSummary = detachOk
			? "Debugger detached cleanly."
			: detachNotice || "Debugger detach unverified; transport unmounted.";

		return {
			content: [
				{
					type: "text",
					text: `Successfully disconnected native MCP session '${params.session_id}' (${session.service}). ${detachSummary}`,
				},
			],
			details: {
				action: "disconnect",
				session,
			},
		};
	}

	private async handleLocate(params: NativeMcpSessionParams): Promise<AgentToolResult<NativeMcpSessionResult>> {
		if (!params.runtime_address) {
			throw new ToolError("Parameter 'runtime_address' is required for 'locate' address mapping");
		}
		if (!params.module_base) {
			throw new ToolError("Parameter 'module_base' is required for 'locate' address mapping");
		}

		const runtimeVA = parseBigIntAddress(params.runtime_address, "runtime_address");
		const moduleBase = parseBigIntAddress(params.module_base, "module_base");

		if (runtimeVA < moduleBase) {
			throw new ToolError(
				`runtime_address (0x${runtimeVA.toString(16).toUpperCase()}) cannot be smaller than module_base (0x${moduleBase.toString(16).toUpperCase()}).`,
			);
		}

		const rva = runtimeVA - moduleBase;
		let staticVA: bigint | undefined;
		let staticBase: bigint | undefined;

		if (params.static_base !== undefined && params.static_base.trim().length > 0) {
			staticBase = parseBigIntAddress(params.static_base, "static_base");
			staticVA = staticBase + rva;
		}

		const moduleName = params.module_name ? path.basename(params.module_name) : "module";
		const rvaHex = `0x${rva.toString(16).toUpperCase()}`;
		const dynamicLocator = `${moduleName}+${rvaHex}`;
		const evidenceLocator =
			staticVA !== undefined
				? `${dynamicLocator} -> static:0x${staticVA.toString(16).toUpperCase()}`
				: dynamicLocator;

		const mapping: AddressMappingResult = {
			source: "supplied",
			computation: "arithmetic",
			evidence_verified: false,
			runtime_address: `0x${runtimeVA.toString(16).toUpperCase()}`,
			module_base: `0x${moduleBase.toString(16).toUpperCase()}`,
			module_offset: rvaHex,
			rva: rvaHex,
			static_base: staticBase !== undefined ? `0x${staticBase.toString(16).toUpperCase()}` : undefined,
			static_address: staticVA !== undefined ? `0x${staticVA.toString(16).toUpperCase()}` : undefined,
			module_name: moduleName,
			evidence_locator: evidenceLocator,
		};

		const lines: string[] = [
			`### Dynamic to Static Address Mapping`,
			`- **Runtime Address (VA)**: \`${mapping.runtime_address}\``,
			`- **Module Base**: \`${mapping.module_base}\``,
			`- **Module Offset (RVA)**: \`${mapping.module_offset}\``,
		];
		if (mapping.static_base) {
			lines.push(`- **Static Base (Ghidra/PE)**: \`${mapping.static_base}\``);
		}
		if (mapping.static_address) {
			lines.push(`- **Static Address (VA)**: \`${mapping.static_address}\``);
		}
		lines.push(`- **Evidence Locator**: \`${mapping.evidence_locator}\``);
		lines.push(
			`- **Coordinates Source**: \`supplied\` (pure 64-bit integer arithmetic, not empirically verified conclusion)`,
		);
		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "locate",
				mapping,
			},
		};
	}
	private async handleJniEnrich(
		params: NativeMcpSessionParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<NativeMcpSessionResult>> {
		if (!params.session_id) {
			throw new ToolError("Parameter 'session_id' is required for 'jni_enrich' action");
		}
		const session = this.#ownedSessions.get(params.session_id);
		if (!session) {
			throw new ToolError(`Session not found: '${params.session_id}'`);
		}
		if (session.status !== "connected") {
			throw new ToolError(`Session '${params.session_id}' is not connected (status: ${session.status})`);
		}
		if (session.service !== "ghidra") {
			throw new ToolError(
				`Service '${session.service}' does not support JNI enrichment; only 'ghidra' sessions are supported.`,
			);
		}

		// 1. Resolve records
		let rawEvents: unknown = params.events;
		if (!rawEvents && params.events_path) {
			const resolvedPath = path.resolve(this.session.cwd, params.events_path);
			try {
				rawEvents = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
			} catch (err) {
				throw new ToolError(
					`Failed to read events_path '${resolvedPath}': ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		}

		let records: CanonicalJniMethodRecord[] = [];
		if (Array.isArray(params.records) && params.records.length > 0) {
			records = params.records as CanonicalJniMethodRecord[];
		} else if (rawEvents) {
			let eventsList: unknown[] = [];
			if (Array.isArray(rawEvents)) {
				eventsList = rawEvents;
			} else if (typeof rawEvents === "object" && rawEvents !== null) {
				if ("events" in rawEvents && Array.isArray((rawEvents as { events: unknown[] }).events)) {
					eventsList = (rawEvents as { events: unknown[] }).events;
				} else {
					eventsList = [rawEvents];
				}
			}
			for (const ev of eventsList) {
				const canon = canonicalizeRegisterNativesEvent(ev, {
					expectedSha256: session.verifiedTarget?.sha256,
				});
				records.push(...canon);
			}
		} else {
			throw new ToolError("Either 'events', 'events_path', or 'records' parameter is required for 'jni_enrich'");
		}
		// Merge is_static_map across both events and records
		if (params.is_static_map && typeof params.is_static_map === "object") {
			const map = params.is_static_map as Record<string, boolean>;
			for (const rec of records) {
				if (typeof rec.isStatic !== "boolean") {
					const key1 = `${rec.className}->${rec.methodName}${rec.signature}`;
					const key2 = `${rec.methodName}${rec.signature}`;
					const key3 = rec.methodName;
					if (typeof map[key1] === "boolean") rec.isStatic = map[key1];
					else if (typeof map[key2] === "boolean") rec.isStatic = map[key2];
					else if (typeof map[key3] === "boolean") rec.isStatic = map[key3];
				}
			}
		}

		// Enforce confirmation contract: only confirmed records
		for (const rec of records) {
			if (rec.status !== "confirmed") {
				throw new ToolError(
					`Cannot apply unconfirmed JNI method record for '${rec.className}->${rec.methodName}': status is '${rec.status}'`,
				);
			}
		}

		// Compute preview with actual binary ELF metadata if accessible
		const targetFile = session.verifiedTarget?.path ?? session.target;
		let elfMeta: ElfJniMetadata | undefined;
		if (targetFile && fs.existsSync(targetFile)) {
			try {
				const buf = fs.readFileSync(targetFile);
				elfMeta = parseElfMetadataForJni(buf);
			} catch {}
		}

		const staticBase = session.verifiedTarget?.baseAddress ?? params.static_base;
		const previewSummary = previewJniEnrichment(records, {
			staticImageBase: staticBase ?? elfMeta?.minLoadVaddr,
			arch: elfMeta?.arch,
			bitness: elfMeta?.bitness,
			executableRanges: elfMeta?.executableRanges,
			minLoadVaddr: elfMeta?.minLoadVaddr,
		});
		const previewOnly = params.preview !== false;
		if (previewOnly) {
			const lines = [
				`### JNI Registration Enrichment Preview (Session: ${session.sessionId})`,
				`- **Total Methods**: ${previewSummary.total}`,
				`- **Eligible for Application**: ${previewSummary.eligible}`,
				`- **Rejected / Out of Bounds**: ${previewSummary.rejected}`,
				"",
				"| Class | Method | JVM Signature | Receiver | Static Address | Planned Symbol | Status |",
				"|---|---|---|---|---|---|---|",
				...previewSummary.items.map(
					it =>
						`| \`${it.className}\` | \`${it.methodName}\` | \`${it.signature}\` | ${it.isStatic === true ? "static" : it.isStatic === false ? "virtual" : "unverified"} | \`${it.staticAddress}\` | \`${it.targetFunctionName}\` | ${it.status} |`,
				),
				"",
				"> Note: Preview only (dry-run). Set `preview: false` to apply function rename and prototypes to active session.",
			];
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "jni_enrich",
					session,
					enrichment: previewSummary,
				},
			};
		}

		// 2. Applying changes (preview: false)
		// Enforce target verification and provenance:
		if (session.target && session.targetMatched === false) {
			throw new ToolError(
				`Cannot apply JNI enrichment: session target verification failed (targetMatched is false for '${session.target}'). ` +
					"Refusing writeback to prevent corrupting mismatched sample.",
			);
		}

		// Verify sample SHA-256 (if bound) and receiver typing for each record
		for (const rec of records) {
			if (session.verifiedTarget?.sha256 && rec.sampleSha256) {
				if (session.verifiedTarget.sha256.toLowerCase() !== rec.sampleSha256.toLowerCase()) {
					throw new ToolError(
						`Sample SHA256 mismatch for method '${rec.methodName}': record has '${rec.sampleSha256}', but session binary has '${session.verifiedTarget.sha256}'.`,
					);
				}
			}
			// Receiver kind must be boolean for writeback (no unknown or undefined)
			if (typeof rec.isStatic !== "boolean") {
				throw new ToolError(
					`Receiver kind for method '${rec.className}->${rec.methodName}' is unverified (must be boolean true for static or false for virtual). ` +
						"Provide explicit DEX ACC_STATIC declaration in is_static_map before applying writeback.",
				);
			}
		}

		// Discover upstream MCP tools
		const connection = this.#mcpManager.getConnection(session.serverName);
		if (!connection) {
			throw new ToolError(`Active connection lost for server '${session.serverName}'`);
		}

		// Check for rename tool
		const getToolProps = (name: string): Record<string, unknown> | undefined => {
			const t = connection.tools?.find(tool => tool.name === name);
			if (t?.inputSchema && typeof t.inputSchema === "object" && "properties" in t.inputSchema) {
				return t.inputSchema.properties as Record<string, unknown>;
			}
			return undefined;
		};
		const renameAddrTool = connection.tools?.find(t => t.name === "rename_function_by_address");
		const renameFuncTool = connection.tools?.find(t => t.name === "rename_function");
		const setProtoTool = connection.tools?.find(t => t.name === "set_function_prototype");
		const decompileAddrTool = connection.tools?.find(t => t.name === "decompile_function_by_address");
		const decompileFuncTool = connection.tools?.find(t => t.name === "decompile_function");

		// Preflight check: both rename tool and prototype tool MUST be present
		if (!renameAddrTool && !renameFuncTool) {
			throw new ToolError(
				`Active service '${session.service}' does not expose a function rename tool ('rename_function_by_address' or 'rename_function'). Cannot apply JNI symbols.`,
			);
		}
		if (!setProtoTool) {
			throw new ToolError(
				`Active service '${session.service}' does not expose prototype setting tool ('set_function_prototype'). Cannot apply JNI prototypes.`,
			);
		}

		const decompilations: Array<{ name: string; address: string; code: string }> = [];
		const failedErrors: string[] = [];
		let appliedCount = 0;

		const batchLimit = Math.min(params.batch_size ?? 20, 100);
		const toApply = previewSummary.items.filter(it => it.status === "eligible").slice(0, batchLimit);

		const hasTextError = (text: string) => /^(?:Error:|Failed\b|Invalid\b|Exception\b)/i.test(text.trim());

		for (const item of toApply) {
			throwIfAborted(signal);

			// 1. Rename via advertised schema ({ function_address, new_name } or fallback)
			let renameOk = false;
			if (renameAddrTool) {
				const props = getToolProps("rename_function_by_address") ?? {};
				const addrKey = "function_address" in props ? "function_address" : "address";
				const nameKey = "new_name" in props ? "new_name" : "name";
				const res = await callTool(connection, "rename_function_by_address", {
					[addrKey]: item.staticAddress,
					[nameKey]: item.targetFunctionName,
				});
				const resText = getToolCallText(res);
				if (res.isError || hasTextError(resText)) {
					failedErrors.push(`Failed to rename at ${item.staticAddress}: ${resText}`);
					continue;
				}
				renameOk = true;
			} else if (renameFuncTool) {
				const props = getToolProps("rename_function") ?? {};
				const oldKey = "old_name" in props ? "old_name" : "name";
				const newKey = "new_name" in props ? "new_name" : "new_function_name";
				const res = await callTool(connection, "rename_function", {
					[oldKey]: item.methodName,
					[newKey]: item.targetFunctionName,
				});
				const resText = getToolCallText(res);
				if (res.isError || hasTextError(resText)) {
					failedErrors.push(`Failed to rename ${item.methodName}: ${resText}`);
					continue;
				}
				renameOk = true;
			}

			if (!renameOk) {
				failedErrors.push(`Rename step failed for ${item.targetFunctionName} at ${item.staticAddress}`);
				continue;
			}

			// 2. Set prototype via advertised schema ({ function_address, prototype } or fallback)
			const protoProps = getToolProps("set_function_prototype") ?? {};
			const protoAddrKey = "function_address" in protoProps ? "function_address" : "address";
			const protoKey = "prototype" in protoProps ? "prototype" : "new_prototype";
			const protoRes = await callTool(connection, "set_function_prototype", {
				[protoAddrKey]: item.staticAddress,
				[protoKey]: item.cPrototype,
			});
			const protoText = getToolCallText(protoRes);
			if (protoRes.isError || hasTextError(protoText)) {
				failedErrors.push(`Failed to set prototype at ${item.staticAddress}: ${protoText}`);
				continue;
			}

			// 3. Decompile and verify readback reflects the updated symbol name
			let readbackVerified = false;
			let code = "";
			if (decompileAddrTool) {
				const props = getToolProps("decompile_function_by_address") ?? {};
				const addrKey = "function_address" in props ? "function_address" : "address";
				const res = await callTool(connection, "decompile_function_by_address", {
					[addrKey]: item.staticAddress,
				}).catch(() => null);
				if (res && !res.isError) {
					code = getToolCallText(res);
					if (code && !hasTextError(code) && code.includes(item.targetFunctionName)) {
						readbackVerified = true;
					}
				}
			} else if (decompileFuncTool) {
				const res = await callTool(connection, "decompile_function", {
					name: item.targetFunctionName,
				}).catch(() => null);
				if (res && !res.isError) {
					code = getToolCallText(res);
					if (code && !hasTextError(code) && code.includes(item.targetFunctionName)) {
						readbackVerified = true;
					}
				}
			} else {
				// If no decompiler tool is published on this service, consider prototype setting verified by tool success
				readbackVerified = true;
			}

			if (!readbackVerified) {
				failedErrors.push(
					`Readback verification failed for ${item.targetFunctionName} at ${item.staticAddress}: decompiler did not reflect updated symbol`,
				);
				continue;
			}

			if (code) {
				decompilations.push({
					name: item.targetFunctionName,
					address: item.staticAddress,
					code,
				});
			}

			appliedCount++;
		}

		const lines = [
			`### JNI Registration Enrichment Applied (Session: ${session.sessionId})`,
			`- **Applied Functions**: ${appliedCount} / ${toApply.length}`,
			`- **Failed Functions**: ${failedErrors.length}`,
			`- **Decompiled**: ${decompilations.length}`,
			"",
			"| Target Function | Address | Prototype | Verified |",
			"|---|---|---|---|",
			...toApply.map(it => {
				const hasCode = decompilations.some(d => d.address === it.staticAddress);
				return `| \`${it.targetFunctionName}\` | \`${it.staticAddress}\` | \`${it.cPrototype}\` | ${hasCode ? "✅ Verified" : "❌ Failed"} |`;
			}),
		];

		if (failedErrors.length > 0) {
			lines.push("", "#### Failed Operations:", ...failedErrors.map(e => `- ❌ ${e}`));
		}

		if (decompilations.length > 0) {
			lines.push("", "#### Decompiled Functions Preview:");
			for (const d of decompilations.slice(0, 5)) {
				lines.push(`\n**${d.name}** (\`${d.address}\`):`, "```c", d.code.slice(0, 1000), "```");
			}
		}

		if (appliedCount > 0 && (session.workflowId || session.stepId || params.workflow_id || params.step_id)) {
			try {
				const evidenceStore = EvidenceStore.forSession(this.session.cwd);
				const factInput: AddFactInput = {
					kind: "fact",
					sourceTool: "native_mcp_session",
					locator: formatDynamicLocator(session.sessionId, session.eventSeq++),
					title: `JNI RegisterNatives Enrichment Applied: ${appliedCount} methods`,
					target: session.target ? path.resolve(this.session.cwd, session.target) : undefined,
					content: `Applied ${appliedCount} confirmed JNI RegisterNatives bindings to Ghidra session '${session.sessionId}'. Verified via backend readback.`,
					tags: ["jni", "enrichment", "native", session.service],
					executionBinding: {
						artifactSha256: session.verifiedTarget?.sha256,
					},
				};
				await evidenceStore.addFact(factInput);
			} catch (err) {
				logger.warn(`Failed to record JNI enrichment fact in evidence store: ${err}`);
			}
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "jni_enrich",
				session,
				enrichment: previewSummary,
				decompilations,
			},
		};
	}
}
