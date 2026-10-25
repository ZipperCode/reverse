import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { prompt, getProjectDir } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseCapabilityDescription from "../prompts/tools/reverse-capability.md" with { type: "text" };
import { checkReverseTools } from "../cli/setup-reverse";
import {
	getReverseCapabilities,
	type CapabilityDescriptor,
	type ReverseCapabilityStatus,
} from "../extensibility/skill-tool-catalog";
import { getJshookMcpServer, installJshookMcp, JSHOOK_MCP_SERVER_NAME } from "../extensibility/jshookmcp-install";
import { cfgMcpEnableProjectConfig } from "../mcp/settings";
import {
	getMcpServerRuntimeState,
	getRecordedSkillLoads,
	type McpToolExecutionRecord,
	type SkillLoadRecord,
} from "../extensibility/capability-state";
import { getIdaBackendStatus, type IdaBackendStatus } from "../ida/install";
const reverseCapabilitySchema = type({
	action: type
		.enumerated("list", "resolve", "get", "install", "status")
		.describe(
			"Capability action: list, resolve or get host capability status; status inspects observable MCP/skill lifecycle states (configured/connected/discovered/targetMatched/executed/succeeded); install provisions the trusted jshookmcp service and registers its MCP tools in this session (write approval required)",
		),
	"capability?": type("string").describe(
		"Canonical capability ID (e.g. 'apk_unpacking', 'dex_runtime_unpacking', 'dex_codeitem_repair', 'instruction_trace_capture', 'dex_structural_search', 'bytecode_deobfuscation', 'native_cfg_deobfuscation', 'mba_simplification', 'native_path_recovery', 'symbolic_trace_analysis'); list returns all IDs",
	),
	"id?": type("string").describe("Alias for capability"),
	"refresh?": type("boolean").describe(
		"Bypass cached tool checks when resolving host capabilities (defaults to false)",
	),
	"service?": type.enumerated("jshookmcp").describe("Trusted service to install (required for install)"),
	"scope?": type.enumerated("user", "project").describe("MCP configuration scope for install (default user)"),
	"server?": type("string").describe("MCP server name to filter status (e.g. 'jshook', 'unidbg')"),
	"target?": type("string").describe(
		"Expected target URL or file path to evaluate against active server bindings in this session",
	),
});

export type ReverseCapabilityParams = typeof reverseCapabilitySchema.infer;

export interface McpDetailedServiceStatus {
	id: string;
	serverName: string;
	configured: boolean;
	configuredScopes: string[];
	connected: boolean;
	discovered: boolean;
	discoveredTools: string[];
	targetMatched: boolean;
	target: string | null;
	executed: boolean;
	executionCount: number;
	lastExecution: McpToolExecutionRecord | null;
}

export interface ReverseCapabilityDetails {
	action: "list" | "resolve" | "get" | "install" | "status";
	total?: number;
	capability?: ReverseCapabilityStatus | CapabilityDescriptor;
	capabilities?: ReverseCapabilityStatus[] | CapabilityDescriptor[];
	platform?: string;
	mcpServices?: McpDetailedServiceStatus[];
	idaBackends?: IdaBackendStatus;
	skills?: { recorded: SkillLoadRecord[] };
	installation?: {
		configPath: string;
		serverName: string;
		tools: string[];
		connected: boolean;
	};
}

export class ReverseCapabilityTool implements AgentTool<typeof reverseCapabilitySchema, ReverseCapabilityDetails> {
	readonly name = "reverse_capability";
	readonly label = "Reverse Engineering Capability Resolver";
	readonly summary =
		"Capability-driven runtime dispatch and host environment capability query tool: discovers, resolves, and inspects reverse engineering capabilities, recommended native tools, fallbacks, and trusted setup commands.";
	readonly description: string;
	readonly parameters = reverseCapabilitySchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier =>
		args && typeof args === "object" && "action" in args && args.action === "install" ? "write" : "read";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(reverseCapabilityDescription);
	}

	private getReport(projectDir: string, filterCap?: string, refresh?: boolean, target?: string) {
		// 直接保留同一次依赖闭包解析；展示用 tools 列表不包含所有回退依赖。
		return checkReverseTools({
			cwd: projectDir,
			filter: filterCap ? { capability: filterCap } : undefined,
			session: this.session,
			settings: this.session.settings,
			refresh,
			target,
		});
	}

	async execute(
		toolCallIdOrParams: string | ReverseCapabilityParams,
		paramsOrContext?: ReverseCapabilityParams | { abortSignal?: AbortSignal },
		signal?: AbortSignal,
	): Promise<AgentToolResult<ReverseCapabilityDetails>> {
		let params: ReverseCapabilityParams;
		let abortSignal: AbortSignal | undefined;

		if (typeof toolCallIdOrParams === "string") {
			params = paramsOrContext as ReverseCapabilityParams;
			abortSignal = signal;
		} else {
			params = toolCallIdOrParams;
			if (paramsOrContext && "abortSignal" in paramsOrContext) {
				abortSignal = paramsOrContext.abortSignal;
			}
		}

		throwIfAborted(abortSignal);

		const projectDir = this.session.cwd ?? getProjectDir();
		const capId = (params.capability ?? params.id)?.trim().toLowerCase();

		switch (params.action) {
			case "install": {
				if (this.session.getPlanModeState?.()?.enabled) {
					throw new ToolError("Plan mode is read-only. Install jshookmcp after leaving plan mode.");
				}
				if (params.service !== "jshookmcp") {
					throw new ToolError(
						"install requires service: 'jshookmcp'. Other catalog installers remain interactive.",
					);
				}
				const manager = this.session.mcpManager;
				if (this.session.enableMCP === false || !manager) {
					throw new ToolError("MCP is unavailable in this session. Enable MCP before installing jshookmcp.");
				}
				const currentConnection = manager.getConnection(JSHOOK_MCP_SERVER_NAME);
				if (currentConnection && !Bun.deepEquals(currentConnection.config, getJshookMcpServer())) {
					throw new ToolError(
						"A different jshook MCP configuration is already connected. Resolve the existing server before installing the managed service.",
					);
				}
				const scope = params.scope ?? "user";
				if (scope === "project" && !cfgMcpEnableProjectConfig.get(this.session.settings)) {
					throw new ToolError(
						"Project MCP configuration is disabled. Use user scope or enable project MCP discovery before installation.",
					);
				}
				const installed = await installJshookMcp({ cwd: projectDir, scope, signal: abortSignal });
				throwIfAborted(abortSignal);
				// 复用会话的 MCP manager，连接成功后由现有工具刷新回调挂载到当前 agent。
				const loaded = await manager.connectServers(
					{ [installed.serverName]: installed.server },
					{
						[installed.serverName]: {
							provider: "reverse",
							providerName: "reverse",
							path: installed.configPath,
							level: scope,
						},
					},
					undefined,
					installed.server.timeout ?? 120_000,
				);
				const error = loaded.errors.get(installed.serverName);
				if (error || manager.getConnectionStatus(installed.serverName) !== "connected") {
					throw new ToolError(
						`jshookmcp was installed and configured at ${installed.configPath}, but session activation failed: ${error ?? "connection incomplete"}`,
					);
				}
				return {
					content: [
						{
							type: "text",
							text: `jshookmcp installed and connected. Config: ${installed.configPath}. Use its search_tools → describe_tool → call_tool flow. Keep one browser controller per target.`,
						},
					],
					details: {
						action: "install",
						installation: {
							configPath: installed.configPath,
							serverName: installed.serverName,
							tools: installed.tools,
							connected: true,
						},
					},
				};
			}
			case "list": {
				const capabilities = getReverseCapabilities();
				const lines: string[] = [`### Reverse Engineering Capabilities (${capabilities.length} total)`, ""];
				for (const cap of capabilities) {
					lines.push(`- **\`${cap.id}\`**: ${cap.name} [${cap.category}]`);
					lines.push(`  - Scenario: ${cap.scenario}`);
					if (cap.recommendedNativeTool) {
						lines.push(`  - Recommended Native Tool: \`${cap.recommendedNativeTool}\``);
					}
					lines.push(`  - Optional External Tools: ${cap.optionalExternalTools.join(", ")}`);
					lines.push(`  - Fallbacks: ${cap.fallbacks.join(", ")}`);
					lines.push(`  - Trusted Setup Command: \`${cap.setupCommand}\``);
					lines.push(`  - Post-Install Invocation: \`${cap.postInstallInvocation}\``);
					lines.push("");
				}
				lines.push(
					'Call `reverse_capability(action: "resolve")` to evaluate host system tool availability and readiness.',
				);

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "list",
						total: capabilities.length,
						capabilities: [...capabilities],
					},
				};
			}

			case "resolve": {
				const report = this.getReport(projectDir, capId, params.refresh, params.target);
				let targetCaps = report.capabilities;
				if (capId) {
					const matched = report.capabilities.filter(c => c.id.toLowerCase() === capId);
					if (matched.length === 0) {
						const available = getReverseCapabilities()
							.map(c => c.id)
							.join(", ");
						throw new ToolError(`Capability '${capId}' not found. Available capabilities: ${available}`);
					}
					targetCaps = matched;
				}

				const lines: string[] = [
					`### Resolved Reverse Capabilities (${targetCaps.length} evaluated, Platform: ${report.platform})`,
					"",
				];

				for (const cap of targetCaps) {
					const statusBadge =
						cap.status === "ready"
							? "READY"
							: cap.status === "available_with_fallbacks"
								? "AVAILABLE_WITH_FALLBACKS"
								: "MISSING";

					lines.push(`#### [${statusBadge}] \`${cap.id}\`: ${cap.name}`);
					lines.push(`- **Status**: ${cap.status} (Ready: ${cap.ready ? "true" : "false"})`);
					if (cap.canStart !== undefined) {
						lines.push(`- **Can Start**: ${cap.canStart ? "true" : "false"}`);
					}
					if (cap.runtimeReady !== undefined) {
						lines.push(`- **Runtime Connected**: ${cap.runtimeReady ? "true" : "false"}`);
					}
					if (cap.compatible !== undefined) {
						lines.push(`- **Toolchain Compatible**: ${cap.compatible ? "true" : "false"}`);
					}
					if (cap.unpackingStages) {
						lines.push(`- **Unpacking Stages**:`);
						lines.push(
							`  - Baseline (manifest/dex/container): ${cap.unpackingStages.baseline.ready ? "Ready" : "Missing"}`,
						);
						lines.push(`  - Java Decompile: ${cap.unpackingStages.javaDecompile.ready ? "Ready" : "Missing"}`);
						lines.push(`  - Smali / Resources: ${cap.unpackingStages.smali.ready ? "Ready" : "Missing"}`);
					}
					if (cap.emulationStages) {
						lines.push(`- **Emulation Stages**:`);
						lines.push(
							`  - Launch Prerequisites: ${cap.emulationStages.launchPrerequisites.ready ? "Ready" : "Missing"} (Installed: ${cap.emulationStages.launchPrerequisites.installed ? "Yes" : "No"}, JDK 8 Compatible: ${cap.emulationStages.launchPrerequisites.compatible ? "Yes" : "No"})`,
						);
						lines.push(
							`  - Runtime Session: ${cap.emulationStages.runtimeSession.connected ? "Connected" : "Disconnected"}`,
						);
						lines.push(
							`  - Target matched: ${cap.targetMatched ?? "unknown"}; execution verified: ${cap.executedVerified ?? "unknown"}`,
						);
						if (cap.emulationStages.launchPrerequisites.error)
							lines.push(`  - Blocker: ${cap.emulationStages.launchPrerequisites.error}`);
						if (cap.emulationStages.launchPrerequisites.remedy)
							lines.push(`  - Remedy: ${cap.emulationStages.launchPrerequisites.remedy}`);
					}
					lines.push(`- **Category**: ${cap.category}`);
					lines.push(`- **Scenario**: ${cap.scenario}`);
					if (cap.recommendedNativeTool) {
						lines.push(`- **Recommended Native Tool**: \`${cap.recommendedNativeTool}\``);
					}
					const toolSummary =
						cap.optionalExternalTools.length > 0
							? cap.optionalExternalTools.map(t => `${t.id} (${t.status})`).join(", ")
							: "none";
					lines.push(`- **Optional External Tools**: ${toolSummary}`);
					const availableFbStr = cap.availableFallbacks.length > 0 ? cap.availableFallbacks.join(", ") : "none";
					lines.push(`- **Available Fallbacks**: ${availableFbStr} (All: ${cap.fallbacks.join(", ")})`);
					lines.push(`- **Trusted Setup Command**: \`${cap.setupCommand}\``);
					lines.push(`- **Post-Install Invocation**: \`${cap.postInstallInvocation}\``);
					lines.push("");
				}
				let idaBackends: IdaBackendStatus | undefined;
				if (!capId || capId === "native_debugger" || capId === "ida") {
					idaBackends = getIdaBackendStatus({
						cwd: projectDir,
						mcpManager: this.session.mcpManager,
						settings: this.session.settings,
					});
					lines.push("### IDA Pro Multi-Backend Status");
					lines.push(
						`- **GUI Application**: ${idaBackends.guiAvailable ? `Available (${idaBackends.guiPath})` : "Not found"}`,
					);
					lines.push(
						`- **idalib Headless SDK**: ${idaBackends.idalibAvailable ? `Available (${idaBackends.idalibPath})` : "Not found"}`,
					);
					lines.push(
						`- **Local Database (.idb/.i64)**: Recognized: ${idaBackends.localDatabaseRecognized ? "Yes" : "No"}, Backend Parser Available: ${idaBackends.localDatabaseBackendAvailable ? "Yes (idalib)" : idaBackends.idalibAvailable ? (idaBackends.adapterError ? `No (${idaBackends.adapterError})` : "No (Python adapter not ready)") : "No (requires idalib)"}`,
					);
					if (idaBackends.idalibAvailable) {
						const pyDesc = idaBackends.pythonAdapterReady
							? `Ready (${idaBackends.pythonPath})`
							: idaBackends.adapterError
								? `Not ready (${idaBackends.adapterError})`
								: "Not ready";
						lines.push(`- **idalib Python Adapter**: ${pyDesc}`);
					}
					lines.push(
						`- **MCP Bridge**: ${idaBackends.mcpBridgeConnected ? "Connected" : idaBackends.mcpBridgeConfigured ? "Configured (disconnected)" : "Not configured (bridge absent does not imply IDA absent)"}`,
					);
					if (idaBackends.bridgeAbsentReason) {
						lines.push(`  - Note: ${idaBackends.bridgeAbsentReason}`);
					}
					lines.push("");
				}
				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "resolve",
						total: targetCaps.length,
						capabilities: targetCaps,
						platform: report.platform,
						...(idaBackends ? { idaBackends } : {}),
					},
				};
			}

			case "get": {
				if (!capId) {
					const valid = getReverseCapabilities()
						.map(c => c.id)
						.join(", ");
					throw new ToolError(`capability parameter is required for 'get' action. Valid capabilities: ${valid}`);
				}

				const report = this.getReport(projectDir, capId, params.refresh, params.target);
				const capStatus = report.capabilities.find(c => c.id.toLowerCase() === capId);
				if (!capStatus) {
					const valid = report.capabilities.map(c => c.id).join(", ");
					throw new ToolError(`Capability '${capId}' not found. Valid capabilities: ${valid}`);
				}

				const statusBadge =
					capStatus.status === "ready"
						? "READY"
						: capStatus.status === "available_with_fallbacks"
							? "AVAILABLE_WITH_FALLBACKS"
							: "MISSING";

				const lines: string[] = [
					`### Capability: \`${capStatus.id}\` [${statusBadge}]`,
					`**${capStatus.name}** (${capStatus.category})`,
					"",
					`**Scenario**: ${capStatus.scenario}`,
					"",
					`**Description**: ${capStatus.description}`,
					"",
					`**Why**: ${capStatus.why}`,
					"",
					`- **Readiness Status**: ${capStatus.status} (Fully Ready: ${capStatus.ready ? "Yes" : "No"})`,
				];
				if (capStatus.canStart !== undefined) {
					lines.push(`- **Can Start**: ${capStatus.canStart ? "Yes" : "No"}`);
				}
				if (capStatus.runtimeReady !== undefined) {
					lines.push(`- **Runtime Connected**: ${capStatus.runtimeReady ? "Yes" : "No"}`);
				}
				if (capStatus.compatible !== undefined) {
					lines.push(`- **Toolchain Compatible**: ${capStatus.compatible ? "Yes" : "No"}`);
				}
				if (capStatus.unpackingStages) {
					lines.push(`- **Unpacking Stages**:`);
					lines.push(
						`  - Baseline (manifest/dex/container): ${capStatus.unpackingStages.baseline.ready ? "Ready" : "Missing"}`,
					);
					lines.push(`  - Java Decompile: ${capStatus.unpackingStages.javaDecompile.ready ? "Ready" : "Missing"}`);
					lines.push(`  - Smali / Resources: ${capStatus.unpackingStages.smali.ready ? "Ready" : "Missing"}`);
				}
				if (capStatus.emulationStages) {
					lines.push(`- **Emulation Stages**:`);
					lines.push(
						`  - Launch Prerequisites: ${capStatus.emulationStages.launchPrerequisites.ready ? "Ready" : "Missing"} (Installed: ${capStatus.emulationStages.launchPrerequisites.installed ? "Yes" : "No"}, JDK 8 Compatible: ${capStatus.emulationStages.launchPrerequisites.compatible ? "Yes" : "No"})`,
					);
					lines.push(
						`  - Runtime Session: ${capStatus.emulationStages.runtimeSession.connected ? "Connected" : "Disconnected"}`,
					);
					lines.push(
						`  - Target matched: ${capStatus.targetMatched ?? "unknown"}; execution verified: ${capStatus.executedVerified ?? "unknown"}`,
					);
					if (capStatus.emulationStages.launchPrerequisites.error)
						lines.push(`  - Blocker: ${capStatus.emulationStages.launchPrerequisites.error}`);
					if (capStatus.emulationStages.launchPrerequisites.remedy)
						lines.push(`  - Remedy: ${capStatus.emulationStages.launchPrerequisites.remedy}`);
				}

				if (capStatus.recommendedNativeTool) {
					lines.push(`- **Recommended Native Tool**: \`${capStatus.recommendedNativeTool}\``);
				}

				const extToolsStr =
					capStatus.optionalExternalTools.length > 0
						? capStatus.optionalExternalTools
								.map(
									t =>
										`${t.name ?? t.id} [${t.status}]${t.installCommand ? ` (install: ${t.installCommand})` : ""}`,
								)
								.join("; ")
						: "none";
				lines.push(`- **Optional External Tools**: ${extToolsStr}`);

				if (capStatus.prerequisites && capStatus.prerequisites.length > 0) {
					lines.push(`- **Prerequisites**: ${capStatus.prerequisites.join(", ")}`);
				}

				const availFbStr =
					capStatus.availableFallbacks.length > 0 ? capStatus.availableFallbacks.join(", ") : "none";
				lines.push(`- **Available Fallbacks**: ${availFbStr}`);
				lines.push(`- **All Defined Fallbacks**: ${capStatus.fallbacks.join(", ")}`);
				lines.push(`- **Trusted Setup Command**: \`${capStatus.setupCommand}\``);
				lines.push(`- **Post-Install Invocation**: \`${capStatus.postInstallInvocation}\``);
				let idaBackends: IdaBackendStatus | undefined;
				if (capStatus.id === "native_debugger" || capId === "ida") {
					idaBackends = getIdaBackendStatus({
						cwd: projectDir,
						mcpManager: this.session.mcpManager,
						settings: this.session.settings,
					});
					lines.push("");
					lines.push("#### IDA Pro Backend Status:");
					lines.push(
						`- **GUI Application**: ${idaBackends.guiAvailable ? `Available (${idaBackends.guiPath})` : "Not found"}`,
					);
					lines.push(
						`- **idalib Headless SDK**: ${idaBackends.idalibAvailable ? `Available (${idaBackends.idalibPath})` : "Not found"}`,
					);
					lines.push(
						`- **Local Database (.idb/.i64)**: Recognized: ${idaBackends.localDatabaseRecognized ? "Yes" : "No"}, Backend Parser Available: ${idaBackends.localDatabaseBackendAvailable ? "Yes (idalib)" : idaBackends.idalibAvailable ? (idaBackends.adapterError ? `No (${idaBackends.adapterError})` : "No (Python adapter not ready)") : "No (requires idalib)"}`,
					);
					if (idaBackends.idalibAvailable) {
						const pyDesc = idaBackends.pythonAdapterReady
							? `Ready (${idaBackends.pythonPath})`
							: idaBackends.adapterError
								? `Not ready (${idaBackends.adapterError})`
								: "Not ready";
						lines.push(`- **idalib Python Adapter**: ${pyDesc}`);
					}
					lines.push(
						`- **MCP Bridge**: ${idaBackends.mcpBridgeConnected ? "Connected" : idaBackends.mcpBridgeConfigured ? "Configured (disconnected)" : "Not configured (bridge absent does not imply IDA absent)"}`,
					);
					if (idaBackends.bridgeAbsentReason) {
						lines.push(`  - Note: ${idaBackends.bridgeAbsentReason}`);
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "get",
						capability: capStatus,
						platform: report.platform,
						...(idaBackends ? { idaBackends } : {}),
					},
				};
			}
			case "status": {
				const sessionKey = this.session.sessionManager ?? this.session;
				const report = this.getReport(projectDir);
				const manager = this.session.mcpManager;
				const filterServer = params.server?.trim().toLowerCase();
				const expectedTarget = params.target?.trim();

				const catalogServices = report.services;
				const knownServerNames = new Set(catalogServices.map(s => s.serverName.toLowerCase()));
				const liveServerNames = manager ? manager.getAllServerNames() : [];

				const allServices: Array<{
					id: string;
					serverName: string;
					configured: boolean;
					configuredScopes: string[];
				}> = catalogServices.map(s => ({
					id: s.id,
					serverName: s.serverName,
					configured: s.configured,
					configuredScopes: s.configuredScopes,
				}));

				for (const liveName of liveServerNames) {
					if (!knownServerNames.has(liveName.toLowerCase())) {
						const source = manager?.getSource(liveName);
						const isConfigured = Boolean(
							source && source.path && source.path !== "in-memory" && source.level !== "native",
						);
						const scopes: string[] = isConfigured && source?.level ? [source.level] : [];
						allServices.push({
							id: liveName,
							serverName: liveName,
							configured: isConfigured,
							configuredScopes: scopes,
						});
					}
				}

				const mcpServices: McpDetailedServiceStatus[] = allServices
					.filter(
						s =>
							!filterServer ||
							s.serverName.toLowerCase() === filterServer ||
							s.id.toLowerCase() === filterServer,
					)
					.map(s => {
						const serverName = s.serverName;
						const conn = manager?.getConnection(serverName);
						const connStatus = manager?.getConnectionStatus(serverName);
						const isConnected = connStatus === "connected";
						const toolsFromConn = conn?.tools?.map(t => t.name) ?? [];
						const toolsFromManager = manager
							? manager
									.getTools()
									.filter(t => "mcpServerName" in t && t.mcpServerName === serverName)
									.map(t => t.name)
							: [];
						const uniqueTools = Array.from(new Set([...toolsFromConn, ...toolsFromManager]));
						const isDiscovered = isConnected && uniqueTools.length > 0;
						const runtimeState = getMcpServerRuntimeState(serverName, sessionKey);
						const isCurrentConn = isConnected && Boolean(conn) && runtimeState?.connection === conn;
						const observedTarget = isCurrentConn ? (runtimeState?.target ?? null) : null;
						const targetMatched =
							isCurrentConn &&
							Boolean(runtimeState?.targetMatched) &&
							(!expectedTarget || observedTarget === expectedTarget);
						const target = observedTarget;
						const executed = isCurrentConn && (runtimeState?.executionCount ?? 0) > 0;
						const executionCount = isCurrentConn ? (runtimeState?.executionCount ?? 0) : 0;
						const lastExecution = isCurrentConn ? (runtimeState?.lastExecution ?? null) : null;
						return {
							id: s.id,
							serverName: s.serverName,
							configured: s.configured,
							configuredScopes: s.configuredScopes,
							connected: isConnected,
							discovered: isDiscovered,
							discoveredTools: uniqueTools,
							targetMatched,
							target,
							executed,
							executionCount,
							lastExecution,
						};
					});

				const skillLoads = getRecordedSkillLoads(sessionKey);

				const lines: string[] = [
					`### Reverse Engineering MCP Services & Evidence Status (${mcpServices.length} services)`,
					"",
				];
				for (const s of mcpServices) {
					lines.push(`#### \`${s.serverName}\` (ID: ${s.id})`);
					lines.push(`- **Configured**: ${s.configured ? "Yes (" + s.configuredScopes.join(", ") + ")" : "No"}`);
					lines.push(`- **Connected**: ${s.connected ? "Connected" : "Not connected"}`);
					lines.push(
						`- **Discovered**: ${s.discovered ? `Yes (${s.discoveredTools.length} tools: ${s.discoveredTools.slice(0, 5).join(", ")}${s.discoveredTools.length > 5 ? "..." : ""})` : "No"}`,
					);
					lines.push(
						`- **Target Matched**: ${s.targetMatched ? `Yes (target: ${s.target ?? "unspecified"})` : "No"}`,
					);
					lines.push(`- **Executed Tools**: ${s.executed ? `Yes (${s.executionCount} calls)` : "No"}`);
					if (s.lastExecution) {
						lines.push(
							`  - Last Tool Call: ${s.lastExecution.tool} (isError: ${s.lastExecution.isError}, innerSuccess: ${s.lastExecution.innerSuccess}${s.lastExecution.error ? `, error: ${s.lastExecution.error}` : ""})`,
						);
					}
					lines.push("");
				}

				lines.push(`### Recorded Skill Loads (${skillLoads.length} recorded)`);
				if (skillLoads.length === 0) {
					lines.push("- No skills read yet in this session.");
				} else {
					for (const sl of skillLoads) {
						lines.push(
							`- **\`${sl.name}\`**: ${sl.loaded ? "Loaded [OK]" : "Failed [ERROR]"}${sl.error ? ` (${sl.error})` : ""}${sl.fallback ? ` -> Fallback: ${sl.fallback}` : ""}`,
						);
					}
				}

				const idaBackends = getIdaBackendStatus({
					cwd: projectDir,
					mcpManager: this.session.mcpManager,
					settings: this.session.settings,
				});
				lines.push("");
				lines.push("### IDA Pro Backend Status");
				lines.push(
					`- **GUI Application**: ${idaBackends.guiAvailable ? `Available (${idaBackends.guiPath})` : "Not found"}`,
				);
				lines.push(
					`- **idalib Headless SDK**: ${idaBackends.idalibAvailable ? `Available (${idaBackends.idalibPath})` : "Not found"}`,
				);
				lines.push(
					`- **Local Database (.idb/.i64)**: Recognized: ${idaBackends.localDatabaseRecognized ? "Yes" : "No"}, Backend Parser Available: ${idaBackends.localDatabaseBackendAvailable ? "Yes (idalib)" : idaBackends.idalibAvailable ? (idaBackends.adapterError ? `No (${idaBackends.adapterError})` : "No (Python adapter not ready)") : "No (requires idalib)"}`,
				);
				if (idaBackends.idalibAvailable) {
					const pyDesc = idaBackends.pythonAdapterReady
						? `Ready (${idaBackends.pythonPath})`
						: idaBackends.adapterError
							? `Not ready (${idaBackends.adapterError})`
							: "Not ready";
					lines.push(`- **idalib Python Adapter**: ${pyDesc}`);
				}
				lines.push(
					`- **MCP Bridge**: ${idaBackends.mcpBridgeConnected ? "Connected" : idaBackends.mcpBridgeConfigured ? "Configured (disconnected)" : "Not configured (bridge absent does not imply IDA absent)"}`,
				);
				if (idaBackends.bridgeAbsentReason) {
					lines.push(`  - Note: ${idaBackends.bridgeAbsentReason}`);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "status",
						mcpServices,
						skills: { recorded: skillLoads },
						platform: report.platform,
						idaBackends,
					},
				};
			}

			default:
				throw new ToolError(`Unknown reverse_capability action: '${String(params.action)}'`);
		}
	}
}
