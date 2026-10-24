/**
 * Trusted catalog of optional MCP helper services for reverse engineering.
 *
 * This catalog is deliberately separate from {@link SKILL_TOOL_CATALOG}: an MCP
 * service is not a PATH binary. It owns the server configuration template, the
 * launch command, prerequisite catalog ids, install hints, and the canonical
 * usage guidance an agent needs to call the service correctly.
 *
 * Only client-vetted entries belong here. Package installs are executed
 * by the setup panel after interactive confirmation or explicit agent tool
 * write approval; no skill, MCP server, or remote registry can inject an argv into that path.
 */
import type { MCPServerConfig } from "../mcp/types";
import type { PackageInstallCommand, SkillToolPlatform, ToolCategory, ToolUsageGuide } from "./skill-tool-catalog";
import { getJshookMcpServer } from "./jshookmcp-install";
import { getNativeMcpServer } from "./native-mcp-install";

export type McpServiceTransport = "stdio" | "http" | "sse";

/** How to find and install one optional MCP helper service. */
export interface McpServiceDescriptor {
	/** Logical id used by setup commands and skill requirements. */
	id: string;
	/** Human-friendly service name. */
	name: string;
	/** Functional category shared with the CLI tool catalog. */
	category: ToolCategory;
	/** Brief summary of what the service provides to the agent. */
	description: string;
	/** Whether the service is optional (all catalogued helper services are). */
	optional: boolean;
	/** Catalog ids that must be present before the server can start. */
	requires: readonly string[];
	/** Platforms the service supports; omitted means every supported platform. */
	platforms?: readonly SkillToolPlatform[];
	/** Trusted, client-vetted installation commands grouped by platform. */
	installCommands?: Partial<Record<SkillToolPlatform, readonly PackageInstallCommand[]>>;
	/** Trusted, display-only install hints per platform. */
	installHints?: Partial<Record<SkillToolPlatform, readonly string[]>>;
	/** Official download page or release repository URL for manual installation. */
	manualUrl: string;
	/** Manual instructions per platform when automated install is unavailable or unnecessary. */
	manualInstructions: Partial<Record<SkillToolPlatform, string>>;
	/** Human-readable launch command (display only; config declares the argv). */
	startCommand: string;
	/** Server key written under `mcpServers` in the reverse MCP config. */
	serverName: string;
	/** Trusted MCP server config template for `.reverse/mcp.json`. */
	server: MCPServerConfig;
	/** Display-only config path hint; `setup reverse --json` reports resolved `configPaths`. */
	configPath: string;
	/** Species/documentation URL for the server integration. */
	docsUrl: string;
	/** Upstream license identifier for external services. Sources are never vendored or copied into reverse. */
	license: string;
	/** Packaging, privilege, network, or commercial-software warning. */
	riskNote: string;
	/** Canonical model-facing usage guidance. */
	usage: ToolUsageGuide;
	/** Dedicated installer helper identifier for services with custom lifecycle. */
	installer?: "jshookmcp" | "native-mcp";
}

/** Config path hint shown by setup panels and the guide skill. */
export const MCP_CONFIG_PATH_HINT = ".reverse/mcp.json (project) or ~/.reverse/agent/mcp.json (user)";

/** Suggested server key + config for a service, ready to merge into `mcpServers`. */
export function mcpServerSnippet(descriptor: McpServiceDescriptor): { mcpServers: Record<string, MCPServerConfig> } {
	return { mcpServers: { [descriptor.serverName]: descriptor.server } };
}

/**
 * Built-in catalog of optional MCP helper services.
 *
 * Every package below is published by its upstream project or vendor.
 * External service licenses (including AGPL-3.0) are declared for transparency;
 * sources are never vendored or copied into reverse, running strictly out-of-process.
 */
export const MCP_SERVICE_CATALOG: Readonly<Record<string, McpServiceDescriptor>> = {
	"playwright-mcp": {
		id: "playwright-mcp",
		name: "Playwright MCP",
		category: "web",
		description: "Browser automation and page inspection for authorized web and protocol analysis",
		optional: true,
		requires: ["node"],
		manualUrl: "https://github.com/microsoft/playwright-mcp",
		docsUrl: "https://github.com/microsoft/playwright-mcp",
		license: "Apache-2.0",
		startCommand: "npx -y @playwright/mcp@latest",
		serverName: "playwright",
		server: {
			type: "stdio",
			command: "npx",
			args: ["-y", "@playwright/mcp@latest"],
		},
		configPath: MCP_CONFIG_PATH_HINT,
		manualInstructions: {
			darwin:
				"No server install is required: npx resolves @playwright/mcp. Install Playwright browsers with 'npx playwright install chromium'.",
			linux: "No server install is required: npx resolves @playwright/mcp. Install Playwright browsers with 'npx playwright install chromium'.",
			win32: "No server install is required: npx resolves @playwright/mcp. Install Playwright browsers with 'npx playwright install chromium'.",
		},
		riskNote:
			"Downloads the MCP package and browser binaries on first use. Operate only against authorized staging or loopback targets.",
		usage: {
			canonical: "browser_navigate -> browser_snapshot -> browser_click/browser_evaluate",
			whenToUse:
				"Web frontend and protocol work that needs a persistent browser session: source-map discovery, console hooks, network inspection, and authorized replay.",
			prerequisites: ["node"],
			outputLimits:
				"Read accessibility snapshots or targeted console/network results; never dump multi-megabyte bundles into context.",
			fallback: "Native browser-relay/CDP when available, otherwise curl + static bundle grep.",
			examples: [
				{
					description: "Start the server via npx (no global install)",
					command: "npx -y @playwright/mcp@latest",
				},
				{
					description: "Install the Chromium runtime used by the server",
					command: "npx playwright install chromium",
				},
			],
		},
	},

	r2mcp: {
		id: "r2mcp",
		name: "radare2 MCP (r2mcp)",
		category: "binary",
		description: "Official radare2 MCP server exposing disassembly, analysis, and scripting tools",
		optional: true,
		installer: "native-mcp",
		requires: ["radare2"],
		manualUrl: "https://github.com/radareorg/radare2-mcp",
		docsUrl: "https://github.com/radareorg/radare2-mcp",
		license: "MIT",
		startCommand: "r2pm -r r2mcp",
		serverName: "radare2",
		server: {
			type: "stdio",
			command: "r2pm",
			args: ["-r", "r2mcp"],
		},
		configPath: MCP_CONFIG_PATH_HINT,
		installHints: {
			darwin: ["r2pm -Uci r2mcp"],
			linux: ["r2pm -Uci r2mcp"],
			win32: ["r2pm -Uci r2mcp"],
		},
		manualInstructions: {
			darwin: "Install radare2 first, then run 'r2pm -Uci r2mcp'. Launch with 'r2pm -r r2mcp'.",
			linux: "Install radare2 first, then run 'r2pm -Uci r2mcp'. Launch with 'r2pm -r r2mcp'.",
			win32: "Install radare2 first, then run 'r2pm -Uci r2mcp'. Launch with 'r2pm -r r2mcp'.",
		},
		installCommands: {
			darwin: [
				{
					manager: "r2pm",
					command: "r2pm -Uci r2mcp",
					argv: ["r2pm", "-Uci", "r2mcp"],
					riskNote:
						"Updates the r2pm package database and installs r2mcp from the radare2 package repository. Requires radare2/r2pm.",
				},
			],
			linux: [
				{
					manager: "r2pm",
					command: "r2pm -Uci r2mcp",
					argv: ["r2pm", "-Uci", "r2mcp"],
					riskNote:
						"Updates the r2pm package database and installs r2mcp from the radare2 package repository. Requires radare2/r2pm.",
				},
			],
			win32: [
				{
					manager: "r2pm",
					command: "r2pm -Uci r2mcp",
					argv: ["r2pm", "-Uci", "r2mcp"],
					riskNote:
						"Updates the r2pm package database and installs r2mcp from the radare2 package repository. Requires radare2/r2pm.",
				},
			],
		},
		riskNote:
			"r2pm installs from the radare2 package repository and may compile the plugin locally. The executable is meant to be launched by the MCP client, not directly.",
		usage: {
			canonical: "r2mcp tools: open/seek/analyze, disassemble, xrefs, strings, r2 command escape",
			whenToUse:
				"Persistent radare2 analysis sessions where the agent needs repeated seeks, xrefs, and scripted queries without respawning r2.",
			prerequisites: ["radare2", "r2mcp"],
			outputLimits:
				"Prefer per-symbol or bounded disassembly calls; keep raw r2 command output small and write bulk results to files.",
			fallback: "r2 -qc one-shot commands for the same query when the MCP session is unavailable.",
			examples: [
				{
					description: "Install the server through the radare2 package manager",
					command: "r2pm -Uci r2mcp",
				},
				{
					description: "Launch the stdio server through r2pm",
					command: "r2pm -r r2mcp",
				},
			],
		},
	},

	"x64dbg-mcp": {
		id: "x64dbg-mcp",
		name: "x64dbg MCP",
		category: "binary",
		description: "x64dbg automation and debugging MCP server (local Windows or cross-platform remote)",
		optional: true,
		installer: "native-mcp",
		requires: ["python"],
		manualUrl: "https://github.com/dariushoule/x64dbg-automate",
		docsUrl: "https://github.com/dariushoule/x64dbg-automate",
		license: "GPL-3.0-or-later",
		get startCommand() {
			const server = getNativeMcpServer("x64dbg");
			return `${server.command} ${(server.args ?? []).join(" ")}`.trim();
		},
		serverName: "x64dbg",
		get server() {
			return getNativeMcpServer("x64dbg");
		},
		configPath: MCP_CONFIG_PATH_HINT,
		installHints: {
			darwin: ["reverse setup reverse x64dbg-mcp --execute"],
			linux: ["reverse setup reverse x64dbg-mcp --execute"],
			win32: ["reverse setup reverse x64dbg-mcp --execute"],
		},
		manualInstructions: {
			darwin:
				"Install managed Python client bridge via 'reverse setup reverse x64dbg-mcp --execute' (Python >= 3.10 required). Connects remotely to x64dbg over trusted loopback or secure SSH tunnels.",
			linux: "Install managed Python client bridge via 'reverse setup reverse x64dbg-mcp --execute' (Python >= 3.10 required). Connects remotely to x64dbg over trusted loopback or secure SSH tunnels.",
			win32: "Install managed Python bridge via 'reverse setup reverse x64dbg-mcp --execute' and optional portable x64dbg debugger with ghost_fungus plugin.",
		},
		riskNote:
			"Runs a local Python MCP bridge communicating with x64dbg via ZeroMQ RPC. Remote debugging uses unauthenticated ZMQ; operate only over private loopback or secure SSH tunnels.",
		usage: {
			canonical: "start_session / connect_remote -> get_debugger_status -> break / step / read memory",
			whenToUse:
				"Dynamic analysis, process memory inspection, and breakpoint tracing of Windows PE binaries locally on Windows or remotely from macOS/Linux.",
			prerequisites: ["python"],
			outputLimits:
				"Request targeted memory ranges, register snapshots, or single-step disassembly; avoid dumping full process memory into context.",
			fallback: "Static analysis via ghidra / r2 or Frida native dynamic tracing when debugger is unavailable.",
			examples: [
				{
					description: "Check status of connected x64dbg instance",
					command: "get_debugger_status()",
				},
				{
					description: "Connect to remote x64dbg session via ZeroMQ ports",
					command: 'connect_remote(host: "127.0.0.1", req_rep_port: 5555, pub_sub_port: 5556)',
				},
			],
		},
	},

	"ghidra-mcp": {
		id: "ghidra-mcp",
		name: "Ghidra MCP",
		category: "decompiler",
		description: "Ghidra software reverse engineering MCP server (headless project analysis and GUI backend)",
		optional: true,
		installer: "native-mcp",
		requires: ["python", "ghidra"],
		manualUrl: "https://github.com/LaurieWired/GhidraMCP",
		docsUrl: "https://github.com/LaurieWired/GhidraMCP",
		license: "Apache-2.0",
		get startCommand() {
			const server = getNativeMcpServer("ghidra");
			return `${server.command} ${(server.args ?? []).join(" ")}`.trim();
		},
		serverName: "ghidra",
		get server() {
			return getNativeMcpServer("ghidra");
		},
		configPath: MCP_CONFIG_PATH_HINT,
		installHints: {
			darwin: ["reverse setup reverse ghidra-mcp --execute"],
			linux: ["reverse setup reverse ghidra-mcp --execute"],
			win32: ["reverse setup reverse ghidra-mcp --execute"],
		},
		manualInstructions: {
			darwin:
				"Install Ghidra first ('brew install --cask ghidra', JDK 21+ required). Then run 'reverse setup reverse ghidra-mcp --execute' to install managed GhidraMCP wheel and extension JAR.",
			linux: "Install Ghidra first (JDK 21+ required). Then run 'reverse setup reverse ghidra-mcp --execute' to install managed GhidraMCP wheel and extension JAR.",
			win32: "Install Ghidra first (JDK 21+ required). Then run 'reverse setup reverse ghidra-mcp --execute' to install managed GhidraMCP wheel and extension JAR.",
		},
		riskNote:
			"Installs managed GhidraMCP wheel and extension JAR into agent profile tools. Headless analysis requires local Ghidra installation (12.1.4+ recommended) and Java 21+.",
		usage: {
			canonical: "get_program_info -> list_functions -> decompile_function_by_address",
			whenToUse:
				"Deep decompilation, symbol discovery, cross-reference mapping, and batch analysis on native binary targets via persistent Ghidra projects.",
			prerequisites: ["python", "ghidra"],
			outputLimits:
				"Decompile individual functions by address or name; do not request bulk whole-binary decompilation at once.",
			fallback: "r2mcp or native binary triage when Ghidra is unavailable.",
			examples: [
				{
					description: "Inspect target program info and architecture",
					command: "get_program_info()",
				},
				{
					description: "Decompile function at address",
					command: 'decompile_function_by_address(address: "0x140001000")',
				},
			],
		},
	},

	jshookmcp: {
		id: "jshookmcp",
		name: "jshook MCP",
		category: "web",
		description:
			"Multi-domain JavaScript analysis, CDP debugging, AST deobfuscation, and network inspection MCP server",
		optional: true,
		installer: "jshookmcp",
		requires: ["node"],
		manualUrl: "https://github.com/vmoranv/jshookmcp",
		docsUrl: "https://github.com/vmoranv/jshookmcp",
		license: "AGPL-3.0-only",
		get startCommand() {
			const server = getJshookMcpServer();
			return `${server.command} ${(server.args ?? []).join(" ")}`;
		},
		serverName: "jshook",
		get server() {
			return getJshookMcpServer();
		},
		configPath: MCP_CONFIG_PATH_HINT,
		installHints: {
			darwin: [
				"npm install --prefix ~/.reverse/agent/tools/jshookmcp --omit=dev --omit=optional --no-audit --no-fund @jshookmcp/jshook@0.4.2 webcrack@2.16.0",
			],
			linux: [
				"npm install --prefix ~/.reverse/agent/tools/jshookmcp --omit=dev --omit=optional --no-audit --no-fund @jshookmcp/jshook@0.4.2 webcrack@2.16.0",
			],
			win32: [
				"npm install --prefix %USERPROFILE%\\.reverse\\agent\\tools\\jshookmcp --omit=dev --omit=optional --no-audit --no-fund @jshookmcp/jshook@0.4.2 webcrack@2.16.0",
			],
		},
		manualInstructions: {
			darwin:
				"Run 'reverse setup reverse jshookmcp --execute' or install into ~/.reverse/agent/tools/jshookmcp via npm.",
			linux: "Run 'reverse setup reverse jshookmcp --execute' or install into ~/.reverse/agent/tools/jshookmcp via npm.",
			win32: "Run 'reverse setup reverse jshookmcp --execute' or install into ~/.reverse/agent/tools/jshookmcp via npm.",
		},
		riskNote:
			"Runs an AGPL-3.0 local Node.js process with CDP and JavaScript inspection capabilities. Operates over local stdio with search profile.",
		usage: {
			canonical: "search_tools -> describe_tool -> call_tool(deobfuscate) / activate_tools",
			whenToUse:
				"Complex web frontend reverse engineering, obfuscated JavaScript unpacking, runtime script hooks, and CDP inspection.",
			prerequisites: ["node"],
			outputLimits:
				"Uses search profile with 8 meta-tools by default. Query search_tools with 2-4 keywords rather than dumping full tool lists.",
			fallback: "Native browser_reverse_session and sourcemap_inspect when unavailable.",
			examples: [
				{
					description: "Search for deobfuscation and hook tools",
					command: 'search_tools(query: "deobfuscate webcrack hook")',
				},
				{
					description: "Directly execute deobfuscation without full activation",
					command: 'call_tool(name: "deobfuscate", arguments: { code: "...", unpack: true })',
				},
			],
		},
	},
};

/** All catalogued MCP helper services. */
export function getMcpServices(): readonly McpServiceDescriptor[] {
	return Object.values(MCP_SERVICE_CATALOG);
}

/** Lookup a single MCP helper service by its canonical id (case-insensitive). */
export function getMcpService(id: string): McpServiceDescriptor | undefined {
	return MCP_SERVICE_CATALOG[id.trim().toLowerCase()];
}
