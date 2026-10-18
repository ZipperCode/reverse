/**
 * Trusted catalog of optional MCP helper services for reverse engineering.
 *
 * This catalog is deliberately separate from {@link SKILL_TOOL_CATALOG}: an MCP
 * service is not a PATH binary. It owns the server configuration template, the
 * launch command, prerequisite catalog ids, install hints, and the canonical
 * usage guidance an agent needs to call the service correctly.
 *
 * Only client-vetted entries belong here. Package installs are executed
 * exclusively by the setup panel after explicit interactive confirmation; no
 * skill, MCP server, or remote registry can inject an argv into that path.
 */
import type { MCPServerConfig } from "../mcp/types";
import type { PackageInstallCommand, SkillToolPlatform, ToolCategory, ToolUsageGuide } from "./skill-tool-catalog";

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
	/** Server key written under `mcpServers` in the rea MCP config. */
	serverName: string;
	/** Trusted MCP server config template for `.rva/mcp.json`. */
	server: MCPServerConfig;
	/** Display-only config path hint; `setup reverse --json` reports resolved `configPaths`. */
	configPath: string;
	/** Species/documentation URL for the server integration. */
	docsUrl: string;
	/** Upstream license identifier; sources must not be AGPL/GPL-only. */
	license: string;
	/** Packaging, privilege, network, or commercial-software warning. */
	riskNote: string;
	/** Canonical model-facing usage guidance. */
	usage: ToolUsageGuide;
}

/** Config path hint shown by setup panels and the guide skill. */
export const MCP_CONFIG_PATH_HINT = ".rva/mcp.json (project) or ~/.rva/agent/mcp.json (user)";

/** Suggested server key + config for a service, ready to merge into `mcpServers`. */
export function mcpServerSnippet(descriptor: McpServiceDescriptor): { mcpServers: Record<string, MCPServerConfig> } {
	return { mcpServers: { [descriptor.serverName]: descriptor.server } };
}

/**
 * Built-in catalog of optional MCP helper services.
 *
 * Every package below is published by its upstream project or vendor and is
 * licensed permissively; AGPL/GPL-only reverse-engineering projects are not
 * vendored or copied here.
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
};

/** All catalogued MCP helper services. */
export function getMcpServices(): readonly McpServiceDescriptor[] {
	return Object.values(MCP_SERVICE_CATALOG);
}

/** Lookup a single MCP helper service by its canonical id (case-insensitive). */
export function getMcpService(id: string): McpServiceDescriptor | undefined {
	return MCP_SERVICE_CATALOG[id.trim().toLowerCase()];
}
