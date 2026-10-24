import { afterEach, describe, expect, it, vi } from "bun:test";
import { getMCPConfigPath } from "@reverse/utils";
import { checkReverseTools, handleReverseSetup } from "../src/cli/setup-reverse";
import {
	MCP_CONFIG_PATH_HINT,
	getMcpService,
	getMcpServices,
	mcpServerSnippet,
} from "../src/extensibility/mcp-service-catalog";
import { SKILL_TOOL_CATALOG, getReverseTools } from "../src/extensibility/skill-tool-catalog";
import type { SkillRequirementWhich } from "../src/extensibility/skill-requirements";

function mockWhich(lookup: Record<string, string | null>): SkillRequirementWhich {
	return command => lookup[command] ?? null;
}

afterEach(() => {
	process.env.REVERSE_LANG = "en";
});

describe("MCP helper service catalog", () => {
	it("declares a complete, trusted schema for every service", () => {
		const services = getMcpServices();
		expect(services.length).toBeGreaterThanOrEqual(2);

		for (const service of services) {
			expect(service.id).toBeTruthy();
			expect(getMcpService(service.id)).toBe(service);
			expect(getMcpService(service.id.toUpperCase())).toBe(service);
			expect(service.name.length).toBeGreaterThan(0);
			expect(service.description.length).toBeGreaterThan(0);
			expect(service.optional).toBe(true);
			expect(service.manualUrl.startsWith("https://")).toBe(true);
			expect(service.docsUrl.startsWith("https://")).toBe(true);
			expect(service.license.length).toBeGreaterThan(0);
			expect(service.startCommand.length).toBeGreaterThan(0);
			expect(service.usage.canonical.length).toBeGreaterThan(0);
			expect(service.usage.whenToUse.length).toBeGreaterThan(0);
			expect(service.usage.examples.length).toBeGreaterThan(0);
			expect(service.configPath).toBe(MCP_CONFIG_PATH_HINT);
			expect(service.server.type).toBeDefined();
		}
	});

	it("only requires catalogued CLI ids and produces mergeable mcpServers snippets", () => {
		for (const service of getMcpServices()) {
			expect(service.requires.length).toBeGreaterThan(0);
			for (const id of service.requires) {
				expect(SKILL_TOOL_CATALOG[id]).toBeDefined();
			}

			const snippet = mcpServerSnippet(service);
			expect(Object.keys(snippet.mcpServers)).toEqual([service.serverName]);
			expect(snippet.mcpServers[service.serverName]).toEqual(service.server);
			expect(JSON.parse(JSON.stringify(snippet))).toEqual(snippet);
		}
	});

	it("ships install metadata or manual instructions for each service", () => {
		for (const service of getMcpServices()) {
			const hasInstall = (service.installCommands?.darwin?.length ?? 0) > 0;
			const manual = service.manualInstructions.darwin ?? service.manualInstructions.linux;
			expect(hasInstall || Boolean(manual)).toBe(true);
			expect(JSON.stringify(service.manualInstructions).length).toBeGreaterThan(0);
			expect(service.riskNote.length).toBeGreaterThan(0);
		}
	});
});

describe("reverse setup MCP/CLI separation", () => {
	it("never reports an MCP service as a PATH tool", () => {
		const lookups: string[] = [];
		const which: SkillRequirementWhich = command => {
			lookups.push(command);
			return { strings: "/usr/bin/strings", file: "/usr/bin/file", radare2: "/usr/local/bin/r2" }[command] ?? null;
		};

		const report = checkReverseTools({ platform: "darwin", which });
		const toolIds = report.tools.map(tool => tool.id);
		const serviceIds = report.services.map(service => service.id);

		expect(report.services.length).toBeGreaterThanOrEqual(2);
		for (const id of serviceIds) {
			expect(toolIds).not.toContain(id);
			expect(lookups).not.toContain(id);
		}

		expect(toolIds).toContain("radare2");
		const r2mcp = report.services.find(service => service.id === "r2mcp");
		expect(r2mcp?.kind).toBe("mcp");
		expect(r2mcp?.ready).toBe(true);
		expect(r2mcp?.status).toBe("ready");
		expect("foundPath" in (r2mcp ?? {})).toBe(false);
		expect(r2mcp?.prerequisites.map(status => status.id)).toEqual(["radare2"]);
		expect(r2mcp?.configSnippet).toEqual(mcpServerSnippet(getMcpService("r2mcp")!));
	});

	it("reports missing service prerequisites and a trusted install command", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			r2pm: "/usr/local/bin/r2pm",
		});
		const report = checkReverseTools({ platform: "darwin", which });

		const r2mcp = report.services.find(service => service.id === "r2mcp");
		expect(r2mcp?.ready).toBe(false);
		expect(r2mcp?.status).toBe("missing");
		expect(r2mcp?.missingPrerequisites).toContain("radare2");
		expect(r2mcp?.installCommand).toBe("r2pm -Uci r2mcp");
		expect(r2mcp?.installArgv).toEqual(["r2pm", "-Uci", "r2mcp"]);
	});

	it("falls back to manual instructions when no package manager is available", () => {
		const which = mockWhich({ strings: "/usr/bin/strings", file: "/usr/bin/file" });
		const report = checkReverseTools({ platform: "linux", which });

		for (const service of report.services) {
			expect(service.ready).toBe(false);
			expect(service.installCommand).toBeNull();
			expect(service.installArgv).toBeNull();
			expect(service.manualUrl.startsWith("https://")).toBe(true);
			expect(service.manualInstructions.length).toBeGreaterThan(0);
		}

		const playwright = report.services.find(service => service.id === "playwright-mcp");
		expect(playwright?.manualInstructions).toContain("npx");
	});

	it("reports prerequisite readiness, configuration, and connection as separate states", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			radare2: "/usr/local/bin/r2",
			r2pm: "/usr/local/bin/r2pm",
		});
		const cwd = "/tmp/rev-config-probe";
		const projectPath = getMCPConfigPath("project", cwd);
		const userPath = getMCPConfigPath("user", cwd);
		const file = (path: string) =>
			path === projectPath
				? {
						mcpServers: {
							radare2: { type: "stdio" as const, command: "r2pm", args: ["-r", "r2mcp"] },
						},
					}
				: null;

		const report = checkReverseTools({ platform: "darwin", which, cwd, readMcpConfig: file });
		const r2mcp = report.services.find(service => service.id === "r2mcp");

		expect(r2mcp?.prerequisitesReady).toBe(true);
		expect(r2mcp?.ready).toBe(true);
		expect(r2mcp?.configured).toBe(true);
		expect(r2mcp?.configuredScopes).toEqual(["project"]);
		expect(r2mcp?.enabled).toBe(true);
		expect(r2mcp?.connection).toBe("unknown");
		expect(r2mcp?.configPaths).toEqual({ project: projectPath, user: userPath });
	});

	it("does not treat prerequisite readiness as configuration or connection", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			radare2: "/usr/local/bin/r2",
			r2pm: "/usr/local/bin/r2pm",
		});

		const report = checkReverseTools({
			platform: "darwin",
			which,
			cwd: "/tmp/rev-unconfigured-probe",
			readMcpConfig: () => null,
		});
		const r2mcp = report.services.find(service => service.id === "r2mcp");

		expect(r2mcp?.ready).toBe(true);
		expect(r2mcp?.prerequisitesReady).toBe(true);
		expect(r2mcp?.configured).toBe(false);
		expect(r2mcp?.configuredScopes).toEqual([]);
		expect(r2mcp?.enabled).toBeNull();
		expect(r2mcp?.connection).toBe("unknown");
	});

	it("reports a configured but disabled server entry without probing the connection", () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			radare2: "/usr/local/bin/r2",
			r2pm: "/usr/local/bin/r2pm",
		});
		const cwd = "/tmp/rev-disabled-probe";
		const userPath = getMCPConfigPath("user", cwd);

		const report = checkReverseTools({
			platform: "darwin",
			which,
			cwd,
			readMcpConfig: path =>
				path === userPath
					? {
							mcpServers: {
								radare2: { type: "stdio" as const, command: "r2pm", args: ["-r", "r2mcp"], enabled: false },
							},
						}
					: null,
		});
		const r2mcp = report.services.find(service => service.id === "r2mcp");

		expect(r2mcp?.configured).toBe(true);
		expect(r2mcp?.configuredScopes).toEqual(["user"]);
		expect(r2mcp?.enabled).toBe(false);
		expect(r2mcp?.connection).toBe("unknown");
	});

	it("includes services in --json without adding them to tools", async () => {
		let output = "";
		const which = mockWhich({ strings: "/usr/bin/strings", file: "/usr/bin/file", brew: "/opt/homebrew/bin/brew" });
		const code = await handleReverseSetup({ json: true }, "r2mcp", {
			platform: "darwin",
			which,
			writeStdout: text => {
				output += text;
			},
		});

		expect(code).toBe(0);
		const parsed = JSON.parse(output);
		expect(Array.isArray(parsed.services)).toBe(true);
		expect(parsed.services.length).toBeGreaterThanOrEqual(2);
		expect(parsed.tools.some((tool: { id: string }) => tool.id === "r2mcp")).toBe(false);
		const r2mcp = parsed.services.find((service: { id: string }) => service.id === "r2mcp");
		expect(r2mcp.serverName).toBe("radare2");
		expect(r2mcp.configSnippet.mcpServers.radare2.command).toBe("r2pm");
		expect(r2mcp.usage.canonical).toContain("r2mcp");
	});

	it("keeps service inspection read-only and respects a declined interactive installation", async () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			brew: "/opt/homebrew/bin/brew",
			radare2: "/usr/local/bin/r2",
		});
		const checkCode = await handleReverseSetup({ check: true }, undefined, {
			platform: "darwin",
			which,
			writeStdout: () => {},
		});
		expect(checkCode).toBe(0);

		const executor = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
		const confirm = vi.fn(async () => false);
		const panelCode = await handleReverseSetup({}, "r2mcp", {
			platform: "darwin",
			which,
			isTTY: true,
			executor,
			confirm,
			writeStdout: () => {},
		});
		expect(panelCode).toBe(0);
		expect(executor).not.toHaveBeenCalled();
		expect(confirm).toHaveBeenCalledTimes(1);
	});

	it("keeps service install commands read-only in --json and --check", async () => {
		const which = mockWhich({
			strings: "/usr/bin/strings",
			file: "/usr/bin/file",
			radare2: "/usr/local/bin/r2",
			r2pm: "/usr/local/bin/r2pm",
		});
		const executor = vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "" }));
		const confirm = vi.fn(async () => true);

		let jsonOutput = "";
		const jsonCode = await handleReverseSetup({ json: true }, undefined, {
			platform: "darwin",
			which,
			executor,
			confirm,
			writeStdout: text => {
				jsonOutput += text;
			},
		});
		expect(jsonCode).toBe(0);
		const parsed = JSON.parse(jsonOutput);
		const r2mcpJson = parsed.services.find((service: { id: string }) => service.id === "r2mcp");
		expect(r2mcpJson.ready).toBe(true);
		expect(r2mcpJson.installCommand).toBe("r2pm -Uci r2mcp");

		const checkCode = await handleReverseSetup({ check: true }, undefined, {
			platform: "darwin",
			which,
			executor,
			confirm,
			writeStdout: () => {},
		});
		expect(checkCode).toBe(0);
		expect(executor).not.toHaveBeenCalled();
		expect(confirm).not.toHaveBeenCalled();
	});

	it("keeps the reverse CLI catalog free of MCP service ids", () => {
		const ids = getReverseTools().map(tool => tool.id);
		for (const service of getMcpServices()) {
			expect(ids).not.toContain(service.id);
		}
	});
});
