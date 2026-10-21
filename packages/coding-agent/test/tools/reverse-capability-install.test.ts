import { describe, expect, it } from "bun:test";
import { ReverseCapabilityTool } from "../../src/tools/reverse-capability";
import type { ToolSession } from "../../src/tools";
import { Settings } from "../../src/config/settings";
import { MCPManager } from "../../src/mcp/manager";

function makeTool(overrides: Partial<ToolSession> = {}): ReverseCapabilityTool {
	return new ReverseCapabilityTool({
		cwd: "/tmp/reverse-capability-install",
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({}),
		...overrides,
	});
}

describe("reverse capability installation authorization", () => {
	it("requires write approval for installation but leaves inspection read-only", () => {
		const tool = makeTool();
		expect(tool.approval({ action: "install", service: "jshookmcp" })).toBe("write");
		for (const action of ["list", "get", "resolve"]) expect(tool.approval({ action })).toBe("read");
	});

	it("rejects installation in a read-only plan before touching the host", async () => {
		const tool = makeTool({ getPlanModeState: () => ({ enabled: true, planFilePath: "local://plan.md" }) });
		await expect(tool.execute("install", { action: "install", service: "jshookmcp" })).rejects.toThrow("Plan mode");
	});

	it("rejects disabled MCP sessions before installing persistent packages", async () => {
		const tool = makeTool({ enableMCP: false });
		await expect(tool.execute("install", { action: "install", service: "jshookmcp" })).rejects.toThrow(
			"MCP is unavailable",
		);
	});

	it("rejects project installation when project MCP discovery is disabled", async () => {
		const tool = makeTool({
			settings: Settings.isolated({ "mcp.enableProjectConfig": false }),
			mcpManager: new MCPManager("/tmp/reverse-capability-install"),
		});
		await expect(
			tool.execute("install", { action: "install", service: "jshookmcp", scope: "project" }),
		).rejects.toThrow("Project MCP configuration is disabled");
	});

	it("does not turn other catalog services into noninteractive installers", async () => {
		const tool = makeTool();
		await expect(tool.execute("install", { action: "install" })).rejects.toThrow("install requires service");
	});
});
