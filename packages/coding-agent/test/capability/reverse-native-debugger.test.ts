import { describe, expect, it } from "bun:test";
import { checkReverseTools } from "../../src/cli/setup-reverse";
import { resolveReverseCapabilities } from "../../src/extensibility/skill-tool-catalog";
import { ReverseCapabilityTool } from "../../src/tools/reverse-capability";
import { Settings } from "../../src/config/settings";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";

function mockWhich(lookup: Record<string, string | null>): SkillRequirementWhich {
	return command => lookup[command] ?? null;
}

describe("native_debugger Capability Resolution & Backend Truthfulness", () => {
	it("reports available_with_fallbacks and triage (not r2_inspect or debug) when only Frida is installed", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "frida", status: "installed" },
				{ id: "radare2", status: "missing" },
				{ id: "ghidra", status: "missing" },
			],
			dapAdapters: [],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(false);
		expect(cap?.status).toBe("available_with_fallbacks");
		expect(cap?.recommendedNativeTool).toBe("triage");
		expect(cap?.recommendedNativeTool).not.toBe("r2_inspect");
		expect(cap?.recommendedNativeTool).not.toBe("debug");
		expect(cap?.setupCommand).toBe("reverse setup reverse radare2");
		expect(cap?.postInstallInvocation).toContain("frida_session");

		const fridaRef = cap?.optionalExternalTools.find(t => t.id === "frida");
		expect(fridaRef?.status).toBe("installed");
		const radareRef = cap?.optionalExternalTools.find(t => t.id === "radare2");
		expect(radareRef?.status).toBe("missing");
	});

	it("reports available_with_fallbacks and triage when only Ghidra is installed", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "ghidra", status: "installed" },
				{ id: "radare2", status: "missing" },
				{ id: "frida", status: "missing" },
			],
			dapAdapters: [],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(false);
		expect(cap?.status).toBe("available_with_fallbacks");
		expect(cap?.recommendedNativeTool).toBe("triage");
		expect(cap?.recommendedNativeTool).not.toBe("r2_inspect");
		expect(cap?.setupCommand).toBe("reverse setup reverse radare2");
	});

	it("transitions to ready and recommends debug when a real DAP native debugger is available", () => {
		for (const adapterId of ["lldb-dap", "gdb", "codelldb"]) {
			const resolved = resolveReverseCapabilities({
				platform: "darwin",
				dapAdapters: [adapterId],
				toolStatuses: [
					{ id: "radare2", status: "missing" },
					{ id: "frida", status: "missing" },
					{ id: "ghidra", status: "missing" },
				],
			});

			const cap = resolved.find(c => c.id === "native_debugger");
			expect(cap).toBeDefined();
			expect(cap?.ready).toBe(true);
			expect(cap?.status).toBe("ready");
			expect(cap?.recommendedNativeTool).toBe("debug");
			expect(cap?.postInstallInvocation).toContain("debug");
			expect(cap?.postInstallInvocation).toContain(adapterId);
		}
	});

	it("respects session settings disabling debug tool and demotes DAP route readiness", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			dapAdapters: ["lldb-dap"],
			debugToolEnabled: false,
			toolStatuses: [
				{ id: "radare2", status: "missing" },
				{ id: "frida", status: "installed" },
			],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(false);
		expect(cap?.status).toBe("available_with_fallbacks");
		expect(cap?.recommendedNativeTool).toBe("triage");
	});

	it("reports ready for radare2 installation and routes postInstallInvocation to r2 -d", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "radare2", status: "installed" },
				{ id: "frida", status: "missing" },
				{ id: "ghidra", status: "missing" },
			],
			dapAdapters: [],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(true);
		expect(cap?.status).toBe("ready");
		expect(cap?.recommendedNativeTool).toBe("triage");
		expect(cap?.postInstallInvocation).toContain("r2 -d");
	});

	it("prefers native DAP debug when both DAP debugger and radare2 are present", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "radare2", status: "installed" },
				{ id: "frida", status: "installed" },
			],
			dapAdapters: ["lldb-dap"],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(true);
		expect(cap?.status).toBe("ready");
		expect(cap?.recommendedNativeTool).toBe("debug");
	});

	it("reports missing when all tools, DAP adapters, and fallbacks are absent", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [
				{ id: "radare2", status: "missing" },
				{ id: "frida", status: "missing" },
				{ id: "ghidra", status: "missing" },
				{ id: "file", status: "missing" },
				{ id: "strings", status: "missing" },
				{ id: "readelf", status: "missing" },
				{ id: "binary_metadata_inspect", status: "missing" },
			],
			dapAdapters: [],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(false);
		expect(cap?.status).toBe("missing");
		expect(cap?.recommendedNativeTool).toBe("triage");
		expect(cap?.postInstallInvocation).toContain("radare2");
	});

	it("rejects readiness when r2mcp is configured but unconnected and radare2 is missing", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			toolStatuses: [{ id: "radare2", status: "missing" }],
			serviceStatuses: [
				{
					id: "r2mcp",
					configured: true,
					connection: "unknown",
					ready: false,
					prerequisitesReady: false,
				},
			],
			dapAdapters: [],
		});

		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap).toBeDefined();
		expect(cap?.ready).toBe(false);
	});

	it("preserves custom native adapter names passed via authoritative dapAdapters seam", () => {
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			dapAdapters: ["custom-lldb"],
		});
		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap?.ready).toBe(true);
		expect(cap?.status).toBe("ready");
		expect(cap?.recommendedNativeTool).toBe("debug");
		expect(cap?.postInstallInvocation).toContain("debug");
		expect(cap?.postInstallInvocation).toContain("custom-lldb");
	});

	it("excludes Python and JS debug adapters from native binary debugger discovery", () => {
		const which = mockWhich({
			debugpy: "/usr/local/bin/debugpy",
			"js-debug-adapter": "/usr/local/bin/js-debug-adapter",
			"lldb-dap": "/usr/bin/lldb-dap",
		});
		const resolved = resolveReverseCapabilities({
			platform: "darwin",
			which,
		});
		const cap = resolved.find(c => c.id === "native_debugger");
		expect(cap?.ready).toBe(true);
		expect(cap?.recommendedNativeTool).toBe("debug");
		expect(cap?.postInstallInvocation).toContain("lldb-dap");
		expect(cap?.postInstallInvocation).not.toContain("debugpy");
		expect(cap?.postInstallInvocation).not.toContain("js-debug-adapter");
	});

	it("integrates with checkReverseTools using mockWhich without ambient environment pollution", () => {
		// Case A: Frida only on PATH
		const reportFridaOnly = checkReverseTools({
			platform: "darwin",
			which: mockWhich({ frida: "/usr/local/bin/frida" }),
		});
		const capFrida = reportFridaOnly.capabilities.find(c => c.id === "native_debugger");
		expect(capFrida?.ready).toBe(false);
		expect(capFrida?.status).toBe("available_with_fallbacks");
		expect(capFrida?.recommendedNativeTool).toBe("triage");
		expect(capFrida?.recommendedNativeTool).not.toBe("r2_inspect");

		// Case B: Radare2 on PATH
		const reportRadareOnly = checkReverseTools({
			platform: "darwin",
			which: mockWhich({ r2: "/usr/local/bin/r2", radare2: "/usr/local/bin/radare2" }),
		});
		const capRadare = reportRadareOnly.capabilities.find(c => c.id === "native_debugger");
		expect(capRadare?.ready).toBe(true);
		expect(capRadare?.status).toBe("ready");
		expect(capRadare?.postInstallInvocation).toContain("r2 -d");

		// Case C: lldb-dap on PATH
		const reportLldbDap = checkReverseTools({
			platform: "darwin",
			which: mockWhich({ "lldb-dap": "/usr/bin/lldb-dap" }),
		});
		const capLldb = reportLldbDap.capabilities.find(c => c.id === "native_debugger");
		expect(capLldb?.ready).toBe(true);
		expect(capLldb?.status).toBe("ready");
		expect(capLldb?.recommendedNativeTool).toBe("debug");
	});

	it("executes ReverseCapabilityTool runtime resolve with debug.enabled true vs false", async () => {
		const toolEnabled = new ReverseCapabilityTool({
			cwd: process.cwd(),
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated({ "debug.enabled": true }),
		});
		const resultEnabled = await toolEnabled.execute("smoke-enabled", {
			action: "resolve",
			capability: "native_debugger",
		});
		const detailsEnabled = resultEnabled.details as {
			capabilities: Array<{ id: string; ready: boolean; recommendedNativeTool?: string }>;
		};
		const capEnabled = detailsEnabled.capabilities.find(c => c.id === "native_debugger");
		expect(capEnabled).toBeDefined();

		const toolDisabled = new ReverseCapabilityTool({
			cwd: process.cwd(),
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated({ "debug.enabled": false }),
		});
		const resultDisabled = await toolDisabled.execute("smoke-disabled", {
			action: "resolve",
			capability: "native_debugger",
		});
		const detailsDisabled = resultDisabled.details as {
			capabilities: Array<{ id: string; ready: boolean; recommendedNativeTool?: string }>;
		};
		const capDisabled = detailsDisabled.capabilities.find(c => c.id === "native_debugger");
		expect(capDisabled).toBeDefined();
		expect(capDisabled?.recommendedNativeTool).not.toBe("debug");
	});
});
