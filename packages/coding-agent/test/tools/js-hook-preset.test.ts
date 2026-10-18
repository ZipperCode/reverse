import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	JsHookPresetTool,
	type JsHookPresetDetails,
	type ToolSession,
	validateCustomTargetSelector,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

describe("js_hook_preset discovery and registration", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("js_hook_preset");
		expect(normalizeToolName("js_hook_preset")).toBe("js_hook_preset");
		expect(normalizeToolName("jshook")).toBe("js_hook_preset");
		expect(normalizeToolName("jshook_preset")).toBe("js_hook_preset");
		expect(normalizeToolName("generate_js_hook")).toBe("js_hook_preset");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["js_hook_preset"]);
			const tool = tools.find(t => t.name === "js_hook_preset");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("js_hook_preset");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("js_hook_preset action: list", () => {
	it("lists all supported presets with targets and options", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-list-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_1", { action: "list" });

			expect(result.details?.action).toBe("list");
			expect(result.details?.isTemplateOnly).toBe(true);
			expect(result.details?.executed).toBe(false);

			const presets = result.details?.catalog?.map(p => p.preset) ?? [];
			expect(presets).toContain("fetch");
			expect(presets).toContain("xhr");
			expect(presets).toContain("websocket");
			expect(presets).toContain("crypto");
			expect(presets).toContain("eval");
			expect(presets).toContain("json_parse");
			expect(presets).toContain("contextBridge");
			expect(presets).toContain("custom");

			const outputText = textOf(result);
			expect(outputText).toContain("Fetch API Interceptor");
			expect(outputText).toContain("Electron ContextBridge");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("js_hook_preset action: generate", () => {
	it("generates fetch interceptor template with filtering and options", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-fetch-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_2", {
				action: "generate",
				preset: "fetch",
				filter: "/api/v2/",
				tamper_mode: "debugger",
			});

			expect(result.details?.action).toBe("generate");
			expect(result.details?.preset).toBe("fetch");
			expect(result.details?.isTemplateOnly).toBe(true);
			expect(result.details?.executed).toBe(false);

			const script = result.details?.script ?? "";
			expect(script).toContain("window.fetch");
			expect(script).toContain('"/api/v2/"');
			expect(script).toContain("debugger;");
			expect(script).toContain("THIS SCRIPT HAS NOT BEEN EXECUTED");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates xhr interceptor template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-xhr-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_3", {
				action: "generate",
				preset: "xhr",
				max_payload_length: 512,
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("XMLHttpRequest.prototype.open");
			expect(script).toContain("XMLHttpRequest.prototype.setRequestHeader");
			expect(script).toContain("XMLHttpRequest.prototype.send");
			expect(result.details?.isTemplateOnly).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates websocket interceptor template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-ws-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_4", {
				action: "generate",
				preset: "websocket",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("window.WebSocket");
			expect(script).toContain("ws.send");
			expect(script).toContain("addEventListener(\"message\"");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates web crypto monitor template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-crypto-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_5", {
				action: "generate",
				preset: "crypto",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("crypto.subtle");
			expect(script).toContain("encrypt");
			expect(script).toContain("decrypt");
			expect(script).toContain("digest");
			expect(script).toContain("toHex");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates eval & dynamic execution detector template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-eval-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_6", {
				action: "generate",
				preset: "eval",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("window.eval");
			expect(script).toContain("FunctionHook");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates json_parse observer template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-json-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_7", {
				action: "generate",
				preset: "json_parse",
				filter: "auth_token",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("JSON.parse");
			expect(script).toContain('"auth_token"');
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates Electron contextBridge IPC tracer template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-bridge-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_8", {
				action: "generate",
				preset: "contextBridge",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("contextBridge.exposeInMainWorld");
			expect(script).toContain("wrapObject");
			expect(script).toContain("ELECTRON IPC");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates custom target selector hook for allowlisted path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-custom-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_9", {
				action: "generate",
				preset: "custom",
				target: "window.myApp.crypto.signToken",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain('"window.myApp.crypto.signToken"');
			expect(script).toContain("CUSTOM HOOK");
			expect(result.details?.target).toBe("window.myApp.crypto.signToken");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("formats script with userscript metadata header when requested", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-user-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_10", {
				action: "generate",
				preset: "fetch",
				format: "userscript",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("// ==UserScript==");
			expect(script).toContain("// @run-at       document-start");
			expect(script).toContain("// ==/UserScript==");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("formats script with Frida wrapper when format is frida", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-frida-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const result = await tool.execute("call_11", {
				action: "generate",
				preset: "crypto",
				format: "frida",
			});

			const script = result.details?.script ?? "";
			expect(script).toContain("[Frida]");
			expect(script).toContain("evaluateJavascript");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("js_hook_preset validation and security allowlisting", () => {
	it("rejects invalid or unsafe target selectors with ToolError", () => {
		expect(() => validateCustomTargetSelector("")).toThrow("target is required");
		expect(() => validateCustomTargetSelector("window.eval('malicious')")).toThrow("Invalid target selector");
		expect(() => validateCustomTargetSelector("window.a;alert(1)")).toThrow("Invalid target selector");
		expect(() => validateCustomTargetSelector("window[0]")).toThrow("Invalid target selector");
		expect(() => validateCustomTargetSelector("window.__proto__.polluted")).toThrow("Disallowed property accessor");
		expect(() => validateCustomTargetSelector("Object.prototype.polluted")).toThrow("Disallowed property accessor");
		expect(() => validateCustomTargetSelector("myClass.constructor.evil")).toThrow("Disallowed property accessor");
	});

	it("accepts valid dotted identifier chains", () => {
		expect(() => validateCustomTargetSelector("window.api.login")).not.toThrow();
		expect(() => validateCustomTargetSelector("document.cookie")).not.toThrow();
		expect(() => validateCustomTargetSelector("_global$Service.v2_endpoint")).not.toThrow();
	});

	it("fails execution when custom preset is missing target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			await expect(
				tool.execute("call_err", {
					action: "generate",
					preset: "custom",
				}),
			).rejects.toThrow("target parameter is required");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
function createMockBrowserRunner(initialTabs: Record<string, { state: "alive" | "dead"; url?: string; title?: string }> = {}) {
	const tabs = new Map<string, { state: "alive" | "dead"; url?: string; title?: string }>(Object.entries(initialTabs));
	const calls: Array<{ type: string; name: string; payload?: unknown }> = [];
	const inTabEvents = new Map<string, any[]>();
	const inTabConsole = new Map<string, any[]>();
	const inTabRequests = new Map<string, any[]>();

	return {
		calls,
		tabs,
		inTabEvents,
		inTabConsole,
		inTabRequests,
		getTab(name: string) {
			const t = tabs.get(name);
			return t ? { name, state: t.state, url: t.url, title: t.title } : undefined;
		},
		async openTab(name: string, url: string) {
			calls.push({ type: "openTab", name, payload: url });
			tabs.set(name, { state: "alive", url, title: "Test Page" });
			return { name, url };
		},
		async runInTab(name: string, opts: { code: string; timeoutMs?: number; signal?: AbortSignal }) {
			calls.push({ type: "runInTab", name, payload: opts.code });
			if (opts.code.includes("tab.addInitScript")) {
				return {
					returnValue: { initScriptId: `init_${name}_123`, evaluated: true },
					displays: [],
				};
			}
			if (opts.code.includes("window.__rea_events__") && opts.code.includes("tab.console")) {
				const events = inTabEvents.get(name) || [];
				const consoleLogs = inTabConsole.get(name) || [];
				const requests = inTabRequests.get(name) || [];
				if (opts.code.includes("window.__rea_events__ = []")) {
					inTabEvents.set(name, []);
				}
				return {
					returnValue: { events, consoleLogs, requests },
					displays: [],
				};
			}
			if (opts.code.includes("window.__rea_events__ = []")) {
				inTabEvents.set(name, []);
				return { returnValue: { cleared: true }, displays: [] };
			}
			return { returnValue: {}, displays: [] };
		},
		async closeTab(name: string) {
			calls.push({ type: "closeTab", name });
			tabs.set(name, { state: "dead" });
			return true;
		},
	};
}

describe("js_hook_preset action: inject", () => {
	it("rejects when target tab is missing and no url is provided", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-inj-err-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new JsHookPresetTool(session, runner);

			await expect(
				tool.execute("call_inj_missing", {
					action: "inject",
					preset: "fetch",
					tab_name: "nonexistent",
				}),
			).rejects.toThrow("Browser tab \"nonexistent\" is not open or alive");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("opens a new tab and injects preset when url is supplied", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-inj-open-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new JsHookPresetTool(session, runner);

			const result = await tool.execute("call_inj_open", {
				action: "inject",
				preset: "fetch",
				tab_name: "auth_tab",
				url: "https://auth.example.com",
				filter: "/oauth/token",
			});

			expect(result.details?.action).toBe("inject");
			expect(result.details?.preset).toBe("fetch");
			expect(result.details?.tab_name).toBe("auth_tab");
			expect(result.details?.url).toBe("https://auth.example.com");
			expect(result.details?.executed).toBe(true);
			expect(result.details?.isTemplateOnly).toBe(false);
			expect(result.details?.init_script_id).toBe("init_auth_tab_123");
			expect(result.details?.evaluated).toBe(true);

			expect(runner.calls.some(c => c.type === "openTab" && c.name === "auth_tab")).toBe(true);
			expect(runner.calls.some(c => c.type === "runInTab" && c.name === "auth_tab")).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("injects preset into an existing live tab", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-inj-live-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://app.test/dashboard" },
			});
			const tool = new JsHookPresetTool(session, runner);

			const result = await tool.execute("call_inj_live", {
				action: "inject",
				preset: "crypto",
				tab_name: "main",
			});

			expect(result.details?.action).toBe("inject");
			expect(result.details?.preset).toBe("crypto");
			expect(result.details?.executed).toBe(true);
			expect(result.details?.init_script_id).toBe("init_main_123");
			expect(result.details?.evaluated).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("js_hook_preset action: capture and clear", () => {
	it("fails capture when tab is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-cap-err-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new JsHookPresetTool(session, runner);

			await expect(
				tool.execute("call_cap_err", {
					action: "capture",
					tab_name: "missing",
				}),
			).rejects.toThrow("Browser tab \"missing\" is not open or alive");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("captures structured events, console logs, and formats evidence records", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-cap-ok-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://secure.test/login" },
			});

			runner.inTabEvents.set("main", [
				{
					timestamp: Date.now(),
					type: "fetch_request",
					id: "req1",
					method: "POST",
					url: "https://secure.test/api/login",
					body: '{"user":"admin"}',
				},
				{
					timestamp: Date.now(),
					type: "crypto_call",
					id: "cry1",
					method: "encrypt",
					algorithm: "AES-GCM",
					dataHex: "61646d696e",
				},
			]);
			runner.inTabConsole.set("main", ["console message 1"]);
			runner.inTabRequests.set("main", [{ url: "https://secure.test/api/login" }]);

			const tool = new JsHookPresetTool(session, runner);
			const result = await tool.execute("call_cap_ok", {
				action: "capture",
				tab_name: "main",
				export_evidence: true,
			});

			expect(result.details?.action).toBe("capture");
			expect(result.details?.eventCount).toBe(2);
			expect(result.details?.events).toHaveLength(2);
			expect(result.details?.events?.[0].type).toBe("fetch_request");
			expect(result.details?.events?.[1].type).toBe("crypto_call");
			expect(result.details?.consoleLogs).toHaveLength(1);
			expect(result.details?.requests).toHaveLength(1);

			expect(result.details?.evidence).toBeDefined();
			expect(result.details?.evidence).toHaveLength(2);
			expect(result.details?.evidence?.[0].kind).toBe("fact");
			expect(result.details?.evidence?.[0].locator).toBe("tab:main:fetch_request:req1");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("clears event buffer via action: clear", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-clear-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://secure.test" },
			});
			runner.inTabEvents.set("main", [{ type: "test" }]);

			const tool = new JsHookPresetTool(session, runner);
			const result = await tool.execute("call_clr", {
				action: "clear",
				tab_name: "main",
			});

			expect(result.details?.action).toBe("clear");
			expect(result.details?.executed).toBe(true);
			expect(runner.inTabEvents.get("main")).toEqual([]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("embeds structured ring buffer recording in all generated templates", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-ring-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);

			for (const preset of ["fetch", "xhr", "websocket", "crypto", "eval", "json_parse", "contextBridge"] as const) {
				const res = await tool.execute(`gen_${preset}`, { action: "generate", preset });
				const script = res.details?.script ?? "";
				expect(script).toContain("window.__rea_events__");
				expect(script).toContain("_reaRecord");
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
