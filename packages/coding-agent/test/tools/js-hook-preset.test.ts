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
