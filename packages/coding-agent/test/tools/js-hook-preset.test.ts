import { describe, expect, it } from "bun:test";
import type { webcrypto } from "node:crypto";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import {
	type BrowserReverseEvent,
	createTools,
	JsHookPresetTool,
	type ToolSession,
	validateCustomTargetSelector,
} from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

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
			expect(script).toContain('addEventListener("message"');
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
function createMockBrowserRunner(
	initialTabs: Record<string, { state: "alive" | "dead"; url?: string; title?: string }> = {},
) {
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
			).rejects.toThrow('Browser tab "nonexistent" is not open or alive');
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
			).rejects.toThrow('Browser tab "missing" is not open or alive');
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

function createInstrumentedCryptoEnv(script: string) {
	const realSubtle = globalThis.crypto.subtle;
	let exportKeyCalls = 0;
	const subtleFacade = {
		encrypt: realSubtle.encrypt.bind(realSubtle),
		decrypt: realSubtle.decrypt.bind(realSubtle),
		digest: realSubtle.digest.bind(realSubtle),
		importKey: realSubtle.importKey.bind(realSubtle),
		exportKey: ((format: Parameters<SubtleCrypto["exportKey"]>[0], key: CryptoKey) => {
			exportKeyCalls += 1;
			return realSubtle.exportKey(format as "raw", key);
		}) as SubtleCrypto["exportKey"],
		sign: realSubtle.sign.bind(realSubtle),
		verify: realSubtle.verify.bind(realSubtle),
	} as unknown as SubtleCrypto; // Partial SubtleCrypto facade forwarding the 7 hooked operations
	const cryptoFacade = {
		subtle: subtleFacade,
		getRandomValues: <T extends ArrayBufferView | null>(array: T): T => globalThis.crypto.getRandomValues(array),
	};
	const consoleLogs: string[] = [];
	const mockConsole = {
		log: (...args: unknown[]) => consoleLogs.push(args.map(String).join(" ")),
		warn: (...args: unknown[]) => consoleLogs.push(args.map(String).join(" ")),
		error: (...args: unknown[]) => consoleLogs.push(args.map(String).join(" ")),
		groupCollapsed: (...args: unknown[]) => consoleLogs.push(args.map(String).join(" ")),
		groupEnd: () => undefined,
	};
	const win: { __rea_events__: BrowserReverseEvent[]; crypto: typeof cryptoFacade; [key: string]: unknown } = {
		__rea_events__: [],
		crypto: cryptoFacade,
	};
	const installer = new Function("window", "crypto", "console", script);
	installer(win, cryptoFacade, mockConsole);
	return {
		win,
		crypto: cryptoFacade,
		subtle: cryptoFacade.subtle,
		events: win.__rea_events__,
		consoleLogs,
		getExportKeyCalls: () => exportKeyCalls,
	};
}

describe("js_hook_preset behavioral execution: Web Crypto & custom hooks", () => {
	it("captures digest(algorithm, data) argument position and correlates result", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-digest-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_digest", { action: "generate", preset: "crypto" });
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			const input = new TextEncoder().encode("abc");
			const digestBuf = await env.subtle.digest("SHA-256", input);
			const digestHex = Buffer.from(digestBuf).toString("hex");
			expect(digestHex).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

			expect(env.events).toHaveLength(2);
			const [callEv, resEv] = env.events;
			expect(callEv.type).toBe("crypto_call");
			expect(callEv.method).toBe("digest");
			expect(callEv.algorithm).toBe("SHA-256");
			expect(callEv.algorithmParameters).toEqual({ name: "SHA-256" });
			expect(callEv.keyPreview).toBeNull();
			expect(callEv.dataHex).toBe("616263");
			expect(callEv.dataByteLength).toBe(3);
			expect(callEv.dataTruncated).toBe(false);
			expect(callEv.complete).toBe(true);

			expect(resEv.type).toBe("crypto_result");
			expect(resEv.id).toBe(callEv.id);
			expect(resEv.method).toBe("digest");
			expect(resEv.resultHex).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
			expect(resEv.resultByteLength).toBe(32);
			expect(resEv.resultTruncated).toBe(false);
			expect(resEv.complete).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("captures importKey, sign, and verify(true/false) without auto-exporting keys or leaking secret bytes in previews", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-verify-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_verify", { action: "generate", preset: "crypto" });
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			const secretHex = "deadbeefcafebabe00112233445566778899aabbccddeeff0011223344556677";
			const keyBytes = Uint8Array.from(Buffer.from(secretHex, "hex"));
			const hmacKey = await env.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, [
				"sign",
				"verify",
			]);

			// Non-extractable key must never be auto-exported
			expect(env.getExportKeyCalls()).toBe(0);

			const importCall = env.events[0];
			const importRes = env.events[1];
			expect(importCall.type).toBe("crypto_call");
			expect(importCall.method).toBe("importKey");
			expect(importCall.format).toBe("raw");
			expect(importCall.algorithm).toBe("HMAC");
			expect(importCall.algorithmParameters).toMatchObject({ name: "HMAC", hash: "SHA-256" });
			expect(importCall.extractable).toBe(false);
			expect(importCall.keyUsages).toEqual(["sign", "verify"]);
			expect(importCall.keyPreview).not.toContain(secretHex);
			expect(importCall.dataPreview).toContain("redacted keyData");
			expect(env.consoleLogs.join("\n")).not.toContain(secretHex);

			expect(importRes.type).toBe("crypto_result");
			expect(importRes.id).toBe(importCall.id);
			expect(importRes.result).toMatchObject({
				type: "secret",
				extractable: false,
				usages: ["sign", "verify"],
			});

			const message = new TextEncoder().encode("protocol=v2&ts=1700000000");
			const messageHex = Buffer.from(message).toString("hex");
			const sigBuf = await env.subtle.sign("HMAC", hmacKey, message);
			const sigHex = Buffer.from(sigBuf).toString("hex");

			const validOk = await env.subtle.verify("HMAC", hmacKey, sigBuf, message);
			expect(validOk).toBe(true);

			const tamperedSig = new Uint8Array(sigBuf.slice(0));
			tamperedSig[0] ^= 0xff;
			const tamperedHex = Buffer.from(tamperedSig).toString("hex");
			const invalidOk = await env.subtle.verify("HMAC", hmacKey, tamperedSig, message);
			expect(invalidOk).toBe(false);
			expect(env.getExportKeyCalls()).toBe(0);

			const verifyTrueCall = env.events[4];
			const verifyTrueRes = env.events[5];
			expect(verifyTrueCall.method).toBe("verify");
			expect(verifyTrueCall.signatureHex).toBe(sigHex);
			expect(verifyTrueCall.signatureByteLength).toBe(32);
			expect(verifyTrueCall.dataHex).toBe(messageHex);
			expect(verifyTrueCall.dataByteLength).toBe(message.byteLength);
			expect(verifyTrueCall.complete).toBe(true);
			expect(verifyTrueRes.id).toBe(verifyTrueCall.id);
			expect(verifyTrueRes.result).toBe(true);
			expect(verifyTrueRes.verified).toBe(true);
			expect(verifyTrueRes.resultHex).toBe("true");
			expect(verifyTrueRes.complete).toBe(true);

			const verifyFalseCall = env.events[6];
			const verifyFalseRes = env.events[7];
			expect(verifyFalseCall.method).toBe("verify");
			expect(verifyFalseCall.signatureHex).toBe(tamperedHex);
			expect(verifyFalseCall.dataHex).toBe(messageHex);
			expect(verifyFalseRes.id).toBe(verifyFalseCall.id);
			expect(verifyFalseRes.result).toBe(false);
			expect(verifyFalseRes.verified).toBe(false);
			expect(verifyFalseRes.resultHex).toBe("false");
			expect(verifyFalseRes.complete).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("retains full algorithm parameters (IV, AAD, tagLength) and slices TypedArray/DataView subviews accurately", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-subview-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_subview", { action: "generate", preset: "crypto" });
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			const rawKey = new Uint8Array(16);
			for (let i = 0; i < 16; i++) rawKey[i] = i + 1;
			const aesKey = await env.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
			env.events.length = 0;

			// Shared backing buffer filled with 0xff sentinel bytes to verify subview offsets/lengths
			const arena = new Uint8Array(64).fill(0xff);
			const ivBytes = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
			const aadBytes = Uint8Array.from([0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]);
			const ptBytes = new TextEncoder().encode("SubviewMsg");
			arena.set(ivBytes, 4);
			arena.set(aadBytes, 20);
			arena.set(ptBytes, 36);

			const ivSubview = new Uint8Array(arena.buffer, 4, 12);
			const aadDataView = new DataView(arena.buffer, 20, 8);
			const ptSubview = new Uint8Array(arena.buffer, 36, ptBytes.byteLength);

			const ciphertext = await env.subtle.encrypt(
				{ name: "AES-GCM", iv: ivSubview, additionalData: aadDataView, tagLength: 128 },
				aesKey,
				ptSubview,
			);
			const decrypted = await env.subtle.decrypt(
				{ name: "AES-GCM", iv: ivSubview, additionalData: aadDataView, tagLength: 128 },
				aesKey,
				ciphertext,
			);
			expect(new TextDecoder().decode(decrypted)).toBe("SubviewMsg");

			const encCall = env.events[0];
			const encRes = env.events[1];
			const decRes = env.events[3];
			expect(encCall.algorithm).toBe("AES-GCM");
			expect(encCall.algorithmParameters).toMatchObject({
				name: "AES-GCM",
				iv: "0102030405060708090a0b0c",
				ivHex: "0102030405060708090a0b0c",
				ivByteLength: 12,
				ivTruncated: false,
				additionalData: "a1a2a3a4a5a6a7a8",
				additionalDataHex: "a1a2a3a4a5a6a7a8",
				additionalDataByteLength: 8,
				additionalDataTruncated: false,
				tagLength: 128,
			});
			expect(encCall.dataHex).toBe(Buffer.from(ptBytes).toString("hex"));
			expect(encCall.dataByteLength).toBe(10);
			expect(encCall.complete).toBe(true);
			expect(encRes.resultByteLength).toBe(10 + 16);
			expect(decRes.resultHex).toBe(Buffer.from(ptBytes).toString("hex"));
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("separates preview truncation from bounded complete raw bytes and marks truncated or redacted captures incomplete", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-trunc-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			// max_payload_length = 64 -> raw limit = 32 bytes (64 hex chars), preview limit = 8 bytes (16 hex chars)
			const gen = await tool.execute("gen_trunc", {
				action: "generate",
				preset: "crypto",
				max_payload_length: 64,
			});
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			// 1) 20-byte buffer: preview is truncated (20 > 8), but raw dataHex is complete (20 <= 32)
			const mediumPayload = new Uint8Array(20);
			for (let i = 0; i < mediumPayload.length; i++) mediumPayload[i] = i + 1;
			await env.subtle.digest("SHA-256", mediumPayload);

			const medCall = env.events[0];
			const medRes = env.events[1];
			expect(medCall.dataPreviewTruncated).toBe(true);
			expect(medCall.dataPreview).toContain("...[+12 bytes]");
			expect(medCall.dataHex).toBe(Buffer.from(mediumPayload).toString("hex"));
			expect(medCall.dataByteLength).toBe(20);
			expect(medCall.dataCapturedByteLength).toBe(20);
			expect(medCall.dataTruncated).toBe(false);
			expect(medCall.truncated).toBe(false);
			expect(medCall.complete).toBe(true);
			expect(medRes.resultByteLength).toBe(32);
			expect(medRes.resultTruncated).toBe(false);
			expect(medRes.complete).toBe(true);

			// 2) 48-byte buffer: exceeds 32-byte raw capture limit -> bounded pure hex, marked incomplete
			env.events.length = 0;
			const largePayload = new Uint8Array(48);
			for (let i = 0; i < largePayload.length; i++) largePayload[i] = (i * 3) & 0xff;
			await env.subtle.digest("SHA-256", largePayload);

			const lgCall = env.events[0];
			const lgRes = env.events[1];
			expect(lgCall.dataHex).toBe(Buffer.from(largePayload.subarray(0, 32)).toString("hex"));
			expect(lgCall.dataHex).not.toContain("...[+");
			expect(lgCall.dataByteLength).toBe(48);
			expect(lgCall.dataCapturedByteLength).toBe(32);
			expect(lgCall.dataTruncated).toBe(true);
			expect(lgCall.truncated).toBe(true);
			expect(lgCall.complete).toBe(false);
			// Result event inherits incomplete call status so partial input never becomes an oracle vector
			expect(lgRes.id).toBe(lgCall.id);
			expect(lgRes.truncated).toBe(true);
			expect(lgRes.complete).toBe(false);

			// 3) JWK importKey & exportKey with secret field k: redacts k and marks omission/incomplete
			env.events.length = 0;
			const jwkKey = await env.subtle.importKey(
				"jwk",
				{
					kty: "oct",
					k: "c2VjcmV0X2tleV9tYXRlcmlhbF8xMjM0NTY3ODkwMTI",
					alg: "HS256",
					ext: true,
					key_ops: ["sign", "verify"],
				},
				{ name: "HMAC", hash: "SHA-256" },
				true,
				["sign", "verify"],
			);
			const exportedJwk = (await env.subtle.exportKey("jwk", jwkKey)) as unknown as Record<string, unknown>;
			expect(exportedJwk.k).toBe("c2VjcmV0X2tleV9tYXRlcmlhbF8xMjM0NTY3ODkwMTI");

			const jwkImportCall = env.events[0];
			const jwkExportRes = env.events[3];
			expect(jwkImportCall.jwk?.k).toBe("[REDACTED]");
			expect(jwkImportCall.omittedFields).toContain("k");
			expect(jwkImportCall.truncated).toBe(true);
			expect(jwkImportCall.complete).toBe(false);

			expect(jwkExportRes.jwk?.k).toBe("[REDACTED]");
			expect(jwkExportRes.omittedFields).toContain("k");
			expect(jwkExportRes.truncated).toBe(true);
			expect(jwkExportRes.complete).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("records correlated crypto_error events and rethrows original exceptions on failure", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_err", { action: "generate", preset: "crypto" });
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			const rawKey = new Uint8Array(16).fill(7);
			const nonExtractableKey = await env.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
			env.events.length = 0;

			// 1) Decrypting invalid ciphertext/authentication tag must reject and log correlated crypto_error
			const iv = new Uint8Array(12).fill(1);
			const bogusCiphertext = new Uint8Array(24).fill(0x42);
			await expect(
				env.subtle.decrypt({ name: "AES-GCM", iv }, nonExtractableKey, bogusCiphertext),
			).rejects.toThrow();

			expect(env.events).toHaveLength(2);
			const [decCall, decErr] = env.events;
			expect(decCall.type).toBe("crypto_call");
			expect(decCall.method).toBe("decrypt");
			expect(decErr.type).toBe("crypto_error");
			expect(decErr.id).toBe(decCall.id);
			expect(decErr.method).toBe("decrypt");
			expect(decErr.algorithm).toBe("AES-GCM");
			expect(decErr.complete).toBe(false);
			expect(typeof decErr.error).toBe("string");

			// 2) Exporting a non-extractable key must reject and log correlated crypto_error
			env.events.length = 0;
			await expect(env.subtle.exportKey("raw", nonExtractableKey)).rejects.toThrow();
			expect(env.events).toHaveLength(2);
			expect(env.events[0].type).toBe("crypto_call");
			expect(env.events[1].type).toBe("crypto_error");
			expect(env.events[1].id).toBe(env.events[0].id);
			expect(env.events[1].method).toBe("exportKey");
			expect(env.events[1].complete).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes custom hook preset on allowlisted signing function with subviews and correlated results", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-custom-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_custom_exec", {
				action: "generate",
				preset: "custom",
				target: "window.customCrypto.signFrame",
			});

			interface CustomHookTestWindow {
				__rea_events__: BrowserReverseEvent[];
				customCrypto: {
					signFrame: (payloadView: Uint8Array, nonce: string) => string;
				};
				window?: CustomHookTestWindow;
			}
			const win: CustomHookTestWindow = {
				__rea_events__: [],
				customCrypto: {
					signFrame(payloadView: Uint8Array, nonce: string) {
						return `sig:${Buffer.from(payloadView).toString("hex")}:${nonce}`;
					},
				},
			};
			win.window = win;
			const mockConsole = {
				log: () => undefined,
				warn: () => undefined,
				error: () => undefined,
				groupCollapsed: () => undefined,
				groupEnd: () => undefined,
			};
			const installer = new Function("window", "console", gen.details?.script ?? "");
			installer(win, mockConsole);

			const backing = new Uint8Array([0xff, 0x10, 0x20, 0x30, 0xff]);
			const sub = backing.subarray(1, 4);
			const out = win.customCrypto.signFrame(sub, "n1");
			expect(out).toBe("sig:102030:n1");

			expect(win.__rea_events__).toHaveLength(2);
			expect(win.__rea_events__[0].type).toBe("custom_call");
			expect(win.__rea_events__[0].args).toEqual(["102030", "n1"]);
			expect(win.__rea_events__[1].type).toBe("custom_result");
			expect(win.__rea_events__[1].id).toBe(win.__rea_events__[0].id);
			expect(win.__rea_events__[1].result).toBe("sig:102030:n1");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("bounds excessive algorithm/JWK keys and long array items, propagating incomplete status", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-bounds-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const gen = await tool.execute("gen_bounds", {
				action: "generate",
				preset: "crypto",
				max_payload_length: 64,
			});
			const env = createInstrumentedCryptoEnv(gen.details?.script ?? "");

			// 1) Algorithm object with >16 extra keys and an array containing an oversized string item
			const bloatedAlgo: Record<string, unknown> = {
				name: "SHA-256",
				tags: ["short", "x".repeat(200)],
			};
			for (let i = 0; i < 30; i++) {
				bloatedAlgo[`extra_${i}`] = i;
			}
			await env.subtle.digest(
				bloatedAlgo as unknown as Parameters<SubtleCrypto["digest"]>[0],
				new Uint8Array([1, 2, 3]),
			);

			const algoCall = env.events[0];
			const algoRes = env.events[1];
			expect(algoCall.algorithm).toBe("SHA-256");
			expect(algoCall.algorithmTruncated).toBe(true);
			expect(algoCall.omittedFields?.length).toBeGreaterThan(0);
			expect(algoCall.omittedFields?.length).toBeLessThanOrEqual(9);
			expect(algoCall.truncated).toBe(true);
			expect(algoCall.complete).toBe(false);
			expect(algoRes.truncated).toBe(true);
			expect(algoRes.complete).toBe(false);

			// 2) Public JWK with >24 extra keys and a long array item in custom_tags (no secret fields, yet still incomplete due to bounds)
			env.events.length = 0;
			const keyPair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
				"sign",
				"verify",
			]);
			const pubJwk = (await globalThis.crypto.subtle.exportKey("jwk", keyPair.publicKey)) as unknown as Record<
				string,
				unknown
			>;
			const bloatedJwk: webcrypto.JsonWebKey & Record<string, unknown> = {
				...pubJwk,
				custom_tags: ["M".repeat(200)],
			};
			for (let i = 0; i < 35; i++) {
				bloatedJwk[`meta_${i}`] = `v${i}`;
			}
			await env.subtle.importKey("jwk", bloatedJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);

			const jwkCall = env.events[0];
			const jwkRes = env.events[1];
			expect(jwkCall.truncatedFields).toContain("custom_tags");
			expect(jwkCall.omittedFields?.length).toBeLessThanOrEqual(9);
			expect(jwkCall.truncated).toBe(true);
			expect(jwkCall.complete).toBe(false);
			expect(jwkRes.truncated).toBe(true);
			expect(jwkRes.complete).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("generates distinct monotonic call IDs without calling or perturbing Math.random", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "js-hook-exec-rng-"));
		const origRandom = Math.random;
		let randomCalls = 0;
		try {
			const session = createTestSession(tempDir);
			const tool = new JsHookPresetTool(session);
			const cryptoGen = await tool.execute("gen_crypto_rng", { action: "generate", preset: "crypto" });
			const customGen = await tool.execute("gen_custom_rng", {
				action: "generate",
				preset: "custom",
				target: "window.customSigner.sign",
			});

			Math.random = () => {
				randomCalls += 1;
				return 0.424242;
			};

			const env = createInstrumentedCryptoEnv(cryptoGen.details?.script ?? "");
			env.win.window = env.win;
			env.win.customSigner = {
				sign: (msg: string) => `signed:${msg}`,
			};
			const customInstaller = new Function("window", "console", customGen.details?.script ?? "");
			customInstaller(env.win, {
				log: () => undefined,
				warn: () => undefined,
				error: () => undefined,
				groupCollapsed: () => undefined,
				groupEnd: () => undefined,
			});

			await env.subtle.digest("SHA-256", new Uint8Array([1]));
			await env.subtle.digest("SHA-256", new Uint8Array([2]));
			env.crypto.getRandomValues(new Uint8Array(4));
			env.crypto.getRandomValues(new Uint8Array(4));
			const customSigner = env.win.customSigner as { sign: (msg: string) => string };
			customSigner.sign("a");
			customSigner.sign("b");

			expect(randomCalls).toBe(0);

			const callEvents = env.events.filter(
				e => e.type === "crypto_call" || e.type === "crypto_random" || e.type === "custom_call",
			);
			expect(callEvents).toHaveLength(6);
			const ids = callEvents.map(e => e.id);
			expect(new Set(ids).size).toBe(6);
		} finally {
			Math.random = origRandom;
			await removeWithRetries(tempDir);
		}
	});
});
