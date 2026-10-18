import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	BrowserReverseSessionTool,
	type ToolSession,
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

function createMockBrowserRunner(
	initialTabs: Record<string, { state: "alive" | "dead"; url?: string; title?: string }> = {},
) {
	const tabs = new Map<string, { state: "alive" | "dead"; url?: string; title?: string }>(
		Object.entries(initialTabs),
	);
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
					returnValue: { initScriptId: `init_${name}_999`, evaluated: true },
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

describe("browser_reverse_session registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("browser_reverse_session");
		expect(normalizeToolName("browser_reverse_session")).toBe("browser_reverse_session");
		expect(normalizeToolName("browser_reverse")).toBe("browser_reverse_session");
		expect(normalizeToolName("browser_hook")).toBe("browser_reverse_session");
		expect(normalizeToolName("browser_session")).toBe("browser_reverse_session");
	});

	it("creates tool instance with discoverable loadMode and approval policy", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["browser_reverse_session"]);
			const tool = tools.find(t => t.name === "browser_reverse_session");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("browser_reverse_session");
			expect(tool?.loadMode).toBe("discoverable");

			// Check dynamic approval decisions
			const approvalFn = tool?.approval as (args: unknown) => string;
			expect(approvalFn({ action: "status" })).toBe("read");
			expect(approvalFn({ action: "events" })).toBe("read");
			expect(approvalFn({ action: "capture" })).toBe("read");
			expect(approvalFn({ action: "export_evidence" })).toBe("read");
			expect(approvalFn({ action: "open" })).toBe("write");
			expect(approvalFn({ action: "inject" })).toBe("write");
			expect(approvalFn({ action: "close" })).toBe("write");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("browser_reverse_session action: open", () => {
	it("rejects open when tab is not alive and url is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-open-err-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new BrowserReverseSessionTool(session, runner);

			await expect(
				tool.execute("call_open_err", {
					action: "open",
					tab_name: "new_tab",
				}),
			).rejects.toThrow("url is required for action 'open'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("opens a browser tab and auto-injects hook preset", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-open-ok-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new BrowserReverseSessionTool(session, runner);

			const result = await tool.execute("call_open_ok", {
				action: "open",
				tab_name: "target_site",
				url: "https://crypto.example.com",
				preset: "crypto",
			});

			expect(result.details?.action).toBe("open");
			expect(result.details?.status).toBe("active");
			expect(result.details?.tab_name).toBe("target_site");
			expect(result.details?.url).toBe("https://crypto.example.com");
			expect(result.details?.injected_hooks).toHaveLength(1);
			expect(result.details?.injected_hooks?.[0].preset).toBe("crypto");
			expect(result.details?.injected_hooks?.[0].initScriptId).toBe("init_target_site_999");
			expect(result.details?.injected_hooks?.[0].evaluated).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("browser_reverse_session action: inject", () => {
	it("strictly fails without claiming injection when tab is dead", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-inj-dead-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({});
			const tool = new BrowserReverseSessionTool(session, runner);

			await expect(
				tool.execute("call_inj_dead", {
					action: "inject",
					tab_name: "dead_tab",
					preset: "fetch",
				}),
			).rejects.toThrow("Browser tab \"dead_tab\" is not open or alive");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("injects preset and tracks active hooks on live tab", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-inj-live-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://spa.test/app" },
			});
			const tool = new BrowserReverseSessionTool(session, runner);

			const result = await tool.execute("call_inj_live", {
				action: "inject",
				tab_name: "main",
				preset: "websocket",
			});

			expect(result.details?.action).toBe("inject");
			expect(result.details?.preset).toBe("websocket");
			expect(result.details?.init_script_id).toBe("init_main_999");
			expect(result.details?.evaluated).toBe(true);
			expect(result.details?.injected_hooks?.some(h => h.preset === "websocket")).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("validates custom target selector for custom preset", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-inj-custom-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://spa.test/app" },
			});
			const tool = new BrowserReverseSessionTool(session, runner);

			await expect(
				tool.execute("call_inj_invalid_custom", {
					action: "inject",
					tab_name: "main",
					preset: "custom",
					target: "window.eval('malicious')",
				}),
			).rejects.toThrow("Invalid target selector");

			const validRes = await tool.execute("call_inj_valid_custom", {
				action: "inject",
				tab_name: "main",
				preset: "custom",
				target: "window.appService.decryptData",
			});
			expect(validRes.details?.preset).toBe("custom");
			expect(validRes.details?.target).toBe("window.appService.decryptData");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("browser_reverse_session action: capture, events, export_evidence, status, close", () => {
	it("captures events, pages event stream, and exports structured evidence", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-full-cycle-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				work: { state: "alive", url: "https://finance.test/exchange" },
			});

			runner.inTabEvents.set("work", [
				{
					timestamp: Date.now(),
					type: "websocket_send",
					id: "ws_1",
					url: "wss://finance.test/feed",
					data: '{"sub":"trades"}',
				},
				{
					timestamp: Date.now(),
					type: "crypto_call",
					id: "cr_1",
					method: "sign",
					dataHex: "01020304",
				},
			]);
			runner.inTabConsole.set("work", ["Connected to WebSocket"]);
			runner.inTabRequests.set("work", [{ url: "https://finance.test/api/auth" }]);

			const tool = new BrowserReverseSessionTool(session, runner);

			// 1. Capture
			const capRes = await tool.execute("cap_1", {
				action: "capture",
				tab_name: "work",
			});
			expect(capRes.details?.events).toHaveLength(2);
			expect(capRes.details?.consoleLogs).toHaveLength(1);
			expect(capRes.details?.requests).toHaveLength(1);

			// 2. Events query
			const evRes = await tool.execute("ev_1", {
				action: "events",
				tab_name: "work",
				limit: 1,
			});
			expect(evRes.details?.events).toHaveLength(1);

			// 3. Export evidence
			const expRes = await tool.execute("exp_1", {
				action: "export_evidence",
				tab_name: "work",
				tags: ["crypto", "ws"],
			});
			expect(expRes.details?.evidence).toBeDefined();
			expect(expRes.details?.evidence).toHaveLength(2);
			expect(expRes.details?.evidence?.[0].locator).toBe("tab:work:websocket_send:ws_1");
			expect(expRes.details?.evidence?.[0].tags).toContain("crypto");
			expect(expRes.details?.evidence?.[0].tags).toContain("websocket_send");

			// 4. Status
			const statusRes = await tool.execute("st_1", {
				action: "status",
				tab_name: "work",
			});
			expect(statusRes.details?.status).toBe("active");
			expect(statusRes.details?.eventCount).toBe(2);

			// 5. Close
			const closeRes = await tool.execute("cl_1", {
				action: "close",
				tab_name: "work",
			});
			expect(closeRes.details?.status).toBe("closed");
			expect(runner.tabs.get("work")?.state).toBe("dead");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
describe("browser_reverse_session regression: structured send/console/ws/crypto events, query, and persistence", () => {
	it("predictably classifies and queries structured send, console, ws, and crypto events", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-events-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-state-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				app: { state: "alive", url: "https://secure.bank.test/dashboard" },
			});

			runner.inTabEvents.set("app", [
				{
					timestamp: 1000,
					type: "websocket_send",
					id: "ws_send_1",
					url: "wss://secure.bank.test/stream",
					data: '{"action":"subscribe","channel":"transactions"}',
				},
				{
					timestamp: 2000,
					type: "console",
					method: "warn",
					text: "TLS certificate pinned successfully",
				},
				{
					timestamp: 3000,
					type: "websocket_message",
					id: "ws_msg_1",
					url: "wss://secure.bank.test/stream",
					data: '{"status":"ok","session":"sess_xyz"}',
				},
				{
					timestamp: 4000,
					type: "crypto_call",
					id: "cr_sign_1",
					method: "sign",
					algorithm: { name: "ECDSA", hash: "SHA-256" },
					dataHex: "deadbeefcafebabe",
				},
				{
					timestamp: 5000,
					type: "crypto_result",
					id: "cr_sign_1",
					method: "sign",
					resultHex: "0102030405060708",
				},
				{
					timestamp: 6000,
					type: "xhr_send",
					id: "xhr_1",
					method: "POST",
					url: "https://secure.bank.test/api/transfer",
					data: '{"recipient":"alice","amount":500}',
				},
			]);

			const tool = new BrowserReverseSessionTool(session, runner, stateDir);

			// 1. Capture events
			const capRes = await tool.execute("c1", {
				action: "capture",
				tab_name: "app",
			});
			expect(capRes.details?.events).toHaveLength(6);
			expect(capRes.details?.eventCount).toBe(6);

			// 2. Query 'ws' events via filter
			const wsEvents = await tool.execute("q_ws", {
				action: "events",
				tab_name: "app",
				filter: "ws",
			});
			expect(wsEvents.details?.events).toHaveLength(2);
			expect(wsEvents.details?.events?.every(e => e.type.startsWith("websocket_"))).toBe(true);

			// 3. Query 'crypto' events via filter
			const cryptoEvents = await tool.execute("q_cr", {
				action: "events",
				tab_name: "app",
				filter: "crypto",
			});
			expect(cryptoEvents.details?.events).toHaveLength(2);
			expect(cryptoEvents.details?.events?.every(e => e.type.startsWith("crypto_"))).toBe(true);

			// 4. Query 'send' events via filter (matches websocket_send and xhr_send)
			const sendEvents = await tool.execute("q_send", {
				action: "events",
				tab_name: "app",
				filter: "send",
			});
			expect(sendEvents.details?.events).toHaveLength(2);
			const sendTypes = sendEvents.details?.events?.map(e => e.type) ?? [];
			expect(sendTypes).toContain("websocket_send");
			expect(sendTypes).toContain("xhr_send");

			// 5. Query 'console' events via filter
			const consoleEvents = await tool.execute("q_cons", {
				action: "events",
				tab_name: "app",
				filter: "console",
			});
			expect(consoleEvents.details?.events).toHaveLength(1);
			expect(consoleEvents.details?.events?.[0].type).toBe("console");

			// 6. Export evidence specifically for crypto
			const expCrypto = await tool.execute("exp_cr", {
				action: "export_evidence",
				tab_name: "app",
				filter: "crypto",
				tags: ["crypto", "signing"],
			});
			expect(expCrypto.details?.evidence).toHaveLength(2);
			expect(expCrypto.details?.evidence?.[0].locator).toBe("tab:app:crypto_call:cr_sign_1");
			expect(expCrypto.details?.evidence?.[0].tags).toContain("crypto");
			expect(expCrypto.details?.evidence?.[0].tags).toContain("signing");

			// 7. Export evidence specifically for ws
			const expWs = await tool.execute("exp_ws", {
				action: "export_evidence",
				tab_name: "app",
				filter: "ws",
			});
			expect(expWs.details?.evidence).toHaveLength(2);
			expect(expWs.details?.evidence?.[0].locator).toBe("tab:app:websocket_send:ws_send_1");

			// 8. Clear only crypto events via filter
			const clearCr = await tool.execute("clr_cr", {
				action: "events",
				tab_name: "app",
				filter: "crypto",
				clear: true,
			});
			expect(clearCr.details?.eventCount).toBe(2);
			expect(clearCr.details?.totalEvents).toBe(4);

			// Verify remaining events in buffer
			const remainEvents = await tool.execute("q_remain", {
				action: "events",
				tab_name: "app",
			});
			expect(remainEvents.details?.totalEvents).toBe(4);
			expect(remainEvents.details?.events?.some(e => e.type.startsWith("crypto_"))).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
			await removeWithRetries(stateDir);
		}
	});

	it("deduplicates captured events across successive captures without clearing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-dedup-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-dedup-state-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				main: { state: "alive", url: "https://spa.test" },
			});

			runner.inTabEvents.set("main", [
				{ timestamp: 100, type: "websocket_open", id: "ws_0", url: "wss://spa.test/socket" },
			]);

			const tool = new BrowserReverseSessionTool(session, runner, stateDir);

			// First capture
			const cap1 = await tool.execute("c1", { action: "capture", tab_name: "main" });
			expect(cap1.details?.events).toHaveLength(1);
			expect(cap1.details?.eventCount).toBe(1);

			// Add a second event to tab
			runner.inTabEvents.set("main", [
				{ timestamp: 100, type: "websocket_open", id: "ws_0", url: "wss://spa.test/socket" },
				{ timestamp: 200, type: "websocket_send", id: "ws_1", url: "wss://spa.test/socket", data: "ping" },
			]);

			// Second capture without clear — first event should NOT be duplicated in buffer
			const cap2 = await tool.execute("c2", { action: "capture", tab_name: "main" });
			expect(cap2.details?.events).toHaveLength(2);
			expect(cap2.details?.eventCount).toBe(2);

			const evs = await tool.execute("evs", { action: "events", tab_name: "main" });
			expect(evs.details?.totalEvents).toBe(2);
			expect(evs.details?.events).toHaveLength(2);
		} finally {
			await removeWithRetries(tempDir);
			await removeWithRetries(stateDir);
		}
	});

	it("persists browser session state and events across tool instances", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-persist-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "brs-regress-persist-state-"));
		try {
			const session = createTestSession(tempDir);
			const runner = createMockBrowserRunner({
				persistTab: { state: "alive", url: "https://persistent.app.test" },
			});

			runner.inTabEvents.set("persistTab", [
				{ timestamp: 1234, type: "crypto_call", id: "persist_cr_1", method: "encrypt" },
			]);

			// Tool instance 1
			const tool1 = new BrowserReverseSessionTool(session, runner, stateDir);
			await tool1.execute("open_1", {
				action: "open",
				tab_name: "persistTab",
				url: "https://persistent.app.test",
				session_id: "persisted-browser-sess",
			});
			await tool1.execute("cap_1", {
				action: "capture",
				tab_name: "persistTab",
				session_id: "persisted-browser-sess",
			});

			// Now create completely new Tool instance 2 simulating a subsequent turn
			const tool2 = new BrowserReverseSessionTool(session, runner, stateDir);
			const statusRes = await tool2.execute("st_2", {
				action: "status",
				session_id: "persisted-browser-sess",
				tab_name: "persistTab",
			});

			expect(statusRes.details?.status).toBe("active");
			expect(statusRes.details?.session_id).toBe("persisted-browser-sess");
			expect(statusRes.details?.eventCount).toBe(1);

			const eventsRes = await tool2.execute("ev_2", {
				action: "events",
				session_id: "persisted-browser-sess",
				tab_name: "persistTab",
				filter: "crypto",
			});
			expect(eventsRes.details?.events).toHaveLength(1);
			expect(eventsRes.details?.events?.[0].id).toBe("persist_cr_1");
		} finally {
			await removeWithRetries(tempDir);
			await removeWithRetries(stateDir);
		}
	});
});
