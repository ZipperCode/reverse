import { afterAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { EvidenceStore } from "@reverse/coding-agent/evidence";
import { disposeAllVmContexts } from "@reverse/coding-agent/eval/js/context-manager";
import { ReverseRuntimeSessionStore } from "@reverse/coding-agent/reverse-runtime-session";
import {
	BrowserReverseSessionTool,
	ReverseDynamicEvidenceTool,
	clearActiveBrowserReverseSessionsForTest,
	type ToolSession,
} from "@reverse/coding-agent/tools";
import { createBrowserPrelude } from "@reverse/coding-agent/tools/browser";
import { PageConsoleCapture } from "@reverse/coding-agent/tools/browser/console-capture";
import {
	normalizeRequestInitiator,
	toPublicRecord,
	type NetworkRequestDetail,
	type NetworkRequestRecord,
} from "@reverse/coding-agent/tools/browser/network";
import { releaseAllTabs } from "@reverse/coding-agent/tools/browser/tab-supervisor";
import type { Page } from "puppeteer-core";
import { chromiumAvailable } from "./chromium-probe";

const CHROMIUM_AVAILABLE = await chromiumAvailable();

const CALLER_SCRIPT_LINES = [
	"// local reverse caller fixture",
	"globalThis.triggerApiFetch = async function triggerApiFetch() {",
	'  console.log("caller-console-observation");',
	'  return await fetch("/api?source=caller");',
	"};",
];
const CALLER_SCRIPT = `${CALLER_SCRIPT_LINES.join("\n")}\n`;
const CALLER_FETCH_LINE = 3;
const CALLER_FETCH_COLUMN = CALLER_SCRIPT_LINES[CALLER_FETCH_LINE]!.indexOf("fetch");
const server = Bun.serve({
	port: 0,
	fetch(request) {
		const { pathname } = new URL(request.url);
		if (pathname === "/api") {
			return Response.json({ source: "fixture" }, { headers: { "access-control-allow-origin": "*" } });
		}
		if (pathname === "/text") {
			return new Response("response body", {
				headers: { "content-type": "text/plain", "access-control-allow-origin": "*" },
			});
		}
		if (pathname === "/image") {
			return new Response(Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]), {
				headers: { "content-type": "image/png", "access-control-allow-origin": "*" },
			});
		}
		if (pathname === "/caller.js") {
			return new Response(CALLER_SCRIPT, {
				headers: { "content-type": "application/javascript", "access-control-allow-origin": "*" },
			});
		}
		if (pathname === "/caller-page") {
			return new Response('<!doctype html><title>caller fixture</title><script src="/caller.js"></script>', {
				headers: { "content-type": "text/html" },
			});
		}
		return new Response("<!doctype html><title>network fixture</title>", {
			headers: { "content-type": "text/html" },
		});
	},
});
const baseUrl = `http://127.0.0.1:${server.port}`;
const crossHostUrl = `http://localhost:${server.port}`;
const harPath = path.join(os.tmpdir(), `reverse-browser-network-${process.pid}-${Date.now()}.har`);

function createHost() {
	const session: ToolSession = {
		cwd: process.cwd(),
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({
			"browser.enabled": true,
			"browser.headless": true,
			"browser.cmux": false,
			"browser.tern": false,
			"tools.maxTimeout": 0,
		}),
	};
	const prelude = createBrowserPrelude(session);
	return (parameters: unknown) => prelude.invoke(parameters, { session, toolCallId: "browser-network-test" });
}

function valueOf(result: { details?: unknown }): unknown {
	return (result.details as { value?: unknown } | undefined)?.value;
}

/** Run code that leaves the page's CDP session unable to answer `Fetch.disable`. */
const STALL_FETCH_DISABLE = `const client = page._client();
const send = client.send.bind(client);
client.send = (method, ...args) => (method === "Fetch.disable" ? Promise.withResolvers().promise : send(method, ...args));`;

function isObjectRecord(value: unknown): value is Record<string, unknown> {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
afterAll(async () => {
	await releaseAllTabs({ kill: true });
	await disposeAllVmContexts();
	server.stop(true);
	await fs.rm(harPath, { force: true });
});

describe("browser network initiator normalization and console CDP setup", () => {
	test("retains undefined when initiator is missing, flattens max 4 async parents up to 10 frames, and deep-clones in toPublicRecord", () => {
		const baseRecord: NetworkRequestRecord = {
			id: "request-1",
			seq: 1,
			ts: 1_700_000_000_000,
			method: "GET",
			url: "http://127.0.0.1:8080/page",
			resourceType: "document",
			requestHeaders: { accept: "text/html" },
			sizes: { requestBody: 0 },
		};
		const missingCopy = toPublicRecord(baseRecord);
		expect(missingCopy.initiator).toBeUndefined();
		expect("initiator" in missingCopy).toBe(false);

		const otherInitiator = normalizeRequestInitiator({ type: "other" });
		expect(otherInitiator).toEqual({ type: "other" });
		expect(otherInitiator?.lineNumber).toBeUndefined();
		expect(otherInitiator?.columnNumber).toBeUndefined();
		expect(otherInitiator?.stack).toBeUndefined();

		// 构造 6 层异步父栈（第 5 层及以上应丢弃）
		const makeFrame = (label: string, line: number) => ({
			functionName: label,
			scriptId: `s-${label}`,
			url: "http://127.0.0.1:8080/caller.js",
			lineNumber: line,
			columnNumber: 0,
		});
		const deepAsync = normalizeRequestInitiator({
			type: "script",
			stack: {
				callFrames: [makeFrame("sync0", 0)],
				parent: {
					callFrames: [makeFrame("async1", 1)],
					parent: {
						callFrames: [makeFrame("async2", 2)],
						parent: {
							callFrames: [makeFrame("async3", 3)],
							parent: {
								callFrames: [makeFrame("async4", 4)],
								parent: {
									callFrames: [makeFrame("async5_dropped", 5)],
								},
							},
						},
					},
				},
			},
		});
		expect(deepAsync?.stack?.callFrames.map(f => f.functionName)).toEqual([
			"sync0",
			"async1",
			"async2",
			"async3",
			"async4",
		]);

		// 构造超过 10 帧的调用栈，验证总帧数上限为 10 且 toPublicRecord 完全深拷贝
		const twelveFrames = Array.from({ length: 8 }, (_, idx) => makeFrame(`sync_${idx}`, idx));
		const parentFrames = Array.from({ length: 5 }, (_, idx) => makeFrame(`parent_${idx}`, 100 + idx));
		const cappedInitiator = normalizeRequestInitiator({
			type: "script",
			stack: {
				callFrames: twelveFrames,
				parent: { callFrames: parentFrames },
			},
		});
		const stored: NetworkRequestRecord = {
			...baseRecord,
			initiator: cappedInitiator,
		};
		const publicCopy = toPublicRecord(stored);
		expect(publicCopy.initiator?.stack?.callFrames).toHaveLength(10);
		expect(publicCopy.initiator?.stack?.callFrames.map(f => f.functionName)).toEqual([
			"sync_0",
			"sync_1",
			"sync_2",
			"sync_3",
			"sync_4",
			"sync_5",
			"sync_6",
			"sync_7",
			"parent_0",
			"parent_1",
		]);

		publicCopy.initiator!.stack!.callFrames[0]!.functionName = "mutated";
		publicCopy.initiator!.stack!.callFrames.pop();
		expect(stored.initiator?.stack?.callFrames).toHaveLength(10);
		expect(stored.initiator?.stack?.callFrames[0]?.functionName).toBe("sync_0");
	});

	test("PageConsoleCapture enables Debugger then asyncDepth 4 without pause and preserves basic capture on failure", async () => {
		const sentCommands: Array<{ method: string; params?: unknown }> = [];
		const cdpListeners = new Map<string, (event: unknown) => void>();

		const buildFakePage = (failDebugger: boolean): Page => {
			const fakeSession = {
				on(event: string, handler: (payload: unknown) => void) {
					cdpListeners.set(event, handler);
				},
				off(event: string) {
					cdpListeners.delete(event);
				},
				async send(method: string, params?: unknown) {
					sentCommands.push({ method, params });
					if (failDebugger && method === "Debugger.enable") {
						throw new Error("Debugger domain restricted by policy");
					}
					return {};
				},
				async detach() {},
			};
			const fakePage = {
				on() {},
				off() {},
				url: () => "http://127.0.0.1:8080/",
				async createCDPSession() {
					return fakeSession;
				},
			};
			// Minimal Page test double for unit-testing PageConsoleCapture.install
			return fakePage as unknown as Page;
		};

		const captureOk = new PageConsoleCapture();
		await captureOk.install(buildFakePage(false));
		const debuggerIdx = sentCommands.findIndex(c => c.method === "Debugger.enable");
		const asyncIdx = sentCommands.findIndex(c => c.method === "Debugger.setAsyncCallStackDepth");
		expect(debuggerIdx).toBeGreaterThanOrEqual(0);
		expect(asyncIdx).toBeGreaterThan(debuggerIdx);
		expect(sentCommands[asyncIdx]?.params).toEqual({ maxDepth: 4 });
		expect(sentCommands.some(c => c.method.includes("pause") || c.method.includes("Breakpoint"))).toBe(false);
		expect(captureOk.callStackAvailable).toBe(true);
		expect(captureOk.callStackDiagnostic).toBeUndefined();
		await captureOk.detach();

		sentCommands.length = 0;
		cdpListeners.clear();
		const captureFallback = new PageConsoleCapture();
		await captureFallback.install(buildFakePage(true));
		expect(captureFallback.callStackAvailable).toBe(false);
		expect(captureFallback.callStackDiagnostic).toContain("CDP call stack capture unavailable");

		// 基础采集依然正常工作
		const consoleListener = cdpListeners.get("Runtime.consoleAPICalled");
		expect(consoleListener).toBeDefined();
		consoleListener!({
			type: "log",
			args: [{ type: "string", value: "basic-capture-alive" }],
			executionContextId: 1,
			timestamp: Date.now(),
		});
		const captured = await captureFallback.console();
		expect(captured.callStackAvailable).toBe(false);
		expect(captured.callStackDiagnostic).toContain("Debugger domain restricted by policy");
		expect(
			captured.entries.some(e => e.level === "warn" && e.text.includes("CDP call stack capture unavailable")),
		).toBe(true);
		expect(captured.entries.some(e => e.text === "basic-capture-alive")).toBe(true);
		await captureFallback.detach();
	});
});
describe.skipIf(!CHROMIUM_AVAILABLE)("browser network helpers", () => {
	test("persists cooperative routes across runs and removes them with unroute", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "routes", url: `${baseUrl}/` });
		await invoke({
			action: "call",
			name: "routes",
			chain: [{ method: "route", args: ["**/api", { body: { source: "route" } }] }],
		});

		const first = valueOf(
			await invoke({
				action: "run",
				name: "routes",
				code: `return await tab.evaluate(async url => await (await fetch(url)).json(), ${JSON.stringify(`${baseUrl}/api`)})`,
			}),
		);
		expect(first).toEqual({ source: "route" });

		const second = valueOf(
			await invoke({
				action: "run",
				name: "routes",
				code: `let seen = 0;
await page.setRequestInterception(true);
page.on("request", async request => {
  if (request.url().endsWith("/api")) seen += 1;
  if (!request.isInterceptResolutionHandled()) await request.continue({}, 5);
});
const body = await tab.evaluate(async url => await (await fetch(url)).json(), ${JSON.stringify(`${baseUrl}/api`)});
return { body, seen };`,
			}),
		);
		expect(second).toEqual({ body: { source: "route" }, seen: 1 });

		await invoke({ action: "call", name: "routes", chain: [{ method: "unroute", args: ["**/api"] }] });
		const original = valueOf(
			await invoke({
				action: "run",
				name: "routes",
				code: `return await tab.evaluate(async url => await (await fetch(url)).json(), ${JSON.stringify(`${baseUrl}/api`)})`,
			}),
		);
		expect(original).toEqual({ source: "fixture" });
	});

	test("limits abort routes by resource type", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "resource-route", url: `${baseUrl}/` });
		await invoke({
			action: "call",
			name: "resource-route",
			chain: [{ method: "route", args: ["**/image", { abort: true, resourceType: "image" }] }],
		});
		const result = valueOf(
			await invoke({
				action: "run",
				name: "resource-route",
				code: `return await tab.evaluate(async url => {
  const fetched = await fetch(url).then(response => response.status);
  const image = await new Promise(resolve => {
    const element = new Image();
    element.onload = () => resolve("loaded");
    element.onerror = () => resolve("blocked");
    element.src = url;
  });
  return { fetched, image };
}, ${JSON.stringify(`${baseUrl}/image`)})`,
			}),
		);
		expect(result).toEqual({ fetched: 200, image: "blocked" });
	});

	test("filters request logs, loads response bodies, and writes matching HAR entries", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "log", url: `${baseUrl}/` });
		await invoke({ action: "call", name: "log", chain: [{ method: "clearRequests", args: [] }] });
		await invoke({
			action: "run",
			name: "log",
			code: `await tab.evaluate(async urls => { for (const url of urls) await fetch(url); }, ${JSON.stringify([
				`${baseUrl}/text`,
				`${baseUrl}/missing`,
			])});`,
		});
		const successful = valueOf(
			await invoke({
				action: "call",
				name: "log",
				chain: [{ method: "requests", args: [{ status: "2xx" }] }],
			}),
		) as Array<{ id: string; url: string; status: number }>;
		expect(successful.some(request => request.url.endsWith("/text") && request.status === 200)).toBe(true);
		const textRequest = successful.find(request => request.url.endsWith("/text"));
		expect(textRequest).toBeDefined();
		const detail = valueOf(
			await invoke({
				action: "call",
				name: "log",
				chain: [{ method: "request", args: [textRequest!.id] }],
			}),
		) as { body?: unknown };
		expect(detail.body).toBe("response body");

		await invoke({ action: "call", name: "log", chain: [{ method: "harStart", args: [{ content: "text" }] }] });
		await invoke({
			action: "run",
			name: "log",
			code: `await tab.evaluate(async urls => { for (const url of urls) await fetch(url); }, ${JSON.stringify([
				`${baseUrl}/text?har=1`,
				`${baseUrl}/api?har=2`,
			])});`,
		});
		const stoppedPath = valueOf(
			await invoke({
				action: "call",
				name: "log",
				chain: [{ method: "harStop", args: [{ path: harPath }] }],
			}),
		);
		expect(stoppedPath).toBe(harPath);
		const har = JSON.parse(await Bun.file(harPath).text()) as { log: { entries: unknown[] } };
		expect(har.log.entries).toHaveLength(2);
	});

	test("enforces allowed_domains and logs blocked cross-host fetches", async () => {
		const invoke = createHost();
		await invoke({
			action: "open",
			name: "allowlist",
			url: `${baseUrl}/`,
			allowed_domains: ["127.0.0.1"],
		});
		const result = valueOf(
			await invoke({
				action: "run",
				name: "allowlist",
				code: `return await tab.evaluate(async urls => {
  const allowed = await fetch(urls.allowed).then(response => response.text());
  const blocked = await fetch(urls.blocked).then(() => false, () => true);
  return { allowed, blocked };
}, ${JSON.stringify({ allowed: `${baseUrl}/text`, blocked: `${crossHostUrl}/text` })})`,
			}),
		);
		expect(result).toEqual({ allowed: "response body", blocked: true });
		expect(
			valueOf(
				await invoke({
					action: "call",
					name: "allowlist",
					chain: [{ method: "allowedDomains", args: [] }],
				}),
			),
		).toEqual(["127.0.0.1"]);
		const blocked = valueOf(
			await invoke({
				action: "call",
				name: "allowlist",
				chain: [{ method: "requests", args: [{ filter: "localhost" }] }],
			}),
		) as Array<{ failureText?: string }>;
		expect(blocked.some(request => request.failureText === "blocked by allowed_domains")).toBe(true);
	});

	test("keeps a run's result when interception was never touched and cannot be reset", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "untouched-interception", url: `${baseUrl}/` });
		const result = valueOf(
			await invoke({
				action: "run",
				name: "untouched-interception",
				code: `${STALL_FETCH_DISABLE}
return "done";`,
			}),
		);
		expect(result).toBe("done");
	});

	test("keeps a completed run's result when its interception cannot be reset", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "stuck-interception", url: `${baseUrl}/` });
		const completed = await invoke({
			action: "run",
			name: "stuck-interception",
			code: `await page.setRequestInterception(true);
${STALL_FETCH_DISABLE}
return "done";`,
		});
		expect(valueOf(completed)).toBe("done");
		expect(completed.content).toContainEqual({
			type: "text",
			text: "Browser request interception could not be reset after this run; the tab was reattached to a new worker. Tab state set since it was opened was reset (tab.route routes, emulation and user agent, init scripts, element ids, the request log, HAR recording, run globals), any open dialog was dismissed, and any page still loading was stopped.",
		});
		const next = valueOf(
			await invoke({
				action: "run",
				name: "stuck-interception",
				code: `return await tab.evaluate(async url => await (await fetch(url)).json(), ${JSON.stringify(`${baseUrl}/api`)})`,
			}),
		);
		expect(next).toEqual({ source: "fixture" });
	});

	test("captures exact 0-based initiator callFrames from /caller.js without synthetic lines", async () => {
		const invoke = createHost();
		await invoke({ action: "open", name: "caller-initiator", url: `${baseUrl}/caller-page` });
		try {
			const initialRequests = valueOf(
				await invoke({
					action: "call",
					name: "caller-initiator",
					chain: [{ method: "requests", args: [] }],
				}),
			) as NetworkRequestRecord[];
			const navReq = initialRequests.find(r => r.url === `${baseUrl}/caller-page`);
			expect(navReq).toBeDefined();
			expect(navReq?.initiator?.lineNumber).toBeUndefined();
			expect(navReq?.initiator?.columnNumber).toBeUndefined();
			expect(navReq?.initiator?.stack).toBeUndefined();

			const fetched = valueOf(
				await invoke({
					action: "run",
					name: "caller-initiator",
					code: "return await tab.evaluate(async () => await (await globalThis.triggerApiFetch()).json());",
				}),
			);
			expect(fetched).toEqual({ source: "fixture" });

			const apiRequests = valueOf(
				await invoke({
					action: "call",
					name: "caller-initiator",
					chain: [{ method: "requests", args: [{ filter: "/api?source=caller" }] }],
				}),
			) as NetworkRequestRecord[];
			expect(apiRequests).toHaveLength(1);
			const apiReq = apiRequests[0]!;
			expect(apiReq.initiator?.type).toBe("script");
			const frames = apiReq.initiator?.stack?.callFrames ?? [];
			expect(frames.length).toBeGreaterThanOrEqual(1);
			expect(frames.length).toBeLessThanOrEqual(10);
			expect(frames[0]).toMatchObject({
				functionName: "triggerApiFetch",
				url: `${baseUrl}/caller.js`,
				lineNumber: CALLER_FETCH_LINE,
				columnNumber: CALLER_FETCH_COLUMN,
			});
			expect(frames[0]?.scriptId.length).toBeGreaterThan(0);

			const detail = valueOf(
				await invoke({
					action: "call",
					name: "caller-initiator",
					chain: [{ method: "request", args: [apiReq.id] }],
				}),
			) as NetworkRequestDetail;
			expect(detail.initiator).toEqual(apiReq.initiator);
		} finally {
			await invoke({ action: "close", name: "caller-initiator" }).catch(() => undefined);
		}
	});

	test("threads real browser_reverse_session capture through reverse_dynamic_evidence ingest and verify", async () => {
		const tempCwd = await fs.mkdtemp(path.join(os.tmpdir(), "rev-brs-e2e-cwd-"));
		const tempState = await fs.mkdtemp(path.join(os.tmpdir(), "rev-brs-e2e-state-"));
		const e2eSession: ToolSession = {
			cwd: tempCwd,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated({
				"browser.enabled": true,
				"browser.headless": true,
				"browser.cmux": false,
				"browser.tern": false,
				"browser.relay": false,
				"tools.maxTimeout": 0,
			}),
		};
		const browserSessionTool = new BrowserReverseSessionTool(e2eSession, undefined, tempState);
		const dynamicEvidenceTool = new ReverseDynamicEvidenceTool(e2eSession, { stateRoot: tempState });
		const evidenceStore = new EvidenceStore({ repositoryRoot: tempCwd, stateRoot: tempState });
		const runtimeStore = ReverseRuntimeSessionStore.forSession(tempCwd, tempState);
		const prelude = createBrowserPrelude(e2eSession);
		const targetUrl = `${baseUrl}/caller-page`;
		const subject = "triggerApiFetch";

		try {
			await browserSessionTool.execute("e2e-open", {
				action: "open",
				session_id: "brs-live-caller",
				tab_name: "brs-live-caller-tab",
				url: targetUrl,
				preset: "console",
			});

			await prelude.invoke(
				{
					action: "run",
					name: "brs-live-caller-tab",
					code: "return await tab.evaluate(async () => await (await globalThis.triggerApiFetch()).json());",
				},
				{ session: e2eSession, toolCallId: "e2e-trigger" },
			);

			const cap1 = await browserSessionTool.execute("e2e-cap-1", {
				action: "capture",
				session_id: "brs-live-caller",
				tab_name: "brs-live-caller-tab",
			});
			expect((cap1.details?.requests ?? []).length).toBeGreaterThanOrEqual(1);
			const cap1Events = cap1.details?.events ?? [];
			const consoleEv = cap1Events.find(
				e => e.type === "console" && String(e.text ?? "").includes("caller-console-observation"),
			);
			expect(consoleEv).toBeDefined();
			const apiReqEv = cap1Events.find(e => e.type === "request" && e.url === `${baseUrl}/api?source=caller`);
			expect(apiReqEv).toBeDefined();
			expect(apiReqEv?.id?.startsWith("network:request-")).toBe(true);
			expect(apiReqEv?.requestId?.startsWith("request-")).toBe(true);
			expect(apiReqEv?.initiator).toMatchObject({
				type: "script",
				stack: {
					callFrames: expect.arrayContaining([
						expect.objectContaining({
							functionName: "triggerApiFetch",
							url: `${baseUrl}/caller.js`,
							lineNumber: CALLER_FETCH_LINE,
							columnNumber: CALLER_FETCH_COLUMN,
						}),
					]),
				},
			});

			// 重复 capture 验证已捕获请求与 console 事件 seq 幂等且无重复 seq
			const cap2 = await browserSessionTool.execute("e2e-cap-2", {
				action: "capture",
				session_id: "brs-live-caller",
				tab_name: "brs-live-caller-tab",
			});
			const cap2Events = cap2.details?.events ?? [];
			const seqs2 = cap2Events.map(e => e.seq);
			expect(new Set(seqs2).size).toBe(seqs2.length);
			const cap2ApiReq = cap2Events.find(e => e.id === apiReqEv?.id);
			expect(cap2ApiReq?.seq).toBe(apiReqEv?.seq);
			const cap2Console = cap2Events.find(
				e => e.type === "console" && String(e.text ?? "").includes("caller-console-observation"),
			);
			expect(cap2Console?.seq).toBe(consoleEv?.seq);
			const cap2ConsoleMatches = cap2Events.filter(
				e => e.type === "console" && String(e.text ?? "").includes("caller-console-observation"),
			);
			expect(cap2ConsoleMatches).toHaveLength(1);
			const cap2ApiMatches = cap2Events.filter(e => e.id === apiReqEv?.id);
			expect(cap2ApiMatches).toHaveLength(1);
			// 验证运行时会话存储已写入 0 基 callsite 与 initiator
			const runtimeRecord = await runtimeStore.get("brs-live-caller");
			expect(runtimeRecord).not.toBeNull();
			const recentEvents = Array.isArray(runtimeRecord?.metadata?.recent_events)
				? runtimeRecord.metadata.recent_events
				: [];
			const persistedApiEvent = recentEvents.find(ev => isObjectRecord(ev) && ev.id === apiReqEv?.id);
			expect(persistedApiEvent).toMatchObject({
				kind: "network",
				channel: "request",
				metadata: {
					requestId: apiReqEv?.requestId,
					callsite: {
						url: `${baseUrl}/caller.js`,
						lineNumber: CALLER_FETCH_LINE,
						columnNumber: CALLER_FETCH_COLUMN,
					},
					initiator: {
						type: "script",
						stack: {
							callFrames: expect.arrayContaining([
								expect.objectContaining({
									functionName: "triggerApiFetch",
									url: `${baseUrl}/caller.js`,
									lineNumber: CALLER_FETCH_LINE,
									columnNumber: CALLER_FETCH_COLUMN,
								}),
							]),
						},
					},
				},
			});

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				target: targetUrl,
				subject,
				claim: "triggerApiFetch initiates GET /api?source=caller",
				verificationPlan: "Capture browser CDP request initiator and verify callsite",
			});

			const ingested = await dynamicEvidenceTool.execute("e2e-ingest", {
				action: "ingest",
				session_id: "brs-live-caller",
				source: "browser",
				target: targetUrl,
				subject,
				limit: 50,
			});
			const facts = ingested.details.facts ?? [];
			const consoleFact = facts.find(
				f => f.tags?.includes("console") && f.content.includes("caller-console-observation"),
			);
			expect(consoleFact).toBeDefined();
			expect(consoleFact?.context?.assurance).toBeUndefined();

			const requestFact = facts.find(f => f.tags?.includes("request") && f.content.includes("/api?source=caller"));
			expect(requestFact).toBeDefined();
			expect(requestFact?.context?.assurance).toBe("dynamic_call_observation");
			expect(requestFact?.content).toContain(
				`Callsite: ${baseUrl}/caller.js:${CALLER_FETCH_LINE + 1}:${CALLER_FETCH_COLUMN + 1}`,
			);
			expect(requestFact?.content).toContain(`Request ID: ${apiReqEv?.requestId}`);

			// 普通 console 事实不能通过动态验证
			await expect(
				dynamicEvidenceTool.execute("e2e-verify-console", {
					action: "verify",
					session_id: "brs-live-caller",
					hypothesis_id: hyp.id,
					fact_ids: [consoleFact!.id],
					subject,
					conclusion: "Console log proves endpoint invocation",
					method: "Browser console hook",
					command: "await globalThis.triggerApiFetch()",
					result: "Logged caller-console-observation",
				}),
			).rejects.toThrow(/Cannot verify hypothesis/);

			const verified = await dynamicEvidenceTool.execute("e2e-verify-request", {
				action: "verify",
				session_id: "brs-live-caller",
				hypothesis_id: hyp.id,
				fact_ids: [requestFact!.id],
				subject,
				conclusion: "triggerApiFetch initiates GET /api?source=caller",
				method: "CDP Network.Initiator stack capture",
				command: "await globalThis.triggerApiFetch()",
				result: "Observed GET /api?source=caller initiated from triggerApiFetch",
			});
			expect(verified.details.conclusion?.status).toBe("verified");
			expect(verified.details.conclusion?.context?.assurance).toBe("dynamic_call_observation");
			expect(verified.details.conclusion?.reproducibility).toBe("not specified");
		} finally {
			await browserSessionTool
				.execute("e2e-close", {
					action: "close",
					session_id: "brs-live-caller",
					tab_name: "brs-live-caller-tab",
				})
				.catch(() => undefined);
			clearActiveBrowserReverseSessionsForTest();
			await fs.rm(tempCwd, { recursive: true, force: true });
			await fs.rm(tempState, { recursive: true, force: true });
		}
	});
});
