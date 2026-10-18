import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { prompt, isEnoent, getBrowserSessionsProjectDir } from "@rva/utils";
import { replaceFileAtomically } from "../utils/atomic-file";
import { encodeProjectKey } from "./frida-session";
import { ReverseRuntimeSessionStore } from "../reverse-runtime-session/store";
import type { RuntimeSessionRecord } from "../reverse-runtime-session/contracts";
import { normalizeBrowserEvent, type UniversalDynamicEvent } from "../reverse-runtime-session/dynamic-events";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";
import browserReverseSessionDescription from "../prompts/tools/browser-reverse-session.md" with { type: "text" };
import {
	HOOK_PRESETS,
	HOOK_TAMPER_MODES,
	type HookPresetKind,
	type HookTamperMode,
	type BrowserReverseEvent,
	type BrowserReverseRunner,
	type BrowserTabSummary,
	createDefaultBrowserReverseRunner,
	validateCustomTargetSelector,
	JsHookPresetTool,
} from "./js-hook-preset";

export const BROWSER_REVERSE_ACTIONS = [
	"open",
	"inject",
	"capture",
	"events",
	"export_evidence",
	"status",
	"close",
] as const;

export type BrowserReverseAction = (typeof BROWSER_REVERSE_ACTIONS)[number];

const browserReverseSessionSchema = type({
	action: type.enumerated("open", "inject", "capture", "events", "export_evidence", "status", "close"),
	"session_id?": type("string").describe("Identifier for the reverse runtime session (auto-generated if omitted)"),
	"tab_name?": type("string").describe("Browser tab identifier (default 'main')"),
	"url?": type("string").describe("Target URL to open (required for action 'open')"),
	"preset?": type.enumerated(...HOOK_PRESETS).describe(
		"Hook preset to inject: fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, custom",
	),
	"target?": type("string").describe("Allowlisted target selector for custom preset (e.g. 'window.api.login')"),
	"filter?": type("string").describe("Substring filter to match specific URLs, methods, or payloads"),
	"kind?": type("string").describe(
		"Optional category filter: 'ws', 'websocket', 'crypto', 'send', 'console', 'fetch', 'xhr', etc.",
	),
	"since_seq?": type("number").describe(
		"For action: 'events': filter to events strictly greater than this sequence number",
	),
	"stack_trace?": type("boolean").describe("Whether to capture call stack traces with events (default true)"),
	"tamper_mode?": type.enumerated(...HOOK_TAMPER_MODES).describe(
		"Hook mode: 'log' (default read-only observer), 'debugger', or 'stub'",
	),
	"max_payload_length?": type("number.integer >= 1").describe(
		"Maximum characters of argument/response payload to capture (default 1024, max 32768)",
	),
	"clear?": type("boolean").describe("Whether to clear captured event buffer after reading (for 'capture'/'events')"),
	"limit?": type("number.integer >= 1").describe("Maximum number of events to return or export (default 50, max 500)"),
	"export_target?": type("string").describe("Target file/URL name recorded in exported evidence facts"),
	"evidence_kind?": type.enumerated("fact", "hypothesis").describe(
		"Kind of evidence to export ('fact' or 'hypothesis', default 'fact')",
	),
	"tags?": type("string[]").describe("Categorization tags to attach to exported evidence"),
});

export type BrowserReverseSessionParams = typeof browserReverseSessionSchema.infer;

export interface InjectedHookRecord {
	preset: HookPresetKind;
	target?: string;
	filter?: string;
	injectedAt: string;
	initScriptId?: string;
	evaluated?: boolean;
}

export interface ActiveBrowserReverseSession {
	id: string;
	tabName: string;
	url?: string;
	title?: string;
	status: "active" | "idle" | "closed";
	createdAt: string;
	lastActivityAt: string;
	injectedHooks: InjectedHookRecord[];
	capturedEvents: BrowserReverseEvent[];
	eventsCount?: number;
}

export interface BrowserEvidenceExportItem {
	sourceTool: string;
	kind: "fact" | "hypothesis";
	target: string;
	locator: string;
	content: string;
	tags: string[];
}

export interface BrowserReverseSessionDetails {
	action: BrowserReverseAction;
	session_id?: string;
	tab_name: string;
	url?: string;
	status?: "active" | "idle" | "closed" | "unknown";
	preset?: HookPresetKind;
	target?: string;
	init_script_id?: string;
	evaluated?: boolean;
	injected_hooks?: InjectedHookRecord[];
	events?: BrowserReverseEvent[];
	eventCount?: number;
	consoleLogs?: unknown[];
	requests?: unknown[];
	evidence?: BrowserEvidenceExportItem[];
	safetyNote: string;
	executed: boolean;
}

const activeReverseSessions = new Map<string, ActiveBrowserReverseSession>();

export function getActiveBrowserReverseSessionForTest(sessionIdOrTabName: string): ActiveBrowserReverseSession | undefined {
	const direct = activeReverseSessions.get(sessionIdOrTabName);
	if (direct) return direct;
	for (const session of activeReverseSessions.values()) {
		if (session.tabName === sessionIdOrTabName) return session;
	}
	return undefined;
}

export function clearActiveBrowserReverseSessionsForTest(): void {
	activeReverseSessions.clear();
}

export class BrowserReverseSessionStore {
	readonly projectDirectory: string;

	constructor(projectDirectory: string) {
		this.projectDirectory = projectDirectory;
	}

	static forSession(cwd: string, stateRoot?: string): BrowserReverseSessionStore {
		const projectKey = encodeProjectKey(cwd);
		if (stateRoot) {
			const resolved = path.resolve(stateRoot);
			const baseDir = resolved.endsWith("browser_sessions") || resolved.endsWith("browser-sessions")
				? resolved
				: path.join(resolved, "browser_sessions");
			return new BrowserReverseSessionStore(path.join(baseDir, projectKey));
		}
		return new BrowserReverseSessionStore(getBrowserSessionsProjectDir(projectKey));
	}

	async ensureDir(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: 0o700 });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, 0o700).catch(() => undefined);
		}
	}

	filePath(sessionId: string): string {
		const safeId = sessionId.replace(/[^a-zA-Z0-9._-]/g, "_");
		return path.join(this.projectDirectory, `${safeId}.json`);
	}

	async save(record: ActiveBrowserReverseSession): Promise<void> {
		await this.ensureDir();
		const targetPath = this.filePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7().slice(0, 8)}.tmp`;
		const json = JSON.stringify(record, null, 2);
		await Bun.write(tempPath, json);
		if (process.platform !== "win32") {
			await fs.chmod(tempPath, 0o600).catch(() => undefined);
		}
		await replaceFileAtomically(tempPath, targetPath);
	}

	async get(sessionId: string): Promise<ActiveBrowserReverseSession | null> {
		const targetPath = this.filePath(sessionId);
		try {
			const text = await Bun.file(targetPath).text();
			return JSON.parse(text) as ActiveBrowserReverseSession;
		} catch (error) {
			if (isEnoent(error)) return null;
			return null;
		}
	}

	async delete(sessionId: string): Promise<boolean> {
		const targetPath = this.filePath(sessionId);
		try {
			await fs.unlink(targetPath);
			return true;
		} catch (error) {
			if (isEnoent(error)) return false;
			return false;
		}
	}

	async list(): Promise<ActiveBrowserReverseSession[]> {
		await this.ensureDir();
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: ActiveBrowserReverseSession[] = [];
			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				try {
					const text = await Bun.file(path.join(this.projectDirectory, entry.name)).text();
					records.push(JSON.parse(text) as ActiveBrowserReverseSession);
				} catch {}
			}
			records.sort((a, b) => b.lastActivityAt.localeCompare(a.lastActivityAt));
			return records;
		} catch {
			return [];
		}
	}
}

export class BrowserReverseSessionTool
	implements AgentTool<typeof browserReverseSessionSchema, BrowserReverseSessionDetails>
{
	readonly name = "browser_reverse_session";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "status" || action === "events" || action === "capture" || action === "export_evidence") {
				return "read";
			}
		}
		return "write";
	};
	readonly label = "Browser Reverse Session";
	readonly summary =
		"Native browser reverse-engineering session: live tab lifecycle, hook preset injection, network/console/WebSocket capture, and bounded evidence extraction.";
	readonly description: string;
	readonly parameters = browserReverseSessionSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly store: BrowserReverseSessionStore;

	constructor(
		private readonly session: ToolSession,
		private readonly runner?: BrowserReverseRunner,
		private readonly stateRoot?: string,
	) {
		this.description = prompt.render(browserReverseSessionDescription);
		this.store = BrowserReverseSessionStore.forSession(this.session.cwd, this.stateRoot);
	}

	private async syncToRuntimeSessionStore(revSession: ActiveBrowserReverseSession): Promise<void> {
		try {
			const runtimeStore = ReverseRuntimeSessionStore.forSession(
				this.session.cwd,
				this.stateRoot,
			);
			const recent = (revSession.capturedEvents ?? []).slice(-50);
			const normalizedRecent: UniversalDynamicEvent[] = recent.map((ev, idx) =>
				normalizeBrowserEvent(ev, revSession.id, {
					target: revSession.url || revSession.tabName,
					seq: typeof ev.seq === "number" ? ev.seq : idx + 1,
					timestamp:
						typeof ev.timestamp === "number"
							? new Date(ev.timestamp).toISOString()
							: typeof ev.timestamp === "string"
								? ev.timestamp
								: undefined,
				}),
			);
			const runtimeRecord: RuntimeSessionRecord = {
				id: revSession.id,
				name: `Browser tab ${revSession.tabName}`,
				kind: "browser",
				status: revSession.status === "active" ? "active" : revSession.status === "idle" ? "idle" : "closed",
				target_summary: revSession.url || revSession.tabName,
				target_details: { tabName: revSession.tabName, tab_name: revSession.tabName, url: revSession.url },
				connection: { type: "cdp", tabName: revSession.tabName, tab_name: revSession.tabName },
				recovery_hints: {
					restore_tool: "browser_reverse_session",
					restore_action: "open",
					restore_params: {
						session_id: revSession.id,
						tab_name: revSession.tabName,
						url: revSession.url,
						...(revSession.injectedHooks.length > 0
							? {
									injected_hooks: revSession.injectedHooks.map(h => ({
										preset: h.preset,
										target: h.target,
										filter: h.filter,
									})),
								}
							: {}),
					},
					instructions: [
						`Reopen browser tab "${revSession.tabName}" with url "${revSession.url || ""}"`,
						...revSession.injectedHooks.map(
							h =>
								`Re-inject hook preset "${h.preset}"${h.target ? ` on target "${h.target}"` : ""}${h.filter ? ` with filter "${h.filter}"` : ""}`,
						),
					],
				},
				created_at: revSession.createdAt,
				updated_at: revSession.lastActivityAt,
				last_heartbeat_at: revSession.lastActivityAt,
				heartbeat_count: 1,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
				metadata: {
					tab_name: revSession.tabName,
					url: revSession.url,
					injectedHooksCount: revSession.injectedHooks.length,
					capturedEventsCount: revSession.capturedEvents.length,
					eventsCount: revSession.eventsCount ?? revSession.capturedEvents.length,
					events_count: revSession.eventsCount ?? revSession.capturedEvents.length,
					recent_events: normalizedRecent,
				},
			};
			await runtimeStore.save(runtimeRecord);
		} catch {}
	}

	private async saveSession(revSession: ActiveBrowserReverseSession): Promise<void> {
		activeReverseSessions.set(revSession.id, revSession);
		await this.store.save(revSession).catch(() => undefined);
		await this.syncToRuntimeSessionStore(revSession).catch(() => undefined);
	}

	private async findOrCreateSession(
		tabName: string,
		sessionId?: string,
		initialUrl?: string,
	): Promise<ActiveBrowserReverseSession> {
		const existingId = sessionId ?? `browser-rev-${tabName}`;
		let found = activeReverseSessions.get(existingId);
		if (!found) {
			for (const item of activeReverseSessions.values()) {
				if (item.tabName === tabName && item.status !== "closed") {
					found = item;
					break;
				}
			}
		}

		if (!found) {
			try {
				found = (await this.store.get(existingId)) ?? undefined;
				if (!found) {
					const all = await this.store.list();
					found = all.find(s => s.tabName === tabName && s.status !== "closed");
				}
			} catch {}
		}

		if (!found) {
			const now = new Date().toISOString();
			found = {
				id: existingId,
				tabName,
				url: initialUrl,
				status: "active",
				createdAt: now,
				lastActivityAt: now,
				injectedHooks: [],
				capturedEvents: [],
				eventsCount: 0,
			};
		} else {
			if (initialUrl) found.url = initialUrl;
			found.lastActivityAt = new Date().toISOString();
			if (typeof found.eventsCount !== "number") {
				found.eventsCount = found.capturedEvents.reduce(
					(max, e) => Math.max(max, typeof e.seq === "number" ? e.seq : 0),
					found.capturedEvents.length,
				);
			}
		}
		await this.saveSession(found);
		return found;
	}

	private getRunner(): BrowserReverseRunner {
		return this.runner ?? createDefaultBrowserReverseRunner(this.session);
	}


	async execute(
		_toolCallId: string,
		params: BrowserReverseSessionParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<BrowserReverseSessionDetails>> {
		throwIfAborted(signal);

		const action = params.action;
		const tabName = params.tab_name?.trim() || "main";
		const runner = this.getRunner();

		if (action === "open") {
			const targetUrl = params.url?.trim();
			if (!targetUrl) {
				const liveTab = runner.getTab(tabName);
				if (!liveTab || liveTab.state !== "alive") {
					throw new ToolError(
						`url is required for action 'open' when tab "${tabName}" is not already open.`,
					);
				}
			}

			const opened = targetUrl ? await runner.openTab(tabName, targetUrl, signal) : { name: tabName, url: "" };
			const finalUrl = opened.url || targetUrl;
			const revSession = await this.findOrCreateSession(tabName, params.session_id, finalUrl);
			revSession.status = "active";
			revSession.url = finalUrl;

			const autoInjected: InjectedHookRecord[] = [];
			if (params.preset) {
				const hookTool = new JsHookPresetTool(this.session, runner);
				const injectRes = await hookTool.execute(
					"sub_inject",
					{
						action: "inject",
						preset: params.preset,
						target: params.target,
						filter: params.filter,
						stack_trace: params.stack_trace,
						tamper_mode: params.tamper_mode,
						max_payload_length: params.max_payload_length,
						tab_name: tabName,
					},
					signal,
				);
				const record: InjectedHookRecord = {
					preset: params.preset,
					target: params.target,
					filter: params.filter,
					injectedAt: new Date().toISOString(),
					initScriptId: injectRes.details?.init_script_id,
					evaluated: injectRes.details?.evaluated,
				};
				revSession.injectedHooks.push(record);
				autoInjected.push(record);
			}
			await this.saveSession(revSession);

			const summaryLines = [
				`# Browser Reverse Session Opened`,
				`- **Session ID**: \`${revSession.id}\``,
				`- **Tab**: \`${tabName}\``,
				`- **URL**: ${finalUrl || "[current page]"}`,
				`- **Status**: active`,
				`- **Auto-injected Hooks**: ${autoInjected.length > 0 ? autoInjected.map(h => h.preset).join(", ") : "[none]"}`,
			];

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "open",
					session_id: revSession.id,
					tab_name: tabName,
					url: finalUrl,
					status: "active",
					injected_hooks: revSession.injectedHooks,
					executed: true,
					safetyNote: "Browser reverse session active.",
				},
			};
		}

		if (action === "inject") {
			const preset = params.preset;
			if (!preset) {
				throw new ToolError("preset is required for action 'inject'");
			}
			if (preset === "custom" && !params.target) {
				throw new ToolError("target parameter is required when preset is 'custom'");
			}
			if (params.target) {
				validateCustomTargetSelector(params.target);
			}

			const liveTab = runner.getTab(tabName);
			if (!liveTab || liveTab.state !== "alive") {
				throw new ToolError(
					`Browser tab "${tabName}" is not open or alive. Open the session first using browser_reverse_session(action: 'open', url: '...').`,
				);
			}

			const hookTool = new JsHookPresetTool(this.session, runner);
			const injectRes = await hookTool.execute(
				"sub_inject",
				{
					action: "inject",
					preset,
					target: params.target,
					filter: params.filter,
					stack_trace: params.stack_trace,
					tamper_mode: params.tamper_mode,
					max_payload_length: params.max_payload_length,
					tab_name: tabName,
				},
				signal,
			);

			const revSession = await this.findOrCreateSession(tabName, params.session_id, liveTab.url);
			const record: InjectedHookRecord = {
				preset,
				target: params.target,
				filter: params.filter,
				injectedAt: new Date().toISOString(),
				initScriptId: injectRes.details?.init_script_id,
				evaluated: injectRes.details?.evaluated,
			};
			revSession.injectedHooks.push(record);
			await this.saveSession(revSession);

			const summaryLines = [
				`# Browser Reverse Hook Injected`,
				`- **Session ID**: \`${revSession.id}\``,
				`- **Tab**: \`${tabName}\``,
				`- **Preset**: \`${preset}\`${params.target ? ` (${params.target})` : ""}`,
				`- **Init Script Registered**: ${record.initScriptId ? `yes (${record.initScriptId})` : "no"}`,
				`- **Page Evaluated**: ${record.evaluated ? "yes" : "no"}`,
			];

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "inject",
					session_id: revSession.id,
					tab_name: tabName,
					url: liveTab.url,
					status: revSession.status,
					preset,
					target: params.target,
					init_script_id: record.initScriptId,
					evaluated: record.evaluated,
					injected_hooks: revSession.injectedHooks,
					executed: true,
					safetyNote: "Instrumentation hook injected into live browser tab.",
				},
			};
		}

		if (action === "capture") {
			const liveTab = runner.getTab(tabName);
			if (!liveTab || liveTab.state !== "alive") throw new ToolError(`Browser tab "${tabName}" is not open or alive. Cannot capture events from an inactive tab.`);
			const revSession = await this.findOrCreateSession(tabName, params.session_id, liveTab.url);
			const limit = Math.min(500, Math.max(1, Math.floor(params.limit ?? 50)));
			const hookTool = new JsHookPresetTool(this.session, runner);
			const captureRes = await hookTool.execute("sub_capture", { action: "capture", tab_name: tabName, filter: params.filter, clear: params.clear === true, limit }, signal);
			const newEvents = captureRes.details?.events ?? [];
			if (typeof revSession.eventsCount !== "number") {
				revSession.eventsCount = revSession.capturedEvents.reduce(
					(max, e) => Math.max(max, typeof e.seq === "number" ? e.seq : 0),
					revSession.capturedEvents.length,
				);
			}
			for (const ev of newEvents) {
				const existing = revSession.capturedEvents.find(e => {
					if (ev.id && e.id) return ev.id === e.id && ev.type === e.type;
					return (
						e.timestamp === ev.timestamp &&
						e.type === ev.type &&
						JSON.stringify(e.data ?? e.payload ?? e) ===
							JSON.stringify(ev.data ?? ev.payload ?? ev)
					);
				});
				if (existing) {
					if (typeof existing.seq === "number" && typeof ev.seq !== "number") {
						ev.seq = existing.seq;
					}
				} else {
					revSession.eventsCount += 1;
					ev.seq = revSession.eventsCount;
					if (revSession.capturedEvents.length >= 1000) revSession.capturedEvents.shift();
					revSession.capturedEvents.push(ev);
				}
			}
			if (params.clear === true) {
				revSession.capturedEvents = [];
			}
			await this.saveSession(revSession);
			return {
				content: captureRes.content,
				details: {
					action,
					session_id: revSession.id,
					tab_name: tabName,
					url: liveTab.url,
					status: revSession.status,
					events: newEvents,
					eventCount: revSession.capturedEvents.length,
					consoleLogs: captureRes.details?.consoleLogs ?? [],
					requests: captureRes.details?.requests ?? [],
					injected_hooks: revSession.injectedHooks,
					executed: true,
					safetyNote: "Structured events captured from browser session.",
				},
			};
		}

		if (action === "events") {
			const revSession = await this.findOrCreateSession(tabName, params.session_id);
			let matchingEvents = [...revSession.capturedEvents];
			if (typeof params.since_seq === "number") {
				matchingEvents = matchingEvents.filter(
					e => typeof e.seq === "number" && e.seq > params.since_seq!,
				);
			}
			const filterQuery = (params.filter || (params as Record<string, unknown>).kind ? String(params.filter || (params as Record<string, unknown>).kind).trim().toLowerCase() : null);
			if (filterQuery) {
				matchingEvents = matchingEvents.filter(e => {
					const typeLower = (e.type || "").toLowerCase();
					if (filterQuery === "ws" && typeLower.startsWith("websocket")) return true;
					if (filterQuery === "send" && (typeLower.includes("send") || typeLower.includes("request"))) return true;
					if (filterQuery === "console" && typeLower.includes("console")) return true;
					if (filterQuery === "crypto" && typeLower.startsWith("crypto")) return true;
					try {
						return JSON.stringify(e).toLowerCase().includes(filterQuery);
					} catch {
						return false;
					}
				});
			}
			const totalMatching = matchingEvents.length;

			if (params.clear === true) {
				if (filterQuery || typeof params.since_seq === "number") {
					const matchedSet = new Set(matchingEvents);
					revSession.capturedEvents = revSession.capturedEvents.filter(e => !matchedSet.has(e));
				} else {
					revSession.capturedEvents = [];
				}
				await this.saveSession(revSession);
			}

			const limit = Math.min(500, Math.max(1, Math.floor(params.limit ?? 50)));
			const paged = matchingEvents.slice(0, limit);

			const summaryLines = [
				`# Browser Reverse Events: Tab \`${tabName}\``,
				`- **Session ID**: \`${revSession.id}\``,
				`- **Total Events Buffered**: ${revSession.capturedEvents.length}`,
				`- **Matching Events**: ${totalMatching}${filterQuery ? ` (filter: "${filterQuery}")` : ""}${typeof params.since_seq === "number" ? ` (since_seq: ${params.since_seq})` : ""}`,
				`- **Returned**: ${paged.length}`,
				`- **Buffer Cleared**: ${params.clear === true ? "yes" : "no"}`,
			];

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action,
					session_id: revSession.id,
					tab_name: tabName,
					status: revSession.status,
					events: paged,
					eventCount: paged.length,
					totalEvents: revSession.capturedEvents.length,
					executed: true,
					safetyNote: "Read from buffered browser events.",
				},
			};
		}

		if (action === "export_evidence") {
			const liveTab = runner.getTab(tabName);
			const revSession = await this.findOrCreateSession(tabName, params.session_id, liveTab?.url);
			const filter = (params.filter || (params as Record<string, unknown>).kind ? String(params.filter || (params as Record<string, unknown>).kind).trim().toLowerCase() : null);
			const limit = Math.min(500, Math.max(1, Math.floor(params.limit ?? 50)));

			let matchingEvents = revSession.capturedEvents;
			if (filter) {
				matchingEvents = matchingEvents.filter(e => {
					const typeLower = (e.type || "").toLowerCase();
					if (filter === "ws" && typeLower.startsWith("websocket")) return true;
					if (filter === "send" && (typeLower.includes("send") || typeLower.includes("request"))) return true;
					if (filter === "console" && typeLower.includes("console")) return true;
					if (filter === "crypto" && typeLower.startsWith("crypto")) return true;
					try {
						return JSON.stringify(e).toLowerCase().includes(filter);
					} catch {
						return false;
					}
				});
			}

			const paged = matchingEvents.slice(0, limit);
			const targetUri = params.export_target || revSession.url || tabName;
			const kind = params.evidence_kind ?? "fact";
			const baseTags = params.tags ?? ["browser", "reverse"];

			const evidenceList: BrowserEvidenceExportItem[] = paged.map((ev, idx) => ({
				sourceTool: "browser_reverse_session",
				kind,
				target: targetUri,
				locator: `tab:${tabName}:${ev.type}${ev.id ? `:${ev.id}` : `:${idx + 1}`}`,
				content: `Observed browser ${ev.type} on ${targetUri}: ${JSON.stringify(ev).slice(0, 1024)}`,
				tags: [...baseTags, ev.type],
			}));

			const summaryLines = [
				`# Exported Evidence Records: Tab \`${tabName}\``,
				`- **Session ID**: \`${revSession.id}\``,
				`- **Records Formatted**: ${evidenceList.length}`,
				`- **Target**: \`${targetUri}\``,
				`- **Evidence Kind**: \`${kind}\``,
				"",
			];

			if (evidenceList.length > 0) {
				summaryLines.push("### Evidence Candidates (Ready for `evidence` tool):");
				for (const item of evidenceList.slice(0, 5)) {
					summaryLines.push(`- **${item.locator}**: ${item.content.slice(0, 120)}...`);
				}
				if (evidenceList.length > 5) {
					summaryLines.push(`... and ${evidenceList.length - 5} more records.`);
				}
			} else {
				summaryLines.push("_No matching events available to export as evidence._");
			}

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "export_evidence",
					session_id: revSession.id,
					tab_name: tabName,
					url: revSession.url,
					evidence: evidenceList,
					eventCount: evidenceList.length,
					executed: true,
					safetyNote: "Structured facts prepared for evidence ledger.",
				},
			};
		}

		if (action === "status") {
			const liveTab = runner.getTab(tabName);
			const revSession = await this.findOrCreateSession(tabName, params.session_id, liveTab?.url);
			const status = liveTab && liveTab.state === "alive" ? "active" : "closed";
			revSession.status = status;
			await this.saveSession(revSession);

			const summaryLines = [
				`# Browser Reverse Session Status`,
				`- **Session ID**: \`${revSession.id}\``,
				`- **Tab**: \`${tabName}\``,
				`- **Status**: ${status}`,
				`- **URL**: ${liveTab?.url || revSession.url || "[none]"}`,
				`- **Injected Hooks Count**: ${revSession.injectedHooks.length}`,
				`- **Captured Events in Buffer**: ${revSession.capturedEvents.length}`,
			];

			if (revSession.injectedHooks.length > 0) {
				summaryLines.push("### Active Hooks:");
				for (const h of revSession.injectedHooks) {
					summaryLines.push(`- **${h.preset}** ${h.target ? `(${h.target})` : ""}${h.filter ? ` [filter: ${h.filter}]` : ""}`);
				}
			}

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "status",
					session_id: revSession.id,
					tab_name: tabName,
					url: liveTab?.url || revSession.url,
					status,
					injected_hooks: revSession.injectedHooks,
					eventCount: revSession.capturedEvents.length,
					executed: true,
					safetyNote: "Status checked successfully.",
				},
			};
		}

		if (action === "close") {
			const revSession = await this.findOrCreateSession(tabName, params.session_id);
			if (runner.closeTab) {
				await runner.closeTab(tabName, signal);
			}
			revSession.status = "closed";
			await this.saveSession(revSession);

			return {
				content: [{ type: "text", text: `Browser reverse session \`${revSession.id}\` (tab \`${tabName}\`) closed.` }],
				details: {
					action: "close",
					session_id: revSession.id,
					tab_name: tabName,
					url: revSession.url,
					status: "closed",
					executed: true,
					safetyNote: "Tab released and session marked closed.",
				},
			};
		}

		throw new ToolError(`Unsupported action: ${action}`);
	}
}
