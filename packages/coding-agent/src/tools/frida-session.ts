import * as fs from "node:fs/promises";
import * as path from "node:path";
import { type } from "@reverse/reversetype";
import type {
	AgentTool,
	AgentToolContext,
	AgentToolResult,
	AgentToolUpdateCallback,
	ToolApprovalDecision,
} from "@reverse/agent";
import { $which, getFridaSessionsDir, isEnoent, logger } from "@reverse/utils";
import fridaSessionDescription from "../prompts/tools/frida-session.md" with { type: "text" };
import { redactMemorySecrets } from "../memory-backend/redact";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import { replaceFileAtomically } from "../utils/atomic-file";
import { ReverseRuntimeSessionStore } from "../reverse-runtime-session/store";
import type { RuntimeSessionRecord } from "../reverse-runtime-session/contracts";
import {
	normalizeFridaEvent,
	formatDynamicLocator,
	type UniversalDynamicEvent,
} from "../reverse-runtime-session/dynamic-events";
import { EvidenceStore } from "../evidence/store";
import type { ToolSession } from "./index";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import {
	defaultFridaRunner,
	FIXED_ENUMERATE_MODULES_SCRIPT,
	fridaDependency,
	type FridaDependencyStatus,
	type FridaFallbackInfo,
	type FridaRunner,
	resolveFridaFallback,
	resolveScriptPath,
	resolveTemplateScript,
	splitCliArgs,
	parsePythonLiteral,
} from "./frida";
import { probeFridaLiveDependency, type FridaLiveDependencyStatus } from "./frida-live-env";
import { FridaLiveClient, type FridaLiveInitResult, type FridaLiveLoadResult } from "./frida-live-client";
export const fridaSessionSchema = type({
	"action?": type
		.enumerated("create", "list", "status", "run", "events", "stop", "destroy", "load", "unload", "rpc", "resume")
		.describe(
			"Action to perform: 'create' (start/initialize new analysis session), 'list' (list saved sessions), 'status' (inspect session state and target status), 'run' (execute script or enumeration in session context), 'load' (load or hot-reload script in live session), 'unload' (unload active script from live session), 'rpc' (call exported RPC function in live session), 'resume' (resume paused/suspended live spawned process), 'events' (inspect, query, or export structured event ring buffer), 'stop' (suspend/stop session and active child), 'destroy' (terminate and remove session)",
		),
	"mode?": type
		.enumerated("batch", "live")
		.describe(
			"Session mode: 'batch' (default: oneshot CLI invocation per run) or 'live' (persistent long-lived Frida session process with RPC, live telemetry, and hot reload)",
		),
	"session_id?": type("string").describe(
		"Identifier for the session. Auto-generated on create if omitted. Required for run/status/events/stop/destroy when multiple sessions exist",
	),
	"name?": type("string").describe("Optional friendly name or label for the session"),
	"pid?": type("number").describe("Target process ID (PID) to attach to. Mutually exclusive with process and spawn"),
	"process?": type("string").describe(
		"Target process name or application package to attach to. Mutually exclusive with pid and spawn",
	),
	"spawn?": type("string").describe(
		"Target application identifier or binary path to spawn as a persistent session. Mutually exclusive with pid and process",
	),
	"usb?": type("boolean").describe("Target USB device/emulator (shorthand for frida -U)"),
	"device?": type("string").describe("Target device serial or ID (passes -D <device>)"),
	"host?": type("string").describe("Target remote frida-server host (e.g. '192.168.1.5:27042', passes -H <host>)"),
	"script?": type("string").describe("Inline Frida JavaScript source code to execute or load"),
	"script_path?": type("string").describe("Local path to a Frida JavaScript script file to execute or load"),
	"rpc_method?": type("string").describe("For action: 'rpc': name of exported RPC function in rpc.exports"),
	"rpc_args?": type("unknown").describe(
		"For action: 'rpc': arguments passed to the RPC function (scalar, array, or object)",
	),
	"command?": type("string").describe(
		"Builtin evaluation command: 'script' (default), 'modules' (list loaded modules), 'ps' (list processes), 'inspect' (inspect target environment)",
	),
	"script_args?": type("unknown").describe("Optional arguments passed to the script via -P / --parameters JSON"),
	"pause?": type("boolean").describe("For spawn mode: leave main thread paused after spawning (passes --pause)"),
	"no_pause?": type("boolean").describe(
		"For spawn mode: legacy flag for starting main thread immediately; set false to leave paused via --pause",
	),
	"filter?": type("string").describe("Optional text filter for list/events action or output inspection"),
	"cli_args?": type("unknown").describe("Optional array of extra CLI arguments passed directly to Frida"),
	"timeout?": type("number").describe("Watchdog execution timeout in seconds (default: 30)"),
	"max_bytes?": type("number").describe("Maximum stdout bytes captured before truncation (default: 262144)"),
	"to_artifact?": type("boolean").describe("Save complete output and session records to session artifact"),
	"since_seq?": type("number").describe(
		"For action: 'events': filter to events strictly greater than this sequence number",
	),
	"limit?": type("number").describe(
		"For action: 'events' or 'list': maximum number of records to return (default 50, max 500)",
	),
	"clear?": type("boolean").describe("For action: 'events': clear all captured events from session event ring buffer"),
	"kind?": type("string").describe(
		"For action: 'events': filter events by kind ('stdout', 'stderr', 'message', 'trace', 'lifecycle', 'error')",
	),
	"channel?": type("string").describe(
		"For action: 'events': filter events by channel ('console', 'send', 'spawn', 'trace', 'lifecycle')",
	),
	"export_evidence?": type("boolean").describe(
		"For action: 'events' or 'run': format structured evidence references compatible with the evidence ledger",
	),
	"template?": type
		.enumerated("module_load", "exports", "jni_register", "native_functions")
		.describe(
			"Optional built-in Frida script template to execute or load: 'jni_register' (trace JNI RegisterNatives bindings), 'native_functions' (trace native function executions), 'module_load' (trace module loads), 'exports' (trace module exports)",
		),
	"module?": type("string").describe(
		"Target module name (e.g. 'libnative-lib.so') for template 'exports', 'native_functions', or 'jni_register'",
	),
	"symbol?": type("string").describe(
		"Target function symbol name for template 'native_functions' or custom JNI entry",
	),
	"symbols?": type("unknown").describe("Array of target function symbol names for template 'native_functions'"),
	"offset?": type("unknown").describe(
		"Target function offset from module base (hex string e.g. '0x1234' or number) for template 'native_functions'",
	),
	"offsets?": type("unknown").describe("Array of target function offsets for template 'native_functions'"),
	"args_count?": type("number").describe("Number of arguments to capture in native_functions template (default 4)"),
	"args_decode?": type("unknown").describe(
		"Map or array specifying argument decoding types (e.g. {'0': 'int', '1': 'string'}) for native_functions template",
	),
	"retval?": type("boolean").describe("Whether to capture return value in native_functions template (default true)"),
	"backtrace?": type("unknown").describe(
		"Whether to capture backtrace in native_functions template (true, 'accurate', 'fuzzy', or false; default false)",
	),
	"max_events?": type("number").describe("Maximum events to capture before detaching hooks (default 100)"),
	"max_buffer_bytes?": type("number").describe(
		"Maximum buffer/string bytes to read per argument in native_functions template (default 256)",
	),
});

export type FridaSessionParams = typeof fridaSessionSchema.infer;
export type FridaSessionAction =
	| "create"
	| "list"
	| "status"
	| "run"
	| "events"
	| "stop"
	| "destroy"
	| "load"
	| "unload"
	| "rpc"
	| "resume";
export type FridaSessionStatus = "ok" | "missing_dependency" | "stopped" | "not_found" | "timeout" | "error";

export type DynamicSessionEventKind = "stdout" | "stderr" | "message" | "trace" | "lifecycle" | "error";

export interface DynamicSessionEvent {
	id: string;
	seq: number;
	timestamp: string;
	sessionId: string;
	kind: DynamicSessionEventKind;
	channel?: string;
	payload: unknown;
	raw?: string;
	metadata?: Record<string, unknown>;
}

export interface DynamicEvidenceReference {
	sourceTool: "frida_session" | "reverse_dynamic_session";
	target: string;
	locator: string;
	kind: "fact";
	title?: string;
	content: string;
	excerpt?: string;
	metadata?: Record<string, unknown>;
}
export interface FridaSessionTarget {
	type: "pid" | "process" | "spawn";
	value: string | number;
	pid?: number;
	process?: string;
	spawn?: string;
	usb?: boolean;
	device?: string;
	host?: string;
	pause?: boolean;
	noPause?: boolean;
}

export interface FridaSessionRunEntry {
	id: string;
	timestamp: string;
	command?: string;
	scriptSnippet?: string;
	scriptSource?: "inline" | "file";
	scriptPath?: string;
	exitCode?: number | null;
	outputBytes?: number;
	truncated?: boolean;
	error?: string;
}

export interface FridaSessionRecord {
	id: string;
	name?: string;
	mode?: "batch" | "live";
	liveStatus?: "connected" | "detached" | "stopped" | "error" | "disconnected";
	target: FridaSessionTarget;
	status: "active" | "stopped" | "failed" | "error";
	createdAt: string;
	updatedAt: string;
	lastRunAt?: string;
	runsCount: number;
	history: FridaSessionRunEntry[];
	activeChildPid?: number;
	lastScript?: string;
	loadedScript?: string;
	rpcExports?: string[];
	metadata?: Record<string, unknown>;
	events?: DynamicSessionEvent[];
	eventsCount?: number;
}

export interface FridaSessionDetails {
	action: FridaSessionAction;
	status: FridaSessionStatus;
	sessionId?: string;
	mode?: "batch" | "live";
	liveStatus?: string;
	session?: FridaSessionRecord;
	sessions?: FridaSessionRecord[];
	target?: string;
	targetMode?: string;
	exitCode?: number | null;
	stdout?: string;
	stderr?: string;
	outputBytes?: number;
	truncated?: boolean;
	timedOut?: boolean;
	dependency?: FridaDependencyStatus | FridaLiveDependencyStatus;
	fallback?: FridaFallbackInfo;
	error?: string;
	events?: DynamicSessionEvent[];
	eventsCount?: number;
	totalEvents?: number;
	evidence?: DynamicEvidenceReference | DynamicEvidenceReference[];
	artifactId?: string;
	artifactPath?: string;
	rpcResult?: unknown;
	exports?: string[];
}

export interface FridaSessionToolOptions {
	which?: SkillRequirementWhich;
	runner?: FridaRunner;
	stateRoot?: string;
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const DEFAULT_MAX_BYTES = 256 * 1024;
const INSPECT_TARGET_SCRIPT =
	"(function(){try{return JSON.stringify({pid:Process.id,arch:Process.arch,platform:Process.platform,pageSize:Process.pageSize,pointerSize:Process.pointerSize});}catch(e){return JSON.stringify({error:e.message||String(e)});}})();";

interface ActiveChild {
	sessionId: string;
	pid?: number;
	child?: {
		kill: (signal?: number | string) => void;
		exited: Promise<number>;
		pid?: number;
	};
	abortController?: AbortController;
	startedAt: number;
}

const ACTIVE_CHILDREN = new Map<string, ActiveChild>();
export interface FridaLiveContext {
	sessionId: string;
	projectKey: string;
	client: FridaLiveClient;
	record: FridaSessionRecord;
	store: FridaSessionStore;
	syncToRuntime: (r: FridaSessionRecord) => Promise<void>;
	hasPendingSave: boolean;
	isWritingSave: boolean;
	disposed: boolean;
	flushResolvers: Array<() => void>;
}

const ACTIVE_LIVE_SESSIONS = new Map<string, FridaLiveContext>();

function getLiveSessionKey(projectKey: string, sessionId: string): string {
	return `${projectKey}:${sessionId}`;
}
async function persistLiveSessionContext(context: FridaLiveContext, waitForFlush = false): Promise<void> {
	if (context.disposed) return;
	context.hasPendingSave = true;

	if (context.isWritingSave) {
		if (waitForFlush) {
			const { promise, resolve } = Promise.withResolvers<void>();
			context.flushResolvers.push(resolve);
			return promise;
		}
		return;
	}

	context.isWritingSave = true;

	const runSaveLoop = async () => {
		try {
			while (context.hasPendingSave && !context.disposed) {
				context.hasPendingSave = false;
				const snapshot: FridaSessionRecord = {
					...context.record,
					events: context.record.events ? [...context.record.events] : [],
					history: [...context.record.history],
				};
				await context.store.save(snapshot);
				await context.syncToRuntime(snapshot);
			}
		} catch (err) {
			logger.warn(`Failed serialized save for live Frida session ${context.sessionId}`, { error: String(err) });
		} finally {
			context.isWritingSave = false;
			const resolvers = context.flushResolvers;
			context.flushResolvers = [];
			for (const resolve of resolvers) {
				resolve();
			}
		}
	};

	if (waitForFlush) {
		await runSaveLoop();
	} else {
		queueMicrotask(runSaveLoop);
	}
}

let exitHookInstalled = false;
function ensureExitHook(): void {
	if (exitHookInstalled) return;
	exitHookInstalled = true;
	process.once("exit", () => {
		for (const [, ctx] of ACTIVE_LIVE_SESSIONS) {
			try {
				ctx.client.destroy();
			} catch {
				// Best effort on exit
			}
		}
		ACTIVE_LIVE_SESSIONS.clear();
		for (const [, active] of ACTIVE_CHILDREN) {
			try {
				active.abortController?.abort();
				active.child?.kill();
			} catch {
				// Best effort on exit
			}
		}
		ACTIVE_CHILDREN.clear();
	});
}

export function isProcessAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (error: unknown) {
		if (error && typeof error === "object" && "code" in error) {
			return error.code === "EPERM";
		}
		return false;
	}
}

function stopActiveChild(sessionId: string, targetPid?: number): boolean {
	let stopped = false;
	const active = ACTIVE_CHILDREN.get(sessionId);
	if (active) {
		try {
			active.abortController?.abort();
			active.child?.kill();
			stopped = true;
		} catch {
			// ignore
		}
		ACTIVE_CHILDREN.delete(sessionId);
	}
	if (targetPid && isProcessAlive(targetPid)) {
		try {
			process.kill(targetPid, "SIGTERM");
			stopped = true;
		} catch {
			// ignore
		}
	}
	return stopped;
}

export function encodeProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}

function sanitizeSessionText(value: string): string {
	let redacted = redactMemorySecrets(value);
	redacted = redacted.replace(/(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]");
	redacted = redacted.replace(/(\b(?:password|secret|token)\s*[:=]\s*['"]?)[^\s,'"`;}]+/gi, "$1[REDACTED]");
	return redacted;
}

export const DEFAULT_MAX_EVENT_BUFFER_SIZE = 500;

export function appendEventsToBuffer(
	existingEvents: DynamicSessionEvent[] | undefined,
	newEvents: DynamicSessionEvent[],
	maxCapacity: number = DEFAULT_MAX_EVENT_BUFFER_SIZE,
): DynamicSessionEvent[] {
	const current = existingEvents ? [...existingEvents] : [];
	current.push(...newEvents);
	if (current.length > maxCapacity) {
		return current.slice(current.length - maxCapacity);
	}
	return current;
}

/**
 * Recursively verifies that parsed object nesting does not exceed maxDepth.
 */
function checkMaxObjectDepth(val: unknown, maxDepth: number, currentDepth = 0): boolean {
	if (currentDepth > maxDepth) return false;
	if (!val || typeof val !== "object") return true;
	if (Array.isArray(val)) {
		for (const item of val) {
			if (!checkMaxObjectDepth(item, maxDepth, currentDepth + 1)) return false;
		}
	} else {
		for (const key of Object.keys(val)) {
			if (!checkMaxObjectDepth((val as Record<string, unknown>)[key], maxDepth, currentDepth + 1)) return false;
		}
	}
	return true;
}

/**
 * Safely parses a structured Frida CLI message line (JSON or Python dict repr).
 * Handles prefixes like `message:`, `Message:`, `[*]`, `[Local::...] >` and trailing `data: None` / `data: b'...'`.
 */
export function parseStructuredFridaMessage(line: string): { parsed: unknown; data: unknown } | null {
	const trimmed = line.trim();
	if (trimmed.length === 0) return null;

	// Use dotAll / [\s\S]* to prevent truncating on unicode line separators U+2028 / U+2029
	const prefixMatch = trimmed.match(
		/^(?:\[\*\]|\[\+\]|\[Local::.*?\]\s*>)?\s*(?:message:\s*|Message:\s*)?([\s\S]*)$/i,
	);
	const candidate = prefixMatch ? prefixMatch[1].trim() : trimmed;

	if (candidate.length > 1024 * 1024) {
		return null;
	}

	if (!candidate.startsWith("{") && !candidate.startsWith("[")) {
		return null;
	}

	// 1. Try JSON.parse fast path only if candidate looks like a standalone JSON object/array
	if (
		(candidate.startsWith("{") && candidate.endsWith("}")) ||
		(candidate.startsWith("[") && candidate.endsWith("]"))
	) {
		try {
			const parsed = JSON.parse(candidate);
			if (checkMaxObjectDepth(parsed, 64)) {
				return { parsed, data: null };
			}
		} catch {
			// Fall through to Python literal parser
		}
	}

	try {
		const { value, end } = parsePythonLiteral(candidate, 0, { maxDepth: 64 });
		let data: unknown = null;
		const rest = candidate.slice(end).trim();

		if (rest.length > 0) {
			// Must strictly match `data: <content>` without arbitrary trailing garbage
			const dataMatch = rest.match(/^data:\s*([\s\S]*)$/);
			if (!dataMatch) {
				return null; // Unrecognized trailing text after parsed object
			}
			const rawData = dataMatch[1].trim();
			if (rawData === "None" || rawData === "null" || rawData.length === 0) {
				data = null;
			} else {
				try {
					data = parsePythonLiteral(rawData, 0, { requireEnd: true, maxDepth: 64 }).value;
				} catch {
					return null;
				}
			}
		}

		return { parsed: value, data };
	} catch {
		return null;
	}
}

export function parseFridaOutputIntoEvents(
	sessionId: string,
	stdout: string,
	stderr: string,
	startSeq: number,
	context: {
		command?: string;
		exitCode?: number | null;
		durationMs?: number;
	} = {},
): { events: DynamicSessionEvent[]; spawnedPid?: number } {
	const events: DynamicSessionEvent[] = [];
	let currentSeq = startSeq;
	const timestamp = new Date().toISOString();
	let spawnedPid: number | undefined;

	// 1. Lifecycle start event if command was provided
	if (context.command) {
		currentSeq++;
		events.push({
			id: `ev_${sessionId}_${currentSeq}`,
			seq: currentSeq,
			timestamp,
			sessionId,
			kind: "lifecycle",
			channel: "run_start",
			payload: { command: context.command },
			raw: `[lifecycle] started execution: ${context.command}`,
		});
	}

	// 2. Parse stdout lines
	if (stdout && stdout.length > 0) {
		const lines = stdout.split(/\r?\n|\n/g);
		for (const line of lines) {
			const trimmed = line.trim();
			if (!trimmed) continue;

			// Check for spawn marker
			const spawnMatch =
				trimmed.match(/__FRIDA_SPAWN_OK__:(\d+)/) ||
				trimmed.match(/Spawned `.*?`\s*\.\.\.\s*PID:\s*(\d+)/i) ||
				trimmed.match(/Spawned .*?\(pid (\d+)\)/i);
			if (spawnMatch) {
				spawnedPid = Number.parseInt(spawnMatch[1], 10);
				currentSeq++;
				events.push({
					id: `ev_${sessionId}_${currentSeq}`,
					seq: currentSeq,
					timestamp,
					sessionId,
					kind: "lifecycle",
					channel: "spawn",
					payload: { pid: spawnedPid },
					raw: trimmed,
				});
				continue;
			}

			// Check for JSON send / structured message / Python repr message
			const structured = parseStructuredFridaMessage(trimmed);
			if (structured) {
				const parsed = structured.parsed;
				currentSeq++;
				if (
					parsed &&
					typeof parsed === "object" &&
					!Array.isArray(parsed) &&
					(parsed as Record<string, unknown>).type === "send" &&
					"payload" in (parsed as Record<string, unknown>)
				) {
					const parsedRecord = parsed as Record<string, unknown>;
					const payloadObj =
						parsedRecord.payload && typeof parsedRecord.payload === "object" ? parsedRecord.payload : null;
					const isCrypto = Boolean(
						payloadObj &&
						((payloadObj as Record<string, unknown>).cipher ||
							(payloadObj as Record<string, unknown>).algorithm ||
							(payloadObj as Record<string, unknown>).key ||
							(payloadObj as Record<string, unknown>).type === "crypto" ||
							(payloadObj as Record<string, unknown>).event === "crypto" ||
							(payloadObj as Record<string, unknown>).event === "key_exchange"),
					);
					const isWs = Boolean(
						payloadObj &&
						((payloadObj as Record<string, unknown>).type === "ws" ||
							(payloadObj as Record<string, unknown>).type === "websocket" ||
							(payloadObj as Record<string, unknown>).event === "ws" ||
							(payloadObj as Record<string, unknown>).event === "websocket"),
					);
					const isConsole = Boolean(
						payloadObj &&
						((payloadObj as Record<string, unknown>).type === "console" ||
							(payloadObj as Record<string, unknown>).type === "log" ||
							(payloadObj as Record<string, unknown>).event === "console"),
					);
					const isJni = Boolean(
						payloadObj &&
						((payloadObj as Record<string, unknown>).event === "jni_register_natives" ||
							(payloadObj as Record<string, unknown>).event === "jni_register"),
					);
					const isNativeTrace = Boolean(
						payloadObj &&
						((payloadObj as Record<string, unknown>).event === "native_call" ||
							(payloadObj as Record<string, unknown>).event === "native_functions"),
					);
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "message",
						channel: "send",
						payload: parsedRecord.payload,
						raw: trimmed,
						metadata: {
							...(isCrypto ? { category: "crypto", subChannel: "crypto" } : {}),
							...(isWs ? { category: "ws", subChannel: "ws" } : {}),
							...(isConsole ? { category: "console", subChannel: "console" } : {}),
							...(isJni ? { category: "jni", subChannel: "jni" } : {}),
							...(isNativeTrace ? { category: "native_trace", subChannel: "native_trace" } : {}),
							...(structured.data !== null && structured.data !== undefined ? { data: structured.data } : {}),
						},
					});
				} else if (
					parsed &&
					typeof parsed === "object" &&
					!Array.isArray(parsed) &&
					((parsed as Record<string, unknown>).type === "log" ||
						(parsed as Record<string, unknown>).type === "console")
				) {
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "stdout",
						channel: "console",
						payload:
							"payload" in (parsed as Record<string, unknown>)
								? (parsed as Record<string, unknown>).payload
								: parsed,
						raw: trimmed,
					});
				} else if (
					parsed &&
					typeof parsed === "object" &&
					!Array.isArray(parsed) &&
					((parsed as Record<string, unknown>).type === "error" ||
						(parsed as Record<string, unknown>).type === "exception")
				) {
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "stderr",
						channel: "error",
						payload:
							"description" in (parsed as Record<string, unknown>)
								? (parsed as Record<string, unknown>).description
								: "payload" in (parsed as Record<string, unknown>)
									? (parsed as Record<string, unknown>).payload
									: parsed,
						raw: trimmed,
					});
				} else if (
					parsed &&
					typeof parsed === "object" &&
					!Array.isArray(parsed) &&
					(parsed as Record<string, unknown>).type === "crypto"
				) {
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "message",
						channel: "crypto",
						payload:
							"payload" in (parsed as Record<string, unknown>)
								? (parsed as Record<string, unknown>).payload
								: parsed,
						raw: trimmed,
						metadata: { category: "crypto", subChannel: "crypto" },
					});
				} else if (
					parsed &&
					typeof parsed === "object" &&
					!Array.isArray(parsed) &&
					((parsed as Record<string, unknown>).type === "ws" ||
						(parsed as Record<string, unknown>).type === "websocket")
				) {
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "message",
						channel: "ws",
						payload:
							"payload" in (parsed as Record<string, unknown>)
								? (parsed as Record<string, unknown>).payload
								: parsed,
						raw: trimmed,
						metadata: { category: "ws", subChannel: "ws" },
					});
				} else {
					const channel =
						parsed &&
						typeof parsed === "object" &&
						!Array.isArray(parsed) &&
						typeof (parsed as Record<string, unknown>).type === "string"
							? ((parsed as Record<string, unknown>).type as string)
							: "message";
					events.push({
						id: `ev_${sessionId}_${currentSeq}`,
						seq: currentSeq,
						timestamp,
						sessionId,
						kind: "message",
						channel,
						payload: parsed,
						raw: trimmed,
					});
				}
				continue;
			}

			const consoleMatch = trimmed.match(/^(?:console(?:\.log)?:\s*|\[console\]\s*)(.*)$/i);
			if (consoleMatch) {
				currentSeq++;
				events.push({
					id: `ev_${sessionId}_${currentSeq}`,
					seq: currentSeq,
					timestamp,
					sessionId,
					kind: "stdout",
					channel: "console",
					payload: consoleMatch[1],
					raw: trimmed,
				});
				continue;
			}

			// Check for trace marker
			if (trimmed.includes("__FRIDA_TRACE_START__")) {
				currentSeq++;
				let tracePayload: unknown = trimmed;
				const startIdx = trimmed.indexOf("__FRIDA_TRACE_START__");
				const endIdx = trimmed.indexOf("__FRIDA_TRACE_END__");
				if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
					const jsonStr = trimmed.slice(startIdx + "__FRIDA_TRACE_START__".length, endIdx).trim();
					try {
						tracePayload = JSON.parse(jsonStr);
					} catch {
						try {
							tracePayload = parsePythonLiteral(jsonStr, 0, { requireEnd: true }).value;
						} catch {}
					}
				}
				const isJni = Boolean(
					tracePayload &&
					typeof tracePayload === "object" &&
					((tracePayload as Record<string, unknown>).event === "jni_register_natives" ||
						(tracePayload as Record<string, unknown>).event === "jni_register"),
				);
				const isNativeTrace = Boolean(
					tracePayload &&
					typeof tracePayload === "object" &&
					((tracePayload as Record<string, unknown>).event === "native_call" ||
						(tracePayload as Record<string, unknown>).event === "native_functions"),
				);
				events.push({
					id: `ev_${sessionId}_${currentSeq}`,
					seq: currentSeq,
					timestamp,
					sessionId,
					kind: "trace",
					channel: "trace",
					payload: tracePayload,
					raw: trimmed,
					metadata: {
						...(isJni ? { category: "jni", subChannel: "jni" } : {}),
						...(isNativeTrace ? { category: "native_trace", subChannel: "native_trace" } : {}),
					},
				});
				continue;
			}
			if (trimmed.startsWith("/*") || /0x[0-9a-fA-F]+\s+call\s+/.test(trimmed)) {
				currentSeq++;
				events.push({
					id: `ev_${sessionId}_${currentSeq}`,
					seq: currentSeq,
					timestamp,
					sessionId,
					kind: "trace",
					channel: "trace",
					payload: trimmed,
					raw: trimmed,
				});
				continue;
			}

			// Standard stdout console message
			currentSeq++;
			events.push({
				id: `ev_${sessionId}_${currentSeq}`,
				seq: currentSeq,
				timestamp,
				sessionId,
				kind: "stdout",
				channel: "console",
				payload: trimmed,
				raw: trimmed,
			});
		}
	}

	// 3. Parse stderr lines
	if (stderr && stderr.length > 0) {
		const errLines = stderr.split(/\r?\n/);
		for (const errLine of errLines) {
			const trimmedErr = errLine.trim();
			if (!trimmedErr) continue;

			currentSeq++;
			events.push({
				id: `ev_${sessionId}_${currentSeq}`,
				seq: currentSeq,
				timestamp,
				sessionId,
				kind: "stderr",
				channel: "error",
				payload: trimmedErr,
				raw: trimmedErr,
			});
		}
	}

	// 4. Lifecycle finish event if exitCode is provided
	if (context.exitCode !== undefined) {
		currentSeq++;
		events.push({
			id: `ev_${sessionId}_${currentSeq}`,
			seq: currentSeq,
			timestamp,
			sessionId,
			kind: "lifecycle",
			channel: "run_finish",
			payload: {
				exitCode: context.exitCode,
				durationMs: context.durationMs,
			},
			raw: `[lifecycle] run finished with exitCode ${context.exitCode}`,
		});
	}

	return { events, spawnedPid };
}

export function buildEvidenceReference(
	session: FridaSessionRecord,
	event: DynamicSessionEvent,
): DynamicEvidenceReference {
	const excerpt = event.raw || (typeof event.payload === "string" ? event.payload : JSON.stringify(event.payload));
	const targetDesc = String(session.target.value);
	let title = `Dynamic ${event.kind} [${event.channel || "event"}] on ${targetDesc}`;
	const locator = formatDynamicLocator(session.id, event.seq);
	let content = `Captured dynamic ${event.kind} event in Frida session '${session.id}' on target ${session.target.type}:${targetDesc}: ${
		typeof event.payload === "object" ? JSON.stringify(event.payload) : String(event.payload)
	}`;
	const metadata: Record<string, unknown> = {
		sessionId: session.id,
		seq: event.seq,
		kind: event.kind,
		channel: event.channel,
		timestamp: event.timestamp,
	};

	if (event.payload && typeof event.payload === "object") {
		const p = event.payload as Record<string, unknown>;
		if (p.event === "jni_register_natives" || p.event === "jni_register") {
			const className = String(p.class || "UnknownClass");
			const isConfirmed = p.status === "confirmed" || (p.status !== "rejected" && p.retval === 0);
			if (isConfirmed) {
				title = `JNI RegisterNatives: ${className}`;
				const methodCount = Array.isArray(p.methods) ? p.methods.length : Number(p.nMethods ?? 0);
				content = `Confirmed JNI RegisterNatives mapping for ${className} (${methodCount} methods, retval: ${p.retval ?? 0}, javaBridge: ${p.javaBridgeAvailable ?? false})`;
				metadata.confirmed = true;
				metadata.rejected = false;
				metadata.class = className;
				metadata.nMethods = p.nMethods;
				metadata.methods = p.methods;
				metadata.truncated = p.truncated;
			} else {
				title = `[Rejected] JNI RegisterNatives: ${className}`;
				content = `Rejected JNI RegisterNatives mapping for ${className} (retval: ${p.retval}, status: ${p.status || "rejected"})`;
				metadata.confirmed = false;
				metadata.rejected = true;
				metadata.retval = p.retval;
				metadata.class = className;
			}
		} else if (p.event === "native_call" || p.event === "native_functions") {
			const targetName = String(p.target || p.address || "unknown");
			const mod = p.module ? String(p.module) : "unknown";
			const off = p.offset ? String(p.offset) : "";
			title = `Native Call: ${targetName} [${mod}${off ? "+" + off : ""}]`;
			content = `Captured native function call to ${targetName} at address ${p.address ?? "unknown"} (${mod}${off ? "+" + off : ""})`;
			metadata.target = targetName;
			metadata.address = p.address;
			metadata.module = p.module;
			metadata.offset = p.offset;
			metadata.args = p.args;
			metadata.retval = p.retval;
		}
	}

	return {
		sourceTool: "frida_session",
		target: targetDesc,
		locator,
		kind: "fact",
		title,
		content,
		excerpt: excerpt ? excerpt.slice(0, 1000) : undefined,
		metadata,
	};
}

export function sanitizeRecordSecrets(record: FridaSessionRecord): FridaSessionRecord {
	return {
		...record,
		lastScript: record.lastScript ? sanitizeSessionText(record.lastScript) : undefined,
		loadedScript: record.loadedScript ? sanitizeSessionText(record.loadedScript) : undefined,
		history: record.history.map(entry => ({
			...entry,
			scriptSnippet: entry.scriptSnippet ? sanitizeSessionText(entry.scriptSnippet) : undefined,
			error: entry.error ? sanitizeSessionText(entry.error) : undefined,
		})),
		metadata: record.metadata
			? (JSON.parse(sanitizeSessionText(JSON.stringify(record.metadata))) as Record<string, unknown>)
			: undefined,
		events: record.events
			? record.events.map(ev => ({
					...ev,
					raw: ev.raw ? sanitizeSessionText(ev.raw) : undefined,
					payload:
						typeof ev.payload === "string"
							? sanitizeSessionText(ev.payload)
							: ev.payload && typeof ev.payload === "object"
								? (JSON.parse(sanitizeSessionText(JSON.stringify(ev.payload))) as unknown)
								: ev.payload,
				}))
			: undefined,
	};
}

export class FridaSessionStore {
	readonly projectDirectory: string;

	constructor(projectDirectory: string) {
		this.projectDirectory = projectDirectory;
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

	async save(record: FridaSessionRecord): Promise<void> {
		await this.ensureDir();
		const targetPath = this.filePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7()}.${Math.random().toString(36).slice(2)}.tmp`;
		const sanitized = sanitizeRecordSecrets(record);
		const json = JSON.stringify(sanitized, null, 2);
		await Bun.write(tempPath, json);
		if (process.platform !== "win32") {
			await fs.chmod(tempPath, 0o600).catch(() => undefined);
		}
		await replaceFileAtomically(tempPath, targetPath);
	}

	async get(sessionId: string): Promise<FridaSessionRecord | null> {
		const targetPath = this.filePath(sessionId);
		try {
			const text = await Bun.file(targetPath).text();
			return JSON.parse(text) as FridaSessionRecord;
		} catch (error) {
			if (isEnoent(error)) return null;
			throw error;
		}
	}

	async delete(sessionId: string): Promise<boolean> {
		const targetPath = this.filePath(sessionId);
		try {
			await fs.unlink(targetPath);
			return true;
		} catch (error) {
			if (isEnoent(error)) return false;
			throw error;
		}
	}

	async list(): Promise<FridaSessionRecord[]> {
		await this.ensureDir();
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: FridaSessionRecord[] = [];
			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				try {
					const text = await Bun.file(path.join(this.projectDirectory, entry.name)).text();
					records.push(JSON.parse(text) as FridaSessionRecord);
				} catch {
					// Skip damaged entry
				}
			}
			records.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
			return records;
		} catch (error) {
			if (isEnoent(error)) return [];
			throw error;
		}
	}
}

export class FridaSessionTool implements AgentTool<typeof fridaSessionSchema, FridaSessionDetails> {
	readonly name = "frida_session";
	readonly description = fridaSessionDescription;
	readonly label = "Frida Session";
	readonly parameters = fridaSessionSchema;
	readonly schema = fridaSessionSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly which: SkillRequirementWhich;
	private readonly runner: FridaRunner;
	private readonly stateRoot?: string;

	constructor(
		private readonly session: ToolSession,
		options: FridaSessionToolOptions = {},
	) {
		this.which = options.which ?? $which;
		this.runner = options.runner ?? defaultFridaRunner;
		this.stateRoot = options.stateRoot;
		ensureExitHook();
	}

	private getStore(): FridaSessionStore {
		const projectKey = encodeProjectKey(this.session.cwd);
		const baseDir = this.stateRoot
			? this.stateRoot.endsWith("frida-sessions") || this.stateRoot.endsWith("frida_sessions")
				? path.resolve(this.stateRoot)
				: path.join(path.resolve(this.stateRoot), "frida-sessions")
			: getFridaSessionsDir();
		const projectDir = path.join(baseDir, projectKey);
		return new FridaSessionStore(projectDir);
	}

	async execute(
		_toolCallId: string,
		params: FridaSessionParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<FridaSessionDetails, typeof fridaSessionSchema>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		throwIfAborted(signal);

		const action: FridaSessionAction =
			params.action ?? (params.script || params.script_path || params.command ? "run" : "list");
		const store = this.getStore();
		switch (action) {
			case "create":
				return this.handleCreate(params, store, signal);
			case "list":
				return this.handleList(params, store);
			case "status":
				return this.handleStatus(params, store, signal);
			case "run":
				return this.handleRun(params, store, signal);
			case "load":
				return this.handleLoad(params, store, signal);
			case "unload":
				return this.handleUnload(params, store, signal);
			case "rpc":
				return this.handleRpc(params, store, signal);
			case "resume":
				return this.handleResume(params, store, signal);
			case "events":
				return this.handleEvents(params, store, signal);
			case "stop":
				return this.handleStop(params, store);
			case "destroy":
				return this.handleDestroy(params, store);
			default:
				throw new ToolError(`Unsupported action: ${action}`);
		}
	}

	approval(args: unknown): ToolApprovalDecision {
		if (!args || typeof args !== "object") {
			return "exec";
		}
		const params = args as Partial<FridaSessionParams>;
		const action = params.action ?? (params.script || params.script_path || params.command ? "run" : "list");
		switch (action) {
			case "list":
			case "status":
				return "read";
			case "events":
				return params.clear ? "write" : "read";
			case "resume":
			case "load":
			case "unload":
			case "rpc":
			case "create":
			case "run":
			case "stop":
			case "destroy":
			default:
				return "exec";
		}
	}

	private async handleCreate(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		if (params.mode === "live") {
			return this.handleCreateLive(params, store, signal);
		}
		const targetCount = [params.pid !== undefined, Boolean(params.process), Boolean(params.spawn)].filter(
			Boolean,
		).length;
		if (targetCount === 0) {
			throw new ToolError("Must specify target: 'pid', 'process', or 'spawn'");
		}
		if (targetCount > 1) {
			throw new ToolError("Mutually exclusive: cannot provide more than one of 'pid', 'process', or 'spawn'");
		}

		const transportCount = [Boolean(params.usb), Boolean(params.device), Boolean(params.host)].filter(Boolean).length;
		if (transportCount > 1) {
			throw new ToolError("Mutually exclusive: cannot combine 'usb', 'device', or 'host'");
		}

		const dependency = fridaDependency(this.which);
		if (!dependency.available) {
			const fallback = resolveFridaFallback("exec", {
				process: params.process,
				pid: params.pid,
			});
			const installHint =
				dependency.installHint ?? "pipx install frida-tools (or python3 -m pip install --user frida-tools)";
			return {
				content: [
					{
						type: "text",
						text: [
							"frida_session: Frida tools are not available on this machine.",
							`Install: ${installHint}`,
							`Documentation: ${dependency.manualUrl ?? "https://frida.re/docs/installation/"}`,
							"",
							`Suggested fallback: ${fallback.suggestedFallback}`,
							"Alternative approaches:",
							...fallback.alternatives.map(a => `  - ${a}`),
						].join("\n"),
					},
				],
				details: {
					action: "create",
					status: "missing_dependency",
					dependency,
					fallback,
					error: "Frida CLI binary not found in PATH",
				},
			};
		}

		const sessionId = params.session_id?.trim() || `frida_sess_${Bun.randomUUIDv7().slice(0, 12)}`;
		const hasInitialScript = Boolean(params.script || params.script_path || params.template);
		const existing = await store.get(sessionId);
		if (existing && existing.status === "active" && !hasInitialScript) {
			return {
				content: [
					{
						type: "text",
						text: `Frida session '${sessionId}' is already active for target ${existing.target.type}:${existing.target.value}.`,
					},
				],
				details: {
					action: "create",
					status: "ok",
					sessionId,
					session: existing,
					target: String(existing.target.value),
					targetMode: existing.target.type,
				},
			};
		}

		const targetType: "pid" | "process" | "spawn" =
			params.pid !== undefined ? "pid" : params.process ? "process" : "spawn";
		const targetValue: string | number =
			params.pid !== undefined ? params.pid : params.process ? params.process.trim() : params.spawn!.trim();

		const target: FridaSessionTarget = {
			type: targetType,
			value: targetValue,
			...(params.pid !== undefined ? { pid: params.pid } : {}),
			...(params.process ? { process: params.process.trim() } : {}),
			...(params.spawn ? { spawn: params.spawn.trim() } : {}),
			...(params.usb ? { usb: true } : {}),
			...(params.device ? { device: params.device.trim() } : {}),
			...(params.host ? { host: params.host.trim() } : {}),
			...(params.pause !== undefined ? { pause: params.pause } : {}),
			...(params.no_pause !== undefined ? { noPause: params.no_pause } : {}),
		};

		let initialStdout = "";
		let initialStderr = "";
		let initialExitCode: number | null = 0;
		const initialHistory: FridaSessionRunEntry[] = [];
		let activeChildPid: number | undefined;

		if (hasInitialScript) {
			let scriptToRun = params.script;
			if (!scriptToRun && !params.script_path && params.template) {
				scriptToRun = resolveTemplateScript(params);
			}
			const runResult = await this.executeFridaRun(
				target,
				{
					script: scriptToRun,
					script_path: params.script_path,
					script_args: params.script_args,
					cli_args: params.cli_args,
					timeout: params.timeout,
					max_bytes: params.max_bytes,
				},
				signal,
			);
			initialStdout = runResult.stdout;
			initialStderr = runResult.stderr;
			initialExitCode = runResult.exitCode;
			initialHistory.push({
				id: Bun.randomUUIDv7().slice(0, 8),
				timestamp: new Date().toISOString(),
				command: "initial_script",
				scriptSnippet: (params.script ?? params.script_path ?? "").slice(0, 200),
				scriptSource: params.script_path ? "file" : "inline",
				scriptPath: params.script_path ? resolveScriptPath(params.script_path, this.session.cwd) : undefined,
				exitCode: runResult.exitCode,
				outputBytes: runResult.outputBytes,
				truncated: runResult.truncated,
				error: runResult.exitCode !== 0 ? runResult.stderr.trim() : undefined,
			});
		} else if (targetType === "spawn") {
			// Probe spawn target
			const probeResult = await this.executeFridaRun(
				target,
				{
					script: "console.log('__FRIDA_SPAWN_OK__:' + Process.id);",
					timeout: params.timeout ?? 10,
					max_bytes: params.max_bytes,
				},
				signal,
			);
			initialStdout = probeResult.stdout;
			initialStderr = probeResult.stderr;
			initialExitCode = probeResult.exitCode;
			const match = probeResult.stdout.match(/__FRIDA_SPAWN_OK__:(\d+)/);
			if (match) {
				activeChildPid = Number.parseInt(match[1], 10);
			}
		}

		let initialEvents: DynamicSessionEvent[] = [];
		if (hasInitialScript || targetType === "spawn") {
			const parsed = parseFridaOutputIntoEvents(sessionId, initialStdout, initialStderr, 0, {
				command: hasInitialScript ? "initial_script" : "spawn_probe",
				exitCode: initialExitCode,
			});
			initialEvents = parsed.events;
			if (parsed.spawnedPid && !activeChildPid) {
				activeChildPid = parsed.spawnedPid;
			}
		} else {
			initialEvents = [
				{
					id: `ev_${sessionId}_1`,
					seq: 1,
					timestamp: new Date().toISOString(),
					sessionId,
					kind: "lifecycle",
					channel: "session_create",
					payload: { targetType, targetValue, ...(params.name ? { name: params.name.trim() } : {}) },
					raw: `[lifecycle] session created for ${targetType}:${targetValue}`,
				},
			];
		}
		const now = new Date().toISOString();
		const record: FridaSessionRecord = {
			id: sessionId,
			...(params.name ? { name: params.name.trim() } : {}),
			target,
			status: initialExitCode === 0 ? "active" : "failed",
			createdAt: now,
			updatedAt: now,
			...(hasInitialScript ? { lastRunAt: now } : {}),
			runsCount: initialHistory.length,
			history: initialHistory,
			...(activeChildPid !== undefined ? { activeChildPid } : {}),
			...(hasInitialScript ? { lastScript: (params.script ?? params.script_path ?? "").slice(0, 500) } : {}),
			events: initialEvents,
			eventsCount: initialEvents.length,
		};

		await store.save(record);
		await this.syncToRuntimeSessionStore(record);

		const lines: string[] = [
			`Frida session '${sessionId}' created for target ${targetType}:${targetValue} (status: ${record.status}).`,
		];
		if (params.name) lines.push(`Name: ${params.name}`);
		if (target.usb) lines.push("Transport: USB / emulator");
		else if (target.device) lines.push(`Transport: device (${target.device})`);
		else if (target.host) lines.push(`Transport: remote host (${target.host})`);

		if (initialStdout.length > 0) {
			lines.push("", initialStdout.trimEnd());
		}
		if (initialStderr.length > 0) {
			lines.push(`[stderr]\n${initialStderr.trimEnd()}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "create",
				status: record.status === "active" ? "ok" : "error",
				sessionId,
				session: record,
				target: String(targetValue),
				targetMode: targetType,
				exitCode: initialExitCode,
				stdout: initialStdout,
				stderr: initialStderr,
				events: initialEvents,
				eventsCount: initialEvents.length,
				totalEvents: initialEvents.length,
			},
		};
	}
	private async handleCreateLive(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const targetCount = [params.pid !== undefined, Boolean(params.process), Boolean(params.spawn)].filter(
			Boolean,
		).length;
		if (targetCount === 0) {
			throw new ToolError("Must specify target: 'pid', 'process', or 'spawn'");
		}
		if (targetCount > 1) {
			throw new ToolError("Mutually exclusive: cannot provide more than one of 'pid', 'process', or 'spawn'");
		}

		const transportCount = [Boolean(params.usb), Boolean(params.device), Boolean(params.host)].filter(Boolean).length;
		if (transportCount > 1) {
			throw new ToolError("Mutually exclusive: cannot combine 'usb', 'device', or 'host'");
		}

		// Pre-validate initial script or script_path before starting worker process
		let initialScriptSource: string | undefined;
		if (params.script_path) {
			const resolved = resolveScriptPath(params.script_path, this.session.cwd);
			try {
				initialScriptSource = await Bun.file(resolved).text();
			} catch (err) {
				throw new ToolError(`Failed to read script_path file at '${resolved}': ${err}`);
			}
		} else if (params.script) {
			initialScriptSource = params.script;
		} else if (params.template) {
			initialScriptSource = resolveTemplateScript(params);
		}

		const liveDep = await probeFridaLiveDependency(this.which);
		if (!liveDep.available || !liveDep.pythonPath) {
			return {
				content: [
					{
						type: "text",
						text: [
							"frida_session: Frida Python toolchain is not available for persistent live mode.",
							`Error: ${liveDep.error ?? "No suitable Python interpreter with 'frida' package found."}`,
							`Install: ${liveDep.installHint ?? "pipx install frida-tools (or python3 -m pip install --user frida)"}`,
							`Documentation: ${liveDep.manualUrl ?? "https://frida.re/docs/installation/"}`,
						].join("\n"),
					},
				],
				details: {
					action: "create",
					status: "missing_dependency",
					mode: "live",
					dependency: liveDep,
					error: liveDep.error ?? "Frida Python toolchain not found",
				},
			};
		}

		const targetType: "pid" | "process" | "spawn" =
			params.pid !== undefined ? "pid" : params.process ? "process" : "spawn";
		const targetValue: string | number =
			params.pid !== undefined ? params.pid : params.process ? params.process.trim() : params.spawn!.trim();

		const target: FridaSessionTarget = {
			type: targetType,
			value: targetValue,
			...(params.pid !== undefined ? { pid: params.pid } : {}),
			...(params.process ? { process: params.process.trim() } : {}),
			...(params.spawn ? { spawn: params.spawn.trim() } : {}),
			...(params.usb ? { usb: true } : {}),
			...(params.device ? { device: params.device.trim() } : {}),
			...(params.host ? { host: params.host.trim() } : {}),
			...(params.pause !== undefined ? { pause: params.pause } : {}),
			...(params.no_pause !== undefined ? { noPause: params.no_pause } : {}),
		};

		const sessionId = params.session_id
			? params.session_id.trim()
			: `frida_live_${Bun.randomUUIDv7()}_${Math.random().toString(36).slice(2, 8)}`;
		const projectKey = encodeProjectKey(this.session.cwd);
		const sessionKey = getLiveSessionKey(projectKey, sessionId);

		const existing = ACTIVE_LIVE_SESSIONS.get(sessionKey);
		if (existing) {
			existing.disposed = true;
			existing.client.onEvent(undefined);
			await persistLiveSessionContext(existing, true);
			try {
				await existing.client.stop(2000);
			} catch {}
			existing.client.destroy();
			ACTIVE_LIVE_SESSIONS.delete(sessionKey);
		}

		const client = new FridaLiveClient({
			pythonPath: liveDep.pythonPath,
			cwd: this.session.cwd,
		});

		await client.start();

		const timeoutMs = (params.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
		let initRes: FridaLiveInitResult;
		try {
			initRes = await client.init(target, timeoutMs, signal);
		} catch (err) {
			client.destroy();
			return {
				content: [
					{ type: "text", text: `Failed to attach to target ${targetType}:${targetValue}: ${String(err)}` },
				],
				details: {
					action: "create",
					status: "error",
					sessionId,
					mode: "live",
					error: String(err),
				},
			};
		}

		const now = new Date().toISOString();
		const initialEvents: DynamicSessionEvent[] = [
			{
				id: `ev_${sessionId}_1`,
				seq: 1,
				timestamp: now,
				sessionId,
				kind: "lifecycle",
				channel: "session_create",
				payload: { targetType, targetValue, pid: initRes.pid ?? params.pid, mode: "live" },
				raw: `[lifecycle] live session created for ${targetType}:${targetValue} (pid: ${initRes.pid ?? params.pid})`,
			},
		];

		const record: FridaSessionRecord = {
			id: sessionId,
			...(params.name ? { name: params.name.trim() } : {}),
			mode: "live",
			liveStatus: "connected",
			target,
			status: "active",
			createdAt: now,
			updatedAt: now,
			runsCount: 0,
			history: [],
			activeChildPid: initRes.pid ?? params.pid,
			events: initialEvents,
			eventsCount: 1,
		};

		const liveCtx: FridaLiveContext = {
			sessionId,
			projectKey,
			client,
			record,
			store,
			syncToRuntime: r => this.syncToRuntimeSessionStore(r),
			hasPendingSave: false,
			isWritingSave: false,
			disposed: false,
			flushResolvers: [],
		};

		ACTIVE_LIVE_SESSIONS.set(sessionKey, liveCtx);

		client.onEvent(eventFrame => {
			if (liveCtx.disposed) return;
			const seq = (record.eventsCount ?? record.events?.length ?? 0) + 1;
			record.eventsCount = seq;
			const newEv: DynamicSessionEvent = {
				id: `ev_${sessionId}_${seq}`,
				seq,
				timestamp: eventFrame.timestamp || new Date().toISOString(),
				sessionId,
				kind: eventFrame.kind,
				channel: eventFrame.channel,
				payload: eventFrame.payload,
				raw: eventFrame.raw,
				...(eventFrame.metadata ? { metadata: eventFrame.metadata } : {}),
			};
			if (!record.events) record.events = [];
			record.events.push(newEv);
			if (record.events.length > 500) {
				record.events = record.events.slice(-500);
			}
			record.updatedAt = new Date().toISOString();

			if (eventFrame.kind === "lifecycle" && eventFrame.channel === "detached") {
				record.status = "stopped";
				record.liveStatus = "detached";
			}

			persistLiveSessionContext(liveCtx, false);
		});

		let loadRes: FridaLiveLoadResult | undefined;
		if (initialScriptSource) {
			try {
				loadRes = await client.load(initialScriptSource, "initial_script", timeoutMs, signal);
				record.loadedScript = initialScriptSource;
				record.lastScript = initialScriptSource.slice(0, 500);
				record.rpcExports = loadRes.exports;
				record.runsCount = 1;
				record.history.push({
					id: Bun.randomUUIDv7(),
					timestamp: new Date().toISOString(),
					command: "load:initial_script",
					scriptSnippet: initialScriptSource.slice(0, 200),
					scriptSource: params.script_path ? "file" : "inline",
					scriptPath: params.script_path ? resolveScriptPath(params.script_path, this.session.cwd) : undefined,
					exitCode: 0,
				});
			} catch (err) {
				record.status = "error";
				record.history.push({
					id: Bun.randomUUIDv7(),
					timestamp: new Date().toISOString(),
					command: "load:initial_script",
					error: String(err),
				});
			}
		}

		// Auto-resume spawned target after initial script loaded (unless paused explicitly)
		if (targetType === "spawn" && target.pause !== true && target.noPause !== false) {
			try {
				await client.resume(timeoutMs, signal);
			} catch (err) {
				logger.warn(`Failed to auto-resume spawned target for ${sessionId}`, { error: String(err) });
			}
		}

		await persistLiveSessionContext(liveCtx, true);

		const lines: string[] = [
			`Frida persistent live session '${sessionId}' created for target ${targetType}:${targetValue} (pid: ${initRes.pid ?? params.pid ?? "attached"}).`,
			`Mode: live (persistent worker process)`,
		];
		if (params.name) lines.push(`Name: ${params.name}`);
		if (loadRes) {
			lines.push(`Script loaded successfully. Exports: [${loadRes.exports.join(", ")}]`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "create",
				status: record.status === "active" ? "ok" : "error",
				sessionId,
				mode: "live",
				liveStatus: record.liveStatus,
				session: record,
				target: String(targetValue),
				targetMode: targetType,
				exports: loadRes?.exports,
				events: record.events,
				eventsCount: record.events?.length ?? 0,
				totalEvents: record.events?.length ?? 0,
			},
		};
	}

	private async handleLoad(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id ? `Frida session '${params.session_id}' not found.` : "No Frida session found.",
			);
		}
		if (session.mode !== "live") {
			throw new ToolError(
				`Session '${session.id}' is in batch mode. Action 'load' is only supported on live mode sessions.`,
			);
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (!liveCtx || liveCtx.disposed || liveCtx.client.exited) {
			session.status = "stopped";
			session.liveStatus = "disconnected";
			session.updatedAt = new Date().toISOString();
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [
					{
						type: "text",
						text: `Frida live session '${session.id}' is disconnected. Reconnect with action: 'create', mode: 'live', session_id: '${session.id}'.`,
					},
				],
				details: {
					action: "load",
					status: "stopped",
					sessionId: session.id,
					mode: "live",
					liveStatus: "disconnected",
					error: "Worker process is not active",
				},
			};
		}

		let scriptSource = params.script;
		if (!scriptSource && params.script_path) {
			const resolved = resolveScriptPath(params.script_path, this.session.cwd);
			try {
				scriptSource = await Bun.file(resolved).text();
			} catch (err) {
				throw new ToolError(`Failed to read script_path file at '${resolved}': ${err}`);
			}
		} else if (!scriptSource && params.template) {
			scriptSource = resolveTemplateScript(params);
		}
		if (!scriptSource) {
			throw new ToolError("Must provide 'script', 'script_path', or 'template' for action: 'load'");
		}

		const timeoutMs = (params.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
		const loadRes = await liveCtx.client.load(scriptSource, "user_script", timeoutMs, signal);

		const now = new Date().toISOString();
		liveCtx.record.loadedScript = scriptSource;
		liveCtx.record.lastScript = scriptSource.slice(0, 500);
		liveCtx.record.rpcExports = loadRes.exports;
		liveCtx.record.updatedAt = now;
		liveCtx.record.lastRunAt = now;
		liveCtx.record.runsCount++;
		liveCtx.record.history.push({
			id: Bun.randomUUIDv7(),
			timestamp: now,
			command: "load",
			scriptSnippet: scriptSource.slice(0, 200),
			scriptSource: params.script_path ? "file" : "inline",
			scriptPath: params.script_path ? resolveScriptPath(params.script_path, this.session.cwd) : undefined,
			exitCode: 0,
		});

		await persistLiveSessionContext(liveCtx, true);

		return {
			content: [
				{
					type: "text",
					text: `Frida live session '${session.id}': script loaded/hot-reloaded successfully.\nExports: [${loadRes.exports.join(", ")}]`,
				},
			],
			details: {
				action: "load",
				status: "ok",
				sessionId: session.id,
				mode: "live",
				liveStatus: session.liveStatus,
				session: liveCtx.record,
				exports: loadRes.exports,
			},
		};
	}

	private async handleUnload(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id ? `Frida session '${params.session_id}' not found.` : "No Frida session found.",
			);
		}
		if (session.mode !== "live") {
			throw new ToolError(
				`Session '${session.id}' is in batch mode. Action 'unload' is only supported on live mode sessions.`,
			);
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (!liveCtx || liveCtx.disposed || liveCtx.client.exited) {
			session.status = "stopped";
			session.liveStatus = "disconnected";
			session.updatedAt = new Date().toISOString();
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [
					{
						type: "text",
						text: `Frida live session '${session.id}' is disconnected.`,
					},
				],
				details: {
					action: "unload",
					status: "stopped",
					sessionId: session.id,
					mode: "live",
					liveStatus: "disconnected",
				},
			};
		}

		const timeoutMs = (params.timeout ?? 10) * 1000;
		await liveCtx.client.unload(timeoutMs, signal);

		const now = new Date().toISOString();
		liveCtx.record.loadedScript = undefined;
		liveCtx.record.rpcExports = [];
		liveCtx.record.updatedAt = now;
		liveCtx.record.history.push({
			id: Bun.randomUUIDv7(),
			timestamp: now,
			command: "unload",
			exitCode: 0,
		});

		await persistLiveSessionContext(liveCtx, true);

		return {
			content: [{ type: "text", text: `Frida live session '${session.id}': script unloaded, hooks removed.` }],
			details: {
				action: "unload",
				status: "ok",
				sessionId: session.id,
				mode: "live",
				liveStatus: session.liveStatus,
				session: liveCtx.record,
			},
		};
	}

	private async handleRpc(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id ? `Frida session '${params.session_id}' not found.` : "No Frida session found.",
			);
		}
		if (!params.rpc_method) {
			throw new ToolError("Must provide 'rpc_method' for action: 'rpc'");
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (!liveCtx || liveCtx.disposed || liveCtx.client.exited) {
			session.status = "stopped";
			session.liveStatus = "disconnected";
			session.updatedAt = new Date().toISOString();
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [
					{
						type: "text",
						text: `Frida live session '${session.id}' is disconnected. Cannot execute RPC.`,
					},
				],
				details: {
					action: "rpc",
					status: "stopped",
					sessionId: session.id,
					mode: "live",
					liveStatus: "disconnected",
					error: "Worker process is not active",
				},
			};
		}

		const timeoutMs = (params.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
		const rpcRes = await liveCtx.client.rpc(params.rpc_method, params.rpc_args, timeoutMs, signal);

		const now = new Date().toISOString();
		liveCtx.record.runsCount++;
		liveCtx.record.lastRunAt = now;
		liveCtx.record.updatedAt = now;
		liveCtx.record.history.push({
			id: Bun.randomUUIDv7(),
			timestamp: now,
			command: `rpc:${params.rpc_method}`,
			exitCode: 0,
		});

		await persistLiveSessionContext(liveCtx, true);

		const textResult = typeof rpcRes.result === "string" ? rpcRes.result : JSON.stringify(rpcRes.result, null, 2);

		return {
			content: [
				{
					type: "text",
					text: `Frida live session '${session.id}' RPC [${params.rpc_method}] result:\n${textResult}`,
				},
			],
			details: {
				action: "rpc",
				status: "ok",
				sessionId: session.id,
				mode: "live",
				liveStatus: session.liveStatus,
				session: liveCtx.record,
				rpcResult: rpcRes.result,
			},
		};
	}

	private async handleResume(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id ? `Frida session '${params.session_id}' not found.` : "No Frida session found.",
			);
		}
		if (session.mode !== "live") {
			throw new ToolError("Action 'resume' is only supported on live mode sessions.");
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (!liveCtx || liveCtx.disposed || liveCtx.client.exited) {
			session.status = "stopped";
			session.liveStatus = "disconnected";
			session.updatedAt = new Date().toISOString();
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [{ type: "text", text: `Frida live session '${session.id}' is disconnected.` }],
				details: {
					action: "resume",
					status: "stopped",
					sessionId: session.id,
					mode: "live",
					liveStatus: "disconnected",
				},
			};
		}

		const res = await liveCtx.client.resume(10_000, signal);
		const now = new Date().toISOString();
		liveCtx.record.updatedAt = now;
		liveCtx.record.history.push({
			id: Bun.randomUUIDv7(),
			timestamp: now,
			command: "resume",
			exitCode: 0,
		});

		await persistLiveSessionContext(liveCtx, true);

		return {
			content: [
				{
					type: "text",
					text: `Frida live session '${session.id}' target resumed (pid: ${res.pid ?? session.activeChildPid}).`,
				},
			],
			details: {
				action: "resume",
				status: "ok",
				sessionId: session.id,
				mode: "live",
				liveStatus: session.liveStatus,
				session: liveCtx.record,
			},
		};
	}

	private async handleRunLive(
		session: FridaSessionRecord,
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (!liveCtx || liveCtx.disposed || liveCtx.client.exited) {
			session.status = "stopped";
			session.liveStatus = "disconnected";
			session.updatedAt = new Date().toISOString();
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [
					{
						type: "text",
						text: `Frida live session '${session.id}' is disconnected (process-local worker does not persist across restarts). Reconnect with action: 'create', mode: 'live', session_id: '${session.id}'.`,
					},
				],
				details: {
					action: "run",
					status: "stopped",
					sessionId: session.id,
					mode: "live",
					liveStatus: "disconnected",
					error: "Live session is disconnected",
				},
			};
		}

		const command = params.command ?? (params.script || params.script_path ? "script" : "inspect");
		if (command === "ps") {
			return this.handleRunPs(session, params, store, signal);
		}

		if (command === "inspect") {
			const inspectScript = `rpc.exports = { inspect: function() { try { return { pid: Process.id, arch: Process.arch, platform: Process.platform, pageSize: Process.pageSize, pointerSize: Process.pointerSize }; } catch(e) { return { error: e.message || String(e) }; } } };`;
			await this.handleLoad({ ...params, session_id: session.id, script: inspectScript }, store, signal);
			return this.handleRpc({ ...params, session_id: session.id, rpc_method: "inspect" }, store, signal);
		}

		let scriptSource = params.script;
		if (!scriptSource && params.script_path) {
			const resolved = resolveScriptPath(params.script_path, this.session.cwd);
			try {
				scriptSource = await Bun.file(resolved).text();
			} catch (err) {
				throw new ToolError(`Failed to read script_path file at '${resolved}': ${err}`);
			}
		} else if (!scriptSource && params.template) {
			scriptSource = resolveTemplateScript(params);
		}
		if (command === "modules" && !scriptSource) {
			scriptSource = FIXED_ENUMERATE_MODULES_SCRIPT;
		}

		if (!scriptSource) {
			throw new ToolError("Must provide 'script', 'script_path', 'template', or 'command' for run action");
		}

		return this.handleLoad({ ...params, session_id: session.id, script: scriptSource }, store, signal);
	}

	private async handleList(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const projectKey = encodeProjectKey(this.session.cwd);
		const records = await store.list();
		const updatedRecords: FridaSessionRecord[] = [];

		for (const record of records) {
			if (record.mode === "live") {
				const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, record.id));
				if (liveCtx && !liveCtx.disposed && !liveCtx.client.exited) {
					record.status = "active";
					record.liveStatus = "connected";
				} else {
					record.status = "stopped";
					record.liveStatus = "disconnected";
				}
				updatedRecords.push(record);
				continue;
			}
			if (
				!record.target.usb &&
				!record.target.device &&
				!record.target.host &&
				record.status === "active" &&
				record.activeChildPid
			) {
				if (!isProcessAlive(record.activeChildPid)) {
					record.status = "stopped";
					record.updatedAt = new Date().toISOString();
					await store.save(record);
				}
			}
			updatedRecords.push(record);
		}
		const filterText = params.filter?.toLowerCase().trim();
		const filtered = updatedRecords.filter(r => {
			if (!filterText) return true;
			return (
				r.id.toLowerCase().includes(filterText) ||
				r.name?.toLowerCase().includes(filterText) ||
				String(r.target.value).toLowerCase().includes(filterText) ||
				r.status.toLowerCase().includes(filterText)
			);
		});

		if (filtered.length === 0) {
			return {
				content: [{ type: "text", text: "No Frida sessions found." }],
				details: {
					action: "list",
					status: "ok",
					sessions: [],
				},
			};
		}

		const lines: string[] = [`Frida sessions (${filtered.length} found):`];
		for (const s of filtered) {
			const label = s.name ? `${s.id} (${s.name})` : s.id;
			const transport = s.target.usb ? " [USB]" : s.target.host ? ` [${s.target.host}]` : "";
			lines.push(
				`  - ${label}: ${s.target.type}=${s.target.value}${transport} | status=${s.status} | runs=${s.runsCount} | updated=${s.updatedAt}`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "list",
				status: "ok",
				sessions: filtered,
			},
		};
	}

	private async handleStatus(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [
					{
						type: "text",
						text: params.session_id
							? `Frida session '${params.session_id}' not found.`
							: "No active or existing Frida sessions found.",
					},
				],
				details: {
					action: "status",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (session.mode === "live" || liveCtx) {
			if (liveCtx && !liveCtx.disposed && !liveCtx.client.exited) {
				try {
					const liveStatusRes = await liveCtx.client.status(5000, signal);
					if (liveStatusRes.detached) {
						liveCtx.record.status = "stopped";
						liveCtx.record.liveStatus = "detached";
					} else {
						liveCtx.record.status = "active";
						liveCtx.record.liveStatus = "connected";
					}
					liveCtx.record.rpcExports = liveStatusRes.exports;
					if (liveStatusRes.pid) {
						liveCtx.record.activeChildPid = liveStatusRes.pid;
					}
				} catch {
					// Client probe error
				}
				liveCtx.record.updatedAt = new Date().toISOString();
				await persistLiveSessionContext(liveCtx, true);
			} else {
				session.status = "stopped";
				session.liveStatus = "disconnected";
				session.updatedAt = new Date().toISOString();
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
		} else if (session.status === "active" && session.activeChildPid) {
			if (!session.target.usb && !session.target.device && !session.target.host) {
				if (!isProcessAlive(session.activeChildPid)) {
					session.status = "stopped";
					session.updatedAt = new Date().toISOString();
					await store.save(session);
				}
			}
		}

		const lines: string[] = [
			`Frida session status: ${session.id}`,
			`Target: ${session.target.type}:${session.target.value}`,
			`Status: ${session.status}`,
			`Runs executed: ${session.runsCount}`,
			`Created: ${session.createdAt}`,
			`Updated: ${session.updatedAt}`,
		];
		if (session.name) lines.push(`Name: ${session.name}`);
		if (session.mode === "live") {
			lines.push(`Mode: live (persistent worker process)`);
			lines.push(`Live status: ${session.liveStatus ?? "disconnected"}`);
			if (session.rpcExports && session.rpcExports.length > 0) {
				lines.push(`RPC exports: [${session.rpcExports.join(", ")}]`);
			}
		}
		if (session.activeChildPid) lines.push(`Active PID: ${session.activeChildPid}`);
		if (session.lastRunAt) lines.push(`Last run: ${session.lastRunAt}`);
		if (session.lastScript) lines.push(`Last script snippet:\n  ${session.lastScript.replace(/\n/g, "\n  ")}`);

		if (session.history.length > 0) {
			lines.push("", `Recent history (${Math.min(session.history.length, 5)} runs):`);
			for (const h of session.history.slice(-5)) {
				lines.push(
					`  - [${h.timestamp}] exitCode=${h.exitCode ?? 0} bytes=${h.outputBytes ?? 0}: ${h.command ?? h.scriptSnippet?.slice(0, 60)}`,
				);
			}
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				status: "ok",
				sessionId: session.id,
				mode: session.mode,
				liveStatus: session.liveStatus,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
				exports: session.rpcExports,
			},
		};
	}

	private async handleRun(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id
					? `Frida session '${params.session_id}' not found.`
					: "No Frida session found. Create a session first using action: 'create'",
			);
		}

		if (session.mode === "live") {
			return this.handleRunLive(session, params, store, signal);
		}

		const dependency = fridaDependency(this.which);
		if (!dependency.available) {
			const fallback = resolveFridaFallback("exec", {
				process: session.target.process,
				pid: session.target.pid,
			});
			return {
				content: [
					{
						type: "text",
						text: [
							"frida_session: Frida tools are not available on this machine.",
							`Install: ${dependency.installHint ?? "pipx install frida-tools"}`,
							`Suggested fallback: ${fallback.suggestedFallback}`,
						].join("\n"),
					},
				],
				details: {
					action: "run",
					status: "missing_dependency",
					sessionId: session.id,
					session,
					dependency,
					fallback,
					error: "Frida CLI binary not found in PATH",
				},
			};
		}

		const command = params.command ?? (params.script || params.script_path ? "script" : "inspect");
		let scriptToRun: string | undefined = params.script;
		let scriptPathToRun: string | undefined = params.script_path;

		if (command === "modules") {
			scriptToRun = FIXED_ENUMERATE_MODULES_SCRIPT;
			scriptPathToRun = undefined;
		} else if (command === "inspect") {
			scriptToRun = INSPECT_TARGET_SCRIPT;
			scriptPathToRun = undefined;
		} else if (command === "ps") {
			// run frida-ps against session target device
			return this.handleRunPs(session, params, store, signal);
		} else if (!scriptToRun && !scriptPathToRun && params.template) {
			scriptToRun = resolveTemplateScript(params);
		} else if (!scriptToRun && !scriptPathToRun) {
			throw new ToolError("Must provide 'script', 'script_path', 'template', or 'command' for run action");
		}

		const maxBytes = params.max_bytes ?? DEFAULT_MAX_BYTES;
		const runResult = await this.executeFridaRun(
			session.target,
			{
				script: scriptToRun,
				script_path: scriptPathToRun,
				script_args: params.script_args,
				cli_args: params.cli_args,
				timeout: params.timeout,
				max_bytes: maxBytes,
				activeChildPid: session.activeChildPid,
			},
			signal,
		);

		const now = new Date().toISOString();
		const snippet = (scriptToRun ?? scriptPathToRun ?? command).slice(0, 300);
		const historyEntry: FridaSessionRunEntry = {
			id: Bun.randomUUIDv7().slice(0, 8),
			timestamp: now,
			command,
			scriptSnippet: snippet,
			scriptSource: scriptPathToRun ? "file" : "inline",
			scriptPath: scriptPathToRun ? resolveScriptPath(scriptPathToRun, this.session.cwd) : undefined,
			exitCode: runResult.exitCode,
			outputBytes: runResult.outputBytes,
			truncated: runResult.truncated,
			error: runResult.exitCode !== 0 ? runResult.stderr.trim() : undefined,
		};

		session.history.push(historyEntry);
		session.runsCount++;
		session.lastRunAt = now;
		session.updatedAt = now;
		session.lastScript = snippet;
		if (runResult.exitCode === 0 && session.status !== "active") {
			session.status = "active";
		}

		const existingSeq = session.eventsCount ?? (session.events ? session.events.length : 0);
		const { events: newEvents, spawnedPid } = parseFridaOutputIntoEvents(
			session.id,
			runResult.stdout,
			runResult.stderr,
			existingSeq,
			{
				command,
				exitCode: runResult.exitCode,
			},
		);

		if (spawnedPid && !session.activeChildPid) {
			session.activeChildPid = spawnedPid;
		}

		session.events = appendEventsToBuffer(session.events, newEvents);
		session.eventsCount = existingSeq + newEvents.length;

		await store.save(session);
		await this.syncToRuntimeSessionStore(session);

		let evidenceRefs: DynamicEvidenceReference[] | undefined;
		if (params.export_evidence) {
			evidenceRefs = newEvents.map(ev => buildEvidenceReference(session, ev));
			try {
				const evidenceStore = new EvidenceStore({ repositoryRoot: this.session.cwd, stateRoot: this.stateRoot });
				for (const ref of evidenceRefs) {
					if (ref.metadata?.confirmed !== false) {
						await evidenceStore.addFact({
							kind: "fact",
							sourceTool: "frida_session",
							target: ref.target,
							locator: ref.locator,
							title: ref.title,
							content: ref.content,
							excerpt: ref.excerpt,
							tags: ref.metadata?.class ? [String(ref.metadata.class)] : undefined,
						});
					}
				}
			} catch (err) {
				logger.warn(`Failed to export evidence to ledger: ${err}`);
			}
		}

		let artifactId: string | undefined;
		let artifactPath: string | undefined;
		if (params.to_artifact && this.session.allocateOutputArtifact) {
			try {
				const allocation = await this.session.allocateOutputArtifact("frida_session");
				if (allocation?.path && allocation.id) {
					artifactId = allocation.id;
					artifactPath = allocation.path;
					const recordToSave = {
						sessionId: session.id,
						target: session.target,
						command,
						stdout: runResult.stdout,
						stderr: runResult.stderr,
						exitCode: runResult.exitCode,
						executedAt: now,
						evidence: evidenceRefs,
						events: newEvents,
					};
					await Bun.write(artifactPath, JSON.stringify(recordToSave, null, 2));
				}
			} catch (err) {
				logger.warn(`Failed to allocate artifact: ${err}`);
			}
		}

		const lines: string[] = [];
		if (runResult.exitCode === 0) {
			lines.push(`frida_session run succeeded on ${session.id} (${session.target.type}:${session.target.value}):`);
		} else if (runResult.timedOut) {
			lines.push(`frida_session run timed out on ${session.id}:`);
		} else {
			lines.push(`frida_session run failed on ${session.id} (exit code ${runResult.exitCode}):`);
		}

		if (runResult.stdout.length > 0) {
			lines.push(runResult.stdout.trimEnd());
		}
		if (runResult.stderr.length > 0) {
			lines.push(`[stderr]\n${runResult.stderr.trimEnd()}`);
		}
		if (runResult.truncated) {
			lines.push(`\n… output truncated at ${maxBytes} bytes; full record preserved in session.`);
		}
		if (evidenceRefs && evidenceRefs.length > 0) {
			lines.push("", "--- Evidence Ledger References ---");
			for (const ref of evidenceRefs.slice(0, 5)) {
				lines.push(`- [${ref.locator}] ${ref.title}: ${ref.excerpt?.slice(0, 100)}`);
			}
			if (evidenceRefs.length > 5) {
				lines.push(`... and ${evidenceRefs.length - 5} more evidence references.`);
			}
		}
		if (artifactId) {
			lines.push(`Full execution record saved to artifact: ${artifactId}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "run",
				status: runResult.exitCode === 0 ? "ok" : runResult.timedOut ? "timeout" : "error",
				sessionId: session.id,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
				exitCode: runResult.exitCode,
				stdout: runResult.stdout,
				stderr: runResult.stderr,
				outputBytes: runResult.outputBytes,
				truncated: runResult.truncated,
				timedOut: runResult.timedOut,
				events: newEvents,
				eventsCount: newEvents.length,
				totalEvents: session.events?.length ?? 0,
				...(evidenceRefs ? { evidence: evidenceRefs } : {}),
				...(artifactId ? { artifactId } : {}),
				...(artifactPath ? { artifactPath } : {}),
			},
		};
	}

	private async handleEvents(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		throwIfAborted(signal);
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id
					? `Frida session '${params.session_id}' not found.`
					: "No Frida session found. Create a session first using action: 'create'",
			);
		}

		const allEvents = session.events ?? [];

		if (params.clear) {
			const count = allEvents.length;
			session.events = [];
			session.eventsCount = 0;
			session.updatedAt = new Date().toISOString();
			const projectKey = encodeProjectKey(this.session.cwd);
			const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
			if (liveCtx && !liveCtx.disposed) {
				await persistLiveSessionContext(liveCtx, true);
			} else {
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
			return {
				content: [{ type: "text", text: `Cleared ${count} events from session '${session.id}'.` }],
				details: {
					action: "events",
					status: "ok",
					sessionId: session.id,
					session,
					events: [],
					eventsCount: 0,
					totalEvents: 0,
				},
			};
		}

		let filtered = allEvents;

		if (typeof params.since_seq === "number") {
			filtered = filtered.filter(e => e.seq > params.since_seq!);
		}

		if (params.kind) {
			const k = params.kind.toLowerCase().trim();
			filtered = filtered.filter(e => {
				if (k === "send") {
					return e.channel?.toLowerCase() === "send";
				}
				if (k === "message") {
					return e.kind.toLowerCase() === "message" || e.channel?.toLowerCase() === "send";
				}
				if (k === "console" || k === "stdout") {
					return e.kind.toLowerCase() === "stdout" || e.channel?.toLowerCase() === "console";
				}
				if (k === "error" || k === "stderr") {
					return e.kind.toLowerCase() === "stderr" || e.channel?.toLowerCase() === "error";
				}
				if (k === "ws" || k === "websocket") {
					return (
						e.channel?.toLowerCase() === "ws" ||
						e.channel?.toLowerCase() === "websocket" ||
						e.metadata?.category === "ws" ||
						e.metadata?.subChannel === "ws" ||
						(typeof e.payload === "object" &&
							e.payload !== null &&
							((e.payload as Record<string, unknown>).type === "ws" ||
								(e.payload as Record<string, unknown>).type === "websocket" ||
								(e.payload as Record<string, unknown>).event === "ws"))
					);
				}
				if (k === "crypto") {
					return (
						e.channel?.toLowerCase() === "crypto" ||
						e.metadata?.category === "crypto" ||
						e.metadata?.subChannel === "crypto" ||
						(typeof e.payload === "object" &&
							e.payload !== null &&
							(Boolean((e.payload as Record<string, unknown>).cipher) ||
								Boolean((e.payload as Record<string, unknown>).algorithm) ||
								(e.payload as Record<string, unknown>).type === "crypto" ||
								(e.payload as Record<string, unknown>).event === "crypto" ||
								(e.payload as Record<string, unknown>).event === "key_exchange"))
					);
				}
				return e.kind.toLowerCase() === k;
			});
		}

		if (params.channel) {
			const ch = params.channel.toLowerCase().trim();
			filtered = filtered.filter(e => {
				if (e.channel?.toLowerCase() === ch) return true;
				if (ch === "send" && e.kind === "message") return true;
				if (ch === "console" && (e.kind === "stdout" || e.channel === "log")) return true;
				if (ch === "error" && e.kind === "stderr") return true;
				if (ch === "ws" || ch === "websocket") {
					return (
						e.channel?.toLowerCase() === "ws" ||
						e.channel?.toLowerCase() === "websocket" ||
						e.metadata?.category === "ws" ||
						e.metadata?.subChannel === "ws" ||
						(typeof e.payload === "object" &&
							e.payload !== null &&
							((e.payload as Record<string, unknown>).type === "ws" ||
								(e.payload as Record<string, unknown>).type === "websocket" ||
								(e.payload as Record<string, unknown>).event === "ws"))
					);
				}
				if (ch === "crypto") {
					return (
						e.channel?.toLowerCase() === "crypto" ||
						e.metadata?.category === "crypto" ||
						e.metadata?.subChannel === "crypto" ||
						(typeof e.payload === "object" &&
							e.payload !== null &&
							(Boolean((e.payload as Record<string, unknown>).cipher) ||
								Boolean((e.payload as Record<string, unknown>).algorithm) ||
								(e.payload as Record<string, unknown>).type === "crypto" ||
								(e.payload as Record<string, unknown>).event === "crypto" ||
								(e.payload as Record<string, unknown>).event === "key_exchange"))
					);
				}
				return false;
			});
		}

		if (params.filter) {
			const query = params.filter.toLowerCase().trim();
			filtered = filtered.filter(e => {
				const raw = (e.raw || "").toLowerCase();
				let payloadStr = "";
				try {
					payloadStr =
						typeof e.payload === "string" ? e.payload.toLowerCase() : JSON.stringify(e.payload).toLowerCase();
				} catch {}
				const channel = (e.channel || "").toLowerCase();
				const kind = (e.kind || "").toLowerCase();
				const category = (typeof e.metadata?.category === "string" ? e.metadata.category : "").toLowerCase();
				return (
					raw.includes(query) ||
					payloadStr.includes(query) ||
					channel.includes(query) ||
					kind.includes(query) ||
					category.includes(query)
				);
			});
		}

		const limit = Math.min(Math.max(params.limit ?? 50, 1), 500);
		const paged = filtered.slice(-limit);

		let evidenceRefs: DynamicEvidenceReference[] | undefined;
		if (params.export_evidence) {
			evidenceRefs = paged.map(ev => buildEvidenceReference(session, ev));
			try {
				const evidenceStore = new EvidenceStore({ repositoryRoot: this.session.cwd, stateRoot: this.stateRoot });
				for (const ref of evidenceRefs) {
					if (ref.metadata?.confirmed !== false) {
						await evidenceStore.addFact({
							kind: "fact",
							sourceTool: "frida_session",
							target: ref.target,
							locator: ref.locator,
							title: ref.title,
							content: ref.content,
							excerpt: ref.excerpt,
							tags: ref.metadata?.class ? [String(ref.metadata.class)] : undefined,
						});
					}
				}
			} catch (err) {
				logger.warn(`Failed to export evidence to ledger: ${err}`);
			}
		}

		let artifactId: string | undefined;
		let artifactPath: string | undefined;
		if (params.to_artifact && this.session.allocateOutputArtifact) {
			try {
				const allocation = await this.session.allocateOutputArtifact("frida_session_events");
				if (allocation?.path && allocation.id) {
					artifactId = allocation.id;
					artifactPath = allocation.path;
					const exportPayload = {
						sessionId: session.id,
						target: session.target,
						totalEvents: allEvents.length,
						matchedEvents: filtered.length,
						returnedEvents: paged.length,
						evidence: evidenceRefs,
						events: paged,
					};
					await Bun.write(artifactPath, JSON.stringify(exportPayload, null, 2));
				}
			} catch (err) {
				logger.warn(`Failed to allocate artifact for events: ${err}`);
			}
		}

		const lines: string[] = [
			`Frida session '${session.id}' events: showing ${paged.length} of ${filtered.length} matched (${allEvents.length} total buffered).`,
		];

		if (paged.length === 0) {
			lines.push("No events match the specified criteria.");
		} else {
			for (const ev of paged) {
				const ch = ev.channel ? `/${ev.channel}` : "";
				const payloadStr = typeof ev.payload === "string" ? ev.payload : JSON.stringify(ev.payload);
				lines.push(`[#${ev.seq} ${ev.kind}${ch} @ ${ev.timestamp}] ${payloadStr}`);
			}
		}

		if (evidenceRefs && evidenceRefs.length > 0) {
			lines.push("", "--- Evidence Ledger References ---");
			for (const ref of evidenceRefs.slice(0, 10)) {
				lines.push(`- [${ref.locator}] ${ref.title}: ${ref.excerpt?.slice(0, 120)}`);
			}
			if (evidenceRefs.length > 10) {
				lines.push(`... and ${evidenceRefs.length - 10} more evidence references.`);
			}
		}

		if (artifactId) {
			lines.push(`\nFull events exported to artifact: ${artifactId}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "events",
				status: "ok",
				sessionId: session.id,
				session,
				events: paged,
				eventsCount: paged.length,
				totalEvents: allEvents.length,
				...(evidenceRefs ? { evidence: evidenceRefs } : {}),
				...(artifactId ? { artifactId } : {}),
				...(artifactPath ? { artifactPath } : {}),
			},
		};
	}

	private async handleRunPs(
		session: FridaSessionRecord,
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const dependency = fridaDependency(this.which);
		const binary = dependency.fridaPsPath ?? dependency.path ?? "frida-ps";
		const args: string[] = [];
		if (session.target.usb) args.push("-U");
		else if (session.target.device) args.push("-D", session.target.device);
		else if (session.target.host) args.push("-H", session.target.host);

		if (params.cli_args) {
			const extra = Array.isArray(params.cli_args)
				? params.cli_args.map(String)
				: splitCliArgs(String(params.cli_args));
			args.push(...extra);
		}

		const maxBytes = params.max_bytes ?? DEFAULT_MAX_BYTES;
		const result = await this.runner(binary, args, {
			cwd: this.session.cwd,
			timeoutMs: (params.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000,
			maxBytes,
			signal,
		});

		const rawOutput = Buffer.from(result.stdout).toString("utf8");
		const now = new Date().toISOString();
		session.history.push({
			id: Bun.randomUUIDv7().slice(0, 8),
			timestamp: now,
			command: "ps",
			exitCode: result.exitCode,
			outputBytes: result.outputBytes,
		});
		session.runsCount++;
		session.lastRunAt = now;
		session.updatedAt = now;
		await store.save(session);

		return {
			content: [{ type: "text", text: rawOutput.trimEnd() }],
			details: {
				action: "run",
				status: result.exitCode === 0 ? "ok" : "error",
				sessionId: session.id,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
				exitCode: result.exitCode,
				stdout: rawOutput,
				stderr: result.stderr,
				outputBytes: result.outputBytes,
				truncated: result.truncated,
				timedOut: result.timedOut,
			},
		};
	}

	private async handleStop(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [{ type: "text", text: `Frida session '${params.session_id ?? "unknown"}' not found.` }],
				details: {
					action: "stop",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}
		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (session.mode === "live" || liveCtx) {
			if (liveCtx) {
				liveCtx.disposed = true;
				liveCtx.client.onEvent(undefined);
				try {
					await liveCtx.client.stop(5000);
				} catch {}
				liveCtx.client.destroy();
				ACTIVE_LIVE_SESSIONS.delete(getLiveSessionKey(projectKey, session.id));
				liveCtx.record.status = "stopped";
				liveCtx.record.liveStatus = "stopped";
				liveCtx.record.updatedAt = new Date().toISOString();
				await persistLiveSessionContext(liveCtx, true);
			} else {
				session.status = "stopped";
				session.liveStatus = "stopped";
				session.updatedAt = new Date().toISOString();
				await store.save(session);
				await this.syncToRuntimeSessionStore(session);
			}
		} else {
			stopActiveChild(session.id, session.activeChildPid);
			session.status = "stopped";
			session.updatedAt = new Date().toISOString();
			await store.save(session);
			await this.syncToRuntimeSessionStore(session);
		}

		return {
			content: [{ type: "text", text: `Frida session '${session.id}' stopped.` }],
			details: {
				action: "stop",
				status: "ok",
				sessionId: session.id,
				session,
			},
		};
	}

	private async handleDestroy(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [{ type: "text", text: `Frida session '${params.session_id ?? "unknown"}' not found.` }],
				details: {
					action: "destroy",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}

		const projectKey = encodeProjectKey(this.session.cwd);
		const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, session.id));
		if (session.mode === "live" || liveCtx) {
			if (liveCtx) {
				liveCtx.disposed = true;
				liveCtx.client.onEvent(undefined);
				await persistLiveSessionContext(liveCtx, true);
				try {
					liveCtx.client.destroy();
				} catch {}
				ACTIVE_LIVE_SESSIONS.delete(getLiveSessionKey(projectKey, session.id));
			}
		} else {
			stopActiveChild(session.id, session.activeChildPid);
		}
		await store.delete(session.id);
		try {
			const runtimeStore = ReverseRuntimeSessionStore.forSession(this.session.cwd, this.stateRoot);
			await runtimeStore.delete(session.id);
		} catch {}

		return {
			content: [{ type: "text", text: `Frida session '${session.id}' destroyed and removed.` }],
			details: {
				action: "destroy",
				status: "ok",
				sessionId: session.id,
			},
		};
	}

	private async resolveTargetSession(
		sessionId: string | undefined,
		store: FridaSessionStore,
	): Promise<FridaSessionRecord | null> {
		const projectKey = encodeProjectKey(this.session.cwd);
		if (sessionId && sessionId.trim().length > 0) {
			const id = sessionId.trim();
			const liveCtx = ACTIVE_LIVE_SESSIONS.get(getLiveSessionKey(projectKey, id));
			if (liveCtx && !liveCtx.disposed) return liveCtx.record;
			return store.get(id);
		}
		for (const [key, ctx] of ACTIVE_LIVE_SESSIONS) {
			if (key.startsWith(`${projectKey}:`) && !ctx.disposed && ctx.record.status === "active") {
				return ctx.record;
			}
		}
		const all = await store.list();
		if (all.length === 0) return null;
		const active = all.find(s => s.status === "active");
		return active ?? all[0];
	}
	private async syncToRuntimeSessionStore(session: FridaSessionRecord): Promise<void> {
		try {
			const runtimeStore = ReverseRuntimeSessionStore.forSession(this.session.cwd, this.stateRoot);
			const targetVal = String(session.target.value ?? session.target.process ?? session.target.pid ?? "");
			const recent = (session.events ?? []).slice(-50);
			const normalizedRecent: UniversalDynamicEvent[] = recent.map((ev, idx) =>
				normalizeFridaEvent(ev, session.id, {
					target: targetVal,
					seq: typeof ev.seq === "number" ? ev.seq : idx + 1,
					timestamp: ev.timestamp,
				}),
			);
			const runtimeRecord: RuntimeSessionRecord = {
				id: session.id,
				name: session.name || `Frida target ${session.target.type}:${targetVal}`,
				kind: "frida",
				status: session.status === "active" ? "active" : session.status === "stopped" ? "closed" : "unknown",
				target_summary: targetVal,
				target_details: { ...session.target },
				connection: {
					type: "frida_bridge",
					usb: session.target.usb,
					device: session.target.device,
					host: session.target.host,
				},
				recovery_hints: {
					restore_tool: "frida_session",
					restore_action: "create",
					restore_params: {
						session_id: session.id,
						pid: session.target.pid,
						process: session.target.process,
						spawn: session.target.spawn,
						usb: session.target.usb,
						device: session.target.device,
						host: session.target.host,
						...(session.mode ? { mode: session.mode } : {}),
						...(session.lastScript ? { script: session.lastScript } : {}),
					},
					instructions: [
						`Attach or spawn Frida session "${session.id}" on target ${session.target.type}:${targetVal}`,
						...(session.lastScript
							? ["Re-apply previous instrumentation script via frida_session(action: 'run')"]
							: []),
					],
				},
				created_at: session.createdAt,
				updated_at: session.updatedAt,
				last_heartbeat_at: session.lastRunAt || session.updatedAt,
				heartbeat_count: session.runsCount || 1,
				stale_timeout_sec: 300,
				status_source: "caller_reported",
				metadata: {
					...session.metadata,
					mode: session.mode,
					live_status: session.liveStatus,
					rpc_exports: session.rpcExports,
					eventsCount: session.eventsCount ?? session.events?.length ?? 0,
					events_count: session.eventsCount ?? session.events?.length ?? 0,
					runsCount: session.runsCount,
					recent_events: normalizedRecent,
					...(session.lastScript ? { last_script: session.lastScript } : {}),
				},
			};
			await runtimeStore.save(runtimeRecord);
		} catch {}
	}

	private async executeFridaRun(
		target: FridaSessionTarget,
		options: {
			script?: string;
			script_path?: string;
			script_args?: unknown;
			cli_args?: unknown;
			timeout?: number;
			max_bytes?: number;
			activeChildPid?: number;
		},
		signal?: AbortSignal,
	): Promise<{
		stdout: string;
		stderr: string;
		exitCode: number | null;
		outputBytes: number;
		truncated: boolean;
		timedOut: boolean;
	}> {
		const dependency = fridaDependency(this.which);
		const binary = dependency.path ?? "frida";
		const args: string[] = [];

		if (target.usb) {
			args.push("-U");
		} else if (target.device) {
			args.push("-D", target.device);
		} else if (target.host) {
			args.push("-H", target.host);
		}

		if (target.type === "pid") {
			args.push("-p", String(target.pid));
		} else if (target.type === "process") {
			args.push("-n", target.process!);
		} else if (target.type === "spawn") {
			if (options.activeChildPid !== undefined) {
				args.push("-p", String(options.activeChildPid));
			} else {
				args.push("-f", target.spawn!);
				if (target.pause === true || target.noPause === false) {
					args.push("--pause");
				}
			}
		}

		if (options.script_path) {
			const resolved = resolveScriptPath(options.script_path, this.session.cwd);
			args.push("-l", resolved);
		} else if (options.script) {
			args.push("-e", options.script);
		}

		if (options.script_args !== undefined) {
			const json =
				typeof options.script_args === "string" ? options.script_args : JSON.stringify(options.script_args);
			args.push("-P", json);
		}

		args.push("-q");
		const timeout = options.timeout ?? DEFAULT_TIMEOUT_SECONDS;
		if (timeout > 0) {
			args.push("-t", String(timeout));
		}

		if (options.cli_args) {
			const extra = Array.isArray(options.cli_args)
				? options.cli_args.map(String)
				: splitCliArgs(String(options.cli_args));
			args.push(...extra);
		}

		const maxBytes = options.max_bytes ?? DEFAULT_MAX_BYTES;
		const result = await this.runner(binary, args, {
			cwd: this.session.cwd,
			timeoutMs: timeout > 0 ? timeout * 1000 + 3000 : undefined,
			maxBytes,
			signal,
		});

		const rawOutput = Buffer.from(result.stdout).toString("utf8");
		const isTruncated = result.truncated || rawOutput.length > maxBytes;
		const displayOutput = isTruncated ? rawOutput.slice(0, maxBytes) : rawOutput;

		return {
			stdout: displayOutput,
			stderr: result.stderr,
			exitCode: result.exitCode,
			outputBytes: result.outputBytes,
			truncated: isTruncated,
			timedOut: result.timedOut,
		};
	}
}
