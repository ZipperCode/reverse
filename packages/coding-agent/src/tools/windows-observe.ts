import { type } from "@rva/omptype";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { prompt } from "@rva/utils";
import * as fs from "node:fs/promises";
import windowsObserveDescription from "../prompts/tools/windows-observe.md" with { type: "text" };
import { resolveReadPath, specialFileKind } from "./path-utils";
import type { ToolSession } from "./index";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";

/** Maximum capture file size allowed for offline analysis (128 MiB). */
const MAX_CAPTURE_FILE_BYTES = 128 * 1024 * 1024;
/** Maximum parsed events before stopping parse to bound memory. */
const MAX_PARSED_EVENTS = 200_000;
/** Maximum characters for parameter summaries in preview listings. */
const PREVIEW_PARAMS_CHARS = 300;
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 500;
const DEFAULT_EXPORT_LIMIT = 1000;
const MAX_EXPORT_LIMIT = 5000;
const DEFAULT_OUTPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_EXPORT_BYTES = 1024 * 1024;
const MAX_EXPORT_BYTES = 16 * 1024 * 1024;

const REDACTED = "[redacted]";

const windowsObserveSchema = type({
	action: type
		.enumerated("inspect", "list", "search", "export")
		.describe(
			"Offline read-only Windows API trace analysis: inspect (capture summary, processes, modules, categories), list (paged events), search (paged events matching filter), or export (write matching events to an artifact)",
		),
	path: type("string").describe(
		"Local ETW, API Monitor, or structured JSON/NDJSON capture file, resolved against session cwd. URLs and remote paths are rejected; this tool never touches live processes",
	),
	"format?": type
		.enumerated("auto", "json", "ndjson", "api_monitor", "etw")
		.describe("Capture format override: auto, json, ndjson, api_monitor, or etw (default auto)"),
	"pid?": type("number").describe("Filter by process ID (PID)"),
	"tid?": type("number").describe("Filter by thread ID (TID)"),
	"module?": type("string").describe(
		"Case-insensitive substring filter on the module/DLL name (e.g. kernel32.dll, advapi32)",
	),
	"api?": type("string").describe(
		"Case-insensitive substring filter on the API function name (e.g. CreateFileW, RegOpenKey)",
	),
	"category?": type("string").describe(
		"Filter by API category: file, registry, process, memory, network, crypto, sync, security, or other",
	),
	"direction?": type
		.enumerated("call", "return", "in", "out", "both")
		.describe("Filter by call direction: call/in (entry), return/out (exit), or both"),
	"filter?": type("string").describe(
		"Case-insensitive substring filter over API name, module, parameter values, and return result; required for search",
	),
	"regex?": type("boolean").describe("Treat filter as a regular expression instead of a literal string"),
	"start_time?": type("string").describe("Timestamp lower bound (ISO string or epoch ms)"),
	"end_time?": type("string").describe("Timestamp upper bound (ISO string or epoch ms)"),
	"offset?": type("number").describe("Zero-based event offset after filtering (default 0)"),
	"limit?": type("number").describe(
		"Maximum events: list/search default 50 (max 500); export default 1000 (max 5000)",
	),
	"max_bytes?": type("number").describe(
		"Output cap: inspect/list/search truncate rendered text (default 262144, max 4194304); export caps artifact (default 1048576, max 16777216)",
	),
	"export_format?": type
		.enumerated("json", "ndjson")
		.describe("export only: artifact format, JSON array or one event per line (default json)"),
});

export type WindowsObserveParams = typeof windowsObserveSchema.infer;
export type WindowsObserveAction = WindowsObserveParams["action"];
export type WindowsCaptureFormat = "json" | "ndjson" | "api_monitor" | "etw";
export type WindowsApiCategory =
	| "file"
	| "registry"
	| "process"
	| "memory"
	| "network"
	| "crypto"
	| "sync"
	| "security"
	| "other";
export type WindowsApiDirection = "call" | "return" | "both" | "unknown";
export type WindowsObserveStatus =
	| "ok"
	| "not_found"
	| "not_a_file"
	| "unreadable"
	| "empty"
	| "file_too_large"
	| "invalid_format"
	| "artifact_unavailable"
	| "error";

export interface WindowsApiEventInfo {
	index: number;
	timestamp?: string;
	epochMs?: number;
	pid?: number;
	tid?: number;
	processName?: string;
	module: string;
	api: string;
	direction: WindowsApiDirection;
	category: WindowsApiCategory;
	parameters: Record<string, unknown> | unknown[];
	paramSummary: string;
	paramSummaryTruncated: boolean;
	result?: string | number | boolean | null;
	duration?: string;
	durationMs?: number;
	redacted: boolean;
	redactions: number;
}

export interface WindowsProcessInfo {
	pid: number;
	processName?: string;
	events: number;
}

export interface WindowsObserveDetails {
	action: WindowsObserveAction;
	status: WindowsObserveStatus;
	path?: string;
	format?: WindowsCaptureFormat;
	fileBytes?: number;
	totalEvents?: number;
	matchedEvents?: number;
	processes?: WindowsProcessInfo[];
	modules?: Array<{ module: string; count: number }>;
	categories?: Record<string, number>;
	topApis?: Array<{ api: string; count: number }>;
	timeRange?: { firstTime?: string; lastTime?: string };
	events?: WindowsApiEventInfo[];
	offset?: number;
	limit?: number;
	nextOffset?: number;
	hasMore?: boolean;
	truncated?: boolean;
	redactions?: number;
	artifactId?: string;
	artifactPath?: string;
	exportFormat?: "json" | "ndjson";
	bytesWritten?: number;
	eventsWritten?: number;
	omitted?: number;
	error?: string;
}

export interface ParsedWindowsCapture {
	format: WindowsCaptureFormat;
	events: WindowsApiEventInfo[];
	totalEvents: number;
	truncated: boolean;
}

const SENSITIVE_KEYS: Record<string, true> = {
	authorization: true,
	auth: true,
	cookie: true,
	setcookie: true,
	token: true,
	accesstoken: true,
	refreshtoken: true,
	idtoken: true,
	bearertoken: true,
	apikey: true,
	key: true,
	secret: true,
	clientsecret: true,
	password: true,
	passwd: true,
	pwd: true,
	lpszpassword: true,
	session: true,
	sessionid: true,
	sid: true,
	csrf: true,
	xsrf: true,
	signature: true,
	sig: true,
	credential: true,
	credentials: true,
	privatekey: true,
	ticket: true,
	otp: true,
	mfa: true,
	sam: true,
	hash: true,
	pbesalt: true,
	seed: true,
	cert: true,
	certificate: true,
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, keys: readonly string[]): unknown {
	for (const key of keys) {
		const val = record[key];
		if (val !== undefined && val !== null) return val;
	}
	return undefined;
}

function stringField(record: Record<string, unknown> | undefined, keys: readonly string[]): string | undefined {
	if (!record) return undefined;
	const val = field(record, keys);
	if (typeof val === "string") return val;
	if (typeof val === "number" || typeof val === "boolean") return String(val);
	return undefined;
}

function numberField(record: Record<string, unknown> | undefined, keys: readonly string[]): number | undefined {
	if (!record) return undefined;
	const val = field(record, keys);
	if (typeof val === "number" && Number.isFinite(val)) return Math.trunc(val);
	if (typeof val === "string") {
		const parsed = Number(val.trim());
		if (Number.isFinite(parsed)) return Math.trunc(parsed);
	}
	return undefined;
}

function isSensitiveKey(key: string): boolean {
	return Object.hasOwn(SENSITIVE_KEYS, key.replace(/[-_\s]/g, "").toLowerCase());
}

function redactJsonValue(value: unknown, depth: number, counter: { count: number }): unknown {
	if (depth > 12) return value;
	if (Array.isArray(value)) return value.map(item => redactJsonValue(item, depth + 1, counter));
	const record = asRecord(value);
	if (!record) {
		if (typeof value === "string") {
			const res = redactTextValue(value, counter);
			return res;
		}
		return value;
	}
	const out: Record<string, unknown> = {};
	for (const [key, child] of Object.entries(record)) {
		if (isSensitiveKey(key)) {
			out[key] = REDACTED;
			counter.count += 1;
			continue;
		}
		out[key] = redactJsonValue(child, depth + 1, counter);
	}
	return out;
}

function redactTextValue(text: string, counter: { count: number }): string {
	let result = text;
	const pairs =
		/((?:"|')?(?:authorization|auth|cookie|token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pwd|lpszpassword|session[_-]?id|sid|credential|credentials|private[_-]?key|ticket|cert)(?:"|')?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,&;]+)/gi;
	result = result.replace(pairs, (_match, prefix: string) => {
		counter.count += 1;
		return `${prefix}${REDACTED}`;
	});
	result = result.replace(/\b(Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=-]+/gi, (_match, scheme: string) => {
		counter.count += 1;
		return `${scheme} ${REDACTED}`;
	});
	const jwt = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g;
	result = result.replace(jwt, () => {
		counter.count += 1;
		return REDACTED;
	});
	return result;
}

function parseTimestampToEpochMs(val: unknown): number | undefined {
	if (typeof val === "number" && Number.isFinite(val)) {
		if (val > 100_000_000_000_000_000) return Math.trunc((val - 116444736000000000) / 10000);
		if (val > 10_000_000_000_000) return Math.trunc(val / 1000);
		if (val > 10_000_000_000) return val;
		if (val > 1_000_000_000) return val * 1000;
		return val;
	}
	if (typeof val === "string") {
		const trimmed = val.trim();
		const num = Number(trimmed);
		if (!Number.isNaN(num) && Number.isFinite(num)) {
			if (num > 100_000_000_000_000_000) return Math.trunc((num - 116444736000000000) / 10000);
			if (num > 10_000_000_000_000) return Math.trunc(num / 1000);
			if (num > 10_000_000_000) return num;
			if (num > 1_000_000_000) return num * 1000;
			return num;
		}
		const parsed = Date.parse(trimmed);
		if (!Number.isNaN(parsed)) return parsed;
	}
	return undefined;
}

function formatTimestamp(val: unknown): { display?: string; epochMs?: number } {
	if (val === undefined || val === null) return {};
	const epochMs = parseTimestampToEpochMs(val);
	if (epochMs !== undefined) {
		try {
			return { display: new Date(epochMs).toISOString(), epochMs };
		} catch {
			return { display: String(val), epochMs };
		}
	}
	return { display: String(val) };
}

function normalizeDirection(value: unknown): WindowsApiDirection {
	if (typeof value !== "string") return "call";
	const trimmed = value.trim().toLowerCase();
	if (/^(call|entry|enter|before|in|request|begin|start)$/.test(trimmed)) return "call";
	if (/^(return|exit|leave|after|out|response|end|finish)$/.test(trimmed)) return "return";
	if (/^(both|all)$/.test(trimmed)) return "both";
	return "call";
}

function classifyApiCategory(api: string, module: string): WindowsApiCategory {
	const a = api.toLowerCase();
	const m = module.toLowerCase();

	if (
		m.includes("crypt") ||
		m.includes("bcrypt") ||
		m.includes("ncrypt") ||
		/^(crypt|bcrypt|ncrypt)/.test(a) ||
		/(md5|sha|aes|rsa|des|cipher|hash|cert|key|encrypt|decrypt)/.test(a)
	) {
		return "crypto";
	}

	if (a.startsWith("reg") || a.startsWith("ntkey") || (a.startsWith("nt") && a.includes("key"))) {
		return "registry";
	}

	if (
		/^(createfile|readfile|writefile|deletefile|movefile|copyfile|findfirstfile|findnextfile|setfilepointer|getfilesize|getfileattributes|setfileattributes|flushfilebuffers|deviceiocontrol)/.test(
			a,
		) ||
		(a.startsWith("nt") && (a.includes("file") || a.includes("directory")))
	) {
		return "file";
	}

	if (
		/^(virtualalloc|virtualprotect|virtualfree|virtualquery|readprocessmemory|writeprocessmemory|heapalloc|heapfree|heapcreate|mapviewoffile|unmapviewoffile|createfilemapping)/.test(
			a,
		) ||
		(a.startsWith("nt") && (a.includes("virtualmemory") || a.includes("section")))
	) {
		return "memory";
	}

	if (
		/^(createprocess|openprocess|terminateprocess|exitprocess|createremotethread|createthread|openthread|terminatethread|suspendthread|resumethread|queueuserapc|setthreadcontext|getthreadcontext)/.test(
			a,
		) ||
		(a.startsWith("nt") && (a.includes("process") || a.includes("thread") || a.includes("apc")))
	) {
		return "process";
	}

	if (
		m.includes("ws2_32") ||
		m.includes("wsock32") ||
		m.includes("wininet") ||
		m.includes("winhttp") ||
		/^(socket|connect|send|recv|sendto|recvfrom|bind|listen|accept|closesocket|wsastartup|wsasend|wsarecv|internetopen|internetconnect|httpopenrequest|httpsendrequest|winhttp)/.test(
			a,
		)
	) {
		return "network";
	}

	if (
		/^(isdebuggerpresent|checkremotedebuggerpresent|ntqueryinformationprocess|outputdebugstring|adjusttokenprivileges|openprocesstoken|openthreadtoken|lookupprivilegevalue|gettokeninformation|logonuser)/.test(
			a,
		)
	) {
		return "security";
	}

	if (
		/^(createmutex|openmutex|releasemutex|createevent|openevent|setevent|resetevent|createsemaphore|opensemaphore|releasesemaphore|waitforsingleobject|waitformultipleobjects|sleep)/.test(
			a,
		) ||
		(a.startsWith("nt") && (a.includes("mutant") || a.includes("event") || a.includes("wait")))
	) {
		return "sync";
	}

	return "other";
}

function normalizeCategory(explicitCategory: string | undefined, module: string, api: string): WindowsApiCategory {
	if (explicitCategory) {
		const lower = explicitCategory.trim().toLowerCase();
		if (
			lower === "file" ||
			lower === "registry" ||
			lower === "process" ||
			lower === "memory" ||
			lower === "network" ||
			lower === "crypto" ||
			lower === "sync" ||
			lower === "security" ||
			lower === "other"
		) {
			return lower;
		}
	}
	return classifyApiCategory(api, module);
}

function formatDuration(val: unknown): string | undefined {
	if (val === undefined || val === null) return undefined;
	if (typeof val === "number" && Number.isFinite(val)) {
		return `${val.toFixed(2)}ms`;
	}
	if (typeof val === "string") return val.trim();
	return undefined;
}

function formatParamSummary(
	parameters: unknown,
	maxChars: number = PREVIEW_PARAMS_CHARS,
): { summary: string; truncated: boolean } {
	if (parameters === undefined || parameters === null) return { summary: "", truncated: false };
	let text = "";
	if (typeof parameters === "object") {
		if (Array.isArray(parameters)) {
			text = parameters.map(p => (typeof p === "object" ? JSON.stringify(p) : String(p))).join(", ");
		} else {
			const entries = Object.entries(parameters as Record<string, unknown>);
			text = entries
				.map(([k, v]) => `${k}=${typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v)}`)
				.join(", ");
		}
	} else {
		text = String(parameters);
	}
	if (text.length <= maxChars) {
		return { summary: text, truncated: false };
	}
	return { summary: `${text.slice(0, maxChars)}…`, truncated: true };
}

function parseRawEvent(raw: unknown, index: number): WindowsApiEventInfo {
	const record = asRecord(raw) ?? {};
	const counter = { count: 0 };

	// 1. Check ETW envelope (System / EventData)
	const eventWrapper = asRecord(record.Event) ?? record;
	const system = asRecord(eventWrapper.System);
	const eventData = asRecord(eventWrapper.EventData) ?? asRecord(eventWrapper.UserData);

	let module = "<unknown>";
	let api = "<unknown>";
	let pid: number | undefined;
	let tid: number | undefined;
	let rawTimestamp: unknown;
	let parameters: Record<string, unknown> | unknown[] = {};
	let result: string | number | boolean | null | undefined;
	let processName: string | undefined;
	let duration: string | undefined;
	let direction: WindowsApiDirection = "call";
	let explicitCategory: string | undefined;

	if (system) {
		const providerRecord = asRecord(system.Provider);
		module =
			stringField(providerRecord, ["Name", "name"]) ??
			stringField(system, ["ProviderName", "Provider", "provider"]) ??
			"ETW";
		api =
			stringField(system, ["EventName", "TaskName", "OpcodeName", "EventID"]) ??
			stringField(eventData, ["EventName", "ApiName", "Function", "FunctionName"]) ??
			`Event_${system.EventID ?? "0"}`;
		pid = numberField(system, ["ProcessID", "ProcessId", "pid"]);
		tid = numberField(system, ["ThreadID", "ThreadId", "tid"]);
		const timeCreated = asRecord(system.TimeCreated);
		rawTimestamp =
			stringField(timeCreated, ["SystemTime", "systemTime"]) ?? field(system, ["TimeStamp", "TimeCreated", "time"]);
		if (eventData) {
			parameters = eventData;
			processName = stringField(eventData, ["ProcessName", "ImageName", "process"]);
			const rawRes = field(eventData, ["Result", "Status", "ErrorCode", "ReturnCode"]);
			if (
				typeof rawRes === "string" ||
				typeof rawRes === "number" ||
				typeof rawRes === "boolean" ||
				rawRes === null
			) {
				result = rawRes;
			}
		}
	} else {
		// API Monitor or generic structured JSON
		module =
			stringField(record, ["module", "Module", "dll", "DLL", "library", "Library", "provider", "Provider"]) ??
			"<unknown>";
		api =
			stringField(record, [
				"api",
				"API",
				"function",
				"FunctionName",
				"name",
				"Name",
				"event",
				"EventName",
				"call",
			]) ?? "<unknown>";
		pid = numberField(record, ["pid", "PID", "processId", "ProcessId", "ProcessID", "process_id"]);
		tid = numberField(record, ["tid", "TID", "threadId", "ThreadId", "ThreadID", "thread_id"]);
		processName = stringField(record, ["processName", "ProcessName", "process", "image", "ImageName", "app"]);
		rawTimestamp = field(record, [
			"timestamp",
			"Timestamp",
			"time",
			"Time",
			"ts",
			"TimeCreated",
			"DateTime",
			"TimeStamp",
			"Date",
		]);
		direction = normalizeDirection(
			field(record, ["direction", "Direction", "type", "Type", "phase", "Phase", "kind", "Kind"]),
		);
		explicitCategory = stringField(record, ["category", "Category", "group", "Group"]);
		const rawParams = field(record, [
			"parameters",
			"Parameters",
			"args",
			"Arguments",
			"params",
			"Params",
			"EventData",
			"data",
			"Data",
			"payload",
		]);
		parameters = rawParams && typeof rawParams === "object" ? (rawParams as Record<string, unknown> | unknown[]) : {};
		const rawRes = field(record, [
			"result",
			"Result",
			"returnValue",
			"ReturnValue",
			"Return",
			"status",
			"Status",
			"errorCode",
			"ErrorCode",
			"hr",
			"HRESULT",
		]);
		if (typeof rawRes === "string" || typeof rawRes === "number" || typeof rawRes === "boolean" || rawRes === null) {
			result = rawRes;
		}
		duration = formatDuration(
			field(record, ["duration", "Duration", "durationMs", "duration_ms", "duration_us", "elapsed", "Elapsed"]),
		);
	}

	const category = normalizeCategory(explicitCategory, module, api);
	const timeInfo = formatTimestamp(rawTimestamp);

	// Redaction pass
	const redactedVal = redactJsonValue(parameters, 0, counter);
	const redactedParameters =
		redactedVal && typeof redactedVal === "object" ? (redactedVal as Record<string, unknown> | unknown[]) : {};
	let redactedResult: string | number | boolean | null | undefined;
	if (typeof result === "string") {
		redactedResult = redactTextValue(result, counter);
	} else if (result !== undefined) {
		const resVal = redactJsonValue(result, 0, counter);
		if (typeof resVal === "string" || typeof resVal === "number" || typeof resVal === "boolean" || resVal === null) {
			redactedResult = resVal;
		}
	}

	const paramSummaryInfo = formatParamSummary(redactedParameters);

	return {
		index,
		timestamp: timeInfo.display,
		epochMs: timeInfo.epochMs,
		pid,
		tid,
		processName,
		module,
		api,
		direction,
		category,
		parameters: redactedParameters,
		paramSummary: paramSummaryInfo.summary,
		paramSummaryTruncated: paramSummaryInfo.truncated,
		result: redactedResult,
		duration,
		redacted: counter.count > 0,
		redactions: counter.count,
	};
}

export function parseWindowsCapture(
	text: string,
	options: { format?: WindowsCaptureFormat | "auto" } = {},
): ParsedWindowsCapture {
	const forced = options.format ?? "auto";
	const body = text.replace(/^\uFEFF/, "").trim();
	if (body.length === 0) throw new ToolError("invalid capture: file is empty");

	const rawEvents: unknown[] = [];
	let detectedFormat: WindowsCaptureFormat = "json";

	if (forced === "ndjson") {
		const lines = body
			.split(/\r?\n/)
			.map(l => l.trim())
			.filter(l => l.length > 0);
		for (let i = 0; i < lines.length; i++) {
			try {
				rawEvents.push(JSON.parse(lines[i]!));
			} catch (err) {
				throw new ToolError(
					`invalid NDJSON capture at line ${i + 1}: ${err instanceof Error ? err.message : String(err)}`,
				);
			}
			if (rawEvents.length >= MAX_PARSED_EVENTS) break;
		}
		detectedFormat = "ndjson";
	} else if (forced === "json" || forced === "api_monitor" || forced === "etw") {
		let root: unknown;
		try {
			root = JSON.parse(body);
		} catch (err) {
			throw new ToolError(`invalid JSON capture: ${err instanceof Error ? err.message : String(err)}`);
		}
		extractEventsFromRoot(root, rawEvents);
		detectedFormat = forced;
	} else {
		// auto mode: try JSON first
		let jsonParsed = false;
		try {
			const root: unknown = JSON.parse(body);
			extractEventsFromRoot(root, rawEvents);
			jsonParsed = true;
			detectedFormat = detectFormatFromRoot(root);
		} catch {
			// fallback to NDJSON
		}

		if (!jsonParsed) {
			const lines = body
				.split(/\r?\n/)
				.map(l => l.trim())
				.filter(l => l.length > 0);
			if (lines.length === 0) throw new ToolError("invalid capture: no content");
			for (let i = 0; i < lines.length; i++) {
				try {
					rawEvents.push(JSON.parse(lines[i]!));
				} catch (err) {
					throw new ToolError(
						`invalid capture: neither valid JSON nor NDJSON (line ${i + 1}: ${err instanceof Error ? err.message : String(err)})`,
					);
				}
				if (rawEvents.length >= MAX_PARSED_EVENTS) break;
			}
			detectedFormat = "ndjson";
		}
	}

	const truncated = rawEvents.length >= MAX_PARSED_EVENTS;
	const events: WindowsApiEventInfo[] = rawEvents.map((raw, idx) => parseRawEvent(raw, idx));

	return {
		format: detectedFormat,
		events,
		totalEvents: events.length,
		truncated,
	};
}

function extractEventsFromRoot(root: unknown, out: unknown[]): void {
	if (Array.isArray(root)) {
		for (const item of root) {
			out.push(item);
			if (out.length >= MAX_PARSED_EVENTS) break;
		}
		return;
	}
	const record = asRecord(root);
	if (!record) {
		throw new ToolError("invalid capture: expected a JSON array or object");
	}
	const arrayField = field(record, [
		"events",
		"Events",
		"calls",
		"Calls",
		"apis",
		"Apis",
		"traces",
		"Traces",
		"records",
		"items",
		"entries",
	]);
	if (Array.isArray(arrayField)) {
		for (const item of arrayField) {
			out.push(item);
			if (out.length >= MAX_PARSED_EVENTS) break;
		}
		return;
	}
	// Check single event
	if (record.Event || record.api || record.API || record.module || record.Module) {
		out.push(record);
		return;
	}
	throw new ToolError(
		"invalid capture: expected events, calls, or apis array in JSON object or top-level array of events",
	);
}

function detectFormatFromRoot(root: unknown): WindowsCaptureFormat {
	const record = asRecord(root);
	if (record) {
		if (record.Calls || record.calls) return "api_monitor";
		if (record.Events || record.Event) return "etw";
	} else if (Array.isArray(root) && root.length > 0) {
		const first = asRecord(root[0]);
		if (first?.Event || first?.Provider) return "etw";
		if (first?.Calls || first?.API) return "api_monitor";
	}
	return "json";
}

interface EventFilter {
	pid?: number;
	tid?: number;
	module?: string;
	api?: string;
	category?: string;
	direction?: "call" | "return" | "in" | "out" | "both";
	text?: string;
	regex?: boolean;
	startTime?: string;
	endTime?: string;
	startEpochMs?: number;
	endEpochMs?: number;
}

function eventMatches(event: WindowsApiEventInfo, filter: EventFilter, matcher: (v: string) => boolean): boolean {
	if (filter.pid !== undefined && event.pid !== filter.pid) return false;
	if (filter.tid !== undefined && event.tid !== filter.tid) return false;
	if (filter.module !== undefined && !event.module.toLowerCase().includes(filter.module.toLowerCase())) return false;
	if (filter.api !== undefined && !event.api.toLowerCase().includes(filter.api.toLowerCase())) return false;
	if (filter.category !== undefined && event.category.toLowerCase() !== filter.category.toLowerCase()) return false;

	if (filter.direction !== undefined) {
		const d = filter.direction;
		if (d === "call" || d === "in") {
			if (event.direction !== "call" && event.direction !== "both") return false;
		} else if (d === "return" || d === "out") {
			if (event.direction !== "return" && event.direction !== "both") return false;
		}
	}

	if (filter.startEpochMs !== undefined) {
		if (event.epochMs !== undefined) {
			if (event.epochMs < filter.startEpochMs) return false;
		} else if (filter.startTime && event.timestamp && event.timestamp < filter.startTime) {
			return false;
		}
	}

	if (filter.endEpochMs !== undefined) {
		if (event.epochMs !== undefined) {
			if (event.epochMs > filter.endEpochMs) return false;
		} else if (filter.endTime && event.timestamp && event.timestamp > filter.endTime) {
			return false;
		}
	}

	if (filter.text !== undefined) {
		const payload = `${event.api} ${event.module} ${event.category} ${event.paramSummary} ${event.result ?? ""} ${event.processName ?? ""} ${JSON.stringify(event.parameters)}`;
		if (!matcher(payload)) return false;
	}

	return true;
}

function compileMatcher(filter: EventFilter): (value: string) => boolean {
	if (filter.text === undefined) return () => true;
	if (filter.regex) {
		let expression: RegExp;
		try {
			expression = new RegExp(filter.text, "i");
		} catch (error) {
			throw new ToolError(
				`invalid filter regular expression: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		return value => expression.test(value);
	}
	const needle = filter.text.toLowerCase();
	return value => value.toLowerCase().includes(needle);
}

function formatEventLine(event: WindowsApiEventInfo): string {
	const time = event.timestamp ? `${event.timestamp} ` : "";
	const pidTid =
		event.pid !== undefined || event.tid !== undefined ? `[${event.pid ?? "?"}:${event.tid ?? "?"}] ` : "";
	const result = event.result !== undefined ? ` result=${JSON.stringify(event.result)}` : "";
	const duration = event.duration ? ` duration=${event.duration}` : "";
	const redacted = event.redacted ? " [redacted]" : "";
	const params = event.paramSummary ? `\n  params: ${event.paramSummary}` : "";
	return `#${event.index} ${time}${pidTid}${event.module}!${event.api} (${event.category}/${event.direction})${result}${duration}${redacted}${params}`;
}

function truncateUtf8(text: string, maxBytes: number): string {
	const buffer = Buffer.from(text, "utf8");
	if (buffer.byteLength <= maxBytes) return text;
	return buffer
		.subarray(0, Math.max(0, maxBytes))
		.toString("utf8")
		.replace(/\uFFFD$/, "");
}

function capRendered(lines: string[], maxBytes: number): { text: string; truncated: boolean; keptLines: number } {
	let text = "";
	let kept = 0;
	for (const line of lines) {
		const candidate = kept === 0 ? line : `${text}\n${line}`;
		if (Buffer.byteLength(candidate, "utf8") > maxBytes) {
			if (kept === 0) {
				text = truncateUtf8(line, maxBytes);
				kept = line.length > 0 ? 1 : 0;
			}
			return {
				text: `${text}\n… output truncated at ${maxBytes} bytes; narrow the filter or lower limit for more.`,
				truncated: true,
				keptLines: kept,
			};
		}
		text = candidate;
		kept += 1;
	}
	return { text, truncated: false, keptLines: kept };
}

function validatePath(raw: string): string {
	const trimmed = raw.trim();
	if (trimmed.length === 0) throw new ToolError("path must not be empty");
	if (
		/^(?:powershell|pwsh|cmd(?:\.exe)?|logman|wevtutil|type|cat|wmic)\s+/i.test(trimmed) ||
		trimmed.startsWith("|") ||
		trimmed.startsWith(">") ||
		trimmed.startsWith("<") ||
		/[;&|`\0\r\n]/.test(trimmed)
	) {
		throw new ToolError(
			"path must be a local capture file, not a command; windows_observe is an offline capture reader",
		);
	}
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) || /^[a-z][a-z0-9+.-]{1,}:/i.test(trimmed)) {
		throw new ToolError(
			"path must be a local capture file; windows_observe never connects to a remote URL or target",
		);
	}
	if (
		trimmed.startsWith("\\\\") ||
		trimmed.startsWith("//") ||
		trimmed.startsWith("/\\") ||
		trimmed.startsWith("\\/")
	) {
		throw new ToolError("path must be a local capture file; remote network shares are forbidden");
	}
	if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:/i.test(trimmed)) {
		throw new ToolError("path must be a local capture file; remote paths are forbidden");
	}
	return trimmed;
}

function integerOption(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
	if (value === undefined) return fallback;
	if (!Number.isFinite(value) || Math.trunc(value) !== value) {
		throw new ToolError("numeric options must be integers");
	}
	return Math.min(maximum, Math.max(minimum, value));
}

function validateParams(params: WindowsObserveParams): {
	path: string;
	format: WindowsCaptureFormat | "auto";
	filter: EventFilter;
	offset: number;
	limit: number;
	maxBytes: number;
	exportFormat: "json" | "ndjson";
} {
	const action = params.action;
	const path = validatePath(params.path);

	if (params.module !== undefined && params.module.trim().length === 0) {
		throw new ToolError("module filter must not be empty when provided");
	}
	if (params.api !== undefined && params.api.trim().length === 0) {
		throw new ToolError("api filter must not be empty when provided");
	}
	if (params.filter !== undefined && params.filter.length === 0) {
		throw new ToolError("filter must not be empty when provided");
	}
	if (params.regex === true) {
		if (params.filter === undefined) {
			throw new ToolError("regex requires filter");
		}
		try {
			new RegExp(params.filter, "i");
		} catch (error) {
			throw new ToolError(
				`invalid filter regular expression: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}
	if (action === "search" && params.filter === undefined) {
		throw new ToolError("search requires a filter (use list to enumerate events without one)");
	}
	if (params.export_format !== undefined && action !== "export") {
		throw new ToolError(`export_format is not supported by action "${action}"`);
	}

	if (action === "inspect") {
		if (
			params.offset !== undefined ||
			params.limit !== undefined ||
			params.pid !== undefined ||
			params.tid !== undefined ||
			params.module !== undefined ||
			params.api !== undefined ||
			params.category !== undefined ||
			params.direction !== undefined ||
			params.filter !== undefined ||
			params.start_time !== undefined ||
			params.end_time !== undefined
		) {
			throw new ToolError(
				"inspect does not accept event filters, offset, or limit; use list or search to page events",
			);
		}
	}
	let startEpochMs: number | undefined;
	if (params.start_time !== undefined) {
		startEpochMs = parseTimestampToEpochMs(params.start_time);
		if (startEpochMs === undefined) {
			throw new ToolError(`invalid start_time: "${params.start_time}" could not be parsed as a timestamp`);
		}
	}
	let endEpochMs: number | undefined;
	if (params.end_time !== undefined) {
		endEpochMs = parseTimestampToEpochMs(params.end_time);
		if (endEpochMs === undefined) {
			throw new ToolError(`invalid end_time: "${params.end_time}" could not be parsed as a timestamp`);
		}
	}
	if (startEpochMs !== undefined && endEpochMs !== undefined && startEpochMs > endEpochMs) {
		throw new ToolError("start_time must be earlier than or equal to end_time");
	}

	const maxDefault = action === "export" ? DEFAULT_EXPORT_BYTES : DEFAULT_OUTPUT_BYTES;
	const maxLimit = action === "export" ? MAX_EXPORT_BYTES : MAX_OUTPUT_BYTES;
	const maxBytes = integerOption(params.max_bytes, maxDefault, 1024, maxLimit);
	const limitDefault = action === "export" ? DEFAULT_EXPORT_LIMIT : DEFAULT_PAGE_LIMIT;
	const limitMax = action === "export" ? MAX_EXPORT_LIMIT : MAX_PAGE_LIMIT;
	const limit = integerOption(params.limit, limitDefault, 1, limitMax);
	const offset = integerOption(params.offset, 0, 0, Number.MAX_SAFE_INTEGER);

	return {
		path,
		format: params.format ?? "auto",
		filter: {
			pid: params.pid,
			tid: params.tid,
			module: params.module,
			api: params.api,
			category: params.category,
			direction: params.direction,
			text: params.filter,
			regex: params.regex,
			startTime: params.start_time,
			endTime: params.end_time,
			startEpochMs,
			endEpochMs,
		},
		offset,
		limit,
		maxBytes,
		exportFormat: params.export_format ?? "json",
	};
}

interface ExportRender {
	text: string;
	eventsWritten: number;
	omitted: number;
}

function renderExport(events: WindowsApiEventInfo[], format: "json" | "ndjson", maxBytes: number): ExportRender {
	let text = format === "json" ? "[\n" : "";
	let eventsWritten = 0;

	for (let i = 0; i < events.length; i++) {
		const ev = events[i]!;
		const itemStr = JSON.stringify(ev, null, format === "json" ? 2 : undefined);
		const line = format === "json" ? (eventsWritten === 0 ? `  ${itemStr}` : `,\n  ${itemStr}`) : `${itemStr}\n`;
		const closing = format === "json" ? "\n]" : "";

		if (Buffer.byteLength(`${text}${line}${closing}`, "utf8") > maxBytes) {
			break;
		}

		text += line;
		eventsWritten += 1;
	}

	if (format === "json") text += "\n]";
	return { text, eventsWritten, omitted: events.length - eventsWritten };
}

export class WindowsObserveTool implements AgentTool<typeof windowsObserveSchema, WindowsObserveDetails> {
	readonly name = "windows_observe";
	readonly approval: ToolTier = "read";
	readonly label = "Windows Observe";
	readonly summary =
		"Offline read-only Windows API / ETW / API Monitor trace analysis: summarize, list, search, and export API call events";
	readonly description: string;
	readonly parameters = windowsObserveSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(windowsObserveDescription);
	}

	async execute(
		_toolCallId: string,
		params: WindowsObserveParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<WindowsObserveDetails>> {
		throwIfAborted(signal);
		const options = validateParams(params);
		const resolved = resolveReadPath(options.path, this.session.cwd);

		let stat;
		try {
			stat = await fs.stat(resolved);
		} catch (error) {
			const code = (error as { code?: string }).code;
			if (code === "ENOENT" || code === "ENOTDIR") {
				return {
					content: [
						{
							type: "text",
							text: `windows_observe: capture file not found: ${options.path}\nThis tool analyzes existing offline captures only; it never captures live processes.`,
						},
					],
					details: { action: params.action, status: "not_found", path: options.path },
				};
			}
			return {
				content: [
					{
						type: "text",
						text: `windows_observe: cannot read ${options.path}: ${error instanceof Error ? error.message : String(error)}`,
					},
				],
				details: {
					action: params.action,
					status: "unreadable",
					path: options.path,
					error: error instanceof Error ? error.message : String(error),
				},
			};
		}

		const special = specialFileKind(stat);
		if (special) {
			return {
				content: [{ type: "text", text: `windows_observe: ${options.path} is a ${special}, not a regular file.` }],
				details: { action: params.action, status: "not_a_file", path: options.path, error: special },
			};
		}
		if (!stat.isFile()) {
			return {
				content: [{ type: "text", text: `windows_observe: ${options.path} is not a regular file.` }],
				details: { action: params.action, status: "not_a_file", path: options.path },
			};
		}
		if (stat.size === 0) {
			return {
				content: [{ type: "text", text: `windows_observe: ${options.path} is empty.` }],
				details: { action: params.action, status: "empty", path: options.path, fileBytes: 0 },
			};
		}
		if (stat.size > MAX_CAPTURE_FILE_BYTES) {
			return {
				content: [
					{
						type: "text",
						text: `windows_observe: ${options.path} is ${stat.size} bytes, above the ${MAX_CAPTURE_FILE_BYTES}-byte analysis limit. Split the capture or filter it externally first.`,
					},
				],
				details: {
					action: params.action,
					status: "file_too_large",
					path: options.path,
					fileBytes: stat.size,
					error: `file exceeds ${MAX_CAPTURE_FILE_BYTES} bytes`,
				},
			};
		}

		throwIfAborted(signal);
		let text: string;
		try {
			text = await fs.readFile(resolved, "utf8");
		} catch (error) {
			return {
				content: [
					{
						type: "text",
						text: `windows_observe: cannot read ${options.path}: ${error instanceof Error ? error.message : String(error)}`,
					},
				],
				details: {
					action: params.action,
					status: "unreadable",
					path: options.path,
					fileBytes: stat.size,
					error: error instanceof Error ? error.message : String(error),
				},
			};
		}

		let parsed: ParsedWindowsCapture;
		try {
			parsed = parseWindowsCapture(text, { format: options.format });
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return {
				content: [
					{
						type: "text",
						text: `windows_observe: cannot analyze ${options.path}: ${message}\nSupported inputs: structured JSON captures ({events: [...]} or array), NDJSON event streams, API Monitor JSON exports, or ETW JSON exports.`,
					},
				],
				details: {
					action: params.action,
					status: "invalid_format",
					path: options.path,
					fileBytes: stat.size,
					error: message,
				},
			};
		}

		if (parsed.totalEvents === 0) {
			return {
				content: [
					{
						type: "text",
						text: `windows_observe: no API events found in ${options.path} (format: ${parsed.format}).\nThis tool analyzes recorded capture data only; it does not observe live processes.`,
					},
				],
				details: {
					action: params.action,
					status: "ok",
					path: options.path,
					format: parsed.format,
					fileBytes: stat.size,
					totalEvents: 0,
					matchedEvents: 0,
				},
			};
		}

		if (params.action === "inspect") {
			return this.inspect(parsed, options, stat.size);
		}

		const matcher = compileMatcher(options.filter);
		const matched = parsed.events.filter(ev => eventMatches(ev, options.filter, matcher));

		if (params.action === "export") {
			const page = matched.slice(options.offset, options.offset + options.limit);
			return this.exportEvents(page, matched.length, parsed, options, stat.size);
		}

		const page = matched.slice(options.offset, options.offset + options.limit);
		const hasMore = options.offset + page.length < matched.length;
		const nextOffset = hasMore ? options.offset + page.length : undefined;

		const header = `windows_observe ${params.action}: ${options.path} (${matched.length} matching of ${parsed.totalEvents} events, ${parsed.format}, ${stat.size} bytes)`;
		const range = page.length
			? `showing ${options.offset}..${options.offset + page.length - 1}${hasMore ? ` (next offset ${nextOffset})` : ""}`
			: "no events in range";

		const lines = [header, range, ...page.map(formatEventLine)];
		const rendered = capRendered(lines, options.maxBytes);

		return {
			content: [{ type: "text", text: rendered.text }],
			details: {
				action: params.action,
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes: stat.size,
				events: page,
				totalEvents: parsed.totalEvents,
				matchedEvents: matched.length,
				offset: options.offset,
				limit: options.limit,
				nextOffset,
				hasMore,
				truncated: parsed.truncated || rendered.truncated,
				redactions: page.reduce((sum, ev) => sum + ev.redactions, 0),
			},
		};
	}

	private inspect(
		parsed: ParsedWindowsCapture,
		options: { path: string; maxBytes: number },
		fileBytes: number,
	): AgentToolResult<WindowsObserveDetails> {
		const processMap = new Map<number, { pid: number; processName?: string; events: number }>();
		const moduleMap = new Map<string, number>();
		const categoryMap: Record<string, number> = {};
		const apiMap = new Map<string, number>();

		let firstTime: string | undefined;
		let lastTime: string | undefined;

		for (const ev of parsed.events) {
			if (ev.pid !== undefined) {
				const existing = processMap.get(ev.pid);
				if (existing) {
					existing.events += 1;
					if (!existing.processName && ev.processName) existing.processName = ev.processName;
				} else {
					processMap.set(ev.pid, { pid: ev.pid, processName: ev.processName, events: 1 });
				}
			}

			moduleMap.set(ev.module, (moduleMap.get(ev.module) ?? 0) + 1);
			categoryMap[ev.category] = (categoryMap[ev.category] ?? 0) + 1;
			apiMap.set(ev.api, (apiMap.get(ev.api) ?? 0) + 1);

			if (ev.timestamp) {
				if (!firstTime || ev.timestamp < firstTime) firstTime = ev.timestamp;
				if (!lastTime || ev.timestamp > lastTime) lastTime = ev.timestamp;
			}
		}

		const processes = [...processMap.values()].sort((a, b) => b.events - a.events);
		const modules = [...moduleMap.entries()]
			.map(([module, count]) => ({ module, count }))
			.sort((a, b) => b.count - a.count);
		const topApis = [...apiMap.entries()].map(([api, count]) => ({ api, count })).sort((a, b) => b.count - a.count);

		const totalRedactions = parsed.events.reduce((sum, ev) => sum + ev.redactions, 0);

		const lines: string[] = [
			`windows_observe inspect: ${options.path}`,
			`Format: ${parsed.format}${parsed.truncated ? " (parsing capped)" : ""}, ${fileBytes} bytes`,
			`Events: ${parsed.totalEvents}${firstTime ? ` (time range: ${firstTime}${lastTime && lastTime !== firstTime ? ` .. ${lastTime}` : ""})` : ""}`,
			`Processes: ${processes.length}`,
			...processes
				.slice(0, 10)
				.map(p => `  PID ${p.pid}${p.processName ? ` (${p.processName})` : ""}: ${p.events} events`),
			...(processes.length > 10 ? [`  … ${processes.length - 10} more processes`] : []),
			`Modules: ${modules
				.slice(0, 8)
				.map(m => `${m.module} (${m.count})`)
				.join(", ")}${modules.length > 8 ? " …" : ""}`,
			`Categories: ${Object.entries(categoryMap)
				.map(([cat, cnt]) => `${cat} (${cnt})`)
				.join(", ")}`,
			`Top APIs: ${topApis
				.slice(0, 8)
				.map(a => `${a.api} (${a.count})`)
				.join(", ")}${topApis.length > 8 ? " …" : ""}`,
			`Redactions: ${totalRedactions > 0 ? `${totalRedactions} sensitive parameters redacted` : "none"}`,
		];

		const rendered = capRendered(lines, options.maxBytes);

		return {
			content: [{ type: "text", text: rendered.text }],
			details: {
				action: "inspect",
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes,
				totalEvents: parsed.totalEvents,
				matchedEvents: parsed.totalEvents,
				processes,
				modules,
				categories: categoryMap,
				topApis,
				timeRange: firstTime ? { firstTime, lastTime } : undefined,
				truncated: parsed.truncated || rendered.truncated,
				redactions: totalRedactions,
			},
		};
	}

	private async exportEvents(
		page: WindowsApiEventInfo[],
		matchedEvents: number,
		parsed: ParsedWindowsCapture,
		options: { path: string; maxBytes: number; exportFormat: "json" | "ndjson"; offset: number; limit: number },
		fileBytes: number,
	): Promise<AgentToolResult<WindowsObserveDetails>> {
		if (page.length === 0) {
			return {
				content: [
					{
						type: "text",
						text: "windows_observe export: no events matched the filters; nothing was written.",
					},
				],
				details: {
					action: "export",
					status: "ok",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalEvents: parsed.totalEvents,
					matchedEvents,
					offset: options.offset,
					limit: options.limit,
					truncated: false,
					redactions: 0,
				},
			};
		}

		const allocation = await this.session.allocateOutputArtifact?.("windows_observe");
		if (!allocation?.path || !allocation.id) {
			return {
				content: [
					{
						type: "text",
						text: `windows_observe export: ${page.length} events matched, but artifact storage is unavailable in this session.`,
					},
				],
				details: {
					action: "export",
					status: "artifact_unavailable",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalEvents: parsed.totalEvents,
					matchedEvents,
					error: "artifact storage unavailable",
				},
			};
		}

		const rendered = renderExport(page, options.exportFormat, options.maxBytes);
		try {
			await Bun.write(allocation.path, rendered.text);
		} catch (error) {
			return {
				content: [
					{
						type: "text",
						text: `windows_observe export: writing artifact failed: ${error instanceof Error ? error.message : String(error)}`,
					},
				],
				details: {
					action: "export",
					status: "error",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalEvents: parsed.totalEvents,
					matchedEvents,
					error: `failed to write artifact: ${error instanceof Error ? error.message : String(error)}`,
				},
			};
		}

		const bytesWritten = Buffer.byteLength(rendered.text, "utf8");
		const text = [
			`windows_observe export: wrote ${rendered.eventsWritten} of ${page.length} matched events (${bytesWritten} bytes, ${options.exportFormat})`,
			`Saved artifact: artifact://${allocation.id}`,
			`Path: ${allocation.path}`,
			...(rendered.omitted > 0
				? [`Truncated: ${rendered.omitted} events omitted at ${options.maxBytes}-byte cap`]
				: []),
			"Credentials and tokens are redacted in the artifact; event order and metadata are preserved.",
		].join("\n");

		return {
			content: [{ type: "text", text }],
			details: {
				action: "export",
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes,
				totalEvents: parsed.totalEvents,
				matchedEvents,
				offset: options.offset,
				limit: options.limit,
				hasMore: options.offset + page.length < matchedEvents,
				truncated: rendered.omitted > 0 || parsed.truncated,
				redactions: page.reduce((sum, ev) => sum + ev.redactions, 0),
				artifactId: allocation.id,
				artifactPath: allocation.path,
				exportFormat: options.exportFormat,
				bytesWritten,
				eventsWritten: rendered.eventsWritten,
				omitted: rendered.omitted,
			},
		};
	}
}
