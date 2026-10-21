import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { prompt } from "@reverse/utils";
import * as fs from "node:fs/promises";
import websocketObserveDescription from "../prompts/tools/websocket-observe.md" with { type: "text" };
import { resolveReadPath, specialFileKind } from "./path-utils";
import type { ToolSession } from "./index";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";

/** Largest capture file this tool will read; analysis is offline and bounded. */
const MAX_CAPTURE_FILE_BYTES = 128 * 1024 * 1024;
/** Frames parsed from one capture before parsing stops. */
const MAX_PARSED_FRAMES = 200_000;
/** Characters of a payload kept in list/search previews. */
const PREVIEW_CHARS = 400;
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGE_LIMIT = 500;
const DEFAULT_EXPORT_LIMIT = 1000;
const MAX_EXPORT_LIMIT = 5000;
const DEFAULT_OUTPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_EXPORT_BYTES = 1024 * 1024;
const MAX_EXPORT_BYTES = 16 * 1024 * 1024;

const REDACTED = "[redacted]";
const MAX_CONNECTION_LINES = 200;

const websocketObserveSchema = type({
	action: type
		.enumerated("inspect", "list", "search", "export")
		.describe(
			"Offline read-only analysis: inspect (capture summary and connections), list (paged frames), search (paged frames matching filter), or export (write matching frames to an artifact)",
		),
	path: type("string").describe(
		"Local HAR or structured capture file, resolved against the session cwd. URLs are rejected; this tool never fetches a target",
	),
	"format?": type
		.enumerated("auto", "har", "json", "ndjson")
		.describe("Capture format override; auto detects HAR 1.2, JSON capture objects, or CDP NDJSON (default auto)"),
	"url?": type("string").describe(
		"Case-insensitive substring filter on the WebSocket URL; applies to list/search/export",
	),
	"filter?": type("string").describe(
		"Case-insensitive substring filter over the frame payload and URL; required for search",
	),
	"regex?": type("boolean").describe("Treat filter as a JavaScript regular expression instead of a literal string"),
	"direction?": type
		.enumerated("in", "out")
		.describe("Keep only inbound (server→client) or outbound (client→server) frames"),
	"opcode?": type("number").describe("Keep only frames with this WebSocket opcode (0, 1, 2, 8, 9, 10, ...)"),
	"offset?": type("number").describe("Zero-based frame offset after filtering (default 0)"),
	"limit?": type("number").describe(
		"Maximum frames: list/search default 50 (max 500); export default 1000 (max 5000)",
	),
	"max_bytes?": type("number").describe(
		"Output cap: inspect/list/search truncate the rendered text (default 262144, max 4194304); export caps the artifact (default 1048576, max 16777216)",
	),
	"export_format?": type
		.enumerated("json", "ndjson")
		.describe("export only: artifact format, a JSON array or one frame per line (default json)"),
});

export type WebSocketObserveParams = typeof websocketObserveSchema.infer;
export type WebSocketObserveAction = WebSocketObserveParams["action"];
export type WebSocketCaptureFormat = "har" | "json" | "ndjson";
export type WebSocketDirection = "in" | "out" | "unknown";
export type WebSocketObserveStatus =
	| "ok"
	| "not_found"
	| "not_a_file"
	| "unreadable"
	| "empty"
	| "file_too_large"
	| "invalid_format"
	| "artifact_unavailable"
	| "error";

export interface WebSocketFrameInfo {
	index: number;
	connection: number;
	url: string;
	direction: WebSocketDirection;
	timestamp?: string | number;
	time?: string;
	opcode?: number;
	opcodeName?: string;
	encoding: "text" | "base64";
	payloadType: "json" | "text" | "empty" | "binary";
	bytes: number;
	preview: string;
	previewTruncated: boolean;
	redacted: boolean;
}

export interface WebSocketConnectionInfo {
	index: number;
	url: string;
	frames: number;
	inFrames: number;
	outFrames: number;
	firstTime?: string;
	lastTime?: string;
}

export interface WebSocketObserveDetails {
	action: WebSocketObserveAction;
	status: WebSocketObserveStatus;
	path?: string;
	format?: WebSocketCaptureFormat;
	fileBytes?: number;
	connections?: WebSocketConnectionInfo[];
	frames?: WebSocketFrameInfo[];
	totalConnections?: number;
	totalFrames?: number;
	matchedFrames?: number;
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
	payloadsTruncated?: number;
	error?: string;
}

interface ParsedFrame {
	index: number;
	connection: number;
	url: string;
	direction: WebSocketDirection;
	timestamp?: string | number;
	time?: string;
	opcode?: number;
	opcodeName?: string;
	encoding: "text" | "base64";
	payloadType: "json" | "text" | "empty" | "binary";
	payload: string;
	payloadRedacted: string;
	bytes: number;
	redacted: boolean;
	redactions: number;
	preview: string;
	previewTruncated: boolean;
}

interface RawConnection {
	url: string;
}

interface RawFrame {
	connection: number;
	direction: WebSocketDirection;
	timestamp?: unknown;
	opcode?: unknown;
	payload: string;
	encoding?: "text" | "base64";
}

export interface ParsedWebSocketCapture {
	format: WebSocketCaptureFormat;
	connections: WebSocketConnectionInfo[];
	frames: ParsedFrame[];
	totalConnections: number;
	totalFrames: number;
	truncated: boolean;
}

const OPCODE_NAMES: Record<number, string> = {
	0: "continuation",
	1: "text",
	2: "binary",
	8: "close",
	9: "ping",
	10: "pong",
};

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
	secret: true,
	clientsecret: true,
	password: true,
	passwd: true,
	pwd: true,
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
};

function asRecord(value: unknown): Record<string, unknown> | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, keys: readonly string[]): unknown {
	for (const key of keys) {
		const value = record[key];
		if (value !== undefined && value !== null) return value;
	}
	return undefined;
}

function stringField(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
	const value = field(record, keys);
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "boolean") return String(value);
	return undefined;
}

function isSensitiveKey(key: string): boolean {
	return Object.hasOwn(SENSITIVE_KEYS, key.replace(/[-_\s]/g, "").toLowerCase());
}

/**
 * Redact userinfo and sensitive query values from a WebSocket URL. Never
 * throws: malformed URLs still get the query-key redaction pass.
 */
export function redactWebSocketUrl(raw: string): { url: string; redacted: boolean } {
	let redacted = false;
	let url = raw;
	if (/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i.test(url)) {
		url = url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i, `$1${REDACTED}@`);
		redacted = true;
	}
	const hashIndex = url.indexOf("#");
	const hash = hashIndex === -1 ? "" : url.slice(hashIndex);
	const withoutHash = hashIndex === -1 ? url : url.slice(0, hashIndex);
	const queryIndex = withoutHash.indexOf("?");
	if (queryIndex === -1) return { url: url, redacted };
	const base = withoutHash.slice(0, queryIndex);
	const query = withoutHash.slice(queryIndex + 1);
	const parts = query.split("&").map(part => {
		const equals = part.indexOf("=");
		if (equals <= 0) return part;
		const key = part.slice(0, equals);
		let decodedKey = key;
		try {
			decodedKey = decodeURIComponent(key);
		} catch {
			// Keep the raw key when percent-decoding fails.
		}
		if (!isSensitiveKey(decodedKey)) return part;
		redacted = true;
		return `${key}=${encodeURIComponent(REDACTED)}`;
	});
	return { url: `${base}?${parts.join("&")}${hash}`, redacted };
}

function redactJsonValue(value: unknown, depth: number, counter: { count: number }): unknown {
	if (depth > 12) return value;
	if (Array.isArray(value)) return value.map(item => redactJsonValue(item, depth + 1, counter));
	const record = asRecord(value);
	if (!record) return value;
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

/** Redact credential-looking values from a text frame while preserving JSON shape. */
export function redactTextPayload(payload: string): { payload: string; redacted: boolean; redactions: number } {
	const counter = { count: 0 };
	try {
		const parsed: unknown = JSON.parse(payload);
		const redactedValue = redactJsonValue(parsed, 0, counter);
		if (counter.count === 0) return { payload, redacted: false, redactions: 0 };
		return { payload: JSON.stringify(redactedValue), redacted: true, redactions: counter.count };
	} catch {
		// Not JSON: fall through to textual credential patterns.
	}
	let text = payload;
	const pairs =
		/((?:"|')?(?:authorization|auth|cookie|set-cookie|token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|pwd|session[_-]?id|sid|csrf|xsrf|signature|sig|credential|private[_-]?key|ticket)(?:"|')?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,&;]+)/gi;
	text = text.replace(pairs, (_match, prefix: string) => {
		counter.count += 1;
		return `${prefix}${REDACTED}`;
	});
	text = text.replace(/\b(Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=-]+/gi, (_match, scheme: string) => {
		counter.count += 1;
		return `${scheme} ${REDACTED}`;
	});
	const jwt = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g;
	text = text.replace(jwt, () => {
		counter.count += 1;
		return REDACTED;
	});
	return { payload: text, redacted: counter.count > 0, redactions: counter.count };
}

function normalizeDirection(value: unknown): WebSocketDirection {
	if (typeof value !== "string") return "unknown";
	switch (value.trim().toLowerCase()) {
		case "send":
		case "sent":
		case "out":
		case "outgoing":
		case "client":
		case "request":
		case "client→server":
		case "client->server":
		case "c2s":
			return "out";
		case "receive":
		case "received":
		case "in":
		case "incoming":
		case "server":
		case "response":
		case "server→client":
		case "server->client":
		case "s2c":
			return "in";
		default:
			return "unknown";
	}
}

function normalizeOpcode(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 15) return value;
	if (typeof value !== "string") return undefined;
	const trimmed = value.trim().toLowerCase();
	const numeric = Number(trimmed);
	if (Number.isInteger(numeric) && numeric >= 0 && numeric <= 15) return numeric;
	for (const [opcode, name] of Object.entries(OPCODE_NAMES)) {
		if (name === trimmed) return Number(opcode);
	}
	if (trimmed === "text_frame") return 1;
	if (trimmed === "binary_frame") return 2;
	return undefined;
}

function payloadToString(value: unknown): string {
	if (value === undefined || value === null) return "";
	if (typeof value === "string") return value;
	try {
		return JSON.stringify(value);
	} catch {
		return String(value);
	}
}

function isBase64(value: string): boolean {
	const compact = value.replace(/\s+/g, "");
	if (compact.length === 0 || compact.length % 4 !== 0) return false;
	return /^[A-Za-z0-9+/]*={0,2}$/.test(compact);
}

function payloadBytes(payload: string, encoding: "text" | "base64"): number {
	if (encoding === "base64" && isBase64(payload)) {
		return Buffer.from(payload.replace(/\s+/g, ""), "base64").byteLength;
	}
	return Buffer.byteLength(payload, "utf8");
}

function payloadTypeOf(payload: string, encoding: "text" | "base64"): ParsedFrame["payloadType"] {
	if (encoding === "base64") return "binary";
	if (payload.length === 0) return "empty";
	try {
		JSON.parse(payload);
		return "json";
	} catch {
		return "text";
	}
}

function timestampInfo(value: unknown): { timestamp?: string | number; time?: string } {
	if (typeof value === "number" && Number.isFinite(value)) {
		const millis = value > 1e12 ? value : value > 1e9 ? value * 1000 : undefined;
		if (millis !== undefined) {
			const date = new Date(millis);
			if (!Number.isNaN(date.getTime())) return { timestamp: value, time: date.toISOString() };
		}
		return { timestamp: value };
	}
	if (typeof value === "string") {
		const parsed = Date.parse(value);
		if (!Number.isNaN(parsed)) return { timestamp: value, time: new Date(parsed).toISOString() };
		return { timestamp: value };
	}
	return {};
}

function previewOf(
	payload: string,
	bytes: number,
	encoding: "text" | "base64",
): { preview: string; truncated: boolean } {
	if (encoding === "base64") {
		return { preview: `<binary payload, ${bytes} bytes>`, truncated: false };
	}
	if (payload.length <= PREVIEW_CHARS) return { preview: payload, truncated: false };
	return { preview: payload.slice(0, PREVIEW_CHARS), truncated: true };
}

function buildFrame(raw: RawFrame, index: number, connections: RawConnection[]): ParsedFrame {
	const connection = connections[raw.connection];
	const urlInfo = redactWebSocketUrl(connection?.url ?? "");
	const opcode = normalizeOpcode(raw.opcode);
	const encoding = raw.encoding ?? (opcode === 2 ? "base64" : "text");
	const bytes = payloadBytes(raw.payload, encoding);
	const payloadType = payloadTypeOf(raw.payload, encoding);
	const redaction =
		encoding === "base64" ? { payload: raw.payload, redacted: false, redactions: 0 } : redactTextPayload(raw.payload);
	const preview = previewOf(redaction.payload, bytes, encoding);
	const { timestamp, time } = timestampInfo(raw.timestamp);
	return {
		index,
		connection: raw.connection,
		url: urlInfo.url,
		direction: raw.direction,
		...(timestamp !== undefined ? { timestamp } : {}),
		...(time ? { time } : {}),
		...(opcode !== undefined ? { opcode, opcodeName: OPCODE_NAMES[opcode] ?? "reserved" } : {}),
		encoding,
		payloadType,
		payload: raw.payload,
		payloadRedacted: redaction.payload,
		bytes,
		redacted: redaction.redacted || urlInfo.redacted,
		redactions: redaction.redactions + (urlInfo.redacted ? 1 : 0),
		preview: preview.preview,
		previewTruncated: preview.truncated,
	};
}

function toFrameInfo(frame: ParsedFrame): WebSocketFrameInfo {
	return {
		index: frame.index,
		connection: frame.connection,
		url: frame.url,
		direction: frame.direction,
		...(frame.timestamp !== undefined ? { timestamp: frame.timestamp } : {}),
		...(frame.time ? { time: frame.time } : {}),
		...(frame.opcode !== undefined ? { opcode: frame.opcode, opcodeName: frame.opcodeName } : {}),
		encoding: frame.encoding,
		payloadType: frame.payloadType,
		bytes: frame.bytes,
		preview: frame.preview,
		previewTruncated: frame.previewTruncated,
		redacted: frame.redacted,
	};
}

class RawCaptureBuilder {
	readonly connections: RawConnection[] = [];
	readonly frames: RawFrame[] = [];
	truncated = false;
	private readonly connectionByUrl = new Map<string, number>();

	addConnection(url: string | undefined): number {
		const trimmed = url?.trim();
		const redacted = redactWebSocketUrl(trimmed ? trimmed : "<unknown>");
		this.connections.push({ url: redacted.url });
		return this.connections.length - 1;
	}

	connectionForUrl(url: string | undefined): number {
		const trimmed = url?.trim();
		const key = trimmed ? trimmed : "<unknown>";
		const existing = this.connectionByUrl.get(key);
		if (existing !== undefined) return existing;
		const index = this.addConnection(key);
		this.connectionByUrl.set(key, index);
		return index;
	}

	addFrame(frame: Omit<RawFrame, "connection"> & { connection?: number }): void {
		if (this.frames.length >= MAX_PARSED_FRAMES) {
			this.truncated = true;
			return;
		}
		this.frames.push({ ...frame, connection: frame.connection ?? 0 });
	}
}

function parseStructuredFrame(
	value: unknown,
	connection: number,
	fallback: { direction?: unknown; opcode?: unknown } = {},
): RawFrame | undefined {
	const record = asRecord(value);
	if (!record) return undefined;
	const payloadValue = field(record, ["payload", "payloadData", "data", "message", "text", "body", "content"]);
	const directionValue = field(record, ["direction", "type", "way"]) ?? fallback.direction;
	const opcodeValue = field(record, ["opcode", "opCode", "op_code"]) ?? fallback.opcode;
	if (payloadValue === undefined && directionValue === undefined && opcodeValue === undefined) return undefined;
	const encodingValue = stringField(record, ["encoding", "payloadEncoding", "dataEncoding"]);
	const encoding =
		encodingValue && /^(base64|binary)$/i.test(encodingValue)
			? "base64"
			: normalizeOpcode(opcodeValue) === 2
				? "base64"
				: undefined;
	return {
		connection,
		direction: normalizeDirection(directionValue),
		timestamp: field(record, ["timestamp", "time", "ts", "createdAt"]),
		opcode: opcodeValue,
		payload: payloadToString(payloadValue),
		...(encoding ? { encoding } : {}),
	};
}

function isConnectionShape(record: Record<string, unknown>): boolean {
	if (field(record, ["frames", "messages", "events"]) !== undefined) return true;
	const hasUrl = stringField(record, ["url", "requestUrl", "webSocketUrl"]) !== undefined;
	const hasDirection = field(record, ["direction", "type", "way"]) !== undefined;
	const hasPayload =
		field(record, ["payload", "payloadData", "data", "message", "text", "body", "content"]) !== undefined;
	return hasUrl && !hasDirection && !hasPayload;
}

function isFrameShape(record: Record<string, unknown>): boolean {
	return (
		field(record, ["direction", "type", "way", "opcode", "opCode", "op_code", "payload", "payloadData", "data"]) !==
		undefined
	);
}

function addConnectionObject(value: unknown, builder: RawCaptureBuilder): void {
	const record = asRecord(value);
	if (!record) return;
	const index = builder.addConnection(stringField(record, ["url", "requestUrl", "webSocketUrl"]) ?? "<unknown>");
	const frames = field(record, ["frames", "messages", "events"]);
	if (!Array.isArray(frames)) return;
	const fallback = {
		direction: field(record, ["direction", "type", "way"]),
		opcode: field(record, ["opcode", "opCode", "op_code"]),
	};
	for (const item of frames) {
		if (typeof item === "string") {
			builder.addFrame({
				connection: index,
				direction: normalizeDirection(fallback.direction),
				opcode: fallback.opcode,
				payload: item,
			});
			continue;
		}
		const frame = parseStructuredFrame(item, index, fallback);
		if (frame) builder.addFrame(frame);
	}
}

function addFlatFrames(items: unknown[], builder: RawCaptureBuilder): void {
	for (const item of items) {
		if (typeof item === "string") {
			builder.addFrame({
				connection: builder.connectionForUrl("<unknown>"),
				direction: "unknown",
				payload: item,
			});
			continue;
		}
		const record = asRecord(item);
		if (!record) continue;
		const url = stringField(record, ["url", "requestUrl", "webSocketUrl"]) ?? "<unknown>";
		const frame = parseStructuredFrame(item, builder.connectionForUrl(url));
		if (frame) builder.addFrame(frame);
	}
}

function parseStructuredCapture(root: unknown, builder: RawCaptureBuilder): void {
	const rootRecord = asRecord(root);
	const containers = rootRecord ? field(rootRecord, ["websockets", "connections", "sockets", "captures"]) : undefined;
	const rootFrames = rootRecord ? field(rootRecord, ["frames", "messages", "events"]) : undefined;

	if (Array.isArray(containers)) {
		for (const item of containers) {
			const record = asRecord(item);
			if (record && isConnectionShape(record)) addConnectionObject(record, builder);
			else if (record && isFrameShape(record)) addFlatFrames([item], builder);
			else if (typeof item === "string") addFlatFrames([item], builder);
		}
	}
	if (Array.isArray(rootFrames)) addFlatFrames(rootFrames, builder);

	if (!containers && !rootFrames && Array.isArray(root)) {
		const connectionLike = root.some(item => {
			const record = asRecord(item);
			return record !== undefined && isConnectionShape(record) && !isFrameShape(record);
		});
		if (connectionLike) {
			for (const item of root) {
				const record = asRecord(item);
				if (record && isConnectionShape(record)) addConnectionObject(record, builder);
			}
		} else {
			addFlatFrames(root, builder);
		}
	}

	if (!containers && !rootFrames && !Array.isArray(root) && rootRecord && isConnectionShape(rootRecord)) {
		addConnectionObject(rootRecord, builder);
	}
}

function parseHarCapture(root: Record<string, unknown>, builder: RawCaptureBuilder): void {
	const log = asRecord(root.log);
	const entries = log ? field(log, ["entries"]) : undefined;
	if (!Array.isArray(entries)) {
		throw new ToolError("invalid HAR capture: expected log.entries to be an array");
	}
	for (const entry of entries) {
		const record = asRecord(entry);
		if (!record) continue;
		const request = asRecord(field(record, ["request"]));
		const url =
			stringField(record, ["_webSocketUrl", "webSocketUrl", "url"]) ??
			(request ? stringField(request, ["url"]) : undefined) ??
			"<unknown>";
		const messages = field(record, ["_webSocketMessages", "webSocketMessages", "_webSocketFrames", "messages"]);
		const resourceType = stringField(record, ["_resourceType", "resourceType"]);
		const isWebSocket =
			/^wss?:\/\//i.test(url) || resourceType?.toLowerCase() === "websocket" || Array.isArray(messages);
		if (!isWebSocket) continue;
		const index = builder.addConnection(url);
		if (!Array.isArray(messages)) continue;
		for (const message of messages) {
			const messageRecord = asRecord(message);
			if (!messageRecord) continue;
			const type = field(messageRecord, ["type", "direction", "way"]);
			const opcode = field(messageRecord, ["opcode", "opCode"]);
			const payloadValue = field(messageRecord, ["data", "payload", "message", "text", "body"]);
			builder.addFrame({
				connection: index,
				direction: normalizeDirection(type),
				timestamp: field(messageRecord, ["time", "timestamp", "ts"]),
				opcode,
				payload: payloadToString(payloadValue),
				encoding: normalizeOpcode(opcode) === 2 ? "base64" : "text",
			});
		}
	}
}

interface CdpEvent {
	method: string;
	params?: Record<string, unknown>;
}

function parseCdpEvents(events: CdpEvent[], builder: RawCaptureBuilder): void {
	const byRequestId = new Map<string, number>();
	const connectionFor = (requestId: string, url: string): number => {
		const existing = byRequestId.get(requestId);
		if (existing !== undefined) {
			if (url !== "<unknown>" && builder.connections[existing]?.url === "<unknown>") {
				builder.connections[existing] = { url: redactWebSocketUrl(url).url };
			}
			return existing;
		}
		const index = builder.addConnection(url);
		byRequestId.set(requestId, index);
		return index;
	};
	for (const event of events) {
		const params = event.params ?? {};
		const requestId = stringField(params, ["requestId", "requestID"]) ?? "<unknown>";
		const request = asRecord(field(params, ["request"])) ?? {};
		const response = asRecord(field(params, ["response"])) ?? {};
		const url =
			stringField(params, ["url"]) ?? stringField(request, ["url"]) ?? stringField(response, ["url"]) ?? "<unknown>";
		if (event.method === "Network.webSocketFrameSent" || event.method === "Network.webSocketFrameReceived") {
			const index = connectionFor(requestId, url);
			const opcode = field(response, ["opcode"]);
			builder.addFrame({
				connection: index,
				direction: event.method.endsWith("Received") ? "in" : "out",
				timestamp: field(params, ["timestamp", "time"]),
				opcode,
				payload: payloadToString(field(response, ["payloadData", "payload", "data"])),
				encoding: normalizeOpcode(opcode) === 2 ? "base64" : "text",
			});
			continue;
		}
		if (event.method === "Network.webSocketCreated" || event.method === "Network.webSocketWillSendHandshakeRequest") {
			connectionFor(requestId, url);
		}
	}
}

function parseRootJson(
	root: unknown,
	builder: RawCaptureBuilder,
	forced: WebSocketCaptureFormat | "auto",
): WebSocketCaptureFormat {
	const record = asRecord(root);
	const log = record ? asRecord(record.log) : undefined;
	const isHar = log !== undefined && Array.isArray(field(log, ["entries"]));
	if (isHar && forced !== "ndjson") {
		if (!record) throw new ToolError("invalid HAR capture: expected a JSON object");
		parseHarCapture(record, builder);
		return "har";
	}
	if (forced === "har") {
		throw new ToolError("invalid HAR capture: expected an object with a log.entries array");
	}
	if (forced === "ndjson") {
		throw new ToolError("invalid NDJSON capture: expected one JSON object per line");
	}
	if (record && typeof record.method === "string" && record.method.startsWith("Network.webSocket")) {
		parseCdpEvents([{ method: record.method, params: asRecord(record.params) }], builder);
		return "ndjson";
	}
	const recognized =
		record !== undefined &&
		field(record, ["websockets", "connections", "sockets", "captures", "frames", "messages", "events"]) !== undefined;
	if (forced === "json" || recognized || Array.isArray(root)) {
		if (!recognized && !Array.isArray(root)) {
			throw new ToolError(
				"invalid capture: expected a HAR log, a websockets/connections/frames array, or CDP Network.webSocket events",
			);
		}
		parseStructuredCapture(root, builder);
		return "json";
	}
	throw new ToolError(
		"invalid capture: expected a HAR log, a websockets/connections/frames array, or CDP Network.webSocket events",
	);
}

function parseNdjson(
	text: string,
	builder: RawCaptureBuilder,
	forced: WebSocketCaptureFormat | "auto",
): WebSocketCaptureFormat {
	const lines = text.split(/\r?\n/);
	const values: unknown[] = [];
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index]?.trim() ?? "";
		if (line.length === 0) continue;
		try {
			values.push(JSON.parse(line));
		} catch (error) {
			throw new ToolError(
				`invalid NDJSON capture at line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}
	if (values.length === 0) throw new ToolError("invalid capture: no JSON records found");
	const cdpEvents: CdpEvent[] = [];
	for (const value of values) {
		const record = asRecord(value);
		const method = record ? stringField(record, ["method"]) : undefined;
		if (record && method?.startsWith("Network.webSocket")) {
			cdpEvents.push({ method, params: asRecord(record.params) });
		}
	}
	if (cdpEvents.length > 0 && (forced === "auto" || forced === "ndjson")) {
		parseCdpEvents(cdpEvents, builder);
		return "ndjson";
	}
	if (forced === "har") throw new ToolError("invalid HAR capture: NDJSON input is not a HAR document");
	const looksLikeConnections = values.some(value => {
		const record = asRecord(value);
		return record !== undefined && isConnectionShape(record) && !isFrameShape(record);
	});
	if (looksLikeConnections && forced !== "json") {
		for (const value of values) {
			const record = asRecord(value);
			if (record && isConnectionShape(record)) parseStructuredCapture(record, builder);
		}
		return "ndjson";
	}
	const looksLikeFrames = values.every(value => {
		const record = asRecord(value);
		return record !== undefined && isFrameShape(record);
	});
	if (!looksLikeFrames) {
		throw new ToolError(
			"invalid NDJSON capture: lines must be CDP Network.webSocket events, frame objects, or connection objects",
		);
	}
	parseStructuredCapture(values, builder);
	return "ndjson";
}

/**
 * Parse an offline capture. HAR 1.2 `_webSocketMessages` entries, structured
 * `{websockets|connections|frames}` JSON, and CDP `Network.webSocket*` NDJSON
 * are supported. Throws {@link ToolError} for malformed or unrecognized input.
 */
export function parseWebSocketCapture(
	text: string,
	options: { format?: WebSocketCaptureFormat | "auto" } = {},
): ParsedWebSocketCapture {
	const forced = options.format ?? "auto";
	const body = text.replace(/^\uFEFF/, "").trim();
	if (body.length === 0) throw new ToolError("invalid capture: file is empty");
	const builder = new RawCaptureBuilder();
	let format: WebSocketCaptureFormat;
	try {
		const root: unknown = JSON.parse(body);
		format = parseRootJson(root, builder, forced);
	} catch (error) {
		if (error instanceof ToolError) throw error;
		// Whole-file JSON failed: try CDP NDJSON before reporting a format error.
		format = parseNdjson(body, builder, forced);
	}

	const frames = builder.frames.map((frame, index) => buildFrame(frame, index, builder.connections));
	const connectionStats: WebSocketConnectionInfo[] = builder.connections.map((connection, index) => {
		const own = frames.filter(frame => frame.connection === index);
		const times = own
			.map(frame => frame.time)
			.filter((time): time is string => typeof time === "string")
			.sort();
		return {
			index,
			url: connection.url,
			frames: own.length,
			inFrames: own.filter(frame => frame.direction === "in").length,
			outFrames: own.filter(frame => frame.direction === "out").length,
			...(times[0] ? { firstTime: times[0] } : {}),
			...(times[times.length - 1] ? { lastTime: times[times.length - 1] } : {}),
		};
	});
	return {
		format,
		connections: connectionStats,
		frames,
		totalConnections: connectionStats.length,
		totalFrames: frames.length,
		truncated: builder.truncated,
	};
}

interface FrameFilter {
	url?: string;
	text?: string;
	regex?: boolean;
	direction?: "in" | "out";
	opcode?: number;
}

function frameMatches(frame: ParsedFrame, filter: FrameFilter, matcher: (value: string) => boolean): boolean {
	if (filter.url !== undefined && !frame.url.toLowerCase().includes(filter.url.toLowerCase())) return false;
	if (filter.direction !== undefined && frame.direction !== filter.direction) return false;
	if (filter.opcode !== undefined && frame.opcode !== filter.opcode) return false;
	if (filter.text !== undefined && !matcher(`${frame.url}\n${frame.payload}`)) return false;
	return true;
}

function compileMatcher(filter: FrameFilter): (value: string) => boolean {
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

function formatFrameLine(frame: ParsedFrame): string {
	const direction = frame.direction === "unknown" ? "?" : frame.direction;
	const opcode = frame.opcodeName ? ` opcode=${frame.opcode}:${frame.opcodeName}` : "";
	const time = frame.time ?? (typeof frame.timestamp === "number" ? String(frame.timestamp) : "");
	const redacted = frame.redacted ? " redacted" : "";
	const preview = frame.preview.replace(/\r?\n/g, "\\n");
	const suffix = frame.previewTruncated ? " …" : "";
	return `#${frame.index} ${direction}${opcode} ${frame.payloadType} ${frame.bytes}B${time ? ` ${time}` : ""}${redacted} ${frame.url}\n  ${preview}${suffix}`;
}

function formatConnectionLine(connection: WebSocketConnectionInfo): string {
	const range = connection.firstTime
		? ` ${connection.firstTime}${connection.lastTime && connection.lastTime !== connection.firstTime ? `..${connection.lastTime}` : ""}`
		: "";
	return `#${connection.index} ${connection.url} (in ${connection.inFrames} / out ${connection.outFrames}, total ${connection.frames})${range}`;
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

function summarizeOpcodes(frames: ParsedFrame[]): string {
	const counts = new Map<string, number>();
	for (const frame of frames) {
		const name = frame.opcodeName ?? "unknown";
		counts.set(name, (counts.get(name) ?? 0) + 1);
	}
	return [...counts.entries()]
		.sort((left, right) => right[1] - left[1])
		.map(([name, count]) => `${name}=${count}`)
		.join(", ");
}

function validatePath(raw: string): string {
	const trimmed = raw.trim();
	if (trimmed.length === 0) throw new ToolError("path must not be empty");
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
		throw new ToolError(
			"path must be a local capture file; websocket_observe never connects to a URL or fetches a target",
		);
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

function validateParams(params: WebSocketObserveParams): {
	path: string;
	format: WebSocketCaptureFormat | "auto";
	filter: FrameFilter;
	offset: number;
	limit: number;
	maxBytes: number;
	exportFormat: "json" | "ndjson";
} {
	const action = params.action;
	const path = validatePath(params.path);
	if (params.url !== undefined && params.url.trim().length === 0) {
		throw new ToolError("url filter must not be empty when provided");
	}
	if (params.filter !== undefined && params.filter.length === 0) {
		throw new ToolError("filter must not be empty when provided");
	}
	if (params.regex === true && params.filter === undefined) {
		throw new ToolError("regex requires filter");
	}
	if (action === "search" && params.filter === undefined) {
		throw new ToolError("search requires a filter (use list to enumerate frames without one)");
	}
	if (params.opcode !== undefined && (!Number.isInteger(params.opcode) || params.opcode < 0 || params.opcode > 15)) {
		throw new ToolError("opcode must be an integer from 0 to 15");
	}
	if (params.export_format !== undefined && action !== "export") {
		throw new ToolError(`export_format is not supported by action "${action}"`);
	}
	if (action === "inspect") {
		if (
			params.offset !== undefined ||
			params.limit !== undefined ||
			params.direction !== undefined ||
			params.url !== undefined ||
			params.filter !== undefined ||
			params.opcode !== undefined
		) {
			throw new ToolError(
				"inspect does not accept frame filters, offset, or limit; use list or search to page frames",
			);
		}
	}
	const maxDefault = action === "export" ? DEFAULT_EXPORT_BYTES : DEFAULT_OUTPUT_BYTES;
	const maxLimit = action === "export" ? MAX_EXPORT_BYTES : MAX_OUTPUT_BYTES;
	const maxBytes = integerOption(params.max_bytes, maxDefault, action === "export" ? 1024 : 1024, maxLimit);
	const limitDefault = action === "export" ? DEFAULT_EXPORT_LIMIT : DEFAULT_PAGE_LIMIT;
	const limitMax = action === "export" ? MAX_EXPORT_LIMIT : MAX_PAGE_LIMIT;
	const limit = integerOption(params.limit, limitDefault, 1, limitMax);
	const offset = integerOption(params.offset, 0, 0, Number.MAX_SAFE_INTEGER);
	return {
		path,
		format: params.format ?? "auto",
		filter: {
			...(params.url !== undefined ? { url: params.url } : {}),
			...(params.filter !== undefined ? { text: params.filter } : {}),
			...(params.regex !== undefined ? { regex: params.regex } : {}),
			...(params.direction !== undefined ? { direction: params.direction } : {}),
			...(params.opcode !== undefined ? { opcode: params.opcode } : {}),
		},
		offset,
		limit,
		maxBytes,
		exportFormat: params.export_format ?? "json",
	};
}

function exportRecord(frame: ParsedFrame): Record<string, unknown> {
	return {
		index: frame.index,
		connection: frame.connection,
		url: frame.url,
		direction: frame.direction,
		...(frame.timestamp !== undefined ? { timestamp: frame.timestamp } : {}),
		...(frame.time ? { time: frame.time } : {}),
		...(frame.opcode !== undefined ? { opcode: frame.opcode, opcodeName: frame.opcodeName } : {}),
		encoding: frame.encoding,
		payloadType: frame.payloadType,
		bytes: frame.bytes,
		redacted: frame.redacted,
		payload: frame.payloadRedacted,
	};
}

interface ExportRender {
	text: string;
	framesWritten: number;
	payloadsTruncated: number;
	omitted: number;
}

function renderExport(frames: ParsedFrame[], format: "json" | "ndjson", maxBytes: number): ExportRender {
	const renderLine = (record: Record<string, unknown>, payload: string): string =>
		JSON.stringify({ ...record, payload });
	let text = format === "json" ? "[" : "";
	let framesWritten = 0;
	let payloadsTruncated = 0;
	for (const frame of frames) {
		const record = exportRecord(frame);
		const separator = format === "json" && framesWritten > 0 ? "," : "";
		const closing = format === "json" ? "\n]" : "\n";
		let line = renderLine(record, frame.payloadRedacted);
		if (Buffer.byteLength(`${text}${separator}${line}${closing}`, "utf8") > maxBytes) {
			if (framesWritten > 0) {
				return {
					text: format === "json" ? `${text}${closing}` : text,
					framesWritten,
					payloadsTruncated,
					omitted: frames.length - framesWritten,
				};
			}
			// Fit one frame by shortening its payload; a tiny cap still gets a valid envelope.
			let low = 0;
			let high = frame.payloadRedacted.length;
			let best: string | undefined;
			while (low <= high) {
				const mid = Math.floor((low + high) / 2);
				const candidatePayload = `${frame.payloadRedacted.slice(0, mid)}…[truncated]`;
				const candidate = renderLine(record, candidatePayload);
				const size = Buffer.byteLength(`${format === "json" ? "[" : ""}${candidate}${closing}`, "utf8");
				if (size <= maxBytes) {
					best = candidatePayload;
					low = mid + 1;
				} else {
					high = mid - 1;
				}
			}
			line =
				best !== undefined
					? renderLine(record, best)
					: JSON.stringify({ ...record, payload: "", payloadTruncated: true });
			payloadsTruncated += 1;
		}
		text = `${text}${separator}${line}`;
		framesWritten += 1;
		if (format === "ndjson") text += "\n";
	}
	if (format === "json") text += "\n]";
	return { text, framesWritten, payloadsTruncated, omitted: frames.length - framesWritten };
}

export class WebSocketObserveTool implements AgentTool<typeof websocketObserveSchema, WebSocketObserveDetails> {
	readonly name = "websocket_observe";
	readonly approval: ToolTier = "read";
	readonly label = "WebSocket Observe";
	readonly summary =
		"Offline read-only WebSocket frame analysis of HAR or structured capture files: summarize, list, search, and export";
	readonly description: string;
	readonly parameters = websocketObserveSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(websocketObserveDescription);
	}

	async execute(
		_toolCallId: string,
		params: WebSocketObserveParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<WebSocketObserveDetails>> {
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
							text: `websocket_observe: capture file not found: ${options.path}\nThis tool analyzes existing offline captures only; it never records traffic or connects to a target.`,
						},
					],
					details: { action: params.action, status: "not_found", path: options.path },
				};
			}
			return {
				content: [
					{
						type: "text",
						text: `websocket_observe: cannot read ${options.path}: ${error instanceof Error ? error.message : String(error)}`,
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
				content: [
					{ type: "text", text: `websocket_observe: ${options.path} is a ${special}, not a regular file.` },
				],
				details: { action: params.action, status: "not_a_file", path: options.path, error: special },
			};
		}
		if (!stat.isFile()) {
			return {
				content: [{ type: "text", text: `websocket_observe: ${options.path} is not a regular file.` }],
				details: { action: params.action, status: "not_a_file", path: options.path },
			};
		}
		if (stat.size === 0) {
			return {
				content: [{ type: "text", text: `websocket_observe: ${options.path} is empty.` }],
				details: { action: params.action, status: "empty", path: options.path, fileBytes: 0 },
			};
		}
		if (stat.size > MAX_CAPTURE_FILE_BYTES) {
			return {
				content: [
					{
						type: "text",
						text: `websocket_observe: ${options.path} is ${stat.size} bytes, above the ${MAX_CAPTURE_FILE_BYTES}-byte analysis limit. Split the capture or filter it externally first.`,
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
						text: `websocket_observe: cannot read ${options.path}: ${error instanceof Error ? error.message : String(error)}`,
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

		let parsed: ParsedWebSocketCapture;
		try {
			parsed = parseWebSocketCapture(text, { format: options.format });
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return {
				content: [
					{
						type: "text",
						text: `websocket_observe: cannot analyze ${options.path}: ${message}\nSupported inputs: HAR 1.2 entries with _webSocketMessages, structured JSON captures, or CDP Network.webSocket* NDJSON.`,
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

		if (parsed.totalFrames === 0 && parsed.totalConnections === 0) {
			return {
				content: [
					{
						type: "text",
						text: `websocket_observe: no WebSocket connections found in ${options.path} (format: ${parsed.format}).\nThis tool reads recorded HAR/capture data only; it does not observe live sockets.`,
					},
				],
				details: {
					action: params.action,
					status: "ok",
					path: options.path,
					format: parsed.format,
					fileBytes: stat.size,
					connections: [],
					totalConnections: 0,
					totalFrames: 0,
					matchedFrames: 0,
				},
			};
		}

		if (params.action === "inspect") {
			return this.inspect(parsed, options, stat.size);
		}

		const matcher = compileMatcher(options.filter);
		const matched = parsed.frames.filter(frame => frameMatches(frame, options.filter, matcher));
		if (params.action === "export") {
			const page = matched.slice(options.offset, options.offset + options.limit);
			return this.exportFrames(page, matched.length, parsed, options, stat.size);
		}

		const page = matched.slice(options.offset, options.offset + options.limit);
		const hasMore = options.offset + page.length < matched.length;
		const header = `websocket_observe ${params.action}: ${matched.length} matching of ${parsed.totalFrames} frames (${parsed.format}, ${stat.size} bytes)`;
		const range = page.length
			? `showing ${options.offset}..${options.offset + page.length - 1}`
			: "no frames in range";
		const lines = [header, range, ...page.map(formatFrameLine)];
		if (hasMore) {
			lines.push(
				`… ${matched.length - options.offset - page.length} more; next offset ${options.offset + page.length}`,
			);
		}
		const rendered = capRendered(lines, options.maxBytes);
		return {
			content: [{ type: "text", text: rendered.text }],
			details: {
				action: params.action,
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes: stat.size,
				connections: parsed.connections,
				frames: page.map(toFrameInfo),
				totalConnections: parsed.totalConnections,
				totalFrames: parsed.totalFrames,
				matchedFrames: matched.length,
				offset: options.offset,
				limit: options.limit,
				...(hasMore ? { nextOffset: options.offset + page.length } : {}),
				hasMore,
				truncated: parsed.truncated || rendered.truncated || hasMore,
				redactions: page.reduce((sum, frame) => sum + frame.redactions, 0),
			},
		};
	}

	private inspect(
		parsed: ParsedWebSocketCapture,
		options: { path: string; maxBytes: number },
		fileBytes: number,
	): AgentToolResult<WebSocketObserveDetails> {
		const inFrames = parsed.frames.filter(frame => frame.direction === "in").length;
		const outFrames = parsed.frames.filter(frame => frame.direction === "out").length;
		const times = parsed.frames
			.map(frame => frame.time)
			.filter((time): time is string => typeof time === "string")
			.sort();
		const lines = [
			`websocket_observe inspect: ${options.path}`,
			`Format: ${parsed.format}${parsed.truncated ? " (parsing capped)" : ""}, ${fileBytes} bytes`,
			`Connections: ${parsed.totalConnections}, frames: ${parsed.totalFrames} (in ${inFrames} / out ${outFrames})`,
			`Opcodes: ${summarizeOpcodes(parsed.frames) || "none"}`,
			`Time range: ${times[0] ?? "unknown"} .. ${times[times.length - 1] ?? "unknown"}`,
			`Redactions: ${parsed.frames.reduce((sum, frame) => sum + frame.redactions, 0)}`,
			"",
			...parsed.connections.slice(0, MAX_CONNECTION_LINES).map(formatConnectionLine),
		];
		if (parsed.connections.length > MAX_CONNECTION_LINES) {
			lines.push(
				`… ${parsed.connections.length - MAX_CONNECTION_LINES} more connections; use list/search for paging.`,
			);
		}
		const rendered = capRendered(lines, options.maxBytes);
		return {
			content: [{ type: "text", text: rendered.text }],
			details: {
				action: "inspect",
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes,
				connections: parsed.connections,
				totalConnections: parsed.totalConnections,
				totalFrames: parsed.totalFrames,
				matchedFrames: parsed.totalFrames,
				truncated: parsed.truncated || rendered.truncated,
				redactions: parsed.frames.reduce((sum, frame) => sum + frame.redactions, 0),
			},
		};
	}

	private async exportFrames(
		page: ParsedFrame[],
		matchedFrames: number,
		parsed: ParsedWebSocketCapture,
		options: { path: string; maxBytes: number; exportFormat: "json" | "ndjson"; offset: number; limit: number },
		fileBytes: number,
	): Promise<AgentToolResult<WebSocketObserveDetails>> {
		if (page.length === 0) {
			return {
				content: [
					{ type: "text", text: "websocket_observe export: no frames matched the filters; nothing was written." },
				],
				details: {
					action: "export",
					status: "ok",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalConnections: parsed.totalConnections,
					totalFrames: parsed.totalFrames,
					matchedFrames,
					offset: options.offset,
					limit: options.limit,
					truncated: false,
					redactions: 0,
				},
			};
		}
		const allocation = await this.session.allocateOutputArtifact?.("websocket_observe");
		if (!allocation?.path || !allocation.id) {
			return {
				content: [
					{
						type: "text",
						text: `websocket_observe export: ${page.length} frames matched, but artifact storage is unavailable in this session.`,
					},
				],
				details: {
					action: "export",
					status: "artifact_unavailable",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalFrames: parsed.totalFrames,
					matchedFrames,
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
						text: `websocket_observe export: writing the artifact failed: ${error instanceof Error ? error.message : String(error)}`,
					},
				],
				details: {
					action: "export",
					status: "error",
					path: options.path,
					format: parsed.format,
					fileBytes,
					totalFrames: parsed.totalFrames,
					matchedFrames,
					error: `failed to write artifact: ${error instanceof Error ? error.message : String(error)}`,
				},
			};
		}
		const bytesWritten = Buffer.byteLength(rendered.text, "utf8");
		const omitted = page.length - rendered.framesWritten;
		const text = [
			`websocket_observe export: wrote ${rendered.framesWritten} of ${page.length} matched frames (${bytesWritten} bytes, ${options.exportFormat})`,
			`Saved artifact: artifact://${allocation.id}`,
			`Path: ${allocation.path}`,
			...(omitted > 0 ? [`Truncated: ${omitted} frames omitted at the ${options.maxBytes}-byte cap`] : []),
			...(rendered.payloadsTruncated > 0 ? [`Payloads truncated: ${rendered.payloadsTruncated}`] : []),
			"Payloads are redacted in the artifact; capture order and frame metadata are preserved.",
		].join("\n");
		return {
			content: [{ type: "text", text }],
			details: {
				action: "export",
				status: "ok",
				path: options.path,
				format: parsed.format,
				fileBytes,
				totalConnections: parsed.totalConnections,
				totalFrames: parsed.totalFrames,
				matchedFrames,
				offset: options.offset,
				limit: options.limit,
				hasMore: options.offset + page.length < matchedFrames,
				truncated: omitted > 0 || rendered.payloadsTruncated > 0 || parsed.truncated,
				redactions: page.reduce((sum, frame) => sum + frame.redactions, 0),
				artifactId: allocation.id,
				artifactPath: allocation.path,
				exportFormat: options.exportFormat,
				bytesWritten,
				payloadsTruncated: rendered.payloadsTruncated,
			},
		};
	}
}
