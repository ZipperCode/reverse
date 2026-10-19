import { redactEvidenceText } from "../evidence/contracts";
import type { AddFactInput } from "../evidence/contracts";

export const DYNAMIC_EVENT_SOURCES = ["frida", "browser", "dap", "unidbg", "custom"] as const;
export type DynamicEventSource = (typeof DYNAMIC_EVENT_SOURCES)[number];

export const DYNAMIC_EVENT_KINDS = [
	"stdout",
	"stderr",
	"message",
	"trace",
	"lifecycle",
	"error",
	"network",
	"crypto",
	"storage",
	"dom",
	"breakpoint",
	"step",
	"custom",
] as const;
export type DynamicEventKind = (typeof DYNAMIC_EVENT_KINDS)[number];

export interface UniversalDynamicEvent {
	id: string;
	source: DynamicEventSource;
	sessionId: string;
	seq: number;
	timestamp: string;
	kind: DynamicEventKind;
	channel?: string;
	target?: string;
	payload?: unknown;
	raw?: string;
	metadata?: Record<string, unknown>;
}

export const DYNAMIC_LOCATOR_PREFIX = "session:";
export const DYNAMIC_LOCATOR_REGEX = /^session:([a-zA-Z0-9_.-]+):seq:(\d+)$/;

export function formatDynamicLocator(sessionId: string, seq: number): string {
	return `session:${sessionId}:seq:${seq}`;
}

export function parseDynamicLocator(locator: string): { sessionId: string; seq: number } | null {
	if (!locator || typeof locator !== "string") return null;
	const match = locator.match(DYNAMIC_LOCATOR_REGEX);
	if (!match) return null;
	return {
		sessionId: match[1],
		seq: parseInt(match[2], 10),
	};
}

export function isDynamicLocator(locator: string): boolean {
	return Boolean(locator && DYNAMIC_LOCATOR_REGEX.test(locator.trim()));
}

export interface NormalizeDynamicEventOptions {
	target?: string;
	seq?: number;
	timestamp?: string;
	metadata?: Record<string, unknown>;
}

export function normalizeFridaEvent(
	raw: unknown,
	sessionId: string,
	options: NormalizeDynamicEventOptions = {},
): UniversalDynamicEvent {
	const timestamp = options.timestamp || new Date().toISOString();
	const seq = options.seq ?? 1;
	const target = options.target;

	if (raw && typeof raw === "object") {
		const obj = raw as Record<string, unknown>;
		const rawSeq = typeof obj.seq === "number" ? obj.seq : seq;
		const rawId = typeof obj.id === "string" ? obj.id : `ev_${sessionId}_${rawSeq}`;
		const rawTimestamp = typeof obj.timestamp === "string" ? obj.timestamp : timestamp;
		const rawChannel = typeof obj.channel === "string" ? obj.channel : undefined;
		const rawTarget = typeof obj.target === "string" ? obj.target : target;

		let kind: DynamicEventKind = "message";
		if (obj.kind && typeof obj.kind === "string") {
			const candidate = obj.kind.toLowerCase();
			if (DYNAMIC_EVENT_KINDS.includes(candidate as DynamicEventKind)) {
				kind = candidate as DynamicEventKind;
			}
		} else if (obj.type === "error" || rawChannel === "error") {
			kind = "error";
		} else if (rawChannel === "trace") {
			kind = "trace";
		} else if (rawChannel === "lifecycle" || rawChannel === "spawn") {
			kind = "lifecycle";
		}

		const payload = obj.payload ?? (obj.type === "send" && "payload" in obj ? obj.payload : obj);
		let rawText = typeof obj.raw === "string" ? obj.raw : undefined;
		if (!rawText && typeof payload === "string") {
			rawText = payload;
		}

		return {
			id: rawId,
			source: "frida",
			sessionId,
			seq: rawSeq,
			timestamp: rawTimestamp,
			kind,
			channel: rawChannel ?? (typeof obj.type === "string" ? obj.type : "send"),
			target: rawTarget,
			payload,
			raw: rawText,
			metadata: options.metadata ?? (obj.metadata as Record<string, unknown> | undefined),
		};
	}

	const stringVal = String(raw ?? "");
	return {
		id: `ev_${sessionId}_${seq}`,
		source: "frida",
		sessionId,
		seq,
		timestamp,
		kind: "stdout",
		channel: "stdout",
		target,
		payload: stringVal,
		raw: stringVal,
		metadata: options.metadata,
	};
}

export function normalizeBrowserEvent(
	raw: unknown,
	sessionId: string,
	options: NormalizeDynamicEventOptions = {},
): UniversalDynamicEvent {
	const timestamp = options.timestamp || new Date().toISOString();
	const seq = options.seq ?? 1;
	const target = options.target;

	if (raw && typeof raw === "object") {
		const obj = raw as Record<string, unknown>;
		const rawSeq = typeof obj.seq === "number" ? obj.seq : seq;
		const rawId = typeof obj.id === "string" ? obj.id : `ev_${sessionId}_${rawSeq}`;
		const rawTimestamp = typeof obj.timestamp === "string" ? obj.timestamp : timestamp;
		const rawTarget = typeof obj.target === "string" ? obj.target : typeof obj.url === "string" ? obj.url : target;

		const typeStr = typeof obj.type === "string" ? obj.type.toLowerCase() : "";
		let kind: DynamicEventKind = "custom";
		let channel: string | undefined = typeStr || undefined;

		if (typeStr === "crypto") {
			kind = "crypto";
			channel = "crypto";
		} else if (typeStr === "websocket" || typeStr === "ws") {
			kind = "network";
			channel = "websocket";
		} else if (typeStr === "fetch" || typeStr === "xhr" || typeStr === "request" || typeStr === "response") {
			kind = "network";
			channel = typeStr;
		} else if (typeStr === "dom") {
			kind = "dom";
			channel = "dom";
		} else if (typeStr === "storage" || typeStr === "cookie" || typeStr === "localstorage") {
			kind = "storage";
			channel = "storage";
		} else if (typeStr === "console" || typeStr === "log") {
			kind = "message";
			channel = "console";
		} else if (typeStr === "error" || typeStr === "exception") {
			kind = "error";
			channel = "error";
		} else if (typeStr === "eval") {
			kind = "trace";
			channel = "eval";
		} else if (
			obj.kind &&
			typeof obj.kind === "string" &&
			DYNAMIC_EVENT_KINDS.includes(obj.kind as DynamicEventKind)
		) {
			kind = obj.kind as DynamicEventKind;
		} else {
			kind = "message";
		}

		const payload = obj.payload ?? obj.details ?? obj.data ?? obj;
		const rawText =
			typeof obj.raw === "string" ? obj.raw : typeof payload === "string" ? payload : JSON.stringify(payload);

		return {
			id: rawId,
			source: "browser",
			sessionId,
			seq: rawSeq,
			timestamp: rawTimestamp,
			kind,
			channel,
			target: rawTarget,
			payload,
			raw: rawText,
			metadata: options.metadata ?? (obj.metadata as Record<string, unknown> | undefined),
		};
	}

	const stringVal = String(raw ?? "");
	return {
		id: `ev_${sessionId}_${seq}`,
		source: "browser",
		sessionId,
		seq,
		timestamp,
		kind: "message",
		channel: "console",
		target,
		payload: stringVal,
		raw: stringVal,
		metadata: options.metadata,
	};
}

export function normalizeDapEvent(
	raw: unknown,
	sessionId: string,
	options: NormalizeDynamicEventOptions = {},
): UniversalDynamicEvent {
	const timestamp = options.timestamp || new Date().toISOString();
	const seq = options.seq ?? 1;
	const target = options.target;

	if (raw && typeof raw === "object") {
		const obj = raw as Record<string, unknown>;
		const rawSeq = typeof obj.seq === "number" ? obj.seq : seq;
		const rawId = typeof obj.id === "string" ? obj.id : `ev_${sessionId}_${rawSeq}`;
		const rawTimestamp = typeof obj.timestamp === "string" ? obj.timestamp : timestamp;

		const eventName = typeof obj.event === "string" ? obj.event : typeof obj.type === "string" ? obj.type : "";
		const body = (obj.body && typeof obj.body === "object" ? obj.body : obj) as Record<string, unknown>;

		let kind: DynamicEventKind = "custom";
		let channel: string | undefined = eventName || undefined;

		if (eventName === "output") {
			const category = typeof body.category === "string" ? body.category.toLowerCase() : "";
			kind = category === "stderr" ? "stderr" : "stdout";
			channel = "output";
		} else if (eventName === "stopped") {
			const reason = typeof body.reason === "string" ? body.reason.toLowerCase() : "";
			if (reason === "step" || reason === "entry") {
				kind = "step";
			} else if (reason === "breakpoint" || reason === "data breakpoint" || reason === "instruction breakpoint") {
				kind = "breakpoint";
			} else {
				kind = "lifecycle";
			}
			channel = "stopped";
		} else if (eventName === "breakpoint") {
			kind = "breakpoint";
			channel = "breakpoint";
		} else if (
			eventName === "continued" ||
			eventName === "exited" ||
			eventName === "terminated" ||
			eventName === "initialized"
		) {
			kind = "lifecycle";
			channel = eventName;
		} else if (
			obj.kind &&
			typeof obj.kind === "string" &&
			DYNAMIC_EVENT_KINDS.includes(obj.kind as DynamicEventKind)
		) {
			kind = obj.kind as DynamicEventKind;
		}

		const rawOutput = typeof body.output === "string" ? body.output : undefined;
		const rawText = typeof obj.raw === "string" ? obj.raw : (rawOutput ?? JSON.stringify(body));

		return {
			id: rawId,
			source: "dap",
			sessionId,
			seq: rawSeq,
			timestamp: rawTimestamp,
			kind,
			channel,
			target,
			payload: body,
			raw: rawText,
			metadata: options.metadata,
		};
	}

	const stringVal = String(raw ?? "");
	return {
		id: `ev_${sessionId}_${seq}`,
		source: "dap",
		sessionId,
		seq,
		timestamp,
		kind: "stdout",
		channel: "output",
		target,
		payload: stringVal,
		raw: stringVal,
		metadata: options.metadata,
	};
}

export function normalizeDynamicEvent(
	raw: unknown,
	defaultSource: DynamicEventSource = "custom",
	sessionId: string,
	options: NormalizeDynamicEventOptions = {},
): UniversalDynamicEvent {
	if (raw && typeof raw === "object") {
		const obj = raw as Record<string, unknown>;
		if (obj.source === "frida") {
			return normalizeFridaEvent(raw, sessionId, options);
		}
		if (obj.source === "browser") {
			return normalizeBrowserEvent(raw, sessionId, options);
		}
		if (obj.source === "dap") {
			return normalizeDapEvent(raw, sessionId, options);
		}

		if (obj.event === "output" || obj.event === "stopped" || "threadId" in obj || "stopLocation" in obj) {
			return normalizeDapEvent(raw, sessionId, options);
		}
		if (
			obj.type === "crypto" ||
			obj.type === "websocket" ||
			obj.type === "xhr" ||
			obj.type === "fetch" ||
			"injectedHooks" in obj
		) {
			return normalizeBrowserEvent(raw, sessionId, options);
		}
		if (obj.type === "send" || ("payload" in obj && "channel" in obj) || "spawnedPid" in obj) {
			return normalizeFridaEvent(raw, sessionId, options);
		}
	}

	switch (defaultSource) {
		case "frida":
			return normalizeFridaEvent(raw, sessionId, options);
		case "browser":
			return normalizeBrowserEvent(raw, sessionId, options);
		case "dap":
			return normalizeDapEvent(raw, sessionId, options);
		default: {
			const timestamp = options.timestamp || new Date().toISOString();
			const seq = options.seq ?? 1;
			const target = options.target;
			const stringVal = typeof raw === "string" ? raw : JSON.stringify(raw);
			return {
				id: `ev_${sessionId}_${seq}`,
				source: defaultSource,
				sessionId,
				seq,
				timestamp,
				kind: "custom",
				channel: "default",
				target,
				payload: raw,
				raw: stringVal,
				metadata: options.metadata,
			};
		}
	}
}

export interface DynamicEventFilterOptions {
	kind?: string;
	channel?: string;
	sinceSeq?: number;
	limit?: number;
	query?: string;
}

export function filterDynamicEvents(
	events: UniversalDynamicEvent[],
	options: DynamicEventFilterOptions = {},
): UniversalDynamicEvent[] {
	let filtered = events;

	if (options.sinceSeq !== undefined) {
		filtered = filtered.filter(e => e.seq > options.sinceSeq!);
	}

	if (options.kind) {
		const targetKind = options.kind.toLowerCase();
		filtered = filtered.filter(e => e.kind.toLowerCase() === targetKind);
	}

	if (options.channel) {
		const targetChannel = options.channel.toLowerCase();
		filtered = filtered.filter(e => (e.channel || "").toLowerCase() === targetChannel);
	}

	if (options.query) {
		const q = options.query.toLowerCase();
		filtered = filtered.filter(e => {
			if (e.raw && e.raw.toLowerCase().includes(q)) return true;
			if (e.target && e.target.toLowerCase().includes(q)) return true;
			if (e.channel && e.channel.toLowerCase().includes(q)) return true;
			if (typeof e.payload === "string" && e.payload.toLowerCase().includes(q)) return true;
			if (typeof e.payload === "object" && e.payload !== null) {
				try {
					return JSON.stringify(e.payload).toLowerCase().includes(q);
				} catch {
					return false;
				}
			}
			return false;
		});
	}

	if (options.limit !== undefined && options.limit > 0) {
		filtered = filtered.slice(0, options.limit);
	}

	return filtered;
}

export const DEFAULT_MAX_DYNAMIC_EVENT_CAPACITY = 1000;

export function appendDynamicEvents(
	buffer: UniversalDynamicEvent[] | undefined,
	newEvents: UniversalDynamicEvent[],
	maxCapacity: number = DEFAULT_MAX_DYNAMIC_EVENT_CAPACITY,
): UniversalDynamicEvent[] {
	const current = buffer ? [...buffer] : [];
	current.push(...newEvents);
	if (current.length > maxCapacity) {
		return current.slice(current.length - maxCapacity);
	}
	return current;
}

export interface DynamicFactConversionOptions {
	target?: string;
	classification?: string;
	tags?: string[];
	titlePrefix?: string;
}

const DYNAMIC_BEARER_AUTH_RE = /(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/gi;

const DYNAMIC_SECRET_KEY_QUOTED_RE =
	/(["']?(?:[a-zA-Z0-9_.-]*(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token|access_token|refresh_token|credential|private_key|_key)\b|key)["']?\s*[:=]\s*)(["'])(?:(?!\2)[^\\]|\\.)*\2/gi;

const DYNAMIC_SECRET_KEY_UNQUOTED_RE =
	/(["']?(?:[a-zA-Z0-9_.-]*(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token|access_token|refresh_token|credential|private_key|_key)\b|key)["']?\s*[:=]\s*)(?!\[REDACTED\])[^\s,'"`;})\]>]+/gi;

const DYNAMIC_STANDALONE_SECRET_RE = /\b(?:[a-zA-Z0-9]+_)*(?:secret|token|password)_[a-zA-Z0-9_]{6,}\b/gi;

export function redactDynamicEvidenceText(input: string): string {
	if (!input) return input;
	let text = redactEvidenceText(input);
	text = text.replace(DYNAMIC_BEARER_AUTH_RE, "$1[REDACTED]");
	text = text.replace(DYNAMIC_SECRET_KEY_QUOTED_RE, (match, prefix, quote) => `${prefix}${quote}[REDACTED]${quote}`);
	text = text.replace(DYNAMIC_SECRET_KEY_UNQUOTED_RE, (match, prefix) => `${prefix}[REDACTED]`);
	text = text.replace(DYNAMIC_STANDALONE_SECRET_RE, "[REDACTED]");
	return text;
}

export function dynamicEventToFactInput(
	event: UniversalDynamicEvent,
	options: DynamicFactConversionOptions = {},
): AddFactInput {
	const target = options.target || event.target || `session:${event.sessionId}`;
	const locator = formatDynamicLocator(event.sessionId, event.seq);
	const sourceTool =
		event.source === "frida"
			? "frida_session"
			: event.source === "browser"
				? "browser_reverse_session"
				: event.source === "dap"
					? "debug"
					: "reverse_dynamic_evidence";

	const channelDesc = event.channel ? ` [${event.channel}]` : "";
	const titlePrefix = options.titlePrefix || `Dynamic ${event.source.toUpperCase()}`;
	const title = `${titlePrefix}: ${event.kind}${channelDesc} on ${target}`;

	let payloadStr = "";
	if (typeof event.payload === "string") {
		payloadStr = event.payload;
	} else if (event.payload !== undefined && event.payload !== null) {
		try {
			payloadStr = JSON.stringify(event.payload, null, 2);
		} catch {
			payloadStr = String(event.payload);
		}
	}

	const content = redactDynamicEvidenceText(
		`Dynamic event captured from session '${event.sessionId}' (${event.source}) at sequence ${event.seq} (${event.timestamp}).\n` +
			`Kind: ${event.kind}, Channel: ${event.channel || "default"}\n` +
			(payloadStr ? `Payload:\n${payloadStr.slice(0, 4000)}` : `Raw: ${String(event.raw || "").slice(0, 4000)}`),
	);

	const excerpt = event.raw ? redactDynamicEvidenceText(event.raw.slice(0, 4096)) : undefined;

	const derivedTags: string[] = ["dynamic", event.source, event.kind];
	if (event.channel && !derivedTags.includes(event.channel)) {
		derivedTags.push(event.channel);
	}
	if (options.tags) {
		for (const t of options.tags) {
			if (!derivedTags.includes(t)) derivedTags.push(t);
		}
	}

	let classification = options.classification;
	if (!classification) {
		if (event.kind === "crypto" || event.channel === "crypto") {
			classification = "CWE-311";
		} else if (
			event.kind === "network" &&
			(event.channel === "ws" || event.channel === "websocket" || event.channel === "xhr")
		) {
			classification = "CWE-319";
		}
	}

	return {
		kind: "fact",
		title,
		target,
		sourceTool,
		locator,
		content,
		excerpt,
		classification,
		tags: derivedTags,
	};
}
