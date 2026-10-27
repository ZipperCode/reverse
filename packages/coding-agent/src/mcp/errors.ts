import { isRecord } from "@reverse/utils";
import type { JsonRpcError } from "./types";

/** MCP transport used by a failed operation. */
export type MCPTransportKind = "http" | "stdio" | "unknown";

/** Protocol stage at which an MCP operation failed. */
export type MCPFailureStage = "connect" | "send" | "receive" | "decode" | "protocol";

/** Stable failure classes exposed in MCP tool diagnostics. */
export type MCPFailureClass =
	| "connect"
	| "timeout"
	| "eof"
	| "reset"
	| "malformed_response"
	| "json_rpc"
	| "http_status"
	| "closed"
	| "unknown";

interface MCPTransportErrorOptions {
	transport: MCPTransportKind;
	stage: MCPFailureStage;
	failure: MCPFailureClass;
	message: string;
	retryable: boolean;
	code?: string | number;
	data?: string;
	traceId?: string;
	cause?: unknown;
	phase?: string;
	signal?: string;
	stderr?: string;
	command?: string;
}

const MAX_MESSAGE_CHARS = 1_000;
const MAX_DATA_CHARS = 2_000;
const MAX_TRACE_ID_CHARS = 128;
const MAX_DATA_STRING_CHARS = 256;
const MAX_DATA_DEPTH = 5;
const MAX_DATA_ENTRIES = 30;
const FETCH_VERBOSE_ADVICE =
	/\s*For more information, pass `verbose: true` in the second argument to fetch\(\)\.?\s*$/i;
// Substring match, not exact: compound names (`client_secret`, `clientSecret`,
// `private_key`, `signingSecret`, `access_token`) must classify as secrets so
// their values never reach the exposed `data:` diagnostic.
const SECRET_KEY =
	/(?:authorization|bearer|cookie|secret|passw(?:or)?d|pwd|token|credential|api[-_]?key|private[-_]?key|access[-_]?key|signature)/i;
const TRACE_KEYS = /^(?:trace[-_]?id|request[-_]?id|correlation[-_]?id|traceparent)$/i;

export class MCPTransportError extends Error {
	/** Transport implementation handling the failed operation. */
	readonly transport: MCPTransportKind;
	/** Protocol stage reached before failure. */
	readonly stage: MCPFailureStage;
	/** Stable machine-readable failure classification. */
	readonly failure: MCPFailureClass;
	/** Whether reconnecting and replaying follows the existing safe-retry policy. */
	readonly retryable: boolean;
	/** Transport, HTTP, subprocess, or JSON-RPC error code when available. */
	readonly code: string | number | undefined;
	/** Bounded, credential-redacted JSON-RPC error data. */
	readonly data: string | undefined;
	/** Safe server trace or request identifier. */
	readonly traceId: string | undefined;
	/** Protocol or lifecycle phase reached before failure (e.g. "spawn", "initialize", "tools/list"). */
	readonly phase: string | undefined;
	/** Subprocess termination signal when available (e.g. "SIGSEGV", "SIGKILL"). */
	readonly signal: string | undefined;
	/** Bounded subprocess stderr output captured before or during failure. */
	readonly stderr: string | undefined;
	/** Subprocess command that failed. */
	readonly command: string | undefined;

	constructor(options: MCPTransportErrorOptions) {
		super(
			sanitizeDiagnosticText(options.message, MAX_MESSAGE_CHARS),
			options.cause === undefined ? undefined : { cause: options.cause },
		);
		this.name = "MCPTransportError";
		this.transport = options.transport;
		this.stage = options.stage;
		this.failure = options.failure;
		this.retryable = options.retryable;
		this.code = options.code;
		this.data = options.data;
		this.traceId = options.traceId;
		this.phase = options.phase;
		this.signal = options.signal;
		this.stderr = options.stderr ? sanitizeDiagnosticTail(options.stderr, MAX_DATA_CHARS) : undefined;
		this.command = options.command ? sanitizeCommandString(options.command) : undefined;
	}
}

/** Prevent replay once a request may have reached the server. */
export function nonRetryableMCPTransportError(error: MCPTransportError): MCPTransportError {
	if (!error.retryable) return error;
	return new MCPTransportError({
		transport: error.transport,
		stage: error.stage,
		failure: error.failure,
		message: error.message,
		retryable: false,
		code: error.code,
		data: error.data,
		traceId: error.traceId,
		phase: error.phase,
		signal: error.signal,
		stderr: error.stderr,
		command: error.command,
		cause: error,
	});
}

function errorCode(error: unknown): string | number | undefined {
	if (!isRecord(error)) return undefined;
	if (typeof error.code === "string" || typeof error.code === "number") return error.code;
	return error.cause === undefined ? undefined : errorCode(error.cause);
}

function sanitizeDiagnosticText(value: string, maxChars: number): string {
	return (
		value
			.replace(FETCH_VERBOSE_ADVICE, "")
			// Redact URL userinfo credentials across any URI scheme (e.g. postgresql://user:secret@host)
			.replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^:\s/]+:[^@\s/]+@/gi, "$1[redacted]:[redacted]@")
			// Redact quoted JSON sensitive keys first while JSON quote/escape boundaries are intact
			.replace(
				/("([A-Za-z0-9_-]*(?:authorization|bearer|cookie|signature|access[-_]?token|api[-_]?key|key|token|secret|password|pwd|credential|private[-_]?key|client[-_]?secret|signing[-_]?secret)[A-Za-z0-9_-]*)"\s*:\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,}]+)/gi,
				(match, prefix: string, key: string) => {
					// OAuth 发现读取端点元数据；URL 凭据仍由前后的专用规则脱敏。
					if (/^(?:authorization|token)[_-]?(?:url|uri|endpoint)$/i.test(key)) return match;
					return `${prefix}"[redacted]"`;
				},
			)
			// Redact entire Cookie and Set-Cookie header lines (handling both literal newlines and escaped \n / \r)
			.replace(/((?:\b(?:cookie|set[-_]?cookie)\b\s*[:=]\s*))(?:\\.[^"'\r\n\\]*|[^"'\r\n\\])+/gi, "$1[redacted]")
			// Redact entire Authorization and Proxy-Authorization header lines (leaving WWW-Authenticate intact)
			.replace(
				/((?:\b(?:authorization|proxy-authorization)\b\s*[:=]\s*))(?:\\.[^"'\r\n\\]*|[^"'\r\n\\])+/gi,
				"$1[redacted]",
			)
			// A credential is token68 and never contains `"`; `Bearer name="…"` is a
			// WWW-Authenticate challenge whose params (resource_metadata, scope, error)
			// drive OAuth discovery, so leave it intact. Exclude quotes so adjacent JSON is not swallowed.
			.replace(/\b(Bearer|Basic)\s+(?![\w.~+/-]+\s*=\s*")[^\s,;"']+/gi, "$1 [redacted]")
			.replace(/([?&](?:access[-_]?token|api[-_]?key|key|token|secret|password)=)[^&#\s"'\\]+/gi, "$1[redacted]")
			.replace(
				/((?:api[-_]?key|private[-_]?key|access[-_]?key|client[-_]?secret|signing[-_]?secret|token|secret|passw(?:or)?d|pwd|credential)\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}"'\\]+)/gi,
				"$1[redacted]",
			)
			.replace(
				/((?:--?(?:access[-_]?token|api[-_]?key|key|token|secret|password|pwd|client[-_]?secret|access[-_]?key))\s+)[^\s,;}]+/gi,
				"$1[redacted]",
			)
			.slice(0, maxChars)
			.trim()
	);
}

/** Sanitize diagnostic text while preserving the trailing tail of the buffer (critical for stderr logs). */
export function sanitizeDiagnosticTail(value: string, maxChars: number, extraSecrets: readonly string[] = []): string {
	let sanitized = sanitizeDiagnosticText(value, Number.MAX_SAFE_INTEGER);
	for (const secret of extraSecrets) {
		if (secret && secret.length >= 3) {
			sanitized = sanitized.replaceAll(secret, "[redacted]");
		}
	}
	if (sanitized.length <= maxChars) return sanitized;
	let start = sanitized.length - maxChars;
	const code = sanitized.charCodeAt(start);
	if (code >= 0xdc00 && code <= 0xdfff) {
		start++;
	}
	return sanitized.slice(start);
}

/** Extract known sensitive argument values from a command line for targeted redaction. */
export function extractSecretArgValues(command: string, args: readonly string[] = []): string[] {
	const secrets: string[] = [];
	const tokens = [command, ...args];
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (!token) continue;

		const urlMatch = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/]+:([^@\s/]+)@/i.exec(token);
		if (urlMatch && urlMatch[1]) {
			secrets.push(urlMatch[1]);
		}

		if (token.startsWith("-")) {
			const eqIndex = token.indexOf("=");
			if (eqIndex > 0) {
				const flag = token.slice(0, eqIndex);
				const val = token.slice(eqIndex + 1);
				if (SECRET_KEY.test(flag) && val) {
					secrets.push(val);
				}
				continue;
			}

			if (SECRET_KEY.test(token)) {
				if (i + 1 < tokens.length) {
					const val = tokens[i + 1];
					if (val) {
						secrets.push(val);
					}
					i++;
				}
				continue;
			}
		}
	}
	return secrets.filter(s => s.length >= 3);
}
/** Redact sensitive credentials from CLI argument vectors before recording or logging. */
export function sanitizeCommandArgv(command: string, args: readonly string[] = []): string {
	const sanitized: string[] = [];
	const tokens = [command, ...args];
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (!token) continue;
		// When an argument follows an inline script flag (-e, -c, --eval), omit the inline code body
		if (i > 0 && /^-(?:e|c|-eval)$/i.test(tokens[i - 1])) {
			sanitized.push("[script]");
			continue;
		}

		if (token.startsWith("-")) {
			const eqIndex = token.indexOf("=");
			if (eqIndex > 0) {
				const flag = token.slice(0, eqIndex);
				if (SECRET_KEY.test(flag)) {
					sanitized.push(`${flag}=[redacted]`);
					continue;
				}
			}

			if (SECRET_KEY.test(token)) {
				sanitized.push(token);
				if (i + 1 < tokens.length) {
					sanitized.push("[redacted]");
					i++;
				}
				continue;
			}
		}

		sanitized.push(sanitizeDiagnosticText(token, MAX_MESSAGE_CHARS));
	}
	return sanitized.join(" ");
}

/** Redact command strings that may already be serialized. */
export function sanitizeCommandString(command: string): string {
	if (!command) return "";
	return sanitizeDiagnosticText(
		command
			.replace(/(^|\s)(-(?:e|c|-eval))\s+(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s]+)/gi, "$1$2 [script]")
			.replace(
				/((?:--?(?:access[-_]?token|api[-_]?key|key|token|secret|password|pwd|client[-_]?secret|access[-_]?key))\s*[=:]\s*)[^\s,;]+/gi,
				"$1[redacted]",
			)
			.replace(
				/((?:--?(?:access[-_]?token|api[-_]?key|key|token|secret|password|pwd|client[-_]?secret|access[-_]?key))\s+)[^\s,;]+/gi,
				"$1[redacted]",
			),
		MAX_MESSAGE_CHARS,
	);
}

function sanitizeData(value: unknown, depth: number, seen: WeakSet<object>): unknown {
	if (depth > MAX_DATA_DEPTH) return "[truncated]";
	if (typeof value === "string") return sanitizeDiagnosticText(value, MAX_DATA_STRING_CHARS);
	if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
	if (Array.isArray(value)) {
		if (seen.has(value)) return "[circular]";
		seen.add(value);
		return value.slice(0, MAX_DATA_ENTRIES).map(item => sanitizeData(item, depth + 1, seen));
	}
	if (!isRecord(value)) return String(value);
	if (seen.has(value)) return "[circular]";
	seen.add(value);
	const result: Record<string, unknown> = {};
	let count = 0;
	for (const key in value) {
		if (count++ === MAX_DATA_ENTRIES) break;
		const item = value[key];
		result[key] = SECRET_KEY.test(key) ? "[redacted]" : sanitizeData(item, depth + 1, seen);
	}
	return result;
}

function serializeData(value: unknown): string | undefined {
	if (value === undefined) return undefined;
	try {
		const serialized = JSON.stringify(sanitizeData(value, 0, new WeakSet()));
		if (serialized.length <= MAX_DATA_CHARS) return serialized;
		let previewChars = MAX_DATA_CHARS - 64;
		for (;;) {
			const bounded = JSON.stringify({ truncated: true, preview: serialized.slice(0, previewChars) });
			if (bounded.length <= MAX_DATA_CHARS) return bounded;
			previewChars -= bounded.length - MAX_DATA_CHARS;
		}
	} catch {
		return undefined;
	}
}

function safeTraceId(value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	const trimmed = value.trim();
	if (!trimmed || trimmed.length > MAX_TRACE_ID_CHARS || !/^[A-Za-z0-9._:/-]+$/.test(trimmed)) return undefined;
	return trimmed;
}

function findTraceId(value: unknown, depth = 0): string | undefined {
	if (depth > MAX_DATA_DEPTH || !isRecord(value)) return undefined;
	for (const key in value) {
		const item = value[key];
		if (TRACE_KEYS.test(key)) {
			const traceId = safeTraceId(item);
			if (traceId) return traceId;
		}
		const nested = findTraceId(item, depth + 1);
		if (nested) return nested;
	}
	return undefined;
}

/** Extract a safe request or trace identifier from MCP HTTP response headers. */
export function mcpTraceIdFromHeaders(headers: Headers): string | undefined {
	for (const name of ["traceparent", "x-request-id", "x-trace-id", "x-correlation-id", "cf-ray"]) {
		const traceId = safeTraceId(headers.get(name));
		if (traceId) return traceId;
	}
	return undefined;
}

/** Preserve a server-provided JSON-RPC error without exposing credential-shaped data. */
export function createMCPJsonRpcError(
	transport: MCPTransportKind,
	error: JsonRpcError,
	traceId?: string,
): MCPTransportError {
	return new MCPTransportError({
		transport,
		stage: "protocol",
		failure: "json_rpc",
		message: `MCP error ${error.code}: ${error.message}`,
		retryable: false,
		code: error.code,
		data: serializeData(error.data),
		traceId: safeTraceId(traceId) ?? findTraceId(error.data),
	});
}

/** Classify an arbitrary transport exception while removing runtime-only advice. */
export function normalizeMCPTransportError(
	error: unknown,
	options: {
		transport: MCPTransportKind;
		stage: MCPFailureStage;
		traceId?: string;
		phase?: string;
		signal?: string;
		stderr?: string;
		command?: string;
	},
): MCPTransportError {
	if (error instanceof MCPTransportError) {
		if (
			(options.phase && !error.phase) ||
			(options.signal && !error.signal) ||
			(options.stderr && !error.stderr) ||
			(options.command && !error.command)
		) {
			return new MCPTransportError({
				transport: error.transport,
				stage: error.stage,
				failure: error.failure,
				message: error.message,
				retryable: error.retryable,
				code: error.code,
				data: error.data,
				traceId: error.traceId,
				cause: error.cause ?? error,
				phase: error.phase ?? options.phase,
				signal: error.signal ?? options.signal,
				stderr: error.stderr ?? options.stderr,
				command: error.command ?? options.command,
			});
		}
		return error;
	}
	const message = sanitizeDiagnosticText(error instanceof Error ? error.message : String(error), MAX_MESSAGE_CHARS);
	let code = errorCode(error);
	const normalizedCode = typeof code === "string" ? code.toUpperCase() : code;
	const httpStatusMatch = /^HTTP (\d{3}):/i.exec(message);
	let failure: MCPFailureClass = "unknown";
	let retryable = false;

	if (
		normalizedCode === "ECONNREFUSED" ||
		normalizedCode === "CONNECTIONREFUSED" ||
		normalizedCode === "ENETUNREACH" ||
		normalizedCode === "EHOSTUNREACH" ||
		/\b(?:ECONNREFUSED|ConnectionRefused|ENETUNREACH|EHOSTUNREACH)\b/i.test(message)
	) {
		failure = "connect";
		retryable = true;
	} else if (normalizedCode === "ECONNRESET" || /\bECONNRESET\b/i.test(message)) {
		failure = "reset";
		retryable = true;
	} else if (normalizedCode === "EPIPE" || /\b(?:EPIPE|eof|transport closed|socket closed)\b/i.test(message)) {
		failure = "eof";
		retryable = true;
	} else if (/timeout|timed out/i.test(message)) {
		failure = "timeout";
		retryable = false;
	} else if (
		error instanceof SyntaxError ||
		/(?:invalid|unexpected end).*(?:json|jsonl)|jsonl? (?:parse|parser) error|malformed/i.test(message)
	) {
		failure = "malformed_response";
	} else if (httpStatusMatch) {
		code = Number(httpStatusMatch[1]);
		failure = "http_status";
		retryable = code === 404 || code === 502 || code === 503;
	} else if (/not connected|connection failed|fetch failed/i.test(message)) {
		failure = "connect";
		retryable = true;
	}

	return new MCPTransportError({
		transport: options.transport,
		stage: failure === "connect" ? "connect" : failure === "malformed_response" ? "decode" : options.stage,
		failure,
		message: message || "Unknown MCP transport failure",
		retryable,
		code,
		traceId: safeTraceId(options.traceId),
		phase: options.phase,
		signal: options.signal,
		stderr: options.stderr,
		command: options.command,
		cause: error,
	});
}

function nextStep(error: MCPTransportError): string {
	// Every connection-class failure is retryable before dispatch, so a non-retryable one was lost after sending.
	if (
		!error.retryable &&
		(error.failure === "connect" ||
			error.failure === "eof" ||
			error.failure === "reset" ||
			error.failure === "closed")
	) {
		return "The connection was lost after the request was sent, so it may already have run; check its effect before retrying.";
	}
	if (error.transport === "stdio" && (error.failure === "eof" || error.failure === "connect")) {
		if (error.phase === "spawn" || error.failure === "connect") {
			return "Verify that the command executable exists and has execution permissions.";
		}
		if (error.stderr) {
			if (/dll|shared library|cannot open shared object/i.test(error.stderr)) {
				return "The MCP server is missing required shared libraries/DLLs. Ensure dependencies are in PATH.";
			}
			return "Inspect the subprocess stderr above, resolve the server failure, then retry.";
		}
		if (error.code !== undefined && error.code !== 0) {
			return `Subprocess exited with code ${error.code}. Check the server command arguments and environment.`;
		}
		if (error.signal) {
			return `Subprocess was terminated by signal ${error.signal}. Check for crashes or external signals.`;
		}
	}
	switch (error.failure) {
		case "connect":
			return "Check that the MCP server is running and reachable, then retry.";
		case "timeout":
			return "Check server health or increase the MCP timeout; the request outcome is unknown.";
		case "eof":
		case "reset":
			return error.transport === "stdio"
				? "Inspect the MCP subprocess logs, restart the server, then retry."
				: "Check the MCP server logs and availability, then retry.";
		case "malformed_response":
			return "Inspect the MCP server logs for an invalid JSON-RPC response.";
		case "json_rpc":
			return "Address the server-reported MCP error before retrying.";
		case "http_status":
			return error.retryable
				? "Check the MCP server status, then retry."
				: "Check the MCP endpoint and authentication configuration.";
		case "closed":
			return "Reconnect the MCP server, then retry.";
		case "unknown":
			return "Inspect the MCP server logs and transport configuration.";
	}
}

/** Render an MCP tool failure as stable, actionable diagnostic fields. */
export function formatMCPToolFailure(error: unknown, serverName: string, toolName: string): string {
	const diagnostic =
		error instanceof MCPTransportError
			? error
			: normalizeMCPTransportError(error, { transport: "unknown", stage: "protocol" });
	const lines = [
		"MCP failure",
		`server: ${sanitizeDiagnosticText(serverName, MAX_MESSAGE_CHARS)}`,
		`tool: ${sanitizeDiagnosticText(toolName, MAX_MESSAGE_CHARS)}`,
		`transport: ${diagnostic.transport}`,
		`stage: ${diagnostic.stage}`,
		`failure: ${diagnostic.failure}`,
		`retryable: ${diagnostic.retryable ? "yes" : "no"}`,
		`message: ${diagnostic.message}`,
	];
	if (diagnostic.phase !== undefined) lines.push(`phase: ${diagnostic.phase}`);
	if (diagnostic.command !== undefined) lines.push(`command: ${diagnostic.command}`);
	if (diagnostic.code !== undefined) lines.push(`code: ${String(diagnostic.code)}`);
	if (diagnostic.signal !== undefined) lines.push(`signal: ${diagnostic.signal}`);
	if (diagnostic.stderr !== undefined) lines.push(`stderr: ${diagnostic.stderr}`);
	if (diagnostic.traceId !== undefined) lines.push(`trace_id: ${diagnostic.traceId}`);
	if (diagnostic.data !== undefined) lines.push(`data: ${diagnostic.data}`);
	lines.push(`next: ${nextStep(diagnostic)}`);
	return lines.join("\n");
}
