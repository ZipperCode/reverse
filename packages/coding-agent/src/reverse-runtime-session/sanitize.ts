import { redactMemorySecrets } from "../memory-backend/redact";
import {
	type RuntimeSessionRecord,
	type RuntimeSessionKind,
	type RuntimeSessionProbeInfo,
	MAX_METADATA_VALUE_LENGTH,
} from "./contracts";

const SENSITIVE_KEY_NAMES: Record<string, true> = {
	password: true,
	passwd: true,
	pwd: true,
	secret: true,
	token: true,
	api_key: true,
	apikey: true,
	auth_token: true,
	access_token: true,
	refresh_token: true,
	private_key: true,
	bearer: true,
	authorization: true,
	credential: true,
	credentials: true,
};


const LIVE_HANDLE_KEYS: Record<string, true> = {
	socket: true,
	stream: true,
	stdin: true,
	stdout: true,
	stderr: true,
	_handle: true,
	handle: true,
	channel: true,
	pipe: true,
	child_process: true,
	process_handle: true,
	listeners: true,
};

export function sanitizeUrlString(rawUrl: string): string {
	try {
		const parsed = new URL(rawUrl);
		if (parsed.username) parsed.username = "[REDACTED]";
		if (parsed.password) parsed.password = "[REDACTED]";

		const params = parsed.searchParams;
		for (const [key] of Array.from(params.entries())) {
			const lowerKey = key.toLowerCase();
			if (
				lowerKey.includes("token") ||
				lowerKey.includes("auth") ||
				lowerKey.includes("key") ||
				lowerKey.includes("secret") ||
				lowerKey.includes("sig") ||
				lowerKey.includes("pass") ||
				lowerKey.includes("pwd") ||
				lowerKey.includes("cred")
			) {
				params.set(key, "[REDACTED]");
			}
		}
		return parsed
			.toString()
			.replaceAll("%5BREDACTED%5D", "[REDACTED]");
	} catch {
		// Fallback regex replacement for non-standard / relative URLs
		return rawUrl
			.replace(/([?&](?:token|auth|key|secret|password|passwd|sig|cred|pwd|apikey)[^=]*=)[^&\s,"'`;}]+/gi, "$1[REDACTED]")
			.replace(/((?:https?|wss?):\/\/)([^:@/\s]+):([^:@/\s]+)@/gi, "$1[REDACTED]:[REDACTED]@");
	}
}

export function sanitizeSessionString(value: string): string {
	if (typeof value !== "string") return "";
	let str = value;
	if (str.length > MAX_METADATA_VALUE_LENGTH) {
		str = str.slice(0, MAX_METADATA_VALUE_LENGTH) + "... [truncated]";
	}

	let redacted = redactMemorySecrets(str);
	redacted = redacted.replace(/(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]");
	redacted = redacted.replace(
		/(\b(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token|access_token|refresh_token|credential)\s*[:=]\s*['"]?)[^\s,'"`;}]+/gi,
		"$1[REDACTED]",
	);

	if (redacted.includes("://") || redacted.includes("ws://") || redacted.includes("wss://")) {
		try {
			new URL(redacted);
			redacted = sanitizeUrlString(redacted);
		} catch {
			redacted = redacted.replace(
				/((?:https?|wss?):\/\/[^\s"'`<>]+)/gi,
				match => sanitizeUrlString(match),
			);
		}
	}

	return redacted;
}

export function sanitizeMetadataObject(
	obj: unknown,
	depth: number = 0,
): Record<string, unknown> | unknown[] | string | number | boolean | null {
	if (obj === null || obj === undefined) return null;
	if (typeof obj === "boolean" || typeof obj === "number") return obj;
	if (typeof obj === "string") return sanitizeSessionString(obj);
	if (typeof obj !== "object") return null;

	if (depth > 5) return "[Max depth exceeded]";

	if (Array.isArray(obj)) {
		return obj.map(item => sanitizeMetadataObject(item, depth + 1));
	}

	const result: Record<string, unknown> = {};
	for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
		const lowerKey = key.toLowerCase();
		if (LIVE_HANDLE_KEYS[lowerKey]) {
			continue;
		}

		if (
			SENSITIVE_KEY_NAMES[lowerKey] ||
			((lowerKey.includes("password") ||
				lowerKey.includes("passwd") ||
				lowerKey.includes("secret") ||
				lowerKey.includes("token") ||
				lowerKey.includes("api_key") ||
				lowerKey.includes("apikey") ||
				lowerKey.includes("auth_token") ||
				lowerKey.includes("access_token") ||
				lowerKey.includes("private_key") ||
				lowerKey.includes("credential")) &&
				lowerKey !== "token_count" &&
				lowerKey !== "tokens" &&
				lowerKey !== "author")
		) {
			result[key] = "[REDACTED]";
			continue;
		}

		if (typeof val === "function" || typeof val === "symbol") {
			continue;
		}

		result[key] = sanitizeMetadataObject(val, depth + 1);
	}

	return result;
}

export function deriveTargetSummary(
	kind: RuntimeSessionKind,
	targetDetails: Record<string, unknown>,
	explicitTarget?: string,
): string {
	if (explicitTarget && typeof explicitTarget === "string" && explicitTarget.trim().length > 0) {
		return sanitizeSessionString(explicitTarget.trim());
	}

	if (targetDetails && typeof targetDetails === "object") {
		const field =
			targetDetails.url ??
			targetDetails.process ??
			targetDetails.package ??
			targetDetails.binary ??
			targetDetails.path ??
			targetDetails.db ??
			targetDetails.idb_path;

		if (typeof field === "string" && field.trim().length > 0) {
			const label = targetDetails.pid ? `PID ${targetDetails.pid} (${field})` : field;
			return sanitizeSessionString(label);
		}

		if (targetDetails.pid !== undefined && targetDetails.pid !== null) {
			return `PID ${targetDetails.pid}`;
		}

		if (Object.keys(targetDetails).length > 0) {
			return sanitizeSessionString(JSON.stringify(targetDetails));
		}
	}

	return `${kind} session`;
}

export function sanitizeRuntimeSessionRecord(record: RuntimeSessionRecord): RuntimeSessionRecord {
	const sanitizedDetails = (sanitizeMetadataObject(record.target_details) as Record<string, unknown>) ?? {};
	const sanitizedConnection = (sanitizeMetadataObject(record.connection) as Record<string, unknown>) ?? {};

	const targetSummary = record.target_summary
		? sanitizeSessionString(record.target_summary)
		: deriveTargetSummary(record.kind, sanitizedDetails);

	const name = record.name ? sanitizeSessionString(record.name) : undefined;
	const workflowId = record.workflow_id ? sanitizeSessionString(record.workflow_id) : undefined;
	const stepId = record.step_id ? sanitizeSessionString(record.step_id) : undefined;

	let lastProbe: RuntimeSessionProbeInfo | undefined;
	if (record.last_probe) {
		lastProbe = {
			...record.last_probe,
			message: record.last_probe.message ? sanitizeSessionString(record.last_probe.message) : undefined,
		};
	}

	const recoveryHints = record.recovery_hints
		? (sanitizeMetadataObject(record.recovery_hints) as unknown as RuntimeSessionRecord["recovery_hints"])
		: record.recovery_hints;

	const metadata = record.metadata
		? (sanitizeMetadataObject(record.metadata) as Record<string, unknown>)
		: undefined;

	return {
		...record,
		name,
		target_summary: targetSummary,
		target_details: sanitizedDetails,
		connection: sanitizedConnection,
		recovery_hints: recoveryHints,
		last_probe: lastProbe,
		workflow_id: workflowId,
		step_id: stepId,
		metadata,
	};
}
