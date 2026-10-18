export const RUNTIME_SESSION_KINDS = [
	"frida",
	"browser",
	"ida",
	"ghidra",
	"generic",
] as const;

export type RuntimeSessionKind = (typeof RUNTIME_SESSION_KINDS)[number];

export const RUNTIME_SESSION_STATUSES = [
	"active",
	"idle",
	"stale",
	"closed",
	"failed",
	"unknown",
] as const;

export type RuntimeSessionStatus = (typeof RUNTIME_SESSION_STATUSES)[number];

export type RuntimeSessionStatusSource =
	| "registered"
	| "heartbeat"
	| "caller_reported"
	| "stale_timeout"
	| "metadata_probe"
	| "restored"
	| "closed";

export interface RuntimeSessionRecoveryHint {
	restore_tool: string;
	restore_action: string;
	restore_params: Record<string, unknown>;
	instructions: string[];
	prerequisites?: string[];
	install_hint?: string;
}

export interface RestorePlan {
	session_id: string;
	kind: RuntimeSessionKind;
	status: RuntimeSessionStatus;
	can_restore: boolean;
	restore_tool: string;
	restore_action: string;
	restore_params: Record<string, unknown>;
	instructions: string[];
	prerequisites?: string[];
	reasoning: string;
}

export interface RuntimeSessionProbeInfo {
	timestamp: string;
	ok: boolean;
	status?: RuntimeSessionStatus;
	message?: string;
	source?: "metadata_check" | "caller_reported";
}

export interface RuntimeSessionRecord {
	id: string;
	name?: string;
	kind: RuntimeSessionKind;
	status: RuntimeSessionStatus;
	target_summary: string;
	target_details: Record<string, unknown>;
	connection: Record<string, unknown>;
	recovery_hints: RuntimeSessionRecoveryHint;
	created_at: string;
	updated_at: string;
	last_heartbeat_at: string;
	heartbeat_count: number;
	stale_timeout_sec: number;
	status_source: RuntimeSessionStatusSource;
	last_probe?: RuntimeSessionProbeInfo;
	workflow_id?: string;
	step_id?: string;
	metadata?: Record<string, unknown>;
}

export const DEFAULT_STALE_TIMEOUT_SEC = 300;
export const MAX_REGISTRY_SESSIONS = 100;
export const MAX_METADATA_VALUE_LENGTH = 4096;
export const MAX_PARAM_STRING_LENGTH = 8192;
export const MAX_LIST_LIMIT = 100;
export const DEFAULT_LIST_LIMIT = 20;

export function createRuntimeSessionId(kind: RuntimeSessionKind): string {
	const safeKind = RUNTIME_SESSION_KINDS.includes(kind) ? kind : "generic";
	return `runt_${safeKind}_${Bun.randomUUIDv7()}`;
}

export function encodeRuntimeSessionProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}

export function computeSessionStaleState(
	record: RuntimeSessionRecord,
	nowMs: number = Date.now(),
): { isStale: boolean; secondsSinceHeartbeat: number; effectiveStatus: RuntimeSessionStatus } {
	const lastHbTime = record.last_heartbeat_at
		? Date.parse(record.last_heartbeat_at)
		: Date.parse(record.updated_at || record.created_at);
	const validHbTime = Number.isFinite(lastHbTime) ? lastHbTime : nowMs;
	const elapsedSec = Math.max(0, Math.floor((nowMs - validHbTime) / 1000));
	const timeoutSec = record.stale_timeout_sec > 0 ? record.stale_timeout_sec : DEFAULT_STALE_TIMEOUT_SEC;

	if (record.status === "closed") {
		return { isStale: false, secondsSinceHeartbeat: elapsedSec, effectiveStatus: "closed" };
	}

	const isStale = elapsedSec > timeoutSec;
	if (isStale && record.status !== "failed") {
		return { isStale: true, secondsSinceHeartbeat: elapsedSec, effectiveStatus: "stale" };
	}

	return { isStale, secondsSinceHeartbeat: elapsedSec, effectiveStatus: record.status };
}
