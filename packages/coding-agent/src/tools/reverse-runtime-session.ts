import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { prompt } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseRuntimeSessionDescription from "../prompts/tools/reverse-runtime-session.md" with { type: "text" };
import {
	type RuntimeSessionRecord,
	type RuntimeSessionKind,
	type RuntimeSessionStatus,
	type RestorePlan,
	type RuntimeSessionProbeInfo,
	RUNTIME_SESSION_KINDS,
	DEFAULT_STALE_TIMEOUT_SEC,
	DEFAULT_LIST_LIMIT,
	createRuntimeSessionId,
	computeSessionStaleState,
	ReverseRuntimeSessionStore,
	probeSessionStatus,
	generateRestorePlan,
	sanitizeMetadataObject,
	sanitizeSessionString,
	deriveTargetSummary,
	sanitizeRuntimeSessionRecord,
} from "../reverse-runtime-session";

export const reverseRuntimeSessionSchema = type({
	action: type
		.enumerated("register", "list", "status", "restore", "unregister", "heartbeat")
		.describe(
			"Action to perform: 'register' (add or initialize session record), 'list' (list sessions with stale detection), 'status' (inspect session state and opt-in safe probes), 'restore' (formulate deterministic restore plan), 'unregister' (remove session record), 'heartbeat' (refresh heartbeat and health metrics)",
		),
	"session_id?": type("string").describe(
		"Identifier for the session (e.g. 'runt_frida_...'). Auto-generated on register if omitted. Required for status/restore/unregister/heartbeat",
	),
	"id?": type("string").describe("Alias for session_id"),
	"kind?": type
		.enumerated("frida", "browser", "ida", "ghidra", "generic")
		.describe("Runtime session kind: 'frida', 'browser', 'ida', 'ghidra', or 'generic'. Required for 'register'"),
	"name?": type("string").describe("Optional friendly label or description for the session"),
	"target?": type("string").describe(
		"High-level target description (e.g. process name, PID, URL, binary path, or package ID)",
	),
	"target_details?": type("unknown").describe(
		"Structured target parameters (pid, process, spawn, usb, device, url, db, path, etc.)",
	),
	"connection?": type("unknown").describe(
		"Connection metadata (host, port, device, cdp_url, etc.). Secrets are automatically scrubbed",
	),
	"recovery_hints?": type("unknown").describe(
		"Optional custom recovery hints and tool instructions for restoration",
	),
	"workflow_id?": type("string").describe(
		"Optional reverse_workflow ID to link this runtime session with",
	),
	"step_id?": type("string").describe(
		"Optional reverse_workflow step ID to link this runtime session with",
	),
	"status?": type
		.enumerated("active", "idle", "stale", "closed", "failed", "unknown")
		.describe("Initial or reported status for the session"),
	"caller_status?": type("string").describe(
		"Caller-reported status or observation for heartbeat and status actions",
	),
	"probe?": type("boolean").describe(
		"Perform safe, non-invasive opt-in metadata probe (no arbitrary process manipulation)",
	),
	"probe_result?": type("string").describe(
		"Caller-reported probe outcome, error message, or diagnostic observation",
	),
	"stale_timeout?": type("number.integer >= 10").describe(
		"Stale detection threshold in seconds (default 300)",
	),
	"limit?": type("number.integer >= 1").describe(
		"Maximum sessions to return in 'list' action (default 20, max 100)",
	),
	"filter_kind?": type
		.enumerated("frida", "browser", "ida", "ghidra", "generic")
		.describe("Filter sessions by kind in 'list' action"),
	"filter_status?": type("string").describe("Filter sessions by status in 'list' action"),
	"to_artifact?": type("boolean").describe(
		"Export full session details and restore plan to session artifact",
	),
});

export type ReverseRuntimeSessionParams = typeof reverseRuntimeSessionSchema.infer;

export interface ReverseRuntimeSessionDetails {
	action: "register" | "list" | "status" | "restore" | "unregister" | "heartbeat";
	session?: RuntimeSessionRecord;
	sessions?: RuntimeSessionRecord[];
	restore_plan?: RestorePlan;
	probe_info?: RuntimeSessionProbeInfo;
	artifactId?: string;
	artifactPath?: string;
	unregistered?: boolean;
}

export interface ReverseRuntimeSessionToolOptions {
	stateRoot?: string;
}

export class ReverseRuntimeSessionTool
	implements AgentTool<typeof reverseRuntimeSessionSchema, ReverseRuntimeSessionDetails>
{
	readonly name = "reverse_runtime_session";
	readonly label = "Reverse Runtime Session Registry";
	readonly summary =
		"Unified reverse engineering runtime session registry: manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans across Frida, browser, IDA, and Ghidra.";
	readonly description: string;
	readonly parameters = reverseRuntimeSessionSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "register" || action === "unregister" || action === "heartbeat") {
				return "write";
			}
		}
		return "read";
	};

	private readonly stateRoot?: string;

	constructor(
		private readonly session: ToolSession,
		options: ReverseRuntimeSessionToolOptions = {},
	) {
		this.description = prompt.render(reverseRuntimeSessionDescription);
		this.stateRoot = options.stateRoot;
	}

	private getStore(): ReverseRuntimeSessionStore {
		return ReverseRuntimeSessionStore.forSession(this.session.cwd, this.stateRoot);
	}

	async execute(
		params: ReverseRuntimeSessionParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ReverseRuntimeSessionDetails>> {
		throwIfAborted(signal);

		const store = this.getStore();
		const action = params.action;

		switch (action) {
			case "register": {
				const rawKind = params.kind;
				if (!rawKind || !RUNTIME_SESSION_KINDS.includes(rawKind as RuntimeSessionKind)) {
					throw new ToolError(
						`Invalid or missing session kind: '${String(rawKind)}'. Must be one of: ${RUNTIME_SESSION_KINDS.join(", ")}.`,
					);
				}
				const kind = rawKind as RuntimeSessionKind;
				const sessionId = (params.session_id ?? params.id ?? createRuntimeSessionId(kind)).trim();

				const targetDetails =
					(sanitizeMetadataObject(params.target_details) as Record<string, unknown>) ?? {};
				const connection =
					(sanitizeMetadataObject(params.connection) as Record<string, unknown>) ?? {};

				const targetSummary = deriveTargetSummary(kind, targetDetails, params.target);
				const name = params.name ? sanitizeSessionString(params.name) : undefined;
				const workflowId = params.workflow_id ? sanitizeSessionString(params.workflow_id) : undefined;
				const stepId = params.step_id ? sanitizeSessionString(params.step_id) : undefined;

				const now = new Date().toISOString();
				const initialStatus: RuntimeSessionStatus = params.status ?? "active";

				// Build draft record to formulate default recovery hints if omitted
				const draftRecord: RuntimeSessionRecord = {
					id: sessionId,
					name,
					kind,
					status: initialStatus,
					target_summary: targetSummary,
					target_details: targetDetails,
					connection,
					recovery_hints: {
						restore_tool: "",
						restore_action: "",
						restore_params: {},
						instructions: [],
					},
					created_at: now,
					updated_at: now,
					last_heartbeat_at: now,
					heartbeat_count: 1,
					stale_timeout_sec: params.stale_timeout ?? DEFAULT_STALE_TIMEOUT_SEC,
					status_source: "registered",
					workflow_id: workflowId,
					step_id: stepId,
				};

				// Generate deterministic recovery hints
				const defaultPlan = generateRestorePlan(draftRecord);
				draftRecord.recovery_hints = (sanitizeMetadataObject(
					params.recovery_hints ?? {
						restore_tool: defaultPlan.restore_tool,
						restore_action: defaultPlan.restore_action,
						restore_params: defaultPlan.restore_params,
						instructions: defaultPlan.instructions,
						prerequisites: defaultPlan.prerequisites,
					},
				) as unknown as RuntimeSessionRecord["recovery_hints"]);

				await store.save(draftRecord);

				const lines = [
					`Registered reverse runtime session \`${draftRecord.id}\`:`,
					`- **Kind**: \`${draftRecord.kind}\``,
					`- **Target**: ${draftRecord.target_summary}`,
					`- **Status**: **${draftRecord.status.toUpperCase()}** (Source: ${draftRecord.status_source})`,
					`- **Stale Timeout**: ${draftRecord.stale_timeout_sec}s`,
					draftRecord.name ? `- **Label**: ${draftRecord.name}` : undefined,
					draftRecord.workflow_id ? `- **Workflow**: \`${draftRecord.workflow_id}\`` : undefined,
					draftRecord.step_id ? `- **Step**: \`${draftRecord.step_id}\`` : undefined,
					`- **Restore Tool**: \`${draftRecord.recovery_hints.restore_tool}\` (Action: \`${draftRecord.recovery_hints.restore_action}\`)`,
				].filter(Boolean);

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: { action: "register", session: draftRecord },
				};
			}

			case "list": {
				const filter = {
					kind: params.filter_kind as RuntimeSessionKind | undefined,
					status: params.filter_status,
					workflow_id: params.workflow_id,
					limit: params.limit ?? DEFAULT_LIST_LIMIT,
				};

				const sessions = await store.list(filter);
				if (sessions.length === 0) {
					return {
						content: [
							{
								type: "text",
								text: "No reverse runtime sessions registered in this project. Use reverse_runtime_session(action: 'register', ...) to register a session.",
							},
						],
						details: { action: "list", sessions: [] },
					};
				}

				const lines = [
					`Registered Reverse Runtime Sessions (${sessions.length} shown):`,
					"",
					"| Session ID | Kind | Status | Target | Last Heartbeat | Workflow |",
					"| :--- | :---: | :---: | :--- | :--- | :---: |",
				];

				for (const s of sessions) {
					const staleBadge = s.status === "stale" ? " [STALE]" : "";
					const statusText = `**${s.status.toUpperCase()}**${staleBadge}`;
					const targetPreview = s.target_summary.length > 40 ? s.target_summary.slice(0, 37) + "..." : s.target_summary;
					const wf = s.workflow_id ? `\`${s.workflow_id}\`` : "-";
					lines.push(`| \`${s.id}\` | \`${s.kind}\` | ${statusText} | ${targetPreview} | ${s.last_heartbeat_at} | ${wf} |`);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: { action: "list", sessions },
				};
			}

			case "status": {
				const sessionId = (params.session_id ?? params.id)?.trim();
				if (!sessionId) {
					// If session_id omitted, delegate to list behavior
					const sessions = await store.list({ limit: params.limit ?? DEFAULT_LIST_LIMIT });
					const text = `No session_id specified. Project has ${sessions.length} registered runtime session(s). Call reverse_runtime_session(action: 'status', session_id: '...') to inspect a specific session.`;
					return {
						content: [{ type: "text", text }],
						details: { action: "status", sessions },
					};
				}

				const record = await store.get(sessionId);
				if (!record) {
					throw new ToolError(`Runtime session '${sessionId}' not found.`);
				}

				let probeInfo: RuntimeSessionProbeInfo | undefined;
				if (params.probe || params.caller_status || params.probe_result) {
					probeInfo = await probeSessionStatus(record, {
						caller_status: params.caller_status ? sanitizeSessionString(params.caller_status) : undefined,
						probe_result: params.probe_result ? sanitizeSessionString(params.probe_result) : undefined,
						error: params.probe_result ? sanitizeSessionString(params.probe_result) : undefined,
						cwd: this.session.cwd,
					});

					record.last_probe = probeInfo;
					if (probeInfo.status && probeInfo.status !== record.status) {
						record.status = probeInfo.status;
						record.status_source = probeInfo.source === "caller_reported" ? "caller_reported" : "metadata_probe";
					}
					record.updated_at = new Date().toISOString();
					await store.save(record);
				}

				const staleCheck = computeSessionStaleState(record);
				const restorePlan = generateRestorePlan(record);

				const statusLines = [
					`### Runtime Session: \`${record.id}\``,
					`- **Kind**: \`${record.kind}\``,
					`- **Target**: ${record.target_summary}`,
					`- **Status**: **${record.status.toUpperCase()}** (Stale: ${staleCheck.isStale ? "YES" : "NO"}, Source: ${record.status_source})`,
					`- **Last Heartbeat**: ${record.last_heartbeat_at} (${staleCheck.secondsSinceHeartbeat}s ago, Count: ${record.heartbeat_count})`,
					`- **Stale Timeout Threshold**: ${record.stale_timeout_sec}s`,
				];

				if (record.name) statusLines.push(`- **Label**: ${record.name}`);
				if (record.workflow_id) statusLines.push(`- **Associated Workflow**: \`${record.workflow_id}\``);
				if (record.step_id) statusLines.push(`- **Associated Step**: \`${record.step_id}\``);

				if (Object.keys(record.target_details).length > 0) {
					statusLines.push(`- **Target Details**: \`${JSON.stringify(record.target_details)}\``);
				}
				if (Object.keys(record.connection).length > 0) {
					statusLines.push(`- **Sanitized Connection**: \`${JSON.stringify(record.connection)}\``);
				}

				if (record.last_probe) {
					statusLines.push("- **Last Probe Status**:");
					statusLines.push(`  - Source: ${record.last_probe.source}`);
					statusLines.push(`  - Outcome: ${record.last_probe.ok ? "OK" : "FAILURE"}`);
					if (record.last_probe.message) statusLines.push(`  - Message: ${record.last_probe.message}`);
					statusLines.push(`  - Timestamp: ${record.last_probe.timestamp}`);
				}

				statusLines.push("- **Deterministic Restore Plan Preview**:");
				statusLines.push(`  - Tool: \`${restorePlan.restore_tool}\` (Action: \`${restorePlan.restore_action}\`)`);
				statusLines.push(`  - Parameters: \`${JSON.stringify(restorePlan.restore_params)}\``);
				statusLines.push(`  - Can Restore: ${restorePlan.can_restore ? "YES" : "NO"}`);
				statusLines.push(`  - Reasoning: ${restorePlan.reasoning}`);

				let artifactId: string | undefined;
				let artifactPath: string | undefined;
				if (params.to_artifact && this.session.allocateOutputArtifact) {
					try {
						const alloc = await this.session.allocateOutputArtifact("reverse_runtime_session");
						if (alloc?.path && alloc.id) {
							artifactId = alloc.id;
							artifactPath = alloc.path;
							await fs.writeFile(alloc.path, JSON.stringify({ record: sanitizeRuntimeSessionRecord(record), restorePlan, probeInfo }, null, 2), "utf8");
							statusLines.push(`- **Session Artifact**: \`${artifactId}\` (${alloc.path})`);
						}
					} catch {
						// Fall back to inline text
					}
				}

				return {
					content: [{ type: "text", text: statusLines.join("\n") }],
					details: { action: "status", session: record, restore_plan: restorePlan, probe_info: probeInfo, artifactId, artifactPath },
				};
			}

			case "heartbeat": {
				const sessionId = (params.session_id ?? params.id)?.trim();
				if (!sessionId) {
					throw new ToolError("session_id is required for 'heartbeat' action.");
				}

				const record = await store.get(sessionId);
				if (!record) {
					throw new ToolError(`Runtime session '${sessionId}' not found.`);
				}

				const now = new Date().toISOString();
				record.last_heartbeat_at = now;
				record.updated_at = now;
				record.heartbeat_count = (record.heartbeat_count ?? 0) + 1;

				if (params.status) {
					record.status = params.status;
					record.status_source = "heartbeat";
				} else if (params.caller_status) {
					const lower = params.caller_status.trim().toLowerCase();
					if (lower === "active" || lower === "idle" || lower === "closed" || lower === "failed") {
						record.status = lower as RuntimeSessionStatus;
					}
					record.status_source = "caller_reported";
				} else if (record.status === "stale") {
					record.status = "active";
					record.status_source = "heartbeat";
				}

				if (params.probe_result) {
					const sanitizedMsg = sanitizeSessionString(params.probe_result);
					record.last_probe = {
						timestamp: now,
						ok: record.status !== "failed",
						status: record.status,
						message: sanitizedMsg,
						source: "caller_reported",
					};
				}

				await store.save(record);

				const text = [
					`Heartbeat acknowledged for session \`${record.id}\`:`,
					`- Status: **${record.status.toUpperCase()}**`,
					`- Heartbeat Count: ${record.heartbeat_count}`,
					`- Timestamp: ${record.last_heartbeat_at}`,
					record.last_probe?.message ? `- Observation: ${record.last_probe.message}` : undefined,
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: { action: "heartbeat", session: record },
				};
			}

			case "restore": {
				const sessionId = (params.session_id ?? params.id)?.trim();
				if (!sessionId) {
					throw new ToolError("session_id is required for 'restore' action.");
				}

				const record = await store.get(sessionId);
				if (!record) {
					throw new ToolError(`Runtime session '${sessionId}' not found.`);
				}

				const plan = generateRestorePlan(record);

				const lines = [
					`### Deterministic Restore Plan for \`${record.id}\` (${record.kind})`,
					`- **Current Status**: **${record.status.toUpperCase()}**`,
					`- **Target Tool**: \`${plan.restore_tool}\``,
					`- **Action**: \`${plan.restore_action}\``,
					`- **Can Restore**: ${plan.can_restore ? "**YES**" : "**NO** (insufficient connection parameters)"}`,
					`- **Reasoning**: ${plan.reasoning}`,
					"",
					"#### Parameters to Invoke:",
					"```json",
					JSON.stringify(plan.restore_params, null, 2),
					"```",
					"",
					"#### Prerequisites:",
					...(plan.prerequisites?.length ? plan.prerequisites.map(p => `- ${p}`) : ["- None specified"]),
					"",
					"#### Step-by-Step Instructions:",
					...plan.instructions.map(inst => `${inst}`),
					"",
					"To execute restoration, invoke the indicated tool above with the provided parameters, then issue a heartbeat to re-activate session tracking.",
				];

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: { action: "restore", session: record, restore_plan: plan },
				};
			}

			case "unregister": {
				const sessionId = (params.session_id ?? params.id)?.trim();
				if (!sessionId) {
					throw new ToolError("session_id is required for 'unregister' action.");
				}

				const record = await store.get(sessionId);
				if (!record) {
					throw new ToolError(`Runtime session '${sessionId}' not found.`);
				}

				const deleted = await store.delete(sessionId);

				return {
					content: [
						{
							type: "text",
							text: `Unregistered runtime session \`${sessionId}\` (${record.kind}: ${record.target_summary}). Record deleted from project registry.`,
						},
					],
					details: { action: "unregister", session: record, unregistered: deleted },
				};
			}

			default:
				throw new ToolError(`Unknown reverse_runtime_session action: '${String(action)}'`);
		}
	}
}
