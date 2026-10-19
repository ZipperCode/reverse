import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import type { OutputMeta } from "@reverse/tui/tools/output-meta";
import { type } from "@reverse/omptype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseDynamicEvidenceDescription from "../prompts/tools/reverse-dynamic-evidence.md" with { type: "text" };
import { EvidenceStore, type FactEvidence, type ConclusionEvidence } from "../evidence";
import { ReverseWorkflowStore } from "../reverse-workflow";
import {
	ReverseKnowledgeStore,
	learnFromEvidenceAndWorkflows,
	type ReverseKnowledgeRecord,
} from "../reverse-knowledge";
import { ReverseRuntimeSessionStore } from "../reverse-runtime-session";
import {
	type UniversalDynamicEvent,
	type DynamicEventSource,
	DYNAMIC_EVENT_SOURCES,
	isDynamicLocator,
	normalizeDynamicEvent,
	filterDynamicEvents,
	dynamicEventToFactInput,
} from "../reverse-runtime-session/dynamic-events";
import { dapSessionManager } from "../dap";

export const reverseDynamicEvidenceSchema = type({
	action: type
		.enumerated("ingest", "events", "verify", "status")
		.describe(
			"Action to perform: 'ingest' (normalize and save bounded dynamic events as Evidence facts), 'events' (query and normalize buffered dynamic events without writing), 'verify' (verify hypothesis with dynamic evidence and create verified conclusion), 'status' (inspect dynamic evidence closure for session or workflow)",
		),
	"session_id?": type("string").describe(
		"Runtime session identifier (Frida, Browser, DAP, Unidbg) to pull buffered events from",
	),
	"source?": type
		.enumerated(...DYNAMIC_EVENT_SOURCES)
		.describe("Event source platform: 'frida', 'browser', 'dap', 'unidbg', or 'custom'"),
	"target?": type("string").describe("Target binary, package, process name, or URL associated with these events"),
	"events?": type("unknown").describe("Explicit array of raw or structured dynamic events to ingest or query"),
	"kind?": type("string").describe(
		"Filter events by kind: 'stdout', 'stderr', 'message', 'trace', 'network', 'crypto', 'storage', 'dom', 'breakpoint', 'step', 'lifecycle', 'error'",
	),
	"channel?": type("string").describe(
		"Filter events by channel: 'send', 'console', 'websocket', 'crypto', 'fetch', 'xhr', 'stopped', 'output', etc.",
	),
	"since_seq?": type("number").describe("Filter to events strictly greater than this sequence number"),
	"limit?": type("number").describe("Maximum number of events to ingest or return (default 20, max 100)"),
	"classification?": type("string").describe(
		"Weakness classification for generated facts, e.g. 'CWE-311' (crypto) or 'CWE-319' (cleartext transmission)",
	),
	"tags?": type("string[]").describe(
		"Categorization tags to attach to generated evidence facts, e.g. ['crypto', 'token', 'auth']",
	),
	"workflow_id?": type("string").describe("Reverse workflow ID to link newly ingested dynamic facts and update steps"),
	"step_id?": type("string").describe("Specific workflow step ID to link newly ingested dynamic facts to"),
	"advance_workflow?": type("boolean").describe(
		"Whether to mark the associated workflow step as completed if backed by verified evidence",
	),
	"hypothesis_id?": type("string").describe("Hypothesis ID in Evidence ledger to verify with these dynamic facts"),
	"conclusion?": type("string").describe("Confirmed deductive conclusion text to record when verifying a hypothesis"),
	"method?": type("string").describe(
		"Experimental dynamic method, e.g. 'Frida JNI hook', 'CDP network intercept', 'DAP breakpoint'",
	),
	"command?": type("string").describe("Exact script, CLI invocation, or expression that produced the dynamic outcome"),
	"result?": type("string").describe("Observed empirical result, output string, decrypted buffer, or register delta"),
	"reproducibility?": type("string").describe("Reproducibility metric or description, e.g. '100% (5/5 runs)'"),
	"learn?": type("boolean").describe(
		"Whether to automatically promote verified conclusions into reusable reverse knowledge (default true)",
	),
});

export type ReverseDynamicEvidenceParams = typeof reverseDynamicEvidenceSchema.infer;

export interface IngestDynamicEvidenceDetails {
	action: "ingest" | "events" | "verify" | "status";
	sessionId?: string;
	source: DynamicEventSource;
	target?: string;
	eventsCount: number;
	totalBuffered?: number;
	factIds?: string[];
	facts?: FactEvidence[];
	conclusionId?: string;
	conclusion?: ConclusionEvidence;
	workflowId?: string;
	stepId?: string;
	stepUpdated?: boolean;
	knowledgeCreatedCount?: number;
	knowledgeRecords?: ReverseKnowledgeRecord[];
	events?: UniversalDynamicEvent[];
	statusSummary?: Record<string, unknown>;
	meta?: OutputMeta;
}

export interface ReverseDynamicEvidenceToolOptions {
	stateRoot?: string;
}

export class ReverseDynamicEvidenceTool implements AgentTool<
	typeof reverseDynamicEvidenceSchema,
	IngestDynamicEvidenceDetails
> {
	readonly name = "reverse_dynamic_evidence";
	readonly label = "Reverse Dynamic Evidence & Closure";
	readonly summary =
		"Normalizes and ingests bounded dynamic events (Frida, browser CDP, DAP, Unidbg) into the Evidence ledger, links workflow steps, and promotes verified outcomes into reusable reverse knowledge.";
	readonly parameters = reverseDynamicEvidenceSchema;
	readonly approval: ToolTier = "read";
	readonly strict = true;
	private readonly stateRoot?: string;

	constructor(
		private readonly session: ToolSession,
		options: ReverseDynamicEvidenceToolOptions = {},
	) {
		this.stateRoot = options.stateRoot;
	}
	get description(): string {
		return reverseDynamicEvidenceDescription;
	}

	async execute(
		callId: string,
		params: ReverseDynamicEvidenceParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<IngestDynamicEvidenceDetails> & { details: IngestDynamicEvidenceDetails }> {
		throwIfAborted(signal);

		const cwd = this.session.cwd;
		const action = params.action;
		const sessionId = params.session_id?.trim() || "dynamic_session";
		const source: DynamicEventSource =
			(params.source as DynamicEventSource) ||
			(sessionId.startsWith("runt_frida") || sessionId.includes("frida")
				? "frida"
				: sessionId.startsWith("browser") || sessionId.includes("browser")
					? "browser"
					: sessionId.startsWith("dap_") || sessionId.includes("dap")
						? "dap"
						: "custom");
		const target = params.target?.trim();
		const limit = Math.min(Math.max(params.limit ?? 20, 1), 100);

		// Resolve stores
		const evidenceStore = new EvidenceStore({ repositoryRoot: cwd, stateRoot: this.stateRoot, signal });
		const workflowStore = new ReverseWorkflowStore({ repositoryRoot: cwd, stateRoot: this.stateRoot });
		const knowledgeStore = new ReverseKnowledgeStore({ repositoryRoot: cwd, stateRoot: this.stateRoot });
		const runtimeSessionStore = ReverseRuntimeSessionStore.forSession(cwd, this.stateRoot);

		switch (action) {
			case "events":
			case "ingest": {
				// 1. Gather raw events from input or session manager / runtime store
				const rawEvents = await this.gatherRawEvents(params, source, sessionId, runtimeSessionStore);

				// 2. Normalize events into UniversalDynamicEvent[]
				const normalizedEvents = this.normalizeEventsList(rawEvents, source, sessionId, target);

				// 3. Filter and page events
				const filteredEvents = filterDynamicEvents(normalizedEvents, {
					kind: params.kind,
					channel: params.channel,
					sinceSeq: params.since_seq,
					limit,
				});

				if (action === "events") {
					const lines: string[] = [
						`Dynamic events for session '${sessionId}' (${source}): showing ${filteredEvents.length} of ${normalizedEvents.length} total.`,
					];
					if (filteredEvents.length === 0) {
						lines.push("No dynamic events found matching the specified filters.");
					} else {
						for (const ev of filteredEvents) {
							const preview = ev.raw
								? ev.raw.replace(/\r?\n/g, " ").slice(0, 100)
								: JSON.stringify(ev.payload).slice(0, 100);
							lines.push(`  #${ev.seq} [${ev.kind}/${ev.channel || "event"}] ${preview}`);
						}
					}
					return {
						content: [{ type: "text", text: lines.join("\n") }],
						details: {
							action: "events",
							sessionId,
							source,
							target,
							eventsCount: filteredEvents.length,
							totalBuffered: normalizedEvents.length,
							events: filteredEvents,
						},
					};
				}

				// Action is 'ingest': Convert to FactEvidence and write to EvidenceStore
				if (filteredEvents.length === 0) {
					return {
						content: [
							{
								type: "text",
								text: `No dynamic events found to ingest for session '${sessionId}'. Provide explicit events or an active session_id.`,
							},
						],
						details: {
							action: "ingest",
							sessionId,
							source,
							target,
							eventsCount: 0,
							totalBuffered: normalizedEvents.length,
							factIds: [],
							facts: [],
						},
					};
				}

				const createdFacts: FactEvidence[] = [];
				const createdFactIds: string[] = [];

				for (const ev of filteredEvents) {
					const factInput = dynamicEventToFactInput(ev, {
						target,
						classification: params.classification,
						tags: params.tags,
					});
					const factRecord = await evidenceStore.addFact(factInput);
					createdFacts.push(factRecord);
					createdFactIds.push(factRecord.id);
				}

				// Attach to workflow step if requested
				let stepUpdated = false;
				if (params.workflow_id) {
					const wf = await workflowStore.get(params.workflow_id);
					if (wf) {
						if (params.step_id) {
							const step = wf.steps.find(s => s.id === params.step_id);
							if (step) {
								step.evidence_ids = Array.from(new Set([...(step.evidence_ids ?? []), ...createdFactIds]));
								if (params.advance_workflow) {
									step.status = "completed";
								}
								step.updated_at = new Date().toISOString();
								stepUpdated = true;
							}
						}
						wf.runtime_session_ids = Array.from(new Set([...(wf.runtime_session_ids ?? []), sessionId]));
						wf.updated_at = new Date().toISOString();
						await workflowStore.save(wf);
					}
				}

				// If hypothesis_id and conclusion provided, verify immediately
				let conclusionRecord: ConclusionEvidence | undefined;
				let learnedRecords: ReverseKnowledgeRecord[] = [];
				if (params.hypothesis_id && params.conclusion) {
					const verifyInput = {
						hypothesisId: params.hypothesis_id,
						method: params.method || `Dynamic telemetry via ${source}`,
						command: params.command || `reverse_dynamic_evidence(session_id: "${sessionId}")`,
						result:
							params.result ||
							`Captured ${createdFacts.length} empirical dynamic events (${createdFactIds.join(", ")})`,
						conclusion: params.conclusion,
						reproducibility: params.reproducibility || "100%",
						status: "verified" as const,
						facts: createdFactIds,
					};
					conclusionRecord = await evidenceStore.verifyHypothesis(verifyInput);

					if (params.learn !== false) {
						const learnRes = await learnFromEvidenceAndWorkflows(
							evidenceStore,
							workflowStore,
							knowledgeStore,
							this.session,
							{ workflow_id: params.workflow_id },
						);
						learnedRecords = learnRes.created_records;
						for (const record of learnedRecords) {
							let changed = false;
							if (!record.metadata) {
								record.metadata = {};
								changed = true;
							}
							if (record.metadata.dynamic_verified !== true) {
								record.metadata.dynamic_verified = true;
								changed = true;
							}
							if (
								!record.metadata.dynamic_locators ||
								(record.metadata.dynamic_locators as string[]).length === 0
							) {
								if (createdFacts.length > 0) {
									record.metadata.dynamic_locators = createdFacts.map(f => f.locator);
									changed = true;
								}
							}
							if (
								!record.metadata.dynamic_sessions ||
								(record.metadata.dynamic_sessions as string[]).length === 0
							) {
								record.metadata.dynamic_sessions = [sessionId];
								changed = true;
							}
							if (changed) {
								await knowledgeStore.save(record);
							}
						}
					}
				}

				const lines: string[] = [
					`Ingested ${createdFacts.length} dynamic fact(s) into Evidence ledger from session '${sessionId}' (${source}):`,
				];
				for (const f of createdFacts) {
					lines.push(`  - [${f.id}] ${f.locator}: ${f.title}`);
				}
				if (stepUpdated) {
					lines.push(`\nAttached evidence facts to workflow '${params.workflow_id}', step '${params.step_id}'.`);
				}
				if (conclusionRecord) {
					lines.push(
						`\nVerified hypothesis '${params.hypothesis_id}' -> Conclusion [${conclusionRecord.id}]: ${conclusionRecord.conclusion}`,
					);
				}
				if (learnedRecords.length > 0) {
					lines.push(`Promoted ${learnedRecords.length} verified outcome(s) into reusable reverse knowledge:`);
					for (const kn of learnedRecords) {
						lines.push(`  - [${kn.id}] ${kn.title} (${kn.pattern || "verified"})`);
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "ingest",
						sessionId,
						source,
						target,
						eventsCount: createdFacts.length,
						totalBuffered: normalizedEvents.length,
						factIds: createdFactIds,
						facts: createdFacts,
						conclusionId: conclusionRecord?.id,
						conclusion: conclusionRecord,
						workflowId: params.workflow_id,
						stepId: params.step_id,
						stepUpdated,
						knowledgeCreatedCount: learnedRecords.length,
						knowledgeRecords: learnedRecords,
					},
				};
			}

			case "verify": {
				if (!params.hypothesis_id) {
					throw new ToolError("Action 'verify' requires 'hypothesis_id'.");
				}
				if (!params.conclusion) {
					throw new ToolError("Action 'verify' requires 'conclusion'.");
				}

				const method = params.method || `Dynamic observation via ${source}`;
				const command = params.command || `reverse_dynamic_evidence(session_id: "${sessionId}")`;
				const resultText = params.result || "Verified through dynamic session trace telemetry";

				const conclusionRecord = await evidenceStore.verifyHypothesis({
					hypothesisId: params.hypothesis_id,
					method,
					command,
					result: resultText,
					conclusion: params.conclusion,
					reproducibility: params.reproducibility || "100%",
					status: "verified",
				});

				let learnedRecords: ReverseKnowledgeRecord[] = [];
				if (params.learn !== false) {
					const learnRes = await learnFromEvidenceAndWorkflows(
						evidenceStore,
						workflowStore,
						knowledgeStore,
						this.session,
						{ workflow_id: params.workflow_id },
					);
					learnedRecords = learnRes.created_records;
					for (const record of learnedRecords) {
						let changed = false;
						if (!record.metadata) {
							record.metadata = {};
							changed = true;
						}
						if (record.metadata.dynamic_verified !== true) {
							record.metadata.dynamic_verified = true;
							changed = true;
						}
						if (
							!record.metadata.dynamic_sessions ||
							(record.metadata.dynamic_sessions as string[]).length === 0
						) {
							record.metadata.dynamic_sessions = [sessionId];
							changed = true;
						}
						if (changed) {
							await knowledgeStore.save(record);
						}
					}
				}

				let stepUpdated = false;
				if (params.workflow_id && params.step_id) {
					const wf = await workflowStore.get(params.workflow_id);
					if (wf) {
						const step = wf.steps.find(s => s.id === params.step_id);
						if (step) {
							step.evidence_ids = Array.from(new Set([...(step.evidence_ids ?? []), conclusionRecord.id]));
							if (params.advance_workflow) {
								step.status = "completed";
							}
							step.updated_at = new Date().toISOString();
							stepUpdated = true;
							await workflowStore.save(wf);
						}
					}
				}

				const lines: string[] = [
					`Verified hypothesis '${params.hypothesis_id}' -> Conclusion [${conclusionRecord.id}]:`,
					`  Conclusion: ${conclusionRecord.conclusion}`,
					`  Method: ${conclusionRecord.method}`,
					`  Result: ${conclusionRecord.result}`,
				];
				if (learnedRecords.length > 0) {
					lines.push(`\nPromoted ${learnedRecords.length} record(s) into reusable reverse knowledge:`);
					for (const kn of learnedRecords) {
						lines.push(`  - [${kn.id}] ${kn.title}`);
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "verify",
						sessionId,
						source,
						target,
						eventsCount: 0,
						conclusionId: conclusionRecord.id,
						conclusion: conclusionRecord,
						workflowId: params.workflow_id,
						stepId: params.step_id,
						stepUpdated,
						knowledgeCreatedCount: learnedRecords.length,
						knowledgeRecords: learnedRecords,
					},
				};
			}

			case "status": {
				const allEvidence = await evidenceStore.listRecords({ limit: 100 });
				const dynamicFacts = allEvidence.items.filter(
					r => r.kind === "fact" && isDynamicLocator((r as FactEvidence).locator),
				);
				const verifiedConclusions = allEvidence.items.filter(
					r => r.kind === "conclusion" && (r as ConclusionEvidence).status === "verified",
				);

				let workflowStatus: unknown;
				if (params.workflow_id) {
					const wf = await workflowStore.get(params.workflow_id);
					if (wf) {
						workflowStatus = {
							id: wf.id,
							target: wf.target,
							status: wf.status,
							steps: wf.steps.map(s => ({
								id: s.id,
								title: s.title,
								tool: s.tool,
								status: s.status,
								evidenceCount: s.evidence_ids?.length ?? 0,
							})),
						};
					}
				}

				const allKnowledge = await knowledgeStore.list();
				const dynamicKnowledge = allKnowledge.filter(
					k => k.metadata?.dynamic_verified === true || k.pattern?.startsWith("dynamic_"),
				);

				const lines: string[] = [
					`Dynamic Evidence & Closure Status:`,
					`  Dynamic Facts Recorded: ${dynamicFacts.length}`,
					`  Verified Conclusions: ${verifiedConclusions.length}`,
					`  Dynamic Knowledge Patterns: ${dynamicKnowledge.length}`,
				];
				if (workflowStatus) {
					lines.push(`  Workflow '${params.workflow_id}': active and linked.`);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "status",
						sessionId,
						source,
						target,
						eventsCount: dynamicFacts.length,
						statusSummary: {
							dynamicFactsCount: dynamicFacts.length,
							verifiedConclusionsCount: verifiedConclusions.length,
							dynamicKnowledgeCount: dynamicKnowledge.length,
							workflow: workflowStatus,
						},
					},
				};
			}

			default:
				throw new ToolError(`Unknown action: '${String(action)}'`);
		}
	}

	private async gatherRawEvents(
		params: ReverseDynamicEvidenceParams,
		source: DynamicEventSource,
		sessionId: string,
		runtimeSessionStore: ReverseRuntimeSessionStore,
	): Promise<unknown[]> {
		if (Array.isArray(params.events) && params.events.length > 0) {
			return params.events;
		}

		if (source === "dap") {
			const dapEvents = dapSessionManager.getEvents(sessionId, {
				limit: params.limit,
				sinceSeq: params.since_seq,
				kind: params.kind,
			});
			if (dapEvents.events.length > 0) {
				return dapEvents.events;
			}
		}

		// Try loading from runtimeSessionStore
		const sessionRecord = await runtimeSessionStore.get(sessionId).catch(() => null);
		if (sessionRecord?.metadata) {
			const metaEvents =
				sessionRecord.metadata.events ??
				sessionRecord.metadata.recent_events ??
				sessionRecord.metadata.capturedEvents;
			if (Array.isArray(metaEvents) && metaEvents.length > 0) {
				return metaEvents;
			}
		}

		return [];
	}

	private normalizeEventsList(
		rawEvents: unknown[],
		source: DynamicEventSource,
		sessionId: string,
		target?: string,
	): UniversalDynamicEvent[] {
		return rawEvents.map((raw, idx) => {
			const fallbackSeq = idx + 1;
			return normalizeDynamicEvent(raw, source, sessionId, {
				target,
				seq: fallbackSeq,
			});
		});
	}
}
