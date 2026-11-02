import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import type { OutputMeta } from "@reverse/tui/tools/output-meta";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseDynamicEvidenceDescription from "../prompts/tools/reverse-dynamic-evidence.md" with { type: "text" };
import { EvidenceStore, type FactEvidence, type ConclusionEvidence } from "../evidence";
import { ReverseWorkflowStore, advanceWorkflow } from "../reverse-workflow";
import {
	ReverseKnowledgeStore,
	learnFromEvidenceAndWorkflows,
	type ReverseKnowledgeRecord,
} from "../reverse-knowledge";
import { ReverseRuntimeSessionStore, type RuntimeSessionRecord } from "../reverse-runtime-session";
import {
	type UniversalDynamicEvent,
	type DynamicEventSource,
	DYNAMIC_EVENT_SOURCES,
	isDynamicLocator,
	parseDynamicLocator,
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
	"hypothesis_id?": type("string").describe("Hypothesis ID in Evidence ledger to verify with ingested dynamic facts"),
	"fact_ids?": type("string[]").describe(
		"Non-empty array of ingested dynamic FactEvidence IDs from the target session supporting hypothesis verification",
	),
	"subject?": type("string").describe(
		"Subject identifier (e.g. function, endpoint, symbol, or protocol field) under investigation",
	),
	"conclusion?": type("string").describe("Confirmed deductive conclusion text to record when verifying a hypothesis"),
	"method?": type("string").describe(
		"Experimental dynamic method, e.g. 'Frida JNI hook', 'CDP network intercept', 'DAP breakpoint'",
	),
	"command?": type("string").describe("Exact script, CLI invocation, or expression that produced the dynamic outcome"),
	"result?": type("string").describe("Observed empirical result, output string, decrypted buffer, or register delta"),
	"reproducibility?": type("string").describe("Reproducibility metric or description, e.g. '100% (5/5 runs)'"),
	"learn?": type("boolean").describe(
		"Whether to automatically promote the newly verified conclusion into reusable reverse knowledge (default true)",
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

const SOURCE_BY_FACT_TOOL: Readonly<Record<string, DynamicEventSource>> = {
	frida_session: "frida",
	frida: "frida",
	browser_reverse_session: "browser",
	browser: "browser",
	debug: "dap",
	dap: "dap",
	unidbg: "unidbg",
};

function resolveSessionDynamicSource(sessionRecord: RuntimeSessionRecord): DynamicEventSource | undefined {
	if (sessionRecord.kind === "frida" || sessionRecord.kind === "browser" || sessionRecord.kind === "dap") {
		return sessionRecord.kind;
	}
	const metaSource = sessionRecord.metadata?.source;
	if (typeof metaSource === "string" && DYNAMIC_EVENT_SOURCES.includes(metaSource as DynamicEventSource)) {
		return metaSource as DynamicEventSource;
	}
	if (sessionRecord.id.includes("unidbg") || sessionRecord.recovery_hints?.restore_tool === "unidbg") {
		return "unidbg";
	}
	return undefined;
}

function resolveFactDynamicSource(fact: FactEvidence): DynamicEventSource | undefined {
	const mapped = SOURCE_BY_FACT_TOOL[fact.sourceTool];
	if (mapped) {
		return mapped;
	}
	if (fact.sourceTool === "reverse_dynamic_evidence") {
		if (Array.isArray(fact.tags)) {
			for (const tag of fact.tags) {
				if (DYNAMIC_EVENT_SOURCES.includes(tag as DynamicEventSource)) {
					return tag as DynamicEventSource;
				}
			}
		}
		return "custom";
	}
	return undefined;
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
		const rawSessionId = params.session_id?.trim();
		const sessionId = rawSessionId || "dynamic_session";
		const target = params.target?.trim();
		const limit = Math.min(Math.max(params.limit ?? 20, 1), 100);

		// Resolve stores
		const evidenceStore = new EvidenceStore({ repositoryRoot: cwd, stateRoot: this.stateRoot, signal });
		const workflowStore = new ReverseWorkflowStore({ repositoryRoot: cwd, stateRoot: this.stateRoot });
		const knowledgeStore = new ReverseKnowledgeStore({ repositoryRoot: cwd, stateRoot: this.stateRoot });
		const runtimeSessionStore = ReverseRuntimeSessionStore.forSession(cwd, this.stateRoot);
		const sessionRecord = rawSessionId ? await runtimeSessionStore.get(rawSessionId).catch(() => null) : null;
		const sessionSource = sessionRecord ? resolveSessionDynamicSource(sessionRecord) : undefined;
		const source: DynamicEventSource =
			(params.source as DynamicEventSource) ||
			sessionSource ||
			(sessionId.startsWith("runt_frida") || sessionId.includes("frida")
				? "frida"
				: sessionId.startsWith("browser") || sessionId.includes("browser")
					? "browser"
					: sessionId.startsWith("dap_") || sessionId.includes("dap")
						? "dap"
						: sessionId.includes("unidbg")
							? "unidbg"
							: "custom");

		switch (action) {
			case "events":
			case "ingest": {
				// 1. Gather raw events from input or session manager / runtime store
				const { rawEvents, trustedSessionEvent } = await this.gatherRawEvents(
					params,
					source,
					sessionId,
					sessionRecord,
				);

				// 2. Normalize events into UniversalDynamicEvent[]
				const normalizedEvents = this.normalizeEventsList(rawEvents, source, sessionId, target);
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
						subject: params.subject,
						trustedSessionEvent,
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
									await advanceWorkflow(
										wf,
										{
											step_id: params.step_id,
											status: "completed",
											evidence_ids: createdFactIds,
										},
										{ repositoryRoot: cwd, evidenceStore, knowledgeStore },
									);
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

				const lines: string[] = [
					`Ingested ${createdFacts.length} dynamic fact(s) into Evidence ledger from session '${sessionId}' (${source}):`,
				];
				for (const f of createdFacts) {
					lines.push(`  - [${f.id}] ${f.locator}: ${f.title}`);
				}
				if (stepUpdated) {
					lines.push(`\nAttached evidence facts to workflow '${params.workflow_id}', step '${params.step_id}'.`);
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
						workflowId: params.workflow_id,
						stepId: params.step_id,
						stepUpdated,
					},
				};
			}

			case "verify": {
				if (!rawSessionId) {
					throw new ToolError("Action 'verify' requires an explicit 'session_id'.");
				}
				const hypothesisId = params.hypothesis_id?.trim();
				if (!hypothesisId) {
					throw new ToolError("Action 'verify' requires 'hypothesis_id'.");
				}
				const factIds = Array.isArray(params.fact_ids)
					? Array.from(
							new Set(
								params.fact_ids
									.map(id => (typeof id === "string" ? id.trim() : ""))
									.filter((id): id is string => id.length > 0),
							),
						)
					: [];
				if (factIds.length === 0) {
					throw new ToolError("Action 'verify' requires a non-empty 'fact_ids' array.");
				}
				const conclusionText = params.conclusion?.trim();
				if (!conclusionText) {
					throw new ToolError("Action 'verify' requires 'conclusion'.");
				}
				const method = params.method?.trim();
				if (!method) {
					throw new ToolError("Action 'verify' requires 'method'.");
				}
				const command = params.command?.trim();
				if (!command) {
					throw new ToolError("Action 'verify' requires 'command'.");
				}
				const resultText = params.result?.trim();
				if (!resultText) {
					throw new ToolError("Action 'verify' requires 'result'.");
				}

				if (!sessionRecord) {
					throw new ToolError(`Runtime session '${rawSessionId}' is not registered in the runtime session store.`);
				}

				const explicitSource = params.source as DynamicEventSource | undefined;
				if (explicitSource && sessionSource && explicitSource !== sessionSource) {
					throw new ToolError(
						`Source mismatch: verify source '${explicitSource}' does not match session '${rawSessionId}' source '${sessionSource}'.`,
					);
				}
				const expectedSource = explicitSource ?? sessionSource;

				const hypRecord = await evidenceStore.getRecord(hypothesisId);
				if (!hypRecord) {
					throw new ToolError(`Hypothesis '${hypothesisId}' not found in evidence ledger.`);
				}
				if (hypRecord.kind !== "hypothesis") {
					throw new ToolError(
						`Target evidence '${hypothesisId}' is of kind '${hypRecord.kind}', not 'hypothesis'.`,
					);
				}

				const ledgerValidity = await evidenceStore.resolveValidity();
				const hypValidity = ledgerValidity.get(hypothesisId);
				if (hypValidity?.isRefuted) {
					throw new ToolError(`Cannot verify hypothesis '${hypothesisId}': hypothesis has been refuted.`);
				}
				if (hypValidity?.isStale) {
					throw new ToolError(`Cannot verify hypothesis '${hypothesisId}': hypothesis is stale or invalidated.`);
				}

				const hypTarget = hypRecord.target?.trim();
				if (target && (!hypTarget || target !== hypTarget)) {
					throw new ToolError(
						`Target mismatch: cannot rebind hypothesis target '${hypTarget ?? "none"}' to '${target}' during verify.`,
					);
				}

				const hypSubject = hypRecord.subject ?? hypRecord.context?.subject;
				const paramSubject = params.subject?.trim();
				if (hypSubject && paramSubject && hypSubject !== paramSubject) {
					throw new ToolError(
						`Subject mismatch: verify subject '${paramSubject}' does not match hypothesis subject '${hypSubject}'.`,
					);
				}
				const requiredSubject = hypSubject ?? paramSubject;
				const hypHash = hypRecord.targetSha256 ?? hypRecord.context?.executionBinding?.artifactSha256;

				let inferredFactSource: DynamicEventSource | undefined;
				let inferredFactTarget: string | undefined;
				let inferredFactHash: string | undefined;
				for (const fId of factIds) {
					const rec = await evidenceStore.getRecord(fId);
					if (!rec) {
						throw new ToolError(`Supporting evidence fact '${fId}' not found in ledger.`);
					}
					if (rec.kind !== "fact") {
						throw new ToolError(`Supporting evidence record '${fId}' is of kind '${rec.kind}', expected 'fact'.`);
					}
					const parsedLoc = parseDynamicLocator(rec.locator);
					if (!parsedLoc) {
						throw new ToolError(
							`Fact '${fId}' does not have a valid dynamic session locator ('${rec.locator}').`,
						);
					}
					if (parsedLoc.sessionId !== rawSessionId) {
						throw new ToolError(
							`Fact '${fId}' locator session '${parsedLoc.sessionId}' does not match verify session_id '${rawSessionId}'.`,
						);
					}
					const factSource = resolveFactDynamicSource(rec);
					if (!factSource) {
						throw new ToolError(
							`Fact '${fId}' (sourceTool: '${rec.sourceTool}') is not a dynamic session observation fact.`,
						);
					}
					if (expectedSource && factSource !== expectedSource) {
						throw new ToolError(
							`Fact '${fId}' source '${factSource}' does not match expected dynamic source '${expectedSource}'.`,
						);
					}
					if (inferredFactSource && factSource !== inferredFactSource) {
						throw new ToolError(
							`Fact '${fId}' source '${factSource}' conflicts with earlier fact source '${inferredFactSource}'.`,
						);
					}
					inferredFactSource = factSource;

					if (hypTarget) {
						if (!rec.target || rec.target !== hypTarget) {
							throw new ToolError(
								`Fact '${fId}' target '${rec.target ?? "none"}' does not match hypothesis target '${hypTarget}'.`,
							);
						}
					} else if (rec.target) {
						if (inferredFactTarget && rec.target !== inferredFactTarget) {
							throw new ToolError(
								`Fact '${fId}' target '${rec.target}' conflicts with earlier fact target '${inferredFactTarget}'.`,
							);
						}
						inferredFactTarget = rec.target;
					}

					const recHash = rec.targetSha256 ?? rec.context?.executionBinding?.artifactSha256;
					if (!hypHash && recHash) {
						if (inferredFactHash && recHash.toLowerCase() !== inferredFactHash.toLowerCase()) {
							throw new ToolError(
								`Fact '${fId}' target SHA-256 '${recHash}' conflicts with earlier fact SHA-256 '${inferredFactHash}'.`,
							);
						}
						inferredFactHash = recHash;
					}
				}

				const supportEval = await evidenceStore.evaluateSupport(factIds, {
					requiredKinds: ["fact"],
					minAssurance: "dynamic_call_observation",
					...(requiredSubject ? { requiredSubject } : {}),
					...(hypHash ? { requiredTargetSha256: hypHash } : {}),
					requireZeroExitStages: true,
				});
				if (!supportEval.valid) {
					throw new ToolError(
						`Cannot verify hypothesis '${hypothesisId}' with dynamic evidence: ${supportEval.reason ?? "supporting facts failed validation"}`,
					);
				}

				const conclusionRecord = await evidenceStore.verifyHypothesis({
					hypothesisId,
					method,
					command,
					result: resultText,
					conclusion: conclusionText,
					...(params.reproducibility?.trim() ? { reproducibility: params.reproducibility.trim() } : {}),
					status: "verified",
					facts: factIds,
					...(hypTarget ? { target: hypTarget } : {}),
					...(hypHash ? { targetSha256: hypHash } : {}),
					...(requiredSubject ? { subject: requiredSubject } : {}),
					assurance: "dynamic_call_observation",
				});

				let learnedRecords: ReverseKnowledgeRecord[] = [];
				if (params.learn !== false) {
					const learnRes = await learnFromEvidenceAndWorkflows(
						evidenceStore,
						workflowStore,
						knowledgeStore,
						this.session,
						{
							workflow_id: params.workflow_id,
							conclusion_ids: [conclusionRecord.id],
						},
					);
					learnedRecords = learnRes.created_records;
				}

				let stepUpdated = false;
				if (params.workflow_id && params.step_id) {
					const wf = await workflowStore.get(params.workflow_id);
					if (wf) {
						const step = wf.steps.find(s => s.id === params.step_id);
						if (step) {
							const mergedEvidenceIds = Array.from(
								new Set([...(step.evidence_ids ?? []), ...factIds, conclusionRecord.id]),
							);
							step.evidence_ids = mergedEvidenceIds;
							if (params.advance_workflow) {
								await advanceWorkflow(
									wf,
									{
										step_id: params.step_id,
										status: "completed",
										evidence_ids: mergedEvidenceIds,
									},
									{ repositoryRoot: cwd, evidenceStore, knowledgeStore },
								);
							}
							step.updated_at = new Date().toISOString();
							stepUpdated = true;
							wf.runtime_session_ids = Array.from(new Set([...(wf.runtime_session_ids ?? []), rawSessionId]));
							wf.updated_at = new Date().toISOString();
							await workflowStore.save(wf);
						}
					}
				}

				const resolvedSource = expectedSource ?? inferredFactSource ?? source;
				const lines: string[] = [
					`Verified hypothesis '${hypothesisId}' -> Conclusion [${conclusionRecord.id}]:`,
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
						sessionId: rawSessionId,
						source: resolvedSource,
						target: hypTarget,
						eventsCount: factIds.length,
						factIds,
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
		sessionRecord: RuntimeSessionRecord | null,
	): Promise<{ rawEvents: unknown[]; trustedSessionEvent: boolean }> {
		if (params.events !== undefined) {
			return {
				rawEvents: Array.isArray(params.events) ? params.events : [],
				trustedSessionEvent: false,
			};
		}

		if (source === "dap") {
			const dapEvents = dapSessionManager.getEvents(sessionId, {
				limit: params.limit,
				sinceSeq: params.since_seq,
				kind: params.kind,
			});
			if (dapEvents.events.length > 0) {
				return {
					rawEvents: dapEvents.events,
					trustedSessionEvent: true,
				};
			}
		}

		if (sessionRecord?.metadata) {
			const metaEvents =
				sessionRecord.metadata.events ??
				sessionRecord.metadata.recent_events ??
				sessionRecord.metadata.capturedEvents;
			if (Array.isArray(metaEvents) && metaEvents.length > 0) {
				return {
					rawEvents: metaEvents,
					trustedSessionEvent: true,
				};
			}
		}

		return { rawEvents: [], trustedSessionEvent: false };
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
