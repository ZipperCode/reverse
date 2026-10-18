import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createHash } from "node:crypto";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { getProjectDir } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import { resolveReadPath } from "./path-utils";
import type { ToolSession } from "./index";
import reverseKnowledgeDescription from "../prompts/tools/reverse-knowledge.md" with { type: "text" };
import { EvidenceStore } from "../evidence/store";
import { ReverseWorkflowStore } from "../reverse-workflow/store";
import { normalizeTargetFormat, type TargetFormat } from "../reverse-workflow/contracts";
import {
	ReverseKnowledgeStore,
	MnemopiKnowledgeBridge,
	validateVerifiedOnly,
	learnFromEvidenceAndWorkflows,
	applyKnowledge,
	createKnowledgeId,
	type ReverseKnowledgeRecord,
	type KnowledgeKind,
	type KnowledgeConfidence,
	type LearnKnowledgeResult,
	type ApplyKnowledgeResult,
	type KnowledgeAuditResult,
	type MergeKnowledgeResult,
	type ExpireKnowledgeResult,
	type DisableKnowledgeResult,
	DEFAULT_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_INLINE_CHARS,
} from "../reverse-knowledge";

const reverseKnowledgeSchema = type({
	action: type
		.enumerated("search", "retain", "learn", "apply", "audit", "merge", "expire", "disable")
		.describe(
			"Reverse knowledge action: search (bounded query across reverse findings and patterns), retain (persist verified conclusion or recovery pattern), learn (extract verified knowledge from evidence ledger and workflow recovery audits), apply (retrieve actionable recommendations for target, tool, or error), audit (deterministic duplicate detection, stale evidence reporting, expiration review), merge (consolidate duplicate knowledge into target record without destructive deletion), expire (retire obsolete knowledge records), disable (deactivate knowledge records from active retrieval)",
		),
	"query?": type("string").describe("Keyword query to search across stored knowledge titles, summaries, and guidance"),
	"format?": type("string").describe(
		"Target binary/package format (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite)",
	),
	"target?": type("string").describe("Path to target file or sample relative to workspace"),
	"path?": type("string").describe("Alias for target"),
	"target_hash?": type("string").describe("SHA256 hash of target binary for exact knowledge matching"),
	"tool?": type("string").describe("Specific reverse engineering tool name (e.g. 'r2_inspect', 'ghidra_inspect')"),
	"kind?": type
		.enumerated("verified_conclusion", "recovery_pattern")
		.describe("Category of knowledge: verified analytical conclusion or recovery pattern"),
	"title?": type("string").describe("Title or descriptive headline for retained knowledge"),
	"summary?": type("string").describe("Summary of verified findings, analytical methodology, or recovery outcome"),
	"pattern?": type("string").describe("Applicability pattern or error condition signature"),
	"actionable_guidance?": type("string").describe(
		"Actionable instructions, suggested tool parameters, or analysis recommendations",
	),
	"params?": type("string").describe("Suggested parameters or config adjustments as JSON or description"),
	"confidence?": type
		.enumerated("high", "medium", "low")
		.describe("Confidence level for retained knowledge (verified conclusions require high or medium)"),
	"source_evidence_ids?": type("string[]").describe(
		"Array of evidence ledger IDs (ev_conc_..., ev_hyp_...) backing this verified finding",
	),
	"source_workflow_id?": type("string").describe("Originating reverse engineering workflow ID"),
	"source_step_id?": type("string").describe("Originating workflow step ID"),
	"workflow_id?": type("string").describe("Optional workflow ID to restrict 'learn' action"),
	"error?": type("string").describe("Error message or failure category to match against recovery patterns in 'apply'"),
	"goal?": type("string").describe("Analytical goal or objective for 'search' or 'apply'"),
	"target_id?": type("string").describe("Target knowledge record ID to absorb merged records in 'merge'"),
	"source_ids?": type("string[]").describe("Array of source knowledge record IDs to be merged into target_id"),
	"knowledge_id?": type("string").describe("Knowledge record ID for expire, disable, or audit lookup"),
	"knowledge_ids?": type("string[]").describe("Array of knowledge record IDs for bulk expire, disable, or merge"),
	"reason?": type("string").describe("Governance reason for expiring, disabling, or merging records"),
	"mark_stale?": type("boolean").describe(
		"Whether 'audit' action should persist 'stale: true' on records with missing or refuted source evidence",
	),
	"include_inactive?": type("boolean").describe(
		"Whether 'search' or 'audit' should include inactive/expired/disabled/merged records",
	),
	"limit?": type("number.integer >= 1").describe("Maximum results to return (default 5, max 20)"),
});

export type ReverseKnowledgeParams = typeof reverseKnowledgeSchema.infer;

export interface ReverseKnowledgeDetails {
	action: "search" | "retain" | "learn" | "apply" | "audit" | "merge" | "expire" | "disable";
	records?: ReverseKnowledgeRecord[];
	record?: ReverseKnowledgeRecord;
	learn_result?: LearnKnowledgeResult;
	apply_result?: ApplyKnowledgeResult;
	audit_result?: KnowledgeAuditResult;
	merge_result?: MergeKnowledgeResult;
	expire_result?: ExpireKnowledgeResult;
	disable_result?: DisableKnowledgeResult;
	total_hits?: number;
}

export class ReverseKnowledgeTool implements AgentTool<typeof reverseKnowledgeSchema, ReverseKnowledgeDetails> {
	readonly name = "reverse_knowledge";
	readonly label = "Reverse Engineering Knowledge";
	readonly summary =
		"Bounded reverse knowledge repository and Mnemopi bridge: search, retain verified conclusions, learn recovery patterns, and apply findings without promoting unverified hypotheses.";
	readonly description = reverseKnowledgeDescription;
	readonly parameters = reverseKnowledgeSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (
				action === "retain" ||
				action === "learn" ||
				action === "merge" ||
				action === "expire" ||
				action === "disable"
			) {
				return "modify";
			}
		}
		return "read";
	};

	constructor(private readonly session: ToolSession) {}

	async execute(_id: string, params: ReverseKnowledgeParams, signal?: AbortSignal): Promise<AgentToolResult<ReverseKnowledgeDetails>> {
		throwIfAborted(signal);

		const repoRoot = this.session.cwd ?? getProjectDir();
		const knowledgeStore = new ReverseKnowledgeStore({ repositoryRoot: repoRoot });
		const evidenceStore = new EvidenceStore({ repositoryRoot: repoRoot, signal });
		const workflowStore = new ReverseWorkflowStore({ repositoryRoot: repoRoot });

		switch (params.action) {
			case "search": {
				const limit = Math.min(
					Math.max(params.limit ?? DEFAULT_KNOWLEDGE_SEARCH_LIMIT, 1),
					MAX_KNOWLEDGE_SEARCH_LIMIT,
				);

				const filterFormat = normalizeTargetFormat(params.format);

				// Compute target hash if target path was supplied
				let targetHash = params.target_hash;
				const rawTarget = params.target ?? params.path;
				if (rawTarget && !targetHash) {
					try {
						const resolved = resolveReadPath(rawTarget, this.session.cwd);
						const stat = await fs.stat(resolved);
						if (stat.isFile()) {
							const fh = await fs.open(resolved, "r");
							try {
								const readLen = Math.min(stat.size, 65536);
								const buf = Buffer.alloc(readLen);
								await fh.read(buf, 0, readLen, 0);
								targetHash = createHash("sha256").update(buf).digest("hex");
							} finally {
								await fh.close();
							}
						}
					} catch {
						// Non-existent target, continue without hash
					}
				}

				const records = await knowledgeStore.search({
					query: params.query ?? params.goal,
					format: filterFormat,
					target_hash: targetHash,
					tool: params.tool,
					kind: params.kind,
					confidence: params.confidence,
					include_inactive: params.include_inactive,
					limit,
				});

				if (records.length === 0) {
					const text = [
						"No matching reverse knowledge records found.",
						"",
						"Suggestions:",
						"- Use 'learn' action to automatically extract verified findings from the evidence ledger and successful recovery audits.",
						"- Use 'retain' action to save verified analytical conclusions from recent tool runs.",
					].join("\n");

					return {
						content: [{ type: "text", text }],
						details: {
							action: "search",
							records: [],
							total_hits: 0,
						},
					};
				}

				const items = records.map(r => {
					const lines = [
						`### [${r.id}] ${r.title} (${r.kind})`,
						`- **Format**: ${r.target_format} | **Confidence**: ${r.confidence.toUpperCase()}${r.tool ? ` | **Tool**: \`${r.tool}\`` : ""}`,
						r.target_hash ? `- **Target Hash**: \`${r.target_hash.slice(0, 16)}...\`` : undefined,
						r.source_evidence_ids && r.source_evidence_ids.length > 0
							? `- **Evidence Links**: ${r.source_evidence_ids.map(id => `\`${id}\``).join(", ")}`
							: undefined,
						`- **Summary**: ${r.summary}`,
						r.actionable_guidance ? `- **Actionable Guidance**: ${r.actionable_guidance}` : undefined,
					].filter(Boolean);
					return lines.join("\n");
				});

				const text = [
					`Found ${records.length} reverse engineering knowledge ${records.length === 1 ? "entry" : "entries"}:`,
					"",
					items.join("\n\n"),
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "search",
						records,
						total_hits: records.length,
					},
				};
			}

			case "retain": {
				if (!params.title || params.title.trim().length === 0) {
					throw new ToolError("Parameter 'title' is required for 'retain' action.");
				}
				if (!params.summary || params.summary.trim().length === 0) {
					throw new ToolError("Parameter 'summary' is required for 'retain' action.");
				}
				if (!params.kind) {
					throw new ToolError("Parameter 'kind' ('verified_conclusion' or 'recovery_pattern') is required for 'retain' action.");
				}

				const targetFormat: TargetFormat = normalizeTargetFormat(params.format) ?? "unknown";

				let targetHash = params.target_hash;
				const rawTarget = params.target ?? params.path;
				if (rawTarget && !targetHash) {
					try {
						const resolved = resolveReadPath(rawTarget, this.session.cwd);
						const stat = await fs.stat(resolved);
						if (stat.isFile()) {
							const fh = await fs.open(resolved, "r");
							try {
								const readLen = Math.min(stat.size, 65536);
								const buf = Buffer.alloc(readLen);
								await fh.read(buf, 0, readLen, 0);
								targetHash = createHash("sha256").update(buf).digest("hex");
							} finally {
								await fh.close();
							}
						}
					} catch {
						// Continue without target hash
					}
				}

				const confidence: KnowledgeConfidence = params.confidence ?? "high";

				// Strictly validate that unverified hypotheses and unknowns are rejected
				const validation = await validateVerifiedOnly(
					{
						title: params.title,
						kind: params.kind,
						target_format: targetFormat,
						target_hash: targetHash,
						tool: params.tool,
						confidence,
						source_evidence_ids: params.source_evidence_ids,
						source_workflow_id: params.source_workflow_id,
						source_step_id: params.source_step_id,
						summary: params.summary,
						pattern: params.pattern,
						actionable_guidance: params.actionable_guidance,
						params: params.params,
					},
					evidenceStore,
				);

				const metadata: Record<string, unknown> = {
					...(params.params && typeof params.params === "object" ? (params.params as Record<string, unknown>) : {}),
				};
				if (validation?.missingEvidenceIds && validation.missingEvidenceIds.length > 0) {
					metadata.missing_evidence_ids = validation.missingEvidenceIds;
					metadata.unverified_evidence = true;
				}
				if (validation?.refutedEvidenceIds && validation.refutedEvidenceIds.length > 0) {
					metadata.refuted_evidence_ids = validation.refutedEvidenceIds;
					metadata.stale_evidence = true;
				}

				const now = new Date().toISOString();
				const record: ReverseKnowledgeRecord = {
					id: createKnowledgeId(),
					kind: params.kind,
					title: params.title.trim(),
					target_format: targetFormat,
					target_hash: targetHash,
					tool: params.tool,
					confidence,
					source_evidence_ids: params.source_evidence_ids,
					source_workflow_id: params.source_workflow_id,
					source_step_id: params.source_step_id,
					summary: params.summary.trim(),
					pattern: params.pattern,
					actionable_guidance: params.actionable_guidance,
					params: params.params,
					metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
					created_at: now,
					updated_at: now,
				};

				await knowledgeStore.save(record);

				// Bridge to Mnemopi if session has Mnemopi backend active
				await MnemopiKnowledgeBridge.retain(record, this.session);

				const text = [
					`Retained verified reverse knowledge \`${record.id}\`:`,
					`- **Title**: ${record.title}`,
					`- **Kind**: ${record.kind}`,
					`- **Format**: ${record.target_format} | **Confidence**: ${record.confidence.toUpperCase()}`,
					record.tool ? `- **Tool**: \`${record.tool}\`` : undefined,
					record.source_evidence_ids && record.source_evidence_ids.length > 0
						? `- **Evidence Links**: ${record.source_evidence_ids.map(id => `\`${id}\``).join(", ")}`
						: undefined,
					`- **Summary**: ${record.summary}`,
					record.actionable_guidance ? `- **Actionable Guidance**: ${record.actionable_guidance}` : undefined,
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "retain",
						record,
					},
				};
			}

			case "learn": {
				const learnResult = await learnFromEvidenceAndWorkflows(
					evidenceStore,
					workflowStore,
					knowledgeStore,
					this.session,
					{
						workflow_id: params.workflow_id,
						target_hash: params.target_hash,
						format: params.format,
					},
				);

				const createdList = learnResult.created_records.map(
					r => `  - [\`${r.id}\`] ${r.title} (${r.kind}, format: **${r.target_format}**)`,
				);

				const text = [
					`Learned ${learnResult.learned_conclusions + learnResult.learned_recoveries} reusable knowledge entries:`,
					`- **Verified conclusions learned**: ${learnResult.learned_conclusions}`,
					`- **Successful recovery patterns learned**: ${learnResult.learned_recoveries}`,
					`- **Unverified records skipped**: ${learnResult.skipped_unverified} (unverified hypotheses and questions were preserved without premature promotion)`,
					"",
					createdList.length > 0 ? `Created Entries:\n${createdList.join("\n")}` : "No new verified entries to learn.",
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "learn",
						learn_result: learnResult,
					},
				};
			}

			case "apply": {
				const limit = Math.min(
					Math.max(params.limit ?? DEFAULT_KNOWLEDGE_SEARCH_LIMIT, 1),
					MAX_KNOWLEDGE_SEARCH_LIMIT,
				);

				let targetHash = params.target_hash;
				const rawTarget = params.target ?? params.path;
				if (rawTarget && !targetHash) {
					try {
						const resolved = resolveReadPath(rawTarget, this.session.cwd);
						const stat = await fs.stat(resolved);
						if (stat.isFile()) {
							const fh = await fs.open(resolved, "r");
							try {
								const readLen = Math.min(stat.size, 65536);
								const buf = Buffer.alloc(readLen);
								await fh.read(buf, 0, readLen, 0);
								targetHash = createHash("sha256").update(buf).digest("hex");
							} finally {
								await fh.close();
							}
						}
					} catch {
						// Continue without target hash
					}
				}

				const applyResult = await applyKnowledge(knowledgeStore, {
					target: rawTarget,
					format: params.format,
					target_hash: targetHash,
					tool: params.tool,
					goal: params.goal,
					error: params.error,
					limit,
				});

				if (applyResult.recommendations.length === 0) {
					const text = [
						"No matching reverse knowledge or recovery patterns found for the given target/context.",
						"",
						"Run analysis tools and verify conclusions in the evidence ledger (`evidence action: 'verify'`), then call `reverse_knowledge action: 'learn'` to build reusable patterns.",
					].join("\n");

					return {
						content: [{ type: "text", text }],
						details: {
							action: "apply",
							apply_result: applyResult,
						},
					};
				}

				const recItems = applyResult.recommendations.map(rec => {
					const lines = [
						`### [${rec.knowledge_id}] ${rec.title} (${rec.kind})`,
						`- **Confidence**: ${rec.confidence.toUpperCase()}${rec.tool ? ` | **Tool**: \`${rec.tool}\`` : ""} | **Format**: ${rec.format}`,
						`- **Guidance**: ${rec.guidance}`,
						rec.suggested_params
							? `- **Suggested Parameters**: \`${typeof rec.suggested_params === "string" ? rec.suggested_params : JSON.stringify(rec.suggested_params)}\``
							: undefined,
						rec.source_evidence_ids && rec.source_evidence_ids.length > 0
							? `- **Evidence Source**: ${rec.source_evidence_ids.map(id => `\`${id}\``).join(", ")}`
							: undefined,
					].filter(Boolean);
					return lines.join("\n");
				});

				const text = [
					`Applied ${applyResult.recommendations.length} relevant knowledge ${applyResult.recommendations.length === 1 ? "pattern" : "patterns"}:`,
					"",
					recItems.join("\n\n"),
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "apply",
						apply_result: applyResult,
					},
				};
			}
			case "audit": {
				const auditResult = await knowledgeStore.audit(
					{
						limit: params.limit,
						mark_stale: params.mark_stale,
						include_inactive: params.include_inactive,
					},
					evidenceStore,
				);

				const lines: string[] = [
					`## Reverse Knowledge Governance Audit`,
					`- **Total Records Audited**: ${auditResult.total_records}`,
					`- **Active Records**: ${auditResult.active_records}`,
					`- **Duplicate Records**: ${auditResult.duplicate_count} (across ${auditResult.duplicate_groups.length} groups)`,
					`- **Stale Records**: ${auditResult.stale_records}`,
					`- **Expired Records**: ${auditResult.expired_records}`,
					`- **Disabled Records**: ${auditResult.disabled_records}`,
					`- **Merged Records**: ${auditResult.merged_records}`,
					"",
				];

				if (auditResult.duplicate_groups.length > 0) {
					lines.push("### Duplicate Groups:");
					for (const group of auditResult.duplicate_groups) {
						lines.push(
							`- **Fingerprint**: \`${group.fingerprint}\` | Primary: \`${group.primary_id}\` | Duplicates (${group.duplicate_ids.length}): ${group.duplicate_ids.map(id => `\`${id}\``).join(", ")}`,
						);
					}
					lines.push("");
				}

				if (auditResult.findings.length > 0) {
					lines.push("### Governance Findings:");
					for (const finding of auditResult.findings.slice(0, 10)) {
						lines.push(`- [${finding.type.toUpperCase()}] \`${finding.record_id}\` (${finding.title}): ${finding.reason}`);
					}
					if (auditResult.findings.length > 10) {
						lines.push(`  ... and ${auditResult.findings.length - 10} more finding(s)`);
					}
					lines.push("");
				}

				if (auditResult.recommendations.length > 0) {
					lines.push("### Recommendations:");
					for (const rec of auditResult.recommendations) {
						lines.push(`- ${rec}`);
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n").trim() }],
					details: {
						action: "audit",
						audit_result: auditResult,
					},
				};
			}

			case "merge": {
				const targetId = params.target_id ?? params.knowledge_id ?? params.id;
				if (!targetId) {
					throw new ToolError("target_id is required for 'merge' action.");
				}
				const sourceIds = params.source_ids ?? params.knowledge_ids;
				if (!sourceIds || sourceIds.length === 0) {
					throw new ToolError("source_ids is required for 'merge' action.");
				}

				const mergeResult = await knowledgeStore.merge({
					target_id: targetId,
					source_ids: sourceIds,
					reason: params.reason,
				});

				const text = [
					`Consolidated ${mergeResult.merged_ids.length} duplicate knowledge record(s) into primary record \`${mergeResult.target_id}\`:`,
					`- **Primary Title**: ${mergeResult.target_record.title}`,
					`- **Confidence**: ${mergeResult.target_record.confidence.toUpperCase()}`,
					`- **Total Combined Evidence Links**: ${mergeResult.target_record.source_evidence_ids?.length ?? 0}`,
					`- **Total Usage Count**: ${mergeResult.target_record.usage_count ?? 0}`,
					`- **Preserved Merged Records**: ${mergeResult.merged_ids.map(id => `\`${id}\``).join(", ")} (marked with status 'merged', not deleted)`,
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "merge",
						merge_result: mergeResult,
					},
				};
			}

			case "expire": {
				const ids = params.knowledge_ids ?? (params.knowledge_id ? [params.knowledge_id] : (params.id ? [params.id] : []));
				if (ids.length === 0) {
					throw new ToolError("knowledge_id or knowledge_ids is required for 'expire' action.");
				}

				const expireResult = await knowledgeStore.expire({
					knowledge_ids: ids,
					reason: params.reason,
				});

				const text = [
					`Expired ${expireResult.expired_ids.length} knowledge record(s):`,
					...expireResult.records.map(r => `  - [\`${r.id}\`] ${r.title} (Status: expired, Reason: ${r.status_reason})`),
					"Records are preserved for auditability and excluded from active tool retrieval.",
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "expire",
						expire_result: expireResult,
					},
				};
			}

			case "disable": {
				const ids = params.knowledge_ids ?? (params.knowledge_id ? [params.knowledge_id] : (params.id ? [params.id] : []));
				if (ids.length === 0) {
					throw new ToolError("knowledge_id or knowledge_ids is required for 'disable' action.");
				}

				const disableResult = await knowledgeStore.disable({
					knowledge_ids: ids,
					reason: params.reason,
				});

				const text = [
					`Disabled ${disableResult.disabled_ids.length} knowledge record(s):`,
					...disableResult.records.map(r => `  - [\`${r.id}\`] ${r.title} (Status: disabled, Reason: ${r.status_reason})`),
					"Records are deactivated from active recommendations.",
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "disable",
						disable_result: disableResult,
					},
				};
			}
		}
	}
}
