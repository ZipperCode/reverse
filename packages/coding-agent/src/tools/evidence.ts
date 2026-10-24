import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { getProjectDir, prompt } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import evidenceDescription from "../prompts/tools/evidence.md" with { type: "text" };
import {
	EvidenceStore,
	type EvidenceRecord,
	type EvidenceDriftStatus,
	type EvidenceListResult,
	type EvidenceAssuranceLevel,
	MAX_INLINE_CHARS,
	exportEvidenceToMarkdown,
	renderListText,
	renderRecordText,
	type FactEvidence,
	type HypothesisEvidence,
	type ConclusionEvidence,
} from "../evidence";

const evidenceSchema = type({
	action: type
		.enumerated("add", "list", "show", "verify", "export")
		.describe(
			"Evidence ledger action: add (record fact/hypothesis/unknown), list (filter/paginate entries), show (inspect entry with hash drift check), verify (verify hypothesis and record conclusion), export (generate reverse-lab evidence markdown)",
		),
	"kind?": type
		.enumerated("fact", "hypothesis", "unknown", "conclusion")
		.describe(
			"Kind of evidence: 'fact', 'hypothesis', or 'unknown' for add (conclusion is forbidden for add); filter for list",
		),
	"id?": type("string").describe("Evidence record ID to inspect (for show) or filter (for export)"),
	"hypothesisId?": type("string").describe("Target hypothesis ID to verify (required for verify)"),
	"title?": type("string").describe("Optional title or headline for the evidence record"),
	"target?": type("string").describe("Target file, binary, or package path relative to project root"),
	"sourceTool?": type("string").describe(
		"Source analysis tool that observed the fact (e.g. triage, r2_inspect, droidasc, frida_session, debug, read, strings; required for fact)",
	),
	"locator?": type("string").describe(
		"Exact location coordinate, e.g. symbol, RVA/offset 0x14001A240, session:<id>:seq:<seq>, line number (required for fact)",
	),
	"content?": type("string").describe(
		"Observed ground truth for fact, context for hypothesis, or question for unknown",
	),
	"excerpt?": type("string").describe(
		"Verbatim disassembly, decompiled snippet, or string from target (tracked for excerpt drift)",
	),
	"claim?": type("string").describe("Suspected mechanism, logic, or vulnerability claim (required for hypothesis)"),
	"verificationPlan?": type("string").describe(
		"Actionable, falsifiable verification method or experiment plan (required for hypothesis)",
	),
	"facts?": type("string[]").describe("Array of supporting fact record IDs for hypothesis"),
	"method?": type("string").describe(
		"Experimental method used for verification, e.g. Frida hook, replay, memory patch (required for verify)",
	),
	"command?": type("string").describe("Exact reproduction command or script invocation (required for verify)"),
	"result?": type("string").describe("Observed outcome or delta produced by the experiment (required for verify)"),
	"conclusion?": type("string").describe(
		"Confirmed deductive conclusion backed by verification result (required for verify)",
	),
	"reproducibility?": type("string").describe("Reproducibility rate or description, e.g. '100% (5/5 runs)'"),
	"status?": type
		.enumerated("verified", "refuted")
		.describe("Verification outcome status ('verified' or 'refuted', default 'verified')"),
	"classification?": type("string").describe("Taxonomy or weakness classification, e.g. CWE-602, CWE-798"),
	"tags?": type("string[]").describe("Categorization tags, e.g. ['auth', 'crypto', 'license']"),
	"subject?": type("string").describe("Target domain subject or component identity (e.g. login_flow, license_check)"),
	"assurance?": type
		.enumerated("static_candidate", "dynamic_call_observation", "algorithm_recovery", "independent_reproduction")
		.describe("Assurance tier of the observed evidence or conclusion"),
	"artifactSha256?": type("string").describe("Exact SHA-256 hash of the execution artifact"),
	"deviceAbi?": type("string").describe("Device architecture or ABI (e.g. arm64-v8a, x86_64)"),
	"os?": type("string").describe("Operating system and version of the execution environment"),
	"pid?": type("number").describe("Process ID of the observed execution"),
	"isExhaustive?": type("boolean").describe("Whether a negative search was exhaustive across the entire target space"),
	"searchTarget?": type("string").describe("Target scope or file for negative search"),
	"scopeBoundary?": type("string").describe("Boundary of negative search (e.g. single_file, process_memory, all_dex)"),
	"verifiedUnits?": type("number").describe(
		"Number of verified units or successful trials for quantitative reproducibility",
	),
	"totalRequiredUnits?": type("number").describe("Total required units or total runs denominator (>0)"),
	"unitDescription?": type("string").describe("Description of units for quantitative ratio (e.g. runs, tests, bytes)"),
	"invalidatesConclusions?": type("string[]").describe(
		"Array of prior conclusion IDs invalidated or refuted by this conclusion",
	),
	"claimScope?": type
		.enumerated("bounded", "universal")
		.describe(
			"Scope of claim for negative observations ('bounded' for local observation, 'universal' for total absence)",
		),
	"requireExhaustiveNegative?": type("boolean").describe(
		"Whether exhaustive negative search proof is strictly required",
	),
	"query?": type("string").describe("Keyword search string for filtering list"),
	"limit?": type("number").describe("Maximum items returned in list (default 20, max 100)"),
	"offset?": type("number").describe("Zero-based pagination offset for list (default 0)"),
	"to_artifact?": type("boolean").describe(
		"Force exporting markdown report to session artifact instead of inline text",
	),
});

export type EvidenceParams = typeof evidenceSchema.infer;

export interface EvidenceDetails {
	action: "add" | "list" | "show" | "verify" | "export";
	record?: EvidenceRecord;
	drift?: EvidenceDriftStatus;
	list?: EvidenceListResult;
	artifactId?: string;
	artifactPath?: string;
}

export class EvidenceTool implements AgentTool<typeof evidenceSchema, EvidenceDetails> {
	readonly name = "evidence";
	readonly label = "Evidence Ledger";
	readonly summary =
		"Empirical reverse-engineering evidence ledger: manage facts, hypotheses, verifications, and conclusions";
	readonly description: string;
	readonly parameters = evidenceSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "add" || action === "verify") {
				return "write";
			}
		}
		return "read";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(evidenceDescription);
	}

	async execute(
		_toolCallId: string,
		params: EvidenceParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<EvidenceDetails>> {
		throwIfAborted(signal);

		const repoRoot = this.session.cwd ?? getProjectDir();
		const store = new EvidenceStore({ repositoryRoot: repoRoot, signal });

		switch (params.action) {
			case "add": {
				if (params.kind === "conclusion") {
					throw new ToolError(
						"Directly adding a 'conclusion' is forbidden. Conclusions must be established through 'verify' against an existing hypothesis.",
					);
				}
				if (!params.kind) {
					throw new ToolError(
						"Parameter 'kind' is required for action 'add' (must be 'fact', 'hypothesis', or 'unknown')",
					);
				}

				let record: EvidenceRecord;
				if (params.kind === "fact") {
					if (!params.sourceTool) throw new ToolError("Field 'sourceTool' is required for fact evidence");
					if (!params.locator) throw new ToolError("Field 'locator' is required for fact evidence");
					const content = params.content ?? params.title;
					if (!content) throw new ToolError("Field 'content' is required for fact evidence");

					const executionBinding =
						params.artifactSha256 || params.deviceAbi || params.os || params.pid !== undefined
							? {
									...(params.artifactSha256 ? { artifactSha256: params.artifactSha256 } : {}),
									...(params.deviceAbi ? { deviceAbi: params.deviceAbi } : {}),
									...(params.os ? { os: params.os } : {}),
									...(params.pid !== undefined ? { pid: params.pid } : {}),
								}
							: undefined;

					const negativeScope =
						params.searchTarget || params.isExhaustive !== undefined
							? {
									searchTarget: params.searchTarget ?? params.target ?? "target",
									query: content,
									isExhaustive: Boolean(params.isExhaustive),
									...(params.scopeBoundary ? { scopeBoundary: params.scopeBoundary } : {}),
								}
							: undefined;

					const completionRatio =
						params.totalRequiredUnits !== undefined && params.verifiedUnits !== undefined
							? {
									verifiedUnits: params.verifiedUnits,
									totalRequiredUnits: params.totalRequiredUnits,
									...(params.unitDescription ? { unitDescription: params.unitDescription } : {}),
								}
							: undefined;

					record = await store.addFact({
						kind: "fact",
						sourceTool: params.sourceTool,
						locator: params.locator,
						content,
						title: params.title,
						target: params.target,
						excerpt: params.excerpt,
						classification: params.classification,
						tags: params.tags,
						subject: params.subject,
						assurance: params.assurance as EvidenceAssuranceLevel | undefined,
						executionBinding,
						negativeScope,
						completionRatio,
					});
				} else if (params.kind === "hypothesis") {
					if (!params.claim) throw new ToolError("Field 'claim' is required for hypothesis evidence");
					if (!params.verificationPlan)
						throw new ToolError("Field 'verificationPlan' is required for hypothesis evidence");

					const executionBinding =
						params.artifactSha256 || params.deviceAbi || params.os || params.pid !== undefined
							? {
									...(params.artifactSha256 ? { artifactSha256: params.artifactSha256 } : {}),
									...(params.deviceAbi ? { deviceAbi: params.deviceAbi } : {}),
									...(params.os ? { os: params.os } : {}),
									...(params.pid !== undefined ? { pid: params.pid } : {}),
								}
							: undefined;

					const negativeScope =
						params.searchTarget || params.isExhaustive !== undefined
							? {
									searchTarget: params.searchTarget ?? params.target ?? "target",
									query: params.claim,
									isExhaustive: Boolean(params.isExhaustive),
									...(params.scopeBoundary ? { scopeBoundary: params.scopeBoundary } : {}),
								}
							: undefined;

					record = await store.addHypothesis({
						kind: "hypothesis",
						claim: params.claim,
						verificationPlan: params.verificationPlan,
						title: params.title,
						target: params.target,
						facts: params.facts,
						content: params.content,
						classification: params.classification,
						tags: params.tags,
						subject: params.subject,
						assurance: params.assurance as EvidenceAssuranceLevel | undefined,
						executionBinding,
						negativeScope,
					});
				} else if (params.kind === "unknown") {
					const question = params.content ?? params.claim;
					if (!question)
						throw new ToolError(
							"Field 'content' (question/anomaly description) is required for unknown evidence",
						);

					record = await store.addUnknown({
						kind: "unknown",
						question,
						title: params.title,
						target: params.target,
						content: params.content,
						classification: params.classification,
						tags: params.tags,
						subject: params.subject,
					});
				} else {
					throw new ToolError(`Unsupported kind '${params.kind}' for action 'add'`);
				}

				const text = renderRecordText(record);
				return {
					content: [{ type: "text", text: `Recorded new evidence:\n${text}` }],
					details: { action: "add", record },
				};
			}

			case "verify": {
				if (!params.hypothesisId) {
					throw new ToolError("Field 'hypothesisId' is required for action 'verify'");
				}
				if (!params.method) throw new ToolError("Field 'method' is required for action 'verify'");
				if (!params.command) throw new ToolError("Field 'command' is required for action 'verify'");
				if (!params.result) throw new ToolError("Field 'result' is required for action 'verify'");
				if (!params.conclusion) throw new ToolError("Field 'conclusion' is required for action 'verify'");

				const executionBinding =
					params.artifactSha256 || params.deviceAbi || params.os || params.pid !== undefined
						? {
								...(params.artifactSha256 ? { artifactSha256: params.artifactSha256 } : {}),
								...(params.deviceAbi ? { deviceAbi: params.deviceAbi } : {}),
								...(params.os ? { os: params.os } : {}),
								...(params.pid !== undefined ? { pid: params.pid } : {}),
							}
						: undefined;

				const negativeScope =
					params.searchTarget || params.isExhaustive !== undefined
						? {
								searchTarget: params.searchTarget ?? params.target ?? "target",
								query: params.conclusion,
								isExhaustive: Boolean(params.isExhaustive),
								...(params.scopeBoundary ? { scopeBoundary: params.scopeBoundary } : {}),
							}
						: undefined;

				const completionRatio =
					params.totalRequiredUnits !== undefined && params.verifiedUnits !== undefined
						? {
								verifiedUnits: params.verifiedUnits,
								totalRequiredUnits: params.totalRequiredUnits,
								...(params.unitDescription ? { unitDescription: params.unitDescription } : {}),
							}
						: undefined;

				const conclusion = await store.verifyHypothesis({
					hypothesisId: params.hypothesisId,
					method: params.method,
					command: params.command,
					result: params.result,
					conclusion: params.conclusion,
					reproducibility: params.reproducibility,
					status: params.status as "verified" | "refuted" | undefined,
					title: params.title,
					facts: params.facts,
					target: params.target,
					targetSha256: params.artifactSha256,
					subject: params.subject,
					assurance: params.assurance as EvidenceAssuranceLevel | undefined,
					executionBinding,
					negativeScope,
					completionRatio,
					invalidatesConclusions: params.invalidatesConclusions,
					claimScope: params.claimScope,
					requireExhaustiveNegative: params.requireExhaustiveNegative,
				});

				const hyp = (await store.getRecord(conclusion.hypothesisId)) as HypothesisEvidence | null;
				let supportingFacts: FactEvidence[] | undefined;
				if (hyp?.facts && hyp.facts.length > 0) {
					const allFacts: FactEvidence[] = [];
					for (const fid of hyp.facts) {
						const f = (await store.getRecord(fid)) as FactEvidence | null;
						if (f) allFacts.push(f);
					}
					supportingFacts = allFacts;
				}

				const text = renderRecordText(conclusion, undefined, {
					hypothesis: hyp ?? undefined,
					facts: supportingFacts,
				});

				return {
					content: [{ type: "text", text: `Verified hypothesis and established conclusion:\n${text}` }],
					details: { action: "verify", record: conclusion },
				};
			}

			case "show": {
				if (!params.id) {
					throw new ToolError("Parameter 'id' is required for action 'show'");
				}

				const record = await store.getRecord(params.id);
				if (!record) {
					throw new ToolError(`Evidence record not found with id '${params.id}'`);
				}

				const drift = await store.checkDrift(record);

				let relatedHyp: HypothesisEvidence | undefined;
				let relatedConc: ConclusionEvidence[] | undefined;
				let supportingFacts: FactEvidence[] | undefined;

				if (record.kind === "conclusion") {
					const h = (await store.getRecord(record.hypothesisId)) as HypothesisEvidence | null;
					if (h) {
						relatedHyp = h;
						if (h.facts && h.facts.length > 0) {
							const factsList: FactEvidence[] = [];
							for (const fid of h.facts) {
								const f = (await store.getRecord(fid)) as FactEvidence | null;
								if (f) factsList.push(f);
							}
							supportingFacts = factsList;
						}
					}
				} else if (record.kind === "hypothesis") {
					if (record.verifiedBy) {
						const c = (await store.getRecord(record.verifiedBy)) as ConclusionEvidence | null;
						if (c) relatedConc = [c];
					}
					if (record.facts && record.facts.length > 0) {
						const factsList: FactEvidence[] = [];
						for (const fid of record.facts) {
							const f = (await store.getRecord(fid)) as FactEvidence | null;
							if (f) factsList.push(f);
						}
						supportingFacts = factsList;
					}
				}

				const validityMap = await store.resolveValidity();
				const recordValidity = validityMap.get(record.id);

				let text = renderRecordText(record, drift, {
					hypothesis: relatedHyp,
					conclusions: relatedConc,
					facts: supportingFacts,
				});

				if (recordValidity && (recordValidity.isRefuted || recordValidity.isStale)) {
					text += `\n\n--- VALIDITY WARNING ---\n⚠ Canonical Validity: ${recordValidity.effectiveStatus.toUpperCase()} (${recordValidity.reason ?? "superseded by subsequent ledger evidence"})`;
				}

				return {
					content: [{ type: "text", text }],
					details: { action: "show", record, drift },
				};
			}

			case "list": {
				const listResult = await store.listRecords({
					kind: params.kind,
					target: params.target,
					query: params.query,
					limit: params.limit,
					offset: params.offset,
				});

				const text = renderListText(listResult);
				return {
					content: [{ type: "text", text }],
					details: { action: "list", list: listResult },
				};
			}

			case "export": {
				const listResult = await store.listRecords({
					target: params.target,
					limit: 1000,
				});

				const md = exportEvidenceToMarkdown(listResult.items, {
					title: params.title,
					target: params.target,
					specificId: params.id,
				});

				const mustArtifact = params.to_artifact === true || md.length > MAX_INLINE_CHARS;
				if (mustArtifact && this.session.allocateOutputArtifact) {
					try {
						const alloc = await this.session.allocateOutputArtifact("evidence");
						if (alloc?.path && alloc.id) {
							await Bun.write(alloc.path, md);
							const preview = md.slice(0, 1200);
							const text = `Exported evidence artifact (${Buffer.byteLength(md)} bytes): artifact://${alloc.id}\n\nPreview:\n${preview}...\n(Read full artifact with 'read artifact://${alloc.id}')`;
							return {
								content: [{ type: "text", text }],
								details: { action: "export", artifactId: alloc.id, artifactPath: alloc.path },
							};
						}
					} catch {
						// Fall back to inline text on artifact allocation failure
					}
				}

				return {
					content: [{ type: "text", text: md }],
					details: { action: "export" },
				};
			}

			default:
				throw new ToolError(`Unknown action '${params.action}' for evidence tool`);
		}
	}
}
