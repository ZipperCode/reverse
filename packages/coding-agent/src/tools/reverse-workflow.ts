import { createReadStream } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { createHash } from "node:crypto";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { prompt, getProjectDir } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import { resolveReadPath } from "./path-utils";
import type { ToolSession } from "./index";
import reverseWorkflowDescription from "../prompts/tools/reverse-workflow.md" with { type: "text" };
import { EvidenceStore } from "../evidence/store";
import { ReverseKnowledgeStore } from "../reverse-knowledge/store";
import { exportWorkflowToWorkspace, hashFile, type ReverseWorkspaceManifest } from "../reverse-workspace";
import {
	ReverseWorkflowStore,
	sniffTargetFormat,
	generateDeterministicPlan,
	exportWorkflowToMarkdown,
	exportWorkflowToJson,
	createWorkflowId,
	computeWorkflowMetrics,
	validateEvidenceIdFormat,
	validateKnowledgeIdFormat,
	classifyFailure,
	generateRecoveryPlan,
	verifyInstalledTool,
	type VerifyToolResult,
	advanceWorkflow,
	type ReverseWorkflowRecord,
	type WorkflowStepRecord,
	type WorkflowMetrics,
	type TargetFormat,
	type StepRetryEntry,
	type RecoveryAuditEntry,
	type RecoveryPlan,
	type ProgressionAuditEntry,
	type ProgressionStatus,
	type StepResumeMetadata,
	MAX_INLINE_CHARS,
	DEFAULT_MAX_ATTEMPTS,
	HARD_MAX_ATTEMPTS,
	type BuildArtifactRecord,
	type BuildVerificationResult,
	type PatchRetirementAuditEntry,
	type RegisterDerivativeOptions,
	type AcceptanceCriterion,
	type TargetDeviceConstraints,
	type WorkflowDependencyRecord,
	getWorkflowAcceptanceCriteria,
	setWorkflowAcceptanceCriteria,
	evaluateAcceptanceSatisfaction,
	validateDeploymentConstraints,
	updateAcceptanceCriterion,
	cascadeEvidenceRefutation,
	normalizeAcceptanceCriterion,
	normalizeTargetDeviceConstraints,
	normalizeWorkflowDependencies,
} from "../reverse-workflow";
import { evaluateEvidenceSupport } from "../evidence/validity";
import type { EvidenceRecord } from "../evidence/contracts";
import type { OutputMeta } from "@reverse/tui/tools/output-meta";
const reverseWorkflowSchema = type({
	action: type
		.enumerated(
			"create",
			"plan",
			"status",
			"record",
			"retry",
			"recover",
			"retry_plan",
			"export",
			"destroy",
			"advance",
			"auto_advance",
			"register_derivative",
			"verify_lineage",
			"retire_patch",
			"waive_acceptance",
			"approve_dependency",
		)
		.describe(
			"Workflow orchestrator action: create (initialize target-routed workflow plan), plan (preview/generate deterministic plan), status (inspect workflow and step progress), record (record step execution, outputs, and evidence ledger links), retry (retry failed step with bounded attempts and caller params), recover (diagnose failure, attribute category, propose deterministic fallback/corrected params, record audit trail, and transition to pending), retry_plan (preview failure attribution and recovery plan without mutating state), export (produce bounded Markdown/JSON report), destroy (delete workflow), advance (progress or record next allowlisted low-risk static step), auto_advance (progress next allowlisted read/static triage step, attaching verified prior knowledge and halting on dynamic/high-risk tools or ambiguous targets)",
		),
	"workflow_id?": type("string").describe("Workflow identifier (e.g. 'wf_rw_...')"),
	"id?": type("string").describe("Alias for workflow_id"),
	"target?": type("string").describe("Path to target binary, package, capture, or script relative to project"),
	"path?": type("string").describe("Alias for target"),
	"format?": type("string").describe("Explicit target format override (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite)"),
	"goal?": type("string").describe("Analytical goal or objective for the reverse engineering workflow"),
	"step_id?": type("string").describe("Target step identifier within the workflow (e.g. 'pe_step_1')"),
	"status?": type
		.enumerated("completed", "failed", "running", "skipped")
		.describe("Execution status for the step in 'record' action"),
	"outputs?": type("string").describe("Output summary, extracted strings, or execution results for 'record'"),
	"artifact_refs?": type("string[]").describe(
		"Optional list of artifact IDs or generated file references produced by the step",
	),
	"evidence_ids?": type("string[]").describe(
		"Array of evidence ledger IDs (ev_fact_..., ev_hyp_..., ev_conc_..., ev_unk_...) to link to this step",
	),
	"knowledge_refs?": type("string[]").describe(
		"Optional array of reverse knowledge IDs (kn_rev_...) to link to this step or workflow",
	),
	"runtime_session_id?": type("string").describe(
		"Optional reverse runtime session identifier (e.g. 'runt_frida_...') to associate with this step or workflow",
	),
	"runtime_session_ids?": type("string[]").describe(
		"Optional array of reverse runtime session identifiers to associate with this step or workflow",
	),
	"error?": type("string").describe("Failure reason or error message when marking step as 'failed'"),
	"failure_reason?": type("string").describe("Alias for error"),
	"next_params?": type("string").describe(
		"Caller-provided parameters or adjusted arguments for the upcoming retry attempt (JSON or description)",
	),
	"result?": type("string").describe(
		"Caller-provided diagnostic result, failure analysis, or hypothesis verification outcome for retry",
	),
	"caller_result?": type("string").describe("Alias for result"),
	"fallback_tool?": type("string").describe(
		"Optional fallback tool to replace the failed step's tool for the next retry attempt",
	),
	"max_attempts?": type("number.integer >= 1").describe(
		"Maximum retry attempts allowed for step or workflow (default 3, max 10)",
	),
	"capability_id?": type("string").describe(
		"Canonical capability ID (e.g. 'apk_unpacking', 'dex_patching', 'apk_artifact_generation', 'android_native_emulation', 'browser_debugger', 'websocket_capture', 'js_deobfuscation', 'traffic_interception', 'native_debugger')",
	),
	"installed_tool?": type("string").describe(
		"Logical identifier of newly installed external tool (e.g. 'jadx', 'apktool', 'unidbg', 'radare2') for install-after resumption",
	),
	"setup_command?": type("string").describe(
		"Trusted setup command executed to install the tool (e.g. 'reverse setup reverse apktool')",
	),
	"verified?": type("boolean").describe(
		"Whether tool availability was verified post-install before resuming (defaults to true)",
	),
	"strategy?": type
		.enumerated("resume_original", "fallback")
		.describe(
			"Resumption strategy: 'resume_original' to re-dispatch the original planned tool, or 'fallback' to engage alternative",
		),
	"resume_strategy?": type.enumerated("resume_original", "fallback").describe("Alias for strategy"),
	"resumed_at?": type("string").describe(
		"ISO timestamp when the step was resumed following installation (defaults to current time)",
	),
	"format_type?": type.enumerated("markdown", "json").describe("Export report format: 'markdown' (default) or 'json'"),
	"to_artifact?": type("boolean").describe("Export full report to session artifact instead of inline response"),
	"to_workspace?": type("boolean").describe(
		"Export standardized reverse engineering workspace to local .reverse/ directory (target info, workflow, evidence, findings, and safe artifact references)",
	),
	"workspace_path?": type("string").describe(
		"Custom directory path for workspace export (defaults to '.reverse' in project root)",
	),
	"clean_workspace?": type("boolean").describe("Clean previous dumps/scripts before exporting new workspace run"),
	"max_steps?": type("number.integer >= 1").describe("Maximum steps to evaluate in auto_advance (default 1, max 5)"),
	"propose_only?": type("boolean").describe("Only propose the next low-risk static step without mutating state"),
	"limit?": type("number.integer >= 1").describe("Maximum items to list in 'status' action (default 20)"),
	"build_id?": type("string").describe("Derivative build identifier (e.g. 'bld_mod1' or 'mod1')"),
	"derivative_path?": type("string").describe(
		"Path to derivative artifact file (alias for target in register_derivative)",
	),
	"output_sha256?": type("string").describe("Expected SHA-256 hash of the built derivative artifact"),
	"original_sha256?": type("string").describe("SHA-256 hash of the clean base target"),
	"parent_sha256?": type("string").describe("SHA-256 hash of the immediate parent derivative or base target"),
	"parent_build_id?": type("string").describe("Build ID of the immediate parent derivative"),
	"target_version?": type("string").describe("Target application version (e.g. 'v9.5.0')"),
	"abi?": type("string").describe("Target ABI or architecture (e.g. 'arm64-v8a', 'x86_64')"),
	"architecture?": type("string").describe("Target CPU architecture"),
	"patches?": type("unknown").describe(
		"Array of cumulative or new patch records: [{ patch_id, member_path?, offset, original_bytes, expected_bytes, status?, retirement_reason?, evidence_id? }]",
	),
	"retired_patches?": type("unknown").describe(
		"Array of patches explicitly retired in this revision: [{ patch_id, reason }]",
	),
	"patch_id?": type("string").describe("Patch identifier for retire_patch action"),
	"reason?": type("string").describe("Mandatory reason when retiring a patch"),
	"signature_status?": type.enumerated("signed", "unsigned", "unknown").describe("Signature status of the derivative"),
	"signature_fingerprint?": type("string").describe("Signature certificate or block fingerprint (SHA-256)"),
	"signature_scheme?": type("string").describe("Signature scheme (e.g. 'v1', 'v2', 'v3', 'Authenticode')"),
	"runtime_evidence_ids?": type("string[]").describe(
		"Array of evidence IDs bound to this exact derivative output SHA-256",
	),
	"verification_conditions?": type("unknown").describe("Optional verification conditions or requirements"),
	"criterion_id?": type("string").describe("Acceptance criterion identifier for 'waive_acceptance' action"),
	"dependency_id?": type("string").describe("Workflow dependency identifier for 'approve_dependency' action"),
	"acceptance_criteria?": type("unknown").describe(
		"Array of acceptance criteria: [{ id, title, target_object, required_evidence_types?, min_assurance? }]",
	),
	"target_device_constraints?": type("unknown").describe(
		"Target device constraints: { target_environment?, disallowed_dependencies?, allowed_delivery_modes?, requires_standalone? }",
	),
	"dependencies?": type("unknown").describe(
		"Array of workflow dependencies: [{ id, name, kind, scope, target_host?, approved_for_delivery? }]",
	),
	"scope?": type
		.enumerated("experiment", "delivery")
		.describe("Target scope or deployment mode: 'experiment' or 'delivery'"),
	"delivery_mode?": type("string").describe(
		"Delivery packaging mode for derivative registration (e.g. 'standalone_package', 'modified_apk')",
	),
});

export type ReverseWorkflowParams = typeof reverseWorkflowSchema.infer;

export interface ReverseWorkflowDetails {
	action:
		| "create"
		| "plan"
		| "status"
		| "record"
		| "retry"
		| "recover"
		| "retry_plan"
		| "export"
		| "destroy"
		| "advance"
		| "auto_advance"
		| "register_derivative"
		| "verify_lineage"
		| "retire_patch"
		| "waive_acceptance"
		| "approve_dependency";
	derivative?: BuildArtifactRecord;
	derivatives?: BuildArtifactRecord[];
	baseline?: BuildArtifactRecord;
	verification_result?: BuildVerificationResult;
	retirement_audit?: PatchRetirementAuditEntry;
	workflow?: ReverseWorkflowRecord;
	workflows?: ReverseWorkflowRecord[];
	step?: WorkflowStepRecord;
	plan?: {
		format: TargetFormat;
		steps: WorkflowStepRecord[];
	};
	recovery_plan?: RecoveryPlan;
	metrics?: WorkflowMetrics;
	export_format?: "markdown" | "json";
	artifactId?: string;
	artifactPath?: string;
	destroyed?: boolean;
	workspace_dir?: string;
	workspace_manifest?: ReverseWorkspaceManifest;
	workspace_files_count?: number;
	knowledge_refs?: string[];
	prior_knowledge?: Array<{
		id: string;
		title: string;
		kind: string;
		confidence: string;
	}>;
	progression_status?: ProgressionStatus;
	decision?: string;
	decision_reason?: string;
	progression_audit?: ProgressionAuditEntry[];
	evaluated_steps?: WorkflowStepRecord[];
	resume?: StepResumeMetadata;
	status?: string;
	verified?: boolean;
	missing_tool?: string;
	setup_command?: string;
	advanced?: boolean;
	meta?: OutputMeta;
	criterion?: AcceptanceCriterion;
	dependency?: WorkflowDependencyRecord;
	waiver_approved?: boolean;
	dependency_approved?: boolean;
}

export class ReverseWorkflowTool implements AgentTool<typeof reverseWorkflowSchema, ReverseWorkflowDetails> {
	readonly name = "reverse_workflow";
	readonly label = "Reverse Engineering Workflow Orchestrator";
	readonly summary =
		"Bounded reverse-engineering workflow orchestrator: target-first routing, deterministic tool plans, cross-tool evidence association, and failure recovery metadata without arbitrary execution.";
	readonly description: string;
	readonly parameters = reverseWorkflowSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (
				action === "create" ||
				action === "record" ||
				action === "retry" ||
				action === "recover" ||
				action === "destroy" ||
				action === "advance" ||
				action === "auto_advance" ||
				action === "register_derivative" ||
				action === "retire_patch" ||
				action === "waive_acceptance" ||
				action === "approve_dependency" ||
				(action === "export" &&
					(("to_workspace" in args && Boolean(args.to_workspace)) ||
						("workspace_path" in args && Boolean(args.workspace_path))))
			) {
				return "write";
			}
		}
		return "read";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(reverseWorkflowDescription);
	}

	async execute(
		_toolCallId: string,
		params: ReverseWorkflowParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<ReverseWorkflowDetails> & { details: ReverseWorkflowDetails }> {
		throwIfAborted(signal);

		const repoRoot = this.session.cwd ?? getProjectDir();
		const store = new ReverseWorkflowStore({ repositoryRoot: repoRoot });
		const evidenceStore = new EvidenceStore({ repositoryRoot: repoRoot, signal });
		const knowledgeStore = new ReverseKnowledgeStore({ repositoryRoot: repoRoot });

		switch (params.action) {
			case "create": {
				const rawTarget = params.target ?? params.path;
				if (!rawTarget) {
					throw new ToolError("Target file path ('target' or 'path') is required for 'create' action.");
				}

				const targetPath = resolveReadPath(rawTarget, this.session.cwd);
				let stat;
				try {
					stat = await fs.stat(targetPath);
				} catch (err) {
					throw new ToolError(
						`Target file not found: ${rawTarget} (${err instanceof Error ? err.message : String(err)})`,
					);
				}

				if (stat.isDirectory()) {
					throw new ToolError(`Target path must be a file, not a directory: ${rawTarget}`);
				}

				// Sample header up to 64KB for format sniffing
				const readLen = Math.min(stat.size, 65536);
				const buf = Buffer.alloc(readLen);
				const fileHandle = await fs.open(targetPath, "r");
				try {
					await fileHandle.read(buf, 0, readLen, 0);
				} finally {
					await fileHandle.close();
				}

				// Compute full target SHA-256 (not bounded to prefix sample)
				let fileHash: string;
				if (stat.size <= readLen) {
					fileHash = createHash("sha256").update(buf.subarray(0, stat.size)).digest("hex");
				} else {
					const hashed = await hashFile(targetPath);
					if (hashed?.sha256) {
						fileHash = hashed.sha256;
					} else {
						const hash = createHash("sha256");
						const stream = createReadStream(targetPath);
						for await (const chunk of stream) {
							hash.update(chunk);
						}
						fileHash = hash.digest("hex");
					}
				}
				const detectedFormat = sniffTargetFormat(targetPath, buf, stat.size);
				const plan = generateDeterministicPlan(targetPath, detectedFormat, {
					goal: params.goal,
					maxAttempts: params.max_attempts,
					formatOverride: params.format,
				});

				const priorKnowledge = await knowledgeStore.search({
					format: plan.format,
					target_hash: fileHash,
					query: params.goal,
					limit: 5,
				});
				const knowledgeRefs = priorKnowledge.length > 0 ? priorKnowledge.map(k => k.id) : undefined;

				const workflowId = params.workflow_id ?? params.id ?? createWorkflowId();
				const now = new Date().toISOString();

				const metadata: Record<string, unknown> = {};
				const constraints = normalizeTargetDeviceConstraints(params.target_device_constraints);
				if (constraints) {
					metadata.target_device_constraints = constraints;
				}
				const dependencies = normalizeWorkflowDependencies(params.dependencies, { isInitialCreation: true });
				if (dependencies) {
					metadata.dependencies = dependencies;
				}

				const workflow: ReverseWorkflowRecord = {
					id: workflowId,
					target: path.relative(this.session.cwd, targetPath) || targetPath,
					target_abs_path: targetPath,
					target_sha256: fileHash,
					target_size: stat.size,
					format: plan.format,
					goal: params.goal,
					status: "active",
					steps: plan.steps,
					created_at: now,
					updated_at: now,
					...(knowledgeRefs ? { knowledge_refs: knowledgeRefs } : {}),
					...(Object.keys(metadata).length > 0 ? { metadata } : {}),
				};

				if (Array.isArray(params.acceptance_criteria)) {
					const normalizedCriteria = params.acceptance_criteria.map(c =>
						normalizeAcceptanceCriterion(c, undefined, { isInitialCreation: true }),
					);
					setWorkflowAcceptanceCriteria(workflow, normalizedCriteria);
				}

				await store.save(workflow);
				const metrics = computeWorkflowMetrics(workflow.steps, workflow.metadata);

				const stepListText = workflow.steps
					.map(s => `  - [${s.id}] ${s.title} -> tool: \`${s.tool}\` (${s.gate})`)
					.join("\n");

				const text = [
					`Created reverse engineering workflow \`${workflow.id}\``,
					`- **Target**: \`${workflow.target}\` (${stat.size} bytes, format: **${workflow.format}**)`,
					workflow.goal ? `- **Goal**: ${workflow.goal}` : undefined,
					`- **Status**: active | ${workflow.steps.length} steps planned`,
					"",
					"Planned Steps:",
					stepListText,
					"",
					`Next recommended step: \`${workflow.steps[0]?.id}\` via \`${workflow.steps[0]?.tool}\`. Run the tool and call 'record' when finished.`,
					...(priorKnowledge.length > 0
						? [
								"",
								`Prior Knowledge (${priorKnowledge.length} reusable ${priorKnowledge.length === 1 ? "entry" : "entries"} found):`,
								...priorKnowledge.map(k => {
									const sourceTag =
										k.source === "bundled" || k.metadata?.source === "bundled" ? " [bundled template]" : "";
									return `  - [\`${k.id}\`] ${k.title} (${k.kind}, ${k.confidence.toUpperCase()})${sourceTag}${k.actionable_guidance ? `\n    Guidance: ${k.actionable_guidance}` : ""}`;
								}),
							]
						: []),
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "create",
						workflow,
						metrics,
						knowledge_refs: knowledgeRefs,
						prior_knowledge: priorKnowledge.map(k => ({
							id: k.id,
							title: k.title,
							kind: k.kind,
							confidence: k.confidence,
						})),
					},
				};
			}

			case "plan": {
				const workflowId = params.workflow_id ?? params.id;
				if (workflowId) {
					const existing = await store.get(workflowId);
					if (existing) {
						const metrics = computeWorkflowMetrics(existing.steps);
						const stepListText = existing.steps
							.map(s => `  - [${s.status.toUpperCase()}] ${s.id}: ${s.title} -> tool: \`${s.tool}\``)
							.join("\n");
						const knText = existing.knowledge_refs?.length
							? `\nLinked Knowledge: ${existing.knowledge_refs.join(", ")}`
							: "";
						const text = `Plan for existing workflow \`${existing.id}\` (Format: ${existing.format}):\n${stepListText}${knText}`;
						return {
							content: [{ type: "text", text }],
							details: {
								action: "plan",
								workflow: existing,
								plan: { format: existing.format, steps: existing.steps },
								metrics,
								knowledge_refs: existing.knowledge_refs,
							},
						};
					}
				}

				const rawTarget = params.target ?? params.path;
				if (!rawTarget && !params.format) {
					throw new ToolError(
						"Either target path ('target') or format ('format') must be specified for 'plan' action.",
					);
				}

				let detectedFormat: TargetFormat = "unknown";
				let targetPath = rawTarget ?? "";

				if (rawTarget) {
					targetPath = resolveReadPath(rawTarget, this.session.cwd);
					try {
						const stat = await fs.stat(targetPath);
						if (!stat.isDirectory()) {
							const readLen = Math.min(stat.size, 65536);
							const buf = Buffer.alloc(readLen);
							const fh = await fs.open(targetPath, "r");
							try {
								await fh.read(buf, 0, readLen, 0);
							} finally {
								await fh.close();
							}
							detectedFormat = sniffTargetFormat(targetPath, buf, stat.size);
						}
					} catch {
						// Target doesn't exist on disk, fallback to format override
						if (!params.format) {
							throw new ToolError(`Target file not found: ${rawTarget}`);
						}
					}
				}

				const plan = generateDeterministicPlan(targetPath || (rawTarget ?? "sample"), detectedFormat, {
					goal: params.goal,
					maxAttempts: params.max_attempts,
					formatOverride: params.format,
				});

				const priorKnowledge = await knowledgeStore.search({
					format: plan.format,
					query: params.goal,
					limit: 5,
				});

				const priorKnowledgeLines =
					priorKnowledge.length > 0
						? [
								"",
								`Prior Knowledge (${priorKnowledge.length} reusable ${priorKnowledge.length === 1 ? "entry" : "entries"} found):`,
								...priorKnowledge.map(
									k =>
										`  - [\`${k.id}\`] ${k.title} (${k.kind}, ${k.confidence.toUpperCase()})${k.actionable_guidance ? `\n    Guidance: ${k.actionable_guidance}` : ""}`,
								),
							]
						: [];

				const stepListText = plan.steps
					.map(s => {
						const paramsSummary =
							typeof s.params_summary === "string" ? s.params_summary : JSON.stringify(s.params_summary);
						return `  - [${s.id}] ${s.title}\n    Tool: \`${s.tool}\` (${s.gate}) | Default params: \`${paramsSummary}\``;
					})
					.join("\n");

				const text = [
					`Deterministic Reverse Engineering Plan for **${plan.format}**:`,
					stepListText,
					...priorKnowledgeLines,
					"",
					'To initiate this workflow and start tracking execution state, call \'reverse_workflow(action: "create", target: "...")\'.',
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "plan",
						plan,
						knowledge_refs: priorKnowledge.map(k => k.id),
						prior_knowledge: priorKnowledge.map(k => ({
							id: k.id,
							title: k.title,
							kind: k.kind,
							confidence: k.confidence,
						})),
					},
				};
			}

			case "status": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					const workflows = await store.list();
					if (workflows.length === 0) {
						return {
							content: [{ type: "text", text: "No reverse engineering workflows found for this project." }],
							details: { action: "status", workflows: [] },
						};
					}

					const listLimit = Math.min(params.limit ?? 20, 100);
					const items = workflows.slice(0, listLimit).map(wf => {
						const m = computeWorkflowMetrics(wf.steps);
						const knTag = wf.knowledge_refs?.length ? `, ${wf.knowledge_refs.length} knowledge refs` : "";
						return `- \`${wf.id}\` [${wf.status.toUpperCase()}]: ${wf.target} (${wf.format}) - ${m.completed_steps}/${m.total_steps} steps, ${m.total_evidence_links} evidence links${knTag} (Updated: ${wf.updated_at})`;
					});

					const text = `Reverse Engineering Workflows (${workflows.length} total):\n\n${items.join("\n")}`;
					return {
						content: [{ type: "text", text }],
						details: { action: "status", workflows },
					};
				}

				const workflow = await store.get(workflowId);
				if (!workflow) {
					throw new ToolError(`Workflow '${workflowId}' not found.`);
				}
				const refutationResult = await cascadeEvidenceRefutation(workflow, evidenceStore).catch(() => null);
				if (
					refutationResult &&
					(refutationResult.invalidatedSteps.length > 0 || refutationResult.invalidatedCriteria.length > 0)
				) {
					await store.save(workflow);
				}

				if (params.step_id) {
					const step = workflow.steps.find(s => s.id === params.step_id);
					if (!step) {
						throw new ToolError(`Step '${params.step_id}' not found in workflow '${workflowId}'.`);
					}

					const stepLines = [
						`### Step Details: \`${step.id}\` (${step.title})`,
						`- **Tool**: \`${step.tool}\` (${step.gate})`,
						`- **Status**: ${step.status} (Attempts: ${step.attempts}/${step.max_attempts})`,
						`- **Parameters**: \`${typeof step.params_summary === "string" ? step.params_summary : JSON.stringify(step.params_summary)}\``,
					];

					if (step.outputs) {
						const outStr = typeof step.outputs === "string" ? step.outputs : JSON.stringify(step.outputs);
						stepLines.push(`- **Output**: ${outStr}`);
					}
					if (step.artifact_refs?.length) {
						stepLines.push(`- **Artifacts**: ${step.artifact_refs.join(", ")}`);
					}
					if (step.evidence_ids?.length) {
						stepLines.push(`- **Linked Evidence**: ${step.evidence_ids.join(", ")}`);
					}
					if (step.knowledge_refs?.length) {
						stepLines.push(`- **Knowledge References**: ${step.knowledge_refs.join(", ")}`);
					}
					if (step.error) {
						stepLines.push(`- **Error**: ${step.error}`);
					}
					if (step.runtime_session_id) {
						stepLines.push(`- **Runtime Session**: \`${step.runtime_session_id}\``);
					}
					if (step.runtime_session_ids?.length) {
						stepLines.push(
							`- **Runtime Sessions**: ${step.runtime_session_ids.map(id => `\`${id}\``).join(", ")}`,
						);
					}
					if (step.recovery_metadata) {
						const rec = step.recovery_metadata;
						stepLines.push("- **Recovery Metadata**:");
						if (rec.attribution) {
							stepLines.push(
								`  - Attribution: [${rec.attribution.category.toUpperCase()}] ${rec.attribution.cause}`,
							);
							if (rec.attribution.install_hint) {
								stepLines.push(`    - Install Hint: \`${rec.attribution.install_hint}\``);
							}
							if (rec.attribution.setup_command) {
								stepLines.push(`    - Setup Command: \`${rec.attribution.setup_command}\``);
							}
						}
						if (rec.resume) {
							stepLines.push("  - Install-After Resume Metadata:");
							if (rec.resume.capability_id)
								stepLines.push(`    - Capability ID: \`${rec.resume.capability_id}\``);
							stepLines.push(`    - Installed Tool: \`${rec.resume.installed_tool}\``);
							if (rec.resume.setup_command)
								stepLines.push(`    - Setup Command: \`${rec.resume.setup_command}\``);
							stepLines.push(`    - Verified: ${rec.resume.verified}`);
							stepLines.push(`    - Strategy: \`${rec.resume.strategy}\``);
							stepLines.push(`    - Resumed At: ${rec.resume.resumed_at}`);
							if (rec.resume.notes) stepLines.push(`    - Notes: ${rec.resume.notes}`);
						}
						if (rec.failure_reason && !rec.attribution) {
							stepLines.push(`  - Failure Reason: ${rec.failure_reason}`);
						}
						if (rec.fallback_tool) stepLines.push(`  - Fallback Tool: \`${rec.fallback_tool}\``);
						if (rec.suggested_fix) stepLines.push(`  - Suggested Fix: ${rec.suggested_fix}`);
						if (rec.recovery_audit && rec.recovery_audit.length > 0) {
							stepLines.push("  - Recovery Audit Trail:");
							for (const audit of rec.recovery_audit) {
								const toolTransition =
									audit.previous_tool === audit.proposed_tool
										? `\`${audit.proposed_tool}\``
										: `\`${audit.previous_tool}\` -> \`${audit.proposed_tool}\``;
								stepLines.push(
									`    - [Attempt ${audit.attempt}] (${audit.action}): [${audit.category}] ${toolTransition} - ${audit.decision}`,
								);
								if (audit.evidence_ids && audit.evidence_ids.length > 0) {
									stepLines.push(
										`      - Associated Evidence: ${audit.evidence_ids.map(id => `\`${id}\``).join(", ")}`,
									);
								}
							}
						}
					}
					return {
						content: [{ type: "text", text: stepLines.join("\n") }],
						details: { action: "status", workflow, step, resume: step.recovery_metadata?.resume },
					};
				}

				const metrics = computeWorkflowMetrics(workflow.steps, workflow.metadata);
				const stepRows = workflow.steps.map(s => {
					const evLinks = s.evidence_ids?.length ? ` [${s.evidence_ids.length} ev]` : "";
					const runtTag = s.runtime_session_id ? ` [runt: ${s.runtime_session_id}]` : "";
					const auditCount = s.recovery_metadata?.recovery_audit?.length
						? ` [${s.recovery_metadata.recovery_audit.length} recovery audit]`
						: "";
					const resumeTag = s.recovery_metadata?.resume
						? ` [resumed: ${s.recovery_metadata.resume.installed_tool}]`
						: "";
					return `  - [${s.status.toUpperCase()}] ${s.id}: ${s.title} -> \`${s.tool}\` (${s.attempts}/${s.max_attempts} attempts)${evLinks}${runtTag}${auditCount}${resumeTag}`;
				});

				const text = [
					`Workflow Status: \`${workflow.id}\``,
					`- **Target**: \`${workflow.target}\` (${workflow.format})`,
					`- **Status**: ${workflow.status.toUpperCase()}`,
					`- **Metrics**: ${metrics.completed_steps} completed, ${metrics.failed_steps} failed, ${metrics.pending_steps} pending, ${metrics.total_evidence_links} evidence links${metrics.resumed_steps ? `, ${metrics.resumed_steps} resumed` : ""}${metrics.total_knowledge_links ? `, ${metrics.total_knowledge_links} knowledge links` : ""}`,
					...(metrics.total_acceptance_criteria !== undefined
						? [
								`- **Acceptance Criteria**: ${metrics.satisfied_acceptance_criteria ?? 0}/${metrics.total_acceptance_criteria} satisfied (${metrics.pending_acceptance_criteria ?? 0} pending${metrics.proxy_verified_acceptance_criteria ? `, ${metrics.proxy_verified_acceptance_criteria} proxy verified` : ""}${metrics.waived_acceptance_criteria ? `, ${metrics.waived_acceptance_criteria} waived` : ""}) - ${Math.round((metrics.acceptance_completion_ratio ?? 0) * 100)}% completion`,
							]
						: []),
					workflow.knowledge_refs && workflow.knowledge_refs.length > 0
						? `- **Knowledge References**: ${workflow.knowledge_refs.map(id => `\`${id}\``).join(", ")}`
						: undefined,
					"",
					...(workflow.progression_audit && workflow.progression_audit.length > 0
						? [
								"Recent Progression Decisions:",
								...workflow.progression_audit
									.slice(-3)
									.map(a => `  - [${a.status.toUpperCase()}] ${a.step_id} (${a.tool}): ${a.decision}`),
								"",
							]
						: []),
					...(workflow.build_lineage && workflow.build_lineage.length > 0
						? [
								"",
								`Build Lineage (${workflow.build_lineage.length} derivatives):`,
								`- Current Baseline: \`${workflow.current_baseline_build_id ?? "none"}\``,
								...workflow.build_lineage.map(b => {
									const activeP = b.cumulative_patches.filter(p => p.status === "active").length;
									const isBase = b.build_id === workflow.current_baseline_build_id ? " [ACTIVE BASELINE]" : "";
									return `  - \`${b.build_id}\`${isBase}: ${b.target_path} (Output: ${b.output_sha256.slice(0, 12)}...) | Static: ${b.verification_result.static_status.toUpperCase()} (${activeP} active patches) | Runtime: ${b.verification_result.runtime_status.toUpperCase()}`;
								}),
							]
						: []),
					"Steps:",
					stepRows.join("\n"),
					"",
					metrics.next_step
						? `Next pending step: \`${metrics.next_step.id}\` via \`${metrics.next_step.tool}\`.`
						: "All steps completed or no pending steps.",
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "status",
						workflow,
						metrics,
						baseline: workflow.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id),
						derivatives: workflow.build_lineage,
					},
				};
			}

			case "record": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'record' action.");

				const stepId = params.step_id;
				if (!stepId) throw new ToolError("step_id is required for 'record' action.");

				const status = params.status;
				if (!status) {
					throw new ToolError(
						"status ('completed', 'failed', 'running', 'skipped') is required for 'record' action.",
					);
				}

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const step = workflow.steps.find(s => s.id === stepId);
				if (!step) throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);

				// Validate and link evidence IDs if provided
				if (Array.isArray(params.evidence_ids) && params.evidence_ids.length > 0) {
					for (const evId of params.evidence_ids) {
						if (!validateEvidenceIdFormat(evId)) {
							throw new ToolError(
								`Invalid evidence ID format: '${evId}'. Must be a valid evidence ledger ID starting with ev_fact_, ev_hyp_, ev_conc_, or ev_unk_.`,
							);
						}
						const existingRecord = await evidenceStore.getRecord(evId);
						if (!existingRecord) {
							throw new ToolError(
								`Evidence ID '${evId}' not found in the project evidence ledger. You must first record the fact or hypothesis using the 'evidence' tool (action: 'add') before linking it to workflow steps.`,
							);
						}
					}
					step.evidence_ids = Array.from(new Set([...(step.evidence_ids ?? []), ...params.evidence_ids]));
				}

				if (Array.isArray(params.knowledge_refs) && params.knowledge_refs.length > 0) {
					for (const knId of params.knowledge_refs) {
						if (!validateKnowledgeIdFormat(knId)) {
							throw new ToolError(
								`Invalid knowledge ID format: '${knId}'. Must be a valid reverse knowledge ID starting with kn_rev_.`,
							);
						}
						const existingRecord = await knowledgeStore.get(knId);
						if (!existingRecord) {
							throw new ToolError(`Knowledge ID '${knId}' not found in the project reverse knowledge store.`);
						}
					}
					step.knowledge_refs = Array.from(new Set([...(step.knowledge_refs ?? []), ...params.knowledge_refs]));
					workflow.knowledge_refs = Array.from(
						new Set([...(workflow.knowledge_refs ?? []), ...params.knowledge_refs]),
					);
				}
				if (Array.isArray(params.artifact_refs)) {
					step.artifact_refs = Array.from(new Set([...(step.artifact_refs ?? []), ...params.artifact_refs]));
				}

				if (params.runtime_session_id) {
					step.runtime_session_id = params.runtime_session_id;
					step.runtime_session_ids = Array.from(
						new Set([...(step.runtime_session_ids ?? []), params.runtime_session_id]),
					);
					workflow.runtime_session_ids = Array.from(
						new Set([...(workflow.runtime_session_ids ?? []), params.runtime_session_id]),
					);
				}
				if (Array.isArray(params.runtime_session_ids) && params.runtime_session_ids.length > 0) {
					step.runtime_session_ids = Array.from(
						new Set([...(step.runtime_session_ids ?? []), ...params.runtime_session_ids]),
					);
					workflow.runtime_session_ids = Array.from(
						new Set([...(workflow.runtime_session_ids ?? []), ...params.runtime_session_ids]),
					);
					if (!step.runtime_session_id) {
						step.runtime_session_id = params.runtime_session_ids[0];
					}
				}
				if (params.outputs !== undefined) {
					step.outputs = params.outputs;
				}

				const errorMsg = params.error ?? params.failure_reason;
				if (errorMsg) {
					step.error = errorMsg;
					step.recovery_metadata = {
						...step.recovery_metadata,
						failure_reason: errorMsg,
					};
				}
				if (params.installed_tool) {
					const verification = verifyInstalledTool(params.installed_tool, { cwd: repoRoot });
					const resumeStrategy = params.strategy ?? params.resume_strategy ?? "resume_original";
					const resumeMeta: StepResumeMetadata = {
						capability_id: params.capability_id,
						installed_tool: params.installed_tool,
						setup_command: params.setup_command ?? verification.setup_command,
						verified: verification.verified,
						strategy: resumeStrategy,
						resumed_at: params.resumed_at ?? new Date().toISOString(),
					};
					step.recovery_metadata = {
						...step.recovery_metadata,
						resume: resumeMeta,
					};
				}
				if (status === "completed") {
					await cascadeEvidenceRefutation(workflow, evidenceStore).catch(() => null);

					// 1. Evidence validation via evaluateEvidenceSupport
					const evidenceRecords: EvidenceRecord[] = [];
					if (step.evidence_ids && step.evidence_ids.length > 0) {
						const evalResult = await evaluateEvidenceSupport(evidenceStore, step.evidence_ids);
						if (evalResult.refutedIds.length > 0) {
							throw new ToolError(
								`Cannot mark step '${step.id}' completed: supporting evidence has been refuted: ${evalResult.refutedIds.join(", ")}`,
							);
						}
						if (evalResult.staleIds.length > 0) {
							throw new ToolError(
								`Cannot mark step '${step.id}' completed: supporting evidence is stale or invalidated: ${evalResult.staleIds.join(", ")}`,
							);
						}
						if (evalResult.failedStageIds.length > 0) {
							throw new ToolError(
								`Cannot mark step '${step.id}' completed: supporting evidence contains failed execution stages: ${evalResult.failedStageIds.join(", ")}`,
							);
						}
						for (const evId of step.evidence_ids) {
							const rec = await evidenceStore.getRecord(evId);
							if (rec) evidenceRecords.push(rec);
						}
					}

					// 2. Acceptance criteria gate
					const stepCriteria = getWorkflowAcceptanceCriteria(workflow, step.id);
					if (stepCriteria.length > 0) {
						let allSatisfied = true;
						let proxyDetected = false;
						let proxyReasonMessage: string | undefined;

						for (const criterion of stepCriteria) {
							if (criterion.status === "waived" || criterion.status === "satisfied") continue;

							const satisfaction = await evaluateAcceptanceSatisfaction(
								criterion,
								evidenceRecords,
								evidenceStore,
							);
							if (satisfaction.isProxy) {
								proxyDetected = true;
								proxyReasonMessage = satisfaction.proxyReason;
								criterion.status = "proxy_verified";
								criterion.is_proxy = true;
								criterion.proxy_for_criterion_id = criterion.id;
								criterion.proxy_evidence_ids = satisfaction.matchingEvidenceIds;
								criterion.updated_at = new Date().toISOString();
								updateAcceptanceCriterion(workflow, criterion);
								allSatisfied = false;
							} else if (satisfaction.status === "satisfied") {
								criterion.status = "satisfied";
								criterion.satisfied_by_evidence_ids = satisfaction.matchingEvidenceIds;
								criterion.updated_at = new Date().toISOString();
								updateAcceptanceCriterion(workflow, criterion);
							} else {
								allSatisfied = false;
							}
						}

						if (!allSatisfied) {
							await store.save(workflow);
							const msg = proxyDetected
								? (proxyReasonMessage ??
									`Proxy observation recorded for step '${step.id}', but original acceptance criteria remain pending without explicit user waiver.`)
								: `Step '${step.id}' cannot be marked completed: required acceptance criteria remain unsatisfied.`;
							throw new ToolError(msg);
						}
					}

					// 3. Delivery & Target Device constraints gate
					const isDelivery = step.is_delivery_step || step.delivery_scope === "delivery" || step.gate === "G4";
					if (isDelivery) {
						const constraints = workflow.metadata?.target_device_constraints as
							| TargetDeviceConstraints
							| undefined;
						const dependencies = workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined;
						const constraintCheck = validateDeploymentConstraints(constraints, dependencies, "delivery");
						if (!constraintCheck.valid) {
							throw new ToolError(
								`Delivery step '${step.id}' cannot be marked completed: ${constraintCheck.violationCode}: ${constraintCheck.violation}`,
							);
						}
					}
				}

				step.attempts = (step.attempts ?? 0) + 1;
				step.status = status;
				step.updated_at = new Date().toISOString();

				// Update overall workflow status: verify that ALL acceptance criteria are satisfied or waived
				const allDone = workflow.steps.every(s => s.status === "completed" || s.status === "skipped");
				const allCriteria = getWorkflowAcceptanceCriteria(workflow);
				const unresolvedCriteria = allCriteria.filter(c => c.status !== "satisfied" && c.status !== "waived");
				if (allDone && unresolvedCriteria.length === 0) {
					workflow.status = "completed";
				} else {
					workflow.status = "active";
				}

				if (status === "completed") {
					if (!workflow.metadata) workflow.metadata = {};
					const activeProof = (workflow.metadata.active_proof as Record<string, string[]> | undefined) ?? {};
					activeProof[step.id] = params.evidence_ids ?? [];
					workflow.metadata.active_proof = activeProof;
				}
				workflow.updated_at = new Date().toISOString();
				if (allDone && workflow.metadata?.auto_export_workspace === true) {
					try {
						const projectDir = repoRoot;
						await exportWorkflowToWorkspace({
							workflow,
							evidenceStore,
							projectDir,
						});
					} catch {
						// completion policy export is non-fatal
					}
				}

				await store.save(workflow);
				const metrics = computeWorkflowMetrics(workflow.steps, workflow.metadata);

				const text = [
					`Updated step \`${step.id}\` in workflow \`${workflow.id}\`:`,
					`- Status: **${step.status}** (Attempts: ${step.attempts}/${step.max_attempts})`,
					step.evidence_ids?.length ? `- Linked Evidence: ${step.evidence_ids.join(", ")}` : undefined,
					step.runtime_session_id ? `- Associated Runtime Session: \`${step.runtime_session_id}\`` : undefined,
					step.outputs
						? `- Output recorded (${typeof step.outputs === "string" ? step.outputs.length : JSON.stringify(step.outputs).length} chars)`
						: undefined,
					step.error ? `- Failure reason: ${step.error}` : undefined,
					step.recovery_metadata?.resume
						? `- Resumed Tool: \`${step.recovery_metadata.resume.installed_tool}\` (Capability: \`${step.recovery_metadata.resume.capability_id || "none"}\`)`
						: undefined,
					metrics.next_step
						? `Next recommended step: \`${metrics.next_step.id}\` via \`${metrics.next_step.tool}\`.`
						: "Workflow completed!",
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "record",
						workflow,
						step,
						metrics,
						resume: step.recovery_metadata?.resume,
					},
				};
			}

			case "retry": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'retry' action.");

				const stepId = params.step_id;
				if (!stepId) throw new ToolError("step_id is required for 'retry' action.");

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const step = workflow.steps.find(s => s.id === stepId);
				if (!step) throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);

				if (step.status !== "failed") {
					throw new ToolError(
						`Cannot retry step '${stepId}': step is currently in '${step.status}' state. Only steps in 'failed' state can be retried.`,
					);
				}

				const maxAttempts =
					typeof params.max_attempts === "number" && params.max_attempts > 0
						? Math.min(params.max_attempts, HARD_MAX_ATTEMPTS)
						: step.max_attempts || DEFAULT_MAX_ATTEMPTS;

				if (step.attempts >= maxAttempts) {
					throw new ToolError(
						`Retry attempt limit reached for step '${stepId}' (${step.attempts}/${maxAttempts} attempts). Maximum retry attempts exceeded.`,
					);
				}

				const retryNumber = step.attempts + 1;
				const callerResult = params.result ?? params.caller_result;

				const rawError = step.error ?? step.recovery_metadata?.failure_reason ?? "Step execution failed";
				const attribution = classifyFailure(rawError, {
					tool: step.tool,
					stepId: step.id,
					targetPath: workflow.target_abs_path || workflow.target,
					targetFormat: workflow.format,
					paramsSummary: step.params_summary,
				});
				const proposedParams = params.next_params !== undefined ? params.next_params : step.params_summary;
				let resumeMeta: StepResumeMetadata | undefined = step.recovery_metadata?.resume;
				let isVerified = true;
				let verificationResult: VerifyToolResult | undefined;

				if (params.installed_tool) {
					verificationResult = verifyInstalledTool(params.installed_tool, { cwd: repoRoot });
					isVerified = verificationResult.verified;
					const resumeStrategy =
						params.strategy ??
						params.resume_strategy ??
						(params.installed_tool === step.tool ? "resume_original" : "fallback");
					resumeMeta = {
						capability_id: params.capability_id,
						installed_tool: params.installed_tool,
						setup_command: params.setup_command ?? verificationResult.setup_command ?? attribution.setup_command,
						verified: isVerified,
						strategy: resumeStrategy,
						resumed_at: params.resumed_at ?? new Date().toISOString(),
						resumed_params: proposedParams,
					};
				}

				const proposedTool =
					params.fallback_tool ??
					(resumeMeta && resumeMeta.strategy === "fallback" ? resumeMeta.installed_tool : step.tool);

				if (params.installed_tool && !isVerified) {
					const auditEntry: RecoveryAuditEntry = {
						attempt: retryNumber,
						timestamp: new Date().toISOString(),
						action: "resume",
						category: "missing_dependency",
						cause:
							verificationResult?.missing_reason ??
							`Tool '${params.installed_tool}' not found or unconfigured on host`,
						previous_tool: step.tool,
						proposed_tool: step.tool,
						proposed_params: step.params_summary,
						decision: `Resumption rejected: tool '${params.installed_tool}' is unverified on host system.`,
						applied: false,
						evidence_ids: params.evidence_ids,
						caller_result: callerResult,
						capability_id: resumeMeta?.capability_id,
						installed_tool: resumeMeta?.installed_tool,
						setup_command: resumeMeta?.setup_command,
						verified: false,
						strategy: resumeMeta?.strategy,
					};
					step.recovery_metadata = {
						...step.recovery_metadata,
						failure_reason: rawError,
						recovery_audit: [...(step.recovery_metadata?.recovery_audit ?? []), auditEntry],
						resume: resumeMeta,
					};
					await store.save(workflow);
					const metrics = computeWorkflowMetrics(workflow.steps);
					const missingReason =
						verificationResult?.missing_reason ??
						"Executable binary not found on PATH or service unconfigured in mcp.json.";
					const setupCmd = resumeMeta?.setup_command ?? `reverse setup reverse ${params.installed_tool}`;
					const text = [
						`Cannot resume step \`${step.id}\` in workflow \`${workflow.id}\`:`,
						`- Tool: \`${params.installed_tool}\` could not be verified on the host system.`,
						`- Verification: **failed** (user-supplied \`verified: true\` rejected without host proof).`,
						`- Reason: ${missingReason}`,
						`- Required Setup: \`${setupCmd}\``,
						`- Status: step remains in **failed** state without replacing original tool or target parameters.`,
					].join("\n");

					return {
						content: [{ type: "text", text }],
						details: {
							action: "retry",
							workflow,
							step,
							metrics,
							resume: resumeMeta,
							status: "missing_dependency",
							verified: false,
							missing_tool: params.installed_tool,
							setup_command: setupCmd,
						},
					};
				}
				const auditAction: "retry" | "resume" = params.installed_tool ? "resume" : "retry";
				const auditEntry: RecoveryAuditEntry = {
					attempt: retryNumber,
					timestamp: new Date().toISOString(),
					action: auditAction,
					category: attribution.category,
					cause: attribution.cause,
					previous_tool: step.tool,
					proposed_tool: proposedTool,
					proposed_params: proposedParams,
					decision: resumeMeta
						? `Resumed with installed tool '${resumeMeta.installed_tool}' (${resumeMeta.strategy})`
						: callerResult
							? `Retry with caller diagnosis: ${callerResult}`
							: `Retry configured for attempt ${retryNumber}`,
					applied: true,
					evidence_ids: params.evidence_ids,
					caller_result: callerResult,
					capability_id: resumeMeta?.capability_id,
					installed_tool: resumeMeta?.installed_tool,
					setup_command: resumeMeta?.setup_command,
					verified: resumeMeta?.verified,
					strategy: resumeMeta?.strategy,
				};

				const retryEntry: StepRetryEntry = {
					attempt: retryNumber,
					timestamp: new Date().toISOString(),
					error: rawError,
					caller_result: callerResult,
					params: params.next_params,
				};

				step.recovery_metadata = {
					...step.recovery_metadata,
					failure_reason: rawError,
					fallback_tool: params.fallback_tool ?? step.recovery_metadata?.fallback_tool,
					attribution: step.recovery_metadata?.attribution ?? attribution,
					recovery_audit: [...(step.recovery_metadata?.recovery_audit ?? []), auditEntry],
					retry_history: [...(step.recovery_metadata?.retry_history ?? []), retryEntry],
					resume: resumeMeta ?? step.recovery_metadata?.resume,
				};

				if (params.fallback_tool) {
					step.tool = params.fallback_tool;
				} else if (resumeMeta && resumeMeta.strategy === "fallback") {
					step.tool = resumeMeta.installed_tool;
				}

				if (params.next_params !== undefined) {
					step.next_params = params.next_params;
					step.params_summary = params.next_params;
				}
				step.status = "pending";
				step.error = undefined;
				step.updated_at = new Date().toISOString();
				workflow.status = "active";
				workflow.updated_at = new Date().toISOString();

				await store.save(workflow);
				const metrics = computeWorkflowMetrics(workflow.steps);

				const text = [
					`Prepared retry for step \`${step.id}\` in workflow \`${workflow.id}\`:`,
					`- Tool: \`${step.tool}\``,
					`- Status: **pending** (Upcoming Attempt: ${retryNumber}/${maxAttempts})`,
					params.fallback_tool ? `- Fallback tool switched to: \`${params.fallback_tool}\`` : undefined,
					params.next_params ? `- Prepared retry parameters: \`${params.next_params}\`` : undefined,
					callerResult ? `- Diagnostic note: ${callerResult}` : undefined,
					resumeMeta
						? `- Resumed via installed tool: \`${resumeMeta.installed_tool}\` (Capability: \`${resumeMeta.capability_id || "none"}\`, Strategy: \`${resumeMeta.strategy}\`, Verified: ${resumeMeta.verified})`
						: undefined,
					"",
					`Ready for execution. Run \`${step.tool}\` with the specified parameters, then call 'record' with the result.`,
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "retry",
						workflow,
						step,
						metrics,
						resume: resumeMeta,
					},
				};
			}
			case "recover": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'recover' action.");

				const stepId = params.step_id;
				if (!stepId) throw new ToolError("step_id is required for 'recover' action.");

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const step = workflow.steps.find(s => s.id === stepId);
				if (!step) throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);

				if (step.status !== "failed") {
					throw new ToolError(
						`Cannot recover step '${stepId}': step is currently in '${step.status}' state. Only steps in 'failed' state can be recovered.`,
					);
				}

				const maxAttempts =
					typeof params.max_attempts === "number" && params.max_attempts > 0
						? Math.min(params.max_attempts, HARD_MAX_ATTEMPTS)
						: step.max_attempts || DEFAULT_MAX_ATTEMPTS;

				if (step.attempts >= maxAttempts) {
					throw new ToolError(
						`Retry attempt limit reached for step '${stepId}' (${step.attempts}/${maxAttempts} attempts). Maximum recovery attempts exceeded.`,
					);
				}

				// Validate and link evidence IDs if provided
				if (Array.isArray(params.evidence_ids) && params.evidence_ids.length > 0) {
					for (const evId of params.evidence_ids) {
						if (!validateEvidenceIdFormat(evId)) {
							throw new ToolError(
								`Invalid evidence ID format: '${evId}'. Must be a valid evidence ledger ID starting with ev_fact_, ev_hyp_, ev_conc_, or ev_unk_.`,
							);
						}
						const existingRecord = await evidenceStore.getRecord(evId);
						if (!existingRecord) {
							throw new ToolError(
								`Evidence ID '${evId}' not found in the project evidence ledger. You must first record the fact or hypothesis using the 'evidence' tool (action: 'add') before linking it to workflow recovery.`,
							);
						}
					}
					step.evidence_ids = Array.from(new Set([...(step.evidence_ids ?? []), ...params.evidence_ids]));
				}

				const rawError =
					params.error ?? params.failure_reason ?? step.error ?? "Step execution failed without explicit error";

				const plan = generateRecoveryPlan(step, workflow, {
					error: rawError,
					fallbackToolOverride: params.fallback_tool,
					nextParamsOverride: params.next_params,
					maxAttempts,
					capabilityId: params.capability_id,
					installedTool: params.installed_tool,
					setupCommand: params.setup_command,
					verified: params.verified,
					strategy: params.strategy ?? params.resume_strategy,
				});

				const retryNumber = step.attempts + 1;
				const callerResult = params.result ?? params.caller_result;

				const resumeMeta: StepResumeMetadata | undefined =
					plan.resume ??
					(params.installed_tool
						? {
								capability_id: params.capability_id,
								installed_tool: params.installed_tool,
								setup_command: params.setup_command ?? plan.attribution.setup_command,
								verified: false,
								strategy:
									params.strategy ??
									params.resume_strategy ??
									(params.installed_tool === step.tool ? "resume_original" : "fallback"),
								resumed_at: params.resumed_at ?? new Date().toISOString(),
								resumed_params: plan.next_params,
							}
						: undefined);

				if (resumeMeta && !resumeMeta.verified) {
					const unverifiedAudit: RecoveryAuditEntry = {
						attempt: retryNumber,
						timestamp: new Date().toISOString(),
						action: "resume",
						category: plan.attribution.category,
						cause: plan.attribution.cause,
						previous_tool: step.tool,
						proposed_tool: step.tool,
						proposed_params: step.params_summary,
						decision: `Resumption rejected: tool '${resumeMeta.installed_tool}' could not be verified on the host system.`,
						applied: false,
						evidence_ids: params.evidence_ids,
						caller_result: callerResult,
						capability_id: resumeMeta.capability_id,
						installed_tool: resumeMeta.installed_tool,
						setup_command: resumeMeta.setup_command,
						verified: false,
						strategy: resumeMeta.strategy,
					};
					step.recovery_metadata = {
						...step.recovery_metadata,
						failure_reason: rawError,
						attribution: plan.attribution,
						recovery_audit: [...(step.recovery_metadata?.recovery_audit ?? []), unverifiedAudit],
						resume: resumeMeta,
					};
					await store.save(workflow);
					const metrics = computeWorkflowMetrics(workflow.steps);
					const setupCmd = resumeMeta.setup_command ?? `reverse setup reverse ${resumeMeta.installed_tool}`;
					const text = [
						`Cannot recover step \`${step.id}\` in workflow \`${workflow.id}\`:`,
						`- Tool: \`${resumeMeta.installed_tool}\` could not be verified on the host system.`,
						`- Verification: **failed** (user-supplied \`verified: true\` rejected without host proof).`,
						`- Reason: ${plan.reasoning}`,
						`- Required Setup: \`${setupCmd}\``,
						`- Status: step remains in **failed** state without replacing original tool or target parameters.`,
					].join("\n");

					return {
						content: [{ type: "text", text }],
						details: {
							action: "recover",
							workflow,
							step,
							metrics,
							recovery_plan: plan,
							resume: resumeMeta,
							status: "missing_dependency",
							verified: false,
							missing_tool: resumeMeta.installed_tool,
							setup_command: setupCmd,
						},
					};
				}

				const auditAction: "recover" | "resume" = resumeMeta ? "resume" : "recover";
				const auditEntry: RecoveryAuditEntry = {
					attempt: retryNumber,
					timestamp: new Date().toISOString(),
					action: auditAction,
					category: plan.attribution.category,
					cause: plan.attribution.cause,
					previous_tool: step.tool,
					proposed_tool: plan.next_tool,
					proposed_params: plan.next_params,
					decision: resumeMeta
						? `Resumed with installed tool '${resumeMeta.installed_tool}' (${resumeMeta.strategy}): ${plan.reasoning}`
						: `Attributed as '${plan.attribution.category}'. ${plan.reasoning}`,
					applied: true,
					evidence_ids: params.evidence_ids,
					caller_result: callerResult,
					capability_id: resumeMeta?.capability_id,
					installed_tool: resumeMeta?.installed_tool,
					setup_command: resumeMeta?.setup_command,
					verified: resumeMeta?.verified,
					strategy: resumeMeta?.strategy,
					capability_depth: plan.capability_depth,
					verification_boundary: plan.verification_boundary,
					remaining_acceptance: plan.remaining_acceptance,
				};

				const retryEntry: StepRetryEntry = {
					attempt: retryNumber,
					timestamp: new Date().toISOString(),
					error: rawError,
					caller_result: callerResult,
					params: plan.next_params,
				};

				step.recovery_metadata = {
					...step.recovery_metadata,
					failure_reason: rawError,
					fallback_tool: plan.next_tool !== step.tool ? plan.next_tool : step.recovery_metadata?.fallback_tool,
					suggested_fix: plan.reasoning,
					attribution: plan.attribution,
					recovery_audit: [...(step.recovery_metadata?.recovery_audit ?? []), auditEntry],
					retry_history: [...(step.recovery_metadata?.retry_history ?? []), retryEntry],
					resume: resumeMeta ?? step.recovery_metadata?.resume,
					capability_depth: plan.capability_depth,
					verification_boundary: plan.verification_boundary,
					remaining_acceptance: plan.remaining_acceptance,
				};

				step.tool = plan.next_tool;
				step.params_summary = plan.next_params;
				step.next_params = plan.next_params;
				step.status = "pending";
				step.error = undefined;
				step.updated_at = new Date().toISOString();
				workflow.status = "active";
				workflow.updated_at = new Date().toISOString();

				await store.save(workflow);
				const metrics = computeWorkflowMetrics(workflow.steps);

				const nextParamsStr =
					typeof plan.next_params === "string" ? plan.next_params : JSON.stringify(plan.next_params);

				const text = [
					`Recovered step \`${step.id}\` in workflow \`${workflow.id}\`:`,
					`- Failure Attribution: **[${plan.attribution.category.toUpperCase()}]** ${plan.attribution.cause}`,
					plan.attribution.install_hint ? `- Install Hint: \`${plan.attribution.install_hint}\`` : undefined,
					plan.attribution.setup_command ? `- Setup Command: \`${plan.attribution.setup_command}\`` : undefined,
					`- Recovery Strategy: **${plan.suggested_action}**`,
					plan.capability_depth ? `- Capability Depth: **${plan.capability_depth.toUpperCase()}**` : undefined,
					plan.verification_boundary ? `- Verification Boundary: ${plan.verification_boundary}` : undefined,
					plan.remaining_acceptance ? `- Remaining Acceptance: ${plan.remaining_acceptance}` : undefined,
					plan.prerequisites && plan.prerequisites.length > 0
						? `- Prerequisites: ${plan.prerequisites.map(p => `\`${p}\``).join(", ")}`
						: undefined,
					plan.discovery_guidance?.notice ? `- Discovery Guidance: ${plan.discovery_guidance.notice}` : undefined,
					resumeMeta
						? `- Install-After Resume: Tool \`${resumeMeta.installed_tool}\` installed and verified (Capability: \`${resumeMeta.capability_id || "none"}\`, Strategy: \`${resumeMeta.strategy}\`)`
						: undefined,
					`- Tool: \`${step.tool}\` (Previous: \`${auditEntry.previous_tool}\`)`,
					`- Status: **pending** (Upcoming Attempt: ${retryNumber}/${maxAttempts})`,
					`- Corrected Parameters: \`${nextParamsStr}\``,
					plan.alternatives.length > 1
						? `- Alternatives: ${plan.alternatives.map(a => `\`${a}\``).join(", ")}`
						: undefined,
					step.evidence_ids?.length ? `- Linked Evidence: ${step.evidence_ids.join(", ")}` : undefined,
					callerResult ? `- Diagnostic Note: ${callerResult}` : undefined,
					"",
					`Ready for caller execution. Run \`${step.tool}\` with the corrected parameters, then call 'record' with the result.`,
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "recover",
						workflow,
						step,
						recovery_plan: plan,
						metrics,
						resume: resumeMeta,
					},
				};
			}

			case "retry_plan": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'retry_plan' action.");

				const stepId = params.step_id;
				if (!stepId) throw new ToolError("step_id is required for 'retry_plan' action.");

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const step = workflow.steps.find(s => s.id === stepId);
				if (!step) throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);

				const maxAttempts =
					typeof params.max_attempts === "number" && params.max_attempts > 0
						? Math.min(params.max_attempts, HARD_MAX_ATTEMPTS)
						: step.max_attempts || DEFAULT_MAX_ATTEMPTS;

				const rawError =
					params.error ?? params.failure_reason ?? step.error ?? "Step execution failed without explicit error";

				const plan = generateRecoveryPlan(step, workflow, {
					error: rawError,
					fallbackToolOverride: params.fallback_tool,
					nextParamsOverride: params.next_params,
					maxAttempts,
					capabilityId: params.capability_id,
					installedTool: params.installed_tool,
					setupCommand: params.setup_command,
					verified: params.verified,
					strategy: params.strategy ?? params.resume_strategy,
				});

				const nextParamsStr =
					typeof plan.next_params === "string" ? plan.next_params : JSON.stringify(plan.next_params);

				const text = [
					`Recovery Plan for step \`${step.id}\` in workflow \`${workflow.id}\`:`,
					`- Current Tool: \`${step.tool}\` (Status: ${step.status}, Attempts: ${step.attempts}/${maxAttempts})`,
					`- Failure Attribution: **[${plan.attribution.category.toUpperCase()}]** ${plan.attribution.cause}`,
					plan.attribution.install_hint ? `- Install Hint: \`${plan.attribution.install_hint}\`` : undefined,
					plan.attribution.setup_command ? `- Setup Command: \`${plan.attribution.setup_command}\`` : undefined,
					`- Proposed Action: **${plan.suggested_action}**`,
					plan.capability_depth ? `- Capability Depth: **${plan.capability_depth.toUpperCase()}**` : undefined,
					plan.verification_boundary ? `- Verification Boundary: ${plan.verification_boundary}` : undefined,
					plan.remaining_acceptance ? `- Remaining Acceptance: ${plan.remaining_acceptance}` : undefined,
					plan.prerequisites && plan.prerequisites.length > 0
						? `- Prerequisites: ${plan.prerequisites.map(p => `\`${p}\``).join(", ")}`
						: undefined,
					plan.discovery_guidance?.notice ? `- Discovery Guidance: ${plan.discovery_guidance.notice}` : undefined,
					`- Proposed Tool: \`${plan.next_tool}\``,
					`- Corrected Parameters: \`${nextParamsStr}\``,
					`- Alternatives: ${plan.alternatives.map(a => `\`${a}\``).join(", ")}`,
					`- Reasoning: ${plan.reasoning}`,
					plan.resume
						? `- Install-After Resume Preview: Tool \`${plan.resume.installed_tool}\` (Capability: \`${plan.resume.capability_id || "none"}\`, Strategy: \`${plan.resume.strategy}\`, Verified: ${plan.resume.verified})`
						: undefined,
					`- Bounded Recovery Status: ${plan.can_retry ? "Retry permitted" : "Exhausted"}`,
					"",
					plan.can_retry
						? `To apply this recovery and transition step to pending, call 'reverse_workflow(action: "recover", workflow_id: "${workflow.id}", step_id: "${step.id}")'.`
						: "Retry limit reached. No further automated retries permitted for this step.",
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "retry_plan",
						workflow,
						step,
						recovery_plan: plan,
						resume: plan.resume,
					},
				};
			}

			case "export": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'export' action.");

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const formatType = params.format_type ?? "markdown";
				const content =
					formatType === "json"
						? await exportWorkflowToJson(workflow, evidenceStore)
						: await exportWorkflowToMarkdown(workflow, evidenceStore);
				if (params.to_workspace === true || params.workspace_path) {
					const projectDir = repoRoot;
					const wsResult = await exportWorkflowToWorkspace({
						workflow,
						evidenceStore,
						projectDir,
						workspaceDir: params.workspace_path,
						formatType,
						clean: params.clean_workspace ?? false,
					});

					const summaryLines = [
						`# Standardized Reverse Workspace Exported: \`${wsResult.relative_workspace_dir}\``,
						"",
						`- **Target**: \`${wsResult.target_info.name}\` (\`${wsResult.target_info.format}\`) — Safe reference preserved (never mutated)`,
						`- **Manifest**: \`${wsResult.relative_workspace_dir}/manifest.json\``,
						`- **Layout**: \`manifest\`, \`target\`, \`workflow\`, \`evidence\`, \`findings\`, \`scripts\`, \`dumps\`, \`reports\``,
						`- **Created Files**: ${wsResult.created_files.length}`,
						`- **Execution Progress**: ${wsResult.stats.steps_completed}/${wsResult.stats.steps_total} steps completed`,
						`- **Evidence Ledger**: ${wsResult.stats.evidence_total} items (${wsResult.stats.facts_count} facts, ${wsResult.stats.conclusions_count} verified conclusions)`,
						`- **Artifacts**: ${wsResult.manifest.artifacts.length} total (${wsResult.stats.scripts_count} scripts copied, ${wsResult.stats.dumps_count} dumps copied, ${wsResult.manifest.artifacts.filter(a => !a.copied).length} safe references)`,
					];

					return {
						content: [{ type: "text", text: summaryLines.join("\n") }],
						details: {
							action: "export",
							workflow,
							export_format: formatType,
							workspace_dir: wsResult.workspace_dir,
							workspace_manifest: wsResult.manifest,
							workspace_files_count: wsResult.created_files.length,
						},
					};
				}

				const mustArtifact = params.to_artifact === true || content.length > MAX_INLINE_CHARS;
				if (mustArtifact && this.session.allocateOutputArtifact) {
					try {
						const alloc = await this.session.allocateOutputArtifact("reverse_workflow");
						if (alloc?.path && alloc.id) {
							await fs.writeFile(alloc.path, content, "utf8");
							const preview = content.slice(0, 1200);
							const text = `Exported workflow artifact (${Buffer.byteLength(content)} bytes): artifact://${alloc.id}\n\nPreview:\n${preview}...\n\n(Read full report with 'read artifact://${alloc.id}')`;
							return {
								content: [{ type: "text", text }],
								details: {
									action: "export",
									workflow,
									export_format: formatType,
									artifactId: alloc.id,
									artifactPath: alloc.path,
								},
							};
						}
					} catch {
						// Fall back to inline output on artifact error
					}
				}

				return {
					content: [{ type: "text", text: content }],
					details: {
						action: "export",
						workflow,
						export_format: formatType,
					},
				};
			}

			case "destroy": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError("workflow_id is required for 'destroy' action.");

				const deleted = await store.delete(workflowId);
				if (!deleted) {
					throw new ToolError(`Workflow '${workflowId}' not found.`);
				}

				return {
					content: [{ type: "text", text: `Destroyed workflow \`${workflowId}\` and removed its state.` }],
					details: { action: "destroy", destroyed: true },
				};
			}
			case "advance":
			case "auto_advance": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) throw new ToolError(`workflow_id is required for '${params.action}' action.`);

				const workflow = await store.get(workflowId);
				if (!workflow) throw new ToolError(`Workflow '${workflowId}' not found.`);

				const progressionResult = await advanceWorkflow(
					workflow,
					{
						step_id: params.step_id,
						max_steps: params.max_steps,
						status: params.status,
						outputs: params.outputs,
						evidence_ids: params.evidence_ids,
						knowledge_refs: params.knowledge_refs,
						artifact_refs: params.artifact_refs,
						propose_only: params.propose_only,
					},
					{
						repositoryRoot: repoRoot,
						knowledgeStore,
						evidenceStore,
					},
				);

				await store.save(workflow);

				const lines: string[] = [
					`Workflow Auto Progression: \`${workflow.id}\``,
					`- **Target**: \`${workflow.target}\` (${workflow.format})`,
					`- **Progression Status**: \`${progressionResult.status.toUpperCase()}\``,
					`- **Decision**: ${progressionResult.decision}`,
					`- **Reason**: ${progressionResult.reason}`,
				];

				if (progressionResult.pending_decision_step) {
					const step = progressionResult.pending_decision_step;
					lines.push("");
					lines.push(
						`**Notice: Step \`${step.id}\` requires dynamic or high-risk tool \`${step.tool}\`.** Auto progression halts here; please inspect and run this step manually via the tool, then call \`reverse_workflow(action: "record", step_id: "${step.id}", ...)\`.`,
					);
				} else if (progressionResult.evaluated_steps.length > 0) {
					const proposed = progressionResult.evaluated_steps[0];
					lines.push("");
					lines.push(`Proposed Next Step: \`${proposed.id}\` via \`${proposed.tool}\` (${proposed.gate})`);
					lines.push(`- **Title**: ${proposed.title}`);
					const paramsStr =
						typeof proposed.params_summary === "string"
							? proposed.params_summary
							: JSON.stringify(proposed.params_summary);
					lines.push(`- **Suggested Parameters**: \`${paramsStr}\``);
				}

				if (progressionResult.knowledge_refs.length > 0) {
					lines.push("");
					lines.push(
						`- **Associated Prior Knowledge**: ${progressionResult.knowledge_refs.map(id => `\`${id}\``).join(", ")}`,
					);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: params.action,
						workflow,
						advanced: progressionResult.advanced,
						step: progressionResult.evaluated_steps[0] ?? progressionResult.pending_decision_step,
						evaluated_steps: progressionResult.evaluated_steps,
						progression_status: progressionResult.status,
						decision: progressionResult.decision,
						decision_reason: progressionResult.reason,
						progression_audit: progressionResult.audit_entries,
						knowledge_refs: progressionResult.knowledge_refs,
					},
				};
			}

			case "register_derivative": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'register_derivative' action.");
				}

				const targetFile = params.target ?? params.path ?? params.derivative_path;
				if (!targetFile) {
					throw new ToolError("Derivative target file path ('target', 'path', or 'derivative_path') is required.");
				}

				let parsedPatches: RegisterDerivativeOptions["patches"];
				if (params.patches) {
					if (typeof params.patches === "string") {
						try {
							parsedPatches = JSON.parse(params.patches);
						} catch (e) {
							throw new ToolError(
								`Failed to parse 'patches' parameter as JSON: ${e instanceof Error ? e.message : String(e)}`,
							);
						}
					} else if (Array.isArray(params.patches)) {
						parsedPatches = params.patches as RegisterDerivativeOptions["patches"];
					} else {
						throw new ToolError("'patches' must be an array of patch definitions.");
					}
				}

				let parsedRetiredPatches: RegisterDerivativeOptions["retired_patches"];
				if (params.retired_patches) {
					if (typeof params.retired_patches === "string") {
						try {
							parsedRetiredPatches = JSON.parse(params.retired_patches);
						} catch (e) {
							throw new ToolError(
								`Failed to parse 'retired_patches' parameter as JSON: ${e instanceof Error ? e.message : String(e)}`,
							);
						}
					} else if (Array.isArray(params.retired_patches)) {
						parsedRetiredPatches = params.retired_patches as RegisterDerivativeOptions["retired_patches"];
					} else {
						throw new ToolError("'retired_patches' must be an array of { patch_id, reason } objects.");
					}
				}

				const signatureOption =
					params.signature_status || params.signature_fingerprint || params.signature_scheme
						? {
								status: params.signature_status,
								fingerprint: params.signature_fingerprint,
								scheme: params.signature_scheme,
							}
						: undefined;

				const derivative = await store.registerDerivative(workflowId, {
					build_id: params.build_id,
					target_path: targetFile,
					output_sha256: params.output_sha256,
					original_sha256: params.original_sha256,
					parent_sha256: params.parent_sha256,
					parent_build_id: params.parent_build_id,
					target_version: params.target_version,
					abi: params.abi,
					architecture: params.architecture,
					patches: parsedPatches,
					retired_patches: parsedRetiredPatches,
					signature: signatureOption,
					runtime_evidence_ids: params.runtime_evidence_ids,
					verification_conditions: params.verification_conditions as Record<string, unknown> | undefined,
					target_device_constraints: params.target_device_constraints as TargetDeviceConstraints | undefined,
					scope: params.scope,
					delivery_mode: params.delivery_mode,
					dependencies: params.dependencies as WorkflowDependencyRecord[] | undefined,
				});

				const activeCount = derivative.cumulative_patches.filter(p => p.status === "active").length;
				const retiredCount = derivative.cumulative_patches.filter(p => p.status === "retired").length;

				const lines = [
					`Registered Derivative: \`${derivative.build_id}\` for workflow \`${workflowId}\``,
					`- **Target Path**: \`${derivative.target_path}\``,
					`- **Output SHA-256**: \`${derivative.output_sha256}\``,
					`- **Original SHA-256**: \`${derivative.original_sha256}\``,
					`- **Parent SHA-256**: \`${derivative.parent_sha256}\`${derivative.parent_build_id ? ` (Parent Build: \`${derivative.parent_build_id}\`)` : ""}`,
					`- **Static Verification**: **${derivative.verification_result.static_status.toUpperCase()}** (${activeCount} active patches verified in container/binary${retiredCount > 0 ? `, ${retiredCount} retired` : ""})`,
					`- **Runtime Status**: **${derivative.verification_result.runtime_status.toUpperCase()}**${derivative.runtime_evidence_ids?.length ? ` (Bound Evidence: ${derivative.runtime_evidence_ids.join(", ")})` : " (Pending direct execution proof on this output hash)"}`,
					`- **Signature**: ${derivative.signature.status}${derivative.signature.fingerprint ? ` (${derivative.signature.fingerprint.slice(0, 16)}...)` : ""}`,
					"",
					"Cumulative Patches:",
					...derivative.cumulative_patches.map(p => {
						const loc = p.member_path
							? `\`${p.member_path}\`+0x${p.offset.toString(16)}`
							: `offset 0x${p.offset.toString(16)}`;
						const statusStr =
							p.status === "active" ? "[ACTIVE]" : `[RETIRED: ${p.retirement_reason ?? "reason not recorded"}]`;
						return `  - ${statusStr} \`${p.patch_id}\` (${loc}): expected \`${p.expected_bytes}\``;
					}),
					"",
					`Current verified baseline updated to \`${derivative.build_id}\`.`,
				];

				const updatedWorkflow = await store.get(workflowId);

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "register_derivative",
						workflow: updatedWorkflow ?? undefined,
						derivative,
						baseline: derivative,
						verification_result: derivative.verification_result,
					},
				};
			}

			case "verify_lineage": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'verify_lineage' action.");
				}

				const targetFile = params.target ?? params.path ?? params.derivative_path;
				const verificationResult = await store.verifyDerivative(workflowId, params.build_id, targetFile);

				const workflow = await store.get(workflowId);
				const derivative = params.build_id
					? workflow?.build_lineage?.find(b => b.build_id === params.build_id)
					: workflow?.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id);

				const lines = [
					`Lineage Verification Result for Workflow \`${workflowId}\`${params.build_id ? ` (Build: \`${params.build_id}\`)` : ""}`,
					`- **Overall Status**: **${verificationResult.status.toUpperCase()}**`,
					`- **Static Status**: ${verificationResult.static_status.toUpperCase()} (${verificationResult.checked_patches_count} active patches checked)`,
					`- **Runtime Status**: ${verificationResult.runtime_status.toUpperCase()}`,
				];

				if (verificationResult.failure_reason) {
					lines.push(`- **Failure Reason**: ${verificationResult.failure_reason}`);
				}
				if (verificationResult.failed_patch_id) {
					lines.push(`- **Failed Patch**: \`${verificationResult.failed_patch_id}\``);
				}
				if (verificationResult.verified_at) {
					lines.push(`- **Verified At**: ${verificationResult.verified_at}`);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "verify_lineage",
						workflow: workflow ?? undefined,
						derivative,
						verification_result: verificationResult,
					},
				};
			}

			case "retire_patch": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'retire_patch' action.");
				}

				const patchId = params.patch_id;
				if (!patchId) {
					throw new ToolError("patch_id is required for 'retire_patch' action.");
				}

				const reason = params.reason ?? params.failure_reason ?? params.error;
				if (!reason || reason.trim().length === 0) {
					throw new ToolError("reason is required for 'retire_patch' action.");
				}

				const audit = await store.retirePatch(workflowId, patchId, reason, params.build_id);
				const workflow = await store.get(workflowId);

				const text = [
					`Explicit Patch Retirement Recorded for Workflow \`${workflowId}\``,
					`- **Patch ID**: \`${audit.patch_id}\``,
					`- **Retirement Reason**: ${audit.reason}`,
					`- **Timestamp**: ${audit.retired_at}`,
					audit.build_id ? `- **Target Build ID**: \`${audit.build_id}\`` : undefined,
					"",
					"This patch will be recognized as explicitly retired in subsequent derivative registrations and will not cause missing-patch verification failure.",
				]
					.filter(Boolean)
					.join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "retire_patch",
						workflow: workflow ?? undefined,
						retirement_audit: audit,
					},
				};
			}
			case "waive_acceptance": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'waive_acceptance' action.");
				}
				const criterionId = params.criterion_id;
				if (!criterionId) {
					throw new ToolError("criterion_id is required for 'waive_acceptance' action.");
				}
				const reason = params.reason ?? params.failure_reason ?? params.error;
				if (!reason || reason.trim().length === 0) {
					throw new ToolError("reason is mandatory for 'waive_acceptance' action.");
				}

				const workflow = await store.get(workflowId);
				if (!workflow) {
					throw new ToolError(`Workflow '${workflowId}' not found.`);
				}

				const criteria = getWorkflowAcceptanceCriteria(workflow);
				const targetCriterion = criteria.find(c => c.id === criterionId);
				if (!targetCriterion) {
					throw new ToolError(`Acceptance criterion '${criterionId}' not found in workflow '${workflowId}'.`);
				}

				// Enforce interactive confirmation via session UI
				const toolContext = this.session.getToolContext?.();
				let approved = false;

				if (toolContext?.ui && toolContext.hasUI !== false) {
					approved = await toolContext.ui.confirm(
						"Approve Acceptance Criterion Waiver?",
						`Workflow: ${workflowId}\nCriterion: ${targetCriterion.id} (${targetCriterion.title})\nSubject: ${targetCriterion.subject}\nReason: ${reason}\n\nExplicitly waiving this requirement will allow the workflow to complete without satisfying this acceptance criterion.`,
					);
				} else {
					throw new ToolError(
						`Acceptance criterion waiver requires explicit interactive user confirmation via session UI. Non-interactive waiver of criterion '${criterionId}' is prohibited. Please confirm interactively or create a new workflow revision with a linked revision ID.`,
					);
				}

				if (!approved) {
					throw new ToolError(`User denied waiver for acceptance criterion '${criterionId}'.`);
				}

				const now = new Date().toISOString();
				targetCriterion.status = "waived";
				targetCriterion.waiver_reason = reason;
				targetCriterion.waiver_timestamp = now;
				targetCriterion.waived_by_decision = "user_interactive_approval";
				targetCriterion.updated_at = now;

				updateAcceptanceCriterion(workflow, targetCriterion);
				workflow.updated_at = now;
				await store.save(workflow);

				const text = [
					`# Explicit Acceptance Criterion Waiver Approved`,
					`- **Workflow**: \`${workflowId}\``,
					`- **Criterion ID**: \`${targetCriterion.id}\``,
					`- **Title**: ${targetCriterion.title}`,
					`- **Subject**: \`${targetCriterion.subject}\``,
					`- **Waiver Reason**: ${reason}`,
					`- **Approved Decision**: \`user_interactive_approval\``,
					`- **Timestamp**: ${now}`,
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "waive_acceptance",
						workflow,
						criterion: targetCriterion,
						waiver_approved: true,
					},
				};
			}

			case "approve_dependency": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'approve_dependency' action.");
				}
				const dependencyId = params.dependency_id;
				if (!dependencyId) {
					throw new ToolError("dependency_id is required for 'approve_dependency' action.");
				}
				const reason = params.reason ?? params.failure_reason ?? params.error;
				if (!reason || reason.trim().length === 0) {
					throw new ToolError("reason is mandatory for 'approve_dependency' action.");
				}

				const workflow = await store.get(workflowId);
				if (!workflow) {
					throw new ToolError(`Workflow '${workflowId}' not found.`);
				}

				const dependencies: WorkflowDependencyRecord[] =
					(workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined) ?? [];
				const targetDep = dependencies.find(d => d.id === dependencyId);
				if (!targetDep) {
					throw new ToolError(`Dependency '${dependencyId}' not found in workflow '${workflowId}'.`);
				}

				// Enforce interactive confirmation via session UI
				const toolContext = this.session.getToolContext?.();
				let approved = false;

				if (toolContext?.ui && toolContext.hasUI !== false) {
					approved = await toolContext.ui.confirm(
						"Approve Dependency for Delivery?",
						`Workflow: ${workflowId}\nDependency: ${targetDep.id} (${targetDep.name})\nKind: ${targetDep.kind}\nTarget Host: ${targetDep.target_host ?? "target_device"}\nReason: ${reason}\n\nApproving this dependency will authorize delivery builds and packages to require or include this dependency.`,
					);
				} else {
					throw new ToolError(
						`Delivery dependency approval requires explicit interactive user confirmation via session UI. Non-interactive approval of dependency '${dependencyId}' is prohibited.`,
					);
				}

				if (!approved) {
					throw new ToolError(`User denied delivery approval for dependency '${dependencyId}'.`);
				}

				const now = new Date().toISOString();
				targetDep.approved_for_delivery = true;
				targetDep.approval_notes = reason;
				targetDep.approved_at = now;
				targetDep.decision_id = "user_interactive_approval";

				const depIdx = dependencies.findIndex(d => d.id === dependencyId);
				if (depIdx >= 0) {
					dependencies[depIdx] = targetDep;
				} else {
					dependencies.push(targetDep);
				}
				if (!workflow.metadata) workflow.metadata = {};
				workflow.metadata.dependencies = dependencies;

				workflow.updated_at = now;
				await store.save(workflow);

				const text = [
					`# Delivery Dependency Approval Granted`,
					`- **Workflow**: \`${workflowId}\``,
					`- **Dependency ID**: \`${targetDep.id}\``,
					`- **Name**: ${targetDep.name}`,
					`- **Kind**: \`${targetDep.kind}\``,
					`- **Scope**: \`delivery\``,
					`- **Approval Reason**: ${reason}`,
					`- **Approved Decision**: \`user_interactive_approval\``,
					`- **Timestamp**: ${now}`,
				].join("\n");

				return {
					content: [{ type: "text", text }],
					details: {
						action: "approve_dependency",
						workflow,
						dependency: targetDep,
						dependency_approved: true,
					},
				};
			}

			default:
				throw new ToolError(`Unknown reverse_workflow action: '${String(params.action)}'`);
		}
	}
}
