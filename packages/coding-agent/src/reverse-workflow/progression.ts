import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import type { ReverseKnowledgeStore } from "../reverse-knowledge/store";
import type { EvidenceStore } from "../evidence/store";
import type { EvidenceRecord } from "../evidence/contracts";
import { evaluateEvidenceSupport } from "../evidence/validity";
import {
	cascadeEvidenceRefutation,
	getWorkflowAcceptanceCriteria,
	evaluateAcceptanceSatisfaction,
	validateDeploymentConstraints,
	updateAcceptanceCriterion,
} from "./acceptance";
import { isDynamicLocator } from "../reverse-runtime-session/dynamic-events";
import {
	type ReverseWorkflowRecord,
	type WorkflowStepRecord,
	type ProgressionAuditEntry,
	type ProgressionStatus,
	type TargetDeviceConstraints,
	type WorkflowDependencyRecord,
	validateEvidenceIdFormat,
	validateKnowledgeIdFormat,
} from "./contracts";
import { verifyInstalledTool } from "./recovery";
import { SKILL_TOOL_CATALOG } from "../extensibility/skill-tool-catalog";
import { getMcpService } from "../extensibility/mcp-service-catalog";

/**
 * Allowlisted read-only static analysis and triage tools permitted for auto-progression.
 */
export const ALLOWLISTED_LOW_RISK_TOOLS: readonly string[] = [
	"triage",
	"binary_metadata_inspect",
	"sourcemap_inspect",
	"android_package_inspect",
	"pcap_inspect",
	"sqlite_inspect",
	"wasm_inspect",
	"grep",
	"evidence",
	"reverse_dynamic_evidence",
];

/**
 * High-risk, dynamic, interactive, or modifying tools strictly prohibited from silent auto-execution.
 */
export const HIGH_RISK_OR_DYNAMIC_TOOLS: readonly string[] = [
	"shell",
	"bash",
	"exec",
	"frida",
	"reverse_runtime_session",
	"patch",
	"replay",
	"droidasc",
	"r2_inspect",
	"ghidra_inspect",
	"unidbg",
];

export interface StepRiskAssessment {
	is_low_risk: boolean;
	tool: string;
	gate: string;
	risk_level: "low" | "high" | "dynamic";
	reason: string;
}
function extractStepAction(step: WorkflowStepRecord): string {
	if (typeof step.params_summary === "object" && step.params_summary !== null) {
		return String((step.params_summary as Record<string, unknown>).action ?? "")
			.toLowerCase()
			.trim();
	}
	if (typeof step.params_summary === "string") {
		try {
			const parsed = JSON.parse(step.params_summary);
			if (typeof parsed === "object" && parsed !== null && "action" in parsed) {
				return String(parsed.action ?? "")
					.toLowerCase()
					.trim();
			}
		} catch {
			// non-JSON string
		}
	}
	return "";
}

export function assessStepRisk(step: WorkflowStepRecord): StepRiskAssessment {
	const tool = (step.tool ?? "").trim().toLowerCase();

	if (tool === "elf_inspect") {
		const action = extractStepAction(step);
		if (action === "query" || action === "status") {
			return {
				is_low_risk: true,
				tool: step.tool,
				gate: step.gate,
				risk_level: "low",
				reason: `Tool 'elf_inspect' (action: '${action}') is an allowlisted read-only static ELF triage/inspection tool (${step.gate}).`,
			};
		}
		return {
			is_low_risk: false,
			tool: step.tool,
			gate: step.gate,
			risk_level: "dynamic",
			reason: `Tool 'elf_inspect' with action '${action || "unknown"}' requires explicit execution authorization. Auto progression halted; step remains pending manual decision.`,
		};
	}
	// 动作级别细粒度风险判定：防止仅凭工具名匹配白名单导致具有写操作或环境副作用的动作
	// （如 android_native_workflow 的 extract 解压写文件、reverse_capability 的 install 安装/配置服务）
	// 被误判为 low-risk 而在 auto-progression 中被静默自动执行。只有明确列入白名单的只读动作才允许通过。
	if (tool === "android_native_workflow") {
		const action = extractStepAction(step);
		if (action === "inspect" || action === "plan" || action === "status") {
			return {
				is_low_risk: true,
				tool: step.tool,
				gate: step.gate,
				risk_level: "low",
				reason: `Tool 'android_native_workflow' (action: '${action}') is an allowlisted read-only static Android inspection tool (${step.gate}).`,
			};
		}
		return {
			is_low_risk: false,
			tool: step.tool,
			gate: step.gate,
			risk_level: "high",
			reason: `Tool 'android_native_workflow' with action '${action || "unknown"}' requires explicit execution authorization. Auto progression halted; step remains pending manual decision.`,
		};
	}

	if (tool === "reverse_capability") {
		const action = extractStepAction(step);
		if (action === "list" || action === "resolve" || action === "status" || action === "get") {
			return {
				is_low_risk: true,
				tool: step.tool,
				gate: step.gate,
				risk_level: "low",
				reason: `Tool 'reverse_capability' (action: '${action}') is an allowlisted read-only capability query tool (${step.gate}).`,
			};
		}
		return {
			is_low_risk: false,
			tool: step.tool,
			gate: step.gate,
			risk_level: "high",
			reason: `Tool 'reverse_capability' with action '${action || "unknown"}' requires explicit execution authorization. Auto progression halted; step remains pending manual decision.`,
		};
	}
	// Protection analysis tools: dex_unpack, dex_repair, instruction_trace, dex_search, deobfuscate, native_recover, triton_analyze
	// Only "status" read action is permitted for auto-progression. Any write, execution, dynamic tracing, or heavy analysis action
	// is classified as high-risk or dynamic, halting auto-progression for explicit operator decision.
	if (
		tool === "dex_unpack" ||
		tool === "dex_repair" ||
		tool === "instruction_trace" ||
		tool === "dex_search" ||
		tool === "deobfuscate" ||
		tool === "native_recover" ||
		tool === "triton_analyze"
	) {
		const action = extractStepAction(step);
		if (action === "status") {
			return {
				is_low_risk: true,
				tool: step.tool,
				gate: step.gate,
				risk_level: "low",
				reason: `Tool '${step.tool}' (action: 'status') is an allowlisted read-only status check (${step.gate}).`,
			};
		}
		const isDynamic = tool === "instruction_trace" || tool === "dex_unpack" || tool === "native_recover";
		return {
			is_low_risk: false,
			tool: step.tool,
			gate: step.gate,
			risk_level: isDynamic ? "dynamic" : "high",
			reason: `Tool '${step.tool}' with action '${action || "execute"}' is a ${isDynamic ? "dynamic runtime" : "high-risk analysis/write"} operation. Auto progression halted; step remains pending manual decision.`,
		};
	}

	// Check explicitly prohibited / high-risk / dynamic tools
	for (const dynamicTool of HIGH_RISK_OR_DYNAMIC_TOOLS) {
		if (tool === dynamicTool || tool.startsWith(`${dynamicTool}_`) || tool.includes(dynamicTool)) {
			const isDynamic =
				dynamicTool === "frida" ||
				dynamicTool === "reverse_runtime_session" ||
				dynamicTool === "replay" ||
				dynamicTool === "unidbg";
			return {
				is_low_risk: false,
				tool: step.tool,
				gate: step.gate,
				risk_level: isDynamic ? "dynamic" : "high",
				reason: `Tool '${step.tool}' is a ${isDynamic ? "dynamic runtime" : "high-risk/deep disassembly"} operation. Auto progression halted; step remains pending manual decision.`,
			};
		}
	}

	// Check allowlisted low-risk static tools
	const isAllowlisted = ALLOWLISTED_LOW_RISK_TOOLS.some(
		allowed => tool === allowed || tool.endsWith(`_${allowed}`) || tool.includes(allowed),
	);

	if (isAllowlisted) {
		return {
			is_low_risk: true,
			tool: step.tool,
			gate: step.gate,
			risk_level: "low",
			reason: `Tool '${step.tool}' is an allowlisted read-only static triage/inspection tool (${step.gate}).`,
		};
	}

	return {
		is_low_risk: false,
		tool: step.tool,
		gate: step.gate,
		risk_level: "high",
		reason: `Tool '${step.tool}' is not in the allowlisted low-risk static tools (${ALLOWLISTED_LOW_RISK_TOOLS.join(", ")}). Requires explicit execution decision.`,
	};
}

export interface AutoAdvanceOptions {
	step_id?: string;
	max_steps?: number;
	status?: "completed" | "failed" | "running" | "skipped";
	outputs?: string;
	evidence_ids?: string[];
	knowledge_refs?: string[];
	artifact_refs?: string[];
	propose_only?: boolean;
}

export interface AutoAdvanceContext {
	repositoryRoot: string;
	knowledgeStore?: ReverseKnowledgeStore;
	evidenceStore?: EvidenceStore;
}

export interface AutoAdvanceResult {
	advanced: boolean;
	status: ProgressionStatus;
	decision: string;
	reason: string;
	evaluated_steps: WorkflowStepRecord[];
	pending_decision_step?: WorkflowStepRecord;
	audit_entries: ProgressionAuditEntry[];
	knowledge_refs: string[];
	workflow: ReverseWorkflowRecord;
}

/**
 * Deterministically evaluate and advance reverse engineering workflow steps.
 * Enforces strict verification guardrails:
 * 1. Only proposes or records allowlisted read/static tools.
 * 2. Halts on dynamic, high-risk, shell, frida, patch, replay steps and marks them held pending decision.
 * 3. Halts on ambiguous target files or missing dependencies.
 * 4. Bounded progression (max 5 steps).
 * 5. Never executes shell commands or dynamic processes silently.
 */
export async function advanceWorkflow(
	workflow: ReverseWorkflowRecord,
	options: AutoAdvanceOptions = {},
	context: AutoAdvanceContext,
): Promise<AutoAdvanceResult> {
	const now = new Date().toISOString();
	const auditEntries: ProgressionAuditEntry[] = [];
	const evaluatedSteps: WorkflowStepRecord[] = [];
	const allKnowledgeRefs = new Set<string>(workflow.knowledge_refs ?? []);
	if (context.evidenceStore) {
		await cascadeEvidenceRefutation(workflow, context.evidenceStore).catch(() => undefined);
	}

	// 1. Guardrail: Validate target ambiguity and accessibility
	const targetPath = workflow.target_abs_path ?? path.resolve(context.repositoryRoot, workflow.target);
	let targetAccessible = false;
	try {
		const stat = await fs.stat(targetPath);
		if (stat.isFile() || stat.isDirectory()) {
			targetAccessible = true;
		}
	} catch {
		targetAccessible = false;
	}

	if (!targetAccessible && !options.step_id) {
		const decision = "stopped_ambiguous_target";
		const reason = `Target '${workflow.target}' cannot be accessed or resolved on disk at '${targetPath}'. Auto progression halted.`;
		const audit: ProgressionAuditEntry = {
			step_id: workflow.steps[0]?.id ?? "g0_init",
			step_title: "Target Resolution",
			tool: "triage",
			gate: "G0",
			action: "advance",
			status: "stopped_ambiguous_target",
			decision,
			reason,
			is_low_risk: false,
			timestamp: now,
		};
		workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
		return {
			advanced: false,
			status: "stopped_ambiguous_target",
			decision,
			reason,
			evaluated_steps: [],
			audit_entries: [audit],
			knowledge_refs: Array.from(allKnowledgeRefs),
			workflow,
		};
	}

	if (workflow.format === "unknown" && !options.step_id) {
		const decision = "stopped_ambiguous_target";
		const reason = `Target format is unknown or ambiguous; requires manual triage before auto progression can proceed safely.`;
		const audit: ProgressionAuditEntry = {
			step_id: workflow.steps[0]?.id ?? "g0_init",
			step_title: "Target Classification",
			tool: "triage",
			gate: "G0",
			action: "advance",
			status: "stopped_ambiguous_target",
			decision,
			reason,
			is_low_risk: false,
			timestamp: now,
		};
		workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
		return {
			advanced: false,
			status: "stopped_ambiguous_target",
			decision,
			reason,
			evaluated_steps: [],
			audit_entries: [audit],
			knowledge_refs: Array.from(allKnowledgeRefs),
			workflow,
		};
	}

	// 2. Single step recording mode (if step_id and status/outputs passed)
	if (options.step_id && options.status) {
		const step = workflow.steps.find(s => s.id === options.step_id);
		if (!step) {
			throw new ToolError(`Step '${options.step_id}' not found in workflow '${workflow.id}'.`);
		}

		const risk = assessStepRisk(step);
		let verifiedByDynamicEvidence = false;
		if (
			!risk.is_low_risk &&
			options.status === "completed" &&
			options.evidence_ids &&
			options.evidence_ids.length > 0 &&
			context.evidenceStore
		) {
			for (const evId of options.evidence_ids) {
				const rec = await context.evidenceStore.getRecord(evId).catch(() => null);
				if (
					rec &&
					((rec.kind === "conclusion" && rec.status === "verified") ||
						(rec.kind === "fact" && isDynamicLocator(rec.locator)))
				) {
					verifiedByDynamicEvidence = true;
					break;
				}
			}
		}

		if (!risk.is_low_risk && !verifiedByDynamicEvidence) {
			const decision = "held_pending_decision";
			const reason = `Cannot auto-record step '${step.id}': ${risk.reason}`;
			step.progression_status = "held_pending_decision";
			step.decision = decision;
			step.decision_reason = reason;

			const audit: ProgressionAuditEntry = {
				step_id: step.id,
				step_title: step.title,
				tool: step.tool,
				gate: step.gate,
				action: "advance",
				status: "held_pending_decision",
				decision,
				reason,
				is_low_risk: false,
				timestamp: now,
				params_summary: step.params_summary,
			};
			workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];

			return {
				advanced: false,
				status: "held_pending_decision",
				decision,
				reason,
				evaluated_steps: [step],
				pending_decision_step: step,
				audit_entries: [audit],
				knowledge_refs: Array.from(allKnowledgeRefs),
				workflow,
			};
		}

		// Validate evidence links if provided
		const fetchedEvidenceRecords: EvidenceRecord[] = [];
		if (options.evidence_ids && options.evidence_ids.length > 0 && context.evidenceStore) {
			for (const evId of options.evidence_ids) {
				if (!validateEvidenceIdFormat(evId)) {
					throw new ToolError(`Invalid evidence ID format: '${evId}'.`);
				}
				const exists = await context.evidenceStore.getRecord(evId);
				if (!exists) {
					throw new ToolError(`Evidence ID '${evId}' not found in project evidence ledger.`);
				}
				fetchedEvidenceRecords.push(exists);
			}

			// Validate evidence support integrity
			const evalResult = await evaluateEvidenceSupport(context.evidenceStore, options.evidence_ids);
			if (evalResult.refutedIds.length > 0) {
				throw new ToolError(
					`Cannot advance step '${step.id}': supporting evidence has been refuted: ${evalResult.refutedIds.join(", ")}`,
				);
			}
			if (evalResult.staleIds.length > 0) {
				throw new ToolError(
					`Cannot advance step '${step.id}': supporting evidence is stale or invalidated: ${evalResult.staleIds.join(", ")}`,
				);
			}
			if (evalResult.failedStageIds.length > 0) {
				throw new ToolError(
					`Cannot advance step '${step.id}': supporting evidence contains failed execution stages: ${evalResult.failedStageIds.join(", ")}`,
				);
			}

			step.evidence_ids = Array.from(new Set([...(step.evidence_ids ?? []), ...options.evidence_ids]));
		}

		// If completing the step, enforce Acceptance Criteria and Delivery Constraints
		if (options.status === "completed") {
			// 1. Acceptance criteria enforcement
			const stepCriteria = getWorkflowAcceptanceCriteria(workflow, step.id);
			if (stepCriteria.length > 0) {
				let allSatisfied = true;
				let proxyDetected = false;
				let proxyReasonMessage: string | undefined;

				for (const criterion of stepCriteria) {
					if (criterion.status === "waived" || criterion.status === "satisfied") continue;

					const satisfaction = await evaluateAcceptanceSatisfaction(
						criterion,
						fetchedEvidenceRecords,
						context.evidenceStore,
					);
					if (satisfaction.isProxy) {
						proxyDetected = true;
						proxyReasonMessage = satisfaction.proxyReason;
						criterion.status = "proxy_verified";
						criterion.is_proxy = true;
						criterion.proxy_for_criterion_id = criterion.id;
						criterion.proxy_evidence_ids = satisfaction.matchingEvidenceIds;
						criterion.updated_at = now;
						updateAcceptanceCriterion(workflow, criterion);
						allSatisfied = false;
					} else if (satisfaction.status === "satisfied") {
						criterion.status = "satisfied";
						criterion.is_proxy = false;
						criterion.proxy_for_criterion_id = undefined;
						criterion.proxy_evidence_ids = undefined;
						criterion.satisfied_by_evidence_ids = satisfaction.matchingEvidenceIds;
						criterion.updated_at = now;
						updateAcceptanceCriterion(workflow, criterion);
					} else {
						allSatisfied = false;
					}
				}

				if (!allSatisfied) {
					const decision = "held_pending_decision";
					const reason = proxyDetected
						? (proxyReasonMessage ??
							`Proxy observation recorded for step '${step.id}', but original acceptance criteria remain pending without explicit user waiver.`)
						: `Step '${step.id}' cannot be completed: required acceptance criteria remain unsatisfied.`;

					step.progression_status = "held_pending_decision";
					step.decision = decision;
					step.decision_reason = reason;
					step.updated_at = now;

					const audit: ProgressionAuditEntry = {
						step_id: step.id,
						step_title: step.title,
						tool: step.tool,
						gate: step.gate,
						action: "advance",
						status: "held_pending_decision",
						decision,
						reason,
						is_low_risk: false,
						timestamp: now,
						params_summary: step.params_summary,
					};
					workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];

					return {
						advanced: false,
						status: "held_pending_decision",
						decision,
						reason,
						evaluated_steps: [step],
						pending_decision_step: step,
						audit_entries: [audit],
						knowledge_refs: Array.from(allKnowledgeRefs),
						workflow,
					};
				}
			}

			// 2. Delivery & Target Device constraints enforcement
			const isDelivery = step.is_delivery_step || step.delivery_scope === "delivery" || step.gate === "G4";
			if (isDelivery) {
				const constraints = workflow.metadata?.target_device_constraints as TargetDeviceConstraints | undefined;
				const dependencies = workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined;
				const constraintCheck = validateDeploymentConstraints(constraints, dependencies, "delivery");
				if (!constraintCheck.valid) {
					const decision = "held_pending_decision";
					const reason = `Delivery step '${step.id}' halted: ${constraintCheck.violation}`;

					step.progression_status = "held_pending_decision";
					step.decision = decision;
					step.decision_reason = reason;
					step.updated_at = now;

					const audit: ProgressionAuditEntry = {
						step_id: step.id,
						step_title: step.title,
						tool: step.tool,
						gate: step.gate,
						action: "advance",
						status: "held_pending_decision",
						decision,
						reason,
						is_low_risk: false,
						timestamp: now,
						params_summary: step.params_summary,
					};
					workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];

					return {
						advanced: false,
						status: "held_pending_decision",
						decision,
						reason,
						evaluated_steps: [step],
						pending_decision_step: step,
						audit_entries: [audit],
						knowledge_refs: Array.from(allKnowledgeRefs),
						workflow,
					};
				}
			}
		}

		if (options.knowledge_refs && options.knowledge_refs.length > 0 && context.knowledgeStore) {
			for (const knId of options.knowledge_refs) {
				if (!validateKnowledgeIdFormat(knId)) throw new ToolError(`Invalid knowledge ID format: '${knId}'.`);
				const exists = await context.knowledgeStore.get(knId);
				if (!exists && !knId.startsWith("kn_rev_seed_"))
					throw new ToolError(`Knowledge ID '${knId}' not found in project reverse knowledge store.`);
				allKnowledgeRefs.add(knId);
			}
			step.knowledge_refs = Array.from(new Set([...(step.knowledge_refs ?? []), ...options.knowledge_refs]));
			workflow.knowledge_refs = Array.from(allKnowledgeRefs);
		}

		if (options.artifact_refs) {
			step.artifact_refs = Array.from(new Set([...(step.artifact_refs ?? []), ...options.artifact_refs]));
		}

		step.status = options.status;
		if (options.outputs !== undefined) {
			step.outputs = options.outputs;
		}
		step.attempts = (step.attempts ?? 0) + 1;
		step.updated_at = now;
		step.progression_status = "recorded";
		step.decision = verifiedByDynamicEvidence
			? `Recorded completion of dynamic step '${step.id}' verified by dynamic evidence`
			: `Recorded completion of low-risk static step '${step.id}'`;
		step.decision_reason = verifiedByDynamicEvidence
			? `Step verified by dynamic session evidence: ${options.evidence_ids?.join(", ")}`
			: risk.reason;

		const audit: ProgressionAuditEntry = {
			step_id: step.id,
			step_title: step.title,
			tool: step.tool,
			gate: step.gate,
			action: "advance",
			status: "recorded",
			decision: step.decision,
			reason: step.decision_reason,
			is_low_risk: true,
			timestamp: now,
			knowledge_refs: step.knowledge_refs,
			params_summary: step.params_summary,
		};
		auditEntries.push(audit);
		workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];

		const allDone = workflow.steps.every(s => s.status === "completed" || s.status === "skipped");
		const allCriteria = getWorkflowAcceptanceCriteria(workflow);
		const unresolvedCriteria = allCriteria.filter(c => c.status !== "satisfied" && c.status !== "waived");
		if (allDone && unresolvedCriteria.length === 0) {
			workflow.status = "completed";
		} else {
			workflow.status = "active";
		}

		if (options.status === "completed") {
			if (!workflow.metadata) workflow.metadata = {};
			const activeProof = (workflow.metadata.active_proof as Record<string, string[]> | undefined) ?? {};
			activeProof[step.id] = options.evidence_ids ?? [];
			workflow.metadata.active_proof = activeProof;
		}
		workflow.updated_at = now;

		return {
			advanced: true,
			status: "recorded",
			decision: step.decision,
			reason: step.decision_reason,
			evaluated_steps: [step],
			audit_entries: auditEntries,
			knowledge_refs: Array.from(allKnowledgeRefs),
			workflow,
		};
	}

	// 3. Auto Progression Mode: Bounded evaluation of next pending steps
	const maxSteps = Math.min(Math.max(options.max_steps ?? 1, 1), 5);
	let stepsEvaluated = 0;
	let terminalStatus: ProgressionStatus = "proposed";
	let terminalDecision = "";
	let terminalReason = "";
	let pendingDecisionStep: WorkflowStepRecord | undefined;

	for (const step of workflow.steps) {
		if (step.status !== "pending") continue;
		if (options.step_id && step.id !== options.step_id) continue;
		if (stepsEvaluated >= maxSteps) break;

		stepsEvaluated++;
		evaluatedSteps.push(step);

		// Assess risk of tool
		// Check delivery step
		const isDelivery = step.is_delivery_step || step.delivery_scope === "delivery" || step.gate === "G4";
		if (isDelivery) {
			terminalStatus = "held_pending_decision";
			terminalDecision = `Held delivery step '${step.id}' pending explicit verification decision`;
			terminalReason = `Delivery step '${step.id}' requires verified delivery build and explicit deployment decision.`;
			pendingDecisionStep = step;

			step.progression_status = "held_pending_decision";
			step.decision = terminalDecision;
			step.decision_reason = terminalReason;
			step.updated_at = now;

			const audit: ProgressionAuditEntry = {
				step_id: step.id,
				step_title: step.title,
				tool: step.tool,
				gate: step.gate,
				action: "auto_advance",
				status: "held_pending_decision",
				decision: terminalDecision,
				reason: terminalReason,
				is_low_risk: false,
				timestamp: now,
				params_summary: step.params_summary,
			};
			auditEntries.push(audit);
			workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
			break;
		}

		// Check acceptance criteria
		const stepCriteria = getWorkflowAcceptanceCriteria(workflow, step.id);
		const pendingCriteria = stepCriteria.filter(c => c.status !== "satisfied" && c.status !== "waived");
		if (pendingCriteria.length > 0 && (step.gate === "G2" || step.gate === "G3" || step.gate === "G4")) {
			terminalStatus = "held_pending_decision";
			terminalDecision = `Held step '${step.id}' pending satisfaction of ${pendingCriteria.length} acceptance criteria`;
			terminalReason = `Step '${step.id}' has required acceptance criteria (${pendingCriteria.map(c => c.id).join(", ")}) that cannot be auto-advanced without explicit verification evidence.`;
			pendingDecisionStep = step;

			step.progression_status = "held_pending_decision";
			step.decision = terminalDecision;
			step.decision_reason = terminalReason;
			step.updated_at = now;

			const audit: ProgressionAuditEntry = {
				step_id: step.id,
				step_title: step.title,
				tool: step.tool,
				gate: step.gate,
				action: "auto_advance",
				status: "held_pending_decision",
				decision: terminalDecision,
				reason: terminalReason,
				is_low_risk: false,
				timestamp: now,
				params_summary: step.params_summary,
			};
			auditEntries.push(audit);
			workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
			break;
		}

		const risk = assessStepRisk(step);

		if (!risk.is_low_risk) {
			// Dynamic / high-risk tool: Halt progression!
			terminalStatus = "held_pending_decision";
			terminalDecision = `Held step '${step.id}' pending explicit decision (${step.tool})`;
			terminalReason = risk.reason;
			pendingDecisionStep = step;

			step.progression_status = "held_pending_decision";
			step.decision = terminalDecision;
			step.decision_reason = terminalReason;
			step.updated_at = now;

			const audit: ProgressionAuditEntry = {
				step_id: step.id,
				step_title: step.title,
				tool: step.tool,
				gate: step.gate,
				action: "auto_advance",
				status: "held_pending_decision",
				decision: terminalDecision,
				reason: terminalReason,
				is_low_risk: false,
				timestamp: now,
				params_summary: step.params_summary,
			};
			auditEntries.push(audit);
			workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
			break; // STOP loop on first dynamic/high-risk step
		}
		// Guardrail: Verify host toolchain availability for catalogued tools
		const normalizedTool = (step.tool ?? "").trim().toLowerCase();
		if (SKILL_TOOL_CATALOG[normalizedTool] || getMcpService(normalizedTool)) {
			const check = verifyInstalledTool(step.tool, { cwd: context.repositoryRoot });
			if (!check.verified) {
				terminalStatus = "stopped_missing_dependency";
				terminalDecision = `Halted progression: required dependency '${step.tool}' is missing on host system`;
				terminalReason =
					check.missing_reason ??
					`Required tool '${step.tool}' is not installed or configured. Run '${check.setup_command ?? `reverse setup reverse ${step.tool}`}' before proceeding.`;
				pendingDecisionStep = step;

				step.progression_status = "stopped_missing_dependency";
				step.decision = terminalDecision;
				step.decision_reason = terminalReason;
				step.updated_at = now;

				const audit: ProgressionAuditEntry = {
					step_id: step.id,
					step_title: step.title,
					tool: step.tool,
					gate: step.gate,
					action: "auto_advance",
					status: "stopped_missing_dependency",
					decision: terminalDecision,
					reason: terminalReason,
					is_low_risk: false,
					timestamp: now,
					params_summary: step.params_summary,
				};
				auditEntries.push(audit);
				workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];
				break; // STOP loop on missing dependency
			}
		}

		// Tool is allowlisted low-risk static: query knowledge references
		const stepKnowledgeRefs: string[] = [];
		if (context.knowledgeStore) {
			try {
				const activePrior = await context.knowledgeStore.search({
					format: workflow.format,
					tool: step.tool,
					target_hash: workflow.target_sha256,
					limit: 3,
				});
				for (const kn of activePrior) {
					stepKnowledgeRefs.push(kn.id);
					allKnowledgeRefs.add(kn.id);
				}
			} catch {
				// Non-fatal if search fails
			}
		}

		if (stepKnowledgeRefs.length > 0) {
			step.knowledge_refs = Array.from(new Set([...(step.knowledge_refs ?? []), ...stepKnowledgeRefs]));
			workflow.knowledge_refs = Array.from(allKnowledgeRefs);
		}

		terminalStatus = "proposed";
		terminalDecision = `Proposed low-risk static step '${step.id}' via tool '${step.tool}'`;
		terminalReason = risk.reason;

		step.progression_status = "proposed";
		step.decision = terminalDecision;
		step.decision_reason = terminalReason;
		step.updated_at = now;

		const audit: ProgressionAuditEntry = {
			step_id: step.id,
			step_title: step.title,
			tool: step.tool,
			gate: step.gate,
			action: "auto_advance",
			status: "proposed",
			decision: terminalDecision,
			reason: terminalReason,
			is_low_risk: true,
			timestamp: now,
			knowledge_refs: stepKnowledgeRefs.length > 0 ? stepKnowledgeRefs : undefined,
			params_summary: step.params_summary,
		};
		auditEntries.push(audit);
		workflow.progression_audit = [...(workflow.progression_audit ?? []), audit];

		// Proposing mode proposes the single next step and pauses for invocation
		break;
	}

	if (stepsEvaluated === 0) {
		const allDone = workflow.steps.every(s => s.status === "completed" || s.status === "skipped");
		const allCriteria = getWorkflowAcceptanceCriteria(workflow);
		const unresolvedCriteria = allCriteria.filter(c => c.status !== "satisfied" && c.status !== "waived");
		if (allDone && unresolvedCriteria.length === 0) {
			terminalStatus = "completed";
			terminalDecision = "All workflow steps and acceptance criteria completed";
			terminalReason = "No pending steps or unresolved acceptance criteria remaining.";
			workflow.status = "completed";
		} else {
			terminalStatus = "held_pending_decision";
			terminalDecision =
				unresolvedCriteria.length > 0
					? `Held workflow completion: ${unresolvedCriteria.length} acceptance criteria remain unresolved`
					: "No pending low-risk steps eligible for progression";
			terminalReason =
				unresolvedCriteria.length > 0
					? `Acceptance criteria (${unresolvedCriteria.map(c => c.id).join(", ")}) must be satisfied with verified evidence or explicitly waived before workflow completion.`
					: "All remaining steps are in non-pending or completed state.";
			workflow.status = "active";
		}
	}

	workflow.updated_at = now;

	return {
		advanced: terminalStatus === "proposed",
		status: terminalStatus,
		decision: terminalDecision,
		reason: terminalReason,
		evaluated_steps: evaluatedSteps,
		pending_decision_step: pendingDecisionStep,
		audit_entries: auditEntries,
		knowledge_refs: Array.from(allKnowledgeRefs),
		workflow,
	};
}
