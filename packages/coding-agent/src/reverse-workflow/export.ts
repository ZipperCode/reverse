import type { EvidenceRecord } from "../evidence/contracts";
import type { EvidenceStore } from "../evidence/store";
import {
	type ReverseWorkflowRecord,
	type WorkflowMetrics,
	type WorkflowStepRecord,
	type AcceptanceCriterion,
	type TargetDeviceConstraints,
	type WorkflowDependencyRecord,
	computeWorkflowMetrics,
	MAX_EXPORT_CHARS,
} from "./contracts";
import { getWorkflowAcceptanceCriteria, cascadeEvidenceRefutation } from "./acceptance";
export interface HydratedEvidenceItem {
	id: string;
	record?: EvidenceRecord;
}

export interface HydratedStepRecord extends WorkflowStepRecord {
	hydrated_evidence?: HydratedEvidenceItem[];
}

export interface HydratedWorkflowRecord extends Omit<ReverseWorkflowRecord, "steps"> {
	steps: HydratedStepRecord[];
	metrics: WorkflowMetrics;
	acceptance_criteria?: AcceptanceCriterion[];
	target_device_constraints?: TargetDeviceConstraints;
	dependencies?: WorkflowDependencyRecord[];
}

export async function hydrateWorkflowEvidence(
	workflow: ReverseWorkflowRecord,
	evidenceStore?: EvidenceStore,
): Promise<HydratedWorkflowRecord> {
	if (evidenceStore) {
		await cascadeEvidenceRefutation(workflow, evidenceStore).catch(() => undefined);
	}
	const metrics = computeWorkflowMetrics(workflow.steps, workflow.metadata);
	const acceptanceCriteria = getWorkflowAcceptanceCriteria(workflow);
	const constraints = workflow.metadata?.target_device_constraints as TargetDeviceConstraints | undefined;
	const dependencies = workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined;
	const steps: HydratedStepRecord[] = [];

	for (const step of workflow.steps) {
		const hydratedStep: HydratedStepRecord = { ...step };
		const combinedEvidenceIds = new Set<string>(step.evidence_ids ?? []);
		if (step.recovery_metadata?.recovery_audit) {
			for (const audit of step.recovery_metadata.recovery_audit) {
				if (Array.isArray(audit.evidence_ids)) {
					for (const evId of audit.evidence_ids) {
						combinedEvidenceIds.add(evId);
					}
				}
			}
		}

		if (evidenceStore && combinedEvidenceIds.size > 0) {
			const hydratedList: HydratedEvidenceItem[] = [];
			for (const evId of combinedEvidenceIds) {
				const record = await evidenceStore.getRecord(evId).catch(() => null);
				hydratedList.push({ id: evId, record: record ?? undefined });
			}
			hydratedStep.hydrated_evidence = hydratedList;
		}
		steps.push(hydratedStep);
	}

	return {
		...workflow,
		steps,
		metrics,
		...(acceptanceCriteria.length > 0 ? { acceptance_criteria: acceptanceCriteria } : {}),
		...(constraints ? { target_device_constraints: constraints } : {}),
		...(dependencies && dependencies.length > 0 ? { dependencies } : {}),
	};
}

export async function exportWorkflowToJson(
	workflow: ReverseWorkflowRecord,
	evidenceStore?: EvidenceStore,
): Promise<string> {
	const hydrated = await hydrateWorkflowEvidence(workflow, evidenceStore);
	const jsonString = JSON.stringify(hydrated, null, 2);
	if (jsonString.length > MAX_EXPORT_CHARS) {
		return jsonString.slice(0, MAX_EXPORT_CHARS) + "\n... [truncated to 32 KiB]";
	}
	return jsonString;
}

export async function exportWorkflowToMarkdown(
	workflow: ReverseWorkflowRecord,
	evidenceStore?: EvidenceStore,
): Promise<string> {
	const hydrated = await hydrateWorkflowEvidence(workflow, evidenceStore);
	const { metrics } = hydrated;

	const lines: string[] = [
		`# Reverse Engineering Workflow: ${workflow.id}`,
		"",
		`- **Target**: \`${workflow.target}\``,
		`- **Format**: \`${workflow.format}\``,
		`- **Status**: \`${workflow.status.toUpperCase()}\``,
		`- **Goal**: ${workflow.goal || "Reverse engineering analysis"}`,
		`- **Created**: ${workflow.created_at}`,
		`- **Updated**: ${workflow.updated_at}`,
		...(workflow.runtime_session_ids?.length
			? [`- **Runtime Sessions**: ${workflow.runtime_session_ids.map(id => `\`${id}\``).join(", ")}`]
			: []),
		...(workflow.knowledge_refs?.length
			? [`- **Knowledge References**: ${workflow.knowledge_refs.map(id => `\`${id}\``).join(", ")}`]
			: []),
		"",
		"## Execution Progress",
		"",
		`| Total Steps | Completed | Failed | Pending | Skipped | Evidence Links |`,
		`| :---: | :---: | :---: | :---: | :---: | :---: |`,
		`| ${metrics.total_steps} | ${metrics.completed_steps} | ${metrics.failed_steps} | ${metrics.pending_steps} | ${metrics.skipped_steps} | ${metrics.total_evidence_links} |`,
		...(metrics.total_acceptance_criteria !== undefined
			? [
					"",
					"### Acceptance Criteria Progress",
					"",
					"| Total Criteria | Satisfied | Waived | Proxy Verified | Pending | Criteria Completion |",
					"| :---: | :---: | :---: | :---: | :---: | :---: |",
					`| ${metrics.total_acceptance_criteria} | ${metrics.satisfied_acceptance_criteria ?? 0} | ${metrics.waived_acceptance_criteria ?? 0} | ${metrics.proxy_verified_acceptance_criteria ?? 0} | ${metrics.pending_acceptance_criteria ?? 0} | ${Math.round((metrics.acceptance_completion_ratio ?? 0) * 100)}% |`,
				]
			: []),
		"",
	];

	const allCriteria = getWorkflowAcceptanceCriteria(workflow);
	if (allCriteria.length > 0) {
		lines.push("## Acceptance Criteria", "");
		lines.push("| ID | Title | Subject | Status | Proxy? | Evidence IDs | Waiver Reason |");
		lines.push("| :--- | :--- | :--- | :---: | :---: | :--- | :--- |");
		for (const c of allCriteria) {
			const badge =
				c.status === "satisfied"
					? "[SATISFIED]"
					: c.status === "waived"
						? "[WAIVED]"
						: c.status === "proxy_verified"
							? "[PROXY_VERIFIED]"
							: "[PENDING]";
			const isProxy = c.is_proxy ? "Yes" : "No";
			const evIds =
				(c.satisfied_by_evidence_ids ?? c.proxy_evidence_ids ?? []).map(id => `\`${id}\``).join(", ") || "none";
			const waiver = c.waiver_reason ? `${c.waiver_reason} (${c.waived_by_decision ?? "approved"})` : "-";
			lines.push(`| \`${c.id}\` | ${c.title} | \`${c.subject}\` | ${badge} | ${isProxy} | ${evIds} | ${waiver} |`);
		}
		lines.push("");
	}

	const constraints = workflow.metadata?.target_device_constraints as TargetDeviceConstraints | undefined;
	const dependencies = workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined;

	if (constraints || (dependencies && dependencies.length > 0)) {
		lines.push("## Target Device Constraints & Dependencies", "");
		if (constraints) {
			lines.push(`- **Target Environment**: \`${constraints.target_environment || "unspecified"}\``);
			lines.push(`- **Requires Standalone**: \`${constraints.requires_standalone ? "YES" : "NO"}\``);
			if (constraints.disallowed_dependencies && constraints.disallowed_dependencies.length > 0) {
				lines.push(
					`- **Disallowed Dependencies**: ${constraints.disallowed_dependencies.map(d => `\`${d}\``).join(", ")}`,
				);
			}
			if (constraints.notes) {
				lines.push(`- **Notes**: ${constraints.notes}`);
			}
		}

		if (dependencies && dependencies.length > 0) {
			lines.push("", "### Declared Dependencies", "");
			lines.push("| ID | Name | Kind | Scope | Target Host | Approved for Delivery | Notes |");
			lines.push("| :--- | :--- | :--- | :---: | :---: | :---: | :--- |");
			for (const dep of dependencies) {
				const app = dep.approved_for_delivery ? "APPROVED" : "NOT APPROVED";
				lines.push(
					`| \`${dep.id}\` | ${dep.name} | \`${dep.kind}\` | \`${dep.scope}\` | \`${dep.target_host ?? "target_device"}\` | ${app} | ${dep.approval_notes || "-"} |`,
				);
			}
		}
		lines.push("");
	}

	lines.push("## Step Execution Plan", "");

	for (const step of hydrated.steps) {
		const statusBadge =
			step.status === "completed"
				? "[COMPLETED]"
				: step.status === "failed"
					? "[FAILED]"
					: step.status === "running"
						? "[RUNNING]"
						: step.status === "skipped"
							? "[SKIPPED]"
							: "[PENDING]";

		lines.push(`### ${statusBadge} ${step.id}: ${step.title}`);
		lines.push(`- **Tool**: \`${step.tool}\` (${step.gate})`);
		lines.push(`- **Status**: ${step.status} (Attempts: ${step.attempts}/${step.max_attempts})`);
		if (step.decision) {
			lines.push(`- **Progression Decision**: \`${step.decision}\``);
		}
		if (step.decision_reason) {
			lines.push(`- **Decision Reason**: ${step.decision_reason}`);
		}
		const paramsStr =
			typeof step.params_summary === "string" ? step.params_summary : JSON.stringify(step.params_summary);
		lines.push(`- **Parameters**: \`${paramsStr}\``);
		const stepCriteria = getWorkflowAcceptanceCriteria(workflow, step.id);
		if (stepCriteria.length > 0) {
			lines.push(
				`- **Step Acceptance Criteria**: ${stepCriteria.map(c => `\`${c.id}\` [${c.status.toUpperCase()}] (Subject: \`${c.subject}\`)`).join(", ")}`,
			);
		}
		if (step.is_delivery_step || step.delivery_scope) {
			lines.push(
				`- **Delivery Scope**: \`${step.delivery_scope ?? (step.is_delivery_step ? "delivery" : "experiment")}\``,
			);
		}

		if (step.outputs) {
			const outputStr = typeof step.outputs === "string" ? step.outputs : JSON.stringify(step.outputs);
			lines.push(`- **Output Summary**: ${outputStr.length > 500 ? outputStr.slice(0, 500) + "..." : outputStr}`);
		}

		if (step.artifact_refs && step.artifact_refs.length > 0) {
			lines.push(`- **Artifacts**: ${step.artifact_refs.map(ref => `\`${ref}\``).join(", ")}`);
		}
		if (step.runtime_session_id) {
			lines.push(`- **Runtime Session**: \`${step.runtime_session_id}\``);
		}
		if (step.runtime_session_ids && step.runtime_session_ids.length > 0) {
			lines.push(`- **Runtime Sessions**: ${step.runtime_session_ids.map(id => `\`${id}\``).join(", ")}`);
		}
		if (step.knowledge_refs && step.knowledge_refs.length > 0) {
			lines.push(`- **Knowledge References**: ${step.knowledge_refs.map(ref => `\`${ref}\``).join(", ")}`);
		}

		if (step.error) {
			lines.push(`- **Error**: ${step.error}`);
		}

		if (step.recovery_metadata) {
			const rec = step.recovery_metadata;
			lines.push("- **Recovery Metadata**:");
			if (rec.attribution) {
				lines.push(`  - Attribution: [${rec.attribution.category.toUpperCase()}] ${rec.attribution.cause}`);
				if (rec.attribution.install_hint) {
					lines.push(`    - Install Hint: \`${rec.attribution.install_hint}\``);
				}
				if (rec.attribution.setup_command) {
					lines.push(`    - Setup Command: \`${rec.attribution.setup_command}\``);
				}
			}
			if (rec.resume) {
				lines.push("  - Install-After Resume Metadata:");
				if (rec.resume.capability_id) lines.push(`    - Capability ID: \`${rec.resume.capability_id}\``);
				lines.push(`    - Installed Tool: \`${rec.resume.installed_tool}\``);
				if (rec.resume.setup_command) lines.push(`    - Setup Command: \`${rec.resume.setup_command}\``);
				lines.push(`    - Verified: ${rec.resume.verified}`);
				lines.push(`    - Strategy: \`${rec.resume.strategy}\``);
				lines.push(`    - Resumed At: ${rec.resume.resumed_at}`);
				if (rec.resume.notes) lines.push(`    - Notes: ${rec.resume.notes}`);
			}
			if (rec.failure_reason && !rec.attribution) lines.push(`  - Failure Reason: ${rec.failure_reason}`);
			if (rec.fallback_tool) lines.push(`  - Fallback Tool: \`${rec.fallback_tool}\``);
			if (rec.suggested_fix) lines.push(`  - Suggested Fix: ${rec.suggested_fix}`);
			if (rec.capability_depth) lines.push(`  - Capability Depth: \`${rec.capability_depth}\``);
			if (rec.verification_boundary) lines.push(`  - Verification Boundary: ${rec.verification_boundary}`);
			if (rec.remaining_acceptance) lines.push(`  - Remaining Acceptance: ${rec.remaining_acceptance}`);
			if (rec.recovery_audit && rec.recovery_audit.length > 0) {
				lines.push("  - Recovery Audit Trail:");
				for (const audit of rec.recovery_audit) {
					const toolTransition =
						audit.previous_tool === audit.proposed_tool
							? `\`${audit.proposed_tool}\``
							: `\`${audit.previous_tool}\` -> \`${audit.proposed_tool}\``;
					const paramsStr =
						typeof audit.proposed_params === "string"
							? audit.proposed_params
							: JSON.stringify(audit.proposed_params);
					const capTag = audit.capability_id ? ` (Capability: \`${audit.capability_id}\`)` : "";
					lines.push(
						`    - Attempt ${audit.attempt} (${audit.action}): [${audit.category}] ${toolTransition}${capTag}`,
					);
					lines.push(`      - Decision: ${audit.decision}`);
					lines.push(`      - Proposed Params: \`${paramsStr}\``);
					if (audit.installed_tool) {
						lines.push(
							`      - Installed Tool: \`${audit.installed_tool}\` (Verified: ${audit.verified ?? true})`,
						);
					}
					if (audit.evidence_ids && audit.evidence_ids.length > 0) {
						lines.push(`      - Associated Evidence: ${audit.evidence_ids.map(id => `\`${id}\``).join(", ")}`);
					}
					if (audit.capability_depth) lines.push(`      - Capability Depth: \`${audit.capability_depth}\``);
					if (audit.verification_boundary)
						lines.push(`      - Verification Boundary: ${audit.verification_boundary}`);
					if (audit.remaining_acceptance)
						lines.push(`      - Remaining Acceptance: ${audit.remaining_acceptance}`);
				}
			}
			if (rec.retry_history && rec.retry_history.length > 0) {
				lines.push("  - Retry History:");
				for (const rh of rec.retry_history) {
					lines.push(
						`    - Attempt ${rh.attempt} at ${rh.timestamp}: ${rh.caller_result || rh.error || "Retried"}`,
					);
				}
			}
		}

		if (step.hydrated_evidence && step.hydrated_evidence.length > 0) {
			lines.push("- **Linked Evidence**:");
			for (const ev of step.hydrated_evidence) {
				if (ev.record) {
					const r = ev.record;
					lines.push(`  - \`${r.id}\` [${r.kind.toUpperCase()}]: ${r.title || "(no title)"}`);
					if (r.kind === "fact") {
						lines.push(`    - Locator: \`${r.locator}\` | Source: \`${r.sourceTool}\``);
						lines.push(`    - Content: ${r.content.slice(0, 200)}`);
					} else if (r.kind === "hypothesis") {
						lines.push(`    - Claim: ${r.claim.slice(0, 200)}`);
					} else if (r.kind === "conclusion") {
						lines.push(`    - Conclusion: ${r.conclusion.slice(0, 200)}`);
					}
				} else {
					lines.push(`  - \`${ev.id}\` (Not found in ledger)`);
				}
			}
		}

		lines.push("");
	}
	if (workflow.progression_audit && workflow.progression_audit.length > 0) {
		lines.push("## Auto Progression & Governance Decisions");
		lines.push("");
		for (const audit of workflow.progression_audit) {
			lines.push(
				`- [${audit.timestamp}] **${audit.step_id}** (\`${audit.tool}\`, ${audit.gate}): \`${audit.status.toUpperCase()}\``,
			);
			lines.push(`  - **Decision**: ${audit.decision}`);
			lines.push(`  - **Reason**: ${audit.reason}`);
			if (audit.knowledge_refs && audit.knowledge_refs.length > 0) {
				lines.push(`  - **Knowledge References**: ${audit.knowledge_refs.map(k => `\`${k}\``).join(", ")}`);
			}
		}
		lines.push("");
	}

	const fullText = lines.join("\n");
	if (fullText.length > MAX_EXPORT_CHARS) {
		return fullText.slice(0, MAX_EXPORT_CHARS) + "\n\n... [Report truncated to 32 KiB]";
	}
	return fullText;
}

export { exportWorkflowToWorkspace } from "../reverse-workspace";
