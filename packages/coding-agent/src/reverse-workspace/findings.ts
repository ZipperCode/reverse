import type { HydratedEvidenceItem } from "../reverse-workflow/export";
import type { ReverseWorkflowRecord } from "../reverse-workflow/contracts";
import type { FactEvidence, HypothesisEvidence, ConclusionEvidence } from "../evidence/contracts";
import type { ReverseWorkspaceTargetInfo, ReverseFindingsSummary } from "./contracts";
import { MAX_REPORT_CHARS } from "./contracts";
import { redactSecrets } from "./atomic";

/**
 * Extracts and categorizes verified findings, empirical facts, and hypotheses
 * from hydrated workflow evidence.
 */
export function generateFindingsData(
	workflow: ReverseWorkflowRecord,
	hydratedEvidence: HydratedEvidenceItem[],
	targetInfo: ReverseWorkspaceTargetInfo,
): ReverseFindingsSummary {
	const facts: ReverseFindingsSummary["facts"] = [];
	const verifiedHypotheses: ReverseFindingsSummary["verified_hypotheses"] = [];
	const unverifiedHypotheses: ReverseFindingsSummary["unverified_hypotheses"] = [];
	const conclusions: ReverseFindingsSummary["conclusions"] = [];

	const seenIds = new Set<string>();

	for (const item of hydratedEvidence) {
		const record = item.record;
		if (!record || seenIds.has(record.id)) continue;
		seenIds.add(record.id);

		if (record.kind === "fact") {
			const f = record as FactEvidence;
			facts.push({
				id: f.id,
				title: f.title,
				locator: f.locator,
				sourceTool: f.sourceTool,
				content: redactSecrets(f.content),
				timestamp: f.createdAt,
			});
		} else if (record.kind === "hypothesis") {
			const h = record as HypothesisEvidence;
			if (h.verifiedBy) {
				verifiedHypotheses.push({
					id: h.id,
					claim: redactSecrets(h.claim),
					verificationPlan: h.verificationPlan,
					verifiedBy: h.verifiedBy,
					timestamp: h.createdAt,
				});
			} else {
				unverifiedHypotheses.push({
					id: h.id,
					claim: redactSecrets(h.claim),
					verificationPlan: h.verificationPlan,
					timestamp: h.createdAt,
				});
			}
		} else if (record.kind === "conclusion") {
			const c = record as ConclusionEvidence;
			conclusions.push({
				id: c.id,
				conclusion: redactSecrets(c.conclusion),
				method: c.method,
				command: c.command,
				result: redactSecrets(c.result),
				reproducibility: c.reproducibility,
				status: c.status,
				hypothesisId: c.hypothesisId,
				timestamp: c.verifiedAt || c.createdAt,
			});
		}
	}

	const keyTakeaways: string[] = [];
	if (conclusions.length > 0) {
		for (const c of conclusions.slice(0, 5)) {
			keyTakeaways.push(c.conclusion.slice(0, 200));
		}
	} else if (facts.length > 0) {
		for (const f of facts.slice(0, 3)) {
			keyTakeaways.push(`[${f.sourceTool}] ${f.content.slice(0, 150)}`);
		}
	}

	return {
		target: {
			name: targetInfo.name,
			format: targetInfo.format,
			sha256: targetInfo.sha256,
		},
		goal: workflow.goal,
		conclusions,
		verified_hypotheses: verifiedHypotheses,
		unverified_hypotheses: unverifiedHypotheses,
		facts,
		key_takeaways: keyTakeaways,
	};
}

/**
 * Renders an editorial findings report in markdown format.
 */
export function generateFindingsMarkdown(
	workflow: ReverseWorkflowRecord,
	hydratedEvidence: HydratedEvidenceItem[],
	targetInfo: ReverseWorkspaceTargetInfo,
): string {
	const summary = generateFindingsData(workflow, hydratedEvidence, targetInfo);

	const lines: string[] = [
		`# Reverse Engineering Findings: ${targetInfo.name}`,
		"",
		`- **Target**: \`${targetInfo.path}\` (${targetInfo.format})`,
		`- **SHA-256**: \`${targetInfo.sha256 || "unknown"}\``,
		`- **Size**: ${targetInfo.size !== undefined ? `${targetInfo.size} bytes` : "unknown"}`,
		`- **Workflow ID**: \`${workflow.id}\``,
		`- **Status**: \`${workflow.status.toUpperCase()}\``,
		`- **Goal**: ${workflow.goal || "Reverse engineering analysis"}`,
		`- **Generated**: ${new Date().toISOString()}`,
		"",
		"## 1. Executive Summary & Takeaways",
		"",
	];

	if (summary.key_takeaways.length > 0) {
		for (const takeaway of summary.key_takeaways) {
			lines.push(`- ${takeaway}`);
		}
	} else {
		lines.push("_No confirmed takeaways recorded yet._");
	}
	lines.push("");

	lines.push("## 2. Verified Conclusions (Ironclad Proof)");
	lines.push("");
	if (summary.conclusions.length > 0) {
		for (const c of summary.conclusions) {
			lines.push(`### [CONCLUSION] ${c.id}`);
			lines.push(`- **Conclusion**: ${c.conclusion}`);
			if (c.method) lines.push(`- **Method**: \`${c.method}\``);
			if (c.status) lines.push(`- **Status**: \`${c.status}\``);
			if (c.hypothesisId) lines.push(`- **Hypothesis**: \`${c.hypothesisId}\``);
			lines.push(`- **Timestamp**: ${c.timestamp}`);
			lines.push("");
		}
	} else {
		lines.push("_No verified conclusions recorded yet. Hypotheses require dynamic/experimental validation._");
		lines.push("");
	}

	lines.push("## 3. Hypothesis Verification Matrix");
	lines.push("");
	if (summary.verified_hypotheses.length > 0 || summary.unverified_hypotheses.length > 0) {
		if (summary.verified_hypotheses.length > 0) {
			lines.push("### Verified Hypotheses");
			for (const vh of summary.verified_hypotheses) {
				lines.push(`- **\`${vh.id}\`** [VERIFIED]: ${vh.claim}`);
				if (vh.verificationPlan) lines.push(`  - Verification Plan: ${vh.verificationPlan}`);
				if (vh.verifiedBy) lines.push(`  - Backed by Conclusion: \`${vh.verifiedBy}\``);
			}
			lines.push("");
		}
		if (summary.unverified_hypotheses.length > 0) {
			lines.push("### Unverified / Working Hypotheses");
			for (const uh of summary.unverified_hypotheses) {
				lines.push(`- **\`${uh.id}\`** [PENDING]: ${uh.claim}`);
				if (uh.verificationPlan) lines.push(`  - Verification Plan: ${uh.verificationPlan}`);
			}
			lines.push("");
		}
	} else {
		lines.push("_No working hypotheses logged in workflow evidence._");
		lines.push("");
	}

	lines.push("## 4. Empirical Ground Truth Ledger");
	lines.push("");
	if (summary.facts.length > 0) {
		lines.push("| ID | Source Tool | Locator | Fact Content |");
		lines.push("| :--- | :--- | :--- | :--- |");
		for (const f of summary.facts) {
			const escapedContent = f.content.replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 120);
			lines.push(`| \`${f.id}\` | \`${f.sourceTool}\` | \`${f.locator}\` | ${escapedContent} |`);
		}
		lines.push("");
	} else {
		lines.push("_No empirical facts registered for this workflow._");
		lines.push("");
	}

	const fullText = lines.join("\n");
	if (fullText.length > MAX_REPORT_CHARS) {
		return fullText.slice(0, MAX_REPORT_CHARS) + "\n\n... [Findings report truncated to 128 KiB]";
	}
	return fullText;
}
