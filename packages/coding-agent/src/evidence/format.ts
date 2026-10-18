import type {
	ConclusionEvidence,
	EvidenceDriftStatus,
	EvidenceListResult,
	EvidenceRecord,
	FactEvidence,
	HypothesisEvidence,
	UnknownEvidence,
} from "./contracts";

export function renderRecordText(
	record: EvidenceRecord,
	drift?: EvidenceDriftStatus,
	related?: {
		hypothesis?: HypothesisEvidence;
		conclusions?: ConclusionEvidence[];
		facts?: FactEvidence[];
	},
): string {
	const lines: string[] = [];
	lines.push(`[Evidence: ${record.id}] [${record.kind.toUpperCase()}]`);
	lines.push(`Title: ${record.title}`);
	lines.push(`Created: ${record.createdAt}`);
	if (record.target) lines.push(`Target: ${record.target}`);
	if (record.targetSha256) lines.push(`Target SHA-256: ${record.targetSha256}`);
	if (record.classification) lines.push(`Classification: ${record.classification}`);
	if (record.tags && record.tags.length > 0) lines.push(`Tags: ${record.tags.join(", ")}`);

	if (record.kind === "fact") {
		lines.push(`Source Tool: ${record.sourceTool}`);
		lines.push(`Locator: ${record.locator}`);
		lines.push(`Content:\n  ${record.content.split("\n").join("\n  ")}`);
		if (record.excerpt) {
			lines.push(`Excerpt:\n  ${record.excerpt.split("\n").join("\n  ")}`);
		}
		if (related?.hypothesis) {
			lines.push(`Referenced in Hypothesis: [${related.hypothesis.id}] ${related.hypothesis.title}`);
		}
	} else if (record.kind === "hypothesis") {
		lines.push(`Claim:\n  ${record.claim.split("\n").join("\n  ")}`);
		lines.push(`Verification Plan:\n  ${record.verificationPlan.split("\n").join("\n  ")}`);
		if (record.content) {
			lines.push(`Context:\n  ${record.content.split("\n").join("\n  ")}`);
		}
		if (record.facts && record.facts.length > 0) {
			lines.push(`Grounding Facts: ${record.facts.join(", ")}`);
		}
		if (record.verifiedBy) {
			lines.push(`Status: VERIFIED (Conclusion: [${record.verifiedBy}])`);
		} else {
			lines.push(`Status: UNVERIFIED (Awaiting experimental proof via 'verify')`);
		}
		if (related?.facts && related.facts.length > 0) {
			lines.push("Supporting Facts Detail:");
			for (const f of related.facts) {
				lines.push(`  - [${f.id}] (${f.sourceTool} @ ${f.locator}) ${f.content}`);
			}
		}
	} else if (record.kind === "unknown") {
		lines.push(`Question:\n  ${record.question.split("\n").join("\n  ")}`);
		if (record.notes) {
			lines.push(`Notes:\n  ${record.notes.split("\n").join("\n  ")}`);
		}
		if (record.content) {
			lines.push(`Context:\n  ${record.content.split("\n").join("\n  ")}`);
		}
	} else if (record.kind === "conclusion") {
		lines.push(`Verified Hypothesis: [${record.hypothesisId}]`);
		lines.push(`Status: ${record.status.toUpperCase()}`);
		lines.push(`Verified At: ${record.verifiedAt}`);
		lines.push(`Reproducibility: ${record.reproducibility}`);
		lines.push(`Method: ${record.method}`);
		lines.push(`Command:\n  ${record.command.split("\n").join("\n  ")}`);
		lines.push(`Observed Result:\n  ${record.result.split("\n").join("\n  ")}`);
		lines.push(`Conclusion:\n  ${record.conclusion.split("\n").join("\n  ")}`);
		if (related?.hypothesis) {
			lines.push(`Original Claim:\n  ${related.hypothesis.claim.split("\n").join("\n  ")}`);
		}
		if (related?.facts && related.facts.length > 0) {
			lines.push("Underlying Fact Trail:");
			for (const f of related.facts) {
				lines.push(`  - [${f.id}] (${f.sourceTool} @ ${f.locator}) ${f.content}`);
			}
		}
	}

	if (drift && drift.warnings.length > 0) {
		lines.push("");
		lines.push("--- DRIFT WARNINGS ---");
		for (const w of drift.warnings) {
			lines.push(`⚠ ${w}`);
		}
	} else if (drift && record.target) {
		lines.push("");
		lines.push("✓ Integrity: Target hash verified (no drift detected)");
	}

	return lines.join("\n");
}

export function renderListText(result: EvidenceListResult): string {
	const { items, total, limit, offset } = result;
	if (total === 0) {
		return "Evidence Ledger is empty. Use action: 'add' to record a fact, hypothesis, or unknown.";
	}

	const start = offset + 1;
	const end = Math.min(offset + items.length, total);
	const lines: string[] = [`Evidence Ledger: showing ${start}-${end} of ${total} entries (limit ${limit})`, ""];

	for (const item of items) {
		const targetStr = item.target ? ` [${item.target}]` : "";
		const kindTag = `[${item.kind.toUpperCase()}]`;
		let extra = "";
		if (item.kind === "fact") {
			extra = ` (${item.sourceTool} @ ${item.locator})`;
		} else if (item.kind === "hypothesis") {
			extra = item.verifiedBy ? ` [VERIFIED -> ${item.verifiedBy}]` : " [UNVERIFIED]";
		} else if (item.kind === "conclusion") {
			extra = ` (${item.status}: ${item.method})`;
		}
		lines.push(`- ${item.id.padEnd(20)} ${kindTag.padEnd(14)}${targetStr} ${item.title}${extra}`);
	}

	return lines.join("\n");
}

export function exportEvidenceToMarkdown(
	records: EvidenceRecord[],
	options: { title?: string; target?: string; specificId?: string } = {},
): string {
	const conclusions = records.filter((r): r is ConclusionEvidence => r.kind === "conclusion");
	const hypotheses = records.filter((r): r is HypothesisEvidence => r.kind === "hypothesis");
	const facts = records.filter((r): r is FactEvidence => r.kind === "fact");
	const unknowns = records.filter((r): r is UnknownEvidence => r.kind === "unknown");

	const factMap = new Map<string, FactEvidence>();
	for (const f of facts) factMap.set(f.id, f);

	const hypMap = new Map<string, HypothesisEvidence>();
	for (const h of hypotheses) hypMap.set(h.id, h);

	// If specificId is requested, filter
	if (options.specificId) {
		const targetRecord = records.find(r => r.id === options.specificId);
		if (!targetRecord) return `# Evidence Artifact\n\nNo evidence found matching ID ${options.specificId}.\n`;
	}

	const docTitle = options.title ?? "Reverse Engineering Evidence Chain";
	const md: string[] = [`# Evidence Artifact: ${docTitle}`, ""];

	// If we have verified conclusions, format full evidence chains
	if (conclusions.length > 0) {
		for (let i = 0; i < conclusions.length; i++) {
			const conc = conclusions[i];
			const hyp = hypMap.get(conc.hypothesisId);
			const supportingFacts: FactEvidence[] = [];
			if (hyp?.facts) {
				for (const fId of hyp.facts) {
					const f = factMap.get(fId);
					if (f) supportingFacts.push(f);
				}
			}

			md.push(`## Finding ${i + 1}: ${conc.title.replace(/^\[Conclusion\]\s*/, "")}`);
			md.push("");
			md.push("### 1. Target Metadata");
			md.push(`- **Target**: \`${conc.target ?? "N/A"}\``);
			if (conc.targetSha256) md.push(`- **SHA-256**: \`${conc.targetSha256}\``);
			md.push(`- **Analysis Date**: \`${conc.verifiedAt.slice(0, 10)}\``);
			if (conc.classification) md.push(`- **Classification**: \`${conc.classification}\``);
			if (conc.tags && conc.tags.length > 0) md.push(`- **Tags**: \`${conc.tags.join(", ")}\``);
			md.push("");

			md.push("### 2. Evidence Chain");
			md.push("");

			if (supportingFacts.length > 0) {
				md.push("#### [FACT] Observable Ground Truth");
				for (const fact of supportingFacts) {
					md.push(`- **Location**: \`${fact.locator}\` (Tool: \`${fact.sourceTool}\`)`);
					md.push(`- **Observation**: ${fact.content}`);
					if (fact.excerpt) {
						md.push("```");
						md.push(fact.excerpt);
						md.push("```");
					}
				}
				md.push("");
			}

			md.push("#### [HYPOTHESIS] Working Hypothesis");
			md.push(`- ${hyp ? hyp.claim : "Hypothesis logic confirmed by experiment"}`);
			md.push("");

			md.push("#### [EXPERIMENT] Verification Procedure");
			md.push(`- **Method**: ${conc.method}`);
			md.push("- **Execution Command**:");
			md.push("```bash");
			md.push(conc.command);
			md.push("```");
			md.push(`- **Observed Result**: ${conc.result}`);
			md.push("");

			md.push("#### [CONCLUSION] Verified Result");
			md.push(`- **Status**: ${conc.status.toUpperCase()}`);
			md.push(`- **Confirmed Behavior**: ${conc.conclusion}`);
			md.push(`- **Reproducibility**: ${conc.reproducibility}`);
			md.push("");
			md.push("---");
			md.push("");
		}
	}

	// Working hypotheses without verified conclusion
	const unverifiedHyps = hypotheses.filter(h => !h.verifiedBy);
	if (unverifiedHyps.length > 0) {
		md.push("## Working Hypotheses (Unverified)");
		md.push("");
		for (const h of unverifiedHyps) {
			md.push(`### [HYPOTHESIS] ${h.title}`);
			md.push(`- **Claim**: ${h.claim}`);
			md.push(`- **Verification Plan**: ${h.verificationPlan}`);
			if (h.target) md.push(`- **Target**: \`${h.target}\``);
			if (h.facts && h.facts.length > 0) md.push(`- **Supporting Facts**: ${h.facts.join(", ")}`);
			md.push("");
		}
	}

	// Unknowns
	if (unknowns.length > 0) {
		md.push("## Open Questions & Anomalies ([UNKNOWN])");
		md.push("");
		for (const u of unknowns) {
			md.push(`- **[${u.id}] ${u.title}**: ${u.question}`);
			if (u.notes) md.push(`  *Notes*: ${u.notes}`);
		}
		md.push("");
	}

	return md.join("\n");
}
