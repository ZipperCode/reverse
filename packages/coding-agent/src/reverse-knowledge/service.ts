import type { EvidenceStore } from "../evidence/store";
import type { EvidenceRecord } from "../evidence/contracts";
import { isDynamicLocator, parseDynamicLocator } from "../reverse-runtime-session/dynamic-events";
import type { ReverseWorkflowStore } from "../reverse-workflow/store";
import type { ReverseKnowledgeStore } from "./store";
import type { ToolSession } from "../tools/index";
import { ToolError } from "@rva/tui/tools/tool-errors";
import {
	type ReverseKnowledgeRecord,
	type RetainKnowledgeInput,
	type EvidenceValidationResult,
	type LearnKnowledgeInput,
	type LearnKnowledgeResult,
	type ApplyKnowledgeInput,
	type ApplyKnowledgeResult,
	type KnowledgeRecommendation,
	createKnowledgeId,
	DEFAULT_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_SEARCH_LIMIT,
} from "./contracts";
import { normalizeTargetFormat, type TargetFormat } from "../reverse-workflow/contracts";
import { MnemopiKnowledgeBridge } from "./bridge";

function extractToolName(command: string): string | undefined {
	const trimmed = command.trim().toLowerCase();
	if (trimmed.includes("r2") || trimmed.includes("radare2")) return "r2_inspect";
	if (trimmed.includes("ghidra")) return "ghidra_inspect";
	if (trimmed.includes("frida")) return "frida";
	if (trimmed.includes("sourcemap") || trimmed.includes("source-map")) return "sourcemap_inspect";
	if (trimmed.includes("jadx") || trimmed.includes("apktool") || trimmed.includes("dex")) return "android_package_inspect";
	if (trimmed.includes("tshark") || trimmed.includes("tcpdump") || trimmed.includes("wireshark")) return "pcap_inspect";
	if (trimmed.includes("sqlite")) return "sqlite_inspect";
	if (trimmed.includes("binwalk")) return "firmware_inspect";
	if (trimmed.includes("vbindiff") || trimmed.includes("bindiff")) return "binary_diff";
	if (trimmed.includes("debug") || trimmed.includes("gdb") || trimmed.includes("lldb")) return "debug";
	if (trimmed.includes("browser") || trimmed.includes("playwright") || trimmed.includes("cdp")) return "browser_reverse_session";
	if (trimmed.includes("dynamic_evidence") || trimmed.includes("reverse_dynamic_evidence")) return "reverse_dynamic_evidence";
	if (trimmed.includes("unidbg")) return "unidbg";
	if (trimmed.includes("android_native_workflow")) return "android_native_workflow";
	const firstWord = trimmed.split(/\s+/)[0];
	return firstWord && firstWord.length <= 32 ? firstWord : undefined;
}

export async function validateVerifiedOnly(
	input: RetainKnowledgeInput,
	evidenceStore?: EvidenceStore,
): Promise<EvidenceValidationResult> {
	if (input.kind !== "verified_conclusion" && input.kind !== "recovery_pattern") {
		throw new ToolError(
			`Cannot retain knowledge with unverified kind '${input.kind}'. Only 'verified_conclusion' and 'recovery_pattern' may be retained as reusable knowledge.`,
		);
	}

	if (input.confidence === "low") {
		const isLifecycleOrExpired =
			input.title?.toLowerCase().includes("expired") ||
			input.title?.toLowerCase().includes("deprecated") ||
			input.title?.toLowerCase().includes("obsolete");
		if (!isLifecycleOrExpired) {
			throw new ToolError(
				"Cannot retain knowledge with 'low' confidence as reusable verified knowledge. Verified conclusions require 'high' or 'medium' confidence.",
			);
		}
	}

	const missingEvidenceIds: string[] = [];
	const refutedEvidenceIds: string[] = [];

	if (evidenceStore && input.source_evidence_ids && input.source_evidence_ids.length > 0) {
		for (const evId of input.source_evidence_ids) {
			const record = await evidenceStore.getRecord(evId);
			if (!record) {
				missingEvidenceIds.push(evId);
				continue;
			}

			if (record.kind === "unknown") {
				throw new ToolError(
					`Cannot retain knowledge derived from unverified unknown question '${evId}'. Only verified conclusions and successful recoveries may be retained.`,
				);
			}

			if (record.kind === "hypothesis") {
				if (!record.verifiedBy) {
					throw new ToolError(
						`Cannot promote unverified hypothesis '${evId}' ('${record.claim}') to reusable knowledge. Hypotheses must first be verified by a conclusion in the evidence ledger before retention.`,
					);
				}
			}

			if (record.kind === "conclusion") {
				if (record.status !== "verified") {
					refutedEvidenceIds.push(evId);
					continue;
				}
			}
		}
	}

	return {
		missingEvidenceIds,
		refutedEvidenceIds,
		unverified: missingEvidenceIds.length > 0 || refutedEvidenceIds.length > 0,
	};
}

export async function learnFromEvidenceAndWorkflows(
	evidenceStore: EvidenceStore,
	workflowStore: ReverseWorkflowStore,
	knowledgeStore: ReverseKnowledgeStore,
	session?: ToolSession,
	options: LearnKnowledgeInput = {},
): Promise<LearnKnowledgeResult> {
	let learnedConclusions = 0;
	let learnedRecoveries = 0;
	let skippedUnverified = 0;
	const createdRecords: ReverseKnowledgeRecord[] = [];

	const existingKnowledge = await knowledgeStore.list();
	const seenEvidenceIds = new Set<string>();
	const seenRecoveryKeys = new Set<string>();

	for (const k of existingKnowledge) {
		if (k.source_evidence_ids) {
			for (const id of k.source_evidence_ids) {
				seenEvidenceIds.add(id);
			}
		}
		if (k.source_workflow_id && k.source_step_id) {
			seenRecoveryKeys.add(`${k.source_workflow_id}:${k.source_step_id}`);
		}
	}

	// 1. Learn from EvidenceStore
	const evidenceRecords: EvidenceRecord[] = [];
	let offset = 0;
	while (true) {
		const page = await evidenceStore.listRecords({ offset, limit: 100 });
		evidenceRecords.push(...page.items);
		if (evidenceRecords.length >= page.total || page.items.length === 0) {
			break;
		}
		offset += page.items.length;
	}
	for (const ev of evidenceRecords) {
		if (ev.kind === "unknown") {
			skippedUnverified++;
			continue;
		}

		if (ev.kind === "hypothesis") {
			if (!ev.verifiedBy) {
				// Unverified hypothesis - skip to prevent auto-promoting unverified claims
				skippedUnverified++;
				continue;
			}
			// Verified hypothesis is represented by its conclusion record.
			continue;
		}

		if (ev.kind === "conclusion") {
			if (ev.status !== "verified") {
				// Refuted conclusion - skip
				skippedUnverified++;
				continue;
			}

			if (seenEvidenceIds.has(ev.id)) {
				// Already retained in knowledge
				continue;
			}

			// Format matching
			let format: TargetFormat = "unknown";
			if (ev.target) {
				format = normalizeTargetFormat(ev.target) ?? "unknown";
			}
			if (options.format && format === "unknown") {
				format = normalizeTargetFormat(options.format) ?? "unknown";
			}
			if (options.target_hash && ev.targetSha256 && options.target_hash !== ev.targetSha256) {
				continue;
			}

			// Look up linked hypothesis for richer context
			let hypothesisClaim: string | undefined;
			let hasDynamicEvidence = false;
			const dynamicLocators: string[] = [];
			const dynamicSessions = new Set<string>();
			if (ev.hypothesisId) {
				const hyp = await evidenceStore.getRecord(ev.hypothesisId).catch(() => null);
				if (hyp && hyp.kind === "hypothesis") {
					hypothesisClaim = hyp.claim;
					if (format === "unknown" && hyp.target) {
						format = normalizeTargetFormat(hyp.target) ?? "unknown";
					}
					if (hyp.facts && hyp.facts.length > 0) {
						for (const fId of hyp.facts) {
							const f = await evidenceStore.getRecord(fId).catch(() => null);
							if (f && f.kind === "fact" && isDynamicLocator(f.locator)) {
								hasDynamicEvidence = true;
								dynamicLocators.push(f.locator);
								const parsed = parseDynamicLocator(f.locator);
								if (parsed) dynamicSessions.add(parsed.sessionId);
							}
						}
					}
				}
			}

			if (!hasDynamicEvidence) {
				const sessionMatch = ev.command?.match(/session_id:\s*["']?([a-zA-Z0-9_.-]+)["']?/);
				const sessionIdFromCmd = sessionMatch ? sessionMatch[1] : undefined;
				const isDynamicContext =
					Boolean(sessionMatch) ||
					ev.command?.includes("reverse_dynamic_evidence") ||
					ev.method?.toLowerCase().includes("dynamic") ||
					ev.result?.toLowerCase().includes("dynamic");

				if (isDynamicContext) {
					const allFacts = await evidenceStore.listRecords({ kind: "fact", limit: 100 }).catch(() => ({ items: [] }));
					for (const r of allFacts.items) {
						if (r.kind === "fact" && isDynamicLocator(r.locator)) {
							const parsed = parseDynamicLocator(r.locator);
							const matchesSession = sessionIdFromCmd ? parsed?.sessionId === sessionIdFromCmd : false;
							const matchesTarget = Boolean(ev.target && r.target && r.target === ev.target);
							if (matchesSession || matchesTarget) {
								hasDynamicEvidence = true;
								if (!dynamicLocators.includes(r.locator)) {
									dynamicLocators.push(r.locator);
								}
								if (parsed) dynamicSessions.add(parsed.sessionId);
							}
						}
					}
					if (!hasDynamicEvidence && sessionIdFromCmd) {
						hasDynamicEvidence = true;
						dynamicSessions.add(sessionIdFromCmd);
					}
				}
			}

			const now = new Date().toISOString();
			const toolName = extractToolName(ev.command);
			const title = ev.title.startsWith("[Conclusion]")
				? ev.title
				: `[Verified Finding] ${hypothesisClaim ? hypothesisClaim.slice(0, 80) : ev.conclusion.slice(0, 80)}`;

			let pattern: string | undefined;
			const lowerText = `${ev.conclusion} ${ev.result} ${ev.method}`.toLowerCase();
			if (lowerText.includes("aes") || lowerText.includes("crypto") || lowerText.includes("decrypt") || lowerText.includes("encrypt")) {
				pattern = "dynamic_crypto_verification";
			} else if (lowerText.includes("jni") || lowerText.includes("registernatives")) {
				pattern = "dynamic_jni_resolution";
			} else if (lowerText.includes("token") || lowerText.includes("auth") || lowerText.includes("session")) {
				pattern = "dynamic_auth_observation";
			} else if (hasDynamicEvidence) {
				pattern = "dynamic_runtime_verification";
			}

			let guidance = `Verified finding via ${ev.method} (${ev.command}): ${ev.conclusion}`;
			if (hasDynamicEvidence) {
				guidance += `\nDynamic Verification: Grounded in session telemetry (${dynamicLocators.join(", ")}).`;
			}

			const metadata: Record<string, unknown> = {
				command: ev.command,
				reproducibility: ev.reproducibility,
			};
			if (hasDynamicEvidence) {
				metadata.dynamic_verified = true;
				metadata.dynamic_locators = dynamicLocators;
				metadata.dynamic_sessions = Array.from(dynamicSessions);
			}

			const record: ReverseKnowledgeRecord = {
				id: createKnowledgeId(),
				kind: "verified_conclusion",
				title,
				target_format: format,
				target_hash: ev.targetSha256,
				tool: toolName,
				confidence: "high",
				pattern,
				source_evidence_ids: [ev.id, ...(ev.hypothesisId ? [ev.hypothesisId] : [])],
				summary: `${ev.conclusion}\nMethod: ${ev.method}\nResult: ${ev.result}`,
				actionable_guidance: guidance,
				metadata,
				created_at: now,
				updated_at: now,
			};

			await knowledgeStore.save(record);
			if (session) {
				await MnemopiKnowledgeBridge.retain(record, session);
			}

			seenEvidenceIds.add(ev.id);
			if (ev.hypothesisId) seenEvidenceIds.add(ev.hypothesisId);
			createdRecords.push(record);
			learnedConclusions++;
		}
	}

	// 2. Learn from ReverseWorkflowStore
	const workflows = options.workflow_id
		? [(await workflowStore.get(options.workflow_id))].filter((w): w is NonNullable<typeof w> => Boolean(w))
		: await workflowStore.list();

	for (const wf of workflows) {
		if (options.target_hash && wf.target_sha256 && options.target_hash !== wf.target_sha256) {
			continue;
		}

		for (const step of wf.steps) {
			const audits = step.recovery_metadata?.recovery_audit;
			if (!audits || audits.length === 0) continue;

			// Check if step succeeded after recovery
			const isSuccess = step.status === "completed";

			for (const audit of audits) {
				if (!isSuccess || !audit.applied) {
					skippedUnverified++;
					continue;
				}
				const recoveryKey = `${wf.id}:${step.id}`;
				if (seenRecoveryKeys.has(recoveryKey)) continue;

				const now = new Date().toISOString();
				const proposedParamsStr =
					typeof audit.proposed_params === "string"
						? audit.proposed_params
						: JSON.stringify(audit.proposed_params);

				const resumeInfo = step.recovery_metadata?.resume;
				const isResume = audit.action === "resume" || Boolean(resumeInfo);
				const title = isResume && resumeInfo
					? `Recovery Pattern: ${audit.category} on ${audit.previous_tool} -> Resumed via ${resumeInfo.installed_tool} (${resumeInfo.strategy})`
					: `Recovery Pattern: ${audit.category} on ${audit.previous_tool} -> ${audit.proposed_tool}`;
				const summary = isResume && resumeInfo
					? `Failure category: ${audit.category}. Cause: ${audit.cause}. Decision: ${audit.decision}. Resumed after installing '${resumeInfo.installed_tool}' (capability: ${resumeInfo.capability_id || "none"}, strategy: ${resumeInfo.strategy}).`
					: `Failure category: ${audit.category}. Cause: ${audit.cause}. Decision: ${audit.decision}. Fallback from ${audit.previous_tool} to ${audit.proposed_tool} succeeded.`;
				const pattern = isResume && resumeInfo
					? `category:${audit.category};previous_tool:${audit.previous_tool};installed_tool:${resumeInfo.installed_tool};strategy:${resumeInfo.strategy}`
					: `category:${audit.category};previous_tool:${audit.previous_tool};fallback_tool:${audit.proposed_tool}`;
				const guidance = isResume && resumeInfo
					? `When tool '${audit.previous_tool}' encounters ${audit.category} (${audit.cause}), install '${resumeInfo.installed_tool}' via '${resumeInfo.setup_command || `reverse setup reverse ${resumeInfo.installed_tool}`}' and resume (${resumeInfo.strategy}).`
					: `When tool '${audit.previous_tool}' encounters ${audit.category} (${audit.cause}), fallback to '${audit.proposed_tool}' with params: ${proposedParamsStr}`;

				const record: ReverseKnowledgeRecord = {
					id: createKnowledgeId(),
					kind: "recovery_pattern",
					title,
					target_format: wf.format,
					target_hash: wf.target_sha256,
					tool: audit.previous_tool,
					confidence: "high",
					source_workflow_id: wf.id,
					source_step_id: step.id,
					source_evidence_ids: audit.evidence_ids,
					summary,
					pattern,
					actionable_guidance: guidance,
					params: audit.proposed_params,
					created_at: now,
					updated_at: now,
				};

				await knowledgeStore.save(record);
				if (session) {
					await MnemopiKnowledgeBridge.retain(record, session);
				}

				seenRecoveryKeys.add(recoveryKey);
				createdRecords.push(record);
				learnedRecoveries++;
			}
		}
	}

	return {
		learned_conclusions: learnedConclusions,
		learned_recoveries: learnedRecoveries,
		skipped_unverified: skippedUnverified,
		created_records: createdRecords,
	};
}

export async function applyKnowledge(
	knowledgeStore: ReverseKnowledgeStore,
	input: ApplyKnowledgeInput,
): Promise<ApplyKnowledgeResult> {
	const limit = Math.min(
		Math.max(input.limit ?? DEFAULT_KNOWLEDGE_SEARCH_LIMIT, 1),
		MAX_KNOWLEDGE_SEARCH_LIMIT,
	);

	const queryParts = [input.goal, input.error, input.tool].filter(Boolean).join(" ");
	const normalizedFormat = normalizeTargetFormat(input.format);

	const records = await knowledgeStore.search({
		query: queryParts || undefined,
		format: normalizedFormat,
		target_hash: input.target_hash,
		tool: input.tool,
		limit,
		include_stale: false,
	});

	const recommendations: KnowledgeRecommendation[] = records.map(r => {
		const source: "evidence_ledger" | "workflow_recovery" | "retained_finding" | "bundled" =
			r.source === "bundled" || r.metadata?.source === "bundled"
				? "bundled"
				: r.source_evidence_ids && r.source_evidence_ids.length > 0
					? "evidence_ledger"
					: r.source_workflow_id
						? "workflow_recovery"
						: "retained_finding";
		return {
			knowledge_id: r.id,
			title: r.title,
			kind: r.kind,
			confidence: r.confidence,
			tool: r.tool,
			format: r.target_format,
			guidance: r.actionable_guidance ?? r.summary,
			suggested_params: r.params,
			source_evidence_ids: r.source_evidence_ids,
			source_workflow_id: r.source_workflow_id,
			source_step_id: r.source_step_id,
			source,
			status: r.status ?? "active",
			usage_count: r.usage_count ?? 0,
		};
	});

	// Increment usage metadata on retrieved active records
	for (const r of records) {
		r.usage_count = (r.usage_count ?? 0) + 1;
		r.last_used_at = new Date().toISOString();
		if (r.source !== "bundled" && r.metadata?.source !== "bundled") {
			await knowledgeStore.save(r).catch(() => undefined);
		}
	}

	return {
		target: input.target,
		format: normalizedFormat,
		target_hash: input.target_hash,
		recommendations,
		knowledge_refs: recommendations.map(r => r.knowledge_id),
	};
}
