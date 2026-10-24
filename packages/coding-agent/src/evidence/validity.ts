import {
	type EvidenceAssuranceLevel,
	type EvidenceKind,
	type EvidenceRecord,
	type HypothesisEvidence,
	type ConclusionEvidence,
	ASSURANCE_LEVEL_RANK,
} from "./contracts";

export interface EvidenceRequirements {
	requiredSubject?: string;
	requiredTargetSha256?: string;
	minAssurance?: EvidenceAssuranceLevel;
	requiredKinds?: EvidenceKind[];
	allowRefuted?: boolean;
	requireExhaustiveNegative?: boolean;
	requireZeroExitStages?: boolean;
}

export interface CanonicalEvidenceValidity {
	id: string;
	kind: EvidenceKind;
	effectiveStatus: "verified" | "refuted" | "stale" | "pending" | "valid";
	isRefuted: boolean;
	isStale: boolean;
	isValid: boolean;
	refutedByConclusionId?: string;
	invalidatedBy?: string;
	reason?: string;
	assurance?: EvidenceAssuranceLevel;
	subject?: string;
	targetSha256?: string;
}

export interface EvidenceSupportEvaluation {
	valid: boolean;
	reason?: string;
	highestAssurance?: EvidenceAssuranceLevel;
	records: EvidenceRecord[];
	validityMap: Record<string, CanonicalEvidenceValidity>;
	refutedIds: string[];
	staleIds: string[];
	unverifiedIds: string[];
	mismatchedSubjectIds: string[];
	mismatchedHashIds: string[];
	failedStageIds: string[];
	nonExhaustiveNegativeIds: string[];
	unmetAssuranceIds: string[];
	unmetKindIds: string[];
}

export interface EvidenceRecordResolver {
	getRecord(id: string): Promise<EvidenceRecord | null> | EvidenceRecord | null;
	listRecords?(filter?: {
		kind?: EvidenceKind;
		limit?: number;
		offset?: number;
	}): Promise<{ items: EvidenceRecord[] }> | { items: EvidenceRecord[] };
	getAllRecords?(): Promise<EvidenceRecord[]> | EvidenceRecord[];
}

/**
 * Resolves canonical validity across an append-only evidence ledger.
 *
 * Rules:
 * - Conclusions are evaluated in chronological order for each hypothesis.
 * - If the latest conclusion for a hypothesis is refuted, the hypothesis is refuted,
 *   and any earlier conclusions for that hypothesis become stale (invalidated by refutation).
 * - Explicit invalidations via conclusion.invalidatesConclusions mark targets stale.
 * - Transitive refutation cascade: if a hypothesis or conclusion depends on a refuted
 *   or stale supporting record, its effective status becomes stale.
 */
export function resolveEvidenceLedgerValidity(records: EvidenceRecord[]): Map<string, CanonicalEvidenceValidity> {
	const validityMap = new Map<string, CanonicalEvidenceValidity>();
	const recordMap = new Map<string, EvidenceRecord>();

	for (const r of records) {
		recordMap.set(r.id, r);
	}

	const conclusionsByHypothesis = new Map<string, ConclusionEvidence[]>();
	const explicitlyInvalidated = new Map<string, string>(); // targetId -> invalidatingConclusionId

	for (const r of records) {
		if (r.kind === "conclusion") {
			const list = conclusionsByHypothesis.get(r.hypothesisId) ?? [];
			list.push(r);
			conclusionsByHypothesis.set(r.hypothesisId, list);

			if (r.invalidatesConclusions && Array.isArray(r.invalidatesConclusions)) {
				for (const invId of r.invalidatesConclusions) {
					if (typeof invId === "string" && invId.trim().length > 0) {
						explicitlyInvalidated.set(invId.trim(), r.id);
					}
				}
			}
		}
	}

	// 1. Initial pass: evaluate facts and unknowns
	for (const r of records) {
		const assurance = r.context?.assurance;
		const subject = r.subject ?? r.context?.subject;
		const targetSha256 = r.targetSha256 ?? r.context?.executionBinding?.artifactSha256;

		if (r.kind === "fact") {
			validityMap.set(r.id, {
				id: r.id,
				kind: "fact",
				effectiveStatus: "valid",
				isRefuted: false,
				isStale: false,
				isValid: true,
				assurance,
				subject,
				targetSha256,
			});
		} else if (r.kind === "unknown") {
			validityMap.set(r.id, {
				id: r.id,
				kind: "unknown",
				effectiveStatus: "pending",
				isRefuted: false,
				isStale: false,
				isValid: false,
				subject,
				targetSha256,
			});
		}
	}

	// 2. Second pass: evaluate hypotheses and their conclusion chains
	for (const r of records) {
		if (r.kind !== "hypothesis") continue;

		const hyp = r as HypothesisEvidence;
		const conclusions = conclusionsByHypothesis.get(hyp.id) ?? [];
		const subject = hyp.subject ?? hyp.context?.subject;
		const targetSha256 = hyp.targetSha256 ?? hyp.context?.executionBinding?.artifactSha256;
		const assurance = hyp.context?.assurance;

		if (conclusions.length === 0) {
			validityMap.set(hyp.id, {
				id: hyp.id,
				kind: "hypothesis",
				effectiveStatus: "pending",
				isRefuted: false,
				isStale: false,
				isValid: false,
				subject,
				targetSha256,
				assurance,
			});
		} else {
			const latestConc = conclusions[conclusions.length - 1];
			const isLatestRefuted = latestConc.status === "refuted";

			if (isLatestRefuted) {
				validityMap.set(hyp.id, {
					id: hyp.id,
					kind: "hypothesis",
					effectiveStatus: "refuted",
					isRefuted: true,
					isStale: false,
					isValid: false,
					refutedByConclusionId: latestConc.id,
					reason: `Refuted by subsequent conclusion ${latestConc.id}`,
					subject,
					targetSha256,
					assurance,
				});
			} else {
				// Effective assurance, subject, and target hash derive from active verifying conclusion
				const effectiveSubject = latestConc.subject ?? latestConc.context?.subject ?? subject;
				const effectiveHash =
					latestConc.targetSha256 ?? latestConc.context?.executionBinding?.artifactSha256 ?? targetSha256;
				const effectiveAssurance = latestConc.context?.assurance ?? hyp.context?.assurance;

				validityMap.set(hyp.id, {
					id: hyp.id,
					kind: "hypothesis",
					effectiveStatus: "verified",
					isRefuted: false,
					isStale: false,
					isValid: true,
					subject: effectiveSubject,
					targetSha256: effectiveHash,
					assurance: effectiveAssurance,
				});
			}

			// Process each conclusion for this hypothesis
			for (let i = 0; i < conclusions.length; i++) {
				const conc = conclusions[i];
				const isLast = i === conclusions.length - 1;
				const concSubject = conc.subject ?? conc.context?.subject ?? subject;
				const concHash = conc.targetSha256 ?? conc.context?.executionBinding?.artifactSha256 ?? targetSha256;
				const concAssurance = conc.context?.assurance;

				if (conc.status === "refuted") {
					validityMap.set(conc.id, {
						id: conc.id,
						kind: "conclusion",
						effectiveStatus: "refuted",
						isRefuted: true,
						isStale: false,
						isValid: false,
						subject: concSubject,
						targetSha256: concHash,
						assurance: concAssurance,
					});
				} else if (!isLast && isLatestRefuted) {
					// Prior verified conclusion superseded by later refutation
					validityMap.set(conc.id, {
						id: conc.id,
						kind: "conclusion",
						effectiveStatus: "stale",
						isRefuted: false,
						isStale: true,
						isValid: false,
						refutedByConclusionId: latestConc.id,
						reason: `Prior verified conclusion superseded by subsequent refutation ${latestConc.id}`,
						subject: concSubject,
						targetSha256: concHash,
						assurance: concAssurance,
					});
				} else if (!isLast) {
					// Prior verified conclusion superseded by newer verified conclusion
					validityMap.set(conc.id, {
						id: conc.id,
						kind: "conclusion",
						effectiveStatus: "stale",
						isRefuted: false,
						isStale: true,
						isValid: false,
						reason: `Superseded by newer conclusion ${latestConc.id}`,
						subject: concSubject,
						targetSha256: concHash,
						assurance: concAssurance,
					});
				} else {
					// Latest conclusion, status === "verified"
					validityMap.set(conc.id, {
						id: conc.id,
						kind: "conclusion",
						effectiveStatus: "verified",
						isRefuted: false,
						isStale: false,
						isValid: true,
						subject: concSubject,
						targetSha256: concHash,
						assurance: concAssurance,
					});
				}
			}
		}
	}

	// 3. Apply explicit invalidations
	for (const [targetId, invalidatorId] of explicitlyInvalidated.entries()) {
		const existing = validityMap.get(targetId);
		if (existing) {
			validityMap.set(targetId, {
				...existing,
				effectiveStatus: "stale",
				isStale: true,
				isValid: false,
				invalidatedBy: invalidatorId,
				reason: `Explicitly invalidated by conclusion ${invalidatorId}`,
			});
		}
	}

	// 4. Worklist-based transitive invalidation cascade (O(V+E) to complete resolution)
	const dependentsOf = new Map<string, Set<string>>();

	function addDep(sourceId: string, depId: string) {
		let set = dependentsOf.get(sourceId);
		if (!set) {
			set = new Set<string>();
			dependentsOf.set(sourceId, set);
		}
		set.add(depId);
	}

	for (const r of records) {
		if (r.kind === "hypothesis") {
			const hyp = r as HypothesisEvidence;
			if (hyp.facts && Array.isArray(hyp.facts)) {
				for (const fid of hyp.facts) {
					if (typeof fid === "string" && fid.trim().length > 0) {
						addDep(fid.trim(), hyp.id);
					}
				}
			}
			const hypConcs = conclusionsByHypothesis.get(hyp.id) ?? [];
			if (hypConcs.length > 0) {
				const latestC = hypConcs[hypConcs.length - 1];
				// Hypothesis validity depends on its active verifying conclusion
				addDep(latestC.id, hyp.id);
			}
		} else if (r.kind === "conclusion") {
			const conc = r as ConclusionEvidence;
			// Conclusion depends on its hypothesis
			addDep(conc.hypothesisId, conc.id);
		}
	}

	const queue: string[] = [];
	const visitedInvalid = new Set<string>();

	for (const [id, val] of validityMap.entries()) {
		if (val.isRefuted || val.isStale || !val.isValid) {
			if (val.isRefuted || val.isStale) {
				queue.push(id);
				visitedInvalid.add(id);
			}
		}
	}

	let qIdx = 0;
	while (qIdx < queue.length) {
		const currId = queue[qIdx++];
		const currVal = validityMap.get(currId);
		const deps = dependentsOf.get(currId);
		if (!deps) continue;

		for (const depId of deps) {
			const depVal = validityMap.get(depId);
			if (depVal && depVal.isValid) {
				validityMap.set(depId, {
					...depVal,
					effectiveStatus: "stale",
					isStale: true,
					isValid: false,
					reason: `Dependency '${currId}' is ${currVal?.isRefuted ? "refuted" : "stale"}`,
				});
				if (!visitedInvalid.has(depId)) {
					visitedInvalid.add(depId);
					queue.push(depId);
				}
			}
		}
	}

	return validityMap;
}

/**
 * Evaluates whether a set of evidence record IDs satisfies acceptance requirements.
 */
export async function evaluateEvidenceSupport(
	resolver: EvidenceRecordResolver | EvidenceRecord[],
	ids: string[],
	requirements: EvidenceRequirements = {},
): Promise<EvidenceSupportEvaluation> {
	if (ids.length === 0) {
		return {
			valid: false,
			reason: "No evidence records provided to satisfy support requirements",
			records: [],
			validityMap: {},
			refutedIds: [],
			staleIds: [],
			unverifiedIds: [],
			mismatchedSubjectIds: [],
			mismatchedHashIds: [],
			failedStageIds: [],
			nonExhaustiveNegativeIds: [],
			unmetAssuranceIds: [],
			unmetKindIds: [],
		};
	}

	// 1. Resolve records
	let allRecords: EvidenceRecord[] = [];
	const requestedRecords: EvidenceRecord[] = [];

	if (Array.isArray(resolver)) {
		allRecords = resolver;
		const idSet = new Set(ids);
		for (const r of allRecords) {
			if (idSet.has(r.id)) {
				requestedRecords.push(r);
			}
		}
	} else if (typeof resolver.getAllRecords === "function") {
		allRecords = await resolver.getAllRecords();
		const idSet = new Set(ids);
		for (const r of allRecords) {
			if (idSet.has(r.id)) {
				requestedRecords.push(r);
			}
		}
	} else {
		// Fetch requested IDs individually
		for (const id of ids) {
			const rec = await resolver.getRecord(id);
			if (rec) {
				requestedRecords.push(rec);
				allRecords.push(rec);
			}
		}
	}

	const validityMapObj: Record<string, CanonicalEvidenceValidity> = {};
	const validityMap = resolveEvidenceLedgerValidity(allRecords);
	for (const [k, v] of validityMap.entries()) {
		validityMapObj[k] = v;
	}

	const refutedIds: string[] = [];
	const staleIds: string[] = [];
	const unverifiedIds: string[] = [];
	const mismatchedSubjectIds: string[] = [];
	const mismatchedHashIds: string[] = [];
	const failedStageIds: string[] = [];
	const nonExhaustiveNegativeIds: string[] = [];
	const unmetAssuranceIds: string[] = [];
	const unmetKindIds: string[] = [];

	let highestAssurance: EvidenceAssuranceLevel | undefined;

	// Check if any requested ID was not found
	const foundIds = new Set(requestedRecords.map(r => r.id));
	const missingIds = ids.filter(id => !foundIds.has(id));

	if (missingIds.length > 0) {
		return {
			valid: false,
			reason: `Evidence records not found in ledger: ${missingIds.join(", ")}`,
			records: requestedRecords,
			validityMap: validityMapObj,
			refutedIds,
			staleIds,
			unverifiedIds,
			mismatchedSubjectIds,
			mismatchedHashIds,
			failedStageIds,
			nonExhaustiveNegativeIds,
			unmetAssuranceIds,
			unmetKindIds,
		};
	}

	for (const record of requestedRecords) {
		const validity = validityMap.get(record.id);

		// Check refuted
		if (validity?.isRefuted && !requirements.allowRefuted) {
			refutedIds.push(record.id);
		}

		// Check stale
		if (validity?.isStale) {
			staleIds.push(record.id);
		}

		// Check verified proof (reject pending hypotheses, unknowns, or invalid records)
		if (!validity || !validity.isValid) {
			if (!refutedIds.includes(record.id) && !staleIds.includes(record.id)) {
				unverifiedIds.push(record.id);
			}
		}

		// Check permitted kinds
		if (requirements.requiredKinds && requirements.requiredKinds.length > 0) {
			if (!requirements.requiredKinds.includes(record.kind)) {
				unmetKindIds.push(record.id);
			}
		}

		// Check subject (missing subject or mismatched subject fails)
		if (requirements.requiredSubject) {
			const recSubject = validity?.subject ?? record.subject ?? record.context?.subject;
			if (!recSubject || recSubject !== requirements.requiredSubject) {
				mismatchedSubjectIds.push(record.id);
			}
		}

		// Check conflicting recorded vs execution hashes (Finding 4)
		const recordedHash = record.targetSha256;
		const executionHash = record.context?.executionBinding?.artifactSha256;
		if (recordedHash && executionHash && recordedHash.toLowerCase() !== executionHash.toLowerCase()) {
			mismatchedHashIds.push(record.id);
		}

		// Check target hash
		if (requirements.requiredTargetSha256) {
			const recHash = validity?.targetSha256 ?? recordedHash ?? executionHash;
			if (!recHash || recHash.toLowerCase() !== requirements.requiredTargetSha256.toLowerCase()) {
				mismatchedHashIds.push(record.id);
			}
		}

		// Check compound stages (require zero exit code)
		if (requirements.requireZeroExitStages !== false) {
			const stages = record.context?.compoundStages;
			if (stages && Array.isArray(stages) && stages.length > 0) {
				const hasFailed = stages.some(s => s.exitCode !== 0 || s.status === "failed");
				if (hasFailed) {
					failedStageIds.push(record.id);
				}
			}
		}

		// Check negative scope exhaustiveness (must exist and be exhaustive when requested)
		if (requirements.requireExhaustiveNegative) {
			const neg = record.context?.negativeScope;
			if (!neg || !neg.isExhaustive) {
				nonExhaustiveNegativeIds.push(record.id);
			}
		}

		// Check assurance level (uses validity.assurance derived from active verification)
		const recAssurance = validity?.assurance ?? record.context?.assurance;
		if (recAssurance) {
			if (
				!highestAssurance ||
				(ASSURANCE_LEVEL_RANK[recAssurance] ?? 0) > (ASSURANCE_LEVEL_RANK[highestAssurance] ?? 0)
			) {
				highestAssurance = recAssurance;
			}
		}

		if (requirements.minAssurance) {
			const recRank = recAssurance ? (ASSURANCE_LEVEL_RANK[recAssurance] ?? 0) : 0;
			const minRank = ASSURANCE_LEVEL_RANK[requirements.minAssurance] ?? 0;
			if (recRank < minRank) {
				unmetAssuranceIds.push(record.id);
			}
		}
	}
	const reasons: string[] = [];
	if (refutedIds.length > 0) {
		reasons.push(`Evidence records are refuted: ${refutedIds.join(", ")}`);
	}
	if (staleIds.length > 0) {
		reasons.push(`Evidence records are stale or superseded: ${staleIds.join(", ")}`);
	}
	if (unverifiedIds.length > 0) {
		reasons.push(
			`Evidence records are not verified proof (pending hypothesis, unknown, or unverified): ${unverifiedIds.join(", ")}`,
		);
	}
	if (unmetKindIds.length > 0) {
		reasons.push(
			`Evidence records do not match permitted kinds [${requirements.requiredKinds?.join(", ")}]: ${unmetKindIds.join(", ")}`,
		);
	}
	if (mismatchedSubjectIds.length > 0) {
		reasons.push(
			`Evidence records do not match required subject '${requirements.requiredSubject}': ${mismatchedSubjectIds.join(", ")}`,
		);
	}
	if (mismatchedHashIds.length > 0) {
		reasons.push(
			`Evidence records do not match required target SHA-256 '${requirements.requiredTargetSha256}': ${mismatchedHashIds.join(", ")}`,
		);
	}
	if (failedStageIds.length > 0) {
		reasons.push(
			`Evidence records contain compound command stages with non-zero exit codes: ${failedStageIds.join(", ")}`,
		);
	}
	if (nonExhaustiveNegativeIds.length > 0) {
		reasons.push(`Evidence records contain non-exhaustive negative searches: ${nonExhaustiveNegativeIds.join(", ")}`);
	}
	if (unmetAssuranceIds.length > 0) {
		reasons.push(
			`Evidence records do not meet minimum assurance tier '${requirements.minAssurance}': ${unmetAssuranceIds.join(", ")}`,
		);
	}

	const isValid = reasons.length === 0;

	return {
		valid: isValid,
		...(reasons.length > 0 ? { reason: reasons.join("; ") } : {}),
		highestAssurance,
		records: requestedRecords,
		validityMap: validityMapObj,
		refutedIds,
		staleIds,
		unverifiedIds,
		mismatchedSubjectIds,
		mismatchedHashIds,
		failedStageIds,
		nonExhaustiveNegativeIds,
		unmetAssuranceIds,
		unmetKindIds,
	};
}
