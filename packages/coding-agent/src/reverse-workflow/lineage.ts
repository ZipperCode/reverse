import * as fs from "node:fs/promises";
import * as path from "node:path";
import { openArchive, type ArchiveReader } from "@reverse/utils/ar";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { hashFile } from "../reverse-workspace/atomic";
import type {
	BuildArtifactRecord,
	BuildSignatureInfo,
	BuildSignatureStatus,
	BuildVerificationResult,
	CumulativePatchRecord,
	PatchStatus,
	ReverseWorkflowRecord,
} from "./contracts";
import { ReverseWorkflowStore } from "./store";

/**
 * Compute streaming SHA-256 hash of a file on disk without reading whole file into memory.
 */
export async function hashFileSha256(filePath: string): Promise<string> {
	const res = await hashFile(filePath);
	if (!res?.sha256) {
		throw new ToolError(`Failed to compute SHA-256 hash for file '${filePath}'.`);
	}
	return res.sha256;
}

/**
 * Scoped byte reader for an artifact target: opens archive once and caches uncompressed
 * members in memory; seek-reads plain binaries with bounds checking without loading entire file.
 */
export class TargetByteReader {
	private archiveReader?: ArchiveReader;
	private archiveOpened = false;
	private memberCache = new Map<string, Buffer>();

	constructor(readonly targetPath: string) {}

	async readSlice(memberPath: string | undefined, offset: number, length: number): Promise<Buffer> {
		if (offset < 0) {
			throw new ToolError(`Invalid negative offset 0x${offset.toString(16)} for '${this.targetPath}'.`);
		}
		if (length <= 0) return Buffer.alloc(0);

		const normalizedMember = memberPath?.trim().replace(/^\/+/, "");

		if (normalizedMember && normalizedMember.length > 0) {
			let memberBuf = this.memberCache.get(normalizedMember);
			if (!memberBuf) {
				if (!this.archiveOpened) {
					try {
						this.archiveReader = await openArchive(this.targetPath);
					} catch (err) {
						throw new ToolError(
							`Failed to open target archive '${this.targetPath}': ${err instanceof Error ? err.message : String(err)}`,
						);
					}
					this.archiveOpened = true;
				}

				if (!this.archiveReader) {
					throw new ToolError(`Archive reader unavailable for '${this.targetPath}'.`);
				}

				try {
					const memberFile = await this.archiveReader.readFile(normalizedMember);
					if (!memberFile || !memberFile.bytes) {
						throw new ToolError(
							`Member '${normalizedMember}' in archive '${this.targetPath}' has no readable data.`,
						);
					}
					memberBuf = Buffer.from(
						memberFile.bytes.buffer,
						memberFile.bytes.byteOffset,
						memberFile.bytes.byteLength,
					);
					this.memberCache.set(normalizedMember, memberBuf);
				} catch (err) {
					if (err instanceof ToolError) throw err;
					throw new ToolError(
						`Failed to read member '${normalizedMember}' from '${this.targetPath}': ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}

			if (offset + length > memberBuf.length) {
				throw new ToolError(
					`Requested slice [0x${offset.toString(16)}, 0x${(offset + length).toString(16)}) exceeds member '${normalizedMember}' size (${memberBuf.length} bytes).`,
				);
			}

			return memberBuf.subarray(offset, offset + length);
		}

		// Plain binary: open handle and seek-read range
		let handle;
		try {
			handle = await fs.open(this.targetPath, "r");
		} catch (err) {
			throw new ToolError(
				`Failed to open target binary '${this.targetPath}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		try {
			const stat = await handle.stat();
			if (offset + length > stat.size) {
				throw new ToolError(
					`Requested slice [0x${offset.toString(16)}, 0x${(offset + length).toString(16)}) exceeds binary '${this.targetPath}' size (${stat.size} bytes).`,
				);
			}
			const buf = Buffer.alloc(length);
			const { bytesRead } = await handle.read(buf, 0, length, offset);
			if (bytesRead !== length) {
				throw new ToolError(
					`Expected ${length} bytes at offset 0x${offset.toString(16)} in '${this.targetPath}', read ${bytesRead} bytes.`,
				);
			}
			return buf;
		} finally {
			await handle.close();
		}
	}
}

/**
 * Resolve signature information preserving explicit signed, unsigned, and unknown states.
 * Caller-declared fingerprints are noted as declared without claiming unverified host cert validity.
 */
export function resolveSignatureInfo(callerClaim?: {
	status?: BuildSignatureStatus;
	fingerprint?: string;
	scheme?: string;
	details?: string;
}): BuildSignatureInfo {
	if (!callerClaim) {
		return { status: "unknown", details: "No signature metadata declared" };
	}

	const status = callerClaim.status ?? (callerClaim.fingerprint ? "signed" : "unknown");

	if (status === "unsigned") {
		return { status: "unsigned", details: callerClaim.details ?? "Artifact explicitly marked unsigned" };
	}

	if (status === "signed") {
		return {
			status: "signed",
			scheme: callerClaim.scheme,
			fingerprint: callerClaim.fingerprint,
			details:
				callerClaim.details ??
				(callerClaim.fingerprint ? "declared, not cryptographically verified" : "unverified_signed_claim"),
		};
	}

	return {
		status: "unknown",
		scheme: callerClaim.scheme,
		fingerprint: callerClaim.fingerprint,
		details: callerClaim.details ?? "Signature status unknown",
	};
}

/**
 * Verify that all active cumulative patches match expected bytes in target artifact.
 * Uses a single cached reader session for archive targets and seek-reads for raw binaries.
 */
export async function verifyActivePatches(
	targetPath: string,
	cumulativePatches: CumulativePatchRecord[],
): Promise<BuildVerificationResult> {
	let checkedCount = 0;
	const reader = new TargetByteReader(targetPath);

	for (const patch of cumulativePatches) {
		if (patch.status === "retired") continue;

		const cleanExpectedHex = patch.expected_bytes.replace(/\s+/g, "").toLowerCase();
		if (!cleanExpectedHex || cleanExpectedHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(cleanExpectedHex)) {
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: "pending",
				checked_patches_count: checkedCount,
				failed_patch_id: patch.patch_id,
				failure_reason: `Invalid expected_bytes hex string for patch '${patch.patch_id}': '${patch.expected_bytes}'`,
			};
		}

		const expectedLen = cleanExpectedHex.length / 2;
		let actualBytes: Buffer;
		try {
			actualBytes = await reader.readSlice(patch.member_path, patch.offset, expectedLen);
		} catch (err) {
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: "pending",
				checked_patches_count: checkedCount,
				failed_patch_id: patch.patch_id,
				failure_reason: `Failed to read target bytes for patch '${patch.patch_id}': ${err instanceof Error ? err.message : String(err)}`,
			};
		}

		const actualHex = actualBytes.toString("hex").toLowerCase();
		if (actualHex !== cleanExpectedHex) {
			const memberLabel = patch.member_path ? `'${patch.member_path}'` : "binary";
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: "pending",
				checked_patches_count: checkedCount,
				failed_patch_id: patch.patch_id,
				failure_reason: `Byte mismatch at ${memberLabel} offset 0x${patch.offset.toString(16)}: expected '${cleanExpectedHex}', found '${actualHex}'`,
			};
		}

		checkedCount++;
	}

	return {
		status: "verified",
		static_status: "verified",
		runtime_status: "pending",
		checked_patches_count: checkedCount,
		verified_at: new Date().toISOString(),
	};
}

/**
 * Verify that declared original_bytes match the actual parent or clean base source file.
 */
export async function verifySourceOriginalBytes(
	sourcePath: string,
	newPatches: Array<{
		patch_id: string;
		member_path?: string;
		offset: number;
		original_bytes: string;
		status?: PatchStatus;
	}>,
): Promise<void> {
	const reader = new TargetByteReader(sourcePath);

	for (const p of newPatches) {
		if (p.status === "retired") continue;
		const cleanOrigHex = p.original_bytes.replace(/\s+/g, "").toLowerCase();
		if (cleanOrigHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(cleanOrigHex)) {
			throw new ToolError(`Invalid original_bytes hex string for patch '${p.patch_id}': '${p.original_bytes}'`);
		}

		const origLen = cleanOrigHex.length / 2;
		let actualBytes: Buffer;
		try {
			actualBytes = await reader.readSlice(p.member_path, p.offset, origLen);
		} catch (err) {
			throw new ToolError(
				`Failed to verify source original_bytes for patch '${p.patch_id}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		const actualHex = actualBytes.toString("hex").toLowerCase();
		if (actualHex !== cleanOrigHex) {
			const memberLabel = p.member_path ? `'${p.member_path}'` : "binary";
			throw new ToolError(
				`Patch '${p.patch_id}' original_bytes mismatch against source at ${memberLabel} offset 0x${p.offset.toString(16)}: expected '${cleanOrigHex}', found '${actualHex}'. Unverified original bytes rejected.`,
			);
		}
	}
}

/**
 * Combine inherited parent cumulative patches with new patches and explicit retirements.
 * Ensures prior revisions in history are NEVER mutated.
 * Rejects silent patch ID identity collisions and overlapping spans on the same member.
 */
export function accumulatePatches(
	parentPatches: CumulativePatchRecord[] | undefined,
	newPatches:
		| Array<{
				patch_id: string;
				member_path?: string;
				offset: number;
				original_bytes: string;
				expected_bytes: string;
				status?: PatchStatus;
				retirement_reason?: string;
				evidence_id?: string;
		  }>
		| undefined,
	retirements: Array<{ patch_id: string; reason: string }> | undefined,
	currentBuildId: string,
): CumulativePatchRecord[] {
	const patchMap = new Map<string, CumulativePatchRecord>();
	const now = new Date().toISOString();

	// 1. Inherit parent patches (deep copy to preserve historical immutability)
	if (parentPatches) {
		for (const p of parentPatches) {
			patchMap.set(p.patch_id, {
				patch_id: p.patch_id,
				member_path: p.member_path,
				offset: p.offset,
				original_bytes: p.original_bytes,
				expected_bytes: p.expected_bytes,
				status: p.status,
				retirement_reason: p.retirement_reason,
				retired_at: p.retired_at,
				retired_in_build_id: p.retired_in_build_id,
				evidence_id: p.evidence_id,
				created_at: p.created_at,
			});
		}
	}

	// 2. Apply explicit retirements for this build revision
	if (retirements) {
		for (const r of retirements) {
			if (!r.reason || r.reason.trim().length === 0) {
				throw new ToolError(`Retiring patch '${r.patch_id}' requires a non-empty retirement reason.`);
			}
			const existing = patchMap.get(r.patch_id);
			if (!existing) {
				throw new ToolError(`Cannot retire patch '${r.patch_id}': patch does not exist in cumulative lineage.`);
			}
			existing.status = "retired";
			existing.retirement_reason = r.reason.trim();
			existing.retired_at = now;
			existing.retired_in_build_id = currentBuildId;
		}
	}

	// 3. Add or update new patches for this revision with collision guards
	if (newPatches) {
		for (const np of newPatches) {
			const cleanOriginal = np.original_bytes.replace(/\s+/g, "").toLowerCase();
			const cleanExpected = np.expected_bytes.replace(/\s+/g, "").toLowerCase();
			const isRetired = np.status === "retired";

			if (isRetired) {
				if (!np.retirement_reason || np.retirement_reason.trim().length === 0) {
					throw new ToolError(`Retiring patch '${np.patch_id}' requires a non-empty retirement_reason.`);
				}
				const existing = patchMap.get(np.patch_id);
				if (!existing) {
					throw new ToolError(
						`Cannot declare retired patch '${np.patch_id}': patch does not exist in cumulative lineage to retire.`,
					);
				}
				existing.status = "retired";
				existing.retirement_reason = np.retirement_reason.trim();
				existing.retired_at = now;
				existing.retired_in_build_id = currentBuildId;
				continue;
			}

			const existing = patchMap.get(np.patch_id);
			if (existing && existing.status === "active") {
				const existingMember = existing.member_path ?? "";
				const newMember = np.member_path ?? "";
				if (
					existingMember !== newMember ||
					existing.offset !== np.offset ||
					existing.original_bytes !== cleanOriginal ||
					existing.expected_bytes !== cleanExpected
				) {
					throw new ToolError(
						`Patch '${np.patch_id}' identity collision: patch already exists in cumulative lineage with a different definition. To replace an existing patch, explicitly retire it with a retirement reason and register a new patch_id.`,
					);
				}
				// Same definition: idempotent re-declaration!
				if (np.evidence_id) {
					existing.evidence_id = np.evidence_id;
				}
				continue;
			}

			patchMap.set(np.patch_id, {
				patch_id: np.patch_id,
				member_path: np.member_path,
				offset: np.offset,
				original_bytes: cleanOriginal,
				expected_bytes: cleanExpected,
				status: "active",
				evidence_id: np.evidence_id,
				created_at: now,
			});
		}
	}

	const accumulated = Array.from(patchMap.values());

	// 4. Validate non-overlapping spans among active patches targeting the same container member (case-sensitive)
	const activeByMember = new Map<string, Array<{ id: string; offset: number; len: number }>>();
	for (const p of accumulated) {
		if (p.status !== "active") continue;
		const memberKey = p.member_path ?? "";
		const len = p.expected_bytes.replace(/\s+/g, "").length / 2;
		const list = activeByMember.get(memberKey) ?? [];
		list.push({ id: p.patch_id, offset: p.offset, len });
		activeByMember.set(memberKey, list);
	}
	for (const [memberKey, patches] of activeByMember.entries()) {
		if (patches.length <= 1) continue;
		patches.sort((a, b) => a.offset - b.offset);
		for (let i = 0; i < patches.length - 1; i++) {
			const p1 = patches[i]!;
			const p2 = patches[i + 1]!;
			if (p1.offset + p1.len > p2.offset) {
				const memberLabel = memberKey ? `'${memberKey}'` : "binary";
				throw new ToolError(
					`Overlapping active patches detected on ${memberLabel} between '${p1.id}' [0x${p1.offset.toString(16)}, 0x${(p1.offset + p1.len).toString(16)}) and '${p2.id}' [0x${p2.offset.toString(16)}, 0x${(p2.offset + p2.len).toString(16)}). Overlapping patches must explicitly retire earlier patch or declare non-overlapping spans.`,
				);
			}
		}
	}

	return accumulated;
}

/**
 * Format active build lineage and verified baseline for compaction recovery context.
 * Exposes manifest IDs, hashes, cumulative active patches, and bound evidence without relying on filenames.
 */
export async function formatBuildLineageContext(
	repoRoot: string,
	options?: { stateRoot?: string },
): Promise<string | undefined> {
	const store = new ReverseWorkflowStore({ repositoryRoot: repoRoot, stateRoot: options?.stateRoot });
	const workflows = await store.list({ readOnly: true });

	if (!workflows || workflows.length === 0) {
		return undefined;
	}

	const reports: Record<string, unknown>[] = [];

	for (const wf of workflows) {
		if (wf.status !== "active") continue;

		const metadata = (wf.metadata as Record<string, unknown> | undefined) ?? {};
		const hasLineage = Array.isArray(wf.build_lineage) && wf.build_lineage.length > 0;
		const rawAcceptance = metadata.acceptance as Record<string, unknown[]> | undefined;
		const hasAcceptance = rawAcceptance && typeof rawAcceptance === "object" && Object.keys(rawAcceptance).length > 0;
		const rawConstraints = metadata.target_device_constraints as Record<string, unknown> | undefined;
		const hasConstraints =
			rawConstraints && typeof rawConstraints === "object" && Object.keys(rawConstraints).length > 0;
		const rawDeps = metadata.dependencies as unknown[] | undefined;
		const hasDeps = Array.isArray(rawDeps) && rawDeps.length > 0;

		if (!hasLineage && !hasAcceptance && !hasConstraints && !hasDeps) {
			continue;
		}

		const wfReport: Record<string, unknown> = {
			workflow_id: wf.id,
			target: wf.target,
			format: wf.format,
			base_target_sha256: wf.base_target_sha256 ?? wf.target_sha256,
		};

		if (hasLineage) {
			if (!wf.current_baseline_build_id) {
				wfReport.baseline_status = "no_baseline_established";
			} else {
				const baseline = wf.build_lineage!.find(b => b.build_id === wf.current_baseline_build_id);
				if (!baseline) {
					wfReport.error = "CORRUPT_BASELINE_REFERENCE";
					wfReport.current_baseline_build_id = wf.current_baseline_build_id;
					wfReport.message = `Recorded current_baseline_build_id '${wf.current_baseline_build_id}' was not found in build_lineage manifest.`;
				} else if (baseline.verification_result.static_status !== "verified") {
					wfReport.error = "BASELINE_VERIFICATION_FAILED";
					wfReport.current_baseline_build_id = baseline.build_id;
					wfReport.static_status = baseline.verification_result.static_status;
					wfReport.failure_reason = baseline.verification_result.failure_reason;
				} else {
					const activePatches = baseline.cumulative_patches.filter(p => p.status === "active");
					const retiredPatches = baseline.cumulative_patches.filter(p => p.status === "retired");

					wfReport.active_baseline = {
						build_id: baseline.build_id,
						target_path: baseline.target_path,
						output_sha256: baseline.output_sha256,
						parent_sha256: baseline.parent_sha256,
						parent_build_id: baseline.parent_build_id,
						static_status: baseline.verification_result.static_status,
						runtime_status: baseline.verification_result.runtime_status,
						signature: {
							status: baseline.signature.status,
							scheme: baseline.signature.scheme,
							fingerprint: baseline.signature.fingerprint,
						},
						active_patches_count: activePatches.length,
						active_patches: activePatches.slice(0, 50).map(p => ({
							patch_id: p.patch_id,
							member_path: p.member_path,
							offset: p.offset,
							expected_bytes: p.expected_bytes,
						})),
						has_more_active_patches: activePatches.length > 50,
						retired_patches: retiredPatches.map(r => ({
							patch_id: r.patch_id,
							reason: r.retirement_reason,
						})),
						runtime_evidence_ids: baseline.runtime_evidence_ids ?? [],
					};
				}
			}
		}

		if (hasAcceptance) {
			const allCriteria: Record<string, unknown>[] = [];
			for (const [stepId, criteriaList] of Object.entries(rawAcceptance!)) {
				if (Array.isArray(criteriaList)) {
					for (const c of criteriaList) {
						if (c && typeof c === "object" && "id" in c) {
							const rec = c as Record<string, unknown>;
							allCriteria.push({
								id: rec.id,
								step_id: rec.step_id ?? stepId,
								title: rec.title,
								subject: rec.subject,
								status: rec.status ?? "pending",
								required_evidence_types: rec.required_evidence_types,
								min_assurance: rec.min_assurance,
								satisfied_by_evidence_ids: rec.satisfied_by_evidence_ids,
								is_proxy: rec.is_proxy,
							});
						}
					}
				}
			}
			const criteriaCap = 50;
			const pendingCount = allCriteria.filter(c => c.status === "pending").length;
			const satisfiedCount = allCriteria.filter(
				c => c.status === "satisfied" || c.status === "proxy_verified",
			).length;
			wfReport.acceptance = {
				total_criteria: allCriteria.length,
				pending_count: pendingCount,
				satisfied_count: satisfiedCount,
				criteria: allCriteria.slice(0, criteriaCap),
				...(allCriteria.length > criteriaCap
					? {
							has_more: true,
							omitted_count: allCriteria.length - criteriaCap,
							omitted_pending_ids: allCriteria
								.slice(criteriaCap)
								.filter(c => c.status === "pending")
								.map(c => c.id as string),
						}
					: {}),
			};
		}

		if (hasConstraints) {
			wfReport.target_device_constraints = rawConstraints;
		}

		if (hasDeps) {
			const depList: Record<string, unknown>[] = [];
			for (const d of rawDeps!) {
				if (d && typeof d === "object" && "id" in d) {
					const dep = d as Record<string, unknown>;
					depList.push({
						id: dep.id,
						name: dep.name,
						kind: dep.kind,
						scope: dep.scope,
						target_host: dep.target_host,
						approved_for_delivery: dep.approved_for_delivery,
						approved_for_experiment: dep.approved_for_experiment,
					});
				}
			}
			const depCap = 30;
			wfReport.dependencies = {
				total_dependencies: depList.length,
				items: depList.slice(0, depCap),
				...(depList.length > depCap
					? {
							has_more: true,
							omitted_count: depList.length - depCap,
						}
					: {}),
			};
		}
		const rawActiveProof = metadata.active_proof as Record<string, string[]> | undefined;
		if (rawActiveProof && typeof rawActiveProof === "object" && Object.keys(rawActiveProof).length > 0) {
			wfReport.active_proof = rawActiveProof;
		}

		reports.push(wfReport);
	}

	if (reports.length === 0) return undefined;

	return [
		"### Reverse Workflow Verified Lineage & Baseline Manifest",
		"```json",
		JSON.stringify({ active_baselines: reports }, null, 2),
		"```",
	].join("\n");
}

export interface ActiveBaselineResolution {
	store: ReverseWorkflowStore;
	workflow: ReverseWorkflowRecord | null;
	baseline: BuildArtifactRecord | null;
	activePatches: CumulativePatchRecord[];
	baseTargetSha256?: string;
}

/**
 * Automatically link an input sample or explicit workflow ID to an active workflow baseline.
 * Matches by explicit workflowId, or by matching sample path or SHA256 against workflow targets
 * and registered build lineage. Rejects ambiguous matches with a clear ToolError.
 */
export async function resolveActiveWorkflowBaseline(
	repoRoot: string,
	options: {
		workflowId?: string;
		targetPath?: string;
		targetSha256?: string;
		stateRoot?: string;
	} = {},
): Promise<ActiveBaselineResolution> {
	const store = new ReverseWorkflowStore({ repositoryRoot: repoRoot, stateRoot: options.stateRoot });

	if (options.workflowId) {
		const wf = await store.get(options.workflowId);
		if (!wf) {
			throw new ToolError(`Workflow '${options.workflowId}' not found.`);
		}
		// Validate that the target input belongs to this workflow (original base or registered derivative)
		const targetHash = options.targetSha256?.toLowerCase();
		const baseHash = (wf.base_target_sha256 ?? wf.target_sha256)?.toLowerCase();
		const lineageHashes = (wf.build_lineage ?? []).map(b => b.output_sha256.toLowerCase());

		if (targetHash) {
			const hashMatches = baseHash === targetHash || lineageHashes.includes(targetHash);
			if (!hashMatches) {
				let pathMatches = false;
				if (options.targetPath) {
					const normInput = path.resolve(repoRoot, options.targetPath);
					const normBase = path.resolve(repoRoot, wf.target);
					if (normInput === normBase) {
						pathMatches = true;
					} else {
						pathMatches = (wf.build_lineage ?? []).some(b => path.resolve(repoRoot, b.target_path) === normInput);
					}
				}
				if (!pathMatches) {
					throw new ToolError(
						`Input sample does not belong to workflow '${wf.id}': SHA-256 '${options.targetSha256}' matches neither original base nor registered derivative builds.`,
					);
				}
			}
		}

		const baseline = await store.getBaseline(wf.id);
		const retiredPatchIds = new Set((wf.retired_patches_audit ?? []).map(r => r.patch_id));
		const activePatches = (baseline?.cumulative_patches ?? []).filter(
			p => p.status === "active" && !retiredPatchIds.has(p.patch_id),
		);
		return {
			store,
			workflow: wf,
			baseline,
			activePatches,
			baseTargetSha256: wf.base_target_sha256 ?? wf.target_sha256,
		};
	}

	const workflows = await store.list({ readOnly: true });
	if (workflows.length === 0) {
		return { store, workflow: null, baseline: null, activePatches: [] };
	}

	const targetHash = options.targetSha256?.toLowerCase();
	const normInputPath = options.targetPath ? path.resolve(repoRoot, options.targetPath) : undefined;

	const matched: ReverseWorkflowRecord[] = [];
	for (const wf of workflows) {
		let match = false;

		// Exact SHA-256 identity check against base target or any build in lineage
		if (targetHash) {
			const baseHash = (wf.base_target_sha256 ?? wf.target_sha256)?.toLowerCase();
			if (baseHash === targetHash) {
				match = true;
			} else if (wf.build_lineage?.some(b => b.output_sha256.toLowerCase() === targetHash)) {
				match = true;
			}
		}

		// Exact normalized filesystem path check against base target or any build in lineage
		if (!match && normInputPath) {
			const normBase = path.resolve(repoRoot, wf.target);
			if (normBase === normInputPath) {
				match = true;
			} else if (wf.build_lineage?.some(b => path.resolve(repoRoot, b.target_path) === normInputPath)) {
				match = true;
			}
		}

		if (match) {
			matched.push(wf);
		}
	}

	if (matched.length > 1) {
		const ids = matched.map(m => m.id).join(", ");
		throw new ToolError(
			`Multiple reverse workflows match input target. Please provide 'workflow_id' to disambiguate: ${ids}`,
		);
	}

	if (matched.length === 1) {
		const wf = matched[0]!;
		const baseline = await store.getBaseline(wf.id);
		const retiredPatchIds = new Set((wf.retired_patches_audit ?? []).map(r => r.patch_id));
		const activePatches = (baseline?.cumulative_patches ?? []).filter(
			p => p.status === "active" && !retiredPatchIds.has(p.patch_id),
		);
		return {
			store,
			workflow: wf,
			baseline,
			activePatches,
			baseTargetSha256: wf.base_target_sha256 ?? wf.target_sha256,
		};
	}

	return { store, workflow: null, baseline: null, activePatches: [] };
}

/**
 * Verify that an artifact preserves all active baseline patches before publication or promotion.
 * Throws a detailed ToolError if any active baseline patch was dropped or modified.
 */
export async function assertArtifactPreservesBaseline(
	artifactPath: string,
	activePatches: CumulativePatchRecord[],
	contextLabel?: string,
): Promise<BuildVerificationResult> {
	if (!activePatches || activePatches.length === 0) {
		return {
			status: "verified",
			static_status: "verified",
			runtime_status: "pending",
			checked_patches_count: 0,
			verified_at: new Date().toISOString(),
		};
	}

	const verificationResult = await verifyActivePatches(artifactPath, activePatches);
	if (verificationResult.status !== "verified") {
		const label = contextLabel ? ` (${contextLabel})` : "";
		throw new ToolError(
			`Artifact baseline verification failed${label}: Active patch '${verificationResult.failed_patch_id}' was dropped or mismatched: ${verificationResult.failure_reason}. Repack from original base or incremental modifications must retain all active cumulative patches (replay A+B) or explicitly retire them.`,
		);
	}
	return verificationResult;
}
