import * as fs from "node:fs/promises";
import { openArchive, type ArchiveReader } from "@reverse/utils/ar";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { hashFile } from "../reverse-workspace/atomic";
import type {
	BuildSignatureInfo,
	BuildSignatureStatus,
	BuildVerificationResult,
	CumulativePatchRecord,
	PatchStatus,
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
						throw new ToolError(`Member '${normalizedMember}' in archive '${this.targetPath}' has no readable data.`);
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
export function resolveSignatureInfo(
	callerClaim?: { status?: BuildSignatureStatus; fingerprint?: string; scheme?: string; details?: string },
): BuildSignatureInfo {
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
			details: callerClaim.details ?? (callerClaim.fingerprint ? "declared, not cryptographically verified" : "unverified_signed_claim"),
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
				throw new ToolError(
					`Cannot retire patch '${r.patch_id}': patch does not exist in cumulative lineage.`,
				);
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
					throw new ToolError(
						`Retiring patch '${np.patch_id}' requires a non-empty retirement_reason.`,
					);
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
		if (!wf.build_lineage || wf.build_lineage.length === 0) continue;

		if (!wf.current_baseline_build_id) {
			reports.push({
				workflow_id: wf.id,
				target: wf.target,
				format: wf.format,
				base_target_sha256: wf.base_target_sha256 ?? wf.target_sha256,
				baseline_status: "no_baseline_established",
			});
			continue;
		}

		const baseline = wf.build_lineage.find(b => b.build_id === wf.current_baseline_build_id);
		if (!baseline) {
			reports.push({
				workflow_id: wf.id,
				target: wf.target,
				format: wf.format,
				base_target_sha256: wf.base_target_sha256 ?? wf.target_sha256,
				error: "CORRUPT_BASELINE_REFERENCE",
				current_baseline_build_id: wf.current_baseline_build_id,
				message: `Recorded current_baseline_build_id '${wf.current_baseline_build_id}' was not found in build_lineage manifest.`,
			});
			continue;
		}

		if (baseline.verification_result.static_status !== "verified") {
			reports.push({
				workflow_id: wf.id,
				target: wf.target,
				format: wf.format,
				base_target_sha256: wf.base_target_sha256 ?? wf.target_sha256,
				error: "BASELINE_VERIFICATION_FAILED",
				current_baseline_build_id: baseline.build_id,
				static_status: baseline.verification_result.static_status,
				failure_reason: baseline.verification_result.failure_reason,
			});
			continue;
		}

		const activePatches = baseline.cumulative_patches.filter(p => p.status === "active");
		const retiredPatches = baseline.cumulative_patches.filter(p => p.status === "retired");

		reports.push({
			workflow_id: wf.id,
			target: wf.target,
			format: wf.format,
			base_target_sha256: wf.base_target_sha256 ?? wf.target_sha256,
			active_baseline: {
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
			},
		});
	}

	if (reports.length === 0) return undefined;

	return [
		"### Reverse Workflow Verified Lineage & Baseline Manifest",
		"```json",
		JSON.stringify({ active_baselines: reports }, null, 2),
		"```",
	].join("\n");
}
