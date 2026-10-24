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
import {
	isPackageSetManifest,
	parseAndValidatePackageSetManifest,
	resolvePackageSetInput,
	type ValidatedPackageSetManifest,
} from "./package-set";

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

	private initialized = false;
	private isPackageSet = false;
	private packageSetValidation?: ValidatedPackageSetManifest;
	private packageMemberReaders = new Map<string, ArchiveReader>();
	private packageMemberCaches = new Map<string, Map<string, Buffer>>();

	constructor(
		readonly targetPath: string,
		private readonly rawPackageSet?: {
			base: string;
			splits?: Record<string, string>;
		},
	) {}

	/**
	 * Initialize reader and verify target integrity.
	 * For package sets: strictly parses manifest, verifies directory containment & symlinks,
	 * verifies on-disk sizes and streaming SHA-256 for all members, and checks aggregate set_sha256.
	 * Runs even when zero active patches are present so mutated members cannot be concealed.
	 */
	async initAndVerify(): Promise<void> {
		if (this.initialized) return;

		const isPkg = await isPackageSetManifest(this.targetPath);
		if (isPkg) {
			this.isPackageSet = true;
			this.packageSetValidation = await parseAndValidatePackageSetManifest(this.targetPath);
			this.initialized = true;
			return;
		}

		if (this.rawPackageSet) {
			const resolvedRaw = await resolvePackageSetInput(
				path.dirname(path.resolve(this.targetPath)),
				this.rawPackageSet,
			);
			this.isPackageSet = true;
			this.packageSetValidation = {
				manifest: {
					format: "apk_package_set",
					package: resolvedRaw.package ?? "raw_package_set",
					versionCode: resolvedRaw.versionCode ?? 1,
					set_sha256: resolvedRaw.setSha256,
					members: resolvedRaw.members,
				},
				manifestSha256: resolvedRaw.manifestSha256 ?? "",
				manifestDir: path.dirname(path.resolve(this.targetPath)),
				memberPaths: resolvedRaw.memberPaths,
			};
			this.initialized = true;
			return;
		}

		try {
			await fs.access(this.targetPath, fs.constants.R_OK);
		} catch (err) {
			throw new ToolError(
				`Target file '${this.targetPath}' does not exist or is not readable: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		this.initialized = true;
	}

	async readSlice(
		memberPath: string | undefined,
		offset: number,
		length: number,
		packageMember?: string,
	): Promise<Buffer> {
		if (offset < 0) {
			throw new ToolError(`Invalid negative offset 0x${offset.toString(16)} for '${this.targetPath}'.`);
		}
		if (length <= 0) return Buffer.alloc(0);

		if (!this.initialized) {
			await this.initAndVerify();
		}

		if (this.isPackageSet) {
			const memberInfo = this.packageSetValidation!;
			const targetPkgMember = packageMember?.trim() || "base";
			const effectiveEntry = memberPath?.trim().replace(/^\/+/, "");

			const memberApkPath = memberInfo.memberPaths.get(targetPkgMember);
			if (!memberApkPath) {
				const available = Array.from(memberInfo.memberPaths.keys()).join(", ");
				throw new ToolError(
					`Package member '${targetPkgMember}' not found in package set manifest '${this.targetPath}'. Available members: ${available}`,
				);
			}

			if (!effectiveEntry || effectiveEntry.length === 0) {
				throw new ToolError(
					`Package set member '${targetPkgMember}' requires a non-empty container member_path (e.g. 'classes.dex', 'lib/arm64-v8a/...').`,
				);
			}

			let entryCache = this.packageMemberCaches.get(targetPkgMember);
			if (!entryCache) {
				entryCache = new Map<string, Buffer>();
				this.packageMemberCaches.set(targetPkgMember, entryCache);
			}

			let memberBuf = entryCache.get(effectiveEntry);
			if (!memberBuf) {
				let reader = this.packageMemberReaders.get(targetPkgMember);
				if (!reader) {
					try {
						reader = await openArchive(memberApkPath);
					} catch (err) {
						throw new ToolError(
							`Failed to open package member archive '${memberApkPath}': ${err instanceof Error ? err.message : String(err)}`,
						);
					}
					this.packageMemberReaders.set(targetPkgMember, reader);
				}

				try {
					const memberFile = await reader.readFile(effectiveEntry);
					if (!memberFile || !memberFile.bytes) {
						throw new ToolError(
							`Entry '${effectiveEntry}' in member '${targetPkgMember}' archive '${memberApkPath}' has no readable data.`,
						);
					}
					memberBuf = Buffer.from(
						memberFile.bytes.buffer,
						memberFile.bytes.byteOffset,
						memberFile.bytes.byteLength,
					);
					entryCache.set(effectiveEntry, memberBuf);
				} catch (err) {
					if (err instanceof ToolError) throw err;
					throw new ToolError(
						`Failed to read entry '${effectiveEntry}' from member '${targetPkgMember}' ('${memberApkPath}'): ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}

			if (offset + length > memberBuf.length) {
				throw new ToolError(
					`Requested slice [0x${offset.toString(16)}, 0x${(offset + length).toString(16)}) exceeds entry '${effectiveEntry}' in member '${targetPkgMember}' size (${memberBuf.length} bytes).`,
				);
			}

			return memberBuf.subarray(offset, offset + length);
		}

		const reqMember = packageMember?.trim();
		if (reqMember && reqMember !== "base") {
			throw new ToolError(
				`Cannot access package member '${reqMember}' on non-package-set target '${this.targetPath}'. Target must be a valid package set manifest declaring member '${reqMember}'.`,
			);
		}
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

	try {
		await reader.initAndVerify();
	} catch (err) {
		return {
			status: "failed",
			static_status: "failed",
			runtime_status: "pending",
			checked_patches_count: 0,
			failure_reason: `Target verification failed for '${targetPath}': ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	for (const patch of cumulativePatches) {
		if (patch.status === "retired") continue;

		if (!Number.isSafeInteger(patch.offset) || patch.offset < 0) {
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: "pending",
				checked_patches_count: checkedCount,
				failed_patch_id: patch.patch_id,
				failure_reason: `Invalid or missing offset for patch '${patch.patch_id}': '${patch.offset}'. Offsets must be non-negative safe integers.`,
			};
		}

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
			actualBytes = await reader.readSlice(patch.member_path, patch.offset, expectedLen, patch.package_member);
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
			const memberLabel = [patch.package_member, patch.member_path].filter(Boolean).join("!/") || "binary";
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: "pending",
				checked_patches_count: checkedCount,
				failed_patch_id: patch.patch_id,
				failure_reason: `Byte mismatch at '${memberLabel}' offset 0x${patch.offset.toString(16)}: expected '${cleanExpectedHex}', found '${actualHex}'`,
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
		package_member?: string;
		member_path?: string;
		offset: number;
		original_bytes: string;
		status?: PatchStatus;
	}>,
	rawPackageSet?: {
		base: string;
		splits?: Record<string, string>;
	},
): Promise<void> {
	const reader = new TargetByteReader(sourcePath, rawPackageSet);
	await reader.initAndVerify();

	for (const p of newPatches) {
		if (p.status === "retired") continue;
		if (!Number.isSafeInteger(p.offset) || p.offset < 0) {
			throw new ToolError(
				`Invalid or missing offset for patch '${p.patch_id}': '${p.offset}'. Offsets must be non-negative safe integers.`,
			);
		}

		const cleanOrigHex = p.original_bytes.replace(/\s+/g, "").toLowerCase();
		if (cleanOrigHex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(cleanOrigHex)) {
			throw new ToolError(`Invalid original_bytes hex string for patch '${p.patch_id}': '${p.original_bytes}'`);
		}

		const origLen = cleanOrigHex.length / 2;
		let actualBytes: Buffer;
		try {
			actualBytes = await reader.readSlice(p.member_path, p.offset, origLen, p.package_member);
		} catch (err) {
			throw new ToolError(
				`Failed to verify source original_bytes for patch '${p.patch_id}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		const actualHex = actualBytes.toString("hex").toLowerCase();
		if (actualHex !== cleanOrigHex) {
			const memberLabel = [p.package_member, p.member_path].filter(Boolean).join("!/") || "binary";
			throw new ToolError(
				`Patch '${p.patch_id}' original_bytes mismatch against source at '${memberLabel}' offset 0x${p.offset.toString(16)}: expected '${cleanOrigHex}', found '${actualHex}'. Unverified original bytes rejected.`,
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
				package_member?: string;
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
				package_member: p.package_member,
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

			if (!isRetired && (!Number.isSafeInteger(np.offset) || np.offset < 0)) {
				throw new ToolError(
					`Invalid or missing offset for patch '${np.patch_id}': '${np.offset}'. Offsets must be non-negative safe integers.`,
				);
			}
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
				const normExistingPkg = existing.package_member?.trim() || "base";
				const normNewPkg = np.package_member?.trim() || "base";
				const hasPkg = Boolean(existing.package_member || np.package_member);
				const pkgMismatch = hasPkg ? normExistingPkg !== normNewPkg : false;
				const existingMember = existing.member_path ?? "";
				const newMember = np.member_path ?? "";
				if (
					pkgMismatch ||
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
				if (np.package_member && !existing.package_member) {
					existing.package_member = np.package_member;
				}
				if (np.evidence_id) {
					existing.evidence_id = np.evidence_id;
				}
				continue;
			}

			patchMap.set(np.patch_id, {
				patch_id: np.patch_id,
				package_member: np.package_member,
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
	const hasAnyPackageMember = accumulated.some(p => Boolean(p.package_member));
	const activeByMember = new Map<string, Array<{ id: string; offset: number; len: number }>>();
	for (const p of accumulated) {
		if (p.status !== "active") continue;
		let memberKey: string;
		if (hasAnyPackageMember) {
			const pkg = p.package_member?.trim() || "base";
			memberKey = `${pkg}!/${p.member_path ?? ""}`;
		} else {
			memberKey = p.member_path ?? "";
		}
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
							package_member: p.package_member,
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
	packageSet?: {
		manifestPath: string;
		manifestSha256: string;
		setSha256: string;
	};
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
		packageSet?: { base: string; splits?: Record<string, string> } | string;
		setSha256?: string;
		manifestSha256?: string;
		stateRoot?: string;
	} = {},
): Promise<ActiveBaselineResolution> {
	const store = new ReverseWorkflowStore({ repositoryRoot: repoRoot, stateRoot: options.stateRoot });

	let resolvedManifestPath: string | undefined;
	let resolvedManifestSha256: string | undefined = options.manifestSha256?.toLowerCase();
	let resolvedSetSha256: string | undefined = options.setSha256?.toLowerCase();

	if (options.packageSet) {
		const pkgInfo = await resolvePackageSetInput(repoRoot, options.packageSet);
		resolvedManifestPath = pkgInfo.manifestPath;
		resolvedManifestSha256 = pkgInfo.manifestSha256?.toLowerCase() ?? resolvedManifestSha256;
		resolvedSetSha256 = pkgInfo.setSha256.toLowerCase();
	} else if (options.targetPath) {
		const norm = path.resolve(repoRoot, options.targetPath);
		try {
			if (await isPackageSetManifest(norm)) {
				const val = await parseAndValidatePackageSetManifest(norm);
				resolvedManifestPath = norm;
				resolvedManifestSha256 = val.manifestSha256.toLowerCase();
				resolvedSetSha256 = val.manifest.set_sha256.toLowerCase();
			} else {
				const adjacent = path.join(path.dirname(norm), "package-set.json");
				if (await isPackageSetManifest(adjacent)) {
					const val = await parseAndValidatePackageSetManifest(adjacent);
					resolvedManifestPath = adjacent;
					resolvedManifestSha256 = val.manifestSha256.toLowerCase();
					resolvedSetSha256 = val.manifest.set_sha256.toLowerCase();
				}
			}
		} catch {
			// ignore
		}
	}

	const packageSetInfo =
		resolvedManifestPath && resolvedManifestSha256 && resolvedSetSha256
			? {
					manifestPath: resolvedManifestPath,
					manifestSha256: resolvedManifestSha256,
					setSha256: resolvedSetSha256,
				}
			: undefined;

	if (options.workflowId) {
		const wf = await store.get(options.workflowId);
		if (!wf) {
			throw new ToolError(`Workflow '${options.workflowId}' not found.`);
		}
		// Validate that the target input belongs to this workflow (original base or registered derivative)
		const targetHash = options.targetSha256?.toLowerCase();
		const baseHash = (wf.base_target_sha256 ?? wf.target_sha256)?.toLowerCase();
		const lineageHashes = (wf.build_lineage ?? []).map(b => b.output_sha256.toLowerCase());
		const lineageSetHashes = (wf.build_lineage ?? [])
			.map(b => (b.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256)
			.filter((s): s is string => typeof s === "string")
			.map(s => s.toLowerCase());

		let hashMatches = false;
		if (targetHash) {
			hashMatches = baseHash === targetHash || lineageHashes.includes(targetHash);
		}
		if (!hashMatches && resolvedManifestSha256) {
			hashMatches = baseHash === resolvedManifestSha256 || lineageHashes.includes(resolvedManifestSha256);
		}
		if (!hashMatches && resolvedSetSha256) {
			const wfSetSha = (wf.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256;
			hashMatches =
				(typeof wfSetSha === "string" && wfSetSha.toLowerCase() === resolvedSetSha256) ||
				lineageSetHashes.includes(resolvedSetSha256);
		}

		if (!hashMatches && (targetHash || resolvedManifestSha256 || resolvedSetSha256)) {
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
			if (!pathMatches && resolvedManifestPath) {
				const normManifest = path.resolve(repoRoot, resolvedManifestPath);
				const normBase = path.resolve(repoRoot, wf.target);
				if (normManifest === normBase) {
					pathMatches = true;
				} else {
					pathMatches = (wf.build_lineage ?? []).some(b => path.resolve(repoRoot, b.target_path) === normManifest);
				}
			}
			if (!pathMatches) {
				throw new ToolError(
					`Input sample does not belong to workflow '${wf.id}': SHA-256 '${options.targetSha256 ?? resolvedManifestSha256}' matches neither original base nor registered derivative builds.`,
				);
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
			packageSet: packageSetInfo,
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
		const baseHash = (wf.base_target_sha256 ?? wf.target_sha256)?.toLowerCase();
		const wfSetSha = (wf.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256;
		const lineageOutputs = (wf.build_lineage ?? []).map(b => b.output_sha256.toLowerCase());
		const lineageSetHashes = (wf.build_lineage ?? [])
			.map(b => (b.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256)
			.filter((s): s is string => typeof s === "string")
			.map(s => s.toLowerCase());

		// Exact SHA-256 identity check against base target or any build in lineage
		if (targetHash) {
			if (baseHash === targetHash || lineageOutputs.includes(targetHash)) {
				match = true;
			}
		}

		if (!match && resolvedManifestSha256) {
			if (baseHash === resolvedManifestSha256 || lineageOutputs.includes(resolvedManifestSha256)) {
				match = true;
			}
		}

		if (!match && resolvedSetSha256) {
			if (
				(typeof wfSetSha === "string" && wfSetSha.toLowerCase() === resolvedSetSha256) ||
				lineageSetHashes.includes(resolvedSetSha256)
			) {
				match = true;
			}
		}

		// Candidate index: member hash matches in package_set metadata
		if (!match && targetHash) {
			for (const b of wf.build_lineage ?? []) {
				const members = (b.metadata?.package_set as Record<string, unknown> | undefined)?.members;
				if (Array.isArray(members)) {
					const hasMember = members.some(
						(m: unknown) =>
							typeof m === "object" &&
							m !== null &&
							String((m as Record<string, unknown>).sha256 ?? "").toLowerCase() === targetHash,
					);
					if (hasMember) {
						const bSetSha = (b.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256;
						if (
							!resolvedSetSha256 ||
							(typeof bSetSha === "string" && bSetSha.toLowerCase() === resolvedSetSha256)
						) {
							match = true;
							break;
						}
					}
				}
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

		if (!match && resolvedManifestPath) {
			const normManifest = path.resolve(repoRoot, resolvedManifestPath);
			const normBase = path.resolve(repoRoot, wf.target);
			if (normBase === normManifest) {
				match = true;
			} else if (wf.build_lineage?.some(b => path.resolve(repoRoot, b.target_path) === normManifest)) {
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
			packageSet: packageSetInfo,
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
