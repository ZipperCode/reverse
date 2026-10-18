import { AsyncLocalStorage } from "node:async_hooks";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getReverseKnowledgeProjectDir, isEnoent } from "@rva/utils";
import { withFileLock } from "@rva/utils/file-lock";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { replaceFileAtomically } from "../utils/atomic-file";
import {
	type ReverseKnowledgeRecord,
	type ReverseKnowledgeFilter,
	type AuditKnowledgeInput,
	type KnowledgeAuditResult,
	type KnowledgeAuditFinding,
	type DuplicateGroup,
	type MergeKnowledgeInput,
	type MergeKnowledgeResult,
	type ExpireKnowledgeInput,
	type ExpireKnowledgeResult,
	type DisableKnowledgeInput,
	type DisableKnowledgeResult,
	encodeKnowledgeProjectKey,
	computeKnowledgeFingerprint,
	DEFAULT_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_SEARCH_LIMIT,
	MAX_KNOWLEDGE_TITLE_LENGTH,
	MAX_KNOWLEDGE_SUMMARY_LENGTH,
	MAX_KNOWLEDGE_FIELD_LENGTH,
	KNOWLEDGE_KINDS,
	KNOWLEDGE_CONFIDENCE_LEVELS,
	KNOWLEDGE_STATUSES,
} from "./contracts";
import type { EvidenceStore } from "../evidence/store";
import type { ConclusionEvidence, HypothesisEvidence } from "../evidence/contracts";
import { normalizeTargetFormat } from "../reverse-workflow/contracts";
import {
	matchAndScoreKnowledgeRecords,
	searchBundledReverseKnowledge,
	getBundledReverseKnowledgeRecord,
} from "./bundled";

const PRIVATE_DIR_MODE = 0o700;

/** In-process write serializer per project directory */
const KNOWLEDGE_STORE_WRITE_CHAINS = new Map<string, Promise<unknown>>();
const KNOWLEDGE_STORE_ACTIVE_LOCKS = new AsyncLocalStorage<Set<string>>();

async function withKnowledgeStoreWrite<T>(
	projectDirectory: string,
	lockTarget: string,
	operation: () => Promise<T>,
): Promise<T> {
	const currentLocks = KNOWLEDGE_STORE_ACTIVE_LOCKS.getStore();
	if (currentLocks && (currentLocks.has(lockTarget) || currentLocks.has(projectDirectory))) {
		// Reentrant lock acquisition within active async call graph - avoid nested deadlocks
		return await operation();
	}

	await fs.mkdir(projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
	if (process.platform !== "win32") {
		await fs.chmod(projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
	}

	const nextLocks = new Set(currentLocks);
	nextLocks.add(lockTarget);
	nextLocks.add(projectDirectory);

	return await KNOWLEDGE_STORE_ACTIVE_LOCKS.run(nextLocks, async () => {
		const run = (KNOWLEDGE_STORE_WRITE_CHAINS.get(projectDirectory) ?? Promise.resolve()).then(() =>
			withFileLock(lockTarget, () => KNOWLEDGE_STORE_ACTIVE_LOCKS.run(nextLocks, operation), {
				retries: 200,
				retryDelayMs: 50,
			}),
		);
		const guarded = run.catch(() => undefined);
		KNOWLEDGE_STORE_WRITE_CHAINS.set(projectDirectory, guarded);
		try {
			return await run;
		} finally {
			if (KNOWLEDGE_STORE_WRITE_CHAINS.get(projectDirectory) === guarded) {
				KNOWLEDGE_STORE_WRITE_CHAINS.delete(projectDirectory);
			}
		}
	});
}

export interface ReverseKnowledgeStoreOptions {
	repositoryRoot: string;
	stateRoot?: string;
}

export class ReverseKnowledgeStore {
	readonly repositoryRoot: string;
	readonly projectKey: string;
	readonly projectDirectory: string;
	readonly lockPath: string;

	constructor(options: ReverseKnowledgeStoreOptions) {
		this.repositoryRoot = path.resolve(options.repositoryRoot);
		this.projectKey = encodeKnowledgeProjectKey(this.repositoryRoot);
		this.projectDirectory = options.stateRoot
			? path.join(path.resolve(options.stateRoot), this.projectKey)
			: getReverseKnowledgeProjectDir(this.projectKey);
		this.lockPath = path.join(this.projectDirectory, "store.lock");
	}

	static forSession(cwd: string, stateRoot?: string): ReverseKnowledgeStore {
		return new ReverseKnowledgeStore({ repositoryRoot: cwd, stateRoot });
	}

	async ensureDir(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
		}
	}

	private recordFilePath(id: string): string {
		const safeId = id.replace(/[^a-zA-Z0-9._-]/g, "_");
		return path.join(this.projectDirectory, `${safeId}.json`);
	}

	private validateRecord(record: ReverseKnowledgeRecord): void {
		if (!record.id || typeof record.id !== "string" || !record.id.startsWith("kn_rev_")) {
			throw new ToolError(`Invalid knowledge record ID: '${record.id}'. Must start with 'kn_rev_'.`);
		}
		if (!KNOWLEDGE_KINDS.includes(record.kind)) {
			throw new ToolError(
				`Invalid knowledge kind: '${record.kind}'. Only verified knowledge kinds are permitted: ${KNOWLEDGE_KINDS.join(", ")}`,
			);
		}
		if (!record.title || typeof record.title !== "string" || record.title.trim().length === 0) {
			throw new ToolError("Knowledge title is required and cannot be empty.");
		}
		if (record.title.length > MAX_KNOWLEDGE_TITLE_LENGTH) {
			throw new ToolError(
				`Knowledge title exceeds maximum length of ${MAX_KNOWLEDGE_TITLE_LENGTH} characters.`,
			);
		}
		if (!record.summary || typeof record.summary !== "string" || record.summary.trim().length === 0) {
			throw new ToolError("Knowledge summary is required and cannot be empty.");
		}
		if (record.summary.length > MAX_KNOWLEDGE_SUMMARY_LENGTH) {
			throw new ToolError(
				`Knowledge summary exceeds maximum length of ${MAX_KNOWLEDGE_SUMMARY_LENGTH} characters.`,
			);
		}
		if (!KNOWLEDGE_CONFIDENCE_LEVELS.includes(record.confidence)) {
			throw new ToolError(
				`Invalid confidence level: '${record.confidence}'. Permitted: ${KNOWLEDGE_CONFIDENCE_LEVELS.join(", ")}`,
			);
		}
		if (record.status && !KNOWLEDGE_STATUSES.includes(record.status)) {
			throw new ToolError(
				`Invalid knowledge status: '${record.status}'. Permitted: ${KNOWLEDGE_STATUSES.join(", ")}`,
			);
		}
	}

	private async saveRecordUnlocked(record: ReverseKnowledgeRecord): Promise<void> {
		if (!record.fingerprint) {
			record.fingerprint = computeKnowledgeFingerprint(record);
		}
		if (!record.status) {
			record.status = "active";
		}
		if (record.usage_count === undefined) {
			record.usage_count = 0;
		}
		this.validateRecord(record);
		await this.ensureDir();
		const targetPath = this.recordFilePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7()}.tmp`;
		const payload = JSON.stringify(record, null, 2);

		await fs.writeFile(tempPath, payload, "utf8");
		await replaceFileAtomically(tempPath, targetPath);
	}

	async save(record: ReverseKnowledgeRecord): Promise<void> {
		await withKnowledgeStoreWrite(this.projectDirectory, this.lockPath, async () => {
			await this.saveRecordUnlocked(record);
		});
	}

	async get(id: string): Promise<ReverseKnowledgeRecord | null> {
		const filePath = this.recordFilePath(id);
		try {
			const text = await fs.readFile(filePath, "utf8");
			return JSON.parse(text) as ReverseKnowledgeRecord;
		} catch (err) {
			if (isEnoent(err)) {
				const bundled = getBundledReverseKnowledgeRecord(id);
				return bundled ?? null;
			}
			throw new ToolError(
				`Failed to read knowledge record '${id}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	async list(): Promise<ReverseKnowledgeRecord[]> {
		await this.ensureDir();
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: ReverseKnowledgeRecord[] = [];

			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				const filePath = path.join(this.projectDirectory, entry.name);
				try {
					const text = await fs.readFile(filePath, "utf8");
					records.push(JSON.parse(text) as ReverseKnowledgeRecord);
				} catch {
					// Skip corrupted or unparseable JSON files
				}
			}

			// Sort by updated_at descending
			records.sort((a, b) => {
				const timeA = a.updated_at ? new Date(a.updated_at).getTime() : 0;
				const timeB = b.updated_at ? new Date(b.updated_at).getTime() : 0;
				return timeB - timeA;
			});

			return records;
		} catch (err) {
			if (isEnoent(err)) return [];
			throw new ToolError(
				`Failed to list knowledge records in ${this.projectDirectory}: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	async delete(id: string): Promise<boolean> {
		const filePath = this.recordFilePath(id);
		return await withKnowledgeStoreWrite(this.projectDirectory, this.lockPath, async () => {
			try {
				await fs.unlink(filePath);
				return true;
			} catch (err) {
				if (isEnoent(err)) return false;
				throw new ToolError(
					`Failed to delete knowledge record '${id}': ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		});
	}

	async search(filter: ReverseKnowledgeFilter = {}): Promise<ReverseKnowledgeRecord[]> {
		const records = await this.list();
		const projectMatches = matchAndScoreKnowledgeRecords(records, filter);

		if (filter.include_bundled === true) {
			const bundledMatches = searchBundledReverseKnowledge(filter);
			const seenIds = new Set(projectMatches.map(r => r.id));
			const combined = [...projectMatches];
			for (const b of bundledMatches) {
				if (!seenIds.has(b.id)) {
					combined.push(b);
				}
			}
			const limit = Math.min(
				Math.max(filter.limit ?? DEFAULT_KNOWLEDGE_SEARCH_LIMIT, 1),
				MAX_KNOWLEDGE_SEARCH_LIMIT,
			);
			const offset = Math.max(filter.offset ?? 0, 0);
			return combined.slice(offset, offset + limit);
		}

		if (projectMatches.length > 0) {
			return projectMatches;
		}

		if (filter.include_bundled !== false) {
			return searchBundledReverseKnowledge(filter);
		}

		return [];
	}

	async audit(
		options: AuditKnowledgeInput = {},
		evidenceStore?: EvidenceStore,
	): Promise<KnowledgeAuditResult> {
		const allRecords = await this.list();
		const limit = Math.min(Math.max(options.limit ?? 100, 1), 200);
		const auditedRecords = allRecords.slice(0, limit);

		const now = Date.now();
		let activeCount = 0;
		let expiredCount = 0;
		let disabledCount = 0;
		let mergedCount = 0;
		let staleCount = 0;

		const findings: KnowledgeAuditFinding[] = [];
		const groupsByFingerprint = new Map<string, ReverseKnowledgeRecord[]>();

		for (const record of auditedRecords) {
			const fp = record.fingerprint ?? computeKnowledgeFingerprint(record);
			const existingGroup = groupsByFingerprint.get(fp) ?? [];
			existingGroup.push(record);
			groupsByFingerprint.set(fp, existingGroup);

			const isExpiredDate = record.expires_at ? new Date(record.expires_at).getTime() <= now : false;
			const isExpired = record.status === "expired" || isExpiredDate;
			const isDisabled = record.status === "disabled";
			const isMerged = record.status === "merged";
			const isActive = !isExpired && !isDisabled && !isMerged && (record.status === "active" || !record.status);

			if (isActive) activeCount++;
			if (isExpired) expiredCount++;
			if (isDisabled) disabledCount++;
			if (isMerged) mergedCount++;

			if (isExpiredDate && record.status === "active") {
				findings.push({
					type: "expired",
					record_id: record.id,
					title: record.title,
					reason: `Record exceeded expiration time: ${record.expires_at}`,
				});
			}

			// Check stale evidence backing and stale flags
			let isStale = Boolean(record.stale);
			let staleReason = record.stale_reason ?? "";
			let staleFindingType: KnowledgeAuditFinding["type"] = "stale_evidence";

			if (evidenceStore && record.source_evidence_ids && record.source_evidence_ids.length > 0) {
				for (const evId of record.source_evidence_ids) {
					const ev = await evidenceStore.getRecord(evId);
					if (!ev) {
						isStale = true;
						staleReason = `Source evidence ID '${evId}' not found in project evidence ledger.`;
						staleFindingType = "invalid_source";
						break;
					}
					if (ev.kind === "conclusion") {
						const conc = ev as ConclusionEvidence;
						if (conc.status === "refuted") {
							isStale = true;
							staleReason = `Backing conclusion '${evId}' is marked refuted in evidence ledger.`;
							staleFindingType = "stale_evidence";
							break;
						}
					}
					if (ev.kind === "hypothesis") {
						const hyp = ev as HypothesisEvidence;
						if (hyp.verifiedBy) {
							const conc = await evidenceStore.getRecord(hyp.verifiedBy);
							if (!conc || (conc.kind === "conclusion" && (conc as ConclusionEvidence).status === "refuted")) {
								isStale = true;
								staleReason = `Backing conclusion '${hyp.verifiedBy}' for hypothesis '${evId}' is ${!conc ? "missing" : "marked refuted"} in evidence ledger.`;
								staleFindingType = !conc ? "invalid_source" : "stale_evidence";
								break;
							}
						}
					}
				}
			}

			if (isStale) {
				staleCount++;
				findings.push({
					type: staleFindingType,
					record_id: record.id,
					title: record.title,
					reason: staleReason || "Flagged as stale in knowledge repository",
				});

				if (options.mark_stale && (!record.stale || (staleReason && record.stale_reason !== staleReason))) {
					record.stale = true;
					record.stale_reason = staleReason;
					record.updated_at = new Date().toISOString();
					await this.save(record);
				}
			}
		}

		const duplicateGroups: DuplicateGroup[] = [];
		let totalDuplicates = 0;

		for (const [fp, group] of groupsByFingerprint.entries()) {
			if (group.length <= 1) continue;

			// Sort group to select primary winner deterministically
			group.sort((a, b) => {
				// 1. Active status preferred
				const aActive = (a.status === "active" || !a.status) ? 1 : 0;
				const bActive = (b.status === "active" || !b.status) ? 1 : 0;
				if (bActive !== aActive) return bActive - aActive;

				// 2. Confidence level
				const confWeight = { high: 3, medium: 2, low: 1 };
				const aConf = confWeight[a.confidence] ?? 0;
				const bConf = confWeight[b.confidence] ?? 0;
				if (bConf !== aConf) return bConf - aConf;

				// 3. Usage count
				const aUsage = a.usage_count ?? 0;
				const bUsage = b.usage_count ?? 0;
				if (bUsage !== aUsage) return bUsage - aUsage;

				// 4. Source evidence links
				const aEv = a.source_evidence_ids?.length ?? 0;
				const bEv = b.source_evidence_ids?.length ?? 0;
				if (bEv !== aEv) return bEv - aEv;

				// 5. Updated at descending
				const timeA = a.updated_at ? new Date(a.updated_at).getTime() : 0;
				const timeB = b.updated_at ? new Date(b.updated_at).getTime() : 0;
				return timeB - timeA;
			});

			const primary = group[0];
			const dups = group.slice(1);
			totalDuplicates += dups.length;

			duplicateGroups.push({
				fingerprint: fp,
				primary_id: primary.id,
				duplicate_ids: dups.map(d => d.id),
				titles: group.map(g => g.title),
				count: group.length,
			});

			for (const dup of dups) {
				findings.push({
					type: "duplicate",
					record_id: dup.id,
					title: dup.title,
					reason: `Duplicate of primary knowledge '${primary.id}' (fingerprint: ${fp})`,
				});
			}
		}

		const recommendations: string[] = [];
		if (duplicateGroups.length > 0) {
			recommendations.push(
				`Found ${duplicateGroups.length} duplicate group(s) across ${totalDuplicates} redundant record(s). Consolidate using 'reverse_knowledge(action: "merge", target_id: "...", source_ids: [...])'.`,
			);
		}
		if (staleCount > 0) {
			recommendations.push(
				`Found ${staleCount} record(s) with stale or refuted source evidence. Retain verified findings or retire them via 'reverse_knowledge(action: "expire" | "disable", ...)'.`,
			);
		}
		if (activeCount === 0) {
			recommendations.push(
				"No active reverse knowledge records found. Use 'reverse_knowledge(action: \"learn\")' or 'retain' to build verified knowledge.",
			);
		}

		return {
			total_records: auditedRecords.length,
			active_records: activeCount,
			expired_records: expiredCount,
			disabled_records: disabledCount,
			merged_records: mergedCount,
			stale_records: staleCount,
			duplicate_count: totalDuplicates,
			duplicate_groups: duplicateGroups,
			findings,
			recommendations,
		};
	}

	async merge(input: MergeKnowledgeInput): Promise<MergeKnowledgeResult> {
		if (!input.target_id) throw new ToolError("target_id is required for 'merge' action.");
		if (!Array.isArray(input.source_ids) || input.source_ids.length === 0) {
			throw new ToolError("source_ids must be a non-empty array of knowledge record IDs to merge.");
		}

		const targetRecord = await this.get(input.target_id);
		if (!targetRecord) throw new ToolError(`Target knowledge record '${input.target_id}' not found.`);
		if (targetRecord.status === "merged") {
			throw new ToolError(
				`Target record '${input.target_id}' is already merged into '${targetRecord.merged_into}'. Cannot merge into a merged record.`,
			);
		}

		const sourceRecords: ReverseKnowledgeRecord[] = [];
		for (const srcId of input.source_ids) {
			if (srcId === input.target_id) {
				throw new ToolError(`Cannot merge target record '${srcId}' into itself.`);
			}
			const src = await this.get(srcId);
			if (!src) throw new ToolError(`Source knowledge record '${srcId}' not found.`);
			sourceRecords.push(src);
		}

		return await withKnowledgeStoreWrite(this.projectDirectory, this.lockPath, async () => {
			// Combine source evidence IDs
			const combinedEvidence = new Set(targetRecord.source_evidence_ids ?? []);
			let additionalUsage = 0;
			let latestUsedAt = targetRecord.last_used_at;

			for (const src of sourceRecords) {
				for (const evId of src.source_evidence_ids ?? []) {
					combinedEvidence.add(evId);
				}
				additionalUsage += src.usage_count ?? 0;
				if (src.last_used_at) {
					if (!latestUsedAt || new Date(src.last_used_at).getTime() > new Date(latestUsedAt).getTime()) {
						latestUsedAt = src.last_used_at;
					}
				}
				// Promote confidence if source has higher confidence
				if (src.confidence === "high" && targetRecord.confidence !== "high") {
					targetRecord.confidence = "high";
				}
			}

			targetRecord.source_evidence_ids = Array.from(combinedEvidence);
			targetRecord.usage_count = (targetRecord.usage_count ?? 0) + additionalUsage;
			targetRecord.last_used_at = latestUsedAt;
			targetRecord.merged_from = Array.from(
				new Set([...(targetRecord.merged_from ?? []), ...input.source_ids]),
			);
			targetRecord.updated_at = new Date().toISOString();

			// Save updated target
			await this.saveRecordUnlocked(targetRecord);

			// Mark source records as merged (never delete destructively)
			for (const src of sourceRecords) {
				src.status = "merged";
				src.merged_into = targetRecord.id;
				src.status_reason = input.reason ?? `Merged into knowledge record '${targetRecord.id}'`;
				src.updated_at = new Date().toISOString();
				await this.saveRecordUnlocked(src);
			}

			return {
				target_id: targetRecord.id,
				merged_ids: input.source_ids,
				target_record: targetRecord,
				merged_records: sourceRecords,
			};
		});
	}

	async expire(input: ExpireKnowledgeInput): Promise<ExpireKnowledgeResult> {
		const ids = Array.isArray(input.knowledge_ids) && input.knowledge_ids.length > 0
			? input.knowledge_ids
			: (input.knowledge_id ? [input.knowledge_id] : []);
		if (ids.length === 0) {
			throw new ToolError("knowledge_id or knowledge_ids is required for 'expire' action.");
		}

		const expiredRecords: ReverseKnowledgeRecord[] = [];
		const reason = input.reason ?? "Knowledge record expired";
		const now = new Date().toISOString();

		for (const id of ids) {
			const record = await this.get(id);
			if (!record) throw new ToolError(`Knowledge record '${id}' not found.`);
			record.status = "expired";
			record.status_reason = reason;
			record.updated_at = now;
			await this.save(record);
			expiredRecords.push(record);
		}

		return {
			expired_ids: ids,
			reason,
			records: expiredRecords,
		};
	}

	async disable(input: DisableKnowledgeInput): Promise<DisableKnowledgeResult> {
		const ids = Array.isArray(input.knowledge_ids) && input.knowledge_ids.length > 0
			? input.knowledge_ids
			: (input.knowledge_id ? [input.knowledge_id] : []);
		if (ids.length === 0) {
			throw new ToolError("knowledge_id or knowledge_ids is required for 'disable' action.");
		}

		const disabledRecords: ReverseKnowledgeRecord[] = [];
		const reason = input.reason ?? "Knowledge record disabled";
		const now = new Date().toISOString();

		for (const id of ids) {
			const record = await this.get(id);
			if (!record) throw new ToolError(`Knowledge record '${id}' not found.`);
			record.status = "disabled";
			record.status_reason = reason;
			record.updated_at = now;
			await this.save(record);
			disabledRecords.push(record);
		}

		return {
			disabled_ids: ids,
			reason,
			records: disabledRecords,
		};
	}
}
