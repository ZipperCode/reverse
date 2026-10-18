import type { TargetFormat } from "../reverse-workflow/contracts";
import { normalizeTargetFormat } from "../reverse-workflow/contracts";

export const KNOWLEDGE_KINDS = ["verified_conclusion", "recovery_pattern"] as const;
export type KnowledgeKind = (typeof KNOWLEDGE_KINDS)[number];

export const KNOWLEDGE_CONFIDENCE_LEVELS = ["high", "medium", "low"] as const;
export type KnowledgeConfidence = (typeof KNOWLEDGE_CONFIDENCE_LEVELS)[number];

export const KNOWLEDGE_STATUSES = ["active", "expired", "disabled", "merged"] as const;
export type KnowledgeStatus = (typeof KNOWLEDGE_STATUSES)[number];

export const MAX_KNOWLEDGE_TITLE_LENGTH = 256;
export const MAX_KNOWLEDGE_FIELD_LENGTH = 32768;
export const MAX_KNOWLEDGE_SUMMARY_LENGTH = 16384;
export const DEFAULT_KNOWLEDGE_SEARCH_LIMIT = 5;
export const MAX_KNOWLEDGE_SEARCH_LIMIT = 20;
export const MAX_KNOWLEDGE_INLINE_CHARS = 4000;

export interface ReverseKnowledgeRecord {
	id: string;
	kind: KnowledgeKind;
	title: string;
	target_format: TargetFormat;
	target_hash?: string;
	target_fingerprint?: string;
	tool?: string;
	confidence: KnowledgeConfidence;
	source_evidence_ids?: string[];
	source_workflow_id?: string;
	source_step_id?: string;
	source?: "bundled" | "evidence_ledger" | "workflow_recovery" | "retained_finding";
	summary: string;
	pattern?: string;
	actionable_guidance?: string;
	params?: Record<string, unknown> | string;
	metadata?: Record<string, unknown>;
	created_at: string;
	updated_at: string;
	status?: KnowledgeStatus;
	status_reason?: string;
	fingerprint?: string;
	usage_count?: number;
	last_used_at?: string;
	stale?: boolean;
	stale_reason?: string;
	merged_into?: string;
	merged_from?: string[];
	expires_at?: string;
}

export interface ReverseKnowledgeFilter {
	query?: string;
	format?: string;
	target_hash?: string;
	tool?: string;
	kind?: KnowledgeKind;
	confidence?: KnowledgeConfidence;
	status?: KnowledgeStatus;
	include_inactive?: boolean;
	include_stale?: boolean;
	include_bundled?: boolean;
	limit?: number;
	offset?: number;
}

export interface RetainKnowledgeInput {
	title: string;
	kind: KnowledgeKind;
	target_format: TargetFormat | string;
	target_hash?: string;
	target_fingerprint?: string;
	tool?: string;
	confidence?: KnowledgeConfidence;
	source_evidence_ids?: string[];
	source_workflow_id?: string;
	source_step_id?: string;
	summary: string;
	pattern?: string;
	actionable_guidance?: string;
	params?: Record<string, unknown> | string;
	metadata?: Record<string, unknown>;
}

export interface EvidenceValidationResult {
	missingEvidenceIds: string[];
	refutedEvidenceIds: string[];
	unverified: boolean;
}

export interface LearnKnowledgeInput {
	workflow_id?: string;
	target_hash?: string;
	format?: string;
}

export interface LearnKnowledgeResult {
	learned_conclusions: number;
	learned_recoveries: number;
	skipped_unverified: number;
	created_records: ReverseKnowledgeRecord[];
}

export interface KnowledgeRecommendation {
	knowledge_id: string;
	title: string;
	kind: KnowledgeKind;
	confidence: KnowledgeConfidence;
	tool?: string;
	format: TargetFormat;
	guidance: string;
	suggested_params?: Record<string, unknown> | string;
	source_evidence_ids?: string[];
	source_workflow_id?: string;
	source_step_id?: string;
	source?: "evidence_ledger" | "workflow_recovery" | "retained_finding" | "bundled";
	status?: KnowledgeStatus;
	usage_count?: number;
}

export interface ApplyKnowledgeInput {
	target?: string;
	format?: TargetFormat | string;
	target_hash?: string;
	tool?: string;
	goal?: string;
	error?: string;
	step_id?: string;
	limit?: number;
}

export interface ApplyKnowledgeResult {
	target?: string;
	format?: TargetFormat;
	target_hash?: string;
	recommendations: KnowledgeRecommendation[];
	knowledge_refs: string[];
}

export interface AuditKnowledgeInput {
	limit?: number;
	mark_stale?: boolean;
	include_inactive?: boolean;
}

export interface DuplicateGroup {
	fingerprint: string;
	primary_id: string;
	duplicate_ids: string[];
	titles: string[];
	count: number;
}

export interface KnowledgeAuditFinding {
	type: "duplicate" | "stale_evidence" | "invalid_source" | "expired" | "low_confidence_stale";
	record_id: string;
	title: string;
	reason: string;
	details?: Record<string, unknown>;
}

export interface KnowledgeAuditResult {
	total_records: number;
	active_records: number;
	expired_records: number;
	disabled_records: number;
	merged_records: number;
	stale_records: number;
	duplicate_count: number;
	duplicate_groups: DuplicateGroup[];
	findings: KnowledgeAuditFinding[];
	recommendations: string[];
}

export interface MergeKnowledgeInput {
	target_id: string;
	source_ids: string[];
	reason?: string;
}

export interface MergeKnowledgeResult {
	target_id: string;
	merged_ids: string[];
	target_record: ReverseKnowledgeRecord;
	merged_records: ReverseKnowledgeRecord[];
}

export interface ExpireKnowledgeInput {
	knowledge_id?: string;
	knowledge_ids?: string[];
	reason?: string;
}

export interface ExpireKnowledgeResult {
	expired_ids: string[];
	reason: string;
	records: ReverseKnowledgeRecord[];
}

export interface DisableKnowledgeInput {
	knowledge_id?: string;
	knowledge_ids?: string[];
	reason?: string;
}

export interface DisableKnowledgeResult {
	disabled_ids: string[];
	reason: string;
	records: ReverseKnowledgeRecord[];
}

export function computeKnowledgeFingerprint(
	record: Pick<ReverseKnowledgeRecord, "kind" | "target_format" | "tool" | "title" | "target_hash" | "pattern">,
): string {
	const normKind = (record.kind || "").trim().toLowerCase();
	const normFormat = (record.target_format || "unknown").trim().toLowerCase();
	const normTool = (record.tool || "").trim().toLowerCase();
	const normHash = (record.target_hash || "").trim().toLowerCase();
	const normTitle = (record.title || "")
		.toLowerCase()
		.replace(/[^a-z0-9\s]/g, " ")
		.split(/\s+/)
		.filter(w => w.length > 2 && !["the", "for", "and", "with", "sample", "binary", "file"].includes(w))
		.sort()
		.join("_");
	const normPattern = (record.pattern || "")
		.toLowerCase()
		.replace(/[^a-z0-9\s]/g, " ")
		.split(/\s+/)
		.filter(w => w.length > 2)
		.slice(0, 10)
		.sort()
		.join("_");

	const canonical = `${normKind}:${normFormat}:${normTool}:${normHash}:${normTitle}:${normPattern}`;
	return `fp_kn_${Bun.SHA256.hash(canonical, "hex").slice(0, 16)}`;
}

export function createKnowledgeId(): string {
	return `kn_rev_${Bun.randomUUIDv7()}`;
}

export function encodeKnowledgeProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}
