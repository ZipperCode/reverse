import type { EvidenceAssuranceLevel } from "../evidence/contracts";

export type AcceptanceCriterionStatus = "pending" | "satisfied" | "waived" | "proxy_verified";

export interface AcceptanceCriterion {
	id: string; // Stable ID, e.g. "ac_login_traffic", "c5"
	step_id: string; // Stable workflow step.id
	title: string;
	subject: string; // Canonical immutable acceptance subject string
	required_evidence_types?: string[];
	min_assurance?: EvidenceAssuranceLevel;
	status: AcceptanceCriterionStatus;
	satisfied_by_evidence_ids?: string[];
	is_proxy?: boolean;
	proxy_for_criterion_id?: string;
	proxy_evidence_ids?: string[];
	waiver_reason?: string;
	waiver_timestamp?: string;
	waived_by_decision?: string;
	created_at?: string;
	updated_at?: string;
}

export type AcceptanceCriterionInput = Omit<AcceptanceCriterion, "status"> & {
	status?: "pending";
};

export interface TargetDeviceConstraints {
	target_environment?: string; // e.g. "vehicle_ivi", "android_phone", "windows_vm"
	disallowed_dependencies?: string[]; // e.g. ["xposed", "lsposed", "frida", "external_oracle", "phone_oracle", "root"]
	allowed_delivery_modes?: string[]; // e.g. ["standalone_package", "modified_apk"]
	requires_standalone?: boolean; // true: no external oracle helpers or tethered devices permitted for delivery
	notes?: string;
}

export interface WorkflowDependencyRecord {
	id: string; // e.g. "dep_lsposed", "dep_phone_oracle"
	name: string;
	kind: "framework" | "external_service" | "hook_agent" | "debugger" | "runtime_library" | string;
	scope: "experiment" | "delivery"; // experiment vs delivery
	target_host?: "target_device" | "workstation" | "external_phone" | string;
	approved_for_experiment?: boolean;
	approved_for_delivery?: boolean; // Lab approval NEVER sets approved_for_delivery!
	approval_notes?: string;
	approved_at?: string;
	decision_id?: string;
}

export const SUPPORTED_TARGET_FORMATS = ["PE", "ELF", "Mach-O", "APK", "JS", "WASM", "PCAP", "SQLite"] as const;

export type TargetFormat = (typeof SUPPORTED_TARGET_FORMATS)[number] | "unknown";

export type WorkflowStepStatus = "pending" | "running" | "completed" | "failed" | "skipped";
export type WorkflowStatus = "active" | "completed" | "failed";

export const PROGRESSION_STATUSES = [
	"proposed",
	"recorded",
	"held_pending_decision",
	"stopped_missing_dependency",
	"stopped_ambiguous_target",
	"completed",
] as const;
export type ProgressionStatus = (typeof PROGRESSION_STATUSES)[number];

export interface ProgressionAuditEntry {
	step_id: string;
	step_title: string;
	tool: string;
	gate: "G0" | "G1" | "G2" | "G3" | "G4";
	action: "advance" | "auto_advance";
	status: ProgressionStatus;
	decision: string;
	reason: string;
	is_low_risk: boolean;
	timestamp: string;
	knowledge_refs?: string[];
	params_summary?: Record<string, unknown> | string;
}
export const DEFAULT_MAX_ATTEMPTS = 3;
export const HARD_MAX_ATTEMPTS = 10;
export const MAX_WORKFLOW_ID_LENGTH = 128;
export const MAX_EXPORT_CHARS = 32768; // 32 KiB bounded output
export const MAX_INLINE_CHARS = 4000;

export const FAILURE_CATEGORIES = [
	"missing_dependency",
	"invalid_format",
	"timeout",
	"truncated",
	"device_required",
	"unsupported",
	"unknown",
] as const;

export type FailureCategory = (typeof FAILURE_CATEGORIES)[number];

export interface FailureAttribution {
	category: FailureCategory;
	cause: string;
	confidence: "high" | "medium" | "low";
	raw_error: string;
	matched_pattern?: string;
	missing_tool?: string;
	install_hint?: string;
	setup_command?: string;
}

/**
 * Canonical install-after resume metadata recorded when recovering or retrying
 * a step following external tool installation via trusted setup.
 */
export interface StepResumeMetadata {
	/** Canonical capability ID (e.g. 'apk_unpacking', 'dex_patching', 'apk_artifact_generation', 'android_native_emulation', 'browser_debugger', 'websocket_capture', 'js_deobfuscation', 'traffic_interception', 'native_debugger') */
	capability_id?: string;
	/** Logical name of the installed external tool (e.g. 'jadx', 'apktool', 'unidbg', 'radare2') */
	installed_tool: string;
	/** Trusted setup command executed to install the tool (e.g. 'reverse setup reverse apktool') */
	setup_command?: string;
	/** Whether tool availability was verified post-install before resuming execution */
	verified: boolean;
	/** Resumption strategy: resume original planned tool or engage fallback */
	strategy: "resume_original" | "fallback" | string;
	/** ISO timestamp when the step was resumed following installation */
	resumed_at: string;
	/** Optional parameters passed or adjusted for the resumed tool execution */
	resumed_params?: Record<string, unknown> | string;
	/** Optional notes or diagnostic message from operator/caller */
	notes?: string;
}

export interface RecoveryAuditEntry {
	attempt: number;
	timestamp: string;
	action: "recover" | "retry" | "retry_plan" | "resume";
	category: FailureCategory;
	cause: string;
	previous_tool: string;
	proposed_tool: string;
	proposed_params: Record<string, unknown> | string;
	decision: string;
	applied: boolean;
	evidence_ids?: string[];
	caller_result?: string;
	capability_id?: string;
	installed_tool?: string;
	setup_command?: string;
	verified?: boolean;
	strategy?: string;
}

export interface RecoveryPlan {
	attribution: FailureAttribution;
	suggested_action: "retry" | "fallback" | "adjust_params" | "abort";
	original_tool: string;
	next_tool: string;
	original_params: Record<string, unknown> | string;
	next_params: Record<string, unknown> | string;
	alternatives: string[];
	reasoning: string;
	can_retry: boolean;
	current_attempts: number;
	max_attempts: number;
	exhausted: boolean;
	install_hint?: string;
	setup_command?: string;
	/** Canonical install-after resume metadata if proposed or configured */
	resume?: StepResumeMetadata;
}

export interface StepRetryEntry {
	attempt: number;
	timestamp: string;
	error?: string;
	caller_result?: string;
	params?: Record<string, unknown> | string;
}

export interface StepRecoveryMetadata {
	failure_reason?: string;
	fallback_tool?: string;
	suggested_fix?: string;
	attribution?: FailureAttribution;
	retry_history?: StepRetryEntry[];
	recovery_audit?: RecoveryAuditEntry[];
	/** Canonical install-after resume metadata when recovering following external tool installation */
	resume?: StepResumeMetadata;
}

export interface WorkflowStepRecord {
	id: string;
	title: string;
	tool: string;
	gate: "G0" | "G1" | "G2" | "G3" | "G4";
	params_summary: Record<string, unknown> | string;
	status: WorkflowStepStatus;
	attempts: number;
	max_attempts: number;
	outputs?: string | Record<string, unknown>;
	artifact_refs?: string[];
	evidence_ids?: string[];
	knowledge_refs?: string[];
	runtime_session_id?: string;
	runtime_session_ids?: string[];
	error?: string;
	next_params?: Record<string, unknown> | string;
	recovery_metadata?: StepRecoveryMetadata;
	decision?: string;
	decision_reason?: string;
	progression_status?: ProgressionStatus;
	is_delivery_step?: boolean;
	delivery_scope?: "experiment" | "delivery";
	created_at: string;
	updated_at: string;
}
export type PatchStatus = "active" | "retired";

export interface CumulativePatchRecord {
	patch_id: string;
	/** Member path inside container (e.g. 'lib/arm64-v8a/libEaglet.so', 'classes.dex') or undefined for plain binary */
	member_path?: string;
	/** Byte offset from beginning of file or container member */
	offset: number;
	/** Original bytes in hex */
	original_bytes: string;
	/** Expected bytes in hex after patch */
	expected_bytes: string;
	/** Active or retired status */
	status: PatchStatus;
	/** Mandatory reason if status is 'retired' */
	retirement_reason?: string;
	/** Timestamp when patch was retired */
	retired_at?: string;
	/** Build identifier where the retirement took effect */
	retired_in_build_id?: string;
	/** Linked evidence identifier if verified via evidence ledger */
	evidence_id?: string;
	created_at: string;
}

export type BuildSignatureStatus = "signed" | "unsigned" | "unknown";

export interface BuildSignatureInfo {
	status: BuildSignatureStatus;
	scheme?: string;
	fingerprint?: string;
	details?: string;
}

export interface BuildVerificationResult {
	/** Overall status: 'verified' requires static_status === 'verified' */
	status: "verified" | "failed" | "unverified";
	/** Static member/binary byte verification across all active cumulative patches */
	static_status: "verified" | "failed";
	/** Runtime execution proof: 'pending' until runtime evidence bound to exact output_sha256 is recorded */
	runtime_status: "pending" | "verified" | "failed";
	verified_at?: string;
	conditions?: Record<string, unknown> | string[];
	checked_patches_count: number;
	failed_patch_id?: string;
	failure_reason?: string;
}

export interface BuildArtifactRecord {
	build_id: string;
	workflow_id: string;
	target_path: string;
	output_sha256: string;
	original_sha256: string;
	parent_sha256: string;
	parent_build_id?: string;
	target_version?: string;
	abi?: string;
	architecture?: string;
	cumulative_patches: CumulativePatchRecord[];
	signature: BuildSignatureInfo;
	verification_conditions?: Record<string, unknown> | string[];
	verification_result: BuildVerificationResult;
	target_device_constraints?: TargetDeviceConstraints;
	scope?: "experiment" | "delivery";
	delivery_mode?: string;
	dependencies?: WorkflowDependencyRecord[];
	evidence_ids?: string[];
	runtime_evidence_ids?: string[];
	metadata?: Record<string, unknown>;
	created_at: string;
	updated_at: string;
}

export interface PatchRetirementAuditEntry {
	patch_id: string;
	reason: string;
	retired_at: string;
	build_id?: string;
}

export interface WorkflowBaselineSummary {
	workflow_id: string;
	current_baseline_build_id?: string;
	base_target_sha256?: string;
	active_baseline?: {
		build_id: string;
		target_path: string;
		output_sha256: string;
		parent_sha256: string;
		active_patches_count: number;
		active_patches: Array<{
			patch_id: string;
			member_path?: string;
			offset: number;
			expected_bytes: string;
		}>;
		retired_patches: Array<{
			patch_id: string;
			reason: string;
		}>;
		static_status: "verified" | "failed";
		runtime_status: "pending" | "verified" | "failed";
		runtime_evidence_ids?: string[];
	};
}

export interface ReverseWorkflowRecord {
	id: string;
	target: string;
	target_abs_path?: string;
	target_sha256?: string;
	target_size?: number;
	format: TargetFormat;
	goal?: string;
	status: WorkflowStatus;
	steps: WorkflowStepRecord[];
	created_at: string;
	updated_at: string;
	runtime_session_ids?: string[];
	metadata?: Record<string, unknown>;
	knowledge_refs?: string[];
	progression_audit?: ProgressionAuditEntry[];
	build_lineage?: BuildArtifactRecord[];
	current_baseline_build_id?: string;
	base_target_sha256?: string;
	retired_patches_audit?: PatchRetirementAuditEntry[];
	linked_revision_workflow_id?: string;
	revision_reason?: string;
}

export interface WorkflowMetrics {
	total_steps: number;
	completed_steps: number;
	failed_steps: number;
	pending_steps: number;
	skipped_steps: number;
	total_evidence_links: number;
	total_knowledge_links?: number;
	resumed_steps?: number;
	next_step?: WorkflowStepRecord;
	total_acceptance_criteria?: number;
	satisfied_acceptance_criteria?: number;
	waived_acceptance_criteria?: number;
	proxy_verified_acceptance_criteria?: number;
	pending_acceptance_criteria?: number;
	acceptance_completion_ratio?: number;
}

export function computeWorkflowMetrics(
	steps: WorkflowStepRecord[],
	metadata?: Record<string, unknown>,
): WorkflowMetrics {
	let completed = 0;
	let failed = 0;
	let pending = 0;
	let skipped = 0;
	let evidenceLinks = 0;
	let nextStep: WorkflowStepRecord | undefined;
	let knowledgeLinks = 0;
	let resumed = 0;

	for (const step of steps) {
		if (step.status === "completed") completed++;
		else if (step.status === "failed") failed++;
		else if (step.status === "skipped") skipped++;
		else if (step.status === "pending" || step.status === "running") {
			pending++;
			if (!nextStep) nextStep = step;
		}

		if (step.recovery_metadata?.resume) {
			resumed++;
		}

		if (Array.isArray(step.evidence_ids)) {
			evidenceLinks += step.evidence_ids.length;
		}
		if (Array.isArray(step.knowledge_refs)) {
			knowledgeLinks += step.knowledge_refs.length;
		}
	}

	// Compute stable acceptance criteria metrics from single reserved metadata typed key
	const allCriteriaMap = new Map<string, AcceptanceCriterion>();
	if (metadata && metadata.acceptance) {
		if (Array.isArray(metadata.acceptance)) {
			for (const ac of metadata.acceptance as AcceptanceCriterion[]) {
				if (ac && typeof ac.id === "string") {
					allCriteriaMap.set(ac.id, ac);
				}
			}
		} else if (typeof metadata.acceptance === "object") {
			for (const list of Object.values(metadata.acceptance as Record<string, AcceptanceCriterion[]>)) {
				if (Array.isArray(list)) {
					for (const ac of list) {
						if (ac && typeof ac.id === "string") {
							allCriteriaMap.set(ac.id, ac);
						}
					}
				}
			}
		}
	}

	let totalCriteria: number | undefined;
	let satisfiedCriteria: number | undefined;
	let waivedCriteria: number | undefined;
	let proxyVerifiedCriteria: number | undefined;
	let pendingCriteria: number | undefined;
	let acceptanceRatio: number | undefined;

	if (allCriteriaMap.size > 0) {
		totalCriteria = allCriteriaMap.size;
		satisfiedCriteria = 0;
		waivedCriteria = 0;
		proxyVerifiedCriteria = 0;
		pendingCriteria = 0;

		for (const ac of allCriteriaMap.values()) {
			if (ac.status === "satisfied") satisfiedCriteria++;
			else if (ac.status === "waived") waivedCriteria++;
			else if (ac.status === "proxy_verified") proxyVerifiedCriteria++;
			else pendingCriteria++;
		}

		const effectiveTotal = totalCriteria - waivedCriteria;
		acceptanceRatio = effectiveTotal <= 0 ? 1 : satisfiedCriteria / effectiveTotal;
	}

	return {
		total_steps: steps.length,
		completed_steps: completed,
		failed_steps: failed,
		pending_steps: pending,
		skipped_steps: skipped,
		total_evidence_links: evidenceLinks,
		total_knowledge_links: knowledgeLinks,
		resumed_steps: resumed,
		next_step: nextStep,
		total_acceptance_criteria: totalCriteria,
		satisfied_acceptance_criteria: satisfiedCriteria,
		waived_acceptance_criteria: waivedCriteria,
		proxy_verified_acceptance_criteria: proxyVerifiedCriteria,
		pending_acceptance_criteria: pendingCriteria,
		acceptance_completion_ratio: acceptanceRatio,
	};
}

export function createWorkflowId(): string {
	return `wf_rw_${Bun.randomUUIDv7()}`;
}

export function normalizeTargetFormat(input?: string): TargetFormat | undefined {
	if (!input) return undefined;
	const lower = input.trim().toLowerCase();
	if (lower === "pe" || lower === "pe32" || lower === "pe32+" || lower === "exe" || lower === "dll") return "PE";
	if (lower === "elf" || lower === "elf32" || lower === "elf64" || lower === "so") return "ELF";
	if (lower === "macho" || lower === "mach-o" || lower === "dylib") return "Mach-O";
	if (lower === "apk" || lower === "aab" || lower === "dex") return "APK";
	if (lower === "js" || lower === "javascript" || lower === "sourcemap" || lower === "map" || lower === "hbc")
		return "JS";
	if (lower === "wasm" || lower === "wat" || lower === "webassembly") return "WASM";
	if (lower === "pcap" || lower === "pcapng") return "PCAP";
	if (lower === "sqlite" || lower === "sqlite3" || lower === "db") return "SQLite";
	return undefined;
}

const EVIDENCE_ID_REGEX = /^ev_(fact|hyp|conc|unk)_[a-zA-Z0-9_-]+$/;

export function validateEvidenceIdFormat(id: string): boolean {
	return EVIDENCE_ID_REGEX.test(id);
}

export const KNOWLEDGE_ID_REGEX = /^kn_rev_[a-zA-Z0-9_-]+$/;

export function validateKnowledgeIdFormat(id: string): boolean {
	return KNOWLEDGE_ID_REGEX.test(id);
}

export function encodeWorkflowProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}

export function createBuildId(prefix = "bld"): string {
	return `${prefix}_${Bun.randomUUIDv7()}`;
}
