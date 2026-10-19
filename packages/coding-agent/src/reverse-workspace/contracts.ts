import type { TargetFormat, WorkflowStatus, ReverseWorkflowRecord } from "../reverse-workflow/contracts";
import type { EvidenceStore } from "../evidence/store";

export const DEFAULT_WORKSPACE_DIR = ".reverse";

export const WORKSPACE_SUBDIRS = ["target", "workflow", "evidence", "findings", "scripts", "dumps", "reports"] as const;

export type WorkspaceSubdir = (typeof WORKSPACE_SUBDIRS)[number];

export const MAX_SAFE_ARTIFACT_COPY_BYTES = 1024 * 1024; // 1 MiB ceiling for safe inline/script/dump copy
export const MAX_REPORT_CHARS = 131072; // 128 KiB bounded report text
export const MAX_OUTPUT_CHARS = 65536; // 64 KiB bounded summary text

export const WORKSPACE_FILES = {
	MANIFEST: "manifest.json",
	GITIGNORE: ".gitignore",
	TARGET_INFO: "target/target.json",
	WORKFLOW_JSON: "workflow/workflow.json",
	WORKFLOW_MD: "workflow/workflow.md",
	EVIDENCE_JSON: "evidence/evidence.json",
	EVIDENCE_LEDGER: "evidence/ledger.json",
	FINDINGS_JSON: "findings/findings.json",
	FINDINGS_MD: "findings/findings.md",
	REPORT_WORKFLOW: "reports/workflow_report.md",
	REPORT_FINDINGS: "reports/findings_report.md",
} as const;

export interface ReverseWorkspaceTargetInfo {
	path: string; // safe relative path to project root
	name: string;
	format: TargetFormat;
	sha256?: string;
	size?: number;
	is_reference: true; // explicit confirmation that original target binary is never mutated or duplicated
	inspected_at: string;
}

export interface ReverseWorkspaceStats {
	steps_total: number;
	steps_completed: number;
	steps_failed: number;
	steps_pending: number;
	steps_skipped: number;
	evidence_total: number;
	facts_count: number;
	hypotheses_count: number;
	hypotheses_verified_count: number;
	conclusions_count: number;
	artifacts_count: number;
	scripts_count: number;
	dumps_count: number;
	reports_count: number;
}

export interface ReverseWorkspaceArtifactRef {
	id: string;
	source_path?: string;
	destination_path?: string;
	kind: "script" | "dump" | "report" | "reference";
	size_bytes?: number;
	sha256?: string;
	copied: boolean; // true if small safe copy placed in workspace; false if kept as safe external reference
	reason?: string;
}

export interface ReverseWorkspaceFileEntry {
	path: string; // relative to workspace root (e.g. "reports/workflow_report.md")
	size_bytes: number;
	sha256: string;
}

export interface ReverseWorkspaceManifest {
	schema_version: "1.0.0";
	created_at: string;
	updated_at: string;
	workspace_dir: string;
	workflow: {
		id: string;
		format: TargetFormat;
		status: WorkflowStatus;
		goal?: string;
		created_at: string;
		updated_at: string;
	};
	target: ReverseWorkspaceTargetInfo;
	stats: ReverseWorkspaceStats;
	files: ReverseWorkspaceFileEntry[];
	artifacts: ReverseWorkspaceArtifactRef[];
}

export interface ReverseFindingsSummary {
	target: {
		name: string;
		format: TargetFormat;
		sha256?: string;
	};
	goal?: string;
	conclusions: Array<{
		id: string;
		conclusion: string;
		method?: string;
		command?: string;
		result?: string;
		reproducibility?: string;
		status?: "verified" | "refuted";
		hypothesisId?: string;
		timestamp: string;
	}>;
	verified_hypotheses: Array<{
		id: string;
		claim: string;
		verificationPlan?: string;
		verifiedBy?: string;
		timestamp: string;
	}>;
	unverified_hypotheses: Array<{
		id: string;
		claim: string;
		verificationPlan?: string;
		timestamp: string;
	}>;
	facts: Array<{
		id: string;
		title?: string;
		locator: string;
		sourceTool: string;
		content: string;
		timestamp: string;
	}>;
	key_takeaways: string[];
}

export interface ExportToWorkspaceOptions {
	workflow: ReverseWorkflowRecord;
	evidenceStore?: EvidenceStore;
	projectDir: string;
	workspaceDir?: string;
	formatType?: "markdown" | "json";
	clean?: boolean;
}

export interface ExportToWorkspaceResult {
	workspace_dir: string;
	relative_workspace_dir: string;
	manifest: ReverseWorkspaceManifest;
	created_files: string[];
	target_info: ReverseWorkspaceTargetInfo;
	stats: ReverseWorkspaceStats;
}

export interface InspectWorkspaceResult {
	exists: boolean;
	workspace_dir: string;
	relative_workspace_dir: string;
	manifest?: ReverseWorkspaceManifest;
	file_count: number;
	subdirs: string[];
	valid: boolean;
	validation_errors?: string[];
}

export interface CleanWorkspaceOptions {
	workspaceDir?: string;
	projectDir: string;
	removeDumpsOnly?: boolean;
}

export interface CleanWorkspaceResult {
	workspace_dir: string;
	removed_files: string[];
	preserved_files: string[];
}
