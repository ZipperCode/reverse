import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { prompt, getProjectDir } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import reverseWorkspaceDescription from "../prompts/tools/reverse-workspace.md" with { type: "text" };
import { EvidenceStore } from "../evidence/store";
import { ReverseWorkflowStore } from "../reverse-workflow/store";
import {
	exportWorkflowToWorkspace,
	inspectWorkspace,
	loadWorkspaceManifest,
	cleanWorkspace,
	DEFAULT_WORKSPACE_DIR,
	type ReverseWorkspaceManifest,
	type InspectWorkspaceResult,
	type CleanWorkspaceResult,
} from "../reverse-workspace";

const reverseWorkspaceSchema = type({
	action: type
		.enumerated("export", "status", "manifest", "clean")
		.describe(
			"Workspace action: export (write standardized .rea/ workspace), status (inspect .rea/ workspace integrity and layout), manifest (read manifest.json), clean (safely remove dump files while preserving reports)",
		),
	"workflow_id?": type("string").describe(
		"Workflow identifier to export (optional for status/manifest/clean, will pick most recent if omitted)",
	),
	"id?": type("string").describe("Alias for workflow_id"),
	"workspace_path?": type("string").describe(
		"Target workspace directory (defaults to '.rea' in project root)",
	),
	"format_type?": type
		.enumerated("markdown", "json")
		.describe("Report format: 'markdown' (default) or 'json'"),
	"clean_dumps_only?": type("boolean").describe(
		"When cleaning, remove only dumps while keeping scripts (default false: cleans dumps and scripts)",
	),
});

export type ReverseWorkspaceParams = typeof reverseWorkspaceSchema.infer;

export interface ReverseWorkspaceDetails {
	action: "export" | "status" | "manifest" | "clean";
	workspace_dir: string;
	manifest?: ReverseWorkspaceManifest;
	inspection?: InspectWorkspaceResult;
	clean_result?: CleanWorkspaceResult;
}

export class ReverseWorkspaceTool implements AgentTool<typeof reverseWorkspaceSchema, ReverseWorkspaceDetails> {
	readonly name = "reverse_workspace";
	readonly label = "Reverse Engineering Workspace Manager";
	readonly summary =
		"Standardized reverse-engineering workspace manager: creates and validates local .rea/ layout with manifest, target profile, workflow, evidence ledger, findings, and safe artifact references.";
	readonly description: string;
	readonly parameters = reverseWorkspaceSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "export" || action === "clean") {
				return "write";
			}
		}
		return "read";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(reverseWorkspaceDescription);
	}

	async execute(
		toolCallIdOrParams: string | ReverseWorkspaceParams,
		paramsOrContext?: ReverseWorkspaceParams | { abortSignal?: AbortSignal },
		signal?: AbortSignal,
	): Promise<AgentToolResult<ReverseWorkspaceDetails>> {
		let params: ReverseWorkspaceParams;
		let abortSignal: AbortSignal | undefined;

		if (typeof toolCallIdOrParams === "string") {
			params = paramsOrContext as ReverseWorkspaceParams;
			abortSignal = signal;
		} else {
			params = toolCallIdOrParams;
			if (paramsOrContext && "abortSignal" in paramsOrContext) {
				abortSignal = paramsOrContext.abortSignal;
			}
		}

		throwIfAborted(abortSignal);

		const projectDir = this.session.cwd ?? getProjectDir();
		const workspacePath = params.workspace_path || DEFAULT_WORKSPACE_DIR;

		switch (params.action) {
			case "export": {
				const workflowStore = new ReverseWorkflowStore({ repositoryRoot: projectDir });
				const evidenceStore = new EvidenceStore({ repositoryRoot: projectDir });

				let workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					const allWorkflows = await workflowStore.list(1);
					if (allWorkflows.length > 0) {
						workflowId = allWorkflows[0].id;
					} else {
						throw new ToolError(
							"workflow_id is required for 'export' action when no prior workflows exist.",
						);
					}
				}

				const workflow = await workflowStore.get(workflowId);
				if (!workflow) {
					throw new ToolError(`Workflow '${workflowId}' not found.`);
				}

				const result = await exportWorkflowToWorkspace({
					workflow,
					evidenceStore,
					projectDir,
					workspaceDir: workspacePath,
					formatType: params.format_type ?? "markdown",
				});

				const lines = [
					`# Exported Standardized Reverse Workspace: \`${result.relative_workspace_dir}\``,
					"",
					`- **Target**: \`${result.target_info.name}\` (\`${result.target_info.format}\`) — Safe reference preserved`,
					`- **Manifest**: \`${result.relative_workspace_dir}/manifest.json\``,
					`- **Standard Directories**: manifest, target, workflow, evidence, findings, scripts, dumps, reports`,
					`- **Created Files**: ${result.created_files.length}`,
					`- **Step Progress**: ${result.stats.steps_completed}/${result.stats.steps_total} steps`,
					`- **Evidence Items**: ${result.stats.evidence_total} total (${result.stats.conclusions_count} verified conclusions)`,
					`- **Artifacts Index**: ${result.manifest.artifacts.length} entries (${result.stats.scripts_count} scripts copied, ${result.stats.dumps_count} dumps copied)`,
				];

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "export",
						workspace_dir: result.workspace_dir,
						manifest: result.manifest,
					},
				};
			}

			case "status": {
				const inspection = await inspectWorkspace(workspacePath, projectDir);
				const lines = [
					`# Reverse Engineering Workspace Status: \`${inspection.relative_workspace_dir}\``,
					"",
					`- **Exists**: ${inspection.exists ? "Yes" : "No"}`,
					`- **Valid Layout**: ${inspection.valid ? "Yes" : "No"}`,
					`- **Total Files**: ${inspection.file_count}`,
					`- **Subdirectories**: ${inspection.subdirs.join(", ") || "(none)"}`,
				];

				if (inspection.manifest) {
					const m = inspection.manifest;
					lines.push("");
					lines.push("## Manifest Details");
					lines.push(`- **Workflow ID**: \`${m.workflow.id}\` (${m.workflow.status})`);
					lines.push(`- **Target**: \`${m.target.name}\` (${m.target.format})`);
					lines.push(`- **Target SHA-256**: \`${m.target.sha256 || "unknown"}\``);
					lines.push(
						`- **Stats**: ${m.stats.steps_completed}/${m.stats.steps_total} steps completed, ${m.stats.evidence_total} evidence items, ${m.stats.conclusions_count} conclusions`,
					);
					lines.push(`- **Indexed Files**: ${m.files.length}`);
					lines.push(`- **Indexed Artifacts**: ${m.artifacts.length}`);
				}

				if (inspection.validation_errors && inspection.validation_errors.length > 0) {
					lines.push("");
					lines.push("## Validation Warnings / Errors");
					for (const err of inspection.validation_errors) {
						lines.push(`- ${err}`);
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "status",
						workspace_dir: inspection.workspace_dir,
						inspection,
						manifest: inspection.manifest,
					},
				};
			}

			case "manifest": {
				const manifest = await loadWorkspaceManifest(
					path.resolve(projectDir, workspacePath),
				);
				if (!manifest) {
					throw new ToolError(
						`Workspace manifest not found or invalid at '${workspacePath}/manifest.json'. Run export first.`,
					);
				}

				const text = JSON.stringify(manifest, null, 2);
				return {
					content: [{ type: "text", text }],
					details: {
						action: "manifest",
						workspace_dir: path.resolve(projectDir, workspacePath),
						manifest,
					},
				};
			}

			case "clean": {
				const cleanResult = await cleanWorkspace({
					projectDir,
					workspaceDir: workspacePath,
					removeDumpsOnly: params.clean_dumps_only ?? false,
				});

				const lines = [
					`# Cleaned Reverse Engineering Workspace: \`${workspacePath}\``,
					"",
					`- **Removed Files**: ${cleanResult.removed_files.length}`,
					cleanResult.removed_files.length > 0
						? cleanResult.removed_files.map(f => `  - \`${f}\``).join("\n")
						: "  - (no files removed)",
					`- **Preserved Core Files**: ${cleanResult.preserved_files.length} (manifest, target, workflow, evidence, findings, reports)`,
				];

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "clean",
						workspace_dir: cleanResult.workspace_dir,
						clean_result: cleanResult,
					},
				};
			}
		}
	}
}
