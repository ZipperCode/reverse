import * as path from "node:path";
import type { AgentTool, AgentToolContext, AgentToolResult, ToolApprovalDecision } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { prompt, getProjectDir } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
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
	beginAnalysisRun,
	recordAnalysisRun,
	recallAnalysisRuns,
	DEFAULT_WORKSPACE_DIR,
	type ReverseWorkspaceManifest,
	type InspectWorkspaceResult,
	type CleanWorkspaceResult,
	type AnalysisRunPaths,
	type AnalysisRunRecord,
	type AnalysisRunRecall,
} from "../reverse-workspace";

const reverseWorkspaceSchema = type({
	action: type
		.enumerated("export", "status", "manifest", "clean", "begin", "record", "recall")
		.describe(
			"Workspace action: export (write standardized .reverse/ workspace), status (inspect .reverse/ workspace integrity and layout), manifest (read manifest.json), clean (safely remove dump files while preserving reports), begin (allocate active experiment run directory and record input hashes), record (finalize experiment run and link artifacts to workflow step), recall (search prior project experiment runs)",
		),
	"workflow_id?": type("string").describe(
		"Workflow identifier (required for begin/record; optional for export/status/manifest/clean/recall)",
	),
	"id?": type("string").describe("Alias for workflow_id"),
	"workspace_path?": type("string").describe("Target workspace directory (defaults to '.reverse' in project root)"),
	"format_type?": type.enumerated("markdown", "json").describe("Report format: 'markdown' (default) or 'json'"),
	"clean_dumps_only?": type("boolean").describe(
		"When cleaning, remove only dumps while keeping scripts (default false: cleans dumps and scripts)",
	),
	"experimental_targets?": type("string[]").describe(
		"Specific named experimental targets to clean (relative to workspace). Defaults to all classified experimental entries.",
	),
	"include_protected?": type("boolean").describe(
		"Request deletion of protected artifacts. Requires explicit confirmation decision via available approval not free boolean.",
	),
	"run_id?": type("string").describe("Experiment run identifier (required for record; optional for begin)"),
	"step_id?": type("string").describe(
		"Workflow step identifier (required for begin; optional verification for record)",
	),
	"purpose?": type("string").describe(
		"Concise experiment goal and hypothesis/question being tested (required for begin)",
	),
	"command?": type("string").describe("Planned execution command for the experiment (required for begin)"),
	"inputs?": type("string[]").describe("Explicit input file paths consumed by the experiment"),
	"script_paths?": type("string[]").describe(
		"Script file paths (existing reused project scripts at begin, or run-local scripts at record)",
	),
	"output_paths?": type("string[]").describe(
		"Output artifact file paths generated inside the run directory (required for succeeded record)",
	),
	"exit_code?": type("number.integer").describe(
		"Process exit code for experiment run (required for record; 0 = succeeded)",
	),
	"summary?": type("string").describe(
		"Empirical result or error summary for the experiment run (required for record)",
	),
	"evidence_ids?": type("string[]").describe("Existing evidence ledger IDs associated with this experiment run"),
	"query?": type("string").describe(
		"Case-insensitive substring query across purpose, summary, command, and script paths for recall",
	),
	"target_hash?": type("string").describe("Exact target SHA-256 filter for recall"),
	"limit?": type("1 <= number.integer <= 20").describe("Maximum number of recalled runs to return (1-20, default 5)"),
});

export type ReverseWorkspaceParams = typeof reverseWorkspaceSchema.infer;

export interface ReverseWorkspaceDetails {
	action: "export" | "status" | "manifest" | "clean" | "begin" | "record" | "recall";
	workspace_dir: string;
	manifest?: ReverseWorkspaceManifest;
	inspection?: InspectWorkspaceResult;
	clean_result?: CleanWorkspaceResult;
	cancelled?: boolean;
	workflow_id?: string;
	step_id?: string;
	run_id?: string;
	run_dir?: string;
	relative_run_dir?: string;
	paths?: AnalysisRunPaths;
	run?: AnalysisRunRecord;
	artifact_refs?: string[];
	idempotent_retry?: boolean;
	recent_runs?: AnalysisRunRecall[];
	recalled_runs?: AnalysisRunRecall[];
	reusable_script_paths?: string[];
}

export class ReverseWorkspaceTool implements AgentTool<typeof reverseWorkspaceSchema, ReverseWorkspaceDetails> {
	readonly name = "reverse_workspace";
	readonly label = "Reverse Engineering Workspace Manager";
	readonly summary =
		"Standardized reverse-engineering workspace manager: creates and validates local .reverse/ layout with manifest, target profile, workflow, evidence ledger, findings, and safe artifact references.";
	readonly description: string;
	readonly parameters = reverseWorkspaceSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolApprovalDecision => {
		if (args && typeof args === "object" && "action" in args) {
			const action = String(args.action);
			if (action === "clean") {
				if ("include_protected" in args && args.include_protected === true) {
					return {
						tier: "write",
						override: true,
						policy: "prompt",
						reason: "Deleting protected artifacts requires explicit user confirmation.",
					};
				}
				return "write";
			}
			if (action === "export" || action === "begin" || action === "record") {
				return "write";
			}
		}
		return "read";
	};

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(reverseWorkspaceDescription);
	}

	async execute(
		_toolCallId: string,
		params: ReverseWorkspaceParams,
		signal?: AbortSignal,
		_onUpdate?: (result: AgentToolResult<ReverseWorkspaceDetails>) => void,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<ReverseWorkspaceDetails> & { details: ReverseWorkspaceDetails }> {
		throwIfAborted(signal);

		const projectDir = this.session.cwd ?? getProjectDir();
		const workspacePath = params.workspace_path || DEFAULT_WORKSPACE_DIR;

		switch (params.action) {
			case "export": {
				const workflowStore = new ReverseWorkflowStore({ repositoryRoot: projectDir });
				const evidenceStore = new EvidenceStore({ repositoryRoot: projectDir });

				let workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					const allWorkflows = await workflowStore.list();
					if (allWorkflows.length > 0) {
						workflowId = allWorkflows[0].id;
					} else {
						throw new ToolError("workflow_id is required for 'export' action when no prior workflows exist.");
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
				const manifest = await loadWorkspaceManifest(path.resolve(projectDir, workspacePath));
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
				let confirmed = false;
				if (params.include_protected === true) {
					if (!params.experimental_targets || params.experimental_targets.length === 0) {
						throw new ToolError(
							"Explicit targets are required when requesting protected artifact deletion via 'experimental_targets'. Blanket deletion of protected artifacts is prohibited.",
						);
					}

					if (!_context?.ui?.confirm) {
						return {
							content: [
								{
									type: "text",
									text: `# Workspace Cleanup Refused: \`${workspacePath}\`\n\nDeletion of protected artifacts was refused because interactive UI confirmation is unavailable in this session. Protected artifacts (baseline, evidence, rollback, userfile) cannot be deleted without verified interactive confirmation.`,
								},
							],
							details: {
								action: "clean",
								workspace_dir: path.resolve(projectDir, workspacePath),
								cancelled: true,
							},
						};
					}

					const manifest = await loadWorkspaceManifest(path.resolve(projectDir, workspacePath));
					const targetedProtected = (manifest?.artifacts ?? [])
						.filter(
							a =>
								a.destination_path &&
								params.experimental_targets?.includes(a.destination_path) &&
								(a.protected ||
									(a.classification && a.classification !== "experiment") ||
									(!a.classification && a.kind === "script")),
						)
						.map(a => `${a.destination_path} (${a.classification ?? "userfile"})`);

					const protectedListing =
						targetedProtected.length > 0
							? targetedProtected.map(p => `  - ${p}`).join("\n")
							: params.experimental_targets.map(t => `  - ${t}`).join("\n");

					confirmed = await _context.ui.confirm(
						"Protected Workspace Artifact Deletion",
						`You are requesting deletion of the following protected artifacts:\n${protectedListing}\n\nCore reproducibility manifest and other materials will be retained. Confirm deletion?`,
					);

					if (!confirmed) {
						return {
							content: [
								{
									type: "text",
									text: `# Workspace Cleanup Cancelled: \`${workspacePath}\`\n\nDeletion of protected artifacts was denied by user. No protected artifacts were removed; all core files retained.`,
								},
							],
							details: {
								action: "clean",
								workspace_dir: path.resolve(projectDir, workspacePath),
								cancelled: true,
							},
						};
					}
				}

				const cleanResult = await cleanWorkspace({
					projectDir,
					workspaceDir: workspacePath,
					removeDumpsOnly: params.clean_dumps_only ?? false,
					experimentalTargets: params.experimental_targets,
					includeProtected: params.include_protected ?? false,
					confirmDeleteProtected: confirmed ? async () => true : undefined,
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

				if (cleanResult.protected_files && cleanResult.protected_files.length > 0) {
					lines.push(`- **Protected Artifacts Retained**: ${cleanResult.protected_files.length}`);
					for (const p of cleanResult.protected_files) {
						lines.push(`  - \`${p}\` (protected)`);
					}
				}

				if (cleanResult.locked_or_failed_files && cleanResult.locked_or_failed_files.length > 0) {
					lines.push("");
					lines.push("## Deletion Warnings / Locked Files");
					for (const fail of cleanResult.locked_or_failed_files) {
						lines.push(`- \`${fail.path}\`: ${fail.error}`);
					}
				}

				if (cleanResult.reproducibility) {
					lines.push("");
					lines.push("## Minimal Reproducibility Manifest");
					lines.push(`- **Retained Core Artifacts**: ${cleanResult.reproducibility.retained_count}`);
					lines.push(`- **Manifest Saved**: \`${cleanResult.reproducibility.manifest_path}\``);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "clean",
						workspace_dir: cleanResult.workspace_dir,
						clean_result: cleanResult,
					},
				};
			}

			case "begin": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'begin' action.");
				}
				if (!params.step_id) {
					throw new ToolError("step_id is required for 'begin' action.");
				}
				if (!params.purpose) {
					throw new ToolError("purpose is required for 'begin' action.");
				}
				if (!params.command) {
					throw new ToolError("command is required for 'begin' action.");
				}

				const workflowStore = new ReverseWorkflowStore({ repositoryRoot: projectDir });
				const beginRes = await beginAnalysisRun({
					projectDir,
					workspaceDir: workspacePath,
					workflowId,
					stepId: params.step_id,
					purpose: params.purpose,
					command: params.command,
					runId: params.run_id,
					inputs: params.inputs,
					scriptPaths: params.script_paths,
					workflowStore,
				});

				const lines = [
					`# Initialized Experiment Run: \`${beginRes.run_id}\``,
					"",
					`- **Workflow**: \`${beginRes.workflow_id}\` (step \`${beginRes.step_id}\`)`,
					`- **Target SHA-256**: \`${beginRes.run.target_sha256}\``,
					`- **Run Directory**: \`${beginRes.relative_run_dir}\` (\`${beginRes.run_dir}\`)`,
					`- **Scripts Directory**: \`${beginRes.paths.relative.scripts_dir}\` (\`${beginRes.scripts_dir}\`)`,
					`- **Dumps Directory**: \`${beginRes.paths.relative.dumps_dir}\` (\`${beginRes.dumps_dir}\`)`,
					`- **Reports Directory**: \`${beginRes.paths.relative.reports_dir}\` (\`${beginRes.reports_dir}\`)`,
					`- **Temp Directory**: \`${beginRes.paths.relative.tmp_dir}\` (\`${beginRes.tmp_dir}\`)`,
					`- **Run Metadata**: \`${beginRes.paths.relative.run_json}\``,
					`- **Recorded Inputs**: ${beginRes.run.inputs.length}`,
					`- **Pre-Existing Scripts**: ${beginRes.run.scripts.length}`,
					`- **Prior Same-Target Runs**: ${beginRes.recent_runs.length}`,
					`- **Reusable Verified Scripts**: ${beginRes.reusable_script_paths.length}`,
				];

				if (beginRes.reusable_script_paths.length > 0) {
					lines.push("");
					lines.push("## Reusable Script Absolute Paths");
					for (const scriptAbsPath of beginRes.reusable_script_paths) {
						lines.push(`- \`${scriptAbsPath}\``);
					}
				}

				if (beginRes.recent_runs.length > 0) {
					lines.push("");
					lines.push("## Recent Runs for Same Target SHA-256");
					for (const item of beginRes.recent_runs) {
						const exitInfo = item.run.exit_code !== undefined ? `, exit=${item.run.exit_code}` : "";
						lines.push(
							`- \`${item.run.id}\` (\`${item.run.status}\`${exitInfo}, reuse: \`${item.reuse_status}\`, step \`${item.run.step_id}\`): ${item.run.purpose}`,
						);
						if (item.run.summary) {
							lines.push(`  - Summary: ${item.run.summary}`);
						}
						for (const reason of item.reuse_reasons) {
							lines.push(`  - Reuse Check: ${reason}`);
						}
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "begin",
						workspace_dir: beginRes.workspace_dir,
						workflow_id: beginRes.workflow_id,
						step_id: beginRes.step_id,
						run_id: beginRes.run_id,
						run_dir: beginRes.run_dir,
						relative_run_dir: beginRes.relative_run_dir,
						paths: beginRes.paths,
						run: beginRes.run,
						recent_runs: beginRes.recent_runs,
						reusable_script_paths: beginRes.reusable_script_paths,
					},
				};
			}

			case "record": {
				const workflowId = params.workflow_id ?? params.id;
				if (!workflowId) {
					throw new ToolError("workflow_id is required for 'record' action.");
				}
				if (!params.run_id) {
					throw new ToolError("run_id is required for 'record' action.");
				}
				if (params.exit_code === undefined || params.exit_code === null) {
					throw new ToolError("exit_code is required for 'record' action.");
				}
				if (!params.summary) {
					throw new ToolError("summary is required for 'record' action.");
				}

				const workflowStore = new ReverseWorkflowStore({ repositoryRoot: projectDir });
				const evidenceStore = new EvidenceStore({ repositoryRoot: projectDir });
				const recordRes = await recordAnalysisRun({
					projectDir,
					workspaceDir: workspacePath,
					workflowId,
					runId: params.run_id,
					exitCode: params.exit_code,
					summary: params.summary,
					stepId: params.step_id,
					purpose: params.purpose,
					command: params.command,
					inputs: params.inputs,
					scriptPaths: params.script_paths,
					outputPaths: params.output_paths,
					evidenceIds: params.evidence_ids,
					workflowStore,
					evidenceStore,
				});

				const lines = [
					`# Recorded Experiment Run: \`${recordRes.run_id}\` (${recordRes.run.status})`,
					"",
					`- **Workflow**: \`${recordRes.workflow_id}\` (step \`${recordRes.step_id}\`)`,
					`- **Status**: \`${recordRes.run.status}\` (exit code ${recordRes.run.exit_code})`,
					`- **Summary**: ${recordRes.run.summary}`,
					`- **Run Metadata**: \`${recordRes.paths.relative.run_json}\``,
					`- **Scripts Recorded**: ${recordRes.run.scripts.length}`,
					`- **Outputs Recorded**: ${recordRes.run.outputs.length}`,
					`- **Linked Workflow Artifact Refs**: ${recordRes.artifact_refs.length}`,
				];

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "record",
						workspace_dir: recordRes.workspace_dir,
						workflow_id: recordRes.workflow_id,
						step_id: recordRes.step_id,
						run_id: recordRes.run_id,
						run_dir: recordRes.run_dir,
						relative_run_dir: recordRes.relative_run_dir,
						paths: recordRes.paths,
						run: recordRes.run,
						artifact_refs: recordRes.artifact_refs,
						idempotent_retry: recordRes.idempotent_retry,
					},
				};
			}

			case "recall": {
				const workflowId = params.workflow_id ?? params.id;
				const recalledRuns = await recallAnalysisRuns(projectDir, {
					workspaceDir: workspacePath,
					workflowId,
					targetHash: params.target_hash,
					query: params.query,
					limit: params.limit,
				});
				const reusableScriptPaths = Array.from(new Set(recalledRuns.flatMap(item => item.reusable_script_paths)));

				const lines = [
					`# Recalled Experiment Runs: \`${workspacePath}\``,
					"",
					`- **Matched Runs**: ${recalledRuns.length}`,
					`- **Reusable Verified Scripts**: ${reusableScriptPaths.length}`,
				];
				if (workflowId) lines.push(`- **Workflow Filter**: \`${workflowId}\``);
				if (params.target_hash) lines.push(`- **Target SHA-256 Filter**: \`${params.target_hash}\``);
				if (params.query) lines.push(`- **Query Filter**: \`${params.query}\``);

				if (reusableScriptPaths.length > 0) {
					lines.push("");
					lines.push("## Reusable Script Absolute Paths");
					for (const scriptAbsPath of reusableScriptPaths) {
						lines.push(`- \`${scriptAbsPath}\``);
					}
				}

				if (recalledRuns.length === 0) {
					lines.push("");
					lines.push("No matching managed experiment runs found.");
				} else {
					lines.push("");
					lines.push("## Experiment History");
					for (const item of recalledRuns) {
						const exitInfo = item.run.exit_code !== undefined ? `, exit=${item.run.exit_code}` : "";
						lines.push(
							`- \`${item.run.id}\` (workflow \`${item.run.workflow_id}\`, step \`${item.run.step_id}\`, status \`${item.run.status}\`${exitInfo}, reuse \`${item.reuse_status}\`)`,
						);
						lines.push(`  - Target SHA-256: \`${item.run.target_sha256}\``);
						lines.push(`  - Purpose: ${item.run.purpose}`);
						lines.push(`  - Command: \`${item.run.command}\``);
						if (item.run.summary) {
							lines.push(`  - Summary: ${item.run.summary}`);
						}
						for (const reason of item.reuse_reasons) {
							lines.push(`  - Reuse Check: ${reason}`);
						}
						if (item.reusable_script_paths.length > 0) {
							lines.push(`  - Reusable Scripts: ${item.reusable_script_paths.map(p => `\`${p}\``).join(", ")}`);
						}
					}
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "recall",
						workspace_dir: path.resolve(projectDir, workspacePath),
						...(workflowId ? { workflow_id: workflowId } : {}),
						recalled_runs: recalledRuns,
						reusable_script_paths: reusableScriptPaths,
					},
				};
			}
		}
	}
}
