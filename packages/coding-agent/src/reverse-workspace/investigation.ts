import type { Dirent, Stats } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isEnoent, logger } from "@reverse/utils";
import { withFileLock } from "@reverse/utils/file-lock";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { EvidenceStore } from "../evidence/store";
import type { ReverseWorkflowRecord } from "../reverse-workflow/contracts";
import { ReverseWorkflowStore } from "../reverse-workflow/store";
import { DEFAULT_WORKSPACE_DIR } from "./contracts";
import {
	atomicWriteFile,
	assertRealPathWithin,
	hashFile,
	redactSecrets,
	deterministicJsonStringify,
	type SafeResolvedPath,
} from "./atomic";

export const ANALYSIS_RUN_SUBDIRS = ["scripts", "dumps", "reports", "tmp"] as const;
export type AnalysisRunSubdir = (typeof ANALYSIS_RUN_SUBDIRS)[number];

const ANALYSIS_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

/** 进程内按 run 目录串行化写入锁链 */
const ANALYSIS_RUN_WRITE_CHAINS = new Map<string, Promise<unknown>>();

async function withAnalysisRunWrite<T>(runDir: string, lockPath: string, operation: () => Promise<T>): Promise<T> {
	await fs.mkdir(runDir, { recursive: true });
	const run = (ANALYSIS_RUN_WRITE_CHAINS.get(runDir) ?? Promise.resolve()).then(() =>
		withFileLock(lockPath, operation, { retries: 200, retryDelayMs: 50 }),
	);
	const guarded = run.catch(() => undefined);
	ANALYSIS_RUN_WRITE_CHAINS.set(runDir, guarded);
	try {
		return await run;
	} finally {
		if (ANALYSIS_RUN_WRITE_CHAINS.get(runDir) === guarded) {
			ANALYSIS_RUN_WRITE_CHAINS.delete(runDir);
		}
	}
}

export interface AnalysisFileRef {
	path: string;
	sha256: string;
	size_bytes: number;
}

export interface AnalysisRunRecord {
	schema_version: "1";
	id: string;
	workflow_id: string;
	step_id: string;
	target_sha256: string;
	purpose: string;
	command: string;
	status: "running" | "succeeded" | "failed";
	inputs: AnalysisFileRef[];
	scripts: AnalysisFileRef[];
	outputs: AnalysisFileRef[];
	evidence_ids: string[];
	created_at: string;
	finished_at?: string;
	exit_code?: number;
	summary?: string;
}

export interface AnalysisRunPaths {
	run_dir: string;
	run_json: string;
	scripts_dir: string;
	dumps_dir: string;
	reports_dir: string;
	tmp_dir: string;
	relative: {
		run_dir: string;
		run_json: string;
		scripts_dir: string;
		dumps_dir: string;
		reports_dir: string;
		tmp_dir: string;
	};
}

export interface BeginAnalysisRunOptions {
	projectDir: string;
	workspaceDir?: string;
	workflowId: string;
	stepId: string;
	purpose: string;
	command: string;
	runId?: string;
	inputs?: string[];
	scriptPaths?: string[];
	workflowStore?: ReverseWorkflowStore;
}

export type AnalysisRunReuseStatus = "available" | "changed" | "missing" | "incomplete";

export interface RecallAnalysisRunsOptions {
	workspaceDir?: string;
	workflowId?: string;
	targetHash?: string;
	query?: string;
	limit?: number;
}

export interface AnalysisRunRecall {
	run: AnalysisRunRecord;
	run_dir: string;
	relative_run_dir: string;
	run_json: string;
	reuse_status: AnalysisRunReuseStatus;
	reuse_reasons: string[];
	reusable_script_paths: string[];
}

export interface LoadInvestigationBriefOptions {
	workspaceDir?: string;
	stateRoot?: string;
}

export interface BeginAnalysisRunResult {
	workspace_dir: string;
	relative_workspace_dir: string;
	workflow_id: string;
	step_id: string;
	run_id: string;
	run_dir: string;
	relative_run_dir: string;
	run_json: string;
	scripts_dir: string;
	dumps_dir: string;
	reports_dir: string;
	tmp_dir: string;
	paths: AnalysisRunPaths;
	run: AnalysisRunRecord;
	recent_runs: AnalysisRunRecall[];
	reusable_script_paths: string[];
}

export interface RecordAnalysisRunOptions {
	projectDir: string;
	workspaceDir?: string;
	workflowId: string;
	runId: string;
	exitCode: number;
	summary: string;
	stepId?: string;
	purpose?: string;
	command?: string;
	inputs?: string[];
	scriptPaths?: string[];
	outputPaths?: string[];
	evidenceIds?: string[];
	workflowStore?: ReverseWorkflowStore;
	evidenceStore?: EvidenceStore;
}

export interface RecordAnalysisRunResult {
	workspace_dir: string;
	relative_workspace_dir: string;
	workflow_id: string;
	step_id: string;
	run_id: string;
	run_dir: string;
	relative_run_dir: string;
	run_json: string;
	paths: AnalysisRunPaths;
	run: AnalysisRunRecord;
	artifact_refs: string[];
	idempotent_retry: boolean;
}

export interface ResolveAnalysisOutputPathOptions {
	projectDir: string;
	outputPath: string;
	runDir?: string;
	paths?: AnalysisRunPaths;
}

export interface SafeAnalysisOutputPath {
	resolvedPath: string;
	realPath: string;
	relativePath: string;
	runRelativePath: string;
	subdir: AnalysisRunSubdir;
}

export interface LoadAnalysisExecutionOptions {
	projectDir: string;
	workspaceDir?: string;
	workflowId: string;
	stepId: string;
	runId: string;
	inputPaths?: string[];
	outputPaths?: string[];
	workflowStore?: ReverseWorkflowStore;
}

export interface LoadAnalysisExecutionResult {
	workspace_dir: string;
	relative_workspace_dir: string;
	run: AnalysisRunRecord;
	paths: AnalysisRunPaths;
	inputRefs: AnalysisFileRef[];
	outputPaths: SafeAnalysisOutputPath[];
}

export function validateAnalysisIdentifier(fieldName: string, rawValue: string | undefined): string {
	const trimmed = rawValue?.trim() ?? "";
	if (!ANALYSIS_ID_PATTERN.test(trimmed)) {
		throw new ToolError(
			`Invalid ${fieldName} '${rawValue ?? ""}': must match [A-Za-z0-9_-]+ and be 1..128 characters.`,
		);
	}
	return trimmed;
}

export function createAnalysisRunId(): string {
	return `run_${Bun.randomUUIDv7()}`;
}

function requireNonEmptyText(fieldName: string, rawValue: string | undefined): string {
	const trimmed = rawValue?.trim() ?? "";
	if (trimmed.length === 0) {
		throw new ToolError(`Field '${fieldName}' is required for reverse_workspace experiment tracking.`);
	}
	return trimmed;
}

async function resolveSafeWorkspaceDir(projectDir: string, workspaceDir?: string): Promise<SafeResolvedPath> {
	const resolvedProjectDir = path.resolve(projectDir);
	const realProjectDir = await fs.realpath(resolvedProjectDir);
	const candidate = workspaceDir?.trim() || DEFAULT_WORKSPACE_DIR;

	let resolved: SafeResolvedPath;
	try {
		resolved = await assertRealPathWithin(resolvedProjectDir, candidate, { baseDir: resolvedProjectDir });
	} catch (err) {
		throw new ToolError(`Invalid workspace_path '${candidate}': ${err instanceof Error ? err.message : String(err)}`);
	}

	if (resolved.resolvedPath === resolvedProjectDir || resolved.realPath === realProjectDir) {
		throw new ToolError(`Workspace directory cannot be the project root directory itself: '${candidate}'`);
	}

	try {
		const stat = await fs.stat(resolved.resolvedPath);
		if (!stat.isDirectory()) {
			throw new ToolError(`Workspace path exists and is not a directory: '${candidate}'`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
			throw new ToolError(
				`Failed to inspect workspace directory '${candidate}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	return resolved;
}

async function resolveSafeFileRef(
	allowedRootDir: string,
	rawPath: string,
	projectDir: string,
	label: string,
): Promise<AnalysisFileRef & { resolvedPath: string; realPath: string }> {
	let safePath: SafeResolvedPath;
	try {
		safePath = await assertRealPathWithin(allowedRootDir, rawPath, {
			baseDir: projectDir,
			requireRegularFile: true,
		});
	} catch (err) {
		throw new ToolError(`Invalid ${label} path '${rawPath}': ${err instanceof Error ? err.message : String(err)}`);
	}

	const realProjectDir = await fs.realpath(path.resolve(projectDir));
	const expectedRealPath = path.join(realProjectDir, ...safePath.relativePath.split("/").filter(Boolean));
	const entryStat = await fs.lstat(safePath.resolvedPath);
	if (entryStat.isSymbolicLink() || safePath.realPath !== expectedRealPath) {
		throw new ToolError(
			`Invalid ${label} path '${rawPath}': Symlink escape violation: symbolic link is not allowed.`,
		);
	}

	const hashed = await hashFile(safePath.resolvedPath);
	if (!hashed) {
		throw new ToolError(`Failed to read or hash ${label} file '${rawPath}'.`);
	}

	return {
		path: safePath.relativePath,
		sha256: hashed.sha256,
		size_bytes: hashed.size,
		resolvedPath: safePath.resolvedPath,
		realPath: safePath.realPath,
	};
}

function buildRunPaths(projectDir: string, runDir: string): AnalysisRunPaths {
	const toRel = (target: string) => path.relative(projectDir, target).split(path.sep).join("/");
	const runJson = path.join(runDir, "run.json");
	const scriptsDir = path.join(runDir, "scripts");
	const dumpsDir = path.join(runDir, "dumps");
	const reportsDir = path.join(runDir, "reports");
	const tmpDir = path.join(runDir, "tmp");

	return {
		run_dir: runDir,
		run_json: runJson,
		scripts_dir: scriptsDir,
		dumps_dir: dumpsDir,
		reports_dir: reportsDir,
		tmp_dir: tmpDir,
		relative: {
			run_dir: toRel(runDir),
			run_json: toRel(runJson),
			scripts_dir: toRel(scriptsDir),
			dumps_dir: toRel(dumpsDir),
			reports_dir: toRel(reportsDir),
			tmp_dir: toRel(tmpDir),
		},
	};
}

/**
 * 分配受管理的逆向实验目录并持久化初始 running 状态记录（不自动执行命令、不修改原始样本）。
 */
export async function beginAnalysisRun(options: BeginAnalysisRunOptions): Promise<BeginAnalysisRunResult> {
	const resolvedProjectDir = path.resolve(options.projectDir);
	const workflowId = validateAnalysisIdentifier("workflow_id", options.workflowId);
	const stepId = requireNonEmptyText("step_id", options.stepId);
	const purpose = redactSecrets(requireNonEmptyText("purpose", options.purpose));
	const command = redactSecrets(requireNonEmptyText("command", options.command));
	const runId =
		options.runId !== undefined ? validateAnalysisIdentifier("run_id", options.runId) : createAnalysisRunId();

	const workspace = await resolveSafeWorkspaceDir(resolvedProjectDir, options.workspaceDir);
	const candidateRunDir = path.join(workspace.resolvedPath, "analysis", workflowId, "runs", runId);

	let safeRunDir: SafeResolvedPath;
	try {
		safeRunDir = await assertRealPathWithin(workspace.resolvedPath, candidateRunDir, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(
			`Unsafe analysis run directory for '${runId}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	const workflowStore = options.workflowStore ?? new ReverseWorkflowStore({ repositoryRoot: resolvedProjectDir });
	const workflow = await workflowStore.get(workflowId);
	if (!workflow) {
		throw new ToolError(`Workflow '${workflowId}' not found.`);
	}

	const step = workflow.steps.find(s => s.id === stepId);
	if (!step) {
		throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);
	}

	if (!workflow.target_sha256 || workflow.target_sha256.trim().length === 0) {
		throw new ToolError(
			`Workflow '${workflowId}' does not have an established target_sha256; cannot begin verified experiment run.`,
		);
	}

	const targetCandidate = workflow.target_abs_path || workflow.target;
	const targetRef = await resolveSafeFileRef(resolvedProjectDir, targetCandidate, resolvedProjectDir, "target");
	if (targetRef.sha256.toLowerCase() !== workflow.target_sha256.toLowerCase()) {
		throw new ToolError(
			`Target file '${workflow.target}' SHA-256 mismatch: workflow recorded '${workflow.target_sha256}', current file is '${targetRef.sha256}'.`,
		);
	}

	const inputs: AnalysisFileRef[] = [
		{
			path: targetRef.path,
			sha256: targetRef.sha256,
			size_bytes: targetRef.size_bytes,
		},
	];
	const seenInputPaths = new Set<string>([targetRef.path]);

	for (const rawInput of options.inputs ?? []) {
		const inputRef = await resolveSafeFileRef(resolvedProjectDir, rawInput, resolvedProjectDir, "input");
		if (seenInputPaths.has(inputRef.path)) continue;
		seenInputPaths.add(inputRef.path);
		inputs.push({
			path: inputRef.path,
			sha256: inputRef.sha256,
			size_bytes: inputRef.size_bytes,
		});
	}

	const scripts: AnalysisFileRef[] = [];
	const seenScriptPaths = new Set<string>();
	for (const rawScript of options.scriptPaths ?? []) {
		let checkedScriptPath: SafeResolvedPath;
		try {
			checkedScriptPath = await assertRealPathWithin(resolvedProjectDir, rawScript, {
				baseDir: resolvedProjectDir,
			});
		} catch (err) {
			throw new ToolError(
				`Invalid script_paths entry '${rawScript}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		let existsOnDisk = false;
		try {
			await fs.lstat(checkedScriptPath.resolvedPath);
			existsOnDisk = true;
		} catch (err) {
			if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
				throw err;
			}
		}

		if (existsOnDisk) {
			const scriptRef = await resolveSafeFileRef(resolvedProjectDir, rawScript, resolvedProjectDir, "script");
			if (!seenScriptPaths.has(scriptRef.path)) {
				seenScriptPaths.add(scriptRef.path);
				scripts.push({
					path: scriptRef.path,
					sha256: scriptRef.sha256,
					size_bytes: scriptRef.size_bytes,
				});
			}
		} else {
			// 新建脚本必须在当前 run 目录内并在 record 阶段登记；指向其他位置的不存在文件直接报错
			const relToRun = path.relative(safeRunDir.resolvedPath, checkedScriptPath.resolvedPath);
			if (relToRun.startsWith("..") || path.isAbsolute(relToRun)) {
				throw new ToolError(`Existing script file '${rawScript}' does not exist.`);
			}
		}
	}

	const priorSameTargetRuns = await recallAnalysisRuns(resolvedProjectDir, {
		workspaceDir: options.workspaceDir,
		targetHash: targetRef.sha256,
		limit: 5,
	});
	const recentRuns = priorSameTargetRuns.filter(item => item.run.id !== runId);
	const reusableScriptPaths = Array.from(new Set(recentRuns.flatMap(item => item.reusable_script_paths)));

	const paths = buildRunPaths(resolvedProjectDir, safeRunDir.resolvedPath);
	const lockPath = path.join(safeRunDir.resolvedPath, "run.lock");
	const runRecord = await withAnalysisRunWrite(safeRunDir.resolvedPath, lockPath, async () => {
		try {
			await fs.lstat(paths.run_json);
			throw new ToolError(`Analysis run '${runId}' already exists for workflow '${workflowId}'.`);
		} catch (err) {
			if (err instanceof ToolError) throw err;
			if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
				throw err;
			}
		}

		for (const subdir of ANALYSIS_RUN_SUBDIRS) {
			const subdirPath = path.join(safeRunDir.resolvedPath, subdir);
			await fs.mkdir(subdirPath, { recursive: true });
			await assertRealPathWithin(safeRunDir.resolvedPath, subdirPath, { baseDir: resolvedProjectDir });
		}

		const record: AnalysisRunRecord = {
			schema_version: "1",
			id: runId,
			workflow_id: workflowId,
			step_id: stepId,
			target_sha256: targetRef.sha256,
			purpose,
			command,
			status: "running",
			inputs,
			scripts,
			outputs: [],
			evidence_ids: [],
			created_at: new Date().toISOString(),
		};

		await atomicWriteFile(paths.run_json, deterministicJsonStringify(record));
		return record;
	});

	return {
		workspace_dir: workspace.resolvedPath,
		relative_workspace_dir: workspace.relativePath || ".",
		workflow_id: workflowId,
		step_id: stepId,
		run_id: runId,
		run_dir: paths.run_dir,
		relative_run_dir: paths.relative.run_dir,
		run_json: paths.run_json,
		scripts_dir: paths.scripts_dir,
		dumps_dir: paths.dumps_dir,
		reports_dir: paths.reports_dir,
		tmp_dir: paths.tmp_dir,
		paths,
		run: runRecord,
		recent_runs: recentRuns,
		reusable_script_paths: reusableScriptPaths,
	};
}

async function verifyRecordedRefsUnchanged(
	projectDir: string,
	refs: AnalysisFileRef[],
	label: "input" | "script" | "output",
): Promise<void> {
	for (const ref of refs) {
		const current = await resolveSafeFileRef(projectDir, ref.path, projectDir, label);
		if (current.sha256 !== ref.sha256 || current.size_bytes !== ref.size_bytes) {
			throw new ToolError(
				`Recorded ${label} '${ref.path}' changed since run began (expected SHA-256 ${ref.sha256}, got ${current.sha256}). Start a new run with 'begin'.`,
			);
		}
	}
}

/**
 * 校验并持久化实验结果（复核输入与旧脚本未篡改、校验新脚本与输出位于当前 run 内、关联工作流步骤产物引用）。
 */
export async function recordAnalysisRun(options: RecordAnalysisRunOptions): Promise<RecordAnalysisRunResult> {
	const resolvedProjectDir = path.resolve(options.projectDir);
	const workflowId = validateAnalysisIdentifier("workflow_id", options.workflowId);
	const runId = validateAnalysisIdentifier("run_id", options.runId);

	if (typeof options.exitCode !== "number" || !Number.isInteger(options.exitCode)) {
		throw new ToolError("Field 'exit_code' must be an integer for reverse_workspace 'record'.");
	}
	const summary = redactSecrets(requireNonEmptyText("summary", options.summary));

	const workspace = await resolveSafeWorkspaceDir(resolvedProjectDir, options.workspaceDir);
	const candidateRunDir = path.join(workspace.resolvedPath, "analysis", workflowId, "runs", runId);

	let safeRunDir: SafeResolvedPath;
	try {
		safeRunDir = await assertRealPathWithin(workspace.resolvedPath, candidateRunDir, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(
			`Unsafe analysis run directory for '${runId}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	const paths = buildRunPaths(resolvedProjectDir, safeRunDir.resolvedPath);
	const lockPath = path.join(safeRunDir.resolvedPath, "run.lock");

	try {
		await assertRealPathWithin(safeRunDir.resolvedPath, paths.run_json, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});
	} catch {
		throw new ToolError(`Analysis run '${runId}' not found for workflow '${workflowId}'. Run 'begin' first.`);
	}

	const workflowStore = options.workflowStore ?? new ReverseWorkflowStore({ repositoryRoot: resolvedProjectDir });
	const workflow = await workflowStore.get(workflowId);
	if (!workflow) {
		throw new ToolError(`Workflow '${workflowId}' not found.`);
	}

	const normalizedEvidenceIds = Array.from(
		new Set((options.evidenceIds ?? []).map(id => id.trim()).filter(id => id.length > 0)),
	);
	if (normalizedEvidenceIds.length > 0) {
		const evidenceStore = options.evidenceStore ?? new EvidenceStore({ repositoryRoot: resolvedProjectDir });
		const allRecords = await evidenceStore.getAllRecords();
		const existingIds = new Set(allRecords.map(r => r.id));
		for (const evId of normalizedEvidenceIds) {
			if (!existingIds.has(evId)) {
				throw new ToolError(`Evidence record '${evId}' does not exist in the project evidence ledger.`);
			}
		}
	}

	const { finalRun, artifactRefs, idempotentRetry } = await withAnalysisRunWrite(
		safeRunDir.resolvedPath,
		lockPath,
		async () => {
			let existingRun: AnalysisRunRecord;
			try {
				const rawJson = await fs.readFile(paths.run_json, "utf8");
				existingRun = JSON.parse(rawJson) as AnalysisRunRecord;
			} catch (err) {
				throw new ToolError(
					`Failed to read run record '${runId}': ${err instanceof Error ? err.message : String(err)}`,
				);
			}

			if (
				!existingRun ||
				existingRun.schema_version !== "1" ||
				existingRun.id !== runId ||
				existingRun.workflow_id !== workflowId
			) {
				throw new ToolError(`Corrupt or mismatched run.json for workflow '${workflowId}' run '${runId}'.`);
			}

			const step = workflow.steps.find(s => s.id === existingRun.step_id);
			if (!step) {
				throw new ToolError(`Step '${existingRun.step_id}' not found in workflow '${workflowId}'.`);
			}

			if (options.stepId !== undefined && options.stepId.trim() !== existingRun.step_id) {
				throw new ToolError(
					`Step ID mismatch for run '${runId}': expected '${existingRun.step_id}', got '${options.stepId.trim()}'.`,
				);
			}
			if (options.purpose !== undefined && redactSecrets(options.purpose.trim()) !== existingRun.purpose) {
				throw new ToolError(`Conflict for run '${runId}': purpose does not match recorded run purpose.`);
			}
			if (options.command !== undefined && redactSecrets(options.command.trim()) !== existingRun.command) {
				throw new ToolError(`Conflict for run '${runId}': command does not match recorded run command.`);
			}

			if (options.inputs !== undefined) {
				const recordedInputSet = new Set(existingRun.inputs.map(i => i.path));
				for (const rawInput of options.inputs) {
					const inputRef = await resolveSafeFileRef(resolvedProjectDir, rawInput, resolvedProjectDir, "input");
					if (!recordedInputSet.has(inputRef.path)) {
						throw new ToolError(
							`Input '${rawInput}' was not declared at 'begin' for run '${runId}'. Start a new run with 'begin'.`,
						);
					}
				}
			}

			// 已完成记录：校验是否完全一致的幂等重试，冲突则拒绝修改历史
			if (existingRun.status !== "running") {
				if (existingRun.exit_code !== options.exitCode) {
					throw new ToolError(
						`Conflict recording run '${runId}': already finalized with exit_code ${existingRun.exit_code}, cannot overwrite with ${options.exitCode}.`,
					);
				}
				if (existingRun.summary !== summary) {
					throw new ToolError(`Conflict recording run '${runId}': already finalized with a different summary.`);
				}
				if (
					normalizedEvidenceIds.length !== existingRun.evidence_ids.length ||
					!normalizedEvidenceIds.every((id, idx) => id === existingRun.evidence_ids[idx])
				) {
					throw new ToolError(`Conflict recording run '${runId}': already finalized with different evidence_ids.`);
				}

				await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.inputs, "input");
				await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.scripts, "script");
				await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.outputs, "output");

				const submittedOutputPaths: string[] = [];
				const seenSubOut = new Set<string>();
				for (const rawOut of options.outputPaths ?? []) {
					const outRef = await resolveSafeFileRef(safeRunDir.resolvedPath, rawOut, resolvedProjectDir, "output");
					if (!seenSubOut.has(outRef.path)) {
						seenSubOut.add(outRef.path);
						submittedOutputPaths.push(outRef.path);
					}
				}
				if (
					submittedOutputPaths.length !== existingRun.outputs.length ||
					!submittedOutputPaths.every((p, idx) => p === existingRun.outputs[idx].path)
				) {
					throw new ToolError(`Conflict recording run '${runId}': already finalized with different output_paths.`);
				}

				const submittedScriptSet = new Set<string>();
				for (const rawScr of options.scriptPaths ?? []) {
					const scrRef = await resolveSafeFileRef(resolvedProjectDir, rawScr, resolvedProjectDir, "script");
					submittedScriptSet.add(scrRef.path);
				}
				const existingScriptSet = new Set(existingRun.scripts.map(s => s.path));
				for (const subPath of submittedScriptSet) {
					if (!existingScriptSet.has(subPath)) {
						throw new ToolError(
							`Conflict recording run '${runId}': script '${subPath}' was not part of finalized run.`,
						);
					}
				}
				const runRelPrefix = `${paths.relative.run_dir}/`;
				for (const recScript of existingRun.scripts) {
					if (recScript.path.startsWith(runRelPrefix) && !submittedScriptSet.has(recScript.path)) {
						throw new ToolError(
							`Conflict recording run '${runId}': finalized run-local script '${recScript.path}' omitted from script_paths.`,
						);
					}
				}

				const refs = Array.from(
					new Set([
						...existingRun.scripts.map(s => s.path),
						...existingRun.outputs.map(o => o.path),
						paths.relative.run_json,
					]),
				);
				return { finalRun: existingRun, artifactRefs: refs, idempotentRetry: true };
			}

			// running 状态：写入前复核所有输入和已有脚本 hash，变化则报错并保留 running 记录
			await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.inputs, "input");
			await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.scripts, "script");

			const finalScripts: AnalysisFileRef[] = [...existingRun.scripts];
			const seenScriptPaths = new Set<string>(existingRun.scripts.map(s => s.path));

			for (const rawScript of options.scriptPaths ?? []) {
				const projectScriptRef = await resolveSafeFileRef(
					resolvedProjectDir,
					rawScript,
					resolvedProjectDir,
					"script",
				);
				if (seenScriptPaths.has(projectScriptRef.path)) {
					continue;
				}
				// 新脚本必须位于当前 run 目录内
				const runLocalScriptRef = await resolveSafeFileRef(
					safeRunDir.resolvedPath,
					rawScript,
					resolvedProjectDir,
					"run-local script",
				);
				if (runLocalScriptRef.resolvedPath === paths.run_json || runLocalScriptRef.resolvedPath === lockPath) {
					throw new ToolError(`Cannot register internal run metadata file '${rawScript}' as a script.`);
				}
				seenScriptPaths.add(runLocalScriptRef.path);
				finalScripts.push({
					path: runLocalScriptRef.path,
					sha256: runLocalScriptRef.sha256,
					size_bytes: runLocalScriptRef.size_bytes,
				});
			}

			const finalOutputs: AnalysisFileRef[] = [];
			const seenOutputPaths = new Set<string>();
			for (const rawOutput of options.outputPaths ?? []) {
				const outRef = await resolveSafeFileRef(safeRunDir.resolvedPath, rawOutput, resolvedProjectDir, "output");
				if (outRef.resolvedPath === paths.run_json || outRef.resolvedPath === lockPath) {
					throw new ToolError(`Cannot register internal run metadata file '${rawOutput}' as an output.`);
				}
				if (seenOutputPaths.has(outRef.path)) continue;
				seenOutputPaths.add(outRef.path);
				finalOutputs.push({
					path: outRef.path,
					sha256: outRef.sha256,
					size_bytes: outRef.size_bytes,
				});
			}

			const status: "succeeded" | "failed" = options.exitCode === 0 ? "succeeded" : "failed";
			if (status === "succeeded" && finalOutputs.length === 0) {
				throw new ToolError(
					"Succeeded experiment run (exit_code = 0) requires at least one explicit regular file in 'output_paths'.",
				);
			}

			const updatedRun: AnalysisRunRecord = {
				...existingRun,
				status,
				scripts: finalScripts,
				outputs: finalOutputs,
				evidence_ids: normalizedEvidenceIds,
				finished_at: new Date().toISOString(),
				exit_code: options.exitCode,
				summary,
			};

			await atomicWriteFile(paths.run_json, deterministicJsonStringify(updatedRun));
			const refs = Array.from(
				new Set([
					...updatedRun.scripts.map(s => s.path),
					...updatedRun.outputs.map(o => o.path),
					paths.relative.run_json,
				]),
			);
			return { finalRun: updatedRun, artifactRefs: refs, idempotentRetry: false };
		},
	);

	try {
		await workflowStore.mergeStepArtifactRefs(workflowId, finalRun.step_id, artifactRefs);
	} catch (err) {
		throw new ToolError(
			`Run '${runId}' metadata was saved, but linking artifact_refs to workflow '${workflowId}' step '${finalRun.step_id}' failed: ${err instanceof Error ? err.message : String(err)}. Retry 'record' with identical parameters to repair workflow links without re-running the experiment.`,
		);
	}

	return {
		workspace_dir: workspace.resolvedPath,
		relative_workspace_dir: workspace.relativePath || ".",
		workflow_id: workflowId,
		step_id: finalRun.step_id,
		run_id: runId,
		run_dir: paths.run_dir,
		relative_run_dir: paths.relative.run_dir,
		run_json: paths.run_json,
		paths,
		run: finalRun,
		artifact_refs: artifactRefs,
		idempotent_retry: idempotentRetry,
	};
}

/**
 * 校验实验产物输出路径必须位于当前 run 的受管子目录（scripts/dumps/reports/tmp）内，
 * 禁止覆盖 run.json/run.lock 元数据、禁止目录充当输出文件、禁止任何符号链接或路径越界。
 */
export async function resolveAnalysisOutputPath(
	options: ResolveAnalysisOutputPathOptions,
): Promise<SafeAnalysisOutputPath> {
	const resolvedProjectDir = path.resolve(options.projectDir);
	const rawRunDir = options.runDir ?? options.paths?.run_dir;
	if (!rawRunDir || rawRunDir.trim().length === 0) {
		throw new ToolError("Run directory ('runDir' or 'paths.run_dir') is required to resolve analysis output path.");
	}

	let safeRunDir: SafeResolvedPath;
	try {
		safeRunDir = await assertRealPathWithin(resolvedProjectDir, rawRunDir, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(`Invalid run directory '${rawRunDir}': ${err instanceof Error ? err.message : String(err)}`);
	}

	try {
		const runDirStat = await fs.lstat(safeRunDir.resolvedPath);
		if (runDirStat.isSymbolicLink()) {
			throw new ToolError(
				`Invalid output path '${options.outputPath}': Symlink escape violation at run directory '${rawRunDir}'.`,
			);
		}
		if (!runDirStat.isDirectory()) {
			throw new ToolError(`Analysis run directory '${rawRunDir}' is not a directory.`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		throw new ToolError(
			`Analysis run directory '${rawRunDir}' does not exist: ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	let safeOut: SafeResolvedPath;
	try {
		safeOut = await assertRealPathWithin(safeRunDir.resolvedPath, options.outputPath, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(
			`Invalid output path '${options.outputPath}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	const runJsonPath = path.join(safeRunDir.resolvedPath, "run.json");
	const lockPath = path.join(safeRunDir.resolvedPath, "run.lock");
	const realRunJsonPath = path.join(safeRunDir.realPath, "run.json");
	const realLockPath = path.join(safeRunDir.realPath, "run.lock");

	if (
		safeOut.resolvedPath === runJsonPath ||
		safeOut.resolvedPath === lockPath ||
		safeOut.realPath === realRunJsonPath ||
		safeOut.realPath === realLockPath
	) {
		throw new ToolError(`Cannot overwrite internal run metadata file '${options.outputPath}'.`);
	}

	if (safeOut.resolvedPath === safeRunDir.resolvedPath || safeOut.realPath === safeRunDir.realPath) {
		throw new ToolError(`Invalid output path '${options.outputPath}': path is a directory, not a regular file.`);
	}

	const relToRun = path.relative(safeRunDir.resolvedPath, safeOut.resolvedPath);
	const segments = relToRun.split(path.sep).filter(Boolean);
	if (segments.length === 0) {
		throw new ToolError(`Invalid output path '${options.outputPath}': path is a directory, not a regular file.`);
	}

	const firstSegment = segments[0];
	if (!(ANALYSIS_RUN_SUBDIRS as readonly string[]).includes(firstSegment)) {
		throw new ToolError(
			`Invalid output path '${options.outputPath}': outputs must be confined within run subdirectories (${ANALYSIS_RUN_SUBDIRS.join(", ")}).`,
		);
	}
	if (segments.length === 1) {
		throw new ToolError(
			`Invalid output path '${options.outputPath}': path points to run subdirectory '${firstSegment}', not a regular file.`,
		);
	}

	// 逐级检查 run 目录内不存在符号链接，且已存在节点类型合法（父节点为目录、末节点为普通文件）
	let curPath = safeRunDir.resolvedPath;
	for (let i = 0; i < segments.length; i++) {
		curPath = path.join(curPath, segments[i]);
		try {
			const st = await fs.lstat(curPath);
			if (st.isSymbolicLink()) {
				throw new ToolError(
					`Invalid output path '${options.outputPath}': Symlink escape violation: symbolic link '${curPath}' is not allowed inside analysis run directory.`,
				);
			}
			if (i < segments.length - 1) {
				if (!st.isDirectory()) {
					throw new ToolError(
						`Invalid output path '${options.outputPath}': parent path '${curPath}' exists and is not a directory.`,
					);
				}
			} else if (!st.isFile()) {
				throw new ToolError(
					`Invalid output path '${options.outputPath}': path already exists and is not a regular file.`,
				);
			}
		} catch (err) {
			if (err instanceof ToolError) throw err;
			if (isEnoent(err)) {
				break;
			}
			throw err;
		}
	}

	const expectedRealOut = path.join(safeRunDir.realPath, ...segments);
	if (safeOut.realPath !== expectedRealOut) {
		throw new ToolError(
			`Invalid output path '${options.outputPath}': Symlink escape violation: resolved real path '${safeOut.realPath}' does not match '${expectedRealOut}'.`,
		);
	}

	return {
		resolvedPath: safeOut.resolvedPath,
		realPath: safeOut.realPath,
		relativePath: safeOut.relativePath,
		runRelativePath: segments.join("/"),
		subdir: firstSegment as AnalysisRunSubdir,
	};
}

/**
 * 在领域工具实际执行或写入产物前，以只读方式校验活跃实验 run 的工作流/步骤归属、running 状态、
 * 目标样本哈希与全部已登记输入/脚本完整性。允许只读消费同次 run 内的中间产物（不追加或改写 run.json），
 * 拒绝未在 begin 声明的外部输入并提示重新发起 begin。
 */
export async function loadAnalysisExecution(
	options: LoadAnalysisExecutionOptions,
): Promise<LoadAnalysisExecutionResult> {
	const resolvedProjectDir = path.resolve(options.projectDir);
	const workflowId = validateAnalysisIdentifier("workflow_id", options.workflowId);
	const stepId = requireNonEmptyText("step_id", options.stepId);
	const runId = validateAnalysisIdentifier("run_id", options.runId);

	const workspace = await resolveSafeWorkspaceDir(resolvedProjectDir, options.workspaceDir);

	const workflowStore = options.workflowStore ?? new ReverseWorkflowStore({ repositoryRoot: resolvedProjectDir });
	const workflow = await workflowStore.get(workflowId);
	if (!workflow) {
		throw new ToolError(`Workflow '${workflowId}' not found.`);
	}

	const step = workflow.steps.find(s => s.id === stepId);
	if (!step) {
		throw new ToolError(`Step '${stepId}' not found in workflow '${workflowId}'.`);
	}

	if (!workflow.target_sha256 || workflow.target_sha256.trim().length === 0) {
		throw new ToolError(
			`Workflow '${workflowId}' does not have an established target_sha256; cannot execute bound analysis run.`,
		);
	}

	const candidateRunDir = path.join(workspace.resolvedPath, "analysis", workflowId, "runs", runId);
	let safeRunDir: SafeResolvedPath;
	try {
		safeRunDir = await assertRealPathWithin(workspace.resolvedPath, candidateRunDir, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(
			`Unsafe analysis run directory for '${runId}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	try {
		const runDirStat = await fs.lstat(safeRunDir.resolvedPath);
		if (runDirStat.isSymbolicLink()) {
			throw new ToolError(`Unsafe analysis run directory for '${runId}': Symlink escape violation.`);
		}
		if (!runDirStat.isDirectory()) {
			throw new ToolError(`Analysis run '${runId}' not found for workflow '${workflowId}'. Run 'begin' first.`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		if (isEnoent(err)) {
			throw new ToolError(`Analysis run '${runId}' not found for workflow '${workflowId}'. Run 'begin' first.`);
		}
		throw err;
	}

	const paths = buildRunPaths(resolvedProjectDir, safeRunDir.resolvedPath);
	try {
		const runJsonStat = await fs.lstat(paths.run_json);
		if (runJsonStat.isSymbolicLink()) {
			throw new ToolError(`Unsafe run.json for '${runId}': Symlink escape violation.`);
		}
		if (!runJsonStat.isFile()) {
			throw new ToolError(`Analysis run '${runId}' not found for workflow '${workflowId}'. Run 'begin' first.`);
		}
		await assertRealPathWithin(safeRunDir.resolvedPath, paths.run_json, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});
	} catch (err) {
		if (err instanceof ToolError) throw err;
		throw new ToolError(`Analysis run '${runId}' not found for workflow '${workflowId}'. Run 'begin' first.`);
	}

	let parsedRun: unknown;
	try {
		const rawJson = await fs.readFile(paths.run_json, "utf8");
		parsedRun = JSON.parse(rawJson);
	} catch (err) {
		throw new ToolError(`Failed to read run record '${runId}': ${err instanceof Error ? err.message : String(err)}`);
	}

	if (isRecordObject(parsedRun)) {
		if (typeof parsedRun.workflow_id === "string" && parsedRun.workflow_id !== workflowId) {
			throw new ToolError(
				`Workflow ID mismatch for run '${runId}': expected '${parsedRun.workflow_id}', got '${workflowId}'.`,
			);
		}
		if (typeof parsedRun.id === "string" && parsedRun.id !== runId) {
			throw new ToolError(`Run ID mismatch in run.json: expected '${runId}', got '${parsedRun.id}'.`);
		}
	}

	if (!isValidAnalysisRunRecord(parsedRun, workflowId, runId)) {
		throw new ToolError(`Corrupt or mismatched run.json for workflow '${workflowId}' run '${runId}'.`);
	}

	const existingRun: AnalysisRunRecord = parsedRun;
	if (existingRun.step_id !== stepId) {
		throw new ToolError(`Step ID mismatch for run '${runId}': expected '${existingRun.step_id}', got '${stepId}'.`);
	}

	if (existingRun.status !== "running") {
		throw new ToolError(
			`Analysis run '${runId}' has status '${existingRun.status}' and is no longer 'running'. Start a new run with 'begin'.`,
		);
	}

	if (existingRun.target_sha256.toLowerCase() !== workflow.target_sha256.toLowerCase()) {
		throw new ToolError(
			`Target SHA-256 mismatch for run '${runId}': run recorded '${existingRun.target_sha256}', workflow expects '${workflow.target_sha256}'. Start a new run with 'begin'.`,
		);
	}

	const targetCandidate = workflow.target_abs_path || workflow.target;
	const targetRef = await resolveSafeFileRef(resolvedProjectDir, targetCandidate, resolvedProjectDir, "target");
	if (targetRef.sha256.toLowerCase() !== workflow.target_sha256.toLowerCase()) {
		throw new ToolError(
			`Target file '${workflow.target}' changed since run began (expected SHA-256 ${workflow.target_sha256}, got ${targetRef.sha256}). Start a new run with 'begin'.`,
		);
	}

	const recordedTargetInput = existingRun.inputs.find(i => i.path === targetRef.path);
	if (
		!recordedTargetInput ||
		recordedTargetInput.sha256.toLowerCase() !== targetRef.sha256.toLowerCase() ||
		recordedTargetInput.size_bytes !== targetRef.size_bytes
	) {
		throw new ToolError(
			`Target file '${targetRef.path}' is missing or mismatched in recorded inputs for run '${runId}'. Start a new run with 'begin'.`,
		);
	}

	// 复核 begin 阶段登记的全部输入与既有脚本均未发生篡改或丢失
	await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.inputs, "input");
	await verifyRecordedRefsUnchanged(resolvedProjectDir, existingRun.scripts, "script");

	const recordedInputsByPath = new Map<string, AnalysisFileRef>(existingRun.inputs.map(item => [item.path, item]));
	const inputRefs: AnalysisFileRef[] = [];
	const seenInputPaths = new Set<string>();

	for (const rawInput of options.inputPaths ?? []) {
		const inputRef = await resolveSafeFileRef(resolvedProjectDir, rawInput, resolvedProjectDir, "input");
		const recordedInput = recordedInputsByPath.get(inputRef.path);
		if (recordedInput) {
			if (inputRef.sha256 !== recordedInput.sha256 || inputRef.size_bytes !== recordedInput.size_bytes) {
				throw new ToolError(
					`Recorded input '${inputRef.path}' changed since run began (expected SHA-256 ${recordedInput.sha256}, got ${inputRef.sha256}). Start a new run with 'begin'.`,
				);
			}
			if (!seenInputPaths.has(inputRef.path)) {
				seenInputPaths.add(inputRef.path);
				inputRefs.push({
					path: inputRef.path,
					sha256: inputRef.sha256,
					size_bytes: inputRef.size_bytes,
				});
			}
			continue;
		}

		// 非 begin 登记输入：仅允许只读消费同次 run 目录内的安全中间产物，外部新输入必须报错并提示重新 begin
		const relToRun = path.relative(safeRunDir.resolvedPath, inputRef.resolvedPath);
		const isInsideCurrentRun = relToRun !== "" && !relToRun.startsWith("..") && !path.isAbsolute(relToRun);
		if (!isInsideCurrentRun) {
			throw new ToolError(
				`Input '${rawInput}' ('${inputRef.path}') was not declared in 'inputs' at 'begin' for run '${runId}'. Start a new run with 'begin' including all external inputs.`,
			);
		}

		await resolveAnalysisOutputPath({
			projectDir: resolvedProjectDir,
			runDir: safeRunDir.resolvedPath,
			outputPath: rawInput,
		});
		const runLocalRef = await resolveSafeFileRef(
			safeRunDir.resolvedPath,
			rawInput,
			resolvedProjectDir,
			"run-local intermediate input",
		);
		if (!seenInputPaths.has(runLocalRef.path)) {
			seenInputPaths.add(runLocalRef.path);
			inputRefs.push({
				path: runLocalRef.path,
				sha256: runLocalRef.sha256,
				size_bytes: runLocalRef.size_bytes,
			});
		}
	}

	const validatedOutputs: SafeAnalysisOutputPath[] = [];
	for (const rawOutput of options.outputPaths ?? []) {
		const safeOut = await resolveAnalysisOutputPath({
			projectDir: resolvedProjectDir,
			runDir: safeRunDir.resolvedPath,
			outputPath: rawOutput,
		});
		validatedOutputs.push(safeOut);
	}

	return {
		workspace_dir: workspace.resolvedPath,
		relative_workspace_dir: workspace.relativePath || ".",
		run: existingRun,
		paths,
		inputRefs,
		outputPaths: validatedOutputs,
	};
}

const SHA256_HEX_PATTERN = /^[a-fA-F0-9]{64}$/;
const MAX_INVESTIGATION_BRIEF_LINES = 30;
const MAX_INVESTIGATION_BRIEF_BYTES = 4096;
const BRIEF_TRUNCATION_HINT =
	'Brief truncated; call reverse_workspace(action: "recall") to query full experiment history and verify hashes.';

function isRecordObject(value: unknown): value is Record<string, unknown> {
	return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isPermissionFsError(err: unknown): boolean {
	if (!isRecordObject(err) || !("code" in err)) return false;
	const code = String(err.code);
	return code === "EACCES" || code === "EPERM";
}

function isSafeRelativeRefPath(rawPath: unknown): rawPath is string {
	if (typeof rawPath !== "string") return false;
	const trimmed = rawPath.trim();
	if (trimmed.length === 0 || trimmed.includes("\0") || path.isAbsolute(trimmed)) return false;
	const segments = trimmed.split(/[\\/]+/);
	return !segments.includes("..");
}

function isValidFileRefArray(value: unknown): value is AnalysisFileRef[] {
	if (!Array.isArray(value)) return false;
	return value.every(
		item =>
			isRecordObject(item) &&
			isSafeRelativeRefPath(item.path) &&
			typeof item.sha256 === "string" &&
			SHA256_HEX_PATTERN.test(item.sha256) &&
			typeof item.size_bytes === "number" &&
			Number.isInteger(item.size_bytes) &&
			item.size_bytes >= 0,
	);
}

function isValidAnalysisRunRecord(
	value: unknown,
	expectedWorkflowId: string,
	expectedRunId: string,
): value is AnalysisRunRecord {
	if (!isRecordObject(value)) return false;
	if (value.schema_version !== "1") return false;
	if (value.id !== expectedRunId || typeof value.id !== "string" || !ANALYSIS_ID_PATTERN.test(value.id)) return false;
	if (
		value.workflow_id !== expectedWorkflowId ||
		typeof value.workflow_id !== "string" ||
		!ANALYSIS_ID_PATTERN.test(value.workflow_id)
	) {
		return false;
	}
	if (typeof value.step_id !== "string" || value.step_id.trim().length === 0) return false;
	if (typeof value.target_sha256 !== "string" || !SHA256_HEX_PATTERN.test(value.target_sha256)) return false;
	if (typeof value.purpose !== "string" || typeof value.command !== "string") return false;
	if (value.status !== "running" && value.status !== "succeeded" && value.status !== "failed") return false;
	if (
		!isValidFileRefArray(value.inputs) ||
		!isValidFileRefArray(value.scripts) ||
		!isValidFileRefArray(value.outputs)
	) {
		return false;
	}
	if (!Array.isArray(value.evidence_ids) || !value.evidence_ids.every(id => typeof id === "string")) return false;
	if (typeof value.created_at !== "string" || value.created_at.trim().length === 0) return false;
	if (value.finished_at !== undefined && typeof value.finished_at !== "string") return false;
	if (value.exit_code !== undefined && (typeof value.exit_code !== "number" || !Number.isInteger(value.exit_code))) {
		return false;
	}
	if (value.summary !== undefined && typeof value.summary !== "string") return false;
	return true;
}

interface ManagedRunEntry {
	run: AnalysisRunRecord;
	runDir: string;
	relativeRunDir: string;
	runJsonPath: string;
}

interface ScanManagedRunsResult {
	entries: ManagedRunEntry[];
	corruptCount: number;
}

function parseIsoMs(iso: string | undefined): number {
	if (!iso) return 0;
	const ms = Date.parse(iso);
	return Number.isNaN(ms) ? 0 : ms;
}

function compareAnalysisRunsDescending(a: AnalysisRunRecord, b: AnalysisRunRecord): number {
	const primaryA = parseIsoMs(a.finished_at ?? a.created_at);
	const primaryB = parseIsoMs(b.finished_at ?? b.created_at);
	if (primaryB !== primaryA) return primaryB - primaryA;

	return b.id.localeCompare(a.id);
}

async function scanManagedAnalysisRuns(
	resolvedProjectDir: string,
	workspaceDir: string | undefined,
	options: { workflowId?: string } = {},
): Promise<ScanManagedRunsResult> {
	const workspace = await resolveSafeWorkspaceDir(resolvedProjectDir, workspaceDir);

	try {
		const wsStat = await fs.lstat(workspace.resolvedPath);
		if (wsStat.isSymbolicLink() || !wsStat.isDirectory()) {
			return { entries: [], corruptCount: 0 };
		}
	} catch (err) {
		if (isEnoent(err)) return { entries: [], corruptCount: 0 };
		throw err;
	}

	const analysisDir = path.join(workspace.resolvedPath, "analysis");
	try {
		await assertRealPathWithin(workspace.resolvedPath, analysisDir, { baseDir: resolvedProjectDir });
		const analysisStat = await fs.lstat(analysisDir);
		if (analysisStat.isSymbolicLink() || !analysisStat.isDirectory()) {
			return { entries: [], corruptCount: 0 };
		}
	} catch (err) {
		if (isEnoent(err)) return { entries: [], corruptCount: 0 };
		throw err;
	}

	let workflowIds: string[];
	if (options.workflowId !== undefined) {
		workflowIds = [validateAnalysisIdentifier("workflow_id", options.workflowId)];
	} else {
		const dirEntries = await fs.readdir(analysisDir, { withFileTypes: true });
		workflowIds = dirEntries
			.filter(entry => entry.isDirectory() && ANALYSIS_ID_PATTERN.test(entry.name))
			.map(entry => entry.name)
			.sort();
	}

	const entries: ManagedRunEntry[] = [];
	let corruptCount = 0;

	for (const wfId of workflowIds) {
		const wfDirPath = path.join(analysisDir, wfId);
		const runsDirPath = path.join(wfDirPath, "runs");
		try {
			await assertRealPathWithin(workspace.resolvedPath, runsDirPath, { baseDir: resolvedProjectDir });
			const wfStat = await fs.lstat(wfDirPath);
			if (wfStat.isSymbolicLink() || !wfStat.isDirectory()) continue;
			const runsStat = await fs.lstat(runsDirPath);
			if (runsStat.isSymbolicLink() || !runsStat.isDirectory()) continue;
		} catch (err) {
			if (isEnoent(err)) continue;
			throw err;
		}

		const runEntries = await fs.readdir(runsDirPath, { withFileTypes: true });
		for (const runEntry of runEntries) {
			if (!runEntry.isDirectory() || !ANALYSIS_ID_PATTERN.test(runEntry.name)) continue;
			const runId = runEntry.name;
			const candidateRunDir = path.join(runsDirPath, runId);
			const candidateRunJson = path.join(candidateRunDir, "run.json");

			let safeRunDir: SafeResolvedPath;
			let safeRunJson: SafeResolvedPath;
			try {
				const runDirStat = await fs.lstat(candidateRunDir);
				if (runDirStat.isSymbolicLink() || !runDirStat.isDirectory()) {
					corruptCount += 1;
					continue;
				}
				safeRunDir = await assertRealPathWithin(workspace.resolvedPath, candidateRunDir, {
					baseDir: resolvedProjectDir,
				});
				const runJsonStat = await fs.lstat(candidateRunJson);
				if (runJsonStat.isSymbolicLink() || !runJsonStat.isFile()) {
					corruptCount += 1;
					continue;
				}
				safeRunJson = await assertRealPathWithin(safeRunDir.resolvedPath, candidateRunJson, {
					baseDir: resolvedProjectDir,
					requireRegularFile: true,
				});
			} catch (err) {
				if (isEnoent(err)) continue;
				corruptCount += 1;
				continue;
			}

			let parsed: unknown;
			try {
				const raw = await fs.readFile(safeRunJson.resolvedPath, "utf8");
				parsed = JSON.parse(raw);
			} catch {
				corruptCount += 1;
				continue;
			}

			if (!isValidAnalysisRunRecord(parsed, wfId, runId)) {
				corruptCount += 1;
				continue;
			}

			entries.push({
				run: parsed,
				runDir: safeRunDir.resolvedPath,
				relativeRunDir: safeRunDir.relativePath,
				runJsonPath: safeRunJson.resolvedPath,
			});
		}
	}

	return { entries, corruptCount };
}

async function evaluateManagedRunReuse(
	resolvedProjectDir: string,
	entry: ManagedRunEntry,
): Promise<{
	reuse_status: AnalysisRunReuseStatus;
	reuse_reasons: string[];
	reusable_script_paths: string[];
}> {
	const { run, runDir } = entry;

	if (run.status === "failed") {
		const detail = run.summary ? `: ${run.summary}` : "";
		return {
			reuse_status: "incomplete",
			reuse_reasons: [`Experiment failed (exit_code=${run.exit_code ?? "unknown"})${detail}`],
			reusable_script_paths: [],
		};
	}

	if (run.status === "running") {
		const detail = run.summary ? `: ${run.summary}` : "";
		return {
			reuse_status: "incomplete",
			reuse_reasons: [`Experiment is incomplete (status='running')${detail}`],
			reusable_script_paths: [],
		};
	}

	if (run.outputs.length === 0) {
		return {
			reuse_status: "incomplete",
			reuse_reasons: ["Succeeded run has no recorded output_paths."],
			reusable_script_paths: [],
		};
	}

	const changedReasons: string[] = [];
	const missingReasons: string[] = [];
	const verifiedScriptAbsPaths: string[] = [];

	const inspectRefList = async (
		refs: AnalysisFileRef[],
		allowedRoot: string,
		label: "input" | "script" | "output",
	): Promise<void> => {
		for (const ref of refs) {
			let safeRef: SafeResolvedPath;
			try {
				safeRef = await assertRealPathWithin(allowedRoot, ref.path, {
					baseDir: resolvedProjectDir,
				});
			} catch (err) {
				changedReasons.push(
					`Unsafe ${label} path '${ref.path}': ${err instanceof Error ? err.message : String(err)}`,
				);
				continue;
			}

			let stat: Stats;
			try {
				stat = await fs.lstat(safeRef.resolvedPath);
			} catch (err) {
				if (isEnoent(err)) {
					missingReasons.push(`Missing ${label} file '${ref.path}'.`);
					continue;
				}
				missingReasons.push(
					`Unable to stat ${label} file '${ref.path}': ${err instanceof Error ? err.message : String(err)}`,
				);
				continue;
			}

			if (stat.isSymbolicLink() || !stat.isFile()) {
				changedReasons.push(`Invalid ${label} '${ref.path}': path is no longer a regular non-symlink file.`);
				continue;
			}

			const currentHash = await hashFile(safeRef.resolvedPath);
			if (!currentHash) {
				missingReasons.push(`Unable to read ${label} file '${ref.path}'.`);
				continue;
			}

			if (currentHash.sha256.toLowerCase() !== ref.sha256.toLowerCase() || currentHash.size !== ref.size_bytes) {
				changedReasons.push(
					`Changed ${label} file '${ref.path}' (recorded SHA-256 ${ref.sha256}, current ${currentHash.sha256}).`,
				);
				continue;
			}

			if (label === "script") {
				verifiedScriptAbsPaths.push(safeRef.resolvedPath);
			}
		}
	};

	await inspectRefList(run.inputs, resolvedProjectDir, "input");
	await inspectRefList(run.scripts, resolvedProjectDir, "script");
	await inspectRefList(run.outputs, runDir, "output");

	if (changedReasons.length > 0) {
		return {
			reuse_status: "changed",
			reuse_reasons: [...changedReasons, ...missingReasons],
			reusable_script_paths: [],
		};
	}

	if (missingReasons.length > 0) {
		return {
			reuse_status: "missing",
			reuse_reasons: missingReasons,
			reusable_script_paths: [],
		};
	}

	return {
		reuse_status: "available",
		reuse_reasons: ["All recorded inputs, scripts, and outputs match their SHA-256 hashes."],
		reusable_script_paths: Array.from(new Set(verifiedScriptAbsPaths)),
	};
}

/**
 * 检索受管 run.json 历史实验记录，重新校验输入/脚本/输出文件哈希并标记可复用状态（不自动删除或执行脚本）。
 */
export async function recallAnalysisRuns(
	projectDir: string,
	options: RecallAnalysisRunsOptions = {},
): Promise<AnalysisRunRecall[]> {
	const resolvedProjectDir = path.resolve(projectDir);
	const limit = options.limit ?? 5;
	if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > 20) {
		throw new ToolError(`Invalid recall limit '${options.limit}': must be an integer between 1 and 20.`);
	}

	const workflowFilter = options.workflowId?.trim()
		? validateAnalysisIdentifier("workflow_id", options.workflowId)
		: undefined;
	const targetHashFilter = options.targetHash?.trim() ? options.targetHash.trim().toLowerCase() : undefined;
	const queryFilter = options.query?.trim() ? options.query.trim().toLowerCase() : undefined;

	const { entries } = await scanManagedAnalysisRuns(resolvedProjectDir, options.workspaceDir, {
		workflowId: workflowFilter,
	});

	const filtered = entries.filter(({ run }) => {
		if (workflowFilter && run.workflow_id !== workflowFilter) {
			return false;
		}
		if (targetHashFilter && run.target_sha256.toLowerCase() !== targetHashFilter) {
			return false;
		}
		if (queryFilter) {
			const inPurpose = run.purpose.toLowerCase().includes(queryFilter);
			const inSummary = (run.summary ?? "").toLowerCase().includes(queryFilter);
			const inCommand = run.command.toLowerCase().includes(queryFilter);
			const inScripts = run.scripts.some(s => s.path.toLowerCase().includes(queryFilter));
			if (!inPurpose && !inSummary && !inCommand && !inScripts) {
				return false;
			}
		}
		return true;
	});

	filtered.sort((a, b) => compareAnalysisRunsDescending(a.run, b.run));
	const topEntries = filtered.slice(0, limit);

	const results: AnalysisRunRecall[] = [];
	for (const entry of topEntries) {
		const evaluation = await evaluateManagedRunReuse(resolvedProjectDir, entry);
		results.push({
			run: entry.run,
			run_dir: entry.runDir,
			relative_run_dir: entry.relativeRunDir,
			run_json: entry.runJsonPath,
			reuse_status: evaluation.reuse_status,
			reuse_reasons: evaluation.reuse_reasons,
			reusable_script_paths: evaluation.reusable_script_paths,
		});
	}
	return results;
}

function escapeXmlPlainText(raw: string): string {
	return raw
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function sanitizeBriefField(raw: string | undefined, maxChars: number): { text: string; truncated: boolean } {
	const redacted = redactSecrets(raw ?? "");
	const collapsed = redacted
		.replace(/[\r\n\t\x00-\x1f\x7f]+/g, " ")
		.replace(/\s+/g, " ")
		.trim();
	if (collapsed.length <= maxChars) {
		return { text: escapeXmlPlainText(collapsed), truncated: false };
	}
	const sliced = `${collapsed.slice(0, Math.max(1, maxChars - 3))}...`;
	return { text: escapeXmlPlainText(sliced), truncated: true };
}

function trimUtf8ToByteBudget(text: string, maxBytes: number): string {
	if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
	const suffix = "...";
	const suffixBytes = Buffer.byteLength(suffix, "utf8");
	if (maxBytes <= suffixBytes) return suffix.slice(0, Math.max(0, maxBytes));
	const targetBytes = maxBytes - suffixBytes;
	let acc = "";
	let used = 0;
	for (const ch of text) {
		const chBytes = Buffer.byteLength(ch, "utf8");
		if (used + chBytes > targetBytes) break;
		acc += ch;
		used += chBytes;
	}
	return `${acc}${suffix}`;
}

function enforceInvestigationBriefBounds(lines: string[], forceHint: boolean): string {
	const direct = lines.join("\n");
	if (
		!forceHint &&
		lines.length <= MAX_INVESTIGATION_BRIEF_LINES &&
		Buffer.byteLength(direct, "utf8") <= MAX_INVESTIGATION_BRIEF_BYTES
	) {
		return direct;
	}

	const maxContentLines = MAX_INVESTIGATION_BRIEF_LINES - 1;
	const hintBytes = Buffer.byteLength(BRIEF_TRUNCATION_HINT, "utf8");
	const maxContentBytes = MAX_INVESTIGATION_BRIEF_BYTES - hintBytes - 1;

	const kept: string[] = [];
	let usedBytes = 0;
	for (const line of lines) {
		if (kept.length >= maxContentLines) break;
		const sepBytes = kept.length > 0 ? 1 : 0;
		const lineBytes = Buffer.byteLength(line, "utf8");
		if (usedBytes + sepBytes + lineBytes <= maxContentBytes) {
			kept.push(line);
			usedBytes += sepBytes + lineBytes;
			continue;
		}
		const remaining = maxContentBytes - usedBytes - sepBytes;
		if (remaining >= 24) {
			kept.push(trimUtf8ToByteBudget(line, remaining));
		}
		break;
	}

	kept.push(BRIEF_TRUNCATION_HINT);
	return kept.join("\n");
}

function isValidWorkflowStepSummary(value: unknown): boolean {
	if (!isRecordObject(value)) return false;
	if (typeof value.id !== "string" || value.id.trim().length === 0) return false;
	if (typeof value.status !== "string" || value.status.trim().length === 0) return false;
	if (value.title !== undefined && typeof value.title !== "string") return false;
	return true;
}

function isValidWorkflowSummaryRecord(value: unknown): value is ReverseWorkflowRecord {
	if (!isRecordObject(value)) return false;
	if (typeof value.id !== "string" || value.id.trim().length === 0) return false;
	if (typeof value.target !== "string" || value.target.trim().length === 0) return false;
	if (typeof value.status !== "string" || value.status.trim().length === 0) return false;
	if (value.target_sha256 !== undefined && typeof value.target_sha256 !== "string") return false;
	if (value.created_at !== undefined && typeof value.created_at !== "string") return false;
	if (value.updated_at !== undefined && typeof value.updated_at !== "string") return false;
	if (!Array.isArray(value.steps) || !value.steps.every(isValidWorkflowStepSummary)) return false;
	return true;
}

async function inspectWorkflowStoreFilesReadOnly(
	workflowProjectDir: string,
): Promise<{ validRecords: ReverseWorkflowRecord[]; corruptCount: number }> {
	let dirEntries: Dirent[];
	try {
		const st = await fs.lstat(workflowProjectDir);
		if (st.isSymbolicLink() || !st.isDirectory()) return { validRecords: [], corruptCount: 0 };
		dirEntries = await fs.readdir(workflowProjectDir, { withFileTypes: true });
	} catch (err) {
		if (isEnoent(err)) return { validRecords: [], corruptCount: 0 };
		throw err;
	}

	const validRecords: ReverseWorkflowRecord[] = [];
	let corruptCount = 0;
	for (const entry of dirEntries) {
		if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
		const filePath = path.join(workflowProjectDir, entry.name);
		try {
			const raw = await fs.readFile(filePath, "utf8");
			const parsed = JSON.parse(raw) as unknown;
			if (isValidWorkflowSummaryRecord(parsed)) {
				validRecords.push(parsed);
			} else {
				corruptCount += 1;
			}
		} catch {
			corruptCount += 1;
		}
	}
	validRecords.sort((a, b) => parseIsoMs(b.updated_at) - parseIsoMs(a.updated_at));
	return { validRecords, corruptCount };
}

/**
 * 构建新会话/上下文刷新的轻量历史调查索引（不创建任何目录、不计算大文件哈希、转义不可信文本并限制 30 行 / 4096 UTF-8 字节）。
 */
export async function loadInvestigationBrief(
	projectDir: string,
	options: LoadInvestigationBriefOptions = {},
): Promise<string | undefined> {
	let resolvedProjectDir: string;
	try {
		resolvedProjectDir = path.resolve(projectDir);
		const stat = await fs.stat(resolvedProjectDir);
		if (!stat.isDirectory()) return undefined;
	} catch (err) {
		if (!isEnoent(err)) {
			logger.warn("Diagnostic: unable to inspect project directory for investigation brief", {
				projectDir,
				error: err instanceof Error ? err.message : String(err),
			});
		}
		return undefined;
	}

	const workflowStore = new ReverseWorkflowStore({
		repositoryRoot: resolvedProjectDir,
		stateRoot: options.stateRoot,
	});

	let workflows: ReverseWorkflowRecord[] = [];
	let corruptWorkflowCount = 0;
	try {
		const inspected = await inspectWorkflowStoreFilesReadOnly(workflowStore.projectDirectory);
		corruptWorkflowCount = inspected.corruptCount;
		try {
			workflows = (await workflowStore.list({ readOnly: true })).filter(isValidWorkflowSummaryRecord);
		} catch {
			workflows = inspected.validRecords;
		}
	} catch (err) {
		logger.warn("Diagnostic: failed to read workflow store for investigation brief", {
			projectDir: resolvedProjectDir,
			permissionError: isPermissionFsError(err),
			error: err instanceof Error ? err.message : String(err),
		});
	}

	let runEntries: ManagedRunEntry[] = [];
	let corruptRunCount = 0;
	try {
		const scanned = await scanManagedAnalysisRuns(resolvedProjectDir, options.workspaceDir);
		runEntries = scanned.entries;
		corruptRunCount = scanned.corruptCount;
	} catch (err) {
		logger.warn("Diagnostic: failed to scan analysis runs for investigation brief", {
			projectDir: resolvedProjectDir,
			permissionError: isPermissionFsError(err),
			error: err instanceof Error ? err.message : String(err),
		});
	}

	const totalCorruptCount = corruptWorkflowCount + corruptRunCount;
	if (workflows.length === 0 && runEntries.length === 0 && totalCorruptCount === 0) {
		return undefined;
	}

	const runsByWorkflow = new Map<string, ManagedRunEntry[]>();
	for (const entry of runEntries) {
		const list = runsByWorkflow.get(entry.run.workflow_id) ?? [];
		list.push(entry);
		runsByWorkflow.set(entry.run.workflow_id, list);
	}
	for (const list of runsByWorkflow.values()) {
		list.sort((a, b) => compareAnalysisRunsDescending(a.run, b.run));
	}

	const lines: string[] = [
		'Index status: unverified startup index (hashes not re-checked; call reverse_workspace action="recall" before reuse).',
	];
	let truncated = false;

	if (totalCorruptCount > 0) {
		lines.push(
			`Notice: skipped ${totalCorruptCount} corrupted analysis/workflow JSON record(s); use reverse_workspace(action: "recall") to inspect valid history.`,
		);
	}

	const formatTargetLabel = (rawTarget: string): string => {
		let display = rawTarget;
		if (path.isAbsolute(rawTarget)) {
			const rel = path.relative(resolvedProjectDir, rawTarget);
			if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) {
				display = rel.split(path.sep).join("/");
			}
		}
		const s = sanitizeBriefField(display, 96);
		if (s.truncated) truncated = true;
		return s.text;
	};

	const appendRunLine = (entry: ManagedRunEntry): void => {
		const r = entry.run;
		const idField = sanitizeBriefField(r.id, 48);
		const statusField = sanitizeBriefField(r.status, 16);
		const stepField = sanitizeBriefField(r.step_id, 32);
		const purposeField = sanitizeBriefField(r.purpose, 100);
		const summaryRaw = r.summary ?? (r.status === "running" ? "running (not finalized)" : "no summary recorded");
		const summaryField = sanitizeBriefField(summaryRaw, 140);
		if (
			idField.truncated ||
			statusField.truncated ||
			stepField.truncated ||
			purposeField.truncated ||
			summaryField.truncated
		) {
			truncated = true;
		}

		const scriptItems = r.scripts.slice(0, 3).map(s => {
			const sf = sanitizeBriefField(s.path, 512);
			if (sf.truncated) truncated = true;
			return sf.text;
		});
		if (r.scripts.length > 3) {
			truncated = true;
			scriptItems.push("...");
		}
		const scriptsText = scriptItems.length > 0 ? scriptItems.join(", ") : "none";
		const exitText = r.exit_code !== undefined ? `, exit_code=${r.exit_code}` : "";
		lines.push(
			`  Run ${idField.text} [${statusField.text}${exitText}, step=${stepField.text}]: purpose="${purposeField.text}" summary="${summaryField.text}" scripts=[${scriptsText}]`,
		);
	};

	if (workflows.length > 3) {
		truncated = true;
	}
	const latestWorkflows = workflows.slice(0, 3);

	if (latestWorkflows.length > 0) {
		for (const wf of latestWorkflows) {
			const wfId = sanitizeBriefField(wf.id, 64);
			const wfStatus = sanitizeBriefField(wf.status, 24);
			const hashField = wf.target_sha256
				? sanitizeBriefField(wf.target_sha256, 80)
				: { text: "unknown", truncated: false };
			if (wfId.truncated || wfStatus.truncated || hashField.truncated) truncated = true;

			const steps = Array.isArray(wf.steps) ? wf.steps : [];
			const completedCount = steps.filter(s => s.status === "completed").length;
			const stepBadges = steps.slice(0, 4).map(s => {
				const sid = sanitizeBriefField(s.id, 28);
				const sst = sanitizeBriefField(s.status, 16);
				if (sid.truncated || sst.truncated) truncated = true;
				return `${sid.text}:${sst.text}`;
			});
			if (steps.length > 4) {
				stepBadges.push("...");
			}
			const nextIncomplete = steps.find(s => s.status !== "completed" && s.status !== "skipped");
			let nextStepText = "none";
			if (nextIncomplete) {
				const nid = sanitizeBriefField(nextIncomplete.id, 36);
				const ntitle = sanitizeBriefField(nextIncomplete.title || nextIncomplete.status, 56);
				const nst = sanitizeBriefField(nextIncomplete.status, 16);
				if (nid.truncated || ntitle.truncated || nst.truncated) truncated = true;
				nextStepText = `${nid.text} (${ntitle.text}) [${nst.text}]`;
			}

			lines.push(
				`- Workflow ${wfId.text}: target=${formatTargetLabel(wf.target)} sha256=${hashField.text} status=${wfStatus.text} steps=${completedCount}/${steps.length} (${stepBadges.join(", ") || "none"}) next_step=${nextStepText}`,
			);

			const wfRuns = runsByWorkflow.get(wf.id) ?? [];
			if (wfRuns.length > 2) {
				truncated = true;
			}
			const latestRuns = wfRuns.slice(0, 2);
			if (latestRuns.length === 0) {
				lines.push("  Runs: none recorded");
			} else {
				for (const runEntry of latestRuns) {
					appendRunLine(runEntry);
				}
			}
		}
	} else if (runsByWorkflow.size > 0) {
		const grouped = Array.from(runsByWorkflow.entries()).sort(([, runsA], [, runsB]) =>
			compareAnalysisRunsDescending(runsA[0].run, runsB[0].run),
		);
		if (grouped.length > 3) {
			truncated = true;
		}
		for (const [wfIdRaw, wfRuns] of grouped.slice(0, 3)) {
			const wfId = sanitizeBriefField(wfIdRaw, 64);
			const hashField = sanitizeBriefField(wfRuns[0].run.target_sha256, 80);
			if (wfId.truncated || hashField.truncated) truncated = true;
			lines.push(`- Workflow ${wfId.text}: sha256=${hashField.text}`);
			if (wfRuns.length > 2) {
				truncated = true;
			}
			for (const runEntry of wfRuns.slice(0, 2)) {
				appendRunLine(runEntry);
			}
		}
	}

	return enforceInvestigationBriefBounds(lines, truncated);
}
