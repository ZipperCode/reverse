import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getReverseWorkflowProjectDir, isEnoent } from "@reverse/utils";
import { withFileLock } from "@reverse/utils/file-lock";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { replaceFileAtomically } from "../utils/atomic-file";
import {
	type ReverseWorkflowRecord,
	type TargetFormat,
	type WorkflowStepRecord,
	type BuildArtifactRecord,
	type BuildSignatureStatus,
	type BuildVerificationResult,
	type PatchRetirementAuditEntry,
	type PatchStatus,
	type TargetDeviceConstraints,
	type WorkflowDependencyRecord,
	type AcceptanceCriterion,
	type AcceptanceCriterionInput,
	encodeWorkflowProjectKey,
	createWorkflowId,
	createBuildId,
	normalizeTargetFormat,
} from "./contracts";
import {
	validateDeploymentConstraints,
	normalizeAcceptanceCriterion,
	setWorkflowAcceptanceCriteria,
	normalizeTargetDeviceConstraints,
	normalizeWorkflowDependencies,
	getWorkflowAcceptanceCriteria,
	updateAcceptanceCriterion,
} from "./acceptance";
import { evaluateEvidenceSupport } from "../evidence/validity";
import { EvidenceStore } from "../evidence/store";
import {
	hashFileSha256,
	resolveSignatureInfo,
	verifyActivePatches,
	verifySourceOriginalBytes,
	accumulatePatches,
} from "./lineage";
import {
	isPackageSetManifest,
	parseAndValidatePackageSetManifest,
	resolvePackageSetInput,
	type ValidatedPackageSetManifest,
} from "./package-set";
import { generateDeterministicPlan } from "./planner";

const PRIVATE_DIR_MODE = 0o700;

/** In-process write serializer per project directory */
const WORKFLOW_STORE_WRITE_CHAINS = new Map<string, Promise<unknown>>();

async function withWorkflowStoreWrite<T>(
	projectDirectory: string,
	lockTarget: string,
	operation: () => Promise<T>,
): Promise<T> {
	await fs.mkdir(projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
	if (process.platform !== "win32") {
		await fs.chmod(projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
	}
	const run = (WORKFLOW_STORE_WRITE_CHAINS.get(projectDirectory) ?? Promise.resolve()).then(() =>
		withFileLock(lockTarget, operation, { retries: 200, retryDelayMs: 50 }),
	);
	const guarded = run.catch(() => undefined);
	WORKFLOW_STORE_WRITE_CHAINS.set(projectDirectory, guarded);
	try {
		return await run;
	} finally {
		if (WORKFLOW_STORE_WRITE_CHAINS.get(projectDirectory) === guarded) {
			WORKFLOW_STORE_WRITE_CHAINS.delete(projectDirectory);
		}
	}
}

export interface ReverseWorkflowStoreOptions {
	repositoryRoot: string;
	stateRoot?: string;
}

export interface CreateWorkflowOptions {
	id?: string;
	target: string;
	format?: TargetFormat | string;
	goal?: string;
	steps?: WorkflowStepRecord[];
	knowledge_refs?: string[];
	runtime_session_ids?: string[];
	metadata?: Record<string, unknown>;
	max_attempts?: number;
	target_device_constraints?: TargetDeviceConstraints;
	dependencies?: WorkflowDependencyRecord[];
	acceptance_criteria?: AcceptanceCriterionInput[] | AcceptanceCriterion[];
}

export interface RegisterDerivativeOptions {
	build_id?: string;
	target_path: string;
	output_sha256?: string;
	original_sha256?: string;
	parent_sha256?: string;
	parent_build_id?: string;
	target_version?: string;
	abi?: string;
	architecture?: string;
	patches?: Array<{
		patch_id: string;
		package_member?: string;
		member_path?: string;
		offset: number;
		original_bytes: string;
		expected_bytes: string;
		status?: PatchStatus;
		retirement_reason?: string;
		evidence_id?: string;
	}>;
	retired_patches?: Array<{
		patch_id: string;
		reason: string;
	}>;
	signature?: {
		status?: BuildSignatureStatus;
		scheme?: string;
		fingerprint?: string;
	};
	verification_conditions?: Record<string, unknown> | string[];
	target_device_constraints?: TargetDeviceConstraints;
	scope?: "experiment" | "delivery";
	delivery_mode?: string;
	dependencies?: WorkflowDependencyRecord[];
	evidence_ids?: string[];
	runtime_evidence_ids?: string[];
	metadata?: Record<string, unknown>;
}

export class ReverseWorkflowStore {
	readonly repositoryRoot: string;
	readonly projectKey: string;
	readonly projectDirectory: string;
	readonly lockPath: string;

	constructor(options: ReverseWorkflowStoreOptions) {
		this.repositoryRoot = path.resolve(options.repositoryRoot);
		this.projectKey = encodeWorkflowProjectKey(this.repositoryRoot);
		this.projectDirectory = options.stateRoot
			? path.join(path.resolve(options.stateRoot), this.projectKey)
			: getReverseWorkflowProjectDir(this.projectKey);
		this.lockPath = path.join(this.projectDirectory, "store.lock");
	}

	static forSession(cwd: string, stateRoot?: string): ReverseWorkflowStore {
		return new ReverseWorkflowStore({ repositoryRoot: cwd, stateRoot });
	}

	static async create(options: ReverseWorkflowStoreOptions & CreateWorkflowOptions): Promise<ReverseWorkflowRecord> {
		const store = new ReverseWorkflowStore(options);
		return store.create(options);
	}

	async create(input: CreateWorkflowOptions): Promise<ReverseWorkflowRecord> {
		const workflowId = input.id ?? createWorkflowId();
		const format = normalizeTargetFormat(input.format) ?? "unknown";
		const steps =
			input.steps && input.steps.length > 0
				? input.steps
				: generateDeterministicPlan(input.target, format, {
						goal: input.goal,
						maxAttempts: input.max_attempts,
						formatOverride: input.format,
					}).steps;

		const now = new Date().toISOString();
		const metadata: Record<string, unknown> = {
			...input.metadata,
		};

		const constraints = normalizeTargetDeviceConstraints(input.target_device_constraints);
		if (constraints) {
			metadata.target_device_constraints = constraints;
		}

		const dependencies = normalizeWorkflowDependencies(input.dependencies, { isInitialCreation: true });
		if (dependencies) {
			metadata.dependencies = dependencies;
		}
		const targetAbs = path.isAbsolute(input.target) ? input.target : path.resolve(this.repositoryRoot, input.target);
		let targetSha256: string | undefined;
		try {
			targetSha256 = await hashFileSha256(targetAbs);
		} catch {
			// speculative or not yet on disk
		}

		const record: ReverseWorkflowRecord = {
			id: workflowId,
			target: input.target,
			target_abs_path: targetAbs,
			target_sha256: targetSha256,
			base_target_sha256: targetSha256,
			format,
			goal: input.goal,
			status: "active",
			steps,
			created_at: now,
			updated_at: now,
			...(input.knowledge_refs ? { knowledge_refs: input.knowledge_refs } : {}),
			...(input.runtime_session_ids ? { runtime_session_ids: input.runtime_session_ids } : {}),
			...(Object.keys(metadata).length > 0 ? { metadata } : {}),
		};

		const g4Step = steps.find(s => s.gate === "G4") ?? steps[steps.length - 1];
		if (g4Step) {
			g4Step.is_delivery_step = true;
		}

		if (input.acceptance_criteria && Array.isArray(input.acceptance_criteria)) {
			const normalizedCriteria = input.acceptance_criteria.map(c =>
				normalizeAcceptanceCriterion(c, undefined, { isInitialCreation: true }),
			);
			setWorkflowAcceptanceCriteria(record, normalizedCriteria);
		} else if (g4Step) {
			const rawSubject =
				input.goal && input.goal.trim()
					? input.goal
							.trim()
							.toLowerCase()
							.replace(/[^a-z0-9_-]+/g, "_")
							.slice(0, 64)
					: `${path
							.basename(input.target)
							.toLowerCase()
							.replace(/[^a-z0-9_-]+/g, "_")}_verification`;
			const goalSubject = rawSubject.replace(/^_+|_+$/g, "") || "target_verification";

			const defaultCriterion: AcceptanceCriterion = {
				id: `ac_${g4Step.id}_delivery`,
				step_id: g4Step.id,
				title: input.goal
					? `Verify: ${input.goal.slice(0, 100)}`
					: `Delivery Verification: ${path.basename(input.target)}`,
				subject: goalSubject,
				min_assurance: "dynamic_call_observation",
				status: "pending",
			};
			setWorkflowAcceptanceCriteria(record, [defaultCriterion]);
		}

		return await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			const existing = await this.get(workflowId);
			if (existing) {
				throw new ToolError(
					`Workflow with ID '${workflowId}' already exists. Overwriting existing workflows is prohibited to preserve criteria and audit history.`,
				);
			}
			await this.writeWorkflowFileUnlocked(record);
			return record;
		});
	}

	async ensureDir(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: PRIVATE_DIR_MODE });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, PRIVATE_DIR_MODE).catch(() => undefined);
		}
	}

	private workflowFilePath(id: string): string {
		const safeId = id.replace(/[^a-zA-Z0-9._-]/g, "_");
		return path.join(this.projectDirectory, `${safeId}.json`);
	}

	private async writeWorkflowFileUnlocked(record: ReverseWorkflowRecord): Promise<void> {
		await this.ensureDir();
		const targetPath = this.workflowFilePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7().slice(0, 8)}.tmp`;
		const payload = JSON.stringify(record, null, 2);
		await fs.writeFile(tempPath, payload, "utf8");
		await replaceFileAtomically(tempPath, targetPath);
	}

	async save(record: ReverseWorkflowRecord): Promise<void> {
		await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			const existing = await this.get(record.id);
			if (existing) {
				const existingCriteria = getWorkflowAcceptanceCriteria(existing);
				if (existingCriteria.length > 0) {
					const currentCriteria = getWorkflowAcceptanceCriteria(record);
					const currentMap = new Map(currentCriteria.map(c => [c.id, c]));
					for (const ec of existingCriteria) {
						if (!currentMap.has(ec.id)) {
							updateAcceptanceCriterion(record, ec);
						}
					}
				}
			}
			await this.writeWorkflowFileUnlocked(record);
		});
	}

	async get(id: string): Promise<ReverseWorkflowRecord | null> {
		const filePath = this.workflowFilePath(id);
		try {
			const text = await fs.readFile(filePath, "utf8");
			return JSON.parse(text) as ReverseWorkflowRecord;
		} catch (err) {
			if (isEnoent(err)) return null;
			throw new ToolError(
				`Failed to read workflow record '${id}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}

	async list(options: { readOnly?: boolean } = {}): Promise<ReverseWorkflowRecord[]> {
		if (!options.readOnly) {
			await this.ensureDir();
		} else {
			try {
				await fs.stat(this.projectDirectory);
			} catch (err) {
				if (isEnoent(err)) return [];
				throw err;
			}
		}
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: ReverseWorkflowRecord[] = [];

			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				const filePath = path.join(this.projectDirectory, entry.name);
				try {
					const text = await fs.readFile(filePath, "utf8");
					records.push(JSON.parse(text) as ReverseWorkflowRecord);
				} catch {
					// Skip corrupted or unparseable JSON files
				}
			}

			records.sort((a, b) => {
				const timeA = a.updated_at ? new Date(a.updated_at).getTime() : 0;
				const timeB = b.updated_at ? new Date(b.updated_at).getTime() : 0;
				return timeB - timeA;
			});

			return records;
		} catch (err) {
			if (isEnoent(err)) return [];
			throw new ToolError(`Failed to list workflows: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	async delete(id: string): Promise<boolean> {
		const filePath = this.workflowFilePath(id);
		return await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			try {
				await fs.unlink(filePath);
				return true;
			} catch (err) {
				if (isEnoent(err)) return false;
				throw new ToolError(
					`Failed to delete workflow '${id}': ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		});
	}

	async registerDerivative(workflowId: string, input: RegisterDerivativeOptions): Promise<BuildArtifactRecord> {
		const resolvedPath = path.isAbsolute(input.target_path)
			? input.target_path
			: path.resolve(this.repositoryRoot, input.target_path);

		try {
			await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Derivative target file '${input.target_path}' does not exist on disk: ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		const actualSha256 = await hashFileSha256(resolvedPath);
		if (input.output_sha256 && input.output_sha256.trim().toLowerCase() !== actualSha256.toLowerCase()) {
			throw new ToolError(
				`Derivative target '${input.target_path}' output SHA-256 mismatch (tampered/drifted): expected '${input.output_sha256}', actual '${actualSha256}'`,
			);
		}

		const isPkgSet = await isPackageSetManifest(resolvedPath);
		let pkgManifestInfo: ValidatedPackageSetManifest | undefined;
		if (isPkgSet) {
			pkgManifestInfo = await parseAndValidatePackageSetManifest(resolvedPath);
		}
		return await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			const workflow = await this.get(workflowId);
			if (!workflow) {
				throw new ToolError(`Workflow '${workflowId}' not found.`);
			}
			// Validate deployment constraints and dependencies
			const constraints: TargetDeviceConstraints | undefined = normalizeTargetDeviceConstraints(
				input.target_device_constraints ??
					(input.metadata?.target_device_constraints as TargetDeviceConstraints | undefined) ??
					(workflow.metadata?.target_device_constraints as TargetDeviceConstraints | undefined),
			);

			const dependencies: WorkflowDependencyRecord[] | undefined = normalizeWorkflowDependencies(
				input.dependencies ??
					(input.metadata?.dependencies as WorkflowDependencyRecord[] | undefined) ??
					(workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined),
			);

			const targetScope: "experiment" | "delivery" =
				input.scope ??
				(input.metadata?.scope as "experiment" | "delivery" | undefined) ??
				(constraints?.requires_standalone ? "delivery" : "experiment");

			const constraintCheck = validateDeploymentConstraints(constraints, dependencies, targetScope);
			if (!constraintCheck.valid) {
				throw new ToolError(
					`Cannot register derivative '${resolvedPath}': ${constraintCheck.violationCode}: ${constraintCheck.violation}`,
				);
			}

			const baseTargetPath = workflow.target_abs_path ?? path.resolve(this.repositoryRoot, workflow.target);
			let originalSha256: string;
			try {
				originalSha256 = await hashFileSha256(baseTargetPath);
			} catch (err) {
				const recorded = workflow.base_target_sha256 ?? workflow.target_sha256;
				if (recorded) {
					originalSha256 = recorded;
				} else {
					throw new ToolError(
						`Cannot determine original base target SHA-256 for workflow '${workflowId}': base file '${workflow.target}' cannot be read: ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}

			const recordedBase = workflow.base_target_sha256 ?? workflow.target_sha256;
			if (recordedBase && recordedBase.toLowerCase() !== originalSha256.toLowerCase()) {
				throw new ToolError(
					`Original base target '${workflow.target}' hash has drifted from registered hash '${recordedBase}' to '${originalSha256}'.`,
				);
			}
			if (input.original_sha256 && input.original_sha256.trim().toLowerCase() !== originalSha256.toLowerCase()) {
				throw new ToolError(
					`original_sha256 '${input.original_sha256}' does not match workflow base target SHA-256 '${originalSha256}'`,
				);
			}
			let capturedOriginalSetSha: string | undefined;
			let capturedOriginalMembers: unknown[] | undefined;
			let validatedRawSourceSet: { base: string; splits?: Record<string, string> } | undefined;

			// Validate original base package set integrity at root level independently of parent derivation
			const wfPkgSet = workflow.metadata?.package_set as
				| { base?: string; splits?: Record<string, string>; set_sha256?: string; members?: unknown[] }
				| undefined;
			const inputSourceSet = input.metadata?.source_package_set as
				| { base?: string; splits?: Record<string, string> }
				| undefined;
			const candidateRawSet =
				inputSourceSet && typeof inputSourceSet.base === "string"
					? inputSourceSet
					: wfPkgSet && typeof wfPkgSet.base === "string"
						? wfPkgSet
						: undefined;

			if (await isPackageSetManifest(baseTargetPath)) {
				try {
					const val = await parseAndValidatePackageSetManifest(baseTargetPath);
					if (
						wfPkgSet?.set_sha256 &&
						wfPkgSet.set_sha256.toLowerCase() !== val.manifest.set_sha256.toLowerCase()
					) {
						throw new ToolError(
							`Stale original base package set: aggregate SHA-256 drifted from registered '${wfPkgSet.set_sha256}' to '${val.manifest.set_sha256}'.`,
						);
					}
					capturedOriginalSetSha = val.manifest.set_sha256;
					capturedOriginalMembers = val.manifest.members;
				} catch (err) {
					if (err instanceof ToolError) throw err;
					throw new ToolError(
						`Stale original base package set: manifest '${workflow.target}' member verification failed: ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			} else if (candidateRawSet && typeof candidateRawSet.base === "string") {
				const normRawBase = path.isAbsolute(candidateRawSet.base)
					? candidateRawSet.base
					: path.resolve(this.repositoryRoot, candidateRawSet.base);
				const realRawBase = await fs.realpath(normRawBase).catch(() => null);
				const realCandidateBase = await fs.realpath(baseTargetPath).catch(() => null);
				if (realRawBase && realCandidateBase && realRawBase === realCandidateBase) {
					const rawBaseHash = await hashFileSha256(realRawBase);
					if (rawBaseHash.toLowerCase() === originalSha256.toLowerCase()) {
						const rawInput = {
							base: normRawBase,
							splits: candidateRawSet.splits
								? Object.fromEntries(
										Object.entries(candidateRawSet.splits).map(([k, v]) => [
											k,
											path.isAbsolute(v) ? v : path.resolve(this.repositoryRoot, v),
										]),
									)
								: undefined,
						};
						const valRaw = await resolvePackageSetInput(this.repositoryRoot, rawInput);
						if (wfPkgSet?.set_sha256 && wfPkgSet.set_sha256.toLowerCase() !== valRaw.setSha256.toLowerCase()) {
							throw new ToolError(
								`Stale original base package set: aggregate SHA-256 drifted from registered '${wfPkgSet.set_sha256}' to '${valRaw.setSha256}'. Member APKs have been modified.`,
							);
						}
						capturedOriginalSetSha = valRaw.setSha256;
						capturedOriginalMembers = valRaw.members;
						validatedRawSourceSet = rawInput;
					}
				}
			}
			let parentBuild: BuildArtifactRecord | undefined;
			let parentSha256: string;

			if (input.parent_build_id) {
				parentBuild = workflow.build_lineage?.find(b => b.build_id === input.parent_build_id);
				if (!parentBuild) {
					throw new ToolError(
						`Parent build '${input.parent_build_id}' not found in workflow '${workflowId}' build lineage.`,
					);
				}
				if (
					input.parent_sha256 &&
					input.parent_sha256.trim().toLowerCase() !== parentBuild.output_sha256.toLowerCase()
				) {
					throw new ToolError(
						`parent_sha256 '${input.parent_sha256}' does not match parent build '${parentBuild.build_id}' output SHA-256 '${parentBuild.output_sha256}'`,
					);
				}
				parentSha256 = parentBuild.output_sha256;
			} else if (input.parent_sha256) {
				const cleanParent = input.parent_sha256.trim().toLowerCase();
				const matched = workflow.build_lineage?.find(b => {
					if (b.output_sha256.toLowerCase() === cleanParent) return true;
					const bSetSha = (b.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256;
					return typeof bSetSha === "string" && bSetSha.toLowerCase() === cleanParent;
				});
				if (matched) {
					parentBuild = matched;
					parentSha256 = matched.output_sha256;
				} else if (cleanParent === originalSha256.toLowerCase()) {
					parentSha256 = originalSha256;
				} else {
					const wfSetSha = (workflow.metadata?.package_set as Record<string, unknown> | undefined)?.set_sha256;
					if (typeof wfSetSha === "string" && wfSetSha.toLowerCase() === cleanParent) {
						parentSha256 = originalSha256;
					} else {
						throw new ToolError(
							`parent_sha256 '${input.parent_sha256}' is neither the base SHA-256 nor a recognized prior derivative output SHA-256.`,
						);
					}
				}
			} else if (workflow.current_baseline_build_id) {
				parentBuild = workflow.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id);
				parentSha256 = parentBuild ? parentBuild.output_sha256 : originalSha256;
			} else {
				parentSha256 = originalSha256;
			}

			if (parentBuild) {
				const parentPath = path.isAbsolute(parentBuild.target_path)
					? parentBuild.target_path
					: path.resolve(this.repositoryRoot, parentBuild.target_path);
				try {
					const diskParentHash = await hashFileSha256(parentPath);
					if (diskParentHash.toLowerCase() !== parentBuild.output_sha256.toLowerCase()) {
						throw new ToolError(
							`Stale parent source: file '${parentBuild.target_path}' on disk hash (${diskParentHash}) has drifted from registered hash (${parentBuild.output_sha256}).`,
						);
					}
				} catch (err) {
					if (!isEnoent(err)) {
						if (err instanceof ToolError) throw err;
						throw new ToolError(
							`Failed to verify parent source '${parentBuild.target_path}': ${err instanceof Error ? err.message : String(err)}`,
						);
					}
				}
				if (await isPackageSetManifest(parentPath)) {
					try {
						const parentPkgVal = await parseAndValidatePackageSetManifest(parentPath);
						const inputSourceSet = input.metadata?.source_package_set as
							| { base?: string; splits?: Record<string, string> }
							| undefined;
						if (inputSourceSet && typeof inputSourceSet.base === "string") {
							const normInputBase = path.isAbsolute(inputSourceSet.base)
								? inputSourceSet.base
								: path.resolve(this.repositoryRoot, inputSourceSet.base);
							const [realInputBase, realParentBase] = await Promise.all([
								fs.realpath(normInputBase).catch(() => null),
								fs.realpath(parentPkgVal.memberPaths.get("base")!).catch(() => null),
							]);
							if (!realInputBase || !realParentBase || realInputBase !== realParentBase) {
								throw new ToolError(
									`Declared source_package_set base '${inputSourceSet.base}' does not match parent build base '${parentPkgVal.manifest.members.find(m => m.name === "base")?.filename}'.`,
								);
							}
						}
					} catch (err) {
						if (err instanceof ToolError) throw err;
						throw new ToolError(
							`Stale parent package set: manifest '${parentBuild.target_path}' member verification failed: ${err instanceof Error ? err.message : String(err)}`,
						);
					}
				}
			} else if (parentSha256 === originalSha256) {
				try {
					const diskBaseHash = await hashFileSha256(baseTargetPath);
					if (diskBaseHash.toLowerCase() !== originalSha256.toLowerCase()) {
						throw new ToolError(
							`Stale original base source: file '${workflow.target}' on disk hash (${diskBaseHash}) has drifted from registered hash (${originalSha256}).`,
						);
					}
				} catch (err) {
					if (isEnoent(err)) {
						throw new ToolError(
							`Original base source file '${workflow.target}' does not exist on disk. Cannot replay or derive directly from missing original base.`,
						);
					}
					if (err instanceof ToolError) throw err;
					throw new ToolError(
						`Failed to verify original base source '${workflow.target}': ${err instanceof Error ? err.message : String(err)}`,
					);
				}
			}

			let baselineBuild: BuildArtifactRecord | undefined;
			if (workflow.current_baseline_build_id) {
				baselineBuild = workflow.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id);
				if (!baselineBuild) {
					throw new ToolError(
						`Corrupt baseline reference: current_baseline_build_id '${workflow.current_baseline_build_id}' was not found in workflow '${workflowId}' build lineage.`,
					);
				}
			}
			const baseCumulativePatches = baselineBuild?.cumulative_patches ?? parentBuild?.cumulative_patches;

			const allRetirements: Array<{ patch_id: string; reason: string }> = [
				...(workflow.retired_patches_audit?.map(a => ({ patch_id: a.patch_id, reason: a.reason })) ?? []),
				...(input.retired_patches ?? []),
			];

			const buildId = input.build_id ?? createBuildId("bld");
			if (workflow.build_lineage?.some(b => b.build_id === buildId)) {
				throw new ToolError(
					`Derivative with build_id '${buildId}' already exists in workflow '${workflowId}' build lineage. Duplicate build IDs are rejected to prevent ambiguous baselines.`,
				);
			}
			const cumulativePatches = accumulatePatches(baseCumulativePatches, input.patches, allRetirements, buildId);

			if (input.patches && input.patches.length > 0) {
				let candidateSourcePath = parentBuild
					? path.isAbsolute(parentBuild.target_path)
						? parentBuild.target_path
						: path.resolve(this.repositoryRoot, parentBuild.target_path)
					: baseTargetPath;

				const hasSplitPatch = input.patches.some(p => p.package_member && p.package_member !== "base");
				const isSplitSetMode = isPkgSet || hasSplitPatch;

				// Only switch to adjacent package-set.json if in split set mode,
				// AND the adjacent manifest's "base" member strictly maps to candidateSourcePath
				if (isSplitSetMode && !(await isPackageSetManifest(candidateSourcePath))) {
					const adjacentManifest = path.join(path.dirname(candidateSourcePath), "package-set.json");
					if (await isPackageSetManifest(adjacentManifest)) {
						try {
							const adjValidation = await parseAndValidatePackageSetManifest(adjacentManifest);
							const adjBaseFile = adjValidation.memberPaths.get("base");
							if (adjBaseFile) {
								const [realAdjBase, realTarget] = await Promise.all([
									fs.realpath(adjBaseFile),
									fs.realpath(candidateSourcePath),
								]);
								if (realAdjBase === realTarget) {
									candidateSourcePath = adjacentManifest;
								}
							}
						} catch {
							// adjacent manifest invalid or doesn't map to this base
						}
					}
				}

				if (hasSplitPatch && !(await isPackageSetManifest(candidateSourcePath))) {
					if (!validatedRawSourceSet) {
						throw new ToolError(
							`Cannot verify patches for split package members without a valid package set manifest source or declared source_package_set. Base target '${workflow.target}' is not a package set manifest.`,
						);
					}
				}
				try {
					await fs.stat(candidateSourcePath);
				} catch (err) {
					if (isEnoent(err)) {
						throw new ToolError(
							`Physical source file '${candidateSourcePath}' does not exist on disk. Cannot introduce new patches without verifying source original_bytes.`,
						);
					}
					throw new ToolError(
						`Failed to access physical source file '${candidateSourcePath}': ${err instanceof Error ? err.message : String(err)}`,
					);
				}
				await verifySourceOriginalBytes(candidateSourcePath, input.patches, validatedRawSourceSet);
			}

			const verificationResult = await verifyActivePatches(resolvedPath, cumulativePatches);
			if (verificationResult.status !== "verified") {
				throw new ToolError(`Derivative '${buildId}' registration rejected: ${verificationResult.failure_reason}`);
			}

			const signatureInfo = resolveSignatureInfo(input.signature);

			const validatedRuntimeEvidenceIds: string[] = [];
			const runtimeEvidenceConditions: Array<{
				evidence_id: string;
				method: string;
				command: string;
				result: string;
				reproducibility: string;
			}> = [];

			if (input.runtime_evidence_ids && input.runtime_evidence_ids.length > 0) {
				const evidenceStore = new EvidenceStore({ repositoryRoot: this.repositoryRoot });
				const evalResult = await evaluateEvidenceSupport(evidenceStore, input.runtime_evidence_ids, {
					requiredTargetSha256: actualSha256,
				});
				if (evalResult.refutedIds.length > 0) {
					throw new ToolError(
						`Cannot bind refuted runtime evidence to build: ${evalResult.refutedIds.join(", ")}`,
					);
				}
				if (evalResult.staleIds.length > 0) {
					throw new ToolError(
						`Cannot bind stale/invalidated runtime evidence to build: ${evalResult.staleIds.join(", ")}`,
					);
				}
				if (evalResult.mismatchedHashIds.length > 0) {
					throw new ToolError(
						`Runtime evidence target SHA-256 does not match derivative output SHA-256 '${actualSha256}': ${evalResult.mismatchedHashIds.join(", ")}`,
					);
				}
				if (evalResult.failedStageIds.length > 0) {
					throw new ToolError(
						`Runtime evidence contains failed execution stages: ${evalResult.failedStageIds.join(", ")}`,
					);
				}

				for (const evId of input.runtime_evidence_ids) {
					const rec = await evidenceStore.getRecord(evId);
					if (!rec) {
						throw new ToolError(`Runtime evidence '${evId}' not found in project evidence ledger.`);
					}
					if (rec.kind !== "conclusion") {
						throw new ToolError(
							`Runtime evidence '${evId}' is of kind '${rec.kind}', not 'conclusion'. Only verified conclusion evidence may be bound to build runtime status.`,
						);
					}
					if (rec.status !== "verified") {
						throw new ToolError(
							`Runtime evidence '${evId}' conclusion status is '${rec.status}', not 'verified'.`,
						);
					}
					if (!rec.targetSha256 || rec.targetSha256.toLowerCase() !== actualSha256.toLowerCase()) {
						throw new ToolError(
							`Runtime evidence '${evId}' is bound to target SHA-256 '${rec.targetSha256 ?? "undefined"}', which does not match derivative output SHA-256 '${actualSha256}'. Prior revision runtime evidence cannot be inherited by a new revision.`,
						);
					}
					validatedRuntimeEvidenceIds.push(evId);
					runtimeEvidenceConditions.push({
						evidence_id: rec.id,
						method: rec.method,
						command: rec.command,
						result: rec.result,
						reproducibility: rec.reproducibility,
					});
				}
				const mergedConditions: Record<string, unknown> = {
					...(input.verification_conditions ? { declared_conditions: input.verification_conditions } : {}),
					runtime_evidence: runtimeEvidenceConditions,
				};
				verificationResult.runtime_status = "verified";
				verificationResult.conditions = mergedConditions;
			} else {
				verificationResult.runtime_status = "pending";
				verificationResult.conditions = input.verification_conditions;
			}
			const now = new Date().toISOString();
			const derivativeRecord: BuildArtifactRecord = {
				build_id: buildId,
				workflow_id: workflow.id,
				target_path: path.relative(this.repositoryRoot, resolvedPath) || input.target_path,
				output_sha256: actualSha256,
				original_sha256: originalSha256,
				parent_sha256: parentSha256,
				...(parentBuild ? { parent_build_id: parentBuild.build_id } : {}),
				...((input.target_version ?? parentBuild?.target_version ?? baselineBuild?.target_version)
					? {
							target_version:
								input.target_version ?? parentBuild?.target_version ?? baselineBuild?.target_version,
						}
					: {}),
				...((input.abi ?? parentBuild?.abi ?? baselineBuild?.abi)
					? { abi: input.abi ?? parentBuild?.abi ?? baselineBuild?.abi }
					: {}),
				...((input.architecture ?? parentBuild?.architecture ?? baselineBuild?.architecture)
					? { architecture: input.architecture ?? parentBuild?.architecture ?? baselineBuild?.architecture }
					: {}),
				cumulative_patches: cumulativePatches,
				signature: signatureInfo,
				...(verificationResult.conditions ? { verification_conditions: verificationResult.conditions } : {}),
				verification_result: verificationResult,
				...(input.evidence_ids ? { evidence_ids: input.evidence_ids } : {}),
				...(validatedRuntimeEvidenceIds.length > 0 ? { runtime_evidence_ids: validatedRuntimeEvidenceIds } : {}),
				target_device_constraints: constraints,
				scope: targetScope,
				...(input.delivery_mode ? { delivery_mode: input.delivery_mode } : {}),
				...(dependencies ? { dependencies } : {}),
				...(isPkgSet && pkgManifestInfo
					? {
							package_set: pkgManifestInfo.manifest,
						}
					: {}),
				metadata: {
					...input.metadata,
					...(isPkgSet && pkgManifestInfo
						? {
								package_set: {
									package: pkgManifestInfo.manifest.package,
									versionCode: pkgManifestInfo.manifest.versionCode,
									set_sha256: pkgManifestInfo.manifest.set_sha256,
									manifest_sha256: pkgManifestInfo.manifestSha256,
									members: pkgManifestInfo.manifest.members,
								},
							}
						: {}),
				},
				created_at: now,
				updated_at: now,
			};

			workflow.build_lineage = [...(workflow.build_lineage ?? []), derivativeRecord];
			workflow.current_baseline_build_id = derivativeRecord.build_id;
			workflow.base_target_sha256 = originalSha256;
			if (capturedOriginalSetSha) {
				workflow.metadata = {
					...workflow.metadata,
					package_set: {
						...(workflow.metadata?.package_set as Record<string, unknown> | undefined),
						set_sha256: capturedOriginalSetSha,
						...(capturedOriginalMembers ? { members: capturedOriginalMembers } : {}),
						...(validatedRawSourceSet
							? { base: validatedRawSourceSet.base, splits: validatedRawSourceSet.splits }
							: {}),
					},
				};
			}
			workflow.updated_at = now;

			await this.writeWorkflowFileUnlocked(workflow);
			return derivativeRecord;
		});
	}

	async retirePatch(
		workflowId: string,
		patchId: string,
		reason: string,
		buildId?: string,
	): Promise<PatchRetirementAuditEntry> {
		return await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			const workflow = await this.get(workflowId);
			if (!workflow) {
				throw new ToolError(`Workflow '${workflowId}' not found.`);
			}
			if (!reason || reason.trim().length === 0) {
				throw new ToolError("A non-empty retirement reason is required to retire a patch.");
			}

			let targetBuild: BuildArtifactRecord | undefined;
			if (buildId) {
				targetBuild = workflow.build_lineage?.find(b => b.build_id === buildId);
				if (!targetBuild) {
					throw new ToolError(`Target build '${buildId}' not found in workflow '${workflowId}' build lineage.`);
				}
			} else if (workflow.current_baseline_build_id) {
				targetBuild = workflow.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id);
				if (!targetBuild) {
					throw new ToolError(
						`Corrupt baseline reference: current_baseline_build_id '${workflow.current_baseline_build_id}' not found in workflow '${workflowId}' build lineage.`,
					);
				}
			} else {
				throw new ToolError(
					`No active baseline or derivative established in workflow '${workflowId}' to retire patch from.`,
				);
			}

			const activePatch = targetBuild.cumulative_patches.find(p => p.patch_id === patchId && p.status === "active");
			if (!activePatch) {
				throw new ToolError(
					`Patch '${patchId}' is not an active patch in baseline '${targetBuild.build_id}'. Cannot retire unknown or already retired patch.`,
				);
			}

			const now = new Date().toISOString();
			const auditEntry: PatchRetirementAuditEntry = {
				patch_id: patchId,
				reason: reason.trim(),
				retired_at: now,
				build_id: targetBuild.build_id,
			};

			workflow.retired_patches_audit = [...(workflow.retired_patches_audit ?? []), auditEntry];
			workflow.updated_at = now;

			await this.writeWorkflowFileUnlocked(workflow);
			return auditEntry;
		});
	}

	async verifyDerivative(workflowId: string, buildId?: string, targetPath?: string): Promise<BuildVerificationResult> {
		const workflow = await this.get(workflowId);
		if (!workflow) {
			throw new ToolError(`Workflow '${workflowId}' not found.`);
		}

		let derivative: BuildArtifactRecord | undefined;
		if (buildId) {
			derivative = workflow.build_lineage?.find(b => b.build_id === buildId);
			if (!derivative) {
				throw new ToolError(`Build ID '${buildId}' not found in workflow '${workflowId}' build lineage.`);
			}
		} else if (workflow.current_baseline_build_id) {
			derivative = workflow.build_lineage?.find(b => b.build_id === workflow.current_baseline_build_id);
			if (!derivative) {
				throw new ToolError(
					`Corrupt baseline reference: current_baseline_build_id '${workflow.current_baseline_build_id}' not found in workflow '${workflowId}' build lineage.`,
				);
			}
		} else {
			throw new ToolError(`No active baseline or derivative established in workflow '${workflowId}'.`);
		}

		const checkPath = targetPath ?? derivative.target_path;
		const resolvedPath = path.isAbsolute(checkPath) ? checkPath : path.resolve(this.repositoryRoot, checkPath);

		let diskSha256: string;
		try {
			diskSha256 = await hashFileSha256(resolvedPath);
		} catch (err) {
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: derivative.verification_result.runtime_status,
				checked_patches_count: 0,
				failure_reason: `Target file '${checkPath}' unreadable: ${err instanceof Error ? err.message : String(err)}`,
			};
		}

		if (diskSha256.toLowerCase() !== derivative.output_sha256.toLowerCase()) {
			return {
				status: "failed",
				static_status: "failed",
				runtime_status: derivative.verification_result.runtime_status,
				checked_patches_count: 0,
				failure_reason: `Derivative output SHA-256 mismatch (tampered/drifted): expected '${derivative.output_sha256}', actual '${diskSha256}'`,
			};
		}

		if (
			derivative.package_set ||
			(derivative.metadata?.package_set as Record<string, unknown> | undefined)?.format === "apk_package_set" ||
			path.basename(resolvedPath).toLowerCase() === "package-set.json"
		) {
			try {
				await parseAndValidatePackageSetManifest(resolvedPath);
			} catch (err) {
				return {
					status: "failed",
					static_status: "failed",
					runtime_status: derivative.verification_result.runtime_status,
					checked_patches_count: 0,
					failure_reason: `Package set derivative verification failed: ${err instanceof Error ? err.message : String(err)}`,
				};
			}
		}

		const patchRes = await verifyActivePatches(resolvedPath, derivative.cumulative_patches);
		if (patchRes.status === "failed") return patchRes;

		const constraints: TargetDeviceConstraints | undefined = normalizeTargetDeviceConstraints(
			derivative.target_device_constraints ??
				(derivative.metadata?.target_device_constraints as TargetDeviceConstraints | undefined) ??
				(workflow.metadata?.target_device_constraints as TargetDeviceConstraints | undefined),
		);

		const dependencies: WorkflowDependencyRecord[] | undefined = normalizeWorkflowDependencies(
			derivative.dependencies ??
				(derivative.metadata?.dependencies as WorkflowDependencyRecord[] | undefined) ??
				(workflow.metadata?.dependencies as WorkflowDependencyRecord[] | undefined),
		);

		const targetScope: "experiment" | "delivery" =
			derivative.scope ??
			(derivative.metadata?.scope as "experiment" | "delivery" | undefined) ??
			(constraints?.requires_standalone ? "delivery" : "experiment");

		const constraintCheck = validateDeploymentConstraints(constraints, dependencies, targetScope);
		if (!constraintCheck.valid) {
			return {
				status: "failed",
				static_status: patchRes.static_status,
				runtime_status: derivative.verification_result.runtime_status,
				checked_patches_count: patchRes.checked_patches_count,
				failure_reason: `${constraintCheck.violationCode}: ${constraintCheck.violation}`,
			};
		}
		if (derivative.runtime_evidence_ids && derivative.runtime_evidence_ids.length > 0) {
			const evidenceStore = new EvidenceStore({ repositoryRoot: this.repositoryRoot });
			const evalResult = await evaluateEvidenceSupport(evidenceStore, derivative.runtime_evidence_ids, {
				requiredTargetSha256: diskSha256,
			}).catch(() => null);

			if (!evalResult || !evalResult.valid || evalResult.refutedIds.length > 0 || evalResult.staleIds.length > 0) {
				const reason = evalResult?.reason ?? "Runtime evidence was refuted or is no longer valid.";
				return {
					status: "failed",
					static_status: patchRes.static_status,
					runtime_status: "failed",
					checked_patches_count: patchRes.checked_patches_count,
					failure_reason: `Runtime evidence verification failed: ${reason}`,
				};
			}
		}

		return patchRes;
	}

	async getBaseline(workflowId: string): Promise<BuildArtifactRecord | null> {
		const workflow = await this.get(workflowId);
		if (!workflow || !workflow.build_lineage || workflow.build_lineage.length === 0) return null;
		if (workflow.current_baseline_build_id) {
			return workflow.build_lineage.find(b => b.build_id === workflow.current_baseline_build_id) ?? null;
		}
		return workflow.build_lineage[workflow.build_lineage.length - 1] ?? null;
	}

	async listDerivatives(workflowId: string): Promise<BuildArtifactRecord[]> {
		const workflow = await this.get(workflowId);
		return workflow?.build_lineage ?? [];
	}

	async getDerivative(workflowId: string, buildId: string): Promise<BuildArtifactRecord | null> {
		const workflow = await this.get(workflowId);
		return workflow?.build_lineage?.find(b => b.build_id === buildId) ?? null;
	}
}
