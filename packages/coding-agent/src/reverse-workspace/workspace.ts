import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { EvidenceStore } from "../evidence/store";
import type { EvidenceRecord } from "../evidence/contracts";
import type { ReverseWorkflowRecord } from "../reverse-workflow/contracts";
import {
	hydrateWorkflowEvidence,
	exportWorkflowToMarkdown,
	exportWorkflowToJson,
	type HydratedEvidenceItem,
} from "../reverse-workflow/export";
import {
	DEFAULT_WORKSPACE_DIR,
	WORKSPACE_SUBDIRS,
	WORKSPACE_FILES,
	MAX_SAFE_ARTIFACT_COPY_BYTES,
	type ExportToWorkspaceOptions,
	type ExportToWorkspaceResult,
	type InspectWorkspaceResult,
	type CleanWorkspaceOptions,
	type CleanWorkspaceResult,
	type ReverseWorkspaceManifest,
	type ReverseWorkspaceTargetInfo,
	type ReverseWorkspaceStats,
	type ReverseWorkspaceArtifactRef,
	type ReverseWorkspaceFileEntry,
} from "./contracts";
import {
	atomicWriteFile,
	assertWithinPath,
	hashBuffer,
	hashString,
	hashFile,
	redactSecrets,
	deterministicJsonStringify,
} from "./atomic";
import { generateFindingsData, generateFindingsMarkdown } from "./findings";

const SCRIPT_EXTENSIONS: Record<string, true> = {
	".js": true,
	".mjs": true,
	".cjs": true,
	".ts": true,
	".py": true,
	".sh": true,
	".bash": true,
	".rb": true,
	".ps1": true,
};

const DUMP_EXTENSIONS: Record<string, true> = {
	".txt": true,
	".json": true,
	".csv": true,
	".dump": true,
	".log": true,
	".asm": true,
	".s": true,
	".decomp.c": true,
	".c": true,
	".h": true,
	".headers": true,
};

const GITIGNORE_CONTENT = `# Rea reverse workspace gitignore
# Excludes heavy raw binaries, cores, and memory dumps while preserving reports and manifests
*.raw
*.bin
*.dmp
*.core
*.iso
*.vmdk
*.pcap
*.pcapng
.tmp*
*.tmp
`;

/**
 * Exports a reverse workflow and all associated evidence, findings, and safe artifact
 * references into a standardized, deterministic .rea/ workspace.
 */
export async function exportWorkflowToWorkspace(
	options: ExportToWorkspaceOptions,
): Promise<ExportToWorkspaceResult> {
	const { workflow, evidenceStore, projectDir } = options;

	const resolvedWorkspaceDir = options.workspaceDir
		? path.resolve(projectDir, options.workspaceDir)
		: path.resolve(projectDir, DEFAULT_WORKSPACE_DIR);

	const relativeWorkspaceDir = path.relative(projectDir, resolvedWorkspaceDir) || ".";

	// Ensure all standard subdirectories exist
	for (const subdir of WORKSPACE_SUBDIRS) {
		const dirPath = path.join(resolvedWorkspaceDir, subdir);
		await fs.mkdir(dirPath, { recursive: true });
	}

	// 1. Inspect target without mutation or copying raw huge binary
	const candidatePath = workflow.target_abs_path || workflow.target;
	const resolvedTargetPath = path.isAbsolute(candidatePath)
		? candidatePath
		: path.resolve(projectDir, candidatePath);

	let targetSha256 = workflow.target_sha256;
	let targetSize = workflow.target_size;

	try {
		const targetStat = await fs.stat(resolvedTargetPath);
		if (targetStat.isFile()) {
			targetSize = targetStat.size;
			const hash = createHash("sha256");
			const stream = createReadStream(resolvedTargetPath);
			for await (const chunk of stream) hash.update(chunk);
			targetSha256 = hash.digest("hex");
		}
	} catch {
		// Target may be remote or logical; preserve existing workflow target metadata.
		targetSha256 = workflow.target_sha256;
	}

	targetSha256 = targetSha256 ?? workflow.target_sha256;
	targetSize = targetSize ?? workflow.target_size;
	const safeTargetRelPath = path.isAbsolute(workflow.target)
		? path.relative(projectDir, workflow.target)
		: workflow.target;

	const targetInfo: ReverseWorkspaceTargetInfo = {
		path: safeTargetRelPath,
		name: path.basename(workflow.target),
		format: workflow.format,
		sha256: targetSha256,
		size: targetSize,
		is_reference: true,
		inspected_at: new Date().toISOString(),
	};

	// 2. Hydrate workflow and evidence
	const hydrated = await hydrateWorkflowEvidence(workflow, evidenceStore);
	const allHydratedItems: HydratedEvidenceItem[] = [];
	const seenEvidenceIds = new Set<string>();

	for (const step of hydrated.steps) {
		if (step.hydrated_evidence) {
			for (const item of step.hydrated_evidence) {
				if (!seenEvidenceIds.has(item.id)) {
					seenEvidenceIds.add(item.id);
					allHydratedItems.push(item);
				}
			}
		}
	}

	// 3. Process artifact references (safe small copy vs safe reference)
	const artifactRefs: ReverseWorkspaceArtifactRef[] = [];
	const seenArtifactIds = new Set<string>();
	const usedDestPaths = new Set<string>();
	let scriptsCopiedCount = 0;
	let dumpsCopiedCount = 0;
	for (const step of workflow.steps) {
		if (!step.artifact_refs || !Array.isArray(step.artifact_refs)) continue;

		for (const ref of step.artifact_refs) {
			if (seenArtifactIds.has(ref)) continue;
			seenArtifactIds.add(ref);

			if (ref.startsWith("artifact://") || ref.startsWith("art-")) {
				artifactRefs.push({
					id: ref,
					kind: "reference",
					copied: false,
					reason: "session_artifact",
				});
				continue;
			}

			const resolvedArtifactPath = path.isAbsolute(ref) ? ref : path.resolve(projectDir, ref);

			try {
				const artStat = await fs.stat(resolvedArtifactPath);
				if (!artStat.isFile()) {
					artifactRefs.push({
						id: ref,
						source_path: ref,
						kind: "reference",
						copied: false,
						reason: "not_a_regular_file",
					});
					continue;
				}

				const ext = path.extname(ref).toLowerCase();
				const isScript = SCRIPT_EXTENSIONS[ext] === true;
				const isDump = DUMP_EXTENSIONS[ext] === true;

				if (artStat.size > MAX_SAFE_ARTIFACT_COPY_BYTES) {
					const hashed = await hashFile(resolvedArtifactPath);
					artifactRefs.push({
						id: ref,
						source_path: path.relative(projectDir, resolvedArtifactPath),
						kind: "reference",
						size_bytes: artStat.size,
						sha256: hashed?.sha256,
						copied: false,
						reason: "exceeds_safe_size_limit",
					});
					continue;
				}

				if (isScript || isDump) {
					const destSubdir = isScript ? "scripts" : "dumps";
					const destRel = allocateArtifactDestinationPath(destSubdir, ref, usedDestPaths);
					const destPath = assertWithinPath(resolvedWorkspaceDir, destRel);
					const rawContent = await fs.readFile(resolvedArtifactPath);
					let finalContent = rawContent;

					// Redact text files
					try {
						const asText = rawContent.toString("utf8");
						if (!asText.includes("\0")) {
							finalContent = Buffer.from(redactSecrets(asText), "utf8");
						}
					} catch {
						// Keep raw bytes if not valid utf8
					}

					await atomicWriteFile(destPath, finalContent);
					const contentHash = hashBuffer(finalContent);

					if (isScript) scriptsCopiedCount++;
					else dumpsCopiedCount++;

					artifactRefs.push({
						id: ref,
						source_path: path.relative(projectDir, resolvedArtifactPath),
						destination_path: destRel,
						kind: isScript ? "script" : "dump",
						size_bytes: contentHash.size,
						sha256: contentHash.sha256,
						copied: true,
					});
				} else {
					const hashed = await hashFile(resolvedArtifactPath);
					artifactRefs.push({
						id: ref,
						source_path: path.relative(projectDir, resolvedArtifactPath),
						kind: "reference",
						size_bytes: artStat.size,
						sha256: hashed?.sha256,
						copied: false,
						reason: "binary_format_reference_only",
					});
				}
			} catch {
				artifactRefs.push({
					id: ref,
					source_path: ref,
					kind: "reference",
					copied: false,
					reason: "file_not_found",
				});
			}
		}
	}

	// 4. Generate core reports and evidence files
	const findingsData = generateFindingsData(workflow, allHydratedItems, targetInfo);
	const findingsMd = generateFindingsMarkdown(workflow, allHydratedItems, targetInfo);
	const workflowMd = await exportWorkflowToMarkdown(workflow, evidenceStore);
	const workflowJson = await exportWorkflowToJson(workflow, evidenceStore);

	const evidenceRecords: EvidenceRecord[] = [];
	for (const item of allHydratedItems) {
		if (item.record) evidenceRecords.push(item.record);
	}

	const evidenceLedger = {
		facts: findingsData.facts,
		verified_hypotheses: findingsData.verified_hypotheses,
		unverified_hypotheses: findingsData.unverified_hypotheses,
		conclusions: findingsData.conclusions,
	};

	// 5. Write workspace files atomically
	const filesToWrite: Array<{ relPath: string; content: string }> = [
		{ relPath: WORKSPACE_FILES.GITIGNORE, content: GITIGNORE_CONTENT },
		{ relPath: WORKSPACE_FILES.TARGET_INFO, content: deterministicJsonStringify(targetInfo) },
		{ relPath: WORKSPACE_FILES.WORKFLOW_JSON, content: workflowJson },
		{ relPath: WORKSPACE_FILES.WORKFLOW_MD, content: workflowMd },
		{ relPath: WORKSPACE_FILES.EVIDENCE_JSON, content: deterministicJsonStringify(evidenceRecords) },
		{ relPath: WORKSPACE_FILES.EVIDENCE_LEDGER, content: deterministicJsonStringify(evidenceLedger) },
		{ relPath: WORKSPACE_FILES.FINDINGS_JSON, content: deterministicJsonStringify(findingsData) },
		{ relPath: WORKSPACE_FILES.FINDINGS_MD, content: findingsMd },
		{ relPath: WORKSPACE_FILES.REPORT_WORKFLOW, content: workflowMd },
		{ relPath: WORKSPACE_FILES.REPORT_FINDINGS, content: findingsMd },
	];

	const createdFileEntries: ReverseWorkspaceFileEntry[] = [];
	const createdFilePaths: string[] = [];

	for (const file of filesToWrite) {
		const fullPath = assertWithinPath(resolvedWorkspaceDir, file.relPath);
		await atomicWriteFile(fullPath, file.content);
		const hashMeta = hashString(file.content);

		createdFileEntries.push({
			path: file.relPath,
			size_bytes: hashMeta.size,
			sha256: hashMeta.sha256,
		});
		createdFilePaths.push(file.relPath);
	}

	// Include copied script and dump files in files manifest
	for (const art of artifactRefs) {
		if (art.copied && art.destination_path && art.sha256 && art.size_bytes !== undefined) {
			createdFileEntries.push({
				path: art.destination_path,
				size_bytes: art.size_bytes,
				sha256: art.sha256,
			});
			createdFilePaths.push(art.destination_path);
		}
	}

	createdFileEntries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

	// 6. Compute statistics
	let stepsCompleted = 0;
	let stepsFailed = 0;
	let stepsPending = 0;
	let stepsSkipped = 0;

	for (const s of workflow.steps) {
		if (s.status === "completed") stepsCompleted++;
		else if (s.status === "failed") stepsFailed++;
		else if (s.status === "skipped") stepsSkipped++;
		else stepsPending++;
	}

	const stats: ReverseWorkspaceStats = {
		steps_total: workflow.steps.length,
		steps_completed: stepsCompleted,
		steps_failed: stepsFailed,
		steps_pending: stepsPending,
		steps_skipped: stepsSkipped,
		evidence_total: allHydratedItems.length,
		facts_count: findingsData.facts.length,
		hypotheses_count: findingsData.verified_hypotheses.length + findingsData.unverified_hypotheses.length,
		hypotheses_verified_count: findingsData.verified_hypotheses.length,
		conclusions_count: findingsData.conclusions.length,
		artifacts_count: artifactRefs.length,
		scripts_count: scriptsCopiedCount,
		dumps_count: dumpsCopiedCount,
		reports_count: 2,
	};

	// 7. Write manifest.json
	const manifest: ReverseWorkspaceManifest = {
		schema_version: "1.0.0",
		created_at: workflow.created_at || new Date().toISOString(),
		updated_at: new Date().toISOString(),
		workspace_dir: relativeWorkspaceDir,
		workflow: {
			id: workflow.id,
			format: workflow.format,
			status: workflow.status,
			goal: workflow.goal,
			created_at: workflow.created_at,
			updated_at: workflow.updated_at,
		},
		target: targetInfo,
		stats,
		files: createdFileEntries,
		artifacts: artifactRefs,
	};

	const manifestContent = deterministicJsonStringify(manifest);
	const manifestFullPath = path.join(resolvedWorkspaceDir, WORKSPACE_FILES.MANIFEST);
	await atomicWriteFile(manifestFullPath, manifestContent);

	createdFilePaths.push(WORKSPACE_FILES.MANIFEST);

	return {
		workspace_dir: resolvedWorkspaceDir,
		relative_workspace_dir: relativeWorkspaceDir,
		manifest,
		created_files: createdFilePaths,
		target_info: targetInfo,
		stats,
	};
}

/**
 * Deterministically allocates a unique destination relative path within a workspace
 * subdirectory (e.g. "scripts" or "dumps") to avoid basename collisions.
 * Preserves the file extension and appends incrementing integer counters (_1, _2, ...)
 * for colliding basenames, ensuring all files and manifest references remain distinct.
 */
export function allocateArtifactDestinationPath(
	destSubdir: "scripts" | "dumps",
	rawFileName: string,
	usedPaths: Set<string>,
): string {
	const rawBase = path.basename(rawFileName);
	let safeBaseName = rawBase.replace(/[^a-zA-Z0-9._-]/g, "_");
	if (!safeBaseName || safeBaseName === "." || safeBaseName === "..") {
		safeBaseName = "artifact";
	}

	const preferredRel = `${destSubdir}/${safeBaseName}`;
	if (!usedPaths.has(preferredRel)) {
		usedPaths.add(preferredRel);
		return preferredRel;
	}

	const ext = path.extname(safeBaseName);
	const stem = ext ? safeBaseName.slice(0, -ext.length) : safeBaseName;

	let counter = 1;
	while (true) {
		const candidate = `${destSubdir}/${stem}_${counter}${ext}`;
		if (!usedPaths.has(candidate)) {
			usedPaths.add(candidate);
			return candidate;
		}
		counter++;
	}
}

/**
 * Reads and validates a workspace manifest from disk.
 */
export async function loadWorkspaceManifest(
	workspaceDir: string,
): Promise<ReverseWorkspaceManifest | null> {
	const manifestPath = path.join(workspaceDir, WORKSPACE_FILES.MANIFEST);
	try {
		const content = await fs.readFile(manifestPath, "utf8");
		const parsed = JSON.parse(content) as ReverseWorkspaceManifest;
		if (
			parsed &&
			parsed.schema_version === "1.0.0" &&
			parsed.workflow &&
			typeof parsed.workflow.id === "string" &&
			parsed.target &&
			typeof parsed.target.name === "string" &&
			Array.isArray(parsed.files) &&
			Array.isArray(parsed.artifacts)
		) {
			return parsed;
		}
		return null;
	} catch {
		return null;
	}
}

/**
 * Inspects a workspace directory, validating manifest and structural directories.
 */
export async function inspectWorkspace(
	workspaceDir: string,
	projectDir: string = process.cwd(),
): Promise<InspectWorkspaceResult> {
	const resolvedWorkspaceDir = path.isAbsolute(workspaceDir)
		? workspaceDir
		: path.resolve(projectDir, workspaceDir);

	const relativeWorkspaceDir = path.relative(projectDir, resolvedWorkspaceDir) || ".";

	try {
		const stat = await fs.stat(resolvedWorkspaceDir);
		if (!stat.isDirectory()) {
			return {
				exists: false,
				workspace_dir: resolvedWorkspaceDir,
				relative_workspace_dir: relativeWorkspaceDir,
				file_count: 0,
				subdirs: [],
				valid: false,
				validation_errors: ["Target workspace path is not a directory"],
			};
		}

		const entries = await fs.readdir(resolvedWorkspaceDir, { withFileTypes: true });
		const subdirs = entries.filter(e => e.isDirectory()).map(e => e.name);
		const manifest = await loadWorkspaceManifest(resolvedWorkspaceDir);

		const validationErrors: string[] = [];
		if (!manifest) {
			validationErrors.push("Missing or invalid manifest.json");
		}

		for (const expectedSubdir of WORKSPACE_SUBDIRS) {
			if (!subdirs.includes(expectedSubdir)) {
				validationErrors.push(`Missing expected subdirectory: ${expectedSubdir}`);
			}
		}

		let totalFiles = 0;
		for (const entry of entries) {
			if (entry.isFile()) totalFiles++;
			else if (entry.isDirectory()) {
				try {
					const subEntries = await fs.readdir(path.join(resolvedWorkspaceDir, entry.name));
					totalFiles += subEntries.length;
				} catch {
					// ignore read errors on subdirectories
				}
			}
		}

		return {
			exists: true,
			workspace_dir: resolvedWorkspaceDir,
			relative_workspace_dir: relativeWorkspaceDir,
			manifest: manifest || undefined,
			file_count: totalFiles,
			subdirs,
			valid: validationErrors.length === 0,
			validation_errors: validationErrors.length > 0 ? validationErrors : undefined,
		};
	} catch {
		return {
			exists: false,
			workspace_dir: resolvedWorkspaceDir,
			relative_workspace_dir: relativeWorkspaceDir,
			file_count: 0,
			subdirs: [],
			valid: false,
			validation_errors: ["Workspace directory does not exist"],
		};
	}
}

/**
 * Safely cleans temporary or dump files from a reverse engineering workspace.
 */
export async function cleanWorkspace(options: CleanWorkspaceOptions): Promise<CleanWorkspaceResult> {
	const { projectDir, removeDumpsOnly = false } = options;

	if (!projectDir || typeof projectDir !== "string") {
		throw new Error("Cannot clean workspace: invalid projectDir");
	}

	const resolvedProjectDir = path.resolve(projectDir);

	// 1. Verify project directory exists and is a directory
	let projectStat: fs.Stats;
	try {
		projectStat = await fs.stat(resolvedProjectDir);
	} catch {
		throw new Error(`Project directory does not exist: ${resolvedProjectDir}`);
	}
	if (!projectStat.isDirectory()) {
		throw new Error(`Project directory is not a directory: ${resolvedProjectDir}`);
	}

	const realProjectDir = await fs.realpath(resolvedProjectDir);

	// 2. Resolve workspace directory
	const resolvedWorkspaceDir = options.workspaceDir
		? path.resolve(resolvedProjectDir, options.workspaceDir)
		: path.resolve(resolvedProjectDir, DEFAULT_WORKSPACE_DIR);

	// 3. Reject root directory
	const rootDir = path.parse(resolvedWorkspaceDir).root;
	if (resolvedWorkspaceDir === rootDir) {
		throw new Error(`Workspace directory cannot be filesystem root: ${resolvedWorkspaceDir}`);
	}

	// 4. Reject plain project directory
	if (resolvedWorkspaceDir === resolvedProjectDir) {
		throw new Error(`Workspace directory cannot be project directory itself: ${resolvedWorkspaceDir}`);
	}

	// 5. Reject lexical path traversal escaping project directory
	const relToProject = path.relative(resolvedProjectDir, resolvedWorkspaceDir);
	if (relToProject.startsWith("..") || path.isAbsolute(relToProject)) {
		throw new Error(`Workspace directory escapes project directory: ${resolvedWorkspaceDir}`);
	}

	// 6. Check workspace directory exists and check lstat
	let wsLstat: fs.Stats;
	try {
		wsLstat = await fs.lstat(resolvedWorkspaceDir);
	} catch {
		throw new Error(`Workspace directory does not exist: ${resolvedWorkspaceDir}`);
	}

	if (!wsLstat.isDirectory() && !wsLstat.isSymbolicLink()) {
		throw new Error(`Workspace path is not a directory: ${resolvedWorkspaceDir}`);
	}

	// 7. Check realpath containment for workspace directory
	const realWorkspaceDir = await fs.realpath(resolvedWorkspaceDir);
	if (realWorkspaceDir === path.parse(realWorkspaceDir).root) {
		throw new Error(`Workspace realpath cannot be filesystem root: ${realWorkspaceDir}`);
	}
	if (realWorkspaceDir === realProjectDir) {
		throw new Error(`Workspace realpath cannot be project directory itself: ${realWorkspaceDir}`);
	}

	const relRealProject = path.relative(realProjectDir, realWorkspaceDir);
	if (relRealProject.startsWith("..") || path.isAbsolute(relRealProject)) {
		throw new Error(
			`Workspace directory escapes project directory via symlink: ${resolvedWorkspaceDir} -> ${realWorkspaceDir}`,
		);
	}

	// 8. Validate manifest file and ownership before ANY deletion
	const manifestPath = path.join(resolvedWorkspaceDir, WORKSPACE_FILES.MANIFEST);
	let manifestLstat: fs.Stats;
	try {
		manifestLstat = await fs.lstat(manifestPath);
	} catch {
		throw new Error(`Cannot clean workspace: missing manifest at ${manifestPath}`);
	}

	if (manifestLstat.isSymbolicLink()) {
		const realManifestPath = await fs.realpath(manifestPath);
		const relManifest = path.relative(realWorkspaceDir, realManifestPath);
		if (relManifest.startsWith("..") || path.isAbsolute(relManifest)) {
			throw new Error("Cannot clean workspace: manifest symlink escapes workspace directory");
		}
	}

	const manifest = await loadWorkspaceManifest(resolvedWorkspaceDir);
	if (!manifest) {
		throw new Error(`Cannot clean workspace: invalid manifest at ${manifestPath}`);
	}

	// Real owned manifest checks
	if (
		manifest.schema_version !== "1.0.0" ||
		!manifest.workflow ||
		typeof manifest.workflow.id !== "string" ||
		!manifest.target ||
		typeof manifest.target.name !== "string" ||
		manifest.target.is_reference !== true ||
		!Array.isArray(manifest.files) ||
		!Array.isArray(manifest.artifacts)
	) {
		throw new Error("Cannot clean workspace: invalid manifest ownership or structure");
	}

	// 9. Check subdirectories for symlink escapes
	const dirsToCheck = removeDumpsOnly ? ["dumps"] : ["dumps", "scripts"];
	for (const dirName of dirsToCheck) {
		const targetDir = path.join(resolvedWorkspaceDir, dirName);
		let dirLstat: fs.Stats;
		try {
			dirLstat = await fs.lstat(targetDir);
		} catch (error) {
			if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") continue;
			throw error;
		}
		if (dirLstat.isSymbolicLink()) {
			const realSubdir = await fs.realpath(targetDir);
			const relSub = path.relative(realWorkspaceDir, realSubdir);
			if (relSub.startsWith("..") || path.isAbsolute(relSub)) {
				throw new Error(`Symlink escape detected on subdirectory ${dirName}: resolves to ${realSubdir}`);
			}
		}
	}

	// 10. Identify manifest-indexed generated scripts/dumps only
	const allowedSubdirs = removeDumpsOnly ? ["dumps"] : ["dumps", "scripts"];
	const manifestFilePaths = new Set(manifest.files.map(f => f.path));

	// Candidate destination paths from manifest.artifacts that were actually copied
	const candidatePaths: string[] = [];
	for (const art of manifest.artifacts) {
		if (art.copied !== true || !art.destination_path) continue;

		const normDest = path.normalize(art.destination_path);
		// Must not escape
		if (normDest.startsWith("..") || path.isAbsolute(normDest)) continue;

		// Must match allowed kind and subdirectory
		const parts = normDest.split(path.sep);
		const topDir = parts[0];
		if (!allowedSubdirs.includes(topDir)) continue;

		if (removeDumpsOnly && art.kind !== "dump") continue;
		if (!removeDumpsOnly && art.kind !== "dump" && art.kind !== "script") continue;

		// Must also be indexed in manifest.files
		if (!manifestFilePaths.has(normDest)) continue;

		candidatePaths.push(normDest);
	}

	const uniqueCandidatePaths = Array.from(new Set(candidatePaths));
	const removedFiles: string[] = [];

	// 11. Safely remove each manifest-indexed file, verifying lstat/realpath containment
	for (const relPath of uniqueCandidatePaths) {
		const fullFilePath = assertWithinPath(resolvedWorkspaceDir, relPath);

		let fileLstat: fs.Stats;
		try {
			fileLstat = await fs.lstat(fullFilePath);
		} catch {
			// File does not exist on disk
			continue;
		}

		if (fileLstat.isDirectory()) {
			throw new Error(`Expected file but found directory at ${relPath}`);
		}

		if (fileLstat.isSymbolicLink()) {
			const realFilePath = await fs.realpath(fullFilePath);
			const relToWs = path.relative(realWorkspaceDir, realFilePath);
			if (relToWs.startsWith("..") || path.isAbsolute(relToWs)) {
				throw new Error(
					`Symlink escape detected for file ${relPath}: resolves to ${realFilePath}`,
				);
			}
			const expectedSubdir = relPath.startsWith("dumps") ? "dumps" : "scripts";
			const realSubdirPath = await fs.realpath(path.join(resolvedWorkspaceDir, expectedSubdir));
			const relToSub = path.relative(realSubdirPath, realFilePath);
			if (relToSub.startsWith("..") || path.isAbsolute(relToSub)) {
				throw new Error(
					`Symlink escape detected for file ${relPath}: escapes ${expectedSubdir}`,
				);
			}
		}

		await fs.unlink(fullFilePath);
		removedFiles.push(relPath);
	}

	removedFiles.sort();

	// 12. Compute preserved files
	const preservedFiles: string[] = [];
	for (const f of manifest.files) {
		if (!removedFiles.includes(f.path)) {
			preservedFiles.push(f.path);
		}
	}
	preservedFiles.sort();

	return {
		workspace_dir: resolvedWorkspaceDir,
		removed_files: removedFiles,
		preserved_files: preservedFiles,
	};
}
