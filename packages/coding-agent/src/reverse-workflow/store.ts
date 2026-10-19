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
	encodeWorkflowProjectKey,
	createWorkflowId,
	normalizeTargetFormat,
} from "./contracts";
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
		const record: ReverseWorkflowRecord = {
			id: workflowId,
			target: input.target,
			format,
			goal: input.goal,
			status: "active",
			steps,
			created_at: now,
			updated_at: now,
			...(input.knowledge_refs ? { knowledge_refs: input.knowledge_refs } : {}),
			...(input.runtime_session_ids ? { runtime_session_ids: input.runtime_session_ids } : {}),
			...(input.metadata ? { metadata: input.metadata } : {}),
		};

		await this.save(record);
		return record;
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

	async save(record: ReverseWorkflowRecord): Promise<void> {
		await this.ensureDir();
		const targetPath = this.workflowFilePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7().slice(0, 8)}.tmp`;
		const payload = JSON.stringify(record, null, 2);

		await withWorkflowStoreWrite(this.projectDirectory, this.lockPath, async () => {
			await fs.writeFile(tempPath, payload, "utf8");
			await replaceFileAtomically(tempPath, targetPath);
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

	async list(): Promise<ReverseWorkflowRecord[]> {
		await this.ensureDir();
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

			// Sort by updated_at descending
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
}
