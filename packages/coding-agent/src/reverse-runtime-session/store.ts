import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isEnoent, getReverseRuntimeSessionsProjectDir } from "@reverse/utils";
import { replaceFileAtomically } from "../utils/atomic-file";
import {
	type RuntimeSessionRecord,
	type RuntimeSessionKind,
	DEFAULT_LIST_LIMIT,
	MAX_LIST_LIMIT,
	MAX_REGISTRY_SESSIONS,
	computeSessionStaleState,
	encodeRuntimeSessionProjectKey,
} from "./contracts";
import { sanitizeRuntimeSessionRecord } from "./sanitize";

export interface SessionListFilter {
	kind?: RuntimeSessionKind;
	status?: string;
	workflow_id?: string;
	limit?: number;
}
export interface ReverseRuntimeSessionStoreOptions {
	repositoryRoot?: string;
	projectDirectory?: string;
	stateRoot?: string;
}

export class ReverseRuntimeSessionStore {
	readonly projectDirectory: string;

	constructor(projectDirectoryOrOptions: string | ReverseRuntimeSessionStoreOptions) {
		if (typeof projectDirectoryOrOptions === "string") {
			this.projectDirectory = projectDirectoryOrOptions;
		} else if (projectDirectoryOrOptions.projectDirectory) {
			this.projectDirectory = projectDirectoryOrOptions.projectDirectory;
		} else {
			const cwd = projectDirectoryOrOptions.repositoryRoot ?? process.cwd();
			const projectKey = encodeRuntimeSessionProjectKey(cwd);
			this.projectDirectory = projectDirectoryOrOptions.stateRoot
				? path.join(path.resolve(projectDirectoryOrOptions.stateRoot), projectKey)
				: getReverseRuntimeSessionsProjectDir(projectKey);
		}
	}

	static forSession(cwd: string, stateRoot?: string): ReverseRuntimeSessionStore {
		return new ReverseRuntimeSessionStore({ repositoryRoot: cwd, stateRoot });
	}

	async ensureDir(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: 0o700 });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, 0o700).catch(() => undefined);
		}
	}

	filePath(sessionId: string): string {
		const safeId = sessionId.replace(/[^a-zA-Z0-9._-]/g, "_");
		return path.join(this.projectDirectory, `${safeId}.json`);
	}

	async save(record: RuntimeSessionRecord): Promise<void> {
		await this.ensureDir();

		// Check capacity limit and evict oldest closed/stale sessions if exceeding MAX_REGISTRY_SESSIONS
		try {
			const existing = await this.list({ limit: MAX_REGISTRY_SESSIONS + 10 });
			if (existing.length >= MAX_REGISTRY_SESSIONS && !existing.some(r => r.id === record.id)) {
				// Find candidates for eviction (closed, stale, or oldest updated)
				const candidates = existing
					.filter(r => r.status === "closed" || r.status === "stale" || r.status === "failed")
					.sort((a, b) => a.updated_at.localeCompare(b.updated_at));

				const evictTarget = candidates[0] ?? existing[existing.length - 1];
				if (evictTarget && evictTarget.id !== record.id) {
					await this.delete(evictTarget.id).catch(() => undefined);
				}
			}
		} catch {
			// Best-effort eviction
		}

		const targetPath = this.filePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7()}.${Math.random().toString(36).slice(2)}.tmp`;

		// Deep sanitize all record fields before persisting
		const sanitizedRecord = sanitizeRuntimeSessionRecord(record);

		const json = JSON.stringify(sanitizedRecord, null, 2);
		await Bun.write(tempPath, json);
		if (process.platform !== "win32") {
			await fs.chmod(tempPath, 0o600).catch(() => undefined);
		}
		await replaceFileAtomically(tempPath, targetPath);
	}

	async get(sessionId: string): Promise<RuntimeSessionRecord | null> {
		const targetPath = this.filePath(sessionId);
		try {
			const text = await Bun.file(targetPath).text();
			let record = JSON.parse(text) as RuntimeSessionRecord;
			record = sanitizeRuntimeSessionRecord(record);
			const staleCheck = computeSessionStaleState(record);
			if (
				staleCheck.isStale &&
				record.status !== "stale" &&
				record.status !== "closed" &&
				record.status !== "failed"
			) {
				record.status = "stale";
				record.status_source = "stale_timeout";
			}
			return record;
		} catch (error) {
			if (isEnoent(error)) return null;
			throw error;
		}
	}

	async delete(sessionId: string): Promise<boolean> {
		const targetPath = this.filePath(sessionId);
		try {
			await fs.unlink(targetPath);
			return true;
		} catch (error) {
			if (isEnoent(error)) return false;
			throw error;
		}
	}

	async list(filter: SessionListFilter = {}): Promise<RuntimeSessionRecord[]> {
		await this.ensureDir();
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: RuntimeSessionRecord[] = [];

			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				try {
					const text = await Bun.file(path.join(this.projectDirectory, entry.name)).text();
					let record = JSON.parse(text) as RuntimeSessionRecord;
					record = sanitizeRuntimeSessionRecord(record);
					const staleCheck = computeSessionStaleState(record);
					if (
						staleCheck.isStale &&
						record.status !== "stale" &&
						record.status !== "closed" &&
						record.status !== "failed"
					) {
						record.status = "stale";
						record.status_source = "stale_timeout";
					}

					// Apply filters
					if (filter.kind && record.kind !== filter.kind) continue;
					if (filter.status && record.status !== filter.status) continue;
					if (filter.workflow_id && record.workflow_id !== filter.workflow_id) continue;

					records.push(record);
				} catch {
					// Skip damaged records
				}
			}

			// Sort newest updated_at first
			records.sort((a, b) => b.updated_at.localeCompare(a.updated_at));

			const limit = Math.min(filter.limit ?? DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT);
			return records.slice(0, limit);
		} catch (error) {
			if (isEnoent(error)) return [];
			throw error;
		}
	}
}
