/**
 * Session-scoped artifact storage for truncated tool outputs.
 *
 * Artifacts are stored in a directory alongside the session file,
 * accessible via artifact:// URLs.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { replaceFileAtomically } from "../utils/atomic-file";

/**
 * Sanitize a tool name for safe use as the middle segment of the artifact
 * filename (`${id}.${toolType}.log`). Built-in tool names are fixed, but MCP,
 * extension, and RPC-host tool names are arbitrary and may contain path
 * separators (`/`, `\`) or traversal sequences (`..`) that would otherwise let
 * a spilled artifact escape the artifacts directory. Collapse everything
 * outside `[A-Za-z0-9_-]` to `_`, and cap the length so an arbitrarily long
 * name cannot overflow the filesystem's filename limit (ENAMETOOLONG). Fall
 * back to `tool` when nothing survives.
 */
function sanitizeToolType(toolType: string): string {
	const sanitized = toolType
		.replace(/[^A-Za-z0-9_-]+/g, "_")
		.slice(0, 64)
		.replace(/^_+|_+$/g, "");
	return sanitized.length > 0 ? sanitized : "tool";
}

// 语义分析产物与原始恢复快照不计入流式日志累计预算，避免截断或拒写逆向分析结论。
const SEMANTIC_ARTIFACT_TOOL_TYPES: Record<string, true> = {
	shake: true,
	deobfuscate_msynth: true,
	deobfuscate_d810: true,
	"elf-query": true,
	native_recover: true,
	triton_analyze: true,
	ida: true,
	"bash-original": true,
};

/**
 * Persist an artifact only when the filesystem confirms the complete payload is
 * readable, then swap it into place atomically.
 *
 * Content is staged to a temporary sibling and verified (byte count, on-disk
 * size, readability) before an atomic `rename` publishes it. `agent://<id>`
 * discovers `${id}.md` by scanning the artifacts directory rather than reading
 * `result.outputPath`, so a direct in-place write that fell short would leave a
 * truncated file resolvable as incomplete output and a failed follow-up write
 * would destroy the prior valid artifact. Staging keeps both hazards out: on
 * any failure the temp file is removed and the existing artifact at `path` is
 * untouched.
 *
 * Returns the verified UTF-8 byte count.
 */
export async function writeArtifact(path: string, content: string): Promise<number> {
	const expectedBytes = Buffer.byteLength(content);
	const tempPath = `${path}.tmp-${crypto.randomUUID()}`;
	try {
		const writtenBytes = await Bun.write(tempPath, content);
		if (writtenBytes !== expectedBytes) {
			throw new Error(`Artifact write incomplete: wrote ${writtenBytes} of ${expectedBytes} bytes`);
		}
		const file = Bun.file(tempPath);
		if (file.size !== expectedBytes) {
			throw new Error(`Artifact size mismatch: found ${file.size} of ${expectedBytes} bytes`);
		}
		await file.slice(0, Math.min(expectedBytes, 1)).arrayBuffer();
		await replaceFileAtomically(tempPath, path);
	} catch (error) {
		await fs.rm(tempPath, { force: true });
		throw error;
	}
	return expectedBytes;
}

/**
 * Manages artifact storage for a session.
 *
 * Artifacts are stored with sequential IDs in the session's artifact directory.
 * The directory is created lazily on first write.
 *
 * Subagents do not own their own `ArtifactManager`. The parent's instance is
 * adopted via `SessionManager.adoptArtifactManager`, so the whole parent +
 * subagent tree shares one ID space and one directory.
 */
export class ArtifactManager {
	#nextId = 0;
	readonly #dir: string;
	#dirCreated = false;
	#initPromise: Promise<void> | null = null;
	readonly #ready: Promise<void> | undefined;
	readonly #reservedIdsDir: string | undefined;
	readonly #capturedFileBytes = new Map<string, number>();
	readonly #reservedCaptureBytes = new Map<string, number>();
	/**
	 * @param dir Directory that will hold artifact files. Created lazily on first save.
	 * @param ready Settles once `dir` is seeded (a session move copying the previous
	 *   session's artifacts in the background). Id scans and lookups wait for it,
	 *   so new ids never collide with copied ones. Must not reject.
	 * @param reservedIdsDir Read-only directory whose ids stay reserved: a seance
	 *   fork allocates past its source's ids so `artifact://<n>` from the inherited
	 *   transcript keeps naming the source artifact.
	 */
	constructor(dir: string, ready?: Promise<void>, reservedIdsDir?: string) {
		this.#dir = dir;
		this.#ready = ready;
		this.#reservedIdsDir = reservedIdsDir;
	}

	/**
	 * Artifact directory path.
	 * Directory may not exist until first artifact is saved.
	 */
	get dir(): string {
		return this.#dir;
	}

	async #ensureDir(): Promise<void> {
		await this.#ready;
		if (!this.#dirCreated) {
			await fs.mkdir(this.#dir, { recursive: true });
			this.#dirCreated = true;
		}
		// Memoize the first-use scan so it runs exactly once. Concurrent callers
		// share the in-flight promise instead of each re-seeding #nextId across
		// the readdir yield in #scanExistingIds (which would hand duplicate ids).
		this.#initPromise ??= this.#scanExistingIds();
		await this.#initPromise;
	}

	/**
	 * Scan existing artifact files to find the next available ID.
	 * This ensures we don't overwrite artifacts when resuming a session.
	 */
	async #scanExistingIds(): Promise<void> {
		const dirFiles = await this.listFiles();
		const allFiles = [...dirFiles];
		if (this.#reservedIdsDir) {
			try {
				allFiles.push(...(await fs.readdir(this.#reservedIdsDir)));
			} catch {
				// A missing source artifacts dir reserves nothing.
			}
		}
		let maxId = -1;
		for (const file of allFiles) {
			// Files are named: {id}.{toolType}.log
			const match = file.match(/^(\d+)\.([A-Za-z0-9_-]+)\.log$/);
			if (match) {
				const id = parseInt(match[1], 10);
				if (id > maxId) maxId = id;
			}
		}
		for (const file of dirFiles) {
			const match = file.match(/^(\d+)\.([A-Za-z0-9_-]+)\.log$/);
			if (!match || SEMANTIC_ARTIFACT_TOOL_TYPES[match[2]]) continue;
			const fullPath = path.resolve(this.#dir, file);
			if (this.#capturedFileBytes.has(fullPath)) continue;
			const size = Bun.file(fullPath).size;
			if (Number.isFinite(size) && size > 0) {
				this.#capturedFileBytes.set(fullPath, size);
			}
		}
		this.#nextId = maxId + 1;
	}

	/** Ensure the artifact directory and existing capture-log accounting are initialized. */
	async ensureInitialized(): Promise<void> {
		await this.#ensureDir();
	}

	/** Total bytes persisted or reserved for tool capture logs in this session. */
	getCapturedLogBytes(): number {
		let total = 0;
		for (const bytes of this.#capturedFileBytes.values()) total += bytes;
		for (const bytes of this.#reservedCaptureBytes.values()) total += bytes;
		return total;
	}

	/** Remaining session capture-log byte budget, or `undefined` when `sessionMaxBytes <= 0` (unbounded). */
	getRemainingCaptureBudgetBytes(sessionMaxBytes: number): number | undefined {
		if (sessionMaxBytes <= 0) return undefined;
		return Math.max(0, sessionMaxBytes - this.getCapturedLogBytes());
	}

	/** True when a positive session capture-log budget is configured and already exhausted. */
	isCaptureBudgetExhausted(sessionMaxBytes: number): boolean {
		return sessionMaxBytes > 0 && this.getCapturedLogBytes() >= sessionMaxBytes;
	}

	/** Reserve in-flight capture bytes for a streaming sink before its final size is known. */
	reserveCaptureBytes(filePath: string, bytes: number): void {
		const key = path.resolve(filePath);
		if (bytes > 0) {
			this.#reservedCaptureBytes.set(key, Math.max(0, bytes));
		} else {
			this.#reservedCaptureBytes.delete(key);
		}
	}

	/** Release an in-flight reservation and record the final on-disk byte size for `filePath`. */
	recordCapturedArtifact(filePath: string, bytes: number): void {
		const key = path.resolve(filePath);
		this.#reservedCaptureBytes.delete(key);
		if (bytes > 0) {
			this.#capturedFileBytes.set(key, bytes);
		} else {
			this.#capturedFileBytes.delete(key);
		}
	}
	/** Record captured bytes for a persisted `{id}.{toolType}.log` artifact id. */
	recordCapturedById(id: string, toolType: string, bytes: number): void {
		const filename = `${id}.${sanitizeToolType(toolType)}.log`;
		this.recordCapturedArtifact(path.join(this.#dir, filename), bytes);
	}

	/** Record captured bytes (keyed by `filePath` when provided to prevent double-counting). */
	recordCapturedBytes(bytes: number, filePath?: string): void {
		if (filePath) {
			this.recordCapturedArtifact(filePath, bytes);
			return;
		}
		if (bytes > 0) {
			this.#capturedFileBytes.set(`__capture_${this.#nextId}_${this.#capturedFileBytes.size}`, bytes);
		}
	}
	/**
	 * Atomically allocate next artifact ID.
	 * IDs are sequential within the session.
	 */
	allocateId(): number {
		return this.#nextId++;
	}

	/**
	 * Allocate a new artifact path and ID without writing content.
	 *
	 * @param toolType Tool name for file extension (e.g., "bash", "read")
	 */
	async allocatePath(toolType: string): Promise<{ id: string; path: string }> {
		await this.#ensureDir();
		const id = String(this.allocateId());
		const filename = `${id}.${sanitizeToolType(toolType)}.log`;
		return { id, path: path.join(this.#dir, filename) };
	}

	/**
	 * Save content as an artifact and return the artifact ID.
	 *
	 * @param content Full content to save
	 * @param toolType Tool name for file extension (e.g., "bash", "read")
	 * @returns Artifact ID (numeric string)
	 */
	async save(content: string, toolType: string): Promise<string> {
		const { id, path: artifactPath } = await this.allocatePath(toolType);
		await writeArtifact(artifactPath, content);
		return id;
	}

	/**
	 * Check if an artifact exists.
	 * @param id Artifact ID (numeric string)
	 */
	async exists(id: string): Promise<boolean> {
		const files = await this.listFiles();
		return files.some(f => f.startsWith(`${id}.`));
	}

	/**
	 * List all artifact files in the directory.
	 * Returns empty array if directory doesn't exist.
	 */
	async listFiles(): Promise<string[]> {
		await this.#ready;
		try {
			return await fs.readdir(this.#dir);
		} catch {
			return [];
		}
	}

	/**
	 * Get the full path to an artifact file.
	 * Returns null if artifact doesn't exist.
	 *
	 * @param id Artifact ID (numeric string)
	 */
	async getPath(id: string): Promise<string | null> {
		const files = await this.listFiles();
		const match = files.find(f => f.startsWith(`${id}.`));
		return match ? path.join(this.#dir, match) : null;
	}
}
