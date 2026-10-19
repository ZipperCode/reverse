import * as fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { redactEvidenceText } from "../evidence/contracts";

/**
 * Atomically writes data to a target file path by writing to a sibling
 * temporary file first and renaming it to the destination.
 */
export async function atomicWriteFile(filePath: string, data: string | Buffer): Promise<void> {
	const dir = path.dirname(filePath);
	await fs.mkdir(dir, { recursive: true });

	const tempSuffix = `.tmp.${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
	const tempPath = `${filePath}${tempSuffix}`;

	try {
		await fs.writeFile(tempPath, data);
		await fs.rename(tempPath, filePath);
	} catch (error) {
		try {
			await fs.unlink(tempPath);
		} catch {
			// ignore cleanup error
		}
		throw error;
	}
}

/**
 * Ensures a target path does not escape the parent directory (prevents path traversal).
 */
export function assertWithinPath(parentDir: string, targetPath: string): string {
	const resolvedParent = path.resolve(parentDir);
	const resolvedTarget = path.resolve(parentDir, targetPath);

	if (resolvedTarget !== resolvedParent && !resolvedTarget.startsWith(`${resolvedParent}${path.sep}`)) {
		throw new Error(`Path traversal violation: '${targetPath}' escapes root directory '${parentDir}'`);
	}

	return resolvedTarget;
}

/**
 * Computes sha256 and byte size of a Buffer.
 */
export function hashBuffer(buf: Buffer): { sha256: string; size: number } {
	const sha256 = createHash("sha256").update(buf).digest("hex");
	return { sha256, size: buf.byteLength };
}

/**
 * Computes sha256 and byte size of a UTF-8 string.
 */
export function hashString(str: string): { sha256: string; size: number } {
	const buf = Buffer.from(str, "utf8");
	return hashBuffer(buf);
}

/**
 * Computes sha256 and byte size of a file on disk, or returns null if file not accessible.
 */
export async function hashFile(filePath: string): Promise<{ sha256: string; size: number } | null> {
	try {
		const stat = await fs.stat(filePath);
		if (!stat.isFile()) return null;

		// For moderate sizes, reading is faster than stream setup
		if (stat.size <= 32 * 1024 * 1024) {
			const buf = await fs.readFile(filePath);
			return hashBuffer(buf);
		}

		const { promise, resolve, reject } = Promise.withResolvers<{ sha256: string; size: number }>();
		const hash = createHash("sha256");
		const stream = createReadStream(filePath);
		stream.on("data", chunk => hash.update(chunk));
		stream.on("end", () => resolve({ sha256: hash.digest("hex"), size: stat.size }));
		stream.on("error", err => reject(err));
		return promise;
	} catch {
		return null;
	}
}

/**
 * Redacts secrets, tokens, and credentials from text content.
 */
export function redactSecrets(input: string): string {
	if (!input) return input;
	return redactEvidenceText(input);
}

/**
 * Produces deterministic JSON with sorted keys for reproducible diffs.
 */
export function deterministicJsonStringify(obj: unknown, space = 2): string {
	return JSON.stringify(sortKeysRecursively(obj), null, space) ?? "";
}

function sortKeysRecursively(val: unknown): unknown {
	if (val === null || typeof val !== "object") return val;

	if (Array.isArray(val)) {
		return val.map(sortKeysRecursively);
	}

	const entries = Object.entries(val as Record<string, unknown>);
	entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

	const sortedObj: Record<string, unknown> = {};
	for (const [k, v] of entries) {
		if (v !== undefined) {
			sortedObj[k] = sortKeysRecursively(v);
		}
	}
	return sortedObj;
}
