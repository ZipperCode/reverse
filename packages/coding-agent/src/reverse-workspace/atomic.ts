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

export interface SafeResolvedPath {
	resolvedPath: string;
	realPath: string;
	relativePath: string;
}

export interface AssertRealPathOptions {
	baseDir?: string;
	requireRegularFile?: boolean;
}

function isWithinRoot(rootPath: string, candidatePath: string): boolean {
	const rel = path.relative(rootPath, candidatePath);
	return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

async function resolveRealTargetWithExistingAncestor(
	resolvedBase: string,
	realBase: string,
	targetPath: string,
): Promise<{ realTarget: string; deepestExisting: string }> {
	const rel = path.relative(resolvedBase, targetPath);
	const segments = rel ? rel.split(path.sep).filter(Boolean) : [];
	let current = resolvedBase;
	let deepestExisting = resolvedBase;

	for (const seg of segments) {
		current = path.join(current, seg);
		try {
			const st = await fs.lstat(current);
			if (st.isSymbolicLink()) {
				let realCurrent: string;
				try {
					realCurrent = await fs.realpath(current);
				} catch {
					throw new Error(`Symlink escape violation: broken or unresolvable symlink at '${current}'`);
				}
				if (!isWithinRoot(realBase, realCurrent)) {
					throw new Error(
						`Symlink escape violation: '${current}' resolves to '${realCurrent}' outside '${realBase}'`,
					);
				}
			}
			deepestExisting = current;
		} catch (error) {
			if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
				break;
			}
			throw error;
		}
	}

	const realDeepest = await fs.realpath(deepestExisting);
	if (!isWithinRoot(realBase, realDeepest)) {
		throw new Error(
			`Symlink escape violation: '${deepestExisting}' resolves to '${realDeepest}' outside '${realBase}'`,
		);
	}

	const remaining = path.relative(deepestExisting, targetPath);
	const realTarget = remaining ? path.join(realDeepest, remaining) : realDeepest;
	return { realTarget, deepestExisting };
}

/**
 * 校验目标路径在允许根目录内（同时检查词法路径、已存在父目录与 realpath，拒绝 .. 与 symlink 越界）。
 */
export async function assertRealPathWithin(
	allowedRootDir: string,
	targetPath: string,
	options: AssertRealPathOptions = {},
): Promise<SafeResolvedPath> {
	if (!targetPath || typeof targetPath !== "string" || targetPath.trim().length === 0 || targetPath.includes("\0")) {
		throw new Error(`Invalid path: '${targetPath}'`);
	}

	const rawSegments = targetPath.split(/[\\/]+/);
	if (rawSegments.includes("..")) {
		throw new Error(`Path traversal violation: '${targetPath}' contains '..' segment`);
	}

	const baseDir = options.baseDir ?? allowedRootDir;
	const resolvedBase = path.resolve(baseDir);
	const baseStat = await fs.stat(resolvedBase);
	if (!baseStat.isDirectory()) {
		throw new Error(`Base directory is not a directory: '${resolvedBase}'`);
	}
	const realBase = await fs.realpath(resolvedBase);

	let resolvedAllowed: string;
	const absAllowed = path.resolve(resolvedBase, allowedRootDir);
	if (isWithinRoot(resolvedBase, absAllowed)) {
		resolvedAllowed = absAllowed;
	} else if (isWithinRoot(realBase, absAllowed)) {
		resolvedAllowed = path.resolve(resolvedBase, path.relative(realBase, absAllowed));
	} else {
		throw new Error(`Allowed root '${allowedRootDir}' escapes base directory '${resolvedBase}'`);
	}

	const { realTarget: realAllowed } = await resolveRealTargetWithExistingAncestor(
		resolvedBase,
		realBase,
		resolvedAllowed,
	);

	let relFromBase: string;
	if (path.isAbsolute(targetPath)) {
		const normAbs = path.resolve(targetPath);
		if (isWithinRoot(resolvedBase, normAbs)) {
			relFromBase = path.relative(resolvedBase, normAbs);
		} else if (isWithinRoot(realBase, normAbs)) {
			relFromBase = path.relative(realBase, normAbs);
		} else {
			throw new Error(`Path traversal violation: '${targetPath}' escapes root directory '${baseDir}'`);
		}
	} else {
		const resolvedFromBase = assertWithinPath(resolvedBase, targetPath);
		relFromBase = path.relative(resolvedBase, resolvedFromBase);
	}

	const resolvedTarget = path.resolve(resolvedBase, relFromBase);
	if (!isWithinRoot(resolvedAllowed, resolvedTarget)) {
		throw new Error(`Path traversal violation: '${targetPath}' escapes allowed directory '${allowedRootDir}'`);
	}

	const { realTarget, deepestExisting } = await resolveRealTargetWithExistingAncestor(
		resolvedBase,
		realBase,
		resolvedTarget,
	);

	if (!isWithinRoot(realAllowed, realTarget)) {
		throw new Error(
			`Symlink escape violation: '${targetPath}' resolves to '${realTarget}' outside allowed directory '${realAllowed}'`,
		);
	}

	// 若路径位于 allowedRoot 内，进一步逐级检查 allowedRoot 下的符号链接是否越界
	const relTargetFromAllowed = path.relative(resolvedAllowed, resolvedTarget);
	const allowedSegments = relTargetFromAllowed ? relTargetFromAllowed.split(path.sep).filter(Boolean) : [];
	let curAllowed = resolvedAllowed;
	for (const seg of allowedSegments) {
		curAllowed = path.join(curAllowed, seg);
		try {
			const st = await fs.lstat(curAllowed);
			if (st.isSymbolicLink()) {
				const realCur = await fs.realpath(curAllowed);
				if (!isWithinRoot(realAllowed, realCur)) {
					throw new Error(
						`Symlink escape violation: '${curAllowed}' resolves to '${realCur}' outside allowed directory '${realAllowed}'`,
					);
				}
			}
		} catch (error) {
			if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
				break;
			}
			throw error;
		}
	}

	if (options.requireRegularFile) {
		if (deepestExisting !== resolvedTarget) {
			throw new Error(`File does not exist: '${targetPath}'`);
		}
		const stat = await fs.stat(resolvedTarget);
		if (!stat.isFile()) {
			throw new Error(`Path is not a regular file: '${targetPath}'`);
		}
	}

	return {
		resolvedPath: resolvedTarget,
		realPath: realTarget,
		relativePath: relFromBase.split(path.sep).join("/"),
	};
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
