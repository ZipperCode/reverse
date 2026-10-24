/**
 * Cross-runtime deep inspection and analysis tool for mobile and native applications.
 *
 * Provides bounded single-action adapters composing established upstream tools:
 * - action: "inventory" - offline static detection of Flutter (AOT), React Native / Hermes,
 *   Unity IL2CPP, and generic native shared libraries from APK, AAB, directory, or direct files.
 * - action: "hermes" - disassembles Hermes bytecode (.hbc / index.android.bundle) via
 *   detected hbctool (HBC 59, 62, 74, 76 only) or hermes-dec (hbc-disassembler for HBC 61–96).
 *   Distinguishes plain RN JS text from binary HBC and reports explicit version compatibility.
 * - action: "il2cpp" - extracts and dumps Unity IL2CPP binary (libil2cpp.so) + global-metadata.dat
 *   via Il2CppDumper. Validates metadata sanity (0xFAB11BAF), generates C# dump.cs, C++ headers,
 *   stages private RequireAnyKey=false config to prevent interactive hangs or thrown Console.ReadKey exceptions,
 *   and exports Ghidra/IDA scripts with direct handoff to ghidra_inspect.
 * - action: "flutter" - inspects Flutter Android Dart AOT snapshots (libapp.so + libflutter.so)
 *   via Blutter for ARM64 (arm64-v8a). Extracts Dart VM snapshot hashes, strictly enforces
 *   upstream boundaries (arm64 only, exact prebuilt Dart VM executable directly invoked to prevent
 *   unapproved background checkout/compilation of Dart SDK).
 *
 * Upstream references:
 * - hbctool: https://github.com/bongtrop/hbctool
 * - hermes-dec: https://github.com/P1sec/hermes-dec
 * - Il2CppDumper: https://github.com/Perfare/Il2CppDumper
 * - Blutter: https://github.com/worawit/blutter
 */

import * as child_process from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as fsSync from "node:fs";
import * as path from "node:path";
import type { Stats } from "node:fs";
import * as zlib from "node:zlib";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt, $which } from "@reverse/utils";
import runtimeAnalyzeDescription from "../prompts/tools/runtime-analyze.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import { ZipParser, type ZipEntry } from "./android-package-inspect";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import { checkToolRequirements, type SkillRequirementWhich } from "../extensibility/skill-requirements";

// ============================================================================
// Parameter Schema
// ============================================================================

export const runtimeAnalyzeSchema = type({
	action: type
		.enumerated("inventory", "hermes", "il2cpp", "flutter")
		.describe(
			"Runtime analysis action: inventory (detect Flutter, React Native/Hermes, Unity IL2CPP across APK, AAB, or directory), hermes (disassemble Hermes bytecode with hbctool/hermes-dec), il2cpp (extract Unity IL2CPP with Il2CppDumper and export Ghidra/IDA scripts), or flutter (disassemble Flutter Android arm64 AOT snapshot libapp.so with Blutter)",
		),
	path: type("string").describe(
		"Path to target file (APK, AAB, directory, .bundle, .hbc, libapp.so, libil2cpp.so, or global-metadata.dat)",
	),
	"target?": type("string").describe("Alias for path"),
	"metadata_path?": type("string").describe(
		"Optional path to Unity global-metadata.dat (for il2cpp action if not adjacent to binary)",
	),
	"engine_path?": type("string").describe(
		"Optional path to Flutter libflutter.so (for flutter action if not adjacent to libapp.so)",
	),
	"output_dir?": type("string").describe(
		"Optional destination directory for analysis artifacts (default ./artifacts/runtime_analyze/<runtime>/...)",
	),
	"format?": type.enumerated("markdown", "json").describe("Output format: markdown (default) or json"),
	"limit?": type("number").describe("Maximum items returned in lists (default 50, max 200)"),
	"offset?": type("number").describe("Zero-based pagination offset (default 0)"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 60, max 300)"),
	"max_bytes?": type("number").describe("Maximum output bytes captured (default 262144, max 4194304)"),
});

export type RuntimeAnalyzeParams = typeof runtimeAnalyzeSchema.infer;
export type RuntimeAnalyzeAction = RuntimeAnalyzeParams["action"];

// ============================================================================
// Constants & Magic Signatures
// ============================================================================

/** Hermes 字节码 Magic: 0x1F1903C103BC1FC6 (UTF-16BE 希腊语 "Hermes" 截断 8 字节) */
export const HERMES_MAGIC_BYTES = Buffer.from([0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f]);

/** Unity global-metadata.dat 校验魔数: 0xFAB11BAF (小端字节序: AF 1B B1 FA) */
export const UNITY_METADATA_MAGIC = 0xfab11baf;

/** ELF 机器架构标识 */
export const ELF_MACHINE_AARCH64 = 183; // 0xb7 (arm64-v8a)
export const ELF_MACHINE_ARM = 40; // 0x28 (armeabi-v7a)
export const ELF_MACHINE_X86_64 = 62; // 0x3e (x86_64)
export const ELF_MACHINE_386 = 3; // 0x03 (x86)

/** hbctool 官方严格支持的 Hermes 字节码版本集合 (README: HBC59, 62, 74, 76 only) */
export const HBCTOOL_SUPPORTED_VERSIONS: Record<number, true> = {
	59: true,
	62: true,
	74: true,
	76: true,
};

/** 单个文件/条目读取上限 (防 Zip 炸弹与过大内存分配) */
const MAX_READ_FILE_BYTES = 128 * 1024 * 1024; // 128 MiB
const MAX_ZIP_ENTRY_UNCOMPRESSED = 64 * 1024 * 1024; // 64 MiB
const MAX_AGGREGATE_DECOMPRESSED_BYTES = 128 * 1024 * 1024; // 128 MiB aggregate limit per scan
const MAX_INVENTORY_CANDIDATE_ENTRIES = 20; // 单次 inventory 最多解压候选条目数
const MAX_DIRECTORY_SCAN_FILES = 2000; // 目录扫描文件数上限
const MAX_OUTPUT_QUOTA_BYTES = 256 * 1024 * 1024; // 256 MiB 磁盘生成物上限

// ============================================================================
// Data Contracts & Output Interfaces
// ============================================================================

export type RuntimeType = "flutter" | "react_native" | "unity_il2cpp" | "native_generic" | "unknown";

export interface TargetArtifactHashes {
	sha256: string;
	size: number;
}

export interface DetectedRuntimeInfo {
	runtime: RuntimeType;
	frameworkName: string;
	confidence: "confirmed" | "probable" | "candidate";
	indicators: string[];
	version?: string;
	snapshotHash?: string;
	architecture?: string;
	recommendedAction?: "hermes" | "il2cpp" | "flutter" | "native_inspect";
}

export interface InventoryResult {
	targetPath: string;
	targetType: "apk" | "directory" | "binary" | "bundle" | "archive";
	hashes: TargetArtifactHashes;
	runtimes: DetectedRuntimeInfo[];
	summary: string;
}

export interface MissingDependencyStatus {
	id: string;
	tool: string;
	category: string;
	manualUrl: string;
	installHint: string;
	prerequisites?: string[];
	targetDiagnostics: Record<string, unknown>;
}

export interface RuntimeAnalyzeDetails {
	action: RuntimeAnalyzeAction;
	targetPath: string;
	status: "ok" | "missing_dependency" | "unsupported" | "error" | "backend_build_required";
	runtime?: RuntimeType;
	hashes?: TargetArtifactHashes;
	secondaryHashes?: TargetArtifactHashes;
	inventory?: InventoryResult;
	missingDependency?: MissingDependencyStatus;
	unsupportedReason?: string;
	outputDir?: string;
	artifactFiles?: string[];
	handoff?: {
		engine: "ghidra" | "ida" | "frida" | "static";
		suggestedCommands: string[];
		scriptPath?: string;
	};
	metrics?: {
		typesCount?: number;
		instructionsCount?: number;
	};
	error?: string;
	executionTimeMs?: number;
}

export interface RuntimeAnalyzeRunResult {
	stdout: string;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
}

export type RuntimeAnalyzeRunner = (
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
		stdin?: string | Uint8Array;
		monitorDir?: string;
		maxOutputBytes?: number;
	},
) => Promise<RuntimeAnalyzeRunResult>;

export interface RuntimeAnalyzeToolOptions {
	which?: SkillRequirementWhich;
	runner?: RuntimeAnalyzeRunner;
}

// ============================================================================
// Process Execution & Stream Helpers
// ============================================================================

export async function defaultRuntimeAnalyzeRunner(
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
		stdin?: string | Uint8Array;
		monitorDir?: string;
		maxOutputBytes?: number;
	},
): Promise<RuntimeAnalyzeRunResult> {
	if (options.signal?.aborted) {
		throw new ToolError("Execution aborted before process spawn");
	}

	const isWindows = process.platform === "win32";
	const child = child_process.spawn(binary, args, {
		cwd: options.cwd,
		stdio: ["pipe", "pipe", "pipe"],
		detached: !isWindows,
	});

	if (options.stdin !== undefined && child.stdin) {
		child.stdin.end(typeof options.stdin === "string" ? Buffer.from(options.stdin) : options.stdin);
	} else if (child.stdin) {
		child.stdin.end();
	}

	let timedOut = false;
	let diskQuotaExceeded = false;
	let escalationTimer: NodeJS.Timeout | undefined;

	const terminateProcessTree = () => {
		if (child.pid === undefined) return;
		try {
			if (isWindows) {
				child_process.spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" });
			} else {
				process.kill(-child.pid, "SIGTERM");
				escalationTimer = setTimeout(() => {
					try {
						if (child.pid) process.kill(-child.pid, "SIGKILL");
					} catch {}
				}, 1000);
			}
		} catch {
			try {
				child.kill("SIGKILL");
			} catch {}
		}
	};

	const timer = setTimeout(() => {
		timedOut = true;
		terminateProcessTree();
	}, options.timeoutMs);

	const onAbort = () => {
		terminateProcessTree();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });

	const calculateDirBytes = async (dir: string): Promise<number> => {
		let total = 0;
		try {
			const entries = await fs.readdir(dir, { withFileTypes: true });
			for (const e of entries) {
				if (e.name === ".dumper" || e.name === "inputs") continue;
				const full = path.join(dir, e.name);
				if (e.isDirectory()) {
					total += await calculateDirBytes(full);
				} else if (e.isFile()) {
					const st = await fs.stat(full);
					total += st.size;
				}
			}
		} catch {}
		return total;
	};

	let monitorTimer: NodeJS.Timeout | undefined;
	if (options.monitorDir) {
		const monDir = options.monitorDir;
		const maxDiskQuota = options.maxOutputBytes ?? MAX_OUTPUT_QUOTA_BYTES;
		monitorTimer = setInterval(async () => {
			if (fsSync.existsSync(monDir)) {
				const bytes = await calculateDirBytes(monDir);
				if (bytes > maxDiskQuota) {
					diskQuotaExceeded = true;
					terminateProcessTree();
				}
			}
		}, 250);
	}

	const readNodeStream = (
		stream: NodeJS.ReadableStream | null,
		cap: number,
		onCap?: () => void,
	): Promise<{ text: string; bytes: number; truncated: boolean }> => {
		const { promise, resolve } = Promise.withResolvers<{ text: string; bytes: number; truncated: boolean }>();
		if (!stream) {
			resolve({ text: "", bytes: 0, truncated: false });
			return promise;
		}
		const chunks: Buffer[] = [];
		let bytes = 0;
		let truncated = false;

		stream.on("data", (chunk: Buffer) => {
			if (truncated) return;
			const remaining = cap - bytes;
			if (chunk.length >= remaining) {
				if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
				bytes += Math.max(0, remaining);
				truncated = true;
				onCap?.();
				return;
			}
			chunks.push(chunk);
			bytes += chunk.length;
		});

		stream.on("end", () => {
			resolve({
				text: Buffer.concat(chunks).toString("utf8"),
				bytes,
				truncated,
			});
		});

		stream.on("error", () => {
			resolve({
				text: Buffer.concat(chunks).toString("utf8"),
				bytes,
				truncated,
			});
		});

		return promise;
	};

	const { promise: exitCodePromise, resolve: resolveExitCode } = Promise.withResolvers<number>();
	child.on("close", code => resolveExitCode(code ?? -1));
	child.on("error", () => resolveExitCode(-1));

	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			readNodeStream(child.stdout, options.maxBytes, () => terminateProcessTree()),
			readNodeStream(child.stderr, 32 * 1024),
			exitCodePromise,
		]);

		if (options.monitorDir && fsSync.existsSync(options.monitorDir)) {
			const finalBytes = await calculateDirBytes(options.monitorDir);
			if (finalBytes > (options.maxOutputBytes ?? MAX_OUTPUT_QUOTA_BYTES)) {
				diskQuotaExceeded = true;
			}
		}

		if (diskQuotaExceeded) {
			throw new ToolError(
				`Disassembly output exceeded disk quota limit (${options.maxOutputBytes ?? MAX_OUTPUT_QUOTA_BYTES} bytes) in ${options.monitorDir}`,
			);
		}

		return {
			stdout: stdout.text,
			stderr: stderr.text,
			exitCode,
			outputBytes: stdout.bytes,
			truncated: stdout.truncated,
			timedOut,
		};
	} finally {
		clearTimeout(timer);
		clearTimeout(escalationTimer);
		clearInterval(monitorTimer);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

// ============================================================================
// Inspection Helpers & Safe Path / Output Management
// ============================================================================

/** 计算文件的 SHA-256 哈希及大小 */
export function computeHashes(buf: Buffer): TargetArtifactHashes {
	return {
		sha256: crypto.createHash("sha256").update(buf).digest("hex"),
		size: buf.length,
	};
}

/** 校验输入目标与输出目录互不重叠，支持符号链接真实路径解析，防止意外覆盖或自包含循环 */
async function assertNoPathOverlap(targetPath: string, outDir: string): Promise<void> {
	let realTarget = path.resolve(targetPath);
	try {
		realTarget = await fs.realpath(realTarget);
	} catch {}

	let realOut = path.resolve(outDir);
	try {
		realOut = await fs.realpath(realOut);
	} catch {
		let cur = path.dirname(realOut);
		while (cur !== path.dirname(cur)) {
			try {
				const realCur = await fs.realpath(cur);
				realOut = path.join(realCur, path.relative(cur, realOut));
				break;
			} catch {
				cur = path.dirname(cur);
			}
		}
	}

	const relInToOut = path.relative(realTarget, realOut);
	const relOutToIn = path.relative(realOut, realTarget);
	if (relInToOut === "" || !relInToOut.startsWith("..") || relOutToIn === "" || !relOutToIn.startsWith("..")) {
		throw new ToolError(
			`Output directory (${realOut}) overlaps with target input path (${realTarget}). Choose a separate output destination.`,
		);
	}
}

/** 独占式原子创建输出目录：采用 mkdtemp 原子保证唯一，绝不静默覆盖已有文件 */
async function createExclusiveOutputDir(baseOutDir: string): Promise<string> {
	await fs.mkdir(path.dirname(baseOutDir), { recursive: true });
	return await fs.mkdtemp(`${baseOutDir}_`);
}

/** 安全有界限读取常规文件内容，防范特殊设备文件 (/dev/zero, FIFO, pipe) 与超大文件 */
async function safeReadFileBounded(filePath: string, signal?: AbortSignal): Promise<Buffer> {
	throwIfAborted(signal);
	const st = await fs.stat(filePath);
	if (!st.isFile()) {
		throw new ToolError(`Target is not a regular file: ${filePath}`);
	}
	if (st.size > MAX_READ_FILE_BYTES) {
		throw new ToolError(
			`Target file exceeds safety size limit: ${st.size} bytes > ${MAX_READ_FILE_BYTES} bytes (${filePath})`,
		);
	}
	const handle = await fs.open(filePath, "r");
	try {
		const buf = Buffer.alloc(st.size);
		let totalRead = 0;
		while (totalRead < st.size) {
			throwIfAborted(signal);
			const chunk = Math.min(64 * 1024, st.size - totalRead);
			const { bytesRead } = await handle.read(buf, totalRead, chunk, totalRead);
			if (bytesRead === 0) break;
			totalRead += bytesRead;
			if (totalRead > MAX_READ_FILE_BYTES) {
				throw new ToolError(`Read exceeded maximum allowed bytes: ${MAX_READ_FILE_BYTES}`);
			}
		}
		return buf.subarray(0, totalRead);
	} finally {
		await handle.close().catch(() => {});
	}
}

/** 安全解压单个 ZIP 条目 (采用 zlib maxOutputLength 硬限制，杜绝伪造 uncompressedSize 的 zip-bomb) */
function safeReadZipEntry(zipBuffer: Buffer, entry: ZipEntry, maxOutputBytes = MAX_ZIP_ENTRY_UNCOMPRESSED): Buffer {
	if (entry.localHeaderOffset + 30 > zipBuffer.length) {
		throw new ToolError(`Invalid archive: local header offset exceeds buffer length for ${entry.name}`);
	}
	const sig = zipBuffer.readUInt32LE(entry.localHeaderOffset);
	if (sig !== 0x04034b50) {
		throw new ToolError(`Invalid archive: local file header signature mismatch for ${entry.name}`);
	}
	const nameLen = zipBuffer.readUInt16LE(entry.localHeaderOffset + 26);
	const extraLen = zipBuffer.readUInt16LE(entry.localHeaderOffset + 28);
	const dataStart = entry.localHeaderOffset + 30 + nameLen + extraLen;
	const dataEnd = dataStart + entry.compressedSize;
	if (dataEnd > zipBuffer.length) {
		throw new ToolError(`Invalid archive: compressed data exceeds file boundary for ${entry.name}`);
	}
	const rawData = zipBuffer.subarray(dataStart, dataEnd);

	if (entry.compressionMethod === 0) {
		if (rawData.length > maxOutputBytes) {
			throw new ToolError(
				`Archive entry ${entry.name} exceeds decompression limit: ${rawData.length} bytes > ${maxOutputBytes} bytes`,
			);
		}
		return Buffer.from(rawData);
	}

	if (entry.compressionMethod === 8) {
		try {
			return zlib.inflateRawSync(rawData, { maxOutputLength: maxOutputBytes });
		} catch (err) {
			throw new ToolError(
				`Archive entry ${entry.name} decompression failed (limit ${maxOutputBytes} bytes): ${(err as Error).message}`,
			);
		}
	}

	throw new ToolError(`Unsupported compression method ${entry.compressionMethod} for ${entry.name}`);
}

/** 检查 Buffer 是否匹配 Hermes Bytecode 魔数 */
export function isHermesBytecode(buf: Buffer): boolean {
	if (buf.length < 8) return false;
	for (let i = 0; i < 8; i++) {
		if (buf[i] !== HERMES_MAGIC_BYTES[i]) return false;
	}
	return true;
}

/** 解析 Hermes Bytecode 头信息 */
export function parseHermesHeader(buf: Buffer): {
	isHbc: boolean;
	version?: number;
	sourceHash?: string;
	fileLength?: number;
} {
	if (!isHermesBytecode(buf)) {
		return { isHbc: false };
	}
	const version = buf.length >= 12 ? buf.readUInt32LE(8) : undefined;
	const sourceHash = buf.length >= 32 ? buf.subarray(12, 32).toString("hex") : undefined;
	const fileLength = buf.length >= 36 ? buf.readUInt32LE(32) : undefined;
	return { isHbc: true, version, sourceHash, fileLength };
}

/** 检查是否为纯文本 JavaScript Bundle (非 Hermes 字节码) */
export function isPlainJavaScriptBundle(buf: Buffer): boolean {
	if (isHermesBytecode(buf)) return false;
	const checkLen = Math.min(buf.length, 4096);
	if (checkLen === 0) return false;

	let nullCount = 0;
	for (let i = 0; i < checkLen; i++) {
		if (buf[i] === 0) nullCount++;
	}
	if (nullCount > 2) return false;

	const sample = buf.subarray(0, checkLen).toString("utf8");
	return (
		sample.includes("__d(") ||
		sample.includes("var ") ||
		sample.includes("function(") ||
		sample.includes("use strict") ||
		sample.includes("require(")
	);
}

/** 检查并解析 Unity global-metadata.dat 文件头 */
export function parseUnityMetadataHeader(buf: Buffer): {
	isValid: boolean;
	sanity?: number;
	version?: number;
} {
	if (buf.length < 8) return { isValid: false };
	const sanity = buf.readUInt32LE(0);
	if (sanity !== UNITY_METADATA_MAGIC) {
		return { isValid: false, sanity };
	}
	const version = buf.readInt32LE(4);
	return { isValid: true, sanity, version };
}

/** 从 ELF 符号表及数据段提取 Dart Snapshot Hash 与 flags */
export function extractDartSnapshotInfo(buf: Buffer): {
	snapshotHash?: string;
	flags?: string[];
	hasCompressedPointers?: boolean;
} {
	if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
		return {};
	}
	const is64 = buf[4] === 2;
	if (is64 && buf.length < 64) {
		return {};
	}
	const isLe = buf[5] === 1;
	const shOff = is64
		? isLe
			? Number(buf.readBigUInt64LE(40))
			: Number(buf.readBigUInt64BE(40))
		: isLe
			? buf.readUInt32LE(32)
			: buf.readUInt32BE(32);
	const shEntSize = isLe ? buf.readUInt16LE(is64 ? 58 : 46) : buf.readUInt16BE(is64 ? 58 : 46);
	const shNum = isLe ? buf.readUInt16LE(is64 ? 60 : 48) : buf.readUInt16BE(is64 ? 60 : 48);

	if (shOff > 0 && shNum > 0 && shEntSize >= 16 && shOff + shNum * shEntSize <= buf.length) {
		interface SectionHeader {
			type: number;
			offset: number;
			size: number;
			link: number;
			entSize: number;
		}
		const sections: SectionHeader[] = [];
		for (let i = 0; i < shNum; i++) {
			const entryOff = shOff + i * shEntSize;
			if (entryOff + (is64 ? 64 : 40) > buf.length) break;
			const type = isLe ? buf.readUInt32LE(entryOff + 4) : buf.readUInt32BE(entryOff + 4);
			const offset = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 24))
					: Number(buf.readBigUInt64BE(entryOff + 24))
				: isLe
					? buf.readUInt32LE(entryOff + 16)
					: buf.readUInt32BE(entryOff + 16);
			const size = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 32))
					: Number(buf.readBigUInt64BE(entryOff + 32))
				: isLe
					? buf.readUInt32LE(entryOff + 20)
					: buf.readUInt32BE(entryOff + 20);
			const link = isLe
				? buf.readUInt32LE(entryOff + (is64 ? 40 : 24))
				: buf.readUInt32BE(entryOff + (is64 ? 40 : 24));
			const entSize = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 56))
					: Number(buf.readBigUInt64BE(entryOff + 56))
				: isLe
					? buf.readUInt32LE(entryOff + 36)
					: buf.readUInt32BE(entryOff + 36);
			sections.push({ type, offset, size, link, entSize });
		}

		for (const sec of sections) {
			if (sec.type === 11 || sec.type === 2) {
				if (sec.offset + sec.size > buf.length) continue;
				if (sec.link >= sections.length) continue;
				const strSec = sections[sec.link];
				if (!strSec || strSec.offset + strSec.size > buf.length) continue;
				const minSymEntSize = is64 ? 24 : 16;
				const symEntSize = sec.entSize >= minSymEntSize ? sec.entSize : minSymEntSize;
				if (symEntSize <= 0) continue;
				const count = Math.min(Math.floor(sec.size / symEntSize), 5000);
				for (let i = 0; i < count; i++) {
					const symOff = sec.offset + i * symEntSize;
					if (symOff + symEntSize > buf.length) break;
					const nameOff = isLe ? buf.readUInt32LE(symOff) : buf.readUInt32BE(symOff);
					const namePos = strSec.offset + nameOff;
					if (namePos >= buf.length || namePos >= strSec.offset + strSec.size) continue;
					const nullIdx = buf.indexOf(0, namePos);
					if (nullIdx === -1 || nullIdx > strSec.offset + strSec.size) continue;
					const symName = buf.toString("utf8", namePos, nullIdx);
					if (symName === "_kDartVmSnapshotData") {
						const symValue = is64
							? isLe
								? Number(buf.readBigUInt64LE(symOff + 8))
								: Number(buf.readBigUInt64BE(symOff + 8))
							: isLe
								? buf.readUInt32LE(symOff + 4)
								: buf.readUInt32BE(symOff + 4);
						if (symValue + 52 <= buf.length) {
							const hash = buf.toString("ascii", symValue + 20, symValue + 52);
							if (/^[0-9a-fA-F]{32}$/.test(hash)) {
								const flagsEnd = buf.indexOf(0, symValue + 52);
								if (flagsEnd !== -1 && flagsEnd <= Math.min(buf.length, symValue + 512)) {
									const flagsStr = buf.toString("ascii", symValue + 52, flagsEnd).trim();
									const flags = flagsStr.length > 0 ? flagsStr.split(/\s+/) : [];
									const hasCompressedPointers =
										flags.includes("compressed-pointers") && !flags.includes("no-compressed-pointers");
									return { snapshotHash: hash, flags, hasCompressedPointers };
								}
								return { snapshotHash: hash };
							}
						}
					}
				}
			}
		}
	}

	// 内存紧随模式提取: 32字节ASCII hash紧随空格分隔的NUL结尾flags
	const match = buf.toString("latin1").match(/([0-9a-f]{32})([a-z0-9 _-]{5,128})\0/);
	if (match) {
		const hash = match[1]!;
		const flagsStr = match[2]!.trim();
		const flags = flagsStr.split(/\s+/);
		if (
			flags.includes("compressed-pointers") ||
			flags.includes("no-compressed-pointers") ||
			flags.includes("product")
		) {
			const hasCompressedPointers =
				flags.includes("compressed-pointers") && !flags.includes("no-compressed-pointers");
			return { snapshotHash: hash, flags, hasCompressedPointers };
		}
	}
	return {};
}

export interface ElfCharacteristics {
	isElf: boolean;
	machine?: number;
	architecture?: string;
	isDartAot?: boolean;
	isFlutterEngine?: boolean;
	isIl2Cpp?: boolean;
	dartSnapshotHash?: string;
	dartVersion?: string;
	hasCompressedPointers?: boolean;
}

/** 简要解析 ELF 二进制机器架构与 Dart/Unity 符号标识 */
export function parseElfCharacteristics(buf: Buffer): ElfCharacteristics {
	if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
		return { isElf: false };
	}
	const isLe = buf[5] === 1;
	const machine = isLe ? buf.readUInt16LE(18) : buf.readUInt16BE(18);

	let architecture = "unknown";
	if (machine === ELF_MACHINE_AARCH64) architecture = "arm64-v8a";
	else if (machine === ELF_MACHINE_ARM) architecture = "armeabi-v7a";
	else if (machine === ELF_MACHINE_X86_64) architecture = "x86_64";
	else if (machine === ELF_MACHINE_386) architecture = "x86";

	const contentStr = buf.toString("latin1");
	const isDartAot =
		contentStr.includes("_kDartVmSnapshotData") ||
		contentStr.includes("_kDartVmSnapshotInstructions") ||
		contentStr.includes("_kDartIsolateSnapshotInstructions");

	const isFlutterEngine =
		contentStr.includes("FlutterEngine") ||
		contentStr.includes("io.flutter") ||
		contentStr.includes("Dart_Initialize");

	const isIl2Cpp =
		contentStr.includes("il2cpp_init") ||
		contentStr.includes("il2cpp_runtime_invoke") ||
		contentStr.includes("Il2CppCodeGen");

	const snapInfo = isDartAot ? extractDartSnapshotInfo(buf) : {};
	const dartSnapshotHash = snapInfo.snapshotHash;
	const hasCompressedPointers = snapInfo.hasCompressedPointers;

	let dartVersion: string | undefined;
	// 真实 libflutter.so rodata 中的 Dart SDK 版本串通常带渠道标识，例如 "\03.2.0 (stable)" 或 "\03.2.0\0"
	const verMatch =
		contentStr.match(/(?:\x00|\s)([23]\.\d+\.\d+(?:\+hotfix\.\d+)?)\s*\((?:stable|beta|dev|main)/) ||
		contentStr.match(/\0([23]\.\d+\.\d+(?:\+hotfix\.\d+)?)\0/);
	if (verMatch) {
		dartVersion = verMatch[1];
	}

	return {
		isElf: true,
		machine,
		architecture,
		isDartAot,
		isFlutterEngine,
		isIl2Cpp,
		dartSnapshotHash,
		dartVersion,
		hasCompressedPointers,
	};
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class RuntimeAnalyzeTool implements AgentTool<typeof runtimeAnalyzeSchema, RuntimeAnalyzeDetails> {
	readonly name = "runtime_analyze";

	/** 权限分级：只读静态 inventory 采用 read；外部工具调度采用 exec */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args && typeof args.action === "string") {
			if (args.action === "inventory") {
				return "read";
			}
		}
		return "exec";
	};

	readonly label = "Runtime Analyze";
	readonly summary =
		"Cross-runtime deep inspection and analysis for Flutter (AOT), React Native/Hermes, and Unity IL2CPP applications.";
	readonly description: string;
	readonly parameters = runtimeAnalyzeSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly runner: RuntimeAnalyzeRunner;
	private readonly which: SkillRequirementWhich;

	constructor(
		private readonly session: ToolSession,
		private readonly options: RuntimeAnalyzeToolOptions = {},
	) {
		this.description = prompt.render(runtimeAnalyzeDescription);
		this.runner = options.runner ?? defaultRuntimeAnalyzeRunner;
		this.which = options.which ?? ((cmd, opts) => $which(cmd, opts));
	}

	/** 准确解析 Hermes 工具：绝不把 hbctool 误判为 hermes-dec，且仅认准 hbc-disassembler 入口 */
	private resolveHermesTools(): {
		hbctoolPath: string | null;
		hermesDecPath: string | null;
		hbctoolInstallHint: string;
		hermesDecInstallHint: string;
	} {
		let hbctoolPath: string | null = null;
		const [hbcReq] = checkToolRequirements([{ id: "hbctool" }], { which: this.which });
		if (hbcReq?.foundPath && path.basename(hbcReq.foundPath).toLowerCase().startsWith("hbctool")) {
			hbctoolPath = hbcReq.foundPath;
		} else {
			const direct = this.which("hbctool");
			if (direct && path.basename(direct).toLowerCase().startsWith("hbctool")) {
				hbctoolPath = direct;
			}
		}

		let hermesDecPath: string | null = null;
		for (const alt of ["hbc-disassembler", "hermes-dec.hbc-disassembler", "hermes-dec"]) {
			const direct = this.which(alt);
			if (direct && !path.basename(direct).toLowerCase().startsWith("hbctool")) {
				hermesDecPath = direct;
				break;
			}
		}
		if (!hermesDecPath) {
			const [decReq] = checkToolRequirements([{ id: "hermes-dec" }], { which: this.which });
			if (decReq?.foundPath && !path.basename(decReq.foundPath).toLowerCase().startsWith("hbctool")) {
				hermesDecPath = decReq.foundPath;
			}
		}

		const platform: SkillToolPlatform =
			process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
		const hbctoolInstallHint =
			hbcReq?.hint ?? SKILL_TOOL_CATALOG.hbctool?.installHints?.[platform]?.join(" or ") ?? "pipx install hbctool";
		const hermesDecInstallHint =
			SKILL_TOOL_CATALOG["hermes-dec"]?.installHints?.[platform]?.join(" or ") ?? "pip install hermes-dec";

		return {
			hbctoolPath,
			hermesDecPath,
			hbctoolInstallHint,
			hermesDecInstallHint,
		};
	}

	/** 统一解析 Catalog 工具：支持探测 managed-tools 目录与 PATH */
	private resolveCatalogTool(
		id: string,
		alternateBinaries: string[] = [],
	): { available: boolean; path: string | null; installHint?: string; manualUrl?: string } {
		const [reqStatus] = checkToolRequirements([{ id }], { which: this.which });
		if (reqStatus?.foundPath) {
			return {
				available: true,
				path: reqStatus.foundPath,
				installHint: reqStatus.hint,
				manualUrl: SKILL_TOOL_CATALOG[id]?.manualUrl,
			};
		}
		for (const alt of alternateBinaries) {
			const found = this.which(alt);
			if (found) {
				return {
					available: true,
					path: found,
					installHint: reqStatus?.hint,
					manualUrl: SKILL_TOOL_CATALOG[id]?.manualUrl,
				};
			}
		}
		const platform: SkillToolPlatform =
			process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
		const catalogHint = SKILL_TOOL_CATALOG[id]?.installHints?.[platform]?.join(" or ");
		return {
			available: false,
			path: null,
			installHint: reqStatus?.hint ?? catalogHint,
			manualUrl: SKILL_TOOL_CATALOG[id]?.manualUrl,
		};
	}

	async execute(
		_toolCallId: string,
		rawParams: RuntimeAnalyzeParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<RuntimeAnalyzeDetails> & { details: RuntimeAnalyzeDetails }> {
		throwIfAborted(signal);

		const params: RuntimeAnalyzeParams = {
			...rawParams,
			limit: Math.max(1, Math.min(rawParams.limit ?? 50, 200)),
			offset: Math.max(0, rawParams.offset ?? 0),
			timeout: Math.max(1, Math.min(rawParams.timeout ?? (rawParams.action === "flutter" ? 120 : 60), 300)),
			max_bytes: Math.max(1024, Math.min(rawParams.max_bytes ?? 262144, 4 * 1024 * 1024)),
		};

		const targetInput = params.path || params.target;
		if (!targetInput) {
			throw new ToolError("Missing required parameter 'path'");
		}

		const resolvedPath = resolveReadPath(targetInput, this.session.cwd);

		let targetStat: Stats;
		try {
			targetStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(`Target path does not exist: ${resolvedPath} (${(err as Error).message})`);
		}
		if (params.output_dir) {
			const requestedOut = resolveReadPath(params.output_dir, this.session.cwd);
			await assertNoPathOverlap(resolvedPath, requestedOut);
			if (params.metadata_path) {
				const metaP = resolveReadPath(params.metadata_path, this.session.cwd);
				await assertNoPathOverlap(metaP, requestedOut);
			}
			if (params.engine_path) {
				const engineP = resolveReadPath(params.engine_path, this.session.cwd);
				await assertNoPathOverlap(engineP, requestedOut);
			}
		}

		const action = params.action;
		const startTime = Date.now();
		let details: RuntimeAnalyzeDetails;

		switch (action) {
			case "inventory":
				details = await this.executeInventory(resolvedPath, targetStat, params, signal);
				break;
			case "hermes":
				details = await this.executeHermes(resolvedPath, targetStat, params, signal);
				break;
			case "il2cpp":
				details = await this.executeIl2Cpp(resolvedPath, targetStat, params, signal);
				break;
			case "flutter":
				details = await this.executeFlutter(resolvedPath, targetStat, params, signal);
				break;
			default:
				throw new ToolError(`Unsupported action: ${String(action)}`);
		}

		details.executionTimeMs = Date.now() - startTime;
		const text = this.formatResult(details, params.format ?? "markdown");

		return {
			content: [{ type: "text", text }],
			details,
		};
	}

	// ========================================================================
	// Action: Inventory
	// ========================================================================

	private async executeInventory(
		targetPath: string,
		stat: Stats,
		params: RuntimeAnalyzeParams,
		signal?: AbortSignal,
	): Promise<RuntimeAnalyzeDetails> {
		throwIfAborted(signal);
		const runtimes: DetectedRuntimeInfo[] = [];

		if (stat.isDirectory()) {
			await this.scanDirectoryForRuntimes(targetPath, runtimes, signal);
			return {
				action: "inventory",
				targetPath,
				status: "ok",
				inventory: {
					targetPath,
					targetType: "directory",
					hashes: { sha256: "directory", size: 0 },
					runtimes,
					summary: this.summarizeInventory(runtimes),
				},
			};
		}

		const fileBuffer = await safeReadFileBounded(targetPath, signal);
		const hashes = computeHashes(fileBuffer);

		let isZip = false;
		try {
			const zip = new ZipParser(fileBuffer);
			isZip = true;
			this.scanZipForRuntimes(fileBuffer, zip, runtimes, signal);
		} catch {
			isZip = false;
		}

		if (!isZip) {
			this.inspectSingleFileBuffer(targetPath, fileBuffer, runtimes);
		}

		return {
			action: "inventory",
			targetPath,
			status: "ok",
			hashes,
			inventory: {
				targetPath,
				targetType: isZip ? "apk" : "binary",
				hashes,
				runtimes,
				summary: this.summarizeInventory(runtimes),
			},
		};
	}

	private scanZipForRuntimes(
		zipBuffer: Buffer,
		zip: ZipParser,
		runtimes: DetectedRuntimeInfo[],
		signal?: AbortSignal,
	): void {
		let hasReactNativeBundle = false;
		let hasHermesLib = false;
		let hasFlutterApp = false;
		let hasFlutterEngine = false;
		let hasIl2CppLib = false;
		let hasIl2CppMeta = false;
		let hbcVersion: number | undefined;
		let isPlainJs = false;
		let metadataVersion: number | undefined;
		let flutterArch: string | undefined;
		let dartSnapshotHash: string | undefined;

		let aggregateDecompressedBytes = 0;
		let candidateEntriesExamined = 0;

		const readZipEntryBudgeted = (entry: ZipEntry): Buffer | null => {
			throwIfAborted(signal);
			if (
				candidateEntriesExamined >= MAX_INVENTORY_CANDIDATE_ENTRIES ||
				aggregateDecompressedBytes >= MAX_AGGREGATE_DECOMPRESSED_BYTES
			) {
				return null;
			}
			candidateEntriesExamined++;
			const remainingBudget = Math.max(0, MAX_AGGREGATE_DECOMPRESSED_BYTES - aggregateDecompressedBytes);
			if (remainingBudget <= 0) return null;
			const maxCap = Math.min(remainingBudget, MAX_ZIP_ENTRY_UNCOMPRESSED);

			try {
				const data = safeReadZipEntry(zipBuffer, entry, maxCap);
				aggregateDecompressedBytes += data.length;
				return data;
			} catch {
				aggregateDecompressedBytes += maxCap;
				return null;
			}
		};

		// 结构化匹配 APK 与 AAB 条目 (支持 base/lib/<abi>/ 及常规 lib/<abi>/，同 module+ABI 配对)
		const appEntriesByModuleAbi = new Map<string, ZipEntry>();
		const flutterEntriesByModuleAbi = new Map<string, ZipEntry>();
		const il2cppEntriesByModuleAbi = new Map<string, ZipEntry>();

		for (const entry of zip.entries) {
			throwIfAborted(signal);
			const name = entry.name;
			if (
				name === "assets/index.android.bundle" ||
				name === "base/assets/index.android.bundle" ||
				name.endsWith(".bundle") ||
				name.endsWith(".hbc")
			) {
				hasReactNativeBundle = true;
				const data = readZipEntryBudgeted(entry);
				if (data) {
					if (isHermesBytecode(data)) {
						hbcVersion = parseHermesHeader(data).version;
					} else if (isPlainJavaScriptBundle(data)) {
						isPlainJs = true;
					}
				}
			}
			if (name.includes("libhermes.so") || name.includes("libreactnativejni.so")) {
				hasHermesLib = true;
			}
			const m = name.match(/^(?:([a-zA-Z0-9_-]+)\/)?lib\/([^/]+)\/(libapp\.so|libflutter\.so|libil2cpp\.so)$/);
			if (m) {
				const mod = m[1] ?? "root";
				const abi = m[2]!;
				const lib = m[3]!;
				const key = `${mod}/${abi}`;
				if (lib === "libapp.so") appEntriesByModuleAbi.set(key, entry);
				else if (lib === "libflutter.so") flutterEntriesByModuleAbi.set(key, entry);
				else if (lib === "libil2cpp.so") il2cppEntriesByModuleAbi.set(key, entry);
			}
			if (name.endsWith("global-metadata.dat")) {
				hasIl2CppMeta = true;
				const data = readZipEntryBudgeted(entry);
				if (data) {
					const meta = parseUnityMetadataHeader(data);
					if (meta.isValid) metadataVersion = meta.version;
				}
			}
		}

		if (hasReactNativeBundle || hasHermesLib) {
			const indicators = [
				hasReactNativeBundle ? "Bundle asset present" : "",
				hasHermesLib ? "libhermes/libreactnativejni present" : "",
				hbcVersion !== undefined ? `Hermes Bytecode v${hbcVersion}` : isPlainJs ? "Plain JS bundle" : "",
			].filter(Boolean);

			runtimes.push({
				runtime: "react_native",
				frameworkName: `React Native (${hbcVersion !== undefined ? `Hermes HBC v${hbcVersion}` : isPlainJs ? "Plain JS" : "Bundle"})`,
				confidence: "confirmed",
				indicators,
				version: hbcVersion !== undefined ? `v${hbcVersion}` : isPlainJs ? "Plain JS" : undefined,
				recommendedAction: "hermes",
			});
		}

		// 必须在同一 module 中优先配对 arm64-v8a 架构
		let selectedFlutterKey: string | null = null;
		for (const key of appEntriesByModuleAbi.keys()) {
			if (key.endsWith("/arm64-v8a") && flutterEntriesByModuleAbi.has(key)) {
				selectedFlutterKey = key;
				break;
			}
		}
		if (!selectedFlutterKey) {
			for (const key of appEntriesByModuleAbi.keys()) {
				if (flutterEntriesByModuleAbi.has(key)) {
					selectedFlutterKey = key;
					break;
				}
			}
		}
		if (!selectedFlutterKey) {
			for (const key of appEntriesByModuleAbi.keys()) {
				selectedFlutterKey = key;
				break;
			}
		}
		if (!selectedFlutterKey) {
			for (const key of flutterEntriesByModuleAbi.keys()) {
				selectedFlutterKey = key;
				break;
			}
		}

		if (selectedFlutterKey) {
			const appEntry = appEntriesByModuleAbi.get(selectedFlutterKey);
			const flutterEntry = flutterEntriesByModuleAbi.get(selectedFlutterKey);
			if (appEntry) {
				hasFlutterApp = true;
				const data = readZipEntryBudgeted(appEntry);
				if (data) {
					const elf = parseElfCharacteristics(data);
					flutterArch = elf.architecture;
					if (elf.dartSnapshotHash) dartSnapshotHash = elf.dartSnapshotHash;
				}
			}
			if (flutterEntry) {
				hasFlutterEngine = true;
				const data = readZipEntryBudgeted(flutterEntry);
				if (data) {
					const elf = parseElfCharacteristics(data);
					if (elf.dartSnapshotHash) dartSnapshotHash = elf.dartSnapshotHash;
				}
			}
		}

		if (hasFlutterApp || hasFlutterEngine) {
			const indicators = [
				hasFlutterApp ? "libapp.so Dart AOT snapshot present" : "",
				hasFlutterEngine ? "libflutter.so Flutter engine present" : "",
				flutterArch ? `Architecture: ${flutterArch}` : "",
				dartSnapshotHash ? `Snapshot Hash: ${dartSnapshotHash}` : "",
			].filter(Boolean);

			runtimes.push({
				runtime: "flutter",
				frameworkName: "Flutter (Dart AOT)",
				confidence: "confirmed",
				indicators,
				architecture: flutterArch,
				snapshotHash: dartSnapshotHash,
				recommendedAction: "flutter",
			});
		}

		let selectedIl2CppKey: string | null = null;
		for (const key of il2cppEntriesByModuleAbi.keys()) {
			if (key.endsWith("/arm64-v8a")) {
				selectedIl2CppKey = key;
				break;
			}
		}
		if (!selectedIl2CppKey && il2cppEntriesByModuleAbi.size > 0) {
			selectedIl2CppKey = Array.from(il2cppEntriesByModuleAbi.keys())[0]!;
		}
		if (selectedIl2CppKey || zip.entries.some(e => e.name.endsWith("GameAssembly.dll"))) {
			hasIl2CppLib = true;
		}

		if (hasIl2CppLib || hasIl2CppMeta) {
			const indicators = [
				hasIl2CppLib ? "libil2cpp.so binary present" : "",
				hasIl2CppMeta ? "global-metadata.dat present" : "",
				metadataVersion !== undefined ? `IL2CPP Metadata v${metadataVersion}` : "",
			].filter(Boolean);

			runtimes.push({
				runtime: "unity_il2cpp",
				frameworkName: `Unity (IL2CPP${metadataVersion !== undefined ? ` v${metadataVersion}` : ""})`,
				confidence: hasIl2CppLib && hasIl2CppMeta ? "confirmed" : "probable",
				indicators,
				version: metadataVersion !== undefined ? `v${metadataVersion}` : undefined,
				recommendedAction: "il2cpp",
			});
		}
	}

	private async scanDirectoryForRuntimes(
		dirPath: string,
		runtimes: DetectedRuntimeInfo[],
		signal?: AbortSignal,
	): Promise<void> {
		const files: string[] = [];
		const walk = async (current: string, depth = 0) => {
			throwIfAborted(signal);
			if (depth > 4 || files.length >= MAX_DIRECTORY_SCAN_FILES) return;
			let entries: fsSync.Dirent[];
			try {
				entries = await fs.readdir(current, { withFileTypes: true });
			} catch {
				return;
			}
			for (const e of entries) {
				if (files.length >= MAX_DIRECTORY_SCAN_FILES) return;
				const full = path.join(current, e.name);
				if (e.isDirectory()) {
					await walk(full, depth + 1);
				} else if (e.isFile()) {
					files.push(full);
				}
			}
		};
		await walk(dirPath);

		const bundleFile = files.find(f => path.basename(f) === "index.android.bundle" || f.endsWith(".hbc"));
		if (bundleFile) {
			try {
				const buf = await safeReadFileBounded(bundleFile, signal);
				const hbc = parseHermesHeader(buf);
				if (hbc.isHbc) {
					runtimes.push({
						runtime: "react_native",
						frameworkName: `React Native (Hermes HBC v${hbc.version ?? "unknown"})`,
						confidence: "confirmed",
						indicators: [`Found Hermes bytecode: ${path.basename(bundleFile)}`],
						version: hbc.version !== undefined ? `v${hbc.version}` : undefined,
						recommendedAction: "hermes",
					});
				} else if (isPlainJavaScriptBundle(buf)) {
					runtimes.push({
						runtime: "react_native",
						frameworkName: "React Native (Plain JS)",
						confidence: "confirmed",
						indicators: [`Found Plain JS bundle: ${path.basename(bundleFile)}`],
						recommendedAction: "hermes",
					});
				}
			} catch {}
		}

		const appSo = files.find(f => path.basename(f) === "libapp.so");
		const flutterSo = files.find(f => path.basename(f) === "libflutter.so");
		if (appSo || flutterSo) {
			let arch = "unknown";
			let hash: string | undefined;
			if (appSo) {
				try {
					const buf = await safeReadFileBounded(appSo, signal);
					const elf = parseElfCharacteristics(buf);
					arch = elf.architecture ?? "unknown";
					hash = elf.dartSnapshotHash;
				} catch {}
			}
			runtimes.push({
				runtime: "flutter",
				frameworkName: "Flutter (Dart AOT)",
				confidence: "confirmed",
				indicators: [appSo ? `libapp.so (${arch})` : "", flutterSo ? "libflutter.so" : ""].filter(Boolean),
				architecture: arch,
				snapshotHash: hash,
				recommendedAction: "flutter",
			});
		}

		const il2cppSo = files.find(f => path.basename(f) === "libil2cpp.so" || path.basename(f) === "GameAssembly.dll");
		const metadataDat = files.find(f => path.basename(f) === "global-metadata.dat");
		if (il2cppSo || metadataDat) {
			let metaVer: number | undefined;
			if (metadataDat) {
				try {
					const buf = await safeReadFileBounded(metadataDat, signal);
					const meta = parseUnityMetadataHeader(buf);
					if (meta.isValid) metaVer = meta.version;
				} catch {}
			}
			runtimes.push({
				runtime: "unity_il2cpp",
				frameworkName: `Unity (IL2CPP${metaVer !== undefined ? ` v${metaVer}` : ""})`,
				confidence: il2cppSo && metadataDat ? "confirmed" : "probable",
				indicators: [
					il2cppSo ? "libil2cpp binary" : "",
					metadataDat ? `global-metadata.dat (v${metaVer ?? "?"})` : "",
				].filter(Boolean),
				version: metaVer !== undefined ? `v${metaVer}` : undefined,
				recommendedAction: "il2cpp",
			});
		}
	}

	private inspectSingleFileBuffer(targetPath: string, buf: Buffer, runtimes: DetectedRuntimeInfo[]): void {
		const hbc = parseHermesHeader(buf);
		if (hbc.isHbc) {
			runtimes.push({
				runtime: "react_native",
				frameworkName: `React Native (Hermes HBC v${hbc.version ?? "unknown"})`,
				confidence: "confirmed",
				indicators: [`Hermes magic verified`, `Bytecode version: v${hbc.version ?? "unknown"}`],
				version: hbc.version !== undefined ? `v${hbc.version}` : undefined,
				recommendedAction: "hermes",
			});
			return;
		}

		if (isPlainJavaScriptBundle(buf)) {
			runtimes.push({
				runtime: "react_native",
				frameworkName: "React Native (Plain JS)",
				confidence: "probable",
				indicators: ["Plain JavaScript bundle signatures (Metro packager)"],
				recommendedAction: "hermes",
			});
			return;
		}

		const meta = parseUnityMetadataHeader(buf);
		if (meta.isValid) {
			runtimes.push({
				runtime: "unity_il2cpp",
				frameworkName: `Unity IL2CPP Global Metadata (v${meta.version})`,
				confidence: "confirmed",
				indicators: [`Unity metadata sanity 0xFAB11BAF verified`, `Version: v${meta.version}`],
				version: `v${meta.version}`,
				recommendedAction: "il2cpp",
			});
			return;
		}

		const elf = parseElfCharacteristics(buf);
		if (elf.isElf) {
			if (elf.isDartAot) {
				runtimes.push({
					runtime: "flutter",
					frameworkName: "Flutter Dart AOT Snapshot (libapp.so)",
					confidence: "confirmed",
					indicators: [`ELF machine: ${elf.architecture}`, "Dart snapshot exports verified"],
					architecture: elf.architecture,
					snapshotHash: elf.dartSnapshotHash,
					recommendedAction: "flutter",
				});
			} else if (elf.isFlutterEngine) {
				runtimes.push({
					runtime: "flutter",
					frameworkName: "Flutter Runtime Engine (libflutter.so)",
					confidence: "confirmed",
					indicators: [`ELF machine: ${elf.architecture}`, "Flutter Engine symbols verified"],
					architecture: elf.architecture,
					snapshotHash: elf.dartSnapshotHash,
					recommendedAction: "flutter",
				});
			} else if (elf.isIl2Cpp) {
				runtimes.push({
					runtime: "unity_il2cpp",
					frameworkName: "Unity IL2CPP Native Shared Library",
					confidence: "confirmed",
					indicators: [`ELF machine: ${elf.architecture}`, "IL2CPP VM exports verified"],
					recommendedAction: "il2cpp",
				});
			} else {
				runtimes.push({
					runtime: "native_generic",
					frameworkName: `Generic Native Shared Library (${elf.architecture})`,
					confidence: "confirmed",
					indicators: [`Valid ELF shared object, architecture: ${elf.architecture}`],
					recommendedAction: "native_inspect",
				});
			}
		}
	}

	private summarizeInventory(runtimes: DetectedRuntimeInfo[]): string {
		if (runtimes.length === 0) {
			return "No recognized mobile cross-platform runtimes (Flutter, React Native/Hermes, Unity IL2CPP) detected.";
		}
		return `Detected ${runtimes.length} cross-platform runtime(s): ${runtimes.map(r => r.frameworkName).join(", ")}.`;
	}

	// ========================================================================
	// Action: Hermes (React Native)
	// ========================================================================

	private async executeHermes(
		targetPath: string,
		stat: Stats,
		params: RuntimeAnalyzeParams,
		signal?: AbortSignal,
	): Promise<RuntimeAnalyzeDetails> {
		throwIfAborted(signal);

		let bundleBuffer: Buffer | null = null;
		let effectiveBundlePath = targetPath;

		if (stat.isDirectory()) {
			const candidates = [
				path.join(targetPath, "index.android.bundle"),
				path.join(targetPath, "assets", "index.android.bundle"),
				path.join(targetPath, "base", "assets", "index.android.bundle"),
				path.join(targetPath, "bundle.hbc"),
				path.join(targetPath, "app.hbc"),
			];
			const foundCandidate = candidates.find(c => fsSync.existsSync(c));
			if (foundCandidate) {
				bundleBuffer = await safeReadFileBounded(foundCandidate, signal);
				effectiveBundlePath = foundCandidate;
			} else {
				return {
					action: "hermes",
					targetPath,
					status: "error",
					error: `Directory does not contain Hermes bundle (checked index.android.bundle, assets/index.android.bundle, *.hbc): ${targetPath}`,
				};
			}
		} else {
			const rawBuf = await safeReadFileBounded(targetPath, signal);
			try {
				const zip = new ZipParser(rawBuf);
				const bundleEntry = zip.entries.find(
					e =>
						e.name === "assets/index.android.bundle" ||
						e.name === "base/assets/index.android.bundle" ||
						e.name.endsWith(".bundle") ||
						e.name.endsWith(".hbc"),
				);
				if (bundleEntry) {
					bundleBuffer = safeReadZipEntry(rawBuf, bundleEntry);
					effectiveBundlePath = `${targetPath}!/${bundleEntry.name}`;
				}
			} catch {
				bundleBuffer = rawBuf;
			}
		}

		if (!bundleBuffer) {
			return {
				action: "hermes",
				targetPath,
				status: "error",
				error: "Failed to read target bundle data.",
			};
		}

		const hashes = computeHashes(bundleBuffer);

		// 1. 严格区分 Plain JS 与二进制 Hermes HBC
		if (!isHermesBytecode(bundleBuffer)) {
			const isPlain = isPlainJavaScriptBundle(bundleBuffer);
			return {
				action: "hermes",
				targetPath: effectiveBundlePath,
				status: "unsupported",
				runtime: "react_native",
				hashes,
				unsupportedReason: isPlain
					? "Target is a plain React Native JavaScript bundle (not binary Hermes Bytecode). hbctool and hermes-dec operate exclusively on compiled Hermes bytecode (.hbc). For plain JS bundles, use sourcemap_inspect for source maps or ast_grep for AST analysis."
					: "Target file does not match Hermes Bytecode magic (0x1F1903C103BC1FC6) or valid JS bundle.",
			};
		}

		// 2. 解析 HBC 字节码头与版本兼容性
		const hbc = parseHermesHeader(bundleBuffer);
		const bytecodeVer = hbc.version ?? 0;
		const isHbctoolCompatible = HBCTOOL_SUPPORTED_VERSIONS[bytecodeVer] === true;
		const isHermesDecCompatible = bytecodeVer >= 61 && bytecodeVer <= 96;

		// 3. 区分工具方言，绝不把 hbctool 误当 hermes-dec 派发
		const { hbctoolPath, hermesDecPath, hbctoolInstallHint, hermesDecInstallHint } = this.resolveHermesTools();

		// 若版本超出双方支持范围，直接报错
		if (!isHbctoolCompatible && !isHermesDecCompatible) {
			return {
				action: "hermes",
				targetPath: effectiveBundlePath,
				status: "unsupported",
				runtime: "react_native",
				hashes,
				unsupportedReason: `Target Hermes Bytecode version is v${bytecodeVer}, which is outside the supported range of both hbctool (HBC 59, 62, 74, 76) and hermes-dec (HBC 61–96).`,
			};
		}

		// 判定工具适用性与调度，绝不允许 HBC 59 派发给 hermes-dec 或高版本派发给 hbctool
		let chosenDialect: "hbctool" | "hermes-dec";
		let chosenExecutable: string | null = null;

		if (isHbctoolCompatible && isHermesDecCompatible) {
			if (hbctoolPath) {
				chosenDialect = "hbctool";
				chosenExecutable = hbctoolPath;
			} else if (hermesDecPath) {
				chosenDialect = "hermes-dec";
				chosenExecutable = hermesDecPath;
			} else {
				chosenDialect = "hbctool";
			}
		} else if (isHbctoolCompatible) {
			chosenDialect = "hbctool";
			chosenExecutable = hbctoolPath;
			if (!hbctoolPath && hermesDecPath) {
				return {
					action: "hermes",
					targetPath: effectiveBundlePath,
					status: "unsupported",
					runtime: "react_native",
					hashes,
					unsupportedReason: `Target Hermes Bytecode version is v${bytecodeVer}, which is supported only by hbctool (hermes-dec supports HBC 61–96). Installed hermes-dec cannot disassemble HBC v${bytecodeVer}; please install hbctool (pipx install hbctool).`,
				};
			}
		} else {
			chosenDialect = "hermes-dec";
			chosenExecutable = hermesDecPath;
			if (!hermesDecPath && hbctoolPath) {
				return {
					action: "hermes",
					targetPath: effectiveBundlePath,
					status: "unsupported",
					runtime: "react_native",
					hashes,
					unsupportedReason: `Target Hermes Bytecode version is v${bytecodeVer}, which is not supported by hbctool (hbctool strictly supports HBC 59, 62, 74, 76 only). Please install hermes-dec (pip install hermes-dec) for HBC v${bytecodeVer} support.`,
				};
			}
		}

		if (!chosenExecutable) {
			return {
				action: "hermes",
				targetPath: effectiveBundlePath,
				status: "missing_dependency",
				runtime: "react_native",
				hashes,
				missingDependency: {
					id: chosenDialect,
					tool: chosenDialect === "hbctool" ? "hbctool" : "hermes-dec (hbc-disassembler)",
					category: "web",
					manualUrl:
						chosenDialect === "hbctool"
							? "https://github.com/bongtrop/hbctool"
							: "https://github.com/P1sec/hermes-dec",
					installHint: chosenDialect === "hbctool" ? hbctoolInstallHint : hermesDecInstallHint,
					targetDiagnostics: {
						bytecodeVersion: bytecodeVer,
						sourceHash: hbc.sourceHash,
						fileLength: hbc.fileLength,
						supportedByHbctool: isHbctoolCompatible,
						supportedByHermesDec: isHermesDecCompatible,
					},
				},
			};
		}

		// 4. 路径重叠检查与独占输出目录生成 (绝对路径基于 session.cwd 解析)
		const defaultOutDir = path.join(
			this.session.cwd,
			"artifacts",
			"runtime_analyze",
			"hermes",
			`hbc_v${bytecodeVer}_${hashes.sha256.slice(0, 8)}`,
		);
		const requestedOut = params.output_dir ? resolveReadPath(params.output_dir, this.session.cwd) : defaultOutDir;
		await assertNoPathOverlap(targetPath, requestedOut);
		const outDir = await createExclusiveOutputDir(requestedOut);

		// 独占隔离暂存输入 bundle
		const stagedInputsDir = path.join(outDir, "inputs");
		await fs.mkdir(stagedInputsDir, { recursive: true });
		const bundleOnDisk = path.join(stagedInputsDir, "source_bundle.hbc");
		await fs.writeFile(bundleOnDisk, bundleBuffer);

		// 5. 真实工具调用
		const timeout = Math.max(1, Math.min(params.timeout ?? 60, 300));
		const timeoutMs = timeout * 1000;
		const maxBytes = Math.max(1024, Math.min(params.max_bytes ?? 256 * 1024, 4 * 1024 * 1024));
		const limit = Math.max(1, Math.min(params.limit ?? 50, 200));

		let runRes: RuntimeAnalyzeRunResult;
		let toolName = "";
		let expectedArtifact = "";

		if (chosenDialect === "hermes-dec") {
			toolName = path.basename(chosenExecutable);
			const disasmFile = path.join(outDir, "disassembly.hasm");
			expectedArtifact = disasmFile;
			// 真实 upstream hermes-dec: hbc-disassembler <bundle> <output.hasm>
			runRes = await this.runner(chosenExecutable, [bundleOnDisk, disasmFile], {
				cwd: this.session.cwd,
				timeoutMs,
				maxBytes,
				signal,
				monitorDir: outDir,
				maxOutputBytes: MAX_OUTPUT_QUOTA_BYTES,
			});
		} else {
			toolName = "hbctool";
			// 真实 upstream hbctool: hbctool disasm <HBC_FILE> <HASM_DIR>
			// HASM_DIR 是目录，内部生成 instruction.hasm, metadata.json, string.json
			const hasmDir = path.join(outDir, "hasm");
			expectedArtifact = path.join(hasmDir, "instruction.hasm");
			runRes = await this.runner(chosenExecutable, ["disasm", bundleOnDisk, hasmDir], {
				cwd: this.session.cwd,
				timeoutMs,
				maxBytes,
				signal,
				monitorDir: outDir,
				maxOutputBytes: MAX_OUTPUT_QUOTA_BYTES,
			});
		}

		// 产物有效性与退出状态双重校验：任何非零或超时均作为错误，绝不将残留/部分产物误标成功
		const artifactSuccess = fsSync.existsSync(expectedArtifact) && (await fs.stat(expectedArtifact)).size > 0;

		if (runRes.exitCode !== 0 || runRes.timedOut || !artifactSuccess) {
			const errorDetail = runRes.timedOut
				? "Command timed out"
				: runRes.stderr.trim() || runRes.stdout.trim() || `Exit code ${runRes.exitCode}`;
			return {
				action: "hermes",
				targetPath: effectiveBundlePath,
				status: "error",
				runtime: "react_native",
				hashes,
				error: `${toolName} disassembly failed (${errorDetail})`,
			};
		}

		let generatedFiles: string[] = [];
		try {
			generatedFiles = await fs.readdir(outDir);
		} catch {}

		return {
			action: "hermes",
			targetPath: effectiveBundlePath,
			status: "ok",
			runtime: "react_native",
			hashes,
			outputDir: outDir,
			artifactFiles: generatedFiles.slice(0, limit),
			metrics: {
				instructionsCount: generatedFiles.length,
			},
		};
	}

	// ========================================================================
	// Action: Il2Cpp (Unity)
	// ========================================================================

	private async executeIl2Cpp(
		targetPath: string,
		stat: Stats,
		params: RuntimeAnalyzeParams,
		signal?: AbortSignal,
	): Promise<RuntimeAnalyzeDetails> {
		throwIfAborted(signal);

		let soBuffer: Buffer | null = null;
		let metaBuffer: Buffer | null = null;
		let soPath = targetPath;
		let metaPath = params.metadata_path;

		// 1. 若显式指定了 metadata_path，优先加载
		if (metaPath) {
			const resolvedMeta = resolveReadPath(metaPath, this.session.cwd);
			metaBuffer = await safeReadFileBounded(resolvedMeta, signal);
			metaPath = resolvedMeta;
		}

		if (stat.isDirectory()) {
			// 在目录中查找 libil2cpp.so (优先 arm64-v8a)
			const arm64Candidate = path.join(targetPath, "lib", "arm64-v8a", "libil2cpp.so");
			const arm64Direct = path.join(targetPath, "arm64-v8a", "libil2cpp.so");
			const baseArm64Candidate = path.join(targetPath, "base", "lib", "arm64-v8a", "libil2cpp.so");
			const rootCandidate = path.join(targetPath, "libil2cpp.so");
			const gameAssembly = path.join(targetPath, "GameAssembly.dll");

			if (fsSync.existsSync(arm64Candidate)) soPath = arm64Candidate;
			else if (fsSync.existsSync(arm64Direct)) soPath = arm64Direct;
			else if (fsSync.existsSync(baseArm64Candidate)) soPath = baseArm64Candidate;
			else if (fsSync.existsSync(rootCandidate)) soPath = rootCandidate;
			else if (fsSync.existsSync(gameAssembly)) soPath = gameAssembly;
			else {
				const entries = await fs.readdir(targetPath);
				const matched = entries.find(e => e.includes("libil2cpp.so") || e.includes("GameAssembly.dll"));
				if (matched) soPath = path.join(targetPath, matched);
			}

			if (fsSync.existsSync(soPath)) {
				soBuffer = await safeReadFileBounded(soPath, signal);
			}

			// 若未显式传入 metadata_path，在目录及常见路径查找 global-metadata.dat
			if (!metaBuffer) {
				const standardMeta = path.join(
					targetPath,
					"assets",
					"bin",
					"Data",
					"Managed",
					"Metadata",
					"global-metadata.dat",
				);
				const baseMeta = path.join(
					targetPath,
					"base",
					"assets",
					"bin",
					"Data",
					"Managed",
					"Metadata",
					"global-metadata.dat",
				);
				const managedMeta = path.join(targetPath, "Managed", "Metadata", "global-metadata.dat");
				const rootMeta = path.join(targetPath, "global-metadata.dat");

				if (fsSync.existsSync(standardMeta)) metaPath = standardMeta;
				else if (fsSync.existsSync(baseMeta)) metaPath = baseMeta;
				else if (fsSync.existsSync(managedMeta)) metaPath = managedMeta;
				else if (fsSync.existsSync(rootMeta)) metaPath = rootMeta;

				if (metaPath && fsSync.existsSync(metaPath)) {
					metaBuffer = await safeReadFileBounded(metaPath, signal);
				}
			}
		} else {
			const rawBuf = await safeReadFileBounded(targetPath, signal);
			let isZip = false;
			try {
				const zip = new ZipParser(rawBuf);
				isZip = true;
				// 优先选择 arm64-v8a (支持 AAB base/lib/ 及常规 lib/)
				const arm64SoEntry = zip.entries.find(
					e => e.name === "lib/arm64-v8a/libil2cpp.so" || e.name === "base/lib/arm64-v8a/libil2cpp.so",
				);
				const soEntry = arm64SoEntry ?? zip.entries.find(e => e.name.endsWith("libil2cpp.so"));
				if (soEntry) {
					soBuffer = safeReadZipEntry(rawBuf, soEntry);
				}
				if (!metaBuffer) {
					const metaEntry =
						zip.entries.find(
							e =>
								e.name === "assets/bin/Data/Managed/Metadata/global-metadata.dat" ||
								e.name === "base/assets/bin/Data/Managed/Metadata/global-metadata.dat",
						) ?? zip.entries.find(e => e.name.endsWith("global-metadata.dat"));
					if (metaEntry) {
						metaBuffer = safeReadZipEntry(rawBuf, metaEntry);
						metaPath = `${targetPath}!/${metaEntry.name}`;
					}
				}
			} catch {
				isZip = false;
			}

			if (!isZip) {
				const isMetadata = parseUnityMetadataHeader(rawBuf).isValid;
				if (isMetadata) {
					// 目标输入文件直接为 global-metadata.dat，自动向上搜寻配对的 libil2cpp.so / GameAssembly.dll
					metaBuffer = rawBuf;
					metaPath = targetPath;
					const baseDirCandidates: string[] = [path.dirname(targetPath)];
					let cur = path.dirname(targetPath);
					for (let i = 0; i < 8; i++) {
						const parent = path.dirname(cur);
						if (parent === cur) break;
						baseDirCandidates.push(
							parent,
							path.join(parent, "lib", "arm64-v8a"),
							path.join(parent, "base", "lib", "arm64-v8a"),
							path.join(parent, "lib"),
						);
						cur = parent;
					}
					for (const d of baseDirCandidates) {
						const arm64So = path.join(d, "libil2cpp.so");
						const gameAss = path.join(d, "GameAssembly.dll");
						if (fsSync.existsSync(arm64So)) {
							soPath = arm64So;
							soBuffer = await safeReadFileBounded(soPath, signal);
							break;
						} else if (fsSync.existsSync(gameAss)) {
							soPath = gameAss;
							soBuffer = await safeReadFileBounded(soPath, signal);
							break;
						}
					}
				} else {
					// 目标输入文件为二进制 (ELF / PE)
					soBuffer = rawBuf;
					if (!metaBuffer) {
						const adjacent = path.join(path.dirname(targetPath), "global-metadata.dat");
						if (fsSync.existsSync(adjacent)) {
							metaBuffer = await safeReadFileBounded(adjacent, signal);
							metaPath = adjacent;
						}
					}
				}
			}
		}

		if (!soBuffer || !metaBuffer || !metaPath) {
			return {
				action: "il2cpp",
				targetPath,
				status: "error",
				error: "Could not locate both Unity IL2CPP binary (libil2cpp.so) and global-metadata.dat metadata pair. Specify metadata_path parameter.",
			};
		}

		const soHashes = computeHashes(soBuffer);
		const metaHashes = computeHashes(metaBuffer);

		// 1. 严格校验 global-metadata.dat 校验魔数 (0xFAB11BAF)
		const metaHeader = parseUnityMetadataHeader(metaBuffer);
		if (!metaHeader.isValid) {
			return {
				action: "il2cpp",
				targetPath: soPath,
				status: "error",
				hashes: soHashes,
				secondaryHashes: metaHashes,
				error: `Target metadata file is not a valid global-metadata.dat (magic mismatch: expected 0xFAB11BAF, got 0x${(metaHeader.sanity ?? 0).toString(16).toUpperCase()}). File may be encrypted or corrupted.`,
			};
		}

		const metadataVer = metaHeader.version ?? 0;

		// 2. 检查 Il2CppDumper 依赖 (通过 catalog 与 PATH)
		const dumperStatus = this.resolveCatalogTool("il2cppdumper", ["Il2CppDumper", "il2cppdumper"]);
		const dumperBin = dumperStatus.path;
		if (!dumperStatus.available || !dumperBin) {
			return {
				action: "il2cpp",
				targetPath: soPath,
				status: "missing_dependency",
				runtime: "unity_il2cpp",
				hashes: soHashes,
				secondaryHashes: metaHashes,
				missingDependency: {
					id: "il2cppdumper",
					tool: "Il2CppDumper",
					category: "binary",
					manualUrl: dumperStatus.manualUrl ?? "https://github.com/Perfare/Il2CppDumper",
					installHint:
						dumperStatus.installHint ?? "reverse setup reverse il2cppdumper (portable upstream download)",
					targetDiagnostics: {
						metadataVersion: metadataVer,
						metadataSanity: "0xFAB11BAF (valid)",
						unitySupportRange: "Unity 5.3–2022.2 (metadata v16–29)",
						isSupportedVersion: metadataVer >= 16 && metadataVer <= 29,
					},
				},
			};
		}

		// 3. 输出路径重叠保护与独占生成 (绝对路径基于 session.cwd 解析)
		const baseDir = path.join(this.session.cwd, "artifacts", "runtime_analyze", "il2cpp");
		const defaultOutDir = path.join(baseDir, `dump_v${metadataVer}_${soHashes.sha256.slice(0, 8)}`);
		const requestedOut = params.output_dir ? resolveReadPath(params.output_dir, this.session.cwd) : defaultOutDir;
		await assertNoPathOverlap(soPath, requestedOut);
		if (metaPath && !metaPath.includes("!/")) await assertNoPathOverlap(metaPath, requestedOut);
		const outDir = await createExclusiveOutputDir(requestedOut);

		// 4. 独占隔离暂存输入文件，杜绝并发调用竞争与覆盖
		const stagedInputsDir = path.join(outDir, "inputs");
		await fs.mkdir(stagedInputsDir, { recursive: true });
		const stagedSo = path.join(stagedInputsDir, "libil2cpp.so");
		const stagedMeta = path.join(stagedInputsDir, "global-metadata.dat");
		await fs.writeFile(stagedSo, soBuffer);
		await fs.writeFile(stagedMeta, metaBuffer);
		soPath = stagedSo;
		metaPath = stagedMeta;

		// 5. 为 Il2CppDumper 准备隔离的真实私有 sandbox 与 config.json (RequireAnyKey=false)
		const realDumperPath = await fs.realpath(dumperBin).catch(() => dumperBin);
		let realDumperDir = path.dirname(realDumperPath);

		// 确保定位到包含 Il2CppDumper.dll 的真实发布根目录
		if (!fsSync.existsSync(path.join(realDumperDir, "Il2CppDumper.dll"))) {
			const parentDir = path.resolve(realDumperDir, "..");
			if (fsSync.existsSync(path.join(parentDir, "Il2CppDumper.dll"))) {
				realDumperDir = parentDir;
			} else {
				try {
					const wrapperBuf = await safeReadFileBounded(realDumperPath, signal);
					const wrapperText = wrapperBuf.toString("utf8");
					const dllMatch = wrapperText.match(/["']?([A-Za-z0-9_/.-]+Il2CppDumper\.dll)["']?/);
					if (dllMatch && fsSync.existsSync(dllMatch[1]!)) {
						realDumperDir = path.dirname(dllMatch[1]!);
					}
				} catch {}
			}
		}

		const dumperExeName = path.basename(realDumperPath);
		const stagedDumperDir = path.join(outDir, ".dumper");
		await fs.mkdir(stagedDumperDir, { recursive: true });

		const dumperFiles = await fs.readdir(realDumperDir).catch(() => [] as string[]);
		for (const file of dumperFiles) {
			if (file === "config.json" || file === "bin") continue;
			const isDumperAsset =
				file.startsWith("Il2CppDumper") ||
				file.endsWith(".dll") ||
				file.endsWith(".runtimeconfig.json") ||
				file.endsWith(".deps.json") ||
				file.endsWith(".exe");
			if (!isDumperAsset && dumperFiles.length > 20) continue;

			const src = path.join(realDumperDir, file);
			const dest = path.join(stagedDumperDir, file);
			try {
				const st = await fs.stat(src);
				if (st.isFile()) {
					await fs.copyFile(src, dest);
				}
			} catch {}
		}

		const privateConfig = {
			DumpMethod: true,
			DumpField: true,
			DumpProperty: true,
			DumpAttribute: true,
			DumpFieldOffset: true,
			DumpMethodOffset: true,
			DumpTypeDefIndex: true,
			GenerateDummyDll: true,
			GenerateStruct: true,
			DummyDllAddToken: true,
			RequireAnyKey: false,
			ForceIl2CppVersion: false,
			ForceVersion: 16,
			ForceDump: false,
			NoRedirectedPointer: false,
		};
		await fs.writeFile(path.join(stagedDumperDir, "config.json"), JSON.stringify(privateConfig, null, 2));

		let dumperExecutableToRun = realDumperPath;
		let dumperArgsPrefix: string[] = [];

		const stagedDll = path.join(stagedDumperDir, "Il2CppDumper.dll");
		const stagedExe = path.join(stagedDumperDir, "Il2CppDumper.exe");
		const stagedDirect = path.join(stagedDumperDir, dumperExeName);

		// 在非 Windows 平台优先选择 dotnet Il2CppDumper.dll 执行，绝不在 Unix/macOS 执行 Windows PE .exe
		if (process.platform !== "win32" && fsSync.existsSync(stagedDll)) {
			const dotnetBin = this.which("dotnet") ?? "dotnet";
			dumperExecutableToRun = dotnetBin;
			dumperArgsPrefix = [stagedDll];
		} else if (process.platform === "win32" && fsSync.existsSync(stagedExe)) {
			dumperExecutableToRun = stagedExe;
		} else if (fsSync.existsSync(stagedDirect)) {
			dumperExecutableToRun = stagedDirect;
		}

		const timeout = Math.max(1, Math.min(params.timeout ?? 60, 300));
		const timeoutMs = timeout * 1000;
		const maxBytes = Math.max(1024, Math.min(params.max_bytes ?? 256 * 1024, 4 * 1024 * 1024));
		const limit = Math.max(1, Math.min(params.limit ?? 50, 200));
		const validMetaPath = metaPath;

		// 6. 执行沙箱化 Il2CppDumper
		const runRes = await this.runner(dumperExecutableToRun, [...dumperArgsPrefix, soPath, validMetaPath, outDir], {
			cwd: this.session.cwd,
			timeoutMs,
			maxBytes,
			stdin: "\n",
			signal,
			monitorDir: outDir,
			maxOutputBytes: MAX_OUTPUT_QUOTA_BYTES,
		});

		const dumpCs = path.join(outDir, "dump.cs");
		const scriptJson = path.join(outDir, "script.json");
		const il2cppH = path.join(outDir, "il2cpp.h");

		let isScriptValid = false;
		if (fsSync.existsSync(scriptJson) && (await fs.stat(scriptJson)).size > 0) {
			try {
				const scriptContent = await safeReadFileBounded(scriptJson, signal);
				const parsed = JSON.parse(scriptContent.toString("utf8"));
				isScriptValid =
					Array.isArray(parsed) || (parsed && typeof parsed === "object" && Object.keys(parsed).length > 0);
			} catch {}
		}

		const hasValidOutputs =
			fsSync.existsSync(dumpCs) &&
			(await fs.stat(dumpCs)).size > 0 &&
			fsSync.existsSync(il2cppH) &&
			(await fs.stat(il2cppH)).size > 0 &&
			isScriptValid;

		if (runRes.exitCode !== 0 || runRes.timedOut || !hasValidOutputs) {
			const errorMsg =
				runRes.stderr.trim() ||
				runRes.stdout.trim() ||
				`Il2CppDumper failed to produce expected dump outputs (dump.cs, script.json, il2cpp.h) in ${outDir} (exit code ${runRes.exitCode})`;
			return {
				action: "il2cpp",
				targetPath: soPath,
				status: "error",
				runtime: "unity_il2cpp",
				hashes: soHashes,
				secondaryHashes: metaHashes,
				error: errorMsg,
			};
		}

		let typesCount: number | undefined;
		if (fsSync.existsSync(dumpCs)) {
			try {
				const dumpHandle = await fs.open(dumpCs, "r");
				try {
					const headBuf = Buffer.alloc(64 * 1024);
					const { bytesRead } = await dumpHandle.read(headBuf, 0, 64 * 1024, 0);
					const dumpHead = headBuf.subarray(0, bytesRead).toString("utf8");
					const match = dumpHead.match(/\/\/\s*Image\s*\d+:\s*(.+)/g);
					typesCount = match ? match.length : undefined;
				} finally {
					await dumpHandle.close().catch(() => {});
				}
			} catch {}
		}

		let generatedFiles: string[] = [];
		try {
			generatedFiles = await fs.readdir(outDir);
		} catch {}

		const adjacentGhidraPy = path.join(realDumperDir, "ghidra.py");
		const adjacentIdaPy = path.join(realDumperDir, "ida_with_struct.py");

		return {
			action: "il2cpp",
			targetPath: soPath,
			status: "ok",
			runtime: "unity_il2cpp",
			hashes: soHashes,
			secondaryHashes: metaHashes,
			outputDir: outDir,
			artifactFiles: generatedFiles.filter(f => !f.startsWith(".")).slice(0, limit),
			handoff: {
				engine: "ghidra",
				scriptPath: fsSync.existsSync(adjacentGhidraPy) ? adjacentGhidraPy : undefined,
				suggestedCommands: [
					`ghidra_inspect(action: "analyze", path: "${soPath}")`,
					fsSync.existsSync(adjacentIdaPy)
						? `ida(action: "run_script", path: "${soPath}", script: "${adjacentIdaPy}")`
						: "",
				].filter(Boolean),
			},
			metrics: {
				typesCount,
			},
		};
	}

	// ========================================================================
	// Action: Flutter (Dart AOT)
	// ========================================================================

	private async executeFlutter(
		targetPath: string,
		stat: Stats,
		params: RuntimeAnalyzeParams,
		signal?: AbortSignal,
	): Promise<RuntimeAnalyzeDetails> {
		throwIfAborted(signal);

		let appBuffer: Buffer | null = null;
		let flutterBuffer: Buffer | null = null;
		let appPath = targetPath;
		let enginePath = params.engine_path;

		// 1. 若显式指定了 engine_path，优先加载
		if (enginePath) {
			const resolvedEngine = resolveReadPath(enginePath, this.session.cwd);
			flutterBuffer = await safeReadFileBounded(resolvedEngine, signal);
			enginePath = resolvedEngine;
		}

		if (stat.isDirectory()) {
			// 在目录中查找 libapp.so (优先 arm64-v8a)
			const arm64App = path.join(targetPath, "lib", "arm64-v8a", "libapp.so");
			const arm64Direct = path.join(targetPath, "arm64-v8a", "libapp.so");
			const baseArm64App = path.join(targetPath, "base", "lib", "arm64-v8a", "libapp.so");
			const rootApp = path.join(targetPath, "libapp.so");

			if (fsSync.existsSync(arm64App)) appPath = arm64App;
			else if (fsSync.existsSync(arm64Direct)) appPath = arm64Direct;
			else if (fsSync.existsSync(baseArm64App)) appPath = baseArm64App;
			else if (fsSync.existsSync(rootApp)) appPath = rootApp;
			else {
				const entries = await fs.readdir(targetPath);
				const matched = entries.find(e => e.includes("libapp.so"));
				if (matched) appPath = path.join(targetPath, matched);
			}

			if (fsSync.existsSync(appPath)) {
				appBuffer = await safeReadFileBounded(appPath, signal);
			}

			// 若未显式传入 engine_path，在目录中查找 libflutter.so
			if (!flutterBuffer) {
				const arm64Flutter = path.join(targetPath, "lib", "arm64-v8a", "libflutter.so");
				const arm64DirectFlutter = path.join(targetPath, "arm64-v8a", "libflutter.so");
				const baseArm64Flutter = path.join(targetPath, "base", "lib", "arm64-v8a", "libflutter.so");
				const rootFlutter = path.join(targetPath, "libflutter.so");

				if (fsSync.existsSync(arm64Flutter)) enginePath = arm64Flutter;
				else if (fsSync.existsSync(arm64DirectFlutter)) enginePath = arm64DirectFlutter;
				else if (fsSync.existsSync(baseArm64Flutter)) enginePath = baseArm64Flutter;
				else if (fsSync.existsSync(rootFlutter)) enginePath = rootFlutter;

				if (enginePath && fsSync.existsSync(enginePath)) {
					flutterBuffer = await safeReadFileBounded(enginePath, signal);
				}
			}
		} else {
			const rawBuf = await safeReadFileBounded(targetPath, signal);
			let isZip = false;
			try {
				const zip = new ZipParser(rawBuf);
				isZip = true;

				// 收集所有条目并按 module/abi 配对，严格杜绝跨 ABI / 跨 module 错配
				const appEntries = new Map<string, ZipEntry>();
				const flutterEntries = new Map<string, ZipEntry>();

				for (const entry of zip.entries) {
					const m = entry.name.match(/^(?:([a-zA-Z0-9_-]+)\/)?lib\/([^/]+)\/(libapp\.so|libflutter\.so)$/);
					if (m) {
						const mod = m[1] ?? "root";
						const abi = m[2]!;
						const lib = m[3]!;
						const key = `${mod}/${abi}`;
						if (lib === "libapp.so") appEntries.set(key, entry);
						else if (lib === "libflutter.so") flutterEntries.set(key, entry);
					}
				}

				// 优先选择同一 module 下的 arm64-v8a 配对
				let matchedKey: string | null = null;
				for (const key of appEntries.keys()) {
					if (key.endsWith("/arm64-v8a") && flutterEntries.has(key)) {
						matchedKey = key;
						break;
					}
				}
				if (!matchedKey) {
					for (const key of appEntries.keys()) {
						if (key.endsWith("/arm64-v8a")) {
							matchedKey = key;
							break;
						}
					}
				}
				if (!matchedKey && appEntries.size > 0) {
					matchedKey = Array.from(appEntries.keys())[0]!;
				}

				if (matchedKey) {
					const appEntry = appEntries.get(matchedKey);
					if (appEntry) {
						appBuffer = safeReadZipEntry(rawBuf, appEntry);
					}
					if (!flutterBuffer) {
						const flutterEntry = flutterEntries.get(matchedKey);
						if (flutterEntry) {
							flutterBuffer = safeReadZipEntry(rawBuf, flutterEntry);
							enginePath = `${targetPath}!/${flutterEntry.name}`;
						}
					}
				}
			} catch {
				isZip = false;
			}

			if (!isZip) {
				appBuffer = rawBuf;
				if (!flutterBuffer) {
					const adjacent = path.join(path.dirname(targetPath), "libflutter.so");
					if (fsSync.existsSync(adjacent)) {
						flutterBuffer = await safeReadFileBounded(adjacent, signal);
						enginePath = adjacent;
					}
				}
			}
		}

		if (!appBuffer) {
			return {
				action: "flutter",
				targetPath,
				status: "error",
				error: "Target does not contain Flutter Dart AOT snapshot (libapp.so).",
			};
		}

		const appHashes = computeHashes(appBuffer);
		const flutterHashes = flutterBuffer ? computeHashes(flutterBuffer) : undefined;

		// 1. 严格架构边界: Blutter 仅支持 Android arm64-v8a
		const elf = parseElfCharacteristics(appBuffer);
		if (!elf.isElf) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "unsupported",
				runtime: "flutter",
				hashes: appHashes,
				unsupportedReason: "Target is not a valid ELF binary.",
			};
		}

		if (elf.machine !== ELF_MACHINE_AARCH64) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "unsupported",
				runtime: "flutter",
				hashes: appHashes,
				unsupportedReason: `Blutter currently supports only Android libapp.so for arm64-v8a architecture. Detected architecture: ${elf.architecture}. 32-bit ARM (armeabi-v7a) and x86_64 are not supported by Blutter.`,
			};
		}

		// 校验 engineElf 是否与 libapp.so 匹配同一架构
		let validEngineElf: ElfCharacteristics | null = null;
		if (flutterBuffer) {
			const engineElf = parseElfCharacteristics(flutterBuffer);
			if (!engineElf.isElf || engineElf.machine !== elf.machine) {
				return {
					action: "flutter",
					targetPath: appPath,
					status: "unsupported",
					runtime: "flutter",
					hashes: appHashes,
					secondaryHashes: flutterHashes,
					unsupportedReason: `ABI mismatch between Dart AOT snapshot (${elf.architecture}) and Flutter engine (${engineElf.architecture}). Both must be valid arm64-v8a binaries.`,
				};
			}
			validEngineElf = engineElf;
		}

		// 2. 检查是否为真实的 Flutter Dart AOT 快照
		if (!elf.isDartAot && !elf.isFlutterEngine && (!validEngineElf || !validEngineElf.isFlutterEngine)) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "unsupported",
				runtime: "flutter",
				hashes: appHashes,
				unsupportedReason:
					"Target binary does not contain Dart AOT snapshot symbols (_kDartVmSnapshotData / _kDartVmSnapshotInstructions) or Flutter engine markers; not a Flutter AOT application.",
			};
		}

		// 3. 提取 Dart 快照 Hash 与 Dart SDK 版本
		const snapInfo = extractDartSnapshotInfo(appBuffer);
		let snapshotHash = snapInfo.snapshotHash;
		const hasCompressedPointers = snapInfo.hasCompressedPointers;

		let dartVersion: string | undefined;
		if (validEngineElf) {
			if (validEngineElf.dartVersion) dartVersion = validEngineElf.dartVersion;
			if (!snapshotHash && validEngineElf.dartSnapshotHash) snapshotHash = validEngineElf.dartSnapshotHash;
		}
		// 4. 检查 Blutter 依赖
		const blutterStatus = this.resolveCatalogTool("blutter", ["blutter", "blutter.py"]);
		if (!blutterStatus.available || !blutterStatus.path) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "missing_dependency",
				runtime: "flutter",
				hashes: appHashes,
				secondaryHashes: flutterHashes,
				missingDependency: {
					id: "blutter",
					tool: "blutter",
					category: "binary",
					manualUrl: blutterStatus.manualUrl ?? "https://github.com/worawit/blutter",
					installHint:
						blutterStatus.installHint ??
						"Clone https://github.com/worawit/blutter and install prerequisites: Python 3.9+, pyelftools, requests, cmake, ninja, gcc 13 / clang 16, libicu, libcapstone. Run setup via reverse setup reverse blutter or compile blutter with --rebuild.",
					prerequisites: ["python3", "cmake", "ninja", "pyelftools", "requests", "libicu", "libcapstone"],
					targetDiagnostics: {
						architecture: "arm64-v8a",
						snapshotHash,
						engineVersion: dartVersion,
						isArm64: true,
					},
				},
			};
		}

		// 5. 严格匹配预编译后端可执行文件 (绝不调用 blutter.py 触发网络与源码编译)
		if (!dartVersion) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "backend_build_required",
				runtime: "flutter",
				hashes: appHashes,
				secondaryHashes: flutterHashes,
				unsupportedReason:
					"Dart SDK version could not be extracted from libflutter.so rodata (expected '\\0X.Y.Z (channel)'). Matching prebuilt Blutter Dart VM cannot be resolved without explicit version preparation. Automated analysis does not silently checkout or compile external Dart SDK sources.",
			};
		}

		if (hasCompressedPointers === undefined) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "backend_build_required",
				runtime: "flutter",
				hashes: appHashes,
				secondaryHashes: flutterHashes,
				unsupportedReason:
					"Dart snapshot flags (compressed-pointers status) could not be verified from _kDartVmSnapshotData. Automated analysis will not guess ABI. Please run explicit blutter preparation via 'python3 blutter.py <indir> <outdir> --rebuild'.",
			};
		}

		const isDartOld = (() => {
			const parts = dartVersion.split(".");
			const major = parseInt(parts[0] ?? "0", 10);
			const minor = parseInt(parts[1] ?? "0", 10);
			return major === 2 && minor < 15;
		})();

		let ptrSuffix = "";
		if (!hasCompressedPointers) ptrSuffix += "_no-compressed-ptrs";
		if (isDartOld) ptrSuffix += "_no-analysis";

		const exactBinaryName = `blutter_dartvm${dartVersion}_android_arm64${ptrSuffix}`;

		const rawBlutterDir = path.dirname(blutterStatus.path);
		const isDedicatedBlutterDir = blutterStatus.path.toLowerCase().includes("blutter");
		const binDir =
			isDedicatedBlutterDir && path.basename(rawBlutterDir) === "bin"
				? rawBlutterDir
				: path.join(rawBlutterDir, "bin");
		const exactPrebuiltExe = path.join(binDir, exactBinaryName) + (process.platform === "win32" ? ".exe" : "");

		if (!fsSync.existsSync(exactPrebuiltExe)) {
			return {
				action: "flutter",
				targetPath: appPath,
				status: "backend_build_required",
				runtime: "flutter",
				hashes: appHashes,
				secondaryHashes: flutterHashes,
				unsupportedReason: `Blutter requires compiling a Dart VM matching snapshot version ${dartVersion} (${hasCompressedPointers ? "compressed-pointers" : "no-compressed-pointers"}). Prebuilt backend '${exactBinaryName}' was not found in ${binDir}. Automated analysis does not silently checkout or compile external Dart SDK sources in the background. Please compile blutter with '--rebuild' via reverse setup or place the matching prebuilt executable in the blutter bin directory.`,
			};
		}

		// 6. 输出路径重叠保护与独占生成 (绝对路径基于 session.cwd 解析)
		const baseDir = path.join(this.session.cwd, "artifacts", "runtime_analyze", "flutter");
		const defaultOutDir = path.join(
			baseDir,
			`flutter_${snapshotHash ? snapshotHash.slice(0, 8) : appHashes.sha256.slice(0, 8)}`,
		);
		const requestedOut = params.output_dir ? resolveReadPath(params.output_dir, this.session.cwd) : defaultOutDir;
		await assertNoPathOverlap(appPath, requestedOut);
		if (enginePath && !enginePath.includes("!/")) await assertNoPathOverlap(enginePath, requestedOut);
		const outDir = await createExclusiveOutputDir(requestedOut);

		// 7. 独占隔离暂存输入文件，杜绝并发调用竞争与覆盖，并保证 libapp.so 与 libflutter.so 物理紧邻
		const stagedInputsDir = path.join(outDir, "inputs");
		await fs.mkdir(stagedInputsDir, { recursive: true });
		const stagedApp = path.join(stagedInputsDir, "libapp.so");
		await fs.writeFile(stagedApp, appBuffer);
		appPath = stagedApp;

		if (flutterBuffer) {
			const stagedFlutter = path.join(stagedInputsDir, "libflutter.so");
			await fs.writeFile(stagedFlutter, flutterBuffer);
			enginePath = stagedFlutter;
		}

		const timeout = Math.max(1, Math.min(params.timeout ?? 120, 300));
		const timeoutMs = timeout * 1000;
		const maxBytes = Math.max(1024, Math.min(params.max_bytes ?? 256 * 1024, 4 * 1024 * 1024));
		const limit = Math.max(1, Math.min(params.limit ?? 50, 200));

		// 直接执行精确匹配的预编译二进制，保证离线与确定性: blutter_exe -i <libapp_path> -o <outdir>
		const runRes = await this.runner(exactPrebuiltExe, ["-i", appPath, "-o", outDir], {
			cwd: this.session.cwd,
			timeoutMs,
			maxBytes,
			signal,
			monitorDir: outDir,
			maxOutputBytes: MAX_OUTPUT_QUOTA_BYTES,
		});

		let generatedFiles: string[] = [];
		try {
			generatedFiles = await fs.readdir(outDir);
		} catch {}

		const objsTxt = path.join(outDir, "objs.txt");
		const ppTxt = path.join(outDir, "pp.txt");
		const fridaScript = path.join(outDir, "blutter_frida.js");
		const asmDir = path.join(outDir, "asm");

		let hasAsmFiles = false;
		if (fsSync.existsSync(asmDir)) {
			try {
				const asmEntries = await fs.readdir(asmDir);
				hasAsmFiles = asmEntries.length > 0;
			} catch {}
		}

		const flutterArtifactSuccess =
			fsSync.existsSync(objsTxt) &&
			(await fs.stat(objsTxt)).size > 0 &&
			fsSync.existsSync(ppTxt) &&
			(await fs.stat(ppTxt)).size > 0 &&
			fsSync.existsSync(fridaScript) &&
			(await fs.stat(fridaScript)).size > 0 &&
			hasAsmFiles;

		const hasExceptionNotice =
			runRes.stdout.toLowerCase().includes("exception:") || runRes.stderr.toLowerCase().includes("exception:");

		if (runRes.exitCode !== 0 || runRes.timedOut || hasExceptionNotice || !flutterArtifactSuccess) {
			const errorDetail = runRes.timedOut
				? "Command timed out"
				: hasExceptionNotice
					? "Blutter runtime exception in main"
					: runRes.stderr.trim() || runRes.stdout.trim() || `Exit code ${runRes.exitCode}`;
			return {
				action: "flutter",
				targetPath: appPath,
				status: "error",
				runtime: "flutter",
				hashes: appHashes,
				secondaryHashes: flutterHashes,
				error: `Blutter backend execution failed (${errorDetail})`,
			};
		}

		return {
			action: "flutter",
			targetPath: appPath,
			status: "ok",
			runtime: "flutter",
			hashes: appHashes,
			secondaryHashes: flutterHashes,
			outputDir: outDir,
			artifactFiles: generatedFiles.filter(f => !f.startsWith(".")).slice(0, limit),
			handoff: {
				engine: "frida",
				scriptPath: fsSync.existsSync(fridaScript) ? fridaScript : undefined,
				suggestedCommands: fsSync.existsSync(fridaScript) ? [`frida -l "${fridaScript}" -f <package_name>`] : [],
			},
		};
	}

	// ========================================================================
	// Rendering & Output Formatting
	// ========================================================================

	private formatResult(details: RuntimeAnalyzeDetails, format: "markdown" | "json"): string {
		if (format === "json") {
			return JSON.stringify(details, null, 2);
		}

		const lines: string[] = [];
		lines.push(`# Runtime Analyze (${details.action.toUpperCase()})`);
		lines.push(`- **Target**: \`${details.targetPath}\``);
		lines.push(`- **Status**: \`${details.status}\``);

		if (details.hashes) {
			lines.push(`- **SHA-256**: \`${details.hashes.sha256}\``);
			lines.push(`- **Size**: ${details.hashes.size} bytes`);
		}

		if (details.inventory) {
			lines.push("");
			lines.push("## Inventory Findings");
			lines.push(details.inventory.summary);
			lines.push("");
			for (const r of details.inventory.runtimes) {
				lines.push(`### ${r.frameworkName} (${r.confidence})`);
				for (const ind of r.indicators) {
					lines.push(`- ${ind}`);
				}
				if (r.recommendedAction === "native_inspect") {
					lines.push(
						`- *Recommended Next Action*: \`triage(path: "${details.targetPath}")\` for generic native inspection; use \`android_native_workflow\` when Android/JNI evidence is present.`,
					);
				} else if (r.recommendedAction) {
					lines.push(
						`- *Recommended Next Action*: \`runtime_analyze(action: "${r.recommendedAction}", path: "${details.targetPath}")\``,
					);
				}
				lines.push("");
			}
		}

		if (details.status === "missing_dependency" && details.missingDependency) {
			const m = details.missingDependency;
			lines.push("");
			lines.push("## Missing Dependency");
			lines.push(`- **Required Tool**: \`${m.tool}\``);
			lines.push(`- **Category**: ${m.category}`);
			lines.push(`- **Manual URL**: ${m.manualUrl}`);
			lines.push(`- **Install Command**: \`${m.installHint}\``);
			if (m.prerequisites && m.prerequisites.length > 0) {
				lines.push(`- **Prerequisites**: ${m.prerequisites.join(", ")}`);
			}
			lines.push("");
			lines.push("### Target Diagnostics");
			for (const [k, v] of Object.entries(m.targetDiagnostics)) {
				lines.push(`- **${k}**: ${String(v)}`);
			}
		}

		if (details.status === "unsupported" || details.status === "backend_build_required") {
			lines.push("");
			lines.push(
				`## ${details.status === "backend_build_required" ? "Build Required" : "Unsupported Target Boundary"}`,
			);
			lines.push(details.unsupportedReason ?? "Target is not supported by the requested runtime adapter.");
		}

		if (details.status === "ok" && details.outputDir) {
			lines.push("");
			lines.push("## Analysis Artifacts");
			lines.push(`- **Output Directory**: \`${details.outputDir}\``);
			if (details.artifactFiles && details.artifactFiles.length > 0) {
				lines.push(`- **Generated Files (${details.artifactFiles.length})**:`);
				for (const f of details.artifactFiles.slice(0, 20)) {
					lines.push(`  - \`${f}\``);
				}
				if (details.artifactFiles.length > 20) {
					lines.push(`  - ... and ${details.artifactFiles.length - 20} more files`);
				}
			}
			if (details.handoff && details.handoff.suggestedCommands.length > 0) {
				lines.push("");
				lines.push("## Static Engine Handoff");
				for (const cmd of details.handoff.suggestedCommands) {
					lines.push(`- \`${cmd}\``);
				}
			}
		}

		if (details.error) {
			lines.push("");
			lines.push(`## Error: ${details.error}`);
		}

		return lines.join("\n");
	}
}
