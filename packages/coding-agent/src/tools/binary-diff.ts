import * as fs from "node:fs/promises";
import { type Stats } from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import binaryDiffDescription from "../prompts/tools/binary-diff.md" with { type: "text" };

const DEFAULT_BLOCK_SIZE = 4096;
const MIN_BLOCK_SIZE = 64;
const MAX_BLOCK_SIZE = 65536;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024; // 64 MB
const HARD_MAX_BYTES = 256 * 1024 * 1024; // 256 MB

// ============================================================================
// Parameter Schema
// ============================================================================

const binaryDiffSchema = type({
	"path_a?": type("string").describe("Path to first file (or alias path1)"),
	"path1?": type("string").describe("Path to first file (alias for path_a)"),
	"path_b?": type("string").describe("Path to second file (or alias path2)"),
	"path2?": type("string").describe("Path to second file (alias for path_b)"),
	"action?": type
		.enumerated("summary", "blocks", "bytes", "headers")
		.describe(
			"Diff action: summary (hash, size, delta, and similarity overview), blocks (block-level change chunks), bytes (contiguous byte-level diff regions with hex/ASCII), or headers (binary format header comparison). Default is summary.",
		),
	"block_size?": type("number.integer >= 64").describe(
		"Block chunk size in bytes for block comparison (default 4096, min 64, max 65536)",
	),
	"limit?": type("number.integer >= 1").describe(
		"Maximum blocks, byte ranges, or entries to return (default 50, max 200)",
	),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum file bytes to read for diffing (default 64MB, max 256MB)",
	),
});

export type BinaryDiffParams = typeof binaryDiffSchema.infer;
export type BinaryDiffAction = NonNullable<BinaryDiffParams["action"]>;

// ============================================================================
// Data Models
// ============================================================================

export interface FileMetadata {
	path: string;
	size: number;
	sha256: string;
	md5: string;
	format?: string;
	architecture?: string;
}

export interface BlockDiffEntry {
	index: number;
	offset: number;
	size: number;
	status: "identical" | "modified" | "inserted" | "deleted";
	differingBytes: number;
	hashA?: string;
	hashB?: string;
}

export interface ByteDiffRegion {
	offset: number;
	length: number;
	bytesA: string;
	bytesB: string;
	asciiA: string;
	asciiB: string;
}

export interface HeaderFieldComparison {
	field: string;
	valueA: string;
	valueB: string;
	matches: boolean;
}

export interface BinaryDiffDetails {
	action: BinaryDiffAction;
	fileA: FileMetadata;
	fileB: FileMetadata;
	isIdentical: boolean;
	sizeDelta: number;
	similarityPercent: number;
	totalDifferingBytes: number;
	firstDifferenceOffset?: number;
	blockSize: number;
	totalBlocks: number;
	identicalBlocks: number;
	modifiedBlocks: number;
	insertedBlocks: number;
	deletedBlocks: number;
	blocks?: BlockDiffEntry[];
	byteDiffs?: ByteDiffRegion[];
	headerComparison?: HeaderFieldComparison[];
}

// ============================================================================
// Header Sniffer
// ============================================================================

interface SniffedHeader {
	format: string;
	architecture?: string;
	bitness?: string;
	endianness?: string;
	entryPoint?: string;
	sectionCount?: number;
}

function sniffHeader(buffer: Buffer): SniffedHeader {
	if (buffer.length >= 4 && buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
		const is64 = buffer[4] === 2;
		const isLe = buffer[5] === 1;
		const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
		const eMachine = view.getUint16(18, isLe);
		let arch = `0x${eMachine.toString(16)}`;
		if (eMachine === 3) arch = "x86";
		else if (eMachine === 62) arch = "x86_64";
		else if (eMachine === 40) arch = "arm";
		else if (eMachine === 183) arch = "aarch64";
		else if (eMachine === 8) arch = "mips";
		else if (eMachine === 243) arch = "riscv";

		const entry = is64 ? view.getBigUint64(24, isLe) : BigInt(view.getUint32(24, isLe));
		const shNum = view.getUint16(is64 ? 60 : 48, isLe);

		return {
			format: "ELF",
			architecture: arch,
			bitness: is64 ? "64-bit" : "32-bit",
			endianness: isLe ? "little" : "big",
			entryPoint: `0x${entry.toString(16)}`,
			sectionCount: shNum,
		};
	}

	if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
		const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
		const eLfanew = view.getUint32(0x3c, true);
		if (eLfanew + 24 <= buffer.length && buffer[eLfanew] === 0x50 && buffer[eLfanew + 1] === 0x45) {
			const machine = view.getUint16(eLfanew + 4, true);
			const numSections = view.getUint16(eLfanew + 6, true);
			const sizeOfOpt = view.getUint16(eLfanew + 20, true);
			const magic = sizeOfOpt >= 2 ? view.getUint16(eLfanew + 24, true) : 0;
			const is64 = magic === 0x20b;
			let arch = `0x${machine.toString(16)}`;
			if (machine === 0x14c) arch = "x86";
			else if (machine === 0x8664) arch = "x86_64";
			else if (machine === 0xaa64) arch = "arm64";

			let entryPoint: string | undefined;
			if (sizeOfOpt >= 20) {
				const ep = view.getUint32(eLfanew + 40, true);
				entryPoint = `0x${ep.toString(16)}`;
			}

			return {
				format: "PE",
				architecture: arch,
				bitness: is64 ? "64-bit (PE32+)" : "32-bit (PE32)",
				endianness: "little",
				entryPoint,
				sectionCount: numSections,
			};
		}
	}

	if (buffer.length >= 4) {
		const m32LE = buffer.readUInt32LE(0);
		const m32BE = buffer.readUInt32BE(0);
		if (m32LE === 0xfeedface || m32LE === 0xfeedfacf || m32BE === 0xfeedface || m32BE === 0xfeedfacf) {
			const is64 = m32LE === 0xfeedfacf || m32BE === 0xfeedfacf;
			const isLe = m32LE === 0xfeedface || m32LE === 0xfeedfacf;
			const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
			const cpuType = view.getUint32(4, isLe);
			let arch = `0x${cpuType.toString(16)}`;
			if (cpuType === 7) arch = "x86";
			else if (cpuType === 0x01000007) arch = "x86_64";
			else if (cpuType === 12) arch = "arm";
			else if (cpuType === 0x0100000c) arch = "arm64";

			return {
				format: "Mach-O",
				architecture: arch,
				bitness: is64 ? "64-bit" : "32-bit",
				endianness: isLe ? "little" : "big",
				sectionCount: view.getUint32(16, isLe),
			};
		}
	}

	if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
		return { format: "ZIP / Archive" };
	}

	if (buffer.length >= 16 && buffer.subarray(0, 15).toString("utf8") === "SQLite format 3") {
		return { format: "SQLite Database" };
	}

	return { format: "Raw / Unknown" };
}

// ============================================================================
// Tool Class
// ============================================================================

export class BinaryDiffTool implements AgentTool<typeof binaryDiffSchema, BinaryDiffDetails> {
	readonly name = "binary_diff";
	readonly approval: ToolTier = "read";
	readonly label = "Binary Diff";
	readonly summary = "Native offline read-only binary diffing between two local files with hashes and block changes.";
	readonly description = binaryDiffDescription;
	readonly parameters = binaryDiffSchema;
	readonly loadMode = "discoverable";
	readonly strict = true;

	constructor(private readonly session: ToolSession) {}

	async execute(
		_toolCallId: string,
		params: BinaryDiffParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<BinaryDiffDetails>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<BinaryDiffDetails> & { details: BinaryDiffDetails }> {
		throwIfAborted(signal);

		const pathA = params.path_a ?? params.path1;
		const pathB = params.path_b ?? params.path2;

		if (!pathA || !pathB) {
			throw new ToolError(
				"Both 'path_a' (or path1) and 'path_b' (or path2) must be specified for binary comparison.",
			);
		}

		const resolvedA = resolveReadPath(pathA, this.session.cwd);
		const resolvedB = resolveReadPath(pathB, this.session.cwd);

		// Guard: safe rejection of identical paths
		if (resolvedA === resolvedB) {
			throw new ToolError(`path_a and path_b must point to distinct files; identical path provided: ${resolvedA}`);
		}

		let statA: Stats;
		let statB: Stats;

		try {
			statA = await fs.stat(resolvedA);
		} catch (err) {
			throw new ToolError(`File A not found: ${pathA} (${err instanceof Error ? err.message : String(err)})`);
		}

		try {
			statB = await fs.stat(resolvedB);
		} catch (err) {
			throw new ToolError(`File B not found: ${pathB} (${err instanceof Error ? err.message : String(err)})`);
		}

		if (statA.isDirectory() || statB.isDirectory()) {
			throw new ToolError("Directories are not supported for binary diff; provide binary files.");
		}

		const realA = await fs.realpath(resolvedA).catch(() => resolvedA);
		const realB = await fs.realpath(resolvedB).catch(() => resolvedB);
		if (realA === realB) {
			throw new ToolError(
				`path_a and path_b resolve to the exact same file (${realA}). Cannot diff identical target.`,
			);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		const blockSize = Math.max(MIN_BLOCK_SIZE, Math.min(params.block_size ?? DEFAULT_BLOCK_SIZE, MAX_BLOCK_SIZE));
		const action = params.action ?? "summary";
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;

		const bytesToReadA = Math.min(statA.size, maxBytes);
		const bytesToReadB = Math.min(statB.size, maxBytes);

		let bufA: Buffer;
		let bufB: Buffer;

		try {
			const fhA = await fs.open(resolvedA, "r");
			try {
				bufA = Buffer.alloc(bytesToReadA);
				const { bytesRead } = await fhA.read(bufA, 0, bytesToReadA, 0);
				bufA = bufA.subarray(0, bytesRead);
			} finally {
				await fhA.close();
			}

			const fhB = await fs.open(resolvedB, "r");
			try {
				bufB = Buffer.alloc(bytesToReadB);
				const { bytesRead } = await fhB.read(bufB, 0, bytesToReadB, 0);
				bufB = bufB.subarray(0, bytesRead);
			} finally {
				await fhB.close();
			}
		} catch (err) {
			throw new ToolError(`Error reading comparison files: ${err instanceof Error ? err.message : String(err)}`);
		}

		throwIfAborted(signal);

		// Compute deterministic hashes
		const sha256A = createHash("sha256").update(bufA).digest("hex");
		const md5A = createHash("md5").update(bufA).digest("hex");
		const sha256B = createHash("sha256").update(bufB).digest("hex");
		const md5B = createHash("md5").update(bufB).digest("hex");

		const headerA = sniffHeader(bufA);
		const headerB = sniffHeader(bufB);

		const isIdentical = statA.size === statB.size && sha256A === sha256B;
		const sizeDelta = statB.size - statA.size;

		// Block and byte-level diff analysis
		const maxLen = Math.max(bufA.length, bufB.length);
		const totalBlocks = Math.ceil(maxLen / blockSize) || 1;

		let identicalBlocks = 0;
		let modifiedBlocks = 0;
		let insertedBlocks = 0;
		let deletedBlocks = 0;
		let totalDifferingBytes = 0;
		let firstDifferenceOffset: number | undefined;

		const allBlockEntries: BlockDiffEntry[] = [];

		for (let i = 0; i < totalBlocks; i++) {
			const blkOffset = i * blockSize;
			const blkEnd = Math.min(maxLen, blkOffset + blockSize);
			const blkSize = blkEnd - blkOffset;

			const inA = blkOffset < bufA.length;
			const inB = blkOffset < bufB.length;

			if (inA && inB) {
				const sliceA = bufA.subarray(blkOffset, Math.min(bufA.length, blkEnd));
				const sliceB = bufB.subarray(blkOffset, Math.min(bufB.length, blkEnd));

				let diffInBlock = 0;
				const compLen = Math.min(sliceA.length, sliceB.length);
				for (let b = 0; b < compLen; b++) {
					if (sliceA[b] !== sliceB[b]) {
						diffInBlock++;
						if (firstDifferenceOffset === undefined) {
							firstDifferenceOffset = blkOffset + b;
						}
					}
				}
				diffInBlock += Math.abs(sliceA.length - sliceB.length);
				if (sliceA.length !== sliceB.length && firstDifferenceOffset === undefined) {
					firstDifferenceOffset = blkOffset + compLen;
				}

				totalDifferingBytes += diffInBlock;

				if (diffInBlock === 0) {
					identicalBlocks++;
					allBlockEntries.push({
						index: i,
						offset: blkOffset,
						size: blkSize,
						status: "identical",
						differingBytes: 0,
					});
				} else {
					modifiedBlocks++;
					const hashA = createHash("md5").update(sliceA).digest("hex");
					const hashB = createHash("md5").update(sliceB).digest("hex");
					allBlockEntries.push({
						index: i,
						offset: blkOffset,
						size: blkSize,
						status: "modified",
						differingBytes: diffInBlock,
						hashA,
						hashB,
					});
				}
			} else if (!inA && inB) {
				// Block only in B
				const sliceB = bufB.subarray(blkOffset, Math.min(bufB.length, blkEnd));
				insertedBlocks++;
				totalDifferingBytes += sliceB.length;
				if (firstDifferenceOffset === undefined) {
					firstDifferenceOffset = blkOffset;
				}
				allBlockEntries.push({
					index: i,
					offset: blkOffset,
					size: blkSize,
					status: "inserted",
					differingBytes: sliceB.length,
					hashB: createHash("md5").update(sliceB).digest("hex"),
				});
			} else {
				// Block only in A
				const sliceA = bufA.subarray(blkOffset, Math.min(bufA.length, blkEnd));
				deletedBlocks++;
				totalDifferingBytes += sliceA.length;
				if (firstDifferenceOffset === undefined) {
					firstDifferenceOffset = blkOffset;
				}
				allBlockEntries.push({
					index: i,
					offset: blkOffset,
					size: blkSize,
					status: "deleted",
					differingBytes: sliceA.length,
					hashA: createHash("md5").update(sliceA).digest("hex"),
				});
			}
		}

		if (statA.size > maxBytes || statB.size > maxBytes) {
			// Account for unread byte differences
			totalDifferingBytes += Math.abs(statA.size - statB.size);
		}

		const identicalBytes = Math.max(0, Math.max(statA.size, statB.size) - totalDifferingBytes);
		const denominator = Math.max(statA.size, statB.size, 1);
		const similarityPercent = isIdentical ? 100.0 : Math.round((identicalBytes / denominator) * 10000) / 100;

		const fileMetadataA: FileMetadata = {
			path: resolvedA,
			size: statA.size,
			sha256: sha256A,
			md5: md5A,
			format: headerA.format,
			architecture: headerA.architecture,
		};

		const fileMetadataB: FileMetadata = {
			path: resolvedB,
			size: statB.size,
			sha256: sha256B,
			md5: md5B,
			format: headerB.format,
			architecture: headerB.architecture,
		};

		// ------------------------------------------------------------------------
		// Action: summary
		// ------------------------------------------------------------------------
		if (action === "summary") {
			const deltaSign = sizeDelta > 0 ? `+${sizeDelta}` : `${sizeDelta}`;
			const lines = [
				`# Binary Diff Summary`,
				"",
				`| Metric | File A (\`${path.basename(resolvedA)}\`) | File B (\`${path.basename(resolvedB)}\`) | Comparison |`,
				`|---|---|---|---|`,
				`| **File Path** | \`${resolvedA}\` | \`${resolvedB}\` | - |`,
				`| **File Size** | ${formatBytes(statA.size)} (${statA.size} B) | ${formatBytes(statB.size)} (${statB.size} B) | Delta: **${deltaSign} B** |`,
				`| **Format** | \`${headerA.format}\` | \`${headerB.format}\` | ${headerA.format === headerB.format ? "Matched" : "⚠️ Differing format"} |`,
				`| **SHA-256** | \`${sha256A}\` | \`${sha256B}\` | ${isIdentical ? "✅ Identical" : "⚠️ Different"} |`,
				`| **MD5** | \`${md5A}\` | \`${md5B}\` | ${isIdentical ? "✅ Identical" : "⚠️ Different"} |`,
				"",
				"## Diff Metrics",
				`| Metric | Value |`,
				`|---|---|`,
				`| **Status** | ${isIdentical ? "✅ **Identical**" : "⚠️ **Modified / Differing**"} |`,
				`| **Similarity** | **${similarityPercent.toFixed(2)}%** |`,
				`| **Differing Bytes** | ${formatBytes(totalDifferingBytes)} (${totalDifferingBytes} bytes) |`,
				`| **First Difference Offset** | ${firstDifferenceOffset !== undefined ? `\`0x${firstDifferenceOffset.toString(16)}\` (${firstDifferenceOffset})` : "None"} |`,
				`First Difference Offset: ${firstDifferenceOffset !== undefined ? `0x${firstDifferenceOffset.toString(16)} (${firstDifferenceOffset})` : "None"}`,
				`| **Total Blocks** | ${totalBlocks} |`,
				`| **Identical Blocks** | ${identicalBlocks} |`,
				`| **Modified Blocks** | ${modifiedBlocks} |`,
				`| **Inserted Blocks** | ${insertedBlocks} |`,
				`| **Deleted Blocks** | ${deletedBlocks} |`,
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "summary",
					fileA: fileMetadataA,
					fileB: fileMetadataB,
					isIdentical,
					sizeDelta,
					similarityPercent,
					totalDifferingBytes,
					firstDifferenceOffset,
					blockSize,
					totalBlocks,
					identicalBlocks,
					modifiedBlocks,
					insertedBlocks,
					deletedBlocks,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: blocks
		// ------------------------------------------------------------------------
		if (action === "blocks") {
			// Show changed blocks first or paged
			const changedBlocks = allBlockEntries.filter(b => b.status !== "identical");
			const pagedBlocks = (changedBlocks.length > 0 ? changedBlocks : allBlockEntries).slice(offset, offset + limit);

			const lines = [
				`# Binary Block Diff: \`${path.basename(resolvedA)}\` vs \`${path.basename(resolvedB)}\``,
				`*Block size: ${formatBytes(blockSize)} | Showing ${pagedBlocks.length} of ${changedBlocks.length > 0 ? changedBlocks.length : allBlockEntries.length} blocks*`,
				"",
				`| Block # | Offset | Size | Status | Differing Bytes | Hash A (MD5) | Hash B (MD5) |`,
				`|---|---|---|---|---|---|---|`,
			];

			for (const b of pagedBlocks) {
				const offHex = `0x${b.offset.toString(16).padStart(6, "0")}`;
				const statusBadge =
					b.status === "identical"
						? "identical"
						: b.status === "modified"
							? "🟡 **modified**"
							: b.status === "inserted"
								? "🟢 **inserted**"
								: "🔴 **deleted**";
				const hA = b.hashA ? `\`${b.hashA.slice(0, 8)}...\`` : "-";
				const hB = b.hashB ? `\`${b.hashB.slice(0, 8)}...\`` : "-";
				lines.push(
					`| ${b.index} | \`${offHex}\` | ${formatBytes(b.size)} | ${statusBadge} | ${b.differingBytes} B | ${hA} | ${hB} |`,
				);
			}

			const targetListLen = changedBlocks.length > 0 ? changedBlocks.length : allBlockEntries.length;
			if (targetListLen > offset + limit) {
				lines.push(`*...and ${targetListLen - (offset + limit)} more blocks (use \`offset\` to paginate)*`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "blocks",
					fileA: fileMetadataA,
					fileB: fileMetadataB,
					isIdentical,
					sizeDelta,
					similarityPercent,
					totalDifferingBytes,
					firstDifferenceOffset,
					blockSize,
					totalBlocks,
					identicalBlocks,
					modifiedBlocks,
					insertedBlocks,
					deletedBlocks,
					blocks: pagedBlocks,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: bytes
		// ------------------------------------------------------------------------
		if (action === "bytes") {
			const byteRegions: ByteDiffRegion[] = [];
			let regionStart = -1;

			const toAscii = (buf: Buffer, start: number, len: number): string => {
				let s = "";
				for (let i = 0; i < len; i++) {
					const c = buf[start + i];
					s += c >= 32 && c <= 126 ? String.fromCharCode(c) : ".";
				}
				return s;
			};

			const minB = Math.min(bufA.length, bufB.length);
			for (let i = 0; i < minB; i++) {
				if (bufA[i] !== bufB[i]) {
					if (regionStart === -1) regionStart = i;
				} else {
					if (regionStart !== -1) {
						const rLen = i - regionStart;
						const sliceA = bufA.subarray(regionStart, regionStart + Math.min(rLen, 16));
						const sliceB = bufB.subarray(regionStart, regionStart + Math.min(rLen, 16));
						byteRegions.push({
							offset: regionStart,
							length: rLen,
							bytesA: sliceA.toString("hex").match(/../g)?.join(" ") ?? "",
							bytesB: sliceB.toString("hex").match(/../g)?.join(" ") ?? "",
							asciiA: toAscii(bufA, regionStart, sliceA.length),
							asciiB: toAscii(bufB, regionStart, sliceB.length),
						});
						regionStart = -1;
					}
				}
			}

			if (regionStart !== -1) {
				const rLen = minB - regionStart;
				const sliceA = bufA.subarray(regionStart, regionStart + Math.min(rLen, 16));
				const sliceB = bufB.subarray(regionStart, regionStart + Math.min(rLen, 16));
				byteRegions.push({
					offset: regionStart,
					length: rLen,
					bytesA: sliceA.toString("hex").match(/../g)?.join(" ") ?? "",
					bytesB: sliceB.toString("hex").match(/../g)?.join(" ") ?? "",
					asciiA: toAscii(bufA, regionStart, sliceA.length),
					asciiB: toAscii(bufB, regionStart, sliceB.length),
				});
			}

			// Size difference region
			if (bufA.length !== bufB.length) {
				const extraLen = Math.abs(bufA.length - bufB.length);
				const isAExtra = bufA.length > bufB.length;
				const extraBuf = isAExtra ? bufA : bufB;
				const slice = extraBuf.subarray(minB, minB + Math.min(extraLen, 16));
				byteRegions.push({
					offset: minB,
					length: extraLen,
					bytesA: isAExtra ? (slice.toString("hex").match(/../g)?.join(" ") ?? "") : "[truncated]",
					bytesB: !isAExtra ? (slice.toString("hex").match(/../g)?.join(" ") ?? "") : "[truncated]",
					asciiA: isAExtra ? toAscii(bufA, minB, slice.length) : "-",
					asciiB: !isAExtra ? toAscii(bufB, minB, slice.length) : "-",
				});
			}

			const pagedRegions = byteRegions.slice(offset, offset + limit);

			const lines = [
				`# Byte-Level Differences: \`${path.basename(resolvedA)}\` vs \`${path.basename(resolvedB)}\``,
				`*Found ${byteRegions.length} differing byte regions | Showing ${pagedRegions.length}*`,
				"",
				`| Offset | Length | File A Hex | File A ASCII | File B Hex | File B ASCII |`,
				`|---|---|---|---|---|---|`,
			];

			for (const r of pagedRegions) {
				const offHex = `0x${r.offset.toString(16).padStart(6, "0")}`;
				lines.push(
					`| \`${offHex}\` | ${r.length} B | \`${r.bytesA}\` | \`${r.asciiA}\` | \`${r.bytesB}\` | \`${r.asciiB}\` |`,
				);
			}

			if (byteRegions.length > offset + limit) {
				lines.push(
					`*...and ${byteRegions.length - (offset + limit)} more byte regions (use \`offset\` to paginate)*`,
				);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "bytes",
					fileA: fileMetadataA,
					fileB: fileMetadataB,
					isIdentical,
					sizeDelta,
					similarityPercent,
					totalDifferingBytes,
					firstDifferenceOffset,
					blockSize,
					totalBlocks,
					identicalBlocks,
					modifiedBlocks,
					insertedBlocks,
					deletedBlocks,
					byteDiffs: pagedRegions,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: headers
		// ------------------------------------------------------------------------
		if (action === "headers") {
			const comparison: HeaderFieldComparison[] = [
				{
					field: "Format",
					valueA: headerA.format,
					valueB: headerB.format,
					matches: headerA.format === headerB.format,
				},
				{
					field: "Architecture",
					valueA: headerA.architecture ?? "unknown",
					valueB: headerB.architecture ?? "unknown",
					matches: headerA.architecture === headerB.architecture,
				},
				{
					field: "Bitness",
					valueA: headerA.bitness ?? "unknown",
					valueB: headerB.bitness ?? "unknown",
					matches: headerA.bitness === headerB.bitness,
				},
				{
					field: "Endianness",
					valueA: headerA.endianness ?? "unknown",
					valueB: headerB.endianness ?? "unknown",
					matches: headerA.endianness === headerB.endianness,
				},
				{
					field: "Entry Point",
					valueA: headerA.entryPoint ?? "none",
					valueB: headerB.entryPoint ?? "none",
					matches: headerA.entryPoint === headerB.entryPoint,
				},
				{
					field: "Section / Header Count",
					valueA: headerA.sectionCount !== undefined ? String(headerA.sectionCount) : "none",
					valueB: headerB.sectionCount !== undefined ? String(headerB.sectionCount) : "none",
					matches: headerA.sectionCount === headerB.sectionCount,
				},
			];

			const lines = [
				`# Binary Header Comparison: \`${path.basename(resolvedA)}\` vs \`${path.basename(resolvedB)}\``,
				"",
				`| Header Field | File A | File B | Status |`,
				`|---|---|---|---|`,
			];

			for (const c of comparison) {
				const status = c.matches ? "✅ Matched" : "⚠️ **Differing**";
				lines.push(`| **${c.field}** | \`${c.valueA}\` | \`${c.valueB}\` | ${status} |`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "headers",
					fileA: fileMetadataA,
					fileB: fileMetadataB,
					isIdentical,
					sizeDelta,
					similarityPercent,
					totalDifferingBytes,
					firstDifferenceOffset,
					blockSize,
					totalBlocks,
					identicalBlocks,
					modifiedBlocks,
					insertedBlocks,
					deletedBlocks,
					headerComparison: comparison,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
