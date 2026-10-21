import * as fs from "node:fs/promises";
import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes, prompt } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import firmwareInspectDescription from "../prompts/tools/firmware-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_BLOCK_SIZE = 64 * 1024; // 64 KiB
const MIN_BLOCK_SIZE = 512;
const MAX_BLOCK_SIZE = 1024 * 1024; // 1 MiB
const DEFAULT_MAX_BYTES = 100 * 1024 * 1024; // 100 MB
const HARD_MAX_BYTES = 500 * 1024 * 1024; // 500 MB

// ============================================================================
// Parameter Schema
// ============================================================================

const firmwareInspectSchema = type({
	action: type
		.enumerated("info", "regions", "entries", "entropy")
		.describe(
			"Inspection action: info (format, size, hashes, entropy, embedded regions summary, container headers), regions (detected partitions, filesystem headers, bootloaders, containers with offsets, magic, size, entropy), entries (inventory files/members inside embedded archives or filesystems like TAR, CPIO, ZIP, SquashFS), or entropy (block-by-block Shannon entropy scan across the image)",
		),
	path: type("string").describe("Path to target firmware image, ROM, or container file"),
	"limit?": type("number.integer >= 1").describe(
		"Maximum regions, file entries, or entropy blocks to return (default 50, max 500)",
	),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"block_size?": type("number.integer >= 512").describe(
		"Block/chunk size in bytes for entropy scanning (default 65536, min 512, max 1048576)",
	),
	"path_filter?": type("string").describe("Filter file entries by filename or path substring (for 'entries' action)"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum image bytes to read and scan (default 100MB, max 500MB)",
	),
});

export type FirmwareInspectParams = typeof firmwareInspectSchema.infer;
export type FirmwareInspectAction = FirmwareInspectParams["action"];

// ============================================================================
// Internal Data Models
// ============================================================================

export interface FirmwareRegion {
	offset: number;
	name: string;
	format: string;
	size?: number;
	entropy?: number;
	compression?: string;
	description: string;
	metadata?: Record<string, string | number | boolean>;
}

export interface FirmwareEntry {
	path: string;
	size: number;
	compressedSize?: number;
	type: "file" | "directory" | "symlink" | "block_device" | "char_device" | "fifo" | "other";
	offset?: number;
	mode?: string;
	mtime?: string;
	container: string;
}

export interface FirmwareEntropyBlock {
	offset: number;
	size: number;
	entropy: number;
	classification: "sparse" | "text_data" | "code_data" | "compressed_or_encrypted";
}

export interface FirmwareInspectDetails {
	action: FirmwareInspectAction;
	targetPath: string;
	fileSize: number;
	sha256: string;
	md5: string;
	overallEntropy: number;
	primaryFormat: string;
	regionsSummary?: {
		totalDetected: number;
		regions: FirmwareRegion[];
	};
	containerSummary?: {
		format: string;
		entryCount?: number;
		totalUncompressedSize?: number;
	};
	regions?: FirmwareRegion[];
	entries?: FirmwareEntry[];
	totalEntries?: number;
	entropyBlocks?: FirmwareEntropyBlock[];
	totalBlocks?: number;
}

// ============================================================================
// Entropy & Math Helpers
// ============================================================================

export function computeShannonEntropy(buffer: Uint8Array): number {
	if (buffer.length === 0) return 0;
	const frequencies = new Uint32Array(256);
	for (let i = 0; i < buffer.length; i++) {
		frequencies[buffer[i]]++;
	}
	let entropy = 0;
	const total = buffer.length;
	const log2 = Math.log2;
	for (let i = 0; i < 256; i++) {
		const count = frequencies[i];
		if (count > 0) {
			const p = count / total;
			entropy -= p * log2(p);
		}
	}
	return Number(entropy.toFixed(4));
}

function classifyEntropy(entropy: number): FirmwareEntropyBlock["classification"] {
	if (entropy < 1.0) return "sparse";
	if (entropy < 5.0) return "text_data";
	if (entropy < 7.2) return "code_data";
	return "compressed_or_encrypted";
}

function renderEntropyBar(entropy: number, width = 10): string {
	const filled = Math.min(width, Math.max(0, Math.round((entropy / 8.0) * width)));
	const empty = width - filled;
	return `[${"█".repeat(filled)}${"░".repeat(empty)}]`;
}

// ============================================================================
// Signature & Container Constants
// ============================================================================

const UIMAGE_OS_MAP: Record<number, string> = {
	1: "OpenBSD",
	2: "NetBSD",
	3: "FreeBSD",
	4: "4.4BSD",
	5: "Linux",
	6: "SVR4",
	7: "Esix",
	8: "Solaris",
	9: "Irix",
	10: "SCO",
	11: "Dell",
	12: "NCR",
	13: "LynxOS",
	14: "VxWorks",
	15: "psOS",
	16: "QNX",
	17: "U-Boot",
	18: "RTEMS",
	19: "ARTOS",
	20: "Unity",
	21: "Integrity",
};

const UIMAGE_ARCH_MAP: Record<number, string> = {
	1: "Alpha",
	2: "ARM",
	3: "x86",
	4: "IA64",
	5: "MIPS",
	6: "MIPS64",
	7: "PowerPC",
	8: "S390",
	9: "SuperH",
	10: "SPARC",
	11: "SPARC64",
	12: "M68K",
	14: "ARM64",
	15: "RISC-V",
};

const UIMAGE_TYPE_MAP: Record<number, string> = {
	1: "Standalone Program",
	2: "OS Kernel Image",
	3: "RAMDisk Image",
	4: "Multi-File Image",
	5: "Firmware Image",
	6: "Script",
	7: "Filesystem Image",
	8: "Flat Device Tree Blob",
};

const UIMAGE_COMP_MAP: Record<number, string> = {
	0: "none",
	1: "gzip",
	2: "bzip2",
	3: "lzma",
	4: "lzo",
	5: "lz4",
	6: "zstd",
};

const SQUASHFS_COMP_MAP: Record<number, string> = {
	1: "gzip",
	2: "lzma",
	3: "lzo",
	4: "xz",
	5: "lz4",
	6: "zstd",
};

// ============================================================================
// Specialized Container / Header Parsers
// ============================================================================

/** Parse U-Boot legacy uImage header at specific offset */
function parseUImageHeader(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 64 > buf.length) return null;
	if (buf.readUInt32BE(offset) !== 0x27051956) return null;

	const headerCrc = buf.readUInt32BE(offset + 4);
	const timestamp = buf.readUInt32BE(offset + 8);
	const dataSize = buf.readUInt32BE(offset + 12);
	const loadAddr = buf.readUInt32BE(offset + 16);
	const entryPoint = buf.readUInt32BE(offset + 20);
	const dataCrc = buf.readUInt32BE(offset + 24);
	const osId = buf[offset + 28];
	const archId = buf[offset + 29];
	const typeId = buf[offset + 30];
	const compId = buf[offset + 31];

	// Null-terminated image name (32 bytes)
	let nameEnd = offset + 32;
	while (nameEnd < offset + 64 && buf[nameEnd] !== 0) nameEnd++;
	const imageName = buf.toString("utf8", offset + 32, nameEnd).trim();

	const osName = UIMAGE_OS_MAP[osId] ?? `OS-${osId}`;
	const archName = UIMAGE_ARCH_MAP[archId] ?? `Arch-${archId}`;
	const typeName = UIMAGE_TYPE_MAP[typeId] ?? `Type-${typeId}`;
	const compName = UIMAGE_COMP_MAP[compId] ?? "unknown";

	const totalSize = 64 + dataSize;
	const regionBuf = buf.subarray(offset, Math.min(buf.length, offset + totalSize));
	const entropy = computeShannonEntropy(regionBuf);

	const timeStr = timestamp > 0 ? new Date(timestamp * 1000).toISOString() : "unknown";
	const desc = `uImage header: "${imageName}" (${osName} ${archName} ${typeName}, comp: ${compName}, load: 0x${loadAddr.toString(16)}, entry: 0x${entryPoint.toString(16)}, size: ${formatBytes(dataSize)}, built: ${timeStr})`;

	return {
		offset,
		name: imageName.length > 0 ? imageName : "uImage",
		format: "uImage",
		size: totalSize,
		entropy,
		compression: compName,
		description: desc,
		metadata: {
			os: osName,
			arch: archName,
			type: typeName,
			compression: compName,
			loadAddress: `0x${loadAddr.toString(16).padStart(8, "0")}`,
			entryPoint: `0x${entryPoint.toString(16).padStart(8, "0")}`,
			dataSize,
			headerCrc: `0x${headerCrc.toString(16)}`,
			dataCrc: `0x${dataCrc.toString(16)}`,
			timestamp: timeStr,
		},
	};
}

/** Parse Flattened Device Tree (FIT / DTB) header */
function parseFitHeader(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 32 > buf.length) return null;
	if (buf.readUInt32BE(offset) !== 0xd00dfeed) return null;

	const totalSize = buf.readUInt32BE(offset + 4);
	const version = buf.readUInt32BE(offset + 20);
	const bootCpuid = buf.readUInt32BE(offset + 28);

	if (totalSize < 32 || totalSize > 100 * 1024 * 1024) return null;

	const regionBuf = buf.subarray(offset, Math.min(buf.length, offset + totalSize));
	const entropy = computeShannonEntropy(regionBuf);

	return {
		offset,
		name: "Device Tree Blob / FIT",
		format: "FIT / FDT",
		size: totalSize,
		entropy,
		compression: "none",
		description: `Flattened Device Tree blob (version: ${version}, boot CPU: ${bootCpuid}, total size: ${formatBytes(totalSize)})`,
		metadata: {
			version,
			bootCpuid,
			totalSize,
		},
	};
}

/** Parse SquashFS superblock at specific offset */
function parseSquashfsSuperblock(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 96 > buf.length) return null;

	const magicLE = buf.readUInt32LE(offset);
	const magicBE = buf.readUInt32BE(offset);

	let isLE = false;
	let version = 4;

	if (magicLE === 0x73717368) {
		isLE = true;
	} else if (magicBE === 0x68737173) {
		isLE = false;
	} else {
		return null;
	}

	const sMajor = isLE ? buf.readUInt16LE(offset + 28) : buf.readUInt16BE(offset + 28);
	const sMinor = isLE ? buf.readUInt16LE(offset + 30) : buf.readUInt16BE(offset + 30);

	// Validate SquashFS version
	if (sMajor < 1 || sMajor > 4) return null;
	version = sMajor;

	let inodes = 0;
	let blockSize = 0;
	let compId = 1;
	let bytesUsed = 0;
	let mkfsTime = 0;

	if (version === 4) {
		inodes = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
		mkfsTime = isLE ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
		blockSize = isLE ? buf.readUInt32LE(offset + 12) : buf.readUInt32BE(offset + 12);
		compId = isLE ? buf.readUInt16LE(offset + 20) : buf.readUInt16BE(offset + 20);
		const bytesUsedLo = isLE ? buf.readUInt32LE(offset + 40) : buf.readUInt32BE(offset + 44);
		const bytesUsedHi = isLE ? buf.readUInt32LE(offset + 44) : buf.readUInt32BE(offset + 40);
		bytesUsed = bytesUsedHi * 4294967296 + bytesUsedLo;
	} else {
		// v3 / v2
		inodes = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
		blockSize = isLE ? buf.readUInt32LE(offset + 12) : buf.readUInt32BE(offset + 12);
		mkfsTime = isLE ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
		bytesUsed = isLE ? buf.readUInt32LE(offset + 20) : buf.readUInt32BE(offset + 20);
	}

	// Validate block size (must be power of 2 between 4096 and 1048576)
	if (blockSize < 4096 || blockSize > 1048576 || (blockSize & (blockSize - 1)) !== 0) {
		return null;
	}

	const compName = SQUASHFS_COMP_MAP[compId] ?? `comp-${compId}`;
	const timeStr = mkfsTime > 0 ? new Date(mkfsTime * 1000).toISOString() : "unknown";
	const regionSize = bytesUsed > 0 ? bytesUsed : Math.min(buf.length - offset, 1024 * 1024);
	const regionBuf = buf.subarray(offset, Math.min(buf.length, offset + regionSize));
	const entropy = computeShannonEntropy(regionBuf);

	const endianStr = isLE ? "little-endian" : "big-endian";
	const desc = `SquashFS v${sMajor}.${sMinor} superblock (${endianStr}, comp: ${compName}, inodes: ${inodes}, block_size: ${formatBytes(blockSize)}, fs_size: ${formatBytes(bytesUsed)}, created: ${timeStr})`;

	return {
		offset,
		name: `SquashFS v${sMajor}.${sMinor}`,
		format: `SquashFS ${sMajor}.x`,
		size: bytesUsed > 0 ? bytesUsed : undefined,
		entropy,
		compression: compName,
		description: desc,
		metadata: {
			version: `${sMajor}.${sMinor}`,
			endianness: endianStr,
			compression: compName,
			inodes,
			blockSize,
			bytesUsed,
			created: timeStr,
		},
	};
}

/** Parse CramFS superblock at specific offset */
function parseCramfsSuperblock(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 64 > buf.length) return null;

	const magicLE = buf.readUInt32LE(offset);
	const magicBE = buf.readUInt32BE(offset);

	let isLE = false;
	if (magicLE === 0x28cd3d45) {
		isLE = true;
	} else if (magicBE === 0x453dcd28) {
		isLE = false;
	} else {
		return null;
	}

	const size = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
	const flags = isLE ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);

	// Read name (16 bytes null-terminated ASCII)
	let nameEnd = offset + 48;
	while (nameEnd < offset + 64 && buf[nameEnd] !== 0) nameEnd++;
	const name = buf.toString("ascii", offset + 48, nameEnd).trim();

	const regionBuf = buf.subarray(offset, Math.min(buf.length, offset + size));
	const entropy = computeShannonEntropy(regionBuf);

	return {
		offset,
		name: name.length > 0 ? `CramFS: ${name}` : "CramFS",
		format: "CramFS",
		size,
		entropy,
		compression: "zlib",
		description: `CramFS filesystem "${name}" (size: ${formatBytes(size)}, flags: 0x${flags.toString(16)})`,
		metadata: {
			name,
			size,
			flags: `0x${flags.toString(16)}`,
		},
	};
}

/** Parse JFFS2 partition node at specific offset */
function parseJffs2Node(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 12 > buf.length) return null;
	const magic = buf.readUInt16LE(offset);
	if (magic !== 0x1985 && magic !== 0x8519) return null;

	const isLE = magic === 0x1985;
	const nodetype = isLE ? buf.readUInt16LE(offset + 2) : buf.readUInt16BE(offset + 2);
	const totlen = isLE ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);

	if (totlen < 12 || totlen > 64 * 1024) return null;

	return {
		offset,
		name: "JFFS2 Node",
		format: "JFFS2",
		size: totlen,
		compression: "mixed",
		description: `JFFS2 log-structured flash filesystem node (type: 0x${nodetype.toString(16)}, length: ${totlen})`,
		metadata: {
			nodetype: `0x${nodetype.toString(16)}`,
			totlen,
		},
	};
}

/** Parse Linux ARM zImage header */
function parseArmZImage(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 0x30 > buf.length) return null;
	// ARM zImage magic is at offset + 0x24: 0x016f2818
	const magic = buf.readUInt32LE(offset + 0x24);
	if (magic !== 0x016f2818) return null;

	const startAddr = buf.readUInt32LE(offset + 0x28);
	const endAddr = buf.readUInt32LE(offset + 0x2c);
	const size = endAddr > startAddr ? endAddr - startAddr : undefined;

	const regionBuf = buf.subarray(offset, Math.min(buf.length, offset + (size ?? 1024 * 1024)));
	const entropy = computeShannonEntropy(regionBuf);

	return {
		offset,
		name: "Linux ARM zImage",
		format: "ARM zImage",
		size,
		entropy,
		compression: "gzip/lzma/xz",
		description: `Linux ARM self-extracting kernel zImage (start: 0x${startAddr.toString(16)}, end: 0x${endAddr.toString(16)}, size: ${size ? formatBytes(size) : "unknown"})`,
		metadata: {
			startAddress: `0x${startAddr.toString(16)}`,
			endAddress: `0x${endAddr.toString(16)}`,
			size: size ?? 0,
		},
	};
}

/** Parse ELF header embedded in firmware */
function parseElfHeader(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 52 > buf.length) return null;
	if (buf[offset] !== 0x7f || buf[offset + 1] !== 0x45 || buf[offset + 2] !== 0x4c || buf[offset + 3] !== 0x46) {
		return null;
	}

	const is64 = buf[offset + 4] === 2;
	const isLE = buf[offset + 5] === 1;
	const machine = isLE ? buf.readUInt16LE(offset + 18) : buf.readUInt16BE(offset + 18);

	const archMap: Record<number, string> = {
		3: "x86",
		62: "x86_64",
		40: "ARM",
		183: "AArch64",
		8: "MIPS",
		243: "RISC-V",
	};
	const archName = archMap[machine] ?? `arch-${machine}`;

	let entryPoint = 0;
	if (is64) {
		entryPoint = isLE ? Number(buf.readBigUInt64LE(offset + 24)) : Number(buf.readBigUInt64BE(offset + 24));
	} else {
		entryPoint = isLE ? buf.readUInt32LE(offset + 24) : buf.readUInt32BE(offset + 24);
	}

	return {
		offset,
		name: `ELF Binary (${archName})`,
		format: `ELF ${is64 ? "64-bit" : "32-bit"}`,
		compression: "none",
		description: `Embedded ELF executable / module (${is64 ? "64-bit" : "32-bit"}, ${archName}, entry: 0x${entryPoint.toString(16)})`,
		metadata: {
			bitness: is64 ? 64 : 32,
			arch: archName,
			entryPoint: `0x${entryPoint.toString(16)}`,
		},
	};
}

/** Parse compressed stream headers (GZIP, XZ, BZIP2, LZ4, ZSTD) */
function parseCompressedStream(buf: Buffer, offset: number): FirmwareRegion | null {
	if (offset + 10 > buf.length) return null;

	// GZIP: 1F 8B 08
	if (buf[offset] === 0x1f && buf[offset + 1] === 0x8b && buf[offset + 2] === 0x08) {
		const mtime = buf.readUInt32LE(offset + 4);
		const timeStr = mtime > 0 ? new Date(mtime * 1000).toISOString() : "unknown";
		return {
			offset,
			name: "GZIP compressed stream",
			format: "gzip",
			compression: "deflate",
			description: `GZIP compressed data stream (mtime: ${timeStr})`,
		};
	}

	// XZ: FD 37 7A 58 5A 00
	if (
		buf[offset] === 0xfd &&
		buf[offset + 1] === 0x37 &&
		buf[offset + 2] === 0x7a &&
		buf[offset + 3] === 0x58 &&
		buf[offset + 4] === 0x5a &&
		buf[offset + 5] === 0x00
	) {
		return {
			offset,
			name: "XZ compressed stream",
			format: "xz",
			compression: "lzma2",
			description: "XZ compressed container stream",
		};
	}

	// BZIP2: 42 5A 68 ('BZh')
	if (buf[offset] === 0x42 && buf[offset + 1] === 0x5a && buf[offset + 2] === 0x68) {
		const blockSize = String.fromCharCode(buf[offset + 3]);
		return {
			offset,
			name: "BZIP2 compressed stream",
			format: "bzip2",
			compression: "bzip2",
			description: `BZIP2 compressed stream (block size: ${blockSize}00k)`,
		};
	}

	// LZ4: 04 22 4D 18
	if (buf[offset] === 0x04 && buf[offset + 1] === 0x22 && buf[offset + 2] === 0x4d && buf[offset + 3] === 0x18) {
		return {
			offset,
			name: "LZ4 compressed frame",
			format: "lz4",
			compression: "lz4",
			description: "LZ4 framed data stream",
		};
	}

	// ZSTD: 28 B5 2F FD
	if (buf[offset] === 0x28 && buf[offset + 1] === 0xb5 && buf[offset + 2] === 0x2f && buf[offset + 3] === 0xfd) {
		return {
			offset,
			name: "Zstandard compressed stream",
			format: "zstd",
			compression: "zstd",
			description: "Zstandard (zstd) compressed frame",
		};
	}

	return null;
}

// ============================================================================
// Archive Parsing (CPIO, TAR, ZIP) for Entries
// ============================================================================

/** Parse CPIO archive (New ASCII format 070701 / 070702) */
function parseCpioArchive(
	buf: Buffer,
	startOffset: number,
): { region: FirmwareRegion; entries: FirmwareEntry[] } | null {
	if (startOffset + 110 > buf.length) return null;
	const magic = buf.toString("ascii", startOffset, startOffset + 6);
	if (magic !== "070701" && magic !== "070702" && magic !== "070707") return null;

	const entries: FirmwareEntry[] = [];
	let curr = startOffset;
	const isNewAscii = magic === "070701" || magic === "070702";

	while (curr + 110 <= buf.length) {
		const entryMagic = buf.toString("ascii", curr, curr + 6);
		if (entryMagic !== magic) break;

		if (isNewAscii) {
			const modeHex = buf.toString("ascii", curr + 14, curr + 22);
			const mtimeHex = buf.toString("ascii", curr + 46, curr + 54);
			const filesizeHex = buf.toString("ascii", curr + 54, curr + 62);
			const namesizeHex = buf.toString("ascii", curr + 94, curr + 102);

			const mode = Number.parseInt(modeHex, 16);
			const mtime = Number.parseInt(mtimeHex, 16);
			const fileSize = Number.parseInt(filesizeHex, 16);
			const nameSize = Number.parseInt(namesizeHex, 16);

			if (Number.isNaN(fileSize) || Number.isNaN(nameSize) || nameSize <= 0 || fileSize < 0) {
				break;
			}

			const nameOffset = curr + 110;
			if (nameOffset + nameSize > buf.length) break;

			let name = buf.toString("utf8", nameOffset, nameOffset + nameSize);
			if (name.endsWith("\0")) name = name.slice(0, -1);

			const headerAndNameLen = 110 + nameSize;
			const paddedHeaderLen = (headerAndNameLen + 3) & ~3;
			const paddedFileLen = (fileSize + 3) & ~3;

			if (curr + paddedHeaderLen + fileSize > buf.length) break;

			if (name === "TRAILER!!!") {
				curr += paddedHeaderLen + paddedFileLen;
				while (curr < buf.length && buf[curr] === 0 && curr % 512 !== 0) {
					curr++;
				}
				break;
			}
			const safeMode = Number.isNaN(mode) ? 0o100644 : mode;
			const safeMtime = Number.isNaN(mtime) ? 0 : mtime;

			// File type decoding
			const fileTypeMask = safeMode & 0xf000;
			let type: FirmwareEntry["type"] = "file";
			if (fileTypeMask === 0x4000) type = "directory";
			else if (fileTypeMask === 0xa000) type = "symlink";
			else if (fileTypeMask === 0x6000) type = "block_device";
			else if (fileTypeMask === 0x2000) type = "char_device";
			else if (fileTypeMask === 0x1000) type = "fifo";

			entries.push({
				path: name,
				size: fileSize,
				type,
				offset: curr,
				mode: `0${(safeMode & 0o777).toString(8)}`,
				mtime: safeMtime > 0 ? new Date(safeMtime * 1000).toISOString() : undefined,
				container: "cpio",
			});

			curr += paddedHeaderLen + paddedFileLen;
		} else {
			// Old ASCII format (070707)
			break;
		}
	}

	if (entries.length === 0) return null;

	const totalSize = curr - startOffset;
	const region: FirmwareRegion = {
		offset: startOffset,
		name: "CPIO Archive (initramfs)",
		format: "CPIO",
		size: totalSize > 0 ? totalSize : undefined,
		compression: "none",
		description: `CPIO archive containing ${entries.length} members (size: ${formatBytes(totalSize)})`,
		metadata: {
			memberCount: entries.length,
		},
	};

	return { region, entries };
}

/** Parse POSIX TAR archive */
function parseTarArchive(
	buf: Buffer,
	startOffset: number,
): { region: FirmwareRegion; entries: FirmwareEntry[] } | null {
	if (startOffset + 512 > buf.length) return null;
	const magic = buf.toString("ascii", startOffset + 257, startOffset + 262);
	if (magic !== "ustar\0" && magic !== "ustar ") return null;

	const entries: FirmwareEntry[] = [];
	let curr = startOffset;

	while (curr + 512 <= buf.length) {
		// End of archive is marked by two consecutive 512-byte blocks of zeroes
		const isZero = buf.subarray(curr, curr + 512).every(b => b === 0);
		if (isZero) {
			curr += 512;
			if (curr + 512 <= buf.length && buf.subarray(curr, curr + 512).every(b => b === 0)) {
				curr += 512;
			}
			break;
		}

		let name = buf
			.toString("utf8", curr, curr + 100)
			.replace(/\0.*$/, "")
			.trim();
		const prefix = buf
			.toString("utf8", curr + 345, curr + 500)
			.replace(/\0.*$/, "")
			.trim();
		if (prefix) name = `${prefix}/${name}`;

		if (!name) break;

		const modeStr = buf
			.toString("ascii", curr + 100, curr + 108)
			.replace(/\0.*$/, "")
			.trim();
		const sizeStr = buf
			.toString("ascii", curr + 124, curr + 136)
			.replace(/\0.*$/, "")
			.trim();
		const mtimeStr = buf
			.toString("ascii", curr + 136, curr + 148)
			.replace(/\0.*$/, "")
			.trim();
		const typeflag = String.fromCharCode(buf[curr + 156]);

		const size = Number.parseInt(sizeStr, 8) || 0;
		const mode = Number.parseInt(modeStr, 8) || 0;
		const mtime = Number.parseInt(mtimeStr, 8) || 0;

		let type: FirmwareEntry["type"] = "file";
		if (typeflag === "5") type = "directory";
		else if (typeflag === "2") type = "symlink";
		else if (typeflag === "3") type = "char_device";
		else if (typeflag === "4") type = "block_device";
		else if (typeflag === "6") type = "fifo";

		entries.push({
			path: name,
			size,
			type,
			offset: curr,
			mode: `0${(mode & 0o777).toString(8)}`,
			mtime: mtime > 0 ? new Date(mtime * 1000).toISOString() : undefined,
			container: "tar",
		});

		const paddedSize = Math.ceil(size / 512) * 512;
		curr += 512 + paddedSize;
	}

	const totalSize = curr - startOffset;
	const region: FirmwareRegion = {
		offset: startOffset,
		name: "POSIX TAR Archive",
		format: "TAR",
		size: totalSize > 0 ? totalSize : undefined,
		compression: "none",
		description: `POSIX TAR archive containing ${entries.length} members (size: ${formatBytes(totalSize)})`,
		metadata: {
			memberCount: entries.length,
		},
	};

	return { region, entries };
}

/** Parse ZIP archive */
function parseZipArchive(
	buf: Buffer,
	startOffset: number,
): { region: FirmwareRegion; entries: FirmwareEntry[] } | null {
	if (startOffset + 30 > buf.length) return null;
	if (buf.readUInt32LE(startOffset) !== 0x04034b50) return null;

	const entries: FirmwareEntry[] = [];
	let curr = startOffset;

	while (curr + 30 <= buf.length) {
		const sig = buf.readUInt32LE(curr);
		if (sig !== 0x04034b50) break; // Local file header

		const mtime = buf.readUInt16LE(curr + 10);
		const mdate = buf.readUInt16LE(curr + 12);
		const compressedSize = buf.readUInt32LE(curr + 18);
		const uncompressedSize = buf.readUInt32LE(curr + 22);
		const filenameLen = buf.readUInt16LE(curr + 26);
		const extraLen = buf.readUInt16LE(curr + 28);

		if (curr + 30 + filenameLen > buf.length) break;

		const filename = buf.toString("utf8", curr + 30, curr + 30 + filenameLen);
		const isDir = filename.endsWith("/");

		// DOS date/time format
		const year = ((mdate >> 9) & 0x7f) + 1980;
		const month = (mdate >> 5) & 0x0f;
		const day = mdate & 0x1f;
		const hour = (mtime >> 11) & 0x1f;
		const min = (mtime >> 5) & 0x3f;
		const sec = (mtime & 0x1f) * 2;
		const dateIso = `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${String(min).padStart(2, "0")}:${String(sec).padStart(2, "0")}Z`;

		entries.push({
			path: filename,
			size: uncompressedSize,
			compressedSize,
			type: isDir ? "directory" : "file",
			offset: curr,
			mtime: dateIso,
			container: "zip",
		});

		curr += 30 + filenameLen + extraLen + compressedSize;
	}

	const totalSize = curr - startOffset;
	const region: FirmwareRegion = {
		offset: startOffset,
		name: "ZIP Container",
		format: "ZIP",
		size: totalSize > 0 ? totalSize : undefined,
		compression: "deflate/stored",
		description: `ZIP archive container with ${entries.length} files (size: ${formatBytes(totalSize)})`,
		metadata: {
			memberCount: entries.length,
		},
	};

	return { region, entries };
}

// ============================================================================
// Multi-Region Scanner
// ============================================================================

/** Scan the buffer for embedded headers, filesystems, and partitions */
export function scanFirmwareRegions(buf: Buffer): { regions: FirmwareRegion[]; entries: FirmwareEntry[] } {
	const regions: FirmwareRegion[] = [];
	const allEntries: FirmwareEntry[] = [];
	const length = buf.length;
	const skipRanges: Array<{ start: number; end: number }> = [];

	// Check offset 0 first for top-level containers
	const uimage0 = parseUImageHeader(buf, 0);
	if (uimage0) regions.push(uimage0);

	const fit0 = parseFitHeader(buf, 0);
	if (fit0) regions.push(fit0);

	const sqsh0 = parseSquashfsSuperblock(buf, 0);
	if (sqsh0) regions.push(sqsh0);

	const cpio0 = parseCpioArchive(buf, 0);
	if (cpio0 && cpio0.entries.length > 0) {
		regions.push(cpio0.region);
		allEntries.push(...cpio0.entries);
		if (cpio0.region.size && cpio0.region.size > 0) {
			skipRanges.push({ start: 0, end: cpio0.region.size });
		}
	}

	const tar0 = parseTarArchive(buf, 0);
	if (tar0 && tar0.entries.length > 0) {
		regions.push(tar0.region);
		allEntries.push(...tar0.entries);
		if (tar0.region.size && tar0.region.size > 0) {
			skipRanges.push({ start: 0, end: tar0.region.size });
		}
	}

	const zip0 = parseZipArchive(buf, 0);
	if (zip0 && zip0.entries.length > 0) {
		regions.push(zip0.region);
		allEntries.push(...zip0.entries);
		if (zip0.region.size && zip0.region.size > 0) {
			skipRanges.push({ start: 0, end: zip0.region.size });
		}
	}

	// Scan through buffer at alignment boundaries (every 4 bytes for magic signatures)
	// For performance on large files, check 4-byte words
	const knownOffsets = new Set<number>(regions.map(r => r.offset));
	for (const entry of allEntries) {
		if (entry.offset !== undefined) {
			knownOffsets.add(entry.offset);
		}
	}
	for (let i = 4; i < length - 32; i += 4) {
		const inRange = skipRanges.find(r => i >= r.start && i < r.end);
		if (inRange) {
			const next = Math.ceil(inRange.end / 4) * 4;
			i = next - 4;
			continue;
		}

		if (knownOffsets.has(i)) continue;

		const b0 = buf[i];
		const b1 = buf[i + 1];
		const b2 = buf[i + 2];
		const b3 = buf[i + 3];

		// uImage: 0x27051956
		if (b0 === 0x27 && b1 === 0x05 && b2 === 0x19 && b3 === 0x56) {
			const uimg = parseUImageHeader(buf, i);
			if (uimg) {
				regions.push(uimg);
				knownOffsets.add(i);
				continue;
			}
		}

		// FIT / FDT: 0xd00dfeed
		if (b0 === 0xd0 && b1 === 0x0d && b2 === 0xfe && b3 === 0xed) {
			const fit = parseFitHeader(buf, i);
			if (fit) {
				regions.push(fit);
				knownOffsets.add(i);
				continue;
			}
		}

		// SquashFS: "sqsh" (0x73717368) or "hsqs" (0x68737173)
		if (
			(b0 === 0x73 && b1 === 0x71 && b2 === 0x73 && b3 === 0x68) ||
			(b0 === 0x68 && b1 === 0x73 && b2 === 0x71 && b3 === 0x73)
		) {
			const sqsh = parseSquashfsSuperblock(buf, i);
			if (sqsh) {
				regions.push(sqsh);
				knownOffsets.add(i);
				continue;
			}
		}

		// CPIO: "070701" or "070702"
		if (b0 === 0x30 && b1 === 0x37 && b2 === 0x30 && b3 === 0x37) {
			const cpio = parseCpioArchive(buf, i);
			if (cpio && cpio.entries.length > 0) {
				regions.push(cpio.region);
				allEntries.push(...cpio.entries);
				knownOffsets.add(i);
				for (const entry of cpio.entries) {
					if (entry.offset !== undefined) {
						knownOffsets.add(entry.offset);
					}
				}
				if (cpio.region.size && cpio.region.size > 0) {
					skipRanges.push({ start: i, end: i + cpio.region.size });
					const next = Math.ceil((i + cpio.region.size) / 4) * 4;
					i = next - 4;
				}
				continue;
			}
		}

		// TAR ustar check
		if (i % 512 === 0 && i + 512 <= length) {
			const tar = parseTarArchive(buf, i);
			if (tar && tar.entries.length > 0) {
				regions.push(tar.region);
				allEntries.push(...tar.entries);
				knownOffsets.add(i);
				for (const entry of tar.entries) {
					if (entry.offset !== undefined) {
						knownOffsets.add(entry.offset);
					}
				}
				if (tar.region.size && tar.region.size > 0) {
					skipRanges.push({ start: i, end: i + tar.region.size });
					const next = Math.ceil((i + tar.region.size) / 4) * 4;
					i = next - 4;
				}
				continue;
			}
		}

		// ZIP: PK\x03\x04
		if (b0 === 0x50 && b1 === 0x4b && b2 === 0x03 && b3 === 0x04) {
			const zip = parseZipArchive(buf, i);
			if (zip && zip.entries.length > 0) {
				regions.push(zip.region);
				allEntries.push(...zip.entries);
				knownOffsets.add(i);
				for (const entry of zip.entries) {
					if (entry.offset !== undefined) {
						knownOffsets.add(entry.offset);
					}
				}
				if (zip.region.size && zip.region.size > 0) {
					skipRanges.push({ start: i, end: i + zip.region.size });
					const next = Math.ceil((i + zip.region.size) / 4) * 4;
					i = next - 4;
				}
				continue;
			}
		}
		// CramFS: 0x28cd3d45 or 0x453dcd28
		if (
			(b0 === 0x45 && b1 === 0x3d && b2 === 0xcd && b3 === 0x28) ||
			(b0 === 0x28 && b1 === 0xcd && b2 === 0x3d && b3 === 0x45)
		) {
			const cramfs = parseCramfsSuperblock(buf, i);
			if (cramfs) {
				regions.push(cramfs);
				knownOffsets.add(i);
				continue;
			}
		}

		// JFFS2: 0x1985
		if ((b0 === 0x85 && b1 === 0x19) || (b0 === 0x19 && b1 === 0x85)) {
			const jffs = parseJffs2Node(buf, i);
			if (jffs) {
				regions.push(jffs);
				knownOffsets.add(i);
				continue;
			}
		}

		// ELF: \x7fELF
		if (b0 === 0x7f && b1 === 0x45 && b2 === 0x4c && b3 === 0x46) {
			const elf = parseElfHeader(buf, i);
			if (elf) {
				regions.push(elf);
				knownOffsets.add(i);
				continue;
			}
		}

		// ARM zImage (magic at +0x24)
		if (i % 1024 === 0) {
			const zimg = parseArmZImage(buf, i);
			if (zimg) {
				regions.push(zimg);
				knownOffsets.add(i);
				continue;
			}
		}

		// Compressed stream signatures
		const comp = parseCompressedStream(buf, i);
		if (comp) {
			regions.push(comp);
			knownOffsets.add(i);
			continue;
		}
	}

	// Sort regions by offset
	regions.sort((a, b) => a.offset - b.offset);

	return { regions, entries: allEntries };
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class FirmwareInspectTool implements AgentTool<typeof firmwareInspectSchema, FirmwareInspectDetails> {
	readonly name = "firmware_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Firmware Image / ROM Inspect";
	readonly summary =
		"Native offline read-only firmware image, ROM, and embedded filesystem inspection: partition layout, uImage, SquashFS, CPIO, TAR, ZIP, hashes, entropy, and archive inventory without extraction or execution";
	readonly description: string;
	readonly parameters = firmwareInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(firmwareInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: FirmwareInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<FirmwareInspectDetails>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<FirmwareInspectDetails> & { details: FirmwareInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Firmware file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a firmware image: ${resolvedPath}`);
		}

		if (fileStat.size === 0) {
			throw new ToolError(`Firmware image is empty (0 bytes): ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`Firmware image size (${formatBytes(fileStat.size)}) exceeds maximum allowed limit (${formatBytes(maxBytes)})`,
			);
		}

		throwIfAborted(signal);

		// Read the target file buffer into memory
		const buffer = await fs.readFile(resolvedPath);
		throwIfAborted(signal);

		// Compute cryptographic hashes
		const sha256 = createHash("sha256").update(buffer).digest("hex");
		const md5 = createHash("md5").update(buffer).digest("hex");
		const overallEntropy = computeShannonEntropy(buffer);

		// Scan for embedded regions and archives
		const { regions, entries } = scanFirmwareRegions(buffer);
		throwIfAborted(signal);

		// Determine primary format
		let primaryFormat = "Raw Binary / ROM";
		if (regions.length > 0 && regions[0].offset === 0) {
			primaryFormat = regions[0].format;
		} else if (regions.length > 0) {
			primaryFormat = `Multi-Region Firmware (${regions.length} partition${regions.length === 1 ? "" : "s"} detected)`;
		}

		const action = params.action;
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;

		// ------------------------------------------------------------------------
		// Action: info
		// ------------------------------------------------------------------------
		if (action === "info") {
			const textLines = [
				`# Firmware Overview: \`${resolvedPath}\``,
				"",
				"| Property | Value |",
				"|---|---|",
				`| **File Size** | ${formatBytes(fileStat.size)} (${fileStat.size.toLocaleString()} bytes) |`,
				`| **Primary Format** | \`${primaryFormat}\` |`,
				`| **SHA-256** | \`${sha256}\` |`,
				`| **MD5** | \`${md5}\` |`,
				`| **Shannon Entropy** | ${overallEntropy.toFixed(4)} / 8.0000 ${renderEntropyBar(overallEntropy)} (${classifyEntropy(overallEntropy)}) |`,
				`| **Regions Detected** | ${regions.length} |`,
				`| **Embedded File Entries** | ${entries.length} |`,
			];

			if (regions.length > 0) {
				textLines.push(
					"",
					"## Embedded Partitions & Superblocks",
					"| Offset (Hex) | Offset (Dec) | Format | Size | Compression | Description |",
					"|---|---|---|---|---|---|",
				);
				for (const reg of regions.slice(0, 15)) {
					const hexOffset = `0x${reg.offset.toString(16).toUpperCase()}`;
					const sizeStr = reg.size !== undefined ? formatBytes(reg.size) : "-";
					const compStr = reg.compression ?? "-";
					textLines.push(
						`| \`${hexOffset}\` | ${reg.offset.toLocaleString()} | **${reg.format}** | ${sizeStr} | ${compStr} | ${reg.description} |`,
					);
				}
				if (regions.length > 15) {
					textLines.push(
						`*...and ${regions.length - 15} more regions (use \`action: "regions"\` to inspect all)*`,
					);
				}
			}

			if (entries.length > 0) {
				const sampleEntries = entries.slice(0, 8);
				textLines.push(
					"",
					`## Embedded Container Inventory Preview (${entries.length} items total)`,
					"| Path | Type | Size | Container |",
					"|---|---|---|---|",
				);
				for (const ent of sampleEntries) {
					textLines.push(`| \`${ent.path}\` | ${ent.type} | ${formatBytes(ent.size)} | ${ent.container} |`);
				}
				if (entries.length > 8) {
					textLines.push(
						`*...and ${entries.length - 8} more files (use \`action: "entries"\` to search and paginate)*`,
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "info",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					sha256,
					md5,
					overallEntropy,
					primaryFormat,
					regionsSummary: {
						totalDetected: regions.length,
						regions: regions.slice(0, 50),
					},
					containerSummary: {
						format: primaryFormat,
						entryCount: entries.length,
						totalUncompressedSize: entries.reduce((acc, e) => acc + e.size, 0),
					},
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: regions
		// ------------------------------------------------------------------------
		if (action === "regions") {
			const pagedRegions = regions.slice(offset, offset + limit);
			const textLines = [
				`# Embedded Regions & Superblocks: \`${resolvedPath}\` (${regions.length} total, showing ${pagedRegions.length})`,
				"",
			];

			if (regions.length === 0) {
				textLines.push(
					"No standard filesystem, bootloader, or container headers were automatically recognized.",
					"The image may be raw flash, encrypted, compressed with a proprietary wrapper, or contain architecture-specific partitions.",
					"Try `action: 'entropy'` to identify encrypted or compressed byte ranges.",
				);
			} else {
				textLines.push(
					"| Offset (Hex) | Offset (Dec) | Format | Size | Entropy | Compression | Description |",
					"|---|---|---|---|---|---|---|",
				);
				for (const reg of pagedRegions) {
					const hexOffset = `0x${reg.offset.toString(16).toUpperCase()}`;
					const sizeStr = reg.size !== undefined ? formatBytes(reg.size) : "-";
					const entropyStr = reg.entropy !== undefined ? `${reg.entropy.toFixed(2)}` : "-";
					const compStr = reg.compression ?? "-";
					textLines.push(
						`| \`${hexOffset}\` | ${reg.offset.toLocaleString()} | **${reg.format}** | ${sizeStr} | ${entropyStr} | ${compStr} | ${reg.description} |`,
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "regions",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					sha256,
					md5,
					overallEntropy,
					primaryFormat,
					regions: pagedRegions,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: entries
		// ------------------------------------------------------------------------
		if (action === "entries") {
			let filtered = entries;
			if (params.path_filter) {
				const query = params.path_filter.toLowerCase();
				filtered = filtered.filter(e => e.path.toLowerCase().includes(query));
			}

			const pagedEntries = filtered.slice(offset, offset + limit);
			const textLines = [
				`# File Inventory: \`${resolvedPath}\` (${filtered.length} matching entries, showing ${pagedEntries.length})`,
				"",
			];

			if (entries.length === 0) {
				textLines.push(
					"No file entries were found inside embedded archives (CPIO, TAR, ZIP).",
					"If this firmware uses SquashFS, files are organized in compressed metadata blocks and inodes.",
					"Use `action: 'regions'` to confirm partition boundaries.",
				);
			} else if (pagedEntries.length === 0) {
				textLines.push(
					`No files matched the filter query \`${params.path_filter}\` across ${entries.length} total entries.`,
				);
			} else {
				textLines.push(
					"| Path | Type | Size | Compressed | Mode | Modified | Container |",
					"|---|---|---|---|---|---|---|",
				);
				for (const ent of pagedEntries) {
					const compSizeStr = ent.compressedSize !== undefined ? formatBytes(ent.compressedSize) : "-";
					const modeStr = ent.mode ?? "-";
					const mtimeStr = ent.mtime ?? "-";
					textLines.push(
						`| \`${ent.path}\` | ${ent.type} | ${formatBytes(ent.size)} | ${compSizeStr} | ${modeStr} | ${mtimeStr} | ${ent.container} |`,
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "entries",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					sha256,
					md5,
					overallEntropy,
					primaryFormat,
					entries: pagedEntries,
					totalEntries: filtered.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: entropy
		// ------------------------------------------------------------------------
		if (action === "entropy") {
			const blockSize = Math.min(Math.max(params.block_size ?? DEFAULT_BLOCK_SIZE, MIN_BLOCK_SIZE), MAX_BLOCK_SIZE);
			const totalBlocks = Math.ceil(buffer.length / blockSize);
			const allBlocks: FirmwareEntropyBlock[] = [];

			for (let i = 0; i < totalBlocks; i++) {
				const start = i * blockSize;
				const end = Math.min(buffer.length, start + blockSize);
				const chunk = buffer.subarray(start, end);
				const ent = computeShannonEntropy(chunk);
				allBlocks.push({
					offset: start,
					size: chunk.length,
					entropy: ent,
					classification: classifyEntropy(ent),
				});
			}

			const pagedBlocks = allBlocks.slice(offset, offset + limit);

			const textLines = [
				`# Entropy Distribution: \`${resolvedPath}\` (${totalBlocks} blocks @ ${formatBytes(blockSize)}, showing ${pagedBlocks.length})`,
				`Overall Shannon Entropy: **${overallEntropy.toFixed(4)} / 8.0000** ${renderEntropyBar(overallEntropy)} (${classifyEntropy(overallEntropy)})`,
				"",
				"| Offset (Hex) | Offset (Dec) | Size | Entropy | Visual Level | Classification |",
				"|---|---|---|---|---|---|",
			];

			for (const b of pagedBlocks) {
				const hexOffset = `0x${b.offset.toString(16).toUpperCase().padStart(8, "0")}`;
				const bar = renderEntropyBar(b.entropy);
				textLines.push(
					`| \`${hexOffset}\` | ${b.offset.toLocaleString()} | ${formatBytes(b.size)} | ${b.entropy.toFixed(4)} | ${bar} | \`${b.classification}\` |`,
				);
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "entropy",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					sha256,
					md5,
					overallEntropy,
					primaryFormat,
					entropyBlocks: pagedBlocks,
					totalBlocks,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
