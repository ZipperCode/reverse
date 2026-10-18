import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import * as zlib from "node:zlib";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { prompt } from "@rva/utils";
import androidPackageInspectDescription from "../prompts/tools/android-package-inspect.md" with { type: "text" };
import { checkToolRequirements, type SkillRequirementWhich } from "../extensibility/skill-requirements";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

// ============================================================================
// Parameter Schema
// ============================================================================

const androidPackageInspectSchema = type({
	action: type
		.enumerated("info", "manifest", "dex", "signing", "resources")
		.describe(
			"Inspection action: info (container overview, DEX summaries, native libs, signing presence), manifest (AndroidManifest.xml structure/metadata), dex (DEX headers and class listing), signing (signature scheme v1/v2/v3/v4 evidence and apksigner bridge), or resources (ARSC/resource entries breakdown and aapt2 bridge)",
		),
	"path?": type("string").describe(
		"Path to target Android package (.apk, .aab, .apks) or Dalvik executable (.dex)",
	),
	"target?": type("string").describe("Alias for path"),
	"dex_index?": type("number.integer >= 0").describe(
		"Optional zero-based DEX index (e.g. 0 for classes.dex, 1 for classes2.dex)",
	),
	"dex?": type("string").describe("Optional DEX name filter (e.g. 'classes.dex' or 'classes2.dex')"),
	"filter?": type("string").describe(
		"Optional class name filter for dex action or filename filter for resources action",
	),
	"limit?": type("number.integer >= 1").describe(
		"Maximum items returned for classes or resources (default 50, max 500)",
	),
	"offset?": type("number.integer >= 0").describe("Zero-based pagination offset (default 0)"),
	"use_bridge?": type("boolean").describe(
		"Whether to invoke optional external tools (apksigner/aapt2) if installed (default false)",
	),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum file bytes to read before error (default 209715200, max 524288000)",
	),
});

export type AndroidPackageInspectParams = typeof androidPackageInspectSchema.infer;
export type AndroidPackageInspectAction = AndroidPackageInspectParams["action"];

// ============================================================================
// Result Models & Detail Interfaces
// ============================================================================

export interface AndroidDexHeaderInfo {
	version: string;
	checksum: string;
	signature: string;
	fileSize: number;
	headerSize: number;
	endian: "little" | "big";
	linkSize: number;
	linkOff: number;
	mapOff: number;
	stringIdsCount: number;
	typeIdsCount: number;
	protoIdsCount: number;
	fieldIdsCount: number;
	methodIdsCount: number;
	classDefsCount: number;
	dataSize: number;
	dataOff: number;
}

export interface AndroidDexClassInfo {
	index: number;
	name: string;
	superclass?: string;
	accessFlags: number;
	flags: string[];
}

export interface AndroidPackageDexEntry {
	name: string;
	size: number;
	header?: AndroidDexHeaderInfo;
	classCount?: number;
}

export interface AndroidManifestComponent {
	name: string;
	exported?: boolean;
	authorities?: string;
}

export interface AndroidManifestMetadata {
	package: string;
	versionCode?: number | string;
	versionName?: string;
	compileSdkVersion?: number | string;
	minSdkVersion?: number | string;
	targetSdkVersion?: number | string;
	permissions: string[];
	permissionsDeclared: string[];
	application: {
		name?: string;
		label?: string;
		icon?: string;
		debuggable?: boolean;
		allowBackup?: boolean;
	};
	activities: AndroidManifestComponent[];
	services: AndroidManifestComponent[];
	receivers: AndroidManifestComponent[];
	providers: AndroidManifestComponent[];
	totalComponents: number;
}

export interface AndroidApkSigningBlockInfo {
	present: boolean;
	offset?: number;
	size?: number;
	v2Scheme?: boolean;
	v3Scheme?: boolean;
	v31Scheme?: boolean;
	sourceStamp?: boolean;
	blockIds?: Array<{ id: string; name: string }>;
}

export interface AndroidSigningSummary {
	schemes: {
		v1: {
			detected: boolean;
			manifest: boolean;
			signatureFiles: string[];
			blockFiles: string[];
		};
		v2: {
			detected: boolean;
			blockPresent: boolean;
		};
		v3: {
			detected: boolean;
			blockPresent: boolean;
		};
		v31: {
			detected: boolean;
		};
		sourceStamp: {
			detected: boolean;
		};
	};
	apkSigningBlock: AndroidApkSigningBlockInfo;
	apksignerBridge?: {
		available: boolean;
		path?: string;
		installHint?: string;
		verified?: boolean;
		output?: string;
	};
}

export interface AndroidResourceBreakdown {
	layouts: { count: number; samples: string[] };
	drawables: { count: number; samples: string[] };
	values: { count: number; hasArsc: boolean };
	xml: { count: number; samples: string[] };
	raw: { count: number; samples: string[] };
	assets: { count: number; samples: string[] };
	other: { count: number };
	totalFiles: number;
}

export interface AndroidResourcesSummary {
	arsc?: {
		present: boolean;
		size?: number;
		packageCount?: number;
		packageName?: string;
	};
	breakdown: AndroidResourceBreakdown;
	matchingFiles?: string[];
	aapt2Bridge?: {
		available: boolean;
		path?: string;
		installHint?: string;
		output?: string;
	};
}

export interface AndroidPackageInfoSummary {
	container?: {
		totalEntries: number;
		manifestPresent: boolean;
		manifestFormat?: "binary_xml" | "plain_xml" | "compiled_proto" | "unknown";
		dexFiles: AndroidPackageDexEntry[];
		nativeLibraries: Record<string, string[]>;
		resources: {
			totalFiles: number;
			hasArsc: boolean;
			arscSize?: number;
			layoutsCount: number;
			drawablesCount: number;
			assetsCount: number;
		};
		signing: {
			v1Files: string[];
			v1Signed: boolean;
			apkSigningBlock: boolean;
			v2Scheme: boolean;
			v3Scheme: boolean;
			v31Scheme: boolean;
			sourceStamp: boolean;
		};
	};
	dexSummary?: {
		totalDexCount: number;
		totalClasses: number;
		totalMethods: number;
		totalFields: number;
		headers: AndroidDexHeaderInfo[];
	};
	bareDex?: {
		header: AndroidDexHeaderInfo;
		sampleClasses: AndroidDexClassInfo[];
	};
}

export interface AndroidDexSummaryResult {
	dexFiles: AndroidPackageDexEntry[];
	classes: AndroidDexClassInfo[];
	selectedDex?: string;
	totalClasses: number;
}

export interface AndroidPackageInspectDetails {
	action: AndroidPackageInspectAction;
	path: string;
	status: "ok" | "unsupported" | "error";
	format?: "APK" | "AAB" | "APKS" | "DEX" | "ZIP" | string;
	size?: number;
	sha256?: string;
	info?: AndroidPackageInfoSummary;
	manifest?: AndroidManifestMetadata;
	dex?: AndroidDexSummaryResult;
	signing?: AndroidSigningSummary;
	resources?: AndroidResourcesSummary;
	total?: number;
	count?: number;
	offset?: number;
	hasMore?: boolean;
	error?: string;
}

export interface AndroidPackageInspectToolOptions {
	which?: SkillRequirementWhich;
}

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_MAX_FILE_BYTES = 200 * 1024 * 1024; // 200 MiB
const HARD_MAX_FILE_BYTES = 500 * 1024 * 1024; // 500 MiB

// ============================================================================
// ZIP & Container Parser
// ============================================================================

export class ZipEntry {
	constructor(
		public name: string,
		public compressionMethod: number,
		public compressedSize: number,
		public uncompressedSize: number,
		public localHeaderOffset: number,
		public crc32: number,
	) {}
}

export class ZipParser {
	readonly entries: ZipEntry[] = [];
	readonly cdOffset: number;
	readonly cdSize: number;
	readonly totalEntries: number;

	constructor(private readonly buffer: Buffer) {
		const eocd = this.findEocdOffset();
		if (eocd === -1) {
			throw new Error("Target is not a valid ZIP archive (EOCD record not found)");
		}
		this.totalEntries = buffer.readUInt16LE(eocd + 10);
		this.cdSize = buffer.readUInt32LE(eocd + 12);
		this.cdOffset = buffer.readUInt32LE(eocd + 16);

		let ptr = this.cdOffset;
		const end = Math.min(buffer.length, this.cdOffset + this.cdSize);

		while (ptr + 46 <= end) {
			const sig = buffer.readUInt32LE(ptr);
			if (sig !== 0x02014b50) break;

			const compMethod = buffer.readUInt16LE(ptr + 10);
			const crc32 = buffer.readUInt32LE(ptr + 16);
			const compSize = buffer.readUInt32LE(ptr + 20);
			const uncompSize = buffer.readUInt32LE(ptr + 24);
			const fnLen = buffer.readUInt16LE(ptr + 28);
			const extraLen = buffer.readUInt16LE(ptr + 30);
			const commentLen = buffer.readUInt16LE(ptr + 32);
			const localOff = buffer.readUInt32LE(ptr + 42);

			if (ptr + 46 + fnLen > buffer.length) break;
			const name = buffer.toString("utf8", ptr + 46, ptr + 46 + fnLen);
			this.entries.push(new ZipEntry(name, compMethod, compSize, uncompSize, localOff, crc32));

			ptr += 46 + fnLen + extraLen + commentLen;
		}
	}

	private findEocdOffset(): number {
		const minOffset = Math.max(0, this.buffer.length - 65535 - 22);
		for (let i = this.buffer.length - 22; i >= minOffset; i--) {
			if (
				this.buffer[i] === 0x50 &&
				this.buffer[i + 1] === 0x4b &&
				this.buffer[i + 2] === 0x05 &&
				this.buffer[i + 3] === 0x06
			) {
				return i;
			}
		}
		return -1;
	}

	getEntry(name: string): ZipEntry | undefined {
		return this.entries.find(e => e.name === name);
	}

	readFile(entry: ZipEntry): Buffer | null {
		if (entry.localHeaderOffset + 30 > this.buffer.length) return null;
		const sig = this.buffer.readUInt32LE(entry.localHeaderOffset);
		if (sig !== 0x04034b50) return null;

		const nameLen = this.buffer.readUInt16LE(entry.localHeaderOffset + 26);
		const extraLen = this.buffer.readUInt16LE(entry.localHeaderOffset + 28);
		const dataStart = entry.localHeaderOffset + 30 + nameLen + extraLen;
		const dataEnd = dataStart + entry.compressedSize;

		if (dataEnd > this.buffer.length) return null;
		const rawData = this.buffer.subarray(dataStart, dataEnd);

		if (entry.compressionMethod === 0) {
			return Buffer.from(rawData);
		}
		if (entry.compressionMethod === 8) {
			try {
				return zlib.inflateRawSync(rawData);
			} catch {
				return null;
			}
		}
		return null;
	}
}

// ============================================================================
// APK Signing Block Parser
// ============================================================================

export function parseApkSigningBlock(buffer: Buffer, cdOffset: number): AndroidApkSigningBlockInfo {
	if (cdOffset < 24) {
		return { present: false };
	}

	const magic = buffer.subarray(cdOffset - 16, cdOffset).toString("ascii");
	if (magic !== "APK Sig Block 42") {
		return { present: false };
	}

	let blockSize: number;
	try {
		blockSize = Number(buffer.readBigUInt64LE(cdOffset - 24));
	} catch {
		return { present: false };
	}

	if (blockSize <= 0 || blockSize > 100 * 1024 * 1024) {
		return { present: false };
	}

	const blockStart = cdOffset - 8 - blockSize;
	if (blockStart < 0 || blockStart + 8 > buffer.length) {
		return { present: false };
	}

	try {
		const initialSize = Number(buffer.readBigUInt64LE(blockStart));
		if (initialSize !== blockSize) {
			return { present: false };
		}
	} catch {
		return { present: false };
	}

	const recognizedIds: Array<{ id: string; name: string }> = [];
	let v2Scheme = false;
	let v3Scheme = false;
	let v31Scheme = false;
	let sourceStamp = false;

	let ptr = blockStart + 8;
	const pairsEnd = cdOffset - 24;

	while (ptr + 12 <= pairsEnd) {
		try {
			const pairLen = Number(buffer.readBigUInt64LE(ptr));
			if (pairLen < 4 || ptr + 8 + pairLen > pairsEnd) break;
			const pairId = buffer.readUInt32LE(ptr + 8);
			const hexId = `0x${pairId.toString(16).padStart(8, "0")}`;

			let schemeName = "Unknown Block";
			if (pairId === 0x7109871a) {
				schemeName = "APK Signature Scheme v2";
				v2Scheme = true;
			} else if (pairId === 0xf05368c0) {
				schemeName = "APK Signature Scheme v3";
				v3Scheme = true;
			} else if (pairId === 0x1b93ad61) {
				schemeName = "APK Signature Scheme v3.1";
				v31Scheme = true;
			} else if (pairId === 0x42726577) {
				schemeName = "Android SourceStamp";
				sourceStamp = true;
			} else if (pairId === 0x2146444e) {
				schemeName = "APK Signature Scheme v4 Auxiliary";
			} else if (pairId === 0x50435354) {
				schemeName = "Dependency Info / Play Billing";
			}

			recognizedIds.push({ id: hexId, name: schemeName });
			ptr += 8 + pairLen;
		} catch {
			break;
		}
	}

	return {
		present: true,
		offset: blockStart,
		size: blockSize + 8,
		v2Scheme,
		v3Scheme,
		v31Scheme,
		sourceStamp,
		blockIds: recognizedIds,
	};
}

// ============================================================================
// DEX Parser
// ============================================================================

export interface DexParsedData {
	header: AndroidDexHeaderInfo;
	getDexString: (idx: number) => string | null;
	getClassNameFromTypeIdx: (typeIdx: number) => string | null;
	classDefsOff: number;
	classDefsSize: number;
}

export function parseDexBuffer(buf: Buffer): DexParsedData | null {
	if (buf.length < 112) return null;
	if (buf[0] !== 0x64 || buf[1] !== 0x65 || buf[2] !== 0x78 || buf[3] !== 0x0a) {
		return null;
	}

	const version = buf.toString("ascii", 4, 7);
	const checksum = `0x${buf.readUInt32LE(0x08).toString(16).padStart(8, "0")}`;
	const signature = buf.subarray(0x0c, 0x20).toString("hex");
	const fileSize = buf.readUInt32LE(0x20);
	const headerSize = buf.readUInt32LE(0x24);
	const endianTagVal = buf.readUInt32LE(0x28);
	const endian: "little" | "big" = endianTagVal === 0x12345678 ? "little" : "big";
	const linkSize = buf.readUInt32LE(0x2c);
	const linkOff = buf.readUInt32LE(0x30);
	const mapOff = buf.readUInt32LE(0x34);
	const stringIdsSize = buf.readUInt32LE(0x38);
	const stringIdsOff = buf.readUInt32LE(0x3c);
	const typeIdsSize = buf.readUInt32LE(0x40);
	const typeIdsOff = buf.readUInt32LE(0x44);
	const protoIdsSize = buf.readUInt32LE(0x48);
	const protoIdsOff = buf.readUInt32LE(0x4c);
	const fieldIdsSize = buf.readUInt32LE(0x50);
	const fieldIdsOff = buf.readUInt32LE(0x54);
	const methodIdsSize = buf.readUInt32LE(0x58);
	const methodIdsOff = buf.readUInt32LE(0x5c);
	const classDefsSize = buf.readUInt32LE(0x60);
	const classDefsOff = buf.readUInt32LE(0x64);
	const dataSize = buf.readUInt32LE(0x68);
	const dataOff = buf.readUInt32LE(0x6c);

	const getDexString = (idx: number): string | null => {
		if (idx >= stringIdsSize || stringIdsOff + idx * 4 + 4 > buf.length) return null;
		const strDataOff = buf.readUInt32LE(stringIdsOff + idx * 4);
		if (strDataOff >= buf.length) return null;
		let p = strDataOff;
		while (p < buf.length && (buf[p] & 0x80) !== 0) p++;
		p++;
		if (p >= buf.length) return null;
		const end = buf.indexOf(0, p);
		if (end === -1) return null;
		return buf.toString("utf8", p, end);
	};

	const getClassNameFromTypeIdx = (typeIdx: number): string | null => {
		if (typeIdx >= typeIdsSize || typeIdsOff + typeIdx * 4 + 4 > buf.length) return null;
		const descIdx = buf.readUInt32LE(typeIdsOff + typeIdx * 4);
		const desc = getDexString(descIdx);
		if (!desc) return null;
		if (desc.startsWith("L") && desc.endsWith(";")) {
			return desc.slice(1, -1).replace(/\//g, ".");
		}
		return desc;
	};

	return {
		header: {
			version,
			checksum,
			signature,
			fileSize,
			headerSize,
			endian,
			linkSize,
			linkOff,
			mapOff,
			stringIdsCount: stringIdsSize,
			typeIdsCount: typeIdsSize,
			protoIdsCount: protoIdsSize,
			fieldIdsCount: fieldIdsSize,
			methodIdsCount: methodIdsSize,
			classDefsCount: classDefsSize,
			dataSize,
			dataOff,
		},
		getDexString,
		getClassNameFromTypeIdx,
		classDefsOff,
		classDefsSize,
	};
}

export function extractDexClasses(dex: DexParsedData, buf: Buffer, filter?: string): AndroidDexClassInfo[] {
	const classes: AndroidDexClassInfo[] = [];
	const lowerFilter = filter ? filter.toLowerCase() : null;

	for (let i = 0; i < dex.classDefsSize; i++) {
		const off = dex.classDefsOff + i * 32;
		if (off + 32 > buf.length) break;
		const classIdx = buf.readUInt32LE(off);
		const accessFlags = buf.readUInt32LE(off + 4);
		const superclassIdx = buf.readUInt32LE(off + 8);

		const name = dex.getClassNameFromTypeIdx(classIdx);
		if (!name) continue;

		if (lowerFilter && !name.toLowerCase().includes(lowerFilter)) {
			continue;
		}

		const superclass =
			superclassIdx !== 0xffffffff ? dex.getClassNameFromTypeIdx(superclassIdx) ?? undefined : undefined;

		const flags: string[] = [];
		if (accessFlags & 0x0001) flags.push("public");
		if (accessFlags & 0x0002) flags.push("private");
		if (accessFlags & 0x0004) flags.push("protected");
		if (accessFlags & 0x0008) flags.push("static");
		if (accessFlags & 0x0010) flags.push("final");
		if (accessFlags & 0x0200) flags.push("interface");
		if (accessFlags & 0x0400) flags.push("abstract");
		if (accessFlags & 0x4000) flags.push("enum");

		classes.push({
			index: i,
			name,
			superclass,
			accessFlags,
			flags,
		});
	}

	return classes;
}

// ============================================================================
// Android Binary XML (AXML) & Text XML Parser
// ============================================================================

function readUleb128Len(buf: Buffer, off: number, limit: number): { len: number; bytesRead: number } | null {
	if (off >= limit) return null;
	const b0 = buf[off];
	if ((b0 & 0x80) !== 0) {
		if (off + 1 >= limit) return null;
		const b1 = buf[off + 1];
		return { len: ((b0 & 0x7f) << 8) | b1, bytesRead: 2 };
	}
	return { len: b0, bytesRead: 1 };
}

export function parseAxml(buf: Buffer): AndroidManifestMetadata | null {
	if (buf.length < 8) return null;
	const chunkType = buf.readUInt16LE(0);
	if (chunkType !== 0x0003) return null; // RES_XML_TYPE
	const rawTotalSize = buf.readUInt32LE(4);
	const totalSize = rawTotalSize > 0 ? Math.min(buf.length, rawTotalSize) : buf.length;

	let poolOff = buf.readUInt16LE(2);
	if (poolOff < 8 || poolOff + 28 > buf.length || buf.readUInt16LE(poolOff) !== 0x0001) {
		poolOff = 8;
	}
	if (poolOff + 28 > buf.length || buf.readUInt16LE(poolOff) !== 0x0001) {
		let found = -1;
		for (let i = 8; i + 28 <= buf.length && i <= 256; i += 4) {
			if (buf.readUInt16LE(i) === 0x0001) {
				found = i;
				break;
			}
		}
		if (found === -1) return null;
		poolOff = found;
	}

	const poolHeaderSize = buf.readUInt16LE(poolOff + 2);
	const poolSize = buf.readUInt32LE(poolOff + 4);
	const stringCount = buf.readUInt32LE(poolOff + 8);
	const flags = buf.readUInt32LE(poolOff + 16);
	const isUtf8 = (flags & 0x0100) !== 0;
	const stringsStart = buf.readUInt32LE(poolOff + 20);

	const poolDataStart = poolOff + stringsStart;
	const poolEnd = Math.min(buf.length, poolOff + poolSize);
	const offsetTableStart = poolOff + (poolHeaderSize >= 28 ? poolHeaderSize : 28);

	const strings: string[] = [];
	for (let i = 0; i < stringCount; i++) {
		const offTableEntry = offsetTableStart + i * 4;
		if (offTableEntry + 4 > buf.length || offTableEntry + 4 > poolEnd) break;
		const strRelOff = buf.readUInt32LE(offTableEntry);
		const strDataOff = poolDataStart + strRelOff;
		if (strDataOff >= buf.length || strDataOff >= poolEnd) {
			strings.push("");
			continue;
		}

		try {
			if (isUtf8) {
				let nullIdx = buf.indexOf(0, strDataOff);
				if (nullIdx === -1 || nullIdx > poolEnd) nullIdx = poolEnd;

				let str = "";
				const l1 = readUleb128Len(buf, strDataOff, nullIdx);
				if (l1) {
					const start1 = strDataOff + l1.bytesRead;
					const l2 = readUleb128Len(buf, start1, nullIdx);
					const start2 = l2 ? start1 + l2.bytesRead : start1;

					if (nullIdx < poolEnd) {
						if (l2 && start2 + l2.len === nullIdx) {
							str = buf.toString("utf8", start2, start2 + l2.len);
						} else if (start1 + l1.len === nullIdx) {
							str = buf.toString("utf8", start1, start1 + l1.len);
						}
					}

					if (!str) {
						if (l2 && start2 + l2.len <= poolEnd && buf[start2 + l2.len] === 0) {
							str = buf.toString("utf8", start2, start2 + l2.len);
						} else if (start1 + l1.len <= poolEnd && buf[start1 + l1.len] === 0) {
							str = buf.toString("utf8", start1, start1 + l1.len);
						} else if (l2 && l1.len === l2.len && start2 + l2.len <= poolEnd) {
							str = buf.toString("utf8", start2, start2 + l2.len);
						} else if (start1 + l1.len <= poolEnd) {
							str = buf.toString("utf8", start1, start1 + l1.len);
						} else if (start1 < nullIdx) {
							str = buf.toString("utf8", start1, nullIdx);
						}
					}
				}
				if (!str && strDataOff < nullIdx) {
					str = buf.toString("utf8", strDataOff, nullIdx);
				}
				if (str.includes("\0")) {
					str = str.split("\0")[0];
				}
				strings.push(str);
			} else {
				let p = strDataOff;
				if (p + 2 > poolEnd) {
					strings.push("");
					continue;
				}
				const u1 = buf.readUInt16LE(p);
				p += 2;
				let charLen = u1;
				if ((u1 & 0x8000) !== 0) {
					if (p + 2 > poolEnd) {
						strings.push("");
						continue;
					}
					const u2 = buf.readUInt16LE(p);
					p += 2;
					charLen = ((u1 & 0x7fff) << 16) | u2;
				}
				let byteLen = charLen * 2;
				const maxAvail = Math.max(0, poolEnd - p);
				byteLen = Math.min(byteLen, maxAvail);
				for (let j = p; j + 1 < p + byteLen; j += 2) {
					if (buf.readUInt16LE(j) === 0) {
						byteLen = j - p;
						break;
					}
				}
				let str = buf.toString("utf16le", p, p + byteLen);
				if (str.includes("\0")) {
					str = str.split("\0")[0];
				}
				strings.push(str);
			}
		} catch {
			strings.push("");
		}
	}

	let ptr = poolOff + poolSize;
	if (ptr + 2 <= buf.length && ptr % 4 !== 0) {
		const currType = buf.readUInt16LE(ptr);
		const isCurrValid = (currType >= 0x0100 && currType <= 0x017f) || currType === 0x0180;
		if (!isCurrValid) {
			const aligned = ptr + (4 - (ptr % 4));
			if (aligned + 2 <= buf.length) {
				const alignedType = buf.readUInt16LE(aligned);
				if ((alignedType >= 0x0100 && alignedType <= 0x017f) || alignedType === 0x0180) {
					ptr = aligned;
				}
			}
		}
	}

	let packageName = "";
	let versionCode: number | string | undefined;
	let versionName: string | undefined;
	let compileSdkVersion: number | string | undefined;
	let minSdkVersion: number | string | undefined;
	let targetSdkVersion: number | string | undefined;
	const permissions: string[] = [];
	const permissionsDeclared: string[] = [];
	const activities: AndroidManifestComponent[] = [];
	const services: AndroidManifestComponent[] = [];
	const receivers: AndroidManifestComponent[] = [];
	const providers: AndroidManifestComponent[] = [];
	let appName: string | undefined;
	let appLabel: string | undefined;
	let appIcon: string | undefined;
	let appDebuggable: boolean | undefined;
	let appAllowBackup: boolean | undefined;

	while (ptr + 8 <= buf.length && ptr < totalSize) {
		const type = buf.readUInt16LE(ptr);
		const size = buf.readUInt32LE(ptr + 4);
		if (size <= 0 || ptr + size > buf.length) break;

		if (type === 0x0102) {
			// RES_XML_START_ELEMENT_TYPE
			const nameIdx = buf.readUInt32LE(ptr + 20);
			const elemName = strings[nameIdx] ?? "";
			const nodeHeaderSize = buf.readUInt16LE(ptr + 2) || 16;
			const attrStart = buf.readUInt16LE(ptr + 24);
			const attrSize = buf.readUInt16LE(ptr + 26);
			const attrCount = buf.readUInt16LE(ptr + 28);

			const attrs: Record<string, string | number | boolean> = {};
			let attrsBase = ptr + (attrStart >= 32 ? attrStart : nodeHeaderSize + attrStart);
			if (attrsBase + attrCount * 20 > buf.length) {
				attrsBase = ptr + 36;
			}
			const effectiveAttrSize = attrSize >= 20 ? attrSize : 20;

			for (let a = 0; a < attrCount; a++) {
				const aOff = attrsBase + a * effectiveAttrSize;
				if (aOff + 20 > buf.length) break;
				const aNameIdx = buf.readUInt32LE(aOff + 4);
				const aRawValIdx = buf.readUInt32LE(aOff + 8);
				const typedValType = buf.readUInt8(aOff + 15);
				const typedValData = buf.readUInt32LE(aOff + 16);

				const aName = strings[aNameIdx] ?? "";
				let val: string | number | boolean;

				if (typedValType === 0x03) {
					val = strings[typedValData] ?? (aRawValIdx !== 0xffffffff && aRawValIdx < strings.length ? strings[aRawValIdx] : "") ?? "";
				} else if (aRawValIdx !== 0xffffffff && aRawValIdx < strings.length) {
					val = strings[aRawValIdx];
				} else if (typedValType === 0x12) {
					val = typedValData !== 0;
				} else if (typedValType === 0x10) {
					val = typedValData;
				} else if (typedValType === 0x11) {
					val = `0x${typedValData.toString(16)}`;
				} else if (typedValType === 0x01) {
					val = `@0x${typedValData.toString(16)}`;
				} else {
					val = typedValData;
				}

				attrs[aName] = val;
			}

			const normElemName = elemName.split(":").pop()?.toLowerCase() ?? "";
			const getAttr = (k: string): string | number | boolean | undefined => {
				if (attrs[k] !== undefined) return attrs[k];
				const lowerK = k.toLowerCase();
				for (const [key, val] of Object.entries(attrs)) {
					const bare = key.split(":").pop()?.toLowerCase();
					if (bare === lowerK) return val;
				}
				return undefined;
			};

			if (normElemName === "manifest") {
				const pkg = getAttr("package");
				if (pkg) packageName = String(pkg);
				const vc = getAttr("versionCode");
				if (vc !== undefined) versionCode = typeof vc === "number" ? vc : Number(vc) || String(vc);
				const vn = getAttr("versionName");
				if (vn !== undefined) versionName = String(vn);
				const csv = getAttr("compileSdkVersion");
				if (csv !== undefined) compileSdkVersion = typeof csv === "number" ? csv : Number(csv) || String(csv);
			} else if (normElemName === "uses-sdk") {
				const min = getAttr("minSdkVersion");
				if (min !== undefined) minSdkVersion = typeof min === "number" ? min : Number(min) || String(min);
				const target = getAttr("targetSdkVersion");
				if (target !== undefined) targetSdkVersion = typeof target === "number" ? target : Number(target) || String(target);
			} else if (normElemName === "uses-permission") {
				const name = getAttr("name");
				if (name) permissions.push(String(name));
			} else if (normElemName === "permission") {
				const name = getAttr("name");
				if (name) permissionsDeclared.push(String(name));
			} else if (normElemName === "application") {
				const name = getAttr("name");
				if (name) appName = String(name);
				const label = getAttr("label");
				if (label) appLabel = String(label);
				const icon = getAttr("icon");
				if (icon) appIcon = String(icon);
				const debuggable = getAttr("debuggable");
				if (debuggable !== undefined) appDebuggable = Boolean(debuggable);
				const allowBackup = getAttr("allowBackup");
				if (allowBackup !== undefined) appAllowBackup = Boolean(allowBackup);
			} else if (normElemName === "activity" || normElemName === "activity-alias") {
				const name = getAttr("name");
				if (name) {
					const exp = getAttr("exported");
					activities.push({
						name: String(name),
						exported: exp !== undefined ? Boolean(exp) : undefined,
					});
				}
			} else if (normElemName === "service") {
				const name = getAttr("name");
				if (name) {
					const exp = getAttr("exported");
					services.push({
						name: String(name),
						exported: exp !== undefined ? Boolean(exp) : undefined,
					});
				}
			} else if (normElemName === "receiver") {
				const name = getAttr("name");
				if (name) {
					const exp = getAttr("exported");
					receivers.push({
						name: String(name),
						exported: exp !== undefined ? Boolean(exp) : undefined,
					});
				}
			} else if (normElemName === "provider") {
				const name = getAttr("name");
				if (name) {
					const auth = getAttr("authorities");
					const exp = getAttr("exported");
					providers.push({
						name: String(name),
						authorities: auth ? String(auth) : undefined,
						exported: exp !== undefined ? Boolean(exp) : undefined,
					});
				}
			}
		}

		ptr += size;
		if (ptr + 2 <= buf.length && ptr % 4 !== 0) {
			const currType = buf.readUInt16LE(ptr);
			const isCurrValid = (currType >= 0x0100 && currType <= 0x017f) || currType === 0x0180;
			if (!isCurrValid) {
				const aligned = ptr + (4 - (ptr % 4));
				if (aligned + 2 <= buf.length) {
					const alignedType = buf.readUInt16LE(aligned);
					if ((alignedType >= 0x0100 && alignedType <= 0x017f) || alignedType === 0x0180) {
						ptr = aligned;
					}
				}
			}
		}
	}

	return {
		package: packageName,
		versionCode,
		versionName,
		compileSdkVersion,
		minSdkVersion,
		targetSdkVersion,
		permissions,
		permissionsDeclared,
		application: {
			name: appName,
			label: appLabel,
			icon: appIcon,
			debuggable: appDebuggable,
			allowBackup: appAllowBackup,
		},
		activities,
		services,
		receivers,
		providers,
		totalComponents: activities.length + services.length + receivers.length + providers.length,
	};
}

export function parseXmlText(text: string): AndroidManifestMetadata | null {
	if (!text.includes("<manifest")) return null;
	const pkgMatch = text.match(/package\s*=\s*["']([^"']+)["']/i);
	const vCodeMatch = text.match(/(?:android:)?versionCode\s*=\s*["']([^"']+)["']/i);
	const vNameMatch = text.match(/(?:android:)?versionName\s*=\s*["']([^"']+)["']/i);
	const minSdkMatch = text.match(/(?:android:)?minSdkVersion\s*=\s*["']([^"']+)["']/i);
	const targetSdkMatch = text.match(/(?:android:)?targetSdkVersion\s*=\s*["']([^"']+)["']/i);

	const permissions: string[] = [];
	const permRegex = /<uses-permission[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']/gi;
	let pMatch: RegExpExecArray | null;
	while ((pMatch = permRegex.exec(text)) !== null) {
		permissions.push(pMatch[1]);
	}

	const activities: AndroidManifestComponent[] = [];
	const actRegex = /<activity(?:-alias)?[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']/gi;
	let aMatch: RegExpExecArray | null;
	while ((aMatch = actRegex.exec(text)) !== null) {
		activities.push({ name: aMatch[1] });
	}

	const services: AndroidManifestComponent[] = [];
	const srvRegex = /<service[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']/gi;
	let sMatch: RegExpExecArray | null;
	while ((sMatch = srvRegex.exec(text)) !== null) {
		services.push({ name: sMatch[1] });
	}

	const receivers: AndroidManifestComponent[] = [];
	const recRegex = /<receiver[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']/gi;
	let rMatch: RegExpExecArray | null;
	while ((rMatch = recRegex.exec(text)) !== null) {
		receivers.push({ name: rMatch[1] });
	}

	const providers: AndroidManifestComponent[] = [];
	const provRegex = /<provider[^>]+(?:android:)?name\s*=\s*["']([^"']+)["']/gi;
	let prMatch: RegExpExecArray | null;
	while ((prMatch = provRegex.exec(text)) !== null) {
		providers.push({ name: prMatch[1] });
	}

	return {
		package: pkgMatch ? pkgMatch[1] : "",
		versionCode: vCodeMatch ? Number(vCodeMatch[1]) || vCodeMatch[1] : undefined,
		versionName: vNameMatch ? vNameMatch[1] : undefined,
		minSdkVersion: minSdkMatch ? Number(minSdkMatch[1]) || minSdkMatch[1] : undefined,
		targetSdkVersion: targetSdkMatch ? Number(targetSdkMatch[1]) || targetSdkMatch[1] : undefined,
		permissions,
		permissionsDeclared: [],
		application: {},
		activities,
		services,
		receivers,
		providers,
		totalComponents: activities.length + services.length + receivers.length + providers.length,
	};
}

// ============================================================================
// Resource ARSC Parser
// ============================================================================

export function parseArscHeader(buf: Buffer): { packageCount: number; packageName?: string } | null {
	if (buf.length < 12) return null;
	const type = buf.readUInt16LE(0);
	if (type !== 0x0002) return null; // RES_TABLE_TYPE
	const packageCount = buf.readUInt32LE(8);
	let packageName: string | undefined;

	let ptr = 12;
	while (ptr + 8 <= buf.length) {
		const chunkType = buf.readUInt16LE(ptr);
		const chunkSize = buf.readUInt32LE(ptr + 4);
		if (chunkSize <= 0 || ptr + chunkSize > buf.length) break;

		if (chunkType === 0x0200 && ptr + 288 <= buf.length) {
			const rawName = buf.toString("utf16le", ptr + 12, ptr + 268);
			const nullIdx = rawName.indexOf("\0");
			packageName = nullIdx !== -1 ? rawName.slice(0, nullIdx) : rawName;
			break;
		}
		ptr += chunkSize;
	}

	return { packageCount, packageName };
}

// ============================================================================
// External Bridge Runners
// ============================================================================

async function runApksignerBridge(
	targetPath: string,
	which?: SkillRequirementWhich,
	signal?: AbortSignal,
): Promise<{ available: boolean; path?: string; installHint?: string; verified?: boolean; output?: string }> {
	const reqs = [{ id: "apksigner" }];
	const [status] = checkToolRequirements(reqs, which ? { which } : undefined);
	const available = status?.foundPath !== null && status?.foundPath !== undefined;
	if (!available || !status?.foundPath) {
		return {
			available: false,
			installHint:
				status?.hint ??
				"Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'. Requires Java.",
		};
	}

	const binary = status.foundPath;
	try {
		const child = Bun.spawn([binary, "verify", "--verbose", targetPath], {
			stdout: "pipe",
			stderr: "pipe",
			stdin: "ignore",
		});

		const timer = setTimeout(() => child.kill(), 15000);
		const onAbort = () => child.kill();
		signal?.addEventListener("abort", onAbort, { once: true });

		try {
			const [stdout, stderr, exitCode] = await Promise.all([
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
				child.exited,
			]);

			const combined = (stdout + "\n" + stderr).trim();
			return {
				available: true,
				path: binary,
				verified: exitCode === 0,
				output: combined.slice(0, 4096),
			};
		} finally {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
		}
	} catch (err) {
		return {
			available: true,
			path: binary,
			verified: false,
			output: `Bridge execution error: ${err instanceof Error ? err.message : String(err)}`,
		};
	}
}

async function runAapt2Bridge(
	targetPath: string,
	which?: SkillRequirementWhich,
	signal?: AbortSignal,
): Promise<{ available: boolean; path?: string; installHint?: string; output?: string }> {
	const reqs = [{ id: "aapt2" }];
	const [status] = checkToolRequirements(reqs, which ? { which } : undefined);
	const available = status?.foundPath !== null && status?.foundPath !== undefined;
	if (!available || !status?.foundPath) {
		return {
			available: false,
			installHint:
				status?.hint ??
				"Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'.",
		};
	}

	const binary = status.foundPath;
	try {
		const child = Bun.spawn([binary, "dump", "badging", targetPath], {
			stdout: "pipe",
			stderr: "pipe",
			stdin: "ignore",
		});

		const timer = setTimeout(() => child.kill(), 15000);
		const onAbort = () => child.kill();
		signal?.addEventListener("abort", onAbort, { once: true });

		try {
			const [stdout, stderr] = await Promise.all([
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
				child.exited,
			]);

			const combined = (stdout + "\n" + stderr).trim();
			return {
				available: true,
				path: binary,
				output: combined.slice(0, 4096),
			};
		} finally {
			clearTimeout(timer);
			signal?.removeEventListener("abort", onAbort);
		}
	} catch (err) {
		return {
			available: true,
			path: binary,
			output: `Bridge execution error: ${err instanceof Error ? err.message : String(err)}`,
		};
	}
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class AndroidPackageInspectTool
	implements AgentTool<typeof androidPackageInspectSchema, AndroidPackageInspectDetails>
{
	readonly name = "android_package_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Android Package Inspect";
	readonly summary =
		"Native read-only inspection of Android packages (.apk, .aab, .apks) and Dalvik executables (.dex): container layout, DEX headers/classes, manifest metadata, signature schemes, and resources";
	readonly description: string;
	readonly parameters = androidPackageInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: AndroidPackageInspectToolOptions = {},
	) {
		this.description = prompt.render(androidPackageInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: AndroidPackageInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidPackageInspectDetails>> {
		throwIfAborted(signal);

		const targetPath = params.path ?? params.target;
		if (!targetPath) {
			throw new ToolError("Missing required parameter 'path' (or alias 'target')");
		}

		const resolvedPath = resolveReadPath(targetPath, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Target file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a file: ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`File size (${fileStat.size} bytes) exceeds configured max_bytes limit (${maxBytes} bytes)`,
			);
		}

		let fileBuffer: Buffer;
		try {
			fileBuffer = await readFile(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Failed to read file: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		const sha256 = createHash("sha256").update(fileBuffer).digest("hex");

		// Format identification
		const isDex =
			fileBuffer.length >= 8 &&
			fileBuffer[0] === 0x64 &&
			fileBuffer[1] === 0x65 &&
			fileBuffer[2] === 0x78 &&
			fileBuffer[3] === 0x0a;

		let zip: ZipParser | null = null;
		let format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP" | "unknown" = "unknown";

		if (isDex) {
			format = "DEX";
		} else {
			try {
				zip = new ZipParser(fileBuffer);
				const lower = resolvedPath.toLowerCase();
				if (lower.endsWith(".aab") || zip.entries.some(e => e.name.startsWith("base/manifest/"))) {
					format = "AAB";
				} else if (lower.endsWith(".apks") || zip.entries.some(e => e.name.startsWith("splits/"))) {
					format = "APKS";
				} else if (
					lower.endsWith(".apk") ||
					zip.entries.some(e => e.name === "AndroidManifest.xml" || e.name.endsWith(".dex"))
				) {
					format = "APK";
				} else {
					format = "ZIP";
				}
			} catch {
				format = "unknown";
			}
		}

		if (format === "unknown") {
			const text = `[Unsupported] Target file is not an Android package (.apk, .aab, .apks) or Dalvik executable (.dex). File does not contain standard Android container headers.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: params.action,
					path: targetPath,
					status: "unsupported",
					size: fileStat.size,
					sha256,
					error: "Unsupported file format (expected .apk, .aab, .apks, or .dex)",
				},
			};
		}

		switch (params.action) {
			case "info":
				return this.handleInfo(targetPath, format, fileStat.size, sha256, fileBuffer, zip);
			case "manifest":
				return this.handleManifest(targetPath, format, zip, params, signal);
			case "dex":
				return this.handleDex(targetPath, format, fileBuffer, zip, params);
			case "signing":
				return this.handleSigning(targetPath, resolvedPath, format, fileBuffer, zip, params, signal);
			case "resources":
				return this.handleResources(targetPath, resolvedPath, format, zip, params, signal);
			default:
				throw new ToolError(`Unknown action: ${String(params.action)}`);
		}
	}

	// --------------------------------------------------------------------------
	// Action: info
	// --------------------------------------------------------------------------

	private handleInfo(
		targetPath: string,
		format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP",
		size: number,
		sha256: string,
		fileBuffer: Buffer,
		zip: ZipParser | null,
	): AgentToolResult<AndroidPackageInspectDetails> {
		if (format === "DEX" || !zip) {
			const dexData = parseDexBuffer(fileBuffer);
			if (!dexData) {
				return {
					content: [{ type: "text", text: `[Error] Truncated or corrupt DEX file: ${targetPath}` }],
					details: {
						action: "info",
						path: targetPath,
						status: "error",
						format: "DEX",
						size,
						sha256,
						error: "Truncated or corrupt DEX header",
					},
				};
			}

			const sampleClasses = extractDexClasses(dexData, fileBuffer).slice(0, 10);
			const lines = [
				`// Android Binary Inspection: Bare DEX File`,
				`Target: ${targetPath}`,
				`Format: DEX (version ${dexData.header.version})`,
				`Size: ${size} bytes | SHA-256: ${sha256}`,
				`Endianness: ${dexData.header.endian} | Header Size: ${dexData.header.headerSize} bytes`,
				`Checksum: ${dexData.header.checksum} | Signature: ${dexData.header.signature}`,
				`Counts:`,
				`  • Classes: ${dexData.header.classDefsCount}`,
				`  • Methods: ${dexData.header.methodIdsCount}`,
				`  • Fields: ${dexData.header.fieldIdsCount}`,
				`  • Prototypes: ${dexData.header.protoIdsCount}`,
				`  • Types: ${dexData.header.typeIdsCount}`,
				`  • Strings: ${dexData.header.stringIdsCount}`,
				`Data Segment: ${dexData.header.dataSize} bytes (offset: 0x${dexData.header.dataOff.toString(16)})`,
			];

			if (sampleClasses.length > 0) {
				lines.push(`Sample Classes (${sampleClasses.length} of ${dexData.header.classDefsCount}):`);
				for (const cls of sampleClasses) {
					const flagsStr = cls.flags.length > 0 ? ` [${cls.flags.join(", ")}]` : "";
					const superStr = cls.superclass ? ` extends ${cls.superclass}` : "";
					lines.push(`  • ${cls.name}${superStr}${flagsStr}`);
				}
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "info",
					path: targetPath,
					status: "ok",
					format: "DEX",
					size,
					sha256,
					info: {
						bareDex: {
							header: dexData.header,
							sampleClasses,
						},
					},
				},
			};
		}

		// Container analysis (.apk, .aab, .apks)
		const manifestEntry = zip.getEntry("AndroidManifest.xml") ?? zip.getEntry("base/manifest/AndroidManifest.xml");
		let manifestFormat: "binary_xml" | "plain_xml" | "compiled_proto" | "unknown" | undefined;
		if (manifestEntry) {
			const mBuf = zip.readFile(manifestEntry);
			if (mBuf) {
				if (mBuf.length >= 2 && mBuf.readUInt16LE(0) === 0x0003) {
					manifestFormat = "binary_xml";
				} else if (mBuf.toString("utf8", 0, Math.min(mBuf.length, 64)).includes("<")) {
					manifestFormat = "plain_xml";
				} else {
					manifestFormat = "compiled_proto";
				}
			}
		}

		// Native libraries grouped by ABI
		const nativeLibs: Record<string, string[]> = {};
		for (const entry of zip.entries) {
			const libMatch = entry.name.match(/(?:^|\/)lib\/([^/]+)\/(.+\.so)$/);
			if (libMatch) {
				const abi = libMatch[1];
				const soName = libMatch[2];
				nativeLibs[abi] ??= [];
				nativeLibs[abi].push(soName);
			}
		}

		// DEX entries
		const dexEntries: AndroidPackageDexEntry[] = [];
		const dexHeaders: AndroidDexHeaderInfo[] = [];
		let totalClasses = 0;
		let totalMethods = 0;
		let totalFields = 0;

		for (const entry of zip.entries) {
			if (entry.name.endsWith(".dex")) {
				const dexBuf = zip.readFile(entry);
				let headerInfo: AndroidDexHeaderInfo | undefined;
				let classCount: number | undefined;

				if (dexBuf) {
					const parsed = parseDexBuffer(dexBuf);
					if (parsed) {
						headerInfo = parsed.header;
						classCount = parsed.header.classDefsCount;
						dexHeaders.push(parsed.header);
						totalClasses += parsed.header.classDefsCount;
						totalMethods += parsed.header.methodIdsCount;
						totalFields += parsed.header.fieldIdsCount;
					}
				}

				dexEntries.push({
					name: entry.name,
					size: entry.uncompressedSize,
					header: headerInfo,
					classCount,
				});
			}
		}

		// Resource counts
		const arscEntry = zip.getEntry("resources.arsc") ?? zip.getEntry("base/resources.pb");
		let layoutsCount = 0;
		let drawablesCount = 0;
		let assetsCount = 0;
		let resTotal = 0;

		for (const entry of zip.entries) {
			if (entry.name.includes("res/layout")) layoutsCount++;
			if (entry.name.includes("res/drawable") || entry.name.includes("res/mipmap")) drawablesCount++;
			if (entry.name.startsWith("assets/") || entry.name.includes("/assets/")) assetsCount++;
			if (entry.name.includes("res/")) resTotal++;
		}

		// Signing files in META-INF
		const v1Files: string[] = [];
		for (const entry of zip.entries) {
			if (
				entry.name.startsWith("META-INF/") &&
				(entry.name.endsWith(".SF") ||
					entry.name.endsWith(".RSA") ||
					entry.name.endsWith(".DSA") ||
					entry.name.endsWith(".EC") ||
					entry.name === "META-INF/MANIFEST.MF")
			) {
				v1Files.push(entry.name);
			}
		}

		const signingBlock = parseApkSigningBlock(fileBuffer, zip.cdOffset);

		const lines = [
			`// Android Package Inspection: Container Overview`,
			`Target: ${targetPath}`,
			`Format: ${format}`,
			`Size: ${size} bytes | SHA-256: ${sha256}`,
			`Total Container Entries: ${zip.entries.length}`,
			`Manifest: ${manifestEntry ? `Present (${manifestEntry.name}, format: ${manifestFormat ?? "unknown"})` : "Not Found"}`,
			`DEX Files (${dexEntries.length}):`,
		];

		for (const d of dexEntries) {
			const clsStr = d.classCount !== undefined ? ` [${d.classCount} classes]` : "";
			const verStr = d.header?.version ? ` (dex v${d.header.version})` : "";
			lines.push(`  • ${d.name} (${d.size} bytes)${verStr}${clsStr}`);
		}
		if (dexHeaders.length > 0) {
			lines.push(`DEX Totals: ${totalClasses} classes, ${totalMethods} methods, ${totalFields} fields across ${dexEntries.length} DEX files`);
		}

		const abiList = Object.keys(nativeLibs);
		lines.push(`Native Libraries (${abiList.length} ABIs):`);
		if (abiList.length === 0) {
			lines.push(`  • None detected`);
		} else {
			for (const abi of abiList) {
				lines.push(`  • ${abi}: ${nativeLibs[abi].join(", ")}`);
			}
		}

		lines.push(`Resources:`);
		lines.push(`  • Table: ${arscEntry ? `Present (${arscEntry.name}, ${arscEntry.uncompressedSize} bytes)` : "None"}`);
		lines.push(`  • Files: ${resTotal} in res/ (${layoutsCount} layouts, ${drawablesCount} drawables), ${assetsCount} in assets/`);

		lines.push(`Signing Schemes Detected:`);
		lines.push(`  • v1 (JAR signing): ${v1Files.length > 0 ? `Yes (${v1Files.length} files: ${v1Files.join(", ")})` : "No"}`);
		lines.push(`  • APK Signing Block: ${signingBlock.present ? `Yes (size: ${signingBlock.size} bytes)` : "No"}`);
		if (signingBlock.present) {
			lines.push(`    - Scheme v2: ${signingBlock.v2Scheme ? "Yes" : "No"}`);
			lines.push(`    - Scheme v3: ${signingBlock.v3Scheme ? "Yes" : "No"}`);
			lines.push(`    - v2 Scheme: ${signingBlock.v2Scheme ? "Yes" : "No"}`);
			lines.push(`    - v3 Scheme: ${signingBlock.v3Scheme ? "Yes" : "No"}`);
			lines.push(`    - Scheme v2 (APK Signature Scheme v2): ${signingBlock.v2Scheme ? "Present (0x7109871a)" : "No"}`);
			lines.push(`    - Scheme v3 (APK Signature Scheme v3): ${signingBlock.v3Scheme ? "Present (0xf05368c0)" : "No"}`);
			lines.push(`    - v3.1 Scheme: ${signingBlock.v31Scheme ? "Yes" : "No"}`);
			lines.push(`    - SourceStamp: ${signingBlock.sourceStamp ? "Yes" : "No"}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "info",
				path: targetPath,
				status: "ok",
				format,
				size,
				sha256,
				info: {
					container: {
						totalEntries: zip.entries.length,
						manifestPresent: Boolean(manifestEntry),
						manifestFormat,
						dexFiles: dexEntries,
						nativeLibraries: nativeLibs,
						resources: {
							totalFiles: resTotal,
							hasArsc: Boolean(arscEntry),
							arscSize: arscEntry?.uncompressedSize,
							layoutsCount,
							drawablesCount,
							assetsCount,
						},
						signing: {
							v1Files,
							v1Signed: v1Files.length > 0,
							apkSigningBlock: signingBlock.present,
							v2Scheme: Boolean(signingBlock.v2Scheme),
							v3Scheme: Boolean(signingBlock.v3Scheme),
							v31Scheme: Boolean(signingBlock.v31Scheme),
							sourceStamp: Boolean(signingBlock.sourceStamp),
						},
					},
					dexSummary: {
						totalDexCount: dexEntries.length,
						totalClasses,
						totalMethods,
						totalFields,
						headers: dexHeaders,
					},
				},
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: manifest
	// --------------------------------------------------------------------------

	private async handleManifest(
		targetPath: string,
		format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP",
		zip: ZipParser | null,
		params: AndroidPackageInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidPackageInspectDetails>> {
		if (format === "DEX" || !zip) {
			const text = `[Unsupported] Manifest inspection is not applicable to bare Dalvik executable (.dex) files. Target is a raw DEX binary without an Android package container.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "manifest",
					path: targetPath,
					status: "unsupported",
					format: "DEX",
					error: "Manifest inspection is not applicable to bare DEX files",
				},
			};
		}

		const manifestEntry = zip.getEntry("AndroidManifest.xml") ?? zip.getEntry("base/manifest/AndroidManifest.xml");
		if (!manifestEntry) {
			return {
				content: [{ type: "text", text: `[Error] AndroidManifest.xml not found in package: ${targetPath}` }],
				details: {
					action: "manifest",
					path: targetPath,
					status: "error",
					format,
					error: "AndroidManifest.xml entry not found in archive",
				},
			};
		}

		const mBuf = zip.readFile(manifestEntry);
		if (!mBuf) {
			return {
				content: [{ type: "text", text: `[Error] Failed to read AndroidManifest.xml from package: ${targetPath}` }],
				details: {
					action: "manifest",
					path: targetPath,
					status: "error",
					format,
					error: "Failed to decompress AndroidManifest.xml",
				},
			};
		}

		let metadata: AndroidManifestMetadata | null = null;
		if (mBuf.length >= 2 && mBuf.readUInt16LE(0) === 0x0003) {
			metadata = parseAxml(mBuf);
		} else {
			const str = mBuf.toString("utf8");
			if (str.includes("<manifest")) {
				metadata = parseXmlText(str);
			}
		}

		if (!metadata) {
			// Manifest is compiled protobuf or unsupported format (common in AAB)
			if (params.use_bridge) {
				const resolved = resolveReadPath(targetPath, this.session.cwd);
				const bridge = await runAapt2Bridge(resolved, this.options.which, signal);
				if (bridge.available && bridge.output) {
					return {
						content: [
							{
								type: "text",
								text: `// Android Manifest (aapt2 bridge output):\n${bridge.output}`,
							},
						],
						details: {
							action: "manifest",
							path: targetPath,
							status: "ok",
							format,
							error: undefined,
						},
					};
				}
			}

			const text = `[Unsupported] AndroidManifest.xml is in compiled Protobuf binary format (common in Android App Bundles / .aab) or unrecognized format. Native protobuf decoding is not supported; use aapt2 bridge (use_bridge: true) or bundletool.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "manifest",
					path: targetPath,
					status: "unsupported",
					format,
					error: "Manifest is in compiled Protobuf format without aapt2 bridge",
				},
			};
		}

		const lines = [
			`// Android Package Manifest Inspection`,
			`Target: ${targetPath} (${manifestEntry.name})`,
			`Package: ${metadata.package}`,
			`Version: ${metadata.versionName ?? "none"} (versionCode: ${metadata.versionCode ?? "none"})`,
			`SDK Versions: min: ${metadata.minSdkVersion ?? "unspecified"}, target: ${metadata.targetSdkVersion ?? "unspecified"}, compile: ${metadata.compileSdkVersion ?? "unspecified"}`,
			`Application: name: ${metadata.application.name ?? "default"}, label: ${metadata.application.label ?? "none"}, debuggable: ${metadata.application.debuggable ?? false}, allowBackup: ${metadata.application.allowBackup ?? true}`,
			`Permissions Requested (${metadata.permissions.length}):`,
		];

		if (metadata.permissions.length === 0) {
			lines.push(`  • None`);
		} else {
			for (const p of metadata.permissions) {
				lines.push(`  • ${p}`);
			}
		}

		if (metadata.permissionsDeclared.length > 0) {
			lines.push(`Permissions Declared (${metadata.permissionsDeclared.length}):`);
			for (const p of metadata.permissionsDeclared) {
				lines.push(`  • ${p}`);
			}
		}

		lines.push(`Components (${metadata.totalComponents} total):`);
		lines.push(`  • Activities (${metadata.activities.length}):`);
		for (const act of metadata.activities.slice(0, 30)) {
			const expStr = act.exported !== undefined ? ` [exported: ${act.exported}]` : "";
			lines.push(`    - ${act.name}${expStr}`);
		}
		if (metadata.activities.length > 30) {
			lines.push(`    ... (${metadata.activities.length - 30} more activities omitted)`);
		}

		lines.push(`  • Services (${metadata.services.length}):`);
		for (const s of metadata.services.slice(0, 20)) {
			const expStr = s.exported !== undefined ? ` [exported: ${s.exported}]` : "";
			lines.push(`    - ${s.name}${expStr}`);
		}

		lines.push(`  • Broadcast Receivers (${metadata.receivers.length}):`);
		for (const r of metadata.receivers.slice(0, 20)) {
			const expStr = r.exported !== undefined ? ` [exported: ${r.exported}]` : "";
			lines.push(`    - ${r.name}${expStr}`);
		}

		lines.push(`  • Content Providers (${metadata.providers.length}):`);
		for (const prov of metadata.providers.slice(0, 20)) {
			const authStr = prov.authorities ? ` (auth: ${prov.authorities})` : "";
			const expStr = prov.exported !== undefined ? ` [exported: ${prov.exported}]` : "";
			lines.push(`    - ${prov.name}${authStr}${expStr}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "manifest",
				path: targetPath,
				status: "ok",
				format,
				manifest: metadata,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: dex
	// --------------------------------------------------------------------------

	private handleDex(
		targetPath: string,
		format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP",
		fileBuffer: Buffer,
		zip: ZipParser | null,
		params: AndroidPackageInspectParams,
	): AgentToolResult<AndroidPackageInspectDetails> {
		if (format === "DEX" || !zip) {
			const parsed = parseDexBuffer(fileBuffer);
			if (!parsed) {
				return {
					content: [{ type: "text", text: `[Error] Truncated or corrupt DEX file: ${targetPath}` }],
					details: {
						action: "dex",
						path: targetPath,
						status: "error",
						format: "DEX",
						error: "Truncated or corrupt DEX header",
					},
				};
			}

			const allClasses = extractDexClasses(parsed, fileBuffer, params.filter);
			const offset = Math.max(0, params.offset ?? 0);
			const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_LIST_LIMIT), MAX_LIST_LIMIT);
			const paged = allClasses.slice(offset, offset + limit);

			const lines = [
				`// Android DEX Inspection: Bare DEX File`,
				`Target: ${targetPath}`,
				`Version: dex v${parsed.header.version} | Endian: ${parsed.header.endian} | Size: ${fileBuffer.length} bytes`,
				`Header Counts: ${parsed.header.classDefsCount} classes, ${parsed.header.methodIdsCount} methods, ${parsed.header.fieldIdsCount} fields, ${parsed.header.stringIdsCount} strings`,
				`Classes (${paged.length} shown of ${allClasses.length} matching, total ${parsed.header.classDefsCount}, offset ${offset}):`,
			];

			for (const cls of paged) {
				const flagsStr = cls.flags.length > 0 ? ` [${cls.flags.join(", ")}]` : "";
				const superStr = cls.superclass ? ` extends ${cls.superclass}` : "";
				lines.push(`  #${cls.index}: ${cls.name}${superStr}${flagsStr}`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "dex",
					path: targetPath,
					status: "ok",
					format: "DEX",
					dex: {
						dexFiles: [
							{
								name: targetPath,
								size: fileBuffer.length,
								header: parsed.header,
								classCount: parsed.header.classDefsCount,
							},
						],
						classes: paged,
						totalClasses: allClasses.length,
					},
					total: allClasses.length,
					count: paged.length,
					offset,
					hasMore: offset + paged.length < allClasses.length,
				},
			};
		}

		// DEX files in container (.apk, .aab)
		const dexEntries = zip.entries.filter(e => e.name.endsWith(".dex"));
		if (dexEntries.length === 0) {
			return {
				content: [{ type: "text", text: `[Notice] No .dex entries found in package: ${targetPath}` }],
				details: {
					action: "dex",
					path: targetPath,
					status: "ok",
					format,
					dex: {
						dexFiles: [],
						classes: [],
						totalClasses: 0,
					},
					total: 0,
					count: 0,
				},
			};
		}

		// Choose target DEX
		let targetDexEntry = dexEntries[0];
		if (params.dex_index !== undefined && params.dex_index >= 0 && params.dex_index < dexEntries.length) {
			targetDexEntry = dexEntries[params.dex_index];
		} else if (params.dex) {
			const found = dexEntries.find(e => e.name === params.dex || e.name.endsWith(`/${params.dex}`));
			if (found) targetDexEntry = found;
		}

		const dexSummaryList: AndroidPackageDexEntry[] = [];
		for (const e of dexEntries) {
			const buf = zip.readFile(e);
			const parsed = buf ? parseDexBuffer(buf) : null;
			dexSummaryList.push({
				name: e.name,
				size: e.uncompressedSize,
				header: parsed?.header,
				classCount: parsed?.header.classDefsCount,
			});
		}

		const targetBuf = zip.readFile(targetDexEntry);
		if (!targetBuf) {
			return {
				content: [{ type: "text", text: `[Error] Failed to read ${targetDexEntry.name} from ${targetPath}` }],
				details: {
					action: "dex",
					path: targetPath,
					status: "error",
					format,
					error: `Failed to decompress ${targetDexEntry.name}`,
				},
			};
		}

		const parsedTarget = parseDexBuffer(targetBuf);
		if (!parsedTarget) {
			return {
				content: [{ type: "text", text: `[Error] Truncated or corrupt DEX file: ${targetDexEntry.name}` }],
				details: {
					action: "dex",
					path: targetPath,
					status: "error",
					format,
					error: `Truncated or corrupt DEX: ${targetDexEntry.name}`,
				},
			};
		}

		const allClasses = extractDexClasses(parsedTarget, targetBuf, params.filter);
		const offset = Math.max(0, params.offset ?? 0);
		const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_LIST_LIMIT), MAX_LIST_LIMIT);
		const paged = allClasses.slice(offset, offset + limit);

		const lines = [
			`// Android Package DEX Inspection`,
			`Target: ${targetPath} -> ${targetDexEntry.name}`,
			`Container DEX Files (${dexEntries.length}):`,
		];

		for (let i = 0; i < dexSummaryList.length; i++) {
			const d = dexSummaryList[i];
			const activeMarker = d.name === targetDexEntry.name ? " [*active*]" : "";
			const clsCount = d.classCount !== undefined ? ` [${d.classCount} classes]` : "";
			lines.push(`  [${i}] ${d.name} (${d.size} bytes)${clsCount}${activeMarker}`);
		}

		lines.push(`Selected DEX (${targetDexEntry.name}):`);
		lines.push(`  • Version: dex v${parsedTarget.header.version} | Endian: ${parsedTarget.header.endian}`);
		lines.push(`  • Header Metrics: ${parsedTarget.header.classDefsCount} classes, ${parsedTarget.header.methodIdsCount} methods, ${parsedTarget.header.fieldIdsCount} fields`);
		lines.push(
			`Classes (${paged.length} shown of ${allClasses.length} matching, total ${parsedTarget.header.classDefsCount}, offset ${offset}):`,
		);

		for (const cls of paged) {
			const flagsStr = cls.flags.length > 0 ? ` [${cls.flags.join(", ")}]` : "";
			const superStr = cls.superclass ? ` extends ${cls.superclass}` : "";
			lines.push(`  #${cls.index}: ${cls.name}${superStr}${flagsStr}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "dex",
				path: targetPath,
				status: "ok",
				format,
				dex: {
					dexFiles: dexSummaryList,
					selectedDex: targetDexEntry.name,
					classes: paged,
					totalClasses: allClasses.length,
				},
				total: allClasses.length,
				count: paged.length,
				offset,
				hasMore: offset + paged.length < allClasses.length,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: signing
	// --------------------------------------------------------------------------

	private async handleSigning(
		targetPath: string,
		resolvedPath: string,
		format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP",
		fileBuffer: Buffer,
		zip: ZipParser | null,
		params: AndroidPackageInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidPackageInspectDetails>> {
		if (format === "DEX" || !zip) {
			const text = `[Unsupported] Signing inspection is not applicable to bare Dalvik executable (.dex) files. Bare DEX files do not possess an APK signature block or META-INF certificate manifest.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "signing",
					path: targetPath,
					status: "unsupported",
					format: "DEX",
					error: "Signing inspection is not applicable to bare DEX files",
				},
			};
		}

		// v1 JAR signing evidence
		const manifestFile = Boolean(zip.getEntry("META-INF/MANIFEST.MF"));
		const signatureFiles: string[] = [];
		const blockFiles: string[] = [];

		for (const e of zip.entries) {
			if (e.name.startsWith("META-INF/")) {
				if (e.name.endsWith(".SF")) {
					signatureFiles.push(e.name);
				} else if (e.name.endsWith(".RSA") || e.name.endsWith(".DSA") || e.name.endsWith(".EC")) {
					blockFiles.push(e.name);
				}
			}
		}

		const v1Detected = manifestFile && signatureFiles.length > 0 && blockFiles.length > 0;

		// v2/v3/v3.1 APK Signing Block
		const signingBlock = parseApkSigningBlock(fileBuffer, zip.cdOffset);

		// Optional apksigner bridge
		let bridgeStatus: {
			available: boolean;
			path?: string;
			installHint?: string;
			verified?: boolean;
			output?: string;
		} = { available: false };

		if (params.use_bridge) {
			bridgeStatus = await runApksignerBridge(resolvedPath, this.options.which, signal);
		} else {
			const reqs = [{ id: "apksigner" }];
			const [chk] = checkToolRequirements(reqs, this.options.which ? { which: this.options.which } : undefined);
			bridgeStatus = {
				available: chk?.foundPath !== null && chk?.foundPath !== undefined,
				path: chk?.foundPath ?? undefined,
				installHint: chk?.hint ?? "Install via Android SDK build-tools;35.0.0",
			};
		}

		const signingSummary: AndroidSigningSummary = {
			schemes: {
				v1: {
					detected: v1Detected,
					manifest: manifestFile,
					signatureFiles,
					blockFiles,
				},
				v2: {
					detected: Boolean(signingBlock.v2Scheme),
					blockPresent: Boolean(signingBlock.v2Scheme),
				},
				v3: {
					detected: Boolean(signingBlock.v3Scheme),
					blockPresent: Boolean(signingBlock.v3Scheme),
				},
				v31: {
					detected: Boolean(signingBlock.v31Scheme),
				},
				sourceStamp: {
					detected: Boolean(signingBlock.sourceStamp),
				},
			},
			apkSigningBlock: signingBlock,
			apksignerBridge: bridgeStatus,
		};

		const lines = [
			`// Android Package Signature Scheme Inspection`,
			`Target: ${targetPath}`,
			`Signature Scheme Evidence:`,
			`  • Scheme v1 (JAR signing): ${v1Detected ? "Present (Verified evidence)" : "Not Found / Incomplete"}`,
			`    - MANIFEST.MF: ${manifestFile ? "Yes" : "No"}`,
			`    - Signature files (.SF): ${signatureFiles.length > 0 ? signatureFiles.join(", ") : "None"}`,
			`    - Block certificate files: ${blockFiles.length > 0 ? blockFiles.join(", ") : "None"}`,
			`  • APK Signing Block (Binary Block): ${signingBlock.present ? `Present (${signingBlock.size} bytes at offset 0x${signingBlock.offset?.toString(16)})` : "Not Present"}`,
		];

		if (signingBlock.present) {
			lines.push(`    - Scheme v2 (APK Signature Scheme v2): ${signingBlock.v2Scheme ? "Present (0x7109871a)" : "No"}`);
			lines.push(`    - Scheme v3 (APK Signature Scheme v3): ${signingBlock.v3Scheme ? "Present (0xf05368c0)" : "No"}`);
			lines.push(`    - Scheme v3.1: ${signingBlock.v31Scheme ? "Present (0x1b93ad61)" : "No"}`);
			lines.push(`    - SourceStamp: ${signingBlock.sourceStamp ? "Present (0x42726577)" : "No"}`);
			if (signingBlock.blockIds && signingBlock.blockIds.length > 0) {
				lines.push(`    - Recognized Block IDs: ${signingBlock.blockIds.map(b => `${b.id} (${b.name})`).join(", ")}`);
			}
		}

		lines.push(`External Bridge (apksigner):`);
		lines.push(`  • Tool Installed: ${bridgeStatus.available ? `Yes (${bridgeStatus.path})` : "No"}`);
		if (!bridgeStatus.available && bridgeStatus.installHint) {
			lines.push(`  • Install Hint: ${bridgeStatus.installHint}`);
		}
		if (bridgeStatus.output) {
			lines.push(`  • apksigner verify result: ${bridgeStatus.verified ? "VERIFIED" : "FAILED"}`);
			lines.push(
				bridgeStatus.output
					.split("\n")
					.map(l => `    ${l}`)
					.join("\n"),
			);
		} else if (!params.use_bridge) {
			lines.push(`  • (To run cryptographic verification with apksigner, pass use_bridge: true)`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "signing",
				path: targetPath,
				status: "ok",
				format,
				signing: signingSummary,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: resources
	// --------------------------------------------------------------------------

	private async handleResources(
		targetPath: string,
		resolvedPath: string,
		format: "APK" | "AAB" | "APKS" | "DEX" | "ZIP",
		zip: ZipParser | null,
		params: AndroidPackageInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidPackageInspectDetails>> {
		if (format === "DEX" || !zip) {
			const text = `[Unsupported] Resource inspection is not applicable to bare Dalvik executable (.dex) files. Raw DEX binaries do not contain an Android resource table (resources.arsc) or packaged res/ layout trees.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "resources",
					path: targetPath,
					status: "unsupported",
					format: "DEX",
					error: "Resource inspection is not applicable to bare DEX files",
				},
			};
		}

		const arscEntry = zip.getEntry("resources.arsc") ?? zip.getEntry("base/resources.pb");
		let arscInfo: { present: boolean; size?: number; packageCount?: number; packageName?: string } = {
			present: Boolean(arscEntry),
			size: arscEntry?.uncompressedSize,
		};

		if (arscEntry && arscEntry.name === "resources.arsc") {
			const arscBuf = zip.readFile(arscEntry);
			if (arscBuf) {
				const parsed = parseArscHeader(arscBuf);
				if (parsed) {
					arscInfo = {
						present: true,
						size: arscEntry.uncompressedSize,
						packageCount: parsed.packageCount,
						packageName: parsed.packageName,
					};
				}
			}
		}

		const layouts: string[] = [];
		const drawables: string[] = [];
		const xmls: string[] = [];
		const raws: string[] = [];
		const assets: string[] = [];
		let otherCount = 0;
		const matchingFiles: string[] = [];

		const filterLower = params.filter ? params.filter.toLowerCase() : null;

		for (const entry of zip.entries) {
			const name = entry.name;
			if (filterLower && name.toLowerCase().includes(filterLower)) {
				matchingFiles.push(name);
			}

			if (name.includes("res/layout")) {
				layouts.push(name);
			} else if (name.includes("res/drawable") || name.includes("res/mipmap")) {
				drawables.push(name);
			} else if (name.includes("res/xml")) {
				xmls.push(name);
			} else if (name.includes("res/raw")) {
				raws.push(name);
			} else if (name.startsWith("assets/") || name.includes("/assets/")) {
				assets.push(name);
			} else if (name.includes("res/")) {
				otherCount++;
			}
		}

		// Optional aapt2 bridge
		let bridgeStatus: {
			available: boolean;
			path?: string;
			installHint?: string;
			output?: string;
		} = { available: false };

		if (params.use_bridge) {
			bridgeStatus = await runAapt2Bridge(resolvedPath, this.options.which, signal);
		} else {
			const reqs = [{ id: "aapt2" }];
			const [chk] = checkToolRequirements(reqs, this.options.which ? { which: this.options.which } : undefined);
			bridgeStatus = {
				available: chk?.foundPath !== null && chk?.foundPath !== undefined,
				path: chk?.foundPath ?? undefined,
				installHint: chk?.hint ?? "Install via Android SDK build-tools;35.0.0",
			};
		}

		const breakdown: AndroidResourceBreakdown = {
			layouts: { count: layouts.length, samples: layouts.slice(0, 10) },
			drawables: { count: drawables.length, samples: drawables.slice(0, 10) },
			values: { count: arscInfo.present ? 1 : 0, hasArsc: arscInfo.present },
			xml: { count: xmls.length, samples: xmls.slice(0, 10) },
			raw: { count: raws.length, samples: raws.slice(0, 10) },
			assets: { count: assets.length, samples: assets.slice(0, 10) },
			other: { count: otherCount },
			totalFiles: layouts.length + drawables.length + xmls.length + raws.length + assets.length + otherCount,
		};

		const resourcesSummary: AndroidResourcesSummary = {
			arsc: arscInfo,
			breakdown,
			matchingFiles: filterLower ? matchingFiles : undefined,
			aapt2Bridge: bridgeStatus,
		};

		const lines = [
			`// Android Package Resources Inspection`,
			`Target: ${targetPath}`,
			`Resource Table (ARSC): ${arscInfo.present ? `Present (${arscInfo.size} bytes)` : "Not Found"}`,
		];

		if (arscInfo.present && arscInfo.packageCount !== undefined) {
			lines.push(`  • Packages in ARSC: ${arscInfo.packageCount}${arscInfo.packageName ? ` (primary: ${arscInfo.packageName})` : ""}`);
		}

		lines.push(`Resource Breakdown (${breakdown.totalFiles} files total):`);
		lines.push(`  • Layouts: ${breakdown.layouts.count} files (e.g. ${breakdown.layouts.samples.slice(0, 3).join(", ") || "none"})`);
		lines.push(`  • Drawables/Mipmaps: ${breakdown.drawables.count} files (e.g. ${breakdown.drawables.samples.slice(0, 3).join(", ") || "none"})`);
		lines.push(`  • XML Configurations: ${breakdown.xml.count} files (e.g. ${breakdown.xml.samples.slice(0, 3).join(", ") || "none"})`);
		lines.push(`  • Raw Resources: ${breakdown.raw.count} files (e.g. ${breakdown.raw.samples.slice(0, 3).join(", ") || "none"})`);
		lines.push(`  • Assets: ${breakdown.assets.count} files (e.g. ${breakdown.assets.samples.slice(0, 3).join(", ") || "none"})`);

		if (filterLower) {
			lines.push(`Filtered Results for "${params.filter}" (${matchingFiles.length} matches):`);
			for (const f of matchingFiles.slice(0, 30)) {
				lines.push(`  • ${f}`);
			}
			if (matchingFiles.length > 30) {
				lines.push(`  ... (${matchingFiles.length - 30} more matches omitted)`);
			}
		}

		lines.push(`External Bridge (aapt2):`);
		lines.push(`  • Tool Installed: ${bridgeStatus.available ? `Yes (${bridgeStatus.path})` : "No"}`);
		if (!bridgeStatus.available && bridgeStatus.installHint) {
			lines.push(`  • Install Hint: ${bridgeStatus.installHint}`);
		}
		if (bridgeStatus.output) {
			lines.push(`  • aapt2 dump badging output:`);
			lines.push(
				bridgeStatus.output
					.split("\n")
					.slice(0, 20)
					.map(l => `    ${l}`)
					.join("\n"),
			);
		} else if (!params.use_bridge) {
			lines.push(`  • (To dump full parsed resources with aapt2, pass use_bridge: true)`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "resources",
				path: targetPath,
				status: "ok",
				format,
				resources: resourcesSummary,
			},
		};
	}
}
