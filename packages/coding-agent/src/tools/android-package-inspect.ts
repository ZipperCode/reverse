import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import * as zlib from "node:zlib";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import { XMLParser } from "@reverse/utils/xml";
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
	"path?": type("string").describe("Path to target Android package (.apk, .aab, .apks) or Dalvik executable (.dex)"),
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
	stringIdsOff: number;
	typeIdsCount: number;
	typeIdsOff: number;
	protoIdsCount: number;
	protoIdsOff: number;
	fieldIdsCount: number;
	fieldIdsOff: number;
	methodIdsCount: number;
	methodIdsOff: number;
	classDefsCount: number;
	classDefsOff: number;
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

export interface AndroidIntentFilterData {
	scheme?: string;
	host?: string;
	port?: string;
	path?: string;
	pathPrefix?: string;
	pathPattern?: string;
	mimeType?: string;
}

export interface AndroidIntentFilter {
	actions: string[];
	categories: string[];
	data: AndroidIntentFilterData[];
	autoVerify?: boolean | "unknown";
}

export interface AndroidPathPermission {
	path?: string;
	pathPrefix?: string;
	pathPattern?: string;
	permission?: string;
	readPermission?: string;
	writePermission?: string;
}

export interface AndroidManifestComponent {
	name: string;
	type?: "activity" | "activity-alias" | "service" | "receiver" | "provider";
	exported?: boolean;
	rawExported?: string;
	effectiveExported?: boolean | "unknown";
	exportReason?: string;
	permission?: string;
	readPermission?: string;
	writePermission?: string;
	inheritedPermission?: string;
	effectivePermission?: string;
	effectiveReadPermission?: string;
	effectiveWritePermission?: string;
	authorities?: string;
	grantUriPermissions?: boolean;
	hasGrantUriPermissionTags?: boolean;
	pathPermissions?: AndroidPathPermission[];
	enabled?: boolean | "unknown";
	rawEnabled?: string;
	process?: string;
	targetActivity?: string;
	intentFilters?: AndroidIntentFilter[];
}

export interface AndroidDeepLink {
	component: string;
	componentType: "activity" | "activity-alias";
	schemes: string[];
	hosts: string[];
	pathPatterns: Array<{
		type: "literal" | "prefix" | "pattern";
		value: string;
	}>;
	mimeType?: string;
	autoVerify?: boolean | "unknown";
	actions: string[];
	categories: string[];
	exported: boolean | "unknown";
	permission?: string;
	sampleUris: string[];
}

export interface AndroidNetworkSecurityConfigPin {
	digest: string;
	value: string;
}

export interface AndroidNetworkSecurityConfigTrustAnchor {
	src: string;
	overridePins?: boolean;
}

export interface AndroidNetworkSecurityConfigDomain {
	domain: string;
	includeSubdomains: boolean;
	cleartextTrafficPermitted?: boolean | "unknown";
	pinSet?: {
		expiration?: string;
		pins: AndroidNetworkSecurityConfigPin[];
	};
	trustAnchors?: AndroidNetworkSecurityConfigTrustAnchor[];
}

export interface AndroidNetworkSecurityConfigData {
	rawRef?: string;
	resolvedFile?: string;
	format?: "plain_xml" | "binary_xml";
	unresolvedResourceId?: string;
	cleartextTrafficPermitted?: boolean | "unknown";
	baseTrustAnchors?: AndroidNetworkSecurityConfigTrustAnchor[];
	domainConfigs?: AndroidNetworkSecurityConfigDomain[];
	debugOverrides?: {
		cleartextTrafficPermitted?: boolean | "unknown";
		trustAnchors?: AndroidNetworkSecurityConfigTrustAnchor[];
	};
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
	declaredPermissions?: Array<{
		name: string;
		protectionLevel?: string;
	}>;
	application: {
		name?: string;
		label?: string;
		icon?: string;
		debuggable?: boolean;
		rawDebuggable?: string;
		allowBackup?: boolean;
		rawAllowBackup?: string;
		extractNativeLibs?: boolean;
		rawExtractNativeLibs?: string;
		useEmbeddedDex?: boolean;
		rawUseEmbeddedDex?: string;
		hasCode?: boolean;
		rawHasCode?: string;
		usesCleartextTraffic?: boolean;
		rawUsesCleartextTraffic?: string;
		networkSecurityConfig?: string;
		permission?: string;
		enabled?: boolean;
		rawEnabled?: string;
		effectiveEnabled?: boolean | "unknown";
	};
	activities: AndroidManifestComponent[];
	services: AndroidManifestComponent[];
	receivers: AndroidManifestComponent[];
	providers: AndroidManifestComponent[];
	totalComponents: number;
	deepLinks?: AndroidDeepLink[];
	networkSecurityConfig?: AndroidNetworkSecurityConfigData;
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

	readFile(entry: ZipEntry, maxOutputLength?: number): Buffer | null {
		if (entry.localHeaderOffset + 30 > this.buffer.length) return null;
		const sig = this.buffer.readUInt32LE(entry.localHeaderOffset);
		if (sig !== 0x04034b50) return null;

		const nameLen = this.buffer.readUInt16LE(entry.localHeaderOffset + 26);
		const extraLen = this.buffer.readUInt16LE(entry.localHeaderOffset + 28);
		const dataStart = entry.localHeaderOffset + 30 + nameLen + extraLen;
		const dataEnd = dataStart + entry.compressedSize;

		if (dataEnd > this.buffer.length) return null;
		const rawData = this.buffer.subarray(dataStart, dataEnd);

		if (maxOutputLength && entry.uncompressedSize > maxOutputLength) {
			return null;
		}

		if (entry.compressionMethod === 0) {
			if (maxOutputLength && rawData.length > maxOutputLength) return null;
			return Buffer.from(rawData);
		}
		if (entry.compressionMethod === 8) {
			try {
				return zlib.inflateRawSync(rawData, maxOutputLength ? { maxOutputLength } : undefined);
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
			stringIdsOff,
			typeIdsCount: typeIdsSize,
			typeIdsOff,
			protoIdsCount: protoIdsSize,
			protoIdsOff,
			fieldIdsCount: fieldIdsSize,
			fieldIdsOff,
			methodIdsCount: methodIdsSize,
			methodIdsOff,
			classDefsCount: classDefsSize,
			classDefsOff,
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
			superclassIdx !== 0xffffffff ? (dex.getClassNameFromTypeIdx(superclassIdx) ?? undefined) : undefined;

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

export function parseBooleanAttr(val: unknown): { value?: boolean; isReference?: boolean; raw?: string } {
	if (val === undefined || val === null) return {};
	if (typeof val === "boolean") return { value: val };
	if (typeof val === "number") return { value: val !== 0 };
	if (typeof val === "string") {
		const trimmed = val.trim();
		if (trimmed === "true" || trimmed === "1") return { value: true };
		if (trimmed === "false" || trimmed === "0") return { value: false };
		if (trimmed.startsWith("@")) return { isReference: true, raw: trimmed };
	}
	return {};
}

export function calculateEffectiveEnabled(
	compEnabledParsed: { value?: boolean; isReference?: boolean; raw?: string },
	appEnabledParsed: { value?: boolean; isReference?: boolean; raw?: string },
): boolean | "unknown" {
	// Android 官方语义 (https://developer.android.com/guide/topics/manifest/application-element#enabled)：
	// 1. 若 application 的 android:enabled 明确为 false，则覆盖所有组件设置，组件均不可被实例化
	if (appEnabledParsed.value === false) {
		return false;
	}
	// 2. 若组件自身的 android:enabled 明确为 false，则组件被禁用
	if (compEnabledParsed.value === false) {
		return false;
	}
	// 3. 若 application 的 enabled 是未解析的资源引用（如 @bool/...），且未明确被组件 false 覆盖，无法静态判定
	if (appEnabledParsed.isReference) {
		return "unknown";
	}
	// 4. 若组件自身的 enabled 是未解析的资源引用，且 application 未为 false，无法静态判定
	if (compEnabledParsed.isReference) {
		return "unknown";
	}
	// 5. 其余情况：application 与 component 均为 true 或未声明（默认 true），组件生效启用
	return true;
}

export function calculateEffectiveExported(
	componentType: "activity" | "activity-alias" | "service" | "receiver" | "provider",
	declaredExported: boolean | undefined,
	hasIntentFilters: boolean,
	targetSdkVersion: number | string | undefined,
	isResourceReference = false,
	rawRef?: string,
	minSdkVersion?: number | string | undefined,
): { effective: boolean | "unknown"; reason: string } {
	// 1. 未解析的资源引用（例如 @bool/is_exported 或 @0x7f050001）
	if (isResourceReference) {
		return {
			effective: "unknown",
			reason: `Unresolved resource reference (${rawRef ?? "@..."}) for exported attribute; cannot determine static boolean value without resource table`,
		};
	}

	// 2. 显式声明的 exported 取值优先（AOSP PackageParser 即使在 API <= 16 也尊重 ContentProvider 显式 exported=false）
	if (declaredExported !== undefined) {
		return {
			effective: declaredExported,
			reason: `Explicitly declared exported="${declaredExported}"`,
		};
	}

	// 3. 解析 targetSdkVersion 与 minSdkVersion，区分“未声明（默认值）”与“未解析（未知）”
	let targetIsUnknown = false;
	let parsedTarget: number | undefined;

	if (targetSdkVersion !== undefined) {
		if (typeof targetSdkVersion === "number") {
			parsedTarget = targetSdkVersion;
		} else if (typeof targetSdkVersion === "string" && /^\d+$/.test(targetSdkVersion.trim())) {
			parsedTarget = parseInt(targetSdkVersion.trim(), 10);
		} else {
			targetIsUnknown = true;
		}
	}

	let minIsUnknown = false;
	let parsedMin: number | undefined;

	if (minSdkVersion !== undefined) {
		if (typeof minSdkVersion === "number") {
			parsedMin = minSdkVersion;
		} else if (typeof minSdkVersion === "string" && /^\d+$/.test(minSdkVersion.trim())) {
			parsedMin = parseInt(minSdkVersion.trim(), 10);
		} else {
			minIsUnknown = true;
		}
	}

	// 官方文档规则（https://developer.android.com/guide/topics/manifest/uses-sdk-element#target）：
	// 若 targetSdkVersion 未设置，其默认值与 minSdkVersion 相同；若 minSdkVersion 亦未设置，则默认值为 1
	let effectiveTargetSdk: number | undefined;
	if (targetIsUnknown) {
		effectiveTargetSdk = undefined;
	} else if (parsedTarget !== undefined) {
		effectiveTargetSdk = parsedTarget;
	} else if (minIsUnknown) {
		effectiveTargetSdk = undefined;
	} else if (parsedMin !== undefined) {
		effectiveTargetSdk = parsedMin;
	} else {
		effectiveTargetSdk = 1;
	}

	// 4. ContentProvider 默认导出规则与 API 17 临界特性
	if (componentType === "provider") {
		if (effectiveTargetSdk === undefined) {
			return {
				effective: "unknown",
				reason: "targetSdkVersion is unknown/unresolved; cannot determine provider default exported state",
			};
		}

		if (effectiveTargetSdk < 17) {
			return {
				effective: true,
				reason: `Undeclared on targetSdkVersion < 17 (${effectiveTargetSdk}); defaults to exported=true across all Android versions`,
			};
		}

		// targetSdkVersion >= 17：在 API >= 17 设备上默认 exported=false；若 minSdkVersion 未解析或 < 17（未指定时默认 minSdk 为 1），在 API <= 16 设备上平台默认 exported=true
		if (minIsUnknown) {
			return {
				effective: "unknown",
				reason: `targetSdkVersion >= 17 (${effectiveTargetSdk}) with unresolved minSdkVersion (${minSdkVersion}); cannot establish whether minSdkVersion >= 17`,
			};
		}
		const effectiveMin = parsedMin ?? 1;
		if (effectiveMin < 17) {
			return {
				effective: "unknown",
				reason: `Undeclared on targetSdkVersion >= 17 (${effectiveTargetSdk}) with minSdkVersion < 17 (${effectiveMin}); runtime default is environment-dependent (exported=true on devices running API <= 16, exported=false on API >= 17)`,
			};
		}

		return {
			effective: false,
			reason: `Undeclared on targetSdkVersion >= 17 (${effectiveTargetSdk}); defaults to exported=false`,
		};
	}
	// 5. 带有 intent-filter 的 Activity/Service/Receiver/Alias 默认导出规则
	if (hasIntentFilters) {
		if (effectiveTargetSdk === undefined) {
			return {
				effective: "unknown",
				reason:
					"targetSdkVersion is unknown/unresolved; cannot determine default exported state for component with intent-filters",
			};
		}

		if (effectiveTargetSdk >= 31) {
			return {
				effective: "unknown",
				reason: `targetSdkVersion >= 31 (${effectiveTargetSdk}) requires explicit android:exported declaration when intent-filters exist; omitted exported causes installation failure (status unknown/invalid)`,
			};
		}

		return {
			effective: true,
			reason: `Default for component with intent-filters when targetSdkVersion (${effectiveTargetSdk}) < 31 is exported=true`,
		};
	}

	// 6. 无 intent-filter 的组件默认导出规则为 false
	return {
		effective: false,
		reason: "Default for component without intent-filters is exported=false",
	};
}

export function extractDeepLinks(activities: AndroidManifestComponent[]): AndroidDeepLink[] {
	const deepLinks: AndroidDeepLink[] = [];

	for (const comp of activities) {
		if (!comp.intentFilters || comp.intentFilters.length === 0) continue;

		for (const filter of comp.intentFilters) {
			const hasViewAction = filter.actions.includes("android.intent.action.VIEW");
			const hasData = filter.data.length > 0;
			if (!hasViewAction || !hasData) continue;

			const schemes = Array.from(new Set(filter.data.map(d => d.scheme).filter((s): s is string => Boolean(s))));
			const authorities: Array<{ host: string; port?: string }> = [];
			for (const d of filter.data) {
				if (d.host) {
					const existing = authorities.find(a => a.host === d.host && a.port === d.port);
					if (!existing) {
						authorities.push({ host: d.host, port: d.port });
					}
				}
			}
			const hosts = Array.from(new Set(authorities.map(a => a.host)));
			const pathPatterns: Array<{ type: "literal" | "prefix" | "pattern"; value: string }> = [];

			for (const d of filter.data) {
				if (d.path) pathPatterns.push({ type: "literal", value: d.path });
				if (d.pathPrefix) pathPatterns.push({ type: "prefix", value: d.pathPrefix });
				if (d.pathPattern) pathPatterns.push({ type: "pattern", value: d.pathPattern });
			}

			const mimeTypes = Array.from(new Set(filter.data.map(d => d.mimeType).filter((m): m is string => Boolean(m))));

			const sampleUris: string[] = [];
			const MAX_SAMPLE_URIS = 10;

			// 仅 literal 与 prefix 生成确定的静态样本 URI；pattern（正则/通配）独立保留在 pathPatterns 中，不臆造虚假样本
			const concretePaths = pathPatterns
				.filter(p => p.type === "literal" || p.type === "prefix")
				.map(p => (p.value.startsWith("/") ? p.value : `/${p.value}`));

			// 在构造笛卡尔积前进行预截断，防止维度爆炸
			const boundedSchemes = schemes.slice(0, 3);
			const boundedAuths = authorities.slice(0, 3);
			const boundedPaths = concretePaths.slice(0, 5);

			if (boundedSchemes.length > 0) {
				for (const scheme of boundedSchemes) {
					if (sampleUris.length >= MAX_SAMPLE_URIS) break;
					if (boundedAuths.length > 0) {
						for (const auth of boundedAuths) {
							if (sampleUris.length >= MAX_SAMPLE_URIS) break;
							const concreteHost = auth.host.startsWith("*.") ? `app.${auth.host.slice(2)}` : auth.host;
							const authorityStr = auth.port ? `${concreteHost}:${auth.port}` : concreteHost;

							if (boundedPaths.length > 0) {
								for (const sPath of boundedPaths) {
									if (sampleUris.length >= MAX_SAMPLE_URIS) break;
									sampleUris.push(`${scheme}://${authorityStr}${sPath}`);
								}
							} else if (pathPatterns.length === 0) {
								sampleUris.push(`${scheme}://${authorityStr}`);
							}
						}
					} else {
						if (boundedPaths.length > 0) {
							for (const sPath of boundedPaths) {
								if (sampleUris.length >= MAX_SAMPLE_URIS) break;
								sampleUris.push(`${scheme}://${sPath.slice(1)}`);
							}
						} else if (pathPatterns.length === 0) {
							sampleUris.push(`${scheme}://`);
						}
					}
				}
			}
			deepLinks.push({
				component: comp.name,
				componentType: comp.type === "activity-alias" ? "activity-alias" : "activity",
				schemes,
				hosts,
				pathPatterns,
				mimeType: mimeTypes.length > 0 ? mimeTypes.join(", ") : undefined,
				autoVerify: filter.autoVerify !== undefined ? filter.autoVerify : false,
				actions: filter.actions,
				categories: filter.categories,
				exported: comp.effectiveExported ?? "unknown",
				permission: comp.effectivePermission,
				sampleUris: Array.from(new Set(sampleUris)),
			});
		}
	}

	return deepLinks;
}

export interface GenericXmlNode {
	tag: string;
	attrs: Record<string, string | number | boolean>;
	text?: string;
	children: GenericXmlNode[];
	isTruncated?: boolean;
}

export function getNodeAttr(
	node: GenericXmlNode | Record<string, unknown> | undefined,
	attrName: string,
): string | undefined {
	if (!node || typeof node !== "object") return undefined;
	if ("attrs" in node && typeof (node as GenericXmlNode).attrs === "object") {
		const gNode = node as GenericXmlNode;
		const lower = attrName.toLowerCase();
		if (gNode.attrs[lower] !== undefined) return String(gNode.attrs[lower]);
		if (gNode.attrs[attrName] !== undefined) return String(gNode.attrs[attrName]);
		for (const [k, v] of Object.entries(gNode.attrs)) {
			const bare = k.includes(":") ? k.split(":").pop()!.toLowerCase() : k.toLowerCase();
			if (bare === lower) return String(v);
		}
		return undefined;
	}
	const lower = attrName.toLowerCase();
	for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
		if (!key.startsWith("@_")) continue;
		const rawKey = key.slice(2);
		const bare = rawKey.includes(":") ? rawKey.split(":").pop()! : rawKey;
		if (bare.toLowerCase() === lower || rawKey.toLowerCase() === lower) {
			return String(value);
		}
	}
	return undefined;
}

export function getChildNodes(
	parent: GenericXmlNode | Record<string, unknown> | undefined,
	tagName: string,
): Array<GenericXmlNode | Record<string, unknown>> {
	if (!parent || typeof parent !== "object") return [];
	if ("children" in parent && Array.isArray((parent as GenericXmlNode).children)) {
		const lower = tagName.toLowerCase();
		return (parent as GenericXmlNode).children.filter(c => c.tag === lower);
	}
	const lower = tagName.toLowerCase();
	const matches: Array<Record<string, unknown>> = [];
	for (const [key, value] of Object.entries(parent as Record<string, unknown>)) {
		if (key.startsWith("@_") || key.startsWith("#")) continue;
		const bare = key.includes(":") ? key.split(":").pop()! : key;
		if (bare.toLowerCase() === lower) {
			if (Array.isArray(value)) {
				for (const item of value) {
					if (item && typeof item === "object") matches.push(item as Record<string, unknown>);
				}
			} else if (value && typeof value === "object") {
				matches.push(value as Record<string, unknown>);
			}
		}
	}
	return matches;
}
function decodeXmlEntities(str: string): string {
	return str.replace(/&(?:(amp|lt|gt|quot|apos)|#(\d+)|#x([0-9a-fA-F]+));/g, (_, named, dec, hex) => {
		if (named) {
			if (named === "amp") return "&";
			if (named === "lt") return "<";
			if (named === "gt") return ">";
			if (named === "quot") return '"';
			if (named === "apos") return "'";
		}
		try {
			const code = dec ? parseInt(dec, 10) : parseInt(hex, 16);
			if (code >= 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff)) {
				return String.fromCodePoint(code);
			}
		} catch {
			// 忽略异常 code point
		}
		return "";
	});
}

export function convertFastXmlToNode(name: string, val: unknown): GenericXmlNode {
	const bareTag = name.includes(":") ? name.split(":").pop()!.toLowerCase() : name.toLowerCase();
	const attrs: Record<string, string | number | boolean> = {};
	const children: GenericXmlNode[] = [];
	let text: string | undefined;

	if (typeof val === "string" || typeof val === "number" || typeof val === "boolean") {
		text = typeof val === "string" ? decodeXmlEntities(val.trim()) : String(val).trim();
	} else if (val && typeof val === "object") {
		for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
			if (k.startsWith("@_")) {
				const attrRaw = k.slice(2);
				const attrBare = attrRaw.includes(":") ? attrRaw.split(":").pop()!.toLowerCase() : attrRaw.toLowerCase();
				const strVal =
					typeof v === "boolean" || typeof v === "number"
						? v
						: typeof v === "string"
							? decodeXmlEntities(v)
							: String(v);
				attrs[attrBare] = strVal;
				attrs[attrRaw] = strVal;
			} else if (k === "#text") {
				text = typeof v === "string" ? decodeXmlEntities(v.trim()) : String(v).trim();
			} else {
				const items = Array.isArray(v) ? v : [v];
				for (const item of items) {
					if (item !== undefined && item !== null) {
						children.push(convertFastXmlToNode(k, item));
					}
				}
			}
		}
	}

	return {
		tag: bareTag,
		attrs,
		text,
		children,
	};
}

export function extractNetworkSecurityConfigFromNode(rootNode: GenericXmlNode): {
	cleartextTrafficPermitted?: boolean | "unknown";
	baseTrustAnchors?: AndroidNetworkSecurityConfigTrustAnchor[];
	domainConfigs?: AndroidNetworkSecurityConfigDomain[];
	debugOverrides?: AndroidNetworkSecurityConfigData["debugOverrides"];
} {
	let cleartextTrafficPermitted: boolean | "unknown" | undefined;
	const baseTrustAnchors: AndroidNetworkSecurityConfigTrustAnchor[] = [];
	const domainConfigs: AndroidNetworkSecurityConfigDomain[] = [];
	let debugOverrides: AndroidNetworkSecurityConfigData["debugOverrides"];

	// 1. Base Config
	const baseNode = rootNode.children.find(c => c.tag === "base-config");
	if (baseNode) {
		const clrParsed = parseBooleanAttr(getNodeAttr(baseNode, "cleartextTrafficPermitted"));
		if (clrParsed.isReference) {
			cleartextTrafficPermitted = "unknown";
		} else if (clrParsed.value !== undefined) {
			cleartextTrafficPermitted = clrParsed.value;
		}

		for (const taNode of baseNode.children.filter(c => c.tag === "trust-anchors")) {
			for (const certNode of taNode.children.filter(c => c.tag === "certificates")) {
				const src = getNodeAttr(certNode, "src");
				if (src) {
					const overridePins = getNodeAttr(certNode, "overridePins") === "true";
					baseTrustAnchors.push({ src, overridePins });
				}
			}
		}
	}

	// 2. Domain Configs (recursive with inheritance)
	// Android 官方语义：
	// - 子配置未显式声明的值继承自父级 domain-config 或 base-config
	// - 显式声明的 trust-anchors 会完全替换（override）继承的 trust-anchors，而非追加合并
	// - 显式声明的 cleartextTrafficPermitted 覆盖父级设置
	// - 显式声明的 pin-set 覆盖父级设置
	interface DomainInheritedState {
		cleartextTrafficPermitted?: boolean | "unknown";
		trustAnchors?: AndroidNetworkSecurityConfigTrustAnchor[];
		pinSet?: {
			expiration?: string;
			pins: AndroidNetworkSecurityConfigPin[];
		};
	}

	const initialState: DomainInheritedState = {
		cleartextTrafficPermitted,
		trustAnchors: baseTrustAnchors.length > 0 ? baseTrustAnchors : undefined,
		pinSet: undefined,
	};

	const processDomainConfig = (node: GenericXmlNode, parentState: DomainInheritedState, depth = 0) => {
		if (depth > 20) {
			throw new Error("Network security config nested domain-config exceeded maximum recursion depth");
		}

		// cleartextTrafficPermitted 判定（未解析资源引用保留 unknown）
		const clrParsed = parseBooleanAttr(getNodeAttr(node, "cleartextTrafficPermitted"));
		let currentCleartext: boolean | "unknown" | undefined;
		if (clrParsed.isReference) {
			currentCleartext = "unknown";
		} else if (clrParsed.value !== undefined) {
			currentCleartext = clrParsed.value;
		} else {
			currentCleartext = parentState.cleartextTrafficPermitted;
		}
		// trust-anchors 判定：若本节点显式声明 trust-anchors，则替换父级；否则继承父级
		let currentTrustAnchors: AndroidNetworkSecurityConfigTrustAnchor[] | undefined = parentState.trustAnchors;
		const taNodes = node.children.filter(c => c.tag === "trust-anchors");
		if (taNodes.length > 0) {
			const explicitAnchors: AndroidNetworkSecurityConfigTrustAnchor[] = [];
			for (const taNode of taNodes) {
				for (const certNode of taNode.children.filter(c => c.tag === "certificates")) {
					const src = getNodeAttr(certNode, "src");
					if (src) {
						const overridePins = getNodeAttr(certNode, "overridePins") === "true";
						explicitAnchors.push({ src, overridePins });
					}
				}
			}
			currentTrustAnchors = explicitAnchors.length > 0 ? explicitAnchors : undefined;
		}

		// pin-set 判定：若本节点显式声明 pin-set，则替换父级；否则继承父级
		let currentPinSet: AndroidNetworkSecurityConfigDomain["pinSet"] = parentState.pinSet;
		const pinSetNode = node.children.find(c => c.tag === "pin-set");
		if (pinSetNode) {
			const exp = getNodeAttr(pinSetNode, "expiration");
			const pins: AndroidNetworkSecurityConfigPin[] = [];
			for (const pinNode of pinSetNode.children.filter(c => c.tag === "pin")) {
				const pinVal = (pinNode.text || getNodeAttr(pinNode, "value") || getNodeAttr(pinNode, "pin") || "").trim();
				const digest = (getNodeAttr(pinNode, "digest") || "SHA-256").trim();
				if (pinVal) {
					pins.push({ digest, value: pinVal });
				}
			}
			currentPinSet = { expiration: exp, pins };
		}

		// 解析本层所有 <domain> 声明
		for (const domainNode of node.children.filter(c => c.tag === "domain")) {
			const domainName = (
				domainNode.text ||
				getNodeAttr(domainNode, "name") ||
				getNodeAttr(domainNode, "domain") ||
				""
			).trim();
			const incSubAttr = getNodeAttr(domainNode, "includeSubdomains");
			const includeSubdomains = incSubAttr === "true" || incSubAttr === "1";

			if (domainName) {
				domainConfigs.push({
					domain: domainName,
					includeSubdomains,
					cleartextTrafficPermitted: currentCleartext,
					pinSet: currentPinSet,
					trustAnchors: currentTrustAnchors,
				});
			}
		}

		// 递归处理嵌套的 <domain-config>
		const currentState: DomainInheritedState = {
			cleartextTrafficPermitted: currentCleartext,
			trustAnchors: currentTrustAnchors,
			pinSet: currentPinSet,
		};
		for (const childConfig of node.children.filter(c => c.tag === "domain-config")) {
			processDomainConfig(childConfig, currentState, depth + 1);
		}
	};

	for (const topDomainConfig of rootNode.children.filter(c => c.tag === "domain-config")) {
		processDomainConfig(topDomainConfig, initialState, 0);
	}

	// 3. Debug Overrides
	const debugNode = rootNode.children.find(c => c.tag === "debug-overrides");
	if (debugNode) {
		const clr = getNodeAttr(debugNode, "cleartextTrafficPermitted");
		const debugAnchors: AndroidNetworkSecurityConfigTrustAnchor[] = [];

		for (const taNode of debugNode.children.filter(c => c.tag === "trust-anchors")) {
			for (const certNode of taNode.children.filter(c => c.tag === "certificates")) {
				const src = getNodeAttr(certNode, "src");
				if (src) {
					const overrideAttr = getNodeAttr(certNode, "overridePins");
					// Per Android documentation:
					// Inside <debug-overrides>, overridePins defaults to true unless explicitly set to "false"
					const overridePins = overrideAttr !== undefined ? overrideAttr === "true" : true;
					debugAnchors.push({ src, overridePins });
				}
			}
		}

		debugOverrides = {
			cleartextTrafficPermitted: clr !== undefined ? clr === "true" || clr === "1" : undefined,
			trustAnchors: debugAnchors.length > 0 ? debugAnchors : undefined,
		};
	}

	return {
		cleartextTrafficPermitted,
		baseTrustAnchors: baseTrustAnchors.length > 0 ? baseTrustAnchors : undefined,
		domainConfigs: domainConfigs.length > 0 ? domainConfigs : undefined,
		debugOverrides,
	};
}

export function parseAxmlStringPoolAt(buf: Buffer, poolOff: number): string[] | null {
	if (poolOff + 28 > buf.length || buf.readUInt16LE(poolOff) !== 0x0001) return null;
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
	return strings;
}

export function parseAxmlTree(buf: Buffer, maxNodes = 5000): GenericXmlNode | null {
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

	const strings = parseAxmlStringPoolAt(buf, poolOff);
	if (!strings) return null;

	const poolSize = buf.readUInt32LE(poolOff + 4);
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

	let rootNode: GenericXmlNode | null = null;
	const nodeStack: GenericXmlNode[] = [];
	let nodeCount = 0;
	let totalDecodedChars = 0;
	const MAX_DECODED_CHARS = 2 * 1024 * 1024; // 200万字符上限，防止 CDATA / 属性放大攻击
	const MAX_NODE_TEXT_LEN = 65536; // 单个节点 64 KiB 文本上限

	while (ptr + 8 <= buf.length && ptr < totalSize) {
		const type = buf.readUInt16LE(ptr);
		const size = buf.readUInt32LE(ptr + 4);
		if (size <= 0 || ptr + size > buf.length || ptr + size > totalSize) {
			if (rootNode) rootNode.isTruncated = true;
			break;
		}

		if (type === 0x0102) {
			// RES_XML_START_ELEMENT_TYPE
			if (size < 36 || nodeCount >= maxNodes || totalDecodedChars >= MAX_DECODED_CHARS) {
				if (rootNode) rootNode.isTruncated = true;
				break;
			}
			nodeCount++;

			const nameIdx = ptr + 20 + 4 <= buf.length ? buf.readUInt32LE(ptr + 20) : 0xffffffff;
			const elemName = nameIdx !== 0xffffffff && nameIdx < strings.length ? strings[nameIdx] : "";
			const normTag = elemName.includes(":") ? elemName.split(":").pop()!.toLowerCase() : elemName.toLowerCase();

			const nodeHeaderSize = buf.readUInt16LE(ptr + 2) || 16;
			const attrStart = ptr + 24 + 2 <= buf.length ? buf.readUInt16LE(ptr + 24) : 0;
			const attrSize = ptr + 26 + 2 <= buf.length ? buf.readUInt16LE(ptr + 26) : 20;
			const attrCount = ptr + 28 + 2 <= buf.length ? buf.readUInt16LE(ptr + 28) : 0;

			const attrs: Record<string, string | number | boolean> = {};
			let attrsBase = ptr + (attrStart >= 32 ? attrStart : nodeHeaderSize + attrStart);
			if (attrsBase + attrCount * 20 > ptr + size || attrsBase + attrCount * 20 > buf.length) {
				attrsBase = ptr + 36;
			}
			const effectiveAttrSize = attrSize >= 20 ? attrSize : 20;
			if (attrsBase + attrCount * effectiveAttrSize > ptr + size) {
				if (rootNode) rootNode.isTruncated = true;
				break;
			}
			for (let a = 0; a < attrCount; a++) {
				const aOff = attrsBase + a * effectiveAttrSize;
				if (aOff + 20 > buf.length) break;

				const aNameIdx = buf.readUInt32LE(aOff + 4);
				const aRawValIdx = buf.readUInt32LE(aOff + 8);
				const typedValType = buf.readUInt8(aOff + 15);
				const typedValData = buf.readUInt32LE(aOff + 16);

				const aName = aNameIdx < strings.length ? strings[aNameIdx] : "";
				let val: string | number | boolean;

				if (typedValType === 0x03) {
					// TYPE_STRING
					val =
						(typedValData < strings.length ? strings[typedValData] : undefined) ??
						(aRawValIdx !== 0xffffffff && aRawValIdx < strings.length ? strings[aRawValIdx] : "") ??
						"";
				} else if (aRawValIdx !== 0xffffffff && aRawValIdx < strings.length) {
					val = strings[aRawValIdx];
				} else if (typedValType === 0x12) {
					// TYPE_INT_BOOLEAN
					val = typedValData !== 0;
				} else if (typedValType === 0x10) {
					// TYPE_INT_DEC
					val = typedValData;
				} else if (typedValType === 0x11) {
					// TYPE_INT_HEX
					val = `0x${typedValData.toString(16)}`;
				} else if (typedValType === 0x01) {
					// TYPE_REFERENCE
					val = `@0x${typedValData.toString(16)}`;
				} else {
					val = typedValData;
				}

				if (aName) {
					const bare = aName.includes(":") ? aName.split(":").pop()!.toLowerCase() : aName.toLowerCase();
					attrs[bare] = val;
					attrs[aName] = val;
				}
			}

			const newNode: GenericXmlNode = {
				tag: normTag,
				attrs,
				children: [],
			};

			if (nodeStack.length > 0) {
				nodeStack[nodeStack.length - 1].children.push(newNode);
			} else if (!rootNode) {
				rootNode = newNode;
			}
			nodeStack.push(newNode);
		} else if (type === 0x0104) {
			// RES_XML_CDATA_TYPE
			if (ptr + 20 <= buf.length) {
				const cdataIdx = buf.readUInt32LE(ptr + 16);
				if (cdataIdx < strings.length) {
					const text = strings[cdataIdx];
					if (text && nodeStack.length > 0) {
						const top = nodeStack[nodeStack.length - 1];
						const currentLen = top.text?.length ?? 0;
						if (
							currentLen + text.length > MAX_NODE_TEXT_LEN ||
							totalDecodedChars + text.length > MAX_DECODED_CHARS
						) {
							if (rootNode) rootNode.isTruncated = true;
							break;
						}
						totalDecodedChars += text.length;
						top.text = (top.text ?? "") + text;
					}
				}
			}
		} else if (type === 0x0103) {
			// RES_XML_END_ELEMENT_TYPE
			// 严格防范截断块：END_ELEMENT 块需完整 24 字节且落在声明块内，避免越界读取 RangeError
			if (size < 24 || ptr + 24 > buf.length || ptr + size > totalSize) {
				if (rootNode) rootNode.isTruncated = true;
				break;
			}
			const nameIdx = buf.readUInt32LE(ptr + 20);
			const elemName = nameIdx < strings.length ? strings[nameIdx] : "";
			const normTag = elemName.includes(":") ? elemName.split(":").pop()!.toLowerCase() : elemName.toLowerCase();

			const matchIdx = nodeStack.map(n => n.tag).lastIndexOf(normTag);
			if (matchIdx !== -1) {
				nodeStack.splice(matchIdx, nodeStack.length - matchIdx);
			} else if (nodeStack.length > 0) {
				nodeStack.pop();
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

	// 循环结束时若仍有未闭合的节点（包括根节点未闭合），判定为截断或不完整的 XML 树
	if (nodeStack.length > 0) {
		if (rootNode) rootNode.isTruncated = true;
	}

	return rootNode;
}

export function resolveNetworkSecurityConfig(
	rawRef: string | undefined,
	zip?: ZipParser | null,
): AndroidNetworkSecurityConfigData | undefined {
	if (!rawRef) return undefined;
	const trimmed = rawRef.trim();

	// 显式保留未解析的数值资源 ID（如 @0x7f100001 或 0x7f100001）
	if (/^@?0x[0-9a-fA-F]+$/.test(trimmed)) {
		return {
			rawRef: trimmed,
			unresolvedResourceId: trimmed,
		};
	}

	if (trimmed.startsWith("@xml/")) {
		const xmlName = trimmed.slice(5).trim();
		const candidatePath = `res/xml/${xmlName}.xml`;

		if (zip) {
			const entry =
				zip.getEntry(candidatePath) ?? zip.entries.find(e => e.name.toLowerCase() === candidatePath.toLowerCase());
			if (entry) {
				const MAX_XML_BYTES = 10 * 1024 * 1024; // 10 MiB 最大解压上限，防止 zip 炸弹
				const buf = zip.readFile(entry, MAX_XML_BYTES);
				if (buf) {
					let format: "plain_xml" | "binary_xml" = "plain_xml";
					let extracted: AndroidNetworkSecurityConfigData | undefined;

					try {
						const isAxml = buf.length >= 2 && buf.readUInt16LE(0) === 0x0003;
						if (isAxml) {
							format = "binary_xml";
							const rootNode = parseAxmlTree(buf);
							if (rootNode && !rootNode.isTruncated) {
								const nscNode =
									rootNode.tag === "network-security-config"
										? rootNode
										: rootNode.children.find(c => c.tag === "network-security-config");
								if (nscNode) {
									extracted = extractNetworkSecurityConfigFromNode(nscNode);
								}
							}
						} else {
							format = "plain_xml";
							const text = buf.toString("utf8");
							if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
								extracted = undefined;
							} else {
								const parser = new XMLParser({
									ignoreAttributes: false,
									attributeNamePrefix: "@_",
									trimValues: true,
									parseTagValue: false,
									parseAttributeValue: false,
									processEntities: false,
								});
								const parsed = parser.parse(text) as Record<string, unknown>;
								const rootKey = Object.keys(parsed).find(
									k => k.split(":").pop()?.toLowerCase() === "network-security-config",
								);
								if (rootKey && parsed[rootKey]) {
									const rootNode = convertFastXmlToNode(rootKey, parsed[rootKey]);
									extracted = extractNetworkSecurityConfigFromNode(rootNode);
								}
							}
						}
					} catch {
						// 容错处理：畸形格式不抛出未捕获异常
					}

					if (!extracted) {
						return {
							rawRef: trimmed,
							resolvedFile: candidatePath,
							format,
							unresolvedResourceId: `${trimmed} (failed to parse or truncated network security config)`,
						};
					}

					return {
						rawRef: trimmed,
						resolvedFile: candidatePath,
						format,
						cleartextTrafficPermitted: extracted.cleartextTrafficPermitted,
						baseTrustAnchors: extracted.baseTrustAnchors,
						domainConfigs: extracted.domainConfigs,
						debugOverrides: extracted.debugOverrides,
					};
				}
			}
		}

		return {
			rawRef: trimmed,
			unresolvedResourceId: trimmed,
		};
	}

	return {
		rawRef: trimmed,
		unresolvedResourceId: trimmed,
	};
}

export function parseNetworkSecurityConfigAxml(buf: Buffer): AndroidNetworkSecurityConfigData | null {
	if (buf.length < 8 || buf.readUInt16LE(0) !== 0x0003) return null;
	const rootNode = parseAxmlTree(buf);
	if (!rootNode || rootNode.isTruncated) return null;
	const nscNode =
		rootNode.tag === "network-security-config"
			? rootNode
			: rootNode.children.find(c => c.tag === "network-security-config");
	if (!nscNode) return null;
	const extracted = extractNetworkSecurityConfigFromNode(nscNode);
	return {
		format: "binary_xml",
		...extracted,
	};
}

export function extractManifestFromNode(
	manifestNode: GenericXmlNode,
	zip?: ZipParser | null,
): AndroidManifestMetadata | null {
	if (manifestNode.tag !== "manifest") return null;
	if (manifestNode.isTruncated) return null;

	const packageName = getNodeAttr(manifestNode, "package") ?? "";
	const versionCodeRaw = getNodeAttr(manifestNode, "versionCode");
	const versionCode =
		versionCodeRaw !== undefined
			? typeof versionCodeRaw === "number"
				? versionCodeRaw
				: /^\d+$/.test(versionCodeRaw.trim())
					? parseInt(versionCodeRaw.trim(), 10)
					: versionCodeRaw
			: undefined;
	const versionName = getNodeAttr(manifestNode, "versionName");
	const compileSdkVersionRaw = getNodeAttr(manifestNode, "compileSdkVersion");
	const compileSdkVersion =
		compileSdkVersionRaw !== undefined
			? typeof compileSdkVersionRaw === "number"
				? compileSdkVersionRaw
				: /^\d+$/.test(compileSdkVersionRaw.trim())
					? parseInt(compileSdkVersionRaw.trim(), 10)
					: compileSdkVersionRaw
			: undefined;

	const usesSdkNodes = manifestNode.children.filter(c => c.tag === "uses-sdk");
	let minSdkVersion: number | string | undefined;
	let targetSdkVersion: number | string | undefined;
	if (usesSdkNodes.length > 0) {
		const minRaw = getNodeAttr(usesSdkNodes[0], "minSdkVersion");
		if (minRaw !== undefined) {
			minSdkVersion =
				typeof minRaw === "number" ? minRaw : /^\d+$/.test(minRaw.trim()) ? parseInt(minRaw.trim(), 10) : minRaw;
		}
		const targetRaw = getNodeAttr(usesSdkNodes[0], "targetSdkVersion");
		if (targetRaw !== undefined) {
			targetSdkVersion =
				typeof targetRaw === "number"
					? targetRaw
					: /^\d+$/.test(targetRaw.trim())
						? parseInt(targetRaw.trim(), 10)
						: targetRaw;
		}
	}

	const permissions: string[] = [];
	for (const child of manifestNode.children) {
		if (
			child.tag === "uses-permission" ||
			child.tag === "uses-permission-sdk-23" ||
			child.tag === "uses-permission-sdk-m"
		) {
			const name = getNodeAttr(child, "name");
			if (name && !permissions.includes(name)) permissions.push(name);
		}
	}

	const permissionsDeclared: string[] = [];
	const declaredPermissions: Array<{ name: string; protectionLevel?: string }> = [];
	for (const child of manifestNode.children.filter(c => c.tag === "permission")) {
		const name = getNodeAttr(child, "name");
		if (name) {
			permissionsDeclared.push(name);
			const protRaw = getNodeAttr(child, "protectionLevel");
			let protectionLevel: string | undefined;
			if (protRaw !== undefined) {
				// Android 官方标准 protectionLevel 映射（数值 0 为 normal，truthiness 不能将其丢弃）
				if (protRaw === "0" || protRaw === "0x0" || protRaw === "0x00000000") {
					protectionLevel = "normal";
				} else if (protRaw === "1" || protRaw === "0x1") {
					protectionLevel = "dangerous";
				} else if (protRaw === "2" || protRaw === "0x2") {
					protectionLevel = "signature";
				} else if (protRaw === "3" || protRaw === "0x3") {
					protectionLevel = "signatureOrSystem";
				} else {
					protectionLevel = String(protRaw);
				}
			}
			declaredPermissions.push({ name, protectionLevel });
		}
	}

	const appNode = manifestNode.children.find(c => c.tag === "application");

	let appName: string | undefined;
	let appLabel: string | undefined;
	let appIcon: string | undefined;
	let appDebuggable: boolean | undefined;
	let rawDebuggable: string | undefined;
	let appAllowBackup: boolean | undefined;
	let rawAllowBackup: string | undefined;
	let appExtractNativeLibs: boolean | undefined;
	let rawExtractNativeLibs: string | undefined;
	let appUseEmbeddedDex: boolean | undefined;
	let rawUseEmbeddedDex: string | undefined;
	let appHasCode: boolean | undefined;
	let rawHasCode: string | undefined;
	let appUsesCleartextTraffic: boolean | undefined;
	let rawUsesCleartextTraffic: string | undefined;
	let appNetworkSecurityConfig: string | undefined;
	let appPermission: string | undefined;
	let appEnabled: boolean | undefined;
	let rawEnabled: string | undefined;
	let appEnabledParsed: { value?: boolean; isReference?: boolean; raw?: string } = {};

	if (appNode) {
		appName = getNodeAttr(appNode, "name");
		appLabel = getNodeAttr(appNode, "label");
		appIcon = getNodeAttr(appNode, "icon");

		const dbg = parseBooleanAttr(getNodeAttr(appNode, "debuggable"));
		appDebuggable = dbg.value;
		rawDebuggable = dbg.raw;

		const bk = parseBooleanAttr(getNodeAttr(appNode, "allowBackup"));
		appAllowBackup = bk.value;
		rawAllowBackup = bk.raw;

		const nl = parseBooleanAttr(getNodeAttr(appNode, "extractNativeLibs"));
		appExtractNativeLibs = nl.value;
		rawExtractNativeLibs = nl.raw;

		const ed = parseBooleanAttr(getNodeAttr(appNode, "useEmbeddedDex"));
		appUseEmbeddedDex = ed.value;
		rawUseEmbeddedDex = ed.raw;

		const hc = parseBooleanAttr(getNodeAttr(appNode, "hasCode"));
		appHasCode = hc.value;
		rawHasCode = hc.raw;

		const clr = parseBooleanAttr(getNodeAttr(appNode, "usesCleartextTraffic"));
		appUsesCleartextTraffic = clr.value;
		rawUsesCleartextTraffic = clr.raw;

		appNetworkSecurityConfig = getNodeAttr(appNode, "networkSecurityConfig");
		appPermission = getNodeAttr(appNode, "permission");

		appEnabledParsed = parseBooleanAttr(getNodeAttr(appNode, "enabled"));
		appEnabled = appEnabledParsed.value;
		rawEnabled = appEnabledParsed.raw;
	}

	const activities: AndroidManifestComponent[] = [];
	const services: AndroidManifestComponent[] = [];
	const receivers: AndroidManifestComponent[] = [];
	const providers: AndroidManifestComponent[] = [];

	if (appNode) {
		for (const compNode of appNode.children) {
			const tag = compNode.tag;
			if (
				tag !== "activity" &&
				tag !== "activity-alias" &&
				tag !== "service" &&
				tag !== "receiver" &&
				tag !== "provider"
			) {
				continue;
			}

			const name = getNodeAttr(compNode, "name");
			// Android Parity: 严格忽略缺少 name 属性的幽灵组件（如 <queries><provider .../></queries>）
			if (!name || name.trim() === "") continue;

			const expAttr = getNodeAttr(compNode, "exported");
			const expParsed = parseBooleanAttr(expAttr);
			const compPerm = getNodeAttr(compNode, "permission");
			const readPerm = getNodeAttr(compNode, "readPermission");
			const writePerm = getNodeAttr(compNode, "writePermission");
			const authorities = getNodeAttr(compNode, "authorities");
			const grantUriPerm = parseBooleanAttr(getNodeAttr(compNode, "grantUriPermissions")).value;
			const targetActivity = getNodeAttr(compNode, "targetActivity");
			const compEnabledParsed = parseBooleanAttr(getNodeAttr(compNode, "enabled"));
			const compProcess = getNodeAttr(compNode, "process");
			const hasGrantUriTags = compNode.children.some(c => c.tag === "grant-uri-permission");

			const intentFilters: AndroidIntentFilter[] = [];
			for (const ifNode of compNode.children.filter(c => c.tag === "intent-filter")) {
				const autoVerifyParsed = parseBooleanAttr(getNodeAttr(ifNode, "autoVerify"));
				const actions: string[] = [];
				for (const an of ifNode.children.filter(c => c.tag === "action")) {
					const aName = getNodeAttr(an, "name");
					if (aName) actions.push(aName);
				}
				const categories: string[] = [];
				for (const cn of ifNode.children.filter(c => c.tag === "category")) {
					const cName = getNodeAttr(cn, "name");
					if (cName) categories.push(cName);
				}
				const data: AndroidIntentFilterData[] = [];
				for (const dn of ifNode.children.filter(c => c.tag === "data")) {
					data.push({
						scheme: getNodeAttr(dn, "scheme"),
						host: getNodeAttr(dn, "host"),
						port: getNodeAttr(dn, "port"),
						path: getNodeAttr(dn, "path"),
						pathPrefix: getNodeAttr(dn, "pathPrefix"),
						pathPattern: getNodeAttr(dn, "pathPattern"),
						mimeType: getNodeAttr(dn, "mimeType"),
					});
				}
				intentFilters.push({
					actions,
					categories,
					data,
					autoVerify:
						autoVerifyParsed.value !== undefined
							? autoVerifyParsed.value
							: autoVerifyParsed.isReference
								? "unknown"
								: false,
				});
			}

			const pathPermissions: AndroidPathPermission[] = [];
			for (const ppNode of compNode.children.filter(c => c.tag === "path-permission")) {
				pathPermissions.push({
					path: getNodeAttr(ppNode, "path"),
					pathPrefix: getNodeAttr(ppNode, "pathPrefix"),
					pathPattern: getNodeAttr(ppNode, "pathPattern"),
					permission: getNodeAttr(ppNode, "permission"),
					readPermission: getNodeAttr(ppNode, "readPermission"),
					writePermission: getNodeAttr(ppNode, "writePermission"),
				});
			}

			// AOSP 规则：Activity/Alias/Receiver 的 intent-filter 必须至少包含一个 action 才是有效过滤器；Service 则不论有无 action 均视为有效
			const hasEffectiveIntentFilters =
				tag === "service" ? intentFilters.length > 0 : intentFilters.some(f => f.actions.length > 0);

			const { effective: effExported, reason: expReason } = calculateEffectiveExported(
				(tag as AndroidManifestComponent["type"]) ?? "activity",
				expParsed.value,
				hasEffectiveIntentFilters,
				targetSdkVersion,
				expParsed.isReference,
				expParsed.raw,
				minSdkVersion,
			);

			// 权限继承语义：
			// 1. activity-alias 没有声明 android:permission 时，根据 Android 官方文档与 AOSP PackageParser 实现，
			//    alias 本身无需任何权限，它 supplant 目标 activity 的权限，且不继承 application 的默认权限。
			// 2. 其它组件（activity, service, receiver, provider）：
			//    若显式声明了 permission（包括空字符串 "" 显式重置），则保留自身权限；若未声明，则继承 application 级权限。
			let effectivePerm: string | undefined;
			let inheritedPerm: string | undefined;
			if (tag === "activity-alias") {
				effectivePerm = compPerm;
				inheritedPerm = undefined;
			} else {
				if (compPerm !== undefined) {
					effectivePerm = compPerm;
					inheritedPerm = undefined;
				} else {
					effectivePerm = appPermission;
					inheritedPerm = appPermission;
				}
			}

			const effReadPerm = readPerm !== undefined ? readPerm : effectivePerm;
			const effWritePerm = writePerm !== undefined ? writePerm : effectivePerm;

			// 三态 enabled 状态判定
			const effectiveEnabled = calculateEffectiveEnabled(compEnabledParsed, appEnabledParsed);

			const comp: AndroidManifestComponent = {
				name,
				type: tag as AndroidManifestComponent["type"],
				exported: expParsed.value,
				rawExported: expParsed.raw,
				effectiveExported: effExported,
				exportReason: expReason,
				permission: compPerm,
				readPermission: readPerm,
				writePermission: writePerm,
				inheritedPermission: inheritedPerm,
				effectivePermission: effectivePerm,
				effectiveReadPermission: effReadPerm,
				effectiveWritePermission: effWritePerm,
				authorities,
				grantUriPermissions: grantUriPerm,
				hasGrantUriPermissionTags: hasGrantUriTags ? true : undefined,
				pathPermissions: pathPermissions.length > 0 ? pathPermissions : undefined,
				targetActivity,
				enabled: effectiveEnabled,
				rawEnabled: compEnabledParsed.raw,
				process: compProcess,
				intentFilters,
			};

			if (tag === "activity" || tag === "activity-alias") {
				activities.push(comp);
			} else if (tag === "service") {
				services.push(comp);
			} else if (tag === "receiver") {
				receivers.push(comp);
			} else if (tag === "provider") {
				providers.push(comp);
			}
		}
	}

	const deepLinks = extractDeepLinks(activities);
	const networkSecurityConfig = resolveNetworkSecurityConfig(appNetworkSecurityConfig, zip);

	return {
		package: packageName,
		versionCode,
		versionName,
		compileSdkVersion,
		minSdkVersion,
		targetSdkVersion,
		permissions,
		permissionsDeclared,
		declaredPermissions: declaredPermissions.length > 0 ? declaredPermissions : undefined,
		application: {
			name: appName,
			label: appLabel,
			icon: appIcon,
			debuggable: appDebuggable,
			rawDebuggable,
			allowBackup: appAllowBackup,
			rawAllowBackup,
			extractNativeLibs: appExtractNativeLibs,
			rawExtractNativeLibs,
			useEmbeddedDex: appUseEmbeddedDex,
			rawUseEmbeddedDex,
			hasCode: appHasCode,
			rawHasCode,
			usesCleartextTraffic: appUsesCleartextTraffic,
			rawUsesCleartextTraffic,
			networkSecurityConfig: appNetworkSecurityConfig,
			permission: appPermission,
			enabled: appEnabled,
			rawEnabled,
			effectiveEnabled: appEnabledParsed.isReference ? "unknown" : appEnabled,
		},
		activities,
		services,
		receivers,
		providers,
		totalComponents: activities.length + services.length + receivers.length + providers.length,
		deepLinks,
		networkSecurityConfig,
	};
}

export function parseAxml(buf: Buffer, zip?: ZipParser | null): AndroidManifestMetadata | null {
	if (buf.length < 8) return null;
	const rootNode = parseAxmlTree(buf);
	if (!rootNode) return null;
	const manifestNode = rootNode.tag === "manifest" ? rootNode : rootNode.children.find(c => c.tag === "manifest");
	if (!manifestNode) return null;
	return extractManifestFromNode(manifestNode, zip);
}

export function parseXmlText(text: string, zip?: ZipParser | null): AndroidManifestMetadata | null {
	if (!text.includes("<manifest")) return null;
	// Android 规范：清单文件不支持 DTD / 自定义实体，直接防御实体膨胀攻击
	if (/<!DOCTYPE|<!ENTITY/i.test(text)) return null;

	let doc: Record<string, unknown> | null = null;
	try {
		const parser = new XMLParser({
			ignoreAttributes: false,
			attributeNamePrefix: "@_",
			trimValues: true,
			parseTagValue: false,
			parseAttributeValue: false,
			processEntities: false,
		});
		doc = parser.parse(text) as Record<string, unknown>;
	} catch {
		doc = null;
	}
	if (!doc || typeof doc !== "object") return null;

	let manifestKey: string | undefined;
	for (const k of Object.keys(doc)) {
		if (k.split(":").pop()?.toLowerCase() === "manifest" && doc[k] && typeof doc[k] === "object") {
			manifestKey = k;
			break;
		}
	}
	if (!manifestKey) return null;

	const rootNode = convertFastXmlToNode(manifestKey, doc[manifestKey]);
	return extractManifestFromNode(rootNode, zip);
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
			installHint: status?.hint ?? "Install via Android Studio SDK Manager or CLI: sdkmanager 'build-tools;35.0.0'.",
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

export class AndroidPackageInspectTool implements AgentTool<
	typeof androidPackageInspectSchema,
	AndroidPackageInspectDetails
> {
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
	): Promise<AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails }> {
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
	): AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails } {
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
			lines.push(
				`DEX Totals: ${totalClasses} classes, ${totalMethods} methods, ${totalFields} fields across ${dexEntries.length} DEX files`,
			);
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
		lines.push(
			`  • Table: ${arscEntry ? `Present (${arscEntry.name}, ${arscEntry.uncompressedSize} bytes)` : "None"}`,
		);
		lines.push(
			`  • Files: ${resTotal} in res/ (${layoutsCount} layouts, ${drawablesCount} drawables), ${assetsCount} in assets/`,
		);

		lines.push(`Signing Schemes Detected:`);
		lines.push(
			`  • v1 (JAR signing): ${v1Files.length > 0 ? `Yes (${v1Files.length} files: ${v1Files.join(", ")})` : "No"}`,
		);
		lines.push(`  • APK Signing Block: ${signingBlock.present ? `Yes (size: ${signingBlock.size} bytes)` : "No"}`);
		if (signingBlock.present) {
			lines.push(`    - Scheme v2: ${signingBlock.v2Scheme ? "Yes" : "No"}`);
			lines.push(`    - Scheme v3: ${signingBlock.v3Scheme ? "Yes" : "No"}`);
			lines.push(`    - v2 Scheme: ${signingBlock.v2Scheme ? "Yes" : "No"}`);
			lines.push(`    - v3 Scheme: ${signingBlock.v3Scheme ? "Yes" : "No"}`);
			lines.push(
				`    - Scheme v2 (APK Signature Scheme v2): ${signingBlock.v2Scheme ? "Present (0x7109871a)" : "No"}`,
			);
			lines.push(
				`    - Scheme v3 (APK Signature Scheme v3): ${signingBlock.v3Scheme ? "Present (0xf05368c0)" : "No"}`,
			);
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
	): Promise<AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails }> {
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
			metadata = parseAxml(mBuf, zip);
		} else {
			const str = mBuf.toString("utf8");
			if (str.includes("<manifest")) {
				metadata = parseXmlText(str, zip);
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

		const formatBool = (val: boolean | undefined, raw: string | undefined, defaultVal: boolean | string): string => {
			if (val !== undefined) return String(val);
			if (raw) return `${raw} (unresolved resource)`;
			return `${defaultVal} (default)`;
		};

		const lines = [
			`// Android Package Manifest Inspection`,
			`Target: ${targetPath} (${manifestEntry.name})`,
			`Package: ${metadata.package}`,
			`Version: ${metadata.versionName ?? "none"} (versionCode: ${metadata.versionCode ?? "none"})`,
			`SDK Versions: min: ${metadata.minSdkVersion ?? "unspecified"}, target: ${metadata.targetSdkVersion ?? "unspecified"}, compile: ${metadata.compileSdkVersion ?? "unspecified"}`,
			`Application: name: ${metadata.application.name ?? "default"}, label: ${metadata.application.label ?? "none"}, debuggable: ${formatBool(metadata.application.debuggable, metadata.application.rawDebuggable, false)}, allowBackup: ${formatBool(metadata.application.allowBackup, metadata.application.rawAllowBackup, true)}, cleartext: ${formatBool(metadata.application.usesCleartextTraffic, metadata.application.rawUsesCleartextTraffic, "default")}, enabled: ${formatBool(metadata.application.enabled, metadata.application.rawEnabled, true)}`,
		];

		if (metadata.application.networkSecurityConfig) {
			lines.push(`Network Security Config: ${metadata.application.networkSecurityConfig}`);
			const nsc = metadata.networkSecurityConfig;
			if (nsc?.unresolvedResourceId) {
				lines.push(
					`  • Unresolved resource reference: ${nsc.unresolvedResourceId} (resource table / aapt2 bridge required)`,
				);
			} else if (nsc?.resolvedFile) {
				lines.push(`  • Resolved file: ${nsc.resolvedFile} (${nsc.format ?? "unknown"})`);
				if (nsc.cleartextTrafficPermitted !== undefined) {
					lines.push(`  • Base cleartext permitted: ${nsc.cleartextTrafficPermitted}`);
				}
				if (nsc.baseTrustAnchors && nsc.baseTrustAnchors.length > 0) {
					lines.push(
						`  • Base Trust Anchors: ${nsc.baseTrustAnchors.map(a => `${a.src}${a.overridePins ? " (overridePins)" : ""}`).join(", ")}`,
					);
				}
				if (nsc.domainConfigs && nsc.domainConfigs.length > 0) {
					lines.push(`  • Domain Configs (${nsc.domainConfigs.length}):`);
					for (const dc of nsc.domainConfigs.slice(0, 15)) {
						const subStr = dc.includeSubdomains ? " (includeSubdomains)" : "";
						const clrStr =
							dc.cleartextTrafficPermitted !== undefined ? `, cleartext: ${dc.cleartextTrafficPermitted}` : "";
						const pinStr =
							dc.pinSet && dc.pinSet.pins.length > 0
								? `, pins: [${dc.pinSet.pins.map(p => `${p.digest}=${p.value}`).join(", ")}]${dc.pinSet.expiration ? `, expires: ${dc.pinSet.expiration}` : ""}`
								: "";
						const taStr =
							dc.trustAnchors && dc.trustAnchors.length > 0
								? `, trustAnchors: [${dc.trustAnchors.map(t => `${t.src}${t.overridePins ? " (overridePins)" : ""}`).join(", ")}]`
								: "";
						lines.push(`    - ${dc.domain}${subStr}${clrStr}${pinStr}${taStr}`);
					}
					if (nsc.domainConfigs.length > 15) {
						lines.push(`    ... (${nsc.domainConfigs.length - 15} more domain configs omitted)`);
					}
				}
				if (nsc.debugOverrides) {
					const dbg = nsc.debugOverrides;
					const dbgTaStr = dbg.trustAnchors
						? `trustAnchors: [${dbg.trustAnchors.map(a => `${a.src}${a.overridePins ? " (overridePins)" : ""}`).join(", ")}]`
						: "none";
					lines.push(
						`  • Debug Overrides: ${dbgTaStr}${dbg.cleartextTrafficPermitted !== undefined ? `, cleartext: ${dbg.cleartextTrafficPermitted}` : ""}`,
					);
				}
			}
		}

		lines.push(`Permissions Requested (${metadata.permissions.length}):`);
		if (metadata.permissions.length === 0) {
			lines.push(`  • None`);
		} else {
			for (const p of metadata.permissions) {
				lines.push(`  • ${p}`);
			}
		}

		if (metadata.permissionsDeclared.length > 0) {
			lines.push(`Permissions Declared (${metadata.permissionsDeclared.length}):`);
			if (metadata.declaredPermissions && metadata.declaredPermissions.length > 0) {
				for (const dp of metadata.declaredPermissions) {
					const protStr = dp.protectionLevel ? ` [protectionLevel: ${dp.protectionLevel}]` : "";
					lines.push(`  • ${dp.name}${protStr}`);
				}
			} else {
				for (const p of metadata.permissionsDeclared) {
					lines.push(`  • ${p}`);
				}
			}
		}
		const formatIntentFilter = (f: AndroidIntentFilter): string => {
			const acts = f.actions.length > 0 ? `actions: [${f.actions.slice(0, 3).join(", ")}]` : "actions: []";
			const cats = f.categories.length > 0 ? `, categories: [${f.categories.slice(0, 3).join(", ")}]` : "";
			const dataEntries: string[] = [];
			for (const d of f.data.slice(0, 3)) {
				const parts: string[] = [];
				if (d.scheme) parts.push(`scheme=${d.scheme}`);
				if (d.host) parts.push(`host=${d.host}`);
				if (d.port) parts.push(`port=${d.port}`);
				if (d.path) parts.push(`path=${d.path}`);
				if (d.pathPrefix) parts.push(`prefix=${d.pathPrefix}`);
				if (d.pathPattern) parts.push(`pattern=${d.pathPattern}`);
				if (d.mimeType) parts.push(`mime=${d.mimeType}`);
				if (parts.length > 0) dataEntries.push(parts.join(" "));
			}
			const dataStr = dataEntries.length > 0 ? `, data: [${dataEntries.join(", ")}]` : "";
			const avStr =
				f.autoVerify === true ? ", autoVerify: true" : f.autoVerify === "unknown" ? ", autoVerify: unknown" : "";
			return `      • intent-filter: ${acts}${cats}${dataStr}${avStr}`;
		};

		lines.push(`Components (${metadata.totalComponents} total):`);
		lines.push(`  • Activities (${metadata.activities.length}):`);
		for (const act of metadata.activities.slice(0, 30)) {
			const expStr =
				act.exported !== undefined
					? ` [exported: ${act.exported}]`
					: ` [exported: undeclared, effective: ${act.effectiveExported ?? "unknown"}]`;
			const permStr =
				act.effectivePermission !== undefined
					? act.effectivePermission === ""
						? " [perm: none (public)]"
						: ` [perm: ${act.effectivePermission}]`
					: "";
			const enabledStr = act.enabled !== undefined && act.enabled !== true ? ` [enabled: ${act.enabled}]` : "";
			const procStr = act.process ? ` [process: ${act.process}]` : "";
			const targetStr = act.targetActivity ? ` -> ${act.targetActivity}` : "";
			lines.push(`    - ${act.name}${targetStr}${expStr}${permStr}${enabledStr}${procStr}`);
			if (act.intentFilters && act.intentFilters.length > 0) {
				for (const f of act.intentFilters.slice(0, 3)) {
					lines.push(formatIntentFilter(f));
				}
			}
		}
		if (metadata.activities.length > 30) {
			lines.push(`    ... (${metadata.activities.length - 30} more activities omitted)`);
		}

		lines.push(`  • Services (${metadata.services.length}):`);
		for (const s of metadata.services.slice(0, 20)) {
			const expStr =
				s.exported !== undefined
					? ` [exported: ${s.exported}]`
					: ` [exported: undeclared, effective: ${s.effectiveExported ?? "unknown"}]`;
			const permStr =
				s.effectivePermission !== undefined
					? s.effectivePermission === ""
						? " [perm: none (public)]"
						: ` [perm: ${s.effectivePermission}]`
					: "";
			const enabledStr = s.enabled !== undefined && s.enabled !== true ? ` [enabled: ${s.enabled}]` : "";
			const procStr = s.process ? ` [process: ${s.process}]` : "";
			lines.push(`    - ${s.name}${expStr}${permStr}${enabledStr}${procStr}`);
			if (s.intentFilters && s.intentFilters.length > 0) {
				for (const f of s.intentFilters.slice(0, 3)) {
					lines.push(formatIntentFilter(f));
				}
			}
		}

		lines.push(`  • Broadcast Receivers (${metadata.receivers.length}):`);
		for (const r of metadata.receivers.slice(0, 20)) {
			const expStr =
				r.exported !== undefined
					? ` [exported: ${r.exported}]`
					: ` [exported: undeclared, effective: ${r.effectiveExported ?? "unknown"}]`;
			const permStr =
				r.effectivePermission !== undefined
					? r.effectivePermission === ""
						? " [perm: none (public)]"
						: ` [perm: ${r.effectivePermission}]`
					: "";
			const enabledStr = r.enabled !== undefined && r.enabled !== true ? ` [enabled: ${r.enabled}]` : "";
			const procStr = r.process ? ` [process: ${r.process}]` : "";
			lines.push(`    - ${r.name}${expStr}${permStr}${enabledStr}${procStr}`);
			if (r.intentFilters && r.intentFilters.length > 0) {
				for (const f of r.intentFilters.slice(0, 3)) {
					lines.push(formatIntentFilter(f));
				}
			}
		}

		lines.push(`  • Content Providers (${metadata.providers.length}):`);
		for (const prov of metadata.providers.slice(0, 20)) {
			const authStr = prov.authorities ? ` (auth: ${prov.authorities})` : "";
			const expStr =
				prov.exported !== undefined
					? ` [exported: ${prov.exported}]`
					: ` [exported: undeclared, effective: ${prov.effectiveExported ?? "unknown"}]`;
			const permStr =
				prov.effectivePermission !== undefined
					? prov.effectivePermission === ""
						? " [perm: none (public)]"
						: ` [perm: ${prov.effectivePermission}]`
					: "";
			const readPermStr =
				prov.effectiveReadPermission !== undefined && prov.effectiveReadPermission !== prov.effectivePermission
					? ` [readPerm: ${prov.effectiveReadPermission === "" ? "none (public)" : prov.effectiveReadPermission}]`
					: "";
			const writePermStr =
				prov.effectiveWritePermission !== undefined && prov.effectiveWritePermission !== prov.effectivePermission
					? ` [writePerm: ${prov.effectiveWritePermission === "" ? "none (public)" : prov.effectiveWritePermission}]`
					: "";
			const grantStr = prov.grantUriPermissions ? ` [grantUri: true]` : "";
			const enabledStr = prov.enabled !== undefined && prov.enabled !== true ? ` [enabled: ${prov.enabled}]` : "";
			const procStr = prov.process ? ` [process: ${prov.process}]` : "";
			lines.push(
				`    - ${prov.name}${authStr}${expStr}${permStr}${readPermStr}${writePermStr}${grantStr}${enabledStr}${procStr}`,
			);
			if (prov.pathPermissions && prov.pathPermissions.length > 0) {
				for (const pp of prov.pathPermissions) {
					const pathStr = pp.pathPrefix
						? `prefix:${pp.pathPrefix}`
						: pp.path
							? `path:${pp.path}`
							: pp.pathPattern
								? `pattern:${pp.pathPattern}`
								: "*";
					lines.push(
						`      • path-permission: ${pathStr} (read: ${pp.readPermission ?? pp.permission ?? "default"}, write: ${pp.writePermission ?? pp.permission ?? "default"})`,
					);
				}
			}
		}

		if (metadata.deepLinks && metadata.deepLinks.length > 0) {
			lines.push(`Deep Links Inventory (${metadata.deepLinks.length}):`);
			for (const dl of metadata.deepLinks.slice(0, 15)) {
				const uris =
					dl.sampleUris.length > 0 ? dl.sampleUris.slice(0, 2).join(", ") : "(pattern without static URI)";
				const patStr =
					dl.pathPatterns.length > 0
						? ` [patterns: ${dl.pathPatterns.map(p => `${p.type}:${p.value}`).join(", ")}]`
						: "";
				const avStr =
					dl.autoVerify === true
						? " [autoVerify: true]"
						: dl.autoVerify === "unknown"
							? " [autoVerify: unknown]"
							: "";
				lines.push(
					`  • [${dl.componentType}] ${dl.component}${avStr} (effectiveExported: ${dl.exported}): ${uris}${patStr}`,
				);
			}
			if (metadata.deepLinks.length > 15) {
				lines.push(`    ... (${metadata.deepLinks.length - 15} more deep links omitted)`);
			}
		}

		lines.push(
			`// Security note: Exported components represent attack surface; reachability, intent validation, and concrete impact require dynamic verification before concluding vulnerability.`,
		);
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
	): AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails } {
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
		lines.push(
			`  • Header Metrics: ${parsedTarget.header.classDefsCount} classes, ${parsedTarget.header.methodIdsCount} methods, ${parsedTarget.header.fieldIdsCount} fields`,
		);
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
	): Promise<AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails }> {
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
			lines.push(
				`    - Scheme v2 (APK Signature Scheme v2): ${signingBlock.v2Scheme ? "Present (0x7109871a)" : "No"}`,
			);
			lines.push(
				`    - Scheme v3 (APK Signature Scheme v3): ${signingBlock.v3Scheme ? "Present (0xf05368c0)" : "No"}`,
			);
			lines.push(`    - Scheme v3.1: ${signingBlock.v31Scheme ? "Present (0x1b93ad61)" : "No"}`);
			lines.push(`    - SourceStamp: ${signingBlock.sourceStamp ? "Present (0x42726577)" : "No"}`);
			if (signingBlock.blockIds && signingBlock.blockIds.length > 0) {
				lines.push(
					`    - Recognized Block IDs: ${signingBlock.blockIds.map(b => `${b.id} (${b.name})`).join(", ")}`,
				);
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
	): Promise<AgentToolResult<AndroidPackageInspectDetails> & { details: AndroidPackageInspectDetails }> {
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
			lines.push(
				`  • Packages in ARSC: ${arscInfo.packageCount}${arscInfo.packageName ? ` (primary: ${arscInfo.packageName})` : ""}`,
			);
		}

		lines.push(`Resource Breakdown (${breakdown.totalFiles} files total):`);
		lines.push(
			`  • Layouts: ${breakdown.layouts.count} files (e.g. ${breakdown.layouts.samples.slice(0, 3).join(", ") || "none"})`,
		);
		lines.push(
			`  • Drawables/Mipmaps: ${breakdown.drawables.count} files (e.g. ${breakdown.drawables.samples.slice(0, 3).join(", ") || "none"})`,
		);
		lines.push(
			`  • XML Configurations: ${breakdown.xml.count} files (e.g. ${breakdown.xml.samples.slice(0, 3).join(", ") || "none"})`,
		);
		lines.push(
			`  • Raw Resources: ${breakdown.raw.count} files (e.g. ${breakdown.raw.samples.slice(0, 3).join(", ") || "none"})`,
		);
		lines.push(
			`  • Assets: ${breakdown.assets.count} files (e.g. ${breakdown.assets.samples.slice(0, 3).join(", ") || "none"})`,
		);

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
