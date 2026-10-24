import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, AndroidPackageInspectTool, type ToolSession } from "@reverse/coding-agent/tools";
import {
	parseDexBuffer,
	parseXmlText,
	parseAxml,
	calculateEffectiveExported,
	extractDeepLinks,
	calculateEffectiveEnabled,
	resolveNetworkSecurityConfig,
	ZipParser,
	parseBooleanAttr,
	type AndroidManifestComponent,
} from "../../src/tools/android-package-inspect";
import { BUILTIN_TOOL_NAMES } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.flatMap(item => (item.type === "text" && item.text ? [item.text] : [])).join("\n");
}

// ============================================================================
// Fixture Generators
// ============================================================================

function buildTestDex(classNames: string[] = ["Lcom/example/MainActivity;", "Lcom/example/AuthService;"]): Buffer {
	const strings: string[] = ["Ljava/lang/Object;"];
	for (const c of classNames) {
		if (!strings.includes(c)) strings.push(c);
	}
	strings.sort();
	const stringCount = strings.length;
	const typeCount = strings.length;
	const classCount = classNames.length;

	// Header is 112 bytes
	const headerSize = 112;
	const stringIdsOff = headerSize;
	const stringIdsSize = stringCount;
	const typeIdsOff = stringIdsOff + stringIdsSize * 4;
	const typeIdsSize = typeCount;
	const classDefsOff = typeIdsOff + typeIdsSize * 4;
	const classDefsSize = classCount;

	// Prepare string data
	const strOffsets: number[] = [];
	const strDataChunks: Buffer[] = [];
	let currentStrDataOff = classDefsOff + classDefsSize * 32;

	for (const str of strings) {
		strOffsets.push(currentStrDataOff);
		const strBytes = Buffer.from(str, "utf8");
		// 1 byte uleb128 length + string bytes + null terminator
		const chunk = Buffer.concat([Buffer.from([strBytes.length]), strBytes, Buffer.from([0])]);
		strDataChunks.push(chunk);
		currentStrDataOff += chunk.length;
	}

	const totalSize = currentStrDataOff;
	const buf = Buffer.alloc(totalSize);

	// 1. DEX Magic: "dex\n035\0"
	buf.write("dex\n035\0", 0, "ascii");
	buf.writeUInt32LE(0x12345678, 0x08); // Checksum
	buf.fill(0xaa, 0x0c, 0x20); // 20-byte SHA-1 signature
	buf.writeUInt32LE(totalSize, 0x20); // File size
	buf.writeUInt32LE(headerSize, 0x24); // Header size
	buf.writeUInt32LE(0x12345678, 0x28); // Endian tag (little endian)
	buf.writeUInt32LE(stringIdsSize, 0x38);
	buf.writeUInt32LE(stringIdsOff, 0x3c);
	buf.writeUInt32LE(typeIdsSize, 0x40);
	buf.writeUInt32LE(typeIdsOff, 0x44);
	buf.writeUInt32LE(2, 0x48); // protoIdsSize
	buf.writeUInt32LE(0x100, 0x4c); // protoIdsOff
	buf.writeUInt32LE(3, 0x50); // fieldIdsSize
	buf.writeUInt32LE(0x120, 0x54); // fieldIdsOff
	buf.writeUInt32LE(5, 0x58); // methodIdsSize
	buf.writeUInt32LE(0x140, 0x5c); // methodIdsOff
	buf.writeUInt32LE(classDefsSize, 0x60);
	buf.writeUInt32LE(classDefsOff, 0x64);
	buf.writeUInt32LE(currentStrDataOff - (classDefsOff + classDefsSize * 32), 0x68); // dataSize
	buf.writeUInt32LE(classDefsOff + classDefsSize * 32, 0x6c); // dataOff

	// 2. String IDs Table
	for (let i = 0; i < stringCount; i++) {
		buf.writeUInt32LE(strOffsets[i], stringIdsOff + i * 4);
	}

	// 3. Type IDs Table (each type points to its string index)
	for (let i = 0; i < typeCount; i++) {
		buf.writeUInt32LE(i, typeIdsOff + i * 4);
	}

	// 4. Class Defs Table
	const objTypeIdx = strings.indexOf("Ljava/lang/Object;");
	for (let i = 0; i < classCount; i++) {
		const cName = classNames[i];
		const classIdx = strings.indexOf(cName);
		const off = classDefsOff + i * 32;
		buf.writeUInt32LE(classIdx, off); // class_idx
		buf.writeUInt32LE(0x0001, off + 4); // access_flags (public)
		buf.writeUInt32LE(objTypeIdx !== -1 ? objTypeIdx : 0xffffffff, off + 8); // superclass_idx
		buf.writeUInt32LE(0, off + 12);
		buf.writeUInt32LE(0xffffffff, off + 16);
		buf.writeUInt32LE(0, off + 20);
		buf.writeUInt32LE(0, off + 24);
		buf.writeUInt32LE(0, off + 28);
	}

	// 5. String Data
	let p = classDefsOff + classDefsSize * 32;
	for (const chunk of strDataChunks) {
		chunk.copy(buf, p);
		p += chunk.length;
	}

	return buf;
}

function buildApkSigningBlock(options: { v2?: boolean; v3?: boolean; v31?: boolean; sourceStamp?: boolean }): Buffer {
	const pairs: Buffer[] = [];

	if (options.v2) {
		const pair = Buffer.alloc(16);
		pair.writeBigUInt64LE(8n, 0); // lengthOfPair = 8
		pair.writeUInt32LE(0x7109871a, 8); // ID: APK Signature Scheme v2
		pair.writeUInt32LE(0xdeadbeef, 12); // dummy payload
		pairs.push(pair);
	}

	if (options.v3) {
		const pair = Buffer.alloc(16);
		pair.writeBigUInt64LE(8n, 0); // lengthOfPair = 8
		pair.writeUInt32LE(0xf05368c0, 8); // ID: APK Signature Scheme v3
		pair.writeUInt32LE(0xcafebabe, 12);
		pairs.push(pair);
	}

	if (options.v31) {
		const pair = Buffer.alloc(16);
		pair.writeBigUInt64LE(8n, 0);
		pair.writeUInt32LE(0x1b93ad61, 8);
		pair.writeUInt32LE(0x01020304, 12);
		pairs.push(pair);
	}

	if (options.sourceStamp) {
		const pair = Buffer.alloc(16);
		pair.writeBigUInt64LE(8n, 0);
		pair.writeUInt32LE(0x42726577, 8);
		pair.writeUInt32LE(0x55667788, 12);
		pairs.push(pair);
	}

	const pairsPayload = Buffer.concat(pairs);
	// Total block size excludes the 8-byte initial size:
	// blockSize = pairsPayload.length + 8 (size field at end) + 16 (magic)
	const blockSize = BigInt(pairsPayload.length + 8 + 16);

	const header = Buffer.alloc(8);
	header.writeBigUInt64LE(blockSize, 0);

	const footer = Buffer.alloc(24);
	footer.writeBigUInt64LE(blockSize, 0);
	footer.write("APK Sig Block 42", 8, "ascii");

	return Buffer.concat([header, pairsPayload, footer]);
}

interface TestZipFileEntry {
	name: string;
	data: Buffer | Uint8Array;
	compressionMethod?: number; // 0 = STORED, 8 = DEFLATED
}

function buildTestZip(entries: TestZipFileEntry[], signingBlock?: Buffer): Buffer {
	const chunks: Buffer[] = [];
	const cdEntries: Array<{
		name: string;
		method: number;
		compressedSize: number;
		uncompressedSize: number;
		localOffset: number;
	}> = [];

	let currentOffset = 0;

	for (const entry of entries) {
		const method = entry.compressionMethod ?? 0;
		const uncomp = Buffer.from(entry.data);
		let comp: Buffer;

		if (method === 8) {
			comp = zlib.deflateRawSync(uncomp);
		} else {
			comp = uncomp;
		}

		const nameBytes = Buffer.from(entry.name, "utf8");
		const localHeader = Buffer.alloc(30 + nameBytes.length);
		localHeader.writeUInt32LE(0x04034b50, 0); // Local signature
		localHeader.writeUInt16LE(0x0014, 4); // Version needed (2.0)
		localHeader.writeUInt16LE(0, 6); // Flags
		localHeader.writeUInt16LE(method, 8); // Compression method
		localHeader.writeUInt16LE(0, 10); // Time
		localHeader.writeUInt16LE(0, 12); // Date
		localHeader.writeUInt32LE(0x12345678, 14); // CRC-32 dummy
		localHeader.writeUInt32LE(comp.length, 18); // Compressed size
		localHeader.writeUInt32LE(uncomp.length, 22); // Uncompressed size
		localHeader.writeUInt16LE(nameBytes.length, 26); // Name length
		localHeader.writeUInt16LE(0, 28); // Extra length
		nameBytes.copy(localHeader, 30);

		cdEntries.push({
			name: entry.name,
			method,
			compressedSize: comp.length,
			uncompressedSize: uncomp.length,
			localOffset: currentOffset,
		});

		chunks.push(localHeader, comp);
		currentOffset += localHeader.length + comp.length;
	}

	// Insert APK Signing Block before Central Directory if present
	if (signingBlock && signingBlock.length > 0) {
		chunks.push(signingBlock);
		currentOffset += signingBlock.length;
	}

	const cdStartOffset = currentOffset;

	// Central Directory
	for (const cd of cdEntries) {
		const nameBytes = Buffer.from(cd.name, "utf8");
		const cdHeader = Buffer.alloc(46 + nameBytes.length);
		cdHeader.writeUInt32LE(0x02014b50, 0); // CD signature
		cdHeader.writeUInt16LE(0x0014, 4); // Made by
		cdHeader.writeUInt16LE(0x0014, 6); // Needed
		cdHeader.writeUInt16LE(0, 8); // Flags
		cdHeader.writeUInt16LE(cd.method, 10);
		cdHeader.writeUInt16LE(0, 12);
		cdHeader.writeUInt16LE(0, 14);
		cdHeader.writeUInt32LE(0x12345678, 16);
		cdHeader.writeUInt32LE(cd.compressedSize, 20);
		cdHeader.writeUInt32LE(cd.uncompressedSize, 24);
		cdHeader.writeUInt16LE(nameBytes.length, 28);
		cdHeader.writeUInt16LE(0, 30);
		cdHeader.writeUInt16LE(0, 32);
		cdHeader.writeUInt16LE(0, 34);
		cdHeader.writeUInt16LE(0, 36);
		cdHeader.writeUInt32LE(0, 38);
		cdHeader.writeUInt32LE(cd.localOffset, 42);
		nameBytes.copy(cdHeader, 46);

		chunks.push(cdHeader);
		currentOffset += cdHeader.length;
	}

	const cdSize = currentOffset - cdStartOffset;

	// EOCD record
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(cdEntries.length, 8);
	eocd.writeUInt16LE(cdEntries.length, 10);
	eocd.writeUInt32LE(cdSize, 12);
	eocd.writeUInt32LE(cdStartOffset, 16);
	eocd.writeUInt16LE(0, 20);

	chunks.push(eocd);

	return Buffer.concat(chunks);
}

function buildTestArsc(packageName: string = "com.example.app"): Buffer {
	const buf = Buffer.alloc(512);
	buf.writeUInt16LE(0x0002, 0); // RES_TABLE_TYPE
	buf.writeUInt16LE(12, 2); // Header size
	buf.writeUInt32LE(512, 4); // Total size
	buf.writeUInt32LE(1, 8); // Package count

	// Package chunk at offset 12
	buf.writeUInt16LE(0x0200, 12); // RES_TABLE_PACKAGE_TYPE
	buf.writeUInt16LE(288, 14); // Header size
	buf.writeUInt32LE(300, 16); // Chunk size
	buf.writeUInt32LE(0x7f, 20); // Package ID
	buf.write(packageName, 24, "utf16le"); // Package name in UTF-16LE

	return buf;
}

function buildEndElementChunk(nameIdx: number): Buffer {
	const endElem = Buffer.alloc(24);
	endElem.writeUInt16LE(0x0103, 0); // RES_XML_END_ELEMENT_TYPE
	endElem.writeUInt16LE(16, 2);
	endElem.writeUInt32LE(24, 4);
	endElem.writeUInt32LE(0, 8); // Line
	endElem.writeUInt32LE(0xffffffff, 12); // Comment
	endElem.writeUInt32LE(0xffffffff, 16); // NS
	endElem.writeUInt32LE(nameIdx, 20); // Name
	return endElem;
}
function encodeUleb128(val: number): Buffer {
	if (val < 0x80) return Buffer.from([val]);
	return Buffer.from([((val >> 8) & 0x7f) | 0x80, val & 0xff]);
}

function encodeAxmlUtf8String(s: string): Buffer {
	const sBuf = Buffer.from(s, "utf8");
	const u16Len = s.length;
	const u8Len = sBuf.length;
	return Buffer.concat([encodeUleb128(u16Len), encodeUleb128(u8Len), sBuf, Buffer.from([0])]);
}

function buildTestAxml(manifest: {
	packageName: string;
	versionCode?: number;
	versionName?: string;
	minSdkVersion?: number;
	targetSdkVersion?: number;
	permission?: string;
	activityName?: string;
	exported?: boolean;
	appEnabled?: boolean;
	compEnabled?: boolean;
	targetActivity?: string;
}): Buffer {
	const strings = [
		"manifest",
		"package",
		manifest.packageName,
		"versionCode",
		"versionName",
		manifest.versionName ?? "1.0.0",
		"uses-sdk",
		"minSdkVersion",
		"targetSdkVersion",
		"uses-permission",
		"name",
		manifest.permission ?? "android.permission.INTERNET",
		"application",
		"activity",
		manifest.activityName ?? "com.example.app.MainActivity",
		"exported",
		"enabled",
		"targetActivity",
		manifest.targetActivity ?? "",
	];

	// Build string pool chunk
	const strOffsets: number[] = [];
	const strDataChunks: Buffer[] = [];
	let currentRelOff = 0;

	for (const s of strings) {
		strOffsets.push(currentRelOff);
		const chunk = encodeAxmlUtf8String(s);
		strDataChunks.push(chunk);
		currentRelOff += chunk.length;
	}

	const poolHeaderSize = 28;
	const poolOffsetsSize = strings.length * 4;
	const stringsStart = poolHeaderSize + poolOffsetsSize;
	const unpaddedPoolSize = stringsStart + currentRelOff;
	const pad = (4 - (unpaddedPoolSize % 4)) % 4;
	const totalPoolSize = unpaddedPoolSize + pad;

	const poolBuf = Buffer.alloc(totalPoolSize);
	poolBuf.writeUInt16LE(0x0001, 0); // RES_STRING_POOL_TYPE
	poolBuf.writeUInt16LE(poolHeaderSize, 2);
	poolBuf.writeUInt32LE(totalPoolSize, 4);
	poolBuf.writeUInt32LE(strings.length, 8);
	poolBuf.writeUInt32LE(0, 12); // Style count
	poolBuf.writeUInt32LE(0x0100, 16); // Flags: UTF-8
	poolBuf.writeUInt32LE(stringsStart, 20);
	poolBuf.writeUInt32LE(0, 24); // Styles start

	for (let i = 0; i < strings.length; i++) {
		poolBuf.writeUInt32LE(strOffsets[i], poolHeaderSize + i * 4);
	}

	let p = stringsStart;
	for (const c of strDataChunks) {
		c.copy(poolBuf, p);
		p += c.length;
	}

	// XML element chunks
	const elemChunks: Buffer[] = [];

	// <manifest package="com.example.app" versionCode="42" versionName="1.0.0">
	const manifestElem = Buffer.alloc(36 + 3 * 20);
	manifestElem.writeUInt16LE(0x0102, 0); // RES_XML_START_ELEMENT_TYPE
	manifestElem.writeUInt16LE(16, 2);
	manifestElem.writeUInt32LE(manifestElem.length, 4);
	manifestElem.writeUInt32LE(0, 8); // Line
	manifestElem.writeUInt32LE(0xffffffff, 12); // Comment
	manifestElem.writeUInt32LE(0xffffffff, 16); // NS
	manifestElem.writeUInt32LE(strings.indexOf("manifest"), 20); // Name
	manifestElem.writeUInt16LE(20, 24); // Attr start
	manifestElem.writeUInt16LE(20, 26); // Attr size
	manifestElem.writeUInt16LE(3, 28); // Attr count

	// Attr 1: package
	const a1 = 36;
	manifestElem.writeUInt32LE(0xffffffff, a1);
	manifestElem.writeUInt32LE(strings.indexOf("package"), a1 + 4);
	manifestElem.writeUInt32LE(strings.indexOf(manifest.packageName), a1 + 8);
	manifestElem.writeUInt16LE(8, a1 + 12);
	manifestElem.writeUInt8(0x03, a1 + 15); // TYPE_STRING
	manifestElem.writeUInt32LE(strings.indexOf(manifest.packageName), a1 + 16);

	// Attr 2: versionCode
	const a2 = a1 + 20;
	manifestElem.writeUInt32LE(0xffffffff, a2);
	manifestElem.writeUInt32LE(strings.indexOf("versionCode"), a2 + 4);
	manifestElem.writeUInt32LE(0xffffffff, a2 + 8);
	manifestElem.writeUInt16LE(8, a2 + 12);
	manifestElem.writeUInt8(0x10, a2 + 15); // TYPE_INT_DEC
	manifestElem.writeUInt32LE(manifest.versionCode ?? 42, a2 + 16);

	// Attr 3: versionName
	const a3 = a2 + 20;
	manifestElem.writeUInt32LE(0xffffffff, a3);
	manifestElem.writeUInt32LE(strings.indexOf("versionName"), a3 + 4);
	manifestElem.writeUInt32LE(strings.indexOf(manifest.versionName ?? "1.0.0"), a3 + 8);
	manifestElem.writeUInt16LE(8, a3 + 12);
	manifestElem.writeUInt8(0x03, a3 + 15); // TYPE_STRING
	manifestElem.writeUInt32LE(strings.indexOf(manifest.versionName ?? "1.0.0"), a3 + 16);

	elemChunks.push(manifestElem);

	// <uses-sdk minSdkVersion="24" targetSdkVersion="34">
	const sdkElem = Buffer.alloc(36 + 2 * 20);
	sdkElem.writeUInt16LE(0x0102, 0);
	sdkElem.writeUInt16LE(16, 2);
	sdkElem.writeUInt32LE(sdkElem.length, 4);
	sdkElem.writeUInt32LE(strings.indexOf("uses-sdk"), 20);
	sdkElem.writeUInt16LE(20, 24);
	sdkElem.writeUInt16LE(20, 26);
	sdkElem.writeUInt16LE(2, 28);

	const s1 = 36;
	sdkElem.writeUInt32LE(0xffffffff, s1);
	sdkElem.writeUInt32LE(strings.indexOf("minSdkVersion"), s1 + 4);
	sdkElem.writeUInt32LE(0xffffffff, s1 + 8);
	sdkElem.writeUInt16LE(8, s1 + 12);
	sdkElem.writeUInt8(0x10, s1 + 15); // TYPE_INT_DEC
	sdkElem.writeUInt32LE(manifest.minSdkVersion ?? 24, s1 + 16);

	const s2 = s1 + 20;
	sdkElem.writeUInt32LE(0xffffffff, s2);
	sdkElem.writeUInt32LE(strings.indexOf("targetSdkVersion"), s2 + 4);
	sdkElem.writeUInt32LE(0xffffffff, s2 + 8);
	sdkElem.writeUInt16LE(8, s2 + 12);
	sdkElem.writeUInt8(0x10, s2 + 15); // TYPE_INT_DEC
	sdkElem.writeUInt32LE(manifest.targetSdkVersion ?? 34, s2 + 16);

	elemChunks.push(sdkElem);
	elemChunks.push(buildEndElementChunk(strings.indexOf("uses-sdk")));

	// <uses-permission name="android.permission.INTERNET">
	const permElem = Buffer.alloc(36 + 1 * 20);
	permElem.writeUInt16LE(0x0102, 0);
	permElem.writeUInt16LE(16, 2);
	permElem.writeUInt32LE(permElem.length, 4);
	permElem.writeUInt32LE(strings.indexOf("uses-permission"), 20);
	permElem.writeUInt16LE(20, 24);
	permElem.writeUInt16LE(20, 26);
	permElem.writeUInt16LE(1, 28);

	const p1 = 36;
	permElem.writeUInt32LE(0xffffffff, p1);
	permElem.writeUInt32LE(strings.indexOf("name"), p1 + 4);
	permElem.writeUInt32LE(strings.indexOf(manifest.permission ?? "android.permission.INTERNET"), p1 + 8);
	permElem.writeUInt16LE(8, p1 + 12);
	permElem.writeUInt8(0x03, p1 + 15); // TYPE_STRING
	permElem.writeUInt32LE(strings.indexOf(manifest.permission ?? "android.permission.INTERNET"), p1 + 16);

	elemChunks.push(permElem);
	elemChunks.push(buildEndElementChunk(strings.indexOf("uses-permission")));

	// <application>
	const appAttrCount = manifest.appEnabled !== undefined ? 1 : 0;
	const appElem = Buffer.alloc(36 + appAttrCount * 20);
	appElem.writeUInt16LE(0x0102, 0);
	appElem.writeUInt16LE(16, 2);
	appElem.writeUInt32LE(appElem.length, 4);
	appElem.writeUInt32LE(strings.indexOf("application"), 20);
	appElem.writeUInt16LE(20, 24);
	appElem.writeUInt16LE(20, 26);
	appElem.writeUInt16LE(appAttrCount, 28);
	if (manifest.appEnabled !== undefined) {
		appElem.writeUInt32LE(0xffffffff, 36);
		appElem.writeUInt32LE(strings.indexOf("enabled"), 36 + 4);
		appElem.writeUInt32LE(0xffffffff, 36 + 8);
		appElem.writeUInt16LE(8, 36 + 12);
		appElem.writeUInt8(0x12, 36 + 15);
		appElem.writeUInt32LE(manifest.appEnabled ? 1 : 0, 36 + 16);
	}
	elemChunks.push(appElem);

	// <activity name="com.example.app.MainActivity" exported="true">
	let actAttrCount = 2;
	if (manifest.compEnabled !== undefined) actAttrCount++;
	if (manifest.targetActivity) actAttrCount++;
	const actElem = Buffer.alloc(36 + actAttrCount * 20);
	actElem.writeUInt16LE(0x0102, 0);
	actElem.writeUInt16LE(16, 2);
	actElem.writeUInt32LE(actElem.length, 4);
	actElem.writeUInt32LE(strings.indexOf("activity"), 20);
	actElem.writeUInt16LE(20, 24);
	actElem.writeUInt16LE(20, 26);
	actElem.writeUInt16LE(actAttrCount, 28);

	let curActOff = 36;
	actElem.writeUInt32LE(0xffffffff, curActOff);
	actElem.writeUInt32LE(strings.indexOf("name"), curActOff + 4);
	actElem.writeUInt32LE(strings.indexOf(manifest.activityName ?? "com.example.app.MainActivity"), curActOff + 8);
	actElem.writeUInt16LE(8, curActOff + 12);
	actElem.writeUInt8(0x03, curActOff + 15); // TYPE_STRING
	actElem.writeUInt32LE(strings.indexOf(manifest.activityName ?? "com.example.app.MainActivity"), curActOff + 16);
	curActOff += 20;

	actElem.writeUInt32LE(0xffffffff, curActOff);
	actElem.writeUInt32LE(strings.indexOf("exported"), curActOff + 4);
	actElem.writeUInt32LE(0xffffffff, curActOff + 8);
	actElem.writeUInt16LE(8, curActOff + 12);
	actElem.writeUInt8(0x12, curActOff + 15); // TYPE_INT_BOOLEAN
	actElem.writeUInt32LE(manifest.exported !== false ? 1 : 0, curActOff + 16);
	curActOff += 20;

	if (manifest.compEnabled !== undefined) {
		actElem.writeUInt32LE(0xffffffff, curActOff);
		actElem.writeUInt32LE(strings.indexOf("enabled"), curActOff + 4);
		actElem.writeUInt32LE(0xffffffff, curActOff + 8);
		actElem.writeUInt16LE(8, curActOff + 12);
		actElem.writeUInt8(0x12, curActOff + 15);
		actElem.writeUInt32LE(manifest.compEnabled ? 1 : 0, curActOff + 16);
		curActOff += 20;
	}

	if (manifest.targetActivity) {
		actElem.writeUInt32LE(0xffffffff, curActOff);
		actElem.writeUInt32LE(strings.indexOf("targetActivity"), curActOff + 4);
		actElem.writeUInt32LE(strings.indexOf(manifest.targetActivity), curActOff + 8);
		actElem.writeUInt16LE(8, curActOff + 12);
		actElem.writeUInt8(0x03, curActOff + 15);
		actElem.writeUInt32LE(strings.indexOf(manifest.targetActivity), curActOff + 16);
		curActOff += 20;
	}

	elemChunks.push(actElem);
	elemChunks.push(buildEndElementChunk(strings.indexOf("activity")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("application")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("manifest")));

	const allElems = Buffer.concat(elemChunks);
	const totalSize = 8 + poolBuf.length + allElems.length;

	const axmlHeader = Buffer.alloc(8);
	axmlHeader.writeUInt16LE(0x0003, 0); // RES_XML_TYPE
	axmlHeader.writeUInt16LE(8, 2); // Header size
	axmlHeader.writeUInt32LE(totalSize, 4); // Total size

	return Buffer.concat([axmlHeader, poolBuf, allElems]);
}
function buildTestNetworkSecurityConfigAxml(opts?: {
	cleartextTrafficPermitted?: boolean;
	baseCertSrc?: string;
	baseOverridePins?: boolean;
	domain?: string;
	includeSubdomains?: boolean;
	domainCleartext?: boolean;
	domainCertSrc?: string;
	nestedDomain?: string;
	nestedCertSrc?: string;
	siblingDomain?: string;
	pinDigest?: string;
	pinVal?: string;
	debugCertSrc?: string;
	debugOverridePins?: boolean;
}): Buffer {
	const strings = [
		"network-security-config",
		"base-config",
		"cleartextTrafficPermitted",
		"trust-anchors",
		"certificates",
		"src",
		"overridePins",
		opts?.baseCertSrc ?? "system",
		"domain-config",
		"domain",
		"includeSubdomains",
		opts?.domain ?? "example.com",
		opts?.domainCertSrc ?? "user",
		"pin-set",
		"expiration",
		"2027-01-01",
		"pin",
		"digest",
		opts?.pinDigest ?? "SHA-256",
		opts?.pinVal ?? "7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=",
		opts?.nestedDomain ?? "private.example.com",
		opts?.nestedCertSrc ?? "@raw/private",
		opts?.siblingDomain ?? "cdn.example.com",
		"debug-overrides",
		opts?.debugCertSrc ?? "user",
	];

	const strOffsets: number[] = [];
	const strDataChunks: Buffer[] = [];
	let currentRelOff = 0;

	for (const s of strings) {
		strOffsets.push(currentRelOff);
		const chunk = encodeAxmlUtf8String(s);
		strDataChunks.push(chunk);
		currentRelOff += chunk.length;
	}

	const poolHeaderSize = 28;
	const poolOffsetsSize = strings.length * 4;
	const stringsStart = poolHeaderSize + poolOffsetsSize;
	const unpaddedPoolSize = stringsStart + currentRelOff;
	const pad = (4 - (unpaddedPoolSize % 4)) % 4;
	const totalPoolSize = unpaddedPoolSize + pad;

	const poolBuf = Buffer.alloc(totalPoolSize);
	poolBuf.writeUInt16LE(0x0001, 0); // RES_STRING_POOL_TYPE
	poolBuf.writeUInt16LE(poolHeaderSize, 2);
	poolBuf.writeUInt32LE(totalPoolSize, 4);
	poolBuf.writeUInt32LE(strings.length, 8);
	poolBuf.writeUInt32LE(0, 12);
	poolBuf.writeUInt32LE(0x0100, 16); // UTF-8
	poolBuf.writeUInt32LE(stringsStart, 20);
	poolBuf.writeUInt32LE(0, 24);

	for (let i = 0; i < strings.length; i++) {
		poolBuf.writeUInt32LE(strOffsets[i], poolHeaderSize + i * 4);
	}

	let p = stringsStart;
	for (const c of strDataChunks) {
		c.copy(poolBuf, p);
		p += c.length;
	}

	const makeElem = (
		tag: string,
		attrs: Array<{ name: string; val: string | number | boolean; type: number }>,
	): Buffer => {
		const elem = Buffer.alloc(36 + attrs.length * 20);
		elem.writeUInt16LE(0x0102, 0); // RES_XML_START_ELEMENT_TYPE
		elem.writeUInt16LE(16, 2);
		elem.writeUInt32LE(elem.length, 4);
		elem.writeUInt32LE(strings.indexOf(tag), 20);
		elem.writeUInt16LE(20, 24);
		elem.writeUInt16LE(20, 26);
		elem.writeUInt16LE(attrs.length, 28);

		let off = 36;
		for (const a of attrs) {
			elem.writeUInt32LE(0xffffffff, off);
			elem.writeUInt32LE(strings.indexOf(a.name), off + 4);
			if (typeof a.val === "string") {
				elem.writeUInt32LE(strings.indexOf(a.val), off + 8);
			} else {
				elem.writeUInt32LE(0xffffffff, off + 8);
			}
			elem.writeUInt16LE(8, off + 12);
			elem.writeUInt8(a.type, off + 15);
			if (typeof a.val === "boolean") {
				elem.writeUInt32LE(a.val ? 1 : 0, off + 16);
			} else if (typeof a.val === "number") {
				elem.writeUInt32LE(a.val, off + 16);
			} else {
				elem.writeUInt32LE(strings.indexOf(a.val), off + 16);
			}
			off += 20;
		}
		return elem;
	};

	const makeCdata = (text: string): Buffer => {
		const cdata = Buffer.alloc(28);
		cdata.writeUInt16LE(0x0104, 0); // RES_XML_CDATA_TYPE
		cdata.writeUInt16LE(16, 2);
		cdata.writeUInt32LE(28, 4);
		cdata.writeUInt32LE(strings.indexOf(text), 16);
		return cdata;
	};

	const elemChunks: Buffer[] = [];

	// <network-security-config>
	elemChunks.push(makeElem("network-security-config", []));

	// <base-config cleartextTrafficPermitted="...">
	const baseAttrs: Array<{ name: string; val: string | number | boolean; type: number }> = [];
	if (opts?.cleartextTrafficPermitted !== undefined) {
		baseAttrs.push({
			name: "cleartextTrafficPermitted",
			val: opts.cleartextTrafficPermitted,
			type: 0x12,
		});
	}
	elemChunks.push(makeElem("base-config", baseAttrs));
	// <trust-anchors><certificates src="..." overridePins="..."/></trust-anchors>
	elemChunks.push(makeElem("trust-anchors", []));
	const certAttrs: Array<{ name: string; val: string | number | boolean; type: number }> = [
		{ name: "src", val: opts?.baseCertSrc ?? "system", type: 0x03 },
	];
	if (opts?.baseOverridePins !== undefined) {
		certAttrs.push({ name: "overridePins", val: opts.baseOverridePins, type: 0x12 });
	}
	elemChunks.push(makeElem("certificates", certAttrs));
	elemChunks.push(buildEndElementChunk(strings.indexOf("certificates")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("trust-anchors")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("base-config")));

	// Outer <domain-config cleartextTrafficPermitted="...">
	const domConfigAttrs: Array<{ name: string; val: string | number | boolean; type: number }> = [];
	if (opts?.domainCleartext !== undefined) {
		domConfigAttrs.push({ name: "cleartextTrafficPermitted", val: opts.domainCleartext, type: 0x12 });
	}
	elemChunks.push(makeElem("domain-config", domConfigAttrs));
	// <domain includeSubdomains="true">example.com</domain>
	const domAttrs: Array<{ name: string; val: string | number | boolean; type: number }> = [];
	if (opts?.includeSubdomains !== false) {
		domAttrs.push({ name: "includeSubdomains", val: true, type: 0x12 });
	}
	elemChunks.push(makeElem("domain", domAttrs));
	elemChunks.push(makeCdata(opts?.domain ?? "example.com"));
	elemChunks.push(buildEndElementChunk(strings.indexOf("domain")));

	// <trust-anchors><certificates src="user"/></trust-anchors>
	elemChunks.push(makeElem("trust-anchors", []));
	elemChunks.push(makeElem("certificates", [{ name: "src", val: opts?.domainCertSrc ?? "user", type: 0x03 }]));
	elemChunks.push(buildEndElementChunk(strings.indexOf("certificates")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("trust-anchors")));

	// <pin-set expiration="2027-01-01"><pin digest="SHA-256">...</pin></pin-set>
	elemChunks.push(makeElem("pin-set", [{ name: "expiration", val: "2027-01-01", type: 0x03 }]));
	elemChunks.push(makeElem("pin", [{ name: "digest", val: opts?.pinDigest ?? "SHA-256", type: 0x03 }]));
	elemChunks.push(makeCdata(opts?.pinVal ?? "7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y="));
	elemChunks.push(buildEndElementChunk(strings.indexOf("pin")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("pin-set")));

	// Nested <domain-config> (explicit anchors: @raw/private)
	elemChunks.push(makeElem("domain-config", []));
	elemChunks.push(makeElem("domain", []));
	elemChunks.push(makeCdata(opts?.nestedDomain ?? "private.example.com"));
	elemChunks.push(buildEndElementChunk(strings.indexOf("domain")));
	elemChunks.push(makeElem("trust-anchors", []));
	elemChunks.push(makeElem("certificates", [{ name: "src", val: opts?.nestedCertSrc ?? "@raw/private", type: 0x03 }]));
	elemChunks.push(buildEndElementChunk(strings.indexOf("certificates")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("trust-anchors")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("domain-config")));

	// Sibling nested <domain-config> (absent anchors -> inherits user from outer domain)
	elemChunks.push(makeElem("domain-config", []));
	elemChunks.push(makeElem("domain", []));
	elemChunks.push(makeCdata(opts?.siblingDomain ?? "cdn.example.com"));
	elemChunks.push(buildEndElementChunk(strings.indexOf("domain")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("domain-config")));

	elemChunks.push(buildEndElementChunk(strings.indexOf("domain-config"))); // close outer domain-config

	// <debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>
	elemChunks.push(makeElem("debug-overrides", []));
	elemChunks.push(makeElem("trust-anchors", []));
	const debugCertAttrs: Array<{ name: string; val: string | number | boolean; type: number }> = [
		{ name: "src", val: opts?.debugCertSrc ?? "user", type: 0x03 },
	];
	if (opts?.debugOverridePins !== undefined) {
		debugCertAttrs.push({ name: "overridePins", val: opts.debugOverridePins, type: 0x12 });
	}
	elemChunks.push(makeElem("certificates", debugCertAttrs));
	elemChunks.push(buildEndElementChunk(strings.indexOf("certificates")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("trust-anchors")));
	elemChunks.push(buildEndElementChunk(strings.indexOf("debug-overrides")));

	elemChunks.push(buildEndElementChunk(strings.indexOf("network-security-config")));

	const allElems = Buffer.concat(elemChunks);
	const totalSize = 8 + poolBuf.length + allElems.length;

	const axmlHeader = Buffer.alloc(8);
	axmlHeader.writeUInt16LE(0x0003, 0); // RES_XML_TYPE
	axmlHeader.writeUInt16LE(8, 2);
	axmlHeader.writeUInt32LE(totalSize, 4);

	return Buffer.concat([axmlHeader, poolBuf, allElems]);
}

// ============================================================================
// Tests
// ============================================================================

describe("android_package_inspect registration", () => {
	it("is registered as a builtin tool", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("android_package_inspect");
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["android_package_inspect"]);
			const tool = tools.find(t => t.name === "android_package_inspect") as AndroidPackageInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Android Package Inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("android_package_inspect path validation and errors", () => {
	it("rejects non-existent file path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-missing-"));
		try {
			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { action: "info", path: "nonexistent.apk" })).rejects.toThrow(
				"Target file not found",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-dir-"));
		try {
			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { action: "info", path: "." })).rejects.toThrow("is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects missing path and target parameters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-nopath-"));
		try {
			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", { action: "info" } as unknown as { action: "info"; path: string }),
			).rejects.toThrow("Missing required parameter 'path'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns unsupported for non-Android files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-unsupported-"));
		try {
			const textFile = path.join(tempDir, "sample.txt");
			await fs.writeFile(textFile, "Hello plain text world", "utf8");
			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "sample.txt" });
			expect(res.details.status).toBe("unsupported");
			expect(textOf(res)).toContain("[Unsupported]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("android_package_inspect bare DEX inspection", () => {
	it("inspects bare DEX header metrics and sample classes in info action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dex-info-"));
		try {
			const dexPath = path.join(tempDir, "classes.dex");
			await fs.writeFile(dexPath, buildTestDex(["Lcom/example/MainActivity;", "Lcom/example/AuthManager;"]));

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "classes.dex" });

			expect(res.details.status).toBe("ok");
			expect(res.details.format).toBe("DEX");
			expect(res.details.info?.bareDex).toBeDefined();
			expect(res.details.info?.bareDex?.header.version).toBe("035");
			expect(res.details.info?.bareDex?.header.classDefsCount).toBe(2);
			expect(res.details.info?.bareDex?.header.endian).toBe("little");
			expect(textOf(res)).toContain("Bare DEX File");
			expect(textOf(res)).toContain("com.example.MainActivity");
			expect(textOf(res)).toContain("com.example.AuthManager");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects classes and supports filtering in dex action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dex-action-"));
		try {
			const dexPath = path.join(tempDir, "classes.dex");
			await fs.writeFile(
				dexPath,
				buildTestDex(["Lcom/example/MainActivity;", "Lcom/example/AuthManager;", "Lcom/example/NetworkClient;"]),
			);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));

			// 1. All classes
			const resAll = await tool.execute("call-1", { action: "dex", path: "classes.dex" });
			expect(resAll.details.status).toBe("ok");
			expect(resAll.details.dex?.classes.length).toBe(3);
			expect(resAll.details.dex?.classes[0].name).toBe("com.example.MainActivity");

			// 2. Filter classes by "Auth"
			const resFiltered = await tool.execute("call-2", {
				action: "dex",
				path: "classes.dex",
				filter: "Auth",
			});
			expect(resFiltered.details.status).toBe("ok");
			expect(resFiltered.details.dex?.classes.length).toBe(1);
			expect(resFiltered.details.dex?.classes[0].name).toBe("com.example.AuthManager");

			// 3. Pagination offset
			const resPaged = await tool.execute("call-3", {
				action: "dex",
				path: "classes.dex",
				limit: 1,
				offset: 1,
			});
			expect(resPaged.details.status).toBe("ok");
			expect(resPaged.details.dex?.classes.length).toBe(1);
			expect(resPaged.details.hasMore).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns unsupported for manifest, signing, and resources actions against bare DEX", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dex-unsupported-"));
		try {
			const dexPath = path.join(tempDir, "classes.dex");
			await fs.writeFile(dexPath, buildTestDex(["Lcom/example/MainActivity;"]));

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));

			const resManifest = await tool.execute("call-1", { action: "manifest", path: "classes.dex" });
			expect(resManifest.details.status).toBe("unsupported");
			expect(resManifest.details.error).toContain("bare DEX");

			const resSigning = await tool.execute("call-2", { action: "signing", path: "classes.dex" });
			expect(resSigning.details.status).toBe("unsupported");
			expect(resSigning.details.error).toContain("bare DEX");

			const resResources = await tool.execute("call-3", { action: "resources", path: "classes.dex" });
			expect(resResources.details.status).toBe("unsupported");
			expect(resResources.details.error).toContain("bare DEX");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("android_package_inspect APK container inspection", () => {
	it("inspects APK container entries, native libs, DEX summaries, and signing presence in info action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-info-"));
		try {
			const dex1 = buildTestDex(["Lcom/example/MainActivity;"]);
			const dex2 = buildTestDex(["Lcom/example/SecondActivity;"]);
			const axml = buildTestAxml({ packageName: "com.example.app" });
			const arsc = buildTestArsc("com.example.app");

			const signingBlock = buildApkSigningBlock({ v2: true, v3: true });

			const apkBuffer = buildTestZip(
				[
					{ name: "AndroidManifest.xml", data: axml },
					{ name: "classes.dex", data: dex1 },
					{ name: "classes2.dex", data: dex2 },
					{ name: "lib/arm64-v8a/libnative-crypto.so", data: Buffer.from("dummy-so-1") },
					{ name: "lib/arm64-v8a/libssl.so", data: Buffer.from("dummy-so-2") },
					{ name: "lib/x86_64/libnative-crypto.so", data: Buffer.from("dummy-so-3") },
					{ name: "res/layout/activity_main.xml", data: Buffer.from("<layout/>") },
					{ name: "res/drawable/ic_launcher.png", data: Buffer.from("png-data") },
					{ name: "resources.arsc", data: arsc },
					{ name: "assets/config.json", data: Buffer.from("{}") },
					{ name: "META-INF/MANIFEST.MF", data: Buffer.from("Manifest-Version: 1.0\n") },
					{ name: "META-INF/CERT.SF", data: Buffer.from("Signature-Version: 1.0\n") },
					{ name: "META-INF/CERT.RSA", data: Buffer.from("dummy-rsa-block") },
				],
				signingBlock,
			);

			const apkPath = path.join(tempDir, "app-release.apk");
			await fs.writeFile(apkPath, apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "app-release.apk" });

			expect(res.details.status).toBe("ok");
			expect(res.details.format).toBe("APK");
			expect(res.details.info?.container).toBeDefined();

			const container = res.details.info!.container!;
			expect(container.manifestPresent).toBe(true);
			expect(container.manifestFormat).toBe("binary_xml");
			expect(container.dexFiles.length).toBe(2);
			expect(container.nativeLibraries["arm64-v8a"]).toEqual(["libnative-crypto.so", "libssl.so"]);
			expect(container.nativeLibraries["x86_64"]).toEqual(["libnative-crypto.so"]);
			expect(container.resources.hasArsc).toBe(true);
			expect(container.resources.layoutsCount).toBe(1);
			expect(container.resources.drawablesCount).toBe(1);
			expect(container.resources.assetsCount).toBe(1);
			expect(container.signing.v1Signed).toBe(true);
			expect(container.signing.apkSigningBlock).toBe(true);
			expect(container.signing.v2Scheme).toBe(true);
			expect(container.signing.v3Scheme).toBe(true);

			expect(textOf(res)).toContain("arm64-v8a: libnative-crypto.so, libssl.so");
			expect(textOf(res)).toContain("Scheme v2: Yes");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Android Binary XML manifest in manifest action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-manifest-"));
		try {
			const axml = buildTestAxml({
				packageName: "com.test.demo",
				versionCode: 101,
				versionName: "2.1.0",
				minSdkVersion: 26,
				targetSdkVersion: 34,
				permission: "android.permission.ACCESS_FINE_LOCATION",
				activityName: "com.test.demo.HomeActivity",
			});

			const apkBuffer = buildTestZip([{ name: "AndroidManifest.xml", data: axml }]);
			const apkPath = path.join(tempDir, "sample.apk");
			await fs.writeFile(apkPath, apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "manifest", path: "sample.apk" });

			expect(res.details.status).toBe("ok");
			expect(res.details.manifest).toBeDefined();
			const m = res.details.manifest!;
			expect(m.package).toBe("com.test.demo");
			expect(m.versionCode).toBe(101);
			expect(m.versionName).toBe("2.1.0");
			expect(m.minSdkVersion).toBe(26);
			expect(m.targetSdkVersion).toBe(34);
			expect(m.permissions).toContain("android.permission.ACCESS_FINE_LOCATION");
			expect(m.activities.some(a => a.name === "com.test.demo.HomeActivity")).toBe(true);

			expect(textOf(res)).toContain("Package: com.test.demo");
			expect(textOf(res)).toContain("min: 26, target: 34");
			expect(textOf(res)).toContain("android.permission.ACCESS_FINE_LOCATION");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects multi-DEX files and scopes dex action by dex_index", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-dex-"));
		try {
			const dex1 = buildTestDex(["Lcom/example/MainClass;"]);
			const dex2 = buildTestDex(["Lcom/example/SecondClass;", "Lcom/example/ThirdClass;"]);

			const apkBuffer = buildTestZip([
				{ name: "classes.dex", data: dex1 },
				{ name: "classes2.dex", data: dex2 },
			]);
			const apkPath = path.join(tempDir, "multidex.apk");
			await fs.writeFile(apkPath, apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));

			// Target classes2.dex by dex_index = 1
			const res = await tool.execute("call-1", {
				action: "dex",
				path: "multidex.apk",
				dex_index: 1,
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.dex?.selectedDex).toBe("classes2.dex");
			expect(res.details.dex?.classes.length).toBe(2);
			expect(res.details.dex?.classes[0].name).toBe("com.example.SecondClass");
			expect(textOf(res)).toContain("classes2.dex");
			expect(textOf(res)).toContain("com.example.SecondClass");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects signature schemes and APK Signing Block in signing action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-signing-"));
		try {
			const signingBlock = buildApkSigningBlock({ v2: true, v3: true, sourceStamp: true });
			const apkBuffer = buildTestZip(
				[
					{ name: "classes.dex", data: buildTestDex() },
					{ name: "META-INF/MANIFEST.MF", data: Buffer.from("Manifest-Version: 1.0\n") },
					{ name: "META-INF/ANDROID.SF", data: Buffer.from("Signature-Version: 1.0\n") },
					{ name: "META-INF/ANDROID.RSA", data: Buffer.from("dummy-cert-data") },
				],
				signingBlock,
			);
			const apkPath = path.join(tempDir, "signed.apk");
			await fs.writeFile(apkPath, apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "signing", path: "signed.apk" });

			expect(res.details.status).toBe("ok");
			expect(res.details.signing).toBeDefined();
			const s = res.details.signing!;

			expect(s.schemes.v1.detected).toBe(true);
			expect(s.schemes.v1.manifest).toBe(true);
			expect(s.schemes.v1.signatureFiles).toContain("META-INF/ANDROID.SF");
			expect(s.schemes.v1.blockFiles).toContain("META-INF/ANDROID.RSA");

			expect(s.apkSigningBlock.present).toBe(true);
			expect(s.apkSigningBlock.v2Scheme).toBe(true);
			expect(s.apkSigningBlock.v3Scheme).toBe(true);
			expect(s.apkSigningBlock.sourceStamp).toBe(true);
			expect(s.apkSigningBlock.blockIds?.length).toBe(3);

			expect(textOf(res)).toContain("Scheme v1 (JAR signing): Present");
			expect(textOf(res)).toContain("Scheme v2 (APK Signature Scheme v2): Present");
			expect(textOf(res)).toContain("Scheme v3 (APK Signature Scheme v3): Present");
			expect(textOf(res)).toContain("SourceStamp: Present");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects resource tables and resource files in resources action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-resources-"));
		try {
			const arsc = buildTestArsc("com.example.myapp");
			const apkBuffer = buildTestZip([
				{ name: "resources.arsc", data: arsc },
				{ name: "res/layout/activity_main.xml", data: Buffer.from("<layout/>") },
				{ name: "res/layout/dialog_auth.xml", data: Buffer.from("<dialog/>") },
				{ name: "res/drawable-hdpi/icon.png", data: Buffer.from("png") },
				{ name: "res/xml/network_security_config.xml", data: Buffer.from("<config/>") },
				{ name: "assets/web/index.html", data: Buffer.from("<html></html>") },
			]);
			const apkPath = path.join(tempDir, "res.apk");
			await fs.writeFile(apkPath, apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", {
				action: "resources",
				path: "res.apk",
				filter: "auth",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.resources).toBeDefined();
			const r = res.details.resources!;

			expect(r.arsc?.present).toBe(true);
			expect(r.arsc?.packageName).toBe("com.example.myapp");
			expect(r.breakdown.layouts.count).toBe(2);
			expect(r.breakdown.drawables.count).toBe(1);
			expect(r.breakdown.xml.count).toBe(1);
			expect(r.breakdown.assets.count).toBe(1);
			expect(r.matchingFiles).toContain("res/layout/dialog_auth.xml");

			expect(textOf(res)).toContain("Resource Table (ARSC): Present");
			expect(textOf(res)).toContain("com.example.myapp");
			expect(textOf(res)).toContain("res/layout/dialog_auth.xml");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("android_package_inspect AAB and APKS inspection", () => {
	it("recognizes Android App Bundle (.aab) structure and safely reports compiled proto manifest", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "aab-inspect-"));
		try {
			const dex = buildTestDex(["Lcom/example/aab/FeatureClass;"]);
			// Compiled protobuf manifest simulation (not binary XML, not text XML)
			const protoManifest = Buffer.from([0x08, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74]);

			const aabBuffer = buildTestZip([
				{ name: "BundleConfig.pb", data: Buffer.from("bundle-config") },
				{ name: "base/manifest/AndroidManifest.xml", data: protoManifest },
				{ name: "base/dex/classes.dex", data: dex },
				{ name: "base/lib/arm64-v8a/libbundle.so", data: Buffer.from("so-bytes") },
			]);

			const aabPath = path.join(tempDir, "bundle.aab");
			await fs.writeFile(aabPath, aabBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));

			// 1. info action
			const resInfo = await tool.execute("call-1", { action: "info", path: "bundle.aab" });
			expect(resInfo.details.status).toBe("ok");
			expect(resInfo.details.format).toBe("AAB");
			expect(resInfo.details.info?.container?.manifestPresent).toBe(true);
			expect(resInfo.details.info?.container?.manifestFormat).toBe("compiled_proto");
			expect(resInfo.details.info?.container?.dexFiles.length).toBe(1);
			expect(resInfo.details.info?.container?.nativeLibraries["arm64-v8a"]).toEqual(["libbundle.so"]);

			// 2. manifest action returns structured unsupported without fake values
			const resManifest = await tool.execute("call-2", { action: "manifest", path: "bundle.aab" });
			expect(resManifest.details.status).toBe("unsupported");
			expect(resManifest.details.error).toContain("Protobuf");
			expect(textOf(resManifest)).toContain("[Unsupported]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recognizes Android APK set (.apks) structure in info action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apks-inspect-"));
		try {
			const apksBuffer = buildTestZip([
				{ name: "toc.pb", data: Buffer.from("table-of-contents") },
				{ name: "splits/base-master.apk", data: Buffer.from("dummy-apk-1") },
				{ name: "splits/base-arm64_v8a.apk", data: Buffer.from("dummy-apk-2") },
			]);

			const apksPath = path.join(tempDir, "universal.apks");
			await fs.writeFile(apksPath, apksBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "universal.apks" });

			expect(res.details.status).toBe("ok");
			expect(res.details.format).toBe("APKS");
			expect(textOf(res)).toContain("Format: APKS");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("parseDexBuffer and parseXmlText parser fields", () => {
	it("parses all DEX header offsets correctly", () => {
		const buf = buildTestDex(["Lcom/example/MyClass;"]);
		const parsed = parseDexBuffer(buf);
		expect(parsed).not.toBeNull();
		expect(parsed!.header.stringIdsCount).toBeGreaterThan(0);
		expect(parsed!.header.stringIdsOff).toBe(112);
		expect(parsed!.header.typeIdsCount).toBeGreaterThan(0);
		expect(parsed!.header.typeIdsOff).toBeGreaterThan(112);
		expect(parsed!.header.protoIdsCount).toBe(2);
		expect(parsed!.header.protoIdsOff).toBe(0x100);
		expect(parsed!.header.fieldIdsCount).toBe(3);
		expect(parsed!.header.fieldIdsOff).toBe(0x120);
		expect(parsed!.header.methodIdsCount).toBe(5);
		expect(parsed!.header.methodIdsOff).toBe(0x140);
		expect(parsed!.header.classDefsCount).toBe(1);
		expect(parsed!.header.classDefsOff).toBeGreaterThan(0);
	});

	it("extracts application manifest flags from XML text", () => {
		const xml = `
			<manifest package="com.test.app"
				android:versionCode="12"
				android:versionName="1.2.0">
				<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
				<application
					android:name="com.test.app.MainApplication"
					android:debuggable="true"
					android:allowBackup="false"
					android:extractNativeLibs="false"
					android:useEmbeddedDex="true"
					android:hasCode="true" />
			</manifest>
		`;
		const parsed = parseXmlText(xml);
		expect(parsed).not.toBeNull();
		expect(parsed!.package).toBe("com.test.app");
		expect(parsed!.application.name).toBe("com.test.app.MainApplication");
		expect(parsed!.application.debuggable).toBe(true);
		expect(parsed!.application.allowBackup).toBe(false);
		expect(parsed!.application.extractNativeLibs).toBe(false);
		expect(parsed!.application.useEmbeddedDex).toBe(true);
		expect(parsed!.application.hasCode).toBe(true);
	});
});

describe("calculateEffectiveExported platform rules and edge cases", () => {
	it("honors explicit declared exported values", () => {
		expect(calculateEffectiveExported("activity", true, false, 34).effective).toBe(true);
		expect(calculateEffectiveExported("activity", false, true, 34).effective).toBe(false);
		expect(calculateEffectiveExported("provider", true, false, 34).effective).toBe(true);
		expect(calculateEffectiveExported("provider", false, false, 15).effective).toBe(false);
	});

	it("handles ContentProvider default exported rules across targetSdk < 17 vs >= 17", () => {
		// targetSdk < 17: defaults to true
		const older = calculateEffectiveExported("provider", undefined, false, 15);
		expect(older.effective).toBe(true);
		expect(older.reason).toContain("< 17");

		// targetSdk >= 17 with minSdk >= 17: defaults to false
		const newer = calculateEffectiveExported("provider", undefined, false, 24, false, undefined, 24);
		expect(newer.effective).toBe(false);
		expect(newer.reason).toContain(">= 17");

		// targetSdk >= 17 with minSdk < 17: environment-dependent
		const envDep = calculateEffectiveExported("provider", undefined, false, 24, false, undefined, 14);
		expect(envDep.effective).toBe("unknown");
		expect(envDep.reason).toContain("environment-dependent");

		// Both targetSdk and minSdk omitted: both default to 1 (< 17) -> exported=true
		const absentSdk = calculateEffectiveExported("provider", undefined, false, undefined);
		expect(absentSdk.effective).toBe(true);
		expect(absentSdk.reason).toContain("< 17");

		// targetSdk unresolved reference -> unknown
		const unresolvedTarget = calculateEffectiveExported("provider", undefined, false, "@0x7f050001");
		expect(unresolvedTarget.effective).toBe("unknown");

		// targetSdk >= 17 with unresolved minSdk reference -> unknown
		const unresolvedMin = calculateEffectiveExported(
			"provider",
			undefined,
			false,
			28,
			false,
			undefined,
			"@0x7f010001",
		);
		expect(unresolvedMin.effective).toBe("unknown");
		expect(unresolvedMin.reason).toContain("unresolved minSdkVersion");
	});

	it("handles intent-filter exported rules across targetSdk < 31 vs >= 31", () => {
		// Component without intent-filters: always defaults to false
		expect(calculateEffectiveExported("activity", undefined, false, 34).effective).toBe(false);
		expect(calculateEffectiveExported("service", undefined, false, 28).effective).toBe(false);

		// Component with intent-filters on targetSdk < 31: defaults to true
		const legacyIntent = calculateEffectiveExported("activity", undefined, true, 28);
		expect(legacyIntent.effective).toBe(true);

		// Component with intent-filters on targetSdk >= 31: undeclared causes installation invalid/unknown
		const modernIntent = calculateEffectiveExported("activity", undefined, true, 34);
		expect(modernIntent.effective).toBe("unknown");
		expect(modernIntent.reason).toContain("targetSdkVersion >= 31");

		// Both targetSdk and minSdk omitted: both default to 1 (< 31) -> exported=true
		const absentTargetIntent = calculateEffectiveExported("activity", undefined, true, undefined);
		expect(absentTargetIntent.effective).toBe(true);
		expect(absentTargetIntent.reason).toContain("< 31");

		// Unresolved targetSdk -> unknown
		const unknownTargetIntent = calculateEffectiveExported("activity", undefined, true, "@0x7f050001");
		expect(unknownTargetIntent.effective).toBe("unknown");
	});

	it("flags unresolved resource references as unknown exported", () => {
		const resRef = calculateEffectiveExported("activity", undefined, true, 34, true, "@0x7f050001");
		expect(resRef.effective).toBe("unknown");
		expect(resRef.reason).toContain("Unresolved resource reference");
	});
});

describe("parseXmlText rich manifest features and deep link inventory", () => {
	it("extracts permissions inheritance, alias targets, provider configs, and deep links", () => {
		const manifestXml = `
			<manifest package="com.example.bank"
				android:versionCode="200"
				android:versionName="2.0.0">
				<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33" />
				<uses-permission android:name="android.permission.INTERNET" />
				<permission android:name="com.example.bank.READ_DATA" android:protectionLevel="signature" />
				<application
					android:name="com.example.bank.App"
					android:permission="com.example.bank.DEFAULT_PERM"
					android:usesCleartextTraffic="false"
					android:networkSecurityConfig="@xml/network_security_config">
					<activity
						android:name=".MainActivity"
						android:exported="true">
						<intent-filter android:autoVerify="true">
							<action android:name="android.intent.action.VIEW" />
							<category android:name="android.intent.category.DEFAULT" />
							<category android:name="android.intent.category.BROWSABLE" />
							<data android:scheme="https" android:host="bank.example.com" android:pathPrefix="/account" />
							<data android:scheme="bankapp" android:host="open" />
						</intent-filter>
					</activity>
					<activity-alias
						android:name=".AliasActivity"
						android:targetActivity=".MainActivity"
						android:exported="true" />
					<service
						android:name=".SyncService"
						android:exported="false"
						android:permission="com.example.bank.CUSTOM_SYNC_PERM" />
					<provider
						android:name=".DataProvider"
						android:authorities="com.example.bank.provider"
						android:exported="false"
						android:grantUriPermissions="true"
						android:readPermission="com.example.bank.READ_PROVIDER">
						<path-permission
							android:pathPrefix="/public"
							android:readPermission="android.permission.INTERNET" />
					</provider>
				</application>
			</manifest>
		`;

		const parsed = parseXmlText(manifestXml);
		expect(parsed).not.toBeNull();
		expect(parsed!.package).toBe("com.example.bank");
		expect(parsed!.application.usesCleartextTraffic).toBe(false);
		expect(parsed!.application.networkSecurityConfig).toBe("@xml/network_security_config");

		// Application-level permission inheritance
		expect(parsed!.application.permission).toBe("com.example.bank.DEFAULT_PERM");

		// Activity checks
		const mainAct = parsed!.activities.find(a => a.name === ".MainActivity")!;
		expect(mainAct).toBeDefined();
		expect(mainAct.exported).toBe(true);
		expect(mainAct.effectiveExported).toBe(true);
		expect(mainAct.inheritedPermission).toBe("com.example.bank.DEFAULT_PERM");
		expect(mainAct.effectivePermission).toBe("com.example.bank.DEFAULT_PERM");
		expect(mainAct.intentFilters?.length).toBe(1);
		expect(mainAct.intentFilters![0].autoVerify).toBe(true);

		// Activity-alias targetActivity
		const alias = parsed!.activities.find(a => a.name === ".AliasActivity")!;
		expect(alias).toBeDefined();
		expect(alias.targetActivity).toBe(".MainActivity");

		// Service permission override
		const syncSrv = parsed!.services.find(s => s.name === ".SyncService")!;
		expect(syncSrv).toBeDefined();
		expect(syncSrv.permission).toBe("com.example.bank.CUSTOM_SYNC_PERM");
		expect(syncSrv.effectivePermission).toBe("com.example.bank.CUSTOM_SYNC_PERM");

		// ContentProvider authorities, grantUriPermissions, and readPermission
		const provider = parsed!.providers.find(p => p.name === ".DataProvider")!;
		expect(provider).toBeDefined();
		expect(provider.authorities).toBe("com.example.bank.provider");
		expect(provider.grantUriPermissions).toBe(true);
		expect(provider.readPermission).toBe("com.example.bank.READ_PROVIDER");
		expect(provider.effectiveReadPermission).toBe("com.example.bank.READ_PROVIDER");
		expect(provider.pathPermissions?.length).toBe(1);
		expect(provider.pathPermissions![0].pathPrefix).toBe("/public");

		// Deep Links inventory
		expect(parsed!.deepLinks).toBeDefined();
		expect(parsed!.deepLinks!.length).toBeGreaterThan(0);
		const dl = parsed!.deepLinks![0];
		expect(dl.component).toBe(".MainActivity");
		expect(dl.schemes).toContain("https");
		expect(dl.schemes).toContain("bankapp");
		expect(dl.hosts).toContain("bank.example.com");
		expect(dl.sampleUris).toContain("https://bank.example.com/account");
		expect(dl.autoVerify).toBe(true);
	});
});
describe("calculateEffectiveEnabled tri-state logic", () => {
	it("enforces application false dominance over component true", () => {
		const appFalse = parseBooleanAttr(false);
		const compTrue = parseBooleanAttr(true);
		expect(calculateEffectiveEnabled(compTrue, appFalse)).toBe(false);
	});

	it("enforces component false dominance over application true", () => {
		const appTrue = parseBooleanAttr(true);
		const compFalse = parseBooleanAttr(false);
		expect(calculateEffectiveEnabled(compFalse, appTrue)).toBe(false);
	});

	it("defaults to true when both application and component omit enabled", () => {
		const appOmitted = parseBooleanAttr(undefined);
		const compOmitted = parseBooleanAttr(undefined);
		expect(calculateEffectiveEnabled(compOmitted, appOmitted)).toBe(true);
	});

	it("propagates unknown for unresolved resource references unless overridden by false", () => {
		const appRef = parseBooleanAttr("@bool/app_enabled");
		const compRef = parseBooleanAttr("@0x7f050001");
		const compTrue = parseBooleanAttr(true);
		const compFalse = parseBooleanAttr(false);

		expect(calculateEffectiveEnabled(compTrue, appRef)).toBe("unknown");
		expect(calculateEffectiveEnabled(compRef, parseBooleanAttr(true))).toBe("unknown");
		// Explicit component false still dominates unknown application ref
		expect(calculateEffectiveEnabled(compFalse, appRef)).toBe(false);
	});
});

describe("calculateEffectiveExported provider and targetSdk nuance", () => {
	it("defaults omitted targetSdkVersion to minSdkVersion for ContentProviders", () => {
		// targetSdkVersion omitted, minSdkVersion = 15 (< 17) -> defaults to exported=true
		const older = calculateEffectiveExported("provider", undefined, false, undefined, false, undefined, 15);
		expect(older.effective).toBe(true);
		expect(older.reason).toContain("< 17");

		// targetSdkVersion = 28, minSdkVersion = 14 -> environment-dependent
		const envDep = calculateEffectiveExported("provider", undefined, false, 28, false, undefined, 14);
		expect(envDep.effective).toBe("unknown");
		expect(envDep.reason).toContain("environment-dependent");

		// targetSdkVersion = 28, minSdkVersion = 24 (both >= 17) -> exported=false
		const newer = calculateEffectiveExported("provider", undefined, false, 28, false, undefined, 24);
		expect(newer.effective).toBe(false);
	});

	it("defaults omitted targetSdkVersion to minSdkVersion for activity intent filters", () => {
		// targetSdkVersion omitted, minSdkVersion = 28 (< 31) -> exported=true
		const legacy = calculateEffectiveExported("activity", undefined, true, undefined, false, undefined, 28);
		expect(legacy.effective).toBe(true);

		// Unresolved resource reference targetSdk -> unknown
		const resTarget = calculateEffectiveExported("activity", undefined, true, "@0x7f050001", false, undefined, 24);
		expect(resTarget.effective).toBe("unknown");
	});

	it("respects explicit declared exported=false on legacy ContentProviders", () => {
		// AOSP respects explicit exported=false even on API <= 16
		const explicitFalse = calculateEffectiveExported("provider", false, false, 15);
		expect(explicitFalse.effective).toBe(false);
		expect(explicitFalse.reason).toContain('Explicitly declared exported="false"');
	});
});

describe("permissions, protectionLevel, and alias permission semantics in XML & AXML", () => {
	it("includes uses-permission-sdk-23 and uses-permission-sdk-m in permission inventory", () => {
		const xml = `
			<manifest package="com.test.perm">
				<uses-permission android:name="android.permission.INTERNET" />
				<uses-permission-sdk-23 android:name="android.permission.ACCESS_FINE_LOCATION" />
				<uses-permission-sdk-m android:name="android.permission.RECORD_AUDIO" />
				<application android:name=".App" />
			</manifest>
		`;
		const parsed = parseXmlText(xml);
		expect(parsed).not.toBeNull();
		expect(parsed!.permissions).toContain("android.permission.INTERNET");
		expect(parsed!.permissions).toContain("android.permission.ACCESS_FINE_LOCATION");
		expect(parsed!.permissions).toContain("android.permission.RECORD_AUDIO");
	});

	it("maps numeric protectionLevel 0 to normal without truthiness dropping", () => {
		const xml = `
			<manifest package="com.test.prot">
				<permission android:name="com.test.NORMAL_PERM" android:protectionLevel="0" />
				<permission android:name="com.test.DANGER_PERM" android:protectionLevel="1" />
				<permission android:name="com.test.SIG_PERM" android:protectionLevel="signature" />
				<application android:name=".App" />
			</manifest>
		`;
		const parsed = parseXmlText(xml);
		expect(parsed).not.toBeNull();
		expect(parsed!.declaredPermissions).toBeDefined();
		const norm = parsed!.declaredPermissions!.find(p => p.name === "com.test.NORMAL_PERM");
		expect(norm?.protectionLevel).toBe("normal");
		const danger = parsed!.declaredPermissions!.find(p => p.name === "com.test.DANGER_PERM");
		expect(danger?.protectionLevel).toBe("dangerous");
		const sig = parsed!.declaredPermissions!.find(p => p.name === "com.test.SIG_PERM");
		expect(sig?.protectionLevel).toBe("signature");
	});

	it("preserves explicit empty permission and activity-alias no-permission default", () => {
		const xml = `
			<manifest package="com.test.alias">
				<application android:name=".App" android:permission="com.test.APP_PERM">
					<activity android:name=".ProtectedActivity" />
					<activity android:name=".PublicActivity" android:permission="" />
					<activity-alias
						android:name=".AliasToProtected"
						android:targetActivity=".ProtectedActivity" />
					<activity-alias
						android:name=".ExplicitAlias"
						android:targetActivity=".ProtectedActivity"
						android:permission="com.test.ALIAS_PERM" />
				</application>
			</manifest>
		`;
		const parsed = parseXmlText(xml);
		expect(parsed).not.toBeNull();

		// Default component inherits application permission
		const protectedAct = parsed!.activities.find(a => a.name === ".ProtectedActivity")!;
		expect(protectedAct.effectivePermission).toBe("com.test.APP_PERM");
		expect(protectedAct.inheritedPermission).toBe("com.test.APP_PERM");

		// Explicit empty permission is preserved and NOT overridden by app permission
		const publicAct = parsed!.activities.find(a => a.name === ".PublicActivity")!;
		expect(publicAct.permission).toBe("");
		expect(publicAct.effectivePermission).toBe("");
		expect(publicAct.inheritedPermission).toBeUndefined();

		// activity-alias without permission requires NO permission (supplants target, does not inherit app permission)
		const aliasDefault = parsed!.activities.find(a => a.name === ".AliasToProtected")!;
		expect(aliasDefault.permission).toBeUndefined();
		expect(aliasDefault.effectivePermission).toBeUndefined();
		expect(aliasDefault.inheritedPermission).toBeUndefined();

		// activity-alias with explicit permission uses explicit permission
		const explicitAlias = parsed!.activities.find(a => a.name === ".ExplicitAlias")!;
		expect(explicitAlias.effectivePermission).toBe("com.test.ALIAS_PERM");
	});

	it("decodes numeric XML character references in attributes and text", () => {
		// &#102; = 'f', &#116; = 't'
		const xml = `
			<manifest package="com.test.entities">
				<application android:name=".App" android:debuggable="&#102;alse">
					<activity android:name=".MainActivity" android:exported="&#116;rue" />
				</application>
			</manifest>
		`;
		const parsed = parseXmlText(xml);
		expect(parsed).not.toBeNull();
		expect(parsed!.application.debuggable).toBe(false);
		expect(parsed!.activities[0].exported).toBe(true);
	});
});

describe("AXML package visibility and component scoping", () => {
	it("does not treat queries provider as an application provider in AXML", () => {
		// Build AXML with queries/provider
		const strings = [
			"manifest",
			"package",
			"com.test.queries",
			"queries",
			"provider",
			"authorities",
			"other.package.authority",
			"application",
			"activity",
			"name",
			"com.test.queries.MainActivity",
			"exported",
		];
		const strOffsets: number[] = [];
		const strDataChunks: Buffer[] = [];
		let currentRelOff = 0;
		for (const s of strings) {
			strOffsets.push(currentRelOff);
			const sBuf = Buffer.from(s, "utf8");
			const chunk = Buffer.concat([Buffer.from([sBuf.length]), sBuf, Buffer.from([0])]);
			strDataChunks.push(chunk);
			currentRelOff += chunk.length;
		}
		const poolHeaderSize = 28;
		const poolOffsetsSize = strings.length * 4;
		const stringsStart = poolHeaderSize + poolOffsetsSize;
		const unpaddedPoolSize = stringsStart + currentRelOff;
		const pad = (4 - (unpaddedPoolSize % 4)) % 4;
		const totalPoolSize = unpaddedPoolSize + pad;
		const poolBuf = Buffer.alloc(totalPoolSize);
		poolBuf.writeUInt16LE(0x0001, 0);
		poolBuf.writeUInt16LE(poolHeaderSize, 2);
		poolBuf.writeUInt32LE(totalPoolSize, 4);
		poolBuf.writeUInt32LE(strings.length, 8);
		poolBuf.writeUInt32LE(0x0100, 16);
		poolBuf.writeUInt32LE(stringsStart, 20);
		for (let i = 0; i < strings.length; i++) {
			poolBuf.writeUInt32LE(strOffsets[i], poolHeaderSize + i * 4);
		}
		let p = stringsStart;
		for (const c of strDataChunks) {
			c.copy(poolBuf, p);
			p += c.length;
		}

		const elemChunks: Buffer[] = [];
		// <manifest package="com.test.queries">
		const manElem = Buffer.alloc(36 + 20);
		manElem.writeUInt16LE(0x0102, 0);
		manElem.writeUInt16LE(16, 2);
		manElem.writeUInt32LE(manElem.length, 4);
		manElem.writeUInt32LE(strings.indexOf("manifest"), 20);
		manElem.writeUInt16LE(20, 24);
		manElem.writeUInt16LE(20, 26);
		manElem.writeUInt16LE(1, 28);
		manElem.writeUInt32LE(0xffffffff, 36);
		manElem.writeUInt32LE(strings.indexOf("package"), 36 + 4);
		manElem.writeUInt32LE(strings.indexOf("com.test.queries"), 36 + 8);
		manElem.writeUInt16LE(8, 36 + 12);
		manElem.writeUInt8(0x03, 36 + 15);
		manElem.writeUInt32LE(strings.indexOf("com.test.queries"), 36 + 16);
		elemChunks.push(manElem);

		// <queries><provider authorities="other.package.authority"/></queries>
		const qElem = Buffer.alloc(36);
		qElem.writeUInt16LE(0x0102, 0);
		qElem.writeUInt16LE(16, 2);
		qElem.writeUInt32LE(36, 4);
		qElem.writeUInt32LE(strings.indexOf("queries"), 20);
		elemChunks.push(qElem);

		const qProvElem = Buffer.alloc(36 + 20);
		qProvElem.writeUInt16LE(0x0102, 0);
		qProvElem.writeUInt16LE(16, 2);
		qProvElem.writeUInt32LE(qProvElem.length, 4);
		qProvElem.writeUInt32LE(strings.indexOf("provider"), 20);
		qProvElem.writeUInt16LE(20, 24);
		qProvElem.writeUInt16LE(20, 26);
		qProvElem.writeUInt16LE(1, 28);
		qProvElem.writeUInt32LE(0xffffffff, 36);
		qProvElem.writeUInt32LE(strings.indexOf("authorities"), 36 + 4);
		qProvElem.writeUInt32LE(strings.indexOf("other.package.authority"), 36 + 8);
		qProvElem.writeUInt16LE(8, 36 + 12);
		qProvElem.writeUInt8(0x03, 36 + 15);
		qProvElem.writeUInt32LE(strings.indexOf("other.package.authority"), 36 + 16);
		elemChunks.push(qProvElem);
		elemChunks.push(buildEndElementChunk(strings.indexOf("provider")));
		elemChunks.push(buildEndElementChunk(strings.indexOf("queries")));

		// <application><activity name="com.test.queries.MainActivity" exported="true"/></application>
		const appElem = Buffer.alloc(36);
		appElem.writeUInt16LE(0x0102, 0);
		appElem.writeUInt16LE(16, 2);
		appElem.writeUInt32LE(36, 4);
		appElem.writeUInt32LE(strings.indexOf("application"), 20);
		elemChunks.push(appElem);

		const actElem = Buffer.alloc(36 + 40);
		actElem.writeUInt16LE(0x0102, 0);
		actElem.writeUInt16LE(16, 2);
		actElem.writeUInt32LE(actElem.length, 4);
		actElem.writeUInt32LE(strings.indexOf("activity"), 20);
		actElem.writeUInt16LE(20, 24);
		actElem.writeUInt16LE(20, 26);
		actElem.writeUInt16LE(2, 28);
		actElem.writeUInt32LE(0xffffffff, 36);
		actElem.writeUInt32LE(strings.indexOf("name"), 36 + 4);
		actElem.writeUInt32LE(strings.indexOf("com.test.queries.MainActivity"), 36 + 8);
		actElem.writeUInt16LE(8, 36 + 12);
		actElem.writeUInt8(0x03, 36 + 15);
		actElem.writeUInt32LE(strings.indexOf("com.test.queries.MainActivity"), 36 + 16);
		actElem.writeUInt32LE(0xffffffff, 56);
		actElem.writeUInt32LE(strings.indexOf("exported"), 56 + 4);
		actElem.writeUInt32LE(0xffffffff, 56 + 8);
		actElem.writeUInt16LE(8, 56 + 12);
		actElem.writeUInt8(0x12, 56 + 15);
		actElem.writeUInt32LE(1, 56 + 16);
		elemChunks.push(actElem);
		elemChunks.push(buildEndElementChunk(strings.indexOf("activity")));
		elemChunks.push(buildEndElementChunk(strings.indexOf("application")));
		elemChunks.push(buildEndElementChunk(strings.indexOf("manifest")));

		const all = Buffer.concat(elemChunks);
		const axmlHeader = Buffer.alloc(8);
		axmlHeader.writeUInt16LE(0x0003, 0);
		axmlHeader.writeUInt16LE(8, 2);
		axmlHeader.writeUInt32LE(8 + poolBuf.length + all.length, 4);
		const axmlBuf = Buffer.concat([axmlHeader, poolBuf, all]);

		const parsed = parseAxml(axmlBuf);
		expect(parsed).not.toBeNull();
		expect(parsed!.activities.length).toBe(1);
		expect(parsed!.activities[0].name).toBe("com.test.queries.MainActivity");
		// queries/provider must NOT be classified as an application provider
		expect(parsed!.providers.length).toBe(0);
		expect(parsed!.totalComponents).toBe(1);
	});

	it("safely handles truncated END_ELEMENT chunk without RangeError", () => {
		const baseAxml = buildTestAxml({ packageName: "com.test.trunc" });
		// Craft truncated end element chunk of size 8
		const badEnd = Buffer.alloc(8);
		badEnd.writeUInt16LE(0x0103, 0); // RES_XML_END_ELEMENT_TYPE
		badEnd.writeUInt16LE(8, 2);
		badEnd.writeUInt32LE(8, 4); // declared size 8, but end element requires 24

		const corrupted = Buffer.concat([baseAxml, badEnd]);
		// Update header total size
		corrupted.writeUInt32LE(corrupted.length, 4);

		expect(() => parseAxml(corrupted)).not.toThrow();
		expect(parseAxml(corrupted)).toBeNull();
	});

	it("rejects truncated binary AXML network security config as unresolved", () => {
		const axmlNsc = buildTestNetworkSecurityConfigAxml({ cleartextTrafficPermitted: false });
		const truncated = axmlNsc.subarray(0, axmlNsc.length - 40);
		const zipData = buildTestZip([
			{
				name: "AndroidManifest.xml",
				data: Buffer.from(
					'<manifest package="com.test"><application android:networkSecurityConfig="@xml/nsc"/></manifest>',
				),
			},
			{ name: "res/xml/nsc.xml", data: truncated },
		]);
		const zip = new ZipParser(zipData);
		const res = resolveNetworkSecurityConfig("@xml/nsc", zip);
		expect(res?.unresolvedResourceId).toBeDefined();
		expect(res?.domainConfigs).toBeUndefined();
	});
});

describe("Network Security Config inheritance, overridePins, and AXML parity", () => {
	it("enforces inheritance and override rules in plain XML network security config", () => {
		const nscXml = `
			<network-security-config>
				<base-config cleartextTrafficPermitted="false">
					<trust-anchors>
						<certificates src="system" />
					</trust-anchors>
				</base-config>
				<domain-config cleartextTrafficPermitted="true">
					<domain includeSubdomains="true">example.com</domain>
					<trust-anchors>
						<certificates src="user" />
					</trust-anchors>
					<pin-set expiration="2027-01-01">
						<pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
					</pin-set>
					<domain-config>
						<domain>private.example.com</domain>
						<trust-anchors>
							<certificates src="@raw/private" />
						</trust-anchors>
					</domain-config>
					<domain-config>
						<domain>cdn.example.com</domain>
					</domain-config>
				</domain-config>
				<debug-overrides>
					<trust-anchors>
						<certificates src="user" />
					</trust-anchors>
				</debug-overrides>
			</network-security-config>
		`;

		const zipData = buildTestZip([
			{
				name: "AndroidManifest.xml",
				data: Buffer.from(
					'<manifest package="com.test.nsc"><application android:networkSecurityConfig="@xml/nsc"/></manifest>',
				),
			},
			{ name: "res/xml/nsc.xml", data: Buffer.from(nscXml, "utf8") },
		]);
		const zip = new ZipParser(zipData);
		const resolved = resolveNetworkSecurityConfig("@xml/nsc", zip);

		expect(resolved).toBeDefined();
		expect(resolved!.resolvedFile).toBe("res/xml/nsc.xml");
		expect(resolved!.format).toBe("plain_xml");
		expect(resolved!.cleartextTrafficPermitted).toBe(false);
		expect(resolved!.baseTrustAnchors).toEqual([{ src: "system", overridePins: false }]);

		expect(resolved!.domainConfigs).toBeDefined();
		expect(resolved!.domainConfigs!.length).toBe(3);

		// Outer domain: example.com
		const outer = resolved!.domainConfigs!.find(d => d.domain === "example.com")!;
		expect(outer).toBeDefined();
		expect(outer.includeSubdomains).toBe(true);
		expect(outer.cleartextTrafficPermitted).toBe(true);
		expect(outer.trustAnchors).toEqual([{ src: "user", overridePins: false }]);
		expect(outer.pinSet?.pins[0].digest).toBe("SHA-256");

		// First nested: private.example.com has explicit trust-anchors -> REPLACES ancestor anchors
		const nestedPrivate = resolved!.domainConfigs!.find(d => d.domain === "private.example.com")!;
		expect(nestedPrivate).toBeDefined();
		expect(nestedPrivate.trustAnchors).toEqual([{ src: "@raw/private", overridePins: false }]);
		expect(nestedPrivate.cleartextTrafficPermitted).toBe(true); // inherited from outer
		expect(nestedPrivate.pinSet).toBeDefined(); // inherited from outer

		// Second nested: cdn.example.com absent trust-anchors -> INHERITS user anchors from outer
		const nestedCdn = resolved!.domainConfigs!.find(d => d.domain === "cdn.example.com")!;
		expect(nestedCdn).toBeDefined();
		expect(nestedCdn.trustAnchors).toEqual([{ src: "user", overridePins: false }]);
		expect(nestedCdn.cleartextTrafficPermitted).toBe(true); // inherited from outer

		// Debug overrides: overridePins defaults to true inside debug-overrides
		expect(resolved!.debugOverrides).toBeDefined();
		expect(resolved!.debugOverrides!.trustAnchors).toEqual([{ src: "user", overridePins: true }]);
	});

	it("parses binary AXML Network Security Config with identical semantic structure", () => {
		const axmlNsc = buildTestNetworkSecurityConfigAxml({
			cleartextTrafficPermitted: false,
			baseCertSrc: "system",
			domain: "example.com",
			domainCleartext: true,
			domainCertSrc: "user",
			nestedDomain: "private.example.com",
			nestedCertSrc: "@raw/private",
			siblingDomain: "cdn.example.com",
		});

		const zipData = buildTestZip([
			{
				name: "AndroidManifest.xml",
				data: Buffer.from(
					'<manifest package="com.test.axmlnsc"><application android:networkSecurityConfig="@xml/netsec"/></manifest>',
				),
			},
			{ name: "res/xml/netsec.xml", data: axmlNsc },
		]);
		const zip = new ZipParser(zipData);
		const resolved = resolveNetworkSecurityConfig("@xml/netsec", zip);

		expect(resolved).toBeDefined();
		expect(resolved!.format).toBe("binary_xml");
		expect(resolved!.cleartextTrafficPermitted).toBe(false);
		expect(resolved!.baseTrustAnchors).toEqual([{ src: "system", overridePins: false }]);

		expect(resolved!.domainConfigs).toBeDefined();
		expect(resolved!.domainConfigs!.length).toBe(3);

		const outer = resolved!.domainConfigs!.find(d => d.domain === "example.com")!;
		expect(outer.cleartextTrafficPermitted).toBe(true);
		expect(outer.trustAnchors).toEqual([{ src: "user", overridePins: false }]);

		const nestedPriv = resolved!.domainConfigs!.find(d => d.domain === "private.example.com")!;
		expect(nestedPriv.trustAnchors).toEqual([{ src: "@raw/private", overridePins: false }]);

		const nestedCdn = resolved!.domainConfigs!.find(d => d.domain === "cdn.example.com")!;
		expect(nestedCdn.trustAnchors).toEqual([{ src: "user", overridePins: false }]);

		expect(resolved!.debugOverrides?.trustAnchors).toEqual([{ src: "user", overridePins: true }]);
	});

	it("preserves unresolved numeric resource IDs and rejects entity expansion", () => {
		// Numeric unresolved reference
		const unresolved = resolveNetworkSecurityConfig("@0x7f100001", null);
		expect(unresolved?.unresolvedResourceId).toBe("@0x7f100001");

		// DTD / entity bomb rejection
		const bombXml = `<!DOCTYPE nsc [ <!ENTITY bomb "AAAA"> ]><network-security-config>&bomb;</network-security-config>`;
		const bombZip = new ZipParser(buildTestZip([{ name: "res/xml/nsc.xml", data: Buffer.from(bombXml) }]));
		const bombResolved = resolveNetworkSecurityConfig("@xml/nsc", bombZip);
		expect(bombResolved?.domainConfigs).toBeUndefined();

		// Manifest with DTD is rejected by parseXmlText
		const manifestBomb = `<!DOCTYPE manifest [ <!ENTITY lol "lol"> ]><manifest package="com.test"><application /></manifest>`;
		expect(parseXmlText(manifestBomb)).toBeNull();
	});
});

describe("DeepLink URI authority port and bounding", () => {
	it("includes port in authority for concrete sample URIs", () => {
		const act: AndroidManifestComponent = {
			name: ".PortActivity",
			effectiveExported: true,
			intentFilters: [
				{
					actions: ["android.intent.action.VIEW"],
					categories: ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
					data: [{ scheme: "https", host: "api.example.com", port: "8443", pathPrefix: "/auth" }],
				},
			],
		};
		const links = extractDeepLinks([act]);
		expect(links.length).toBe(1);
		expect(links[0].sampleUris).toContain("https://api.example.com:8443/auth");
	});

	it("synthesizes concrete hostname from wildcard host and bounds sample count", () => {
		const act: AndroidManifestComponent = {
			name: ".WildcardActivity",
			effectiveExported: true,
			intentFilters: [
				{
					actions: ["android.intent.action.VIEW"],
					categories: ["android.intent.category.BROWSABLE"],
					data: [
						{ scheme: "https", host: "*.example.com", pathPrefix: "/item" },
						{ scheme: "custom", host: "item", pathPattern: "/view/.*" },
					],
				},
			],
		};
		const links = extractDeepLinks([act]);
		expect(links.length).toBe(1);
		// Wildcard *.example.com normalized to concrete app.example.com
		expect(links[0].sampleUris).toContain("https://app.example.com/item");
		expect(links[0].pathPatterns).toContainEqual({ type: "pattern", value: "/view/.*" });
		expect(links[0].sampleUris.length).toBeLessThanOrEqual(10);
	});

	it("does not treat activity intent-filter without action as effective filter", () => {
		const comp: AndroidManifestComponent = {
			name: ".NoActionActivity",
			type: "activity",
			intentFilters: [
				{
					actions: [], // Empty actions: AOSP PackageParser discards this filter for activities
					categories: ["android.intent.category.BROWSABLE"],
					data: [{ scheme: "https", host: "example.com" }],
				},
			],
		};
		const links = extractDeepLinks([comp]);
		// Without VIEW action and browsable category with VIEW, deep link is not generated
		expect(links.length).toBe(0);
	});
});

describe("handleManifest model-visible serialization", () => {
	it("renders declared protectionLevels, directional/path permissions, enabled state, and NSC details into content text", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-render-"));
		try {
			const manifestXml = `
				<manifest package="com.test.rendered" android:versionCode="1" android:versionName="1.0">
					<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="34" />
					<uses-permission android:name="android.permission.INTERNET" />
					<permission android:name="com.test.SECURE_ACTION" android:protectionLevel="signature" />
					<application android:name=".App" android:enabled="true" android:networkSecurityConfig="@xml/nsc">
						<activity android:name=".MainActivity" android:exported="true" android:enabled="true" />
						<activity android:name=".DisabledActivity" android:exported="false" android:enabled="false" />
						<activity android:name=".VerifyActivity" android:exported="true">
							<intent-filter android:autoVerify="@bool/autoverify">
								<action android:name="android.intent.action.VIEW" />
								<category android:name="android.intent.category.DEFAULT" />
								<category android:name="android.intent.category.BROWSABLE" />
								<data android:scheme="https" android:host="verify.test.com" />
							</intent-filter>
						</activity>
						<provider
							android:name=".SecProvider"
							android:authorities="com.test.provider"
							android:exported="true"
							android:grantUriPermissions="true"
							android:readPermission="com.test.READ"
							android:writePermission="com.test.WRITE">
							<path-permission android:pathPrefix="/share" android:readPermission="android.permission.INTERNET" />
						</provider>
					</application>
				</manifest>
			`;
			const nscXml = `
				<network-security-config>
					<domain-config cleartextTrafficPermitted="false">
						<domain includeSubdomains="true">api.test.com</domain>
						<trust-anchors><certificates src="user" overridePins="true" /></trust-anchors>
					</domain-config>
				</network-security-config>
			`;

			const apkBuffer = buildTestZip([
				{ name: "AndroidManifest.xml", data: Buffer.from(manifestXml, "utf8") },
				{ name: "res/xml/nsc.xml", data: Buffer.from(nscXml, "utf8") },
			]);
			await fs.writeFile(path.join(tempDir, "test.apk"), apkBuffer);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-render", { action: "manifest", path: "test.apk" });

			expect(res.details.status).toBe("ok");
			const text = textOf(res);

			// Declared permission with protectionLevel visible in model text
			expect(text).toContain("com.test.SECURE_ACTION [protectionLevel: signature]");

			// Provider directional and path permissions visible
			expect(text).toContain("[readPerm: com.test.READ]");
			expect(text).toContain("[writePerm: com.test.WRITE]");
			expect(text).toContain("[grantUri: true]");
			expect(text).toContain("path-permission: prefix:/share (read: android.permission.INTERNET");

			// Component enabled states visible
			expect(text).toContain(".DisabledActivity");
			expect(text).toContain("[enabled: false]");

			// Network Security Config details visible
			expect(text).toContain("Domain Configs");
			expect(text).toContain("api.test.com (includeSubdomains), cleartext: false");
			expect(text).toContain("trustAnchors: [user (overridePins)]");

			// Unresolved autoVerify rendered as unknown in filter and deep link text
			expect(text).toContain("autoVerify: unknown");
			expect(text).toContain("[autoVerify: unknown]");
			expect(text).toContain("scheme=https host=verify.test.com");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
describe("binary AXML parity regression: typed 0 protection, empty permission, and resource boolean", () => {
	it("parses numeric 0 protectionLevel, empty permission string, and resource reference boolean in binary AXML", () => {
		const strings = [
			"manifest",
			"package",
			"com.test.axmlparity",
			"permission",
			"name",
			"com.test.NORMAL_AXML",
			"protectionLevel",
			"application",
			"activity",
			"com.test.axmlparity.MainActivity",
			"exported",
			"permission",
			"",
			"enabled",
		];
		const strOffsets: number[] = [];
		const strDataChunks: Buffer[] = [];
		let currentRelOff = 0;
		for (const s of strings) {
			strOffsets.push(currentRelOff);
			const chunk = encodeAxmlUtf8String(s);
			strDataChunks.push(chunk);
			currentRelOff += chunk.length;
		}
		const poolHeaderSize = 28;
		const poolOffsetsSize = strings.length * 4;
		const stringsStart = poolHeaderSize + poolOffsetsSize;
		const unpaddedPoolSize = stringsStart + currentRelOff;
		const pad = (4 - (unpaddedPoolSize % 4)) % 4;
		const totalPoolSize = unpaddedPoolSize + pad;
		const poolBuf = Buffer.alloc(totalPoolSize);
		poolBuf.writeUInt16LE(0x0001, 0);
		poolBuf.writeUInt16LE(poolHeaderSize, 2);
		poolBuf.writeUInt32LE(totalPoolSize, 4);
		poolBuf.writeUInt32LE(strings.length, 8);
		poolBuf.writeUInt32LE(0x0100, 16);
		poolBuf.writeUInt32LE(stringsStart, 20);
		for (let i = 0; i < strings.length; i++) {
			poolBuf.writeUInt32LE(strOffsets[i], poolHeaderSize + i * 4);
		}
		let p = stringsStart;
		for (const c of strDataChunks) {
			c.copy(poolBuf, p);
			p += c.length;
		}

		const elemChunks: Buffer[] = [];
		// <manifest package="com.test.axmlparity">
		const manElem = Buffer.alloc(36 + 20);
		manElem.writeUInt16LE(0x0102, 0);
		manElem.writeUInt16LE(16, 2);
		manElem.writeUInt32LE(manElem.length, 4);
		manElem.writeUInt32LE(strings.indexOf("manifest"), 20);
		manElem.writeUInt16LE(20, 24);
		manElem.writeUInt16LE(20, 26);
		manElem.writeUInt16LE(1, 28);
		manElem.writeUInt32LE(0xffffffff, 36);
		manElem.writeUInt32LE(strings.indexOf("package"), 36 + 4);
		manElem.writeUInt32LE(strings.indexOf("com.test.axmlparity"), 36 + 8);
		manElem.writeUInt16LE(8, 36 + 12);
		manElem.writeUInt8(0x03, 36 + 15);
		manElem.writeUInt32LE(strings.indexOf("com.test.axmlparity"), 36 + 16);
		elemChunks.push(manElem);

		// <permission name="com.test.NORMAL_AXML" protectionLevel=0> (typed integer 0)
		const permElem = Buffer.alloc(36 + 40);
		permElem.writeUInt16LE(0x0102, 0);
		permElem.writeUInt16LE(16, 2);
		permElem.writeUInt32LE(permElem.length, 4);
		permElem.writeUInt32LE(strings.indexOf("permission"), 20);
		permElem.writeUInt16LE(20, 24);
		permElem.writeUInt16LE(20, 26);
		permElem.writeUInt16LE(2, 28);
		permElem.writeUInt32LE(0xffffffff, 36);
		permElem.writeUInt32LE(strings.indexOf("name"), 36 + 4);
		permElem.writeUInt32LE(strings.indexOf("com.test.NORMAL_AXML"), 36 + 8);
		permElem.writeUInt16LE(8, 36 + 12);
		permElem.writeUInt8(0x03, 36 + 15);
		permElem.writeUInt32LE(strings.indexOf("com.test.NORMAL_AXML"), 36 + 16);
		permElem.writeUInt32LE(0xffffffff, 56);
		permElem.writeUInt32LE(strings.indexOf("protectionLevel"), 56 + 4);
		permElem.writeUInt32LE(0xffffffff, 56 + 8);
		permElem.writeUInt16LE(8, 56 + 12);
		permElem.writeUInt8(0x10, 56 + 15); // TYPE_INT_DEC
		permElem.writeUInt32LE(0, 56 + 16); // numeric 0
		elemChunks.push(permElem);
		elemChunks.push(buildEndElementChunk(strings.indexOf("permission")));

		// <application><activity name="com.test.axmlparity.MainActivity" exported="true" permission="" enabled="@0x7f050001"/></application>
		const appElem = Buffer.alloc(36);
		appElem.writeUInt16LE(0x0102, 0);
		appElem.writeUInt16LE(16, 2);
		appElem.writeUInt32LE(36, 4);
		appElem.writeUInt32LE(strings.indexOf("application"), 20);
		elemChunks.push(appElem);

		const actElem = Buffer.alloc(36 + 80);
		actElem.writeUInt16LE(0x0102, 0);
		actElem.writeUInt16LE(16, 2);
		actElem.writeUInt32LE(actElem.length, 4);
		actElem.writeUInt32LE(strings.indexOf("activity"), 20);
		actElem.writeUInt16LE(20, 24);
		actElem.writeUInt16LE(20, 26);
		actElem.writeUInt16LE(4, 28);
		let curOff = 36;
		actElem.writeUInt32LE(0xffffffff, curOff);
		actElem.writeUInt32LE(strings.indexOf("name"), curOff + 4);
		actElem.writeUInt32LE(strings.indexOf("com.test.axmlparity.MainActivity"), curOff + 8);
		actElem.writeUInt16LE(8, curOff + 12);
		actElem.writeUInt8(0x03, curOff + 15);
		actElem.writeUInt32LE(strings.indexOf("com.test.axmlparity.MainActivity"), curOff + 16);
		curOff += 20;

		actElem.writeUInt32LE(0xffffffff, curOff);
		actElem.writeUInt32LE(strings.indexOf("exported"), curOff + 4);
		actElem.writeUInt32LE(0xffffffff, curOff + 8);
		actElem.writeUInt16LE(8, curOff + 12);
		actElem.writeUInt8(0x12, curOff + 15);
		actElem.writeUInt32LE(1, curOff + 16);
		curOff += 20;

		// explicit empty string permission: ""
		actElem.writeUInt32LE(0xffffffff, curOff);
		actElem.writeUInt32LE(strings.indexOf("permission"), curOff + 4);
		actElem.writeUInt32LE(strings.indexOf(""), curOff + 8);
		actElem.writeUInt16LE(8, curOff + 12);
		actElem.writeUInt8(0x03, curOff + 15);
		actElem.writeUInt32LE(strings.indexOf(""), curOff + 16);
		curOff += 20;

		// TYPE_REFERENCE enabled: @0x7f050001
		actElem.writeUInt32LE(0xffffffff, curOff);
		actElem.writeUInt32LE(strings.indexOf("enabled"), curOff + 4);
		actElem.writeUInt32LE(0xffffffff, curOff + 8);
		actElem.writeUInt16LE(8, curOff + 12);
		actElem.writeUInt8(0x01, curOff + 15); // TYPE_REFERENCE
		actElem.writeUInt32LE(0x7f050001, curOff + 16);

		elemChunks.push(actElem);
		elemChunks.push(buildEndElementChunk(strings.indexOf("activity")));
		elemChunks.push(buildEndElementChunk(strings.indexOf("application")));
		elemChunks.push(buildEndElementChunk(strings.indexOf("manifest")));

		const all = Buffer.concat(elemChunks);
		const axmlHeader = Buffer.alloc(8);
		axmlHeader.writeUInt16LE(0x0003, 0);
		axmlHeader.writeUInt16LE(8, 2);
		axmlHeader.writeUInt32LE(8 + poolBuf.length + all.length, 4);
		const axmlBuf = Buffer.concat([axmlHeader, poolBuf, all]);

		const parsed = parseAxml(axmlBuf);
		expect(parsed).not.toBeNull();

		// Numeric 0 protectionLevel mapped to "normal"
		const perm = parsed!.declaredPermissions?.find(p => p.name === "com.test.NORMAL_AXML");
		expect(perm?.protectionLevel).toBe("normal");

		// Explicit empty permission preserved as ""
		const act = parsed!.activities[0];
		expect(act.permission).toBe("");
		expect(act.effectivePermission).toBe("");

		// TYPE_REFERENCE boolean preserves unknown
		expect(act.enabled).toBe("unknown");
		expect(act.rawEnabled).toBe("@0x7f050001");
	});
});
