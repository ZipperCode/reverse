import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	AndroidPackageInspectTool,
	type ToolSession,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

// ============================================================================
// Fixture Generators
// ============================================================================

function buildTestDex(
	classNames: string[] = ["Lcom/example/MainActivity;", "Lcom/example/AuthService;"],
): Buffer {
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
	buf.writeUInt32LE(5, 0x58); // methodIdsSize
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

function buildApkSigningBlock(options: {
	v2?: boolean;
	v3?: boolean;
	v31?: boolean;
	sourceStamp?: boolean;
}): Buffer {
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

function buildTestAxml(manifest: {
	packageName: string;
	versionCode?: number;
	versionName?: string;
	minSdkVersion?: number;
	targetSdkVersion?: number;
	permission?: string;
	activityName?: string;
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
	];

	// Build string pool chunk
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

	// <activity name="com.example.app.MainActivity" exported="true">
	const actElem = Buffer.alloc(36 + 2 * 20);
	actElem.writeUInt16LE(0x0102, 0);
	actElem.writeUInt16LE(16, 2);
	actElem.writeUInt32LE(actElem.length, 4);
	actElem.writeUInt32LE(strings.indexOf("activity"), 20);
	actElem.writeUInt16LE(20, 24);
	actElem.writeUInt16LE(20, 26);
	actElem.writeUInt16LE(2, 28);

	const act1 = 36;
	actElem.writeUInt32LE(0xffffffff, act1);
	actElem.writeUInt32LE(strings.indexOf("name"), act1 + 4);
	actElem.writeUInt32LE(strings.indexOf(manifest.activityName ?? "com.example.app.MainActivity"), act1 + 8);
	actElem.writeUInt16LE(8, act1 + 12);
	actElem.writeUInt8(0x03, act1 + 15); // TYPE_STRING
	actElem.writeUInt32LE(strings.indexOf(manifest.activityName ?? "com.example.app.MainActivity"), act1 + 16);

	const act2 = act1 + 20;
	actElem.writeUInt32LE(0xffffffff, act2);
	actElem.writeUInt32LE(strings.indexOf("exported"), act2 + 4);
	actElem.writeUInt32LE(0xffffffff, act2 + 8);
	actElem.writeUInt16LE(8, act2 + 12);
	actElem.writeUInt8(0x12, act2 + 15); // TYPE_INT_BOOLEAN
	actElem.writeUInt32LE(1, act2 + 16); // true

	elemChunks.push(actElem);

	const allElems = Buffer.concat(elemChunks);
	const totalSize = 8 + poolBuf.length + allElems.length;

	const axmlHeader = Buffer.alloc(8);
	axmlHeader.writeUInt16LE(0x0003, 0); // RES_XML_TYPE
	axmlHeader.writeUInt16LE(8, 2); // Header size
	axmlHeader.writeUInt32LE(totalSize, 4); // Total size

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
			const tool = tools.find(t => t.name === "android_package_inspect") as
				| AndroidPackageInspectTool
				| undefined;
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
			await expect(
				tool.execute("call-1", { action: "info", path: "nonexistent.apk" }),
			).rejects.toThrow("Target file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "apk-dir-"));
		try {
			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { action: "info", path: "." })).rejects.toThrow(
				"is a directory",
			);
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
			expect(res.content[0].text).toContain("[Unsupported]");
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
			await fs.writeFile(
				dexPath,
				buildTestDex(["Lcom/example/MainActivity;", "Lcom/example/AuthManager;"]),
			);

			const tool = new AndroidPackageInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "classes.dex" });

			expect(res.details.status).toBe("ok");
			expect(res.details.format).toBe("DEX");
			expect(res.details.info?.bareDex).toBeDefined();
			expect(res.details.info?.bareDex?.header.version).toBe("035");
			expect(res.details.info?.bareDex?.header.classDefsCount).toBe(2);
			expect(res.details.info?.bareDex?.header.endian).toBe("little");
			expect(res.content[0].text).toContain("Bare DEX File");
			expect(res.content[0].text).toContain("com.example.MainActivity");
			expect(res.content[0].text).toContain("com.example.AuthManager");
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
				buildTestDex([
					"Lcom/example/MainActivity;",
					"Lcom/example/AuthManager;",
					"Lcom/example/NetworkClient;",
				]),
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

			expect(res.content[0].text).toContain("arm64-v8a: libnative-crypto.so, libssl.so");
			expect(res.content[0].text).toContain("Scheme v2: Yes");
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

			expect(res.content[0].text).toContain("Package: com.test.demo");
			expect(res.content[0].text).toContain("min: 26, target: 34");
			expect(res.content[0].text).toContain("android.permission.ACCESS_FINE_LOCATION");
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
			expect(res.content[0].text).toContain("classes2.dex");
			expect(res.content[0].text).toContain("com.example.SecondClass");
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

			expect(res.content[0].text).toContain("Scheme v1 (JAR signing): Present");
			expect(res.content[0].text).toContain("Scheme v2 (APK Signature Scheme v2): Present");
			expect(res.content[0].text).toContain("Scheme v3 (APK Signature Scheme v3): Present");
			expect(res.content[0].text).toContain("SourceStamp: Present");
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

			expect(res.content[0].text).toContain("Resource Table (ARSC): Present");
			expect(res.content[0].text).toContain("com.example.myapp");
			expect(res.content[0].text).toContain("res/layout/dialog_auth.xml");
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
			expect(resManifest.content[0].text).toContain("[Unsupported]");
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
			expect(res.content[0].text).toContain("Format: APKS");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
