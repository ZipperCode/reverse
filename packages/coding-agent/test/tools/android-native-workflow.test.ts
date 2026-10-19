import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { ToolSession } from "@reverse/coding-agent/tools";
import {
	AndroidNativeWorkflowTool,
	mangleJniSymbol,
	parseElfBuffer,
	extractDexNativeMethods,
} from "../../src/tools/android-native-workflow";

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

/**
 * Creates a minimal valid 64-bit ELF shared object with dynamic symbols
 */
function createMockElf64Buffer(options: {
	exportedSymbols?: string[];
	hasJniOnLoad?: boolean;
	hasRegisterNatives?: boolean;
	neededLibs?: string[];
	antiAnalysis?: boolean;
}): Buffer {
	const buf = Buffer.alloc(1024);

	// ELF Magic: \x7fELF
	buf[0] = 0x7f;
	buf[1] = 0x45;
	buf[2] = 0x4c;
	buf[3] = 0x46;
	buf[4] = 2; // 64-bit (ELFCLASS64)
	buf[5] = 1; // Little endian (ELFDATA2LSB)
	buf[6] = 1; // EV_CURRENT

	// e_type = ET_DYN (3)
	buf.writeUInt16LE(3, 16);
	// e_machine = AArch64 (183 = 0xb7)
	buf.writeUInt16LE(183, 18);
	// e_version = 1
	buf.writeUInt32LE(1, 20);

	// Embed raw strings for fallback scanner and simulated symbol table
	const stringPool: string[] = [];
	if (options.hasJniOnLoad) stringPool.push("JNI_OnLoad");
	if (options.hasRegisterNatives) stringPool.push("RegisterNatives");
	if (options.exportedSymbols) stringPool.push(...options.exportedSymbols);
	if (options.neededLibs) stringPool.push(...options.neededLibs);
	if (options.antiAnalysis) stringPool.push("ptrace", "TracerPid");
	stringPool.push("AES_encrypt", "SHA256_Update");

	let writeOffset = 128;
	for (const s of stringPool) {
		buf.write(s + "\0", writeOffset, "utf8");
		writeOffset += s.length + 1;
	}

	return buf;
}

/**
 * Creates a minimal valid ZIP file containing specified files
 */
function createMockZipBuffer(files: Array<{ name: string; content: Buffer }>): Buffer {
	const localHeaders: Buffer[] = [];
	const cdEntries: Buffer[] = [];
	let offset = 0;

	for (const f of files) {
		const nameBuf = Buffer.from(f.name, "utf8");
		const compData = zlib.deflateRawSync(f.content);

		// Local file header (30 bytes + name)
		const lh = Buffer.alloc(30 + nameBuf.length);
		lh.writeUInt32LE(0x04034b50, 0); // signature
		lh.writeUInt16LE(20, 4); // version needed
		lh.writeUInt16LE(0, 6); // flags
		lh.writeUInt16LE(8, 8); // compression = deflate
		lh.writeUInt16LE(0, 10); // time
		lh.writeUInt16LE(0, 12); // date
		lh.writeUInt32LE(0, 14); // crc32
		lh.writeUInt32LE(compData.length, 18); // compSize
		lh.writeUInt32LE(f.content.length, 22); // uncompSize
		lh.writeUInt16LE(nameBuf.length, 26); // nameLen
		lh.writeUInt16LE(0, 28); // extraLen
		nameBuf.copy(lh, 30);

		localHeaders.push(lh, compData);

		// Central directory entry (46 bytes + name)
		const cd = Buffer.alloc(46 + nameBuf.length);
		cd.writeUInt32LE(0x02014b50, 0); // signature
		cd.writeUInt16LE(20, 4); // version made by
		cd.writeUInt16LE(20, 6); // version needed
		cd.writeUInt16LE(0, 8); // flags
		cd.writeUInt16LE(8, 10); // compression = deflate
		cd.writeUInt16LE(0, 12); // time
		cd.writeUInt16LE(0, 14); // date
		cd.writeUInt32LE(0, 16); // crc32
		cd.writeUInt32LE(compData.length, 20); // compSize
		cd.writeUInt32LE(f.content.length, 24); // uncompSize
		cd.writeUInt16LE(nameBuf.length, 28); // nameLen
		cd.writeUInt16LE(0, 30); // extraLen
		cd.writeUInt16LE(0, 32); // commentLen
		cd.writeUInt16LE(0, 34); // diskStart
		cd.writeUInt16LE(0, 36); // intAttr
		cd.writeUInt32LE(0, 38); // extAttr
		cd.writeUInt32LE(offset, 42); // localHeaderOffset
		nameBuf.copy(cd, 46);

		cdEntries.push(cd);
		offset += lh.length + compData.length;
	}

	const cdStart = offset;
	let cdSize = 0;
	for (const cd of cdEntries) cdSize += cd.length;

	// EOCD (22 bytes)
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(0x06054b50, 0);
	eocd.writeUInt16LE(0, 4); // diskNum
	eocd.writeUInt16LE(0, 6); // cdDisk
	eocd.writeUInt16LE(files.length, 8); // cdEntriesDisk
	eocd.writeUInt16LE(files.length, 10); // cdEntriesTotal
	eocd.writeUInt32LE(cdSize, 12); // cdSize
	eocd.writeUInt32LE(cdStart, 16); // cdOffset
	eocd.writeUInt16LE(0, 20); // commentLen

	return Buffer.concat([...localHeaders, ...cdEntries, eocd]);
}

/**
 * Creates a minimal valid DEX buffer
 */
function createMockDexBuffer(): Buffer {
	const buf = Buffer.alloc(256);
	// DEX Magic: dex\n035\0
	buf.write("dex\n035\0", 0, 8, "ascii");
	buf.writeUInt32LE(0x12345678, 40); // Endian tag
	buf.writeUInt32LE(256, 32); // fileSize
	buf.writeUInt32LE(112, 36); // headerSize
	buf.writeUInt32LE(0, 56); // stringIdsSize
	buf.writeUInt32LE(112, 60); // stringIdsOff
	buf.writeUInt32LE(0, 96); // classDefsSize
	buf.writeUInt32LE(112, 100); // classDefsOff
	return buf;
}

describe("mangleJniSymbol", () => {
	it("mangles standard Java class and method names per JNI spec", () => {
		expect(mangleJniSymbol("com.example.app.SecurityUtil", "verifySignature")).toBe(
			"Java_com_example_app_SecurityUtil_verifySignature",
		);
	});

	it("escapes underscores and dollar signs properly", () => {
		expect(mangleJniSymbol("com.my_org.crypto.Key_Store", "sign_token")).toBe(
			"Java_com_1my_1org_crypto_Key_1Store_sign_1token",
		);

		expect(mangleJniSymbol("com.example.App$InnerHelper", "doWork")).toBe(
			"Java_com_example_App_00024InnerHelper_doWork",
		);
	});

	it("handles raw Dalvik descriptors with L and ; wrapper", () => {
		expect(mangleJniSymbol("Lcom/example/NativeCrypto;", "encrypt")).toBe("Java_com_example_NativeCrypto_encrypt");
	});
});

describe("parseElfBuffer", () => {
	it("parses ELF machine architecture, endian, and JNI symbols", () => {
		const elf = createMockElf64Buffer({
			exportedSymbols: ["Java_com_example_app_Security_sign", "Java_com_example_app_Security_decrypt"],
			hasJniOnLoad: true,
			hasRegisterNatives: true,
			neededLibs: ["liblog.so", "libc.so"],
			antiAnalysis: true,
		});

		const res = parseElfBuffer(elf, "lib/arm64-v8a/libnative-crypto.so", 512);
		expect(res.name).toBe("libnative-crypto.so");
		expect(res.abi).toBe("arm64-v8a");
		expect(res.architecture).toBe("AArch64");
		expect(res.bitness).toBe(64);
		expect(res.endian).toBe("little");
		expect(res.hasJniOnLoad).toBe(true);
		expect(res.hasRegisterNatives).toBe(true);
		expect(res.exportedJniFunctions).toContain("Java_com_example_app_Security_sign");
		expect(res.exportedJniFunctions).toContain("Java_com_example_app_Security_decrypt");
		expect(res.antiAnalysisKeywords).toContain("ptrace");
		expect(res.antiAnalysisKeywords).toContain("tracerpid");
		expect(res.cryptoKeywords).toContain("aes");
		expect(res.cryptoKeywords).toContain("sha256");
	});

	it("handles non-ELF buffers without throwing", () => {
		const nonElf = Buffer.from("NOT_AN_ELF_BUFFER_DATA");
		const res = parseElfBuffer(nonElf, "lib/armeabi-v7a/dummy.so");
		expect(res.architecture).toBe("Unknown");
		expect(res.exportedJniFunctions).toHaveLength(0);
		expect(res.hasJniOnLoad).toBe(false);
	});
});

describe("extractDexNativeMethods", () => {
	it("gracefully returns empty list on empty or truncated DEX", () => {
		const dex = createMockDexBuffer();
		const methods = extractDexNativeMethods(dex);
		expect(methods).toEqual([]);
	});
});

describe("AndroidNativeWorkflowTool", () => {
	it("executes status action reporting companion tool readiness", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-status-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session, {
				which: cmd => (cmd === "java" ? "/usr/bin/java" : null),
			});

			const res = await tool.execute("call_status", { action: "status" });
			expect(res.details?.status).toBe("ok");
			expect(res.details?.action).toBe("status");
			expect(res.details?.tools).toBeDefined();

			const unidbg = res.details?.tools?.find(t => t.id === "unidbg");
			expect(unidbg).toBeDefined();
			expect(unidbg?.workflowRole).toContain("ARM32/ARM64");

			const bundletool = res.details?.tools?.find(t => t.id === "bundletool");
			expect(bundletool).toBeDefined();

			const javaTool = res.details?.tools?.find(t => t.id === "java");
			expect(javaTool?.installed).toBe(true);

			expect(res.details?.readiness?.staticInspect).toBe(true);
			expect(res.details?.readiness?.unpack).toBe(true);

			const text = textOf(res);
			expect(text).toContain("Android Reverse Companion Toolchain Status");
			expect(text).toContain("Workflow Capability Readiness");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("generates deterministic 6-stage reverse engineering plan", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-plan-"));
		try {
			const elfBuf = createMockElf64Buffer({
				exportedSymbols: ["Java_com_example_app_Native_sign"],
				hasJniOnLoad: true,
			});
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libcrypto.so", content: elfBuf },
				{ name: "classes.dex", content: createMockDexBuffer() },
				{ name: "AndroidManifest.xml", content: Buffer.from('<manifest package="com.example.app"></manifest>') },
			]);

			const apkPath = path.join(tempDir, "test.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", path: apkPath });
			expect(res.details?.status).toBe("ok");
			expect(res.details?.plan?.stages).toHaveLength(6);

			const stages = res.details?.plan?.stages ?? [];
			expect(stages[0].stage).toBe("unpack");
			expect(stages[0].tool).toBe("android_native_workflow");
			expect(stages[0].status).toBe("ready");

			expect(stages[4].stage).toBe("emulate");
			expect(stages[4].tool).toBe("unidbg");

			expect(stages[5].stage).toBe("record_evidence");
			expect(stages[5].tool).toBe("evidence");

			const text = textOf(res);
			expect(text).toContain("Android Native Reverse Engineering Plan");
			expect(text).toContain("Plan Execution Recommendations");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("extracts native .so shared libraries safely to artifacts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-extract-"));
		try {
			const elf64 = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_calc"] });
			const elf32 = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_calc"] });
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libnative.so", content: elf64 },
				{ name: "lib/armeabi-v7a/libnative.so", content: elf32 },
				{ name: "AndroidManifest.xml", content: Buffer.from("<manifest></manifest>") },
			]);

			const apkPath = path.join(tempDir, "sample.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);

			const outDir = path.join(tempDir, "artifacts", "extracted_so");
			const res = await tool.execute("call_extract", {
				action: "extract",
				path: apkPath,
				abi: "arm64-v8a",
				output_dir: outDir,
			});

			expect(res.details?.status).toBe("ok");
			expect(res.details?.extractedFiles).toBeDefined();
			expect(res.details?.extractedFiles?.length).toBeGreaterThanOrEqual(1);

			const extractedLib = path.join(outDir, "lib", "arm64-v8a", "libnative.so");
			const exists = await fs
				.stat(extractedLib)
				.then(() => true)
				.catch(() => false);
			expect(exists).toBe(true);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("inspects APK native libraries, symbols, and anti-analysis markers", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-inspect-"));
		try {
			const elfBuf = createMockElf64Buffer({
				exportedSymbols: ["Java_com_example_app_Token_generate"],
				hasJniOnLoad: true,
				antiAnalysis: true,
			});
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libjiagu.so", content: elfBuf },
				{ name: "classes.dex", content: createMockDexBuffer() },
				{
					name: "AndroidManifest.xml",
					content: Buffer.from('<manifest package="com.example.protected"></manifest>'),
				},
			]);

			const apkPath = path.join(tempDir, "protected.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);

			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });
			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.totalLibraries).toBe(1);
			expect(res.details?.summary?.abis).toContain("arm64-v8a");
			expect(res.details?.antiAnalysis?.some(a => a.includes("Jiagu"))).toBe(true);

			const text = textOf(res);
			expect(text).toContain("Android Native SO & JNI Inspection Report");
			expect(text).toContain("Anti-Analysis & Packer Indicators");
			expect(text).toContain("libjiagu.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("outputs structured JSON when format='json' is requested", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-json-"));
		try {
			const elfBuf = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Auth_login"] });
			const apkBuf = createMockZipBuffer([{ name: "lib/arm64-v8a/libauth.so", content: elfBuf }]);

			const apkPath = path.join(tempDir, "auth.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);

			const res = await tool.execute("call_json", { action: "inspect", path: apkPath, format: "json" });
			expect(res.details?.status).toBe("ok");
			const parsed = JSON.parse(textOf(res) || "{}");
			expect(parsed.summary?.totalLibraries).toBe(1);
			expect(parsed.libraries?.[0]?.name).toBe("libauth.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("parses AndroidManifest flags (extractNativeLibs, useEmbeddedDex, hasCode, debuggable)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-manifest-"));
		try {
			const manifestXml = `
				<manifest package="com.example.flags"
					xmlns:android="http://schemas.android.com/apk/res/android"
					android:versionCode="42"
					android:versionName="1.0.0">
					<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
					<application
						android:name="com.example.flags.App"
						android:debuggable="true"
						android:allowBackup="false"
						android:extractNativeLibs="true"
						android:useEmbeddedDex="true"
						android:hasCode="true" />
				</manifest>
			`;
			const apkBuf = createMockZipBuffer([
				{ name: "AndroidManifest.xml", content: Buffer.from(manifestXml, "utf8") },
			]);
			const apkPath = path.join(tempDir, "flags.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_flags", { action: "inspect", path: apkPath, format: "json" });
			expect(res.details?.status).toBe("ok");
			expect(res.details?.manifest?.package).toBe("com.example.flags");
			expect(res.details?.manifest?.extractNativeLibs).toBe(true);
			expect(res.details?.manifest?.useEmbeddedDex).toBe(true);
			expect(res.details?.manifest?.hasCode).toBe(true);
			expect(res.details?.manifest?.debuggable).toBe(true);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
