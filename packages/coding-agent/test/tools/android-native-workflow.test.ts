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
	importedSymbols?: string[];
	hasJniOnLoad?: boolean;
	hasRegisterNatives?: boolean;
	neededLibs?: string[];
	antiAnalysis?: boolean;
	rawStringsOnly?: boolean;
	useSymtabSection?: boolean;
	customSymbols?: Array<{
		name: string;
		bind?: number; // 0 = LOCAL, 1 = GLOBAL, 2 = WEAK
		type?: number; // 1 = OBJECT, 2 = FUNC, 10 = GNU_IFUNC
		visibility?: number; // 0 = DEFAULT, 2 = HIDDEN, 3 = PROTECTED
		shndx?: number; // 0 = UNDEF, 3 = .text
	}>;
}): Buffer {
	const buf = Buffer.alloc(2048);

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

	const exported = options.exportedSymbols ?? [];
	const imported = options.importedSymbols ?? [];
	const custom = options.customSymbols ?? [];

	if (options.rawStringsOnly || (exported.length === 0 && imported.length === 0 && custom.length === 0)) {
		const stringPool: string[] = [];
		if (options.hasJniOnLoad) stringPool.push("JNI_OnLoad");
		if (options.hasRegisterNatives) stringPool.push("RegisterNatives");
		if (options.exportedSymbols) stringPool.push(...options.exportedSymbols);
		if (options.importedSymbols) stringPool.push(...options.importedSymbols);
		if (options.neededLibs) stringPool.push(...options.neededLibs);
		if (options.antiAnalysis) stringPool.push("ptrace", "TracerPid");
		stringPool.push("AES_encrypt", "SHA256_Update");

		let writeOffset = 128;
		for (const s of stringPool) {
			buf.write(s + "\0", writeOffset, "utf8");
			writeOffset += s.length + 1;
		}
		return buf.subarray(0, 1024);
	}

	// Build string table at offset 64
	let strOff = 64;
	buf[strOff++] = 0; // First byte is null string

	const symOffsets: Array<{
		name: string;
		off: number;
		bind: number;
		type: number;
		visibility: number;
		shndx: number;
	}> = [];
	for (const name of exported) {
		symOffsets.push({ name, off: strOff - 64, bind: 1, type: 2, visibility: 0, shndx: 3 });
		buf.write(name + "\0", strOff, "utf8");
		strOff += name.length + 1;
	}
	for (const name of imported) {
		symOffsets.push({ name, off: strOff - 64, bind: 1, type: 2, visibility: 0, shndx: 0 });
		buf.write(name + "\0", strOff, "utf8");
		strOff += name.length + 1;
	}
	for (const sym of custom) {
		symOffsets.push({
			name: sym.name,
			off: strOff - 64,
			bind: sym.bind ?? 1,
			type: sym.type ?? 2,
			visibility: sym.visibility ?? 0,
			shndx: sym.shndx ?? 3,
		});
		buf.write(sym.name + "\0", strOff, "utf8");
		strOff += sym.name.length + 1;
	}
	if (options.hasJniOnLoad) {
		buf.write("JNI_OnLoad\0", strOff, "utf8");
		strOff += 11;
	}
	if (options.hasRegisterNatives) {
		buf.write("RegisterNatives\0", strOff, "utf8");
		strOff += 16;
	}
	if (options.antiAnalysis) {
		buf.write("ptrace\0TracerPid\0", strOff, "utf8");
		strOff += 17;
	}
	buf.write("AES_encrypt\0SHA256_Update\0", strOff, "utf8");
	strOff += 26;

	const strTabSize = strOff - 64;

	// Align to 8 bytes for symbol table
	const symTabOff = (strOff + 7) & ~7;
	let currSymOff = symTabOff;

	// Entry 0: STN_UNDEF (24 bytes of 0)
	buf.fill(0, currSymOff, currSymOff + 24);
	currSymOff += 24;

	// Symbol entries (Elf64_Sym is 24 bytes)
	for (const sym of symOffsets) {
		buf.writeUInt32LE(sym.off, currSymOff); // st_name
		buf.writeUInt8(((sym.bind & 0x0f) << 4) | (sym.type & 0x0f), currSymOff + 4); // st_info
		buf.writeUInt8(sym.visibility & 0x03, currSymOff + 5); // st_other (visibility)
		buf.writeUInt16LE(sym.shndx, currSymOff + 6); // st_shndx
		buf.writeBigUInt64LE(sym.shndx !== 0 ? 0x1000n : 0n, currSymOff + 8); // st_value
		buf.writeBigUInt64LE(sym.shndx !== 0 ? 0x20n : 0n, currSymOff + 16); // st_size
		currSymOff += 24;
	}
	const symTabSize = currSymOff - symTabOff;

	// Section 3: .text
	const textOff = currSymOff;
	const textSize = 64;
	currSymOff += textSize;

	// Section header table at currSymOff
	const shOff = (currSymOff + 7) & ~7;
	const shEntSize = 64;
	const shNum = 4;

	// Write e_shoff (offset 40), e_shentsize (58), e_shnum (60), e_shstrndx (62)
	buf.writeBigUInt64LE(BigInt(shOff), 40);
	buf.writeUInt16LE(shEntSize, 58);
	buf.writeUInt16LE(shNum, 60);
	buf.writeUInt16LE(1, 62); // .dynstr is section 1

	// Sec 0: SHT_NULL
	buf.fill(0, shOff, shOff + shEntSize);

	// Sec 1: .dynstr (SHT_STRTAB = 3)
	const sec1 = shOff + shEntSize;
	buf.writeUInt32LE(3, sec1 + 4); // sh_type = SHT_STRTAB
	buf.writeBigUInt64LE(BigInt(64), sec1 + 24); // sh_offset
	buf.writeBigUInt64LE(BigInt(strTabSize), sec1 + 32); // sh_size

	// Sec 2: .dynsym (SHT_DYNSYM = 11)
	const sec2 = shOff + 2 * shEntSize;
	buf.writeUInt32LE(options.useSymtabSection ? 2 : 11, sec2 + 4); // sh_type = SHT_DYNSYM (11) or SHT_SYMTAB (2)
	buf.writeBigUInt64LE(BigInt(symTabOff), sec2 + 24); // sh_offset
	buf.writeBigUInt64LE(BigInt(symTabSize), sec2 + 32); // sh_size
	buf.writeUInt32LE(1, sec2 + 40); // sh_link = 1 (.dynstr)
	buf.writeBigUInt64LE(24n, sec2 + 56); // sh_entsize = 24

	// Sec 3: .text (SHT_PROGBITS = 1)
	const sec3 = shOff + 3 * shEntSize;
	buf.writeUInt32LE(1, sec3 + 4); // sh_type = SHT_PROGBITS
	buf.writeBigUInt64LE(BigInt(textOff), sec3 + 24); // sh_offset
	buf.writeBigUInt64LE(BigInt(textSize), sec3 + 32); // sh_size

	return buf.subarray(0, shOff + 4 * shEntSize);
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
			"Java_com_my_1org_crypto_Key_1Store_sign_1token",
		);

		expect(mangleJniSymbol("com.example.App$InnerHelper", "doWork")).toBe(
			"Java_com_example_App_00024InnerHelper_doWork",
		);
	});

	it("handles raw Dalvik descriptors with L and ; wrapper", () => {
		expect(mangleJniSymbol("Lcom/example/NativeCrypto;", "encrypt")).toBe("Java_com_example_NativeCrypto_encrypt");
	});
	it("mangles overloaded method signatures with parameter types", () => {
		expect(mangleJniSymbol("com.example.app.Native", "calculate", "(I)Z")).toBe(
			"Java_com_example_app_Native_calculate__I",
		);
		expect(mangleJniSymbol("com.example.app.Native", "process", "(Ljava/lang/String;[B)V")).toBe(
			"Java_com_example_app_Native_process__Ljava_lang_String_2_3B",
		);
	});

	it("mangles zero-argument signatures with trailing double-underscore suffix", () => {
		expect(mangleJniSymbol("com.example.Native", "sign", "()V")).toBe("Java_com_example_Native_sign__");
	});

	it("escapes non-ASCII Unicode characters in parameters as _0xxxx per JNI spec", () => {
		expect(mangleJniSymbol("com.example.Native", "sign", "(Lcom/example/É;)V")).toBe(
			"Java_com_example_Native_sign__Lcom_example__000c9_2",
		);
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
	it("distinguishes verified exported symbols from imported symbols", () => {
		const elf = createMockElf64Buffer({
			exportedSymbols: ["Java_com_example_Native_exported"],
			importedSymbols: ["Java_com_example_Native_imported"],
			hasJniOnLoad: true,
		});

		const res = parseElfBuffer(elf, "lib/arm64-v8a/libtest.so");
		expect(res.exportedJniFunctions).toContain("Java_com_example_Native_exported");
		expect(res.exportedJniFunctions).not.toContain("Java_com_example_Native_imported");
		expect(res.importedSymbols).toContain("Java_com_example_Native_imported");
	});

	it("does not treat unverified raw string matches as verified exports when symbol table is absent", () => {
		const rawOnlyElf = createMockElf64Buffer({
			exportedSymbols: ["Java_com_example_Native_sign"],
			hasJniOnLoad: true,
			rawStringsOnly: true,
		});

		const res = parseElfBuffer(rawOnlyElf, "lib/arm64-v8a/libmarker.so");
		expect(res.exportedJniFunctions).toHaveLength(0);
		expect(res.hasJniOnLoad).toBe(true);
		expect(res.rawJniCandidates).toContain("Java_com_example_Native_sign");
	});
	it("rejects symbols that fail dynamic export criteria (hidden, local, non-function, or symtab-only)", () => {
		const elf = createMockElf64Buffer({
			customSymbols: [
				// Valid export: STB_GLOBAL, STT_FUNC, STV_DEFAULT, shndx=3
				{ name: "Java_com_example_Valid_export", bind: 1, type: 2, visibility: 0, shndx: 3 },
				// Weak export: STB_WEAK, STT_FUNC, STV_DEFAULT, shndx=3
				{ name: "Java_com_example_Weak_export", bind: 2, type: 2, visibility: 0, shndx: 3 },
				// Hidden visibility: STV_HIDDEN (2) -> not an export
				{ name: "Java_com_example_Hidden_func", bind: 1, type: 2, visibility: 2, shndx: 3 },
				// Local binding: STB_LOCAL (0) -> not an export
				{ name: "Java_com_example_Local_func", bind: 0, type: 2, visibility: 0, shndx: 3 },
				// Non-function: STT_OBJECT (1) -> not an export
				{ name: "Java_com_example_Object_var", bind: 1, type: 1, visibility: 0, shndx: 3 },
				// Imported: shndx = 0 (SHN_UNDEF) -> imported, not export
				{ name: "Java_com_example_Imported_func", bind: 1, type: 2, visibility: 0, shndx: 0 },
			],
		});

		const res = parseElfBuffer(elf, "lib/arm64-v8a/libboundary.so");
		expect(res.exportedJniFunctions).toContain("Java_com_example_Valid_export");
		expect(res.exportedJniFunctions).toContain("Java_com_example_Weak_export");
		expect(res.exportedJniFunctions).not.toContain("Java_com_example_Hidden_func");
		expect(res.exportedJniFunctions).not.toContain("Java_com_example_Local_func");
		expect(res.exportedJniFunctions).not.toContain("Java_com_example_Object_var");
		expect(res.exportedJniFunctions).not.toContain("Java_com_example_Imported_func");
		expect(res.importedSymbols).toContain("Java_com_example_Imported_func");
	});

	it("does not treat regular SHT_SYMTAB symbols as dynamic JNI loader exports", () => {
		const symtabElf = createMockElf64Buffer({
			exportedSymbols: ["Java_com_example_Internal_symtabOnly"],
			useSymtabSection: true, // SHT_SYMTAB (2)
		});

		const res = parseElfBuffer(symtabElf, "lib/arm64-v8a/libdebug.so");
		expect(res.exportedJniFunctions).toHaveLength(0);
	});
});

describe("extractDexNativeMethods", () => {
	it("gracefully returns empty list on empty or truncated DEX", () => {
		const dex = createMockDexBuffer();
		const methods = extractDexNativeMethods(dex);
		expect(methods).toEqual([]);
	});
	it("extracts zero-argument overloaded symbol with trailing __ suffix for valid DEX", () => {
		const nativeDex = Buffer.from(
			"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
			"hex",
		);
		const methods = extractDexNativeMethods(nativeDex);
		expect(methods).toHaveLength(1);
		expect(methods[0].expectedSymbol).toBe("Java_com_example_Native_sign");
		expect(methods[0].overloadedSymbol).toBe("Java_com_example_Native_sign__");
	});

	it("does not create invented overloadedSymbol when DEX prototype has invalid parameter type indices", () => {
		const baseDex = Buffer.from(
			"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
			"hex",
		);
		const corruptDex = Buffer.alloc(256);
		baseDex.copy(corruptDex);
		// Point protoId 0 parameters_off to offset 224
		corruptDex.writeUInt32LE(224, 0x8c);
		// Write 2 parameters: 1st valid type index 1, 2nd invalid type index 9999 (>= typeIdsCount)
		corruptDex.writeUInt32LE(2, 224);
		corruptDex.writeUInt16LE(1, 228);
		corruptDex.writeUInt16LE(9999, 230);
		corruptDex.writeUInt32LE(232, 0x20); // file_size

		const methods = extractDexNativeMethods(corruptDex);
		expect(methods).toHaveLength(1);
		expect(methods[0].expectedSymbol).toBe("Java_com_example_Native_sign");
		// Prototype is incomplete/invalid: signature is marked <invalid> and must not create invented overloadedSymbol
		expect(methods[0].signature).toBe("<invalid>");
		expect(methods[0].overloadedSymbol).toBeUndefined();
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
			const stages = res.details?.plan?.stages ?? [];
			expect(stages).toHaveLength(8);
			expect(stages[0].stage).toBe("unpack");
			expect(stages[0].tool).toBe("android_native_workflow");
			expect(stages[0].status).toBe("ready");

			expect(stages[4].stage).toBe("emulate");
			expect(stages[4].tool).toBe("unidbg");

			expect(stages[5].tool).toBe("ghidra_inspect");
			expect(stages[6].tool).toBe("frida");

			expect(stages[7].stage).toBe("record_evidence");
			expect(stages[7].tool).toBe("evidence");

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
	it("does not attribute unmatched DEX native methods to the first library based on markers alone", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-marker-attribution-"));
		try {
			// Two libraries: both have JNI_OnLoad/RegisterNatives markers, but neither exports the DEX native method
			const libFirst = createMockElf64Buffer({ hasJniOnLoad: true, rawStringsOnly: true });
			const libSecond = createMockElf64Buffer({ hasRegisterNatives: true, rawStringsOnly: true });
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libfirst.so", content: libFirst },
				{ name: "lib/arm64-v8a/libsecond.so", content: libSecond },
				{ name: "classes.dex", content: nativeDex },
			]);

			const apkPath = path.join(tempDir, "markers.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.totalNativeMethods).toBe(1);
			expect(res.details?.summary?.staticExportMatched).toBe(0);
			expect(res.details?.summary?.dynamicRegistrationLikely).toBe(0);
			expect(res.details?.summary?.unresolvedMethods).toBe(1);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("unresolved");
			expect(method?.matchedLibrary).toBeNull();
			expect(method?.candidateLibraries).toContain("libfirst.so");
			expect(method?.candidateLibraries).toContain("libsecond.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("correctly matches verified static export in multi-library APK to the specific exporting library", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-verified-binding-"));
		try {
			// libfirst has only markers, libsecond has verified static export for com.example.Native.sign
			const libFirst = createMockElf64Buffer({ hasJniOnLoad: true, rawStringsOnly: true });
			const libSecond = createMockElf64Buffer({
				exportedSymbols: ["Java_com_example_Native_sign"],
				hasRegisterNatives: true,
			});
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libfirst.so", content: libFirst },
				{ name: "lib/arm64-v8a/libsecond.so", content: libSecond },
				{ name: "classes.dex", content: nativeDex },
			]);

			const apkPath = path.join(tempDir, "verified.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.staticExportMatched).toBe(1);
			expect(res.details?.summary?.unresolvedMethods).toBe(0);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("static_export");
			expect(method?.matchedLibrary).toBe("libsecond.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("uniquely attributes static export across multiple ABIs when library name matches", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-multi-abi-"));
		try {
			// Same library (libcrypto.so) across arm64-v8a and armeabi-v7a exporting the native method
			const lib64 = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_sign"] });
			const lib32 = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_sign"] });
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libcrypto.so", content: lib64 },
				{ name: "lib/armeabi-v7a/libcrypto.so", content: lib32 },
				{ name: "classes.dex", content: nativeDex },
			]);

			const apkPath = path.join(tempDir, "multi-abi.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.staticExportMatched).toBe(1);
			expect(res.details?.summary?.unresolvedMethods).toBe(0);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("static_export");
			expect(method?.matchedLibrary).toBe("libcrypto.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("does not assert ownership when multiple distinct libraries export the same JNI symbol", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-duplicate-export-"));
		try {
			// Two distinct libraries (libalpha.so and libbeta.so) both exporting Java_com_example_Native_sign
			const libAlpha = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_sign"] });
			const libBeta = createMockElf64Buffer({ exportedSymbols: ["Java_com_example_Native_sign"] });
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libalpha.so", content: libAlpha },
				{ name: "lib/arm64-v8a/libbeta.so", content: libBeta },
				{ name: "classes.dex", content: nativeDex },
			]);

			const apkPath = path.join(tempDir, "dup-export.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.staticExportMatched).toBe(0);
			expect(res.details?.summary?.unresolvedMethods).toBe(1);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("unresolved");
			expect(method?.matchedLibrary).toBeNull();
			expect(method?.candidateLibraries).toContain("libalpha.so");
			expect(method?.candidateLibraries).toContain("libbeta.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
	it("matches zero-argument overloaded long symbol (Java_..._sign__) when exported by .so", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-zero-arg-overload-"));
		try {
			// Library exports zero-argument long symbol with __ suffix
			const lib = createMockElf64Buffer({
				exportedSymbols: ["Java_com_example_Native_sign__"],
			});
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libnative.so", content: lib },
				{ name: "classes.dex", content: nativeDex },
			]);

			const apkPath = path.join(tempDir, "zero-arg.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			expect(res.details?.summary?.staticExportMatched).toBe(1);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("static_export");
			expect(method?.matchedLibrary).toBe("libnative.so");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("does not match long symbol when DEX prototype is invalid or corrupted", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-corrupt-proto-"));
		try {
			// Library exports long symbol sign__I
			const lib = createMockElf64Buffer({
				exportedSymbols: ["Java_com_example_Native_sign__I"],
			});
			// DEX has corrupt prototype with parameter 1 invalid
			const baseDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const corruptDex = Buffer.alloc(256);
			baseDex.copy(corruptDex);
			corruptDex.writeUInt32LE(224, 0x8c);
			corruptDex.writeUInt32LE(2, 224);
			corruptDex.writeUInt16LE(1, 228);
			corruptDex.writeUInt16LE(9999, 230);
			corruptDex.writeUInt32LE(232, 0x20);

			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libnative.so", content: lib },
				{ name: "classes.dex", content: corruptDex },
			]);

			const apkPath = path.join(tempDir, "corrupt.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_inspect", { action: "inspect", path: apkPath });

			expect(res.details?.status).toBe("ok");
			// Must not falsely match sign__I
			expect(res.details?.summary?.staticExportMatched).toBe(0);
			expect(res.details?.summary?.unresolvedMethods).toBe(1);

			const method = res.details?.nativeMethods?.[0];
			expect(method?.status).toBe("unresolved");
			expect(method?.matchedLibrary).toBeNull();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
	it("extracts isStatic flag from DEX native method access flags", () => {
		const nativeDexStatic = Buffer.from(
			"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
			"hex",
		);
		const methodsStatic = extractDexNativeMethods(nativeDexStatic);
		expect(methodsStatic).toHaveLength(1);
		expect(methodsStatic[0].isStatic).toBe(true);

		// Change access flags from 0x109 (ACC_NATIVE | ACC_STATIC | ACC_PUBLIC) to 0x101 (clear ACC_STATIC)
		const nativeDexInstance = Buffer.from(nativeDexStatic);
		// byte 0xdf - 2 has 0x89 0x02. 0x101 in ULEB128 is 0x81 0x02
		const flagsOff = nativeDexInstance.length - 3;
		nativeDexInstance[flagsOff] = 0x81;
		nativeDexInstance[flagsOff + 1] = 0x02;

		const methodsInstance = extractDexNativeMethods(nativeDexInstance);
		expect(methodsInstance).toHaveLength(1);
		expect(methodsInstance[0].isStatic).toBe(false);
	});

	it("exposes actionable parameters and routes unresolved registrations to Unidbg probe", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-plan-actionable-"));
		try {
			const elfBuf = createMockElf64Buffer({
				exportedSymbols: [],
				hasJniOnLoad: true,
			});
			const nativeDex = Buffer.from(
				"6465780a30333500000000000000000000000000000000000000000000000000df00000070000000785634120000000000000000000000000300000070000000020000007c000000010000008400000000000000000000000100000090000000010000009800000027000000b8000000b8000000ce000000d4000000000000000200000002000000010000000000000000000000010000000000000001000000ffffffff00000000ffffffff00000000d700000000000000144c636f6d2f6578616d706c652f4e61746976653b00047369676e000156000000010000890200",
				"hex",
			);
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libtarget.so", content: elfBuf },
				{ name: "classes.dex", content: nativeDex },
				{ name: "AndroidManifest.xml", content: Buffer.from('<manifest package="com.example.app"></manifest>') },
			]);

			const apkPath = path.join(tempDir, "unresolved.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_plan", { action: "plan", path: apkPath });

			expect(res.details?.status).toBe("ok");
			const stages = res.details?.plan?.stages ?? [];
			expect(stages).toHaveLength(8);

			// Disassemble stage references LIEF constructors query
			const disasmStep = stages.find(s => s.stage === "disassemble");
			expect(disasmStep?.command_or_action).toContain("elf_inspect");
			expect(disasmStep?.actionable_params?.query_type).toBe("constructors");

			// Emulate stage routes to Unidbg probe with artifact output consumed by JNI enrichment
			const emulateStep = stages.find(s => s.stage === "emulate");
			const enrichStep = stages.find(s => s.step_id === "step_6_jni_enrich");
			expect(emulateStep?.command_or_action).toContain('unidbg(action: "probe"');
			expect(emulateStep?.actionable_params?.callOnLoad).toBe(true);
			expect(emulateStep?.expected_artifacts?.[0]).toBeDefined();
			expect(emulateStep?.actionable_params?.out).toEqual(emulateStep?.expected_artifacts?.[0]);
			expect(enrichStep?.actionable_params?.events_path).toEqual(emulateStep?.actionable_params?.out);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("includes memory dump & SoFixer repair step only when concrete commercial packer payload is detected", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-packed-"));
		try {
			const packedElf = createMockElf64Buffer({
				antiAnalysis: true, // triggers ptrace / TracerPid anti-analysis detection
			});
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libjiagu.so", content: packedElf },
				{ name: "classes.dex", content: createMockDexBuffer() },
				{ name: "AndroidManifest.xml", content: Buffer.from('<manifest package="com.example.packed"></manifest>') },
			]);

			const apkPath = path.join(tempDir, "packed.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_plan", { action: "plan", path: apkPath });

			expect(res.details?.status).toBe("ok");
			const stages = res.details?.plan?.stages ?? [];
			expect(stages).toHaveLength(9);

			const repairStep = stages.find(s => s.stage === "repair");
			expect(repairStep).toBeDefined();
			expect(repairStep?.tool).toBe("elf_inspect");
			expect(repairStep?.status).toBe("blocked");
			expect(repairStep?.command_or_action).toContain("dump_and_repair");
			expect(repairStep?.missing_dependencies).toContain("sofixer");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("does not include memory dump & SoFixer repair step for plain anti-analysis ptrace text", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "anw-ptrace-"));
		try {
			const ptraceElf = createMockElf64Buffer({
				antiAnalysis: true, // triggers ptrace / TracerPid anti-analysis detection
			});
			const apkBuf = createMockZipBuffer([
				{ name: "lib/arm64-v8a/libplain.so", content: ptraceElf },
				{ name: "classes.dex", content: createMockDexBuffer() },
				{ name: "AndroidManifest.xml", content: Buffer.from('<manifest package="com.example.plain"></manifest>') },
			]);

			const apkPath = path.join(tempDir, "plain.apk");
			await fs.writeFile(apkPath, apkBuf);

			const session = createTestSession(tempDir);
			const tool = new AndroidNativeWorkflowTool(session);
			const res = await tool.execute("call_plan", { action: "plan", path: apkPath });

			expect(res.details?.status).toBe("ok");
			const stages = res.details?.plan?.stages ?? [];
			// Plain anti-debug != unpacking, so repair step must NOT be scheduled
			expect(stages).toHaveLength(8);
			expect(stages.find(s => s.stage === "repair")).toBeUndefined();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
