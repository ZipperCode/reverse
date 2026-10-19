import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { Settings } from "@reverse/coding-agent/config/settings";
import {
	createTools,
	TriageTool,
	type TriageDetails,
	type ToolSession,
	computeEntropy,
	extractPrintableStrings,
} from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string, options: { allocateArtifact?: boolean } = {}): ToolSession {
	const artifactsDir = path.join(cwd, "artifacts");
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		allocateOutputArtifact: options.allocateArtifact
			? async (toolType: string) => {
					await fs.mkdir(artifactsDir, { recursive: true });
					const id = `art-${Date.now()}`;
					return { id, path: path.join(artifactsDir, `${id}.${toolType}.txt`) };
				}
			: undefined,
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}
function detailsOf(result: { details?: TriageDetails }): TriageDetails {
	if (!result.details) throw new Error("Expected details to be defined");
	return result.details;
}

/** Build synthetic minimal PE32+ (64-bit) executable */
function createSyntheticPe(): Buffer {
	const buf = Buffer.alloc(1024, 0);
	// DOS Header
	buf[0] = 0x4d; // 'M'
	buf[1] = 0x5a; // 'Z'
	buf.writeUInt32LE(0x40, 0x3c); // e_lfanew = 0x40

	// PE signature
	buf.write("PE\0\0", 0x40, "ascii");

	// COFF Header (0x44)
	buf.writeUInt16LE(0x8664, 0x44); // Machine = AMD64 (x86_64)
	buf.writeUInt16LE(1, 0x46); // NumberOfSections = 1
	buf.writeUInt32LE(0x60000000, 0x48); // TimeDateStamp
	buf.writeUInt16LE(0xf0, 0x54); // SizeOfOptionalHeader = 240
	buf.writeUInt16LE(0x0022, 0x56); // Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// Optional Header PE32+ (0x58)
	buf.writeUInt16LE(0x020b, 0x58); // Magic = PE32+
	buf.writeUInt32LE(0x1000, 0x58 + 16); // AddressOfEntryPoint = 0x1000
	buf.writeBigUInt64LE(0x0000000140000000n, 0x58 + 24); // ImageBase = 0x140000000
	buf.writeUInt16LE(2, 0x58 + 68); // Subsystem = Windows GUI

	// Section Header (0x58 + 240 = 0x148)
	const sOff = 0x58 + 0xf0;
	buf.write(".text\0\0\0", sOff, "ascii");
	buf.writeUInt32LE(0x100, sOff + 8); // VirtualSize = 0x100
	buf.writeUInt32LE(0x1000, sOff + 12); // VirtualAddress = 0x1000
	buf.writeUInt32LE(0x200, sOff + 16); // SizeOfRawData = 0x200
	buf.writeUInt32LE(0x200, sOff + 20); // PointerToRawData = 0x200
	buf.writeUInt32LE(0x60000020, sOff + 36); // Characteristics = CODE | EXECUTE | READ

	// Raw payload at 0x200
	buf.write("HelloPEExecutablePayloadString!", 0x200, "ascii");
	return buf;
}

/** Build synthetic minimal ELF64 Little-Endian executable */
function createSyntheticElf(): Buffer {
	const buf = Buffer.alloc(512, 0);
	// e_ident
	buf[0] = 0x7f;
	buf[1] = 0x45; // 'E'
	buf[2] = 0x4c; // 'L'
	buf[3] = 0x46; // 'F'
	buf[4] = 2; // ELFCLASS64
	buf[5] = 1; // ELFDATA2LSB (LE)
	buf[6] = 1; // EV_CURRENT
	buf[7] = 0; // ELFOSABI_NONE

	// e_type, e_machine, e_version
	buf.writeUInt16LE(2, 16); // ET_EXEC
	buf.writeUInt16LE(0x3e, 18); // EM_X86_64
	buf.writeUInt32LE(1, 20); // EV_CURRENT

	// e_entry
	buf.writeBigUInt64LE(0x0000000000401000n, 24); // entrypoint = 0x401000

	// e_shoff, e_ehsize, e_shentsize, e_shnum, e_shstrndx
	buf.writeBigUInt64LE(64n, 40); // e_shoff = 64
	buf.writeUInt16LE(64, 52); // e_ehsize = 64
	buf.writeUInt16LE(64, 58); // e_shentsize = 64
	buf.writeUInt16LE(2, 60); // e_shnum = 2
	buf.writeUInt16LE(1, 62); // e_shstrndx = 1

	// Section 0: NULL section (all 0)
	// Section 1: .shstrtab section header at 64 + 64 = 128
	const s1Off = 128;
	buf.writeUInt32LE(1, s1Off); // sh_name = 1 (points to ".shstrtab" at offset 1)
	buf.writeUInt32LE(3, s1Off + 4); // sh_type = SHT_STRTAB
	buf.writeBigUInt64LE(256n, s1Off + 24); // sh_offset = 256
	buf.writeBigUInt64LE(32n, s1Off + 32); // sh_size = 32

	// String table at offset 256: "\0.shstrtab\0.text\0"
	buf.write("\0.shstrtab\0.text\0", 256, "ascii");

	// Some string in file
	buf.write("SyntheticELFStringPayload", 300, "ascii");
	return buf;
}

/** Build synthetic minimal Mach-O 64-bit executable */
function createSyntheticMachO(): Buffer {
	const buf = Buffer.alloc(512, 0);
	buf.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
	buf.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64
	buf.writeUInt32LE(0, 8); // CPU_SUBTYPE
	buf.writeUInt32LE(2, 12); // MH_EXECUTE
	buf.writeUInt32LE(1, 16); // ncmds = 1
	buf.writeUInt32LE(72, 20); // sizeofcmds = 72
	buf.writeUInt32LE(0x00200085, 24); // flags

	// LC_SEGMENT_64 at offset 32
	buf.writeUInt32LE(0x19, 32); // LC_SEGMENT_64
	buf.writeUInt32LE(72, 36); // cmdsize = 72
	buf.write("__TEXT\0\0\0\0\0\0\0\0\0\0", 40, "ascii");
	buf.writeBigUInt64LE(0x100000000n, 56); // vmaddr
	buf.writeBigUInt64LE(0x4000n, 64); // vmsize
	buf.writeBigUInt64LE(0n, 72); // fileoff
	buf.writeBigUInt64LE(512n, 80); // filesize
	buf.writeUInt32LE(0, 88); // maxprot
	buf.writeUInt32LE(0, 92); // initprot
	buf.writeUInt32LE(0, 96); // nsects = 0

	buf.write("AppleMachOExecutablePayload", 200, "ascii");
	return buf;
}

/** Build synthetic Fat (Universal) Mach-O */
function createSyntheticFatMachO(): Buffer {
	const buf = Buffer.alloc(1024, 0);
	// Header: 0xcafebabe, count = 2
	buf.writeUInt32BE(0xcafebabe, 0);
	buf.writeUInt32BE(2, 4);

	// Slice 0: x86_64 at 0x100
	buf.writeUInt32BE(0x01000007, 8); // x86_64
	buf.writeUInt32BE(3, 12); // subtype
	buf.writeUInt32BE(0x100, 16); // offset = 256
	buf.writeUInt32BE(0x100, 20); // size = 256
	buf.writeUInt32BE(2, 24); // align

	// Slice 1: arm64 at 0x200
	buf.writeUInt32BE(0x0100000c, 28); // arm64
	buf.writeUInt32BE(0, 32);
	buf.writeUInt32BE(0x200, 36); // offset = 512
	buf.writeUInt32BE(0x100, 40); // size = 256
	buf.writeUInt32BE(2, 44);

	// Slice 0 header at 0x100
	buf.writeUInt32LE(0xfeedfacf, 0x100);
	buf.writeUInt32LE(0x01000007, 0x104);

	// Slice 1 header at 0x200
	buf.writeUInt32LE(0xfeedfacf, 0x200);
	buf.writeUInt32LE(0x0100000c, 0x204);

	return buf;
}

/** Build synthetic minimal WASM module */
function createSyntheticWasm(): Buffer {
	return Buffer.from([
		0x00,
		0x61,
		0x73,
		0x6d, // \0asm
		0x01,
		0x00,
		0x00,
		0x00, // version 1
		0x01,
		0x04,
		0x01,
		0x60,
		0x00,
		0x00, // Type section (id=1, len=4)
		0x03,
		0x02,
		0x01,
		0x00, // Function section (id=3, len=2)
		0x0a,
		0x04,
		0x01,
		0x02,
		0x00,
		0x0b, // Code section (id=10, len=4)
	]);
}

/** Build synthetic minimal DEX file */
function createSyntheticDex(): Buffer {
	const buf = Buffer.alloc(128, 0);
	buf.write("dex\n035\0", 0, "ascii");
	buf.writeUInt32LE(0x12345678, 0x28); // endian_tag
	buf.writeUInt32LE(128, 0x20); // file_size
	buf.writeUInt32LE(112, 0x24); // header_size
	buf.writeUInt32LE(5, 0x38); // string_ids_size
	buf.writeUInt32LE(3, 0x40); // type_ids_size
	buf.writeUInt32LE(2, 0x48); // proto_ids_size
	buf.writeUInt32LE(4, 0x50); // field_ids_size
	buf.writeUInt32LE(8, 0x58); // method_ids_size
	buf.writeUInt32LE(2, 0x60); // class_defs_size
	return buf;
}

/** Build synthetic Java Class file */
function createSyntheticJavaClass(): Buffer {
	const buf = Buffer.alloc(16, 0);
	buf.writeUInt32BE(0xcafebabe, 0); // magic
	buf.writeUInt16BE(0, 4); // minor_version = 0
	buf.writeUInt16BE(52, 6); // major_version = 52 (Java 8)
	buf.writeUInt16BE(12, 8); // constant_pool_count = 12
	return buf;
}

/** Build synthetic ZIP file containing given file entry */
function createSyntheticZip(entryName: string, content = "file-content"): Buffer {
	const nameBuf = Buffer.from(entryName, "utf8");
	const dataBuf = Buffer.from(content, "utf8");
	const header = Buffer.alloc(30);

	header.write("PK\x03\x04", 0, "ascii");
	header.writeUInt16LE(20, 4); // version needed
	header.writeUInt16LE(0, 6); // flags
	header.writeUInt16LE(0, 8); // compression = 0 (stored)
	header.writeUInt32LE(dataBuf.length, 18); // comp size
	header.writeUInt32LE(dataBuf.length, 22); // uncomp size
	header.writeUInt16LE(nameBuf.length, 26); // name length
	header.writeUInt16LE(0, 28); // extra length

	return Buffer.concat([header, nameBuf, dataBuf]);
}

describe("triage tool registration and canonical naming", () => {
	it("is registered in BUILTIN_TOOL_NAMES", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("triage");
	});

	it("normalizes binary_triage alias to triage", () => {
		expect(normalizeToolName("binary_triage")).toBe("triage");
		expect(normalizeToolName("BINARY_TRIAGE")).toBe("triage");
		expect(normalizeToolName("triage")).toBe("triage");
	});

	it("instantiates via createTools", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["triage"]);
			const tool = tools.find(t => t.name === "triage");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Triage");
			expect(tool?.strict).toBe(true);
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.approval).toBe("read");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("instantiates via binary_triage alias", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-alias-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["binary_triage"]);
			const tool = tools.find(t => t.name === "triage");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("triage");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("triage input validation and error handling", () => {
	it("rejects non-existent target files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-missing-"));
		try {
			const tool = new TriageTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { path: "nonexistent.exe" })).rejects.toThrow("Target not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-dir-"));
		try {
			const subDir = path.join(tempDir, "some-dir");
			await fs.mkdir(subDir);
			const tool = new TriageTool(createTestSession(tempDir));
			await expect(tool.execute("call-2", { path: "some-dir" })).rejects.toThrow(
				"Target is a directory, not a regular file",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects empty or whitespace-only paths", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-empty-path-"));
		try {
			const tool = new TriageTool(createTestSession(tempDir));
			await expect(tool.execute("call-3", { path: "   " })).rejects.toThrow("path or target is required");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles target alias parameter", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-target-alias-"));
		try {
			const filePath = path.join(tempDir, "test.bin");
			await fs.writeFile(filePath, Buffer.from("arbitrary content for alias test"));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-4", { target: "test.bin" });
			const details = detailsOf(res);
			expect(details.status).toBe("ok");
			expect(details.format).toBe("unknown");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles completely empty files without crashing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-zero-byte-"));
		try {
			const filePath = path.join(tempDir, "empty.bin");
			await fs.writeFile(filePath, Buffer.alloc(0));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-5", { path: "empty.bin" });
			const details = detailsOf(res);
			expect(details.size).toBe(0);
			expect(details.format).toBe("empty");
			expect(details.sha256).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
			expect(details.entropy.overall).toBe(0);
			expect(details.indicators).toContain("empty_file");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("triage format recognition and metadata extraction", () => {
	it("inspects Windows PE binaries", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-pe-"));
		try {
			const pePath = path.join(tempDir, "app.exe");
			await fs.writeFile(pePath, createSyntheticPe());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-pe", { path: "app.exe" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("PE");
			expect(details.subformat).toBe("PE32+ (EXE)");
			expect(details.arch).toBe("x86_64");
			expect(details.bits).toBe(64);
			expect(details.endian).toBe("little");
			expect(details.entrypoint).toBe("0x140001000");
			expect(details.sections?.length).toBe(1);
			expect(details.sections?.[0].name).toBe(".text");
			expect(details.sections?.[0].virtualSize).toBe(0x100);
			expect(text).toContain("PE32+ (EXE)");
			expect(text).toContain("0x140001000");
			expect(text).toContain(".text");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Linux ELF binaries", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-elf-"));
		try {
			const elfPath = path.join(tempDir, "binary.elf");
			await fs.writeFile(elfPath, createSyntheticElf());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-elf", { path: "binary.elf" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("ELF");
			expect(details.subformat).toBe("ELF64 (executable)");
			expect(details.arch).toBe("x86_64");
			expect(details.bits).toBe(64);
			expect(details.endian).toBe("little");
			expect(details.entrypoint).toBe("0x401000");
			expect(text).toContain("ELF64 (executable)");
			expect(text).toContain("0x401000");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Apple Mach-O binaries", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-macho-"));
		try {
			const machoPath = path.join(tempDir, "macos_bin");
			await fs.writeFile(machoPath, createSyntheticMachO());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-macho", { path: "macos_bin" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("Mach-O");
			expect(details.arch).toBe("arm64");
			expect(details.bits).toBe(64);
			expect(text).toContain("arm64");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Universal Fat Mach-O binaries", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-fat-"));
		try {
			const fatPath = path.join(tempDir, "universal_bin");
			await fs.writeFile(fatPath, createSyntheticFatMachO());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-fat", { path: "universal_bin" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("Mach-O (fat/universal)");
			expect(details.arch).toContain("x86_64");
			expect(details.arch).toContain("arm64");
			expect(details.indicators).toContain("universal_binary");
			expect(text).toContain("Universal Binary");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects WebAssembly modules and provides wasm_inspect guidance", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-wasm-"));
		try {
			const wasmPath = path.join(tempDir, "module.wasm");
			await fs.writeFile(wasmPath, createSyntheticWasm());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-wasm", { path: "module.wasm" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("WASM");
			expect(details.arch).toBe("wasm32");
			expect(details.sections?.some(s => s.name === "type")).toBe(true);
			expect(details.hints?.some(h => h.includes("wasm_inspect"))).toBe(true);
			expect(text).toContain("wasm_inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Android APK packages and suggests droidasc", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-apk-"));
		try {
			const apkPath = path.join(tempDir, "sample.apk");
			await fs.writeFile(apkPath, createSyntheticZip("AndroidManifest.xml", "<manifest></manifest>"));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-apk", { path: "sample.apk" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("APK");
			expect(details.indicators).toContain("android_apk");
			expect(details.hints?.some(h => h.includes("droidasc"))).toBe(true);
			expect(text).toContain("droidasc");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Android DEX files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-dex-"));
		try {
			const dexPath = path.join(tempDir, "classes.dex");
			await fs.writeFile(dexPath, createSyntheticDex());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-dex", { path: "classes.dex" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("DEX");
			expect(details.arch).toBe("Dalvik / ART VM");
			expect(details.sections?.some(s => s.name === "classes" && s.size === 2)).toBe(true);
			expect(details.sections?.some(s => s.name === "methods" && s.size === 8)).toBe(true);
			expect(text).toContain("Dalvik");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects Java Class files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-class-"));
		try {
			const classPath = path.join(tempDir, "Example.class");
			await fs.writeFile(classPath, createSyntheticJavaClass());
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-class", { path: "Example.class" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("Java Class");
			expect(details.arch).toBe("JVM Bytecode");
			expect(details.subformat).toContain("Java 8");
			expect(text).toContain("Java Class");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("inspects generic ZIP archives", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-zip-"));
		try {
			const zipPath = path.join(tempDir, "bundle.zip");
			await fs.writeFile(zipPath, createSyntheticZip("readme.txt", "Hello World"));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-zip", { path: "bundle.zip" });
			const text = textOf(res);
			const details = detailsOf(res);

			expect(details.format).toBe("ZIP");
			expect(details.sections?.some(s => s.name === "readme.txt")).toBe(true);
			expect(text).toContain("readme.txt");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("triage corrupt and malformed input handling", () => {
	it("returns structured corrupt status on truncated DOS header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-pe-"));
		try {
			const filePath = path.join(tempDir, "bad_dos.exe");
			// "MZ" followed by only 10 bytes (header must be at least 64 bytes)
			await fs.writeFile(filePath, Buffer.from("MZ1234567890"));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-pe", { path: "bad_dos.exe" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("corrupted");
			expect(details.indicators).toContain("truncated_dos_header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured corrupt status on truncated ELF ident", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-elf-"));
		try {
			const filePath = path.join(tempDir, "bad.elf");
			// "\x7fELF" followed by 4 bytes (ident is 16 bytes)
			await fs.writeFile(filePath, Buffer.from("\x7fELF1234"));
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-elf", { path: "bad.elf" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("truncated");
			expect(details.indicators).toContain("truncated_elf_ident");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured corrupt status on truncated Mach-O header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-macho-"));
		try {
			const filePath = path.join(tempDir, "bad.macho");
			const buf = Buffer.alloc(10);
			buf.writeUInt32LE(0xfeedfacf, 0);
			await fs.writeFile(filePath, buf);
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-macho", { path: "bad.macho" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("truncated");
			expect(details.indicators).toContain("truncated_macho_header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured corrupt status on truncated WASM header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-wasm-"));
		try {
			const filePath = path.join(tempDir, "bad.wasm");
			await fs.writeFile(filePath, Buffer.from("\0asm12")); // 6 bytes (needs 8)
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-wasm", { path: "bad.wasm" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("truncated");
			expect(details.indicators).toContain("truncated_wasm_header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured corrupt status on truncated DEX header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-dex-"));
		try {
			const filePath = path.join(tempDir, "bad.dex");
			await fs.writeFile(filePath, Buffer.from("dex\n035\0short")); // less than 112 bytes
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-dex", { path: "bad.dex" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("truncated");
			expect(details.indicators).toContain("truncated_dex_header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured corrupt status on truncated Java Class header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-trunc-class-"));
		try {
			const filePath = path.join(tempDir, "bad.class");
			await fs.writeFile(filePath, Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00])); // 6 bytes (needs 8)
			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-bad-class", { path: "bad.class" });
			const details = detailsOf(res);

			expect(details.status).toBe("corrupt");
			expect(details.format).toContain("truncated");
			expect(details.indicators).toContain("truncated_class_header");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("triage hash calculation and entropy analysis", () => {
	it("computes accurate SHA-256 matching node:crypto", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-hash-"));
		try {
			const content = Buffer.from("Verification Payload For SHA-256 Hashing");
			const expectedHash = createHash("sha256").update(content).digest("hex");
			const filePath = path.join(tempDir, "test.bin");
			await fs.writeFile(filePath, content);

			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-hash", { path: "test.bin" });
			const details = detailsOf(res);

			expect(details.sha256).toBe(expectedHash);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("computes Shannon entropy and reports high entropy indicator", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-entropy-"));
		try {
			// Zero bytes has 0.0 entropy
			const zeroBuf = Buffer.alloc(1024, 0);
			expect(computeEntropy(zeroBuf)).toBe(0);

			// Random high-entropy buffer (pseudo-random / uniform)
			const randomBuf = Buffer.alloc(2048);
			for (let i = 0; i < randomBuf.length; i++) {
				randomBuf[i] = i % 256;
			}
			const ent = computeEntropy(randomBuf);
			expect(ent).toBe(8); // uniform 256 bytes = exactly 8.0 bits/byte

			const randomPath = path.join(tempDir, "random.bin");
			await fs.writeFile(randomPath, randomBuf);

			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-entropy", { path: "random.bin" });
			const details = detailsOf(res);

			expect(details.entropy.overall).toBe(8);
			expect(details.entropy.highEntropy).toBe(true);
			expect(details.indicators).toContain("high_entropy");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("triage strings extraction and output boundaries", () => {
	it("extracts printable ASCII and UTF-16LE strings", () => {
		const buf = Buffer.alloc(256, 0);
		buf.write("ASCIIStringRun1", 10, "ascii");
		buf.write("Short", 50, "ascii"); // 5 chars
		// Write UTF-16LE string "WideTextSample" (14 chars)
		const wideText = "WideTextSample";
		for (let i = 0; i < wideText.length; i++) {
			buf[100 + i * 2] = wideText.charCodeAt(i);
			buf[100 + i * 2 + 1] = 0x00;
		}

		const { strings, totalStrings } = extractPrintableStrings(buf, 6, 50);
		expect(totalStrings).toBe(2); // "ASCIIStringRun1" and "WideTextSample" (Short is 5 chars < 6)
		expect(strings.some(s => s.text === "ASCIIStringRun1" && s.encoding === "ascii")).toBe(true);
		expect(strings.some(s => s.text === "WideTextSample" && s.encoding === "utf-16le")).toBe(true);
	});

	it("respects limit and min_length parameters during execute", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-strings-limits-"));
		try {
			const buf = Buffer.alloc(1024, 0);
			// Write 20 strings of length 10
			for (let i = 0; i < 20; i++) {
				buf.write(`String_${i.toString().padStart(3, "0")}_X`, i * 30, "ascii");
			}
			const filePath = path.join(tempDir, "strings.bin");
			await fs.writeFile(filePath, buf);

			const tool = new TriageTool(createTestSession(tempDir));
			const res = await tool.execute("call-str", {
				path: "strings.bin",
				strings: true,
				limit: 5,
				min_length: 8,
			});
			const details = detailsOf(res);
			expect(details.strings?.length).toBe(5);
			expect(details.totalStrings).toBe(20);
			expect(details.stringsTruncated).toBe(true);

			const text = textOf(res);
			expect(text).toContain("Strings (5 shown of 20, min length 8)");
			expect(text).toContain("15 more strings; raise limit");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("allocates session artifact when strings exceed limit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "triage-artifact-"));
		try {
			const buf = Buffer.alloc(1024, 0);
			for (let i = 0; i < 15; i++) {
				buf.write(`ArtifactStringItem_${i}`, i * 35, "ascii");
			}
			const filePath = path.join(tempDir, "spill.bin");
			await fs.writeFile(filePath, buf);

			const session = createTestSession(tempDir, { allocateArtifact: true });
			const tool = new TriageTool(session);
			const res = await tool.execute("call-spill", {
				path: "spill.bin",
				strings: true,
				limit: 5,
			});

			const details = detailsOf(res);
			expect(details.artifactId).toBeDefined();
			expect(details.stringsTruncated).toBe(true);

			const text = textOf(res);
			expect(text).toContain(`[raw strings: artifact://${details.artifactId}]`);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
