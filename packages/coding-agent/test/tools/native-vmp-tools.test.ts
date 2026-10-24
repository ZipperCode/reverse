import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import {
	parseAddress,
	parseAndValidatePe64,
	safePublishArtifact,
	validateLlvmIr,
	validateMergenStartVa,
	validateNoVmpRva,
} from "../../src/tools/vmp-common";
import { VmpDumpTool } from "../../src/tools/vmp-dump";
import { NativeDevirtualizeTool } from "../../src/tools/native-devirtualize";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

/**
 * Builds a minimal, structurally valid x64 PE (AMD64, PE32+) binary buffer.
 */
function createMinimalPe64Buffer(options?: {
	machine?: number;
	optMagic?: number;
	imageBase?: bigint;
	sizeOfImage?: number;
	sectionRawOffset?: number;
	sectionRawSize?: number;
	sectionVirtualAddr?: number;
	sectionVirtualSize?: number;
	corruptDos?: boolean;
	corruptNt?: boolean;
}): Buffer {
	const buf = Buffer.alloc(1024, 0);

	if (options?.corruptDos) {
		buf[0] = 0x00;
		buf[1] = 0x00;
		return buf;
	}

	// DOS Header
	buf[0] = 0x4d; // 'M'
	buf[1] = 0x5a; // 'Z'
	const eLfanew = 0x80;
	buf.writeUInt32LE(eLfanew, 0x3c);

	if (options?.corruptNt) {
		buf.write("XX\0\0", eLfanew, "ascii");
		return buf;
	}

	// NT Signature: "PE\0\0"
	buf.write("PE\0\0", eLfanew, "ascii");

	// File Header (20 bytes at eLfanew + 4)
	const machine = options?.machine ?? 0x8664; // AMD64
	buf.writeUInt16LE(machine, eLfanew + 4);
	buf.writeUInt16LE(1, eLfanew + 6); // numSections = 1
	const sizeOfOpt = 240; // 0xF0
	buf.writeUInt16LE(sizeOfOpt, eLfanew + 20);

	// Optional Header (at eLfanew + 24)
	const optMagic = options?.optMagic ?? 0x20b; // PE32+
	buf.writeUInt16LE(optMagic, eLfanew + 24);
	buf.writeUInt32LE(0x1000, eLfanew + 40); // AddressOfEntryPoint RVA = 0x1000
	const imageBase = options?.imageBase ?? 0x140000000n;
	buf.writeBigUInt64LE(imageBase, eLfanew + 48); // ImageBase
	const sizeOfImage = options?.sizeOfImage ?? 0x10000;
	buf.writeUInt32LE(sizeOfImage, eLfanew + 80); // SizeOfImage

	// Section Table (at eLfanew + 24 + sizeOfOpt = 0x80 + 24 + 240 = 0x188)
	const secPos = eLfanew + 24 + sizeOfOpt;
	buf.write(".text\0\0\0", secPos, "ascii");
	const vSize = options?.sectionVirtualSize ?? 0x200;
	const vAddr = options?.sectionVirtualAddr ?? 0x1000;
	const rSize = options?.sectionRawSize ?? 0x200;
	const rOff = options?.sectionRawOffset ?? 0x200;
	buf.writeUInt32LE(vSize, secPos + 8);
	buf.writeUInt32LE(vAddr, secPos + 12);
	buf.writeUInt32LE(rSize, secPos + 16);
	buf.writeUInt32LE(rOff, secPos + 20);
	buf.writeUInt32LE(0x60000020, secPos + 36); // MEM_EXECUTE | MEM_READ | CNT_CODE

	return buf;
}

// ============================================================================
// 1. PE64 Format and Boundary Verification
// ============================================================================

describe("PE64 parser and validation bounds", () => {
	it("parses valid AMD64 PE32+ binary with exact ImageBase and section layout", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-valid-"));
		try {
			const filePath = path.join(tempDir, "sample.exe");
			const peBuf = createMinimalPe64Buffer({ imageBase: 0x140000000n, sizeOfImage: 0x20000 });
			await fs.writeFile(filePath, peBuf);

			const peInfo = await parseAndValidatePe64(filePath);
			expect(peInfo.machine).toBe(0x8664);
			expect(peInfo.magic).toBe(0x20b);
			expect(peInfo.imageBase).toBe(0x140000000n);
			expect(peInfo.sizeOfImage).toBe(0x20000n);
			expect(peInfo.numSections).toBe(1);
			expect(peInfo.sections[0]?.name).toBe(".text");
			expect(peInfo.sections[0]?.isExecutable).toBe(true);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects non-PE files with invalid DOS signature", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-invalid-"));
		try {
			const filePath = path.join(tempDir, "not_pe.bin");
			await fs.writeFile(filePath, createMinimalPe64Buffer({ corruptDos: true }));

			await expect(parseAndValidatePe64(filePath)).rejects.toThrow("缺少 MZ 签名");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects 32-bit x86 and ARM64 machine architectures with exact diagnostics", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-arch-"));
		try {
			const x86Path = path.join(tempDir, "x86.exe");
			await fs.writeFile(x86Path, createMinimalPe64Buffer({ machine: 0x14c })); // x86
			await expect(parseAndValidatePe64(x86Path)).rejects.toThrow("不支持的 PE 架构: x86 32位");

			const armPath = path.join(tempDir, "arm.exe");
			await fs.writeFile(armPath, createMinimalPe64Buffer({ machine: 0xaa64 })); // ARM64
			await expect(parseAndValidatePe64(armPath)).rejects.toThrow("不支持的 PE 架构: ARM64");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects PE32 32-bit optional header magic", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-opt-"));
		try {
			const filePath = path.join(tempDir, "pe32.exe");
			await fs.writeFile(filePath, createMinimalPe64Buffer({ optMagic: 0x10b }));
			await expect(parseAndValidatePe64(filePath)).rejects.toThrow("必须为 PE32+ 64位");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects section table pointing outside file bounds", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-bounds-"));
		try {
			const filePath = path.join(tempDir, "truncated.exe");
			// Section raw offset 0x10000 exceeds file size 1024
			await fs.writeFile(filePath, createMinimalPe64Buffer({ sectionRawOffset: 0x10000, sectionRawSize: 0x200 }));
			await expect(parseAndValidatePe64(filePath)).rejects.toThrow("文件偏移超界");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects symbolic links to prevent link hijacking", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pe-symlink-"));
		try {
			const realPath = path.join(tempDir, "real.exe");
			const linkPath = path.join(tempDir, "link.exe");
			await fs.writeFile(realPath, createMinimalPe64Buffer());
			await fs.symlink(realPath, linkPath);

			await expect(parseAndValidatePe64(linkPath)).rejects.toThrow("拒绝符号链接输入");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

// ============================================================================
// 2. High-Precision BigInt and VA vs RVA Boundaries
// ============================================================================

describe("address parsing and coordinate boundaries", () => {
	it("parses safe integers, hex strings, and BigInts without precision loss", () => {
		expect(parseAddress("0x140001000", "addr")).toBe(0x140001000n);
		expect(parseAddress("14000beef", "addr")).toBe(0x14000beefn);
		expect(parseAddress(5368713257, "addr")).toBe(5368713257n);
		expect(parseAddress(0x140000000n, "addr")).toBe(0x140000000n);
	});

	it("strictly rejects negative numbers, negative strings, and non-integers", () => {
		expect(() => parseAddress("-1", "addr")).toThrow("must be non-negative");
		expect(() => parseAddress(-1, "addr")).toThrow("must be a non-negative safe integer");
		expect(() => parseAddress(1234.56, "addr")).toThrow("must be a non-negative safe integer");
		expect(() => parseAddress(Number.MAX_SAFE_INTEGER + 10, "addr")).toThrow("safe integer");
	});

	it("rejects values exceeding 64-bit integer limit", () => {
		expect(() => parseAddress("0x10000000000000000", "addr")).toThrow("exceeds 64-bit integer range");
	});

	it("Mergen strictly requires VA >= ImageBase and rejects RVA shorthand", () => {
		const mockPe = {
			magic: 0x20b,
			machine: 0x8664,
			characteristics: 0x0020,
			imageBase: 0x140000000n,
			sizeOfImage: 0x20000n,
			entryPointRva: 0x1000n,
			entryPointVa: 0x140001000n,
			numSections: 1,
			sections: [],
		};

		// Valid VA >= imageBase
		expect(validateMergenStartVa("0x140001000", mockPe)).toBe(0x140001000n);

		// Passing an RVA (e.g. 0x1000 < imageBase) must be rejected with conversion guidance
		expect(() => validateMergenStartVa("0x1000", mockPe)).toThrow("Mergen 严格要求函数起始虚拟地址");
		expect(() => validateMergenStartVa("0x1000", mockPe)).toThrow("0x140001000");

		// Out of image bounds
		expect(() => validateMergenStartVa("0x140030000", mockPe)).toThrow("超出 PE 镜像范围");
	});

	it("NoVmp strictly requires RVA < SizeOfImage and rejects VA", () => {
		const mockPe = {
			magic: 0x20b,
			machine: 0x8664,
			characteristics: 0x0020,
			imageBase: 0x140000000n,
			sizeOfImage: 0x20000n,
			entryPointRva: 0x1000n,
			entryPointVa: 0x140001000n,
			numSections: 1,
			sections: [],
		};

		// Valid RVA < sizeOfImage
		expect(validateNoVmpRva("0x15a0", mockPe, "vms")).toBe(0x15a0n);

		// Passing a VA (>= imageBase) must be rejected with conversion guidance
		expect(() => validateNoVmpRva("0x1400015a0", mockPe, "vms")).toThrow("要求相对虚拟地址 (RVA)");
		expect(() => validateNoVmpRva("0x1400015a0", mockPe, "vms")).toThrow("0x15a0");

		// Out of image bounds
		expect(() => validateNoVmpRva("0x30000", mockPe, "vms")).toThrow("超出 PE 镜像范围");
	});
});

// ============================================================================
// 3. Option Injection Prevention in NoVmp Section Prefixes
// ============================================================================

describe("NoVmp option injection prevention", () => {
	it("rejects section prefixes starting with '-' in native_devirtualize tool", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "devirt-sec-"));
		try {
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, createMinimalPe64Buffer());

			const session = createTestSession(tempDir);
			const tool = new NativeDevirtualizeTool(session);

			// Injecting -experimental:recompile via sections
			const promise = tool.execute("call_1", {
				action: "lift",
				backend: "novmp",
				path: samplePath,
				sections: ["-experimental:recompile"],
			});

			await expect(promise).rejects.toThrow("section names cannot start with '-'");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects section prefixes with spaces or length > 8", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "devirt-sec2-"));
		try {
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, createMinimalPe64Buffer());

			const session = createTestSession(tempDir);
			const tool = new NativeDevirtualizeTool(session);

			await expect(
				tool.execute("call_1", {
					action: "lift",
					backend: "novmp",
					path: samplePath,
					sections: ["verylongsectionname"],
				}),
			).rejects.toThrow("must be <= 8 bytes");

			await expect(
				tool.execute("call_2", {
					action: "lift",
					backend: "novmp",
					path: samplePath,
					sections: ["sec tion"],
				}),
			).rejects.toThrow("control or whitespace characters");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

// ============================================================================
// 4. Artifact Overwrite Prevention and Inode Protection
// ============================================================================

describe("artifact publish safety (COPYFILE_EXCL and inode guard)", () => {
	it("refuses to overwrite an existing destination file (COPYFILE_EXCL)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "art-excl-"));
		try {
			const srcPath = path.join(tempDir, "generated.ll");
			const destPath = path.join(tempDir, "existing.ll");

			await fs.writeFile(srcPath, "; ModuleID = 'test'\ndefine i32 @main() { ret i32 0 }\n");
			await fs.writeFile(destPath, "pre-existing content that must not be clobbered");

			await expect(safePublishArtifact(srcPath, destPath)).rejects.toThrow("目标路径已存在，拒绝静默覆盖");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects copying if destination shares inode with forbidden input file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "art-inode-"));
		try {
			const inputPath = path.join(tempDir, "input.exe");
			const artifactPath = path.join(tempDir, "output.exe");
			const linkPath = path.join(tempDir, "hardlink.exe");

			await fs.writeFile(inputPath, "original protected input binary");
			await fs.writeFile(artifactPath, "new artifact content");
			await fs.link(inputPath, linkPath); // hardlink to input

			const inputStat = await fs.lstat(inputPath);
			const forbidden = new Set<string>([`${inputStat.dev}:${inputStat.ino}`]);

			await expect(safePublishArtifact(artifactPath, linkPath, forbidden)).rejects.toThrow(
				"指向被保护的原始输入文件或链接",
			);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

// ============================================================================
// 5. LLVM IR Syntactic Validation
// ============================================================================

describe("LLVM IR syntax verification", () => {
	it("accepts valid LLVM IR with ModuleID and define", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "llvm-ok-"));
		try {
			const llPath = path.join(tempDir, "output.ll");
			await fs.writeFile(
				llPath,
				"; ModuleID = 'my_lifting_module'\nsource_filename = 'my_lifting_module'\ndefine i64 @main() { ret i64 0 }\n",
			);
			await expect(validateLlvmIr(llPath)).resolves.toBeUndefined();
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects non-IR garbage files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "llvm-bad-"));
		try {
			const llPath = path.join(tempDir, "garbage.ll");
			await fs.writeFile(llPath, "This is plain text with no LLVM IR declarations.\n");
			await expect(validateLlvmIr(llPath)).rejects.toThrow("缺少合法 LLVM IR 标记");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});

// ============================================================================
// 6. VMPDump Parameter and Coordinate Bounds
// ============================================================================

describe("VMPDump parameter boundaries", () => {
	it("rejects invalid, negative, or fractional PIDs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vmp-pid-"));
		try {
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, createMinimalPe64Buffer());

			const session = createTestSession(tempDir);
			const tool = new VmpDumpTool(session);

			// Fractional PID string
			await expect(
				tool.execute("c1", {
					action: "dump",
					pid: "123.4",
					module_path: samplePath,
					observed_oep: true,
				}),
			).rejects.toThrow("Invalid target PID format");

			await expect(
				tool.execute("c2", {
					action: "dump",
					pid: -10,
					module_path: samplePath,
					observed_oep: true,
				}),
			).rejects.toThrow("Target PID must be a positive 32-bit integer");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects dump without observed_oep: true", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vmp-oep-"));
		try {
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, createMinimalPe64Buffer());

			const session = createTestSession(tempDir);
			const tool = new VmpDumpTool(session);

			await expect(
				tool.execute("c1", {
					action: "dump",
					pid: 1234,
					module_path: samplePath,
					observed_oep: false,
				}),
			).rejects.toThrow("VMPDump requires confirmed user evidence");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("rejects entry_point passed as VA (>= ImageBase)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vmp-ep-"));
		try {
			const samplePath = path.join(tempDir, "sample.exe");
			await fs.writeFile(samplePath, createMinimalPe64Buffer({ imageBase: 0x140000000n }));

			const session = createTestSession(tempDir);
			const tool = new VmpDumpTool(session);

			await expect(
				tool.execute("c1", {
					action: "dump",
					pid: 1234,
					module_path: samplePath,
					entry_point: "0x140001000", // Passed VA instead of RVA
					observed_oep: true,
				}),
			).rejects.toThrow("entry_point must be a Relative Virtual Address");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("requires process_image_path when dumping secondary DLL module", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "vmp-dll-"));
		try {
			const dllPath = path.join(tempDir, "plugin.dll");
			await fs.writeFile(dllPath, createMinimalPe64Buffer());

			const session = createTestSession(tempDir);
			const tool = new VmpDumpTool(session);

			await expect(
				tool.execute("c1", {
					action: "dump",
					pid: 1234,
					module: "plugin.dll",
					module_path: dllPath,
					// process_image_path omitted
					observed_oep: true,
				}),
			).rejects.toThrow("process_image_path");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
