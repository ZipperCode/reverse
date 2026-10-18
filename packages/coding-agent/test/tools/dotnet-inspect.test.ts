import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	DotnetInspectTool,
	type DotnetInspectDetails,
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

function buildTestDotnetAssembly(): Buffer {
	const buf = Buffer.alloc(2048);

	// 1. DOS Header
	buf.write("MZ", 0, "ascii");
	buf.writeUInt32LE(0x80, 0x3c); // e_lfanew -> 0x80

	// 2. PE Signature
	const peOff = 0x80;
	buf.write("PE\0\0", peOff, "ascii");

	// COFF Header (20 bytes)
	buf.writeUInt16LE(0x014c, peOff + 4); // Machine (I386)
	buf.writeUInt16LE(1, peOff + 6); // NumberOfSections
	buf.writeUInt32LE(0, peOff + 8); // TimeDateStamp
	buf.writeUInt32LE(0, peOff + 12);
	buf.writeUInt32LE(0, peOff + 16);
	buf.writeUInt16LE(224, peOff + 20); // SizeOfOptionalHeader
	buf.writeUInt16LE(0x0102, peOff + 22); // Characteristics

	// Optional Header (PE32)
	const optOff = peOff + 24;
	buf.writeUInt16LE(0x010b, optOff); // Magic (PE32)
	buf.writeUInt8(11, optOff + 2);
	buf.writeUInt8(0, optOff + 3);
	buf.writeUInt32LE(512, optOff + 4); // SizeOfCode
	buf.writeUInt32LE(512, optOff + 8); // SizeOfInitializedData
	buf.writeUInt32LE(0, optOff + 12);
	buf.writeUInt32LE(0x2000, optOff + 16); // EntryPoint
	buf.writeUInt32LE(0x2000, optOff + 20); // BaseOfCode
	buf.writeUInt32LE(0x4000, optOff + 24); // BaseOfData
	buf.writeUInt32LE(0x00400000, optOff + 28); // ImageBase
	buf.writeUInt32LE(0x2000, optOff + 32); // SectionAlignment
	buf.writeUInt32LE(0x200, optOff + 36); // FileAlignment
	buf.writeUInt16LE(4, optOff + 40); // MajorOSVersion
	buf.writeUInt16LE(0, optOff + 42);
	buf.writeUInt16LE(0, optOff + 44);
	buf.writeUInt16LE(0, optOff + 46);
	buf.writeUInt16LE(4, optOff + 48); // MajorSubsystemVersion
	buf.writeUInt16LE(0, optOff + 50);
	buf.writeUInt32LE(0, optOff + 52); // Win32Version
	buf.writeUInt32LE(0x6000, optOff + 56); // SizeOfImage
	buf.writeUInt32LE(0x200, optOff + 60); // SizeOfHeaders
	buf.writeUInt32LE(0, optOff + 64); // CheckSum
	buf.writeUInt16LE(3, optOff + 68); // Subsystem (CUI)
	buf.writeUInt16LE(0x8540, optOff + 70); // DllCharacteristics
	buf.writeUInt32LE(0x100000, optOff + 72); // SizeOfStackReserve
	buf.writeUInt32LE(0x1000, optOff + 76);
	buf.writeUInt32LE(0x100000, optOff + 80); // SizeOfHeapReserve
	buf.writeUInt32LE(0x1000, optOff + 84);
	buf.writeUInt32LE(0, optOff + 88); // LoaderFlags
	buf.writeUInt32LE(16, optOff + 92); // NumberOfRvaAndSizes

	// DataDirectory[14] = COM Descriptor (CLI Header)
	const dataDirOff = optOff + 96;
	buf.writeUInt32LE(0x2008, dataDirOff + 14 * 8); // VirtualAddress
	buf.writeUInt32LE(72, dataDirOff + 14 * 8 + 4); // Size

	// Section Header (.text)
	const secOff = optOff + 224;
	buf.write(".text\0\0\0", secOff, "ascii");
	buf.writeUInt32LE(0x1000, secOff + 8); // VirtualSize
	buf.writeUInt32LE(0x2000, secOff + 12); // VirtualAddress
	buf.writeUInt32LE(0x400, secOff + 16); // SizeOfRawData
	buf.writeUInt32LE(0x200, secOff + 20); // PointerToRawData
	buf.writeUInt32LE(0x60000020, secOff + 36); // Characteristics

	// CLI Header at file offset 0x208 (RVA 0x2008)
	const cliOff = 0x208;
	buf.writeUInt32LE(72, cliOff);
	buf.writeUInt16LE(2, cliOff + 4); // MajorRuntimeVersion
	buf.writeUInt16LE(5, cliOff + 6); // MinorRuntimeVersion
	buf.writeUInt32LE(0x2050, cliOff + 8); // Metadata RVA
	buf.writeUInt32LE(0x300, cliOff + 12); // Metadata Size
	buf.writeUInt32LE(1, cliOff + 16); // Flags (ILONLY)
	buf.writeUInt32LE(0x06000001, cliOff + 20); // EntryPointToken

	// Metadata Root at file offset 0x250 (RVA 0x2050)
	const metaOff = 0x250;
	buf.writeUInt32LE(0x424a5342, metaOff); // BSJB
	buf.writeUInt16LE(1, metaOff + 4);
	buf.writeUInt16LE(1, metaOff + 6);
	buf.writeUInt32LE(0, metaOff + 8);
	const vstr = "v4.0.30319\0\0";
	buf.writeUInt32LE(vstr.length, metaOff + 12);
	buf.write(vstr, metaOff + 16, "utf8");

	const streamsHdrOff = metaOff + 16 + vstr.length;
	buf.writeUInt16LE(0, streamsHdrOff);
	buf.writeUInt16LE(5, streamsHdrOff + 2); // 5 streams

	// Streams
	const stringsData = Buffer.from(
		"\0TestModule.dll\0TestAssembly\0TestNamespace\0Calculator\0Add\0<Module>\0",
		"utf8",
	);
	const usData = Buffer.from([0, 5, 0x48, 0, 0x69, 0, 0, 0]); // "Hi"
	const guidData = Buffer.alloc(16, 0xaa);
	const blobData = Buffer.from([0, 1, 0, 0]);

	// Tilde stream
	const validMask = (1n << 0n) | (1n << 2n) | (1n << 6n) | (1n << 32n);
	const tildeParts = [];
	const tildeHdr = Buffer.alloc(40);
	tildeHdr.writeUInt32LE(0, 0);
	tildeHdr.writeUInt8(2, 4);
	tildeHdr.writeUInt8(0, 5);
	tildeHdr.writeUInt8(0, 6); // HeapSizes
	tildeHdr.writeUInt8(1, 7);
	tildeHdr.writeBigUInt64LE(validMask, 8);
	tildeHdr.writeBigUInt64LE(0n, 16);
	tildeHdr.writeUInt32LE(1, 24); // Module: 1
	tildeHdr.writeUInt32LE(2, 28); // TypeDef: 2
	tildeHdr.writeUInt32LE(1, 32); // MethodDef: 1
	tildeHdr.writeUInt32LE(1, 36); // Assembly: 1
	tildeParts.push(tildeHdr);

	// Module row: Gen(2), Name(2)=1, Mvid(2)=1, EncId(2)=0, EncBaseId(2)=0
	const modRow = Buffer.alloc(10);
	modRow.writeUInt16LE(1, 2);
	modRow.writeUInt16LE(1, 4);
	tildeParts.push(modRow);

	// TypeDef row 1 (<Module>): Flags(4)=0, Name(2)=58, Ns(2)=0, Extends(2)=0, Field(2)=1, Method(2)=1
	const td1 = Buffer.alloc(14);
	td1.writeUInt16LE(58, 4);
	td1.writeUInt16LE(1, 10);
	td1.writeUInt16LE(1, 12);
	tildeParts.push(td1);

	// TypeDef row 2 (Calculator): Flags(4)=1 (public), Name(2)=43, Ns(2)=29, Extends(2)=0, Field(2)=1, Method(2)=1
	const td2 = Buffer.alloc(14);
	td2.writeUInt32LE(1, 0); // public
	td2.writeUInt16LE(43, 4); // Calculator
	td2.writeUInt16LE(29, 6); // TestNamespace
	td2.writeUInt16LE(1, 10);
	td2.writeUInt16LE(1, 12);
	tildeParts.push(td2);

	// MethodDef row 1 (Add): RVA(4)=0x2300, ImplFlags(2)=0, Flags(2)=0x0016 (static|public), Name(2)=54, Sig(2)=1, Param(2)=1
	const md1 = Buffer.alloc(14);
	md1.writeUInt32LE(0x2300, 0);
	md1.writeUInt16LE(0x0016, 6);
	md1.writeUInt16LE(54, 8); // Add
	md1.writeUInt16LE(1, 10);
	md1.writeUInt16LE(1, 12);
	tildeParts.push(md1);

	// Assembly row 1: HashAlg(4)=0x8004, Major(2)=1, Minor(2)=0, Build(2)=0, Rev(2)=0, Flags(4)=0, PK(2)=0, Name(2)=16, Cult(2)=0
	const asmRow = Buffer.alloc(22);
	asmRow.writeUInt32LE(0x8004, 0);
	asmRow.writeUInt16LE(1, 4);
	asmRow.writeUInt16LE(16, 18); // TestAssembly
	tildeParts.push(asmRow);

	let tildeData = Buffer.concat(tildeParts);
	if (tildeData.length % 4 !== 0) {
		const pad = Buffer.alloc(4 - (tildeData.length % 4));
		tildeData = Buffer.concat([tildeData, pad]);
	}

	const streams = [
		{ name: "#~\0\0", data: tildeData },
		{ name: "#Strings\0", data: stringsData },
		{ name: "#US\0", data: usData },
		{ name: "#GUID\0", data: guidData },
		{ name: "#Blob\0", data: blobData },
	];

	let curOffset = 16 + vstr.length + 4 + streams.length * 12;
	let sHdrPtr = streamsHdrOff + 4;
	for (const s of streams) {
		buf.writeUInt32LE(curOffset, sHdrPtr);
		buf.writeUInt32LE(s.data.length, sHdrPtr + 4);
		buf.write(s.name, sHdrPtr + 8, "ascii");
		sHdrPtr += 12;
		s.data.copy(buf, metaOff + curOffset);
		curOffset += s.data.length;
	}

	// CIL Method Body at RVA 0x2300 (file offset 0x500)
	// Code: ldarg.0 (0x02), ldc.i4.s 42 (0x1f 0x2a), add (0x58), ret (0x2a) -> 5 bytes
	const cilBytes = Buffer.from([0x02, 0x1f, 0x2a, 0x58, 0x2a]);
	const methodFileOff = 0x500;
	buf.writeUInt8((cilBytes.length << 2) | 0x02, methodFileOff); // Tiny header
	cilBytes.copy(buf, methodFileOff + 1);

	return buf;
}

function buildNativePeWithoutCli(): Buffer {
	const buf = Buffer.alloc(1024);
	buf.write("MZ", 0, "ascii");
	buf.writeUInt32LE(0x80, 0x3c);
	const peOff = 0x80;
	buf.write("PE\0\0", peOff, "ascii");
	buf.writeUInt16LE(0x014c, peOff + 4);
	buf.writeUInt16LE(1, peOff + 6);
	buf.writeUInt16LE(224, peOff + 20);
	const optOff = peOff + 24;
	buf.writeUInt16LE(0x010b, optOff);
	buf.writeUInt32LE(16, optOff + 92);
	// DataDirectory 14 (CLI) is zeroed out
	return buf;
}

describe("dotnet_inspect registration", () => {
	it("is registered as a builtin tool", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("dotnet_inspect");
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["dotnet_inspect"]);
			const tool = tools.find(t => t.name === "dotnet_inspect") as DotnetInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Dotnet Inspect");
			expect(tool?.approval).toBe("read");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("dotnet_inspect path validation and errors", () => {
	it("rejects non-existent file path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-missing-"));
		try {
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", { action: "info", path: "nonexistent.dll" }),
			).rejects.toThrow("Target file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-dir-"));
		try {
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", { action: "info", path: "." }),
			).rejects.toThrow("is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns unsupported for non-PE files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-nonpe-"));
		try {
			const textFile = path.join(tempDir, "text.txt");
			await fs.writeFile(textFile, "This is not a PE file", "utf8");
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "text.txt" });
			expect(res.details.status).toBe("unsupported");
			expect(res.content[0].text).toContain("[Unsupported]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns unsupported for native PE binary without CLI descriptor", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-nativepe-"));
		try {
			const nativePe = path.join(tempDir, "native.exe");
			await fs.writeFile(nativePe, buildNativePeWithoutCli());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "native.exe" });
			expect(res.details.status).toBe("unsupported");
			expect(res.details.error).toContain("native");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("dotnet_inspect with generated .NET assembly", () => {
	it("inspects assembly info, runtime version, and metadata streams", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-info-"));
		try {
			const dllPath = path.join(tempDir, "sample.dll");
			await fs.writeFile(dllPath, buildTestDotnetAssembly());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "info", path: "sample.dll" });

			expect(res.details.status).toBe("ok");
			expect(res.details.format).toBe("PE32");
			expect(res.details.runtimeVersion).toBe("2.5");
			expect(res.details.metadataVersion).toBe("v4.0.30319");
			expect(res.details.flags).toContain("ILONLY");
			expect(res.details.assembly?.name).toBe("TestAssembly");
			expect(res.details.assembly?.version).toBe("1.0.0.0");
			expect(res.details.module?.name).toBe("TestModule.dll");
			expect(res.details.streams?.some(s => s.name === "#~")).toBe(true);
			expect(res.details.streams?.some(s => s.name === "#Strings")).toBe(true);
			expect(res.content[0].text).toContain("TestAssembly");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("lists declared types with flags and counts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-types-"));
		try {
			const dllPath = path.join(tempDir, "sample.dll");
			await fs.writeFile(dllPath, buildTestDotnetAssembly());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "types", path: "sample.dll" });

			expect(res.details.status).toBe("ok");
			expect(res.details.types?.length).toBe(2);
			const calcType = res.details.types?.find(t => t.name === "Calculator");
			expect(calcType).toBeDefined();
			expect(calcType?.namespace).toBe("TestNamespace");
			expect(calcType?.fullName).toBe("TestNamespace.Calculator");
			expect(calcType?.flags).toContain("public");
			expect(calcType?.flags).toContain("class");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("filters declared types by substring", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-filter-"));
		try {
			const dllPath = path.join(tempDir, "sample.dll");
			await fs.writeFile(dllPath, buildTestDotnetAssembly());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", {
				action: "types",
				path: "sample.dll",
				filter: "Calc",
			});

			expect(res.details.types?.length).toBe(1);
			expect(res.details.types?.[0].name).toBe("Calculator");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("lists methods with declaring type, RVA, and flags", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-methods-"));
		try {
			const dllPath = path.join(tempDir, "sample.dll");
			await fs.writeFile(dllPath, buildTestDotnetAssembly());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", { action: "methods", path: "sample.dll" });

			expect(res.details.status).toBe("ok");
			expect(res.details.methods?.length).toBe(1);
			const addMethod = res.details.methods?.[0];
			expect(addMethod?.name).toBe("Add");
			expect(addMethod?.declaringType).toBe("TestNamespace.Calculator");
			expect(addMethod?.hasBody).toBe(true);
			expect(addMethod?.codeSize).toBe(5);
			expect(addMethod?.flags).toContain("public");
			expect(addMethod?.flags).toContain("static");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("disassembles CIL method instructions with opcodes and offsets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dotnet-cil-"));
		try {
			const dllPath = path.join(tempDir, "sample.dll");
			await fs.writeFile(dllPath, buildTestDotnetAssembly());
			const tool = new DotnetInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", {
				action: "cil",
				path: "sample.dll",
				method: "Add",
			});

			expect(res.details.status).toBe("ok");
			const cil = res.details.cil;
			expect(cil).toBeDefined();
			expect(cil?.methodName).toBe("Add");
			expect(cil?.declaringType).toBe("TestNamespace.Calculator");
			expect(cil?.headerFormat).toBe("Tiny");
			expect(cil?.codeSize).toBe(5);

			const insts = cil?.instructions ?? [];
			expect(insts.length).toBe(4);
			expect(insts[0].opcode).toBe("ldarg.0");
			expect(insts[1].opcode).toBe("ldc.i4.s");
			expect(insts[1].operand).toBe(42);
			expect(insts[2].opcode).toBe("add");
			expect(insts[3].opcode).toBe("ret");

			expect(res.content[0].text).toContain("IL_0000: ldarg.0");
			expect(res.content[0].text).toContain("IL_0001: ldc.i4.s 42");
			expect(res.content[0].text).toContain("IL_0003: add");
			expect(res.content[0].text).toContain("IL_0004: ret");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
