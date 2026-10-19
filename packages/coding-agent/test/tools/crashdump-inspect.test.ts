import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, CrashdumpInspectTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
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
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

// ============================================================================
// Fixture Generators
// ============================================================================

/**
 * Builds a synthetic minimal Linux ELF64 Core Dump (x86_64).
 */
function createSyntheticElfCore(
	options: {
		pid?: number;
		signal?: number;
		rip?: bigint;
		rsp?: bigint;
		rbp?: bigint;
		rax?: bigint;
		faultAddr?: bigint;
		processName?: string;
		processArgs?: string;
	} = {},
): Buffer {
	const pid = options.pid ?? 1234;
	const signal = options.signal ?? 11; // SIGSEGV
	const rip = options.rip ?? 0x7fff5fc01234n;
	const rsp = options.rsp ?? 0x7fffffffe000n;
	const rbp = options.rbp ?? 0x7fffffffe050n;
	const rax = options.rax ?? 0xdeadbeefn;
	const faultAddr = options.faultAddr ?? 0x0000000000000000n;
	const procName = options.processName ?? "test_crash";
	const procArgs = options.processArgs ?? "./test_crash --debug";

	// 1. Build Notes: NT_PRSTATUS (336 bytes), NT_PRPSINFO (136 bytes), NT_SIGINFO (24 bytes)
	const notesChunks: Buffer[] = [];

	// --- Note 1: NT_PRSTATUS (type 1) ---
	const prstatusDesc = Buffer.alloc(336, 0);
	prstatusDesc.writeInt16LE(signal, 12); // pr_cursig
	prstatusDesc.writeInt32LE(pid, 32); // pr_pid
	// Registers at offset 112:
	// 112: r15, 120: r14, 128: r13, 136: r12, 144: rbp, 152: rbx, 160: r11, 168: r10, 176: r9, 184: r8,
	// 192: rax, 200: rcx, 208: rdx, 216: rsi, 224: rdi, 232: orig_rax, 240: rip, 248: cs, 256: eflags,
	// 264: rsp, 272: ss
	prstatusDesc.writeBigUInt64LE(rbp, 144);
	prstatusDesc.writeBigUInt64LE(rax, 192);
	prstatusDesc.writeBigUInt64LE(rip, 240);
	prstatusDesc.writeBigUInt64LE(0x10206n, 256); // eflags
	prstatusDesc.writeBigUInt64LE(rsp, 264);

	const nameCore = Buffer.from("CORE\0");
	const n1Hdr = Buffer.alloc(12);
	n1Hdr.writeUInt32LE(nameCore.length, 0);
	n1Hdr.writeUInt32LE(prstatusDesc.length, 4);
	n1Hdr.writeUInt32LE(1, 8); // NT_PRSTATUS
	notesChunks.push(n1Hdr, nameCore);
	// Pad name to 4 bytes
	const n1Pad = ((nameCore.length + 3) & ~3) - nameCore.length;
	if (n1Pad > 0) notesChunks.push(Buffer.alloc(n1Pad, 0));
	notesChunks.push(prstatusDesc);

	// --- Note 2: NT_PRPSINFO (type 3) ---
	const prpsinfoDesc = Buffer.alloc(136, 0);
	prpsinfoDesc.writeUInt32LE(pid, 24); // pr_pid
	prpsinfoDesc.write(procName, 40, 16, "ascii"); // pr_fname (16 bytes)
	prpsinfoDesc.write(procArgs, 56, 80, "ascii"); // pr_psargs (80 bytes)

	const n2Hdr = Buffer.alloc(12);
	n2Hdr.writeUInt32LE(nameCore.length, 0);
	n2Hdr.writeUInt32LE(prpsinfoDesc.length, 4);
	n2Hdr.writeUInt32LE(3, 8); // NT_PRPSINFO
	notesChunks.push(n2Hdr, nameCore);
	if (n1Pad > 0) notesChunks.push(Buffer.alloc(n1Pad, 0));
	notesChunks.push(prpsinfoDesc);

	// --- Note 3: NT_SIGINFO (type 0x53494749) ---
	const siginfoDesc = Buffer.alloc(24, 0);
	siginfoDesc.writeInt32LE(signal, 0); // si_signo
	siginfoDesc.writeInt32LE(1, 8); // si_code = SEGV_MAPERR
	siginfoDesc.writeBigUInt64LE(faultAddr, 16); // si_addr

	const n3Hdr = Buffer.alloc(12);
	n3Hdr.writeUInt32LE(nameCore.length, 0);
	n3Hdr.writeUInt32LE(siginfoDesc.length, 4);
	n3Hdr.writeUInt32LE(0x53494749, 8); // NT_SIGINFO
	notesChunks.push(n3Hdr, nameCore);
	if (n1Pad > 0) notesChunks.push(Buffer.alloc(n1Pad, 0));
	notesChunks.push(siginfoDesc);

	const allNotes = Buffer.concat(notesChunks);

	// 2. Program Headers (2 headers: PT_NOTE and PT_LOAD)
	// Header size for ELF64 is 64 bytes. Phdr size is 56 bytes.
	const phOff = 64;
	const phCount = 2;
	const phSize = 56;
	const notesFileOffset = phOff + phCount * phSize; // 64 + 112 = 176

	const elfHdr = Buffer.alloc(64, 0);
	elfHdr[0] = 0x7f;
	elfHdr[1] = 0x45; // 'E'
	elfHdr[2] = 0x4c; // 'L'
	elfHdr[3] = 0x46; // 'F'
	elfHdr[4] = 2; // ELFCLASS64
	elfHdr[5] = 1; // ELFDATA2LSB (little endian)
	elfHdr[6] = 1; // EV_CURRENT
	elfHdr[7] = 0; // ELFOSABI_NONE
	elfHdr.writeUInt16LE(4, 16); // e_type = ET_CORE
	elfHdr.writeUInt16LE(62, 18); // e_machine = EM_X86_64
	elfHdr.writeUInt32LE(1, 20); // e_version
	elfHdr.writeBigUInt64LE(BigInt(phOff), 32); // e_phoff
	elfHdr.writeUInt16LE(64, 52); // e_ehsize
	elfHdr.writeUInt16LE(phSize, 54); // e_phentsize
	elfHdr.writeUInt16LE(phCount, 56); // e_phnum

	// Phdr 0: PT_NOTE (type 4)
	const phdr0 = Buffer.alloc(phSize, 0);
	phdr0.writeUInt32LE(4, 0); // p_type = PT_NOTE
	phdr0.writeUInt32LE(4, 4); // p_flags = R
	phdr0.writeBigUInt64LE(BigInt(notesFileOffset), 8); // p_offset
	phdr0.writeBigUInt64LE(0n, 16); // p_vaddr
	phdr0.writeBigUInt64LE(0n, 24); // p_paddr
	phdr0.writeBigUInt64LE(BigInt(allNotes.length), 32); // p_filesz
	phdr0.writeBigUInt64LE(BigInt(allNotes.length), 40); // p_memsz
	phdr0.writeBigUInt64LE(1n, 48); // p_align

	// Phdr 1: PT_LOAD (type 1) - Memory mapping
	const phdr1 = Buffer.alloc(phSize, 0);
	phdr1.writeUInt32LE(1, 0); // p_type = PT_LOAD
	phdr1.writeUInt32LE(5, 4); // p_flags = R | X (5)
	phdr1.writeBigUInt64LE(BigInt(notesFileOffset + allNotes.length), 8); // p_offset
	phdr1.writeBigUInt64LE(0x00400000n, 16); // p_vaddr
	phdr1.writeBigUInt64LE(0x00400000n, 24); // p_paddr
	phdr1.writeBigUInt64LE(4096n, 32); // p_filesz
	phdr1.writeBigUInt64LE(4096n, 40); // p_memsz
	phdr1.writeBigUInt64LE(4096n, 48); // p_align

	const loadData = Buffer.alloc(4096, 0x90); // NOPs

	return Buffer.concat([elfHdr, phdr0, phdr1, allNotes, loadData]);
}

/**
 * Builds a synthetic minimal Microsoft Minidump (MDMP).
 */
function createSyntheticMinidump(
	options: {
		threadId?: number;
		excCode?: number;
		excAddress?: bigint;
		rip?: bigint;
		rsp?: bigint;
		moduleName?: string;
	} = {},
): Buffer {
	const threadId = options.threadId ?? 4567;
	const excCode = options.excCode ?? 0xc0000005; // STATUS_ACCESS_VIOLATION
	const excAddress = options.excAddress ?? 0x7ff7a0101000n;
	const rip = options.rip ?? 0x7ff7a0101000n;
	const rsp = options.rsp ?? 0x000000e00000f000n;
	const moduleName = options.moduleName ?? "C:\\App\\crash_demo.exe";

	// Stream 1: SystemInfoStream (type 7) - 24 bytes
	const sysInfo = Buffer.alloc(24, 0);
	sysInfo.writeUInt16LE(9, 0); // ProcessorArchitecture = 9 (AMD64)
	sysInfo.writeUInt32LE(10, 8); // MajorVersion = 10
	sysInfo.writeUInt32LE(0, 12); // MinorVersion = 0
	sysInfo.writeUInt32LE(19045, 16); // BuildNumber = 19045

	// Stream 2: ExceptionStream (type 6) - 168 bytes
	// Structure: ThreadId(4), alignment(4), ExceptionRecord(152), ThreadContext(8: DataSize, Rva)
	const excStream = Buffer.alloc(168, 0);
	excStream.writeUInt32LE(threadId, 0);
	excStream.writeUInt32LE(excCode, 8); // ExceptionCode
	excStream.writeBigUInt64LE(excAddress, 24); // ExceptionAddress

	// Context buffer (Windows AMD64 context, 0x108 bytes minimum)
	const ctxBuf = Buffer.alloc(0x108, 0);
	ctxBuf.writeBigUInt64LE(rip, 0xf8); // Rip
	ctxBuf.writeBigUInt64LE(rsp, 0x98); // Rsp
	ctxBuf.writeBigUInt64LE(0x12345678n, 0x78); // Rax

	// ModuleName String (MINIDUMP_STRING: uint32 length in bytes, then UTF-16LE characters)
	const modNameChars = Buffer.from(moduleName, "utf16le");
	const modNameBuf = Buffer.alloc(4 + modNameChars.length);
	modNameBuf.writeUInt32LE(modNameChars.length, 0);
	modNameChars.copy(modNameBuf, 4);

	// Stream 3: ModuleListStream (type 4)
	// Structure: NumberOfModules (uint32), then MINIDUMP_MODULE (108 bytes)
	const modStream = Buffer.alloc(4 + 108, 0);
	modStream.writeUInt32LE(1, 0); // 1 module
	modStream.writeBigUInt64LE(0x7ff7a0000000n, 4); // BaseOfImage
	modStream.writeUInt32LE(0x20000, 12); // SizeOfImage = 128 KiB
	// ModuleNameRva will be patched later

	// Stream 4: ThreadListStream (type 3)
	// Structure: NumberOfThreads (uint32), then MINIDUMP_THREAD (48 bytes)
	const threadStream = Buffer.alloc(4 + 48, 0);
	threadStream.writeUInt32LE(1, 0); // 1 thread
	threadStream.writeUInt32LE(threadId, 4); // ThreadId

	// Layout in file:
	// 0x00: Minidump Header (32 bytes)
	// 0x20: Stream Directory (4 streams * 12 bytes = 48 bytes)
	// 0x50: SystemInfo
	// +: ExceptionStream
	// +: ModuleStream
	// +: ThreadStream
	// +: Context
	// +: ModuleName
	const headerSize = 32;
	const numStreams = 4;
	const streamDirSize = numStreams * 12;

	let currentRva = headerSize + streamDirSize;

	const sysInfoRva = currentRva;
	currentRva += sysInfo.length;

	const excStreamRva = currentRva;
	currentRva += excStream.length;

	const modStreamRva = currentRva;
	currentRva += modStream.length;

	const threadStreamRva = currentRva;
	currentRva += threadStream.length;

	const ctxRva = currentRva;
	currentRva += ctxBuf.length;

	const modNameRva = currentRva;
	currentRva += modNameBuf.length;

	// Patch references
	excStream.writeUInt32LE(ctxBuf.length, 160); // Context DataSize
	excStream.writeUInt32LE(ctxRva, 164); // Context Rva
	modStream.writeUInt32LE(modNameRva, 4 + 20); // ModuleNameRva
	threadStream.writeUInt32LE(ctxBuf.length, 4 + 40); // Thread Context DataSize
	threadStream.writeUInt32LE(ctxRva, 4 + 44); // Thread Context Rva

	// Build Minidump Header
	const header = Buffer.alloc(32, 0);
	header.write("MDMP", 0, "ascii"); // Signature 0x504d444d
	header.writeUInt32LE(0xa793, 4); // Version
	header.writeUInt32LE(numStreams, 8); // NumberOfStreams
	header.writeUInt32LE(headerSize, 12); // StreamDirectoryRva
	header.writeUInt32LE(1672531200, 20); // TimeDateStamp

	// Build Stream Directory
	const streamDir = Buffer.alloc(streamDirSize, 0);
	// Stream 0: SystemInfo (7)
	streamDir.writeUInt32LE(7, 0);
	streamDir.writeUInt32LE(sysInfo.length, 4);
	streamDir.writeUInt32LE(sysInfoRva, 8);
	// Stream 1: Exception (6)
	streamDir.writeUInt32LE(6, 12);
	streamDir.writeUInt32LE(excStream.length, 16);
	streamDir.writeUInt32LE(excStreamRva, 20);
	// Stream 2: ModuleList (4)
	streamDir.writeUInt32LE(4, 24);
	streamDir.writeUInt32LE(modStream.length, 28);
	streamDir.writeUInt32LE(modStreamRva, 32);
	// Stream 3: ThreadList (3)
	streamDir.writeUInt32LE(3, 36);
	streamDir.writeUInt32LE(threadStream.length, 40);
	streamDir.writeUInt32LE(threadStreamRva, 44);

	return Buffer.concat([header, streamDir, sysInfo, excStream, modStream, threadStream, ctxBuf, modNameBuf]);
}

// ============================================================================
// Tests
// ============================================================================

describe("crashdump_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("crashdump_inspect");
		expect(normalizeToolName("crashdump_inspect")).toBe("crashdump_inspect");
		expect(normalizeToolName("crashdump")).toBe("crashdump_inspect");
		expect(normalizeToolName("crash_dump")).toBe("crashdump_inspect");
		expect(normalizeToolName("coredump")).toBe("crashdump_inspect");
		expect(normalizeToolName("core_dump")).toBe("crashdump_inspect");
		expect(normalizeToolName("minidump")).toBe("crashdump_inspect");
		expect(normalizeToolName("crash_inspect")).toBe("crashdump_inspect");
		expect(normalizeToolName("core_inspect")).toBe("crashdump_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-test-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["crashdump_inspect"]);
			const tool = tools.find(t => t.name === "crashdump_inspect") as CrashdumpInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("crashdump_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("Crash Dump / Core File Inspect");
			expect(tool?.description).toContain("Native offline read-only crash dump");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("crashdump_inspect path validation and structured error handling", () => {
	it("rejects non-existent file with descriptive ToolError", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: path.join(tempDir, "missing.dmp"),
				}),
			).rejects.toThrow("Crash dump file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target with descriptive ToolError", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-err-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);
			await expect(
				tool.execute("call-1", {
					action: "info",
					path: tempDir,
				}),
			).rejects.toThrow("Target path is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured unsupported status for non-crash files without throwing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-unsupp-"));
		try {
			const plainFile = path.join(tempDir, "readme.txt");
			await fs.writeFile(plainFile, "This is plain text, not a crash dump file.");

			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);
			const res = await tool.execute("call-unsupp", {
				action: "info",
				path: plainFile,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.format).toBe("unknown");
			expect(res.details.unsupportedReason).toContain("not a recognized crash dump format");

			const text = textOf(res);
			expect(text).toContain("Status**: `unsupported`");
			expect(text).toContain("not a supported crash dump");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns structured unsupported status for standard ELF executables", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-elf-exec-"));
		try {
			const execFile = path.join(tempDir, "my_binary");
			const elfExecBuf = Buffer.alloc(64, 0);
			elfExecBuf[0] = 0x7f;
			elfExecBuf[1] = 0x45;
			elfExecBuf[2] = 0x4c;
			elfExecBuf[3] = 0x46;
			elfExecBuf[4] = 2; // 64-bit
			elfExecBuf[5] = 1; // LE
			elfExecBuf.writeUInt16LE(2, 16); // e_type = 2 (ET_EXEC), NOT ET_CORE
			await fs.writeFile(execFile, elfExecBuf);

			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);
			const res = await tool.execute("call-exec", {
				action: "info",
				path: execFile,
			});

			expect(res.details.status).toBe("unsupported");
			expect(res.details.unsupportedReason).toContain("instead of ET_CORE");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("crashdump_inspect Linux ELF Core Dump analysis", () => {
	it("parses ELF64 core dump info, signals, threads, and registers", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-elfcore-"));
		try {
			const coreFile = path.join(tempDir, "core.dump");
			const coreBuf = createSyntheticElfCore({
				pid: 8899,
				signal: 11, // SIGSEGV
				rip: 0x00007fff5fc01234n,
				rsp: 0x00007fffffffe000n,
				rbp: 0x00007fffffffe050n,
				rax: 0x00000000deadbeefn,
				faultAddr: 0x0000000000000000n,
				processName: "faulty_service",
				processArgs: "./faulty_service --port 8080",
			});
			await fs.writeFile(coreFile, coreBuf);

			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);

			// 1. Action: info
			const infoRes = await tool.execute("call-info", {
				action: "info",
				path: coreFile,
			});
			expect(infoRes.details.status).toBe("ok");
			expect(infoRes.details.format).toBe("elf_core");
			expect(infoRes.details.architecture).toBe("x86_64");
			expect(infoRes.details.bitness).toBe(64);
			expect(infoRes.details.signal?.code).toBe(11);
			expect(infoRes.details.signal?.name).toBe("SIGSEGV");
			expect(infoRes.details.faultingThreadId).toBe(8899);
			expect(infoRes.details.faultingInstructionPointer).toBe("0x00007fff5fc01234");
			expect(infoRes.details.processName).toBe("faulty_service");
			expect(infoRes.details.processArgs).toBe("./faulty_service --port 8080");

			const infoText = textOf(infoRes);
			expect(infoText).toContain("SIGSEGV");
			expect(infoText).toContain("faulty_service");
			expect(infoText).toContain("0x00007fff5fc01234");

			// 2. Action: threads
			const threadsRes = await tool.execute("call-threads", {
				action: "threads",
				path: coreFile,
			});
			expect(threadsRes.details.threads?.length).toBe(1);
			const th = threadsRes.details.threads![0];
			expect(th.id).toBe(8899);
			expect(th.isFaulting).toBe(true);
			expect(th.instructionPointer).toBe("0x00007fff5fc01234");
			expect(th.stackPointer).toBe("0x00007fffffffe000");

			// 3. Action: registers
			const regRes = await tool.execute("call-regs", {
				action: "registers",
				path: coreFile,
			});
			expect(regRes.details.registers?.threadId).toBe(8899);
			expect(regRes.details.registers?.values.rax).toBe("0x00000000deadbeef");
			expect(regRes.details.registers?.values.rip).toBe("0x00007fff5fc01234");

			const regText = textOf(regRes);
			expect(regText).toContain("RAX");
			expect(regText).toContain("0x00000000deadbeef");

			// 4. Action: mappings
			const mapRes = await tool.execute("call-maps", {
				action: "mappings",
				path: coreFile,
			});
			expect(mapRes.details.mappings?.length).toBeGreaterThanOrEqual(1);
			const m0 = mapRes.details.mappings![0];
			expect(m0.startAddress).toBe("0x0000000000400000");

			// 5. Action: notes
			const notesRes = await tool.execute("call-notes", {
				action: "notes",
				path: coreFile,
			});
			expect(notesRes.details.notes?.length).toBeGreaterThanOrEqual(3);
			const noteTypes = notesRes.details.notes!.map(n => n.type);
			expect(noteTypes).toContain("NT_PRSTATUS");
			expect(noteTypes).toContain("NT_PRPSINFO");
			expect(noteTypes).toContain("NT_SIGINFO");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("crashdump_inspect Microsoft Minidump analysis", () => {
	it("parses Minidump headers, exceptions, modules, and threads", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "cd-minidump-"));
		try {
			const dmpFile = path.join(tempDir, "crash.dmp");
			const dmpBuf = createSyntheticMinidump({
				threadId: 6789,
				excCode: 0xc0000005, // STATUS_ACCESS_VIOLATION
				excAddress: 0x7ff7a0101000n,
				rip: 0x7ff7a0101000n,
				rsp: 0x000000e00000f000n,
				moduleName: "C:\\Program Files\\App\\engine.exe",
			});
			await fs.writeFile(dmpFile, dmpBuf);

			const session = createTestSession(tempDir);
			const tool = new CrashdumpInspectTool(session);

			// 1. Action: info
			const infoRes = await tool.execute("call-info", {
				action: "info",
				path: dmpFile,
			});
			expect(infoRes.details.status).toBe("ok");
			expect(infoRes.details.format).toBe("minidump");
			expect(infoRes.details.architecture).toBe("AMD64 (x86_64)");
			expect(infoRes.details.os).toContain("Windows");
			expect(infoRes.details.exception?.code).toBe("0xC0000005");
			expect(infoRes.details.exception?.name).toBe("STATUS_ACCESS_VIOLATION");
			expect(infoRes.details.faultingThreadId).toBe(6789);
			expect(infoRes.details.faultingInstructionPointer).toBe("0x00007ff7a0101000");

			const infoText = textOf(infoRes);
			expect(infoText).toContain("STATUS_ACCESS_VIOLATION");
			expect(infoText).toContain("0xC0000005");
			expect(infoText).toContain("6789");

			// 2. Action: threads
			const threadsRes = await tool.execute("call-threads", {
				action: "threads",
				path: dmpFile,
			});
			expect(threadsRes.details.threads?.length).toBe(1);
			expect(threadsRes.details.threads![0].id).toBe(6789);
			expect(threadsRes.details.threads![0].isFaulting).toBe(true);

			// 3. Action: mappings
			const mapRes = await tool.execute("call-maps", {
				action: "mappings",
				path: dmpFile,
			});
			expect(mapRes.details.mappings?.length).toBe(1);
			expect(mapRes.details.mappings![0].modulePath).toBe("C:\\Program Files\\App\\engine.exe");

			// 4. Action: registers
			const regRes = await tool.execute("call-regs", {
				action: "registers",
				path: dmpFile,
			});
			expect(regRes.details.registers?.threadId).toBe(6789);
			expect(regRes.details.registers?.values.rip).toBe("0x00007ff7a0101000");
			expect(regRes.details.registers?.values.rsp).toBe("0x000000e00000f000");

			// 5. Specific thread lookup
			await expect(
				tool.execute("call-miss-th", {
					action: "registers",
					path: dmpFile,
					thread_id: 99999,
				}),
			).rejects.toThrow("Thread ID 99999 not found in dump");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
