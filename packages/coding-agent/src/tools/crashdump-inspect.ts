import * as fs from "node:fs/promises";
import type { Stats } from "node:fs";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes, prompt } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import crashdumpInspectDescription from "../prompts/tools/crashdump-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_MAX_BYTES = 100 * 1024 * 1024; // 100 MB
const HARD_MAX_BYTES = 500 * 1024 * 1024; // 500 MB

// ============================================================================
// Parameter Schema
// ============================================================================

const crashdumpInspectSchema = type({
	action: type
		.enumerated("info", "threads", "mappings", "registers", "notes")
		.describe(
			"Inspection action: info (crash summary, format, architecture, faulting thread/instruction, exception/signal), threads (thread list with IDs, fault status, and key register pointers), mappings (memory mappings and loaded modules with virtual addresses and file paths), registers (detailed register dump for faulting or specified thread), or notes (raw/structured ELF core notes or Minidump stream headers)",
		),
	path: type("string").describe("Path to target core dump or minidump file"),
	"thread_id?": type("number.integer >= 0").describe("Specific thread ID to inspect for registers or thread details"),
	"limit?": type("number.integer >= 1").describe(
		"Maximum threads, mappings, or notes to return (default 50, max 500)",
	),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"max_bytes?": type("number.integer >= 1").describe("Maximum dump file bytes to read (default 100MB, max 500MB)"),
});

export type CrashdumpInspectParams = typeof crashdumpInspectSchema.infer;
export type CrashdumpInspectAction = CrashdumpInspectParams["action"];

// ============================================================================
// Data Models
// ============================================================================

export interface CrashdumpThread {
	id: number;
	name?: string;
	isFaulting: boolean;
	signal?: string;
	instructionPointer?: string;
	stackPointer?: string;
	framePointer?: string;
	registers?: Record<string, string>;
}

export interface CrashdumpMapping {
	startAddress: string;
	endAddress: string;
	size: number;
	permissions?: string;
	offset?: number;
	modulePath?: string;
	buildId?: string;
}

export interface CrashdumpNoteOrStream {
	index: number;
	type: string;
	typeId: number;
	name?: string;
	size: number;
	description?: string;
}

export interface CrashdumpInspectDetails {
	action: CrashdumpInspectAction;
	targetPath: string;
	fileSize: number;
	status: "ok" | "unsupported" | "corrupt";
	format: "elf_core" | "minidump" | "macho_core" | "unknown";
	architecture?: string;
	bitness?: 32 | 64;
	endianness?: "little" | "big";
	os?: string;
	timestamp?: string;
	signal?: {
		code: number;
		name: string;
		description: string;
	};
	exception?: {
		code: string;
		name: string;
		address?: string;
		flags?: number;
	};
	faultingThreadId?: number;
	faultingInstructionPointer?: string;
	faultingMemoryAddress?: string;
	processName?: string;
	processArgs?: string;
	totalThreads?: number;
	totalMappings?: number;
	threads?: CrashdumpThread[];
	mappings?: CrashdumpMapping[];
	registers?: {
		threadId: number;
		isFaulting: boolean;
		values: Record<string, string>;
	};
	notes?: CrashdumpNoteOrStream[];
	unsupportedReason?: string;
	error?: string;
}

// ============================================================================
// Lookup Tables
// ============================================================================

const LINUX_SIGNAL_MAP: Record<number, { name: string; description: string }> = {
	1: { name: "SIGHUP", description: "Hangup" },
	2: { name: "SIGINT", description: "Terminal interrupt" },
	3: { name: "SIGQUIT", description: "Terminal quit" },
	4: { name: "SIGILL", description: "Illegal instruction" },
	5: { name: "SIGTRAP", description: "Trace/breakpoint trap" },
	6: { name: "SIGABRT", description: "Aborted (abort called or assertion failed)" },
	7: { name: "SIGBUS", description: "Bus error (bad memory access / unaligned)" },
	8: { name: "SIGFPE", description: "Floating-point exception / division by zero" },
	9: { name: "SIGKILL", description: "Killed" },
	11: { name: "SIGSEGV", description: "Segmentation fault (invalid memory reference)" },
	13: { name: "SIGPIPE", description: "Broken pipe" },
	14: { name: "SIGALRM", description: "Timer alarm" },
	15: { name: "SIGTERM", description: "Termination signal" },
	24: { name: "SIGXCPU", description: "CPU time limit exceeded" },
	25: { name: "SIGXFSZ", description: "File size limit exceeded" },
	31: { name: "SIGSYS", description: "Bad system call" },
};

const WINDOWS_EXCEPTION_MAP: Record<number, { name: string; description: string }> = {
	0xc0000005: {
		name: "STATUS_ACCESS_VIOLATION",
		description: "The thread attempted to read/write to a virtual address without proper access",
	},
	0x80000003: { name: "STATUS_BREAKPOINT", description: "A breakpoint or assertion was encountered" },
	0x80000004: { name: "STATUS_SINGLE_STEP", description: "A single step trap occurred" },
	0xc00000fd: { name: "STATUS_STACK_OVERFLOW", description: "The thread exhausted its stack space" },
	0xc000001d: {
		name: "STATUS_ILLEGAL_INSTRUCTION",
		description: "The thread attempted to execute an illegal instruction",
	},
	0xc000008c: { name: "STATUS_ARRAY_BOUNDS_EXCEEDED", description: "Array index out of bounds" },
	0xc000008e: { name: "STATUS_FLOAT_DIVIDE_BY_ZERO", description: "Floating point division by zero" },
	0xc0000094: { name: "STATUS_INTEGER_DIVIDE_BY_ZERO", description: "Integer division by zero" },
	0xc0000095: { name: "STATUS_INTEGER_OVERFLOW", description: "Integer overflow trap" },
	0xc0000025: { name: "STATUS_NONCONTINUABLE_EXCEPTION", description: "Cannot continue after exception" },
	0xe06d7363: { name: "STATUS_CPP_EXCEPTION", description: "Microsoft C++ software exception" },
};

const ELF_MACHINE_MAP: Record<number, string> = {
	3: "x86",
	62: "x86_64",
	40: "ARM",
	183: "AArch64",
	8: "MIPS",
	243: "RISC-V",
};

const MINIDUMP_ARCH_MAP: Record<number, string> = {
	0: "x86",
	5: "ARM",
	6: "IA64",
	9: "AMD64 (x86_64)",
	12: "ARM64",
};

const MINIDUMP_STREAM_TYPE_MAP: Record<number, string> = {
	0: "UnusedStream",
	1: "ReservedStream0",
	2: "ReservedStream1",
	3: "ThreadListStream",
	4: "ModuleListStream",
	5: "MemoryListStream",
	6: "ExceptionStream",
	7: "SystemInfoStream",
	8: "ThreadExListStream",
	9: "Memory64ListStream",
	10: "CommentStreamA",
	11: "CommentStreamW",
	12: "HandleDataStream",
	13: "FunctionTableStream",
	14: "UnloadedModuleListStream",
	15: "MiscInfoStream",
	16: "MemoryInfoListStream",
	17: "ThreadInfoListStream",
	18: "HandleOperationListStream",
	19: "TokenStream",
	20: "JavaScriptDataStream",
	21: "SystemMemoryInfoStream",
	22: "ProcessVmCountersStream",
	24: "ThreadNamesStream",
};

const ELF_NOTE_TYPE_MAP: Record<number, string> = {
	1: "NT_PRSTATUS",
	2: "NT_FPREGSET",
	3: "NT_PRPSINFO",
	4: "NT_PRXFPREG",
	6: "NT_AUXV",
	0x46494c45: "NT_FILE",
	0x53494749: "NT_SIGINFO",
	0x400: "NT_ARM_VFP",
	0x401: "NT_ARM_TLS",
};

// ============================================================================
// Internal Parsed Dump Model
// ============================================================================

interface ParsedCrashdump {
	status: "ok" | "unsupported" | "corrupt";
	format: "elf_core" | "minidump" | "macho_core" | "unknown";
	architecture?: string;
	bitness?: 32 | 64;
	endianness?: "little" | "big";
	os?: string;
	timestamp?: string;
	signal?: {
		code: number;
		name: string;
		description: string;
	};
	exception?: {
		code: string;
		name: string;
		address?: string;
		flags?: number;
	};
	faultingThreadId?: number;
	faultingInstructionPointer?: string;
	faultingMemoryAddress?: string;
	processName?: string;
	processArgs?: string;
	threads: CrashdumpThread[];
	mappings: CrashdumpMapping[];
	notes: CrashdumpNoteOrStream[];
	unsupportedReason?: string;
	error?: string;
}

// ============================================================================
// ELF Core Parser
// ============================================================================

function parseElfCore(buf: Buffer): ParsedCrashdump {
	if (buf.length < 52) {
		return {
			status: "corrupt",
			format: "elf_core",
			error: "ELF header is truncated (less than 52 bytes)",
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	const is64 = buf[4] === 2;
	const isLE = buf[5] === 1;
	const bitness: 32 | 64 = is64 ? 64 : 32;
	const endianness: "little" | "big" = isLE ? "little" : "big";

	const eType = isLE ? buf.readUInt16LE(16) : buf.readUInt16BE(16);
	if (eType !== 4) {
		return {
			status: "unsupported",
			format: "unknown",
			unsupportedReason: `Target ELF binary has e_type=${eType} (${eType === 2 ? "ET_EXEC executable" : eType === 3 ? "ET_DYN shared library" : "non-core"}) instead of ET_CORE (4). It is not an ELF core dump.`,
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	const machine = isLE ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
	const arch = ELF_MACHINE_MAP[machine] ?? `arch-${machine}`;

	const phOff = is64
		? isLE
			? Number(buf.readBigUInt64LE(32))
			: Number(buf.readBigUInt64BE(32))
		: isLE
			? buf.readUInt32LE(28)
			: buf.readUInt32BE(28);
	const phEntSize = isLE ? buf.readUInt16LE(is64 ? 54 : 42) : buf.readUInt16BE(is64 ? 54 : 42);
	const phNum = isLE ? buf.readUInt16LE(is64 ? 56 : 44) : buf.readUInt16BE(is64 ? 56 : 44);

	const threads: CrashdumpThread[] = [];
	const rawMappings: Array<{ start: number; end: number; perms: string; offset: number; size: number }> = [];
	const notes: CrashdumpNoteOrStream[] = [];
	const mappedFiles = new Map<number, string>(); // startAddr -> filename

	let processName: string | undefined;
	let processArgs: string | undefined;
	let faultingSigNo: number | undefined;
	let faultingAddr: string | undefined;

	// Parse Program Headers
	for (let i = 0; i < phNum; i++) {
		const entryOffset = phOff + i * phEntSize;
		if (entryOffset + phEntSize > buf.length) break;

		const pType = isLE ? buf.readUInt32LE(entryOffset) : buf.readUInt32BE(entryOffset);

		if (is64) {
			const pFlags = isLE ? buf.readUInt32LE(entryOffset + 4) : buf.readUInt32BE(entryOffset + 4);
			const pOffset = isLE
				? Number(buf.readBigUInt64LE(entryOffset + 8))
				: Number(buf.readBigUInt64BE(entryOffset + 8));
			const pVAddr = isLE
				? Number(buf.readBigUInt64LE(entryOffset + 16))
				: Number(buf.readBigUInt64BE(entryOffset + 16));
			const pMemSz = isLE
				? Number(buf.readBigUInt64LE(entryOffset + 40))
				: Number(buf.readBigUInt64BE(entryOffset + 40));

			const r = (pFlags & 4) !== 0 ? "r" : "-";
			const w = (pFlags & 2) !== 0 ? "w" : "-";
			const x = (pFlags & 1) !== 0 ? "x" : "-";
			const perms = `${r}${w}${x}p`;

			if (pType === 1 && pMemSz > 0) {
				// PT_LOAD
				rawMappings.push({
					start: pVAddr,
					end: pVAddr + pMemSz,
					perms,
					offset: pOffset,
					size: pMemSz,
				});
			} else if (pType === 4) {
				// PT_NOTE
				const noteData = buf.subarray(pOffset, Math.min(buf.length, pOffset + pMemSz));
				parseElfNotes(noteData, is64, isLE);
			}
		} else {
			// 32-bit ELF
			const pOffset = isLE ? buf.readUInt32LE(entryOffset + 4) : buf.readUInt32BE(entryOffset + 4);
			const pVAddr = isLE ? buf.readUInt32LE(entryOffset + 8) : buf.readUInt32BE(entryOffset + 8);
			const pMemSz = isLE ? buf.readUInt32LE(entryOffset + 20) : buf.readUInt32BE(entryOffset + 20);
			const pFlags = isLE ? buf.readUInt32LE(entryOffset + 24) : buf.readUInt32BE(entryOffset + 24);

			const r = (pFlags & 4) !== 0 ? "r" : "-";
			const w = (pFlags & 2) !== 0 ? "w" : "-";
			const x = (pFlags & 1) !== 0 ? "x" : "-";
			const perms = `${r}${w}${x}p`;

			if (pType === 1 && pMemSz > 0) {
				rawMappings.push({
					start: pVAddr,
					end: pVAddr + pMemSz,
					perms,
					offset: pOffset,
					size: pMemSz,
				});
			} else if (pType === 4) {
				const noteData = buf.subarray(pOffset, Math.min(buf.length, pOffset + pMemSz));
				parseElfNotes(noteData, is64, isLE);
			}
		}
	}

	function parseElfNotes(noteBuf: Buffer, is64Bit: boolean, isLittleEndian: boolean) {
		let curr = 0;
		while (curr + 12 <= noteBuf.length) {
			const nameSz = isLittleEndian ? noteBuf.readUInt32LE(curr) : noteBuf.readUInt32BE(curr);
			const descSz = isLittleEndian ? noteBuf.readUInt32LE(curr + 4) : noteBuf.readUInt32BE(curr + 4);
			const typeId = isLittleEndian ? noteBuf.readUInt32LE(curr + 8) : noteBuf.readUInt32BE(curr + 8);

			const paddedNameSz = (nameSz + 3) & ~3;
			const nameOffset = curr + 12;
			if (nameOffset + paddedNameSz > noteBuf.length) break;

			let name = noteBuf.toString("ascii", nameOffset, nameOffset + nameSz);
			if (name.endsWith("\0")) name = name.slice(0, -1);

			const descOffset = nameOffset + paddedNameSz;
			if (descOffset + descSz > noteBuf.length) break;

			const descBuf = noteBuf.subarray(descOffset, descOffset + descSz);
			const typeName = ELF_NOTE_TYPE_MAP[typeId] ?? `type-0x${typeId.toString(16)}`;

			let descSummary: string | undefined;

			// NT_PRSTATUS (1) - Thread status and registers
			if (typeId === 1) {
				const prCursig = isLittleEndian ? descBuf.readInt16LE(12) : descBuf.readInt16BE(12);
				const prPid = isLittleEndian ? descBuf.readInt32LE(32) : descBuf.readInt32BE(32);

				if (prCursig > 0 && !faultingSigNo) {
					faultingSigNo = prCursig;
				}

				const isFaulting = prCursig > 0 || (threads.length === 0 && (faultingSigNo ?? 0) > 0);
				const regs: Record<string, string> = {};
				let ipStr: string | undefined;
				let spStr: string | undefined;
				let fpStr: string | undefined;

				// Parse registers from pr_reg
				if (is64Bit && machine === 62 && descBuf.length >= 328) {
					// Linux x86_64: 27 x 8-byte uint64 at offset 112
					const regOffset = 112;
					const rNames = [
						"r15",
						"r14",
						"r13",
						"r12",
						"rbp",
						"rbx",
						"r11",
						"r10",
						"r9",
						"r8",
						"rax",
						"rcx",
						"rdx",
						"rsi",
						"rdi",
						"orig_rax",
						"rip",
						"cs",
						"eflags",
						"rsp",
						"ss",
						"fs_base",
						"gs_base",
						"ds",
						"es",
						"fs",
						"gs",
					];
					for (let rIdx = 0; rIdx < rNames.length; rIdx++) {
						const val = isLittleEndian
							? descBuf.readBigUInt64LE(regOffset + rIdx * 8)
							: descBuf.readBigUInt64BE(regOffset + rIdx * 8);
						const hex = `0x${val.toString(16).padStart(16, "0")}`;
						regs[rNames[rIdx]] = hex;
					}
					ipStr = regs.rip;
					spStr = regs.rsp;
					fpStr = regs.rbp;
				} else if (!is64Bit && machine === 3 && descBuf.length >= 72) {
					// Linux x86 (32-bit): 17 x 4-byte uint32 at offset 72
					const regOffset = 72;
					const rNames = [
						"ebx",
						"ecx",
						"edx",
						"esi",
						"edi",
						"ebp",
						"eax",
						"ds",
						"es",
						"fs",
						"gs",
						"orig_eax",
						"eip",
						"cs",
						"eflags",
						"esp",
						"ss",
					];
					for (let rIdx = 0; rIdx < rNames.length && regOffset + (rIdx + 1) * 4 <= descBuf.length; rIdx++) {
						const val = isLittleEndian
							? descBuf.readUInt32LE(regOffset + rIdx * 4)
							: descBuf.readUInt32BE(regOffset + rIdx * 4);
						regs[rNames[rIdx]] = `0x${val.toString(16).padStart(8, "0")}`;
					}
					ipStr = regs.eip;
					spStr = regs.esp;
					fpStr = regs.ebp;
				} else if (machine === 40 && descBuf.length >= 72) {
					// ARM (32-bit)
					const regOffset = 72;
					for (let rIdx = 0; rIdx <= 12; rIdx++) {
						const val = isLittleEndian
							? descBuf.readUInt32LE(regOffset + rIdx * 4)
							: descBuf.readUInt32BE(regOffset + rIdx * 4);
						regs[`r${rIdx}`] = `0x${val.toString(16).padStart(8, "0")}`;
					}
					const sp = isLittleEndian
						? descBuf.readUInt32LE(regOffset + 13 * 4)
						: descBuf.readUInt32BE(regOffset + 13 * 4);
					const lr = isLittleEndian
						? descBuf.readUInt32LE(regOffset + 14 * 4)
						: descBuf.readUInt32BE(regOffset + 14 * 4);
					const pc = isLittleEndian
						? descBuf.readUInt32LE(regOffset + 15 * 4)
						: descBuf.readUInt32BE(regOffset + 15 * 4);
					regs.sp = `0x${sp.toString(16).padStart(8, "0")}`;
					regs.lr = `0x${lr.toString(16).padStart(8, "0")}`;
					regs.pc = `0x${pc.toString(16).padStart(8, "0")}`;
					ipStr = regs.pc;
					spStr = regs.sp;
					fpStr = regs.r11;
				}

				const sigInfo = LINUX_SIGNAL_MAP[prCursig];
				const sigStr = sigInfo ? `${sigInfo.name} (${prCursig})` : prCursig > 0 ? `Signal ${prCursig}` : undefined;

				threads.push({
					id: prPid > 0 ? prPid : threads.length + 1,
					isFaulting,
					signal: sigStr,
					instructionPointer: ipStr,
					stackPointer: spStr,
					framePointer: fpStr,
					registers: regs,
				});

				descSummary = `Thread ${prPid}${sigStr ? ` with ${sigStr}` : ""}${ipStr ? ` at IP ${ipStr}` : ""}`;
			}

			// NT_PRPSINFO (3) - Process info & command line args
			if (typeId === 3 && descBuf.length >= 128) {
				const fname = descBuf
					.toString("ascii", is64Bit ? 40 : 28, is64Bit ? 56 : 44)
					.replace(/\0.*$/, "")
					.trim();
				const psargs = descBuf
					.toString("ascii", is64Bit ? 56 : 44, is64Bit ? 136 : 124)
					.replace(/\0.*$/, "")
					.trim();
				if (fname) processName = fname;
				if (psargs) processArgs = psargs;
				descSummary = `Process: "${fname}" args: "${psargs}"`;
			}

			// NT_SIGINFO (0x53494749) - Signal details and faulting address
			if (typeId === 0x53494749 && descBuf.length >= 16) {
				const sigNo = isLittleEndian ? descBuf.readInt32LE(0) : descBuf.readInt32BE(0);
				if (sigNo > 0) faultingSigNo = sigNo;

				if (is64Bit && descBuf.length >= 24) {
					const addr = isLittleEndian ? descBuf.readBigUInt64LE(16) : descBuf.readBigUInt64BE(16);
					faultingAddr = `0x${addr.toString(16).padStart(16, "0")}`;
					descSummary = `Signal ${sigNo}, fault address: ${faultingAddr}`;
				}
			}

			// NT_FILE (0x46494c45) - Memory mapped file paths
			if (typeId === 0x46494c45 && descBuf.length >= 16) {
				const count = is64Bit
					? isLittleEndian
						? Number(descBuf.readBigUInt64LE(0))
						: Number(descBuf.readBigUInt64BE(0))
					: isLittleEndian
						? descBuf.readUInt32LE(0)
						: descBuf.readUInt32BE(0);

				const entrySize = is64Bit ? 24 : 12;
				const stringsOffset = (is64Bit ? 16 : 8) + count * entrySize;

				if (stringsOffset <= descBuf.length) {
					const fileEntries: Array<{ start: number; end: number }> = [];
					for (let fIdx = 0; fIdx < count; fIdx++) {
						const eOff = (is64Bit ? 16 : 8) + fIdx * entrySize;
						const vmStart = is64Bit
							? isLittleEndian
								? Number(descBuf.readBigUInt64LE(eOff))
								: Number(descBuf.readBigUInt64BE(eOff))
							: isLittleEndian
								? descBuf.readUInt32LE(eOff)
								: descBuf.readUInt32BE(eOff);
						const vmEnd = is64Bit
							? isLittleEndian
								? Number(descBuf.readBigUInt64LE(eOff + (is64Bit ? 8 : 4)))
								: Number(descBuf.readBigUInt64BE(eOff + (is64Bit ? 8 : 4)))
							: isLittleEndian
								? descBuf.readUInt32LE(eOff + (is64Bit ? 8 : 4))
								: descBuf.readUInt32BE(eOff + (is64Bit ? 8 : 4));
						fileEntries.push({ start: vmStart, end: vmEnd });
					}

					let strPtr = stringsOffset;
					for (const fe of fileEntries) {
						if (strPtr >= descBuf.length) break;
						let nullIdx = strPtr;
						while (nullIdx < descBuf.length && descBuf[nullIdx] !== 0) nullIdx++;
						const filePath = descBuf.toString("utf8", strPtr, nullIdx).trim();
						if (filePath) {
							mappedFiles.set(fe.start, filePath);
						}
						strPtr = nullIdx + 1;
					}
					descSummary = `${count} memory-mapped file entries`;
				}
			}

			notes.push({
				index: notes.length + 1,
				type: typeName,
				typeId,
				name: name.length > 0 ? name : "CORE",
				size: descSz,
				description: descSummary,
			});

			const paddedDescSz = (descSz + 3) & ~3;
			curr = descOffset + paddedDescSz;
		}
	}

	// Correlate mappings with mapped files
	const mappings: CrashdumpMapping[] = rawMappings.map(rm => {
		const padWidth = is64 ? 16 : 8;
		const startStr = `0x${rm.start.toString(16).padStart(padWidth, "0")}`;
		const endStr = `0x${rm.end.toString(16).padStart(padWidth, "0")}`;
		return {
			startAddress: startStr,
			endAddress: endStr,
			size: rm.size,
			permissions: rm.perms,
			offset: rm.offset,
			modulePath: mappedFiles.get(rm.start),
		};
	});

	// If no thread was marked faulting, mark the first thread
	if (threads.length > 0 && !threads.some(t => t.isFaulting)) {
		threads[0].isFaulting = true;
	}

	const faultingThread = threads.find(t => t.isFaulting) ?? threads[0];
	const signalObj = faultingSigNo
		? {
				code: faultingSigNo,
				name: LINUX_SIGNAL_MAP[faultingSigNo]?.name ?? `SIG-${faultingSigNo}`,
				description: LINUX_SIGNAL_MAP[faultingSigNo]?.description ?? `Signal ${faultingSigNo}`,
			}
		: undefined;

	return {
		status: "ok",
		format: "elf_core",
		architecture: arch,
		bitness,
		endianness,
		os: "Linux / POSIX",
		signal: signalObj,
		faultingThreadId: faultingThread?.id,
		faultingInstructionPointer: faultingThread?.instructionPointer,
		faultingMemoryAddress: faultingAddr,
		processName,
		processArgs,
		threads,
		mappings,
		notes,
	};
}

// ============================================================================
// Microsoft Minidump Parser
// ============================================================================

function parseMinidump(buf: Buffer): ParsedCrashdump {
	if (buf.length < 32) {
		return {
			status: "corrupt",
			format: "minidump",
			error: "Minidump header is truncated (less than 32 bytes)",
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	const numStreams = buf.readUInt32LE(8);
	const streamDirRva = buf.readUInt32LE(12);
	const timeDateStamp = buf.readUInt32LE(20);

	const timeStr = timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : undefined;

	let arch = "x86_64";
	let osName = "Windows NT";
	let faultingThreadId: number | undefined;
	let faultingIP: string | undefined;
	let faultingMemoryAddr: string | undefined;
	let exceptionObj: CrashdumpInspectDetails["exception"];

	const threads: CrashdumpThread[] = [];
	const mappings: CrashdumpMapping[] = [];
	const notes: CrashdumpNoteOrStream[] = [];

	// Stream entries are 12 bytes each: StreamType (uint32), DataSize (uint32), Rva (uint32)
	for (let i = 0; i < numStreams; i++) {
		const sOffset = streamDirRva + i * 12;
		if (sOffset + 12 > buf.length) break;

		const streamType = buf.readUInt32LE(sOffset);
		const dataSize = buf.readUInt32LE(sOffset + 4);
		const rva = buf.readUInt32LE(sOffset + 8);

		const typeName = MINIDUMP_STREAM_TYPE_MAP[streamType] ?? `Stream-0x${streamType.toString(16)}`;
		let streamDesc: string | undefined;

		if (rva + dataSize <= buf.length) {
			const sBuf = buf.subarray(rva, rva + dataSize);

			// SystemInfoStream (7)
			if (streamType === 7 && sBuf.length >= 24) {
				const processorArch = sBuf.readUInt16LE(0);
				const majorVersion = sBuf.readUInt32LE(8);
				const minorVersion = sBuf.readUInt32LE(12);
				const buildNumber = sBuf.readUInt32LE(16);

				arch = MINIDUMP_ARCH_MAP[processorArch] ?? `arch-${processorArch}`;
				osName = `Windows ${majorVersion}.${minorVersion} (Build ${buildNumber})`;
				streamDesc = `OS: ${osName}, Arch: ${arch}`;
			}

			// ExceptionStream (6)
			if (streamType === 6 && sBuf.length >= 168) {
				const threadId = sBuf.readUInt32LE(0);
				const excCode = sBuf.readUInt32LE(8);
				const excFlags = sBuf.readUInt32LE(12);
				const excAddress = sBuf.readBigUInt64LE(24);
				const numParams = sBuf.readUInt32LE(32);

				faultingThreadId = threadId;
				faultingIP = `0x${excAddress.toString(16).padStart(16, "0")}`;

				const excInfo = WINDOWS_EXCEPTION_MAP[excCode];
				const excCodeHex = `0x${excCode.toString(16).toUpperCase().padStart(8, "0")}`;
				exceptionObj = {
					code: excCodeHex,
					name: excInfo?.name ?? `EXCEPTION_${excCodeHex}`,
					address: faultingIP,
					flags: excFlags,
				};

				// For STATUS_ACCESS_VIOLATION (0xC0000005), param 1 is faulting address
				if (excCode === 0xc0000005 && numParams >= 2 && sBuf.length >= 40 + 16) {
					const faultAddr = sBuf.readBigUInt64LE(48);
					faultingMemoryAddr = `0x${faultAddr.toString(16).padStart(16, "0")}`;
				}

				// Context pointer
				const ctxRva = sBuf.readUInt32LE(164);
				const ctxSize = sBuf.readUInt32LE(160);
				let regs: Record<string, string> | undefined;

				if (ctxRva + ctxSize <= buf.length && ctxSize >= 0x108) {
					regs = parseWindowsContext(buf.subarray(ctxRva, ctxRva + ctxSize), arch);
				}

				threads.push({
					id: threadId,
					isFaulting: true,
					instructionPointer: faultingIP,
					stackPointer: regs?.rsp ?? regs?.esp,
					framePointer: regs?.rbp ?? regs?.ebp,
					registers: regs,
				});

				streamDesc = `Faulting thread ${threadId}, Exception: ${exceptionObj.name} (${excCodeHex}) at ${faultingIP}`;
			}

			// ThreadListStream (3)
			if (streamType === 3 && sBuf.length >= 4) {
				const threadCount = sBuf.readUInt32LE(0);
				for (let tIdx = 0; tIdx < threadCount; tIdx++) {
					const tOffset = 4 + tIdx * 48;
					if (tOffset + 48 > sBuf.length) break;

					const tId = sBuf.readUInt32LE(tOffset);
					if (threads.some(t => t.id === tId)) continue; // Already added faulting thread

					const ctxRva = sBuf.readUInt32LE(tOffset + 44);
					const ctxSize = sBuf.readUInt32LE(tOffset + 40);

					let regs: Record<string, string> | undefined;
					if (ctxRva + ctxSize <= buf.length && ctxSize >= 0x108) {
						regs = parseWindowsContext(buf.subarray(ctxRva, ctxRva + ctxSize), arch);
					}

					threads.push({
						id: tId,
						isFaulting: false,
						instructionPointer: regs?.rip ?? regs?.eip,
						stackPointer: regs?.rsp ?? regs?.esp,
						framePointer: regs?.rbp ?? regs?.ebp,
						registers: regs,
					});
				}
				streamDesc = `${threadCount} threads in dump`;
			}

			// ModuleListStream (4)
			if (streamType === 4 && sBuf.length >= 4) {
				const modCount = sBuf.readUInt32LE(0);
				for (let mIdx = 0; mIdx < modCount; mIdx++) {
					const mOffset = 4 + mIdx * 108;
					if (mOffset + 108 > sBuf.length) break;

					const baseAddr = sBuf.readBigUInt64LE(mOffset);
					const size = sBuf.readUInt32LE(mOffset + 8);
					const nameRva = sBuf.readUInt32LE(mOffset + 20);

					let modName = `module_${mIdx + 1}`;
					if (nameRva + 4 <= buf.length) {
						const strLen = buf.readUInt32LE(nameRva);
						if (nameRva + 4 + strLen <= buf.length) {
							modName = buf.toString("utf16le", nameRva + 4, nameRva + 4 + strLen).trim();
						}
					}

					const startHex = `0x${baseAddr.toString(16).padStart(16, "0")}`;
					const endHex = `0x${(baseAddr + BigInt(size)).toString(16).padStart(16, "0")}`;

					mappings.push({
						startAddress: startHex,
						endAddress: endHex,
						size,
						permissions: "r-xp",
						modulePath: modName,
					});
				}
				streamDesc = `${modCount} loaded modules`;
			}
		}

		notes.push({
			index: notes.length + 1,
			type: typeName,
			typeId: streamType,
			size: dataSize,
			description: streamDesc,
		});
	}

	return {
		status: "ok",
		format: "minidump",
		architecture: arch,
		bitness: arch.includes("64") ? 64 : 32,
		endianness: "little",
		os: osName,
		timestamp: timeStr,
		exception: exceptionObj,
		faultingThreadId: faultingThreadId ?? threads[0]?.id,
		faultingInstructionPointer: faultingIP ?? threads[0]?.instructionPointer,
		faultingMemoryAddress: faultingMemoryAddr,
		threads,
		mappings,
		notes,
	};
}

function parseWindowsContext(ctxBuf: Buffer, arch: string): Record<string, string> {
	const regs: Record<string, string> = {};

	if (arch.includes("64") && ctxBuf.length >= 0x108) {
		// Windows AMD64 CONTEXT
		const r64 = [
			{ name: "rax", off: 0x78 },
			{ name: "rcx", off: 0x80 },
			{ name: "rdx", off: 0x88 },
			{ name: "rbx", off: 0x90 },
			{ name: "rsp", off: 0x98 },
			{ name: "rbp", off: 0xa0 },
			{ name: "rsi", off: 0xa8 },
			{ name: "rdi", off: 0xb0 },
			{ name: "r8", off: 0xb8 },
			{ name: "r9", off: 0xc0 },
			{ name: "r10", off: 0xc8 },
			{ name: "r11", off: 0xd0 },
			{ name: "r12", off: 0xd8 },
			{ name: "r13", off: 0xe0 },
			{ name: "r14", off: 0xe8 },
			{ name: "r15", off: 0xf0 },
			{ name: "rip", off: 0xf8 },
		];
		for (const r of r64) {
			const val = ctxBuf.readBigUInt64LE(r.off);
			regs[r.name] = `0x${val.toString(16).padStart(16, "0")}`;
		}
		const eflags = ctxBuf.readUInt32LE(0x100);
		regs.eflags = `0x${eflags.toString(16).padStart(8, "0")}`;
	} else if (ctxBuf.length >= 0xcc) {
		// Windows x86 (32-bit) CONTEXT
		const r32 = [
			{ name: "edi", off: 0x9c },
			{ name: "esi", off: 0xa0 },
			{ name: "ebx", off: 0xa4 },
			{ name: "edx", off: 0xa8 },
			{ name: "ecx", off: 0xac },
			{ name: "eax", off: 0xb0 },
			{ name: "ebp", off: 0xb4 },
			{ name: "eip", off: 0xb8 },
			{ name: "eflags", off: 0xc0 },
			{ name: "esp", off: 0xc4 },
		];
		for (const r of r32) {
			const val = ctxBuf.readUInt32LE(r.off);
			regs[r.name] = `0x${val.toString(16).padStart(8, "0")}`;
		}
	}

	return regs;
}

// ============================================================================
// Mach-O Core Parser
// ============================================================================

function parseMachoCore(buf: Buffer): ParsedCrashdump {
	if (buf.length < 32) {
		return {
			status: "corrupt",
			format: "macho_core",
			error: "Mach-O header is truncated (less than 32 bytes)",
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	const magic = buf.readUInt32BE(0);
	const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
	const isLE = magic === 0xfeedfacf || magic === 0xfeedface;

	const fileType = isLE ? buf.readUInt32LE(12) : buf.readUInt32BE(12);
	if (fileType !== 4) {
		// MH_CORE = 4
		return {
			status: "unsupported",
			format: "unknown",
			unsupportedReason: `Target Mach-O binary has filetype=${fileType} (${fileType === 2 ? "MH_EXECUTE" : fileType === 6 ? "MH_DYLIB" : "non-core"}) instead of MH_CORE (4). It is not a Mach-O core dump.`,
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	const ncmds = isLE ? buf.readUInt32LE(16) : buf.readUInt32BE(16);
	const mappings: CrashdumpMapping[] = [];
	const threads: CrashdumpThread[] = [];
	let cmdOffset = is64 ? 32 : 28;

	for (let i = 0; i < ncmds; i++) {
		if (cmdOffset + 8 > buf.length) break;
		const cmd = isLE ? buf.readUInt32LE(cmdOffset) : buf.readUInt32BE(cmdOffset);
		const cmdSize = isLE ? buf.readUInt32LE(cmdOffset + 4) : buf.readUInt32BE(cmdOffset + 4);

		if (cmdSize < 8 || cmdOffset + cmdSize > buf.length) break;

		// LC_SEGMENT_64 (0x19) or LC_SEGMENT (1)
		if (cmd === 0x19 && is64 && cmdSize >= 72) {
			const segName = buf
				.toString("ascii", cmdOffset + 8, cmdOffset + 24)
				.replace(/\0.*$/, "")
				.trim();
			const vmAddr = isLE ? buf.readBigUInt64LE(cmdOffset + 24) : buf.readBigUInt64BE(cmdOffset + 24);
			const vmSize = isLE ? buf.readBigUInt64LE(cmdOffset + 32) : buf.readBigUInt64BE(cmdOffset + 32);
			const fileOff = isLE ? buf.readBigUInt64LE(cmdOffset + 40) : buf.readBigUInt64BE(cmdOffset + 40);

			if (vmSize > 0n) {
				mappings.push({
					startAddress: `0x${vmAddr.toString(16).padStart(16, "0")}`,
					endAddress: `0x${(vmAddr + vmSize).toString(16).padStart(16, "0")}`,
					size: Number(vmSize),
					permissions: "r-xp",
					offset: Number(fileOff),
					modulePath: segName.length > 0 ? segName : undefined,
				});
			}
		}

		// LC_THREAD (4)
		if (cmd === 4 && cmdSize >= 16) {
			const flavor = isLE ? buf.readUInt32LE(cmdOffset + 8) : buf.readUInt32BE(cmdOffset + 8);
			const _count = isLE ? buf.readUInt32LE(cmdOffset + 12) : buf.readUInt32BE(cmdOffset + 12);
			threads.push({
				id: threads.length + 1,
				isFaulting: threads.length === 0,
				instructionPointer: `flavor-${flavor}`,
			});
		}

		cmdOffset += cmdSize;
	}

	return {
		status: "ok",
		format: "macho_core",
		architecture: is64 ? "ARM64 / x86_64" : "x86",
		bitness: is64 ? 64 : 32,
		endianness: isLE ? "little" : "big",
		os: "macOS / Darwin",
		faultingThreadId: 1,
		threads,
		mappings,
		notes: [],
	};
}

// ============================================================================
// Top-Level Crashdump Sniffer & Dispatcher
// ============================================================================

export function inspectCrashdump(buffer: Buffer): ParsedCrashdump {
	if (buffer.length < 4) {
		return {
			status: "unsupported",
			format: "unknown",
			unsupportedReason: "File is too small to contain a crash dump header",
			threads: [],
			mappings: [],
			notes: [],
		};
	}

	// 1. Linux ELF Core: 7F 45 4C 46
	if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
		return parseElfCore(buffer);
	}

	// 2. Microsoft Minidump: 4D 44 4D 50 ("MDMP")
	if (buffer[0] === 0x4d && buffer[1] === 0x44 && buffer[2] === 0x4d && buffer[3] === 0x50) {
		return parseMinidump(buffer);
	}

	// 3. Mach-O Core: FEEDFACE / FEEDFACF / CEFAEDFE / CFFAEDFE
	const magic = buffer.readUInt32BE(0);
	if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcefaedfe || magic === 0xcffaedfe) {
		return parseMachoCore(buffer);
	}

	// Structured Unsupported Result
	const headerHex = buffer.subarray(0, Math.min(16, buffer.length)).toString("hex").toUpperCase();
	return {
		status: "unsupported",
		format: "unknown",
		unsupportedReason: `File signature (${headerHex}) is not a recognized crash dump format. Supported formats are Linux ELF Core (ET_CORE), Microsoft Minidump (MDMP), and Apple Mach-O Core (MH_CORE).`,
		threads: [],
		mappings: [],
		notes: [],
	};
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class CrashdumpInspectTool implements AgentTool<typeof crashdumpInspectSchema, CrashdumpInspectDetails> {
	readonly name = "crashdump_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Crash Dump / Core File Inspect";
	readonly summary =
		"Native offline read-only crash dump and core file analysis: ELF core (ET_CORE), Minidump (MDMP), registers, termination signals, exception codes, threads, and memory mappings without debuggers or execution";
	readonly description: string;
	readonly parameters = crashdumpInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(crashdumpInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: CrashdumpInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<CrashdumpInspectDetails> & { details: CrashdumpInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Crash dump file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a crash dump file: ${resolvedPath}`);
		}

		if (fileStat.size === 0) {
			throw new ToolError(`Crash dump file is empty (0 bytes): ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`Crash dump file size (${formatBytes(fileStat.size)}) exceeds maximum allowed limit (${formatBytes(maxBytes)})`,
			);
		}

		throwIfAborted(signal);

		const buffer = await fs.readFile(resolvedPath);
		throwIfAborted(signal);

		const dump = inspectCrashdump(buffer);
		throwIfAborted(signal);

		const action = params.action;
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;

		// If unsupported or corrupt, return structured result immediately
		if (dump.status !== "ok") {
			const textLines = [
				`# Crash Dump Inspection: \`${resolvedPath}\``,
				"",
				`**Status**: \`${dump.status}\``,
				`**Format**: \`${dump.format}\``,
				`**Reason**: ${dump.unsupportedReason ?? dump.error ?? "Unsupported binary container"}`,
				"",
				"The provided target file is not a supported crash dump (Linux ELF Core ET_CORE, Microsoft Minidump MDMP, or Apple Mach-O Core MH_CORE).",
				"Ensure you are pointing to a memory core dump rather than a standard executable binary.",
			];

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action,
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: dump.status,
					format: dump.format,
					unsupportedReason: dump.unsupportedReason,
					error: dump.error,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: info
		// ------------------------------------------------------------------------
		if (action === "info") {
			const textLines = [
				`# Crash Dump Summary: \`${resolvedPath}\``,
				"",
				"| Property | Value |",
				"|---|---|",
				`| **Format** | \`${dump.format}\` (${dump.bitness ?? "?"}-bit, ${dump.endianness ?? "?"}-endian) |`,
				`| **File Size** | ${formatBytes(fileStat.size)} (${fileStat.size.toLocaleString()} bytes) |`,
				`| **Architecture** | \`${dump.architecture ?? "unknown"}\` |`,
				`| **Operating System** | \`${dump.os ?? "unknown"}\` |`,
				`| **Crash Timestamp** | \`${dump.timestamp ?? "unknown"}\` |`,
			];

			if (dump.signal) {
				textLines.push(
					`| **Termination Signal** | \`${dump.signal.name}\` (${dump.signal.code}): ${dump.signal.description} |`,
				);
			}

			if (dump.exception) {
				textLines.push(
					`| **Exception** | \`${dump.exception.name}\` (${dump.exception.code}) |`,
					`| **Exception Address** | \`${dump.exception.address ?? "-"}\` |`,
				);
			}

			if (dump.faultingThreadId !== undefined) {
				textLines.push(`| **Faulting Thread ID** | \`${dump.faultingThreadId}\` |`);
			}
			if (dump.faultingInstructionPointer) {
				textLines.push(`| **Instruction Pointer (IP/PC)** | \`${dump.faultingInstructionPointer}\` |`);
			}
			if (dump.faultingMemoryAddress) {
				textLines.push(`| **Faulting Memory Address** | \`${dump.faultingMemoryAddress}\` |`);
			}
			if (dump.processName) {
				textLines.push(`| **Process Name** | \`${dump.processName}\` |`);
			}
			if (dump.processArgs) {
				textLines.push(`| **Invocation Arguments** | \`${dump.processArgs}\` |`);
			}

			textLines.push(
				`| **Total Threads** | ${dump.threads.length} |`,
				`| **Memory Mappings / Modules** | ${dump.mappings.length} |`,
				`| **Notes / Stream Descriptors** | ${dump.notes.length} |`,
			);

			// Thread preview
			if (dump.threads.length > 0) {
				textLines.push(
					"",
					"## Threads Preview",
					"| Thread ID | State | IP / PC | SP | FP |",
					"|---|---|---|---|---|",
				);
				for (const th of dump.threads.slice(0, 8)) {
					const stateStr = th.isFaulting ? "**FAULTING / CRASHED**" : "running/stopped";
					textLines.push(
						`| ${th.id} | ${stateStr} | \`${th.instructionPointer ?? "-"}\` | \`${th.stackPointer ?? "-"}\` | \`${th.framePointer ?? "-"}\` |`,
					);
				}
				if (dump.threads.length > 8) {
					textLines.push(
						`*...and ${dump.threads.length - 8} more threads (use \`action: "threads"\` to view all)*`,
					);
				}
			}

			// Mappings preview
			if (dump.mappings.length > 0) {
				textLines.push(
					"",
					"## Memory Mappings / Modules Preview",
					"| Start Address | End Address | Size | Perms | Module / Path |",
					"|---|---|---|---|---|",
				);
				for (const mp of dump.mappings.slice(0, 8)) {
					textLines.push(
						`| \`${mp.startAddress}\` | \`${mp.endAddress}\` | ${formatBytes(mp.size)} | \`${mp.permissions ?? "-"}\` | \`${mp.modulePath ?? "[anonymous]"}\` |`,
					);
				}
				if (dump.mappings.length > 8) {
					textLines.push(
						`*...and ${dump.mappings.length - 8} more mappings (use \`action: "mappings"\` to paginate)*`,
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "info",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: "ok",
					format: dump.format,
					architecture: dump.architecture,
					bitness: dump.bitness,
					endianness: dump.endianness,
					os: dump.os,
					timestamp: dump.timestamp,
					signal: dump.signal,
					exception: dump.exception,
					faultingThreadId: dump.faultingThreadId,
					faultingInstructionPointer: dump.faultingInstructionPointer,
					faultingMemoryAddress: dump.faultingMemoryAddress,
					processName: dump.processName,
					processArgs: dump.processArgs,
					totalThreads: dump.threads.length,
					totalMappings: dump.mappings.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: threads
		// ------------------------------------------------------------------------
		if (action === "threads") {
			const pagedThreads = dump.threads.slice(offset, offset + limit);
			const textLines = [
				`# Threads Listing: \`${resolvedPath}\` (${dump.threads.length} total, showing ${pagedThreads.length})`,
				"",
				"| Thread ID | Status | Signal | IP / PC | Stack Pointer (SP) | Frame Pointer (FP) |",
				"|---|---|---|---|---|---|",
			];

			for (const th of pagedThreads) {
				const statusStr = th.isFaulting ? "**FAULTING**" : "active";
				const sigStr = th.signal ?? "-";
				textLines.push(
					`| \`${th.id}\` | ${statusStr} | ${sigStr} | \`${th.instructionPointer ?? "-"}\` | \`${th.stackPointer ?? "-"}\` | \`${th.framePointer ?? "-"}\` |`,
				);
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "threads",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: "ok",
					format: dump.format,
					threads: pagedThreads,
					totalThreads: dump.threads.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: mappings
		// ------------------------------------------------------------------------
		if (action === "mappings") {
			const pagedMappings = dump.mappings.slice(offset, offset + limit);
			const textLines = [
				`# Memory Mappings & Loaded Modules: \`${resolvedPath}\` (${dump.mappings.length} total, showing ${pagedMappings.length})`,
				"",
				"| Start Address | End Address | Size | Permissions | Offset | Module / File Path |",
				"|---|---|---|---|---|---|",
			];

			for (const mp of pagedMappings) {
				const offStr = mp.offset !== undefined ? `0x${mp.offset.toString(16)}` : "-";
				const modStr = mp.modulePath ? `\`${mp.modulePath}\`` : "*[anonymous]*";
				textLines.push(
					`| \`${mp.startAddress}\` | \`${mp.endAddress}\` | ${formatBytes(mp.size)} | \`${mp.permissions ?? "-"}\` | ${offStr} | ${modStr} |`,
				);
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "mappings",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: "ok",
					format: dump.format,
					mappings: pagedMappings,
					totalMappings: dump.mappings.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: registers
		// ------------------------------------------------------------------------
		if (action === "registers") {
			let targetThread = dump.threads.find(t => t.isFaulting) ?? dump.threads[0];
			if (params.thread_id !== undefined) {
				const matched = dump.threads.find(t => t.id === params.thread_id);
				if (!matched) {
					throw new ToolError(
						`Thread ID ${params.thread_id} not found in dump. Available threads: ${dump.threads.map(t => t.id).join(", ")}`,
					);
				}
				targetThread = matched;
			}

			const regValues = targetThread?.registers ?? {};
			const regKeys = Object.keys(regValues);

			const textLines = [
				`# Register State: \`${resolvedPath}\` (Thread ID: ${targetThread?.id ?? "?"}${targetThread?.isFaulting ? " [FAULTING]" : ""})`,
				`Architecture: **${dump.architecture ?? "unknown"}**`,
				"",
			];

			if (regKeys.length === 0) {
				textLines.push(
					"No detailed register context was available for this thread.",
					targetThread?.instructionPointer ? `Instruction Pointer: \`${targetThread.instructionPointer}\`` : "",
					targetThread?.stackPointer ? `Stack Pointer: \`${targetThread.stackPointer}\`` : "",
				);
			} else {
				textLines.push("| Register | Hexadecimal Value | Register | Hexadecimal Value |", "|---|---|---|---|");
				for (let i = 0; i < regKeys.length; i += 2) {
					const k1 = regKeys[i];
					const v1 = regValues[k1];
					const k2 = regKeys[i + 1];
					const v2 = k2 ? regValues[k2] : "";
					textLines.push(
						`| **${k1.toUpperCase()}** | \`${v1}\` | ${k2 ? `**${k2.toUpperCase()}**` : ""} | ${k2 ? `\`${v2}\`` : ""} |`,
					);
				}
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "registers",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: "ok",
					format: dump.format,
					registers: {
						threadId: targetThread?.id ?? 0,
						isFaulting: targetThread?.isFaulting ?? false,
						values: regValues,
					},
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: notes
		// ------------------------------------------------------------------------
		if (action === "notes") {
			const pagedNotes = dump.notes.slice(offset, offset + limit);
			const isElf = dump.format === "elf_core";
			const textLines = [
				`# ${isElf ? "ELF Program Notes" : "Minidump Streams"}: \`${resolvedPath}\` (${dump.notes.length} total, showing ${pagedNotes.length})`,
				"",
				"| # | Type | Type ID | Size | Description |",
				"|---|---|---|---|---|",
			];

			for (const nt of pagedNotes) {
				const typeIdHex = `0x${nt.typeId.toString(16).toUpperCase()}`;
				const descStr = nt.description ?? "-";
				textLines.push(
					`| ${nt.index} | **${nt.type}** | \`${typeIdHex}\` | ${formatBytes(nt.size)} | ${descStr} |`,
				);
			}

			return {
				content: [{ type: "text", text: textLines.join("\n") }],
				details: {
					action: "notes",
					targetPath: resolvedPath,
					fileSize: fileStat.size,
					status: "ok",
					format: dump.format,
					notes: pagedNotes,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
