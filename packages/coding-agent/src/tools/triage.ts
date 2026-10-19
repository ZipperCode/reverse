import { createHash } from "node:crypto";
import { createReadStream, type Stats } from "node:fs";
import { stat } from "node:fs/promises";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { prompt } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import triageDescription from "../prompts/tools/triage.md" with { type: "text" };

const triageSchema = type({
	"path?": type("string").describe("Path to target binary, package, or artifact to inspect and triage"),
	"target?": type("string").describe("Target file path (alias for path)"),
	"strings?": type("boolean").describe("Optional printable string extraction (default false)"),
	"limit?": type("number.integer >= 1").describe(
		"Maximum strings or section entries to display (default 50, max 500)",
	),
	"min_length?": type("number.integer >= 1").describe("Minimum length of extracted strings (default 6, min 3)"),
	"max_bytes?": type("number.integer >= 1").describe(
		"Maximum bytes scanned for strings and sampled entropy (default 16 MiB)",
	),
});

export type TriageParams = typeof triageSchema.infer;

export interface TriageSectionSummary {
	name: string;
	size: number;
	virtualSize?: number;
	offset?: number;
	entropy?: number;
}

export interface TriageStringEntry {
	offset: number;
	text: string;
	encoding: "ascii" | "utf-16le";
}

export interface TriageEntropyInfo {
	overall: number;
	sampled: boolean;
	highEntropy: boolean;
}

export interface TriageDetails {
	path: string;
	status: "ok" | "corrupt" | "unsupported" | "error";
	size: number;
	sha256: string;
	format: string;
	subformat?: string;
	arch?: string;
	bits?: 32 | 64;
	endian?: "little" | "big";
	entrypoint?: string;
	sections?: TriageSectionSummary[];
	entropy: TriageEntropyInfo;
	indicators: string[];
	hints?: string[];
	strings?: TriageStringEntry[];
	totalStrings?: number;
	stringsTruncated?: boolean;
	artifactId?: string;
	error?: string;
}

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_STRING_MIN_LENGTH = 6;
const MIN_STRING_MIN_LENGTH = 3;
const DEFAULT_MAX_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_FILE_BYTES = 512 * 1024 * 1024; // 512 MiB
const HEADER_SNIFF_BYTES = 64 * 1024; // 64 KiB
const HIGH_ENTROPY_THRESHOLD = 7.2;

interface StreamAnalysisResult {
	sha256: string;
	entropy: number;
	sampled: boolean;
	sniffBuffer: Uint8Array;
	stringsBuffer?: Uint8Array;
}

/** Compute Shannon entropy from byte frequency counts. */
export function computeEntropyFromFrequencies(frequencies: Uint32Array, totalBytes: number): number {
	if (totalBytes === 0) return 0;
	let entropy = 0;
	const log2 = Math.log2;
	for (let i = 0; i < 256; i++) {
		const count = frequencies[i];
		if (count > 0) {
			const p = count / totalBytes;
			entropy -= p * log2(p);
		}
	}
	return Math.round(entropy * 100) / 100;
}

/** Compute Shannon entropy over a buffer. */
export function computeEntropy(buffer: Uint8Array): number {
	if (buffer.length === 0) return 0;
	const frequencies = new Uint32Array(256);
	for (let i = 0; i < buffer.length; i++) {
		frequencies[buffer[i]]++;
	}
	return computeEntropyFromFrequencies(frequencies, buffer.length);
}

/** Stream-process file: SHA-256, sampled frequency histogram, sniff prefix, strings prefix. */
async function analyzeFileStream(
	filePath: string,
	fileSize: number,
	maxEntropyBytes: number,
	collectStrings: boolean,
	maxStringsBytes: number,
	signal?: AbortSignal,
): Promise<StreamAnalysisResult> {
	if (fileSize === 0) {
		return {
			sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			entropy: 0,
			sampled: false,
			sniffBuffer: new Uint8Array(0),
			stringsBuffer: collectStrings ? new Uint8Array(0) : undefined,
		};
	}

	const { promise, resolve, reject } = Promise.withResolvers<StreamAnalysisResult>();
	const hash = createHash("sha256");
	const frequencies = new Uint32Array(256);
	let entropyBytesRead = 0;
	const sniffChunks: Buffer[] = [];
	let sniffBytesRead = 0;
	const stringsChunks: Buffer[] = [];
	let stringsBytesRead = 0;

	const stream = createReadStream(filePath);

	const cleanup = () => {
		if (signal) {
			signal.removeEventListener("abort", onAbort);
		}
	};

	const onAbort = () => {
		stream.destroy();
		cleanup();
		reject(new ToolError("Triage cancelled"));
	};

	if (signal) {
		if (signal.aborted) {
			onAbort();
			return promise;
		}
		signal.addEventListener("abort", onAbort, { once: true });
	}

	stream.on("data", (chunk: Buffer) => {
		hash.update(chunk);

		// Sniff buffer (up to 64 KiB)
		if (sniffBytesRead < HEADER_SNIFF_BYTES) {
			const needed = HEADER_SNIFF_BYTES - sniffBytesRead;
			const toTake = Math.min(needed, chunk.length);
			sniffChunks.push(chunk.subarray(0, toTake));
			sniffBytesRead += toTake;
		}

		// Strings buffer (if requested, up to maxStringsBytes)
		if (collectStrings && stringsBytesRead < maxStringsBytes) {
			const needed = maxStringsBytes - stringsBytesRead;
			const toTake = Math.min(needed, chunk.length);
			stringsChunks.push(chunk.subarray(0, toTake));
			stringsBytesRead += toTake;
		}

		// Entropy histogram (up to maxEntropyBytes)
		if (entropyBytesRead < maxEntropyBytes) {
			const toScan = Math.min(maxEntropyBytes - entropyBytesRead, chunk.length);
			for (let i = 0; i < toScan; i++) {
				frequencies[chunk[i]]++;
			}
			entropyBytesRead += toScan;
		}
	});

	stream.on("end", () => {
		cleanup();
		const sha256 = hash.digest("hex");
		const sniffBuffer = Buffer.concat(sniffChunks);
		const stringsBuffer = collectStrings ? Buffer.concat(stringsChunks) : undefined;
		const entropy = computeEntropyFromFrequencies(frequencies, entropyBytesRead);
		const sampled = fileSize > maxEntropyBytes;

		resolve({
			sha256,
			entropy,
			sampled,
			sniffBuffer: new Uint8Array(sniffBuffer.buffer, sniffBuffer.byteOffset, sniffBuffer.byteLength),
			stringsBuffer: stringsBuffer
				? new Uint8Array(stringsBuffer.buffer, stringsBuffer.byteOffset, stringsBuffer.byteLength)
				: undefined,
		});
	});

	stream.on("error", err => {
		cleanup();
		reject(err);
	});

	return promise;
}

/** Extract printable ASCII and UTF-16LE strings. */
export function extractPrintableStrings(
	buffer: Uint8Array,
	minLength: number,
	limit: number,
): { strings: TriageStringEntry[]; totalStrings: number; allExtracted: TriageStringEntry[] } {
	const allExtracted: TriageStringEntry[] = [];
	const len = buffer.length;

	// ASCII scan: runs of 0x20-0x7e or 0x09 (\t)
	let asciiStart = -1;
	for (let i = 0; i < len; i++) {
		const b = buffer[i];
		if ((b >= 0x20 && b <= 0x7e) || b === 0x09) {
			if (asciiStart === -1) asciiStart = i;
		} else {
			if (asciiStart !== -1) {
				const strLen = i - asciiStart;
				if (strLen >= minLength) {
					const text = new TextDecoder("ascii").decode(buffer.subarray(asciiStart, i));
					allExtracted.push({ offset: asciiStart, text, encoding: "ascii" });
				}
				asciiStart = -1;
			}
		}
	}
	if (asciiStart !== -1) {
		const strLen = len - asciiStart;
		if (strLen >= minLength) {
			const text = new TextDecoder("ascii").decode(buffer.subarray(asciiStart, len));
			allExtracted.push({ offset: asciiStart, text, encoding: "ascii" });
		}
	}

	// UTF-16LE scan: alternating (ascii, 0x00) pairs
	let utf16Start = -1;
	let utf16Chars = 0;
	for (let i = 0; i + 1 < len; i += 2) {
		const b0 = buffer[i];
		const b1 = buffer[i + 1];
		if (b1 === 0x00 && ((b0 >= 0x20 && b0 <= 0x7e) || b0 === 0x09)) {
			if (utf16Start === -1) {
				utf16Start = i;
				utf16Chars = 0;
			}
			utf16Chars++;
		} else {
			if (utf16Start !== -1) {
				if (utf16Chars >= minLength) {
					const text = new TextDecoder("utf-16le").decode(
						buffer.subarray(utf16Start, utf16Start + utf16Chars * 2),
					);
					allExtracted.push({ offset: utf16Start, text, encoding: "utf-16le" });
				}
				utf16Start = -1;
				utf16Chars = 0;
			}
		}
	}
	if (utf16Start !== -1 && utf16Chars >= minLength) {
		const text = new TextDecoder("utf-16le").decode(buffer.subarray(utf16Start, utf16Start + utf16Chars * 2));
		allExtracted.push({ offset: utf16Start, text, encoding: "utf-16le" });
	}

	allExtracted.sort((a, b) => a.offset - b.offset);

	const totalStrings = allExtracted.length;
	const strings = allExtracted.slice(0, limit);

	return { strings, totalStrings, allExtracted };
}

/** Parse Portable Executable (PE) headers. */
function parsePe(buf: Uint8Array, fileSize: number): Partial<TriageDetails> | null {
	if (buf.length < 2 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null; // "MZ"
	if (buf.length < 64) {
		return {
			format: "PE (corrupted)",
			status: "corrupt",
			indicators: ["truncated_dos_header"],
		};
	}
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const eLfanew = view.getUint32(0x3c, true);
	if (eLfanew < 64 || eLfanew + 24 > fileSize) {
		return {
			format: "PE (corrupted)",
			status: "corrupt",
			indicators: ["invalid_pe_offset"],
		};
	}
	if (eLfanew + 24 > buf.length) {
		return {
			format: "PE",
			status: "corrupt",
			indicators: ["pe_header_beyond_sniff_buffer"],
		};
	}
	if (buf[eLfanew] !== 0x50 || buf[eLfanew + 1] !== 0x45 || buf[eLfanew + 2] !== 0x00 || buf[eLfanew + 3] !== 0x00) {
		return {
			format: "MS-DOS Executable",
			subformat: "MZ Executable (non-PE)",
			indicators: ["dos_stub_only"],
		};
	}

	const machine = view.getUint16(eLfanew + 4, true);
	const numSections = view.getUint16(eLfanew + 6, true);
	const sizeOfOptHeader = view.getUint16(eLfanew + 20, true);
	const characteristics = view.getUint16(eLfanew + 22, true);

	let arch = "unknown";
	let bits: 32 | 64 | undefined;
	switch (machine) {
		case 0x8664:
			arch = "x86_64";
			bits = 64;
			break;
		case 0x014c:
			arch = "i386";
			bits = 32;
			break;
		case 0xaa64:
			arch = "arm64";
			bits = 64;
			break;
		case 0x01c0:
			arch = "arm";
			bits = 32;
			break;
		case 0x01c4:
			arch = "armv7";
			bits = 32;
			break;
		case 0x0200:
			arch = "ia64";
			bits = 64;
			break;
		default:
			arch = `machine-0x${machine.toString(16)}`;
			break;
	}

	const isDll = (characteristics & 0x2000) !== 0;
	let subformat = isDll ? "PE (DLL)" : "PE (EXE)";
	let entrypoint: string | undefined;

	if (sizeOfOptHeader >= 28 && eLfanew + 24 + sizeOfOptHeader <= buf.length) {
		const optMagic = view.getUint16(eLfanew + 24, true);
		if (optMagic === 0x020b) {
			bits = 64;
			subformat = isDll ? "PE32+ (DLL)" : "PE32+ (EXE)";
		} else if (optMagic === 0x010b) {
			bits = 32;
			subformat = isDll ? "PE32 (DLL)" : "PE32 (EXE)";
		}
		const epRva = view.getUint32(eLfanew + 24 + 16, true);
		if (epRva > 0) {
			if (bits === 64 && sizeOfOptHeader >= 32) {
				const imageBase = view.getBigUint64(eLfanew + 24 + 24, true);
				entrypoint = `0x${(imageBase + BigInt(epRva)).toString(16)}`;
			} else if (bits === 32 && sizeOfOptHeader >= 32) {
				const imageBase = view.getUint32(eLfanew + 24 + 28, true);
				entrypoint = `0x${(imageBase + epRva).toString(16)}`;
			} else {
				entrypoint = `RVA 0x${epRva.toString(16)}`;
			}
		}
	}

	const sections: TriageSectionSummary[] = [];
	const sectionTableOffset = eLfanew + 24 + sizeOfOptHeader;
	const sectionCount = Math.min(numSections, 96);
	const indicators: string[] = [];
	if (isDll) indicators.push("dll");
	else indicators.push("executable");

	for (let i = 0; i < sectionCount; i++) {
		const sOff = sectionTableOffset + i * 40;
		if (sOff + 40 > buf.length) break;
		const nameBytes = buf.subarray(sOff, sOff + 8);
		let nameEnd = 0;
		while (nameEnd < 8 && nameBytes[nameEnd] !== 0) nameEnd++;
		const name = new TextDecoder("ascii").decode(nameBytes.subarray(0, nameEnd)).trim();
		const virtualSize = view.getUint32(sOff + 8, true);
		const rawSize = view.getUint32(sOff + 16, true);
		const rawOffset = view.getUint32(sOff + 20, true);

		let sectionEntropy: number | undefined;
		if (rawOffset + rawSize <= buf.length && rawSize > 0) {
			const sectionData = buf.subarray(rawOffset, rawOffset + rawSize);
			sectionEntropy = computeEntropy(sectionData);
			if (sectionEntropy >= HIGH_ENTROPY_THRESHOLD) {
				indicators.push(`high_entropy_section:${name}`);
			}
		}

		sections.push({
			name: name || `sec_${i}`,
			size: rawSize,
			virtualSize,
			offset: rawOffset,
			entropy: sectionEntropy,
		});
	}

	return {
		format: "PE",
		subformat,
		arch,
		bits,
		endian: "little",
		entrypoint,
		sections,
		indicators,
		hints: ["For disassembly and decompilation, use read-binary (IDA) or radare2 (r2)."],
	};
}

/** Parse Executable and Linkable Format (ELF) headers. */
function parseElf(buf: Uint8Array, _fileSize: number): Partial<TriageDetails> | null {
	if (buf.length < 4 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
		return null; // "\x7fELF"
	}
	if (buf.length < 16) {
		return {
			format: "ELF (truncated)",
			status: "corrupt",
			indicators: ["truncated_elf_ident"],
		};
	}
	const is64 = buf[4] === 2;
	const bits: 32 | 64 = is64 ? 64 : 32;
	const isLe = buf[5] === 1;
	const endian: "little" | "big" = isLe ? "little" : "big";
	const minHeaderSize = is64 ? 64 : 52;
	if (buf.length < minHeaderSize) {
		return {
			format: "ELF (truncated)",
			status: "corrupt",
			bits,
			endian,
			indicators: ["truncated_elf_header"],
		};
	}

	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const eType = view.getUint16(16, isLe);
	const eMachine = view.getUint16(18, isLe);

	let arch = "unknown";
	switch (eMachine) {
		case 0x03:
			arch = "i386";
			break;
		case 0x3e:
			arch = "x86_64";
			break;
		case 0x28:
			arch = "arm";
			break;
		case 0xb7:
			arch = "arm64";
			break;
		case 0xf3:
			arch = "riscv";
			break;
		case 0x08:
			arch = "mips";
			break;
		case 0x14:
			arch = "ppc";
			break;
		case 0x15:
			arch = "ppc64";
			break;
		default:
			arch = `machine-0x${eMachine.toString(16)}`;
			break;
	}

	let subformat = "ELF";
	switch (eType) {
		case 1:
			subformat = `ELF${bits} (relocatable .o)`;
			break;
		case 2:
			subformat = `ELF${bits} (executable)`;
			break;
		case 3:
			subformat = `ELF${bits} (shared object / PIE)`;
			break;
		case 4:
			subformat = `ELF${bits} (core dump)`;
			break;
		default:
			subformat = `ELF${bits} (type ${eType})`;
			break;
	}

	let entrypoint: string | undefined;
	if (is64) {
		const ep = view.getBigUint64(24, isLe);
		if (ep > 0n) entrypoint = `0x${ep.toString(16)}`;
	} else {
		const ep = view.getUint32(24, isLe);
		if (ep > 0) entrypoint = `0x${ep.toString(16)}`;
	}

	const indicators: string[] = [];
	if (eType === 3) indicators.push("pie_or_shared");
	else if (eType === 2) indicators.push("executable");

	const sections: TriageSectionSummary[] = [];
	const shOff = is64 ? Number(view.getBigUint64(40, isLe)) : view.getUint32(32, isLe);
	const shEntSize = is64 ? view.getUint16(58, isLe) : view.getUint16(46, isLe);
	const shNum = is64 ? view.getUint16(60, isLe) : view.getUint16(48, isLe);
	const shStrNdx = is64 ? view.getUint16(62, isLe) : view.getUint16(50, isLe);

	if (shOff > 0 && shNum > 0 && shEntSize >= (is64 ? 64 : 40) && shOff + shNum * shEntSize <= buf.length) {
		if (shStrNdx < shNum) {
			const strtabEntry = shOff + shStrNdx * shEntSize;
			const strtabOff = is64
				? Number(view.getBigUint64(strtabEntry + 24, isLe))
				: view.getUint32(strtabEntry + 16, isLe);
			const strtabSize = is64
				? Number(view.getBigUint64(strtabEntry + 32, isLe))
				: view.getUint32(strtabEntry + 20, isLe);
			const strtabBuf =
				strtabOff + strtabSize <= buf.length ? buf.subarray(strtabOff, strtabOff + strtabSize) : null;

			const maxSections = Math.min(shNum, 64);
			for (let i = 0; i < maxSections; i++) {
				const entryOff = shOff + i * shEntSize;
				const nameOff = view.getUint32(entryOff, isLe);
				let name = "";
				if (strtabBuf && nameOff < strtabBuf.length) {
					let end = nameOff;
					while (end < strtabBuf.length && strtabBuf[end] !== 0) end++;
					name = new TextDecoder("ascii").decode(strtabBuf.subarray(nameOff, end));
				}
				const secOffset = is64
					? Number(view.getBigUint64(entryOff + 24, isLe))
					: view.getUint32(entryOff + 16, isLe);
				const secSize = is64 ? Number(view.getBigUint64(entryOff + 32, isLe)) : view.getUint32(entryOff + 20, isLe);

				let sectionEntropy: number | undefined;
				if (secOffset + secSize <= buf.length && secSize > 0) {
					sectionEntropy = computeEntropy(buf.subarray(secOffset, secOffset + secSize));
				}
				if (name) {
					sections.push({
						name,
						size: secSize,
						offset: secOffset,
						entropy: sectionEntropy,
					});
				}
			}
		}
	} else if (shNum === 0 || shOff === 0) {
		indicators.push("stripped_sections");
	}

	return {
		format: "ELF",
		subformat,
		arch,
		bits,
		endian,
		entrypoint,
		sections,
		indicators,
		hints: ["For disassembly and decompilation, use read-binary (IDA) or radare2 (r2)."],
	};
}

/** Parse Apple Mach-O headers (thin and universal fat). */
function parseMachO(buf: Uint8Array, fileSize: number): Partial<TriageDetails> | null {
	if (buf.length < 4) return null;
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const magic = view.getUint32(0, false); // read big-endian initially

	// Universal Fat Mach-O
	if (magic === 0xcafebabe || magic === 0xcafebabf || magic === 0xbebafeca || magic === 0xbfbafeca) {
		if (buf.length >= 8) {
			const majorVer = view.getUint16(6, false);
			const nfat = view.getUint32(4, false);
			// Exclude Java class files
			if (!(nfat > 30 && majorVer >= 45) && nfat >= 1 && nfat <= 30) {
				const is64 = magic === 0xcafebabf || magic === 0xbfbafeca;
				const isLe = magic === 0xbebafeca || magic === 0xbfbafeca;
				const entrySize = is64 ? 32 : 20;
				if (buf.length >= 8 + nfat * entrySize) {
					const s0Off = is64 ? Number(view.getBigUint64(8 + 8, isLe)) : view.getUint32(8 + 8, isLe);
					const s0Size = is64 ? Number(view.getBigUint64(8 + 16, isLe)) : view.getUint32(8 + 12, isLe);
					if (s0Off > 0 && s0Off + s0Size <= fileSize) {
						const slices: Array<{ arch: string; cpuType: number; offset: number; size: number }> = [];
						for (let i = 0; i < nfat; i++) {
							const at = 8 + i * entrySize;
							const cpuType = view.getUint32(at, isLe);
							const off = is64 ? Number(view.getBigUint64(at + 8, isLe)) : view.getUint32(at + 8, isLe);
							const sz = is64 ? Number(view.getBigUint64(at + 16, isLe)) : view.getUint32(at + 12, isLe);
							let archName = "unknown";
							if (cpuType === 7) archName = "i386";
							else if (cpuType === 0x01000007) archName = "x86_64";
							else if (cpuType === 12) archName = "arm";
							else if (cpuType === 0x0100000c) archName = "arm64";
							else if (cpuType === 0x0200000c) archName = "arm64_32";
							else if (cpuType === 18) archName = "ppc";
							else if (cpuType === 0x01000012) archName = "ppc64";
							else archName = `cpu-0x${cpuType.toString(16)}`;
							slices.push({ arch: archName, cpuType, offset: off, size: sz });
						}
						const archList = slices.map(s => s.arch).join(", ");
						return {
							format: "Mach-O (fat/universal)",
							subformat: `Universal Binary (${slices.length} slices: ${archList})`,
							arch: archList,
							indicators: ["universal_binary", `${slices.length}_slices`],
							hints: [
								"Universal binary contains multiple architectures. Use read-binary :@<arch> or lipo to extract slices.",
							],
						};
					}
				}
			}
		}
	}

	// Thin Mach-O
	const is32Be = magic === 0xfeedface;
	const is32Le = magic === 0xcefaedfe;
	const is64Be = magic === 0xfeedfacf;
	const is64Le = magic === 0xcffaedfe;

	if (!is32Be && !is32Le && !is64Be && !is64Le) return null;

	const is64 = is64Be || is64Le;
	const isLe = is32Le || is64Le;
	const bits: 32 | 64 = is64 ? 64 : 32;
	const endian: "little" | "big" = isLe ? "little" : "big";
	const headerSize = is64 ? 32 : 28;

	if (buf.length < headerSize) {
		return {
			format: "Mach-O (truncated)",
			status: "corrupt",
			bits,
			endian,
			indicators: ["truncated_macho_header"],
		};
	}

	const cpuType = view.getUint32(4, isLe);
	const fileType = view.getUint32(12, isLe);
	const ncmds = view.getUint32(16, isLe);

	let arch = "unknown";
	if (cpuType === 7) arch = "i386";
	else if (cpuType === 0x01000007) arch = "x86_64";
	else if (cpuType === 12) arch = "arm";
	else if (cpuType === 0x0100000c) arch = "arm64";
	else if (cpuType === 0x0200000c) arch = "arm64_32";
	else if (cpuType === 18) arch = "ppc";
	else if (cpuType === 0x01000012) arch = "ppc64";

	let subformat = `Mach-O ${bits}-bit`;
	switch (fileType) {
		case 1:
			subformat += " (OBJECT)";
			break;
		case 2:
			subformat += " (EXECUTE)";
			break;
		case 6:
			subformat += " (DYLIB)";
			break;
		case 8:
			subformat += " (BUNDLE)";
			break;
		default:
			subformat += ` (type ${fileType})`;
			break;
	}

	const sections: TriageSectionSummary[] = [];
	let entrypoint: string | undefined;
	let cmdOffset = headerSize;
	const maxCmds = Math.min(ncmds, 64);

	for (let i = 0; i < maxCmds; i++) {
		if (cmdOffset + 8 > buf.length) break;
		const cmd = view.getUint32(cmdOffset, isLe);
		const cmdSize = view.getUint32(cmdOffset + 4, isLe);
		if (cmdSize < 8 || cmdOffset + cmdSize > buf.length) break;

		// LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
		if ((!is64 && cmd === 0x1) || (is64 && cmd === 0x19)) {
			const segNameBytes = buf.subarray(cmdOffset + 8, cmdOffset + 24);
			let end = 0;
			while (end < 16 && segNameBytes[end] !== 0) end++;
			const segName = new TextDecoder("ascii").decode(segNameBytes.subarray(0, end)).trim();

			const nsects = is64 ? view.getUint32(cmdOffset + 64, isLe) : view.getUint32(cmdOffset + 48, isLe);
			const sectHeaderSize = is64 ? 80 : 68;
			const sectStart = is64 ? cmdOffset + 72 : cmdOffset + 56;

			for (let s = 0; s < Math.min(nsects, 32); s++) {
				const sAt = sectStart + s * sectHeaderSize;
				if (sAt + sectHeaderSize > buf.length) break;
				const sNameBytes = buf.subarray(sAt, sAt + 16);
				let sEnd = 0;
				while (sEnd < 16 && sNameBytes[sEnd] !== 0) sEnd++;
				const sectName = new TextDecoder("ascii").decode(sNameBytes.subarray(0, sEnd)).trim();
				const sSize = is64 ? Number(view.getBigUint64(sAt + 40, isLe)) : view.getUint32(sAt + 36, isLe);
				const sOffset = view.getUint32(sAt + (is64 ? 48 : 40), isLe);

				let sEntropy: number | undefined;
				if (sOffset + sSize <= buf.length && sSize > 0) {
					sEntropy = computeEntropy(buf.subarray(sOffset, sOffset + sSize));
				}
				sections.push({
					name: `${segName},${sectName}`,
					size: sSize,
					offset: sOffset,
					entropy: sEntropy,
				});
			}
		} else if (cmd === 0x80000028) {
			// LC_MAIN
			if (cmdOffset + 16 <= buf.length) {
				const entryoff = view.getBigUint64(cmdOffset + 8, isLe);
				entrypoint = `0x${entryoff.toString(16)}`;
			}
		}

		cmdOffset += cmdSize;
	}

	return {
		format: "Mach-O",
		subformat,
		arch,
		bits,
		endian,
		entrypoint,
		sections,
		indicators: [fileType === 2 ? "executable" : fileType === 6 ? "dylib" : `macho_${fileType}`],
		hints: ["For disassembly and decompilation, use read-binary (IDA) or radare2 (r2)."],
	};
}

/** Parse WebAssembly (.wasm) headers and sections. */
function parseWasm(buf: Uint8Array, _fileSize: number): Partial<TriageDetails> | null {
	if (buf.length < 4 || buf[0] !== 0x00 || buf[1] !== 0x61 || buf[2] !== 0x73 || buf[3] !== 0x6d) {
		return null; // "\0asm"
	}
	if (buf.length < 8) {
		return {
			format: "WASM (truncated)",
			status: "corrupt",
			indicators: ["truncated_wasm_header"],
		};
	}
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const version = view.getUint32(4, true);

	const SECTION_NAMES: Record<number, string> = {
		0: "custom",
		1: "type",
		2: "import",
		3: "function",
		4: "table",
		5: "memory",
		6: "global",
		7: "export",
		8: "start",
		9: "element",
		10: "code",
		11: "data",
		12: "data_count",
		13: "tag",
	};

	const sections: TriageSectionSummary[] = [];
	let offset = 8;
	const maxSections = 64;

	while (offset < buf.length && sections.length < maxSections) {
		const secId = buf[offset++];
		let secSize = 0;
		let shift = 0;
		let byte = 0;
		while (offset < buf.length) {
			byte = buf[offset++];
			secSize |= (byte & 0x7f) << shift;
			if ((byte & 0x80) === 0) break;
			shift += 7;
			if (shift > 28) break;
		}
		const secName = SECTION_NAMES[secId] ?? `section_${secId}`;
		const secStart = offset;
		let secEntropy: number | undefined;
		if (secStart + secSize <= buf.length && secSize > 0) {
			secEntropy = computeEntropy(buf.subarray(secStart, secStart + secSize));
		}
		sections.push({
			name: secName,
			size: secSize,
			offset: secStart,
			entropy: secEntropy,
		});
		offset += secSize;
	}

	return {
		format: "WASM",
		subformat: `WebAssembly binary v${version}`,
		arch: "wasm32",
		bits: 32,
		endian: "little",
		sections,
		indicators: [`wasm_v${version}`],
		hints: [
			'Target is a WebAssembly binary. Use wasm_inspect(action: "info", path: "...") for exports/imports and signatures.',
			'Use wasm_inspect(action: "strings" | "wat", path: "...") for data strings or WAT disassembly.',
		],
	};
}

/** Parse Android DEX headers. */
function parseDex(buf: Uint8Array, _fileSize: number): Partial<TriageDetails> | null {
	if (
		buf.length < 8 ||
		buf[0] !== 0x64 ||
		buf[1] !== 0x65 ||
		buf[2] !== 0x78 ||
		buf[3] !== 0x0a // "dex\n"
	) {
		return null;
	}
	const ver = new TextDecoder("ascii").decode(buf.subarray(4, 7));
	if (buf.length < 112) {
		return {
			format: "DEX (truncated)",
			status: "corrupt",
			indicators: ["truncated_dex_header"],
		};
	}
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const stringIdsSize = view.getUint32(0x38, true);
	const typeIdsSize = view.getUint32(0x40, true);
	const protoIdsSize = view.getUint32(0x48, true);
	const fieldIdsSize = view.getUint32(0x50, true);
	const methodIdsSize = view.getUint32(0x58, true);
	const classDefsSize = view.getUint32(0x60, true);

	const sections: TriageSectionSummary[] = [
		{ name: "classes", size: classDefsSize },
		{ name: "methods", size: methodIdsSize },
		{ name: "fields", size: fieldIdsSize },
		{ name: "strings", size: stringIdsSize },
		{ name: "types", size: typeIdsSize },
		{ name: "protos", size: protoIdsSize },
	];

	return {
		format: "DEX",
		subformat: `Dalvik Executable format (dex v${ver})`,
		arch: "Dalvik / ART VM",
		bits: 32,
		endian: "little",
		sections,
		indicators: [`dex_v${ver}`, `${classDefsSize}_classes`, `${methodIdsSize}_methods`],
		hints: [
			"Target is a raw DEX file. Use dexdump or jadx (jadx -d ./artifacts/jadx_out <target.dex>) to decompile.",
			"Note: droidasc requires a packaged .apk; for raw .dex use jadx.",
		],
	};
}

/** Parse Java Class file headers. */
function parseJavaClass(buf: Uint8Array, _fileSize: number): Partial<TriageDetails> | null {
	if (
		buf.length < 4 ||
		buf[0] !== 0xca ||
		buf[1] !== 0xfe ||
		buf[2] !== 0xba ||
		buf[3] !== 0xbe // "\xca\xfe\xba\xbe"
	) {
		return null;
	}
	if (buf.length < 8) {
		return {
			format: "Java Class (truncated)",
			status: "corrupt",
			indicators: ["truncated_class_header"],
		};
	}
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
	const minor = view.getUint16(4, false);
	const major = view.getUint16(6, false);
	if (major < 45 || major > 100) return null;

	let cpCount = 0;
	if (buf.length >= 10) {
		cpCount = view.getUint16(8, false);
	}

	const JAVA_VERSIONS: Record<number, string> = {
		45: "Java 1.1",
		46: "Java 1.2",
		47: "Java 1.3",
		48: "Java 1.4",
		49: "Java 5",
		50: "Java 6",
		51: "Java 7",
		52: "Java 8",
		53: "Java 9",
		54: "Java 10",
		55: "Java 11",
		56: "Java 12",
		57: "Java 13",
		58: "Java 14",
		59: "Java 15",
		60: "Java 16",
		61: "Java 17",
		62: "Java 18",
		63: "Java 19",
		64: "Java 20",
		65: "Java 21",
		66: "Java 22",
		67: "Java 23",
		68: "Java 24",
		69: "Java 25",
	};
	const javaVer = JAVA_VERSIONS[major] ?? `Java (class version ${major}.${minor})`;

	return {
		format: "Java Class",
		subformat: `Java Class File (${javaVer}, ${major}.${minor})`,
		arch: "JVM Bytecode",
		endian: "big",
		sections: cpCount > 0 ? [{ name: "constant_pool", size: cpCount }] : [],
		indicators: [`java_major_${major}`],
		hints: ["Target is a compiled Java class. Decompile with jadx or javap."],
	};
}

/** Parse ZIP / APK / JAR archives. */
function parseZipOrApk(buf: Uint8Array, _fileSize: number, requestedPath = ""): Partial<TriageDetails> | null {
	if (buf.length < 4) return null;
	if (
		(buf[0] !== 0x50 || buf[1] !== 0x4b || buf[2] !== 0x03 || buf[3] !== 0x04) &&
		(buf[0] !== 0x50 || buf[1] !== 0x4b || buf[2] !== 0x05 || buf[3] !== 0x06)
	) {
		return null;
	}

	let isApk = requestedPath.toLowerCase().endsWith(".apk");
	let isJar = requestedPath.toLowerCase().endsWith(".jar");
	const entries: TriageSectionSummary[] = [];
	let offset = 0;
	const maxScan = Math.min(buf.length, 64 * 1024);
	const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

	while (offset + 30 <= maxScan && entries.length < 50) {
		if (buf[offset] !== 0x50 || buf[offset + 1] !== 0x4b || buf[offset + 2] !== 0x03 || buf[offset + 3] !== 0x04) {
			break;
		}
		const compSize = view.getUint32(offset + 18, true);
		const uncompSize = view.getUint32(offset + 22, true);
		const fnLen = view.getUint16(offset + 26, true);
		const extraLen = view.getUint16(offset + 28, true);

		if (offset + 30 + fnLen > buf.length) break;
		const fnBytes = buf.subarray(offset + 30, offset + 30 + fnLen);
		const filename = new TextDecoder("utf8", { fatal: false }).decode(fnBytes);

		if (filename === "AndroidManifest.xml" || filename.endsWith(".dex")) {
			isApk = true;
		}
		if (filename.startsWith("META-INF/")) {
			isJar = true;
		}

		entries.push({
			name: filename,
			size: uncompSize,
			offset,
		});

		offset += 30 + fnLen + extraLen + compSize;
	}

	if (isApk) {
		return {
			format: "APK",
			subformat: "Android Application Package (ZIP)",
			sections: entries,
			indicators: ["android_apk"],
			hints: [
				'Target is an Android APK package. Use droidasc(op: "manifest", target: "...") to inspect AndroidManifest.xml.',
				'Use droidasc(op: "listclass" | "findrefs" | "getclass", target: "...") for on-demand DEX queries and decompilation.',
			],
		};
	}

	if (isJar) {
		return {
			format: "JAR",
			subformat: "Java Archive (ZIP)",
			sections: entries,
			indicators: ["java_archive"],
			hints: ["Target is a Java archive (JAR). Classes inside can be inspected with decompiler tooling."],
		};
	}

	return {
		format: "ZIP",
		subformat: "ZIP Archive",
		sections: entries,
		indicators: ["zip_archive"],
	};
}

/** Render model-facing concise triage report text. */
function renderTriageReport(details: TriageDetails, requestedPath: string, limit: number, minLength: number): string {
	const lines: string[] = [];
	const parts: string[] = [];
	if (details.subformat) parts.push(details.subformat);
	else parts.push(details.format);
	if (details.arch) parts.push(details.arch);
	if (details.bits) parts.push(`${details.bits}-bit`);
	if (details.endian) parts.push(`${details.endian}-endian`);
	parts.push(`${details.size.toLocaleString("en-US")} bytes`);

	lines.push(`Triage: ${requestedPath} (${parts.join(", ")})`);
	lines.push(`SHA-256: ${details.sha256}`);
	if (details.entrypoint) {
		lines.push(`Entrypoint: ${details.entrypoint}`);
	}

	const entropyDesc = `${details.entropy.overall} bits/byte (${details.entropy.sampled ? "sampled" : "full"})`;
	const indDesc = details.indicators.length > 0 ? details.indicators.join(", ") : "none";
	lines.push(`Entropy: ${entropyDesc} | Indicators: ${indDesc}`);

	if (details.sections && details.sections.length > 0) {
		lines.push(`\nSections / Entries (${details.sections.length}):`);
		for (const sec of details.sections) {
			const detailsPart: string[] = [];
			detailsPart.push(`size: ${sec.size.toLocaleString("en-US")} B`);
			if (sec.virtualSize !== undefined) {
				detailsPart.push(`vsize: 0x${sec.virtualSize.toString(16)}`);
			}
			if (sec.offset !== undefined) {
				detailsPart.push(`offset: 0x${sec.offset.toString(16)}`);
			}
			if (sec.entropy !== undefined) {
				detailsPart.push(`entropy: ${sec.entropy}`);
			}
			lines.push(`  ${sec.name.padEnd(20)} ${detailsPart.join("  ")}`);
		}
	}

	if (details.strings && details.strings.length > 0) {
		const total = details.totalStrings ?? details.strings.length;
		lines.push(`\nStrings (${details.strings.length} shown of ${total}, min length ${minLength}):`);
		for (const str of details.strings) {
			lines.push(`  0x${str.offset.toString(16).padStart(8, "0")}: "${str.text}" (${str.encoding})`);
		}
		if (details.stringsTruncated) {
			lines.push(
				`… ${total - details.strings.length} more strings; raise limit (up to ${MAX_LIST_LIMIT}) or scan with specific min_length.`,
			);
			if (details.artifactId) {
				lines.push(`[raw strings: artifact://${details.artifactId}]`);
			}
		}
	}

	if (details.hints && details.hints.length > 0) {
		lines.push(`\nHints:`);
		for (const hint of details.hints) {
			lines.push(`  - ${hint}`);
		}
	}

	return lines.join("\n");
}

export class TriageTool implements AgentTool<typeof triageSchema, TriageDetails> {
	readonly name = "triage";
	readonly approval: ToolTier = "read";
	readonly label = "Triage";
	readonly summary =
		"Multi-format binary, archive, and artifact reconnaissance (PE, ELF, Mach-O, WASM, APK, DEX, Java Class, ZIP)";
	readonly description: string;
	readonly parameters = triageSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(triageDescription);
	}

	async execute(
		_toolCallId: string,
		params: TriageParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<TriageDetails>> {
		throwIfAborted(signal);
		const requestedPath = params.path?.trim() || params.target?.trim() || "";
		if (requestedPath.length === 0) {
			throw new ToolError("path or target is required");
		}
		const absolutePath = resolveReadPath(requestedPath, this.session.cwd);
		let fileStat: Stats;
		try {
			fileStat = await stat(absolutePath);
		} catch {
			throw new ToolError(`Target not found: ${requestedPath}`);
		}
		if (fileStat.isDirectory()) {
			throw new ToolError(`Target is a directory, not a regular file: ${requestedPath}`);
		}
		if (!fileStat.isFile()) {
			throw new ToolError(`Not a regular file: ${requestedPath}`);
		}
		if (fileStat.size > MAX_FILE_BYTES) {
			throw new ToolError(
				`Target file size (${fileStat.size} bytes) exceeds maximum triage limit of ${MAX_FILE_BYTES} bytes`,
			);
		}

		throwIfAborted(signal);

		const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, Math.floor(params.limit ?? DEFAULT_LIST_LIMIT)));
		const minLength = Math.max(MIN_STRING_MIN_LENGTH, Math.floor(params.min_length ?? DEFAULT_STRING_MIN_LENGTH));
		const maxBytes = Math.min(MAX_FILE_BYTES, Math.max(1024, Math.floor(params.max_bytes ?? DEFAULT_MAX_BYTES)));
		const scanStrings = params.strings === true;

		let analysis: StreamAnalysisResult;
		try {
			analysis = await analyzeFileStream(absolutePath, fileStat.size, maxBytes, scanStrings, maxBytes, signal);
		} catch (err) {
			if (err instanceof ToolError || (err instanceof Error && err.name === "ToolAbortError")) {
				throw err;
			}
			throw new ToolError(
				`Failed to read and analyze ${requestedPath}: ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		throwIfAborted(signal);

		// Format parsing from sniffBuffer
		const sniff = analysis.sniffBuffer;
		let parsed: Partial<TriageDetails> | null = null;

		if (fileStat.size === 0) {
			parsed = {
				format: "empty",
				subformat: "Empty file (0 bytes)",
				indicators: ["empty_file"],
			};
		} else {
			try {
				parsed =
					parsePe(sniff, fileStat.size) ??
					parseElf(sniff, fileStat.size) ??
					parseMachO(sniff, fileStat.size) ??
					parseJavaClass(sniff, fileStat.size) ??
					parseWasm(sniff, fileStat.size) ??
					parseDex(sniff, fileStat.size) ??
					parseZipOrApk(sniff, fileStat.size, requestedPath) ??
					null;
			} catch {
				parsed = {
					format: "corrupt",
					status: "corrupt",
					indicators: ["parser_exception"],
				};
			}
		}

		const format = parsed?.format ?? "unknown";
		const status = parsed?.status ?? "ok";
		const indicators = [...(parsed?.indicators ?? [])];
		if (analysis.entropy >= HIGH_ENTROPY_THRESHOLD) {
			if (!indicators.includes("high_entropy")) {
				indicators.push("high_entropy");
			}
		}

		let extractedStrings: TriageStringEntry[] | undefined;
		let totalStrings: number | undefined;
		let stringsTruncated = false;
		let artifactId: string | undefined;

		if (scanStrings && analysis.stringsBuffer) {
			const res = extractPrintableStrings(analysis.stringsBuffer, minLength, limit);
			extractedStrings = res.strings;
			totalStrings = res.totalStrings;
			stringsTruncated = totalStrings > limit;

			if (stringsTruncated && this.session.allocateOutputArtifact) {
				try {
					const alloc = await this.session.allocateOutputArtifact("triage");
					if (alloc?.path && alloc.id) {
						const lines = res.allExtracted.map(
							s => `0x${s.offset.toString(16).padStart(8, "0")}: "${s.text}" (${s.encoding})`,
						);
						await Bun.write(alloc.path, lines.join("\n"));
						artifactId = alloc.id;
					}
				} catch {
					// Ignore artifact allocation failure
				}
			}
		}

		const details: TriageDetails = {
			path: requestedPath,
			status,
			size: fileStat.size,
			sha256: analysis.sha256,
			format,
			subformat: parsed?.subformat,
			arch: parsed?.arch,
			bits: parsed?.bits,
			endian: parsed?.endian,
			entrypoint: parsed?.entrypoint,
			sections: parsed?.sections ? parsed.sections.slice(0, limit) : undefined,
			entropy: {
				overall: analysis.entropy,
				sampled: analysis.sampled,
				highEntropy: analysis.entropy >= HIGH_ENTROPY_THRESHOLD,
			},
			indicators,
			hints: parsed?.hints,
			strings: extractedStrings,
			totalStrings,
			stringsTruncated: stringsTruncated || undefined,
			artifactId,
		};

		const reportText = renderTriageReport(details, requestedPath, limit, minLength);

		return {
			content: [{ type: "text", text: reportText }],
			details,
		};
	}
}
