import * as fs from "node:fs/promises";
import { type Stats } from "node:fs";
import * as path from "node:path";
import * as zlib from "node:zlib";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import binaryMetadataInspectDescription from "../prompts/tools/binary-metadata-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024; // 64 MB
const HARD_MAX_BYTES = 256 * 1024 * 1024; // 256 MB

// ============================================================================
// Parameter Schema
// ============================================================================

const binaryMetadataInspectSchema = type({
	action: type
		.enumerated("info", "go", "rust", "sections")
		.describe(
			"Inspection action: info (high-level metadata summary, format, detected compiler/language, Go/Rust markers), go (detailed Go module path, runtime version, build settings, and dependencies), rust (detailed Rust cargo-auditable dependency packages, rustc version, and runtime hints), or sections (binary sections and metadata markers)",
		),
	path: type("string").describe("Path to target binary (ELF, PE, Mach-O, or raw executable)"),
	"filter?": type("string").describe(
		"Optional case-insensitive substring filter for dependencies, crates, or modules",
	),
	"limit?": type("number.integer >= 1").describe(
		"Maximum dependency or package records to return (default 50, max 500)",
	),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
	"max_bytes?": type("number.integer >= 1").describe("Maximum binary bytes to inspect (default 64MB, max 256MB)"),
});

export type BinaryMetadataInspectParams = typeof binaryMetadataInspectSchema.infer;
export type BinaryMetadataInspectAction = BinaryMetadataInspectParams["action"];

// ============================================================================
// Data Models
// ============================================================================

export interface GoDependencyInfo {
	path: string;
	version?: string;
	sum?: string;
	replacedBy?: string;
}

export interface GoBuildInfo {
	runtimeVersion?: string;
	modulePath?: string;
	mainPackage?: string;
	compiler?: string;
	buildSettings: Record<string, string>;
	dependencies: GoDependencyInfo[];
	totalDependencies: number;
	pclntabVersion?: string;
	hasGoBuildInfoMagic: boolean;
}

export interface RustPackageInfo {
	name: string;
	version: string;
	source?: string;
	kind?: string;
	root?: boolean;
	dependencies?: Array<number | string>;
}

export interface RustAuditInfo {
	cargoAuditable: boolean;
	rustcVersion?: string;
	rustcCommit?: string;
	panicStrategy?: "unwind" | "abort" | "unknown";
	allocator?: "jemalloc" | "mimalloc" | "system" | "unknown";
	packages: RustPackageInfo[];
	totalPackages: number;
	detectedCrates: string[];
}

export interface BinarySectionInfo {
	index: number;
	name: string;
	offset: number;
	size: number;
	virtualAddress?: string;
	flags?: string;
	markerType?: "go" | "rust" | "standard";
}

export interface BinaryMetadataInspectDetails {
	action: BinaryMetadataInspectAction;
	path: string;
	fileSize: number;
	format: "elf" | "pe" | "macho" | "universal" | "unknown";
	architecture?: string;
	bitness?: 32 | 64;
	endianness?: "little" | "big";
	language: "go" | "rust" | "both" | "unknown";
	isGo: boolean;
	isRust: boolean;
	go?: GoBuildInfo;
	rust?: RustAuditInfo;
	sections?: BinarySectionInfo[];
	totalSections?: number;
	unsupportedReason?: string;
}

// ============================================================================
// Parser Implementations
// ============================================================================

const GO_BUILDINF_MAGIC = Buffer.from("\xff Go buildinf:");
const PCLNTAB_MAGIC_V12 = Buffer.from([0xfb, 0xff, 0xff, 0xff]);
const PCLNTAB_MAGIC_V16 = Buffer.from([0xfa, 0xff, 0xff, 0xff]);
const PCLNTAB_MAGIC_V18 = Buffer.from([0xf0, 0xff, 0xff, 0xff]);
const PCLNTAB_MAGIC_V20 = Buffer.from([0xf2, 0xff, 0xff, 0xff]);

interface ParsedContainer {
	format: "elf" | "pe" | "macho" | "universal" | "unknown";
	architecture?: string;
	bitness?: 32 | 64;
	endianness?: "little" | "big";
	sections: BinarySectionInfo[];
}

/** Detects container format and extracts section headers if present. */
function parseContainer(buffer: Buffer): ParsedContainer {
	if (buffer.length >= 4 && buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) {
		// ELF
		const is64 = buffer[4] === 2;
		const isLe = buffer[5] === 1;
		const bitness = is64 ? 64 : 32;
		const endianness = isLe ? "little" : "big";
		const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
		const eMachine = view.getUint16(18, isLe);
		let architecture = `machine-0x${eMachine.toString(16)}`;
		if (eMachine === 3) architecture = "x86";
		else if (eMachine === 62) architecture = "x86_64";
		else if (eMachine === 40) architecture = "arm";
		else if (eMachine === 183) architecture = "aarch64";
		else if (eMachine === 8) architecture = "mips";
		else if (eMachine === 243) architecture = "riscv";

		const sections: BinarySectionInfo[] = [];
		const shOff = is64 ? Number(view.getBigUint64(40, isLe)) : view.getUint32(32, isLe);
		const shEntSize = view.getUint16(is64 ? 58 : 46, isLe);
		const shNum = view.getUint16(is64 ? 60 : 48, isLe);
		const shStrNdx = view.getUint16(is64 ? 62 : 50, isLe);

		if (shOff > 0 && shEntSize >= (is64 ? 64 : 40) && shNum > 0 && shOff + shNum * shEntSize <= buffer.length) {
			let strTabOffset = 0;
			let strTabSize = 0;
			if (shStrNdx < shNum) {
				const strHeaderPos = shOff + shStrNdx * shEntSize;
				strTabOffset = is64
					? Number(view.getBigUint64(strHeaderPos + 24, isLe))
					: view.getUint32(strHeaderPos + 16, isLe);
				strTabSize = is64
					? Number(view.getBigUint64(strHeaderPos + 32, isLe))
					: view.getUint32(strHeaderPos + 20, isLe);
			}

			const getString = (offset: number): string => {
				if (!strTabOffset || offset >= strTabSize || strTabOffset + offset >= buffer.length) return "";
				let end = strTabOffset + offset;
				while (end < buffer.length && buffer[end] !== 0 && end - (strTabOffset + offset) < 128) end++;
				return buffer.toString("utf8", strTabOffset + offset, end);
			};

			for (let i = 0; i < shNum; i++) {
				const pos = shOff + i * shEntSize;
				const nameOffset = view.getUint32(pos, isLe);
				const secOffset = is64 ? Number(view.getBigUint64(pos + 24, isLe)) : view.getUint32(pos + 16, isLe);
				const secSize = is64 ? Number(view.getBigUint64(pos + 32, isLe)) : view.getUint32(pos + 20, isLe);
				const secAddr = is64 ? view.getBigUint64(pos + 16, isLe) : BigInt(view.getUint32(pos + 12, isLe));
				const name = getString(nameOffset) || `sec_${i}`;

				let markerType: "go" | "rust" | "standard" = "standard";
				if (name.includes("go.") || name.includes("gopclntab") || name.includes("gosymtab")) {
					markerType = "go";
				} else if (name.includes("dep-v0") || name.includes("rust") || name.includes("rmeta")) {
					markerType = "rust";
				}

				sections.push({
					index: i,
					name,
					offset: secOffset,
					size: secSize,
					virtualAddress: `0x${secAddr.toString(16)}`,
					markerType,
				});
			}
		}

		return { format: "elf", architecture, bitness, endianness, sections };
	}

	if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
		// PE
		const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
		const eLfanew = view.getUint32(0x3c, true);
		if (eLfanew + 24 <= buffer.length && buffer[eLfanew] === 0x50 && buffer[eLfanew + 1] === 0x45) {
			const machine = view.getUint16(eLfanew + 4, true);
			const numSections = view.getUint16(eLfanew + 6, true);
			const sizeOfOptHeader = view.getUint16(eLfanew + 20, true);
			const magic = sizeOfOptHeader >= 2 ? view.getUint16(eLfanew + 24, true) : 0;
			const is64 = magic === 0x20b;
			const bitness = is64 ? 64 : 32;
			let architecture = `machine-0x${machine.toString(16)}`;
			if (machine === 0x14c) architecture = "x86";
			else if (machine === 0x8664) architecture = "x86_64";
			else if (machine === 0xaa64) architecture = "arm64";

			const sections: BinarySectionInfo[] = [];
			const secTablePos = eLfanew + 24 + sizeOfOptHeader;
			const secEntrySize = 40;
			if (secTablePos + numSections * secEntrySize <= buffer.length) {
				for (let i = 0; i < numSections; i++) {
					const pos = secTablePos + i * secEntrySize;
					let name = "";
					for (let n = 0; n < 8; n++) {
						const b = buffer[pos + n];
						if (b === 0) break;
						name += String.fromCharCode(b);
					}
					const secSize = view.getUint32(pos + 16, true);
					const secOffset = view.getUint32(pos + 20, true);
					const secAddr = view.getUint32(pos + 12, true);

					let markerType: "go" | "rust" | "standard" = "standard";
					if (name.includes("go") || name.includes("buildinf")) markerType = "go";
					else if (name.includes("dep-v0") || name.includes("rust")) markerType = "rust";

					sections.push({
						index: i,
						name,
						offset: secOffset,
						size: secSize,
						virtualAddress: `0x${secAddr.toString(16)}`,
						markerType,
					});
				}
			}

			return { format: "pe", architecture, bitness, endianness: "little", sections };
		}
	}

	if (buffer.length >= 4) {
		const magic32LE = buffer.readUInt32LE(0);
		const magic32BE = buffer.readUInt32BE(0);
		const isMachO =
			magic32LE === 0xfeedface || magic32LE === 0xfeedfacf || magic32BE === 0xfeedface || magic32BE === 0xfeedfacf;
		const isFat =
			magic32LE === 0xcafebabe || magic32LE === 0xbebafeca || magic32BE === 0xcafebabe || magic32BE === 0xbebafeca;

		if (isFat) {
			return { format: "universal", architecture: "fat/universal", sections: [] };
		}

		if (isMachO) {
			const is64 = magic32LE === 0xfeedfacf || magic32BE === 0xfeedfacf;
			const isLe = magic32LE === 0xfeedface || magic32LE === 0xfeedfacf;
			const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
			const cpuType = view.getUint32(4, isLe);
			let architecture = `cpu-0x${cpuType.toString(16)}`;
			if (cpuType === 7) architecture = "x86";
			else if (cpuType === 0x01000007) architecture = "x86_64";
			else if (cpuType === 12) architecture = "arm";
			else if (cpuType === 0x0100000c) architecture = "arm64";

			const sections: BinarySectionInfo[] = [];
			const ncmds = view.getUint32(16, isLe);
			let cmdOffset = is64 ? 32 : 28;

			for (let i = 0; i < ncmds && cmdOffset + 8 <= buffer.length; i++) {
				const cmd = view.getUint32(cmdOffset, isLe);
				const cmdSize = view.getUint32(cmdOffset + 4, isLe);
				if (cmdSize < 8 || cmdOffset + cmdSize > buffer.length) break;

				// LC_SEGMENT (1) or LC_SEGMENT_64 (0x19)
				if ((is64 && cmd === 0x19) || (!is64 && cmd === 0x01)) {
					const numSects = view.getUint32(cmdOffset + (is64 ? 64 : 48), isLe);
					let sectOffset = cmdOffset + (is64 ? 72 : 56);
					const sectHeaderSize = is64 ? 80 : 68;

					for (let s = 0; s < numSects && sectOffset + sectHeaderSize <= cmdOffset + cmdSize; s++) {
						let sectName = "";
						for (let n = 0; n < 16; n++) {
							const b = buffer[sectOffset + n];
							if (b === 0) break;
							sectName += String.fromCharCode(b);
						}
						const sAddr = is64
							? view.getBigUint64(sectOffset + 32, isLe)
							: BigInt(view.getUint32(sectOffset + 32, isLe));
						const sSize = is64
							? Number(view.getBigUint64(sectOffset + 40, isLe))
							: view.getUint32(sectOffset + 36, isLe);
						const sOff = view.getUint32(sectOffset + (is64 ? 48 : 40), isLe);

						let markerType: "go" | "rust" | "standard" = "standard";
						if (sectName.includes("go") || sectName.includes("gopclntab")) markerType = "go";
						else if (sectName.includes("dep_v0") || sectName.includes("dep-v0") || sectName.includes("rust"))
							markerType = "rust";

						sections.push({
							index: sections.length,
							name: sectName,
							offset: sOff,
							size: sSize,
							virtualAddress: `0x${sAddr.toString(16)}`,
							markerType,
						});
						sectOffset += sectHeaderSize;
					}
				}
				cmdOffset += cmdSize;
			}

			return {
				format: "macho",
				architecture,
				bitness: is64 ? 64 : 32,
				endianness: isLe ? "little" : "big",
				sections,
			};
		}
	}

	return { format: "unknown", sections: [] };
}

// ============================================================================
// Go Metadata Extraction
// ============================================================================

export function inspectGoBuildInfo(buffer: Buffer): GoBuildInfo | undefined {
	const buildSettings: Record<string, string> = {};
	const dependencies: GoDependencyInfo[] = [];
	let modulePath: string | undefined;
	let mainPackage: string | undefined;
	let runtimeVersion: string | undefined;
	let pclntabVersion: string | undefined;

	// 1. Check for Go buildinfo magic
	const magicIdx = buffer.indexOf(GO_BUILDINF_MAGIC);
	const hasGoBuildInfoMagic = magicIdx !== -1;

	// 2. Check for pclntab magic
	if (buffer.includes(PCLNTAB_MAGIC_V20)) {
		pclntabVersion = "go1.20+";
	} else if (buffer.includes(PCLNTAB_MAGIC_V18)) {
		pclntabVersion = "go1.18";
	} else if (buffer.includes(PCLNTAB_MAGIC_V16)) {
		pclntabVersion = "go1.16";
	} else if (buffer.includes(PCLNTAB_MAGIC_V12)) {
		pclntabVersion = "go1.2";
	}

	// 3. Search for runtime version strings e.g. "go1.21.5" or "go1.22"
	const goVersionRegex = /\bgo1\.[0-9]+(?:\.[0-9]+)?(?:[a-zA-Z0-9.\-_]+)?\b/g;
	const bufStr = buffer.toString("binary");
	const versionMatches = bufStr.match(goVersionRegex);
	if (versionMatches && versionMatches.length > 0) {
		// Prefer the shortest clean standard version string e.g. "go1.22.4"
		const clean = versionMatches.find(v => /^go1\.[0-9]+(?:\.[0-9]+)?$/.test(v)) ?? versionMatches[0];
		runtimeVersion = clean;
	}

	// 4. Search for Go module table lines
	// Standard runtime/debug.BuildInfo format:
	// path\t<modpath>\n
	// mod\t<path>\t<ver>\t<hash>\n
	// dep\t<path>\t<ver>\t<hash>\n
	// =>\t<path>\t<ver>\t<hash>\n
	// build\t<key>=<value>\n
	const pathIdx = buffer.indexOf(Buffer.from("path\t"));
	const buildIdx = buffer.indexOf(Buffer.from("build\t"));
	const depIdx = buffer.indexOf(Buffer.from("dep\t"));

	let foundModuleTable = false;
	const candidateOffsets = [pathIdx, buildIdx, depIdx].filter(idx => idx !== -1);
	if (candidateOffsets.length > 0) {
		const startOffset = Math.min(...candidateOffsets);
		// Read a slice of up to 512KB for module data
		const tableSlice = buffer.subarray(startOffset, Math.min(buffer.length, startOffset + 512 * 1024));
		const text = tableSlice.toString("utf8");
		const lines = text.split("\n");

		for (const line of lines) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			const parts = trimmed.split("\t");
			const cmd = parts[0];

			if (cmd === "path" && parts[1]) {
				modulePath = parts[1];
				mainPackage = parts[1];
				foundModuleTable = true;
			} else if (cmd === "mod" && parts[1]) {
				modulePath = parts[1];
				foundModuleTable = true;
			} else if (cmd === "dep" && parts[1]) {
				foundModuleTable = true;
				dependencies.push({
					path: parts[1],
					version: parts[2] || undefined,
					sum: parts[3] || undefined,
				});
			} else if (cmd === "=>" && parts[1]) {
				// Replaces previous dependency
				if (dependencies.length > 0) {
					dependencies[dependencies.length - 1].replacedBy = parts[1] + (parts[2] ? `@${parts[2]}` : "");
				}
			} else if (cmd === "build" && parts[1]) {
				foundModuleTable = true;
				const eqIdx = parts[1].indexOf("=");
				if (eqIdx !== -1) {
					const k = parts[1].slice(0, eqIdx);
					const v = parts[1].slice(eqIdx + 1);
					buildSettings[k] = v;
				}
			}
		}
	}

	// 5. Look for compiler indicators
	let compiler = buildSettings["-compiler"] || "gc";
	if (buffer.indexOf(Buffer.from("runtime.main")) !== -1 || buffer.indexOf(Buffer.from("runtime.goexit")) !== -1) {
		compiler = compiler || "gc";
	}

	if (!hasGoBuildInfoMagic && !foundModuleTable && !pclntabVersion && !runtimeVersion) {
		return undefined;
	}

	return {
		runtimeVersion,
		modulePath,
		mainPackage,
		compiler,
		buildSettings,
		dependencies,
		totalDependencies: dependencies.length,
		pclntabVersion,
		hasGoBuildInfoMagic,
	};
}

// ============================================================================
// Rust Metadata Extraction
// ============================================================================

export function inspectRustAuditInfo(buffer: Buffer, sections: BinarySectionInfo[]): RustAuditInfo | undefined {
	let cargoAuditable = false;
	const packages: RustPackageInfo[] = [];
	let rustcVersion: string | undefined;
	let rustcCommit: string | undefined;
	let panicStrategy: "unwind" | "abort" | "unknown" = "unknown";
	let allocator: "jemalloc" | "mimalloc" | "system" | "unknown" = "unknown";
	const detectedCratesSet = new Set<string>();

	// 1. Check sections for cargo-auditable: .dep-v0 or __dep_v0
	const depSection = sections.find(s => s.name === ".dep-v0" || s.name === "__dep_v0");
	let depData: Buffer | undefined;

	if (depSection && depSection.offset > 0 && depSection.offset + depSection.size <= buffer.length) {
		depData = buffer.subarray(depSection.offset, depSection.offset + depSection.size);
	} else {
		// Scan for .dep-v0 signature: 0x01 followed by zlib header 0x78 (0x9c, 0x01, 0xda, 0x5e)
		for (let i = 0; i < Math.min(buffer.length - 8, 32 * 1024 * 1024); i++) {
			if (
				buffer[i] === 0x01 &&
				buffer[i + 1] === 0x78 &&
				(buffer[i + 2] === 0x9c || buffer[i + 2] === 0x01 || buffer[i + 2] === 0xda)
			) {
				depData = buffer.subarray(i);
				break;
			}
		}
	}

	if (depData && depData.length > 2) {
		try {
			// Skip 1-byte version header (0x01)
			const decompressed = zlib.inflateSync(depData.subarray(1));
			const parsed = JSON.parse(decompressed.toString("utf8"));
			if (parsed && Array.isArray(parsed.packages)) {
				cargoAuditable = true;
				for (const pkg of parsed.packages) {
					if (typeof pkg.name === "string") {
						packages.push({
							name: pkg.name,
							version: pkg.version ?? "unknown",
							source: pkg.source,
							kind: pkg.kind,
							root: pkg.root,
							dependencies: pkg.dependencies,
						});
						detectedCratesSet.add(pkg.name);
					}
				}
			}
		} catch {
			// Not valid zlib or JSON
		}
	}

	// 2. Extract rustc commit hash: /rustc/<40-hex-chars>/
	const rustcCommitRegex = /\/rustc\/([0-9a-f]{40})\//;
	const bufBinary = buffer.toString("binary");
	const commitMatch = bufBinary.match(rustcCommitRegex);
	if (commitMatch && commitMatch[1]) {
		rustcCommit = commitMatch[1];
	}

	// 3. Extract rustc version string e.g. "rustc 1.77.2"
	const rustcVersionRegex = /\brustc\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9.\-_]+)?)\b/;
	const versionMatch = bufBinary.match(rustcVersionRegex);
	if (versionMatch && versionMatch[1]) {
		rustcVersion = versionMatch[1];
	}

	// 4. Panic runtime heuristics
	if (bufBinary.includes("panic_unwind") || bufBinary.includes("library/std/src/panicking.rs")) {
		panicStrategy = "unwind";
	} else if (bufBinary.includes("panic_abort") || bufBinary.includes("rust_begin_unwind")) {
		panicStrategy = "abort";
	}

	// 5. Memory allocator heuristics
	if (bufBinary.includes("je_malloc") || bufBinary.includes("jemalloc")) {
		allocator = "jemalloc";
	} else if (bufBinary.includes("mi_malloc") || bufBinary.includes("mimalloc")) {
		allocator = "mimalloc";
	} else if (bufBinary.includes("rust_oom") || bufBinary.includes("__rust_alloc")) {
		allocator = "system";
	}

	// 6. Common crates heuristics from symbols/paths if not auditable
	const commonCrates = [
		"tokio",
		"serde",
		"reqwest",
		"clap",
		"syn",
		"quote",
		"anyhow",
		"thiserror",
		"tracing",
		"hyper",
		"regex",
		"rand",
		"log",
		"axum",
		"actix",
		"bytes",
		"futures",
	];
	for (const crateName of commonCrates) {
		if (bufBinary.includes(`${crateName}::`) || bufBinary.includes(`/${crateName}-`)) {
			detectedCratesSet.add(crateName);
		}
	}

	const hasRustMarkers =
		cargoAuditable ||
		Boolean(rustcCommit) ||
		Boolean(rustcVersion) ||
		bufBinary.includes("rust_eh_personality") ||
		bufBinary.includes("core::panicking::panic") ||
		bufBinary.includes("RUST_BACKTRACE");

	if (!hasRustMarkers && detectedCratesSet.size === 0) {
		return undefined;
	}

	return {
		cargoAuditable,
		rustcVersion,
		rustcCommit,
		panicStrategy,
		allocator,
		packages,
		totalPackages: packages.length,
		detectedCrates: Array.from(detectedCratesSet).sort(),
	};
}

// ============================================================================
// Main Tool Implementation
// ============================================================================

export class BinaryMetadataInspectTool implements AgentTool<
	typeof binaryMetadataInspectSchema,
	BinaryMetadataInspectDetails
> {
	readonly name = "binary_metadata_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Binary Metadata Inspect (Go/Rust)";
	readonly summary = "Native offline read-only Go and Rust binary metadata inspection without execution.";
	readonly description = binaryMetadataInspectDescription;
	readonly parameters = binaryMetadataInspectSchema;
	readonly loadMode = "discoverable";
	readonly strict = true;

	constructor(private readonly session: ToolSession) {}

	async execute(
		_toolCallId: string,
		params: BinaryMetadataInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<BinaryMetadataInspectDetails>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<BinaryMetadataInspectDetails> & { details: BinaryMetadataInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);
		let fileStat: Stats;
		try {
			fileStat = await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(`File not found: ${params.path} (${err instanceof Error ? err.message : String(err)})`);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Path is a directory, not a binary file: ${params.path}. Use a valid executable binary.`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
		const bytesToRead = Math.min(fileStat.size, maxBytes);

		let buffer: Buffer;
		try {
			const fh = await fs.open(resolvedPath, "r");
			try {
				buffer = Buffer.alloc(bytesToRead);
				const { bytesRead } = await fh.read(buffer, 0, bytesToRead, 0);
				buffer = buffer.subarray(0, bytesRead);
			} finally {
				await fh.close();
			}
		} catch (err) {
			throw new ToolError(
				`Failed to read binary ${params.path}: ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		throwIfAborted(signal);

		const container = parseContainer(buffer);
		const goInfo = inspectGoBuildInfo(buffer);
		const rustInfo = inspectRustAuditInfo(buffer, container.sections);

		const isGo = Boolean(goInfo);
		const isRust = Boolean(rustInfo);
		let language: "go" | "rust" | "both" | "unknown" = "unknown";
		if (isGo && isRust) language = "both";
		else if (isGo) language = "go";
		else if (isRust) language = "rust";

		const action = params.action;
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;
		const filter = params.filter?.toLowerCase();

		// ------------------------------------------------------------------------
		// Action: info
		// ------------------------------------------------------------------------
		if (action === "info") {
			const lines = [
				`# Binary Metadata: \`${path.basename(resolvedPath)}\``,
				"",
				`| Property | Value |`,
				`|---|---|`,
				`| **File Size** | ${formatBytes(fileStat.size)} |`,
				`| **Format** | \`${container.format.toUpperCase()}\` |`,
				`| **Architecture** | \`${container.architecture ?? "unknown"}\` |`,
				`| **Bitness** | ${container.bitness ? `${container.bitness}-bit` : "unknown"} |`,
				`| **Endianness** | \`${container.endianness ?? "unknown"}\` |`,
				`| **Detected Language** | **${language.toUpperCase()}** |`,
				`| **Binary Sections** | ${container.sections.length} |`,
			];

			if (isGo && goInfo) {
				lines.push(
					"",
					"## Go Metadata Summary",
					`| Go Property | Value |`,
					`|---|---|`,
					`| **Go Runtime Version** | \`${goInfo.runtimeVersion ?? "unknown"}\` |`,
					`| **Main Module** | \`${goInfo.modulePath ?? "unknown / unversioned"}\` |`,
					`| **Compiler** | \`${goInfo.compiler ?? "gc"}\` |`,
					`| **Dependencies Count** | ${goInfo.totalDependencies} |`,
					`| **CGO Enabled** | \`${goInfo.buildSettings["CGO_ENABLED"] ?? "unknown"}\` |`,
					`| **VCS Revision** | \`${goInfo.buildSettings["vcs.revision"] ?? "none"}\` |`,
					`| **pclntab Version** | \`${goInfo.pclntabVersion ?? "none"}\` |`,
				);
			}

			if (isRust && rustInfo) {
				lines.push(
					"",
					"## Rust Metadata Summary",
					`| Rust Property | Value |`,
					`|---|---|`,
					`| **Cargo Auditable (.dep-v0)** | ${rustInfo.cargoAuditable ? "✅ Present" : "❌ Not embedded"} |`,
					`| **rustc Version** | \`${rustInfo.rustcVersion ?? "unknown"}\` |`,
					`| **rustc Commit** | \`${rustInfo.rustcCommit ? rustInfo.rustcCommit.slice(0, 10) : "unknown"}\` |`,
					`| **Panic Strategy** | \`${rustInfo.panicStrategy}\` |`,
					`| **Memory Allocator** | \`${rustInfo.allocator}\` |`,
					`| **Auditable Packages** | ${rustInfo.totalPackages} |`,
					`| **Detected Crates** | ${rustInfo.detectedCrates.length > 0 ? rustInfo.detectedCrates.slice(0, 10).join(", ") : "none"} |`,
				);
			}

			if (!isGo && !isRust) {
				lines.push(
					"",
					"> **Note**: No Go or Rust build metadata detected in binary header, sections, or scanned strings. Binary may be C/C++, stripped, or an unknown compiler.",
				);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "info",
					path: resolvedPath,
					fileSize: fileStat.size,
					format: container.format,
					architecture: container.architecture,
					bitness: container.bitness,
					endianness: container.endianness,
					language,
					isGo,
					isRust,
					go: goInfo,
					rust: rustInfo,
					totalSections: container.sections.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: go
		// ------------------------------------------------------------------------
		if (action === "go") {
			if (!goInfo) {
				return {
					content: [
						{
							type: "text",
							text: `# Go Metadata: \`${path.basename(resolvedPath)}\`\n\nNo Go build metadata or runtime markers were detected in this binary.`,
						},
					],
					details: {
						action: "go",
						path: resolvedPath,
						fileSize: fileStat.size,
						format: container.format,
						language,
						isGo: false,
						isRust,
						unsupportedReason: "No Go build metadata detected in target binary.",
					},
				};
			}

			let deps = goInfo.dependencies;
			if (filter) {
				deps = deps.filter(d => d.path.toLowerCase().includes(filter));
			}
			const pagedDeps = deps.slice(offset, offset + limit);

			const lines = [
				`# Go Build Information: \`${path.basename(resolvedPath)}\``,
				"",
				`| Property | Value |`,
				`|---|---|`,
				`| **Runtime Version** | \`${goInfo.runtimeVersion ?? "unknown"}\` |`,
				`| **Module Path** | \`${goInfo.modulePath ?? "unknown"}\` |`,
				`| **Compiler** | \`${goInfo.compiler ?? "gc"}\` |`,
				`| **Dependencies (Total)** | ${goInfo.totalDependencies} (matching filter: ${deps.length}) |`,
				"",
				"## Build Settings",
			];

			const settingKeys = Object.keys(goInfo.buildSettings);
			if (settingKeys.length > 0) {
				lines.push("| Key | Value |", "|---|---|");
				for (const k of settingKeys.sort()) {
					lines.push(`| \`${k}\` | \`${goInfo.buildSettings[k]}\` |`);
				}
			} else {
				lines.push("*No key-value build settings recorded.*");
			}

			lines.push(
				"",
				"## Compiled Dependencies",
				"| Module Path | Version | Hash / Checksum | Replaced By |",
				"|---|---|---|---|",
			);
			if (pagedDeps.length > 0) {
				for (const dep of pagedDeps) {
					lines.push(
						`| \`${dep.path}\` | \`${dep.version ?? "-"}\` | \`${dep.sum ? dep.sum.slice(0, 16) + "..." : "-"}\` | \`${dep.replacedBy ?? "-"}\` |`,
					);
				}
				if (deps.length > offset + limit) {
					lines.push(`*...and ${deps.length - (offset + limit)} more dependencies (use \`offset\` to paginate)*`);
				}
			} else {
				lines.push("*No dependencies found matching filter.*");
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "go",
					path: resolvedPath,
					fileSize: fileStat.size,
					format: container.format,
					language,
					isGo: true,
					isRust,
					go: {
						...goInfo,
						dependencies: pagedDeps,
					},
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: rust
		// ------------------------------------------------------------------------
		if (action === "rust") {
			if (!rustInfo) {
				return {
					content: [
						{
							type: "text",
							text: `# Rust Metadata: \`${path.basename(resolvedPath)}\`\n\nNo Rust metadata or runtime markers were detected in this binary.`,
						},
					],
					details: {
						action: "rust",
						path: resolvedPath,
						fileSize: fileStat.size,
						format: container.format,
						language,
						isGo,
						isRust: false,
						unsupportedReason: "No Rust metadata detected in target binary.",
					},
				};
			}

			let pkgs = rustInfo.packages;
			if (filter) {
				pkgs = pkgs.filter(p => p.name.toLowerCase().includes(filter));
			}
			const pagedPkgs = pkgs.slice(offset, offset + limit);

			const lines = [
				`# Rust Audit Information: \`${path.basename(resolvedPath)}\``,
				"",
				`| Property | Value |`,
				`|---|---|`,
				`| **Cargo Auditable (.dep-v0)** | ${rustInfo.cargoAuditable ? "✅ Embedded" : "❌ None"} |`,
				`| **rustc Version** | \`${rustInfo.rustcVersion ?? "unknown"}\` |`,
				`| **rustc Commit** | \`${rustInfo.rustcCommit ?? "unknown"}\` |`,
				`| **Panic Strategy** | \`${rustInfo.panicStrategy}\` |`,
				`| **Allocator** | \`${rustInfo.allocator}\` |`,
				`| **Total Packages** | ${rustInfo.totalPackages} (matching filter: ${pkgs.length}) |`,
				"",
				"## Cargo Dependency Packages",
			];

			if (pagedPkgs.length > 0) {
				lines.push("| Package Name | Version | Source | Kind |", "|---|---|---|---|");
				for (const pkg of pagedPkgs) {
					lines.push(
						`| **${pkg.name}** | \`${pkg.version}\` | \`${pkg.source ?? "crates.io"}\` | \`${pkg.kind ?? "dependency"}\` |`,
					);
				}
				if (pkgs.length > offset + limit) {
					lines.push(`*...and ${pkgs.length - (offset + limit)} more packages (use \`offset\` to paginate)*`);
				}
			} else if (rustInfo.cargoAuditable) {
				lines.push("*No packages found matching filter.*");
			} else {
				lines.push(
					"*Binary does not contain embedded cargo-auditable dependency data (.dep-v0).* ",
					"",
					`**Detected Crate Symbols:** ${rustInfo.detectedCrates.length > 0 ? rustInfo.detectedCrates.join(", ") : "none"}`,
				);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "rust",
					path: resolvedPath,
					fileSize: fileStat.size,
					format: container.format,
					language,
					isGo,
					isRust: true,
					rust: {
						...rustInfo,
						packages: pagedPkgs,
					},
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: sections
		// ------------------------------------------------------------------------
		if (action === "sections") {
			const pagedSections = container.sections.slice(offset, offset + limit);
			const lines = [
				`# Binary Sections & Markers: \`${path.basename(resolvedPath)}\` (${container.sections.length} total)`,
				"",
				`| # | Name | Offset | Size | Virtual Addr | Type Marker |`,
				`|---|---|---|---|---|---|`,
			];

			for (const sec of pagedSections) {
				const markerStr =
					sec.markerType === "go" ? "🔷 Go Runtime" : sec.markerType === "rust" ? "🦀 Rust Audit" : "standard";
				lines.push(
					`| ${sec.index} | **\`${sec.name}\`** | \`0x${sec.offset.toString(16)}\` | ${formatBytes(sec.size)} | \`${sec.virtualAddress ?? "-"}\` | ${markerStr} |`,
				);
			}

			if (container.sections.length > offset + limit) {
				lines.push(
					`*...and ${container.sections.length - (offset + limit)} more sections (use \`offset\` to paginate)*`,
				);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "sections",
					path: resolvedPath,
					fileSize: fileStat.size,
					format: container.format,
					language,
					isGo,
					isRust,
					sections: pagedSections,
					totalSections: container.sections.length,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
