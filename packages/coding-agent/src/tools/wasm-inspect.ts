import type { Stats } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import type { ToolSession } from ".";
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import wasmInspectDescription from "../prompts/tools/wasm-inspect.md" with { type: "text" };
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

const wasmInspectSchema = type({
	action: type.enumerated("info", "strings", "search", "wat"),
	path: type("string").describe("Path to a .wasm binary"),
	"pattern?": type("string").describe("Literal or regular expression for search"),
	"regex?": "boolean",
	"case_sensitive?": "boolean",
	"min_length?": type("number.integer >= 1").describe("Minimum string length for strings"),
	"limit?": type("number.integer >= 1").describe("Maximum results per list"),
	"skip?": type("number.integer >= 0").describe("Results to skip"),
	"max_bytes?": type("number.integer >= 1").describe("WAT output cap or search byte cap"),
	"timeout?": type("number > 0").describe("wasm2wat timeout in seconds"),
});

/** Parameters accepted by the `wasm_inspect` tool. */
export type WasmInspectParams = typeof wasmInspectSchema.infer;
/** Actions supported by the `wasm_inspect` tool. */
export type WasmInspectAction = WasmInspectParams["action"];

export interface WasmSectionInfo {
	id: number;
	name: string;
	size: number;
	offset: number;
}

export interface WasmLimits {
	min: number | string;
	max?: number | string;
	shared?: boolean;
	memory64?: boolean;
	imported?: boolean;
}

export interface WasmTypeInfo {
	index: number;
	params: string[];
	results: string[];
}

export interface WasmImportInfo {
	module: string;
	name: string;
	kind: string;
	index: number;
	typeIndex?: number;
	signature?: string;
	limits?: WasmLimits;
	valueType?: string;
	mutable?: boolean;
}

export interface WasmExportInfo {
	name: string;
	kind: string;
	index: number;
	typeIndex?: number;
	signature?: string;
	functionName?: string;
}

export interface WasmDataSegmentInfo {
	index: number;
	mode: "active" | "passive";
	memory: number;
	size: number;
	offset: number;
}

export interface WasmSearchMatch {
	offset: number;
	length: number;
	context: string;
}

export interface WasmStringMatch {
	text: string;
	source: string;
	offset: number;
}

export interface WasmDependencyStatus {
	id: string;
	binary: string;
	available: boolean;
	path?: string;
	installHint?: string;
}

export interface WasmInspectDetails {
	action: WasmInspectAction;
	path: string;
	status: "ok" | "missing_dependency" | "error";
	bytes?: number;
	version?: number;
	sections?: WasmSectionInfo[];
	types?: WasmTypeInfo[];
	imports?: WasmImportInfo[];
	exports?: WasmExportInfo[];
	importedFunctionCount?: number;
	definedFunctionCount?: number;
	functionCount?: number;
	functionNames?: number;
	moduleName?: string;
	memories?: WasmLimits[];
	globals?: { index: number; valueType: string; mutable: boolean }[];
	dataSegments?: WasmDataSegmentInfo[];
	customSections?: { name: string; size: number }[];
	startFunction?: number;
	matches?: WasmSearchMatch[];
	strings?: WasmStringMatch[];
	totalMatches?: number;
	totalStrings?: number;
	truncated?: boolean;
	dependency?: WasmDependencyStatus;
	outputBytes?: number;
	error?: string;
}

/** Default cap for every model-facing list; callers can raise it up to {@link MAX_LIST_LIMIT}. */
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_STRING_MIN_LENGTH = 5;
const DEFAULT_SEARCH_BYTES = 64 * 1024 * 1024;
const DEFAULT_WAT_MAX_BYTES = 128 * 1024;
const MAX_WAT_MAX_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 512 * 1024 * 1024;
const DEFAULT_WAT_TIMEOUT_SECONDS = 30;
const MAX_WAT_TIMEOUT_SECONDS = 120;
const MAX_PATTERN_LENGTH = 4_096;
const MAX_NAME_ENTRIES = 5_000;
const CONTEXT_BYTES = 24;

const WASM_MAGIC = [0x00, 0x61, 0x73, 0x6d] as const;
const WASM_VERSION = 1;

const SECTION_NAMES: Readonly<Record<number, string>> = {
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

const EXTERNAL_KIND_NAMES: Readonly<Record<number, string>> = {
	0: "func",
	1: "table",
	2: "memory",
	3: "global",
	4: "tag",
};

const VAL_TYPE_NAMES: Readonly<Record<number, string>> = {
	0x7f: "i32",
	0x7e: "i64",
	0x7d: "f32",
	0x7c: "f64",
	0x7b: "v128",
	0x70: "funcref",
	0x6f: "externref",
};

type RawDataSegment = WasmDataSegmentInfo & { bytes: Uint8Array };
type RawCustomSection = { name: string; offset: number; bytes: Uint8Array };

interface ParsedWasmModule {
	sections: WasmSectionInfo[];
	types: WasmTypeInfo[];
	imports: WasmImportInfo[];
	exports: WasmExportInfo[];
	memories: WasmLimits[];
	globals: { index: number; valueType: string; mutable: boolean }[];
	dataSegments: RawDataSegment[];
	customSections: { name: string; size: number }[];
	rawCustomSections: RawCustomSection[];
	functionTypeIndices: number[];
	importedFunctionCount: number;
	definedFunctionCount: number;
	functionNames: Map<number, string>;
	moduleName?: string;
	startFunction?: number;
}

class WasmReader {
	readonly data: Uint8Array;
	readonly end: number;
	pos: number;

	constructor(data: Uint8Array, start = 0, end = data.length) {
		this.data = data;
		this.pos = start;
		this.end = end;
	}

	get remaining(): number {
		return this.end - this.pos;
	}

	private ensure(length: number, what: string): void {
		if (length < 0 || this.pos + length > this.end) {
			throw new ToolError(`Malformed WebAssembly: truncated ${what} at byte ${this.pos}`);
		}
	}

	u8(what = "byte"): number {
		this.ensure(1, what);
		return this.data[this.pos++]!;
	}

	bytes(length: number, what = "bytes"): Uint8Array {
		this.ensure(length, what);
		const out = this.data.subarray(this.pos, this.pos + length);
		this.pos += length;
		return out;
	}

	skip(length: number, what = "payload"): void {
		this.ensure(length, what);
		this.pos += length;
	}

	u32(what = "LEB128"): number {
		let result = 0;
		let factor = 1;
		for (let i = 0; i < 5; i++) {
			const byte = this.u8(what);
			result += (byte & 0x7f) * factor;
			if ((byte & 0x80) === 0) return result >>> 0;
			factor *= 128;
		}
		throw new ToolError(`Malformed WebAssembly: ${what} exceeds 32 bits at byte ${this.pos}`);
	}

	u64(what = "LEB128"): string {
		let result = 0n;
		let factor = 1n;
		for (let i = 0; i < 10; i++) {
			const byte = this.u8(what);
			result += BigInt(byte & 0x7f) * factor;
			if ((byte & 0x80) === 0) return result.toString();
			factor *= 128n;
		}
		throw new ToolError(`Malformed WebAssembly: ${what} exceeds 64 bits at byte ${this.pos}`);
	}

	name(what = "name"): string {
		const length = this.u32(`${what} length`);
		return new TextDecoder().decode(this.bytes(length, what));
	}
}

function skipLeb(reader: WasmReader, maxBytes: number): void {
	for (let i = 0; i < maxBytes; i++) {
		if ((reader.u8() & 0x80) === 0) return;
	}
	throw new ToolError(`Malformed WebAssembly: unterminated LEB128 at byte ${reader.pos}`);
}

/** Skip one constant expression, including the terminating `end` opcode. */
function skipConstExpr(reader: WasmReader): void {
	for (;;) {
		const opcode = reader.u8("constant expression");
		switch (opcode) {
			case 0x0b:
				return;
			case 0x41:
			case 0x42:
				skipLeb(reader, 10);
				break;
			case 0x43:
				reader.skip(4, "f32 immediate");
				break;
			case 0x44:
				reader.skip(8, "f64 immediate");
				break;
			case 0x23:
			case 0xd2:
				reader.u32("constant expression index");
				break;
			case 0xd0:
				reader.u8("reference type");
				break;
			default:
				// Numeric and reference operators used by extended const
				// expressions carry no immediate in their MVP form.
				break;
		}
	}
}

function readValType(reader: WasmReader): string {
	const value = reader.u8("value type");
	return VAL_TYPE_NAMES[value] ?? `0x${value.toString(16).padStart(2, "0")}`;
}

function readValTypes(reader: WasmReader): string[] {
	const count = reader.u32("value type count");
	const types: string[] = [];
	for (let i = 0; i < count; i++) types.push(readValType(reader));
	return types;
}

function readLimits(reader: WasmReader): WasmLimits {
	const flags = reader.u32("limits flags");
	const memory64 = (flags & 0x4) !== 0;
	const hasMax = (flags & 0x1) !== 0;
	return {
		min: memory64 ? reader.u64("memory minimum") : reader.u32("memory minimum"),
		...(hasMax ? { max: memory64 ? reader.u64("memory maximum") : reader.u32("memory maximum") } : {}),
		shared: (flags & 0x2) !== 0,
		memory64,
	};
}

function signatureOf(type: WasmTypeInfo | undefined): string | undefined {
	if (!type) return undefined;
	return `(${type.params.join(", ")}) -> (${type.results.join(", ")})`;
}

function parseNameSection(
	reader: WasmReader,
	functionNames: Map<number, string>,
	moduleName: { value?: string },
): void {
	while (reader.remaining > 0) {
		const subsectionId = reader.u8("name subsection id");
		const size = reader.u32("name subsection size");
		const end = reader.pos + size;
		if (end > reader.end) throw new ToolError("Malformed WebAssembly: name subsection exceeds its section");
		const sub = new WasmReader(reader.data, reader.pos, end);
		if (subsectionId === 0) {
			moduleName.value = sub.name("module name");
		} else if (subsectionId === 1) {
			const count = sub.u32("function name count");
			for (let i = 0; i < count && functionNames.size < MAX_NAME_ENTRIES; i++) {
				const index = sub.u32("function index");
				functionNames.set(index, sub.name("function name"));
			}
		}
		reader.pos = end;
	}
}

/** Parse the stable WebAssembly binary sections needed for reverse-engineering recon. */
export function parseWasmModule(data: Uint8Array): ParsedWasmModule {
	if (data.length < 8) {
		throw new ToolError(`Not a WebAssembly module: expected at least 8 header bytes, got ${data.length}`);
	}
	for (let i = 0; i < WASM_MAGIC.length; i++) {
		if (data[i] !== WASM_MAGIC[i]) throw new ToolError("Not a WebAssembly module: missing \\0asm magic");
	}
	const version = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(4, true);
	if (version !== WASM_VERSION) {
		throw new ToolError(`Unsupported WebAssembly binary version ${version}; only version 1 is supported`);
	}

	const parsed: ParsedWasmModule = {
		sections: [],
		types: [],
		imports: [],
		exports: [],
		memories: [],
		globals: [],
		dataSegments: [],
		customSections: [],
		rawCustomSections: [],
		functionTypeIndices: [],
		importedFunctionCount: 0,
		definedFunctionCount: 0,
		functionNames: new Map(),
	};
	const moduleName: { value?: string } = {};
	const reader = new WasmReader(data, 8);
	let functionTypeIndicesFromSection: number[] = [];
	let codeCount: number | undefined;

	while (reader.remaining > 0) {
		const sectionStart = reader.pos;
		const id = reader.u8("section id");
		const size = reader.u32("section size");
		const payloadStart = reader.pos;
		const payloadEnd = payloadStart + size;
		if (payloadEnd > reader.end) {
			throw new ToolError(
				`Malformed WebAssembly: section ${SECTION_NAMES[id] ?? id} at byte ${sectionStart} claims ${size} bytes but only ${reader.end - payloadStart} remain`,
			);
		}
		const section = new WasmReader(data, payloadStart, payloadEnd);
		parsed.sections.push({
			id,
			name: SECTION_NAMES[id] ?? `unknown_${id}`,
			size,
			offset: sectionStart,
		});

		switch (id) {
			case 0: {
				const name = section.name("custom section name");
				const payloadOffset = section.pos;
				if (name !== "name") {
					parsed.rawCustomSections.push({
						name,
						offset: payloadOffset,
						bytes: data.subarray(payloadOffset, payloadEnd),
					});
				}
				if (name === "name") {
					try {
						parseNameSection(section, parsed.functionNames, moduleName);
					} catch {
						// A damaged names section must not hide imports and exports.
					}
				}
				parsed.customSections.push({ name, size: payloadEnd - payloadOffset });
				break;
			}
			case 1: {
				const count = section.u32("type count");
				for (let i = 0; i < count; i++) {
					const form = section.u8("type form");
					if (form !== 0x60) {
						throw new ToolError(
							`Unsupported WebAssembly type form 0x${form.toString(16)} at byte ${section.pos - 1}`,
						);
					}
					parsed.types.push({
						index: parsed.types.length,
						params: readValTypes(section),
						results: readValTypes(section),
					});
				}
				break;
			}
			case 2: {
				const count = section.u32("import count");
				const importCounts: Record<string, number> = { func: 0, table: 0, memory: 0, global: 0, tag: 0 };
				for (let i = 0; i < count; i++) {
					const module = section.name("import module");
					const name = section.name("import name");
					const kindByte = section.u8("import kind");
					const kind = EXTERNAL_KIND_NAMES[kindByte] ?? `0x${kindByte.toString(16)}`;
					const entry: WasmImportInfo = { module, name, kind, index: importCounts[kind] ?? 0 };
					importCounts[kind] = (importCounts[kind] ?? 0) + 1;
					if (kindByte === 0) {
						entry.typeIndex = section.u32("function type index");
						parsed.importedFunctionCount++;
					} else if (kindByte === 1) {
						readValType(section);
						entry.limits = readLimits(section);
					} else if (kindByte === 2) {
						entry.limits = { ...readLimits(section), imported: true };
						parsed.memories.push(entry.limits);
					} else if (kindByte === 3) {
						entry.valueType = readValType(section);
						entry.mutable = section.u8("global mutability") !== 0;
					} else if (kindByte === 4) {
						section.u8("tag attribute");
						entry.typeIndex = section.u32("tag type index");
					} else {
						throw new ToolError(`Unsupported WebAssembly import kind ${kindByte} at byte ${section.pos - 1}`);
					}
					parsed.imports.push(entry);
				}
				break;
			}
			case 3: {
				const count = section.u32("function count");
				functionTypeIndicesFromSection = [];
				for (let i = 0; i < count; i++) {
					functionTypeIndicesFromSection.push(section.u32("function type index"));
				}
				parsed.definedFunctionCount = count;
				break;
			}
			case 4: {
				const count = section.u32("table count");
				for (let i = 0; i < count; i++) {
					readValType(section);
					readLimits(section);
				}
				break;
			}
			case 5: {
				const count = section.u32("memory count");
				for (let i = 0; i < count; i++) parsed.memories.push(readLimits(section));
				break;
			}
			case 6: {
				const count = section.u32("global count");
				for (let i = 0; i < count; i++) {
					parsed.globals.push({
						index: i,
						valueType: readValType(section),
						mutable: section.u8("global mutability") !== 0,
					});
					skipConstExpr(section);
				}
				break;
			}
			case 7: {
				const count = section.u32("export count");
				for (let i = 0; i < count; i++) {
					const name = section.name("export name");
					const kindByte = section.u8("export kind");
					const index = section.u32("export index");
					parsed.exports.push({
						name,
						kind: EXTERNAL_KIND_NAMES[kindByte] ?? `0x${kindByte.toString(16)}`,
						index,
					});
				}
				break;
			}
			case 8:
				parsed.startFunction = section.u32("start function index");
				break;
			case 10:
				codeCount = section.u32("code body count");
				break;
			case 11: {
				const count = section.u32("data segment count");
				for (let i = 0; i < count; i++) {
					const flags = section.u32("data segment flags");
					const mode = flags === 0x1 ? "passive" : "active";
					const memory = flags === 0x2 ? section.u32("data memory index") : 0;
					if (mode === "active") skipConstExpr(section);
					const size = section.u32("data segment size");
					const offset = section.pos;
					const bytes = section.bytes(size, "data segment payload");
					parsed.dataSegments.push({ index: i, mode, memory, size, offset, bytes });
				}
				break;
			}
			default:
				// Table/element/tag/data-count bodies are length-delimited and not
				// needed for recon; the section table above still reports them.
				break;
		}
		reader.pos = payloadEnd;
	}

	if (codeCount !== undefined && codeCount !== parsed.definedFunctionCount) {
		throw new ToolError(
			`Malformed WebAssembly: function section declares ${parsed.definedFunctionCount} functions but code section has ${codeCount}`,
		);
	}

	// Imported functions come first, in import order, then defined functions.
	for (const entry of parsed.imports) {
		if (entry.kind === "func" && entry.typeIndex !== undefined) {
			parsed.functionTypeIndices.push(entry.typeIndex);
		}
	}
	parsed.functionTypeIndices.push(...functionTypeIndicesFromSection);

	for (const entry of parsed.exports) {
		if (entry.kind === "func") {
			entry.typeIndex = parsed.functionTypeIndices[entry.index];
			entry.signature = signatureOf(parsed.types[entry.typeIndex]);
			entry.functionName = parsed.functionNames.get(entry.index);
		}
	}
	for (const entry of parsed.imports) {
		if (entry.kind === "func") entry.signature = signatureOf(parsed.types[entry.typeIndex ?? -1]);
	}
	parsed.moduleName = moduleName.value;
	return parsed;
}

function formatLimits(limits: WasmLimits): string {
	const flags = [
		limits.imported ? "imported" : undefined,
		limits.shared ? "shared" : undefined,
		limits.memory64 ? "memory64" : undefined,
	].filter(Boolean);
	return `min=${limits.min}${limits.max !== undefined ? ` max=${limits.max}` : ""}${flags.length > 0 ? ` ${flags.join(" ")}` : ""}`;
}

function firstLine(value: string): string {
	const newline = value.indexOf("\n");
	return (newline === -1 ? value : value.slice(0, newline)).trim();
}

function renderInfo(filePath: string, bytes: number, parsed: ParsedWasmModule, limit: number): string {
	const lines: string[] = [];
	lines.push(`WebAssembly module: ${filePath}`);
	lines.push(`size: ${bytes} bytes, binary version 1, sections: ${parsed.sections.length}`);

	const sectionSummary = parsed.sections
		.slice(0, Math.min(limit, 32))
		.map(section => `${section.name}(${section.size})@0x${section.offset.toString(16)}`);
	lines.push(
		`sections: ${sectionSummary.join(", ")}${parsed.sections.length > sectionSummary.length ? ` … ${parsed.sections.length - sectionSummary.length} more` : ""}`,
	);

	lines.push(`types (${parsed.types.length}):`);
	for (const entry of parsed.types.slice(0, limit)) {
		lines.push(`  type[${entry.index}] ${signatureOf(entry)}`);
	}
	if (parsed.types.length > limit) lines.push(`  … ${parsed.types.length - limit} more`);

	lines.push(`imports (${parsed.imports.length}):`);
	for (const entry of parsed.imports.slice(0, limit)) {
		const details =
			entry.kind === "func"
				? `func[${entry.index}] ${entry.signature ?? `type ${entry.typeIndex}`}`
				: entry.kind === "memory" || entry.kind === "table"
					? `${entry.kind}[${entry.index}] ${entry.limits ? formatLimits(entry.limits) : ""}`
					: entry.kind === "global"
						? `global[${entry.index}] ${entry.valueType}${entry.mutable ? " mut" : " const"}`
						: `${entry.kind}[${entry.index}]`;
		lines.push(`  ${entry.module}.${entry.name} → ${details}`);
	}
	if (parsed.imports.length > limit) lines.push(`  … ${parsed.imports.length - limit} more`);

	lines.push(`exports (${parsed.exports.length}):`);
	for (const entry of parsed.exports.slice(0, limit)) {
		const target =
			entry.kind === "func"
				? `func[${entry.index}] ${entry.signature ?? "unknown signature"}${entry.functionName ? ` name="${entry.functionName}"` : ""}`
				: `${entry.kind}[${entry.index}]`;
		lines.push(`  "${entry.name}" → ${target}`);
	}
	if (parsed.exports.length > limit) lines.push(`  … ${parsed.exports.length - limit} more`);

	lines.push(
		`functions: ${parsed.importedFunctionCount} imported, ${parsed.definedFunctionCount} defined, ${parsed.functionTypeIndices.length} total`,
	);
	lines.push(
		`memories: ${parsed.memories.length}${parsed.memories.length > 0 ? ` (${parsed.memories.map(formatLimits).join("; ")})` : ""}`,
	);
	const mutableGlobals = parsed.globals.filter(entry => entry.mutable).length;
	lines.push(`globals: ${parsed.globals.length} (${mutableGlobals} mutable)`);
	lines.push(`data segments: ${parsed.dataSegments.length}`);
	for (const segment of parsed.dataSegments.slice(0, limit)) {
		lines.push(
			`  data[${segment.index}] ${segment.mode}${segment.mode === "active" ? ` memory=${segment.memory}` : ""} size=${segment.size} @0x${segment.offset.toString(16)}`,
		);
	}
	if (parsed.dataSegments.length > limit) lines.push(`  … ${parsed.dataSegments.length - limit} more`);

	if (parsed.functionNames.size > 0) {
		lines.push(
			`function names: ${parsed.functionNames.size}${parsed.moduleName ? `, module "${parsed.moduleName}"` : ""}`,
		);
		const namedExports = parsed.exports.filter(entry => entry.kind === "func" && entry.functionName);
		for (const entry of namedExports.slice(0, Math.min(limit, 20))) {
			lines.push(`  ${entry.functionName} = func[${entry.index}] (export "${entry.name}")`);
		}
	} else if (parsed.moduleName) {
		lines.push(`module name: "${parsed.moduleName}"`);
	}

	if (parsed.customSections.length > 0) {
		const summary = parsed.customSections
			.slice(0, Math.min(limit, 32))
			.map(section => `${section.name}(${section.size})`);
		lines.push(
			`custom sections: ${summary.join(", ")}${parsed.customSections.length > summary.length ? ` … ${parsed.customSections.length - summary.length} more` : ""}`,
		);
	}
	if (parsed.startFunction !== undefined) lines.push(`start function: func[${parsed.startFunction}]`);
	return lines.join("\n");
}

function extractStrings(
	bytes: Uint8Array,
	fileOffset: number,
	source: string,
	minLength: number,
	max: number,
): WasmStringMatch[] {
	const out: WasmStringMatch[] = [];
	let start = -1;
	const flush = (end: number) => {
		if (start === -1) return;
		const value = Buffer.from(bytes.subarray(start, end)).toString("utf8").trim();
		if (value.length >= minLength) {
			out.push({
				text: value.length > 300 ? `${value.slice(0, 300)}…` : value,
				source,
				offset: fileOffset + start,
			});
		}
		start = -1;
	};
	for (let i = 0; i < bytes.length; i++) {
		const byte = bytes[i]!;
		if (byte >= 0x20 && byte <= 0x7e) {
			if (start === -1) start = i;
		} else if (start !== -1) {
			flush(i);
			if (out.length >= max) return out;
		}
	}
	flush(bytes.length);
	return out;
}

function countStrings(bytes: Uint8Array, minLength: number): number {
	let count = 0;
	let start = -1;
	for (let i = 0; i <= bytes.length; i++) {
		const byte = i < bytes.length ? bytes[i]! : 0;
		if (byte >= 0x20 && byte <= 0x7e) {
			if (start === -1) start = i;
		} else if (start !== -1) {
			const value = Buffer.from(bytes.subarray(start, i)).toString("utf8").trim();
			if (value.length >= minLength) count++;
			start = -1;
		}
	}
	return count;
}

function renderContext(data: Uint8Array, offset: number, length: number): string {
	const start = Math.max(0, offset - CONTEXT_BYTES);
	const end = Math.min(data.length, offset + length + CONTEXT_BYTES);
	let out = "";
	for (let i = start; i < end; i++) {
		const byte = data[i]!;
		out += byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
	}
	if (out.length > 200) out = `${out.slice(0, 197)}...`;
	return `${start < offset ? "…" : ""}${out}${end > offset + length ? "…" : ""}`;
}

interface WasmSearchResult {
	matches: WasmSearchMatch[];
	totalMatches: number;
	truncated: boolean;
}

function findLiteralMatches(
	data: Uint8Array,
	needle: string,
	ignoreCase: boolean,
	scanBytes: number,
	skip: number,
	limit: number,
	signal?: AbortSignal,
): WasmSearchResult {
	const haystack = Buffer.from(data.subarray(0, scanBytes)).toString("latin1");
	const foldedHaystack = ignoreCase ? haystack.toLowerCase() : haystack;
	const foldedNeedle = ignoreCase ? needle.toLowerCase() : needle;
	if (foldedNeedle.length === 0) return { matches: [], totalMatches: 0, truncated: scanBytes < data.length };
	const matches: WasmSearchMatch[] = [];
	let totalMatches = 0;
	let index = 0;
	let truncated = false;
	for (;;) {
		throwIfAborted(signal);
		const found = foldedHaystack.indexOf(foldedNeedle, index);
		if (found === -1) break;
		totalMatches++;
		if (totalMatches > skip && matches.length < limit) {
			matches.push({
				offset: found,
				length: foldedNeedle.length,
				context: renderContext(data, found, foldedNeedle.length),
			});
		}
		if (matches.length >= limit) {
			truncated = true;
			break;
		}
		index = found + Math.max(1, foldedNeedle.length);
	}
	return { matches, totalMatches, truncated: truncated || scanBytes < data.length };
}

function findRegexMatches(
	data: Uint8Array,
	pattern: string,
	caseSensitive: boolean,
	scanBytes: number,
	skip: number,
	limit: number,
	signal?: AbortSignal,
): WasmSearchResult {
	const haystack = Buffer.from(data.subarray(0, scanBytes)).toString("latin1");
	const expression = new RegExp(pattern, caseSensitive ? "g" : "gi");
	const matches: WasmSearchMatch[] = [];
	let totalMatches = 0;
	let truncated = false;
	for (;;) {
		throwIfAborted(signal);
		const found = expression.exec(haystack);
		if (!found) break;
		totalMatches++;
		if (totalMatches > skip && matches.length < limit) {
			matches.push({
				offset: found.index,
				length: found[0].length,
				context: renderContext(data, found.index, found[0].length),
			});
		}
		if (matches.length >= limit) {
			truncated = true;
			break;
		}
		if (found[0].length === 0) expression.lastIndex++;
	}
	return { matches, totalMatches, truncated: truncated || scanBytes < data.length };
}

interface CappedRead {
	text: string;
	bytes: number;
	truncated: boolean;
}

async function readCapped(
	stream: ReadableStream<Uint8Array>,
	cap: number,
	onOverflow?: () => void,
): Promise<CappedRead> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	let truncated = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			const remaining = cap - bytes;
			if (value.byteLength >= remaining) {
				if (remaining > 0) chunks.push(value.subarray(0, remaining));
				bytes += Math.max(0, remaining);
				truncated = true;
				onOverflow?.();
				break;
			}
			chunks.push(value);
			bytes += value.byteLength;
		}
	} finally {
		if (truncated) await reader.cancel().catch(() => {});
	}
	return {
		text: Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString("utf8"),
		bytes,
		truncated,
	};
}

export function wabtDependency(which?: SkillRequirementWhich): WasmDependencyStatus {
	const requirements: ToolRequirement[] = [{ id: "wabt" }];
	const [status] = checkToolRequirements(requirements, which ? { which } : undefined);
	const found = status?.foundPath ?? null;
	const basename = found ? path.basename(found).replace(/\.exe$/i, "") : "";
	const available = basename === "wasm2wat";
	const platform: SkillToolPlatform =
		process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
	const catalogHint = SKILL_TOOL_CATALOG.wabt?.installHints?.[platform]?.join(" or ");
	const installHint = status?.hint ?? (available ? undefined : catalogHint);
	return {
		id: "wabt",
		binary: "wasm2wat",
		available,
		...(available && found ? { path: found } : {}),
		...(installHint && !available ? { installHint } : {}),
	};
}

interface WatRunResult {
	stdout: string;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
}

async function runWasm2Wat(
	binary: string,
	filePath: string,
	maxBytes: number,
	timeoutMs: number,
	signal?: AbortSignal,
): Promise<WatRunResult> {
	const child = Bun.spawn([binary, filePath], {
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill();
	}, timeoutMs);
	const onAbort = () => {
		child.kill();
	};
	signal?.addEventListener("abort", onAbort, { once: true });
	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			readCapped(child.stdout, maxBytes, () => child.kill()),
			readCapped(child.stderr, 16 * 1024),
			child.exited,
		]);
		return {
			stdout: stdout.text,
			stderr: stderr.text,
			exitCode,
			outputBytes: stdout.bytes,
			truncated: stdout.truncated,
			timedOut,
		};
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
	}
}

export interface WasmInspectOptions {
	/** Lookup seam for dependency checks; tests inject a deterministic `which`. */
	which?: SkillRequirementWhich;
}

export class WasmInspectTool implements AgentTool<typeof wasmInspectSchema, WasmInspectDetails> {
	readonly name = "wasm_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "WASM Inspect";
	readonly summary =
		"Inspect WebAssembly binaries natively and summarize imports, exports, names, strings, and byte matches";
	readonly description = wasmInspectDescription.trim();
	readonly parameters = wasmInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: WasmInspectOptions = {},
	) {}

	async execute(
		_toolCallId: string,
		params: WasmInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<WasmInspectDetails>> {
		throwIfAborted(signal);
		const requestedPath = params.path.trim();
		if (requestedPath.length === 0) throw new ToolError("path is required");
		const absolutePath = resolveReadPath(requestedPath, this.session.cwd);
		const limit = Math.min(MAX_LIST_LIMIT, Math.max(1, Math.floor(params.limit ?? DEFAULT_LIST_LIMIT)));
		const skip = Math.max(0, Math.floor(params.skip ?? 0));

		let info: Stats;
		try {
			info = await stat(absolutePath);
		} catch {
			throw new ToolError(`WebAssembly file not found: ${requestedPath}`);
		}
		if (!info.isFile()) throw new ToolError(`Not a regular file: ${requestedPath}`);
		if (info.size > MAX_FILE_BYTES) {
			throw new ToolError(
				`WebAssembly file is ${info.size} bytes; the ${MAX_FILE_BYTES}-byte analysis cap was exceeded`,
			);
		}

		if (params.action === "wat") {
			return this.#runWat(requestedPath, absolutePath, params, signal);
		}

		let data: Uint8Array;
		try {
			data = new Uint8Array(await readFile(absolutePath));
		} catch (error) {
			throw new ToolError(
				`Failed to read ${requestedPath}: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		throwIfAborted(signal);
		const parsed = parseWasmModule(data);
		const displayPath = requestedPath;
		const baseDetails: WasmInspectDetails = {
			action: params.action,
			path: displayPath,
			status: "ok",
			bytes: data.length,
			version: 1,
		};

		if (params.action === "info") {
			return {
				content: [{ type: "text", text: renderInfo(displayPath, data.length, parsed, limit) }],
				details: {
					...baseDetails,
					sections: parsed.sections,
					types: parsed.types.slice(0, limit),
					imports: parsed.imports.slice(0, limit),
					exports: parsed.exports.slice(0, limit),
					importedFunctionCount: parsed.importedFunctionCount,
					definedFunctionCount: parsed.definedFunctionCount,
					functionCount: parsed.functionTypeIndices.length,
					functionNames: parsed.functionNames.size,
					...(parsed.moduleName !== undefined && { moduleName: parsed.moduleName }),
					memories: parsed.memories,
					globals: parsed.globals.slice(0, limit),
					dataSegments: parsed.dataSegments.slice(0, limit),
					customSections: parsed.customSections.slice(0, limit),
					...(parsed.startFunction !== undefined && { startFunction: parsed.startFunction }),
					truncated:
						parsed.types.length > limit ||
						parsed.imports.length > limit ||
						parsed.exports.length > limit ||
						parsed.dataSegments.length > limit ||
						parsed.globals.length > limit ||
						parsed.customSections.length > limit ||
						parsed.sections.length > Math.min(limit, 32),
				},
			};
		}

		if (params.action === "strings") {
			const minLength = params.min_length === undefined ? DEFAULT_STRING_MIN_LENGTH : Math.floor(params.min_length);
			let totalStrings = 0;
			const strings: WasmStringMatch[] = [];
			const textSources = [
				...parsed.dataSegments.map(segment => ({
					bytes: segment.bytes,
					offset: segment.offset,
					source: `data[${segment.index}]`,
				})),
				...parsed.rawCustomSections.map(segment => ({
					bytes: segment.bytes,
					offset: segment.offset,
					source: `custom:${segment.name}`,
				})),
			];
			for (const segment of textSources) {
				throwIfAborted(signal);
				totalStrings += countStrings(segment.bytes, minLength);
				if (strings.length < skip + limit) {
					for (const match of extractStrings(
						segment.bytes,
						segment.offset,
						segment.source,
						minLength,
						skip + limit - strings.length,
					)) {
						if (strings.length >= skip + limit) break;
						strings.push(match);
					}
				}
			}
			const page = strings.slice(skip, skip + limit);
			const lines = [
				`WASM strings: ${displayPath} (${page.length} shown of ${totalStrings}, min length ${minLength})`,
			];
			for (const match of page) {
				lines.push(`  ${match.source} @0x${match.offset.toString(16)}: "${match.text}"`);
			}
			if (totalStrings > page.length) {
				lines.push(
					`… ${totalStrings - page.length} more; raise limit or use skip to page, or narrow with action "search".`,
				);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					...baseDetails,
					strings: page,
					totalStrings,
					truncated: totalStrings > page.length,
				},
			};
		}

		// search
		const pattern = params.pattern?.trim() ?? "";
		if (pattern.length === 0) throw new ToolError("pattern is required for search");
		if (pattern.length > MAX_PATTERN_LENGTH) {
			throw new ToolError(`pattern is longer than the ${MAX_PATTERN_LENGTH}-character search limit`);
		}
		const scanBytes = Math.min(
			data.length,
			params.max_bytes === undefined ? DEFAULT_SEARCH_BYTES : Math.floor(params.max_bytes),
		);
		const caseSensitive = params.case_sensitive !== false;
		let result: WasmSearchResult;
		try {
			result = params.regex
				? findRegexMatches(data, pattern, caseSensitive, scanBytes, skip, limit, signal)
				: findLiteralMatches(data, pattern, !caseSensitive, scanBytes, skip, limit, signal);
		} catch (error) {
			if (error instanceof SyntaxError) {
				throw new ToolError(`Invalid regular expression: ${error.message}`);
			}
			throw error;
		}
		const lines = [
			`WASM search: ${displayPath} — ${result.matches.length} shown, ${result.totalMatches} match${result.totalMatches === 1 ? "" : "es"}${result.truncated ? " (truncated)" : ""}`,
		];
		for (const match of result.matches) {
			lines.push(`  0x${match.offset.toString(16)} (${match.length} bytes) ${match.context}`);
		}
		if (result.truncated) {
			lines.push("Search stopped at a bound; use skip to page, raise limit/max_bytes, or narrow the pattern.");
		}
		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				...baseDetails,
				matches: result.matches,
				totalMatches: result.totalMatches,
				truncated: result.truncated,
			},
		};
	}

	async #runWat(
		displayPath: string,
		absolutePath: string,
		params: WasmInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<WasmInspectDetails>> {
		const dependency = wabtDependency(this.options.which);
		if (!dependency.available || !dependency.path) {
			const hint = dependency.installHint ? ` Install it with: ${dependency.installHint}.` : "";
			const text = [
				`wasm2wat (wabt) is not available on PATH.${hint}`,
				`The native actions "info", "strings", and "search" work without wabt and cover section/import/export/name inspection plus byte and string search.`,
				`To get WAT, install wabt, then retry action "wat".`,
			].join("\n");
			return {
				content: [{ type: "text", text }],
				details: {
					action: "wat",
					path: displayPath,
					status: "missing_dependency",
					dependency,
				},
			};
		}

		const maxBytes = Math.min(
			MAX_WAT_MAX_BYTES,
			params.max_bytes === undefined ? DEFAULT_WAT_MAX_BYTES : Math.floor(params.max_bytes),
		);
		const timeoutSeconds = Math.min(
			MAX_WAT_TIMEOUT_SECONDS,
			params.timeout === undefined ? DEFAULT_WAT_TIMEOUT_SECONDS : params.timeout,
		);
		throwIfAborted(signal);
		let run: WatRunResult;
		try {
			run = await runWasm2Wat(dependency.path, absolutePath, maxBytes, timeoutSeconds * 1000, signal);
		} catch (error) {
			throw new ToolError(`Failed to run wasm2wat: ${error instanceof Error ? error.message : String(error)}`);
		}
		throwIfAborted(signal);

		if (run.timedOut) {
			const text = `wasm2wat timed out after ${timeoutSeconds}s for ${displayPath}. Raise timeout, or use the native "info" and "search" actions first.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "wat",
					path: displayPath,
					status: "error",
					dependency,
					outputBytes: run.outputBytes,
					error: `timed out after ${timeoutSeconds}s`,
				},
			};
		}
		const cappedSuccess = run.truncated && run.stdout.length > 0;
		if (run.exitCode !== 0 && !cappedSuccess) {
			const stderr = firstLine(run.stderr).slice(0, 400);
			const text = `wasm2wat failed (exit ${run.exitCode}) for ${displayPath}${stderr ? `: ${stderr}` : ""}`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "wat",
					path: displayPath,
					status: "error",
					dependency,
					outputBytes: run.outputBytes,
					error: `exit ${run.exitCode}${stderr ? `: ${stderr}` : ""}`,
				},
			};
		}

		const header = `WebAssembly text: ${displayPath} (${run.outputBytes} bytes${run.truncated ? ", truncated" : ""})`;
		const footer = run.truncated
			? `\n… WAT output truncated at ${maxBytes} bytes; raise max_bytes (up to ${MAX_WAT_MAX_BYTES}) for more.`
			: "";
		return {
			content: [{ type: "text", text: `${header}\n${run.stdout}${footer}` }],
			details: {
				action: "wat",
				path: displayPath,
				status: "ok",
				dependency,
				outputBytes: run.outputBytes,
				truncated: run.truncated,
				...(run.stderr.trim().length > 0 && { error: firstLine(run.stderr).slice(0, 400) }),
			},
		};
	}

	/** Expose the parsed list cap for tests and callers that reuse the schema. */
	static readonly maxListLimit = MAX_LIST_LIMIT;
}
