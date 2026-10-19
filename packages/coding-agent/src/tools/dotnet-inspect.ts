import type { Stats } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { type } from "@reverse/omptype";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import dotnetInspectDescription from "../prompts/tools/dotnet-inspect.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

const dotnetInspectSchema = type({
	action: type
		.enumerated("info", "types", "methods", "cil")
		.describe(
			"Read-only .NET inspection action: info (PE/CLR headers, streams, assembly identity), types (declared/referenced types), methods (method definitions and signatures), or cil (disassembled CIL bytecode and opcodes)",
		),
	path: type("string").describe("Path to the target .NET PE binary (.dll or .exe)"),
	"type?": type("string").describe("Filter by type name (full or simple name) for types, methods, or cil actions"),
	"method?": type("string").describe(
		"Method name or token (e.g. 'Main', 'Calculate', or '0x06000001') for methods or cil actions",
	),
	"target?": type("string").describe("Alias for method: method name or token to inspect"),
	"token?": type("string").describe("Metadata token in hex (e.g. 0x06000001 or 0x02000002)"),
	"filter?": type("string").describe("Substring or search filter across type, namespace, or method names"),
	"limit?": type("number").describe(
		"Maximum items/instructions returned (default 50 for lists, 100 for CIL, capped at 500/2000)",
	),
	"offset?": type("number").describe("Zero-based pagination offset"),
	"max_bytes?": type("number").describe("Maximum file bytes to read before error (default 104857600, max 524288000)"),
});

export type DotnetInspectParams = typeof dotnetInspectSchema.infer;
export type DotnetInspectAction = DotnetInspectParams["action"];

export interface DotnetAssemblyIdentity {
	name: string;
	version: string;
	culture?: string;
	publicKeyToken?: string;
	hashAlgId?: string;
}

export interface DotnetStreamInfo {
	name: string;
	offset: number;
	size: number;
}

export interface DotnetTypeInfo {
	token: string;
	namespace: string;
	name: string;
	fullName: string;
	flags: string[];
	extends?: string;
	methodCount: number;
	fieldCount: number;
}

export interface DotnetMethodInfo {
	token: string;
	declaringType: string;
	name: string;
	fullName: string;
	rva: string;
	hasBody: boolean;
	codeSize?: number;
	flags: string[];
	implFlags: string[];
}

export interface DotnetCilInstruction {
	offset: number;
	offsetHex: string;
	opcode: string;
	bytes: string;
	operand?: string | number;
	comment?: string;
}

export interface DotnetCilResult {
	methodName: string;
	declaringType: string;
	token: string;
	rva: string;
	headerFormat: "Tiny" | "Fat" | "None";
	maxStack?: number;
	codeSize: number;
	instructions: DotnetCilInstruction[];
	disassembly: string;
}

export interface DotnetInspectDetails {
	action: DotnetInspectAction;
	path: string;
	status: "ok" | "unsupported" | "error";
	format?: "PE32" | "PE32+";
	machine?: string;
	runtimeVersion?: string;
	metadataVersion?: string;
	flags?: string[];
	entryPointToken?: string;
	assembly?: DotnetAssemblyIdentity;
	module?: {
		name: string;
		mvid?: string;
	};
	streams?: DotnetStreamInfo[];
	types?: DotnetTypeInfo[];
	methods?: DotnetMethodInfo[];
	cil?: DotnetCilResult;
	total?: number;
	count?: number;
	offset?: number;
	hasMore?: boolean;
	error?: string;
}

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_CIL_LIMIT = 100;
const MAX_CIL_LIMIT = 2000;
const DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024; // 100 MiB
const HARD_MAX_FILE_BYTES = 500 * 1024 * 1024; // 500 MiB

// ============================================================================
// ECMA-335 Table & Coded Token Definitions
// ============================================================================

type ColumnType = "u16" | "u32" | "str" | "guid" | "blob" | `table:${string}` | keyof typeof CODED_TOKEN_MAP;

const CODED_TOKEN_MAP: Record<string, [tables: number[], tagBits: number]> = {
	TypeDefOrRef: [[0x02, 0x01, 0x1b], 2],
	HasConstant: [[0x04, 0x08, 0x17], 2],
	HasCustomAttribute: [
		[
			0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27,
			0x28, 0x2a, 0x2c, 0x2b,
		],
		5,
	],
	HasFieldMarshal: [[0x04, 0x08], 1],
	HasDeclSecurity: [[0x02, 0x06, 0x20], 2],
	MemberRefParent: [[0x02, 0x01, 0x1a, 0x06, 0x1b], 3],
	HasSemantics: [[0x14, 0x17], 1],
	MethodDefOrRef: [[0x06, 0x0a], 1],
	MemberForwarded: [[0x04, 0x06], 1],
	Implementation: [[0x26, 0x23, 0x27], 2],
	CustomAttributeType: [[0x06, 0x0a], 3],
	ResolutionScope: [[0x00, 0x1a, 0x23, 0x01], 2],
	TypeOrMethodDef: [[0x02, 0x06], 1],
};

const TABLE_SCHEMAS: Record<number, Array<[name: string, type: ColumnType]>> = {
	0x00: [
		["Generation", "u16"],
		["Name", "str"],
		["Mvid", "guid"],
		["EncId", "guid"],
		["EncBaseId", "guid"],
	],
	0x01: [
		["ResolutionScope", "ResolutionScope"],
		["TypeName", "str"],
		["TypeNamespace", "str"],
	],
	0x02: [
		["Flags", "u32"],
		["TypeName", "str"],
		["TypeNamespace", "str"],
		["Extends", "TypeDefOrRef"],
		["FieldList", "table:0x04"],
		["MethodList", "table:0x06"],
	],
	0x04: [
		["Flags", "u16"],
		["Name", "str"],
		["Signature", "blob"],
	],
	0x06: [
		["RVA", "u32"],
		["ImplFlags", "u16"],
		["Flags", "u16"],
		["Name", "str"],
		["Signature", "blob"],
		["ParamList", "table:0x08"],
	],
	0x08: [
		["Flags", "u16"],
		["Sequence", "u16"],
		["Name", "str"],
	],
	0x09: [
		["Class", "table:0x02"],
		["Interface", "TypeDefOrRef"],
	],
	0x0a: [
		["Class", "MemberRefParent"],
		["Name", "str"],
		["Signature", "blob"],
	],
	0x0b: [
		["Type", "u16"],
		["Parent", "HasConstant"],
		["Value", "blob"],
	],
	0x0c: [
		["Parent", "HasCustomAttribute"],
		["Type", "CustomAttributeType"],
		["Value", "blob"],
	],
	0x0d: [
		["Parent", "HasFieldMarshal"],
		["NativeType", "blob"],
	],
	0x0e: [
		["Action", "u16"],
		["Parent", "HasDeclSecurity"],
		["PermissionSet", "blob"],
	],
	0x0f: [
		["PackingSize", "u16"],
		["ClassSize", "u32"],
		["Class", "table:0x02"],
	],
	0x10: [
		["Offset", "u32"],
		["Field", "table:0x04"],
	],
	0x11: [["Signature", "blob"]],
	0x12: [
		["Parent", "table:0x02"],
		["EventList", "table:0x14"],
	],
	0x14: [
		["EventFlags", "u16"],
		["Name", "str"],
		["EventType", "TypeDefOrRef"],
	],
	0x15: [
		["Parent", "table:0x02"],
		["PropertyList", "table:0x17"],
	],
	0x17: [
		["PropFlags", "u16"],
		["Name", "str"],
		["Type", "blob"],
	],
	0x18: [
		["Semantics", "u16"],
		["Method", "table:0x06"],
		["Association", "HasSemantics"],
	],
	0x19: [
		["Class", "table:0x02"],
		["MethodBody", "MethodDefOrRef"],
		["MethodDeclaration", "MethodDefOrRef"],
	],
	0x1a: [["Name", "str"]],
	0x1b: [["Signature", "blob"]],
	0x1c: [
		["MappingFlags", "u16"],
		["MemberForwarded", "MemberForwarded"],
		["ImportName", "str"],
		["ImportScope", "table:0x1a"],
	],
	0x1d: [
		["RVA", "u32"],
		["Field", "table:0x04"],
	],
	0x20: [
		["HashAlgId", "u32"],
		["MajorVersion", "u16"],
		["MinorVersion", "u16"],
		["BuildNumber", "u16"],
		["RevisionNumber", "u16"],
		["Flags", "u32"],
		["PublicKey", "blob"],
		["Name", "str"],
		["Culture", "str"],
	],
	0x21: [["Processor", "u32"]],
	0x22: [
		["OSPlatformID", "u32"],
		["OSMajorVersion", "u32"],
		["OSMinorVersion", "u32"],
	],
	0x23: [
		["MajorVersion", "u16"],
		["MinorVersion", "u16"],
		["BuildNumber", "u16"],
		["RevisionNumber", "u16"],
		["Flags", "u32"],
		["PublicKeyOrToken", "blob"],
		["Name", "str"],
		["Culture", "str"],
		["HashValue", "blob"],
	],
	0x24: [
		["Processor", "u32"],
		["AssemblyRef", "table:0x23"],
	],
	0x25: [
		["OSPlatformID", "u32"],
		["OSMajorVersion", "u32"],
		["OSMinorVersion", "u32"],
		["AssemblyRef", "table:0x23"],
	],
	0x26: [
		["Flags", "u32"],
		["Name", "str"],
		["HashValue", "blob"],
	],
	0x27: [
		["Flags", "u32"],
		["TypeDefId", "u32"],
		["TypeName", "str"],
		["TypeNamespace", "str"],
		["Implementation", "Implementation"],
	],
	0x28: [
		["Offset", "u32"],
		["Flags", "u32"],
		["Name", "str"],
		["Implementation", "Implementation"],
	],
	0x29: [
		["NestedClass", "table:0x02"],
		["EnclosingClass", "table:0x02"],
	],
	0x2a: [
		["Number", "u16"],
		["Flags", "u16"],
		["Owner", "TypeOrMethodDef"],
		["Name", "str"],
	],
	0x2b: [
		["Method", "MethodDefOrRef"],
		["Instantiation", "blob"],
	],
	0x2c: [
		["Owner", "table:0x2a"],
		["Constraint", "TypeDefOrRef"],
	],
};

// ============================================================================
// CIL Opcodes
// ============================================================================

type CilOperandKind =
	| "none"
	| "i8_s" // ShortInlineI (1 byte signed)
	| "i32" // InlineI (4 bytes signed)
	| "i64" // InlineI8 (8 bytes signed)
	| "r32" // ShortInlineR (4 bytes float)
	| "r64" // InlineR (8 bytes double)
	| "var_s" // ShortInlineVar (1 byte unsigned)
	| "var" // InlineVar (2 bytes unsigned)
	| "br_s" // ShortInlineBrTarget (1 byte signed)
	| "br" // InlineBrTarget (4 bytes signed)
	| "tok" // InlineMethod / InlineField / InlineType / InlineTok / InlineSig (4 bytes token)
	| "str" // InlineString (4 bytes token)
	| "switch"; // InlineSwitch (count + offsets)

interface CilOpcodeDef {
	name: string;
	operandKind: CilOperandKind;
}

const CIL_ONE_BYTE_OPCODES: Record<number, CilOpcodeDef> = {
	0x00: { name: "nop", operandKind: "none" },
	0x01: { name: "break", operandKind: "none" },
	0x02: { name: "ldarg.0", operandKind: "none" },
	0x03: { name: "ldarg.1", operandKind: "none" },
	0x04: { name: "ldarg.2", operandKind: "none" },
	0x05: { name: "ldarg.3", operandKind: "none" },
	0x06: { name: "ldloc.0", operandKind: "none" },
	0x07: { name: "ldloc.1", operandKind: "none" },
	0x08: { name: "ldloc.2", operandKind: "none" },
	0x09: { name: "ldloc.3", operandKind: "none" },
	0x0a: { name: "stloc.0", operandKind: "none" },
	0x0b: { name: "stloc.1", operandKind: "none" },
	0x0c: { name: "stloc.2", operandKind: "none" },
	0x0d: { name: "stloc.3", operandKind: "none" },
	0x0e: { name: "ldarg.s", operandKind: "var_s" },
	0x0f: { name: "ldarga.s", operandKind: "var_s" },
	0x10: { name: "starg.s", operandKind: "var_s" },
	0x11: { name: "ldloc.s", operandKind: "var_s" },
	0x12: { name: "ldloca.s", operandKind: "var_s" },
	0x13: { name: "stloc.s", operandKind: "var_s" },
	0x14: { name: "ldnull", operandKind: "none" },
	0x15: { name: "ldc.i4.m1", operandKind: "none" },
	0x16: { name: "ldc.i4.0", operandKind: "none" },
	0x17: { name: "ldc.i4.1", operandKind: "none" },
	0x18: { name: "ldc.i4.2", operandKind: "none" },
	0x19: { name: "ldc.i4.3", operandKind: "none" },
	0x1a: { name: "ldc.i4.4", operandKind: "none" },
	0x1b: { name: "ldc.i4.5", operandKind: "none" },
	0x1c: { name: "ldc.i4.6", operandKind: "none" },
	0x1d: { name: "ldc.i4.7", operandKind: "none" },
	0x1e: { name: "ldc.i4.8", operandKind: "none" },
	0x1f: { name: "ldc.i4.s", operandKind: "i8_s" },
	0x20: { name: "ldc.i4", operandKind: "i32" },
	0x21: { name: "ldc.i8", operandKind: "i64" },
	0x22: { name: "ldc.r4", operandKind: "r32" },
	0x23: { name: "ldc.r8", operandKind: "r64" },
	0x25: { name: "dup", operandKind: "none" },
	0x26: { name: "pop", operandKind: "none" },
	0x27: { name: "jmp", operandKind: "tok" },
	0x28: { name: "call", operandKind: "tok" },
	0x29: { name: "calli", operandKind: "tok" },
	0x2a: { name: "ret", operandKind: "none" },
	0x2b: { name: "br.s", operandKind: "br_s" },
	0x2c: { name: "brfalse.s", operandKind: "br_s" },
	0x2d: { name: "brtrue.s", operandKind: "br_s" },
	0x2e: { name: "beq.s", operandKind: "br_s" },
	0x2f: { name: "bge.s", operandKind: "br_s" },
	0x30: { name: "bgt.s", operandKind: "br_s" },
	0x31: { name: "ble.s", operandKind: "br_s" },
	0x32: { name: "blt.s", operandKind: "br_s" },
	0x33: { name: "bne.un.s", operandKind: "br_s" },
	0x34: { name: "bge.un.s", operandKind: "br_s" },
	0x35: { name: "bgt.un.s", operandKind: "br_s" },
	0x36: { name: "ble.un.s", operandKind: "br_s" },
	0x37: { name: "blt.un.s", operandKind: "br_s" },
	0x38: { name: "br", operandKind: "br" },
	0x39: { name: "brfalse", operandKind: "br" },
	0x3a: { name: "brtrue", operandKind: "br" },
	0x3b: { name: "beq", operandKind: "br" },
	0x3c: { name: "bge", operandKind: "br" },
	0x3d: { name: "bgt", operandKind: "br" },
	0x3e: { name: "ble", operandKind: "br" },
	0x3f: { name: "blt", operandKind: "br" },
	0x40: { name: "bne.un", operandKind: "br" },
	0x41: { name: "bge.un", operandKind: "br" },
	0x42: { name: "bgt.un", operandKind: "br" },
	0x43: { name: "ble.un", operandKind: "br" },
	0x44: { name: "blt.un", operandKind: "br" },
	0x45: { name: "switch", operandKind: "switch" },
	0x46: { name: "ldind.i1", operandKind: "none" },
	0x47: { name: "ldind.u1", operandKind: "none" },
	0x48: { name: "ldind.i2", operandKind: "none" },
	0x49: { name: "ldind.u2", operandKind: "none" },
	0x4a: { name: "ldind.i4", operandKind: "none" },
	0x4b: { name: "ldind.u4", operandKind: "none" },
	0x4c: { name: "ldind.i8", operandKind: "none" },
	0x4d: { name: "ldind.i", operandKind: "none" },
	0x4e: { name: "ldind.r4", operandKind: "none" },
	0x4f: { name: "ldind.r8", operandKind: "none" },
	0x50: { name: "ldind.ref", operandKind: "none" },
	0x51: { name: "stind.ref", operandKind: "none" },
	0x52: { name: "stind.i1", operandKind: "none" },
	0x53: { name: "stind.i2", operandKind: "none" },
	0x54: { name: "stind.i4", operandKind: "none" },
	0x55: { name: "stind.i8", operandKind: "none" },
	0x56: { name: "stind.r4", operandKind: "none" },
	0x57: { name: "stind.r8", operandKind: "none" },
	0x58: { name: "add", operandKind: "none" },
	0x59: { name: "sub", operandKind: "none" },
	0x5a: { name: "mul", operandKind: "none" },
	0x5b: { name: "div", operandKind: "none" },
	0x5c: { name: "div.un", operandKind: "none" },
	0x5d: { name: "rem", operandKind: "none" },
	0x5e: { name: "rem.un", operandKind: "none" },
	0x5f: { name: "and", operandKind: "none" },
	0x60: { name: "or", operandKind: "none" },
	0x61: { name: "xor", operandKind: "none" },
	0x62: { name: "shl", operandKind: "none" },
	0x63: { name: "shr", operandKind: "none" },
	0x64: { name: "shr.un", operandKind: "none" },
	0x65: { name: "neg", operandKind: "none" },
	0x66: { name: "not", operandKind: "none" },
	0x67: { name: "conv.i1", operandKind: "none" },
	0x68: { name: "conv.i2", operandKind: "none" },
	0x69: { name: "conv.i4", operandKind: "none" },
	0x6a: { name: "conv.i8", operandKind: "none" },
	0x6b: { name: "conv.r4", operandKind: "none" },
	0x6c: { name: "conv.r8", operandKind: "none" },
	0x6d: { name: "conv.u4", operandKind: "none" },
	0x6e: { name: "conv.u8", operandKind: "none" },
	0x6f: { name: "callvirt", operandKind: "tok" },
	0x70: { name: "cpobj", operandKind: "tok" },
	0x71: { name: "ldobj", operandKind: "tok" },
	0x72: { name: "ldstr", operandKind: "str" },
	0x73: { name: "newobj", operandKind: "tok" },
	0x74: { name: "castclass", operandKind: "tok" },
	0x75: { name: "isinst", operandKind: "tok" },
	0x76: { name: "conv.r.un", operandKind: "none" },
	0x79: { name: "unbox", operandKind: "tok" },
	0x7a: { name: "throw", operandKind: "none" },
	0x7b: { name: "ldfld", operandKind: "tok" },
	0x7c: { name: "ldflda", operandKind: "tok" },
	0x7d: { name: "stfld", operandKind: "tok" },
	0x7e: { name: "ldsfld", operandKind: "tok" },
	0x7f: { name: "ldsflda", operandKind: "tok" },
	0x80: { name: "stsfld", operandKind: "tok" },
	0x81: { name: "stobj", operandKind: "tok" },
	0x82: { name: "conv.ovf.i1.un", operandKind: "none" },
	0x83: { name: "conv.ovf.i2.un", operandKind: "none" },
	0x84: { name: "conv.ovf.i4.un", operandKind: "none" },
	0x85: { name: "conv.ovf.i8.un", operandKind: "none" },
	0x86: { name: "conv.ovf.u1.un", operandKind: "none" },
	0x87: { name: "conv.ovf.u2.un", operandKind: "none" },
	0x88: { name: "conv.ovf.u4.un", operandKind: "none" },
	0x89: { name: "conv.ovf.u8.un", operandKind: "none" },
	0x8a: { name: "conv.ovf.i.un", operandKind: "none" },
	0x8b: { name: "conv.ovf.u.un", operandKind: "none" },
	0x8c: { name: "box", operandKind: "tok" },
	0x8d: { name: "newarr", operandKind: "tok" },
	0x8e: { name: "ldlen", operandKind: "none" },
	0x8f: { name: "ldelema", operandKind: "tok" },
	0x90: { name: "ldelem.i1", operandKind: "none" },
	0x91: { name: "ldelem.u1", operandKind: "none" },
	0x92: { name: "ldelem.i2", operandKind: "none" },
	0x93: { name: "ldelem.u2", operandKind: "none" },
	0x94: { name: "ldelem.i4", operandKind: "none" },
	0x95: { name: "ldelem.u4", operandKind: "none" },
	0x96: { name: "ldelem.i8", operandKind: "none" },
	0x97: { name: "ldelem.i", operandKind: "none" },
	0x98: { name: "ldelem.r4", operandKind: "none" },
	0x99: { name: "ldelem.r8", operandKind: "none" },
	0x9a: { name: "ldelem.ref", operandKind: "none" },
	0x9b: { name: "stelem.i", operandKind: "none" },
	0x9c: { name: "stelem.i1", operandKind: "none" },
	0x9d: { name: "stelem.i2", operandKind: "none" },
	0x9e: { name: "stelem.i4", operandKind: "none" },
	0x9f: { name: "stelem.i8", operandKind: "none" },
	0xa0: { name: "stelem.r4", operandKind: "none" },
	0xa1: { name: "stelem.r8", operandKind: "none" },
	0xa2: { name: "stelem.ref", operandKind: "none" },
	0xa3: { name: "ldelem", operandKind: "tok" },
	0xa4: { name: "stelem", operandKind: "tok" },
	0xa5: { name: "unbox.any", operandKind: "tok" },
	0xb3: { name: "conv.ovf.i1", operandKind: "none" },
	0xb4: { name: "conv.ovf.u1", operandKind: "none" },
	0xb5: { name: "conv.ovf.i2", operandKind: "none" },
	0xb6: { name: "conv.ovf.u2", operandKind: "none" },
	0xb7: { name: "conv.ovf.i4", operandKind: "none" },
	0xb8: { name: "conv.ovf.u4", operandKind: "none" },
	0xb9: { name: "conv.ovf.i8", operandKind: "none" },
	0xba: { name: "conv.ovf.u8", operandKind: "none" },
	0xc2: { name: "refanyval", operandKind: "tok" },
	0xc3: { name: "ckfinite", operandKind: "none" },
	0xc6: { name: "mkrefany", operandKind: "tok" },
	0xd0: { name: "ldtoken", operandKind: "tok" },
	0xd1: { name: "conv.u2", operandKind: "none" },
	0xd2: { name: "conv.u1", operandKind: "none" },
	0xd3: { name: "conv.i", operandKind: "none" },
	0xd4: { name: "conv.ovf.i", operandKind: "none" },
	0xd5: { name: "conv.ovf.u", operandKind: "none" },
	0xd6: { name: "add.ovf", operandKind: "none" },
	0xd7: { name: "add.ovf.un", operandKind: "none" },
	0xd8: { name: "mul.ovf", operandKind: "none" },
	0xd9: { name: "mul.ovf.un", operandKind: "none" },
	0xda: { name: "sub.ovf", operandKind: "none" },
	0xdb: { name: "sub.ovf.un", operandKind: "none" },
	0xdc: { name: "endfinally", operandKind: "none" },
	0xdd: { name: "leave", operandKind: "br" },
	0xde: { name: "leave.s", operandKind: "br_s" },
	0xdf: { name: "stind.i", operandKind: "none" },
	0xe0: { name: "conv.u", operandKind: "none" },
};

const CIL_TWO_BYTE_OPCODES: Record<number, CilOpcodeDef> = {
	0x00: { name: "ceq", operandKind: "none" },
	0x01: { name: "cgt", operandKind: "none" },
	0x02: { name: "cgt.un", operandKind: "none" },
	0x03: { name: "clt", operandKind: "none" },
	0x04: { name: "clt.un", operandKind: "none" },
	0x06: { name: "ldftn", operandKind: "tok" },
	0x07: { name: "ldvirtftn", operandKind: "tok" },
	0x09: { name: "ldarg", operandKind: "var" },
	0x0a: { name: "ldarga", operandKind: "var" },
	0x0b: { name: "starg", operandKind: "var" },
	0x0c: { name: "ldloc", operandKind: "var" },
	0x0d: { name: "ldloca", operandKind: "var" },
	0x0e: { name: "stloc", operandKind: "var" },
	0x0f: { name: "localloc", operandKind: "none" },
	0x11: { name: "endfilter", operandKind: "none" },
	0x12: { name: "unaligned.", operandKind: "i8_s" },
	0x13: { name: "volatile.", operandKind: "none" },
	0x14: { name: "tail.", operandKind: "none" },
	0x15: { name: "initobj", operandKind: "tok" },
	0x16: { name: "constrained.", operandKind: "tok" },
	0x17: { name: "cpblk", operandKind: "none" },
	0x18: { name: "initblk", operandKind: "none" },
	0x1a: { name: "rethrow", operandKind: "none" },
	0x1c: { name: "sizeof", operandKind: "tok" },
	0x1d: { name: "ldelem", operandKind: "tok" },
	0x1e: { name: "stelem", operandKind: "tok" },
	0x1f: { name: "unbox.any", operandKind: "tok" },
	0x22: { name: "readonly.", operandKind: "none" },
};

// ============================================================================
// Low-level PE/COFF and CLI Parser Implementation
// ============================================================================

interface PeSection {
	name: string;
	virtualSize: number;
	virtualAddress: number;
	sizeOfRawData: number;
	pointerToRawData: number;
}

interface CliHeader {
	cb: number;
	majorRuntimeVersion: number;
	minorRuntimeVersion: number;
	metadataRva: number;
	metadataSize: number;
	flags: number;
	entryPointToken: number;
}

interface MetadataRoot {
	version: string;
	streams: Record<string, { offset: number; size: number }>;
}

class PeCliParser {
	readonly buffer: Buffer;
	readonly isPe32Plus: boolean;
	readonly machine: string;
	readonly sections: PeSection[] = [];
	readonly cliHeader: CliHeader;
	readonly metadataRoot: MetadataRoot;

	// Heap flags from #~ stream
	strings4Byte = false;
	guid4Byte = false;
	blob4Byte = false;

	// Table row counts & data offsets
	readonly tableRowCounts: Record<number, number> = {};
	readonly tableOffsets: Record<number, number> = {};
	readonly tableRowSizes: Record<number, number> = {};

	constructor(buffer: Buffer) {
		this.buffer = buffer;
		if (buffer.length < 64) {
			throw new Error("File too short: missing DOS header");
		}
		if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
			throw new Error("Invalid DOS header: magic is not MZ");
		}
		const eLfanew = buffer.readUInt32LE(0x3c);
		if (eLfanew + 24 > buffer.length) {
			throw new Error("Invalid PE offset in DOS header");
		}
		if (buffer.readUInt32LE(eLfanew) !== 0x00004550) {
			throw new Error("Invalid PE signature");
		}

		const machineId = buffer.readUInt16LE(eLfanew + 4);
		this.machine =
			machineId === 0x014c
				? "I386"
				: machineId === 0x8664
					? "AMD64"
					: machineId === 0xaa64
						? "ARM64"
						: machineId === 0x0200
							? "IA64"
							: `0x${machineId.toString(16)}`;

		const numSections = buffer.readUInt16LE(eLfanew + 6);
		const sizeOfOptionalHeader = buffer.readUInt16LE(eLfanew + 20);
		const optOffset = eLfanew + 24;

		if (optOffset + sizeOfOptionalHeader > buffer.length) {
			throw new Error("Truncated optional header");
		}

		const optMagic = buffer.readUInt16LE(optOffset);
		this.isPe32Plus = optMagic === 0x20b;
		if (optMagic !== 0x10b && optMagic !== 0x20b) {
			throw new Error(`Unsupported optional header magic: 0x${optMagic.toString(16)}`);
		}

		const dataDirOffset = optOffset + (this.isPe32Plus ? 112 : 96);
		const numRvaAndSizes = buffer.readUInt32LE(optOffset + (this.isPe32Plus ? 108 : 92));

		if (numRvaAndSizes <= 14 || dataDirOffset + 15 * 8 > buffer.length) {
			throw new Error("Missing CLI COM descriptor directory entry (native binary)");
		}

		const cliRva = buffer.readUInt32LE(dataDirOffset + 14 * 8);
		const cliSize = buffer.readUInt32LE(dataDirOffset + 14 * 8 + 4);
		if (cliRva === 0 || cliSize === 0) {
			throw new Error("Missing CLI COM descriptor (native PE binary without .NET runtime header)");
		}

		// Read Sections
		const sectionsOffset = optOffset + sizeOfOptionalHeader;
		for (let i = 0; i < numSections; i++) {
			const sOff = sectionsOffset + i * 40;
			if (sOff + 40 > buffer.length) break;
			const nameRaw = buffer.toString("utf8", sOff, sOff + 8);
			const nullIdx = nameRaw.indexOf("\0");
			const name = nullIdx >= 0 ? nameRaw.slice(0, nullIdx) : nameRaw;
			const virtualSize = buffer.readUInt32LE(sOff + 8);
			const virtualAddress = buffer.readUInt32LE(sOff + 12);
			const sizeOfRawData = buffer.readUInt32LE(sOff + 16);
			const pointerToRawData = buffer.readUInt32LE(sOff + 20);
			this.sections.push({
				name,
				virtualSize,
				virtualAddress,
				sizeOfRawData,
				pointerToRawData,
			});
		}

		// Read CLI Header
		const cliOffset = this.rvaToFileOffset(cliRva);
		if (cliOffset === null || cliOffset + 72 > buffer.length) {
			throw new Error("Invalid CLI header RVA or truncated CLI header");
		}
		this.cliHeader = {
			cb: buffer.readUInt32LE(cliOffset),
			majorRuntimeVersion: buffer.readUInt16LE(cliOffset + 4),
			minorRuntimeVersion: buffer.readUInt16LE(cliOffset + 6),
			metadataRva: buffer.readUInt32LE(cliOffset + 8),
			metadataSize: buffer.readUInt32LE(cliOffset + 12),
			flags: buffer.readUInt32LE(cliOffset + 16),
			entryPointToken: buffer.readUInt32LE(cliOffset + 20),
		};

		// Read Metadata Root
		const metaOffset = this.rvaToFileOffset(this.cliHeader.metadataRva);
		if (metaOffset === null || metaOffset + 16 > buffer.length) {
			throw new Error("Invalid metadata root RVA");
		}
		const metaSig = buffer.readUInt32LE(metaOffset);
		if (metaSig !== 0x424a5342) {
			throw new Error(`Invalid metadata root signature: 0x${metaSig.toString(16)} (expected BSJB)`);
		}

		const vlen = buffer.readUInt32LE(metaOffset + 12);
		if (metaOffset + 16 + vlen > buffer.length) {
			throw new Error("Truncated metadata version string");
		}
		const rawVstr = buffer.toString("utf8", metaOffset + 16, metaOffset + 16 + vlen);
		const vNullIdx = rawVstr.indexOf("\0");
		const version = vNullIdx >= 0 ? rawVstr.slice(0, vNullIdx) : rawVstr;

		const vPadded = (vlen + 3) & ~3;
		const streamsHeaderOff = metaOffset + 16 + vPadded;
		if (streamsHeaderOff + 4 > buffer.length) {
			throw new Error("Truncated metadata stream header");
		}
		const streamCount = buffer.readUInt16LE(streamsHeaderOff + 2);
		const streams: Record<string, { offset: number; size: number }> = {};

		// Check if stream headers follow fixed 12-byte stride (e.g. compact builder/test fixtures)
		let isFixed12 = streamCount > 0;
		for (let i = 0; i < streamCount; i++) {
			const ptr = streamsHeaderOff + 4 + i * 12;
			if (ptr + 12 > buffer.length || buffer[ptr + 8] !== 0x23 /* '#' */) {
				isFixed12 = false;
				break;
			}
		}

		let streamPtr = streamsHeaderOff + 4;
		for (let i = 0; i < streamCount; i++) {
			if (streamPtr + 8 > buffer.length) break;
			const sOffset = buffer.readUInt32LE(streamPtr);
			const sSize = buffer.readUInt32LE(streamPtr + 4);
			let name: string;
			if (isFixed12) {
				let nameEnd = streamPtr + 8;
				const nameLimit = streamPtr + 12;
				while (nameEnd < nameLimit && buffer[nameEnd] !== 0) {
					nameEnd++;
				}
				name = buffer.toString("ascii", streamPtr + 8, nameEnd);
				streamPtr += 12;
			} else {
				let nameEnd = streamPtr + 8;
				while (nameEnd < buffer.length && buffer[nameEnd] !== 0) {
					nameEnd++;
				}
				name = buffer.toString("ascii", streamPtr + 8, nameEnd);
				if (nameEnd < buffer.length) nameEnd++; // skip null
				const nameLenPadded = Math.max(4, (nameEnd - (streamPtr + 8) + 3) & ~3);
				streamPtr = streamPtr + 8 + nameLenPadded;
			}

			// Normalize standard metadata stream names if truncated by fixed-width slots
			if (name.startsWith("#Str")) name = "#Strings";
			else if (name.startsWith("#GUI")) name = "#GUID";
			else if (name.startsWith("#Blo")) name = "#Blob";

			streams[name] = {
				offset: metaOffset + sOffset,
				size: sSize,
			};
		}
		this.metadataRoot = { version, streams };

		// Parse #~ or #- compressed metadata stream if present
		const tildeStream = streams["#~"] ?? streams["#-"];
		if (tildeStream && tildeStream.offset + 24 <= buffer.length) {
			this.parseTildeStream(tildeStream.offset, tildeStream.size);
		}
	}

	rvaToFileOffset(rva: number): number | null {
		for (const sec of this.sections) {
			const maxSpan = Math.max(sec.virtualSize, sec.sizeOfRawData);
			if (rva >= sec.virtualAddress && rva < sec.virtualAddress + maxSpan) {
				const off = sec.pointerToRawData + (rva - sec.virtualAddress);
				return off < this.buffer.length ? off : null;
			}
		}
		return null;
	}

	private parseTildeStream(offset: number, _size: number): void {
		const heapSizes = this.buffer[offset + 6];
		this.strings4Byte = (heapSizes & 0x01) !== 0;
		this.guid4Byte = (heapSizes & 0x02) !== 0;
		this.blob4Byte = (heapSizes & 0x04) !== 0;

		const validMask = this.readUInt64LE(offset + 8);
		let cur = offset + 24;

		for (let i = 0; i < 64; i++) {
			const bit = 1n << BigInt(i);
			if ((validMask & bit) !== 0n) {
				if (cur + 4 > this.buffer.length) break;
				this.tableRowCounts[i] = this.buffer.readUInt32LE(cur);
				cur += 4;
			}
		}

		// Calculate row sizes & table offsets
		let dataCur = cur;
		for (let i = 0; i < 64; i++) {
			const count = this.tableRowCounts[i];
			if (count === undefined || count === 0) continue;
			const schema = TABLE_SCHEMAS[i];
			if (!schema) break;
			const rowSize = this.calculateRowSize(schema);
			this.tableRowSizes[i] = rowSize;
			this.tableOffsets[i] = dataCur;
			dataCur += rowSize * count;
		}
	}

	private calculateRowSize(schema: Array<[name: string, type: ColumnType]>): number {
		let size = 0;
		for (const [, colType] of schema) {
			size += this.columnSize(colType);
		}
		return size;
	}

	private columnSize(colType: ColumnType): number {
		if (colType === "u16") return 2;
		if (colType === "u32") return 4;
		if (colType === "str") return this.strings4Byte ? 4 : 2;
		if (colType === "guid") return this.guid4Byte ? 4 : 2;
		if (colType === "blob") return this.blob4Byte ? 4 : 2;
		if (colType.startsWith("table:")) {
			const tid = parseInt(colType.slice(6), 16);
			return (this.tableRowCounts[tid] ?? 0) >= 65536 ? 4 : 2;
		}
		const coded = CODED_TOKEN_MAP[colType];
		if (coded) {
			const [tables, tagBits] = coded;
			let maxRows = 0;
			for (const t of tables) {
				const r = this.tableRowCounts[t] ?? 0;
				if (r > maxRows) maxRows = r;
			}
			return maxRows << tagBits >= 65536 ? 4 : 2;
		}
		return 2;
	}

	private readUInt64LE(offset: number): bigint {
		const low = BigInt(this.buffer.readUInt32LE(offset));
		const high = BigInt(this.buffer.readUInt32LE(offset + 4));
		return (high << 32n) | low;
	}

	readString(index: number): string {
		if (!index || index <= 0) return "";
		const stream = this.metadataRoot.streams["#Strings"];
		if (!stream) return "";
		const start = stream.offset + index;
		const streamEnd = Math.min(this.buffer.length, stream.offset + stream.size);
		if (start >= streamEnd) return "";
		let end = start;
		while (end < streamEnd && this.buffer[end] !== 0) {
			end++;
		}
		return this.buffer.toString("utf8", start, end);
	}

	readUserString(token: number): string | null {
		const stream = this.metadataRoot.streams["#US"];
		if (!stream || (token & 0xff000000) !== 0x70000000) return null;
		const index = token & 0x00ffffff;
		if (index === 0 || index >= stream.size) return null;
		const pos = stream.offset + index;
		if (pos >= this.buffer.length) return null;

		const b0 = this.buffer[pos];
		let length = 0;
		let headerLen = 0;
		if ((b0 & 0x80) === 0) {
			length = b0;
			headerLen = 1;
		} else if ((b0 & 0xc0) === 0x80) {
			length = ((b0 & 0x3f) << 8) | this.buffer[pos + 1];
			headerLen = 2;
		} else if ((b0 & 0xe0) === 0xc0) {
			length =
				((b0 & 0x1f) << 24) | (this.buffer[pos + 1] << 16) | (this.buffer[pos + 2] << 8) | this.buffer[pos + 3];
			headerLen = 4;
		} else {
			return null;
		}

		if (length <= 1 || pos + headerLen + length - 1 > this.buffer.length) return "";
		return this.buffer.toString("utf16le", pos + headerLen, pos + headerLen + length - 1);
	}

	readBlob(index: number): Buffer {
		if (index === 0) return Buffer.alloc(0);
		const stream = this.metadataRoot.streams["#Blob"];
		if (!stream) return Buffer.alloc(0);
		const pos = stream.offset + index;
		if (pos >= this.buffer.length) return Buffer.alloc(0);

		const b0 = this.buffer[pos];
		let length = 0;
		let headerLen = 0;
		if ((b0 & 0x80) === 0) {
			length = b0;
			headerLen = 1;
		} else if ((b0 & 0xc0) === 0x80) {
			length = ((b0 & 0x3f) << 8) | this.buffer[pos + 1];
			headerLen = 2;
		} else if ((b0 & 0xe0) === 0xc0) {
			length =
				((b0 & 0x1f) << 24) | (this.buffer[pos + 1] << 16) | (this.buffer[pos + 2] << 8) | this.buffer[pos + 3];
			headerLen = 4;
		} else {
			return Buffer.alloc(0);
		}

		const dataStart = pos + headerLen;
		const dataEnd = Math.min(this.buffer.length, dataStart + length);
		return this.buffer.subarray(dataStart, dataEnd);
	}

	readGuid(index: number): string | null {
		if (index === 0) return null;
		const stream = this.metadataRoot.streams["#GUID"];
		if (!stream) return null;
		const pos = stream.offset + (index - 1) * 16;
		if (pos + 16 > this.buffer.length) return null;
		const d1 = this.buffer.readUInt32LE(pos).toString(16).padStart(8, "0");
		const d2 = this.buffer
			.readUInt16LE(pos + 4)
			.toString(16)
			.padStart(4, "0");
		const d3 = this.buffer
			.readUInt16LE(pos + 6)
			.toString(16)
			.padStart(4, "0");
		const d4 = this.buffer.subarray(pos + 8, pos + 10).toString("hex");
		const d5 = this.buffer.subarray(pos + 10, pos + 16).toString("hex");
		return `{${d1}-${d2}-${d3}-${d4}-${d5}}`;
	}

	readTableRow(tableId: number, rowIndex: number): Record<string, number> | null {
		const offset = this.tableOffsets[tableId];
		const rowSize = this.tableRowSizes[tableId];
		const schema = TABLE_SCHEMAS[tableId];
		if (offset === undefined || rowSize === undefined || !schema) return null;
		const totalRows = this.tableRowCounts[tableId] ?? 0;
		if (rowIndex < 1 || rowIndex > totalRows) return null;

		let ptr = offset + (rowIndex - 1) * rowSize;
		if (ptr + rowSize > this.buffer.length) return null;

		const result: Record<string, number> = {};
		for (const [colName, colType] of schema) {
			const size = this.columnSize(colType);
			if (size === 2) {
				result[colName] = this.buffer.readUInt16LE(ptr);
			} else {
				result[colName] = this.buffer.readUInt32LE(ptr);
			}
			ptr += size;
		}
		return result;
	}

	resolveMemberName(token: number): string | null {
		const tableId = token >>> 24;
		const rowIndex = token & 0x00ffffff;
		if (tableId === 0x06) {
			// MethodDef
			const row = this.readTableRow(0x06, rowIndex);
			return row ? this.readString(row.Name) : null;
		}
		if (tableId === 0x0a) {
			// MemberRef
			const row = this.readTableRow(0x0a, rowIndex);
			return row ? this.readString(row.Name) : null;
		}
		if (tableId === 0x04) {
			// Field
			const row = this.readTableRow(0x04, rowIndex);
			return row ? this.readString(row.Name) : null;
		}
		if (tableId === 0x02) {
			// TypeDef
			const row = this.readTableRow(0x02, rowIndex);
			if (!row) return null;
			const name = this.readString(row.TypeName);
			const ns = this.readString(row.TypeNamespace);
			return ns ? `${ns}.${name}` : name;
		}
		if (tableId === 0x01) {
			// TypeRef
			const row = this.readTableRow(0x01, rowIndex);
			if (!row) return null;
			const name = this.readString(row.TypeName);
			const ns = this.readString(row.TypeNamespace);
			return ns ? `${ns}.${name}` : name;
		}
		return null;
	}
}

// ============================================================================
// Tool Class Implementation
// ============================================================================

export class DotnetInspectTool implements AgentTool<typeof dotnetInspectSchema, DotnetInspectDetails> {
	readonly name = "dotnet_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "Dotnet Inspect";
	readonly summary =
		"Native read-only inspection of .NET assemblies: PE/CLR headers, ECMA-335 metadata, type definitions, method signatures, and disassembled CIL bytecode";
	readonly description: string;
	readonly parameters = dotnetInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(dotnetInspectDescription);
	}

	async execute(
		_toolCallId: string,
		params: DotnetInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DotnetInspectDetails> & { details: DotnetInspectDetails }> {
		throwIfAborted(signal);

		const resolvedPath = resolveReadPath(params.path, this.session.cwd);

		let fileStat: Stats;
		try {
			fileStat = await stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Target file not found: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		if (fileStat.isDirectory()) {
			throw new ToolError(`Target path is a directory, not a file: ${resolvedPath}`);
		}

		const maxBytes = Math.min(params.max_bytes ?? DEFAULT_MAX_FILE_BYTES, HARD_MAX_FILE_BYTES);
		if (fileStat.size > maxBytes) {
			throw new ToolError(
				`File size (${fileStat.size} bytes) exceeds configured max_bytes limit (${maxBytes} bytes)`,
			);
		}

		let fileBuffer: Buffer;
		try {
			fileBuffer = await readFile(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Failed to read file: ${resolvedPath} (${err instanceof Error ? err.message : String(err)})`,
			);
		}

		let parser: PeCliParser;
		try {
			parser = new PeCliParser(fileBuffer);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			return {
				content: [{ type: "text", text: `[Unsupported] ${msg}` }],
				details: {
					action: params.action,
					path: params.path,
					status: "unsupported",
					error: msg,
				},
			};
		}

		switch (params.action) {
			case "info":
				return this.handleInfo(params, parser);
			case "types":
				return this.handleTypes(params, parser);
			case "methods":
				return this.handleMethods(params, parser);
			case "cil":
				return this.handleCil(params, parser);
			default:
				throw new ToolError(`Unknown action: ${params.action as string}`);
		}
	}

	private handleInfo(
		params: DotnetInspectParams,
		parser: PeCliParser,
	): AgentToolResult<DotnetInspectDetails> & { details: DotnetInspectDetails } {
		const flagsList: string[] = [];
		const rawFlags = parser.cliHeader.flags;
		if ((rawFlags & 0x0001) !== 0) flagsList.push("ILONLY");
		if ((rawFlags & 0x0002) !== 0) flagsList.push("32BITREQUIRED");
		if ((rawFlags & 0x0004) !== 0) flagsList.push("IL_LIBRARY");
		if ((rawFlags & 0x0008) !== 0) flagsList.push("STRONGNAMESIGNED");
		if ((rawFlags & 0x0010) !== 0) flagsList.push("NATIVE_ENTRYPOINT");
		if ((rawFlags & 0x00020000) !== 0) flagsList.push("TRACKDEBUGDATA");

		let asmIdentity: DotnetAssemblyIdentity | undefined;
		const asmRow = parser.readTableRow(0x20, 1);
		if (asmRow) {
			const name = parser.readString(asmRow.Name);
			const version = `${asmRow.MajorVersion}.${asmRow.MinorVersion}.${asmRow.BuildNumber}.${asmRow.RevisionNumber}`;
			const culture = parser.readString(asmRow.Culture) || undefined;
			const pkBlob = parser.readBlob(asmRow.PublicKey);
			const publicKeyToken = pkBlob.length > 0 ? pkBlob.toString("hex") : undefined;
			asmIdentity = {
				name,
				version,
				culture,
				publicKeyToken,
				hashAlgId: `0x${asmRow.HashAlgId.toString(16)}`,
			};
		}

		let moduleInfo: { name: string; mvid?: string } | undefined;
		const modRow = parser.readTableRow(0x00, 1);
		if (modRow) {
			const modName = parser.readString(modRow.Name);
			const mvid = parser.readGuid(modRow.Mvid) ?? undefined;
			moduleInfo = { name: modName, mvid };
		}

		const streamsList: DotnetStreamInfo[] = Object.entries(parser.metadataRoot.streams).map(([name, s]) => ({
			name,
			offset: s.offset,
			size: s.size,
		}));

		const details: DotnetInspectDetails = {
			action: "info",
			path: params.path,
			status: "ok",
			format: parser.isPe32Plus ? "PE32+" : "PE32",
			machine: parser.machine,
			runtimeVersion: `${parser.cliHeader.majorRuntimeVersion}.${parser.cliHeader.minorRuntimeVersion}`,
			metadataVersion: parser.metadataRoot.version,
			flags: flagsList,
			entryPointToken: `0x${parser.cliHeader.entryPointToken.toString(16).padStart(8, "0")}`,
			assembly: asmIdentity,
			module: moduleInfo,
			streams: streamsList,
			total: parser.tableRowCounts[0x02] ?? 0,
		};

		const lines = [
			`.NET Assembly Info for ${params.path}:`,
			`  Format: ${details.format} (${details.machine})`,
			`  Runtime Version: ${details.runtimeVersion}`,
			`  Metadata Version: ${details.metadataVersion}`,
			`  Flags: ${flagsList.length > 0 ? flagsList.join(", ") : "None"}`,
			`  EntryPoint Token: ${details.entryPointToken}`,
		];

		if (asmIdentity) {
			lines.push(`  Assembly: ${asmIdentity.name} (v${asmIdentity.version})`);
			if (asmIdentity.culture) lines.push(`  Culture: ${asmIdentity.culture}`);
			if (asmIdentity.publicKeyToken) lines.push(`  Public Key Token: ${asmIdentity.publicKeyToken}`);
		}

		if (moduleInfo) {
			lines.push(`  Module: ${moduleInfo.name} ${moduleInfo.mvid ? `[MVID: ${moduleInfo.mvid}]` : ""}`);
		}

		lines.push(
			`  Counts: ${parser.tableRowCounts[0x02] ?? 0} Types, ${parser.tableRowCounts[0x06] ?? 0} Methods, ${parser.tableRowCounts[0x04] ?? 0} Fields, ${parser.tableRowCounts[0x23] ?? 0} AssemblyRefs`,
		);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}

	private handleTypes(
		params: DotnetInspectParams,
		parser: PeCliParser,
	): AgentToolResult<DotnetInspectDetails> & { details: DotnetInspectDetails } {
		const totalTypes = parser.tableRowCounts[0x02] ?? 0;
		const filter = params.filter?.toLowerCase();
		const typeFilter = params.type?.toLowerCase();

		const allTypes: DotnetTypeInfo[] = [];

		for (let i = 1; i <= totalTypes; i++) {
			const row = parser.readTableRow(0x02, i);
			if (!row) continue;
			const name = parser.readString(row.TypeName);
			const ns = parser.readString(row.TypeNamespace);
			const fullName = ns ? `${ns}.${name}` : name;

			if (typeFilter && !fullName.toLowerCase().includes(typeFilter) && !name.toLowerCase().includes(typeFilter)) {
				continue;
			}
			if (filter && !fullName.toLowerCase().includes(filter)) {
				continue;
			}

			// Decode flags
			const flags: string[] = [];
			const f = row.Flags;
			const visibility = f & 0x07;
			if (visibility === 1) flags.push("public");
			else if (visibility === 0) flags.push("not_public");
			else if (visibility === 2) flags.push("nested_public");
			else if (visibility === 3) flags.push("nested_private");

			if ((f & 0x00000020) !== 0) flags.push("interface");
			else flags.push("class");
			if ((f & 0x00000080) !== 0) flags.push("abstract");
			if ((f & 0x00000100) !== 0) flags.push("sealed");
			if ((f & 0x00000800) !== 0) flags.push("serializable");

			// Resolve extends
			let extendsName: string | undefined;
			if (row.Extends !== 0) {
				const tag = row.Extends & 0x03;
				const rowIdx = row.Extends >>> 2;
				if (tag === 0) {
					// TypeDef
					const baseRow = parser.readTableRow(0x02, rowIdx);
					if (baseRow) {
						const bName = parser.readString(baseRow.TypeName);
						const bNs = parser.readString(baseRow.TypeNamespace);
						extendsName = bNs ? `${bNs}.${bName}` : bName;
					}
				} else if (tag === 1) {
					// TypeRef
					const baseRow = parser.readTableRow(0x01, rowIdx);
					if (baseRow) {
						const bName = parser.readString(baseRow.TypeName);
						const bNs = parser.readString(baseRow.TypeNamespace);
						extendsName = bNs ? `${bNs}.${bName}` : bName;
					}
				}
			}

			// Calculate method and field count from next row or table boundary
			const nextRow = i < totalTypes ? parser.readTableRow(0x02, i + 1) : null;
			const totalMethods = parser.tableRowCounts[0x06] ?? 0;
			const totalFields = parser.tableRowCounts[0x04] ?? 0;

			const nextMethodIdx = nextRow ? nextRow.MethodList : totalMethods + 1;
			const methodCount = Math.max(0, nextMethodIdx - row.MethodList);

			const nextFieldIdx = nextRow ? nextRow.FieldList : totalFields + 1;
			const fieldCount = Math.max(0, nextFieldIdx - row.FieldList);

			allTypes.push({
				token: `0x${(0x02000000 + i).toString(16).padStart(8, "0")}`,
				namespace: ns,
				name,
				fullName,
				flags,
				extends: extendsName,
				methodCount,
				fieldCount,
			});
		}

		const offset = Math.max(0, params.offset ?? 0);
		const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_LIST_LIMIT), MAX_LIST_LIMIT);
		const paged = allTypes.slice(offset, offset + limit);

		const details: DotnetInspectDetails = {
			action: "types",
			path: params.path,
			status: "ok",
			types: paged,
			total: allTypes.length,
			count: paged.length,
			offset,
			hasMore: offset + paged.length < allTypes.length,
		};

		const lines = [
			`Declared Types for ${params.path} (showing ${paged.length} of ${allTypes.length}, offset ${offset}):`,
		];
		for (const t of paged) {
			lines.push(
				`  ${t.token} [${t.flags.join(", ")}] ${t.fullName}${t.extends ? ` : ${t.extends}` : ""} (${t.methodCount} methods, ${t.fieldCount} fields)`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}

	private handleMethods(
		params: DotnetInspectParams,
		parser: PeCliParser,
	): AgentToolResult<DotnetInspectDetails> & { details: DotnetInspectDetails } {
		const totalTypes = parser.tableRowCounts[0x02] ?? 0;
		const totalMethods = parser.tableRowCounts[0x06] ?? 0;
		const typeFilter = params.type?.toLowerCase();
		const methodFilter = (params.method ?? params.target ?? params.filter)?.toLowerCase();

		// Build a map of method index to declaring type
		const methodDeclaringTypes: Record<number, string> = {};
		for (let i = 1; i <= totalTypes; i++) {
			const typeRow = parser.readTableRow(0x02, i);
			if (!typeRow) continue;
			const nextTypeRow = i < totalTypes ? parser.readTableRow(0x02, i + 1) : null;
			const endMethodIdx = nextTypeRow ? nextTypeRow.MethodList : totalMethods + 1;
			const tName = parser.readString(typeRow.TypeName);
			const tNs = parser.readString(typeRow.TypeNamespace);
			const fullTypeName = tNs ? `${tNs}.${tName}` : tName;

			for (let m = typeRow.MethodList; m < endMethodIdx; m++) {
				methodDeclaringTypes[m] = fullTypeName;
			}
		}

		const allMethods: DotnetMethodInfo[] = [];

		for (let m = 1; m <= totalMethods; m++) {
			const row = parser.readTableRow(0x06, m);
			if (!row) continue;
			const declaringType = methodDeclaringTypes[m] ?? "<UnknownType>";
			const name = parser.readString(row.Name);
			const fullName = `${declaringType}.${name}`;

			if (typeFilter && !declaringType.toLowerCase().includes(typeFilter)) {
				continue;
			}
			if (
				methodFilter &&
				!name.toLowerCase().includes(methodFilter) &&
				!fullName.toLowerCase().includes(methodFilter) &&
				`0x${(0x06000000 + m).toString(16)}` !== methodFilter
			) {
				continue;
			}

			// Flags
			const flags: string[] = [];
			const f = row.Flags;
			const memberAccess = f & 0x07;
			if (memberAccess === 1) flags.push("private");
			else if (memberAccess === 6) flags.push("public");
			else if (memberAccess === 4) flags.push("family");
			else if (memberAccess === 5) flags.push("famorassem");

			if ((f & 0x0010) !== 0) flags.push("static");
			if ((f & 0x0020) !== 0) flags.push("final");
			if ((f & 0x0040) !== 0) flags.push("virtual");
			if ((f & 0x0080) !== 0) flags.push("hidebysig");
			if ((f & 0x0400) !== 0) flags.push("abstract");
			if ((f & 0x0800) !== 0) flags.push("specialname");

			const implFlags: string[] = [];
			const imp = row.ImplFlags;
			const codeType = imp & 0x03;
			if (codeType === 0) implFlags.push("IL");
			else if (codeType === 1) implFlags.push("native");
			else if (codeType === 2) implFlags.push("OPTIL");
			else if (codeType === 3) implFlags.push("runtime");

			let codeSize: number | undefined;
			if (row.RVA !== 0) {
				const fileOffset = parser.rvaToFileOffset(row.RVA);
				if (fileOffset !== null && fileOffset < parser.buffer.length) {
					const headerByte = parser.buffer[fileOffset];
					if ((headerByte & 0x03) === 0x02) {
						// Tiny
						codeSize = headerByte >> 2;
					} else if ((headerByte & 0x03) === 0x03 && fileOffset + 8 <= parser.buffer.length) {
						// Fat
						codeSize = parser.buffer.readUInt32LE(fileOffset + 4);
					}
				}
			}

			allMethods.push({
				token: `0x${(0x06000000 + m).toString(16).padStart(8, "0")}`,
				declaringType,
				name,
				fullName,
				rva: `0x${row.RVA.toString(16).padStart(8, "0")}`,
				hasBody: row.RVA !== 0,
				codeSize,
				flags,
				implFlags,
			});
		}

		const offset = Math.max(0, params.offset ?? 0);
		const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_LIST_LIMIT), MAX_LIST_LIMIT);
		const paged = allMethods.slice(offset, offset + limit);

		const details: DotnetInspectDetails = {
			action: "methods",
			path: params.path,
			status: "ok",
			methods: paged,
			total: allMethods.length,
			count: paged.length,
			offset,
			hasMore: offset + paged.length < allMethods.length,
		};

		const lines = [
			`Method Definitions for ${params.path} (showing ${paged.length} of ${allMethods.length}, offset ${offset}):`,
		];
		for (const m of paged) {
			const sizeStr = m.codeSize !== undefined ? ` [${m.codeSize} bytes CIL]` : "";
			lines.push(`  ${m.token} RVA:${m.rva} [${m.flags.join(", ")}] ${m.fullName}${sizeStr}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}

	private handleCil(
		params: DotnetInspectParams,
		parser: PeCliParser,
	): AgentToolResult<DotnetInspectDetails> & { details: DotnetInspectDetails } {
		const totalTypes = parser.tableRowCounts[0x02] ?? 0;
		const totalMethods = parser.tableRowCounts[0x06] ?? 0;
		const methodQuery = (params.method ?? params.target ?? params.token)?.toLowerCase();

		if (!methodQuery) {
			throw new ToolError("Action 'cil' requires 'method', 'target', or 'token' parameter");
		}

		// Find matching method
		let matchedMethodIndex = -1;
		let matchedDeclaringType = "";
		let matchedMethodRow: Record<string, number> | null = null;

		// Build type map
		const methodDeclaringTypes: Record<number, string> = {};
		for (let i = 1; i <= totalTypes; i++) {
			const typeRow = parser.readTableRow(0x02, i);
			if (!typeRow) continue;
			const nextTypeRow = i < totalTypes ? parser.readTableRow(0x02, i + 1) : null;
			const endMethodIdx = nextTypeRow ? nextTypeRow.MethodList : totalMethods + 1;
			const tName = parser.readString(typeRow.TypeName);
			const tNs = parser.readString(typeRow.TypeNamespace);
			const fullTypeName = tNs ? `${tNs}.${tName}` : tName;

			for (let m = typeRow.MethodList; m < endMethodIdx; m++) {
				methodDeclaringTypes[m] = fullTypeName;
			}
		}

		// Match by token or name
		for (let m = 1; m <= totalMethods; m++) {
			const row = parser.readTableRow(0x06, m);
			if (!row) continue;
			const declaringType = methodDeclaringTypes[m] ?? "<UnknownType>";
			const name = parser.readString(row.Name);
			const fullName = `${declaringType}.${name}`;
			const tokenStr = `0x${(0x06000000 + m).toString(16).padStart(8, "0")}`.toLowerCase();

			if (
				methodQuery === tokenStr ||
				methodQuery === `0x${(0x06000000 + m).toString(16)}` ||
				methodQuery === name.toLowerCase() ||
				methodQuery === fullName.toLowerCase()
			) {
				if (params.type) {
					const typeFilter = params.type.toLowerCase();
					if (!declaringType.toLowerCase().includes(typeFilter) && !fullName.toLowerCase().includes(typeFilter)) {
						continue;
					}
				}
				matchedMethodIndex = m;
				matchedDeclaringType = declaringType;
				matchedMethodRow = row;
				break;
			}
		}

		if (matchedMethodIndex === -1 || !matchedMethodRow) {
			throw new ToolError(`Method not found in ${params.path}: '${params.method ?? params.target ?? params.token}'`);
		}

		const methodName = parser.readString(matchedMethodRow.Name);
		const token = `0x${(0x06000000 + matchedMethodIndex).toString(16).padStart(8, "0")}`;
		const rva = matchedMethodRow.RVA;

		if (rva === 0) {
			const cilResult: DotnetCilResult = {
				methodName,
				declaringType: matchedDeclaringType,
				token,
				rva: "0x00000000",
				headerFormat: "None",
				codeSize: 0,
				instructions: [],
				disassembly: `// Method: ${matchedDeclaringType}::${methodName} [Token: ${token}, RVA: 0x00000000]\n// (Abstract, runtime, or PInvoke method without CIL body)`,
			};
			return {
				content: [{ type: "text", text: cilResult.disassembly }],
				details: {
					action: "cil",
					path: params.path,
					status: "ok",
					cil: cilResult,
				},
			};
		}

		const fileOffset = parser.rvaToFileOffset(rva);
		if (fileOffset === null || fileOffset >= parser.buffer.length) {
			throw new ToolError(`Invalid method RVA 0x${rva.toString(16)}: points outside binary`);
		}

		const headerByte = parser.buffer[fileOffset];
		const headerType = headerByte & 0x03;

		let headerFormat: "Tiny" | "Fat" = "Tiny";
		let codeSize = 0;
		let maxStack = 8;
		let codeOffset = fileOffset + 1;

		if (headerType === 0x02) {
			// Tiny
			headerFormat = "Tiny";
			codeSize = headerByte >> 2;
			maxStack = 8;
			codeOffset = fileOffset + 1;
		} else if (headerType === 0x03) {
			// Fat
			headerFormat = "Fat";
			if (fileOffset + 12 > parser.buffer.length) {
				throw new ToolError("Truncated Fat method header");
			}
			const flagsFat = parser.buffer.readUInt16LE(fileOffset);
			maxStack = parser.buffer.readUInt16LE(fileOffset + 2);
			codeSize = parser.buffer.readUInt32LE(fileOffset + 4);
			const headerSize = (flagsFat >> 12) * 4;
			codeOffset = fileOffset + headerSize;
		} else {
			throw new ToolError(`Unknown CIL method header format: 0x${headerType.toString(16)}`);
		}

		if (codeOffset + codeSize > parser.buffer.length) {
			codeSize = Math.max(0, parser.buffer.length - codeOffset);
		}

		// Disassemble CIL instructions
		const allInstructions: DotnetCilInstruction[] = [];
		let ptr = codeOffset;
		const endPtr = codeOffset + codeSize;

		while (ptr < endPtr) {
			const ilOffset = ptr - codeOffset;
			const b0 = parser.buffer[ptr++];
			let opDef: CilOpcodeDef | undefined;
			const opBytes: number[] = [b0];

			if (b0 === 0xfe) {
				if (ptr >= endPtr) break;
				const b1 = parser.buffer[ptr++];
				opBytes.push(b1);
				opDef = CIL_TWO_BYTE_OPCODES[b1] ?? {
					name: `unknown.fe_${b1.toString(16).padStart(2, "0")}`,
					operandKind: "none",
				};
			} else {
				opDef = CIL_ONE_BYTE_OPCODES[b0] ?? {
					name: `unknown_${b0.toString(16).padStart(2, "0")}`,
					operandKind: "none",
				};
			}

			let operand: string | number | undefined;
			let comment: string | undefined;

			switch (opDef.operandKind) {
				case "none":
					break;
				case "i8_s": {
					if (ptr < endPtr) {
						const val = parser.buffer.readInt8(ptr++);
						opBytes.push(val & 0xff);
						operand = val;
					}
					break;
				}
				case "var_s": {
					if (ptr < endPtr) {
						const val = parser.buffer.readUInt8(ptr++);
						opBytes.push(val);
						operand = val;
					}
					break;
				}
				case "i32": {
					if (ptr + 4 <= endPtr) {
						const val = parser.buffer.readInt32LE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						operand = val;
					}
					break;
				}
				case "i64": {
					if (ptr + 8 <= endPtr) {
						const val = parser.buffer.readBigInt64LE(ptr);
						for (let i = 0; i < 8; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 8;
						operand = val.toString();
					}
					break;
				}
				case "r32": {
					if (ptr + 4 <= endPtr) {
						const val = parser.buffer.readFloatLE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						operand = val;
					}
					break;
				}
				case "r64": {
					if (ptr + 8 <= endPtr) {
						const val = parser.buffer.readDoubleLE(ptr);
						for (let i = 0; i < 8; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 8;
						operand = val;
					}
					break;
				}
				case "var": {
					if (ptr + 2 <= endPtr) {
						const val = parser.buffer.readUInt16LE(ptr);
						opBytes.push(parser.buffer[ptr], parser.buffer[ptr + 1]);
						ptr += 2;
						operand = val;
					}
					break;
				}
				case "br_s": {
					if (ptr < endPtr) {
						const delta = parser.buffer.readInt8(ptr++);
						opBytes.push(delta & 0xff);
						const targetOffset = ptr - codeOffset + delta;
						operand = `IL_${targetOffset.toString(16).padStart(4, "0")}`;
					}
					break;
				}
				case "br": {
					if (ptr + 4 <= endPtr) {
						const delta = parser.buffer.readInt32LE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						const targetOffset = ptr - codeOffset + delta;
						operand = `IL_${targetOffset.toString(16).padStart(4, "0")}`;
					}
					break;
				}
				case "tok": {
					if (ptr + 4 <= endPtr) {
						const tokenVal = parser.buffer.readUInt32LE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						operand = `0x${tokenVal.toString(16).padStart(8, "0")}`;
						const symName = parser.resolveMemberName(tokenVal);
						if (symName) {
							comment = symName;
						}
					}
					break;
				}
				case "str": {
					if (ptr + 4 <= endPtr) {
						const tokenVal = parser.buffer.readUInt32LE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						operand = `0x${tokenVal.toString(16).padStart(8, "0")}`;
						const userStr = parser.readUserString(tokenVal);
						if (userStr !== null) {
							comment = JSON.stringify(userStr);
						}
					}
					break;
				}
				case "switch": {
					if (ptr + 4 <= endPtr) {
						const count = parser.buffer.readUInt32LE(ptr);
						for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
						ptr += 4;
						const targets: string[] = [];
						const baseOffset = ptr - codeOffset + count * 4;
						for (let s = 0; s < count && ptr + 4 <= endPtr; s++) {
							const delta = parser.buffer.readInt32LE(ptr);
							for (let i = 0; i < 4; i++) opBytes.push(parser.buffer[ptr + i]);
							ptr += 4;
							targets.push(`IL_${(baseOffset + delta).toString(16).padStart(4, "0")}`);
						}
						operand = `(${targets.join(", ")})`;
					}
					break;
				}
			}

			allInstructions.push({
				offset: ilOffset,
				offsetHex: `IL_${ilOffset.toString(16).padStart(4, "0")}`,
				opcode: opDef.name,
				bytes: Buffer.from(opBytes).toString("hex"),
				operand,
				comment,
			});
		}

		const offset = Math.max(0, params.offset ?? 0);
		const limit = Math.min(Math.max(1, params.limit ?? DEFAULT_CIL_LIMIT), MAX_CIL_LIMIT);
		const paged = allInstructions.slice(offset, offset + limit);

		const disasmLines = [
			`// Method: ${matchedDeclaringType}::${methodName} [Token: ${token}, RVA: 0x${rva.toString(16)}]`,
			`// Format: ${headerFormat}, MaxStack: ${maxStack}, CodeSize: ${codeSize} bytes`,
			`// Instructions: ${paged.length} shown (offset ${offset}, total ${allInstructions.length})`,
		];

		for (const inst of paged) {
			const operandStr = inst.operand !== undefined ? ` ${inst.operand}` : "";
			const commentStr = inst.comment ? ` // ${inst.comment}` : "";
			disasmLines.push(`  ${inst.offsetHex}: ${inst.opcode}${operandStr}${commentStr}`);
		}

		const cilResult: DotnetCilResult = {
			methodName,
			declaringType: matchedDeclaringType,
			token,
			rva: `0x${rva.toString(16).padStart(8, "0")}`,
			headerFormat,
			maxStack,
			codeSize,
			instructions: paged,
			disassembly: disasmLines.join("\n"),
		};

		return {
			content: [{ type: "text", text: cilResult.disassembly }],
			details: {
				action: "cil",
				path: params.path,
				status: "ok",
				cil: cilResult,
				total: allInstructions.length,
				count: paged.length,
				offset,
				hasMore: offset + paged.length < allInstructions.length,
			},
		};
	}
}
