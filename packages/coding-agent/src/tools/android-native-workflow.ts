/**
 * Android Native Shared Library (.so), JNI, and Reverse Engineering Workflow Tool.
 *
 * Provides native, zero-external-dependency inspection of Android native libraries,
 * ELF architectures, exported JNI symbols, and Dalvik/DEX native method links
 * (RegisterNatives / Java_* exports).
 *
 * Supports:
 * - action: "inspect" - inventory native .so libraries across ABIs, ELF dynamic symbols,
 *   DEX native method declarations, and cross-references static vs dynamic JNI bindings.
 * - action: "plan" - generates a deterministic 6-stage reverse engineering workflow
 *   (unpack, decompile, disassemble, dynamic_inject, emulate, record_evidence) with
 *   structured missing dependency statuses and install hints (JADX, Apktool, Frida, Unidbg).
 * - action: "status" - reports readiness of Android reverse companions and runtime tools.
 * - action: "extract" - decompresses native .so libraries from APK containers to a
 *   dedicated output directory (e.g. ./artifacts/extracted_so/) using pure in-process deflation.
 *
 * License boundary: Clean-room implementation in pure TypeScript from standard ELF
 * and Dalvik specifications; zero GPL/AGPL copyleft dependencies or copied code.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { $which, prompt } from "@reverse/utils";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import type { ToolSession } from "./index";
import { ZipParser, parseDexBuffer, parseAxml, parseXmlText } from "./android-package-inspect";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform, type ToolCategory } from "../extensibility/skill-tool-catalog";
import {
	checkToolRequirements,
	type RequirementStatus,
	type SkillRequirementWhich,
} from "../extensibility/skill-requirements";
import androidNativeWorkflowDescription from "../prompts/tools/android-native-workflow.md" with { type: "text" };

// ============================================================================
// Parameter Schema
// ============================================================================

const androidNativeWorkflowSchema = type({
	action: type
		.enumerated("inspect", "plan", "status", "extract")
		.describe(
			"Workflow action: inspect (inventory native .so libraries, JNI exports, DEX native methods, manifest links), plan (generate 6-stage reverse engineering plan with dependency status), status (check Android toolchain and runtime readiness), or extract (decompress .so libraries to output directory)",
		),
	"path?": type("string").describe(
		"Path to target Android package (.apk, .aab, .zip) or directory with native libraries",
	),
	"target?": type("string").describe("Alias for path"),
	"abi?": type("string").describe(
		"Optional ABI architecture filter (e.g. 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')",
	),
	"library?": type("string").describe("Optional library name filter (e.g. 'libnative-crypto.so')"),
	"so_name?": type("string").describe("Alias for library"),
	"class_filter?": type("string").describe(
		"Optional substring filter for Java/Kotlin class names declaring native methods",
	),
	"output_dir?": type("string").describe(
		"Destination directory for extracted .so files (default './artifacts/extracted_so')",
	),
	"format?": type.enumerated("markdown", "json").describe("Result output format (markdown or json, default markdown)"),
	"limit?": type("number.integer >= 1").describe("Maximum items returned in lists (default 50, max 200)"),
	"offset?": type("number.integer >= 0").describe("Zero-based pagination offset (default 0)"),
});

export type AndroidNativeWorkflowParams = typeof androidNativeWorkflowSchema.infer;
export type AndroidNativeWorkflowAction = AndroidNativeWorkflowParams["action"];

// ============================================================================
// Data Interfaces & Contracts
// ============================================================================

export interface AndroidNativeLibraryInfo {
	path: string;
	name: string;
	abi: string;
	size: number;
	compressedSize: number;
	architecture: string;
	bitness: 32 | 64;
	endian: "little" | "big";
	hasJniOnLoad: boolean;
	hasJniOnUnload: boolean;
	hasRegisterNatives: boolean;
	exportedJniFunctions: string[];
	cryptoKeywords: string[];
	antiAnalysisKeywords: string[];
	importedSymbols: string[];
	neededLibraries: string[];
	rawJniCandidates?: string[]; // 未验证的原始字符串候选（仅在缺少符号表或调试字符串中发现）
}

export interface AndroidNativeMethodInfo {
	className: string;
	methodName: string;
	signature: string;
	expectedSymbol: string;
	overloadedSymbol?: string;
	status: "static_export" | "dynamic_registration" | "unresolved";
	matchedLibrary: string | null;
	candidateLibraries?: string[]; // 可能提供动态注册或存在多库同名导出的候选共享库清单
}

export interface AndroidNativeManifestLinks {
	package?: string;
	extractNativeLibs?: boolean;
	useEmbeddedDex?: boolean;
	hasCode?: boolean;
	debuggable?: boolean;
	targetSdkVersion?: number | string;
	minSdkVersion?: number | string;
}

export interface AndroidCompanionToolStatus {
	id: string;
	name: string;
	category: ToolCategory;
	installed: boolean;
	foundPath: string | null;
	secondaryMissing?: string[];
	installHint?: string;
	installCommand?: string;
	workflowRole: string;
}

export interface AndroidWorkflowReadiness {
	staticInspect: boolean;
	unpack: boolean;
	decompile: boolean;
	dynamicInject: boolean;
	emulation: boolean;
}

export interface AndroidWorkflowPlanStep {
	step_id: string;
	stage: "unpack" | "decompile" | "disassemble" | "dynamic_inject" | "emulate" | "record_evidence";
	title: string;
	tool: string;
	status: "ready" | "blocked" | "skipped";
	command_or_action: string;
	description: string;
	missing_dependencies?: string[];
	install_hints?: string[];
	remedy?: string;
}

export interface AndroidNativeWorkflowDetails {
	action: AndroidNativeWorkflowAction;
	path?: string;
	status: "ok" | "unsupported" | "error";
	error?: string;
	summary?: {
		totalLibraries: number;
		abis: string[];
		totalNativeMethods: number;
		staticExportMatched: number;
		dynamicRegistrationLikely: number;
		unresolvedMethods: number;
		antiAnalysisDetected: boolean;
	};
	libraries?: AndroidNativeLibraryInfo[];
	nativeMethods?: AndroidNativeMethodInfo[];
	manifest?: AndroidNativeManifestLinks;
	antiAnalysis?: string[];
	readiness?: AndroidWorkflowReadiness;
	tools?: AndroidCompanionToolStatus[];
	plan?: {
		target: string;
		stages: AndroidWorkflowPlanStep[];
		readiness: AndroidWorkflowReadiness;
		recommendations: string[];
	};
	extractedFiles?: Array<{
		name: string;
		size: number;
		destination: string;
	}>;
}

// ============================================================================
// JNI Name Mangling Utility (Standard JNI Spec)
// ============================================================================

/**
 * 依据 JNI 规范对标识符进行转义：
 * - '/' 替换为 '_'
 * - '_' 转义为 '_1'
 * - ';' 转义为 '_2'
 * - '[' 转义为 '_3'
 * - 非 ASCII 字母数字字符转义为 '_0xxxx'（小写 4 位十六进制）
 */
function escapeJniIdentifier(str: string): string {
	let result = "";
	for (let i = 0; i < str.length; i++) {
		const c = str[i];
		if (c === "/") {
			result += "_";
		} else if (c === "_") {
			result += "_1";
		} else if (c === ";") {
			result += "_2";
		} else if (c === "[") {
			result += "_3";
		} else if ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9")) {
			result += c;
		} else {
			const code = c.charCodeAt(0);
			result += `_0${code.toString(16).toLowerCase().padStart(4, "0")}`;
		}
	}
	return result;
}

/**
 * 根据 Oracle JNI 规范第 2 节（解析本地方法名称）转义方法参数类型签名。
 * 例如：(ILjava/lang/String;[B)V -> ILjava_lang_String_2_3B
 *       (Lcom/example/É;)V -> Lcom_example__000c9_2
 *       ()V -> ""
 */
export function mangleJniSignature(signature: string): string {
	const match = signature.match(/\((.*?)\)/);
	if (!match) return "";
	return escapeJniIdentifier(match[1]);
}

/**
 * 根据 Java/Kotlin 类名与方法名推导预期的 JNI 导出符号名。
 * 遵循 Oracle JNI 规范第 2 节规则：
 * - 前缀：Java_
 * - 类名：'.' 替换为 '_'，'_' 转义为 '_1'，非 ASCII/特殊字符转义为 '_0xxxx'
 * - 分隔符：_
 * - 方法名：'_' 转义为 '_1'，非 ASCII/特殊字符转义为 '_0xxxx'
 * - 重载后缀（提供 signature 时）：'__' 附加经转义后的参数类型签名（零参数为 '__'）
 */
export function mangleJniSymbol(className: string, methodName: string, signature?: string): string {
	const cleanClass = className.replace(/^L|;$/g, "");
	const escapedClass = escapeJniIdentifier(cleanClass.replace(/\./g, "/"));
	const escapedMethod = escapeJniIdentifier(methodName);
	const baseSymbol = `Java_${escapedClass}_${escapedMethod}`;

	if (signature !== undefined) {
		const mangledSig = mangleJniSignature(signature);
		return `${baseSymbol}__${mangledSig}`;
	}
	return baseSymbol;
}
// ============================================================================
// ULEB128 Reader for DEX Class Methods
// ============================================================================

function readUleb128(buf: Buffer, pos: { val: number }): number {
	let result = 0;
	let shift = 0;
	while (pos.val < buf.length) {
		const byte = buf[pos.val++];
		result |= (byte & 0x7f) << shift;
		if ((byte & 0x80) === 0) break;
		shift += 7;
	}
	return result;
}

// ============================================================================
// Pure TypeScript ELF Shared Object Parser
// ============================================================================

const ELF_MACHINE_NAMES: Record<number, string> = {
	40: "ARM", // 0x28 (armeabi-v7a)
	183: "AArch64", // 0xb7 (arm64-v8a)
	3: "x86", // 0x03 (x86)
	62: "x86_64", // 0x3e (x86_64)
	8: "MIPS", // 0x08
};

const CRYPTO_KEYWORD_PATTERNS = [
	/(?:aes|rsa|md5|sha1|sha256|sha512|rc4|chacha|poly1305|des|blowfish)/gi,
	/(?:encrypt|decrypt|cipher|signature|sign|verify|digest|hash|token|secret|keystore)/gi,
];

const ANTI_ANALYSIS_PATTERNS = [
	/\b(?:ptrace|TracerPid|\/proc\/self\/status|fork|kill|raise)\b/i,
	/\b(?:frida|xposed|substrate|gum-js|magisk|supersu)\b/i,
	/\b(?:debugger|anti_debug|isDebuggerConnected|detect_root|check_root)\b/i,
];

/**
 * In-process, clean-room parser for ELF shared libraries (.so).
 * Extracts machine arch, bitness, endian, exported JNI functions, dynamic symbols,
 * JNI_OnLoad/RegisterNatives links, and crypto/anti-analysis keywords.
 */
export function parseElfBuffer(buf: Buffer, libPath: string, compressedSize = 0): AndroidNativeLibraryInfo {
	const libName = path.basename(libPath);
	const abiMatch = libPath.match(/lib\/([^/]+)\//);
	const abi = abiMatch ? abiMatch[1] : "unknown";

	// Validate ELF magic: \x7fELF
	if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
		return {
			path: libPath,
			name: libName,
			abi,
			size: buf.length,
			compressedSize,
			architecture: "Unknown",
			bitness: 32,
			endian: "little",
			hasJniOnLoad: false,
			hasJniOnUnload: false,
			hasRegisterNatives: false,
			exportedJniFunctions: [],
			cryptoKeywords: [],
			antiAnalysisKeywords: [],
			importedSymbols: [],
			neededLibraries: [],
		};
	}

	const is64 = buf[4] === 2;
	const isLe = buf[5] === 1;
	const endian = isLe ? "little" : "big";
	const machine = isLe ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
	const architecture = ELF_MACHINE_NAMES[machine] ?? `arch-${machine}`;

	const exportedJniFunctions = new Set<string>();
	const importedSymbols = new Set<string>();
	const neededLibraries = new Set<string>();
	let hasJniOnLoad = false;
	let hasJniOnUnload = false;
	let hasRegisterNatives = false;

	// Read Section Headers if present
	const shOff = is64
		? isLe
			? Number(buf.readBigUInt64LE(40))
			: Number(buf.readBigUInt64BE(40))
		: isLe
			? buf.readUInt32LE(32)
			: buf.readUInt32BE(32);
	const shEntSize = isLe ? buf.readUInt16LE(is64 ? 58 : 46) : buf.readUInt16BE(is64 ? 58 : 46);
	const shNum = isLe ? buf.readUInt16LE(is64 ? 60 : 48) : buf.readUInt16BE(is64 ? 60 : 48);

	if (shOff > 0 && shNum > 0 && shOff + shNum * shEntSize <= buf.length) {
		interface SectionHeader {
			nameOff: number;
			type: number;
			offset: number;
			size: number;
			link: number;
			entSize: number;
		}

		const sections: SectionHeader[] = [];
		for (let i = 0; i < shNum; i++) {
			const entryOff = shOff + i * shEntSize;
			const type = isLe ? buf.readUInt32LE(entryOff + 4) : buf.readUInt32BE(entryOff + 4);
			const offset = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 24))
					: Number(buf.readBigUInt64BE(entryOff + 24))
				: isLe
					? buf.readUInt32LE(entryOff + 16)
					: buf.readUInt32BE(entryOff + 16);
			const size = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 32))
					: Number(buf.readBigUInt64BE(entryOff + 32))
				: isLe
					? buf.readUInt32LE(entryOff + 20)
					: buf.readUInt32BE(entryOff + 20);
			const link = isLe
				? buf.readUInt32LE(entryOff + (is64 ? 40 : 24))
				: buf.readUInt32BE(entryOff + (is64 ? 40 : 24));
			const entSize = is64
				? isLe
					? Number(buf.readBigUInt64LE(entryOff + 56))
					: Number(buf.readBigUInt64BE(entryOff + 56))
				: isLe
					? buf.readUInt32LE(entryOff + 36)
					: buf.readUInt32BE(entryOff + 36);

			sections.push({
				nameOff: isLe ? buf.readUInt32LE(entryOff) : buf.readUInt32BE(entryOff),
				type,
				offset,
				size,
				link,
				entSize,
			});
		}

		// Helper to read string from a specific string table section
		const readString = (strSecIdx: number, strOff: number): string | null => {
			if (strSecIdx >= sections.length) return null;
			const sec = sections[strSecIdx];
			if (sec.offset + strOff >= buf.length) return null;
			const p = sec.offset + strOff;
			const end = buf.indexOf(0, p);
			if (end === -1 || end > sec.offset + sec.size) return null;
			return buf.toString("utf8", p, end);
		};

		// 解析符号表：仅 SHT_DYNSYM (11) 为动态链接器所用的导出/导入符号表；SHT_SYMTAB (2) 仅用于静态调试，不属于 JNI 动态加载导出
		for (const sec of sections) {
			if (sec.type === 11 || sec.type === 2) {
				const minSymEntSize = is64 ? 24 : 16;
				const symEntSize = sec.entSize >= minSymEntSize ? sec.entSize : minSymEntSize;
				if (symEntSize <= 0) continue;
				const symCount = Math.floor(sec.size / symEntSize);

				for (let s = 0; s < symCount; s++) {
					const symOff = sec.offset + s * symEntSize;
					if (symOff + symEntSize > buf.length) break;

					const nameOff = isLe ? buf.readUInt32LE(symOff) : buf.readUInt32BE(symOff);
					if (nameOff === 0) continue;

					// 读取符号元数据：bind（绑定）、type（类型）、visibility（可见性）、shndx（段索引）
					const info = is64 ? buf.readUInt8(symOff + 4) : buf.readUInt8(symOff + 12);
					const other = is64 ? buf.readUInt8(symOff + 5) : buf.readUInt8(symOff + 13);
					const bind = info >> 4;
					const type = info & 0x0f;
					const visibility = other & 0x03;

					const shndx = is64
						? isLe
							? buf.readUInt16LE(symOff + 6)
							: buf.readUInt16BE(symOff + 6)
						: isLe
							? buf.readUInt16LE(symOff + 14)
							: buf.readUInt16BE(symOff + 14);

					const name = readString(sec.link, nameOff);
					if (!name) continue;

					// shndx === 0 为未定义导入符号 (SHN_UNDEF)
					if (shndx === 0) {
						importedSymbols.add(name);
						continue;
					}

					// 已定义符号 (SHN_UNDEF 以外且非特殊段)
					const isDefined = shndx > 0 && shndx < 0xff00;
					const isGlobalOrWeak = bind === 1 || bind === 2; // STB_GLOBAL (1) 或 STB_WEAK (2)
					const isFunction = type === 2 || type === 10; // STT_FUNC (2) 或 STT_GNU_IFUNC (10)
					const isVisible = visibility === 0 || visibility === 3; // STV_DEFAULT (0) 或 STV_PROTECTED (3)

					if (isGlobalOrWeak && isVisible) {
						if (name === "JNI_OnLoad") hasJniOnLoad = true;
						if (name === "JNI_OnUnload") hasJniOnUnload = true;
						if (name.includes("RegisterNatives")) hasRegisterNatives = true;
					}

					// 仅在 SHT_DYNSYM 中已定义、全局/弱绑定、函数类型且具有默认/受保护可见性的符号，才是真正的 JNI 动态导出
					if (sec.type === 11 && isDefined && isGlobalOrWeak && isFunction && isVisible) {
						if (name.startsWith("Java_")) {
							exportedJniFunctions.add(name);
						}
					}
				}
			} else if (sec.type === 6) {
				// SHT_DYNAMIC
				const dynEntSize = is64 ? 16 : 8;
				const dynCount = Math.floor(sec.size / dynEntSize);
				for (let d = 0; d < dynCount; d++) {
					const dynOff = sec.offset + d * dynEntSize;
					if (dynOff + dynEntSize > buf.length) break;

					const tag = is64
						? isLe
							? Number(buf.readBigInt64LE(dynOff))
							: Number(buf.readBigInt64BE(dynOff))
						: isLe
							? buf.readInt32LE(dynOff)
							: buf.readInt32BE(dynOff);
					const val = is64
						? isLe
							? Number(buf.readBigUInt64LE(dynOff + 8))
							: Number(buf.readBigUInt64BE(dynOff + 8))
						: isLe
							? buf.readUInt32LE(dynOff + 4)
							: buf.readUInt32BE(dynOff + 4);

					if (tag === 1) {
						// DT_NEEDED
						const needed = readString(sec.link, val);
						if (needed) neededLibraries.add(needed);
					}
				}
			}
		}
	}
	// 二级缓冲区扫描：在无段表时恢复关键词与标记；未在符号表中的 Java_* 仅作为未验证候选记录，绝不提升为已验证导出
	const textSample = buf.toString("latin1");
	if (textSample.includes("JNI_OnLoad")) hasJniOnLoad = true;
	if (textSample.includes("JNI_OnUnload")) hasJniOnUnload = true;
	if (textSample.includes("RegisterNatives")) hasRegisterNatives = true;

	// 收集未经验证的文本原始字符串匹配项，不作为确认导出
	const rawJniCandidates = new Set<string>();
	const javaMatches = textSample.matchAll(/\bJava_[a-zA-Z0-9_$]+/g);
	for (const m of javaMatches) {
		const sym = m[0];
		if (!exportedJniFunctions.has(sym) && !importedSymbols.has(sym)) {
			rawJniCandidates.add(sym);
		}
	}
	// Detect crypto keywords
	const cryptoKeywords = new Set<string>();
	for (const pat of CRYPTO_KEYWORD_PATTERNS) {
		const matches = textSample.matchAll(new RegExp(pat, "gi"));
		for (const m of matches) {
			cryptoKeywords.add(m[0].toLowerCase());
			if (cryptoKeywords.size >= 15) break;
		}
	}

	// Detect anti-analysis keywords
	const antiAnalysisKeywords = new Set<string>();
	for (const pat of ANTI_ANALYSIS_PATTERNS) {
		const matches = textSample.matchAll(new RegExp(pat, "gi"));
		for (const m of matches) {
			antiAnalysisKeywords.add(m[0].toLowerCase());
			if (antiAnalysisKeywords.size >= 15) break;
		}
	}

	return {
		path: libPath,
		name: libName,
		abi,
		size: buf.length,
		compressedSize,
		architecture,
		bitness: is64 ? 64 : 32,
		endian,
		hasJniOnLoad,
		hasJniOnUnload,
		hasRegisterNatives,
		exportedJniFunctions: Array.from(exportedJniFunctions).sort(),
		cryptoKeywords: Array.from(cryptoKeywords).sort(),
		antiAnalysisKeywords: Array.from(antiAnalysisKeywords).sort(),
		importedSymbols: Array.from(importedSymbols).slice(0, 50).sort(),
		neededLibraries: Array.from(neededLibraries).sort(),
		...(rawJniCandidates.size > 0 ? { rawJniCandidates: Array.from(rawJniCandidates).slice(0, 50).sort() } : {}),
	};
}

// ============================================================================
// DEX Native Method Parser
// ============================================================================

/**
 * Scans a DEX buffer for class definitions with ACC_NATIVE methods and
 * derives expected JNI symbol names.
 */
export function extractDexNativeMethods(buf: Buffer, filter?: string): AndroidNativeMethodInfo[] {
	const dexParsed = parseDexBuffer(buf);
	if (!dexParsed) return [];

	const lowerFilter = filter ? filter.toLowerCase() : null;
	const nativeMethods: AndroidNativeMethodInfo[] = [];

	for (let i = 0; i < dexParsed.classDefsSize; i++) {
		const classDefOff = dexParsed.classDefsOff + i * 32;
		if (classDefOff + 32 > buf.length) break;

		const classIdx = buf.readUInt32LE(classDefOff);
		const className = dexParsed.getClassNameFromTypeIdx(classIdx);
		if (!className) continue;

		if (lowerFilter && !className.toLowerCase().includes(lowerFilter)) {
			continue;
		}

		const classDataOff = buf.readUInt32LE(classDefOff + 24);
		if (classDataOff === 0 || classDataOff >= buf.length) continue;

		try {
			const pos = { val: classDataOff };
			const staticFieldsSize = readUleb128(buf, pos);
			const instanceFieldsSize = readUleb128(buf, pos);
			const directMethodsSize = readUleb128(buf, pos);
			const virtualMethodsSize = readUleb128(buf, pos);

			// Skip static and instance fields
			for (let f = 0; f < staticFieldsSize + instanceFieldsSize; f++) {
				readUleb128(buf, pos);
				readUleb128(buf, pos);
			}

			// Helper to process method entry
			const inspectMethod = (methodIdx: number, accessFlags: number) => {
				if ((accessFlags & 0x0100) === 0) return; // Must have ACC_NATIVE

				const methodIdOff = dexParsed.header.methodIdsOff + methodIdx * 8;
				if (methodIdOff + 8 > buf.length) return;

				const protoIdx = buf.readUInt16LE(methodIdOff + 2);
				const nameIdx = buf.readUInt32LE(methodIdOff + 4);
				const methodName = dexParsed.getDexString(nameIdx);
				if (!methodName) return;

				// 解析方法签名并校验 DEX 原型完整性
				let signature: string | null = null;
				let prototypeValid = false;

				if (protoIdx < dexParsed.header.protoIdsCount) {
					const protoIdOff = dexParsed.header.protoIdsOff + protoIdx * 12;
					if (protoIdOff + 12 <= buf.length) {
						const returnTypeIdx = buf.readUInt32LE(protoIdOff + 4);
						let returnTypeStr: string | null = null;
						if (
							returnTypeIdx < dexParsed.header.typeIdsCount &&
							dexParsed.header.typeIdsOff + returnTypeIdx * 4 + 4 <= buf.length
						) {
							returnTypeStr = dexParsed.getDexString(
								buf.readUInt32LE(dexParsed.header.typeIdsOff + returnTypeIdx * 4),
							);
						}

						if (returnTypeStr) {
							const paramsOff = buf.readUInt32LE(protoIdOff + 8);
							let paramTypes = "";
							let allParamsValid = true;

							if (paramsOff === 0) {
								prototypeValid = true;
								signature = `()${returnTypeStr}`;
							} else if (paramsOff + 4 <= buf.length) {
								const paramCount = buf.readUInt32LE(paramsOff);
								if (paramsOff + 4 + paramCount * 2 <= buf.length) {
									for (let p = 0; p < paramCount; p++) {
										const pTypeIdx = buf.readUInt16LE(paramsOff + 4 + p * 2);
										if (
											pTypeIdx < dexParsed.header.typeIdsCount &&
											dexParsed.header.typeIdsOff + pTypeIdx * 4 + 4 <= buf.length
										) {
											const desc = dexParsed.getDexString(
												buf.readUInt32LE(dexParsed.header.typeIdsOff + pTypeIdx * 4),
											);
											if (desc) {
												paramTypes += desc;
											} else {
												allParamsValid = false;
												break;
											}
										} else {
											allParamsValid = false;
											break;
										}
									}
									if (allParamsValid) {
										prototypeValid = true;
										signature = `(${paramTypes})${returnTypeStr}`;
									}
								}
							}
						}
					}
				}

				const expectedSymbol = mangleJniSymbol(className, methodName);
				const finalSignature = signature ?? "<invalid>";
				const overloadedSymbol =
					prototypeValid && signature ? mangleJniSymbol(className, methodName, signature) : undefined;

				nativeMethods.push({
					className,
					methodName,
					signature: finalSignature,
					expectedSymbol,
					...(overloadedSymbol ? { overloadedSymbol } : {}),
					status: "unresolved",
					matchedLibrary: null,
				});
			};

			// Process direct methods
			let methodIdx = 0;
			for (let m = 0; m < directMethodsSize && pos.val < buf.length; m++) {
				const diff = readUleb128(buf, pos);
				methodIdx += diff;
				const accessFlags = readUleb128(buf, pos);
				readUleb128(buf, pos); // code_off
				inspectMethod(methodIdx, accessFlags);
			}

			// Process virtual methods
			methodIdx = 0;
			for (let m = 0; m < virtualMethodsSize && pos.val < buf.length; m++) {
				const diff = readUleb128(buf, pos);
				methodIdx += diff;
				const accessFlags = readUleb128(buf, pos);
				readUleb128(buf, pos); // code_off
				inspectMethod(methodIdx, accessFlags);
			}
		} catch {
			// Continue on corrupted or non-standard class_data
		}
	}

	return nativeMethods;
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class AndroidNativeWorkflowTool implements AgentTool<
	typeof androidNativeWorkflowSchema,
	AndroidNativeWorkflowDetails
> {
	readonly name = "android_native_workflow";
	readonly approval: ToolTier = "read";
	readonly label = "Android Native Workflow";
	readonly summary =
		"Native zero-dependency reverse engineering inspection, planning, and extraction for Android native libraries (.so), JNI exports, and Dalvik/DEX native method links";
	readonly description: string;
	readonly parameters = androidNativeWorkflowSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: { which?: SkillRequirementWhich } = {},
	) {
		this.description = prompt.render(androidNativeWorkflowDescription);
	}

	async execute(
		_toolCallId: string,
		params: AndroidNativeWorkflowParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidNativeWorkflowDetails> & { details: AndroidNativeWorkflowDetails }> {
		throwIfAborted(signal);

		const action = params.action;
		const targetPath = params.path ?? params.target;
		const which = this.options.which ?? $which;
		const platform: SkillToolPlatform =
			process.platform === "darwin" || process.platform === "win32" ? process.platform : "linux";

		// ------------------------------------------------------------------------
		// Action: STATUS
		// ------------------------------------------------------------------------
		if (action === "status") {
			return this.executeStatus(which, platform);
		}

		if (!targetPath) {
			throw new ToolError(
				`Parameter 'path' or 'target' is required for action '${action}'. Please provide the path to an Android package (.apk, .aab) or native library directory.`,
			);
		}

		const resolvedPath = resolveReadPath(targetPath, this.session.cwd);
		try {
			await fs.stat(resolvedPath);
		} catch (err) {
			throw new ToolError(
				`Failed to access target path '${targetPath}' (${resolvedPath}): ${(err as Error).message}`,
			);
		}

		// ------------------------------------------------------------------------
		// Action: EXTRACT
		// ------------------------------------------------------------------------
		if (action === "extract") {
			return this.executeExtract(resolvedPath, targetPath, params, signal);
		}

		// ------------------------------------------------------------------------
		// Action: PLAN
		// ------------------------------------------------------------------------
		if (action === "plan") {
			return this.executePlan(resolvedPath, targetPath, params, which, platform, signal);
		}

		// ------------------------------------------------------------------------
		// Action: INSPECT
		// ------------------------------------------------------------------------
		return this.executeInspect(resolvedPath, targetPath, params, which, platform, signal);
	}

	// ========================================================================
	// Implementation: STATUS
	// ========================================================================

	private async executeStatus(
		which: SkillRequirementWhich,
		platform: SkillToolPlatform,
	): Promise<AgentToolResult<AndroidNativeWorkflowDetails> & { details: AndroidNativeWorkflowDetails }> {
		const androidToolIds = [
			"unidbg",
			"jadx",
			"apktool",
			"adb",
			"frida",
			"droidasc",
			"aapt2",
			"bundletool",
			"dex2jar",
			"baksmali",
			"scrcpy",
			"java",
			"radare2",
		];

		const reqs = androidToolIds.map(id => ({ id, optional: true }));
		const statuses = checkToolRequirements(reqs, { platform, which });
		const statusById: Record<string, RequirementStatus> = Object.fromEntries(statuses.map(s => [s.id, s]));

		const toolRoles: Record<string, string> = {
			unidbg: "ARM32/ARM64 Host JVM Emulation & JNI Invocation (No Device Required)",
			jadx: "DEX to Java Source Decompiler & Cross-Reference Tracing",
			apktool: "Resource Decoding & Smali Disassembly/Rebuilding",
			adb: "Android Debug Bridge & Connected Device Supervisor",
			frida: "Dynamic Memory Hooking & Native JNI Interception",
			droidasc: "Sub-Second APK Querying, Manifest & DEX Class Inspection",
			aapt2: "Android Asset Packaging Tool 2 & Resource Parsing",
			bundletool: "Android App Bundle (.aab) Inspection & APK Split Extraction",
			dex2jar: "DEX Bytecode to Java .class/.jar Converter",
			baksmali: "Dalvik Bytecode Disassembler to Smali",
			scrcpy: "Low-Latency Android Screen Mirroring & Device Control",
			java: "Java Runtime Environment (JDK/JRE) for Android Toolchain",
			radare2: "Binary Disassembly & Native ELF Section/Symbol Inspection",
		};

		const companionStatuses: AndroidCompanionToolStatus[] = [];
		for (const id of androidToolIds) {
			const desc = SKILL_TOOL_CATALOG[id];
			const req = statusById[id];
			const installed = !!req?.foundPath && (!req.secondaryMissing || req.secondaryMissing.length === 0);
			const cmds = desc?.installCommands?.[platform];
			const firstCmd = cmds && cmds.length > 0 ? cmds[0].command : undefined;
			const hint = desc?.installHints?.[platform]?.join(" or ");

			companionStatuses.push({
				id,
				name: desc?.name ?? id,
				category: desc?.category ?? "android",
				installed,
				foundPath: req?.foundPath ?? null,
				secondaryMissing: req?.secondaryMissing,
				installHint: hint,
				installCommand: firstCmd,
				workflowRole: toolRoles[id] ?? "Companion Tool",
			});
		}

		const installedTools: Record<string, boolean> = {};
		for (const t of companionStatuses) {
			installedTools[t.id] = t.installed;
		}

		const readiness: AndroidWorkflowReadiness = {
			staticInspect: true, // Native pure TypeScript tool always available
			unpack: true, // In-process zip extractor always available
			decompile: Boolean(installedTools.jadx || installedTools.droidasc),
			dynamicInject: Boolean(installedTools.frida && installedTools.adb),
			emulation: Boolean(installedTools.unidbg && installedTools.java),
		};

		const lines = [
			"# Android Reverse Companion Toolchain Status",
			"",
			"| Tool | ID | Installed | Found Path | Role |",
			"|---|---|---|---|---|",
		];

		for (const t of companionStatuses) {
			const mark = t.installed ? "✅ Yes" : "❌ No";
			const p = t.foundPath ? `\`${t.foundPath}\`` : "-";
			lines.push(`| **${t.name}** | \`${t.id}\` | ${mark} | ${p} | ${t.workflowRole} |`);
		}

		lines.push("");
		lines.push("## Workflow Capability Readiness");
		lines.push(`- **Static Native SO & JNI Triage**: ✅ Ready (built-in TypeScript zero-prep parser)`);
		lines.push(`- **Package Unpack & Native SO Extraction**: ✅ Ready (built-in in-process decompressor)`);
		lines.push(
			`- **Java/Kotlin Source Decompilation**: ${readiness.decompile ? "✅ Ready (`jadx` / `droidasc`)" : "⚠️ Limited (install `jadx` for full decompilation; zero-prep DEX header inspection available)"}`,
		);
		lines.push(
			`- **Dynamic Instrumentation on Device**: ${readiness.dynamicInject ? "✅ Ready (`frida` + `adb`)" : "⚠️ Offline (requires `frida` and `adb` with connected device/emulator)"}`,
		);
		lines.push(
			`- **Offline ARM CPU / JNI Host Emulation**: ${readiness.emulation ? "✅ Ready (`unidbg` + `java`)" : "⚠️ Missing (`unidbg` not installed; run `reverse setup reverse` to view install recipes)"}`,
		);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				status: "ok",
				tools: companionStatuses,
				readiness,
			},
		};
	}

	// ========================================================================
	// Implementation: EXTRACT
	// ========================================================================

	private async executeExtract(
		resolvedPath: string,
		displayPath: string,
		params: AndroidNativeWorkflowParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidNativeWorkflowDetails> & { details: AndroidNativeWorkflowDetails }> {
		throwIfAborted(signal);

		let buffer: Buffer;
		try {
			buffer = await fs.readFile(resolvedPath);
		} catch (err) {
			throw new ToolError(`Failed to read package file '${displayPath}': ${(err as Error).message}`);
		}

		let zip: ZipParser;
		try {
			zip = new ZipParser(buffer);
		} catch (err) {
			throw new ToolError(
				`File '${displayPath}' is not a valid ZIP/APK archive container: ${(err as Error).message}`,
			);
		}

		const outputDir = params.output_dir ?? path.join(this.session.cwd, "artifacts", "extracted_so");
		const resolvedOutDir = path.isAbsolute(outputDir) ? outputDir : path.join(this.session.cwd, outputDir);
		await fs.mkdir(resolvedOutDir, { recursive: true });

		const abiFilter = params.abi?.toLowerCase();
		const libFilter = (params.library ?? params.so_name)?.toLowerCase();

		const extractedFiles: Array<{ name: string; size: number; destination: string }> = [];

		for (const entry of zip.entries) {
			throwIfAborted(signal);

			const isSo = entry.name.startsWith("lib/") && entry.name.endsWith(".so");
			const isManifest = entry.name === "AndroidManifest.xml";

			if (!isSo && !isManifest) continue;

			if (isSo) {
				if (abiFilter && !entry.name.toLowerCase().includes(`lib/${abiFilter}/`)) continue;
				if (libFilter && !entry.name.toLowerCase().includes(libFilter)) continue;
			}

			const fileBuf = zip.readFile(entry);
			if (!fileBuf) continue;

			const destPath = path.join(resolvedOutDir, entry.name);
			await fs.mkdir(path.dirname(destPath), { recursive: true });
			await fs.writeFile(destPath, fileBuf);

			extractedFiles.push({
				name: entry.name,
				size: fileBuf.length,
				destination: destPath,
			});
		}

		const lines = [
			`# Extracted Native Shared Libraries & Manifest: \`${displayPath}\``,
			`Destination: \`${resolvedOutDir}\``,
			`Extracted Items: ${extractedFiles.length}`,
			"",
			"| Entry | Size (bytes) | Destination |",
			"|---|---|---|",
		];

		for (const f of extractedFiles) {
			lines.push(`| \`${f.name}\` | ${f.size.toLocaleString()} | \`${f.destination}\` |`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "extract",
				path: displayPath,
				status: "ok",
				extractedFiles,
			},
		};
	}

	// ========================================================================
	// Implementation: PLAN
	// ========================================================================

	private async executePlan(
		resolvedPath: string,
		displayPath: string,
		params: AndroidNativeWorkflowParams,
		which: SkillRequirementWhich,
		platform: SkillToolPlatform,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidNativeWorkflowDetails> & { details: AndroidNativeWorkflowDetails }> {
		throwIfAborted(signal);

		// Perform rapid inspection to parameterize the plan
		const inspection = await this.performInventory(resolvedPath, displayPath, params, signal);
		const statusRes = await this.executeStatus(which, platform);
		const statusDetails = statusRes.details;
		const readiness = statusDetails?.readiness ?? {
			staticInspect: true,
			unpack: true,
			decompile: false,
			dynamicInject: false,
			emulation: false,
		};
		const radareInstalled = Boolean(statusDetails?.tools?.find(t => t.id === "radare2")?.installed);

		const sampleLib = inspection.libraries[0]?.name ?? "libnative.so";
		const sampleMethod = inspection.nativeMethods[0];
		const sampleSymbol = sampleMethod?.expectedSymbol ?? "Java_com_example_app_Native_sign";
		const sampleClass = sampleMethod?.className ?? "com.example.app.Native";
		const pkg = inspection.manifest.package ?? "com.example.app";

		const stages: AndroidWorkflowPlanStep[] = [
			{
				step_id: "step_1_unpack",
				stage: "unpack",
				title: "G0/G1: Decompress Native Libraries & Manifest to Artifacts",
				tool: "android_native_workflow",
				status: "ready",
				command_or_action: `android_native_workflow(action: "extract", path: "${displayPath}")`,
				description:
					"Extract target .so binaries (arm64-v8a / armeabi-v7a) and AndroidManifest.xml safely into ./artifacts/extracted_so/ for static analysis and emulation.",
			},
			{
				step_id: "step_2_decompile",
				stage: "decompile",
				title: "G1/G2: Decompile Java/Kotlin Call Sites & Native Declarations",
				tool: readiness.decompile ? "jadx" : "android_package_inspect",
				status: readiness.decompile ? "ready" : "blocked",
				command_or_action: readiness.decompile
					? `jadx -d ./artifacts/jadx_out --single-class "${sampleClass}" ${displayPath}`
					: `android_package_inspect(action: "dex", path: "${displayPath}")`,
				description:
					"Analyze Java method arguments, System.loadLibrary() calls, and data preparation before native boundary transitions.",
				missing_dependencies: readiness.decompile ? undefined : ["jadx"],
				install_hints: readiness.decompile ? undefined : ["brew install jadx (macOS) or apt install jadx (Linux)"],
				remedy: readiness.decompile
					? undefined
					: "Use zero-prep android_package_inspect(action: 'dex') as fallback or install JADX via setup reverse.",
			},
			{
				step_id: "step_3_disassemble",
				stage: "disassemble",
				title: "G2/G3: Disassemble Native .so & Map JNI Functions",
				tool: "r2_inspect",
				status: radareInstalled ? "ready" : "blocked",
				command_or_action: `r2_inspect(action: "functions", path: "./artifacts/extracted_so/lib/arm64-v8a/${sampleLib}")`,
				description:
					"Analyze exported JNI functions, JNI_OnLoad registration pointers, and cryptographic or anti-debug routines.",
				missing_dependencies: radareInstalled ? undefined : ["radare2"],
				install_hints: ["brew install radare2 or apt install radare2"],
			},
			{
				step_id: "step_4_dynamic_inject",
				stage: "dynamic_inject",
				title: "G3: Dynamic Instrumentation via Frida on Live Device",
				tool: "frida_session",
				status: readiness.dynamicInject ? "ready" : "blocked",
				command_or_action: `frida_session(action: "create", spawn: "${pkg}")`,
				description:
					"Hook JNI methods or intercept RegisterNatives in memory on an attached Android device to record live parameters and decrypted keys.",
				missing_dependencies: readiness.dynamicInject ? undefined : ["frida", "adb"],
				install_hints: ["pipx install frida-tools && brew install --cask android-platform-tools"],
				remedy:
					"If no physical device or emulator is connected, bypass this step and execute Step 5 (Unidbg Host Emulation).",
			},
			{
				step_id: "step_5_emulate",
				stage: "emulate",
				title: "G3: Headless ARM CPU & JNI Emulation via Unidbg (Device-Free)",
				tool: "unidbg",
				status: readiness.emulation ? "ready" : "blocked",
				command_or_action: `mvn test -Dtest=UnidbgTest (custom Java harness required for ./artifacts/extracted_so/lib/arm64-v8a/${sampleLib})`,
				description:
					"Emulate ARM instructions on host JVM to execute target JNI function headlessly via custom Maven Java harness (manual integration required).",
				missing_dependencies: readiness.emulation ? undefined : ["unidbg"],
				install_hints: ["git clone https://github.com/zhkl0228/unidbg.git && cd unidbg && mvn package -DskipTests"],
				remedy: "Compile Unidbg runner or set UNIDBG_HOME in environment. Safe for CI and offline workstations.",
			},
			{
				step_id: "step_6_record_evidence",
				stage: "record_evidence",
				title: "G4: Record Verified Findings to Evidence Ledger",
				tool: "evidence",
				status: "ready",
				command_or_action: `evidence(action: "add", kind: "fact", target: "${displayPath}", sourceTool: "android_native_workflow", locator: "${sampleSymbol}")`,
				description:
					"Record verified cryptographic keys, decrypted payloads, or JNI method mappings into the empirical evidence ledger.",
			},
		];

		const recommendations = [
			"For immediate static triage: execute Step 1 (extract) to unpack native .so files into ./artifacts/.",
			readiness.emulation
				? "Unidbg is installed: you can emulate ARM native code directly on this machine without a phone."
				: "Unidbg is missing: run 'reverse setup reverse' or compile zhkl0228/unidbg to enable device-free JNI emulation.",
			readiness.dynamicInject
				? "Frida and ADB are available: attach an Android device to execute live on-device hooks."
				: "No dynamic device toolchain detected: proceed with static disassembly (Step 3) or Unidbg emulation (Step 5).",
		];

		const lines = [
			`# Android Native Reverse Engineering Plan: \`${displayPath}\``,
			`Target Package: \`${pkg}\` | Libraries: ${inspection.libraries.length} | Native Methods: ${inspection.nativeMethods.length}`,
			"",
			"| Step | Stage | Tool | Status | Action / Command |",
			"|---|---|---|---|---|",
		];

		for (const s of stages) {
			const mark = s.status === "ready" ? "✅ Ready" : "⚠️ Blocked";
			lines.push(`| \`${s.step_id}\` | ${s.stage} | \`${s.tool}\` | ${mark} | \`${s.command_or_action}\` |`);
		}

		lines.push("");
		lines.push("## Plan Execution Recommendations");
		for (const r of recommendations) {
			lines.push(`- ${r}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "plan",
				path: displayPath,
				status: "ok",
				plan: {
					target: displayPath,
					stages,
					readiness,
					recommendations,
				},
			},
		};
	}

	// ========================================================================
	// Implementation: INSPECT
	// ========================================================================

	private async executeInspect(
		resolvedPath: string,
		displayPath: string,
		params: AndroidNativeWorkflowParams,
		which: SkillRequirementWhich,
		platform: SkillToolPlatform,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AndroidNativeWorkflowDetails> & { details: AndroidNativeWorkflowDetails }> {
		throwIfAborted(signal);

		const inventory = await this.performInventory(resolvedPath, displayPath, params, signal);
		const statusRes = await this.executeStatus(which, platform);

		if (params.format === "json") {
			return {
				content: [{ type: "text", text: JSON.stringify(inventory, null, 2) }],
				details: {
					action: "inspect",
					path: displayPath,
					status: "ok",
					summary: inventory.summary,
					libraries: inventory.libraries,
					nativeMethods: inventory.nativeMethods,
					manifest: inventory.manifest,
					antiAnalysis: inventory.antiAnalysis,
					readiness: statusRes.details?.readiness,
				},
			};
		}

		const lines = [
			`# Android Native SO & JNI Inspection Report: \`${displayPath}\``,
			`Package: \`${inventory.manifest.package ?? "unknown"}\` | Target SDK: \`${inventory.manifest.targetSdkVersion ?? "unknown"}\``,
			`Native Libraries: ${inventory.summary.totalLibraries} | ABIs: ${inventory.summary.abis.join(", ") || "none"}`,
			`DEX Native Methods: ${inventory.summary.totalNativeMethods} (Matched Exports: ${inventory.summary.staticExportMatched}, Dynamic Registration: ${inventory.summary.dynamicRegistrationLikely}, Unresolved: ${inventory.summary.unresolvedMethods})`,
			"",
		];

		if (inventory.antiAnalysis.length > 0) {
			lines.push("## ⚠️ Anti-Analysis & Packer Indicators");
			for (const ind of inventory.antiAnalysis) {
				lines.push(`- **Warning**: ${ind}`);
			}
			lines.push("");
		}

		lines.push("## Native Libraries (.so) Inventory");
		if (inventory.libraries.length === 0) {
			lines.push("No native `.so` libraries found in target package container.");
		} else {
			lines.push("| Library | ABI | Arch | Bitness | JNI_OnLoad | RegisterNatives | Exported JNI | Size |");
			lines.push("|---|---|---|---|---|---|---|---|");
			for (const lib of inventory.libraries) {
				const onLoad = lib.hasJniOnLoad ? "✅ Yes" : "No";
				const regNat = lib.hasRegisterNatives ? "✅ Yes" : "No";
				lines.push(
					`| \`${lib.name}\` | \`${lib.abi}\` | ${lib.architecture} | ${lib.bitness}-bit | ${onLoad} | ${regNat} | ${lib.exportedJniFunctions.length} | ${lib.size.toLocaleString()} B |`,
				);
			}
		}

		lines.push("");
		lines.push("## DEX Native Methods & JNI Binding Resolution");
		if (inventory.nativeMethods.length === 0) {
			lines.push("No classes declare `native` methods in scanned DEX files.");
		} else {
			lines.push("| Class | Method | Signature | Expected Symbol | Resolution | Matched SO |");
			lines.push("|---|---|---|---|---|---|");
			const limit = params.limit ?? 50;
			const offset = params.offset ?? 0;
			const paged = inventory.nativeMethods.slice(offset, offset + limit);

			for (const m of paged) {
				let resIcon = "❓ Unresolved";
				if (m.status === "static_export") resIcon = "✅ Static Export";
				else if (m.status === "dynamic_registration") resIcon = "⚡ Dynamic (RegisterNatives)";

				let matched = "-";
				if (m.matchedLibrary) {
					matched = `\`${m.matchedLibrary}\``;
				} else if (m.candidateLibraries && m.candidateLibraries.length > 0) {
					matched = `Candidates: ${m.candidateLibraries.map(c => `\`${c}\``).join(", ")}`;
				}
				lines.push(
					`| \`${m.className}\` | \`${m.methodName}\` | \`${m.signature}\` | \`${m.expectedSymbol}\` | ${resIcon} | ${matched} |`,
				);
			}

			if (inventory.nativeMethods.length > offset + limit) {
				lines.push("");
				lines.push(
					`*(Showing ${paged.length} of ${inventory.nativeMethods.length} native methods. Use offset=${offset + limit} to page)*`,
				);
			}
		}

		lines.push("");
		lines.push("## Recommended Next Steps");
		lines.push(
			`- Run \`android_native_workflow(action: "extract", path: "${displayPath}")\` to unpack .so files to disk.`,
		);
		lines.push(
			`- Run \`android_native_workflow(action: "plan", path: "${displayPath}")\` to preview the structured 6-stage reverse plan.`,
		);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "inspect",
				path: displayPath,
				status: "ok",
				summary: inventory.summary,
				libraries: inventory.libraries,
				nativeMethods: inventory.nativeMethods,
				manifest: inventory.manifest,
				antiAnalysis: inventory.antiAnalysis,
				readiness: statusRes.details?.readiness,
			},
		};
	}

	// ========================================================================
	// Core Analysis Engine
	// ========================================================================

	private async performInventory(
		resolvedPath: string,
		displayPath: string,
		params: AndroidNativeWorkflowParams,
		signal?: AbortSignal,
	): Promise<{
		summary: NonNullable<AndroidNativeWorkflowDetails["summary"]>;
		libraries: AndroidNativeLibraryInfo[];
		nativeMethods: AndroidNativeMethodInfo[];
		manifest: AndroidNativeManifestLinks;
		antiAnalysis: string[];
	}> {
		throwIfAborted(signal);

		let buffer: Buffer;
		try {
			buffer = await fs.readFile(resolvedPath);
		} catch (err) {
			throw new ToolError(`Failed to read target file '${displayPath}': ${(err as Error).message}`);
		}

		let zip: ZipParser;
		try {
			zip = new ZipParser(buffer);
		} catch (err) {
			throw new ToolError(
				`File '${displayPath}' is not a valid ZIP/APK archive container: ${(err as Error).message}`,
			);
		}

		const abiFilter = params.abi?.toLowerCase();
		const libFilter = (params.library ?? params.so_name)?.toLowerCase();
		const classFilter = params.class_filter;

		// 1. Parse Native Libraries (.so)
		const libraries: AndroidNativeLibraryInfo[] = [];
		const soEntries = zip.entries.filter(e => e.name.startsWith("lib/") && e.name.endsWith(".so"));

		for (const entry of soEntries) {
			throwIfAborted(signal);

			if (abiFilter && !entry.name.toLowerCase().includes(`lib/${abiFilter}/`)) continue;
			if (libFilter && !entry.name.toLowerCase().includes(libFilter)) continue;

			const soBuf = zip.readFile(entry);
			if (!soBuf) continue;

			const parsedLib = parseElfBuffer(soBuf, entry.name, entry.compressedSize);
			libraries.push(parsedLib);
		}

		// 2. Parse DEX Files for native method declarations
		const nativeMethods: AndroidNativeMethodInfo[] = [];
		const dexEntries = zip.entries.filter(e => e.name.endsWith(".dex"));

		for (const entry of dexEntries) {
			throwIfAborted(signal);

			const dexBuf = zip.readFile(entry);
			if (!dexBuf) continue;

			const methods = extractDexNativeMethods(dexBuf, classFilter);
			nativeMethods.push(...methods);
		}

		// 3. 解析 DEX 本地方法与 .so 导出及 JNI_OnLoad 候选关联
		let staticExportMatched = 0;
		// 遗留启发式字段：静态分析在缺乏运行时追踪（如 Frida/Unidbg）时无法断言具体动态注册绑定，设为 0 避免虚假确认
		const dynamicRegistrationLikely = 0;
		let unresolvedMethods = 0;

		const markerCandidateLibs = libraries.filter(l => l.hasJniOnLoad || l.hasRegisterNatives).map(l => l.name);
		const uniqueMarkerLibs = Array.from(new Set(markerCandidateLibs));

		for (const method of nativeMethods) {
			// 收集所有导出了该 JNI 符号的共享库
			const matchingLibs = libraries.filter(
				l =>
					l.exportedJniFunctions.includes(method.expectedSymbol) ||
					(Boolean(method.overloadedSymbol) && l.exportedJniFunctions.includes(method.overloadedSymbol!)),
			);

			const uniqueExportingLibNames = Array.from(new Set(matchingLibs.map(l => l.name)));

			if (uniqueExportingLibNames.length === 1) {
				// 唯一定义匹配：无论存在单 ABI 还是跨多个 ABI 的同名库，均确定归属为该库
				method.status = "static_export";
				method.matchedLibrary = uniqueExportingLibNames[0];
				staticExportMatched++;
			} else if (uniqueExportingLibNames.length > 1) {
				// 存在多个不同库导出同名符号，缺乏运行时加载顺序时不可武断指定归属，标记为未解决并保留所有候选库
				method.status = "unresolved";
				method.matchedLibrary = null;
				method.candidateLibraries = uniqueExportingLibNames;
				unresolvedMethods++;
			} else {
				// 无静态导出符号匹配：仅作为动态注册候选提示，不确认归属
				method.status = "unresolved";
				method.matchedLibrary = null;
				if (uniqueMarkerLibs.length > 0) {
					method.candidateLibraries = [...uniqueMarkerLibs];
				}
				unresolvedMethods++;
			}
		}

		// 4. Parse AndroidManifest.xml links
		const manifestLinks: AndroidNativeManifestLinks = {};
		const manifestEntry = zip.getEntry("AndroidManifest.xml");
		if (manifestEntry) {
			const mBuf = zip.readFile(manifestEntry);
			if (mBuf) {
				const parsedManifest = parseAxml(mBuf) ?? parseXmlText(mBuf.toString("utf8"));
				if (parsedManifest) {
					manifestLinks.package = parsedManifest.package;
					manifestLinks.targetSdkVersion = parsedManifest.targetSdkVersion;
					manifestLinks.minSdkVersion = parsedManifest.minSdkVersion;
					manifestLinks.extractNativeLibs = parsedManifest.application?.extractNativeLibs;
					manifestLinks.useEmbeddedDex = parsedManifest.application?.useEmbeddedDex;
					manifestLinks.hasCode = parsedManifest.application?.hasCode;
					manifestLinks.debuggable = parsedManifest.application?.debuggable;
				}
			}
		}

		// 5. Anti-Analysis & Packer Audits
		const antiAnalysis: string[] = [];
		const knownPackers: Record<string, string> = {
			"libjiagu.so": "Qihoo 360 Jiagu Packer",
			"libsecmain.so": "Bangcle / Secneo Packer",
			"libtup.so": "Tencent Legu Packer",
			"libDexHelper.so": "Secshell Packer",
			"libprotectClass.so": "Alibaba / Ali2Cloud Packer",
			"libkwscmm.so": "Kuaishou Packer",
		};

		for (const lib of libraries) {
			if (knownPackers[lib.name]) {
				antiAnalysis.push(`Known commercial Android packer detected: '${lib.name}' (${knownPackers[lib.name]}).`);
			}
			if (lib.antiAnalysisKeywords.includes("ptrace")) {
				antiAnalysis.push(`Library '${lib.name}' references 'ptrace' anti-debugging routine or API symbol.`);
			}
			if (lib.antiAnalysisKeywords.includes("tracerpid")) {
				antiAnalysis.push(`Library '${lib.name}' inspects '/proc/self/status' TracerPid to detect debuggers.`);
			}
		}

		const abis = Array.from(new Set(libraries.map(l => l.abi))).sort();

		return {
			summary: {
				totalLibraries: libraries.length,
				abis,
				totalNativeMethods: nativeMethods.length,
				staticExportMatched,
				dynamicRegistrationLikely,
				unresolvedMethods,
				antiAnalysisDetected: antiAnalysis.length > 0,
			},
			libraries,
			nativeMethods,
			manifest: manifestLinks,
			antiAnalysis,
		};
	}
}
