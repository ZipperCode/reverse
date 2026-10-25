/**
 * DexKit structured Dalvik/ART code search engine.
 *
 * Exposes engine-backed DEX/APK queries matching classes, methods, and fields on
 * string constants, signatures, annotations, and call-graph / cross-references.
 * Uses upstream LuckyPray/DexKit external runtime (Core LGPL-3.0, wrapper Apache-2.0).
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import { stat } from "node:fs/promises";
import type { Stats } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt, $which } from "@reverse/utils";
import dexSearchDescription from "../prompts/tools/dex-search.md" with { type: "text" };
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import {
	resolveProtectionTool,
	inspectProtectionTool,
	type ProtectionToolResolved,
} from "../extensibility/protection-toolchain";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";

// ============================================================================
// Limits & Defaults
// ============================================================================

export const DEX_SEARCH_DEFAULT_LIMIT = 50;
export const DEX_SEARCH_MAX_LIMIT = 200;
export const DEX_SEARCH_DEFAULT_TIMEOUT_SEC = 60;
export const DEX_SEARCH_MAX_TIMEOUT_SEC = 300;
export const DEX_SEARCH_MAX_OUTPUT_BYTES = 4 * 1024 * 1024; // 4 MiB
export const DEX_SEARCH_MAX_TARGET_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB

// ============================================================================
// Schema
// ============================================================================

const dexSearchSchema = type({
	target: type("string").describe(
		"Path to target Android .apk, .dex, or archive (.jar/.zip) containing Dalvik bytecode",
	),
	"type?": type
		.enumerated("class", "method", "field", "callers", "callees", "field_uses", "batch_strings", "info")
		.describe("Search query type (default: 'class')"),
	"action?": type
		.enumerated("class", "method", "field", "callers", "callees", "field_uses", "batch_strings", "info")
		.describe("Alias for type"),
	"class?": type("string").describe(
		"Target class name or pattern (e.g. 'com.example.MainActivity' or 'Lcom/example/MainActivity;')",
	),
	"className?": type("string").describe("Alias for class"),
	"name?": type("string").describe("Member name to match (method name or field name)"),
	"methodName?": type("string").describe("Alias for name in method searches"),
	"fieldName?": type("string").describe("Alias for name in field searches"),
	"returnType?": type("string").describe(
		"Method return type to match (e.g. 'void', 'boolean', 'java.lang.String', 'byte[]')",
	),
	"return_type?": type("string").describe("Alias for returnType"),
	"paramTypes?": type("string")
		.array()
		.describe("Array of parameter type names to match (e.g. ['java.lang.String', 'int'])"),
	"param_types?": type("string").array().describe("Alias for paramTypes"),
	"fieldType?": type("string").describe("Field type to match (e.g. 'java.lang.String', 'int')"),
	"field_type?": type("string").describe("Alias for fieldType"),
	"superClass?": type("string").describe("Superclass name to match in class queries (e.g. 'android.app.Activity')"),
	"super_class?": type("string").describe("Alias for superClass"),
	"searchPackages?": type("string").array().describe("Package prefixes to restrict search to (e.g. ['com.example'])"),
	"search_packages?": type("string").array().describe("Alias for searchPackages"),
	"excludePackages?": type("string").array().describe("Package prefixes to exclude from search"),
	"exclude_packages?": type("string").array().describe("Alias for excludePackages"),
	"usingStrings?": type("string").array().describe("String literal constants used by the class or method"),
	"using_strings?": type("string").array().describe("Alias for usingStrings"),
	"usingNumbers?": type("number").array().describe("Numeric constants used by the method"),
	"using_numbers?": type("number").array().describe("Alias for usingNumbers"),
	"stringMatchType?": type
		.enumerated("contains", "equals", "startsWith", "endsWith", "similarRegex")
		.describe("String matching mode: 'contains' (default), 'equals', 'startsWith', 'endsWith', or 'similarRegex'"),
	"string_match_type?": type
		.enumerated("contains", "equals", "startsWith", "endsWith", "similarRegex")
		.describe("Alias for stringMatchType"),
	"ignoreCase?": type("boolean").describe("Whether string matching should ignore case (default: false)"),
	"ignore_case?": type("boolean").describe("Alias for ignoreCase"),
	"modifiers?": type("string").array().describe("Expected modifiers (e.g. ['public', 'static', 'final'])"),
	"method?": type("string").describe(
		"Target method descriptor for callers/callees queries (e.g. 'Lcom/example/Auth;->verifyToken(Ljava/lang/String;)Z')",
	),
	"target_method?": type("string").describe("Alias for method"),
	"field?": type("string").describe(
		"Target field descriptor for field_uses queries (e.g. 'Lcom/example/Auth;->token:Ljava/lang/String;')",
	),
	"target_field?": type("string").describe("Alias for field"),
	"groups?": type
		.record(type("string"), type("string").array())
		.describe("Search groups dictionary for batch_strings query (e.g. {'auth': ['token', 'login']})"),
	"batchTarget?": type
		.enumerated("class", "method")
		.describe("Target entity for batch_strings query ('class' or 'method', default: 'method')"),
	"batch_target?": type.enumerated("class", "method").describe("Alias for batchTarget"),
	"limit?": type("number").describe("Maximum results to return per page (default: 50, max: 200)"),
	"offset?": type("number").describe("Result offset for pagination (default: 0)"),
	"timeout?": type("number").describe("Execution timeout in seconds (default: 60, max: 300)"),
});

export type DexSearchParams = typeof dexSearchSchema.infer;
export type DexSearchQueryType =
	| "class"
	| "method"
	| "field"
	| "callers"
	| "callees"
	| "field_uses"
	| "batch_strings"
	| "info";

// ============================================================================
// Result & Details Interfaces
// ============================================================================

export interface DexSearchResultItem {
	descriptor: string;
	className?: string;
	simpleName?: string;
	name?: string;
	returnType?: string;
	paramTypes?: string[];
	type?: string;
	modifiers?: number;
	modifierStrings?: string[];
	isStatic?: boolean;
	isConstructor?: boolean;
	sourceFile?: string;
	superClass?: string;
	interfaces?: string[];
	methodCount?: number;
	fieldCount?: number;
	usingStrings?: string[];
	fridaHook?: string;
	jadxFilter?: string;
	[key: string]: unknown;
}

export interface DexSearchFallbackInfo {
	primary: "dex_search";
	suggestedFallback: string;
	alternatives: string[];
}

export interface DexSearchDetails {
	action: DexSearchQueryType;
	target: string;
	status: "ok" | "error" | "missing_dependency";
	executed: boolean;
	targetHash?: string;
	targetSize?: number;
	dexNum?: number;
	total?: number;
	offset?: number;
	limit?: number;
	has_more?: boolean;
	items?: DexSearchResultItem[];
	readers?: DexSearchResultItem[];
	writers?: DexSearchResultItem[];
	targetField?: DexSearchResultItem;
	groups?: Record<string, DexSearchResultItem[]>;
	engine?: string;
	durationMs?: number;
	error?: string;
	fallback?: DexSearchFallbackInfo;
	setupCommand?: string;
	dependency?: ProtectionToolResolved;
}

export interface DexSearchRunOptions {
	cwd: string;
	timeoutMs: number;
	maxBytes: number;
	signal?: AbortSignal;
}

export interface DexSearchRunResult {
	stdout: string;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
}

export type DexSearchRunner = (
	binary: string,
	args: string[],
	options: DexSearchRunOptions,
) => Promise<DexSearchRunResult>;

export interface DexSearchToolOptions {
	runner?: DexSearchRunner;
	which?: SkillRequirementWhich;
	agentDir?: string;
}

// ============================================================================
// Default Subprocess Runner
// ============================================================================

async function readCapped(
	stream: ReadableStream<Uint8Array> | null,
	maxBytes: number,
	onCap?: () => void,
): Promise<{ text: string; bytes: number; truncated: boolean }> {
	if (!stream) return { text: "", bytes: 0, truncated: false };
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	let truncated = false;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			if (total + value.byteLength > maxBytes) {
				const take = Math.max(0, maxBytes - total);
				if (take > 0) {
					chunks.push(value.subarray(0, take));
					total += take;
				}
				truncated = true;
				onCap?.();
				try {
					await reader.cancel();
				} catch {
					// Ignore cancel failure
				}
				break;
			}
			chunks.push(value);
			total += value.byteLength;
		}
	} finally {
		reader.releaseLock();
	}
	const combined = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		combined.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return {
		text: new TextDecoder("utf-8", { fatal: false }).decode(combined),
		bytes: total,
		truncated,
	};
}

export async function defaultDexSearchRunner(
	binary: string,
	args: string[],
	options: DexSearchRunOptions,
): Promise<DexSearchRunResult> {
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});

	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill();
	}, options.timeoutMs);

	const onAbort = () => {
		child.kill();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });

	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			readCapped(child.stdout, options.maxBytes, () => {
				child.kill();
			}),
			readCapped(child.stderr, 64 * 1024),
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
		options.signal?.removeEventListener("abort", onAbort);
	}
}

// ============================================================================
// Helpers
// ============================================================================

async function computeFileSha256(filePath: string): Promise<string> {
	const fileBuffer = await Bun.file(filePath).arrayBuffer();
	const hash = crypto.createHash("sha256");
	hash.update(Buffer.from(fileBuffer));
	return hash.digest("hex");
}
export function toFridaParamType(type: string): string {
	let trimmed = type.trim();
	if (trimmed.length === 0) return "";

	// Count array dimensions
	let dimensions = 0;
	while (trimmed.endsWith("[]")) {
		dimensions++;
		trimmed = trimmed.slice(0, -2).trim();
	}
	while (trimmed.startsWith("[")) {
		dimensions++;
		trimmed = trimmed.slice(1).trim();
	}

	let baseType: string;
	switch (trimmed) {
		case "byte":
		case "B":
			baseType = dimensions > 0 ? "B" : "byte";
			break;
		case "short":
		case "S":
			baseType = dimensions > 0 ? "S" : "short";
			break;
		case "int":
		case "I":
			baseType = dimensions > 0 ? "I" : "int";
			break;
		case "long":
		case "J":
			baseType = dimensions > 0 ? "J" : "long";
			break;
		case "float":
		case "F":
			baseType = dimensions > 0 ? "F" : "float";
			break;
		case "double":
		case "D":
			baseType = dimensions > 0 ? "D" : "double";
			break;
		case "boolean":
		case "Z":
			baseType = dimensions > 0 ? "Z" : "boolean";
			break;
		case "char":
		case "C":
			baseType = dimensions > 0 ? "C" : "char";
			break;
		default: {
			let objName = trimmed;
			if (objName.startsWith("L") && objName.endsWith(";") && objName.length > 2) {
				objName = objName.slice(1, -1);
			}
			objName = objName.replace(/\//g, ".");
			if (dimensions > 0) {
				baseType = `L${objName};`;
			} else {
				baseType = objName;
			}
			break;
		}
	}

	if (dimensions > 0) {
		return "[".repeat(dimensions) + baseType;
	}
	return baseType;
}

export function normalizeDalvikClassName(name?: string): string | undefined {
	if (!name) return undefined;
	const s = name.trim();
	if (s.startsWith("L") && s.endsWith(";") && s.length > 2) {
		return s.substring(1, s.length - 1).replace(/\//g, ".");
	}
	if (s.startsWith("L") && s.includes("/")) {
		return s.substring(1).replace(/\//g, ".");
	}
	return s;
}

export function generateFridaHook(item: DexSearchResultItem, type: DexSearchQueryType): string {
	const rawClass =
		item.className ||
		(item.descriptor.startsWith("L") ? item.descriptor.replace(/^L|;.*$/g, "").replace(/\//g, ".") : "");
	const className = normalizeDalvikClassName(rawClass);
	if (!className) return "// No class name available for Frida hook";

	if (type === "class") {
		return [
			`// Frida hook for ${className}`,
			`Java.perform(function() {`,
			`    let targetClass = Java.use("${className}");`,
			`    console.log("[+] Hooked class: ${className}");`,
			`});`,
		].join("\n");
	}

	if (type === "field" || type === "field_uses") {
		const fieldName = item.name || "targetField";
		return [
			`// Frida field access for ${item.descriptor}`,
			`Java.perform(function() {`,
			`    let targetClass = Java.use("${className}");`,
			`    // Read field: targetClass.${fieldName}.value`,
			`    // Write field: targetClass.${fieldName}.value = ...;`,
			`});`,
		].join("\n");
	}

	const rawMethodName = item.name || "targetMethod";
	const isConstructor = item.isConstructor || rawMethodName === "<init>";
	const targetVar = isConstructor ? "targetCtor" : "targetMethod";
	const methodAccess = isConstructor ? "targetClass.$init" : `targetClass["${rawMethodName}"]`;
	const paramTypes = item.paramTypes ?? [];
	const paramList = paramTypes.map((_, i) => `arg${i}`).join(", ");
	const overloadArgs = paramTypes.map(p => `"${toFridaParamType(p)}"`).join(", ");

	const hookLines = [
		`// Frida hook for ${item.descriptor}`,
		`Java.perform(function() {`,
		`    let targetClass = Java.use("${className}");`,
		`    let ${targetVar} = ${methodAccess}.overload(${overloadArgs});`,
		`    ${targetVar}.implementation = function(${paramList}) {`,
		`        console.log("[+] Called ${className}.${isConstructor ? "$init" : rawMethodName}");`,
	];

	if (paramTypes.length > 0) {
		for (let i = 0; i < paramTypes.length; i++) {
			hookLines.push(`        console.log("    arg[${i}]: " + arg${i});`);
		}
	}
	hookLines.push(`        let ret = ${targetVar}.call(this${paramList.length > 0 ? ", " + paramList : ""});`);
	if (!isConstructor) {
		hookLines.push(`        console.log("    return: " + ret);`);
		hookLines.push(`        return ret;`);
	}
	hookLines.push(`    };`);
	hookLines.push(`});`);

	return hookLines.join("\n");
}

export function generateJadxFilter(item: DexSearchResultItem): string {
	if (item.descriptor) {
		return item.descriptor;
	}
	if (item.className && item.name) {
		return `${item.className}.${item.name}`;
	}
	return item.className || "";
}

export function resolveDexSearchFallback(
	type: DexSearchQueryType,
	targetPath: string,
	options: {
		query?: string;
		className?: string;
		usingStrings?: string[];
	} = {},
): DexSearchFallbackInfo {
	const quoted = `"${targetPath}"`;
	const term = options.query || options.className || (options.usingStrings && options.usingStrings[0]) || "target";

	switch (type) {
		case "class":
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "listclass", target: ${quoted}, prefix: "${options.className ?? ""}")`,
				alternatives: [
					`droidasc(op: "listclass", target: ${quoted})`,
					`dex_patch(action: "validate", path: ${quoted})`,
					`dexdump -f ${quoted}`,
				],
			};
		case "method":
		case "field":
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "findrefs", target: ${quoted}, kind: "${type}", query: "${term}")`,
				alternatives: [
					`droidasc(op: "findrefs", target: ${quoted}, kind: "${type}", query: "${term}")`,
					`dex_patch(action: "inspect", path: ${quoted}, method: "${term}")`,
					`jadx -d ./artifacts/jadx_out ${quoted}`,
				],
			};
		case "callers":
		case "callees":
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "findrefs", target: ${quoted}, kind: "method", query: "${term}")`,
				alternatives: [
					`droidasc(op: "findrefs", target: ${quoted}, kind: "method", query: "${term}")`,
					`jadx -d ./artifacts/jadx_out ${quoted}`,
				],
			};
		case "field_uses":
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "findrefs", target: ${quoted}, kind: "field", query: "${term}")`,
				alternatives: [`droidasc(op: "findrefs", target: ${quoted}, kind: "field", query: "${term}")`],
			};
		case "batch_strings":
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "findrefs", target: ${quoted}, kind: "string", query: "${term}")`,
				alternatives: [
					`droidasc(op: "findrefs", target: ${quoted}, kind: "string", query: "${term}")`,
					`strings ${quoted} | grep -i "${term}"`,
				],
			};
		default:
			return {
				primary: "dex_search",
				suggestedFallback: `droidasc(op: "listclass", target: ${quoted})`,
				alternatives: [
					`dex_patch(action: "validate", path: ${quoted})`,
					`droidasc(op: "manifest", target: ${quoted})`,
				],
			};
	}
}

// ============================================================================
// Tool Implementation
// ============================================================================

export class DexSearchTool implements AgentTool<typeof dexSearchSchema, DexSearchDetails> {
	readonly name = "dex_search";
	approval(_args?: unknown): ToolTier {
		return "exec";
	}
	readonly label = "DexKit Search";
	readonly summary = "High-performance structured Dalvik/ART code search engine powered by LuckyPray/DexKit";
	readonly description: string;
	readonly parameters = dexSearchSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: DexSearchToolOptions = {},
	) {
		this.description = prompt.render(dexSearchDescription);
	}

	async execute(
		_toolCallId: string,
		params: DexSearchParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<DexSearchDetails>> {
		throwIfAborted(signal);

		const startTime = Date.now();
		const requestedTarget = params.target.trim();
		if (requestedTarget.length === 0) {
			throw new ToolError("target is required (path to Android .apk, .dex, or .jar/.zip file)");
		}

		const absolutePath = resolveReadPath(requestedTarget, this.session.cwd);
		let targetStats: Stats;
		try {
			targetStats = await stat(absolutePath);
		} catch {
			throw new ToolError(`Target file not found: ${requestedTarget}`);
		}

		if (!targetStats.isFile()) {
			throw new ToolError(`Not a regular file: ${requestedTarget}`);
		}

		if (targetStats.size > DEX_SEARCH_MAX_TARGET_BYTES) {
			throw new ToolError(
				`Target file size (${targetStats.size} bytes) exceeds maximum limit of ${DEX_SEARCH_MAX_TARGET_BYTES} bytes (2 GiB)`,
			);
		}

		const normalizedType: DexSearchQueryType = (params.type || params.action || "class") as DexSearchQueryType;
		const className = normalizeDalvikClassName(params.class?.trim() || params.className?.trim());
		const memberName = params.name?.trim() || params.methodName?.trim() || params.fieldName?.trim();
		const returnType = params.returnType?.trim() || params.return_type?.trim();
		const paramTypes = params.paramTypes || params.param_types;
		const fieldType = params.fieldType?.trim() || params.field_type?.trim();
		const superClass = normalizeDalvikClassName(params.superClass?.trim() || params.super_class?.trim());
		const searchPackages = params.searchPackages || params.search_packages;
		const excludePackages = params.excludePackages || params.exclude_packages;
		const usingStrings = params.usingStrings || params.using_strings;
		const usingNumbers = params.usingNumbers || params.using_numbers;
		const stringMatchType = params.stringMatchType || params.string_match_type || "contains";
		const ignoreCase = params.ignoreCase ?? params.ignore_case ?? false;
		const targetMethod = params.method?.trim() || params.target_method?.trim();
		const targetField = params.field?.trim() || params.target_field?.trim();
		const groups = params.groups;
		const batchTarget = params.batchTarget || params.batch_target || "method";

		const limit = Math.min(DEX_SEARCH_MAX_LIMIT, Math.max(1, Math.floor(params.limit ?? DEX_SEARCH_DEFAULT_LIMIT)));
		const offset = Math.max(0, Math.floor(params.offset ?? 0));
		const timeoutSeconds = Math.min(
			DEX_SEARCH_MAX_TIMEOUT_SEC,
			Math.max(1, Math.floor(params.timeout ?? DEX_SEARCH_DEFAULT_TIMEOUT_SEC)),
		);

		// Resolve DexKit protection tool
		const resolvedDexkit = resolveProtectionTool("dexkit", {
			agentDir: this.options.agentDir,
			which: this.options.which,
		});

		if (!resolvedDexkit || !resolvedDexkit.installed || !resolvedDexkit.canStart) {
			const fallback = resolveDexSearchFallback(normalizedType, requestedTarget, {
				className,
				query: memberName,
				usingStrings,
			});
			const agentDirDisplay = resolvedDexkit?.binDir || "~/.reverse/tools/dexkit";
			const text = [
				`DexKit engine components are not installed in the managed directory (${agentDirDisplay}).`,
				"",
				"DexKit provides high-performance C++20 Dalvik/ART structured code search via LuckyPray/DexKit.",
				"To install DexKit runtime (JNI native library and bridge):",
				"  `reverse setup reverse dexkit --execute`",
				"",
				`Suggested active fallback for ${normalizedType}:`,
				`  ${fallback.suggestedFallback}`,
				"",
				"Alternatives:",
				...fallback.alternatives.map(a => `  - ${a}`),
			].join("\n");

			return {
				content: [{ type: "text", text }],
				details: {
					action: normalizedType,
					target: requestedTarget,
					status: "missing_dependency",
					executed: false,
					setupCommand: "reverse setup reverse dexkit --execute",
					fallback,
					dependency: resolvedDexkit ?? inspectProtectionTool("dexkit", { allowMissing: true }),
				},
			};
		}

		// Compute target hash
		const targetHash = await computeFileSha256(absolutePath);

		// Construct request payload
		const requestPayload = {
			action: normalizedType,
			target: absolutePath,
			nativeLibPath: resolvedDexkit.metadata.nativeLibPath,
			limit,
			offset,
			query: {
				className,
				class: className,
				name: memberName,
				methodName: memberName,
				fieldName: memberName,
				returnType,
				return_type: returnType,
				paramTypes,
				fieldType,
				superClass,
				searchPackages,
				excludePackages,
				usingStrings,
				usingNumbers,
				stringMatchType,
				ignoreCase,
				modifiers: params.modifiers,
				targetMethod,
				targetField,
				method: targetMethod,
				field: targetField,
				groups,
				batchTarget,
			},
		};

		// Determine runner invocation
		const runner = this.options.runner ?? defaultDexSearchRunner;

		// Write temporary input JSON
		const tmpJsonPath = path.join(os.tmpdir(), `dexkit-req-${crypto.randomBytes(8).toString("hex")}.json`);
		await fs.promises.writeFile(tmpJsonPath, JSON.stringify(requestPayload, null, 2), "utf8");

		let execBinary: string;
		let execArgs: string[];

		if (resolvedDexkit.metadata.bridgeScript && fs.existsSync(resolvedDexkit.metadata.bridgeScript)) {
			execBinary = resolvedDexkit.metadata.bridgeScript;
			execArgs = ["--input-file", tmpJsonPath];
		} else {
			const whichLookup = this.options.which ?? $which;
			const javaPath =
				whichLookup("java") || (process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, "bin", "java") : "java");
			const libDir = resolvedDexkit.binDir;
			execBinary = javaPath;
			execArgs = [
				`-Djava.library.path=${libDir}`,
				"-cp",
				`${path.join(libDir, "*")}`,
				"org.reverse.dexsearch.DexSearchBridge",
				"--input-file",
				tmpJsonPath,
			];
		}

		throwIfAborted(signal);

		let runResult: DexSearchRunResult;
		try {
			runResult = await runner(execBinary, execArgs, {
				cwd: this.session.cwd,
				timeoutMs: timeoutSeconds * 1000,
				maxBytes: DEX_SEARCH_MAX_OUTPUT_BYTES,
				signal,
			});
		} catch (error) {
			try {
				await fs.promises.unlink(tmpJsonPath);
			} catch {
				// Ignore
			}
			throw new ToolError(
				`Failed to execute DexKit runner: ${error instanceof Error ? error.message : String(error)}`,
			);
		} finally {
			try {
				await fs.promises.unlink(tmpJsonPath);
			} catch {
				// Ignore
			}
		}

		throwIfAborted(signal);

		if (runResult.timedOut) {
			const fallback = resolveDexSearchFallback(normalizedType, requestedTarget, {
				className,
				query: memberName,
				usingStrings,
			});
			return {
				content: [
					{
						type: "text",
						text: `dex_search timed out after ${timeoutSeconds}s for ${requestedTarget}. Try narrowing query parameters (e.g. searchPackages) or increasing timeout.`,
					},
				],
				details: {
					action: normalizedType,
					target: requestedTarget,
					status: "error",
					executed: false,
					error: `Timed out after ${timeoutSeconds}s`,
					fallback,
				},
			};
		}

		// Extract JSON output from sentinel tokens (matching standalone delimiter lines)
		const stdout = runResult.stdout;
		const startMatch = stdout.match(/(?:^|\n)<<<DEX_SEARCH_OUTPUT_START>>>\r?\n/);
		const lastEndIdx = stdout.lastIndexOf("<<<DEX_SEARCH_OUTPUT_END>>>");

		let parsedResponse: Record<string, unknown> | null = null;
		if (startMatch && startMatch.index !== undefined && lastEndIdx !== -1) {
			const startIdx = startMatch.index + startMatch[0].length;
			if (lastEndIdx > startIdx) {
				const jsonText = stdout.slice(startIdx, lastEndIdx).trim();
				try {
					const parsed = JSON.parse(jsonText);
					if (parsed && typeof parsed === "object") {
						parsedResponse = parsed as Record<string, unknown>;
					}
				} catch {
					// Fall through
				}
			}
		}

		if (!parsedResponse) {
			// Try parsing bare stdout if markers not found
			try {
				const parsed = JSON.parse(stdout.trim());
				if (parsed && typeof parsed === "object") {
					parsedResponse = parsed as Record<string, unknown>;
				}
			} catch {
				const errMsg = runResult.stderr.trim() || stdout.trim() || `Exit code ${runResult.exitCode}`;
				throw new ToolError(`DexKit bridge returned non-JSON output: ${errMsg}`);
			}
		}

		if (!parsedResponse) {
			const errMsg = runResult.stderr.trim() || stdout.trim() || `Exit code ${runResult.exitCode}`;
			throw new ToolError(`DexKit bridge returned non-JSON output: ${errMsg}`);
		}

		if (parsedResponse.success === false || parsedResponse.error) {
			const errMsg = String(parsedResponse.error || "Unknown DexKit bridge error");
			return {
				content: [{ type: "text", text: `DexKit search error: ${errMsg}` }],
				details: {
					action: normalizedType,
					target: requestedTarget,
					status: "error",
					executed: false,
					error: errMsg,
				},
			};
		}

		const durationMs = Date.now() - startTime;
		const total = Number(parsedResponse.total ?? 0);
		const rawItems = (parsedResponse.items as DexSearchResultItem[]) || [];
		const rawReaders = (parsedResponse.readers as DexSearchResultItem[]) || [];
		const rawWriters = (parsedResponse.writers as DexSearchResultItem[]) || [];
		const rawTargetField = parsedResponse.targetField as DexSearchResultItem | undefined;
		const rawGroups = (parsedResponse.groups as Record<string, DexSearchResultItem[]>) || undefined;

		const items = rawItems.map(item => ({
			...item,
			fridaHook: generateFridaHook(item, normalizedType),
			jadxFilter: generateJadxFilter(item),
		}));

		const readers = rawReaders.map(item => ({
			...item,
			fridaHook: generateFridaHook(item, "method"),
			jadxFilter: generateJadxFilter(item),
		}));

		const writers = rawWriters.map(item => ({
			...item,
			fridaHook: generateFridaHook(item, "method"),
			jadxFilter: generateJadxFilter(item),
		}));

		const targetFieldItem = rawTargetField
			? {
					...rawTargetField,
					fridaHook: generateFridaHook(rawTargetField, "field"),
					jadxFilter: generateJadxFilter(rawTargetField),
				}
			: undefined;

		const decoratedGroups: Record<string, DexSearchResultItem[]> | undefined = rawGroups
			? Object.fromEntries(
					Object.entries(rawGroups).map(([k, v]) => [
						k,
						(v || []).map(item => ({
							...item,
							fridaHook: generateFridaHook(item, batchTarget),
							jadxFilter: generateJadxFilter(item),
						})),
					]),
				)
			: undefined;

		const details: DexSearchDetails = {
			action: normalizedType,
			target: requestedTarget,
			status: "ok",
			executed: true,
			targetHash,
			targetSize: targetStats.size,
			dexNum: parsedResponse.dexNum as number | undefined,
			total,
			offset,
			limit,
			has_more: Boolean(parsedResponse.has_more ?? offset + limit < total),
			items,
			readers: readers.length > 0 ? readers : undefined,
			writers: writers.length > 0 ? writers : undefined,
			targetField: targetFieldItem,
			groups: decoratedGroups,
			engine: (parsedResponse.engine as string) || "DexKit 2.3.0",
			durationMs,
			dependency: resolvedDexkit,
		};

		// Format output markdown
		const lines: string[] = [];
		lines.push(`### DexKit Code Search Results`);
		lines.push(
			`**Target**: \`${requestedTarget}\` (SHA-256: \`${targetHash.slice(0, 16)}...\` | ${Math.round(targetStats.size / 1024)} KB)`,
		);
		lines.push(`**Query Type**: \`${normalizedType}\` | **Engine**: ${details.engine} (${durationMs}ms)`);

		if (details.dexNum !== undefined) {
			lines.push(`**DEX Entries**: ${details.dexNum}`);
		}

		if (normalizedType === "info") {
			lines.push(`\nDexKit engine is ready. Parsed ${details.dexNum ?? 1} DEX file(s).`);
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details,
			};
		}

		if (normalizedType === "field_uses") {
			const totalReaders = Number(parsedResponse.totalReaders ?? readers.length);
			const totalWriters = Number(parsedResponse.totalWriters ?? writers.length);
			lines.push(`\n**Target Field**: \`${targetField ?? "unknown"}\` (Total References: ${total})`);
			lines.push(`**Readers** (showing ${readers.length} of ${totalReaders}):`);
			if (totalReaders === 0) {
				lines.push("  *(No reading methods found in target)*");
			} else if (readers.length === 0) {
				lines.push("  *(No reading methods in current page)*");
			} else {
				for (const r of readers) {
					lines.push(`  - \`${r.descriptor}\``);
				}
			}
			lines.push(`\n**Writers** (showing ${writers.length} of ${totalWriters}):`);
			if (totalWriters === 0) {
				lines.push("  *(No writing methods found in target)*");
			} else if (writers.length === 0) {
				lines.push("  *(No writing methods in current page)*");
			} else {
				for (const w of writers) {
					lines.push(`  - \`${w.descriptor}\``);
				}
			}
		} else if (normalizedType === "batch_strings" && decoratedGroups) {
			lines.push(
				`\n**Batch String Results** (${Object.keys(decoratedGroups).length} groups, ${total} total matches):`,
			);
			for (const [groupName, groupItems] of Object.entries(decoratedGroups)) {
				lines.push(`\n#### Group: \`${groupName}\` (${groupItems.length} returned in current page)`);
				if (groupItems.length === 0) {
					lines.push("  *(No matches)*");
				} else {
					for (const item of groupItems) {
						lines.push(`  - \`${item.descriptor}\``);
					}
				}
			}
		} else {
			lines.push(`\n**Matches Found**: ${total} (showing ${items.length} from offset ${offset})`);

			if (items.length === 0) {
				lines.push("\n*(No matches found matching the specified query criteria)*");
			} else {
				lines.push("\n| Descriptor | Modifiers | Java Signature |");
				lines.push("| --- | --- | --- |");
				for (const item of items) {
					const mods = item.modifierStrings ? item.modifierStrings.join(" ") : "";
					const sig =
						item.returnType && item.className && item.name
							? `${item.returnType} ${item.className}.${item.name}(${(item.paramTypes || []).join(", ")})`
							: item.className || item.descriptor;
					lines.push(`| \`${item.descriptor}\` | \`${mods}\` | \`${sig}\` |`);
				}

				// Add Frida hook sample for the first match
				if (items[0] && items[0].fridaHook) {
					lines.push(`\n#### Frida Hook Template (Top Match)`);
					lines.push("```javascript");
					lines.push(items[0].fridaHook);
					lines.push("```");
				}
			}
		}

		if (details.has_more) {
			lines.push(
				`\n> Bounded pagination: more results available. Use \`offset: ${offset + limit}\` to fetch the next page.`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details,
		};
	}
}
