/**
 * Kaitai Struct 可执行协议/二进制格式定义与验证工具（Step 4）：
 * - status：检测 kaitai-struct-compiler（JVM + --read-pos）、Python kaitaistruct 运行时及版本兼容性；
 * - compile：校验显式本地 import_roots 与 KSY 闭包（绑定 begin 输入哈希，拒绝网络/越界/软链/custom process/opaque 类型），
 *   以固定参数与隔离 KSPATH 生成 Python 解析器及哈希绑定的 FormatInspectManifestV1；
 * - parse：校验 manifest、KSY 闭包、生成源码哈希与运行时版本兼容性，通过 runReversePython 在私有临时目录执行解析，
 *   返回字段路径、类型、64位整数十进制字符串、stream_id、0基 [start, end) 偏移、仅确定映射时的原文件偏移、错误偏移与尾部残留字节；
 * - validate：对显式 sample_paths[] 执行正/负样本预期与显式字段断言校验，仅声明语料与断言满足率（static_candidate），不伪造覆盖率。
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { isRecord, prompt } from "@reverse/utils";
import { filterEnv } from "../eval/py/runtime";
import { redactEvidenceText, type EvidenceAssuranceLevel } from "../evidence/contracts";
import {
	checkKaitaiVersionCompatibility,
	resolveKaitaiToolchainReadiness,
	type KaitaiCompilerProbeResult,
	type KaitaiStructDetailedProbeResult,
} from "../extensibility/protocol-toolchain";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import formatInspectDescription from "../prompts/tools/format-inspect.md" with { type: "text" };
import {
	assertRealPathWithin,
	deterministicJsonStringify,
	hashBuffer,
	loadAnalysisExecution,
	redactSecrets,
	resolveAnalysisOutputPath,
	type LoadAnalysisExecutionResult,
	type SafeResolvedPath,
} from "../reverse-workspace";
import formatInspectWorkerPy from "./format-inspect-worker.py" with { type: "text" };
import type { ToolSession } from "./index";
import { readRegularFileBoundedNoFollow, writePrivateRunArtifactFile } from "./network-import";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";

// ============================================================================
// 固定边界与语法安全常量
// ============================================================================

const MAX_KSY_FILE_BYTES = 1 * 1024 * 1024; // 1 MiB
const MAX_MANIFEST_FILE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_GENERATED_PY_BYTES = 4 * 1024 * 1024; // 4 MiB
const MAX_KSY_CLOSURE_FILES = 64;

const DEFAULT_MAX_INPUT_BYTES = 4 * 1024 * 1024; // 4 MiB
const HARD_MAX_INPUT_BYTES = 16 * 1024 * 1024; // 16 MiB
const DEFAULT_MAX_DEPTH = 16;
const HARD_MAX_DEPTH = 64;
const DEFAULT_MAX_FIELDS = 2000;
const HARD_MAX_FIELDS = 20000;
const DEFAULT_MAX_OUTPUT_BYTES = 1 * 1024 * 1024; // 1 MiB（严格低于 runReversePython 16 MiB 上限）
const HARD_MAX_OUTPUT_BYTES = 8 * 1024 * 1024; // 8 MiB
const DEFAULT_TIMEOUT_MS = 30_000;
const HARD_MAX_TIMEOUT_MS = 120_000;
const DEFAULT_BYTE_PREVIEW_LEN = 64;

const KAITAI_IDENT_PATTERN = /^[a-z][a-z0-9_]{0,127}$/;
const PASCAL_CLASS_PATTERN = /^[A-Z][A-Za-z0-9]{0,127}$/;
const URL_SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const BUILTIN_PROCESS_PATTERN = /^(?:zlib|xor\s*\([^()\r\n]+\)|ro[lr]\s*\([^()\r\n]+\))$/;
const BIT_INT_TYPE_PATTERN = /^b[1-9]\d*(?:le|be)?$/;
const GENERATED_BANNER_PREFIX =
	"# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild";

const FORBIDDEN_MODULE_IDENTS: Readonly<Record<string, true>> = {
	kaitaistruct: true,
	sys: true,
	os: true,
	io: true,
	json: true,
	struct: true,
	enum: true,
	collections: true,
	zlib: true,
	builtins: true,
	importlib: true,
	subprocess: true,
	socket: true,
	ctypes: true,
	math: true,
	stat: true,
	resource: true,
	packaging: true,
	itertools: true,
	__worker__: true,
	__init__: true,
	__main__: true,
	and: true,
	as: true,
	assert: true,
	async: true,
	await: true,
	break: true,
	class: true,
	continue: true,
	def: true,
	del: true,
	elif: true,
	else: true,
	except: true,
	finally: true,
	for: true,
	from: true,
	global: true,
	if: true,
	import: true,
	in: true,
	is: true,
	lambda: true,
	nonlocal: true,
	not: true,
	or: true,
	pass: true,
	raise: true,
	return: true,
	try: true,
	while: true,
	with: true,
	yield: true,
	true: true,
	false: true,
	none: true,
};

const ALLOWED_META_KEYS: Readonly<Record<string, true>> = {
	id: true,
	title: true,
	application: true,
	"file-extension": true,
	xref: true,
	license: true,
	"ks-version": true,
	"ks-debug": true,
	"ks-opaque-types": true,
	imports: true,
	encoding: true,
	endian: true,
	"bit-endian": true,
	tags: true,
};

const BUILTIN_KSY_TYPES: Readonly<Record<string, true>> = {
	u1: true,
	u2: true,
	u2le: true,
	u2be: true,
	u4: true,
	u4le: true,
	u4be: true,
	u8: true,
	u8le: true,
	u8be: true,
	s1: true,
	s2: true,
	s2le: true,
	s2be: true,
	s4: true,
	s4le: true,
	s4be: true,
	s8: true,
	s8le: true,
	s8be: true,
	f4: true,
	f4le: true,
	f4be: true,
	f8: true,
	f8le: true,
	f8be: true,
	str: true,
	strz: true,
	bytes: true,
};

const BASE_ALLOWED_PY_IMPORTS: Readonly<Record<string, true>> = {
	kaitaistruct: true,
	enum: true,
	collections: true,
	zlib: true,
	struct: true,
	packaging: true,
	sys: true,
	io: true,
	itertools: true,
};

// ============================================================================
// 参数 Schema（TypeBox / reversetype）
// ============================================================================

export const formatFieldAssertionSchema = type({
	"sample_path?": type("string").describe("Target sample path when used in top-level field_assertions"),
	path: type("string").describe("Flattened field path from root (e.g. 'magic', 'items[0].id', 'body.inner_val')"),
	"exists?": type("boolean").describe("Expected field presence (default true; false asserts inactive branch)"),
	"type?": type("string").describe(
		"Expected field type (e.g. 'bytes', 'int', 'uint64', 'int64', 'str', 'enum', 'struct', 'array')",
	),
	"equals?": type("unknown").describe("Expected field value (decimal string for 64-bit ints, hex string for bytes)"),
	"stream_id?": type("string").describe("Expected stream_id ('root' or 'substream:<path>')"),
	"start?": type("number").describe("Expected 0-based inclusive start offset within stream_id"),
	"end?": type("number").describe("Expected 0-based exclusive end offset within stream_id"),
	"file_start?": type("number | null").describe(
		"Expected 0-based start offset in raw file, or null for processed substreams",
	),
	"file_end?": type("number | null").describe(
		"Expected 0-based exclusive end offset in raw file, or null for processed substreams",
	),
});

export const formatSampleExpectationSchema = type({
	sample_path: type("string").describe("Sample path matching an entry in sample_paths"),
	"expect_success?": type("boolean").describe(
		"Whether parsing is expected to succeed (true) or fail as a negative sample (false). Default: true",
	),
	"max_trailing_bytes?": type("number").describe(
		"Optional maximum unconsumed trailing bytes allowed when expect_success is true",
	),
	"expected_error_offset?": type("number").describe(
		"Optional expected 0-based error_offset when expect_success is false",
	),
	"expected_error_contains?": type("string").describe(
		"Optional substring expected in parse error message when expect_success is false",
	),
	"assertions?": formatFieldAssertionSchema.array().describe("Explicit field assertions for this sample"),
});

export const formatInspectSchema = type({
	action: type
		.enumerated("status", "compile", "parse", "validate")
		.describe("Kaitai format inspection action: status, compile, parse, or validate"),
	"workspace_path?": type("string").describe("Optional workspace directory path (defaults to '.reverse')"),
	"workflow_id?": type("string").describe("Active reverse workflow ID (required for compile, parse, validate)"),
	"step_id?": type("string").describe("Active workflow step ID (required for compile, parse, validate)"),
	"run_id?": type("string").describe("Active analysis run ID from reverse_workspace(action: 'begin')"),
	"schema_path?": type("string").describe("Root Kaitai Struct (.ksy) specification path (required for compile)"),
	"import_roots?": type("string[]").describe(
		"Explicit local project directories for resolving meta.imports during compile",
	),
	"manifest_path?": type("string").describe(
		"Compiled FormatInspectManifestV1 JSON path (required for parse and validate)",
	),
	"sample_path?": type("string").describe("Binary sample path to parse (required for parse)"),
	"sample_paths?": type("string[]").describe("Explicit binary sample paths to validate (required for validate)"),
	"sample_expectations?": formatSampleExpectationSchema
		.array()
		.describe("Per-sample expected parse success/failure and explicit field assertions for validate"),
	"field_assertions?": formatFieldAssertionSchema
		.array()
		.describe("Optional top-level explicit field assertions for validate"),
	"output_path?": type("string").describe(
		"Optional unique destination path inside the active run's managed subdirectories",
	),
	"max_input_bytes?": type("number").describe(
		"Maximum allowed input sample size in bytes (default 4 MiB, max 16 MiB)",
	),
	"max_depth?": type("number").describe("Maximum struct/array expansion depth (default 16, max 64)"),
	"max_fields?": type("number").describe("Maximum flattened field records per sample (default 2000, max 20000)"),
	"max_output_bytes?": type("number").describe("Maximum worker JSON output bytes (default 1 MiB, max 8 MiB)"),
	"timeout?": type("number").describe("Execution timeout in seconds (1 to 120, default 30)"),
	"timeout_ms?": type("number").describe(
		"Execution timeout in milliseconds (10 to 120000; overrides timeout when set)",
	),
});

export type FormatInspectParams = typeof formatInspectSchema.infer;
export type FormatFieldAssertion = typeof formatFieldAssertionSchema.infer;
export type FormatSampleExpectation = typeof formatSampleExpectationSchema.infer;

// ============================================================================
// 持久化 Manifest、解析报告与证据候选契约（单一规范 Schema）
// ============================================================================

export interface FormatInspectSchemaClosureEntry {
	path: string;
	sha256: string;
	size_bytes: number;
	meta_id: string;
	is_root: boolean;
	imports: string[];
}

export interface FormatInspectGeneratedSourceEntry {
	module_name: string;
	class_name: string;
	path: string;
	sha256: string;
	size_bytes: number;
	is_entry: boolean;
}

export interface FormatInspectManifestV1 {
	schema_version: "1";
	manifest_id: string;
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	root_schema_path: string;
	root_schema_sha256: string;
	import_roots: string[];
	schema_closure: FormatInspectSchemaClosureEntry[];
	compiler: {
		path: string;
		version: string;
		argv: string[];
		read_pos_enabled: true;
		opaque_types_allowed: false;
	};
	runtime: {
		python_path: string;
		version: string;
		api_version: string;
	};
	entry_module: string;
	entry_class: string;
	generated_sources: FormatInspectGeneratedSourceEntry[];
	field_type_hints: Record<string, string>;
	processed_field_hints: Record<string, boolean>;
}

export interface FormatInspectCompileFailureReportV1 {
	schema_version: "1";
	report_kind: "compile_failure";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	schema_path: string;
	schema_sha256: string;
	import_roots: string[];
	compiler_version: string;
	argv: string[];
	exit_code: number | null;
	timed_out: boolean;
	stdout: string;
	stderr: string;
	error: string;
}

export interface FormatInspectFieldRecord {
	path: string;
	type: string;
	ksy_type?: string;
	value: unknown;
	stream_id: string;
	start: number | null;
	end: number | null;
	file_start: number | null;
	file_end: number | null;
	file_offset: { start: number; end: number } | null;
	processed: boolean;
	byte_length?: number;
	bytes_sha256?: string;
	preview_truncated?: boolean;
	enum_value?: number | string;
	lazy_instances_skipped?: string[];
}

export interface FormatInspectTrailingInfo {
	count: number;
	start: number;
	end: number;
	preview_hex: string;
	truncated_preview: boolean;
}

export interface FormatInspectResourceLimitsReport {
	isolation_model: "subprocess_staging_not_security_sandbox";
	max_input_bytes: number;
	max_depth: number;
	max_fields: number;
	max_output_bytes: number;
	timeout_ms: number;
	rlimit_cpu: { enforced: boolean; seconds?: number; reason?: string };
	rlimit_as: { enforced: boolean; bytes?: number; reason?: string };
}

export interface FormatInspectSampleParseResult {
	sample_path: string;
	sample_sha256: string;
	sample_size: number;
	ok: boolean;
	consumed_bytes: number;
	trailing_bytes: number;
	trailing: FormatInspectTrailingInfo;
	fields: FormatInspectFieldRecord[];
	total_fields: number;
	root_lazy_instances_skipped: string[];
	truncated: boolean;
	output_truncated: boolean;
	truncation_reason: string | null;
	error_kind: string | null;
	error: string | null;
	error_offset: number | null;
	error_stream_pos: number | null;
	error_field_start: number | null;
	error_field_path: string | null;
	error_stream_id: string | null;
	error_file_offset: number | null;
	error_src_path: string | null;
}

export interface FormatInspectParseReportV1 {
	schema_version: "1";
	report_kind: "parse";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	manifest_path: string;
	manifest_sha256: string;
	root_schema_path: string;
	root_schema_sha256: string;
	entry_module: string;
	entry_class: string;
	compiler_version: string;
	runtime_version: string;
	runtime_api_version: string;
	resource_limits: FormatInspectResourceLimitsReport;
	result: FormatInspectSampleParseResult;
}

export interface FormatInspectFieldAssertionOutcome {
	sample_path: string;
	path: string;
	passed: boolean;
	reason?: string;
	expected: {
		exists?: boolean;
		type?: string;
		equals?: unknown;
		stream_id?: string;
		start?: number;
		end?: number;
		file_start?: number | null;
		file_end?: number | null;
	};
	actual?: {
		exists: boolean;
		type?: string;
		ksy_type?: string;
		value?: unknown;
		stream_id?: string;
		start?: number | null;
		end?: number | null;
		file_start?: number | null;
		file_end?: number | null;
	};
}

export interface FormatInspectSampleValidationOutcome {
	sample_path: string;
	sample_sha256: string;
	expect_success: boolean;
	actual_success: boolean;
	expectation_matched: boolean;
	expectation_failure_reason?: string;
	parse_result: FormatInspectSampleParseResult;
	assertion_results: FormatInspectFieldAssertionOutcome[];
	passed_assertions: number;
	failed_assertions: number;
}

export interface FormatInspectValidateReportV1 {
	schema_version: "1";
	report_kind: "validate";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	manifest_path: string;
	manifest_sha256: string;
	root_schema_path: string;
	root_schema_sha256: string;
	compiler_version: string;
	runtime_version: string;
	runtime_api_version: string;
	resource_limits: FormatInspectResourceLimitsReport;
	total_samples: number;
	samples_matching_expectation: number;
	sample_expectation_rate: number;
	total_assertions: number;
	passed_assertions: number;
	failed_assertions: number;
	assertion_satisfaction_rate: number | null;
	all_passed: boolean;
	coverage_claim: "corpus_and_explicit_assertions_only";
	assurance_level: EvidenceAssuranceLevel;
	sample_outcomes: FormatInspectSampleValidationOutcome[];
	next_experiment_suggestions: string[];
}

export interface FormatInspectEvidenceCandidate {
	kind: "fact" | "hypothesis";
	assurance_level: EvidenceAssuranceLevel;
	statement: string;
	artifact_path: string;
	artifact_sha256: string;
}

export interface FormatInspectDetails {
	action: "status" | "compile" | "parse" | "validate";
	status: "ok" | "missing_dependency" | "error";
	ready?: boolean;
	compatible?: boolean;
	compiler?: KaitaiCompilerProbeResult;
	runtime?: KaitaiStructDetailedProbeResult;
	missingTools?: string[];
	setupCommands?: string[];
	workflowId?: string;
	stepId?: string;
	runId?: string;
	runDir?: string;
	manifest?: FormatInspectManifestV1;
	manifestPath?: string;
	manifestRelativePath?: string;
	manifestSha256?: string;
	generatedSources?: FormatInspectGeneratedSourceEntry[];
	reportPath?: string;
	reportRelativePath?: string;
	reportSha256?: string;
	outputPaths?: string[];
	relativeOutputPaths?: string[];
	parseResult?: FormatInspectSampleParseResult;
	parseReport?: FormatInspectParseReportV1;
	validateReport?: FormatInspectValidateReportV1;
	compileFailureReport?: FormatInspectCompileFailureReportV1;
	resourceLimits?: FormatInspectResourceLimitsReport;
	argv?: string[];
	exitCode?: number | null;
	engineVersion?: string;
	assuranceLevel?: EvidenceAssuranceLevel;
	evidenceCandidates?: FormatInspectEvidenceCandidate[];
	nextExperimentSuggestions?: string[];
	error?: string;
}

export interface FormatInspectToolOptions {
	env?: Record<string, string | undefined>;
	which?: SkillRequirementWhich;
	agentDir?: string;
	compilerPath?: string;
	pythonPath?: string;
}

// ============================================================================
// 基础辅助函数：标识符、路径防逃逸与子进程生命周期管理
// ============================================================================

function requireNonEmptyParam(name: string, raw: string | undefined, action: string): string {
	if (typeof raw !== "string" || raw.trim().length === 0) {
		throw new ToolError(`Parameter '${name}' is required for format_inspect(action: "${action}").`);
	}
	const trimmed = raw.trim();
	if (trimmed.includes("\0")) {
		throw new ToolError(`Parameter '${name}' contains prohibited NUL byte.`);
	}
	return trimmed;
}

function rejectNetworkOrUriPath(label: string, rawPath: string): void {
	const trimmed = rawPath.trim();
	if (URL_SCHEME_PATTERN.test(trimmed) || /^(?:http|https|ftp|file|ssh|git|jar|data):/i.test(trimmed)) {
		throw new ToolError(
			`Network or URI path is prohibited for ${label}: '${rawPath}'. Only local project paths are permitted.`,
		);
	}
}

function toPascalCase(snakeId: string): string {
	return snakeId
		.split("_")
		.filter(Boolean)
		.map(part => part.charAt(0).toUpperCase() + part.slice(1))
		.join("");
}

function validateKaitaiIdentifier(
	kind: string,
	raw: unknown,
	ksyRelPath: string,
	forbidReservedModule = false,
): string {
	if (typeof raw !== "string" || !KAITAI_IDENT_PATTERN.test(raw)) {
		throw new ToolError(
			`Invalid Kaitai ${kind} identifier '${String(raw)}' in '${ksyRelPath}': must match /^[a-z][a-z0-9_]{0,127}$/.`,
		);
	}
	if (forbidReservedModule && FORBIDDEN_MODULE_IDENTS[raw]) {
		throw new ToolError(`Reserved or prohibited ${kind} identifier '${raw}' in '${ksyRelPath}'.`);
	}
	return raw;
}

async function assertNoSymlinkSegmentsWithinRoot(
	rootResolvedPath: string,
	targetResolvedPath: string,
	label: string,
): Promise<void> {
	const rel = path.relative(rootResolvedPath, targetResolvedPath);
	if (rel.startsWith("..") || path.isAbsolute(rel)) {
		throw new ToolError(
			`Path escape violation for ${label}: '${targetResolvedPath}' is outside '${rootResolvedPath}'.`,
		);
	}
	const rootStat = await fs.lstat(rootResolvedPath);
	if (rootStat.isSymbolicLink()) {
		throw new ToolError(`Symlink escape violation: root '${rootResolvedPath}' is a symbolic link.`);
	}
	const segments = rel.split(path.sep).filter(Boolean);
	let cur = rootResolvedPath;
	for (const seg of segments) {
		cur = path.join(cur, seg);
		const st = await fs.lstat(cur);
		if (st.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation for ${label}: '${cur}' is a symbolic link.`);
		}
	}
}

async function resolveValidatedImportRoots(
	resolvedProjectDir: string,
	rawRoots: string[] | undefined,
): Promise<Array<SafeResolvedPath & { relativeNormalized: string }>> {
	if (!rawRoots || rawRoots.length === 0) {
		return [];
	}
	const results: Array<SafeResolvedPath & { relativeNormalized: string }> = [];
	const seen = new Set<string>();
	for (const raw of rawRoots) {
		if (typeof raw !== "string" || raw.trim().length === 0) {
			throw new ToolError("Each entry in 'import_roots' must be a non-empty local project directory path.");
		}
		if (raw.includes("\0")) {
			throw new ToolError("Entry in 'import_roots' contains prohibited NUL byte.");
		}
		rejectNetworkOrUriPath("import_roots", raw);

		let safeRoot: SafeResolvedPath;
		try {
			safeRoot = await assertRealPathWithin(resolvedProjectDir, raw.trim(), {
				baseDir: resolvedProjectDir,
			});
		} catch (err) {
			throw new ToolError(
				`Invalid import_roots entry '${raw}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		let st: Stats;
		try {
			st = await fs.lstat(safeRoot.resolvedPath);
		} catch (err) {
			throw new ToolError(
				`import_roots directory '${raw}' does not exist: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
		if (st.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation: import_roots entry '${raw}' is a symbolic link.`);
		}
		if (!st.isDirectory()) {
			throw new ToolError(`import_roots entry '${raw}' is not a directory.`);
		}
		await assertNoSymlinkSegmentsWithinRoot(resolvedProjectDir, safeRoot.resolvedPath, `import_roots '${raw}'`);

		if (!seen.has(safeRoot.realPath)) {
			seen.add(safeRoot.realPath);
			results.push({
				...safeRoot,
				relativeNormalized: safeRoot.relativePath || ".",
			});
		}
	}
	return results;
}

// ============================================================================
// KSY YAML 解析、安全规则校验与闭包提取（使用 Bun.YAML.parse，零第三方依赖）
// ============================================================================

interface ValidatedKsyNode {
	resolvedPath: string;
	realPath: string;
	relativePath: string;
	rawBytes: Buffer;
	sha256: string;
	sizeBytes: number;
	metaId: string;
	rawImports: string[];
	localTypeNames: Set<string>;
	referencedTypes: string[];
	fieldTypeHints: Record<string, string>;
	processedFieldHints: Record<string, boolean>;
}

function extractReferencedTypeStrings(
	rawTypeField: unknown,
	ksyRelPath: string,
): {
	primaryType?: string;
	refs: string[];
} {
	if (rawTypeField === undefined || rawTypeField === null) {
		return { refs: [] };
	}
	if (typeof rawTypeField === "string") {
		const trimmed = rawTypeField.trim();
		if (!trimmed) {
			throw new ToolError(`Empty 'type' string in '${ksyRelPath}'.`);
		}
		const withoutParams = trimmed.replace(/\([\s\S]*\)$/, "").trim();
		return { primaryType: withoutParams, refs: [withoutParams] };
	}
	if (isRecord(rawTypeField)) {
		const cases = rawTypeField.cases;
		if (!isRecord(cases)) {
			throw new ToolError(`Invalid switch-on 'type' definition in '${ksyRelPath}': missing 'cases' mapping.`);
		}
		const refs: string[] = [];
		for (const caseTarget of Object.values(cases)) {
			if (typeof caseTarget !== "string" || caseTarget.trim().length === 0) {
				throw new ToolError(`Invalid switch-on case target '${String(caseTarget)}' in '${ksyRelPath}'.`);
			}
			const withoutParams = caseTarget
				.trim()
				.replace(/\([\s\S]*\)$/, "")
				.trim();
			refs.push(withoutParams);
		}
		return { refs };
	}
	throw new ToolError(`Invalid 'type' specification in '${ksyRelPath}'.`);
}

function validateKsyTypeBlock(
	block: Record<string, unknown>,
	ksyRelPath: string,
	classQualPrefix: string,
	localTypeNames: Set<string>,
	referencedTypes: string[],
	fieldTypeHints: Record<string, string>,
	processedFieldHints: Record<string, boolean>,
): void {
	if (block.params !== undefined) {
		if (!Array.isArray(block.params)) {
			throw new ToolError(`'params' in '${ksyRelPath}' must be a YAML sequence.`);
		}
		for (const param of block.params) {
			if (!isRecord(param)) {
				throw new ToolError(`Each entry in 'params' in '${ksyRelPath}' must be a mapping.`);
			}
			validateKaitaiIdentifier("param.id", param.id, ksyRelPath);
			if (param.type !== undefined) {
				const { refs } = extractReferencedTypeStrings(param.type, ksyRelPath);
				referencedTypes.push(...refs);
			}
		}
	}

	if (block.enums !== undefined) {
		if (!isRecord(block.enums)) {
			throw new ToolError(`'enums' in '${ksyRelPath}' must be a mapping.`);
		}
		for (const [enumName, enumMap] of Object.entries(block.enums)) {
			validateKaitaiIdentifier("enum", enumName, ksyRelPath);
			if (!isRecord(enumMap)) {
				throw new ToolError(`Enum '${enumName}' in '${ksyRelPath}' must map integer keys to identifiers.`);
			}
			for (const enumVal of Object.values(enumMap)) {
				if (typeof enumVal === "string") {
					validateKaitaiIdentifier(`enum '${enumName}' member`, enumVal, ksyRelPath);
				} else if (isRecord(enumVal)) {
					validateKaitaiIdentifier(`enum '${enumName}' member.id`, enumVal.id, ksyRelPath);
				} else {
					throw new ToolError(`Invalid enum member in '${enumName}' of '${ksyRelPath}'.`);
				}
			}
		}
	}

	const validateAttrSpec = (attr: Record<string, unknown>, attrId: string, isSeq: boolean) => {
		if (attr.process !== undefined) {
			if (typeof attr.process !== "string" || !BUILTIN_PROCESS_PATTERN.test(attr.process.trim())) {
				throw new ToolError(
					`Custom processor '${String(attr.process)}' on field '${attrId}' in '${ksyRelPath}' is prohibited; only built-in Kaitai processors (zlib, xor(...), rol(...), ror(...)) are permitted.`,
				);
			}
			processedFieldHints[`${classQualPrefix}.${attrId}`] = true;
		}
		const { primaryType, refs } = extractReferencedTypeStrings(attr.type, ksyRelPath);
		referencedTypes.push(...refs);
		if (isSeq && primaryType) {
			fieldTypeHints[`${classQualPrefix}.${attrId}`] = primaryType;
		}
	};

	if (block.seq !== undefined) {
		if (!Array.isArray(block.seq)) {
			throw new ToolError(`'seq' in '${ksyRelPath}' must be a YAML sequence.`);
		}
		let unnamedIdx = 0;
		for (const item of block.seq) {
			if (!isRecord(item)) {
				throw new ToolError(`Each entry in 'seq' in '${ksyRelPath}' must be a mapping.`);
			}
			let attrId: string;
			if (item.id !== undefined) {
				attrId = validateKaitaiIdentifier("seq.id", item.id, ksyRelPath);
			} else {
				attrId = `_unnamed${unnamedIdx}`;
				unnamedIdx += 1;
			}
			validateAttrSpec(item, attrId, true);
		}
	}

	if (block.instances !== undefined) {
		if (!isRecord(block.instances)) {
			throw new ToolError(`'instances' in '${ksyRelPath}' must be a mapping.`);
		}
		for (const [instName, instSpec] of Object.entries(block.instances)) {
			validateKaitaiIdentifier("instance", instName, ksyRelPath);
			if (!isRecord(instSpec)) {
				throw new ToolError(`Instance '${instName}' in '${ksyRelPath}' must be a mapping.`);
			}
			validateAttrSpec(instSpec, instName, false);
		}
	}

	if (block.types !== undefined) {
		if (!isRecord(block.types)) {
			throw new ToolError(`'types' in '${ksyRelPath}' must be a mapping.`);
		}
		for (const subTypeName of Object.keys(block.types)) {
			validateKaitaiIdentifier("type", subTypeName, ksyRelPath, true);
			localTypeNames.add(subTypeName);
		}
		for (const [subTypeName, subSpec] of Object.entries(block.types)) {
			if (!isRecord(subSpec)) {
				throw new ToolError(`Type '${subTypeName}' in '${ksyRelPath}' must be a mapping.`);
			}
			if (subSpec.meta !== undefined) {
				if (!isRecord(subSpec.meta)) {
					throw new ToolError(`'meta' in nested type '${subTypeName}' of '${ksyRelPath}' must be a mapping.`);
				}
				for (const subMetaKey of Object.keys(subSpec.meta)) {
					if (!ALLOWED_META_KEYS[subMetaKey] || subMetaKey === "imports" || subMetaKey === "id") {
						throw new ToolError(
							`Prohibited meta key 'meta.${subMetaKey}' in nested type '${subTypeName}' of '${ksyRelPath}'.`,
						);
					}
				}
				if (subSpec.meta["ks-opaque-types"] !== undefined && subSpec.meta["ks-opaque-types"] !== false) {
					throw new ToolError(
						`Opaque external types ('meta.ks-opaque-types') are prohibited in nested type '${subTypeName}' of '${ksyRelPath}'.`,
					);
				}
				if (subSpec.meta["ks-debug"] !== undefined && subSpec.meta["ks-debug"] !== false) {
					throw new ToolError(`'meta.ks-debug' is prohibited in nested type '${subTypeName}' of '${ksyRelPath}'.`);
				}
			}
			const subClassQual = `${classQualPrefix}.${toPascalCase(subTypeName)}`;
			validateKsyTypeBlock(
				subSpec,
				ksyRelPath,
				subClassQual,
				localTypeNames,
				referencedTypes,
				fieldTypeHints,
				processedFieldHints,
			);
		}
	}
}

function parseAndValidateSingleKsy(
	rawBytes: Buffer,
	ksyRelPath: string,
	resolvedPath: string,
	realPath: string,
): ValidatedKsyNode {
	const hashed = hashBuffer(rawBytes);
	let parsed: unknown;
	try {
		parsed = Bun.YAML.parse(rawBytes.toString("utf8"));
	} catch (err) {
		throw new ToolError(
			`Failed to parse KSY YAML '${ksyRelPath}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	if (!isRecord(parsed)) {
		throw new ToolError(`Invalid KSY document '${ksyRelPath}': root YAML value must be a mapping.`);
	}
	if (!isRecord(parsed.meta)) {
		throw new ToolError(`Invalid KSY document '${ksyRelPath}': missing required 'meta' mapping.`);
	}

	for (const metaKey of Object.keys(parsed.meta)) {
		if (!ALLOWED_META_KEYS[metaKey]) {
			throw new ToolError(`Unsupported or prohibited meta key 'meta.${metaKey}' in '${ksyRelPath}'.`);
		}
	}

	const metaId = validateKaitaiIdentifier("meta.id", parsed.meta.id, ksyRelPath, true);

	if (parsed.meta["ks-opaque-types"] !== undefined && parsed.meta["ks-opaque-types"] !== false) {
		throw new ToolError(
			`Opaque external types ('meta.ks-opaque-types: ${String(parsed.meta["ks-opaque-types"])}') are prohibited in '${ksyRelPath}'.`,
		);
	}
	if (parsed.meta["ks-debug"] !== undefined && parsed.meta["ks-debug"] !== false) {
		throw new ToolError(
			`'meta.ks-debug' is prohibited in '${ksyRelPath}'; position tracking is managed via '--read-pos'.`,
		);
	}

	const rawImports: string[] = [];
	if (parsed.meta.imports !== undefined) {
		if (!Array.isArray(parsed.meta.imports)) {
			throw new ToolError(`'meta.imports' in '${ksyRelPath}' must be an array of relative import strings.`);
		}
		for (const imp of parsed.meta.imports) {
			if (typeof imp !== "string" || imp.trim().length === 0) {
				throw new ToolError(`Each entry in 'meta.imports' in '${ksyRelPath}' must be a non-empty string.`);
			}
			const trimmedImp = imp.trim();
			rejectNetworkOrUriPath(`meta.imports in '${ksyRelPath}'`, trimmedImp);
			if (
				trimmedImp.startsWith("/") ||
				trimmedImp.startsWith("\\") ||
				trimmedImp.startsWith("~") ||
				trimmedImp.includes("\\") ||
				trimmedImp.includes(":")
			) {
				throw new ToolError(
					`Prohibited non-relative or root-escaping import '${trimmedImp}' in '${ksyRelPath}'; imports must resolve strictly within declared local import_roots.`,
				);
			}
			const withoutExt = trimmedImp.endsWith(".ksy") ? trimmedImp.slice(0, -4) : trimmedImp;
			const parts = withoutExt.split("/");
			if (parts.length === 0 || parts.some(p => p === "" || p === "." || p === "..")) {
				throw new ToolError(`Path traversal or malformed import '${trimmedImp}' in '${ksyRelPath}'.`);
			}
			for (const seg of parts) {
				validateKaitaiIdentifier("meta.imports segment", seg, ksyRelPath, true);
			}
			rawImports.push(withoutExt);
		}
	}

	const localTypeNames = new Set<string>([metaId]);
	const referencedTypes: string[] = [];
	const fieldTypeHints: Record<string, string> = {};
	const processedFieldHints: Record<string, boolean> = {};
	const rootClassQual = `${metaId}.${toPascalCase(metaId)}`;

	validateKsyTypeBlock(
		parsed,
		ksyRelPath,
		rootClassQual,
		localTypeNames,
		referencedTypes,
		fieldTypeHints,
		processedFieldHints,
	);

	return {
		resolvedPath,
		realPath,
		relativePath: ksyRelPath,
		rawBytes,
		sha256: hashed.sha256,
		sizeBytes: hashed.size,
		metaId,
		rawImports,
		localTypeNames,
		referencedTypes,
		fieldTypeHints,
		processedFieldHints,
	};
}

function verifyKsyNodeTypeReferences(node: ValidatedKsyNode, directImportedMetaIds: Set<string>): void {
	for (const ref of node.referencedTypes) {
		if (BUILTIN_KSY_TYPES[ref] || BIT_INT_TYPE_PATTERN.test(ref)) continue;
		const segments = ref.split("::");
		for (const seg of segments) {
			if (!KAITAI_IDENT_PATTERN.test(seg)) {
				throw new ToolError(`Invalid type reference '${ref}' in '${node.relativePath}'.`);
			}
		}
		const head = segments[0]!;
		if (!node.localTypeNames.has(head) && !directImportedMetaIds.has(head)) {
			throw new ToolError(
				`Unresolved or opaque external type '${ref}' in '${node.relativePath}': type is neither built-in, locally defined, nor imported via meta.imports.`,
			);
		}
	}
}

async function resolveImportedKsyInRoots(
	importSpec: string,
	importingRelPath: string,
	importRoots: Array<SafeResolvedPath & { relativeNormalized: string }>,
	resolvedProjectDir: string,
): Promise<SafeResolvedPath> {
	if (importRoots.length === 0) {
		throw new ToolError(
			`KSY schema '${importingRelPath}' declares meta.imports ('${importSpec}'), which requires explicit local 'import_roots' within the project.`,
		);
	}

	const relKsyFile = `${importSpec}.ksy`;
	for (const root of importRoots) {
		const candPath = path.join(root.resolvedPath, ...relKsyFile.split("/"));
		let st: Stats | null = null;
		try {
			st = await fs.lstat(candPath);
		} catch (err) {
			if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
				continue;
			}
			throw err;
		}
		if (st.isSymbolicLink()) {
			throw new ToolError(
				`Symlink escape violation while resolving import '${importSpec}' in '${root.relativeNormalized}': '${candPath}' is a symbolic link.`,
			);
		}
		await assertNoSymlinkSegmentsWithinRoot(root.resolvedPath, candPath, `imported KSY '${importSpec}'`);
		const safeCand = await assertRealPathWithin(root.resolvedPath, candPath, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});
		return safeCand;
	}

	throw new ToolError(
		`Imported KSY '${importSpec}' (referenced by '${importingRelPath}') was not found in any declared import_roots (${importRoots.map(r => r.relativeNormalized).join(", ")}).`,
	);
}

interface ValidatedKsyClosure {
	rootNode: ValidatedKsyNode;
	closureNodes: ValidatedKsyNode[];
	closureEntries: FormatInspectSchemaClosureEntry[];
	resolvedImportNodesBySpec: ReadonlyMap<string, ValidatedKsyNode>;
	mergedFieldTypeHints: Record<string, string>;
	mergedProcessedFieldHints: Record<string, boolean>;
}

async function resolveAndValidateKsyClosure(options: {
	resolvedProjectDir: string;
	schemaPath: string;
	importRoots: Array<SafeResolvedPath & { relativeNormalized: string }>;
}): Promise<ValidatedKsyClosure> {
	rejectNetworkOrUriPath("schema_path", options.schemaPath);
	const safeRoot = await assertRealPathWithin(options.resolvedProjectDir, options.schemaPath, {
		baseDir: options.resolvedProjectDir,
		requireRegularFile: true,
	});
	await assertNoSymlinkSegmentsWithinRoot(
		options.resolvedProjectDir,
		safeRoot.resolvedPath,
		`schema_path '${options.schemaPath}'`,
	);

	const rootBytes = await readRegularFileBoundedNoFollow(safeRoot.resolvedPath, MAX_KSY_FILE_BYTES, "KSY schema");
	const rootNode = parseAndValidateSingleKsy(
		rootBytes,
		safeRoot.relativePath,
		safeRoot.resolvedPath,
		safeRoot.realPath,
	);

	const nodesByRealPath = new Map<string, ValidatedKsyNode>([[rootNode.realPath, rootNode]]);
	const directImportsByRealPath = new Map<string, Set<string>>();
	const resolvedImportNodesBySpec = new Map<string, ValidatedKsyNode>();
	const metaIdOwner = new Map<string, string>([[rootNode.metaId, rootNode.relativePath]]);
	const queue: ValidatedKsyNode[] = [rootNode];

	while (queue.length > 0) {
		const current = queue.shift()!;
		if (nodesByRealPath.size > MAX_KSY_CLOSURE_FILES) {
			throw new ToolError(`KSY import closure exceeds maximum of ${MAX_KSY_CLOSURE_FILES} files.`);
		}
		const directMetaIds = new Set<string>();
		for (const impSpec of current.rawImports) {
			const safeImp = await resolveImportedKsyInRoots(
				impSpec,
				current.relativePath,
				options.importRoots,
				options.resolvedProjectDir,
			);
			let impNode = nodesByRealPath.get(safeImp.realPath);
			if (!impNode) {
				const impBytes = await readRegularFileBoundedNoFollow(
					safeImp.resolvedPath,
					MAX_KSY_FILE_BYTES,
					`imported KSY '${impSpec}'`,
				);
				impNode = parseAndValidateSingleKsy(impBytes, safeImp.relativePath, safeImp.resolvedPath, safeImp.realPath);
				const existingOwner = metaIdOwner.get(impNode.metaId);
				if (existingOwner && existingOwner !== impNode.relativePath) {
					throw new ToolError(
						`Duplicate meta.id '${impNode.metaId}' across '${existingOwner}' and '${impNode.relativePath}' in KSY closure.`,
					);
				}
				metaIdOwner.set(impNode.metaId, impNode.relativePath);
				nodesByRealPath.set(impNode.realPath, impNode);
				queue.push(impNode);
			}
			directMetaIds.add(impNode.metaId);
			resolvedImportNodesBySpec.set(impSpec, impNode);
		}
		directImportsByRealPath.set(current.realPath, directMetaIds);
	}

	for (const node of nodesByRealPath.values()) {
		const directMetaIds = directImportsByRealPath.get(node.realPath) ?? new Set<string>();
		verifyKsyNodeTypeReferences(node, directMetaIds);
	}

	const importedNodes = [...nodesByRealPath.values()]
		.filter(n => n.realPath !== rootNode.realPath)
		.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
	const closureNodes = [rootNode, ...importedNodes];

	const mergedFieldTypeHints: Record<string, string> = {};
	const mergedProcessedFieldHints: Record<string, boolean> = {};
	for (const node of closureNodes) {
		Object.assign(mergedFieldTypeHints, node.fieldTypeHints);
		Object.assign(mergedProcessedFieldHints, node.processedFieldHints);
	}

	const closureEntries: FormatInspectSchemaClosureEntry[] = closureNodes.map((n, idx) => ({
		path: n.relativePath,
		sha256: n.sha256,
		size_bytes: n.sizeBytes,
		meta_id: n.metaId,
		is_root: idx === 0,
		imports: [...n.rawImports],
	}));

	return {
		rootNode,
		closureNodes,
		closureEntries,
		resolvedImportNodesBySpec,
		mergedFieldTypeHints,
		mergedProcessedFieldHints,
	};
}

// ============================================================================
// 生成 Python 解析器源码结构校验（拒绝外来任意 .py、自定义处理器与危险导入）
// ============================================================================

function verifyCompilerGeneratedPythonSource(options: {
	sourceText: string;
	expectedClassName: string;
	allowedClosureModules: ReadonlySet<string>;
	sourceLabel: string;
}): void {
	const { sourceText, expectedClassName, allowedClosureModules, sourceLabel } = options;

	if (!sourceText.startsWith(GENERATED_BANNER_PREFIX)) {
		throw new ToolError(
			`Generated Python parser verification failed for '${sourceLabel}': missing official kaitai-struct-compiler header banner.`,
		);
	}

	const classPattern = new RegExp(
		`^class\\s+${expectedClassName}\\((?:kaitaistruct\\.)?(?:ReadWrite)?KaitaiStruct\\):`,
		"m",
	);
	if (!classPattern.test(sourceText)) {
		throw new ToolError(
			`Generated Python parser verification failed for '${sourceLabel}': expected KaitaiStruct class '${expectedClassName}' not found.`,
		);
	}

	if (!sourceText.includes("SEQ_FIELDS") || !sourceText.includes("self._debug")) {
		throw new ToolError(
			`Generated Python parser verification failed for '${sourceLabel}': missing '--read-pos' position tracking instrumentation (SEQ_FIELDS / self._debug).`,
		);
	}

	const lines = sourceText.split(/\r?\n/);
	for (let i = 0; i < lines.length; i++) {
		const trimmed = lines[i]!.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		if (/^(?:import|from)\b/.test(trimmed) && trimmed.includes(";")) {
			throw new ToolError(
				`Semicolon-chained import statement is prohibited in generated parser '${sourceLabel}' (line ${i + 1}).`,
			);
		}

		const importMatch = trimmed.match(/^import\s+([^#]+)$/);
		if (importMatch) {
			const specs = importMatch[1]!.split(",");
			for (const rawSpec of specs) {
				const modToken =
					rawSpec
						.trim()
						.split(/\s+as\s+/)[0]
						?.trim()
						.split(".")[0] ?? "";
				if (
					!modToken ||
					!/^[A-Za-z_][A-Za-z0-9_]*$/.test(modToken) ||
					(!BASE_ALLOWED_PY_IMPORTS[modToken] && !allowedClosureModules.has(modToken))
				) {
					throw new ToolError(
						`Unauthorized import '${modToken || rawSpec.trim()}' detected in generated parser '${sourceLabel}' (line ${i + 1}). Custom processors and external modules are prohibited.`,
					);
				}
			}
			continue;
		}

		const fromMatch = trimmed.match(/^from\s+([^\s#]+)\s+import\s+/);
		if (fromMatch) {
			const rootMod = fromMatch[1]!.split(".")[0] ?? "";
			if (
				!rootMod ||
				!/^[A-Za-z_][A-Za-z0-9_]*$/.test(rootMod) ||
				(!BASE_ALLOWED_PY_IMPORTS[rootMod] && !allowedClosureModules.has(rootMod))
			) {
				throw new ToolError(
					`Unauthorized from-import '${fromMatch[1]}' detected in generated parser '${sourceLabel}' (line ${i + 1}). Custom processors and external modules are prohibited.`,
				);
			}
		}

		if (/\b(?:__import__|eval|exec|compile)\s*\(/.test(trimmed)) {
			throw new ToolError(
				`Prohibited dynamic code execution primitive detected in generated parser '${sourceLabel}' (line ${i + 1}).`,
			);
		}
	}
}

// ============================================================================
// 有界编译器子进程执行与进程组清理
// ============================================================================

async function terminateProcessGroup(child: ChildProcess | undefined, graceMs = 250, waitMs = 2000): Promise<void> {
	if (!child || child.pid === undefined || child.pid <= 0) return;
	if (child.exitCode !== null || child.signalCode !== null) return;

	const pid = child.pid;
	const { promise, resolve } = Promise.withResolvers<void>();
	const onDone = () => resolve();
	child.once("exit", onDone);
	child.once("close", onDone);

	try {
		if (process.platform === "win32") {
			Bun.spawnSync(["taskkill", "/F", "/T", "/PID", String(pid)]);
		} else {
			process.kill(-pid, "SIGTERM");
		}
	} catch {
		try {
			process.kill(pid, "SIGTERM");
		} catch {}
	}

	const killTimer = setTimeout(() => {
		if (child.exitCode === null && child.signalCode === null) {
			try {
				if (process.platform !== "win32") {
					process.kill(-pid, "SIGKILL");
				}
			} catch {
				try {
					process.kill(pid, "SIGKILL");
				} catch {}
			}
		}
	}, graceMs);
	killTimer.unref?.();

	const maxTimer = setTimeout(() => resolve(), waitMs);
	maxTimer.unref?.();

	try {
		await promise;
	} finally {
		clearTimeout(killTimer);
		clearTimeout(maxTimer);
		child.off("exit", onDone);
		child.off("close", onDone);
	}
}

interface CompilerSubprocessResult {
	exitCode: number | null;
	stdout: string;
	stderr: string;
	timedOut: boolean;
}

async function runBoundedKaitaiCompiler(options: {
	compilerPath: string;
	args: string[];
	env: NodeJS.ProcessEnv;
	cwd: string;
	timeoutMs: number;
	signal?: AbortSignal;
}): Promise<CompilerSubprocessResult> {
	throwIfAborted(options.signal);

	const child = spawn(options.compilerPath, options.args, {
		cwd: options.cwd,
		detached: process.platform !== "win32",
		stdio: ["ignore", "pipe", "pipe"],
		env: options.env,
		windowsHide: true,
	});

	let stdout = "";
	let stderr = "";
	let timedOut = false;
	const maxLogChars = 65536;

	child.stdout?.setEncoding("utf8");
	child.stdout?.on("data", (chunk: string) => {
		if (stdout.length < maxLogChars) {
			stdout = (stdout + chunk).slice(0, maxLogChars);
		}
	});
	child.stderr?.setEncoding("utf8");
	child.stderr?.on("data", (chunk: string) => {
		if (stderr.length < maxLogChars) {
			stderr = (stderr + chunk).slice(0, maxLogChars);
		}
	});

	const { promise: donePromise, resolve: doneResolve } = Promise.withResolvers<number | null>();
	let spawnErr: Error | undefined;
	child.once("error", err => {
		spawnErr = err;
		doneResolve(null);
	});
	child.once("close", code => doneResolve(code));

	const onAbort = () => {
		void terminateProcessGroup(child);
	};
	if (options.signal?.aborted) {
		await terminateProcessGroup(child);
		throwIfAborted(options.signal);
	}
	options.signal?.addEventListener("abort", onAbort, { once: true });

	const timer = setTimeout(() => {
		timedOut = true;
		void terminateProcessGroup(child);
	}, options.timeoutMs);
	timer.unref?.();

	try {
		const exitCode = await donePromise;
		if (options.signal?.aborted) {
			await terminateProcessGroup(child);
			throwIfAborted(options.signal);
		}
		if (spawnErr) {
			throw new ToolError(`Failed to spawn kaitai-struct-compiler: ${spawnErr.message}`);
		}
		return { exitCode, stdout, stderr, timedOut };
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
		await terminateProcessGroup(child);
	}
}

interface CanonicalCompiledPythonModule {
	moduleName: string;
	className: string;
	isEntry: boolean;
	bytes: Buffer;
	sourceText: string;
	sha256: string;
	sizeBytes: number;
}

type PrivateClosureCompileResult =
	| {
			ok: true;
			recordedArgv: string[];
			modules: CanonicalCompiledPythonModule[];
	  }
	| {
			ok: false;
			recordedArgv: string[];
			compRes: CompilerSubprocessResult;
	  };

/**
 * 在隔离临时目录与隔离 KSPATH 下，使用固定且经校验的编译器参数编译哈希绑定的 KSY 闭包，
 * 返回所有规范生成模块的源码与 SHA-256 摘要，结束后立即清理临时目录（无缓存或持久状态）。
 */
async function compileValidatedClosurePrivately(options: {
	compilerPath: string;
	javaPath: string | null;
	validatedImportRoots: Array<SafeResolvedPath & { relativeNormalized: string }>;
	closure: ValidatedKsyClosure;
	baseEnvSource: Record<string, string | undefined>;
	timeoutMs: number;
	signal?: AbortSignal;
}): Promise<PrivateClosureCompileResult> {
	const tempOutDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-ksc-out-"));
	const tempSchemaDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-ksc-ksy-"));
	const emptyKspathDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-ksc-kspath-"));

	try {
		// 将已完成哈希校验的内存 KSY 闭包字节落入私有临时目录，既消除 TOCTOU 与目录外隐式解析，又对齐 KSC 的相对导入查找规则
		const stagedRootKsyPath = path.join(tempSchemaDir, `${options.closure.rootNode.metaId}.ksy`);
		await fs.writeFile(stagedRootKsyPath, options.closure.rootNode.rawBytes, { mode: 0o600 });

		const stagedVisit = new Set<string>([`${options.closure.rootNode.realPath}::${stagedRootKsyPath}`]);
		const stageQueue: Array<{ node: ValidatedKsyNode; stagedPath: string }> = [
			{ node: options.closure.rootNode, stagedPath: stagedRootKsyPath },
		];
		while (stageQueue.length > 0) {
			const { node, stagedPath } = stageQueue.shift()!;
			const parentDir = path.dirname(stagedPath);
			for (const impSpec of node.rawImports) {
				const impNode = options.closure.resolvedImportNodesBySpec.get(impSpec);
				if (!impNode) {
					throw new ToolError(`Internal KSY closure staging error: missing resolved node for '${impSpec}'.`);
				}
				const stagedImpPath = `${path.join(parentDir, ...impSpec.split("/"))}.ksy`;
				await fs.mkdir(path.dirname(stagedImpPath), { recursive: true });
				await fs.writeFile(stagedImpPath, impNode.rawBytes, { mode: 0o600 });
				const visitKey = `${impNode.realPath}::${stagedImpPath}`;
				if (!stagedVisit.has(visitKey)) {
					stagedVisit.add(visitKey);
					stageQueue.push({ node: impNode, stagedPath: stagedImpPath });
				}
			}
		}

		const importPathArgs = options.validatedImportRoots.length > 0 ? ["--import-path", tempSchemaDir] : [];
		const compilerArgs = [
			"--target",
			"python",
			"--read-pos",
			"--opaque-types",
			"false",
			...importPathArgs,
			"--outdir",
			tempOutDir,
			stagedRootKsyPath,
		];
		const recordedArgv = [
			options.compilerPath,
			"--target",
			"python",
			"--read-pos",
			"--opaque-types",
			"false",
			...options.validatedImportRoots.flatMap(r => ["--import-path", r.relativeNormalized]),
			"--outdir",
			"<staged_outdir>",
			options.closure.rootNode.relativePath,
		].map(a => redactSecrets(a));

		const baseEnv = filterEnv(options.baseEnvSource);
		const compilerEnv: NodeJS.ProcessEnv = { ...baseEnv };
		delete compilerEnv.KSPATH;
		delete compilerEnv.JAVA_TOOL_OPTIONS;
		delete compilerEnv._JAVA_OPTIONS;
		delete compilerEnv.JDK_JAVA_OPTIONS;
		delete compilerEnv.CLASSPATH;

		compilerEnv.KSPATH = options.validatedImportRoots.length > 0 ? tempSchemaDir : emptyKspathDir;

		if (options.javaPath) {
			const javaBinDir = path.dirname(options.javaPath);
			compilerEnv.PATH = [javaBinDir, compilerEnv.PATH ?? ""].filter(Boolean).join(path.delimiter);
			if (path.basename(javaBinDir).toLowerCase() === "bin") {
				compilerEnv.JAVA_HOME = path.dirname(javaBinDir);
			}
		}

		const compRes = await runBoundedKaitaiCompiler({
			compilerPath: options.compilerPath,
			args: compilerArgs,
			env: compilerEnv,
			cwd: tempOutDir,
			timeoutMs: options.timeoutMs,
			signal: options.signal,
		});

		if (compRes.timedOut || compRes.exitCode !== 0) {
			return { ok: false, recordedArgv, compRes };
		}

		const allowedClosureModules = new Set(options.closure.closureEntries.map(c => c.meta_id));
		const producedFiles = (await fs.readdir(tempOutDir)).filter(name => name.endsWith(".py"));
		for (const fileName of producedFiles) {
			const modStem = fileName.slice(0, -3);
			if (!allowedClosureModules.has(modStem)) {
				throw new ToolError(
					`Compiler emitted unexpected Python module '${fileName}' outside verified KSY closure.`,
				);
			}
		}

		const modules: CanonicalCompiledPythonModule[] = [];
		for (const entry of options.closure.closureEntries) {
			const stagedPyPath = path.join(tempOutDir, `${entry.meta_id}.py`);
			const pyBytes = await readRegularFileBoundedNoFollow(
				stagedPyPath,
				MAX_GENERATED_PY_BYTES,
				`generated Python module '${entry.meta_id}.py'`,
			);
			const hashed = hashBuffer(pyBytes);
			const sourceText = pyBytes.toString("utf8");
			const expectedClass = toPascalCase(entry.meta_id);
			verifyCompilerGeneratedPythonSource({
				sourceText,
				expectedClassName: expectedClass,
				allowedClosureModules,
				sourceLabel: `${entry.meta_id}.py`,
			});
			modules.push({
				moduleName: entry.meta_id,
				className: expectedClass,
				isEntry: entry.is_root,
				bytes: pyBytes,
				sourceText,
				sha256: hashed.sha256,
				sizeBytes: hashed.size,
			});
		}

		return { ok: true, recordedArgv, modules };
	} finally {
		await fs.rm(tempOutDir, { recursive: true, force: true }).catch(() => {});
		await fs.rm(tempSchemaDir, { recursive: true, force: true }).catch(() => {});
		await fs.rm(emptyKspathDir, { recursive: true, force: true }).catch(() => {});
	}
}

// ============================================================================
// 输出路径分配（模式 0600，绝不覆盖源文件、现有产物或 run 元数据）
// ============================================================================

async function ensureExclusiveRunOutputPath(options: {
	projectDir: string;
	runDir: string;
	explicitOutputPath?: string;
	defaultSubdir: "scripts" | "reports";
	defaultFilenamePrefix: string;
	defaultExtension: string;
}): Promise<{ resolvedPath: string; relativePath: string }> {
	let candidateOutput: string;
	if (options.explicitOutputPath !== undefined) {
		const trimmed = options.explicitOutputPath.trim();
		if (!trimmed) {
			throw new ToolError("Parameter 'output_path' must not be empty when specified.");
		}
		rejectNetworkOrUriPath("output_path", trimmed);
		candidateOutput = trimmed;
	} else {
		const uniqueToken = `${Date.now()}_${randomBytes(4).toString("hex")}`;
		const defaultRelative = path.join(
			options.defaultSubdir,
			`${options.defaultFilenamePrefix}_${uniqueToken}${options.defaultExtension}`,
		);
		candidateOutput = path.join(options.runDir, defaultRelative);
	}

	const safeOut = await resolveAnalysisOutputPath({
		projectDir: options.projectDir,
		runDir: options.runDir,
		outputPath: candidateOutput,
	});

	try {
		await fs.lstat(safeOut.resolvedPath);
		throw new ToolError(
			`Output path '${candidateOutput}' ('${safeOut.relativePath}') already exists; refusing to overwrite existing source or artifact file.`,
		);
	} catch (err) {
		if (err instanceof ToolError) throw err;
		if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
			throw err;
		}
	}

	return {
		resolvedPath: safeOut.resolvedPath,
		relativePath: safeOut.relativePath,
	};
}

// ============================================================================
// 资源界限参数解析与 Manifest 完整结构校验
// ============================================================================

interface ValidatedExecutionLimits {
	maxInputBytes: number;
	maxDepth: number;
	maxFields: number;
	maxOutputBytes: number;
	timeoutMs: number;
}

function resolveExecutionLimits(params: FormatInspectParams): ValidatedExecutionLimits {
	const checkPositiveInt = (name: string, val: number | undefined, min: number, max: number, def: number): number => {
		if (val === undefined) return def;
		if (typeof val !== "number" || !Number.isFinite(val) || !Number.isInteger(val) || val < min || val > max) {
			throw new ToolError(`Parameter '${name}' must be an integer between ${min} and ${max}.`);
		}
		return val;
	};

	const maxInputBytes = checkPositiveInt(
		"max_input_bytes",
		params.max_input_bytes,
		1,
		HARD_MAX_INPUT_BYTES,
		DEFAULT_MAX_INPUT_BYTES,
	);
	const maxDepth = checkPositiveInt("max_depth", params.max_depth, 1, HARD_MAX_DEPTH, DEFAULT_MAX_DEPTH);
	const maxFields = checkPositiveInt("max_fields", params.max_fields, 1, HARD_MAX_FIELDS, DEFAULT_MAX_FIELDS);
	const maxOutputBytes = checkPositiveInt(
		"max_output_bytes",
		params.max_output_bytes,
		512,
		HARD_MAX_OUTPUT_BYTES,
		DEFAULT_MAX_OUTPUT_BYTES,
	);

	let timeoutMs = DEFAULT_TIMEOUT_MS;
	if (params.timeout_ms !== undefined) {
		if (
			typeof params.timeout_ms !== "number" ||
			!Number.isFinite(params.timeout_ms) ||
			params.timeout_ms < 10 ||
			params.timeout_ms > HARD_MAX_TIMEOUT_MS
		) {
			throw new ToolError(`Parameter 'timeout_ms' must be a number between 10 and ${HARD_MAX_TIMEOUT_MS}.`);
		}
		timeoutMs = Math.floor(params.timeout_ms);
	} else if (params.timeout !== undefined) {
		if (
			typeof params.timeout !== "number" ||
			!Number.isFinite(params.timeout) ||
			params.timeout < 1 ||
			params.timeout > 120
		) {
			throw new ToolError("Parameter 'timeout' must be a number between 1 and 120 seconds.");
		}
		timeoutMs = Math.floor(params.timeout * 1000);
	}

	return {
		maxInputBytes,
		maxDepth,
		maxFields,
		maxOutputBytes,
		timeoutMs,
	};
}

function isManagedRunScriptsRelativePath(relWorkspaceDir: string, candidateRelPath: string): boolean {
	const normCand = candidateRelPath.split(path.sep).join("/");
	const normWs = relWorkspaceDir === "." ? "" : relWorkspaceDir.split(path.sep).join("/");
	const prefix = normWs ? `${normWs}/analysis/` : "analysis/";
	if (!normCand.startsWith(prefix)) return false;
	const rest = normCand.slice(prefix.length).split("/");
	// <workflow_id>/runs/<run_id>/scripts/<subdir_or_file>...
	if (rest.length < 5) return false;
	if (rest[1] !== "runs" || rest[3] !== "scripts") return false;
	if (!/^[A-Za-z0-9_-]{1,128}$/.test(rest[0]!) || !/^[A-Za-z0-9_-]{1,128}$/.test(rest[2]!)) return false;
	return normCand.endsWith(".py");
}

function isManagedRunManifestRelativePath(relWorkspaceDir: string, candidateRelPath: string): boolean {
	const normCand = candidateRelPath.split(path.sep).join("/");
	const normWs = relWorkspaceDir === "." ? "" : relWorkspaceDir.split(path.sep).join("/");
	const prefix = normWs ? `${normWs}/analysis/` : "analysis/";
	if (!normCand.startsWith(prefix)) return false;
	const rest = normCand.slice(prefix.length).split("/");
	if (rest.length < 5) return false;
	if (rest[1] !== "runs" || (rest[3] !== "reports" && rest[3] !== "scripts")) return false;
	if (!/^[A-Za-z0-9_-]{1,128}$/.test(rest[0]!) || !/^[A-Za-z0-9_-]{1,128}$/.test(rest[2]!)) return false;
	return normCand.endsWith(".json");
}

function parseAndValidateManifestObject(rawText: string, manifestLabel: string): FormatInspectManifestV1 {
	let parsed: unknown;
	try {
		parsed = JSON.parse(rawText);
	} catch (err) {
		throw new ToolError(
			`Failed to parse FormatInspectManifestV1 JSON '${manifestLabel}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	if (!isRecord(parsed) || parsed.schema_version !== "1") {
		throw new ToolError(`Invalid FormatInspectManifestV1 '${manifestLabel}': expected schema_version '1'.`);
	}
	if (
		typeof parsed.manifest_id !== "string" ||
		!parsed.manifest_id ||
		typeof parsed.workflow_id !== "string" ||
		!/^[A-Za-z0-9_-]{1,128}$/.test(parsed.workflow_id) ||
		typeof parsed.step_id !== "string" ||
		!parsed.step_id ||
		typeof parsed.run_id !== "string" ||
		!/^[A-Za-z0-9_-]{1,128}$/.test(parsed.run_id) ||
		typeof parsed.root_schema_path !== "string" ||
		!parsed.root_schema_path ||
		typeof parsed.root_schema_sha256 !== "string" ||
		!/^[a-f0-9]{64}$/i.test(parsed.root_schema_sha256) ||
		typeof parsed.entry_module !== "string" ||
		!KAITAI_IDENT_PATTERN.test(parsed.entry_module) ||
		Boolean(FORBIDDEN_MODULE_IDENTS[parsed.entry_module]) ||
		typeof parsed.entry_class !== "string" ||
		!PASCAL_CLASS_PATTERN.test(parsed.entry_class) ||
		parsed.entry_class !== toPascalCase(parsed.entry_module)
	) {
		throw new ToolError(`Invalid or tampered FormatInspectManifestV1 metadata fields in '${manifestLabel}'.`);
	}

	if (
		!Array.isArray(parsed.import_roots) ||
		parsed.import_roots.some(r => typeof r !== "string" || r.trim().length === 0)
	) {
		throw new ToolError(
			`Invalid FormatInspectManifestV1 '${manifestLabel}': import_roots must be an array of strings.`,
		);
	}

	if (!isRecord(parsed.compiler) || !isRecord(parsed.runtime)) {
		throw new ToolError(`Invalid FormatInspectManifestV1 '${manifestLabel}': missing compiler or runtime metadata.`);
	}
	const expectedArgvTail = [
		"--target",
		"python",
		"--read-pos",
		"--opaque-types",
		"false",
		...(parsed.import_roots as string[]).flatMap(r => ["--import-path", r]),
		"--outdir",
		"<staged_outdir>",
		parsed.root_schema_path as string,
	].map(a => redactSecrets(a));
	if (
		typeof parsed.compiler.version !== "string" ||
		!parsed.compiler.version ||
		parsed.compiler.read_pos_enabled !== true ||
		parsed.compiler.opaque_types_allowed !== false ||
		!Array.isArray(parsed.compiler.argv) ||
		parsed.compiler.argv.length !== expectedArgvTail.length + 1 ||
		typeof parsed.compiler.argv[0] !== "string" ||
		!parsed.compiler.argv[0] ||
		parsed.compiler.argv.slice(1).some((arg, idx) => arg !== expectedArgvTail[idx])
	) {
		throw new ToolError(
			`Invalid FormatInspectManifestV1 '${manifestLabel}': compiler metadata does not match canonical fixed '--target python --read-pos --opaque-types false' policy.`,
		);
	}
	if (!Array.isArray(parsed.schema_closure) || parsed.schema_closure.length === 0) {
		throw new ToolError(`Invalid FormatInspectManifestV1 '${manifestLabel}': schema_closure must be non-empty.`);
	}
	if (!Array.isArray(parsed.generated_sources) || parsed.generated_sources.length !== parsed.schema_closure.length) {
		throw new ToolError(
			`Invalid FormatInspectManifestV1 '${manifestLabel}': generated_sources count must match schema_closure count 1-to-1.`,
		);
	}

	const closureMetaIds = new Set<string>();
	for (const item of parsed.schema_closure) {
		if (
			!isRecord(item) ||
			typeof item.path !== "string" ||
			!item.path ||
			typeof item.sha256 !== "string" ||
			!/^[a-f0-9]{64}$/i.test(item.sha256) ||
			typeof item.size_bytes !== "number" ||
			typeof item.meta_id !== "string" ||
			!KAITAI_IDENT_PATTERN.test(item.meta_id) ||
			Boolean(FORBIDDEN_MODULE_IDENTS[item.meta_id]) ||
			typeof item.is_root !== "boolean" ||
			!Array.isArray(item.imports)
		) {
			throw new ToolError(`Invalid schema_closure entry in FormatInspectManifestV1 '${manifestLabel}'.`);
		}
		closureMetaIds.add(item.meta_id);
	}

	const seenGeneratedModules = new Set<string>();
	let entryGenCount = 0;
	for (const gen of parsed.generated_sources) {
		if (
			!isRecord(gen) ||
			typeof gen.module_name !== "string" ||
			!closureMetaIds.has(gen.module_name) ||
			seenGeneratedModules.has(gen.module_name) ||
			typeof gen.class_name !== "string" ||
			gen.class_name !== toPascalCase(gen.module_name) ||
			typeof gen.path !== "string" ||
			path.basename(gen.path) !== `${gen.module_name}.py` ||
			typeof gen.sha256 !== "string" ||
			!/^[a-f0-9]{64}$/i.test(gen.sha256) ||
			typeof gen.size_bytes !== "number" ||
			typeof gen.is_entry !== "boolean"
		) {
			throw new ToolError(`Invalid generated_sources entry in FormatInspectManifestV1 '${manifestLabel}'.`);
		}
		seenGeneratedModules.add(gen.module_name);
		if (gen.is_entry) {
			if (gen.module_name !== parsed.entry_module) {
				throw new ToolError(`Entry module mismatch in FormatInspectManifestV1 '${manifestLabel}'.`);
			}
			entryGenCount += 1;
		}
	}
	if (entryGenCount !== 1) {
		throw new ToolError(`Invalid FormatInspectManifestV1 '${manifestLabel}': expected exactly one entry module.`);
	}

	const rootEntry = (parsed.schema_closure as FormatInspectSchemaClosureEntry[]).find(c => c.is_root);
	if (
		!rootEntry ||
		rootEntry.path !== parsed.root_schema_path ||
		rootEntry.sha256.toLowerCase() !== parsed.root_schema_sha256.toLowerCase() ||
		rootEntry.meta_id !== parsed.entry_module
	) {
		throw new ToolError(`Root schema mismatch in FormatInspectManifestV1 '${manifestLabel}'.`);
	}

	return parsed as unknown as FormatInspectManifestV1;
}

// ============================================================================
// 显式字段断言求值与下一步实验建议生成
// ============================================================================

function valuesEqualLossless(actual: unknown, expected: unknown, fieldType: string): boolean {
	if (fieldType === "uint64" || fieldType === "int64") {
		try {
			const actualBig = BigInt(String(actual));
			if (typeof expected === "string" && /^-?\d+$/.test(expected.trim())) {
				return actualBig === BigInt(expected.trim());
			}
			if (typeof expected === "number" && Number.isSafeInteger(expected)) {
				return actualBig === BigInt(expected);
			}
			if (typeof expected === "bigint") {
				return actualBig === expected;
			}
			return false;
		} catch {
			return false;
		}
	}
	if (fieldType === "bytes" && typeof actual === "string" && typeof expected === "string") {
		const normActual = actual.trim().toLowerCase().replace(/^0x/, "");
		const normExpected = expected.trim().toLowerCase().replace(/^0x/, "");
		return normActual === normExpected;
	}
	return deterministicJsonStringify(actual, 0) === deterministicJsonStringify(expected, 0);
}

function evaluateFieldAssertion(
	sampleRelPath: string,
	fieldsByPath: ReadonlyMap<string, FormatInspectFieldRecord>,
	assertion: FormatFieldAssertion,
): FormatInspectFieldAssertionOutcome {
	const expectExists = assertion.exists ?? true;
	const expectedVal = assertion.equals;
	const hasExpectedVal = assertion.equals !== undefined;

	const expectedSummary: FormatInspectFieldAssertionOutcome["expected"] = {
		exists: expectExists,
		...(assertion.type !== undefined ? { type: assertion.type } : {}),
		...(hasExpectedVal ? { equals: expectedVal } : {}),
		...(assertion.stream_id !== undefined ? { stream_id: assertion.stream_id } : {}),
		...(assertion.start !== undefined ? { start: assertion.start } : {}),
		...(assertion.end !== undefined ? { end: assertion.end } : {}),
		...(assertion.file_start !== undefined ? { file_start: assertion.file_start } : {}),
		...(assertion.file_end !== undefined ? { file_end: assertion.file_end } : {}),
	};

	const found = fieldsByPath.get(assertion.path);
	if (!found) {
		if (!expectExists) {
			return {
				sample_path: sampleRelPath,
				path: assertion.path,
				passed: true,
				expected: expectedSummary,
				actual: { exists: false },
			};
		}
		return {
			sample_path: sampleRelPath,
			path: assertion.path,
			passed: false,
			reason: `Field '${assertion.path}' was not present in parsed output.`,
			expected: expectedSummary,
			actual: { exists: false },
		};
	}

	const actualSummary: FormatInspectFieldAssertionOutcome["actual"] = {
		exists: true,
		type: found.type,
		...(found.ksy_type ? { ksy_type: found.ksy_type } : {}),
		value: found.value,
		stream_id: found.stream_id,
		start: found.start,
		end: found.end,
		file_start: found.file_start,
		file_end: found.file_end,
	};

	if (!expectExists) {
		return {
			sample_path: sampleRelPath,
			path: assertion.path,
			passed: false,
			reason: `Field '${assertion.path}' was expected to be absent (exists: false), but was parsed at ${found.stream_id}[${found.start}..${found.end}).`,
			expected: expectedSummary,
			actual: actualSummary,
		};
	}

	const mismatches: string[] = [];
	if (assertion.type !== undefined && found.type !== assertion.type && found.ksy_type !== assertion.type) {
		mismatches.push(`type expected '${assertion.type}', got '${found.type}'`);
	}
	if (hasExpectedVal && !valuesEqualLossless(found.value, expectedVal, found.type)) {
		mismatches.push(`value expected ${JSON.stringify(expectedVal)}, got ${JSON.stringify(found.value)}`);
	}
	if (assertion.stream_id !== undefined && found.stream_id !== assertion.stream_id) {
		mismatches.push(`stream_id expected '${assertion.stream_id}', got '${found.stream_id}'`);
	}
	if (assertion.start !== undefined && found.start !== assertion.start) {
		mismatches.push(`start expected ${assertion.start}, got ${String(found.start)}`);
	}
	if (assertion.end !== undefined && found.end !== assertion.end) {
		mismatches.push(`end expected ${assertion.end}, got ${String(found.end)}`);
	}
	if (assertion.file_start !== undefined && found.file_start !== assertion.file_start) {
		mismatches.push(`file_start expected ${String(assertion.file_start)}, got ${String(found.file_start)}`);
	}
	if (assertion.file_end !== undefined && found.file_end !== assertion.file_end) {
		mismatches.push(`file_end expected ${String(assertion.file_end)}, got ${String(found.file_end)}`);
	}

	if (mismatches.length > 0) {
		return {
			sample_path: sampleRelPath,
			path: assertion.path,
			passed: false,
			reason: mismatches.join("; "),
			expected: expectedSummary,
			actual: actualSummary,
		};
	}

	return {
		sample_path: sampleRelPath,
		path: assertion.path,
		passed: true,
		expected: expectedSummary,
		actual: actualSummary,
	};
}

// ============================================================================
// FormatInspectTool 主体实现
// ============================================================================

interface VerifiedParserExecutionContext {
	action: "parse" | "validate";
	resolvedProjectDir: string;
	workflowId: string;
	stepId: string;
	runId: string;
	limits: ValidatedExecutionLimits;
	manifest: FormatInspectManifestV1;
	manifestSafe: SafeResolvedPath;
	manifestSha256: string;
	execution: LoadAnalysisExecutionResult;
	validatedImportRoots: Array<SafeResolvedPath & { relativeNormalized: string }>;
	currentClosure: ValidatedKsyClosure;
	allowedClosureModules: string[];
	resolvedSamples: Array<{
		rawPath: string;
		resolvedPath: string;
		relativePath: string;
		sha256: string;
		sizeBytes: number;
	}>;
	fieldTypeHints: Record<string, string>;
	processedFieldHints: Record<string, boolean>;
}

export class FormatInspectTool implements AgentTool<typeof formatInspectSchema, FormatInspectDetails> {
	readonly name = "format_inspect";
	readonly label = "Format Inspect";
	readonly description: string;
	readonly parameters = formatInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	/**
	 * 按实际动作划分审批等级：
	 * - status：只读探测（read）
	 * - compile / parse / validate：外部编译器或生成代码子进程执行并写入实验产物（exec）
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args && args.action === "status") {
			return "read";
		}
		return "exec";
	};

	readonly formatApprovalDetails = (args: unknown): string[] => {
		const lines: string[] = [];
		if (isRecord(args)) {
			lines.push(`Action: ${typeof args.action === "string" ? args.action : "(missing)"}`);
			if (typeof args.schema_path === "string") lines.push(`Schema: ${args.schema_path}`);
			if (typeof args.manifest_path === "string") lines.push(`Manifest: ${args.manifest_path}`);
			if (typeof args.sample_path === "string") lines.push(`Sample: ${args.sample_path}`);
			if (Array.isArray(args.sample_paths)) lines.push(`Samples: ${args.sample_paths.length} file(s)`);
		}
		return lines;
	};

	constructor(
		private readonly session: ToolSession,
		private readonly options: FormatInspectToolOptions = {},
	) {
		this.description = prompt.render(formatInspectDescription);
	}

	private getProbeDeps() {
		return {
			cwd: this.session.cwd,
			settings: this.session.settings,
			...(this.options.env ? { env: this.options.env } : {}),
			...(this.options.which ? { which: this.options.which } : {}),
			...(this.options.agentDir ? { agentDir: this.options.agentDir } : {}),
			...(this.options.compilerPath ? { compilerPath: this.options.compilerPath } : {}),
			...(this.options.pythonPath ? { pythonPath: this.options.pythonPath } : {}),
		};
	}

	async execute(
		_toolCallId: string,
		params: FormatInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<FormatInspectDetails>,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<FormatInspectDetails> & { details: FormatInspectDetails }> {
		throwIfAborted(signal);

		if (params.action === "status") {
			return this.executeStatus();
		}

		// 计划模式只读门禁：在任何子进程执行或文件写入前拒绝 compile / parse / validate
		if (this.session.getPlanModeState?.()?.enabled) {
			throw new ToolError(
				`Plan mode is read-only. format_inspect '${params.action}' executes compiler/parser subprocesses and writes mode-0600 artifacts; only 'status' is permitted in plan mode.`,
			);
		}

		switch (params.action) {
			case "compile":
				return this.executeCompile(params, signal);
			case "parse":
				return this.executeParse(params, signal);
			case "validate":
				return this.executeValidate(params, signal);
			default:
				throw new ToolError(`Unsupported format_inspect action: '${String(params.action)}'.`);
		}
	}

	// --------------------------------------------------------------------------
	// Action: status
	// --------------------------------------------------------------------------

	private executeStatus(): AgentToolResult<FormatInspectDetails> & { details: FormatInspectDetails } {
		const readiness = resolveKaitaiToolchainReadiness(this.getProbeDeps());
		const status = readiness.ready ? "ok" : "missing_dependency";
		const lines = [
			`// Kaitai Struct Format Inspection Toolchain Status`,
			`Ready: ${readiness.ready} (Compatible: ${readiness.compatible})`,
			`Compiler: ${readiness.compiler.available ? `${readiness.compiler.version} at ${readiness.compiler.path} (--read-pos: ${readiness.compiler.supportsReadPos})` : `unavailable (${readiness.compiler.error ?? "not found"})`}`,
			`Java Runtime: ${readiness.compiler.javaReady ? readiness.compiler.javaPath : "unavailable"}`,
			`Python Runtime: ${readiness.runtime.available ? `kaitaistruct ${readiness.runtime.version} (API ${readiness.runtime.apiVersion}) via ${readiness.runtime.pythonBin}` : `unavailable (${readiness.runtime.error ?? readiness.runtime.status})`}`,
			...(readiness.incompatibilityReason ? [`Incompatibility: ${readiness.incompatibilityReason}`] : []),
			...(readiness.missingRequirements.length > 0
				? [`Missing Requirements: ${readiness.missingRequirements.join(", ")}`]
				: []),
			...(readiness.setupCommands.length > 0 ? [`Install Commands: ${readiness.setupCommands.join(" && ")}`] : []),
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				status,
				ready: readiness.ready,
				compatible: readiness.compatible,
				compiler: readiness.compiler,
				runtime: readiness.runtime,
				missingTools: readiness.missingRequirements,
				setupCommands: readiness.setupCommands,
				...(readiness.incompatibilityReason || readiness.compiler.error || readiness.runtime.error
					? {
							error: readiness.incompatibilityReason ?? readiness.compiler.error ?? readiness.runtime.error,
						}
					: {}),
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: compile
	// --------------------------------------------------------------------------

	private async executeCompile(
		params: FormatInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FormatInspectDetails> & { details: FormatInspectDetails }> {
		const resolvedProjectDir = path.resolve(this.session.cwd);
		const workflowId = requireNonEmptyParam("workflow_id", params.workflow_id, "compile");
		const stepId = requireNonEmptyParam("step_id", params.step_id, "compile");
		const runId = requireNonEmptyParam("run_id", params.run_id, "compile");
		const rawSchemaPath = requireNonEmptyParam("schema_path", params.schema_path, "compile");
		const limits = resolveExecutionLimits(params);

		rejectNetworkOrUriPath("schema_path", rawSchemaPath);

		// 1. 先校验活跃实验 run 与根 schema_path 输入绑定
		await loadAnalysisExecution({
			projectDir: resolvedProjectDir,
			workspaceDir: params.workspace_path,
			workflowId,
			stepId,
			runId,
			inputPaths: [rawSchemaPath],
			...(params.output_path !== undefined ? { outputPaths: [params.output_path] } : {}),
		});

		// 2. 校验显式本地 import_roots 并解析完整 KSY 闭包（拒绝网络/越界/软链/custom process/opaque 类型）
		const validatedImportRoots = await resolveValidatedImportRoots(resolvedProjectDir, params.import_roots);
		const closure = await resolveAndValidateKsyClosure({
			resolvedProjectDir,
			schemaPath: rawSchemaPath,
			importRoots: validatedImportRoots,
		});

		// 3. 校验 KSY 闭包内每一个文件均已在 begin inputs 声明（或为同次 run 中间产物），且哈希一致
		const execution = await loadAnalysisExecution({
			projectDir: resolvedProjectDir,
			workspaceDir: params.workspace_path,
			workflowId,
			stepId,
			runId,
			inputPaths: closure.closureEntries.map(c => c.path),
			...(params.output_path !== undefined ? { outputPaths: [params.output_path] } : {}),
		});

		// 4. 预分配独占 manifest 输出路径（绝不覆盖源文件、现有产物或 run 元数据）
		const manifestTarget = await ensureExclusiveRunOutputPath({
			projectDir: resolvedProjectDir,
			runDir: execution.paths.run_dir,
			explicitOutputPath: params.output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `kaitai_${closure.rootNode.metaId}`,
			defaultExtension: ".manifest.json",
		});

		// 5. 检查外部编译器与 Python kaitaistruct 运行时就绪状态及版本兼容性
		const readiness = resolveKaitaiToolchainReadiness(this.getProbeDeps());
		if (
			!readiness.ready ||
			!readiness.compiler.path ||
			!readiness.compiler.version ||
			!readiness.runtime.pythonBin ||
			!readiness.runtime.version
		) {
			const errMsg =
				readiness.incompatibilityReason ??
				readiness.compiler.error ??
				readiness.runtime.error ??
				"Kaitai Struct compiler or Python runtime is unavailable.";
			return {
				content: [
					{
						type: "text",
						text: `[Missing Dependency] ${errMsg}\nInstall command: ${readiness.setupCommands.join(" && ")}`,
					},
				],
				details: {
					action: "compile",
					status: "missing_dependency",
					workflowId,
					stepId,
					runId,
					missingTools: readiness.missingRequirements,
					setupCommands: readiness.setupCommands,
					compiler: readiness.compiler,
					runtime: readiness.runtime,
					error: errMsg,
				},
			};
		}

		throwIfAborted(signal);

		// 6. 在私有临时目录与隔离 KSPATH 下以固定 argv 编译 KSY 闭包
		const baseEnvSource = (this.options.env ?? (process.env as Record<string, string | undefined>)) as Record<
			string,
			string | undefined
		>;
		const compileOut = await compileValidatedClosurePrivately({
			compilerPath: readiness.compiler.path,
			javaPath: readiness.compiler.javaPath,
			validatedImportRoots,
			closure,
			baseEnvSource,
			timeoutMs: limits.timeoutMs,
			signal,
		});

		const engineVersion = `kaitai-struct-compiler ${readiness.compiler.version}; kaitaistruct ${readiness.runtime.version}`;

		if (!compileOut.ok) {
			const { compRes, recordedArgv } = compileOut;
			const diagText = redactSecrets(
				compRes.stderr.trim() || compRes.stdout.trim() || `Compiler exited with code ${String(compRes.exitCode)}`,
			);
			const errSummary = compRes.timedOut
				? `kaitai-struct-compiler timed out after ${limits.timeoutMs}ms on '${closure.rootNode.relativePath}': ${diagText}`
				: `kaitai-struct-compiler failed on '${closure.rootNode.relativePath}' (exit ${String(compRes.exitCode)}): ${diagText}`;

			const failTarget = await ensureExclusiveRunOutputPath({
				projectDir: resolvedProjectDir,
				runDir: execution.paths.run_dir,
				explicitOutputPath: params.output_path,
				defaultSubdir: "reports",
				defaultFilenamePrefix: `kaitai_compile_error_${closure.rootNode.metaId}`,
				defaultExtension: ".report.json",
			});
			const failReport: FormatInspectCompileFailureReportV1 = {
				schema_version: "1",
				report_kind: "compile_failure",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				created_at: new Date().toISOString(),
				schema_path: closure.rootNode.relativePath,
				schema_sha256: closure.rootNode.sha256,
				import_roots: validatedImportRoots.map(r => r.relativeNormalized),
				compiler_version: readiness.compiler.version,
				argv: recordedArgv,
				exit_code: compRes.exitCode,
				timed_out: compRes.timedOut,
				stdout: redactSecrets(compRes.stdout),
				stderr: redactSecrets(compRes.stderr),
				error: errSummary,
			};
			const writtenFail = await writePrivateRunArtifactFile(
				failTarget.resolvedPath,
				deterministicJsonStringify(failReport),
			);

			return {
				content: [
					{
						type: "text",
						text: [
							`[Kaitai Compile Failed] ${errSummary}`,
							`Schema: ${closure.rootNode.relativePath}`,
							`Diagnostic Report (mode 0600): ${failTarget.relativePath}`,
						].join("\n"),
					},
				],
				details: {
					action: "compile",
					status: "error",
					workflowId,
					stepId,
					runId,
					runDir: execution.paths.relative.run_dir,
					reportPath: failTarget.resolvedPath,
					reportRelativePath: failTarget.relativePath,
					reportSha256: writtenFail.sha256,
					outputPaths: [failTarget.resolvedPath],
					relativeOutputPaths: [failTarget.relativePath],
					compileFailureReport: failReport,
					argv: recordedArgv,
					exitCode: compRes.exitCode,
					engineVersion,
					error: errSummary,
				},
			};
		}

		// 7. 将规范生成的 .py 源码写入当前 run/scripts/ 下的独占子目录（mode 0600）
		const genDirName = `kaitai_gen_${closure.rootNode.metaId}_${Date.now()}_${randomBytes(4).toString("hex")}`;
		const generatedSources: FormatInspectGeneratedSourceEntry[] = [];
		const outputPaths: string[] = [];
		const relativeOutputPaths: string[] = [];

		for (const mod of compileOut.modules) {
			const relInRun = path.join("scripts", genDirName, `${mod.moduleName}.py`);
			const safePyOut = await resolveAnalysisOutputPath({
				projectDir: resolvedProjectDir,
				runDir: execution.paths.run_dir,
				outputPath: path.join(execution.paths.run_dir, relInRun),
			});
			const writtenPy = await writePrivateRunArtifactFile(safePyOut.resolvedPath, mod.bytes);

			generatedSources.push({
				module_name: mod.moduleName,
				class_name: mod.className,
				path: safePyOut.relativePath,
				sha256: writtenPy.sha256,
				size_bytes: writtenPy.size_bytes,
				is_entry: mod.isEntry,
			});
			outputPaths.push(safePyOut.resolvedPath);
			relativeOutputPaths.push(safePyOut.relativePath);
		}

		const entryClass = toPascalCase(closure.rootNode.metaId);
		const manifest: FormatInspectManifestV1 = {
			schema_version: "1",
			manifest_id: `ksym_${Bun.randomUUIDv7()}`,
			workflow_id: workflowId,
			step_id: stepId,
			run_id: runId,
			created_at: new Date().toISOString(),
			root_schema_path: closure.rootNode.relativePath,
			root_schema_sha256: closure.rootNode.sha256,
			import_roots: validatedImportRoots.map(r => r.relativeNormalized),
			schema_closure: closure.closureEntries,
			compiler: {
				path: readiness.compiler.path,
				version: readiness.compiler.version,
				argv: compileOut.recordedArgv,
				read_pos_enabled: true,
				opaque_types_allowed: false,
			},
			runtime: {
				python_path: readiness.runtime.pythonBin,
				version: readiness.runtime.version,
				api_version: readiness.runtime.apiVersion ?? readiness.runtime.version,
			},
			entry_module: closure.rootNode.metaId,
			entry_class: entryClass,
			generated_sources: generatedSources,
			field_type_hints: closure.mergedFieldTypeHints,
			processed_field_hints: closure.mergedProcessedFieldHints,
		};

		const writtenManifest = await writePrivateRunArtifactFile(
			manifestTarget.resolvedPath,
			deterministicJsonStringify(manifest),
		);
		outputPaths.unshift(manifestTarget.resolvedPath);
		relativeOutputPaths.unshift(manifestTarget.relativePath);

		const evidenceCandidates: FormatInspectEvidenceCandidate[] = [
			{
				kind: "hypothesis",
				assurance_level: "static_candidate",
				statement: redactEvidenceText(
					`Compiled Kaitai format specification '${closure.rootNode.relativePath}' (SHA-256 ${closure.rootNode.sha256.slice(0, 16)}...) into entry parser ${manifest.entry_module}.${manifest.entry_class} with --read-pos.`,
				),
				artifact_path: manifestTarget.relativePath,
				artifact_sha256: writtenManifest.sha256,
			},
		];

		const lines = [
			`// Kaitai Struct Schema Compiled`,
			`Workflow / Step / Run: ${workflowId} / ${stepId} / ${runId}`,
			`Root Schema: ${closure.rootNode.relativePath} (sha256: ${closure.rootNode.sha256.slice(0, 16)}..., closure files: ${closure.closureEntries.length})`,
			`Entry Parser: ${manifest.entry_module}.${manifest.entry_class}`,
			`Engine: ${engineVersion}`,
			`Manifest (mode 0600): ${manifestTarget.relativePath} (sha256: ${writtenManifest.sha256.slice(0, 16)}...)`,
			`Generated Modules (${generatedSources.length}):`,
			...generatedSources.map(
				g => `  • ${g.module_name} (${g.class_name}): ${g.path} (sha256: ${g.sha256.slice(0, 16)}...)`,
			),
			`Record Hint: Pass output_paths: ${JSON.stringify(relativeOutputPaths)} when calling reverse_workspace(action: "record").`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "compile",
				status: "ok",
				workflowId,
				stepId,
				runId,
				runDir: execution.paths.relative.run_dir,
				manifest,
				manifestPath: manifestTarget.resolvedPath,
				manifestRelativePath: manifestTarget.relativePath,
				manifestSha256: writtenManifest.sha256,
				generatedSources,
				outputPaths,
				relativeOutputPaths,
				argv: compileOut.recordedArgv,
				exitCode: 0,
				engineVersion,
				assuranceLevel: "static_candidate",
				evidenceCandidates,
			},
		};
	}

	// --------------------------------------------------------------------------
	// 共享辅助：加载并严格校验 Manifest、KSY 闭包、生成源码哈希与活跃 run 绑定
	// --------------------------------------------------------------------------

	private async loadVerifiedParserExecution(options: {
		params: FormatInspectParams;
		action: "parse" | "validate";
		rawSamplePaths: string[];
	}): Promise<VerifiedParserExecutionContext> {
		const resolvedProjectDir = path.resolve(this.session.cwd);
		const workflowId = requireNonEmptyParam("workflow_id", options.params.workflow_id, options.action);
		const stepId = requireNonEmptyParam("step_id", options.params.step_id, options.action);
		const runId = requireNonEmptyParam("run_id", options.params.run_id, options.action);
		const rawManifestPath = requireNonEmptyParam("manifest_path", options.params.manifest_path, options.action);
		const limits = resolveExecutionLimits(options.params);

		rejectNetworkOrUriPath("manifest_path", rawManifestPath);
		for (const sp of options.rawSamplePaths) {
			rejectNetworkOrUriPath("sample_path", sp);
		}

		// 1. 先安全读取并解析 manifest_path（确保其非软链且结构合法，拒绝将任意 .py 当作 manifest）
		const safeManifest = await assertRealPathWithin(resolvedProjectDir, rawManifestPath, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});
		await assertNoSymlinkSegmentsWithinRoot(
			resolvedProjectDir,
			safeManifest.resolvedPath,
			`manifest_path '${rawManifestPath}'`,
		);
		const manifestBytes = await readRegularFileBoundedNoFollow(
			safeManifest.resolvedPath,
			MAX_MANIFEST_FILE_BYTES,
			"FormatInspectManifestV1",
		);
		const manifestHash = hashBuffer(manifestBytes);
		const manifest = parseAndValidateManifestObject(manifestBytes.toString("utf8"), safeManifest.relativePath);

		// 2. 通过 loadAnalysisExecution 一次性校验活跃 run 状态与全部引用（manifest、样本、KSY 闭包、生成源码）
		//    跨 run 复用解析器时，若任一文件未在当前 run 的 begin inputs 中声明，loadAnalysisExecution 直接拒绝！
		const allInputPaths = [
			safeManifest.relativePath,
			...options.rawSamplePaths,
			...manifest.schema_closure.map(c => c.path),
			...manifest.generated_sources.map(g => g.path),
		];
		const execution = await loadAnalysisExecution({
			projectDir: resolvedProjectDir,
			workspaceDir: options.params.workspace_path,
			workflowId,
			stepId,
			runId,
			inputPaths: allInputPaths,
			...(options.params.output_path !== undefined ? { outputPaths: [options.params.output_path] } : {}),
		});

		if (!isManagedRunManifestRelativePath(execution.relative_workspace_dir, safeManifest.relativePath)) {
			throw new ToolError(
				`Manifest '${safeManifest.relativePath}' is outside managed analysis run directories; arbitrary external manifests are prohibited.`,
			);
		}

		// 若复用历史 run 编译的 manifest，交叉校验源 run.json 已登记的产物/脚本哈希一致（防止 record 后篡改）
		if (manifest.workflow_id !== workflowId || manifest.run_id !== runId) {
			const originRunJsonPath = path.join(
				execution.workspace_dir,
				"analysis",
				manifest.workflow_id,
				"runs",
				manifest.run_id,
				"run.json",
			);
			try {
				const safeOriginJson = await assertRealPathWithin(execution.workspace_dir, originRunJsonPath, {
					baseDir: resolvedProjectDir,
					requireRegularFile: true,
				});
				const originBytes = await readRegularFileBoundedNoFollow(
					safeOriginJson.resolvedPath,
					MAX_MANIFEST_FILE_BYTES,
					"origin run.json",
				);
				const originRun = JSON.parse(originBytes.toString("utf8")) as unknown;
				if (isRecord(originRun)) {
					const recordedMap = new Map<string, string>();
					for (const listKey of ["outputs", "scripts"] as const) {
						const arr = originRun[listKey];
						if (Array.isArray(arr)) {
							for (const ref of arr) {
								if (isRecord(ref) && typeof ref.path === "string" && typeof ref.sha256 === "string") {
									recordedMap.set(ref.path, ref.sha256.toLowerCase());
								}
							}
						}
					}
					const recManifestSha = recordedMap.get(safeManifest.relativePath);
					if (recManifestSha && recManifestSha !== manifestHash.sha256.toLowerCase()) {
						throw new ToolError(
							`Prior-run manifest '${safeManifest.relativePath}' differs from origin run '${manifest.run_id}' recorded output hash.`,
						);
					}
					for (const gen of manifest.generated_sources) {
						const recGenSha = recordedMap.get(gen.path);
						if (recGenSha && recGenSha !== gen.sha256.toLowerCase()) {
							throw new ToolError(
								`Prior-run generated parser '${gen.path}' differs from origin run '${manifest.run_id}' recorded output hash.`,
							);
						}
					}
				}
			} catch (err) {
				if (err instanceof ToolError) throw err;
				throw new ToolError(
					`Cannot verify prior-run manifest origin '${manifest.workflow_id}/${manifest.run_id}': ${err instanceof Error ? err.message : String(err)}`,
				);
			}
		}

		// 3. 复核 KSY 闭包中所有根/导入 .ksy 文件无哈希漂移（import drift / schema drift）且语法安全约束仍成立
		const validatedRoots = await resolveValidatedImportRoots(resolvedProjectDir, manifest.import_roots);
		const currentClosure = await resolveAndValidateKsyClosure({
			resolvedProjectDir,
			schemaPath: manifest.root_schema_path,
			importRoots: validatedRoots,
		});

		const currentByPath = new Map(currentClosure.closureEntries.map(e => [e.path, e]));
		if (currentByPath.size !== manifest.schema_closure.length) {
			throw new ToolError(
				`KSY schema closure drift detected: manifest recorded ${manifest.schema_closure.length} file(s), but current closure resolves to ${currentByPath.size} file(s). Recompile with format_inspect(action: "compile").`,
			);
		}
		for (const expectedEntry of manifest.schema_closure) {
			const actualEntry = currentByPath.get(expectedEntry.path);
			if (!actualEntry) {
				throw new ToolError(
					`KSY schema closure drift detected: '${expectedEntry.path}' is no longer in the resolved import closure. Recompile with format_inspect(action: "compile").`,
				);
			}
			if (
				actualEntry.sha256.toLowerCase() !== expectedEntry.sha256.toLowerCase() ||
				actualEntry.size_bytes !== expectedEntry.size_bytes ||
				actualEntry.meta_id !== expectedEntry.meta_id
			) {
				throw new ToolError(
					`KSY schema/import drift detected for '${expectedEntry.path}': manifest recorded SHA-256 ${expectedEntry.sha256}, current file has ${actualEntry.sha256}. Recompile with format_inspect(action: "compile").`,
				);
			}
		}

		// 4. 复核磁盘上全部生成 .py 文件路径受限、SHA-256 与 manifest 无漂移（generated drift）且结构合法；
		//    注意：此处绝不直接采信磁盘上的源码作为执行源，真正执行前将重新用受信任编译器私有编译 KSY 闭包并做全量哈希比对。
		const allowedClosureModules = new Set(manifest.schema_closure.map(c => c.meta_id));

		for (const gen of manifest.generated_sources) {
			if (!isManagedRunScriptsRelativePath(execution.relative_workspace_dir, gen.path)) {
				throw new ToolError(
					`Generated parser '${gen.path}' is outside managed analysis run 'scripts/' directories; loading arbitrary Python files is prohibited.`,
				);
			}
			const safeGen = await assertRealPathWithin(resolvedProjectDir, gen.path, {
				baseDir: resolvedProjectDir,
				requireRegularFile: true,
			});
			await assertNoSymlinkSegmentsWithinRoot(
				resolvedProjectDir,
				safeGen.resolvedPath,
				`generated parser '${gen.path}'`,
			);
			const genBytes = await readRegularFileBoundedNoFollow(
				safeGen.resolvedPath,
				MAX_GENERATED_PY_BYTES,
				`generated parser '${gen.path}'`,
			);
			const genHash = hashBuffer(genBytes);
			if (genHash.sha256.toLowerCase() !== gen.sha256.toLowerCase() || genHash.size !== gen.size_bytes) {
				throw new ToolError(
					`Generated parser drift detected for '${gen.path}': manifest recorded SHA-256 ${gen.sha256}, current file has ${genHash.sha256}. Refusing to execute modified parser source.`,
				);
			}
			verifyCompilerGeneratedPythonSource({
				sourceText: genBytes.toString("utf8"),
				expectedClassName: gen.class_name,
				allowedClosureModules,
				sourceLabel: gen.path,
			});
		}

		// 5. 解析并校验样本路径与输入字节上限
		const resolvedSamples: Array<{
			rawPath: string;
			resolvedPath: string;
			relativePath: string;
			sha256: string;
			sizeBytes: number;
		}> = [];
		const inputRefByRelPath = new Map(execution.inputRefs.map(r => [r.path, r]));

		for (const rawSample of options.rawSamplePaths) {
			const safeSample = await assertRealPathWithin(resolvedProjectDir, rawSample, {
				baseDir: resolvedProjectDir,
				requireRegularFile: true,
			});
			await assertNoSymlinkSegmentsWithinRoot(resolvedProjectDir, safeSample.resolvedPath, `sample '${rawSample}'`);
			const st = await fs.lstat(safeSample.resolvedPath);
			if (st.isSymbolicLink() || !st.isFile()) {
				throw new ToolError(`Sample '${rawSample}' must be a regular non-symlink file.`);
			}
			if (st.size > limits.maxInputBytes) {
				throw new ToolError(
					`Sample '${safeSample.relativePath}' size (${st.size} bytes) exceeds max_input_bytes (${limits.maxInputBytes} bytes).`,
				);
			}
			const ref = inputRefByRelPath.get(safeSample.relativePath);
			if (!ref) {
				throw new ToolError(`Internal input binding missing for sample '${safeSample.relativePath}'.`);
			}
			resolvedSamples.push({
				rawPath: rawSample,
				resolvedPath: safeSample.resolvedPath,
				relativePath: safeSample.relativePath,
				sha256: ref.sha256,
				sizeBytes: ref.size_bytes,
			});
		}

		return {
			action: options.action,
			resolvedProjectDir,
			workflowId,
			stepId,
			runId,
			limits,
			manifest,
			manifestSafe: safeManifest,
			manifestSha256: manifestHash.sha256,
			execution,
			validatedImportRoots: validatedRoots,
			currentClosure,
			allowedClosureModules: [...allowedClosureModules],
			resolvedSamples,
			fieldTypeHints: currentClosure.mergedFieldTypeHints,
			processedFieldHints: currentClosure.mergedProcessedFieldHints,
		};
	}

	private async invokeVerifiedParserWorker(ctx: VerifiedParserExecutionContext, signal?: AbortSignal) {
		// parse / validate 执行前必须同时具备受信任编译器与兼容的 Python kaitaistruct 运行时，缺失编译器直接阻断
		const readiness = resolveKaitaiToolchainReadiness(this.getProbeDeps());
		if (
			!readiness.ready ||
			!readiness.compiler.path ||
			!readiness.compiler.version ||
			!readiness.runtime.pythonBin ||
			!readiness.runtime.version
		) {
			const errMsg =
				readiness.incompatibilityReason ??
				readiness.compiler.error ??
				readiness.runtime.error ??
				"Kaitai Struct compiler or Python runtime is unavailable.";
			return {
				kind: "missing_dependency" as const,
				compiler: readiness.compiler,
				runtime: readiness.runtime,
				missingTools: readiness.missingRequirements,
				setupCommands: readiness.setupCommands,
				error: errMsg,
			};
		}

		const runtime = readiness.runtime;
		const runtimeVersion = readiness.runtime.version;
		const compat = checkKaitaiVersionCompatibility(
			ctx.manifest.compiler.version,
			runtime.version!,
			runtime.apiVersion,
		);
		if (!compat.compatible) {
			throw new ToolError(
				`Kaitai compiler/runtime version incompatibility: manifest compiled with kaitai-struct-compiler ${ctx.manifest.compiler.version} is incompatible with current kaitaistruct runtime ${runtime.version}: ${compat.reason ?? "version mismatch"}`,
			);
		}

		throwIfAborted(signal);

		// 用固定验证后的编译器参数对哈希绑定的 KSY 闭包做私有重编译，全量比对新生成源码 SHA-256 与 manifest 条目，
		// 杜绝利用无额外 import 的内置 open() 等伪造解析器 + 自洽 manifest 哈希绕过校验，且仅执行新鲜重编译出的规范源码
		const baseEnvSource = (this.options.env ?? (process.env as Record<string, string | undefined>)) as Record<
			string,
			string | undefined
		>;
		const recompiled = await compileValidatedClosurePrivately({
			compilerPath: readiness.compiler.path,
			javaPath: readiness.compiler.javaPath,
			validatedImportRoots: ctx.validatedImportRoots,
			closure: ctx.currentClosure,
			baseEnvSource,
			timeoutMs: ctx.limits.timeoutMs,
			signal,
		});

		if (!recompiled.ok) {
			const diagText = redactSecrets(
				recompiled.compRes.stderr.trim() ||
					recompiled.compRes.stdout.trim() ||
					`Compiler exited with code ${String(recompiled.compRes.exitCode)}`,
			);
			const errMsg = recompiled.compRes.timedOut
				? `Canonical Kaitai recompilation timed out after ${ctx.limits.timeoutMs}ms before ${ctx.action} on '${ctx.manifest.root_schema_path}': ${diagText}`
				: `Canonical Kaitai recompilation failed before ${ctx.action} on '${ctx.manifest.root_schema_path}' (exit ${String(recompiled.compRes.exitCode)}): ${diagText}`;
			throw new ToolError(errMsg);
		}

		const freshByModule = new Map(recompiled.modules.map(m => [m.moduleName, m]));
		if (freshByModule.size !== ctx.manifest.generated_sources.length) {
			throw new ToolError(
				`Canonical Kaitai source verification failed: compiler produced ${freshByModule.size} module(s), but manifest '${ctx.manifestSafe.relativePath}' declares ${ctx.manifest.generated_sources.length}.`,
			);
		}

		const canonicalStagedSources: Record<string, string> = {
			"__worker__.py": formatInspectWorkerPy,
		};
		for (const gen of ctx.manifest.generated_sources) {
			const fresh = freshByModule.get(gen.module_name);
			if (!fresh) {
				throw new ToolError(
					`Canonical Kaitai source verification failed: module '${gen.module_name}' declared in manifest '${ctx.manifestSafe.relativePath}' was not produced by compiler.`,
				);
			}
			if (
				fresh.sha256.toLowerCase() !== gen.sha256.toLowerCase() ||
				fresh.sizeBytes !== gen.size_bytes ||
				fresh.className !== gen.class_name ||
				fresh.isEntry !== gen.is_entry
			) {
				throw new ToolError(
					`Canonical Kaitai source verification failed for '${gen.path}' (module '${gen.module_name}'): manifest SHA-256 ${gen.sha256} does not match freshly compiled KSY output SHA-256 ${fresh.sha256}. Refusing to execute forged or non-canonical parser source.`,
				);
			}
			canonicalStagedSources[`${fresh.moduleName}.py`] = fresh.sourceText;
		}

		throwIfAborted(signal);

		interface WorkerRawResponse {
			ok: boolean;
			error_code?: string;
			error?: string;
			runtime_version?: string;
			runtime_api_version?: string;
			resource_limits?: FormatInspectResourceLimitsReport;
			output_budget_truncated?: boolean;
			results?: Array<Omit<FormatInspectSampleParseResult, "sample_sha256">>;
		}

		const workerRes = await runReversePython<WorkerRawResponse>({
			cwd: ctx.resolvedProjectDir,
			pythonPath: runtime.pythonBin!,
			requiredPackage: "kaitaistruct",
			sources: canonicalStagedSources,
			entry: "__worker__.py",
			timeoutMs: ctx.limits.timeoutMs,
			signal,
			env: {
				PYTHONNOUSERSITE: "1",
				PYTHONPATH: "",
			},
			request: {
				action: "parse",
				entry_module: ctx.manifest.entry_module,
				entry_class: ctx.manifest.entry_class,
				allowed_modules: ctx.allowedClosureModules,
				sample_paths: ctx.resolvedSamples.map(s => s.resolvedPath),
				field_type_hints: ctx.fieldTypeHints,
				processed_field_hints: ctx.processedFieldHints,
				limits: {
					max_input_bytes: ctx.limits.maxInputBytes,
					max_depth: ctx.limits.maxDepth,
					max_fields: ctx.limits.maxFields,
					max_output_bytes: ctx.limits.maxOutputBytes,
					max_byte_preview_len: DEFAULT_BYTE_PREVIEW_LEN,
					timeout_ms: ctx.limits.timeoutMs,
				},
			},
		});

		if (signal?.aborted) {
			throwIfAborted(signal);
		}

		if (workerRes.status === "missing_dependency") {
			return {
				kind: "missing_dependency" as const,
				compiler: readiness.compiler,
				runtime,
				missingTools: ["kaitaistruct"],
				setupCommands: ["reverse setup reverse kaitaistruct --execute"],
				error: workerRes.error ?? "kaitaistruct runtime missing in selected Python interpreter.",
			};
		}

		if (workerRes.status === "error" || !workerRes.result || !workerRes.result.ok) {
			const errDetail = workerRes.result?.error ?? workerRes.error ?? "Python format-inspect worker failed.";
			throw new ToolError(`Kaitai parser worker execution failed: ${redactSecrets(errDetail)}`);
		}

		const rawResults = workerRes.result.results ?? [];
		if (rawResults.length !== ctx.resolvedSamples.length) {
			throw new ToolError(
				`Kaitai parser worker returned ${rawResults.length} sample result(s), expected ${ctx.resolvedSamples.length}.`,
			);
		}

		const hydratedResults: FormatInspectSampleParseResult[] = rawResults.map((r, idx) => {
			const sampleMeta = ctx.resolvedSamples[idx]!;
			return {
				...r,
				sample_path: sampleMeta.relativePath,
				sample_sha256: sampleMeta.sha256,
			};
		});

		const resourceLimits: FormatInspectResourceLimitsReport = workerRes.result.resource_limits ?? {
			isolation_model: "subprocess_staging_not_security_sandbox",
			max_input_bytes: ctx.limits.maxInputBytes,
			max_depth: ctx.limits.maxDepth,
			max_fields: ctx.limits.maxFields,
			max_output_bytes: ctx.limits.maxOutputBytes,
			timeout_ms: ctx.limits.timeoutMs,
			rlimit_cpu: { enforced: false, reason: "not reported" },
			rlimit_as: { enforced: false, reason: "not reported" },
		};

		return {
			kind: "ok" as const,
			runtime,
			runtimeVersion: workerRes.result.runtime_version ?? runtimeVersion,
			runtimeApiVersion: workerRes.result.runtime_api_version ?? runtime.apiVersion ?? runtimeVersion,
			resourceLimits,
			results: hydratedResults,
		};
	}

	// --------------------------------------------------------------------------
	// Action: parse
	// --------------------------------------------------------------------------

	private async executeParse(
		params: FormatInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FormatInspectDetails> & { details: FormatInspectDetails }> {
		const rawSamplePath = requireNonEmptyParam("sample_path", params.sample_path, "parse");
		const ctx = await this.loadVerifiedParserExecution({
			params,
			action: "parse",
			rawSamplePaths: [rawSamplePath],
		});

		const reportTarget = await ensureExclusiveRunOutputPath({
			projectDir: ctx.resolvedProjectDir,
			runDir: ctx.execution.paths.run_dir,
			explicitOutputPath: params.output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `kaitai_parse_${ctx.manifest.entry_module}`,
			defaultExtension: ".report.json",
		});

		const workerOutcome = await this.invokeVerifiedParserWorker(ctx, signal);
		if (workerOutcome.kind === "missing_dependency") {
			return {
				content: [
					{
						type: "text",
						text: `[Missing Dependency] ${workerOutcome.error}\nInstall command: ${workerOutcome.setupCommands.join(" && ")}`,
					},
				],
				details: {
					action: "parse",
					status: "missing_dependency",
					workflowId: ctx.workflowId,
					stepId: ctx.stepId,
					runId: ctx.runId,
					missingTools: workerOutcome.missingTools,
					setupCommands: workerOutcome.setupCommands,
					compiler: workerOutcome.compiler,
					runtime: workerOutcome.runtime,
					error: workerOutcome.error,
				},
			};
		}

		const sampleRes = workerOutcome.results[0]!;
		const engineVersion = `kaitai-struct-compiler ${ctx.manifest.compiler.version}; kaitaistruct ${workerOutcome.runtimeVersion}`;
		const parseReport: FormatInspectParseReportV1 = {
			schema_version: "1",
			report_kind: "parse",
			workflow_id: ctx.workflowId,
			step_id: ctx.stepId,
			run_id: ctx.runId,
			created_at: new Date().toISOString(),
			manifest_path: ctx.manifestSafe.relativePath,
			manifest_sha256: ctx.manifestSha256,
			root_schema_path: ctx.manifest.root_schema_path,
			root_schema_sha256: ctx.manifest.root_schema_sha256,
			entry_module: ctx.manifest.entry_module,
			entry_class: ctx.manifest.entry_class,
			compiler_version: ctx.manifest.compiler.version,
			runtime_version: workerOutcome.runtimeVersion,
			runtime_api_version: workerOutcome.runtimeApiVersion,
			resource_limits: workerOutcome.resourceLimits,
			result: sampleRes,
		};

		const writtenReport = await writePrivateRunArtifactFile(
			reportTarget.resolvedPath,
			deterministicJsonStringify(parseReport),
		);

		const argvSummary = [
			workerOutcome.runtime.pythonBin ?? "python3",
			"-u",
			"<staged_format_inspect_worker.py>",
			`${ctx.manifest.entry_module}.${ctx.manifest.entry_class}`,
			sampleRes.sample_path,
		].map(a => redactSecrets(a));

		const status = sampleRes.ok ? "ok" : "error";
		const evidenceCandidates: FormatInspectEvidenceCandidate[] = sampleRes.ok
			? [
					{
						kind: "fact",
						assurance_level: "static_candidate",
						statement: redactEvidenceText(
							`Parsed sample '${sampleRes.sample_path}' (${sampleRes.consumed_bytes}/${sampleRes.sample_size} bytes consumed, ${sampleRes.trailing_bytes} trailing bytes, ${sampleRes.total_fields} fields) against Kaitai schema '${ctx.manifest.root_schema_path}'.`,
						),
						artifact_path: reportTarget.relativePath,
						artifact_sha256: writtenReport.sha256,
					},
				]
			: [
					{
						kind: "fact",
						assurance_level: "static_candidate",
						statement: redactEvidenceText(
							`Sample '${sampleRes.sample_path}' failed Kaitai schema '${ctx.manifest.root_schema_path}' at ${sampleRes.error_stream_id ?? "root"} offset ${String(sampleRes.error_offset)} (${sampleRes.error_field_path ?? "unknown field"}): ${sampleRes.error ?? "parse error"}.`,
						),
						artifact_path: reportTarget.relativePath,
						artifact_sha256: writtenReport.sha256,
					},
				];

		const previewFields = sampleRes.fields.slice(0, 20);
		const lines = [
			`// Kaitai Struct Sample Parse (${sampleRes.ok ? "SUCCEEDED" : "FAILED"})`,
			`Workflow / Step / Run: ${ctx.workflowId} / ${ctx.stepId} / ${ctx.runId}`,
			`Manifest: ${ctx.manifestSafe.relativePath} (${ctx.manifest.entry_module}.${ctx.manifest.entry_class})`,
			`Sample: ${sampleRes.sample_path} (${sampleRes.sample_size} bytes, sha256: ${sampleRes.sample_sha256.slice(0, 16)}...)`,
			`Consumed: ${sampleRes.consumed_bytes} bytes | Trailing: ${sampleRes.trailing_bytes} bytes${sampleRes.trailing_bytes > 0 ? ` (0x${sampleRes.trailing.preview_hex})` : ""}`,
			...(sampleRes.ok
				? []
				: [
						`Parse Error (${sampleRes.error_kind ?? "error"}): ${sampleRes.error}`,
						`Error Position: stream=${sampleRes.error_stream_id ?? "root"}, error_offset=${String(sampleRes.error_offset)}, stream_pos=${String(sampleRes.error_stream_pos)}, field=${sampleRes.error_field_path ?? "n/a"}, file_offset=${String(sampleRes.error_file_offset)}`,
					]),
			`Fields Extracted: ${sampleRes.fields.length}${sampleRes.truncated ? ` (truncated: ${sampleRes.truncation_reason})` : ""}`,
			...previewFields.map(
				f =>
					`  • ${f.path} [${f.type}] = ${JSON.stringify(f.value)} @ ${f.stream_id}[${String(f.start)}..${String(f.end)}) (file_offset=${f.file_offset ? `${f.file_offset.start}..${f.file_offset.end}` : "null"}${f.processed ? ", processed" : ""})`,
			),
			...(sampleRes.fields.length > previewFields.length
				? [`  … ${sampleRes.fields.length - previewFields.length} more field(s) in report JSON`]
				: []),
			`Parse Report (mode 0600): ${reportTarget.relativePath}`,
			`Notice: Process isolation stages verified generated modules in a private temp directory and is not a security sandbox.`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "parse",
				status,
				workflowId: ctx.workflowId,
				stepId: ctx.stepId,
				runId: ctx.runId,
				runDir: ctx.execution.paths.relative.run_dir,
				manifestPath: ctx.manifestSafe.resolvedPath,
				manifestRelativePath: ctx.manifestSafe.relativePath,
				manifestSha256: ctx.manifestSha256,
				reportPath: reportTarget.resolvedPath,
				reportRelativePath: reportTarget.relativePath,
				reportSha256: writtenReport.sha256,
				outputPaths: [reportTarget.resolvedPath],
				relativeOutputPaths: [reportTarget.relativePath],
				parseResult: sampleRes,
				parseReport,
				resourceLimits: workerOutcome.resourceLimits,
				argv: argvSummary,
				exitCode: sampleRes.ok ? 0 : 1,
				engineVersion,
				assuranceLevel: "static_candidate",
				evidenceCandidates,
				...(sampleRes.error ? { error: sampleRes.error } : {}),
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: validate
	// --------------------------------------------------------------------------

	private async executeValidate(
		params: FormatInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FormatInspectDetails> & { details: FormatInspectDetails }> {
		if (!Array.isArray(params.sample_paths) || params.sample_paths.length === 0) {
			throw new ToolError(
				`Parameter 'sample_paths' must be a non-empty array for format_inspect(action: "validate").`,
			);
		}
		for (const sp of params.sample_paths) {
			if (typeof sp !== "string" || sp.trim().length === 0) {
				throw new ToolError("Each entry in 'sample_paths' must be a non-empty file path string.");
			}
		}

		const ctx = await this.loadVerifiedParserExecution({
			params,
			action: "validate",
			rawSamplePaths: params.sample_paths,
		});

		// 规范化并校验 sample_expectations 与 top-level field_assertions 的样本归属
		const sampleByNormRel = new Map(ctx.resolvedSamples.map(s => [s.relativePath, s]));
		const resolveTargetSampleRel = (rawRef: string, sourceLabel: string): string => {
			rejectNetworkOrUriPath(sourceLabel, rawRef);
			const resolved = path.resolve(ctx.resolvedProjectDir, rawRef.trim());
			const rel = path.relative(ctx.resolvedProjectDir, resolved);
			if (!sampleByNormRel.has(rel)) {
				throw new ToolError(
					`${sourceLabel} references sample '${rawRef}' ('${rel}'), which is not listed in 'sample_paths'.`,
				);
			}
			return rel;
		};

		const expectationBySample = new Map<
			string,
			{
				expectSuccess: boolean;
				maxTrailingBytes?: number;
				expectedErrorOffset?: number;
				expectedErrorContains?: string;
				assertions: FormatFieldAssertion[];
			}
		>();

		for (const s of ctx.resolvedSamples) {
			expectationBySample.set(s.relativePath, {
				expectSuccess: true,
				assertions: [],
			});
		}

		for (const exp of params.sample_expectations ?? []) {
			const rel = resolveTargetSampleRel(exp.sample_path, "sample_expectations.sample_path");
			const bucket = expectationBySample.get(rel)!;
			if (exp.expect_success !== undefined) bucket.expectSuccess = exp.expect_success;
			if (exp.max_trailing_bytes !== undefined) {
				if (!Number.isInteger(exp.max_trailing_bytes) || exp.max_trailing_bytes < 0) {
					throw new ToolError("sample_expectations.max_trailing_bytes must be a non-negative integer.");
				}
				bucket.maxTrailingBytes = exp.max_trailing_bytes;
			}
			if (exp.expected_error_offset !== undefined) {
				if (!Number.isInteger(exp.expected_error_offset) || exp.expected_error_offset < 0) {
					throw new ToolError("sample_expectations.expected_error_offset must be a non-negative integer.");
				}
				bucket.expectedErrorOffset = exp.expected_error_offset;
			}
			if (exp.expected_error_contains !== undefined) {
				bucket.expectedErrorContains = exp.expected_error_contains;
			}
			if (exp.assertions) {
				bucket.assertions.push(...exp.assertions);
			}
		}

		for (const topAssertion of params.field_assertions ?? []) {
			if (topAssertion.sample_path !== undefined) {
				const rel = resolveTargetSampleRel(topAssertion.sample_path, "field_assertions.sample_path");
				expectationBySample.get(rel)!.assertions.push(topAssertion);
			} else {
				for (const bucket of expectationBySample.values()) {
					if (bucket.expectSuccess) {
						bucket.assertions.push(topAssertion);
					}
				}
			}
		}

		const reportTarget = await ensureExclusiveRunOutputPath({
			projectDir: ctx.resolvedProjectDir,
			runDir: ctx.execution.paths.run_dir,
			explicitOutputPath: params.output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `kaitai_validate_${ctx.manifest.entry_module}`,
			defaultExtension: ".report.json",
		});

		const workerOutcome = await this.invokeVerifiedParserWorker(ctx, signal);
		if (workerOutcome.kind === "missing_dependency") {
			return {
				content: [
					{
						type: "text",
						text: `[Missing Dependency] ${workerOutcome.error}\nInstall command: ${workerOutcome.setupCommands.join(" && ")}`,
					},
				],
				details: {
					action: "validate",
					status: "missing_dependency",
					workflowId: ctx.workflowId,
					stepId: ctx.stepId,
					runId: ctx.runId,
					missingTools: workerOutcome.missingTools,
					setupCommands: workerOutcome.setupCommands,
					compiler: workerOutcome.compiler,
					runtime: workerOutcome.runtime,
					error: workerOutcome.error,
				},
			};
		}

		const sampleOutcomes: FormatInspectSampleValidationOutcome[] = [];
		const nextSuggestions: string[] = [];
		let samplesMatchingExpectation = 0;
		let totalAssertions = 0;
		let passedAssertions = 0;
		let failedAssertions = 0;

		for (const parseRes of workerOutcome.results) {
			const spec = expectationBySample.get(parseRes.sample_path)!;
			let expectationMatched = parseRes.ok === spec.expectSuccess;
			let failureReason: string | undefined;

			if (!expectationMatched) {
				if (spec.expectSuccess) {
					failureReason = `Expected parse success, but failed at ${parseRes.error_stream_id ?? "root"} offset ${String(parseRes.error_offset)} (field '${parseRes.error_field_path ?? "unknown"}'): ${parseRes.error ?? "parse error"}`;
					nextSuggestions.push(
						`Sample '${parseRes.sample_path}' failed at field '${parseRes.error_field_path ?? parseRes.error_src_path ?? "root"}' (offset ${String(parseRes.error_offset)}): inspect framing/length/magic hypothesis for '${parseRes.error_field_path ?? "failing field"}'.`,
					);
				} else {
					failureReason = `Negative sample was expected to fail (expect_success: false), but schema accepted it (${parseRes.consumed_bytes}/${parseRes.sample_size} bytes consumed).`;
					nextSuggestions.push(
						`Negative sample '${parseRes.sample_path}' unexpectedly parsed without error: tighten 'contents' / 'valid' constraints on discriminating header or tag fields in '${ctx.manifest.root_schema_path}'.`,
					);
				}
			} else if (
				spec.expectSuccess &&
				spec.maxTrailingBytes !== undefined &&
				parseRes.trailing_bytes > spec.maxTrailingBytes
			) {
				expectationMatched = false;
				failureReason = `Trailing bytes (${parseRes.trailing_bytes}) exceeded max_trailing_bytes (${spec.maxTrailingBytes}) starting at offset ${parseRes.consumed_bytes}.`;
				nextSuggestions.push(
					`Sample '${parseRes.sample_path}' left ${parseRes.trailing_bytes} unconsumed trailing byte(s) at offset ${parseRes.consumed_bytes} (preview 0x${parseRes.trailing.preview_hex}): inspect unmodeled trailer/TLV fields after last parsed field.`,
				);
			} else if (!spec.expectSuccess) {
				if (spec.expectedErrorOffset !== undefined && parseRes.error_offset !== spec.expectedErrorOffset) {
					expectationMatched = false;
					failureReason = `Negative sample failed as expected, but error_offset was ${String(parseRes.error_offset)} instead of expected ${spec.expectedErrorOffset}.`;
					nextSuggestions.push(
						`Negative sample '${parseRes.sample_path}' failed at offset ${String(parseRes.error_offset)} (field '${parseRes.error_field_path ?? "n/a"}') rather than expected offset ${spec.expectedErrorOffset}: verify preceding field widths.`,
					);
				} else if (
					spec.expectedErrorContains !== undefined &&
					!(parseRes.error ?? "").toLowerCase().includes(spec.expectedErrorContains.toLowerCase())
				) {
					expectationMatched = false;
					failureReason = `Negative sample error '${parseRes.error ?? ""}' did not contain expected substring '${spec.expectedErrorContains}'.`;
					nextSuggestions.push(
						`Negative sample '${parseRes.sample_path}' failed with '${parseRes.error ?? "unknown"}' at field '${parseRes.error_field_path ?? "n/a"}': check validation constraint kind.`,
					);
				}
			}

			if (expectationMatched) {
				samplesMatchingExpectation += 1;
			}

			const fieldsByPath = new Map(parseRes.fields.map(f => [f.path, f]));
			const assertionResults: FormatInspectFieldAssertionOutcome[] = [];
			let samplePassedAssertions = 0;
			let sampleFailedAssertions = 0;

			for (const assertion of spec.assertions) {
				const outcome = evaluateFieldAssertion(parseRes.sample_path, fieldsByPath, assertion);
				assertionResults.push(outcome);
				totalAssertions += 1;
				if (outcome.passed) {
					passedAssertions += 1;
					samplePassedAssertions += 1;
				} else {
					failedAssertions += 1;
					sampleFailedAssertions += 1;
					nextSuggestions.push(
						`Sample '${parseRes.sample_path}' failed assertion on field '${assertion.path}': ${outcome.reason ?? "mismatch"}. Refine endianness, conditional guard, or offset hypothesis for '${assertion.path}'.`,
					);
				}
			}

			sampleOutcomes.push({
				sample_path: parseRes.sample_path,
				sample_sha256: parseRes.sample_sha256,
				expect_success: spec.expectSuccess,
				actual_success: parseRes.ok,
				expectation_matched: expectationMatched,
				...(failureReason ? { expectation_failure_reason: failureReason } : {}),
				parse_result: parseRes,
				assertion_results: assertionResults,
				passed_assertions: samplePassedAssertions,
				failed_assertions: sampleFailedAssertions,
			});
		}

		const totalSamples = sampleOutcomes.length;
		const sampleExpectationRate = totalSamples > 0 ? samplesMatchingExpectation / totalSamples : 0;
		const assertionSatisfactionRate = totalAssertions > 0 ? passedAssertions / totalAssertions : null;
		const allPassed = samplesMatchingExpectation === totalSamples && failedAssertions === 0;
		const dedupedSuggestions = [...new Set(nextSuggestions)];

		const validateReport: FormatInspectValidateReportV1 = {
			schema_version: "1",
			report_kind: "validate",
			workflow_id: ctx.workflowId,
			step_id: ctx.stepId,
			run_id: ctx.runId,
			created_at: new Date().toISOString(),
			manifest_path: ctx.manifestSafe.relativePath,
			manifest_sha256: ctx.manifestSha256,
			root_schema_path: ctx.manifest.root_schema_path,
			root_schema_sha256: ctx.manifest.root_schema_sha256,
			compiler_version: ctx.manifest.compiler.version,
			runtime_version: workerOutcome.runtimeVersion,
			runtime_api_version: workerOutcome.runtimeApiVersion,
			resource_limits: workerOutcome.resourceLimits,
			total_samples: totalSamples,
			samples_matching_expectation: samplesMatchingExpectation,
			sample_expectation_rate: sampleExpectationRate,
			total_assertions: totalAssertions,
			passed_assertions: passedAssertions,
			failed_assertions: failedAssertions,
			assertion_satisfaction_rate: assertionSatisfactionRate,
			all_passed: allPassed,
			coverage_claim: "corpus_and_explicit_assertions_only",
			assurance_level: "static_candidate",
			sample_outcomes: sampleOutcomes,
			next_experiment_suggestions: dedupedSuggestions,
		};

		const writtenReport = await writePrivateRunArtifactFile(
			reportTarget.resolvedPath,
			deterministicJsonStringify(validateReport),
		);

		const engineVersion = `kaitai-struct-compiler ${ctx.manifest.compiler.version}; kaitaistruct ${workerOutcome.runtimeVersion}`;
		const argvSummary = [
			workerOutcome.runtime.pythonBin ?? "python3",
			"-u",
			"<staged_format_inspect_worker.py>",
			`${ctx.manifest.entry_module}.${ctx.manifest.entry_class}`,
			...ctx.resolvedSamples.map(s => s.relativePath),
		].map(a => redactSecrets(a));

		const evidenceCandidates: FormatInspectEvidenceCandidate[] = [
			{
				kind: "fact",
				assurance_level: "static_candidate",
				statement: redactEvidenceText(
					`Validated Kaitai schema '${ctx.manifest.root_schema_path}' against ${totalSamples} explicit sample(s): ${samplesMatchingExpectation}/${totalSamples} sample expectations matched, ${passedAssertions}/${totalAssertions} explicit field assertions satisfied (corpus_and_explicit_assertions_only).`,
				),
				artifact_path: reportTarget.relativePath,
				artifact_sha256: writtenReport.sha256,
			},
		];

		const lines = [
			`// Kaitai Struct Corpus Validation (${allPassed ? "ALL EXPECTATIONS SATISFIED" : "MISMATCHES OBSERVED"})`,
			`Workflow / Step / Run: ${ctx.workflowId} / ${ctx.stepId} / ${ctx.runId}`,
			`Schema / Entry: ${ctx.manifest.root_schema_path} (${ctx.manifest.entry_module}.${ctx.manifest.entry_class})`,
			`Sample Expectations: ${samplesMatchingExpectation}/${totalSamples} (${(sampleExpectationRate * 100).toFixed(1)}%)`,
			`Explicit Field Assertions: ${totalAssertions > 0 ? `${passedAssertions}/${totalAssertions} (${((assertionSatisfactionRate ?? 0) * 100).toFixed(1)}%)` : "0 (none specified)"}`,
			`Scope & Assurance: coverage_claim=corpus_and_explicit_assertions_only, assurance_level=static_candidate (parsing corpus samples does not prove branch coverage or full protocol recovery)`,
			...sampleOutcomes.map(
				o =>
					`  • ${o.sample_path} [expect_success=${o.expect_success}, actual=${o.actual_success}]: ${o.expectation_matched && o.failed_assertions === 0 ? "PASS" : "FAIL"}${o.expectation_failure_reason ? ` — ${o.expectation_failure_reason}` : ""} (assertions: ${o.passed_assertions}/${o.assertion_results.length}, trailing: ${o.parse_result.trailing_bytes}b)`,
			),
			...(dedupedSuggestions.length > 0
				? [`Next Experiment Suggestions:`, ...dedupedSuggestions.map(s => `  → ${s}`)]
				: []),
			`Validation Report (mode 0600): ${reportTarget.relativePath}`,
			`Record Hint: Pass output_paths: ${JSON.stringify([reportTarget.relativePath])} when calling reverse_workspace(action: "record").`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "validate",
				status: allPassed ? "ok" : "error",
				workflowId: ctx.workflowId,
				stepId: ctx.stepId,
				runId: ctx.runId,
				runDir: ctx.execution.paths.relative.run_dir,
				manifestPath: ctx.manifestSafe.resolvedPath,
				manifestRelativePath: ctx.manifestSafe.relativePath,
				manifestSha256: ctx.manifestSha256,
				reportPath: reportTarget.resolvedPath,
				reportRelativePath: reportTarget.relativePath,
				reportSha256: writtenReport.sha256,
				outputPaths: [reportTarget.resolvedPath],
				relativeOutputPaths: [reportTarget.relativePath],
				validateReport,
				resourceLimits: workerOutcome.resourceLimits,
				argv: argvSummary,
				exitCode: allPassed ? 0 : 1,
				engineVersion,
				assuranceLevel: "static_candidate",
				evidenceCandidates,
				nextExperimentSuggestions: dedupedSuggestions,
				...(!allPassed
					? {
							error: `Validation did not satisfy all corpus expectations (${samplesMatchingExpectation}/${totalSamples} samples, ${passedAssertions}/${totalAssertions} assertions).`,
						}
					: {}),
			},
		};
	}
}
