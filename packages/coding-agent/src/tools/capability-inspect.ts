/**
 * capa 可解释能力识别与规则匹配树检视工具（Step 5）：
 * - status：探测本地 capa 引擎可执行文件（--version）与规则库就绪状态（resolveCapa）；
 * - detect：校验活跃实验 run 输入绑定（样本与显式外部规则库全量 YAML 闭包），以固定 argv 调用本地 capa -j，
 *   执行前后复核外部规则 manifest SHA-256 未发生漂移（或在使用内嵌规则时记录引擎二进制分发 SHA-256 + 版本并声明独立规则哈希不可用），
 *   保留 0600 原始 JSON 报告与规范化 CapabilityInspectReportV1（失败/超时保留 0600 诊断报告，绝不返回空匹配伪成功）；
 * - import：在不依赖本地 capa 可执行文件的前提下离线导入原始 capa JSON 报告，校验活跃 run 输入绑定与样本 SHA-256 一致性；
 * - 无损整数与地址桥接：通过 runReversePython 在进入 TypeScript JSON.parse 前由 Python 原生任意精度整数解析器将所有 64 位/超大整数
 *   及各类地址（no_address / absolute / relative / file_offset / dotnet_token / dotnet_token_offset / process / thread / call）
 *   无损编码为十进制与十六进制字符串，保留完整布尔语句匹配树（and/or/not/optional/some/range/subscope）、叶特征 locations/captures、
 *   RFC 6901 JSON Pointer，以及严格处于 static_candidate 等级的 FACT（规则命中位置）与 HYPOTHESIS（程序行为假设）证据候选。
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { getAgentDir, isRecord, prompt } from "@reverse/utils";
import { filterEnv } from "../eval/py/runtime";
import { redactEvidenceText, type EvidenceAssuranceLevel } from "../evidence/contracts";
import {
	computeCapaRulesManifest,
	resolveCapa,
	validateCapaRulesDir,
	type CapaProbeResult,
	type CapaRulesManifest,
} from "../extensibility/protocol-toolchain";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import capabilityInspectDescription from "../prompts/tools/capability-inspect.md" with { type: "text" };
import {
	assertRealPathWithin,
	deterministicJsonStringify,
	hashBuffer,
	hashFile,
	loadAnalysisExecution,
	redactSecrets,
	resolveAnalysisOutputPath,
	type SafeResolvedPath,
} from "../reverse-workspace";
import capabilityInspectWorkerPy from "./capability-inspect-worker.py" with { type: "text" };
import type { ToolSession } from "./index";
import { readRegularFileBoundedNoFollow, writePrivateRunArtifactFile } from "./network-import";
import { runReversePython } from "./reverse-python";
import { throwIfAborted } from "./tool-errors";

// ============================================================================
// 固定边界与安全常量
// ============================================================================

const DEFAULT_MAX_SAMPLE_BYTES = 32 * 1024 * 1024; // 32 MiB
const HARD_MAX_SAMPLE_BYTES = 128 * 1024 * 1024; // 128 MiB
const DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024; // 8 MiB（严格低于 runReversePython 16 MiB stdout 上限）
const HARD_MAX_OUTPUT_BYTES = 12 * 1024 * 1024; // 12 MiB
const DEFAULT_TIMEOUT_MS = 60_000;
const HARD_MAX_TIMEOUT_MS = 300_000;
const MAX_STDERR_CAPTURE_BYTES = 256 * 1024; // 256 KiB
const MAX_RULE_FILE_BYTES = 2 * 1024 * 1024; // 2 MiB
const MAX_RULE_TOTAL_BYTES = 64 * 1024 * 1024; // 64 MiB

const URL_SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const FUNCTION_ADDRESS_TOKEN_PATTERN = /^(?:0x[0-9a-fA-F]{1,16}|\d{1,20})$/;
const CRYPTO_OR_ENCODING_RULE_PATTERN =
	/(?:encrypt|decrypt|cipher|crypto|hash|checksum|crc|xor|rc4|aes|des|rsa|sha|md5|hmac|prng|mersenne|base64|encode|decode|murmur|twofish|tea|salsa|chacha)/;
const STATIC_INPUT_FORMATS: Readonly<Record<string, true>> = {
	auto: true,
	pe: true,
	elf: true,
	dotnet: true,
	sc32: true,
	sc64: true,
};
const STATIC_CAPA_BACKENDS: Readonly<Record<string, true>> = {
	auto: true,
	vivisect: true,
	pefile: true,
	dotnet: true,
};
const SUPPORTED_OS_VALUES: Readonly<Record<string, true>> = {
	auto: true,
	linux: true,
	macos: true,
	windows: true,
};
// ============================================================================
// 参数 Schema（TypeBox / reversetype）
// ============================================================================

export const capabilityInspectSchema = type({
	action: type
		.enumerated("status", "detect", "import")
		.describe("Capability inspection action: status, detect, or import"),
	"backend?": type.enumerated("capa").describe("Capability inspection engine backend (fixed to 'capa')"),
	"workspace_path?": type("string").describe("Optional workspace directory path (defaults to '.reverse')"),
	"workflow_id?": type("string").describe("Active reverse workflow ID (required for detect and import)"),
	"step_id?": type("string").describe("Active workflow step ID (required for detect and import)"),
	"run_id?": type("string").describe("Active analysis run ID from reverse_workspace(action: 'begin')"),
	"sample_path?": type("string").describe(
		"Target binary sample path inside project (required for detect; optional or explicit on import to verify sample SHA-256)",
	),
	"report_path?": type("string").describe(
		"Path to raw capa JSON report file for offline 'import' (must be bound in begin inputs or current run)",
	),
	"rules_path?": type("string").describe(
		"Optional explicit project-local capa rules directory or .yml/.yaml rule file (all rule files must be bound in begin inputs)",
	),
	"use_embedded_rules?": type("boolean").describe(
		"When true in 'detect' (and rules_path is omitted), invoke capa with its built-in embedded rules and record engine distribution SHA-256 + version provenance",
	),
	"namespace?": type("string").describe(
		"Optional capa rule namespace filter for 'detect' (e.g. 'data-manipulation/encryption/xor')",
	),
	"tag?": type("string").describe("Optional capa rule meta/tag filter for 'detect' (-t)"),
	"tags?": type("string[]").describe("Optional list of capa rule meta/tag filters for 'detect'"),
	"restrict_to_functions?": type("string[]").describe(
		"Optional list of function virtual addresses (hex e.g. '0x401000' or decimal) to restrict static analysis (--restrict-to-functions)",
	),
	"format?": type
		.enumerated("auto", "pe", "elf", "dotnet", "sc32", "sc64")
		.describe("Optional static input format for 'detect' (-f): auto, pe, elf, dotnet, sc32, or sc64"),
	"capa_backend?": type
		.enumerated("auto", "vivisect", "pefile", "dotnet")
		.describe("Optional static feature extractor backend for 'detect' (-b): auto, vivisect, pefile, or dotnet"),
	"os?": type
		.enumerated("auto", "linux", "macos", "windows")
		.describe("Optional target OS override for 'detect' (--os): auto, linux, macos, or windows"),
	"output_path?": type("string").describe(
		"Optional unique destination path for normalized CapabilityInspectReportV1 JSON inside the active run's managed subdirectories",
	),
	"raw_output_path?": type("string").describe(
		"Optional unique destination path for retained raw capa JSON inside the active run's managed subdirectories",
	),
	"max_sample_bytes?": type("number").describe(
		"Maximum allowed input sample size in bytes (default 32 MiB, max 128 MiB)",
	),
	"max_output_bytes?": type("number").describe(
		"Maximum allowed raw capa JSON report size in bytes (default 8 MiB, max 12 MiB)",
	),
	"timeout?": type("number").describe("Execution timeout in seconds (1 to 300, default 60)"),
	"timeout_ms?": type("number").describe(
		"Execution timeout in milliseconds (100 to 300000, overrides timeout when specified)",
	),
});

export type CapabilityInspectParams = typeof capabilityInspectSchema.infer;

// ============================================================================
// 公开返回与持久化产物类型定义
// ============================================================================

export type CapabilityAddressKind =
	| "no_address"
	| "absolute"
	| "relative"
	| "file_offset"
	| "dotnet_token"
	| "dotnet_token_offset"
	| "process"
	| "thread"
	| "call";

export interface CapabilityAddress {
	kind: CapabilityAddressKind;
	raw_type: string;
	has_address: boolean;
	value: string | null;
	decimal: string | null;
	hex: string | null;
	display: string;
	json_pointer: string;
	token?: {
		decimal: string;
		hex: string;
		offset_decimal?: string;
		offset_hex?: string;
	};
	dynamic?: {
		pid?: string;
		ppid?: string;
		tid?: string;
		call_id?: string;
		parts_decimal: string[];
		parts_hex: string[];
	};
}

export interface CapabilityFeatureDescriptor {
	type: string;
	value?: string | null;
	decimal?: string | null;
	hex?: string | null;
	description?: string;
	access?: string;
	bitness?: string;
	operand_index?: number;
	match?: string;
}

export interface CapabilityStatementDescriptor {
	type: string;
	description?: string;
	count?: string;
	min?: string;
	max?: string;
	scope?: string;
	child_feature?: CapabilityFeatureDescriptor;
}

export interface CapabilityLeafFeature {
	json_pointer: string;
	type: string;
	value?: string | null;
	decimal?: string | null;
	hex?: string | null;
	description?: string;
	success: boolean;
	locations: CapabilityAddress[];
	captures: Record<string, CapabilityAddress[]>;
}

export interface CapabilityMatchTreeNode {
	json_pointer: string;
	node_kind: "statement" | "feature";
	type: string;
	success: boolean;
	statement?: CapabilityStatementDescriptor;
	feature?: CapabilityFeatureDescriptor;
	locations: CapabilityAddress[];
	captures: Record<string, CapabilityAddress[]>;
	children: CapabilityMatchTreeNode[];
}

export interface CapabilityRuleMatchEntry {
	match_index: number;
	json_pointer: string;
	address: CapabilityAddress;
	success: boolean;
	tree: CapabilityMatchTreeNode;
	leaf_features: CapabilityLeafFeature[];
}

export interface CapabilityRuleMatchRecord {
	rule_key: string;
	rule_name: string;
	namespace: string | null;
	scopes: {
		static: string | null;
		dynamic: string | null;
	};
	primary_scope: string;
	is_subscope_rule: boolean;
	is_library_rule: boolean;
	authors: string[];
	description: string | null;
	attack: unknown[];
	mbc: unknown[];
	references: string[];
	source: string | null;
	json_pointer: string;
	source_json_pointer: string;
	match_count: number;
	matches: CapabilityRuleMatchEntry[];
}

export interface CapabilityRulesProvenance {
	source: "external_manifest" | "managed_distribution_manifest" | "embedded" | "imported_report_metadata";
	rules_kind: "directory" | "single_file" | "managed_distribution" | "embedded_in_engine" | "imported_unverified";
	rules_path: string | null;
	rule_count: number | null;
	manifest_sha256: string | null;
	independent_content_hash_available: boolean;
	independent_hash_unavailable_reason?: string;
	engine_binary_path?: string | null;
	engine_binary_sha256?: string | null;
	engine_binary_size_bytes?: number | null;
	engine_version?: string | null;
	verified_unchanged_after_execution: boolean;
	bound_in_begin_inputs: boolean;
	reported_rules?: string[];
	files?: Array<{ path: string; sha256: string; sizeBytes: number }>;
}

export interface CapabilityInspectEvidenceCandidate {
	kind: "fact" | "hypothesis";
	assurance_level: EvidenceAssuranceLevel;
	rule_name?: string;
	namespace?: string | null;
	scope?: string;
	statement: string;
	claim?: string;
	verification_plan?: string;
	match_locations: CapabilityAddress[];
	leaf_locations: CapabilityAddress[];
	artifact_path: string;
	artifact_sha256: string;
	raw_report_path: string;
	raw_report_sha256: string;
	json_pointer?: string;
	historical_context_only: boolean;
	can_satisfy_dynamic_call_gate: false;
}

export interface CapabilityRecommendedNextAction {
	rule_name: string;
	namespace: string | null;
	scope: string;
	tool: string;
	action_kind: "decompile" | "debug_or_hook" | "inspect_offset" | "inspect_dotnet" | "reproduce_live";
	observed_locations: CapabilityAddress[];
	complements_findcrypt: boolean;
	guidance: string;
}

export interface CapabilityInspectReportV1 {
	schema_version: "1";
	report_kind: "capability_inspect";
	backend: "capa";
	source_action: "detect" | "import";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	engine_version: string;
	analysis_flavor: "static" | "dynamic";
	historical_dynamic_import: boolean;
	assurance_level: "static_candidate";
	sample: {
		path: string;
		sha256: string;
		size_bytes: number;
		md5: string | null;
		sha1: string | null;
		reported_path: string | null;
	};
	raw_report: {
		path: string;
		sha256: string;
		size_bytes: number;
	};
	analysis: {
		format: string;
		arch: string;
		os: string;
		extractor: string;
		base_address: CapabilityAddress | null;
		feature_counts: {
			file: number;
			functions: Array<{ address: CapabilityAddress; count: number }>;
			processes: Array<{ address: CapabilityAddress; count: number }>;
		};
		library_functions_count: number;
	};
	filters: {
		namespace: string | null;
		tags: string[];
		restrict_to_functions: string[];
		format: string;
		capa_backend: string;
		os: string;
	};
	rules_provenance: CapabilityRulesProvenance;
	matched_rule_count: number;
	rules: CapabilityRuleMatchRecord[];
	warnings: string[];
	limitations: string[];
	evidence_candidates: CapabilityInspectEvidenceCandidate[];
	next_actions: CapabilityRecommendedNextAction[];
	next_experiment_suggestions: string[];
}

export interface CapabilityInspectFailureReportV1 {
	schema_version: "1";
	report_kind: "capability_inspect_failure";
	backend: "capa";
	source_action: "detect";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	sample_path: string;
	sample_sha256: string;
	engine_version: string;
	rules_provenance: CapabilityRulesProvenance;
	argv: string[];
	exit_code: number | null;
	timed_out: boolean;
	output_overflowed: boolean;
	raw_output_sha256: string | null;
	raw_output_size_bytes: number;
	stdout_preview: string;
	stderr: string;
	error: string;
}

export interface CapabilityInspectDetails {
	action: CapabilityInspectParams["action"];
	backend: "capa";
	status: "ok" | "missing_dependency" | "error";
	ready?: boolean;
	capa?: CapaProbeResult;
	missingTools?: string[];
	setupCommands?: string[];
	workflowId?: string;
	stepId?: string;
	runId?: string;
	runDir?: string;
	samplePath?: string;
	sampleSha256?: string;
	rawReportPath?: string;
	rawReportRelativePath?: string;
	rawReportSha256?: string;
	reportPath?: string;
	reportRelativePath?: string;
	reportSha256?: string;
	outputPaths?: string[];
	relativeOutputPaths?: string[];
	rulesProvenance?: CapabilityRulesProvenance;
	report?: CapabilityInspectReportV1;
	failureReport?: CapabilityInspectFailureReportV1;
	argv?: string[];
	exitCode?: number | null;
	engineVersion?: string;
	assuranceLevel?: EvidenceAssuranceLevel;
	evidenceCandidates?: CapabilityInspectEvidenceCandidate[];
	nextActions?: CapabilityRecommendedNextAction[];
	nextExperimentSuggestions?: string[];
	warnings?: string[];
	limitations?: string[];
	error?: string;
}

export interface CapabilityInspectToolOptions {
	env?: Record<string, string | undefined>;
	which?: SkillRequirementWhich;
	agentDir?: string;
	capaPath?: string;
	rulesPath?: string;
	pythonPath?: string;
	/** 测试专用钩子：在 capa 子进程退出后、执行规则完整性复核前触发，用于验证运行期规则篡改拦截。 */
	onBeforePostExecutionRulesCheck?: () => Promise<void> | void;
}

// ============================================================================
// 内部校验、路径安全与子进程辅助函数
// ============================================================================

interface ExecutionLimits {
	maxSampleBytes: number;
	maxOutputBytes: number;
	timeoutMs: number;
}

function requireNonEmptyParam(fieldName: string, value: string | undefined, action: string): string {
	const trimmed = value?.trim() ?? "";
	if (!trimmed) {
		throw new ToolError(`Parameter '${fieldName}' is required for capability_inspect(action: "${action}").`);
	}
	return trimmed;
}

function rejectNetworkOrUriPath(fieldName: string, rawPath: string): void {
	const trimmed = rawPath.trim();
	if (URL_SCHEME_PATTERN.test(trimmed) || trimmed.startsWith("//")) {
		throw new ToolError(
			`Network or URI path is prohibited for '${fieldName}' ('${rawPath}'); only local project files are allowed.`,
		);
	}
}

function clampIntegerLimit(
	fieldName: string,
	rawValue: number | undefined,
	defaultValue: number,
	minValue: number,
	hardMaxValue: number,
): number {
	if (rawValue === undefined) return defaultValue;
	if (typeof rawValue !== "number" || !Number.isFinite(rawValue) || !Number.isInteger(rawValue)) {
		throw new ToolError(`Parameter '${fieldName}' must be an integer.`);
	}
	if (rawValue < minValue || rawValue > hardMaxValue) {
		throw new ToolError(`Parameter '${fieldName}' (${rawValue}) must be between ${minValue} and ${hardMaxValue}.`);
	}
	return rawValue;
}

function resolveExecutionLimits(params: CapabilityInspectParams): ExecutionLimits {
	const maxSampleBytes = clampIntegerLimit(
		"max_sample_bytes",
		params.max_sample_bytes,
		DEFAULT_MAX_SAMPLE_BYTES,
		1,
		HARD_MAX_SAMPLE_BYTES,
	);
	const maxOutputBytes = clampIntegerLimit(
		"max_output_bytes",
		params.max_output_bytes,
		DEFAULT_MAX_OUTPUT_BYTES,
		512,
		HARD_MAX_OUTPUT_BYTES,
	);

	let timeoutMs = DEFAULT_TIMEOUT_MS;
	if (params.timeout_ms !== undefined) {
		timeoutMs = clampIntegerLimit("timeout_ms", params.timeout_ms, DEFAULT_TIMEOUT_MS, 100, HARD_MAX_TIMEOUT_MS);
	} else if (params.timeout !== undefined) {
		if (typeof params.timeout !== "number" || !Number.isFinite(params.timeout) || params.timeout <= 0) {
			throw new ToolError("Parameter 'timeout' must be a positive number of seconds.");
		}
		timeoutMs = Math.min(HARD_MAX_TIMEOUT_MS, Math.max(100, Math.round(params.timeout * 1000)));
	}

	return {
		maxSampleBytes,
		maxOutputBytes,
		timeoutMs,
	};
}

async function assertNoSymlinkSegmentsWithinRoot(
	rootDir: string,
	targetResolvedPath: string,
	label: string,
): Promise<void> {
	const resolvedRoot = path.resolve(rootDir);
	const resolvedTarget = path.resolve(targetResolvedPath);
	const rel = path.relative(resolvedRoot, resolvedTarget);
	if (rel.startsWith("..") || path.isAbsolute(rel)) {
		throw new ToolError(`Path '${targetResolvedPath}' for ${label} escapes root directory '${resolvedRoot}'.`);
	}
	if (!rel) return;

	const parts = rel.split(path.sep).filter(Boolean);
	let current = resolvedRoot;
	for (const part of parts) {
		current = path.join(current, part);
		let st: Stats;
		try {
			st = await fs.lstat(current);
		} catch (err) {
			if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
				break;
			}
			throw err;
		}
		if (st.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation: '${current}' in ${label} is a symbolic link.`);
		}
	}
}

async function ensureExclusiveRunOutputPath(options: {
	projectDir: string;
	runDir: string;
	explicitOutputPath?: string;
	defaultSubdir: "scripts" | "dumps" | "reports" | "tmp";
	defaultFilenamePrefix: string;
	defaultExtension: string;
}): Promise<{
	resolvedPath: string;
	realPath: string;
	relativePath: string;
	runRelativePath: string;
}> {
	const rawOut =
		options.explicitOutputPath?.trim() ||
		path.join(
			options.runDir,
			options.defaultSubdir,
			`${options.defaultFilenamePrefix}_${Date.now()}_${randomBytes(4).toString("hex")}${options.defaultExtension}`,
		);

	rejectNetworkOrUriPath("output_path", rawOut);

	const resolvedCandidate = path.resolve(options.projectDir, rawOut);
	const relToRun = path.relative(path.resolve(options.runDir), resolvedCandidate);
	if (!relToRun || relToRun.startsWith("..") || path.isAbsolute(relToRun)) {
		throw new ToolError(
			`Invalid output path '${rawOut}': path escapes allowed directory '${options.runDir}'. Output must reside inside the active run's managed subdirectories (scripts, dumps, reports, tmp).`,
		);
	}

	const safeOut = await resolveAnalysisOutputPath({
		projectDir: options.projectDir,
		runDir: options.runDir,
		outputPath: resolvedCandidate,
	});

	try {
		await fs.lstat(safeOut.resolvedPath);
		throw new ToolError(
			`Output artifact '${safeOut.relativePath}' already exists; refusing to overwrite existing experiment artifact.`,
		);
	} catch (err) {
		if (err instanceof ToolError) throw err;
		if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
			throw err;
		}
	}

	return safeOut;
}

const CAPA_RULE_YAML_BLOCK_PATTERN = /\brule\s*:[\s\S]*\bmeta\s*:[\s\S]*\bfeatures\s*:/m;

interface ResolvedExternalRulesTarget {
	source: "external_manifest" | "managed_distribution_manifest";
	rulesKind: "directory" | "single_file" | "managed_distribution";
	resolvedPath: string;
	displayPath: string;
	boundInBeginInputs: boolean;
	projectRelativeRuleFiles: string[];
	manifest: CapaRulesManifest;
}

async function resolveAndHashProjectRulesPath(
	resolvedProjectDir: string,
	rawRulesPath: string,
): Promise<ResolvedExternalRulesTarget> {
	rejectNetworkOrUriPath("rules_path", rawRulesPath);

	const candidateAbs = path.resolve(resolvedProjectDir, rawRulesPath.trim());
	await assertNoSymlinkSegmentsWithinRoot(resolvedProjectDir, candidateAbs, `rules_path '${rawRulesPath}'`);

	let safeRules: SafeResolvedPath;
	try {
		safeRules = await assertRealPathWithin(resolvedProjectDir, candidateAbs, {
			baseDir: resolvedProjectDir,
		});
	} catch (err) {
		throw new ToolError(`Invalid rules_path '${rawRulesPath}': ${err instanceof Error ? err.message : String(err)}`);
	}

	let st: Stats;
	try {
		st = await fs.lstat(safeRules.resolvedPath);
	} catch (err) {
		throw new ToolError(
			`rules_path '${rawRulesPath}' does not exist: ${err instanceof Error ? err.message : String(err)}`,
		);
	}
	if (st.isSymbolicLink()) {
		throw new ToolError(`Symlink escape violation: rules_path '${rawRulesPath}' is a symbolic link.`);
	}

	if (st.isDirectory()) {
		const manifest = computeCapaRulesManifest(safeRules.resolvedPath, {
			maxFileBytes: MAX_RULE_FILE_BYTES,
			maxTotalBytes: MAX_RULE_TOTAL_BYTES,
		});
		if (!manifest) {
			const validation = validateCapaRulesDir(safeRules.resolvedPath, {
				maxFileBytes: MAX_RULE_FILE_BYTES,
				maxTotalBytes: MAX_RULE_TOTAL_BYTES,
			});
			throw new ToolError(
				validation.error ??
					`Invalid capa rules directory '${safeRules.relativePath}': failed strict YAML closure manifest check.`,
			);
		}
		const projectRelativeRuleFiles = manifest.files.map(entry => path.join(safeRules.relativePath, entry.path));
		return {
			source: "external_manifest",
			rulesKind: "directory",
			resolvedPath: safeRules.resolvedPath,
			displayPath: safeRules.relativePath,
			boundInBeginInputs: true,
			projectRelativeRuleFiles,
			manifest,
		};
	}

	if (st.isFile()) {
		const lower = safeRules.resolvedPath.toLowerCase();
		if (!lower.endsWith(".yml") && !lower.endsWith(".yaml")) {
			throw new ToolError(
				`Invalid rules_path '${rawRulesPath}': single rule file must have a .yml or .yaml extension.`,
			);
		}
		const rawBytes = await readRegularFileBoundedNoFollow(safeRules.resolvedPath, MAX_RULE_FILE_BYTES, "rules_path");
		const text = rawBytes.toString("utf8");
		if (!CAPA_RULE_YAML_BLOCK_PATTERN.test(text)) {
			throw new ToolError(
				`Invalid capa rule file '${safeRules.relativePath}': file does not contain required rule/meta/features YAML structure.`,
			);
		}
		const fileHash = hashBuffer(rawBytes);
		const baseName = path.basename(safeRules.resolvedPath);
		const manifestSha256 = createHash("sha256")
			.update(`${baseName}:${fileHash.sha256}:${fileHash.size}\n`)
			.digest("hex");
		const manifest: CapaRulesManifest = {
			rulesPath: safeRules.resolvedPath,
			ruleCount: 1,
			manifestSha256,
			files: [
				{
					path: baseName,
					sha256: fileHash.sha256,
					sizeBytes: fileHash.size,
				},
			],
		};
		return {
			source: "external_manifest",
			rulesKind: "single_file",
			resolvedPath: safeRules.resolvedPath,
			displayPath: safeRules.relativePath,
			boundInBeginInputs: true,
			projectRelativeRuleFiles: [safeRules.relativePath],
			manifest,
		};
	}

	throw new ToolError(`Invalid rules_path '${rawRulesPath}': must be a regular file or directory.`);
}

async function recomputeExternalRulesManifest(target: ResolvedExternalRulesTarget): Promise<CapaRulesManifest | null> {
	if (target.rulesKind === "directory" || target.rulesKind === "managed_distribution") {
		return computeCapaRulesManifest(target.resolvedPath, {
			maxFileBytes: MAX_RULE_FILE_BYTES,
			maxTotalBytes: MAX_RULE_TOTAL_BYTES,
		});
	}
	try {
		const rawBytes = await readRegularFileBoundedNoFollow(target.resolvedPath, MAX_RULE_FILE_BYTES, "rules_path");
		const text = rawBytes.toString("utf8");
		if (!CAPA_RULE_YAML_BLOCK_PATTERN.test(text)) return null;
		const fileHash = hashBuffer(rawBytes);
		const baseName = path.basename(target.resolvedPath);
		const manifestSha256 = createHash("sha256")
			.update(`${baseName}:${fileHash.sha256}:${fileHash.size}\n`)
			.digest("hex");
		return {
			rulesPath: target.resolvedPath,
			ruleCount: 1,
			manifestSha256,
			files: [
				{
					path: baseName,
					sha256: fileHash.sha256,
					sizeBytes: fileHash.size,
				},
			],
		};
	} catch {
		return null;
	}
}

function validateFilterToken(fieldName: string, rawVal: string): string {
	const trimmed = rawVal.trim();
	if (!trimmed) {
		throw new ToolError(`Parameter '${fieldName}' must not be empty.`);
	}
	if (/[\r\n\0]/.test(trimmed)) {
		throw new ToolError(`Parameter '${fieldName}' contains prohibited control characters.`);
	}
	if (trimmed.startsWith("-")) {
		throw new ToolError(`Parameter '${fieldName}' ('${trimmed}') must not start with '-'.`);
	}
	return trimmed;
}

function parseValidatedFunctionFilters(rawList: string[] | undefined): string[] {
	if (!rawList || rawList.length === 0) return [];
	const tokens: string[] = [];
	const seen = new Set<string>();
	for (const entry of rawList) {
		if (typeof entry !== "string") {
			throw new ToolError("Each entry in 'restrict_to_functions' must be a string.");
		}
		const parts = entry
			.split(",")
			.map(p => p.trim())
			.filter(Boolean);
		if (parts.length === 0) {
			throw new ToolError("Entries in 'restrict_to_functions' must not be empty.");
		}
		for (const part of parts) {
			if (!FUNCTION_ADDRESS_TOKEN_PATTERN.test(part)) {
				throw new ToolError(
					`Invalid function address '${part}' in 'restrict_to_functions': must be a hexadecimal (e.g. '0x401000') or decimal virtual address.`,
				);
			}
			const normKey = part.toLowerCase();
			if (!seen.has(normKey)) {
				seen.add(normKey);
				tokens.push(part);
			}
		}
	}
	return tokens;
}

async function terminateProcessGroup(child: ChildProcess | undefined, timeoutMs = 2000): Promise<void> {
	if (!child || child.pid === undefined || child.pid <= 0) return;
	if (child.exitCode !== null || child.signalCode !== null) return;

	const pid = child.pid;
	const { promise: exitPromise, resolve: exitResolve } = Promise.withResolvers<void>();
	const onExit = () => exitResolve();
	child.once("exit", onExit);
	child.once("close", onExit);

	try {
		if (process.platform === "win32") {
			child.kill("SIGTERM");
		} else {
			process.kill(-pid, "SIGTERM");
		}
	} catch {
		try {
			child.kill("SIGTERM");
		} catch {}
	}

	const escalationTimer = setTimeout(() => {
		if (child.exitCode === null && child.signalCode === null) {
			try {
				if (process.platform === "win32") {
					Bun.spawnSync(["taskkill", "/F", "/T", "/PID", String(pid)]);
				} else {
					process.kill(-pid, "SIGKILL");
				}
			} catch {
				try {
					child.kill("SIGKILL");
				} catch {}
			}
		}
	}, 250);
	escalationTimer.unref?.();

	const waitTimer = setTimeout(() => exitResolve(), timeoutMs);
	waitTimer.unref?.();

	try {
		await exitPromise;
	} finally {
		clearTimeout(escalationTimer);
		clearTimeout(waitTimer);
		child.removeListener("exit", onExit);
		child.removeListener("close", onExit);
	}
}

interface BoundedCapaExecResult {
	exitCode: number | null;
	stdoutBytes: Buffer;
	stderr: string;
	timedOut: boolean;
	outputOverflowed: boolean;
}

async function runBoundedCapaProcess(options: {
	capaBin: string;
	argv: string[];
	cwd: string;
	env: Record<string, string | undefined>;
	timeoutMs: number;
	maxOutputBytes: number;
	signal?: AbortSignal;
}): Promise<BoundedCapaExecResult> {
	throwIfAborted(options.signal);

	const child = spawn(options.capaBin, options.argv, {
		cwd: options.cwd,
		env: options.env,
		stdio: ["ignore", "pipe", "pipe"],
		detached: process.platform !== "win32",
	});

	const stdoutChunks: Buffer[] = [];
	let stdoutTotal = 0;
	let outputOverflowed = false;
	let stderr = "";
	let timedOut = false;

	child.stdout?.on("data", (chunk: Buffer | string) => {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		stdoutTotal += buf.byteLength;
		if (stdoutTotal > options.maxOutputBytes) {
			outputOverflowed = true;
			void terminateProcessGroup(child);
			return;
		}
		stdoutChunks.push(buf);
	});

	child.stderr?.setEncoding("utf8");
	child.stderr?.on("data", (chunk: string) => {
		if (stderr.length < MAX_STDERR_CAPTURE_BYTES) {
			stderr = (stderr + chunk).slice(0, MAX_STDERR_CAPTURE_BYTES);
		}
	});

	const { promise: donePromise, resolve: doneResolve, reject: doneReject } = Promise.withResolvers<number | null>();
	child.once("error", err => doneReject(err));
	child.once("close", code => doneResolve(code));

	const onAbort = () => {
		void terminateProcessGroup(child);
		doneReject(new ToolError("capability_inspect operation aborted by caller signal."));
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });

	const timer = setTimeout(() => {
		timedOut = true;
		void terminateProcessGroup(child);
	}, options.timeoutMs);
	timer.unref?.();

	try {
		const exitCode = await donePromise;
		return {
			exitCode,
			stdoutBytes: Buffer.concat(stdoutChunks),
			stderr,
			timedOut,
			outputOverflowed,
		};
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
		await terminateProcessGroup(child);
	}
}

// ============================================================================
// Python 无损 JSON 桥接调用与证据/后续行动构造
// ============================================================================

interface WorkerNormalizedDocument {
	meta: {
		timestamp: string;
		version: string;
		argv: string[];
		flavor: "static" | "dynamic";
		sample: {
			sha256: string;
			md5: string | null;
			sha1: string | null;
			reported_path: string | null;
		};
		analysis: {
			format: string;
			arch: string;
			os: string;
			extractor: string;
			reported_rules: string[];
			base_address: CapabilityAddress | null;
			feature_counts: {
				file: number;
				functions: Array<{ address: CapabilityAddress; count: number }>;
				processes: Array<{ address: CapabilityAddress; count: number }>;
			};
			library_functions_count: number;
		};
	};
	rules: CapabilityRuleMatchRecord[];
}

interface WorkerBridgeResponse {
	ok: boolean;
	error_code?: string;
	error?: string;
	json_pointer?: string;
	raw_sha256?: string;
	raw_size_bytes?: number;
	document?: WorkerNormalizedDocument;
}

async function parseCapaJsonViaLosslessPythonBridge(options: {
	cwd: string;
	jsonPath: string;
	maxOutputBytes: number;
	timeoutMs: number;
	pythonPath?: string;
	signal?: AbortSignal;
}): Promise<WorkerBridgeResponse> {
	throwIfAborted(options.signal);

	const workerRes = await runReversePython<WorkerBridgeResponse>({
		cwd: options.cwd,
		...(options.pythonPath ? { pythonPath: options.pythonPath } : {}),
		sources: {
			"__capa_worker__.py": capabilityInspectWorkerPy,
		},
		entry: "__capa_worker__.py",
		timeoutMs: Math.max(10_000, Math.min(options.timeoutMs, 60_000)),
		signal: options.signal,
		env: {
			PYTHONNOUSERSITE: "1",
			PYTHONPATH: "",
		},
		request: {
			json_path: options.jsonPath,
			max_output_bytes: options.maxOutputBytes,
		},
	});

	if (workerRes.status !== "ok" || !workerRes.result) {
		throw new ToolError(
			`Lossless capa JSON bridge failed: ${workerRes.error ?? (workerRes.stderr || "unknown worker failure")}`,
		);
	}

	return workerRes.result;
}

function ruleMatchesRequestedFilters(
	rule: CapabilityRuleMatchRecord,
	namespaceFilter: string | null,
	tagFilters: string[],
): boolean {
	if (namespaceFilter) {
		const wantNs = namespaceFilter.toLowerCase();
		const ruleNs = (rule.namespace ?? "").toLowerCase();
		if (ruleNs !== wantNs && !ruleNs.startsWith(`${wantNs}/`)) {
			return false;
		}
	}
	if (tagFilters.length > 0) {
		const searchable = [
			rule.rule_name,
			rule.rule_key,
			rule.namespace ?? "",
			rule.description ?? "",
			...rule.authors,
			...rule.references,
			JSON.stringify(rule.attack),
			JSON.stringify(rule.mbc),
		]
			.join("\n")
			.toLowerCase();
		for (const tag of tagFilters) {
			if (!searchable.includes(tag.toLowerCase())) {
				return false;
			}
		}
	}
	return true;
}

function collectRuleObservedLocations(rule: CapabilityRuleMatchRecord): {
	matchLocations: CapabilityAddress[];
	leafLocations: CapabilityAddress[];
	allAddressableLocations: CapabilityAddress[];
} {
	const matchLocations: CapabilityAddress[] = [];
	const seenMatch = new Set<string>();
	const leafLocations: CapabilityAddress[] = [];
	const seenLeaf = new Set<string>();

	for (const m of rule.matches) {
		const addrKey = `${m.address.kind}:${m.address.display}`;
		if (!seenMatch.has(addrKey)) {
			seenMatch.add(addrKey);
			matchLocations.push(m.address);
		}
		for (const lf of m.leaf_features) {
			if (!lf.success) continue;
			for (const loc of lf.locations) {
				const lk = `${loc.kind}:${loc.display}`;
				if (!seenLeaf.has(lk)) {
					seenLeaf.add(lk);
					leafLocations.push(loc);
				}
			}
			for (const capLocs of Object.values(lf.captures)) {
				for (const loc of capLocs) {
					const lk = `${loc.kind}:${loc.display}`;
					if (!seenLeaf.has(lk)) {
						seenLeaf.add(lk);
						leafLocations.push(loc);
					}
				}
			}
		}
	}

	const allAddressableLocations: CapabilityAddress[] = [];
	const seenAll = new Set<string>();
	for (const loc of [...matchLocations, ...leafLocations]) {
		if (!loc.has_address) continue;
		const k = `${loc.kind}:${loc.display}`;
		if (!seenAll.has(k)) {
			seenAll.add(k);
			allAddressableLocations.push(loc);
		}
	}

	return { matchLocations, leafLocations, allAddressableLocations };
}
function buildEvidenceCandidatesAndNextActions(options: {
	sourceAction: "detect" | "import";
	flavor: "static" | "dynamic";
	sampleRelPath: string;
	sampleSha256: string;
	reportRelPath: string;
	reportSha256: string;
	rawReportRelPath: string;
	rawReportSha256: string;
	rules: CapabilityRuleMatchRecord[];
}): {
	evidenceCandidates: CapabilityInspectEvidenceCandidate[];
	nextActions: CapabilityRecommendedNextAction[];
	nextExperimentSuggestions: string[];
} {
	const evidenceCandidates: CapabilityInspectEvidenceCandidate[] = [];
	const nextActions: CapabilityRecommendedNextAction[] = [];
	const nextSuggestions: string[] = [];
	const historicalOnly = options.flavor === "dynamic" || options.sourceAction === "import";

	if (options.rules.length === 0) {
		evidenceCandidates.push({
			kind: "fact",
			assurance_level: "static_candidate",
			statement: redactEvidenceText(
				`Observed 0 capa capability rule matches in sample '${options.sampleRelPath}' (SHA-256 ${options.sampleSha256.slice(0, 16)}...) under the evaluated ruleset and filter scope.`,
			),
			match_locations: [],
			leaf_locations: [],
			artifact_path: options.reportRelPath,
			artifact_sha256: options.reportSha256,
			raw_report_path: options.rawReportRelPath,
			raw_report_sha256: options.rawReportSha256,
			historical_context_only: historicalOnly,
			can_satisfy_dynamic_call_gate: false,
		});
		return {
			evidenceCandidates,
			nextActions,
			nextExperimentSuggestions: nextSuggestions,
		};
	}

	for (const rule of options.rules) {
		const { matchLocations, leafLocations, allAddressableLocations } = collectRuleObservedLocations(rule);
		const matchLocText = matchLocations.length > 0 ? matchLocations.map(l => l.display).join(", ") : "no address";
		const leafLocPreview =
			leafLocations.length > 0
				? ` (leaf feature locations: ${leafLocations
						.slice(0, 5)
						.map(l => l.display)
						.join(", ")}${leafLocations.length > 5 ? ", ..." : ""})`
				: "";
		const complementsFindCrypt = CRYPTO_OR_ENCODING_RULE_PATTERN.test(
			`${rule.rule_name} ${rule.namespace ?? ""} ${rule.description ?? ""}`.toLowerCase(),
		);

		const factPrefix =
			options.flavor === "dynamic" ? "[Historical Imported Dynamic Report - Static Candidate Only] " : "";
		const factSuffix =
			options.flavor === "dynamic"
				? " Imported dynamic sandbox traces are historical context only and do not establish a verified live runtime callsite."
				: "";

		evidenceCandidates.push({
			kind: "fact",
			assurance_level: "static_candidate",
			rule_name: rule.rule_name,
			namespace: rule.namespace,
			scope: rule.primary_scope,
			statement: redactEvidenceText(
				`${factPrefix}Observed capa rule '${rule.rule_name}' (namespace: ${rule.namespace ?? "none"}, scope: ${rule.primary_scope}) matched in sample '${options.sampleRelPath}' (SHA-256 ${options.sampleSha256.slice(0, 16)}...) at [${matchLocText}]${leafLocPreview}.${factSuffix}`,
			),
			match_locations: matchLocations,
			leaf_locations: leafLocations,
			artifact_path: options.reportRelPath,
			artifact_sha256: options.reportSha256,
			raw_report_path: options.rawReportRelPath,
			raw_report_sha256: options.rawReportSha256,
			json_pointer: rule.json_pointer,
			historical_context_only: historicalOnly,
			can_satisfy_dynamic_call_gate: false,
		});

		const vaOrRvaLocs = allAddressableLocations.filter(l => l.kind === "absolute" || l.kind === "relative");
		const fileLocs = allAddressableLocations.filter(l => l.kind === "file_offset");
		const dotnetLocs = allAddressableLocations.filter(
			l => l.kind === "dotnet_token" || l.kind === "dotnet_token_offset",
		);
		const dynLocs = allAddressableLocations.filter(
			l => l.kind === "process" || l.kind === "thread" || l.kind === "call",
		);

		let verificationPlan: string;
		if (vaOrRvaLocs.length > 0) {
			const locList = vaOrRvaLocs
				.slice(0, 4)
				.map(l => l.display)
				.join(", ");
			const findCryptNote = complementsFindCrypt
				? " Cross-check with FindCrypt constant matches in the same function/module."
				: "";
			verificationPlan = `1) Decompile observed address(es) [${locList}] in '${options.sampleRelPath}' with ghidra_inspect or r2_inspect to verify control flow and data operands.${findCryptNote} 2) Place a breakpoint or runtime hook at [${locList}] using debug, frida_session, or instruction_trace under reproducible input to record a verified dynamic_call_observation.`;

			nextActions.push({
				rule_name: rule.rule_name,
				namespace: rule.namespace,
				scope: rule.primary_scope,
				tool: "ghidra_inspect",
				action_kind: "decompile",
				observed_locations: vaOrRvaLocs,
				complements_findcrypt: complementsFindCrypt,
				guidance: `Decompile observed match address(es) [${locList}] for rule '${rule.rule_name}' with ghidra_inspect or r2_inspect${complementsFindCrypt ? " (complements FindCrypt constant identification)" : ""}.`,
			});
			nextActions.push({
				rule_name: rule.rule_name,
				namespace: rule.namespace,
				scope: rule.primary_scope,
				tool: "debug",
				action_kind: "debug_or_hook",
				observed_locations: vaOrRvaLocs,
				complements_findcrypt: complementsFindCrypt,
				guidance: `Set breakpoint or attach hook at observed address(es) [${locList}] using debug, frida_session, or instruction_trace to verify live execution of '${rule.rule_name}'.`,
			});
			nextSuggestions.push(
				`Rule '${rule.rule_name}' matched at [${locList}]: decompile [${locList}] with ghidra_inspect/r2_inspect${complementsFindCrypt ? " (correlate with FindCrypt constants)" : ""} and hook/breakpoint [${locList}] with debug/frida_session to verify runtime execution.`,
			);
		} else if (dotnetLocs.length > 0) {
			const locList = dotnetLocs
				.slice(0, 4)
				.map(l => l.display)
				.join(", ");
			verificationPlan = `Inspect observed .NET metadata token(s) [${locList}] in '${options.sampleRelPath}' with dotnet_inspect, then verify runtime invocation under controlled execution.`;
			nextActions.push({
				rule_name: rule.rule_name,
				namespace: rule.namespace,
				scope: rule.primary_scope,
				tool: "dotnet_inspect",
				action_kind: "inspect_dotnet",
				observed_locations: dotnetLocs,
				complements_findcrypt: complementsFindCrypt,
				guidance: `Inspect observed .NET token(s) [${locList}] for rule '${rule.rule_name}' using dotnet_inspect.`,
			});
			nextSuggestions.push(
				`Rule '${rule.rule_name}' matched .NET token(s) [${locList}]: inspect token(s) with dotnet_inspect.`,
			);
		} else if (dynLocs.length > 0) {
			const locList = dynLocs
				.slice(0, 4)
				.map(l => l.display)
				.join(", ");
			verificationPlan = `Imported dynamic trace recorded '${rule.rule_name}' at historical [${locList}]. Reproduce execution on bound sample '${options.sampleRelPath}' inside a live managed debug or frida_session session to capture verified runtime callsite evidence.`;
			nextActions.push({
				rule_name: rule.rule_name,
				namespace: rule.namespace,
				scope: rule.primary_scope,
				tool: "debug",
				action_kind: "reproduce_live",
				observed_locations: dynLocs,
				complements_findcrypt: complementsFindCrypt,
				guidance: `Historical dynamic location(s) [${locList}] for '${rule.rule_name}' are static_candidate context only; reproduce under a live debug or frida_session session on '${options.sampleRelPath}'.`,
			});
			nextSuggestions.push(
				`Imported dynamic rule '${rule.rule_name}' at [${locList}] is historical context only; reproduce in a live debug/frida_session run to satisfy dynamic callsite verification.`,
			);
		} else {
			const locList =
				fileLocs.length > 0
					? fileLocs
							.slice(0, 4)
							.map(l => l.display)
							.join(", ")
					: "file-scope (no address)";
			verificationPlan = `Inspect file-level feature location(s) [${locList}] in '${options.sampleRelPath}' with r2_inspect or elf_inspect to locate code cross-references before dynamic tracing.`;
			nextActions.push({
				rule_name: rule.rule_name,
				namespace: rule.namespace,
				scope: rule.primary_scope,
				tool: "r2_inspect",
				action_kind: "inspect_offset",
				observed_locations: fileLocs.length > 0 ? fileLocs : matchLocations,
				complements_findcrypt: complementsFindCrypt,
				guidance: `Inspect file-scope match / offset(s) [${locList}] for rule '${rule.rule_name}' with r2_inspect or elf_inspect to identify code cross-references.`,
			});
			nextSuggestions.push(
				`File-scope rule '${rule.rule_name}' matched (${locList}): inspect cross-references in '${options.sampleRelPath}' with r2_inspect/elf_inspect.`,
			);
		}

		const claimText = redactEvidenceText(
			`Program behavior hypothesis: sample '${options.sampleRelPath}' may execute capability '${rule.rule_name}'${rule.namespace ? ` (${rule.namespace})` : ""} observed at [${matchLocText}]; static rule matching identifies candidate structure only and requires decompiler/runtime verification.`,
		);

		evidenceCandidates.push({
			kind: "hypothesis",
			assurance_level: "static_candidate",
			rule_name: rule.rule_name,
			namespace: rule.namespace,
			scope: rule.primary_scope,
			statement: claimText,
			claim: claimText,
			verification_plan: redactEvidenceText(verificationPlan),
			match_locations: matchLocations,
			leaf_locations: leafLocations,
			artifact_path: options.reportRelPath,
			artifact_sha256: options.reportSha256,
			raw_report_path: options.rawReportRelPath,
			raw_report_sha256: options.rawReportSha256,
			json_pointer: rule.json_pointer,
			historical_context_only: historicalOnly,
			can_satisfy_dynamic_call_gate: false,
		});
	}

	return {
		evidenceCandidates,
		nextActions,
		nextExperimentSuggestions: [...new Set(nextSuggestions)],
	};
}

function collectWarningsAndLimitations(options: {
	sourceAction: "detect" | "import";
	doc: WorkerNormalizedDocument;
	rulesProvenance: CapabilityRulesProvenance;
	namespaceFilter: string | null;
	tagFilters: string[];
	restrictToFunctions: string[];
	capaBackend: string;
	stderrText?: string;
}): { warnings: string[]; limitations: string[] } {
	const warnings: string[] = [];
	const limitations: string[] = [];

	if (options.stderrText) {
		for (const rawLine of options.stderrText.split(/\r?\n/)) {
			const trimmed = rawLine.trim();
			if (!trimmed) continue;
			if (/^(?:WARNING|WARN|ERROR)\b/i.test(trimmed)) {
				warnings.push(redactSecrets(trimmed));
			}
		}
	}

	const extractorLower = options.doc.meta.analysis.extractor.toLowerCase();
	if (extractorLower.includes("pefile") || options.capaBackend === "pefile") {
		limitations.push(
			"Extractor 'pefile' evaluates file-scope features only; function, basic-block, and instruction capabilities were not analyzed.",
		);
	} else if (options.doc.meta.flavor === "static" && options.doc.meta.analysis.feature_counts.functions.length === 0) {
		warnings.push(
			"Zero functions were extracted during static analysis; only file-scope capability rules could be evaluated.",
		);
	}

	if (options.restrictToFunctions.length > 0) {
		limitations.push(
			`Function scope was explicitly restricted to [${options.restrictToFunctions.join(", ")}] (--restrict-to-functions); functions outside this set were not evaluated.`,
		);
	}

	if (options.namespaceFilter || options.tagFilters.length > 0) {
		const parts: string[] = [];
		if (options.namespaceFilter) parts.push(`namespace='${options.namespaceFilter}'`);
		if (options.tagFilters.length > 0) parts.push(`tags=[${options.tagFilters.join(", ")}]`);
		limitations.push(
			`Rule evaluation was filtered by ${parts.join(" and ")}; capabilities outside the selected rule filter were not evaluated.`,
		);
	}

	if (options.rulesProvenance.source === "embedded") {
		limitations.push(
			"capa executed with built-in embedded rules bundled inside the engine executable; an independent rule directory content SHA-256 is unavailable (provenance is bound to engine binary SHA-256 + version).",
		);
	} else if (options.rulesProvenance.source === "imported_report_metadata") {
		limitations.push(
			"Offline report import did not bind a local project rules directory; rule provenance reflects the imported report metadata and engine version only.",
		);
	}

	if (options.doc.meta.flavor === "dynamic") {
		limitations.push(
			"Imported report has flavor='dynamic': treated strictly as historical context at assurance_level='static_candidate' (cannot satisfy live runtime session callsite verification gates).",
		);
	} else {
		limitations.push(
			"Static capability matches establish candidate locations (static_candidate) and do not prove runtime execution or full algorithm recovery without dynamic verification.",
		);
	}

	return {
		warnings: [...new Set(warnings)],
		limitations: [...new Set(limitations)],
	};
}

// ============================================================================
// CapabilityInspectTool 实现
// ============================================================================

export class CapabilityInspectTool implements AgentTool<typeof capabilityInspectSchema, CapabilityInspectDetails> {
	readonly name = "capability_inspect";
	readonly label = "Capability Inspect";
	readonly description: string;
	readonly parameters = capabilityInspectSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	/**
	 * 按实际动作划分审批等级：
	 * - status：只读探测（read）
	 * - import：离线校验并写入 0600 规范化实验报告（write）
	 * - detect：执行本地 capa 引擎并写入 0600 实验报告（exec）
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			if (args.action === "status") return "read";
			if (args.action === "import") return "write";
			if (args.action === "detect") return "exec";
		}
		return "exec";
	};

	readonly formatApprovalDetails = (args: unknown): string[] => {
		const lines: string[] = [];
		if (isRecord(args)) {
			lines.push(`Action: ${typeof args.action === "string" ? args.action : "(missing)"}`);
			lines.push(`Backend: ${typeof args.backend === "string" ? args.backend : "capa"}`);
			if (typeof args.sample_path === "string") lines.push(`Sample: ${args.sample_path}`);
			if (typeof args.report_path === "string") lines.push(`Report: ${args.report_path}`);
			if (typeof args.rules_path === "string") lines.push(`Rules: ${args.rules_path}`);
		}
		return lines;
	};

	constructor(
		private readonly session: ToolSession,
		private readonly options: CapabilityInspectToolOptions = {},
	) {
		this.description = prompt.render(capabilityInspectDescription);
	}

	private getProbeDeps() {
		return {
			cwd: this.session.cwd,
			settings: this.session.settings,
			timeoutMs: 20_000,
			...(this.options.env ? { env: this.options.env } : {}),
			...(this.options.which ? { which: this.options.which } : {}),
			...(this.options.agentDir ? { agentDir: this.options.agentDir } : {}),
			...(this.options.capaPath ? { capaPath: this.options.capaPath } : {}),
			...(this.options.rulesPath ? { rulesPath: this.options.rulesPath } : {}),
		};
	}

	async execute(
		_toolCallId: string,
		params: CapabilityInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<CapabilityInspectDetails>,
		_context?: AgentToolContext,
	): Promise<AgentToolResult<CapabilityInspectDetails> & { details: CapabilityInspectDetails }> {
		throwIfAborted(signal);

		if (params.backend !== undefined && params.backend !== "capa") {
			throw new ToolError(
				`Unsupported capability_inspect backend '${String(params.backend)}': only 'capa' is supported.`,
			);
		}

		if (params.action === "status") {
			return this.executeStatus();
		}

		// 计划模式只读门禁：在任何子进程执行或产物写入前拒绝 detect 与 import
		if (this.session.getPlanModeState?.()?.enabled) {
			throw new ToolError(
				`Plan mode is read-only. capability_inspect '${params.action}' writes mode-0600 artifacts${params.action === "detect" ? " and executes the local capa engine" : ""}; only 'status' is permitted in plan mode.`,
			);
		}

		switch (params.action) {
			case "detect":
				return this.executeDetect(params, signal);
			case "import":
				return this.executeImport(params, signal);
			default:
				throw new ToolError(`Unsupported capability_inspect action: '${String(params.action)}'.`);
		}
	}

	// --------------------------------------------------------------------------
	// Action: status
	// --------------------------------------------------------------------------

	private executeStatus(): AgentToolResult<CapabilityInspectDetails> & { details: CapabilityInspectDetails } {
		const capa = resolveCapa(this.getProbeDeps());
		const status = capa.available ? "ok" : "missing_dependency";
		const missingTools = capa.available ? [] : capa.engineReady ? ["capa", "capa-rules"] : ["capa"];
		const setupCommands = capa.available ? [] : ["reverse setup reverse capa --execute"];

		const lines = [
			`// Capa Capability Inspection Toolchain Status`,
			`Backend: capa`,
			`Ready: ${capa.available} (Engine Ready: ${capa.engineReady}, Rules Ready: ${capa.rulesReady})`,
			`Executable: ${capa.path ? `${capa.path} (version: ${capa.version ?? "unknown"})` : "unavailable"}`,
			`Default Rules: ${capa.rulesPath ? `${capa.rulesPath} (${capa.ruleCount} rule file(s))` : "unavailable"}`,
			...(capa.error ? [`Diagnostic: ${capa.error}`] : []),
			...(missingTools.length > 0 ? [`Missing Requirements: ${missingTools.join(", ")}`] : []),
			...(setupCommands.length > 0 ? [`Install Command: ${setupCommands.join(" && ")}`] : []),
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				backend: "capa",
				status,
				ready: capa.available,
				capa,
				missingTools,
				setupCommands,
				...(capa.error ? { error: capa.error } : {}),
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: detect
	// --------------------------------------------------------------------------

	private async executeDetect(
		params: CapabilityInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<CapabilityInspectDetails> & { details: CapabilityInspectDetails }> {
		const resolvedProjectDir = path.resolve(this.session.cwd);
		const workflowId = requireNonEmptyParam("workflow_id", params.workflow_id, "detect");
		const stepId = requireNonEmptyParam("step_id", params.step_id, "detect");
		const runId = requireNonEmptyParam("run_id", params.run_id, "detect");
		const rawSamplePath = requireNonEmptyParam("sample_path", params.sample_path, "detect");
		const limits = resolveExecutionLimits(params);

		rejectNetworkOrUriPath("sample_path", rawSamplePath);

		const inputFormat = (params.format ?? "auto").trim().toLowerCase();
		if (!STATIC_INPUT_FORMATS[inputFormat]) {
			throw new ToolError(
				`Unsupported static format '${String(params.format)}' for capability_inspect(action: "detect"). Supported static formats: auto, pe, elf, dotnet, sc32, sc64. Use action: "import" for historical dynamic reports.`,
			);
		}

		const capaBackend = (params.capa_backend ?? "auto").trim().toLowerCase();
		if (!STATIC_CAPA_BACKENDS[capaBackend]) {
			throw new ToolError(
				`Unsupported static extractor capa_backend '${String(params.capa_backend)}' for capability_inspect(action: "detect"). Supported: auto, vivisect, pefile, dotnet.`,
			);
		}

		const targetOs = (params.os ?? "auto").trim().toLowerCase();
		if (!SUPPORTED_OS_VALUES[targetOs]) {
			throw new ToolError(
				`Unsupported os '${String(params.os)}' for capability_inspect(action: "detect"). Supported: auto, linux, macos, windows.`,
			);
		}

		const namespaceFilter =
			params.namespace !== undefined ? validateFilterToken("namespace", params.namespace) : null;
		const tagFilters: string[] = [];
		if (params.tag !== undefined) {
			tagFilters.push(validateFilterToken("tag", params.tag));
		}
		if (Array.isArray(params.tags)) {
			for (const t of params.tags) {
				if (typeof t !== "string") {
					throw new ToolError("Each entry in 'tags' must be a string.");
				}
				tagFilters.push(validateFilterToken("tags", t));
			}
		}
		const restrictToFunctions = parseValidatedFunctionFilters(params.restrict_to_functions);

		// 1. 若显式指定了 rules_path，在调用 loadAnalysisExecution 前解析并提取全量 YAML 闭包，
		//    确保样本与每一个规则 YAML 文件都在执行前通过 begin inputs 绑定校验！
		let explicitRulesTarget: ResolvedExternalRulesTarget | null = null;
		if (params.rules_path !== undefined && params.rules_path.trim().length > 0) {
			if (params.use_embedded_rules === true) {
				throw new ToolError(
					"Parameters 'rules_path' and 'use_embedded_rules: true' are mutually exclusive in capability_inspect(action: \"detect\").",
				);
			}
			explicitRulesTarget = await resolveAndHashProjectRulesPath(resolvedProjectDir, params.rules_path);
		}

		const sampleAbsCandidate = path.resolve(resolvedProjectDir, rawSamplePath.trim());
		await assertNoSymlinkSegmentsWithinRoot(resolvedProjectDir, sampleAbsCandidate, `sample_path '${rawSamplePath}'`);

		const boundInputPaths = [
			rawSamplePath,
			...(explicitRulesTarget ? explicitRulesTarget.projectRelativeRuleFiles : []),
		];

		// 2. 通过 loadAnalysisExecution 一次性校验活跃 run 状态及样本 + 显式规则闭包输入绑定（在进程启动前拒绝漂移或未登记输入）
		const execution = await loadAnalysisExecution({
			projectDir: resolvedProjectDir,
			workspaceDir: params.workspace_path,
			workflowId,
			stepId,
			runId,
			inputPaths: boundInputPaths,
		});

		const safeSample = await assertRealPathWithin(resolvedProjectDir, sampleAbsCandidate, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});
		const sampleStat = await fs.lstat(safeSample.resolvedPath);
		if (sampleStat.isSymbolicLink() || !sampleStat.isFile()) {
			throw new ToolError(`Invalid sample_path '${rawSamplePath}': must be a regular non-symlink file.`);
		}
		if (sampleStat.size > limits.maxSampleBytes) {
			throw new ToolError(
				`Sample '${safeSample.relativePath}' size (${sampleStat.size} bytes) exceeds max_sample_bytes (${limits.maxSampleBytes} bytes).`,
			);
		}

		const recordedSampleRef = execution.inputRefs.find(r => r.path === safeSample.relativePath);
		let sampleSha256 = recordedSampleRef?.sha256;
		if (!sampleSha256) {
			const fallbackHash = await hashFile(safeSample.resolvedPath);
			if (!fallbackHash) {
				throw new ToolError(`Failed to compute SHA-256 for sample '${safeSample.relativePath}'.`);
			}
			sampleSha256 = fallbackHash.sha256;
		}
		const sampleSizeBytes = recordedSampleRef?.size_bytes ?? sampleStat.size;
		// 3. 校验输出路径合法且不覆盖已有文件（在启动 capa 进程前完成预检）
		const sampleStem =
			path
				.basename(safeSample.relativePath)
				.replace(/[^A-Za-z0-9_-]+/g, "_")
				.replace(/^_+|_+$/g, "") || "sample";

		const reportTarget = await ensureExclusiveRunOutputPath({
			projectDir: resolvedProjectDir,
			runDir: execution.paths.run_dir,
			explicitOutputPath: params.output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `capa_detect_${sampleStem}`,
			defaultExtension: ".report.json",
		});

		const rawReportTarget = await ensureExclusiveRunOutputPath({
			projectDir: resolvedProjectDir,
			runDir: execution.paths.run_dir,
			explicitOutputPath: params.raw_output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `capa_raw_${sampleStem}`,
			defaultExtension: ".json",
		});

		if (reportTarget.resolvedPath === rawReportTarget.resolvedPath) {
			throw new ToolError("Parameters 'output_path' and 'raw_output_path' must resolve to distinct paths.");
		}

		// 4. 探测本地 capa 引擎与规则来源
		const probeDeps = this.getProbeDeps();
		const capaProbe = resolveCapa({
			...probeDeps,
			...(explicitRulesTarget?.rulesKind === "directory" ? { rulesPath: explicitRulesTarget.resolvedPath } : {}),
		});
		const useEmbedded = params.use_embedded_rules === true;
		if (!capaProbe.engineReady || !capaProbe.path || !capaProbe.version) {
			const missingTools = ["capa"];
			const setupCommands = ["reverse setup reverse capa --execute"];
			const errMsg = capaProbe.error ?? "capa executable is not available.";
			return {
				content: [
					{
						type: "text",
						text: `[Missing Dependency] ${errMsg}\nInstall command: ${setupCommands.join(" && ")}`,
					},
				],
				details: {
					action: "detect",
					backend: "capa",
					status: "missing_dependency",
					workflowId,
					stepId,
					runId,
					capa: capaProbe,
					missingTools,
					setupCommands,
					error: errMsg,
				},
			};
		}

		let externalRulesTarget: ResolvedExternalRulesTarget | null = explicitRulesTarget;
		let beforeEngineHash: { sha256: string; size: number } | null = null;

		if (!externalRulesTarget && !useEmbedded) {
			if (!capaProbe.rulesReady || !capaProbe.rulesPath) {
				const missingTools = ["capa", "capa-rules"];
				const setupCommands = ["reverse setup reverse capa --execute"];
				const errMsg =
					capaProbe.error ??
					"capa rules directory is not configured or valid. Run 'reverse setup reverse capa --execute' or pass an explicit project-local 'rules_path'.";
				return {
					content: [
						{
							type: "text",
							text: `[Missing Dependency] ${errMsg}\nInstall command: ${setupCommands.join(" && ")}`,
						},
					],
					details: {
						action: "detect",
						backend: "capa",
						status: "missing_dependency",
						workflowId,
						stepId,
						runId,
						capa: capaProbe,
						missingTools,
						setupCommands,
						error: errMsg,
					},
				};
			}

			// 若默认规则路径位于当前项目内，强制要求其全量 YAML 闭包在 begin inputs 中声明并绑定
			const resolvedDefaultRules = path.resolve(capaProbe.rulesPath);
			const relToProject = path.relative(resolvedProjectDir, resolvedDefaultRules);
			const isInsideProject =
				relToProject !== "" && !relToProject.startsWith("..") && !path.isAbsolute(relToProject);
			if (isInsideProject) {
				externalRulesTarget = await resolveAndHashProjectRulesPath(resolvedProjectDir, relToProject);
				await loadAnalysisExecution({
					projectDir: resolvedProjectDir,
					workspaceDir: params.workspace_path,
					workflowId,
					stepId,
					runId,
					inputPaths: [rawSamplePath, ...externalRulesTarget.projectRelativeRuleFiles],
				});
			} else {
				// 非项目内路径仅允许受管工具链分发目录（<agentDir>/tools/capa/rules），
				// 严禁通过 CAPA_RULES_PATH / CAPA_RULES_DIR 将任意未绑定外部目录伪装为受管资产！
				const effectiveEnv = (this.options.env ?? (process.env as Record<string, string | undefined>)) as Record<
					string,
					string | undefined
				>;
				const effectiveAgentDir = path.resolve(
					this.options.agentDir ?? effectiveEnv.REVERSE_CODING_AGENT_DIR ?? getAgentDir(),
				);
				const managedRulesDir = path.resolve(effectiveAgentDir, "tools", "capa", "rules");
				let realDefaultRules: string;
				let realManagedRules: string;
				try {
					realDefaultRules = await fs.realpath(resolvedDefaultRules);
					realManagedRules = await fs.realpath(managedRulesDir);
				} catch {
					throw new ToolError(
						`External capa rules path '${capaProbe.rulesPath}' is outside the project directory '${resolvedProjectDir}' and is not a valid managed toolchain rules distribution ('${managedRulesDir}'). Place custom rules inside the project and bind them in 'begin' inputs via 'rules_path', or set 'use_embedded_rules: true'.`,
					);
				}
				if (realDefaultRules !== realManagedRules) {
					throw new ToolError(
						`Unbound external capa rules path '${capaProbe.rulesPath}' (via CAPA_RULES_PATH/CAPA_RULES_DIR or options) is outside the project directory '${resolvedProjectDir}' and is not the managed toolchain distribution ('${managedRulesDir}'). Place custom rules inside the project and bind them in 'begin' inputs via 'rules_path', or set 'use_embedded_rules: true'.`,
					);
				}

				const managedManifest = computeCapaRulesManifest(capaProbe.rulesPath, {
					maxFileBytes: MAX_RULE_FILE_BYTES,
					maxTotalBytes: MAX_RULE_TOTAL_BYTES,
				});
				if (!managedManifest) {
					throw new ToolError(
						`Managed capa rules directory '${capaProbe.rulesPath}' failed strict YAML closure manifest verification prior to execution.`,
					);
				}
				externalRulesTarget = {
					source: "managed_distribution_manifest",
					rulesKind: "managed_distribution",
					resolvedPath: managedManifest.rulesPath,
					displayPath: managedManifest.rulesPath,
					boundInBeginInputs: false,
					projectRelativeRuleFiles: [],
					manifest: managedManifest,
				};
			}
		}

		if (useEmbedded) {
			beforeEngineHash = await hashFile(capaProbe.path);
		}

		// 5. 组装固定 argv（绝不拼接 shell 命令，绝不自动联网或下载）
		const argv: string[] = ["-j", "-f", inputFormat, "-b", capaBackend, "--os", targetOs];
		if (restrictToFunctions.length > 0) {
			argv.push("--restrict-to-functions", restrictToFunctions.join(","));
		}
		if (externalRulesTarget) {
			argv.push("-r", externalRulesTarget.resolvedPath);
		}
		const primaryCliTag = tagFilters[0] ?? namespaceFilter;
		if (primaryCliTag) {
			argv.push("-t", primaryCliTag);
		}
		argv.push(safeSample.resolvedPath);

		const recordedArgv = [capaProbe.path, ...argv].map(a => redactSecrets(a));
		const engineVersion = `capa ${capaProbe.version}`;

		const baseEnvSource = (this.options.env ?? (process.env as Record<string, string | undefined>)) as Record<
			string,
			string | undefined
		>;
		const cleanEnv = {
			...filterEnv(baseEnvSource),
			PYTHONNOUSERSITE: "1",
			NO_COLOR: "1",
		};

		// 6. 执行受界 capa 子进程
		const execRes = await runBoundedCapaProcess({
			capaBin: capaProbe.path,
			argv,
			cwd: resolvedProjectDir,
			env: cleanEnv,
			timeoutMs: limits.timeoutMs,
			maxOutputBytes: limits.maxOutputBytes,
			signal,
		});

		throwIfAborted(signal);

		if (this.options.onBeforePostExecutionRulesCheck) {
			await this.options.onBeforePostExecutionRulesCheck();
		}

		// 7. 执行后复核规则 manifest 或内嵌规则引擎二进制哈希未发生漂移
		let rulesProvenance: CapabilityRulesProvenance;
		if (externalRulesTarget) {
			const afterManifest = await recomputeExternalRulesManifest(externalRulesTarget);
			if (
				!afterManifest ||
				afterManifest.manifestSha256 !== externalRulesTarget.manifest.manifestSha256 ||
				afterManifest.ruleCount !== externalRulesTarget.manifest.ruleCount
			) {
				throw new ToolError(
					`Capa rules integrity check failed after execution: rules manifest SHA-256 for '${externalRulesTarget.displayPath}' changed from '${externalRulesTarget.manifest.manifestSha256}' to '${afterManifest?.manifestSha256 ?? "invalid"}' during execution.`,
				);
			}
			rulesProvenance = {
				source: externalRulesTarget.source,
				rules_kind: externalRulesTarget.rulesKind,
				rules_path: externalRulesTarget.displayPath,
				rule_count: externalRulesTarget.manifest.ruleCount,
				manifest_sha256: externalRulesTarget.manifest.manifestSha256,
				independent_content_hash_available: true,
				verified_unchanged_after_execution: true,
				bound_in_begin_inputs: externalRulesTarget.boundInBeginInputs,
				files: externalRulesTarget.manifest.files,
			};
		} else {
			const afterEngineHash = await hashFile(capaProbe.path);
			if (
				!beforeEngineHash ||
				!afterEngineHash ||
				afterEngineHash.sha256 !== beforeEngineHash.sha256 ||
				afterEngineHash.size !== beforeEngineHash.size
			) {
				throw new ToolError(
					`Capa engine binary integrity check failed after embedded-rules execution: '${capaProbe.path}' SHA-256 changed during execution.`,
				);
			}
			rulesProvenance = {
				source: "embedded",
				rules_kind: "embedded_in_engine",
				rules_path: null,
				rule_count: null,
				manifest_sha256: null,
				independent_content_hash_available: false,
				independent_hash_unavailable_reason:
					"capa executed with built-in embedded rules bundled inside the engine executable; an independent rule set content hash is unavailable. Provenance is bound to the capa engine distribution binary SHA-256 and version.",
				engine_binary_path: capaProbe.path,
				engine_binary_sha256: beforeEngineHash.sha256,
				engine_binary_size_bytes: beforeEngineHash.size,
				engine_version: capaProbe.version,
				verified_unchanged_after_execution: true,
				bound_in_begin_inputs: false,
			};
		}

		// 8. 处理超时、输出越界或非零退出码：保留 0600 失败诊断报告，绝不返回空匹配伪成功
		if (
			execRes.timedOut ||
			execRes.outputOverflowed ||
			execRes.exitCode !== 0 ||
			execRes.stdoutBytes.byteLength === 0
		) {
			const rawHash = execRes.stdoutBytes.byteLength > 0 ? hashBuffer(execRes.stdoutBytes).sha256 : null;
			const diagReason = execRes.timedOut
				? `capa timed out after ${limits.timeoutMs}ms on '${safeSample.relativePath}'`
				: execRes.outputOverflowed
					? `capa JSON output on '${safeSample.relativePath}' exceeded max_output_bytes (${limits.maxOutputBytes} bytes)`
					: `capa failed on '${safeSample.relativePath}' (exit ${String(execRes.exitCode)}): ${redactSecrets(execRes.stderr.trim() || execRes.stdoutBytes.toString("utf8", 0, 512).trim() || "non-zero exit status")}`;

			const failureReport: CapabilityInspectFailureReportV1 = {
				schema_version: "1",
				report_kind: "capability_inspect_failure",
				backend: "capa",
				source_action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				created_at: new Date().toISOString(),
				sample_path: safeSample.relativePath,
				sample_sha256: sampleSha256,
				engine_version: engineVersion,
				rules_provenance: rulesProvenance,
				argv: recordedArgv,
				exit_code: execRes.exitCode,
				timed_out: execRes.timedOut,
				output_overflowed: execRes.outputOverflowed,
				raw_output_sha256: rawHash,
				raw_output_size_bytes: execRes.stdoutBytes.byteLength,
				stdout_preview: redactSecrets(execRes.stdoutBytes.toString("utf8", 0, 4096)),
				stderr: redactSecrets(execRes.stderr),
				error: diagReason,
			};

			const writtenFail = await writePrivateRunArtifactFile(
				reportTarget.resolvedPath,
				deterministicJsonStringify(failureReport),
			);

			return {
				content: [
					{
						type: "text",
						text: [
							`[Capa Detect Failed] ${diagReason}`,
							`Workflow / Step / Run: ${workflowId} / ${stepId} / ${runId}`,
							`Sample: ${safeSample.relativePath} (sha256: ${sampleSha256.slice(0, 16)}...)`,
							`Diagnostic Failure Report (mode 0600): ${reportTarget.relativePath}`,
						].join("\n"),
					},
				],
				details: {
					action: "detect",
					backend: "capa",
					status: "error",
					workflowId,
					stepId,
					runId,
					runDir: execution.paths.relative.run_dir,
					samplePath: safeSample.relativePath,
					sampleSha256,
					reportPath: reportTarget.resolvedPath,
					reportRelativePath: reportTarget.relativePath,
					reportSha256: writtenFail.sha256,
					outputPaths: [reportTarget.resolvedPath],
					relativeOutputPaths: [reportTarget.relativePath],
					rulesProvenance,
					failureReport,
					argv: recordedArgv,
					exitCode: execRes.exitCode,
					engineVersion,
					error: diagReason,
				},
			};
		}

		// 9. 先将原始 capa JSON 落盘（mode 0600），再通过 Python 无损整数桥接解析与校验
		const writtenRaw = await writePrivateRunArtifactFile(rawReportTarget.resolvedPath, execRes.stdoutBytes);

		const bridgeRes = await parseCapaJsonViaLosslessPythonBridge({
			cwd: resolvedProjectDir,
			jsonPath: rawReportTarget.resolvedPath,
			maxOutputBytes: limits.maxOutputBytes,
			timeoutMs: limits.timeoutMs,
			pythonPath: this.options.pythonPath,
			signal,
		});

		if (!bridgeRes.ok || !bridgeRes.document) {
			const schemaErr = `capa emitted invalid or unsupported JSON output on '${safeSample.relativePath}' (${bridgeRes.error_code ?? "schema_error"}): ${bridgeRes.error ?? "malformed JSON"}`;
			const failureReport: CapabilityInspectFailureReportV1 = {
				schema_version: "1",
				report_kind: "capability_inspect_failure",
				backend: "capa",
				source_action: "detect",
				workflow_id: workflowId,
				step_id: stepId,
				run_id: runId,
				created_at: new Date().toISOString(),
				sample_path: safeSample.relativePath,
				sample_sha256: sampleSha256,
				engine_version: engineVersion,
				rules_provenance: rulesProvenance,
				argv: recordedArgv,
				exit_code: execRes.exitCode,
				timed_out: false,
				output_overflowed: false,
				raw_output_sha256: writtenRaw.sha256,
				raw_output_size_bytes: writtenRaw.size_bytes,
				stdout_preview: redactSecrets(execRes.stdoutBytes.toString("utf8", 0, 4096)),
				stderr: redactSecrets(execRes.stderr),
				error: schemaErr,
			};
			const writtenFail = await writePrivateRunArtifactFile(
				reportTarget.resolvedPath,
				deterministicJsonStringify(failureReport),
			);
			return {
				content: [
					{
						type: "text",
						text: [
							`[Capa Detect Invalid Output] ${schemaErr}`,
							`Diagnostic Failure Report (mode 0600): ${reportTarget.relativePath}`,
							`Retained Raw Output (mode 0600): ${rawReportTarget.relativePath}`,
						].join("\n"),
					},
				],
				details: {
					action: "detect",
					backend: "capa",
					status: "error",
					workflowId,
					stepId,
					runId,
					runDir: execution.paths.relative.run_dir,
					samplePath: safeSample.relativePath,
					sampleSha256,
					rawReportPath: rawReportTarget.resolvedPath,
					rawReportRelativePath: rawReportTarget.relativePath,
					rawReportSha256: writtenRaw.sha256,
					reportPath: reportTarget.resolvedPath,
					reportRelativePath: reportTarget.relativePath,
					reportSha256: writtenFail.sha256,
					outputPaths: [reportTarget.resolvedPath, rawReportTarget.resolvedPath],
					relativeOutputPaths: [reportTarget.relativePath, rawReportTarget.relativePath],
					rulesProvenance,
					failureReport,
					argv: recordedArgv,
					exitCode: execRes.exitCode,
					engineVersion,
					error: schemaErr,
				},
			};
		}

		const doc = bridgeRes.document;
		if (doc.meta.sample.sha256.toLowerCase() !== sampleSha256.toLowerCase()) {
			throw new ToolError(
				`Sample SHA-256 mismatch in capability_inspect(action: "detect"): capa JSON output reported '${doc.meta.sample.sha256}', expected bound sample SHA-256 '${sampleSha256}'.`,
			);
		}

		const filteredRules = doc.rules.filter(r => ruleMatchesRequestedFilters(r, namespaceFilter, tagFilters));

		const { warnings, limitations } = collectWarningsAndLimitations({
			sourceAction: "detect",
			doc,
			rulesProvenance,
			namespaceFilter,
			tagFilters,
			restrictToFunctions,
			capaBackend,
			stderrText: execRes.stderr,
		});

		const baseReportWithoutCandidates: Omit<
			CapabilityInspectReportV1,
			"evidence_candidates" | "next_actions" | "next_experiment_suggestions"
		> = {
			schema_version: "1",
			report_kind: "capability_inspect",
			backend: "capa",
			source_action: "detect",
			workflow_id: workflowId,
			step_id: stepId,
			run_id: runId,
			created_at: new Date().toISOString(),
			engine_version: `capa ${doc.meta.version}`,
			analysis_flavor: doc.meta.flavor,
			historical_dynamic_import: false,
			assurance_level: "static_candidate",
			sample: {
				path: safeSample.relativePath,
				sha256: sampleSha256,
				size_bytes: sampleSizeBytes,
				md5: doc.meta.sample.md5,
				sha1: doc.meta.sample.sha1,
				reported_path: doc.meta.sample.reported_path,
			},
			raw_report: {
				path: rawReportTarget.relativePath,
				sha256: writtenRaw.sha256,
				size_bytes: writtenRaw.size_bytes,
			},
			analysis: {
				format: doc.meta.analysis.format,
				arch: doc.meta.analysis.arch,
				os: doc.meta.analysis.os,
				extractor: doc.meta.analysis.extractor,
				base_address: doc.meta.analysis.base_address,
				feature_counts: doc.meta.analysis.feature_counts,
				library_functions_count: doc.meta.analysis.library_functions_count,
			},
			filters: {
				namespace: namespaceFilter,
				tags: tagFilters,
				restrict_to_functions: restrictToFunctions,
				format: inputFormat,
				capa_backend: capaBackend,
				os: targetOs,
			},
			rules_provenance: rulesProvenance,
			matched_rule_count: filteredRules.length,
			rules: filteredRules,
			warnings,
			limitations,
		};

		// 先计算包含完整 candidates 的确定性报告，再将最终 report SHA-256 同步回返回值
		const builtCandidates = buildEvidenceCandidatesAndNextActions({
			sourceAction: "detect",
			flavor: doc.meta.flavor,
			sampleRelPath: safeSample.relativePath,
			sampleSha256,
			reportRelPath: reportTarget.relativePath,
			reportSha256: writtenRaw.sha256,
			rawReportRelPath: rawReportTarget.relativePath,
			rawReportSha256: writtenRaw.sha256,
			rules: filteredRules,
		});

		const fullReport: CapabilityInspectReportV1 = {
			...baseReportWithoutCandidates,
			evidence_candidates: builtCandidates.evidenceCandidates,
			next_actions: builtCandidates.nextActions,
			next_experiment_suggestions: builtCandidates.nextExperimentSuggestions,
		};

		const writtenReport = await writePrivateRunArtifactFile(
			reportTarget.resolvedPath,
			deterministicJsonStringify(fullReport),
		);

		const finalCandidates = builtCandidates.evidenceCandidates.map(c => ({
			...c,
			artifact_sha256: writtenReport.sha256,
		}));
		const outputPaths = [reportTarget.resolvedPath, rawReportTarget.resolvedPath];
		const relativeOutputPaths = [reportTarget.relativePath, rawReportTarget.relativePath];

		const lines = [
			`// Capa Capability Detection Complete (${filteredRules.length} rule(s) matched)`,
			`Workflow / Step / Run: ${workflowId} / ${stepId} / ${runId}`,
			`Sample: ${safeSample.relativePath} (${sampleSizeBytes} bytes, sha256: ${sampleSha256.slice(0, 16)}...)`,
			`Engine & Extractor: capa ${doc.meta.version} | flavor=${doc.meta.flavor} | format=${doc.meta.analysis.format} | arch=${doc.meta.analysis.arch} | os=${doc.meta.analysis.os} | extractor=${doc.meta.analysis.extractor}`,
			`Rules Provenance: source=${rulesProvenance.source}${rulesProvenance.manifest_sha256 ? `, manifest_sha256=${rulesProvenance.manifest_sha256.slice(0, 16)}..., count=${String(rulesProvenance.rule_count)}` : `, engine_sha256=${rulesProvenance.engine_binary_sha256?.slice(0, 16) ?? "n/a"}... (independent_content_hash_available=false)`}`,
			...filteredRules.slice(0, 15).map(r => {
				const locs = r.matches.map(m => m.address.display).join(", ");
				return `  • ${r.rule_name} [${r.namespace ?? "no-namespace"}] (scope=${r.primary_scope}, matches=${r.match_count} @ ${locs}, ptr=${r.json_pointer})`;
			}),
			...(filteredRules.length > 15 ? [`  … ${filteredRules.length - 15} more matched rule(s) in report JSON`] : []),
			...(warnings.length > 0 ? [`Warnings: ${warnings.join(" | ")}`] : []),
			...(limitations.length > 0 ? [`Limitations: ${limitations.join(" | ")}`] : []),
			`Normalized Report (mode 0600): ${reportTarget.relativePath} (sha256: ${writtenReport.sha256.slice(0, 16)}...)`,
			`Retained Raw Capa JSON (mode 0600): ${rawReportTarget.relativePath} (sha256: ${writtenRaw.sha256.slice(0, 16)}...)`,
			`Record Hint: Pass output_paths: ${JSON.stringify(relativeOutputPaths)} when calling reverse_workspace(action: "record").`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "detect",
				backend: "capa",
				status: "ok",
				workflowId,
				stepId,
				runId,
				runDir: execution.paths.relative.run_dir,
				samplePath: safeSample.relativePath,
				sampleSha256,
				rawReportPath: rawReportTarget.resolvedPath,
				rawReportRelativePath: rawReportTarget.relativePath,
				rawReportSha256: writtenRaw.sha256,
				reportPath: reportTarget.resolvedPath,
				reportRelativePath: reportTarget.relativePath,
				reportSha256: writtenReport.sha256,
				outputPaths,
				relativeOutputPaths,
				rulesProvenance,
				report: fullReport,
				argv: recordedArgv,
				exitCode: 0,
				engineVersion: `capa ${doc.meta.version}`,
				assuranceLevel: "static_candidate",
				evidenceCandidates: finalCandidates,
				nextActions: builtCandidates.nextActions,
				nextExperimentSuggestions: builtCandidates.nextExperimentSuggestions,
				warnings,
				limitations,
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: import (Offline — does NOT require capa executable)
	// --------------------------------------------------------------------------

	private async executeImport(
		params: CapabilityInspectParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<CapabilityInspectDetails> & { details: CapabilityInspectDetails }> {
		const resolvedProjectDir = path.resolve(this.session.cwd);
		const workflowId = requireNonEmptyParam("workflow_id", params.workflow_id, "import");
		const stepId = requireNonEmptyParam("step_id", params.step_id, "import");
		const runId = requireNonEmptyParam("run_id", params.run_id, "import");
		const rawReportPath = requireNonEmptyParam("report_path", params.report_path, "import");
		const limits = resolveExecutionLimits(params);

		rejectNetworkOrUriPath("report_path", rawReportPath);
		const reportAbsCandidate = path.resolve(resolvedProjectDir, rawReportPath.trim());
		await assertNoSymlinkSegmentsWithinRoot(resolvedProjectDir, reportAbsCandidate, `report_path '${rawReportPath}'`);

		let explicitSampleSafe: SafeResolvedPath | null = null;
		if (params.sample_path !== undefined && params.sample_path.trim().length > 0) {
			rejectNetworkOrUriPath("sample_path", params.sample_path);
			const sampleAbsCandidate = path.resolve(resolvedProjectDir, params.sample_path.trim());
			await assertNoSymlinkSegmentsWithinRoot(
				resolvedProjectDir,
				sampleAbsCandidate,
				`sample_path '${params.sample_path}'`,
			);
			explicitSampleSafe = await assertRealPathWithin(resolvedProjectDir, sampleAbsCandidate, {
				baseDir: resolvedProjectDir,
				requireRegularFile: true,
			});
		}

		let explicitRulesTarget: ResolvedExternalRulesTarget | null = null;
		if (params.rules_path !== undefined && params.rules_path.trim().length > 0) {
			explicitRulesTarget = await resolveAndHashProjectRulesPath(resolvedProjectDir, params.rules_path);
		}

		const boundInputPaths = [
			rawReportPath,
			...(params.sample_path?.trim() ? [params.sample_path.trim()] : []),
			...(explicitRulesTarget ? explicitRulesTarget.projectRelativeRuleFiles : []),
		];

		// 1. 绑定并校验活跃实验 run 及输入文件哈希（report_path、可选 sample_path、可选 rules_path 闭包）
		const execution = await loadAnalysisExecution({
			projectDir: resolvedProjectDir,
			workspaceDir: params.workspace_path,
			workflowId,
			stepId,
			runId,
			inputPaths: boundInputPaths,
		});

		const safeReportInput = await assertRealPathWithin(resolvedProjectDir, reportAbsCandidate, {
			baseDir: resolvedProjectDir,
			requireRegularFile: true,
		});

		// 读取并校验原始 JSON 大小与非软链属性
		const rawReportBytes = await readRegularFileBoundedNoFollow(
			safeReportInput.resolvedPath,
			limits.maxOutputBytes,
			"report_path",
		);
		const rawReportHash = hashBuffer(rawReportBytes);

		const boundSamplePath = explicitSampleSafe
			? explicitSampleSafe.relativePath
			: (execution.run.inputs[0]?.path ?? "target");
		const boundSampleRef =
			execution.inputRefs.find(r => r.path === boundSamplePath) ??
			execution.run.inputs.find(r => r.path === boundSamplePath);
		const boundSampleSha256 = boundSampleRef?.sha256 ?? execution.run.target_sha256;
		const boundSampleSizeBytes = boundSampleRef?.size_bytes ?? 0;

		if (explicitSampleSafe && boundSampleSizeBytes > limits.maxSampleBytes) {
			throw new ToolError(
				`Sample '${boundSamplePath}' size (${boundSampleSizeBytes} bytes) exceeds max_sample_bytes (${limits.maxSampleBytes} bytes).`,
			);
		}

		// 2. 通过无损 Python 桥接解析并严格校验 capa JSON 结构与版本
		const bridgeRes = await parseCapaJsonViaLosslessPythonBridge({
			cwd: resolvedProjectDir,
			jsonPath: safeReportInput.resolvedPath,
			maxOutputBytes: limits.maxOutputBytes,
			timeoutMs: limits.timeoutMs,
			pythonPath: this.options.pythonPath,
			signal,
		});

		if (!bridgeRes.ok || !bridgeRes.document) {
			throw new ToolError(
				`Failed to import capa JSON report '${safeReportInput.relativePath}' (${bridgeRes.error_code ?? "schema_error"}): ${bridgeRes.error ?? "malformed or unsupported capa JSON report"}${bridgeRes.json_pointer ? ` at '${bridgeRes.json_pointer}'` : ""}`,
			);
		}

		const doc = bridgeRes.document;

		// 3. 强制校对报告中的 /meta/sample/sha256 与当前绑定样本 SHA-256 一致
		if (doc.meta.sample.sha256.toLowerCase() !== boundSampleSha256.toLowerCase()) {
			throw new ToolError(
				`Sample SHA-256 mismatch in capability_inspect(action: "import"): raw capa report '${safeReportInput.relativePath}' declares sample SHA-256 '${doc.meta.sample.sha256}', which does not match bound sample '${boundSamplePath}' SHA-256 '${boundSampleSha256}'.`,
			);
		}

		const namespaceFilter =
			params.namespace !== undefined ? validateFilterToken("namespace", params.namespace) : null;
		const tagFilters: string[] = [];
		if (params.tag !== undefined) {
			tagFilters.push(validateFilterToken("tag", params.tag));
		}
		if (Array.isArray(params.tags)) {
			for (const t of params.tags) {
				if (typeof t !== "string") {
					throw new ToolError("Each entry in 'tags' must be a string.");
				}
				tagFilters.push(validateFilterToken("tags", t));
			}
		}

		const filteredRules = doc.rules.filter(r => ruleMatchesRequestedFilters(r, namespaceFilter, tagFilters));

		const reportStem =
			path
				.basename(safeReportInput.relativePath, path.extname(safeReportInput.relativePath))
				.replace(/[^A-Za-z0-9_-]+/g, "_")
				.replace(/^_+|_+$/g, "") || "imported";

		const reportTarget = await ensureExclusiveRunOutputPath({
			projectDir: resolvedProjectDir,
			runDir: execution.paths.run_dir,
			explicitOutputPath: params.output_path,
			defaultSubdir: "reports",
			defaultFilenamePrefix: `capa_import_${reportStem}`,
			defaultExtension: ".report.json",
		});

		// 若输入报告不在当前 run 目录内，则在当前 run/reports/ 下保留一份 0600 原始报告副本；若已在当前 run 内则可按需写入或引用
		const relInputToRun = path.relative(execution.paths.run_dir, safeReportInput.resolvedPath);
		const isInputAlreadyInRun =
			relInputToRun !== "" && !relInputToRun.startsWith("..") && !path.isAbsolute(relInputToRun);

		let retainedRawRelPath = safeReportInput.relativePath;
		let retainedRawAbsPath = safeReportInput.resolvedPath;
		const outputPaths: string[] = [reportTarget.resolvedPath];
		const relativeOutputPaths: string[] = [reportTarget.relativePath];

		if (!isInputAlreadyInRun || params.raw_output_path !== undefined) {
			const rawCopyTarget = await ensureExclusiveRunOutputPath({
				projectDir: resolvedProjectDir,
				runDir: execution.paths.run_dir,
				explicitOutputPath: params.raw_output_path,
				defaultSubdir: "reports",
				defaultFilenamePrefix: `capa_raw_import_${reportStem}`,
				defaultExtension: ".json",
			});
			if (rawCopyTarget.resolvedPath === reportTarget.resolvedPath) {
				throw new ToolError("Parameters 'output_path' and 'raw_output_path' must resolve to distinct paths.");
			}
			await writePrivateRunArtifactFile(rawCopyTarget.resolvedPath, rawReportBytes);
			retainedRawRelPath = rawCopyTarget.relativePath;
			retainedRawAbsPath = rawCopyTarget.resolvedPath;
			outputPaths.push(rawCopyTarget.resolvedPath);
			relativeOutputPaths.push(rawCopyTarget.relativePath);
		}

		const rulesProvenance: CapabilityRulesProvenance = explicitRulesTarget
			? {
					source: "external_manifest",
					rules_kind: explicitRulesTarget.rulesKind,
					rules_path: explicitRulesTarget.displayPath,
					rule_count: explicitRulesTarget.manifest.ruleCount,
					manifest_sha256: explicitRulesTarget.manifest.manifestSha256,
					independent_content_hash_available: true,
					verified_unchanged_after_execution: true,
					bound_in_begin_inputs: true,
					reported_rules: doc.meta.analysis.reported_rules,
					files: explicitRulesTarget.manifest.files,
				}
			: {
					source: "imported_report_metadata",
					rules_kind: "imported_unverified",
					rules_path: null,
					rule_count: null,
					manifest_sha256: null,
					independent_content_hash_available: false,
					independent_hash_unavailable_reason:
						"Capa report was imported offline without binding an external local rule directory manifest; rule provenance is limited to the imported report's '/meta/analysis/rules' and '/meta/version'.",
					engine_version: doc.meta.version,
					verified_unchanged_after_execution: false,
					bound_in_begin_inputs: false,
					reported_rules: doc.meta.analysis.reported_rules,
				};

		const { warnings, limitations } = collectWarningsAndLimitations({
			sourceAction: "import",
			doc,
			rulesProvenance,
			namespaceFilter,
			tagFilters,
			restrictToFunctions: [],
			capaBackend: "auto",
		});

		const builtCandidates = buildEvidenceCandidatesAndNextActions({
			sourceAction: "import",
			flavor: doc.meta.flavor,
			sampleRelPath: boundSamplePath,
			sampleSha256: boundSampleSha256,
			reportRelPath: reportTarget.relativePath,
			reportSha256: rawReportHash.sha256,
			rawReportRelPath: retainedRawRelPath,
			rawReportSha256: rawReportHash.sha256,
			rules: filteredRules,
		});

		const fullReport: CapabilityInspectReportV1 = {
			schema_version: "1",
			report_kind: "capability_inspect",
			backend: "capa",
			source_action: "import",
			workflow_id: workflowId,
			step_id: stepId,
			run_id: runId,
			created_at: new Date().toISOString(),
			engine_version: `capa ${doc.meta.version}`,
			analysis_flavor: doc.meta.flavor,
			historical_dynamic_import: doc.meta.flavor === "dynamic",
			assurance_level: "static_candidate",
			sample: {
				path: boundSamplePath,
				sha256: boundSampleSha256,
				size_bytes: boundSampleSizeBytes,
				md5: doc.meta.sample.md5,
				sha1: doc.meta.sample.sha1,
				reported_path: doc.meta.sample.reported_path,
			},
			raw_report: {
				path: retainedRawRelPath,
				sha256: rawReportHash.sha256,
				size_bytes: rawReportHash.size,
			},
			analysis: {
				format: doc.meta.analysis.format,
				arch: doc.meta.analysis.arch,
				os: doc.meta.analysis.os,
				extractor: doc.meta.analysis.extractor,
				base_address: doc.meta.analysis.base_address,
				feature_counts: doc.meta.analysis.feature_counts,
				library_functions_count: doc.meta.analysis.library_functions_count,
			},
			filters: {
				namespace: namespaceFilter,
				tags: tagFilters,
				restrict_to_functions: [],
				format: doc.meta.analysis.format,
				capa_backend: doc.meta.analysis.extractor,
				os: doc.meta.analysis.os,
			},
			rules_provenance: rulesProvenance,
			matched_rule_count: filteredRules.length,
			rules: filteredRules,
			warnings,
			limitations,
			evidence_candidates: builtCandidates.evidenceCandidates,
			next_actions: builtCandidates.nextActions,
			next_experiment_suggestions: builtCandidates.nextExperimentSuggestions,
		};

		const writtenReport = await writePrivateRunArtifactFile(
			reportTarget.resolvedPath,
			deterministicJsonStringify(fullReport),
		);

		const finalCandidates = builtCandidates.evidenceCandidates.map(c => ({
			...c,
			artifact_sha256: writtenReport.sha256,
		}));

		const recordedArgv = ["capability_inspect:import", safeReportInput.relativePath, boundSamplePath].map(a =>
			redactSecrets(a),
		);

		const lines = [
			`// Capa Offline Report Import Complete (${filteredRules.length} rule(s) normalized)`,
			`Workflow / Step / Run: ${workflowId} / ${stepId} / ${runId}`,
			`Imported Raw Report: ${safeReportInput.relativePath} (sha256: ${rawReportHash.sha256.slice(0, 16)}...)`,
			`Verified Sample: ${boundSamplePath} (sha256: ${boundSampleSha256.slice(0, 16)}...)`,
			`Report Flavor & Engine: flavor=${doc.meta.flavor}${doc.meta.flavor === "dynamic" ? " (historical_dynamic_import=true, assurance_level=static_candidate)" : ""} | capa ${doc.meta.version} | extractor=${doc.meta.analysis.extractor}`,
			...filteredRules.slice(0, 15).map(r => {
				const locs = r.matches.map(m => m.address.display).join(", ");
				return `  • ${r.rule_name} [${r.namespace ?? "no-namespace"}] (scope=${r.primary_scope}, matches=${r.match_count} @ ${locs}, ptr=${r.json_pointer})`;
			}),
			...(filteredRules.length > 15 ? [`  … ${filteredRules.length - 15} more matched rule(s) in report JSON`] : []),
			...(warnings.length > 0 ? [`Warnings: ${warnings.join(" | ")}`] : []),
			...(limitations.length > 0 ? [`Limitations: ${limitations.join(" | ")}`] : []),
			`Normalized Report (mode 0600): ${reportTarget.relativePath} (sha256: ${writtenReport.sha256.slice(0, 16)}...)`,
			`Record Hint: Pass output_paths: ${JSON.stringify(relativeOutputPaths)} when calling reverse_workspace(action: "record").`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "import",
				backend: "capa",
				status: "ok",
				workflowId,
				stepId,
				runId,
				runDir: execution.paths.relative.run_dir,
				samplePath: boundSamplePath,
				sampleSha256: boundSampleSha256,
				rawReportPath: retainedRawAbsPath,
				rawReportRelativePath: retainedRawRelPath,
				rawReportSha256: rawReportHash.sha256,
				reportPath: reportTarget.resolvedPath,
				reportRelativePath: reportTarget.relativePath,
				reportSha256: writtenReport.sha256,
				outputPaths,
				relativeOutputPaths,
				rulesProvenance,
				report: fullReport,
				argv: recordedArgv,
				exitCode: 0,
				engineVersion: `capa ${doc.meta.version}`,
				assuranceLevel: "static_candidate",
				evidenceCandidates: finalCandidates,
				nextActions: builtCandidates.nextActions,
				nextExperimentSuggestions: builtCandidates.nextExperimentSuggestions,
				warnings,
				limitations,
			},
		};
	}
}
