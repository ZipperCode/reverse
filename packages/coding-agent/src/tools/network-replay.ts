import { createHash } from "node:crypto";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { isRecord } from "@reverse/utils";
import { redactEvidenceText, type EvidenceAssuranceLevel } from "../evidence/contracts";
import {
	deterministicJsonStringify,
	loadAnalysisExecution,
	resolveAnalysisOutputPath,
	type AnalysisRunPaths,
} from "../reverse-workspace";
import {
	assertNotSymlinkCandidate,
	compareResponses,
	evaluateJsonAssertionsForTarget,
	loadAndVerifyCaseWithBodies,
	MAX_INLINE_DIFF_BYTES,
	MAX_INLINE_DIFF_ENTRIES,
	MAX_REPORT_DIFF_ENTRIES,
	validateComparisonOptions,
	type ComparisonTruthValue,
	type HeaderComparisonEntry,
	type JsonFieldDiffEntry,
	type ReplayJsonAssertion,
	type ReplayJsonAssertionResult,
	type ResponseComparisonResult,
} from "./network-compare";
import {
	MAX_IMPORT_BODY_BYTES,
	normalizeContentEncoding,
	readRegularFileBoundedNoFollow,
	SENSITIVE_HEADER_NAME_PATTERN,
	SENSITIVE_QUERY_PARAM_PATTERN,
	writePrivateRunArtifactFile,
	type ReplayBodyCompleteness,
	type ReplayBodyRepresentation,
	type ReplayCaseRecordedResponse,
	type ReplayCaseSourceFormat,
	type ReplayHeaderEntry,
} from "./network-import";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";

// ============================================================================
// Step 3: network_replay 共享网络执行与三方差分契约
// ============================================================================

export interface ReplayVariantInput {
	id: string;
	name?: string;
	url?: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	body_file?: string;
	auth_header_env?: string;
	header_env_map?: Record<string, string>;
}

export interface ReplayBaselineInput {
	url?: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
	body_file?: string;
	auth_header_env?: string;
	header_env_map?: Record<string, string>;
}

export interface DuplicateHeaderPreservationNote {
	name: string;
	values: string[];
	wire_combination: "rfc9110_comma_joined";
}

export interface RecordedResponseSummary {
	isHistoricalRecord: true;
	status: number;
	statusText: string;
	headers: Record<string, string>;
	headerEntries: ReplayHeaderEntry[];
	bodyBytes: number;
	bodySha256: string | null;
	bodyRepresentation: ReplayBodyRepresentation;
	bodyCompleteness: ReplayBodyCompleteness;
	bodyPath: string | null;
	contentEncoding?: string;
	mimeType?: string;
	assertionResults?: ReplayJsonAssertionResult[];
}

export interface ReplayBaselineExecutionResult {
	status: number;
	statusText: string;
	headers: Record<string, string>;
	headerEntries?: ReplayHeaderEntry[];
	bodyBytes: number;
	bodySha256: string;
	bodyHashScope: "complete" | "truncated_prefix";
	bodyTruncated: boolean;
	bodyRepresentation: ReplayBodyRepresentation;
	bodyCompleteness: ReplayBodyCompleteness;
	artifactId?: string;
	artifactPath?: string;
	relativeArtifactPath?: string;
	duplicateHeadersPreserved?: DuplicateHeaderPreservationNote[];
	assertionResults?: ReplayJsonAssertionResult[];
	diffAgainstRecorded?: ResponseComparisonResult;
}

export interface ReplayVariantDiffAgainstBaseline {
	statusMatch: boolean;
	bodyHashMatch: boolean | null;
	statusDelta: string;
	lengthDelta: number;
	raw_equal: ComparisonTruthValue;
	normalized_equal: ComparisonTruthValue;
	selected_headers_equal: boolean;
	compared_headers: string[];
	header_diffs: HeaderComparisonEntry[];
	comparison_reason?: string;
	applied_ignore_pointers: string[];
	field_diffs: JsonFieldDiffEntry[];
	ignored_diffs: JsonFieldDiffEntry[];
	total_raw_diffs: number;
	total_unignored_diffs: number;
	total_ignored_diffs: number;
	diffs_truncated: boolean;
}

export interface ReplayVariantExecutionResult {
	id: string;
	name?: string;
	status: number;
	statusText: string;
	headers: Record<string, string>;
	headerEntries?: ReplayHeaderEntry[];
	bodyBytes: number;
	bodySha256: string;
	bodyHashScope: "complete" | "truncated_prefix";
	bodyTruncated: boolean;
	bodyRepresentation: ReplayBodyRepresentation;
	bodyCompleteness: ReplayBodyCompleteness;
	artifactId?: string;
	artifactPath?: string;
	relativeArtifactPath?: string;
	duplicateHeadersPreserved?: DuplicateHeaderPreservationNote[];
	assertionResults?: ReplayJsonAssertionResult[];
	diffAgainstBaseline: ReplayVariantDiffAgainstBaseline;
	diffAgainstRecorded?: ResponseComparisonResult;
}

export interface NetworkReplayReportV1 {
	schema_version: "1";
	workflow_id?: string;
	step_id?: string;
	run_id?: string;
	created_at: string;
	allowed_origins: string[];
	case_source?: {
		case_path: string;
		case_sha256: string;
		case_id: string;
		capture_path: string;
		capture_sha256: string;
		capture_format: ReplayCaseSourceFormat;
		entry_id: string;
		entry_index: number;
	};
	comparison_config: {
		ignore_json_pointers: string[];
		compare_headers: string[];
		assertions: ReplayJsonAssertion[];
	};
	recorded_response?: RecordedResponseSummary;
	baseline_result: ReplayBaselineExecutionResult;
	baseline_vs_recorded?: ResponseComparisonResult;
	variant_results: ReplayVariantExecutionResult[];
	assertion_results: ReplayJsonAssertionResult[];
	assertions_passed: boolean;
	experimental_conditions: string[];
}

export interface ExecuteNetworkReplayParams {
	projectDir: string;
	workspacePath?: string;
	workflowId?: string;
	stepId?: string;
	runId?: string;
	outputPath?: string;
	allowedOrigins?: string[];
	caseFile?: string;
	requestFile?: string;
	baselineRequest?: ReplayBaselineInput;
	variantRequests?: ReplayVariantInput[];
	authHeaderEnv?: string;
	headerEnvMap?: Record<string, string>;
	ignoreJsonPointers?: string[];
	compareHeaders?: string[];
	assertions?: ReplayJsonAssertion[];
	captureResponseArtifacts?: boolean;
	maxBytes?: number;
	timeout?: number;
	fetcher?: typeof fetch;
	allocateOutputArtifact?: (toolName: string) => Promise<{ id?: string; path?: string } | undefined>;
	signal?: AbortSignal;
}

export interface ExecuteNetworkReplayOutcome {
	status: "ok";
	workflowId?: string;
	stepId?: string;
	runId?: string;
	runDir?: string;
	paths?: AnalysisRunPaths;
	casePath?: string;
	caseRelativePath?: string;
	caseSha256?: string;
	reportPath?: string;
	reportRelativePath?: string;
	reportSha256?: string;
	outputPaths?: string[];
	relativeOutputPaths?: string[];
	allowedOrigins: string[];
	sanitizedBaselineUrl: string;
	baselineMethod: string;
	recordedResponse?: RecordedResponseSummary;
	baselineResult: ReplayBaselineExecutionResult;
	baselineVsRecorded?: ResponseComparisonResult;
	variantResults: ReplayVariantExecutionResult[];
	assertionResults: ReplayJsonAssertionResult[];
	assertionsPassed: boolean;
	observations: string[];
	evidenceCandidates?: Array<{
		kind: "fact";
		target: string;
		locator: string;
		sourceTool: "app_experiment";
		content: string;
		assurance?: EvidenceAssuranceLevel;
	}>;
}

// ============================================================================
// 常量与安全头部集合
// ============================================================================

const SENSITIVE_KEY_PATTERN = /(authorization|cookie|proxy-authorization|x-api-key|apikey|token|secret|password)/i;

const SAFE_RESPONSE_HEADERS: Record<string, true> = {
	"content-type": true,
	"content-length": true,
	"content-encoding": true,
	"cache-control": true,
	date: true,
	etag: true,
	expires: true,
	"last-modified": true,
	location: true,
	pragma: true,
	server: true,
	vary: true,
	"www-authenticate": true,
	"x-content-type-options": true,
	"x-frame-options": true,
	"x-powered-by": true,
	"x-ratelimit-limit": true,
	"x-ratelimit-remaining": true,
	"x-ratelimit-reset": true,
	"x-request-id": true,
};

const ALLOWED_HTTP_METHODS: Record<string, true> = {
	GET: true,
	POST: true,
	PUT: true,
	DELETE: true,
	PATCH: true,
	HEAD: true,
	OPTIONS: true,
};

/**
 * HTTP 关键单值头部集合：这些头部若在同次请求中重复出现且存在多值，
 * 标准 Fetch Headers 无法无损保留或会导致报文定界/路由歧义，必须显式拒绝而非静默覆盖。
 */
const CRITICAL_SINGLETON_REQUEST_HEADERS: Record<string, true> = {
	host: true,
	"content-length": true,
	"content-type": true,
	"content-encoding": true,
	"transfer-encoding": true,
	authorization: true,
	"proxy-authorization": true,
};

const LEGACY_MAX_FILE_BYTES = 1024 * 1024; // 1 MiB 传统 request_file / body_file 上限

// ============================================================================
// 受控二进制/文本文件读取（O_RDONLY | O_NOFOLLOW | O_NONBLOCK，杜绝 UTF-8 破坏）
// ============================================================================

export async function readProtectedBuffer(resolvedPath: string, maxSize: number, label: string): Promise<Buffer> {
	let fh: fs.FileHandle;
	try {
		fh = await fs.open(resolvedPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
	} catch (err) {
		throw new ToolError(
			`Failed to open ${label} '${resolvedPath}': ${err instanceof Error ? err.message : String(err)}`,
		);
	}

	try {
		const st = await fh.stat();
		if (!st.isFile()) {
			throw new ToolError(`${label} '${resolvedPath}' is not a regular file`);
		}
		if (process.platform !== "win32") {
			if ((st.mode & 0o077) !== 0) {
				throw new ToolError(
					`${label} '${resolvedPath}' has insecure permissions (mode 0o${(st.mode & 0o777).toString(8)}). Protected files must be private to owner only (e.g. mode 0o600 or 0o400)`,
				);
			}
			if (typeof process.getuid === "function") {
				const currentUid = process.getuid();
				if (st.uid !== 0 && st.uid !== currentUid) {
					throw new ToolError(
						`${label} '${resolvedPath}' is not owned by the current user (uid ${st.uid} !== ${currentUid})`,
					);
				}
			}
		}

		if (st.size > maxSize) {
			throw new ToolError(`${label} '${resolvedPath}' exceeds maximum allowed size (${maxSize} bytes)`);
		}

		const buffer = Buffer.alloc(maxSize + 1);
		let offset = 0;
		while (offset < maxSize + 1) {
			const { bytesRead } = await fh.read(buffer, offset, maxSize + 1 - offset, offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		if (offset > maxSize) {
			throw new ToolError(`${label} '${resolvedPath}' exceeds maximum allowed size (${maxSize} bytes)`);
		}

		return buffer.subarray(0, offset);
	} finally {
		await fh.close().catch(() => {});
	}
}

// ============================================================================
// 辅助函数：Content-Encoding 与重复 Header 校验
// ============================================================================

function normalizeSingleEncodingValue(raw: string | undefined): string | undefined {
	if (!raw) return undefined;
	const trimmed = raw.trim().toLowerCase();
	if (!trimmed || trimmed === "identity" || trimmed === "none") return undefined;
	return trimmed;
}

function validateAndBuildRequestHeaders(options: {
	label: string;
	baseEntries: readonly ReplayHeaderEntry[];
	overrideRecord: Record<string, string> | undefined;
	authEnv: string | undefined;
	defaultAuthScheme?: string;
	headerEnvMap: Record<string, string> | undefined;
	isFromArgs: boolean;
	parsedUrl: URL;
}): {
	orderedEntries: ReplayHeaderEntry[];
	fetchHeaders: Headers;
	duplicateNotes: DuplicateHeaderPreservationNote[];
} {
	// 1. 校验 baseEntries 中是否存在禁止重复的关键单值头或含未引号逗号的歧义重复头
	const baseCountByLower = new Map<string, ReplayHeaderEntry[]>();
	for (const entry of options.baseEntries) {
		if (typeof entry.name !== "string" || typeof entry.value !== "string") {
			throw new ToolError(`Header names and values in ${options.label} must be strings`);
		}
		if (/[\r\n\0]/.test(entry.name) || /[\r\n\0]/.test(entry.value)) {
			throw new ToolError(`CRLF characters detected in header '${entry.name}' in ${options.label}: prohibited`);
		}
		const lower = entry.name.toLowerCase();
		const list = baseCountByLower.get(lower) ?? [];
		list.push({ name: entry.name, value: entry.value });
		baseCountByLower.set(lower, list);
	}

	for (const [lowerName, list] of baseCountByLower.entries()) {
		if (list.length > 1 && Object.hasOwn(CRITICAL_SINGLETON_REQUEST_HEADERS, lowerName)) {
			throw new ToolError(
				`Critical duplicate header '${list[0]!.name}' (${list.length} occurrences) in ${options.label} cannot be safely preserved or collapsed by HTTP replay`,
			);
		}
	}

	// 复制初始有序条目
	let workingEntries: ReplayHeaderEntry[] = options.baseEntries.map(e => ({ name: e.name, value: e.value }));

	const replaceOrSetHeader = (name: string, value: string) => {
		const lower = name.toLowerCase();
		let replaced = false;
		const next: ReplayHeaderEntry[] = [];
		for (const item of workingEntries) {
			if (item.name.toLowerCase() === lower) {
				if (!replaced) {
					next.push({ name, value });
					replaced = true;
				}
				continue;
			}
			next.push(item);
		}
		if (!replaced) {
			next.push({ name, value });
		}
		workingEntries = next;
	};

	// 2. 应用 overrideRecord（来自 baseline_request.headers 或 variant_requests[i].headers）
	if (options.overrideRecord !== undefined) {
		if (
			typeof options.overrideRecord !== "object" ||
			options.overrideRecord === null ||
			Array.isArray(options.overrideRecord)
		) {
			throw new ToolError(`Invalid headers object in ${options.label}: headers must be a key-value mapping`);
		}
		// 检查 overrideRecord 内部是否由于大小写不同传入了重复的 critical singleton header
		const overrideSeenLower = new Map<string, string>();
		for (const [k, v] of Object.entries(options.overrideRecord)) {
			if (typeof k !== "string" || typeof v !== "string") {
				throw new ToolError(`Header names and values in ${options.label} must be strings`);
			}
			if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
				throw new ToolError(`CRLF characters detected in header '${k}' in ${options.label}: prohibited`);
			}
			if (options.isFromArgs && (SENSITIVE_KEY_PATTERN.test(k) || SENSITIVE_HEADER_NAME_PATTERN.test(k))) {
				throw new ToolError(
					`Inline credential header '${k}' in tool arguments is prohibited to prevent secret exposure. Use auth_header_env, header_env_map, or request_file.`,
				);
			}
			const lower = k.toLowerCase();
			if (overrideSeenLower.has(lower) && Object.hasOwn(CRITICAL_SINGLETON_REQUEST_HEADERS, lower)) {
				throw new ToolError(
					`Critical duplicate header '${k}' in ${options.label} cannot be safely preserved or collapsed by HTTP replay`,
				);
			}
			overrideSeenLower.set(lower, k);
			replaceOrSetHeader(k, v);
		}
	}

	// 3. 绑定 auth_header_env
	if (options.authEnv) {
		const envVal = process.env[options.authEnv];
		if (!envVal || envVal.trim() === "") {
			throw new ToolError(
				`Environment variable '${options.authEnv}' specified in auth_header_env is not set or empty`,
			);
		}
		const token = envVal.trim();
		if (/[\r\n\0]/.test(token)) {
			throw new ToolError(`CRLF characters detected in environment variable '${options.authEnv}': prohibited`);
		}
		const hasKnownPrefix = /^(Bearer|Basic|Digest|Token|HOBA|Mutual|AWS4-HMAC-SHA256)\s+/i.test(token);
		const schemePrefix = options.defaultAuthScheme || "Bearer";
		const authHeaderValue = hasKnownPrefix ? token : `${schemePrefix} ${token}`;
		replaceOrSetHeader("Authorization", authHeaderValue);
	}

	// 4. 绑定 header_env_map
	if (options.headerEnvMap !== undefined) {
		if (
			typeof options.headerEnvMap !== "object" ||
			options.headerEnvMap === null ||
			Array.isArray(options.headerEnvMap)
		) {
			throw new ToolError(`Invalid header_env_map in ${options.label}: must be a key-value mapping`);
		}
		const seenEnvHeaderLower = new Set<string>();
		for (const [headerName, envVarName] of Object.entries(options.headerEnvMap)) {
			if (typeof headerName !== "string" || typeof envVarName !== "string") {
				throw new ToolError(`header_env_map keys and values in ${options.label} must be strings`);
			}
			if (/[\r\n\0]/.test(headerName)) {
				throw new ToolError(`CRLF characters detected in header name '${headerName}': prohibited`);
			}
			const lower = headerName.toLowerCase();
			if (seenEnvHeaderLower.has(lower) && Object.hasOwn(CRITICAL_SINGLETON_REQUEST_HEADERS, lower)) {
				throw new ToolError(
					`Critical duplicate header '${headerName}' in ${options.label} header_env_map is prohibited`,
				);
			}
			seenEnvHeaderLower.add(lower);

			const envVal = process.env[envVarName];
			if (!envVal || envVal.trim() === "") {
				throw new ToolError(
					`Environment variable '${envVarName}' specified for header '${headerName}' in header_env_map is not set or empty`,
				);
			}
			const headerVal = envVal.trim();
			if (/[\r\n\0]/.test(headerVal)) {
				throw new ToolError(`CRLF characters detected in environment variable '${envVarName}': prohibited`);
			}
			replaceOrSetHeader(headerName, headerVal);
		}
	}

	// 5. 构建 Fetch Headers（使用 append 保留同名多值头的原始顺序），并校验 Host 与重复头合法性
	const fetchHeaders = new Headers();
	const groupedByLower = new Map<string, { displayName: string; values: string[] }>();

	for (const entry of workingEntries) {
		try {
			fetchHeaders.append(entry.name, entry.value);
		} catch {
			throw new ToolError(`Invalid header name or value in ${options.label}: header validation failed`);
		}
		const lower = entry.name.toLowerCase();
		const g = groupedByLower.get(lower);
		if (g) {
			g.values.push(entry.value);
		} else {
			groupedByLower.set(lower, { displayName: entry.name, values: [entry.value] });
		}
	}

	const hostGroup = groupedByLower.get("host");
	if (hostGroup && hostGroup.values.length > 0) {
		const hostVal = hostGroup.values[0]!.trim().toLowerCase();
		if (hostVal !== options.parsedUrl.host.toLowerCase()) {
			throw new ToolError(`Host header must match the request URL origin in ${options.label}`);
		}
	}

	const duplicateNotes: DuplicateHeaderPreservationNote[] = [];
	for (const [lower, group] of groupedByLower.entries()) {
		if (group.values.length > 1) {
			if (Object.hasOwn(CRITICAL_SINGLETON_REQUEST_HEADERS, lower)) {
				throw new ToolError(
					`Critical duplicate header '${group.displayName}' in ${options.label} cannot be safely preserved or collapsed by HTTP replay`,
				);
			}
			duplicateNotes.push({
				name: group.displayName,
				values: [...group.values],
				wire_combination: "rfc9110_comma_joined",
			});
		}
	}

	return {
		orderedEntries: workingEntries,
		fetchHeaders,
		duplicateNotes,
	};
}

function validateBodyAndContentEncodingConsistency(options: {
	label: string;
	method: string;
	orderedHeaders: readonly ReplayHeaderEntry[];
	bodyBuffer: Buffer | undefined;
	bodyRefMeta:
		| {
				representation: ReplayBodyRepresentation;
				completeness: ReplayBodyCompleteness;
				content_encoding?: string;
		  }
		| undefined;
}): void {
	const outgoingCE = normalizeContentEncoding([...options.orderedHeaders]);
	const metaCE = normalizeSingleEncodingValue(options.bodyRefMeta?.content_encoding);
	const hasNonEmptyBody = Boolean(options.bodyBuffer && options.bodyBuffer.byteLength > 0);

	if ((options.method === "GET" || options.method === "HEAD") && hasNonEmptyBody && options.bodyRefMeta) {
		throw new ToolError(
			`Request in ${options.label} uses HTTP ${options.method} with a non-empty captured body (${options.bodyBuffer!.byteLength} bytes); HTTP Fetch API prohibits request bodies on GET/HEAD.`,
		);
	}

	// 检查 Content-Length 头（若显式存在）是否与实际发送字节数一致
	for (const h of options.orderedHeaders) {
		if (h.name.toLowerCase() === "content-length") {
			const trimmed = h.value.trim();
			if (!/^\d+$/.test(trimmed)) {
				throw new ToolError(`Invalid Content-Length header '${h.value}' in ${options.label}`);
			}
			const declared = Number(trimmed);
			const actualLen =
				options.method === "GET" || options.method === "HEAD" ? 0 : (options.bodyBuffer?.byteLength ?? 0);
			if (declared !== actualLen) {
				throw new ToolError(
					`Inconsistent Content-Length header (${declared}) vs actual request body size (${actualLen} bytes) in ${options.label}`,
				);
			}
		}
	}

	if (!hasNonEmptyBody || !options.bodyRefMeta) {
		return;
	}

	const rep = options.bodyRefMeta.representation;
	if (outgoingCE !== undefined) {
		if (rep !== "captured_raw_bytes") {
			throw new ToolError(
				`Ambiguous request body encoding in ${options.label}: outgoing Content-Encoding is '${outgoingCE}', but request body representation is '${rep}' (not 'captured_raw_bytes'). Refusing to fabricate or re-compress request body bytes.`,
			);
		}
		if (metaCE !== outgoingCE) {
			throw new ToolError(
				`Inconsistent Content-Encoding in ${options.label}: captured raw request body has content_encoding='${metaCE ?? "identity"}', which does not match outgoing Content-Encoding header '${outgoingCE}'.`,
			);
		}
	} else if (metaCE !== undefined && rep === "captured_raw_bytes") {
		throw new ToolError(
			`Inconsistent Content-Encoding in ${options.label}: captured raw request body is encoded with '${metaCE}', but outgoing Content-Encoding header is absent/identity.`,
		);
	}
}

// ============================================================================
// 主入口：执行 network_replay（支持 case_file 与传统 baseline_request / request_file）
// ============================================================================

export async function executeNetworkReplay(params: ExecuteNetworkReplayParams): Promise<ExecuteNetworkReplayOutcome> {
	throwIfAborted(params.signal);

	// 1. 严格校验并规范化 allowed_origins
	if (!params.allowedOrigins || !Array.isArray(params.allowedOrigins) || params.allowedOrigins.length === 0) {
		throw new ToolError(
			"network_replay strictly requires non-empty 'allowed_origins' (e.g. ['https://api.example.com'])",
		);
	}

	const allowedOrigins: string[] = [];
	const allowedOriginsSet = new Set<string>();
	for (const rawOrigin of params.allowedOrigins) {
		let parsed: URL;
		try {
			parsed = new URL(rawOrigin);
		} catch {
			throw new ToolError(`Invalid allowed_origin URL: '${rawOrigin}'`);
		}
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
			throw new ToolError(`allowed_origins must use http or https scheme: '${rawOrigin}'`);
		}
		const normOrigin = parsed.origin.toLowerCase();
		if (!allowedOriginsSet.has(normOrigin)) {
			allowedOriginsSet.add(normOrigin);
			allowedOrigins.push(normOrigin);
		}
	}

	// 2. 校验输入源互斥性（case_file 与 baseline_request / request_file 严格互斥，绝不创造隐式优先级）
	const hasCaseFile = params.caseFile !== undefined && params.caseFile.trim().length > 0;
	const hasRequestFile = params.requestFile !== undefined && params.requestFile.trim().length > 0;
	const hasInlineBaseline = params.baselineRequest !== undefined;

	if (params.caseFile !== undefined && params.caseFile.trim().length === 0) {
		throw new ToolError("case_file must be a non-empty file path when provided");
	}
	if (hasCaseFile && (hasRequestFile || hasInlineBaseline)) {
		throw new ToolError(
			"network_replay input conflict: 'case_file' is mutually exclusive with 'baseline_request' and 'request_file'; specify only one baseline source.",
		);
	}

	// 3. 预校验比较与断言配置（在任何文件操作与网络请求前完成）
	const validatedComparison = validateComparisonOptions({
		ignoreJsonPointers: params.ignoreJsonPointers,
		compareHeaders: params.compareHeaders,
		assertions: params.assertions,
	});
	const explicitCompareHeaderSet = new Set(validatedComparison.compareHeaders.map(h => h.toLowerCase()));

	const resolvedProjectDir = path.resolve(params.projectDir);

	// 4. 分支加载：case_file（需绑定活跃实验 run） vs 传统 request_file / baseline_request
	interface PreparedReplayRequest {
		id: string;
		name?: string;
		url: string;
		method: string;
		orderedHeaders: ReplayHeaderEntry[];
		fetchHeaders: Headers;
		duplicateNotes: DuplicateHeaderPreservationNote[];
		body?: Buffer;
		bodyRepresentation: ReplayBodyRepresentation;
	}

	let preparedBaseline: PreparedReplayRequest;
	const preparedVariants: PreparedReplayRequest[] = [];
	let loadedCaseInfo:
		| {
				workflowId: string;
				stepId: string;
				runId: string;
				runDir: string;
				paths: AnalysisRunPaths;
				casePath: string;
				caseRelativePath: string;
				caseSha256: string;
				caseId: string;
				capturePath: string;
				captureSha256: string;
				captureFormat: ReplayCaseSourceFormat;
				entryId: string;
				entryIndex: number;
				recordedResponse: ReplayCaseRecordedResponse;
				recordedResponseBuffer: Buffer | null;
		  }
		| undefined;

	if (hasCaseFile) {
		const workflowId = params.workflowId?.trim() ?? "";
		if (!workflowId) {
			throw new ToolError("network_replay with 'case_file' requires explicit 'workflow_id'");
		}
		const stepId = params.stepId?.trim() ?? "";
		if (!stepId) {
			throw new ToolError("network_replay with 'case_file' requires explicit 'step_id'");
		}
		const runId = params.runId?.trim() ?? "";
		if (!runId) {
			throw new ToolError(
				"network_replay with 'case_file' requires explicit 'run_id' from reverse_workspace(action: 'begin')",
			);
		}

		const rawVariants = params.variantRequests ?? [];
		if (rawVariants.length > 10) {
			throw new ToolError("Maximum 10 variant requests allowed per replay run");
		}
		const variantBodyFiles = rawVariants
			.map(v => v.body_file?.trim())
			.filter((p): p is string => Boolean(p && p.length > 0));

		const { loaded, execution } = await loadAndVerifyCaseWithBodies({
			projectDir: resolvedProjectDir,
			workspacePath: params.workspacePath,
			workflowId,
			stepId,
			runId,
			caseFilePath: params.caseFile!.trim(),
			label: "case_file",
			additionalInputPaths: variantBodyFiles,
			outputPaths: params.outputPath ? [params.outputPath] : undefined,
		});

		const caseDoc = loaded.document;

		// 校验 replay_ready 与 blocked_prerequisites
		if (
			caseDoc.replay_ready !== true ||
			(caseDoc.blocked_prerequisites && caseDoc.blocked_prerequisites.length > 0)
		) {
			const blkDesc = (caseDoc.blocked_prerequisites ?? []).map(b => `[${b.code}] ${b.message}`).join("; ");
			throw new ToolError(
				`Cannot replay case '${caseDoc.case_id}': replay_ready is false${blkDesc ? ` due to blocked_prerequisites: ${blkDesc}` : ""}`,
			);
		}

		if (caseDoc.request.body.completeness === "missing" || caseDoc.request.body.completeness === "truncated") {
			throw new ToolError(
				`Cannot replay case '${caseDoc.case_id}': request body completeness is '${caseDoc.request.body.completeness}' (active replay requires complete or empty request body)`,
			);
		}

		if (caseDoc.request.url.includes("[REDACTED]") || caseDoc.request.url.toUpperCase().includes("%5BREDACTED%5D")) {
			throw new ToolError(
				`Cannot replay case '${caseDoc.case_id}': request URL contains redacted placeholder '[REDACTED]'`,
			);
		}

		// 校验 caseDoc.request.headers 不含未剥离的敏感请求头
		for (const h of caseDoc.request.headers) {
			const lower = h.name.toLowerCase();
			if (SENSITIVE_HEADER_NAME_PATTERN.test(lower) || SENSITIVE_KEY_PATTERN.test(lower)) {
				throw new ToolError(
					`ReplayCase '${caseDoc.case_id}' contains unstripped sensitive header '${h.name}' in request.headers; sensitive credentials must be declared in credential_slots and supplied via auth_header_env or header_env_map.`,
				);
			}
		}

		// 校验 credential_slots 绑定完整性（禁止静默丢弃必需凭据或合并重复不可合并凭据头）
		let defaultAuthScheme: string | undefined;
		const effectiveBaselineHeaderEnvMap: Record<string, string> = { ...params.headerEnvMap };
		const envMapLowerKeys = new Map<string, string>();
		for (const [k, v] of Object.entries(effectiveBaselineHeaderEnvMap)) {
			envMapLowerKeys.set(k.toLowerCase(), v);
		}

		for (const slot of caseDoc.request.credential_slots) {
			if (slot.replay_binding === "blocked_prerequisite") {
				throw new ToolError(
					`Cannot replay case '${caseDoc.case_id}': credential slot '${slot.name}' (${slot.location}) is a blocked_prerequisite: ${slot.reason}`,
				);
			}
			if ((slot.occurrences ?? 1) > 1 && slot.location !== "cookie") {
				throw new ToolError(
					`Cannot replay case '${caseDoc.case_id}': duplicate credential header '${slot.name}' (occurrences=${slot.occurrences}) cannot be preserved by HTTP Fetch API without collapsing`,
				);
			}
			const lowerSlotName = slot.name.toLowerCase();
			if (lowerSlotName === "authorization" && slot.scheme) {
				defaultAuthScheme = slot.scheme;
			}
			if (slot.required) {
				const isBoundByAuthEnv =
					lowerSlotName === "authorization" &&
					typeof params.authHeaderEnv === "string" &&
					params.authHeaderEnv.trim().length > 0;
				const isBoundByMap = envMapLowerKeys.has(lowerSlotName);
				if (!isBoundByAuthEnv && !isBoundByMap) {
					throw new ToolError(
						`ReplayCase '${caseDoc.case_id}' requires credential slot '${slot.name}' (${slot.location}) to be explicitly bound via '${slot.replay_binding}' (suggested env var: '${slot.env_var}')`,
					);
				}
			}
		}

		const preconstructCaseRequest = async (options: {
			label: string;
			id: string;
			name?: string;
			urlStr: string;
			rawMethod: string;
			baseHeaders: readonly ReplayHeaderEntry[];
			overrideHeaders?: Record<string, string>;
			authEnv?: string;
			headerEnvMap?: Record<string, string>;
			variantBodyFile?: string;
			isFromArgs: boolean;
		}): Promise<PreparedReplayRequest> => {
			const method = options.rawMethod.trim().toUpperCase();
			if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
				throw new ToolError(
					`Invalid HTTP method in ${options.label}. Allowed methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS`,
				);
			}

			let parsedUrl: URL;
			try {
				parsedUrl = new URL(options.urlStr);
			} catch {
				throw new ToolError(`Invalid request URL in ${options.label}`);
			}
			if (parsedUrl.username || parsedUrl.password) {
				throw new ToolError("Embedded username or password in URL is prohibited to prevent transcript leakage");
			}
			if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
				throw new ToolError(`Request URL must use http or https in ${options.label}`);
			}
			const origin = parsedUrl.origin.toLowerCase();
			if (!allowedOriginsSet.has(origin)) {
				throw new ToolError(
					`URL origin '${origin}' is not in allowed_origins [${allowedOrigins.join(", ")}]. Replay prohibited.`,
				);
			}
			for (const [k] of parsedUrl.searchParams) {
				if (SENSITIVE_QUERY_PARAM_PATTERN.test(k)) {
					throw new ToolError(
						`Inline sensitive credential query parameter '${k}' is prohibited. Use auth_header_env.`,
					);
				}
			}

			// 解析请求体：若 variant 指定了 body_file，则读取该受控文件并不再继承旧 Content-Length
			let bodyBuf: Buffer | undefined;
			let bodyMeta:
				| {
						representation: ReplayBodyRepresentation;
						completeness: ReplayBodyCompleteness;
						content_encoding?: string;
				  }
				| undefined;
			let effectiveBaseHeaders = [...options.baseHeaders];

			if (options.variantBodyFile) {
				const vBodyAbs = path.resolve(resolvedProjectDir, options.variantBodyFile);
				const buf = await readRegularFileBoundedNoFollow(
					vBodyAbs,
					MAX_IMPORT_BODY_BYTES,
					`${options.label} body_file`,
				);
				bodyBuf = buf.byteLength > 0 ? buf : undefined;
				bodyMeta = {
					representation: buf.byteLength > 0 ? "captured_raw_bytes" : "none",
					completeness: buf.byteLength > 0 ? "complete" : "empty",
				};
				// 移除从 baseline 继承的旧 Content-Length，交由 Fetch 或 variant 显式 headers 定界
				effectiveBaseHeaders = effectiveBaseHeaders.filter(h => h.name.toLowerCase() !== "content-length");
			} else {
				const inheritedBuf = loaded.requestBodyBuffer;
				bodyBuf = inheritedBuf && inheritedBuf.byteLength > 0 ? inheritedBuf : undefined;
				bodyMeta = {
					representation: caseDoc.request.body.representation,
					completeness: caseDoc.request.body.completeness,
					content_encoding: caseDoc.request.body.content_encoding,
				};
				if (method === "GET" || method === "HEAD") {
					effectiveBaseHeaders = effectiveBaseHeaders.filter(h => h.name.toLowerCase() !== "content-length");
				}
			}

			// 若 variant 修改了目标 URL 的 host，剔除从 baseline 继承的旧 Host 头（除非 variant 显式指定了 Host）
			const baselineParsedUrl = new URL(caseDoc.request.url);
			if (parsedUrl.host.toLowerCase() !== baselineParsedUrl.host.toLowerCase()) {
				effectiveBaseHeaders = effectiveBaseHeaders.filter(h => h.name.toLowerCase() !== "host");
			}

			const builtHeaders = validateAndBuildRequestHeaders({
				label: options.label,
				baseEntries: effectiveBaseHeaders,
				overrideRecord: options.overrideHeaders,
				authEnv: options.authEnv,
				defaultAuthScheme,
				headerEnvMap: options.headerEnvMap,
				isFromArgs: options.isFromArgs,
				parsedUrl,
			});

			validateBodyAndContentEncodingConsistency({
				label: options.label,
				method,
				orderedHeaders: builtHeaders.orderedEntries,
				bodyBuffer: bodyBuf,
				bodyRefMeta: bodyMeta,
			});

			return {
				id: options.id,
				name: options.name,
				url: options.urlStr,
				method,
				orderedHeaders: builtHeaders.orderedEntries,
				fetchHeaders: builtHeaders.fetchHeaders,
				duplicateNotes: builtHeaders.duplicateNotes,
				body: method !== "GET" && method !== "HEAD" ? bodyBuf : undefined,
				bodyRepresentation:
					method === "GET" || method === "HEAD" || !bodyBuf || bodyBuf.byteLength === 0
						? "none"
						: bodyMeta.representation,
			};
		};

		preparedBaseline = await preconstructCaseRequest({
			label: "baseline request (case_file)",
			id: "baseline",
			urlStr: caseDoc.request.url,
			rawMethod: caseDoc.request.method,
			baseHeaders: caseDoc.request.headers,
			authEnv: params.authHeaderEnv,
			headerEnvMap: params.headerEnvMap,
			isFromArgs: false,
		});

		// 预构建全部 Variants（不继承任何凭据槽位，任一非法变体确保 0 次网络请求）
		const safeInheritedHeaders = caseDoc.request.headers.filter(
			h =>
				!SENSITIVE_HEADER_NAME_PATTERN.test(h.name.toLowerCase()) &&
				!SENSITIVE_KEY_PATTERN.test(h.name.toLowerCase()),
		);

		for (let i = 0; i < rawVariants.length; i++) {
			const v = rawVariants[i]!;
			const variantId = v.id || `variant-${i + 1}`;
			const pv = await preconstructCaseRequest({
				label: `variant '${variantId}'`,
				id: variantId,
				name: v.name,
				urlStr: v.url ?? caseDoc.request.url,
				rawMethod: v.method ?? caseDoc.request.method,
				baseHeaders: safeInheritedHeaders,
				overrideHeaders: v.headers,
				authEnv: v.auth_header_env,
				headerEnvMap: v.header_env_map,
				variantBodyFile: v.body_file,
				isFromArgs: true,
			});
			preparedVariants.push(pv);
		}

		loadedCaseInfo = {
			workflowId,
			stepId,
			runId,
			runDir: execution.paths.run_dir,
			paths: execution.paths,
			casePath: loaded.casePath,
			caseRelativePath: loaded.caseRelativePath,
			caseSha256: loaded.caseSha256,
			caseId: caseDoc.case_id,
			capturePath: caseDoc.source!.path,
			captureSha256: caseDoc.source!.sha256,
			captureFormat: caseDoc.source!.format,
			entryId: caseDoc.source!.entry_id,
			entryIndex: caseDoc.source!.entry_index,
			recordedResponse: caseDoc.recorded_response!,
			recordedResponseBuffer: loaded.responseBodyBuffer,
		};
	} else {
		// 传统 baseline_request / request_file 模式（保持 100% 向后兼容，同时修复二进制 body_file 保真）
		let baseline: ReplayBaselineInput | undefined = params.baselineRequest;
		let fileVariants: ReplayVariantInput[] | undefined;

		if (hasRequestFile) {
			const resolvedPath = resolveReadPath(params.requestFile!, resolvedProjectDir);
			const fileBuf = await readProtectedBuffer(resolvedPath, LEGACY_MAX_FILE_BYTES, "request_file");
			let parsed: unknown;
			try {
				parsed = JSON.parse(fileBuf.toString("utf8"));
			} catch {
				throw new ToolError(`Failed to parse request_file '${params.requestFile}': Invalid JSON syntax`);
			}

			if (!isRecord(parsed) || !("baseline_request" in parsed) || !isRecord(parsed.baseline_request)) {
				throw new ToolError(`request_file '${params.requestFile}' must contain a 'baseline_request' object`);
			}

			const fileBase = parsed.baseline_request as ReplayBaselineInput;
			baseline = {
				url: fileBase.url ?? baseline?.url,
				method: fileBase.method ?? baseline?.method,
				headers: fileBase.headers ?? baseline?.headers,
				body: fileBase.body,
				body_file: fileBase.body_file ?? baseline?.body_file,
				auth_header_env: fileBase.auth_header_env ?? baseline?.auth_header_env,
				header_env_map: fileBase.header_env_map ?? baseline?.header_env_map,
			};

			if (Array.isArray(parsed.variant_requests)) {
				fileVariants = parsed.variant_requests as ReplayVariantInput[];
			}
		}

		if (!baseline || !baseline.url) {
			throw new ToolError("network_replay requires 'case_file', 'baseline_request.url', or a valid 'request_file'");
		}

		const rawVariants: ReplayVariantInput[] = params.variantRequests ?? fileVariants ?? [];
		if (rawVariants.length > 10) {
			throw new ToolError("Maximum 10 variant requests allowed per replay run");
		}

		// 若传统调用显式提供了 workflow_id / step_id / run_id，同样校验活跃实验 run
		if (params.workflowId || params.stepId || params.runId) {
			const wfId = params.workflowId?.trim() ?? "";
			const stId = params.stepId?.trim() ?? "";
			const rId = params.runId?.trim() ?? "";
			if (!wfId || !stId || !rId) {
				throw new ToolError(
					"When associating network_replay with an analysis run, 'workflow_id', 'step_id', and 'run_id' must all be provided.",
				);
			}
			await assertNotSymlinkCandidate(resolvedProjectDir, wfId, "workflow_id");
			await loadAnalysisExecution({
				projectDir: resolvedProjectDir,
				workspaceDir: params.workspacePath,
				workflowId: wfId,
				stepId: stId,
				runId: rId,
				outputPaths: params.outputPath ? [params.outputPath] : undefined,
			});
		}

		const preconstructLegacyRequest = async (
			label: string,
			id: string,
			name: string | undefined,
			urlStr: string,
			rawMethod: string | undefined,
			headers: Record<string, string> | undefined,
			authEnv: string | undefined,
			headerEnvMap: Record<string, string> | undefined,
			rawBody: string | undefined,
			bodyFile: string | undefined,
			inheritedBody: Buffer | undefined,
			inheritedHeaders: readonly ReplayHeaderEntry[],
			isFromArgs: boolean,
		): Promise<PreparedReplayRequest> => {
			const method = String(rawMethod ?? "GET").toUpperCase();
			if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
				throw new ToolError(
					`Invalid HTTP method in ${label}. Allowed methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS`,
				);
			}

			let parsed: URL;
			try {
				parsed = new URL(urlStr);
			} catch {
				throw new ToolError(`Invalid request URL in ${label}`);
			}

			if (parsed.username || parsed.password) {
				throw new ToolError("Embedded username or password in URL is prohibited to prevent transcript leakage");
			}

			if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
				throw new ToolError(`Request URL must use http or https in ${label}`);
			}

			const origin = parsed.origin.toLowerCase();
			if (!allowedOriginsSet.has(origin)) {
				throw new ToolError(
					`URL origin '${origin}' is not in allowed_origins [${allowedOrigins.join(", ")}]. Replay prohibited.`,
				);
			}

			for (const [k] of parsed.searchParams) {
				if (/(token|access_token|key|api[-_]?key|auth|secret|password)/i.test(k)) {
					throw new ToolError(
						`Inline sensitive credential query parameter '${k}' is prohibited. Use auth_header_env.`,
					);
				}
			}

			const builtHeaders = validateAndBuildRequestHeaders({
				label,
				baseEntries: inheritedHeaders,
				overrideRecord: headers,
				authEnv,
				headerEnvMap,
				isFromArgs,
				parsedUrl: parsed,
			});

			// 以原始 Buffer 读取 body_file（修复 UTF-8 转换破坏二进制字节的问题）
			let resolvedBody: Buffer | undefined;
			if (bodyFile) {
				const resolvedBodyPath = resolveReadPath(bodyFile, resolvedProjectDir);
				resolvedBody = await readProtectedBuffer(resolvedBodyPath, LEGACY_MAX_FILE_BYTES, `${label} body_file`);
			} else if (rawBody !== undefined) {
				const buf = Buffer.from(rawBody, "utf8");
				if (buf.byteLength > LEGACY_MAX_FILE_BYTES) {
					throw new ToolError(`${label} request body exceeds maximum allowed size (1 MiB)`);
				}
				resolvedBody = buf;
			} else {
				resolvedBody = inheritedBody;
			}

			if (resolvedBody && resolvedBody.byteLength > LEGACY_MAX_FILE_BYTES) {
				throw new ToolError(`${label} request body exceeds maximum allowed size (1 MiB)`);
			}

			const effectiveBody =
				method !== "GET" && method !== "HEAD" && resolvedBody && resolvedBody.byteLength > 0
					? resolvedBody
					: undefined;

			return {
				id,
				name,
				url: urlStr,
				method,
				orderedHeaders: builtHeaders.orderedEntries,
				fetchHeaders: builtHeaders.fetchHeaders,
				duplicateNotes: builtHeaders.duplicateNotes,
				body: effectiveBody,
				bodyRepresentation: effectiveBody ? "captured_raw_bytes" : "none",
			};
		};

		const baselineHasInlineHeaders = Boolean(params.baselineRequest?.headers);
		const baselineAuthEnv = baseline.auth_header_env ?? params.authHeaderEnv;
		const baselineHeaderEnvMap = baseline.header_env_map ?? params.headerEnvMap;

		preparedBaseline = await preconstructLegacyRequest(
			"baseline request",
			"baseline",
			undefined,
			baseline.url,
			baseline.method,
			baseline.headers,
			baselineAuthEnv,
			baselineHeaderEnvMap,
			baseline.body,
			baseline.body_file,
			undefined,
			[],
			baselineHasInlineHeaders,
		);

		const baselineEnvHeaderNames = new Set<string>();
		if (baselineAuthEnv) {
			baselineEnvHeaderNames.add("authorization");
		}
		if (baselineHeaderEnvMap) {
			for (const hName of Object.keys(baselineHeaderEnvMap)) {
				baselineEnvHeaderNames.add(hName.toLowerCase());
			}
		}

		const safeInheritedBaselineHeaders: ReplayHeaderEntry[] = [];
		if (baseline.headers) {
			for (const [k, v] of Object.entries(baseline.headers)) {
				const lowerK = k.toLowerCase();
				if (!SENSITIVE_KEY_PATTERN.test(lowerK) && !baselineEnvHeaderNames.has(lowerK)) {
					safeInheritedBaselineHeaders.push({ name: k.toLowerCase(), value: v });
				}
			}
		}

		const variantsFromArgs = Boolean(params.variantRequests);
		for (let i = 0; i < rawVariants.length; i++) {
			const v = rawVariants[i]!;
			const variantId = v.id || `variant-${i + 1}`;
			const pv = await preconstructLegacyRequest(
				`variant '${variantId}'`,
				variantId,
				v.name,
				v.url ?? baseline.url,
				v.method ?? baseline.method,
				v.headers,
				v.auth_header_env,
				v.header_env_map,
				v.body,
				v.body_file,
				preparedBaseline.body,
				safeInheritedBaselineHeaders,
				variantsFromArgs,
			);
			preparedVariants.push(pv);
		}
	}

	// 5. 超时与取消控制：结合 caller signal、总体超时与单请求超时
	const timeoutSeconds = Math.min(Math.max(params.timeout ?? 30, 5), 120);
	const overallController = new AbortController();
	const onParentAbort = () => overallController.abort(params.signal?.reason);
	if (params.signal) {
		if (params.signal.aborted) {
			throw new ToolError("Operation aborted before network replay execution");
		}
		params.signal.addEventListener("abort", onParentAbort, { once: true });
	}
	const overallTimeoutTimer = setTimeout(
		() => overallController.abort(new Error(`network_replay execution timed out (${timeoutSeconds}s)`)),
		timeoutSeconds * 1000,
	);

	const maxCapBytes = Math.min(Math.max(params.maxBytes ?? 524288, 1024), 10 * 1024 * 1024);
	const fetchFn = params.fetcher ?? fetch;

	interface RawLiveExecutionResult {
		status: number;
		statusText: string;
		safeHeaders: Record<string, string>;
		sanitizedHeaderEntries: ReplayHeaderEntry[];
		bodyBytes: number;
		bodySha256: string;
		bodyHashScope: "complete" | "truncated_prefix";
		bodyTruncated: boolean;
		bodyRepresentation: ReplayBodyRepresentation;
		bodyCompleteness: ReplayBodyCompleteness;
		contentEncoding?: string;
		mimeType?: string;
		rawBuffer: Buffer;
		artifactId?: string;
		artifactPath?: string;
		relativeArtifactPath?: string;
		duplicateHeadersPreserved?: DuplicateHeaderPreservationNote[];
	}

	// 6. 执行单个请求的核心安全封装
	const executeSingleRequest = async (
		req: PreparedReplayRequest,
		runArtifactFilename?: string,
	): Promise<RawLiveExecutionResult> => {
		if (overallController.signal.aborted) {
			throw new ToolError(
				`network_replay aborted or timed out: ${overallController.signal.reason?.message ?? "Operation cancelled"}`,
			);
		}

		const reqController = new AbortController();
		const onOverallAbort = () => reqController.abort(overallController.signal.reason);
		overallController.signal.addEventListener("abort", onOverallAbort, { once: true });
		const perReqTimer = setTimeout(
			() => reqController.abort(new Error("Single request timed out")),
			Math.min(timeoutSeconds * 1000, 30_000),
		);

		try {
			const bodyPayload = req.body
				? new Uint8Array(req.body.buffer, req.body.byteOffset, req.body.byteLength)
				: undefined;

			const res = await fetchFn(req.url, {
				method: req.method,
				headers: req.fetchHeaders,
				body: bodyPayload,
				redirect: "manual",
				signal: reqController.signal,
			});

			const chunks: Uint8Array[] = [];
			let capturedBytes = 0;
			let totalBytes = 0;
			let truncated = false;

			if (res.body) {
				const reader = res.body.getReader();
				try {
					while (true) {
						const { done, value } = await reader.read();
						if (done) break;
						totalBytes += value.byteLength;
						const remaining = maxCapBytes - capturedBytes;
						if (remaining > 0) {
							if (value.byteLength <= remaining) {
								chunks.push(value);
								capturedBytes += value.byteLength;
							} else {
								chunks.push(value.subarray(0, remaining));
								capturedBytes += remaining;
								truncated = true;
								await reader.cancel().catch(() => {});
								break;
							}
						} else {
							truncated = true;
							await reader.cancel().catch(() => {});
							break;
						}
					}
				} finally {
					reader.releaseLock();
				}
			}

			const receivedBuffer = Buffer.concat(chunks);
			const hash = createHash("sha256").update(receivedBuffer).digest("hex");
			const bodyHashScope = truncated ? ("truncated_prefix" as const) : ("complete" as const);

			const safeHeaders: Record<string, string> = {};
			const sanitizedHeaderEntries: ReplayHeaderEntry[] = [];

			res.headers.forEach((v, k) => {
				const lowerKey = k.toLowerCase();
				const isSensitive = SENSITIVE_KEY_PATTERN.test(lowerKey) || SENSITIVE_HEADER_NAME_PATTERN.test(lowerKey);

				let safeVal: string;
				if (isSensitive) {
					safeVal = "[REDACTED]";
				} else if (lowerKey === "location") {
					try {
						const locUrl = new URL(v, req.url);
						locUrl.search = "";
						locUrl.hash = "";
						locUrl.username = "";
						locUrl.password = "";
						safeVal = locUrl.toString().slice(0, 512);
					} catch {
						safeVal = "[REDACTED LOCATION]";
					}
				} else {
					safeVal = redactEvidenceText(v).slice(0, 512);
				}

				sanitizedHeaderEntries.push({ name: k, value: safeVal });

				if (
					!isSensitive &&
					(Object.hasOwn(SAFE_RESPONSE_HEADERS, lowerKey) || explicitCompareHeaderSet.has(lowerKey))
				) {
					safeHeaders[lowerKey] = safeVal;
				}
			});

			const respContentEncoding = normalizeContentEncoding(sanitizedHeaderEntries);
			const rawContentType = safeHeaders["content-type"];
			const respMimeType = rawContentType ? rawContentType.split(";")[0]?.trim().toLowerCase() : undefined;

			// Fetch API 会自动解压服务端 Content-Encoding：
			// 若响应无 Content-Encoding（identity），接收到的字节即为原始负载字节 (captured_raw_bytes)；
			// 若响应带 Content-Encoding，Fetch 读取流产出的是解压后的实体字节 (decoded_entity_bytes)。
			const bodyCompleteness: ReplayBodyCompleteness = truncated
				? "truncated"
				: receivedBuffer.byteLength === 0
					? "empty"
					: "complete";
			const bodyRepresentation: ReplayBodyRepresentation =
				receivedBuffer.byteLength === 0
					? "none"
					: respContentEncoding
						? "decoded_entity_bytes"
						: "captured_raw_bytes";

			let artifactId: string | undefined;
			let artifactPath: string | undefined;
			let relativeArtifactPath: string | undefined;

			if (loadedCaseInfo && runArtifactFilename) {
				const resolvedBodyOut = await resolveAnalysisOutputPath({
					projectDir: resolvedProjectDir,
					runDir: loadedCaseInfo.runDir,
					outputPath: path.join(loadedCaseInfo.paths.dumps_dir, runArtifactFilename),
				});
				await writePrivateRunArtifactFile(resolvedBodyOut.resolvedPath, receivedBuffer);
				artifactPath = resolvedBodyOut.resolvedPath;
				relativeArtifactPath = resolvedBodyOut.relativePath;
				artifactId = path.basename(resolvedBodyOut.resolvedPath);
			} else if (params.captureResponseArtifacts) {
				try {
					const allocation = await params.allocateOutputArtifact?.("app_experiment");
					let outputPath: string;
					let outputId: string;
					if (allocation?.path && allocation.id) {
						outputPath = allocation.path;
						outputId = allocation.id;
					} else {
						const artDir = path.join(resolvedProjectDir, "artifacts", "replay");
						await fs.mkdir(artDir, { recursive: true, mode: 0o700 });
						const runDir = await fs.mkdtemp(path.join(artDir, "response-"));
						outputPath = path.join(runDir, "body.bin");
						outputId = path.basename(runDir);
					}
					await fs.writeFile(outputPath, receivedBuffer, { mode: 0o600, flag: "wx" });
					artifactPath = outputPath;
					artifactId = outputId;
				} catch {
					throw new ToolError(
						"Response received but private artifact publication failed; no evidence artifact was recorded",
					);
				}
			}

			return {
				status: res.status,
				statusText: res.statusText,
				safeHeaders,
				sanitizedHeaderEntries,
				bodyBytes: totalBytes,
				bodySha256: hash,
				bodyHashScope,
				bodyTruncated: truncated,
				bodyRepresentation,
				bodyCompleteness,
				contentEncoding: respContentEncoding,
				mimeType: respMimeType,
				rawBuffer: receivedBuffer,
				artifactId,
				artifactPath,
				relativeArtifactPath,
				...(req.duplicateNotes.length > 0 ? { duplicateHeadersPreserved: req.duplicateNotes } : {}),
			};
		} catch (err) {
			if (overallController.signal.aborted) {
				throw new ToolError(
					`network_replay aborted or timed out: ${overallController.signal.reason?.message ?? "Operation timed out"}`,
				);
			}
			throw err;
		} finally {
			clearTimeout(perReqTimer);
			overallController.signal.removeEventListener("abort", onOverallAbort);
		}
	};

	const toSyntheticRecordedResponse = (live: RawLiveExecutionResult): ReplayCaseRecordedResponse => ({
		status: live.status,
		status_text: live.statusText,
		headers: live.sanitizedHeaderEntries,
		body: {
			path: live.relativeArtifactPath ?? live.artifactPath ?? null,
			sha256: live.bodySha256,
			size_bytes: live.rawBuffer.byteLength,
			declared_size_bytes: live.bodyBytes,
			representation: live.bodyRepresentation,
			completeness: live.bodyCompleteness,
			...(live.mimeType ? { mime_type: live.mimeType } : {}),
			...(live.contentEncoding ? { content_encoding: live.contentEncoding } : {}),
		},
	});

	try {
		const replayStem = loadedCaseInfo
			? `replay_${loadedCaseInfo.caseId.replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 40)}`
			: "replay";

		// 7. 发起 Baseline 请求
		const rawBaselineRes = await executeSingleRequest(
			preparedBaseline,
			loadedCaseInfo ? `${replayStem}.baseline.response.body.bin` : undefined,
		);
		const syntheticBaselineResp = toSyntheticRecordedResponse(rawBaselineRes);

		// 8. 构建历史 Recorded Response 摘要与 Baseline vs Recorded 对比（若使用 case_file）
		let recordedSummary: RecordedResponseSummary | undefined;
		let baselineVsRecorded: ResponseComparisonResult | undefined;
		let reportBaselineVsRecorded: ResponseComparisonResult | undefined;
		const allAssertionResults: ReplayJsonAssertionResult[] = [];

		if (loadedCaseInfo) {
			const rec = loadedCaseInfo.recordedResponse;
			const recHeadersRecord: Record<string, string> = {};
			for (const h of rec.headers) {
				const lower = h.name.toLowerCase();
				if (Object.hasOwn(SAFE_RESPONSE_HEADERS, lower) || explicitCompareHeaderSet.has(lower)) {
					recHeadersRecord[lower] = h.value;
				}
			}

			const recAssertions = validatedComparison.assertions.filter(
				a => (a.target ?? "").toLowerCase() === "recorded",
			);
			const recAssertionResults = evaluateJsonAssertionsForTarget({
				targetName: "recorded",
				bodyRef: rec.body,
				bodyBuffer: loadedCaseInfo.recordedResponseBuffer,
				assertions: recAssertions,
			});
			allAssertionResults.push(...recAssertionResults);

			recordedSummary = {
				isHistoricalRecord: true,
				status: rec.status,
				statusText: rec.status_text,
				headers: recHeadersRecord,
				headerEntries: rec.headers,
				bodyBytes: rec.body.size_bytes,
				bodySha256: rec.body.sha256,
				bodyRepresentation: rec.body.representation,
				bodyCompleteness: rec.body.completeness,
				bodyPath: rec.body.path,
				...(rec.body.content_encoding ? { contentEncoding: rec.body.content_encoding } : {}),
				...(rec.body.mime_type ? { mimeType: rec.body.mime_type } : {}),
				...(recAssertionResults.length > 0 ? { assertionResults: recAssertionResults } : {}),
			};

			baselineVsRecorded = compareResponses({
				leftResponse: rec,
				leftBodyBuffer: loadedCaseInfo.recordedResponseBuffer,
				rightResponse: syntheticBaselineResp,
				rightBodyBuffer: rawBaselineRes.rawBuffer,
				ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
				compareHeaders: validatedComparison.compareHeaders,
				allowCombinedWireHeaderComparison: true,
				maxDiffEntries: MAX_INLINE_DIFF_ENTRIES,
				maxDiffBytes: MAX_INLINE_DIFF_BYTES,
			});

			reportBaselineVsRecorded = compareResponses({
				leftResponse: rec,
				leftBodyBuffer: loadedCaseInfo.recordedResponseBuffer,
				rightResponse: syntheticBaselineResp,
				rightBodyBuffer: rawBaselineRes.rawBuffer,
				ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
				compareHeaders: validatedComparison.compareHeaders,
				allowCombinedWireHeaderComparison: true,
				maxDiffEntries: MAX_REPORT_DIFF_ENTRIES,
				maxDiffBytes: MAX_INLINE_DIFF_BYTES * 8,
			});
		}

		// 评估针对 baseline 的断言（target 未指定或 target === "baseline"）
		const baselineTargetAssertions = validatedComparison.assertions.filter(a => {
			const t = (a.target ?? "").toLowerCase();
			return t === "" || t === "baseline";
		});
		const baselineAssertionResults = evaluateJsonAssertionsForTarget({
			targetName: "baseline",
			bodyRef: syntheticBaselineResp.body,
			bodyBuffer: rawBaselineRes.rawBuffer,
			assertions: baselineTargetAssertions,
		});
		allAssertionResults.push(...baselineAssertionResults);

		const baselineResult: ReplayBaselineExecutionResult = {
			status: rawBaselineRes.status,
			statusText: rawBaselineRes.statusText,
			headers: rawBaselineRes.safeHeaders,
			headerEntries: rawBaselineRes.sanitizedHeaderEntries,
			bodyBytes: rawBaselineRes.bodyBytes,
			bodySha256: rawBaselineRes.bodySha256,
			bodyHashScope: rawBaselineRes.bodyHashScope,
			bodyTruncated: rawBaselineRes.bodyTruncated,
			bodyRepresentation: rawBaselineRes.bodyRepresentation,
			bodyCompleteness: rawBaselineRes.bodyCompleteness,
			...(rawBaselineRes.artifactId ? { artifactId: rawBaselineRes.artifactId } : {}),
			...(rawBaselineRes.artifactPath ? { artifactPath: rawBaselineRes.artifactPath } : {}),
			...(rawBaselineRes.relativeArtifactPath ? { relativeArtifactPath: rawBaselineRes.relativeArtifactPath } : {}),
			...(rawBaselineRes.duplicateHeadersPreserved
				? { duplicateHeadersPreserved: rawBaselineRes.duplicateHeadersPreserved }
				: {}),
			...(baselineAssertionResults.length > 0 ? { assertionResults: baselineAssertionResults } : {}),
			...(baselineVsRecorded ? { diffAgainstRecorded: baselineVsRecorded } : {}),
		};

		// 9. 依次执行 Variant 请求并对比差异（Baseline vs Variant，以及 Recorded vs Variant）
		const variantResults: ReplayVariantExecutionResult[] = [];
		const reportVariantResults: ReplayVariantExecutionResult[] = [];

		for (const pv of preparedVariants) {
			const safeVarId = pv.id.replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 32) || "variant";
			const rawVarRes = await executeSingleRequest(
				pv,
				loadedCaseInfo ? `${replayStem}.variant_${safeVarId}.response.body.bin` : undefined,
			);
			const syntheticVarResp = toSyntheticRecordedResponse(rawVarRes);

			const statusMatch = rawVarRes.status === rawBaselineRes.status;
			const isTruncated = rawVarRes.bodyTruncated === true || rawBaselineRes.bodyTruncated === true;
			const bodyHashMatch = isTruncated ? null : rawVarRes.bodySha256 === rawBaselineRes.bodySha256;

			let statusDelta = `${rawBaselineRes.status} -> ${rawVarRes.status}`;
			if (isTruncated) {
				statusDelta += " (body truncated; hash match unknown)";
			}

			const inlineCmpAgainstBase = compareResponses({
				leftResponse: syntheticBaselineResp,
				leftBodyBuffer: rawBaselineRes.rawBuffer,
				rightResponse: syntheticVarResp,
				rightBodyBuffer: rawVarRes.rawBuffer,
				ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
				compareHeaders: validatedComparison.compareHeaders,
				allowCombinedWireHeaderComparison: true,
				maxDiffEntries: MAX_INLINE_DIFF_ENTRIES,
				maxDiffBytes: MAX_INLINE_DIFF_BYTES,
			});

			const reportCmpAgainstBase = compareResponses({
				leftResponse: syntheticBaselineResp,
				leftBodyBuffer: rawBaselineRes.rawBuffer,
				rightResponse: syntheticVarResp,
				rightBodyBuffer: rawVarRes.rawBuffer,
				ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
				compareHeaders: validatedComparison.compareHeaders,
				allowCombinedWireHeaderComparison: true,
				maxDiffEntries: MAX_REPORT_DIFF_ENTRIES,
				maxDiffBytes: MAX_INLINE_DIFF_BYTES * 8,
			});

			let inlineCmpAgainstRecorded: ResponseComparisonResult | undefined;
			let reportCmpAgainstRecorded: ResponseComparisonResult | undefined;
			if (loadedCaseInfo) {
				inlineCmpAgainstRecorded = compareResponses({
					leftResponse: loadedCaseInfo.recordedResponse,
					leftBodyBuffer: loadedCaseInfo.recordedResponseBuffer,
					rightResponse: syntheticVarResp,
					rightBodyBuffer: rawVarRes.rawBuffer,
					ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
					compareHeaders: validatedComparison.compareHeaders,
					allowCombinedWireHeaderComparison: true,
					maxDiffEntries: MAX_INLINE_DIFF_ENTRIES,
					maxDiffBytes: MAX_INLINE_DIFF_BYTES,
				});
				reportCmpAgainstRecorded = compareResponses({
					leftResponse: loadedCaseInfo.recordedResponse,
					leftBodyBuffer: loadedCaseInfo.recordedResponseBuffer,
					rightResponse: syntheticVarResp,
					rightBodyBuffer: rawVarRes.rawBuffer,
					ignoreJsonPointers: validatedComparison.ignoreJsonPointers,
					compareHeaders: validatedComparison.compareHeaders,
					allowCombinedWireHeaderComparison: true,
					maxDiffEntries: MAX_REPORT_DIFF_ENTRIES,
					maxDiffBytes: MAX_INLINE_DIFF_BYTES * 8,
				});
			}

			// 评估针对该 variant 的断言
			const variantTargetAssertions = validatedComparison.assertions.filter(a => {
				const t = (a.target ?? "").toLowerCase();
				return t === "variant" || t === "variants" || a.target === pv.id;
			});
			const varAssertionResults = evaluateJsonAssertionsForTarget({
				targetName: pv.id,
				bodyRef: syntheticVarResp.body,
				bodyBuffer: rawVarRes.rawBuffer,
				assertions: variantTargetAssertions,
			});
			allAssertionResults.push(...varAssertionResults);

			const buildVariantResult = (
				cmpBase: ResponseComparisonResult,
				cmpRec?: ResponseComparisonResult,
			): ReplayVariantExecutionResult => ({
				id: pv.id,
				name: pv.name,
				status: rawVarRes.status,
				statusText: rawVarRes.statusText,
				headers: rawVarRes.safeHeaders,
				headerEntries: rawVarRes.sanitizedHeaderEntries,
				bodyBytes: rawVarRes.bodyBytes,
				bodySha256: rawVarRes.bodySha256,
				bodyHashScope: rawVarRes.bodyHashScope,
				bodyTruncated: rawVarRes.bodyTruncated,
				bodyRepresentation: rawVarRes.bodyRepresentation,
				bodyCompleteness: rawVarRes.bodyCompleteness,
				...(rawVarRes.artifactId ? { artifactId: rawVarRes.artifactId } : {}),
				...(rawVarRes.artifactPath ? { artifactPath: rawVarRes.artifactPath } : {}),
				...(rawVarRes.relativeArtifactPath ? { relativeArtifactPath: rawVarRes.relativeArtifactPath } : {}),
				...(rawVarRes.duplicateHeadersPreserved
					? { duplicateHeadersPreserved: rawVarRes.duplicateHeadersPreserved }
					: {}),
				...(varAssertionResults.length > 0 ? { assertionResults: varAssertionResults } : {}),
				diffAgainstBaseline: {
					statusMatch,
					bodyHashMatch,
					statusDelta,
					lengthDelta: rawVarRes.bodyBytes - rawBaselineRes.bodyBytes,
					raw_equal: cmpBase.raw_equal,
					normalized_equal: cmpBase.normalized_equal,
					selected_headers_equal: cmpBase.selected_headers_equal,
					compared_headers: cmpBase.compared_headers,
					header_diffs: cmpBase.header_diffs,
					...(cmpBase.comparison_reason ? { comparison_reason: cmpBase.comparison_reason } : {}),
					applied_ignore_pointers: cmpBase.applied_ignore_pointers,
					field_diffs: cmpBase.field_diffs,
					ignored_diffs: cmpBase.ignored_diffs,
					total_raw_diffs: cmpBase.total_raw_diffs,
					total_unignored_diffs: cmpBase.total_unignored_diffs,
					total_ignored_diffs: cmpBase.total_ignored_diffs,
					diffs_truncated: cmpBase.diffs_truncated,
				},
				...(cmpRec ? { diffAgainstRecorded: cmpRec } : {}),
			});

			variantResults.push(buildVariantResult(inlineCmpAgainstBase, inlineCmpAgainstRecorded));
			reportVariantResults.push(buildVariantResult(reportCmpAgainstBase, reportCmpAgainstRecorded));
		}

		const assertionsPassed = allAssertionResults.every(r => r.passed);

		let sanitizedBaselineUrl = preparedBaseline.url;
		try {
			const u = new URL(preparedBaseline.url);
			sanitizedBaselineUrl = `${u.origin}${u.pathname}`;
		} catch {
			sanitizedBaselineUrl = "[INVALID URL]";
		}

		// 10. 若处于活跃实验 run（case_file 模式），持久化完整 mode-0600 回放与差分报告
		let reportPath: string | undefined;
		let reportRelativePath: string | undefined;
		let reportSha256: string | undefined;
		let outputPaths: string[] | undefined;
		let relativeOutputPaths: string[] | undefined;
		let evidenceCandidates: ExecuteNetworkReplayOutcome["evidenceCandidates"];

		if (loadedCaseInfo) {
			const defaultReportPath = path.join(loadedCaseInfo.paths.reports_dir, `${replayStem}.replay_report.json`);
			const resolvedReportOut = await resolveAnalysisOutputPath({
				projectDir: resolvedProjectDir,
				runDir: loadedCaseInfo.runDir,
				outputPath: params.outputPath ?? defaultReportPath,
			});

			const reportDoc: NetworkReplayReportV1 = {
				schema_version: "1",
				workflow_id: loadedCaseInfo.workflowId,
				step_id: loadedCaseInfo.stepId,
				run_id: loadedCaseInfo.runId,
				created_at: new Date().toISOString(),
				allowed_origins: allowedOrigins,
				case_source: {
					case_path: loadedCaseInfo.caseRelativePath,
					case_sha256: loadedCaseInfo.caseSha256,
					case_id: loadedCaseInfo.caseId,
					capture_path: loadedCaseInfo.capturePath,
					capture_sha256: loadedCaseInfo.captureSha256,
					capture_format: loadedCaseInfo.captureFormat,
					entry_id: loadedCaseInfo.entryId,
					entry_index: loadedCaseInfo.entryIndex,
				},
				comparison_config: {
					ignore_json_pointers: validatedComparison.ignoreJsonPointers,
					compare_headers: validatedComparison.compareHeaders,
					assertions: validatedComparison.assertions,
				},
				recorded_response: recordedSummary,
				baseline_result: {
					...baselineResult,
					...(reportBaselineVsRecorded ? { diffAgainstRecorded: reportBaselineVsRecorded } : {}),
				},
				baseline_vs_recorded: reportBaselineVsRecorded,
				variant_results: reportVariantResults,
				assertion_results: allAssertionResults,
				assertions_passed: assertionsPassed,
				experimental_conditions: [
					"Sequential single-entry HTTP(S) client replay with redirect='manual'",
					"Recorded response is preserved as historical reference and never treated as a live execution",
					"Duplicate non-singleton request headers combined in wire order per RFC 9110 / WHATWG Fetch Headers.append",
				],
			};

			const writtenReport = await writePrivateRunArtifactFile(
				resolvedReportOut.resolvedPath,
				`${deterministicJsonStringify(reportDoc)}\n`,
			);
			reportPath = resolvedReportOut.resolvedPath;
			reportRelativePath = resolvedReportOut.relativePath;
			reportSha256 = writtenReport.sha256;

			outputPaths = [];
			relativeOutputPaths = [];
			if (baselineResult.artifactPath && baselineResult.relativeArtifactPath) {
				outputPaths.push(baselineResult.artifactPath);
				relativeOutputPaths.push(baselineResult.relativeArtifactPath);
			}
			for (const vr of variantResults) {
				if (vr.artifactPath && vr.relativeArtifactPath) {
					outputPaths.push(vr.artifactPath);
					relativeOutputPaths.push(vr.relativeArtifactPath);
				}
			}
			outputPaths.push(reportPath);
			relativeOutputPaths.push(reportRelativePath);

			evidenceCandidates = [
				{
					kind: "fact",
					target: loadedCaseInfo.capturePath,
					locator: `${reportRelativePath}#${loadedCaseInfo.caseId}`,
					sourceTool: "app_experiment",
					assurance: "static_candidate",
					content: `Replayed ${loadedCaseInfo.caseRelativePath} (${preparedBaseline.method} ${sanitizedBaselineUrl}): recorded HTTP ${recordedSummary?.status ?? "n/a"} vs live baseline HTTP ${baselineResult.status} (raw_equal=${String(baselineVsRecorded?.raw_equal)}, normalized_equal=${String(baselineVsRecorded?.normalized_equal)}), variants=${variantResults.length}, assertions_passed=${assertionsPassed}`,
				},
			];
		}

		const observations: string[] = [
			`Replayed baseline and ${variantResults.length} variant requests against ${allowedOrigins.join(", ")}`,
		];
		if (recordedSummary && baselineVsRecorded) {
			observations.push(
				`Historical recorded response (HTTP ${recordedSummary.status}, ${recordedSummary.bodyBytes}b) vs live baseline (HTTP ${baselineResult.status}, ${baselineResult.bodyBytes}b): raw_equal=${String(baselineVsRecorded.raw_equal)}, normalized_equal=${String(baselineVsRecorded.normalized_equal)} (unignored_diffs=${baselineVsRecorded.total_unignored_diffs}, ignored_diffs=${baselineVsRecorded.total_ignored_diffs})`,
			);
		}
		if (preparedBaseline.duplicateNotes.length > 0) {
			observations.push(
				`Preserved duplicate request headers in wire order (RFC 9110 comma-joined): ${preparedBaseline.duplicateNotes.map(d => `${d.name} (${d.values.length})`).join(", ")}`,
			);
		}
		if (allAssertionResults.length > 0) {
			observations.push(
				`Assertions evaluated: ${allAssertionResults.filter(a => a.passed).length}/${allAssertionResults.length} passed (overall: ${assertionsPassed})`,
			);
		}

		return {
			status: "ok",
			...(loadedCaseInfo
				? {
						workflowId: loadedCaseInfo.workflowId,
						stepId: loadedCaseInfo.stepId,
						runId: loadedCaseInfo.runId,
						runDir: loadedCaseInfo.runDir,
						paths: loadedCaseInfo.paths,
						casePath: loadedCaseInfo.casePath,
						caseRelativePath: loadedCaseInfo.caseRelativePath,
						caseSha256: loadedCaseInfo.caseSha256,
						reportPath,
						reportRelativePath,
						reportSha256,
						outputPaths,
						relativeOutputPaths,
					}
				: {}),
			allowedOrigins,
			sanitizedBaselineUrl,
			baselineMethod: preparedBaseline.method,
			...(recordedSummary ? { recordedResponse: recordedSummary } : {}),
			baselineResult,
			...(baselineVsRecorded ? { baselineVsRecorded } : {}),
			variantResults,
			assertionResults: allAssertionResults,
			assertionsPassed,
			observations,
			...(evidenceCandidates ? { evidenceCandidates } : {}),
		};
	} finally {
		clearTimeout(overallTimeoutTimer);
		if (params.signal) {
			params.signal.removeEventListener("abort", onParentAbort);
		}
	}
}
