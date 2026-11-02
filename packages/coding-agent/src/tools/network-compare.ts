import * as fs from "node:fs/promises";
import * as path from "node:path";
import { TextDecoder } from "node:util";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { isRecord } from "@reverse/utils";
import { redactEvidenceText, type EvidenceAssuranceLevel } from "../evidence/contracts";
import {
	deterministicJsonStringify,
	hashBuffer,
	loadAnalysisExecution,
	redactSecrets,
	resolveAnalysisOutputPath,
	type AnalysisFileRef,
	type AnalysisRunPaths,
	type LoadAnalysisExecutionResult,
} from "../reverse-workspace";
import {
	MAX_IMPORT_BODY_BYTES,
	readRegularFileBoundedNoFollow,
	SENSITIVE_HEADER_NAME_PATTERN,
	SENSITIVE_QUERY_PARAM_PATTERN,
	writePrivateRunArtifactFile,
	type ReplayBodyCompleteness,
	type ReplayBodyRef,
	type ReplayBodyRepresentation,
	type ReplayCaseRecordedResponse,
	type ReplayCaseRequest,
	type ReplayCaseSource,
	type ReplayCaseSourceFormat,
	type ReplayCaseV1,
	type ReplayCredentialSlot,
	type ReplayHeaderEntry,
	type ReplayPrerequisiteBlock,
} from "./network-import";
import { throwIfAborted } from "./tool-errors";

export type ComparisonTruthValue = boolean | "unknown" | "not_applicable";
export type JsonValueType = "null" | "boolean" | "number" | "string" | "array" | "object";

export interface ReplayJsonAssertion {
	pointer: string;
	target?: string;
	exists?: boolean;
	type?: JsonValueType;
	eq?: unknown;
}

export interface ReplayJsonAssertionResult {
	pointer: string;
	target: string;
	status: "passed" | "failed" | "unknown" | "not_applicable";
	passed: boolean;
	exists?: boolean;
	expected_exists?: boolean;
	actual_type?: JsonValueType;
	expected_type?: JsonValueType;
	actual_preview?: string;
	expected_preview?: string;
	reason?: string;
}

export interface JsonFieldDiffEntry {
	pointer: string;
	kind: "added" | "removed" | "value_mismatch" | "type_mismatch";
	left_type?: JsonValueType;
	right_type?: JsonValueType;
	left_preview?: string;
	right_preview?: string;
	ignored: boolean;
	matched_ignore_pointer?: string;
}

export interface HeaderComparisonEntry {
	name: string;
	left_values: string[];
	right_values: string[];
	equal: boolean;
}

export interface BodyComparisonResult {
	raw_equal: ComparisonTruthValue;
	normalized_equal: ComparisonTruthValue;
	raw_json_equal?: ComparisonTruthValue;
	left_representation: ReplayBodyRepresentation;
	right_representation: ReplayBodyRepresentation;
	left_completeness: ReplayBodyCompleteness;
	right_completeness: ReplayBodyCompleteness;
	left_size_bytes: number;
	right_size_bytes: number;
	left_sha256: string | null;
	right_sha256: string | null;
	length_delta: number;
	comparison_reason?: string;
	applied_ignore_pointers: string[];
	field_diffs: JsonFieldDiffEntry[];
	ignored_diffs: JsonFieldDiffEntry[];
	total_raw_diffs: number;
	total_unignored_diffs: number;
	total_ignored_diffs: number;
	diffs_truncated: boolean;
}

export interface RequestComparisonResult {
	method_equal: boolean;
	left_method: string;
	right_method: string;
	url_equal: boolean;
	origin_equal: boolean;
	pathname_equal: boolean;
	query_equal: boolean;
	left_url: string;
	right_url: string;
	query_diffs: Array<{ name: string; left_values: string[]; right_values: string[]; equal: boolean }>;
	headers_equal: boolean;
	duplicate_headers_equal: boolean;
	selected_headers_equal: boolean;
	compared_headers: string[];
	header_diffs: HeaderComparisonEntry[];
	credential_slots_equal: boolean;
	raw_equal: ComparisonTruthValue;
	normalized_equal: ComparisonTruthValue;
	comparison_reason?: string;
	applied_ignore_pointers: string[];
	field_diffs: JsonFieldDiffEntry[];
	ignored_diffs: JsonFieldDiffEntry[];
	total_raw_diffs: number;
	total_unignored_diffs: number;
	total_ignored_diffs: number;
	diffs_truncated: boolean;
	body_comparison: BodyComparisonResult;
}

export interface ResponseComparisonResult {
	available: boolean;
	status_equal: boolean;
	left_status: number;
	right_status: number;
	status_delta: string;
	length_delta: number;
	headers_equal: boolean;
	selected_headers_equal: boolean;
	compared_headers: string[];
	header_diffs: HeaderComparisonEntry[];
	raw_equal: ComparisonTruthValue;
	normalized_equal: ComparisonTruthValue;
	comparison_reason?: string;
	applied_ignore_pointers: string[];
	field_diffs: JsonFieldDiffEntry[];
	ignored_diffs: JsonFieldDiffEntry[];
	total_raw_diffs: number;
	total_unignored_diffs: number;
	total_ignored_diffs: number;
	diffs_truncated: boolean;
	body_comparison: BodyComparisonResult;
}

export interface LoadedCaseWithBodies {
	casePath: string;
	caseRelativePath: string;
	caseSha256: string;
	caseSizeBytes: number;
	document: ReplayCaseV1;
	requestBodyBuffer: Buffer | null;
	responseBodyBuffer: Buffer | null;
}

export interface NetworkCompareReportV1 {
	schema_version: "1";
	workflow_id: string;
	step_id: string;
	run_id: string;
	created_at: string;
	left_case: {
		path: string;
		sha256: string;
		case_id: string;
		source_path: string;
		source_sha256: string;
		source_format: ReplayCaseSourceFormat;
	};
	right_case: {
		path: string;
		sha256: string;
		case_id: string;
		source_path: string;
		source_sha256: string;
		source_format: ReplayCaseSourceFormat;
	};
	comparison_config: {
		ignore_json_pointers: string[];
		compare_headers: string[];
		assertions: ReplayJsonAssertion[];
	};
	request_comparison: RequestComparisonResult;
	response_comparison: ResponseComparisonResult;
	assertion_results: ReplayJsonAssertionResult[];
	assertions_passed: boolean;
	independent_reproduction_certified: false;
	note: string;
}

export const MAX_CASE_FILE_BYTES = 1024 * 1024;
export const MAX_INLINE_DIFF_ENTRIES = 50;
export const MAX_INLINE_DIFF_BYTES = 16 * 1024;
export const MAX_REPORT_DIFF_ENTRIES = 500;
const MAX_VALUE_PREVIEW_CHARS = 160;
const SHA256_HEX_PATTERN = /^[a-fA-F0-9]{64}$/;

const ALLOWED_HTTP_METHODS: Record<string, true> = {
	GET: true,
	POST: true,
	PUT: true,
	DELETE: true,
	PATCH: true,
	HEAD: true,
	OPTIONS: true,
};

const VALID_JSON_VALUE_TYPES: Record<JsonValueType, true> = {
	null: true,
	boolean: true,
	number: true,
	string: true,
	array: true,
	object: true,
};

const VALID_REPRESENTATIONS: Record<ReplayBodyRepresentation, true> = {
	none: true,
	captured_raw_bytes: true,
	decoded_entity_bytes: true,
	text_reencoded: true,
};

const VALID_COMPLETENESS: Record<ReplayBodyCompleteness, true> = {
	empty: true,
	complete: true,
	truncated: true,
	missing: true,
};

const VALID_SOURCE_FORMATS: Record<ReplayCaseSourceFormat, true> = {
	har: true,
	mitm: true,
	generated: true,
};

const strictUtf8Decoder = new TextDecoder("utf-8", { fatal: true });

// RFC 6901 JSON Pointer 解析与严格深比较

export function escapeJsonPointerToken(token: string | number): string {
	return String(token).replace(/~/g, "~0").replace(/\//g, "~1");
}

export function formatJsonPointer(tokens: ReadonlyArray<string | number>): string {
	return tokens.length === 0 ? "" : `/${tokens.map(escapeJsonPointerToken).join("/")}`;
}

export function parseJsonPointer(pointer: string, label = "JSON Pointer"): string[] {
	if (typeof pointer !== "string") {
		throw new ToolError(`Invalid ${label}: must be a string`);
	}
	if (pointer === "") return [];
	if (!pointer.startsWith("/")) {
		throw new ToolError(
			`Invalid ${label} '${pointer}': must be empty string '' (root) or start with '/' per RFC 6901`,
		);
	}
	const decoded: string[] = [];
	for (const raw of pointer.slice(1).split("/")) {
		for (let i = 0; i < raw.length; i++) {
			if (raw[i] === "~") {
				const next = raw[i + 1];
				if (next !== "0" && next !== "1") {
					throw new ToolError(
						`Invalid ${label} '${pointer}': invalid escape sequence '~${next ?? ""}' (RFC 6901 requires '~0' for '~' and '~1' for '/')`,
					);
				}
				i++;
			}
		}
		decoded.push(raw.replace(/~1/g, "/").replace(/~0/g, "~"));
	}
	return decoded;
}

export function resolveJsonPointer(root: unknown, pointer: string): { exists: boolean; value: unknown } {
	let current: unknown = root;
	for (const token of parseJsonPointer(pointer)) {
		if (current === null || typeof current !== "object") {
			return { exists: false, value: undefined };
		}
		if (Array.isArray(current)) {
			if (!/^(0|[1-9][0-9]*)$/.test(token)) return { exists: false, value: undefined };
			const index = Number(token);
			if (!Number.isSafeInteger(index) || index < 0 || index >= current.length) {
				return { exists: false, value: undefined };
			}
			current = current[index];
			continue;
		}
		const obj = current as Record<string, unknown>;
		if (!Object.hasOwn(obj, token)) return { exists: false, value: undefined };
		current = obj[token];
	}
	return { exists: true, value: current };
}

export function getJsonValueType(value: unknown): JsonValueType {
	if (value === null) return "null";
	if (Array.isArray(value)) return "array";
	switch (typeof value) {
		case "boolean":
			return "boolean";
		case "number":
			return "number";
		case "string":
			return "string";
		default:
			return "object";
	}
}

export function deepStrictJsonEqual(left: unknown, right: unknown): boolean {
	const leftType = getJsonValueType(left);
	if (leftType !== getJsonValueType(right)) return false;
	if (leftType === "null") return true;
	if (leftType === "boolean" || leftType === "number" || leftType === "string") {
		return Object.is(left, right);
	}
	if (leftType === "array") {
		const lArr = left as unknown[];
		const rArr = right as unknown[];
		return lArr.length === rArr.length && lArr.every((v, i) => deepStrictJsonEqual(v, rArr[i]));
	}
	const lObj = left as Record<string, unknown>;
	const rObj = right as Record<string, unknown>;
	const lKeys = Object.keys(lObj);
	if (lKeys.length !== Object.keys(rObj).length) return false;
	return lKeys.every(k => Object.hasOwn(rObj, k) && deepStrictJsonEqual(lObj[k], rObj[k]));
}

function formatSafeJsonPreview(value: unknown): string {
	let raw: string;
	try {
		raw =
			typeof value === "string"
				? JSON.stringify(redactSecrets(redactEvidenceText(value)))
				: redactSecrets(redactEvidenceText(deterministicJsonStringify(value)));
	} catch {
		raw = String(value);
	}
	return raw.length > MAX_VALUE_PREVIEW_CHARS ? `${raw.slice(0, MAX_VALUE_PREVIEW_CHARS)}...(truncated)` : raw;
}

export function validateComparisonOptions(options: {
	ignoreJsonPointers?: string[];
	compareHeaders?: string[];
	assertions?: ReplayJsonAssertion[];
}): {
	ignoreJsonPointers: string[];
	compareHeaders: string[];
	assertions: ReplayJsonAssertion[];
} {
	const ignoreJsonPointers: string[] = [];
	const seenPointers = new Set<string>();
	if (options.ignoreJsonPointers !== undefined) {
		if (!Array.isArray(options.ignoreJsonPointers)) {
			throw new ToolError("ignore_json_pointers must be an array of RFC 6901 JSON Pointer strings");
		}
		for (const ptr of options.ignoreJsonPointers) {
			parseJsonPointer(ptr, "ignore_json_pointers entry");
			if (!seenPointers.has(ptr)) {
				seenPointers.add(ptr);
				ignoreJsonPointers.push(ptr);
			}
		}
	}

	const compareHeaders: string[] = [];
	const seenHeaders = new Set<string>();
	if (options.compareHeaders !== undefined) {
		if (!Array.isArray(options.compareHeaders)) {
			throw new ToolError("compare_headers must be an array of HTTP header names");
		}
		for (const rawHeader of options.compareHeaders) {
			if (typeof rawHeader !== "string" || rawHeader.trim().length === 0 || /[\r\n\0:]/.test(rawHeader)) {
				throw new ToolError(`Invalid header name '${String(rawHeader)}' in compare_headers`);
			}
			const trimmed = rawHeader.trim();
			const lower = trimmed.toLowerCase();
			if (!seenHeaders.has(lower)) {
				seenHeaders.add(lower);
				compareHeaders.push(trimmed);
			}
		}
	}

	const assertions: ReplayJsonAssertion[] = [];
	if (options.assertions !== undefined) {
		if (!Array.isArray(options.assertions)) {
			throw new ToolError("assertions must be an array of assertion objects");
		}
		for (let i = 0; i < options.assertions.length; i++) {
			const item = options.assertions[i];
			if (!isRecord(item) || typeof item.pointer !== "string") {
				throw new ToolError(`Invalid assertion at index ${i}: must have string RFC 6901 'pointer'`);
			}
			parseJsonPointer(item.pointer, `assertions[${i}].pointer`);
			const hasExists = item.exists !== undefined;
			const hasType = item.type !== undefined;
			const hasEq = Object.hasOwn(item, "eq") && item.eq !== undefined;
			if (!hasExists && !hasType && !hasEq) {
				throw new ToolError(
					`Invalid assertion for pointer '${item.pointer}' at index ${i}: must specify at least one of 'eq', 'type', or 'exists'`,
				);
			}
			if (hasExists && typeof item.exists !== "boolean") {
				throw new ToolError(`Invalid assertion for pointer '${item.pointer}': 'exists' must be a boolean`);
			}
			if (hasType && (typeof item.type !== "string" || !Object.hasOwn(VALID_JSON_VALUE_TYPES, item.type))) {
				throw new ToolError(
					`Invalid assertion for pointer '${item.pointer}': 'type' must be one of null, boolean, number, string, array, object`,
				);
			}
			if (item.target !== undefined && (typeof item.target !== "string" || item.target.trim().length === 0)) {
				throw new ToolError(`Invalid assertion for pointer '${item.pointer}': 'target' must be a non-empty string`);
			}
			assertions.push({
				pointer: item.pointer,
				...(item.target !== undefined ? { target: item.target.trim() } : {}),
				...(hasExists ? { exists: item.exists as boolean } : {}),
				...(hasType ? { type: item.type as JsonValueType } : {}),
				...(hasEq ? { eq: item.eq } : {}),
			});
		}
	}

	return { ignoreJsonPointers, compareHeaders, assertions };
}

function findMatchingIgnorePointer(pointer: string, ignorePointers: readonly string[]): string | undefined {
	for (const ig of ignorePointers) {
		if (ig === "" || pointer === ig || pointer.startsWith(`${ig}/`)) return ig;
	}
	return undefined;
}

function collectJsonDiffsRecursive(
	left: unknown,
	right: unknown,
	currentPointer: string,
	ignorePointers: readonly string[],
	out: JsonFieldDiffEntry[],
): void {
	const matchedIgnore = findMatchingIgnorePointer(currentPointer, ignorePointers);
	const isIgnored = matchedIgnore !== undefined;
	const leftType = getJsonValueType(left);
	const rightType = getJsonValueType(right);

	if (leftType !== rightType) {
		out.push({
			pointer: currentPointer,
			kind: "type_mismatch",
			left_type: leftType,
			right_type: rightType,
			left_preview: formatSafeJsonPreview(left),
			right_preview: formatSafeJsonPreview(right),
			ignored: isIgnored,
			...(matchedIgnore !== undefined ? { matched_ignore_pointer: matchedIgnore } : {}),
		});
		return;
	}
	if (leftType === "null") return;
	if (leftType === "boolean" || leftType === "number" || leftType === "string") {
		if (!Object.is(left, right)) {
			out.push({
				pointer: currentPointer,
				kind: "value_mismatch",
				left_type: leftType,
				right_type: rightType,
				left_preview: formatSafeJsonPreview(left),
				right_preview: formatSafeJsonPreview(right),
				ignored: isIgnored,
				...(matchedIgnore !== undefined ? { matched_ignore_pointer: matchedIgnore } : {}),
			});
		}
		return;
	}

	if (leftType === "array") {
		// 严格按索引顺序比较数组元素，禁止排序
		const lArr = left as unknown[];
		const rArr = right as unknown[];
		const maxLen = Math.max(lArr.length, rArr.length);
		for (let i = 0; i < maxLen; i++) {
			const childPtr = `${currentPointer}/${i}`;
			const childIgnore = findMatchingIgnorePointer(childPtr, ignorePointers);
			if (i >= lArr.length) {
				out.push({
					pointer: childPtr,
					kind: "added",
					right_type: getJsonValueType(rArr[i]),
					right_preview: formatSafeJsonPreview(rArr[i]),
					ignored: childIgnore !== undefined,
					...(childIgnore !== undefined ? { matched_ignore_pointer: childIgnore } : {}),
				});
			} else if (i >= rArr.length) {
				out.push({
					pointer: childPtr,
					kind: "removed",
					left_type: getJsonValueType(lArr[i]),
					left_preview: formatSafeJsonPreview(lArr[i]),
					ignored: childIgnore !== undefined,
					...(childIgnore !== undefined ? { matched_ignore_pointer: childIgnore } : {}),
				});
			} else {
				collectJsonDiffsRecursive(lArr[i], rArr[i], childPtr, ignorePointers, out);
			}
		}
		return;
	}

	const lObj = left as Record<string, unknown>;
	const rObj = right as Record<string, unknown>;
	for (const key of Array.from(new Set([...Object.keys(lObj), ...Object.keys(rObj)])).sort()) {
		const childPtr = `${currentPointer}/${escapeJsonPointerToken(key)}`;
		const childIgnore = findMatchingIgnorePointer(childPtr, ignorePointers);
		const inLeft = Object.hasOwn(lObj, key);
		const inRight = Object.hasOwn(rObj, key);
		if (!inLeft && inRight) {
			out.push({
				pointer: childPtr,
				kind: "added",
				right_type: getJsonValueType(rObj[key]),
				right_preview: formatSafeJsonPreview(rObj[key]),
				ignored: childIgnore !== undefined,
				...(childIgnore !== undefined ? { matched_ignore_pointer: childIgnore } : {}),
			});
		} else if (inLeft && !inRight) {
			out.push({
				pointer: childPtr,
				kind: "removed",
				left_type: getJsonValueType(lObj[key]),
				left_preview: formatSafeJsonPreview(lObj[key]),
				ignored: childIgnore !== undefined,
				...(childIgnore !== undefined ? { matched_ignore_pointer: childIgnore } : {}),
			});
		} else {
			collectJsonDiffsRecursive(lObj[key], rObj[key], childPtr, ignorePointers, out);
		}
	}
}

function boundDiffEntries(
	entries: readonly JsonFieldDiffEntry[],
	maxEntries: number,
	maxBytes: number,
): { bounded: JsonFieldDiffEntry[]; truncated: boolean } {
	const bounded: JsonFieldDiffEntry[] = [];
	let currentBytes = 0;
	for (const entry of entries) {
		if (bounded.length >= maxEntries) return { bounded, truncated: true };
		const entryBytes = Buffer.byteLength(JSON.stringify(entry), "utf8");
		if (bounded.length > 0 && currentBytes + entryBytes > maxBytes) return { bounded, truncated: true };
		bounded.push(entry);
		currentBytes += entryBytes;
	}
	return { bounded, truncated: false };
}

function tryParseStrictUtf8Json(buffer: Buffer | null): { valid: true; value: unknown } | { valid: false } {
	if (!buffer || buffer.byteLength === 0) return { valid: false };
	try {
		return { valid: true, value: JSON.parse(strictUtf8Decoder.decode(buffer)) };
	} catch {
		return { valid: false };
	}
}

// 消息体双层对比（raw_equal 与 normalized_equal 独立返回，保留被忽略原始差异）

export function compareBodies(options: {
	leftRef: ReplayBodyRef;
	leftBuffer: Buffer | null;
	rightRef: ReplayBodyRef;
	rightBuffer: Buffer | null;
	ignoreJsonPointers?: readonly string[];
	maxDiffEntries?: number;
	maxDiffBytes?: number;
}): BodyComparisonResult {
	const ignorePointers = [...(options.ignoreJsonPointers ?? [])];
	const maxEntries = options.maxDiffEntries ?? MAX_INLINE_DIFF_ENTRIES;
	const maxBytes = options.maxDiffBytes ?? MAX_INLINE_DIFF_BYTES;

	const leftComp = options.leftRef.completeness;
	const rightComp = options.rightRef.completeness;
	const leftRep = options.leftRef.representation;
	const rightRep = options.rightRef.representation;
	const leftSize = options.leftRef.size_bytes;
	const rightSize = options.rightRef.size_bytes;
	const leftSha = options.leftRef.sha256;
	const rightSha = options.rightRef.sha256;
	const lengthDelta = rightSize - leftSize;

	const baseResult = (
		rawEqual: ComparisonTruthValue,
		normalizedEqual: ComparisonTruthValue,
		reason?: string,
		rawJsonEqual?: ComparisonTruthValue,
	): BodyComparisonResult => ({
		raw_equal: rawEqual,
		normalized_equal: normalizedEqual,
		...(rawJsonEqual !== undefined ? { raw_json_equal: rawJsonEqual } : {}),
		left_representation: leftRep,
		right_representation: rightRep,
		left_completeness: leftComp,
		right_completeness: rightComp,
		left_size_bytes: leftSize,
		right_size_bytes: rightSize,
		left_sha256: leftSha,
		right_sha256: rightSha,
		length_delta: lengthDelta,
		...(reason ? { comparison_reason: reason } : {}),
		applied_ignore_pointers: ignorePointers,
		field_diffs: [],
		ignored_diffs: [],
		total_raw_diffs: 0,
		total_unignored_diffs: 0,
		total_ignored_diffs: 0,
		diffs_truncated: false,
	});

	if (leftComp === "truncated" || leftComp === "missing" || rightComp === "truncated" || rightComp === "missing") {
		return baseResult("unknown", "unknown", `incomplete_body (left=${leftComp}, right=${rightComp})`);
	}
	if (leftComp === "empty" && rightComp === "empty" && leftSize === 0 && rightSize === 0) {
		return baseResult("not_applicable", "not_applicable", "no_body");
	}
	if (leftSize === 0 || rightSize === 0 || leftComp === "empty" || rightComp === "empty") {
		return baseResult(false, "not_applicable", "empty_vs_non_empty");
	}

	const leftCE = (options.leftRef.content_encoding ?? "").trim().toLowerCase();
	const rightCE = (options.rightRef.content_encoding ?? "").trim().toLowerCase();
	const effectiveLeftCE = leftCE === "identity" || leftCE === "none" ? "" : leftCE;
	const effectiveRightCE = rightCE === "identity" || rightCE === "none" ? "" : rightCE;

	if (leftRep !== rightRep || effectiveLeftCE !== effectiveRightCE) {
		return baseResult(
			"unknown",
			"unknown",
			`representation_mismatch (left=${leftRep}${effectiveLeftCE ? `[${effectiveLeftCE}]` : ""}, right=${rightRep}${effectiveRightCE ? `[${effectiveRightCE}]` : ""})`,
		);
	}

	let rawEqual: ComparisonTruthValue;
	if (leftRep === "text_reencoded") {
		rawEqual = "unknown";
	} else if (leftSha && rightSha) {
		rawEqual = leftSha.toLowerCase() === rightSha.toLowerCase();
	} else if (options.leftBuffer && options.rightBuffer) {
		rawEqual = Buffer.compare(options.leftBuffer, options.rightBuffer) === 0;
	} else {
		rawEqual = "unknown";
	}

	if (effectiveLeftCE && leftRep === "captured_raw_bytes") {
		return baseResult(rawEqual, "unknown", `compressed_raw_bytes (content_encoding=${effectiveLeftCE})`);
	}

	const leftParsed = tryParseStrictUtf8Json(options.leftBuffer);
	const rightParsed = tryParseStrictUtf8Json(options.rightBuffer);
	if (!leftParsed.valid || !rightParsed.valid) {
		return baseResult(
			rawEqual,
			"not_applicable",
			leftRep === "text_reencoded" ? "text_reencoded_invalid_json" : "invalid_json",
			"not_applicable",
		);
	}

	const allDiffs: JsonFieldDiffEntry[] = [];
	collectJsonDiffsRecursive(leftParsed.value, rightParsed.value, "", ignorePointers, allDiffs);
	const unignoredAll = allDiffs.filter(d => !d.ignored);
	const ignoredAll = allDiffs.filter(d => d.ignored);
	const boundedUnignored = boundDiffEntries(unignoredAll, maxEntries, maxBytes);
	const boundedIgnored = boundDiffEntries(ignoredAll, maxEntries, maxBytes);

	return {
		raw_equal: rawEqual,
		normalized_equal: unignoredAll.length === 0,
		raw_json_equal: allDiffs.length === 0,
		left_representation: leftRep,
		right_representation: rightRep,
		left_completeness: leftComp,
		right_completeness: rightComp,
		left_size_bytes: leftSize,
		right_size_bytes: rightSize,
		left_sha256: leftSha,
		right_sha256: rightSha,
		length_delta: lengthDelta,
		...(leftRep === "text_reencoded" ? { comparison_reason: "text_reencoded_raw_bytes_unverified" } : {}),
		applied_ignore_pointers: ignorePointers,
		field_diffs: boundedUnignored.bounded,
		ignored_diffs: boundedIgnored.bounded,
		total_raw_diffs: allDiffs.length,
		total_unignored_diffs: unignoredAll.length,
		total_ignored_diffs: ignoredAll.length,
		diffs_truncated: boundedUnignored.truncated || boundedIgnored.truncated,
	};
}

function maskHeaderValueForDiff(name: string, value: string): string {
	return SENSITIVE_HEADER_NAME_PATTERN.test(name.toLowerCase())
		? "[REDACTED]"
		: redactSecrets(redactEvidenceText(value));
}

export function compareHeaderLists(options: {
	leftHeaders: readonly ReplayHeaderEntry[];
	rightHeaders: readonly ReplayHeaderEntry[];
	selectedHeaders?: readonly string[];
	allowCombinedWireComparison?: boolean;
}): {
	allHeadersEqual: boolean;
	duplicateHeadersEqual: boolean;
	selectedHeadersEqual: boolean;
	comparedHeaders: string[];
	headerDiffs: HeaderComparisonEntry[];
} {
	const leftByLower = new Map<string, string[]>();
	const rightByLower = new Map<string, string[]>();
	const displayNameByLower = new Map<string, string>();

	for (const h of options.leftHeaders) {
		const lower = h.name.toLowerCase();
		if (!displayNameByLower.has(lower)) displayNameByLower.set(lower, h.name);
		const arr = leftByLower.get(lower) ?? [];
		arr.push(maskHeaderValueForDiff(h.name, h.value));
		leftByLower.set(lower, arr);
	}
	for (const h of options.rightHeaders) {
		const lower = h.name.toLowerCase();
		if (!displayNameByLower.has(lower)) displayNameByLower.set(lower, h.name);
		const arr = rightByLower.get(lower) ?? [];
		arr.push(maskHeaderValueForDiff(h.name, h.value));
		rightByLower.set(lower, arr);
	}

	const valuesEqual = (lVals: string[], rVals: string[]): boolean => {
		if (lVals.length === rVals.length && lVals.every((v, idx) => v === rVals[idx])) return true;
		if (options.allowCombinedWireComparison && lVals.length > 0 && rVals.length > 0) {
			return lVals.join(", ") === rVals.join(", ");
		}
		return false;
	};

	const allHeadersEqual =
		options.leftHeaders.length === options.rightHeaders.length &&
		options.leftHeaders.every(
			(lh, idx) =>
				lh.name.toLowerCase() === options.rightHeaders[idx]!.name.toLowerCase() &&
				maskHeaderValueForDiff(lh.name, lh.value) ===
					maskHeaderValueForDiff(options.rightHeaders[idx]!.name, options.rightHeaders[idx]!.value),
		);

	const allLowerKeys = Array.from(new Set([...leftByLower.keys(), ...rightByLower.keys()])).sort();
	let duplicateHeadersEqual = true;
	for (const k of allLowerKeys) {
		const lVals = leftByLower.get(k) ?? [];
		const rVals = rightByLower.get(k) ?? [];
		if ((lVals.length > 1 || rVals.length > 1) && !valuesEqual(lVals, rVals)) {
			duplicateHeadersEqual = false;
		}
	}

	const hasExplicitSelection = options.selectedHeaders !== undefined && options.selectedHeaders.length > 0;
	const targetKeys = hasExplicitSelection ? options.selectedHeaders!.map(h => h.toLowerCase()) : allLowerKeys;
	const headerDiffs: HeaderComparisonEntry[] = [];
	const comparedHeaders: string[] = [];
	let selectedHeadersEqual = true;

	for (const lowerKey of targetKeys) {
		const displayName =
			options.selectedHeaders?.find(h => h.toLowerCase() === lowerKey) ??
			displayNameByLower.get(lowerKey) ??
			lowerKey;
		comparedHeaders.push(displayName);
		const lVals = leftByLower.get(lowerKey) ?? [];
		const rVals = rightByLower.get(lowerKey) ?? [];
		const eq = valuesEqual(lVals, rVals);
		if (!eq) selectedHeadersEqual = false;
		if (hasExplicitSelection || !eq) {
			headerDiffs.push({ name: displayName, left_values: lVals, right_values: rVals, equal: eq });
		}
	}

	return {
		allHeadersEqual,
		duplicateHeadersEqual,
		selectedHeadersEqual: hasExplicitSelection ? selectedHeadersEqual : allHeadersEqual,
		comparedHeaders: hasExplicitSelection ? comparedHeaders : [],
		headerDiffs,
	};
}

export function evaluateJsonAssertionsForTarget(options: {
	targetName: string;
	bodyRef: ReplayBodyRef;
	bodyBuffer: Buffer | null;
	assertions: readonly ReplayJsonAssertion[];
}): ReplayJsonAssertionResult[] {
	if (options.assertions.length === 0) return [];

	const comp = options.bodyRef.completeness;
	const rep = options.bodyRef.representation;
	const ce = (options.bodyRef.content_encoding ?? "").trim().toLowerCase();
	const hasCompressedRaw = Boolean(ce && ce !== "identity" && ce !== "none" && rep === "captured_raw_bytes");

	if (comp === "truncated" || comp === "missing" || hasCompressedRaw) {
		return options.assertions.map(a => ({
			pointer: a.pointer,
			target: options.targetName,
			status: "unknown",
			passed: false,
			...(a.exists !== undefined ? { expected_exists: a.exists } : {}),
			...(a.type !== undefined ? { expected_type: a.type } : {}),
			...(a.eq !== undefined ? { expected_preview: formatSafeJsonPreview(a.eq) } : {}),
			reason: hasCompressedRaw ? `compressed_raw_bytes (${ce})` : `incomplete_body (${comp})`,
		}));
	}

	if (comp === "empty" || options.bodyRef.size_bytes === 0) {
		return options.assertions.map(a => ({
			pointer: a.pointer,
			target: options.targetName,
			status: "not_applicable",
			passed: false,
			...(a.exists !== undefined ? { expected_exists: a.exists } : {}),
			...(a.type !== undefined ? { expected_type: a.type } : {}),
			...(a.eq !== undefined ? { expected_preview: formatSafeJsonPreview(a.eq) } : {}),
			reason: "no_body",
		}));
	}

	const parsed = tryParseStrictUtf8Json(options.bodyBuffer);
	if (!parsed.valid) {
		return options.assertions.map(a => ({
			pointer: a.pointer,
			target: options.targetName,
			status: "not_applicable",
			passed: false,
			...(a.exists !== undefined ? { expected_exists: a.exists } : {}),
			...(a.type !== undefined ? { expected_type: a.type } : {}),
			...(a.eq !== undefined ? { expected_preview: formatSafeJsonPreview(a.eq) } : {}),
			reason: "invalid_json",
		}));
	}

	return options.assertions.map(a => {
		const resolved = resolveJsonPointer(parsed.value, a.pointer);
		const actualType = resolved.exists ? getJsonValueType(resolved.value) : undefined;
		const actualPreview = resolved.exists ? formatSafeJsonPreview(resolved.value) : undefined;
		const expectedPreview = a.eq !== undefined ? formatSafeJsonPreview(a.eq) : undefined;
		const failureReasons: string[] = [];

		if (a.exists !== undefined && resolved.exists !== a.exists) {
			failureReasons.push(`expected exists=${a.exists}, got exists=${resolved.exists}`);
		}
		if (a.type !== undefined) {
			if (!resolved.exists) {
				failureReasons.push(`expected type='${a.type}', but pointer '${a.pointer}' does not exist`);
			} else if (actualType !== a.type) {
				failureReasons.push(`expected type='${a.type}', got type='${actualType}'`);
			}
		}
		if (a.eq !== undefined) {
			if (!resolved.exists) {
				failureReasons.push(`expected eq=${expectedPreview}, but pointer '${a.pointer}' does not exist`);
			} else if (!deepStrictJsonEqual(resolved.value, a.eq)) {
				failureReasons.push(`expected eq=${expectedPreview}, got ${actualPreview}`);
			}
		}

		const passed = failureReasons.length === 0;
		return {
			pointer: a.pointer,
			target: options.targetName,
			status: passed ? "passed" : "failed",
			passed,
			exists: resolved.exists,
			...(a.exists !== undefined ? { expected_exists: a.exists } : {}),
			...(actualType !== undefined ? { actual_type: actualType } : {}),
			...(a.type !== undefined ? { expected_type: a.type } : {}),
			...(actualPreview !== undefined ? { actual_preview: actualPreview } : {}),
			...(expectedPreview !== undefined ? { expected_preview: expectedPreview } : {}),
			...(failureReasons.length > 0 ? { reason: failureReasons.join("; ") } : {}),
		};
	});
}

// 单一标准 ReplayCase v1 严格解析与文件哈希绑定校验（无兼容别名）

function validateHeaderEntries(raw: unknown, label: string): ReplayHeaderEntry[] {
	if (!Array.isArray(raw)) {
		throw new ToolError(`Invalid ${label}: must be an ordered array of { name, value } objects`);
	}
	return raw.map((item, i) => {
		if (!isRecord(item) || typeof item.name !== "string" || typeof item.value !== "string") {
			throw new ToolError(`Invalid ${label}[${i}]: must have string 'name' and 'value'`);
		}
		if (item.name.trim().length === 0 || /[\r\n\0]/.test(item.name) || /[\r\n\0]/.test(item.value)) {
			throw new ToolError(`Invalid ${label}[${i}]: header name/value contains control characters or is empty`);
		}
		return { name: item.name, value: item.value };
	});
}

function validateBodyRefShape(raw: unknown, label: string): ReplayBodyRef {
	if (!isRecord(raw)) {
		throw new ToolError(`Invalid ${label}: must be a ReplayBodyRef object`);
	}
	const representation = raw.representation;
	if (typeof representation !== "string" || !Object.hasOwn(VALID_REPRESENTATIONS, representation)) {
		throw new ToolError(
			`Invalid ${label}.representation '${String(representation)}': must be one of none, captured_raw_bytes, decoded_entity_bytes, text_reencoded`,
		);
	}
	const completeness = raw.completeness;
	if (typeof completeness !== "string" || !Object.hasOwn(VALID_COMPLETENESS, completeness)) {
		throw new ToolError(
			`Invalid ${label}.completeness '${String(completeness)}': must be one of empty, complete, truncated, missing`,
		);
	}
	if (typeof raw.size_bytes !== "number" || !Number.isSafeInteger(raw.size_bytes) || raw.size_bytes < 0) {
		throw new ToolError(`Invalid ${label}.size_bytes: must be a non-negative integer`);
	}
	const pathVal = raw.path;
	if (pathVal !== null && (typeof pathVal !== "string" || pathVal.trim().length === 0)) {
		throw new ToolError(`Invalid ${label}.path: must be a non-empty string or null`);
	}
	const shaVal = raw.sha256;
	if (shaVal !== null && (typeof shaVal !== "string" || !SHA256_HEX_PATTERN.test(shaVal))) {
		throw new ToolError(`Invalid ${label}.sha256: must be a 64-character hex SHA-256 string or null`);
	}

	if (completeness === "missing") {
		if (pathVal !== null || shaVal !== null || raw.size_bytes !== 0) {
			throw new ToolError(`Invalid ${label}: completeness 'missing' requires path=null, sha256=null, size_bytes=0`);
		}
	} else if (completeness === "empty") {
		if (raw.size_bytes !== 0 || representation !== "none") {
			throw new ToolError(`Invalid ${label}: completeness 'empty' requires size_bytes=0 and representation='none'`);
		}
		if ((pathVal === null) !== (shaVal === null)) {
			throw new ToolError(`Invalid ${label}: path and sha256 must both be null or both be non-null`);
		}
	} else if (raw.size_bytes > 0 && (pathVal === null || shaVal === null)) {
		throw new ToolError(
			`Invalid ${label}: completeness '${completeness}' with size_bytes=${raw.size_bytes} requires non-null path and sha256`,
		);
	}

	return {
		path: pathVal,
		sha256: shaVal ? shaVal.toLowerCase() : null,
		size_bytes: raw.size_bytes,
		...(typeof raw.declared_size_bytes === "number" ? { declared_size_bytes: raw.declared_size_bytes } : {}),
		...(typeof raw.decoded_entity_sha256 === "string"
			? { decoded_entity_sha256: raw.decoded_entity_sha256.toLowerCase() }
			: {}),
		...(typeof raw.decoded_entity_size_bytes === "number"
			? { decoded_entity_size_bytes: raw.decoded_entity_size_bytes }
			: {}),
		representation: representation as ReplayBodyRepresentation,
		completeness: completeness as ReplayBodyCompleteness,
		...(typeof raw.mime_type === "string" ? { mime_type: raw.mime_type } : {}),
		...(typeof raw.content_encoding === "string" ? { content_encoding: raw.content_encoding } : {}),
		...(typeof raw.note === "string" ? { note: raw.note } : {}),
	};
}

function validateCredentialSlots(raw: unknown, label: string): ReplayCredentialSlot[] {
	if (!Array.isArray(raw)) {
		throw new ToolError(`Invalid ${label}: must be an array of credential slot objects`);
	}
	return raw.map((s, i) => {
		if (!isRecord(s)) throw new ToolError(`Invalid ${label}[${i}]: must be an object`);
		const loc = s.location;
		if (loc !== "header" && loc !== "cookie" && loc !== "query" && loc !== "url_userinfo" && loc !== "body") {
			throw new ToolError(`Invalid ${label}[${i}].location '${String(loc)}'`);
		}
		const binding = s.replay_binding;
		if (binding !== "auth_header_env" && binding !== "header_env_map" && binding !== "blocked_prerequisite") {
			throw new ToolError(`Invalid ${label}[${i}].replay_binding '${String(binding)}'`);
		}
		if (typeof s.name !== "string" || s.name.trim().length === 0) {
			throw new ToolError(`Invalid ${label}[${i}].name: must be a non-empty string`);
		}
		if (typeof s.env_var !== "string" || s.env_var.trim().length === 0) {
			throw new ToolError(`Invalid ${label}[${i}].env_var: must be a non-empty string`);
		}
		if (typeof s.required !== "boolean") {
			throw new ToolError(`Invalid ${label}[${i}].required: must be a boolean`);
		}
		return {
			location: loc,
			name: s.name,
			env_var: s.env_var,
			replay_binding: binding,
			required: s.required,
			...(typeof s.scheme === "string" ? { scheme: s.scheme } : {}),
			...(Array.isArray(s.cookie_names)
				? { cookie_names: s.cookie_names.filter((c): c is string => typeof c === "string") }
				: {}),
			...(typeof s.occurrences === "number" ? { occurrences: s.occurrences } : {}),
			reason: typeof s.reason === "string" ? s.reason : "",
		};
	});
}

function validateSourceShape(raw: unknown, label: string): ReplayCaseSource {
	if (!isRecord(raw)) throw new ToolError(`Invalid ${label}: must be a ReplayCaseSource object`);
	if (typeof raw.path !== "string" || raw.path.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.path: must be a non-empty string`);
	}
	if (typeof raw.sha256 !== "string" || !SHA256_HEX_PATTERN.test(raw.sha256)) {
		throw new ToolError(`Invalid ${label}.sha256: must be a 64-character hex SHA-256 string`);
	}
	if (typeof raw.size_bytes !== "number" || !Number.isSafeInteger(raw.size_bytes) || raw.size_bytes < 0) {
		throw new ToolError(`Invalid ${label}.size_bytes: must be a non-negative integer`);
	}
	if (typeof raw.format !== "string" || !Object.hasOwn(VALID_SOURCE_FORMATS, raw.format)) {
		throw new ToolError(`Invalid ${label}.format '${String(raw.format)}': must be 'har', 'mitm', or 'generated'`);
	}
	if (typeof raw.entry_id !== "string" || raw.entry_id.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.entry_id: must be a non-empty string`);
	}
	if (typeof raw.entry_index !== "number" || !Number.isInteger(raw.entry_index) || raw.entry_index < 0) {
		throw new ToolError(`Invalid ${label}.entry_index: must be a non-negative integer`);
	}
	if (!isRecord(raw.selector) || (raw.selector.kind !== "entry_index" && raw.selector.kind !== "flow_id")) {
		throw new ToolError(`Invalid ${label}.selector: must specify kind 'entry_index' or 'flow_id'`);
	}
	return {
		path: raw.path,
		sha256: raw.sha256.toLowerCase(),
		size_bytes: raw.size_bytes,
		format: raw.format as ReplayCaseSourceFormat,
		entry_id: raw.entry_id,
		entry_index: raw.entry_index,
		selector: {
			kind: raw.selector.kind,
			value: raw.selector.value as number | string,
		},
	};
}

export function parseReplayCaseV1(rawText: string, label: string): ReplayCaseV1 {
	let parsed: unknown;
	try {
		parsed = JSON.parse(rawText);
	} catch {
		throw new ToolError(`Failed to parse ${label}: invalid JSON syntax`);
	}
	if (!isRecord(parsed)) {
		throw new ToolError(`Invalid ${label}: root value must be a ReplayCase v1 JSON object`);
	}
	if (parsed.schema_version !== "1") {
		throw new ToolError(
			`Unsupported or missing schema_version '${String(parsed.schema_version)}' in ${label}: expected schema_version '1'`,
		);
	}
	if (typeof parsed.case_id !== "string" || parsed.case_id.trim().length === 0) {
		throw new ToolError(`Invalid ${label}: 'case_id' must be a non-empty string`);
	}
	if (typeof parsed.workflow_id !== "string" || parsed.workflow_id.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.workflow_id: must be a non-empty string`);
	}
	if (typeof parsed.step_id !== "string" || parsed.step_id.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.step_id: must be a non-empty string`);
	}
	if (typeof parsed.run_id !== "string" || parsed.run_id.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.run_id: must be a non-empty string`);
	}
	if (typeof parsed.created_at !== "string" || parsed.created_at.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.created_at: must be a non-empty ISO timestamp string`);
	}
	if (!isRecord(parsed.request)) {
		throw new ToolError(
			`Invalid ${label}: missing canonical 'request' object (non-canonical aliases such as 'baseline_request' are refused)`,
		);
	}
	if (!isRecord(parsed.recorded_response)) {
		throw new ToolError(
			`Invalid ${label}: missing canonical 'recorded_response' object (non-canonical aliases such as 'response' are refused)`,
		);
	}
	if (typeof parsed.replay_ready !== "boolean") {
		throw new ToolError(`Invalid ${label}.replay_ready: must be a boolean`);
	}
	if (!Array.isArray(parsed.blocked_prerequisites)) {
		throw new ToolError(`Invalid ${label}.blocked_prerequisites: must be an array`);
	}

	const source = validateSourceShape(parsed.source, `${label}.source`);

	const rawReq = parsed.request;
	const method = typeof rawReq.method === "string" ? rawReq.method.trim().toUpperCase() : "";
	if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
		throw new ToolError(`Invalid ${label}.request.method '${String(rawReq.method)}'`);
	}
	if (typeof rawReq.url !== "string" || rawReq.url.trim().length === 0) {
		throw new ToolError(`Invalid ${label}.request.url: must be a non-empty URL string`);
	}
	try {
		const u = new URL(rawReq.url);
		if (u.protocol !== "http:" && u.protocol !== "https:") {
			throw new ToolError(`Invalid ${label}.request.url: must use http or https scheme`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
		throw new ToolError(`Invalid ${label}.request.url '${rawReq.url}': malformed URL`);
	}

	const reqHeaders = validateHeaderEntries(rawReq.headers, `${label}.request.headers`);
	const reqBody = validateBodyRefShape(rawReq.body, `${label}.request.body`);
	const credentialSlots = validateCredentialSlots(rawReq.credential_slots, `${label}.request.credential_slots`);

	const rawResp = parsed.recorded_response;
	const respBody = validateBodyRefShape(rawResp.body, `${label}.recorded_response.body`);
	const isUnrecordedGeneratedResponse =
		source.format === "generated" && rawResp.status === 0 && respBody.completeness === "missing";
	if (
		!isUnrecordedGeneratedResponse &&
		(typeof rawResp.status !== "number" ||
			!Number.isInteger(rawResp.status) ||
			rawResp.status < 100 ||
			rawResp.status > 599)
	) {
		throw new ToolError(`Invalid ${label}.recorded_response.status '${String(rawResp.status)}'`);
	}
	if (typeof rawResp.status_text !== "string") {
		throw new ToolError(`Invalid ${label}.recorded_response.status_text: must be a string`);
	}
	const respHeaders = validateHeaderEntries(rawResp.headers, `${label}.recorded_response.headers`);

	const blockedPrerequisites: ReplayPrerequisiteBlock[] = parsed.blocked_prerequisites.map((b, idx) => {
		if (!isRecord(b) || typeof b.code !== "string" || typeof b.message !== "string") {
			throw new ToolError(`Invalid ${label}.blocked_prerequisites[${idx}]`);
		}
		return { code: b.code as ReplayPrerequisiteBlock["code"], message: b.message };
	});

	return {
		schema_version: "1",
		case_id: parsed.case_id.trim(),
		workflow_id: parsed.workflow_id.trim(),
		step_id: parsed.step_id.trim(),
		run_id: parsed.run_id.trim(),
		created_at: parsed.created_at.trim(),
		source,
		request: {
			method,
			url: rawReq.url.trim(),
			...(typeof rawReq.http_version === "string" ? { http_version: rawReq.http_version } : {}),
			headers: reqHeaders,
			body: reqBody,
			credential_slots: credentialSlots,
		},
		recorded_response: {
			status: rawResp.status as number,
			status_text: rawResp.status_text,
			...(typeof rawResp.http_version === "string" ? { http_version: rawResp.http_version } : {}),
			headers: respHeaders,
			body: respBody,
		},
		replay_ready: parsed.replay_ready,
		blocked_prerequisites: blockedPrerequisites,
	};
}

export async function assertNotSymlinkCandidate(projectDir: string, rawPath: string, label: string): Promise<void> {
	const candidateAbs = path.resolve(projectDir, rawPath);
	try {
		const st = await fs.lstat(candidateAbs);
		if (st.isSymbolicLink()) {
			throw new ToolError(`Symlink escape violation: ${label} '${rawPath}' is a symbolic link.`);
		}
	} catch (err) {
		if (err instanceof ToolError) throw err;
	}
}

export async function loadAndVerifyCaseWithBodies(options: {
	projectDir: string;
	workspacePath?: string;
	workflowId: string;
	stepId: string;
	runId: string;
	caseFilePath: string;
	label: string;
	additionalInputPaths?: string[];
	outputPaths?: string[];
}): Promise<{
	loaded: LoadedCaseWithBodies;
	execution: LoadAnalysisExecutionResult;
}> {
	const resolvedProjectDir = path.resolve(options.projectDir);
	await assertNotSymlinkCandidate(resolvedProjectDir, options.caseFilePath, options.label);

	const initialExec = await loadAnalysisExecution({
		projectDir: resolvedProjectDir,
		workspaceDir: options.workspacePath,
		workflowId: options.workflowId,
		stepId: options.stepId,
		runId: options.runId,
		inputPaths: [options.caseFilePath, ...(options.additionalInputPaths ?? [])],
		outputPaths: options.outputPaths,
	});

	const caseInputRef: AnalysisFileRef | undefined = initialExec.inputRefs[0];
	if (!caseInputRef) {
		throw new ToolError(`Failed to resolve ${options.label} '${options.caseFilePath}'`);
	}

	const caseAbsPath = path.resolve(resolvedProjectDir, caseInputRef.path);
	const rawCaseBuf = await readRegularFileBoundedNoFollow(caseAbsPath, MAX_CASE_FILE_BYTES, options.label);
	const caseDoc = parseReplayCaseV1(rawCaseBuf.toString("utf8"), options.label);

	await assertNotSymlinkCandidate(resolvedProjectDir, caseDoc.source.path, `${options.label}.source.path`);
	const referencedPaths: string[] = [options.caseFilePath, caseDoc.source.path];

	if (caseDoc.request.body.path !== null) {
		await assertNotSymlinkCandidate(
			resolvedProjectDir,
			caseDoc.request.body.path,
			`${options.label}.request.body.path`,
		);
		referencedPaths.push(caseDoc.request.body.path);
	}
	if (caseDoc.recorded_response.body.path !== null) {
		await assertNotSymlinkCandidate(
			resolvedProjectDir,
			caseDoc.recorded_response.body.path,
			`${options.label}.recorded_response.body.path`,
		);
		referencedPaths.push(caseDoc.recorded_response.body.path);
	}
	for (const extra of options.additionalInputPaths ?? []) {
		await assertNotSymlinkCandidate(resolvedProjectDir, extra, "input file");
		referencedPaths.push(extra);
	}

	const fullExec = await loadAnalysisExecution({
		projectDir: resolvedProjectDir,
		workspaceDir: options.workspacePath,
		workflowId: options.workflowId,
		stepId: options.stepId,
		runId: options.runId,
		inputPaths: referencedPaths,
		outputPaths: options.outputPaths,
	});

	const refsByPath = new Map<string, AnalysisFileRef>(fullExec.inputRefs.map(r => [r.path, r]));
	const normSourceRel = path
		.relative(resolvedProjectDir, path.resolve(resolvedProjectDir, caseDoc.source.path))
		.replace(/\\/g, "/");
	const actualSourceRef = refsByPath.get(normSourceRel);
	if (!actualSourceRef) {
		throw new ToolError(
			`Source '${caseDoc.source.path}' referenced by ${options.label} could not be resolved in run inputs`,
		);
	}
	if (
		actualSourceRef.sha256.toLowerCase() !== caseDoc.source.sha256.toLowerCase() ||
		actualSourceRef.size_bytes !== caseDoc.source.size_bytes
	) {
		throw new ToolError(
			`Source hash/size drift in ${options.label} for '${caseDoc.source.path}': case recorded sha256=${caseDoc.source.sha256} (${caseDoc.source.size_bytes} bytes), actual on disk is sha256=${actualSourceRef.sha256} (${actualSourceRef.size_bytes} bytes)`,
		);
	}

	let requestBodyBuffer: Buffer | null = null;
	if (caseDoc.request.body.path !== null) {
		const reqBodyAbs = path.resolve(resolvedProjectDir, caseDoc.request.body.path);
		const buf = await readRegularFileBoundedNoFollow(
			reqBodyAbs,
			MAX_IMPORT_BODY_BYTES,
			`${options.label}.request.body`,
		);
		const hashed = hashBuffer(buf);
		if (
			hashed.sha256.toLowerCase() !== (caseDoc.request.body.sha256 ?? "").toLowerCase() ||
			hashed.size !== caseDoc.request.body.size_bytes
		) {
			throw new ToolError(
				`Request body hash/size mismatch in ${options.label} ('${caseDoc.request.body.path}'): case expected sha256=${caseDoc.request.body.sha256} (${caseDoc.request.body.size_bytes} bytes), actual sha256=${hashed.sha256} (${hashed.size} bytes)`,
			);
		}
		requestBodyBuffer = buf;
	} else if (caseDoc.request.body.completeness === "empty") {
		requestBodyBuffer = Buffer.alloc(0);
	}

	let responseBodyBuffer: Buffer | null = null;
	if (caseDoc.recorded_response.body.path !== null) {
		const respBodyAbs = path.resolve(resolvedProjectDir, caseDoc.recorded_response.body.path);
		const buf = await readRegularFileBoundedNoFollow(
			respBodyAbs,
			MAX_IMPORT_BODY_BYTES,
			`${options.label}.recorded_response.body`,
		);
		const hashed = hashBuffer(buf);
		if (
			hashed.sha256.toLowerCase() !== (caseDoc.recorded_response.body.sha256 ?? "").toLowerCase() ||
			hashed.size !== caseDoc.recorded_response.body.size_bytes
		) {
			throw new ToolError(
				`Recorded response body hash/size mismatch in ${options.label} ('${caseDoc.recorded_response.body.path}'): case expected sha256=${caseDoc.recorded_response.body.sha256} (${caseDoc.recorded_response.body.size_bytes} bytes), actual sha256=${hashed.sha256} (${hashed.size} bytes)`,
			);
		}
		responseBodyBuffer = buf;
	} else if (caseDoc.recorded_response.body.completeness === "empty") {
		responseBodyBuffer = Buffer.alloc(0);
	}

	return {
		loaded: {
			casePath: caseAbsPath,
			caseRelativePath: caseInputRef.path,
			caseSha256: caseInputRef.sha256,
			caseSizeBytes: caseInputRef.size_bytes,
			document: caseDoc,
			requestBodyBuffer,
			responseBodyBuffer,
		},
		execution: fullExec,
	};
}

function sanitizeUrlForComparisonDisplay(rawUrl: string): {
	parsed: URL;
	displayUrl: string;
	queryMap: Map<string, string[]>;
} {
	const parsed = new URL(rawUrl);
	const safeCopy = new URL(rawUrl);
	safeCopy.username = parsed.username ? "[REDACTED]" : "";
	safeCopy.password = parsed.password ? "[REDACTED]" : "";

	const queryMap = new Map<string, string[]>();
	for (const [k, v] of parsed.searchParams.entries()) {
		const isSens = SENSITIVE_QUERY_PARAM_PATTERN.test(k) || redactEvidenceText(v) !== v;
		const safeVal = isSens ? "[REDACTED]" : redactSecrets(redactEvidenceText(v));
		const arr = queryMap.get(k) ?? [];
		arr.push(safeVal);
		queryMap.set(k, arr);
		if (isSens) safeCopy.searchParams.set(k, "[REDACTED]");
	}
	return {
		parsed,
		displayUrl: redactSecrets(redactEvidenceText(safeCopy.toString())),
		queryMap,
	};
}

export function compareRequests(options: {
	leftRequest: ReplayCaseRequest;
	leftBodyBuffer: Buffer | null;
	rightRequest: ReplayCaseRequest;
	rightBodyBuffer: Buffer | null;
	ignoreJsonPointers?: readonly string[];
	compareHeaders?: readonly string[];
	maxDiffEntries?: number;
	maxDiffBytes?: number;
}): RequestComparisonResult {
	const leftMethod = options.leftRequest.method.toUpperCase();
	const rightMethod = options.rightRequest.method.toUpperCase();
	const leftUrlInfo = sanitizeUrlForComparisonDisplay(options.leftRequest.url);
	const rightUrlInfo = sanitizeUrlForComparisonDisplay(options.rightRequest.url);

	const queryDiffs: Array<{ name: string; left_values: string[]; right_values: string[]; equal: boolean }> = [];
	let queryEqual = leftUrlInfo.parsed.search === rightUrlInfo.parsed.search;
	for (const qk of Array.from(new Set([...leftUrlInfo.queryMap.keys(), ...rightUrlInfo.queryMap.keys()])).sort()) {
		const lVals = leftUrlInfo.queryMap.get(qk) ?? [];
		const rVals = rightUrlInfo.queryMap.get(qk) ?? [];
		const eq = lVals.length === rVals.length && lVals.every((v, i) => v === rVals[i]);
		if (!eq) {
			queryEqual = false;
			queryDiffs.push({ name: qk, left_values: lVals, right_values: rVals, equal: false });
		}
	}

	const headerCmp = compareHeaderLists({
		leftHeaders: options.leftRequest.headers,
		rightHeaders: options.rightRequest.headers,
		selectedHeaders: options.compareHeaders,
		allowCombinedWireComparison: false,
	});

	const leftSlotsSig = options.leftRequest.credential_slots
		.map(s => `${s.location}:${s.name.toLowerCase()}:${s.replay_binding}:${s.required}`)
		.sort()
		.join("|");
	const rightSlotsSig = options.rightRequest.credential_slots
		.map(s => `${s.location}:${s.name.toLowerCase()}:${s.replay_binding}:${s.required}`)
		.sort()
		.join("|");

	const bodyCmp = compareBodies({
		leftRef: options.leftRequest.body,
		leftBuffer: options.leftBodyBuffer,
		rightRef: options.rightRequest.body,
		rightBuffer: options.rightBodyBuffer,
		ignoreJsonPointers: options.ignoreJsonPointers,
		maxDiffEntries: options.maxDiffEntries,
		maxDiffBytes: options.maxDiffBytes,
	});

	return {
		method_equal: leftMethod === rightMethod,
		left_method: leftMethod,
		right_method: rightMethod,
		url_equal: options.leftRequest.url === options.rightRequest.url,
		origin_equal: leftUrlInfo.parsed.origin.toLowerCase() === rightUrlInfo.parsed.origin.toLowerCase(),
		pathname_equal: leftUrlInfo.parsed.pathname === rightUrlInfo.parsed.pathname,
		query_equal: queryEqual,
		left_url: leftUrlInfo.displayUrl,
		right_url: rightUrlInfo.displayUrl,
		query_diffs: queryDiffs,
		headers_equal: headerCmp.allHeadersEqual,
		duplicate_headers_equal: headerCmp.duplicateHeadersEqual,
		selected_headers_equal: headerCmp.selectedHeadersEqual,
		compared_headers: headerCmp.comparedHeaders,
		header_diffs: headerCmp.headerDiffs,
		credential_slots_equal: leftSlotsSig === rightSlotsSig,
		raw_equal: bodyCmp.raw_equal,
		normalized_equal: bodyCmp.normalized_equal,
		...(bodyCmp.comparison_reason ? { comparison_reason: bodyCmp.comparison_reason } : {}),
		applied_ignore_pointers: bodyCmp.applied_ignore_pointers,
		field_diffs: bodyCmp.field_diffs,
		ignored_diffs: bodyCmp.ignored_diffs,
		total_raw_diffs: bodyCmp.total_raw_diffs,
		total_unignored_diffs: bodyCmp.total_unignored_diffs,
		total_ignored_diffs: bodyCmp.total_ignored_diffs,
		diffs_truncated: bodyCmp.diffs_truncated,
		body_comparison: bodyCmp,
	};
}

export function compareResponses(options: {
	leftResponse?: ReplayCaseRecordedResponse;
	leftBodyBuffer: Buffer | null;
	rightResponse?: ReplayCaseRecordedResponse;
	rightBodyBuffer: Buffer | null;
	ignoreJsonPointers?: readonly string[];
	compareHeaders?: readonly string[];
	allowCombinedWireHeaderComparison?: boolean;
	maxDiffEntries?: number;
	maxDiffBytes?: number;
}): ResponseComparisonResult {
	const leftPresent = Boolean(options.leftResponse && options.leftResponse.status > 0);
	const rightPresent = Boolean(options.rightResponse && options.rightResponse.status > 0);

	if (!leftPresent || !rightPresent || !options.leftResponse || !options.rightResponse) {
		const lengthDelta = (options.rightResponse?.body.size_bytes ?? 0) - (options.leftResponse?.body.size_bytes ?? 0);
		const emptyBodyCmp: BodyComparisonResult = {
			raw_equal: "not_applicable",
			normalized_equal: "not_applicable",
			left_representation: options.leftResponse?.body.representation ?? "none",
			right_representation: options.rightResponse?.body.representation ?? "none",
			left_completeness: options.leftResponse?.body.completeness ?? "missing",
			right_completeness: options.rightResponse?.body.completeness ?? "missing",
			left_size_bytes: options.leftResponse?.body.size_bytes ?? 0,
			right_size_bytes: options.rightResponse?.body.size_bytes ?? 0,
			left_sha256: options.leftResponse?.body.sha256 ?? null,
			right_sha256: options.rightResponse?.body.sha256 ?? null,
			length_delta: lengthDelta,
			comparison_reason: "recorded_response_absent",
			applied_ignore_pointers: [...(options.ignoreJsonPointers ?? [])],
			field_diffs: [],
			ignored_diffs: [],
			total_raw_diffs: 0,
			total_unignored_diffs: 0,
			total_ignored_diffs: 0,
			diffs_truncated: false,
		};
		return {
			available: false,
			status_equal: false,
			left_status: options.leftResponse?.status ?? 0,
			right_status: options.rightResponse?.status ?? 0,
			status_delta: `${leftPresent ? options.leftResponse!.status : "unrecorded"} -> ${rightPresent ? options.rightResponse!.status : "unrecorded"}`,
			length_delta: lengthDelta,
			headers_equal: false,
			selected_headers_equal: false,
			compared_headers: [...(options.compareHeaders ?? [])],
			header_diffs: [],
			raw_equal: "not_applicable",
			normalized_equal: "not_applicable",
			comparison_reason: "recorded_response_absent",
			applied_ignore_pointers: [...(options.ignoreJsonPointers ?? [])],
			field_diffs: [],
			ignored_diffs: [],
			total_raw_diffs: 0,
			total_unignored_diffs: 0,
			total_ignored_diffs: 0,
			diffs_truncated: false,
			body_comparison: emptyBodyCmp,
		};
	}

	const headerCmp = compareHeaderLists({
		leftHeaders: options.leftResponse.headers,
		rightHeaders: options.rightResponse.headers,
		selectedHeaders: options.compareHeaders,
		allowCombinedWireComparison: options.allowCombinedWireHeaderComparison ?? false,
	});
	const bodyCmp = compareBodies({
		leftRef: options.leftResponse.body,
		leftBuffer: options.leftBodyBuffer,
		rightRef: options.rightResponse.body,
		rightBuffer: options.rightBodyBuffer,
		ignoreJsonPointers: options.ignoreJsonPointers,
		maxDiffEntries: options.maxDiffEntries,
		maxDiffBytes: options.maxDiffBytes,
	});

	let statusDelta = `${options.leftResponse.status} -> ${options.rightResponse.status}`;
	if (bodyCmp.raw_equal === "unknown") {
		statusDelta += ` (${bodyCmp.comparison_reason ?? "comparison unknown"})`;
	}

	return {
		available: true,
		status_equal: options.leftResponse.status === options.rightResponse.status,
		left_status: options.leftResponse.status,
		right_status: options.rightResponse.status,
		status_delta: statusDelta,
		length_delta: options.rightResponse.body.size_bytes - options.leftResponse.body.size_bytes,
		headers_equal: headerCmp.allHeadersEqual,
		selected_headers_equal: headerCmp.selectedHeadersEqual,
		compared_headers: headerCmp.comparedHeaders,
		header_diffs: headerCmp.headerDiffs,
		raw_equal: bodyCmp.raw_equal,
		normalized_equal: bodyCmp.normalized_equal,
		...(bodyCmp.comparison_reason ? { comparison_reason: bodyCmp.comparison_reason } : {}),
		applied_ignore_pointers: bodyCmp.applied_ignore_pointers,
		field_diffs: bodyCmp.field_diffs,
		ignored_diffs: bodyCmp.ignored_diffs,
		total_raw_diffs: bodyCmp.total_raw_diffs,
		total_unignored_diffs: bodyCmp.total_unignored_diffs,
		total_ignored_diffs: bodyCmp.total_ignored_diffs,
		diffs_truncated: bodyCmp.diffs_truncated,
		body_comparison: bodyCmp,
	};
}

export interface ExecuteNetworkCompareParams {
	projectDir: string;
	workspacePath?: string;
	workflowId?: string;
	stepId?: string;
	runId?: string;
	leftCase?: string;
	rightCase?: string;
	outputPath?: string;
	ignoreJsonPointers?: string[];
	compareHeaders?: string[];
	assertions?: ReplayJsonAssertion[];
	signal?: AbortSignal;
}

export interface ExecuteNetworkCompareOutcome {
	status: "ok";
	workflowId: string;
	stepId: string;
	runId: string;
	runDir: string;
	paths: AnalysisRunPaths;
	reportPath: string;
	reportRelativePath: string;
	reportSha256: string;
	outputPaths: string[];
	relativeOutputPaths: string[];
	report: NetworkCompareReportV1;
	requestComparison: RequestComparisonResult;
	responseComparison: ResponseComparisonResult;
	assertionResults: ReplayJsonAssertionResult[];
	assertionsPassed: boolean;
	observations: string[];
	evidenceCandidates: Array<{
		kind: "fact";
		target: string;
		locator: string;
		sourceTool: "app_experiment";
		content: string;
		assurance?: EvidenceAssuranceLevel;
	}>;
}

export async function executeNetworkCompare(
	params: ExecuteNetworkCompareParams,
): Promise<ExecuteNetworkCompareOutcome> {
	throwIfAborted(params.signal);

	const workflowId = params.workflowId?.trim() ?? "";
	if (!workflowId) throw new ToolError("network_compare requires explicit 'workflow_id'");
	const stepId = params.stepId?.trim() ?? "";
	if (!stepId) throw new ToolError("network_compare requires explicit 'step_id'");
	const runId = params.runId?.trim() ?? "";
	if (!runId)
		throw new ToolError("network_compare requires explicit 'run_id' from reverse_workspace(action: 'begin')");
	const leftCasePath = params.leftCase?.trim() ?? "";
	if (!leftCasePath) throw new ToolError("network_compare requires explicit 'left_case' path");
	const rightCasePath = params.rightCase?.trim() ?? "";
	if (!rightCasePath) throw new ToolError("network_compare requires explicit 'right_case' path");

	const validatedConfig = validateComparisonOptions({
		ignoreJsonPointers: params.ignoreJsonPointers,
		compareHeaders: params.compareHeaders,
		assertions: params.assertions,
	});
	const resolvedProjectDir = path.resolve(params.projectDir);

	const { loaded: leftLoaded } = await loadAndVerifyCaseWithBodies({
		projectDir: resolvedProjectDir,
		workspacePath: params.workspacePath,
		workflowId,
		stepId,
		runId,
		caseFilePath: leftCasePath,
		label: "left_case",
		additionalInputPaths: [rightCasePath],
		outputPaths: params.outputPath ? [params.outputPath] : undefined,
	});

	const { loaded: rightLoaded, execution } = await loadAndVerifyCaseWithBodies({
		projectDir: resolvedProjectDir,
		workspacePath: params.workspacePath,
		workflowId,
		stepId,
		runId,
		caseFilePath: rightCasePath,
		label: "right_case",
		additionalInputPaths: [leftCasePath],
		outputPaths: params.outputPath ? [params.outputPath] : undefined,
	});

	const inlineReqCmp = compareRequests({
		leftRequest: leftLoaded.document.request,
		leftBodyBuffer: leftLoaded.requestBodyBuffer,
		rightRequest: rightLoaded.document.request,
		rightBodyBuffer: rightLoaded.requestBodyBuffer,
		ignoreJsonPointers: validatedConfig.ignoreJsonPointers,
		compareHeaders: validatedConfig.compareHeaders,
		maxDiffEntries: MAX_INLINE_DIFF_ENTRIES,
		maxDiffBytes: MAX_INLINE_DIFF_BYTES,
	});
	const reportReqCmp = compareRequests({
		leftRequest: leftLoaded.document.request,
		leftBodyBuffer: leftLoaded.requestBodyBuffer,
		rightRequest: rightLoaded.document.request,
		rightBodyBuffer: rightLoaded.requestBodyBuffer,
		ignoreJsonPointers: validatedConfig.ignoreJsonPointers,
		compareHeaders: validatedConfig.compareHeaders,
		maxDiffEntries: MAX_REPORT_DIFF_ENTRIES,
		maxDiffBytes: MAX_INLINE_DIFF_BYTES * 8,
	});

	const inlineRespCmp = compareResponses({
		leftResponse: leftLoaded.document.recorded_response,
		leftBodyBuffer: leftLoaded.responseBodyBuffer,
		rightResponse: rightLoaded.document.recorded_response,
		rightBodyBuffer: rightLoaded.responseBodyBuffer,
		ignoreJsonPointers: validatedConfig.ignoreJsonPointers,
		compareHeaders: validatedConfig.compareHeaders,
		allowCombinedWireHeaderComparison: false,
		maxDiffEntries: MAX_INLINE_DIFF_ENTRIES,
		maxDiffBytes: MAX_INLINE_DIFF_BYTES,
	});
	const reportRespCmp = compareResponses({
		leftResponse: leftLoaded.document.recorded_response,
		leftBodyBuffer: leftLoaded.responseBodyBuffer,
		rightResponse: rightLoaded.document.recorded_response,
		rightBodyBuffer: rightLoaded.responseBodyBuffer,
		ignoreJsonPointers: validatedConfig.ignoreJsonPointers,
		compareHeaders: validatedConfig.compareHeaders,
		allowCombinedWireHeaderComparison: false,
		maxDiffEntries: MAX_REPORT_DIFF_ENTRIES,
		maxDiffBytes: MAX_INLINE_DIFF_BYTES * 8,
	});

	const assertionResults: ReplayJsonAssertionResult[] = [];
	for (const assertion of validatedConfig.assertions) {
		const rawTarget = (assertion.target ?? "").toLowerCase();
		let targetLabel: string;
		let targetRef: ReplayBodyRef;
		let targetBuf: Buffer | null;

		if (rawTarget === "left_request") {
			targetLabel = "left_request";
			targetRef = leftLoaded.document.request.body;
			targetBuf = leftLoaded.requestBodyBuffer;
		} else if (rawTarget === "right_request") {
			targetLabel = "right_request";
			targetRef = rightLoaded.document.request.body;
			targetBuf = rightLoaded.requestBodyBuffer;
		} else if (rawTarget === "left" || rawTarget === "left_response") {
			if (leftLoaded.document.recorded_response.status > 0) {
				targetLabel = "left_response";
				targetRef = leftLoaded.document.recorded_response.body;
				targetBuf = leftLoaded.responseBodyBuffer;
			} else {
				targetLabel = "left_request";
				targetRef = leftLoaded.document.request.body;
				targetBuf = leftLoaded.requestBodyBuffer;
			}
		} else if (rawTarget === "right_response" || (!rawTarget && rightLoaded.document.recorded_response.status > 0)) {
			targetLabel = "right_response";
			targetRef = rightLoaded.document.recorded_response.body;
			targetBuf = rightLoaded.responseBodyBuffer;
		} else {
			targetLabel = "right_request";
			targetRef = rightLoaded.document.request.body;
			targetBuf = rightLoaded.requestBodyBuffer;
		}

		assertionResults.push(
			...evaluateJsonAssertionsForTarget({
				targetName: targetLabel,
				bodyRef: targetRef,
				bodyBuffer: targetBuf,
				assertions: [assertion],
			}),
		);
	}

	const assertionsPassed = assertionResults.every(r => r.passed);
	const safeLeftId = leftLoaded.document.case_id.replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 32) || "left";
	const safeRightId = rightLoaded.document.case_id.replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 32) || "right";
	const defaultReportPath = path.join(
		execution.paths.reports_dir,
		`compare_${safeLeftId}_vs_${safeRightId}.report.json`,
	);
	const resolvedReportOut = await resolveAnalysisOutputPath({
		projectDir: resolvedProjectDir,
		runDir: execution.paths.run_dir,
		outputPath: params.outputPath ?? defaultReportPath,
	});

	const report: NetworkCompareReportV1 = {
		schema_version: "1",
		workflow_id: workflowId,
		step_id: stepId,
		run_id: runId,
		created_at: new Date().toISOString(),
		left_case: {
			path: leftLoaded.caseRelativePath,
			sha256: leftLoaded.caseSha256,
			case_id: leftLoaded.document.case_id,
			source_path: leftLoaded.document.source.path,
			source_sha256: leftLoaded.document.source.sha256,
			source_format: leftLoaded.document.source.format,
		},
		right_case: {
			path: rightLoaded.caseRelativePath,
			sha256: rightLoaded.caseSha256,
			case_id: rightLoaded.document.case_id,
			source_path: rightLoaded.document.source.path,
			source_sha256: rightLoaded.document.source.sha256,
			source_format: rightLoaded.document.source.format,
		},
		comparison_config: {
			ignore_json_pointers: validatedConfig.ignoreJsonPointers,
			compare_headers: validatedConfig.compareHeaders,
			assertions: validatedConfig.assertions,
		},
		request_comparison: reportReqCmp,
		response_comparison: reportRespCmp,
		assertion_results: assertionResults,
		assertions_passed: assertionsPassed,
		independent_reproduction_certified: false,
		note: "Offline comparison of two ReplayCase v1 artifacts; does not execute generator scripts or certify independent_reproduction.",
	};

	const writtenReport = await writePrivateRunArtifactFile(
		resolvedReportOut.resolvedPath,
		`${deterministicJsonStringify(report)}\n`,
	);

	const locator = `${resolvedReportOut.relativePath}#${leftLoaded.document.case_id}..${rightLoaded.document.case_id}`;
	const observations: string[] = [
		`Compared left_case '${leftLoaded.caseRelativePath}' (${leftLoaded.document.case_id}) vs right_case '${rightLoaded.caseRelativePath}' (${rightLoaded.document.case_id})`,
		`Request comparison: method_equal=${inlineReqCmp.method_equal}, url_equal=${inlineReqCmp.url_equal}, headers_equal=${inlineReqCmp.headers_equal}, raw_equal=${String(inlineReqCmp.raw_equal)}, normalized_equal=${String(inlineReqCmp.normalized_equal)} (unignored_diffs=${inlineReqCmp.total_unignored_diffs}, ignored_diffs=${inlineReqCmp.total_ignored_diffs})`,
		inlineRespCmp.available
			? `Recorded response comparison: status_equal=${inlineRespCmp.status_equal} (${inlineRespCmp.status_delta}), headers_equal=${inlineRespCmp.headers_equal}, raw_equal=${String(inlineRespCmp.raw_equal)}, normalized_equal=${String(inlineRespCmp.normalized_equal)} (unignored_diffs=${inlineRespCmp.total_unignored_diffs}, ignored_diffs=${inlineRespCmp.total_ignored_diffs})`
			: `Recorded response comparison: not_applicable (${inlineRespCmp.comparison_reason ?? "recorded_response_absent"})`,
		...(assertionResults.length > 0
			? [
					`Assertions evaluated: ${assertionResults.filter(a => a.passed).length}/${assertionResults.length} passed (overall: ${assertionsPassed})`,
				]
			: []),
		`Offline comparison only: no scripts executed and no network packets sent; independent_reproduction is not automatically certified.`,
	];

	return {
		status: "ok",
		workflowId,
		stepId,
		runId,
		runDir: execution.paths.run_dir,
		paths: execution.paths,
		reportPath: resolvedReportOut.resolvedPath,
		reportRelativePath: resolvedReportOut.relativePath,
		reportSha256: writtenReport.sha256,
		outputPaths: [resolvedReportOut.resolvedPath],
		relativeOutputPaths: [resolvedReportOut.relativePath],
		report,
		requestComparison: inlineReqCmp,
		responseComparison: inlineRespCmp,
		assertionResults,
		assertionsPassed,
		observations,
		evidenceCandidates: [
			{
				kind: "fact",
				target: leftLoaded.document.source.path,
				locator,
				sourceTool: "app_experiment",
				content: `Offline network_compare between ${leftLoaded.caseRelativePath} and ${rightLoaded.caseRelativePath}: req(raw_equal=${String(inlineReqCmp.raw_equal)}, normalized_equal=${String(inlineReqCmp.normalized_equal)}, diffs=${inlineReqCmp.total_unignored_diffs}), resp(available=${inlineRespCmp.available}, raw_equal=${String(inlineRespCmp.raw_equal)}, normalized_equal=${String(inlineRespCmp.normalized_equal)}), report=${resolvedReportOut.relativePath}`,
			},
		],
	};
}

export type { ReplayCaseV1 };
