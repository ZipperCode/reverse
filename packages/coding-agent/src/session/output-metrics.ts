/**
 * Deterministic session output, artifact budget, and compaction metrics (#20).
 *
 * Streams session JSONL line-by-line with a hard per-line byte guard, bounded
 * quantile reservoirs, and fixed-capacity LRU/collection caps so arbitrarily large
 * journals can be audited locally in bounded memory.
 * 约束说明：
 * 1. 所有重建开销指标（压缩后重读、eval 缺失符号、edit 锚点/哈希拒绝）仅记录日志可观测事实，
 *    绝不将时间先后推断为已证实的因果链（如“压缩导致变量丢失”）。
 * 2. 缺失或不可计算的数据统一返回 `null` 或 `"unknown"`，不使用误导性的 `0` 填充。
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { type } from "@reverse/reversetype";
import { isRecord } from "@reverse/utils";
import { classifyEditRejection, extractEditErrorKind } from "../edit/error-kind";
import { SESSION_EXIT_CUSTOM_TYPE, TOOL_EXECUTION_START_CUSTOM_TYPE } from "./exit-diagnostics";
import { currentRuntimeIdentity, type RuntimeIdentity } from "./runtime-identity";
import type { FileEntry } from "./session-entries";
import { parseTitleSlotLine } from "./session-title-slot";

const DEFAULT_MAX_LINE_BYTES = 16 * 1024 * 1024;
const RESERVOIR_CAPACITY = 2_048;
const TOP_CAPTURE_LOGS_LIMIT = 10;
const MAX_TRACKED_READ_PATHS = 4_096;
const MAX_PENDING_TOOL_CALLS = 4_096;
const MAX_TRACKED_SHAKEN_ARTIFACTS = 4_096;
const MAX_TRACKED_HANDOFF_SUMMARIES = 128;
const MAX_OBSERVED_RUNTIMES = 64;
const MAX_EVAL_MISSING_NAMES = 512;
const MAX_DISTINCT_KEY_BUCKETS = 256;
const LOG_TRUNCATION_MARKER_RE = /\[ARTIFACT TRUNCATED[^\]\r\n]*\]/i;
const EXACT_ELIDED_BYTES_RE = /[;:]\s*([\d,]+)\s*(?:B|bytes?)?\s+elided(?:\s+from the middle)?\]/i;
const SHAKEN_REGION_RE = /\[shaken ~(\d+) tokens(?:\s+—\s+recover:\s+artifact:\/\/(\d+)(?:\s+\(region\s+(\d+)\))?)?\]/g;
const SHAKE_ARTIFACT_HEADER_RE = /^### region (\d+) \(/gm;
const EVAL_TRACEBACK_MISSING_RE =
	/\b(?:NameError:\s+name\s+'([^']+)'\s+is\s+not\s+defined|ReferenceError:\s+([A-Za-z_$][\w$]*)\s+is\s+not\s+defined)\b/g;

export interface NumericDistribution {
	count: number;
	min: number;
	max: number;
	avg: number;
	p50: number;
	p90: number;
	total: number;
}

export interface CompactionEndpointSummary {
	lineNumber: number;
	entryId: string | null;
	timestamp: string | null;
	method: string;
	tokensBefore: number | null;
	tokensAfter: number | null;
}

export interface CaptureLogEntry {
	fileName: string;
	artifactId: number;
	toolType: string;
	bytes: number;
	truncatedOnDisk: boolean;
	elidedBytes: number | null;
}

export interface HandoffRequiredInvariant {
	name: string;
	pattern: string | RegExp;
}

export type HandoffProvenance = "live_model" | "fixture" | "unverified";

export interface HandoffDocumentQuality {
	/** Structural/invariant check only; cannot prove semantic truth without ground-truth invariants. */
	evaluationScope: "structural_and_invariant_coverage";
	presentHeadings: string[];
	missingHeadings: string[];
	structuralComplete: boolean;
	checkedInvariants: Array<{ name: string; matched: boolean }>;
	allInvariantsMatched: boolean | null;
	byteLength: number;
}

export interface HandoffQualitySummary {
	evaluationScope: "structural_and_invariant_coverage";
	provenance: HandoffProvenance;
	evaluatedCount: number;
	structuralCompleteCount: number;
	invariantMatchedCount: number | null;
	documents: Array<{ source: string; quality: HandoffDocumentQuality }>;
}
export interface SessionOutputMetricsReport {
	schemaVersion: 1;
	sessionFile: string | null;
	artifactsDir: string | null;
	artifactsDirExists: boolean;
	sessionId: string | null;
	runtimeVersion: string | null;
	observedRuntimes: RuntimeIdentity[];
	analyzerRuntime: RuntimeIdentity;
	physicalLines: number;
	malformedRecords: number;
	oversizedLinesSkipped: number;
	window: {
		startTimestamp: string | null;
		endTimestamp: string | null;
		exitReason: string | null;
		exitKind: string | null;
		durationMs: number | null;
	};
	compaction: {
		count: number;
		methods: Record<string, number>;
		warningCount: number;
		fromExtensionCount: number;
		first: CompactionEndpointSummary | null;
		last: CompactionEndpointSummary | null;
		tokensBefore: NumericDistribution | null;
		tokensAfter: NumericDistribution | null;
		totalTokensCompacted: number | null;
		intervalsMs: {
			betweenCompactions: NumericDistribution | null;
			timeToFirstCompactionMs: number | null;
			throughputDurationPerCompactionMs: number | null;
			betweenCompactionsAvgMinutes: number | null;
			timeToFirstCompactionMinutes: number | null;
			throughputDurationPerCompactionMinutes: number | null;
		};
	};
	toolCalls: {
		executionStartCount: number;
		executionStartByTool: Record<string, number>;
		backendRunEstimateByTool: Record<string, number>;
		assistantToolCallCount: number;
		assistantToolCallsByTool: Record<string, number>;
		topTools: Array<{
			toolName: string;
			count: number;
			source: "tool_execution_start" | "assistant_toolCall";
		}>;
	};
	toolResults: {
		total: number;
		errorCount: number;
		shakenToolResultCount: number;
		shakenErrorToolResultCount: number;
		shakenToolResultRatio: number | null;
		shakenRegions: {
			totalRegionsInTranscript: number;
			toolResultRegions: number;
			messageBlockRegions: number;
			distinctArtifactIds: string[];
			maxRegionNumberByArtifact: Record<string, number>;
			estimatedTokensElided: number;
		};
		truncationMeta: {
			truncatedResultCount: number;
			totalSourceBytes: number;
			totalInlineOutputBytes: number;
			totalInlineElidedBytes: number;
			totalArtifactBytes: number;
			totalArtifactElidedBytes: number;
			budgetExhaustedCount: number;
		};
	};
	artifacts: {
		captureLogCount: number;
		totalCaptureLogBytes: number;
		truncatedCaptureLogCount: number;
		totalCaptureLogElidedBytes: number | null;
		maxCaptureLog: CaptureLogEntry | null;
		topCaptureLogs: CaptureLogEntry[];
		shakeArtifactCount: number;
		shakeArtifactBytes: number;
		shakeArtifactRegionsTotal: number;
		handoffFileCount: number;
		handoffSummaryEntryCount: number;
		handoffQuality: HandoffQualitySummary | null;
	};
	reconstructionIndicators: {
		classificationBasis: "approximate_observational";
		postCompactionReadCount: number;
		postCompactionArtifactReadCount: number;
		repeatedPathReadCount: number;
		evalStateErrors: {
			total: number;
			structuredMissingNameCount: number;
			historicalTracebackInferredCount: number;
			postCompactionCount: number;
			missingNames: string[];
		};
		editRejections: {
			totalErrorCount: number;
			anchorRejectCount: number;
			hashRejectCount: number;
			otherErrorCount: number;
			byErrorKind: Record<string, number>;
			structuredCount: number;
			historicalTextInferredCount: number;
			postCompactionAnchorOrHashCount: number;
		};
		prerequisiteBlocks: {
			total: number;
			gateBlockedCount: number;
			backendProbeFailureCount: number;
			byTool: Record<string, number>;
		};
	};
}

export interface SessionOutputMetricsOptions {
	artifactsDir?: string;
	maxLineBytes?: number;
	handoffInvariants?: readonly HandoffRequiredInvariant[];
	handoffProvenance?: HandoffProvenance;
}

export interface SessionOutputMetricsFromEntriesOptions {
	sessionFile?: string | null;
	artifactsDir?: string | null;
	handoffInvariants?: readonly HandoffRequiredInvariant[];
	handoffProvenance?: HandoffProvenance;
}
export interface SessionOutputComparisonThresholds {
	/** Maximum allowed per-call capture `.log` size in bytes (e.g. 4 * 1024 * 1024). */
	maxSingleCaptureLogBytes?: number;
	/** Allow equal compaction count when workload is sub-threshold or identical; default false requires strict improvement on count or interval. */
	allowEqualCompactionPace?: boolean;
}

export type AxisOutcome = "pass" | "fail" | "unknown";

export interface AxisEvaluation {
	status: AxisOutcome;
	reason: string;
	candidateValue: unknown;
	baselineValue: unknown;
}

export interface SessionOutputComparisonReport {
	/** True only when all 5 axes pass (including non-fixture handoff coverage). */
	passed: boolean;
	/** True when the 4 deterministic non-model axes pass and handoff did not fail. */
	deterministicAxesPassed: boolean;
	/** Explicit guard from issue #20: compaction count drop alone never passes overall acceptance. */
	compactionDropAloneGuardTriggered: boolean;
	axes: {
		compactionPace: AxisEvaluation;
		singleArtifactCap: AxisEvaluation;
		shakenRatio: AxisEvaluation;
		postCompactionStateErrors: AxisEvaluation;
		handoffStructuralCoverage: AxisEvaluation;
	};
}

const REQUIRED_HANDOFF_HEADINGS = [
	"## Goal",
	"## Constraints & Preferences",
	"## Progress",
	"## Key Decisions",
	"## Critical Context",
	"## Next Steps",
] as const;

class ReservoirStats {
	#count = 0;
	#min = Number.POSITIVE_INFINITY;
	#max = Number.NEGATIVE_INFINITY;
	#total = 0;
	readonly #sample: number[] = [];
	#rngState = 0x9e3779b9;

	add(value: number): void {
		if (!Number.isFinite(value)) return;
		this.#count++;
		if (value < this.#min) this.#min = value;
		if (value > this.#max) this.#max = value;
		this.#total += value;
		if (this.#sample.length < RESERVOIR_CAPACITY) {
			this.#sample.push(value);
			return;
		}
		// Deterministic xorshift32 reservoir sampling so repeated runs produce identical quantiles.
		this.#rngState ^= this.#rngState << 13;
		this.#rngState ^= this.#rngState >>> 17;
		this.#rngState ^= this.#rngState << 5;
		const index = (this.#rngState >>> 0) % this.#count;
		if (index < RESERVOIR_CAPACITY) {
			this.#sample[index] = value;
		}
	}

	toDistribution(): NumericDistribution | null {
		if (this.#count === 0) return null;
		const sorted = [...this.#sample].sort((a, b) => a - b);
		const quantile = (q: number): number => {
			const pos = Math.min(sorted.length - 1, Math.max(0, Math.floor((sorted.length - 1) * q)));
			return sorted[pos]!;
		};
		return {
			count: this.#count,
			min: this.#min,
			max: this.#max,
			avg: this.#total / this.#count,
			p50: quantile(0.5),
			p90: quantile(0.9),
			total: this.#total,
		};
	}
}

export function resolveSessionArtifactsDirectory(sessionFilePath: string, explicitArtifactsDir?: string): string {
	if (explicitArtifactsDir) return path.resolve(explicitArtifactsDir);
	const resolved = path.resolve(sessionFilePath);
	return resolved.endsWith(".jsonl") ? resolved.slice(0, -".jsonl".length) : `${resolved}.artifacts`;
}

export function evaluateHandoffDocumentQuality(
	markdown: string,
	invariants?: readonly HandoffRequiredInvariant[],
): HandoffDocumentQuality {
	const presentHeadings: string[] = [];
	const missingHeadings: string[] = [];
	for (const heading of REQUIRED_HANDOFF_HEADINGS) {
		const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		if (new RegExp(`^${escaped}\\b`, "m").test(markdown)) {
			presentHeadings.push(heading);
		} else {
			missingHeadings.push(heading);
		}
	}
	const checkedInvariants = (invariants ?? []).map(inv => {
		const matched = typeof inv.pattern === "string" ? markdown.includes(inv.pattern) : inv.pattern.test(markdown);
		return { name: inv.name, matched };
	});
	return {
		evaluationScope: "structural_and_invariant_coverage",
		presentHeadings,
		missingHeadings,
		structuralComplete: missingHeadings.length === 0,
		checkedInvariants,
		allInvariantsMatched: checkedInvariants.length === 0 ? null : checkedInvariants.every(item => item.matched),
		byteLength: Buffer.byteLength(markdown, "utf8"),
	};
}

function parseTimestampMs(ts: unknown): number | null {
	if (typeof ts === "number" && Number.isFinite(ts)) return ts;
	if (typeof ts === "string" && ts.length > 0) {
		const parsed = Date.parse(ts);
		return Number.isFinite(parsed) ? parsed : null;
	}
	return null;
}

function extractTextFromContent(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	const parts: string[] = [];
	for (const block of content) {
		if (isRecord(block) && block.type === "text" && typeof block.text === "string" && block.text.length > 0) {
			parts.push(block.text);
		}
	}
	return parts.join("\n");
}

function incrementCounter(map: Record<string, number>, key: string, delta = 1): void {
	if (map[key] !== undefined) {
		map[key] += delta;
		return;
	}
	const targetKey = Object.keys(map).length >= MAX_DISTINCT_KEY_BUCKETS ? "__other__" : key;
	map[targetKey] = (map[targetKey] ?? 0) + delta;
}

function normalizeReadSelectorBase(rawPath: string): string {
	// Strip `:line-range` or `?query` suffixes while keeping scheme prefixes (`artifact://12`, `local://x`).
	const queryCut = rawPath.indexOf("?");
	const withoutQuery = queryCut >= 0 ? rawPath.slice(0, queryCut) : rawPath;
	const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:]+)(?::.*)?$/.exec(withoutQuery);
	if (schemeMatch) return schemeMatch[1]!;
	const winDriveMatch = /^([A-Za-z]:[\\/][^:]+)(?::.*)?$/.exec(withoutQuery);
	if (winDriveMatch) return winDriveMatch[1]!;
	const colonIndex = withoutQuery.indexOf(":");
	return colonIndex >= 0 ? withoutQuery.slice(0, colonIndex) : withoutQuery;
}

function unwrapEffectiveDetails(
	toolName: string | undefined,
	details: unknown,
): {
	effectiveToolName: string;
	effectiveDetails: Record<string, unknown> | undefined;
} {
	if (!isRecord(details)) {
		return { effectiveToolName: toolName ?? "unknown", effectiveDetails: undefined };
	}
	if (
		(toolName === "write" || toolName === undefined) &&
		isRecord(details.xdev) &&
		typeof details.xdev.tool === "string"
	) {
		const inner = isRecord(details.xdev.inner) ? details.xdev.inner : undefined;
		return { effectiveToolName: details.xdev.tool, effectiveDetails: inner ?? details };
	}
	return { effectiveToolName: toolName ?? "unknown", effectiveDetails: details };
}

class MetricsAccumulator {
	sessionId: string | null = null;
	runtimeVersion: string | null = null;
	readonly observedRuntimes: RuntimeIdentity[] = [];
	#lastRuntimeKey: string | null = null;
	physicalLines = 0;
	malformedRecords = 0;
	oversizedLinesSkipped = 0;

	firstTimestampStr: string | null = null;
	firstTimestampMs: number | null = null;
	lastTimestampStr: string | null = null;
	lastTimestampMs: number | null = null;
	exitReason: string | null = null;
	exitKind: string | null = null;

	compactionCount = 0;
	readonly compactionMethods: Record<string, number> = {};
	compactionWarningCount = 0;
	compactionFromExtensionCount = 0;
	firstCompaction: CompactionEndpointSummary | null = null;
	lastCompaction: CompactionEndpointSummary | null = null;
	readonly tokensBeforeStats = new ReservoirStats();
	readonly tokensAfterStats = new ReservoirStats();
	readonly compactionIntervalsStats = new ReservoirStats();
	#prevCompactionMs: number | null = null;
	#compactedDeltaSum = 0;
	#compactedDeltaPairs = 0;
	handoffSummaryEntryCount = 0;
	readonly handoffSummaries: Array<{ source: string; summary: string }> = [];

	executionStartCount = 0;
	readonly executionStartByTool: Record<string, number> = {};
	assistantToolCallCount = 0;
	readonly assistantToolCallsByTool: Record<string, number> = {};
	readonly #toolCallArgsById = new Map<string, { toolName: string; pathArg?: string }>();

	toolResultTotal = 0;
	toolResultErrorCount = 0;
	shakenToolResultCount = 0;
	shakenErrorToolResultCount = 0;
	totalRegionsInTranscript = 0;
	toolResultRegions = 0;
	messageBlockRegions = 0;
	readonly shakenArtifactIds = new Set<string>();
	readonly maxRegionByArtifact: Record<string, number> = {};
	estimatedTokensElided = 0;

	truncatedResultCount = 0;
	totalSourceBytes = 0;
	totalInlineOutputBytes = 0;
	totalInlineElidedBytes = 0;
	totalMetaArtifactBytes = 0;
	totalMetaArtifactElidedBytes = 0;
	budgetExhaustedCount = 0;

	postCompactionReadCount = 0;
	postCompactionArtifactReadCount = 0;
	repeatedPathReadCount = 0;
	readonly #seenReadBases = new Set<string>();

	evalStateErrorTotal = 0;
	evalStructuredMissingCount = 0;
	evalTracebackInferredCount = 0;
	evalPostCompactionCount = 0;
	readonly evalMissingNames = new Set<string>();

	editTotalErrorCount = 0;
	editAnchorRejectCount = 0;
	editHashRejectCount = 0;
	editOtherErrorCount = 0;
	readonly editByErrorKind: Record<string, number> = {};
	editStructuredCount = 0;
	editTextInferredCount = 0;
	editPostCompactionAnchorOrHashCount = 0;

	prereqBlockTotal = 0;
	prereqGateBlockedCount = 0;
	prereqBackendProbeFailureCount = 0;
	readonly prereqByTool: Record<string, number> = {};

	visitEntry(raw: unknown, physicalLineNumber: number): void {
		if (!isRecord(raw) || typeof raw.type !== "string") return;

		// Track timestamps across all entries for accurate session window bounds.
		if (typeof raw.timestamp === "string") {
			const ms = parseTimestampMs(raw.timestamp);
			if (ms !== null) {
				if (this.firstTimestampMs === null || ms < this.firstTimestampMs) {
					this.firstTimestampMs = ms;
					this.firstTimestampStr = raw.timestamp;
				}
				if (this.lastTimestampMs === null || ms > this.lastTimestampMs) {
					this.lastTimestampMs = ms;
					this.lastTimestampStr = raw.timestamp;
				}
			}
		}

		// Record runtime build stamp transitions.
		if (isRecord(raw.runtime) && typeof raw.runtime.version === "string") {
			this.runtimeVersion ??= raw.runtime.version;
			const stamp: RuntimeIdentity = {
				version: raw.runtime.version,
				...(typeof raw.runtime.commit === "string" ? { commit: raw.runtime.commit } : {}),
				...(typeof raw.runtime.branch === "string" ? { branch: raw.runtime.branch } : {}),
				...(typeof raw.runtime.diff === "string" ? { diff: raw.runtime.diff } : {}),
				...(typeof raw.runtime.label === "string" ? { label: raw.runtime.label } : {}),
			};
			const key = `${stamp.version}|${stamp.commit ?? ""}|${stamp.branch ?? ""}|${stamp.diff ?? ""}|${stamp.label ?? ""}`;
			if (key !== this.#lastRuntimeKey) {
				this.#lastRuntimeKey = key;
				if (this.observedRuntimes.length < MAX_OBSERVED_RUNTIMES) {
					this.observedRuntimes.push(stamp);
				}
			}
		}

		if (raw.type === "session") {
			if (typeof raw.id === "string") this.sessionId = raw.id;
			return;
		}

		if (raw.type === "compaction") {
			this.#visitCompaction(raw, physicalLineNumber);
			return;
		}

		if (raw.type === "custom") {
			this.#visitCustomEntry(raw);
			return;
		}

		if (raw.type === "custom_message") {
			const text = extractTextFromContent(raw.content);
			this.#scanShakenRegions(text, "block");
			return;
		}

		if (raw.type === "message" && isRecord(raw.message)) {
			this.#visitMessage(raw.message);
		}
	}

	#visitCompaction(raw: Record<string, unknown>, lineNumber: number): void {
		this.compactionCount++;
		const method =
			typeof raw.method === "string" && raw.method.length > 0
				? raw.method
				: raw.fromExtension === true
					? "extension"
					: "unspecified";
		incrementCounter(this.compactionMethods, method);
		if (typeof raw.warning === "string" && raw.warning.length > 0) {
			this.compactionWarningCount++;
		}
		if (raw.fromExtension === true) {
			this.compactionFromExtensionCount++;
		}

		const tokensBefore =
			typeof raw.tokensBefore === "number" && Number.isFinite(raw.tokensBefore) ? raw.tokensBefore : null;
		const tokensAfter =
			typeof raw.tokensAfter === "number" && Number.isFinite(raw.tokensAfter) ? raw.tokensAfter : null;
		if (tokensBefore !== null) this.tokensBeforeStats.add(tokensBefore);
		if (tokensAfter !== null) this.tokensAfterStats.add(tokensAfter);
		if (tokensBefore !== null && tokensAfter !== null) {
			this.#compactedDeltaSum += tokensBefore - tokensAfter;
			this.#compactedDeltaPairs++;
		}

		const tsStr = typeof raw.timestamp === "string" ? raw.timestamp : null;
		const tsMs = parseTimestampMs(tsStr);
		if (tsMs !== null) {
			if (this.#prevCompactionMs !== null && tsMs >= this.#prevCompactionMs) {
				this.compactionIntervalsStats.add(tsMs - this.#prevCompactionMs);
			}
			this.#prevCompactionMs = tsMs;
		}

		const endpoint: CompactionEndpointSummary = {
			lineNumber,
			entryId: typeof raw.id === "string" ? raw.id : null,
			timestamp: tsStr,
			method,
			tokensBefore,
			tokensAfter,
		};
		this.firstCompaction ??= endpoint;
		this.lastCompaction = endpoint;

		if (method === "handoff" && typeof raw.summary === "string" && raw.summary.trim().length > 0) {
			this.handoffSummaryEntryCount++;
			if (this.handoffSummaries.length < MAX_TRACKED_HANDOFF_SUMMARIES) {
				this.handoffSummaries.push({
					source: `compaction:L${lineNumber}`,
					summary: raw.summary,
				});
			}
		}
	}

	#visitCustomEntry(raw: Record<string, unknown>): void {
		const customType = raw.customType;
		const data = isRecord(raw.data) ? raw.data : undefined;
		if (customType === TOOL_EXECUTION_START_CUSTOM_TYPE && data && typeof data.toolName === "string") {
			this.executionStartCount++;
			// Normalize `write` targeting `xd://<tool>` when summarized path reveals device name.
			const args = isRecord(data.args) ? data.args : undefined;
			const rawPath = typeof args?.path === "string" ? args.path : undefined;
			const effectiveTool =
				data.toolName === "write" && rawPath?.startsWith("xd://")
					? rawPath.slice("xd://".length).split(/[/?#]/, 1)[0] || "write"
					: data.toolName;
			incrementCounter(this.executionStartByTool, effectiveTool);
			if (typeof data.toolCallId === "string") {
				if (!this.#toolCallArgsById.has(data.toolCallId) && this.#toolCallArgsById.size >= MAX_PENDING_TOOL_CALLS) {
					const oldestKey = this.#toolCallArgsById.keys().next().value;
					if (oldestKey !== undefined) this.#toolCallArgsById.delete(oldestKey);
				}
				this.#toolCallArgsById.set(data.toolCallId, {
					toolName: effectiveTool,
					pathArg: rawPath,
				});
			}
			return;
		}
		if (customType === SESSION_EXIT_CUSTOM_TYPE && data) {
			if (typeof data.reason === "string") this.exitReason = data.reason;
			if (typeof data.kind === "string") this.exitKind = data.kind;
			if (typeof data.recordedAt === "string") {
				const ms = parseTimestampMs(data.recordedAt);
				if (ms !== null && (this.lastTimestampMs === null || ms > this.lastTimestampMs)) {
					this.lastTimestampMs = ms;
					this.lastTimestampStr = data.recordedAt;
				}
			}
		}
	}

	#visitMessage(message: Record<string, unknown>): void {
		const role = message.role;
		if (role === "assistant") {
			const content = Array.isArray(message.content) ? message.content : [];
			for (const block of content) {
				if (!isRecord(block)) continue;
				if (block.type === "text" && typeof block.text === "string") {
					this.#scanShakenRegions(block.text, "block");
				} else if (block.type === "toolCall" && typeof block.name === "string") {
					this.assistantToolCallCount++;
					const args = isRecord(block.arguments) ? block.arguments : undefined;
					const pathArg = typeof args?.path === "string" ? args.path : undefined;
					const effectiveName =
						block.name === "write" && pathArg?.startsWith("xd://")
							? pathArg.slice("xd://".length).split(/[/?#]/, 1)[0] || "write"
							: block.name;
					incrementCounter(this.assistantToolCallsByTool, effectiveName);
					if (typeof block.id === "string" && !this.#toolCallArgsById.has(block.id)) {
						if (this.#toolCallArgsById.size >= MAX_PENDING_TOOL_CALLS) {
							const oldestKey = this.#toolCallArgsById.keys().next().value;
							if (oldestKey !== undefined) this.#toolCallArgsById.delete(oldestKey);
						}
						this.#toolCallArgsById.set(block.id, { toolName: effectiveName, pathArg });
					}
				}
			}
			return;
		}

		if (role === "user" || role === "developer" || role === "custom") {
			const text = extractTextFromContent(message.content);
			this.#scanShakenRegions(text, "block");
			return;
		}

		if (role === "toolResult") {
			this.#visitToolResult(message);
		}
	}

	#visitToolResult(message: Record<string, unknown>): void {
		this.toolResultTotal++;
		const isError = message.isError === true;
		if (isError) this.toolResultErrorCount++;

		const rawToolName = typeof message.toolName === "string" ? message.toolName : undefined;
		const toolCallId = typeof message.toolCallId === "string" ? message.toolCallId : undefined;
		const callInfo = toolCallId ? this.#toolCallArgsById.get(toolCallId) : undefined;
		if (toolCallId) {
			// Bound map growth across multi-thousand-call sessions once paired toolResult arrives.
			this.#toolCallArgsById.delete(toolCallId);
		}

		const text = extractTextFromContent(message.content);
		const regionMatches = this.#scanShakenRegions(text, "toolResult");
		if (regionMatches > 0) {
			this.shakenToolResultCount++;
			if (isError) this.shakenErrorToolResultCount++;
		}

		const { effectiveToolName, effectiveDetails } = unwrapEffectiveDetails(
			rawToolName ?? callInfo?.toolName,
			message.details,
		);

		this.#collectTruncationMeta(effectiveDetails, message.details);
		this.#collectReadIndicators(effectiveToolName, callInfo?.pathArg, effectiveDetails);
		this.#collectEvalIndicators(effectiveToolName, isError, effectiveDetails, text);
		this.#collectEditIndicators(rawToolName, effectiveToolName, isError, message, effectiveDetails);
		this.#collectPrerequisiteIndicators(effectiveToolName, isError, effectiveDetails);
	}

	#scanShakenRegions(text: string, kind: "toolResult" | "block"): number {
		if (!text.includes("[shaken ~")) return 0;
		SHAKEN_REGION_RE.lastIndex = 0;
		let matchedCount = 0;
		for (let match = SHAKEN_REGION_RE.exec(text); match !== null; match = SHAKEN_REGION_RE.exec(text)) {
			matchedCount++;
			this.totalRegionsInTranscript++;
			if (kind === "toolResult") this.toolResultRegions++;
			else this.messageBlockRegions++;

			const tokens = Number.parseInt(match[1] ?? "0", 10);
			if (Number.isFinite(tokens) && tokens > 0) {
				this.estimatedTokensElided += tokens;
			}
			const artifactId = match[2];
			if (artifactId) {
				if (this.shakenArtifactIds.has(artifactId) || this.shakenArtifactIds.size < MAX_TRACKED_SHAKEN_ARTIFACTS) {
					this.shakenArtifactIds.add(artifactId);
					const regionNum = match[3] ? Number.parseInt(match[3], 10) : 0;
					if (regionNum > 0) {
						const prev = this.maxRegionByArtifact[artifactId] ?? 0;
						if (regionNum > prev) this.maxRegionByArtifact[artifactId] = regionNum;
					}
				}
			}
		}
		return matchedCount;
	}

	#collectTruncationMeta(effectiveDetails: Record<string, unknown> | undefined, outerDetails: unknown): void {
		const meta =
			(isRecord(effectiveDetails?.meta) ? effectiveDetails.meta : undefined) ??
			(isRecord(outerDetails) && isRecord(outerDetails.meta) ? outerDetails.meta : undefined);
		if (!meta) return;

		const trunc = isRecord(meta.truncation) ? meta.truncation : undefined;
		if (trunc) {
			this.truncatedResultCount++;
			if (typeof trunc.totalBytes === "number" && Number.isFinite(trunc.totalBytes)) {
				this.totalSourceBytes += trunc.totalBytes;
			}
			if (typeof trunc.outputBytes === "number" && Number.isFinite(trunc.outputBytes)) {
				this.totalInlineOutputBytes += trunc.outputBytes;
			}
			if (typeof trunc.elidedBytes === "number" && Number.isFinite(trunc.elidedBytes)) {
				this.totalInlineElidedBytes += trunc.elidedBytes;
			}
			const artifactBytes =
				typeof trunc.artifactBytes === "number"
					? trunc.artifactBytes
					: typeof trunc.capturedBytes === "number"
						? trunc.capturedBytes
						: undefined;
			if (artifactBytes !== undefined && Number.isFinite(artifactBytes)) {
				this.totalMetaArtifactBytes += artifactBytes;
			}
			if (typeof trunc.artifactElidedBytes === "number" && Number.isFinite(trunc.artifactElidedBytes)) {
				this.totalMetaArtifactElidedBytes += trunc.artifactElidedBytes;
			}
		}

		const budgetExhausted =
			meta.artifactBudgetExhausted === true ||
			trunc?.artifactBudgetExhausted === true ||
			meta.artifactError === "budget" ||
			meta.artifactError === "budget_exhausted";
		if (budgetExhausted) {
			this.budgetExhaustedCount++;
		}
	}

	#collectReadIndicators(
		effectiveToolName: string,
		pathArg: string | undefined,
		effectiveDetails: Record<string, unknown> | undefined,
	): void {
		if (effectiveToolName !== "read") return;
		const meta = isRecord(effectiveDetails?.meta) ? effectiveDetails.meta : undefined;
		const sourceVal = isRecord(meta?.source) && typeof meta.source.value === "string" ? meta.source.value : undefined;
		const target = pathArg ?? sourceVal;
		if (this.compactionCount > 0) {
			this.postCompactionReadCount++;
			if (target?.startsWith("artifact://")) {
				this.postCompactionArtifactReadCount++;
			}
		}
		if (target && !target.startsWith("xd://")) {
			const base = normalizeReadSelectorBase(target);
			if (this.#seenReadBases.has(base)) {
				this.repeatedPathReadCount++;
				// Refresh recency order in the bounded Set.
				this.#seenReadBases.delete(base);
				this.#seenReadBases.add(base);
			} else {
				if (this.#seenReadBases.size >= MAX_TRACKED_READ_PATHS) {
					const oldestBase = this.#seenReadBases.values().next().value;
					if (oldestBase !== undefined) this.#seenReadBases.delete(oldestBase);
				}
				this.#seenReadBases.add(base);
			}
		}
	}

	#collectEvalIndicators(
		effectiveToolName: string,
		isError: boolean,
		effectiveDetails: Record<string, unknown> | undefined,
		text: string,
	): void {
		if (effectiveToolName !== "eval" || !isError) return;
		const structuredNames = new Set<string>();
		if (Array.isArray(effectiveDetails?.missingNames)) {
			for (const name of effectiveDetails.missingNames) {
				if (typeof name === "string" && name.length > 0) structuredNames.add(name);
			}
		}
		if (Array.isArray(effectiveDetails?.cells)) {
			for (const cell of effectiveDetails.cells) {
				if (isRecord(cell) && Array.isArray(cell.missingNames)) {
					for (const name of cell.missingNames) {
						if (typeof name === "string" && name.length > 0) structuredNames.add(name);
					}
				}
			}
		}
		if (structuredNames.size > 0) {
			this.evalStateErrorTotal++;
			this.evalStructuredMissingCount++;
			if (this.compactionCount > 0) this.evalPostCompactionCount++;
			for (const name of structuredNames) {
				if (this.evalMissingNames.size < MAX_EVAL_MISSING_NAMES) this.evalMissingNames.add(name);
			}
			return;
		}

		// Historical fallback: inspect traceback text when structured `missingNames` was not yet persisted.
		EVAL_TRACEBACK_MISSING_RE.lastIndex = 0;
		const inferredNames = new Set<string>();
		for (
			let match = EVAL_TRACEBACK_MISSING_RE.exec(text);
			match !== null;
			match = EVAL_TRACEBACK_MISSING_RE.exec(text)
		) {
			const sym = match[1] ?? match[2];
			if (sym) inferredNames.add(sym);
		}
		if (inferredNames.size > 0) {
			this.evalStateErrorTotal++;
			this.evalTracebackInferredCount++;
			if (this.compactionCount > 0) this.evalPostCompactionCount++;
			for (const name of inferredNames) {
				if (this.evalMissingNames.size < MAX_EVAL_MISSING_NAMES) this.evalMissingNames.add(name);
			}
		}
	}

	#collectEditIndicators(
		rawToolName: string | undefined,
		effectiveToolName: string,
		isError: boolean,
		message: Record<string, unknown>,
		effectiveDetails: Record<string, unknown> | undefined,
	): void {
		if (effectiveToolName !== "edit" || !isError) return;
		this.editTotalErrorCount++;

		const resultLike = {
			toolName: rawToolName ?? "edit",
			isError: true,
			details: message.details,
			content: message.content,
		};

		let structuredKind = extractEditErrorKind(resultLike, { allowTextFallback: false });
		// Also inspect nested per-file outcomes once per call if top-level errorKind is absent.
		if (!structuredKind && Array.isArray(effectiveDetails?.files)) {
			for (const fileEntry of effectiveDetails.files) {
				if (isRecord(fileEntry) && typeof fileEntry.errorKind === "string" && fileEntry.errorKind.length > 0) {
					structuredKind = fileEntry.errorKind;
					break;
				}
			}
		}

		const finalKind = structuredKind ?? extractEditErrorKind(resultLike, { allowTextFallback: true });
		if (finalKind) {
			incrementCounter(this.editByErrorKind, finalKind);
			if (structuredKind) this.editStructuredCount++;
			else this.editTextInferredCount++;

			const category = classifyEditRejection(finalKind);
			if (category === "anchor_reject") {
				this.editAnchorRejectCount++;
				if (this.compactionCount > 0) this.editPostCompactionAnchorOrHashCount++;
			} else if (category === "hash_reject") {
				this.editHashRejectCount++;
				if (this.compactionCount > 0) this.editPostCompactionAnchorOrHashCount++;
			} else {
				this.editOtherErrorCount++;
			}
		} else {
			this.editOtherErrorCount++;
		}
	}

	#collectPrerequisiteIndicators(
		effectiveToolName: string,
		isError: boolean,
		effectiveDetails: Record<string, unknown> | undefined,
	): void {
		if (!isError || !effectiveDetails) return;
		const block = isRecord(effectiveDetails.prerequisiteBlock) ? effectiveDetails.prerequisiteBlock : undefined;
		const isDeterministicPrereq =
			block?.deterministicFailure === true ||
			effectiveDetails.status === "blocked_prerequisite" ||
			effectiveDetails.deterministicFailure === true;
		if (!isDeterministicPrereq) return;

		this.prereqBlockTotal++;
		const toolKey = typeof block?.toolName === "string" ? block.toolName : effectiveToolName;
		incrementCounter(this.prereqByTool, toolKey);
		const gated = block?.blockedByGate === true || effectiveDetails.blockedByGate === true;
		if (gated) this.prereqGateBlockedCount++;
		else this.prereqBackendProbeFailureCount++;
	}

	async buildReport(options: {
		sessionFile: string | null;
		artifactsDir: string | null;
		handoffInvariants?: readonly HandoffRequiredInvariant[];
		handoffProvenance?: HandoffProvenance;
	}): Promise<SessionOutputMetricsReport> {
		const artifactStats = await scanArtifactsDirectory(
			options.artifactsDir,
			this.handoffSummaries,
			options.handoffInvariants,
			options.handoffProvenance ?? "unverified",
		);
		const durationMs =
			this.firstTimestampMs !== null &&
			this.lastTimestampMs !== null &&
			this.lastTimestampMs >= this.firstTimestampMs
				? this.lastTimestampMs - this.firstTimestampMs
				: null;

		const betweenCompactions = this.compactionIntervalsStats.toDistribution();
		const firstCompactionMs = this.firstCompaction ? parseTimestampMs(this.firstCompaction.timestamp) : null;
		const timeToFirstCompactionMs =
			firstCompactionMs !== null && this.firstTimestampMs !== null && firstCompactionMs >= this.firstTimestampMs
				? firstCompactionMs - this.firstTimestampMs
				: null;
		const throughputDurationPerCompactionMs =
			this.compactionCount > 0 && durationMs !== null ? durationMs / this.compactionCount : null;
		const useExecStarts = this.executionStartCount > 0;
		const sourceCounts = useExecStarts ? this.executionStartByTool : this.assistantToolCallsByTool;
		const topTools = Object.entries(sourceCounts)
			.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
			.map(([toolName, count]) => ({
				toolName,
				count,
				source: (useExecStarts ? "tool_execution_start" : "assistant_toolCall") as
					| "tool_execution_start"
					| "assistant_toolCall",
			}));

		// Subtract gate-intercepted no-op dispatches so callers can distinguish dispatch starts from backend runs.
		const backendRunEstimateByTool: Record<string, number> = { ...sourceCounts };
		if (this.prereqGateBlockedCount > 0) {
			for (const [tool, totalBlocked] of Object.entries(this.prereqByTool)) {
				if (backendRunEstimateByTool[tool] !== undefined) {
					const probeCount = Math.min(totalBlocked, 1);
					const gatedForTool = Math.max(0, totalBlocked - probeCount);
					backendRunEstimateByTool[tool] = Math.max(0, backendRunEstimateByTool[tool]! - gatedForTool);
				}
			}
		}

		return {
			schemaVersion: 1,
			sessionFile: options.sessionFile,
			artifactsDir: options.artifactsDir,
			artifactsDirExists: artifactStats.exists,
			sessionId: this.sessionId,
			runtimeVersion: this.runtimeVersion,
			observedRuntimes: this.observedRuntimes,
			analyzerRuntime: currentRuntimeIdentity(),
			physicalLines: this.physicalLines,
			malformedRecords: this.malformedRecords,
			oversizedLinesSkipped: this.oversizedLinesSkipped,
			window: {
				startTimestamp: this.firstTimestampStr,
				endTimestamp: this.lastTimestampStr,
				exitReason: this.exitReason,
				exitKind: this.exitKind,
				durationMs,
			},
			compaction: {
				count: this.compactionCount,
				methods: this.compactionMethods,
				warningCount: this.compactionWarningCount,
				fromExtensionCount: this.compactionFromExtensionCount,
				first: this.firstCompaction,
				last: this.lastCompaction,
				tokensBefore: this.tokensBeforeStats.toDistribution(),
				tokensAfter: this.tokensAfterStats.toDistribution(),
				totalTokensCompacted: this.#compactedDeltaPairs > 0 ? this.#compactedDeltaSum : null,
				intervalsMs: {
					betweenCompactions,
					timeToFirstCompactionMs,
					throughputDurationPerCompactionMs,
					betweenCompactionsAvgMinutes: betweenCompactions ? betweenCompactions.avg / 60_000 : null,
					timeToFirstCompactionMinutes: timeToFirstCompactionMs !== null ? timeToFirstCompactionMs / 60_000 : null,
					throughputDurationPerCompactionMinutes:
						throughputDurationPerCompactionMs !== null ? throughputDurationPerCompactionMs / 60_000 : null,
				},
			},
			toolCalls: {
				executionStartCount: this.executionStartCount,
				executionStartByTool: this.executionStartByTool,
				backendRunEstimateByTool,
				assistantToolCallCount: this.assistantToolCallCount,
				assistantToolCallsByTool: this.assistantToolCallsByTool,
				topTools,
			},
			toolResults: {
				total: this.toolResultTotal,
				errorCount: this.toolResultErrorCount,
				shakenToolResultCount: this.shakenToolResultCount,
				shakenErrorToolResultCount: this.shakenErrorToolResultCount,
				shakenToolResultRatio: this.toolResultTotal > 0 ? this.shakenToolResultCount / this.toolResultTotal : null,
				shakenRegions: {
					totalRegionsInTranscript: this.totalRegionsInTranscript,
					toolResultRegions: this.toolResultRegions,
					messageBlockRegions: this.messageBlockRegions,
					distinctArtifactIds: [...this.shakenArtifactIds].sort((a, b) => Number(a) - Number(b)),
					maxRegionNumberByArtifact: this.maxRegionByArtifact,
					estimatedTokensElided: this.estimatedTokensElided,
				},
				truncationMeta: {
					truncatedResultCount: this.truncatedResultCount,
					totalSourceBytes: this.totalSourceBytes,
					totalInlineOutputBytes: this.totalInlineOutputBytes,
					totalInlineElidedBytes: this.totalInlineElidedBytes,
					totalArtifactBytes: this.totalMetaArtifactBytes,
					totalArtifactElidedBytes: this.totalMetaArtifactElidedBytes,
					budgetExhaustedCount: this.budgetExhaustedCount,
				},
			},
			artifacts: {
				captureLogCount: artifactStats.captureLogCount,
				totalCaptureLogBytes: artifactStats.totalCaptureLogBytes,
				truncatedCaptureLogCount: artifactStats.truncatedCaptureLogCount,
				totalCaptureLogElidedBytes: artifactStats.totalCaptureLogElidedBytes,
				maxCaptureLog: artifactStats.topCaptureLogs[0] ?? null,
				topCaptureLogs: artifactStats.topCaptureLogs,
				shakeArtifactCount: artifactStats.shakeArtifactCount,
				shakeArtifactBytes: artifactStats.shakeArtifactBytes,
				shakeArtifactRegionsTotal: artifactStats.shakeArtifactRegionsTotal,
				handoffFileCount: artifactStats.handoffFileCount,
				handoffSummaryEntryCount: this.handoffSummaryEntryCount,
				handoffQuality: artifactStats.handoffQuality,
			},
			reconstructionIndicators: {
				classificationBasis: "approximate_observational",
				postCompactionReadCount: this.postCompactionReadCount,
				postCompactionArtifactReadCount: this.postCompactionArtifactReadCount,
				repeatedPathReadCount: this.repeatedPathReadCount,
				evalStateErrors: {
					total: this.evalStateErrorTotal,
					structuredMissingNameCount: this.evalStructuredMissingCount,
					historicalTracebackInferredCount: this.evalTracebackInferredCount,
					postCompactionCount: this.evalPostCompactionCount,
					missingNames: [...this.evalMissingNames].sort(),
				},
				editRejections: {
					totalErrorCount: this.editTotalErrorCount,
					anchorRejectCount: this.editAnchorRejectCount,
					hashRejectCount: this.editHashRejectCount,
					otherErrorCount: this.editOtherErrorCount,
					byErrorKind: this.editByErrorKind,
					structuredCount: this.editStructuredCount,
					historicalTextInferredCount: this.editTextInferredCount,
					postCompactionAnchorOrHashCount: this.editPostCompactionAnchorOrHashCount,
				},
				prerequisiteBlocks: {
					total: this.prereqBlockTotal,
					gateBlockedCount: this.prereqGateBlockedCount,
					backendProbeFailureCount: this.prereqBackendProbeFailureCount,
					byTool: this.prereqByTool,
				},
			},
		};
	}
}

async function detectLogTruncationMarker(
	filePath: string,
	fileSize: number,
): Promise<{
	truncated: boolean;
	elidedBytes: number | null;
}> {
	if (fileSize < 20) return { truncated: false, elidedBytes: null };
	const decoder = new TextDecoder();
	let carry = "";
	for await (const chunk of Bun.file(filePath).stream()) {
		const windowText = carry + decoder.decode(chunk, { stream: true });
		const marker = LOG_TRUNCATION_MARKER_RE.exec(windowText)?.[0];
		if (marker) {
			// 人类可读的 KB/MB 数值经过舍入；只把明确的整数 B/bytes 当作精确字节数。
			const exact = EXACT_ELIDED_BYTES_RE.exec(marker)?.[1];
			const bytes = exact === undefined ? null : Number(exact.replace(/,/g, ""));
			return { truncated: true, elidedBytes: bytes !== null && Number.isSafeInteger(bytes) ? bytes : null };
		}
		carry = windowText.slice(-256);
	}
	return { truncated: false, elidedBytes: null };
}

async function countShakeArtifactRegions(filePath: string): Promise<number> {
	const decoder = new TextDecoder();
	let carry = "";
	let count = 0;
	for await (const chunk of Bun.file(filePath).stream()) {
		const text = carry + decoder.decode(chunk, { stream: true });
		const lastNl = text.lastIndexOf("\n");
		if (lastNl === -1) {
			carry = text;
			continue;
		}
		const complete = text.slice(0, lastNl + 1);
		carry = text.slice(lastNl + 1);
		SHAKE_ARTIFACT_HEADER_RE.lastIndex = 0;
		while (SHAKE_ARTIFACT_HEADER_RE.exec(complete) !== null) count++;
	}
	const rest = carry + decoder.decode();
	if (rest.length > 0) {
		SHAKE_ARTIFACT_HEADER_RE.lastIndex = 0;
		while (SHAKE_ARTIFACT_HEADER_RE.exec(rest) !== null) count++;
	}
	return count;
}

async function scanArtifactsDirectory(
	artifactsDir: string | null,
	journalHandoffSummaries: readonly { source: string; summary: string }[],
	handoffInvariants: readonly HandoffRequiredInvariant[] | undefined,
	handoffProvenance: HandoffProvenance,
): Promise<{
	exists: boolean;
	captureLogCount: number;
	totalCaptureLogBytes: number;
	truncatedCaptureLogCount: number;
	totalCaptureLogElidedBytes: number | null;
	topCaptureLogs: CaptureLogEntry[];
	shakeArtifactCount: number;
	shakeArtifactBytes: number;
	shakeArtifactRegionsTotal: number;
	handoffFileCount: number;
	handoffQuality: HandoffQualitySummary | null;
}> {
	let entries: string[] = [];
	let exists = false;
	if (artifactsDir) {
		try {
			entries = await fs.readdir(artifactsDir);
			exists = true;
		} catch {
			exists = false;
		}
	}

	let captureLogCount = 0;
	let totalCaptureLogBytes = 0;
	let truncatedCaptureLogCount = 0;
	let totalCaptureLogElidedBytes: number | null = 0;
	const captureLogs: CaptureLogEntry[] = [];

	let shakeArtifactCount = 0;
	let shakeArtifactBytes = 0;
	let shakeArtifactRegionsTotal = 0;

	const handoffFiles: string[] = [];

	for (const fileName of entries) {
		if (!artifactsDir) break;
		// Ignore atomic staging files created by writeArtifact.
		if (fileName.includes(".tmp-")) continue;

		if (/^handoff-.*\.md$/i.test(fileName)) {
			handoffFiles.push(fileName);
			continue;
		}

		const logMatch = /^(\d+)\.(.+)\.log$/.exec(fileName);
		if (!logMatch) continue;
		const artifactId = Number.parseInt(logMatch[1]!, 10);
		const toolType = logMatch[2]!;
		const fullPath = path.join(artifactsDir, fileName);
		let size = 0;
		try {
			const st = await fs.stat(fullPath);
			if (!st.isFile()) continue;
			size = st.size;
		} catch {
			continue;
		}

		if (toolType === "shake") {
			shakeArtifactCount++;
			shakeArtifactBytes += size;
			shakeArtifactRegionsTotal += await countShakeArtifactRegions(fullPath);
			continue;
		}

		captureLogCount++;
		totalCaptureLogBytes += size;
		const marker = await detectLogTruncationMarker(fullPath, size);
		if (marker.truncated) {
			truncatedCaptureLogCount++;
			totalCaptureLogElidedBytes =
				marker.elidedBytes === null || totalCaptureLogElidedBytes === null
					? null
					: totalCaptureLogElidedBytes + marker.elidedBytes;
		}
		captureLogs.push({
			fileName,
			artifactId,
			toolType,
			bytes: size,
			truncatedOnDisk: marker.truncated,
			elidedBytes: marker.elidedBytes,
		});
		if (captureLogs.length > TOP_CAPTURE_LOGS_LIMIT * 2) {
			captureLogs.sort((a, b) => b.bytes - a.bytes || a.artifactId - b.artifactId);
			captureLogs.length = TOP_CAPTURE_LOGS_LIMIT;
		}
	}

	captureLogs.sort((a, b) => b.bytes - a.bytes || a.artifactId - b.artifactId);
	if (captureLogs.length > TOP_CAPTURE_LOGS_LIMIT) captureLogs.length = TOP_CAPTURE_LOGS_LIMIT;

	handoffFiles.sort();
	const evaluatedDocs: Array<{ source: string; quality: HandoffDocumentQuality }> = [];
	if (artifactsDir && handoffFiles.length > 0) {
		for (const fileName of handoffFiles) {
			try {
				const md = await Bun.file(path.join(artifactsDir, fileName)).text();
				evaluatedDocs.push({
					source: fileName,
					quality: evaluateHandoffDocumentQuality(md, handoffInvariants),
				});
			} catch {
				// Unreadable handoff file is skipped rather than crashing the report.
			}
		}
	} else if (journalHandoffSummaries.length > 0) {
		for (const item of journalHandoffSummaries) {
			evaluatedDocs.push({
				source: item.source,
				quality: evaluateHandoffDocumentQuality(item.summary, handoffInvariants),
			});
		}
	}

	const handoffQuality: HandoffQualitySummary | null =
		evaluatedDocs.length === 0
			? null
			: {
					evaluationScope: "structural_and_invariant_coverage",
					provenance: handoffProvenance,
					evaluatedCount: evaluatedDocs.length,
					structuralCompleteCount: evaluatedDocs.filter(d => d.quality.structuralComplete).length,
					invariantMatchedCount:
						handoffInvariants && handoffInvariants.length > 0
							? evaluatedDocs.filter(d => d.quality.allInvariantsMatched === true).length
							: null,
					documents: evaluatedDocs,
				};
	return {
		exists,
		captureLogCount,
		totalCaptureLogBytes,
		truncatedCaptureLogCount,
		totalCaptureLogElidedBytes,
		topCaptureLogs: captureLogs,
		shakeArtifactCount,
		shakeArtifactBytes,
		shakeArtifactRegionsTotal,
		handoffFileCount: handoffFiles.length,
		handoffQuality,
	};
}

/**
 * Stream a session `.jsonl` file in bounded memory (with a hard per-line byte guard)
 * and compute all #20 output, artifact, compaction, and observational reconstruction metrics.
 */
export async function computeSessionOutputMetrics(
	sessionFilePath: string,
	options: SessionOutputMetricsOptions = {},
): Promise<SessionOutputMetricsReport> {
	const resolvedSessionFile = path.resolve(sessionFilePath);
	const artifactsDir = resolveSessionArtifactsDirectory(resolvedSessionFile, options.artifactsDir);
	const maxLineBytes = Math.max(4_096, options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES);

	const stat = await fs.stat(resolvedSessionFile);
	if (!stat.isFile()) {
		throw new Error(`Session path is not a file: ${resolvedSessionFile}`);
	}

	const acc = new MetricsAccumulator();
	const decoder = new TextDecoder();
	let lineChunks: Uint8Array[] = [];
	let lineBytes = 0;
	let discardingOversizedLine = false;

	const processCompleteLine = (trailingChunk?: Uint8Array): void => {
		acc.physicalLines++;
		if (discardingOversizedLine) {
			acc.oversizedLinesSkipped++;
			lineChunks = [];
			lineBytes = 0;
			discardingOversizedLine = false;
			return;
		}
		if (trailingChunk && trailingChunk.byteLength > 0) {
			if (lineBytes + trailingChunk.byteLength > maxLineBytes) {
				acc.oversizedLinesSkipped++;
				lineChunks = [];
				lineBytes = 0;
				return;
			}
			lineChunks.push(trailingChunk);
			lineBytes += trailingChunk.byteLength;
		}
		if (lineBytes === 0) return;

		let merged: Uint8Array;
		if (lineChunks.length === 1) {
			merged = lineChunks[0]!;
		} else {
			merged = new Uint8Array(lineBytes);
			let offset = 0;
			for (const part of lineChunks) {
				merged.set(part, offset);
				offset += part.byteLength;
			}
		}
		lineChunks = [];
		lineBytes = 0;

		const lineText = decoder.decode(merged).trim();
		if (lineText.length === 0) return;
		if (acc.physicalLines === 1 && parseTitleSlotLine(lineText)) {
			return;
		}
		try {
			const parsed: unknown = JSON.parse(lineText);
			acc.visitEntry(parsed, acc.physicalLines);
		} catch {
			acc.malformedRecords++;
		}
	};

	for await (const chunk of Bun.file(resolvedSessionFile).stream()) {
		let start = 0;
		for (let i = 0; i < chunk.byteLength; i++) {
			if (chunk[i] === 0x0a) {
				const slice = chunk.subarray(start, i);
				processCompleteLine(slice);
				start = i + 1;
			}
		}
		if (start < chunk.byteLength) {
			const remainder = chunk.subarray(start);
			if (discardingOversizedLine) {
				continue;
			}
			if (lineBytes + remainder.byteLength > maxLineBytes) {
				discardingOversizedLine = true;
				lineChunks = [];
				lineBytes = 0;
			} else {
				// Copy subarray out of stream buffer so the underlying stream chunk can be GC'd promptly.
				lineChunks.push(remainder.slice());
				lineBytes += remainder.byteLength;
			}
		}
	}

	if (discardingOversizedLine || lineBytes > 0) {
		processCompleteLine();
	}

	return await acc.buildReport({
		sessionFile: resolvedSessionFile,
		artifactsDir,
		handoffInvariants: options.handoffInvariants,
		handoffProvenance: options.handoffProvenance,
	});
}

/** Compute the same metrics directly from in-memory session entries (used by unit tests and controlled replays). */
export async function computeSessionOutputMetricsFromEntries(
	entries: readonly FileEntry[],
	options: SessionOutputMetricsFromEntriesOptions = {},
): Promise<SessionOutputMetricsReport> {
	const acc = new MetricsAccumulator();
	for (let index = 0; index < entries.length; index++) {
		acc.physicalLines++;
		acc.visitEntry(entries[index], index + 1);
	}
	return await acc.buildReport({
		sessionFile: options.sessionFile ?? null,
		artifactsDir: options.artifactsDir ?? null,
		handoffInvariants: options.handoffInvariants,
		handoffProvenance: options.handoffProvenance,
	});
}

/**
 * Evaluate candidate metrics against a baseline across all five acceptance axes from issue #20:
 * (a) compaction count decreases or mean interval increases
 * (b) max per-call capture log <= configured budget
 * (c) shaken toolResult ratio decreases (or stays 0 when already 0)
 * (d) post-compaction state/anchor error indicators do not increase
 * (e) handoff structural/invariant coverage does not regress (`"unknown"` when handoff docs were not generated)
 *
 * Enforces the explicit #20 rule: compaction count reduction alone never passes when another axis fails or is unknown.
 */
export function compareSessionOutputMetrics(
	candidate: SessionOutputMetricsReport,
	baseline: SessionOutputMetricsReport,
	thresholds: SessionOutputComparisonThresholds = {},
): SessionOutputComparisonReport {
	const maxCap = thresholds.maxSingleCaptureLogBytes ?? 4 * 1024 * 1024;

	// (a) Compaction count decreases OR interval increases
	const candCount = candidate.compaction.count;
	const baseCount = baseline.compaction.count;
	const candInterval =
		candidate.compaction.intervalsMs.betweenCompactions?.avg ??
		candidate.compaction.intervalsMs.timeToFirstCompactionMs;
	const baseInterval =
		baseline.compaction.intervalsMs.betweenCompactions?.avg ??
		baseline.compaction.intervalsMs.timeToFirstCompactionMs;
	const countDecreased = candCount < baseCount;
	const intervalIncreased = candInterval !== null && baseInterval !== null && candInterval > baseInterval;
	const equalAllowed = thresholds.allowEqualCompactionPace === true && candCount <= baseCount;
	const compactionPace: AxisEvaluation = {
		status: countDecreased || intervalIncreased || equalAllowed ? "pass" : "fail",
		reason: countDecreased
			? `compaction count decreased (${baseCount} -> ${candCount})`
			: intervalIncreased
				? `mean compaction interval increased (${Math.round(baseInterval!)}ms -> ${Math.round(candInterval!)}ms)`
				: equalAllowed
					? `compaction count non-increasing (${baseCount} -> ${candCount})`
					: `neither compaction count (${baseCount} -> ${candCount}) nor interval improved`,
		candidateValue: { count: candCount, avgIntervalMs: candInterval },
		baselineValue: { count: baseCount, avgIntervalMs: baseInterval },
	};

	// (b) Max single per-call capture log <= configured budget
	const candMaxBytes = candidate.artifacts.maxCaptureLog?.bytes ?? 0;
	const baseMaxBytes = baseline.artifacts.maxCaptureLog?.bytes ?? 0;
	const singleArtifactCap: AxisEvaluation = {
		status: candMaxBytes <= maxCap ? "pass" : "fail",
		reason:
			candMaxBytes <= maxCap
				? `max capture log ${candMaxBytes} B <= budget ${maxCap} B`
				: `max capture log ${candMaxBytes} B exceeds budget ${maxCap} B`,
		candidateValue: candMaxBytes,
		baselineValue: baseMaxBytes,
	};

	// (c) [shaken] ratio decreases (or remains 0 when baseline is 0)
	const candShaken = candidate.toolResults.shakenToolResultRatio;
	const baseShaken = baseline.toolResults.shakenToolResultRatio;
	let shakenRatio: AxisEvaluation;
	if (candShaken === null || baseShaken === null) {
		shakenRatio = {
			status: "unknown",
			reason: "toolResult count is zero; shaken ratio undefined",
			candidateValue: candShaken,
			baselineValue: baseShaken,
		};
	} else {
		const shakenImproved = candShaken < baseShaken || (candShaken === 0 && baseShaken === 0);
		shakenRatio = {
			status: shakenImproved ? "pass" : "fail",
			reason: shakenImproved
				? `shaken toolResult ratio ${(baseShaken * 100).toFixed(2)}% -> ${(candShaken * 100).toFixed(2)}%`
				: `shaken toolResult ratio did not decrease (${(baseShaken * 100).toFixed(2)}% -> ${(candShaken * 100).toFixed(2)}%)`,
			candidateValue: candShaken,
			baselineValue: baseShaken,
		};
	}

	// (d) Post-compaction state/anchor error indicators do not increase
	const candStateErrors =
		candidate.reconstructionIndicators.evalStateErrors.total +
		candidate.reconstructionIndicators.editRejections.anchorRejectCount +
		candidate.reconstructionIndicators.editRejections.hashRejectCount;
	const baseStateErrors =
		baseline.reconstructionIndicators.evalStateErrors.total +
		baseline.reconstructionIndicators.editRejections.anchorRejectCount +
		baseline.reconstructionIndicators.editRejections.hashRejectCount;
	const postCompactionStateErrors: AxisEvaluation = {
		status: candStateErrors <= baseStateErrors ? "pass" : "fail",
		reason:
			candStateErrors <= baseStateErrors
				? `state/anchor errors did not increase (${baseStateErrors} -> ${candStateErrors})`
				: `state/anchor errors increased (${baseStateErrors} -> ${candStateErrors})`,
		candidateValue: candStateErrors,
		baselineValue: baseStateErrors,
	};

	// (e) Handoff structural & required-invariant coverage does not regress (`unknown` if no handoff docs or fixture-only)
	const candHandoff = candidate.artifacts.handoffQuality;
	const baseHandoff = baseline.artifacts.handoffQuality;
	const baseHandoffSummary = baseHandoff
		? {
				provenance: baseHandoff.provenance,
				evaluatedCount: baseHandoff.evaluatedCount,
				structuralCompleteCount: baseHandoff.structuralCompleteCount,
				invariantMatchedCount: baseHandoff.invariantMatchedCount,
			}
		: null;
	let handoffStructuralCoverage: AxisEvaluation;
	if (!candHandoff || candHandoff.evaluatedCount === 0) {
		handoffStructuralCoverage = {
			status: "unknown",
			reason: "no handoff documents present in candidate run; handoff coverage not exercised",
			candidateValue: null,
			baselineValue: baseHandoffSummary,
		};
	} else if (candHandoff.provenance === "fixture") {
		handoffStructuralCoverage = {
			status: "unknown",
			reason:
				"candidate handoff documents are deterministic fixture templates only; real-model handoff quality not exercised",
			candidateValue: {
				provenance: candHandoff.provenance,
				evaluatedCount: candHandoff.evaluatedCount,
				structuralCompleteCount: candHandoff.structuralCompleteCount,
				invariantMatchedCount: candHandoff.invariantMatchedCount,
			},
			baselineValue: baseHandoffSummary,
		};
	} else {
		const candStructRate = candHandoff.structuralCompleteCount / candHandoff.evaluatedCount;
		const baseStructRate =
			baseHandoff && baseHandoff.evaluatedCount > 0
				? baseHandoff.structuralCompleteCount / baseHandoff.evaluatedCount
				: 1;
		const candInvRate =
			candHandoff.invariantMatchedCount !== null
				? candHandoff.invariantMatchedCount / candHandoff.evaluatedCount
				: null;
		const baseInvRate =
			baseHandoff && baseHandoff.evaluatedCount > 0 && baseHandoff.invariantMatchedCount !== null
				? baseHandoff.invariantMatchedCount / baseHandoff.evaluatedCount
				: candInvRate !== null
					? 1
					: null;
		const structOk = candStructRate >= baseStructRate && candStructRate === 1;
		const invOk = candInvRate === null || (baseInvRate !== null && candInvRate >= baseInvRate && candInvRate === 1);
		handoffStructuralCoverage = {
			status: structOk && invOk ? "pass" : "fail",
			reason:
				structOk && invOk
					? `handoff structural coverage ${candHandoff.structuralCompleteCount}/${candHandoff.evaluatedCount}` +
						(candHandoff.invariantMatchedCount !== null
							? `, invariants ${candHandoff.invariantMatchedCount}/${candHandoff.evaluatedCount}`
							: "")
					: `handoff structural/invariant coverage incomplete or regressed`,
			candidateValue: {
				provenance: candHandoff.provenance,
				evaluatedCount: candHandoff.evaluatedCount,
				structuralCompleteCount: candHandoff.structuralCompleteCount,
				invariantMatchedCount: candHandoff.invariantMatchedCount,
			},
			baselineValue: baseHandoffSummary,
		};
	}

	const deterministicFour = [compactionPace, singleArtifactCap, shakenRatio, postCompactionStateErrors];
	const deterministicAxesPassed =
		deterministicFour.every(axis => axis.status === "pass") && handoffStructuralCoverage.status !== "fail";
	const otherAxes = [singleArtifactCap, shakenRatio, postCompactionStateErrors, handoffStructuralCoverage];
	const allAxesPass = compactionPace.status === "pass" && otherAxes.every(axis => axis.status === "pass");
	const compactionDropAloneGuardTriggered =
		compactionPace.status === "pass" && otherAxes.some(axis => axis.status !== "pass");

	return {
		passed: allAxesPass,
		deterministicAxesPassed,
		compactionDropAloneGuardTriggered,
		axes: {
			compactionPace,
			singleArtifactCap,
			shakenRatio,
			postCompactionStateErrors,
			handoffStructuralCoverage,
		},
	};
}

const numericDistributionSchema = type({
	count: "number",
	min: "number",
	max: "number",
	avg: "number",
	p50: "number",
	p90: "number",
	total: "number",
});

const compactionEndpointSchema = type({
	lineNumber: "number",
	entryId: "string | null",
	timestamp: "string | null",
	method: "string",
	tokensBefore: "number | null",
	tokensAfter: "number | null",
});

const captureLogEntrySchema = type({
	fileName: "string",
	artifactId: "number",
	toolType: "string",
	bytes: "number",
	truncatedOnDisk: "boolean",
	elidedBytes: "number | null",
});

const runtimeIdentitySchema = type({
	version: "string",
	"commit?": "string",
	"branch?": "string",
	"diff?": "string",
	"label?": "string",
});

const handoffDocumentQualitySchema = type({
	evaluationScope: "'structural_and_invariant_coverage'",
	presentHeadings: "string[]",
	missingHeadings: "string[]",
	structuralComplete: "boolean",
	checkedInvariants: type({ name: "string", matched: "boolean" }).array(),
	allInvariantsMatched: "boolean | null",
	byteLength: "number",
});

const handoffQualitySummarySchema = type({
	evaluationScope: "'structural_and_invariant_coverage'",
	provenance: "'live_model' | 'fixture' | 'unverified'",
	evaluatedCount: "number",
	structuralCompleteCount: "number",
	invariantMatchedCount: "number | null",
	documents: type({
		source: "string",
		quality: handoffDocumentQualitySchema,
	}).array(),
});

const sessionOutputMetricsReportSchema = type({
	schemaVersion: "1",
	sessionFile: "string | null",
	artifactsDir: "string | null",
	artifactsDirExists: "boolean",
	sessionId: "string | null",
	runtimeVersion: "string | null",
	observedRuntimes: runtimeIdentitySchema.array(),
	analyzerRuntime: runtimeIdentitySchema,
	physicalLines: "number",
	malformedRecords: "number",
	oversizedLinesSkipped: "number",
	window: {
		startTimestamp: "string | null",
		endTimestamp: "string | null",
		exitReason: "string | null",
		exitKind: "string | null",
		durationMs: "number | null",
	},
	compaction: {
		count: "number",
		methods: "Record<string, number>",
		warningCount: "number",
		fromExtensionCount: "number",
		first: compactionEndpointSchema.or("null"),
		last: compactionEndpointSchema.or("null"),
		tokensBefore: numericDistributionSchema.or("null"),
		tokensAfter: numericDistributionSchema.or("null"),
		totalTokensCompacted: "number | null",
		intervalsMs: {
			betweenCompactions: numericDistributionSchema.or("null"),
			timeToFirstCompactionMs: "number | null",
			throughputDurationPerCompactionMs: "number | null",
			betweenCompactionsAvgMinutes: "number | null",
			timeToFirstCompactionMinutes: "number | null",
			throughputDurationPerCompactionMinutes: "number | null",
		},
	},
	toolCalls: {
		executionStartCount: "number",
		executionStartByTool: "Record<string, number>",
		backendRunEstimateByTool: "Record<string, number>",
		assistantToolCallCount: "number",
		assistantToolCallsByTool: "Record<string, number>",
		topTools: type({
			toolName: "string",
			count: "number",
			source: "'tool_execution_start' | 'assistant_toolCall'",
		}).array(),
	},
	toolResults: {
		total: "number",
		errorCount: "number",
		shakenToolResultCount: "number",
		shakenErrorToolResultCount: "number",
		shakenToolResultRatio: "number | null",
		shakenRegions: {
			totalRegionsInTranscript: "number",
			toolResultRegions: "number",
			messageBlockRegions: "number",
			distinctArtifactIds: "string[]",
			maxRegionNumberByArtifact: "Record<string, number>",
			estimatedTokensElided: "number",
		},
		truncationMeta: {
			truncatedResultCount: "number",
			totalSourceBytes: "number",
			totalInlineOutputBytes: "number",
			totalInlineElidedBytes: "number",
			totalArtifactBytes: "number",
			totalArtifactElidedBytes: "number",
			budgetExhaustedCount: "number",
		},
	},
	artifacts: {
		captureLogCount: "number",
		totalCaptureLogBytes: "number",
		truncatedCaptureLogCount: "number",
		totalCaptureLogElidedBytes: "number | null",
		maxCaptureLog: captureLogEntrySchema.or("null"),
		topCaptureLogs: captureLogEntrySchema.array(),
		shakeArtifactCount: "number",
		shakeArtifactBytes: "number",
		shakeArtifactRegionsTotal: "number",
		handoffFileCount: "number",
		handoffSummaryEntryCount: "number",
		handoffQuality: handoffQualitySummarySchema.or("null"),
	},
	reconstructionIndicators: {
		classificationBasis: "'approximate_observational'",
		postCompactionReadCount: "number",
		postCompactionArtifactReadCount: "number",
		repeatedPathReadCount: "number",
		evalStateErrors: {
			total: "number",
			structuredMissingNameCount: "number",
			historicalTracebackInferredCount: "number",
			postCompactionCount: "number",
			missingNames: "string[]",
		},
		editRejections: {
			totalErrorCount: "number",
			anchorRejectCount: "number",
			hashRejectCount: "number",
			otherErrorCount: "number",
			byErrorKind: "Record<string, number>",
			structuredCount: "number",
			historicalTextInferredCount: "number",
			postCompactionAnchorOrHashCount: "number",
		},
		prerequisiteBlocks: {
			total: "number",
			gateBlockedCount: "number",
			backendProbeFailureCount: "number",
			byTool: "Record<string, number>",
		},
	},
});

/** Validate an external JSON payload (or `{ metrics }` wrapper) as a complete SessionOutputMetricsReport. */
export function parseSessionOutputMetricsReport(raw: unknown): SessionOutputMetricsReport {
	const unwrapped = isRecord(raw) && !("schemaVersion" in raw) && "metrics" in raw ? raw.metrics : raw;
	const parsed = sessionOutputMetricsReportSchema(unwrapped);
	if (parsed instanceof type.errors) {
		throw new Error(`Invalid SessionOutputMetricsReport JSON: ${parsed.summary}`);
	}
	return parsed;
}
