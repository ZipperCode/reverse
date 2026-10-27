#!/usr/bin/env bun
/**
 * One-command local session output, artifact budget, and compaction metrics CLI (#20).
 *
 * Usage:
 *   bun scripts/session-output-metrics.ts <session.jsonl> --json
 *   bun scripts/session-output-metrics.ts <session.jsonl> --baseline <baseline.jsonl|report.json> --json
 *   bun scripts/session-output-metrics.ts <session.jsonl> --baseline <baseline.jsonl> \
 *     --handoff-invariants '[{"name":"anchor_sha","pattern":"ANCHOR_SHA = abcdef"}]' --require-pass
 *
 * `--require-pass` exits 1 unless the comparison passes all five axes; it requires `--baseline`.
 * Axis (e) only passes with observed live-model handoff provenance and supplied invariants on both
 * sides, so supply `--handoff-invariants`. Live-model origin is inferred only from a saved handoff
 * document that exactly matches its journal compaction summary; `--handoff-provenance` can only
 * downgrade to `fixture`/`unverified` and never asserts live-model origin.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { parseArgs } from "node:util";
import {
	compareSessionOutputMetrics,
	computeSessionOutputMetrics,
	parseSessionOutputMetricsReport,
	type HandoffProvenance,
	type HandoffRequiredInvariant,
	type SessionOutputComparisonReport,
	type SessionOutputMetricsReport,
} from "@reverse/coding-agent/session/output-metrics";
import { loadRuntimeIdentity } from "@reverse/coding-agent/session/runtime-identity";

const USAGE = [
	"Usage: bun scripts/session-output-metrics.ts <session.jsonl> [options]",
	"",
	"Options:",
	"  --artifacts-dir <dir>           Explicit session artifact directory",
	"  --baseline <jsonl|report.json>  Compare against baseline session JSONL or saved JSON report",
	"  --baseline-artifacts-dir <dir>  Explicit artifact directory when --baseline is a JSONL file",
	"  --handoff-invariants <json>     Required handoff invariants as a JSON array of",
	'                                  {"name": string, "pattern": string} objects (patterns are literal',
	"                                  substrings). Shared by candidate and baseline so axis (e) has",
	"                                  checked coverage on both sides.",
	"  --handoff-provenance <kind>     Downgrade handoff provenance: fixture | unverified. Omitted =",
	"                                  infer live_model only when a saved handoff-*.md exactly matches",
	"                                  its journal compaction summary. A flag cannot assert live_model.",
	"  --max-artifact-bytes <bytes>    Per-call capture log byte threshold (default: 4194304 = 4 MiB)",
	"  --max-line-bytes <bytes>        Per-line JSONL streaming guard (default: 16777216 = 16 MiB)",
	"  --require-pass                  Exit with code 1 unless --baseline comparison passes all 5 axes",
	"                                  (requires --baseline)",
	"  --json                          Print machine-readable JSON output",
	"  -h, --help                      Show this help",
].join("\n");

/** The CLI can only downgrade provenance; `live_model` must be inferred from matched documents. */
const CLI_HANDOFF_PROVENANCE_DOWNGRADES: readonly HandoffProvenance[] = ["fixture", "unverified"];

interface CliOptions {
	sessionFile: string;
	artifactsDir?: string;
	baselinePath?: string;
	baselineArtifactsDir?: string;
	handoffInvariants?: HandoffRequiredInvariant[];
	handoffProvenance?: HandoffProvenance;
	maxArtifactBytes?: number;
	maxLineBytes?: number;
	requirePass: boolean;
	json: boolean;
}

function parsePositiveInt(flag: string, raw: string | undefined): number | undefined {
	if (raw === undefined) return undefined;
	const trimmed = raw.trim();
	const value = Number(trimmed);
	if (!/^[1-9]\d*$/.test(trimmed) || !Number.isSafeInteger(value) || value <= 0) {
		throw new Error(`Invalid ${flag}: "${raw}" (expected positive integer bytes)`);
	}
	return value;
}

function parseHandoffInvariants(raw: string | undefined): HandoffRequiredInvariant[] | undefined {
	if (raw === undefined) return undefined;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		throw new Error(
			`Invalid --handoff-invariants: not valid JSON (${error instanceof Error ? error.message : String(error)})`,
		);
	}
	if (!Array.isArray(parsed) || parsed.length === 0) {
		throw new Error(
			'Invalid --handoff-invariants: expected a non-empty JSON array of {"name": string, "pattern": string} objects',
		);
	}
	return parsed.map((item: unknown, index: number) => {
		const record = typeof item === "object" && item !== null ? (item as Record<string, unknown>) : undefined;
		const name = record?.name;
		const pattern = record?.pattern;
		if (typeof name !== "string" || name.trim().length === 0) {
			throw new Error(`Invalid --handoff-invariants[${index}]: "name" must be a non-empty string`);
		}
		if (typeof pattern !== "string" || pattern.length === 0) {
			throw new Error(
				`Invalid --handoff-invariants[${index}]: "pattern" must be a non-empty literal substring string`,
			);
		}
		return { name, pattern };
	});
}

function parseHandoffProvenance(raw: string | undefined): HandoffProvenance | undefined {
	if (raw === undefined) return undefined;
	if (!CLI_HANDOFF_PROVENANCE_DOWNGRADES.includes(raw as HandoffProvenance)) {
		throw new Error(
			`Invalid --handoff-provenance: "${raw}". The flag can only downgrade to ${CLI_HANDOFF_PROVENANCE_DOWNGRADES.join(" | ")}; live_model origin is inferred only from a saved handoff-*.md that exactly matches its journal compaction summary, never asserted by a flag.`,
		);
	}
	return raw as HandoffProvenance;
}

function parseCli(argv: string[]): CliOptions | null {
	const parsed = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			"artifacts-dir": { type: "string" },
			baseline: { type: "string" },
			"baseline-artifacts-dir": { type: "string" },
			"handoff-invariants": { type: "string" },
			"handoff-provenance": { type: "string" },
			"max-artifact-bytes": { type: "string" },
			"max-line-bytes": { type: "string" },
			"require-pass": { type: "boolean" },
			json: { type: "boolean" },
			help: { type: "boolean", short: "h" },
		},
	});
	if (parsed.values.help === true) {
		console.log(USAGE);
		return null;
	}
	const sessionFile = parsed.positionals[0];
	if (!sessionFile) {
		throw new Error(`Missing <session.jsonl> path.\n\n${USAGE}`);
	}
	if (parsed.positionals.length > 1) {
		throw new Error(`Unexpected extra argument(s): ${parsed.positionals.slice(1).join(" ")}\n\n${USAGE}`);
	}
	const baselinePath = parsed.values.baseline;
	const requirePass = parsed.values["require-pass"] === true;
	if (requirePass && !baselinePath) {
		throw new Error(`--require-pass requires --baseline; there is no comparison to pass without one.\n\n${USAGE}`);
	}
	if (parsed.values["baseline-artifacts-dir"] !== undefined && !baselinePath) {
		throw new Error(`--baseline-artifacts-dir requires --baseline.\n\n${USAGE}`);
	}
	return {
		sessionFile,
		artifactsDir: parsed.values["artifacts-dir"],
		baselinePath,
		baselineArtifactsDir: parsed.values["baseline-artifacts-dir"],
		handoffInvariants: parseHandoffInvariants(parsed.values["handoff-invariants"]),
		handoffProvenance: parseHandoffProvenance(parsed.values["handoff-provenance"]),
		maxArtifactBytes: parsePositiveInt("--max-artifact-bytes", parsed.values["max-artifact-bytes"]),
		maxLineBytes: parsePositiveInt("--max-line-bytes", parsed.values["max-line-bytes"]),
		requirePass,
		json: parsed.values.json === true,
	};
}

async function loadBaselineReport(
	baselinePath: string,
	baselineArtifactsDir: string | undefined,
	maxLineBytes: number | undefined,
	handoffInvariants: readonly HandoffRequiredInvariant[] | undefined,
	handoffProvenance: HandoffProvenance | undefined,
): Promise<SessionOutputMetricsReport> {
	const resolved = path.resolve(baselinePath);
	if (resolved.endsWith(".json")) {
		if (baselineArtifactsDir !== undefined) {
			throw new Error(
				"--baseline-artifacts-dir only applies to a baseline JSONL session; a saved JSON report already carries its artifact scan",
			);
		}
		// A saved report keeps the provenance and invariant results it was computed
		// with; CLI flags cannot retroactively re-evaluate it.
		if (handoffInvariants !== undefined || handoffProvenance !== undefined) {
			console.error(
				"Warning: --handoff-invariants/--handoff-provenance cannot re-evaluate a saved JSON report; pass the baseline JSONL session to apply them.",
			);
		}
		const raw: unknown = JSON.parse(await fs.readFile(resolved, "utf8"));
		return parseSessionOutputMetricsReport(raw);
	}
	return await computeSessionOutputMetrics(resolved, {
		artifactsDir: baselineArtifactsDir,
		maxLineBytes,
		handoffInvariants,
		handoffProvenance,
	});
}

function formatHumanSummary(report: SessionOutputMetricsReport, comparison?: SessionOutputComparisonReport): string {
	const lines: string[] = [
		`Session: ${report.sessionFile ?? "(in-memory)"}`,
		`Session ID: ${report.sessionId ?? "null"} | Runtime: ${report.runtimeVersion ?? "null"} | Lines: ${report.physicalLines} (malformed=${report.malformedRecords}, oversizedSkipped=${report.oversizedLinesSkipped})`,
		`Window: ${report.window.startTimestamp ?? "null"} -> ${report.window.endTimestamp ?? "null"} (exit=${report.window.exitReason ?? "null"})`,
		`Compactions: ${report.compaction.count} | methods=${JSON.stringify(report.compaction.methods)} | warnings=${report.compaction.warningCount}`,
		`  tokensBefore: ${report.compaction.tokensBefore ? `avg=${Math.round(report.compaction.tokensBefore.avg)} min=${report.compaction.tokensBefore.min} max=${report.compaction.tokensBefore.max} total=${report.compaction.tokensBefore.total}` : "null"}`,
		`  tokensAfter:  ${report.compaction.tokensAfter ? `avg=${Math.round(report.compaction.tokensAfter.avg)} min=${report.compaction.tokensAfter.min} max=${report.compaction.tokensAfter.max}` : "null"}`,
		`  intervalMinutes: betweenAvg=${report.compaction.intervalsMs.betweenCompactionsAvgMinutes?.toFixed(2) ?? "null"} toFirst=${report.compaction.intervalsMs.timeToFirstCompactionMinutes?.toFixed(2) ?? "null"} throughput(duration/count)=${report.compaction.intervalsMs.throughputDurationPerCompactionMinutes?.toFixed(2) ?? "null"}`,
		`ToolResults: total=${report.toolResults.total} isError=${report.toolResults.errorCount} shakenRows=${report.toolResults.shakenToolResultCount} (${report.toolResults.shakenToolResultRatio !== null ? `${(report.toolResults.shakenToolResultRatio * 100).toFixed(1)}%` : "null"}) shakenRegions=${report.toolResults.shakenRegions.totalRegionsInTranscript} (toolResult=${report.toolResults.shakenRegions.toolResultRegions}, block=${report.toolResults.shakenRegions.messageBlockRegions})`,
		`Artifacts: captureLogs=${report.artifacts.captureLogCount} totalBytes=${report.artifacts.totalCaptureLogBytes} maxLog=${report.artifacts.maxCaptureLog ? `${report.artifacts.maxCaptureLog.fileName} (${report.artifacts.maxCaptureLog.bytes} B, truncated=${report.artifacts.maxCaptureLog.truncatedOnDisk})` : "null"} handoffFiles=${report.artifacts.handoffFileCount}`,
		`Handoff: provenance=${report.artifacts.handoffQuality?.provenance ?? "null"} evaluated=${report.artifacts.handoffQuality?.evaluatedCount ?? 0} structural=${report.artifacts.handoffQuality ? `${report.artifacts.handoffQuality.structuralCompleteCount}/${report.artifacts.handoffQuality.evaluatedCount}` : "null"} invariants=${report.artifacts.handoffQuality?.invariantMatchedCount ?? "unmeasured"}`,
		`Observational Indicators (approximate, non-causal): postCompactionReads=${report.reconstructionIndicators.postCompactionReadCount} evalMissingNameErrors=${report.reconstructionIndicators.evalStateErrors.total} editAnchorRejects=${report.reconstructionIndicators.editRejections.anchorRejectCount} editHashRejects=${report.reconstructionIndicators.editRejections.hashRejectCount} prereqBlocks=${report.reconstructionIndicators.prerequisiteBlocks.total} (gated=${report.reconstructionIndicators.prerequisiteBlocks.gateBlockedCount})`,
	];
	if (comparison) {
		lines.push(
			`Comparison Passed: ${comparison.passed} (compactionDropAloneGuard=${comparison.compactionDropAloneGuardTriggered})`,
		);
		for (const [axis, outcome] of Object.entries(comparison.axes)) {
			lines.push(`  [${outcome.status.toUpperCase()}] ${axis}: ${outcome.reason}`);
		}
	}
	return lines.join("\n");
}

async function main(): Promise<void> {
	const cli = parseCli(Bun.argv.slice(2));
	if (!cli) return;

	await loadRuntimeIdentity();
	const metrics = await computeSessionOutputMetrics(cli.sessionFile, {
		artifactsDir: cli.artifactsDir,
		maxLineBytes: cli.maxLineBytes,
		handoffInvariants: cli.handoffInvariants,
		handoffProvenance: cli.handoffProvenance,
	});

	let comparison: SessionOutputComparisonReport | undefined;
	let baseline: SessionOutputMetricsReport | undefined;
	if (cli.baselinePath) {
		baseline = await loadBaselineReport(
			cli.baselinePath,
			cli.baselineArtifactsDir,
			cli.maxLineBytes,
			cli.handoffInvariants,
			cli.handoffProvenance,
		);
		comparison = compareSessionOutputMetrics(metrics, baseline, {
			maxSingleCaptureLogBytes: cli.maxArtifactBytes,
		});
	}

	if (cli.json) {
		const payload = comparison ? { metrics, baseline, comparison } : metrics;
		console.log(JSON.stringify(payload, null, 2));
	} else {
		console.log(formatHumanSummary(metrics, comparison));
	}

	// Defense in depth: parseCli already rejects `--require-pass` without a baseline, and the
	// gate must never exit 0 on a report that was not compared.
	if (cli.requirePass && !comparison?.passed) {
		process.exitCode = 1;
	}
}

if (import.meta.main) {
	main().catch(error => {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	});
}
