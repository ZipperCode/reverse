#!/usr/bin/env bun
/**
 * One-command local session output, artifact budget, and compaction metrics CLI (#20).
 *
 * Usage:
 *   bun scripts/session-output-metrics.ts <session.jsonl> --json
 *   bun scripts/session-output-metrics.ts <session.jsonl> --baseline <baseline.jsonl|report.json> --json
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { parseArgs } from "node:util";
import {
	compareSessionOutputMetrics,
	computeSessionOutputMetrics,
	parseSessionOutputMetricsReport,
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
	"  --max-artifact-bytes <bytes>    Per-call capture log byte threshold (default: 4194304 = 4 MiB)",
	"  --max-line-bytes <bytes>        Per-line JSONL streaming guard (default: 16777216 = 16 MiB)",
	"  --require-pass                  Exit with code 1 when --baseline comparison does not pass all 5 axes",
	"  --json                          Print machine-readable JSON output",
	"  -h, --help                      Show this help",
].join("\n");

interface CliOptions {
	sessionFile: string;
	artifactsDir?: string;
	baselinePath?: string;
	baselineArtifactsDir?: string;
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

function parseCli(argv: string[]): CliOptions | null {
	const parsed = parseArgs({
		args: argv,
		allowPositionals: true,
		options: {
			"artifacts-dir": { type: "string" },
			baseline: { type: "string" },
			"baseline-artifacts-dir": { type: "string" },
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
	return {
		sessionFile,
		artifactsDir: parsed.values["artifacts-dir"],
		baselinePath: parsed.values.baseline,
		baselineArtifactsDir: parsed.values["baseline-artifacts-dir"],
		maxArtifactBytes: parsePositiveInt("--max-artifact-bytes", parsed.values["max-artifact-bytes"]),
		maxLineBytes: parsePositiveInt("--max-line-bytes", parsed.values["max-line-bytes"]),
		requirePass: parsed.values["require-pass"] === true,
		json: parsed.values.json === true,
	};
}

async function loadBaselineReport(
	baselinePath: string,
	baselineArtifactsDir: string | undefined,
	maxLineBytes: number | undefined,
): Promise<SessionOutputMetricsReport> {
	const resolved = path.resolve(baselinePath);
	if (resolved.endsWith(".json")) {
		const raw: unknown = JSON.parse(await fs.readFile(resolved, "utf8"));
		return parseSessionOutputMetricsReport(raw);
	}
	return await computeSessionOutputMetrics(resolved, {
		artifactsDir: baselineArtifactsDir,
		maxLineBytes,
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
	});

	let comparison: SessionOutputComparisonReport | undefined;
	let baseline: SessionOutputMetricsReport | undefined;
	if (cli.baselinePath) {
		baseline = await loadBaselineReport(cli.baselinePath, cli.baselineArtifactsDir, cli.maxLineBytes);
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

	if (cli.requirePass && comparison && !comparison.passed) {
		process.exitCode = 1;
	}
}

if (import.meta.main) {
	main().catch(error => {
		console.error(error instanceof Error ? error.message : String(error));
		process.exitCode = 1;
	});
}
