import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { OutputSink } from "@reverse/tui/tools/streaming-output";
import {
	compareSessionOutputMetrics,
	computeSessionOutputMetrics,
	evaluateHandoffDocumentQuality,
	parseSessionOutputMetricsReport,
} from "../../src/session/output-metrics";
import { serializeTitleSlot } from "../../src/session/session-title-slot";

const tempDirs: string[] = [];

async function makeTempSessionDir(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-output-metrics-test-"));
	tempDirs.push(dir);
	return dir;
}

afterEach(async () => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop()!;
		await fs.rm(dir, { recursive: true, force: true });
	}
});

const LIVE_HANDOFF_DOCUMENT = [
	"## Goal",
	"Verify that compaction output stays within artifact and handoff budgets.",
	"## Constraints & Preferences",
	"- Deterministic analysis; no network access during replay.",
	"- Keep the anchor `ANCHOR_SHA = abcdef` unchanged across runs.",
	"## Progress",
	"### Done",
	"- [x] Captured the baseline session and artifact directories.",
	"- [x] Re-ran the candidate workload with the new budget settings.",
	"## Key Decisions",
	"- Keep per-call capture logs under the configured 4 MiB budget.",
	"## Critical Context",
	"- `ANCHOR_SHA = abcdef` identifies the retained capture log region.",
	"## Next Steps",
	"1. Re-run the replay and compare all five acceptance axes.",
].join("\n");

/** Committed compaction summary of a live handoff: the document plus the appended file-operations tag. */
const LIVE_HANDOFF_SUMMARY = `${LIVE_HANDOFF_DOCUMENT}\n\n<modified-files>\n- packages/a.ts (Write)\n</modified-files>`;

function buildHandoffSessionEntries(options: {
	id: string;
	compactions: number;
	shaken: boolean;
	summary?: string;
}): unknown[] {
	const entries: unknown[] = [
		{ type: "session", version: 3, id: options.id, timestamp: "2026-10-25T00:00:00.000Z", cwd: "/workspace" },
	];
	for (let index = 0; index < options.compactions; index++) {
		entries.push({
			type: "compaction",
			id: `c${index + 1}`,
			parentId: index === 0 ? null : `c${index}`,
			timestamp: `2026-10-25T00:${String(15 * (index + 1)).padStart(2, "0")}:00.000Z`,
			method: "handoff",
			firstKeptEntryId: `c${index + 1}`,
			tokensBefore: 120_000,
			tokensAfter: 50_000,
			summary: options.summary ?? LIVE_HANDOFF_SUMMARY,
		});
	}
	entries.push({
		type: "message",
		id: "m1",
		parentId: `c${options.compactions}`,
		timestamp: "2026-10-25T00:46:00.000Z",
		message: {
			role: "toolResult",
			toolCallId: "t1",
			toolName: "bash",
			isError: false,
			content: [
				{
					type: "text",
					text: options.shaken
						? "[shaken ~500 tokens — recover: artifact://1 (region 1)]"
						: "bounded inline output",
				},
			],
			timestamp: 1,
		},
	});
	return entries;
}

async function writeLiveHandoffSession(options: {
	file: string;
	artifactsDir: string;
	compactions: number;
	captureBytes: number;
	shaken: boolean;
}): Promise<void> {
	const entries = buildHandoffSessionEntries({
		id: path.basename(options.file, ".jsonl"),
		compactions: options.compactions,
		shaken: options.shaken,
	});
	await fs.writeFile(options.file, `${entries.map(entry => JSON.stringify(entry)).join("\n")}\n`, "utf8");
	await fs.writeFile(
		path.join(options.artifactsDir, "handoff-2026-10-25T00-15-00-000Z.md"),
		LIVE_HANDOFF_DOCUMENT,
		"utf8",
	);
	if (options.captureBytes > 0) {
		await fs.writeFile(path.join(options.artifactsDir, "1.bash.log"), "A".repeat(options.captureBytes), "utf8");
	}
}

describe("session output and compaction metrics (#20)", () => {
	it("computes compaction distributions, shaken regions vs rows, artifact caps, and skips oversized lines in streaming pass", async () => {
		const root = await makeTempSessionDir();
		const sessionId = "01a17344-4e83-7000-b528-ef5485adcf89";
		const sessionFile = path.join(root, `${sessionId}.jsonl`);
		const artifactsDir = path.join(root, sessionId);
		await fs.mkdir(artifactsDir, { recursive: true });

		const titleSlot = serializeTitleSlot({
			title: "Android reverse session",
			source: "auto",
			updatedAt: "2026-10-25T13:33:38.820Z",
		});

		const lines = [
			titleSlot.slice(0, -1),
			JSON.stringify({
				type: "session",
				version: 3,
				id: sessionId,
				timestamp: "2026-10-25T13:33:38.820Z",
				cwd: "/workspace/map",
				runtime: { version: "18.11.2", commit: "58965311a4" },
			}),
			// Oversized line exceeding the test's 8 KiB per-line guard; must be skipped without breaking subsequent lines.
			JSON.stringify({
				type: "custom",
				id: "oversized-1",
				parentId: null,
				timestamp: "2026-10-25T13:34:00.000Z",
				customType: "noise",
				data: { payload: "X".repeat(12_000) },
			}),
			JSON.stringify({
				type: "custom",
				id: "start-1",
				parentId: null,
				timestamp: "2026-10-25T13:40:00.000Z",
				customType: "tool_execution_start",
				data: {
					toolCallId: "call-bash-1",
					toolName: "bash",
					args: { command: "adb logcat -d" },
					startedAt: "2026-10-25T13:40:00.000Z",
				},
			}),
			JSON.stringify({
				type: "message",
				id: "msg-tr-1",
				parentId: "start-1",
				timestamp: "2026-10-25T13:41:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "call-bash-1",
					toolName: "bash",
					isError: false,
					content: [
						{
							type: "text",
							text: "[shaken ~1420 tokens — recover: artifact://3 (region 1)]",
						},
					],
					details: {
						meta: {
							truncation: {
								direction: "middle",
								truncatedBy: "middle",
								totalLines: 90_000,
								totalBytes: 6_291_456,
								outputLines: 240,
								outputBytes: 12_288,
								elidedBytes: 6_279_168,
								artifactId: "1",
								artifactBytes: 4_194_304,
								artifactElidedBytes: 2_097_152,
							},
						},
					},
					timestamp: 1761402060000,
				},
			}),
			// Assistant message containing two shaken fenced-code regions inside a single message entry.
			JSON.stringify({
				type: "message",
				id: "msg-asst-1",
				parentId: "msg-tr-1",
				timestamp: "2026-10-25T13:45:00.000Z",
				message: {
					role: "assistant",
					content: [
						{
							type: "text",
							text: [
								"Analysis block A:",
								"[shaken ~600 tokens — recover: artifact://3 (region 2)]",
								"Analysis block B:",
								"[shaken ~800 tokens — recover: artifact://3 (region 3)]",
							].join("\n"),
						},
					],
					timestamp: 1761402300000,
				},
			}),
			JSON.stringify({
				type: "compaction",
				id: "comp-1",
				parentId: "msg-asst-1",
				timestamp: "2026-10-25T13:50:00.000Z",
				method: "handoff",
				firstKeptEntryId: "msg-asst-1",
				tokensBefore: 110_000,
				tokensAfter: 40_000,
				summary: "## Goal\nDecode VM\n",
			}),
			JSON.stringify({
				type: "compaction",
				id: "comp-2",
				parentId: "comp-1",
				timestamp: "2026-10-25T14:10:00.000Z",
				method: "handoff",
				firstKeptEntryId: "comp-1",
				tokensBefore: 130_000,
				tokensAfter: 50_000,
				warning: "Compaction freed limited headroom",
				summary: "## Goal\nDecode VM\n",
			}),
			JSON.stringify({
				type: "custom",
				id: "start-read-1",
				parentId: "comp-2",
				timestamp: "2026-10-25T14:11:00.000Z",
				customType: "tool_execution_start",
				data: {
					toolCallId: "call-read-1",
					toolName: "read",
					args: { path: "artifact://1:1-50" },
					startedAt: "2026-10-25T14:11:00.000Z",
				},
			}),
			JSON.stringify({
				type: "message",
				id: "msg-tr-2",
				parentId: "start-read-1",
				timestamp: "2026-10-25T14:11:02.000Z",
				message: {
					role: "toolResult",
					toolCallId: "call-read-1",
					toolName: "read",
					isError: false,
					content: [{ type: "text", text: "line 1..50" }],
					timestamp: 1761403862000,
				},
			}),
			JSON.stringify({
				type: "custom",
				id: "exit-1",
				parentId: "msg-tr-2",
				timestamp: "2026-10-25T14:33:38.820Z",
				customType: "session_exit",
				data: {
					reason: "dispose",
					kind: "normal",
					recordedAt: "2026-10-25T14:33:38.820Z",
				},
			}),
		];

		await fs.writeFile(sessionFile, `${lines.join("\n")}\n`, "utf8");

		// Write capture log with OutputSink truncation marker, a shake artifact, and a handoff markdown file.
		const bashLogBody = [
			"HEAD_RECORD_0001",
			"[ARTIFACT TRUNCATED: kept first 1 MB + last 3 MB of 6,291,456; 2,097,152 elided from the middle]",
			"TAIL_RECORD_9999",
		].join("\n");
		await fs.writeFile(path.join(artifactsDir, "1.bash.log"), bashLogBody, "utf8");
		await fs.writeFile(path.join(artifactsDir, "2.eval.log"), "plain eval output\n", "utf8");
		await fs.writeFile(
			path.join(artifactsDir, "3.shake.log"),
			[
				"### region 1 (bash, ~1420 tok)",
				"",
				"raw bash output",
				"",
				"### region 2 (assistant, ~600 tok)",
				"",
				"block A",
				"",
				"### region 3 (assistant, ~800 tok)",
				"",
				"block B",
				"",
			].join("\n"),
			"utf8",
		);
		await fs.writeFile(
			path.join(artifactsDir, "handoff-2026-10-25T13-50-00-000Z.md"),
			[
				"## Goal",
				"Verify VM opcode table.",
				"## Constraints & Preferences",
				"- Preserve native bindings.",
				"## Progress",
				"### Done",
				"- [x] Extracted table.",
				"## Key Decisions",
				"- **Use OutputSink**: Bounded logs.",
				"## Critical Context",
				"- `VM_TABLE_SHA256 = 9f86d081`",
				"## Next Steps",
				"1. Inspect handler 0.",
			].join("\n"),
			"utf8",
		);

		const report = await computeSessionOutputMetrics(sessionFile, {
			maxLineBytes: 8_192,
			handoffInvariants: [{ name: "vm_table_sha", pattern: "VM_TABLE_SHA256 = 9f86d081" }],
		});

		expect(report.sessionId).toBe(sessionId);
		expect(report.runtimeVersion).toBe("18.11.2");
		expect(report.oversizedLinesSkipped).toBe(1);
		expect(report.malformedRecords).toBe(0);
		expect(report.window.durationMs).toBe(3_600_000);
		expect(report.window.exitReason).toBe("dispose");

		expect(report.compaction.count).toBe(2);
		expect(report.compaction.methods).toEqual({ handoff: 2 });
		expect(report.compaction.warningCount).toBe(1);
		expect(report.compaction.tokensBefore?.min).toBe(110_000);
		expect(report.compaction.tokensBefore?.max).toBe(130_000);
		expect(report.compaction.tokensBefore?.avg).toBe(120_000);
		expect(report.compaction.tokensBefore?.total).toBe(240_000);
		expect(report.compaction.tokensAfter?.avg).toBe(45_000);
		expect(report.compaction.totalTokensCompacted).toBe(150_000);
		expect(report.compaction.intervalsMs.betweenCompactions?.avg).toBe(20 * 60_000);
		expect(report.compaction.intervalsMs.betweenCompactionsAvgMinutes).toBe(20);
		expect(report.compaction.intervalsMs.throughputDurationPerCompactionMinutes).toBe(30);

		// Distinguish shaken toolResult rows (1 of 2 = 0.5) from total shaken regions (1 toolResult + 2 assistant block = 3).
		expect(report.toolResults.total).toBe(2);
		expect(report.toolResults.shakenToolResultCount).toBe(1);
		expect(report.toolResults.shakenToolResultRatio).toBe(0.5);
		expect(report.toolResults.shakenRegions.totalRegionsInTranscript).toBe(3);
		expect(report.toolResults.shakenRegions.toolResultRegions).toBe(1);
		expect(report.toolResults.shakenRegions.messageBlockRegions).toBe(2);
		expect(report.toolResults.shakenRegions.estimatedTokensElided).toBe(2_820);
		expect(report.toolResults.shakenRegions.maxRegionNumberByArtifact).toEqual({ "3": 3 });

		// Capture logs exclude `3.shake.log` and `handoff-*.md`.
		expect(report.artifacts.captureLogCount).toBe(2);
		expect(report.artifacts.truncatedCaptureLogCount).toBe(1);
		expect(report.artifacts.totalCaptureLogElidedBytes).toBe(2_097_152);
		expect(report.artifacts.maxCaptureLog?.fileName).toBe("1.bash.log");
		expect(report.artifacts.maxCaptureLog?.truncatedOnDisk).toBe(true);
		expect(report.artifacts.maxCaptureLog?.elidedBytes).toBe(2_097_152);
		expect(report.artifacts.shakeArtifactCount).toBe(1);
		expect(report.artifacts.shakeArtifactRegionsTotal).toBe(3);
		expect(report.artifacts.handoffFileCount).toBe(1);
		expect(report.artifacts.handoffQuality?.structuralCompleteCount).toBe(1);
		expect(report.artifacts.handoffQuality?.invariantMatchedCount).toBe(1);

		expect(report.reconstructionIndicators.postCompactionReadCount).toBe(1);
		expect(report.reconstructionIndicators.postCompactionArtifactReadCount).toBe(1);
	});

	it("classifies structured and historical edit rejections, eval missing names, and prerequisite gate blocks without double counting", async () => {
		const root = await makeTempSessionDir();
		const sessionFile = path.join(root, "indicators.jsonl");

		const entries = [
			{
				type: "session",
				version: 3,
				id: "ind-1",
				timestamp: "2026-10-26T00:00:00.000Z",
				cwd: "/workspace",
			},
			{
				type: "compaction",
				id: "c-1",
				parentId: null,
				timestamp: "2026-10-26T00:05:00.000Z",
				method: "handoff",
				firstKeptEntryId: "c-1",
				tokensBefore: 100_000,
				tokensAfter: 40_000,
				summary: "## Goal\nTest",
			},
			// 1. Direct edit with structured unseen_lines errorKind + multi-file details (must count as 1 anchor_reject).
			{
				type: "message",
				id: "m-edit-1",
				parentId: "c-1",
				timestamp: "2026-10-26T00:06:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "e-1",
					toolName: "edit",
					isError: true,
					content: [{ type: "text", text: "This edit anchors to lines 12 never displayed" }],
					details: {
						diff: "",
						errorKind: "unseen_lines",
						files: [
							{ path: "a.ts", errorKind: "unseen_lines" },
							{ path: "b.ts", errorKind: "unseen_lines" },
						],
					},
					timestamp: 1,
				},
			},
			// 2. xd://edit via write with structured other_file_tag errorKind (must count as 1 hash_reject).
			{
				type: "message",
				id: "m-edit-2",
				parentId: "m-edit-1",
				timestamp: "2026-10-26T00:07:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "e-2",
					toolName: "write",
					isError: true,
					content: [{ type: "text", text: "Edit rejected: hash #272E belongs to another file" }],
					details: {
						xdev: {
							tool: "edit",
							mode: "execute",
							inner: { diff: "", errorKind: "other_file_tag" },
						},
					},
					timestamp: 2,
				},
			},
			// 3. Historical edit error without details.errorKind (inferred from text).
			{
				type: "message",
				id: "m-edit-3",
				parentId: "m-edit-2",
				timestamp: "2026-10-26T00:08:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "e-3",
					toolName: "edit",
					isError: true,
					content: [
						{
							type: "text",
							text: "Edit rejected for foo.js: hash #272E is not from this session.\nHash #272E was issued in this session for bar.js.",
						},
					],
					timestamp: 3,
				},
			},
			// 4. Structured eval missingNames + historical traceback NameError.
			{
				type: "message",
				id: "m-eval-1",
				parentId: "m-edit-3",
				timestamp: "2026-10-26T00:09:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "ev-1",
					toolName: "eval",
					isError: true,
					content: [{ type: "text", text: "NameError: name 'libc_path' is not defined" }],
					details: {
						missingNames: ["libc_path"],
					},
					timestamp: 4,
				},
			},
			{
				type: "message",
				id: "m-eval-2",
				parentId: "m-eval-1",
				timestamp: "2026-10-26T00:10:00.000Z",
				message: {
					role: "toolResult",
					toolCallId: "ev-2",
					toolName: "eval",
					isError: true,
					content: [{ type: "text", text: "Traceback...\nNameError: name 'handlers' is not defined" }],
					timestamp: 5,
				},
			},
			// 5. Prerequisite gate: 2 tool_execution_start dispatches for elf_inspect, 1 probe failure + 1 gate block.
			{
				type: "custom",
				id: "s-elf-1",
				parentId: "m-eval-2",
				timestamp: "2026-10-26T00:11:00.000Z",
				customType: "tool_execution_start",
				data: {
					toolCallId: "elf-1",
					toolName: "write",
					args: { path: "xd://elf_inspect" },
					startedAt: "2026-10-26T00:11:00.000Z",
				},
			},
			{
				type: "message",
				id: "m-elf-1",
				parentId: "s-elf-1",
				timestamp: "2026-10-26T00:11:01.000Z",
				message: {
					role: "toolResult",
					toolCallId: "elf-1",
					toolName: "write",
					isError: true,
					content: [{ type: "text", text: "LIEF not available" }],
					details: {
						xdev: {
							tool: "elf_inspect",
							mode: "execute",
							inner: {
								status: "blocked_prerequisite",
								deterministicFailure: true,
								blockedByGate: false,
								prerequisiteBlock: {
									deterministicFailure: true,
									toolName: "elf_inspect",
									blockedByGate: false,
								},
							},
						},
					},
					timestamp: 6,
				},
			},
			{
				type: "custom",
				id: "s-elf-2",
				parentId: "m-elf-1",
				timestamp: "2026-10-26T00:11:05.000Z",
				customType: "tool_execution_start",
				data: {
					toolCallId: "elf-2",
					toolName: "write",
					args: { path: "xd://elf_inspect" },
					startedAt: "2026-10-26T00:11:05.000Z",
				},
			},
			{
				type: "message",
				id: "m-elf-2",
				parentId: "s-elf-2",
				timestamp: "2026-10-26T00:11:05.010Z",
				message: {
					role: "toolResult",
					toolCallId: "elf-2",
					toolName: "write",
					isError: true,
					content: [{ type: "text", text: "Blocked by prerequisite gate" }],
					details: {
						xdev: {
							tool: "elf_inspect",
							mode: "execute",
							inner: {
								status: "blocked_prerequisite",
								deterministicFailure: true,
								blockedByGate: true,
								prerequisiteBlock: {
									deterministicFailure: true,
									toolName: "elf_inspect",
									blockedByGate: true,
								},
							},
						},
					},
					timestamp: 7,
				},
			},
		];

		await fs.writeFile(sessionFile, `${entries.map(e => JSON.stringify(e)).join("\n")}\n`, "utf8");
		const report = await computeSessionOutputMetrics(sessionFile);

		const editInd = report.reconstructionIndicators.editRejections;
		expect(editInd.totalErrorCount).toBe(3);
		expect(editInd.anchorRejectCount).toBe(1);
		expect(editInd.hashRejectCount).toBe(2);
		expect(editInd.structuredCount).toBe(2);
		expect(editInd.historicalTextInferredCount).toBe(1);
		expect(editInd.byErrorKind).toEqual({
			unseen_lines: 1,
			other_file_tag: 2,
		});
		expect(editInd.postCompactionAnchorOrHashCount).toBe(3);

		const evalInd = report.reconstructionIndicators.evalStateErrors;
		expect(evalInd.total).toBe(2);
		expect(evalInd.structuredMissingNameCount).toBe(1);
		expect(evalInd.historicalTracebackInferredCount).toBe(1);
		expect(evalInd.postCompactionCount).toBe(2);
		expect(evalInd.missingNames).toEqual(["handlers", "libc_path"]);

		const prereq = report.reconstructionIndicators.prerequisiteBlocks;
		expect(prereq.total).toBe(2);
		expect(prereq.backendProbeFailureCount).toBe(1);
		expect(prereq.gateBlockedCount).toBe(1);
		expect(report.toolCalls.executionStartByTool.elf_inspect).toBe(2);
		expect(report.toolCalls.backendRunEstimateByTool.elf_inspect).toBe(1);
	});

	it("enforces all five comparison axes and blocks passing on compaction count reduction alone", async () => {
		const root = await makeTempSessionDir();
		const baseFile = path.join(root, "base.jsonl");
		const candFile = path.join(root, "cand.jsonl");
		const candDir = path.join(root, "cand");
		await fs.mkdir(candDir, { recursive: true });

		const completeHandoff = [
			"## Goal",
			"Analyze sample",
			"## Constraints & Preferences",
			"- Deterministic",
			"## Progress",
			"### Done",
			"- [x] Step 1",
			"## Key Decisions",
			"- Keep caps",
			"## Critical Context",
			"- `ANCHOR_SHA = abcdef`",
			"## Next Steps",
			"1. Finish",
		].join("\n");

		await fs.writeFile(
			baseFile,
			[
				JSON.stringify({ type: "session", version: 3, id: "b", timestamp: "2026-10-25T00:00:00.000Z", cwd: "/" }),
				JSON.stringify({
					type: "compaction",
					id: "c1",
					parentId: null,
					timestamp: "2026-10-25T00:15:00.000Z",
					method: "handoff",
					firstKeptEntryId: "c1",
					tokensBefore: 120_000,
					tokensAfter: 50_000,
					summary: completeHandoff,
				}),
				JSON.stringify({
					type: "compaction",
					id: "c2",
					parentId: "c1",
					timestamp: "2026-10-25T00:30:00.000Z",
					method: "handoff",
					firstKeptEntryId: "c2",
					tokensBefore: 120_000,
					tokensAfter: 50_000,
					summary: completeHandoff,
				}),
				JSON.stringify({
					type: "message",
					id: "m1",
					parentId: "c2",
					timestamp: "2026-10-25T00:31:00.000Z",
					message: {
						role: "toolResult",
						toolCallId: "t1",
						toolName: "bash",
						isError: false,
						content: [{ type: "text", text: "[shaken ~500 tokens — recover: artifact://1 (region 1)]" }],
						timestamp: 1,
					},
				}),
			].join("\n"),
			"utf8",
		);

		await fs.writeFile(
			candFile,
			[
				JSON.stringify({ type: "session", version: 3, id: "c", timestamp: "2026-10-25T00:00:00.000Z", cwd: "/" }),
				JSON.stringify({
					type: "compaction",
					id: "c1",
					parentId: null,
					timestamp: "2026-10-25T00:45:00.000Z",
					method: "handoff",
					firstKeptEntryId: "c1",
					tokensBefore: 110_000,
					tokensAfter: 42_000,
					summary: completeHandoff,
				}),
				JSON.stringify({
					type: "message",
					id: "m1",
					parentId: "c1",
					timestamp: "2026-10-25T00:46:00.000Z",
					message: {
						role: "toolResult",
						toolCallId: "t1",
						toolName: "bash",
						isError: false,
						content: [{ type: "text", text: "bounded inline output" }],
						timestamp: 1,
					},
				}),
			].join("\n"),
			"utf8",
		);
		await fs.writeFile(path.join(candDir, "1.bash.log"), "A".repeat(1_024), "utf8");

		const invariants = [{ name: "anchor_sha", pattern: "ANCHOR_SHA = abcdef" }];
		const baseline = await computeSessionOutputMetrics(baseFile, { handoffInvariants: invariants });
		const candidate = await computeSessionOutputMetrics(candFile, { handoffInvariants: invariants });

		const passing = compareSessionOutputMetrics(candidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		// Journal compaction summaries have no corroborating saved handoff documents in this
		// fixture, so provenance stays `unverified` and axis (e) is unmeasured: only the four
		// deterministic axes pass and the overall gate must not.
		expect(passing.axes.compactionPace.status).toBe("pass");
		expect(passing.axes.singleArtifactCap.status).toBe("pass");
		expect(passing.axes.shakenRatio.status).toBe("pass");
		expect(passing.axes.postCompactionStateErrors.status).toBe("pass");
		expect(passing.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(passing.deterministicAxesPassed).toBe(true);
		expect(passing.passed).toBe(false);
		expect(passing.compactionDropAloneGuardTriggered).toBe(true);

		// When compaction count drops (2 -> 1) but single capture log exceeds budget, overall pass must be false
		// and compactionDropAloneGuardTriggered must be true.
		const failingOnCap = compareSessionOutputMetrics(candidate, baseline, {
			maxSingleCaptureLogBytes: 512,
		});
		expect(failingOnCap.axes.compactionPace.status).toBe("pass");
		expect(failingOnCap.axes.singleArtifactCap.status).toBe("fail");
		expect(failingOnCap.passed).toBe(false);
		expect(failingOnCap.compactionDropAloneGuardTriggered).toBe(true);

		// Fixture-provenance handoffs must report `unknown` for axis (e) and never fabricate `passed: true`.
		const fixtureCandidate = await computeSessionOutputMetrics(candFile, {
			handoffInvariants: invariants,
			handoffProvenance: "fixture",
		});
		const fixtureComparison = compareSessionOutputMetrics(fixtureCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(fixtureComparison.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(fixtureComparison.deterministicAxesPassed).toBe(true);
		expect(fixtureComparison.passed).toBe(false);

		// A `live_model` assertion is not proof: without a corroborating saved document the
		// report stays unverified and axis (e) remains unknown.
		const assertedCandidate = await computeSessionOutputMetrics(candFile, { handoffProvenance: "live_model" });
		expect(assertedCandidate.artifacts.handoffQuality?.provenance).toBe("unverified");
		const assertedComparison = compareSessionOutputMetrics(assertedCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(assertedComparison.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(assertedComparison.passed).toBe(false);

		// Validated schema round-trip succeeds on real report and rejects incomplete payloads.
		const parsedRoundTrip = parseSessionOutputMetricsReport(JSON.parse(JSON.stringify({ metrics: candidate })));
		expect(parsedRoundTrip.sessionId).toBe("c");
		expect(() =>
			parseSessionOutputMetricsReport({
				schemaVersion: 1,
				compaction: {},
				toolResults: {},
			}),
		).toThrow(/Invalid SessionOutputMetricsReport JSON/);

		const quality = evaluateHandoffDocumentQuality("## Goal\nOnly goal heading", invariants);
		expect(quality.structuralComplete).toBe(false);
		expect(quality.missingHeadings).toContain("## Next Steps");
		expect(quality.allInvariantsMatched).toBe(false);
	});

	it("recognizes streamed rounded and compact disk-loss markers without inventing exact loss bytes", async () => {
		const root = await makeTempSessionDir();
		const journal = path.join(root, "session.jsonl");
		const artifactsDir = path.join(root, "session");
		await fs.mkdir(artifactsDir);
		await fs.writeFile(journal, "");
		for (const [id, cap, head] of [
			[1, 512, 256],
			[2, 96, 24],
			[3, 24, 0],
		] as const) {
			const sink = new OutputSink({
				artifactPath: path.join(artifactsDir, `${id}.bash.log`),
				artifactId: String(id),
				spillThreshold: 16,
				artifactMaxBytes: cap,
				artifactHeadBytes: head,
			});
			try {
				sink.push("A".repeat(8192));
				const summary = await sink.dump();
				expect(summary.artifactElidedBytes).toBeGreaterThan(0);
			} finally {
				await sink.dispose();
			}
		}
		const report = await computeSessionOutputMetrics(journal);
		expect(report.artifacts.truncatedCaptureLogCount).toBe(3);
		expect(report.artifacts.totalCaptureLogElidedBytes).toBeNull();
		expect(report.artifacts.topCaptureLogs.every(log => log.truncatedOnDisk)).toBe(true);
	});

	it("passes all five axes for observed live-model handoffs with checked invariants on both sides", async () => {
		const root = await makeTempSessionDir();
		const baseDir = path.join(root, "base");
		const candDir = path.join(root, "cand");
		await fs.mkdir(baseDir, { recursive: true });
		await fs.mkdir(candDir, { recursive: true });

		const baseFile = path.join(root, "base.jsonl");
		const candFile = path.join(root, "cand.jsonl");
		await writeLiveHandoffSession({
			file: baseFile,
			artifactsDir: baseDir,
			compactions: 2,
			captureBytes: 2_048,
			shaken: true,
		});
		await writeLiveHandoffSession({
			file: candFile,
			artifactsDir: candDir,
			compactions: 1,
			captureBytes: 1_024,
			shaken: false,
		});

		const invariants = [{ name: "anchor_sha", pattern: "ANCHOR_SHA = abcdef" }];
		const baseline = await computeSessionOutputMetrics(baseFile, { handoffInvariants: invariants });
		const candidate = await computeSessionOutputMetrics(candFile, { handoffInvariants: invariants });

		// Provenance is inferred only because each saved document reproduces its journal summary.
		expect(baseline.artifacts.handoffQuality?.provenance).toBe("live_model");
		expect(candidate.artifacts.handoffQuality?.provenance).toBe("live_model");

		const comparison = compareSessionOutputMetrics(candidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(comparison.axes.handoffStructuralCoverage.status).toBe("pass");
		expect(comparison.axes.handoffStructuralCoverage.reason).toContain("invariants 1/1");
		expect(comparison.deterministicAxesPassed).toBe(true);
		expect(comparison.passed).toBe(true);
		expect(comparison.compactionDropAloneGuardTriggered).toBe(false);

		// Live-model provenance with no supplied invariants leaves invariant coverage unmeasured.
		const noInvariantCandidate = await computeSessionOutputMetrics(candFile);
		expect(noInvariantCandidate.artifacts.handoffQuality?.provenance).toBe("live_model");
		const noInvariantComparison = compareSessionOutputMetrics(noInvariantCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(noInvariantComparison.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(noInvariantComparison.axes.handoffStructuralCoverage.reason).toContain("no required handoff invariants");
		expect(noInvariantComparison.passed).toBe(false);

		// A truncated saved file that merely appears inside the journal summary is not the same
		// generated document and must not claim live-model provenance.
		await fs.writeFile(
			path.join(candDir, "handoff-2026-10-25T00-15-00-000Z.md"),
			LIVE_HANDOFF_DOCUMENT.slice(0, 200),
			"utf8",
		);
		const truncatedCandidate = await computeSessionOutputMetrics(candFile, { handoffInvariants: invariants });
		expect(truncatedCandidate.artifacts.handoffQuality?.provenance).toBe("unverified");

		// A saved handoff document with no matching journal summary proves nothing about
		// provenance; the axis falls back to unknown instead of trusting the file.
		await fs.writeFile(
			path.join(candDir, "handoff-2026-10-25T00-15-00-000Z.md"),
			LIVE_HANDOFF_DOCUMENT.replace(
				"Verify that compaction output stays within artifact and handoff budgets.",
				"A different session generated this document after the replay.",
			),
			"utf8",
		);
		const unrelatedCandidate = await computeSessionOutputMetrics(candFile, { handoffInvariants: invariants });
		expect(unrelatedCandidate.artifacts.handoffQuality?.provenance).toBe("unverified");
		const unrelatedComparison = compareSessionOutputMetrics(unrelatedCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(unrelatedComparison.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(unrelatedComparison.passed).toBe(false);

		// An unreadable handoff document is evaluated as a failed document rather than skipped:
		// the readable subset must never claim full coverage in its place.
		await fs.writeFile(path.join(candDir, "handoff-2026-10-25T00-15-00-000Z.md"), LIVE_HANDOFF_DOCUMENT, "utf8");
		await fs.mkdir(path.join(candDir, "handoff-2026-10-25T00-16-00-000Z.md"), { recursive: true });
		const unreadableCandidate = await computeSessionOutputMetrics(candFile, { handoffInvariants: invariants });
		expect(unreadableCandidate.artifacts.handoffQuality?.evaluatedCount).toBe(2);
		expect(unreadableCandidate.artifacts.handoffQuality?.structuralCompleteCount).toBe(1);
		expect(
			unreadableCandidate.artifacts.handoffQuality?.documents.some(doc => doc.source.includes("(unreadable)")),
		).toBe(true);
		const unreadableComparison = compareSessionOutputMetrics(unreadableCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(unreadableComparison.axes.handoffStructuralCoverage.status).not.toBe("pass");
		expect(unreadableComparison.passed).toBe(false);
	});

	it("keeps absent artifact evidence and incomplete JSONL unmeasured instead of passing on defaults", async () => {
		const root = await makeTempSessionDir();
		const baseFile = path.join(root, "missing-base.jsonl");
		const candFile = path.join(root, "missing-cand.jsonl");
		const baseEntries = buildHandoffSessionEntries({ id: "b", compactions: 2, shaken: true });
		const candEntries = buildHandoffSessionEntries({ id: "c", compactions: 1, shaken: false });
		await fs.writeFile(baseFile, `${baseEntries.map(entry => JSON.stringify(entry)).join("\n")}\n`, "utf8");
		await fs.writeFile(candFile, `${candEntries.map(entry => JSON.stringify(entry)).join("\n")}\n`, "utf8");

		const baseline = await computeSessionOutputMetrics(baseFile, {
			artifactsDir: path.join(root, "missing-base-artifacts"),
		});
		const candidate = await computeSessionOutputMetrics(candFile, {
			artifactsDir: path.join(root, "missing-cand-artifacts"),
		});
		expect(candidate.artifactsDirExists).toBe(false);

		const comparison = compareSessionOutputMetrics(candidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(comparison.axes.compactionPace.status).toBe("pass");
		expect(comparison.axes.singleArtifactCap.status).toBe("unknown");
		expect(comparison.axes.singleArtifactCap.candidateValue).toBeNull();
		expect(comparison.axes.singleArtifactCap.reason).toContain("unmeasured, not 0");
		expect(comparison.axes.handoffStructuralCoverage.status).toBe("unknown");
		expect(comparison.deterministicAxesPassed).toBe(false);
		expect(comparison.passed).toBe(false);

		// An existing empty artifact directory is a measured maximum of 0 when the transcript
		// references nothing on disk; that is evidence, not a missing measurement.
		const emptyDir = path.join(root, "empty-cand-artifacts");
		await fs.mkdir(emptyDir, { recursive: true });
		const emptyCandidate = await computeSessionOutputMetrics(candFile, { artifactsDir: emptyDir });
		const emptyComparison = compareSessionOutputMetrics(emptyCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(emptyComparison.axes.singleArtifactCap.status).toBe("pass");
		expect(emptyComparison.axes.singleArtifactCap.candidateValue).toBe(0);

		// A capture-log name that cannot be measured as a regular file leaves the directory only
		// partially inspected: `artifactsDirExists` is false and the cap axis stays unknown.
		const dirtyDir = path.join(root, "dirty-cand-artifacts");
		await fs.mkdir(path.join(dirtyDir, "2.bash.log"), { recursive: true });
		const dirtyCandidate = await computeSessionOutputMetrics(candFile, { artifactsDir: dirtyDir });
		expect(dirtyCandidate.artifactsDirExists).toBe(false);
		const dirtyComparison = compareSessionOutputMetrics(dirtyCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(dirtyComparison.axes.singleArtifactCap.status).toBe("unknown");
		expect(dirtyComparison.axes.singleArtifactCap.candidateValue).toBeNull();

		// A transcript that references spilled artifacts turns the same empty directory into
		// missing evidence: the maximum must stay unmeasured rather than become 0.
		const shakenFile = path.join(root, "shaken-cand.jsonl");
		const shakenEntries = buildHandoffSessionEntries({ id: "s", compactions: 1, shaken: true });
		await fs.writeFile(shakenFile, `${shakenEntries.map(entry => JSON.stringify(entry)).join("\n")}\n`, "utf8");
		const shakenCandidate = await computeSessionOutputMetrics(shakenFile, { artifactsDir: emptyDir });
		expect(shakenCandidate.toolResults.shakenRegions.distinctArtifactIds).toEqual(["1"]);
		const shakenComparison = compareSessionOutputMetrics(shakenCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(shakenComparison.axes.singleArtifactCap.status).toBe("unknown");
		expect(shakenComparison.axes.singleArtifactCap.reason).toContain("references spilled artifacts");

		// A skipped/malformed JSONL record makes every entry-derived axis unmeasured, so a
		// computed pass cannot stand on partial input.
		const corruptFile = path.join(root, "corrupt-cand.jsonl");
		await fs.writeFile(
			corruptFile,
			`${candEntries.map(entry => JSON.stringify(entry)).join("\n")}\n{"type":"message",\n`,
			"utf8",
		);
		const corruptCandidate = await computeSessionOutputMetrics(corruptFile, { artifactsDir: emptyDir });
		expect(corruptCandidate.malformedRecords).toBe(1);
		const corruptComparison = compareSessionOutputMetrics(corruptCandidate, baseline, {
			maxSingleCaptureLogBytes: 4 * 1024 * 1024,
		});
		expect(corruptComparison.axes.compactionPace.status).toBe("unknown");
		expect(corruptComparison.axes.compactionPace.reason).toContain("malformed=1");
		expect(corruptComparison.axes.shakenRatio.status).toBe("unknown");
		expect(corruptComparison.axes.postCompactionStateErrors.status).toBe("unknown");
		expect(corruptComparison.axes.singleArtifactCap.status).toBe("pass");
		expect(corruptComparison.passed).toBe(false);
	});
});
