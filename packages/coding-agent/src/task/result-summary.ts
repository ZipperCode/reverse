/**
 * Model-facing `<task-result>` envelope for a settled subagent run.
 *
 * Rendered by the task tool for spawn results and by the IRC wake-turn relay
 * when a woken subagent re-yields, so a parent reads the same shape (status,
 * preview, `agent://` pointer) regardless of which path delivered it.
 */
import { prompt } from "@reverse/utils";
import taskSummaryTemplate from "../prompts/tools/task-summary.md" with { type: "text" };
import { AgentRegistry, isResumable } from "../registry/agent-registry";
import { ASYNC_INLINE_RESULT_MAX_CHARS } from "../session/async-job-delivery";
import { escapeHarnessTags } from "../session/harness-tags";
import { formatBytes, formatDuration } from "@reverse/tui/render/render-utils";
import type { SingleResult } from "@reverse/tui/tools/task";

/**
 * Largest output inlined whole. A cut output costs the parent a
 * `read agent://<id>` turn plus the preview it then holds twice, which parents
 * pay for most outputs past ~8k chars. A background task result arrives as an
 * async follow-up, which cuts anything over {@link ASYNC_INLINE_RESULT_MAX_CHARS};
 * an envelope whose `<error>` or `<merge-summary>` would push it over falls back
 * to the preview instead.
 */
export const INLINE_OUTPUT_CHARS = ASYNC_INLINE_RESULT_MAX_CHARS - 500;
/** Head shown for an output over {@link INLINE_OUTPUT_CHARS}, with a pointer to `agent://<id>`. */
const PREVIEW_CHARS = 5000;

/**
 * Preview text for a child result. Falls back to "(no output)" — annotated
 * with the request count when the child actually did work, so the parent can
 * tell a no-op child from one that burned requests before being cancelled.
 */
export function formatResultOutputFallback(result: Pick<SingleResult, "output" | "stderr" | "requests">): string {
	const base = result.output.trim() || result.stderr.trim();
	if (base) return base;
	return result.requests > 0 ? `(no output) after ${result.requests} req` : "(no output)";
}

/**
 * Head of `output` that fits the inline budget. Prefers a line boundary so a
 * markdown preview does not end mid-row, but falls back to a hard cut when the
 * only boundary is near the start (pretty-printed JSON whose second line is
 * one huge string would otherwise preview as a lone `{`).
 */
function previewHead(output: string): string {
	const slice = output.slice(0, PREVIEW_CHARS);
	const lastNewline = slice.lastIndexOf("\n");
	return lastNewline >= PREVIEW_CHARS / 2 ? slice.slice(0, lastNewline) : slice;
}

interface ScoutStructuredPayload {
	summary?: unknown;
	architecture?: unknown;
	files?: unknown;
	report?: unknown;
	unresolved?: unknown;
	[key: string]: unknown;
}

/**
 * 提取 Scout 结构化产物数据。
 * 优先取已校验的 structuredOutput.data；若无则尝试解析 output JSON。
 */
function extractStructuredData(result: SingleResult): ScoutStructuredPayload | undefined {
	if (
		result.structuredOutput?.data &&
		typeof result.structuredOutput.data === "object" &&
		result.structuredOutput.data !== null &&
		!Array.isArray(result.structuredOutput.data)
	) {
		return result.structuredOutput.data as ScoutStructuredPayload;
	}
	if (typeof result.output === "string") {
		const trimmed = result.output.trim();
		if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
			try {
				const parsed = JSON.parse(trimmed);
				if (parsed && typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
					return parsed as ScoutStructuredPayload;
				}
			} catch {
				// 忽略非合法 JSON
			}
		}
	}
	return undefined;
}

const SCOUT_MAX_FILES = 8;
const SCOUT_FILES_BUDGET = 1200;
const SCOUT_MAX_FILE_PATH = 80;
const SCOUT_MAX_FILE_DESC = 100;
const SCOUT_MAX_SUMMARY_FIELD = 600;
const SCOUT_MAX_ARCH_FIELD = 400;
const SCOUT_MAX_UNRESOLVED_FIELD = 400;

/**
 * 格式化 Scout 成功产物的紧凑摘要，为父 Agent 呈现关键结论与证据索引。
 * 注入预算保守控制在约 3k-4k 字符，保留 summary、architecture、有限 files 引用、
 * 明确的未决/验证边界，并提供完整原件与 report 读取入口。
 */
function formatScoutSummary(result: SingleResult, data: ScoutStructuredPayload): string {
	const sections: string[] = [];

	// 1. 摘要
	if (typeof data.summary === "string" && data.summary.trim().length > 0) {
		let summaryText = data.summary.trim();
		if (summaryText.length > SCOUT_MAX_SUMMARY_FIELD) {
			summaryText = summaryText.slice(0, SCOUT_MAX_SUMMARY_FIELD - 3).trimEnd() + "...";
		}
		sections.push(`**核心摘要**:\n${summaryText}`);
	}

	// 2. 架构与连接
	if (typeof data.architecture === "string" && data.architecture.trim().length > 0) {
		let archText = data.architecture.trim();
		if (archText.length > SCOUT_MAX_ARCH_FIELD) {
			archText = archText.slice(0, SCOUT_MAX_ARCH_FIELD - 3).trimEnd() + "...";
		}
		sections.push(`**架构与连接**: ${archText}`);
	}

	// 3. Key Evidence & Files
	let omittedFilesCount = 0;
	if (Array.isArray(data.files) && data.files.length > 0) {
		const fileLines: string[] = [];
		let currentFilesChars = 0;
		let displayedCount = 0;

		for (const item of data.files) {
			if (!item) continue;
			if (displayedCount >= SCOUT_MAX_FILES || currentFilesChars >= SCOUT_FILES_BUDGET) {
				break;
			}
			if (typeof item === "string") {
				let pathStr = item.trim();
				let truncatedPathNotice = "";
				if (pathStr.length > SCOUT_MAX_FILE_PATH) {
					pathStr = pathStr.slice(0, SCOUT_MAX_FILE_PATH);
					truncatedPathNotice = " (路径过长已截断，完整路径见 agent://原件)";
				}
				const line = `- \`${pathStr}\`${truncatedPathNotice}`;
				fileLines.push(line);
				currentFilesChars += line.length + 1;
				displayedCount++;
			} else if (typeof item === "object") {
				const fileObj = item as { path?: unknown; description?: unknown };
				let pathStr = typeof fileObj.path === "string" ? fileObj.path.trim() : "";
				let truncatedPathNotice = "";
				if (pathStr.length > SCOUT_MAX_FILE_PATH) {
					pathStr = pathStr.slice(0, SCOUT_MAX_FILE_PATH);
					truncatedPathNotice = "… (路径过长已截断)";
				}
				let descStr = typeof fileObj.description === "string" ? fileObj.description.trim() : "";
				if (descStr.length > SCOUT_MAX_FILE_DESC) {
					descStr = descStr.slice(0, SCOUT_MAX_FILE_DESC - 3).trimEnd() + "...";
				}
				let line = "";
				if (pathStr && descStr) {
					line = `- \`${pathStr}\`${truncatedPathNotice}: ${descStr}`;
				} else if (pathStr) {
					line = `- \`${pathStr}\`${truncatedPathNotice}`;
				} else if (descStr) {
					line = `- ${descStr}`;
				}
				if (line) {
					fileLines.push(line);
					currentFilesChars += line.length + 1;
					displayedCount++;
				}
			}
		}

		omittedFilesCount = Math.max(0, data.files.length - displayedCount);
		if (omittedFilesCount > 0) {
			fileLines.push(`- ... 另有 ${omittedFilesCount} 个文件引用未内联（详见 \`agent://${result.id}\`）`);
		}

		if (fileLines.length > 0) {
			sections.push(`**关键证据与文件**:\n${fileLines.join("\n")}`);
		}
	}

	// 4. 未决问题与验证边界（兼容 schema 或结构化附带字段）
	if (data.unresolved) {
		const unresolvedItems: string[] = [];
		if (typeof data.unresolved === "string" && data.unresolved.trim().length > 0) {
			unresolvedItems.push(data.unresolved.trim());
		} else if (Array.isArray(data.unresolved)) {
			for (const sub of data.unresolved) {
				if (typeof sub === "string" && sub.trim().length > 0) {
					unresolvedItems.push(sub.trim());
				}
			}
		}
		if (unresolvedItems.length > 0) {
			let unresolvedBlock =
				unresolvedItems.length === 1 && !unresolvedItems[0]!.includes("\n")
					? `**未决问题与验证边界**: ${unresolvedItems[0]}`
					: `**未决问题与验证边界**:\n${unresolvedItems.map(item => `- ${item}`).join("\n")}`;
			if (unresolvedBlock.length > SCOUT_MAX_UNRESOLVED_FIELD) {
				unresolvedBlock = unresolvedBlock.slice(0, SCOUT_MAX_UNRESOLVED_FIELD - 3).trimEnd() + "...";
			}
			sections.push(unresolvedBlock);
		}
	}

	// 5. Pointers & Omitted Evidence
	const hasReport = typeof data.report === "string" && data.report.trim().length > 0;
	const pointerLines: string[] = [];

	if (hasReport) {
		pointerLines.push(`**完整报告**: 可通过 \`read agent://${result.id}/report\` 调阅完整深度报告`);
	}
	pointerLines.push(`**完整原件**: 可通过 \`read agent://${result.id}\` 调阅完整原件`);

	const omittedEvidenceNotes: string[] = [];
	if (hasReport) {
		const reportLen = (data.report as string).length;
		omittedEvidenceNotes.push(
			`完整报告（${reportLen} 字符）未在摘要中全量内联，请调阅 \`agent://${result.id}/report\``,
		);
	}
	if (omittedFilesCount > 0) {
		omittedEvidenceNotes.push(`另有 ${omittedFilesCount} 个文件引用未内联`);
	}

	if (omittedEvidenceNotes.length > 0) {
		pointerLines.push(`**未内联证据**: ${omittedEvidenceNotes.join("；")}`);
	}

	sections.push(pointerLines.join("\n"));

	return sections.length > 0 ? sections.join("\n\n") : previewHead(result.output);
}

/** Render the `<task-result>` envelope for a settled run. */
export function formatTaskResultSummary(
	result: SingleResult,
	options: { totalDurationMs: number; mergeSummary?: string },
): string {
	const status = result.aborted
		? "cancelled"
		: result.exitCode === 0 && result.error
			? "merge failed"
			: result.exitCode === 0
				? "completed"
				: `failed (exit ${result.exitCode})`;
	const output = formatResultOutputFallback(result);
	// The preview prefers `output` over `stderr`, so a run that failed after
	// streaming prose (provider stream error, missing yield) would otherwise
	// show only the half-written text and no reason. Aborts carry their own
	// <abort-reason>; an empty output already previews the error itself.
	const error = result.exitCode !== 0 && !result.aborted && result.output.trim().length > 0 ? result.error : undefined;
	const outputCharCount = result.outputMeta?.charCount ?? output.length;
	// A stopped agent stays messageable; tell the parent so it can resume via
	// irc instead of redoing the work. Isolated runs are parked without a
	// reviver (their worktree is gone), so they must not read as resumable.
	const resumable = result.aborted && !result.isolated && isResumable(AgentRegistry.global().get(result.id));
	const render = (truncated: boolean, customPreview?: string): string =>
		prompt.render(taskSummaryTemplate, {
			agentName: result.agent,
			id: result.id,
			status,
			duration: formatDuration(options.totalDurationMs),
			abortReason: result.aborted ? escapeHarnessTags(result.abortReason ?? "") || undefined : undefined,
			error: error === undefined ? undefined : escapeHarnessTags(error),
			resumable,
			preview: escapeHarnessTags(customPreview ?? (truncated ? previewHead(output) : output)),
			truncated,
			meta: result.outputMeta
				? {
						lineCount: result.outputMeta.lineCount,
						charSize: formatBytes(result.outputMeta.charCount),
					}
				: undefined,
			mergeSummary: options.mergeSummary === undefined ? "" : escapeHarnessTags(options.mergeSummary),
		});
	if (result.outputPath === undefined) return render(false);

	// 仅对有持久化原件且成功执行的 Scout 结构化产物生成压缩摘要
	if (result.agent === "scout" && result.exitCode === 0 && !result.aborted && result.error === undefined) {
		const structured = extractStructuredData(result);
		if (
			structured &&
			("summary" in structured || "architecture" in structured || "files" in structured || "report" in structured)
		) {
			const scoutSummary = formatScoutSummary(result, structured);
			return render(true, scoutSummary);
		}
	}
	if (outputCharCount > INLINE_OUTPUT_CHARS) return render(true);
	const whole = render(false);
	return whole.length > ASYNC_INLINE_RESULT_MAX_CHARS && outputCharCount > PREVIEW_CHARS ? render(true) : whole;
}
