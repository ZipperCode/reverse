import type { Component } from "../index";
import { isRecord } from "@reverse/utils";
import type { NativeToolHead, NativeToolView, RenderResultOptions } from "./renderer";
import { ansi, code, span, text } from "../native/describe";
import type { NativeNode } from "../native/node";
import { plainText } from "../native/spans";
import { INTENT_FIELD } from "@reverse/wire";
import { noteText } from "./native-view";
import type { Theme } from "../theme/theme";
import { formatOutputPaneLines } from "../render/output-pane";
import { renderStatusLine, type StatusLineOptions } from "../render/status-line";
import { plainToolCard, type ToolCardPhase } from "../render/tool-card";
import { clipCollapsed, formatExpandHint, replaceTabs } from "../render/render-utils";
import {
	describeJsonValue,
	formatArgsInline,
	JSON_TREE_MAX_DEPTH_COLLAPSED,
	JSON_TREE_MAX_DEPTH_EXPANDED,
	JSON_TREE_MAX_LINES_COLLAPSED,
	JSON_TREE_MAX_LINES_EXPANDED,
	JSON_TREE_SCALAR_LEN_COLLAPSED,
	JSON_TREE_SCALAR_LEN_EXPANDED,
	renderJsonTreeLines,
} from "./json-tree";

/** Inputs rendered by the fallback card used when a tool has no bespoke renderer. */
export interface DefaultToolRenderInput {
	/** Human-readable tool label. */
	label: string;
	/** Tool arguments, shown inline when collapsed and as a tree when expanded. */
	args: unknown;
	/** Settled or streaming result; omitted while only the call is available. */
	result?: {
		output: string;
		isError?: boolean;
		/** Synthetic placeholder for a call skipped mid-batch to service steering/peer
		 * input — the tool never ran, so it renders neutral (info) rather than as an error. */
		skipped?: boolean;
	};
	/** Current expansion and lifecycle state. */
	options: RenderResultOptions;
}

/** Spinner-dependent header state; cheap, recomputed every frame. */
function buildDefaultToolStatus(input: DefaultToolRenderInput): { status: StatusLineOptions; phase: ToolCardPhase } {
	const { options, result } = input;
	const status: StatusLineOptions = {
		icon: options.isPartial
			? options.spinnerFrame !== undefined
				? "running"
				: "pending"
			: result?.skipped
				? "info"
				: result?.isError
					? "error"
					: "done",
		spinnerFrame: options.spinnerFrame,
		title: input.label,
	};
	if (result?.skipped) status.titleColor = "muted";
	const phase: ToolCardPhase = options.isPartial
		? options.spinnerFrame !== undefined
			? "running"
			: "partial"
		: result?.skipped
			? "info"
			: result?.isError
				? "error"
				: "success";
	return { status, phase };
}

function styleDefaultToolOutputLine(line: string, isError: boolean, theme: Theme): string {
	const normalized = replaceTabs(line);
	if (normalized.includes("\x1b[")) return normalized;
	return theme.fg(isError ? "error" : "toolOutput", normalized);
}

function hasHiddenGenericArgs(
	args: unknown,
	contentWidth: number,
	theme: Theme,
	renderedInlinePreview?: string,
): boolean {
	if (args === undefined || args === null) return false;
	if (!isRecord(args)) {
		return !Array.isArray(args) || args.length > 0;
	}
	const entries = Object.entries(args).filter(([key]) => key !== INTENT_FIELD && key !== "__partialJson");
	if (entries.length === 0) return false;

	for (const [, val] of entries) {
		if (Array.isArray(val) && val.length > 0) return true;
		if (val !== null && typeof val === "object" && Object.keys(val).length > 0) return true;
		if (typeof val === "string" && val.includes("\n")) return true;
	}

	// 宽度截断器使用有符号 32 位整数；最大正值保留原文，也避免把字面省略号误判为截断。
	const fullBudgetPreview = formatArgsInline(args, 0x7fffffff);
	if (renderedInlinePreview !== undefined) {
		return renderedInlinePreview !== fullBudgetPreview;
	}
	const inlineBudget = Math.max(20, contentWidth - Bun.stringWidth(theme.tree.last) - 2);
	const preview = formatArgsInline(args, inlineBudget);
	return preview !== fullBudgetPreview;
}

/** Args preview plus JSON-tree/raw output body; depends only on args, output, expansion and width. */
function buildDefaultToolBody(input: DefaultToolRenderInput, uiTheme: Theme, contentWidth: number): string[] {
	const { options, result } = input;
	const body: string[] = [];
	const args = isRecord(input.args) ? input.args : undefined;
	let renderedInlinePreview: string | undefined;
	if (!options.expanded && args && Object.keys(args).length > 0) {
		const inlineBudget = Math.max(20, contentWidth - Bun.stringWidth(uiTheme.tree.last) - 2);
		const preview = formatArgsInline(args, inlineBudget);
		if (preview) {
			renderedInlinePreview = preview;
			body.push(` ${uiTheme.fg("dim", uiTheme.tree.last)} ${uiTheme.fg("dim", preview)}`);
		}
	}

	if (options.expanded && input.args !== undefined) {
		body.push("");
		body.push(uiTheme.fg("dim", "Args"));
		const tree = renderJsonTreeLines(
			input.args,
			uiTheme,
			JSON_TREE_MAX_DEPTH_EXPANDED,
			JSON_TREE_MAX_LINES_EXPANDED,
			JSON_TREE_SCALAR_LEN_EXPANDED,
		);
		body.push(...tree.lines);
		if (tree.truncated) {
			body.push(uiTheme.fg("dim", "…"));
		}
		body.push("");
	}

	if (result) {
		const textContent = result.output.trimEnd();
		if (!textContent) {
			body.push(uiTheme.fg("dim", "(no output)"));
			if (!options.expanded && hasHiddenGenericArgs(input.args, contentWidth, uiTheme, renderedInlinePreview)) {
				body.push(formatExpandHint(uiTheme, false, true));
			}
		} else {
			let renderedAsJson = false;
			if (isTreeSafeJson(textContent)) {
				try {
					const parsed = JSON.parse(textContent);
					const tree = renderJsonTreeLines(parsed, uiTheme, {
						maxDepth: options.expanded ? JSON_TREE_MAX_DEPTH_EXPANDED : JSON_TREE_MAX_DEPTH_COLLAPSED,
						maxLines: options.expanded ? JSON_TREE_MAX_LINES_EXPANDED : JSON_TREE_MAX_LINES_COLLAPSED,
						maxScalarLen: options.expanded ? JSON_TREE_SCALAR_LEN_EXPANDED : JSON_TREE_SCALAR_LEN_COLLAPSED,
						// A result's own `i` or `__partialJson` keys are data, not call metadata.
						hiddenRootKeys: [],
					});

					// An expanded tree that hit a cap would show less than the raw output, so
					// Ctrl+O falls through to the uncapped raw view instead.
					if (tree.lines.length > 0 && !(options.expanded && tree.truncated)) {
						body.push(...tree.lines);
						if (!options.expanded) {
							if (
								tree.truncated ||
								hasHiddenGenericArgs(input.args, contentWidth, uiTheme, renderedInlinePreview)
							) {
								body.push(formatExpandHint(uiTheme, false, true));
							}
						}
						renderedAsJson = true;
					}
				} catch {
					// Non-JSON output that starts with a bracket is rendered as plain text.
				}
			}
			if (!renderedAsJson) {
				// No expanded cap: the terminal's own disclosure clamp is the only
				// bound, so Ctrl+O reveals every row the collapsed view promised.
				const isError = result.isError ?? false;
				const pane = formatOutputPaneLines(
					{
						lines: textContent.split("\n"),
						expanded: options.expanded,
						collapsedMaxLines: 4,
						styleLine: line =>
							clipCollapsed(styleDefaultToolOutputLine(line, isError, uiTheme), contentWidth, options.expanded),
					},
					uiTheme,
				);
				body.push(...pane.lines);
				if (
					!options.expanded &&
					pane.hiddenCount === 0 &&
					hasHiddenGenericArgs(input.args, contentWidth, uiTheme, renderedInlinePreview)
				) {
					body.push(formatExpandHint(uiTheme, false, true));
				}
			}
		}
	}

	return body;
}

/** Format one generic tool call/result card at the available content width. */
export function formatDefaultToolExecution(
	input: DefaultToolRenderInput,
	contentWidth: number,
	uiTheme: Theme,
): string {
	const { status } = buildDefaultToolStatus(input);
	return [renderStatusLine(status, uiTheme), ...buildDefaultToolBody(input, uiTheme, contentWidth)].join("\n");
}

/**
 * Serialized JSON past this size keeps the raw view: the tree caps out at a few
 * hundred rows anyway, and parsing and indexing a huge payload only to discard
 * the tree can stall the UI.
 */
const JSON_TREE_MAX_CHARS = 64 * 1024;
/** An integer literal of 16+ digits may exceed `Number.MAX_SAFE_INTEGER` and change when parsed. */
const UNSAFE_INTEGER_RE = /(?<![\w.])-?\d{16,}(?![\w.])/;

/**
 * Whether a tool result can render as a JSON tree without losing anything the
 * raw text shows: a bracketed payload small enough to index, with no integer a
 * double would round (64-bit ids).
 */
function isTreeSafeJson(text: string): boolean {
	return (
		(text.startsWith("{") || text.startsWith("[")) &&
		text.length <= JSON_TREE_MAX_CHARS &&
		!UNSAFE_INTEGER_RE.test(text)
	);
}

/** Inline args summary budget in characters (a data cap, not a width). */
const NATIVE_ARGS_SUMMARY_CHARS = 160;

/**
 * TSP view of the generic fallback card: the tool label with a one-line args
 * summary as the head target; the result as JSON (the host's `json` viewer,
 * else a JSON tree) or raw `ansi` output. The complete output goes over the
 * wire — the card-level disclosure clamp the terminal applies is the only
 * bound, so an expanded card keeps every row. The `json` viewer never cuts;
 * JSON the fallback tree's depth, node or scalar caps would cut keeps the raw
 * path instead.
 */
function renderNativeErrorNode(message: string, lines?: number): NativeNode {
	const body = plainText(message).trim();
	return body.includes("\n") && /^[{[]/.test(body)
		? code(body, {
				lang: "json",
				tone: "error",
				role: "reverse.tool.error",
				preview: lines !== undefined ? { lines } : undefined,
			})
		: text([span(body, "error")], {
				wrap: "word",
				role: "reverse.tool.error",
				lines,
			});
}

/**
 * TSP view of the generic fallback card: the tool label with a one-line args
 * summary as the head target; the result as a JSON tree or raw `ansi` output.
 */
export function describeDefaultToolExecution(input: DefaultToolRenderInput): NativeToolView {
	const { result } = input;
	const args = isRecord(input.args) ? input.args : undefined;
	const summary =
		args && Object.keys(args).length > 0
			? formatArgsInline(args, NATIVE_ARGS_SUMMARY_CHARS, { characterBudget: true })
			: undefined;
	const tool: NativeToolHead = { title: input.label, target: summary || undefined, targetKind: "text" };
	if (!result) return { tool };
	const output = result.output.trimEnd();
	const tone = result.skipped ? "info" : result.isError ? "error" : undefined;
	const expanded = input.options?.expanded ?? false;
	const previewLines = expanded ? undefined : 4;
	if (!output) return { tool, tone, body: [noteText("(no output)")], preview: { lines: 4 } };
	if (result.isError) {
		let errorChild: NativeNode | undefined;
		if (isTreeSafeJson(output)) {
			try {
				let truncated = false;
				const tree = describeJsonValue(JSON.parse(output), {
					native: input.options?.json,
					hiddenRootKeys: [],
					onTruncated: () => {
						truncated = true;
					},
				});
				if (!truncated) errorChild = tree;
			} catch {
				// Not JSON: shown as error node below.
			}
		}
		return {
			tool,
			tone: "error",
			body: [errorChild ?? renderNativeErrorNode(output, previewLines)],
			preview: { lines: 4 },
		};
	}
	if (isTreeSafeJson(output)) {
		let parsed: unknown;
		try {
			parsed = JSON.parse(output);
		} catch {
			// Not JSON: shown as raw output below.
		}
		if (parsed !== undefined) {
			let truncated = false;
			const tree = describeJsonValue(parsed, {
				native: input.options.json,
				// A result's own `i` or `__partialJson` keys are data, not call metadata.
				hiddenRootKeys: [],
				onTruncated: () => {
					truncated = true;
				},
			});
			if (!truncated) return { tool, tone, body: [tree], preview: { lines: 4 } };
		}
	}
	return {
		tool,
		tone,
		body: [ansi(output, { preview: previewLines ? { lines: previewLines } : undefined })],
		preview: { lines: 4 },
	};
}

/** Render the generic fallback as the state-tinted card used by direct custom tools. */
export function renderDefaultToolExecution(input: DefaultToolRenderInput, uiTheme: Theme): Component {
	// The body (JSON parse + tree walk or output styling) is spinner-invariant;
	// rebuild it only when its inputs change instead of on every animated frame.
	let memo:
		| { args: unknown; output: string | undefined; expanded: boolean; contentWidth: number; body: readonly string[] }
		| undefined;
	return plainToolCard(
		uiTheme,
		({ contentWidth }) => {
			const { status, phase } = buildDefaultToolStatus(input);
			const output = input.result?.output;
			const expanded = input.options.expanded;
			if (
				memo === undefined ||
				memo.args !== input.args ||
				memo.output !== output ||
				memo.expanded !== expanded ||
				memo.contentWidth !== contentWidth
			) {
				memo = {
					args: input.args,
					output,
					expanded,
					contentWidth,
					body: buildDefaultToolBody(input, uiTheme, contentWidth),
				};
			}
			return { status, phase, body: memo.body };
		},
		{ paddingX: 1, paddingY: 1, ignoreTight: true, onInvalidate: () => (memo = undefined) },
	);
}
