/**
 * Utilities for detecting and handling protocol leaks and malformed tool calls.
 *
 * Issue #9: Models occasionally emit tool invocation markup as raw plain text
 * (e.g. `[tool_use id=... name=_bash]`) instead of structured tool calls, or
 * corrupt the tool name with invocation markup (e.g. `tool_use id=... name=_bash`).
 *
 * Safety requirements:
 * 1. Plain text protocol leaks must NEVER be executed as arbitrary commands.
 * 2. Quoted examples (Markdown code blocks, inline backticks, and blockquotes)
 *    must remain inert. Natural prose mentions of tool tags without complete
 *    invocation envelopes must remain inert.
 * 3. Malformed tool names must produce structured diagnostics preserving raw
 *    call / model / provider / ID info, without misleading fuzzy suggestions.
 * 4. Recovery is bounded; persistent leaks must fail explicitly rather than
 *    silently completing with a normal stop.
 * 5. Original message content must remain unchanged; diagnosed raw snippets
 *    are bounded in size.
 */

import type { AssistantMessage } from "../types";
import { isMalformedToolCallName } from "../providers/transform-messages";

export { isMalformedToolCallName };

export interface ProtocolLeakDetection {
	readonly rawSnippet: string;
	readonly tag: string;
	readonly toolCallId?: string;
	readonly rawName?: string;
}

const MAX_SNIPPET_LENGTH = 512;

// Case-insensitive fast check to avoid unnecessary regex work.
const FAST_CHECK_RE = /tool_use|tool_call|tool_calls|function_call|dsml/i;

/**
 * Recognizable invocation envelopes on standalone lines:
 * Requires opening tag with id/name attributes (or envelope wrapper)
 * followed by a structured JSON payload {...} or DSML parameters.
 */
const BRACKET_INVOCATION_RE =
	/^[ \t]*\[\s*tool_use\b([^\]\n]*?(?:\bid\s*=|\bname\s*=)[^\]\n]*?)\][ \t]*\r?\n[ \t]*(\{[\s\S]*?\})(?:[ \t]*\r?\n[ \t]*\[\s*\/\s*tool_use\s*\])?/m;

const BRACKET_FUNCTION_INVOCATION_RE =
	/^[ \t]*\[\s*function_call\b([^\]\n]*?(?:\bid\s*=|\bname\s*=)[^\]\n]*?)\][ \t]*\r?\n[ \t]*(\{[\s\S]*?\})(?:[ \t]*\r?\n[ \t]*\[\s*\/\s*function_call\s*\])?/m;

const XML_TOOL_USE_INVOCATION_RE =
	/^[ \t]*<\s*tool_use\b([^>\n]*?(?:\bid\s*=|\bname\s*=)[^>\n]*?)>[ \t]*\r?\n[ \t]*(\{[\s\S]*?\})(?:[ \t]*\r?\n[ \t]*<\s*\/\s*tool_use\s*>)?/m;

const XML_TOOL_CALL_INVOCATION_RE =
	/^[ \t]*<\s*tool_call\b[^>\n]*>[ \t]*\r?\n[ \t]*(\{[\s\S]*?\})[ \t]*\r?\n[ \t]*<\s*\/\s*tool_call\s*>/m;

const DSML_INVOCATION_RE =
	/<\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?:tool_calls|invoke)\b[^<>]*>[\s\S]*?<\s*\/\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?:tool_calls|invoke)\s*>/u;

/**
 * Remove quoted examples and blockquotes so they remain completely inert:
 * 1. Fenced code blocks (3+ backticks or 3+ tildes on their own line, closed only by a standalone matching fence).
 * 2. Markdown blockquote lines (`> ...`).
 * 3. Multi-backtick and single-backtick inline spans (`+).
 */
export function stripQuotedAndBlockquoted(text: string): string {
	const lines = text.split(/\r?\n/);
	const outLines: string[] = [];
	let inFence = false;
	let fenceChar = "";
	let fenceLength = 0;
	let inlineDelimiter: string | undefined;

	for (const line of lines) {
		const fenceMatch = /^[ \t]*(`{3,}|~{3,})/.exec(line);
		if (inFence) {
			if (fenceMatch) {
				const matchStr = fenceMatch[1]!;
				const char = matchStr[0]!;
				const len = matchStr.length;
				if (
					char === fenceChar &&
					len >= fenceLength &&
					line.slice(line.indexOf(matchStr) + len).trim().length === 0
				) {
					inFence = false;
					fenceChar = "";
					fenceLength = 0;
				}
			}
			continue;
		}
		if (fenceMatch) {
			const matchStr = fenceMatch[1]!;
			inFence = true;
			fenceChar = matchStr[0]!;
			fenceLength = matchStr.length;
			continue;
		}
		if (/^[ \t]*>/.test(line)) continue;

		let visible = line;
		if (inlineDelimiter) {
			const close = visible.indexOf(inlineDelimiter);
			if (close < 0) continue;
			visible = visible.slice(close + inlineDelimiter.length);
			inlineDelimiter = undefined;
		}
		while (visible.length > 0) {
			const open = /`{1,2}/.exec(visible);
			if (!open) break;
			const delimiter = open[0]!;
			const rest = visible.slice(open.index + delimiter.length);
			const close = rest.indexOf(delimiter);
			if (close < 0) {
				inlineDelimiter = delimiter;
				visible = visible.slice(0, open.index);
				break;
			}
			visible = visible.slice(0, open.index) + rest.slice(close + delimiter.length);
		}
		outLines.push(visible);
	}

	return outLines.join("\n");
}

/**
 * Detect whether unquoted text contains an unexecuted protocol leak invocation envelope.
 */
export function detectProtocolLeakInText(text: string): ProtocolLeakDetection | undefined {
	if (!text || !FAST_CHECK_RE.test(text)) return undefined;

	const unquoted = stripQuotedAndBlockquoted(text);
	if (!unquoted || !FAST_CHECK_RE.test(unquoted)) return undefined;

	// Check bracket tool_use envelope: [tool_use id=... name=...]\n{...}\n[/tool_use]
	const bracketMatch = BRACKET_INVOCATION_RE.exec(unquoted);
	if (bracketMatch) {
		const snippet = bracketMatch[0].slice(0, MAX_SNIPPET_LENGTH);
		const attrs = bracketMatch[1] ?? "";
		const idMatch = /\bid\s*=\s*["']?([^\s"'>\]]+)/i.exec(attrs);
		let rawName = /\bname\s*=\s*["']?([^\s"'>\]]+)/i.exec(attrs)?.[1];
		if (!rawName) {
			const jsonMatch = /"name"\s*:\s*"([^"]+)"/.exec(bracketMatch[2] ?? "");
			if (jsonMatch) rawName = jsonMatch[1];
		}
		const tag = `[tool_use${attrs}]`;
		return {
			rawSnippet: snippet,
			tag,
			toolCallId: idMatch?.[1],
			rawName,
		};
	}

	// Check bracket function_call envelope
	const bracketFuncMatch = BRACKET_FUNCTION_INVOCATION_RE.exec(unquoted);
	if (bracketFuncMatch) {
		const snippet = bracketFuncMatch[0].slice(0, MAX_SNIPPET_LENGTH);
		const attrs = bracketFuncMatch[1] ?? "";
		const idMatch = /\bid\s*=\s*["']?([^\s"'>\]]+)/i.exec(attrs);
		let rawName = /\bname\s*=\s*["']?([^\s"'>\]]+)/i.exec(attrs)?.[1];
		if (!rawName) {
			const jsonMatch = /"name"\s*:\s*"([^"]+)"/.exec(bracketFuncMatch[2] ?? "");
			if (jsonMatch) rawName = jsonMatch[1];
		}
		const tag = `[function_call${attrs}]`;
		return {
			rawSnippet: snippet,
			tag,
			toolCallId: idMatch?.[1],
			rawName,
		};
	}

	// Check XML tool_use envelope: <tool_use id=... name=...>\n{...}\n</tool_use>
	const xmlToolUseMatch = XML_TOOL_USE_INVOCATION_RE.exec(unquoted);
	if (xmlToolUseMatch) {
		const snippet = xmlToolUseMatch[0].slice(0, MAX_SNIPPET_LENGTH);
		const attrs = xmlToolUseMatch[1] ?? "";
		const idMatch = /\bid\s*=\s*["']?([^\s"'>]+)/i.exec(attrs);
		let rawName = /\bname\s*=\s*["']?([^\s"'>]+)/i.exec(attrs)?.[1];
		if (!rawName) {
			const jsonMatch = /"name"\s*:\s*"([^"]+)"/.exec(xmlToolUseMatch[2] ?? "");
			if (jsonMatch) rawName = jsonMatch[1];
		}
		const tag = `<tool_use${attrs}>`;
		return {
			rawSnippet: snippet,
			tag,
			toolCallId: idMatch?.[1],
			rawName,
		};
	}

	// Check XML tool_call envelope: <tool_call>\n{...}\n</tool_call>
	const xmlToolCallMatch = XML_TOOL_CALL_INVOCATION_RE.exec(unquoted);
	if (xmlToolCallMatch) {
		const snippet = xmlToolCallMatch[0].slice(0, MAX_SNIPPET_LENGTH);
		let rawName: string | undefined;
		const jsonMatch = /"name"\s*:\s*"([^"]+)"/.exec(xmlToolCallMatch[1] ?? "");
		if (jsonMatch) rawName = jsonMatch[1];
		return {
			rawSnippet: snippet,
			tag: "<tool_call>",
			rawName,
		};
	}

	// Check DSML invocation envelope
	const dsmlMatch = DSML_INVOCATION_RE.exec(unquoted);
	if (dsmlMatch) {
		const snippet = dsmlMatch[0].slice(0, MAX_SNIPPET_LENGTH);
		const nameMatch = /\bname\s*=\s*["']?([^\s"'>]+)/i.exec(snippet);
		return {
			rawSnippet: snippet,
			tag: "<DSML:invoke>",
			rawName: nameMatch?.[1],
		};
	}

	return undefined;
}

/**
 * Detect whether an assistant message contains unexecuted tool-call protocol markup
 * in its visible text content blocks.
 */
export function detectProtocolLeakInMessage(message: AssistantMessage): ProtocolLeakDetection | undefined {
	for (const block of message.content) {
		if (block.type === "text") {
			const leak = detectProtocolLeakInText(block.text);
			if (leak) return leak;
		}
	}
	return undefined;
}

/**
 * Format an explicit error message for a tool call with a malformed name.
 */
export function formatMalformedToolNameMessage(name: string, id?: string): string {
	const idPart = id ? ` (id: "${id}")` : "";
	return `Malformed tool name "${name}"${idPart}: tool names must not contain spaces, delimiters, or control characters. The tool was NOT executed.`;
}

/**
 * Format a runtime recovery prompt for a turn that leaked tool protocol into text.
 */
export function formatProtocolLeakRecoveryPrompt(leak: ProtocolLeakDetection): string {
	const target = leak.rawName ? ` for tool "${leak.rawName}"` : "";
	return `Tool call failed: your previous response emitted protocol markup (${leak.tag})${target} as plain text instead of a structured tool call. No tool was executed. Please re-issue your intended tool call using the standard structured tool call format.`;
}
