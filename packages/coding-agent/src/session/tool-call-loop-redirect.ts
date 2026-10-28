import type {
	RepeatedDispatchFailureDetection,
	RepeatedToolCallDetection,
} from "@reverse/ai/utils/tool-call-loop-guard";
import { prompt } from "@reverse/utils";
import toolCallLoopRedirectTemplate from "../prompts/system/tool-call-loop-redirect.md" with { type: "text" };

export const TOOL_CALL_LOOP_REDIRECT_TYPE = "tool-call-loop-redirect";
/** Custom message type for a deterministic dispatch failure loop (not an identical-args loop). */
export const TOOL_CALL_LOOP_DISPATCH_FAILURE_REDIRECT_TYPE = "tool-call-loop-dispatch-failure";

/** Structured record of the loop a redirect was issued for. */
export interface ToolCallLoopRedirectDetails {
	toolName: string;
	count: number;
	argumentsSummary: string;
	resultSummary: string;
}

/**
 * Renders the corrective a repeated tool call earns. Shared by the primary
 * session's `LoopGuards` and the advisor's own loop guard: both bounds speak
 * with one wording, while each wraps it in the message shape its own agent
 * converts to LLM context (the primary maps custom messages, the advisor runs
 * the default converter that keeps only LLM-native roles).
 */
export function renderToolCallLoopRedirect(detection: RepeatedToolCallDetection): string {
	return prompt.render(toolCallLoopRedirectTemplate, {
		tool_name: detection.toolName,
		count: detection.count,
		arguments_summary: detection.argumentsSummary,
		result_summary: detection.resultSummary || "(no text result)",
	});
}

export function toolCallLoopRedirectDetails(detection: RepeatedToolCallDetection): ToolCallLoopRedirectDetails {
	return {
		toolName: detection.toolName,
		count: detection.count,
		argumentsSummary: detection.argumentsSummary,
		resultSummary: detection.resultSummary,
	};
}

/** Structured record of a deterministic dispatch failure loop redirect. */
export interface DispatchFailureRedirectDetails {
	toolName: string;
	count: number;
	code: string;
	key: string;
	message: string;
}

/**
 * Renders the corrective for a reissued deterministic dispatch failure. The
 * text comes from the tool's own rejection message: no argument comparison is
 * claimed (a reworded request can share the same broken precondition) and no
 * wording-only change is suggested.
 */
export function renderDispatchFailureRedirect(detection: RepeatedDispatchFailureDetection): string {
	return [
		'<system-interrupt reason="tool_call_loop_detected">',
		`\`${detection.toolName}\` was rejected before dispatch ${detection.count} times for the same reason (${detection.code}): ${detection.message}`,
		"",
		`Nothing ran for those attempts. Correct exactly what that message reports, or change the request, before calling \`${detection.toolName}\` again; repeating the same request is blocked.`,
		"</system-interrupt>",
	].join("\n");
}

export function dispatchFailureRedirectDetails(
	detection: RepeatedDispatchFailureDetection,
): DispatchFailureRedirectDetails {
	return {
		toolName: detection.toolName,
		count: detection.count,
		code: detection.code,
		key: detection.key,
		message: detection.message,
	};
}
