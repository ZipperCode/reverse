import { renderDelimitedThinking, renderToolInventory } from "@rva/ai/dialect";
import { formatDuration } from "@rva/utils";
import { INTENT_FIELD } from "@rva/wire";
import { YAML } from "bun";
import { canonicalizeMessage } from "@rva/tui/chat/thinking-display";
import { bashExecutionToText, pythonExecutionToText, } from "./messages";
import { ANONYMIZED_REVIEW_NOTE } from "./session-anonymizer";
function toInventoryTools(tools) {
    return tools.map(tool => ({
        name: tool.name,
        description: tool.description,
        parameters: tool.parameters,
        examples: tool.examples,
    }));
}
/** System prompt + model/thinking config + tool inventory — shared by both transcript styles. */
function renderDumpHeader(options, inventoryTools) {
    const lines = [];
    const systemPrompt = options.systemPrompt?.filter(prompt => prompt.length > 0) ?? [];
    if (systemPrompt.length > 0) {
        lines.push("## System Prompt\n");
        for (let index = 0; index < systemPrompt.length; index++) {
            if (systemPrompt.length > 1) {
                lines.push(`### System Prompt ${index + 1}\n`);
            }
            lines.push(systemPrompt[index]);
            lines.push("\n");
        }
    }
    const model = options.model;
    lines.push("## Configuration\n");
    lines.push(`Model: ${model ? `${model.provider}/${model.id}` : "(not selected)"}`);
    lines.push(`Thinking Level: ${options.thinkingLevel ?? ""}`);
    lines.push("\n");
    const hasSystemPromptToolInventory = options.inlineToolDescriptors === true;
    if (inventoryTools.length > 0 && !hasSystemPromptToolInventory) {
        lines.push("## Available Tools\n");
        lines.push(renderToolInventory(inventoryTools));
        lines.push("\n");
    }
    return lines;
}
const CUSTOM_TYPE_ACRONYMS = {
    acp: "ACP",
    irc: "IRC",
    lsp: "LSP",
    mcp: "MCP",
    rpc: "RPC",
    ttsr: "TTSR",
    tui: "TUI",
    xdev: "XDev",
};
function systemNoticeTitle(customType) {
    const words = customType.split(/[^A-Za-z0-9]+/).filter(Boolean);
    if (words.at(-1)?.toLowerCase() === "notice")
        words.pop();
    const label = words
        .map(word => CUSTOM_TYPE_ACRONYMS[word.toLowerCase()] ?? `${word[0]?.toUpperCase() ?? ""}${word.slice(1)}`)
        .join(" ");
    return label ? `System Notice: ${label}` : "System Notice";
}
function customMessageText(message) {
    if (typeof message.content === "string")
        return message.content;
    return message.content.map(content => (content.type === "text" ? content.text : "[Image]")).join("\n");
}
function appendCustomMessage(lines, message) {
    const content = customMessageText(message);
    if (!/^<system-notice(?:\s|>)/.test(content.trimStart())) {
        lines.push(`## ${message.customType}${headingStamp(message)}\n`);
        lines.push(content);
        lines.push("\n");
        return;
    }
    const longestBacktickRun = content.match(/`+/g)?.reduce((longest, run) => Math.max(longest, run.length), 0) ?? 0;
    const fence = "`".repeat(Math.max(3, longestBacktickRun + 1));
    lines.push(`## ${systemNoticeTitle(message.customType)}${headingStamp(message)}\n`);
    lines.push(`${fence}xml`);
    lines.push(content);
    lines.push(fence);
    lines.push("\n");
}
/** ISO time, or a marker for timestamps outside the `Date` range (e.g. hand-edited JSONL) so one bad value never aborts the dump. */
function formatDumpTime(ms) {
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? `invalid time ${ms}` : date.toISOString();
}
/** ` · <ISO time>` heading suffix from a message's `timestamp`, plus request timing for assistant turns. */
function headingStamp(message) {
    if (!("timestamp" in message))
        return "";
    const timestamp = message.timestamp;
    if (typeof timestamp !== "number" || !Number.isFinite(timestamp) || timestamp <= 0)
        return "";
    let stamp = ` · ${formatDumpTime(timestamp)}`;
    if (message.role === "assistant") {
        const timing = [];
        if (typeof message.duration === "number")
            timing.push(`took ${formatDuration(message.duration)}`);
        if (typeof message.ttft === "number")
            timing.push(`ttft ${formatDuration(message.ttft)}`);
        if (timing.length > 0)
            stamp += ` (${timing.join(", ")})`;
    }
    return stamp;
}
function appendAssistantContent(lines, content) {
    for (const c of content) {
        if (c.type === "text") {
            lines.push(c.text);
        }
        else if (c.type === "thinking") {
            const thinking = canonicalizeMessage(c.thinking);
            if (thinking.length === 0)
                continue;
            // Unwrap any literal `<thinking>` envelope already present in the
            // block (e.g. Opus 4.5 — issue #2700) so the dump never nests tags.
            lines.push(`${renderDelimitedThinking("<thinking>", "</thinking>", thinking)}\n`);
        }
        else if (c.type === "toolCall") {
            lines.push(`### Tool Call: ${c.name}`);
            const rawArgs = c.arguments;
            if (rawArgs && typeof rawArgs === "object") {
                const intent = rawArgs[INTENT_FIELD];
                if (typeof intent === "string" && intent.trim().length > 0) {
                    for (const line of intent.split("\n"))
                        lines.push(`// ${line}`);
                }
                const args = {};
                let hasArgs = false;
                for (const key in rawArgs) {
                    if (key === INTENT_FIELD)
                        continue;
                    args[key] = rawArgs[key];
                    hasArgs = true;
                }
                if (hasArgs) {
                    lines.push("```yaml");
                    lines.push(YAML.stringify(args, null, 2).trimEnd());
                    lines.push("```\n");
                }
            }
        }
    }
}
/** Append the legacy per-message markdown-heading transcript (the pre-16.x `/dump` body). */
function appendMarkdownTranscript(lines, messages) {
    for (const msg of messages) {
        if (msg.role === "user" || msg.role === "developer") {
            lines.push(`${msg.role === "developer" ? "## Developer" : "## User"}${headingStamp(msg)}\n`);
            if (typeof msg.content === "string") {
                lines.push(msg.content);
            }
            else {
                for (const c of msg.content) {
                    if (c.type === "text")
                        lines.push(c.text);
                    else if (c.type === "image")
                        lines.push("[Image]");
                }
            }
            lines.push("\n");
        }
        else if (msg.role === "assistant") {
            lines.push(`## Assistant${headingStamp(msg)}\n`);
            appendAssistantContent(lines, msg.content);
            lines.push("");
        }
        else if (msg.role === "toolResult") {
            lines.push(`### Tool Result: ${msg.toolName}${headingStamp(msg)}`);
            if (msg.isError)
                lines.push("(error)");
            for (const c of msg.content) {
                if (c.type === "text") {
                    lines.push("```");
                    lines.push(c.text);
                    lines.push("```");
                }
                else if (c.type === "image") {
                    lines.push("[Image output]");
                }
            }
            lines.push("");
        }
        else if (msg.role === "bashExecution") {
            const bashMsg = msg;
            if (!bashMsg.excludeFromContext) {
                lines.push(`## Bash Execution${headingStamp(msg)}\n`);
                lines.push(bashExecutionToText(bashMsg));
                lines.push("\n");
            }
        }
        else if (msg.role === "pythonExecution") {
            const pythonMsg = msg;
            if (!pythonMsg.excludeFromContext) {
                lines.push(`## Python Execution${headingStamp(msg)}\n`);
                lines.push(pythonExecutionToText(pythonMsg));
                lines.push("\n");
            }
        }
        else if (msg.role === "custom" || msg.role === "hookMessage") {
            appendCustomMessage(lines, msg);
        }
        else if (msg.role === "branchSummary") {
            const branchMsg = msg;
            lines.push(`## Branch Summary${headingStamp(msg)}\n`);
            lines.push(`(from branch: ${branchMsg.fromId})\n`);
            lines.push(branchMsg.summary);
            lines.push("\n");
        }
        else if (msg.role === "compactionSummary") {
            const compactMsg = msg;
            lines.push(`## Compaction Summary${headingStamp(msg)}\n`);
            lines.push(`(${compactMsg.tokensBefore} tokens before compaction)\n`);
            lines.push(compactMsg.summary);
            lines.push("\n");
        }
        else if (msg.role === "fileMention") {
            const fileMsg = msg;
            lines.push(`## File Mention${headingStamp(msg)}\n`);
            for (const file of fileMsg.files) {
                lines.push(`<file path="${file.path}">`);
                if (file.content)
                    lines.push(file.content);
                if (file.image)
                    lines.push("[Image attached]");
                lines.push("</file>\n");
            }
            lines.push("\n");
        }
    }
}
/**
 * Format messages and session metadata as markdown/plain text (same as
 * AgentSession.formatSessionAsText / /dump).
 */
export function formatSessionDumpText(options) {
    const inventoryTools = toInventoryTools(options.tools ?? []);
    const lines = renderDumpHeader(options, inventoryTools);
    appendMarkdownTranscript(lines, options.messages);
    return lines.join("\n").trim();
}
/** Live-state header lines: registry status, staleness, and tools still executing. */
function appendLiveHeader(lines, live) {
    // `busy` spans the whole turn; a dispatched tool means the model request already finished.
    const phase = live.pendingToolCalls.length > 0 ? ", running tools" : live.busy ? ", request in flight" : "";
    lines.push(`Live: ${live.status}${phase} (captured ${formatDumpTime(live.capturedAt)})`);
    const sinceActivity = formatDuration(live.capturedAt - live.lastActivity);
    const activity = live.activity ? `: ${live.activity}` : "";
    lines.push(`Last activity: ${formatDumpTime(live.lastActivity)} (${sinceActivity} before capture)${activity}`);
    if (live.pendingToolCalls.length > 0)
        lines.push(`Pending tool calls: ${live.pendingToolCalls.join(", ")}`);
}
/**
 * The turn a live subagent is in the middle of. The persisted transcript only
 * holds finished messages, so without this a stalled stream is invisible.
 */
function appendInFlightTurn(lines, live, messages) {
    const partial = live.streamMessage;
    if (partial?.role === "assistant") {
        const elapsed = formatDuration(live.capturedAt - partial.timestamp);
        lines.push(`## Assistant (in flight, not persisted) · started ${formatDumpTime(partial.timestamp)} (${elapsed} before capture)\n`);
        appendAssistantContent(lines, partial.content);
        if (partial.content.length === 0)
            lines.push("(no content streamed yet)");
        lines.push("");
        return;
    }
    if (!live.busy || live.pendingToolCalls.length > 0)
        return;
    // Request sent, no message_start yet: measure from the last persisted message.
    const last = messages.at(-1);
    const since = last && "timestamp" in last && typeof last.timestamp === "number" ? last.timestamp : undefined;
    lines.push("## Assistant (in flight, not persisted)\n");
    lines.push(since === undefined
        ? "Request in flight; no response events received yet."
        : `Request in flight; no response events received in ${formatDuration(live.capturedAt - since)} since the last persisted message.`);
    lines.push("");
}
/**
 * Format one persisted subagent transcript. Subagent system prompts and tool
 * inventories are not persisted, so the header carries only model, thinking
 * level, whether the agent was killed, and — for agents still live in this
 * process — their runtime state plus the unpersisted in-flight turn.
 */
export function formatSubagentDumpText(subagent) {
    const lines = [`# Subagent: ${subagent.key}\n`, `Model: ${subagent.model ?? "(unknown)"}`];
    if (subagent.thinkingLevel)
        lines.push(`Thinking Level: ${subagent.thinkingLevel}`);
    if (subagent.aborted)
        lines.push("Status: aborted");
    if (subagent.live)
        appendLiveHeader(lines, subagent.live);
    lines.push("\n");
    appendMarkdownTranscript(lines, subagent.messages);
    if (subagent.live)
        appendInFlightTurn(lines, subagent.live, subagent.messages);
    return lines.join("\n").trim();
}
/** Lines describing a `/dump all` archive: path, members, and any subagent discovery failure. */
export function formatDumpArchiveReport(archive) {
    const fileCount = archive.files.length;
    const subCount = archive.subagentCount;
    const lines = [
        `Session dump archive: ${archive.path}`,
        `Contains ${fileCount} file${fileCount === 1 ? "" : "s"} (${subCount} subagent transcript${subCount === 1 ? "" : "s"}):`,
        ...archive.files.map(file => `  ${file}`),
    ];
    if (archive.subagentError)
        lines.push(`Subagent transcripts unavailable: ${archive.subagentError}`);
    for (const [member, skipped] of archive.malformed ?? []) {
        lines.push(`Skipped ${skipped} malformed record${skipped === 1 ? "" : "s"} in ${member}`);
    }
    for (const member of archive.unreadable ?? [])
        lines.push(`Not exported (no readable session header): ${member}`);
    lines.push(archive.anonymized
        ? ANONYMIZED_REVIEW_NOTE
        : "This archive persists on disk and may contain raw context/secrets — treat accordingly.");
    return lines;
}
