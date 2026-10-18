import * as fs from "node:fs";
import { InternalUrlRouter } from "../../internal-urls/router";
import { extractUriScheme } from "../../internal-urls/parse";
import { resolveToCwd, splitPathAndSelPreferringLiteralSync } from "../../tools/path-utils";
import { canonicalizeMessage } from "@rva/tui/chat/thinking-display";
const ACP_TEXT_LIMIT = 4000;
/** Declared spec of the registered scheme a `write` call targets; undefined for file paths and other tools. */
function writeTargetSpec(toolName, args) {
    if (toolName !== "write")
        return undefined;
    const path = extractStringProperty(args, "path");
    if (!path)
        return undefined;
    const router = InternalUrlRouter.instance();
    const scheme = extractUriScheme(path);
    return scheme && router.canHandle(path) ? router.spec(scheme) : undefined;
}
/** Peer-to-peer messages (coordination-scoped writes) stay off the external ACP session stream. */
function isInternalAgentMessageTool(toolName, args) {
    return writeTargetSpec(toolName, args)?.write?.scope === "coordination";
}
export function mapToolKind(toolName, args) {
    // A device write (xd:// tool dispatch, proc:// control) executes something —
    // "edit" would make ACP clients render it as a file modification to a
    // nonexistent path (and auto-approve it under edit-tier policies). Reads
    // stay "read": listing devices or fetching docs is discovery.
    if (writeTargetSpec(toolName, args)?.backing === "device")
        return "execute";
    switch (toolName) {
        case "read":
            return "read";
        case "write":
        case "edit":
            return "edit";
        case "delete":
            return "delete";
        case "move":
            return "move";
        case "bash":
        case "shell":
        case "exec":
        case "eval":
            return "execute";
        case "grep":
        case "glob":
        case "ast_grep":
            return "search";
        case "web_search":
            return "fetch";
        case "todo":
            return "think";
        default:
            return "other";
    }
}
export function mapAgentSessionEventToAcpSessionUpdates(event, sessionId, options = {}) {
    switch (event.type) {
        case "message_update":
            return mapAssistantMessageUpdate(event, sessionId, options);
        case "message_end":
            return mapAssistantMessageEnd(event, sessionId, options);
        case "tool_execution_start": {
            if (isInternalAgentMessageTool(event.toolName, event.args))
                return [];
            const update = buildToolCallStartUpdate({
                toolCallId: event.toolCallId,
                toolName: event.toolName,
                args: event.args,
                intent: event.intent,
                cwd: options.cwd,
            });
            return [toSessionNotification(sessionId, update)];
        }
        case "tool_execution_update": {
            if (isInternalAgentMessageTool(event.toolName, event.args))
                return [];
            const content = mergeToolUpdateContent(buildToolStartContent(event.toolName, event.args), extractToolCallContent(event.partialResult, options));
            const update = {
                sessionUpdate: "tool_call_update",
                toolCallId: event.toolCallId,
                status: toolUpdateStatus(event.partialResult),
                rawOutput: event.partialResult,
            };
            if (content.length > 0) {
                update.content = content;
            }
            const locations = extractToolLocations(event.args, options.cwd, event.toolName);
            if (locations.length > 0) {
                update.locations = locations;
            }
            return [toSessionNotification(sessionId, update)];
        }
        case "tool_execution_end": {
            const args = getToolExecutionEndArgs(event, options);
            if (isInternalAgentMessageTool(event.toolName, args))
                return [];
            const resultContent = [
                ...extractDiffToolCallContent(event.result),
                ...extractToolCallContent(event.result, options),
            ];
            const content = mergeToolUpdateContent(buildToolStartContent(event.toolName, args), resultContent);
            const update = {
                sessionUpdate: "tool_call_update",
                toolCallId: event.toolCallId,
                status: event.isError ? "failed" : "completed",
                rawOutput: event.result,
            };
            if (content.length > 0) {
                update.content = content;
            }
            const locations = extractToolLocationsFromResult(event.result, options.cwd);
            if (locations.length > 0) {
                update.locations = locations;
            }
            const notifications = [toSessionNotification(sessionId, update)];
            const planUpdate = mapTodoResultToPlanUpdate(event);
            if (planUpdate) {
                notifications.push(toSessionNotification(sessionId, planUpdate));
            }
            return notifications;
        }
        case "todo_reminder": {
            const entries = event.todos.map(todo => ({
                content: todo.content,
                priority: "medium",
                status: mapTodoStatus(todo.status),
            }));
            return [toSessionNotification(sessionId, { sessionUpdate: "plan", entries })];
        }
        case "todo_auto_clear":
            return [toSessionNotification(sessionId, { sessionUpdate: "plan", entries: [] })];
        default:
            return [];
    }
}
function mapAssistantMessageUpdate(event, sessionId, options) {
    if (!isAssistantMessage(event.message)) {
        return [];
    }
    let sessionUpdate;
    let text;
    const progress = options.getMessageProgress?.(event.message);
    switch (event.assistantMessageEvent.type) {
        case "image_end":
            return [
                toSessionNotification(sessionId, {
                    sessionUpdate: "agent_message_chunk",
                    content: event.assistantMessageEvent.content,
                    messageId: options.getMessageId?.(event.message),
                }),
            ];
        case "text_delta":
            sessionUpdate = "agent_message_chunk";
            text = event.assistantMessageEvent.delta;
            if (text.length > 0 && progress) {
                progress.textEmitted = true;
            }
            break;
        case "thinking_delta": {
            const block = event.assistantMessageEvent.partial?.content?.[event.assistantMessageEvent.contentIndex];
            if (block?.type === "thinking" && !canonicalizeMessage(block.thinking))
                return [];
            sessionUpdate = "agent_thought_chunk";
            text = event.assistantMessageEvent.delta;
            if (text.length > 0 && progress) {
                progress.thoughtEmitted = true;
            }
            break;
        }
        case "done":
            if (progress?.textEmitted) {
                return [];
            }
            sessionUpdate = "agent_message_chunk";
            text = extractAssistantMessageText(event.assistantMessageEvent.message);
            if (text.length > 0 && progress) {
                progress.textEmitted = true;
            }
            break;
        case "error":
            sessionUpdate = "agent_message_chunk";
            text = event.assistantMessageEvent.error.errorMessage ?? "Unknown error";
            // The surfaced error is the message's visible text: keeps the
            // message_end / agent_end fallbacks from emitting again.
            if (text.length > 0 && progress) {
                progress.textEmitted = true;
            }
            break;
        default:
            return [];
    }
    if (text.length === 0) {
        return [];
    }
    const messageId = options.getMessageId?.(event.message);
    return [
        toSessionNotification(sessionId, {
            sessionUpdate,
            content: { type: "text", text },
            messageId,
        }),
    ];
}
function mapAssistantMessageEnd(event, sessionId, options) {
    if (!isAssistantMessage(event.message)) {
        return [];
    }
    const progress = options.getMessageProgress?.(event.message);
    if (!progress || progress.textEmitted) {
        return [];
    }
    const text = extractAssistantMessageText(event.message);
    if (text.length === 0) {
        return [];
    }
    progress.textEmitted = true;
    const messageId = options.getMessageId?.(event.message);
    return [
        toSessionNotification(sessionId, {
            sessionUpdate: "agent_message_chunk",
            content: { type: "text", text },
            messageId,
        }),
    ];
}
function toSessionNotification(sessionId, update) {
    return { sessionId, update };
}
const todoStatusMap = {
    pending: "pending",
    in_progress: "in_progress",
    completed: "completed",
    abandoned: "completed",
    blocked: "pending",
};
function mapTodoStatus(status) {
    return todoStatusMap[status];
}
function mapTodoResultToPlanUpdate(event) {
    if (event.toolName !== "todo" || event.isError) {
        return undefined;
    }
    const phases = extractTodoPhases(event.result);
    if (!Array.isArray(phases)) {
        return undefined;
    }
    return {
        sessionUpdate: "plan",
        entries: extractTodoEntries(phases).map(todo => ({
            content: todo.content,
            priority: "medium",
            status: mapTodoStatus(todo.status),
        })),
    };
}
function extractTodoPhases(result) {
    if (typeof result !== "object" || result === null || !("details" in result)) {
        return undefined;
    }
    const details = result.details;
    if (typeof details !== "object" || details === null || !("phases" in details)) {
        return undefined;
    }
    return details.phases;
}
function extractTodoEntries(phases) {
    const entries = [];
    for (const phase of phases) {
        if (typeof phase !== "object" || phase === null || !("tasks" in phase)) {
            continue;
        }
        const tasks = phase.tasks;
        if (!Array.isArray(tasks)) {
            continue;
        }
        for (const task of tasks) {
            if (typeof task !== "object" || task === null || !("content" in task)) {
                continue;
            }
            const content = task.content;
            if (typeof content !== "string" || content.length === 0) {
                continue;
            }
            const status = task.status;
            entries.push({ content, status: isTodoStatus(status) ? status : "pending" });
        }
    }
    return entries;
}
function isTodoStatus(status) {
    return (status === "pending" ||
        status === "in_progress" ||
        status === "completed" ||
        status === "abandoned" ||
        status === "blocked");
}
export function buildToolCallStartUpdate(input) {
    const update = {
        sessionUpdate: "tool_call",
        toolCallId: input.toolCallId,
        title: buildToolTitle(input.toolName, input.args, input.intent),
        kind: mapToolKind(input.toolName, input.args),
        status: input.status ?? "pending",
        rawInput: input.args,
    };
    const content = buildToolStartContent(input.toolName, input.args);
    if (content.length > 0) {
        update.content = content;
    }
    const locations = extractToolLocations(input.args, input.cwd, input.toolName);
    if (locations.length > 0) {
        update.locations = locations;
    }
    return update;
}
export function normalizeReplayToolArguments(value) {
    if (typeof value !== "string") {
        return { args: value ?? {} };
    }
    try {
        const parsed = JSON.parse(value);
        return { args: parsed };
    }
    catch {
        return { args: value };
    }
}
function getToolExecutionEndArgs(event, options) {
    if ("args" in event) {
        return event.args;
    }
    return options.getToolArgs?.(event.toolCallId);
}
function buildToolStartContent(toolName, args) {
    const text = buildToolStartText(toolName, args);
    return text ? [textToolCallContent(text)] : [];
}
function buildToolStartText(toolName, args) {
    if (isCommandToolName(toolName)) {
        const command = extractStringProperty(args, "command");
        return command ? limitText(`$ ${command}`) : undefined;
    }
    if (toolName === "eval") {
        return buildEvalStartText(args);
    }
    return undefined;
}
function buildEvalStartText(args) {
    if (typeof args !== "object" || args === null || Array.isArray(args)) {
        return undefined;
    }
    const container = args;
    const cells = Array.isArray(container.cells)
        ? container.cells
        : typeof container.code === "string"
            ? [container]
            : [];
    if (cells.length === 0) {
        return undefined;
    }
    const lines = [];
    for (const cell of cells) {
        if (typeof cell !== "object" || cell === null || Array.isArray(cell)) {
            continue;
        }
        const language = extractStringProperty(cell, "language") ?? "?";
        const title = extractStringProperty(cell, "title");
        const code = extractStringProperty(cell, "code");
        if (!code) {
            continue;
        }
        lines.push(title ? `[${language}] ${title}` : `[${language}]`, code);
    }
    return lines.length > 0 ? limitText(lines.join("\n")) : undefined;
}
function mergeToolUpdateContent(startContent, resultContent) {
    if (startContent.length === 0) {
        return resultContent;
    }
    const merged = [...startContent];
    for (const item of resultContent) {
        if (item.type === "content" &&
            item.content.type === "text" &&
            hasEquivalentTextContent(merged, item.content.text)) {
            continue;
        }
        merged.push(item);
    }
    return merged;
}
function isCommandToolName(toolName) {
    return toolName === "bash" || toolName === "shell" || toolName === "exec";
}
function buildToolTitle(toolName, args, intent) {
    if (isCommandToolName(toolName)) {
        const commandText = buildToolStartText(toolName, args);
        if (commandText)
            return commandText;
    }
    if (toolName === "eval") {
        const evalText = buildEvalStartText(args);
        if (evalText)
            return evalText;
    }
    const trimmedIntent = intent?.trim();
    if (trimmedIntent) {
        return trimmedIntent;
    }
    const subject = extractStringProperty(args, "path") ??
        extractStringProperty(args, "command") ??
        extractStringProperty(args, "pattern") ??
        extractStringProperty(args, "query");
    if (subject) {
        // Internal URLs (xd://github, skill://react, …) name their target fully;
        // prefixing the transport tool reads as a file write to a fake path.
        if (INTERNAL_URL_SUBJECT.test(subject))
            return subject;
        return `${toolName}: ${subject}`;
    }
    return toolName;
}
/**
 * Resolve a single raw path against cwd for an ACP location. When `cwd` is
 * omitted we pass the value through unchanged (callers without session
 * context, e.g. some legacy entry points and tests); the ACP-side caller
 * always supplies cwd so notifications carry absolute paths.
 */
function toAcpLocationPath(value, cwd) {
    if (!cwd)
        return value;
    try {
        return resolveToCwd(value, cwd);
    }
    catch {
        return value;
    }
}
/**
 * Scheme-qualified subjects (`xd://`, `skill://`, `agent://`, `https://`, …)
 * are not local files: resolving them against cwd fabricates paths like
 * `/repo/xd:/github` and makes editors focus nonexistent files.
 */
const INTERNAL_URL_SUBJECT = /^[a-z][a-z0-9+.-]*:\/\//i;
function existingFileLocationPath(raw, cwd) {
    if (!raw || INTERNAL_URL_SUBJECT.test(raw))
        return undefined;
    const resolved = toAcpLocationPath(raw, cwd);
    try {
        return fs.statSync(resolved).isFile() ? resolved : undefined;
    }
    catch {
        return undefined;
    }
}
/**
 * Return the single existing file represented by a `read` argument.
 *
 * ACP locations are editor navigation targets, not tool inputs. Read inputs may
 * name selectors, delimited paths, globs, directories, archive members, or
 * internal resources, so only a path that resolves to a regular file is safe
 * to publish. Literal selector-shaped filenames retain read-tool precedence.
 */
function readLocationBasePath(raw, cwd, toolName) {
    if (raw === undefined || toolName !== "read")
        return raw;
    if (!cwd || INTERNAL_URL_SUBJECT.test(raw))
        return undefined;
    const candidate = splitPathAndSelPreferringLiteralSync(raw, cwd).path;
    return existingFileLocationPath(candidate, cwd);
}
function extractToolLocations(args, cwd, toolName) {
    const locations = [];
    const seen = new Set();
    const pushPath = (raw) => {
        if (!raw || INTERNAL_URL_SUBJECT.test(raw))
            return;
        const path = toAcpLocationPath(raw, cwd);
        if (seen.has(path))
            return;
        seen.add(path);
        locations.push({ path });
    };
    pushPath(readLocationBasePath(extractStringProperty(args, "path"), cwd, toolName));
    pushPath(extractStringProperty(args, "oldPath"));
    pushPath(extractStringProperty(args, "newPath"));
    return locations;
}
/** Pull locations from a tool result's details (e.g. EditToolDetails.perFileResults[].path). */
function extractToolLocationsFromResult(result, cwd) {
    if (typeof result !== "object" || result === null)
        return [];
    const details = result.details;
    if (typeof details !== "object" || details === null)
        return [];
    const direct = extractToolLocations(details, cwd);
    const resolvedFile = existingFileLocationPath(extractStringProperty(details, "resolvedPath"), cwd);
    if (resolvedFile && !direct.some(location => location.path === resolvedFile)) {
        direct.push({ path: resolvedFile });
    }
    const perFile = details.perFileResults;
    if (!Array.isArray(perFile)) {
        return direct;
    }
    const seen = new Set(direct.map(loc => loc.path));
    const locations = [...direct];
    for (const entry of perFile) {
        const raw = extractStringProperty(entry, "path");
        if (!raw)
            continue;
        const path = toAcpLocationPath(raw, cwd);
        if (seen.has(path))
            continue;
        seen.add(path);
        locations.push({ path });
    }
    return locations;
}
/** Emit a `diff` ToolCallContent for each per-file edit result that carries oldText/newText. */
function extractDiffToolCallContent(result) {
    if (typeof result !== "object" || result === null)
        return [];
    const details = result.details;
    if (typeof details !== "object" || details === null)
        return [];
    const blocks = [];
    const perFile = details.perFileResults;
    const entries = Array.isArray(perFile) ? perFile : [details];
    for (const entry of entries) {
        const block = buildDiffContent(entry);
        if (block)
            blocks.push(block);
    }
    return blocks;
}
function buildDiffContent(entry) {
    if (typeof entry !== "object" || entry === null)
        return undefined;
    const candidate = entry;
    if (candidate.isError === true)
        return undefined;
    const path = typeof candidate.path === "string" && candidate.path.length > 0 ? candidate.path : undefined;
    if (!path)
        return undefined;
    const oldText = typeof candidate.oldText === "string" ? candidate.oldText : undefined;
    const newText = typeof candidate.newText === "string" ? candidate.newText : undefined;
    if (oldText === undefined && newText === undefined)
        return undefined;
    return {
        type: "diff",
        path,
        oldText: oldText ?? null,
        newText: newText ?? "",
    };
}
function extractTerminalId(value) {
    const direct = extractStringProperty(value, "terminalId");
    if (direct)
        return direct;
    if (typeof value !== "object" || value === null)
        return undefined;
    const details = value.details;
    return extractStringProperty(details, "terminalId");
}
/**
 * Status of a `tool_execution_update` frame: the settled frame of a call's
 * background job (`details.async.state` completed, failed or cancelled, sent
 * after the call returned) settles the call; any other frame is progress.
 */
function toolUpdateStatus(partialResult) {
    if (typeof partialResult !== "object" || partialResult === null)
        return "in_progress";
    const details = partialResult.details;
    if (typeof details !== "object" || details === null)
        return "in_progress";
    const state = extractStringProperty(details.async, "state");
    if (state === "completed")
        return "completed";
    return state === "failed" || state === "cancelled" ? "failed" : "in_progress";
}
function terminalToolCallContent(terminalId) {
    return { type: "terminal", terminalId };
}
function extractToolCallContent(value, options) {
    const richContent = extractStructuredToolCallContent(value, options);
    const detailsImageContent = extractDetailsImageToolCallContent(value, options, richContent);
    const combinedContent = [...richContent, ...detailsImageContent];
    const terminalId = extractTerminalId(value);
    const content = terminalId && !hasTerminalContent(combinedContent, terminalId)
        ? [...combinedContent, terminalToolCallContent(terminalId)]
        : combinedContent;
    const fallbackText = extractReadableText(value);
    if (!fallbackText) {
        return content;
    }
    if (hasEquivalentTextContent(content, fallbackText)) {
        return content;
    }
    return [...content, textToolCallContent(fallbackText)];
}
function extractStructuredToolCallContent(value, options) {
    const blocks = getContentBlocks(value);
    if (!blocks) {
        return [];
    }
    const content = [];
    for (const block of blocks) {
        const toolCallContent = toToolCallContent(block, options);
        if (toolCallContent) {
            content.push(toolCallContent);
        }
    }
    return content;
}
function getContentBlocks(value) {
    if (Array.isArray(value)) {
        return value;
    }
    if (typeof value !== "object" || value === null || !("content" in value)) {
        return undefined;
    }
    const content = value.content;
    return Array.isArray(content) ? content : undefined;
}
function toToolCallContent(value, options) {
    const type = getContentType(value);
    if (!type) {
        return undefined;
    }
    switch (type) {
        case "text": {
            const text = extractStructuredText(value);
            return text ? textToolCallContent(text) : undefined;
        }
        case "image":
        case "audio":
            return binaryToolCallContent(type, value, options);
        case "resource_link": {
            const uri = extractStringProperty(value, "uri");
            const name = extractStringProperty(value, "name");
            if (!uri || !name) {
                return undefined;
            }
            const resourceLinkContent = {
                type: "resource_link",
                uri,
                name,
            };
            const title = extractStringProperty(value, "title");
            if (title) {
                resourceLinkContent.title = title;
            }
            const description = extractStringProperty(value, "description");
            if (description) {
                resourceLinkContent.description = description;
            }
            const mimeType = extractStringProperty(value, "mimeType");
            if (mimeType) {
                resourceLinkContent.mimeType = mimeType;
            }
            const size = extractNumberProperty(value, "size");
            if (size !== undefined) {
                resourceLinkContent.size = size;
            }
            return {
                type: "content",
                content: resourceLinkContent,
            };
        }
        case "resource": {
            const resource = extractEmbeddedResource(value);
            return resource
                ? {
                    type: "content",
                    content: {
                        type: "resource",
                        resource,
                    },
                }
                : undefined;
        }
        default:
            return undefined;
    }
}
function binaryToolCallContent(type, value, options) {
    const data = extractStringProperty(value, "data");
    const mimeType = extractStringProperty(value, "mimeType");
    if (!data || !mimeType) {
        return undefined;
    }
    return {
        type: "content",
        content: {
            type,
            data: type === "image" ? (options.resolveImageData?.(data, mimeType) ?? data) : data,
            mimeType,
        },
    };
}
function extractDetailsImageToolCallContent(value, options, existing) {
    const images = extractDetailsImages(value);
    if (!images) {
        return [];
    }
    const seen = new Set(existing.map(imageContentKey).filter((key) => key !== undefined));
    const content = [];
    for (const image of images) {
        const toolCallContent = binaryToolCallContent("image", image, options);
        const key = imageContentKey(toolCallContent);
        if (!toolCallContent || !key || seen.has(key)) {
            continue;
        }
        seen.add(key);
        content.push(toolCallContent);
    }
    return content;
}
function extractDetailsImages(value) {
    if (typeof value !== "object" || value === null)
        return undefined;
    const details = value.details;
    if (typeof details !== "object" || details === null)
        return undefined;
    const images = details.images;
    return Array.isArray(images) && images.length > 0 ? images : undefined;
}
function imageContentKey(value) {
    if (value?.type !== "content" || value.content.type !== "image") {
        return undefined;
    }
    return `${value.content.mimeType}\u0000${value.content.data}`;
}
function extractEmbeddedResource(value) {
    if (typeof value !== "object" || value === null || !("resource" in value)) {
        return undefined;
    }
    const resource = value.resource;
    if (typeof resource !== "object" || resource === null) {
        return undefined;
    }
    const uri = extractStringProperty(resource, "uri");
    if (!uri) {
        return undefined;
    }
    const text = extractStringProperty(resource, "text");
    if (text) {
        const mimeType = extractStringProperty(resource, "mimeType");
        return mimeType ? { uri, text, mimeType } : { uri, text };
    }
    const blob = extractStringProperty(resource, "blob");
    if (!blob) {
        return undefined;
    }
    const mimeType = extractStringProperty(resource, "mimeType");
    return mimeType ? { uri, blob, mimeType } : { uri, blob };
}
function textToolCallContent(text) {
    return {
        type: "content",
        content: {
            type: "text",
            text,
        },
    };
}
function hasEquivalentTextContent(content, text) {
    return content.some(item => item.type === "content" && item.content.type === "text" && item.content.text === text);
}
function hasTerminalContent(content, terminalId) {
    return content.some(item => item.type === "terminal" && item.terminalId === terminalId);
}
function extractReadableText(value) {
    if (typeof value === "string") {
        return normalizeText(value);
    }
    if (value instanceof Error) {
        return normalizeText(value.message);
    }
    if (typeof value !== "object" || value === null) {
        return undefined;
    }
    const directText = extractStringProperty(value, "text") ??
        extractStringProperty(value, "errorMessage") ??
        extractStringProperty(value, "message");
    if (directText) {
        return normalizeText(directText);
    }
    const contentBlocks = getContentBlocks(value);
    if (contentBlocks) {
        const text = contentBlocks
            .map(block => extractStructuredText(block))
            .filter((chunk) => typeof chunk === "string" && chunk.length > 0)
            .join("\n");
        if (text.length > 0) {
            return normalizeText(text);
        }
        // A structured result envelope (`{ content: [...] }`) whose blocks carry no
        // plain text has nothing readable to surface, and its data already rides the
        // ACP frame as `rawOutput`. Serializing the whole envelope to JSON would just
        // render a raw blob as the tool row (e.g. wait progress, issue #9511), so
        // stop here instead of falling through to the JSON fallback.
        return undefined;
    }
    if (extractDetailsImages(value)) {
        return undefined;
    }
    if (isTerminalOnlyDetails(value)) {
        return undefined;
    }
    const serialized = safeJsonStringify(value);
    return normalizeText(serialized);
}
function isTerminalOnlyDetails(value) {
    if (typeof value !== "object" || value === null) {
        return false;
    }
    if (extractTerminalId(value) === undefined) {
        return false;
    }
    const content = value.content;
    return content === undefined || (Array.isArray(content) && content.length === 0);
}
export function extractAssistantMessageText(value) {
    if (typeof value !== "object" || value === null || !("content" in value)) {
        return "";
    }
    const content = value.content;
    if (!Array.isArray(content)) {
        return "";
    }
    return content
        .map(block => extractStructuredText(block))
        .filter((chunk) => typeof chunk === "string" && chunk.length > 0)
        .join("\n");
}
function extractStructuredText(value) {
    const text = extractStringProperty(value, "text");
    if (!text) {
        return undefined;
    }
    return limitText(text);
}
function getContentType(value) {
    if (typeof value !== "object" || value === null || !("type" in value)) {
        return undefined;
    }
    const type = value.type;
    return typeof type === "string" ? type : undefined;
}
function extractStringProperty(value, key) {
    if (typeof value !== "object" || value === null || !(key in value)) {
        return undefined;
    }
    const property = value[key];
    return typeof property === "string" && property.length > 0 ? property : undefined;
}
function extractNumberProperty(value, key) {
    if (typeof value !== "object" || value === null || !(key in value)) {
        return undefined;
    }
    const property = value[key];
    return typeof property === "number" && Number.isFinite(property) ? property : undefined;
}
function isAssistantMessage(value) {
    return (typeof value === "object" && value !== null && "role" in value && value.role === "assistant");
}
function normalizeText(text) {
    if (!text) {
        return undefined;
    }
    const normalized = text.trim();
    return normalized.length > 0 ? limitText(normalized) : undefined;
}
function limitText(text) {
    return text.length > ACP_TEXT_LIMIT ? `${text.slice(0, ACP_TEXT_LIMIT - 1)}…` : text;
}
function safeJsonStringify(value) {
    try {
        return JSON.stringify(value);
    }
    catch {
        return undefined;
    }
}
