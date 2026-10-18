/**
 * `xd://` virtual tool devices.
 *
 * Discoverable built-ins and custom tools are unmounted from the request's
 * tools array and exposed as internal URLs driven through the `read`/`write`
 * tools the model already has:
 *
 *   read  xd://          → mounted tool listing (discovery)
 *   read  xd://<tool>    → tool docs + JSON parameter schema
 *   write xd://<tool>    → execute: `content` is the JSON args object
 *
 * Direct and device dispatch share one canonical tool map. The mounted-name
 * set controls presentation only; dispatch accepts the enabled union of
 * top-level active and mounted names. Listing and prompt docs stay
 * mounted-only because top-level tools already ship their schemas.
 *
 * Args go through the same machinery as native tool calls: validated with
 * pi-ai's `validateToolArguments` (the schema is returned on mismatch, so a
 * malformed call self-corrects without a round trip) and streamed through
 * the write tool's existing incremental `content` decoding for live render
 * previews. Compared to a dispatcher def this still costs zero *schema
 * duplication* — one wire schema per tool instead of one per dispatcher
 * branch — but full docs + schema for every mounted device can be inlined
 * into the system prompt, so no discovery read is needed before first use;
 * `read xd://<tool>` remains for on-demand re-fetch.
 *
 * Rendering: the write renderer draws NOTHING until the streamed `path` is
 * known and provably does not target `xd://`. Device writes then show as
 * queued/planning until `tool_execution_start`, and only then delegate to the
 * wrapped tool's own renderer with the decoded inner args.
 */
import { validateAgentToolArguments, } from "@rva/agent";
import { jsonSchemaToTypeScript, toolWireSchema } from "@rva/ai";
import { schemaDeclaresIntentField } from "../utils/tool-schema";
import { stripXdUrlPrefix, XD_URL_PREFIX } from "@rva/tui/tools/xd-url";
import { truncateHeadBytes } from "@rva/tui/tools/streaming-output";
import { resolveToolTier } from "./approval";
import { renderError, ToolAbortError } from "./tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
/**
 * Discoverable built-ins that must stay top-level even when xdev mounting is
 * active: `todo` feeds the todo prelude/prewalk machinery, `ask` is the
 * model's user-interaction affordance, `grep` is the redirect target of the
 * bash interceptor rules, and `web_search` is invoked directly by most models
 * (which have no notion of the `xd://` protocol) so hiding it behind dispatch
 * makes it unreachable in practice (issue #5973). `yield` terminates structured
 * subagent runs and must stay directly callable — each loses its harness
 * integration or usability if hidden behind dispatch.
 */
export const XDEV_KEEP_TOP_LEVEL = {
    todo: true,
    yield: true,
    ask: true,
    grep: true,
    web_search: true,
};
/**
 * Tools that carry the `xd://` transport itself and therefore can never be
 * mounted as devices: `read xd://` lists/documents devices and
 * `write xd://<tool>` executes them. Demoting either leaves every mounted
 * device unreachable (issue #5764), so they stay top-level regardless of a
 * declared `loadMode`.
 */
export const XDEV_TRANSPORT_TOOLS = { read: true, write: true };
/**
 * Whether an enabled tool is presented under `xd://` (rather than top-level)
 * while the `xd://` transport is active. Discoverable tools mount unless they
 * are pinned top-level by {@link XDEV_KEEP_TOP_LEVEL} or carry the transport
 * itself ({@link XDEV_TRANSPORT_TOOLS}); essential tools never do. The caller
 * gates this on the transport being active.
 */
export function isMountableUnderXdev(tool) {
    if (tool.name in XDEV_TRANSPORT_TOOLS || tool.name in XDEV_KEEP_TOP_LEVEL)
        return false;
    return tool.loadMode === "discoverable";
}
function renderDocs(inst, heading = "#", descriptionCap) {
    const schema = jsonSchemaToTypeScript(toolWireSchema(inst));
    let description = inst.description ?? "";
    if (descriptionCap !== undefined && description.length > descriptionCap) {
        description = `${description.slice(0, descriptionCap).trimEnd()}… (full docs: read ${XD_URL_PREFIX}${inst.name})`;
    }
    return [
        `${heading} ${inst.name}${inst.label ? ` — ${inst.label}` : ""}`,
        "",
        description,
        "",
        `${heading}# Schema`,
        "```ts",
        `type Args = ${schema};`,
        "```",
        `Execute by writing JSON to ${XD_URL_PREFIX}${inst.name}.`,
    ].join("\n");
}
/**
 * Parse and validate a device write's JSON `content` against the wrapped
 * tool's wire schema. Strips a habitual top-level `i` (intent) unless the
 * schema declares one. Throws ToolError; schema-mismatch errors carry `docs()`
 * for repair. A device with `lenientArgValidation` receives the raw args on a
 * schema mismatch instead — the same contract the agent loop and the eval
 * tool bridge honor (`AgentTool.lenientArgValidation`) — so a tool that owns
 * its own refusal/repair (e.g. `todo` inferring an omitted `op`) is never
 * pre-empted by the host's generic wording plus the full docs. Lenience covers
 * schema mismatch only: malformed JSON and non-object content still throw.
 * Content is a model-written payload, so lenience strips forged
 * `__parseError`/`__rawJson` sentinels (see `validateAgentToolArguments`).
 */
function parseDeviceArgs(device, content, toolCallId, docs) {
    let parsed;
    try {
        parsed = JSON.parse(content);
    }
    catch (error) {
        throw new ToolError(`${XD_URL_PREFIX}${device.name} expects a JSON args object as content (${error instanceof Error ? error.message : String(error)}). Write \`?\` for docs.`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new ToolError(`${XD_URL_PREFIX}${device.name} content must be a JSON object, got ${Array.isArray(parsed) ? "array" : typeof parsed}.`);
    }
    // The harness only injects the intent field into top-level schemas; strip a
    // habitual `i` from inner args unless the wrapped schema really declares it.
    const args = { ...parsed };
    if ("i" in args && !schemaDeclaresIntentField(toolWireSchema(device)))
        delete args.i;
    try {
        return validateAgentToolArguments(device, { type: "toolCall", id: toolCallId, name: device.name, arguments: args }, "payload");
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new ToolError(`Invalid args for ${XD_URL_PREFIX}${device.name}: ${message}\n\n${docs()}`);
    }
}
/** One-line catalog summary for a mounted tool: `summary`, else first description line. */
function toolSummary(inst) {
    if (inst.summary)
        return inst.summary;
    const firstLine = (inst.description ?? "").split("\n").find(line => line.trim().length > 0);
    return firstLine?.trim() ?? inst.label ?? inst.name;
}
/** C0/C1 controls and Unicode line/paragraph separators; summaries must remain one line. */
const SUMMARY_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g;
const SUMMARY_ELLIPSIS = "…";
const SUMMARY_ELLIPSIS_BYTES = Buffer.byteLength(SUMMARY_ELLIPSIS, "utf-8");
/**
 * Bound a catalog summary for prompt rendering. External summaries are
 * third-party metadata inlined verbatim, so control characters are stripped
 * first, then the result is bounded in UTF-8 BYTES rather than characters (a
 * character bound is not a byte bound for multi-byte scripts). The cut lands
 * on a code point boundary, so the prompt never carries a partial code point.
 */
function sanitizeCatalogSummary(summary, maxBytes) {
    const cleaned = summary.replace(SUMMARY_CONTROL_CHARS, " ").trim();
    if (maxBytes === undefined || Buffer.byteLength(cleaned, "utf-8") <= maxBytes)
        return cleaned;
    if (maxBytes <= 0)
        return "";
    if (maxBytes < SUMMARY_ELLIPSIS_BYTES)
        return truncateHeadBytes(cleaned, maxBytes).text;
    const body = truncateHeadBytes(cleaned, maxBytes - SUMMARY_ELLIPSIS_BYTES).text.trimEnd();
    return `${body}${SUMMARY_ELLIPSIS}`;
}
function promptCatalogSummary(inst, maxBytes) {
    const summary = toolSummary(inst)
        .split("\n")
        .find(line => line.trim().length > 0)
        ?.trim() ?? inst.name;
    return sanitizeCatalogSummary(summary, maxBytes) || inst.name;
}
/** Compile the `tools.xdevInlineDevices` allowlist once per render, dropping
 *  non-string entries so malformed user config cannot break prompt builds. */
function compileInlineGlobs(patterns) {
    if (!Array.isArray(patterns))
        return [];
    const globs = [];
    for (const pattern of patterns) {
        if (typeof pattern !== "string" || pattern.length === 0)
            continue;
        globs.push(new Bun.Glob(pattern));
    }
    return globs;
}
/** Device-write content that requests docs instead of executing: empty, `?`, or `help`. */
const HELP_CONTENT_RE = /^\s*(\?|help)?\s*$/i;
/** Full-doc character budget for system-prompt mounted-device sections. */
export const XDEV_DOCS_TOTAL_BUDGET = 48000;
/** Per-device cap preventing one pathological description from starving later devices. */
export const XDEV_DOCS_PER_DEVICE_CAP = 10000;
/** Description cap for external mounted tools; their full docs remain readable on demand. */
export const XDEV_EXTERNAL_DESCRIPTION_CAP = 200;
/** Resolve any enabled tool through the canonical session map. */
export function resolveXdevTool(state, name) {
    if (!state.mountedNames.has(name) && !state.isActive(name))
        return undefined;
    return state.tools.get(name);
}
/**
 * Resolve a mounted tool by name. Presentation-only: `xd://` docs and renderer
 * lookup ask for names they already hold in canonical form.
 */
export function resolveMountedXdevTool(state, name) {
    const canonicalName = stripXdUrlPrefix(name);
    return state.mountedNames.has(canonicalName) ? state.tools.get(canonicalName) : undefined;
}
/**
 * Resolve a mounted tool with its execution-only permission decorator.
 *
 * Mounted-only, matching {@link resolveMountedXdevTool}, and a published export
 * under `@rva/coding-agent/tools/xdev`, so its semantics must not
 * drift. `sdk.ts` composes this with the calling agent's advertised tools to
 * recover a Claude Code-spelled MCP name: the union has to be resolved in one
 * pass for the ambiguity rule to hold, so that composition lives with the
 * caller that knows both presentation sets rather than here.
 */
export function resolveMountedXdevExecutable(state, name) {
    const tool = resolveMountedXdevTool(state, name);
    return tool && state.decorateExecution ? state.decorateExecution(tool) : tool;
}
/** Mounted tools in presentation order, resolved from the canonical map. */
export function listXdevTools(state) {
    return [...state.mountedNames].flatMap(name => {
        const tool = state.tools.get(name);
        return tool ? [tool] : [];
    });
}
/** `{name, summary, dynamic}` triples for prompt templates and `/tools` display. */
export function xdevEntries(state) {
    return listXdevTools(state).map(tool => {
        // Built-ins are first-party; anything else carries third-party metadata. One
        // boolean drives both the description cap and the flag callers present, so
        // the two can never disagree about which summaries are untrusted.
        const dynamic = !state.builtInNames.has(tool.name);
        return {
            name: tool.name,
            summary: promptCatalogSummary(tool, dynamic ? XDEV_EXTERNAL_DESCRIPTION_CAP : undefined),
            dynamic,
        };
    });
}
/** `read xd://` listing with one device per line. */
export function xdevListing(state) {
    const rows = xdevEntries(state).map(({ name, summary }) => `${XD_URL_PREFIX}${name.padEnd(14)} ${summary}`);
    return [
        `${XD_URL_PREFIX} ${state.mountedNames.size} mounted tool devices.`,
        ...rows,
        "",
        `Read ${XD_URL_PREFIX}<tool> for docs + JSON schema; write the JSON args object to ${XD_URL_PREFIX}<tool> to execute. Active top-level tools accept the same dispatch.`,
    ].join("\n");
}
/** Docs + schema for any enabled tool. */
export function xdevDocs(state, name) {
    return renderDocs(resolveRequiredXdevTool(state, name));
}
/**
 * Place mounted devices under the configured prompt-doc policy and budgets.
 * A device the policy does not inline, or whose docs exceed a cap, becomes a
 * catalog entry.
 */
export function planXdevPromptDocs(state, mode = "inline", inlinePatterns = []) {
    const sections = [];
    const catalog = new Map();
    const inlineGlobs = compileInlineGlobs(inlinePatterns);
    let used = 0;
    for (const tool of listXdevTools(state)) {
        const descriptionCap = state.builtInNames.has(tool.name) ? undefined : XDEV_EXTERNAL_DESCRIPTION_CAP;
        if (shouldInlineXdevTool(state, tool, mode, inlineGlobs)) {
            const docs = renderDocs(tool, "##", descriptionCap);
            if (docs.length <= XDEV_DOCS_PER_DEVICE_CAP && used + docs.length <= XDEV_DOCS_TOTAL_BUDGET) {
                used += docs.length;
                sections.push(docs);
                continue;
            }
        }
        catalog.set(tool.name, promptCatalogSummary(tool, descriptionCap));
    }
    return { sections, catalog };
}
/**
 * Render planned `xd://` prompt docs. Devices in `listedElsewhere` get no
 * catalog line: the caller lists them itself, with their catalog summary.
 */
export function renderXdevPromptDocs(docs, listedElsewhere) {
    const lines = [];
    for (const [name, summary] of docs.catalog) {
        if (!listedElsewhere?.has(name))
            lines.push(`- ${XD_URL_PREFIX}${name} — ${summary}`);
    }
    if (lines.length === 0)
        return docs.sections.join("\n\n");
    const catalogSection = [
        "## Additional devices (docs on demand)",
        ...lines,
        "",
        `Read ${XD_URL_PREFIX}<tool> for full docs + JSON schema before first use.`,
    ].join("\n");
    return [...docs.sections, catalogSection].join("\n\n");
}
/** Docs + schema for mounted devices under the configured prompt-doc policy. */
export function xdevDocsAll(state, mode = "inline", inlinePatterns = []) {
    return renderXdevPromptDocs(planXdevPromptDocs(state, mode, inlinePatterns));
}
/** Docs for selected mounted devices under the configured prompt-doc policy. */
export function xdevDocsFor(state, names, mode, inlinePatterns = []) {
    const sections = [];
    const inlineGlobs = compileInlineGlobs(inlinePatterns);
    let used = 0;
    for (const name of names) {
        const tool = resolveMountedXdevTool(state, name);
        if (!tool || !shouldInlineXdevTool(state, tool, mode, inlineGlobs))
            continue;
        const descriptionCap = state.builtInNames.has(tool.name) ? undefined : XDEV_EXTERNAL_DESCRIPTION_CAP;
        const docs = renderDocs(tool, "##", descriptionCap);
        if (docs.length > XDEV_DOCS_PER_DEVICE_CAP || used + docs.length > XDEV_DOCS_TOTAL_BUDGET)
            continue;
        used += docs.length;
        sections.push(docs);
    }
    return sections.join("\n\n");
}
function shouldInlineXdevTool(state, tool, mode, inlineGlobs) {
    return (mode !== "catalog" &&
        (mode === "inline" || state.builtInNames.has(tool.name) || inlineGlobs.some(glob => glob.match(tool.name))));
}
function resolveRequiredXdevTool(state, name) {
    const inst = resolveXdevTool(state, name);
    if (!inst) {
        throw new ToolError(`No such tool: ${XD_URL_PREFIX}${name}. Mounted devices: ${[...state.mountedNames].join(", ")}. Active top-level tools are also dispatchable via ${XD_URL_PREFIX}<tool>.`);
    }
    return inst;
}
/** Execute an enabled canonical tool through `write xd://<tool>`. */
export async function dispatchXdevTool(state, name, content, toolCallId, signal, onUpdate, context) {
    let xdev = { tool: name, mode: "execute" };
    try {
        const canonical = resolveRequiredXdevTool(state, name);
        if (HELP_CONTENT_RE.test(content)) {
            return {
                result: { content: [{ type: "text", text: renderDocs(canonical) }] },
                xdev: { tool: name, mode: "help" },
            };
        }
        const validated = parseDeviceArgs(canonical, content, toolCallId, () => renderDocs(canonical));
        // Record the wrapped tool's approval tier so the prewalk coordinator can
        // tell a read-only device call (e.g. `lsp` navigation) from a real
        // workspace mutation without re-decoding the payload. Best-effort: a
        // throwing approval leaves the tier absent (prewalk then declines to
        // switch), unlike the write gate which fails closed to `exec`.
        let tier;
        try {
            tier = resolveToolTier(canonical, validated);
        }
        catch {
            tier = undefined;
        }
        xdev = { ...xdev, args: validated, tier };
        if ("mcpReadOnlyHint" in canonical && canonical.mcpReadOnlyHint === true)
            xdev.readOnlyHint = true;
        const innerOnUpdate = onUpdate
            ? partial => onUpdate({
                content: partial.content,
                details: { xdev: { ...xdev, inner: partial.details } },
                isError: partial.isError,
            })
            : undefined;
        const executable = state.decorateExecution?.(canonical) ?? canonical;
        const executionContext = context
            ? {
                ...context,
                xdevTierResolved: (effectiveTier) => {
                    xdev = { ...xdev, tier: effectiveTier };
                },
            }
            : undefined;
        const result = await executable.execute(toolCallId, validated, signal, innerOnUpdate, executionContext);
        return { result, xdev: { ...xdev, inner: result.details } };
    }
    catch (error) {
        if (error instanceof ToolAbortError ||
            signal?.aborted ||
            (error instanceof Error && error.name === "AbortError")) {
            throw error;
        }
        return {
            result: {
                content: [{ type: "text", text: renderError(error) }],
                isError: true,
            },
            xdev,
        };
    }
}
