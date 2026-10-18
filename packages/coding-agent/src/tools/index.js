import { logger } from "@rva/utils";
import { EditTool } from "../edit";
import { checkPythonKernelAvailability } from "../eval/py/kernel";
import { GoalTool } from "../goals/tools/goal-tool";
import { LspTool } from "../lsp";
import { MEMORY_BACKEND_TOOL_NAMES } from "../memory-backend/tool-names";
import { TaskTool } from "../task";
import { canSpawnAtDepth } from "../task/types";
import { WebSearchTool } from "../web/search";
import { AskTool } from "./ask";
import { AstEditTool } from "./ast-edit";
import { AstGrepTool } from "./ast-grep";
import { BashTool } from "./bash";
import { normalizeToolNames } from "./builtin-names";
import { CheckpointTool, RewindTool } from "./checkpoint";
import { ContextNotesTool, NewContextTool } from "./context-notes";
import { DebugTool } from "./debug";
import { cfgIdaAvailable } from "../ida/install";
import { EvalTool } from "./eval";
import { resolveEvalBackends } from "./eval-backends";
import { GithubTool } from "./gh";
import { GlobTool } from "./glob";
import { GrepTool } from "./grep";
import { IdaTool } from "./ida";
import { isIrcEnabled } from "../irc/messaging";
import { FindTool, isFindEnabled } from "./jfind";
import { LearnTool } from "./learn";
import { ManageSkillTool } from "./manage-skill";
import { MemoryEditTool } from "./memory-edit";
import { MemoryRecallTool } from "./memory-recall";
import { MemoryReflectTool } from "./memory-reflect";
import { MemoryRetainTool } from "./memory-retain";
import { wrapToolWithMetaNotice } from "./output-meta";
import { ReadTool } from "./read";
import { SecurityScanTool } from "./security-scan";
import { supportsExternalThinking, ThinkTool } from "./think";
import { TodoTool } from "./todo";
import { WriteTool } from "./write";
import { WaitTool } from "./wait";
import { WasmInspectTool } from "./wasm-inspect";
import { R2InspectTool } from "./r2-inspect";
import { DotnetInspectTool } from "./dotnet-inspect";
import { GhidraInspectTool } from "./ghidra-inspect";
import { DroidascTool } from "./droidasc";
import { AdbObserveTool } from "./adb-observe";
import { FridaTool } from "./frida";
import { FridaSessionTool } from "./frida-session";
import { WebSocketObserveTool } from "./websocket-observe";
import { WindowsObserveTool } from "./windows-observe";
import { TriageTool } from "./triage";
import { EvidenceTool } from "./evidence";
import { JavascriptApplicationTool } from "./javascript-application";
import { JsHookPresetTool } from "./js-hook-preset";
import { SourcemapInspectTool } from "./sourcemap-inspect";
import { PcapInspectTool } from "./pcap-inspect";
import { SqliteInspectTool } from "./sqlite-inspect";
import { FirmwareInspectTool } from "./firmware-inspect";
import { CrashdumpInspectTool } from "./crashdump-inspect";
import { BinaryMetadataInspectTool } from "./binary-metadata-inspect";
import { EvmInspectTool } from "./evm-inspect";
import { BinaryDiffTool } from "./binary-diff";
import { ReverseWorkflowTool } from "./reverse-workflow";
import { ReverseRuntimeSessionTool } from "./reverse-runtime-session";
import { isMountableUnderXdev, resolveXdevTool } from "./xdev";
import { YieldTool } from "./yield";
import { cfgAskEnabled, cfgAstEditEnabled, cfgAstGrepEnabled, cfgAsyncEnabled, cfgCheckpointEnabled, cfgDebugEnabled, cfgGithubEnabled, cfgGlobEnabled, cfgGrepEnabled, cfgLaunchEnabled, cfgSecurityEnabled, cfgTodoEnabled, cfgToolsXdev, cfgWebSearchEnabled, } from "./settings";
import { cfgAutolearnEnabled } from "../autolearn/settings";
import { cfgBashEnabled } from "../exec/settings";
import { cfgCompactionExperimentalContextManagement } from "../session/context-settings";
import { cfgPythonInterpreter } from "../eval/settings";
import { cfgExternalThinking } from "../session/settings";
import { cfgGoalEnabled } from "../goals/settings";
import { cfgLspEnabled } from "../lsp/settings";
import { cfgMemoryBackend } from "../memory-backend/settings";
import { cfgTaskMaxRecursionDepth } from "../task/settings";
export * from "../edit";
export * from "../goals";
export * from "../lsp";
export * from "@rva/tui/tools/streaming-output";
export * from "../task";
export * from "../web/search";
export * from "./ask";
export * from "./ast-edit";
export * from "./ast-grep";
export * from "./bash";
export * from "./browser";
export * from "./checkpoint";
export * from "./computer";
export * from "./computer/supervisor";
export * from "./context-notes";
export * from "./debug";
export * from "./ida";
export * from "./essential-tools";
export * from "./eval";
export * from "./eval-backends";
export * from "./file-mutation-queue";
export * from "./file-write-fallback";
export * from "./gh";
export * from "./glob";
export * from "./grep";
export * from "./jfind";
export * from "./image-gen";
export * from "./learn";
export * from "./manage-skill";
export * from "./memory-edit";
export * from "./memory-recall";
export * from "./memory-reflect";
export * from "./memory-retain";
export * from "./read";
export * from "./resolve";
export * from "./security-scan";
export * from "./think";
export * from "./todo";
export * from "./tts";
export * from "./vibe";
export * from "./wait";
export * from "./wasm-inspect";
export * from "./r2-inspect";
export * from "./dotnet-inspect";
export * from "./ghidra-inspect";
export * from "./droidasc";
export * from "./adb-observe";
export * from "./frida";
export * from "./frida-session";
export * from "./websocket-observe";
export * from "./windows-observe";
export * from "./triage";
export * from "./evidence";
export * from "./javascript-application";
export * from "./js-hook-preset";
export * from "./sourcemap-inspect";
export * from "./pcap-inspect";
export * from "./sqlite-inspect";
export * from "./firmware-inspect";
export * from "./crashdump-inspect";
export * from "./binary-metadata-inspect";
export * from "./evm-inspect";
export * from "./binary-diff";
export * from "./reverse-workflow";
export * from "./reverse-runtime-session";
export * from "./write";
export * from "./xdev";
export * from "./yield";
/**
 * Public callable factory map. External callers may invoke `BUILTIN_TOOLS.read(session)` or
 * `BUILTIN_TOOLS[name](session)` to construct a tool directly.
 */
export const BUILTIN_TOOLS = {
    read: s => new ReadTool(s),
    security_scan: s => new SecurityScanTool(s),
    wasm_inspect: s => new WasmInspectTool(s),
    r2_inspect: s => new R2InspectTool(s),
    dotnet_inspect: s => new DotnetInspectTool(s),
    ghidra_inspect: s => new GhidraInspectTool(s),
    droidasc: s => new DroidascTool(s),
    adb_observe: s => new AdbObserveTool(s),
    frida: s => new FridaTool(s),
    frida_session: s => new FridaSessionTool(s),
    websocket_observe: s => new WebSocketObserveTool(s),
    windows_observe: s => new WindowsObserveTool(s),
    triage: s => new TriageTool(s),
    evidence: s => new EvidenceTool(s),
    javascript_application: s => new JavascriptApplicationTool(s),
    js_hook_preset: s => new JsHookPresetTool(s),
    sourcemap_inspect: s => new SourcemapInspectTool(s),
    pcap_inspect: s => new PcapInspectTool(s),
    sqlite_inspect: s => new SqliteInspectTool(s),
    firmware_inspect: s => new FirmwareInspectTool(s),
    crashdump_inspect: s => new CrashdumpInspectTool(s),
    binary_metadata_inspect: s => new BinaryMetadataInspectTool(s),
    evm_inspect: s => new EvmInspectTool(s),
    binary_diff: s => new BinaryDiffTool(s),
    reverse_workflow: s => new ReverseWorkflowTool(s),
    reverse_runtime_session: s => new ReverseRuntimeSessionTool(s),
    bash: s => new BashTool(s),
    edit: s => new EditTool(s),
    ast_grep: s => new AstGrepTool(s),
    ast_edit: s => new AstEditTool(s),
    ask: AskTool.createIf,
    debug: DebugTool.createIf,
    ida: IdaTool.createIf,
    eval: s => new EvalTool(s),
    github: GithubTool.createIf,
    glob: s => new GlobTool(s, { rootPathAlias: true }),
    grep: s => new GrepTool(s),
    find: s => new FindTool(s),
    lsp: LspTool.createIf,
    checkpoint: CheckpointTool.createIf,
    rewind: RewindTool.createIf,
    context_notes: ContextNotesTool.createIf,
    new_context: NewContextTool.createIf,
    task: s => TaskTool.create(s),
    wait: s => new WaitTool(s),
    todo: s => new TodoTool(s),
    web_search: s => new WebSearchTool(s),
    write: s => new WriteTool(s),
    memory_edit: MemoryEditTool.createIf,
    retain: MemoryRetainTool.createIf,
    recall: MemoryRecallTool.createIf,
    reflect: MemoryReflectTool.createIf,
    learn: LearnTool.createIf,
    manage_skill: ManageSkillTool.createIf,
};
export const HIDDEN_TOOLS = {
    think: () => new ThinkTool(),
    yield: s => new YieldTool(s),
    goal: s => new GoalTool(s),
};
/**
 * Built-ins whose registration follows live settings through the session's built-in
 * reconcile. Memory-backend tools other than `learn` follow `memory.backend` through
 * the memory backend's own tool replacement instead.
 */
export const SETTINGS_GATED_BUILTIN_TOOL_NAMES = Object.keys(BUILTIN_TOOLS).filter(name => name === "learn" || !MEMORY_BACKEND_TOOL_NAMES.includes(name));
/**
 * Resolve which built-in tools `session` gets for `toolNames` under the current
 * settings. Shared by {@link createTools} and the live settings reconcile so both
 * honor explicit lists, `restrictToolNames`, and task depth identically.
 */
export async function resolveBuiltinToolPlan(session, toolNames) {
    const restrictToolNames = session.restrictToolNames === true;
    const includeYield = session.requireYieldTool === true;
    const enableLsp = session.enableLsp ?? true;
    const requestedTools = restrictToolNames
        ? normalizeToolNames(toolNames ?? [])
        : toolNames
            ? normalizeToolNames(toolNames)
            : undefined;
    const goalEnabled = cfgGoalEnabled.get(session.settings);
    const goalModeActive = !restrictToolNames && goalEnabled && session.getGoalModeState?.()?.enabled === true;
    const externalThinkingActive = cfgExternalThinking.get(session.settings) && supportsExternalThinking(session.getActiveModel?.());
    if (goalModeActive && requestedTools && !requestedTools.includes("goal")) {
        requestedTools.push("goal");
    }
    const backends = resolveEvalBackends(session);
    const allowPython = backends.python;
    const allowJs = backends.js;
    const skipEvalPreflight = session.skipPythonPreflight === true;
    // Eval tool is enabled if ANY backend is reachable. JS needs no preflight, so
    // we only probe Python when JS is disabled — otherwise allowEval is
    // already true and per-backend availability is checked at first invocation.
    let pythonAvailable = true;
    const evalRequested = requestedTools === undefined || requestedTools.includes("eval");
    if (!skipEvalPreflight && !allowJs && evalRequested) {
        if (allowPython) {
            const availability = await logger.time("createTools:pythonCheck", checkPythonKernelAvailability, session.cwd, cfgPythonInterpreter.get(session.settings)?.trim() || undefined);
            pythonAvailable = availability.ok;
            if (!availability.ok) {
                logger.warn("Python kernel unavailable and JS backend disabled", { reason: availability.reason });
            }
        }
    }
    const effectivePythonAllowed = allowPython && pythonAvailable;
    // Eval is exposed whenever any backend is reachable. A backend may be
    // unreachable, in which case eval dispatches exclusively to the others.
    const allowEval = effectivePythonAllowed || allowJs;
    // Checkpoint and rewind are a pair: listing one without the other strands
    // the agent (it can checkpoint but not rewind, or vice versa). Auto-include
    // the sister tool so a one-sided frontmatter `tools:` entry still works.
    // Unlike the AST/auto-learn convenience auto-includes below, this is a
    // safety pairing — it applies to restricted sessions too.
    if (requestedTools && cfgCheckpointEnabled.get(session.settings)) {
        if (requestedTools.includes("checkpoint") && !requestedTools.includes("rewind")) {
            requestedTools.push("rewind");
        }
        else if (requestedTools.includes("rewind") && !requestedTools.includes("checkpoint")) {
            requestedTools.push("checkpoint");
        }
    }
    // Auto-include AST counterparts when their text-based sibling is present.
    // Restricted callers own the active list and must not have it widened.
    if (requestedTools && !restrictToolNames) {
        if (cfgCompactionExperimentalContextManagement.get(session.settings) &&
            requestedTools.includes("read") &&
            requestedTools.includes("grep")) {
            if (!requestedTools.includes("context_notes"))
                requestedTools.push("context_notes");
            if (!requestedTools.includes("new_context"))
                requestedTools.push("new_context");
        }
        if (goalModeActive && !requestedTools.includes("goal")) {
            requestedTools.push("goal");
        }
        if (requestedTools.includes("grep") &&
            !requestedTools.includes("ast_grep") &&
            cfgAstGrepEnabled.get(session.settings)) {
            requestedTools.push("ast_grep");
        }
        if (requestedTools.includes("edit") &&
            !requestedTools.includes("ast_edit") &&
            cfgAstEditEnabled.get(session.settings)) {
            requestedTools.push("ast_edit");
        }
        if (["hindsight", "mnemopi"].includes(cfgMemoryBackend.get(session.settings))) {
            for (const name of ["recall", "retain", "reflect"]) {
                if (!requestedTools.includes(name))
                    requestedTools.push(name);
            }
        }
        if (cfgMemoryBackend.get(session.settings) === "mnemopi" && !requestedTools.includes("memory_edit")) {
            requestedTools.push("memory_edit");
        }
        if (externalThinkingActive && !requestedTools.includes("think")) {
            requestedTools.push("think");
        }
        // Auto-learn tools are gated by `autolearn.enabled` but, like the memory
        // tools above, must also be force-included into an explicit requestedTools
        // list so a restricted top-level session whose controller/guidance is
        // active still exposes the tools the nudge points at. Gated to top-level
        // (taskDepth 0): the controller only runs there, so a subagent's explicit
        // tool whitelist must never be silently widened with write-capable tools.
        if (cfgAutolearnEnabled.get(session.settings) && (session.taskDepth ?? 0) === 0) {
            if (!requestedTools.includes("manage_skill"))
                requestedTools.push("manage_skill");
            if (["hindsight", "mnemopi", "local"].includes(cfgMemoryBackend.get(session.settings)) &&
                !requestedTools.includes("learn")) {
                requestedTools.push("learn");
            }
        }
    }
    const isToolAllowed = (name) => {
        // Never in the default set. Explicitly activatable while goal.enabled and
        // no goal record exists yet — /guided-goal enables it so the agent can
        // finish the interview with `goal create`, which turns goal mode on. Once
        // a goal record exists, only an enabled goal keeps the tool: a completed
        // (exiting) or paused goal must stop advertising it on the next rebuild.
        if (name === "goal") {
            if (!goalEnabled || restrictToolNames)
                return false;
            const goalState = session.getGoalModeState?.();
            return goalState === undefined || goalState.enabled === true || goalState.goal.status === "dropped";
        }
        if (name === "lsp")
            return enableLsp && cfgLspEnabled.get(session.settings);
        if (name === "bash")
            return cfgBashEnabled.get(session.settings);
        if (name === "eval")
            return allowEval;
        if (name === "debug")
            return cfgDebugEnabled.get(session.settings);
        if (name === "ida")
            return cfgIdaAvailable.get(session.settings);
        if (name === "todo")
            return (!includeYield || session.prewalkArmed === true) && cfgTodoEnabled.get(session.settings);
        if (name === "glob")
            return cfgGlobEnabled.get(session.settings);
        if (name === "grep")
            return cfgGrepEnabled.get(session.settings);
        if (name === "find")
            return isFindEnabled(session);
        if (name === "github")
            return cfgGithubEnabled.get(session.settings);
        if (name === "ast_grep")
            return cfgAstGrepEnabled.get(session.settings);
        if (name === "ast_edit")
            return cfgAstEditEnabled.get(session.settings);
        if (name === "web_search")
            return cfgWebSearchEnabled.get(session.settings);
        if (name === "security_scan")
            return cfgSecurityEnabled.get(session.settings);
        if (name === "think")
            return externalThinkingActive;
        if (name === "ask")
            return cfgAskEnabled.get(session.settings);
        if (name === "context_notes" || name === "new_context")
            return cfgCompactionExperimentalContextManagement.get(session.settings);
        if (name === "checkpoint" || name === "rewind")
            return (cfgCheckpointEnabled.get(session.settings) &&
                ((session.taskDepth ?? 0) === 0 || requestedTools !== undefined));
        if (name === "wait") {
            return (cfgAsyncEnabled.get(session.settings) ||
                (session.enableIrc !== false && isIrcEnabled(session.settings, session.taskDepth ?? 0)) ||
                cfgLaunchEnabled.get(session.settings));
        }
        if (name === "retain" || name === "recall" || name === "reflect") {
            return ["hindsight", "mnemopi"].includes(cfgMemoryBackend.get(session.settings));
        }
        if (name === "memory_edit")
            return cfgMemoryBackend.get(session.settings) === "mnemopi";
        if (name === "manage_skill")
            return (cfgAutolearnEnabled.get(session.settings) &&
                ((session.taskDepth ?? 0) === 0 || requestedTools !== undefined));
        if (name === "learn") {
            return (cfgAutolearnEnabled.get(session.settings) &&
                ((session.taskDepth ?? 0) === 0 || requestedTools !== undefined) &&
                ["hindsight", "mnemopi", "local"].includes(cfgMemoryBackend.get(session.settings)));
        }
        if (name === "task") {
            return canSpawnAtDepth(cfgTaskMaxRecursionDepth.get(session.settings), session.taskDepth ?? 0);
        }
        return true;
    };
    if (includeYield && requestedTools && !requestedTools.includes("yield")) {
        requestedTools.push("yield");
    }
    const names = requestedTools?.filter(name => (name in BUILTIN_TOOLS || name in HIDDEN_TOOLS) && isToolAllowed(name)) ?? [
        ...Object.keys(BUILTIN_TOOLS).filter(isToolAllowed),
        ...(externalThinkingActive ? ["think"] : []),
        ...(includeYield ? ["yield"] : []),
        ...(goalModeActive ? ["goal"] : []),
    ];
    return { requestedTools, names, isAllowed: isToolAllowed };
}
/** Allocates `xd://` presentation state over the session's canonical tool map. */
export function createXdevState(session, tools, builtInNames, mountedNames = new Set()) {
    const state = {
        tools,
        mountedNames,
        builtInNames,
        isActive: name => session.isToolActive?.(name) === true,
        // Card rendering reads the same predicate as execution: mounted devices
        // plus active top-level tools, which the `write` transport also accepts.
        resolve: name => resolveXdevTool(state, name),
    };
    return state;
}
/**
 * Create tools from BUILTIN_TOOLS registry.
 */
export async function createTools(session, toolNames) {
    const restrictToolNames = session.restrictToolNames === true;
    const { requestedTools, names } = await resolveBuiltinToolPlan(session, toolNames);
    // createTools may be called more than once for the same ToolSession. A later
    // explicit (or full-set) write request is a real grant and must upgrade any
    // device-only transport left by an earlier read-only call.
    if (requestedTools === undefined || requestedTools.includes("write")) {
        session.deviceOnlyWrite = undefined;
        session.pendingFullWriteDescription = undefined;
    }
    const allTools = { ...BUILTIN_TOOLS, ...HIDDEN_TOOLS };
    const baseEntries = names.map(name => [name, allTools[name]]);
    const activeToolNames = new Set(names);
    if (session.setActiveToolNames) {
        session.setActiveToolNames(activeToolNames);
    }
    else {
        session.isToolActive = name => activeToolNames.has(name);
    }
    const baseResults = await Promise.all(baseEntries.map(async ([name, factory]) => {
        const tool = await logger.time(`createTools:${name}`, factory, session);
        return tool ? wrapToolWithMetaNotice(tool) : null;
    }));
    let tools = baseResults.filter((r) => r !== null);
    const toolRegistry = session.toolRegistry ?? new Map();
    session.toolRegistry = toolRegistry;
    const builtInNames = new Set(tools.map(tool => tool.name));
    for (const tool of tools)
        toolRegistry.set(tool.name, tool);
    const xdevRequested = !restrictToolNames && cfgToolsXdev.get(session.settings);
    // xd:// mounting rides the write tool as its execution transport, so a
    // session whose explicit tool list grants `read` but omits `write` would
    // allocate no xd:// state and expose every later-registered MCP/extension
    // tool top-level with its full schema on every request — the opposite of
    // the intended restriction, and enough to overflow narrow provider context
    // windows on MCP-heavy sessions. Grant a device-only `write` instead:
    // `write xd://<tool>` dispatches mounted devices while filesystem writes
    // outside the local:// session scratch stay rejected (enforced by WriteTool
    // via `session.deviceOnlyWrite`). Mounted tools gain no capability: without
    // mounting, they were already presented — and callable — top-level.
    if (xdevRequested &&
        requestedTools !== undefined &&
        !tools.some(tool => tool.name === "write") &&
        tools.some(tool => tool.name === "read")) {
        session.deviceOnlyWrite = true;
        const writeTool = await logger.time("createTools:write:xdev-transport", BUILTIN_TOOLS.write, session);
        if (writeTool) {
            const wrapped = wrapToolWithMetaNotice(writeTool);
            tools.push(wrapped);
            toolRegistry.set(wrapped.name, wrapped);
            builtInNames.add(wrapped.name);
        }
        else {
            session.deviceOnlyWrite = undefined;
        }
    }
    // Ordinary sessions use xd:// for discoverable built-ins, custom tools, and
    // MCP tools. Structured children must expose only their host-provided names,
    // so never allocate a registry that later SDK assembly could populate.
    // Explicitly requested built-ins retain their top-level presentation.
    const xdevEnabled = xdevRequested && tools.some(tool => tool.name === "write");
    const mountBuiltinTools = requestedTools === undefined;
    if (xdevEnabled) {
        const mountedNames = new Set();
        const kept = [];
        for (const tool of tools) {
            const mountable = mountBuiltinTools && isMountableUnderXdev(tool) && tool.name in BUILTIN_TOOLS;
            if (mountable)
                mountedNames.add(tool.name);
            else
                kept.push(tool);
        }
        session.xdev = createXdevState(session, toolRegistry, builtInNames, mountedNames);
        tools = kept;
    }
    // Staged previews from deferrable tools (e.g. ast_edit) resolve through a
    // `write` to xd://resolve/reject, so retain write whenever one can stage.
    const xdevMounted = (session.xdev?.mountedNames.size ?? 0) > 0;
    if (!restrictToolNames &&
        tools.some(tool => tool.deferrable === true) &&
        !tools.some(tool => tool.name === "write")) {
        const writeTool = await logger.time("createTools:write", BUILTIN_TOOLS.write, session);
        if (writeTool) {
            const wrapped = wrapToolWithMetaNotice(writeTool);
            tools.push(wrapped);
            toolRegistry.set(wrapped.name, wrapped);
            builtInNames.add(wrapped.name);
        }
    }
    if (!restrictToolNames && xdevMounted && !tools.some(tool => tool.name === "read")) {
        const readTool = await logger.time("createTools:read", BUILTIN_TOOLS.read, session);
        if (readTool) {
            const wrapped = wrapToolWithMetaNotice(readTool);
            tools.push(wrapped);
            toolRegistry.set(wrapped.name, wrapped);
            builtInNames.add(wrapped.name);
        }
    }
    if (xdevEnabled) {
        const finalActiveNames = new Set(tools.map(tool => tool.name));
        if (session.setActiveToolNames)
            session.setActiveToolNames(finalActiveNames);
        else
            session.isToolActive = name => finalActiveNames.has(name);
    }
    return tools;
}
// Issue #12680: extensions that shadow the built-in ask tool reach the native
// renderer through the injected pi.pi namespace (the root barrel of this
// package). Re-export it so the pi-tui renderer migration doesn't drop it.
export { askToolRenderer } from "@rva/tui/tools/ask";
