import { formatLocation, formatSessionSnapshot } from "@rva/tui/tools/debug";
import * as fs from "node:fs/promises";
import { type } from "@rva/omptype";
import { isEnoent, prompt } from "@rva/utils";
import { dapSessionManager, getAdapterConfigs, getAvailableAdapters, resolveLaunchOverrides, selectAttachAdapter, selectLaunchAdapter, } from "../dap";
import debugDescription from "../prompts/tools/debug.md" with { type: "text" };
import { truncateForPrompt } from "./approval";
import { formatPathRelativeToCwd, resolveToCwd } from "./path-utils";
import { replaceTabs, shortenPath, TRUNCATE_LENGTHS, truncateToWidth } from "@rva/tui/render/render-utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { toolResult } from "./tool-result";
import { clampTimeout } from "./tool-timeouts";
import { cfgDebugEnabled, cfgToolsMaxTimeout } from "./settings";
/**
 * DAP debug actions that only read program state (no mutation, no execution).
 * Execution-side actions (`launch`, `attach`, `continue`, `step_*`, `pause`,
 * `evaluate`, breakpoint mutations, memory writes) are exec-tier.
 */
export const DEBUG_READONLY_ACTIONS = new Set([
    "output",
    "threads",
    "stack_trace",
    "scopes",
    "variables",
    "disassemble",
    "read_memory",
    "loaded_sources",
    "modules",
    "sessions",
]);
const debugActionSchema = type.enumerated("launch", "attach", "set_breakpoint", "remove_breakpoint", "set_instruction_breakpoint", "remove_instruction_breakpoint", "data_breakpoint_info", "set_data_breakpoint", "remove_data_breakpoint", "continue", "step_over", "step_in", "step_out", "pause", "evaluate", "stack_trace", "threads", "scopes", "variables", "disassemble", "read_memory", "write_memory", "modules", "loaded_sources", "custom_request", "output", "terminate", "sessions");
const debugSchema = type({
    action: debugActionSchema,
    "program?": type("string").describe("debug target path; Delve accepts Go package directories"),
    "args?": type("string[]").describe("program arguments"),
    "adapter?": type("string").describe("configured adapter id (gdb, lldb-dap, debugpy, dlv, rdbg, or dap.json entry)"),
    cwd: "string?",
    "file?": type("string").describe("source file"),
    "line?": type("number").describe("source line"),
    "function?": type("string").describe("function name"),
    "name?": type("string").describe("variable or data name"),
    "condition?": type("string").describe("breakpoint condition"),
    hit_condition: "string?",
    "expression?": type("string").describe("expression to evaluate"),
    "context?": type("string").describe("evaluate context: watch | repl | hover | variables | clipboard"),
    frame_id: "number?",
    "scope_id?": type("number").describe("scope variables reference"),
    "variable_ref?": type("number").describe("variable reference"),
    "pid?": type("number").describe("process id for attach"),
    "port?": type("number").describe("remote attach port"),
    "host?": type("string").describe("remote attach host"),
    "levels?": type("number").describe("max stack frames"),
    "memory_reference?": type("string").describe("memory reference or address"),
    instruction_reference: "string?",
    instruction_count: "number?",
    instruction_offset: "number?",
    "count?": type("number").describe("bytes to read"),
    "data?": type("string").describe("base64 memory payload"),
    "data_id?": type("string").describe("data breakpoint id"),
    "access_type?": "'read' | 'write' | 'readWrite'",
    "command?": type("string").describe("custom dap request command"),
    "arguments?": type({
        "[string]": "unknown",
    }).describe("custom request arguments"),
    offset: "number?",
    resolve_symbols: "boolean?",
    allow_partial: "boolean?",
    start_module: "number?",
    module_count: "number?",
    "timeout?": type("number").describe("per-request timeout seconds"),
});
function formatBreakpoints(filePath, breakpoints) {
    const lines = [`Breakpoints for ${filePath}:`];
    if (breakpoints.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const breakpoint of breakpoints) {
        lines.push(`- line ${breakpoint.line}: ${breakpoint.verified ? "verified" : "pending"}${breakpoint.condition ? ` if ${breakpoint.condition}` : ""}${breakpoint.message ? ` (${breakpoint.message})` : ""}`);
    }
    return lines.join("\n");
}
function formatFunctionBreakpoints(breakpoints) {
    const lines = ["Function breakpoints:"];
    if (breakpoints.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const breakpoint of breakpoints) {
        lines.push(`- ${breakpoint.name}: ${breakpoint.verified ? "verified" : "pending"}${breakpoint.condition ? ` if ${breakpoint.condition}` : ""}${breakpoint.message ? ` (${breakpoint.message})` : ""}`);
    }
    return lines.join("\n");
}
function formatStackFrames(frames) {
    const lines = ["Stack trace:"];
    if (frames.length === 0) {
        lines.push("(empty)");
        return lines.join("\n");
    }
    for (const frame of frames) {
        const location = frame.source?.path
            ? `${frame.source.path}:${frame.line}:${frame.column}`
            : `<unknown>:${frame.line}:${frame.column}`;
        lines.push(`- #${frame.id} ${frame.name} @ ${location}`);
    }
    return lines.join("\n");
}
function formatThreads(threads) {
    const lines = ["Threads:"];
    if (threads.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const thread of threads) {
        lines.push(`- ${thread.id}: ${thread.name}`);
    }
    return lines.join("\n");
}
function formatScopes(scopes) {
    const lines = ["Scopes:"];
    if (scopes.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const scope of scopes) {
        lines.push(`- ${scope.name}: ref=${scope.variablesReference}, expensive=${scope.expensive ? "yes" : "no"}${scope.presentationHint ? `, hint=${scope.presentationHint}` : ""}`);
    }
    return lines.join("\n");
}
function formatVariables(variables) {
    const lines = ["Variables:"];
    if (variables.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const variable of variables) {
        lines.push(`- ${variable.name} = ${variable.value}${variable.type ? ` (${variable.type})` : ""}${variable.variablesReference > 0 ? ` [ref=${variable.variablesReference}]` : ""}`);
    }
    return lines.join("\n");
}
function formatSourceLabel(source, line, column) {
    if (!source?.path && !source?.name) {
        return null;
    }
    const base = source.path ?? source.name ?? "<unknown>";
    if (line === undefined) {
        return base;
    }
    return `${base}:${line}${column !== undefined ? `:${column}` : ""}`;
}
function formatDisassembly(instructions) {
    const lines = ["Disassembly:"];
    if (instructions.length === 0) {
        lines.push("(empty)");
        return lines.join("\n");
    }
    const addressWidth = Math.max(...instructions.map(instruction => instruction.address.length));
    const bytesWidth = Math.max(...instructions.map(instruction => instruction.instructionBytes?.length ?? 0), 2);
    for (const instruction of instructions) {
        const location = formatSourceLabel(instruction.location, instruction.line, instruction.column);
        const parts = [
            instruction.address.padEnd(addressWidth),
            (instruction.instructionBytes ?? "").padEnd(bytesWidth),
            instruction.instruction,
        ];
        if (instruction.symbol) {
            parts.push(`<${instruction.symbol}>`);
        }
        if (location) {
            parts.push(`[${location}]`);
        }
        lines.push(parts
            .filter(part => part.length > 0)
            .join("  ")
            .trimEnd());
    }
    return lines.join("\n");
}
function formatMemoryRead(address, data, unreadableBytes) {
    const lines = [`Memory at ${address}:`];
    const buffer = data ? Buffer.from(data, "base64") : Buffer.alloc(0);
    if (buffer.length === 0) {
        lines.push("(no readable bytes)");
    }
    else {
        for (let offset = 0; offset < buffer.length; offset += 16) {
            const chunk = buffer.subarray(offset, offset + 16);
            const hex = Array.from(chunk, byte => byte.toString(16).padStart(2, "0")).join(" ");
            const ascii = Array.from(chunk, byte => (byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".")).join("");
            lines.push(`${(offset === 0 ? address : `+0x${offset.toString(16)}`).padEnd(18)} ${hex.padEnd(47)} |${ascii}|`);
        }
    }
    if (unreadableBytes !== undefined && unreadableBytes > 0) {
        lines.push(`Unreadable bytes: ${unreadableBytes}`);
    }
    return lines.join("\n");
}
function formatTable(headers, rows) {
    const widths = headers.map((header, index) => Math.max(header.length, ...rows.map(row => (row[index] ?? "").length)));
    const formatRow = (row) => row.map((cell, index) => (cell ?? "").padEnd(widths[index])).join("  ");
    return [formatRow(headers), formatRow(widths.map(width => "-".repeat(width))), ...rows.map(formatRow)].join("\n");
}
function formatModules(modules) {
    if (modules.length === 0) {
        return "Modules:\n(none)";
    }
    return [
        "Modules:",
        formatTable(["ID", "Name", "Path", "Symbols", "Range"], modules.map(module => [
            String(module.id),
            module.name,
            module.path ?? "",
            module.symbolStatus ?? "",
            module.addressRange ?? "",
        ])),
    ].join("\n");
}
function formatLoadedSources(sources) {
    const lines = ["Loaded sources:"];
    if (sources.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const source of sources) {
        const label = source.path ?? source.name ?? "<unknown>";
        lines.push(`- ${label}${source.sourceReference !== undefined ? ` [ref=${source.sourceReference}]` : ""}`);
    }
    return lines.join("\n");
}
function formatInstructionBreakpoints(breakpoints) {
    const lines = ["Instruction breakpoints:"];
    if (breakpoints.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const breakpoint of breakpoints) {
        const location = `${breakpoint.instructionReference}${breakpoint.offset !== undefined ? `+${breakpoint.offset}` : ""}`;
        lines.push(`- ${location}: ${breakpoint.verified ? "verified" : "pending"}${breakpoint.condition ? ` if ${breakpoint.condition}` : ""}${breakpoint.hitCondition ? ` after ${breakpoint.hitCondition}` : ""}${breakpoint.message ? ` (${breakpoint.message})` : ""}`);
    }
    return lines.join("\n");
}
function formatDataBreakpointInfo(info) {
    const lines = [`Data breakpoint info: ${info.description}`];
    lines.push(`Data ID: ${info.dataId ?? "(not available)"}`);
    if (info.accessTypes && info.accessTypes.length > 0) {
        lines.push(`Access types: ${info.accessTypes.join(", ")}`);
    }
    if (info.canPersist !== undefined) {
        lines.push(`Persistent: ${info.canPersist ? "yes" : "no"}`);
    }
    return lines.join("\n");
}
function formatDataBreakpoints(breakpoints) {
    const lines = ["Data breakpoints:"];
    if (breakpoints.length === 0) {
        lines.push("(none)");
        return lines.join("\n");
    }
    for (const breakpoint of breakpoints) {
        lines.push(`- ${breakpoint.dataId}: ${breakpoint.verified ? "verified" : "pending"}${breakpoint.accessType ? ` (${breakpoint.accessType})` : ""}${breakpoint.condition ? ` if ${breakpoint.condition}` : ""}${breakpoint.hitCondition ? ` after ${breakpoint.hitCondition}` : ""}${breakpoint.message ? ` (${breakpoint.message})` : ""}`);
    }
    return lines.join("\n");
}
function formatCustomResponse(command, body) {
    let serialized = "";
    try {
        serialized = JSON.stringify(body, null, 2) ?? "null";
    }
    catch {
        serialized = Bun.inspect(body);
    }
    return `${command} response:\n${serialized}`;
}
function formatSessions(sessions) {
    if (sessions.length === 0) {
        return "No debug sessions.";
    }
    return sessions
        .map(session => {
        const location = formatLocation(session);
        return [
            `${session.id}: ${session.status}`,
            `  adapter=${session.adapter}`,
            `  cwd=${session.cwd}`,
            ...(session.program ? [`  program=${session.program}`] : []),
            ...(location ? [`  location=${location}`] : []),
            ...(session.stopReason ? [`  reason=${session.stopReason}`] : []),
        ].join("\n");
    })
        .join("\n\n");
}
function formatEvaluation(evaluation) {
    const lines = [`Result: ${evaluation.result}`];
    if (evaluation.type)
        lines.push(`Type: ${evaluation.type}`);
    if (evaluation.variablesReference > 0) {
        lines.push(`Variables ref: ${evaluation.variablesReference}`);
    }
    return lines.join("\n");
}
function buildOutcomeText(outcome, timeoutSec, verb) {
    const lines = formatSessionSnapshot(outcome.snapshot);
    if (outcome.timedOut) {
        lines.push(`Program is still running after ${timeoutSec}s. Use pause to interrupt and inspect state.`);
        return lines.join("\n");
    }
    if (outcome.state === "stopped") {
        lines.push(`${verb} stopped at ${formatLocation(outcome.snapshot) ?? "unknown location"}.`);
        return lines.join("\n");
    }
    if (outcome.state === "terminated") {
        lines.push(`Program terminated${outcome.snapshot.exitCode !== undefined ? ` with exit code ${outcome.snapshot.exitCode}` : ""}.`);
        return lines.join("\n");
    }
    lines.push("Program is running.");
    return lines.join("\n");
}
function getConfiguredAdapters(cwd) {
    const adapters = getAvailableAdapters(cwd).map(adapter => adapter.name);
    const names = adapters.length > 0 ? adapters.join(", ") : "none";
    return truncateToWidth(replaceTabs(names), TRUNCATE_LENGTHS.LONG);
}
const ADAPTER_UNAVAILABLE_MESSAGES = {
    debugpy: "adapter 'debugpy' is not available: python not found in PATH",
    dlv: "adapter 'dlv' is not available: install with 'go install github.com/go-delve/delve/cmd/dlv@latest'",
    rdbg: "adapter 'rdbg' is not available: install with 'gem install debug'",
    "js-debug-adapter": "adapter 'js-debug-adapter' is not available: download it from https://github.com/microsoft/vscode-js-debug",
};
const ADAPTER_CANONICAL_COMMANDS = {
    debugpy: "python",
    dlv: "dlv",
    rdbg: "rdbg",
    "js-debug-adapter": "js-debug-adapter",
};
function formatAdapterUnavailable(adapterName, command, cwd) {
    const displayName = truncateToWidth(replaceTabs(adapterName), TRUNCATE_LENGTHS.SHORT);
    const canonicalCommand = ADAPTER_CANONICAL_COMMANDS[adapterName] ?? adapterName;
    if (command !== canonicalCommand) {
        const displayCommand = truncateToWidth(replaceTabs(shortenPath(command)), TRUNCATE_LENGTHS.CONTENT);
        return `adapter '${displayName}' is not available: configured command '${displayCommand}' did not resolve. Check the DAP adapter config for this workspace.`;
    }
    return (ADAPTER_UNAVAILABLE_MESSAGES[adapterName] ??
        `adapter '${displayName}' is not available. Installed adapters: ${getConfiguredAdapters(cwd)}`);
}
async function classifyLaunchProgram(program) {
    try {
        return (await fs.stat(program)).isDirectory() ? "directory" : "file";
    }
    catch (error) {
        if (isEnoent(error))
            return "missing";
        throw error;
    }
}
function validateLaunchProgram(program, cwd, programKind, adapter) {
    if (programKind !== "directory" || adapter.acceptsDirectoryProgram)
        return;
    const displayPath = formatPathRelativeToCwd(program, cwd, { trailingSlash: true });
    throw new ToolError(`launch program resolves to a directory: ${displayPath}. Pass an executable file path or choose an adapter that supports package directories.`);
}
function getActiveSessionSnapshot() {
    const snapshot = dapSessionManager.getActiveSession();
    if (!snapshot) {
        throw new ToolError("No active debug session. Launch or attach first.");
    }
    return snapshot;
}
function requireCapability(capability, description) {
    const snapshot = getActiveSessionSnapshot();
    if (dapSessionManager.getCapabilities()?.[capability] !== true) {
        throw new ToolError(`Current adapter does not support ${description}`);
    }
    return snapshot;
}
function resolveDisassemblyReference(memoryReference) {
    if (memoryReference) {
        return memoryReference;
    }
    const snapshot = getActiveSessionSnapshot();
    if (snapshot.instructionPointerReference) {
        return snapshot.instructionPointerReference;
    }
    throw new ToolError("disassemble requires memory_reference unless the current stop location has an instruction pointer reference");
}
export class DebugTool {
    session;
    name = "debug";
    approval = (args) => {
        const rawAction = args.action;
        const action = typeof rawAction === "string" ? rawAction.toLowerCase() : "";
        return DEBUG_READONLY_ACTIONS.has(action) ? "read" : "exec";
    };
    formatApprovalDetails = (args) => {
        const params = args;
        const lines = [`Action: ${typeof params.action === "string" ? params.action : "(missing)"}`];
        if (typeof params.program === "string" && params.program.length > 0) {
            lines.push(`Program: ${truncateForPrompt(params.program)}`);
        }
        return lines;
    };
    label = "Debug";
    summary = "Debug a running process with DAP (debugger adapter protocol)";
    description;
    parameters = debugSchema;
    strict = true;
    examples = [
        {
            caption: "Launch and inspect hang",
            note: '1. debug(action: "launch", program: "./my_app")\n2. debug(action: "set_breakpoint", file: "src/main.c", line: 42)\n3. debug(action: "continue")\n4. If the program appears hung: debug(action: "pause")\n5. Inspect state with `threads`, `stack_trace`, `scopes`, and `variables`',
        },
        {
            caption: "Launch a Python script with debugpy",
            call: { action: "launch", adapter: "debugpy", program: "scripts/job.py", args: ["--flag"] },
        },
        {
            caption: "Raw debugger command through repl",
            call: { action: "evaluate", expression: "info registers", context: "repl" },
        },
    ];
    concurrency = "exclusive";
    loadMode = "discoverable";
    constructor(session) {
        this.session = session;
        this.description = prompt.render(debugDescription);
    }
    static createIf(session) {
        return cfgDebugEnabled.get(session.settings) ? new DebugTool(session) : null;
    }
    async execute(_toolCallId, params, signal, _onUpdate, _context) {
        const timeoutSec = clampTimeout("debug", params.timeout, cfgToolsMaxTimeout.get(this.session.settings));
        const timeoutSignal = AbortSignal.timeout(timeoutSec * 1000);
        const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
        const details = { action: params.action, success: true };
        const result = toolResult(details);
        switch (params.action) {
            case "launch": {
                if (!params.program) {
                    throw new ToolError("program is required for launch");
                }
                const commandCwd = params.cwd ? resolveToCwd(params.cwd, this.session.cwd) : this.session.cwd;
                const program = resolveToCwd(params.program, commandCwd);
                const programKind = await classifyLaunchProgram(program);
                const selection = selectLaunchAdapter(program, commandCwd, params.adapter, programKind);
                if (selection.kind === "unavailable") {
                    throw new ToolError(formatAdapterUnavailable(selection.adapterName, selection.command, commandCwd));
                }
                if (selection.kind === "none") {
                    throw new ToolError(`No debugger adapter available. Installed adapters: ${getConfiguredAdapters(commandCwd)}`);
                }
                const { adapter } = selection;
                validateLaunchProgram(program, commandCwd, programKind, adapter);
                const extraLaunchArguments = resolveLaunchOverrides(adapter, program, programKind);
                const snapshot = await dapSessionManager.launch({ adapter, program, args: params.args, cwd: commandCwd, extraLaunchArguments }, combinedSignal, timeoutSec * 1000);
                details.snapshot = snapshot;
                details.adapter = adapter.name;
                return result.text(formatSessionSnapshot(snapshot).join("\n")).done();
            }
            case "attach": {
                if (params.pid === undefined && params.port === undefined && !params.adapter) {
                    throw new ToolError("attach requires pid or port");
                }
                const commandCwd = params.cwd ? resolveToCwd(params.cwd, this.session.cwd) : this.session.cwd;
                const adapter = selectAttachAdapter(commandCwd, params.adapter, params.port);
                if (!adapter) {
                    if (params.adapter) {
                        const command = getAdapterConfigs(commandCwd)[params.adapter]?.command ?? params.adapter;
                        throw new ToolError(formatAdapterUnavailable(params.adapter, command, commandCwd));
                    }
                    throw new ToolError(`No debugger adapter available. Installed adapters: ${getConfiguredAdapters(commandCwd)}`);
                }
                const snapshot = await dapSessionManager.attach({ adapter, cwd: commandCwd, pid: params.pid, port: params.port, host: params.host }, combinedSignal, timeoutSec * 1000);
                details.snapshot = snapshot;
                details.adapter = adapter.name;
                return result.text(formatSessionSnapshot(snapshot).join("\n")).done();
            }
            case "set_breakpoint": {
                if (params.function) {
                    const response = await dapSessionManager.setFunctionBreakpoint(params.function, params.condition, combinedSignal, timeoutSec * 1000);
                    details.snapshot = response.snapshot;
                    details.functionBreakpoints = response.breakpoints;
                    return result.text(formatFunctionBreakpoints(response.breakpoints)).done();
                }
                if (!params.file || params.line === undefined) {
                    throw new ToolError("set_breakpoint requires file+line or function");
                }
                const file = resolveToCwd(params.file, this.session.cwd);
                const response = await dapSessionManager.setBreakpoint(file, params.line, params.condition, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.breakpoints = response.breakpoints;
                return result.text(formatBreakpoints(response.sourcePath, response.breakpoints)).done();
            }
            case "remove_breakpoint": {
                if (params.function) {
                    const response = await dapSessionManager.removeFunctionBreakpoint(params.function, combinedSignal, timeoutSec * 1000);
                    details.snapshot = response.snapshot;
                    details.functionBreakpoints = response.breakpoints;
                    return result.text(formatFunctionBreakpoints(response.breakpoints)).done();
                }
                if (!params.file || params.line === undefined) {
                    throw new ToolError("remove_breakpoint requires file+line or function");
                }
                const file = resolveToCwd(params.file, this.session.cwd);
                const response = await dapSessionManager.removeBreakpoint(file, params.line, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.breakpoints = response.breakpoints;
                return result.text(formatBreakpoints(response.sourcePath, response.breakpoints)).done();
            }
            case "set_instruction_breakpoint": {
                requireCapability("supportsInstructionBreakpoints", "instruction breakpoints");
                if (!params.instruction_reference) {
                    throw new ToolError("instruction_reference is required for set_instruction_breakpoint");
                }
                const response = await dapSessionManager.setInstructionBreakpoint(params.instruction_reference, params.offset, params.condition, params.hit_condition, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.instructionBreakpoints = response.breakpoints;
                return result.text(formatInstructionBreakpoints(response.breakpoints)).done();
            }
            case "remove_instruction_breakpoint": {
                requireCapability("supportsInstructionBreakpoints", "instruction breakpoints");
                if (!params.instruction_reference) {
                    throw new ToolError("instruction_reference is required for remove_instruction_breakpoint");
                }
                const response = await dapSessionManager.removeInstructionBreakpoint(params.instruction_reference, params.offset, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.instructionBreakpoints = response.breakpoints;
                return result.text(formatInstructionBreakpoints(response.breakpoints)).done();
            }
            case "data_breakpoint_info": {
                requireCapability("supportsDataBreakpoints", "data breakpoints");
                if (!params.name) {
                    throw new ToolError("name is required for data_breakpoint_info");
                }
                const response = await dapSessionManager.dataBreakpointInfo(params.name, params.variable_ref ?? params.scope_id, params.frame_id, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.dataBreakpointInfo = response.info;
                return result.text(formatDataBreakpointInfo(response.info)).done();
            }
            case "set_data_breakpoint": {
                requireCapability("supportsDataBreakpoints", "data breakpoints");
                if (!params.data_id) {
                    throw new ToolError("data_id is required for set_data_breakpoint");
                }
                const response = await dapSessionManager.setDataBreakpoint(params.data_id, params.access_type, params.condition, params.hit_condition, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.dataBreakpoints = response.breakpoints;
                return result.text(formatDataBreakpoints(response.breakpoints)).done();
            }
            case "remove_data_breakpoint": {
                requireCapability("supportsDataBreakpoints", "data breakpoints");
                if (!params.data_id) {
                    throw new ToolError("data_id is required for remove_data_breakpoint");
                }
                const response = await dapSessionManager.removeDataBreakpoint(params.data_id, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.dataBreakpoints = response.breakpoints;
                return result.text(formatDataBreakpoints(response.breakpoints)).done();
            }
            case "continue": {
                const outcome = await dapSessionManager.continue(combinedSignal, timeoutSec * 1000);
                details.snapshot = outcome.snapshot;
                details.state = outcome.state;
                details.timedOut = outcome.timedOut;
                return result.text(buildOutcomeText(outcome, timeoutSec, "Continue")).done();
            }
            case "step_over": {
                const outcome = await dapSessionManager.stepOver(combinedSignal, timeoutSec * 1000);
                details.snapshot = outcome.snapshot;
                details.state = outcome.state;
                details.timedOut = outcome.timedOut;
                return result.text(buildOutcomeText(outcome, timeoutSec, "Step over")).done();
            }
            case "step_in": {
                const outcome = await dapSessionManager.stepIn(combinedSignal, timeoutSec * 1000);
                details.snapshot = outcome.snapshot;
                details.state = outcome.state;
                details.timedOut = outcome.timedOut;
                return result.text(buildOutcomeText(outcome, timeoutSec, "Step in")).done();
            }
            case "step_out": {
                const outcome = await dapSessionManager.stepOut(combinedSignal, timeoutSec * 1000);
                details.snapshot = outcome.snapshot;
                details.state = outcome.state;
                details.timedOut = outcome.timedOut;
                return result.text(buildOutcomeText(outcome, timeoutSec, "Step out")).done();
            }
            case "pause": {
                const snapshot = await dapSessionManager.pause(combinedSignal, timeoutSec * 1000);
                details.snapshot = snapshot;
                return result.text(formatSessionSnapshot(snapshot).concat("Program paused.").join("\n")).done();
            }
            case "evaluate": {
                if (!params.expression) {
                    throw new ToolError("expression is required for evaluate");
                }
                const evaluationContext = params.context ?? "repl";
                const response = await dapSessionManager.evaluate(params.expression, evaluationContext, params.frame_id, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.evaluation = response.evaluation;
                return result.text(formatEvaluation(response.evaluation)).done();
            }
            case "stack_trace": {
                const response = await dapSessionManager.stackTrace(params.levels, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.stackFrames = response.stackFrames;
                return result.text(formatStackFrames(response.stackFrames)).done();
            }
            case "threads": {
                const response = await dapSessionManager.threads(combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.threads = response.threads;
                return result.text(formatThreads(response.threads)).done();
            }
            case "scopes": {
                const response = await dapSessionManager.scopes(params.frame_id, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.scopes = response.scopes;
                return result.text(formatScopes(response.scopes)).done();
            }
            case "variables": {
                const variableReference = params.variable_ref ?? params.scope_id;
                if (variableReference === undefined) {
                    throw new ToolError("variables requires variable_ref or scope_id");
                }
                const response = await dapSessionManager.variables(variableReference, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.variables = response.variables;
                return result.text(formatVariables(response.variables)).done();
            }
            case "disassemble": {
                requireCapability("supportsDisassembleRequest", "disassembly");
                if (params.instruction_count === undefined) {
                    throw new ToolError("instruction_count is required for disassemble");
                }
                const response = await dapSessionManager.disassemble(resolveDisassemblyReference(params.memory_reference), params.instruction_count, params.offset, params.instruction_offset, params.resolve_symbols, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.disassembly = response.instructions;
                return result.text(formatDisassembly(response.instructions)).done();
            }
            case "read_memory": {
                requireCapability("supportsReadMemoryRequest", "memory reads");
                if (!params.memory_reference) {
                    throw new ToolError("memory_reference is required for read_memory");
                }
                if (params.count === undefined) {
                    throw new ToolError("count is required for read_memory");
                }
                const response = await dapSessionManager.readMemory(params.memory_reference, params.count, params.offset, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.memoryAddress = response.address;
                details.memoryData = response.data;
                details.unreadableBytes = response.unreadableBytes;
                return result.text(formatMemoryRead(response.address, response.data, response.unreadableBytes)).done();
            }
            case "write_memory": {
                requireCapability("supportsWriteMemoryRequest", "memory writes");
                if (!params.memory_reference) {
                    throw new ToolError("memory_reference is required for write_memory");
                }
                if (!params.data) {
                    throw new ToolError("data is required for write_memory");
                }
                const response = await dapSessionManager.writeMemory(params.memory_reference, params.data, params.offset, params.allow_partial, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.bytesWritten = response.bytesWritten;
                return result
                    .text([
                    "Memory write completed.",
                    ...(response.bytesWritten !== undefined ? [`Bytes written: ${response.bytesWritten}`] : []),
                    ...(response.offset !== undefined ? [`Offset: ${response.offset}`] : []),
                ].join("\n"))
                    .done();
            }
            case "modules": {
                requireCapability("supportsModulesRequest", "module introspection");
                const response = await dapSessionManager.modules(params.start_module, params.module_count, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.modules = response.modules;
                return result.text(formatModules(response.modules)).done();
            }
            case "loaded_sources": {
                requireCapability("supportsLoadedSourcesRequest", "loaded sources");
                const response = await dapSessionManager.loadedSources(combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.sources = response.sources;
                return result.text(formatLoadedSources(response.sources)).done();
            }
            case "custom_request": {
                if (!params.command) {
                    throw new ToolError("command is required for custom_request");
                }
                const response = await dapSessionManager.customRequest(params.command, params.arguments, combinedSignal, timeoutSec * 1000);
                details.snapshot = response.snapshot;
                details.customBody = response.body;
                return result.text(formatCustomResponse(params.command, response.body)).done();
            }
            case "output": {
                const response = dapSessionManager.getOutput();
                details.snapshot = response.snapshot;
                details.output = response.output;
                return result.text(response.output.length > 0 ? response.output : "(no output captured)").done();
            }
            case "terminate": {
                const snapshot = await dapSessionManager.terminate(combinedSignal, timeoutSec * 1000);
                if (!snapshot) {
                    return result.text("No debug session to terminate.").done();
                }
                details.snapshot = snapshot;
                return result.text(formatSessionSnapshot(snapshot).concat("Debug session terminated.").join("\n")).done();
            }
            case "sessions": {
                const sessions = dapSessionManager.listSessions();
                details.sessions = sessions;
                return result.text(formatSessions(sessions)).done();
            }
            default:
                throw new ToolError(`Unsupported debug action: ${params.action}`);
        }
    }
}
