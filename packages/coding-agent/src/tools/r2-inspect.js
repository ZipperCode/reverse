import { stat } from "node:fs/promises";
import { type } from "@rva/omptype";
import { prompt } from "@rva/utils";
import r2InspectDescription from "../prompts/tools/r2-inspect.md" with { type: "text" };
import { checkToolRequirements, } from "../extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG } from "../extensibility/skill-tool-catalog";
import { resolveReadPath } from "./path-utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
const r2InspectSchema = type({
    action: type
        .enumerated("info", "sections", "imports", "exports", "strings", "functions", "xrefs", "disasm", "decompile")
        .describe("Read-only analysis action: info (binary header), sections, imports, exports, strings, functions, xrefs (to a symbol/address), disasm (bounded instructions), or decompile (requires an r2 decompiler plugin such as r2dec)"),
    path: type("string").describe("Path to the target binary, executable, library, object, or firmware image"),
    "target?": type("string").describe("Alias for symbol: name of the function/symbol to inspect"),
    "symbol?": type("string").describe("Function or flag name, e.g. main, sym.main, sym.imp.malloc, or fcn.00401000. Required for xrefs; defaults to entry0 for disasm/decompile"),
    "address?": type("string").describe("Hex or decimal virtual address, e.g. 0x401000. Cannot be combined with symbol"),
    "limit?": type("number").describe("Maximum items/instructions/lines returned (default 50 for lists, 100 for disasm/decompile; capped at 500/2000)"),
    "offset?": type("number").describe("Zero-based pagination offset for list actions and decompile line windows"),
    "mode?": type
        .enumerated("full", "fold", "summary")
        .describe("Rendering mode: full (default), fold (conservative whitespace/dedupe cleanup), summary (counts + a short preview). fold/summary are heuristic and not verified exhaustive"),
    "timeout?": type("number").describe("Execution timeout in seconds (default 30, max 120)"),
    "max_bytes?": type("number").describe("Maximum stdout bytes to capture before truncation (default 262144, max 4194304)"),
});
const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 500;
const DEFAULT_TEXT_LIMIT = 100;
const MAX_TEXT_LIMIT = 2000;
const MAX_OFFSET = 100000;
const DEFAULT_TIMEOUT_SECONDS = 30;
const MAX_TIMEOUT_SECONDS = 120;
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024; // 1 GiB
const STDERR_BYTES = 16 * 1024;
const RAW_PREVIEW_BYTES = 8 * 1024;
const MAX_FOLD_LINE = 400;
const SUMMARY_PREVIEW_ITEMS = 10;
const ADDRESS_PATTERN = /^(?:0[xX])?[0-9a-fA-F]{1,16}$/;
// Flag/symbol names: no whitespace, semicolons, pipes, backticks, parentheses,
// `@`, `$`, or braces, so a name can never introduce a second r2 command or
// seek/operator expression.
const SYMBOL_PATTERN = /^[A-Za-z0-9_.:-]{1,256}$/;
const ANSI_PATTERN = /\u001b\[[0-9;]*[A-Za-z]/g;
async function readCapped(stream, cap, onOverflow) {
    const reader = stream.getReader();
    const chunks = [];
    let bytes = 0;
    let truncated = false;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            const remaining = cap - bytes;
            if (value.byteLength >= remaining) {
                if (remaining > 0)
                    chunks.push(value.subarray(0, remaining));
                bytes += Math.max(0, remaining);
                truncated = true;
                onOverflow?.();
                break;
            }
            chunks.push(value);
            bytes += value.byteLength;
        }
    }
    finally {
        if (truncated)
            await reader.cancel().catch(() => { });
    }
    return {
        text: Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString("utf8"),
        bytes,
        truncated,
    };
}
/** Spawn radare2 with an argv array; stdin is ignored and the process is killed on timeout/abort/overflow. */
export async function defaultR2Runner(binary, args, options) {
    const child = Bun.spawn([binary, ...args], {
        cwd: options.cwd,
        stdout: "pipe",
        stderr: "pipe",
        stdin: "ignore",
    });
    let timedOut = false;
    let killedOnOverflow = false;
    const timer = setTimeout(() => {
        timedOut = true;
        child.kill();
    }, options.timeoutMs);
    const onAbort = () => {
        child.kill();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });
    try {
        const [stdout, stderr, exitCode] = await Promise.all([
            readCapped(child.stdout, options.maxBytes, () => {
                killedOnOverflow = true;
                child.kill();
            }),
            readCapped(child.stderr, STDERR_BYTES),
            child.exited,
        ]);
        return {
            stdout: stdout.text,
            stderr: stderr.text,
            exitCode,
            outputBytes: stdout.bytes,
            truncated: stdout.truncated,
            timedOut,
            killedOnOverflow,
        };
    }
    finally {
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", onAbort);
    }
}
function platformKey() {
    return process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
}
export function r2Dependency(which) {
    const requirements = [{ id: "radare2" }];
    const [status] = checkToolRequirements(requirements, which ? { which } : undefined);
    const found = status?.foundPath ?? null;
    const available = found !== null;
    const catalogHint = SKILL_TOOL_CATALOG.radare2?.installHints?.[platformKey()]?.join(" or ");
    const installHint = status?.hint ?? (available ? undefined : catalogHint);
    return {
        id: "radare2",
        binary: "r2",
        available,
        ...(available && found ? { path: found } : {}),
        ...(installHint && !available ? { installHint } : {}),
    };
}
function shellQuote(value) {
    return `"${value.replace(/(["\\$`])/g, "\\$1")}"`;
}
export function resolveR2Fallback(action, displayPath, options = {}) {
    const quoted = shellQuote(displayPath);
    const reference = options.address ?? options.symbol;
    const refLabel = reference ? ` (target ${reference})` : "";
    const make = (suggested, alternatives) => ({
        primary: "radare2",
        operation: action,
        suggestedFallback: suggested,
        activeFallback: suggested,
        alternatives,
        executed: false,
    });
    switch (action) {
        case "info":
            return make(`file ${quoted}`, [
                `objdump -f ${quoted}`,
                `readelf -h ${quoted}`,
                `llvm-objdump --file-headers ${quoted}`,
            ]);
        case "sections":
            return make(`objdump -h ${quoted}`, [`readelf -S ${quoted}`, `llvm-objdump --section-headers ${quoted}`]);
        case "imports":
            return make(`objdump -x ${quoted} | grep -i import`, [
                `readelf -r ${quoted}`,
                `llvm-objdump --macho --dylibs-used ${quoted}`,
            ]);
        case "exports":
            return make(`objdump -t ${quoted}`, [`readelf --dyn-syms ${quoted}`, `nm -gU ${quoted}`]);
        case "strings":
            return make(`strings -a -n 5 ${quoted}`, [
                `strings -a -n 8 ${quoted} | head -200`,
                `objdump -s -j .rodata ${quoted}`,
            ]);
        case "functions":
            return make(`objdump -t ${quoted}`, [`readelf -s ${quoted}`, `nm -an ${quoted}`]);
        case "xrefs":
            return make(`objdump -d ${quoted} | grep -i ${shellQuote(reference ?? "<target>")}`, [
                `llvm-objdump -d ${quoted}`,
                `readelf -r ${quoted}${refLabel}`,
            ]);
        case "disasm":
            return make(`objdump -d ${quoted}`, [
                `llvm-objdump -d ${quoted}`,
                `objdump -d --start-address=${reference ?? "0x0"} ${quoted}`,
            ]);
        case "decompile":
            return make(`objdump -d ${quoted}`, [
                `retdec-decompiler ${quoted}`,
                `Ghidra or IDA Pro for higher-level decompilation`,
                `llvm-objdump -d ${quoted}`,
            ]);
    }
}
function formatMissingNotice(dependency, fallback) {
    const hint = dependency.installHint ?? "brew install radare2 (macOS), apt install radare2 (Linux)";
    const note = fallback.operation === "decompile"
        ? `\n  -> Decompilation also needs an r2 plugin: r2pm -ci r2dec (or r2ghidra); the radare2 MCP server (r2pm -Uci r2mcp) is an optional persistent-session alternative.`
        : "";
    return [
        "[Notice] Primary tool 'radare2' (r2) not found on PATH.",
        `  -> Install hint: ${hint}`,
        `  -> Suggested fallback command: ${fallback.suggestedFallback}`,
        `  -> Alternative fallback options:`,
        ...fallback.alternatives.map(alt => `     • ${alt}`),
        `  (Note: the fallback command was not executed automatically; run it yourself if it fits.)${note}`,
    ].join("\n");
}
function asRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value) ? value : undefined;
}
function asArray(value) {
    return Array.isArray(value) ? value : [];
}
function asText(value) {
    return typeof value === "string" ? value : undefined;
}
function asNumber(value) {
    if (typeof value === "number" && Number.isFinite(value))
        return Math.trunc(value);
    if (typeof value === "string" && /^\d+$/.test(value)) {
        const parsed = Number.parseInt(value, 10);
        return Number.isSafeInteger(parsed) ? parsed : undefined;
    }
    return undefined;
}
function asAddress(value) {
    if (typeof value === "number" && Number.isFinite(value) && value >= 0)
        return `0x${Math.trunc(value).toString(16)}`;
    if (typeof value === "string" && ADDRESS_PATTERN.test(value)) {
        return value.toLowerCase().startsWith("0x") ? value.toLowerCase() : `0x${value.toLowerCase()}`;
    }
    return undefined;
}
function firstDefined(...values) {
    return values.find(value => value !== undefined);
}
function normalizeInfo(raw) {
    const record = asRecord(raw) ?? {};
    const core = asRecord(record.core) ?? record;
    const bin = asRecord(record.bin) ?? record;
    const info = {
        arch: firstDefined(asText(bin.arch), asText(core.arch)),
        bits: firstDefined(asNumber(bin.bits), asNumber(core.bits)),
        endian: firstDefined(asText(bin.endian), asText(core.endian)),
        os: firstDefined(asText(bin.os), asText(core.os)),
        machine: asText(bin.machine),
        type: firstDefined(asText(bin.type), asText(core.type)),
        class: asText(bin.class),
        format: firstDefined(asText(core.format), asText(bin.format)),
        baddr: asAddress(firstDefined(bin.baddr, core.baddr)),
        size: firstDefined(asNumber(bin.size), asNumber(core.size)),
        stripped: firstDefined(typeof bin.stripped === "boolean" ? bin.stripped : undefined, typeof core.stripped === "boolean" ? core.stripped : undefined),
    };
    return Object.fromEntries(Object.entries(info).filter(([, value]) => value !== undefined));
}
function normalizeSections(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            name: asText(record.name) ?? asText(record.section) ?? "<unnamed>",
            vaddr: asAddress(record.vaddr),
            paddr: asAddress(record.paddr),
            vsize: asNumber(record.vsize),
            size: asNumber(record.size),
            perm: asText(record.perm),
            type: asText(record.type),
        };
    });
}
function normalizeImports(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            name: asText(record.name) ?? asText(record.import) ?? "<unnamed>",
            libname: asText(record.libname),
            type: asText(record.type),
            bind: asText(record.bind),
            plt: asAddress(record.plt),
        };
    });
}
function normalizeExports(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            name: asText(record.name) ??
                asText(record.demname) ??
                asText(record.realname) ??
                asText(record.flagname) ??
                "<unnamed>",
            vaddr: asAddress(record.vaddr),
            paddr: asAddress(record.paddr),
            type: asText(record.type),
            bind: asText(record.bind),
            size: asNumber(record.size),
        };
    });
}
function normalizeStrings(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            vaddr: asAddress(record.vaddr),
            paddr: asAddress(record.paddr),
            length: asNumber(record.length),
            size: asNumber(record.size),
            section: asText(record.section),
            type: asText(record.type),
            string: asText(record.string) ?? "",
        };
    });
}
function normalizeFunctions(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            name: asText(record.name) ?? "<unnamed>",
            offset: asAddress(record.offset),
            size: asNumber(record.size),
            ninstr: firstDefined(asNumber(record.ninstr), asNumber(record.ninstrs)),
            edges: asNumber(record.edges),
            type: asText(record.type),
        };
    });
}
function normalizeXrefs(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            from: asAddress(record.from) ?? "<unknown>",
            to: asAddress(record.to),
            type: asText(record.type),
            opcode: asText(record.opcode),
        };
    });
}
function normalizeDisasm(raw) {
    return asArray(raw).map(entry => {
        const record = asRecord(entry) ?? {};
        return {
            offset: asAddress(record.offset) ?? "<unknown>",
            disasm: asText(record.disasm) ?? asText(record.opcode) ?? "",
            opcode: asText(record.opcode),
            bytes: asText(record.bytes),
            type: asText(record.type),
        };
    });
}
function parseR2Json(stdout) {
    const trimmed = stdout.trim();
    if (trimmed.length === 0)
        return { error: "radare2 produced no output" };
    try {
        return { value: JSON.parse(trimmed) };
    }
    catch (error) {
        // Some r2 builds prepend warnings to an otherwise valid JSON payload.
        const start = trimmed.search(/[[{]/);
        const end = Math.max(trimmed.lastIndexOf("]"), trimmed.lastIndexOf("}"));
        if (start >= 0 && end > start) {
            try {
                return { value: JSON.parse(trimmed.slice(start, end + 1)) };
            }
            catch {
                // Fall through to the original error.
            }
        }
        return { error: error instanceof Error ? error.message : String(error) };
    }
}
function normalizePayload(action, value) {
    switch (action) {
        case "info":
            return { info: normalizeInfo(value) };
        case "sections":
            return { sections: normalizeSections(value) };
        case "imports":
            return { imports: normalizeImports(value) };
        case "exports":
            return { exports: normalizeExports(value) };
        case "strings":
            return { strings: normalizeStrings(value) };
        case "functions":
            return { functions: normalizeFunctions(value) };
        case "xrefs":
            return { xrefs: normalizeXrefs(value) };
        case "disasm":
            return { disasm: normalizeDisasm(value) };
        case "decompile":
            return {};
    }
}
function payloadItems(details) {
    switch (details.action) {
        case "sections":
            return details.sections;
        case "imports":
            return details.imports;
        case "exports":
            return details.exports;
        case "strings":
            return details.strings;
        case "functions":
            return details.functions;
        case "xrefs":
            return details.xrefs;
        case "disasm":
            return details.disasm;
        default:
            return undefined;
    }
}
function paginate(items, offset, limit) {
    return {
        items: items.slice(offset, offset + limit),
        total: items.length,
        hasMore: offset + limit < items.length,
    };
}
function renderInfo(info) {
    const labels = [
        ["format", "format"],
        ["arch", "arch"],
        ["bits", "bits"],
        ["endian", "endian"],
        ["os", "os"],
        ["machine", "machine"],
        ["type", "type"],
        ["class", "class"],
        ["baddr", "base"],
        ["size", "size"],
        ["stripped", "stripped"],
    ];
    return labels.filter(([key]) => info[key] !== undefined).map(([key, label]) => `${label}: ${String(info[key])}`);
}
function renderSections(items) {
    return items.map(item => {
        const range = [item.vaddr, item.vsize !== undefined ? `size=${item.vsize}` : undefined].filter(Boolean).join(" ");
        return [item.name, range, item.perm].filter(part => part && part.length > 0).join("  ");
    });
}
function renderImports(items) {
    return items.map(item => [item.name, item.libname ? `from ${item.libname}` : undefined, item.type]
        .filter(part => part && part.length > 0)
        .join("  "));
}
function renderExports(items) {
    return items.map(item => [item.vaddr, item.name, item.type].filter(part => part && String(part).length > 0).join("  "));
}
function renderStrings(items) {
    return items.map(item => {
        const address = item.vaddr ?? item.paddr ?? "?";
        const length = item.length ?? item.size;
        const snippet = item.string.replace(/\s+/g, " ").trim();
        return `${address}  ${length !== undefined ? `len=${length}  ` : ""}${snippet}`;
    });
}
function renderFunctions(items) {
    return items.map(item => [item.offset, item.name, item.size !== undefined ? `size=${item.size}` : undefined, item.type]
        .filter(part => part && String(part).length > 0)
        .join("  "));
}
function renderXrefs(items) {
    return items.map(item => [`${item.from} -> ${item.to ?? "?"}`, item.type, item.opcode].filter(part => part && part.length > 0).join("  "));
}
function renderDisasm(items) {
    return items.map(item => `${item.offset}  ${item.disasm}`);
}
function stripAnsi(value) {
    return value.replace(ANSI_PATTERN, "");
}
/** Conservative formatting-only noise reduction; never changes instruction/content lines beyond whitespace/dedupe. */
export function foldR2Text(text) {
    const lines = [];
    let previous;
    for (const rawLine of stripAnsi(text).split(/\r?\n/)) {
        const line = rawLine.replace(/[ \t]+$/g, "").replace(/\t/g, "    ");
        if (line.trim().length === 0)
            continue;
        if (line === previous)
            continue;
        const bounded = line.length > MAX_FOLD_LINE ? `${line.slice(0, MAX_FOLD_LINE)}…` : line;
        lines.push(bounded);
        previous = line;
    }
    return lines.join("\n");
}
function summaryLines(lines, total, show) {
    const preview = lines.slice(0, Math.min(show, lines.length));
    return [`total: ${total}`, `showing: ${preview.length}`, ...preview];
}
function buildSummaryBody(action, lines, total) {
    if (action === "info")
        return lines.join("\n");
    const preview = summaryLines(lines, total, SUMMARY_PREVIEW_ITEMS);
    return preview.join("\n");
}
function validatedReference(params, action) {
    const address = params.address?.trim();
    const symbol = (params.symbol?.trim() || params.target?.trim()) ?? undefined;
    if (address && address.length > 0) {
        if (symbol && symbol.length > 0 && params.address !== undefined) {
            throw new ToolError("Provide either address or symbol, not both");
        }
        if (!ADDRESS_PATTERN.test(address)) {
            throw new ToolError(`Invalid address "${address}": expected decimal or hex (e.g. 0x401000)`);
        }
        const normalized = address.toLowerCase().startsWith("0x") || /[a-f]/i.test(address)
            ? `0x${address.replace(/^0[xX]/, "").toLowerCase()}`
            : `0x${BigInt(address).toString(16)}`;
        return { kind: "address", value: normalized };
    }
    if (symbol && symbol.length > 0) {
        if (!SYMBOL_PATTERN.test(symbol)) {
            throw new ToolError(`Invalid symbol "${symbol}": use a flag/function name (letters, digits, _ . : -) or an address`);
        }
        return { kind: "symbol", value: symbol };
    }
    if (action === "xrefs") {
        throw new ToolError("xrefs requires a target symbol or address");
    }
    return undefined;
}
/** Fixed r2 query for one action. References are validated by {@link validatedReference}. */
export function buildR2Command(action, reference, limit, offset) {
    const ref = reference?.value ?? "entry0";
    switch (action) {
        case "info":
            return "ij";
        case "sections":
            return "iSj";
        case "imports":
            return "iij";
        case "exports":
            return "iEj";
        case "strings":
            return "izzj";
        case "functions":
            return "aflj";
        case "xrefs":
            if (reference === undefined)
                throw new ToolError("xrefs requires a target symbol or address");
            return `axtj @ ${ref}`;
        case "disasm": {
            const window = Math.min(MAX_TEXT_LIMIT, offset + limit);
            return `pdj ${window} @ ${ref}`;
        }
        case "decompile":
            return `pdc @ ${ref}`;
    }
}
/** Build the argv passed to Bun.spawn; the query is always a fixed action command. */
export function buildR2Args(action, command, absolutePath) {
    const needsAnalysis = action === "functions" || action === "xrefs" || action === "disasm" || action === "decompile";
    return [
        "-q",
        "-e",
        "scr.color=0",
        "-e",
        "scr.interactive=false",
        ...(needsAnalysis ? ["-c", "aaa"] : []),
        "-c",
        command,
        "-c",
        "q",
        absolutePath,
    ];
}
function firstLine(value) {
    const trimmed = value.trim();
    const newline = trimmed.indexOf("\n");
    return newline === -1 ? trimmed : trimmed.slice(0, newline).trim();
}
export class R2InspectTool {
    session;
    options;
    name = "r2_inspect";
    approval = "read";
    label = "R2 Inspect";
    summary = "Read-only radare2 triage with fixed actions: info, sections, imports, exports, strings, functions, xrefs, bounded disassembly, and optional decompilation";
    description;
    parameters = r2InspectSchema;
    strict = true;
    loadMode = "discoverable";
    constructor(session, options = {}) {
        this.session = session;
        this.options = options;
        this.description = prompt.render(r2InspectDescription);
    }
    async execute(_toolCallId, params, signal) {
        throwIfAborted(signal);
        const requestedPath = params.path.trim();
        if (requestedPath.length === 0)
            throw new ToolError("path is required");
        const action = params.action;
        const mode = params.mode ?? "full";
        const reference = validatedReference(params, action);
        const absolutePath = resolveReadPath(requestedPath, this.session.cwd);
        let info;
        try {
            info = await stat(absolutePath);
        }
        catch {
            throw new ToolError(`Target file not found: ${requestedPath}`);
        }
        if (!info.isFile())
            throw new ToolError(`Not a regular file: ${requestedPath}`);
        if (info.size > MAX_FILE_BYTES) {
            throw new ToolError(`Target file size (${info.size} bytes) exceeds maximum limit of ${MAX_FILE_BYTES} bytes`);
        }
        const displayPath = requestedPath;
        const baseDetails = {
            action,
            path: displayPath,
            status: "ok",
            mode,
            ...(reference ? { reference: reference.value } : {}),
        };
        const dependency = r2Dependency(this.options.which);
        if (!dependency.available || !dependency.path) {
            const fallback = resolveR2Fallback(action, displayPath, {
                ...(reference?.kind === "symbol" ? { symbol: reference.value } : {}),
                ...(reference?.kind === "address" ? { address: reference.value } : {}),
            });
            return {
                content: [{ type: "text", text: formatMissingNotice(dependency, fallback) }],
                details: {
                    ...baseDetails,
                    status: "missing_dependency",
                    dependency,
                    fallback,
                },
            };
        }
        const textAction = action === "disasm" || action === "decompile";
        const defaultLimit = textAction ? DEFAULT_TEXT_LIMIT : DEFAULT_LIST_LIMIT;
        const maxLimit = textAction ? MAX_TEXT_LIMIT : MAX_LIST_LIMIT;
        const limit = Math.min(maxLimit, Math.max(1, Math.floor(params.limit ?? defaultLimit)));
        const offset = Math.min(MAX_OFFSET, Math.max(0, Math.floor(params.offset ?? 0)));
        const timeoutSeconds = Math.min(MAX_TIMEOUT_SECONDS, Math.max(1, Math.floor(params.timeout ?? DEFAULT_TIMEOUT_SECONDS)));
        const maxBytes = Math.min(MAX_OUTPUT_BYTES, Math.max(1, Math.floor(params.max_bytes ?? DEFAULT_MAX_BYTES)));
        if (action === "disasm" && offset + limit > MAX_TEXT_LIMIT) {
            throw new ToolError(`disasm offset + limit must be <= ${MAX_TEXT_LIMIT}; seek with address instead`);
        }
        const command = buildR2Command(action, reference, limit, offset);
        const args = buildR2Args(action, command, absolutePath);
        const runner = this.options.runner ?? defaultR2Runner;
        let run;
        try {
            run = await runner(dependency.path, args, {
                cwd: this.session.cwd,
                timeoutMs: timeoutSeconds * 1000,
                maxBytes,
                signal,
            });
        }
        catch (error) {
            throw new ToolError(`Failed to execute radare2: ${error instanceof Error ? error.message : String(error)}`);
        }
        throwIfAborted(signal);
        const engine = dependency.path?.split(/[\\/]/).pop() ?? "r2";
        const common = {
            ...baseDetails,
            dependency,
            engine,
            outputBytes: run.outputBytes,
            truncated: run.truncated,
        };
        if (run.timedOut) {
            return {
                content: [
                    {
                        type: "text",
                        text: `radare2 timed out after ${timeoutSeconds}s for ${displayPath}. Narrow the action, raise timeout, or use objdump/strings fallbacks.`,
                    },
                ],
                details: { ...common, status: "error", timedOut: true, error: `timed out after ${timeoutSeconds}s` },
            };
        }
        const cappedSuccess = run.truncated && run.stdout.trim().length > 0;
        if (run.exitCode !== 0 && !cappedSuccess) {
            const stderr = firstLine(run.stderr).slice(0, 400);
            return {
                content: [
                    {
                        type: "text",
                        text: `radare2 ${action} failed (exit ${run.exitCode}) for ${displayPath}${stderr ? `: ${stderr}` : ""}`,
                    },
                ],
                details: {
                    ...common,
                    status: "error",
                    error: `exit ${run.exitCode}${stderr ? `: ${stderr}` : ""}`,
                },
            };
        }
        if (action === "decompile") {
            return this.#renderDecompile(common, run, params, limit, offset, maxBytes);
        }
        const parsed = parseR2Json(run.stdout);
        if (parsed.value === undefined) {
            const raw = run.stdout.slice(0, RAW_PREVIEW_BYTES);
            const detail = parsed.error ?? "failed to parse radare2 JSON";
            const truncationNote = run.truncated
                ? ` Output was truncated at ${maxBytes} bytes, which may have interrupted the JSON payload.`
                : "";
            return {
                content: [
                    {
                        type: "text",
                        text: `radare2 returned output that could not be parsed as JSON (${detail}).${truncationNote}\n\nBounded raw output:\n${raw || "(empty)"}`,
                    },
                ],
                details: {
                    ...common,
                    status: "error",
                    format: "json",
                    parseError: detail,
                    raw,
                    error: detail,
                },
            };
        }
        const normalized = normalizePayload(action, parsed.value);
        const items = payloadItems({ ...normalized, action });
        let bodyLines;
        let total = 1;
        let shown = items;
        let hasMore = false;
        if (items !== undefined) {
            const page = paginate(items, offset, limit);
            total = page.total;
            shown = page.items;
            hasMore = page.hasMore;
        }
        const shownItems = shown ?? [];
        switch (action) {
            case "info":
                bodyLines = renderInfo(normalized.info);
                total = bodyLines.length;
                break;
            case "sections":
                bodyLines = renderSections(shownItems);
                break;
            case "imports":
                bodyLines = renderImports(shownItems);
                break;
            case "exports":
                bodyLines = renderExports(shownItems);
                break;
            case "strings":
                bodyLines = renderStrings(shownItems);
                break;
            case "functions":
                bodyLines = renderFunctions(shownItems);
                break;
            case "xrefs":
                bodyLines = renderXrefs(shownItems);
                break;
            case "disasm":
                bodyLines = renderDisasm(shownItems);
                break;
            default:
                bodyLines = [];
        }
        const body = mode === "summary"
            ? buildSummaryBody(action, bodyLines, total)
            : mode === "fold"
                ? foldR2Text(bodyLines.join("\n"))
                : bodyLines.join("\n");
        const displayBody = body.trim().length > 0 ? body : "(no results)";
        const header = `radare2 ${action}: ${displayPath}${reference ? ` @ ${reference.value}` : ""} (${run.outputBytes} bytes${run.truncated ? ", truncated" : ""})`;
        const modeNote = mode === "summary"
            ? "\n(summary: conservative heuristic; not verified exhaustive)"
            : mode === "fold"
                ? "\n(fold: formatting-only noise reduction; not verified exhaustive)"
                : "";
        const pageNote = items !== undefined && hasMore
            ? `\n… ${total - offset - shownItems.length} more; use offset=${offset + shownItems.length} or raise limit.`
            : "";
        const truncationNote = run.truncated
            ? `\n… output truncated at ${maxBytes} bytes; lower limit or raise max_bytes (up to ${MAX_OUTPUT_BYTES}).`
            : "";
        const actionDetails = {
            ...(normalized.info ? { info: normalized.info } : {}),
            ...(normalized.sections ? { sections: shownItems } : {}),
            ...(normalized.imports ? { imports: shownItems } : {}),
            ...(normalized.exports ? { exports: shownItems } : {}),
            ...(normalized.strings ? { strings: shownItems } : {}),
            ...(normalized.functions ? { functions: shownItems } : {}),
            ...(normalized.xrefs ? { xrefs: shownItems } : {}),
            ...(normalized.disasm ? { disasm: shownItems } : {}),
        };
        return {
            content: [
                {
                    type: "text",
                    text: `${header}\n${displayBody}${pageNote}${truncationNote}${modeNote}`,
                },
            ],
            details: {
                ...common,
                status: "ok",
                format: "json",
                ...actionDetails,
                total,
                count: items !== undefined ? shownItems.length : total,
                offset,
                hasMore,
                ...(mode !== "full" ? { unverified: true } : {}),
                ...(run.stderr.trim().length > 0 && !run.truncated ? { error: firstLine(run.stderr).slice(0, 400) } : {}),
            },
        };
    }
    #renderDecompile(common, run, params, limit, offset, maxBytes) {
        const mode = params.mode ?? "full";
        const stdout = stripAnsi(run.stdout);
        const stderr = run.stderr.trim();
        const failedDecode = stdout.trim().length === 0;
        const pluginMissing = /invalid command|unknown command|command .* not found|No such command/i.test(stderr);
        if (failedDecode) {
            const error = pluginMissing
                ? "decompiler command 'pdc' is unavailable; install an r2 decompiler plugin (r2pm -ci r2dec) or use action=disasm"
                : stderr.length > 0
                    ? firstLine(stderr).slice(0, 400)
                    : "radare2 decompilation produced no output";
            return {
                content: [{ type: "text", text: `radare2 decompile failed for ${common.path}: ${error}` }],
                details: { ...common, status: "error", format: "text", error },
            };
        }
        const allLines = stdout.split(/\r?\n/);
        const totalLines = allLines.length;
        let page = allLines.slice(offset, offset + limit);
        if (mode === "summary")
            page = page.slice(0, Math.min(SUMMARY_PREVIEW_ITEMS, page.length));
        const text = mode === "full" ? page.join("\n") : foldR2Text(page.join("\n"));
        const hasMore = offset + limit < totalLines;
        const modeNote = mode === "summary"
            ? "\n(summary: conservative heuristic; not verified exhaustive)"
            : mode === "fold"
                ? "\n(fold: formatting-only noise reduction; not verified exhaustive)"
                : "";
        const pageNote = hasMore && mode !== "summary" ? `\n… use offset=${offset + limit} for more lines.` : "";
        const truncationNote = run.truncated ? `\n… output truncated at ${maxBytes} bytes.` : "";
        return {
            content: [
                {
                    type: "text",
                    text: `radare2 decompile: ${common.path}${common.reference ? ` @ ${common.reference}` : ""} (${run.outputBytes} bytes${run.truncated ? ", truncated" : ""})\n${text}${pageNote}${truncationNote}${modeNote}`,
                },
            ],
            details: {
                ...common,
                status: "ok",
                format: "text",
                decompile: { text, lineCount: totalLines },
                total: totalLines,
                count: text.split(/\r?\n/).length,
                offset,
                hasMore,
                ...(mode !== "full" ? { unverified: true } : {}),
                ...(stderr.length > 0 ? { error: firstLine(stderr).slice(0, 400) } : {}),
            },
        };
    }
}
