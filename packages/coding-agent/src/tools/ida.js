import * as fs from "node:fs/promises";
import { type } from "@rva/omptype";
import { shortenPath } from "@rva/tui/render/render-utils";
import { enforceInlineByteCap } from "@rva/tui/tools/streaming-output";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { prompt } from "@rva/utils";
import { acquireIdaDatabase, cfgIdaAvailable, findOpenIdaDatabase, listIdaDatabases, locateIdb, splitSliceRef, } from "../ida";
import idaDescription from "../prompts/tools/ida.md" with { type: "text" };
import { truncateForPrompt } from "./approval";
import { saveArtifactText } from "./gh-common";
import { resolveToCwd } from "./path-utils";
import { cfgToolsMaxTimeout } from "./settings";
import { toolResult } from "./tool-result";
import { clampTimeout } from "./tool-timeouts";
/** Timeout for structured edit/save RPCs against the IDA worker. */
const IDA_EDIT_TIMEOUT_MS = 120000;
const idaSchema = type({
    action: type.enumerated("list", "open", "save", "close", "exec", "rename", "comment", "set_type", "make_function"),
    "db?": type("string").describe("binary or .i64/.idb path, or open db id; optional when exactly one db is open"),
    "target?": type("string").describe("symbol name or 0x address"),
    "name?": type("string").describe("new name (rename)"),
    "text?": type("string").describe("comment text"),
    "repeatable?": type("boolean").describe("repeatable comment"),
    "decl?": type("string").describe("C declaration (set_type)"),
    "code?": type("string").describe("Python for exec; `db` is the ida_domain Database; namespace persists per db"),
    "save?": type("boolean").describe("close: save first (default true)"),
    "timeout?": type("number").describe("exec timeout seconds"),
});
function stringArg(args, key) {
    if (typeof args !== "object" || args === null || !(key in args))
        return undefined;
    const value = Reflect.get(args, key);
    return typeof value === "string" ? value : undefined;
}
function requireArg(value, name, action) {
    if (value === undefined || value.trim() === "")
        throw new ToolError(`${name} is required for ${action}`);
    return value;
}
/** IDA Pro tool: lifecycle, structured edits, and Python `exec` against process-wide shared IDBs. */
export class IdaTool {
    session;
    name = "ida";
    approval = (args) => {
        const action = stringArg(args, "action");
        if (action === "list")
            return "read";
        if (action === "exec")
            return "exec";
        return "write";
    };
    formatApprovalDetails = (args) => {
        const lines = [`Action: ${stringArg(args, "action") ?? "(missing)"}`];
        const db = stringArg(args, "db");
        if (db)
            lines.push(`DB: ${truncateForPrompt(db)}`);
        const target = stringArg(args, "target");
        if (target)
            lines.push(`Target: ${truncateForPrompt(target)}`);
        const code = stringArg(args, "code");
        if (code)
            lines.push(`Code: ${truncateForPrompt(code)}`);
        return lines;
    };
    label = "IDA";
    summary = "Open, edit, and script IDA Pro databases shared across agents";
    description;
    parameters = idaSchema;
    strict = true;
    loadMode = "discoverable";
    constructor(session) {
        this.session = session;
        this.description = prompt.render(idaDescription);
    }
    /** Create the tool when `ida.enabled` is on. */
    static createIf(session) {
        return cfgIdaAvailable.get(session.settings) ? new IdaTool(session) : null;
    }
    async execute(_toolCallId, params, signal, _onUpdate, _context) {
        const details = { action: params.action };
        const result = toolResult(details);
        switch (params.action) {
            case "list": {
                const dbs = await listIdaDatabases(this.session);
                if (dbs.length === 0)
                    return result.text("No IDA databases open.").done();
                const lines = dbs.map(db => {
                    const { state, info, current } = db.status;
                    if (state === "opening")
                        return `${db.id}  (opening)  ${shortenPath(db.ref)}`;
                    const running = current ? `  [${current.method} running]` : "";
                    return `${db.id}  ${info.module}  ${info.format}  ${info.arch}/${info.bitness}  ${shortenPath(db.idbPath)}${running}`;
                });
                return result.text(lines.join("\n")).done();
            }
            case "open": {
                const ref = requireArg(params.db, "db", params.action);
                const db = await this.#resolveDb(ref, true, signal);
                details.db = db.id;
                const { module, format, arch, bitness } = db.info;
                return result
                    .text(`Opened ${db.id} (${module}, ${format}, ${arch} ${bitness}-bit) → ${shortenPath(db.idbPath)}. read ${shortenPath(db.ref)} for the overview.`)
                    .done();
            }
            case "save": {
                const db = await this.#resolveDb(params.db, false, signal);
                details.db = db.id;
                const { idb } = await db.request("save", {}, { signal, timeoutMs: IDA_EDIT_TIMEOUT_MS });
                return result.text(`Saved ${shortenPath(idb)}`).done();
            }
            case "close": {
                const db = await this.#resolveDb(params.db, false, signal);
                details.db = db.id;
                const save = params.save ?? true;
                await db.close({ save });
                return result.text(`Closed ${db.id}${save ? " (saved)" : " (discarded unsaved changes)"}`).done();
            }
            case "rename": {
                const target = requireArg(params.target, "target", params.action);
                const name = requireArg(params.name, "name", params.action);
                const db = await this.#resolveDb(params.db, true, signal);
                details.db = db.id;
                const res = await db.request("rename", { target, name }, { signal, timeoutMs: IDA_EDIT_TIMEOUT_MS });
                return result.text(`Renamed ${res.ea} ${res.old || "(unnamed)"} → ${res.new}`).done();
            }
            case "comment": {
                const target = requireArg(params.target, "target", params.action);
                const text = requireArg(params.text, "text", params.action);
                const db = await this.#resolveDb(params.db, true, signal);
                details.db = db.id;
                const repeatable = params.repeatable ?? false;
                const res = await db.request("comment", { target, text, repeatable }, { signal, timeoutMs: IDA_EDIT_TIMEOUT_MS });
                return result.text(`Set ${repeatable ? "repeatable " : ""}comment at ${res.ea}`).done();
            }
            case "set_type": {
                const target = requireArg(params.target, "target", params.action);
                const decl = requireArg(params.decl, "decl", params.action);
                const db = await this.#resolveDb(params.db, true, signal);
                details.db = db.id;
                const res = await db.request("set_type", { target, decl }, { signal, timeoutMs: IDA_EDIT_TIMEOUT_MS });
                return result.text(`Typed ${res.ea} as ${res.type}`).done();
            }
            case "make_function": {
                const target = requireArg(params.target, "target", params.action);
                const db = await this.#resolveDb(params.db, true, signal);
                details.db = db.id;
                const res = await db.request("make_function", { target }, { signal, timeoutMs: IDA_EDIT_TIMEOUT_MS });
                return result.text(`Created function ${res.name} at ${res.ea}`).done();
            }
            case "exec": {
                const code = requireArg(params.code, "code", params.action);
                const db = await this.#resolveDb(params.db, true, signal);
                details.db = db.id;
                const timeoutSec = clampTimeout("ida", params.timeout, cfgToolsMaxTimeout.get(this.session.settings));
                const res = await db.request("exec", { code }, { signal, timeoutMs: timeoutSec * 1000 });
                const parts = [];
                if (res.output)
                    parts.push(res.output.trimEnd());
                if (res.value !== null)
                    parts.push(`=> ${res.value}`);
                if (res.error !== null)
                    parts.push(res.error.trimEnd());
                const text = await enforceInlineByteCap(parts.length > 0 ? parts.join("\n") : "(no output)", {
                    saveArtifact: full => saveArtifactText(this.session, "ida", full).catch(() => undefined),
                });
                return result
                    .text(text)
                    .error(res.error !== null)
                    .done();
            }
        }
    }
    /** Resolve `db` (id, path, or omitted) to an open database; `open` opens/creates it when needed. */
    async #resolveDb(ref, open, signal) {
        if (!ref) {
            const dbs = (await listIdaDatabases(this.session)).filter(db => db.status.state === "open");
            if (dbs.length === 0)
                throw new ToolError("No IDA database open; pass db=<binary path>");
            if (dbs.length > 1)
                throw new ToolError(`Multiple IDA databases open (${dbs.map(db => db.id).join(", ")}); pass db`);
            return dbs[0];
        }
        const byId = await findOpenIdaDatabase(this.session, ref);
        if (byId)
            return byId;
        const { path: sourcePath, arch } = splitSliceRef(ref);
        const abs = resolveToCwd(sourcePath, this.session.cwd);
        const stat = await fs.stat(abs).catch(() => null);
        if (!stat?.isFile())
            throw new ToolError(`db not found: ${ref}`);
        if (open)
            return acquireIdaDatabase(this.session, abs, { arch, signal });
        const loc = await locateIdb(abs, { arch });
        const db = await findOpenIdaDatabase(this.session, loc.id);
        if (!db)
            throw new ToolError(`${ref} is not open`);
        return db;
    }
}
