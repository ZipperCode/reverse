import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { prompt } from "@rva/utils";
import contextNotesDescription from "../prompts/tools/context-notes.md" with { type: "text" };
import contextNotesTextDescription from "../prompts/tools/context-notes-text.md" with { type: "text" };
import newContextDescription from "../prompts/tools/new-context.md" with { type: "text" };
import { CONTEXT_NOTES_ENTRY_TYPE, getContextNotes, MAX_CONTEXT_NOTES_BYTES, } from "../session/context-notes";
import { cfgCompactionExperimentalContextManagement } from "../session/context-settings";
import { throwIfAborted } from "./tool-errors";
const contextNotesSchema = type({
    "text?": type("string").describe(prompt.render(contextNotesTextDescription, { maxBytes: MAX_CONTEXT_NOTES_BYTES })),
});
const newContextSchema = type({});
function resolveExperimentalContextSession(session) {
    if (cfgCompactionExperimentalContextManagement.get(session.settings) !== true || session.isDisposed?.()) {
        return undefined;
    }
    const manager = session.sessionManager;
    const ownerId = session.getSessionId?.();
    if (!manager || !ownerId || manager.getSessionId?.() !== ownerId)
        return undefined;
    return manager;
}
/**
 * Resolves the live session journal only when experimental context management is enabled and
 * owned by this ToolSession. The identity comparison prevents advisor tools from writing the
 * parent agent's notebook or resolving its raw history.
 */
export function getExperimentalContextSession(session) {
    const manager = resolveExperimentalContextSession(session);
    if (manager)
        return manager;
    if (cfgCompactionExperimentalContextManagement.get(session.settings) !== true) {
        throw new ToolError("Experimental context management is disabled.");
    }
    if (session.isDisposed?.()) {
        throw new ToolError("Experimental context management is unavailable because this session is disposed.");
    }
    throw new ToolError("Experimental context management is unavailable for this session.");
}
function createIfSupported(session, ToolClass) {
    return resolveExperimentalContextSession(session) ? new ToolClass(session) : null;
}
/** Reads or replaces the current branch's durable experimental notebook. */
export class ContextNotesTool {
    session;
    name = "context_notes";
    approval = (args) => args !== null && typeof args === "object" && Object.hasOwn(args, "text") ? "write" : "read";
    label = "Context Notes";
    description = contextNotesDescription;
    parameters = contextNotesSchema;
    // Strict-mode providers mark every property required, so an optional `text`
    // would force models to send `""` (a clear) just to read. Stay non-strict
    // so omitted `text` keeps meaning "read" while an explicit empty string clears.
    strict = false;
    loadMode = "essential";
    summary = "Read or replace persistent experimental context notes";
    constructor(session) {
        this.session = session;
    }
    static createIf(session) {
        return createIfSupported(session, ContextNotesTool);
    }
    async execute(_id, params, signal, _onUpdate, _context) {
        const manager = getExperimentalContextSession(this.session);
        throwIfAborted(signal);
        if (params.text !== undefined && typeof params.text !== "string") {
            throw new ToolError("context_notes text must be a string.");
        }
        if (params.text === undefined) {
            const notes = getContextNotes(manager.getBranch());
            return {
                content: [{ type: "text", text: notes?.text ?? "No context notes are stored for this session branch." }],
                details: notes ? { entryId: notes.entryId, text: notes.text } : { entryId: undefined, text: "" },
            };
        }
        const bytes = Buffer.byteLength(params.text, "utf8");
        if (bytes > MAX_CONTEXT_NOTES_BYTES) {
            throw new ToolError(`Context notes are ${bytes} bytes; the limit is ${MAX_CONTEXT_NOTES_BYTES} UTF-8 bytes. Shorten the notebook and use history://current/full to recover raw detail.`);
        }
        const ownerId = this.session.getSessionId?.();
        const branchLeafId = manager.getBranch().at(-1)?.id;
        await manager.ensureOnDisk();
        throwIfAborted(signal);
        const currentManager = getExperimentalContextSession(this.session);
        if (currentManager !== manager ||
            this.session.isDisposed?.() ||
            !ownerId ||
            this.session.getSessionId?.() !== ownerId ||
            manager.getSessionId?.() !== ownerId ||
            manager.getBranch().at(-1)?.id !== branchLeafId) {
            throw new ToolError("Experimental context notes were not saved because the session branch changed.");
        }
        const data = { version: 1, text: params.text };
        const entryId = manager.appendCustomEntry(CONTEXT_NOTES_ENTRY_TYPE, data);
        await manager.flush();
        return {
            content: [{ type: "text", text: "Context notes saved." }],
            details: { entryId, text: params.text, bytes },
        };
    }
}
/** Requests a fresh context window; the owning lifecycle consumes this turn-local signal. */
export class NewContextTool {
    session;
    name = "new_context";
    approval = "write";
    label = "New Context";
    description = newContextDescription;
    parameters = newContextSchema;
    strict = true;
    loadMode = "essential";
    summary = "Request a fresh context window";
    constructor(session) {
        this.session = session;
    }
    static createIf(session) {
        return createIfSupported(session, NewContextTool);
    }
    async execute(_id, _params, signal, _onUpdate, _context) {
        getExperimentalContextSession(this.session);
        throwIfAborted(signal);
        return {
            content: [{ type: "text", text: "New context window requested." }],
            details: { requested: true },
        };
    }
}
