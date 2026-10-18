import { type } from "@rva/omptype";
import { prompt } from "@rva/utils";
import memoryEditDescription from "../prompts/tools/memory-edit.md" with { type: "text" };
import { sessionMemoryToolRefs } from "../memory-backend/tool-names";
import { cfgMemoryBackend } from "../memory-backend/settings";
const memoryEditSchema = type({
    op: type("'update' | 'forget' | 'invalidate'").describe("memory edit operation"),
    id: type("string").describe("memory id from recall output"),
    "content?": type("string").describe("replacement content for update"),
    "importance?": type("number").describe("replacement importance for update (0–1)"),
    "replacement_id?": type("string").describe("replacement memory id for invalidate"),
});
export class MemoryEditTool {
    session;
    name = "memory_edit";
    approval = "read";
    label = "Memory Edit";
    get description() {
        return prompt.render(memoryEditDescription, {
            toolRefs: sessionMemoryToolRefs(this.session),
        });
    }
    parameters = memoryEditSchema;
    strict = true;
    loadMode = "discoverable";
    summary = "Update, forget, or invalidate Mnemopi memories";
    constructor(session) {
        this.session = session;
    }
    static createIf(session) {
        const backend = cfgMemoryBackend.get(session.settings);
        if (backend !== "mnemopi")
            return null;
        return new MemoryEditTool(session);
    }
    async execute(_id, params) {
        const state = this.session.getMnemopiSessionState?.();
        if (!state) {
            throw new Error("Mnemopi backend is not initialised for this session.");
        }
        if (params.op === "update" && params.content === undefined && params.importance === undefined) {
            throw new Error("memory_edit update requires content or importance.");
        }
        const importance = params.importance === undefined ? undefined : Math.max(0, Math.min(1, params.importance));
        const result = state.editScopedMemory(params.op, params.id, {
            content: params.content,
            importance,
            replacementId: params.replacement_id,
        });
        const location = result.bank ? ` in bank ${result.bank}${result.store ? ` (${result.store})` : ""}` : "";
        const text = result.status === "not_found"
            ? `Memory ${params.id} was not found${location}.`
            : result.status === "not_editable"
                ? `Memory ${params.id} is a read-only fact${location}; it cannot be edited. Read it with memory://${params.id}.`
                : `Memory ${params.id} ${result.status}${location}.`;
        return {
            content: [{ type: "text", text }],
            details: result,
        };
    }
}
