import { ToolError } from "@rva/tui/tools/tool-errors";
/** Registers, removes, and lists document-start scripts for one page. */
export class InitScriptManager {
    #page;
    #scripts = new Map();
    constructor(page) {
        this.#page = page;
    }
    /** Register source for every future document and return its stable identifier. */
    async add(source) {
        if (typeof source !== "string")
            throw new ToolError("tab.addInitScript(source) requires a string");
        const registered = await this.#page.evaluateOnNewDocument(source);
        const info = { id: registered.identifier, source };
        this.#scripts.set(info.id, info);
        return { id: info.id };
    }
    /** Remove one previously registered script. */
    async remove(id) {
        if (typeof id !== "string" || id.length === 0) {
            throw new ToolError("tab.removeInitScript(id) requires a non-empty script id");
        }
        if (!this.#scripts.has(id))
            throw new ToolError(`Unknown init script ${JSON.stringify(id)}`);
        await this.#page.removeScriptToEvaluateOnNewDocument(id);
        this.#scripts.delete(id);
    }
    /** Return registered scripts in registration order. */
    list() {
        return [...this.#scripts.values()].map(script => ({ ...script }));
    }
}
