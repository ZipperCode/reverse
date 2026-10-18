import { defaultLoadModeForToolName } from "../../tools/essential-tools";
import { applyToolProxy } from "../tool-proxy";
export class CustomToolAdapter {
    tool;
    getContext;
    strict;
    loadMode;
    constructor(tool, getContext) {
        this.tool = tool;
        this.getContext = getContext;
        applyToolProxy(tool, this);
        this.strict = tool.strict;
        this.loadMode = defaultLoadModeForToolName(tool.name, tool.loadMode);
    }
    execute(toolCallId, params, signal, onUpdate, context) {
        return this.tool.execute(toolCallId, params, onUpdate, context ?? this.getContext(), signal);
    }
    /**
     * Backward-compatible export of factory function for existing callers.
     * Prefer CustomToolAdapter constructor directly.
     */
    static wrap(tool, getContext) {
        return new CustomToolAdapter(tool, getContext);
    }
}
