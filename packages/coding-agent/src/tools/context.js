import { trackUserWaits } from "../extensibility/extensions/user-wait";
export class ToolContextStore {
    getBaseContext;
    trackUserWait;
    #uiContext;
    #hasUI = false;
    #toolNames = [];
    constructor(getBaseContext, 
    /** Runs each dialog a tool opens (`ask`, eval prelude approvals, computer control) as a wait for the user. */
    trackUserWait) {
        this.getBaseContext = getBaseContext;
        this.trackUserWait = trackUserWait;
    }
    getContext(toolCall) {
        return {
            ...this.getBaseContext(),
            ui: this.#uiContext,
            hasUI: this.#hasUI,
            toolNames: this.#toolNames,
            toolCall,
            // Loop-dispatched calls carry the loop's passive-context sink; direct
            // (non-loop) executors such as the Cursor bridge install their own.
            addAdditionalContext: toolCall?.addAdditionalContext,
        };
    }
    setUIContext(uiContext, hasUI) {
        this.#uiContext = this.trackUserWait ? trackUserWaits(uiContext, this.trackUserWait) : uiContext;
        this.#hasUI = hasUI;
    }
    setToolNames(names) {
        this.#toolNames = names;
    }
}
