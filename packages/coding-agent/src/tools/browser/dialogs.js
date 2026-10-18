import { ToolError } from "@rva/tui/tools/tool-errors";
/** Runtime controller for automatic and explicitly handled JavaScript dialogs. */
export class RuntimeDialogController {
    #page;
    #logFailure;
    #policy;
    #pending;
    #installed = false;
    constructor(page, logFailure) {
        this.#page = page;
        this.#logFailure = logFailure;
    }
    /** Install the page listeners exactly once. */
    observe() {
        if (this.#installed)
            return;
        this.#page.on("dialog", this.#onDialog);
        this.#page.on("framenavigated", this.#onFrameNavigated);
        this.#installed = true;
    }
    /** Remove listeners and forget any dialog that can no longer be handled. */
    dispose() {
        if (!this.#installed)
            return;
        this.#page.off("dialog", this.#onDialog);
        this.#page.off("framenavigated", this.#onFrameNavigated);
        this.#installed = false;
        this.#pending = undefined;
    }
    /** Return the current runtime dialog policy. */
    get policy() {
        return this.#policy;
    }
    /** Return a JSON-safe snapshot of the pending dialog. */
    state() {
        const dialog = this.#pending;
        if (!dialog)
            return { open: false };
        const type = dialog.type();
        return {
            open: true,
            type,
            message: dialog.message(),
            ...(type === "prompt" ? { defaultValue: dialog.defaultValue() } : {}),
        };
    }
    /** Change the automatic policy and settle an already-pending decision when enabled. */
    async setPolicy(policy) {
        this.#policy = policy ?? undefined;
        if (!this.#policy || !this.#pending)
            return;
        await this.#settle(this.#pending, this.#policy === "accept", undefined);
    }
    /** Explicitly accept or dismiss the pending confirm or prompt. */
    async handle(options) {
        const dialog = this.#pending;
        if (!dialog)
            throw new ToolError("tab.handleDialog() found no pending confirm or prompt");
        await this.#settle(dialog, options.accept, options.text);
    }
    #onDialog = (dialog) => {
        const policy = this.#policy;
        if (policy) {
            void this.#settle(dialog, policy === "accept", undefined).catch(error => this.#report(error, policy));
            return;
        }
        const type = dialog.type();
        if (type === "alert" || type === "beforeunload") {
            void this.#settle(dialog, true, undefined).catch(error => this.#report(error, "accept"));
            return;
        }
        this.#pending = dialog;
    };
    #onFrameNavigated = (frame) => {
        if (frame === this.#page.mainFrame())
            this.#pending = undefined;
    };
    async #settle(dialog, accept, text) {
        try {
            if (accept)
                await dialog.accept(text);
            else
                await dialog.dismiss();
        }
        finally {
            if (this.#pending === dialog)
                this.#pending = undefined;
        }
    }
    #report(error, policy) {
        this.#logFailure("Dialog auto-handler failed", {
            policy,
            error: error instanceof Error ? error.message : String(error),
        });
    }
}
