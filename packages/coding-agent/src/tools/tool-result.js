import { outputMeta } from "./output-meta";
export class ToolResultBuilder {
    #details;
    #meta = outputMeta();
    #content = [];
    #isError = false;
    #useless = false;
    constructor(details) {
        this.#details = details ?? {};
    }
    text(text) {
        this.#content = [{ type: "text", text }];
        return this;
    }
    content(content) {
        this.#content = content;
        return this;
    }
    truncation(result, options) {
        this.#meta.truncation(result, options);
        return this;
    }
    truncationFromSummary(summary, options) {
        this.#meta.truncationFromSummary(summary, options);
        return this;
    }
    truncationFromText(text, options) {
        this.#meta.truncationFromText(text, options);
        return this;
    }
    limits(limits) {
        this.#meta.limits(limits);
        return this;
    }
    sourceUrl(value) {
        this.#meta.sourceUrl(value);
        return this;
    }
    sourcePath(value) {
        this.#meta.sourcePath(value);
        return this;
    }
    sourceInternal(value) {
        this.#meta.sourceInternal(value);
        return this;
    }
    /** Mark the result as a bounded page of a file its source re-reads with line selectors. */
    pagedSource() {
        this.#meta.pagedSource();
        return this;
    }
    diagnostics(summary, messages) {
        this.#meta.diagnostics(summary, messages);
        return this;
    }
    /** Flag the result as a non-throwing failure (agent-loop surfaces it as a tool error). */
    error(value = true) {
        this.#isError = value;
        return this;
    }
    /** Marks the result contextually useless — compaction may elide it once consumed. */
    useless(value = true) {
        this.#useless = value;
        return this;
    }
    done() {
        const meta = this.#meta.get();
        if (meta) {
            this.#details.meta = meta;
        }
        const hasDetails = Object.entries(this.#details).some(([, value]) => value !== undefined);
        return {
            content: this.#content,
            details: hasDetails ? this.#details : undefined,
            ...(this.#isError ? { isError: true } : {}),
            ...(this.#useless && !this.#isError ? { useless: true } : {}),
        };
    }
}
export function toolResult(details) {
    return new ToolResultBuilder(details);
}
