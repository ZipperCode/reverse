/**
 * Extension system types.
 *
 * Extensions are TypeScript modules that can:
 * - Subscribe to agent lifecycle events
 * - Register LLM-callable tools
 * - Register commands, keyboard shortcuts, and CLI flags
 * - Interact with the user via UI primitives
 */
export function getExtensionUISelectOptionLabel(option) {
    return typeof option === "string" ? option : option.label;
}
/** Answers an ask dialog whose timeout elapsed: each question gets its recommended option, else the first. */
export function timedOutAskDialogResult(questions) {
    return {
        kind: "submit",
        results: questions.map(question => {
            const labels = question.options.map(option => option.label);
            const fallbackIndex = Math.min(Math.max(question.recommended ?? 0, 0), Math.max(labels.length - 1, 0));
            const fallback = labels[fallbackIndex];
            return {
                id: question.id,
                question: question.question,
                options: labels,
                multi: question.multi ?? false,
                selectedOptions: fallback === undefined ? [] : [fallback],
                customInput: undefined,
                timedOut: true,
            };
        }),
    };
}
export function isToolCallEventType(toolName, event) {
    return event.toolName === toolName;
}
