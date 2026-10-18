import { type } from "@rva/omptype";
/** Whether a model transport can suppress native reasoning while private scratchpad thoughts are active. */
export function supportsExternalThinking(model) {
    if (!model)
        return false;
    const compat = model.compat;
    const requiresThinking = model.api === "anthropic-messages" &&
        compat !== undefined &&
        "requiresThinkingEnabled" in compat &&
        compat.requiresThinkingEnabled === true;
    if (model.reasoning && (requiresThinking || (model.thinking?.requiresEffort && !model.thinking.suppressWhenOff))) {
        return false;
    }
    // Transports that reject `reasoning.effort` (xAI Grok 4 and the other
    // reasoning-only Responses models) cannot honour `forceReasoningOff`, so the
    // scratchpad would run alongside native reasoning instead of replacing it.
    if (model.reasoning &&
        compat !== undefined &&
        (("omitReasoningEffort" in compat && compat.omitReasoningEffort === true) ||
            ("supportsReasoningEffort" in compat && compat.supportsReasoningEffort === false))) {
        return false;
    }
    if (model.api === "google-generative-ai" || model.api === "google-gemini-cli" || model.api === "google-vertex") {
        return !model.reasoning || model.thinking?.mode === "budget" || model.thinking?.suppressWhenOff === true;
    }
    return (model.api === "openai-responses" ||
        model.api === "azure-openai-responses" ||
        model.api === "openai-codex-responses" ||
        model.api === "anthropic-messages");
}
const thinkSchema = type({
    thoughts: type("string").describe("private scratchpad; not shown to user"),
    "+": "reject",
}).describe("private scratchpad; not shown to user");
/** Records private scratchpad thoughts while native model reasoning is disabled. */
export class ThinkTool {
    name = "think";
    approval = "read";
    label = "Think";
    summary = "Record private scratchpad thoughts";
    description = "private scratchpad; not shown to user";
    parameters = thinkSchema;
    strict = true;
    intent = "omit";
    async execute(_toolCallId, _params) {
        return {
            content: [
                {
                    type: "text",
                    text: "------",
                },
            ],
            details: { recorded: true },
        };
    }
}
