import { completeSimple } from "@rva/ai";
import { prompt } from "@rva/utils";
import summaryPrompt from "./prompts/text-summary.md" with { type: "text" };
import { normalizeTextReviewContextSummary } from "./text-review";
/** Generate grounding context with the selected session model, never a hidden fallback model. */
export async function generateTextReviewContextSummary(ctx, sourceText, signal) {
    const model = ctx.model;
    if (!model)
        return undefined;
    const timeout = AbortSignal.timeout(60000);
    const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const message = await completeSimple(model, {
        systemPrompt: [prompt.render(summaryPrompt)],
        messages: [{ role: "user", content: sourceText, timestamp: Date.now() }],
    }, {
        apiKey: ctx.modelRegistry.resolver(model, ctx.sessionManager.getSessionId()),
        disableReasoning: true,
        maxTokens: 512,
        signal: requestSignal,
    });
    if (message.stopReason === "error" || message.stopReason === "aborted")
        return undefined;
    const completion = message.content
        .filter((part) => part.type === "text")
        .map(part => part.text)
        .join("");
    return normalizeTextReviewContextSummary(completion) || undefined;
}
