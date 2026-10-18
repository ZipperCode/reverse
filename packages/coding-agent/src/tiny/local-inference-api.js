import { AssistantMessageEventStream } from "@rva/ai/utils/event-stream";
import { registerCustomApi } from "@rva/ai/api-registry";
import { isTinyLocalModelKey } from "./models";
import { tinyModelClient } from "./title-client";
const LOCAL_INFERENCE_API = "local-inference";
const LOCAL_INFERENCE_SOURCE = "omp/local-inference";
const LOCAL_INFERENCE_NO_OUTPUT = "Local inference returned no output.";
const LOCAL_INFERENCE_ABORTED = "Local inference request aborted.";
function zeroUsage() {
    return {
        input: 0,
        output: 0,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 0,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    };
}
function createAssistantMessage(model) {
    return {
        role: "assistant",
        content: [],
        api: model.api,
        provider: model.provider,
        model: model.id,
        usage: zeroUsage(),
        stopReason: "stop",
        timestamp: Date.now(),
    };
}
function textFromContent(content) {
    if (typeof content === "string")
        return content;
    let text = "";
    for (const block of content) {
        if (block.type === "text" && block.text !== undefined)
            text += block.text;
    }
    return text;
}
function messageText(message) {
    if (message.role === "assistant") {
        let text = "";
        for (const block of message.content) {
            if (block.type === "text")
                text += block.text;
        }
        return text;
    }
    return textFromContent(message.content);
}
function joinTurnText(left, right) {
    if (!left)
        return right;
    if (!right)
        return left;
    return `${left}\n\n${right}`;
}
/** Convert unified conversation context into the tiny worker's chat format. */
export function buildLocalInferenceMessages(context) {
    const messages = [];
    for (const content of context.systemPrompt ?? [])
        messages.push({ role: "system", content });
    let pendingAssistant = "";
    for (const message of context.messages) {
        const content = messageText(message);
        if (message.role === "assistant") {
            pendingAssistant = joinTurnText(pendingAssistant, content);
            continue;
        }
        if (message.role === "developer") {
            messages.push({ role: "system", content });
            continue;
        }
        const userContent = joinTurnText(pendingAssistant, content);
        pendingAssistant = "";
        if (userContent)
            messages.push({ role: "user", content: userContent });
    }
    if (pendingAssistant)
        messages.push({ role: "user", content: pendingAssistant });
    return messages;
}
function emitError(stream, output, reason, message) {
    output.stopReason = reason;
    output.errorMessage = message;
    stream.push({ type: "error", reason, error: output });
}
async function runLocalInference(stream, output, model, context, options) {
    if (model.api !== LOCAL_INFERENCE_API || !isTinyLocalModelKey(model.id)) {
        emitError(stream, output, "error", `Local inference cannot run model ${model.provider}/${model.id}.`);
        return;
    }
    try {
        const text = await tinyModelClient.chat(model.id, buildLocalInferenceMessages(context), {
            maxTokens: options?.maxTokens,
            signal: options?.signal,
        });
        if (!text) {
            if (options?.signal?.aborted) {
                const reason = options.signal.reason;
                const message = reason instanceof Error ? reason.message : LOCAL_INFERENCE_ABORTED;
                emitError(stream, output, "aborted", message);
            }
            else {
                emitError(stream, output, "error", LOCAL_INFERENCE_NO_OUTPUT);
            }
            return;
        }
        output.content.push({ type: "text", text });
        stream.push({ type: "text_start", contentIndex: 0, partial: output });
        stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: output });
        stream.push({ type: "text_end", contentIndex: 0, content: text, partial: output });
        stream.push({ type: "done", reason: "stop", message: output });
    }
    catch (error) {
        if (options?.signal?.aborted) {
            const reason = options.signal.reason;
            const message = reason instanceof Error ? reason.message : LOCAL_INFERENCE_ABORTED;
            emitError(stream, output, "aborted", message);
            return;
        }
        const message = error instanceof Error ? error.message : String(error);
        emitError(stream, output, "error", message);
    }
}
/** Stream a tiny local model completion through the shared assistant event protocol. */
export function streamLocalInferenceSimple(model, context, options) {
    const stream = new AssistantMessageEventStream();
    const output = createAssistantMessage(model);
    stream.push({ type: "start", partial: output });
    void runLocalInference(stream, output, model, context, options);
    return stream;
}
/** Register the local-inference transport with the shared API registry. */
export function registerLocalInferenceApi() {
    registerCustomApi(LOCAL_INFERENCE_API, streamLocalInferenceSimple, LOCAL_INFERENCE_SOURCE);
}
