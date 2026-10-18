import { completeSimple } from "@rva/ai";
import { toReasoningEffort } from "@rva/tui/thinking";
import { extractTextContent } from "../utils";
import { computeCommitCacheKey } from "./cache";
/** Omp's model/provider adapter for llm-git's parser-aware one-shot algorithm. */
export class OmpCommitInference {
    #targets;
    #config;
    #cache;
    #authStorage;
    #onProgress;
    #signal;
    #sessionId = Bun.randomUUIDv7();
    constructor(options) {
        const secondary = options.forcePrimaryForEveryRole ? options.primary : options.smol;
        this.#targets = {
            analysis: options.primary,
            summary: secondary,
            map: secondary,
            fast: secondary,
        };
        this.#config = options.config;
        this.#cache = options.cache;
        this.#authStorage = options.authStorage ?? null;
        this.#onProgress = options.onProgress;
        this.#signal = options.signal;
    }
    /** Run one request with cache lookup, parse validation, and exponential retries. */
    async complete(request, parse) {
        const target = this.#targets[request.role];
        const modelKey = `${target.model.provider}/${target.model.id}`;
        const reasoning = toReasoningEffort(target.thinkingLevel);
        const key = computeCommitCacheKey({
            operation: request.operation,
            model: modelKey,
            apiMode: target.model.api,
            toolName: request.toolName,
            systemPrompt: request.systemPrompt,
            userPrompt: request.userPrompt,
            reasoningEffort: reasoning,
        });
        if (request.cacheable !== false) {
            const cached = this.#cache?.get(key);
            if (cached) {
                try {
                    const parsed = parse({ text: cached.text, stopReason: cached.stopReason });
                    this.#onProgress?.(`Cache hit: ${request.progressLabel}`);
                    return parsed;
                }
                catch { }
            }
        }
        const requestJson = JSON.stringify({
            model: modelKey,
            system: request.systemPrompt,
            user: request.userPrompt,
            reasoning,
        });
        let lastError;
        for (let attempt = 1; attempt <= Math.max(1, this.#config.maxRetries); attempt += 1) {
            this.#signal?.throwIfAborted();
            let responseText = "";
            try {
                this.#onProgress?.(request.progressLabel);
                const timeout = AbortSignal.timeout(120000);
                const signal = this.#signal ? AbortSignal.any([this.#signal, timeout]) : timeout;
                const message = await completeSimple(target.model, {
                    systemPrompt: request.systemPrompt.trim() ? [request.systemPrompt] : undefined,
                    messages: [{ role: "user", content: request.userPrompt, timestamp: Date.now() }],
                }, {
                    apiKey: target.apiKey,
                    sessionId: this.#sessionId,
                    maxTokens: 16384,
                    reasoning,
                    signal,
                });
                responseText = extractTextContent(message);
                if (message.stopReason === "error")
                    throw new Error(message.errorMessage ?? "Provider error");
                if (!responseText.trim())
                    throw new Error("Empty model response");
                const raw = { text: responseText, stopReason: message.stopReason };
                const parsed = parse(raw);
                if (request.cacheable !== false) {
                    this.#cache?.put({
                        key,
                        model: modelKey,
                        operation: request.operation,
                        request: requestJson,
                        response: {
                            text: responseText,
                            stopReason: message.stopReason,
                            costUsd: message.usage.cost.total,
                        },
                    });
                }
                this.#cache?.recordUsage(modelKey, request.operation, message.usage);
                return parsed;
            }
            catch (error) {
                this.#signal?.throwIfAborted();
                lastError = error instanceof Error ? error : new Error(String(error));
                this.#cache?.putFailure({
                    key,
                    model: modelKey,
                    operation: request.operation,
                    request: requestJson,
                    response: responseText,
                    error: lastError.message,
                });
                if (attempt < this.#config.maxRetries) {
                    await Bun.sleep(Math.max(0, this.#config.initialBackoffMs) * 2 ** (attempt - 1));
                }
            }
        }
        throw lastError ?? new Error(`Max retries exceeded for ${request.operation}`);
    }
    /** Release the cache and auth-storage handles after generation completes. */
    dispose() {
        this.#cache?.close();
        this.#authStorage?.close();
    }
}
