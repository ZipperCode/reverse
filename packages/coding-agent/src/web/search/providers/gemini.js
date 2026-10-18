/**
 * Google Gemini Web Search Provider
 *
 * Uses Gemini's Google Search grounding via Cloud Code Assist API.
 * Cloud Code Assist auth is resolved through `AuthStorage.oauth.access(...)`
 * for the selected catalog provider; developer API auth uses the selected
 * model's registry resolver. The broker is the sole refresh authority, so this module never opens a
 * sibling SQLite store and never POSTs the broker sentinel to a Google token
 * endpoint.
 */
import { withAuth, withOAuthAccess, } from "@rva/ai";
import { clampThinkingLevelForModel, resolveWireModelId } from "@rva/catalog/model-thinking";
import { parseCloudflareCredential } from "@rva/catalog/wire/cloudflare";
import { getAntigravityUserAgent, getGeminiCliHeaders } from "@rva/catalog/wire/gemini-headers";
import { concreteThinkingLevel, toReasoningEffort } from "@rva/tui/thinking";
import { fetchWithRetry, USER_AGENT } from "@rva/utils";
import { SearchProviderError } from "../../../web/search/types";
import { formatQuery, GOOGLE_QUERY_SYNTAX, parseSearchQuery } from "../query";
import { SearchProvider } from "./base";
import { classifyProviderHttpError, withHardTimeout } from "./utils";
const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;
const RATE_LIMIT_BUDGET_MS = 5 * 60 * 1000;
function resolveGeminiDeveloperEndpoint(baseUrl) {
    const url = baseUrl.trim().replace(/\/+$/, "");
    let parsed;
    try {
        parsed = new URL(url);
    }
    catch {
        throw new SearchProviderError("gemini", `Gemini model base URL must be a valid absolute URL: ${baseUrl}`, 400);
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        throw new SearchProviderError("gemini", "Gemini model base URL must use HTTP or HTTPS", 400);
    }
    return {
        url,
        isCloudflareGateway: parsed.hostname === "gateway.ai.cloudflare.com",
    };
}
export function buildGeminiRequestTools(params) {
    const tools = [{ googleSearch: params.google_search ?? {} }];
    if (params.code_execution !== undefined) {
        tools.push({ codeExecution: params.code_execution });
    }
    if (params.url_context !== undefined) {
        tools.push({ urlContext: params.url_context });
    }
    return tools;
}
/** Resolve the selected Gemini provider's OAuth access and required project identity. */
export async function findGeminiAuth(authStorage, provider, sessionId, signal) {
    const access = await authStorage.oauth.access(provider, sessionId, { signal });
    if (!access?.accessToken || !access.projectId)
        return null;
    return { provider, access, projectId: access.projectId };
}
async function parseGeminiSearchStream(body, fallbackModel) {
    const answerParts = [];
    const sources = [];
    const citations = [];
    const searchQueries = [];
    const seenUrls = new Set();
    let model = fallbackModel;
    let usage;
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split("\n");
            buffer = lines.pop() || "";
            for (const line of lines) {
                if (!line.startsWith("data:"))
                    continue;
                const jsonStr = line.slice(5).trim();
                if (!jsonStr)
                    continue;
                let chunk;
                try {
                    chunk = JSON.parse(jsonStr);
                }
                catch {
                    continue;
                }
                const responseData = chunk.response ?? chunk;
                const candidate = responseData.candidates?.[0];
                if (candidate?.content?.parts) {
                    for (const part of candidate.content.parts) {
                        if (part.text) {
                            answerParts.push(part.text);
                        }
                    }
                }
                const groundingMetadata = candidate?.groundingMetadata;
                if (groundingMetadata) {
                    if (groundingMetadata.groundingChunks) {
                        for (const grChunk of groundingMetadata.groundingChunks) {
                            if (grChunk.web?.uri) {
                                const sourceUrl = grChunk.web.uri;
                                if (!seenUrls.has(sourceUrl)) {
                                    seenUrls.add(sourceUrl);
                                    sources.push({
                                        title: grChunk.web.title ?? sourceUrl,
                                        url: sourceUrl,
                                    });
                                }
                            }
                        }
                    }
                    if (groundingMetadata.groundingSupports && groundingMetadata.groundingChunks) {
                        for (const support of groundingMetadata.groundingSupports) {
                            const citedText = support.segment?.text;
                            const chunkIndices = support.groundingChunkIndices ?? [];
                            for (const idx of chunkIndices) {
                                const grChunk = groundingMetadata.groundingChunks[idx];
                                if (grChunk?.web?.uri) {
                                    citations.push({
                                        url: grChunk.web.uri,
                                        title: grChunk.web.title ?? grChunk.web.uri,
                                        citedText,
                                    });
                                }
                            }
                        }
                    }
                    if (groundingMetadata.webSearchQueries) {
                        for (const q of groundingMetadata.webSearchQueries) {
                            if (!searchQueries.includes(q)) {
                                searchQueries.push(q);
                            }
                        }
                    }
                }
                if (responseData.usageMetadata) {
                    usage = {
                        inputTokens: responseData.usageMetadata.promptTokenCount ?? 0,
                        outputTokens: responseData.usageMetadata.candidatesTokenCount ?? 0,
                        totalTokens: responseData.usageMetadata.totalTokenCount ?? 0,
                    };
                }
                if (responseData.modelVersion) {
                    model = responseData.modelVersion;
                }
            }
        }
    }
    finally {
        reader.releaseLock();
    }
    return {
        answer: answerParts.join(""),
        sources,
        citations,
        searchQueries,
        model,
        usage,
    };
}
function isGroundingRedirectUrl(url) {
    try {
        const parsed = new URL(url);
        return (parsed.hostname === "vertexaisearch.cloud.google.com" && parsed.pathname.includes("/grounding-api-redirect"));
    }
    catch {
        return false;
    }
}
async function resolveGroundingRedirect(proxyUrl, fetchImpl, signal) {
    try {
        const response = await (fetchImpl ?? fetch)(proxyUrl, {
            method: "HEAD",
            redirect: "manual",
            signal: withHardTimeout(signal, 5000),
        });
        const location = response.headers.get("location");
        if (!location)
            return proxyUrl;
        const resolved = new URL(location, proxyUrl);
        return resolved.protocol === "http:" || resolved.protocol === "https:" ? resolved.toString() : proxyUrl;
    }
    catch {
        return proxyUrl;
    }
}
async function finalizeGeminiSearchResult(result, fetchImpl, signal) {
    if (!result.answer && result.sources.length === 0) {
        throw new SearchProviderError("gemini", "Gemini API returned an empty grounded response", 502);
    }
    const redirectUrls = new Set();
    for (const source of result.sources) {
        if (isGroundingRedirectUrl(source.url))
            redirectUrls.add(source.url);
    }
    for (const citation of result.citations) {
        if (isGroundingRedirectUrl(citation.url))
            redirectUrls.add(citation.url);
    }
    if (redirectUrls.size === 0)
        return result;
    signal?.throwIfAborted();
    const resolvedEntries = await Promise.all([...redirectUrls].map(async (url) => [url, await resolveGroundingRedirect(url, fetchImpl, signal)]));
    signal?.throwIfAborted();
    const resolvedUrls = new Map(resolvedEntries);
    for (const source of result.sources) {
        source.url = resolvedUrls.get(source.url) ?? source.url;
    }
    for (const citation of result.citations) {
        citation.url = resolvedUrls.get(citation.url) ?? citation.url;
    }
    const seenUrls = new Set();
    let writeIndex = 0;
    for (const source of result.sources) {
        if (seenUrls.has(source.url))
            continue;
        seenUrls.add(source.url);
        result.sources[writeIndex++] = source;
    }
    result.sources.length = writeIndex;
    return result;
}
/**
 * Calls the Cloud Code Assist API with Google Search grounding enabled.
 *
 * If a request returns a refreshable auth failure (401/403/auth-flavoured 400),
 * we ask AuthStorage to invalidate + refresh the credential and retry once.
 * Provider-direct refresh helpers are intentionally not used: AuthStorage owns
 * the single-flight refresh and broker round-trip.
 */
async function callGeminiSearch(auth, model, baseUrl, configuredHeaders, query, systemPrompt, maxOutputTokens, temperature, toolParams, fetchImpl, signal, timeoutMs) {
    const endpoint = baseUrl.replace(/\/+$/, "");
    const headers = auth.isAntigravity ? { "User-Agent": getAntigravityUserAgent() } : getGeminiCliHeaders();
    const requestMetadata = auth.isAntigravity
        ? {
            requestType: "agent",
            userAgent: "antigravity",
            requestId: `agent-${crypto.randomUUID()}`,
        }
        : {
            userAgent: USER_AGENT,
            requestId: `omp-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`,
        };
    const normalizedSystemPrompt = systemPrompt?.toWellFormed();
    const systemInstructionParts = normalizedSystemPrompt
        ? [{ text: normalizedSystemPrompt }]
        : [];
    const requestBody = {
        project: auth.projectId,
        model,
        request: {
            contents: [
                {
                    role: "user",
                    parts: [{ text: query }],
                },
            ],
            tools: buildGeminiRequestTools(toolParams),
            ...(systemInstructionParts.length > 0 && {
                systemInstruction: {
                    ...(auth.isAntigravity ? { role: "user" } : {}),
                    parts: systemInstructionParts,
                },
            }),
        },
        ...requestMetadata,
    };
    if (maxOutputTokens !== undefined || temperature !== undefined) {
        const generationConfig = {};
        if (maxOutputTokens !== undefined) {
            generationConfig.maxOutputTokens = maxOutputTokens;
        }
        if (temperature !== undefined) {
            generationConfig.temperature = temperature;
        }
        requestBody.request.generationConfig = generationConfig;
    }
    const response = await fetchWithRetry(() => `${endpoint}/v1internal:streamGenerateContent?alt=sse`, {
        method: "POST",
        headers: {
            ...configuredHeaders,
            Authorization: `Bearer ${auth.accessToken}`,
            "Content-Type": "application/json",
            Accept: "text/event-stream",
            ...headers,
        },
        body: JSON.stringify(requestBody),
        signal: withHardTimeout(signal, timeoutMs),
        fetch: fetchImpl,
        maxAttempts: MAX_RETRIES + 1,
        defaultDelayMs: attempt => BASE_DELAY_MS * 2 ** attempt,
        maxDelayMs: RATE_LIMIT_BUDGET_MS,
    });
    if (!response.ok) {
        const rawErrorText = await response.text();
        const errorText = auth.accessToken ? rawErrorText.split(auth.accessToken).join("[redacted]") : rawErrorText;
        const status = response.status;
        const classified = classifyProviderHttpError("gemini", status, errorText);
        if (classified)
            throw classified;
        throw new SearchProviderError("gemini", `Gemini Cloud Code API error (${status}): ${errorText}`, status);
    }
    if (!response.body) {
        throw new SearchProviderError("gemini", "Gemini API returned no response body", 500);
    }
    return finalizeGeminiSearchResult(await parseGeminiSearchStream(response.body, model), fetchImpl, signal);
}
async function callGeminiDeveloperSearch(apiKey, endpoint, configuredHeaders, model, query, systemPrompt, maxOutputTokens, temperature, toolParams, fetchImpl, signal, timeoutMs) {
    const normalizedSystemPrompt = systemPrompt?.toWellFormed();
    const requestBody = {
        contents: [
            {
                role: "user",
                parts: [{ text: query }],
            },
        ],
        tools: buildGeminiRequestTools(toolParams),
        ...(normalizedSystemPrompt && {
            systemInstruction: {
                parts: [{ text: normalizedSystemPrompt }],
            },
        }),
    };
    if (maxOutputTokens !== undefined || temperature !== undefined) {
        const generationConfig = {};
        if (maxOutputTokens !== undefined) {
            generationConfig.maxOutputTokens = maxOutputTokens;
        }
        if (temperature !== undefined) {
            generationConfig.temperature = temperature;
        }
        requestBody.generationConfig = generationConfig;
    }
    const response = await fetchWithRetry(() => `${endpoint.url}/models/${model}:streamGenerateContent?alt=sse`, {
        method: "POST",
        headers: {
            ...configuredHeaders,
            ...(endpoint.isCloudflareGateway
                ? { "cf-aig-authorization": `Bearer ${apiKey}` }
                : { "x-goog-api-key": apiKey }),
            "Content-Type": "application/json",
            Accept: "text/event-stream",
        },
        body: JSON.stringify(requestBody),
        signal: withHardTimeout(signal, timeoutMs),
        fetch: fetchImpl,
        maxAttempts: MAX_RETRIES + 1,
        defaultDelayMs: attempt => BASE_DELAY_MS * 2 ** attempt,
        maxDelayMs: RATE_LIMIT_BUDGET_MS,
    });
    if (!response.ok) {
        const rawErrorText = await response.text();
        const errorText = apiKey ? rawErrorText.split(apiKey).join("[redacted]") : rawErrorText;
        const classified = classifyProviderHttpError("gemini", response.status, errorText);
        if (classified)
            throw classified;
        throw new SearchProviderError("gemini", `Gemini Developer API error (${response.status}): ${errorText}`, response.status);
    }
    if (!response.body) {
        throw new SearchProviderError("gemini", "Gemini API returned no response body", 500);
    }
    return finalizeGeminiSearchResult(await parseGeminiSearchStream(response.body, model), fetchImpl, signal);
}
/**
 * Executes a web search using Google Gemini with Google Search grounding.
 */
export async function searchGemini(params) {
    // Clamp like chat does so an unsupported level (`:xhigh` on a high-capped
    // family) lands on the nearest routed tier instead of the default wire id.
    const selectedModel = resolveWireModelId(params.model, clampThinkingLevelForModel(params.model, toReasoningEffort(concreteThinkingLevel(params.thinkingLevel))));
    // Gemini's googleSearch grounding forwards the query to Google Search, which
    // understands the classic operator set natively. Normalize directive aliases
    // (domain: → site:, since: → after:, …) to canonical Google forms; leave
    // directive-free queries byte-identical.
    const parsed = params.parsedQuery ?? parseSearchQuery(params.query);
    const searchQuery = parsed.hasDirectives ? formatQuery(parsed, GOOGLE_QUERY_SYNTAX) : params.query;
    let result;
    if (params.model.api === "google-gemini-cli") {
        const seed = await findGeminiAuth(params.authStorage, params.model.provider, params.sessionId, params.signal);
        if (!seed) {
            throw new Error(`No Gemini OAuth credentials found for selected provider "${params.model.provider}".`);
        }
        const isAntigravity = params.model.provider === "google-antigravity";
        result = await withOAuthAccess(params.authStorage, seed.provider, async (access) => {
            // Derive bearer + projectId from the access this attempt received; a
            // re-resolved access may omit projectId, in which case the seed's
            // project is still the right tenant for the credential.
            const configuredHeaders = await params.modelRegistry.resolveModelHeaders(params.model, params.signal);
            return callGeminiSearch({
                accessToken: access.accessToken,
                projectId: access.projectId ?? seed.projectId,
                isAntigravity,
            }, selectedModel, params.model.baseUrl, configuredHeaders, searchQuery, params.system_prompt, params.max_output_tokens, params.temperature, {
                google_search: params.google_search,
                code_execution: params.code_execution,
                url_context: params.url_context,
            }, params.fetch, params.signal, params.timeoutMs);
        }, { sessionId: params.sessionId, signal: params.signal, seed: seed.access });
    }
    else if (params.model.api === "google-generative-ai") {
        const endpoint = resolveGeminiDeveloperEndpoint(params.model.baseUrl);
        const keyOrResolver = params.modelRegistry.resolver(params.model, params.sessionId);
        result = await withAuth(keyOrResolver, async (storedApiKey) => {
            const configuredHeaders = await params.modelRegistry.resolveModelHeaders(params.model, params.signal);
            const apiKey = endpoint.isCloudflareGateway ? parseCloudflareCredential(storedApiKey)?.token : storedApiKey;
            if (!apiKey) {
                throw new SearchProviderError("gemini", "Selected Gemini credential is empty", 401);
            }
            return callGeminiDeveloperSearch(apiKey, endpoint, configuredHeaders, selectedModel, searchQuery, params.system_prompt, params.max_output_tokens, params.temperature, {
                google_search: params.google_search,
                code_execution: params.code_execution,
                url_context: params.url_context,
            }, params.fetch, params.signal, params.timeoutMs);
        }, {
            signal: params.signal,
            missingKeyMessage: `No Gemini credentials found for selected provider "${params.model.provider}".`,
        });
    }
    else {
        throw new SearchProviderError("gemini", `Selected model ${params.model.provider}/${params.model.id} does not use a Gemini grounding transport`, 400);
    }
    let sources = result.sources;
    if (params.num_results && sources.length > params.num_results) {
        sources = sources.slice(0, params.num_results);
    }
    return {
        provider: "gemini",
        answer: result.answer || undefined,
        sources,
        citations: result.citations.length > 0 ? result.citations : undefined,
        searchQueries: result.searchQueries.length > 0 ? result.searchQueries : undefined,
        usage: result.usage,
        model: result.model,
    };
}
/** Search provider for Google Gemini web search. */
export class GeminiProvider extends SearchProvider {
    id = "gemini";
    label = "Gemini";
    isAvailable(authStorage, model) {
        if (model) {
            if (model.api === "google-gemini-cli")
                return authStorage.credentials.hasOAuth(model.provider);
            if (model.api === "google-generative-ai")
                return authStorage.keys.source(model.provider) !== undefined;
            return false;
        }
        return (authStorage.credentials.hasOAuth("google-antigravity") ||
            authStorage.credentials.hasOAuth("google-gemini-cli") ||
            authStorage.keys.source("google") !== undefined);
    }
    search(params) {
        return searchGemini({
            query: params.query,
            parsedQuery: params.parsedQuery,
            system_prompt: params.systemPrompt,
            num_results: params.numSearchResults ?? params.limit,
            max_output_tokens: params.maxOutputTokens,
            temperature: params.temperature,
            google_search: params.googleSearch,
            code_execution: params.codeExecution,
            url_context: params.urlContext,
            signal: params.signal,
            timeoutMs: params.timeoutMs,
            authStorage: params.authStorage,
            model: params.model,
            thinkingLevel: params.thinkingLevel,
            modelRegistry: params.modelRegistry,
            sessionId: params.sessionId,
            fetch: params.fetch,
        });
    }
}
