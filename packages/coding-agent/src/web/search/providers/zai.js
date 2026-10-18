/**
 * Z.AI Web Search Provider
 *
 * Calls Z.AI's remote MCP server (`webSearchPrime`) and adapts results into
 * the unified SearchResponse shape used by the web search tool.
 */
import { getEnvApiKey, withAuth } from "@rva/ai";
import { isRecord } from "@rva/utils";
import { SearchProviderError } from "../../../web/search/types";
import { formatQuery, parseSearchQuery } from "../query";
import { dateToAgeSeconds } from "../utils";
import { SearchProvider } from "./base";
import { classifyProviderHttpError, withHardTimeout } from "./utils";
const ZAI_MCP_URL = "https://api.z.ai/api/mcp/web_search_prime/mcp";
const ZAI_TOOL_NAME = "web_search_prime";
const DEFAULT_NUM_RESULTS = 10;
/**
 * webSearchPrime exposes no native filter args (the Web Search API's
 * `search_domain_filter`/`search_recency_filter` are scoped to the
 * `search_pro_jina` engine, not `search-prime`), but its Bing-flavored
 * backend parses the common inline operators. Dates and language are left
 * to the central lenient post-filter.
 */
const ZAI_QUERY_SYNTAX = {
    phrases: true,
    negation: true,
    site: true,
    inTitle: true,
    inUrl: true,
    filetype: true,
};
const ZAI_MCP_PROTOCOL_VERSION = "2025-03-26";
const ZAI_MCP_CLIENT_INFO = {
    name: "omp-coding-agent",
    version: "1.0.0",
};
function asString(value) {
    if (typeof value !== "string")
        return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}
function parseZaiMcpResponse(rawText) {
    const parsedMessages = [];
    for (const line of rawText.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("data:"))
            continue;
        const data = trimmed.slice(5).trim();
        if (!data)
            continue;
        try {
            parsedMessages.push(JSON.parse(data));
        }
        catch {
            // Ignore non-JSON data events.
        }
    }
    if (parsedMessages.length === 0) {
        try {
            parsedMessages.push(JSON.parse(rawText));
        }
        catch {
            throw new SearchProviderError("zai", "Failed to parse Z.AI MCP response", 500);
        }
    }
    return parsedMessages[parsedMessages.length - 1];
}
async function postZaiMcp(apiKey, method, params, sessionId, signal, fetchImpl, expectResponse, timeoutMs) {
    const headers = {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
    };
    if (sessionId) {
        headers["Mcp-Session-Id"] = sessionId;
    }
    const body = {
        jsonrpc: "2.0",
        method,
        params,
    };
    if (expectResponse) {
        body.id = crypto.randomUUID();
    }
    const response = await fetchImpl(ZAI_MCP_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: withHardTimeout(signal, timeoutMs),
    });
    if (!response.ok) {
        const errorText = await response.text();
        const classified = classifyProviderHttpError("zai", response.status, errorText);
        if (classified)
            throw classified;
        throw new SearchProviderError("zai", `Z.AI MCP error (${response.status}): ${errorText}`, response.status);
    }
    const nextSessionId = response.headers.get("Mcp-Session-Id") ?? sessionId;
    if (!expectResponse) {
        await response.body?.cancel();
        return { sessionId: nextSessionId };
    }
    return {
        parsed: parseZaiMcpResponse(await response.text()),
        sessionId: nextSessionId,
    };
}
function readJsonRpcPayload(parsed) {
    const parsedRecord = isRecord(parsed) ? parsed : null;
    const directErrorCode = typeof parsedRecord?.code === "number" ? parsedRecord.code : undefined;
    const directErrorSuccess = parsedRecord?.success;
    const directErrorMessage = asString(parsedRecord?.msg) ?? asString(parsedRecord?.message) ?? asString(parsedRecord?.error_message);
    if (directErrorSuccess === false && directErrorMessage) {
        throw new SearchProviderError("zai", `Z.AI API error${directErrorCode ? ` (${directErrorCode})` : ""}: ${directErrorMessage}`, directErrorCode);
    }
    if (!isRecord(parsed)) {
        throw new SearchProviderError("zai", "Failed to parse Z.AI MCP response", 500);
    }
    const payload = parsed;
    if (payload.error) {
        const status = typeof payload.error.code === "number" ? payload.error.code : 400;
        throw new SearchProviderError("zai", `Z.AI MCP error${payload.error.code ? ` (${payload.error.code})` : ""}: ${payload.error.message ?? "Unknown error"}`, status);
    }
    return payload;
}
/** Resolve Z.AI API credentials through the unified auth storage pipeline. */
export async function findApiKey(authStorage, sessionId, signal) {
    return (await authStorage.keys.get("zai", sessionId, { signal })) ?? null;
}
async function callZaiTool(apiKey, args, signal, fetchImpl, timeoutMs) {
    const initialized = await postZaiMcp(apiKey, "initialize", {
        protocolVersion: ZAI_MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: ZAI_MCP_CLIENT_INFO,
    }, undefined, signal, fetchImpl, true, timeoutMs);
    if (initialized.parsed !== undefined) {
        readJsonRpcPayload(initialized.parsed);
    }
    await postZaiMcp(apiKey, "notifications/initialized", {}, initialized.sessionId, signal, fetchImpl, false, timeoutMs);
    const toolCall = await postZaiMcp(apiKey, "tools/call", {
        name: ZAI_TOOL_NAME,
        arguments: args,
    }, initialized.sessionId, signal, fetchImpl, true, timeoutMs);
    const payload = readJsonRpcPayload(toolCall.parsed);
    const resultRecord = isRecord(payload.result) ? payload.result : null;
    if (resultRecord?.isError === true) {
        const content = Array.isArray(resultRecord.content) ? resultRecord.content : [];
        const errorText = content
            .map(item => {
            if (!isRecord(item))
                return null;
            return asString(item.text);
        })
            .filter((text) => text != null)
            .join("\n")
            .trim();
        const statusMatch = errorText.match(/MCP error\s*(-?\d+)/i);
        const statusCode = statusMatch ? Math.abs(Number.parseInt(statusMatch[1], 10)) : 400;
        throw new SearchProviderError("zai", errorText || "Z.AI MCP tool call failed", statusCode);
    }
    if (payload.result !== undefined) {
        return payload.result;
    }
    return toolCall.parsed;
}
async function callZaiSearch(apiKey, params) {
    const count = params.num_results ?? DEFAULT_NUM_RESULTS;
    const fetchImpl = params.fetch ?? fetch;
    const attempts = [
        { query: params.query, count },
        { search_query: params.query, count },
        { search_query: params.query, search_engine: "search-prime", count },
    ];
    let lastError;
    for (let i = 0; i < attempts.length; i++) {
        try {
            return await callZaiTool(apiKey, attempts[i], params.signal, fetchImpl, params.timeoutMs);
        }
        catch (error) {
            lastError = error;
            const isLastAttempt = i === attempts.length - 1;
            if (isLastAttempt) {
                throw error;
            }
            if (!(error instanceof SearchProviderError)) {
                throw error;
            }
            const message = error.message.toLowerCase();
            const looksLikeArgError = error.status === 400 ||
                message.includes("invalid") ||
                message.includes("argument") ||
                message.includes("search_query") ||
                message.includes("query");
            if (!looksLikeArgError) {
                throw error;
            }
        }
    }
    throw lastError ?? new SearchProviderError("zai", "Z.AI search failed", 500);
}
function getSearchResults(value) {
    if (Array.isArray(value)) {
        return value;
    }
    if (!isRecord(value))
        return [];
    const obj = value;
    const searchResult = obj.search_result;
    if (Array.isArray(searchResult))
        return searchResult;
    const results = obj.results;
    if (Array.isArray(results))
        return results;
    return [];
}
function parseSearchPayload(rawResult) {
    const candidates = [rawResult];
    const textParts = [];
    if (isRecord(rawResult)) {
        if (rawResult.structuredContent)
            candidates.push(rawResult.structuredContent);
        if (rawResult.data)
            candidates.push(rawResult.data);
        if (rawResult.result)
            candidates.push(rawResult.result);
        const content = rawResult.content;
        if (Array.isArray(content)) {
            for (const part of content) {
                const text = isRecord(part) ? asString(part.text) : null;
                if (!text)
                    continue;
                try {
                    let parsed = JSON.parse(text);
                    if (typeof parsed === "string") {
                        try {
                            parsed = JSON.parse(parsed);
                        }
                        catch {
                            // The decoded string is answer text rather than another JSON payload.
                        }
                    }
                    candidates.push(parsed);
                    if (getSearchResults(parsed).length === 0)
                        textParts.push(text);
                }
                catch {
                    // Non-JSON content is preserved as answer text.
                    textParts.push(text);
                }
            }
        }
    }
    for (const candidate of candidates) {
        const results = getSearchResults(candidate);
        if (results.length > 0) {
            const obj = isRecord(candidate) ? candidate : null;
            return {
                results,
                answer: textParts.length > 0 ? textParts.join("\n\n") : undefined,
                requestId: obj?.request_id ?? obj?.requestId ?? obj?.id,
            };
        }
    }
    return {
        results: [],
        answer: textParts.length > 0 ? textParts.join("\n\n") : undefined,
    };
}
function toSources(results) {
    const sources = [];
    for (const result of results) {
        const url = asString(result.link) ?? asString(result.url);
        if (!url)
            continue;
        const publishedDate = asString(result.publish_date) ?? asString(result.publishedDate);
        sources.push({
            title: asString(result.title) ?? url,
            url,
            snippet: asString(result.content) ?? undefined,
            publishedDate: publishedDate ?? undefined,
            ageSeconds: dateToAgeSeconds(publishedDate),
            author: asString(result.media) ?? undefined,
        });
    }
    return sources;
}
/** Execute Z.AI web search via remote MCP endpoint. */
export async function searchZai(params) {
    const keyOrResolver = params.authStorage.keys.resolver("zai", {
        sessionId: params.sessionId,
    });
    const rawResult = await withAuth(keyOrResolver, key => callZaiSearch(key, params), {
        signal: params.signal,
        missingKeyMessage: "Z.AI credentials not found. Set ZAI_API_KEY or login with 'omp /login zai'.",
    });
    const payload = parseSearchPayload(rawResult);
    let sources = toSources(payload.results);
    if (params.num_results && sources.length > params.num_results) {
        sources = sources.slice(0, params.num_results);
    }
    return {
        provider: "zai",
        answer: payload.answer,
        sources,
        requestId: payload.requestId,
    };
}
/** Search provider for Z.AI web search MCP. */
export class ZaiProvider extends SearchProvider {
    id = "zai";
    label = "Z.AI";
    isAvailable(authStorage) {
        return authStorage.keys.source("zai") !== undefined || !!getEnvApiKey("zai");
    }
    search(params) {
        const { fetch: fetchOverride } = params;
        const parsed = params.parsedQuery ?? parseSearchQuery(params.query);
        return searchZai({
            query: parsed.hasDirectives ? formatQuery(parsed, ZAI_QUERY_SYNTAX) : params.query,
            num_results: params.numSearchResults ?? params.limit,
            signal: params.signal,
            timeoutMs: params.timeoutMs,
            authStorage: params.authStorage,
            sessionId: params.sessionId,
            fetch: fetchOverride,
        });
    }
}
