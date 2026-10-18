import { getEnvApiKey } from "@rva/ai";
import { findCredential, withHardTimeout } from "./search/providers/utils";
const PARALLEL_API_URL = "https://api.parallel.ai";
export const PARALLEL_SEARCH_URL = `${PARALLEL_API_URL}/v1beta/search`;
const PARALLEL_EXTRACT_URL = `${PARALLEL_API_URL}/v1beta/extract`;
export const PARALLEL_BETA_HEADER = "search-extract-2025-10-10";
export class ParallelApiError extends Error {
    statusCode;
    constructor(message, statusCode) {
        super(message);
        this.name = "ParallelApiError";
        this.statusCode = statusCode;
    }
}
function isObject(value) {
    return typeof value === "object" && value !== null;
}
function getOwnValue(value, key) {
    return Object.getOwnPropertyDescriptor(value, key)?.value;
}
function getString(value, key) {
    const candidate = getOwnValue(value, key);
    return typeof candidate === "string" ? candidate : undefined;
}
function getNumber(value, key) {
    const candidate = getOwnValue(value, key);
    return typeof candidate === "number" && Number.isFinite(candidate) ? candidate : undefined;
}
function getObjectArray(value, key) {
    const candidate = getOwnValue(value, key);
    if (!Array.isArray(candidate))
        return [];
    return candidate.filter(isObject);
}
function getStringArray(value, key) {
    const candidate = getOwnValue(value, key);
    if (!Array.isArray(candidate))
        return [];
    return candidate.filter(item => typeof item === "string");
}
function extractParallelErrorMessage(payload) {
    if (!isObject(payload))
        return null;
    const directMessage = getString(payload, "message") ?? getString(payload, "detail") ?? getString(payload, "error");
    if (directMessage && directMessage.trim().length > 0) {
        return directMessage.trim();
    }
    const errorObject = getOwnValue(payload, "error");
    if (isObject(errorObject)) {
        const nestedMessage = getString(errorObject, "message") ?? getString(errorObject, "detail");
        if (nestedMessage && nestedMessage.trim().length > 0) {
            return nestedMessage.trim();
        }
    }
    return null;
}
function createParallelApiError(statusCode, detail) {
    return new ParallelApiError(detail ? `Parallel API error (${statusCode}): ${detail}` : `Parallel API error (${statusCode})`, statusCode);
}
export function parseParallelErrorResponse(statusCode, responseText) {
    const trimmedResponseText = responseText.trim();
    if (trimmedResponseText.length === 0) {
        return createParallelApiError(statusCode);
    }
    try {
        const payload = JSON.parse(trimmedResponseText);
        return createParallelApiError(statusCode, extractParallelErrorMessage(payload) ?? trimmedResponseText);
    }
    catch {
        return createParallelApiError(statusCode, trimmedResponseText);
    }
}
export async function parseParallelJsonResponse(response, operation) {
    try {
        return await response.json();
    }
    catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        throw new ParallelApiError(`Parallel ${operation} returned invalid JSON: ${detail}`);
    }
}
function getAuthHeaders(apiKey) {
    return {
        Accept: "application/json",
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "parallel-beta": PARALLEL_BETA_HEADER,
    };
}
function parseWarnings(payload) {
    if (!Array.isArray(payload))
        return [];
    const warnings = [];
    for (const item of payload) {
        if (typeof item === "string") {
            warnings.push(item);
            continue;
        }
        if (!isObject(item))
            continue;
        const message = getString(item, "message") ?? getString(item, "warning");
        if (message) {
            warnings.push(message);
        }
    }
    return warnings;
}
function parseUsageItems(payload) {
    if (!Array.isArray(payload))
        return [];
    const usageItems = [];
    for (const item of payload) {
        if (!isObject(item))
            continue;
        usageItems.push({
            name: getString(item, "name"),
            count: getNumber(item, "count"),
        });
    }
    return usageItems;
}
export function parseParallelSearchPayload(payload, options) {
    if (!isObject(payload)) {
        throw new ParallelApiError("Parallel search returned an invalid response payload.");
    }
    const requestId = getString(payload, "search_id") ?? "";
    const rawResults = getObjectArray(payload, "results");
    const sources = [];
    for (const item of rawResults) {
        const url = getString(item, "url");
        if (!url)
            continue;
        const excerpts = getStringArray(item, "excerpts");
        const snippet = excerpts.length > 0 ? excerpts.join("\n\n") : undefined;
        sources.push({
            title: getString(item, "title") ?? url,
            url,
            snippet,
            publishedDate: getString(item, "publish_date"),
            excerpts,
        });
    }
    const parseMetadata = options?.parseMetadata ?? true;
    return {
        requestId,
        sources,
        warnings: parseMetadata ? parseWarnings(getOwnValue(payload, "warnings")) : [],
        usage: parseMetadata ? parseUsageItems(getOwnValue(payload, "usage")) : [],
    };
}
export function findParallelApiKey(storage) {
    return findCredential(storage, getEnvApiKey("parallel"), "parallel");
}
export function getParallelExtractContent(document) {
    const excerptContent = document.excerpts
        .filter(excerpt => excerpt.trim().length > 0)
        .join("\n\n")
        .trim();
    if (excerptContent.length > 0) {
        return excerptContent;
    }
    return document.fullContent?.trim() ?? "";
}
function parseExtractPayload(payload) {
    if (!isObject(payload)) {
        throw new ParallelApiError("Parallel extract returned an invalid response payload.");
    }
    const requestId = getString(payload, "extract_id") ?? "";
    const resultItems = [];
    for (const item of getObjectArray(payload, "results")) {
        const url = getString(item, "url");
        if (!url)
            continue;
        resultItems.push({
            url,
            title: getString(item, "title"),
            publishedDate: getString(item, "publish_date"),
            excerpts: getStringArray(item, "excerpts"),
            fullContent: getString(item, "full_content"),
        });
    }
    const errors = [];
    for (const item of getObjectArray(payload, "errors")) {
        const url = getString(item, "url");
        if (!url)
            continue;
        errors.push({
            url,
            errorType: getString(item, "error_type"),
            httpStatusCode: getNumber(item, "http_status_code"),
            content: getString(item, "content"),
        });
    }
    return {
        requestId,
        results: resultItems,
        errors,
        warnings: parseWarnings(getOwnValue(payload, "warnings")),
        usage: parseUsageItems(getOwnValue(payload, "usage")),
    };
}
export async function searchWithParallel(objective, queries, options, storage) {
    const apiKey = findParallelApiKey(storage);
    if (!apiKey) {
        throw new ParallelApiError("Parallel credentials not found. Set PARALLEL_API_KEY or login with 'omp /login parallel'.");
    }
    const fetchImpl = options.fetch ?? fetch;
    const response = await fetchImpl(PARALLEL_SEARCH_URL, {
        method: "POST",
        headers: getAuthHeaders(apiKey),
        body: JSON.stringify({
            objective,
            search_queries: queries,
            mode: options.mode === "research" ? "one-shot" : "fast",
            excerpts: {
                max_chars_per_result: options.maxCharsPerResult ?? 10000,
            },
        }),
        signal: withHardTimeout(options.signal),
    });
    if (!response.ok) {
        throw parseParallelErrorResponse(response.status, await response.text());
    }
    const payload = await parseParallelJsonResponse(response, "search");
    return parseParallelSearchPayload(payload);
}
export async function extractWithParallel(urls, options, storage) {
    const apiKey = findParallelApiKey(storage);
    if (!apiKey) {
        throw new ParallelApiError("Parallel credentials not found. Set PARALLEL_API_KEY or login with 'omp /login parallel'.");
    }
    const fetchImpl = options.fetch ?? fetch;
    const response = await fetchImpl(PARALLEL_EXTRACT_URL, {
        method: "POST",
        headers: getAuthHeaders(apiKey),
        body: JSON.stringify({
            urls,
            objective: options.objective,
            search_queries: options.searchQueries,
            excerpts: options.excerpts ?? true,
            full_content: options.fullContent ?? false,
        }),
        signal: withHardTimeout(options.signal),
    });
    if (!response.ok) {
        throw parseParallelErrorResponse(response.status, await response.text());
    }
    const payload = await parseParallelJsonResponse(response, "extract");
    return parseExtractPayload(payload);
}
