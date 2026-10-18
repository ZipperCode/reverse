/**
 * Synthetic Web Search Provider
 *
 * Uses Synthetic's zero-data-retention web search API for coding agents.
 * Endpoint: POST https://api.synthetic.new/v2/search
 */
import { getEnvApiKey, withAuth } from "@rva/ai";
import { SearchProviderError } from "../../../web/search/types";
import { formatQuery, parseSearchQuery } from "../query";
import { SearchProvider } from "./base";
import { classifyProviderHttpError, withHardTimeout } from "./utils";
const SYNTHETIC_SEARCH_URL = "https://api.synthetic.new/v2/search";
/** Resolve Synthetic API key through the shared auth storage pipeline. */
export function findApiKey(authStorage, sessionId, signal) {
    return authStorage.keys.get("synthetic", sessionId, { signal });
}
/** Call Synthetic search API. */
async function callSyntheticSearch(apiKey, query, signal, fetchImpl = fetch, timeoutMs) {
    const response = await fetchImpl(SYNTHETIC_SEARCH_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({ query }),
        signal: withHardTimeout(signal, timeoutMs),
    });
    if (!response.ok) {
        const errorText = await response.text();
        const classified = classifyProviderHttpError("synthetic", response.status, errorText);
        if (classified)
            throw classified;
        throw new SearchProviderError("synthetic", `Synthetic API error (${response.status}): ${errorText}`, response.status);
    }
    return (await response.json());
}
/** Execute Synthetic web search. */
export async function searchSynthetic(params) {
    const keyOrResolver = params.authStorage.keys.resolver("synthetic", {
        sessionId: params.sessionId,
    });
    const parsed = params.parsedQuery ?? parseSearchQuery(params.query);
    const query = parsed.hasDirectives
        ? formatQuery(parsed, { phrases: true, negation: true, site: true })
        : params.query;
    const fetchImpl = params.fetch;
    const data = await withAuth(keyOrResolver, key => callSyntheticSearch(key, query, params.signal, fetchImpl, params.timeoutMs), {
        signal: params.signal,
        missingKeyMessage: "Synthetic credentials not found. Set SYNTHETIC_API_KEY or login with 'omp /login synthetic'.",
    });
    const sources = [];
    for (const result of data.results ?? []) {
        if (!result.url)
            continue;
        sources.push({
            title: result.title ?? result.url,
            url: result.url,
            snippet: result.text ?? undefined,
            publishedDate: result.published ?? undefined,
        });
    }
    const numResults = params.numSearchResults ?? params.limit;
    const limitedSources = numResults ? sources.slice(0, numResults) : sources;
    return {
        provider: "synthetic",
        sources: limitedSources,
    };
}
/** Search provider for Synthetic. */
export class SyntheticProvider extends SearchProvider {
    id = "synthetic";
    label = "Synthetic";
    isAvailable(authStorage) {
        return authStorage.keys.source("synthetic") !== undefined || !!getEnvApiKey("synthetic");
    }
    search(params) {
        return searchSynthetic(params);
    }
}
