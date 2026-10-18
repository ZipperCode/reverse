/**
 * TinyFish Web Search Provider
 *
 * Calls TinyFish's search API and maps results into the unified
 * SearchResponse shape used by the web search tool.
 */
import { getEnvApiKey, withAuth } from "@rva/ai";
import { SearchProviderError } from "../../../web/search/types";
import { formatQuery, parseSearchQuery } from "../query";
import { clampNumResults } from "../utils";
import { SearchProvider } from "./base";
import { classifyProviderHttpError, normalizeSearchText, siteHosts, withHardTimeout } from "./utils";
const TINYFISH_SEARCH_URL = "https://api.search.tinyfish.ai";
const DEFAULT_NUM_RESULTS = 10;
const MAX_NUM_RESULTS = 20;
const MAX_PAGE = 10;
/** TinyFish is SERP-backed: common Google-style operators pass through. */
const TINYFISH_QUERY_SYNTAX = { phrases: true, negation: true, filetype: true };
const RECENCY_MINUTES = {
    day: 1440,
    week: 10080,
    month: 43200,
    year: 525600,
};
/** Resolve TinyFish API key through the shared auth storage pipeline. */
export function findApiKey(authStorage, sessionId, signal) {
    return authStorage.keys.get("tinyfish", sessionId, { signal });
}
async function callTinyFishSearch(apiKey, params) {
    const url = new URL(TINYFISH_SEARCH_URL);
    url.searchParams.set("query", params.query);
    if (params.recency) {
        url.searchParams.set("recency_minutes", String(RECENCY_MINUTES[params.recency]));
    }
    if (params.include_domains?.length) {
        url.searchParams.set("include_domains", params.include_domains.join(","));
    }
    if (params.exclude_domains?.length) {
        url.searchParams.set("exclude_domains", params.exclude_domains.join(","));
    }
    if (params.location) {
        url.searchParams.set("location", params.location);
    }
    if (params.language) {
        url.searchParams.set("language", params.language);
    }
    if (params.num_results !== undefined) {
        url.searchParams.set("num_results", String(params.num_results));
    }
    if (params.page !== undefined) {
        url.searchParams.set("page", String(params.page));
    }
    const response = await (params.fetch ?? fetch)(url, {
        method: "GET",
        headers: {
            Accept: "application/json",
            "X-API-Key": apiKey,
        },
        signal: withHardTimeout(params.signal, params.timeoutMs),
    });
    if (!response.ok) {
        const errorText = await response.text();
        const classified = classifyProviderHttpError("tinyfish", response.status, errorText);
        if (classified)
            throw classified;
        throw new SearchProviderError("tinyfish", `TinyFish API error (${response.status}): ${errorText}`, response.status);
    }
    return (await response.json());
}
function appendTinyFishSources(sources, results, seenUrls) {
    for (const result of results) {
        const url = result.url?.trim();
        if (!url || seenUrls.has(url))
            continue;
        seenUrls.add(url);
        const siteName = result.site_name?.trim();
        sources.push({
            title: result.title?.trim() || siteName || url,
            url,
            snippet: normalizeSearchText(result.snippet),
            author: siteName || undefined,
        });
    }
}
/**
 * Derive TinyFish `location` (ISO 3166-1 alpha-2, uppercase) and `language`
 * (ISO 639-1, lowercase) from a parsed `lang:` directive. The region subtag is
 * optional: `lang:it` yields language only, `lang:it-it` yields both. Non-region
 * subtags (e.g. the script in `zh-hans`) never become a location.
 */
function tinyFishLocale(lang) {
    if (!lang)
        return {};
    const match = /^([a-z]{2})(?:[-_]([a-z]{2}))?(?:[-_]|$)/.exec(lang.toLowerCase());
    if (!match)
        return {};
    return { language: match[1], location: match[2]?.toUpperCase() };
}
/** Execute TinyFish web search. */
export async function searchTinyFish(params) {
    const numResults = clampNumResults(params.numSearchResults ?? params.limit, DEFAULT_NUM_RESULTS, MAX_NUM_RESULTS);
    const pageSize = Math.min(numResults, DEFAULT_NUM_RESULTS);
    const parsed = params.parsedQuery ?? parseSearchQuery(params.query);
    const tinyFishParams = {
        query: parsed.hasDirectives ? formatQuery(parsed, TINYFISH_QUERY_SYNTAX) : params.query,
        num_results: pageSize,
        recency: params.recency,
        signal: params.signal,
        timeoutMs: params.timeoutMs,
        fetch: params.fetch,
    };
    if (parsed.hasDirectives) {
        const includeDomains = siteHosts(parsed.sites);
        const excludeDomains = siteHosts(parsed.excludedSites);
        if (includeDomains.length > 0)
            tinyFishParams.include_domains = includeDomains;
        if (excludeDomains.length > 0)
            tinyFishParams.exclude_domains = excludeDomains;
    }
    const { location, language } = tinyFishLocale(parsed.lang);
    if (location)
        tinyFishParams.location = location;
    if (language)
        tinyFishParams.language = language;
    const keyOrResolver = params.authStorage.keys.resolver("tinyfish", {
        sessionId: params.sessionId,
    });
    const sources = await withAuth(keyOrResolver, async (key) => {
        const collected = [];
        const seenUrls = new Set();
        for (let page = 0; page <= MAX_PAGE && collected.length < numResults; page += 1) {
            const searchPage = await callTinyFishSearch(key, { ...tinyFishParams, page });
            if (!Array.isArray(searchPage.results)) {
                throw new Error("TinyFish Search API returned an unexpected response shape");
            }
            appendTinyFishSources(collected, searchPage.results, seenUrls);
            if (searchPage.results.length < pageSize)
                break;
        }
        return collected.slice(0, numResults);
    }, {
        signal: params.signal,
        missingKeyMessage: 'TinyFish credentials not found. Set TINYFISH_API_KEY or configure an API key for provider "tinyfish".',
    });
    return {
        provider: "tinyfish",
        sources,
        authMode: "api_key",
    };
}
/** Search provider for TinyFish web search. */
export class TinyFishProvider extends SearchProvider {
    id = "tinyfish";
    label = "TinyFish";
    isAvailable(authStorage) {
        return authStorage.keys.source("tinyfish") !== undefined || !!getEnvApiKey("tinyfish");
    }
    search(params) {
        return searchTinyFish(params);
    }
}
