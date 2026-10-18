import { withAuth } from "@rva/ai";
import { resolveXaiBaseUrl, XAI_DEFAULT_BASE_URL } from "@rva/ai/providers/xai-base-url";
import { buildModelProviderPriorityRank } from "@rva/catalog/identity";
import { pickDefaultAvailableModel, resolveRoleChain } from "../../../config/model-resolver";
import { roleCandidatePool } from "../../../config/model-roles";
import { cfgModelProviderOrder } from "../../../config/model-settings";
import { resolveConfiguredModelTarget } from "../../../session/role-models";
import { isXHost, xHandle } from "../../x";
import { SearchProviderError } from "../../../web/search/types";
import { formatQuery, parseSearchQuery } from "../query";
import { clampNumResults } from "../utils";
import { SearchProvider } from "./base";
import { classifyProviderHttpError, withHardTimeout } from "./utils";
/**
 * Reasoning effort for xAI search and X reads: both are latency-sensitive, so
 * stay low regardless of the selected model's configured thinking level.
 */
export const XAI_SEARCH_REASONING_EFFORT = "low";
const DEFAULT_NUM_RESULTS = 10;
const MAX_NUM_RESULTS = 30;
/** Messages at least this long are treated as substantive content, not relay narration. */
const SUBSTANTIVE_MIN_CHARS = 300;
/**
 * Query syntax re-emitted for the Grok search agent. `site:`/`-site:` are
 * stripped because hosts map natively onto the web_search domain filters and
 * the web_search/x_search tool split; `before:`/`after:` stay in the query
 * text as hints for web_search, which has no date parameters (only `x_search`
 * takes `from_date`/`to_date`; the deprecated Live Search `search_parameters`
 * now returns 410).
 */
const XAI_QUERY_SYNTAX = {
    phrases: true,
    negation: true,
    or: true,
    inUrl: true,
    inTitle: true,
    filetype: true,
    dateRange: true,
};
/** xAI web_search accepts at most 5 allowed or excluded domains per request. */
const MAX_DOMAIN_FILTERS = 5;
/** Bare hosts of `site:` values (`github.com/anthropics` → `github.com`), deduped, capped at 5; path parts are enforced by the central constraint filter. */
function domainFilterList(sites) {
    const hosts = new Set();
    for (const site of sites) {
        const slash = site.indexOf("/");
        hosts.add(slash === -1 ? site : site.slice(0, slash));
        if (hosts.size === MAX_DOMAIN_FILTERS)
            break;
    }
    return [...hosts];
}
/** Most handles `x_search` accepts per allow or exclude list. */
const MAX_X_HANDLES = 20;
/** X's author operator: `from:jack`, `from:@jack`. */
const FROM_PATTERN = /^from:@?([A-Za-z0-9_]{1,15})$/i;
/** Whether a `site:` value (`x.com/jack`) is on an X host; web_search barely indexes X posts. */
function isXSite(site) {
    return isXHost(site.split("/", 1)[0]);
}
/** Account handle an X `site:` value scopes to (`x.com/jack/status/1` → `jack`). */
function xSiteHandle(site) {
    const [host, segment] = site.split("/");
    return isXHost(host) ? xHandle(segment) : undefined;
}
/**
 * Author filters a query states: `from:` terms and account-scoped
 * `site:x.com/<handle>` values allow handles, their negations exclude them.
 * `x_search` rejects both lists together, so an allow list drops the excludes.
 */
function xHandleFilter(parsed) {
    const allowed = new Set();
    const excluded = new Set();
    for (const term of parsed.terms) {
        const handle = term.phrase ? undefined : FROM_PATTERN.exec(term.text)?.[1];
        if (handle)
            (term.negated ? excluded : allowed).add(handle);
    }
    for (const site of parsed.sites) {
        const handle = xSiteHandle(site);
        if (handle)
            allowed.add(handle);
    }
    for (const site of parsed.excludedSites) {
        const handle = xSiteHandle(site);
        if (handle)
            excluded.add(handle);
    }
    return {
        allowed: [...allowed].slice(0, MAX_X_HANDLES),
        excluded: allowed.size > 0 ? [] : [...excluded].slice(0, MAX_X_HANDLES),
    };
}
/**
 * Whether a query asks only for X posts: it names `from:` authors, or every
 * `site:` is an X host. The search pipeline routes such queries to xAI first.
 */
export function targetsX(parsed) {
    return xHandleFilter(parsed).allowed.length > 0 || (parsed.sites.length > 0 && parsed.sites.every(isXSite));
}
/** Providers serving xAI models; a Set because `getAvailableForProviders` takes one. */
const XAI_PROVIDERS = new Set(["xai", "xai-oauth"]);
/**
 * Whether X search can run: an xAI-grounded model with credentials exists.
 * Gates the X operators in the `web_search` tool description.
 */
export function xSearchAvailable(modelRegistry) {
    return modelRegistry.getAvailableForProviders(XAI_PROVIDERS).some(model => model.webSearch === "xai");
}
/** UTC start date (`YYYY-MM-DD`) of a `recency` window ending now. */
function recencyStart(recency) {
    const start = new Date();
    if (recency === "day")
        start.setUTCDate(start.getUTCDate() - 1);
    else if (recency === "week")
        start.setUTCDate(start.getUTCDate() - 7);
    else if (recency === "month")
        start.setUTCMonth(start.getUTCMonth() - 1);
    else
        start.setUTCFullYear(start.getUTCFullYear() - 1);
    return start.toISOString().slice(0, 10);
}
/**
 * Hosted tools for one query: `web_search` plus `x_search`, letting Grok pick
 * per query. X-only queries (`site:x.com`, `from:` authors) drop web_search;
 * `site:` without X hosts, or `-site:x.com`, drops x_search. `x_search` takes
 * author handles natively, and `after:`/`before:` (else `recency`) as its date
 * range, which matches the directives' inclusive start and exclusive end.
 */
function searchTools(parsed, recency) {
    const handles = xHandleFilter(parsed);
    const webSites = parsed.sites.filter(site => !isXSite(site));
    const unscoped = parsed.sites.length === 0;
    const tools = [];
    if (webSites.length > 0 || (unscoped && handles.allowed.length === 0)) {
        const webSearch = { type: "web_search" };
        // allowed_domains and excluded_domains are mutually exclusive per
        // request; prefer the allow list, the central filter enforces exclusions.
        if (webSites.length > 0) {
            webSearch.filters = { allowed_domains: domainFilterList(webSites) };
        }
        else if (parsed.excludedSites.length > 0) {
            webSearch.filters = { excluded_domains: domainFilterList(parsed.excludedSites) };
        }
        tools.push(webSearch);
    }
    const xExcluded = parsed.excludedSites.some(site => isXSite(site) && !xSiteHandle(site));
    if (webSites.length < parsed.sites.length || handles.allowed.length > 0 || (unscoped && !xExcluded)) {
        const xSearch = { type: "x_search" };
        if (handles.allowed.length > 0)
            xSearch.allowed_x_handles = handles.allowed;
        else if (handles.excluded.length > 0)
            xSearch.excluded_x_handles = handles.excluded;
        // Explicit before:/after: bounds take precedence over recency.
        if (parsed.after)
            xSearch.from_date = parsed.after;
        else if (recency && !parsed.before)
            xSearch.from_date = recencyStart(recency);
        if (parsed.before)
            xSearch.to_date = parsed.before;
        tools.push(xSearch);
    }
    return tools;
}
function buildRequestBody(params) {
    const parsed = params.parsedQuery ?? parseSearchQuery(params.query);
    const query = parsed.hasDirectives ? formatQuery(parsed, XAI_QUERY_SYNTAX) : params.query;
    const body = {
        model: params.model.id,
        input: [
            { role: "system", content: params.systemPrompt },
            { role: "user", content: query },
        ],
        tools: searchTools(parsed, params.recency),
        reasoning: { effort: XAI_SEARCH_REASONING_EFFORT },
    };
    if (params.maxOutputTokens !== undefined) {
        body.max_output_tokens = params.maxOutputTokens;
    }
    if (params.temperature !== undefined) {
        body.temperature = params.temperature;
    }
    return body;
}
async function postXAIResponses(apiKey, request, body, transport) {
    return (request.fetch ?? fetch)(`${transport.baseURL.replace(/\/+$/, "")}/responses`, {
        method: "POST",
        headers: {
            ...transport.headers,
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(body),
        signal: withHardTimeout(request.signal, request.timeoutMs),
    });
}
function throwXAIResponsesError(status, errorText) {
    const classified = classifyProviderHttpError("xai", status, errorText);
    if (classified)
        throw classified;
    throw new SearchProviderError("xai", `xAI Responses API error (${status}): ${errorText}`, status);
}
async function callXAIResponses(apiKey, request, body, transport) {
    const response = await postXAIResponses(apiKey, request, body, transport);
    if (!response.ok) {
        throwXAIResponsesError(response.status, await response.text());
    }
    try {
        return (await response.json());
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new SearchProviderError("xai", `xAI Responses API returned invalid JSON: ${message}`, response.status);
    }
}
function addCitationSource(sources, citations, seenUrls, url, title, citedText) {
    const trimmedUrl = url.trim();
    if (!trimmedUrl || seenUrls.has(trimmedUrl))
        return;
    seenUrls.add(trimmedUrl);
    const sourceTitle = title?.trim() || trimmedUrl;
    const sourceSnippet = citedText?.trim() || undefined;
    sources.push({
        title: sourceTitle,
        url: trimmedUrl,
        snippet: sourceSnippet,
    });
    citations.push({
        title: sourceTitle,
        url: trimmedUrl,
        citedText: sourceSnippet,
    });
}
function extractSnippetAround(text, start, end) {
    if (!text || typeof start !== "number" || typeof end !== "number")
        return undefined;
    const before = Math.max(0, start - 100);
    const after = Math.min(text.length, end + 100);
    const snippet = text
        .slice(before, after)
        .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
        .trim();
    if (!snippet)
        return undefined;
    return snippet.length > 300 ? `${snippet.slice(0, 297)}...` : snippet;
}
function collectAnnotationSources(annotations, sources, citations, seenUrls, contentText) {
    if (!Array.isArray(annotations))
        return;
    for (const annotation of annotations) {
        if (!annotation || typeof annotation !== "object")
            continue;
        if (annotation.type !== "url_citation" || typeof annotation.url !== "string")
            continue;
        addCitationSource(sources, citations, seenUrls, annotation.url, 
        // Bare numbers are citation markers (`[[1]](url)`), not titles.
        annotation.title && !/^\d+$/.test(annotation.title.trim()) ? annotation.title : undefined, annotation.cited_text ??
            annotation.text ??
            extractSnippetAround(contentText, annotation.start_index, annotation.end_index));
    }
}
function collectWebSearchSources(item, sources, citations, seenUrls) {
    if (item.type !== "web_search_call")
        return;
    for (const group of [item.action?.sources, item.sources, item.results]) {
        if (!Array.isArray(group))
            continue;
        for (const source of group) {
            if (!source || typeof source !== "object")
                continue;
            const url = source.url ?? source.source_website_url;
            if (typeof url !== "string")
                continue;
            addCitationSource(sources, citations, seenUrls, url, source.title ?? source.caption);
        }
    }
}
/** Final answer text of a Responses reply, without relay narration or commentary-phase messages. */
export function parseXAIAnswer(response) {
    const output = Array.isArray(response.output) ? response.output : [];
    // A top-level aggregate can contain narration even without explicit phases.
    // Prefer filtered messages; use the aggregate only when no messages exist.
    // Explicit phases take precedence. Unphased relay messages use the last
    // message/citation/length heuristic; keep commentary positions so removing
    // one cannot promote preceding unphased narration into a final answer.
    const messages = [];
    for (const item of output) {
        if (!item || typeof item !== "object" || (item.type != null && item.type !== "message"))
            continue;
        const content = Array.isArray(item.content) ? item.content : null;
        if (content === null && item.type == null)
            continue;
        // Relays cast external JSON into the typed interface; normalize the
        // phase to a recognized value so "" or unknown strings cannot strand a
        // message outside both the final_answer branch and the unphased
        // heuristic.
        const phase = item.phase === "commentary" || item.phase === "final_answer" ? item.phase : null;
        const entry = { texts: [], hasCitations: false, phase };
        for (const part of content ?? []) {
            if (!part || typeof part !== "object")
                continue;
            const text = (part.output_text ?? part.text)?.trim();
            if (text)
                entry.texts.push(text);
            for (const annotation of Array.isArray(part.annotations) ? part.annotations : []) {
                if (annotation?.type === "url_citation" && typeof annotation.url === "string" && annotation.url.trim()) {
                    entry.hasCitations = true;
                    break;
                }
            }
        }
        for (const annotation of Array.isArray(item.annotations) ? item.annotations : []) {
            if (annotation?.type === "url_citation" && typeof annotation.url === "string" && annotation.url.trim()) {
                entry.hasCitations = true;
                break;
            }
        }
        messages.push(entry);
    }
    const hasFinalAnswerContent = messages.some(m => m.phase === "final_answer" && m.texts.length > 0);
    if (!hasFinalAnswerContent) {
        // A tagged-but-empty final is authoritative: the relay uses the phase
        // protocol and produced no answer, so the aggregate — which mixes the
        // narration in — must not be promoted either.
        if (messages.some(m => m.phase === "final_answer"))
            return undefined;
        // Without authoritative phased content, an empty final message means
        // no answer — do not promote heuristic-kept earlier content.
        const lastMessage = messages.at(-1);
        if (!lastMessage)
            return response.output_text?.trim() || undefined;
        if (lastMessage.texts.length === 0 && lastMessage.phase !== "commentary")
            return undefined;
    }
    const kept = hasFinalAnswerContent
        ? messages.filter(entry => entry.phase === "final_answer")
        : messages.filter((entry, index) => entry.phase == null &&
            (index === messages.length - 1 ||
                entry.hasCitations ||
                entry.texts.join("").length >= SUBSTANTIVE_MIN_CHARS));
    const answer = kept
        .flatMap(entry => entry.texts)
        .join("\n")
        .trim();
    return answer || undefined;
}
function parseUsage(usage) {
    if (!usage)
        return undefined;
    const parsed = {};
    const inputTokens = usage.input_tokens ?? usage.inputTokens;
    const outputTokens = usage.output_tokens ?? usage.outputTokens;
    const totalTokens = usage.total_tokens ?? usage.totalTokens;
    if (typeof inputTokens === "number")
        parsed.inputTokens = inputTokens;
    if (typeof outputTokens === "number")
        parsed.outputTokens = outputTokens;
    if (typeof totalTokens === "number")
        parsed.totalTokens = totalTokens;
    return Object.keys(parsed).length > 0 ? parsed : undefined;
}
function applyResultCap(sources, citations, resultCap) {
    return {
        sources: sources.slice(0, resultCap),
        citations: citations.slice(0, resultCap),
    };
}
function parseResponse(response, resultCap, authMode) {
    const sources = [];
    const citations = [];
    const seenUrls = new Set();
    collectAnnotationSources(response.annotations, sources, citations, seenUrls);
    const output = Array.isArray(response.output) ? response.output : [];
    for (const item of output) {
        if (!item || typeof item !== "object")
            continue;
        collectAnnotationSources(item.annotations, sources, citations, seenUrls);
        const content = Array.isArray(item.content) ? item.content : [];
        for (const part of content) {
            if (!part || typeof part !== "object")
                continue;
            collectAnnotationSources(part.annotations, sources, citations, seenUrls, part.output_text ?? part.text);
        }
    }
    for (const item of output) {
        if (!item || typeof item !== "object")
            continue;
        collectWebSearchSources(item, sources, citations, seenUrls);
    }
    const topLevelCitations = Array.isArray(response.citations) ? response.citations : [];
    for (const url of topLevelCitations) {
        if (typeof url !== "string")
            continue;
        addCitationSource(sources, citations, seenUrls, url);
    }
    const limited = applyResultCap(sources, citations, resultCap);
    return {
        provider: "xai",
        answer: parseXAIAnswer(response),
        sources: limited.sources,
        citations: limited.citations.length > 0 ? limited.citations : undefined,
        usage: parseUsage(response.usage),
        model: response.model,
        requestId: response.id,
        authMode,
    };
}
/**
 * POST one Responses request with `request.model`'s provider credentials,
 * resolved through the model registry. Shared by xAI search and the X reader
 * (`web/scrapers/twitter.ts`).
 *
 * @throws SearchProviderError when the model is not an xAI model, when official
 * xAI OAuth credentials would reach a custom endpoint, on HTTP errors, and on
 * invalid JSON.
 */
export async function requestXAIResponses(request, body) {
    const { model, modelRegistry } = request;
    if (model.provider !== "xai" && model.provider !== "xai-oauth") {
        throw new SearchProviderError("xai", `Selected model ${model.provider}/${model.id} is not an xAI model`, 400);
    }
    const customEndpoint = model.baseUrl.replace(/\/+$/, "") !== XAI_DEFAULT_BASE_URL;
    const credentialOrigin = request.authStorage.keys.source(model.provider);
    const hasCommandBackedKey = modelRegistry.hasCommandBackedApiKey(model.provider);
    const officialOAuthCredential = model.provider === "xai-oauth" &&
        !hasCommandBackedKey &&
        (credentialOrigin?.kind === "oauth" || credentialOrigin?.kind === "env");
    if (customEndpoint && officialOAuthCredential) {
        throw new SearchProviderError("xai", `Refusing to send official xAI OAuth credentials to custom endpoint ${model.baseUrl}. Configure an API key for provider "xai-oauth".`);
    }
    const response = await withAuth(modelRegistry.resolver(model, request.sessionId), async (key) => {
        const transport = {
            // XAI_BASE_URL never receives official OAuth credentials: neither an OAuth-origin
            // credential nor an OAuth access-token bearer leaves the bundled endpoint.
            baseURL: officialOAuthCredential
                ? model.baseUrl
                : (resolveXaiBaseUrl(model.provider, model.baseUrl, key) ?? model.baseUrl),
            headers: await modelRegistry.resolveModelHeaders(model, request.signal),
        };
        return callXAIResponses(key, request, body, transport);
    }, {
        signal: request.signal,
        missingKeyMessage: `xAI credentials not found for selected provider "${model.provider}".`,
    });
    const authMode = model.provider === "xai-oauth" && (credentialOrigin?.kind === "oauth" || credentialOrigin?.kind === "env")
        ? "oauth"
        : "api_key";
    return { response, authMode };
}
/**
 * Reorder the xAI-grounded entries of a model chain by provider priority:
 * `modelProviderOrder`, then the built-in order, which ranks the `xai-oauth`
 * login above an `xai` API key. Other entries keep their slots; same-provider
 * entries keep their relative order.
 */
export function rankXAIProviders(items, modelOf, settings) {
    const priority = buildModelProviderPriorityRank(cfgModelProviderOrder.get(settings));
    const rank = (item) => priority.get(modelOf(item).provider.toLowerCase()) ?? Number.POSITIVE_INFINITY;
    const ranked = items.filter(item => modelOf(item).webSearch === "xai").sort((a, b) => rank(a) - rank(b));
    let next = 0;
    return items.map(item => (modelOf(item).webSearch === "xai" ? ranked[next++] : item));
}
/**
 * xAI models for X reads and X-only searches, in attempt order: the `web` role
 * chain's xAI-grounded candidates plus the provider default swapped to its
 * cheaper `webSearchModel`, ranked by {@link rankXAIProviders}. Empty without
 * xAI credentials.
 */
export function xaiModelChain(modelRegistry, settings) {
    const pool = roleCandidatePool("web", settings, modelRegistry);
    const chain = resolveRoleChain("web", settings, pool)
        .map(candidate => candidate.model)
        .filter(model => model.webSearch === "xai");
    const grounded = pool.filter(model => model.webSearch === "xai");
    const fallback = pickDefaultAvailableModel(grounded);
    const runner = fallback && (resolveConfiguredModelTarget(fallback.webSearchModel, fallback, grounded) ?? fallback);
    const models = runner && !chain.some(model => model.provider === runner.provider && model.id === runner.id)
        ? [...chain, runner]
        : chain;
    return rankXAIProviders(models, model => model, settings);
}
/** Execute xAI Responses API web and X search. */
export async function searchXAI(params) {
    const resultCap = clampNumResults(params.numSearchResults ?? params.limit, DEFAULT_NUM_RESULTS, MAX_NUM_RESULTS);
    const { response, authMode } = await requestXAIResponses(params, buildRequestBody(params));
    const parsed = parseResponse(response, resultCap, authMode);
    if (!parsed.answer && parsed.sources.length === 0) {
        throw new SearchProviderError("xai", "xAI web_search returned no answer or sources", 502);
    }
    return parsed;
}
/** Search provider for xAI web and X search. */
export class XAIProvider extends SearchProvider {
    id = "xai";
    label = "xAI";
    isAvailable(authStorage, model) {
        return authStorage.keys.source(model?.provider ?? "xai") !== undefined;
    }
    search(params) {
        return searchXAI(params);
    }
}
