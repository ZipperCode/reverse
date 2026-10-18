/**
 * Kagi API Client
 *
 * Implements the Kagi V1 Search API (POST /api/v1/search), the public-preview
 * successor to the sunset V0 endpoint. Authentication is resolved exclusively
 * through the shared {@link AuthStorage} broker (Bearer token), and responses
 * are categorized result buckets rather than the legacy flat object array.
 */
import { withAuth } from "@rva/ai";
import { withHardTimeout } from "./search/providers/utils";
const KAGI_SEARCH_URL = "https://kagi.com/api/v1/search";
// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------
export class KagiApiError extends Error {
    statusCode;
    constructor(message, statusCode) {
        super(message);
        this.name = "KagiApiError";
        this.statusCode = statusCode;
    }
}
function extractKagiErrorMessage(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload))
        return null;
    const record = payload;
    for (const value of [record.message, record.detail]) {
        if (typeof value === "string" && value.trim().length > 0) {
            return value.trim();
        }
    }
    for (const errors of [record.error, record.errors]) {
        if (typeof errors === "string" && errors.trim().length > 0) {
            return errors.trim();
        }
        if (!Array.isArray(errors))
            continue;
        for (const entry of errors) {
            if (!entry || typeof entry !== "object")
                continue;
            const e = entry;
            for (const value of [e.message, e.msg, e.code]) {
                if ((typeof value === "string" && value.trim().length > 0) ||
                    (typeof value === "number" && Number.isFinite(value))) {
                    return String(value).trim();
                }
            }
        }
    }
    return null;
}
function createKagiApiError(statusCode, detail) {
    return new KagiApiError(detail ? `Kagi API error (${statusCode}): ${detail}` : `Kagi API error (${statusCode})`, statusCode);
}
function parseKagiErrorResponse(statusCode, responseText) {
    const trimmed = responseText.trim();
    if (trimmed.length === 0) {
        return createKagiApiError(statusCode);
    }
    try {
        const payload = JSON.parse(trimmed);
        return createKagiApiError(statusCode, extractKagiErrorMessage(payload) ?? trimmed);
    }
    catch {
        return createKagiApiError(statusCode, trimmed);
    }
}
function parseKagiSuccessResponse(statusCode, responseText) {
    let payload;
    try {
        payload = JSON.parse(responseText);
    }
    catch {
        throw new KagiApiError("Kagi API returned an invalid response: invalid JSON", statusCode);
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new KagiApiError("Kagi API returned an invalid response: expected an object envelope", statusCode);
    }
    const record = payload;
    const errorMessage = extractKagiErrorMessage(payload);
    if (errorMessage && (record.error !== undefined || record.errors !== undefined)) {
        const errors = Array.isArray(record.error) ? record.error : Array.isArray(record.errors) ? record.errors : [];
        const first = errors[0];
        const code = first && typeof first === "object" && typeof first.code === "number"
            ? first.code
            : statusCode;
        throw createKagiApiError(code, errorMessage);
    }
    if (record.data !== undefined && (!record.data || typeof record.data !== "object" || Array.isArray(record.data))) {
        throw new KagiApiError("Kagi API returned an invalid response: expected data to be an object", statusCode);
    }
    return payload;
}
/**
 * Compute a YYYY-MM-DD date string `recency` units before now, in UTC.
 * UTC keeps the recency window deterministic regardless of host timezone and
 * matches Kagi's date-formatted `filters.after`. Date setters handle month
 * drift (Mar 31 −1mo → Feb 28/29) and leap years correctly.
 */
function recencyToDate(recency) {
    const d = new Date();
    switch (recency) {
        case "day":
            d.setUTCDate(d.getUTCDate() - 1);
            break;
        case "week":
            d.setUTCDate(d.getUTCDate() - 7);
            break;
        case "month":
            d.setUTCMonth(d.getUTCMonth() - 1);
            break;
        case "year":
            d.setUTCFullYear(d.getUTCFullYear() - 1);
            break;
    }
    const yyyy = d.getUTCFullYear();
    const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(d.getUTCDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
}
function buildRequestBody(query, options) {
    const req = {
        query,
        workflow: "search",
        limit: options.limit,
    };
    if (options.recency) {
        req.filters = { after: recencyToDate(options.recency) };
    }
    return req;
}
function firstNonEmptyString(...values) {
    for (const value of values) {
        if (typeof value === "string" && value.trim().length > 0)
            return value.trim();
    }
    return undefined;
}
/** Push every valid item in a result bucket as a source, with an optional title tag. */
function collectSources(sources, items, tag) {
    if (!Array.isArray(items))
        return;
    for (const value of items) {
        if (!value || typeof value !== "object" || Array.isArray(value))
            continue;
        const item = value;
        const url = firstNonEmptyString(item.url, item.href, item.link);
        if (!url)
            continue;
        const title = firstNonEmptyString(item.title, item.name) ?? url;
        sources.push({
            title: tag ? `${tag} ${title}` : title,
            url,
            snippet: firstNonEmptyString(item.snippet, item.description, item.summary),
            publishedDate: firstNonEmptyString(item.time),
        });
    }
}
/** Pull a related/adjacent question from an item's props or fall back to title. */
function questionOf(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return undefined;
    const item = value;
    const props = item.props && typeof item.props === "object" && !Array.isArray(item.props)
        ? item.props
        : undefined;
    return firstNonEmptyString(props?.question, props?.query, item.title);
}
export async function searchWithKagi(query, options = {}, authStorage) {
    const fetchImpl = options.fetch ?? fetch;
    const body = JSON.stringify(buildRequestBody(query, options));
    const response = await withAuth(authStorage.keys.resolver("kagi", { sessionId: options.sessionId }), async (apiKey) => {
        const res = await fetchImpl(KAGI_SEARCH_URL, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${apiKey}`,
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body,
            signal: withHardTimeout(options.signal, options.timeoutMs),
        });
        if (!res.ok) {
            throw parseKagiErrorResponse(res.status, await res.text());
        }
        return res;
    }, {
        signal: options.signal,
        missingKeyMessage: "Kagi credentials not found. Set KAGI_API_KEY or login with 'omp /login kagi'.",
    });
    const payload = parseKagiSuccessResponse(response.status, await response.text());
    const data = payload.data;
    const sources = [];
    const relatedQuestions = [];
    collectSources(sources, data?.search);
    collectSources(sources, data?.video, "[Video]");
    collectSources(sources, data?.news, "[News]");
    collectSources(sources, data?.infobox, "[Info]");
    const adjacentQuestions = data?.adjacent_question;
    if (Array.isArray(adjacentQuestions)) {
        for (const item of adjacentQuestions) {
            const question = questionOf(item);
            if (question)
                relatedQuestions.push(question);
        }
    }
    const relatedSearches = data?.related_search;
    if (Array.isArray(relatedSearches)) {
        for (const item of relatedSearches) {
            const question = questionOf(item);
            if (question)
                relatedQuestions.push(question);
        }
    }
    const directAnswers = data?.direct_answer;
    const directAnswer = Array.isArray(directAnswers) ? directAnswers[0] : undefined;
    const answer = directAnswer && typeof directAnswer === "object" && !Array.isArray(directAnswer)
        ? firstNonEmptyString(directAnswer.snippet, directAnswer.title)
        : undefined;
    return {
        requestId: payload.meta?.trace ?? payload.meta?.id ?? "",
        sources,
        relatedQuestions,
        answer,
    };
}
