/**
 * Minimal fetch-based client for the Hindsight HTTP API.
 *
 * Replaces the `@vectorize-io/hindsight-client` SDK with hand-rolled fetch
 * calls so we depend on nothing more than the API endpoints we actually use:
 * `retain`, `retainBatch`, `recall`, `reflect`, bank + document management,
 * and bulk listing. Centralising construction here keeps a single seam for
 * tests to spy on.
 */
import { USER_AGENT } from "@rva/utils";
import { isTimeoutError, withTimeoutSignal } from "../utils/fetch-timeout";
const DEFAULT_USER_AGENT = USER_AGENT;
/** Fallback deadlines (ms) applied when the caller supplies no override. */
const DEFAULT_REQUEST_TIMEOUT_MS = 30000;
const DEFAULT_REFLECT_TIMEOUT_MS = 120000;
const DEFAULT_RECALL_TIMEOUT_MS = 30000;
const DEFAULT_RETAIN_TIMEOUT_MS = 60000;
/** Server-side maximum `limit` on the mental-model list endpoint; keeps typical banks to one request. */
const MENTAL_MODEL_PAGE_SIZE = 1000;
export class HindsightError extends Error {
    statusCode;
    details;
    constructor(message, statusCode, details) {
        super(message);
        this.name = "HindsightError";
        this.statusCode = statusCode;
        this.details = details;
    }
}
export class HindsightApi {
    #baseUrl;
    #headers;
    #reflectTimeoutMs;
    #recallTimeoutMs;
    #retainTimeoutMs;
    #requestTimeoutMs;
    constructor(options) {
        this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
        this.#headers = {
            "User-Agent": options.userAgent ?? DEFAULT_USER_AGENT,
            "Content-Type": "application/json",
        };
        if (options.apiKey) {
            this.#headers.Authorization = `Bearer ${options.apiKey}`;
        }
        const timeouts = options.timeouts;
        this.#requestTimeoutMs = timeouts?.request ?? DEFAULT_REQUEST_TIMEOUT_MS;
        this.#reflectTimeoutMs = timeouts?.reflect ?? DEFAULT_REFLECT_TIMEOUT_MS;
        this.#recallTimeoutMs = timeouts?.recall ?? DEFAULT_RECALL_TIMEOUT_MS;
        this.#retainTimeoutMs = timeouts?.retain ?? DEFAULT_RETAIN_TIMEOUT_MS;
    }
    async retain(bankId, content, options) {
        const item = buildMemoryItem({
            content,
            timestamp: options?.timestamp,
            context: options?.context,
            metadata: options?.metadata,
            documentId: options?.documentId,
            tags: options?.tags,
            updateMode: options?.updateMode,
        });
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/memories`, "retain", {
            body: { items: [item], async: options?.async },
            signal: options?.signal,
            timeoutMs: this.#retainTimeoutMs,
        });
    }
    /**
     * Retain multiple memories in a single request. Mirrors the official
     * client's `retainBatch` — items hit `POST /memories` together so the
     * server can dedupe and consolidate as a batch instead of N round-trips.
     *
     * Per-item `documentId` wins; `options.documentId` only fills the gaps.
     */
    async retainBatch(bankId, items, options) {
        const processed = items.map(item => {
            const built = buildMemoryItem(item);
            if (built.document_id === undefined && options?.documentId !== undefined) {
                built.document_id = options.documentId;
            }
            return built;
        });
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/memories`, "retainBatch", {
            body: {
                items: processed,
                document_tags: options?.documentTags,
                async: options?.async,
            },
            signal: options?.signal,
            timeoutMs: this.#retainTimeoutMs,
        });
    }
    async recall(bankId, query, options) {
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/memories/recall`, "recall", {
            body: {
                query,
                types: options?.types,
                max_tokens: options?.maxTokens,
                budget: options?.budget ?? "mid",
                tags: options?.tags,
                tags_match: options?.tagsMatch,
            },
            signal: options?.signal,
            timeoutMs: this.#recallTimeoutMs,
        });
    }
    async reflect(bankId, query, options) {
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/reflect`, "reflect", {
            body: {
                query,
                context: options?.context,
                budget: options?.budget ?? "low",
                tags: options?.tags,
                tags_match: options?.tagsMatch,
            },
            signal: options?.signal,
            timeoutMs: this.#reflectTimeoutMs,
        });
    }
    async createBank(bankId, options = {}) {
        return this.#request("PUT", `/v1/default/banks/${encodeURIComponent(bankId)}`, "createBank", {
            body: {
                reflect_mission: options.reflectMission,
                retain_mission: options.retainMission,
            },
            signal: options.signal,
        });
    }
    /**
     * Bulk-list memory units in a bank with optional filters and pagination.
     * Endpoint: `GET /v1/default/banks/{bank_id}/memories/list`.
     */
    async listMemories(bankId, options) {
        return this.#request("GET", `/v1/default/banks/${encodeURIComponent(bankId)}/memories/list`, "listMemories", {
            query: {
                type: options?.type,
                q: options?.q,
                consolidation_state: options?.consolidationState,
                limit: options?.limit,
                offset: options?.offset,
            },
            signal: options?.signal,
        });
    }
    /** Bulk-list documents in a bank. */
    async listDocuments(bankId, options) {
        return this.#request("GET", `/v1/default/banks/${encodeURIComponent(bankId)}/documents`, "listDocuments", { query: { limit: options?.limit, offset: options?.offset }, signal: options?.signal });
    }
    /** Fetch a document. Returns `null` on 404 instead of throwing. */
    async getDocument(bankId, documentId) {
        return this.#request("GET", `/v1/default/banks/${encodeURIComponent(bankId)}/documents/${encodeURIComponent(documentId)}`, "getDocument", { allow404: true });
    }
    /** Update a document's mutable fields (currently just tags). */
    async updateDocument(bankId, documentId, options) {
        return this.#request("PATCH", `/v1/default/banks/${encodeURIComponent(bankId)}/documents/${encodeURIComponent(documentId)}`, "updateDocument", { body: { tags: options.tags }, signal: options.signal });
    }
    /**
     * Delete a document and every memory derived from it. Returns `true` on
     * success, `false` if the document was already gone (404).
     */
    async deleteDocument(bankId, documentId) {
        const result = await this.#request("DELETE", `/v1/default/banks/${encodeURIComponent(bankId)}/documents/${encodeURIComponent(documentId)}`, "deleteDocument", { allow404: true });
        return result !== null;
    }
    /**
     * List every mental model in a bank, following `limit`/`offset` pages until
     * the server runs out — the endpoint defaults to 100 per page, so a single
     * request would silently drop the rest of a shared bank. Default
     * `detail=content` includes the generated `content` text but excludes the
     * heavyweight `reflect_response` provenance chain (which can exceed 200KB).
     * Use `detail=metadata` for inventory and `detail=full` only for debug surfaces.
     */
    async listMentalModels(bankId, options) {
        const path = `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models`;
        const detail = options?.detail ?? "content";
        const items = [];
        while (true) {
            const page = await this.#request("GET", path, "listMentalModels", {
                query: { detail, limit: MENTAL_MODEL_PAGE_SIZE, offset: items.length },
                signal: options?.signal,
            });
            const pageItems = page.items ?? [];
            items.push(...pageItems);
            if (pageItems.length < MENTAL_MODEL_PAGE_SIZE)
                break;
            if (typeof page.total === "number" && items.length >= page.total)
                break;
        }
        return { items, total: items.length };
    }
    /** Fetch a single mental model. Returns `null` on 404. */
    async getMentalModel(bankId, mentalModelId, options) {
        return this.#request("GET", `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models/${encodeURIComponent(mentalModelId)}`, "getMentalModel", { query: { detail: options?.detail ?? "content" }, allow404: true, signal: options?.signal });
    }
    /**
     * Create a mental model. Asynchronous on the server: returns an
     * `operation_id`; the model's `content` populates after the background
     * reflect completes.
     */
    async createMentalModel(bankId, name, sourceQuery, options) {
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models`, "createMentalModel", {
            body: {
                id: options?.id,
                name,
                source_query: sourceQuery,
                tags: options?.tags,
                max_tokens: options?.maxTokens,
                trigger: options?.trigger,
            },
            signal: options?.signal,
        });
    }
    /** Trigger an out-of-band refresh of a mental model. Returns the operation handle. */
    async refreshMentalModel(bankId, mentalModelId) {
        return this.#request("POST", `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models/${encodeURIComponent(mentalModelId)}/refresh`, "refreshMentalModel", {});
    }
    /** Delete a mental model. Returns `true` on success, `false` if it was already gone (404). */
    async deleteMentalModel(bankId, mentalModelId) {
        const result = await this.#request("DELETE", `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models/${encodeURIComponent(mentalModelId)}`, "deleteMentalModel", { allow404: true });
        return result !== null;
    }
    /**
     * Fetch the change history of a mental model. Each entry captures the
     * content snapshot BEFORE that change; the current content is read via
     * `getMentalModel`. Most-recent first.
     */
    async getMentalModelHistory(bankId, mentalModelId) {
        const response = await this.#request("GET", `/v1/default/banks/${encodeURIComponent(bankId)}/mental-models/${encodeURIComponent(mentalModelId)}/history`, "getMentalModelHistory", {});
        if (Array.isArray(response))
            return response;
        return response.items ?? [];
    }
    async #request(method, path, operation, opts) {
        let url = `${this.#baseUrl}${path}`;
        if (opts?.query) {
            const qs = buildQueryString(opts.query);
            if (qs)
                url += `?${qs}`;
        }
        const timeoutMs = opts?.timeoutMs ?? this.#requestTimeoutMs;
        const init = {
            method,
            headers: this.#headers,
            signal: withTimeoutSignal(timeoutMs, opts?.signal),
        };
        if (opts?.body !== undefined) {
            init.body = JSON.stringify(pruneUndefined(opts.body));
        }
        let response;
        try {
            response = await fetch(url, init);
        }
        catch (err) {
            const message = isTimeoutError(err)
                ? `${operation} request timed out after ${Math.round(timeoutMs / 1000)}s`
                : `${operation} request failed: ${err instanceof Error ? err.message : String(err)}`;
            throw new HindsightError(message, undefined, err);
        }
        if (opts?.allow404 && response.status === 404) {
            return null;
        }
        const text = await response.text();
        const parsed = text ? safeJsonParse(text) : null;
        if (!response.ok) {
            const details = (parsed && typeof parsed === "object"
                ? (parsed.detail ??
                    parsed.message)
                : undefined) ??
                parsed ??
                text;
            throw new HindsightError(`${operation} failed: ${typeof details === "string" ? details : JSON.stringify(details)}`, response.status, details);
        }
        return (parsed ?? {});
    }
}
function buildMemoryItem(item) {
    const out = { content: item.content };
    if (item.timestamp !== undefined) {
        out.timestamp = item.timestamp instanceof Date ? formatDateWithLocalOffset(item.timestamp) : item.timestamp;
    }
    if (item.context !== undefined)
        out.context = item.context;
    if (item.metadata !== undefined)
        out.metadata = item.metadata;
    if (item.documentId !== undefined)
        out.document_id = item.documentId;
    if (item.tags !== undefined)
        out.tags = item.tags;
    if (item.observationScopes !== undefined)
        out.observation_scopes = item.observationScopes;
    if (item.strategy !== undefined)
        out.strategy = item.strategy;
    if (item.updateMode !== undefined)
        out.update_mode = item.updateMode;
    return out;
}
function formatDateWithLocalOffset(date) {
    const offsetMinutes = date.getTimezoneOffset();
    const offsetSign = offsetMinutes <= 0 ? "+" : "-";
    const absoluteOffset = Math.abs(offsetMinutes);
    const offsetHours = Math.floor(absoluteOffset / 60);
    const offsetRemainderMinutes = absoluteOffset % 60;
    const milliseconds = date.getMilliseconds();
    const millisecondsPart = milliseconds === 0 ? "" : `.${pad3(milliseconds)}`;
    return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}T${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}${millisecondsPart}${offsetSign}${pad2(offsetHours)}:${pad2(offsetRemainderMinutes)}`;
}
function pad2(value) {
    return value < 10 ? `0${value}` : String(value);
}
function pad3(value) {
    if (value < 10)
        return `00${value}`;
    if (value < 100)
        return `0${value}`;
    return String(value);
}
function buildQueryString(query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null)
            continue;
        if (Array.isArray(value)) {
            for (const item of value) {
                if (item === undefined || item === null)
                    continue;
                params.append(key, String(item));
            }
        }
        else {
            params.set(key, String(value));
        }
    }
    return params.toString();
}
function pruneUndefined(obj) {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
        if (v !== undefined)
            out[k] = v;
    }
    return out;
}
function safeJsonParse(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return null;
    }
}
export function createHindsightClient(config) {
    return new HindsightApi({
        baseUrl: config.hindsightApiUrl,
        apiKey: config.hindsightApiToken ?? undefined,
        userAgent: USER_AGENT,
        timeouts: {
            request: config.requestTimeoutMs,
            reflect: config.reflectTimeoutMs,
            recall: config.recallTimeoutMs,
            retain: config.retainTimeoutMs,
        },
    });
}
