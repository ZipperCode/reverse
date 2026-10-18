/**
 * Shared types and utilities for web-fetch handlers
 */
import { scheduler } from "node:timers/promises";
import { ptree } from "@rva/utils";
import { ToolAbortError } from "../../tools/tool-errors";
import { decodeBody, readBodyCapped } from "../response-body";
export { formatNumber } from "@rva/utils";
export const MAX_OUTPUT_CHARS = 500000;
export const MAX_BYTES = 50 * 1024 * 1024;
const USER_AGENTS = [
    "curl/8.0",
    "Mozilla/5.0 (compatible; TextBot/1.0)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
];
function isBotBlocked(status, content) {
    if (status === 403 || status === 503) {
        const lower = content.toLowerCase();
        return (lower.includes("cloudflare") ||
            lower.includes("captcha") ||
            lower.includes("challenge") ||
            lower.includes("blocked") ||
            lower.includes("access denied") ||
            lower.includes("bot detection"));
    }
    return false;
}
/**
 * Truncate and cleanup output
 */
export function finalizeOutput(content) {
    const cleaned = content.replace(/\n{3,}/g, "\n\n").trim();
    const truncated = cleaned.length > MAX_OUTPUT_CHARS;
    return {
        content: cleaned.slice(0, MAX_OUTPUT_CHARS),
        truncated,
    };
}
const RETRY_AFTER_MAX_MS = 10000;
/** Parse a Retry-After header (seconds or HTTP-date) into a bounded delay. */
function parseRetryAfterMs(value) {
    if (!value)
        return 1000;
    const seconds = Number(value);
    if (Number.isFinite(seconds))
        return Math.min(Math.max(seconds, 0) * 1000, RETRY_AFTER_MAX_MS);
    const date = Date.parse(value);
    if (!Number.isNaN(date))
        return Math.min(Math.max(date - Date.now(), 0), RETRY_AFTER_MAX_MS);
    return 1000;
}
/**
 * Fetch a page with timeout and size limit
 */
export async function loadPage(url, options = {}) {
    const { timeout = 20, headers = {}, maxBytes = MAX_BYTES, signal, method = "GET", body } = options;
    let lastError;
    let retried429 = false;
    for (let attempt = 0; attempt < USER_AGENTS.length; attempt++) {
        if (signal?.aborted) {
            throw new ToolAbortError();
        }
        const userAgent = USER_AGENTS[attempt];
        const requestSignal = ptree.combineSignals(signal, timeout * 1000);
        try {
            const requestInit = {
                signal: requestSignal,
                method,
                headers: {
                    "User-Agent": userAgent,
                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "identity", // Cloudflare Markdown-for-Agents returns corrupted bytes when compression is negotiated
                    ...headers,
                },
                redirect: "follow",
            };
            if (body !== undefined) {
                requestInit.body = body;
            }
            const response = await fetch(url, requestInit);
            const rawContentType = response.headers.get("content-type") ?? "";
            const contentType = rawContentType.split(";")[0]?.trim().toLowerCase() ?? "";
            const finalUrl = response.url;
            if (response.status === 429 && !retried429) {
                // Rate limited: retry once, honoring a bounded Retry-After. The
                // wait observes the caller's signal so an Esc during the backoff
                // does not stall for up to the full delay.
                retried429 = true;
                const delayMs = parseRetryAfterMs(response.headers.get("retry-after"));
                void response.body?.cancel().catch(() => { });
                try {
                    await scheduler.wait(delayMs, { signal });
                }
                catch {
                    throw new ToolAbortError();
                }
                attempt--; // Reuse the same user agent for the retry.
                continue;
            }
            if (response.ok && options.skipBodyForContentType?.(contentType)) {
                void response.body?.cancel().catch(() => { });
                return { content: "", contentType, finalUrl, ok: true, status: response.status, bodySkipped: true };
            }
            const responseBody = await readBodyCapped(response, maxBytes);
            if (!responseBody) {
                // A successful response can still be bodyless (HTTP 204, or a null
                // body stream): keep the transport's own success verdict instead of
                // rewriting it, so the caller's status handling (a 204 is a valid
                // empty read, not a failed fetch) runs on the real outcome.
                return { content: "", contentType, finalUrl, ok: response.ok, status: response.status };
            }
            const content = decodeBody(responseBody.bytes, rawContentType);
            if (isBotBlocked(response.status, content) && attempt < USER_AGENTS.length - 1) {
                continue;
            }
            if (!response.ok) {
                return {
                    content,
                    contentType,
                    finalUrl,
                    ok: false,
                    status: response.status,
                    truncated: responseBody.truncated,
                };
            }
            return {
                content,
                contentType,
                finalUrl,
                ok: true,
                status: response.status,
                truncated: responseBody.truncated,
            };
        }
        catch (error) {
            if (signal?.aborted) {
                throw new ToolAbortError();
            }
            lastError = error instanceof Error ? error.message : String(error);
            if (attempt === USER_AGENTS.length - 1) {
                return { content: "", contentType: "", finalUrl: url, ok: false, error: lastError };
            }
        }
    }
    return { content: "", contentType: "", finalUrl: url, ok: false, error: lastError };
}
/** Module-level Turndown instance — built lazily on first use. */
let turndownPromise;
function getTurndown() {
    turndownPromise ||= initTurndown();
    return turndownPromise;
}
async function initTurndown() {
    // Lazy import keeps turndown/turndown-plugin-gfm off the startup graph.
    const { createTurndown } = await import("../../utils/turndown");
    return createTurndown();
}
/**
 * Convert HTML to markdown using Turndown with GFM support.
 * Strips script/style tags before conversion.
 */
export async function htmlToBasicMarkdown(html) {
    const cleaned = html.replace(/<script[\s\S]*?<\/script>/gi, "").replace(/<style[\s\S]*?<\/style>/gi, "");
    const turndown = await getTurndown();
    return turndown.turndown(cleaned).trim();
}
/**
 * Build a RenderResult from markdown content. Calls finalizeOutput internally.
 */
export function buildResult(md, opts) {
    const output = finalizeOutput(md);
    return {
        url: opts.url,
        finalUrl: opts.finalUrl ?? opts.url,
        contentType: opts.contentType ?? "text/markdown",
        method: opts.method,
        content: output.content,
        fetchedAt: opts.fetchedAt,
        truncated: output.truncated,
        notes: opts.notes ?? [],
    };
}
/**
 * Format a date value as YYYY-MM-DD. Returns empty string on invalid input.
 */
export function formatIsoDate(value) {
    if (value == null)
        return "";
    if (typeof value === "string") {
        const datePrefix = value.match(/^\d{4}-\d{2}-\d{2}/);
        if (datePrefix)
            return datePrefix[0];
    }
    try {
        return new Date(value).toISOString().split("T")[0];
    }
    catch {
        return "";
    }
}
/**
 * Decode common HTML entities.
 */
export function decodeHtmlEntities(text) {
    return text
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#0?39;/g, "'")
        .replace(/&#x27;/g, "'")
        .replace(/&#x2F;/g, "/")
        .replace(/&nbsp;/g, " ");
}
/**
 * Format seconds into HH:MM:SS or MM:SS.
 */
export function formatMediaDuration(totalSeconds) {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const secs = Math.floor(totalSeconds % 60);
    if (hours > 0)
        return `${hours}:${String(minutes).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    return `${minutes}:${String(secs).padStart(2, "0")}`;
}
export function getLocalizedText(value, defaultLocale) {
    if (value == null)
        return undefined;
    if (typeof value === "string")
        return value;
    if (defaultLocale && value[defaultLocale])
        return value[defaultLocale];
    return (value["en-US"] ?? value.en_US ?? value.en ?? Object.values(value).find(v => typeof v === "string") ?? undefined);
}
/**
 * Check if content looks like HTML by inspecting the leading tag.
 */
export function looksLikeHtml(content) {
    // Only the leading tag matters; lowercase a short prefix instead of the whole body.
    const trimmed = content.trimStart().slice(0, 16).toLowerCase();
    return (trimmed.startsWith("<!doctype") ||
        trimmed.startsWith("<html") ||
        trimmed.startsWith("<head") ||
        trimmed.startsWith("<body"));
}
