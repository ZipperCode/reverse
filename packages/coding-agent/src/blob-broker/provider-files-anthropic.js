import { isAnthropicOAuthToken } from "@rva/catalog/utils";
const ANTHROPIC_FILES_URL = "https://api.anthropic.com/v1/files";
const ANTHROPIC_VERSION = "2023-06-01";
const ANTHROPIC_FILES_BETA = "files-api-2025-04-14";
function isOfficialAnthropicBaseUrl(baseUrl) {
    try {
        const url = new URL(baseUrl);
        return (url.protocol === "https:" &&
            url.hostname === "api.anthropic.com" &&
            url.port === "" &&
            (url.pathname === "" || url.pathname === "/") &&
            url.search === "" &&
            url.hash === "" &&
            url.username === "" &&
            url.password === "");
    }
    catch {
        return false;
    }
}
function authHeaders(credential) {
    return isAnthropicOAuthToken(credential) ? { Authorization: `Bearer ${credential}` } : { "x-api-key": credential };
}
function requestHeaders(credential) {
    return {
        ...authHeaders(credential),
        "anthropic-version": ANTHROPIC_VERSION,
        "anthropic-beta": ANTHROPIC_FILES_BETA,
    };
}
async function expectAnthropicOk(response, operation) {
    if (response.ok)
        return response;
    const status = response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
    throw new Error(`Anthropic file ${operation} failed with HTTP ${status}`);
}
function parseMetadata(value) {
    if (typeof value !== "object" || value === null)
        throw new Error("Anthropic file upload returned invalid metadata");
    const record = value;
    if (typeof record.id !== "string" ||
        record.id.length === 0 ||
        typeof record.mime_type !== "string" ||
        record.mime_type.length === 0 ||
        typeof record.size_bytes !== "number" ||
        !Number.isSafeInteger(record.size_bytes) ||
        record.size_bytes < 0 ||
        !(record.expires_at === undefined || record.expires_at === null || typeof record.expires_at === "string")) {
        throw new Error("Anthropic file upload returned invalid metadata");
    }
    return {
        id: record.id,
        mime_type: record.mime_type,
        size_bytes: record.size_bytes,
        expires_at: record.expires_at,
    };
}
function parseExpiresAt(value) {
    if (value == null)
        return undefined;
    const expiresAt = Date.parse(value);
    if (!Number.isFinite(expiresAt))
        throw new Error("Anthropic file upload returned an invalid expiration time");
    return expiresAt;
}
function uploadedFile(request) {
    const preferred = request.filename?.trim().replaceAll("\\", "/").split("/").pop();
    const filename = preferred && preferred !== "." && preferred !== ".." ? preferred : "upload";
    return new File([request.bytes], filename, { type: request.mimeType });
}
/**
 * Create a native Anthropic Files API client for an official Anthropic Messages model.
 * Unsupported providers, APIs, and non-Anthropic endpoints return `null` without making a request.
 */
export function createAnthropicFileClient(model, credential, fetchImpl = globalThis.fetch) {
    if (model.provider !== "anthropic" ||
        model.api !== "anthropic-messages" ||
        !isOfficialAnthropicBaseUrl(model.baseUrl)) {
        return null;
    }
    if (credential.length === 0)
        throw new Error("Anthropic Files API credential is required");
    const headers = requestHeaders(credential);
    return {
        provider: "anthropic",
        async upload(request) {
            const form = new FormData();
            form.append("file", uploadedFile(request));
            const response = await expectAnthropicOk(await fetchImpl(ANTHROPIC_FILES_URL, {
                method: "POST",
                headers,
                body: form,
                signal: request.signal,
            }), "upload");
            const metadata = parseMetadata(await response.json());
            const deleteUrl = `${ANTHROPIC_FILES_URL}/${encodeURIComponent(metadata.id)}`;
            return {
                provider: "anthropic",
                id: metadata.id,
                mimeType: metadata.mime_type,
                bytes: metadata.size_bytes,
                expiresAt: parseExpiresAt(metadata.expires_at),
                delete: { method: "DELETE", url: deleteUrl, headers },
            };
        },
        async delete(handle) {
            if (handle.provider !== "anthropic" || !handle.id)
                throw new Error("Cannot delete an invalid Anthropic file handle");
            await expectAnthropicOk(await fetchImpl(`${ANTHROPIC_FILES_URL}/${encodeURIComponent(handle.id)}`, {
                method: "DELETE",
                headers,
            }), "delete");
        },
    };
}
