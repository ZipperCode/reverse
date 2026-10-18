/** Explicit failure used for destinations that cannot be contacted safely. */
export class DestinationUnavailableError extends Error {
    /** Destination that is unavailable. */
    destination;
    constructor(destination, reason) {
        super(`${destination} is unavailable: ${reason}`);
        this.name = "DestinationUnavailableError";
        this.destination = destination;
    }
}
/** Read a required option without coercing its configured type. */
export function requireOption(config, key) {
    const value = config.options[key];
    if (value === undefined)
        throw new Error(`Missing required destination option: ${key}`);
    return value;
}
/** Read a string option, returning a fallback when it is absent. */
export function optionString(config, key, fallback) {
    const value = config.options[key];
    if (value === undefined)
        return fallback;
    if (typeof value !== "string")
        throw new Error(`Destination option ${key} must be a string`);
    return value;
}
/** Read a number option, returning a fallback when it is absent. */
export function optionNumber(config, key, fallback) {
    const value = config.options[key];
    if (value === undefined)
        return fallback;
    if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new Error(`Destination option ${key} must be a finite number`);
    }
    return value;
}
/** Read a boolean option, returning a fallback when it is absent. */
export function optionBoolean(config, key, fallback) {
    const value = config.options[key];
    if (value === undefined)
        return fallback;
    if (typeof value !== "boolean")
        throw new Error(`Destination option ${key} must be a boolean`);
    return value;
}
/** Read a credential without exposing its value in an error. */
export function credentialString(config, key) {
    const value = config.credentials[key];
    return value === "" ? undefined : value;
}
/** Read a required credential without exposing its value in an error. */
export function requireCredential(config, key) {
    const value = credentialString(config, key);
    if (value === undefined)
        throw new Error(`Missing required destination credential: ${key}`);
    return value;
}
/** Select the injected request implementation, or Bun's global fetch by default. */
export function fetchFor(config) {
    return config.fetch ?? globalThis.fetch;
}
/** Produce a safe remote filename from an upload request. */
export function fileNameFor(request) {
    const preferred = request.filename?.trim().replaceAll("\\", "/").split("/").pop();
    if (preferred && preferred !== "." && preferred !== "..")
        return preferred;
    const extension = request.extension.replace(/^\.+/, "");
    return extension ? `upload.${extension}` : "upload";
}
/** Build a native multipart form containing string fields and the uploaded file. */
export function multipartFile(request, fieldName = "file", fields = {}) {
    const form = new FormData();
    for (const key in fields)
        form.append(key, fields[key]);
    const file = new File([request.bytes], fileNameFor(request), { type: request.mimeType });
    form.append(fieldName, file);
    return form;
}
/** Return a successful response or throw a secret-safe HTTP status error. */
export async function expectOk(response, destination) {
    if (!response.ok) {
        const status = response.statusText ? `${response.status} ${response.statusText}` : String(response.status);
        throw new Error(`${destination} upload failed with HTTP ${status}`);
    }
    return response;
}
/** Construct a durable publication while preserving all upstream metadata. */
export function publication(destination, request, url, extras = {}) {
    return {
        url,
        destination,
        bytes: request.bytes.byteLength,
        ...(extras.expiresAt === undefined ? {} : { expiresAt: extras.expiresAt }),
        ...(extras.delete === undefined ? {} : { delete: extras.delete }),
        ...(extras.remoteId === undefined ? {} : { remoteId: extras.remoteId }),
    };
}
