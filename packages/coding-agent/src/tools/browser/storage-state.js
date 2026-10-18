import * as path from "node:path";
import { getConfigRootDir, isRecord, untilAborted } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { resolveToCwd } from "../path-utils";
import { throwIfAborted } from "../tool-errors";
const COOKIE_PARSE_ERROR = "tab.setCookies() received malformed cookie input";
const COOKIE_SET_ERROR = "tab.setCookies() could not set the supplied cookies";
const STORAGE_STATE_ERROR = "tab.loadState() received an invalid browser state file";
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
function cookieView(cookie) {
    return {
        name: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        expires: cookie.expires,
        httpOnly: cookie.httpOnly ?? false,
        secure: cookie.secure,
        sameSite: cookie.sameSite === "Strict" || cookie.sameSite === "Lax" || cookie.sameSite === "None"
            ? cookie.sameSite
            : "Lax",
    };
}
function isScope(value) {
    if (!isRecord(value) || "name" in value || "value" in value)
        return false;
    return Object.keys(value).every(key => key === "domain" || key === "url");
}
function parseCookieObject(value) {
    if (!isRecord(value) || typeof value.name !== "string" || typeof value.value !== "string") {
        throw new ToolError(COOKIE_PARSE_ERROR);
    }
    if (!COOKIE_NAME_RE.test(value.name))
        throw new ToolError(COOKIE_PARSE_ERROR);
    const cookie = { name: value.name, value: value.value };
    for (const key of ["domain", "path", "url"]) {
        const field = value[key];
        if (field !== undefined && typeof field !== "string")
            throw new ToolError(COOKIE_PARSE_ERROR);
        if (field !== undefined)
            cookie[key] = field;
    }
    for (const key of ["httpOnly", "secure"]) {
        const field = value[key];
        if (field !== undefined && typeof field !== "boolean")
            throw new ToolError(COOKIE_PARSE_ERROR);
        if (field !== undefined)
            cookie[key] = field;
    }
    if (value.expires !== undefined) {
        if (typeof value.expires !== "number" || !Number.isFinite(value.expires))
            throw new ToolError(COOKIE_PARSE_ERROR);
        cookie.expires = value.expires;
    }
    if (value.sameSite !== undefined) {
        if (value.sameSite !== "Strict" && value.sameSite !== "Lax" && value.sameSite !== "None") {
            throw new ToolError(COOKIE_PARSE_ERROR);
        }
        cookie.sameSite = value.sameSite;
    }
    return cookie;
}
function parseCookieHeader(header) {
    const parts = header.split(";");
    if (parts.length === 0)
        throw new ToolError(COOKIE_PARSE_ERROR);
    const cookies = [];
    for (const part of parts) {
        const separator = part.indexOf("=");
        if (separator <= 0)
            throw new ToolError(COOKIE_PARSE_ERROR);
        const name = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();
        if (!COOKIE_NAME_RE.test(name))
            throw new ToolError(COOKIE_PARSE_ERROR);
        cookies.push({ name, value });
    }
    return cookies;
}
function extractCurlCookieHeaders(source) {
    const headers = [];
    const pattern = /(?:^|\s)(?:-H|--header)\s+(?:'([^']*)'|"([^"]*)"|([^\s]+))/gi;
    for (const match of source.matchAll(pattern)) {
        const header = match[1] ?? match[2] ?? match[3] ?? "";
        const separator = header.indexOf(":");
        if (separator < 0 || header.slice(0, separator).trim().toLowerCase() !== "cookie")
            continue;
        headers.push(header.slice(separator + 1).trim());
    }
    return headers;
}
function parseCookieString(source) {
    const trimmed = source.trim();
    if (!trimmed)
        throw new ToolError(COOKIE_PARSE_ERROR);
    if (trimmed.startsWith("[")) {
        let parsed;
        try {
            parsed = JSON.parse(trimmed);
        }
        catch {
            throw new ToolError(COOKIE_PARSE_ERROR);
        }
        if (!Array.isArray(parsed) || parsed.length === 0)
            throw new ToolError(COOKIE_PARSE_ERROR);
        return parsed.map(parseCookieObject);
    }
    const curlHeaders = extractCurlCookieHeaders(trimmed);
    if (curlHeaders.length > 0)
        return curlHeaders.flatMap(parseCookieHeader);
    return parseCookieHeader(trimmed.replace(/^cookie\s*:\s*/i, ""));
}
/** Parse `tab.setCookies()` arguments (objects, Cookie headers, cURL dumps, JSON arrays, trailing scope). */
export function normalizeCookieArguments(args) {
    if (args.length === 0)
        throw new ToolError(COOKIE_PARSE_ERROR);
    const items = [...args];
    const trailing = items.at(-1);
    const scope = isScope(trailing) ? items.pop() : undefined;
    if (items.length === 0)
        throw new ToolError(COOKIE_PARSE_ERROR);
    const parsed = items.flatMap(item => typeof item === "string" ? parseCookieString(item) : [parseCookieObject(item)]);
    return parsed.map(cookie => ({ ...scope, ...cookie }));
}
/** A Web Storage value as stored: strings verbatim, anything else JSON. */
export function storageValue(value) {
    if (typeof value === "string")
        return value;
    let serialized;
    try {
        serialized = JSON.stringify(value);
    }
    catch {
        throw new ToolError("tab.setStorage() could not serialize a supplied value");
    }
    if (serialized === undefined)
        throw new ToolError("tab.setStorage() could not serialize a supplied value");
    return serialized;
}
/** The key/value pairs of a `tab.setStorage()` entries object. */
export function storageEntries(value) {
    if (!isRecord(value))
        throw new ToolError("tab.setStorage() expects a key/value object");
    const entries = [];
    for (const key in value) {
        if (Object.hasOwn(value, key))
            entries.push([key, storageValue(value[key])]);
    }
    return entries;
}
/** Reject storage kinds other than `local`/`session`. */
export function assertStorageKind(kind) {
    if (kind !== "local" && kind !== "session") {
        throw new ToolError('Storage kind must be "local" or "session"');
    }
}
/** Page function: the current origin's Web Storage, or null for an opaque origin. */
export function readOriginStorageInPage() {
    const scope = globalThis;
    if (scope.location.origin === "null")
        return null;
    const entries = (store) => {
        const result = [];
        for (let index = 0; index < store.length; index++) {
            const name = store.key(index);
            if (name !== null)
                result.push({ name, value: store.getItem(name) ?? "" });
        }
        return result;
    };
    return {
        origin: scope.location.origin,
        localStorage: entries(scope.localStorage),
        sessionStorage: entries(scope.sessionStorage),
    };
}
/** Page function: replace the current origin's Web Storage with `state`. */
export function restoreOriginStorageInPage(state) {
    const scope = globalThis;
    scope.localStorage.clear();
    for (const entry of state.localStorage)
        scope.localStorage.setItem(entry.name, entry.value);
    scope.sessionStorage.clear();
    for (const entry of state.sessionStorage ?? [])
        scope.sessionStorage.setItem(entry.name, entry.value);
}
/** Page function: every pair of one storage area, or one key's value. */
export function readStorageInPage(area, key) {
    const scope = globalThis;
    const store = area === "local" ? scope.localStorage : scope.sessionStorage;
    if (key !== undefined)
        return store.getItem(key);
    const result = {};
    for (let index = 0; index < store.length; index++) {
        const name = store.key(index);
        if (name !== null)
            result[name] = store.getItem(name) ?? "";
    }
    return result;
}
/** Page function: store `pairs` in one storage area. */
export function writeStorageInPage(area, pairs) {
    const scope = globalThis;
    const store = area === "local" ? scope.localStorage : scope.sessionStorage;
    for (const [key, entry] of pairs)
        store.setItem(key, entry);
}
/** Page function: clear one storage area. */
export function clearStorageInPage(area) {
    const scope = globalThis;
    (area === "local" ? scope.localStorage : scope.sessionStorage).clear();
}
async function readOriginStorage(page, signal) {
    return await untilAborted(signal, () => page.evaluate(readOriginStorageInPage));
}
async function restoreOriginStorage(page, origin, signal) {
    await untilAborted(signal, () => page.evaluate(restoreOriginStorageInPage, origin));
}
function parseStorageEntries(value) {
    if (!Array.isArray(value))
        throw new ToolError(STORAGE_STATE_ERROR);
    return value.map(entry => {
        if (!isRecord(entry) || typeof entry.name !== "string" || typeof entry.value !== "string") {
            throw new ToolError(STORAGE_STATE_ERROR);
        }
        return { name: entry.name, value: entry.value };
    });
}
function parseStorageState(value) {
    if (!isRecord(value) || !Array.isArray(value.cookies) || !Array.isArray(value.origins)) {
        throw new ToolError(STORAGE_STATE_ERROR);
    }
    const cookies = value.cookies.map(cookie => {
        const parsed = parseCookieObject(cookie);
        if (!parsed.domain || !parsed.path || parsed.expires === undefined)
            throw new ToolError(STORAGE_STATE_ERROR);
        return {
            ...parsed,
            domain: parsed.domain,
            path: parsed.path,
            expires: parsed.expires,
            httpOnly: parsed.httpOnly ?? false,
            secure: parsed.secure ?? false,
            sameSite: parsed.sameSite ?? "Lax",
        };
    });
    const origins = value.origins.map(entry => {
        if (!isRecord(entry) || typeof entry.origin !== "string")
            throw new ToolError(STORAGE_STATE_ERROR);
        try {
            const url = new URL(entry.origin);
            if (url.origin !== entry.origin)
                throw new ToolError(STORAGE_STATE_ERROR);
        }
        catch {
            throw new ToolError(STORAGE_STATE_ERROR);
        }
        return {
            origin: entry.origin,
            localStorage: parseStorageEntries(entry.localStorage),
            ...(entry.sessionStorage === undefined ? {} : { sessionStorage: parseStorageEntries(entry.sessionStorage) }),
        };
    });
    return { cookies, origins };
}
/** Read cookies visible to the current page or the supplied URLs. */
export async function readCookies(page, options = {}, signal) {
    if (!Array.isArray(options.urls) && options.urls !== undefined) {
        throw new ToolError("tab.cookies() expects urls to be an array");
    }
    const cookies = await untilAborted(signal, () => page.cookies(...(options.urls ?? [])));
    return cookies.map(cookieView);
}
/** Parse and install cookie objects, raw Cookie headers, cURL dumps, or JSON arrays. */
export async function setPageCookies(page, args, signal) {
    let cookies;
    try {
        cookies = normalizeCookieArguments(args);
    }
    catch (error) {
        if (error instanceof ToolError)
            throw error;
        throw new ToolError(COOKIE_PARSE_ERROR);
    }
    try {
        await untilAborted(signal, () => page.setCookie(...cookies));
    }
    catch {
        throwIfAborted(signal);
        throw new ToolError(COOKIE_SET_ERROR);
    }
}
/** Delete all current-page cookies or only cookies with selected names. */
export async function clearPageCookies(page, options = {}, signal) {
    if (!Array.isArray(options.names) && options.names !== undefined) {
        throw new ToolError("tab.clearCookies() expects names to be an array");
    }
    const wanted = options.names ? new Set(options.names) : undefined;
    const cookies = await untilAborted(signal, () => page.cookies());
    const matching = cookies.filter(cookie => !wanted || wanted.has(cookie.name));
    if (matching.length === 0)
        return;
    await untilAborted(signal, () => page.deleteCookie(...matching.map(cookie => ({ name: cookie.name, domain: cookie.domain, path: cookie.path }))));
}
/** Read all Web Storage pairs or one selected value from the current origin. */
export async function readStorage(page, kind, options = {}, signal) {
    assertStorageKind(kind);
    if (options.key !== undefined && typeof options.key !== "string") {
        throw new ToolError("tab.storage() expects key to be a string");
    }
    return await untilAborted(signal, () => page.evaluate(readStorageInPage, kind, options.key));
}
/** Set one Web Storage pair or a map of pairs on the current origin. */
export async function setPageStorage(page, kind, keyOrEntries, value, signal) {
    assertStorageKind(kind);
    const entries = typeof keyOrEntries === "string"
        ? [[keyOrEntries, storageValue(value)]]
        : storageEntries(keyOrEntries);
    await untilAborted(signal, () => page.evaluate(writeStorageInPage, kind, entries));
}
/** Clear one Web Storage area on the current origin. */
export async function clearPageStorage(page, kind, signal) {
    assertStorageKind(kind);
    await untilAborted(signal, () => page.evaluate(clearStorageInPage, kind));
}
/** Where `tab.saveState()` writes: the requested path, else `~/.omp/browser-state/<tab>.json`. */
export function storageStatePath(tabName, requestedPath, cwd) {
    const safeName = tabName.replace(/[^A-Za-z0-9._-]/g, "_");
    const fileName = safeName === "." || safeName === ".." ? "_" : safeName || "main";
    return requestedPath
        ? resolveToCwd(requestedPath, cwd)
        : path.join(getConfigRootDir(), "browser-state", `${fileName}.json`);
}
/** Save cookies and current-origin Web Storage to a Playwright-compatible state file. */
export async function saveStorageState(page, name, requestedPath, cwd, signal) {
    const destination = storageStatePath(name, requestedPath, cwd);
    const [browserCookies, origin] = await Promise.all([
        untilAborted(signal, () => page.browserContext().cookies()),
        readOriginStorage(page, signal),
    ]);
    const state = { cookies: browserCookies.map(cookieView), origins: origin ? [origin] : [] };
    await untilAborted(signal, () => Bun.write(destination, `${JSON.stringify(state, null, 2)}\n`));
    return destination;
}
/** Read and validate a saved browser state file. */
export async function readStorageStateFile(requestedPath, cwd, signal) {
    if (typeof requestedPath !== "string" || requestedPath.length === 0)
        throw new ToolError(STORAGE_STATE_ERROR);
    const source = resolveToCwd(requestedPath, cwd);
    try {
        const text = await untilAborted(signal, () => Bun.file(source).text());
        return parseStorageState(JSON.parse(text));
    }
    catch (error) {
        throwIfAborted(signal);
        if (error instanceof ToolError)
            throw error;
        throw new ToolError(STORAGE_STATE_ERROR);
    }
}
/** Restore cookies and Web Storage from a saved browser state file. */
export async function loadStorageState(page, requestedPath, cwd, options) {
    const state = await readStorageStateFile(requestedPath, cwd, options.signal);
    if (state.cookies.length > 0) {
        try {
            await untilAborted(options.signal, () => page.browserContext().setCookie(...state.cookies));
        }
        catch {
            throwIfAborted(options.signal);
            throw new ToolError("tab.loadState() could not restore cookies from the browser state file");
        }
    }
    const currentOrigin = await untilAborted(options.signal, () => page.evaluate(() => {
        const scope = globalThis;
        return scope.location.origin;
    }));
    const loadedOrigins = [];
    const skippedOrigins = [];
    for (const origin of state.origins) {
        if (origin.origin === currentOrigin) {
            await restoreOriginStorage(page, origin, options.signal);
            loadedOrigins.push(origin.origin);
            continue;
        }
        if (!options.allowOtherOrigins || (origin.sessionStorage?.length ?? 0) > 0) {
            // Closing a temporary page discards its sessionStorage, so only localStorage-only
            // origins can be restored without disturbing the caller's current page.
            skippedOrigins.push(origin.origin);
            continue;
        }
        let temporary;
        try {
            temporary = await untilAborted(options.signal, () => page.browserContext().newPage());
            await untilAborted(options.signal, () => temporary.goto(`${origin.origin}/`, {
                waitUntil: "domcontentloaded",
                timeout: options.navigationTimeoutMs,
            }));
            const navigatedOrigin = await untilAborted(options.signal, () => temporary.evaluate(() => {
                const scope = globalThis;
                return scope.location.origin;
            }));
            if (navigatedOrigin !== origin.origin)
                throw new ToolError("Browser state origin redirected");
            await restoreOriginStorage(temporary, origin, options.signal);
            loadedOrigins.push(origin.origin);
        }
        catch {
            throwIfAborted(options.signal);
            skippedOrigins.push(origin.origin);
        }
        finally {
            await temporary?.close().catch(() => undefined);
        }
    }
    return { loadedOrigins, skippedOrigins };
}
