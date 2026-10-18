/**
 * A browser tab shown as a Tern browser picture-in-picture: every helper of
 * the tab API drives the PiP's native web view through Tern's browser op
 * protocol (`wire.ts`). Pages are reached through `eval` (page world for user
 * code and page instrumentation, the isolated world for omp's kit), trusted
 * `input` events at element centres, `capture`, `pdf` and the Tern-level ops;
 * what the page reports on its own arrives through `events` polling.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isRecord, logger, Snowflake, untilAborted } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { JsRuntime } from "../../../eval/js/shared/runtime";
import { formatScreenshot, resizeImage } from "../../../utils/image-resize";
import { resolveToCwd } from "../../path-utils";
import { ToolAbortError, throwIfAborted } from "../../tool-errors";
import { buildA11yPageScript, formatA11ySummary, normalizeA11yResult, } from "../a11y/audit";
import { parseAriaRefSelector } from "../aria/aria-snapshot";
import { loadedKnownDevices, loadPuppeteer } from "../launch";
import { pushStateInPage } from "../navigation";
import { normalizeAllowedDomains } from "../network";
import { resolveOpTimeouts, resolveWaitTimeout, ZERO_MATCH_FAIL_FAST_MS } from "../op-timeouts";
import { DEFAULT_STYLE_PROPERTIES } from "../queries";
import { extractReadableFromHtml } from "../readable";
import { enableReact, REACT_HOOK_INIT_SOURCE, requireReactHookResult, } from "../react/devtools-hook";
import { reactRendersSource } from "../react/renders";
import { reactSuspenseSource } from "../react/suspense";
import { reactInspectResult, reactInspectSource, reactTreeSource, } from "../react/tree";
import { collectVitals, VITALS_INIT_SOURCE } from "../react/vitals";
import { installCursorOverlay, RecordingController, removeCursorOverlay, } from "../recording";
import { createPngDiff, formatScreenshotLegend, pngPixelChangeRatio, screenshotArea, screenshotQuality, screenshotScope, screenshotThreshold, } from "../screenshot";
import { ariaSnapshotBaselineKey, diffAriaSnapshot, postProcessAriaSnapshot, } from "../snapshot-plus";
import { assertStorageKind, clearStorageInPage, normalizeCookieArguments, readOriginStorageInPage, readStorageInPage, readStorageStateFile, restoreOriginStorageInPage, storageEntries, storageStatePath, storageValue, writeStorageInPage, } from "../storage-state";
import { assertTabPressArgs } from "../tab-arguments";
import { readFilePayloads } from "../upload-files";
import { installWebMcpPageHook, uninstallWebMcpPageHook, WEBMCP_BRIDGE_KEY, WebMcpController, webMcpInvokeInPage, webMcpSnapshotInPage, } from "../webmcp";
import { keyDownStep, keyUpStep, pressSteps, ternKey, typeSteps } from "./keys";
import { TernNetworkLog } from "./network-log";
import { TERN_CAPTURE_GLOBAL, TERN_CAPTURE_INSTALLER, ternCaptureScript } from "./page-capture";
import { TERN_KIT_SOURCE, } from "./page-kit";
import { parseTernSelector } from "./selectors";
import { TernError } from "./wire";
const EVENT_LOG_LIMIT = 4000;
const CONSOLE_LIMIT = 500;
const NAVIGATION_IDLE_MS = 500;
const KIT_CALL = "async function (method, args) { const kit = globalThis.__ompTernKit; if (!kit) return { missing: true }; return { value: await kit[method](...args) }; }";
const HANDLE_ATTRIBUTE = "data-omp-tern-handle";
/** The tab-helper name for errors: `tab.pdf()`. */
function helper(name) {
    return `tab.${name}()`;
}
/** A ToolError for a helper the Tern backend cannot provide. */
function unsupported(name, reason) {
    return new ToolError(`${helper(name)} is not supported on the Tern browser backend: ${reason}`);
}
/** The message of a page-side exception answered by Tern (`js` errors), without Tern's prefix. */
function pageErrorText(error) {
    return error.message.replace(/^Tern browser \w+ failed \(js\): /, "");
}
/**
 * The page function running a user source string: an expression's value, or
 * — when the source is a statement list rather than an expression — the
 * statements as a function body. The choice is made by compiling (never
 * running) both candidates here, so the code runs exactly once in the page;
 * source that compiles as neither goes as an expression and the page reports
 * its syntax error.
 */
export function userSourceFunction(source) {
    const expression = `return (\n${source}\n);`;
    try {
        new Function(expression);
        return `function () {\n${expression}\n}`;
    }
    catch { }
    try {
        new Function(source);
        return `function () {\n${source}\n}`;
    }
    catch { }
    return `function () {\n${expression}\n}`;
}
/** The first line of a page-side exception, without the `Error: ` prefix: agent-readable kit failures. */
function kitErrorText(error) {
    return (pageErrorText(error).split("\n", 1)[0] ?? "").replace(/^Error: /, "");
}
function numberOr(value, fallback) {
    return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
function stringOr(value, fallback) {
    return typeof value === "string" ? value : fallback;
}
/** Whether a cookie applies to `url` (domain, path and scheme). */
function cookieMatchesUrl(cookie, url) {
    const host = url.hostname.toLowerCase();
    const domain = cookie.domain.toLowerCase().replace(/^\./, "");
    const domainMatch = cookie.domain.startsWith(".") ? host === domain || host.endsWith(`.${domain}`) : host === domain;
    if (!domainMatch)
        return false;
    if (cookie.secure && url.protocol !== "https:")
        return false;
    const cookiePath = cookie.path || "/";
    return (url.pathname === cookiePath || url.pathname.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`));
}
/**
 * `args` without trailing `undefined`s. JSON turns an array's `undefined` into `null`, so an omitted
 * optional argument would reach the page function as `null` instead of `undefined`.
 */
function withoutTrailingUndefined(args) {
    let end = args.length;
    while (end > 0 && args[end - 1] === undefined)
        end--;
    return end === args.length ? args : args.slice(0, end);
}
/** Whether `requested` is the address `current` already shows (`https://a.test` is `https://a.test/`). */
function sameAddress(requested, current) {
    if (requested === current)
        return true;
    try {
        return new URL(requested).href === new URL(current).href;
    }
    catch {
        return false;
    }
}
/** A Tern cookie as the tab API reports it. */
function cookieFromTern(value) {
    if (!isRecord(value) || typeof value.name !== "string" || typeof value.value !== "string")
        return null;
    const sameSite = value.sameSite === "Strict" || value.sameSite === "None" ? value.sameSite : "Lax";
    return {
        name: value.name,
        value: value.value,
        domain: stringOr(value.domain, ""),
        path: stringOr(value.path, "/"),
        expires: numberOr(value.expires, -1),
        httpOnly: value.httpOnly === true,
        secure: value.secure === true,
        sameSite,
    };
}
/** A captured console message's level (unknown levels read as `log`). */
function consoleLevel(value) {
    return value === "info" || value === "warn" || value === "error" || value === "debug" ? value : "log";
}
/**
 * The Tern backend's tab: one PiP (`block`) and the state its helpers keep —
 * the event cursor, console and request logs, dialog/download/frame state,
 * emulation, scripts, pointer and modifier state.
 */
export class TernTab {
    /** Guest file-name prefix of Tern runs. */
    runLabel = "tern-run";
    /** The PiP's block id (daemon-native). */
    block;
    #client;
    #name;
    /** The user's block this tab adopted (released, never closed); undefined for omp's own PiP. */
    adopted;
    #url = "about:blank";
    #title = "";
    #shown;
    #viewport;
    #cursor = 0;
    #events = [];
    #pulling;
    #runContext;
    #runtime;
    #pageFacade;
    #browserFacade;
    // Console capture.
    #console = [];
    #consoleSeq = 1;
    #consoleDropped = 0;
    // Page state from events.
    #pendingDialog;
    #frameUrls = new Map();
    #downloads = new Map();
    #completedDownloads = [];
    #unclaimedDownloads = [];
    #downloadDir;
    // Network, scripts and emulation.
    #network = new TernNetworkLog();
    #initScripts = [];
    #nextInitScript = 1;
    #allowedDomains = [];
    #emulation = {};
    #pageEmulation = {};
    #deviceUserAgent;
    #reactHook = false;
    #cursorOverlay = false;
    // Input state.
    #pointer;
    #buttons = new Set();
    #mods = [];
    // Screenshots, snapshots, recording, WebMCP.
    #screenshotHistory = new Map();
    #ariaBaselines = new Map();
    #recording = new RecordingController();
    #webmcp;
    constructor(opts) {
        this.#client = opts.client;
        this.block = opts.block;
        this.#name = opts.name;
        this.#viewport = { ...opts.viewport };
        this.adopted = opts.adopted;
    }
    /**
     * Open a PiP over pane `opts.pane` at `about:blank`, wait for that load to
     * report, configure the PiP (dialog policy, allowlist, agent, TLS, downloads,
     * scripts) and only then make the first real navigation. The PiP closes
     * again when configuration fails, and when the open was abandoned
     * (timeout/abort) but Tern answered late.
     */
    static async open(client, opts) {
        const startedAt = Date.now();
        const remainingMs = () => Math.max(1, opts.timeoutMs - (Date.now() - startedAt));
        const opened = await client.request({
            op: "open",
            owner: opts.pane,
            url: "about:blank",
            width: Math.round(opts.viewport.width),
            height: Math.round(opts.viewport.height),
        }, {
            timeoutMs: opts.timeoutMs,
            signal: opts.signal,
            onLateAnswer: late => {
                if (!isRecord(late) || typeof late.block !== "number")
                    return;
                void client.request({ op: "close", block: late.block }, { timeoutMs: 5000 }).catch(() => undefined);
            },
        });
        if (!isRecord(opened) || typeof opened.block !== "number") {
            throw new ToolError("Tern answered the browser open without a block id");
        }
        const tab = new TernTab({ client, block: opened.block, name: opts.name, viewport: opts.viewport });
        try {
            await tab.#configure(opts, remainingMs());
            // The PiP already shows about:blank, and a Tern web view never reloads an unchanged address.
            if (opts.url && opts.url !== "about:blank") {
                await tab.goto(opts.url, { waitUntil: opts.waitUntil ?? "load", timeoutMs: remainingMs() });
            }
        }
        catch (error) {
            await tab.close({ timeoutMs: 5000 }).catch(() => undefined);
            throw error;
        }
        return tab;
    }
    /**
     * Drive the user's existing browser block `opts.block` (docked or PiP)
     * without opening anything: skip the events it reported before, apply only
     * the page settings the caller gave (plus omp's document-start scripts,
     * installed into the current document too), and navigate only when `url`
     * is given. A failure releases the block again; it is never closed.
     */
    static async adopt(client, opts) {
        const startedAt = Date.now();
        const remainingMs = () => Math.max(1, opts.timeoutMs - (Date.now() - startedAt));
        const tab = new TernTab({
            client,
            block: opts.block.block,
            name: opts.name,
            viewport: opts.viewport ?? { width: 0, height: 0 },
            adopted: opts.block,
        });
        try {
            const answer = await tab.#op("events", { after: 0 }, remainingMs());
            if (isRecord(answer) && typeof answer.next === "number")
                tab.#cursor = answer.next;
            // The address the block shows: a `goto` to it must become a reload (see `gotoResponse`).
            await tab.#refreshState();
            if (opts.dialogs !== undefined)
                await tab.#op("dialogs", { policy: opts.dialogs });
            await tab.#applySettings(opts);
            if (opts.viewport && opts.block.owner !== null)
                await tab.setViewport(opts.viewport);
            await tab.#applyCapture();
            if (opts.url) {
                await tab.goto(opts.url, { waitUntil: opts.waitUntil ?? "load", timeoutMs: remainingMs() });
            }
        }
        catch (error) {
            await tab.close({ timeoutMs: 5000 }).catch(() => undefined);
            throw error;
        }
        return tab;
    }
    /** The `page` facade `tab.run` code sees. */
    get page() {
        this.#pageFacade ??= new TernPageFacade(this);
        return this.#pageFacade;
    }
    /** The `browser` facade `tab.run` code sees. */
    get browser() {
        this.#browserFacade ??= new TernBrowserFacade(this);
        return this.#browserFacade;
    }
    /** The tab's JavaScript runtime for `tab.run`. */
    ensureRuntime(session) {
        this.#runtime ??= new JsRuntime({ initialCwd: session.cwd, sessionId: `tern-tab-${this.block}` });
        return this.#runtime;
    }
    /** Publish the active run. */
    setRunContext(context) {
        this.#runContext = context;
    }
    /** Forget the finished run. */
    clearRunContext() {
        this.#runContext = undefined;
    }
    /** Page facts the supervisor records for the tab. */
    async readyInfo() {
        await this.#refreshState();
        return {
            url: this.#url,
            title: this.#title,
            viewport: { ...this.#viewport },
            targetId: String(this.block),
        };
    }
    /**
     * Whether the block was on screen at the last `state` (undefined before one,
     * or from a Tern that does not say). A PiP shows only while the tab holding
     * its owner pane is the one the user looks at.
     */
    get shown() {
        return this.#shown;
    }
    /**
     * Close omp's PiP (its page goes), or release an adopted block: Tern stops
     * driving it and resets what omp set, the user's page stays. A Tern without
     * `release` (answers `invalid`) only gets omp's scripts cleared, best-effort.
     * A block already gone is no error.
     */
    async close(opts) {
        await this.#recording.close().catch(error => {
            logger.warn("Failed to finalize a Tern browser recording during close", {
                error: error instanceof Error ? error.message : String(error),
            });
        });
        try {
            await this.#client.request({ op: this.adopted ? "release" : "close", block: this.block }, { timeoutMs: opts.timeoutMs });
        }
        catch (error) {
            if (error instanceof TernError && (error.kind === "not_found" || error.kind === "closed"))
                return;
            if (!(this.adopted && error instanceof TernError && error.kind === "invalid"))
                throw error;
            await this.#client
                .request({ op: "scripts", block: this.block, scripts: [] }, { timeoutMs: opts.timeoutMs })
                .catch(() => undefined);
        }
    }
    // ─── Protocol plumbing ────────────────────────────────────────────────
    get #signal() {
        return this.#runContext?.signal;
    }
    get #cellMs() {
        return this.#runContext?.timeoutMs ?? 30000;
    }
    /** Send a block op; aborts with the run. */
    async #op(op, fields = {}, timeoutMs) {
        const signal = this.#signal;
        throwIfAborted(signal);
        return await this.#client.request({ op, block: this.block, ...fields }, { timeoutMs: timeoutMs ?? resolveOpTimeouts(this.#cellMs).budgetBound, signal });
    }
    /** Evaluate a function source; resolves its JSON value (`undefined` for none). */
    async #eval(source, args, world, frame, timeoutMs) {
        const answer = await this.#op("eval", { function: source, args: withoutTrailingUndefined(args), world, ...(frame ? { frame } : {}) }, timeoutMs);
        return isRecord(answer) ? answer.value : undefined;
    }
    /** Call a kit method in `frame`'s isolated world, installing the kit when the document lacks it. */
    async #kit(method, args, frame = null) {
        for (let attempt = 0; attempt < 2; attempt++) {
            let result;
            try {
                result = await this.#eval(KIT_CALL, [method, args], "isolated", frame);
            }
            catch (error) {
                if (error instanceof TernError && error.kind === "js")
                    throw new ToolError(kitErrorText(error));
                throw error;
            }
            if (isRecord(result) && result.missing === true) {
                await this.#eval(`function () {\n${TERN_KIT_SOURCE}\n}`, [], "isolated", frame);
                continue;
            }
            return (isRecord(result) ? result.value : undefined);
        }
        throw new ToolError("The Tern page kit could not be installed in this document");
    }
    /** Evaluate user code in the page world, surfacing page exceptions as ToolErrors. */
    async #evalUser(label, fn, args, frame) {
        try {
            if (typeof fn === "function")
                return await this.#eval(fn.toString(), args, "page", frame);
            if (typeof fn !== "string")
                throw new ToolError(`${label} expects a function or a source string`);
            return await this.#eval(userSourceFunction(fn), [], "page", frame);
        }
        catch (error) {
            if (error instanceof TernError && error.kind === "js") {
                throw new ToolError(`${label} threw a JavaScript exception:\n${pageErrorText(error)}`);
            }
            throw error;
        }
    }
    /** Evaluate an expression source (an IIFE string) in the main page world. */
    async #evalExpression(source, signal) {
        throwIfAborted(signal);
        return await this.#eval(`function () {\nreturn ${source};\n}`, [], "page", null);
    }
    /** Send trusted input steps. */
    async #input(steps) {
        if (steps.length === 0)
            return;
        await this.#op("input", { events: steps });
    }
    /** Pull new Tern events into the tab's state (single-flight). */
    async #pull() {
        if (this.#pulling)
            return await this.#pulling;
        const pulling = (async () => {
            const answer = await this.#op("events", { after: this.#cursor }, 10000);
            if (!isRecord(answer) || !Array.isArray(answer.events))
                return;
            for (const raw of answer.events) {
                if (!isRecord(raw) || typeof raw.seq !== "number" || typeof raw.type !== "string")
                    continue;
                if (raw.seq <= this.#cursor)
                    continue;
                this.#cursor = raw.seq;
                const event = { ...raw, seq: raw.seq, type: raw.type };
                this.#events.push(event);
                this.#ingest(event);
            }
            if (this.#events.length > EVENT_LOG_LIMIT)
                this.#events.splice(0, this.#events.length - EVENT_LOG_LIMIT);
            if (typeof answer.dropped === "number" && answer.dropped > 0) {
                logger.debug("Tern dropped browser events before omp read them", { dropped: answer.dropped });
            }
        })();
        this.#pulling = pulling;
        try {
            await pulling;
        }
        finally {
            this.#pulling = undefined;
        }
    }
    /** Apply one event to the tab's state. */
    #ingest(event) {
        switch (event.type) {
            case "url":
            case "committed":
                if (typeof event.url === "string")
                    this.#url = event.url;
                if (event.type === "committed") {
                    this.#pendingDialog = undefined;
                    this.#frameUrls.clear();
                }
                return;
            case "title":
                if (typeof event.title === "string")
                    this.#title = event.title;
                return;
            case "frame":
                if (typeof event.name === "string" && typeof event.url === "string")
                    this.#frameUrls.set(event.name, event.url);
                return;
            case "dialog":
                if (event.handled === null || event.handled === undefined) {
                    this.#pendingDialog = {
                        type: stringOr(event.kind, "alert"),
                        message: stringOr(event.message, ""),
                        ...(event.kind === "prompt" ? { defaultValue: stringOr(event.default, "") } : {}),
                    };
                }
                return;
            case "download":
                this.#ingestDownload(event);
                return;
            case "response":
                this.#network.ingestNavigationResponse(event);
                return;
            case "blocked":
                if (typeof event.url === "string")
                    this.#network.ingestBlocked(event.url);
                return;
            case "message":
                this.#ingestMessage(event);
                return;
        }
    }
    #ingestMessage(event) {
        if (event.world !== "page" || typeof event.body !== "string")
            return;
        let message;
        try {
            message = JSON.parse(event.body);
        }
        catch {
            return;
        }
        if (!isRecord(message) || message.omp !== "tern")
            return;
        if (typeof message.dropped === "number")
            this.#consoleDropped += message.dropped;
        const ts = numberOr(message.ts, Date.now());
        const location = typeof message.location === "string" ? message.location : undefined;
        switch (message.kind) {
            case "console":
                this.#pushConsole({
                    seq: 0,
                    ts,
                    type: "console",
                    level: consoleLevel(message.level),
                    text: stringOr(message.text, ""),
                    location,
                    args: Array.isArray(message.args) ? message.args : [],
                });
                return;
            case "pageerror":
                this.#pushConsole({
                    seq: 0,
                    ts,
                    type: "pageerror",
                    level: "error",
                    text: stringOr(message.text, ""),
                    location,
                    stack: typeof message.stack === "string" ? message.stack : undefined,
                });
                return;
            case "requestfailed":
                this.#network.ingestPageMessage(message);
                this.#pushConsole({
                    seq: 0,
                    ts,
                    type: "requestfailed",
                    level: "error",
                    text: `${stringOr(message.error, "request failed")}: ${stringOr(message.url, "")}`,
                    location: typeof message.url === "string" ? message.url : undefined,
                });
                return;
            case "request":
            case "response":
                this.#network.ingestPageMessage(message);
                return;
        }
    }
    #pushConsole(entry) {
        entry.seq = this.#consoleSeq++;
        this.#console.push(entry);
        while (this.#console.length > CONSOLE_LIMIT) {
            this.#console.shift();
            this.#consoleDropped++;
        }
    }
    #ingestDownload(event) {
        if (typeof event.id !== "number")
            return;
        const known = this.#downloads.get(event.id);
        const entry = {
            url: stringOr(event.url, known?.url ?? ""),
            path: typeof event.path === "string" ? event.path : known?.path,
            state: stringOr(event.state, "started"),
            error: typeof event.error === "string" ? event.error : undefined,
        };
        this.#downloads.set(event.id, entry);
        if (entry.state !== "finished" || !entry.path)
            return;
        let bytes = 0;
        try {
            bytes = fs.statSync(entry.path).size;
        }
        catch { }
        const download = {
            path: entry.path,
            suggestedFilename: path.basename(entry.path),
            url: entry.url,
            bytes,
        };
        this.#completedDownloads.push(download);
        this.#unclaimedDownloads.push(download);
    }
    /** Events newer than `since` (already pulled). */
    #eventsSince(since) {
        return this.#events.filter(event => event.seq > since);
    }
    /**
     * Poll `check` until it yields a value (not `undefined`), backing off
     * 25→100 ms; `pull` also refreshes Tern events before each check.
     */
    async #poll(label, timeoutMs, check, opts = { pull: false }) {
        const deadline = Date.now() + timeoutMs;
        let delay = 25;
        for (;;) {
            if (opts.pull)
                await this.#pull();
            const value = await check();
            if (value !== undefined)
                return value;
            const left = deadline - Date.now();
            if (left <= 0)
                throw new ToolError(`${label} timed out after ${timeoutMs}ms`);
            await untilAborted(this.#signal, () => Bun.sleep(Math.min(delay, left)));
            delay = Math.min(100, Math.round(delay * 1.5));
        }
    }
    /** Refresh url/title (and the known viewport) from Tern's `state`. */
    async #refreshState() {
        const state = await this.#op("state", {}, resolveOpTimeouts(this.#cellMs).quickOpMs);
        if (!isRecord(state))
            return {};
        if (typeof state.url === "string")
            this.#url = state.url;
        if (typeof state.title === "string")
            this.#title = state.title;
        if (typeof state.shown === "boolean")
            this.#shown = state.shown;
        if (typeof state.width === "number" && typeof state.height === "number") {
            this.#viewport = { ...this.#viewport, width: state.width, height: state.height };
        }
        return state;
    }
    // ─── Configuration and scripts ────────────────────────────────────────
    async #configure(opts, timeoutMs) {
        // Tern answers `open` once the page takes calls, before its about:blank load reports. That load's
        // late `committed`/`loaded` events would otherwise settle the first navigation before it loads.
        await this.#poll("The Tern page's initial about:blank load", timeoutMs, () => (this.#events.some(event => event.type === "loaded" || event.type === "failed") ? true : undefined), { pull: true });
        await this.#op("dialogs", { policy: opts.dialogs ?? "default" });
        await this.#applySettings(opts);
        await this.#syncScripts();
    }
    /** The page settings the caller gave: allowlist, agent, TLS, downloads, init scripts (sent with the next script sync). */
    async #applySettings(opts) {
        if (opts.allowedDomains?.length) {
            this.#allowedDomains = normalizeAllowedDomains(opts.allowedDomains);
            await this.#op("allow", { hosts: this.#allowedDomains });
        }
        if (opts.userAgent !== undefined) {
            this.#emulation.userAgent = opts.userAgent;
            await this.#op("agent", { value: opts.userAgent });
        }
        if (opts.ignoreHttpsErrors)
            await this.#op("insecure", { value: true });
        if (opts.downloadsPath !== undefined)
            await this.#enableDownloads(opts.downloadsPath);
        for (const source of opts.initScripts ?? []) {
            this.#initScripts.push({ id: `tern-init-${this.#nextInitScript++}`, source });
        }
    }
    /** Every document-start script this tab needs, in order. */
    #scripts() {
        return [
            {
                source: ternCaptureScript({ routes: this.#network.rules(), emulation: this.#pageEmulation }),
                world: "page",
                frames: "all",
                at: "start",
            },
            {
                source: `(${installWebMcpPageHook.toString()})(${JSON.stringify(WEBMCP_BRIDGE_KEY)});`,
                world: "page",
                frames: "all",
                at: "start",
            },
            { source: `${VITALS_INIT_SOURCE};`, world: "page", frames: "main", at: "start" },
            ...(this.#reactHook
                ? [
                    {
                        source: `${REACT_HOOK_INIT_SOURCE};`,
                        world: "page",
                        frames: "main",
                        at: "start",
                    },
                ]
                : []),
            ...(this.#cursorOverlay
                ? [
                    {
                        source: `(${installCursorOverlay.toString()})();`,
                        world: "page",
                        frames: "main",
                        at: "start",
                    },
                ]
                : []),
            ...this.#initScripts.map(script => ({
                source: script.source,
                world: "page",
                frames: "all",
                at: "start",
            })),
            { source: TERN_KIT_SOURCE, world: "isolated", frames: "all", at: "start" },
        ];
    }
    /** Send the script list (future documents). */
    async #syncScripts() {
        await this.#op("scripts", { scripts: this.#scripts() });
    }
    /** Re-apply the capture configuration: future documents and every frame of the current one. */
    async #applyCapture() {
        await this.#syncScripts();
        const config = { routes: this.#network.rules(), emulation: this.#pageEmulation };
        const children = await this.#kit("frames", []).catch(() => []);
        for (const frame of [null, ...children.map(child => child.path)]) {
            await this.#eval(TERN_CAPTURE_INSTALLER, [config], "page", frame).catch(error => {
                logger.debug("Tern capture update skipped for a frame", {
                    frame,
                    error: error instanceof Error ? error.message : String(error),
                });
            });
        }
    }
    // ─── Navigation ───────────────────────────────────────────────────────
    /**
     * Wait for a navigation started after `since`: `load` = Tern's `loaded`
     * event, `domcontentloaded` = committed and parsed, `networkidle*` = loaded
     * and at most 0/2 page fetch/XHR in flight for 500 ms (page requests only).
     * A load failure or allowlist block throws. When a navigation reports no
     * events (same-document, cached), a settled `state` ends the wait.
     */
    async #awaitNavigation(label, since, waitUntil, timeoutMs, opts) {
        let iteration = 0;
        let idleSince;
        let settledByState = false;
        await this.#poll(label, timeoutMs, async () => {
            iteration++;
            const events = this.#eventsSince(since);
            const failed = events.find(event => event.type === "failed");
            if (failed)
                throw new ToolError(`${label} failed: ${stringOr(failed.message, "load failed")}`);
            const blocked = events.find(event => event.type === "blocked");
            if (blocked) {
                throw new ToolError(`${label} was blocked by allowed_domains: ${stringOr(blocked.url, "")}`);
            }
            const committed = events.some(event => event.type === "committed");
            const changed = committed || events.some(event => event.type === "url");
            let loaded = events.some(event => event.type === "loaded");
            if (!loaded && iteration % 4 === 0) {
                const state = await this.#refreshState();
                if (state.loading === false && (changed || (!opts.requireChange && this.#url !== opts.startUrl))) {
                    loaded = true;
                    settledByState = true;
                }
            }
            if (opts.requireChange && !changed && !settledByState)
                return undefined;
            if (waitUntil === "domcontentloaded") {
                if (loaded)
                    return true;
                if (!committed)
                    return undefined;
                const ready = await this.#eval("function () { return document.readyState; }", [], "page", null).catch(() => "loading");
                return ready === "loading" ? undefined : true;
            }
            if (!loaded)
                return undefined;
            if (waitUntil === "load")
                return true;
            const inflight = numberOr(await this.#eval(`function () { const capture = globalThis[${JSON.stringify(TERN_CAPTURE_GLOBAL)}]; return capture ? capture.inflight : 0; }`, [], "page", null).catch(() => 0), 0);
            if (inflight > (waitUntil === "networkidle0" ? 0 : 2)) {
                idleSince = undefined;
                return undefined;
            }
            idleSince ??= Date.now();
            return Date.now() - idleSince >= NAVIGATION_IDLE_MS ? true : undefined;
        }, { pull: true });
        const mainResponses = this.#network
            .settledAfter(0)
            .filter(record => record.resourceType === "document" && record.status !== undefined);
        const response = mainResponses.at(-1) ?? null;
        await this.#refreshState().catch(() => undefined);
        return response;
    }
    async #navigate(label, start, waitUntil, timeoutMs) {
        await this.#pull();
        const since = this.#cursor;
        const responseCursor = this.#network.cursor;
        const startUrl = this.#url;
        await start();
        const response = await this.#awaitNavigation(label, since, waitUntil ?? "load", timeoutMs, {
            requireChange: false,
            startUrl,
        });
        return response && response.seq >= responseCursor ? response : null;
    }
    /** Navigate and wait for `waitUntil` (default `load`). */
    async goto(url, opts) {
        await this.gotoResponse(url, opts);
    }
    /** {@link goto}, resolving the main document's response (null when none was reported). */
    async gotoResponse(url, opts) {
        const timeoutMs = opts?.timeoutMs ?? resolveOpTimeouts(this.#cellMs).budgetBound;
        // A Tern web view never reloads an unchanged address (Terns before the fix answer the
        // `goto` and report no navigation, so the wait would never end). Reloading is what a goto
        // to the shown address means anyway, and what Tern's own address field does: `nav reload`
        // always reports a fresh load. Settling by `state` instead would race a Tern that does
        // reload: `loading` can still read false before the reload starts. Decided after
        // `#navigate`'s event pull, so the shown address is current.
        const entry = await this.#navigate(`tab.goto(${JSON.stringify(url)})`, () => sameAddress(url, this.#url)
            ? this.#op("nav", { go: "reload" }, timeoutMs)
            : this.#op("goto", { url }, timeoutMs), opts?.waitUntil, timeoutMs);
        return entry ? new TernResponse(entry, this) : null;
    }
    async #history(go, opts) {
        const timeoutMs = resolveOpTimeouts(this.#cellMs).budgetBound;
        if (go !== "reload") {
            const state = await this.#refreshState();
            if (state[go] === false)
                return this.#url;
        }
        await this.#navigate(`tab.${go}()`, () => this.#op("nav", { go }), opts?.waitUntil, timeoutMs);
        return this.#url;
    }
    /** Go back one history entry (no-op at the start of history). */
    async back(opts) {
        return await this.#history("back", opts);
    }
    /** Go forward one history entry (no-op at the end of history). */
    async forward(opts) {
        return await this.#history("forward", opts);
    }
    /** Reload the document. */
    async reload(opts) {
        return await this.#history("reload", opts);
    }
    /** Client-side navigation (`history.pushState`). */
    async pushState(url) {
        const result = await this.#evalUser("tab.pushState()", pushStateInPage, [url], null);
        if (typeof result === "string")
            this.#url = result;
        return this.#url;
    }
    /** Wait for the next navigation (start it before the action that navigates). */
    async waitForNavigation(opts) {
        const timeoutMs = resolveWaitTimeout(this.#cellMs, opts?.timeout ?? resolveOpTimeouts(this.#cellMs).budgetBound);
        await this.#pull();
        const since = this.#cursor;
        const responseCursor = this.#network.cursor;
        const entry = await this.#awaitNavigation("tab.waitForNavigation()", since, opts?.waitUntil ?? "load", timeoutMs, {
            requireChange: true,
            startUrl: this.#url,
        });
        return entry && entry.seq >= responseCursor ? new TernResponse(entry, this) : null;
    }
    /** Wait until the URL contains `pattern` (string) or matches it (RegExp). */
    async waitForUrl(pattern, opts) {
        const timeoutMs = resolveWaitTimeout(this.#cellMs, opts?.timeout);
        let iteration = 0;
        return await this.#poll(`tab.waitForUrl(${String(pattern)})`, timeoutMs, async () => {
            if (++iteration % 4 === 0)
                await this.#refreshState();
            if (typeof pattern === "string")
                return this.#url.includes(pattern) ? this.#url : undefined;
            pattern.lastIndex = 0;
            return pattern.test(this.#url) ? this.#url : undefined;
        }, { pull: true });
    }
    /** The current URL (as last reported). */
    url() {
        return this.#url;
    }
    /** The title as last reported (title events, state, observe), without asking the page. */
    get lastTitle() {
        return this.#title;
    }
    /** The document title. */
    async title() {
        await this.#refreshState();
        return this.#title;
    }
    /** The page layout size. */
    viewport() {
        return { ...this.#viewport };
    }
    /** Resize the PiP's page (`viewport` op); `deviceScaleFactor` scales captures. */
    async setViewport(viewport) {
        await this.#op("viewport", { width: Math.round(viewport.width), height: Math.round(viewport.height) });
        this.#viewport = { ...viewport };
    }
    // ─── Selectors and targets ────────────────────────────────────────────
    #spec(selector) {
        return typeof selector === "string" ? parseTernSelector(selector) : selector;
    }
    /** Viewport offset of `frame`'s content box in the main frame. */
    async #frameOffset(frame) {
        if (!frame)
            return { x: 0, y: 0 };
        const indices = frame.split(".");
        let x = 0;
        let y = 0;
        for (let depth = 0; depth < indices.length; depth++) {
            const parent = depth === 0 ? null : indices.slice(0, depth).join(".");
            const origin = await this.#kit("frameOrigin", [Number(indices[depth])], parent);
            if (!origin)
                throw new ToolError(`Frame ${frame} is no longer in the page`);
            x += origin.x;
            y += origin.y;
        }
        return { x, y };
    }
    /**
     * The point to act on for `action`: waits for the element to be actionable
     * (visible, enabled, editable, stable, not covered) up to the action
     * ceiling, failing fast after 2 s of zero matches.
     */
    async #target(label, selector, action, frame, explicitTimeout) {
        const spec = this.#spec(selector);
        const timeoutMs = explicitTimeout === undefined
            ? resolveOpTimeouts(this.#cellMs).actionOpMs
            : resolveWaitTimeout(this.#cellMs, explicitTimeout);
        const started = Date.now();
        let delay = 30;
        let last;
        for (;;) {
            last = await this.#kit("target", [spec, action], frame);
            if (last.ok) {
                const offset = await this.#frameOffset(frame);
                return { x: last.x + offset.x, y: last.y + offset.y, width: last.width, height: last.height };
            }
            const elapsed = Date.now() - started;
            if (elapsed >= timeoutMs)
                break;
            if (last.reason === "missing" && explicitTimeout === undefined && elapsed >= ZERO_MATCH_FAIL_FAST_MS)
                break;
            await untilAborted(this.#signal, () => Bun.sleep(delay));
            delay = Math.min(250, Math.round(delay * 1.5));
        }
        const why = last.reason === "missing"
            ? "no element matches (wrong page or selector?)"
            : last.reason === "covered"
                ? `the element is covered by ${last.detail ?? "another element"}`
                : last.reason === "hidden"
                    ? "the element is not visible"
                    : last.reason === "disabled"
                        ? "the element is disabled"
                        : last.reason === "notEditable"
                            ? "the element is not editable"
                            : last.reason === "offViewport"
                                ? "the element is outside the viewport"
                                : "the element keeps moving";
        throw new ToolError(`${label} timed out after ${Date.now() - started}ms: ${why} (${last.count} match(es))`);
    }
    #mouseStep(action, point, button, clicks) {
        return {
            type: "mouse",
            action,
            x: point.x,
            y: point.y,
            button,
            ...(clicks === undefined ? {} : { clicks }),
            mods: [...this.#mods],
        };
    }
    /** Trusted clicks at `point` (`count` clicks, the last one with click count `count`). */
    async #clickAt(point, button, count) {
        const steps = [this.#mouseStep("move", point, button, 0)];
        for (let click = 1; click <= count; click++) {
            steps.push(this.#mouseStep("down", point, button, click), this.#mouseStep("up", point, button, click));
        }
        this.#pointer = { ...point };
        await this.#input(steps);
    }
    async #clickSelector(label, selector, frame, count, button = "left") {
        const pressed = this.#button(button);
        const box = await this.#target(label, selector, count === 2 ? "dblclick" : "click", frame);
        await this.#clickAt(box, pressed, count);
    }
    // ─── Interaction ──────────────────────────────────────────────────────
    /** Click the element's centre with a trusted mouse click. */
    async click(selector) {
        await this.clickIn(selector, null);
    }
    /** {@link click} inside `frame`, optionally with another button or click count. */
    async clickIn(selector, frame, options) {
        const count = Math.max(1, Math.floor(options?.count ?? 1));
        await this.#clickSelector(`tab.click(${describe(selector)})`, selector, frame, count, options?.button);
    }
    /** Double-click the element's centre. */
    async dblclick(selector, frame = null) {
        await this.#clickSelector(`tab.dblclick(${describe(selector)})`, selector, frame, 2);
    }
    /** Move the pointer over the element's centre. */
    async hover(selector, frame = null) {
        const box = await this.#target(`tab.hover(${describe(selector)})`, selector, "hover", frame);
        this.#pointer = { x: box.x, y: box.y };
        await this.#input([this.#mouseStep("move", box, "left", 0)]);
    }
    /** Focus the element. */
    async focus(selector, frame = null) {
        await this.#target(`tab.focus(${describe(selector)})`, selector, "focus", frame);
        await this.#kit("focus", [this.#spec(selector)], frame);
    }
    async #setChecked(selector, desired, frame) {
        const label = `tab.${desired ? "check" : "uncheck"}(${describe(selector)})`;
        const spec = this.#spec(selector);
        const box = await this.#target(label, spec, "check", frame);
        const before = await this.#kit("checkState", [spec], frame);
        if (before.checked === desired)
            return;
        await this.#clickAt(box, "left", 1);
        const after = await this.#kit("checkState", [spec], frame);
        if (after.checked !== desired) {
            throw new ToolError(`${label} clicked the element but it is still ${desired ? "unchecked" : "checked"}`);
        }
    }
    /** Check a checkbox, radio or ARIA switch (clicks only when needed). */
    async check(selector, frame = null) {
        await this.#setChecked(selector, true, frame);
    }
    /** Uncheck a checkbox or ARIA switch (clicks only when needed). */
    async uncheck(selector, frame = null) {
        await this.#setChecked(selector, false, frame);
    }
    /** Type `text` at the end of the element's content with trusted key events. */
    async type(selector, text, frame = null) {
        const spec = this.#spec(selector);
        await this.#target(`tab.type(${describe(selector)})`, spec, "type", frame);
        await this.#kit("caretToEnd", [spec], frame);
        await this.#input(typeSteps(String(text), this.#mods));
    }
    /** Replace the element's value (trusted text input for text controls). */
    async fill(selector, value, frame = null) {
        const spec = this.#spec(selector);
        const text = String(value);
        await this.#target(`tab.fill(${describe(selector)})`, spec, "fill", frame);
        const prepared = await this.#kit("prepareFill", [spec, text], frame);
        if (prepared.mode === "done")
            return;
        await this.#input(text.length > 0 ? [{ type: "text", text }] : pressSteps("Backspace", this.#mods));
    }
    /** Press a key (or `Mod+Key` combo), optionally after focusing an element. */
    async press(key, opts) {
        await this.pressIn(key, opts, null);
    }
    /** {@link press} inside `frame`. */
    async pressIn(key, opts, frame) {
        assertTabPressArgs(key, opts);
        if (opts?.selector)
            await this.focus(opts.selector, frame);
        await this.#input(pressSteps(key, this.#mods));
    }
    /** Hold a key down (modifiers apply to later input). */
    async keyDown(key) {
        const resolved = ternKey(key);
        await this.#input([keyDownStep(resolved, this.#mods)]);
        if (resolved.modifier && !this.#mods.includes(resolved.modifier))
            this.#mods.push(resolved.modifier);
    }
    /** Release a held key. */
    async keyUp(key) {
        const resolved = ternKey(key);
        if (resolved.modifier) {
            const index = this.#mods.indexOf(resolved.modifier);
            if (index >= 0)
                this.#mods.splice(index, 1);
        }
        await this.#input([keyUpStep(resolved, this.#mods)]);
    }
    #button(name) {
        const button = name ?? "left";
        if (button === "back" || button === "forward") {
            throw unsupported("mouseDown", `the ${button} mouse button cannot be synthesised (left, right, middle only)`);
        }
        return button;
    }
    async #viewportCentre() {
        const geometry = await this.#kit("geometry", []);
        return { x: geometry.innerWidth / 2, y: geometry.innerHeight / 2 };
    }
    /** Move the pointer (interpolated over `steps`); a held button drags. */
    async mouseMove(x, y, opts) {
        if (!Number.isFinite(x) || !Number.isFinite(y))
            throw new ToolError("mouseMove coordinates must be finite numbers");
        const from = this.#pointer ?? { x, y };
        const steps = Math.max(1, Math.floor(opts?.steps ?? 1));
        const held = [...this.#buttons][0] ?? "left";
        const events = [];
        for (let step = 1; step <= steps; step++) {
            const point = { x: from.x + ((x - from.x) * step) / steps, y: from.y + ((y - from.y) * step) / steps };
            events.push(this.#mouseStep("move", point, held, 0));
        }
        this.#pointer = { x, y };
        await this.#input(events);
    }
    /** Press a mouse button at the pointer. */
    async mouseDown(opts) {
        const button = this.#button(opts?.button);
        const point = this.#pointer ?? (await this.#viewportCentre());
        this.#buttons.add(button);
        await this.#input([this.#mouseStep("down", point, button, opts?.clickCount ?? 1)]);
    }
    /** Release a mouse button at the pointer. */
    async mouseUp(opts) {
        const button = this.#button(opts?.button);
        const point = this.#pointer ?? (await this.#viewportCentre());
        this.#buttons.delete(button);
        await this.#input([this.#mouseStep("up", point, button, opts?.clickCount ?? 1)]);
    }
    /** Click at viewport coordinates. */
    async clickAt(x, y, opts) {
        if (!Number.isFinite(x) || !Number.isFinite(y))
            throw new ToolError("clickAt coordinates must be finite numbers");
        await this.#clickAt({ x, y }, this.#button(opts?.button), Math.max(1, Math.floor(opts?.clickCount ?? 1)));
    }
    /** A trusted wheel event at the pointer (the viewport centre before any pointer move). */
    async wheel(deltaX, deltaY) {
        if (!Number.isFinite(deltaX) || !Number.isFinite(deltaY))
            throw new ToolError("wheel deltas must be finite numbers");
        const point = this.#pointer ?? (await this.#viewportCentre());
        await this.#input([{ type: "wheel", x: point.x, y: point.y, dx: deltaX, dy: deltaY, mods: [...this.#mods] }]);
    }
    /** Scroll the page (trusted wheel at the viewport centre) or an element (`scrollBy`). */
    async scroll(dx, dy, opts) {
        if (opts?.selector) {
            const spec = this.#spec(opts.selector);
            await this.#target(`tab.scroll(${describe(opts.selector)})`, spec, "point", null);
            await this.#kit("scrollBy", [spec, dx, dy]);
            return;
        }
        const centre = await this.#viewportCentre();
        await this.#input([{ type: "wheel", x: centre.x, y: centre.y, dx, dy, mods: [...this.#mods] }]);
    }
    async #dragPoint(target, role) {
        if (typeof target === "string") {
            const box = await this.#target(`tab.drag() ${role} ${JSON.stringify(target)}`, target, "drag", null);
            return { x: box.x, y: box.y };
        }
        if (target && Number.isFinite(target.x) && Number.isFinite(target.y))
            return { x: target.x, y: target.y };
        throw new ToolError("Drag target must be a selector string or { x: number, y: number } point");
    }
    /** Trusted drag from one selector/point to another. */
    async drag(from, to) {
        const start = await this.#dragPoint(from, "from");
        const end = await this.#dragPoint(to, "to");
        const steps = [
            this.#mouseStep("move", start, "left", 0),
            this.#mouseStep("down", start, "left", 1),
        ];
        for (let step = 1; step <= 10; step++) {
            const point = { x: start.x + ((end.x - start.x) * step) / 10, y: start.y + ((end.y - start.y) * step) / 10 };
            steps.push(this.#mouseStep("move", point, "left", 0));
        }
        steps.push(this.#mouseStep("up", end, "left", 1));
        this.#pointer = { ...end };
        await this.#input(steps);
    }
    /** Outline the element for `duration` ms (default 2000). */
    async highlight(selector, opts) {
        const duration = opts?.duration ?? 2000;
        if (!Number.isFinite(duration) || duration < 0)
            throw new ToolError("highlight duration must be a non-negative number");
        const spec = this.#spec(selector);
        await this.#target(`tab.highlight(${describe(selector)})`, spec, "point", null);
        const id = `omp-highlight-${crypto.randomUUID()}`;
        await this.#kit("highlight", [spec, id]);
        try {
            await untilAborted(this.#signal, () => Bun.sleep(duration));
        }
        finally {
            await this.#kit("removeOverlay", [id]).catch(() => undefined);
        }
    }
    /** Scroll the element into view. */
    async scrollIntoView(selector) {
        const spec = this.#spec(selector);
        await this.#target(`tab.scrollIntoView(${describe(selector)})`, spec, "point", null);
        await this.#kit("scrollIntoView", [spec]);
    }
    /** Select `<select>` options by value (then label). */
    async select(selector, ...values) {
        const spec = this.#spec(selector);
        await this.#target(`tab.select(${describe(selector)})`, spec, "point", null);
        return await this.#kit("select", [spec, values.map(String)]);
    }
    /**
     * Upload files: a file input (or its label) gets the files through Tern's
     * native chooser (preset, then opened); any other element gets them dropped.
     */
    async uploadFile(selector, ...filePaths) {
        if (filePaths.length === 0)
            throw new ToolError("tab.uploadFile() requires at least one file path");
        const cwd = this.#requireRunContext("tab.uploadFile()").session.cwd;
        const absolute = filePaths.map(filePath => resolveToCwd(filePath, cwd));
        for (const file of absolute) {
            try {
                await fs.promises.access(file);
            }
            catch {
                throw new ToolError(`tab.uploadFile() cannot read ${file}`);
            }
        }
        const spec = this.#spec(selector);
        await this.#target(`tab.uploadFile(${describe(selector)})`, spec, "upload", null);
        if (await this.#kit("isFileInput", [spec])) {
            await this.#pull();
            const since = this.#cursor;
            await this.#op("files", { paths: absolute });
            if ((await this.#kit("openChooser", [spec])) === "input") {
                const answered = await this.#poll("tab.uploadFile() chooser", 3000, () => (this.#eventsSince(since).some(event => event.type === "chooser") ? true : undefined), { pull: true }).catch(() => false);
                if (answered)
                    return;
            }
            // No chooser asked for the preset: disarm it before dropping the files instead.
            await this.#op("files", { paths: null });
        }
        await this.#kit("setFiles", [spec, await readFilePayloads(absolute)]);
    }
    // ─── Queries ──────────────────────────────────────────────────────────
    async #read(selector, prop, arg, frame = null) {
        return await this.#kit("read", [this.#spec(selector), prop, arg], frame);
    }
    /** The element's rendered text (the page `<body>` without a selector), or null. */
    async text(selector = "body", frame = null) {
        return await this.#read(selector, "text", undefined, frame);
    }
    /** The element's inner HTML (the page `<body>` without a selector), or null. */
    async html(selector = "body", frame = null) {
        return await this.#read(selector, "html", undefined, frame);
    }
    /** The form element's value, or null. */
    async value(selector, frame = null) {
        return await this.#read(selector, "value", undefined, frame);
    }
    /** One attribute, or null. */
    async attr(selector, name, frame = null) {
        return await this.#read(selector, "attr", name, frame);
    }
    /** How many elements match. */
    async count(selector, frame = null) {
        return await this.#kit("count", [this.#spec(selector)], frame);
    }
    /** The element's box in main-frame viewport px, or null. */
    async box(selector, frame = null) {
        const box = await this.#read(selector, "box", undefined, frame);
        if (!box || !frame)
            return box;
        const offset = await this.#frameOffset(frame);
        return { ...box, x: box.x + offset.x, y: box.y + offset.y };
    }
    /** Computed styles, or null. */
    async styles(selector, props = [...DEFAULT_STYLE_PROPERTIES]) {
        return await this.#read(selector, "styles", props);
    }
    /** Whether the element is visible. */
    async isVisible(selector, frame = null) {
        return (await this.#read(selector, "visible", undefined, frame)) === true;
    }
    /** Whether the element is enabled. */
    async isEnabled(selector) {
        return (await this.#read(selector, "enabled")) === true;
    }
    /** Whether the element is checked. */
    async isChecked(selector) {
        return (await this.#read(selector, "checked")) === true;
    }
    /** Wait until `text` appears in the body (or a matching element). */
    async waitForText(text, opts = {}) {
        const root = opts.selector ? this.#spec(opts.selector) : null;
        await this.#poll(`tab.waitForText(${JSON.stringify(text)})`, resolveWaitTimeout(this.#cellMs, opts.timeout), async () => ((await this.#kit("hasText", [text, root, opts.exact === true])) ? true : undefined));
    }
    /** Wait for a visible matching element and return its handle. */
    async waitFor(selector, opts) {
        return await this.waitForIn(selector, opts, null);
    }
    /** {@link waitFor} inside `frame`. */
    async waitForIn(selector, opts, frame) {
        const spec = this.#spec(selector);
        await this.#poll(`tab.waitFor(${describe(selector)})`, resolveWaitTimeout(this.#cellMs, opts?.timeout), async () => ((await this.#read(spec, "visible", undefined, frame)) === true ? true : undefined));
        return new TernElementHandle(this, spec, frame);
    }
    /** Wait for a matching element (`visible`/`hidden` like Puppeteer); null once hidden/absent. */
    async waitForSelector(selector, opts) {
        return await this.waitForSelectorIn(selector, opts, null);
    }
    /** {@link waitForSelector} inside `frame`. */
    async waitForSelectorIn(selector, opts, frame) {
        const spec = this.#spec(selector);
        const timeoutMs = resolveWaitTimeout(this.#cellMs, opts?.timeout);
        const found = await this.#poll(`tab.waitForSelector(${describe(selector)})`, timeoutMs, async () => {
            if (opts?.hidden) {
                const count = await this.#kit("count", [spec], frame);
                if (count === 0)
                    return false;
                return (await this.#read(spec, "visible", undefined, frame)) === true ? undefined : false;
            }
            if (opts?.visible)
                return (await this.#read(spec, "visible", undefined, frame)) === true ? true : undefined;
            return (await this.#kit("count", [spec], frame)) > 0 ? true : undefined;
        });
        return found ? new TernElementHandle(this, spec, frame) : null;
    }
    /** One handle per current match of `selector`, in document order. */
    async handlesFor(selector) {
        const tokens = await this.#kit("markAll", [this.#spec(selector)]);
        return tokens.map(token => new TernElementHandle(this, { engine: "handle", token }, null));
    }
    /** Handle for observation id `id` (from the last `observe()`). */
    async id(id) {
        const spec = { engine: "id", id };
        await this.#kit("count", [spec]);
        return new TernElementHandle(this, spec, null);
    }
    /** Handle for ARIA snapshot ref `eN` (from the last `ariaSnapshot()`). */
    async ref(id) {
        const ref = parseAriaRefSelector(id) ?? id.trim();
        const spec = { engine: "ariaRef", ref };
        if ((await this.#kit("count", [spec])) === 0) {
            throw new ToolError(`Unknown ARIA ref ${JSON.stringify(ref)}. Run tab.ariaSnapshot() to refresh refs (they renumber each snapshot).`);
        }
        return new TernElementHandle(this, spec, null);
    }
    /** Type `text` into whatever has focus (trusted key events). */
    async keyboardType(text) {
        await this.#input(typeSteps(String(text), this.#mods));
    }
    /** Poll a page-world predicate until it returns a truthy value. */
    async waitForFunction(fn, opts, args) {
        const interval = typeof opts?.polling === "number" && opts.polling > 0 ? opts.polling : 100;
        const deadline = Date.now() + resolveWaitTimeout(this.#cellMs, opts?.timeout);
        for (;;) {
            const value = await this.#evalUser("page.waitForFunction()", fn, args, null);
            if (value)
                return value;
            if (Date.now() >= deadline) {
                throw new ToolError(`page.waitForFunction() timed out after ${resolveWaitTimeout(this.#cellMs, opts?.timeout)}ms`);
            }
            await untilAborted(this.#signal, () => Bun.sleep(interval));
        }
    }
    /** Evaluate a function (or expression/statement source) in the page world. */
    async evaluate(fn, ...args) {
        return (await this.#evalUser("tab.evaluate()", fn, args, null));
    }
    /** {@link evaluate} inside `frame`. */
    async evaluateIn(fn, args, frame) {
        return await this.#evalUser("frame.evaluate()", fn, args, frame);
    }
    /** Evaluate `fn(element, ...args)` in the page world for the element `spec` matches. */
    async evaluateOnElement(spec, fn, args, frame) {
        const source = typeof fn === "function" ? fn.toString() : String(fn);
        const token = await this.#kit("mark", [spec], frame);
        if (!token)
            throw new ToolError("Element handle selector no longer resolves");
        const wrapper = `async function (token, args) {
			const find = root => {
				const direct = root.querySelector('[${HANDLE_ATTRIBUTE}~="' + CSS.escape(token) + '"]');
				if (direct) return direct;
				for (const node of root.querySelectorAll("*")) {
					if (node.shadowRoot) {
						const found = find(node.shadowRoot);
						if (found) return found;
					}
				}
				return null;
			};
			const element = find(document);
			if (!element) throw new Error("Element handle selector no longer resolves");
			return await (${source})(element, ...args);
		}`;
        try {
            return await this.#eval(wrapper, [token, args], "page", frame);
        }
        catch (error) {
            if (error instanceof TernError && error.kind === "js") {
                throw new ToolError(`elementHandle.evaluate() threw a JavaScript exception:\n${pageErrorText(error)}`);
            }
            throw error;
        }
        finally {
            // Only this call's token goes; concurrent evaluations on the element keep theirs.
            await this.#kit("unmark", [token], frame).catch(() => undefined);
        }
    }
    // ─── Inspection ───────────────────────────────────────────────────────
    /** Structured observation of interactive (or all) elements; ids feed `tab.id(n)`. */
    async observe(opts) {
        const observation = await this.#kit("observe", [
            {
                includeAll: opts?.includeAll,
                viewportOnly: opts?.viewportOnly,
                compact: opts?.compact,
                ...(opts?.selector ? { root: this.#spec(opts.selector) } : {}),
            },
        ]);
        this.#url = observation.url;
        if (observation.title !== undefined)
            this.#title = observation.title;
        return observation;
    }
    /** Playwright-format ARIA snapshot (refs resolve through `ref()`/`aria-ref=`). */
    async ariaSnapshot(selector, opts) {
        return await this.ariaSnapshotIn(selector, opts, null);
    }
    /** {@link ariaSnapshot} inside `frame`. */
    async ariaSnapshotIn(selector, opts, frame) {
        const payload = await this.#kit("ariaSnapshot", [selector ? this.#spec(selector) : null, { depth: opts?.depth, boxes: opts?.boxes }, opts?.urls === true], frame);
        const snapshot = postProcessAriaSnapshot(payload.snapshot, opts, payload.hrefs);
        if (!opts?.diff || frame)
            return snapshot;
        await this.#refreshState();
        return diffAriaSnapshot(this.#ariaBaselines, ariaSnapshotBaselineKey(selector, opts), this.#url, snapshot);
    }
    /** axe-core audit of the main document (run in the isolated world). */
    async a11y(options = {}) {
        const context = this.#requireRunContext("tab.a11y()");
        const raw = await this.#eval(`function () {\nreturn ${buildA11yPageScript(options)};\n}`, [], "isolated", null, context.timeoutMs).catch(error => {
            if (error instanceof TernError && error.kind === "js") {
                throw new ToolError(`tab.a11y() failed: ${kitErrorText(error)}`);
            }
            throw error;
        });
        const result = normalizeA11yResult(this.#url, raw, options.includeIncomplete === true);
        context.output.push({ type: "text", text: formatA11ySummary(result) });
        return result;
    }
    /** Readable text/markdown of the page. */
    async extract(format = "markdown", opts) {
        const html = await this.pageContent();
        const readable = await extractReadableFromHtml(html, this.#url, format, opts);
        if (!readable)
            throw new ToolError(`tab.extract(${JSON.stringify(format)}) found no readable content on ${this.#url}`);
        const content = format === "markdown" ? readable.markdown : readable.text;
        if (!content) {
            throw new ToolError(`tab.extract(${JSON.stringify(format)}) produced empty ${format} content for ${this.#url}`);
        }
        return content;
    }
    /** The document's outer HTML. */
    async pageContent() {
        const html = await this.#eval("function () { return document.documentElement.outerHTML; }", [], "isolated", null);
        return typeof html === "string" ? html : "";
    }
    // ─── Screenshots, PDF ─────────────────────────────────────────────────
    /** Capture raw image bytes: viewport, full page, or an element (optionally in a frame), at `scale` image pixels per CSS pixel (default: the viewport's). */
    async captureBytes(opts, frame = null) {
        const scale = opts.scale ?? this.#viewport.deviceScaleFactor ?? 1;
        const fields = { scale, format: opts.format };
        if (opts.format === "jpeg")
            fields.quality = opts.quality ?? 80;
        if (opts.selector !== undefined) {
            // Scrolls the element into view and waits for it to be visible before measuring it.
            await this.#target(`tab.screenshot(${describe(opts.selector)})`, opts.selector, "point", frame);
            const rect = await this.box(opts.selector, frame);
            if (!rect)
                throw new ToolError("Screenshot selector did not resolve to a visible element");
            fields.rect = rect;
        }
        else if (opts.fullPage) {
            fields.full = true;
        }
        // Let the page paint the state the caller just produced.
        await this.#eval("function () { return new Promise(resolve => requestAnimationFrame(() => resolve(true))); }", [], "isolated", null).catch(() => undefined);
        const answer = await this.#op("capture", fields, resolveOpTimeouts(this.#cellMs).quickOpMs);
        if (!isRecord(answer) || typeof answer.data !== "string")
            throw new ToolError("Tern capture answered without image data");
        return Buffer.from(answer.data, "base64");
    }
    /** Screenshot with selector/fullPage/annotate/format/quality and change detection. */
    async screenshot(opts = {}) {
        return await this.screenshotIn(opts, null);
    }
    /** {@link screenshot} inside `frame` (selector captures). */
    async screenshotIn(opts, frame) {
        const context = this.#requireRunContext("tab.screenshot()");
        screenshotQuality(opts);
        const threshold = screenshotThreshold(opts.threshold);
        const changeDetection = opts.ifChanged === true || opts.threshold !== undefined;
        const format = opts.format ?? "png";
        const mime = format === "jpeg" ? "image/jpeg" : "image/png";
        let annotation;
        const legend = [];
        if (opts.annotate) {
            const observation = await this.observe();
            annotation = await this.#kit("annotate", [observation.elements.map(element => element.id)]);
            for (const box of annotation.boxes) {
                const element = observation.elements.find(candidate => candidate.id === box.id);
                legend.push({ ...box, role: element?.role ?? "generic", name: element?.name });
            }
        }
        let comparison;
        let buffer;
        const scale = this.#viewport.deviceScaleFactor ?? 1;
        try {
            const capture = { selector: opts.selector, fullPage: opts.fullPage, scale };
            comparison = await this.captureBytes({ ...capture, format: "png" }, frame);
            buffer =
                format === "png"
                    ? comparison
                    : await this.captureBytes({ ...capture, format, quality: opts.quality }, frame);
        }
        finally {
            if (annotation)
                await this.#kit("removeOverlay", [annotation.token]).catch(() => undefined);
        }
        let change;
        if (changeDetection) {
            const scope = screenshotScope(opts);
            const previous = this.#screenshotHistory.get(scope);
            const pixelChangeRatio = previous ? pngPixelChangeRatio(previous.png, comparison) : 1;
            const changed = !previous || pixelChangeRatio > threshold;
            const revision = previous ? previous.revision + (changed ? 1 : 0) : 1;
            this.#screenshotHistory.set(scope, { png: comparison, revision });
            change = { changed, revision, pixelChangeRatio };
            if (!changed)
                return change;
        }
        const resized = await resizeImage({ type: "image", data: buffer.toString("base64"), mimeType: mime }, {
            maxWidth: 1024,
            maxHeight: 1024,
            maxBytes: 150 * 1024,
            jpegQuality: 70,
            excludeWebP: context.session.excludeWebP,
        });
        const saveFullRes = !!context.session.browserScreenshotDir || opts.format !== undefined;
        const savedBuffer = saveFullRes ? buffer : Buffer.from(resized.buffer);
        const savedMimeType = saveFullRes ? mime : resized.mimeType;
        const ext = savedMimeType === "image/webp" ? "webp" : savedMimeType === "image/jpeg" ? "jpg" : "png";
        const dest = context.session.browserScreenshotDir
            ? path.join(context.session.browserScreenshotDir, `screenshot-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, -1)}.${ext}`)
            : path.join(os.tmpdir(), `omp-sshots-${Snowflake.next()}.${ext}`);
        await Bun.write(dest, savedBuffer);
        context.screenshots.push({
            dest,
            mimeType: savedMimeType,
            bytes: savedBuffer.length,
            width: resized.width,
            height: resized.height,
        });
        if (!opts.silent) {
            const lines = formatScreenshot({
                saveFullRes,
                savedMimeType,
                savedByteLength: savedBuffer.length,
                dest,
                resized,
                capture: { area: screenshotArea(opts), scale },
            });
            if (opts.annotate)
                lines.push(formatScreenshotLegend(legend));
            context.output.push({ type: "text", text: lines.join("\n") });
            context.output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
        }
        return change ? { ...change, path: dest } : dest;
    }
    /** Compare the viewport with a PNG baseline and show the highlighted diff. */
    async diffScreenshot(baselinePath, opts = {}) {
        const context = this.#requireRunContext("tab.diffScreenshot()");
        const baseline = await untilAborted(context.signal, () => fs.promises.readFile(resolveToCwd(baselinePath, context.session.cwd)));
        const current = await this.captureBytes({ format: "png" });
        const diff = createPngDiff(baseline, current);
        const changed = diff.pixelChangeRatio > screenshotThreshold(opts.threshold);
        const diffPath = opts.output
            ? resolveToCwd(opts.output, context.session.cwd)
            : path.join(os.tmpdir(), `omp-screenshot-diff-${Snowflake.next()}.png`);
        await Bun.write(diffPath, diff.png);
        const resized = await resizeImage({ type: "image", data: diff.png.toString("base64"), mimeType: "image/png" }, {
            maxWidth: 1024,
            maxHeight: 1024,
            maxBytes: 150 * 1024,
            jpegQuality: 70,
            excludeWebP: context.session.excludeWebP,
        });
        context.screenshots.push({
            dest: diffPath,
            mimeType: "image/png",
            bytes: diff.png.length,
            width: resized.width,
            height: resized.height,
        });
        context.output.push({
            type: "text",
            text: `Screenshot diff: ${diff.pixelChangeRatio.toFixed(6)} changed-pixel ratio (${changed ? "changed" : "unchanged"}); saved to ${diffPath}`,
        });
        context.output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
        return { pixelChangeRatio: diff.pixelChangeRatio, changed, diffPath };
    }
    /** Print the page to PDF (WKWebView pagination; layout options unsupported). */
    async pdf(opts = {}) {
        const ignored = ["format", "landscape", "scale", "printBackground", "margin", "pageRanges"].filter(key => opts[key] !== undefined);
        if (ignored.length > 0) {
            throw unsupported("pdf", `options ${ignored.join(", ")} are unavailable (WKWebView prints the whole document with its own pagination); only path is supported`);
        }
        const context = this.#requireRunContext("tab.pdf()");
        const answer = await this.#op("pdf", {}, resolveOpTimeouts(this.#cellMs).budgetBound);
        if (!isRecord(answer) || typeof answer.data !== "string")
            throw new ToolError("Tern pdf answered without data");
        const dest = opts.path
            ? resolveToCwd(opts.path, context.session.cwd)
            : path.join(os.tmpdir(), `omp-browser-${Snowflake.next()}.pdf`);
        await Bun.write(dest, Buffer.from(answer.data, "base64"));
        return dest;
    }
    // ─── Frames and dialogs ───────────────────────────────────────────────
    /** Main and child frames; child ids are Tern frame paths (`0`, `1.0`). */
    async frames() {
        await this.#pull();
        const children = await this.#kit("frames", []);
        const result = [{ id: "main", name: "", url: this.#url, parentId: null }];
        for (const child of children) {
            const parent = child.path.includes(".") ? child.path.slice(0, child.path.lastIndexOf(".")) : "main";
            const info = {
                id: child.path,
                name: child.name ?? child.id ?? "",
                url: child.url ?? this.#frameUrls.get(child.path) ?? child.src ?? "",
                parentId: parent,
            };
            if (child.id)
                info.selector = `iframe[id=${JSON.stringify(child.id)}]`;
            else if (child.name)
                info.selector = `iframe[name=${JSON.stringify(child.name)}]`;
            result.push(info);
        }
        return result;
    }
    /** A child frame by `<iframe>` selector, frame name, frame id/path, or exact URL. */
    async frame(selectorOrNameOrUrl) {
        let spec;
        try {
            spec = parseTernSelector(selectorOrNameOrUrl);
        }
        catch {
            spec = undefined;
        }
        if (spec) {
            const found = await this.#kit("frameOf", [spec]).catch(() => null);
            if (found)
                return new TernFrame(this, found);
        }
        const match = (await this.frames()).find(frame => frame.parentId !== null &&
            (frame.id === selectorOrNameOrUrl ||
                frame.name === selectorOrNameOrUrl ||
                frame.url === selectorOrNameOrUrl));
        if (!match)
            throw new ToolError(`tab.frame(${JSON.stringify(selectorOrNameOrUrl)}) found no matching frame`);
        return new TernFrame(this, match.id);
    }
    /** The confirm/prompt Tern holds for a decision. */
    async dialog() {
        await this.#pull();
        const pending = this.#pendingDialog;
        if (!pending)
            return { open: false };
        return {
            open: true,
            type: pending.type,
            message: pending.message,
            ...(pending.defaultValue !== undefined ? { defaultValue: pending.defaultValue } : {}),
        };
    }
    /** Accept or dismiss the held dialog. */
    async handleDialog(opts) {
        try {
            await this.#op("dialog", {
                accept: opts.accept === true,
                ...(opts.text !== undefined ? { text: opts.text } : {}),
            });
        }
        catch (error) {
            if (error instanceof TernError && error.kind === "failed") {
                throw new ToolError("tab.handleDialog() found no pending confirm or prompt");
            }
            throw error;
        }
        this.#pendingDialog = undefined;
    }
    /** Change the automatic dialog policy (null: alerts accepted, confirms/prompts held). */
    async setDialogs(policy) {
        await this.#op("dialogs", { policy: policy ?? "default" });
        await this.#pull();
        if (policy && this.#pendingDialog)
            await this.handleDialog({ accept: policy === "accept" });
    }
    // ─── Emulation and clipboard ──────────────────────────────────────────
    /** Merge emulation overrides; unsupported ones throw before anything applies. */
    async emulate(options = {}) {
        if (options.timezone !== undefined && options.timezone !== null) {
            throw unsupported("emulate", "timezone cannot be overridden in WKWebView (Date keeps the system time zone)");
        }
        if (options.headers !== undefined && options.headers !== null && Object.keys(options.headers).length > 0) {
            throw unsupported("emulate", "extra HTTP headers cannot be added to WKWebView navigations and subresources");
        }
        if (options.reducedMotion !== undefined) {
            throw unsupported("emulate", "prefers-reduced-motion cannot be overridden in WKWebView (CSS media queries follow the system)");
        }
        if (options.cpuThrottling !== undefined && options.cpuThrottling !== null && options.cpuThrottling !== 1) {
            throw unsupported("emulate", "CPU throttling needs the Chromium DevTools protocol");
        }
        if (options.network !== undefined && options.network !== null) {
            throw unsupported("emulate", "network throttling needs the Chromium DevTools protocol (use offline: true for offline)");
        }
        let pageChanged = false;
        if (options.device !== undefined) {
            await loadPuppeteer();
            const device = loadedKnownDevices()[options.device];
            if (!device)
                throw new ToolError(`Unknown Puppeteer device ${JSON.stringify(options.device)}. Use tab.devices().`);
            await this.setViewport({
                width: device.viewport.width,
                height: device.viewport.height,
                deviceScaleFactor: device.viewport.deviceScaleFactor,
            });
            this.#deviceUserAgent = device.userAgent;
            await this.#op("agent", { value: options.userAgent ?? device.userAgent });
            this.#emulation.device = options.device;
        }
        if (options.viewport) {
            await this.setViewport({
                width: options.viewport.width,
                height: options.viewport.height,
                deviceScaleFactor: options.viewport.scale,
            });
            this.#emulation.viewport = { ...options.viewport };
        }
        if (options.userAgent !== undefined) {
            await this.#op("agent", { value: options.userAgent ?? this.#deviceUserAgent ?? null });
            this.#emulation.userAgent = options.userAgent;
        }
        if (options.colorScheme !== undefined) {
            await this.#op("appearance", { value: options.colorScheme === "no-preference" ? null : options.colorScheme });
            this.#emulation.colorScheme = options.colorScheme;
        }
        if (options.credentials !== undefined) {
            await this.#op("credentials", options.credentials
                ? { username: options.credentials.username, password: options.credentials.password }
                : {});
            this.#emulation.credentials = options.credentials ? { ...options.credentials } : null;
        }
        if (options.geolocation !== undefined) {
            this.#pageEmulation = { ...this.#pageEmulation, geolocation: options.geolocation ?? undefined };
            this.#emulation.geolocation = options.geolocation ? { ...options.geolocation } : null;
            pageChanged = true;
        }
        if (options.locale !== undefined) {
            this.#pageEmulation = { ...this.#pageEmulation, locale: options.locale ?? undefined };
            this.#emulation.locale = options.locale;
            pageChanged = true;
        }
        if (options.offline !== undefined) {
            this.#pageEmulation = { ...this.#pageEmulation, offline: options.offline };
            this.#emulation.offline = options.offline;
            pageChanged = true;
        }
        for (const key of ["timezone", "headers", "cpuThrottling", "network"]) {
            if (options[key] !== undefined)
                Object.assign(this.#emulation, { [key]: options[key] });
        }
        if (pageChanged)
            await this.#applyCapture();
        return structuredClone(this.#emulation);
    }
    /** Puppeteer known-device names. */
    async devices() {
        await loadPuppeteer();
        return Object.keys(loadedKnownDevices()).sort();
    }
    /** Read the system clipboard (Tern's `clipboard` op). */
    async clipboardRead() {
        const answer = await this.#client.request({ op: "clipboard" }, { signal: this.#signal });
        const text = isRecord(answer) && typeof answer.text === "string" ? answer.text : "";
        return { text, source: "page" };
    }
    /** Write the system clipboard. */
    async clipboardWrite(text) {
        await this.#client.request({ op: "clipboard", text: String(text) }, { signal: this.#signal });
        return { source: "page" };
    }
    /** Copy the page selection to the system clipboard. */
    async clipboardCopy() {
        await this.#op("edit", { action: "copy" });
        return { source: "page" };
    }
    /** Paste the system clipboard into the focused control. */
    async clipboardPaste() {
        await this.#op("edit", { action: "paste" });
        return { source: "page" };
    }
    // ─── Cookies and storage ──────────────────────────────────────────────
    async #allCookies() {
        const answer = await this.#op("cookies");
        if (!isRecord(answer) || !Array.isArray(answer.cookies))
            return [];
        return answer.cookies.map(cookieFromTern).filter((cookie) => cookie !== null);
    }
    /** Cookies visible to the current page (or `urls`). */
    async cookies(options = {}) {
        if (!Array.isArray(options.urls) && options.urls !== undefined) {
            throw new ToolError("tab.cookies() expects urls to be an array");
        }
        const urls = [];
        for (const raw of options.urls?.length ? options.urls : [this.#url]) {
            try {
                urls.push(new URL(raw));
            }
            catch {
                throw new ToolError(`tab.cookies() received an invalid URL ${JSON.stringify(raw)}`);
            }
        }
        return (await this.#allCookies()).filter(cookie => urls.some(url => cookieMatchesUrl(cookie, url)));
    }
    /** Store cookies (objects, Cookie headers, cURL dumps, JSON arrays). */
    async setCookies(...args) {
        for (const cookie of normalizeCookieArguments(args)) {
            let domain = cookie.domain;
            let cookiePath = cookie.path;
            let secure = cookie.secure;
            const base = cookie.url ?? (domain ? undefined : this.#url);
            if (base) {
                let parsed;
                try {
                    parsed = new URL(base);
                }
                catch {
                    throw new ToolError(`tab.setCookies() needs a domain or url for cookie ${JSON.stringify(cookie.name)}`);
                }
                domain ??= parsed.hostname;
                cookiePath ??= "/";
                secure ??= parsed.protocol === "https:";
            }
            if (!domain)
                throw new ToolError(`tab.setCookies() needs a domain or url for cookie ${JSON.stringify(cookie.name)}`);
            await this.#op("setCookie", {
                cookie: {
                    name: cookie.name,
                    value: cookie.value,
                    domain,
                    path: cookiePath ?? "/",
                    expires: cookie.expires === undefined || cookie.expires < 0 ? null : cookie.expires,
                    httpOnly: cookie.httpOnly ?? false,
                    secure: secure ?? false,
                    sameSite: cookie.sameSite ?? null,
                },
            });
        }
    }
    /** Delete the current page's cookies (or only `names`). */
    async clearCookies(options = {}) {
        if (!Array.isArray(options.names) && options.names !== undefined) {
            throw new ToolError("tab.clearCookies() expects names to be an array");
        }
        const wanted = options.names ? new Set(options.names) : undefined;
        for (const cookie of await this.cookies()) {
            if (wanted && !wanted.has(cookie.name))
                continue;
            await this.#op("deleteCookie", { name: cookie.name, domain: cookie.domain, path: cookie.path });
        }
    }
    /** One Web Storage area of the current origin, or one key. */
    async storage(kind, options = {}) {
        assertStorageKind(kind);
        if (options.key !== undefined && typeof options.key !== "string") {
            throw new ToolError("tab.storage() expects key to be a string");
        }
        const value = await this.#evalUser("tab.storage()", readStorageInPage, [kind, options.key], null);
        return typeof value === "string" || isRecord(value) ? value : null;
    }
    /** Set one key or several. */
    async setStorage(kind, keyOrEntries, value) {
        assertStorageKind(kind);
        const entries = typeof keyOrEntries === "string" ? [[keyOrEntries, storageValue(value)]] : storageEntries(keyOrEntries);
        await this.#evalUser("tab.setStorage()", writeStorageInPage, [kind, entries], null);
    }
    /** Clear one Web Storage area. */
    async clearStorage(kind) {
        assertStorageKind(kind);
        await this.#evalUser("tab.clearStorage()", clearStorageInPage, [kind], null);
    }
    /** Save every cookie of the PiP's store plus the current origin's storage. */
    async saveState(requestedPath) {
        const context = this.#requireRunContext("tab.saveState()");
        const destination = storageStatePath(this.#name, requestedPath, context.session.cwd);
        const [cookies, origin] = await Promise.all([
            this.#allCookies(),
            this.#evalUser("tab.saveState()", readOriginStorageInPage, [], null),
        ]);
        const origins = isRecord(origin) ? [origin] : [];
        await Bun.write(destination, `${JSON.stringify({ cookies, origins }, null, 2)}\n`);
        return destination;
    }
    /** Restore cookies and the current origin's storage; other origins are reported as skipped. */
    async loadState(requestedPath) {
        const context = this.#requireRunContext("tab.loadState()");
        const state = await readStorageStateFile(requestedPath, context.session.cwd, context.signal);
        if (state.cookies.length > 0)
            await this.setCookies(...state.cookies);
        let currentOrigin = "null";
        try {
            currentOrigin = new URL(this.#url).origin;
        }
        catch { }
        const loadedOrigins = [];
        const skippedOrigins = [];
        for (const origin of state.origins) {
            if (origin.origin === currentOrigin) {
                await this.#evalUser("tab.loadState()", restoreOriginStorageInPage, [origin], null);
                loadedOrigins.push(origin.origin);
            }
            else {
                skippedOrigins.push(origin.origin);
            }
        }
        return { loadedOrigins, skippedOrigins };
    }
    // ─── Init scripts and downloads ───────────────────────────────────────
    /** Run `source` in every future document (all frames). */
    async addInitScript(source) {
        if (typeof source !== "string")
            throw new ToolError("tab.addInitScript(source) requires a string");
        const id = `tern-init-${this.#nextInitScript++}`;
        this.#initScripts.push({ id, source });
        try {
            await this.#syncScripts();
        }
        catch (error) {
            this.#initScripts.pop();
            throw error;
        }
        return { id };
    }
    /** Stop running a registered script in future documents. */
    async removeInitScript(id) {
        if (typeof id !== "string" || id.length === 0)
            throw new ToolError("tab.removeInitScript(id) requires a non-empty script id");
        const index = this.#initScripts.findIndex(script => script.id === id);
        if (index < 0)
            throw new ToolError(`Unknown init script ${JSON.stringify(id)}`);
        this.#initScripts.splice(index, 1);
        await this.#syncScripts();
    }
    /** Registered init scripts. */
    async initScripts() {
        return this.#initScripts.map(script => ({ ...script }));
    }
    async #enableDownloads(dir) {
        const resolved = path.resolve(dir ?? path.join(os.tmpdir(), `omp-downloads-tern-${this.block}`));
        if (this.#downloadDir === resolved)
            return;
        await fs.promises.mkdir(resolved, { recursive: true });
        await this.#op("downloads", { dir: resolved });
        this.#downloadDir = resolved;
    }
    /** Wait for the next completed download. */
    async waitForDownload(opts) {
        if (!this.#downloadDir)
            await this.#enableDownloads();
        const failedBefore = new Set([...this.#downloads].filter(([, entry]) => entry.state === "failed").map(([id]) => id));
        return await this.#poll("tab.waitForDownload()", resolveWaitTimeout(this.#cellMs, opts?.timeout ?? resolveOpTimeouts(this.#cellMs).budgetBound), () => {
            const ready = this.#unclaimedDownloads.shift();
            if (ready)
                return { ...ready };
            for (const [id, entry] of this.#downloads) {
                if (entry.state === "failed" && !failedBefore.has(id)) {
                    throw new ToolError(`Download of ${entry.url} failed: ${entry.error ?? "unknown error"}`);
                }
            }
            return undefined;
        }, { pull: true });
    }
    /** Completed downloads of this tab. */
    async downloads() {
        if (!this.#downloadDir)
            await this.#enableDownloads();
        await this.#pull();
        return this.#completedDownloads.map(download => ({ ...download }));
    }
    // ─── Console, network ─────────────────────────────────────────────────
    async #capture(kind, options) {
        await this.#pull();
        const since = Number.isFinite(options.since) ? Math.floor(options.since ?? 0) : 0;
        const limit = Number.isFinite(options.limit) ? Math.max(0, Math.floor(options.limit ?? 500)) : 500;
        const level = "level" in options ? options.level : undefined;
        const entries = this.#console
            .filter(entry => entry.seq > since)
            .filter(entry => kind === "console"
            ? entry.type === "console" && (!level || entry.level === level)
            : entry.type !== "console")
            .slice(0, limit)
            .map(entry => ({ ...entry }));
        const result = {
            entries,
            nextSeq: entries.length ? entries[entries.length - 1].seq : this.#consoleSeq - 1,
            dropped: this.#consoleDropped,
        };
        if (options.clear)
            this.#clearConsoleBuffer();
        return result;
    }
    #clearConsoleBuffer() {
        this.#console.length = 0;
        this.#consoleDropped = 0;
    }
    /** Captured console messages (page world, from document start). */
    async console(options = {}) {
        const result = await this.#capture("console", options);
        return {
            ...result,
            entries: result.entries.filter((entry) => entry.type === "console"),
        };
    }
    /** Captured uncaught errors and failed requests. */
    async errors(options = {}) {
        const result = await this.#capture("errors", options);
        return {
            ...result,
            entries: result.entries.filter((entry) => entry.type !== "console"),
        };
    }
    /** Clear the console/error buffer. */
    async clearConsole() {
        await this.#pull();
        this.#clearConsoleBuffer();
    }
    /**
     * Load a captured response body from the frame that made the request,
     * waiting (within the op budget and the run's signal) for a body the page
     * is still reading.
     */
    loadBody = async (entry) => {
        if (!entry.pageId)
            return null;
        const body = await this.#eval(`function (id) { const capture = globalThis[${JSON.stringify(TERN_CAPTURE_GLOBAL)}]; return capture && capture.body ? capture.body(id) : null; }`, [entry.pageId], "page", entry.frame ?? null).catch((error) => {
            if (error instanceof ToolAbortError || (error instanceof Error && error.name === "AbortError"))
                throw error;
            return null;
        });
        if (!isRecord(body) || typeof body.contentType !== "string")
            return null;
        const value = typeof body.value === "string"
            ? body.value
            : isRecord(body.value) && typeof body.value.base64 === "string"
                ? { base64: body.value.base64 }
                : null;
        if (value === null)
            return null;
        return {
            value,
            contentType: body.contentType,
            truncated: body.truncated === true,
            bytes: numberOr(body.bytes, 0),
            isText: body.isText === true,
        };
    };
    /** Register a persistent fetch/XHR route. */
    async route(pattern, options = {}) {
        this.#network.route(pattern, options);
        await this.#applyCapture();
    }
    /** Remove matching routes, or all. */
    async unroute(pattern) {
        this.#network.unroute(pattern);
        await this.#applyCapture();
    }
    /** Registered routes. */
    async routes() {
        return this.#network.routes();
    }
    /** Query the request log. */
    async requests(options = {}) {
        await this.#pull();
        return this.#network.requests(options);
    }
    /** One request with its captured body. */
    async request(id) {
        await this.#pull();
        return await this.#network.request(id, this.loadBody);
    }
    /** Clear the request log. */
    async clearRequests() {
        await this.#pull();
        this.#network.clear();
    }
    /** Start a HAR recording. */
    async harStart(options = {}) {
        await this.#pull();
        this.#network.harStart(options.content ?? "none");
    }
    /** Stop the HAR recording and write it. */
    async harStop(options = {}) {
        const context = this.#requireRunContext("tab.harStop()");
        await this.#pull();
        const har = await this.#network.harStop(this.loadBody);
        const destination = options.path
            ? resolveToCwd(options.path, context.session.cwd)
            : path.join(os.tmpdir(), `omp-browser-${Snowflake.next()}.har`);
        await Bun.write(destination, `${JSON.stringify(har, null, 2)}\n`);
        return destination;
    }
    /** The normalised hostname allowlist. */
    async allowedDomains() {
        return [...this.#allowedDomains];
    }
    /** Wait for a matching fetch/XHR/navigation response after now. */
    async waitForResponse(pattern, opts) {
        await this.#pull();
        // Responses arriving from now on, in arrival order (requests already in flight included).
        let cursor = this.#network.settleCursor;
        return await this.#poll("tab.waitForResponse()", resolveWaitTimeout(this.#cellMs, opts?.timeout ?? resolveOpTimeouts(this.#cellMs).budgetBound), async () => {
            for (const record of this.#network.settledAfter(cursor)) {
                cursor = record.settledSeq ?? cursor;
                if (record.status === undefined)
                    continue;
                const response = new TernResponse(record, this);
                if (typeof pattern === "function") {
                    if (await pattern(response))
                        return response;
                }
                else if (typeof pattern === "string" ? record.url.includes(pattern) : pattern.test(record.url)) {
                    return response;
                }
            }
            return undefined;
        }, { pull: true });
    }
    // ─── Performance, React, WebMCP ───────────────────────────────────────
    /** Navigation timing of the current document. */
    async metrics() {
        const value = await this.#eval(`function () {
				const nav = performance.getEntriesByType("navigation")[0];
				const round = value => Math.round((Number(value) || 0) * 100) / 100;
				return {
					domContentLoaded: round(nav && nav.domContentLoadedEventEnd),
					load: round(nav && nav.loadEventEnd),
					Nodes: document.getElementsByTagName("*").length,
					Timestamp: round(performance.now()),
				};
			}`, [], "isolated", null);
        if (!isRecord(value))
            throw new ToolError("tab.metrics() could not read navigation timing");
        const result = {};
        for (const key in value)
            result[key] = numberOr(value[key], 0);
        return { ...result, domContentLoaded: result.domContentLoaded ?? 0, load: result.load ?? 0 };
    }
    #reactHost() {
        return {
            evaluate: (source, signal) => this.#evalExpression(source, signal),
            addInitSource: async (source) => {
                if (source === REACT_HOOK_INIT_SOURCE)
                    this.#reactHook = true;
                await this.#syncScripts();
            },
            reload: async () => {
                await this.reload({ waitUntil: "load" });
            },
        };
    }
    /** Web Vitals of the current document (observers run from document start). */
    async vitals(options = {}) {
        return await collectVitals(this.#reactHost(), options, this.#signal);
    }
    /** Install the React DevTools hook and reload. */
    async reactEnable() {
        return await enableReact(this.#reactHost(), this.#signal);
    }
    /** The mounted React tree. */
    async reactTree(options = {}) {
        const envelope = await this.#evalExpression(reactTreeSource(options));
        return requireReactHookResult(envelope);
    }
    /** One React fiber. */
    async reactInspect(id) {
        return reactInspectResult(await this.#evalExpression(reactInspectSource(id)), id);
    }
    /** React render recording. */
    async reactRenders(options) {
        const envelope = await this.#evalExpression(reactRendersSource(options.action));
        return requireReactHookResult(envelope);
    }
    /** React Suspense boundaries. */
    async reactSuspense(options = {}) {
        const envelope = await this.#evalExpression(reactSuspenseSource(options));
        return requireReactHookResult(envelope);
    }
    #webMcp() {
        this.#webmcp ??= new WebMcpController({
            frames: async () => [
                {
                    id: "main",
                    snapshot: async () => (await this.#eval(webMcpSnapshotInPage.toString(), [WEBMCP_BRIDGE_KEY], "page", null)),
                    invoke: async (name, params) => (await this.#eval(webMcpInvokeInPage.toString(), [WEBMCP_BRIDGE_KEY, name, params], "page", null)),
                },
            ],
            nativeTools: () => [],
            dispose: async () => {
                await this.#eval(uninstallWebMcpPageHook.toString(), [WEBMCP_BRIDGE_KEY], "page", null).catch(() => undefined);
            },
        }, {
            nativeSupported: false,
            unavailableReason: "No page-side WebMCP tool registrations were observed in the main frame.",
        });
        return this.#webmcp;
    }
    /** Page-provided WebMCP tools (main frame). */
    async webmcpList(options = {}) {
        return await this.#webMcp().list(options);
    }
    /** Invoke one page-provided WebMCP tool. */
    async webmcpInvoke(name, params, options = {}) {
        return await this.#webMcp().invoke(name, params, options);
    }
    /** WebMCP catalog changes. */
    async webmcpEvents(options = {}) {
        return await this.#webMcp().events(options);
    }
    // ─── Recording ────────────────────────────────────────────────────────
    #recordingSource() {
        let active = false;
        let loop;
        const tab = this;
        const capture = async (quality) => await tab.captureBytes({ format: "jpeg", quality: Math.max(1, Math.min(100, Math.round(quality))) });
        return {
            viewport: async () => {
                const geometry = await tab.#kit("geometry", []);
                return { width: geometry.innerWidth, height: geometry.innerHeight };
            },
            start: async (params) => {
                active = true;
                const intervalMs = Math.max(33, (params.everyNthFrame ?? 2) * (1000 / 60));
                loop = (async () => {
                    while (active) {
                        const startedAt = Date.now();
                        try {
                            const data = await tab.#client.request({ op: "capture", block: tab.block, format: "jpeg", quality: params.quality, scale: 1 }, { timeoutMs: 10000 });
                            if (active && isRecord(data) && typeof data.data === "string") {
                                await params.onFrame({ data: Buffer.from(data.data, "base64"), timestampMs: startedAt });
                            }
                        }
                        catch (error) {
                            logger.debug("Tern recording frame capture failed", {
                                error: error instanceof Error ? error.message : String(error),
                            });
                            if (error instanceof TernError && (error.kind === "closed" || error.kind === "not_found"))
                                return;
                        }
                        await Bun.sleep(Math.max(0, intervalMs - (Date.now() - startedAt)));
                    }
                })();
            },
            stop: async () => {
                active = false;
                await loop;
            },
            captureFrame: async (quality) => await capture(quality),
            installCursor: async () => {
                tab.#cursorOverlay = true;
                await tab.#syncScripts();
                await tab.#eval(installCursorOverlay.toString(), [], "page", null).catch(() => undefined);
            },
            removeCursor: async () => {
                tab.#cursorOverlay = false;
                await tab.#syncScripts().catch(() => undefined);
                await tab.#eval(removeCursorOverlay.toString(), [], "page", null).catch(() => undefined);
            },
        };
    }
    /** Record the PiP to MP4/WebM from repeated captures. */
    async recordStart(rawPath, options) {
        const context = this.#requireRunContext("tab.recordStart()");
        return await this.#recording.start(this.#recordingSource(), rawPath, context.session.cwd, options, context.signal);
    }
    /** Finalize the recording. */
    async recordStop() {
        const context = this.#requireRunContext("tab.recordStop()");
        return await this.#recording.stop({
            signal: context.signal,
            output: context.output,
            excludeWebP: context.session.excludeWebP,
        });
    }
    /** Finalize and immediately start another recording. */
    async recordRestart(rawPath, options) {
        const context = this.#requireRunContext("tab.recordRestart()");
        return await this.#recording.restart(this.#recordingSource(), rawPath, context.session.cwd, options, {
            signal: context.signal,
            output: context.output,
            excludeWebP: context.session.excludeWebP,
        });
    }
    /** Recording state. */
    async recording() {
        return this.#recording.status();
    }
    // ─── Unsupported ──────────────────────────────────────────────────────
    /** Unsupported: WKWebView has no tracing protocol. */
    async traceStart(_options = {}) {
        throw unsupported("traceStart", "WKWebView exposes no performance-trace protocol");
    }
    /** Unsupported: WKWebView has no tracing protocol. */
    async traceStop(_options = {}) {
        throw unsupported("traceStop", "WKWebView exposes no performance-trace protocol");
    }
    /** Unsupported: WKWebView has no CPU profiler protocol. */
    async profileStart() {
        throw unsupported("profileStart", "WKWebView exposes no CPU-profiler protocol");
    }
    /** Unsupported: WKWebView has no CPU profiler protocol. */
    async profileStop(_options = {}) {
        throw unsupported("profileStop", "WKWebView exposes no CPU-profiler protocol");
    }
    #requireRunContext(operation) {
        if (!this.#runContext)
            throw new ToolError(`${operation} requires an active Tern browser run`);
        return this.#runContext;
    }
}
/** Selector text for helper labels. */
function describe(selector) {
    return JSON.stringify(selector);
}
/** A response seen by the Tern tab: fetch/XHR (body from the page) or a navigation (no body). */
export class TernResponse {
    #record;
    #tab;
    constructor(record, tab) {
        this.#record = record;
        this.#tab = tab;
    }
    /** The response URL. */
    url() {
        return this.#record.url;
    }
    /** The HTTP status. */
    status() {
        return this.#record.status ?? 0;
    }
    /** The status text. */
    statusText() {
        return this.#record.statusText ?? "";
    }
    /** Whether the status is 2xx. */
    ok() {
        return this.#record.ok === true;
    }
    /** Response headers (lower-case names). */
    headers() {
        return { ...this.#record.responseHeaders };
    }
    /** The request's method and URL. */
    request() {
        const record = this.#record;
        return { url: () => record.url, method: () => record.method, resourceType: () => record.resourceType };
    }
    /** The body as text (fetch/XHR responses the page still holds). */
    async text() {
        const body = await this.#tab.loadBody(this.#record);
        if (!body) {
            throw new ToolError(`The body of ${this.#record.url} is not available on the Tern backend (only fetch/XHR bodies of the current document are captured)`);
        }
        return typeof body.value === "string" ? body.value : Buffer.from(body.value.base64, "base64").toString("utf8");
    }
    /** The body parsed as JSON. */
    async json() {
        return JSON.parse(await this.text());
    }
}
/** Element handle of the Tern tab (`tab.id(n)`, `tab.ref(eN)`, `waitFor`). */
export class TernElementHandle {
    #tab;
    #spec;
    #frame;
    constructor(tab, spec, frame) {
        this.#tab = tab;
        this.#spec = spec;
        this.#frame = frame;
    }
    /** Trusted click at the element's centre. */
    async click(options) {
        await this.#tab.clickIn(this.#spec, this.#frame, options);
    }
    /** Trusted double click. */
    async dblclick() {
        await this.#tab.dblclick(this.#spec, this.#frame);
    }
    /** Check it. */
    async check() {
        await this.#tab.check(this.#spec, this.#frame);
    }
    /** Uncheck it. */
    async uncheck() {
        await this.#tab.uncheck(this.#spec, this.#frame);
    }
    /** Outline it. */
    async highlight(opts) {
        await this.#tab.highlight(this.#spec, opts);
    }
    /** Type at the end of its content. */
    async type(text) {
        await this.#tab.type(this.#spec, text, this.#frame);
    }
    /** Replace its value. */
    async fill(value) {
        await this.#tab.fill(this.#spec, value, this.#frame);
    }
    /** Focus it and press a key. */
    async press(key) {
        await this.#tab.pressIn(key, { selector: this.#spec }, this.#frame);
    }
    /** Hover it. */
    async hover() {
        await this.#tab.hover(this.#spec, this.#frame);
    }
    /** Focus it. */
    async focus() {
        await this.#tab.focus(this.#spec, this.#frame);
    }
    /** Select options. */
    async select(...values) {
        return await this.#tab.select(this.#spec, ...values);
    }
    /** Upload files. */
    async uploadFile(...filePaths) {
        await this.#tab.uploadFile(this.#spec, ...filePaths);
    }
    /** Scroll it into view. */
    async scrollIntoView() {
        await this.#tab.scrollIntoView(this.#spec);
    }
    /** Its box in main-frame viewport px. */
    async boundingBox() {
        return await this.#tab.box(this.#spec, this.#frame);
    }
    /** Whether it is visible. */
    async isVisible() {
        return await this.#tab.isVisible(this.#spec, this.#frame);
    }
    /** Whether it is hidden. */
    async isHidden() {
        return !(await this.#tab.isVisible(this.#spec, this.#frame));
    }
    /** Its rendered text. */
    async text() {
        return (await this.#tab.text(this.#spec, this.#frame)) ?? "";
    }
    /** Its inner HTML. */
    async html() {
        return (await this.#tab.html(this.#spec, this.#frame)) ?? "";
    }
    /** Its form value. */
    async value() {
        return await this.#tab.value(this.#spec, this.#frame);
    }
    /** One attribute. */
    async attr(name) {
        return await this.#tab.attr(this.#spec, name, this.#frame);
    }
    /** Computed styles. */
    async styles(props) {
        return (await this.#tab.styles(this.#spec, props)) ?? {};
    }
    /** Whether it is enabled. */
    async isEnabled() {
        return await this.#tab.isEnabled(this.#spec);
    }
    /** Whether it is checked. */
    async isChecked() {
        return await this.#tab.isChecked(this.#spec);
    }
    /** Evaluate `fn(element, ...args)` in the page world. */
    async evaluate(fn, ...args) {
        return (await this.#tab.evaluateOnElement(this.#spec, fn, args, this.#frame));
    }
    /** Handles hold no page resources. */
    async dispose() { }
}
/** A child frame of the Tern tab (`tab.frame(...)`), addressed by its Tern frame path. */
export class TernFrame {
    #tab;
    #path;
    constructor(tab, framePath) {
        this.#tab = tab;
        this.#path = framePath;
    }
    /** The frame path (`0`, `1.0`). */
    get path() {
        return this.#path;
    }
    /** Click inside the frame. */
    async click(selector) {
        await this.#tab.clickIn(selector, this.#path);
    }
    /** Fill inside the frame. */
    async fill(selector, value) {
        await this.#tab.fill(selector, value, this.#path);
    }
    /** Type inside the frame. */
    async type(selector, text) {
        await this.#tab.type(selector, text, this.#path);
    }
    /** Press a key, optionally after focusing an element in the frame. */
    async press(key, options) {
        await this.#tab.pressIn(key, options, this.#path);
    }
    /** Element text; the frame's `<body>` without a selector. */
    async text(selector = "body") {
        return (await this.#tab.text(selector, this.#path)) ?? "";
    }
    /** Element inner HTML; the frame's `<body>` without a selector. */
    async html(selector = "body") {
        return (await this.#tab.html(selector, this.#path)) ?? "";
    }
    /** Form value. */
    async value(selector) {
        return (await this.#tab.value(selector, this.#path)) ?? "";
    }
    /** One attribute. */
    async attr(selector, name) {
        return await this.#tab.attr(selector, name, this.#path);
    }
    /** Match count. */
    async count(selector) {
        return await this.#tab.count(selector, this.#path);
    }
    /** Visibility. */
    async isVisible(selector) {
        return await this.#tab.isVisible(selector, this.#path);
    }
    /** ARIA snapshot of the frame. */
    async ariaSnapshot(selector, options) {
        const snapshot = await this.#tab.ariaSnapshotIn(selector, options, this.#path);
        return typeof snapshot === "string" ? snapshot : JSON.stringify(snapshot);
    }
    /** Evaluate in the frame's page world. */
    async evaluate(fn, ...args) {
        return (await this.#tab.evaluateIn(fn, args, this.#path));
    }
    /** Wait for a visible element; reports whether it appeared. */
    async waitFor(selector, options) {
        await this.#tab.waitForIn(selector, options, this.#path);
        return true;
    }
    /** Wait for an element; reports whether it appeared. */
    async waitForSelector(selector, options) {
        return (await this.#tab.waitForSelectorIn(selector, options, this.#path)) !== null;
    }
    /** Capture an element of the frame. */
    async screenshot(selector) {
        const result = await this.#tab.screenshotIn({ selector }, this.#path);
        return typeof result === "string" ? result : (result.path ?? "");
    }
}
/** `page.locator()` of the Tern page facade. */
class TernLocator {
    #tab;
    #selector;
    #timeoutMs;
    constructor(tab, selector) {
        this.#tab = tab;
        this.#selector = selector;
    }
    setTimeout(timeoutMs) {
        this.#timeoutMs = timeoutMs;
        return this;
    }
    async click() {
        await this.#tab.waitFor(this.#selector, { timeout: this.#timeoutMs });
        await this.#tab.click(this.#selector);
    }
    async fill(value) {
        await this.#tab.waitFor(this.#selector, { timeout: this.#timeoutMs });
        await this.#tab.fill(this.#selector, value);
    }
    async hover() {
        await this.#tab.waitFor(this.#selector, { timeout: this.#timeoutMs });
        await this.#tab.hover(this.#selector);
    }
    async waitHandle() {
        return await this.#tab.waitFor(this.#selector, { timeout: this.#timeoutMs });
    }
}
/**
 * The `page` object `tab.run` code sees on the Tern backend: a Puppeteer-like
 * subset (navigation, evaluate, content, locator/$/$$, waits, screenshot,
 * keyboard, mouse, cookies, user agent) over the tab's helpers.
 */
export class TernPageFacade {
    #tab;
    /** Keyboard input (trusted key events). */
    keyboard;
    /** Pointer input (trusted mouse events). */
    mouse;
    constructor(tab) {
        this.#tab = tab;
        this.keyboard = {
            press: key => tab.press(key),
            type: text => tab.keyboardType(text),
            down: key => tab.keyDown(key),
            up: key => tab.keyUp(key),
        };
        this.mouse = {
            move: (x, y, options) => tab.mouseMove(x, y, options),
            down: options => tab.mouseDown(options),
            up: options => tab.mouseUp(options),
            click: (x, y, options) => tab.clickAt(x, y, { button: options?.button, clickCount: options?.count }),
            wheel: delta => tab.wheel(delta.deltaX ?? 0, delta.deltaY ?? 0),
        };
    }
    url() {
        return this.#tab.url();
    }
    async title() {
        return await this.#tab.title();
    }
    viewport() {
        return this.#tab.viewport();
    }
    async setViewport(viewport) {
        await this.#tab.setViewport(viewport);
    }
    async setUserAgent(userAgent) {
        await this.#tab.emulate({ userAgent });
    }
    async goto(url, opts) {
        return await this.#tab.gotoResponse(url, { waitUntil: opts?.waitUntil, timeoutMs: opts?.timeout });
    }
    async reload(opts) {
        await this.#tab.reload(opts);
        return null;
    }
    async goBack(opts) {
        await this.#tab.back(opts);
        return null;
    }
    async goForward(opts) {
        await this.#tab.forward(opts);
        return null;
    }
    async evaluate(fn, ...args) {
        return await this.#tab.evaluate(fn, ...args);
    }
    async content() {
        return await this.#tab.pageContent();
    }
    locator(selector) {
        return new TernLocator(this.#tab, selector);
    }
    async $(selector) {
        return (await this.#tab.count(selector)) > 0 ? await this.#tab.waitForSelector(selector, { timeout: 1 }) : null;
    }
    async $$(selector) {
        return await this.#tab.handlesFor(selector);
    }
    async click(selector) {
        await this.#tab.click(selector);
    }
    async type(selector, text) {
        await this.#tab.type(selector, text);
    }
    async waitForSelector(selector, opts) {
        return await this.#tab.waitForSelector(selector, opts);
    }
    async waitForFunction(fn, opts, ...args) {
        return await this.#tab.waitForFunction(fn, opts, args);
    }
    async waitForResponse(pattern, opts) {
        return await this.#tab.waitForResponse(pattern, opts);
    }
    async waitForNavigation(opts) {
        return await this.#tab.waitForNavigation(opts);
    }
    async screenshot(opts = {}) {
        const bytes = await this.#tab.captureBytes({
            fullPage: opts.fullPage,
            format: opts.type ?? "png",
            quality: opts.quality,
        });
        return opts.encoding === "base64" ? bytes.toString("base64") : bytes;
    }
    async cookies(...urls) {
        return await this.#tab.cookies(urls.length ? { urls } : {});
    }
    async setCookie(...cookies) {
        await this.#tab.setCookies(...cookies);
    }
}
/** The `browser` object `tab.run` code sees on the Tern backend. */
export class TernBrowserFacade {
    #tab;
    /** Whether the facade still counts as connected. */
    connected = true;
    constructor(tab) {
        this.#tab = tab;
    }
    async pages() {
        return [this.#tab.page];
    }
    async version() {
        return "Tern WKWebView";
    }
    wsEndpoint() {
        return `tern://block/${this.#tab.block}`;
    }
    disconnect() {
        this.connected = false;
    }
    async close() {
        this.connected = false;
    }
}
