import { truncateHeadBytes } from "@rva/tui/tools/streaming-output";
/** Global property under which `installWebMcpPageHook` stores its page bridge. */
export const WEBMCP_BRIDGE_KEY = "__ompWebMcpBridge_v1";
const MAX_RESULT_BYTES = 64 * 1024;
const MAX_SUMMARY_BYTES = 4 * 1024;
const MAX_SUMMARY_DESCRIPTION_BYTES = 160;
const MAX_SUMMARY_TOOLS = 16;
const MAX_EVENTS = 256;
function frameId(frame) {
    const id = frame._id;
    return typeof id === "string" && id.length > 0 ? id : frame.url();
}
function originForUrl(url) {
    try {
        return new URL(url).origin;
    }
    catch {
        return "null";
    }
}
function untrustedBoundary(value) {
    const nonce = crypto.randomUUID();
    const bounded = truncateHeadBytes(value, Math.floor(MAX_RESULT_BYTES / 2)).text;
    return `[BEGIN UNTRUSTED WEBMCP CONTENT ${nonce}]\n${bounded}\n[END UNTRUSTED WEBMCP CONTENT ${nonce}]`;
}
function errorText(error) {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
function boundedResult(value) {
    let encoded;
    try {
        encoded = JSON.stringify(value);
    }
    catch (error) {
        throw new Error(`WebMCP result is not JSON-serializable: ${errorText(error)}`);
    }
    if (encoded === undefined)
        encoded = "null";
    const bytes = Buffer.byteLength(encoded, "utf8");
    if (bytes <= MAX_RESULT_BYTES) {
        return { ok: true, result: JSON.parse(encoded), untrusted: true };
    }
    const preview = truncateHeadBytes(encoded, Math.floor(MAX_RESULT_BYTES / 4)).text;
    return {
        ok: true,
        result: {
            preview: untrustedBoundary(preview),
            truncated: true,
            originalBytes: bytes,
        },
        truncated: true,
        originalBytes: bytes,
        untrusted: true,
    };
}
/**
 * Page function (self-contained; serialisable via `.toString()`): mirror `navigator/document.modelContext`
 * registrations into a bridge stored at `globalThis[key]`, polyfilling `modelContext` when absent. Idempotent.
 * The platform's `modelContext` getter is never called here: it creates the document's context, and Chromium kills
 * a renderer whose frame creates one twice, as this hook would in an iframe's initial empty document and again in
 * the document the iframe then loads. The platform's `ModelContext.prototype` methods are patched instead, which
 * reaches every reference to the context, however early the page took it; a context the page put on
 * navigator/document itself is patched directly.
 */
export function installWebMcpPageHook(key) {
    const realm = globalThis;
    if (realm[key])
        return;
    const pageGlobals = globalThis;
    const nav = pageGlobals.navigator;
    const doc = pageGlobals.document;
    // Chromium's getter is a native accessor on an interface prototype; anything else the page defined itself and
    // is read now.
    let platform = false;
    let pageContext;
    for (const instance of [doc, nav]) {
        let descriptor = Object.getOwnPropertyDescriptor(instance, "modelContext");
        for (let owner = Object.getPrototypeOf(instance); !descriptor && owner; owner = Object.getPrototypeOf(owner)) {
            descriptor = Object.getOwnPropertyDescriptor(owner, "modelContext");
        }
        if (descriptor?.get &&
            /^function get modelContext\(\) \{\s*\[native code\]\s*\}$/.test(Function.prototype.toString.call(descriptor.get))) {
            platform = true;
        }
        else {
            // Read as `document.modelContext ?? navigator.modelContext`: a null one falls through.
            pageContext ??= instance.modelContext;
        }
    }
    const platformPrototype = platform ? pageGlobals.ModelContext?.prototype : undefined;
    const nativeAvailable = platform || pageContext !== undefined;
    const tools = new Map();
    const patches = [];
    const changeTarget = new EventTarget();
    let polyfillContext;
    const cloneMetadata = (value) => {
        if (value === undefined)
            return undefined;
        try {
            return JSON.parse(JSON.stringify(value));
        }
        catch {
            return undefined;
        }
    };
    const notify = () => {
        const event = new Event("toolchange");
        changeTarget.dispatchEvent(event);
        polyfillContext?.ontoolchange?.(event);
    };
    const remember = (tool, signal) => {
        if (typeof tool?.name !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(tool.name)) {
            throw new TypeError("WebMCP tool name must contain 1-128 ASCII letters, digits, '_', '-', or '.'");
        }
        if (typeof (tool.execute ?? tool.handler) !== "function") {
            throw new TypeError(`WebMCP tool ${JSON.stringify(tool.name)} requires an execute function`);
        }
        tools.set(tool.name, tool);
        if (signal) {
            signal.addEventListener("abort", () => {
                if (tools.get(tool.name) === tool) {
                    tools.delete(tool.name);
                    notify();
                }
            }, { once: true });
        }
        notify();
    };
    const forget = (name) => {
        if (tools.delete(name))
            notify();
    };
    // Wrap the methods every registration goes through: the page's own context, called on that context as before,
    // or the platform prototype, called on whichever context the page used.
    const patch = (target, receiver) => {
        const register = target.registerTool;
        const unregister = target.unregisterTool;
        const wrappers = {
            async registerTool(tool, options) {
                if (register)
                    await register.call(receiver ?? this, tool, options);
                remember(tool, options?.signal);
            },
            async unregisterTool(name) {
                if (unregister)
                    await unregister.call(receiver ?? this, name);
                forget(name);
            },
        };
        for (const name of unregister ? ["registerTool", "unregisterTool"] : ["registerTool"]) {
            // A native context the page exposes itself already resolves to the prototype's wrapper.
            if (patches.some(patched => patched.value === target[name]))
                continue;
            const original = Object.getOwnPropertyDescriptor(target, name);
            // An own method keeps its attributes; an inherited one is shadowed.
            const descriptor = original && "value" in original
                ? { value: wrappers[name] }
                : { configurable: true, writable: true, value: wrappers[name] };
            try {
                Object.defineProperty(target, name, descriptor);
                patches.push({ target, name, original, value: wrappers[name] });
            }
            catch {
                // Native CDP discovery remains authoritative when this object is not patchable.
            }
        }
    };
    if (platformPrototype)
        patch(platformPrototype);
    if (pageContext)
        patch(pageContext, pageContext);
    // A page whose own modelContext is null reports the API but still gets the polyfill.
    if (!platform && !pageContext) {
        polyfillContext = {
            registerTool: async (tool, options) => remember(tool, options?.signal),
            unregisterTool: async (name) => forget(name),
            async provideContext(context) {
                const record = context && typeof context === "object" ? context : undefined;
                const provided = Array.isArray(context) ? context : record?.tools;
                if (!Array.isArray(provided))
                    throw new TypeError("provideContext() expects an array or { tools: [...] }");
                for (const tool of provided)
                    remember(tool);
            },
            async getTools() {
                return bridge.snapshot();
            },
            async executeTool(tool, params) {
                return await bridge.invoke(tool.name, params ?? {});
            },
            addEventListener: changeTarget.addEventListener.bind(changeTarget),
            removeEventListener: changeTarget.removeEventListener.bind(changeTarget),
            dispatchEvent: changeTarget.dispatchEvent.bind(changeTarget),
            ontoolchange: null,
        };
        for (const owner of [nav, doc]) {
            try {
                Object.defineProperty(owner, "modelContext", {
                    configurable: true,
                    enumerable: false,
                    value: polyfillContext,
                });
            }
            catch {
                // A hostile or unusual page can make the host object non-configurable.
            }
        }
    }
    const bridge = {
        nativeAvailable,
        snapshot() {
            return [...tools.values()]
                .map(tool => ({
                name: tool.name,
                description: typeof tool.description === "string" ? tool.description : "",
                inputSchema: cloneMetadata(tool.inputSchema),
                annotations: cloneMetadata(tool.annotations),
            }))
                .sort((left, right) => left.name.localeCompare(right.name));
        },
        async invoke(name, params) {
            const tool = tools.get(name);
            if (!tool)
                throw new Error(`No page-side WebMCP tool named ${JSON.stringify(name)}`);
            const execute = tool.execute ?? tool.handler;
            if (!execute)
                throw new Error(`WebMCP tool ${JSON.stringify(name)} has no execute function`);
            const controller = new AbortController();
            return await execute(params, { signal: controller.signal });
        },
        uninstall() {
            for (const { target, name, original, value } of patches) {
                try {
                    // Leave a method the page replaced after ours, and any attribute it changed.
                    if (Object.getOwnPropertyDescriptor(target, name)?.value !== value)
                        continue;
                    if (!original)
                        delete target[name];
                    else
                        Object.defineProperty(target, name, "value" in original ? { value: original.value } : original);
                }
                catch {
                    // Best-effort cleanup for attached user tabs.
                }
            }
            if (polyfillContext) {
                for (const owner of [nav, doc]) {
                    try {
                        if (owner.modelContext === polyfillContext)
                            delete owner.modelContext;
                    }
                    catch {
                        // Best-effort cleanup for attached user tabs.
                    }
                }
            }
            delete realm[key];
        },
    };
    Object.defineProperty(realm, key, { configurable: true, enumerable: false, value: bridge });
}
/** Page function (self-contained): read the bridge at `globalThis[key]` into a `WebMcpHookSnapshot`. */
export function webMcpSnapshotInPage(key) {
    const realm = globalThis;
    const bridge = realm[key];
    const pageLocation = globalThis;
    return {
        nativeAvailable: bridge?.nativeAvailable ?? false,
        tools: bridge?.snapshot() ?? [],
        origin: pageLocation.location.origin,
    };
}
/** Page function (self-contained): invoke mirrored tool `name` through the bridge at `globalThis[key]`. */
export async function webMcpInvokeInPage(key, name, params) {
    const realm = globalThis;
    const bridge = realm[key];
    if (!bridge)
        return { ok: false, error: "WebMCP page hook is unavailable" };
    try {
        const result = await bridge.invoke(name, params);
        const encoded = JSON.stringify(result === undefined ? null : result);
        return { ok: true, encoded };
    }
    catch (error) {
        return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
}
/** Page function (self-contained): restore wrapped page APIs and delete the bridge at `globalThis[key]`. */
export function uninstallWebMcpPageHook(key) {
    const realm = globalThis;
    realm[key]?.uninstall();
}
class ChromiumWebMcpFrame {
    #frame;
    constructor(frame) {
        this.#frame = frame;
    }
    get id() {
        return frameId(this.#frame);
    }
    async snapshot() {
        return await this.#frame.mainRealm().evaluate(webMcpSnapshotInPage, WEBMCP_BRIDGE_KEY);
    }
    async invoke(name, params) {
        return await this.#frame.mainRealm().evaluate(webMcpInvokeInPage, WEBMCP_BRIDGE_KEY, name, params);
    }
}
class ChromiumWebMcpHost {
    #page;
    #preload;
    constructor(page, preload) {
        this.#page = page;
        this.#preload = preload;
    }
    async frames() {
        return this.#page.frames().map(frame => new ChromiumWebMcpFrame(frame));
    }
    nativeTools() {
        return this.#page.webmcp.tools().map(tool => nativeToolEntry(tool));
    }
    async dispose() {
        await this.#page.removeScriptToEvaluateOnNewDocument(this.#preload.identifier).catch(() => undefined);
        for (const frame of this.#page.frames()) {
            await frame
                .mainRealm()
                .evaluate(uninstallWebMcpPageHook, WEBMCP_BRIDGE_KEY)
                .catch(() => undefined);
        }
    }
}
function nativeToolEntry(tool) {
    return {
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: tool.annotations,
        frameId: frameId(tool.frame),
        origin: originForUrl(tool.frame.url()),
        async execute(params) {
            const result = await tool.execute(params);
            if (result.status !== "Completed") {
                return {
                    ok: false,
                    error: result.errorText ?? result.exception?.description ?? `WebMCP invocation ${result.status}`,
                };
            }
            return { ok: true, output: result.output };
        },
    };
}
/** Per-tab WebMCP discovery, invocation, and catalog-event controller. */
export class WebMcpController {
    #host;
    #unavailableReason;
    #nativeSupported;
    #catalog = new Map();
    #events = [];
    #sequence = 0;
    #droppedThrough = 0;
    constructor(host, options) {
        this.#host = host;
        this.#nativeSupported = options.nativeSupported;
        this.#unavailableReason =
            options.unavailableReason ??
                "Chrome WebMCP CDP is unavailable and no page-side tool registrations were observed.";
    }
    /** Discover page-provided tools, omitting schemas unless an exact name is requested. */
    async list(options = {}) {
        await this.#refreshCatalog();
        let entries = [...this.#catalog.values()];
        if (options.name !== undefined)
            entries = entries.filter(tool => tool.name === options.name);
        if (options.frame !== undefined)
            entries = entries.filter(tool => tool.frameId === options.frame);
        entries.sort((left, right) => left.name.localeCompare(right.name) || left.frameId.localeCompare(right.frameId));
        if (options.name !== undefined) {
            return {
                status: this.#status(),
                tools: entries.map(entry => this.#publicRecord(entry, true)),
                truncated: false,
                ...this.#reason(),
                untrusted: true,
            };
        }
        const tools = [];
        let bytes = 128;
        let truncated = false;
        for (const entry of entries) {
            if (tools.length >= MAX_SUMMARY_TOOLS) {
                truncated = true;
                break;
            }
            const description = truncateHeadBytes(entry.description, MAX_SUMMARY_DESCRIPTION_BYTES).text;
            if (description !== entry.description)
                truncated = true;
            const record = {
                name: entry.name,
                description,
                frameId: entry.frameId,
                origin: entry.origin,
                untrusted: true,
            };
            const recordBytes = Buffer.byteLength(JSON.stringify(record), "utf8") + 1;
            if (bytes + recordBytes > MAX_SUMMARY_BYTES) {
                truncated = true;
                continue;
            }
            bytes += recordBytes;
            tools.push(record);
        }
        if (tools.length < entries.length)
            truncated = true;
        return {
            status: this.#status(),
            tools,
            truncated,
            ...this.#reason(),
            untrusted: true,
        };
    }
    /** Invoke one page-provided tool and return a bounded JSON-cloneable result. */
    async invoke(name, params, options = {}) {
        await this.#refreshCatalog();
        const matches = [...this.#catalog.values()].filter(tool => tool.name === name && (options.frame === undefined || tool.frameId === options.frame));
        if (matches.length === 0) {
            return {
                ok: false,
                error: untrustedBoundary(`No WebMCP tool named ${JSON.stringify(name)}${options.frame ? ` in frame ${JSON.stringify(options.frame)}` : ""}`),
                untrusted: true,
            };
        }
        if (matches.length > 1) {
            return {
                ok: false,
                error: untrustedBoundary(`WebMCP tool ${JSON.stringify(name)} exists in multiple frames: ${matches.map(tool => tool.frameId).join(", ")}`),
                untrusted: true,
            };
        }
        const tool = matches[0];
        try {
            if (tool.nativeTool) {
                const result = await tool.nativeTool.execute(this.#cloneInput(params));
                if (!result.ok)
                    return { ok: false, error: untrustedBoundary(result.error), untrusted: true };
                return boundedResult(result.output);
            }
            const response = await tool.target.invoke(name, this.#cloneInput(params));
            if (!response.ok) {
                return {
                    ok: false,
                    error: untrustedBoundary(response.error ?? "WebMCP invocation failed"),
                    untrusted: true,
                };
            }
            if (response.encoded === undefined) {
                return { ok: false, error: untrustedBoundary("WebMCP result was not JSON-serializable"), untrusted: true };
            }
            return boundedResult(JSON.parse(response.encoded));
        }
        catch (error) {
            return { ok: false, error: untrustedBoundary(errorText(error)), untrusted: true };
        }
    }
    /** Poll catalog transitions observed since a prior cursor. */
    async events(options = {}) {
        await this.#refreshCatalog();
        const since = typeof options.since === "number" && Number.isFinite(options.since) ? options.since : 0;
        const events = this.#events.filter(event => event.sequence > since);
        const truncated = since < this.#droppedThrough;
        const result = { events, cursor: this.#sequence, truncated, untrusted: true };
        if (options.clear) {
            this.#events = [];
            this.#droppedThrough = 0;
        }
        return result;
    }
    /** Remove the preload and restore any page API method wrapped by this controller. */
    async dispose() {
        await this.#host.dispose();
        this.#catalog.clear();
        this.#events = [];
        this.#droppedThrough = 0;
    }
    #status() {
        return this.#nativeSupported || this.#catalog.size > 0 ? "ready" : "unavailable";
    }
    #reason() {
        return this.#status() === "unavailable" ? { reason: this.#unavailableReason } : {};
    }
    #publicRecord(entry, full) {
        return {
            name: entry.name,
            description: entry.description,
            frameId: entry.frameId,
            origin: entry.origin,
            ...(full && entry.inputSchema !== undefined ? { inputSchema: entry.inputSchema } : {}),
            ...(full && entry.annotations !== undefined ? { annotations: entry.annotations } : {}),
            untrusted: true,
        };
    }
    #cloneInput(params) {
        if (params === undefined)
            return {};
        if (params === null || typeof params !== "object" || Array.isArray(params)) {
            throw new TypeError("WebMCP params must be a JSON object");
        }
        const encoded = JSON.stringify(params);
        if (encoded === undefined)
            throw new TypeError("WebMCP params must be JSON-serializable");
        const clone = JSON.parse(encoded);
        if (clone === null || typeof clone !== "object" || Array.isArray(clone)) {
            throw new TypeError("WebMCP params must remain a JSON object after serialization");
        }
        return clone;
    }
    async #refreshCatalog() {
        const next = new Map();
        for (const target of await this.#host.frames()) {
            try {
                const snapshot = await target.snapshot();
                this.#nativeSupported ||= snapshot.nativeAvailable;
                const id = target.id;
                for (const tool of snapshot.tools) {
                    const entry = {
                        name: tool.name,
                        description: tool.description,
                        frameId: id,
                        origin: snapshot.origin,
                        inputSchema: tool.inputSchema,
                        annotations: tool.annotations,
                        untrusted: true,
                        target,
                    };
                    next.set(`${id}\u0000${tool.name}`, entry);
                }
            }
            catch {
                // Detached or cross-process frames remain discoverable through native CDP events.
            }
        }
        if (this.#nativeSupported) {
            for (const tool of this.#host.nativeTools()) {
                const entry = {
                    name: tool.name,
                    description: tool.description,
                    frameId: tool.frameId,
                    origin: tool.origin,
                    inputSchema: tool.inputSchema,
                    annotations: tool.annotations,
                    untrusted: true,
                    nativeTool: tool,
                };
                next.set(`${tool.frameId}\u0000${tool.name}`, entry);
            }
        }
        for (const [key, entry] of next) {
            const previous = this.#catalog.get(key);
            if (!previous)
                this.#recordEvent("registered", entry);
            else if (this.#entryFingerprint(previous) !== this.#entryFingerprint(entry))
                this.#recordEvent("updated", entry);
        }
        for (const [key, entry] of this.#catalog) {
            if (!next.has(key))
                this.#recordEvent("unregistered", entry);
        }
        this.#catalog = next;
    }
    #entryFingerprint(entry) {
        return JSON.stringify({
            name: entry.name,
            description: entry.description,
            frameId: entry.frameId,
            origin: entry.origin,
            inputSchema: entry.inputSchema,
            annotations: entry.annotations,
        });
    }
    #recordEvent(type, entry) {
        this.#sequence += 1;
        this.#events.push({
            sequence: this.#sequence,
            type,
            name: entry.name,
            frameId: entry.frameId,
            origin: entry.origin,
            timestamp: Date.now(),
            untrusted: true,
        });
        if (this.#events.length > MAX_EVENTS) {
            const removed = this.#events.splice(0, this.#events.length - MAX_EVENTS);
            this.#droppedThrough = removed.at(-1)?.sequence ?? this.#droppedThrough;
        }
    }
}
/** Install the WebMCP preload before navigation and probe native CDP support. */
export async function installWebMcp(page) {
    const preload = await page.evaluateOnNewDocument(installWebMcpPageHook, WEBMCP_BRIDGE_KEY);
    for (const frame of page.frames()) {
        await frame
            .mainRealm()
            .evaluate(installWebMcpPageHook, WEBMCP_BRIDGE_KEY)
            .catch(() => undefined);
    }
    let nativeSupported = false;
    let session;
    try {
        session = await page.createCDPSession();
        await Promise.race([
            session.send("WebMCP.enable"),
            Bun.sleep(1000).then(() => {
                throw new Error("WebMCP CDP probe timed out");
            }),
        ]);
        nativeSupported = true;
    }
    catch {
        nativeSupported = false;
    }
    finally {
        await session?.detach().catch(() => undefined);
    }
    return new WebMcpController(new ChromiumWebMcpHost(page, preload), { nativeSupported });
}
