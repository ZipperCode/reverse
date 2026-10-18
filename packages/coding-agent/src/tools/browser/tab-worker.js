import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { formatBytes, isRecord, postmortem, Snowflake, untilAborted, withTimeout } from "@rva/utils";
import { JsRuntime } from "../../eval/js/shared/runtime";
import { formatScreenshot, resizeImage } from "../../utils/image-resize";
import { resolveToCwd } from "../path-utils";
import { bindRunFacade, installBrowserWorkerRejectionGuard, isBrowserRunOwnedRejection, markBrowserRunRejection, markHandled, observeBrowserRunPromise, resolvePredicateTimeout, waitForRun, withBrowserPromiseCombinatorTracking, } from "../run-scope";
import { ToolAbortError, throwIfAborted } from "../tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { assertSelectorString, captureAriaSnapshot, PLAYWRIGHT_ONLY_SELECTOR_RE, parseAriaRefSelector, resolveAriaRefHandle, } from "./aria/aria-snapshot";
import { resolveOpTimeouts, resolveWaitTimeout, ZERO_MATCH_FAIL_FAST_MS, ZERO_MATCH_POLL_MS } from "./op-timeouts";
import { formatA11ySummary, runA11yAudit } from "./a11y/audit";
import { applyUserAgentOverride, BrowserEmulationController, } from "./emulation";
import { applyStealthPatches, applyViewport, BROWSER_PROTOCOL_TIMEOUT_MS, connectPuppeteer, DEFAULT_VIEWPORT, isPuppeteerHandle, loadPuppeteerInWorker, loadedKnownDevices, loadedNetworkConditions, readPageViewport, } from "./launch";
import { extractReadableFromHtml } from "./readable";
import { assertTabPressArgs } from "./tab-arguments";
import { clearPageCookies, loadStorageState, readCookies, readStorage, saveStorageState, setPageCookies, setPageStorage, clearPageStorage, } from "./storage-state";
import { enableReact, puppeteerReactHost } from "./react/devtools-hook";
import { collectReactRenders } from "./react/renders";
import { readReactSuspense } from "./react/suspense";
import { inspectReactFiber, readReactTree, } from "./react/tree";
import { collectVitals, installVitalsObservers } from "./react/vitals";
import { registerSemanticQueryHandlers } from "./query-handlers";
import { enrichElementQueries, queryAttribute, queryBox, queryChecked, queryCount, queryEnabled, queryHtml, queryStyles, queryText, queryValue, queryVisible, waitForPageText, } from "./queries";
import { DownloadManager } from "./downloads";
import { InitScriptManager } from "./init-scripts";
import { applyIgnoreHttpsErrors } from "./open-options";
import { BrowserNetworkManager, } from "./network";
import { PageConsoleCapture, } from "./console-capture";
import { BrowserTracingController, } from "./tracing";
import { installWebMcp, } from "./webmcp";
import { createCdpRecordingSource, RecordingController, } from "./recording";
import { ariaSnapshotBaselineKey, diffAriaSnapshot, } from "./snapshot-plus";
import { ClickRefusedError, clickAt, clickElement, composedContains, clickQueryHandlerText, fillViaHandle, focusTextEntryTarget, highlightElement, keyDown, keyUp, mouseDown, mouseMove, mouseUp, pressKey, selectElementOptions, setElementChecked, prepareElementUpload, wheel, } from "./interactions";
import { captureScreenshotBuffer, createPngDiff, formatScreenshotLegend, installScreenshotAnnotations, pngPixelChangeRatio, screenshotArea, screenshotQuality, screenshotScope, screenshotThreshold, } from "./screenshot";
import { RuntimeDialogController } from "./dialogs";
import { captureFrameScreenshot, createFrameApi, listFrames, resolveFrame, } from "./frames";
import { navigateMainFrame, pushState, reloadPage, traverseHistory } from "./navigation";
import { cloneSafe, RunOutput } from "./run-output";
import { UploadStaging } from "./upload-files";
const INTERACTIVE_AX_ROLES = new Set([
    "button",
    "link",
    "textbox",
    "combobox",
    "listbox",
    "option",
    "checkbox",
    "radio",
    "switch",
    "tab",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "slider",
    "spinbutton",
    "searchbox",
    "treeitem",
]);
const LEGACY_SELECTOR_PREFIXES = ["p-aria/", "p-text/", "p-xpath/", "p-pierce/"];
const SELECTOR_HANDLER_PREFIXES = [
    "aria/",
    "text/",
    "xpath/",
    "pierce/",
    "label/",
    "placeholder/",
    "testid/",
    "alt/",
    "title/",
    "role/",
    "aria-ref=",
    "aria-ref/",
    "ariaref/",
    "p-",
];
/** Maximum wait for a renderer acknowledgement after a wheel event is queued. */
const SCROLL_ACK_TIMEOUT_MS = 2000;
/** Cleanup must settle inside the supervisor's 750ms post-run grace window. */
const REQUEST_INTERCEPTION_CLEANUP_TIMEOUT_MS = 500;
/** Bound cleanup window after a timed-out raw handle action. */
const HANDLE_ACTION_INVALIDATION_TIMEOUT_MS = 500;
/** Bound on reading every iframe in one observation; a frame whose renderer is stuck in script never answers. */
const FRAME_SNAPSHOT_TIMEOUT_MS = 5000;
/** Bound on Puppeteer exposing a page Chromium still has; the supervisor's init budget caps the whole attach anyway. */
const ATTACHED_TARGET_EXPOSE_TIMEOUT_MS = 5000;
/** Queue a wheel event without treating a delayed renderer acknowledgement as dispatch failure. */
export async function dispatchScroll(dispatch, ackTimeoutMs = SCROLL_ACK_TIMEOUT_MS) {
    const deadline = Promise.withResolvers();
    const timer = setTimeout(() => deadline.resolve(), ackTimeoutMs);
    timer.unref();
    try {
        await Promise.race([dispatch(), deadline.promise]);
    }
    finally {
        clearTimeout(timer);
    }
}
export function normalizeSelector(selector) {
    assertSelectorString(selector);
    if (!selector)
        return selector;
    if (!SELECTOR_HANDLER_PREFIXES.some(prefix => selector.startsWith(prefix)) &&
        PLAYWRIGHT_ONLY_SELECTOR_RE.test(selector)) {
        throw new ToolError(`Playwright-only selector ${JSON.stringify(selector)} is not supported by the browser tool. ` +
            `Use a puppeteer text selector ("text/Allow all"), an aria selector ("aria/Name"), CSS, or "xpath/...".`);
    }
    if (selector.startsWith("p-") && !LEGACY_SELECTOR_PREFIXES.some(prefix => selector.startsWith(prefix))) {
        throw new ToolError(`Unsupported selector prefix. Use CSS or puppeteer query handlers (aria/, text/, xpath/, pierce/). Got: ${selector}`);
    }
    if (selector.startsWith("p-text/"))
        return `text/${selector.slice("p-text/".length)}`;
    if (selector.startsWith("p-xpath/"))
        return `xpath/${selector.slice("p-xpath/".length)}`;
    if (selector.startsWith("p-pierce/"))
        return `pierce/${selector.slice("p-pierce/".length)}`;
    if (selector.startsWith("p-aria/")) {
        const rest = selector.slice("p-aria/".length);
        const nameMatch = rest.match(/\[\s*name\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\]]+))\s*\]/);
        const name = nameMatch?.[1] ?? nameMatch?.[2] ?? nameMatch?.[3];
        if (name)
            return `aria/${name.trim()}`;
        return `aria/${rest}`;
    }
    return selector;
}
function isInteractiveNode(node) {
    if (INTERACTIVE_AX_ROLES.has(node.role))
        return true;
    return (node.checked !== undefined ||
        node.pressed !== undefined ||
        node.selected !== undefined ||
        node.expanded !== undefined ||
        node.focused === true);
}
function asElementHandle(handle) {
    return handle ? handle : null;
}
/**
 * Every `ElementHandle` method that dispatches input, pointer/touch, drag, or navigation
 * work and can therefore stall on a busy page. When {@link toActionableHandle} is given a
 * guard, each is routed through the per-op fail-fast wrapper; without it the inherited
 * puppeteer method runs outside the op map and a stall consumes the whole cell (issue #9535).
 * Pure reads (`boundingBox`, `screenshot`, `evaluate`, queries) are omitted — they are not
 * user-driven actions and keep their native puppeteer behavior.
 */
const GUARDED_HANDLE_METHODS = [
    "click",
    "type",
    "hover",
    "tap",
    "focus",
    "press",
    "select",
    "uploadFile",
    "scrollIntoView",
    "drag",
    "dragEnter",
    "dragOver",
    "drop",
    "dragAndDrop",
    "touchStart",
    "touchMove",
    "touchEnd",
    "autofill",
];
/** Symbol-keyed original methods travel with each cached handle without enumerating or colliding. */
const RAW_HANDLE_METHODS = Symbol("browser.rawHandleMethods");
async function runGuardedHandleAction(handle, state, label, signal, action, invalidate) {
    if (state.invalidatedBy) {
        throw new ToolError(`${label} cannot run: this handle was invalidated after ${state.invalidatedBy} timed out; ` +
            "run tab.observe() or tab.ariaSnapshot() to resolve a fresh handle");
    }
    throwIfAborted(signal);
    const pending = action();
    try {
        return await untilAborted(signal, () => pending);
    }
    catch (error) {
        if (!signal.aborted)
            throw error;
        state.invalidatedBy = label;
        let actionError;
        await withTimeout(Promise.all([
            pending.then(() => undefined, (err) => {
                actionError = err;
            }),
            handle.dispose().catch(() => undefined),
            invalidate?.().catch(() => undefined),
        ]), HANDLE_ACTION_INVALIDATION_TIMEOUT_MS, `Timed out invalidating ${label}`).catch(() => undefined);
        // A click still refused when the deadline hit carries the reason on its own abort error.
        throw actionError instanceof ClickRefusedError ? actionError : error;
    }
}
async function uploadThroughHandle(handle, state, filePaths, guard, uploads, invalidate) {
    const label = "handle.uploadFile()";
    // Its own deadline, as for `tab.uploadFile`: the first upload's check must not eat into the action's.
    const route = await guard(`${label} checking how the browser takes files`, signal => uploads.route(signal));
    const prepared = await guard(label, signal => runGuardedHandleAction(handle, state, label, signal, () => uploads.prepare(filePaths, label, route, signal), invalidate));
    try {
        await uploads.deliverGuard(`${label} sending ${formatBytes(prepared.bytes)}`, signal => prepared.deliver(signal));
    }
    finally {
        await prepared.dispose();
    }
}
/**
 * Re-home element handles in `args` into `realm` so they can be passed to an
 * evaluation there. The stealth patch resolves selectors (`tab.waitForSelector`,
 * `tab.$`, …) in Puppeteer's isolated world while `tab.evaluate` runs in the main
 * world; CDP rejects a handle used outside the context that created it. Puppeteer's
 * supported realm adoption is DOM-only, so non-element JSHandles pass through and
 * retain Puppeteer's native same-realm requirement. Nested handles likewise remain
 * unsupported by Puppeteer's positional argument serializer.
 *
 * Adopted copies are disposed on partial adoption failure and after evaluation.
 * Caller-owned handles — including handles already in `realm` — are never disposed.
 */
async function adoptElementArgs(realm, args) {
    let adopted;
    let out;
    let copies;
    const dispose = async () => {
        if (adopted)
            await Promise.all(adopted.map(handle => handle.dispose().catch(() => undefined)));
    };
    try {
        for (let i = 0; i < args.length; i++) {
            const handle = args[i];
            if (!isPuppeteerHandle(handle))
                continue;
            const element = handle.asElement();
            if (!element || handle.realm === realm)
                continue;
            copies ??= new Map();
            let copy = copies.get(handle);
            if (!copy) {
                copy = await realm.adoptHandle(element);
                copies.set(handle, copy);
                (adopted ??= []).push(copy);
            }
            out ??= args.slice();
            out[i] = copy;
        }
    }
    catch (error) {
        await dispose();
        throw error;
    }
    return { args: out ?? args, dispose };
}
/**
 * Attach `fill()` to a puppeteer ElementHandle before handing it to user code and,
 * when a `guard` is supplied, route every interactive method ({@link GUARDED_HANDLE_METHODS})
 * through the same fail-fast per-op wrapper as the selector-based helpers — so
 * `(await tab.id(n)).click()` fails fast with `handle.click() timed out after …ms`
 * instead of stalling until the whole browser cell expires. Repeated enrichment is
 * idempotent: cached handles are always rewrapped from their original bound methods,
 * never from wrappers retaining an earlier run's guard. A timed-out action invalidates
 * and disposes its handle before surfacing the named error, so catching it cannot
 * dispatch a duplicate retry through the stale handle. Puppeteer handles expose
 * `type()` but no `fill()`; the `fill()` semantics mirror the selector-based
 * `tab.fill()`: focus, clear any existing value, then type, or set the value of a
 * colour, date, time or range input directly.
 */
export function toActionableHandle(handle, guard, invalidate, uploads) {
    const enriched = handle;
    const methods = enriched;
    const preserved = enriched[RAW_HANDLE_METHODS];
    if (!guard) {
        if (preserved) {
            for (const method of GUARDED_HANDLE_METHODS) {
                const original = preserved.interactive[method];
                if (original)
                    methods[method] = original;
            }
        }
        enriched.fill = value => fillViaHandle(enriched, value, undefined, preserved?.type);
        enriched.click = options => clickElement(enriched, "handle.click()", undefined, {
            button: options?.button,
            clickCount: options?.count,
        });
        enriched.dblclick = () => clickElement(enriched, "handle.dblclick()", undefined, { clickCount: 2 });
        enriched.check = () => setElementChecked(enriched, true, "handle.check()");
        enriched.uncheck = () => setElementChecked(enriched, false, "handle.uncheck()");
        enriched.select = (...values) => selectElementOptions(enriched, values, "handle.select()");
        enriched.highlight = options => highlightElement(enriched, options);
        const controller = new AbortController();
        return enrichElementQueries(enriched, (_label, fn) => fn(controller.signal));
    }
    let originals = preserved;
    if (!originals) {
        const interactive = {};
        for (const method of GUARDED_HANDLE_METHODS) {
            const original = methods[method];
            if (typeof original === "function")
                interactive[method] = original.bind(enriched);
        }
        // Puppeteer's `ElementHandle.press` takes a single key name; focus and press
        // through `pressKey` so combos and the macOS editing commands work on handles too.
        const focus = interactive.focus;
        if (focus) {
            const press = async (key, options) => {
                await focus();
                await pressKey(enriched.frame.page(), key, options);
            };
            interactive.press = press;
        }
        originals = { interactive, type: enriched.type.bind(enriched) };
        enriched[RAW_HANDLE_METHODS] = originals;
    }
    for (const method of GUARDED_HANDLE_METHODS) {
        if (method === "type")
            continue;
        const original = originals.interactive[method];
        if (!original)
            continue;
        methods[method] = (...args) => guard(`handle.${method}()`, signal => runGuardedHandleAction(enriched, originals, `handle.${method}()`, signal, () => original(...args), invalidate));
    }
    enriched.type = (text, options) => guard("handle.type()", signal => runGuardedHandleAction(enriched, originals, "handle.type()", signal, () => typeViaHandle(enriched, text, options, signal), invalidate));
    enriched.fill = value => guard("handle.fill()", signal => runGuardedHandleAction(enriched, originals, "handle.fill()", signal, () => fillViaHandle(enriched, value, signal, text => typeViaHandle(enriched, text, { delay: 0 }, signal)), invalidate));
    enriched.click = options => guard("handle.click()", signal => runGuardedHandleAction(enriched, originals, "handle.click()", signal, () => clickElement(enriched, "handle.click()", signal, {
        button: options?.button,
        clickCount: options?.count,
    }), invalidate));
    enriched.dblclick = () => guard("handle.dblclick()", signal => runGuardedHandleAction(enriched, originals, "handle.dblclick()", signal, () => clickElement(enriched, "handle.dblclick()", signal, { clickCount: 2 }), invalidate));
    enriched.check = () => guard("handle.check()", signal => runGuardedHandleAction(enriched, originals, "handle.check()", signal, () => setElementChecked(enriched, true, "handle.check()", signal), invalidate));
    enriched.uncheck = () => guard("handle.uncheck()", signal => runGuardedHandleAction(enriched, originals, "handle.uncheck()", signal, () => setElementChecked(enriched, false, "handle.uncheck()", signal), invalidate));
    enriched.select = (...values) => guard("handle.select()", signal => runGuardedHandleAction(enriched, originals, "handle.select()", signal, () => selectElementOptions(enriched, values, "handle.select()", signal), invalidate));
    enriched.highlight = (options) => guard("handle.highlight()", signal => runGuardedHandleAction(enriched, originals, "handle.highlight()", signal, () => highlightElement(enriched, options, signal), invalidate));
    const clearFiles = methods.uploadFile;
    if (uploads) {
        enriched.uploadFile = async (...filePaths) => {
            // With no paths Puppeteer's own method clears the input; there is nothing to route.
            if (!filePaths.length && clearFiles) {
                await clearFiles();
                return;
            }
            await uploadThroughHandle(enriched, originals, filePaths, guard, uploads, invalidate);
        };
    }
    return enrichElementQueries(enriched, guard);
}
/** Focus once, then type one code point at a time so abort stops before the next key dispatch. */
async function typeViaHandle(handle, text, options, signal) {
    await focusTextEntryTarget(handle, "type into", signal);
    for (const character of text) {
        throwIfAborted(signal);
        await untilAborted(signal, () => handle.frame.page().keyboard.type(character, options));
    }
}
/**
 * Strip `user:pass@` from a URL before surfacing it in tool outputs / details
 * so Basic Auth credentials don't leak into transcripts. Returns the original
 * string verbatim when it doesn't parse as a URL or when there are no
 * credentials to redact.
 */
function redactUrlCredentials(url) {
    if (!url || (!url.includes("@") && !url.includes("//")))
        return url;
    try {
        const parsed = new URL(url);
        if (!parsed.username && !parsed.password)
            return url;
        parsed.username = "";
        parsed.password = "";
        return parsed.toString();
    }
    catch {
        return url;
    }
}
class RequestInterceptionCleanupError extends ToolError {
}
/** `tab.goto` outlasted its budget; the page stays on what loaded. */
class NavigationTimeoutError extends ToolError {
}
/** The page's renderer crashed; every later call on the page stalls until its timeout. */
class RendererCrashedError extends ToolError {
}
/** Chrome ended the debugger attachment the page is driven through (omp browser relay); the page itself lives on. */
class DebuggerDetachedError extends ToolError {
    reason;
    when;
    constructor(reason, 
    /** `during`: the run's code had started, so its input may already have landed. */
    when) {
        super(`Chrome detached omp from this tab (${reason}) ${when === "during" ? "during this call" : "before this call, so its code did not run"}`);
        this.reason = reason;
        this.when = when;
    }
}
/**
 * Expose the tab page while retaining every event handler created by this run.
 * The facade removes only run-owned listeners, preserving worker-level routing,
 * request logging, dialogs, and console capture. Raw interception is restored
 * to the tab's persistent route/allowlist state after a run that changed it.
 *
 * A listener added to the page while the run is attached is run-owned, whichever
 * reference reached the page, except one added while the page is delivering an
 * event to a handler the run did not add. Puppeteer's in-flight request tracking
 * subscribes to request completion from inside its own `request` handler; removing
 * those subscriptions with the run left `waitForNetworkIdle` waiting on a request
 * an earlier run started.
 */
function createRunPageScope(page, restoreInterception) {
    const handlers = new Map();
    /**
     * The listener the page holds for each run-owned handler. It runs the handler with
     * `delivering` cleared, so what the handler registers stays run-owned. One per handler,
     * so duplicate registrations and removals keep puppeteer's own ordering.
     */
    const listeners = new Map();
    const on = page.on;
    const off = page.off;
    const once = page.once;
    const emit = page.emit;
    const setRequestInterception = page.setRequestInterception;
    const onDescriptor = Object.getOwnPropertyDescriptor(page, "on");
    const offDescriptor = Object.getOwnPropertyDescriptor(page, "off");
    const onceDescriptor = Object.getOwnPropertyDescriptor(page, "once");
    const emitDescriptor = Object.getOwnPropertyDescriptor(page, "emit");
    const removeAllDescriptor = Object.getOwnPropertyDescriptor(page, "removeAllListeners");
    const interceptionDescriptor = Object.getOwnPropertyDescriptor(page, "setRequestInterception");
    let interceptionChanged = false;
    /** Set while the page delivers an event; a listener the run added clears it while it runs. */
    let delivering = false;
    const withDelivering = (value, fn) => {
        const outer = delivering;
        delivering = value;
        try {
            return fn();
        }
        finally {
            delivering = outer;
        }
    };
    const listenerFor = (handler) => {
        let listener = listeners.get(handler);
        if (!listener) {
            listener = (...args) => withDelivering(false, () => Reflect.apply(handler, undefined, args));
            listeners.set(handler, listener);
        }
        return listener;
    };
    const remember = (type, handler) => {
        const owned = handlers.get(type);
        if (owned)
            owned.push(handler);
        else
            handlers.set(type, [handler]);
        Reflect.apply(on, page, [type, listenerFor(handler)]);
    };
    /** Remove run-owned registrations; reports whether any matched. */
    const forget = (type, handler) => {
        const owned = handlers.get(type);
        if (!owned)
            return false;
        if (handler === undefined) {
            for (const registered of owned)
                Reflect.apply(off, page, [type, listenerFor(registered)]);
            handlers.delete(type);
            return true;
        }
        const index = owned.findLastIndex(registered => registered === handler);
        if (index < 0)
            return false;
        Reflect.apply(off, page, [type, listenerFor(owned[index])]);
        owned.splice(index, 1);
        if (owned.length === 0)
            handlers.delete(type);
        return true;
    };
    Object.defineProperties(page, {
        on: {
            configurable: true,
            value: (type, handler) => {
                if (delivering || typeof handler !== "function")
                    Reflect.apply(on, page, [type, handler]);
                else
                    remember(type, handler);
                return page;
            },
        },
        once: {
            configurable: true,
            value: (type, handler) => {
                if (delivering || typeof handler !== "function") {
                    Reflect.apply(once, page, [type, handler]);
                    return page;
                }
                const wrapper = (event) => {
                    forget(type, wrapper);
                    Reflect.apply(handler, page, [event]);
                };
                remember(type, wrapper);
                return page;
            },
        },
        off: {
            configurable: true,
            value: (type, handler) => {
                // Puppeteer's own subscriptions unsubscribe through here too.
                if (!forget(type, handler) && handler !== undefined)
                    Reflect.apply(off, page, [type, handler]);
                return page;
            },
        },
        emit: {
            configurable: true,
            value: (type, event) => {
                // Puppeteer defers every `request` listener to an interception action that runs after
                // `emit` returns, so each action queued during `emit` keeps the delivery it came from.
                const request = type === "request" && typeof event === "object" ? event : null;
                const enqueue = request?.enqueueInterceptAction;
                if (!request || typeof enqueue !== "function") {
                    return withDelivering(true, () => Reflect.apply(emit, page, [type, event]));
                }
                const enqueueDescriptor = Object.getOwnPropertyDescriptor(request, "enqueueInterceptAction");
                Object.defineProperty(request, "enqueueInterceptAction", {
                    configurable: true,
                    value: (action) => {
                        const queued = delivering;
                        Reflect.apply(enqueue, request, [() => withDelivering(queued, action)]);
                    },
                });
                try {
                    return withDelivering(true, () => Reflect.apply(emit, page, [type, event]));
                }
                finally {
                    // The tab's request log keeps requests well after the run; do not let them hold this scope.
                    if (enqueueDescriptor)
                        Object.defineProperty(request, "enqueueInterceptAction", enqueueDescriptor);
                    else
                        Reflect.deleteProperty(request, "enqueueInterceptAction");
                }
            },
        },
        removeAllListeners: {
            configurable: true,
            value: (type) => {
                if (type !== undefined)
                    forget(type);
                else {
                    // Map iteration tolerates deletion of the current key by forget().
                    for (const ownedType of handlers.keys())
                        forget(ownedType);
                }
                return page;
            },
        },
        setRequestInterception: {
            configurable: true,
            value: (value) => {
                interceptionChanged = true;
                return Reflect.apply(setRequestInterception, page, [value]);
            },
        },
    });
    return {
        page,
        detach() {
            if (onDescriptor)
                Object.defineProperty(page, "on", onDescriptor);
            else
                Reflect.deleteProperty(page, "on");
            if (offDescriptor)
                Object.defineProperty(page, "off", offDescriptor);
            else
                Reflect.deleteProperty(page, "off");
            if (onceDescriptor)
                Object.defineProperty(page, "once", onceDescriptor);
            else
                Reflect.deleteProperty(page, "once");
            if (emitDescriptor)
                Object.defineProperty(page, "emit", emitDescriptor);
            else
                Reflect.deleteProperty(page, "emit");
            if (removeAllDescriptor)
                Object.defineProperty(page, "removeAllListeners", removeAllDescriptor);
            else
                Reflect.deleteProperty(page, "removeAllListeners");
            if (interceptionDescriptor)
                Object.defineProperty(page, "setRequestInterception", interceptionDescriptor);
            else
                Reflect.deleteProperty(page, "setRequestInterception");
            for (const [type, owned] of handlers) {
                for (const handler of owned)
                    Reflect.apply(off, page, [type, listenerFor(handler)]);
            }
            handlers.clear();
        },
        async restoreInterception() {
            if (!interceptionChanged)
                return;
            try {
                await withTimeout(restoreInterception(), REQUEST_INTERCEPTION_CLEANUP_TIMEOUT_MS, "Timed out restoring browser request interception");
            }
            catch (error) {
                throw new RequestInterceptionCleanupError("Failed to restore browser request interception after browser.run", {
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        },
    };
}
function errorPayload(error) {
    const recoverTab = error instanceof RequestInterceptionCleanupError || undefined;
    const navigationTimeout = error instanceof NavigationTimeoutError || undefined;
    const rendererCrashed = error instanceof RendererCrashedError || undefined;
    const debuggerDetached = error instanceof DebuggerDetachedError ? { when: error.when, reason: error.reason } : undefined;
    if (error instanceof ToolAbortError) {
        return { name: error.name, message: error.message, stack: error.stack, isToolError: false, isAbort: true };
    }
    if (error instanceof ToolError) {
        return {
            name: error.name,
            message: error.message,
            stack: error.stack,
            isToolError: true,
            isAbort: false,
            recoverTab,
            navigationTimeout,
            rendererCrashed,
            debuggerDetached,
        };
    }
    if (error instanceof Error) {
        return { name: error.name, message: error.message, stack: error.stack, isToolError: false, isAbort: false };
    }
    return { name: "Error", message: String(error), isToolError: false, isAbort: false };
}
function replyError(payload) {
    if (payload.isAbort) {
        const err = new ToolAbortError(payload.message || "Tool call aborted");
        if (payload.stack)
            err.stack = payload.stack;
        return err;
    }
    const Ctor = payload.isToolError ? ToolError : Error;
    const err = new Ctor(payload.message);
    if (payload.name)
        err.name = payload.name;
    if (payload.stack)
        err.stack = payload.stack;
    return err;
}
function privateTargetId(target) {
    const raw = target;
    return typeof raw._targetId === "string" ? raw._targetId : undefined;
}
async function targetIdForTarget(target) {
    const fastTargetId = privateTargetId(target);
    if (fastTargetId)
        return fastTargetId;
    const session = await target.createCDPSession();
    try {
        const info = (await session.send("Target.getTargetInfo"));
        if (info.targetInfo?.targetId)
            return info.targetInfo.targetId;
        throw new ToolError("Target id unavailable from CDP target info");
    }
    finally {
        await session.detach().catch(() => undefined);
    }
}
async function targetIdForPage(page) {
    return await targetIdForTarget(page.target());
}
async function createTrackedHeadlessPage(browser, reportTarget) {
    const session = await browser.target().createCDPSession();
    let targetId;
    try {
        ({ targetId } = await session.send("Target.createTarget", { url: "about:blank" }));
        reportTarget(targetId);
    }
    finally {
        await session.detach().catch(() => undefined);
    }
    const existing = browser.targets().find(target => privateTargetId(target) === targetId);
    const target = existing ??
        (await browser.waitForTarget(candidate => privateTargetId(candidate) === targetId, {
            timeout: BROWSER_PROTOCOL_TIMEOUT_MS,
        }));
    const page = await target.page();
    if (!page)
        throw new ToolError(`Created headless target ${targetId} did not expose a page`);
    return page;
}
/**
 * Frames that missed an observation deadline, mapped to the document they showed then. Observe skips
 * them until they navigate, so a frame stuck in script costs only the first observation its wait.
 */
const unresponsiveFrames = new WeakMap();
function frameDocumentKey(frame) {
    return `${frame._loaderId} ${frame.url()}`;
}
/**
 * Accessibility snapshots of `frames` and their descendants, each with its frame, in frame-tree
 * order. A frame that does not answer by `deadline` is left out with its descendants, and skipped
 * by later observations until it navigates, so one dead iframe never costs the page its
 * observation. With `root`, only frames inside it are read.
 */
async function snapshotFrames(frames, options) {
    const snapshots = await Promise.all(frames.map(async (frame) => {
        if (unresponsiveFrames.get(frame) === frameDocumentKey(frame))
            return [];
        const timeout = new Error(`Frame ${frame.url()} did not answer`);
        let snapshot;
        try {
            snapshot = await withTimeout(snapshotFrame(frame, options), Math.max(0, options.deadline - Date.now()), timeout, options.signal);
        }
        catch (error) {
            if (options.signal?.aborted)
                throw error;
            if (error === timeout)
                unresponsiveFrames.set(frame, frameDocumentKey(frame));
            return [];
        }
        if (!snapshot)
            return [];
        return [{ frame, snapshot }, ...(await snapshotFrames(frame.childFrames(), { ...options, root: null }))];
    }));
    return snapshots.flat();
}
async function snapshotFrame(frame, options) {
    if (options.root) {
        const owner = await frame.frameElement();
        if (!owner)
            return null;
        const scoped = await options.root.realm.adoptHandle(owner).finally(() => owner.dispose().catch(() => undefined));
        try {
            // The owner may sit in a web component's shadow root under `root`, where `Node.contains` stops.
            if (!(await options.root.evaluate(composedContains, scoped)))
                return null;
        }
        finally {
            await scoped.dispose().catch(() => undefined);
        }
    }
    return await frame.accessibility.snapshot({ interestingOnly: options.interestingOnly });
}
function collectInteractiveObservationAncestors(node, ancestors) {
    let found = false;
    for (const child of node.children ?? []) {
        const descendantInteractive = collectInteractiveObservationAncestors(child, ancestors);
        if (isInteractiveNode(child) || descendantInteractive)
            found = true;
    }
    if (found)
        ancestors.add(node);
    return found;
}
/** Whether the frame has loaded another document since `element` was observed. */
function isObservedDocumentGone(element) {
    return element.frame._loaderId !== element.loaderId;
}
/**
 * Resolve an observed element to a handle in its frame's main world, or null when the node is
 * gone, has left the document, or the frame no longer shows the document it was observed in (any
 * resolution failure counts as gone). Text nodes resolve to their parent.
 */
async function resolveObservedElement(observed) {
    if (isObservedDocumentGone(observed))
        return null;
    let node;
    try {
        node = await observed.frame.mainRealm().adoptBackendNode(observed.backendNodeId);
    }
    catch {
        return null;
    }
    try {
        const resolved = await node.evaluateHandle(value => {
            const candidate = value;
            const element = (candidate.nodeType === 3 ? candidate.parentElement : value);
            if (!element?.isConnected)
                return null;
            // The document itself (the root `includeAll` lists) has no owner document.
            const owner = candidate.nodeType === 9 ? value : element.ownerDocument;
            return owner === document ? element : null;
        });
        const element = resolved.asElement();
        // The frame may have committed another document while the node resolved.
        if (element && !isObservedDocumentGone(observed))
            return element;
        await resolved.dispose().catch(() => undefined);
        return null;
    }
    catch {
        return null;
    }
    finally {
        await node.dispose().catch(() => undefined);
    }
}
async function collectObservationEntries(core, frame, node, entries, options) {
    const emptyStructural = (node.role === "generic" || node.role === "none" || node.role === "group") &&
        !node.name &&
        !options.interactiveAncestors.has(node);
    if (node.backendNodeId !== undefined &&
        (options.includeAll || isInteractiveNode(node)) &&
        !(options.compact && emptyStructural)) {
        const observed = { frame, backendNodeId: node.backendNodeId, loaderId: node.loaderId };
        let handle = null;
        let inViewport = true;
        if (options.viewportOnly) {
            handle = await resolveObservedElement(observed);
            inViewport = (await handle?.isIntersectingViewport().catch(() => false)) ?? false;
        }
        if (inViewport) {
            const id = core.observeElement(observed, handle ?? undefined);
            const states = [];
            if (node.disabled)
                states.push("disabled");
            if (node.checked !== undefined)
                states.push(`checked=${String(node.checked)}`);
            if (node.pressed !== undefined)
                states.push(`pressed=${String(node.pressed)}`);
            if (node.selected !== undefined)
                states.push(`selected=${String(node.selected)}`);
            if (node.expanded !== undefined)
                states.push(`expanded=${String(node.expanded)}`);
            if (node.required)
                states.push("required");
            if (node.readonly)
                states.push("readonly");
            if (node.multiselectable)
                states.push("multiselectable");
            if (node.multiline)
                states.push("multiline");
            if (node.modal)
                states.push("modal");
            if (node.focused)
                states.push("focused");
            entries.push({
                id,
                role: node.role,
                name: node.name,
                value: node.value,
                description: node.description,
                keyshortcuts: node.keyshortcuts,
                states,
            });
        }
        else {
            await handle?.dispose().catch(() => undefined);
        }
    }
    for (const child of node.children ?? []) {
        await collectObservationEntries(core, frame, child, entries, options);
    }
}
/**
 * Hint appended to a selector op's fail-fast timeout, given the selector's current
 * match count: a missing element (consent wall, wrong page) reads differently from
 * a present-but-unactionable one.
 */
export function formatSelectorMatchHint(count) {
    return count === 0
        ? "; selector currently matches no elements — run tab.observe() or tab.ariaSnapshot() to inspect the page"
        : `; selector currently matches ${count} element(s) but the action never became possible — the element may be hidden or covered (try tab.scrollIntoView() or a more specific selector)`;
}
/** Human-readable label for a screenshot op, used in op tracking + timeout errors. */
export function describeScreenshot(opts) {
    if (opts?.selector)
        return `tab.screenshot({ selector: ${JSON.stringify(opts.selector)} })`;
    if (opts?.fullPage)
        return "tab.screenshot({ fullPage: true })";
    return "tab.screenshot()";
}
export async function preparePageForScreenshot(page, signal, activate) {
    if (activate) {
        await untilAborted(signal, () => page.bringToFront()).catch(() => undefined);
        return;
    }
    const visible = await untilAborted(signal, () => page.evaluate(() => document.visibilityState === "visible")).catch(() => false);
    if (!visible) {
        throw new ToolError("The attached browser tab is not visible; switch to it before taking a screenshot");
    }
}
/** Summarize still-running helpers (oldest first) so a cell timeout names what stalled. */
export function describeInflight(inflight) {
    const now = Date.now();
    return [...inflight.values()]
        .sort((a, b) => a.startedAt - b.startedAt)
        .map(op => `${op.label} (${((now - op.startedAt) / 1000).toFixed(1)}s)`)
        .join(", ");
}
export class WorkerCore {
    #transport;
    #browser;
    #page;
    #targetId;
    /** Last viewport read from the page; reported while a dialog or failure blocks a fresh read. */
    #lastViewport;
    #elementCache = new Map();
    #observedElements = new Map();
    #elementCounter = 0;
    #active = null;
    #runtime = null;
    #unsub;
    #isolated;
    #uninstallRejectionGuard;
    #mode;
    #activateForScreenshot = true;
    /** The upload route this worker's browser connection takes, and the tab's staging folder. */
    #uploads;
    #dialogs;
    #network;
    #initScripts;
    #downloads;
    #consoleCapture = new PageConsoleCapture();
    #tracing;
    #ariaSnapshotBaselines = new Map();
    #emulation;
    #screenshotHistory = new Map();
    #webmcp;
    #recording = new RecordingController();
    /**
     * A back/forward cache restore brings a document back without loading it, so the frame keeps the
     * loader id of the document it replaced and the ids observed there would still pass as current.
     */
    #onFrameNavigated = (event) => {
        if (event.type === "BackForwardCacheRestore")
            this.#clearElementCache();
    };
    /** The renderer crashed; the supervisor recycles this worker, so it runs nothing more. */
    #crashed = false;
    /** `ready` was sent; a crash before it fails the start instead. */
    #started = false;
    /** The run whose result is not sent yet; it outlives `#active` while the result is being put together. */
    #unanswered = null;
    /**
     * Puppeteer's page `error` event is Chromium's `Inspector.targetCrashed`: the renderer is gone and every
     * later page call stalls. The unanswered run is answered now rather than after steps that wait on the
     * dead page, and cancelled so its code does not go on after its caller was told it failed.
     */
    #onPageCrashed = () => {
        if (this.#crashed)
            return;
        this.#crashed = true;
        if (!this.#started) {
            const error = new RendererCrashedError("Browser tab's renderer crashed while the tab was starting");
            this.#transport.send({ type: "init-failed", error: errorPayload(error) });
            return;
        }
        const run = this.#unanswered;
        if (!run)
            return;
        this.#unanswered = null;
        run.ac.abort(postmortem.markExpectedCleanupError(new ToolAbortError("Browser tab's renderer crashed")));
        const error = new RendererCrashedError("Browser tab's renderer crashed during this run");
        this.#transport.send({ type: "result", id: run.id, ok: false, error: errorPayload(error) });
    };
    /**
     * The reason Chrome gave for ending the relay's debugger attachment on this tab (another extension's frame
     * loaded in it, or the user cancelled the debugging bar); `undefined` while attached. Every later page call
     * fails or stalls, so this worker runs nothing more and the supervisor re-adopts the tab on a new one.
     */
    #debuggerDetached;
    /** The omp browser relay's `OMP.debuggerDetached` event, sent to the page's sessions ahead of their detach. */
    #onDebuggerDetached = (params) => {
        if (this.#debuggerDetached !== undefined)
            return;
        const reason = isRecord(params) && typeof params.reason === "string" ? params.reason : "no reason given";
        this.#debuggerDetached = reason;
        const run = this.#started ? this.#unanswered : null;
        if (!run)
            return;
        this.#unanswered = null;
        run.ac.abort(postmortem.markExpectedCleanupError(new ToolAbortError("Chrome detached omp from this tab")));
        const error = new DebuggerDetachedError(reason, run.codeStarted ? "during" : "before");
        this.#transport.send({ type: "result", id: run.id, ok: false, error: errorPayload(error) });
    };
    constructor(transport, isolated) {
        this.#transport = transport;
        this.#isolated = isolated;
        this.#unsub = this.#transport.onMessage(msg => {
            void this.#handleMessage(msg);
        });
        this.#uninstallRejectionGuard = this.#installRejectionGuard();
    }
    #installRejectionGuard() {
        if (!this.#isolated) {
            return postmortem.interceptUnhandledRejections(reason => this.#consumeUnhandledRejection(reason));
        }
        return installBrowserWorkerRejectionGuard(reason => this.#consumeUnhandledRejection(reason));
    }
    #consumeUnhandledRejection(reason) {
        const active = this.#active;
        if (!active)
            return false;
        if (!isBrowserRunOwnedRejection(reason, active.rejectionOwner, `browser-run-${active.id}.js`))
            return false;
        this.#recordFloatingRejection(active, reason);
        return true;
    }
    #recordFloatingRejection(active, reason) {
        if (postmortem.isExpectedCleanupError(reason))
            return;
        if (this.#active !== active) {
            this.#log("warn", "Unhandled rejection after browser run ended", {
                runId: active.id,
                error: reason instanceof Error ? reason.message : String(reason),
            });
            return;
        }
        const isFirst = active.floatingRejections.length === 0;
        active.floatingRejections.push(reason);
        if (isFirst)
            active.floatingFailure.reject(this.#floatingRejectionError(reason));
    }
    #floatingRejectionError(reason) {
        const message = reason instanceof Error ? reason.message : String(reason);
        const error = new Error(`Unhandled rejection (missing await?): ${message}`, { cause: reason });
        if (reason instanceof Error)
            error.name = reason.name;
        return error;
    }
    #foldFloatingRejections(active, failure) {
        const rejections = active.floatingRejections;
        if (rejections.length === 0)
            return failure;
        let reported = rejections;
        if (!failure) {
            failure = { error: this.#floatingRejectionError(rejections[0]) };
            reported = rejections.slice(1);
        }
        else if (failure.error instanceof Error && failure.error.cause === rejections[0]) {
            reported = rejections.slice(1);
        }
        for (const reason of reported) {
            this.#log("warn", "Additional unhandled browser-run rejection", {
                error: reason instanceof Error ? reason.message : String(reason),
            });
        }
        return failure;
    }
    /** Number an observed element; keeps `handle` when the observation already resolved it. */
    observeElement(element, handle) {
        this.#elementCounter += 1;
        this.#observedElements.set(this.#elementCounter, element);
        if (handle)
            this.#elementCache.set(this.#elementCounter, handle);
        return this.#elementCounter;
    }
    async #handleMessage(msg) {
        switch (msg.type) {
            case "init":
                await this.#init(msg.payload);
                return;
            case "run":
                await this.#run(msg);
                return;
            case "abort":
                if (this.#active?.id === msg.id) {
                    const reason = msg.expectedCleanup
                        ? postmortem.markExpectedCleanupError(new ToolAbortError())
                        : new ToolAbortError();
                    this.#active.ac.abort(reason);
                }
                return;
            case "tool-reply":
                this.#deliverToolReply(msg.id, msg.reply);
                return;
            case "close":
                await this.#close();
                return;
        }
    }
    async #init(payload) {
        try {
            this.#mode = payload.mode;
            this.#activateForScreenshot = payload.mode === "headless" || payload.activateForScreenshot !== false;
            this.#uploads = new UploadStaging(payload.uploadDir);
            const puppeteer = await loadPuppeteerInWorker(payload.safeDir);
            registerSemanticQueryHandlers(puppeteer);
            this.#browser = await connectPuppeteer(puppeteer, {
                browserWSEndpoint: payload.browserWSEndpoint,
                defaultViewport: null,
                protocolTimeout: BROWSER_PROTOCOL_TIMEOUT_MS,
            });
            // Realm setup is done: puppeteer loaded and browser connected. Sent before
            // page acquisition so the supervisor's cold-start budget bounds only the
            // realm setup; page creation runs under the ready wait.
            this.#transport.send({ type: "setup" });
            if (payload.mode === "headless") {
                // Create the target directly so its id is reportable before
                // Puppeteer waits for target/page initialization. If that wait
                // wedges, the supervisor can still close the created target.
                this.#page = await createTrackedHeadlessPage(this.#browser, targetId => {
                    this.#transport.send({ type: "page-created", targetId });
                });
                this.#observeDialogs();
                await applyStealthPatches(this.#browser, this.#page, { browserSession: null, override: null });
                if (payload.emulateViewport !== false)
                    await applyViewport(this.#page, payload.viewport);
                if (payload.dialogs)
                    this.#applyDialogPolicy(payload.dialogs);
            }
            else {
                const target = await this.#findAttachedTarget(payload.targetId);
                // Post-timeout recycle: unblock the target BEFORE adopting the page — an open
                // modal dialog or hung navigation can stall `target.page()` / ready info, and a
                // stalled init used to time out and force-kill the tab.
                if (payload.recover)
                    await this.#recoverAttachedTarget(target);
                const page = await target.page();
                if (!page)
                    throw new ToolError(`Target ${payload.targetId} is no longer available on the attached browser`);
                this.#page = page;
                await this.#claimRelayTarget(page);
                this.#observeDialogs();
                if (payload.dialogs)
                    this.#applyDialogPolicy(payload.dialogs);
            }
            this.#page.mainFrame().client.on("Page.frameNavigated", this.#onFrameNavigated);
            this.#page.mainFrame().client.on("OMP.debuggerDetached", this.#onDebuggerDetached);
            this.#page.on("error", this.#onPageCrashed);
            if (payload.mode === "headless" || payload.emulateFocus) {
                // Background Chromium tabs stop producing frames, stalling rAF,
                // IntersectionObserver, and input acknowledgements. Keep owned tabs
                // interactive without raising a window; explicit settle-freeze still applies.
                await this.#page.emulateFocusedPage(true);
            }
            this.#webmcp = await installWebMcp(this.#page);
            await installVitalsObservers(this.#page);
            if (payload.userAgent !== undefined)
                await applyUserAgentOverride(this.#page, payload.userAgent);
            if (payload.ignoreHttpsErrors)
                await applyIgnoreHttpsErrors(this.#page);
            this.#targetId = await targetIdForPage(this.#page);
            this.#initScripts = new InitScriptManager(this.#page);
            for (const source of payload.initScripts ?? [])
                await this.#initScripts.add(source);
            this.#downloads = new DownloadManager(this.#browser, this.#page, this.#targetId, {
                perTab: payload.mode === "headless" || payload.userDriven !== true,
            });
            if (payload.downloadsPath)
                await this.#downloads.enable(payload.downloadsPath);
            const baseUserAgent = await this.#page.evaluate(() => navigator.userAgent);
            this.#emulation = new BrowserEmulationController(this.#page, loadedKnownDevices(), loadedNetworkConditions(), baseUserAgent);
            await this.#consoleCapture.install(this.#page);
            this.#tracing = new BrowserTracingController(this.#page);
            this.#network = new BrowserNetworkManager(this.#page, payload.allowedDomains);
            await this.#network.start();
            const info = await this.#currentReadyInfo();
            this.#started = true;
            this.#transport.send({ type: "ready", info });
        }
        catch (error) {
            // A failed headless init leaves the worker's page orphaned in the shared
            // browser (the supervisor retries with a fresh worker), so close it before
            // reporting. Attach mode adopts an existing target — never close it.
            const page = this.#page;
            await this.#webmcp?.dispose().catch(() => undefined);
            this.#webmcp = undefined;
            if (payload.mode === "headless" && page && !page.isClosed()) {
                await page.close().catch(() => undefined);
            }
            this.#transport.send({ type: "init-failed", error: errorPayload(error) });
        }
    }
    async #findAttachedTarget(targetId) {
        if (!this.#browser)
            throw new ToolError("Browser is not connected");
        for (const target of this.#browser.targets()) {
            if ((await targetIdForTarget(target).catch(() => "")) !== targetId)
                continue;
            return target;
        }
        // Puppeteer lists a page only once its URL is non-empty, and a crashed page revived by this attach reloads
        // with an empty URL for a moment. Wait for it while Chromium still has the target; fail at once when not.
        if (await this.#browserHasTarget(this.#browser, targetId)) {
            const target = await this.#browser
                .waitForTarget(async (candidate) => (await targetIdForTarget(candidate).catch(() => "")) === targetId, {
                timeout: ATTACHED_TARGET_EXPOSE_TIMEOUT_MS,
            })
                .catch(() => undefined);
            if (target)
                return target;
        }
        throw new ToolError(`Target ${targetId} is no longer available on the attached browser`);
    }
    async #browserHasTarget(browser, targetId) {
        let session;
        try {
            session = await browser.target().createCDPSession();
            await session.send("Target.getTargetInfo", { targetId });
            return true;
        }
        catch {
            return false;
        }
        finally {
            await session?.detach().catch(() => undefined);
        }
    }
    /**
     * Tell the omp browser relay this worker drives the adopted page, so the
     * relay adds it to the per-window "omp" tab group. Best-effort: plain CDP
     * backends (real Chrome, cmux) reject the relay-private method.
     */
    async #claimRelayTarget(page) {
        let session;
        try {
            session = await page.createCDPSession();
            // Puppeteer's protocol map cannot express the relay-private method; the
            // send signature is otherwise identical.
            const raw = session;
            await raw.send("OMP.claimTarget");
        }
        catch {
            // Not the omp relay; nothing to claim.
        }
        finally {
            await session?.detach().catch(() => undefined);
        }
    }
    /**
     * Best-effort unblocking of a wedged target during post-timeout recovery: dismiss any
     * open JS dialog and stop a pending navigation over a raw CDP session (created on the
     * target, not the page, so it works while the page itself is unresponsive). Every step
     * tolerates "nothing to do".
     */
    async #recoverAttachedTarget(target) {
        let session;
        try {
            session = await target.createCDPSession();
            // A crashed page answers none of the steps below. `Inspector.enable` reports a renderer
            // still dead (a relay attach leaves it so), the listener one that dies again as it reloads.
            session.on("Inspector.targetCrashed", this.#onPageCrashed);
            await session.send("Inspector.enable").catch(() => undefined);
            await session.send("Page.enable").catch(() => undefined);
            await session.send("Page.handleJavaScriptDialog", { accept: false }).catch(() => undefined);
            await session.send("Page.stopLoading").catch(() => undefined);
            await session.send("Fetch.disable").catch(() => undefined);
        }
        catch (error) {
            this.#log("debug", "Recovery CDP session failed; proceeding with attach", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
        finally {
            await session?.detach().catch(() => undefined);
        }
    }
    /** Install runtime dialog observation and default handling. */
    #observeDialogs() {
        const page = this.#requirePage();
        this.#dialogs?.dispose();
        this.#dialogs = new RuntimeDialogController(page, (message, details) => this.#log("debug", message, details));
        this.#dialogs.observe();
    }
    async #currentReadyInfo() {
        const page = this.#requirePage();
        const targetId = this.#targetId ?? (await targetIdForPage(page));
        this.#targetId = targetId;
        const dialogPending = this.#dialogs?.state().open ?? false;
        return {
            url: redactUrlCredentials(page.url()),
            title: dialogPending ? undefined : await page.title().catch(() => undefined),
            viewport: dialogPending
                ? (page.viewport() ?? this.#lastViewport ?? DEFAULT_VIEWPORT)
                : await this.#viewport().catch(() => this.#lastViewport ?? DEFAULT_VIEWPORT),
            targetId,
        };
    }
    async #viewport(signal) {
        this.#lastViewport = await readPageViewport(this.#requirePage(), signal);
        return this.#lastViewport;
    }
    /** Apply an automatic dialog policy selected while opening the tab. */
    #applyDialogPolicy(policy) {
        void this.#requireDialogs()
            .setPolicy(policy)
            .catch(error => this.#log("debug", "Dialog auto-handler failed", {
            policy,
            error: error instanceof Error ? error.message : String(error),
        }));
    }
    async #postReadyInfo() {
        try {
            this.#transport.send({ type: "ready", info: await this.#currentReadyInfo() });
        }
        catch (error) {
            this.#log("debug", "Failed to refresh tab info", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    async #run(msg) {
        if (this.#crashed) {
            const error = new RendererCrashedError("Browser tab's renderer had crashed before this run, so its code did not run");
            this.#transport.send({ type: "result", id: msg.id, ok: false, error: errorPayload(error) });
            return;
        }
        if (this.#debuggerDetached !== undefined) {
            const error = new DebuggerDetachedError(this.#debuggerDetached, "before");
            this.#transport.send({ type: "result", id: msg.id, ok: false, error: errorPayload(error) });
            return;
        }
        if (this.#active) {
            this.#transport.send({
                type: "result",
                id: msg.id,
                ok: false,
                error: errorPayload(new ToolError("Tab worker is busy")),
            });
            return;
        }
        const timeoutSignal = AbortSignal.timeout(msg.timeoutMs);
        const ac = new AbortController();
        const runAc = new AbortController();
        const signal = AbortSignal.any([timeoutSignal, ac.signal, runAc.signal]);
        const output = new RunOutput();
        const screenshots = [];
        const runErrorStartSeq = this.#consoleCapture.nextSequence;
        const floatingFailure = Promise.withResolvers();
        const active = {
            id: msg.id,
            ac,
            signal,
            output,
            screenshots,
            pendingTools: new Map(),
            rejectionOwner: {},
            floatingRejections: [],
            floatingFailure,
            inflight: new Map(),
            opCounter: 0,
            codeStarted: false,
        };
        this.#active = active;
        this.#unanswered = active;
        let completed = false;
        let returnValue;
        let failure;
        let recoverTab = false;
        let runPage;
        try {
            throwIfAborted(signal);
            await untilAborted(signal, () => this.#emulation?.reapply() ?? Promise.resolve());
            runPage = createRunPageScope(this.#requirePage(), () => this.#requireNetwork().restoreInterception());
            const browser = this.#requireBrowser();
            const tabApi = this.#createTabApi(msg.name, msg.timeoutMs, signal, msg.session, output, screenshots, active);
            const runtime = this.#ensureRuntime(msg.session);
            runtime.setCwd(msg.session.cwd);
            const onFloatingRejection = (reason) => this.#recordFloatingRejection(active, reason);
            runtime.setRunScope({
                page: bindRunFacade(runPage.page, signal, active.rejectionOwner, onFloatingRejection),
                browser: bindRunFacade(browser, signal, active.rejectionOwner, onFloatingRejection),
                tab: bindRunFacade(tabApi, signal, active.rejectionOwner, onFloatingRejection),
                assert: (cond, text) => {
                    if (!cond)
                        throw new ToolError(text ?? "Assertion failed");
                },
                // Both wait forms register in the in-flight map so a cell that dies while
                // sleeping/polling names the culprit instead of a bare whole-cell timeout.
                wait: (msOrPredicate, opts) => {
                    const label = typeof msOrPredicate === "number" ? `wait(${msOrPredicate}ms)` : "wait(predicate)";
                    const resolved = typeof msOrPredicate === "number"
                        ? undefined
                        : { timeout: resolvePredicateTimeout(msg.timeoutMs, opts?.timeout), interval: opts?.interval };
                    return observeBrowserRunPromise(this.#runOp(active, label, signal, Number.POSITIVE_INFINITY, sig => waitForRun(msOrPredicate, sig, resolved)), active.rejectionOwner, onFloatingRejection);
                },
            });
            const { promise: cancelRejection, reject: rejectCancel } = Promise.withResolvers();
            const onCancel = () => {
                const abortError = signal.reason instanceof ToolAbortError
                    ? signal.reason
                    : new ToolAbortError(undefined, { cause: signal.reason });
                if (timeoutSignal.aborted) {
                    const stalled = describeInflight(active.inflight);
                    const dialog = this.#dialogs?.state();
                    const dialogNote = dialog?.open
                        ? `; a ${dialog.type}(${JSON.stringify(dialog.message?.slice(0, 80) ?? "")}) dialog opened during this run and may still block the page — use tab.handleDialog() or tab.setDialogs("accept"|"dismiss")`
                        : "";
                    const pageErrorCount = this.#consoleCapture.errorCountSince(runErrorStartSeq);
                    const pageErrorNote = pageErrorCount > 0 ? `; ${pageErrorCount} page error(s) since run start — see tab.errors()` : "";
                    rejectCancel(new ToolError(`Browser code execution timed out after ${msg.timeoutMs}ms${stalled ? ` (stalled on ${stalled})` : ""}${dialogNote}${pageErrorNote}`));
                }
                else {
                    rejectCancel(abortError);
                }
                // Cancel in-flight tool calls so user code's awaited proxies reject promptly.
                const toolAbort = timeoutSignal.aborted
                    ? postmortem.markExpectedCleanupError(new ToolAbortError(undefined, { cause: timeoutSignal.reason }))
                    : abortError;
                for (const pending of active.pendingTools.values()) {
                    pending.reject(toolAbort);
                }
                active.pendingTools.clear();
            };
            if (signal.aborted)
                onCancel();
            else
                signal.addEventListener("abort", onCancel, { once: true });
            try {
                const hooks = this.#hooksForActiveRun();
                if (!hooks)
                    throw new ToolError("Browser runtime started without an active run");
                returnValue = await withBrowserPromiseCombinatorTracking(active.rejectionOwner, onFloatingRejection, async () => await Promise.race([
                    runtime.run(msg.code, `browser-run-${msg.id}.js`, hooks, {
                        runId: msg.id,
                        cwd: msg.session.cwd,
                    }),
                    cancelRejection,
                    floatingFailure.promise,
                ]));
                completed = true;
            }
            finally {
                signal.removeEventListener("abort", onCancel);
            }
        }
        catch (error) {
            failure = { error };
        }
        finally {
            runAc.abort(postmortem.markExpectedCleanupError(new ToolAbortError("Browser run ended")));
            await Bun.sleep(0);
            // Detach first: the stop below fails the cancelled requests, and run handlers that see
            // those events would touch the aborted run's facade.
            runPage?.detach();
            // A cancelled run abandons its main-frame navigation: left loading, it still replaces the
            // page later and holds up any interception restore below. Stopping is gated on
            // that navigation because Page.stopLoading also cancels every fetch and subresource
            // load in flight. A run that merely ended keeps an unawaited goto going.
            if (ac.signal.aborted && this.#network?.hasPendingMainFrameNavigation())
                await this.#stopLoading();
            try {
                await runPage?.restoreInterception();
            }
            catch (error) {
                // A finished run keeps its result; the supervisor still recycles the tab.
                if (completed && active.floatingRejections.length === 0) {
                    recoverTab = true;
                    this.#log("warn", "Browser tab state could not be restored after a completed run", {
                        error: error instanceof Error ? error.message : String(error),
                    });
                }
                else {
                    failure = { error };
                }
            }
            failure = this.#foldFloatingRejections(active, failure);
            if (this.#active?.id === msg.id)
                this.#active = null;
        }
        // A renderer crash or a debugger detach answers the run itself.
        if (this.#unanswered !== active)
            return;
        if (failure) {
            this.#unanswered = null;
            this.#transport.send({ type: "result", id: msg.id, ok: false, error: errorPayload(failure.error) });
            return;
        }
        if (completed) {
            await this.#postReadyInfo();
            if (this.#unanswered !== active)
                return;
            this.#unanswered = null;
            this.#transport.send({
                type: "result",
                id: msg.id,
                ok: true,
                payload: {
                    displays: output.finish(),
                    returnValue: cloneSafe(returnValue),
                    screenshots,
                    recoverTab: recoverTab || undefined,
                },
            });
        }
    }
    #ensureRuntime(session) {
        if (this.#runtime)
            return this.#runtime;
        this.#runtime = new JsRuntime({
            initialCwd: session.cwd,
            sessionId: `browser-tab-${this.#targetId ?? "unknown"}`,
        });
        return this.#runtime;
    }
    #hooksForActiveRun() {
        const active = this.#active;
        if (!active)
            return null;
        return {
            onText: chunk => {
                throwIfAborted(active.signal);
                active.output.pushText(chunk);
                this.#log("debug", chunk.replace(/\n$/, ""));
            },
            onDisplay: output => {
                throwIfAborted(active.signal);
                active.output.pushDisplay(output);
            },
            callTool: (name, args) => {
                throwIfAborted(active.signal);
                return this.#callTool(active, name, args);
            },
            // Compiling the cell can wait (the first run loads Babel); a detach (or any abort) then still ran nothing,
            // and the cell must not run late either.
            onEvaluate: () => {
                throwIfAborted(active.signal);
                active.codeStarted = true;
            },
        };
    }
    async #callTool(active, name, args) {
        const id = `tab-tc-${active.id}-${crypto.randomUUID()}`;
        const { promise, resolve, reject } = Promise.withResolvers();
        active.pendingTools.set(id, { resolve, reject });
        this.#transport.send({ type: "tool-call", id, runId: active.id, name, args });
        return await promise;
    }
    #deliverToolReply(id, reply) {
        const active = this.#active;
        if (!active)
            return;
        const pending = active.pendingTools.get(id);
        if (!pending)
            return;
        active.pendingTools.delete(id);
        if (reply.ok)
            pending.resolve(reply.value);
        else
            pending.reject(replyError(reply.error));
    }
    /**
     * Wrap a tab helper so it (a) registers in the active run's in-flight map for
     * timeout diagnostics and (b) honors an optional per-op deadline that fails fast
     * with a named error instead of silently consuming the whole cell budget. Pass
     * `Number.POSITIVE_INFINITY` for `perOpTimeoutMs` to bound the op only by the cell
     * budget (used for `evaluate` running user code and for locator helpers that already
     * carry puppeteer's own `.setTimeout(timeoutMs)`). When the op targets a `selector`,
     * the fail-fast timeout carries a best-effort match-count hint, and — when
     * `zeroMatchAfterMs` is set — a watchdog aborts the op early once the selector has
     * matched nothing for that long.
     */
    async #runOp(active, label, cellSignal, perOpTimeoutMs, fn, opts) {
        const opId = active.opCounter++;
        active.inflight.set(opId, { label, startedAt: Date.now() });
        const capped = Number.isFinite(perOpTimeoutMs) && perOpTimeoutMs > 0;
        const opTimeout = capped ? AbortSignal.timeout(perOpTimeoutMs) : undefined;
        const opSignal = opTimeout ? AbortSignal.any([cellSignal, opTimeout]) : cellSignal;
        const selector = opts?.selector;
        const watchdog = selector !== undefined && opts?.zeroMatchAfterMs !== undefined && parseAriaRefSelector(selector) === null
            ? { selector, afterMs: opts.zeroMatchAfterMs }
            : undefined;
        // Fired when the watchdog wins the race (tears down the in-flight action) and in
        // the finally (stops the watchdog's polling once the op settles either way).
        const earlyAc = new AbortController();
        try {
            // A download this op starts before a pending `waitForDownload()` has enabled
            // tracking would bypass it, so hold the op until tracking applies — within
            // the op's own deadline, so a stalled enable surfaces as this op's timeout.
            const arming = this.#downloads?.arming;
            if (arming)
                await untilAborted(opSignal, arming.catch(() => undefined));
            if (!watchdog)
                return await fn(opSignal);
            const racedSignal = AbortSignal.any([opSignal, earlyAc.signal]);
            return await Promise.race([
                fn(racedSignal),
                this.#zeroMatchWatchdog(watchdog.selector, label, watchdog.afterMs, racedSignal),
            ]);
        }
        catch (err) {
            // Fail fast with a named, attributable error instead of the opaque whole-cell timeout:
            // our per-op deadline fired, or puppeteer's own (equal) timeout fired first — having
            // already torn down the CDP action via the op signal, so no work is left dangling.
            // Cell-budget aborts and uncapped helpers (goto/evaluate) keep their native errors.
            if (capped &&
                !cellSignal.aborted &&
                (opTimeout?.aborted || (err instanceof Error && err.name === "TimeoutError"))) {
                const refusal = err instanceof ClickRefusedError ? err.refusal : undefined;
                const count = selector ? await this.#selectorMatchCount(selector) : undefined;
                const hint = refusal
                    ? `; the element never became clickable (last check: ${refusal}${count === undefined ? "" : `; selector matches ${count} element(s)`})`
                    : count === undefined
                        ? ""
                        : formatSelectorMatchHint(count);
                throw markBrowserRunRejection(new ToolError(`${label} timed out after ${perOpTimeoutMs}ms${hint}`), active.rejectionOwner);
            }
            throw markBrowserRunRejection(err, active.rejectionOwner);
        }
        finally {
            earlyAc.abort();
            active.inflight.delete(opId);
        }
    }
    /**
     * Fail-fast arm raced against a selector op: rejects once the selector has matched
     * nothing for the whole `afterMs` window, so a wrong selector or wrong page (consent
     * wall, pre-navigation document) costs ~2s instead of the full action deadline.
     * Disarms — hangs until the settled race drops it — the moment at least one element
     * matches; an inconclusive probe (mid-navigation, detached frame) never counts
     * toward the zero-match window.
     */
    async #zeroMatchWatchdog(selector, label, afterMs, signal) {
        const page = this.#requirePage();
        const resolved = normalizeSelector(selector);
        const deadline = Date.now() + afterMs;
        while (!signal.aborted) {
            let count = null;
            try {
                const handles = await page.$$(resolved);
                count = handles.length;
                for (const handle of handles)
                    void handle.dispose().catch(() => undefined);
            }
            catch {
                // Inconclusive probe — keep polling without advancing toward failure.
            }
            if (count !== null && count > 0)
                break;
            if (count === 0 && Date.now() >= deadline) {
                throw new ToolError(`${label} failed fast after ${afterMs}ms${formatSelectorMatchHint(0)}`);
            }
            try {
                await untilAborted(signal, () => Bun.sleep(ZERO_MATCH_POLL_MS));
            }
            catch {
                break;
            }
        }
        return await new Promise(() => { });
    }
    /**
     * Best-effort match count for a timed-out selector op. Never throws;
     * undefined when the probe fails, stalls, or the selector is an aria-ref.
     */
    async #selectorMatchCount(selector) {
        if (parseAriaRefSelector(selector) !== null)
            return undefined;
        try {
            const handles = await Promise.race([
                this.#requirePage().$$(normalizeSelector(selector)),
                Bun.sleep(1000).then(() => null),
            ]);
            if (!handles)
                return undefined;
            for (const handle of handles)
                void handle.dispose().catch(() => undefined);
            return handles.length;
        }
        catch {
            return undefined;
        }
    }
    #createTabApi(name, timeoutMs, signal, session, output, screenshots, active) {
        const page = this.#requirePage();
        const webmcp = this.#webmcp;
        if (!webmcp)
            throw new ToolError("Tab worker WebMCP handling is not initialized");
        const { budgetBound, quickOpMs, actionOpMs } = resolveOpTimeouts(timeoutMs);
        const waitMs = (explicit) => resolveWaitTimeout(timeoutMs, explicit);
        const INF = Number.POSITIVE_INFINITY;
        const op = (label, perOpMs, fn, selectorOpts) => markHandled(this.#runOp(active, label, signal, perOpMs, fn, selectorOpts));
        // Hand user-facing handles the fail-fast per-op guard so their interactive
        // methods (`.click()`, `.type()`, …) can't outrun the cell budget (issue #9535).
        const enrich = (handle) => toActionableHandle(handle, (label, fn) => op(label, actionOpMs, fn), async () => {
            // Raw Puppeteer actions have no AbortSignal. Poison + dispose every
            // cached handle and stop navigation before reporting a recoverable timeout.
            this.#clearElementCache();
            await this.#stopLoading();
        }, {
            route: sig => this.#requireUploads().route(page, sig),
            prepare: (filePaths, label, route, sig) => prepareElementUpload(page, handle, filePaths.map(filePath => resolveToCwd(filePath, session.cwd)), label, route, this.#requireUploads(), sig),
            deliverGuard: (label, fn) => op(label, budgetBound, fn),
        });
        return {
            name,
            page,
            signal,
            url: () => page.url(),
            title: () => op("tab.title()", INF, sig => untilAborted(sig, () => page.title())),
            goto: (url, opts) => op(`tab.goto(${JSON.stringify(url)})`, INF, async (sig) => {
                this.#clearElementCache();
                try {
                    // Default to "load" because dev servers with HMR/WS never reach networkidle.
                    // budgetBound (not the full cell) so a hung navigation fails named and
                    // catchable inside the run instead of dying with the whole cell.
                    await navigateMainFrame(page, opts?.waitUntil ?? "load", budgetBound, sig, options => page.goto(url, options));
                }
                catch (err) {
                    if (err instanceof Error && err.name === "TimeoutError") {
                        // Abandon the hung navigation NOW — a still-pending load stalls every
                        // later op on this page and cascades into more opaque timeouts.
                        await this.#stopLoading();
                        throw new NavigationTimeoutError(`tab.goto(${JSON.stringify(url)}) timed out after ${budgetBound}ms; pending navigation stopped — retry with a longer tool timeout or waitUntil:"domcontentloaded"`);
                    }
                    throw err;
                }
            }),
            observe: opts => op("tab.observe()", quickOpMs, sig => this.#collectObservation({ ...opts, signal: sig })),
            ariaSnapshot: (selector, opts) => op(selector ? `tab.ariaSnapshot(${JSON.stringify(selector)})` : "tab.ariaSnapshot()", quickOpMs, async (sig) => {
                let root = null;
                if (selector) {
                    root = (await untilAborted(sig, () => page.$(normalizeSelector(selector))));
                    if (!root)
                        throw new ToolError(`tab.ariaSnapshot: selector ${JSON.stringify(selector)} matched no element`);
                }
                try {
                    const snapshot = await untilAborted(sig, () => captureAriaSnapshot(page, root, opts));
                    if (!opts?.diff)
                        return snapshot;
                    const key = ariaSnapshotBaselineKey(selector, opts);
                    return diffAriaSnapshot(this.#ariaSnapshotBaselines, key, page.url(), snapshot);
                }
                finally {
                    await root?.dispose().catch(() => undefined);
                }
            }),
            screenshot: opts => op(describeScreenshot(opts), quickOpMs, sig => this.#captureScreenshot(session, output, screenshots, sig, opts)),
            extract: (format = "markdown", opts) => op(`tab.extract(${JSON.stringify(format)})`, quickOpMs, async (sig) => {
                const html = (await untilAborted(sig, () => page.content()));
                const result = await extractReadableFromHtml(html, page.url(), format, opts);
                if (!result) {
                    throw new ToolError(`tab.extract(${JSON.stringify(format)}) found no readable content on ${page.url()}`);
                }
                const content = format === "markdown" ? result.markdown : result.text;
                if (!content) {
                    throw new ToolError(`tab.extract(${JSON.stringify(format)}) produced empty ${format} content for ${page.url()}`);
                }
                return content;
            }),
            click: selector => op(`tab.click(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const label = `tab.click(${JSON.stringify(selector)})`;
                const resolved = normalizeSelector(selector);
                if (resolved.startsWith("text/") && parseAriaRefSelector(selector) === null) {
                    await clickQueryHandlerText(page, resolved, label, actionOpMs, sig);
                    return;
                }
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await clickElement(handle, label, sig);
                }
                finally {
                    void handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            type: (selector, text) => op(`tab.type(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await focusTextEntryTarget(handle, "type into", sig);
                    await untilAborted(sig, () => handle.type(text, { delay: 0 }));
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            fill: (selector, value) => op(`tab.fill(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await fillViaHandle(handle, value, sig);
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            press: (key, opts) => op(`tab.press(${JSON.stringify(key)})`, actionOpMs, async (sig) => {
                assertTabPressArgs(key, opts);
                const selector = opts?.selector;
                if (selector) {
                    if (parseAriaRefSelector(selector) !== null) {
                        const handle = await this.#resolveAriaRef(selector);
                        try {
                            await untilAborted(sig, () => handle.focus());
                        }
                        finally {
                            await handle.dispose().catch(() => undefined);
                        }
                    }
                    else
                        await untilAborted(sig, () => page.focus(normalizeSelector(selector)));
                }
                await untilAborted(sig, () => pressKey(page, key));
            }),
            scroll: (deltaX, deltaY, opts) => op("tab.scroll()", actionOpMs, async (sig) => {
                if (!opts?.selector) {
                    await untilAborted(sig, () => dispatchScroll(() => page.mouse.wheel({ deltaX, deltaY })));
                    return;
                }
                const handle = await this.#resolveActionHandle(opts.selector, actionOpMs, sig);
                try {
                    await untilAborted(sig, () => handle.evaluate((el, dx, dy) => {
                        const target = el;
                        target.scrollBy({ left: dx, top: dy, behavior: "instant" });
                    }, deltaX, deltaY));
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }),
            drag: (from, to) => op("tab.drag()", actionOpMs, sig => this.#drag(from, to, sig)),
            waitFor: (selector, opts) => {
                const w = waitMs(opts?.timeout);
                return op(`tab.waitFor(${JSON.stringify(selector)})`, w, async (sig) => enrich(await this.#resolveActionHandle(selector, w, sig)), { selector, zeroMatchAfterMs: opts?.timeout === undefined ? ZERO_MATCH_FAIL_FAST_MS : undefined });
            },
            waitForSelector: (selector, opts) => {
                const w = waitMs(opts?.timeout);
                return op(`tab.waitForSelector(${JSON.stringify(selector)})`, w, async (sig) => {
                    if (parseAriaRefSelector(selector) !== null)
                        return enrich(await this.#resolveAriaRef(selector));
                    const handle = (await untilAborted(sig, () => page.waitForSelector(normalizeSelector(selector), {
                        timeout: w,
                        visible: opts?.visible,
                        hidden: opts?.hidden,
                        signal: sig,
                    })));
                    return handle ? enrich(handle) : null;
                }, {
                    selector,
                    // `hidden: true` waits for zero matches — that is success, never a fast-fail.
                    zeroMatchAfterMs: opts?.timeout === undefined && !opts?.hidden ? ZERO_MATCH_FAIL_FAST_MS : undefined,
                });
            },
            waitForNavigation: opts => {
                const w = waitMs(opts?.timeout);
                return op("tab.waitForNavigation()", w, sig => untilAborted(sig, () => page.waitForNavigation({ waitUntil: opts?.waitUntil ?? "load", timeout: w, signal: sig })));
            },
            evaluate: (fn, ...args) => op("tab.evaluate()", INF, sig => untilAborted(sig, async () => {
                const realm = page.mainFrame().mainRealm();
                // Puppeteer evaluates strings as expressions and ignores extra args; preserve
                // that behavior without inspecting or adopting otherwise-unused handles.
                if (typeof fn === "string")
                    return realm.evaluate(fn);
                const { args: adopted, dispose } = await adoptElementArgs(realm, args);
                try {
                    throwIfAborted(sig);
                    return await realm.evaluate(fn, ...adopted);
                }
                finally {
                    await dispose();
                }
            })),
            scrollIntoView: selector => op(`tab.scrollIntoView(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await untilAborted(sig, () => handle.evaluate(el => {
                        const target = el;
                        target.scrollIntoView({ behavior: "instant", block: "center", inline: "center" });
                    }));
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            select: (selector, ...values) => op(`tab.select(${JSON.stringify(selector)})`, actionOpMs, sig => this.#select(selector, values, actionOpMs, sig), { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            uploadFile: (selector, ...filePaths) => {
                const label = `tab.uploadFile(${JSON.stringify(selector)})`;
                return markHandled((async () => {
                    if (!filePaths.length)
                        throw new ToolError("tab.uploadFile() requires at least one file path");
                    // Its own deadline: the first upload's check must not eat into the wait for the selector.
                    const route = await op(`${label} checking how the browser takes files`, actionOpMs, sig => this.#requireUploads().route(page, sig));
                    const prepared = await op(label, actionOpMs, sig => this.#prepareTabUpload(selector, filePaths, label, route, actionOpMs, sig, session), { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS });
                    try {
                        await op(`${label} sending ${formatBytes(prepared.bytes)}`, budgetBound, sig => prepared.deliver(sig));
                    }
                    finally {
                        await prepared.dispose();
                    }
                })());
            },
            waitForUrl: (pattern, opts) => {
                const w = waitMs(opts?.timeout);
                return op("tab.waitForUrl()", w, sig => this.#waitForUrl(pattern, w, sig));
            },
            waitForResponse: (pattern, opts) => {
                const w = waitMs(opts?.timeout);
                return op("tab.waitForResponse()", w, sig => this.#waitForResponse(pattern, w, sig));
            },
            id: async (id) => enrich(await this.#resolveCachedHandle(id)),
            ref: async (id) => enrich(await this.#resolveAriaRef(id)),
            cookies: opts => op("tab.cookies()", quickOpMs, sig => readCookies(page, opts, sig)),
            setCookies: (...cookies) => op("tab.setCookies()", actionOpMs, sig => setPageCookies(page, cookies, sig)),
            clearCookies: opts => op("tab.clearCookies()", actionOpMs, sig => clearPageCookies(page, opts, sig)),
            storage: (kind, opts) => op("tab.storage()", quickOpMs, sig => readStorage(page, kind, opts, sig)),
            setStorage: (kind, keyOrEntries, value) => op("tab.setStorage()", actionOpMs, sig => setPageStorage(page, kind, keyOrEntries, value, sig)),
            clearStorage: kind => op("tab.clearStorage()", actionOpMs, sig => clearPageStorage(page, kind, sig)),
            saveState: filePath => op("tab.saveState()", actionOpMs, sig => saveStorageState(page, name, filePath, session.cwd, sig)),
            loadState: filePath => op("tab.loadState()", actionOpMs, sig => loadStorageState(page, filePath, session.cwd, {
                allowOtherOrigins: this.#mode === "headless",
                navigationTimeoutMs: actionOpMs,
                signal: sig,
            })),
            recordStart: (destination, opts) => op(`tab.recordStart(${JSON.stringify(destination)})`, quickOpMs, sig => this.#recording.start(createCdpRecordingSource(page), destination, session.cwd, opts, sig)),
            recordStop: () => op("tab.recordStop()", budgetBound, sig => this.#recording.stop({ signal: sig, output, excludeWebP: session.excludeWebP })),
            recordRestart: (destination, opts) => op(`tab.recordRestart(${JSON.stringify(destination)})`, budgetBound, sig => this.#recording.restart(createCdpRecordingSource(page), destination, session.cwd, opts, {
                signal: sig,
                output,
                excludeWebP: session.excludeWebP,
            })),
            recording: () => op("tab.recording()", quickOpMs, () => Promise.resolve(this.#recording.status())),
            webmcpList: opts => op("tab.webmcpList()", quickOpMs, sig => untilAborted(sig, () => webmcp.list(opts))),
            webmcpInvoke: (toolName, params, opts) => {
                const w = waitMs(opts?.timeout);
                return op(`tab.webmcpInvoke(${JSON.stringify(toolName)})`, w, sig => untilAborted(sig, () => webmcp.invoke(toolName, params, opts)));
            },
            webmcpEvents: opts => op("tab.webmcpEvents()", quickOpMs, sig => untilAborted(sig, () => webmcp.events(opts))),
            a11y: opts => op("tab.a11y()", budgetBound, async (sig) => {
                const result = await untilAborted(sig, () => runA11yAudit(page, opts));
                output.push({ type: "text", text: formatA11ySummary(result) });
                return result;
            }),
            vitals: opts => op("tab.vitals()", INF, sig => collectVitals(puppeteerReactHost(page), opts, sig)),
            reactEnable: () => op("tab.reactEnable()", INF, sig => enableReact(puppeteerReactHost(page), sig)),
            reactTree: opts => op("tab.reactTree()", quickOpMs, sig => readReactTree(page, opts, sig)),
            reactInspect: id => op(`tab.reactInspect(${id})`, quickOpMs, sig => inspectReactFiber(page, id, sig)),
            reactRenders: opts => op("tab.reactRenders()", quickOpMs, sig => collectReactRenders(page, opts, sig)),
            reactSuspense: opts => op("tab.reactSuspense()", quickOpMs, sig => readReactSuspense(page, opts, sig)),
            back: opts => op("tab.back()", INF, async (sig) => {
                this.#clearElementCache();
                return await traverseHistory(page, "back", opts?.waitUntil ?? "load", budgetBound, sig);
            }),
            forward: opts => op("tab.forward()", INF, async (sig) => {
                this.#clearElementCache();
                return await traverseHistory(page, "forward", opts?.waitUntil ?? "load", budgetBound, sig);
            }),
            reload: opts => op("tab.reload()", INF, async (sig) => {
                this.#clearElementCache();
                return await reloadPage(page, opts?.waitUntil ?? "load", budgetBound, sig);
            }),
            pushState: url => op(`tab.pushState(${JSON.stringify(url)})`, actionOpMs, async (sig) => {
                this.#clearElementCache();
                return await pushState(page, url, sig);
            }),
            frames: () => op("tab.frames()", quickOpMs, sig => listFrames(page, sig)),
            frame: selectorOrNameOrUrl => op(`tab.frame(${JSON.stringify(selectorOrNameOrUrl)})`, quickOpMs, async (sig) => {
                const frame = await resolveFrame(page, selectorOrNameOrUrl, normalizeSelector, sig);
                return createFrameApi(frame, {
                    quickOpMs,
                    actionOpMs,
                    zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS,
                    normalizeSelector,
                    waitMs,
                    op,
                    captureScreenshot: (target, selector, screenshotSignal) => captureFrameScreenshot(target, selector, screenshotSignal, normalizeSelector, session, output, screenshots),
                });
            }),
            dialog: () => op("tab.dialog()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireDialogs().state();
            }),
            handleDialog: opts => op("tab.handleDialog()", actionOpMs, sig => untilAborted(sig, () => this.#requireDialogs().handle(opts))),
            setDialogs: policy => op("tab.setDialogs()", actionOpMs, sig => untilAborted(sig, () => this.#requireDialogs().setPolicy(policy))),
            route: (pattern, opts) => op("tab.route()", actionOpMs, sig => untilAborted(sig, () => this.#requireNetwork().route(pattern, opts, sig))),
            unroute: pattern => op("tab.unroute()", actionOpMs, sig => untilAborted(sig, () => this.#requireNetwork().unroute(pattern, sig))),
            routes: () => op("tab.routes()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireNetwork().routes();
            }),
            requests: opts => op("tab.requests()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireNetwork().requests(opts);
            }),
            request: id => op("tab.request()", quickOpMs, sig => untilAborted(sig, () => this.#requireNetwork().request(id, sig))),
            clearRequests: () => op("tab.clearRequests()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                this.#requireNetwork().clearRequests();
            }),
            harStart: opts => op("tab.harStart()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                this.#requireNetwork().harStart(opts?.content);
            }),
            harStop: opts => op("tab.harStop()", INF, sig => {
                const destination = opts?.path
                    ? resolveToCwd(opts.path, session.cwd)
                    : path.join(session.cwd, `browser-${name.replace(/[^a-z0-9_-]+/gi, "-")}-${Snowflake.next()}.har`);
                return untilAborted(sig, () => this.#requireNetwork().harStop(destination, sig));
            }),
            allowedDomains: () => op("tab.allowedDomains()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireNetwork().allowedDomains();
            }),
            diffScreenshot: (baselinePath, opts) => op("tab.diffScreenshot()", quickOpMs, sig => this.#diffScreenshot(session, output, screenshots, sig, baselinePath, opts)),
            pdf: opts => op("tab.pdf()", quickOpMs, sig => this.#pdf(session, sig, opts)),
            addInitScript: source => op("tab.addInitScript()", actionOpMs, sig => untilAborted(sig, () => this.#requireInitScripts().add(source))),
            removeInitScript: id => op("tab.removeInitScript()", actionOpMs, sig => untilAborted(sig, () => this.#requireInitScripts().remove(id))),
            initScripts: () => op("tab.initScripts()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireInitScripts().list();
            }),
            waitForDownload: opts => {
                const w = waitMs(opts?.timeout);
                return op("tab.waitForDownload()", w, sig => this.#requireDownloads().wait(sig));
            },
            downloads: () => op("tab.downloads()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireDownloads().list();
            }),
            text: (selector = "body") => op(`tab.text(${JSON.stringify(selector)})`, quickOpMs, sig => queryText(page, normalizeSelector(selector), sig)),
            html: (selector = "body") => op(`tab.html(${JSON.stringify(selector)})`, quickOpMs, sig => queryHtml(page, normalizeSelector(selector), sig)),
            value: selector => op(`tab.value(${JSON.stringify(selector)})`, quickOpMs, sig => queryValue(page, normalizeSelector(selector), sig)),
            attr: (selector, attribute) => op(`tab.attr(${JSON.stringify(selector)}, ${JSON.stringify(attribute)})`, quickOpMs, sig => queryAttribute(page, normalizeSelector(selector), attribute, sig)),
            count: selector => op(`tab.count(${JSON.stringify(selector)})`, quickOpMs, sig => queryCount(page, normalizeSelector(selector), sig)),
            box: selector => op(`tab.box(${JSON.stringify(selector)})`, quickOpMs, sig => queryBox(page, normalizeSelector(selector), sig)),
            styles: (selector, props) => op(`tab.styles(${JSON.stringify(selector)})`, quickOpMs, sig => queryStyles(page, normalizeSelector(selector), props, sig)),
            isVisible: selector => op(`tab.isVisible(${JSON.stringify(selector)})`, quickOpMs, sig => queryVisible(page, normalizeSelector(selector), sig)),
            isEnabled: selector => op(`tab.isEnabled(${JSON.stringify(selector)})`, quickOpMs, sig => queryEnabled(page, normalizeSelector(selector), sig)),
            isChecked: selector => op(`tab.isChecked(${JSON.stringify(selector)})`, quickOpMs, sig => queryChecked(page, normalizeSelector(selector), sig)),
            waitForText: (text, opts) => {
                const w = waitMs(opts?.timeout);
                return op(`tab.waitForText(${JSON.stringify(text)})`, w, sig => waitForPageText(page, text, {
                    timeout: w,
                    selector: opts?.selector ? normalizeSelector(opts.selector) : undefined,
                    exact: opts?.exact,
                    signal: sig,
                }));
            },
            console: opts => op("tab.console()", quickOpMs, sig => untilAborted(sig, () => this.#consoleCapture.console(opts))),
            errors: opts => op("tab.errors()", quickOpMs, sig => untilAborted(sig, () => this.#consoleCapture.errors(opts))),
            clearConsole: () => op("tab.clearConsole()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                this.#consoleCapture.clear();
            }),
            traceStart: opts => op("tab.traceStart()", actionOpMs, sig => untilAborted(sig, () => this.#requireTracing().traceStart(opts))),
            traceStop: opts => op("tab.traceStop()", actionOpMs, sig => untilAborted(sig, () => this.#requireTracing().traceStop(session.cwd, opts))),
            profileStart: () => op("tab.profileStart()", actionOpMs, sig => untilAborted(sig, () => this.#requireTracing().profileStart())),
            profileStop: opts => op("tab.profileStop()", actionOpMs, sig => untilAborted(sig, () => this.#requireTracing().profileStop(session.cwd, opts))),
            metrics: () => op("tab.metrics()", quickOpMs, sig => untilAborted(sig, () => this.#requireTracing().metrics())),
            dblclick: selector => op(`tab.dblclick(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await clickElement(handle, `tab.dblclick(${JSON.stringify(selector)})`, sig, { clickCount: 2 });
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            hover: selector => op(`tab.hover(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await untilAborted(sig, () => handle.hover());
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            focus: selector => op(`tab.focus(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await untilAborted(sig, () => handle.focus());
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            check: selector => op(`tab.check(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await setElementChecked(handle, true, `tab.check(${JSON.stringify(selector)})`, sig);
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            uncheck: selector => op(`tab.uncheck(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await setElementChecked(handle, false, `tab.uncheck(${JSON.stringify(selector)})`, sig);
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            keyDown: key => op(`tab.keyDown(${JSON.stringify(key)})`, actionOpMs, sig => keyDown(page, key, sig)),
            keyUp: key => op(`tab.keyUp(${JSON.stringify(key)})`, actionOpMs, sig => keyUp(page, key, sig)),
            mouseMove: (x, y, opts) => op("tab.mouseMove()", actionOpMs, sig => mouseMove(page, x, y, opts, sig)),
            mouseDown: opts => op("tab.mouseDown()", actionOpMs, sig => mouseDown(page, opts, sig)),
            mouseUp: opts => op("tab.mouseUp()", actionOpMs, sig => mouseUp(page, opts, sig)),
            clickAt: (x, y, opts) => op("tab.clickAt()", actionOpMs, sig => clickAt(page, x, y, opts, sig)),
            wheel: (deltaX, deltaY) => op("tab.wheel()", actionOpMs, sig => wheel(page, deltaX, deltaY, sig)),
            highlight: (selector, opts) => op(`tab.highlight(${JSON.stringify(selector)})`, actionOpMs, async (sig) => {
                const handle = await this.#resolveActionHandle(selector, actionOpMs, sig);
                try {
                    await highlightElement(handle, opts, sig);
                }
                finally {
                    await handle.dispose().catch(() => undefined);
                }
            }, { selector, zeroMatchAfterMs: ZERO_MATCH_FAIL_FAST_MS }),
            emulate: opts => op("tab.emulate()", actionOpMs, sig => untilAborted(sig, () => this.#requireEmulation().emulate(opts))),
            devices: () => op("tab.devices()", quickOpMs, async (sig) => {
                throwIfAborted(sig);
                return this.#requireEmulation().devices();
            }),
            clipboardRead: () => op("tab.clipboardRead()", actionOpMs, sig => untilAborted(sig, () => this.#requireEmulation().clipboardRead())),
            clipboardWrite: text => op("tab.clipboardWrite()", actionOpMs, sig => untilAborted(sig, () => this.#requireEmulation().clipboardWrite(text))),
            clipboardCopy: () => op("tab.clipboardCopy()", actionOpMs, sig => untilAborted(sig, () => this.#requireEmulation().clipboardCopy())),
            clipboardPaste: () => op("tab.clipboardPaste()", actionOpMs, sig => untilAborted(sig, () => this.#requireEmulation().clipboardPaste())),
        };
    }
    async #collectObservation(options) {
        const page = this.#requirePage();
        this.#clearElementCache();
        const includeAll = options.includeAll ?? false;
        const viewportOnly = options.viewportOnly ?? false;
        let root = null;
        if (options.selector) {
            root =
                parseAriaRefSelector(options.selector) !== null
                    ? await this.#resolveAriaRef(options.selector)
                    : (await untilAborted(options.signal, () => page.$(normalizeSelector(options.selector))));
            if (!root) {
                throw new ToolError(`tab.observe: selector ${JSON.stringify(options.selector)} matched no element`);
            }
        }
        let snapshot;
        let frameSnapshots;
        try {
            snapshot = (await untilAborted(options.signal, () => page.accessibility.snapshot({ interestingOnly: !includeAll, root: root ?? undefined })));
            frameSnapshots = await snapshotFrames(page.mainFrame().childFrames(), {
                interestingOnly: !includeAll,
                root,
                deadline: Date.now() + FRAME_SNAPSHOT_TIMEOUT_MS,
                signal: options.signal,
            });
        }
        finally {
            await root?.dispose().catch(() => undefined);
        }
        if (!snapshot)
            throw new ToolError("Accessibility snapshot unavailable");
        const entries = [];
        const interactiveAncestors = new Set();
        const trees = [{ frame: page.mainFrame(), snapshot }, ...frameSnapshots];
        for (const tree of trees) {
            if (options.compact)
                collectInteractiveObservationAncestors(tree.snapshot, interactiveAncestors);
            await collectObservationEntries(this, tree.frame, tree.snapshot, entries, {
                includeAll,
                viewportOnly,
                compact: options.compact ?? false,
                interactiveAncestors,
            });
        }
        const scroll = (await untilAborted(options.signal, () => page.evaluate(() => {
            const win = globalThis;
            const doc = win.document.documentElement;
            return {
                x: win.scrollX,
                y: win.scrollY,
                width: win.innerWidth,
                height: win.innerHeight,
                scrollWidth: doc.scrollWidth,
                scrollHeight: doc.scrollHeight,
            };
        })));
        return {
            url: page.url(),
            title: (await untilAborted(options.signal, () => page.title())),
            viewport: await this.#viewport(options.signal),
            scroll,
            elements: entries,
        };
    }
    async #captureScreenshot(session, output, screenshots, signal, opts = {}) {
        const page = this.#requirePage();
        await preparePageForScreenshot(page, signal, this.#activateForScreenshot);
        screenshotQuality(opts);
        const threshold = screenshotThreshold(opts.threshold);
        const changeDetection = opts.ifChanged === true || opts.threshold !== undefined;
        const captureFormat = opts.format ?? "png";
        const captureMime = captureFormat === "jpeg" ? "image/jpeg" : "image/png";
        const annotationTargets = [];
        if (opts.annotate) {
            const observation = await this.#collectObservation({ signal });
            for (const entry of observation.elements) {
                const handle = await this.#resolveCachedHandle(entry.id);
                const box = await untilAborted(signal, () => handle.boundingBox()).catch(() => null);
                if (!box || box.width <= 0 || box.height <= 0)
                    continue;
                annotationTargets.push({
                    id: entry.id,
                    role: entry.role,
                    name: entry.name,
                    x: box.x,
                    y: box.y,
                    width: box.width,
                    height: box.height,
                });
            }
        }
        const captureScale = opts.silent ? undefined : ((await this.#viewport(signal)).deviceScaleFactor ?? 1);
        const cleanupAnnotations = opts.annotate
            ? await installScreenshotAnnotations(page, annotationTargets, signal)
            : async () => { };
        const resolveSelector = async (selector) => parseAriaRefSelector(selector) !== null
            ? await this.#resolveAriaRef(selector)
            : asElementHandle(await untilAborted(signal, () => page.$(normalizeSelector(selector))));
        let comparisonBuffer;
        let buffer;
        try {
            comparisonBuffer = await captureScreenshotBuffer(page, opts, signal, resolveSelector, "png");
            buffer =
                captureFormat === "png"
                    ? comparisonBuffer
                    : await captureScreenshotBuffer(page, opts, signal, resolveSelector, captureFormat);
        }
        finally {
            await cleanupAnnotations();
        }
        let changeResult;
        if (changeDetection) {
            const scope = screenshotScope(opts);
            const previous = this.#screenshotHistory.get(scope);
            const pixelChangeRatio = previous ? pngPixelChangeRatio(previous.png, comparisonBuffer) : 1;
            const changed = !previous || pixelChangeRatio > threshold;
            const revision = previous ? previous.revision + (changed ? 1 : 0) : 1;
            this.#screenshotHistory.set(scope, { png: comparisonBuffer, revision });
            changeResult = { changed, revision, pixelChangeRatio };
            if (!changed)
                return changeResult;
        }
        const resized = await resizeImage({ type: "image", data: buffer.toBase64(), mimeType: captureMime }, { maxWidth: 1024, maxHeight: 1024, maxBytes: 150 * 1024, jpegQuality: 70, excludeWebP: session.excludeWebP });
        const preserveFormat = opts.format !== undefined;
        const saveFullRes = !!session.browserScreenshotDir || preserveFormat;
        const savedBuffer = saveFullRes ? buffer : resized.buffer;
        const savedMimeType = saveFullRes ? captureMime : resized.mimeType;
        const ext = savedMimeType === "image/webp" ? "webp" : savedMimeType === "image/jpeg" ? "jpg" : "png";
        const dest = session.browserScreenshotDir
            ? path.join(session.browserScreenshotDir, `screenshot-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, -1)}.${ext}`)
            : path.join(os.tmpdir(), `omp-sshots-${Snowflake.next()}.${ext}`);
        await fs.promises.mkdir(path.dirname(dest), { recursive: true });
        await Bun.write(dest, savedBuffer);
        screenshots.push({
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
                capture: { area: screenshotArea(opts), scale: captureScale },
            });
            if (opts.annotate)
                lines.push(formatScreenshotLegend(annotationTargets));
            output.push({ type: "text", text: lines.join("\n") });
            output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
        }
        if (changeResult)
            return { ...changeResult, path: dest };
        return dest;
    }
    async #diffScreenshot(session, output, screenshots, signal, baselinePath, opts = {}) {
        const page = this.#requirePage();
        await preparePageForScreenshot(page, signal, this.#activateForScreenshot);
        const absoluteBaseline = resolveToCwd(baselinePath, session.cwd);
        const baseline = await untilAborted(signal, () => fs.promises.readFile(absoluteBaseline));
        const current = await captureScreenshotBuffer(page, {}, signal, async () => null, "png");
        const diff = createPngDiff(baseline, current);
        const threshold = screenshotThreshold(opts.threshold);
        const changed = diff.pixelChangeRatio > threshold;
        const diffPath = opts.output
            ? resolveToCwd(opts.output, session.cwd)
            : path.join(os.tmpdir(), `omp-screenshot-diff-${Snowflake.next()}.png`);
        await fs.promises.mkdir(path.dirname(diffPath), { recursive: true });
        await Bun.write(diffPath, diff.png);
        const resized = await resizeImage({ type: "image", data: diff.png.toBase64(), mimeType: "image/png" }, { maxWidth: 1024, maxHeight: 1024, maxBytes: 150 * 1024, jpegQuality: 70, excludeWebP: session.excludeWebP });
        screenshots.push({
            dest: diffPath,
            mimeType: "image/png",
            bytes: diff.png.length,
            width: resized.width,
            height: resized.height,
        });
        output.push({
            type: "text",
            text: `Screenshot diff: ${diff.pixelChangeRatio.toFixed(6)} changed-pixel ratio (${changed ? "changed" : "unchanged"}); saved to ${diffPath}`,
        });
        output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
        return { pixelChangeRatio: diff.pixelChangeRatio, changed, diffPath };
    }
    async #pdf(session, signal, opts = {}) {
        const dest = opts.path
            ? resolveToCwd(opts.path, session.cwd)
            : path.join(os.tmpdir(), `omp-browser-${Snowflake.next()}.pdf`);
        await fs.promises.mkdir(path.dirname(dest), { recursive: true });
        await untilAborted(signal, () => this.#requirePage().pdf({
            path: dest,
            format: opts.format,
            landscape: opts.landscape,
            scale: opts.scale,
            printBackground: opts.printBackground,
            margin: opts.margin,
            pageRanges: opts.pageRanges,
        }));
        return dest;
    }
    async #drag(from, to, signal) {
        const page = this.#requirePage();
        const resolveDragPoint = async (target, role) => {
            if (typeof target === "string") {
                const handle = parseAriaRefSelector(target) !== null
                    ? await this.#resolveAriaRef(target)
                    : asElementHandle(await untilAborted(signal, () => page.$(normalizeSelector(target))));
                if (!handle)
                    throw new ToolError(`Drag ${role} selector did not resolve: ${target}`);
                const box = (await untilAborted(signal, () => handle.boundingBox()));
                if (!box) {
                    await handle.dispose().catch(() => undefined);
                    throw new ToolError(`Drag ${role} element has no bounding box (likely not visible): ${target}`);
                }
                return { x: box.x + box.width / 2, y: box.y + box.height / 2, handle };
            }
            if (target !== null &&
                typeof target === "object" &&
                typeof target.x === "number" &&
                typeof target.y === "number") {
                return { x: target.x, y: target.y };
            }
            throw new ToolError(`Drag ${role} must be a selector string or { x: number, y: number } point. Got: ${typeof target}`);
        };
        const start = await resolveDragPoint(from, "from");
        let end;
        try {
            end = await resolveDragPoint(to, "to");
            await untilAborted(signal, () => page.mouse.move(start.x, start.y));
            await untilAborted(signal, () => page.mouse.down());
            await untilAborted(signal, () => page.mouse.move(end.x, end.y, { steps: 12 }));
            await untilAborted(signal, () => page.mouse.up());
        }
        finally {
            if (start.handle)
                await start.handle.dispose().catch(() => undefined);
            if (end?.handle)
                await end.handle.dispose().catch(() => undefined);
        }
    }
    async #select(selector, values, timeoutMs, signal) {
        const handle = await this.#resolveActionHandle(selector, timeoutMs, signal);
        try {
            return await selectElementOptions(handle, values, "tab.select()", signal);
        }
        finally {
            await handle.dispose().catch(() => undefined);
        }
    }
    /** Find what takes a `tab.uploadFile` under the action deadline; the result owns the resolved handle. */
    async #prepareTabUpload(selector, filePaths, label, route, timeoutMs, signal, session) {
        const page = this.#requirePage();
        const handle = await this.#resolveActionHandle(selector, timeoutMs, signal);
        try {
            const absolute = filePaths.map(filePath => resolveToCwd(filePath, session.cwd));
            const prepared = await prepareElementUpload(page, handle, absolute, label, route, this.#requireUploads(), signal);
            return {
                ...prepared,
                dispose: async () => {
                    await prepared.dispose();
                    await handle.dispose().catch(() => undefined);
                },
            };
        }
        catch (error) {
            await handle.dispose().catch(() => undefined);
            throw error;
        }
    }
    async #waitForUrl(pattern, timeout, signal) {
        const page = this.#requirePage();
        const isRegex = pattern instanceof RegExp;
        const matcher = isRegex ? pattern.source : pattern;
        const flags = isRegex ? pattern.flags : "";
        await untilAborted(signal, () => page.waitForFunction((m, isRe, fl) => {
            const url = globalThis.location.href;
            return isRe ? new RegExp(m, fl).test(url) : url.includes(m);
        }, { timeout, polling: 200, signal }, matcher, isRegex, flags));
        return page.url();
    }
    async #waitForResponse(pattern, timeout, signal) {
        const page = this.#requirePage();
        const predicate = typeof pattern === "function"
            ? pattern
            : pattern instanceof RegExp
                ? response => pattern.test(response.url())
                : response => response.url().includes(pattern);
        return (await untilAborted(signal, () => page.waitForResponse(predicate, { timeout, signal })));
    }
    async #resolveCachedHandle(id) {
        const element = this.#observedElements.get(id);
        if (!element)
            throw new ToolError(`Unknown element id ${id}. Run tab.observe() to refresh the element list.`);
        if (isObservedDocumentGone(element)) {
            this.#clearElementCache();
            throw new ToolError(`Element id ${id} is stale. Run tab.observe() again.`);
        }
        const handle = this.#elementCache.get(id);
        if (!handle) {
            const resolved = await resolveObservedElement(element);
            // An observe() during the await renumbers ids, so the id may now name another element.
            if (!resolved || this.#observedElements.get(id) !== element) {
                await resolved?.dispose().catch(() => undefined);
                if (this.#observedElements.get(id) === element)
                    this.#clearElementCache();
                throw new ToolError(`Element id ${id} is stale. Run tab.observe() again.`);
            }
            const cached = this.#elementCache.get(id);
            if (cached) {
                await resolved.dispose().catch(() => undefined);
                return cached;
            }
            this.#elementCache.set(id, resolved);
            return resolved;
        }
        try {
            const isConnected = (await handle.evaluate(el => el.isConnected));
            if (!isConnected) {
                this.#clearElementCache();
                throw new ToolError(`Element id ${id} is stale. Run tab.observe() again.`);
            }
        }
        catch (err) {
            if (err instanceof ToolError)
                throw err;
            this.#clearElementCache();
            throw new ToolError(`Element id ${id} is stale. Run tab.observe() again.`);
        }
        return handle;
    }
    async #resolveAriaRef(id) {
        const ref = parseAriaRefSelector(id) ?? id.trim();
        const handle = await resolveAriaRefHandle(this.#requirePage(), ref);
        if (!handle) {
            throw new ToolError(`Unknown ARIA ref ${JSON.stringify(ref)}. Run tab.ariaSnapshot() to refresh refs (they renumber each snapshot).`);
        }
        return handle;
    }
    /**
     * Resolve a selector to an ElementHandle for handle-based actions. An
     * `aria-ref=eN` selector resolves against the latest ariaSnapshot's refs
     * (main world); anything else goes through the normal locator wait.
     */
    async #resolveActionHandle(selector, timeoutMs, sig) {
        if (parseAriaRefSelector(selector) !== null)
            return this.#resolveAriaRef(selector);
        return (await untilAborted(sig, () => this.#requirePage().locator(normalizeSelector(selector)).setTimeout(timeoutMs).waitHandle({ signal: sig })));
    }
    #clearElementCache() {
        this.#observedElements.clear();
        if (this.#elementCache.size === 0) {
            this.#elementCounter = 0;
            return;
        }
        const handles = [...this.#elementCache.values()];
        this.#elementCache.clear();
        this.#elementCounter = 0;
        for (const handle of handles)
            void handle.dispose().catch(() => undefined);
    }
    /** Best-effort `Page.stopLoading` so an abandoned navigation cannot stall later ops. */
    async #stopLoading() {
        try {
            const session = await this.#requirePage().createCDPSession();
            try {
                await session.send("Page.stopLoading");
            }
            finally {
                await session.detach().catch(() => undefined);
            }
        }
        catch (error) {
            this.#log("debug", "Page.stopLoading failed", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    async #close() {
        this.#unsub();
        this.#uninstallRejectionGuard();
        this.#clearElementCache();
        const page = this.#page;
        await this.#recording.close().catch(error => {
            this.#log("warn", "Failed to finalize active browser recording during tab close", {
                error: error instanceof Error ? error.message : String(error),
            });
        });
        await this.#webmcp?.dispose().catch(() => undefined);
        this.#webmcp = undefined;
        this.#dialogs?.dispose();
        await this.#network?.close();
        await this.#downloads?.close();
        await this.#tracing?.dispose();
        await this.#consoleCapture.detach();
        this.#emulation?.dispose();
        if (this.#mode === "headless" && page && !page.isClosed())
            await page.close().catch(() => undefined);
        if (this.#browser?.connected)
            this.#browser.disconnect();
        this.#transport.send({ type: "closed" });
        this.#transport.close();
    }
    #requirePage() {
        if (!this.#page)
            throw new ToolError("Tab worker is not initialized");
        return this.#page;
    }
    #requireUploads() {
        if (!this.#uploads)
            throw new ToolError("Tab worker is not initialized");
        return this.#uploads;
    }
    #requireDialogs() {
        if (!this.#dialogs)
            throw new ToolError("Tab worker dialog handling is not initialized");
        return this.#dialogs;
    }
    #requireNetwork() {
        if (!this.#network)
            throw new ToolError("Tab worker network manager is not initialized");
        return this.#network;
    }
    #requireTracing() {
        if (!this.#tracing)
            throw new ToolError("Tab worker tracing is not initialized");
        return this.#tracing;
    }
    #requireInitScripts() {
        if (!this.#initScripts)
            throw new ToolError("Tab worker init scripts are not initialized");
        return this.#initScripts;
    }
    #requireDownloads() {
        if (!this.#downloads)
            throw new ToolError("Tab worker downloads are not initialized");
        return this.#downloads;
    }
    #requireEmulation() {
        if (!this.#emulation)
            throw new ToolError("Tab worker emulation is not initialized");
        return this.#emulation;
    }
    #requireBrowser() {
        if (!this.#browser)
            throw new ToolError("Tab worker is not initialized");
        return this.#browser;
    }
    #log(level, msg, meta) {
        this.#transport.send({ type: "log", level, msg, meta });
    }
}
