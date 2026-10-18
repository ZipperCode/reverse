import { untilAborted } from "@rva/utils";
/** CDP lifecycle event behind each `waitUntil` that is read from the main frame alone. */
const MAIN_FRAME_LIFECYCLE_EVENTS = { load: "load", domcontentloaded: "DOMContentLoaded" };
/** How often the main-frame wait re-reads the frame's lifecycle events. */
const MAIN_FRAME_POLL_MS = 50;
/** Puppeteer-compatible timeout error; built by name so this module keeps `puppeteer-core` type-only. */
function navigationTimeoutError(timeout) {
    const error = new Error(`Navigation timeout of ${timeout} ms exceeded`);
    error.name = "TimeoutError";
    return error;
}
/** Invoke `history.back()` inside a browser page. */
export function historyBackInPage() {
    globalThis.history.back();
}
/** Invoke `history.forward()` inside a browser page. */
export function historyForwardInPage() {
    globalThis.history.forward();
}
/** Invoke `location.reload()` inside a browser page. */
export function reloadInPage() {
    globalThis.location.reload();
}
/** Read `location.href` inside a browser page. */
export function locationHrefInPage() {
    return globalThis.location.href;
}
/** Perform Next.js or History API navigation inside a browser page. */
export async function pushStateInPage(destination) {
    const root = globalThis;
    const routerPush = root.next?.router?.push;
    if (typeof routerPush === "function") {
        await routerPush.call(root.next?.router, destination);
    }
    else {
        root.history.pushState({}, "", destination);
        root.dispatchEvent(new root.PopStateEvent("popstate", { state: root.history.state }));
        root.dispatchEvent(new root.Event("navigate"));
    }
    return root.location.href;
}
/**
 * Run `navigate` and wait for the main document to reach `waitUntil`.
 *
 * Puppeteer's `load` and `domcontentloaded` also wait for that event in every child frame
 * that started loading, so one iframe that never finishes (ad, chat widget, challenge) times
 * out a page whose own document is ready. Puppeteer therefore only waits for the commit, and
 * the main frame's lifecycle events, which Puppeteer's own wait reads too, decide the rest.
 * Any other `waitUntil` (`networkidle*`, arrays, invalid values) keeps Puppeteer's own wait,
 * which also validates the value.
 */
export async function navigateMainFrame(page, waitUntil, timeout, signal, navigate) {
    if (waitUntil !== "load" && waitUntil !== "domcontentloaded") {
        await untilAborted(signal, () => navigate({ waitUntil, timeout }));
        return;
    }
    const deadline = Date.now() + timeout;
    await untilAborted(signal, () => navigate({ waitUntil: [], timeout }));
    const event = MAIN_FRAME_LIFECYCLE_EVENTS[waitUntil];
    for (;;) {
        if (page.isClosed() || !page.browser().connected)
            throw new Error("Navigating frame was detached");
        const frame = page.mainFrame();
        if (frame.detached)
            throw new Error("Navigating frame was detached");
        if (frame._lifecycleEvents.has(event))
            return;
        const remaining = deadline - Date.now();
        if (remaining <= 0)
            throw navigationTimeoutError(timeout);
        // The last read lands on the deadline, so an event that arrives after it is a timeout.
        await untilAborted(signal, () => Bun.sleep(Math.min(MAIN_FRAME_POLL_MS, remaining)));
    }
}
/** Navigate through session history and return the resulting page URL. */
export async function traverseHistory(page, direction, waitUntil, timeout, signal) {
    const navigate = direction === "back" ? page.goBack.bind(page) : page.goForward.bind(page);
    await navigateMainFrame(page, waitUntil, timeout, signal, navigate);
    return page.url();
}
/** Reload the current document and return the resulting page URL. */
export async function reloadPage(page, waitUntil, timeout, signal) {
    await navigateMainFrame(page, waitUntil, timeout, signal, options => page.reload(options));
    return page.url();
}
/** Perform client-side navigation through Next.js when available, otherwise the History API. */
export async function pushState(page, url, signal) {
    return await untilAborted(signal, () => page.evaluate(pushStateInPage, url));
}
