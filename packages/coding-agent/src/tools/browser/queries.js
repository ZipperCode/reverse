import { untilAborted } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
/** Default computed-style properties returned by `tab.styles()`. */
export const DEFAULT_STYLE_PROPERTIES = [
    "font-family",
    "font-size",
    "font-weight",
    "color",
    "background-color",
    "display",
    "visibility",
    "opacity",
    "position",
    "z-index",
    "width",
    "height",
    "margin",
    "padding",
];
async function firstHandle(page, selector, signal) {
    return (await untilAborted(signal, () => page.$(selector)));
}
/** Return the first matching element's rendered text, or `null`. */
export async function queryText(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.evaluate(element => (element.innerText ?? element.textContent ?? "").trim())));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Return the first matching element's inner HTML, or `null`. */
export async function queryHtml(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.evaluate(element => element.innerHTML)));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Return the first matching form element's current value, or `null`. */
export async function queryValue(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.evaluate(element => {
            const candidate = element;
            return "value" in candidate && candidate.value != null ? String(candidate.value) : null;
        })));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Return an attribute from the first matching element, or `null`. */
export async function queryAttribute(page, selector, name, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.evaluate((element, attribute) => element.getAttribute(attribute), name)));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Count elements matching a selector. */
export async function queryCount(page, selector, signal) {
    const handles = (await untilAborted(signal, () => page.$$(selector)));
    try {
        return handles.length;
    }
    finally {
        await Promise.all(handles.map(async (handle) => handle.dispose().catch(() => undefined)));
    }
}
/** Return the first matching element's bounds, or `null`. */
export async function queryBox(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.boundingBox()));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Return computed styles for the first matching element, or `null`. */
export async function queryStyles(page, selector, props, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return null;
    try {
        return (await untilAborted(signal, () => handle.evaluate((element, properties) => {
            const computed = getComputedStyle(element);
            return Object.fromEntries(properties.map(property => [property, computed.getPropertyValue(property)]));
        }, props ?? [...DEFAULT_STYLE_PROPERTIES])));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Report whether the first matching element is visible. */
export async function queryVisible(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return false;
    try {
        return await untilAborted(signal, () => handle.isVisible());
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Report whether the first matching element is enabled. */
export async function queryEnabled(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return false;
    try {
        return (await untilAborted(signal, () => handle.evaluate(element => !element.matches(":disabled") && element.getAttribute("aria-disabled") !== "true")));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Report whether the first matching element is checked. */
export async function queryChecked(page, selector, signal) {
    const handle = await firstHandle(page, selector, signal);
    if (!handle)
        return false;
    try {
        return (await untilAborted(signal, () => handle.evaluate(element => {
            const candidate = element;
            return typeof candidate.checked === "boolean"
                ? candidate.checked
                : element.getAttribute("aria-checked") === "true";
        })));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
}
/** Attach browser-tool query methods to a Puppeteer element handle. */
export function enrichElementQueries(handle, guard) {
    const enriched = handle;
    enriched.text = () => guard("handle.text()", signal => untilAborted(signal, () => handle.evaluate(element => (element.innerText ?? element.textContent ?? "").trim())));
    enriched.html = () => guard("handle.html()", signal => untilAborted(signal, () => handle.evaluate(element => element.innerHTML)));
    enriched.value = () => guard("handle.value()", signal => untilAborted(signal, () => handle.evaluate(element => {
        const candidate = element;
        return "value" in candidate && candidate.value != null ? String(candidate.value) : null;
    })));
    enriched.attr = name => guard("handle.attr()", signal => untilAborted(signal, () => handle.evaluate((element, attribute) => element.getAttribute(attribute), name)));
    enriched.styles = props => guard("handle.styles()", signal => untilAborted(signal, () => handle.evaluate((element, properties) => {
        const computed = getComputedStyle(element);
        return Object.fromEntries(properties.map(property => [property, computed.getPropertyValue(property)]));
    }, props ?? [...DEFAULT_STYLE_PROPERTIES])));
    enriched.isEnabled = () => guard("handle.isEnabled()", signal => untilAborted(signal, () => handle.evaluate(element => !element.matches(":disabled") && element.getAttribute("aria-disabled") !== "true")));
    enriched.isChecked = () => guard("handle.isChecked()", signal => untilAborted(signal, () => handle.evaluate(element => {
        const candidate = element;
        return typeof candidate.checked === "boolean"
            ? candidate.checked
            : element.getAttribute("aria-checked") === "true";
    })));
    return enriched;
}
/** Wait until text appears in the document body or a scoped element. */
export async function waitForPageText(page, text, opts) {
    const deadline = Date.now() + opts.timeout;
    while (Date.now() <= deadline) {
        let content;
        if (opts.selector) {
            content = await queryText(page, opts.selector, opts.signal);
        }
        else {
            content = (await untilAborted(opts.signal, () => page.evaluate(() => {
                const pageGlobal = globalThis;
                return pageGlobal.document.body?.innerText ?? "";
            })));
        }
        if (content !== null) {
            const candidate = content.trim();
            if (opts.exact ? candidate === text : candidate.includes(text))
                return;
        }
        await untilAborted(opts.signal, () => Bun.sleep(Math.min(100, Math.max(1, deadline - Date.now()))));
    }
    throw new ToolError(`tab.waitForText(${JSON.stringify(text)}) timed out after ${opts.timeout}ms`);
}
