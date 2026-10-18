import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Snowflake, untilAborted } from "@rva/utils";
import { formatScreenshot, resizeImage } from "../../utils/image-resize";
import { throwIfAborted } from "../tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { buildAriaSnapshotScript } from "./aria/aria-snapshot";
import { clickElement, fillViaHandle, focusTextEntryTarget, pressKey } from "./interactions";
import { readPageViewport } from "./launch";
/** A frame's DevTools identifier, the id CDP events name it by. */
export function devtoolsFrameId(frame) {
    // Puppeteer keeps the DevTools id on an internal field its public types omit.
    const internal = frame;
    return internal._id;
}
/** List the page's current main and child frames with stable DevTools identifiers. */
export async function listFrames(page, signal) {
    const result = [];
    for (const frame of page.frames()) {
        const parent = frame.parentFrame();
        const info = {
            id: devtoolsFrameId(frame),
            name: frame.name(),
            url: frame.url(),
            parentId: parent ? devtoolsFrameId(parent) : null,
        };
        if (parent) {
            let element = null;
            try {
                element = await untilAborted(signal, () => frame.frameElement());
                const attributes = await untilAborted(signal, () => element.evaluate(node => {
                    const frameElement = node;
                    return {
                        tag: frameElement.localName,
                        id: frameElement.getAttribute("id"),
                        name: frameElement.getAttribute("name"),
                    };
                }));
                if (attributes.id)
                    info.selector = `${attributes.tag}[id=${JSON.stringify(attributes.id)}]`;
                else if (attributes.name)
                    info.selector = `${attributes.tag}[name=${JSON.stringify(attributes.name)}]`;
            }
            catch {
                // Detached or cross-process frame elements may disappear while enumerating.
            }
            finally {
                await element?.dispose().catch(() => undefined);
            }
        }
        result.push(info);
    }
    return result;
}
/** Resolve a frame by owning-element selector, frame name, or exact frame URL. */
export async function resolveFrame(page, selectorOrNameOrUrl, normalizeSelector, signal) {
    let element = null;
    try {
        const selector = normalizeSelector(selectorOrNameOrUrl);
        element = await untilAborted(signal, () => page.$(selector));
        if (element) {
            const frame = await untilAborted(signal, () => element.contentFrame());
            if (!frame)
                throw new ToolError(`tab.frame(${JSON.stringify(selectorOrNameOrUrl)}) matched an element without a frame`);
            return frame;
        }
    }
    catch (error) {
        throwIfAborted(signal);
        if (element)
            throw error;
        // URL-like and name strings are often not valid CSS selectors; match them below.
    }
    finally {
        await element?.dispose().catch(() => undefined);
    }
    const frame = page
        .frames()
        .find(candidate => candidate.name() === selectorOrNameOrUrl || candidate.url() === selectorOrNameOrUrl);
    if (!frame)
        throw new ToolError(`tab.frame(${JSON.stringify(selectorOrNameOrUrl)}) found no matching frame`);
    return frame;
}
/** Build the scoped operations for one already-resolved Puppeteer frame. */
export function createFrameApi(frame, hooks) {
    const selectorOptions = (selector) => ({
        selector,
        zeroMatchAfterMs: hooks.zeroMatchAfterMs,
    });
    const waitForSelector = (selector, options) => {
        const deadline = hooks.waitMs(options?.timeout);
        return hooks.op(`frame.waitForSelector(${JSON.stringify(selector)})`, deadline, async (signal) => {
            const handle = await untilAborted(signal, () => frame.waitForSelector(hooks.normalizeSelector(selector), {
                timeout: deadline,
                visible: options?.visible,
                hidden: options?.hidden,
                signal,
            }));
            await handle?.dispose().catch(() => undefined);
            return true;
        }, {
            selector,
            zeroMatchAfterMs: options?.timeout === undefined && !options?.hidden ? hooks.zeroMatchAfterMs : undefined,
        });
    };
    /**
     * Wait for an actionable match without Puppeteer's `Locator` preconditions:
     * those wait on animation-frame and IntersectionObserver callbacks a
     * backgrounded headless tab never delivers (#12892).
     */
    const actionHandle = async (label, selector, signal) => {
        const handle = await untilAborted(signal, () => frame.waitForSelector(hooks.normalizeSelector(selector), {
            timeout: hooks.actionOpMs,
            visible: true,
            signal,
        }));
        if (!handle)
            throw new ToolError(`${label} matched no visible element`);
        return handle;
    };
    return {
        click: selector => hooks.op(`frame.click(${JSON.stringify(selector)})`, hooks.actionOpMs, async (signal) => {
            const label = `frame.click(${JSON.stringify(selector)})`;
            const handle = await actionHandle(label, selector, signal);
            try {
                await clickElement(handle, label, signal);
            }
            finally {
                await handle.dispose().catch(() => undefined);
            }
        }, selectorOptions(selector)),
        fill: (selector, value) => hooks.op(`frame.fill(${JSON.stringify(selector)})`, hooks.actionOpMs, async (signal) => {
            const handle = await actionHandle(`frame.fill(${JSON.stringify(selector)})`, selector, signal);
            try {
                await fillViaHandle(handle, value, signal);
            }
            finally {
                await handle.dispose().catch(() => undefined);
            }
        }, selectorOptions(selector)),
        type: (selector, text) => hooks.op(`frame.type(${JSON.stringify(selector)})`, hooks.actionOpMs, async (signal) => {
            const handle = await untilAborted(signal, () => frame.$(hooks.normalizeSelector(selector)));
            if (!handle)
                throw new ToolError(`frame.type(${JSON.stringify(selector)}) matched no element`);
            try {
                await focusTextEntryTarget(handle, "type into", signal);
                await untilAborted(signal, () => handle.type(text, { delay: 0 }));
            }
            finally {
                await handle.dispose().catch(() => undefined);
            }
        }, selectorOptions(selector)),
        press: (key, options) => hooks.op(`frame.press(${JSON.stringify(key)})`, hooks.actionOpMs, async (signal) => {
            if (options?.selector)
                await untilAborted(signal, () => frame.focus(hooks.normalizeSelector(options.selector)));
            await untilAborted(signal, () => pressKey(frame.page(), key));
        }),
        // Without a selector, the frame's `<body>`; any value passed, `null` included, is still checked as a selector.
        text: (selector = "body") => hooks.op(`frame.text(${JSON.stringify(selector)})`, hooks.quickOpMs, signal => untilAborted(signal, () => frame.$eval(hooks.normalizeSelector(selector), element => {
            const rendered = "innerText" in element ? element.innerText : undefined;
            return (typeof rendered === "string" ? rendered : (element.textContent ?? "")).trim();
        })), selectorOptions(selector)),
        html: (selector = "body") => hooks.op(`frame.html(${JSON.stringify(selector)})`, hooks.quickOpMs, signal => untilAborted(signal, () => frame.$eval(hooks.normalizeSelector(selector), element => element.innerHTML)), selectorOptions(selector)),
        value: selector => hooks.op(`frame.value(${JSON.stringify(selector)})`, hooks.quickOpMs, signal => untilAborted(signal, () => frame.$eval(hooks.normalizeSelector(selector), element => {
            const control = element;
            return control.value;
        })), selectorOptions(selector)),
        attr: (selector, name) => hooks.op(`frame.attr(${JSON.stringify(selector)}, ${JSON.stringify(name)})`, hooks.quickOpMs, signal => untilAborted(signal, () => frame.$eval(hooks.normalizeSelector(selector), (element, attribute) => element.getAttribute(attribute), name)), selectorOptions(selector)),
        count: selector => hooks.op(`frame.count(${JSON.stringify(selector)})`, hooks.quickOpMs, signal => untilAborted(signal, () => frame.$$eval(hooks.normalizeSelector(selector), elements => elements.length))),
        isVisible: selector => hooks.op(`frame.isVisible(${JSON.stringify(selector)})`, hooks.quickOpMs, async (signal) => {
            const handle = await untilAborted(signal, () => frame.$(hooks.normalizeSelector(selector)));
            if (!handle)
                return false;
            try {
                return await untilAborted(signal, () => handle.isVisible());
            }
            finally {
                await handle.dispose().catch(() => undefined);
            }
        }),
        ariaSnapshot: (selector, options) => hooks.op("frame.ariaSnapshot()", hooks.quickOpMs, async (signal) => {
            return (await untilAborted(signal, () => frame.evaluate(buildAriaSnapshotScript(selector, options))));
        }),
        evaluate: ((fn, ...args) => hooks.op("frame.evaluate()", Number.POSITIVE_INFINITY, signal => untilAborted(signal, () => frame.evaluate(fn, ...args)))),
        waitFor: waitForSelector,
        waitForSelector,
        screenshot: selector => hooks.op(`frame.screenshot(${JSON.stringify(selector)})`, hooks.quickOpMs, signal => hooks.captureScreenshot(frame, selector, signal), selectorOptions(selector)),
    };
}
/** Persist a frame-scoped element screenshot and emit the normal Eval image output. */
export async function captureFrameScreenshot(frame, selector, signal, normalizeSelector, session, output, screenshots) {
    const handle = await untilAborted(signal, () => frame.$(normalizeSelector(selector)));
    if (!handle)
        throw new ToolError(`frame.screenshot(${JSON.stringify(selector)}) matched no element`);
    let buffer;
    let captureScale;
    try {
        await untilAborted(signal, () => handle.evaluate(element => {
            const target = element;
            target.scrollIntoView({ behavior: "instant", block: "center", inline: "center" });
        })).catch(() => undefined);
        captureScale = (await readPageViewport(frame.page(), signal)).deviceScaleFactor ?? 1;
        const screenshotOptions = { type: "png", scrollIntoView: false };
        buffer = (await untilAborted(signal, () => handle.screenshot(screenshotOptions)));
    }
    finally {
        await handle.dispose().catch(() => undefined);
    }
    const resized = await resizeImage({ type: "image", data: buffer.toBase64(), mimeType: "image/png" }, { maxWidth: 1024, maxHeight: 1024, maxBytes: 150 * 1024, jpegQuality: 70, excludeWebP: session.excludeWebP });
    const saveFullRes = !!session.browserScreenshotDir;
    const savedBuffer = saveFullRes ? buffer : resized.buffer;
    const savedMimeType = saveFullRes ? "image/png" : resized.mimeType;
    const ext = savedMimeType === "image/webp" ? "webp" : savedMimeType === "image/jpeg" ? "jpg" : "png";
    const dest = session.browserScreenshotDir
        ? path.join(session.browserScreenshotDir, `frame-screenshot-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, -1)}.${ext}`)
        : path.join(os.tmpdir(), `omp-frame-sshots-${Snowflake.next()}.${ext}`);
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    await Bun.write(dest, savedBuffer);
    screenshots.push({
        dest,
        mimeType: savedMimeType,
        bytes: savedBuffer.length,
        width: resized.width,
        height: resized.height,
    });
    output.push({
        type: "text",
        text: formatScreenshot({
            saveFullRes,
            savedMimeType,
            savedByteLength: savedBuffer.length,
            dest,
            resized,
            capture: { area: "element", scale: captureScale },
        }).join("\n"),
    });
    output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
    return dest;
}
