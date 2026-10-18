import { ToolError } from "@rva/tui/tools/tool-errors";
import { pressKey } from "./interactions";
import { applyViewport } from "./launch";
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
function copyOptions(options) {
    return structuredClone(options);
}
function pageOrigin(page) {
    try {
        const origin = new URL(page.url()).origin;
        return origin === "null" ? null : origin;
    }
    catch {
        return null;
    }
}
/** Apply a page-scoped user-agent override that remains active across navigations. */
export async function applyUserAgentOverride(page, userAgent) {
    await page.setUserAgent(userAgent);
}
/** Owns persistent runtime emulation and clipboard state for one Puppeteer page. */
export class BrowserEmulationController {
    #page;
    #devices;
    #networkConditions;
    #baseUserAgent;
    #state = {};
    #permissionsByOrigin = new Map();
    #clipboardShim;
    #navigationHandler;
    constructor(page, devices, networkConditions, baseUserAgent) {
        this.#page = page;
        this.#devices = devices;
        this.#networkConditions = networkConditions;
        this.#baseUserAgent = baseUserAgent;
        this.#navigationHandler = frame => {
            if (frame !== this.#page.mainFrame())
                return;
            if (this.#state.geolocation)
                void this.#grantPermissions(["geolocation"]).catch(() => undefined);
        };
        page.on("framenavigated", this.#navigationHandler);
    }
    /** Return all Puppeteer known-device names in stable order. */
    devices() {
        return Object.keys(this.#devices).sort();
    }
    /** Merge supplied overrides, apply the effective state, and return a detached state snapshot. */
    async emulate(options = {}) {
        Object.assign(this.#state, copyOptions(options));
        await this.reapply();
        return copyOptions(this.#state);
    }
    /** Re-apply every active override after a browser lifecycle resume. */
    async reapply() {
        const state = this.#state;
        if (hasOwn(state, "device")) {
            const device = this.#devices[state.device];
            if (!device)
                throw new ToolError(`Unknown Puppeteer device ${JSON.stringify(state.device)}. Use tab.devices().`);
            await this.#page.emulate(device);
        }
        if (hasOwn(state, "viewport")) {
            await applyViewport(this.#page, {
                width: state.viewport.width,
                height: state.viewport.height,
                deviceScaleFactor: state.viewport.scale,
            });
        }
        if (hasOwn(state, "userAgent")) {
            if (state.userAgent !== null)
                await applyUserAgentOverride(this.#page, state.userAgent);
            else if (!hasOwn(state, "device"))
                await applyUserAgentOverride(this.#page, this.#baseUserAgent);
        }
        if (hasOwn(state, "geolocation")) {
            if (state.geolocation) {
                await this.#grantPermissions(["geolocation"]);
                await this.#page.setGeolocation(state.geolocation);
            }
            else {
                const session = await this.#page.createCDPSession();
                try {
                    await session.send("Emulation.clearGeolocationOverride");
                }
                finally {
                    await session.detach().catch(() => undefined);
                }
            }
        }
        if (hasOwn(state, "network")) {
            const conditions = this.#resolveNetworkConditions(state.network);
            await this.#page.emulateNetworkConditions(conditions);
        }
        if (hasOwn(state, "offline"))
            await this.#page.setOfflineMode(state.offline);
        if (hasOwn(state, "colorScheme") || hasOwn(state, "reducedMotion")) {
            const features = [];
            if (hasOwn(state, "colorScheme")) {
                features.push({ name: "prefers-color-scheme", value: state.colorScheme });
            }
            if (hasOwn(state, "reducedMotion")) {
                features.push({ name: "prefers-reduced-motion", value: state.reducedMotion ? "reduce" : "no-preference" });
            }
            await this.#page.emulateMediaFeatures(features);
        }
        if (hasOwn(state, "headers"))
            await this.#page.setExtraHTTPHeaders(state.headers ?? {});
        if (hasOwn(state, "credentials"))
            await this.#page.authenticate(state.credentials);
        if (hasOwn(state, "timezone"))
            await this.#page.emulateTimezone(state.timezone ?? undefined);
        if (hasOwn(state, "locale"))
            await this.#page.emulateLocale(state.locale ?? undefined);
        if (hasOwn(state, "cpuThrottling"))
            await this.#page.emulateCPUThrottling(state.cpuThrottling);
    }
    /** Read text through the page clipboard, falling back only to a prior shim write. */
    async clipboardRead() {
        try {
            await this.#grantPermissions(["clipboard-read", "clipboard-write"]);
            const text = await this.#page.evaluate(() => {
                const clipboard = globalThis
                    .navigator.clipboard;
                return clipboard.readText();
            });
            if (this.#clipboardShim !== undefined && text !== this.#clipboardShim) {
                return { text: this.#clipboardShim, source: "shim" };
            }
            return { text, source: "page" };
        }
        catch (error) {
            if (this.#clipboardShim !== undefined)
                return { text: this.#clipboardShim, source: "shim" };
            throw new ToolError("The page clipboard is unavailable and no shim value has been written", { cause: error });
        }
    }
    /** Write clipboard text through the page, retaining a worker shim only when Chromium blocks it. */
    async clipboardWrite(text) {
        try {
            await this.#grantPermissions(["clipboard-read", "clipboard-write"]);
            await this.#page.evaluate(value => {
                const clipboard = globalThis.navigator.clipboard;
                return clipboard.writeText(value);
            }, text);
            this.#clipboardShim = text;
            return { source: "page" };
        }
        catch {
            this.#clipboardShim = text;
            return { source: "shim" };
        }
    }
    /** Copy the page's current selection using the platform keyboard shortcut. */
    async clipboardCopy() {
        this.#clipboardShim = undefined;
        await this.#grantPermissions(["clipboard-read", "clipboard-write"]);
        const modifier = process.platform === "darwin" ? "Meta" : "Control";
        await pressKey(this.#page, `${modifier}+c`);
        return { source: "page" };
    }
    /** Paste the page clipboard into the focused control using the platform keyboard shortcut. */
    async clipboardPaste() {
        await this.#grantPermissions(["clipboard-read", "clipboard-write"]);
        const modifier = process.platform === "darwin" ? "Meta" : "Control";
        await pressKey(this.#page, `${modifier}+v`);
        return { source: "page" };
    }
    /** Remove page listeners owned by this controller. */
    dispose() {
        this.#page.off("framenavigated", this.#navigationHandler);
    }
    #resolveNetworkConditions(value) {
        if (value === null || value === undefined)
            return null;
        if (typeof value !== "string")
            return { ...value };
        if (value !== "slow3g" && value !== "fast3g") {
            throw new ToolError(`Unknown network preset ${JSON.stringify(value)}. Expected "slow3g" or "fast3g".`);
        }
        const key = value === "slow3g" ? "Slow 3G" : "Fast 3G";
        const conditions = this.#networkConditions[key];
        if (!conditions)
            throw new ToolError(`Puppeteer network preset ${JSON.stringify(key)} is unavailable`);
        return conditions;
    }
    async #grantPermissions(permissions) {
        const origin = pageOrigin(this.#page);
        if (!origin)
            return;
        const granted = this.#permissionsByOrigin.get(origin) ?? new Set();
        for (const permission of permissions)
            granted.add(permission);
        this.#permissionsByOrigin.set(origin, granted);
        await this.#page.browserContext().overridePermissions(origin, [...granted]);
    }
}
