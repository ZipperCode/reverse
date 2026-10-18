import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Snowflake } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { resolveToCwd } from "../path-utils";
function outputPath(requested, cwd, extension) {
    if (requested)
        return resolveToCwd(requested, cwd);
    return path.join(os.tmpdir(), `omp-browser-${Snowflake.next()}.${extension}`);
}
/** Stateful trace and CPU-profile controller for one Puppeteer page. */
export class BrowserTracingController {
    #page;
    #traceActive = false;
    #profileSession;
    constructor(page) {
        this.#page = page;
    }
    /** Start Chromium tracing for this page's browser connection. */
    async traceStart(options = {}) {
        if (this.#traceActive)
            throw new ToolError("tab.traceStart() cannot start while a trace is already active");
        await this.#page.tracing.start({ screenshots: options.screenshots, categories: options.categories });
        this.#traceActive = true;
    }
    /** Stop Chromium tracing, save its JSON, and return the absolute path. */
    async traceStop(cwd, options = {}) {
        if (!this.#traceActive)
            throw new ToolError("tab.traceStop() requires an active trace");
        const destination = outputPath(options.path, cwd, "json");
        await fs.promises.mkdir(path.dirname(destination), { recursive: true });
        try {
            const trace = await this.#page.tracing.stop();
            if (!trace)
                throw new ToolError("Chromium tracing stopped without producing trace data");
            await Bun.write(destination, trace);
            return destination;
        }
        finally {
            this.#traceActive = false;
        }
    }
    /** Start a Chromium DevTools CPU profile for the page. */
    async profileStart() {
        if (this.#profileSession)
            throw new ToolError("tab.profileStart() cannot start while a profile is already active");
        const session = await this.#page.createCDPSession();
        try {
            await session.send("Profiler.enable");
            await session.send("Profiler.start");
            this.#profileSession = session;
        }
        catch (error) {
            await session.detach().catch(() => undefined);
            throw error;
        }
    }
    /** Stop the active CPU profile, save it, and return the absolute path. */
    async profileStop(cwd, options = {}) {
        const session = this.#profileSession;
        if (!session)
            throw new ToolError("tab.profileStop() requires an active profile");
        this.#profileSession = undefined;
        const destination = outputPath(options.path, cwd, "cpuprofile");
        await fs.promises.mkdir(path.dirname(destination), { recursive: true });
        try {
            const { profile } = await session.send("Profiler.stop");
            await Bun.write(destination, JSON.stringify(profile));
            return destination;
        }
        finally {
            await session.send("Profiler.disable").catch(() => undefined);
            await session.detach().catch(() => undefined);
        }
    }
    /** Return Puppeteer metrics plus navigation-relative DOMContentLoaded and load durations. */
    async metrics() {
        const [pageMetrics, timing] = await Promise.all([
            this.#page.metrics(),
            this.#page.evaluate(() => {
                const values = globalThis.performance.timing;
                return {
                    navigationStart: values.navigationStart,
                    domContentLoadedEventEnd: values.domContentLoadedEventEnd,
                    loadEventEnd: values.loadEventEnd,
                };
            }),
        ]);
        const metrics = {};
        for (const name in pageMetrics) {
            const value = pageMetrics[name];
            if (typeof value === "number")
                metrics[name] = value;
        }
        const navigationStart = timing.navigationStart;
        return {
            ...metrics,
            domContentLoaded: navigationStart > 0 && timing.domContentLoadedEventEnd > 0
                ? timing.domContentLoadedEventEnd - navigationStart
                : 0,
            load: navigationStart > 0 && timing.loadEventEnd > 0 ? timing.loadEventEnd - navigationStart : 0,
        };
    }
    /** Stop and discard active trace/profile state during tab teardown. */
    async dispose() {
        if (this.#traceActive) {
            this.#traceActive = false;
            await this.#page.tracing.stop().catch(() => undefined);
        }
        const session = this.#profileSession;
        this.#profileSession = undefined;
        if (session) {
            await session.send("Profiler.stop").catch(() => undefined);
            await session.send("Profiler.disable").catch(() => undefined);
            await session.detach().catch(() => undefined);
        }
    }
}
