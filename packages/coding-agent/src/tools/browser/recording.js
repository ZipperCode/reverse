import * as fs from "node:fs/promises";
import * as path from "node:path";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { untilAborted } from "@rva/utils/abortable";
import { TempDir } from "@rva/utils/temp";
import { resizeImage } from "../../utils/image-resize";
import { buildChangedFrameContactSheetPng, requireMediaBinary, runFfmpeg } from "../../utils/video";
import { resolveToCwd } from "../path-utils";
import { readPageViewport } from "./launch";
const DEFAULT_FPS = 30;
const DEFAULT_QUALITY = 80;
const DEFAULT_CONTACT_SHEET_THRESHOLD = 0.02;
const MAX_CONTACT_SHEET_TILES = 12;
/** Named user-facing recording failure raised by every `tab.record*` helper. */
export class BrowserRecordingError extends ToolError {
    constructor(message) {
        super(message);
        this.name = "BrowserRecordingError";
    }
}
function validateNumber(label, value, min, max) {
    if (!Number.isFinite(value) || value < min || value > max) {
        throw new BrowserRecordingError(`${label} must be a finite number from ${min} through ${max}`);
    }
    return value;
}
function validateOptions(options) {
    if (options !== undefined && (options === null || typeof options !== "object" || Array.isArray(options))) {
        throw new BrowserRecordingError("tab.recordStart() options must be an object");
    }
    const fps = validateNumber("tab.recordStart() fps", options?.fps ?? DEFAULT_FPS, 1, 60);
    const quality = validateNumber("tab.recordStart() quality", options?.quality ?? DEFAULT_QUALITY, 0, 100);
    const contactSheetThreshold = validateNumber("tab.recordStart() contactSheetThreshold", options?.contactSheetThreshold ?? DEFAULT_CONTACT_SHEET_THRESHOLD, 0, 1);
    return {
        fps,
        quality: Math.round(quality),
        cursor: options?.cursor ?? false,
        contactSheet: options?.contactSheet ?? false,
        contactSheetThreshold,
    };
}
function recordingError(error, action) {
    if (error instanceof BrowserRecordingError)
        return error;
    const message = error instanceof Error ? error.message : String(error);
    return new BrowserRecordingError(`${action} failed: ${message}`);
}
/** Page function (self-contained): draw a pointer and click ripples that follow page mouse events. Re-entrant. */
export function installCursorOverlay() {
    const state = globalThis;
    const document = state.document;
    state.__ompRecordingCursorCleanup?.();
    let root;
    let pointer;
    const onMove = (event) => {
        if (pointer)
            pointer.style.transform = `translate(${event.clientX}px, ${event.clientY}px)`;
    };
    const onDown = (event) => {
        if (!root)
            return;
        const ripple = document.createElement("div");
        ripple.className = "ripple";
        ripple.style.left = `${event.clientX}px`;
        ripple.style.top = `${event.clientY}px`;
        root.shadowRoot?.append(ripple);
        ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
    };
    const mount = () => {
        if (document.getElementById("__omp_recording_cursor__"))
            return;
        root = document.createElement("div");
        root.id = "__omp_recording_cursor__";
        root.setAttribute("aria-label", "OMP recording cursor overlay");
        root.setAttribute("aria-hidden", "true");
        root.setAttribute("inert", "");
        root.style.cssText = "position:fixed;inset:0;z-index:2147483647;pointer-events:none;overflow:hidden";
        const shadow = root.attachShadow({ mode: "open" });
        const style = document.createElement("style");
        style.textContent =
            ".pointer{position:absolute;left:0;top:0;width:0;height:0;border-left:8px solid white;border-top:14px solid black;border-right:4px solid transparent;filter:drop-shadow(0 0 1px white);transform:translate(-100px,-100px);transform-origin:0 0}.ripple{position:absolute;width:8px;height:8px;margin:-4px;border:2px solid #fff;border-radius:999px;box-shadow:0 0 0 1px #000;animation:omp-recording-ripple .45s ease-out forwards}@keyframes omp-recording-ripple{to{width:34px;height:34px;margin:-17px;opacity:0}}";
        pointer = document.createElement("div");
        pointer.className = "pointer";
        shadow.append(style, pointer);
        document.documentElement?.append(root);
    };
    if (document.documentElement)
        mount();
    else
        document.addEventListener("DOMContentLoaded", mount, { once: true });
    state.addEventListener("mousemove", onMove, true);
    state.addEventListener("mousedown", onDown, true);
    state.__ompRecordingCursorCleanup = () => {
        document.removeEventListener("DOMContentLoaded", mount);
        state.removeEventListener("mousemove", onMove, true);
        state.removeEventListener("mousedown", onDown, true);
        root?.remove();
        document.getElementById("__omp_recording_cursor__")?.remove();
        delete state.__ompRecordingCursorCleanup;
    };
}
/** Page function removing the cursor overlay `installCursorOverlay` drew, and its listeners. */
export function removeCursorOverlay() {
    const state = globalThis;
    state.__ompRecordingCursorCleanup?.();
    state.document.getElementById("__omp_recording_cursor__")?.remove();
}
class CdpRecordingSource {
    #page;
    #session;
    #deliver;
    #stopping;
    #cursorScriptId;
    #onScreencastFrame = (event) => {
        const session = this.#session;
        const deliver = this.#deliver;
        if (!session || !deliver)
            return;
        const timestampMs = typeof event.metadata.timestamp === "number" ? event.metadata.timestamp * 1000 : Date.now();
        const ack = () => {
            void session.send("Page.screencastFrameAck", { sessionId: event.sessionId }).catch(() => undefined);
        };
        void deliver({ data: Buffer.from(event.data, "base64"), timestampMs }).then(ack, ack);
    };
    constructor(page) {
        this.#page = page;
    }
    async viewport(signal) {
        return await readPageViewport(this.#page, signal);
    }
    async start(params, signal) {
        this.#stopping = undefined;
        const session = await untilAborted(signal, () => this.#page.createCDPSession());
        this.#session = session;
        this.#deliver = params.onFrame;
        session.on("Page.screencastFrame", this.#onScreencastFrame);
        await untilAborted(signal, () => session.send("Page.startScreencast", {
            format: "jpeg",
            quality: params.quality,
            maxWidth: params.maxWidth,
            maxHeight: params.maxHeight,
            everyNthFrame: params.everyNthFrame,
        }));
    }
    async stop() {
        this.#stopping ??= this.#stopSession();
        await this.#stopping;
    }
    async captureFrame(quality, signal) {
        return await untilAborted(signal, () => this.#page.screenshot({ type: "jpeg", quality }));
    }
    async installCursor(signal) {
        const script = await untilAborted(signal, () => this.#page.evaluateOnNewDocument(installCursorOverlay));
        this.#cursorScriptId = script.identifier;
        await untilAborted(signal, () => this.#page.evaluate(installCursorOverlay));
    }
    async removeCursor() {
        const scriptId = this.#cursorScriptId;
        this.#cursorScriptId = undefined;
        if (scriptId)
            await this.#page.removeScriptToEvaluateOnNewDocument(scriptId).catch(() => undefined);
        await this.#page.evaluate(removeCursorOverlay).catch(() => undefined);
    }
    async #stopSession() {
        const session = this.#session;
        if (!session)
            return;
        try {
            await session.send("Page.stopScreencast");
        }
        finally {
            session.off("Page.screencastFrame", this.#onScreencastFrame);
            this.#session = undefined;
            this.#deliver = undefined;
            await session.detach().catch(() => undefined);
        }
    }
}
/** Frame source backed by a CDP `Page.startScreencast` session on `page`. */
export function createCdpRecordingSource(page) {
    return new CdpRecordingSource(page);
}
function concatPath(filePath) {
    return filePath.replaceAll("'", "'\\''");
}
async function encodeRecording(active, durationMs, signal) {
    const frames = active.frames;
    const firstTimestamp = frames[0].timestampMs;
    const framePeriodMs = 1000 / active.options.fps;
    const encodedDurationMs = Math.max(durationMs, framePeriodMs);
    const offsets = [];
    let previous = 0;
    for (const [index, frame] of frames.entries()) {
        const observed = index === 0 ? 0 : Math.max(0, frame.timestampMs - firstTimestamp);
        const clamped = Math.min(encodedDurationMs, Math.max(previous, observed));
        offsets.push(clamped);
        previous = clamped;
    }
    const concatLines = [];
    for (let index = 0; index < frames.length; index++) {
        const frame = frames[index];
        const current = offsets[index];
        const next = index + 1 < frames.length ? offsets[index + 1] : encodedDurationMs;
        concatLines.push(`file '${concatPath(path.resolve(frame.path))}'`);
        concatLines.push(`duration ${(Math.max(1, next - current) / 1000).toFixed(6)}`);
    }
    concatLines.push(`file '${concatPath(path.resolve(frames.at(-1).path))}'`);
    const concatFile = active.spool.join("frames.concat");
    await Bun.write(concatFile, `${concatLines.join("\n")}\n`);
    const absoluteConcatFile = path.resolve(concatFile);
    await fs.mkdir(path.dirname(active.path), { recursive: true });
    const quality = active.options.quality;
    const fpsFilter = `fps=${active.options.fps}`;
    const extension = path.extname(active.path).toLowerCase();
    if (extension === ".mp4") {
        await runFfmpeg([
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            absoluteConcatFile,
            "-an",
            "-vf",
            `${fpsFilter},scale=trunc(iw/2)*2:trunc(ih/2)*2`,
            "-c:v",
            "libx264",
            "-crf",
            String(Math.round(((100 - quality) * 51) / 100)),
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            active.path,
        ], signal);
        return;
    }
    const input = ["-f", "concat", "-safe", "0", "-i", absoluteConcatFile, "-an", "-vf", fpsFilter];
    try {
        await runFfmpeg([
            ...input,
            "-c:v",
            "libvpx-vp9",
            "-crf",
            String(Math.round(((100 - quality) * 63) / 100)),
            "-b:v",
            "0",
            "-deadline",
            "realtime",
            "-cpu-used",
            "5",
            active.path,
        ], signal);
    }
    catch (error) {
        if (signal?.aborted)
            throw error;
        await runFfmpeg([
            ...input,
            "-c:v",
            "libvpx",
            "-crf",
            String(Math.round(((100 - quality) * 63) / 100)),
            "-b:v",
            "1M",
            active.path,
        ], signal);
    }
}
/** Persistent, disk-backed recording state owned by one tab worker. */
export class RecordingController {
    #active;
    #starting = false;
    /** Start recording frames from `source` to an absolute cwd-resolved MP4 or WebM path. */
    async start(source, rawPath, cwd, options, signal) {
        if (this.#active)
            throw new BrowserRecordingError(`A recording is already active at ${this.#active.path}`);
        if (this.#starting)
            throw new BrowserRecordingError("A recording is already starting");
        if (typeof rawPath !== "string" || rawPath.trim().length === 0) {
            throw new BrowserRecordingError("tab.recordStart() requires a non-empty output path");
        }
        const absolutePath = resolveToCwd(rawPath, cwd);
        const extension = path.extname(absolutePath).toLowerCase();
        if (extension !== ".mp4" && extension !== ".webm") {
            throw new BrowserRecordingError("tab.recordStart() path must end in .mp4 or .webm");
        }
        const validated = validateOptions(options);
        try {
            requireMediaBinary("ffmpeg");
        }
        catch (error) {
            throw recordingError(error, "tab.recordStart()");
        }
        this.#starting = true;
        let spool;
        try {
            spool = await TempDir.create("@omp-browser-recording-");
            if (validated.cursor)
                await source.installCursor(signal);
            const viewport = await source.viewport(signal);
            const active = {
                source,
                spool,
                path: absolutePath,
                options: validated,
                startedAt: Date.now(),
                frames: [],
                pendingWrites: new Set(),
                nextFrame: 0,
                finalizing: false,
            };
            const onFrame = (frame) => {
                const index = active.nextFrame++;
                const framePath = active.spool.join(`frame-${String(index).padStart(9, "0")}.jpg`);
                active.frames.push({ path: framePath, timestampMs: frame.timestampMs });
                const write = Bun.write(framePath, frame.data)
                    .then(() => undefined)
                    .catch(error => {
                    active.writeError ??= error;
                })
                    .finally(() => {
                    active.pendingWrites.delete(write);
                });
                active.pendingWrites.add(write);
                return write;
            };
            await source.start({
                quality: validated.quality,
                maxWidth: Math.max(1, Math.round(viewport.width)),
                maxHeight: Math.max(1, Math.round(viewport.height)),
                everyNthFrame: Math.max(1, Math.round(60 / validated.fps)),
                onFrame,
            }, signal);
            this.#active = active;
            return { path: absolutePath, fps: validated.fps };
        }
        catch (error) {
            if (validated.cursor)
                await source.removeCursor();
            await source.stop().catch(() => undefined);
            await spool?.remove().catch(() => undefined);
            throw recordingError(error, "tab.recordStart()");
        }
        finally {
            this.#starting = false;
        }
    }
    /** Stop and finalize the active recording. */
    async stop(context = {}) {
        const active = this.#active;
        if (!active)
            throw new BrowserRecordingError("tab.recordStop() requires an active recording");
        if (active.finalizing)
            throw new BrowserRecordingError("tab.recordStop() is already finalizing the active recording");
        active.finalizing = true;
        const durationMs = Math.max(0, Date.now() - active.startedAt);
        const contactPath = `${active.path}.contact.png`;
        let finalized = false;
        try {
            await untilAborted(context.signal, () => active.source.stop());
            await Promise.all(active.pendingWrites);
            if (active.writeError)
                throw active.writeError;
            if (active.options.cursor)
                await active.source.removeCursor();
            if (active.frames.length === 0) {
                const fallback = active.spool.join("frame-000000000.jpg");
                const bytes = await active.source.captureFrame(active.options.quality, context.signal);
                await Bun.write(fallback, bytes);
                active.frames.push({ path: fallback, timestampMs: 0 });
            }
            await encodeRecording(active, durationMs, context.signal);
            let contactSheet;
            if (active.options.contactSheet) {
                const sheet = await buildChangedFrameContactSheetPng(active.path, {
                    outputPath: contactPath,
                    fps: active.options.fps,
                    threshold: active.options.contactSheetThreshold,
                    maxTiles: MAX_CONTACT_SHEET_TILES,
                }, context.signal);
                contactSheet = sheet.path;
                if (context.output) {
                    const resized = await resizeImage({ type: "image", data: sheet.png.data, mimeType: sheet.png.mimeType }, { excludeWebP: context.excludeWebP });
                    context.output.push({ type: "image", data: resized.data, mimeType: resized.mimeType });
                }
            }
            const stat = await fs.stat(active.path);
            finalized = true;
            return {
                path: active.path,
                durationMs,
                frames: active.frames.length,
                bytes: stat.size,
                ...(contactSheet ? { contactSheet } : {}),
            };
        }
        catch (error) {
            throw recordingError(error, "tab.recordStop()");
        }
        finally {
            await active.source.stop().catch(() => undefined);
            await Promise.all(active.pendingWrites);
            if (active.options.cursor)
                await active.source.removeCursor();
            await active.spool.remove().catch(() => undefined);
            if (this.#active === active)
                this.#active = undefined;
            if (!finalized) {
                await fs.rm(active.path, { force: true }).catch(() => undefined);
                await fs.rm(contactPath, { force: true }).catch(() => undefined);
            }
        }
    }
    /** Finalize an active recording, then immediately begin another. */
    async restart(source, rawPath, cwd, options, context = {}) {
        if (this.#active)
            await this.stop(context);
        return await this.start(source, rawPath, cwd, options, context.signal);
    }
    /** Return the current persistent recording state without touching the page. */
    status() {
        const active = this.#active;
        if (!active)
            return { active: false };
        return {
            active: true,
            path: active.path,
            fps: active.options.fps,
            durationMs: Math.max(0, Date.now() - active.startedAt),
            frames: active.frames.length,
        };
    }
    /** Finalize the active recording during tab teardown, discarding failed output. */
    async close() {
        if (!this.#active)
            return;
        await this.stop();
    }
}
