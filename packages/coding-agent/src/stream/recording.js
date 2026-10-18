/**
 * Session recordings (`/record`, `omp play`).
 *
 * A recording is the single-pane `omp stream` feed persisted to disk: the same
 * normalized, redacted screen frames {@link StreamPaintEncoder} produces for
 * live viewers, stamped with their offset from the start of the recording.
 *
 * File format (`.ompcast`, JSON Lines, asciicast-like):
 *
 * ```text
 * {"ompcast":1,"cols":120,"rows":40,"title":"pi","createdAt":"2026-09-22T10:00:00.000Z"}
 * [0,{"t":"viewport","rows":["…","…"]}]
 * [51,{"t":"patch","ops":[[39,"…"]],"rows":40}]
 * [880,{"t":"history","rows":["…"]}]
 * ```
 *
 * Line 1 is the header; every following line is `[ms, frame]` where `frame` is
 * a {@link StreamScreenFrame}. A truncated final line (recorder killed
 * mid-write) is ignored on load.
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { isEnoent } from "@rva/utils";
import { STREAM_FLUSH_INTERVAL_MS, StreamPaintEncoder } from "./paint-encoder";
import { isDimension, isSessionFrame } from "./protocol";
export const RECORDING_VERSION = 1;
export const RECORDING_EXTENSION = ".ompcast";
/** Directory `/record` writes into (temporary storage for now). */
export function recordingsDir() {
    return path.join(os.tmpdir(), "rva-recordings");
}
/** Fresh, sortable recording path for one session: `<recordingsDir>/<utc-stamp>-<session>.ompcast`. */
export function newRecordingPath(sessionId) {
    const stamp = new Date()
        .toISOString()
        .replace(/\.\d+Z$/, "")
        .replaceAll(":", "-");
    return path.join(recordingsDir(), `${stamp}-${sessionId.slice(0, 8)}${RECORDING_EXTENSION}`);
}
/** Newest recording in {@link recordingsDir}, or null when there is none. */
export async function latestRecording() {
    const dir = recordingsDir();
    let names;
    try {
        names = await fs.readdir(dir);
    }
    catch (error) {
        if (isEnoent(error))
            return null;
        throw error;
    }
    let latest = null;
    for (const name of names) {
        if (!name.endsWith(RECORDING_EXTENSION))
            continue;
        const file = path.join(dir, name);
        const { mtimeMs } = await fs.stat(file);
        if (!latest || mtimeMs > latest.mtimeMs)
            latest = { file, mtimeMs };
    }
    return latest?.file ?? null;
}
/**
 * Parse a recording file's contents.
 *
 * @throws {Error} when the header is missing/unsupported or a complete line is
 *   not a valid `[ms, frame]` event.
 */
export function parseRecording(text) {
    const { values, error } = Bun.JSONL.parseChunk(text);
    if (error)
        throw new Error(`malformed recording: ${error.message}`);
    const [header, ...lines] = values;
    if (!isRecordingHeader(header))
        throw new Error("not an omp recording (missing ompcast header)");
    if (header.ompcast !== RECORDING_VERSION)
        throw new Error(`unsupported recording version ${header.ompcast}`);
    const events = [];
    for (const [index, line] of lines.entries()) {
        if (!Array.isArray(line) ||
            line.length !== 2 ||
            !isDimension(line[0]) ||
            !isSessionFrame(line[1]) ||
            line[1].t === "hello" ||
            line[1].t === "paused") {
            throw new Error(`malformed recording event on line ${index + 2}`);
        }
        events.push({ at: line[0], frame: line[1] });
    }
    return { header, events };
}
function isRecordingHeader(value) {
    if (!value || typeof value !== "object")
        return false;
    const header = value;
    return (typeof header.ompcast === "number" &&
        isDimension(header.cols) &&
        isDimension(header.rows) &&
        typeof header.title === "string" &&
        typeof header.createdAt === "string");
}
/** Records one interactive session's painted screen to an `.ompcast` file. */
export class SessionRecorder {
    path;
    #encoder;
    #writer;
    #startedAt = performance.now();
    #lastPaintAt = 0;
    #flushTimer;
    #unsubscribe;
    /** Open the file, write the header, and start observing paints. */
    static async start(options) {
        await fs.mkdir(path.dirname(options.path), { recursive: true });
        return new SessionRecorder(options);
    }
    constructor(options) {
        this.path = options.path;
        const size = { columns: options.tui.terminal.columns, rows: options.tui.terminal.rows };
        this.#encoder = new StreamPaintEncoder(size, options.redactor);
        this.#writer = Bun.file(options.path).writer();
        const header = {
            ompcast: RECORDING_VERSION,
            cols: size.columns,
            rows: size.rows,
            title: options.title,
            createdAt: new Date().toISOString(),
        };
        this.#writer.write(`${JSON.stringify(header)}\n`);
        this.#unsubscribe = options.tui.addPaintListener(paint => {
            this.#encoder.push(paint);
            this.#lastPaintAt = performance.now() - this.#startedAt;
            this.#flushTimer ??= setTimeout(() => {
                this.#flushTimer = undefined;
                this.#flush();
            }, STREAM_FLUSH_INTERVAL_MS).unref();
        });
        // Seed the recording with the current screen instead of waiting for the next change.
        options.tui.requestRender(true);
    }
    /** Milliseconds recorded so far. */
    get elapsedMs() {
        return performance.now() - this.#startedAt;
    }
    /** Stop observing, write pending frames, and close the file. Idempotent. */
    async stop() {
        if (!this.#unsubscribe)
            return;
        this.#unsubscribe();
        this.#unsubscribe = undefined;
        clearTimeout(this.#flushTimer);
        this.#flushTimer = undefined;
        this.#flush();
        await this.#writer.end();
    }
    #flush() {
        const at = Math.round(this.#lastPaintAt);
        let chunk = "";
        for (const frame of this.#encoder.drain())
            chunk += `${JSON.stringify([at, frame])}\n`;
        if (!chunk)
            return;
        this.#writer.write(chunk);
        this.#writer.flush();
    }
}
