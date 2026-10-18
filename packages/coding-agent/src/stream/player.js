/**
 * Terminal playback for `.ompcast` session recordings (`omp play`).
 *
 * Plays on the normal screen, like the recorded session itself: the recorded
 * viewport occupies the bottom rows of the terminal and recorded `history`
 * rows scroll into the terminal's native scrollback above it, so the output
 * stays inspectable after playback ends.
 */
import { replaceTabs, truncateToWidth } from "@rva/tui";
import { applyScreenFrame } from "./protocol";
const SYNC_BEGIN = "\x1b[?2026h";
const SYNC_END = "\x1b[?2026l";
const OSC8_CLOSE = "\x1b]8;;\x1b\\";
/**
 * Play a recording in the controlling terminal until it ends or the viewer
 * quits. Keys: space pauses/resumes, `q`/Esc/Ctrl-C quits.
 */
export async function playRecording(recording, options) {
    const out = process.stdout;
    const painter = new ScreenPainter(recording.header, () => ({ width: out.columns || 80, height: out.rows || 24 }));
    const control = new PlaybackControl();
    const onResize = () => {
        painter.invalidate();
        out.write(painter.flush());
    };
    out.write(painter.begin());
    out.on("resize", onResize);
    try {
        const idleLimit = options.idleLimitMs ?? Number.POSITIVE_INFINITY;
        const { events } = recording;
        let previous = 0;
        for (let index = 0; index < events.length;) {
            const at = events[index].at;
            const gap = Math.min(Math.max(0, at - previous), idleLimit) / options.speed;
            previous = at;
            if (!(await control.wait(gap)))
                return;
            while (index < events.length && events[index].at === at)
                painter.apply(events[index++].frame);
            out.write(painter.flush());
        }
    }
    finally {
        out.off("resize", onResize);
        control.dispose();
        out.write(painter.end());
    }
}
/**
 * Mirrors a recorded screen onto the terminal. The live region is the bottom
 * `min(terminal rows, viewport rows)` rows; output is accumulated per frame
 * batch and emitted as one synchronized update.
 */
class ScreenPainter {
    #screen;
    #size;
    /** Rows currently shown in the live region, top to bottom; `null` marks a row needing repaint. */
    #painted = [];
    #out = "";
    constructor(header, size) {
        this.#screen = { cols: header.cols, rows: header.rows, history: [], viewport: [] };
        this.#size = size;
    }
    /** Claim the screen below the cursor, hide the cursor, and disable autowrap. */
    begin() {
        return `\x1b[?25l\x1b[?7l${"\n".repeat(Math.max(0, this.#size().height - 1))}`;
    }
    /** Leave the final frame on screen with the cursor on a fresh line below it. */
    end() {
        return `${this.flush()}\x1b[0m\x1b[${this.#size().height};1H\n\x1b[?7h\x1b[?25h`;
    }
    /** Terminal geometry changed: clear the screen and repaint the region from scratch. */
    invalidate() {
        this.#out += "\x1b[0m\x1b[2J";
        this.#painted = [];
    }
    apply(frame) {
        if (frame.t === "reset") {
            // The recorded session wiped its scrollback (history replay); mirror it.
            this.#out += "\x1b[0m\x1b[H\x1b[2J\x1b[3J";
            this.#painted = [];
        }
        else if (frame.t === "history") {
            this.#commit(frame.rows);
        }
        applyScreenFrame(this.#screen, frame);
    }
    /** Paint the live region and drain accumulated output. */
    flush() {
        const { width, height } = this.#size();
        const rows = this.#screen.viewport;
        const count = Math.min(height, rows.length);
        const view = rows.slice(rows.length - count);
        const top = height - count + 1;
        const previous = this.#painted;
        // The region shrank: rows above its new top would otherwise read as scrollback.
        for (let row = height - previous.length + 1; row < top; row++)
            this.#out += `\x1b[${row};1H\x1b[0m\x1b[2K`;
        const full = previous.length !== count;
        for (let index = 0; index < count; index++) {
            if (!full && previous[index] === view[index])
                continue;
            this.#out += this.#line(top + index, view[index], width);
        }
        this.#painted = view;
        const out = this.#out;
        this.#out = "";
        return out ? SYNC_BEGIN + out + SYNC_END : "";
    }
    /**
     * Push rows into native scrollback directly above the live region: write
     * them into the region's top rows, then scroll the whole screen up by as
     * many lines. With no region, scroll first and write into the bottom rows.
     */
    #commit(rows) {
        const { width, height } = this.#size();
        const region = this.#painted.length;
        const capacity = region > 0 ? region : height;
        const top = height - region + 1;
        for (let start = 0; start < rows.length; start += capacity) {
            const chunk = rows.slice(start, start + capacity);
            const scroll = `\x1b[${height};1H${"\n".repeat(chunk.length)}`;
            if (region > 0) {
                for (const [index, row] of chunk.entries())
                    this.#out += this.#line(top + index, row, width);
                this.#out += scroll;
            }
            else {
                this.#out += scroll;
                const first = height - chunk.length + 1;
                for (const [index, row] of chunk.entries())
                    this.#out += this.#line(first + index, row, width);
            }
        }
        this.#painted = this.#painted.map(() => null);
    }
    #line(row, content, width) {
        const fitted = truncateToWidth(replaceTabs(content), width, "");
        const close = fitted.includes("\x1b]8;") ? OSC8_CLOSE : "";
        return `\x1b[${row};1H\x1b[0m\x1b[2K${fitted}\x1b[0m${close}`;
    }
}
/** Raw-mode keyboard control and a pausable, interruptible clock. */
class PlaybackControl {
    #paused = false;
    #quit = false;
    #wake = Promise.withResolvers();
    #raw;
    constructor() {
        const stdin = process.stdin;
        this.#raw = stdin.isTTY === true;
        if (this.#raw)
            stdin.setRawMode(true);
        stdin.on("data", this.#onData);
        stdin.resume();
    }
    #onData = (data) => {
        const input = data.toString("utf8");
        // A lone ESC quits; other ESC-prefixed input (arrow keys, …) is ignored.
        if (input.startsWith("\x1b") && input !== "\x1b")
            return;
        if (input === "\x1b" || input.includes("q") || input.includes("\x03"))
            this.#quit = true;
        else if (input.includes(" "))
            this.#paused = !this.#paused;
        else
            return;
        const wake = this.#wake;
        this.#wake = Promise.withResolvers();
        wake.resolve();
    };
    /** Let `ms` of unpaused time pass; false once the viewer quits. */
    async wait(ms) {
        let remaining = ms;
        while (!this.#quit && (this.#paused || remaining > 0)) {
            if (this.#paused) {
                await this.#wake.promise;
                continue;
            }
            const started = performance.now();
            const timer = Promise.withResolvers();
            const handle = setTimeout(timer.resolve, remaining);
            await Promise.race([timer.promise, this.#wake.promise]);
            clearTimeout(handle);
            remaining -= performance.now() - started;
        }
        return !this.#quit;
    }
    dispose() {
        const stdin = process.stdin;
        stdin.off("data", this.#onData);
        if (this.#raw)
            stdin.setRawMode(false);
        stdin.pause();
    }
}
