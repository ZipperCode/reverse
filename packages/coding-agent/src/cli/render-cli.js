/**
 * `omp render` — draw a session's entire thread through the production
 * transcript pipeline, headlessly.
 *
 * Replays the session into a real `InteractiveMode` + `TUI` wired to an
 * in-process byte-sink terminal, then prints the composed transcript lines.
 * `--timing` reports phase costs; `--repaint N` re-runs the clear-scrollback
 * full repaint that `/tree`, Esc-Esc navigation, `/resume`, and theme changes
 * issue — the frame whose cost users feel as a frozen UI on big sessions.
 *
 * The session file is copied to a temp dir before opening, so rendering never
 * takes the single-writer lock on (or appends breadcrumbs to) a live session.
 */
import { Database } from "bun:sqlite";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Agent } from "@rva/agent";
import { formatBytes, getProjectDir, logger, TempDir } from "@rva/utils";
import { VERSION } from "@rva/utils/dirs";
import { ModelRegistry } from "../config/model-registry";
import { Settings } from "../config/settings";
import { Composer } from "@rva/tui/prompt/composer";
import { InteractiveMode } from "../modes/interactive-mode";
import { initTheme } from "@rva/tui/theme";
import { AgentSession } from "../session/agent-session";
import { AuthStorage, SqliteAuthCredentialStore } from "../session/auth-storage";
import { resolveSessionFileArg } from "./session-arg";
import { SessionManager } from "../session/session-manager";
/** Byte-sink terminal: counts emitted output, never touches a real TTY. */
class SinkTerminal {
    bytes = 0;
    writes = 0;
    #columns;
    #rows;
    constructor(columns, rows) {
        this.#columns = columns;
        this.#rows = rows;
    }
    start() { }
    stop() { }
    async drainInput() { }
    write(data) {
        this.bytes += Buffer.byteLength(data);
        this.writes++;
    }
    get columns() {
        return this.#columns;
    }
    get rows() {
        return this.#rows;
    }
    get kittyProtocolActive() {
        return false;
    }
    get kittyEnableSequence() {
        return null;
    }
    moveBy() { }
    hideCursor() { }
    showCursor() { }
    clearLine() { }
    clearFromCursor() { }
    clearScreen() { }
    setTitle() { }
    setProgress() { }
    onAppearanceChange() { }
    refreshAppearance(_requestToken) { }
    get appearance() {
        return undefined;
    }
}
/**
 * Deterministic render scheduler: queues callbacks instead of arming timers so
 * the command can drain every pending paint synchronously between phases.
 */
class DrainScheduler {
    #time = 0;
    #immediate = [];
    #renders = new Map();
    #nextId = 0;
    now() {
        this.#time += 20;
        return this.#time;
    }
    scheduleImmediate(callback) {
        this.#immediate.push(callback);
    }
    scheduleRender(callback, _delayMs) {
        const id = this.#nextId++;
        this.#renders.set(id, callback);
        return { cancel: () => void this.#renders.delete(id) };
    }
    /** Run queued callbacks until no render work remains. */
    drain() {
        for (let rounds = 0; this.#immediate.length > 0 || this.#renders.size > 0; rounds++) {
            if (rounds > 100)
                throw new Error("render scheduler did not settle after 100 drain rounds");
            const immediate = this.#immediate;
            this.#immediate = [];
            for (const callback of immediate)
                callback();
            if (this.#renders.size === 0)
                continue;
            const renders = [...this.#renders.values()];
            this.#renders.clear();
            for (const callback of renders)
                callback();
        }
    }
}
function formatMs(ms) {
    return `${ms.toFixed(0)} ms`;
}
/** Render the resolved session and report timings. Returns the exit code. */
export async function runRenderCommand(args) {
    const cwd = getProjectDir();
    const settings = await Settings.init({ cwd });
    await initTheme();
    const sourcePath = await resolveSessionFileArg(args.session, cwd);
    const sourceSize = (await fs.stat(sourcePath)).size;
    // Copy before opening: SessionManager.open takes the single-writer lock and
    // session teardown appends a session_exit entry — neither may touch a live
    // session file the user has open in another omp.
    const tempDir = TempDir.createSync("@omp-render-");
    const workingCopy = path.join(tempDir.path(), path.basename(sourcePath));
    const width = args.width ?? (process.stdout.isTTY ? process.stdout.columns : undefined) ?? 120;
    const height = args.height ?? (process.stdout.isTTY ? process.stdout.rows : undefined) ?? 40;
    let session;
    let mode;
    try {
        await fs.copyFile(sourcePath, workingCopy);
        const openStart = performance.now();
        const sessionManager = await SessionManager.open(workingCopy, undefined, undefined, {
            suppressBreadcrumb: true,
        });
        const openMs = performance.now() - openStart;
        const authStorage = new AuthStorage(new SqliteAuthCredentialStore(new Database(":memory:")));
        const modelRegistry = new ModelRegistry(authStorage);
        const model = modelRegistry.getAll()[0];
        if (!model)
            throw new Error("No models available in the bundled catalog");
        session = new AgentSession({
            agent: new Agent({ initialState: { model, systemPrompt: [], tools: [], messages: [] } }),
            sessionManager,
            settings,
            modelRegistry,
        });
        const terminal = new SinkTerminal(width, height);
        const scheduler = new DrainScheduler();
        const composer = new Composer({
            terminal,
            tuiOptions: { renderScheduler: scheduler },
            preferences: { quiet: true },
        });
        mode = new InteractiveMode(session, VERSION, undefined, undefined, undefined, undefined, undefined, composer);
        await mode.init({ suppressWelcomeIntro: true });
        scheduler.drain();
        // Replay: transcript context build + component construction (the phase
        // renderInitialMessages runs after /tree navigation and on resume).
        const replayStart = performance.now();
        await mode.renderInitialMessages({ clearTerminalHistory: true });
        const replayMs = performance.now() - replayStart;
        // First full paint: compose every transcript row and emit it, exactly
        // what the clear-scrollback repaint after navigation writes to the PTY.
        const paintStart = performance.now();
        const bytesBeforePaint = terminal.bytes;
        scheduler.drain();
        const paintMs = performance.now() - paintStart;
        const paintBytes = terminal.bytes - bytesBeforePaint;
        const entries = sessionManager.getEntries();
        let messageCount = 0;
        for (const entry of entries)
            if (entry.type === "message")
                messageCount++;
        const repaints = [];
        for (let i = 0; i < (args.repaint ?? 0); i++) {
            const start = performance.now();
            const before = terminal.bytes;
            mode.ui.requestRender(true, { clearScrollback: true });
            scheduler.drain();
            repaints.push({ ms: performance.now() - start, bytes: terminal.bytes - before });
        }
        if (!args.quiet) {
            const lines = mode.chatContainer.render(width);
            const text = args.plain ? lines.map(line => Bun.stripANSI(line)).join("\n") : lines.join("\n");
            process.stdout.write(text);
            process.stdout.write("\n");
        }
        if (args.timing || args.repaint) {
            const rows = mode.chatContainer.render(width).length;
            const report = [
                `session  ${sourcePath}`,
                `         ${formatBytes(sourceSize)}, ${entries.length} entries, ${messageCount} messages, ${rows} transcript rows @ ${width}x${height}`,
                `open     ${formatMs(openMs)}`,
                `replay   ${formatMs(replayMs)}  (transcript build + component construction)`,
                `paint    ${formatMs(paintMs)}  (full frame compose + emit: ${formatBytes(paintBytes)}, ${terminal.writes} writes)`,
            ];
            if (repaints.length > 0) {
                const times = repaints.map(r => r.ms);
                const avg = times.reduce((a, b) => a + b, 0) / times.length;
                const min = Math.min(...times);
                const max = Math.max(...times);
                const bytesPer = repaints[0].bytes;
                report.push(`repaint  ${formatMs(avg)} avg over ${repaints.length} (min ${formatMs(min)}, max ${formatMs(max)}), ${formatBytes(bytesPer)}/frame`);
            }
            process.stderr.write(`${report.join("\n")}\n`);
        }
        return 0;
    }
    finally {
        try {
            mode?.stop();
            await session?.dispose();
        }
        catch (err) {
            logger.debug("omp render teardown failed", { error: String(err) });
        }
        tempDir.removeSync();
    }
}
