import { afterEach, describe, expect, it, vi } from "bun:test";
import {
	type Component,
	CURSOR_MARKER,
	type Focusable,
	type TerminalFrameProvider,
	TUI,
	type TuiPaint,
} from "@reverse/tui";
import { emergencyTerminalRestore, ProcessTerminal, setAltScreenActive } from "@reverse/tui/terminal";
import { setTerminalHeadless } from "@reverse/utils";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";
import { ManualScheduler, TspTestTerminal } from "./native/tsp-harness";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";

withoutTerminalMultiplexer();

const TRACKING_ON = "\x1b[?1000h\x1b[?1003h\x1b[?1006h";
const TRACKING_OFF = "\x1b[?1006l\x1b[?1003l\x1b[?1000l";

class RecordingTerminal extends VirtualTerminal {
	readonly writes: string[] = [];

	override write(data: string): void {
		this.writes.push(data);
		super.write(data);
	}

	takeWrites(): string {
		const out = this.writes.join("");
		this.writes.length = 0;
		return out;
	}
}

class FocusableCursorBox implements Component, Focusable {
	focused = false;
	text: string;
	cursorCol: number;
	alwaysEmitMarker: boolean;

	constructor(text: string, cursorCol = text.length, alwaysEmitMarker = false) {
		this.text = text;
		this.cursorCol = cursorCol;
		this.alwaysEmitMarker = alwaysEmitMarker;
	}

	setUseTerminalCursor(_enabled: boolean): void {}

	render(_width: number): readonly string[] {
		const showMarker = this.alwaysEmitMarker || this.focused;
		const col = Math.max(0, Math.min(this.cursorCol, this.text.length));
		const marker = showMarker ? CURSOR_MARKER : "";
		return [`${this.text.slice(0, col)}${marker}${this.text.slice(col)}`];
	}
}

function screen(terminal: VirtualTerminal): string[] {
	return terminal.getViewport().map(row => Bun.stripANSI(row).trimEnd());
}

function countOccurrences(haystack: string, needle: string): number {
	if (needle.length === 0) return 0;
	let count = 0;
	let offset = 0;
	while (true) {
		const index = haystack.indexOf(needle, offset);
		if (index === -1) return count;
		count++;
		offset = index + needle.length;
	}
}

describe("fullscreen screenMode TUI", () => {
	afterEach(() => {
		setAltScreenActive(false);
	});

	it("owns a single alternate buffer across overlays, resize, and resetDisplay while preserving the shell sentinel", async () => {
		const terminal = new RecordingTerminal(40, 6);
		const scheduler = new VirtualRenderScheduler();
		terminal.write("SHELL-SENTINEL-0\r\nSHELL-SENTINEL-1");
		await terminal.flush();
		expect(screen(terminal).slice(0, 2)).toEqual(["SHELL-SENTINEL-0", "SHELL-SENTINEL-1"]);
		terminal.takeWrites();

		let replayCalls = 0;
		let flushCalls = 0;
		let frameTag = "main";
		const provider: TerminalFrameProvider = {
			renderFrame: ({ columns, rows }) => ({
				viewport: Array.from({ length: rows }, (_, i) => `${frameTag}-${i}@${columns}x${rows}`),
			}),
			beginHistoryReplay: () => {
				replayCalls++;
			},
			beginHistoryFlush: () => {
				flushCalls++;
			},
		};

		const paints: TuiPaint[] = [];
		const tui = new TUI(terminal, true, {
			screenMode: "fullscreen",
			renderScheduler: scheduler,
			onPaint: paint => paints.push(paint),
		});
		tui.setFrameProvider(provider);

		try {
			tui.start({ clearScrollback: true });
			await scheduler.settle(terminal);

			expect(screen(terminal)).toEqual([
				"main-0@40x6",
				"main-1@40x6",
				"main-2@40x6",
				"main-3@40x6",
				"main-4@40x6",
				"main-5@40x6",
			]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 6 });
			expect(paints.at(-1)).toMatchObject({ alt: true, reset: false, history: [], columns: 40, rows: 6 });

			// Normal overlay composites over the provider viewport on the same alt screen.
			const normalOverlay = tui.showOverlay({ render: () => ["[NORMAL-MODAL]"] }, { row: 2, col: 0, width: 14 });
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			await scheduler.settle(terminal);
			expect(screen(terminal)[2]).toContain("[NORMAL-MODAL]");
			expect(screen(terminal)[0]).toBe("main-0@40x6");
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });

			normalOverlay.hide();
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			await scheduler.settle(terminal);
			expect(screen(terminal)[2]).toBe("main-2@40x6");
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 6 });

			// Fullscreen overlay replaces the viewport with a blank base on the same 1049 buffer.
			const fullOverlay = tui.showOverlay(
				{ render: () => ["=== FULLSCREEN OVERLAY ==="] },
				{ fullscreen: true, anchor: "top-left", width: "100%", maxHeight: "100%" },
			);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["=== FULLSCREEN OVERLAY ===", "", "", "", "", ""]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });

			fullOverlay.hide();
			await scheduler.settle(terminal);
			expect(screen(terminal)[0]).toBe("main-0@40x6");
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 6 });

			// Resize repaints in place on the owned alternate screen without borrowing a second buffer,
			// probing CPR, replaying history, or clearing scrollback.
			terminal.resize(30, 4);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["main-0@30x4", "main-1@30x4", "main-2@30x4", "main-3@30x4"]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 4 });

			// Corrupt the alternate grid and verify resetDisplay() + forced clearScrollback repaint it without ED3.
			terminal.write("\x1b[1;1HCORRUPTED");
			frameTag = "reset";
			tui.resetDisplay();
			await scheduler.settle(terminal);
			expect(screen(terminal)[0]).toBe("reset-0@30x4");

			frameTag = "forced";
			tui.requestRender(true, { clearScrollback: true });
			await scheduler.settle(terminal);
			expect(screen(terminal)[0]).toBe("forced-0@30x4");

			const activeSessionWrites = terminal.writes.join("");
			expect(countOccurrences(activeSessionWrites, "\x1b[?1049h")).toBe(1);
			expect(countOccurrences(activeSessionWrites, "\x1b[?1049l")).toBe(0);
			expect(activeSessionWrites).not.toContain("\x1b[3J");
			expect(activeSessionWrites).not.toContain("\x1b[6n");
			expect(replayCalls).toBe(0);
		} finally {
			tui.stop();
		}

		await terminal.flush();
		const allOutput = terminal.writes.join("");
		expect(countOccurrences(allOutput, "\x1b[?1049h")).toBe(1);
		expect(countOccurrences(allOutput, "\x1b[?1049l")).toBe(1);
		expect(allOutput).not.toContain("\x1b[3J");
		expect(flushCalls).toBe(0);
		expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
		expect(screen(terminal).slice(0, 2)).toEqual(["SHELL-SENTINEL-0", "SHELL-SENTINEL-1"]);
		expect(terminal.getScrollBuffer().join("\n")).not.toContain("main-");
		expect(terminal.getScrollBuffer().join("\n")).not.toContain("forced-");
	});

	it("always enables SGR mouse reporting on the fullscreen main screen regardless of inline mouse preference", async () => {
		const terminal = new RecordingTerminal(40, 4);
		const scheduler = new VirtualRenderScheduler();
		const tui = new TUI(terminal, undefined, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.setInlineMouseTrackingProvider(() => false);
		tui.setFrameProvider({
			renderFrame: () => ({ viewport: ["row 0", "row 1", "row 2", "row 3"] }),
		});

		try {
			tui.start();
			await scheduler.settle(terminal);
			expect(terminal.writes.join("")).toContain(TRACKING_ON);

			// A non-fullscreen overlay yields mouse tracking and restores it on close.
			terminal.takeWrites();
			const normalOverlay = tui.showOverlay({ render: () => ["dialog"] }, {});
			await scheduler.settle(terminal);
			expect(terminal.takeWrites()).toContain(TRACKING_OFF);

			normalOverlay.hide();
			await scheduler.settle(terminal);
			expect(terminal.takeWrites()).toContain(TRACKING_ON);

			// A fullscreen overlay with mouseTracking: false disables tracking, and closing it restores main tracking.
			const noMouseOverlay = tui.showOverlay(
				{ render: () => ["selection view"] },
				{ fullscreen: true, mouseTracking: false },
			);
			await scheduler.settle(terminal);
			expect(terminal.takeWrites()).toContain(TRACKING_OFF);

			noMouseOverlay.hide();
			await scheduler.settle(terminal);
			expect(terminal.takeWrites()).toContain(TRACKING_ON);
		} finally {
			terminal.takeWrites();
			tui.stop();
		}

		const stopWrites = terminal.takeWrites();
		expect(stopWrites).toContain(TRACKING_OFF);
		expect(stopWrites).toContain("\x1b[?1049l");
	});

	it("assigns the hardware cursor to the active focus owner and prevents the background editor from stealing it under overlays", async () => {
		const terminal = new RecordingTerminal(40, 6);
		const scheduler = new VirtualRenderScheduler();
		const tui = new TUI(terminal, true, { screenMode: "fullscreen", renderScheduler: scheduler });
		// Simulate an editor that emits CURSOR_MARKER even if rendered behind a modal.
		const editor = new FocusableCursorBox("prompt> ", 8, true);
		tui.setFrameProvider({
			renderFrame: ({ columns }) => ({
				viewport: ["transcript 0", "transcript 1", "", "", ...editor.render(columns), "status"],
			}),
		});
		tui.setFocus(editor);

		try {
			tui.start();
			await scheduler.settle(terminal);
			expect(terminal.getCursor()).toEqual({ row: 4, col: 8 });
			expect(tui.getDebugPaint()?.cursor).toEqual({ x: 8, y: 4, visible: true });

			// Editing one row on the main screen diffs row-by-row rather than rewriting unchanged rows.
			terminal.takeWrites();
			editor.text = "prompt> hi";
			editor.cursorCol = 10;
			tui.requestRender();
			await scheduler.settle(terminal);
			const diffWrite = terminal.takeWrites();
			expect(diffWrite).toContain("prompt> hi");
			expect(diffWrite).not.toContain("transcript 0");
			expect(diffWrite).not.toContain("status");
			expect(terminal.getCursor()).toEqual({ row: 4, col: 10 });

			// Non-focusable normal overlay: background editor marker must not steal cursor.
			const plainModal = tui.showOverlay({ render: () => ["modal line"] }, { row: 1, col: 2, width: 20 });
			await scheduler.settle(terminal);
			expect(tui.getDebugPaint()?.cursor).toBeUndefined();

			// Focusable normal overlay: cursor lands on the overlay's input, not the background editor on row 4.
			const modalInput = new FocusableCursorBox("search: abc", 11);
			const inputModal = tui.showOverlay(modalInput, { row: 2, col: 4, width: 20 });
			await scheduler.settle(terminal);
			expect(terminal.getCursor()).toEqual({ row: 2, col: 15 });
			expect(tui.getDebugPaint()?.cursor).toEqual({ x: 15, y: 2, visible: true });

			// Fullscreen focusable overlay: cursor moves to the fullscreen overlay's target.
			const fullInput = new FocusableCursorBox("full: xy", 8);
			const fullModal = tui.showOverlay(fullInput, {
				fullscreen: true,
				anchor: "top-left",
				width: "100%",
				maxHeight: "100%",
			});
			await scheduler.settle(terminal);
			expect(terminal.getCursor()).toEqual({ row: 0, col: 8 });

			// Closing overlays restores cursor back to the background editor on row 4.
			fullModal.hide();
			inputModal.hide();
			plainModal.hide();
			await scheduler.settle(terminal);
			expect(terminal.getCursor()).toEqual({ row: 4, col: 10 });
			expect(tui.getDebugPaint()?.cursor).toEqual({ x: 10, y: 4, visible: true });
		} finally {
			tui.stop();
		}
	});

	it("renders a bounded tail of children when no frameProvider is installed", async () => {
		const terminal = new RecordingTerminal(30, 4);
		const scheduler = new VirtualRenderScheduler();
		terminal.write("SHELL-BEFORE-CHILDREN");
		await terminal.flush();

		const tui = new TUI(terminal, undefined, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.addChild({
			render: () => ["line-0", "line-1", "line-2", "line-3", "line-4", "line-5"],
		});

		try {
			tui.start();
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["line-2", "line-3", "line-4", "line-5"]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 4 });
		} finally {
			tui.stop();
		}

		await terminal.flush();
		expect(screen(terminal)[0]).toBe("SHELL-BEFORE-CHILDREN");
		expect(terminal.getScrollBuffer().join("\n")).not.toContain("line-0");
	});

	it("rejects frame providers that emit history batches in fullscreen mode", () => {
		const terminal = new RecordingTerminal(30, 4);
		const scheduler = new VirtualRenderScheduler();
		terminal.write("SHELL-GUARD");

		const tui = new TUI(terminal, undefined, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.setFrameProvider({
			renderFrame: () => ({
				history: { id: 1, rows: ["unexpected history"] },
				viewport: ["row 0"],
			}),
		});

		try {
			tui.start();
			expect(() => tui.renderNow()).toThrow("Fullscreen frame providers must not emit history");
			expect(terminal.writes.join("")).not.toContain("unexpected history");
			expect(terminal.writes.join("")).not.toContain("\x1b[?1049h");
		} finally {
			tui.stop();
		}
		expect(screen(terminal)[0]).toBe("SHELL-GUARD");
	});

	it("skips painting at zero columns or rows and forces a full repaint once dimensions recover", async () => {
		const terminal = new RecordingTerminal(30, 4);
		const scheduler = new VirtualRenderScheduler();
		const editor = new FocusableCursorBox("abc", 2);
		const tui = new TUI(terminal, true, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.setFrameProvider({
			renderFrame: ({ columns, rows }) => ({
				viewport: [
					`size=${columns}x${rows}`,
					...Array.from({ length: Math.max(0, rows - 2) }, (_, i) => `fill-${i}`),
					...editor.render(columns),
				].slice(0, rows),
			}),
		});
		tui.setFocus(editor);

		try {
			// Start with zero rows: must not enter 1049 or emit cursor coordinates.
			terminal.resize(30, 0);
			tui.start();
			await scheduler.settle(terminal);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			expect(terminal.writes.join("")).not.toContain("\x1b[?1049h");

			// Recover to 30x4: enters 1049 and paints the full frame.
			terminal.resize(30, 4);
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["size=30x4", "fill-0", "fill-1", "abc"]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 4 });
			expect(terminal.getCursor()).toEqual({ row: 3, col: 2 });

			// Collapse width to 0, then return to the exact same 30x4 dimensions:
			// even if the buffer was dirtied while 0-sized, recovery must force a full repaint.
			terminal.resize(0, 4);
			await scheduler.settle(terminal);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 0 });
			terminal.write("\x1b[1;1HSTALE");

			terminal.resize(30, 4);
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["size=30x4", "fill-0", "fill-1", "abc"]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 4 });
		} finally {
			tui.stop();
		}
	});

	it("preserves the frame provider across stop/start cycles and re-enters fullscreen cleanly", async () => {
		const terminal = new RecordingTerminal(30, 3);
		const scheduler = new VirtualRenderScheduler();
		terminal.write("SHELL-RESTART-SENTINEL");
		await terminal.flush();
		terminal.takeWrites();

		let cycle = 1;
		const tui = new TUI(terminal, true, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.setFrameProvider({
			renderFrame: () => ({
				viewport: [`cycle-${cycle}-0`, `cycle-${cycle}-1`, `cycle-${cycle}-2`],
			}),
		});

		try {
			tui.start();
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["cycle-1-0", "cycle-1-1", "cycle-1-2"]);

			tui.stop();
			await terminal.flush();
			expect(screen(terminal)[0]).toBe("SHELL-RESTART-SENTINEL");

			cycle = 2;
			tui.start();
			await scheduler.settle(terminal);
			expect(screen(terminal)).toEqual(["cycle-2-0", "cycle-2-1", "cycle-2-2"]);
			expect(tui.getMutableViewport()).toEqual({ top: 0, length: 3 });
		} finally {
			tui.stop();
		}

		await terminal.flush();
		expect(screen(terminal)[0]).toBe("SHELL-RESTART-SENTINEL");
		expect(countOccurrences(terminal.writes.join(""), "\x1b[?1049h")).toBe(2);
		expect(countOccurrences(terminal.writes.join(""), "\x1b[?1049l")).toBe(2);
	});

	it("exits the alternate screen on a late TSP handshake without erasing the restored shell, and re-enters fullscreen on TSP fallback", () => {
		// 1. Late TSP handshake after a deferred-input fullscreen prepaint:
		const lateScheduler = new ManualScheduler();
		const lateTerm = new TspTestTerminal({ cols: 40, rows: 5, manualProbe: true });
		const lateTui = new TUI(lateTerm, true, { screenMode: "fullscreen", renderScheduler: lateScheduler });
		lateTui.setFrameProvider({
			renderFrame: () => ({ viewport: ["prepaint-0", "prepaint-1", "prepaint-2", "prepaint-3", "prepaint-4"] }),
		});

		try {
			lateTui.start({ deferInput: true });
			lateScheduler.flush();
			expect(lateTerm.rowBytes).toContain("\x1b[?1049h");
			expect(lateTerm.rowBytes).toContain("prepaint-0");

			lateTerm.rowBytes = "";
			lateTui.enableInput();
			expect(lateTerm.answerProbe()).toBe(true);
			lateScheduler.flush();

			expect(lateTui.nativeRendering).toBe(true);
			expect(lateTerm.rowBytes).toContain("\x1b[?1049l");
			expect(lateTerm.rowBytes).toContain(TRACKING_OFF);
			// Must NOT emit normal-buffer viewport erase (\r\x1b[J) after restoring the shell from 1049l.
			expect(lateTerm.rowBytes).not.toContain("\x1b[J");
		} finally {
			lateTui.stop();
		}

		// 2. Optimistic TSP start that times out falls back to fullscreen 1049:
		const fallbackScheduler = new ManualScheduler();
		const fallbackTerm = new TspTestTerminal({ cols: 40, rows: 4, expected: true, manualProbe: true });
		const fallbackTui = new TUI(fallbackTerm, true, {
			screenMode: "fullscreen",
			renderScheduler: fallbackScheduler,
		});
		fallbackTui.setFrameProvider({
			renderFrame: () => ({ viewport: ["fallback-0", "fallback-1", "fallback-2", "fallback-3"] }),
		});

		try {
			fallbackTui.start();
			fallbackScheduler.flush(500);
			expect(fallbackTui.nativeRendering).toBe(true);
			expect(fallbackTerm.rowBytes).not.toContain("\x1b[?1049h");

			fallbackScheduler.flush(1000);
			expect(fallbackTui.nativeRendering).toBe(false);
			expect(fallbackTerm.rowBytes).toContain("\x1b[?1049h");
			expect(fallbackTerm.rowBytes).toContain(TRACKING_ON);
			expect(fallbackTerm.rowBytes).toContain("fallback-0");
		} finally {
			fallbackTui.stop();
		}
	});

	it("propagates render exceptions and leaves alt-screen tracking armed for emergencyTerminalRestore", () => {
		const previousHeadless = setTerminalHeadless(false);
		const previousNative = Bun.env.PI_TUI_NATIVE;
		const stdinIsTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "isTTY");
		const stdoutIsTtyDescriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
		const stdinSetRawModeDescriptor = Object.getOwnPropertyDescriptor(process.stdin, "setRawMode");
		const writes: string[] = [];

		Bun.env.PI_TUI_NATIVE = "0";
		Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
		Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
		Object.defineProperty(process.stdin, "setRawMode", { value: vi.fn(), configurable: true });
		vi.spyOn(process, "kill").mockReturnValue(true);
		vi.spyOn(process.stdin, "resume").mockImplementation(() => process.stdin);
		vi.spyOn(process.stdin, "pause").mockImplementation(() => process.stdin);
		vi.spyOn(process.stdin, "setEncoding").mockImplementation(() => process.stdin);
		vi.spyOn(process.stdout, "write").mockImplementation(chunk => {
			writes.push(typeof chunk === "string" ? chunk : chunk.toString());
			return true;
		});

		const terminal = new ProcessTerminal({ conpty: false });
		const scheduler = new VirtualRenderScheduler();
		let shouldThrow = false;
		const tui = new TUI(terminal, true, { screenMode: "fullscreen", renderScheduler: scheduler });
		tui.setFrameProvider({
			renderFrame: () => {
				if (shouldThrow) throw new Error("provider render failed");
				return { viewport: ["ok-0", "ok-1", "ok-2", "ok-3"] };
			},
		});

		try {
			tui.start();
			process.stdin.emit("data", "\x1b[?0u");
			tui.renderNow();
			expect(writes.join("")).toContain("\x1b[?1049h");
			expect(writes.join("")).toContain("ok-0");

			shouldThrow = true;
			expect(() => tui.renderNow()).toThrow("provider render failed");

			writes.length = 0;
			emergencyTerminalRestore();
			const restored = writes.join("");
			const altPop = restored.indexOf("\x1b[<u");
			const altExit = restored.indexOf("\x1b[?1049l");
			const mainPop = restored.indexOf("\x1b[<u", altExit + 1);
			expect(altPop).toBeGreaterThanOrEqual(0);
			expect(altPop).toBeLessThan(altExit);
			expect(mainPop).toBeGreaterThan(altExit);
			expect(restored).toContain("\x1b[?1006l");
			expect(restored).toContain("\x1b[?1003l");
			expect(restored).toContain("\x1b[?1000l");
			expect(restored).toContain("\x1b[?25h");
		} finally {
			tui.stop();
			setAltScreenActive(false);
			vi.restoreAllMocks();
			if (previousNative === undefined) delete Bun.env.PI_TUI_NATIVE;
			else Bun.env.PI_TUI_NATIVE = previousNative;
			if (stdinIsTtyDescriptor) Object.defineProperty(process.stdin, "isTTY", stdinIsTtyDescriptor);
			else delete (process.stdin as unknown as Record<string, unknown>).isTTY;
			if (stdoutIsTtyDescriptor) Object.defineProperty(process.stdout, "isTTY", stdoutIsTtyDescriptor);
			else delete (process.stdout as unknown as Record<string, unknown>).isTTY;
			if (stdinSetRawModeDescriptor) {
				Object.defineProperty(process.stdin, "setRawMode", stdinSetRawModeDescriptor);
			} else {
				delete (process.stdin as unknown as Record<string, unknown>).setRawMode;
			}
			setTerminalHeadless(previousHeadless);
		}
	});
});
