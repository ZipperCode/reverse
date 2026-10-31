import { beforeAll, describe, expect, it } from "bun:test";
import { Composer } from "@reverse/tui/prompt/composer";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { Container, CURSOR_MARKER, type Component, Text } from "@reverse/tui";
import { initTheme } from "@reverse/tui/theme";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";

withoutTerminalMultiplexer();
beforeAll(() => initTheme());
const screen = (term: VirtualTerminal) => term.getViewport().map(row => Bun.stripANSI(row).trimEnd());
class Widget implements Component {
	rows = 0;
	render(): string[] {
		return Array.from({ length: this.rows }, (_, i) => `HUD-${i}`);
	}
}
function harness(realEditor = false, rows = 24) {
	const terminal = new VirtualTerminal(80, rows);
	const scheduler = new VirtualRenderScheduler();
	const composer = new Composer({
		terminal,
		tuiOptions: { renderScheduler: scheduler },
		preferences: { quiet: true },
	});
	const transcript = new TranscriptContainer();
	const hud = new Widget();
	const editor = new Container();
	editor.addChild(realEditor ? composer.editor : new Text("EDITOR", 0, 0));
	composer.setRuntimeChildren([transcript, hud, editor]);
	composer.start({ playWelcomeIntro: false });
	return { terminal, scheduler, composer, transcript, hud, editor };
}
function append(transcript: TranscriptContainer, count: number, start = 0) {
	for (let i = start; i < start + count; i++)
		transcript.addChild(new Text(`ROW-${i.toString().padStart(3, "0")}`, 0, 0));
}

describe("Composer fixed bottom dock", () => {
	it("pins the empty and populated editor, preserves browsing on append, and returns to tail", async () => {
		const h = harness();
		try {
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[23]).toBe("EDITOR");
			append(h.transcript, 100);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal).slice(-2)).toEqual(["ROW-099", "EDITOR"]);
			h.composer.scrollTranscript(-10);
			await h.scheduler.settle(h.terminal);
			const top = screen(h.terminal)[0];
			expect(top).toBe("ROW-083");
			append(h.transcript, 1, 100);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[0]).toBe(top);
			expect(screen(h.terminal)[23]).toBe("EDITOR");
			h.composer.scrollTranscriptToBottom();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal).slice(-2)).toEqual(["ROW-100", "EDITOR"]);
		} finally {
			h.composer.stop();
		}
	});

	it("keeps a real editable Unicode draft and cursor while history is anchored through HUD changes and resize", async () => {
		const h = harness(true);
		try {
			append(h.transcript, 100);
			await h.scheduler.settle(h.terminal);
			h.composer.scrollTranscript(-30);
			await h.scheduler.settle(h.terminal);
			const top = screen(h.terminal)[0];
			h.terminal.sendInput("中文🙂");
			h.terminal.sendInput("\x1b[200~\nsecond line\x1b[201~");
			await h.scheduler.settle(h.terminal);
			expect(h.composer.editor.getText()).toBe("中文🙂\nsecond line");
			expect(screen(h.terminal)[0]).toBe(top);
			expect(h.composer.ui.getDebugPaint()?.cursor?.visible).toBe(true);
			for (const count of [8, 40, 0]) {
				h.hud.rows = count;
				h.composer.ui.requestRender();
				await h.scheduler.settle(h.terminal);
			}
			expect(screen(h.terminal)[0]).toBe(top);
			for (const [columns, rows] of [
				[60, 12],
				[100, 40],
				[80, 2],
				[80, 1],
				[80, 24],
			]) {
				h.terminal.resize(columns!, rows!);
				await h.scheduler.settle(h.terminal);
				const paint = h.composer.ui.getDebugPaint();
				expect(paint?.lines.length).toBe(rows);
				expect(paint?.cursor?.y).toBeGreaterThanOrEqual(0);
				expect(paint?.cursor?.y).toBeLessThan(rows!);
				expect(screen(h.terminal).some(row => row.includes("second line"))).toBe(true);
			}
			expect(screen(h.terminal)[0]).toBe(top);
		} finally {
			h.composer.stop();
		}
	});

	it("keeps the focused editor-slot dialog cursor in a tiny dock and restores the draft/history", async () => {
		const h = harness(true);
		try {
			append(h.transcript, 100);
			h.composer.editor.setText("preserved draft");
			await h.scheduler.settle(h.terminal);
			h.composer.scrollTranscript(-20);
			await h.scheduler.settle(h.terminal);
			const before = screen(h.terminal)[0];
			const dialog = {
				focused: false,
				render: () => ["DIALOG-HEADER", `dialog input${CURSOR_MARKER}`, "DIALOG-FOOTER"],
				setUseTerminalCursor(_enabled: boolean) {},
			};
			h.editor.clear();
			h.editor.addChild(dialog);
			h.composer.ui.setFocus(dialog);
			h.terminal.resize(80, 1);
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)).toEqual(["dialog input"]);
			expect(h.terminal.getCursor()).toEqual({ row: 0, col: 12 });
			h.editor.clear();
			h.editor.addChild(h.composer.editor);
			h.composer.ui.setFocus(h.composer.editor);
			h.terminal.resize(80, 24);
			await h.scheduler.settle(h.terminal);
			expect(h.composer.editor.getText()).toBe("preserved draft");
			expect(screen(h.terminal)[0]).toBe(before);
		} finally {
			h.composer.stop();
		}
	});

	it("refills covered history after dock contraction and resets clear→refill on the same transcript", async () => {
		const h = harness();
		try {
			append(h.transcript, 100);
			await h.scheduler.settle(h.terminal);
			h.composer.scrollTranscript(-30);
			await h.scheduler.settle(h.terminal);
			const before = screen(h.terminal);
			h.hud.rows = 15;
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[23]).toBe("EDITOR");
			h.hud.rows = 0;
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)).toEqual(before);
			h.transcript.clear();
			append(h.transcript, 100, 200);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal).slice(-2)).toEqual(["ROW-299", "EDITOR"]);
		} finally {
			h.composer.stop();
		}
	});
});
