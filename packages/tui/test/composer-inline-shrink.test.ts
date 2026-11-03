import { beforeAll, describe, expect, it } from "bun:test";
import { Composer } from "@reverse/tui/prompt/composer";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { Container, CURSOR_MARKER, type Component, Text } from "@reverse/tui";
import { initTheme } from "@reverse/tui/theme";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";
import { parseSgrMouse } from "@reverse/tui/mouse";
import { visibleWidth } from "@reverse/tui/utils";
import { TERMINAL, ImageProtocol } from "@reverse/tui/terminal-capabilities";
const content = (term: VirtualTerminal, height: number) =>
	screen(term)
		.slice(0, height)
		.map(row =>
			row
				.replace(/[│█]$/, "")
				.replace(/\[(?:↑ Go to top|↓ Jump to bottom)\]/g, "")
				.trimEnd(),
		);

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
	composer.setScrollLocaleProvider(() => "en");
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
			expect(content(h.terminal, h.composer.transcriptViewportHeight).at(-1)).toBe("ROW-099");
			h.composer.scrollTranscript(-10);
			await h.scheduler.settle(h.terminal);
			const top = content(h.terminal, h.composer.transcriptViewportHeight)[0];
			expect(top).toBe("ROW-083");
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[1]).toBe("");
			append(h.transcript, 1, 100);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[0]).toBe(top);
			expect(screen(h.terminal)[23]).toBe("EDITOR");
			h.composer.scrollTranscriptToBottom();
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, h.composer.transcriptViewportHeight).at(-1)).toBe("ROW-100");
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
			const top = content(h.terminal, h.composer.transcriptViewportHeight)[0];
			h.terminal.sendInput("中文🙂");
			h.terminal.sendInput("\x1b[200~\nsecond line\x1b[201~");
			await h.scheduler.settle(h.terminal);
			expect(h.composer.editor.getText()).toBe("中文🙂\nsecond line");
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[0]).toBe(top);
			expect(h.composer.ui.getDebugPaint()?.cursor?.visible).toBe(true);
			for (const count of [8, 40, 0]) {
				h.hud.rows = count;
				h.composer.ui.requestRender();
				await h.scheduler.settle(h.terminal);
			}
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[0]).toBe(top);
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
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[0]).toBe(top);
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
			expect(content(h.terminal, h.composer.transcriptViewportHeight).at(-1)).toBe("ROW-299");
		} finally {
			h.composer.stop();
		}
	});
	it("scrolls live informational panels while keeping only the selected dock fixed", async () => {
		const h = harness(true);
		const status = new Text("STATUS", 0, 0);
		h.hud.rows = 5;
		h.composer.setRuntimeChildren([h.transcript, h.hud, status, h.editor], { dockStart: status });
		try {
			append(h.transcript, 100);
			h.composer.editor.setText("preserved draft");
			await h.scheduler.settle(h.terminal);
			const H = h.composer.transcriptViewportHeight;
			expect(content(h.terminal, H).at(-1)).toBe("HUD-4");
			const dock = screen(h.terminal).slice(H + 1);
			h.composer.scrollTranscript(-20);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H).some(row => row.includes("HUD-"))).toBe(false);
			expect(screen(h.terminal).slice(H + 1)).toEqual(dock);
			const anchor = content(h.terminal, H)[0];
			h.hud.rows = 10;
			append(h.transcript, 1, 100);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H)[0]).toBe(anchor);
			expect(h.composer.transcriptViewportHeight).toBe(H);
			h.composer.scrollTranscriptToBottom();
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H).at(-1)).toBe("HUD-9");
			expect(h.composer.editor.getText()).toBe("preserved draft");
			expect(h.composer.ui.getDebugPaint()?.cursor?.visible).toBe(true);
		} finally {
			h.composer.stop();
		}
	});

	it("draws navigation and routes track, endpoint actions and drag cancellation", async () => {
		const h = harness();
		const mouse = (button: number, col: number, row: number, release = false) =>
			h.composer.handleTranscriptMouse(
				{ ...parseSgrMouse(`\x1b[<${button};1;1${release ? "m" : "M"}`)!, col, row },
				row,
			);
		try {
			append(h.transcript, 100);
			await h.scheduler.settle(h.terminal);
			const H = h.composer.transcriptViewportHeight;
			expect(screen(h.terminal)[0]).toContain("Go to top");
			expect(screen(h.terminal)[H]).not.toContain("Go to top");
			expect(screen(h.terminal)[H - 1]?.at(-1)).toBe("█");
			expect(mouse(0, 79, Math.floor(H / 2))).toBe(true);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H).some(row => /ROW-05\d/.test(row))).toBe(true);
			expect(mouse(32, 20, -5)).toBe(true);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H)[0]).toBe("ROW-000");
			expect(mouse(0, 0, H)).toBe(false);
			expect(mouse(0, 79, 0)).toBe(true);
			expect(mouse(32, 10, H + 5)).toBe(true);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, H).at(-1)).toBe("ROW-099");
			expect(mouse(0, 90, H + 10, true)).toBe(true);
			expect(mouse(32, 79, 0)).toBe(false);
			mouse(0, 79, 2);
			mouse(35, 79, 2);
			expect(mouse(32, 79, 0)).toBe(false);
			mouse(0, 79, 2);
			h.terminal.resize(60, 12);
			await h.scheduler.settle(h.terminal);
			expect(mouse(32, 59, 0)).toBe(false);
			expect(mouse(0, 58, 0)).toBe(true);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, h.composer.transcriptViewportHeight)[0]).toBe("ROW-000");
			expect(mouse(0, 58, h.composer.transcriptViewportHeight - 1)).toBe(true);
			await h.scheduler.settle(h.terminal);
			expect(content(h.terminal, h.composer.transcriptViewportHeight).at(-1)).toBe("ROW-099");
		} finally {
			h.composer.stop();
		}
	});

	it("has no track for empty or short history and preserves image rows and wide text", async () => {
		const h = harness();
		const protocol = TERMINAL.imageProtocol;
		TERMINAL.imageProtocol = ImageProtocol.Kitty;
		try {
			await h.scheduler.settle(h.terminal);
			expect(h.composer.handleTranscriptMouse(parseSgrMouse("\x1b[<0;80;1M")!, 0)).toBe(false);
			h.transcript.addChild(new Text("中文🙂", 0, 0));
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal).some(row => /[│█]/.test(row))).toBe(false);
			const image = "\x1b_Ga=p,i=7,r=4;payload\x1b\\";
			h.transcript.addChild({ render: () => [image, ...Array.from({ length: 40 }, () => "中文🙂")] });
			h.composer.scrollTranscriptToRatio(0);
			await h.scheduler.settle(h.terminal);
			const plan = h.composer.renderFrame({ columns: 80, rows: 24 });
			const imageRow = plan.viewport.indexOf(image);
			expect(imageRow).toBeGreaterThanOrEqual(0);
			expect(h.composer.handleTranscriptMouse(parseSgrMouse(`\x1b[<0;80;${imageRow + 1}M`)!, imageRow)).toBe(false);
			for (const row of plan.viewport.filter(row => row !== image))
				expect(visibleWidth(row)).toBeLessThanOrEqual(80);
		} finally {
			TERMINAL.imageProtocol = protocol;
			h.composer.stop();
		}
	});

	it("reads navigation locale each frame and fits translated actions without overflow", async () => {
		const h = harness();
		let locale: "en" | "zh-CN" = "zh-CN";
		h.composer.setScrollLocaleProvider(() => locale);
		try {
			append(h.transcript, 100);
			await h.scheduler.settle(h.terminal);
			let H = h.composer.transcriptViewportHeight;
			expect(screen(h.terminal)[0]).toContain("到顶部");
			expect(screen(h.terminal)[H - 1]).not.toContain("回到底部");
			h.composer.scrollTranscriptToRatio(0.5);
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[H - 1]).toContain("回到底部");
			locale = "en";
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[0]).toContain("Go to top");
			expect(screen(h.terminal)[H - 1]).toContain("Jump to bottom");
			for (const columns of [30, 20, 3]) {
				h.terminal.resize(columns, 24);
				await h.scheduler.settle(h.terminal);
				H = h.composer.transcriptViewportHeight;
				const rows = screen(h.terminal);
				expect(visibleWidth(rows[0]!)).toBeLessThanOrEqual(columns);
				expect(visibleWidth(rows[H - 1]!)).toBeLessThanOrEqual(columns);
				expect(rows[0]).toContain("↑");
				expect(rows[H - 1]).toContain("↓");
			}
		} finally {
			h.composer.stop();
		}
	});

	it("keeps the real cursor visible at widths one/two and heights one/two", async () => {
		const h = harness(true);
		try {
			append(h.transcript, 100);
			h.composer.editor.setText("中文🙂");
			for (const columns of [1, 2])
				for (const rows of [1, 2, 24]) {
					h.terminal.resize(columns, rows);
					await h.scheduler.settle(h.terminal);
					const paint = h.composer.ui.getDebugPaint();
					expect(paint?.cursor?.visible).toBe(true);
					expect(paint?.cursor?.y).toBeLessThan(rows);
				}
		} finally {
			h.composer.stop();
		}
	});
});
