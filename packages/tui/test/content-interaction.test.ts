import { afterEach, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Container, Text } from "@reverse/tui";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { parseSgrMouse } from "@reverse/tui/mouse";
import { Composer } from "@reverse/tui/prompt/composer";
import { ContentSelection } from "@reverse/tui/prompt/content-selection";
import { contentLinkAt } from "@reverse/tui/render/content-links";
import { applyHyperlinkSetting } from "@reverse/tui/render/hyperlink";
import { initTheme } from "@reverse/tui/theme";
import { visibleWidth } from "@reverse/tui/utils";
import { withoutTerminalMultiplexer } from "./helpers/terminal-multiplexer";
import { VirtualRenderScheduler } from "./virtual-render-scheduler";
import { VirtualTerminal } from "./virtual-terminal";

withoutTerminalMultiplexer();
beforeAll(() => initTheme());
afterEach(() => applyHyperlinkSetting("auto"));
const mouse = (button: number, col: number, row: number, release = false) =>
	parseSgrMouse(`\x1b[<${button};${col + 1};${row + 1}${release ? "m" : "M"}`)!;

describe("content selection", () => {
	it("copies styled Unicode across rows in either direction without control sequences", () => {
		const rows = ["\x1b[31mA中文🙂éZ\x1b[0m", "  second line  "];
		for (const backwards of [false, true]) {
			const selection = new ContentSelection();
			const start = backwards ? [5, 1] : [2, 0];
			const end = backwards ? [2, 0] : [5, 1];
			selection.handle(mouse(0, start[0]!, start[1]!), start[1]!, rows, 30);
			selection.handle(mouse(32, end[0]!, end[1]!), end[1]!, rows, 30);
			const result = selection.handle(mouse(0, end[0]!, end[1]!, true), end[1]!, rows, 30);
			expect(result).toEqual({ consume: true, copy: "中文🙂éZ\n  seco" });
			expect(selection.paint(rows).map(Bun.stripANSI)).toEqual(rows.map(Bun.stripANSI));
		}
	});

	it("returns a click only on release, never after dragging away and back", () => {
		const selection = new ContentSelection();
		const rows = ["https://example.com"];
		expect(selection.handle(mouse(0, 2, 0), 0, rows, 40)).toEqual({ consume: true });
		expect(selection.handle(mouse(0, 2, 0, true), 0, rows, 40)).toEqual({ consume: true, click: { row: 0, col: 2 } });
		selection.handle(mouse(0, 2, 0), 0, rows, 40);
		selection.handle(mouse(32, 8, 0), 0, rows, 40);
		expect(selection.handle(mouse(0, 2, 0, true), 0, rows, 40)?.click).toBeUndefined();
	});

	it("keeps the copied highlight on hover and clamps drag release outside content", () => {
		const selection = new ContentSelection();
		const rows = ["first", "second"];
		selection.handle(mouse(0, 0, 0), 0, rows, 20);
		const result = selection.handle(mouse(0, 19, 6, true), 6, rows, 20);
		expect(result).toEqual({ consume: true, copy: "first\nsecond" });
		expect(selection.handle(mouse(35, 0, 0), 0, rows, 20)).toBeUndefined();
		expect(selection.text()).toBe("first\nsecond");
	});

	it("preserves selection while unrelated rows stream", () => {
		const selection = new ContentSelection();
		const rows = ["history", "streaming"];
		selection.handle(mouse(0, 0, 0), 0, rows, 20);
		selection.handle(mouse(32, 6, 0), 0, rows, 20);
		selection.sync(["history", "streaming more"], 20);
		expect(selection.handle(mouse(0, 6, 0, true), 0, rows, 20)?.copy).toBe("history");
	});

	it("cancels stale coordinates on content change and resize, and ignores wheel/dock presses", () => {
		const selection = new ContentSelection();
		const rows = ["first line"];
		expect(selection.handle(mouse(64, 0, 0), 0, rows, 20)).toBeUndefined();
		expect(selection.handle(mouse(0, 0, 1), 1, rows, 20)).toBeUndefined();
		for (const [nextRows, width] of [
			[rows, 10],
			[["new line"], 20],
		] as const) {
			selection.handle(mouse(0, 0, 0), 0, rows, 20);
			selection.sync(nextRows, width);
			expect(selection.handle(mouse(0, 4, 0, true), 0, nextRows, width)).toBeUndefined();
		}
	});
});

describe("content links", () => {
	it("hit-tests BEL/ST OSC8 labels using rendered cell widths", () => {
		for (const end of ["\x07", "\x1b\\"]) {
			const line = `前 \x1b]8;;https://example.com/full${end}\x1b[4m网站\x1b[24m\x1b]8;;${end} tail`;
			expect(contentLinkAt(line, 4)).toEqual({ url: "https://example.com/full", start: 3 });
			expect(contentLinkAt(line, 2)).toBeUndefined();
			expect(contentLinkAt(line, 7)).toBeUndefined();
		}
	});

	it("recognizes visible URLs without OSC8 but respects explicit hyperlink off", () => {
		expect(contentLinkAt("访问 https://example.com/docs, now", 10)?.url).toBe("https://example.com/docs");
		expect(contentLinkAt("www.example.com", 4)?.url).toBe("https://www.example.com/");
		applyHyperlinkSetting("off");
		expect(contentLinkAt("https://example.com", 5)).toBeUndefined();
	});

	it("opens actual paths including quoted spaces and line suffixes, not arbitrary text", () => {
		const dir = mkdtempSync(join(tmpdir(), "reverse-content-"));
		try {
			const file = join(dir, "中文 file.ts");
			writeFileSync(file, "content");
			expect(contentLinkAt(`read \`${file}\``, 10)?.url).toBe(pathToFileURL(file).href);
			expect(contentLinkAt(`\`${file}:12:3\``, 10)?.url).toBe(pathToFileURL(file).href);
			expect(contentLinkAt(dir, 5)?.url).toBe(pathToFileURL(dir).href);
			expect(contentLinkAt("ordinary prose", 2)).toBeUndefined();
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("Composer content surface", () => {
	it("paints selection while preserving scrollbar, navigation and dock, and copies only source text", async () => {
		const terminal = new VirtualTerminal(60, 12);
		const scheduler = new VirtualRenderScheduler();
		const composer = new Composer({
			terminal,
			tuiOptions: { renderScheduler: scheduler },
			preferences: { quiet: true },
		});
		const transcript = new TranscriptContainer();
		const editor = new Container();
		editor.addChild(new Text("EDITOR", 0, 0));
		composer.setRuntimeChildren([transcript, editor]);
		composer.start({ playWelcomeIntro: false });
		try {
			for (let i = 0; i < 30; i++) transcript.addChild(new Text(`line-${i} https://example.com`, 0, 0));
			await scheduler.settle(terminal);
			const before = terminal.getViewport().map(row => Bun.stripANSI(row).trimEnd());
			const source = before[2]!;
			composer.handleContentMouse(mouse(0, 0, 2), 2);
			composer.handleContentMouse(mouse(32, 5, 2), 2);
			await scheduler.settle(terminal);
			const painted = composer.ui.getDebugPaint()!.lines;
			expect(painted[2]).toContain("\x1b[48;");
			expect(terminal.getViewport().map(row => Bun.stripANSI(row).trimEnd())).toEqual(before);
			expect(painted.every(row => visibleWidth(row) <= 60)).toBe(true);
			expect(composer.handleContentMouse(mouse(0, 5, 2, true), 2)?.copy).toBe(source.slice(0, 6));
			expect(composer.viewportLinkAt(2, 15)?.url).toBe("https://example.com/");
			composer.handleContentMouse(mouse(0, 0, 0), 0);
			const copied = composer.handleContentMouse(mouse(0, 58, 1, true), 1)?.copy;
			expect(copied).toBeDefined();
			expect(copied).not.toMatch(/[│█↑↓]/);
			expect(copied).not.toContain("Go to top");
			expect(composer.handleTranscriptMouse(mouse(0, 59, 3), 3)).toBe(true);
			await scheduler.settle(terminal);
			expect(terminal.getViewport().at(-1)?.trimEnd()).toBe("EDITOR");
		} finally {
			composer.stop();
		}
	});
});
