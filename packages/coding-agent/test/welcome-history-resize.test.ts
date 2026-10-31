import { afterEach, beforeAll, describe, expect, it, vi } from "bun:test";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { Composer } from "@reverse/tui/prompt/composer";
import { initTheme } from "@reverse/tui/theme";
import { type Component, Container, Text, visibleWidth } from "@reverse/tui";
import { Image } from "@reverse/tui/components/image";
import { getKittyGraphics, setKittyGraphics } from "@reverse/tui/kitty-graphics";
import { getCellDimensions, ImageProtocol, setCellDimensions, TERMINAL } from "@reverse/tui/terminal-capabilities";
import { VirtualRenderScheduler } from "../../tui/test/virtual-render-scheduler";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";
import { withoutTerminalMultiplexer } from "../../tui/test/helpers/terminal-multiplexer";

withoutTerminalMultiplexer();
beforeAll(() => initTheme());
afterEach(() => vi.restoreAllMocks());
class Tail implements Component {
	status = "thinking low";
	render() {
		return ["EDITOR TOP", this.status, "EDITOR BOTTOM"];
	}
}
class WidthBlock implements Component {
	constructor(readonly id: number) {}
	render(width: number) {
		return [`block-${this.id}@${width}`];
	}
}
class ToolBlock implements Component {
	allocations: number[] = [];
	setTranscriptAllocation(rows: number) {
		this.allocations.push(rows);
	}
	render(width: number) {
		return [`tool-0@${width}`, `tool-1@${width}`];
	}
}
class TrackingTerminal extends VirtualTerminal {
	writes: string[] = [];
	override write(data: string) {
		this.writes.push(data);
		super.write(data);
	}
}
const screen = (terminal: VirtualTerminal) => terminal.getViewport().map(row => Bun.stripANSI(row).trimEnd());
function harness(columns = 80, rows = 24, quiet = false, version = "test") {
	const terminal = new TrackingTerminal(columns, rows);
	terminal.write("SHELL-SENTINEL");
	const scheduler = new VirtualRenderScheduler();
	const composer = new Composer({
		terminal,
		tuiOptions: { renderScheduler: scheduler },
		preferences: { quiet },
		welcome: { version },
	});
	const transcript = new TranscriptContainer();
	const tail = new Tail();
	composer.setRuntimeChildren([transcript, tail]);
	composer.start({ playWelcomeIntro: false });
	return { terminal, scheduler, composer, transcript, tail };
}
async function browse(h: ReturnHarness, needle: string): Promise<string[]> {
	for (let page = 0; page < 50; page++) {
		const rows = screen(h.terminal);
		if (rows.some(row => row.includes(needle))) return rows;
		h.composer.scrollTranscript(-Math.max(1, h.composer.transcriptViewportHeight - 1));
		await h.scheduler.settle(h.terminal);
	}
	throw new Error(`Missing conversation content: ${needle}`);
}
interface ReturnHarness {
	terminal: TrackingTerminal;
	scheduler: VirtualRenderScheduler;
	composer: Composer;
}

describe("fullscreen welcome and conversation resize", () => {
	it("keeps one bottom editor rectangle across repeated status updates and geometry changes", async () => {
		vi.spyOn(Math, "random").mockReturnValue(0.5);
		const h = harness(80, 12);
		try {
			await h.scheduler.settle(h.terminal);
			for (let i = 0; i < 40; i++) {
				h.tail.status = i % 2 ? "thinking low" : "thinking high";
				h.composer.ui.requestRender();
				await h.scheduler.settle(h.terminal);
				expect(screen(h.terminal).slice(-3)).toEqual(["EDITOR TOP", h.tail.status, "EDITOR BOTTOM"]);
			}
			for (const [columns, rows] of [
				[96, 28],
				[104, 30],
				[100, 34],
				[92, 30],
				[72, 50],
			]) {
				h.terminal.resize(columns!, rows!);
				await h.scheduler.settle(h.terminal);
				const view = screen(h.terminal);
				expect(view.slice(-3)).toEqual(["EDITOR TOP", h.tail.status, "EDITOR BOTTOM"]);
				expect(view.filter(row => row.includes("vtest"))).toHaveLength(1);
			}
			expect(h.terminal.writes.join("")).not.toContain("\x1b[3J");
			expect(h.terminal.writes.join("").split("\x1b[?1049h")).toHaveLength(2);
		} finally {
			h.composer.stop();
		}
		expect(screen(h.terminal)[0]).toBe("SHELL-SENTINEL");
	});

	it("recomposes wide Unicode welcome content at the new width without retiring hard rows", async () => {
		const h = harness(60, 24, false, "aaaa界-tail");
		try {
			await h.scheduler.settle(h.terminal);
			const narrow = await browse(h, "界");
			expect(narrow.filter(row => row.includes("界"))).toHaveLength(1);
			h.terminal.resize(100, 40);
			await h.scheduler.settle(h.terminal);
			const wide = await browse(h, "界");
			expect(wide.filter(row => row.includes("界"))).toHaveLength(1);
			expect(Math.max(...wide.map(visibleWidth))).toBeGreaterThan(Math.max(...narrow.map(visibleWidth)));
		} finally {
			h.composer.stop();
		}
	});

	it("retains a historical component anchor and recomposes its rows on resize", async () => {
		const h = harness(20, 10, true);
		for (let i = 0; i < 20; i++) h.transcript.addChild(new WidthBlock(i));
		try {
			await h.scheduler.settle(h.terminal);
			h.composer.scrollTranscript(-10);
			await h.scheduler.settle(h.terminal);
			const first = screen(h.terminal)[0]!.replace("@20", "@30");
			h.terminal.resize(30, 12);
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)[0]).toBe(first);
			expect(screen(h.terminal).some(row => row.includes("@20"))).toBe(false);
			expect((await browse(h, "block-0@30")).some(row => row.includes("block-0@30"))).toBe(true);
		} finally {
			h.composer.stop();
		}
	});

	it("does not flush conversation content into the restored shell on shutdown", async () => {
		const h = harness(40, 10, true);
		h.transcript.addChild(new WidthBlock(1));
		await h.scheduler.settle(h.terminal);
		expect(screen(h.terminal)).toContain("block-1@40");
		h.composer.stop();
		expect(h.terminal.getScrollBuffer().join("\n")).toContain("SHELL-SENTINEL");
		expect(h.terminal.getScrollBuffer().join("\n")).not.toContain("block-1");
	});

	it("keeps resumed blocks reachable and gives visible tool blocks complete allocation after reset", async () => {
		const h = harness(80, 10);
		for (let i = 1; i <= 15; i++) h.transcript.addChild(new WidthBlock(i));
		const tool = new ToolBlock();
		h.transcript.addChild(tool);
		try {
			h.composer.ui.requestRender(true, { clearScrollback: true });
			await h.scheduler.settle(h.terminal);
			expect(tool.allocations.at(-1)).toBe(Number.MAX_SAFE_INTEGER);
			expect((await browse(h, "block-1@80")).some(row => row.includes("block-1@80"))).toBe(true);
			h.composer.scrollTranscriptToBottom();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal)).toContain("tool-1@80");
			expect(h.terminal.writes.join("")).not.toContain("\x1b[3J");
		} finally {
			h.composer.stop();
		}
	});

	it("retries image-budget composition without stale graphics", async () => {
		const protocol = TERMINAL.imageProtocol;
		const terminalId = TERMINAL.id;
		const dimensions = getCellDimensions();
		const graphics = { ...getKittyGraphics() };
		Reflect.set(TERMINAL, "imageProtocol", ImageProtocol.Kitty);
		Reflect.set(TERMINAL, "id", "xterm");
		setCellDimensions({ widthPx: 10, heightPx: 10 });
		setKittyGraphics({ unicodePlaceholders: false });
		const h = harness(40, 10, true);
		try {
			h.composer.ui.setMaxInlineImages(1);
			const block = new Container();
			for (const key of ["first", "second", "third"])
				block.addChild(
					new Image(
						"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==",
						"image/png",
						{ fallbackColor: text => text },
						{ maxWidthCells: 1, maxHeightCells: 1, budget: h.composer.ui.imageBudget, imageKey: key },
						{ widthPx: 10, heightPx: 10 },
					),
				);
			h.transcript.addChild(block);
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(screen(h.terminal).filter(row => row.includes("[Image:"))).toHaveLength(2);
			expect(h.terminal.graphicsPlacements()).toHaveLength(1);
			h.transcript.clear();
			h.transcript.addChild(new Text("plain"));
			h.composer.ui.requestRender();
			await h.scheduler.settle(h.terminal);
			expect(h.terminal.graphicsPlacements()).toEqual([]);
		} finally {
			h.composer.stop();
			Reflect.set(TERMINAL, "imageProtocol", protocol);
			Reflect.set(TERMINAL, "id", terminalId);
			setCellDimensions(dimensions);
			setKittyGraphics(graphics);
		}
	});
});
