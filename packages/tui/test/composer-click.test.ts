import { beforeAll, describe, expect, it } from "bun:test";
import { COMPOSER_DEFAULTS, Composer } from "@reverse/tui/prompt/composer";
import { TranscriptContainer } from "@reverse/tui/chrome/transcript-container";
import { initTheme } from "@reverse/tui/theme";
import { Container, type Component } from "@reverse/tui";
import { VirtualTerminal } from "./virtual-terminal";
import { routeViewportClick, type ViewportClickSpan } from "@reverse/tui/prompt/composer";
import type { MouseRoutable, SgrMouseEvent } from "@reverse/tui/mouse";

function span(start: number, end: number, ids: string[]): ViewportClickSpan {
	return { start, end, candidates: () => ids };
}

describe("routeViewportClick", () => {
	it("returns the hit span's candidates with the span-local row", () => {
		let local = -1;
		const spans: ViewportClickSpan[] = [
			{
				start: 0,
				end: 2,
				candidates: row => {
					local = row;
					return ["CardAgent"];
				},
			},
			{ start: 3, end: 5, candidates: () => ["HudAgent"] },
		];
		expect(routeViewportClick(spans, 1)).toEqual(["CardAgent"]);
		expect(local).toBe(1);
		expect(routeViewportClick(spans, 4)).toEqual(["HudAgent"]);
	});

	it("misses separators, out-of-range rows, and non-integer indexes", () => {
		const spans = [span(0, 2, ["A"]), span(3, 4, ["B"])];
		expect(routeViewportClick(spans, 2)).toEqual([]);
		expect(routeViewportClick(spans, -1)).toEqual([]);
		expect(routeViewportClick(spans, Number.NaN)).toEqual([]);
		expect(routeViewportClick(spans, 99)).toEqual([]);
	});

	it("lets the first overlapping span win", () => {
		const spans = [span(0, 5, ["A"]), span(2, 4, ["B"])];
		expect(routeViewportClick(spans, 3)).toEqual(["A"]);
	});
});

class ClickableBlock implements Component {
	constructor(
		private readonly rows: readonly string[],
		private readonly ids: readonly string[],
	) {}
	isTranscriptBlockFinalized(): boolean {
		return false;
	}
	render(): readonly string[] {
		return this.rows;
	}
	getClickFocusAgentIds(): string[] {
		return [...this.ids];
	}
}

describe("composer hover band", () => {
	beforeAll(() => {
		initTheme();
	});

	it("bands only the hovered target's rows and clears byte-identically", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			transcript.addChild(new ClickableBlock(["card one", "card two"], ["AgentA"]));
			transcript.addChild(new ClickableBlock(["plain"], []));
			composer.setRuntimeChildren([transcript]);
			const plain = composer.renderFrame({ columns: 80, rows: 24 });
			expect(plain.viewport.join("\n")).not.toContain("\x1b[48");

			composer.setHoveredClickId("AgentA");
			const hovered = composer.renderFrame({ columns: 80, rows: 24 });
			const banded = hovered.viewport.filter(line => line.includes("\x1b[48"));
			expect(banded).toHaveLength(2);
			expect(Bun.stripANSI(banded.join("\n"))).toContain("card one");
			expect(Bun.stripANSI(banded.join("\n"))).toContain("card two");
			expect(hovered.viewport.filter(line => line.includes("plain") && line.includes("\x1b[48"))).toHaveLength(0);

			composer.setHoveredClickId("Nobody");
			expect(composer.renderFrame({ columns: 80, rows: 24 }).viewport).toEqual(plain.viewport);

			composer.setHoveredClickId(undefined);
			expect(composer.renderFrame({ columns: 80, rows: 24 }).viewport).toEqual(plain.viewport);
		} finally {
			composer.stop();
		}
	});

	it("drops nested background opens so the band wins tinted rows", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const esc = String.fromCharCode(27);
			const tinted = `${esc}[48;2;15;18;22mcard tinted${esc}[49m`;
			const transcript = new TranscriptContainer();
			transcript.addChild(new ClickableBlock([tinted], ["AgentT"]));
			composer.setRuntimeChildren([transcript]);
			composer.setHoveredClickId("AgentT");
			const hovered = composer.renderFrame({ columns: 80, rows: 24 });
			const banded = hovered.viewport.filter(line => line.includes("card tinted"));
			expect(banded).toHaveLength(1);
			expect(banded[0]).toContain(`${esc}[48`);
			expect(banded[0]).not.toContain("48;2;15;18;22");
		} finally {
			composer.stop();
		}
	});
});
class RowTarget implements Component {
	constructor(
		private readonly rows: readonly string[],
		private readonly ids: readonly string[],
	) {}
	render(): readonly string[] {
		return this.rows;
	}
	getClickAgentAtRow(row: number): string | undefined {
		return this.ids[row];
	}
}

describe("composer click-span clipping", () => {
	beforeAll(() => {
		initTheme();
	});

	it("offsets hit-testing past clipped viewport rows", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			const chrome = new Container();
			const ids = Array.from({ length: 10 }, (_, index) => `row${index}`);
			chrome.addChild(
				new RowTarget(
					ids.map(id => `line ${id}`),
					ids,
				),
			);
			composer.setRuntimeChildren([transcript, chrome]);

			// Ten chrome rows in a six-row viewport: the first four scroll off,
			// so viewport row 0 must hit-test as component row 4.
			const frame = composer.renderFrame({ columns: 80, rows: 6 });
			expect(frame.viewport).toHaveLength(6);
			expect(composer.viewportClickCandidates(0)).toEqual(["row4"]);
			expect(composer.viewportClickCandidates(5)).toEqual(["row9"]);
		} finally {
			composer.stop();
		}
	});
});

class CountingBlock implements Component {
	renders = 0;
	constructor(private readonly rows: readonly string[]) {}
	render(): readonly string[] {
		this.renders++;
		return this.rows;
	}
}

describe("composer chrome span recording", () => {
	beforeAll(() => {
		initTheme();
	});

	it("does not re-render chrome without click targets", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			const chrome = new Container();
			const first = new CountingBlock(["status one"]);
			const second = new CountingBlock(["status two"]);
			chrome.addChild(first);
			chrome.addChild(second);
			composer.setRuntimeChildren([transcript, chrome]);

			const frame = composer.renderFrame({ columns: 80, rows: 24 });
			expect(frame.viewport.join("\n")).toContain("status two");
			expect([first.renders, second.renders]).toEqual([1, 1]);
			expect(composer.viewportClickCandidates(0)).toEqual([]);
		} finally {
			composer.stop();
		}
	});

	it("renders target-bearing chrome children once per frame", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			const chrome = new Container();
			const first = new CountingBlock(["status one"]);
			const hud = new RowTarget(["hud row"], ["AgentH"]);
			chrome.addChild(first);
			chrome.addChild(hud);
			composer.setRuntimeChildren([transcript, chrome]);

			const frame = composer.renderFrame({ columns: 80, rows: 24 });
			const hudRow = frame.viewport.findIndex(line => line.includes("hud row"));
			expect(hudRow).toBeGreaterThanOrEqual(0);
			expect(composer.viewportClickCandidates(hudRow)).toEqual(["AgentH"]);
			expect(first.renders).toBe(1);
		} finally {
			composer.stop();
		}
	});
});

class DetailBlock implements Component, MouseRoutable {
	public expanded = false;
	constructor(
		private readonly rows: readonly string[],
		private readonly headerRow: number,
	) {}
	isTranscriptBlockFinalized(): boolean {
		return false;
	}
	render(): readonly string[] {
		return this.expanded ? [...this.rows, "Expanded detail body"] : this.rows;
	}
	routeMouse(_event: SgrMouseEvent, line: number): boolean {
		if (line === this.headerRow) {
			this.expanded = !this.expanded;
			return true;
		}
		return false;
	}
}

describe("composer detail click coordinate resolution", () => {
	it("maps viewport rows to exact component row origin through blank trimming", () => {
		const term = new VirtualTerminal(80, 24);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			// Component has 1 leading blank line (row 0), 1 header line (row 1), 1 body line (row 2)
			const block = new DetailBlock(["", "Header row", "Body row"], 1);
			transcript.addChild(block);
			composer.setRuntimeChildren([transcript]);

			const frame = composer.renderFrame({ columns: 80, rows: 24 });
			const headerViewportRow = frame.viewport.findIndex(line => line.includes("Header row"));
			const bodyViewportRow = frame.viewport.findIndex(line => line.includes("Body row"));
			expect(headerViewportRow).toBeGreaterThanOrEqual(0);
			expect(bodyViewportRow).toBeGreaterThanOrEqual(0);

			// Body row click must return false and not toggle expanded
			const bodyHandled = composer.routeViewportDetailClick(bodyViewportRow, 7);
			expect(bodyHandled).toBe(false);
			expect(block.expanded).toBe(false);

			// Header row click maps to row 1 (the untrimmed header row), toggling expanded
			const headerHandled = composer.routeViewportDetailClick(headerViewportRow, 7);
			expect(headerHandled).toBe(true);
			expect(block.expanded).toBe(true);
		} finally {
			composer.stop();
		}
	});

	it("rejects clicks on visible body rows when header is clipped off by viewport drop", () => {
		const term = new VirtualTerminal(80, 10);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			// Row 0 is the header; rows 1-7 are body rows
			const block = new DetailBlock(
				["Header row", "Body 1", "Body 2", "Body 3", "Body 4", "Body 5", "Body 6", "Body 7"],
				0,
			);
			transcript.addChild(block);
			// Large chrome below forcing drop/clipping of the header row
			const chrome = new Container();
			chrome.addChild(new RowTarget(["C1", "C2", "C3", "C4", "C5", "C6"], ["AgentC"]));
			composer.setRuntimeChildren([transcript, chrome]);

			const frame = composer.renderFrame({ columns: 80, rows: 10 });
			// Header row is clipped off by drop; only body rows survive in the viewport
			expect(frame.viewport.some(line => line.includes("Header row"))).toBe(false);
			const visibleFirst = frame.viewport.findIndex(line => line.includes("Body"));
			expect(visibleFirst).toBeGreaterThanOrEqual(0);

			// Clicking any visible clipped body row in the transcript area MUST NOT trigger header toggle
			for (let r = visibleFirst; r < frame.viewport.length && frame.viewport[r]!.includes("Body"); r++) {
				const handled = composer.routeViewportDetailClick(r, 3);
				expect(handled).toBe(false);
				expect(block.expanded).toBe(false);
			}
		} finally {
			composer.stop();
		}
	});

	it("routes clicks only to header when header and body are both visible in constrained viewport", () => {
		const term = new VirtualTerminal(80, 10);
		const composer = new Composer({ terminal: term, preferences: { ...COMPOSER_DEFAULTS, quiet: true } });
		composer.start();
		try {
			const transcript = new TranscriptContainer();
			const block1 = new DetailBlock(["Old header", "Old body"], 0);
			const block2 = new DetailBlock(["Header row", "Body 1", "Body 2", "Body 3"], 0);
			transcript.addChild(block1);
			transcript.addChild(block2);
			const chrome = new Container();
			chrome.addChild(new RowTarget(["C1", "C2", "C3", "C4"], ["AgentC"]));
			composer.setRuntimeChildren([transcript, chrome]);

			const frame = composer.renderFrame({ columns: 80, rows: 10 });
			const headerRow = frame.viewport.findIndex(line => line.includes("Header row"));
			const bodyRow = frame.viewport.findIndex(line => line.includes("Body 1"));
			expect(headerRow).toBeGreaterThanOrEqual(0);
			expect(bodyRow).toBeGreaterThanOrEqual(0);

			// Clicking visible body row must return false and NOT toggle
			const bodyHandled = composer.routeViewportDetailClick(bodyRow, 3);
			expect(bodyHandled).toBe(false);
			expect(block2.expanded).toBe(false);

			// Clicking visible header row must return true and toggle
			const headerHandled = composer.routeViewportDetailClick(headerRow, 3);
			expect(headerHandled).toBe(true);
			expect(block2.expanded).toBe(true);
		} finally {
			composer.stop();
		}
	});
});
