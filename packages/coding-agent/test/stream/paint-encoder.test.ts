import { describe, expect, it } from "bun:test";
import { StreamPaintEncoder } from "@reverse/coding-agent/stream/paint-encoder";
import { applyScreenFrame, type StreamScreen, type StreamScreenFrame } from "@reverse/coding-agent/stream/protocol";
import { StreamRedactor } from "@reverse/coding-agent/stream/redactor";

const SIZE = { columns: 40, rows: 2 };

function paint(viewport: string[], history: string[] = []) {
	return { history, viewport, reset: false, alt: false, columns: SIZE.columns, rows: SIZE.rows };
}

describe("StreamPaintEncoder while the consumer is backpressured", () => {
	it("holds the viewport, then resends it redacted with the redactor current at resync", () => {
		const encoder = new StreamPaintEncoder(SIZE, new StreamRedactor([/alpha/g], []));
		encoder.push(paint(["prompt", "alpha beta"], ["old alpha line"]));

		// Backpressured: control frames and history only, redacted when drained.
		const held = encoder.drain({ screen: false });
		expect(held).toEqual([{ t: "history", rows: ["old •••••• line"] }]);
		expect(encoder.pending).toBe(true);

		// The secret set grows before the consumer catches up.
		encoder.setRedactor(new StreamRedactor([/alpha/g, /beta/g], []));
		encoder.resync();
		const resumed = encoder.drain();
		expect(resumed).toEqual([{ t: "viewport", rows: ["prompt", "•••••• ••••••"] }]);
		expect(JSON.stringify(resumed)).not.toContain("beta");
		expect(encoder.pending).toBe(false);
	});

	it("resends the last viewport on resync when nothing new was painted", () => {
		const encoder = new StreamPaintEncoder(SIZE, new StreamRedactor([], []));
		encoder.push(paint(["one", "two"]));
		expect(encoder.drain()).toEqual([{ t: "viewport", rows: ["one", "two"] }]);
		encoder.resync();
		expect(encoder.drain()).toEqual([{ t: "viewport", rows: ["one", "two"] }]);
	});
});

const FULLSCREEN_SIZE = { columns: 80, rows: 6 };

function altPaint(viewport: string[], options?: { alt?: boolean; reset?: boolean; columns?: number; rows?: number }) {
	return {
		history: [],
		viewport,
		reset: options?.reset ?? false,
		alt: options?.alt ?? true,
		columns: options?.columns ?? FULLSCREEN_SIZE.columns,
		rows: options?.rows ?? FULLSCREEN_SIZE.rows,
	};
}

function applyFrames(screen: StreamScreen, frames: readonly StreamScreenFrame[]): void {
	for (const frame of frames) applyScreenFrame(screen, frame);
}

describe("StreamPaintEncoder fullscreen (alt: true) differential encoding", () => {
	it("emits a full snapshot on the first alt frame and a single-row patch when typing one editor character", () => {
		const encoder = new StreamPaintEncoder(FULLSCREEN_SIZE, new StreamRedactor([], []));
		const consumer: StreamScreen = {
			cols: FULLSCREEN_SIZE.columns,
			rows: FULLSCREEN_SIZE.rows,
			history: [],
			viewport: [],
		};

		const frame1 = [
			"header: session",
			"user: explain main()",
			"assistant: analyzing binary...",
			"",
			"── status: idle ──",
			"> hel",
		];
		encoder.push(altPaint(frame1));
		const drained1 = encoder.drain();
		expect(drained1).toEqual([{ t: "viewport", rows: frame1 }]);
		applyFrames(consumer, drained1);
		expect(consumer.viewport).toEqual(frame1);

		const frame2 = [...frame1.slice(0, 5), "> hell"];
		encoder.push(altPaint(frame2));
		const drained2 = encoder.drain();
		expect(drained2).toEqual([{ t: "patch", ops: [[5, "> hell"]], rows: 6 }]);
		applyFrames(consumer, drained2);
		expect(consumer.viewport).toEqual(frame2);

		const frame3 = [...frame1.slice(0, 5), "> hello"];
		encoder.push(altPaint(frame3));
		const drained3 = encoder.drain();
		expect(drained3).toEqual([{ t: "patch", ops: [[5, "> hello"]], rows: 6 }]);
		applyFrames(consumer, drained3);
		expect(consumer.viewport).toEqual(frame3);
	});

	it("reconstructs the exact viewport across inline and fullscreen overlays while alt remains true", () => {
		const encoder = new StreamPaintEncoder(FULLSCREEN_SIZE, new StreamRedactor([], []));
		const consumer: StreamScreen = {
			cols: FULLSCREEN_SIZE.columns,
			rows: FULLSCREEN_SIZE.rows,
			history: [],
			viewport: [],
		};

		const base = [
			"row 0: transcript A",
			"row 1: transcript B",
			"row 2: transcript C",
			"row 3: transcript D",
			"row 4: status bar",
			"row 5: > draft",
		];
		encoder.push(altPaint(base));
		applyFrames(consumer, encoder.drain());
		expect(consumer.viewport).toEqual(base);

		// Small modal overlay covering 2 rows (<= half of 6 rows) emits a patch.
		const withInlineOverlay = [
			"row 0: transcript A",
			"row 1: ┌─ confirm ─┐",
			"row 2: └───────────┘",
			"row 3: transcript D",
			"row 4: status bar",
			"row 5: > draft",
		];
		encoder.push(altPaint(withInlineOverlay));
		const inlineOverlayFrames = encoder.drain();
		expect(inlineOverlayFrames).toEqual([
			{
				t: "patch",
				ops: [
					[1, "row 1: ┌─ confirm ─┐"],
					[2, "row 2: └───────────┘"],
				],
				rows: 6,
			},
		]);
		applyFrames(consumer, inlineOverlayFrames);
		expect(consumer.viewport).toEqual(withInlineOverlay);

		// Fullscreen overlay replacing the whole screen (> half of 6 rows) emits a viewport snapshot.
		const fullscreenOverlay = [
			"Settings",
			"  [x] Mouse click/hover",
			"  [ ] Compact status",
			"",
			"Filter: ",
			"Esc to close",
		];
		encoder.push(altPaint(fullscreenOverlay));
		const fullscreenOverlayFrames = encoder.drain();
		expect(fullscreenOverlayFrames).toEqual([{ t: "viewport", rows: fullscreenOverlay }]);
		applyFrames(consumer, fullscreenOverlayFrames);
		expect(consumer.viewport).toEqual(fullscreenOverlay);

		// Typing one character in the fullscreen overlay filter emits a single-row patch.
		const fullscreenOverlayFiltered = [
			"Settings",
			"  [x] Mouse click/hover",
			"  [ ] Compact status",
			"",
			"Filter: m",
			"Esc to close",
		];
		encoder.push(altPaint(fullscreenOverlayFiltered));
		const overlayEditFrames = encoder.drain();
		expect(overlayEditFrames).toEqual([{ t: "patch", ops: [[4, "Filter: m"]], rows: 6 }]);
		applyFrames(consumer, overlayEditFrames);
		expect(consumer.viewport).toEqual(fullscreenOverlayFiltered);

		// Closing the fullscreen overlay restores the base fullscreen viewport.
		encoder.push(altPaint(base));
		const closedOverlayFrames = encoder.drain();
		applyFrames(consumer, closedOverlayFrames);
		expect(consumer.viewport).toEqual(base);
	});

	it("forces a full snapshot on alt transitions, resize, reset, and resync", () => {
		const encoder = new StreamPaintEncoder(FULLSCREEN_SIZE, new StreamRedactor([], []));
		const consumer: StreamScreen = {
			cols: FULLSCREEN_SIZE.columns,
			rows: FULLSCREEN_SIZE.rows,
			history: [],
			viewport: [],
		};

		const initialAlt = ["line 0", "line 1", "line 2", "line 3", "status", "> a"];
		encoder.push(altPaint(initialAlt, { alt: true }));
		applyFrames(consumer, encoder.drain());
		expect(consumer.viewport).toEqual(initialAlt);

		// Leaving alt screen (alt: true -> false) forces a full snapshot even when only one row changed.
		const inlineFrame = ["line 0", "line 1", "line 2", "line 3", "status", "> ab"];
		encoder.push(altPaint(inlineFrame, { alt: false }));
		const toInlineFrames = encoder.drain();
		expect(toInlineFrames).toEqual([{ t: "viewport", rows: inlineFrame }]);
		applyFrames(consumer, toInlineFrames);
		expect(consumer.viewport).toEqual(inlineFrame);

		// Re-entering alt screen (alt: false -> true) forces a full snapshot even when only one row changed.
		const backToAlt = ["line 0", "line 1", "line 2", "line 3", "status", "> abc"];
		encoder.push(altPaint(backToAlt, { alt: true }));
		const toAltFrames = encoder.drain();
		expect(toAltFrames).toEqual([{ t: "viewport", rows: backToAlt }]);
		applyFrames(consumer, toAltFrames);
		expect(consumer.viewport).toEqual(backToAlt);

		// Resize while alt: true emits resize + full viewport snapshot.
		const resizedAlt = ["line 0", "line 1", "status", "> abc"];
		encoder.push(altPaint(resizedAlt, { alt: true, columns: 60, rows: 4 }));
		const resizeFrames = encoder.drain();
		expect(resizeFrames).toEqual([
			{ t: "resize", cols: 60, rows: 4 },
			{ t: "viewport", rows: resizedAlt },
		]);
		applyFrames(consumer, resizeFrames);
		expect(consumer.cols).toBe(60);
		expect(consumer.rows).toBe(4);
		expect(consumer.viewport).toEqual(resizedAlt);

		// Reset while alt: true emits reset + full viewport snapshot even when only one row changed.
		const resetAlt = ["line 0", "line 1", "status", "> abcd"];
		encoder.push(altPaint(resetAlt, { alt: true, reset: true, columns: 60, rows: 4 }));
		const resetFrames = encoder.drain();
		expect(resetFrames).toEqual([{ t: "reset" }, { t: "viewport", rows: resetAlt }]);
		applyFrames(consumer, resetFrames);
		expect(consumer.viewport).toEqual(resetAlt);

		// Resync while alt: true re-emits the full viewport snapshot.
		encoder.resync();
		const resyncFrames = encoder.drain();
		expect(resyncFrames).toEqual([{ t: "viewport", rows: resetAlt }]);
		applyFrames(consumer, resyncFrames);
		expect(consumer.viewport).toEqual(resetAlt);
	});
});
