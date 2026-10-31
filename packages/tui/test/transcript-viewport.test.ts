import { describe, expect, it } from "bun:test";
import { TranscriptViewport } from "@reverse/tui/chrome/transcript-viewport";
import type { Component } from "@reverse/tui";

const frame = { now: 0, tick: 0 };
const component = (...rows: string[]): Component => ({ render: () => rows });
const numbered = (count: number) => Array.from({ length: count }, (_, i) => component(`ROW-${i}`));

describe("component-anchored transcript viewport", () => {
	it("scrolls from the painted tail, preserves browsing on append, and follows again at bottom", () => {
		const roots = numbered(100);
		const view = new TranscriptViewport();
		expect(view.render(roots, 80, 5, frame).rows).toEqual(["ROW-97", "", "ROW-98", "", "ROW-99"]);
		view.scrollBy(-3);
		const browsing = view.render(roots, 80, 5, frame);
		expect(browsing.rows).toEqual(["", "ROW-96", "", "ROW-97", ""]);
		roots.push(component("ROW-100"));
		expect(view.render(roots, 80, 5, frame).rows).toEqual(browsing.rows);
		view.scrollBy(10000);
		expect(view.render(roots, 80, 5, frame).rows).toEqual(["ROW-98", "", "ROW-99", "", "ROW-100"]);
		roots.push(component("ROW-101"));
		expect(view.render(roots, 80, 5, frame).rows.at(-1)).toBe("ROW-101");
	});

	it("trims blank edges, ignores empty blocks, and maps spans to raw component rows", () => {
		const a = component("", "a", "b", "");
		const b = component("", "c", "");
		const view = new TranscriptViewport();
		const result = view.render([component("", ""), a, component(), b], 80, 20, frame);
		expect(result.rows).toEqual(["a", "b", "", "c"]);
		expect(result.atStart).toBe(true);
		expect(result.atEnd).toBe(true);
		expect(result.spans.map(span => [span.component, span.start, span.end, span.getComponentRow?.(0)])).toEqual([
			[a, 0, 2, 1],
			[b, 3, 4, 1],
		]);
		view.scrollBy(-100);
		expect(view.render([a, b], 80, 3, frame).rows).toEqual(["a", "b", ""]);
	});

	it("retains component identity through insert/move/delete and clamps resized/collapsed blocks", () => {
		let rows = ["a0", "a1", "a2", "a3", "a4"];
		const a: Component = { render: () => rows };
		const roots = [component("before"), a, component("after0", "after1", "after2")];
		const view = new TranscriptViewport();
		view.render(roots, 80, 3, frame);
		view.scrollBy(-4);
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["a2", "a3", "a4"]);
		roots.unshift(component("inserted"));
		expect(view.render(roots, 40, 3, frame).rows[0]).toBe("a2");
		rows = ["collapsed"];
		expect(view.render(roots, 40, 3, frame).rows).toEqual(["collapsed", "", "after0"]);
		roots.splice(roots.indexOf(a), 1);
		expect(view.render(roots, 40, 2, frame).rows).toEqual(["after0", "after1"]);
	});

	it("recovers moved/replaced anchors and clamps both document edges", () => {
		const roots = numbered(12);
		const view = new TranscriptViewport();
		view.render(roots, 80, 3, frame);
		view.scrollBy(-8);
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["ROW-6", "", "ROW-7"]);
		const [moved] = roots.splice(6, 1);
		roots.splice(4, 0, moved!);
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["ROW-6", "", "ROW-4"]);
		roots[4] = component("replacement");
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["replacement", "", "ROW-4"]);
		view.scrollBy(-1000);
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["ROW-0", "", "ROW-1"]);
		view.scrollBy(1000);
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["ROW-10", "", "ROW-11"]);
		roots.pop();
		roots.pop();
		expect(view.render(roots, 80, 3, frame).rows).toEqual(["ROW-8", "", "ROW-9"]);
	});

	it("keeps the browsing anchor while hidden and resets empty documents", () => {
		const roots = numbered(20);
		const view = new TranscriptViewport();
		view.render(roots, 80, 5, frame);
		view.scrollBy(-10);
		const before = view.render(roots, 80, 5, frame).rows;
		expect(view.render(roots, 80, 0, frame).rows).toEqual([]);
		expect(view.render(roots, 80, 5, frame).rows).toEqual(before);
		expect(view.render([], 80, 5, frame).atEnd).toBe(true);
		expect(view.render(roots, 80, 5, frame).rows.at(-1)).toBe("ROW-19");
		view.scrollBy(-5);
		view.render(roots, 80, 5, frame);
		view.reset();
		expect(view.render(roots, 80, 5, frame).rows.at(-1)).toBe("ROW-19");
	});

	it("renders only visible and crossed blocks in a 10,000-component document", () => {
		let calls = 0;
		const roots = Array.from({ length: 10000 }, (_, index): Component => ({
			render: () => {
				calls++;
				return [`ROW-${index}`];
			},
		}));
		const view = new TranscriptViewport();
		view.render(roots, 80, 23, frame);
		expect(calls).toBeLessThan(20);
		calls = 0;
		view.render(roots, 80, 23, frame);
		expect(calls).toBeLessThan(20);
		calls = 0;
		view.scrollBy(-6);
		expect(view.render(roots, 80, 23, frame).rows[0]).toBe("ROW-9985");
		expect(calls).toBeLessThan(25);
	});

	it("keeps image control rows byte-for-byte and requests complete block allocation", () => {
		const image = "\x1b_Ga=p,i=7,r=4;payload\x1b\\";
		let allocation = 0;
		const graphic = {
			render: () => ["reserved", "reserved", image],
			setTranscriptAllocation(rows: number) {
				allocation = rows;
			},
		};
		const result = new TranscriptViewport().render([graphic], 10, 2, frame);
		expect(result.rows).toEqual(["reserved", image]);
		expect(allocation).toBe(Number.MAX_SAFE_INTEGER);
		expect(result.spans[0]?.getComponentRow?.(0)).toBe(1);
	});
});
