import { describe, expect, test } from "bun:test";
import { INTENT_FIELD } from "@reverse/wire";
import { formatArgsInline, JSON_TREE_MAX_DEPTH_EXPANDED, renderJsonTreeLines } from "@reverse/tui/tools/json-tree";
import { formatDefaultToolExecution } from "../src/tools/default-renderer";
import { initTheme, theme } from "@reverse/tui/theme";

describe("formatArgsInline", () => {
	test("a trailing scalar grows into the available width instead of a fixed cap", () => {
		// Regression: the value used to be hard-capped at 24 columns, so a long
		// note was truncated even when the card had plenty of room (issue: advise
		// preview cut to `note="Your “stric…"`).
		const note = "x".repeat(200);
		const narrow = formatArgsInline({ severity: "concern", note }, 40);
		const wide = formatArgsInline({ severity: "concern", note }, 120);
		expect(Bun.stringWidth(wide)).toBeGreaterThan(Bun.stringWidth(narrow) + 40);
		// Both stay within their budget.
		expect(Bun.stringWidth(narrow)).toBeLessThanOrEqual(40);
		expect(Bun.stringWidth(wide)).toBeLessThanOrEqual(120);
	});

	test("every key stays visible even when a leading value is long", () => {
		const out = formatArgsInline({ path: "x".repeat(200), pattern: "needle", limit: 5 }, 80);
		expect(out).toContain("path=");
		expect(out).toContain("pattern=");
		expect(out).toContain("limit=");
		expect(Bun.stringWidth(out)).toBeLessThanOrEqual(80);
	});

	test("short values render fully without truncation markers", () => {
		expect(formatArgsInline({ a: "x", b: 5, c: true }, 80)).toBe('a="x", b=5, c=true');
	});

	test("hidden meta keys are skipped", () => {
		const out = formatArgsInline({ [INTENT_FIELD]: "noise", __partialJson: "{}", path: "src/foo.ts" }, 80);
		expect(out).toBe('path="src/foo.ts"');
	});
});

describe("renderJsonTreeLines truncation detection", () => {
	test("marks depth truncation when object exceeds maxDepth", async () => {
		await initTheme(false);
		const res = renderJsonTreeLines({ a: { b: { c: 1 } } }, theme, 2, 6, 60);
		expect(res.truncated).toBe(true);
	});

	test("marks scalar truncation when single-line string exceeds maxScalarLen", async () => {
		await initTheme(false);
		const res = renderJsonTreeLines({ text: "x".repeat(100) }, theme, 2, 6, 60);
		expect(res.truncated).toBe(true);
	});

	test("does not mark untruncated JSON values as truncated", async () => {
		await initTheme(false);
		const res = renderJsonTreeLines({ a: 1, b: "short" }, theme, 2, 6, 60);
		expect(res.truncated).toBe(false);
	});

	test("marks line truncation at expanded cap and consumer includes ellipsis indicator", async () => {
		await initTheme(false);
		const items = Array.from({ length: 250 }, (_, i) => ({ id: i, name: `item-${i}` }));
		const res = renderJsonTreeLines(items, theme, JSON_TREE_MAX_DEPTH_EXPANDED, 200, 2000);
		expect(res.truncated).toBe(true);
		expect(res.lines.length).toBeLessThanOrEqual(200);

		const consumerOutput = formatDefaultToolExecution(
			{
				label: "test_tool",
				args: {},
				result: { output: JSON.stringify(items) },
				options: { expanded: true, isPartial: false },
			},
			120,
			theme,
		);
		expect(consumerOutput).toContain("…");
	});
});
