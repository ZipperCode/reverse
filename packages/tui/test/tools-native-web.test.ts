import { describe, expect, it } from "bun:test";
import type { NativeChild, NativeNode } from "../src/native/node";
import { askToolRenderer } from "../src/tools/ask";
import { describeDefaultToolExecution } from "../src/tools/default-renderer";
import { describeMCPCall, describeMCPResult } from "../src/tools/mcp";
import type { RenderResultOptions } from "../src/tools/renderer";
import { ToolExecutionComponent } from "../src/chat/tool-execution";
import type { TUI } from "../src/tui";
import { webSearchToolRenderer } from "../src/tools/web-search";

const opts = { expanded: false, isPartial: false } as RenderResultOptions;

function nodes(children: readonly NativeChild[] | undefined): NativeNode[] {
	return (children ?? []).filter((c): c is NativeNode => typeof c === "object" && c !== null && "k" in c);
}

describe("web_search native view", () => {
	it("heads with the query and lists sources as linked rows with a domain mark", () => {
		const view = webSearchToolRenderer.describeResult(
			{
				content: [],
				details: {
					response: {
						provider: "parallel",
						answer: "The answer",
						sources: [{ url: "https://www.example.com/a", title: "Example", ageSeconds: 3 * 86400 }],
						model: "m1",
						usage: { inputTokens: 5 },
					},
				} as never,
			},
			opts,
			{ query: "what is x" },
		);
		expect(view?.tool?.target).toBe("what is x");
		expect(view?.tool?.targetKind).toBe("query");
		expect(view?.tool?.meta?.[0]).toMatch(/1 source$/);
		expect(view?.tool?.badges?.[0]?.title).toContain("in 5");
		const [answer, sources] = nodes(view?.body);
		expect(answer?.k).toBe("md");
		const rowNode = nodes(sources?.c)[0]!;
		expect(rowNode.p).toMatchObject({ role: "reverse.tool.source", href: "https://www.example.com/a" });
		const [mark, title, meta] = nodes(rowNode.c);
		expect(mark?.p).toMatchObject({ text: "E" });
		expect(title?.p).toMatchObject({ spans: [{ href: "https://www.example.com/a" }] });
		expect(meta?.p).toMatchObject({ spans: [{ t: "example.com · 3d" }] });
	});
});

describe("ask native view", () => {
	it("pending call is an inline head naming the question with a waiting line", () => {
		const view = askToolRenderer.describeCall({ question: "Pick one?\nmore", options: [{ label: "A" }] } as never);
		expect(view?.inline).toBe(true);
		expect(view?.tool?.target).toBe("Pick one?");
		expect(nodes(view?.body)).toHaveLength(1);
	});

	it("answered result marks the chosen option and quotes custom input", () => {
		const view = askToolRenderer.describeResult(
			{
				content: [],
				details: { question: "Pick?", options: ["A", "B"], selectedOptions: ["B"], customInput: "own" } as never,
			},
			opts,
		);
		const roles = nodes(view?.body)
			.filter(n => n.k === "row")
			.map(n => n.p?.role);
		expect(roles).toEqual(["reverse.tool.answer.off", "reverse.tool.answer", "reverse.tool.answer"]);
		const custom = nodes(view?.body).at(-1)!;
		expect(JSON.stringify(custom)).toContain("\u201cown\u201d");
	});
});

describe("generic / MCP native views", () => {
	it("default renderer summarizes args in the head and renders JSON output as a tree", () => {
		const view = describeDefaultToolExecution({
			label: "custom",
			args: { a: 1 },
			result: { output: '{"x":1}', isError: false },
			options: opts,
		});
		expect(view.tool).toMatchObject({ title: "custom", targetKind: "text" });
		expect(view.tool?.target).toContain("a");
		expect(nodes(view.body)[0]?.k).toBe("tree");
	});

	it("MCP call and result keep the full args in a folded Args section after the output", () => {
		const query = `find ${"long ".repeat(40)}terms`;
		const args = { query, i: "intent" };
		const call = describeMCPCall(args, "srv/tool");
		const res = describeMCPResult({ content: [{ type: "text", text: "[1,2]" }] }, opts, args);
		for (const view of [call, res]) {
			// The head summary clips the value; the folded section carries all of it.
			expect(view?.tool?.target).not.toContain(query);
			const section = nodes(view?.body).at(-1)!;
			expect(section).toMatchObject({ k: "section", key: "args", p: { collapsible: true, collapsed: true } });
			expect(JSON.stringify(section)).toContain(query);
			expect(JSON.stringify(section)).not.toContain("intent");
		}
		expect(nodes(res?.body).map(n => n.k)).toEqual(["tree", "section"]);
		expect(describeMCPCall({}, "srv/tool").body).toBeUndefined();
	});

	it("clamps native error diagnostics to 4 lines while collapsed and reveals full text when expanded", () => {
		const error30 = Array.from({ length: 30 }, (_, i) => `error stack line ${i + 1}`).join("\n");

		// Generic fallback
		const foldedGeneric = describeDefaultToolExecution({
			label: "custom_proc",
			args: { id: 42 },
			result: { output: error30, isError: true },
			options: { expanded: false, isPartial: false },
		});
		expect(foldedGeneric.tone).toBe("error");
		expect(foldedGeneric.preview).toEqual({ lines: 4 });
		const [genericNode] = nodes(foldedGeneric.body);
		expect(genericNode.p).toMatchObject({ role: "reverse.tool.error", lines: 4 });

		const expandedGeneric = describeDefaultToolExecution({
			label: "custom_proc",
			args: { id: 42 },
			result: { output: error30, isError: true },
			options: { expanded: true, isPartial: false },
		});
		const [expandedNode] = nodes(expandedGeneric.body);
		expect(expandedNode.p).toMatchObject({ role: "reverse.tool.error", lines: undefined });

		// MCP result
		const foldedMcp = describeMCPResult(
			{
				content: [{ type: "text", text: error30 }],
				details: { serverName: "db", mcpToolName: "query", isError: true },
				isError: true,
			},
			{ expanded: false, isPartial: false },
			{ query: "SELECT 1" },
		);
		expect(foldedMcp?.tone).toBe("error");
		expect(foldedMcp?.preview).toEqual({ lines: 4 });
		expect(foldedMcp?.tool?.badges).toEqual([{ text: "MCP", tone: "accent" }]);
		const [mcpNode] = nodes(foldedMcp?.body);
		expect(mcpNode.p).toMatchObject({ role: "reverse.tool.error", lines: 4 });

		const expandedMcp = describeMCPResult(
			{
				content: [{ type: "text", text: error30 }],
				details: { serverName: "db", mcpToolName: "query", isError: true },
				isError: true,
			},
			{ expanded: true, isPartial: false },
			{ query: "SELECT 1" },
		);
		const [expandedMcpNode] = nodes(expandedMcp?.body);
		expect(expandedMcpNode.p).toMatchObject({ role: "reverse.tool.error", lines: undefined });
	});

	it("keeps final error card open with collapsed: false in ToolExecutionComponent", () => {
		const ui = {
			requestRender: () => {},
			requestComponentRender: () => {},
			resetDisplay: () => {},
		} as unknown as TUI;
		const tool = new ToolExecutionComponent("unknown_tool", { arg: "val" }, {}, undefined, ui);
		tool.setArgsComplete("call-1");
		tool.setExecutionStarted("call-1");
		tool.updateResult({ content: [{ type: "text", text: "Fatal error" }], isError: true }, false);

		const described = tool.describe();
		expect(described.p).toMatchObject({ status: "error", collapsed: false });
	});

	it("MCP sends JSON output and args to a host that draws json as values, less the hidden root keys", () => {
		const json = { ...opts, json: true };
		const args = { query: "tokyo", limit: 2, i: "intent" };
		const text = JSON.stringify({ hits: [{ id: 1 }], __partialJson: "{" });
		const res = describeMCPResult({ content: [{ type: "text", text }] }, json, args);
		const [output, section] = nodes(res?.body);
		expect(output?.k).toBe("json");
		expect(output?.p).toEqual({ value: { hits: [{ id: 1 }] } });
		const argsNode = nodes(section?.c)[0];
		expect(argsNode?.k).toBe("json");
		expect(argsNode?.p).toEqual({ value: { query: "tokyo", limit: 2 } });
		const call = describeMCPCall(args, "srv/tool", json);
		expect(nodes(nodes(call.body)[0]?.c)[0]?.k).toBe("json");
	});
});
