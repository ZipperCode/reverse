import { beforeAll, describe, expect, it } from "bun:test";
import type { AgentTool } from "@reverse/agent";
import type { TSchema } from "@reverse/ai";
import { INTENT_FIELD } from "@reverse/wire";
import { resetSettingsForTest, Settings } from "@reverse/coding-agent/config/settings";
import { renderMCPResult, setMcpRenderMarkdownResults } from "@reverse/tui/tools/mcp";
import { DeferredMCPTool, MCPTool } from "@reverse/coding-agent/mcp/tool-bridge";
import { type MCPToolDetails } from "@reverse/tui/tools/mcp";
import type { MCPServerConnection, MCPToolDefinition, MCPTransport } from "@reverse/coding-agent/mcp/types";
import { ToolExecutionComponent } from "@reverse/tui/chat/tool-execution";
import { theme as activeTheme, getThemeByName, initTheme } from "@reverse/tui/theme";
import { type OutputMeta } from "@reverse/tui/tools/output-meta";
import { formatOutputNotice } from "@reverse/tui/tools/output-meta";
import { formatExpandHint, formatStatusIcon } from "@reverse/tui/render/render-utils";
import { TUI } from "@reverse/tui";
import { VirtualTerminal } from "../../tui/test/virtual-terminal";

beforeAll(async () => {
	resetSettingsForTest();
	await Settings.init({ inMemory: true, cwd: process.cwd() });
	await initTheme(false, undefined, undefined, "dark", "light");
}, 15_000);

async function getRequiredTheme() {
	const uiTheme = await getThemeByName("dark");
	if (!uiTheme) {
		throw new Error("dark theme missing");
	}
	return uiTheme;
}

function makeConnection(): MCPServerConnection {
	const transport: MCPTransport = {
		connected: true,
		request<T = unknown>(): Promise<T> {
			return Promise.reject(new Error("transport is not used by renderer tests"));
		},
		notify(): Promise<void> {
			return Promise.resolve();
		},
		close(): Promise<void> {
			return Promise.resolve();
		},
	};

	return {
		name: "sentry",
		config: { command: "sentry-mcp" },
		transport,
		serverInfo: { name: "sentry", version: "1.0.0" },
		capabilities: { tools: {} },
	};
}

function makeDefinition(): MCPToolDefinition {
	return {
		name: "search_events",
		description: "Search Sentry events",
		inputSchema: {
			type: "object",
			properties: { query: { type: "string" } },
			required: ["query"],
		},
	};
}

function makeTool(): MCPTool {
	return new MCPTool(makeConnection(), makeDefinition());
}

function makeDeferredTool(): DeferredMCPTool {
	return new DeferredMCPTool("sentry", makeDefinition(), () => Promise.resolve(makeConnection()));
}

type RenderableMCPAgentTool = AgentTool<TSchema, MCPToolDetails> & { mergeCallAndResult: true };

function makeAgentTool(mcpTool: MCPTool): RenderableMCPAgentTool {
	return {
		name: mcpTool.name,
		label: mcpTool.label,
		description: mcpTool.description,
		parameters: mcpTool.parameters,
		mergeCallAndResult: mcpTool.mergeCallAndResult,
		execute(): Promise<never> {
			return Promise.reject(new Error("MCP execution is not used by renderer tests"));
		},
		renderCall(args, options) {
			return mcpTool.renderCall(args, options, activeTheme);
		},
		renderResult(result, options) {
			return mcpTool.renderResult(result, options, activeTheme);
		},
	};
}

async function renderCompletedMCPTool(isError: boolean): Promise<string> {
	const mcpTool = makeTool();
	const tool = makeAgentTool(mcpTool);
	const tui = new TUI(new VirtualTerminal(120, 20));
	const component = new ToolExecutionComponent(tool.name, { query: "level:error" }, {}, tool, tui);

	component.updateResult(
		{
			content: [{ type: "text", text: isError ? "Error: denied" : '{"ok":true}' }],
			details: { serverName: "sentry", mcpToolName: "search_events", isError },
			...(isError ? { isError: true } : {}),
		},
		false,
	);

	return Bun.stripANSI(component.render(160).join("\n"));
}

describe("MCP tool rendering", () => {
	it("replaces the pending call header with a success header after completion", async () => {
		const uiTheme = await getRequiredTheme();
		const pendingIcon = Bun.stripANSI(formatStatusIcon("pending", uiTheme));
		const doneIcon = Bun.stripANSI(uiTheme.styledSymbol("tool.mcp", "accent"));

		const rendered = await renderCompletedMCPTool(false);

		expect(makeTool().mergeCallAndResult).toBe(true);
		expect(makeDeferredTool().mergeCallAndResult).toBe(true);
		expect(rendered).toContain(`${doneIcon} sentry/search_events`);
		expect(rendered).toContain("MCP");
		expect(rendered).not.toContain(`${pendingIcon} sentry/search_events`);
	}, 15_000);

	it("replaces the pending call header with an error header for MCP errors", async () => {
		const uiTheme = await getRequiredTheme();
		const pendingIcon = Bun.stripANSI(formatStatusIcon("pending", uiTheme));
		const errorIcon = Bun.stripANSI(formatStatusIcon("error", uiTheme));

		const rendered = await renderCompletedMCPTool(true);

		expect(rendered).toContain(`${errorIcon} sentry/search_events`);
		expect(rendered).toContain("MCP");
		expect(rendered).not.toContain(`${pendingIcon} sentry/search_events`);
	}, 15_000);

	it("strips the spill notice from the body and surfaces the artifact link as a styled warning", () => {
		const meta: OutputMeta = {
			truncation: {
				direction: "tail",
				truncatedBy: "bytes",
				totalLines: 100,
				totalBytes: 8000,
				outputLines: 4,
				outputBytes: 160,
				maxBytes: 1024,
				shownRange: { start: 97, end: 100 },
				artifactId: "7",
			},
		};
		// Mirror what the spill wrapper emits: the truncated body with the
		// LLM-facing notice appended (via formatOutputNotice) plus meta.truncation.
		const body = "event 97\nevent 98\nevent 99\nevent 100";
		const result = {
			content: [{ type: "text" as const, text: body + formatOutputNotice(meta) }],
			details: { serverName: "evk", mcpToolName: "peek", meta },
		};

		const rendered = Bun.stripANSI(
			renderMCPResult(result, { expanded: true, isPartial: false }, activeTheme).render(160).join("\n"),
		);

		expect(rendered).toContain("event 97");
		expect(rendered).toContain("event 100");
		expect(rendered).toContain("artifact://7");
		// The link appears exactly once — as the styled warning — proving the
		// inline notice was stripped from the body rather than echoed verbatim.
		expect(rendered.split("artifact://7").length - 1).toBe(1);
	}, 15_000);

	it("renders [MCP] badge in call header while pending", async () => {
		const mcpTool = makeTool();
		const tool = makeAgentTool(mcpTool);
		const tui = new TUI(new VirtualTerminal(120, 20));
		const component = new ToolExecutionComponent(tool.name, { query: "level:error" }, {}, tool, tui);

		const rendered = Bun.stripANSI(component.render(160).join("\n"));
		expect(rendered).toContain("sentry/search_events");
		expect(rendered).toContain("MCP");
	}, 15_000);

	it("renders [MCP] badge in Markdown MCP result", () => {
		setMcpRenderMarkdownResults(true);
		try {
			const result = {
				content: [{ type: "text" as const, text: "# Heading\nMarkdown content" }],
				details: { serverName: "docs", mcpToolName: "search" },
			};
			const rendered = Bun.stripANSI(
				renderMCPResult(result, { expanded: false, isPartial: false }, activeTheme, { query: "test" })
					.render(160)
					.join("\n"),
			);
			expect(rendered).toContain("docs/search");
			expect(rendered).toContain("MCP");
		} finally {
			setMcpRenderMarkdownResults(false);
		}
	});

	it("sets MCP badge on native tool head for describeCall and describeResult across success and error", () => {
		const mcpTool = makeTool();
		const callView = mcpTool.describeCall({ query: "active" }, { expanded: false, isPartial: true });
		expect(callView.tool?.badges).toEqual([{ text: "MCP", tone: "accent" }]);

		const resultView = mcpTool.describeResult(
			{
				content: [{ type: "text", text: '{"count": 5}' }],
				details: { serverName: "sentry", mcpToolName: "search_events" },
			},
			{ expanded: false, isPartial: false },
			{ query: "active" },
		);
		expect(resultView?.tool?.badges).toEqual([{ text: "MCP", tone: "accent" }]);

		const errorView = mcpTool.describeResult(
			{
				content: [{ type: "text", text: "Unauthorized" }],
				details: { serverName: "sentry", mcpToolName: "search_events", isError: true },
				isError: true,
			},
			{ expanded: false, isPartial: false },
			{ query: "active" },
		);
		expect(errorView?.tool?.badges).toEqual([{ text: "MCP", tone: "accent" }]);
	});

	it("falls back to title MCP without fabricated details and keeps MCP badge in native head", () => {
		const mcpTool = makeTool();
		const fallbackView = mcpTool.describeResult(
			{
				content: [{ type: "text", text: "raw error" }],
				isError: true,
			},
			{ expanded: false, isPartial: false },
			{ query: "active" },
		);
		expect(fallbackView?.tool?.title).toBe("MCP");
		expect(fallbackView?.tool?.badges).toEqual([{ text: "MCP", tone: "accent" }]);
	});

	it("renders 30-line output capped to 4 lines when collapsed and fully uncapped when expanded in both plain and markdown branches", () => {
		const lines30 = Array.from({ length: 30 }, (_, i) => `content row ${i + 1}`).join("\n");
		const result = {
			content: [{ type: "text" as const, text: lines30 }],
			details: { serverName: "docs", mcpToolName: "fetch" },
		};

		// 1. Plain text branch (Markdown disabled)
		setMcpRenderMarkdownResults(false);
		const dynamicHint = Bun.stripANSI(formatExpandHint(activeTheme, false, true));
		const collapsedPlain = Bun.stripANSI(
			renderMCPResult(result, { expanded: false, isPartial: false }, activeTheme, { query: "q" })
				.render(160)
				.join("\n"),
		);
		expect(collapsedPlain).toContain("content row 1");
		expect(collapsedPlain).toContain("content row 4");
		expect(collapsedPlain).not.toContain("content row 30");
		expect(collapsedPlain).toContain("… 26 more lines");
		expect(collapsedPlain).toContain(dynamicHint);
		const expandedPlain = Bun.stripANSI(
			renderMCPResult(result, { expanded: true, isPartial: false }, activeTheme, { query: "q" })
				.render(160)
				.join("\n"),
		);
		expect(expandedPlain).toContain("content row 1");
		expect(expandedPlain).toContain("content row 30");
		expect(expandedPlain).not.toContain("… 26 more lines");

		// 2. Markdown branch
		setMcpRenderMarkdownResults(true);
		try {
			const collapsedMd = Bun.stripANSI(
				renderMCPResult(result, { expanded: false, isPartial: false }, activeTheme, { query: "q" })
					.render(160)
					.join("\n"),
			);
			expect(collapsedMd).toContain("content row 1");
			expect(collapsedMd).toContain("content row 4");
			expect(collapsedMd).not.toContain("content row 30");
			expect(collapsedMd).toContain("… 26 more lines");
			expect(collapsedMd).toContain(dynamicHint);
			const expandedMd = Bun.stripANSI(
				renderMCPResult(result, { expanded: true, isPartial: false }, activeTheme, { query: "q" })
					.render(160)
					.join("\n"),
			);
			expect(expandedMd).toContain("content row 1");
			expect(expandedMd).toContain("content row 30");
			expect(expandedMd).not.toContain("… 26 more lines");
		} finally {
			setMcpRenderMarkdownResults(false);
		}
	});

	it("styles plain text and Markdown errors with error color rather than normal tool output", async () => {
		const uiTheme = await getRequiredTheme();
		const result = {
			content: [{ type: "text" as const, text: "Something failed badly" }],
			details: { serverName: "srv", mcpToolName: "fail", isError: true },
			isError: true,
		};

		// Plain text
		setMcpRenderMarkdownResults(false);
		const plainRaw = renderMCPResult(result, { expanded: false, isPartial: false }, uiTheme).render(160).join("\n");
		expect(plainRaw).toContain(uiTheme.fg("error", "Something failed badly"));

		// Markdown
		setMcpRenderMarkdownResults(true);
		try {
			const mdRaw = renderMCPResult(result, { expanded: false, isPartial: false }, uiTheme).render(160).join("\n");
			expect(mdRaw).toContain(uiTheme.fg("error", "Something failed badly"));
		} finally {
			setMcpRenderMarkdownResults(false);
		}
	});

	it("applies generic fallback via actual ToolExecutionComponent with 4-line collapsed and uncapped expanded", () => {
		const tui = new TUI(new VirtualTerminal(120, 20));
		const lines30 = Array.from({ length: 30 }, (_, i) => `generic row ${i + 1}`).join("\n");

		// Unknown tool uses generic fallback
		const component = new ToolExecutionComponent("custom_generic", { path: "demo.txt" }, {}, undefined, tui);
		component.updateResult({ content: [{ type: "text", text: lines30 }] }, false);

		const collapsed = Bun.stripANSI(component.render(120).join("\n"));
		const dynamicHint = Bun.stripANSI(formatExpandHint(activeTheme, false, true));
		expect(collapsed).toContain("generic row 1");
		expect(collapsed).toContain("generic row 4");
		expect(collapsed).not.toContain("generic row 30");
		expect(collapsed).toContain("… 26 more lines");
		expect(collapsed).toContain(dynamicHint);
		component.setExpanded(true);
		const expanded = Bun.stripANSI(component.render(120).join("\n"));
		expect(expanded).toContain("generic row 1");
		expect(expanded).toContain("generic row 30");
		expect(expanded).not.toContain("… 26 more lines");

		// Generic error via ToolExecutionComponent
		const errorComponent = new ToolExecutionComponent("custom_generic", { path: "demo.txt" }, {}, undefined, tui);
		errorComponent.updateResult({ content: [{ type: "text", text: lines30 }], isError: true }, false);
		const errorCollapsed = Bun.stripANSI(errorComponent.render(120).join("\n"));
		expect(errorCollapsed).toContain("generic row 1");
		expect(errorCollapsed).not.toContain("generic row 30");

		errorComponent.setExpanded(true);
		const errorExpanded = Bun.stripANSI(errorComponent.render(120).join("\n"));
		expect(errorExpanded).toContain("generic row 30");
	});

	it("handles missing details, bracket-leading invalid JSON and narrow width identities", () => {
		const invalidJson = "[not valid JSON\nsecond line";
		const result = {
			content: [{ type: "text" as const, text: invalidJson }],
		};

		// Missing details: title falls back to MCP
		const rendered = Bun.stripANSI(
			renderMCPResult(result, { expanded: false, isPartial: false }, activeTheme).render(120).join("\n"),
		);
		expect(rendered).toContain("MCP");
		expect(rendered).toContain("[not valid JSON");

		// Narrow width 40
		const narrow = Bun.stripANSI(
			renderMCPResult(result, { expanded: false, isPartial: false }, activeTheme).render(40).join("\n"),
		);
		expect(narrow).toContain("MCP");
	});

	it("strictly enforces single-expand-hint policy across MCP and generic outputs", () => {
		const dynamicHint = Bun.stripANSI(formatExpandHint(activeTheme, false, true));
		function countExpandHints(renderedText: string): number {
			if (!dynamicHint) return 0;
			return renderedText.split(dynamicHint).length - 1;
		}

		// 1. MCP complete output (2 lines) + NO visible args -> 0 hints
		const mcpNoArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: "line 1\nline 2" }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{},
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpNoArgs)).toBe(0);

		// 2. MCP complete output (2 lines) + metadata keys only -> 0 hints
		const mcpMetaOnly = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: "line 1\nline 2" }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{ [INTENT_FIELD]: "noise", __partialJson: "{}" },
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpMetaOnly)).toBe(0);

		// 3. MCP complete output (2 lines) + visible args -> exactly 1 hint
		const mcpWithArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: "line 1\nline 2" }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{ query: "target" },
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpWithArgs)).toBe(1);

		// 4. MCP 30-line output + visible args -> exactly 1 hint (on truncation line, no duplicate)
		const lines30 = Array.from({ length: 30 }, (_, i) => `row ${i}`).join("\n");
		const mcp30WithArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: lines30 }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{ query: "target" },
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcp30WithArgs)).toBe(1);

		// 5. MCP empty output + visible args -> exactly 1 hint; without args -> 0 hints
		const mcpEmptyWithArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: "" }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{ query: "target" },
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpEmptyWithArgs)).toBe(1);

		const mcpEmptyNoArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: "" }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{},
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpEmptyNoArgs)).toBe(0);

		// 6. MCP untruncated JSON + NO args -> 0 hints; with args -> 1 hint
		const mcpJsonNoArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: '{"ok":true}' }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{},
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpJsonNoArgs)).toBe(0);

		const mcpJsonWithArgs = Bun.stripANSI(
			renderMCPResult(
				{ content: [{ type: "text", text: '{"ok":true}' }] },
				{ expanded: false, isPartial: false },
				activeTheme,
				{ id: 10 },
			)
				.render(120)
				.join("\n"),
		);
		expect(countExpandHints(mcpJsonWithArgs)).toBe(1);

		// 7. Generic fallback: 1 line output + flat complete args -> 0 hints
		const tui = new TUI(new VirtualTerminal(120, 20));
		const genericFlat = new ToolExecutionComponent("custom_tool", { path: "test.txt" }, {}, undefined, tui);
		genericFlat.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericFlat.render(120).join("\n")))).toBe(0);

		// 8. Generic fallback: 1 line output + nested args -> exactly 1 hint
		const genericNested = new ToolExecutionComponent("custom_tool", { tags: ["alpha", "beta"] }, {}, undefined, tui);
		genericNested.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericNested.render(120).join("\n")))).toBe(1);

		// 9. Generic fallback: 30 lines output + nested args -> exactly 1 hint (no duplicate)
		const generic30Nested = new ToolExecutionComponent(
			"custom_tool",
			{ tags: ["alpha", "beta"] },
			{},
			undefined,
			tui,
		);
		generic30Nested.updateResult({ content: [{ type: "text", text: lines30 }] }, false);
		expect(countExpandHints(Bun.stripANSI(generic30Nested.render(120).join("\n")))).toBe(1);

		// 10. Generic fallback: literal ellipsis in arg value does not trigger false positive hint
		const genericLiteralEllipsis = new ToolExecutionComponent("custom_tool", { label: "wait…" }, {}, undefined, tui);
		genericLiteralEllipsis.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericLiteralEllipsis.render(120).join("\n")))).toBe(0);

		// 11. Generic fallback: genuinely truncated arg triggers exactly 1 hint
		const genericTruncatedArg = new ToolExecutionComponent(
			"custom_tool",
			{ label: `wait…${"a".repeat(200)}` },
			{},
			undefined,
			tui,
		);
		genericTruncatedArg.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericTruncatedArg.render(120).join("\n")))).toBe(1);

		// 12. Generic fallback: primitive and array args not shown collapsed trigger hint for hidden args
		const genericArrayArg = new ToolExecutionComponent("custom_tool", ["item1", "item2"], {}, undefined, tui);
		genericArrayArg.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericArrayArg.render(120).join("\n")))).toBe(1);

		const genericPrimitiveArg = new ToolExecutionComponent("custom_tool", "scalar-arg", {}, undefined, tui);
		genericPrimitiveArg.updateResult({ content: [{ type: "text", text: "done" }] }, false);
		expect(countExpandHints(Bun.stripANSI(genericPrimitiveArg.render(120).join("\n")))).toBe(1);
	});
});
