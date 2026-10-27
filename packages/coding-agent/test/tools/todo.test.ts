import { beforeAll, describe, expect, it } from "bun:test";
import * as path from "node:path";
import { type } from "@reverse/reversetype";
import { Settings } from "@reverse/coding-agent/config/settings";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { initTheme, theme } from "@reverse/tui/theme";
import {
	markdownToPhases,
	nextActionableTask,
	phasesToMarkdown,
	resolveTodoMarkdownPath,
	TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE,
	TodoTool,
	type ToolSession,
} from "@reverse/coding-agent/tools";
import {
	selectCollapsedTodos,
	TODO_STRIKE_HOLD_FRAMES,
	TODO_STRIKE_TOTAL_FRAMES,
	type TodoItem,
	type TodoPhase,
	todoMatchesAnyDescription,
	todoToolRenderer,
} from "@reverse/tui/tools/todo";
import type { Component } from "@reverse/tui";

function createSession(initialPhases: TodoPhase[] = []): ToolSession {
	let phases = initialPhases;
	return {
		cwd: "/tmp/test",
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated(),
		getTodoPhases: () => phases,
		setTodoPhases: next => {
			phases = next;
		},
	};
}

beforeAll(async () => {
	await initTheme();
});

describe("resolveTodoMarkdownPath", () => {
	it("defaults to TODO.md under cwd", () => {
		const cwd = path.resolve("tmp", "todo-workspace");

		expect(resolveTodoMarkdownPath("", cwd)).toBe(path.join(cwd, "TODO.md"));
	});

	it("strips surrounding double quotes before resolving", () => {
		const cwd = path.resolve("tmp", "todo-workspace");

		expect(resolveTodoMarkdownPath('"my todos.md"', cwd)).toBe(path.join(cwd, "my todos.md"));
	});

	it("rejects internal URL schemes", () => {
		const cwd = path.resolve("tmp", "todo-workspace");

		expect(() => resolveTodoMarkdownPath("artifact://todo", cwd)).toThrow("internal scheme");
	});
});

describe("TodoTool auto-start behavior", () => {
	it("auto-starts the first task after init", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", {
			op: "init",
			list: [{ phase: "Execution", items: ["status", "diagnostics"] }],
		});

		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => task.status)).toEqual(["in_progress", "pending"]);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary from todo");
		expect(summary.text).toContain("Remaining items (2):");
		expect(summary.text).toContain("status [in_progress] (Execution)");
		expect(summary.text).toContain("diagnostics [pending] (Execution)");
	});

	it("auto-promotes the next pending task when current task is completed", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [{ phase: "Execution", items: ["status", "diagnostics"] }],
		});

		const result = await tool.execute("call-2", { op: "done", task: "status" });

		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => task.status)).toEqual(["completed", "in_progress"]);
		expect(result.details?.completedTasks).toEqual([{ phase: "Execution", content: "status" }]);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary from todo");
		expect(summary.text).toContain("Remaining items (1):");
		expect(summary.text).toContain("diagnostics [in_progress] (Execution)");
		const completedResult = await tool.execute("call-3", { op: "done", task: "diagnostics" });
		const completedSummary = completedResult.content.find(part => part.type === "text");
		if (completedSummary?.type !== "text") {
			throw new Error("Expected text summary from todo");
		}
		expect(completedSummary.text).toContain("Remaining items: none.");
	});
});

describe("nextActionableTask", () => {
	it("returns the in-progress task before the first pending task across phases", () => {
		const task = nextActionableTask([
			{
				name: "First",
				tasks: [{ content: "queued first", status: "pending" }],
			},
			{
				name: "Second",
				tasks: [{ content: "active second", status: "in_progress" }],
			},
		]);

		expect(task?.content).toBe("active second");
	});

	it("falls back to the first pending task when nothing is in progress", () => {
		const task = nextActionableTask([
			{
				name: "Done",
				tasks: [{ content: "finished", status: "completed" }],
			},
			{
				name: "Next",
				tasks: [{ content: "first pending", status: "pending" }],
			},
		]);

		expect(task?.content).toBe("first pending");
	});
});

it("renders completed tasks as checked before revealing strikethrough", async () => {
	const tool = new TodoTool(createSession());
	await tool.execute("call-1", { op: "init", list: [{ phase: "Execution", items: ["finish"] }] });
	const result = await tool.execute("call-2", { op: "done", task: "finish" });
	const options = { expanded: true, isPartial: false, spinnerFrame: 0 };
	const component = todoToolRenderer.renderResult(result, options, theme);

	const firstFrame = component.render(120).join("\n");
	expect(Bun.stripANSI(firstFrame)).toContain("finish");
	expect(firstFrame).not.toContain("\x1b[9m");

	options.spinnerFrame = TODO_STRIKE_HOLD_FRAMES + 1;
	const revealFrame = component.render(120).join("\n");
	expect(Bun.stripANSI(revealFrame)).toContain("finish");
	expect(revealFrame).toContain("\x1b[9m");
});

describe("TodoTool operations", () => {
	it("jumps to a specific task out of order", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [{ phase: "Phase A", items: ["first", "second", "third"] }],
		});

		const result = await tool.execute("call-2", { op: "start", task: "third" });

		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => task.status)).toEqual(["pending", "pending", "in_progress"]);
		expect(result.details?.op).toBe("start");
	});

	it("demotes the current in_progress task when starting another", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [
				{ phase: "A", items: ["a1", "a2"] },
				{ phase: "B", items: ["b1"] },
			],
		});

		const result = await tool.execute("call-2", { op: "start", task: "b1" });

		const allTasks = result.details?.phases.flatMap(phase => phase.tasks) ?? [];
		expect(allTasks.map(task => task.status)).toEqual(["pending", "pending", "in_progress"]);
	});

	it("appends items to an existing phase", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["First"] }] });

		const result = await tool.execute("call-2", {
			op: "append",
			phase: "Work",
			items: ["Second"],
		});

		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => ({ content: task.content, status: task.status }))).toEqual([
			{ content: "First", status: "in_progress" },
			{ content: "Second", status: "pending" },
		]);
	});

	it("blocks a task (excluded from remaining, counted distinctly) and unblocks it", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a", "b"] }] });

		const blocked = await tool.execute("call-2", { op: "block", task: "b", reason: "waiting on sign-off" });
		const bTask = blocked.details?.phases[0]?.tasks.find(task => task.content === "b");
		expect(bTask?.status).toBe("blocked");
		expect(bTask?.blocker).toBe("waiting on sign-off");
		const summary = blocked.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary from todo");
		// `a` stays the only open item; `b` leaves the remaining/open set but is surfaced as blocked.
		expect(summary.text).toContain("Remaining items (1):");
		expect(summary.text).toContain("1 blocked");

		const unblocked = await tool.execute("call-3", { op: "unblock", task: "b" });
		const bAfter = unblocked.details?.phases[0]?.tasks.find(task => task.content === "b");
		expect(bAfter?.status).toBe("pending");
		expect(bAfter?.blocker).toBeUndefined();
	});

	it("does not auto-promote a blocked task to in_progress", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["only"] }] });

		const result = await tool.execute("call-2", { op: "block", task: "only" });

		// `only` was in_progress; blocking it leaves no pending/in_progress, so normalization must not revive it.
		expect(result.details?.phases[0]?.tasks[0]?.status).toBe("blocked");
	});

	it("blocking a phase leaves completed/abandoned tasks closed", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a", "b", "c"] }] });
		await tool.execute("call-2", { op: "done", task: "a" });
		await tool.execute("call-3", { op: "drop", task: "c" });

		const result = await tool.execute("call-4", { op: "block", phase: "Work", reason: "waiting on infra" });
		const tasks = result.details?.phases[0]?.tasks ?? [];
		const byContent = (content: string) => tasks.find(task => task.content === content);
		// Completed/abandoned work is untouched; only the open task becomes blocked.
		expect(byContent("a")?.status).toBe("completed");
		expect(byContent("c")?.status).toBe("abandoned");
		expect(byContent("b")?.status).toBe("blocked");
		expect(byContent("b")?.blocker).toBe("waiting on infra");
		// A completed task must never carry a blocker note.
		expect(byContent("a")?.blocker).toBeUndefined();
	});

	it("re-blocking an already-blocked task refines its blocker note", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a", "b"] }] });
		// First block with no reason, then block again to add one — the agent often
		// learns what it's waiting on only after the initial block.
		await tool.execute("call-2", { op: "block", task: "b" });
		const first = await tool.execute("call-3", { op: "block", task: "b" });
		expect(first.details?.phases[0]?.tasks.find(task => task.content === "b")?.blocker).toBeUndefined();

		const refined = await tool.execute("call-4", { op: "block", task: "b", reason: "waiting on user" });
		const bTask = refined.details?.phases[0]?.tasks.find(task => task.content === "b");
		expect(bTask?.status).toBe("blocked");
		expect(bTask?.blocker).toBe("waiting on user");
	});

	it("rejects a block with neither task nor phase target", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a", "b"] }] });

		const result = await tool.execute("call-2", { op: "block", reason: "oops" });
		expect(result.isError).toBe(true);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary from todo");
		expect(summary.text).toContain("block requires a task or phase target");
		// Nothing was blocked — state is unchanged.
		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.every(task => task.status !== "blocked")).toBe(true);
	});

	it("rejects an unblock with neither task nor phase target", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a"] }] });
		await tool.execute("call-2", { op: "block", task: "a", reason: "x" });

		const result = await tool.execute("call-3", { op: "unblock" });
		expect(result.isError).toBe(true);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary from todo");
		expect(summary.text).toContain("unblock requires a task or phase target");
		// The blocked task stays blocked — the targetless unblock was rejected.
		expect(result.details?.phases[0]?.tasks[0]?.status).toBe("blocked");
	});

	it("preserves blocked status across the markdown round-trip", () => {
		const phases: TodoPhase[] = [
			{
				name: "Work",
				tasks: [
					{ content: "a", status: "blocked", blocker: "x" },
					{ content: "b", status: "completed" },
				],
			},
		];
		const md = phasesToMarkdown(phases);
		expect(md).toContain("- [!] a");

		const { phases: parsed, errors } = markdownToPhases(md);
		expect(errors).toEqual([]);
		const parsedA = parsed[0]?.tasks.find(task => task.content === "a");
		expect(parsedA?.status).toBe("blocked");
		// The blocker reason must survive the round-trip, not just the status.
		expect(parsedA?.blocker).toBe("x");
	});

	it("parses checklist items with backslash-escaped brackets from /todo edit", () => {
		// Editors/serializers (e.g. content pasted from a markdown renderer) escape
		// `[` and `]`; the line still renders as a checkbox, so it must parse rather
		// than error out and drop the user's edits (issue #9188).
		const md = ["# Todos", "* \\[x] first", "- \\[ \\] second", "+ \\[/\\] third"].join("\n");
		const { phases, errors } = markdownToPhases(md);
		expect(errors).toEqual([]);
		const tasks = phases[0]?.tasks ?? [];
		expect(tasks).toEqual([
			{ content: "first", status: "completed" },
			{ content: "second", status: "pending" },
			{ content: "third", status: "in_progress" },
		]);
	});

	it("normalizes a multi-line blocker reason so the markdown round-trip survives", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["a"] }] });
		// A blocker reason lifted from a multi-line external error or user question.
		const blocked = await tool.execute("call-2", {
			op: "block",
			task: "a",
			reason: "waiting on user:\nline two\n\tindented three",
		});
		const phases = blocked.details?.phases ?? [];
		const stored = phases[0]?.tasks.find(task => task.content === "a");
		// Normalized at the source: whitespace runs (incl. newlines) collapse to
		// single spaces, so every one-line consumer stays intact.
		expect(stored?.blocker).toBe("waiting on user: line two indented three");

		// Without normalization the embedded newline splits the HTML comment across
		// two markdown lines: line one is an unclosed `<!-- blocker: …` and line two
		// parses as unrecognized syntax, losing the reason and adding an error.
		const md = phasesToMarkdown(phases);
		expect(md.split("\n").filter(line => line.includes("- [!]"))).toHaveLength(1);
		const { phases: parsed, errors } = markdownToPhases(md);
		expect(errors).toEqual([]);
		const parsedA = parsed[0]?.tasks.find(task => task.content === "a");
		expect(parsedA?.status).toBe("blocked");
		expect(parsedA?.blocker).toBe("waiting on user: line two indented three");
	});

	it("creates a phase when append targets a missing phase", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["First"] }] });

		const result = await tool.execute("call-2", {
			op: "append",
			phase: "Cleanup",
			items: ["Remove dead code"],
		});

		expect(result.details?.phases.map(phase => phase.name)).toEqual(["Work", "Cleanup"]);
		expect(result.details?.phases[1]?.tasks.map(task => task.content)).toEqual(["Remove dead code"]);
	});

	it("marks all tasks in a phase done", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [
				{ phase: "Work", items: ["First", "Second"] },
				{ phase: "Later", items: ["Third"] },
			],
		});

		const result = await tool.execute("call-2", { op: "done", phase: "Work" });
		const allTasks = result.details?.phases.flatMap(phase => phase.tasks) ?? [];
		expect(allTasks.map(task => task.status)).toEqual(["completed", "completed", "in_progress"]);
	});

	it("removes all tasks when rm omits task and phase", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [{ phase: "Work", items: ["First", "Second"] }],
		});

		const result = await tool.execute("call-2", { op: "rm" });
		expect(result.details?.phases[0]?.tasks).toEqual([]);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("Todo list cleared.");
	});

	it("drops all tasks in a phase", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", {
			op: "init",
			list: [{ phase: "Work", items: ["First", "Second"] }],
		});

		const result = await tool.execute("call-2", { op: "drop", phase: "Work" });
		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => task.status)).toEqual(["abandoned", "abandoned"]);
	});

	it("view echoes state without mutating it", async () => {
		const session = createSession([
			{
				name: "Work",
				tasks: [
					{ content: "First", status: "pending" },
					{ content: "Second", status: "pending" },
				],
			},
		]);
		const tool = new TodoTool(session);

		const result = await tool.execute("call-1", { op: "view" });

		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => task.status)).toEqual(["pending", "pending"]);
		// A read never normalizes or writes session state back.
		expect(session.getTodoPhases?.()?.[0]?.tasks.map(task => task.status)).toEqual(["pending", "pending"]);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("First");
		expect(summary.text).toContain("Second");
	});

	it("view on an empty list reports empty, not cleared", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", { op: "view" });
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("Todo list is empty.");
		expect(result.isError).toBeUndefined();
	});
});

describe("TodoTool lenient init shapes", () => {
	it("accepts a flattened init with bare items and no phase", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", { op: "init", items: ["First", "Second"] });

		expect(result.isError).toBeUndefined();
		expect(result.details?.phases.map(phase => phase.name)).toEqual(["Tasks"]);
		const tasks = result.details?.phases[0]?.tasks ?? [];
		expect(tasks.map(task => ({ content: task.content, status: task.status }))).toEqual([
			{ content: "First", status: "in_progress" },
			{ content: "Second", status: "pending" },
		]);
	});

	it("honors a bare phase on a flattened init", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", { op: "init", phase: "Cleanup", items: ["Remove dead code"] });

		expect(result.isError).toBeUndefined();
		expect(result.details?.phases.map(phase => phase.name)).toEqual(["Cleanup"]);
		expect(result.details?.phases[0]?.tasks.map(task => task.content)).toEqual(["Remove dead code"]);
	});

	it("still errors when init has neither list nor items", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", { op: "init" });

		expect(result.isError).toBe(true);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("Missing list for init operation");
	});
});
describe("TodoTool lenient op recovery", () => {
	// Regression: models occasionally drop `op` while sending an otherwise
	// valid payload (e.g. `{list:[...]}`). The schema keeps `op` required, but
	// `lenientArgValidation` routes the raw args to execute(), which infers
	// the op for unambiguous shapes instead of failing the call.
	it("keeps op required at the schema boundary but lenient at execute", () => {
		const tool = new TodoTool(createSession());
		expect(tool.parameters({ list: [{ phase: "Fixes", items: ["One"] }] }) instanceof type.errors).toBe(true);
		expect(tool.lenientArgValidation).toBe(true);
	});

	it("infers init from a bare list payload", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", {
			list: [{ phase: "Fixes", items: ["Bytecompiler ordering", "Posix path fd handling"] }],
		} as never);

		expect(result.isError).toBeUndefined();
		expect(result.details?.op).toBe("init");
		expect(result.details?.phases.map(phase => phase.name)).toEqual(["Fixes"]);
		expect(result.details?.phases[0]?.tasks.map(task => task.content)).toEqual([
			"Bytecompiler ordering",
			"Posix path fd handling",
		]);
	});

	it("infers append from phase plus items", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["First"] }] });

		const result = await tool.execute("call-2", { phase: "Work", items: ["Second"] } as never);

		expect(result.isError).toBeUndefined();
		expect(result.details?.op).toBe("append");
		expect(result.details?.phases[0]?.tasks.map(task => task.content)).toEqual(["First", "Second"]);
	});

	it("infers init from bare items only when no todos exist", async () => {
		const fresh = new TodoTool(createSession());
		const initialized = await fresh.execute("call-1", { items: ["Only task"] } as never);
		expect(initialized.isError).toBeUndefined();
		expect(initialized.details?.op).toBe("init");

		// With existing todos the same shape is ambiguous (flat init would wipe
		// the list; append lacks a phase) and must error instead of guessing.
		const populated = new TodoTool(
			createSession([{ name: "Work", tasks: [{ content: "First", status: "pending" }] }]),
		);
		const ambiguous = await populated.execute("call-2", { items: ["Second"] } as never);
		expect(ambiguous.isError).toBe(true);
	});

	it("surfaces the schema error when op is missing and not inferable", async () => {
		const tool = new TodoTool(createSession());
		const result = await tool.execute("call-1", { task: "Something" } as never);

		expect(result.isError).toBe(true);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("Invalid todo arguments");
		expect(summary.text).toContain("op");
	});
});

describe("TodoTool empty items tolerance", () => {
	// Regression: a stray `items: []` on an op that ignores items (here `view`)
	// must not be a hard schema rejection. The top-level `items` array dropped
	// its `atLeastLength(1)` so callers don't get "items must be tasks to append"
	// for an irrelevant empty array; length is enforced per-op at runtime.
	it("accepts op:view with an empty items array at the schema boundary", () => {
		const schema = new TodoTool(createSession()).parameters;
		expect(schema({ op: "view", items: [] }) instanceof type.errors).toBe(false);
	});

	it("defers empty append items to an op-specific runtime error", async () => {
		const tool = new TodoTool(createSession());
		await tool.execute("call-1", { op: "init", list: [{ phase: "Work", items: ["First"] }] });

		const result = await tool.execute("call-2", { op: "append", phase: "Work", items: [] });

		expect(result.isError).toBe(true);
		const summary = result.content.find(part => part.type === "text");
		if (summary?.type !== "text") throw new Error("Expected text summary");
		expect(summary.text).toContain("Missing items for append operation");
	});
});

describe("todoMatchesAnyDescription", () => {
	it("matches case- and whitespace-insensitively", () => {
		expect(todoMatchesAnyDescription("  Sonnet  #1: AGENTS Audit  ", ["sonnet #1: agents audit"])).toBe(true);
	});

	it("matches when description is a long-enough substring of the todo", () => {
		expect(todoMatchesAnyDescription("Sonnet #2: shallow bug scan of diff", ["Sonnet #2"])).toBe(true);
	});

	it("matches when the todo is a long-enough substring of a description", () => {
		expect(todoMatchesAnyDescription("Sonnet #3", ["Sonnet #3: git blame / history check"])).toBe(true);
	});

	it("rejects substring matches below the minimum overlap", () => {
		// "Fix" is 3 chars — too short to qualify on either side.
		expect(todoMatchesAnyDescription("Fix", ["Fix the auth module bug"])).toBe(false);
		expect(todoMatchesAnyDescription("Fix the auth module bug", ["Fix"])).toBe(false);
	});

	it("ignores empty inputs without throwing", () => {
		expect(todoMatchesAnyDescription("", ["Sonnet #1"])).toBe(false);
		expect(todoMatchesAnyDescription("Sonnet #1", [""])).toBe(false);
		expect(todoMatchesAnyDescription("Sonnet #1", [])).toBe(false);
	});

	it("returns true on the first match without scanning further descriptions", () => {
		expect(
			todoMatchesAnyDescription("Sonnet #2: shallow bug scan", ["unrelated agent task", "Sonnet #2", "Sonnet #3"]),
		).toBe(true);
	});

	it("returns false when no description overlaps the todo", () => {
		expect(todoMatchesAnyDescription("Sonnet #2: shallow bug scan", ["Reviewer1AgentsAdherence", "git blame"])).toBe(
			false,
		);
	});

	it("ignores punctuation differences in identifiers", () => {
		// One side has a method-prefix '#', the other doesn't. Reproduced
		// from a real run where 3 subagents were spawned but only 2 of 3
		// matched todos lit up because the matcher's normalizer collapsed
		// whitespace but left punctuation intact.
		expect(
			todoMatchesAnyDescription("Audit integration site in renderTodoList", [
				"Audit integration site in #renderTodoList",
			]),
		).toBe(true);
		// Dotted abbreviations like AGENTS.md collapse to a space too.
		expect(todoMatchesAnyDescription("Audit AGENTS.md compliance", ["Audit AGENTS md compliance"])).toBe(true);
	});
});
describe("todoToolRenderer.renderResult phase collapsing", () => {
	async function buildThreePhaseAfterDone() {
		const tool = new TodoTool(createSession());
		await tool.execute("init", {
			op: "init",
			list: [
				{ phase: "Alpha", items: ["a1", "a2"] },
				{ phase: "Beta", items: ["b1", "b2"] },
				{ phase: "Gamma", items: ["c1", "c2"] },
			],
		});
		// `done a1` keeps the active task inside Alpha (auto-promotes a2), leaving
		// Beta and Gamma untouched by this update.
		return tool.execute("done", { op: "done", task: "a1" });
	}
	function innerLines(component: Component): string[] {
		const lines = Bun.stripANSI(component.render(100).join("\n")).split("\n");
		return lines.slice(1, -1).map(line =>
			line
				.replace(/^│/, "")
				.replace(/│\s*$/, "")
				.trim(),
		);
	}
	it("collapses untouched phases to a one-line summary while expanding the active phase", async () => {
		const result = await buildThreePhaseAfterDone();
		const component = todoToolRenderer.renderResult(result, { expanded: false, isPartial: false }, theme, {
			op: "done",
			task: "a1",
		});
		const rendered = Bun.stripANSI(component.render(100).join("\n"));
		// Active phase's collapsed viewport keeps the just-closed task as the lead
		// row and shows the promoted current one (#5873), and its header carries
		// progress so the phase being worked on is not the one phase with no
		// completion signal.
		expect(rendered).toContain("a1");
		expect(rendered).toContain("a2");
		expect(rendered).toContain("I. Alpha  1/2");
		// Untouched phases collapse: headers + progress counts, no task contents.
		expect(rendered).toContain("II. Beta");
		expect(rendered).toContain("III. Gamma");
		expect(rendered).toContain("0/2");
		expect(rendered).not.toContain("b1");
		expect(rendered).not.toContain("b2");
		expect(rendered).not.toContain("c1");
		expect(rendered).not.toContain("c2");
	});
	it("sweeps the just-completed row's strike in the collapsed view", async () => {
		const result = await buildThreePhaseAfterDone();
		// The card's default view is collapsed, so the completion animation the
		// `completedTasks` plumbing drives has to land there — while the viewport
		// dropped every closed row, the animation ran against a row nobody rendered.
		const strikeSpan = (spinnerFrame: number): string => {
			const rendered = todoToolRenderer
				.renderResult(result, { expanded: false, isPartial: false, spinnerFrame }, theme, {
					op: "done",
					task: "a1",
				})
				.render(100)
				.join("\n");
			return /\x1b\[9m(.*?)\x1b\[29m/.exec(rendered)?.[1] ?? "";
		};
		expect(strikeSpan(0)).toBe("");
		expect(strikeSpan(TODO_STRIKE_TOTAL_FRAMES)).toBe("a1");
	});
	it("falls back to in_progress / completed signals when call args are unavailable", async () => {
		const result = await buildThreePhaseAfterDone();
		// Transcript rebuilds may not carry call args; the active (Alpha) phase is
		// still derived from the in_progress task and the completion transition.
		const component = todoToolRenderer.renderResult(result, { expanded: false, isPartial: false }, theme);
		const rendered = Bun.stripANSI(component.render(100).join("\n"));
		expect(rendered).toContain("a2");
		expect(rendered).not.toContain("b1");
		expect(rendered).not.toContain("c1");
	});
	it("shows every phase fully when manually expanded", async () => {
		const result = await buildThreePhaseAfterDone();
		const component = todoToolRenderer.renderResult(result, { expanded: true, isPartial: false }, theme, {
			op: "done",
			task: "a1",
		});
		const rendered = Bun.stripANSI(component.render(100).join("\n"));
		expect(rendered).toContain("b1");
		expect(rendered).toContain("b2");
		expect(rendered).toContain("c1");
		expect(rendered).toContain("c2");
	});
	it("drops blank separator lines between phases", async () => {
		const result = await buildThreePhaseAfterDone();
		const component = todoToolRenderer.renderResult(result, { expanded: true, isPartial: false }, theme, {
			op: "done",
			task: "a1",
		});
		// No empty body line survives between phases.
		expect(innerLines(component).every(line => line.length > 0)).toBe(true);
	});
});

describe("selectCollapsedTodos walking viewport (#5873)", () => {
	const mk = (n: number, inProgress: number[]): TodoItem[] =>
		Array.from({ length: n }, (_, i) => ({
			content: `Task ${i + 1}`,
			status: inProgress.includes(i + 1) ? "in_progress" : "pending",
		}));
	const never = () => false;
	const contents = (sel: { items: TodoItem[] }) => sel.items.map(t => t.content);

	it("starts at the sole in-progress task and fills with following tasks", () => {
		const sel = selectCollapsedTodos(mk(14, [6]), never, 8);
		expect(contents(sel)).toEqual([
			"Task 6",
			"Task 7",
			"Task 8",
			"Task 9",
			"Task 10",
			"Task 11",
			"Task 12",
			"Task 13",
		]);
		expect(sel.summary).toContain("6 more todos");
	});

	it("leads with the last closed task and omits the rest in collapsed mode", () => {
		const tasks: TodoItem[] = [
			{ content: "done", status: "completed" },
			{ content: "dropped", status: "abandoned" },
			{ content: "current", status: "in_progress" },
			{ content: "next", status: "pending" },
		];
		const sel = selectCollapsedTodos(tasks, never, 5);
		// One closed row survives so a completion is visible as it lands; earlier
		// closed work stays hidden.
		expect(contents(sel)).toEqual(["dropped", "current", "next"]);
		expect(sel.summary).toBe("");
	});

	it("keeps an out-of-order completion as the closed lead row", () => {
		const tasks: TodoItem[] = [
			{ content: "current", status: "in_progress" },
			{ content: "next", status: "pending" },
			{ content: "finished early", status: "completed" },
		];
		const sel = selectCollapsedTodos(tasks, never, 5);
		expect(contents(sel)).toEqual(["finished early", "current", "next"]);
	});

	it("keeps the closed lead row additive to the open-task cap", () => {
		const tasks: TodoItem[] = [{ content: "closed", status: "completed" }, ...mk(5, [1])];
		const sel = selectCollapsedTodos(tasks, never, 5);
		// All 5 open tasks fit the cap; the closed context row does not evict one.
		expect(contents(sel)).toEqual(["closed", "Task 1", "Task 2", "Task 3", "Task 4", "Task 5"]);
		expect(sel.summary).toBe("");
	});

	it("places every subagent-matched todo at the head in todo order", () => {
		const tasks = mk(14, []); // all pending
		const matched = (t: TodoItem) => t.content === "Task 3" || t.content === "Task 9";
		const sel = selectCollapsedTodos(tasks, matched, 5);
		// Both matched actives lead, then following pending fill from the first active.
		expect(contents(sel).slice(0, 2)).toEqual(["Task 3", "Task 9"]);
		expect(contents(sel)).toHaveLength(5);
	});

	it("caps active todos and counts the hidden actives in the summary", () => {
		const tasks = mk(10, []);
		const matched = (t: TodoItem) =>
			["Task 1", "Task 2", "Task 3", "Task 4", "Task 5", "Task 6", "Task 7"].includes(t.content);
		const sel = selectCollapsedTodos(tasks, matched, 5);
		expect(contents(sel)).toEqual(["Task 1", "Task 2", "Task 3", "Task 4", "Task 5"]);
		expect(sel.summary).toBe("… 2 more active todos");
		// No unrelated pending rows leak in.
		expect(contents(sel).some(c => ["Task 8", "Task 9", "Task 10"].includes(c))).toBe(false);
	});

	it("keeps a summary when actives exactly fill the cap but pending remains", () => {
		// 5 matched actives + 2 trailing pending, cap 5. The active-overflow branch
		// must NOT swallow the hidden pending work with an empty summary (#5878).
		const tasks = mk(7, []);
		const matched = (t: TodoItem) => ["Task 1", "Task 2", "Task 3", "Task 4", "Task 5"].includes(t.content);
		const sel = selectCollapsedTodos(tasks, matched, 5);
		expect(contents(sel)).toEqual(["Task 1", "Task 2", "Task 3", "Task 4", "Task 5"]);
		expect(sel.summary).toBe("… 2 more todos");
	});

	it("renders a lone hidden todo in place of a one-item summary row", () => {
		const pending = selectCollapsedTodos(mk(6, [1]), never, 5);
		expect(contents(pending)).toEqual(["Task 1", "Task 2", "Task 3", "Task 4", "Task 5", "Task 6"]);
		expect(pending.summary).toBe("");

		const active = selectCollapsedTodos(mk(6, []), () => true, 5);
		expect(contents(active)).toEqual(["Task 1", "Task 2", "Task 3", "Task 4", "Task 5", "Task 6"]);
		expect(active.summary).toBe("");
	});

	it("keeps an overflow summary when one active task overflows the cap and pending remains", () => {
		// 6 matched actives + 2 pending, cap 5: showing all 6 actives would hide the
		// pending work with no summary row at all.
		const sel = selectCollapsedTodos(mk(8, []), (t: TodoItem) => Number(t.content.slice(5)) <= 6, 5);
		expect(contents(sel)).toEqual(["Task 1", "Task 2", "Task 3", "Task 4", "Task 5"]);
		expect(sel.summary).toBe("… 1 more active todo");
	});

	it("returns the whole open set with no summary when it fits", () => {
		const sel = selectCollapsedTodos(mk(3, [2]), never, 5);
		expect(contents(sel)).toEqual(["Task 1", "Task 2", "Task 3"]);
		expect(sel.summary).toBe("");
	});

	it("falls back to closed tasks when the phase has no open work", () => {
		const tasks: TodoItem[] = [
			{ content: "done a", status: "completed" },
			{ content: "done b", status: "completed" },
		];
		const sel = selectCollapsedTodos(tasks, never, 5);
		expect(contents(sel)).toEqual(["done a", "done b"]);
	});
});

describe("todoToolRenderer.renderCall malformed-args regression (#2005)", () => {
	// Reporter saw `TypeError: args?.ops?.map is not a function` against
	// Xiaomi Token Plan's Anthropic protocol because `parseStreamingJson`
	// surfaced `{ ops: "[..." }` shapes mid-stream. The renderer is invoked
	// on every streaming delta, so any non-array `ops` (string, object,
	// number) must NOT crash the TUI render loop and trigger the spam-warn /
	// retry cascade.
	const renderOptions = { expanded: false, isPartial: true } as const;

	it("does not throw when op is a streaming-truncated number", () => {
		// Mid-stream the new flat shape can surface `{ op: 1 }` before the
		// discriminator string lands.
		const args = { op: 1 } as unknown as Parameters<typeof todoToolRenderer.renderCall>[0];
		expect(() => todoToolRenderer.renderCall(args, renderOptions, theme)).not.toThrow();
	});

	it("does not throw when a flat op's items field is a non-array", () => {
		const args = {
			op: "append",
			phase: "Work",
			items: "Second" as unknown as string[],
		} as unknown as Parameters<typeof todoToolRenderer.renderCall>[0];
		expect(() => todoToolRenderer.renderCall(args, renderOptions, theme)).not.toThrow();
	});

	it("does not throw on the legacy streaming-truncated `ops` string", () => {
		// Old transcripts/collab-web still carry `{ ops: "[{" }` mid-stream;
		// `normalizeTodoArg` must keep tolerating the legacy batch shape.
		const args = { ops: '[{"op":"init"' } as unknown as Parameters<typeof todoToolRenderer.renderCall>[0];
		expect(() => todoToolRenderer.renderCall(args, renderOptions, theme)).not.toThrow();
	});

	it("renders op summary metadata for a well-formed flat call", () => {
		const args = { op: "init", items: ["a", "b", "c"] };
		const component = todoToolRenderer.renderCall(args, renderOptions, theme);
		// `Text(text, 0, 0)` from `@reverse/tui` exposes the content via .render().
		const rendered = Bun.stripANSI(component.render(120).join("\n"));
		expect(rendered).toContain("init");
		expect(rendered).toContain("3 items");
	});

	it("still renders legacy multi-op `ops` arrays from old transcripts", () => {
		const args = {
			ops: [
				{ op: "init", items: ["a", "b", "c"] },
				{ op: "done", task: "a" },
				{ op: "append", phase: "Cleanup", items: ["d"] },
			],
		};
		const component = todoToolRenderer.renderCall(args, renderOptions, theme);
		const rendered = Bun.stripANSI(component.render(120).join("\n"));
		expect(rendered).toContain("init");
		expect(rendered).toContain("3 items");
		expect(rendered).toContain("done");
		expect(rendered).toContain("append");
		expect(rendered).toContain("Cleanup");
		expect(rendered).toContain("1 item");
	});
});

describe("todoToolRenderer.renderResult label sanitization", () => {
	// A mirrored Cursor snapshot carries provider text verbatim into
	// `details.phases`, and the renderer interpolates it straight into terminal
	// output. A label holding ANSI/C0 sequences would rewrite the terminal every
	// time the list renders or replays.
	function renderPhases(phases: TodoPhase[]): string {
		const result = {
			content: [{ type: "text" as const, text: "1/1 tasks completed" }],
			details: { phases, storage: "session" as const },
			isError: false,
		} as unknown as Parameters<typeof todoToolRenderer.renderResult>[0];
		const component = todoToolRenderer.renderResult(result, { expanded: true, isPartial: false }, theme);
		return component.render(120).join("\n");
	}

	it("strips control sequences from a mirrored task label", () => {
		const hostile = "clear\u001b[2Jscreen\u0007bell";
		const rendered = renderPhases([
			{ name: "Execution", tasks: [{ content: hostile, status: "pending" }] },
		] as unknown as TodoPhase[]);

		// The dangerous bytes are gone; the readable text survives.
		expect(rendered).not.toContain("\u001b[2J");
		expect(rendered).not.toContain("\u0007");
		expect(Bun.stripANSI(rendered)).toContain("clear");
		expect(Bun.stripANSI(rendered)).toContain("screen");
	});

	it("strips control sequences from a blocker note", () => {
		const rendered = renderPhases([
			{
				name: "Execution",
				tasks: [{ content: "ship it", status: "blocked", blocker: "waiting\u001b[2Jhere" }],
			},
		] as unknown as TodoPhase[]);

		expect(rendered).not.toContain("\u001b[2J");
		expect(Bun.stripANSI(rendered)).toContain("waiting");
	});

	it("keeps a completed label intact under the strikethrough path", () => {
		// The completed branch runs the label through `strikethroughText`, which
		// splices per character — sanitizing first keeps that from interleaving
		// styling with control bytes.
		const rendered = renderPhases([
			{ name: "Execution", tasks: [{ content: "done\u001b[2Jtask", status: "completed" }] },
		] as unknown as TodoPhase[]);

		expect(rendered).not.toContain("\u001b[2J");
		expect(Bun.stripANSI(rendered)).toContain("done");
	});

	it("strips control sequences from a phase header", () => {
		// Multi-phase renders the header; single-phase omits it.
		const rendered = renderPhases([
			{ name: "Set\u001b[2Jup", tasks: [{ content: "a", status: "pending" }] },
			{ name: "Ship", tasks: [{ content: "b", status: "pending" }] },
		] as unknown as TodoPhase[]);

		expect(rendered).not.toContain("\u001b[2J");
		expect(Bun.stripANSI(rendered)).toContain("Set");
		expect(Bun.stripANSI(rendered)).toContain("up");
	});

	it("strips control sequences from the zero-task fallback text", () => {
		// Cursor's own summary or refusal note lands here when nothing is mirrored.
		const result = {
			content: [{ type: "text" as const, text: "Todo\u001b[2Jsnapshot not mirrored" }],
			details: { phases: [], storage: "session" as const },
			isError: false,
		} as unknown as Parameters<typeof todoToolRenderer.renderResult>[0];
		const rendered = todoToolRenderer
			.renderResult(result, { expanded: true, isPartial: false }, theme)
			.render(120)
			.join("\n");

		expect(rendered).not.toContain("\u001b[2J");
		expect(Bun.stripANSI(rendered)).toContain("snapshot not mirrored");
	});

	it("flattens tabs in every result-side fragment", () => {
		// `sanitizeText` deliberately preserves tabs, and a raw tab punches holes
		// in bordered TUI output — so the display path must replace them too.
		const rendered = renderPhases([
			{ name: "Set\tup", tasks: [{ content: "ship\tit", status: "blocked", blocker: "waiting\there" }] },
			{ name: "Ship", tasks: [{ content: "b", status: "pending" }] },
		] as unknown as TodoPhase[]);

		expect(rendered).not.toContain("\t");
		expect(Bun.stripANSI(rendered)).toContain("ship");
		expect(Bun.stripANSI(rendered)).toContain("waiting");
		expect(Bun.stripANSI(rendered)).toContain("Set");
	});

	it("flattens tabs in the zero-task fallback text", () => {
		const result = {
			content: [{ type: "text" as const, text: "Todo\tsnapshot not mirrored" }],
			details: { phases: [], storage: "session" as const },
			isError: false,
		} as unknown as Parameters<typeof todoToolRenderer.renderResult>[0];
		const rendered = todoToolRenderer
			.renderResult(result, { expanded: true, isPartial: false }, theme)
			.render(120)
			.join("\n");

		expect(rendered).not.toContain("\t");
		expect(Bun.stripANSI(rendered)).toContain("snapshot not mirrored");
	});
});

describe("todoToolRenderer.renderCall preview sanitization", () => {
	// The streaming preview interpolates partially-parsed, model-authored args
	// straight into the status header. `renderStatusLine` only flattens CR/LF and
	// leaves tabs to the caller, so control sequences and tabs must be handled
	// here or a mid-stream delta rewrites the terminal.
	function renderArgs(args: unknown): string {
		const component = todoToolRenderer.renderCall(
			args as Parameters<typeof todoToolRenderer.renderCall>[0],
			{ expanded: false, isPartial: true, spinnerFrame: 0 },
			theme,
		);
		return component.render(120).join("\n");
	}

	it("strips control sequences from the task and phase fragments", () => {
		const rendered = renderArgs({ op: "done", task: "ship\u001b[2Jit", phase: "Exec\u0007ution" });

		expect(rendered).not.toContain("\u001b[2J");
		expect(rendered).not.toContain("\u0007");
		expect(Bun.stripANSI(rendered)).toContain("ship");
		expect(Bun.stripANSI(rendered)).toContain("Exec");
	});

	it("flattens tabs so a fragment cannot punch holes in the header", () => {
		const rendered = renderArgs({ op: "done", task: "ship\tit" });

		expect(rendered).not.toContain("\t");
		expect(Bun.stripANSI(rendered)).toContain("ship");
		expect(Bun.stripANSI(rendered)).toContain("it");
	});
});

describe("TodoTool acceptance, capability readiness, and fallback decoupling (#21)", () => {
	function createJournalSession(cwd = "/tmp/test") {
		const sessionManager = SessionManager.inMemory(cwd);
		let phases: TodoPhase[] = [];
		const session: ToolSession = {
			cwd,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			sessionManager,
			settings: Settings.isolated(),
			getTodoPhases: () => phases,
			setTodoPhases: next => {
				phases = next;
			},
		};
		return { session, sessionManager };
	}

	function recordToolCallAndResult(
		sessionManager: SessionManager,
		callId: string,
		toolName: string,
		args: Record<string, unknown>,
		result: { text?: string; details?: unknown; isError?: boolean; useless?: boolean },
	) {
		sessionManager.appendMessage({
			role: "assistant",
			content: [{ type: "toolCall", id: callId, name: toolName, arguments: args }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "toolUse",
			timestamp: Date.now(),
		});
		sessionManager.appendMessage({
			role: "toolResult",
			toolCallId: callId,
			toolName,
			content: [{ type: "text", text: result.text ?? "ok" }],
			details: result.details,
			isError: Boolean(result.isError),
			...(result.useless ? { useless: true } : {}),
			timestamp: Date.now(),
		});
	}

	async function runCommittedTodo(
		tool: TodoTool,
		sessionManager: SessionManager,
		callId: string,
		params: Record<string, unknown>,
	) {
		const res = await tool.execute(callId, params as never);
		sessionManager.appendMessage({
			role: "toolResult",
			toolCallId: callId,
			toolName: "todo",
			content: res.content,
			details: res.details,
			isError: Boolean(res.isError),
			timestamp: Date.now(),
		});
		return res;
	}

	it("replays synthetic Q timeline: 4x triton Not Available before smoke start + findcrypt ok keeps smoke blocked/not 4/4 until real triton call succeeds", async () => {
		const { session, sessionManager } = createJournalSession("/tmp/qianniu");
		const tool = new TodoTool(session);

		await runCommittedTodo(tool, sessionManager, "todo-init", {
			op: "init",
			list: [
				{
					phase: "Verification",
					items: [
						"locate target routine",
						"recover formula",
						"verify offline KAT",
						{
							content: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
							acceptance: [
								{ kind: "tool_callable", tool: "triton_analyze", action: "status" },
								{ kind: "tool_callable", tool: "ghidra_inspect", action: "findcrypt" },
							],
						},
					],
				},
			],
		});

		// Four triton status probes fail with installed:false (isError:false) BEFORE the smoke item starts.
		for (let i = 1; i <= 4; i++) {
			recordToolCallAndResult(
				sessionManager,
				`triton-fail-${i}`,
				"write",
				{ path: "xd://triton_analyze", content: '{"action":"status"}' },
				{
					text: "Triton Environment Status: Not Available\n- Installed: false",
					details: {
						xdev: {
							tool: "triton_analyze",
							mode: "execute",
							args: { action: "status" },
							inner: { action: "status", installed: false, python_path: null },
						},
					},
					isError: false,
				},
			);
		}

		await runCommittedTodo(tool, sessionManager, "todo-d1", { op: "done", task: "locate target routine" });
		await runCommittedTodo(tool, sessionManager, "todo-d2", { op: "done", task: "recover formula" });
		await runCommittedTodo(tool, sessionManager, "todo-d3", { op: "done", task: "verify offline KAT" });

		// ghidra_inspect findcrypt succeeds via xd://
		recordToolCallAndResult(
			sessionManager,
			"findcrypt-ok",
			"write",
			{ path: "xd://ghidra_inspect", content: '{"mode":"findcrypt","path":"sample.bin"}' },
			{
				text: "Found AES S-Box",
				details: {
					xdev: {
						tool: "ghidra_inspect",
						mode: "execute",
						args: { mode: "findcrypt", path: "sample.bin" },
						inner: { status: "ok", mode: "findcrypt", path: "sample.bin" },
					},
				},
				isError: false,
			},
		);

		// Attempting to mark smoke done must fail because triton_analyze status never succeeded.
		const prematureDone = await runCommittedTodo(tool, sessionManager, "todo-smoke-premature", {
			op: "done",
			task: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
		});
		expect(prematureDone.isError).toBe(true);
		const prematureText = prematureDone.content.find(c => c.type === "text")?.text ?? "";
		expect(prematureText).toContain("triton_analyze");
		expect(prematureText).not.toContain("Overall: 4/4 done, 0 open.");

		// Explicit block records honest blocked summary and non-green TUI card.
		const blockedRes = await runCommittedTodo(tool, sessionManager, "todo-smoke-block", {
			op: "block",
			task: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
			reason: "triton_analyze status Not Available (4 probes)",
		});
		expect(blockedRes.isError).toBeUndefined();
		const blockedSummary = blockedRes.content.find(c => c.type === "text")?.text ?? "";
		expect(blockedSummary).toContain("Overall: 3/4 done, 0 open, 1 blocked.");
		expect(blockedSummary).toContain("Remaining items: none (1 blocked).");

		const renderedBlocked = Bun.stripANSI(
			todoToolRenderer.renderResult(blockedRes, { expanded: true, isPartial: false }, theme).render(120).join("\n"),
		);
		expect(renderedBlocked).toContain("blocked: triton_analyze status Not Available");

		// Real triton_analyze status probe now succeeds.
		recordToolCallAndResult(
			sessionManager,
			"triton-ok-5",
			"write",
			{ path: "xd://triton_analyze", content: '{"action":"status"}' },
			{
				text: "Triton Environment Status: Available",
				details: {
					xdev: {
						tool: "triton_analyze",
						mode: "execute",
						args: { action: "status" },
						inner: { action: "status", installed: true, python_path: "/venv/bin/python" },
					},
				},
				isError: false,
			},
		);

		const finalDone = await runCommittedTodo(tool, sessionManager, "todo-smoke-done", {
			op: "done",
			task: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
		});
		expect(finalDone.isError).toBeUndefined();
		const smokeTask = finalDone.details?.phases[0]?.tasks[3];
		expect(smokeTask?.status).toBe("completed");
		expect(smokeTask?.evidence?.map(e => e.toolCallId)).toEqual(["triton-ok-5", "findcrypt-ok"]);
	});

	it("rejects invalid, wrong-target (suffix/case), prior-generation, and superseded call_id evidence", async () => {
		const { session, sessionManager } = createJournalSession("/workspace/proj");
		const tool = new TodoTool(session);

		// Generation 1 call BEFORE replan
		await runCommittedTodo(tool, sessionManager, "init-g1", {
			op: "init",
			items: ["old plan"],
		});
		recordToolCallAndResult(
			sessionManager,
			"gen1-r2-ok",
			"r2_inspect",
			{ mode: "info", path: "/workspace/proj/libtarget.so" },
			{ details: { status: "ok", mode: "info", path: "/workspace/proj/libtarget.so" } },
		);

		// Replan (Generation 2) with exact target requirement
		await runCommittedTodo(tool, sessionManager, "init-g2", {
			op: "init",
			items: [
				{
					content: "inspect exact target",
					acceptance: {
						kind: "tool_callable",
						tool: "r2_inspect",
						action: "info",
						target: "/workspace/proj/libtarget.so",
					},
				},
			],
		});

		// 1. Nonexistent call_id rejected
		const missingId = await tool.execute("d-missing", {
			op: "done",
			task: "inspect exact target",
			call_id: "does-not-exist",
		});
		expect(missingId.isError).toBe(true);

		// 2. Prior-generation call_id rejected
		const staleGen = await tool.execute("d-stale", {
			op: "done",
			task: "inspect exact target",
			call_id: "gen1-r2-ok",
		});
		expect(staleGen.isError).toBe(true);

		// 3. Suffix-spoofed target (/evil/workspace/proj/libtarget.so) and case mismatch rejected
		recordToolCallAndResult(
			sessionManager,
			"wrong-suffix",
			"r2_inspect",
			{ mode: "info", path: "/evil/workspace/proj/libtarget.so" },
			{ details: { status: "ok", mode: "info", path: "/evil/workspace/proj/libtarget.so" } },
		);
		recordToolCallAndResult(
			sessionManager,
			"wrong-case",
			"r2_inspect",
			{ mode: "info", path: "/workspace/proj/LibTarget.so" },
			{ details: { status: "ok", mode: "info", path: "/workspace/proj/LibTarget.so" } },
		);
		expect(
			(await tool.execute("d-suffix", { op: "done", task: "inspect exact target", call_id: "wrong-suffix" }))
				.isError,
		).toBe(true);
		expect(
			(await tool.execute("d-case", { op: "done", task: "inspect exact target", call_id: "wrong-case" })).isError,
		).toBe(true);

		// 4. Valid target call succeeds, then a later call for the same target fails -> cannot cherry-pick old call_id
		recordToolCallAndResult(
			sessionManager,
			"exact-ok",
			"r2_inspect",
			{ mode: "info", path: "./libtarget.so" },
			{ details: { status: "ok", mode: "info", path: "/workspace/proj/libtarget.so" } },
		);
		recordToolCallAndResult(
			sessionManager,
			"exact-later-fail",
			"r2_inspect",
			{ mode: "info", path: "/workspace/proj/libtarget.so" },
			{ details: { status: "missing_dependency", mode: "info", path: "/workspace/proj/libtarget.so" } },
		);
		const superseded = await tool.execute("d-superseded", {
			op: "done",
			task: "inspect exact target",
			call_id: "exact-ok",
		});
		expect(superseded.isError).toBe(true);

		// Recovery call on exact target allows completion
		recordToolCallAndResult(
			sessionManager,
			"exact-recovered",
			"r2_inspect",
			{ mode: "info", path: "/workspace/proj/libtarget.so" },
			{ details: { status: "ok", mode: "info", path: "/workspace/proj/libtarget.so" } },
		);
		const okRes = await tool.execute("d-ok", {
			op: "done",
			task: "inspect exact target",
			call_id: "exact-recovered",
		});
		expect(okRes.isError).toBeUndefined();
		expect(okRes.details?.phases[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("exact-recovered");
	});

	it("keeps original task blocked when a fallback task completes and rejects fallback evidence on original", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);

		await runCommittedTodo(tool, sessionManager, "init-fb", {
			op: "init",
			phase: "Verify",
			items: [
				{
					content: "symbolic trace via triton",
					acceptance: { kind: "tool_callable", tool: "triton_analyze", action: "replay" },
				},
			],
		});

		// Append fallback task; original task transitions to blocked automatically.
		const appended = await runCommittedTodo(tool, sessionManager, "append-fb", {
			op: "append",
			phase: "Verify",
			fallback_of: "symbolic trace via triton",
			items: ["offline Python KAT verification"],
		});
		expect(appended.isError).toBeUndefined();
		expect(appended.details?.phases[0]?.tasks[0]?.status).toBe("blocked");
		expect(appended.details?.phases[0]?.tasks[1]?.fallbackOf).toBe("symbolic trace via triton");

		recordToolCallAndResult(
			sessionManager,
			"kat-eval-ok",
			"eval",
			{ language: "py", code: "assert 20 == 20" },
			{ details: {}, isError: false },
		);

		const fbDone = await runCommittedTodo(tool, sessionManager, "done-fb", {
			op: "done",
			task: "offline Python KAT verification",
			call_id: "kat-eval-ok",
		});
		expect(fbDone.isError).toBeUndefined();
		const summary = fbDone.content.find(c => c.type === "text")?.text ?? "";
		expect(summary).toContain("Overall: 1/2 done, 0 open, 1 blocked.");
		expect(fbDone.details?.phases[0]?.tasks[0]?.status).toBe("blocked");

		// Attempting to close original task using fallback's call_id must fail.
		const hijack = await tool.execute("done-orig-hijack", {
			op: "done",
			task: "symbolic trace via triton",
			call_id: "kat-eval-ok",
		});
		expect(hijack.isError).toBe(true);
	});

	it("supports deliberate expected_error acceptance, WaitPollGuard neutrality, dropped-not-done counts, and markdown metadata round-trip", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);

		await runCommittedTodo(tool, sessionManager, "init-neg", {
			op: "init",
			phase: "Checks",
			items: [
				{
					content: "verify invalid flag is rejected",
					acceptance: {
						kind: "tool_callable",
						tool: "bash",
						action: "mycli --bad-flag",
						expectedOutcome: "expected_error",
					},
				},
				{
					content: "run real smoke command",
					acceptance: { kind: "tool_callable", tool: "bash" },
				},
				"optional polish",
			],
		});

		// WaitPollGuard intercepted `bash true` must NOT satisfy `bash` callable requirement.
		recordToolCallAndResult(
			sessionManager,
			"wait-guard-noop",
			"bash",
			{ command: "true" },
			{
				details: {
					unexecuted: true,
					waitPollGuard: { intercepted: true, kind: "noop_bash", reason: "noop", count: 1 },
				},
				isError: false,
				useless: true,
			},
		);
		const noopAttempt = await tool.execute("done-smoke-noop", {
			op: "done",
			task: "run real smoke command",
		});
		expect(noopAttempt.isError).toBe(true);

		// Deliberate negative test fails as expected -> satisfies expected_error.
		recordToolCallAndResult(
			sessionManager,
			"neg-probe-1",
			"bash",
			{ command: "mycli --bad-flag" },
			{ details: { exitCode: 2 }, isError: true },
		);
		const negDone = await runCommittedTodo(tool, sessionManager, "done-neg", {
			op: "done",
			task: "verify invalid flag is rejected",
		});
		expect(negDone.isError).toBeUndefined();
		expect(negDone.details?.phases[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("neg-probe-1");

		// Drop plain optional task -> counted as dropped, NEVER counted as `done`.
		const droppedRes = await runCommittedTodo(tool, sessionManager, "drop-opt", {
			op: "drop",
			task: "optional polish",
		});
		const dropSummary = droppedRes.content.find(c => c.type === "text")?.text ?? "";
		expect(dropSummary).toContain("Overall: 1/3 done, 1 open, 1 dropped.");

		// Markdown export/import round-trip preserves immutable acceptance & evidence.
		const md = phasesToMarkdown(session.getTodoPhases?.() ?? []);
		const { phases: parsed, errors } = markdownToPhases(md);
		expect(errors).toEqual([]);
		expect(parsed[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("neg-probe-1");
		expect(parsed[0]?.tasks[1]?.acceptance).toEqual([{ kind: "tool_callable", tool: "bash" }]);

		// Immutable acceptance task cannot be dropped or removed.
		expect((await tool.execute("try-drop", { op: "drop", task: "run real smoke command" })).isError).toBe(true);
		expect((await tool.execute("try-rm", { op: "rm", task: "run real smoke command" })).isError).toBe(true);
	});
});

describe("TodoTool evidence provenance (#21): docs reads, async settlement, dispatch generation, fallback attribution", () => {
	function createJournalSession(cwd = "/tmp/test") {
		const sessionManager = SessionManager.inMemory(cwd);
		let phases: TodoPhase[] = [];
		const session: ToolSession = {
			cwd,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			sessionManager,
			settings: Settings.isolated(),
			getTodoPhases: () => phases,
			setTodoPhases: next => {
				phases = next;
			},
		};
		return { session, sessionManager };
	}

	function appendAssistantCall(
		sessionManager: SessionManager,
		callId: string,
		toolName: string,
		args: Record<string, unknown>,
	) {
		sessionManager.appendMessage({
			role: "assistant",
			content: [{ type: "toolCall", id: callId, name: toolName, arguments: args }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			usage: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			stopReason: "toolUse",
			timestamp: Date.now(),
		});
	}

	function appendToolResult(
		sessionManager: SessionManager,
		callId: string,
		toolName: string,
		result: { text?: string; details?: unknown; isError?: boolean; useless?: boolean },
	) {
		sessionManager.appendMessage({
			role: "toolResult",
			toolCallId: callId,
			toolName,
			content: [{ type: "text", text: result.text ?? "ok" }],
			details: result.details,
			isError: Boolean(result.isError),
			...(result.useless ? { useless: true } : {}),
			timestamp: Date.now(),
		});
	}

	async function runTodo(
		tool: TodoTool,
		sessionManager: SessionManager,
		callId: string,
		params: Record<string, unknown>,
	) {
		const res = await tool.execute(callId, params as never);
		sessionManager.appendMessage({
			role: "toolResult",
			toolCallId: callId,
			toolName: "todo",
			content: res.content,
			details: res.details,
			isError: Boolean(res.isError),
			timestamp: Date.now(),
		});
		return res;
	}

	/** Durable execution record the tracker writes when it attributes an execution to a task. */
	function appendExecutionAttribution(
		sessionManager: SessionManager,
		phases: TodoPhase[],
		execution: Record<string, unknown>,
	) {
		sessionManager.appendCustomEntry(TODO_EXECUTION_SNAPSHOT_CUSTOM_TYPE, { phases, execution });
	}

	it("treats read xd:// documentation as a non-execution and binds background bash only through a settled wait job", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);
		await runTodo(tool, sessionManager, "init-provenance", {
			op: "init",
			phase: "Checks",
			items: [
				{
					content: "check triton status",
					acceptance: { kind: "tool_callable", tool: "triton_analyze", action: "status" },
				},
				{ content: "background build", acceptance: { kind: "tool_callable", tool: "bash", action: "make build" } },
				{ content: "background test", acceptance: { kind: "tool_callable", tool: "bash", action: "make test" } },
			],
		});

		// `read xd://triton_analyze` returns docs only: it can never satisfy the status requirement.
		appendAssistantCall(sessionManager, "docs-read", "read", { path: "xd://triton_analyze" });
		appendToolResult(sessionManager, "docs-read", "read", { text: "# triton_analyze\nSchema: …" });
		expect(
			(await tool.execute("done-status-docs", { op: "done", task: "check triton status", call_id: "docs-read" }))
				.isError,
		).toBe(true);

		// Background start ack is not verification; the settled `wait` snapshot is.
		appendAssistantCall(sessionManager, "bg-build", "bash", { command: "make build" });
		appendToolResult(sessionManager, "bg-build", "bash", {
			text: "started",
			details: { async: { state: "running", jobId: "job-build", type: "bash" } },
		});
		expect(
			(await tool.execute("done-build-ack", { op: "done", task: "background build", call_id: "bg-build" })).isError,
		).toBe(true);

		appendAssistantCall(sessionManager, "wait-running", "wait", {});
		appendToolResult(sessionManager, "wait-running", "wait", {
			details: { op: "wait", jobs: [{ id: "job-build", type: "bash", status: "running" }] },
		});
		expect((await tool.execute("done-build-running", { op: "done", task: "background build" })).isError).toBe(true);

		appendAssistantCall(sessionManager, "wait-settled", "wait", {});
		appendToolResult(sessionManager, "wait-settled", "wait", {
			details: {
				op: "wait",
				jobs: [{ id: "job-build", type: "bash", status: "completed", exitCode: 0 }],
			},
		});
		const settledDone = await tool.execute("done-build-settled", { op: "done", task: "background build" });
		expect(settledDone.isError).toBeUndefined();
		expect(settledDone.details?.phases[0]?.tasks[1]?.evidence?.[0]?.toolCallId).toBe("bg-build");

		// A completed job with a non-zero exit code is a settled failure, never verification.
		appendAssistantCall(sessionManager, "bg-test", "bash", { command: "make test" });
		appendToolResult(sessionManager, "bg-test", "bash", {
			text: "started",
			details: { async: { state: "running", jobId: "job-test", type: "bash" } },
		});
		appendAssistantCall(sessionManager, "wait-test", "wait", {});
		appendToolResult(sessionManager, "wait-test", "wait", {
			details: { op: "wait", jobs: [{ id: "job-test", type: "bash", status: "completed", exitCode: 2 }] },
		});
		expect((await tool.execute("done-test-failed", { op: "done", task: "background test" })).isError).toBe(true);
	});

	it("keeps a result's dispatch-time plan generation when it is persisted after a later init", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);

		await runTodo(tool, sessionManager, "init-gen1", { op: "init", items: ["gen1 plan"] });
		// Dispatched under generation 1, but its persisted result lands after the replan below.
		appendAssistantCall(sessionManager, "stale-bash", "bash", { command: "uname -a" });
		await runTodo(tool, sessionManager, "init-gen2", {
			op: "init",
			items: [{ content: "gen2 verify", acceptance: { kind: "tool_callable", tool: "bash", action: "uname -a" } }],
		});
		appendToolResult(sessionManager, "stale-bash", "bash", { details: { output: "Linux", exitCode: 0 } });

		const staleDone = await tool.execute("done-stale", { op: "done", task: "gen2 verify" });
		expect(staleDone.isError).toBe(true);

		appendAssistantCall(sessionManager, "fresh-bash", "bash", { command: "uname -a" });
		appendToolResult(sessionManager, "fresh-bash", "bash", { details: { output: "Linux", exitCode: 0 } });
		const freshDone = await tool.execute("done-fresh", { op: "done", task: "gen2 verify" });
		expect(freshDone.isError).toBeUndefined();
		expect(freshDone.details?.phases[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("fresh-bash");
	});

	it("settles auto-delivered background jobs from the delivery frame's reported exit code", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);
		await runTodo(tool, sessionManager, "init-async-delivery", {
			op: "init",
			phase: "Build",
			items: [
				{ content: "package build", acceptance: { kind: "tool_callable", tool: "bash", action: "npm run build" } },
				{ content: "test suite", acceptance: { kind: "tool_callable", tool: "bash", action: "npm test" } },
				{ content: "lint pass", acceptance: { kind: "tool_callable", tool: "bash", action: "npm run lint" } },
				{ content: "serve smoke", acceptance: { kind: "tool_callable", tool: "bash", action: "npm run serve" } },
			],
		});

		const startBackground = (callId: string, command: string, jobId: string) => {
			appendAssistantCall(sessionManager, callId, "bash", { command });
			appendToolResult(sessionManager, callId, "bash", {
				text: "started",
				details: { async: { state: "running", jobId, type: "bash" } },
			});
		};

		startBackground("bg-ok-call", "npm run build", "job-ok");
		sessionManager.appendCustomEntry("async-result", {
			jobs: [{ jobId: "job-ok", type: "bash", status: "completed", exitCode: 0 }],
		});
		const okDone = await tool.execute("done-build", { op: "done", task: "package build" });
		expect(okDone.isError).toBeUndefined();
		expect(okDone.details?.phases[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("bg-ok-call");

		startBackground("bg-fail-call", "npm test", "job-fail");
		sessionManager.appendCustomEntry("async-result", {
			jobs: [{ jobId: "job-fail", type: "bash", status: "completed", exitCode: 1 }],
		});
		expect((await tool.execute("done-tests", { op: "done", task: "test suite" })).isError).toBe(true);

		// BashToolDetails reports `exitCode` only when non-zero; a completed bash job already means
		// exit 0, so a frame without a code still settles the originating call as verified.
		startBackground("bg-unknown-call", "npm run lint", "job-unknown");
		sessionManager.appendCustomEntry("async-result", {
			jobs: [{ jobId: "job-unknown", type: "bash", status: "completed" }],
		});
		const lintDone = await tool.execute("done-lint", { op: "done", task: "lint pass" });
		expect(lintDone.isError).toBeUndefined();
		expect(lintDone.details?.phases[0]?.tasks[2]?.evidence?.[0]?.toolCallId).toBe("bg-unknown-call");

		// A delivered failure settles as a failure, never a pass.
		startBackground("bg-killed-call", "npm run serve", "job-killed");
		sessionManager.appendCustomEntry("async-result", {
			jobs: [{ jobId: "job-killed", type: "bash", status: "failed" }],
		});
		expect(
			(await tool.execute("done-serve", { op: "done", task: "serve smoke", call_id: "bg-killed-call" })).isError,
		).toBe(true);
	});

	it("excludes executions attributed to a fallback task from the original task's acceptance and failures", async () => {
		const { session, sessionManager } = createJournalSession();
		const tool = new TodoTool(session);

		const init = await runTodo(tool, sessionManager, "init-original", {
			op: "init",
			phase: "Trace",
			items: [
				{
					content: "triton symbolic trace",
					acceptance: { kind: "tool_callable", tool: "triton_analyze", action: "replay" },
				},
			],
		});
		const gen1 = init.details?.phases[0]?.tasks[0]?.generation ?? 1;

		// Original attempt fails availability while attributed to the original task.
		appendAssistantCall(sessionManager, "triton-original-fail", "triton_analyze", { action: "replay" });
		appendToolResult(sessionManager, "triton-original-fail", "triton_analyze", {
			details: { action: "replay", installed: false },
		});
		appendExecutionAttribution(sessionManager, init.details?.phases ?? [], {
			toolCallId: "triton-original-fail",
			toolName: "triton_analyze",
			effectiveToolName: "triton_analyze",
			action: "replay",
			details: { action: "replay", installed: false },
			isError: false,
			semanticSuccess: false,
			isReadinessFailure: true,
			failureReason: "tool not installed",
			generation: gen1,
			activeTaskContent: "triton symbolic trace",
		});

		const appended = await runTodo(tool, sessionManager, "append-fallback", {
			op: "append",
			phase: "Trace",
			fallback_of: "triton symbolic trace",
			items: ["unidbg symbolic trace"],
		});
		expect(appended.details?.phases[0]?.tasks[0]?.status).toBe("blocked");

		// The fallback succeeds with the SAME tool/action, attributed to the fallback task.
		appendAssistantCall(sessionManager, "triton-fallback-ok", "triton_analyze", { action: "replay" });
		appendToolResult(sessionManager, "triton-fallback-ok", "triton_analyze", {
			details: { action: "replay", installed: true },
		});
		appendExecutionAttribution(sessionManager, appended.details?.phases ?? [], {
			toolCallId: "triton-fallback-ok",
			toolName: "triton_analyze",
			effectiveToolName: "triton_analyze",
			action: "replay",
			details: { action: "replay", installed: true },
			isError: false,
			semanticSuccess: true,
			isReadinessFailure: false,
			generation: appended.details?.phases[0]?.tasks[1]?.generation ?? gen1,
			activeTaskContent: "unidbg symbolic trace",
		});

		const hijack = await tool.execute("done-original-via-fallback", {
			op: "done",
			task: "triton symbolic trace",
			call_id: "triton-fallback-ok",
		});
		expect(hijack.isError).toBe(true);
		expect(String(hijack.content[0]?.type === "text" ? hijack.content[0].text : "")).toContain("fallback");
		expect((await tool.execute("done-original-auto", { op: "done", task: "triton symbolic trace" })).isError).toBe(
			true,
		);

		// Original-attributed success is the only thing that closes the original task.
		appendAssistantCall(sessionManager, "triton-original-ok", "triton_analyze", { action: "replay" });
		appendToolResult(sessionManager, "triton-original-ok", "triton_analyze", {
			details: { action: "replay", installed: true },
		});
		appendExecutionAttribution(sessionManager, appended.details?.phases ?? [], {
			toolCallId: "triton-original-ok",
			toolName: "triton_analyze",
			effectiveToolName: "triton_analyze",
			action: "replay",
			details: { action: "replay", installed: true },
			isError: false,
			semanticSuccess: true,
			isReadinessFailure: false,
			generation: gen1,
			activeTaskContent: "triton symbolic trace",
		});
		const closed = await tool.execute("done-original-ok", { op: "done", task: "triton symbolic trace" });
		expect(closed.isError).toBeUndefined();
		expect(closed.details?.phases[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("triton-original-ok");
	});
});
