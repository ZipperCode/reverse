import { afterEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { TodoCommandController } from "@reverse/coding-agent/modes/controllers/todo-command-controller";
import type { InteractiveModeContext } from "@reverse/coding-agent/modes/types";
import { type TodoPhase } from "@reverse/tui/tools/todo";
import { USER_TODO_EDIT_CUSTOM_TYPE } from "@reverse/coding-agent/tools";
import { removeWithRetries } from "@reverse/utils";

function createContext(cwd: string, phases: TodoPhase[]): InteractiveModeContext {
	return {
		agent: {
			appendMessage: vi.fn(),
		},
		session: {
			getTodoPhases: () => phases,
			setTodoPhases: vi.fn(next => {
				phases = next;
			}),
		},
		sessionManager: {
			appendCustomEntry: vi.fn(),
			appendMessage: vi.fn(),
			getBranch: () => [],
			getCwd: () => cwd,
		},
		setTodos: vi.fn(),
		showError: vi.fn(),
		showStatus: vi.fn(),
		showWarning: vi.fn(),
	} as unknown as InteractiveModeContext;
}

describe("TodoCommandController", () => {
	let tempRoot = "";

	afterEach(async () => {
		if (tempRoot) await removeWithRetries(tempRoot);
		tempRoot = "";
	});

	it("exports the default TODO.md under the active session cwd", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-export-"));
		const phases: TodoPhase[] = [{ name: "Work", tasks: [{ content: "Ship it", status: "pending" }] }];
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("export");

		const target = path.join(tempRoot, "TODO.md");
		expect(await fs.readFile(target, "utf8")).toBe("# Work\n- [ ] Ship it\n");
		expect(ctx.showStatus).toHaveBeenCalledWith(`Wrote todos to ${target}`);
		expect(ctx.showError).not.toHaveBeenCalled();
	});

	it("exports a quoted path with spaces", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-export-quoted-"));
		const phases: TodoPhase[] = [{ name: "Work", tasks: [{ content: "Ship it", status: "pending" }] }];
		const target = path.join(tempRoot, "todo file.md");
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand(`export "${target}"`);

		expect(await fs.readFile(target, "utf8")).toBe("# Work\n- [ ] Ship it\n");
		expect(ctx.showStatus).toHaveBeenCalledWith(`Wrote todos to ${target}`);
		expect(ctx.showError).not.toHaveBeenCalled();
	});

	it("imports the default TODO.md under the active session cwd", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-import-"));
		const target = path.join(tempRoot, "TODO.md");
		await fs.writeFile(target, "# Imported\n- [ ] From cwd\n", "utf8");
		const ctx = createContext(tempRoot, []);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("import");

		const expected: TodoPhase[] = [{ name: "Imported", tasks: [{ content: "From cwd", status: "in_progress" }] }];
		expect(ctx.session.setTodoPhases).toHaveBeenCalledWith(expected);
		expect(ctx.setTodos).toHaveBeenCalledWith(expected);
		expect(ctx.sessionManager.appendCustomEntry).toHaveBeenCalledWith(USER_TODO_EDIT_CUSTOM_TYPE, {
			phases: expected,
		});
		expect(ctx.agent.appendMessage).toHaveBeenCalledWith(expect.objectContaining({ role: "developer" }));
		expect(ctx.sessionManager.appendMessage).toHaveBeenCalledWith(expect.objectContaining({ role: "developer" }));
		expect(ctx.showStatus).toHaveBeenCalledWith(`Imported 1 phase(s), 1 task(s) from ${target}.`);
		expect(ctx.showError).not.toHaveBeenCalled();
	});

	it("imports a quoted path with spaces", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-import-quoted-"));
		const target = path.join(tempRoot, "todo file.md");
		await fs.writeFile(target, "# Quoted\n- [ ] From quoted path\n", "utf8");
		const ctx = createContext(tempRoot, []);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand(`import "${target}"`);

		const expected: TodoPhase[] = [
			{ name: "Quoted", tasks: [{ content: "From quoted path", status: "in_progress" }] },
		];
		expect(ctx.session.setTodoPhases).toHaveBeenCalledWith(expected);
		expect(ctx.showStatus).toHaveBeenCalledWith(`Imported 1 phase(s), 1 task(s) from ${target}.`);
		expect(ctx.showError).not.toHaveBeenCalled();
	});

	it("reports import parse errors without committing", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-import-invalid-"));
		const target = path.join(tempRoot, "TODO.md");
		await fs.writeFile(target, "# Imported\nnot a todo\n", "utf8");
		const ctx = createContext(tempRoot, []);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("import");

		expect(ctx.showError).toHaveBeenCalledWith(expect.stringContaining(`Could not parse ${target}:`));
		expect(ctx.session.setTodoPhases).not.toHaveBeenCalled();
		expect(ctx.setTodos).not.toHaveBeenCalled();
	});

	it("reports invalid internal-scheme import paths without committing", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-import-scheme-"));
		const ctx = createContext(tempRoot, []);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("import artifact://todo");

		expect(ctx.showError).toHaveBeenCalledWith(expect.stringContaining("Failed to read todos:"));
		expect(ctx.showError).toHaveBeenCalledWith(expect.stringContaining("internal scheme"));
		expect(ctx.session.setTodoPhases).not.toHaveBeenCalled();
		expect(ctx.setTodos).not.toHaveBeenCalled();
	});

	it("reports invalid internal-scheme export paths", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-export-invalid-"));
		const phases: TodoPhase[] = [{ name: "Work", tasks: [{ content: "Ship it", status: "pending" }] }];
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("export artifact://todo");

		expect(ctx.showError).toHaveBeenCalledWith(expect.stringContaining("Failed to write todos:"));
		expect(ctx.showError).toHaveBeenCalledWith(expect.stringContaining("internal scheme"));
	});

	it("clears all todo phases after /todo rm", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-rm-all-"));
		const phases: TodoPhase[] = [
			{ name: "Foundation", tasks: [{ content: "Scaffold crate", status: "in_progress" }] },
		];
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("rm");

		expect(ctx.agent.appendMessage).toHaveBeenCalledTimes(1);
		expect(ctx.session.getTodoPhases()).toEqual([]);
	});

	it("clears tasks from the selected phase while preserving other phases", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-rm-phase-"));
		const phases: TodoPhase[] = [
			{ name: "Foundation", tasks: [{ content: "Scaffold crate", status: "completed" }] },
			{ name: "Auth", tasks: [{ content: "Port credential store", status: "pending" }] },
		];
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("rm Auth");

		expect(ctx.session.getTodoPhases()).toEqual([phases[0]!, { name: "Auth", tasks: [] }]);
	});

	it("completes the active task", async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "pi-tui-todo-done-"));
		const phases: TodoPhase[] = [
			{ name: "Foundation", tasks: [{ content: "Scaffold crate", status: "in_progress" }] },
		];
		const ctx = createContext(tempRoot, phases);
		const controller = new TodoCommandController(ctx);

		await controller.handleTodoCommand("done");

		expect(ctx.session.getTodoPhases()[0]?.tasks[0]?.status).toBe("completed");
	});
});
