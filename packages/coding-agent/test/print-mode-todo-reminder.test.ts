import { afterEach, expect, it, vi } from "bun:test";
import * as path from "node:path";
import { Agent } from "@reverse/agent";
import { createMockModel } from "@reverse/ai/providers/mock";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { runPrintMode } from "@reverse/coding-agent/modes/print-mode";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { USER_TODO_EDIT_CUSTOM_TYPE } from "@reverse/coding-agent/tools/todo";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { TempDir } from "@reverse/utils";

afterEach(() => vi.restoreAllMocks());

it("prints the requested answer without continuing stale todos in print mode", async () => {
	const dir = TempDir.createSync("@pi-print-todo-reminder-");
	const auth = await AuthStorage.create(path.join(dir.path(), "auth.db"));
	const output: string[] = [];
	vi.spyOn(process.stdout, "write").mockImplementation((...args: unknown[]) => {
		if (typeof args[0] === "string") output.push(args[0]);
		const callback = args.at(-1);
		if (typeof callback === "function") callback();
		return true;
	});
	vi.spyOn(process.stderr, "write").mockImplementation(() => true);
	const model = createMockModel({ responses: [{ content: ["PONG"] }, { content: ["UNREQUESTED FOLLOWUP"] }] });
	auth.keys.setRuntime(model.provider, "test-key");
	const sessionManager = SessionManager.inMemory(dir.path());
	sessionManager.appendCustomEntry(USER_TODO_EDIT_CUSTOM_TYPE, {
		phases: [{ name: "Parked work", tasks: [{ content: "Await access", status: "in_progress" }] }],
	});
	const session = new AgentSession({
		agent: new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: ["Test"], tools: [], messages: [] },
			streamFn: model.stream,
		}),
		sessionManager,
		settings: Settings.isolated({ "compaction.enabled": false, "todo.enabled": true, "todo.reminders": true }),
		modelRegistry: new ModelRegistry(auth, path.join(dir.path(), "models.yml")),
	});
	try {
		const code = await runPrintMode(session, { mode: "text", initialMessage: "Reply with PONG" });
		expect(code).toBe(0);
		expect(output.join("")).toBe("PONG\n");
		expect(model.calls).toHaveLength(1);
	} finally {
		await session.dispose();
		auth.close();
		await dir.remove();
	}
});
