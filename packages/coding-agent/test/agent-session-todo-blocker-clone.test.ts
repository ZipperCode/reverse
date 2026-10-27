import * as fs from "node:fs";
import * as path from "node:path";
import { afterAll, describe, expect, it } from "bun:test";
import { Agent, type AgentTool } from "@reverse/agent";
import { createMockModel } from "@reverse/ai/providers/mock";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ExtensionRuntime } from "@reverse/coding-agent/extensibility/extensions/loader";
import { ExtensionRunner } from "@reverse/coding-agent/extensibility/extensions/runner";
import { ExtensionToolWrapper } from "@reverse/coding-agent/extensibility/extensions/wrapper";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import type { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { convertToLlm } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { TodoTool, type ToolSession } from "@reverse/coding-agent/tools";
import { WriteTool } from "@reverse/coding-agent/tools/write";
import { TempDir } from "@reverse/utils";
import { createInMemoryAuthStorage } from "./helpers/agent-session-setup";

const authStorage: AuthStorage = createInMemoryAuthStorage();
for (const provider of ["anthropic", "mock"]) authStorage.keys.setRuntime(provider, "test-key");
const modelRegistry = new ModelRegistry(authStorage);

afterAll(() => {
	authStorage.close();
});

function createTodoSessionHarness(
	dir: string,
	sessionManager = SessionManager.inMemory(dir),
	extraTools: AgentTool[] = [],
) {
	const settings = Settings.isolated({
		"compaction.enabled": false,
		"todo.enabled": true,
		"todo.reminders": false,
		"tools.approvalMode": "yolo",
	});
	const extensionRunner = new ExtensionRunner(
		[],
		new ExtensionRuntime(),
		dir,
		sessionManager,
		modelRegistry,
		undefined,
		settings,
	);
	const mock = createMockModel({ responses: [] });
	const toolSession: ToolSession = {
		cwd: dir,
		hasUI: false,
		getSessionFile: () => sessionManager.getSessionFile() ?? null,
		getSessionId: () => sessionManager.getSessionId(),
		getSessionSpawns: () => "*",
		sessionManager,
		settings,
		getActiveModel: () => mock.model,
		getTodoPhases: () => session.getTodoPhases(),
		setTodoPhases: phases => session.setTodoPhases(phases),
	};
	const wrappedWrite = new ExtensionToolWrapper(
		new WriteTool(toolSession) as unknown as AgentTool,
		extensionRunner,
	) as AgentTool;
	const wrappedExtras = extraTools.map(t => new ExtensionToolWrapper(t, extensionRunner) as AgentTool);
	const todoTool = new TodoTool(toolSession);
	const allTools: AgentTool[] = [wrappedWrite, todoTool as unknown as AgentTool, ...wrappedExtras];
	const agent = new Agent({
		getApiKey: () => "test-key",
		initialState: {
			model: mock.model,
			systemPrompt: ["Test"],
			tools: allTools,
		},
		streamFn: mock.stream,
		convertToLlm,
	});
	const session = new AgentSession({
		agent,
		sessionManager,
		settings,
		modelRegistry,
		extensionRunner,
		toolRegistry: new Map(allTools.map(t => [t.name, t])),
		autoApprove: true,
	});
	return { session, sessionManager, wrappedWrite, wrappedExtras, todoTool };
}

describe("AgentSession todo acceptance, active-task failure tracking, and journal rehydration (#21)", () => {
	it("blocks completion after bridged WriteTool filesystem failure until a real corrective write succeeds, and survives journal reload", async () => {
		using dir = TempDir.createSync("@rev-todo-bridge-write-");
		const sessionDir = path.join(dir.path(), "sessions");
		const manager = SessionManager.create(dir.path(), sessionDir);
		const { session, wrappedWrite, todoTool } = createTodoSessionHarness(dir.path(), manager);
		try {
			const initRes = await todoTool.execute("todo-init", {
				op: "init",
				list: [{ phase: "Deliver", items: ["Write verified output artifact"] }],
			});
			manager.appendMessage({
				role: "toolResult",
				toolCallId: "todo-init",
				toolName: "todo",
				content: initRes.content,
				details: initRes.details,
				isError: false,
				timestamp: Date.now(),
			});

			// Collide target path with an existing directory so WriteTool fails a real filesystem write.
			const collidingDirPath = path.join(dir.path(), "occupied-dir");
			fs.mkdirSync(collidingDirPath);
			await expect(
				wrappedWrite.execute("bridge-write-fail", {
					path: collidingDirPath,
					content: "payload\n",
				}),
			).rejects.toThrow();
			// Active task recorded unresolved failure: TodoTool done is rejected.
			const prematureDone = await todoTool.execute("todo-done-1", {
				op: "done",
				task: "Write verified output artifact",
			});
			expect(prematureDone.isError).toBe(true);
			expect(session.getTodoPhases()[0]?.tasks[0]?.status).toBe("in_progress");

			// Rehydrate a fresh AgentSession from the persisted journal: failure gate still holds!
			manager.ensureOnDisk();
			await manager.flush();
			const sessionFile = manager.getSessionFile();
			if (!sessionFile) throw new Error("Expected persisted session file");
			const reopenedManager = await SessionManager.open(sessionFile, sessionDir);
			const reopened = createTodoSessionHarness(dir.path(), reopenedManager);
			try {
				expect(reopened.session.getTodoPhases()[0]?.tasks[0]?.content).toBe("Write verified output artifact");
				expect(reopened.session.getTodoPhases()[0]?.tasks[0]?.unresolvedFailures).toHaveLength(1);
				const stillRejected = await reopened.todoTool.execute("todo-done-after-reload", {
					op: "done",
					task: "Write verified output artifact",
				});
				expect(stillRejected.isError).toBe(true);
				// Forged self-asserted evidence via direct setTodoPhases is rejected transactionally.
				expect(() =>
					reopened.session.setTodoPhases([
						{
							name: "Deliver",
							tasks: [
								{
									content: "Write verified output artifact",
									status: "completed",
									evidence: [{ toolCallId: "forged-id", tool: "write", semanticSuccess: true }],
								},
							],
						},
					]),
				).toThrow();
				expect(reopened.session.getTodoPhases()[0]?.tasks[0]?.status).toBe("in_progress");

				// Real corrective filesystem write succeeds; citing its call_id resolves the failure and completes the task.
				const validTarget = path.join(dir.path(), "artifact-output.json");
				const okWrite = await reopened.wrappedWrite.execute("bridge-write-ok", {
					path: validTarget,
					content: '{"verified":true}\n',
				});
				expect(okWrite.isError).toBeFalsy();
				expect(fs.readFileSync(validTarget, "utf8")).toBe('{"verified":true}\n');

				const validDone = await reopened.todoTool.execute("todo-done-ok", {
					op: "done",
					task: "Write verified output artifact",
					call_id: "bridge-write-ok",
				});
				expect(validDone.isError).toBeUndefined();
				expect(reopened.session.getTodoPhases()[0]?.tasks[0]?.status).toBe("completed");
				expect(reopened.session.getTodoPhases()[0]?.tasks[0]?.evidence?.[0]?.toolCallId).toBe("bridge-write-ok");
			} finally {
				await reopenedManager.flush();
				await reopened.session.dispose();
			}
		} finally {
			await manager.flush();
			await session.dispose();
		}
	});

	it("guards plain-string Q fixture against unrelated tool successes after triton readiness failure", async () => {
		using dir = TempDir.createSync("@rev-todo-plain-q-");
		const tritonProbeTool: AgentTool = {
			name: "triton_analyze",
			label: "Triton",
			description: "Triton status probe",
			parameters: {} as never,
			async execute() {
				return {
					content: [{ type: "text", text: "Triton Environment Status: Not Available" }],
					details: { action: "status", installed: false },
				};
			},
		};
		const { session, sessionManager, wrappedWrite, wrappedExtras, todoTool } = createTodoSessionHarness(
			dir.path(),
			SessionManager.inMemory(dir.path()),
			[tritonProbeTool],
		);
		const wrappedTriton = wrappedExtras[0]!;
		try {
			const initRes = await todoTool.execute("todo-init-q", {
				op: "init",
				items: ["smoke：triton_analyze status / ghidra_inspect findcrypt 可调用"],
			});
			sessionManager.appendMessage({
				role: "toolResult",
				toolCallId: "todo-init-q",
				toolName: "todo",
				content: initRes.content,
				details: initRes.details,
				isError: false,
				timestamp: Date.now(),
			});

			// Execute wrapped triton_analyze returning installed:false (isError:false)
			await wrappedTriton.execute("triton-status-1", { action: "status" });

			// Unrelated real filesystem write succeeds
			const okFile = path.join(dir.path(), "notes.txt");
			await wrappedWrite.execute("unrelated-write-ok", { path: okFile, content: "ok\n" });

			// Plain-string smoke task STILL rejects done (even when citing unrelated-write-ok) because triton readiness failed!
			const rejected = await todoTool.execute("todo-done-q-reject", {
				op: "done",
				task: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
				call_id: "unrelated-write-ok",
			});
			expect(rejected.isError).toBe(true);

			// Explicit block preserves blocker across getTodoPhases
			const blocked = await todoTool.execute("todo-block-q", {
				op: "block",
				task: "smoke：triton_analyze status / ghidra_inspect findcrypt 可调用",
				reason: "triton Not Available",
			});
			expect(blocked.isError).toBeUndefined();
			const stored = session.getTodoPhases()[0]?.tasks[0];
			expect(stored?.status).toBe("blocked");
			expect(stored?.blocker).toBe("triton Not Available");
		} finally {
			await session.dispose();
		}
	});

	it("keeps generation and fallback linkage authoritative across direct setters", async () => {
		using dir = TempDir.createSync("@rev-todo-setter-identity-");
		const { session, todoTool } = createTodoSessionHarness(dir.path());
		try {
			await todoTool.execute("todo-init-orig", {
				op: "init",
				phase: "Trace",
				items: [
					{
						content: "symbolic trace via triton",
						acceptance: { kind: "tool_callable", tool: "triton_analyze", action: "replay" },
					},
				],
			});
			await todoTool.execute("todo-append-fallback", {
				op: "append",
				phase: "Trace",
				fallback_of: "symbolic trace via triton",
				items: ["offline KAT trace"],
			});

			const before = session.getTodoPhases();
			const originalGen = before[0]?.tasks[0]?.generation;
			const fallbackGen = before[0]?.tasks[1]?.generation;
			expect(before[0]?.tasks[1]?.fallbackOf).toBe("symbolic trace via triton");

			// A setter that forges a newer generation and strips the fallback link changes neither.
			session.setTodoPhases(
				before.map(phase => ({
					name: phase.name,
					tasks: phase.tasks.map(task => {
						const forged: (typeof phase.tasks)[number] = { ...task, generation: 999 };
						delete forged.fallbackOf;
						return forged;
					}),
				})),
			);

			const after = session.getTodoPhases();
			expect(after[0]?.tasks[0]?.generation).toBe(originalGen);
			expect(after[0]?.tasks[1]?.generation).toBe(fallbackGen);
			expect(after[0]?.tasks[1]?.fallbackOf).toBe("symbolic trace via triton");
		} finally {
			await session.dispose();
		}
	});
});
