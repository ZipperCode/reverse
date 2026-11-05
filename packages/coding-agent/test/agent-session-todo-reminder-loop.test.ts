import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Agent, type AgentTool } from "@reverse/agent";
import type { AssistantMessage, TextContent, ToolCall } from "@reverse/ai";
import { getBundledModel } from "@reverse/catalog/models";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { AgentSession, type AgentSessionEvent } from "@reverse/coding-agent/session/agent-session";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { CustomMessageEntry } from "@reverse/coding-agent/session/session-entries";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow/store";
import { setWorkflowAcceptanceCriteria } from "@reverse/coding-agent/reverse-workflow/acceptance";
import { EvidenceStore } from "@reverse/coding-agent/evidence/store";
import { TodoTool, type ToolSession } from "@reverse/coding-agent/tools";
import { cfgTodoEnabled, cfgTodoReminders } from "@reverse/coding-agent/tools/settings";
import { TempDir } from "@reverse/utils";
import { createInMemoryAuthStorage } from "./helpers/agent-session-setup";

/**
 * Regression coverage for issue #2590: `#checkTodoCompletion` used to schedule
 * `agent.continue()` after appending its `<system-reminder>`, so any text-only
 * acknowledgement from the agent ("paused at your instruction") triggered another
 * `agent_end`, which incremented the counter and fired the next reminder — no
 * user input required. Within a single user pause that loop runs 1/3 → 2/3 → 3/3.
 *
 * The contract these tests defend: a reminder MUST NOT escalate inside a
 * self-continuation chain unless the agent has produced a tool-level result
 * (e.g. called `todo` or `edit`) between the prior reminder and the next stop.
 */
const sharedAuthStorage = createInMemoryAuthStorage();
sharedAuthStorage.keys.setRuntime("anthropic", "test-key");
const sharedModelRegistry = new ModelRegistry(sharedAuthStorage);

afterAll(() => {
	sharedAuthStorage.close();
});

describe("AgentSession todo reminder self-continuation suppression", () => {
	let tempDir: TempDir;
	let session: AgentSession;
	let sessionManager: SessionManager;
	let reminderAttempts: number[];

	function textOnlyAssistantMessage(text = "paused at your instruction"): AssistantMessage {
		return {
			role: "assistant",
			content: [{ type: "text", text }],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			stopReason: "stop",
			usage: {
				input: 100,
				output: 20,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 120,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			timestamp: Date.now(),
		};
	}

	function emitTextOnlyStop(text?: string): void {
		const msg = textOnlyAssistantMessage(text);
		session.agent.emitExternalEvent({ type: "message_end", message: msg });
		session.agent.emitExternalEvent({ type: "agent_end", messages: [msg] });
	}

	function emitToolResult(toolName: string, details: Record<string, unknown> = {}): void {
		const toolCallId = `call_${toolName}_${Date.now()}_${Math.random()}`;
		const toolCall: ToolCall = { type: "toolCall", id: toolCallId, name: toolName, arguments: {} };
		const assistantMsg: AssistantMessage = {
			role: "assistant",
			content: [toolCall],
			api: "anthropic-messages",
			provider: "anthropic",
			model: "claude-sonnet-4-5",
			stopReason: "toolUse",
			usage: {
				input: 50,
				output: 10,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 60,
				cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
			},
			timestamp: Date.now(),
		};
		session.agent.emitExternalEvent({ type: "message_end", message: assistantMsg });
		const content: TextContent[] = [{ type: "text", text: "ok" }];
		session.agent.emitExternalEvent({
			type: "message_end",
			message: {
				role: "toolResult",
				toolCallId,
				toolName,
				content,
				isError: false,
				details,
				timestamp: Date.now(),
			},
		});
	}

	function todoReminderTranscriptEntry() {
		return sessionManager.getBranch().find(entry => {
			if (entry.type !== "message" || entry.message.role !== "developer") return false;
			const { content } = entry.message;
			if (!Array.isArray(content)) return false;
			return content.some(
				(item): item is TextContent =>
					item.type === "text" && item.text.includes("You stopped with 2 incomplete todo item(s):"),
			);
		});
	}

	function deliveryReceiptEntry(): CustomMessageEntry | undefined {
		return sessionManager
			.getBranch()
			.find(
				(entry): entry is CustomMessageEntry =>
					entry.type === "custom_message" && entry.customType === "delivery-receipt",
			);
	}

	beforeEach(() => {
		tempDir = TempDir.createSync("@pi-todo-reminder-loop-");
		sessionManager = SessionManager.inMemory(tempDir.path());

		const model = getBundledModel("anthropic", "claude-sonnet-4-5");
		if (!model) throw new Error("Expected built-in anthropic model to exist");

		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": true,
			"todo.reminders": true,
			"todo.remindersMax": 3,
		});
		const toolSession: ToolSession = {
			cwd: tempDir.path(),
			hasUI: false,
			getSessionFile: () => sessionManager.getSessionFile() ?? null,
			getSessionSpawns: () => "*",
			settings,
		};
		const todoTool = new TodoTool(toolSession);

		const agent = new Agent({
			initialState: {
				model,
				systemPrompt: ["Test"],
				tools: [todoTool],
				messages: [],
			},
		});

		session = new AgentSession({
			agent,
			sessionManager,
			settings,
			modelRegistry: sharedModelRegistry,
			toolRegistry: new Map([["todo", todoTool as AgentTool]]),
		});

		reminderAttempts = [];
		session.subscribe((event: AgentSessionEvent) => {
			if (event.type === "todo_reminder") reminderAttempts.push(event.attempt);
		});

		session.setTodoPhases([
			{
				name: "Pending review",
				tasks: [
					{ content: "Slice 81", status: "pending" },
					{ content: "Slice 82", status: "pending" },
				],
			},
		]);
	});

	afterEach(async () => {
		await session.dispose();
		try {
			await tempDir.remove();
		} catch {}
		vi.restoreAllMocks();
	});

	it("baseline: a single text-only stop fires reminder 1/3 and records it in the transcript", async () => {
		vi.spyOn(session.agent, "continue").mockResolvedValue();
		emitTextOnlyStop();
		await session.waitForIdle();
		expect(reminderAttempts).toEqual([1]);

		const reminderEntry = todoReminderTranscriptEntry();
		expect(reminderEntry?.type).toBe("message");
	});

	it("stays silent when todo is not in the active roster", async () => {
		await session.setActiveToolsByName([]);
		expect(session.getActiveToolNames()).not.toContain("todo");
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop();
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([]);
		expect(todoReminderTranscriptEntry()).toBeUndefined();
		expect(continueSpy).not.toHaveBeenCalled();
	});

	it.each(["roster", "todo.reminders", "todo.enabled"] as const)(
		"waits for progress across disabling and re-enabling %s",
		async control => {
			const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();
			emitTextOnlyStop();
			await session.waitForIdle();
			expect(reminderAttempts).toEqual([1]);

			if (control === "roster") await session.setActiveToolsByName([]);
			else (control === "todo.enabled" ? cfgTodoEnabled : cfgTodoReminders).override(session.settings, false);
			emitTextOnlyStop();
			await session.waitForIdle();
			expect(continueSpy).toHaveBeenCalledTimes(1);

			if (control === "roster") await session.setActiveToolsByName(["todo"]);
			else (control === "todo.enabled" ? cfgTodoEnabled : cfgTodoReminders).override(session.settings, true);
			expect(session.getActiveToolNames()).toContain("todo");
			emitTextOnlyStop();
			await session.waitForIdle();
			expect(reminderAttempts).toEqual([1]);
			expect(continueSpy).toHaveBeenCalledTimes(1);

			emitToolResult("todo", { phases: session.getTodoPhases() });
			emitTextOnlyStop();
			await session.waitForIdle();
			expect(reminderAttempts).toEqual([1, 2]);
			expect(continueSpy).toHaveBeenCalledTimes(2);
		},
	);

	it("still reminds and continues when the assistant yields with a user-facing question while pending todos remain", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop("I need your feedback before continuing. Which trade-off should I optimize for?");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it("still reminds and continues when the assistant yields with a non-English (Chinese) question while pending todos remain", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop("我遇到一个需要你决定的问题：是否应该继续删除旧的配置文件？");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it.each(["Go with A?", "Which approach?\n1. MCP tool\n2. Markdown fence\n\nI recommend the MCP tool."])(
		"still reminds and continues across choice prompts while pending todos remain: %s",
		async text => {
			const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

			emitTextOnlyStop(text);
			await session.waitForIdle();

			expect(reminderAttempts).toEqual([1]);
			expect(todoReminderTranscriptEntry()).toBeDefined();
			expect(continueSpy).toHaveBeenCalledTimes(1);
		},
	);

	it("fires at most one correction reminder when all remaining todos are blocked, then settles with delivery receipt", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		session.setTodoPhases([
			{
				name: "Investigation",
				tasks: [{ content: "Inspect target memory", status: "blocked", blocker: "Need hardware debugger" }],
			},
		]);

		emitTextOnlyStop("All remaining tasks are blocked.");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(continueSpy).toHaveBeenCalledTimes(1);

		// Second stop without unblocking: no further reminder, settles
		emitTextOnlyStop("Still blocked.");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(continueSpy).toHaveBeenCalledTimes(1);

		// Delivery receipt emitted at terminal settle
		const receipt = deliveryReceiptEntry();
		expect(receipt).toBeDefined();
		expect(receipt?.content).toContain("0/1 完成");
		expect(receipt?.content).toContain("1 阻塞");
		expect(receipt?.content).toContain("Need hardware debugger");
		expect(receipt?.content).toContain("本轮未绑定领域验收");
	});

	it("settles with delivery receipt showing completed when all tasks are done", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		session.setTodoPhases([
			{
				name: "Review",
				tasks: [
					{ content: "Slice 81", status: "completed" },
					{ content: "Slice 82", status: "completed" },
				],
			},
		]);

		emitTextOnlyStop("All done.");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([]);
		expect(continueSpy).not.toHaveBeenCalled();

		const receipt = deliveryReceiptEntry();
		expect(receipt).toBeDefined();
		expect(receipt?.content).toContain("2/2 完成");
		expect(receipt?.content).toContain("本轮未绑定领域验收");
	});

	it("still resumes unfinished work after a question-headed status list", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop("Finished slice 81.\n\n**What's left?**\n- Slice 82\n- Slice 83");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it("still reminds when the assistant answers its own prompt-shaped question", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop(
			"Which configuration should this use?\nUse the existing default; the remaining todo items still need work.",
		);
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it("still reminds and continues when ordinary prose contains answer", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop("Final answer: I summarized the work completed so far, but the todo items remain open.");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it("still reminds and continues when TypeScript optional syntax appears in the assistant tail", async () => {
		const continueSpy = vi.spyOn(session.agent, "continue").mockResolvedValue();

		emitTextOnlyStop("Tail note: the interface includes foo?: string, but the todo items remain open.");
		await session.waitForIdle();

		expect(reminderAttempts).toEqual([1]);
		expect(todoReminderTranscriptEntry()).toBeDefined();
		expect(continueSpy).toHaveBeenCalledTimes(1);
	});

	it("fires exactly one reminder per user pause when the agent only acknowledges", async () => {
		// Each call to continue() mirrors what the bug-reported model did: emit another
		// text-only stop ("paused at your instruction"), no tool calls in between.
		vi.spyOn(session.agent, "continue").mockImplementation(async () => {
			emitTextOnlyStop();
		});

		emitTextOnlyStop();
		await session.waitForIdle();

		// With the bug: reminderAttempts === [1, 2, 3] within a single user pause.
		// With the fix: the second `agent_end` is suppressed because no tool action ran
		// between the first reminder and the agent's text-only ack.
		expect(reminderAttempts).toEqual([1]);
	});

	it("re-escalates after the agent makes tool-level progress between stops", async () => {
		let continueCount = 0;
		vi.spyOn(session.agent, "continue").mockImplementation(async () => {
			continueCount += 1;
			if (continueCount === 1) {
				// In response to reminder 1/3 the agent actually did work (called `todo`),
				// then stopped again with todos still incomplete.
				emitToolResult("todo", { phases: session.getTodoPhases() });
				emitTextOnlyStop();
				return;
			}
			// Subsequent continuations are bare acks — they must not escalate further.
			emitTextOnlyStop();
		});

		emitTextOnlyStop();
		await session.waitForIdle();

		// 1/3 fires, agent does work, 2/3 fires, agent acks → suppressed, no 3/3.
		expect(reminderAttempts).toEqual([1, 2]);
	});

	it("refreshes same-cycle acceptance after target drift without rewriting workflow history", async () => {
		session.setTodoPhases([]);
		const target = path.join(tempDir.path(), "target.bin");
		await fs.writeFile(target, "original-target");
		const workflowStore = ReverseWorkflowStore.forSession(tempDir.path());
		const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir.path() });
		const evidence = await evidenceStore.addFact({
			kind: "fact",
			target: "target.bin",
			sourceTool: "binary_diff",
			locator: "offset:0x100",
			content: "token validated",
			subject: "auth_token_check",
			assurance: "static_candidate",
		});
		const wf = await workflowStore.create({
			id: "wf_live_test",
			target: "target.bin",
		});
		wf.steps[0].evidence_ids = [evidence.id];
		setWorkflowAcceptanceCriteria(wf, [
			{
				id: "c1",
				step_id: wf.steps[0].id,
				title: "目标事实验收",
				subject: "auth_token_check",
				status: "pending",
				satisfied_by_evidence_ids: [evidence.id],
			},
		]);
		await workflowStore.save(wf);
		const workflowBefore = await workflowStore.get(wf.id);

		emitToolResult("reverse_workflow", { workflow: { id: wf.id } });
		emitTextOnlyStop("Workflow step finished.");
		await session.waitForIdle();

		const receipt = deliveryReceiptEntry();
		const details = receipt?.details as {
			workflows?: Array<{ items?: Array<{ status: string; evidenceIds?: string[] }> }>;
		};
		expect(details.workflows?.[0]?.items?.[0]?.status).toBe("satisfied");
		expect(details.workflows?.[0]?.items?.[0]?.evidenceIds).toContain(evidence.id);

		await fs.writeFile(target, "changed-target");
		emitToolResult("reverse_workflow", { workflow: { id: wf.id } });
		emitTextOnlyStop("重新检查同一目标。");
		await session.waitForIdle();
		const receipts = sessionManager
			.getBranch()
			.filter(
				(entry): entry is CustomMessageEntry =>
					entry.type === "custom_message" && entry.customType === "delivery-receipt",
			);
		expect(receipts).toHaveLength(2);
		const changed = receipts[1].details as {
			workflows?: Array<{ items?: Array<{ status: string; unmetReason?: string }> }>;
		};
		expect(changed.workflows?.[0]?.items?.[0]?.status).toBe("pending");
		expect(changed.workflows?.[0]?.items?.[0]?.unmetReason).toBeDefined();
		expect(await workflowStore.get(wf.id)).toEqual(workflowBefore);
	});

	it("distinguishes proxy evidence in delivery receipt", async () => {
		session.setTodoPhases([]);
		await fs.writeFile(path.join(tempDir.path(), "target.bin"), "proxy-target");
		const workflowStore = ReverseWorkflowStore.forSession(tempDir.path());
		const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir.path() });
		const proxyEvidence = await evidenceStore.addFact({
			kind: "fact",
			target: "target.bin",
			sourceTool: "binary_diff",
			locator: "offset:0x100",
			content: "proxy observation",
			subject: "proxy_auth",
			assurance: "static_candidate",
		});
		const wf = await workflowStore.create({
			id: "wf_proxy_test",
			target: "target.bin",
		});
		wf.steps[0].evidence_ids = [proxyEvidence.id];
		setWorkflowAcceptanceCriteria(wf, [
			{
				id: "c_proxy",
				step_id: wf.steps[0].id,
				title: "代理证据主体校验",
				subject: "main_auth",
				status: "pending",
				satisfied_by_evidence_ids: [proxyEvidence.id],
			},
		]);
		await workflowStore.save(wf);

		emitToolResult("reverse_workflow", { workflow: { id: wf.id } });
		emitTextOnlyStop("Analysis completed with proxy observations.");
		await session.waitForIdle();

		const receipt = deliveryReceiptEntry();
		const details = receipt?.details as { workflows?: Array<{ items?: Array<{ status: string }> }> };
		expect(details.workflows?.[0]?.items?.[0]?.status).toBe("proxy_verified");
	});

	it("handles unbound acceptance criteria when workflow has steps but no criteria", async () => {
		session.setTodoPhases([]);
		const workflowStore = ReverseWorkflowStore.forSession(tempDir.path());
		const wf = await workflowStore.create({
			id: "wf_unbound_test",
			target: "target.bin",
		});
		await workflowStore.update(wf.id, record => {
			setWorkflowAcceptanceCriteria(record, []);
		});

		emitToolResult("reverse_workflow", { workflow: { id: wf.id } });
		emitTextOnlyStop("Unbound workflow done.");
		await session.waitForIdle();

		const receipt = deliveryReceiptEntry();
		const details = receipt?.details as { workflows?: Array<{ workflowId: string; criteriaUnbound: boolean }> };
		expect(details.workflows?.[0]?.workflowId).toBe(wf.id);
		expect(details.workflows?.[0]?.criteriaUnbound).toBe(true);
	});

	it("extracts workflow ID from xd:// wrapped tool execution details", async () => {
		session.setTodoPhases([]);
		const workflowStore = ReverseWorkflowStore.forSession(tempDir.path());
		const wf = await workflowStore.create({
			id: "wf_xd_inner",
			target: "target.bin",
		});

		emitToolResult("write", {
			xdev: {
				tool: "reverse_workflow",
				inner: {
					action: "status",
					workflow: { id: wf.id },
				},
			},
		});
		emitTextOnlyStop("Finished write to xd://.");
		await session.waitForIdle();

		const receipt = deliveryReceiptEntry();
		expect(receipt).toBeDefined();
		expect(receipt?.content).toContain("wf_xd_inner");
	});

	it("does not pollute current cycle with generic read tool returning workflow_id or historical workflow lists", async () => {
		session.setTodoPhases([]);
		const workflowStore = ReverseWorkflowStore.forSession(tempDir.path());
		await workflowStore.create({
			id: "wf_historical_old",
			target: "target.bin",
		});

		emitToolResult("read", { workflow_id: "wf_historical_old" });
		emitToolResult("reverse_workflow", {
			action: "status",
			workflows: [{ id: "wf_historical_old" }],
		});

		emitTextOnlyStop("Done generic read and list.");
		await session.waitForIdle();

		expect(deliveryReceiptEntry()).toBeUndefined();
	});

	it("does not emit delivery receipt when plan mode is enabled", async () => {
		session.setTodoPhases([]);
		session.setPlanModeState({ enabled: true, planFilePath: "local://PLAN.md" });
		emitTextOnlyStop("In plan mode.");
		await session.waitForIdle();

		const receipt = deliveryReceiptEntry();
		expect(receipt).toBeUndefined();
	});
});
