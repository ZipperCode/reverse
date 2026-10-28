import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as path from "node:path";
import { type } from "@reverse/reversetype";
import { Agent, type AgentTool } from "@reverse/agent";
import type { AssistantMessage, Context, ToolResultMessage } from "@reverse/ai";
import { createMockModel, type MockModel } from "@reverse/ai/providers/mock";
import { AssistantMessageEventStream } from "@reverse/ai/utils/event-stream";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { type CustomMessage, convertToLlm } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { TaskTool } from "@reverse/coding-agent/task";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { TempDir } from "@reverse/utils";

const zeroUsage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
} satisfies AssistantMessage["usage"];

interface ScriptedTurn {
	toolCalls?: Array<{ name: string; arguments: Record<string, unknown> }>;
	text?: string;
}

/** A provider script: one assistant response per request, ids derived from its index. */
function createScriptedAgent(options: {
	model: MockModel;
	turns: ScriptedTurn[];
	contexts: Context[];
	tools: AgentTool[];
}): Agent {
	let requestIndex = 0;
	return new Agent({
		getApiKey: () => "test-key",
		initialState: { model: options.model, systemPrompt: ["Test"], tools: options.tools, messages: [] },
		convertToLlm,
		streamFn: (_model, context) => {
			options.contexts.push(context);
			const index = requestIndex++;
			const turn = options.turns[index] ?? { text: "done" };
			const toolCalls = turn.toolCalls;
			const stopReason = toolCalls ? ("toolUse" as const) : ("stop" as const);
			const content: AssistantMessage["content"] = toolCalls
				? toolCalls.map((call, callIndex) => ({
						type: "toolCall" as const,
						id: `tc-${index}-${callIndex}`,
						name: call.name,
						arguments: call.arguments,
					}))
				: [{ type: "text" as const, text: turn.text ?? "" }];
			const message: AssistantMessage = {
				role: "assistant",
				content,
				api: options.model.api,
				provider: options.model.provider,
				model: options.model.id,
				usage: zeroUsage,
				stopReason,
				timestamp: Date.now(),
			};
			const stream = new AssistantMessageEventStream();
			queueMicrotask(() => {
				stream.push({ type: "start", partial: message });
				stream.push({ type: "done", reason: stopReason, message });
			});
			return stream;
		},
	});
}

function toolSession(settings: Settings, cwd: string): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
	} as unknown as ToolSession;
}

function sessionFor(options: {
	agent: Agent;
	settings: Settings;
	authStorage: AuthStorage;
	cwd: string;
	tools: AgentTool[];
}): AgentSession {
	const modelRegistry = new ModelRegistry(options.authStorage);
	return new AgentSession({
		agent: options.agent,
		sessionManager: SessionManager.inMemory(options.cwd),
		settings: options.settings,
		modelRegistry,
		toolRegistry: new Map(options.tools.map(tool => [tool.name, tool])),
	});
}

function recordOf(value: unknown): Record<string, unknown> | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	// Narrowed above: object-like records are the only detail containers these tests read.
	return value as Record<string, unknown>;
}

function dispatchFailureOf(result: ToolResultMessage): { code: string; key: string } | undefined {
	const failure = recordOf(recordOf(result.details)?.dispatchFailure);
	const code = failure?.code;
	const key = failure?.key;
	return typeof code === "string" && typeof key === "string" ? { code, key } : undefined;
}

function loopGuardBlockedOf(result: ToolResultMessage): boolean | undefined {
	const blocked = recordOf(recordOf(result.details)?.toolCallLoopGuard)?.blocked;
	return typeof blocked === "boolean" ? blocked : undefined;
}

function redirectDetailsOf(redirect: CustomMessage): { count: number; key: string } | undefined {
	const details = recordOf(redirect.details);
	const count = details?.count;
	const key = details?.key;
	return typeof count === "number" && typeof key === "string" ? { count, key } : undefined;
}

function toolResultsOf(session: AgentSession): ToolResultMessage[] {
	return session.agent.state.messages.filter((message): message is ToolResultMessage => message.role === "toolResult");
}

function redirectsOf(session: AgentSession, customType: string): CustomMessage[] {
	return session.agent.state.messages.filter(
		(message): message is CustomMessage => message.role === "custom" && message.customType === customType,
	);
}

/**
 * Flat single-spawn payload targeting an ordinary agent while carrying a
 * reserved seance selector. The selector sits at the root because the tool's
 * lenient validation restores root keys the wire schema would drop, which is
 * what lets `execute`/`getDispatchFailure` own the refusal.
 */
function reservedSelectorTask(index: number): ScriptedTurn {
	const agents = ["scout", "reviewer", "security-reviewer", "task", "sonic"];
	return {
		toolCalls: [
			{
				name: "task",
				arguments: {
					name: `guard_probe_${index}`,
					agent: agents[index % agents.length],
					task: `Investigate reworded variant ${index}.`,
					sourceSession: "/tmp/reverse-loop-guard-missing-session.jsonl",
				},
			},
		],
	};
}

describe("AgentSession tool-call loop guard", () => {
	let tempDir: TempDir;
	let authStorage: AuthStorage;
	let session: AgentSession | undefined;

	beforeEach(async () => {
		tempDir = TempDir.createSync("@pi-tool-call-loop-guard-");
		authStorage = await AuthStorage.create(path.join(tempDir.path(), "auth.db"));
		authStorage.keys.setRuntime("openai", "openai-test-key");
	});

	afterEach(async () => {
		await session?.dispose();
		authStorage.close();
		tempDir.removeSync();
	});

	it("injects a hidden redirect before the next model call", async () => {
		const model = createMockModel({ provider: "openai", id: "gpt-test" }).model;
		const modelRegistry = new ModelRegistry(authStorage);
		const contexts: Context[] = [];
		const bashTool: AgentTool = {
			name: "bash",
			label: "Bash",
			description: "Mock bash tool",
			parameters: type({ "command?": "string" }),
			execute: async () => ({ content: [{ type: "text" as const, text: "1263 passed, 4 skipped" }] }),
		};
		let callCount = 0;
		const agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: ["Test"], tools: [bashTool], messages: [] },
			convertToLlm,
			streamFn: (_model, context) => {
				contexts.push(context);
				const toolCallTurn = callCount < 2;
				const toolCallId = `tc-${callCount}`;
				callCount++;
				const message: AssistantMessage = toolCallTurn
					? {
							role: "assistant",
							content: [{ type: "toolCall", id: toolCallId, name: "bash", arguments: { command: "pytest -q" } }],
							api: model.api,
							provider: model.provider,
							model: model.id,
							usage: zeroUsage,
							stopReason: "toolUse",
							timestamp: Date.now(),
						}
					: {
							role: "assistant",
							content: [{ type: "text", text: "Stopped repeating." }],
							api: model.api,
							provider: model.provider,
							model: model.id,
							usage: zeroUsage,
							stopReason: "stop",
							timestamp: Date.now(),
						};
				const stream = new AssistantMessageEventStream();
				queueMicrotask(() => {
					stream.push({ type: "start", partial: message });
					stream.push({ type: "done", reason: toolCallTurn ? "toolUse" : "stop", message });
				});
				return stream;
			},
		});
		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 2,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
		settings.setModelRole("default", `${model.provider}/${model.id}`);
		session = new AgentSession({
			agent,
			sessionManager: SessionManager.inMemory(tempDir.path()),
			settings,
			modelRegistry,
			toolRegistry: new Map([[bashTool.name, bashTool]]),
		});

		await session.prompt("run checks");
		await session.waitForIdle();

		expect(contexts).toHaveLength(3);
		expect(JSON.stringify(contexts[2]!.messages)).toContain("tool_call_loop_detected");
		expect(JSON.stringify(contexts[2]!.messages)).toContain("1263 passed, 4 skipped");
		const redirects = session.agent.state.messages.filter(
			(message): message is CustomMessage =>
				message.role === "custom" && message.customType === "tool-call-loop-redirect",
		);
		expect(redirects).toHaveLength(1);
		expect(redirects[0]!.display).toBe(false);
	});

	it("stops a repeated exact batch before dispatch and resumes it after a new prompt", async () => {
		const model = createMockModel({ provider: "openai", id: "gpt-test" }).model;
		const contexts: Context[] = [];
		const executions = { bash: 0, check: 0 };
		const bashTool: AgentTool = {
			name: "bash",
			label: "Bash",
			description: "Mock bash tool",
			parameters: type({ "command?": "string" }),
			execute: async () => {
				executions.bash++;
				return { content: [{ type: "text" as const, text: "suite passed" }] };
			},
		};
		const checkTool: AgentTool = {
			name: "check",
			label: "Check",
			description: "Mock sibling tool",
			parameters: type({ "query?": "string" }),
			execute: async () => {
				executions.check++;
				return { content: [{ type: "text" as const, text: "checked" }] };
			},
		};
		const batch: ScriptedTurn = {
			toolCalls: [
				{ name: "bash", arguments: { command: "pytest -q" } },
				{ name: "check", arguments: { query: "status" } },
			],
		};
		const agent = createScriptedAgent({
			model,
			contexts,
			tools: [bashTool, checkTool],
			turns: [batch, batch, batch, batch, { text: "moved on" }],
		});
		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 2,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
		settings.setModelRole("default", `${model.provider}/${model.id}`);
		session = sessionFor({ agent, settings, authStorage, cwd: tempDir.path(), tools: [bashTool, checkTool] });

		const starts: Array<{ toolCallId: string; toolName: string }> = [];
		session.subscribe(event => {
			if (event.type === "tool_execution_start") {
				starts.push({ toolCallId: event.toolCallId, toolName: event.toolName });
			}
		});

		await session.prompt("run checks");
		await session.waitForIdle();

		// Two announced turns reach the tool batch; the third identical batch is
		// blocked before dispatch and earns no further provider request.
		expect(contexts).toHaveLength(3);
		expect(executions).toEqual({ bash: 2, check: 2 });
		expect(starts.filter(start => start.toolName === "bash")).toHaveLength(2);
		expect(starts.filter(start => start.toolName === "check")).toHaveLength(2);
		expect(starts.some(start => start.toolCallId.startsWith("tc-2-"))).toBe(false);

		const blockedResults = toolResultsOf(session).filter(result => result.toolCallId.startsWith("tc-2-"));
		expect(blockedResults).toHaveLength(2);
		expect(blockedResults.every(result => result.isError === true)).toBe(true);
		expect(blockedResults.every(result => recordOf(result.details)?.unexecuted === true)).toBe(true);
		expect(blockedResults.every(result => recordOf(result.details)?.executed === false)).toBe(true);
		const blockedTrigger = blockedResults.find(result => loopGuardBlockedOf(result) === true);
		expect(blockedTrigger).toBeDefined();
		expect(recordOf(blockedTrigger!.details)?.unexecuted).toBe(true);
		expect(recordOf(blockedTrigger!.details)?.executed).toBe(false);
		expect(redirectsOf(session, "tool-call-loop-redirect")).toHaveLength(1);
		expect(redirectsOf(session, "tool-call-loop-dispatch-failure")).toHaveLength(0);

		// A deliberate new prompt is a boundary: the same batch may run again.
		await session.prompt("retry the checks");
		await session.waitForIdle();

		expect(contexts).toHaveLength(5);
		expect(executions).toEqual({ bash: 3, check: 3 });
		expect(starts.filter(start => start.toolName === "bash")).toHaveLength(3);
		expect(starts.filter(start => start.toolName === "check")).toHaveLength(3);
	});

	it("counts a reworded TaskTool dispatch rejection and blocks the next repeat", async () => {
		const model = createMockModel({ provider: "openai", id: "gpt-test" }).model;
		const contexts: Context[] = [];
		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 5,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
			"task.batch": false,
			"task.isolation.enabled": false,
		});
		settings.setModelRole("default", `${model.provider}/${model.id}`);
		const taskTool = await TaskTool.create(toolSession(settings, tempDir.path()));
		// Blank ordinary selectors are placeholders, not defects: the same planning
		// boundary drops them exactly like an omitted field.
		expect(
			taskTool.getDispatchFailure({
				name: "blank_selector",
				agent: "scout",
				task: "Do the ordinary work.",
				sourceSession: "   ",
				model: "  ",
			}),
		).toBeUndefined();
		expect(
			taskTool.getDispatchFailure({
				name: "populated_selector",
				agent: "reviewer",
				task: "Do other ordinary work.",
				sourceSession: "/tmp/another-missing-session.jsonl",
			})?.key,
		).toBe("task.seance:reserved-source-session");
		// TaskTool renders with the concrete tui Theme while AgentTool's renderer hook is
		// theme-agnostic; the runtime path under test never invokes renderCall.
		const taskAgentTool = taskTool as unknown as AgentTool;
		const agent = createScriptedAgent({
			model,
			contexts,
			tools: [taskAgentTool],
			turns: [
				...Array.from({ length: 6 }, (_unused, index) => reservedSelectorTask(index)),
				reservedSelectorTask(6),
				{ text: "moved on" },
			],
		});
		session = sessionFor({ agent, settings, authStorage, cwd: tempDir.path(), tools: [taskAgentTool] });

		const starts: Array<{ toolCallId: string; toolName: string }> = [];
		session.subscribe(event => {
			if (event.type === "tool_execution_start") {
				starts.push({ toolCallId: event.toolCallId, toolName: event.toolName });
			}
		});

		await session.prompt("delegate the investigation");
		await session.waitForIdle();

		// Five local rejections with the same semantic key warn, and the sixth
		// reworded call is blocked before TaskTool executes — no seventh request.
		expect(contexts).toHaveLength(6);
		expect(starts).toHaveLength(5);
		expect(starts.every(start => start.toolName === "task")).toBe(true);

		const results = toolResultsOf(session);
		const failedRuns = results.filter(
			result => result.toolCallId.startsWith("tc-") && !result.toolCallId.startsWith("tc-5-"),
		);
		expect(failedRuns).toHaveLength(5);
		const failures = failedRuns.map(result => dispatchFailureOf(result)!);
		expect(failures.every(failure => failure.code === "task.seance")).toBe(true);
		expect(new Set(failures.map(failure => failure.key)).size).toBe(1);
		expect(failedRuns.every(result => recordOf(result.details)?.executed === false)).toBe(true);
		expect(failedRuns.every(result => recordOf(result.details)?.unexecuted === true)).toBe(true);
		expect(failedRuns.every(result => result.isError === true)).toBe(true);
		// A local plan rejection starts no agent: no results and no project dir.
		expect(recordOf(failedRuns[0]!.details)?.results).toEqual([]);
		expect(recordOf(failedRuns[0]!.details)?.projectAgentsDir).toBeNull();
		const badKey = failures[0]!.key;

		const blocked = results.find(result => result.toolCallId === "tc-5-0");
		expect(blocked).toBeDefined();
		expect(blocked!.isError).toBe(true);
		expect(recordOf(blocked!.details)?.unexecuted).toBe(true);
		expect(recordOf(blocked!.details)?.executed).toBe(false);
		expect(loopGuardBlockedOf(blocked!)).toBe(true);
		expect(recordOf(blocked!.details)?.dispatchFailure).toBeUndefined();

		const dispatchRedirects = redirectsOf(session, "tool-call-loop-dispatch-failure");
		expect(dispatchRedirects).toHaveLength(1);
		const redirectDetails = redirectDetailsOf(dispatchRedirects[0]!);
		expect(redirectDetails?.count).toBe(5);
		expect(redirectDetails?.key).toBe(badKey);

		const assistantMessages = session.agent.state.messages.filter(
			(message): message is AssistantMessage => message.role === "assistant",
		);
		expect(assistantMessages).toHaveLength(6);
		expect(assistantMessages[assistantMessages.length - 1]!.stopReason).toBe("toolUse");

		// A new prompt clears the failure state: the same call may run again.
		await session.prompt("retry the delegation");
		await session.waitForIdle();

		expect(contexts).toHaveLength(8);
		expect(starts).toHaveLength(6);
		expect(redirectsOf(session, "tool-call-loop-dispatch-failure")).toHaveLength(1);
	});

	it("allows a corrected TaskTool call right after the dispatch-failure warning", async () => {
		const model = createMockModel({ provider: "openai", id: "gpt-test" }).model;
		const contexts: Context[] = [];
		const settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 5,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
			"task.batch": false,
			"task.isolation.enabled": false,
		});
		settings.setModelRole("default", `${model.provider}/${model.id}`);
		const taskTool = await TaskTool.create(toolSession(settings, tempDir.path()));
		// Same renderer-theme variance as above; renderCall is never invoked here.
		const taskAgentTool = taskTool as unknown as AgentTool;
		const corrected: ScriptedTurn = {
			toolCalls: [
				{
					name: "task",
					arguments: {
						name: "guard_probe_corrected",
						agent: "scout",
						task: "",
					},
				},
			],
		};
		const agent = createScriptedAgent({
			model,
			contexts,
			tools: [taskAgentTool],
			turns: [
				...Array.from({ length: 5 }, (_unused, index) => reservedSelectorTask(index)),
				corrected,
				{ text: "moved on" },
			],
		});
		session = sessionFor({ agent, settings, authStorage, cwd: tempDir.path(), tools: [taskAgentTool] });

		const starts: Array<{ toolCallId: string; toolName: string }> = [];
		session.subscribe(event => {
			if (event.type === "tool_execution_start") {
				starts.push({ toolCallId: event.toolCallId, toolName: event.toolName });
			}
		});

		await session.prompt("delegate the investigation");
		await session.waitForIdle();

		expect(contexts).toHaveLength(7);
		expect(starts).toHaveLength(6);

		const results = toolResultsOf(session);
		const failedRuns = results.filter(result => !result.toolCallId.startsWith("tc-5-"));
		const failures = failedRuns.map(result => dispatchFailureOf(result)!);
		expect(failures.every(failure => failure.code === "task.seance")).toBe(true);
		const warnedKey = failures[0]!.key;

		const correctedResult = results.find(result => result.toolCallId === "tc-5-0");
		expect(correctedResult).toBeDefined();
		// The corrected call executed (raw TaskTool start) and hit a different
		// local preflight rejection instead of being blocked by the guard.
		expect(starts.some(start => start.toolCallId === "tc-5-0")).toBe(true);
		expect(correctedResult!.isError).toBe(true);
		expect(recordOf(correctedResult!.details)?.toolCallLoopGuard).toBeUndefined();
		const correctedFailure = dispatchFailureOf(correctedResult!)!;
		expect(correctedFailure.code).toBe("task.shape");
		expect(correctedFailure.key).not.toBe(warnedKey);
		expect(recordOf(correctedResult!.details)?.executed).toBe(false);
		expect(recordOf(correctedResult!.details)?.unexecuted).toBe(true);
		expect(recordOf(correctedResult!.details)?.results).toEqual([]);
		expect(recordOf(correctedResult!.details)?.projectAgentsDir).toBeNull();

		const dispatchRedirects = redirectsOf(session, "tool-call-loop-dispatch-failure");
		expect(dispatchRedirects).toHaveLength(1);
		expect(redirectDetailsOf(dispatchRedirects[0]!)?.key).toBe(warnedKey);
	});
});
