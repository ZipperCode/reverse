import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
	type AfterToolCallContext,
	Agent,
	type AgentTool,
	type AgentToolResult,
	type AgentMessage,
	type BeforeToolCallContext,
} from "@reverse/agent";
import type { AssistantMessage, ToolCall, ToolResultMessage } from "@reverse/ai";
import { createMockModel } from "@reverse/ai/providers/mock";
import { AssistantMessageEventStream } from "@reverse/ai/utils/event-stream";
import { Settings } from "@reverse/coding-agent/config/settings";
import { type CustomMessage, convertToLlm } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { LoopGuards, type StreamGuardsHost } from "@reverse/coding-agent/session/stream-guards";
import { type } from "@reverse/reversetype";
import { TempDir } from "@reverse/utils";

const zeroUsage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
} satisfies AssistantMessage["usage"];

const missingAgent = {
	code: "invalid_task_request",
	key: "missing_agent",
	message: "task requires an `agent` name; pass `agent` from `agent://` discovery",
};

function assistantMessage(calls: ToolCall[]): AssistantMessage {
	return {
		role: "assistant",
		content: calls,
		api: "openai-responses",
		provider: "openai",
		model: "test-model",
		usage: zeroUsage,
		stopReason: "toolUse",
		timestamp: Date.now(),
	};
}

function failedTaskResult(toolCallId: string): ToolResultMessage {
	return {
		role: "toolResult",
		toolCallId,
		toolName: "task",
		content: [{ type: "text", text: missingAgent.message }],
		details: { dispatchFailure: missingAgent, executed: false, unexecuted: true },
		isError: true,
		timestamp: Date.now(),
	};
}

function dispatchFailureRedirects(messages: readonly AgentMessage[]): CustomMessage[] {
	return messages.filter(
		(message): message is CustomMessage =>
			message.role === "custom" && message.customType === "tool-call-loop-dispatch-failure",
	);
}

describe("LoopGuards deterministic dispatch failures", () => {
	let tempDir: TempDir;
	let agent: Agent;
	let settings: Settings;
	let sessionManager: SessionManager;
	let promptSequence: { value: number };

	function makeGuards(): LoopGuards {
		const host: StreamGuardsHost = {
			agent,
			settings,
			get sessionManager() {
				return sessionManager;
			},
			model: () => undefined,
			isDisposed: () => false,
			promptGeneration: () => 0,
			promptSequence: () => promptSequence.value,
			emitNotice: () => {},
			schedulePostPromptTask: () => {},
			discardAssistantTurn: () => {},
		};
		return new LoopGuards(host);
	}

	function makeTaskTool(options?: { preconditionFixed?: () => boolean }): AgentTool {
		return {
			name: "task",
			label: "Task",
			description: "Delegates work to a subagent",
			parameters: type({ "agent?": "string", "prompt?": "string" }),
			execute: async () => ({ content: [] }),
			getDispatchFailure: args => {
				if (options?.preconditionFixed?.() === true) return undefined;
				const agentName = args && typeof args === "object" && "agent" in args ? args.agent : undefined;
				return typeof agentName === "string" && agentName.length > 0 ? undefined : missingAgent;
			},
		};
	}

	function taskCall(id: string, prompt: string, agentName?: string): ToolCall {
		return {
			type: "toolCall",
			id,
			name: "task",
			arguments: agentName === undefined ? { prompt } : { agent: agentName, prompt },
		};
	}

	function beforeContext(
		tool: AgentTool,
		call: ToolCall,
		args: Record<string, unknown>,
		batch?: ToolCall[],
	): BeforeToolCallContext {
		return {
			assistantMessage: assistantMessage(batch ?? [call]),
			toolCall: call,
			tool,
			args,
			context: { systemPrompt: [], messages: [] },
		};
	}

	function afterContext(
		call: ToolCall,
		args: Record<string, unknown>,
		result: AgentToolResult<unknown>,
		isError: boolean,
	): AfterToolCallContext {
		return {
			assistantMessage: assistantMessage([call]),
			toolCall: call,
			args,
			result,
			isError,
			context: { systemPrompt: [], messages: [] },
		};
	}

	beforeEach(() => {
		tempDir = TempDir.createSync("@pi-loop-guard-dispatch-");
		const model = createMockModel({ provider: "openai", id: "gpt-test" }).model;
		agent = new Agent({
			getApiKey: () => "test-key",
			initialState: { model, systemPrompt: ["Test"], tools: [], messages: [] },
			convertToLlm,
			streamFn: () => new AssistantMessageEventStream(),
		});
		sessionManager = SessionManager.inMemory(tempDir.path());
		promptSequence = { value: 1 };
		settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 5,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
	});

	afterEach(() => {
		tempDir.removeSync();
	});

	it("warns at the fifth rejection and blocks the sixth with the producer's correction", () => {
		const guards = makeGuards();
		const tool = makeTaskTool();
		const messages = agent.state.messages;

		for (let index = 0; index < 5; index++) {
			// The prose changes every attempt; the semantic key does not.
			const call = taskCall(`task-${index}`, `attempt ${index}`);
			guards.afterToolCall(afterContext(call, { prompt: `attempt ${index}` }, failedTaskResult(call.id), true));
			guards.recordTurn(messages, {
				message: assistantMessage([call]),
				toolResults: [failedTaskResult(call.id)],
				willContinue: false,
			});
		}

		const redirects = dispatchFailureRedirects(messages);
		expect(redirects).toHaveLength(1);
		const content = JSON.stringify(redirects[0]!.content);
		expect(content).toContain(missingAgent.message);
		expect(content).not.toContain("identical arguments");

		const sixth = taskCall("task-sixth", "one more angle");
		const blocked = guards.beforeToolCall(beforeContext(tool, sixth, { prompt: "one more angle" }));
		expect(blocked).toMatchObject({ block: true, stopTurn: true });
		expect(blocked!.reason).toContain(missingAgent.message);
		expect(blocked!.reason).not.toContain("identical arguments");

		const corrected = taskCall("task-fixed", "delegate now", "explore");
		expect(
			guards.beforeToolCall(beforeContext(tool, corrected, { agent: "explore", prompt: "delegate now" })),
		).toBeUndefined();
	});

	it("normalizes its own blocked result with observable metadata and no dispatch failure", () => {
		const guards = makeGuards();
		const tool = makeTaskTool();
		const messages = agent.state.messages;
		for (let index = 0; index < 5; index++) {
			const call = taskCall(`task-${index}`, `attempt ${index}`);
			guards.afterToolCall(afterContext(call, { prompt: `attempt ${index}` }, failedTaskResult(call.id), true));
			guards.recordTurn(messages, {
				message: assistantMessage([call]),
				toolResults: [failedTaskResult(call.id)],
				willContinue: false,
			});
		}
		const sixth = taskCall("task-sixth", "again");
		expect(guards.beforeToolCall(beforeContext(tool, sixth, { prompt: "again" }))).toMatchObject({
			block: true,
			stopTurn: true,
		});
		const normalized = guards.afterToolCall(
			afterContext(sixth, { prompt: "again" }, { content: [], details: { blocked: true } }, true),
		);
		expect(normalized?.isError).toBe(true);
		expect(normalized?.details).toMatchObject({
			unexecuted: true,
			executed: false,
			toolCallLoopGuard: { blocked: true },
		});
		expect(JSON.stringify(normalized?.details)).not.toContain("dispatchFailure");
	});

	it("clears deterministic history after a successful call of the same tool", () => {
		const guards = makeGuards();
		const tool = makeTaskTool();
		const messages = agent.state.messages;
		for (let index = 0; index < 5; index++) {
			const call = taskCall(`task-${index}`, `attempt ${index}`);
			guards.afterToolCall(afterContext(call, { prompt: `attempt ${index}` }, failedTaskResult(call.id), true));
			guards.recordTurn(messages, {
				message: assistantMessage([call]),
				toolResults: [failedTaskResult(call.id)],
				willContinue: false,
			});
		}
		const repeated = taskCall("task-repeated", "same");
		expect(guards.beforeToolCall(beforeContext(tool, repeated, { prompt: "same" }))).toMatchObject({ block: true });

		const success = taskCall("task-success", "delegate", "explore");
		guards.afterToolCall(afterContext(success, { agent: "explore" }, { content: [], details: {} }, false));

		const retry = taskCall("task-retry", "same");
		expect(guards.beforeToolCall(beforeContext(tool, retry, { prompt: "same" }))).toBeUndefined();
	});

	it("resets failure history at a new prompt and at a session switch", () => {
		const guards = makeGuards();
		const tool = makeTaskTool();
		const messages = agent.state.messages;
		const recordFiveFailures = (prefix: string) => {
			for (let index = 0; index < 5; index++) {
				const call = taskCall(`${prefix}-${index}`, `attempt ${index}`);
				guards.afterToolCall(afterContext(call, { prompt: `attempt ${index}` }, failedTaskResult(call.id), true));
				guards.recordTurn(messages, {
					message: assistantMessage([call]),
					toolResults: [failedTaskResult(call.id)],
					willContinue: false,
				});
			}
		};

		recordFiveFailures("first");
		expect(guards.beforeToolCall(beforeContext(tool, taskCall("blocked-1", "x"), { prompt: "x" }))).toMatchObject({
			block: true,
		});

		// A fresh user prompt is a true boundary.
		promptSequence.value++;
		expect(guards.beforeToolCall(beforeContext(tool, taskCall("allowed-1", "x"), { prompt: "x" }))).toBeUndefined();

		recordFiveFailures("second");
		expect(guards.beforeToolCall(beforeContext(tool, taskCall("blocked-2", "x"), { prompt: "x" }))).toMatchObject({
			block: true,
		});

		// Switching sessions also resets, even at the same prompt sequence.
		sessionManager = SessionManager.inMemory(tempDir.path());
		expect(guards.beforeToolCall(beforeContext(tool, taskCall("allowed-2", "x"), { prompt: "x" }))).toBeUndefined();
	});

	it("counts bridged failures once and blocks the reissued bridged call", () => {
		const guards = makeGuards();
		const tool = makeTaskTool();
		const messages = agent.state.messages;
		for (let index = 0; index < 5; index++) {
			const toolCallId = `bridge-${index}`;
			expect(guards.beforeBridgedToolCall(toolCallId, tool, { prompt: `attempt ${index}` })).toBeUndefined();
			guards.afterBridgedToolCall(toolCallId, {
				content: [],
				isError: true,
				details: failedTaskResult(toolCallId).details,
			});
			guards.recordTurn(messages, {
				message: assistantMessage([requestedCall(toolCallId)]),
				toolResults: [],
				willContinue: false,
			});
		}
		// The bridge result and a later turn sweep never double count: a sixth
		// bridge failure after the warning would already be a different attempt.
		const warnings = dispatchFailureRedirects(messages);
		expect(warnings).toHaveLength(1);

		const blocked = guards.beforeBridgedToolCall("bridge-sixth", tool, { prompt: "again" });
		expect(blocked).toMatchObject({ block: true, stopTurn: true });
		expect(blocked!.reason).toContain(missingAgent.message);

		// A cancelled bridge dispatch is never observed.
		guards.cancelBridgedToolCall("bridge-cancelled");
		guards.afterBridgedToolCall("bridge-cancelled", {
			content: [],
			isError: true,
			details: { dispatchFailure: missingAgent },
		});
		expect(dispatchFailureRedirects(messages)).toHaveLength(1);
	});

	it("unlocks byte-identical calls once the tool's precondition is fixed", () => {
		const guards = makeGuards();
		const fixed = { value: false };
		const tool = makeTaskTool({ preconditionFixed: () => fixed.value });
		const messages = agent.state.messages;
		for (let index = 0; index < 5; index++) {
			// Identical arguments every attempt: this also trips the exact-batch warning.
			const call = taskCall(`same-${index}`, "same request");
			guards.afterToolCall(afterContext(call, { prompt: "same request" }, failedTaskResult(call.id), true));
			guards.recordTurn(messages, {
				message: assistantMessage([call]),
				toolResults: [failedTaskResult(call.id)],
				willContinue: false,
			});
		}

		expect(
			guards.beforeToolCall(
				beforeContext(tool, taskCall("same-before-fix", "same request"), { prompt: "same request" }),
			),
		).toMatchObject({ block: true });

		// The configuration changed while the arguments stayed byte-identical.
		fixed.value = true;
		expect(
			guards.beforeToolCall(
				beforeContext(tool, taskCall("same-after-fix", "same request"), { prompt: "same request" }),
			),
		).toBeUndefined();
	});

	it("defers the exact stop until the second call's extension repair is known", () => {
		settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 2,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
		const guards = makeGuards();
		const bash: AgentTool = {
			name: "bash",
			label: "Bash",
			description: "Runs a command",
			parameters: type({ "command?": "string" }),
			execute: async () => ({ content: [] }),
		};
		const read: AgentTool = {
			name: "read",
			label: "Read",
			description: "Reads a file",
			parameters: type({ "path?": "string" }),
			execute: async () => ({ content: [] }),
		};
		const batch = (bashId: string, readId: string): ToolCall[] => [
			{ type: "toolCall", id: bashId, name: "bash", arguments: { command: "pwd" } },
			{ type: "toolCall", id: readId, name: "read", arguments: { path: "a.ts" } },
		];
		const messages = agent.state.messages;
		for (const [bashId, readId] of [
			["warn-bash-1", "warn-read-1"],
			["warn-bash-2", "warn-read-2"],
		] as const) {
			guards.recordTurn(messages, {
				message: assistantMessage(batch(bashId, readId)),
				toolResults: [],
				willContinue: false,
			});
		}

		// First call prepares with raw arguments only; the second call's repair is
		// not known yet, so the exact stop must not fire here.
		const reissued = batch("re-bash", "re-read");
		expect(guards.beforeToolCall(beforeContext(bash, reissued[0]!, { command: "pwd" }, reissued))).toBeUndefined();
		// The extension repaired only the second call; the whole batch dispatches.
		expect(
			guards.beforeToolCall(beforeContext(read, reissued[1]!, { path: "repaired.ts" }, reissued)),
		).toBeUndefined();

		// Without a repair the fully prepared identical batch still hard-stops.
		const plain = batch("plain-bash", "plain-read");
		expect(guards.beforeToolCall(beforeContext(bash, plain[0]!, { command: "pwd" }, plain))).toBeUndefined();
		expect(guards.beforeToolCall(beforeContext(read, plain[1]!, { path: "a.ts" }, plain))).toMatchObject({
			block: true,
			stopTurn: true,
		});
	});

	it("hard-blocks the identical batch after its redirect but not changed arguments", () => {
		settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 2,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
		const guards = makeGuards();
		const bash: AgentTool = {
			name: "bash",
			label: "Bash",
			description: "Runs a command",
			parameters: type({ "command?": "string" }),
			execute: async () => ({ content: [] }),
		};
		const messages = agent.state.messages;
		const batch = (id: string): ToolCall[] => [
			{ type: "toolCall", id, name: "bash", arguments: { command: "pytest -q" } },
		];
		for (let index = 0; index < 2; index++) {
			guards.recordTurn(messages, {
				message: assistantMessage(batch(`batch-${index}`)),
				toolResults: [],
				willContinue: false,
			});
		}
		expect(
			messages.filter(message => message.role === "custom" && message.customType === "tool-call-loop-redirect"),
		).toHaveLength(1);

		const third = batch("batch-third")[0]!;
		const blocked = guards.beforeToolCall(beforeContext(bash, third, { command: "pytest -q" }));
		expect(blocked).toMatchObject({ block: true, stopTurn: true });
		expect(blocked!.reason).toContain("same arguments");

		const changed = { ...batch("batch-changed")[0]!, arguments: { command: "pytest -q --maxfail=1" } };
		expect(guards.beforeToolCall(beforeContext(bash, changed, { command: "pytest -q --maxfail=1" }))).toBeUndefined();
	});

	it("uses the revised arguments rather than the stale batch arguments", () => {
		settings = Settings.isolated({
			"compaction.enabled": false,
			"todo.enabled": false,
			"model.toolCallLoopGuard.enabled": true,
			"model.toolCallLoopGuard.threshold": 2,
			"model.toolCallLoopGuard.exemptTools": ["wait"],
		});
		const guards = makeGuards();
		const bash: AgentTool = {
			name: "bash",
			label: "Bash",
			description: "Runs a command",
			parameters: type({ "command?": "string" }),
			execute: async () => ({ content: [] }),
		};
		const messages = agent.state.messages;
		for (let index = 0; index < 2; index++) {
			guards.recordTurn(messages, {
				message: assistantMessage([{ type: "toolCall", id: `call-${index}`, name: "bash", arguments: {} }]),
				toolResults: [],
				willContinue: false,
			});
		}
		// The model resent the same empty call, but an extension revision filled
		// in the command the guard must check instead.
		const stale: ToolCall = { type: "toolCall", id: "call-revised", name: "bash", arguments: {} };
		expect(guards.beforeToolCall(beforeContext(bash, stale, { command: "echo repaired" }))).toBeUndefined();
	});
});

/** Tool call used only to shape a turn; bridge results carry the real tool result. */
function requestedCall(id: string): ToolCall {
	return { type: "toolCall", id, name: "eval", arguments: { code: "await task(...)" } };
}
