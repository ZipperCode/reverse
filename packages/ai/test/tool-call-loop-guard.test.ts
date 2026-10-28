import { describe, expect, test } from "bun:test";
import type { AssistantMessage, ToolCall, ToolResultMessage } from "@reverse/ai";
import { ToolCallLoopGuard } from "@reverse/ai/utils/tool-call-loop-guard";
import { INTENT_FIELD } from "@reverse/wire";

const zeroUsage = {
	input: 0,
	output: 0,
	cacheRead: 0,
	cacheWrite: 0,
	totalTokens: 0,
	cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
} satisfies AssistantMessage["usage"];

describe("ToolCallLoopGuard", () => {
	test("detects the fifth consecutive identical tool call", () => {
		const guard = new ToolCallLoopGuard({ threshold: 5, exemptTools: ["job", "irc"] });
		let detection = null;
		for (let index = 0; index < 5; index++) {
			const toolCallId = `call-${index}`;
			detection = guard.recordTurn({
				message: {
					role: "assistant",
					content: [
						{ type: "toolCall", id: toolCallId, name: "bash", arguments: { command: "pytest -q", timeout: 120 } },
					],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId,
						toolName: "bash",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			});
		}

		expect(detection).toEqual({
			kind: "repeated_tool_call",
			toolName: "bash",
			count: 5,
			resultSummary: "1263 passed, 4 skipped",
			argumentsSummary: '{"command":"pytest -q","timeout":120}',
		});
	});

	test("canonicalizes argument key order and ignores harness intent fields", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [
						{ type: "toolCall", id: "first", name: "read", arguments: { path: "a.ts", [INTENT_FIELD]: "first" } },
					],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "first",
						toolName: "read",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [
						{
							type: "toolCall",
							id: "second",
							name: "read",
							arguments: { [INTENT_FIELD]: "second", path: "a.ts" },
						},
					],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "second",
						toolName: "read",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toMatchObject({ toolName: "read", count: 2 });
	});

	test("resets the consecutive count on a different call", () => {
		const guard = new ToolCallLoopGuard({ threshold: 3, exemptTools: [] });
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [{ type: "toolCall", id: "first", name: "bash", arguments: { command: "pytest -q" } }],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "first",
						toolName: "bash",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [{ type: "toolCall", id: "second", name: "read", arguments: { path: "src/index.ts" } }],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "second",
						toolName: "read",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [{ type: "toolCall", id: "third", name: "bash", arguments: { command: "pytest -q" } }],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "third",
						toolName: "bash",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
	});

	test("re-detects continued identical calls past the threshold (issue #12564)", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const turn = (id: string) => ({
			message: {
				role: "assistant",
				content: [{ type: "toolCall", id, name: "todo", arguments: {} }],
				api: "openai-responses",
				provider: "openai",
				model: "test-model",
				usage: zeroUsage,
				stopReason: "toolUse",
				timestamp: Date.now(),
			} satisfies AssistantMessage,
			toolResults: [],
		});
		expect(guard.recordTurn(turn("a"))).toBeNull();
		expect(guard.recordTurn(turn("b"))).toMatchObject({ toolName: "todo", count: 2 });
		expect(guard.recordTurn(turn("c"))).toMatchObject({ toolName: "todo", count: 3 });
		expect(guard.recordTurn(turn("d"))).toMatchObject({ toolName: "todo", count: 4 });
	});

	test("ignores exempt polling tools", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["job"] });
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [{ type: "toolCall", id: "first", name: "job", arguments: { poll: ["abc"] } }],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "first",
						toolName: "job",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
		expect(
			guard.recordTurn({
				message: {
					role: "assistant",
					content: [{ type: "toolCall", id: "second", name: "job", arguments: { poll: ["abc"] } }],
					api: "openai-responses",
					provider: "openai",
					model: "test-model",
					usage: zeroUsage,
					stopReason: "toolUse",
					timestamp: Date.now(),
				},
				toolResults: [
					{
						role: "toolResult",
						toolCallId: "second",
						toolName: "job",
						content: [{ type: "text", text: "1263 passed, 4 skipped" }],
						isError: false,
						timestamp: Date.now(),
					},
				],
			}),
		).toBeNull();
	});
});

describe("ToolCallLoopGuard multi-call turns", () => {
	let nextId = 0;

	function toolCall(name: string, args: Record<string, unknown>): ToolCall {
		return { type: "toolCall", id: `tc_${nextId++}`, name, arguments: args };
	}

	function turn(calls: ToolCall[], toolResults: ToolResultMessage[] = []) {
		const message = {
			role: "assistant",
			content: calls,
			api: "openai-responses",
			provider: "openai",
			model: "test-model",
			usage: zeroUsage,
			stopReason: "toolUse",
			timestamp: Date.now(),
		} satisfies AssistantMessage;
		return { message, toolResults };
	}

	test("counts consecutive identical multi-call batches toward the threshold", () => {
		const guard = new ToolCallLoopGuard({ threshold: 3, exemptTools: [] });
		const batch = () => [toolCall("bash", { command: "echo a" }), toolCall("read", { path: "a.ts" })];
		expect(guard.recordTurn(turn(batch()))).toBeNull();
		expect(guard.recordTurn(turn(batch()))).toBeNull();
		expect(guard.recordTurn(turn(batch()))).toMatchObject({ toolName: "bash", count: 3 });
	});

	test("resets on a turn with no tool calls", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const batch = () => [toolCall("bash", { command: "echo a" }), toolCall("read", { path: "a.ts" })];
		expect(guard.recordTurn(turn(batch()))).toBeNull();
		expect(guard.recordTurn(turn([]))).toBeNull();
		expect(guard.recordTurn(turn(batch()))).toBeNull();
	});

	/** An exempt `wait` turn; `useless` marks a wait that elapsed with nothing new. */
	function waitTurn(text: string, useless: boolean) {
		const call = toolCall("wait", {});
		return turn(
			[call],
			[
				{
					role: "toolResult",
					toolCallId: call.id,
					toolName: "wait",
					content: [{ type: "text", text }],
					isError: false,
					...(useless ? { useless: true } : {}),
					timestamp: Date.now(),
				},
			],
		);
	}

	test("keeps counting across an idle exempt poll between identical turns", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["wait"] });
		const pytest = () => turn([toolCall("bash", { command: "pytest" })]);
		expect(guard.recordTurn(pytest())).toBeNull();
		// The wait elapsed with nothing new, so it does not hide the loop.
		expect(guard.recordTurn(waitTurn("Wait limit reached.", true))).toBeNull();
		expect(guard.recordTurn(pytest())).toMatchObject({ toolName: "bash", count: 2 });
	});

	test("resets after an exempt poll that returned something, even repeated text", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["wait"] });
		const pytest = () => turn([toolCall("bash", { command: "pytest" })]);
		expect(guard.recordTurn(pytest())).toBeNull();
		// A finished service may have changed what the rerun sees.
		expect(guard.recordTurn(waitTurn("A service finished.", false))).toBeNull();
		expect(guard.recordTurn(pytest())).toBeNull();
		expect(guard.recordTurn(waitTurn("A service finished.", false))).toBeNull();
		expect(guard.recordTurn(pytest())).toBeNull();
	});

	test("resets after an idle exempt poll that arrived with injected context", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["wait"] });
		const pytest = () => turn([toolCall("bash", { command: "pytest" })]);
		expect(guard.recordTurn(pytest())).toBeNull();
		// An extension attached context to the timed-out wait: the rerun may see something new.
		expect(guard.recordTurn({ ...waitTurn("Wait limit reached.", true), injectedContext: true })).toBeNull();
		expect(guard.recordTurn(pytest())).toBeNull();
	});

	test("resets after an exempt call that failed", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["grep"] });
		const pytest = () => turn([toolCall("bash", { command: "pytest" })]);
		const call = toolCall("grep", { pattern: "x" });
		const failedGrep = turn(
			[call],
			[
				{
					role: "toolResult",
					toolCallId: call.id,
					toolName: "grep",
					content: [{ type: "text", text: "Invalid regex." }],
					isError: true,
					timestamp: Date.now(),
				},
			],
		);
		expect(guard.recordTurn(pytest())).toBeNull();
		// Only a result its tool flagged useless is an idle poll; a failure may follow real work.
		expect(guard.recordTurn(failedGrep)).toBeNull();
		expect(guard.recordTurn(pytest())).toBeNull();
	});

	test("counts a mixed batch and reports the first non-exempt call", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["read"] });
		const mixed = () => [toolCall("read", { path: "a.ts" }), toolCall("bash", { command: "echo a" })];
		expect(guard.recordTurn(turn(mixed()))).toBeNull();

		const repeated = mixed();
		expect(
			guard.recordTurn(
				turn(repeated, [
					{
						role: "toolResult",
						toolCallId: repeated[0]!.id,
						toolName: "read",
						content: [{ type: "text", text: "file contents" }],
						isError: false,
						timestamp: Date.now(),
					},
					{
						role: "toolResult",
						toolCallId: repeated[1]!.id,
						toolName: "bash",
						content: [{ type: "text", text: "command output" }],
						isError: false,
						timestamp: Date.now(),
					},
				]),
			),
		).toEqual({
			kind: "repeated_tool_call",
			toolName: "bash",
			count: 2,
			resultSummary: "command output",
			argumentsSummary: '{"command":"echo a"}',
		});
	});

	test("treats reordered parallel calls as the same batch", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		expect(
			guard.recordTurn(turn([toolCall("bash", { command: "echo a" }), toolCall("read", { path: "a.ts" })])),
		).toBeNull();
		expect(
			guard.recordTurn(turn([toolCall("read", { path: "a.ts" }), toolCall("bash", { command: "echo a" })])),
		).toMatchObject({ count: 2 });
	});

	test("does not count alternating distinct batches", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const a = () => [toolCall("bash", { command: "echo a" }), toolCall("read", { path: "a.ts" })];
		const b = () => [toolCall("bash", { command: "echo b" })];
		expect(guard.recordTurn(turn(a()))).toBeNull();
		expect(guard.recordTurn(turn(b()))).toBeNull();
		expect(guard.recordTurn(turn(a()))).toBeNull();
		expect(guard.recordTurn(turn(b()))).toBeNull();
	});
});

describe("ToolCallLoopGuard deterministic dispatch failures", () => {
	const missingPrompt = {
		code: "invalid_task_request",
		key: "missing_task_prompt",
		message: "task requires a non-empty prompt",
	};
	const unknownAgent = { ...missingPrompt, key: "unknown_agent_name" };
	let nextToolCallId = 0;

	function toolCall(name: string, args: Record<string, unknown>): ToolCall {
		return { type: "toolCall", id: `dispatch-tc-${nextToolCallId++}`, name, arguments: args };
	}

	function taskResult(toolCallId: string, details?: unknown, isError = true): ToolResultMessage {
		return {
			role: "toolResult",
			toolCallId,
			toolName: "task",
			content: [{ type: "text", text: isError ? "task requires a non-empty prompt" : "done" }],
			details,
			isError,
			timestamp: Date.now(),
		};
	}

	function assistantTurn(calls: ToolCall[]): AssistantMessage {
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

	test("warns once at the threshold and blocks only the same semantic key", () => {
		const guard = new ToolCallLoopGuard({ threshold: 5, exemptTools: [] });
		for (let index = 0; index < 5; index++) {
			// Prose/context/name changes keep the semantic key, so they accumulate.
			guard.observeToolResult({
				toolCallId: `call-${index}`,
				toolName: "task",
				isError: true,
				details: { dispatchFailure: { ...missingPrompt, message: `task requires a prompt (attempt ${index})` } },
			});
		}
		expect(guard.drainDispatchFailureWarnings()).toEqual([
			{
				kind: "repeated_dispatch_failure",
				toolName: "task",
				count: 5,
				code: "invalid_task_request",
				key: "missing_task_prompt",
				message: "task requires a prompt (attempt 4)",
			},
		]);
		expect(guard.blockedDispatchFailure("task", missingPrompt)).toMatchObject({ count: 5 });
		// A corrected field or another tool never matches the warned precondition.
		expect(guard.blockedDispatchFailure("task", unknownAgent)).toBeNull();
		expect(guard.blockedDispatchFailure("task", undefined)).toBeNull();
		expect(guard.blockedDispatchFailure("eval", missingPrompt)).toBeNull();
		// Failures beyond the warned count do not re-warn.
		guard.observeToolResult({
			toolCallId: "call-late",
			toolName: "task",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
	});

	test("transient failures neither count nor clear the history", () => {
		const guard = new ToolCallLoopGuard({ threshold: 5, exemptTools: [] });
		for (let index = 0; index < 4; index++) {
			guard.observeToolResult({
				toolCallId: `call-${index}`,
				toolName: "task",
				isError: true,
				details: { dispatchFailure: missingPrompt },
			});
		}
		guard.observeToolResult({ toolCallId: "transient", toolName: "task", isError: true, details: undefined });
		guard.observeToolResult({
			toolCallId: "provider-error",
			toolName: "task",
			isError: true,
			details: { error: "ECONNRESET" },
		});
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
		guard.observeToolResult({
			toolCallId: "call-5",
			toolName: "task",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toMatchObject([{ count: 5, key: "missing_task_prompt" }]);
	});

	test("a successful call of the same tool clears its failure history", () => {
		const guard = new ToolCallLoopGuard({ threshold: 5, exemptTools: [] });
		for (let index = 0; index < 4; index++) {
			guard.observeToolResult({
				toolCallId: `call-${index}`,
				toolName: "task",
				isError: true,
				details: { dispatchFailure: missingPrompt },
			});
		}
		guard.observeToolResult({ toolCallId: "ok", toolName: "task", isError: false, details: { executed: true } });
		for (let index = 0; index < 4; index++) {
			guard.observeToolResult({
				toolCallId: `again-${index}`,
				toolName: "task",
				isError: true,
				details: { dispatchFailure: missingPrompt },
			});
		}
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
		guard.observeToolResult({
			toolCallId: "again-5",
			toolName: "task",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toMatchObject([{ count: 5 }]);
	});

	test("ignores malformed dispatch failure details", () => {
		const guard = new ToolCallLoopGuard({ threshold: 1, exemptTools: [] });
		for (const details of [
			{ dispatchFailure: { code: "invalid_task_request", key: "missing_task_prompt" } },
			{ dispatchFailure: { code: "", key: "missing_task_prompt", message: "no code" } },
			{ dispatchFailure: "invalid_task_request" },
			{ dispatchFailure: null },
		]) {
			guard.observeToolResult({
				toolCallId: `bad-${JSON.stringify(details)}`,
				toolName: "task",
				isError: true,
				details,
			});
		}
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
		guard.observeToolResult({
			toolCallId: "valid",
			toolName: "task",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toMatchObject([{ count: 1, key: "missing_task_prompt" }]);
	});

	test("counts one result once when the after hook and the turn sweep both see it", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const result = taskResult("task-call", { dispatchFailure: missingPrompt });
		guard.observeToolResult({
			toolCallId: result.toolCallId,
			toolName: result.toolName,
			isError: result.isError,
			details: result.details,
		});
		guard.recordTurn({ message: assistantTurn([toolCall("task", { prompt: "ship it" })]), toolResults: [result] });
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
		guard.observeToolResult({
			toolCallId: "task-call-2",
			toolName: "task",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toMatchObject([{ count: 2, key: "missing_task_prompt" }]);
	});

	test("reads deterministic failures from completed turn results", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		guard.recordTurn({
			message: assistantTurn([toolCall("task", { prompt: "first wording" })]),
			toolResults: [taskResult("turn-1", { dispatchFailure: missingPrompt })],
		});
		guard.recordTurn({
			message: assistantTurn([toolCall("task", { prompt: "reworded request" })]),
			toolResults: [taskResult("turn-2", { dispatchFailure: missingPrompt })],
		});
		expect(guard.drainDispatchFailureWarnings()).toMatchObject([
			{ toolName: "task", count: 2, key: "missing_task_prompt" },
		]);
	});

	test("blocks the identical warned batch once and stops counting its blocked turn", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: ["wait"] });
		const batch: ToolCall[] = [
			{ type: "toolCall", id: "b1", name: "bash", arguments: { command: "pytest -q" } },
			{ type: "toolCall", id: "b2", name: "read", arguments: { path: "a.ts" } },
		];
		const turn = (calls: ToolCall[]) => ({ message: assistantTurn(calls), toolResults: [] });
		expect(guard.recordTurn(turn(batch))).toBeNull();
		expect(guard.recordTurn(turn(batch))).toMatchObject({ toolName: "bash", count: 2 });
		expect(guard.blockedRepeatedBatch(batch)).toEqual({ toolName: "bash", count: 2 });
		// The stopped batch produced no execution, so its turn earns no second warning.
		expect(
			guard.recordTurn({
				message: assistantTurn(batch),
				toolResults: [taskResult("b1", { unexecuted: true }), taskResult("b2", { unexecuted: true })],
			}),
		).toBeNull();
		// Changed arguments and exempt-only batches are never blocked.
		expect(
			guard.blockedRepeatedBatch([
				{ type: "toolCall", id: "b3", name: "bash", arguments: { command: "pytest -q --maxfail=1" } },
				batch[1]!,
			]),
		).toBeNull();
		expect(
			guard.blockedRepeatedBatch([{ type: "toolCall", id: "b4", name: "wait", arguments: { timeout: 5 } }]),
		).toBeNull();
	});

	test("reset clears batches and deterministic failure history", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const batch: ToolCall[] = [{ type: "toolCall", id: "b1", name: "bash", arguments: { command: "pytest -q" } }];
		guard.recordTurn({ message: assistantTurn(batch), toolResults: [] });
		guard.recordTurn({ message: assistantTurn(batch), toolResults: [] });
		for (let index = 0; index < 2; index++) {
			guard.observeToolResult({
				toolCallId: `call-${index}`,
				toolName: "task",
				isError: true,
				details: { dispatchFailure: missingPrompt },
			});
		}
		expect(guard.blockedRepeatedBatch(batch)).not.toBeNull();
		expect(guard.blockedDispatchFailure("task", missingPrompt)).not.toBeNull();
		guard.drainDispatchFailureWarnings();
		guard.reset();
		expect(guard.blockedRepeatedBatch(batch)).toBeNull();
		expect(guard.blockedDispatchFailure("task", missingPrompt)).toBeNull();
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
	});

	test("stops blocking once the batch sequence moves on", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const repeated = [toolCall("bash", { command: "echo a" })];
		guard.recordTurn({ message: assistantTurn(repeated), toolResults: [] });
		guard.recordTurn({ message: assistantTurn(repeated), toolResults: [] });
		expect(guard.blockedRepeatedBatch(repeated)).not.toBeNull();
		// The model changed approach: the warned batch is no longer the next one.
		guard.recordTurn({ message: assistantTurn([toolCall("bash", { command: "echo b" })]), toolResults: [] });
		expect(guard.blockedRepeatedBatch(repeated)).toBeNull();
	});

	test("a successful call clears its warned exact batch", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const repeated = [toolCall("bash", { command: "echo a" })];
		guard.recordTurn({ message: assistantTurn(repeated), toolResults: [] });
		guard.recordTurn({ message: assistantTurn(repeated), toolResults: [] });
		expect(guard.blockedRepeatedBatch(repeated)).not.toBeNull();
		guard.observeToolResult({ toolCallId: "later-success", toolName: "bash", isError: false, details: {} });
		expect(guard.blockedRepeatedBatch(repeated)).toBeNull();
	});

	test("a leading successful call does not hide a later deterministic failure in the batch", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const batch = () => {
			const bash = toolCall("bash", { command: "pwd" });
			const task = toolCall("task", { batch: [{ agent: "task", task: "x" }] });
			const results: ToolResultMessage[] = [
				{
					role: "toolResult",
					toolCallId: bash.id,
					toolName: "bash",
					content: [{ type: "text", text: "/tmp" }],
					isError: false,
					timestamp: Date.now(),
				},
				taskResult(task.id, { dispatchFailure: missingPrompt }),
			];
			return { bash, task, results };
		};

		const first = batch();
		expect(
			guard.recordTurn({ message: assistantTurn([first.bash, first.task]), toolResults: first.results }),
		).toBeNull();
		const second = batch();
		expect(
			guard.recordTurn({ message: assistantTurn([second.bash, second.task]), toolResults: second.results }),
		).toMatchObject({ kind: "repeated_tool_call", toolName: "bash", count: 2 });

		// With the task precondition fixed, the byte-identical batch must dispatch
		// even though the reported (first) call is the successful bash call.
		const reissued = batch();
		expect(guard.blockedRepeatedBatch([reissued.bash, reissued.task])).toBeNull();
		expect(guard.blockedDispatchFailure("task", undefined)).toBeNull();
		expect(guard.blockedDispatchFailure("task", missingPrompt)).toMatchObject({ count: 2 });
	});

	test("a structured rejection never hard-stops identical calls once the precondition clears", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const first = toolCall("task", { prompt: "same request" });
		guard.recordTurn({
			message: assistantTurn([first]),
			toolResults: [taskResult(first.id, { dispatchFailure: missingPrompt })],
		});
		const second = toolCall("task", { prompt: "same request" });
		expect(
			guard.recordTurn({
				message: assistantTurn([second]),
				toolResults: [taskResult(second.id, { dispatchFailure: missingPrompt })],
			}),
		).toMatchObject({ kind: "repeated_tool_call", count: 2 });
		expect(guard.drainDispatchFailureWarnings()).toHaveLength(1);

		// Same arguments, but the tool now reports no precondition failure: the
		// exact path is owned by the (cleared) semantic state, so it must allow.
		const reissued = toolCall("task", { prompt: "same request" });
		guard.recordDispatchedArgs(reissued.id, { prompt: "same request" });
		expect(guard.blockedRepeatedBatch([reissued])).toBeNull();
		expect(guard.blockedDispatchFailure("task", undefined)).toBeNull();
		// While the same precondition still fails, the semantic path still blocks.
		expect(guard.blockedDispatchFailure("task", missingPrompt)).toMatchObject({ count: 2 });
	});

	test("exempt tools never earn deterministic hard stops", () => {
		const guard = new ToolCallLoopGuard({ threshold: 1, exemptTools: ["wait"] });
		guard.observeToolResult({
			toolCallId: "wait-1",
			toolName: "wait",
			isError: true,
			details: { dispatchFailure: missingPrompt },
		});
		expect(guard.drainDispatchFailureWarnings()).toEqual([]);
		expect(guard.blockedDispatchFailure("wait", missingPrompt)).toBeNull();
	});

	test("compares the arguments that actually dispatch, not the raw model arguments", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const first = toolCall("bash", { command: "echo a" });
		guard.recordDispatchedArgs(first.id, { command: "echo a", timeout: 120 });
		expect(guard.recordTurn({ message: assistantTurn([first]), toolResults: [] })).toBeNull();
		const second = toolCall("bash", { command: "echo a" });
		guard.recordDispatchedArgs(second.id, { command: "echo a", timeout: 120 });
		expect(guard.recordTurn({ message: assistantTurn([second]), toolResults: [] })).toMatchObject({ count: 2 });

		const reissued = toolCall("bash", { command: "echo a" });
		guard.recordDispatchedArgs(reissued.id, { command: "echo a", timeout: 120 });
		expect(guard.hasAllDispatchedArgs([reissued])).toBe(true);
		expect(guard.blockedRepeatedBatch([reissued])).toMatchObject({ toolName: "bash", count: 2 });
		// An extension repair on the prepared call changes what dispatches.
		guard.recordDispatchedArgs(reissued.id, { command: "echo repaired", timeout: 120 });
		expect(guard.blockedRepeatedBatch([reissued])).toBeNull();
	});

	test("holds the exact stop until every call's final arguments are prepared", () => {
		const guard = new ToolCallLoopGuard({ threshold: 2, exemptTools: [] });
		const warned: ToolCall[] = [
			{ type: "toolCall", id: "warned-bash", name: "bash", arguments: { command: "pwd" } },
			{ type: "toolCall", id: "warned-read", name: "read", arguments: { path: "a.ts" } },
		];
		guard.recordTurn({ message: assistantTurn(warned), toolResults: [] });
		expect(guard.recordTurn({ message: assistantTurn(warned), toolResults: [] })).toMatchObject({ count: 2 });

		const first: ToolCall = { type: "toolCall", id: "prepared-bash", name: "bash", arguments: { command: "pwd" } };
		const second: ToolCall = { type: "toolCall", id: "prepared-read", name: "read", arguments: { path: "a.ts" } };
		guard.recordDispatchedArgs(first.id, { command: "pwd" });
		expect(guard.hasAllDispatchedArgs([first, second])).toBe(false);
		// The later call's extension repair changes what actually dispatches.
		guard.recordDispatchedArgs(second.id, { path: "repaired.ts" });
		expect(guard.hasAllDispatchedArgs([first, second])).toBe(true);
		expect(guard.blockedRepeatedBatch([first, second])).toBeNull();

		// Without a repair the fully prepared identical batch still hard-stops.
		const plainFirst: ToolCall = { type: "toolCall", id: "plain-bash", name: "bash", arguments: { command: "pwd" } };
		const plainSecond: ToolCall = { type: "toolCall", id: "plain-read", name: "read", arguments: { path: "a.ts" } };
		guard.recordDispatchedArgs(plainFirst.id, { command: "pwd" });
		guard.recordDispatchedArgs(plainSecond.id, { path: "a.ts" });
		expect(guard.blockedRepeatedBatch([plainFirst, plainSecond])).toMatchObject({ toolName: "bash", count: 2 });
	});
});
