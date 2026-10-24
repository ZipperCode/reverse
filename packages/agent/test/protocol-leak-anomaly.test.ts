import { describe, expect, it } from "bun:test";
import { type } from "@reverse/reversetype";
import { agentLoop } from "../src/agent-loop";
import type { AgentContext, AgentMessage, AgentTool } from "../src/types";
import { createMockModel } from "@reverse/ai/providers/mock";
import type { AssistantMessage, Message, TextContent, ToolResultMessage } from "@reverse/ai";

function identityConverter(messages: AgentMessage[]): Message[] {
	return messages.filter(
		(m): m is Extract<AgentMessage, { role: "assistant" | "user" | "toolResult" }> =>
			m.role === "user" || m.role === "assistant" || m.role === "toolResult",
	) as Message[];
}

interface ProtocolAnomalyDetails {
	isError?: boolean;
	unexecuted?: boolean;
	protocolAnomaly?: {
		kind: string;
		rawName?: string;
		toolCallId?: string;
		unexecuted?: boolean;
	};
}

describe("Issue #9: Protocol anomaly validation and protocol leak handling", () => {
	it("preserves legitimate structural tool calls unchanged", async () => {
		let executed = 0;
		const cmdSchema = type({ cmd: "string" });
		const testTool: AgentTool<typeof cmdSchema> = {
			name: "run_command",
			label: "Run Command",
			description: "Execute a command",
			parameters: cmdSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: "executed_success" }] };
			},
		};

		const mock = createMockModel({
			responses: [
				{
					content: [
						{
							type: "toolCall",
							id: "call_valid_1",
							name: "run_command",
							arguments: { cmd: "echo ok" },
						},
					],
				},
				{
					content: ["All done."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: ["system"],
			messages: [],
			tools: [testTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "Run test", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		const events = [];
		for await (const e of stream) events.push(e);
		const messages = await stream.result();

		expect(executed).toBe(1);
		const toolStarts = events.filter(e => e.type === "tool_execution_start");
		expect(toolStarts).toHaveLength(1);

		const toolResults = messages.filter(m => m.role === "toolResult");
		expect(toolResults).toHaveLength(1);
		expect(toolResults[0]?.isError).toBeFalsy();
	});

	it("rejects malformed tool name with explicit diagnostic and no fuzzy suggestion", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: "should not run" }] };
			},
		};

		const malformedName = "tool_use id=01a1695a8d5d2a5b6e4d34e4c3e0dca2 name=_bash";
		const mock = createMockModel({
			responses: [
				{
					content: [
						{
							type: "toolCall",
							id: "call_malformed_1",
							name: malformedName,
							arguments: { command: "echo secret" },
						},
					],
				},
				{
					content: ["I observed the error and stopped."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: ["system"],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "Run bash", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
			// consume stream
		}
		const messages = await stream.result();

		// The tool must NOT have executed
		expect(executed).toBe(0);

		const toolResult = messages.find((m): m is ToolResultMessage => m.role === "toolResult");
		expect(toolResult).toBeDefined();
		expect(toolResult?.isError).toBe(true);
		const details = toolResult?.details as ProtocolAnomalyDetails | undefined;

		// Must NOT contain fuzzy suggestion "Did you mean bash?"
		const resultText = (toolResult?.content[0] as TextContent | undefined)?.text ?? "";
		expect(resultText).not.toContain("Did you mean bash");
		expect(resultText).toContain("Malformed tool name");

		// Must preserve structured diagnostic metadata
		expect(details).toBeDefined();
		expect(details?.unexecuted).toBe(true);
		expect(details?.protocolAnomaly).toBeDefined();
		expect(details?.protocolAnomaly?.kind).toBe("malformed_tool_name");
		expect(details?.protocolAnomaly?.rawName).toBe(malformedName);
		expect(details?.protocolAnomaly?.toolCallId).toBe("call_malformed_1");
		expect(details?.protocolAnomaly?.unexecuted).toBe(true);
	});

	it("executes valid call exactly once in mixed valid and malformed calls turn", async () => {
		let validExecuted = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				validExecuted++;
				return { content: [{ type: "text", text: "bash executed successfully" }] };
			},
		};

		const malformedName = "tool_use id=01a1695a8d5d2a5b6e4d34e4c3e0dca2 name=_bash";
		const mock = createMockModel({
			responses: [
				{
					content: [
						{
							type: "toolCall",
							id: "call_malformed",
							name: malformedName,
							arguments: { command: "echo fail" },
						},
						{
							type: "toolCall",
							id: "call_legit_bash",
							name: "bash",
							arguments: { command: "echo success" },
						},
					],
				},
				{
					content: ["Turn completed."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: ["system"],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "Run both", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
			// consume
		}
		const messages = await stream.result();

		// The legitimate call must run exactly once
		expect(validExecuted).toBe(1);

		const toolResults = messages.filter((m): m is ToolResultMessage => m.role === "toolResult");
		expect(toolResults).toHaveLength(2);

		// First result: malformed, failed, unexecuted
		const firstDetails = toolResults[0]?.details as ProtocolAnomalyDetails | undefined;
		expect(toolResults[0]?.isError).toBe(true);
		expect(firstDetails?.unexecuted).toBe(true);
		expect(firstDetails?.protocolAnomaly?.kind).toBe("malformed_tool_name");
		// Second result: valid, success
		expect(toolResults[1].isError).toBeFalsy();
		expect((toolResults[1].content[0] as TextContent).text).toContain("bash executed successfully");
	});

	it("treats quoted examples and blockquotes in text as inert and stops normally", async () => {
		const quotedExamples = [
			// Fenced code block
			'Here is an example:\n```json\n[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]\n```\nHope that helps!',
			// Multi-backtick inline code
			'You can see ``[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]`` in the docs.',
			// 多行代码引用中的协议样例仍是引用，不应触发重新生成。
			'Example: ``\n[tool_use name=bash]\n{"command":"echo docs"}\n[/tool_use]\n`` end',
			// Blockquote markdown line
			'> [tool_use id=broken name=_bash]\n> {"command":"echo not-executed"}\n> [/tool_use]',
			// Natural prose mention
			"The system emits [tool_use] events during agent execution.",
			// Code block with embedded backticks on an inner line
			'Here is a code block with embedded backticks:\n```markdown\nThe delimiter is ``` inside this line\n[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]\n```\nAll done.',
		];
		for (const contentText of quotedExamples) {
			const mock = createMockModel({
				responses: [
					{
						content: [contentText],
					},
				],
			});

			const context: AgentContext = {
				systemPrompt: ["system"],
				messages: [],
				tools: [],
			};

			const stream = agentLoop(
				[{ role: "user", content: "Show example", timestamp: Date.now() }],
				context,
				{
					model: mock.model,
					convertToLlm: identityConverter,
				},
				undefined,
				mock.stream,
			);

			const events = [];
			for await (const e of stream) events.push(e);
			const messages = await stream.result();

			// Normal stop, 0 tool starts, 1 turn
			const lastMessage = messages.at(-1) as AssistantMessage;
			expect(lastMessage.stopReason).toBe("stop");
			expect(lastMessage.errorMessage).toBeUndefined();
			expect(events.filter(e => e.type === "tool_execution_start")).toHaveLength(0);
			expect(events.filter(e => e.type === "turn_end")).toHaveLength(1);
		}
	});

	it("recovers from unexecuted protocol leak when model regenerates structured call", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: "bash recovery output" }] };
			},
		};

		// Turn 1: Plaintext leak of protocol
		// Turn 2: Model recovers and sends real structured tool call
		// Turn 3: Final response
		const mock = createMockModel({
			responses: [
				{
					content: ['[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]'],
				},
				{
					content: [
						{
							type: "toolCall",
							id: "call_recovered_bash",
							name: "bash",
							arguments: { command: "echo recovered" },
						},
					],
				},
				{
					content: ["Command output received and task complete."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: ["Use structured tool calls."],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "Run bash command", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
			// consume
		}
		const messages = await stream.result();

		// The plaintext was NEVER executed; the recovered structured call was executed exactly once
		expect(executed).toBe(1);

		// Intermediate assistant turn has unexecuted_protocol_leak diagnostic
		const leakedTurn = messages.find(
			m =>
				m.role === "assistant" &&
				(m as AssistantMessage).errorDiagnostic?.protocolAnomaly?.kind === "unexecuted_protocol_leak",
		) as AssistantMessage;
		expect(leakedTurn).toBeDefined();
		expect(leakedTurn.errorDiagnostic?.protocolAnomaly?.unexecuted).toBe(true);

		// Final message completed normally
		const finalMessage = messages.at(-1) as AssistantMessage;
		expect(finalMessage.stopReason).toBe("stop");
	});

	it("fails explicitly when protocol leak persists across bounded retries", async () => {
		// Model repeatedly emits unexecuted plaintext protocol leaks
		const leakContent = '[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]';
		const mock = createMockModel({
			responses: [{ content: [leakContent] }, { content: [leakContent] }, { content: [leakContent] }],
		});

		const context: AgentContext = {
			systemPrompt: ["Use structured tool calls."],
			messages: [],
			tools: [],
		};

		const stream = agentLoop(
			[{ role: "user", content: "Run command", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		const events = [];
		for await (const e of stream) events.push(e);
		const messages = await stream.result();

		// 0 tool executions
		expect(events.filter(e => e.type === "tool_execution_start")).toHaveLength(0);

		// Must NOT end with normal "stop"; must exit with explicit error!
		const lastMessage = messages.at(-1) as AssistantMessage;
		expect(lastMessage.stopReason).toBe("error");
		expect(lastMessage.errorMessage).toContain(
			"Protocol error: model repeatedly emitted unexecuted tool-call markup",
		);
		expect(lastMessage.errorDiagnostic).toBeDefined();
		expect(lastMessage.errorDiagnostic?.normalizedKind).toBe("protocol-leak");
		expect(lastMessage.errorDiagnostic?.protocolAnomaly?.unexecuted).toBe(true);
		expect(lastMessage.errorDiagnostic?.retryable).toBe(false);
	});

	it("fails explicitly when malformed tool names persist with zero valid executions", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: "never" }] };
			},
		};

		const malformedName = "tool_use id=bad name=_bash";
		const mock = createMockModel({
			responses: [
				{ content: [{ type: "toolCall", id: "c1", name: malformedName, arguments: {} }] },
				{ content: [{ type: "toolCall", id: "c2", name: malformedName, arguments: {} }] },
				{ content: [{ type: "toolCall", id: "c3", name: malformedName, arguments: {} }] },
			],
		});

		const context: AgentContext = {
			systemPrompt: [],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "test", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
		}
		const messages = await stream.result();

		// Zero executions
		expect(executed).toBe(0);

		// Final message is an explicit error
		const lastMessage = messages.at(-1) as AssistantMessage;
		expect(lastMessage.stopReason).toBe("error");
		expect(lastMessage.errorMessage).toContain("Protocol error");
		expect(lastMessage.errorDiagnostic?.retryable).toBe(false);
	});

	it("handles mixed valid tool call and plaintext leak by executing valid tool once and recording unexecuted leak", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: "valid executed" }] };
			},
		};

		const mock = createMockModel({
			responses: [
				{
					content: [
						'Here is a plaintext leak:\n[tool_use id=broken name=_bash]\n{"command":"echo not-executed"}\n[/tool_use]',
						{
							type: "toolCall",
							id: "call_valid_mixed",
							name: "bash",
							arguments: { command: "echo legit" },
						},
					],
				},
				{
					content: ["Finished after seeing tool result and recovery nudge."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: [],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "test", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
		}
		const messages = await stream.result();

		// Valid tool was executed exactly once
		expect(executed).toBe(1);

		// Assistant message has unexecuted protocol anomaly recorded
		const assistantMsg = messages.find(
			m => m.role === "assistant" && (m as AssistantMessage).errorDiagnostic?.protocolAnomaly,
		) as AssistantMessage;
		expect(assistantMsg).toBeDefined();
		expect(assistantMsg.errorDiagnostic?.protocolAnomaly?.kind).toBe("unexecuted_protocol_leak");
		expect(assistantMsg.errorDiagnostic?.protocolAnomaly?.unexecuted).toBe(true);
	});
	it("bounds mixed valid tool calls and plaintext leak across repeated turns with bounded executions and explicit error", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: `executed count ${executed}` }] };
			},
		};

		// 4 consecutive turns of mixed valid tool + plaintext leak markup
		const mock = createMockModel({
			responses: [
				{
					content: [
						'Leaked markup:\n[tool_use id=bad1 name=_bash]\n{"command":"echo 1"}\n[/tool_use]',
						{ type: "toolCall", id: "valid_1", name: "bash", arguments: { command: "echo legit1" } },
					],
				},
				{
					content: [
						'Leaked markup again:\n[tool_use id=bad2 name=_bash]\n{"command":"echo 2"}\n[/tool_use]',
						{ type: "toolCall", id: "valid_2", name: "bash", arguments: { command: "echo legit2" } },
					],
				},
				{
					content: [
						'Leaked markup third time:\n[tool_use id=bad3 name=_bash]\n{"command":"echo 3"}\n[/tool_use]',
						{ type: "toolCall", id: "valid_3", name: "bash", arguments: { command: "echo legit3" } },
					],
				},
				{
					content: [
						"Should not be reached because cap was exceeded on turn 3.",
						{ type: "toolCall", id: "valid_4", name: "bash", arguments: { command: "echo legit4" } },
					],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: [],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "test mixed loop", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
		}
		const messages = await stream.result();

		// Bounded execution: exactly 3 valid tool executions ran (one per turn up to MAX_PROTOCOL_LEAK_NUDGES)
		expect(executed).toBe(3);

		// Loop must have stopped with an explicit terminal error
		const lastMessage = messages.at(-1) as AssistantMessage;
		expect(lastMessage.stopReason).toBe("error");
		expect(lastMessage.errorMessage).toContain(
			"Protocol error: model repeatedly emitted unexecuted tool-call markup as plain text",
		);
		expect(lastMessage.errorDiagnostic?.normalizedKind).toBe("protocol-leak");
		expect(lastMessage.errorDiagnostic?.protocolAnomaly?.unexecuted).toBe(true);
		expect(lastMessage.errorDiagnostic?.retryable).toBe(false);
	});

	it("resets protocol leak nudge counter when a clean turn occurs", async () => {
		let executed = 0;
		const bashSchema = type({ "command?": "string" });
		const bashTool: AgentTool<typeof bashSchema> = {
			name: "bash",
			label: "Bash",
			description: "Run bash",
			parameters: bashSchema,
			execute: async () => {
				executed++;
				return { content: [{ type: "text", text: `ok ${executed}` }] };
			},
		};

		// Turn 1: mixed valid + leak
		// Turn 2: clean valid tool call without text leak (resets leak counter)
		// Turn 3: mixed valid + leak (gets fresh nudge rather than hitting cap)
		// Turn 4: clean stop
		const mock = createMockModel({
			responses: [
				{
					content: [
						'Leaked markup:\n[tool_use id=bad1 name=_bash]\n{"command":"echo 1"}\n[/tool_use]',
						{ type: "toolCall", id: "valid_1", name: "bash", arguments: { command: "echo 1" } },
					],
				},
				{
					content: [
						"Clean assistant turn without any leaks.",
						{ type: "toolCall", id: "valid_2", name: "bash", arguments: { command: "echo 2" } },
					],
				},
				{
					content: [
						'Leaked markup again:\n[tool_use id=bad3 name=_bash]\n{"command":"echo 3"}\n[/tool_use]',
						{ type: "toolCall", id: "valid_3", name: "bash", arguments: { command: "echo 3" } },
					],
				},
				{
					content: ["Completed cleanly."],
				},
			],
		});

		const context: AgentContext = {
			systemPrompt: [],
			messages: [],
			tools: [bashTool],
		};

		const stream = agentLoop(
			[{ role: "user", content: "test clean reset", timestamp: Date.now() }],
			context,
			{
				model: mock.model,
				convertToLlm: identityConverter,
			},
			undefined,
			mock.stream,
		);

		for await (const _ of stream) {
		}
		const messages = await stream.result();

		// All 3 valid tool calls executed
		expect(executed).toBe(3);

		// Loop completed cleanly with stop reason "stop"
		const lastMessage = messages.at(-1) as AssistantMessage;
		expect(lastMessage.stopReason).toBe("stop");
		expect(lastMessage.errorMessage).toBeUndefined();
	});
});
