import { describe, expect, it } from "bun:test";
import { serializeConversation } from "@reverse/agent/compaction/utils";
import type { Message } from "@reverse/ai";

describe("serializeConversation", () => {
	it("truncates long tool results in serialized summaries", () => {
		const longContent = "x".repeat(5000);
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "read",
				content: [{ type: "text", text: longContent }],
				isError: false,
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).toContain("[Tool Result]:");
		expect(result).toContain("[... 3000 more characters truncated]");
		expect(result).toContain("x".repeat(2000));
		expect(result).not.toContain("x".repeat(3000));
	});
	it("retains artifact and evidence references from the tail of long tool results", () => {
		const longContent = `${"x".repeat(5000)}\nFull output: artifact://session/r2-1\nEvidence: ev_fact_abc123`;
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "r2_inspect",
				content: [{ type: "text", text: longContent }],
				isError: false,
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).toContain("artifact://session/r2-1");
		expect(result).toContain("ev_fact_abc123");
		expect(result).toContain("characters truncated");
	});

	it("does not truncate short tool results", () => {
		const shortContent = "x".repeat(1500);
		const messages: Message[] = [
			{
				role: "toolResult",
				toolCallId: "tc1",
				toolName: "read",
				content: [{ type: "text", text: shortContent }],
				isError: false,
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).toBe(`[Tool Result]: ${shortContent}`);
		expect(result).not.toContain("truncated");
	});

	it("does not truncate assistant or user messages", () => {
		const longText = "y".repeat(5000);
		const messages: Message[] = [
			{
				role: "user",
				content: [{ type: "text", text: longText }],
				timestamp: Date.now(),
			},
			{
				role: "assistant",
				content: [{ type: "text", text: longText }],
				api: "anthropic",
				provider: "anthropic",
				model: "test",
				usage: {
					input: 0,
					output: 0,
					cacheRead: 0,
					cacheWrite: 0,
					totalTokens: 0,
					cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
				},
				stopReason: "stop",
				timestamp: Date.now(),
			},
		];

		const result = serializeConversation(messages);

		expect(result).not.toContain("truncated");
		expect(result).toContain(longText);
	});
});
