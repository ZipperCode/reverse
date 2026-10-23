import { describe, expect, it } from "bun:test";
import * as AIError from "../src/error";
import { getBundledModel } from "@reverse/catalog/models";
import { consumeGoogleStream } from "../src/providers/google-shared";
import type { AssistantMessage } from "../src/types";
import { AssistantMessageEventStream } from "../src/utils/event-stream";

function makeAssistantMessage(provider = "google", model = "gemini-3.8-flash"): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: "google-generative-ai",
		provider,
		model,
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
	};
}

describe("Google stream diagnostic & error classification (Issue #11)", () => {
	const model = getBundledModel<"google-generative-ai">("google", "gemini-2.5-flash");
	if (!model) throw new Error("Expected bundled google/gemini-2.5-flash model");

	it("preserves content and labels missing finish reason neutrally without text-based misclassification", async () => {
		const output = makeAssistantMessage();
		const stream = new AssistantMessageEventStream();

		async function* mockStream() {
			yield {
				candidates: [
					{
						content: {
							parts: [{ text: "This request was blocked by Gemini's filters. Please rephrase." }],
						},
					},
				],
			};
		}

		let caught: unknown;
		try {
			await consumeGoogleStream({
				googleStream: mockStream(),
				output,
				stream,
				model,
				options: undefined,
			});
		} catch (error) {
			caught = error;
		}

		expect(caught).toBeInstanceOf(AIError.ProviderResponseError);
		const err = caught as AIError.ProviderResponseError;
		// Must not misclassify as content-blocked purely from prose
		expect(err.kind).toBe("incomplete-stream");
		expect(AIError.is(AIError.classify(err), AIError.Flag.ContentBlocked)).toBe(false);
		expect(AIError.retriable(AIError.classify(err))).toBe(true);
		// Generated content must be preserved
		expect(output.content).toEqual([
			{ type: "text", text: "This request was blocked by Gemini's filters. Please rephrase." },
		]);
		expect(output.errorDiagnostic).toBeDefined();
		expect(output.errorDiagnostic?.normalizedKind).toBe("incomplete-stream");
		expect(output.errorDiagnostic?.retryable).toBe(true);
		// No transport error was observed; transportError must be absent rather than fabricated
		expect(output.errorDiagnostic?.transportError).toBeUndefined();
		expect(output.errorDiagnostic?.rawTerminal).toBeUndefined();
	});

	it("classifies structured SAFETY finishReason as content-blocked with rawTerminal", async () => {
		const output = makeAssistantMessage();
		const stream = new AssistantMessageEventStream();

		async function* mockStream() {
			yield {
				candidates: [
					{
						finishReason: "SAFETY" as const,
						safetyRatings: [{ category: "HARM_CATEGORY_DANGEROUS", probability: "HIGH" }],
					},
				],
			};
		}

		let caught: unknown;
		try {
			await consumeGoogleStream({
				googleStream: mockStream(),
				output,
				stream,
				model,
				options: undefined,
			});
		} catch (error) {
			caught = error;
		}

		expect(caught).toBeInstanceOf(AIError.ProviderResponseError);
		const err = caught as AIError.ProviderResponseError;
		expect(err.kind).toBe("content-blocked");
		expect(AIError.is(AIError.classify(err), AIError.Flag.ContentBlocked)).toBe(true);
		expect(AIError.retriable(AIError.classify(err))).toBe(false);
		expect(output.errorDiagnostic).toBeDefined();
		expect(output.errorDiagnostic?.normalizedKind).toBe("content-blocked");
		expect(output.errorDiagnostic?.retryable).toBe(false);
		expect(output.errorDiagnostic?.rawTerminal?.finishReason).toBe("SAFETY");
	});

	it("classifies promptFeedback.blockReason as content-blocked with rawTerminal", async () => {
		const output = makeAssistantMessage();
		const stream = new AssistantMessageEventStream();

		async function* mockStream() {
			yield {
				promptFeedback: {
					blockReason: "SAFETY",
					blockReasonMessage: "Prompt was flagged by safety filter",
				},
			};
		}

		let caught: unknown;
		try {
			await consumeGoogleStream({
				googleStream: mockStream(),
				output,
				stream,
				model,
				options: undefined,
			});
		} catch (error) {
			caught = error;
		}

		expect(caught).toBeInstanceOf(AIError.ProviderResponseError);
		const err = caught as AIError.ProviderResponseError;
		expect(err.kind).toBe("content-blocked");
		expect(AIError.is(AIError.classify(err), AIError.Flag.ContentBlocked)).toBe(true);
		expect(AIError.retriable(AIError.classify(err))).toBe(false);
		expect(output.errorDiagnostic).toBeDefined();
		expect(output.errorDiagnostic?.normalizedKind).toBe("content-blocked");
		expect(output.errorDiagnostic?.rawTerminal?.blockReason).toBe("SAFETY");
		expect(output.errorDiagnostic?.rawTerminal?.blockReasonMessage).toBe("Prompt was flagged by safety filter");
	});

	it("captures transport error during streaming in transportError diagnostic", async () => {
		const output = makeAssistantMessage();
		const stream = new AssistantMessageEventStream();

		async function* mockStream() {
			yield {
				candidates: [
					{
						content: { parts: [{ text: "Partial reasoning before socket drops..." }] },
					},
				],
			};
			throw new Error("Premature close of HTTP/2 stream");
		}

		let caught: unknown;
		try {
			await consumeGoogleStream({
				googleStream: mockStream(),
				output,
				stream,
				model,
				options: undefined,
			});
		} catch (error) {
			caught = error;
		}

		expect(caught).toBeInstanceOf(AIError.ProviderResponseError);
		const err = caught as AIError.ProviderResponseError;
		expect(err.kind).toBe("incomplete-stream");
		expect(output.errorDiagnostic?.transportError).toBeDefined();
		expect(output.errorDiagnostic?.transportError?.message).toBe("Premature close of HTTP/2 stream");
		expect(output.errorDiagnostic?.retryable).toBe(true);
	});

	it("preserves in-band 401 error as non-retryable GoogleApiError with raw HTTP status", async () => {
		const output = makeAssistantMessage();
		const stream = new AssistantMessageEventStream();

		async function* mockStream() {
			yield {
				error: {
					code: 401,
					status: "UNAUTHENTICATED",
					message: "API key not valid. Please pass a valid API key.",
				},
			};
		}

		let caught: unknown;
		try {
			await consumeGoogleStream({
				googleStream: mockStream(),
				output,
				stream,
				model,
				options: undefined,
			});
		} catch (error) {
			caught = error;
		}

		expect(caught).toBeInstanceOf(AIError.GoogleApiError);
		const err = caught as AIError.GoogleApiError;
		expect(err.status).toBe(401);
		expect(AIError.retriable(AIError.classify(err))).toBe(false);
	});
});
