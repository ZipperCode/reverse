import { describe, expect, test } from "bun:test";
import { getBundledModelReferenceIndex } from "@reverse/catalog/identity";
import {
	DiscoveryHttpError,
	fetchDiscoveredProviderModels,
	isDiscoveryAuthRejection,
} from "@reverse/coding-agent/config/model-discovery";

interface CapturedRequest {
	url: string;
	headers: Headers;
}

interface DiscoveryTestServer {
	baseUrl: string;
	requests: CapturedRequest[];
	stop: () => Promise<void>;
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json" },
	});
}

function startServer(
	handler: (request: Request, captured: CapturedRequest) => Response | Promise<Response>,
): DiscoveryTestServer {
	const requests: CapturedRequest[] = [];
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(request) {
			const captured = { url: request.url, headers: request.headers };
			requests.push(captured);
			return handler(request, captured);
		},
	});
	return {
		baseUrl: `http://127.0.0.1:${server.port}`,
		requests,
		stop: async () => {
			await server.stop(true);
		},
	};
}

async function withServer<T>(
	handler: (request: Request, captured: CapturedRequest) => Response | Promise<Response>,
	run: (server: DiscoveryTestServer) => Promise<T>,
): Promise<T> {
	const server = startServer(handler);
	try {
		return await run(server);
	} finally {
		await server.stop();
	}
}

describe("fetchDiscoveredProviderModels", () => {
	test("configured custom authentication headers override protocol auth case-insensitively", async () => {
		await withServer(
			request =>
				request.headers.get("authorization") === "Token custom-secret" &&
				request.headers.get("x-team") === "local-team"
					? jsonResponse({ data: [{ id: "team/model" }] })
					: new Response("Unauthorized", { status: 401 }),
			async server => {
				const models = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
					apiKey: "default-secret",
					headers: { Authorization: "Token custom-secret", "X-Team": "local-team" },
				});
				expect(models.map(model => model.id)).toEqual(["team/model"]);
			},
		);
	});

	test("OpenAI discovery calls /v1/models with Bearer auth and reports endpoint metadata", async () => {
		await withServer(
			() =>
				jsonResponse({
					data: [
						{
							id: "vendor/meta-chat",
							display_name: "Meta Chat",
							context_length: 131_072,
							max_completion_tokens: 8_192,
							architecture: { input_modalities: ["text", "image"] },
						},
						{ id: "vendor/plain" },
					],
				}),
			async server => {
				const models = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
					apiKey: "sk-loopback-secret",
				});

				expect(server.requests).toHaveLength(1);
				const [request] = server.requests;
				expect(new URL(request.url).pathname).toBe("/v1/models");
				expect(request.headers.get("authorization")).toBe("Bearer sk-loopback-secret");
				expect(request.headers.get("x-api-key")).toBeNull();
				expect(request.headers.get("accept")).toBe("application/json");

				const [chat, plain] = models;
				expect(chat).toMatchObject({
					id: "vendor/meta-chat",
					name: "Meta Chat",
					contextWindow: 131_072,
					contextSource: "endpoint",
					maxTokens: 8_192,
					maxTokensSource: "endpoint",
					input: ["text", "image"],
				});

				expect(plain.id).toBe("vendor/plain");
				expect(plain.name).toBe("vendor/plain");
				expect(plain.contextWindow).toBeUndefined();
				expect(plain.contextSource).toBeUndefined();
				expect(plain.maxTokens).toBeUndefined();
				expect(plain.maxTokensSource).toBeUndefined();
				expect(plain.input).toBeUndefined();
				expect(plain.reasoning).toBeUndefined();
			},
		);
	});

	test("Anthropic discovery targets /v1/models from the root with x-api-key only", async () => {
		await withServer(
			() => jsonResponse({ data: [{ id: "claude-local-proxy", display_name: "Local Claude" }] }),
			async server => {
				const withKey = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "anthropic-messages",
					apiKey: "sk-ant-loopback",
				});

				const [first] = server.requests;
				expect(new URL(first.url).pathname).toBe("/v1/models");
				expect(first.headers.get("x-api-key")).toBe("sk-ant-loopback");
				expect(first.headers.get("anthropic-version")).toBe("2023-06-01");
				expect(first.headers.get("authorization")).toBeNull();
				expect(withKey).toHaveLength(1);
				expect(withKey[0]).toMatchObject({
					id: "claude-local-proxy",
					name: "Local Claude",
					contextWindow: undefined,
					maxTokens: undefined,
					contextSource: undefined,
					maxTokensSource: undefined,
					input: undefined,
				});

				// A base URL that already carries /v1 must not produce /v1/v1/models,
				// and keyless discovery still sends the mandatory Anthropic version.
				const withoutKey = await fetchDiscoveredProviderModels({
					baseUrl: `${server.baseUrl}/v1`,
					api: "anthropic-messages",
				});
				const second = server.requests[1];
				expect(second).toBeDefined();
				expect(new URL(second.url).pathname).toBe("/v1/models");
				expect(second.headers.get("x-api-key")).toBeNull();
				expect(second.headers.get("authorization")).toBeNull();
				expect(second.headers.get("anthropic-version")).toBe("2023-06-01");
				expect(withoutKey.map(model => model.id)).toEqual(["claude-local-proxy"]);
			},
		);
	});

	test("exact catalog fallback fills missing metadata while endpoint overrides stay per-field and non-exact IDs stay unknown", async () => {
		await withServer(
			() =>
				jsonResponse({
					data: [{ id: "gpt-4o" }, { id: "gpt-4o-mini", max_output_tokens: 4_096 }, { id: "proxy/gpt-4o" }],
				}),
			async server => {
				const models = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
				});

				const references = getBundledModelReferenceIndex().exact;
				const exactReference = references.get("gpt-4o");
				const mixedReference = references.get("gpt-4o-mini");
				expect(exactReference).toBeDefined();
				expect(mixedReference).toBeDefined();

				const [exact, mixed, unmatched] = models;
				expect(exact).toMatchObject({
					id: "gpt-4o",
					name: exactReference?.name,
					contextWindow: exactReference?.contextWindow,
					contextSource: "catalog",
					maxTokens: exactReference?.maxTokens,
					maxTokensSource: "catalog",
					input: exactReference?.input,
					reasoning: exactReference?.reasoning,
				});

				expect(mixed).toMatchObject({
					id: "gpt-4o-mini",
					name: mixedReference?.name,
					contextWindow: mixedReference?.contextWindow,
					contextSource: "catalog",
					maxTokens: 4_096,
					maxTokensSource: "endpoint",
					input: mixedReference?.input,
				});

				expect(unmatched.id).toBe("proxy/gpt-4o");
				expect(unmatched.name).toBe("proxy/gpt-4o");
				expect(unmatched.contextWindow).toBeUndefined();
				expect(unmatched.contextSource).toBeUndefined();
				expect(unmatched.maxTokens).toBeUndefined();
				expect(unmatched.maxTokensSource).toBeUndefined();
				expect(unmatched.input).toBeUndefined();
				expect(unmatched.reasoning).toBeUndefined();
			},
		);
	});

	test("duplicate IDs are emitted once", async () => {
		await withServer(
			() =>
				jsonResponse({
					data: [
						{ id: "dup-model", name: "First", context_length: 4_096, max_output_tokens: 512 },
						{ id: "dup-model", name: "Second", context_length: 8_192, max_output_tokens: 1_024 },
					],
				}),
			async server => {
				const models = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
				});

				expect(models).toHaveLength(1);
				expect(models.map(model => model.id)).toEqual(["dup-model"]);
			},
		);
	});

	test("limits-context is the safe sum of endpoint input and output tokens", async () => {
		await withServer(
			() =>
				jsonResponse({
					data: [
						{
							id: "limit-sum-model",
							limits: { max_input_tokens: 1_000_000, max_output_tokens: 64_000 },
						},
						{
							id: "unsafe-limit-sum",
							limits: { max_input_tokens: Number.MAX_SAFE_INTEGER, max_output_tokens: 2 },
						},
					],
				}),
			async server => {
				const [model, unsafeSum] = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
				});

				expect(model).toMatchObject({
					id: "limit-sum-model",
					contextWindow: 1_064_000,
					contextSource: "endpoint",
					maxTokens: 64_000,
					maxTokensSource: "endpoint",
				});
				expect(unsafeSum.id).toBe("unsafe-limit-sum");
				expect(unsafeSum.contextWindow).toBeUndefined();
				expect(unsafeSum.contextSource).toBeUndefined();
				expect(unsafeSum.maxTokens).toBe(2);
				expect(unsafeSum.maxTokensSource).toBe("endpoint");
			},
		);
	});

	test("provenance stays per-field when only context comes from the endpoint", async () => {
		await withServer(
			() => jsonResponse({ data: [{ id: "gpt-4o", context_length: 64_000 }] }),
			async server => {
				const reference = getBundledModelReferenceIndex().exact.get("gpt-4o");
				expect(reference).toBeDefined();
				const [model] = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
				});

				expect(model).toMatchObject({
					id: "gpt-4o",
					name: reference?.name,
					contextWindow: 64_000,
					contextSource: "endpoint",
					maxTokens: reference?.maxTokens,
					maxTokensSource: "catalog",
				});
			},
		);
	});

	test("Anthropic follows has_more pagination on the same origin with the same auth", async () => {
		await withServer(
			request => {
				const url = new URL(request.url);
				if (url.searchParams.get("after_id") === "page-a") {
					return jsonResponse({
						data: [{ id: "page-b", display_name: "Page B" }],
						has_more: false,
					});
				}
				return jsonResponse({
					data: [{ id: "page-a", display_name: "Page A" }],
					has_more: true,
					last_id: "page-a",
				});
			},
			async server => {
				const models = await fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "anthropic-messages",
					apiKey: "sk-ant-paged",
				});

				expect(models.map(model => model.id)).toEqual(["page-a", "page-b"]);
				expect(server.requests).toHaveLength(2);
				for (const request of server.requests) {
					const url = new URL(request.url);
					expect(url.origin).toBe(new URL(server.baseUrl).origin);
					expect(url.pathname).toBe("/v1/models");
					expect(request.headers.get("x-api-key")).toBe("sk-ant-paged");
					expect(request.headers.get("anthropic-version")).toBe("2023-06-01");
					expect(request.headers.get("authorization")).toBeNull();
				}
				expect(new URL(server.requests[1].url).searchParams.get("after_id")).toBe("page-a");
			},
		);
	});

	test("Anthropic pagination rejects a non-progressing cursor instead of returning a partial list", async () => {
		let page = 0;
		await withServer(
			() => {
				page += 1;
				return jsonResponse({
					data: [{ id: `page-${page}` }],
					has_more: true,
					last_id: "stuck-cursor",
				});
			},
			async server => {
				let failure: unknown;
				try {
					await fetchDiscoveredProviderModels({
						baseUrl: server.baseUrl,
						api: "anthropic-messages",
						apiKey: "sk-ant-stuck",
					});
				} catch (error) {
					failure = error;
				}

				expect(failure).toBeInstanceOf(Error);
				expect((failure as Error).message).toMatch(/cursor/i);
				expect(server.requests.length).toBeGreaterThan(1);
				expect(server.requests.length).toBeLessThanOrEqual(3);
				expect(new URL(server.requests[0].url).searchParams.get("after_id")).toBeNull();
				for (const request of server.requests.slice(1)) {
					expect(new URL(request.url).searchParams.get("after_id")).toBe("stuck-cursor");
				}
			},
		);
	});

	test("empty and malformed payloads fail deterministically", async () => {
		const payloads = [
			jsonResponse({ data: [] }),
			jsonResponse({ data: [null, { name: "missing-id" }, { id: "   " }] }),
		];
		await withServer(
			() => payloads.shift() ?? jsonResponse({ data: [] }),
			async server => {
				await expect(
					fetchDiscoveredProviderModels({ baseUrl: server.baseUrl, api: "openai-completions" }),
				).rejects.toThrow("The endpoint returned 0 models.");
				await expect(
					fetchDiscoveredProviderModels({ baseUrl: server.baseUrl, api: "openai-completions" }),
				).rejects.toThrow("No valid model entries found in endpoint response.");
			},
		);
	});

	test("auth rejection surfaces the HTTP status", async () => {
		await withServer(
			() => jsonResponse({ error: { message: "unauthorized" } }, 401),
			async server => {
				let failure: unknown;
				try {
					await fetchDiscoveredProviderModels({
						baseUrl: server.baseUrl,
						api: "openai-completions",
						apiKey: "wrong-key",
					});
				} catch (error) {
					failure = error;
				}

				expect(failure).toBeInstanceOf(DiscoveryHttpError);
				const httpError = failure as DiscoveryHttpError;
				expect(httpError.status).toBe(401);
				expect(httpError.message).toContain(server.baseUrl);
				expect(isDiscoveryAuthRejection(httpError)).toBe(true);
			},
		);
	});

	test("a custom timeout aborts a stalled discovery request", async () => {
		await withServer(
			() => new Promise<Response>(() => {}),
			async server => {
				let failure: unknown;
				try {
					await fetchDiscoveredProviderModels({
						baseUrl: server.baseUrl,
						api: "openai-completions",
						timeoutMs: 25,
					});
				} catch (error) {
					failure = error;
				}
				expect(failure).toBeInstanceOf(DOMException);
				expect((failure as DOMException).name).toBe("TimeoutError");
				expect(server.requests).toHaveLength(1);
			},
		);
	});

	test("an external signal cancels an in-flight request", async () => {
		let notifyStarted: (() => void) | undefined;
		const started = new Promise<void>(resolve => {
			notifyStarted = resolve;
		});
		await withServer(
			() => {
				notifyStarted?.();
				return new Promise<Response>(() => {});
			},
			async server => {
				const controller = new AbortController();
				const pending = fetchDiscoveredProviderModels({
					baseUrl: server.baseUrl,
					api: "openai-completions",
					signal: controller.signal,
				});
				await started;
				controller.abort();

				let failure: unknown;
				try {
					await pending;
				} catch (error) {
					failure = error;
				}
				expect(failure).toBeInstanceOf(DOMException);
				expect((failure as DOMException).name).toBe("AbortError");
				expect(server.requests).toHaveLength(1);
			},
		);
	});
});
