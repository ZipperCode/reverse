import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { YAML } from "bun";
import { AuthStorage } from "@reverse/ai";
import { postOpenAIStream } from "@reverse/ai/utils/openai-http";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { fetchDiscoveredProviderModels } from "@reverse/coding-agent/config/model-discovery";
import { Settings } from "@reverse/coding-agent/config/settings";
import { saveCustomProvider } from "@reverse/coding-agent/config/custom-provider-writer";
import { CustomProviderWizard, type CustomProviderWizardOutput } from "@reverse/tui/overlays/custom-provider-wizard";

describe("custom provider e2e wizard + loopback agent call", () => {
	test("wizard saves config and credentials, reloads registry, and authorizes real loopback request", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-e2e-provider-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelsYmlPath = path.join(tempDir, "models.yml");
		const modelRegistry = new ModelRegistry(authStorage, modelsYmlPath);
		const _settings = await Settings.init({ cwd: tempDir, agentDir: tempDir });

		let capturedAuthHeader: string = "";
		let receivedPrompt: string = "";

		// 1. Start local loopback test server
		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(request) {
				const url = new URL(request.url);
				capturedAuthHeader = request.headers.get("authorization") ?? "";

				if (capturedAuthHeader !== "Bearer loopback-secret-token-xyz") {
					return new Response("Unauthorized", { status: 401 });
				}
				if (url.pathname.endsWith("/models")) {
					return Response.json({
						object: "list",
						data: [
							{
								id: "loopback-model-1",
								display_name: "Loopback Model 1",
								context_length: 128_000,
								max_output_tokens: 4_096,
							},
							{
								id: "loopback-model-2",
								display_name: "Loopback Model 2",
								context_length: 64_000,
								max_output_tokens: 2_048,
							},
						],
					});
				}

				if (url.pathname.endsWith("/chat/completions")) {
					const body = (await request.json()) as { messages?: Array<{ content?: string }> };
					receivedPrompt = body.messages?.[0]?.content ?? "";
					const chunk = {
						id: "chatcmpl-test",
						object: "chat.completion.chunk",
						created: Date.now(),
						model: "loopback-model-1",
						choices: [{ index: 0, delta: { content: "pong from custom provider" }, finish_reason: null }],
					};
					const doneChunk = {
						id: "chatcmpl-test",
						object: "chat.completion.chunk",
						created: Date.now(),
						model: "loopback-model-1",
						choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
					};
					return new Response(
						`data: ${JSON.stringify(chunk)}\n\ndata: ${JSON.stringify(doneChunk)}\n\ndata: [DONE]\n\n`,
						{
							headers: { "content-type": "text/event-stream" },
						},
					);
				}
				return new Response("Not found", { status: 404 });
			},
		});

		try {
			// 2. Drive the CustomProviderWizard
			let _completedConfig: CustomProviderWizardOutput | null = null;
			let cancelled = false;
			const completion = Promise.withResolvers<CustomProviderWizardOutput>();

			const wizard = new CustomProviderWizard(
				{
					existingProviderIds: modelRegistry.getAll().map(m => m.provider),
					fetchModels: opts => fetchDiscoveredProviderModels(opts),
				},
				async config => {
					_completedConfig = config;
					try {
						await saveCustomProvider(
							{
								providerId: config.providerId,
								baseUrl: config.baseUrl,
								api: config.api,
								apiKey: config.apiKey,
								models: config.models,
							},
							{
								authStorage,
								modelRegistry,
								agentDir: tempDir,
							},
						);
						completion.resolve(config);
					} catch (err) {
						completion.reject(err);
					}
				},
				() => {
					cancelled = true;
				},
			);

			// Step 1: Provider ID
			wizard.handleInput("my-loopback-gateway");
			wizard.handleInput("\n");

			// Step 2: API Protocol (select first: openai-completions)
			wizard.handleInput("\n");

			// Step 3: Base URL
			wizard.handleInput(`http://127.0.0.1:${server.port}/v1`);
			wizard.handleInput("\n");

			// Step 4: API Key (masked)
			wizard.handleInput("loopback-secret-token-xyz");
			wizard.handleInput("\n");
			// Step 4 submitted -> triggers fetch -> advances to Step 5 (selectModels)
			await Bun.sleep(50);

			const selectScreen = wizard
				.render(80)
				.map(line => Bun.stripANSI(line))
				.join("\n");
			expect(selectScreen).toContain("Step 5: Select Models");
			expect(selectScreen).toContain("loopback-model-1");
			expect(selectScreen).toContain("loopback-model-2");

			// Confirm selection (Enter) -> advances to Step 6 (confirm)
			wizard.handleInput("\n");

			// Confirm step (Enter) -> saves provider
			wizard.handleInput("\n");

			// Await completion promise
			const finalConfig = await completion.promise;
			expect(cancelled).toBe(false);
			expect(finalConfig.providerId).toBe("my-loopback-gateway");
			expect(finalConfig.models).toHaveLength(2);
			expect(finalConfig.models[0].id).toBe("loopback-model-1");
			expect(finalConfig.models[1].id).toBe("loopback-model-2");
			// 3. Verify models.yml on disk (NO secret plain text)
			const ymlText = fs.readFileSync(modelsYmlPath, "utf-8");
			expect(ymlText).not.toContain("loopback-secret-token-xyz");
			const parsedYml = YAML.parse(ymlText) as {
				providers: Record<string, { baseUrl: string; api: string; auth: string; apiKey?: string }>;
			};
			expect(parsedYml.providers["my-loopback-gateway"]).toBeDefined();
			expect(parsedYml.providers["my-loopback-gateway"].baseUrl).toBe(`http://127.0.0.1:${server.port}/v1`);
			expect(parsedYml.providers["my-loopback-gateway"].api).toBe("openai-completions");
			expect(parsedYml.providers["my-loopback-gateway"].auth).toBe("apiKey");
			expect(parsedYml.providers["my-loopback-gateway"].apiKey).toBeUndefined();

			// 4. Verify SQLite AuthStorage (agent.db)
			const cred = authStorage.credentials.get("my-loopback-gateway");
			expect(cred).toBeDefined();
			expect(cred?.type).toBe("api_key");
			if (cred?.type === "api_key") {
				expect(cred.key).toBe("loopback-secret-token-xyz");
				expect(cred.source).toBe("login");
			}

			// 5. Verify live modelRegistry without restart
			const foundModel = modelRegistry.find("my-loopback-gateway", "loopback-model-1");
			expect(foundModel).toBeDefined();
			expect(foundModel?.id).toBe("loopback-model-1");
			expect(foundModel?.provider).toBe("my-loopback-gateway");

			// Available in chat scope
			const availableModels = modelRegistry.getAvailable("chat");
			expect(availableModels.some(m => m.provider === "my-loopback-gateway" && m.id === "loopback-model-1")).toBe(
				true,
			);

			// 6. Real agent loopback call with resolved credentials
			const resolvedKey = await modelRegistry.getApiKeyForProvider("my-loopback-gateway");
			expect(resolvedKey).toBe("loopback-secret-token-xyz");

			const streamHandle = await postOpenAIStream<{ choices: Array<{ delta: { content?: string } }> }>({
				url: `http://127.0.0.1:${server.port}/v1/chat/completions`,
				headers: {
					Authorization: `Bearer ${resolvedKey}`,
				},
				body: {
					model: "loopback-model-1",
					messages: [{ role: "user", content: "hello rev agent" }],
				},
				signal: AbortSignal.timeout(5000),
			});

			let responseContent = "";
			for await (const event of streamHandle.events) {
				const delta = event.choices?.[0]?.delta?.content;
				if (delta) responseContent += delta;
			}

			expect(capturedAuthHeader).toBe("Bearer loopback-secret-token-xyz");
			expect(receivedPrompt).toBe("hello rev agent");
			expect(responseContent).toBe("pong from custom provider");
		} finally {
			server.stop(true);
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("wizard cancellation does not mutate models.yml or credentials", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-cancel-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelsYmlPath = path.join(tempDir, "models.yml");

		try {
			let cancelled = false;
			const wizard = new CustomProviderWizard(
				{
					fetchModels: async () => [],
				},
				() => {},
				() => {
					cancelled = true;
				},
			);

			// Fill step 1
			wizard.handleInput("cancel-me");
			// User presses Esc on step 1
			wizard.handleInput("\x1b");

			expect(cancelled).toBe(true);
			expect(fs.existsSync(modelsYmlPath)).toBe(false);
			expect(authStorage.credentials.has("cancel-me")).toBe(false);
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("wizard renders Chinese labels when zh-CN locale is passed", async () => {
		const wizard = new CustomProviderWizard(
			{
				fetchModels: async () => [
					{
						id: "zh-model-1",
						name: "中文模型 1",
						contextWindow: 128000,
						contextSource: "catalog",
						maxTokens: 4096,
						maxTokensSource: "catalog",
					},
					{
						id: "zh-model-2",
						name: "中文模型 2",
					},
				],
			},
			() => {},
			() => {},
			undefined,
			"zh-CN",
		);

		expect(wizard.title).toBe("添加自定义大模型提供商");
		const renderedStep1 = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(renderedStep1).toContain("第 1 步：提供商标识");
		expect(renderedStep1).toContain("提供商标识 (Provider ID)：");
		expect(renderedStep1).toContain("例如 my-gateway, deepseek, local-vllm");

		// Advance to Step 2
		wizard.handleInput("my-zh-provider");
		wizard.handleInput("\n");
		const renderedStep2 = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(renderedStep2).toContain("第 2 步：选择 API 协议");
		expect(renderedStep2).toContain("OpenAI 新版 Responses 协议");
		expect(renderedStep2).toContain("选择 · ⏎ 确认 · ⎋ 返回");

		// Advance to Step 3
		wizard.handleInput("\n");
		const renderedStep3 = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(renderedStep3).toContain("第 3 步：端点地址");
		expect(renderedStep3).toContain("API 基础端点地址 (Base URL)：");

		// Advance to Step 4
		wizard.handleInput("https://api.zh.example.com/v1");
		wizard.handleInput("\n");
		const renderedStep4 = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(renderedStep4).toContain("第 4 步：API 密钥");
		expect(renderedStep4).toContain("API 密钥（可选）：");
		wizard.handleInput("\n");

		// Step 4 submitted -> advances to Step 5 (selectModels)
		await Bun.sleep(50);
		const renderedStep5 = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(renderedStep5).toContain("第 5 步：选择模型");
		expect(renderedStep5).toContain("中文模型 1");
		expect(renderedStep5).toContain("ctx: 未知 (运行时使用默认值)");
	});

	test("deferred fetch cancellation / restart ignores late completion and prevents overwriting state", async () => {
		const slowFetchDeferred = Promise.withResolvers<any[]>();
		const fastFetchDeferred = Promise.withResolvers<any[]>();
		let fetchCallCount = 0;

		const wizard = new CustomProviderWizard(
			{
				fetchModels: async () => {
					fetchCallCount += 1;
					if (fetchCallCount === 1) {
						return await slowFetchDeferred.promise;
					}
					return await fastFetchDeferred.promise;
				},
			},
			() => {},
			() => {},
		);

		// Step 1: Provider ID
		wizard.handleInput("race-provider");
		wizard.handleInput("\n");
		// Step 2: Protocol
		wizard.handleInput("\n");
		// Step 3: Base URL
		wizard.handleInput("https://first.example.com/v1");
		wizard.handleInput("\n");
		// Step 4: API Key -> starts fetch 1 (slow)
		wizard.handleInput("\n");

		expect(fetchCallCount).toBe(1);
		// Esc cancels slow fetch and returns to Step 4
		wizard.handleInput("\x1b");

		// Change URL to second endpoint
		wizard.handleInput("\x1b"); // Back to Step 3
		wizard.handleInput("https://second.example.com/v1");
		wizard.handleInput("\n");
		wizard.handleInput("\n"); // Step 4 submitted -> starts fetch 2 (fast)

		expect(fetchCallCount).toBe(2);

		// Fast fetch completes with model-b
		fastFetchDeferred.resolve([{ id: "model-b", name: "Model B" }]);
		await Bun.sleep(10);

		// Wizard is now on selectModels with model-b
		const screenAfterFast = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(screenAfterFast).toContain("Step 5: Select Models");
		expect(screenAfterFast).toContain("model-b");

		// Stale slow fetch completes late with model-a
		slowFetchDeferred.resolve([{ id: "stale-model-a", name: "Stale Model A" }]);
		await Bun.sleep(10);

		// Stale result must NOT overwrite active selections
		const screenAfterStale = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(screenAfterStale).toContain("model-b");
		expect(screenAfterStale).not.toContain("stale-model-a");
	});

	test("multi-select requires at least one model before confirming", async () => {
		const wizard = new CustomProviderWizard(
			{
				fetchModels: async () => [{ id: "lone-model", name: "Lone Model" }],
			},
			() => {},
			() => {},
		);

		wizard.handleInput("min-select-p");
		wizard.handleInput("\n");
		wizard.handleInput("\n");
		wizard.handleInput("https://example.com/v1");
		wizard.handleInput("\n");
		wizard.handleInput("\n"); // Enters fetching -> selectModels
		await Bun.sleep(10);

		// Initially lone-model is checked. Press Space to uncheck it.
		wizard.handleInput(" ");
		expect(
			wizard
				.render(80)
				.map(line => Bun.stripANSI(line))
				.join("\n"),
		).toContain("☐ lone-model");
		expect(
			wizard
				.render(80)
				.map(line => Bun.stripANSI(line))
				.join("\n"),
		).toContain("[0/1 selected]");

		// Try to submit with 0 models checked
		wizard.handleInput("\n");

		// Must remain on Step 5 with error
		const screenWithError = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(screenWithError).toContain("Step 5: Select Models");
		expect(screenWithError).toContain("Please select at least one model.");
		expect(screenWithError).not.toContain("Confirm Configuration");

		// Press Space to re-check
		wizard.handleInput(" ");
		expect(
			wizard
				.render(80)
				.map(line => Bun.stripANSI(line))
				.join("\n"),
		).toContain("☑ lone-model");
		expect(
			wizard
				.render(80)
				.map(line => Bun.stripANSI(line))
				.join("\n"),
		).toContain("[1/1 selected]");

		// Now Enter advances to Confirm
		wizard.handleInput("\n");
		const confirmScreen = wizard
			.render(80)
			.map(line => Bun.stripANSI(line))
			.join("\n");
		expect(confirmScreen).toContain("Confirm Configuration");
		expect(confirmScreen).toContain("lone-model");
	});
});
