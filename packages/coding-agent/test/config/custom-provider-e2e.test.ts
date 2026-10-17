import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { YAML } from "bun";
import { AuthStorage } from "@rva/ai";
import { postOpenAIStream } from "@rva/ai/utils/openai-http";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import { Settings } from "@rva/coding-agent/config/settings";
import { saveCustomProvider } from "@rva/coding-agent/config/custom-provider-writer";
import { CustomProviderWizard, type CustomProviderWizardOutput } from "@rva/tui/overlays/custom-provider-wizard";

describe("custom provider e2e wizard + loopback agent call", () => {
	test("wizard saves config and credentials, reloads registry, and authorizes real loopback request", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-e2e-provider-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelsYmlPath = path.join(tempDir, "models.yml");
		const modelRegistry = new ModelRegistry(authStorage, modelsYmlPath);
		const settings = await Settings.init({ cwd: tempDir, agentDir: tempDir });

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
			let completedConfig: CustomProviderWizardOutput | null = null;
			let cancelled = false;
			const completion = Promise.withResolvers<CustomProviderWizardOutput>();

			const wizard = new CustomProviderWizard(
				{
					existingProviderIds: modelRegistry.getAll().map(m => m.provider),
				},
				async config => {
					completedConfig = config;
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

			// Step 5: Model ID
			wizard.handleInput("loopback-model-1");
			wizard.handleInput("\n");

			// Step 6: Model Name
			wizard.handleInput("My Loopback Model");
			wizard.handleInput("\n");

			// Step 7: Context Window
			wizard.handleInput("128000");
			wizard.handleInput("\n");

			// Step 8: Max Tokens
			wizard.handleInput("4096");
			wizard.handleInput("\n");

			// Step 9: Add another? Select first option ("Save provider")
			wizard.handleInput("\n");

			// Step 10: Confirm step -> press Enter to finalize save
			wizard.handleInput("\n");

			// Await completion promise
			const finalConfig = await completion.promise;
			expect(cancelled).toBe(false);
			expect(finalConfig.providerId).toBe("my-loopback-gateway");
			expect(finalConfig.models[0].id).toBe("loopback-model-1");
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
			expect(
				availableModels.some(m => m.provider === "my-loopback-gateway" && m.id === "loopback-model-1"),
			).toBe(true);

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
				{},
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
});
