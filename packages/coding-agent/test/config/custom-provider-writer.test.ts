import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { YAML } from "bun";
import { AuthStorage } from "@rva/ai";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import {
	saveCustomProvider,
	validateCustomProviderInput,
} from "@rva/coding-agent/config/custom-provider-writer";

describe("custom-provider-writer", () => {
	test("validateCustomProviderInput rejects invalid inputs", () => {
		expect(
			validateCustomProviderInput({
				providerId: "",
				baseUrl: "https://api.example.com",
				api: "openai-completions",
				models: [{ id: "m1" }],
			}),
		).toBe("Provider ID is required.");

		expect(
			validateCustomProviderInput({
				providerId: "bad id with space",
				baseUrl: "https://api.example.com",
				api: "openai-completions",
				models: [{ id: "m1" }],
			}),
		).toMatch(/Provider ID must start with/);

		expect(
			validateCustomProviderInput({
				providerId: "my-provider",
				baseUrl: "ftp://invalid",
				api: "openai-completions",
				models: [{ id: "m1" }],
			}),
		).toBe("Base URL must start with http:// or https://.");

		expect(
			validateCustomProviderInput({
				providerId: "my-provider",
				baseUrl: "https://api.example.com",
				api: "openai-completions",
				models: [],
			}),
		).toBe("At least one model must be defined.");

		expect(
			validateCustomProviderInput({
				providerId: "my-provider",
				baseUrl: "https://api.example.com",
				api: "openai-completions",
				models: [{ id: "m1", contextWindow: 100, maxTokens: 200 }],
			}),
		).toBe("Model m1: maxTokens cannot be larger than contextWindow.");
	});

	test("saves provider to models.yml without secret, stores secret in AuthStorage", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-custom-provider-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir, "models.yml"));

		try {
			const result = await saveCustomProvider(
				{
					providerId: "test-gateway",
					baseUrl: "https://gateway.example.com/v1",
					api: "openai-completions",
					apiKey: "sk-super-secret-key-12345",
					models: [
						{ id: "model-a", name: "Model A", contextWindow: 128000, maxTokens: 4096 },
						{ id: "model-b", name: "Model B", contextWindow: 64000, maxTokens: 2048 },
					],
				},
				{
					agentDir: tempDir,
					authStorage,
					modelRegistry,
				},
			);

			expect(result.providerId).toBe("test-gateway");
			expect(result.keyless).toBe(false);
			expect(result.modelCount).toBe(2);

			// Check models.yml content
			const ymlContent = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");
			expect(ymlContent).not.toContain("sk-super-secret-key-12345");
			const parsed = YAML.parse(ymlContent) as Record<string, any>;
			expect(parsed.providers["test-gateway"]).toBeDefined();
			expect(parsed.providers["test-gateway"].baseUrl).toBe("https://gateway.example.com/v1");
			expect(parsed.providers["test-gateway"].api).toBe("openai-completions");
			expect(parsed.providers["test-gateway"].models).toHaveLength(2);
			expect(parsed.providers["test-gateway"].models[0].id).toBe("model-a");

			// Check AuthStorage (agent.db)
			const cred = authStorage.credentials.get("test-gateway");
			expect(cred).toBeDefined();
			expect(cred?.type).toBe("api_key");
			if (cred?.type === "api_key") {
				expect(cred.key).toBe("sk-super-secret-key-12345");
				expect(cred.source).toBe("login");
			}

			// Check ModelRegistry finds the model immediately
			const found = modelRegistry.find("test-gateway", "model-a");
			expect(found).toBeDefined();
			expect(found?.id).toBe("model-a");
			expect(found?.provider).toBe("test-gateway");
			expect(found?.api).toBe("openai-completions");

			// Check availability passes
			const available = modelRegistry.getAvailable("chat");
			expect(available.some(m => m.provider === "test-gateway" && m.id === "model-a")).toBe(true);
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("saves keyless provider with auth: none", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-custom-keyless-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir, "models.yml"));

		try {
			const result = await saveCustomProvider(
				{
					providerId: "local-vllm",
					baseUrl: "http://127.0.0.1:8000/v1",
					api: "openai-completions",
					models: [{ id: "llama-3-8b" }],
				},
				{
					agentDir: tempDir,
					authStorage,
					modelRegistry,
				},
			);

			expect(result.keyless).toBe(true);
			const ymlContent = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");
			const parsed = YAML.parse(ymlContent) as Record<string, any>;
			expect(parsed.providers["local-vllm"].auth).toBe("none");

			// AuthStorage has no credentials
			expect(authStorage.credentials.has("local-vllm")).toBe(false);

			// Keyless provider is available
			const found = modelRegistry.find("local-vllm", "llama-3-8b");
			expect(found).toBeDefined();
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("rejects duplicate provider ID and preserves existing configuration", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-duplicate-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));

		try {
			await saveCustomProvider(
				{
					providerId: "my-gateway",
					baseUrl: "https://gateway.example.com/v1",
					api: "openai-completions",
					apiKey: "key-1",
					models: [{ id: "model-1" }],
				},
				{
					agentDir: tempDir,
					authStorage,
				},
			);

			const originalYml = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");

			// Attempt duplicate with same case or different case
			await expect(
				saveCustomProvider(
					{
						providerId: "MY-GATEWAY",
						baseUrl: "https://other.example.com",
						api: "openai-completions",
						models: [{ id: "model-2" }],
					},
					{
						agentDir: tempDir,
						authStorage,
					},
				),
			).rejects.toThrow(/already exists in configuration/);

			// Confirm original content untouched
			expect(fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8")).toBe(originalYml);
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("refuses to overwrite broken existing models file", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-broken-file-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const brokenPath = path.join(tempDir, "models.yml");
		fs.writeFileSync(brokenPath, "providers: { invalid_yaml [broken", "utf-8");

		try {
			await expect(
				saveCustomProvider(
					{
						providerId: "new-p",
						baseUrl: "https://example.com/v1",
						api: "openai-completions",
						models: [{ id: "m" }],
					},
					{
						agentDir: tempDir,
						authStorage,
					},
				),
			).rejects.toThrow(/Cannot modify.*syntax or schema errors/);

			expect(fs.readFileSync(brokenPath, "utf-8")).toBe("providers: { invalid_yaml [broken");
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
