import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { YAML } from "bun";
import { AuthStorage } from "@reverse/ai";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import {
	listConfiguredCustomProviders,
	saveCustomProvider,
	updateCustomProviderModels,
	validateCustomModelInputs,
	validateCustomProviderInput,
} from "@reverse/coding-agent/config/custom-provider-writer";

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
	test("listConfiguredCustomProviders discovers configured custom providers, headers, extras, and inferred APIs", () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-list-test-"));
		try {
			const configContent = `
providers:
  custom-gw:
    baseUrl: "https://gw.example.com/v1"
    api: "openai-completions"
    auth: "apiKey"
    headers:
      X-Custom-Env: "{env:MY_KEY}"
    models:
      - id: "m1"
        name: "Model 1"
        contextWindow: 128000
        cost:
          input: 1
          output: 2
          cacheRead: 0.5
          cacheWrite: 1
        tokenizer: "o200k"
  inferred-gw:
    baseUrl: "https://inferred.example.com/v1"
    models:
      - id: "inf-1"
        api: "anthropic-messages"
  bundled-override:
    baseUrl: "https://my-openai-proxy.internal"
    api: "openai-responses"
    models:
      - id: "custom-gpt"
  only-headers-no-models:
    headers:
      X-Some-Header: "val"
  unsupported-api:
    baseUrl: "https://other.example.com"
    api: "azure-openai-responses"
    models:
      - id: "bad"
`;
			fs.writeFileSync(path.join(tempDir, "models.yml"), configContent.trim(), "utf-8");

			const descriptors = listConfiguredCustomProviders(tempDir);
			const byId = new Map(descriptors.map(d => [d.providerId, d]));

			expect(descriptors).toHaveLength(3);

			const customGw = byId.get("custom-gw");
			expect(customGw).toBeDefined();
			expect(customGw?.baseUrl).toBe("https://gw.example.com/v1");
			expect(customGw?.api).toBe("openai-completions");
			expect(customGw?.auth).toBe("apiKey");
			expect(customGw?.headers).toEqual({ "X-Custom-Env": "{env:MY_KEY}" });
			expect(customGw?.models).toHaveLength(1);
			expect(customGw?.models[0].id).toBe("m1");
			expect(customGw?.models[0].name).toBe("Model 1");
			expect(customGw?.models[0].contextWindow).toBe(128000);
			expect(customGw?.models[0].cost).toEqual({ input: 1, output: 2, cacheRead: 0.5, cacheWrite: 1 });
			expect(customGw?.models[0].tokenizer).toBe("o200k");

			const inferredGw = byId.get("inferred-gw");
			expect(inferredGw).toBeDefined();
			expect(inferredGw?.api).toBe("anthropic-messages");
			expect(inferredGw?.models).toHaveLength(1);

			const bundledOverride = byId.get("bundled-override");
			expect(bundledOverride).toBeDefined();
			expect(bundledOverride?.api).toBe("openai-responses");

			expect(byId.has("only-headers-no-models")).toBe(false);
			expect(byId.has("unsupported-api")).toBe(false);
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("updateCustomProviderModels retains provider settings and raw model metadata while adding and deleting models", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-update-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir, "models.yml"));

		try {
			const initialYml = `
providers:
  test-gateway:
    baseUrl: "https://gateway.example.com/v1"
    api: "openai-completions"
    auth: "apiKey"
    headers:
      X-Custom-Header: "custom-val"
    compat:
      supportsDeveloperRole: true
    models:
      - id: "model-1"
        name: "Model One"
        contextWindow: 128000
        cost:
          input: 1
          output: 2
          cacheRead: 0.5
          cacheWrite: 1
        tokenizer: "o200k"
      - id: "model-2"
        name: "Model Two"
        contextWindow: 64000
`;
			fs.writeFileSync(path.join(tempDir, "models.yml"), initialYml.trim(), "utf-8");
			await authStorage.credentials.set("test-gateway", {
				type: "api_key",
				key: "sk-retained-secret-123",
				source: "login",
			});
			await modelRegistry.refresh("offline");

			const result = await updateCustomProviderModels(
				"test-gateway",
				[
					{ id: "model-1", contextWindow: 200000 },
					{ id: "model-3", name: "Model Three", contextWindow: 32000, maxTokens: 4096 },
				],
				{
					agentDir: tempDir,
					authStorage,
					modelRegistry,
				},
			);

			expect(result.providerId).toBe("test-gateway");
			expect(result.modelCount).toBe(2);

			const ymlContent = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");
			const parsed = YAML.parse(ymlContent) as Record<string, unknown>;
			const providers = parsed.providers as Record<string, Record<string, unknown>>;
			const gw = providers["test-gateway"];
			expect(gw).toBeDefined();

			// Retained provider settings
			expect(gw.baseUrl).toBe("https://gateway.example.com/v1");
			expect(gw.api).toBe("openai-completions");
			expect(gw.auth).toBe("apiKey");
			expect(gw.headers).toEqual({ "X-Custom-Header": "custom-val" });
			expect(gw.compat).toEqual({ supportsDeveloperRole: true });

			// Models update verification
			const models = gw.models as Record<string, unknown>[];
			expect(models).toHaveLength(2);

			const m1 = models.find(m => m.id === "model-1");
			expect(m1).toBeDefined();
			expect(m1?.contextWindow).toBe(128000);
			expect(m1?.name).toBe("Model One");
			expect(m1?.cost).toEqual({ input: 1, output: 2, cacheRead: 0.5, cacheWrite: 1 });
			expect(m1?.tokenizer).toBe("o200k");

			const m2 = models.find(m => m.id === "model-2");
			expect(m2).toBeUndefined();

			const m3 = models.find(m => m.id === "model-3");
			expect(m3).toBeDefined();
			expect(m3?.name).toBe("Model Three");
			expect(m3?.contextWindow).toBe(32000);
			expect(m3?.maxTokens).toBe(4096);

			// Retained credentials
			const cred = authStorage.credentials.get("test-gateway");
			expect(cred).toBeDefined();
			if (cred?.type === "api_key") {
				expect(cred.key).toBe("sk-retained-secret-123");
			}

			// Registry reflected changes
			expect(modelRegistry.find("test-gateway", "model-1")).toBeDefined();
			expect(modelRegistry.find("test-gateway", "model-3")).toBeDefined();
			expect(modelRegistry.find("test-gateway", "model-2")).toBeUndefined();
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("updateCustomProviderModels supports removing all models while retaining provider and credentials", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-all-delete-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));
		const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir, "models.yml"));

		try {
			const initialYml = `
providers:
  zero-models-gw:
    baseUrl: "https://empty.example.com/v1"
    api: "openai-completions"
    auth: "apiKey"
    models:
      - id: "m-to-delete"
`;
			fs.writeFileSync(path.join(tempDir, "models.yml"), initialYml.trim(), "utf-8");
			await authStorage.credentials.set("zero-models-gw", {
				type: "api_key",
				key: "sk-keep-this-key",
				source: "login",
			});

			const result = await updateCustomProviderModels("zero-models-gw", [], {
				agentDir: tempDir,
				authStorage,
				modelRegistry,
			});

			expect(result.modelCount).toBe(0);

			const ymlContent = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");
			const parsed = YAML.parse(ymlContent) as Record<string, unknown>;
			const providers = parsed.providers as Record<string, Record<string, unknown>>;
			expect(providers["zero-models-gw"]).toBeDefined();
			expect(providers["zero-models-gw"].baseUrl).toBe("https://empty.example.com/v1");
			expect(providers["zero-models-gw"].models).toEqual([]);

			// Credentials still exist
			const cred = authStorage.credentials.get("zero-models-gw");
			expect(cred).toBeDefined();
			if (cred?.type === "api_key") {
				expect(cred.key).toBe("sk-keep-this-key");
			}

			// Still listed in listConfiguredCustomProviders
			const listed = listConfiguredCustomProviders(tempDir);
			const found = listed.find(p => p.providerId === "zero-models-gw");
			expect(found).toBeDefined();
			expect(found?.models).toEqual([]);
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("updateCustomProviderModels handles omitted provider-level api and promotes inferred api", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-omitted-api-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));

		try {
			const initialYml = `
providers:
  no-api-gw:
    baseUrl: "https://no-api.example.com/v1"
    models:
      - id: "existing-model"
        api: "openai-completions"
`;
			fs.writeFileSync(path.join(tempDir, "models.yml"), initialYml.trim(), "utf-8");

			// Add a newly discovered model that does not have an api field
			const result = await updateCustomProviderModels(
				"no-api-gw",
				[{ id: "existing-model" }, { id: "new-discovered-model", name: "Discovered Model" }],
				{
					agentDir: tempDir,
					authStorage,
				},
			);

			expect(result.modelCount).toBe(2);

			const ymlContent = fs.readFileSync(path.join(tempDir, "models.yml"), "utf-8");
			const parsed = YAML.parse(ymlContent) as Record<string, unknown>;
			const providers = parsed.providers as Record<string, Record<string, unknown>>;
			const gw = providers["no-api-gw"];

			// Provider-level API was promoted from inferred model API
			expect(gw.api).toBe("openai-completions");

			// Existing model API preserved and new model valid
			const models = gw.models as Record<string, unknown>[];
			expect(models).toHaveLength(2);

			// All-delete on this provider succeeds and remains manageable
			const allDeleteResult = await updateCustomProviderModels("no-api-gw", [], {
				agentDir: tempDir,
				authStorage,
			});
			expect(allDeleteResult.modelCount).toBe(0);

			const listed = listConfiguredCustomProviders(tempDir);
			const found = listed.find(p => p.providerId === "no-api-gw");
			expect(found).toBeDefined();
			expect(found?.api).toBe("openai-completions");
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("malformed config safety: rejects updates on broken files and preserves them untouched", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-malformed-safety-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));

		try {
			// Case 1: Broken models.yml
			const brokenYmlPath = path.join(tempDir, "models.yml");
			fs.writeFileSync(brokenYmlPath, "providers: { invalid_yaml: [unclosed", "utf-8");

			await expect(
				updateCustomProviderModels("test-gw", [{ id: "m1" }], {
					agentDir: tempDir,
					authStorage,
				}),
			).rejects.toThrow(/Cannot modify.*syntax or schema errors/);
			expect(fs.readFileSync(brokenYmlPath, "utf-8")).toBe("providers: { invalid_yaml: [unclosed");

			// Remove broken yml
			fs.unlinkSync(brokenYmlPath);

			// Case 2: Broken models.json
			const brokenJsonPath = path.join(tempDir, "models.json");
			fs.writeFileSync(brokenJsonPath, '{"providers": { "broken": unclosed json', "utf-8");

			await expect(
				updateCustomProviderModels("test-gw", [{ id: "m1" }], {
					agentDir: tempDir,
					authStorage,
				}),
			).rejects.toThrow(/Cannot modify.*syntax or schema errors/);

			await expect(
				saveCustomProvider(
					{
						providerId: "new-gw",
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

			expect(fs.readFileSync(brokenJsonPath, "utf-8")).toBe('{"providers": { "broken": unclosed json');

			// Case 3: Non-existent provider
			fs.unlinkSync(brokenJsonPath);
			fs.writeFileSync(brokenYmlPath, "providers: {}", "utf-8");
			await expect(
				updateCustomProviderModels("missing-gw", [{ id: "m1" }], {
					agentDir: tempDir,
					authStorage,
				}),
			).rejects.toThrow(/not found in configuration/);
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("JSON handling and migration respecting loader precedence", async () => {
		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rev-json-handling-test-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "agent.db"));

		try {
			const jsonPath = path.join(tempDir, "models.json");
			const ymlPath = path.join(tempDir, "models.yml");
			const initialJson = {
				providers: {
					"json-gateway": {
						baseUrl: "https://json-gw.example.com/v1",
						api: "openai-completions",
						models: [{ id: "json-m1", name: "JSON Model 1" }],
					},
				},
			};
			fs.writeFileSync(jsonPath, JSON.stringify(initialJson, null, 2), "utf-8");

			// 1. listConfiguredCustomProviders discovers provider from models.json
			const listed = listConfiguredCustomProviders(tempDir);
			expect(listed).toHaveLength(1);
			expect(listed[0].providerId).toBe("json-gateway");
			expect(listed[0].models[0].id).toBe("json-m1");

			// 2. updateCustomProviderModels updates models and migrates to models.yml
			await updateCustomProviderModels(
				"json-gateway",
				[
					{ id: "json-m1", name: "Updated JSON Model" },
					{ id: "json-m2", name: "Added Model 2" },
				],
				{
					agentDir: tempDir,
					authStorage,
				},
			);

			expect(fs.existsSync(ymlPath)).toBe(true);
			const ymlParsed = YAML.parse(fs.readFileSync(ymlPath, "utf-8")) as Record<string, unknown>;
			const providers = ymlParsed.providers as Record<string, Record<string, unknown>>;
			expect(providers["json-gateway"]).toBeDefined();
			const models = providers["json-gateway"].models as Record<string, unknown>[];
			expect(models).toHaveLength(2);

			// 3. Loader precedence: when models.yml exists, it takes precedence over models.json
			const reListed = listConfiguredCustomProviders(tempDir);
			expect(reListed[0].models).toHaveLength(2);
			expect(reListed[0].models[0].name).toBe("JSON Model 1");
			expect(reListed[0].models[1].name).toBe("Added Model 2");
		} finally {
			authStorage.close();
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});

	test("validateCustomModelInputs validates contextWindow and maxTokens constraints", () => {
		expect(validateCustomModelInputs([{ id: "" }])).toBe("Model #1: ID is required.");
		expect(validateCustomModelInputs([{ id: "m1", contextWindow: -1 }])).toBe(
			"Model m1: contextWindow must be a positive integer.",
		);
		expect(validateCustomModelInputs([{ id: "m1", maxTokens: -5 }])).toBe(
			"Model m1: maxTokens must be a positive integer.",
		);
		expect(validateCustomModelInputs([{ id: "m1", contextWindow: 1000, maxTokens: 2000 }])).toBe(
			"Model m1: maxTokens cannot be larger than contextWindow.",
		);
		expect(validateCustomModelInputs([{ id: "m1", contextWindow: 2000, maxTokens: 1000 }])).toBeUndefined();
	});
});
