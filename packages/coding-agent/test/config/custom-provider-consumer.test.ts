import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { YAML } from "bun";
import { AuthStorage } from "@rva/ai";
import { Terminal as VirtualTerminal } from "@rva/utils/vterm";
import { ModelRegistry } from "@rva/coding-agent/config/model-registry";
import { resolveModelsConfigPath, saveCustomProvider } from "@rva/coding-agent/config/custom-provider-writer";

function tempDir(prefix: string): string {
	return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function terminalText(screen: VirtualTerminal): string {
	const buffer = screen.buffer.active;
	return Array.from(
		{ length: buffer.length },
		(_, row) => buffer.getLine(row)?.translateToString(true).trimEnd() ?? "",
	).join("\n");
}

async function waitForTerminal(
	screen: VirtualTerminal,
	nextData: () => Promise<void>,
	predicate: (text: string) => boolean,
	timeoutMs = 15000,
): Promise<void> {
	const timeoutSignal = AbortSignal.timeout(timeoutMs);
	const timeout = new Promise<never>((_, reject) => {
		timeoutSignal.addEventListener(
			"abort",
			() => reject(new Error(`Timed out waiting for terminal state.\n${terminalText(screen)}`)),
			{ once: true },
		);
	});
	while (!predicate(terminalText(screen))) await Promise.race([nextData(), timeout]);
}

describe("custom provider consumer contract", () => {
	test("preserves unrelated root keys and providers while omitting the secret from models.yml", async () => {
		const dir = tempDir("rev-custom-preserve-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const modelsPath = path.join(dir, "models.yml");
		const existing = [
			"version: 2",
			"providers:",
			"  existing:",
			"    baseUrl: https://existing.example.com/v1",
			"    api: openai-completions",
			"    apiKey: EXISTING_KEY_ENV",
			"    headers:",
			"      X-Team: platform",
			"    models:",
			"      - id: existing-model",
			"        name: Existing",
			"        contextWindow: 64000",
			"        maxTokens: 2048",
			"",
		].join("\n");
		fs.writeFileSync(modelsPath, existing, "utf-8");
		const secret = "sk-consumer-secret-12345";

		try {
			await saveCustomProvider(
				{
					providerId: "new-gateway",
					baseUrl: "https://new.example.com/v1/",
					api: "openai-completions",
					apiKey: secret,
					models: [{ id: "new-model", name: "New Model", contextWindow: 128000, maxTokens: 8192 }],
				},
				{ agentDir: dir, authStorage },
			);

			const raw = fs.readFileSync(modelsPath, "utf-8");
			expect(raw).not.toContain(secret);

			const parsed = YAML.parse(fs.readFileSync(modelsPath, "utf-8")) as Record<string, any>;
			expect(parsed.providers["new-gateway"].apiKey).toBeUndefined();
			expect(parsed.version).toBe(2);
			expect(parsed.providers.existing).toEqual({
				baseUrl: "https://existing.example.com/v1",
				api: "openai-completions",
				apiKey: "EXISTING_KEY_ENV",
				headers: { "X-Team": "platform" },
				models: [{ id: "existing-model", name: "Existing", contextWindow: 64000, maxTokens: 2048 }],
			});
			expect(parsed.providers["new-gateway"]).toEqual({
				baseUrl: "https://new.example.com/v1",
				api: "openai-completions",
				auth: "apiKey",
				models: [{ id: "new-model", name: "New Model", contextWindow: 128000, maxTokens: 8192 }],
			});

			const credential = authStorage.credentials.get("new-gateway");
			expect(credential).toEqual({
				type: "api_key",
				key: secret,
				source: "login",
			});
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("a fresh registry resolves the stored secret and exposes the model without network", async () => {
		const dir = tempDir("rev-custom-registry-");
		const dbPath = path.join(dir, "agent.db");
		const modelsPath = path.join(dir, "models.yml");
		const secret = "sk-registry-secret-67890";
		const authStorage = await AuthStorage.create(dbPath);

		try {
			await saveCustomProvider(
				{
					providerId: "stored-auth",
					baseUrl: "http://127.0.0.1:9/v1",
					api: "openai-completions",
					apiKey: secret,
					models: [{ id: "stored-model", contextWindow: 32000, maxTokens: 4096 }],
				},
				{ agentDir: dir, authStorage },
			);
		} finally {
			authStorage.close();
		}

		const reopenedAuth = await AuthStorage.create(dbPath);
		await reopenedAuth.credentials.reload();
		const registry = new ModelRegistry(reopenedAuth, modelsPath, {
			fetch: () => Promise.reject(new Error("network disabled in test")),
		});
		try {
			const model = registry.find("stored-auth", "stored-model");
			expect(model).toBeDefined();
			expect(model?.provider).toBe("stored-auth");
			expect(model?.api).toBe("openai-completions");
			expect(registry.hasConfiguredAuth(model!)).toBe(true);
			expect(await registry.getApiKeyForProvider("stored-auth")).toBe(secret);
			expect(registry.getAvailable("chat").some(candidate => candidate.provider === "stored-auth")).toBe(true);
		} finally {
			reopenedAuth.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("updates an existing models.yaml instead of creating models.yml", async () => {
		const dir = tempDir("rev-custom-yaml-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const yamlPath = path.join(dir, "models.yaml");
		const ymlPath = path.join(dir, "models.yml");
		fs.writeFileSync(
			yamlPath,
			[
				"providers:",
				"  existing:",
				"    baseUrl: https://existing.example.com/v1",
				"    api: openai-completions",
				"    models:",
				"      - id: existing-model",
				"",
			].join("\n"),
			"utf-8",
		);

		try {
			const result = await saveCustomProvider(
				{
					providerId: "yaml-provider",
					baseUrl: "https://yaml.example.com/v1",
					api: "openai-completions",
					models: [{ id: "yaml-model" }],
				},
				{ agentDir: dir, authStorage },
			);

			expect(resolveModelsConfigPath(dir)).toBe(yamlPath);
			expect(result.configPath).toBe(yamlPath);
			expect(fs.existsSync(ymlPath)).toBe(false);
			const parsed = YAML.parse(fs.readFileSync(yamlPath, "utf-8")) as Record<string, any>;
			expect(Object.keys(parsed.providers)).toEqual(["existing", "yaml-provider"]);
			expect(parsed.providers["yaml-provider"].auth).toBe("none");
			expect(authStorage.credentials.has("yaml-provider")).toBe(false);
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("duplicate and invalid inputs leave both the config and credential store untouched", async () => {
		const dir = tempDir("rev-custom-no-mutation-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const modelsPath = path.join(dir, "models.yml");
		const originalKey = "sk-original-key";
		const secret = "sk-original-secret";
		fs.writeFileSync(
			modelsPath,
			[
				"providers:",
				"  taken:",
				"    baseUrl: https://taken.example.com/v1",
				"    api: openai-completions",
				"    models:",
				"      - id: taken-model",
				"",
			].join("\n"),
			"utf-8",
		);
		const before = fs.readFileSync(modelsPath, "utf-8");

		try {
			await authStorage.credentials.set("taken", { type: "api_key", key: originalKey, source: "login" });

			await expect(
				saveCustomProvider(
					{
						providerId: "TAKEN",
						baseUrl: "https://other.example.com/v1",
						api: "openai-completions",
						apiKey: "sk-duplicate-secret",
						models: [{ id: "other-model" }],
					},
					{ agentDir: dir, authStorage },
				),
			).rejects.toThrow(/already exists/);

			expect(fs.readFileSync(modelsPath, "utf-8")).toBe(before);
			expect(authStorage.credentials.get("taken")).toEqual({
				type: "api_key",
				key: originalKey,
				source: "login",
			});
			expect(authStorage.credentials.has("taken")).toBe(true);
			expect(authStorage.credentials.get("taken")).not.toEqual({
				type: "api_key",
				key: secret,
				source: "login",
			});

			await expect(
				saveCustomProvider(
					{
						providerId: "bad id",
						baseUrl: "https://bad.example.com/v1",
						api: "openai-completions",
						apiKey: secret,
						models: [{ id: "bad-model" }],
					},
					{ agentDir: dir, authStorage },
				),
			).rejects.toThrow(/Provider ID must start with/);

			expect(fs.readFileSync(modelsPath, "utf-8")).toBe(before);
			expect(authStorage.credentials.has("bad id")).toBe(false);
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("preserves API-key request shaping for a keyed Anthropic-compatible provider", async () => {
		const dir = tempDir("rev-custom-anthropic-shape-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const modelsPath = path.join(dir, "models.yml");

		try {
			await saveCustomProvider(
				{
					providerId: "anthropic-proxy",
					baseUrl: "https://anthropic-proxy.example.com",
					api: "anthropic-messages",
					apiKey: "sk-anthropic-key",
					models: [{ id: "claude-proxy", contextWindow: 200000, maxTokens: 8192 }],
				},
				{ agentDir: dir, authStorage },
			);

			const parsed = YAML.parse(fs.readFileSync(modelsPath, "utf-8")) as Record<string, any>;
			expect(parsed.providers["anthropic-proxy"].auth).toBe("apiKey");
			expect(parsed.providers["anthropic-proxy"].apiKey).toBeUndefined();

			const registry = new ModelRegistry(authStorage, modelsPath, {
				fetch: () => Promise.reject(new Error("network disabled in test")),
			});
			const model = registry.find("anthropic-proxy", "claude-proxy");
			expect(model?.api).toBe("anthropic-messages");
			expect(model?.isOAuth).not.toBe(true);
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("refuses to overwrite built-in or credential-only provider credentials", async () => {
		const dir = tempDir("rev-custom-credential-collision-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const modelsPath = path.join(dir, "models.yml");

		try {
			await authStorage.credentials.set("openai", {
				type: "api_key",
				key: "original-openai-key",
				source: "login",
			});

			await expect(
				saveCustomProvider(
					{
						providerId: "openai",
						baseUrl: "https://override.example.com/v1",
						api: "openai-completions",
						apiKey: "replacement-openai-key",
						models: [{ id: "override-model" }],
					},
					{ agentDir: dir, authStorage },
				),
			).rejects.toThrow();

			expect(authStorage.credentials.get("openai")).toEqual({
				type: "api_key",
				key: "original-openai-key",
				source: "login",
			});
			expect(fs.existsSync(modelsPath)).toBe(false);

			await authStorage.credentials.set("credential-only", {
				type: "api_key",
				key: "original-credential-only-key",
				source: "login",
			});

			await expect(
				saveCustomProvider(
					{
						providerId: "credential-only",
						baseUrl: "https://credential-only.example.com/v1",
						api: "openai-completions",
						apiKey: "replacement-credential-only-key",
						models: [{ id: "credential-only-model" }],
					},
					{ agentDir: dir, authStorage },
				),
			).rejects.toThrow();

			expect(authStorage.credentials.get("credential-only")).toEqual({
				type: "api_key",
				key: "original-credential-only-key",
				source: "login",
			});
			expect(fs.existsSync(modelsPath)).toBe(false);
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("rejects malformed URLs and unsupported protocols without writing state", async () => {
		const dir = tempDir("rev-custom-url-validation-");
		const authStorage = await AuthStorage.create(path.join(dir, "agent.db"));
		const modelsPath = path.join(dir, "models.yml");
		const existing = [
			"providers:",
			"  existing:",
			"    baseUrl: https://existing.example.com/v1",
			"    api: openai-completions",
			"    models:",
			"      - id: existing-model",
			"",
		].join("\n");
		fs.writeFileSync(modelsPath, existing, "utf-8");

		try {
			for (const baseUrl of ["https://", "https://exa mple.com", "ftp://example.com"]) {
				const providerId = `bad-url-${baseUrl.length}`;
				await expect(
					saveCustomProvider(
						{
							providerId,
							baseUrl,
							api: "openai-completions",
							apiKey: "sk-should-not-persist",
							models: [{ id: "bad-url-model" }],
						},
						{ agentDir: dir, authStorage },
					),
				).rejects.toThrow();
				expect(authStorage.credentials.has(providerId)).toBe(false);
			}

			await expect(
				saveCustomProvider(
					{
						providerId: "unsupported-api",
						baseUrl: "https://example.com/v1",
						api: "google-generative-ai",
						apiKey: "sk-should-not-persist",
						models: [{ id: "unsupported-model" }],
					},
					{ agentDir: dir, authStorage },
				),
			).rejects.toThrow();

			expect(fs.readFileSync(modelsPath, "utf-8")).toBe(existing);
			expect(authStorage.credentials.has("unsupported-api")).toBe(false);
		} finally {
			authStorage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("rolls back the models file when credential persistence fails", async () => {
		const dir = tempDir("rev-custom-rollback-");
		const modelsPath = path.join(dir, "models.yml");
		const existing = [
			"providers:",
			"  existing:",
			"    baseUrl: https://existing.example.com/v1",
			"    api: openai-completions",
			"    models:",
			"      - id: existing-model",
			"",
		].join("\n");
		fs.writeFileSync(modelsPath, existing, "utf-8");
		const failingAuthStorage = {
			credentials: {
				has: () => false,
				set: async () => {
					throw new Error("injected credential failure");
				},
			},
			keys: {
				source: () => undefined,
			},
		} as unknown as AuthStorage;

		try {
			await expect(
				saveCustomProvider(
					{
						providerId: "rollback-provider",
						baseUrl: "https://rollback.example.com/v1",
						api: "openai-completions",
						apiKey: "sk-rollback-secret",
						models: [{ id: "rollback-model" }],
					},
					{ agentDir: dir, authStorage: failingAuthStorage },
				),
			).rejects.toThrow(/Failed to save credential/);

			expect(fs.readFileSync(modelsPath, "utf-8")).toBe(existing);
			expect(fs.readdirSync(dir).filter(name => name.includes(".tmp.") || name.includes(".bak."))).toEqual([]);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test("real PTY: add a provider, then run loopback inference from persisted config", async () => {
		const home = tempDir("rev-custom-pty-");
		const agentDir = path.join(home, "agent");
		fs.mkdirSync(agentDir, { recursive: true });
		const providerId = "pty-loopback";
		const modelId = "pty-loopback-model";
		const secret = "pty-loopback-secret-token";
		fs.writeFileSync(
			path.join(agentDir, "models.yml"),
			[
				"providers:",
				"  bootstrap:",
				"    baseUrl: http://127.0.0.1:1/v1",
				"    api: openai-completions",
				"    auth: none",
				"    models:",
				"      - id: bootstrap-model",
				"        contextWindow: 200000",
				"        maxTokens: 8192",
				"",
			].join("\n"),
			"utf-8",
		);
		let capturedAuthHeader = "";
		const receivedPrompts: string[] = [];
		let authStorage: AuthStorage | undefined;

		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(request) {
				capturedAuthHeader = request.headers.get("authorization") ?? "";
				if (capturedAuthHeader !== `Bearer ${secret}`) return new Response("Unauthorized", { status: 401 });

				const url = new URL(request.url);
				if (url.pathname.endsWith("/models")) {
					return Response.json({
						object: "list",
						data: [
							{ id: modelId, object: "model" },
							{ id: `${modelId}-second`, object: "model" },
						],
					});
				}
				if (!url.pathname.endsWith("/chat/completions")) return new Response("Not found", { status: 404 });

				const body = (await request.json()) as {
					messages?: Array<{ content?: unknown }>;
					stream?: boolean;
				};
				const content = body.messages?.at(-1)?.content;
				const promptText =
					typeof content === "string"
						? content
						: Array.isArray(content)
							? content
									.map(part =>
										typeof part === "object" && part !== null && "text" in part ? String(part.text) : "",
									)
									.join("")
							: "";
				receivedPrompts.push(promptText);
				const chunk = {
					id: "chatcmpl-pty",
					object: "chat.completion.chunk",
					created: 0,
					model: modelId,
					choices: [{ index: 0, delta: { role: "assistant", content: "pong from pty provider" } }],
				};
				const finish = {
					id: "chatcmpl-pty",
					object: "chat.completion.chunk",
					created: 0,
					model: modelId,
					choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
				};
				return new Response(
					`data: ${JSON.stringify(chunk)}\n\ndata: ${JSON.stringify(finish)}\n\ndata: [DONE]\n\n`,
					{ headers: { "content-type": "text/event-stream" } },
				);
			},
		});

		const screen = new VirtualTerminal({ cols: 120, rows: 40, scrollback: 200 });
		let dataVersion = 0;
		let observedVersion = 0;
		const dataWaiters = new Set<() => void>();
		const terminal = new Bun.Terminal({
			cols: 120,
			rows: 40,
			data(_terminal, data) {
				screen.write(data, () => {
					dataVersion += 1;
					for (const wake of dataWaiters) wake();
					dataWaiters.clear();
				});
			},
		});
		const nextData = () => {
			if (dataVersion !== observedVersion) {
				observedVersion = dataVersion;
				return Promise.resolve();
			}
			return new Promise<void>(resolve => {
				dataWaiters.add(() => {
					observedVersion = dataVersion;
					resolve();
				});
			});
		};
		const env = {
			PATH: process.env.PATH ?? "",
			HOME: home,
			TMPDIR: home,
			LANG: process.env.LANG ?? "en_US.UTF-8",
			TERM: "xterm-256color",
			RVA_CODING_AGENT_DIR: agentDir,
			RVA_NO_TITLE: "1",
			RVA_SKIP_SETUP: "1",
			NO_COLOR: "1",
			RVA_TUI_NATIVE: "0",
			PI_TUI_NATIVE: "0",
		};
		const cliBin = path.resolve(import.meta.dir, "../../dist/rva");
		const cliArgs = fs.existsSync(cliBin)
			? [cliBin]
			: [process.execPath, path.join(import.meta.dir, "../../src/cli.ts")];
		const child = Bun.spawn(
			[
				...cliArgs,
				"--no-extensions",
				"--no-skills",
				"--no-rules",
				"--no-lsp",
				"--model",
				"bootstrap/bootstrap-model",
			],
			{
				cwd: home,
				terminal,
				env,
			},
		);

		try {
			await waitForTerminal(screen, nextData, text => text.includes("╰─") || text.includes("❯"), 20000);
			terminal.write("/setup add");
			await waitForTerminal(screen, nextData, text => text.includes("/setup add"));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Step 1: Provider ID"));

			terminal.write(providerId);
			await waitForTerminal(screen, nextData, text => text.includes(providerId));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Step 2: API Protocol"));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Step 3: Base URL"));

			const baseUrl = `http://127.0.0.1:${server.port}/v1`;
			terminal.write(baseUrl);
			await waitForTerminal(screen, nextData, text => text.includes(baseUrl));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Step 4: API Key"));
			terminal.write(secret);
			await waitForTerminal(screen, nextData, text => text.includes("•"));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Step 5: Select Models"));
			await waitForTerminal(screen, nextData, text => text.includes(modelId) && text.includes(`${modelId}-second`));
			// Uncheck first model with Space -> 1/2 selected
			terminal.write(" ");
			await waitForTerminal(screen, nextData, text => text.includes("[1/2 selected]"));
			// Move down and uncheck second model -> 0/2 selected
			terminal.write("\x1b[B");
			terminal.write(" ");
			await waitForTerminal(screen, nextData, text => text.includes("[0/2 selected]"));
			// Enter with 0 selected must show error and not advance
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Please select at least one model."));
			// Re-check second model -> 1/2 selected
			terminal.write(" ");
			await waitForTerminal(screen, nextData, text => text.includes("[1/2 selected]"));
			// Move back up and re-check first model -> 2/2 selected
			terminal.write("\x1b[A");
			terminal.write(" ");
			await waitForTerminal(screen, nextData, text => text.includes("[2/2 selected]"));
			// Advance to Confirm Configuration
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("Confirm Configuration"));
			terminal.write("\x1b[13u");
			await waitForTerminal(screen, nextData, text => text.includes("added with 2 model(s)"), 20000);

			const ymlText = fs.readFileSync(path.join(agentDir, "models.yml"), "utf-8");
			expect(ymlText).not.toContain(secret);
			const parsed = YAML.parse(ymlText) as Record<string, any>;
			expect(parsed.providers.bootstrap).toBeDefined();
			expect(parsed.providers[providerId]).toMatchObject({
				baseUrl,
				api: "openai-completions",
				auth: "apiKey",
			});
			expect(parsed.providers[providerId].apiKey).toBeUndefined();

			authStorage = await AuthStorage.create(path.join(agentDir, "agent.db"));
			await authStorage.credentials.reload();
			expect(authStorage.credentials.get(providerId)).toEqual({
				type: "api_key",
				key: secret,
				source: "login",
			});

			const headless = Bun.spawn(
				[
					...cliArgs,
					"--no-extensions",
					"--no-skills",
					"--no-rules",
					"--no-lsp",
					"--model",
					`${providerId}/${modelId}`,
					"-p",
					"hello from real pty",
				],
				{
					cwd: home,
					env,
					stdout: "pipe",
					stderr: "pipe",
				},
			);
			const [stdout, stderr, exitCode] = await Promise.all([
				new Response(headless.stdout).text(),
				new Response(headless.stderr).text(),
				headless.exited,
			]);
			expect(exitCode, stderr).toBe(0);
			expect(stdout).toContain("pong from pty provider");
			expect(capturedAuthHeader).toBe(`Bearer ${secret}`);
			expect(receivedPrompts.some(prompt => prompt.includes("hello from real pty"))).toBe(true);
		} finally {
			if (child.exitCode === null) child.kill();
			await child.exited;
			terminal.close();
			screen.dispose();
			server.stop(true);
			authStorage?.close();
			fs.rmSync(home, { recursive: true, force: true });
		}
	}, 60_000);
});
