import * as fs from "node:fs";
import * as path from "node:path";
import { YAML } from "bun";
import type { Api } from "@rva/ai";
import type { AuthStorage } from "@rva/ai";
import { getBundledProviders } from "@rva/catalog";
import { OmpErrors } from "@rva/omptype";
import { getAgentDir, withFileLock } from "@rva/utils";
import { stringifyYamlConfig } from "@rva/utils/yaml-config";
import { replaceFileAtomically } from "../utils/atomic-file";
import type { ModelRegistry } from "./model-registry";
import { ModelsConfigFile, validateProviderConfiguration } from "./models-config";
import { ModelsConfigSchema } from "./models-config-schema";

export interface CustomModelInput {
	id: string;
	name?: string;
	contextWindow?: number;
	maxTokens?: number;
	input?: ("text" | "image")[];
	reasoning?: boolean;
}

export interface CustomProviderInput {
	providerId: string;
	baseUrl: string;
	api: Api;
	apiKey?: string;
	models: CustomModelInput[];
}

export interface SaveCustomProviderDeps {
	authStorage: AuthStorage;
	modelRegistry?: ModelRegistry;
	agentDir?: string;
}

export interface SaveCustomProviderResult {
	providerId: string;
	configPath: string;
	keyless: boolean;
	modelCount: number;
}

const PROVIDER_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;
const SUPPORTED_CUSTOM_APIS = new Set(["openai-completions", "openai-responses", "anthropic-messages"]);

export function validateCustomProviderInput(input: CustomProviderInput): string | undefined {
	const id = input.providerId?.trim();
	if (!id) return "Provider ID is required.";
	if (!PROVIDER_ID_RE.test(id)) {
		return "Provider ID must start with an alphanumeric character and contain only letters, numbers, '.', '-', '_'.";
	}

	const baseUrl = input.baseUrl?.trim();
	if (!baseUrl) return "Base URL is required.";
	if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
		return "Base URL must start with http:// or https://.";
	}
	try {
		new URL(baseUrl);
	} catch {
		return "Base URL must be a valid URL.";
	}

	if (!SUPPORTED_CUSTOM_APIS.has(input.api)) {
		return `Unsupported API protocol "${input.api}". Supported protocols: openai-completions, openai-responses, anthropic-messages.`;
	}
	if (!input.models || input.models.length === 0) {
		return "At least one model must be defined.";
	}

	for (const [index, model] of input.models.entries()) {
		const modelId = model.id?.trim();
		if (!modelId) return `Model #${index + 1}: ID is required.`;
		if (model.contextWindow !== undefined) {
			if (!Number.isSafeInteger(model.contextWindow) || model.contextWindow <= 0) {
				return `Model ${modelId}: contextWindow must be a positive integer.`;
			}
		}
		if (model.maxTokens !== undefined) {
			if (!Number.isSafeInteger(model.maxTokens) || model.maxTokens <= 0) {
				return `Model ${modelId}: maxTokens must be a positive integer.`;
			}
			if (model.contextWindow !== undefined && model.maxTokens > model.contextWindow) {
				return `Model ${modelId}: maxTokens cannot be larger than contextWindow.`;
			}
		}
	}

	return undefined;
}

export function resolveModelsConfigPath(agentDir?: string): string {
	const dir = agentDir ?? getAgentDir();
	const ymlPath = path.join(dir, "models.yml");
	const yamlPath = path.join(dir, "models.yaml");
	if (!fs.existsSync(ymlPath) && fs.existsSync(yamlPath)) {
		return yamlPath;
	}
	return ymlPath;
}

function checkProviderCollision(
	providerId: string,
	existingConfigProviders: Record<string, unknown>,
	deps: SaveCustomProviderDeps,
): void {
	const lowerId = providerId.toLowerCase();

	for (const existingId of Object.keys(existingConfigProviders)) {
		if (existingId.toLowerCase() === lowerId) {
			throw new Error(`Provider "${providerId}" already exists in configuration.`);
		}
	}

	const bundled = new Set(getBundledProviders().map(p => p.toLowerCase()));
	if (bundled.has(lowerId)) {
		throw new Error(`Provider ID "${providerId}" collides with a built-in provider.`);
	}

	if (deps.modelRegistry?.hasProvider?.(providerId)) {
		throw new Error(`Provider ID "${providerId}" collides with an existing provider in registry.`);
	}

	if (deps.authStorage?.credentials?.has?.(providerId) || deps.authStorage?.keys?.source?.(providerId) !== undefined) {
		throw new Error(`Provider ID "${providerId}" collides with existing stored credentials.`);
	}
}

export async function saveCustomProvider(
	input: CustomProviderInput,
	deps: SaveCustomProviderDeps,
): Promise<SaveCustomProviderResult> {
	const validationError = validateCustomProviderInput(input);
	if (validationError) throw new Error(validationError);

	const providerId = input.providerId.trim();
	const baseUrl = input.baseUrl.trim().replace(/\/+$/, "");
	const api = input.api;
	const apiKey = input.apiKey?.trim();
	const keyless = !apiKey || apiKey.length === 0;

	const configPath = resolveModelsConfigPath(deps.agentDir);
	const targetDir = path.dirname(configPath);
	await fs.promises.mkdir(targetDir, { recursive: true, mode: 0o700 });

	return await withFileLock(configPath, async () => {
		// 1. Check existing models file status
		let existingContent: string | null = null;
		let existingConfig: Record<string, unknown> = {};

		const loadResult = ModelsConfigFile.relocate(configPath).tryLoad();
		if (loadResult.status === "error") {
			throw new Error(
				`Cannot modify "${configPath}": existing configuration has syntax or schema errors. Please resolve them first.`,
			);
		}

		if (fs.existsSync(configPath)) {
			try {
				existingContent = await fs.promises.readFile(configPath, "utf-8");
				const parsed = YAML.parse(existingContent);
				if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
					existingConfig = parsed as Record<string, unknown>;
				}
			} catch (err) {
				throw new Error(`Cannot parse existing configuration file "${configPath}": ${String(err)}`);
			}
		}

		// 2. Check collision with existing config, built-in catalog, registry, and credentials
		const providers = (existingConfig.providers ?? {}) as Record<string, unknown>;
		checkProviderCollision(providerId, providers, deps);

		// 3. Construct new provider record (auth explicitly set to apiKey or none)
		const newProvider: Record<string, unknown> = {
			baseUrl,
			api,
			auth: keyless ? "none" : "apiKey",
			models: input.models.map(m => ({
				id: m.id.trim(),
				...(m.name?.trim() ? { name: m.name.trim() } : {}),
				...(m.contextWindow !== undefined ? { contextWindow: m.contextWindow } : {}),
				...(m.maxTokens !== undefined ? { maxTokens: m.maxTokens } : {}),
				...(m.input && m.input.length > 0 ? { input: m.input } : {}),
				...(m.reasoning !== undefined ? { reasoning: m.reasoning } : {}),
			})),
		};

		// 4. Update and validate candidate config with full ModelsConfigSchema & validateProviderConfiguration
		const updatedConfig = {
			...existingConfig,
			providers: {
				...providers,
				[providerId]: newProvider,
			},
		};

		const schemaCheck = ModelsConfigSchema(updatedConfig);
		if (schemaCheck instanceof OmpErrors) {
			const errorMsg = schemaCheck.map(e => `${e.path.join(".")}: ${e.problem}`).join("; ");
			throw new Error(`Invalid provider configuration schema: ${errorMsg}`);
		}

		validateProviderConfiguration(
			providerId,
			{
				baseUrl,
				api,
				auth: keyless ? "none" : "apiKey",
				models: input.models.map(m => ({
					id: m.id.trim(),
					api,
					contextWindow: m.contextWindow,
					maxTokens: m.maxTokens,
				})),
			},
			"models-config",
		);

		// 5. Write YAML atomically
		const serialized = stringifyYamlConfig(updatedConfig);
		const tempPath = path.join(targetDir, `.${path.basename(configPath)}.tmp.${process.pid}.${Date.now()}`);
		const backupPath = path.join(targetDir, `.${path.basename(configPath)}.bak.${process.pid}.${Date.now()}`);
		let preservedBackupForRecovery = false;

		try {
			await fs.promises.writeFile(tempPath, serialized, { mode: 0o600 });
			if (existingContent !== null) {
				await fs.promises.writeFile(backupPath, existingContent, { mode: 0o600 });
			}
			await replaceFileAtomically(tempPath, configPath);

			// 6. Store API key secret in AuthStorage (agent.db)
			if (!keyless) {
				try {
					await deps.authStorage.credentials.set(providerId, {
						type: "api_key",
						key: apiKey,
						source: "login",
					});
				} catch (error) {
					let credentialCleanupError: unknown;
					try {
						await deps.authStorage.credentials.remove(providerId);
					} catch (credErr) {
						credentialCleanupError = credErr;
					}

					let rollbackError: unknown;
					let restoredBackup = false;
					try {
						if (existingContent !== null && fs.existsSync(backupPath)) {
							await replaceFileAtomically(backupPath, configPath);
							restoredBackup = true;
						} else {
							await fs.promises.unlink(configPath);
						}
					} catch (rbErr) {
						rollbackError = rbErr;
					}

					if (!restoredBackup && existingContent !== null && fs.existsSync(backupPath)) {
						preservedBackupForRecovery = true;
					}

					const errorDetails = [
						`Failed to save credential for provider "${providerId}": ${String(error)}`,
						rollbackError
							? `file rollback failed: ${String(rollbackError)}${
									preservedBackupForRecovery ? ` (backup preserved at ${backupPath})` : ""
								}`
							: undefined,
						credentialCleanupError ? `credential cleanup failed: ${String(credentialCleanupError)}` : undefined,
					]
						.filter(Boolean)
						.join("; ");

					throw new Error(errorDetails);
				}
			}
		} finally {
			try {
				if (fs.existsSync(tempPath)) await fs.promises.unlink(tempPath);
			} catch {}
			if (!preservedBackupForRecovery) {
				try {
					if (fs.existsSync(backupPath)) await fs.promises.unlink(backupPath);
				} catch {}
			}
		}

		// 7. Invalidate config file cache and refresh registry
		ModelsConfigFile.invalidate();
		if (deps.modelRegistry) {
			await deps.modelRegistry.refresh("offline");
		}

		return {
			providerId,
			configPath,
			keyless,
			modelCount: input.models.length,
		};
	});
}
