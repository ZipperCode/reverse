import * as fs from "node:fs";
import * as path from "node:path";
import { JSONC, YAML } from "bun";
import type { Api } from "@reverse/ai";
import type { AuthStorage } from "@reverse/ai";
import { getBundledProviders } from "@reverse/catalog";
import { ReverseErrors } from "@reverse/reversetype";
import { getAgentDir, withFileLock } from "@reverse/utils";
import { stringifyYamlConfig } from "@reverse/utils/yaml-config";
import { replaceFileAtomically } from "../utils/atomic-file";
import type { ModelRegistry } from "./model-registry";
import { ModelsConfigFile, validateProviderConfiguration, type ProviderValidationConfig } from "./models-config";
import { ModelsConfigSchema, type ProviderAuthMode, type ProviderDiscovery } from "./models-config-schema";

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
export interface ConfiguredCustomProviderDescriptor {
	providerId: string;
	baseUrl: string;
	api: Api;
	auth?: string;
	headers?: Record<string, string>;
	models: (CustomModelInput & Record<string, unknown>)[];
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
const MANAGED_CUSTOM_APIS = new Set([...SUPPORTED_CUSTOM_APIS, "google-generative-ai"]);

export function validateCustomModelInputs(models: CustomModelInput[]): string | undefined {
	for (const [index, model] of models.entries()) {
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

	return validateCustomModelInputs(input.models);
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
interface LoadedConfigState {
	existingContent: string | null;
	existingConfig: Record<string, unknown>;
	sourceFile: string | null;
}

function loadExistingConfigForMutation(configPath: string, agentDir?: string): LoadedConfigState {
	const dir = agentDir ?? path.dirname(configPath);
	const ymlPath = path.join(dir, "models.yml");
	const yamlPath = path.join(dir, "models.yaml");
	const jsonPath = path.join(dir, "models.json");

	let sourceFile: string | null = null;
	if (fs.existsSync(ymlPath)) {
		sourceFile = ymlPath;
	} else if (fs.existsSync(yamlPath)) {
		sourceFile = yamlPath;
	} else if (fs.existsSync(jsonPath)) {
		sourceFile = jsonPath;
	}

	if (!sourceFile) {
		return { existingContent: null, existingConfig: {}, sourceFile: null };
	}

	let existingContent: string;
	try {
		existingContent = fs.readFileSync(sourceFile, "utf-8");
	} catch {
		throw new Error(
			`Cannot modify "${configPath}": existing configuration has syntax or schema errors. Please resolve them first.`,
		);
	}

	let existingConfig: Record<string, unknown> = {};
	try {
		if (sourceFile.endsWith(".json") || sourceFile.endsWith(".jsonc")) {
			const parsed = JSONC.parse(existingContent);
			if (parsed !== null && parsed !== undefined) {
				if (typeof parsed !== "object" || Array.isArray(parsed)) {
					throw new Error("Invalid JSON structure");
				}
				existingConfig = parsed as Record<string, unknown>;
			}
		} else {
			const parsed = YAML.parse(existingContent);
			if (parsed !== null && parsed !== undefined) {
				if (typeof parsed !== "object" || Array.isArray(parsed)) {
					throw new Error("Invalid YAML structure");
				}
				existingConfig = parsed as Record<string, unknown>;
			}
		}
	} catch {
		throw new Error(
			`Cannot modify "${configPath}": existing configuration has syntax or schema errors. Please resolve them first.`,
		);
	}

	const schemaCheck = ModelsConfigSchema(existingConfig);
	if (schemaCheck instanceof ReverseErrors) {
		throw new Error(
			`Cannot modify "${configPath}": existing configuration has syntax or schema errors. Please resolve them first.`,
		);
	}

	const loadResult = ModelsConfigFile.relocate(configPath).tryLoad();
	if (loadResult.status === "error") {
		throw new Error(
			`Cannot modify "${configPath}": existing configuration has syntax or schema errors. Please resolve them first.`,
		);
	}

	return { existingContent, existingConfig, sourceFile };
}

export function listConfiguredCustomProviders(agentDir?: string): ConfiguredCustomProviderDescriptor[] {
	const configPath = resolveModelsConfigPath(agentDir);
	const { existingConfig } = loadExistingConfigForMutation(configPath, agentDir);

	if (
		!existingConfig.providers ||
		typeof existingConfig.providers !== "object" ||
		Array.isArray(existingConfig.providers)
	) {
		return [];
	}

	const providers = existingConfig.providers as Record<string, unknown>;
	const descriptors: ConfiguredCustomProviderDescriptor[] = [];

	for (const [providerId, rawProvider] of Object.entries(providers)) {
		if (!rawProvider || typeof rawProvider !== "object" || Array.isArray(rawProvider)) {
			continue;
		}
		const provider = rawProvider as Record<string, unknown>;
		const baseUrl = typeof provider.baseUrl === "string" ? provider.baseUrl.trim() : "";
		if (!baseUrl || (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://"))) {
			continue;
		}

		let api: Api | undefined;
		if (typeof provider.api === "string" && MANAGED_CUSTOM_APIS.has(provider.api)) {
			api = provider.api as Api;
		}

		const rawModels = Array.isArray(provider.models) ? provider.models : [];
		if (!api && rawModels.length > 0) {
			const modelApis = new Set<string>();
			for (const m of rawModels) {
				if (m && typeof m === "object" && typeof m.api === "string" && m.api.trim()) {
					modelApis.add(m.api.trim());
				}
			}
			if (modelApis.size === 1) {
				const singleApi = Array.from(modelApis)[0];
				if (MANAGED_CUSTOM_APIS.has(singleApi)) {
					api = singleApi as Api;
				}
			}
		}

		if (!api) {
			continue;
		}

		const models: (CustomModelInput & Record<string, unknown>)[] = rawModels
			.filter(m => m && typeof m === "object" && typeof m.id === "string" && m.id.trim())
			.map(m => {
				const modelObj = m as Record<string, unknown>;
				return {
					...modelObj,
					id: String(modelObj.id).trim(),
					name: typeof modelObj.name === "string" ? modelObj.name : undefined,
					contextWindow: typeof modelObj.contextWindow === "number" ? modelObj.contextWindow : undefined,
					maxTokens: typeof modelObj.maxTokens === "number" ? modelObj.maxTokens : undefined,
					input: Array.isArray(modelObj.input) ? (modelObj.input as ("text" | "image")[]) : undefined,
					reasoning: typeof modelObj.reasoning === "boolean" ? modelObj.reasoning : undefined,
				};
			});

		const auth = typeof provider.auth === "string" ? provider.auth : undefined;
		const headers =
			provider.headers && typeof provider.headers === "object" && !Array.isArray(provider.headers)
				? (provider.headers as Record<string, string>)
				: undefined;

		descriptors.push({
			providerId,
			baseUrl,
			api,
			...(auth ? { auth } : {}),
			...(headers ? { headers } : {}),
			models,
		});
	}

	return descriptors;
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
		const { existingContent, existingConfig } = loadExistingConfigForMutation(configPath, deps.agentDir);

		// 2. Check collision with existing config, built-in catalog, registry, and credentials
		const providers = (existingConfig.providers ?? {}) as Record<string, unknown>;
		checkProviderCollision(providerId, providers, deps);

		// 3. Construct new provider record (auth explicitly set to apiKey or none)
		const newProvider: Record<string, unknown> = {
			baseUrl,
			api,
			auth: keyless ? "none" : "apiKey",
			models: input.models.map(m => {
				const modelObj: Record<string, unknown> = {
					id: m.id.trim(),
					...(m.name?.trim() ? { name: m.name.trim() } : {}),
					...(m.contextWindow !== undefined ? { contextWindow: m.contextWindow } : {}),
					...(m.maxTokens !== undefined ? { maxTokens: m.maxTokens } : {}),
					...(m.input && m.input.length > 0 ? { input: m.input } : {}),
					...(m.reasoning !== undefined ? { reasoning: m.reasoning } : {}),
				};
				for (const [k, v] of Object.entries(m)) {
					if (!["id", "name", "contextWindow", "maxTokens", "input", "reasoning"].includes(k) && v !== undefined) {
						modelObj[k] = v;
					}
				}
				return modelObj;
			}),
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
		if (schemaCheck instanceof ReverseErrors) {
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

export async function updateCustomProviderModels(
	providerId: string,
	models: CustomModelInput[],
	deps: SaveCustomProviderDeps,
): Promise<SaveCustomProviderResult> {
	const trimmedId = providerId?.trim();
	if (!trimmedId) {
		throw new Error("Provider ID is required.");
	}

	const modelValidationError = validateCustomModelInputs(models);
	if (modelValidationError) {
		throw new Error(modelValidationError);
	}

	const configPath = resolveModelsConfigPath(deps.agentDir);
	const targetDir = path.dirname(configPath);
	await fs.promises.mkdir(targetDir, { recursive: true, mode: 0o700 });

	return await withFileLock(configPath, async () => {
		const { existingConfig } = loadExistingConfigForMutation(configPath, deps.agentDir);

		const providers = (existingConfig.providers ?? {}) as Record<string, unknown>;
		let matchedKey: string | undefined;
		for (const key of Object.keys(providers)) {
			if (key.toLowerCase() === trimmedId.toLowerCase()) {
				matchedKey = key;
				break;
			}
		}

		if (!matchedKey) {
			throw new Error(`Provider "${trimmedId}" not found in configuration.`);
		}

		const existingProvider = providers[matchedKey] as Record<string, unknown>;
		const updatedProvider: Record<string, unknown> = { ...existingProvider };

		const existingModelsList = Array.isArray(existingProvider.models)
			? (existingProvider.models as Record<string, unknown>[])
			: [];
		const existingModelMap = new Map<string, Record<string, unknown>>();
		for (const m of existingModelsList) {
			if (m && typeof m === "object" && typeof m.id === "string") {
				existingModelMap.set(m.id, m);
			}
		}

		// Determine effective API protocol
		let effectiveApi: Api | undefined;
		if (typeof existingProvider.api === "string" && MANAGED_CUSTOM_APIS.has(existingProvider.api)) {
			effectiveApi = existingProvider.api as Api;
		} else if (existingModelsList.length > 0) {
			const modelApis = new Set<string>();
			for (const m of existingModelsList) {
				if (typeof m.api === "string" && m.api.trim()) {
					modelApis.add(m.api.trim());
				}
			}
			if (modelApis.size === 1) {
				const singleApi = Array.from(modelApis)[0];
				if (MANAGED_CUSTOM_APIS.has(singleApi)) {
					effectiveApi = singleApi as Api;
				}
			}
		}

		if (!effectiveApi) {
			throw new Error(`Provider "${trimmedId}": cannot determine API protocol.`);
		}

		// If provider-level api was omitted, promote effectiveApi to provider level
		if (!existingProvider.api) {
			updatedProvider.api = effectiveApi;
		}

		const updatedModels = models.map(inputModel => {
			const modelId = inputModel.id.trim();
			const existing = existingModelMap.get(modelId);
			if (existing) {
				return existing;
			}
			return {
				id: modelId,
				...(inputModel.name?.trim() ? { name: inputModel.name.trim() } : {}),
				...(inputModel.contextWindow !== undefined ? { contextWindow: inputModel.contextWindow } : {}),
				...(inputModel.maxTokens !== undefined ? { maxTokens: inputModel.maxTokens } : {}),
				...(inputModel.input && inputModel.input.length > 0 ? { input: inputModel.input } : {}),
				...(inputModel.reasoning !== undefined ? { reasoning: inputModel.reasoning } : {}),
				...(!existingProvider.api ? { api: effectiveApi } : {}),
			};
		});

		updatedProvider.models = updatedModels;

		const updatedConfig = {
			...existingConfig,
			providers: {
				...providers,
				[matchedKey]: updatedProvider,
			},
		};

		const schemaCheck = ModelsConfigSchema(updatedConfig);
		if (schemaCheck instanceof ReverseErrors) {
			const errorMsg = schemaCheck.map(e => `${e.path.join(".")}: ${e.problem}`).join("; ");
			throw new Error(`Invalid provider configuration schema: ${errorMsg}`);
		}

		validateProviderConfiguration(
			matchedKey,
			{
				baseUrl: updatedProvider.baseUrl as string,
				api: updatedProvider.api as Api | undefined,
				headers: updatedProvider.headers as Record<string, string> | undefined,
				apiKey: updatedProvider.apiKey as string | undefined,
				auth: (updatedProvider.auth ?? "apiKey") as ProviderAuthMode,
				discovery: updatedProvider.discovery as ProviderDiscovery | undefined,
				compat: updatedProvider.compat as ProviderValidationConfig["compat"],
				remoteCompaction: updatedProvider.remoteCompaction,
				disableStrictTools: updatedProvider.disableStrictTools as boolean | undefined,
				guardrailIdentifier: updatedProvider.guardrailIdentifier as string | undefined,
				requestMetadata: updatedProvider.requestMetadata as Record<string, string> | undefined,
				modelOverrides: updatedProvider.modelOverrides as ProviderValidationConfig["modelOverrides"],
				models: updatedModels.map(m => {
					const mRecord = m as Record<string, unknown>;
					return {
						id: mRecord.id as string,
						api: (mRecord.api ?? updatedProvider.api) as Api | undefined,
						contextWindow: mRecord.contextWindow as number | undefined,
						maxTokens: mRecord.maxTokens as number | undefined,
					};
				}),
			},
			"models-config",
		);

		const serialized = stringifyYamlConfig(updatedConfig);
		const tempPath = path.join(targetDir, `.${path.basename(configPath)}.tmp.${process.pid}.${Date.now()}`);

		try {
			await fs.promises.writeFile(tempPath, serialized, { mode: 0o600 });
			await replaceFileAtomically(tempPath, configPath);
		} finally {
			try {
				if (fs.existsSync(tempPath)) await fs.promises.unlink(tempPath);
			} catch {}
		}

		ModelsConfigFile.invalidate();
		if (deps.modelRegistry) {
			await deps.modelRegistry.refresh("offline");
		}

		const keyless =
			updatedProvider.auth === "none" ||
			(!updatedProvider.apiKey && !deps.authStorage?.credentials?.has(matchedKey));

		return {
			providerId: matchedKey,
			configPath,
			keyless,
			modelCount: updatedModels.length,
		};
	});
}
