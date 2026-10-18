/**
 * Custom model/provider config file handle and validation.
 */
import { AXES } from "@rva/catalog/compat/axes";
import { servedKinds } from "@rva/catalog/types";
import { isRecord, once } from "@rva/utils";
import { ConfigFile } from "./config-file";
import { getModelsConfigSchema, getModelsConfigSchemaBundle } from "./models-config-schema-bundle";
const KIND_LIST = new Intl.ListFormat("en", { type: "disjunction" });
export function validateProviderConfiguration(providerName, config, mode) {
    const hasProviderApi = !!config.api;
    const models = config.models;
    if (models.length === 0) {
        if (mode === "models-config") {
            const hasModelOverrides = config.modelOverrides && Object.keys(config.modelOverrides).length > 0;
            if (!config.baseUrl &&
                !config.headers &&
                !config.compat &&
                !config.apiKey &&
                config.auth !== "none" &&
                !config.disableStrictTools &&
                !config.guardrailIdentifier &&
                !config.requestMetadata &&
                !config.remoteCompaction &&
                !hasModelOverrides &&
                !config.discovery) {
                throw new Error(`Provider ${providerName}: must specify "baseUrl", "headers", "apiKey", "auth: none", "compat", "disableStrictTools", "guardrailIdentifier", "requestMetadata", "remoteCompaction", "modelOverrides", "discovery", or "models"`);
            }
        }
    }
    else {
        if (!config.baseUrl) {
            throw new Error(`Provider ${providerName}: "baseUrl" is required when defining custom models.`);
        }
        const requiresAuth = mode === "runtime-register" && !config.apiKey && !config.oauthConfigured;
        if (requiresAuth) {
            throw new Error(`Provider ${providerName}: "apiKey" or "oauth" is required when defining models.`);
        }
    }
    if (mode === "models-config" && config.discovery && !config.api && config.discovery.type !== "proxy") {
        throw new Error(`Provider ${providerName}: "api" is required when discovery is enabled at provider level.`);
    }
    // Runners dispatch on `api`, so an explicit `kind` must be one its api serves. An
    // omitted `kind` follows the api.
    const checkKind = (subject, kind, api) => {
        const served = servedKinds(api);
        if (served === undefined || served.includes(kind))
            return;
        throw new Error(`Provider ${providerName}, ${subject}: kind "${kind}" does not match api "${api}", which serves kind ${KIND_LIST.format(served.map(k => `"${k}"`))}.`);
    };
    for (const modelDef of models) {
        if (!hasProviderApi && !modelDef.api) {
            throw new Error(mode === "runtime-register"
                ? `Provider ${providerName}, model ${modelDef.id}: no "api" specified.`
                : `Provider ${providerName}, model ${modelDef.id}: no "api" specified. Set at provider or model level.`);
        }
        if (!modelDef.id) {
            throw new Error(`Provider ${providerName}: model missing "id"`);
        }
        const api = modelDef.api ?? config.api;
        if (modelDef.kind !== undefined && api !== undefined)
            checkKind(`model ${modelDef.id}`, modelDef.kind, api);
        if (mode === "models-config") {
            if (modelDef.contextWindow !== undefined && modelDef.contextWindow <= 0) {
                throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid contextWindow`);
            }
            if (modelDef.maxTokens !== undefined && modelDef.maxTokens <= 0) {
                throw new Error(`Provider ${providerName}, model ${modelDef.id}: invalid maxTokens`);
            }
        }
    }
    // Only an api this file names is known here. Built-in, discovered, and `kind-apis`
    // rows get their api later, so `applyModelOverride` checks their kind against it.
    for (const [modelId, override] of Object.entries(config.modelOverrides ?? {})) {
        if (override.kind === undefined)
            continue;
        const declared = models.find(model => model.id === modelId);
        const api = override.api ?? (declared ? (declared.api ?? config.api) : undefined);
        if (api !== undefined)
            checkKind(`modelOverrides.${modelId}`, override.kind, api);
    }
}
function isObjectSchema(schema) {
    return schema.ir.k === "object";
}
// The file schema validates a curated subset of the runtime compatibility fields.
const getRuntimeCompatKeys = once(() => new Set(Object.values(AXES)
    .filter(axis => axis.set === "wire")
    .map(axis => axis.key)));
/** Unknown keys are diagnostic only: keep newer-release configuration intact. */
export function getUnknownCompatKeys(config) {
    const unknownKeys = [];
    const { ApiCompatSchema } = getModelsConfigSchemaBundle();
    const visit = (value, schema, path, level) => {
        if (!isRecord(value))
            return;
        const keys = schema.keyof();
        const properties = schema.props;
        for (const [key, entry] of Object.entries(value)) {
            const keyPath = `${path}.${key}`;
            if (!keys.allows(key) && !(level !== "nested" && key !== "whenThinking" && getRuntimeCompatKeys().has(key))) {
                unknownKeys.push(keyPath);
                continue;
            }
            if (!isRecord(entry))
                continue;
            const property = properties.find(property => property.key === key);
            // Open records (extraBody) have no declared properties to recurse into.
            if (property && isObjectSchema(property.value)) {
                visit(entry, property.value, keyPath, level === "compat" && key === "whenThinking" ? "whenThinking" : "nested");
            }
        }
    };
    for (const [name, provider] of Object.entries(config.providers ?? {})) {
        const path = `providers.${name}`;
        visit(provider.compat, ApiCompatSchema, `${path}.compat`, "compat");
        for (const [index, model] of (provider.models ?? []).entries()) {
            visit(model.compat, ApiCompatSchema, `${path}.models.${index}.compat`, "compat");
        }
        for (const [id, override] of Object.entries(provider.modelOverrides ?? {})) {
            visit(override.compat, ApiCompatSchema, `${path}.modelOverrides.${id}.compat`, "compat");
        }
    }
    return unknownKeys;
}
export const ModelsConfigFile = new ConfigFile("models", {
    kind: "deferred",
    resolve: getModelsConfigSchema,
}).withValidation("models", config => {
    const providers = config.providers ?? {};
    for (const providerName in providers) {
        const providerConfig = providers[providerName];
        validateProviderConfiguration(providerName, {
            baseUrl: providerConfig.baseUrl,
            headers: providerConfig.headers,
            apiKey: providerConfig.apiKey,
            api: providerConfig.api,
            auth: (providerConfig.auth ?? "apiKey"),
            discovery: providerConfig.discovery,
            compat: providerConfig.compat,
            remoteCompaction: providerConfig.remoteCompaction,
            disableStrictTools: providerConfig.disableStrictTools,
            guardrailIdentifier: providerConfig.guardrailIdentifier,
            requestMetadata: providerConfig.requestMetadata,
            modelOverrides: providerConfig.modelOverrides,
            models: (providerConfig.models ?? []),
        }, "models-config");
    }
});
