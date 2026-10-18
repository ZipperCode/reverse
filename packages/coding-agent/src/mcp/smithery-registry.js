import { logger } from "@rva/utils";
import { isTimeoutError, withTimeoutSignal } from "../utils/fetch-timeout";
const SMITHERY_REGISTRY_BASE_URL = "https://registry.smithery.ai";
const SMITHERY_REGISTRY_TIMEOUT_MS = 10000;
export class SmitheryRegistryError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.name = "SmitheryRegistryError";
        this.status = status;
    }
}
function clampLimit(limit) {
    if (!limit || Number.isNaN(limit))
        return 20;
    if (limit < 1)
        return 1;
    if (limit > 100)
        return 100;
    return Math.trunc(limit);
}
function matchesIdentityQuery(query, entry) {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery)
        return true;
    const displayName = entry.displayName?.toLowerCase() ?? "";
    const qualifiedName = entry.qualifiedName?.toLowerCase() ?? "";
    return displayName.includes(normalizedQuery) || qualifiedName.includes(normalizedQuery);
}
function resolveDetailPathCandidates(entry) {
    const candidates = [];
    const pushUnique = (value) => {
        if (!value)
            return;
        if (!candidates.includes(value))
            candidates.push(value);
    };
    if (entry.namespace && entry.slug) {
        pushUnique(`${entry.namespace}/${entry.slug}`);
    }
    if (entry.slug) {
        pushUnique(entry.slug);
    }
    const qualifiedName = entry.qualifiedName?.trim();
    if (qualifiedName) {
        pushUnique(qualifiedName.replace(/^@/, ""));
    }
    return candidates;
}
function getEntryIdentityKey(entry) {
    const candidates = resolveDetailPathCandidates(entry);
    if (candidates.length > 0) {
        return candidates[0] ?? null;
    }
    if (entry.id)
        return `id:${entry.id}`;
    return null;
}
function toConfigNameFromQualifiedName(qualifiedName) {
    const normalized = qualifiedName
        .toLowerCase()
        .replace(/^@/, "")
        .replace(/\//g, "-")
        .replace(/[^a-z0-9_.-]+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-+|-+$/g, "");
    return normalized.length > 0 ? normalized : "mcp-server";
}
function normalizeQualifiedName(value) {
    return value.startsWith("@") ? value : `@${value}`;
}
function scalarToString(value) {
    if (typeof value === "string")
        return value;
    if (typeof value === "number" || typeof value === "boolean")
        return String(value);
    return undefined;
}
function unknownToString(value) {
    if (value === null || value === undefined)
        return undefined;
    if (typeof value === "string")
        return value;
    if (typeof value === "number" || typeof value === "boolean")
        return String(value);
    try {
        return JSON.stringify(value);
    }
    catch {
        return undefined;
    }
}
function safeMetadataValue(value) {
    const raw = unknownToString(value);
    if (!raw)
        return undefined;
    const normalized = raw
        .replace(/[\r\n\t]+/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    return normalized.length > 0 ? normalized : undefined;
}
function toDateLabel(value) {
    if (!value)
        return undefined;
    const date = new Date(value);
    if (Number.isNaN(date.getTime()))
        return undefined;
    return date.toISOString().slice(0, 10);
}
function getToolsList(tools) {
    if (!Array.isArray(tools))
        return [];
    const output = [];
    for (const item of tools) {
        const tool = item;
        const name = safeMetadataValue(tool.name);
        if (!name)
            continue;
        const description = safeMetadataValue(tool.description);
        const params = tool.inputSchema?.properties ? Object.keys(tool.inputSchema.properties) : [];
        output.push({
            name,
            description,
            params,
        });
    }
    return output;
}
function getInputType(propertyType) {
    if (propertyType === "number" || propertyType === "integer")
        return "number";
    if (propertyType === "boolean")
        return "boolean";
    return "string";
}
function isSensitiveInput(key, format) {
    if (format?.toLowerCase() === "password")
        return true;
    return /(api[_-]?key|token|secret|password)/i.test(key);
}
function getSchemaInputs(schema) {
    const required = new Set(schema?.required ?? []);
    const properties = schema?.properties ?? {};
    const inputs = [];
    for (const [key, property] of Object.entries(properties)) {
        const type = getInputType(property.type);
        const enumValues = Array.isArray(property.enum)
            ? property.enum.map(scalarToString).filter((value) => Boolean(value))
            : undefined;
        inputs.push({
            key,
            label: key.replace(/[_-]+/g, " "),
            type,
            required: required.has(key),
            defaultValue: scalarToString(property.default),
            description: property.description,
            enumValues: enumValues && enumValues.length > 0 ? enumValues : undefined,
            sensitive: isSensitiveInput(key, property.format),
        });
    }
    return inputs;
}
function chooseConnection(details) {
    const connections = details.connections ?? [];
    const httpConnection = connections.find(connection => connection.type === "http" && !!connection.deploymentUrl);
    if (httpConnection) {
        const hasConfigInputs = getSchemaInputs(httpConnection.configSchema).length > 0;
        if (!hasConfigInputs) {
            return { connection: httpConnection, useDirectHttp: true };
        }
    }
    const stdioConnection = connections.find(connection => connection.type === "stdio");
    if (stdioConnection) {
        return { connection: stdioConnection, useDirectHttp: false };
    }
    if (httpConnection) {
        return { connection: httpConnection, useDirectHttp: false };
    }
    return null;
}
function createConfig(qualifiedName, selected) {
    if (selected.useDirectHttp && selected.connection.type === "http" && selected.connection.deploymentUrl) {
        return {
            type: "http",
            url: selected.connection.deploymentUrl,
        };
    }
    return {
        type: "stdio",
        command: "bunx",
        args: ["-y", "@smithery/cli", "run", normalizeQualifiedName(qualifiedName), "--config", "{}"],
    };
}
async function fetchServerDetails(path, options) {
    const headers = new Headers();
    if (options?.apiKey) {
        headers.set("Authorization", `Bearer ${options.apiKey}`);
    }
    const response = await fetch(`${SMITHERY_REGISTRY_BASE_URL}/servers/${path}`, {
        headers,
        signal: withTimeoutSignal(SMITHERY_REGISTRY_TIMEOUT_MS, options?.signal),
    });
    if (!response.ok)
        return null;
    return (await response.json());
}
async function fetchServerDetailsFromEntry(entry, options) {
    const candidates = resolveDetailPathCandidates(entry);
    for (const candidate of candidates) {
        try {
            const details = await fetchServerDetails(candidate, options);
            if (details)
                return details;
        }
        catch (error) {
            if (options?.signal?.aborted)
                throw error;
            logger.debug("Smithery detail fetch candidate failed", { candidate, error: String(error) });
        }
    }
    return null;
}
function toSearchResult(entry, details) {
    if (!entry.id)
        return null;
    const qualifiedName = normalizeQualifiedName(details.qualifiedName ?? entry.qualifiedName ?? `${entry.namespace}/${entry.slug}`);
    const selected = chooseConnection(details);
    if (!selected)
        return null;
    const config = createConfig(qualifiedName, selected);
    if (!config)
        return null;
    const requiredInputs = getSchemaInputs(selected.connection.configSchema);
    const warnings = [];
    if (config.type === "stdio") {
        warnings.push("Runs through Smithery CLI at runtime (`bunx @smithery/cli run ...`).");
    }
    if (requiredInputs.length > 0) {
        warnings.push("Provider requires configuration input defined by Smithery schema.");
    }
    const displayName = safeMetadataValue(details.displayName ?? entry.displayName) ?? qualifiedName.replace(/^@/, "");
    const description = safeMetadataValue(details.description ?? entry.description) ?? "No description";
    const connectionType = safeMetadataValue(selected.connection.type) ?? "unknown";
    const transport = safeMetadataValue(config.type ?? "stdio") ?? "stdio";
    const createdAt = toDateLabel(entry.createdAt);
    const homepage = safeMetadataValue(entry.homepage);
    const tools = getToolsList(details.tools);
    return {
        id: entry.id,
        name: qualifiedName.replace(/^@/, ""),
        title: details.displayName ?? entry.displayName,
        description: details.description ?? entry.description,
        score: entry.score,
        useCount: entry.useCount,
        display: {
            displayName,
            description,
            useCount: entry.useCount ?? 0,
            verified: entry.verified === true,
            deployed: entry.isDeployed === true,
            transport,
            connectionType,
            createdAt,
            homepage,
            tools,
        },
        sourceType: selected.useDirectHttp || details.remote ? "remote" : "package",
        config,
        requiredInputs,
        warnings,
    };
}
export async function searchSmitheryRegistry(keyword, options) {
    const query = keyword.trim();
    if (!query)
        return [];
    const limit = clampLimit(options?.limit);
    const isSemantic = options?.includeSemantic === true;
    const pageSize = Math.max(limit * 2, 20);
    const headers = new Headers();
    if (options?.apiKey) {
        headers.set("Authorization", `Bearer ${options.apiKey}`);
    }
    // Fetch pages until we have enough filtered entries or run out of results.
    const maxPages = 3;
    const allEntries = [];
    for (let page = 1; page <= maxPages; page++) {
        const url = new URL(`${SMITHERY_REGISTRY_BASE_URL}/servers`);
        url.searchParams.set("q", query);
        url.searchParams.set("pageSize", String(pageSize));
        if (page > 1)
            url.searchParams.set("page", String(page));
        let response;
        try {
            response = await fetch(url.toString(), {
                headers,
                signal: withTimeoutSignal(SMITHERY_REGISTRY_TIMEOUT_MS, options?.signal),
            });
        }
        catch (err) {
            if (isTimeoutError(err)) {
                throw new SmitheryRegistryError("Smithery search timed out after 10s", 0);
            }
            throw err;
        }
        if (!response.ok) {
            throw new SmitheryRegistryError(`Smithery search failed with status ${response.status}`, response.status);
        }
        const payload = (await response.json());
        const pageEntries = payload.servers ?? [];
        if (pageEntries.length === 0)
            break;
        allEntries.push(...pageEntries);
        // Stop early if we already have enough identity-matching entries.
        const filtered = isSemantic ? allEntries : allEntries.filter(entry => matchesIdentityQuery(query, entry));
        if (filtered.length >= limit * 2)
            break;
        if (pageEntries.length < pageSize)
            break;
    }
    const entries = isSemantic ? [...allEntries] : [...allEntries].filter(entry => matchesIdentityQuery(query, entry));
    // Only apply local useCount sort when not in semantic mode (preserve API relevance ranking).
    if (!isSemantic) {
        entries.sort((a, b) => (b.useCount ?? 0) - (a.useCount ?? 0));
    }
    const uniqueEntries = entries.filter((entry, index) => {
        const identity = getEntryIdentityKey(entry);
        if (!identity)
            return false;
        return (entries.findIndex(candidate => {
            const candidateIdentity = getEntryIdentityKey(candidate);
            return candidateIdentity === identity;
        }) === index);
    });
    const detailFailures = [];
    const results = await Promise.all(uniqueEntries.map(async (entry) => {
        try {
            const details = await fetchServerDetailsFromEntry(entry, {
                apiKey: options?.apiKey,
                signal: options?.signal,
            });
            if (!details)
                return null;
            return toSearchResult(entry, details);
        }
        catch (error) {
            if (options?.signal?.aborted)
                throw error;
            detailFailures.push({
                identity: getEntryIdentityKey(entry) ?? entry.id ?? "unknown",
                error: String(error),
            });
            return null;
        }
    }));
    if (detailFailures.length > 0) {
        logger.warn("Smithery detail fetch failed for some entries", {
            query,
            failedEntries: detailFailures.length,
            totalEntries: uniqueEntries.length,
            sample: detailFailures.slice(0, 3),
        });
    }
    return results.filter((result) => result !== null).slice(0, limit);
}
export function toConfigName(candidate) {
    return toConfigNameFromQualifiedName(candidate);
}
