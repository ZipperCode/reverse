/**
 * MCP tool cache.
 *
 * Stores tool definitions per server in agent.db for fast startup.
 */
import { isRecord, logger, stableStringifyJson } from "@rva/utils";
const CACHE_VERSION = 1;
const CACHE_PREFIX = "mcp_tools:";
const CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
function hashConfig(config) {
    return Bun.SHA256.hash(stableStringifyJson(config), "hex");
}
function cacheKey(serverName) {
    return `${CACHE_PREFIX}${serverName}`;
}
export class MCPToolCache {
    storage;
    constructor(storage) {
        this.storage = storage;
    }
    async get(serverName, config) {
        const key = cacheKey(serverName);
        const raw = this.storage.getCache(key);
        if (!raw)
            return null;
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch (error) {
            logger.warn("MCP tool cache parse failed", { serverName, error: String(error) });
            return null;
        }
        if (!isRecord(parsed))
            return null;
        if (parsed.version !== CACHE_VERSION)
            return null;
        if (typeof parsed.configHash !== "string")
            return null;
        if (!Array.isArray(parsed.tools))
            return null;
        let currentHash;
        try {
            currentHash = hashConfig(config);
        }
        catch (error) {
            logger.warn("MCP tool cache hash failed", { serverName, error: String(error) });
            return null;
        }
        if (parsed.configHash !== currentHash)
            return null;
        return parsed.tools;
    }
    async set(serverName, config, tools) {
        let configHash;
        try {
            configHash = hashConfig(config);
        }
        catch (error) {
            logger.warn("MCP tool cache hash failed", { serverName, error: String(error) });
            return;
        }
        const payload = {
            version: CACHE_VERSION,
            configHash,
            tools,
        };
        let serialized;
        try {
            serialized = JSON.stringify(payload);
        }
        catch (error) {
            logger.warn("MCP tool cache serialize failed", { serverName, error: String(error) });
            return;
        }
        const expiresAtSec = Math.floor((Date.now() + CACHE_TTL_MS) / 1000);
        this.storage.setCache(cacheKey(serverName), serialized, expiresAtSec);
    }
}
