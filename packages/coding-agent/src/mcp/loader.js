/**
 * MCP tools loader.
 *
 * Integrates MCP tool discovery with the custom tools system.
 */
import { logger } from "@rva/utils";
import { AgentStorage } from "../session/agent-storage";
import { MCPManager } from "./manager";
import { MCPToolCache } from "./tool-cache";
async function resolveToolCache(storage) {
    if (storage === null)
        return null;
    try {
        const resolved = storage ?? (await AgentStorage.open());
        return new MCPToolCache(resolved);
    }
    catch (error) {
        logger.warn("MCP tool cache unavailable", { error: String(error) });
        return null;
    }
}
/**
 * Discover and load MCP tools from .mcp.json files.
 *
 * @param cwd Working directory (project root)
 * @param options Load options including progress callbacks
 * @returns MCP tools in LoadedCustomTool format for integration
 */
export async function discoverAndLoadMCPTools(cwd, options) {
    const toolCache = await resolveToolCache(options?.cacheStorage);
    const manager = new MCPManager(cwd, toolCache);
    if (options?.authStorage) {
        manager.setAuthStorage(options.authStorage);
    }
    let result;
    try {
        result = await manager.discoverAndConnect({
            onStatus: options?.onStatus,
            startupTimeoutMs: options?.startupTimeoutMs,
            enableProjectConfig: options?.enableProjectConfig,
            filterExa: options?.filterExa,
            filterBrowser: options?.filterBrowser,
        });
    }
    catch (error) {
        // If discovery fails entirely, return empty result
        const message = error instanceof Error ? error.message : String(error);
        return {
            manager,
            tools: [],
            errors: [{ path: ".mcp.json", error: message }],
            connectedServers: [],
            exaApiKeys: [],
        };
    }
    // Convert MCP tools to LoadedCustomTool format
    const loadedTools = result.tools.map(tool => {
        // MCPTool and DeferredMCPTool have these properties
        const mcpTool = tool;
        const serverName = mcpTool.mcpServerName;
        // Get provider info from manager's connection if available
        const connection = serverName ? manager.getConnection(serverName) : undefined;
        const source = serverName ? manager.getSource(serverName) : undefined;
        const providerName = connection?._source?.providerName ?? source?.providerName ?? connection?._source?.provider ?? source?.provider;
        // Format path with provider info if available
        // Format: "mcp:serverName via providerName" (e.g., "mcp:agentx via Claude Code")
        const path = serverName && providerName ? `mcp:${serverName} via ${providerName}` : `mcp:${tool.name}`;
        return {
            path,
            resolvedPath: `mcp:${tool.name}`,
            tool: tool, // MCPToolDetails is compatible with CustomTool<TSchema, any>
        };
    });
    // Convert error map to array format
    const errors = [];
    for (const [serverName, errorMsg] of result.errors) {
        errors.push({ path: `mcp:${serverName}`, error: errorMsg });
    }
    return {
        manager,
        tools: loadedTools,
        errors,
        connectedServers: result.connectedServers,
        exaApiKeys: result.exaApiKeys,
    };
}
