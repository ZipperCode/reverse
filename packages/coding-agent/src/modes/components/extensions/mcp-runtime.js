import { loadAllMCPConfigs } from "../../../mcp/config";
/**
 * After `/extensions` persists an MCP enable/disable, apply the same live
 * connect/disconnect + session tool refresh that `/mcp enable` / `/mcp disable`
 * already do. Config persistence stays in `setMcpServerEnabled`.
 */
export async function applyMcpToggleRuntime(options) {
    const { name, enabled, cwd, manager, session, discovery, loadConfigs = loadAllMCPConfigs, onStatus } = options;
    if (!manager)
        return;
    if (!enabled) {
        await manager.disconnectServer(name);
        await session?.refreshMCPTools(manager.getTools());
        return;
    }
    if (manager.getConnectionStatus(name) !== "disconnected") {
        await session?.refreshMCPTools(manager.getTools());
        return;
    }
    const { configs, sources } = await loadConfigs(cwd, discovery);
    const config = configs[name];
    if (!config) {
        await session?.refreshMCPTools(manager.getTools());
        return;
    }
    const source = sources[name];
    await manager.connectServers({ [name]: config }, source ? { [name]: source } : {}, onStatus);
    await session?.refreshMCPTools(manager.getTools());
}
