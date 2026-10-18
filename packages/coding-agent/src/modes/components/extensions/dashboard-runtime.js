import { getMCPConfigPath } from "@rva/utils";
import { parseRuleAgents, parseRuleConditionAndScope } from "../../../capability/rule";
import { getAllProvidersInfo, isForeignUserProvider, isUserSourceEnabled } from "../../../discovery";
import { setMcpServerEnabled } from "../../../mcp/config-writer";
import { MCP_CONNECTION_STATUS_EVENT_CHANNEL } from "../../../mcp/startup-events";
import { toolFileHeaderDescription } from "./inspector-runtime";
import { applyMcpToggleRuntime } from "./mcp-runtime";
import { loadAllExtensions, toggleProvider, toggleUserSource } from "./state-manager";
import { cfgDisabledExtensions } from "../../../extensibility/settings";
import { cfgMcpEnableProjectConfig } from "../../../mcp/settings";
/** Bind the dashboard's display-only contract to the live application. */
export function createExtensionDashboardRuntime(options) {
    const { cwd, settings, mcpManager, eventBus, onMcpToolsChanged, browserMcpFilterEnabled } = options;
    return {
        getDisabledExtensions: () => cfgDisabledExtensions.get(settings),
        setDisabledExtensions: ids => cfgDisabledExtensions.set(settings, ids),
        getProviders: () => getAllProvidersInfo().map(provider => ({
            ...provider,
            userSourceEnabled: isUserSourceEnabled(provider.id),
            foreignUserSource: isForeignUserProvider(provider.id),
        })),
        loadExtensions: disabledIds => loadAllExtensions(cwd, disabledIds),
        toggleProvider,
        toggleUserSource,
        async persistMcpToggle(name, enabled, sourcePath) {
            await setMcpServerEnabled({
                userPath: getMCPConfigPath("user", cwd),
                projectPath: getMCPConfigPath("project", cwd),
                sourcePath,
                name,
                enabled,
            });
        },
        applyMcpToggle: (name, enabled) => applyMcpToggleRuntime({
            name,
            enabled,
            cwd,
            manager: mcpManager,
            session: onMcpToolsChanged ? { refreshMCPTools: onMcpToolsChanged } : undefined,
            discovery: {
                enableProjectConfig: cfgMcpEnableProjectConfig.get(settings),
                filterExa: true,
                filterBrowser: browserMcpFilterEnabled?.() ?? false,
            },
            onStatus: event => eventBus?.emit(MCP_CONNECTION_STATUS_EVENT_CHANNEL, event),
        }),
        subscribeMcpChanges(onChange) {
            const subscriptions = [];
            if (eventBus)
                subscriptions.push(eventBus.on(MCP_CONNECTION_STATUS_EVENT_CHANNEL, onChange));
            if (mcpManager)
                subscriptions.push(mcpManager.addNotificationListener(onChange), mcpManager.addConnectionStatusListener(onChange), mcpManager.addCatalogChangeListener(onChange));
            return subscriptions;
        },
        mcpSource: mcpManager,
        inspectorSource: {
            readToolHeader: toolFileHeaderDescription,
            parseRule: raw => ({ ...parseRuleConditionAndScope(raw), agents: parseRuleAgents(raw.agents) }),
        },
    };
}
