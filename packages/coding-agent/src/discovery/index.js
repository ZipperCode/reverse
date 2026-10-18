/**
 * Discovery Module
 *
 * Auto-registers all providers by importing them.
 * Import this module to ensure all providers are registered with the capability registry.
 */
// Import capability definitions (ensures capabilities are defined before providers register)
import "../capability/context-file";
import "../capability/extension";
import "../capability/extension-module";
import "../capability/hook";
import "../capability/instruction";
import "../capability/mcp";
import "../capability/prompt";
import "../capability/rule";
import "../capability/settings";
import "../capability/skill";
import "../capability/slash-command";
import "../capability/ssh";
import "../capability/system-prompt";
import "../capability/tool";
// Import providers (each registers itself on import)
import "./agent-plugins";
import "./agents-md";
import "./claude-md";
import "./custom-context-files";
import "./builtin";
import "./builtin-defaults";
import "./builtin-skills";
import "./claude";
import "./claude-plugins";
import "./cline";
import "./agents";
import "./codex";
import "./cursor";
import "./gemini";
import "./opencode";
import "./github";
import "./mcp-json";
import "./rva-plugins";
import "./skillshare";
import "./ssh";
import "./vscode";
import "./windsurf";
// Re-export the main API from capability registry
export { cacheStats, 
// Provider management
disableProvider, disableUserSource, enableProvider, enableUserSource, getAllCapabilitiesInfo, getAllProvidersInfo, 
// Introspection
getCapability, getCapabilityInfo, getDisabledProviders, getEnabledProviders, getProviderInfo, 
// Initialization
initializeWithSettings, invalidate, isForeignUserProvider, isProviderEnabled, isUserSourceEnabled, listCapabilities, 
// Loading API
loadCapability, 
// Cache management
reset, resetCapabilityForTests, setDisabledProviders, setEnabledProviders, } from "../capability";
