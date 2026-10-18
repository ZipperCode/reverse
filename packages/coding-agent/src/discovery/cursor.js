/**
 * Cursor Provider
 *
 * Loads configuration from Cursor's config directories.
 * Priority: 50 (tool-specific provider)
 *
 * Sources:
 * - User: ~/.cursor
 * - Project: .cursor/ (cwd only)
 *
 * Capabilities:
 * - mcps: From mcp.json with mcpServers key
 * - rules: From rules/*.mdc files with MDC frontmatter (description, globs, alwaysApply)
 * - settings: From settings.json if present
 */
import { tryParseJson } from "@rva/utils";
import { registerProvider } from "../capability";
import { readFile } from "../capability/fs";
import { mcpCapability } from "../capability/mcp";
import { ruleCapability } from "../capability/rule";
import { settingsCapability } from "../capability/settings";
import { discoverRuleFromMarkdown, createSourceMeta, expandEnvVarsDeep, getProjectPath, getUserPath, loadFilesFromDir, } from "./helpers";
const PROVIDER_ID = "cursor";
const DISPLAY_NAME = "Cursor";
const PRIORITY = 50;
// =============================================================================
// MCP Servers
// =============================================================================
function parseMCPServers(content, path, level) {
    const items = [];
    const parsed = tryParseJson(content);
    if (!parsed?.mcpServers) {
        return { items, warning: `${path}: missing or invalid 'mcpServers' key` };
    }
    const servers = expandEnvVarsDeep(parsed.mcpServers);
    for (const [name, config] of Object.entries(servers)) {
        const serverConfig = config;
        items.push({
            name,
            enabled: typeof serverConfig.enabled === "boolean" ? serverConfig.enabled : undefined,
            command: serverConfig.command,
            args: serverConfig.args,
            env: serverConfig.env,
            url: serverConfig.url,
            headers: serverConfig.headers,
            transport: ["stdio", "sse", "http"].includes(serverConfig.type)
                ? serverConfig.type
                : undefined,
            timeout: typeof serverConfig.timeout === "number" ? serverConfig.timeout : undefined,
            _source: createSourceMeta(PROVIDER_ID, path, level),
        });
    }
    return { items };
}
async function loadMCPServers(ctx) {
    const items = [];
    const warnings = [];
    const userPath = getUserPath(ctx, "cursor", "mcp.json");
    const [userContent, projectPath] = await Promise.all([
        userPath ? readFile(userPath) : Promise.resolve(null),
        getProjectPath(ctx, "cursor", "mcp.json"),
    ]);
    const projectContentPromise = projectPath ? readFile(projectPath) : Promise.resolve(null);
    // Load project entries before user entries so a project `enabled: false`
    // claims its dedupe key before a same-named user server can survive (#7654).
    const projectContent = await projectContentPromise;
    if (projectContent && projectPath) {
        const result = parseMCPServers(projectContent, projectPath, "project");
        items.push(...result.items);
        if (result.warning)
            warnings.push(result.warning);
    }
    if (userContent && userPath) {
        const result = parseMCPServers(userContent, userPath, "user");
        items.push(...result.items);
        if (result.warning)
            warnings.push(result.warning);
    }
    return { items, warnings };
}
// =============================================================================
// Rules
// =============================================================================
async function loadRules(ctx) {
    const items = [];
    const warnings = [];
    const userRulesPath = getUserPath(ctx, "cursor", "rules");
    const projectRulesPath = getProjectPath(ctx, "cursor", "rules");
    const [userResult, projectResult] = await Promise.all([
        userRulesPath
            ? loadFilesFromDir(ctx, userRulesPath, PROVIDER_ID, "user", {
                extensions: ["mdc", "md"],
                transform: transformMDCRule,
            })
            : Promise.resolve({ items: [], warnings: undefined }),
        projectRulesPath
            ? loadFilesFromDir(ctx, projectRulesPath, PROVIDER_ID, "project", {
                extensions: ["mdc", "md"],
                transform: transformMDCRule,
            })
            : Promise.resolve({ items: [], warnings: undefined }),
    ]);
    items.push(...userResult.items);
    if (userResult.warnings)
        warnings.push(...userResult.warnings);
    items.push(...projectResult.items);
    if (projectResult.warnings)
        warnings.push(...projectResult.warnings);
    return { items, warnings };
}
function transformMDCRule(name, content, path, source) {
    return discoverRuleFromMarkdown(name, content, path, source, { stripNamePattern: /\.(mdc|md)$/ });
}
// =============================================================================
// Settings
// =============================================================================
async function loadSettings(ctx) {
    const items = [];
    const warnings = [];
    const userPath = getUserPath(ctx, "cursor", "settings.json");
    const [userContent, projectPath] = await Promise.all([
        userPath ? readFile(userPath) : Promise.resolve(null),
        getProjectPath(ctx, "cursor", "settings.json"),
    ]);
    const projectContentPromise = projectPath ? readFile(projectPath) : Promise.resolve(null);
    if (userContent && userPath) {
        const parsed = tryParseJson(userContent);
        if (parsed) {
            items.push({
                path: userPath,
                data: parsed,
                level: "user",
                _source: createSourceMeta(PROVIDER_ID, userPath, "user"),
            });
        }
        else {
            warnings.push(`${userPath}: invalid JSON`);
        }
    }
    const projectContent = await projectContentPromise;
    if (projectContent && projectPath) {
        const parsed = tryParseJson(projectContent);
        if (parsed) {
            items.push({
                path: projectPath,
                data: parsed,
                level: "project",
                _source: createSourceMeta(PROVIDER_ID, projectPath, "project"),
            });
        }
        else {
            warnings.push(`${projectPath}: invalid JSON`);
        }
    }
    return { items, warnings };
}
// =============================================================================
// Provider Registration
// =============================================================================
registerProvider(mcpCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load MCP servers from ~/.cursor/mcp.json and .cursor/mcp.json",
    priority: PRIORITY,
    load: loadMCPServers,
});
registerProvider(ruleCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load rules from .cursor/rules/*.mdc and legacy .cursorrules",
    priority: PRIORITY,
    load: loadRules,
});
registerProvider(settingsCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load settings from ~/.cursor/settings.json and .cursor/settings.json",
    priority: PRIORITY,
    load: loadSettings,
});
