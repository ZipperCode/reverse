/**
 * Codex Discovery Provider
 *
 * Loads configuration from OpenAI Codex format:
 * - System Instructions: AGENTS.md (user-level only at ~/.codex/AGENTS.md)
 *
 * User directory: ~/.codex
 */
import * as path from "node:path";
import { logger, parseFrontmatter } from "@rva/utils";
import { isUserSourceEnabled, registerProvider } from "../capability";
import { contextFileCapability } from "../capability/context-file";
import { extensionModuleCapability } from "../capability/extension-module";
import { readFile } from "../capability/fs";
import { hookCapability } from "../capability/hook";
import { mcpCapability } from "../capability/mcp";
import { promptCapability } from "../capability/prompt";
import { settingsCapability } from "../capability/settings";
import { settings as activeSettings } from "../config/settings";
import { skillCapability } from "../capability/skill";
import { slashCommandCapability } from "../capability/slash-command";
import { systemPromptCapability } from "../capability/system-prompt";
import { slashCommandFrontmatterDisplay } from "@rva/tui/overlays/extensions/inspector-model";
import { toolCapability } from "../capability/tool";
import { buildExtensionModuleItems, createSourceMeta, discoverExtensionModulePaths, loadFilesFromDir, SOURCE_PATHS, scanSkillsFromDir, } from "./helpers";
import { resolvePluginStdioPaths } from "./substitute-plugin-root";
import { cfgSkillsEnableCodexUser } from "../extensibility/settings";
const PROVIDER_ID = "codex";
const DISPLAY_NAME = "OpenAI Codex";
const PRIORITY = 70;
function getProjectCodexDir(ctx) {
    return path.join(ctx.cwd, ".codex");
}
/**
 * `~/.codex`, or null when not opted in. `capabilityToggle` is a legacy
 * per-capability opt-in (`skills.enableCodexUser`) admitting only that
 * capability's directory.
 */
function getUserCodexDir(ctx, capabilityToggle = false) {
    if (!capabilityToggle && !isUserSourceEnabled("codex", ctx))
        return null;
    return path.join(ctx.home, SOURCE_PATHS.codex.userBase);
}
/** Legacy `skills.enableCodexUser` toggle; off by default and without initialized settings. */
function readCodexUserSkillsToggle() {
    try {
        return cfgSkillsEnableCodexUser.get(activeSettings) === true;
    }
    catch {
        return false;
    }
}
// =============================================================================
// Context Files (AGENTS.md)
// =============================================================================
async function loadContextFiles(ctx) {
    const items = [];
    const warnings = [];
    const userDir = getUserCodexDir(ctx);
    if (!userDir)
        return { items, warnings };
    // User level only: ~/.codex/AGENTS.md
    const agentsMd = path.join(userDir, "AGENTS.md");
    const agentsContent = await readFile(agentsMd);
    if (agentsContent) {
        items.push({
            path: agentsMd,
            content: agentsContent,
            level: "user",
            _source: createSourceMeta(PROVIDER_ID, agentsMd, "user"),
        });
    }
    return { items, warnings };
}
// =============================================================================
// MCP Servers (config.toml)
// =============================================================================
async function loadMCPServers(ctx) {
    const warnings = [];
    const userDir = getUserCodexDir(ctx);
    const userConfigPath = userDir ? path.join(userDir, "config.toml") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectConfigPath = path.join(codexDir, "config.toml");
    const [userConfig, projectConfig] = await Promise.all([
        userConfigPath ? loadTomlConfig(ctx, userConfigPath) : Promise.resolve(null),
        loadTomlConfig(ctx, projectConfigPath),
    ]);
    const items = [];
    // Capability dedupe is first-wins, including suppressed items claiming their
    // key. Load project entries first so a project `enabled = false` keeps a
    // same-named user server disabled.
    if (projectConfig) {
        const servers = extractMCPServersFromToml(projectConfig, path.dirname(projectConfigPath));
        for (const name in servers) {
            const config = servers[name];
            items.push({
                name,
                ...config,
                _source: createSourceMeta(PROVIDER_ID, projectConfigPath, "project"),
            });
        }
    }
    if (userConfig && userConfigPath) {
        const servers = extractMCPServersFromToml(userConfig, path.dirname(userConfigPath));
        for (const name in servers) {
            const config = servers[name];
            items.push({
                name,
                ...config,
                _source: createSourceMeta(PROVIDER_ID, userConfigPath, "user"),
            });
        }
    }
    return { items, warnings };
}
async function loadTomlConfig(_ctx, path) {
    const content = await readFile(path);
    if (!content)
        return null;
    try {
        return Bun.TOML.parse(content);
    }
    catch (error) {
        logger.warn("Failed to parse TOML config", { path, error: String(error) });
        return null;
    }
}
function extractMCPServersFromToml(toml, configDir) {
    // Check for [mcp_servers.*] sections (Codex format)
    if (!toml.mcp_servers || typeof toml.mcp_servers !== "object") {
        return {};
    }
    const codexServers = toml.mcp_servers;
    const result = {};
    for (const name in codexServers) {
        const config = codexServers[name];
        // Root relative cwd/command against the Codex config directory. Codex
        // spawns the process with the resolved cwd, so a relative command is
        // resolved by the OS from there — pass "cwd" so e.g. cwd="server",
        // command="./bin/mcp" resolves to <configDir>/server/bin/mcp.
        const rooted = resolvePluginStdioPaths({ command: config.command, cwd: config.cwd }, configDir, "cwd");
        const server = {
            // Carry `enabled: false` through rather than dropping the entry: the
            // central MCP loader (`loadAllMCPConfigs`) suppresses disabled servers
            // so they still claim their dedupe key (keeping a same-named,
            // lower-priority source disabled) and remain overridable via the user
            // force-enable allowlist. Dropping here would defeat both.
            ...(config.enabled === false && { enabled: false }),
            ...(rooted.command !== undefined && { command: rooted.command }),
            args: config.args,
            url: config.url,
            ...(rooted.cwd !== undefined && { cwd: rooted.cwd }),
        };
        // Build env by merging explicit env and forwarded env_vars
        const env = { ...config.env };
        if (config.env_vars) {
            for (const varName of config.env_vars) {
                const value = Bun.env[varName];
                if (value !== undefined) {
                    env[varName] = value;
                }
            }
        }
        if (Object.keys(env).length > 0) {
            server.env = env;
        }
        // Build headers from http_headers, env_http_headers, and bearer_token_env_var
        const headers = { ...config.http_headers };
        if (config.env_http_headers) {
            for (const [headerName, envVarName] of Object.entries(config.env_http_headers)) {
                const value = Bun.env[envVarName];
                if (value !== undefined) {
                    headers[headerName] = value;
                }
            }
        }
        if (config.bearer_token_env_var) {
            const token = Bun.env[config.bearer_token_env_var];
            if (token) {
                headers.Authorization = `Bearer ${token}`;
            }
        }
        if (Object.keys(headers).length > 0) {
            server.headers = headers;
        }
        // Determine transport type (infer from config if not explicit)
        if (config.url) {
            server.transport = "http";
        }
        else if (config.command) {
            server.transport = "stdio";
        }
        // Note: validation of transport vs endpoint is handled by mcpCapability.validate()
        // Map Codex tool_timeout_sec (seconds) to MCPServer timeout (milliseconds)
        if (typeof config.tool_timeout_sec === "number" && config.tool_timeout_sec > 0) {
            server.timeout = config.tool_timeout_sec * 1000;
        }
        result[name] = server;
    }
    return result;
}
// =============================================================================
// Skills (skills/)
// =============================================================================
async function loadSkills(ctx) {
    const userDir = getUserCodexDir(ctx, readCodexUserSkillsToggle());
    const userSkillsDir = userDir ? path.join(userDir, "skills") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectSkillsDir = path.join(codexDir, "skills");
    const results = await Promise.all([
        userSkillsDir
            ? scanSkillsFromDir(ctx, {
                dir: userSkillsDir,
                providerId: PROVIDER_ID,
                level: "user",
            })
            : Promise.resolve({ items: [], warnings: [] }),
        scanSkillsFromDir(ctx, {
            dir: projectSkillsDir,
            providerId: PROVIDER_ID,
            level: "project",
        }),
    ]);
    const items = results.flatMap(r => r.items);
    const warnings = results.flatMap(r => r.warnings || []);
    return { items, warnings };
}
// =============================================================================
// Extension Modules (extensions/)
// =============================================================================
async function loadExtensionModules(ctx) {
    const warnings = [];
    const userDir = getUserCodexDir(ctx);
    const userExtensionsDir = userDir ? path.join(userDir, "extensions") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectExtensionsDir = path.join(codexDir, "extensions");
    const [userPaths, projectPaths] = await Promise.all([
        userExtensionsDir ? discoverExtensionModulePaths(ctx, userExtensionsDir) : Promise.resolve([]),
        discoverExtensionModulePaths(ctx, projectExtensionsDir),
    ]);
    const items = buildExtensionModuleItems(PROVIDER_ID, userPaths, projectPaths);
    return { items, warnings };
}
// =============================================================================
// Slash Commands (commands/)
// =============================================================================
async function loadSlashCommands(ctx) {
    const userDir = getUserCodexDir(ctx);
    const userCommandsDir = userDir ? path.join(userDir, "commands") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectCommandsDir = path.join(codexDir, "commands");
    const transformCommand = (level) => (name, content, path, source) => {
        const { frontmatter, body } = parseFrontmatter(content, { source: path });
        const commandName = frontmatter.name || name.replace(/\.md$/, "");
        return {
            name: String(commandName),
            path,
            content: body,
            ...slashCommandFrontmatterDisplay(frontmatter),
            level,
            _source: source,
        };
    };
    const results = await Promise.all([
        userCommandsDir
            ? loadFilesFromDir(ctx, userCommandsDir, PROVIDER_ID, "user", {
                extensions: ["md"],
                transform: transformCommand("user"),
            })
            : Promise.resolve({ items: [], warnings: [] }),
        loadFilesFromDir(ctx, projectCommandsDir, PROVIDER_ID, "project", {
            extensions: ["md"],
            transform: transformCommand("project"),
        }),
    ]);
    const items = results.flatMap(r => r.items);
    const warnings = results.flatMap(r => r.warnings || []);
    return { items, warnings };
}
// =============================================================================
// Prompts (prompts/*.md)
// =============================================================================
async function loadPrompts(ctx) {
    const userDir = getUserCodexDir(ctx);
    const userPromptsDir = userDir ? path.join(userDir, "prompts") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectPromptsDir = path.join(codexDir, "prompts");
    const transformPrompt = (name, content, path, source) => {
        const { frontmatter, body } = parseFrontmatter(content, { source: path });
        const promptName = frontmatter.name || name.replace(/\.md$/, "");
        return {
            name: String(promptName),
            path,
            content: body,
            description: frontmatter.description ? String(frontmatter.description) : undefined,
            _source: source,
        };
    };
    const results = await Promise.all([
        userPromptsDir
            ? loadFilesFromDir(ctx, userPromptsDir, PROVIDER_ID, "user", {
                extensions: ["md"],
                transform: transformPrompt,
            })
            : Promise.resolve({ items: [], warnings: [] }),
        loadFilesFromDir(ctx, projectPromptsDir, PROVIDER_ID, "project", {
            extensions: ["md"],
            transform: transformPrompt,
        }),
    ]);
    const items = results.flatMap(r => r.items);
    const warnings = results.flatMap(r => r.warnings || []);
    return { items, warnings };
}
// =============================================================================
// Hooks (hooks/)
// =============================================================================
async function loadHooks(ctx) {
    const userDir = getUserCodexDir(ctx);
    const userHooksDir = userDir ? path.join(userDir, "hooks") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectHooksDir = path.join(codexDir, "hooks");
    // OMP hooks must be named `pre-<tool>.<ts|js>` or `post-<tool>.<ts|js>`.
    // Files without that prefix are not OMP hooks (e.g. the standalone Codex
    // hook scripts users keep alongside) — silently dropping the prefix and
    // defaulting to `pre:<basename>` caused those scripts to be imported as
    // extension factories and any top-level `process.exit()` killed startup
    // (#3680).
    const transformHook = (level) => (name, _content, path, source) => {
        const baseName = name.replace(/\.(ts|js)$/, "");
        const match = baseName.match(/^(pre|post)-(.+)$/);
        if (!match)
            return null;
        const hookType = match[1];
        const toolName = match[2];
        return {
            name,
            path,
            type: hookType,
            tool: toolName,
            level,
            _source: source,
        };
    };
    const results = await Promise.all([
        userHooksDir
            ? loadFilesFromDir(ctx, userHooksDir, PROVIDER_ID, "user", {
                extensions: ["ts", "js"],
                transform: transformHook("user"),
            })
            : Promise.resolve({ items: [], warnings: [] }),
        loadFilesFromDir(ctx, projectHooksDir, PROVIDER_ID, "project", {
            extensions: ["ts", "js"],
            transform: transformHook("project"),
        }),
    ]);
    const items = results.flatMap(r => r.items);
    const warnings = results.flatMap(r => r.warnings || []);
    return { items, warnings };
}
// =============================================================================
// Tools (tools/)
// =============================================================================
async function loadTools(ctx) {
    const userDir = getUserCodexDir(ctx);
    const userToolsDir = userDir ? path.join(userDir, "tools") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectToolsDir = path.join(codexDir, "tools");
    const transformTool = (level) => (name, _content, path, source) => {
        const toolName = name.replace(/\.(ts|js)$/, "");
        return {
            name: toolName,
            path,
            level,
            _source: source,
        };
    };
    const results = await Promise.all([
        userToolsDir
            ? loadFilesFromDir(ctx, userToolsDir, PROVIDER_ID, "user", {
                extensions: ["ts", "js"],
                transform: transformTool("user"),
            })
            : Promise.resolve({ items: [], warnings: [] }),
        loadFilesFromDir(ctx, projectToolsDir, PROVIDER_ID, "project", {
            extensions: ["ts", "js"],
            transform: transformTool("project"),
        }),
    ]);
    const items = results.flatMap(r => r.items);
    const warnings = results.flatMap(r => r.warnings || []);
    return { items, warnings };
}
// =============================================================================
// Settings (config.toml)
// =============================================================================
async function loadSettings(ctx) {
    const warnings = [];
    const userDir = getUserCodexDir(ctx);
    const userConfigPath = userDir ? path.join(userDir, "config.toml") : null;
    const codexDir = getProjectCodexDir(ctx);
    const projectConfigPath = path.join(codexDir, "config.toml");
    const [userConfig, projectConfig] = await Promise.all([
        userConfigPath ? loadTomlConfig(ctx, userConfigPath) : Promise.resolve(null),
        loadTomlConfig(ctx, projectConfigPath),
    ]);
    const items = [];
    if (userConfig && userConfigPath) {
        items.push({
            path: userConfigPath,
            data: userConfig,
            level: "user",
            _source: createSourceMeta(PROVIDER_ID, userConfigPath, "user"),
        });
    }
    if (projectConfig) {
        items.push({
            path: projectConfigPath,
            data: projectConfig,
            level: "project",
            _source: createSourceMeta(PROVIDER_ID, projectConfigPath, "project"),
        });
    }
    return { items, warnings };
}
// =============================================================================
// Provider Registration (executes on module import)
// =============================================================================
registerProvider(contextFileCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load context files from ~/.codex/AGENTS.md (user-level only)",
    priority: PRIORITY,
    load: loadContextFiles,
});
registerProvider(mcpCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load MCP servers from config.toml [mcp_servers.*] sections",
    priority: PRIORITY,
    load: loadMCPServers,
});
registerProvider(skillCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load skills from ~/.codex/skills and .codex/skills/",
    priority: PRIORITY,
    load: loadSkills,
});
registerProvider(extensionModuleCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load extension modules from ~/.codex/extensions and .codex/extensions/",
    priority: PRIORITY,
    load: loadExtensionModules,
});
registerProvider(slashCommandCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load slash commands from ~/.codex/commands and .codex/commands/",
    priority: PRIORITY,
    load: loadSlashCommands,
});
registerProvider(promptCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load prompts from ~/.codex/prompts and .codex/prompts/",
    priority: PRIORITY,
    load: loadPrompts,
});
registerProvider(hookCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load hooks from ~/.codex/hooks and .codex/hooks/",
    priority: PRIORITY,
    load: loadHooks,
});
registerProvider(toolCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load custom tools from ~/.codex/tools and .codex/tools/",
    priority: PRIORITY,
    load: loadTools,
});
registerProvider(settingsCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load settings from config.toml",
    priority: PRIORITY,
    load: loadSettings,
});
// System Prompt (SYSTEM.md, SYSTEM_TEMPLATE.md)
async function loadSystemPrompt(ctx) {
    const items = [];
    const load = async (filePath, level, kind) => {
        if (!filePath)
            return;
        const content = await readFile(filePath);
        if (content) {
            items.push({ path: filePath, content, kind, level, _source: createSourceMeta(PROVIDER_ID, filePath, level) });
        }
    };
    // Project entries first: dedupe is first-wins, so a project file claims its
    // key before a same-scope user file can survive.
    const projectDir = getProjectCodexDir(ctx);
    const userDir = getUserCodexDir(ctx);
    await load(path.join(projectDir, "SYSTEM_TEMPLATE.md"), "project", "template");
    await load(path.join(projectDir, "SYSTEM.md"), "project", "text");
    await load(userDir ? path.join(userDir, "SYSTEM_TEMPLATE.md") : null, "user", "template");
    await load(userDir ? path.join(userDir, "SYSTEM.md") : null, "user", "text");
    return { items, warnings: [] };
}
registerProvider(systemPromptCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load SYSTEM.md and SYSTEM_TEMPLATE.md from .codex (project cwd + user home)",
    priority: PRIORITY,
    load: loadSystemPrompt,
});
