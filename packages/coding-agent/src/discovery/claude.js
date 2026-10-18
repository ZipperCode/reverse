/**
 * Claude Code Provider
 *
 * Loads configuration from .claude directories.
 * Priority: 80 (tool-specific, below builtin but above shared standards)
 */
import * as path from "node:path";
import { hasFsCode, tryParseJson } from "@rva/utils";
import { registerProvider } from "../capability";
import { isUserSourceEnabled } from "../capability";
import { contextFileCapability } from "../capability/context-file";
import { extensionModuleCapability } from "../capability/extension-module";
import { readFile } from "../capability/fs";
import { hookCapability } from "../capability/hook";
import { mcpCapability } from "../capability/mcp";
import { settingsCapability } from "../capability/settings";
import { skillCapability } from "../capability/skill";
import { slashCommandCapability } from "../capability/slash-command";
import { systemPromptCapability } from "../capability/system-prompt";
import { toolCapability } from "../capability/tool";
import { resolveClaudePaths } from "../config/claude-paths";
import { settings } from "../config/settings";
import { calculateDepth, createSourceMeta, discoverExtensionModulePaths, expandEnvVarsDeep, getExtensionNameFromPath, loadFilesFromDir, scanSkillsFromDir, } from "./helpers";
import { cfgCommandsEnableClaudeProject, cfgCommandsEnableClaudeUser, cfgSkillsEnableClaudeUser, } from "../extensibility/settings";
const PROVIDER_ID = "claude";
const DISPLAY_NAME = "Claude Code";
const PRIORITY = 80;
const CONFIG_DIR = ".claude";
/**
 * Read a legacy per-capability `~/.claude` toggle. Defaults to off (opt-in);
 * also off when settings are not initialized (discovery unit tests).
 */
function readClaudeUserToggle(toggle) {
    try {
        return toggle.get(settings) === true;
    }
    catch {
        return false;
    }
}
/**
 * Get the active user-level Claude Code directory, or null when `~/.claude`
 * is not opted in. `capabilityToggle` is a legacy per-capability opt-in
 * (`skills.enableClaudeUser`, `commands.enableClaudeUser`) that admits just
 * that capability's directory.
 */
function getUserClaude(ctx, capabilityToggle = false) {
    if (!capabilityToggle && !isUserSourceEnabled("claude", ctx))
        return null;
    const { configDir } = resolveClaudePaths(ctx.home);
    return configDir;
}
/**
 * Get project-level .claude path (cwd only).
 */
function getProjectClaude(ctx) {
    return path.join(ctx.cwd, CONFIG_DIR);
}
function isMissingDirectoryError(error) {
    return hasFsCode(error, "ENOENT") || hasFsCode(error, "ENOTDIR");
}
// =============================================================================
// MCP Servers
// =============================================================================
async function loadMCPServers(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    const userClaudeJson = userBase ? resolveClaudePaths(ctx.home).configFile : null;
    const userMcpJson = userBase ? path.join(userBase, "mcp.json") : null;
    const projectBase = path.join(ctx.cwd, CONFIG_DIR);
    const projectMcpJson = path.join(projectBase, ".mcp.json");
    const projectMcpJsonAlt = path.join(projectBase, "mcp.json");
    const userPaths = [
        ...(userClaudeJson ? [{ path: userClaudeJson, level: "user" }] : []),
        ...(userMcpJson ? [{ path: userMcpJson, level: "user" }] : []),
    ];
    const projectPaths = [
        { path: projectMcpJson, level: "project" },
        { path: projectMcpJsonAlt, level: "project" },
    ];
    const allPaths = [...userPaths, ...projectPaths];
    const contents = await Promise.all(allPaths.map(({ path }) => readFile(path)));
    const parseMcpServers = (content, path, level) => {
        if (!content)
            return [];
        const json = tryParseJson(content);
        if (!json?.mcpServers)
            return [];
        const mcpServers = expandEnvVarsDeep(json.mcpServers);
        return Object.entries(mcpServers).map(([name, config]) => {
            const serverConfig = config;
            return {
                name,
                enabled: typeof serverConfig.enabled === "boolean" ? serverConfig.enabled : undefined,
                timeout: typeof serverConfig.timeout === "number" ? serverConfig.timeout : undefined,
                command: serverConfig.command,
                args: serverConfig.args,
                env: serverConfig.env,
                url: serverConfig.url,
                headers: serverConfig.headers,
                transport: serverConfig.type,
                _source: createSourceMeta(PROVIDER_ID, path, level),
            };
        });
    };
    // Load project entries before user entries so a project `enabled: false`
    // claims its dedupe key before a same-named user server can survive (#7654).
    const projectOffset = userPaths.length;
    for (let i = 0; i < projectPaths.length; i++) {
        const servers = parseMcpServers(contents[projectOffset + i], projectPaths[i].path, projectPaths[i].level);
        if (servers.length > 0) {
            items.push(...servers);
            break;
        }
    }
    for (let i = 0; i < userPaths.length; i++) {
        const servers = parseMcpServers(contents[i], userPaths[i].path, userPaths[i].level);
        if (servers.length > 0) {
            items.push(...servers);
            break;
        }
    }
    return { items, warnings };
}
// =============================================================================
// Context Files (CLAUDE.md)
// =============================================================================
async function loadContextFiles(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    const userClaudeMd = userBase ? path.join(userBase, "CLAUDE.md") : null;
    const userContent = userClaudeMd ? await readFile(userClaudeMd) : null;
    if (userContent !== null && userClaudeMd) {
        items.push({
            path: userClaudeMd,
            content: userContent,
            level: "user",
            _source: createSourceMeta(PROVIDER_ID, userClaudeMd, "user"),
        });
    }
    const projectBase = getProjectClaude(ctx);
    const projectClaudeMd = path.join(projectBase, "CLAUDE.md");
    const projectContent = await readFile(projectClaudeMd);
    if (projectContent !== null) {
        const depth = calculateDepth(ctx.cwd, path.dirname(projectBase), path.sep);
        items.push({
            path: projectClaudeMd,
            content: projectContent,
            level: "project",
            depth,
            _source: createSourceMeta(PROVIDER_ID, projectClaudeMd, "project"),
        });
    }
    return { items, warnings };
}
// =============================================================================
// Skills
// =============================================================================
async function loadSkills(ctx) {
    const userBase = getUserClaude(ctx, readClaudeUserToggle(cfgSkillsEnableClaudeUser));
    const userSkillsDir = userBase ? path.join(userBase, "skills") : null;
    // Walk up from cwd finding .claude/skills/ in ancestors. Skip $HOME:
    // that path is already scanned as the Claude user source below, and scanning
    // it again as project would bypass enableClaudeUser when project skills stay enabled.
    const projectScans = [];
    let current = ctx.cwd;
    while (true) {
        if (current !== ctx.home) {
            projectScans.push(scanSkillsFromDir(ctx, {
                dir: path.join(current, CONFIG_DIR, "skills"),
                providerId: PROVIDER_ID,
                level: "project",
            }));
        }
        if (current === (ctx.repoRoot ?? ctx.home))
            break;
        const parent = path.dirname(current);
        if (parent === current)
            break; // filesystem root
        current = parent;
    }
    const userScanPromise = userSkillsDir
        ? scanSkillsFromDir(ctx, { dir: userSkillsDir, providerId: PROVIDER_ID, level: "user" })
        : Promise.resolve({ items: [], warnings: [] });
    const [userResult, ...projectResults] = await Promise.allSettled([userScanPromise, ...projectScans]);
    const items = [];
    const warnings = [];
    if (userResult.status === "fulfilled") {
        items.push(...userResult.value.items);
        warnings.push(...(userResult.value.warnings ?? []));
    }
    else if (userSkillsDir && !isMissingDirectoryError(userResult.reason)) {
        warnings.push(`Failed to scan Claude user skills in ${userSkillsDir}: ${String(userResult.reason)}`);
    }
    for (const projectResult of projectResults) {
        if (projectResult.status === "fulfilled") {
            items.push(...projectResult.value.items);
            warnings.push(...(projectResult.value.warnings ?? []));
        }
        else if (!isMissingDirectoryError(projectResult.reason)) {
            warnings.push(`Failed to scan Claude project skills: ${String(projectResult.reason)}`);
        }
    }
    return { items, warnings };
}
// =============================================================================
// Extension Modules
// =============================================================================
async function loadExtensionModules(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    const projectExtensionsDir = path.join(ctx.cwd, CONFIG_DIR, "extensions");
    const dirsToDiscover = [
        ...(userBase ? [{ dir: path.join(userBase, "extensions"), level: "user" }] : []),
        { dir: projectExtensionsDir, level: "project" },
    ];
    const pathsByLevel = await Promise.all(dirsToDiscover.map(async ({ dir, level }) => {
        const paths = await discoverExtensionModulePaths(ctx, dir);
        return paths.map(extPath => ({ extPath, level }));
    }));
    for (const extensions of pathsByLevel) {
        for (const { extPath, level } of extensions) {
            items.push({
                name: getExtensionNameFromPath(extPath),
                path: extPath,
                level,
                _source: createSourceMeta(PROVIDER_ID, extPath, level),
            });
        }
    }
    return { items, warnings };
}
// =============================================================================
// Slash Commands
// =============================================================================
/**
 * Read the project command-loading toggle. Falls back to true when settings
 * are not initialized, e.g. inside discovery unit tests without Settings.init().
 */
function readClaudeProjectCommandsToggle() {
    try {
        return cfgCommandsEnableClaudeProject.get(settings);
    }
    catch {
        return true;
    }
}
function getClaudeRelativeCommandName(commandsDir, filePath) {
    return path.relative(commandsDir, filePath).replace(/\.md$/, "");
}
function addClaudeCommandNamespaceAliases(commands, commandsDir) {
    const rootCommands = [];
    const nestedCommands = [];
    const aliases = [];
    for (const command of commands) {
        const relativeName = getClaudeRelativeCommandName(commandsDir, command.path);
        if (!/[\\/]/.test(relativeName)) {
            rootCommands.push(command);
            continue;
        }
        nestedCommands.push(command);
        aliases.push({ ...command, name: relativeName.replace(/[\\/]+/g, ":") });
    }
    return nestedCommands.length === 0 ? commands : [...rootCommands, ...nestedCommands, ...aliases];
}
async function loadSlashCommands(ctx) {
    const items = [];
    const warnings = [];
    const enableProject = readClaudeProjectCommandsToggle();
    const userBase = getUserClaude(ctx, readClaudeUserToggle(cfgCommandsEnableClaudeUser));
    if (userBase) {
        const userCommandsDir = path.join(userBase, "commands");
        const userResult = await loadFilesFromDir(ctx, userCommandsDir, PROVIDER_ID, "user", {
            extensions: ["md"],
            recursive: true,
            transform: (name, content, filePath, source) => ({
                name: name.replace(/\.md$/, ""),
                path: filePath,
                content,
                level: "user",
                _source: source,
            }),
        });
        items.push(...addClaudeCommandNamespaceAliases(userResult.items, userCommandsDir));
        if (userResult.warnings)
            warnings.push(...userResult.warnings);
    }
    if (enableProject) {
        const projectCommandsDir = path.join(ctx.cwd, CONFIG_DIR, "commands");
        const projectResult = await loadFilesFromDir(ctx, projectCommandsDir, PROVIDER_ID, "project", {
            extensions: ["md"],
            recursive: true,
            transform: (name, content, filePath, source) => ({
                name: name.replace(/\.md$/, ""),
                path: filePath,
                content,
                level: "project",
                _source: source,
            }),
        });
        items.push(...addClaudeCommandNamespaceAliases(projectResult.items, projectCommandsDir));
        if (projectResult.warnings)
            warnings.push(...projectResult.warnings);
    }
    return { items, warnings };
}
// =============================================================================
// Hooks
// =============================================================================
async function loadHooks(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    const projectBase = getProjectClaude(ctx);
    const projectHooksDir = path.join(projectBase, "hooks");
    const hookTypes = ["pre", "post"];
    const loadTasks = [];
    if (userBase) {
        const userHooksDir = path.join(userBase, "hooks");
        for (const hookType of hookTypes) {
            loadTasks.push({ dir: path.join(userHooksDir, hookType), hookType, level: "user" });
        }
    }
    for (const hookType of hookTypes) {
        loadTasks.push({ dir: path.join(projectHooksDir, hookType), hookType, level: "project" });
    }
    const results = await Promise.all(loadTasks.map(({ dir, hookType, level }) => loadFilesFromDir(ctx, dir, PROVIDER_ID, level, {
        transform: (name, _content, path, source) => {
            const toolName = name.replace(/\.(sh|bash|zsh|fish)$/, "");
            return {
                name,
                path,
                type: hookType,
                tool: toolName,
                level,
                _source: source,
            };
        },
    })));
    for (const result of results) {
        items.push(...result.items);
        if (result.warnings)
            warnings.push(...result.warnings);
    }
    return { items, warnings };
}
// =============================================================================
// Custom Tools
// =============================================================================
async function loadTools(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    if (userBase) {
        const userToolsDir = path.join(userBase, "tools");
        const userResult = await loadFilesFromDir(ctx, userToolsDir, PROVIDER_ID, "user", {
            extensions: ["ts", "js"],
            transform: (name, _content, path, source) => {
                const toolName = name.replace(/\.(ts|js)$/, "");
                return {
                    name: toolName,
                    path,
                    description: `${toolName} custom tool`,
                    level: "user",
                    _source: source,
                };
            },
        });
        items.push(...userResult.items);
        if (userResult.warnings)
            warnings.push(...userResult.warnings);
    }
    const projectBase = getProjectClaude(ctx);
    const projectToolsDir = path.join(projectBase, "tools");
    const projectResult = await loadFilesFromDir(ctx, projectToolsDir, PROVIDER_ID, "project", {
        extensions: ["ts", "js"],
        transform: (name, _content, path, source) => {
            const toolName = name.replace(/\.(ts|js)$/, "");
            return {
                name: toolName,
                path,
                description: `${toolName} custom tool`,
                level: "project",
                _source: source,
            };
        },
    });
    items.push(...projectResult.items);
    if (projectResult.warnings)
        warnings.push(...projectResult.warnings);
    return { items, warnings };
}
// =============================================================================
// System Prompts
// =============================================================================
async function loadSystemPrompts(ctx) {
    const items = [];
    const warnings = [];
    const projectBase = getProjectClaude(ctx);
    for (const [file, kind] of [
        ["SYSTEM_TEMPLATE.md", "template"],
        ["SYSTEM.md", "text"],
    ]) {
        const projectPath = path.join(projectBase, file);
        const content = await readFile(projectPath);
        if (content) {
            items.push({
                path: projectPath,
                content,
                kind,
                level: "project",
                _source: createSourceMeta(PROVIDER_ID, projectPath, "project"),
            });
        }
    }
    const userBase = getUserClaude(ctx);
    if (userBase) {
        for (const [file, kind] of [
            ["SYSTEM_TEMPLATE.md", "template"],
            ["SYSTEM.md", "text"],
        ]) {
            const userPath = path.join(userBase, file);
            const content = await readFile(userPath);
            if (content !== null) {
                items.push({
                    path: userPath,
                    content,
                    kind,
                    level: "user",
                    _source: createSourceMeta(PROVIDER_ID, userPath, "user"),
                });
            }
        }
    }
    return { items, warnings };
}
// =============================================================================
// Settings
// =============================================================================
async function loadSettings(ctx) {
    const items = [];
    const warnings = [];
    const userBase = getUserClaude(ctx);
    if (userBase) {
        const userSettingsJson = path.join(userBase, "settings.json");
        const userContent = await readFile(userSettingsJson);
        if (userContent) {
            const data = tryParseJson(userContent);
            if (data) {
                items.push({
                    path: userSettingsJson,
                    data,
                    level: "user",
                    _source: createSourceMeta(PROVIDER_ID, userSettingsJson, "user"),
                });
            }
            else {
                warnings.push(`Failed to parse JSON in ${userSettingsJson}`);
            }
        }
    }
    const projectBase = getProjectClaude(ctx);
    const projectSettingsJson = path.join(projectBase, "settings.json");
    const projectContent = await readFile(projectSettingsJson);
    if (projectContent) {
        const data = tryParseJson(projectContent);
        if (data) {
            items.push({
                path: projectSettingsJson,
                data,
                level: "project",
                _source: createSourceMeta(PROVIDER_ID, projectSettingsJson, "project"),
            });
        }
        else {
            warnings.push(`Failed to parse JSON in ${projectSettingsJson}`);
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
    description: "Load MCP servers from .claude.json and .claude/mcp.json",
    priority: PRIORITY,
    load: loadMCPServers,
});
registerProvider(contextFileCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load CLAUDE.md files from .claude/ directories",
    priority: PRIORITY,
    load: loadContextFiles,
});
registerProvider(skillCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load skills from .claude/skills/*/SKILL.md",
    priority: PRIORITY,
    load: loadSkills,
});
registerProvider(extensionModuleCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load extension modules from .claude/extensions",
    priority: PRIORITY,
    load: loadExtensionModules,
});
registerProvider(slashCommandCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load slash commands from .claude/commands/*.md",
    priority: PRIORITY,
    load: loadSlashCommands,
});
registerProvider(hookCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load hooks from .claude/hooks/pre/ and .claude/hooks/post/",
    priority: PRIORITY,
    load: loadHooks,
});
registerProvider(toolCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load custom tools from .claude/tools/",
    priority: PRIORITY,
    load: loadTools,
});
registerProvider(settingsCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load settings from .claude/settings.json",
    priority: PRIORITY,
    load: loadSettings,
});
registerProvider(systemPromptCapability.id, {
    id: PROVIDER_ID,
    displayName: DISPLAY_NAME,
    description: "Load system prompt from .claude/SYSTEM.md",
    priority: PRIORITY,
    load: loadSystemPrompts,
});
