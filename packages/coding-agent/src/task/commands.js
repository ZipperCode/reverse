/**
 * Workflow commands for orchestrating multi-agent workflows.
 *
 * Commands are embedded at build time via Bun's import with { type: "text" }.
 */
import * as path from "node:path";
import { parseFrontmatter, prompt } from "@rva/utils";
import { slashCommandCapability } from "../capability/slash-command";
import { loadCapability } from "../discovery";
// Embed command markdown files at build time
import initMd from "../prompts/agents/init.md" with { type: "text" };
const EMBEDDED_COMMANDS = [{ name: "init.md", content: prompt.render(initMd) }];
export const EMBEDDED_COMMAND_TEMPLATES = EMBEDDED_COMMANDS;
/** Extract string value from frontmatter field */
function getString(frontmatter, key) {
    const value = frontmatter[key];
    return typeof value === "string" ? value : "";
}
/** Cache for bundled commands */
let bundledCommandsCache = null;
/**
 * Load all bundled commands from embedded content.
 */
export function loadBundledCommands() {
    if (bundledCommandsCache !== null) {
        return bundledCommandsCache;
    }
    const commands = [];
    for (const { name, content } of EMBEDDED_COMMANDS) {
        const { frontmatter, body } = parseFrontmatter(content, {
            source: `embedded:${name}`,
            level: "fatal",
        });
        const cmdName = name.replace(/\.md$/, "");
        commands.push({
            name: cmdName,
            description: getString(frontmatter, "description"),
            instructions: body,
            source: "bundled",
            filePath: `embedded:${name}`,
        });
    }
    bundledCommandsCache = commands;
    return commands;
}
/**
 * Discover all available commands.
 *
 * Precedence (highest wins): .omp > .pi > .claude (project before user), then bundled
 */
export async function discoverCommands(cwd) {
    const resolvedCwd = path.resolve(cwd);
    // Load slash commands from capability API
    const result = await loadCapability(slashCommandCapability.id, { cwd: resolvedCwd });
    const commands = [];
    const seen = new Set();
    // Convert SlashCommand to WorkflowCommand format
    for (const cmd of result.items) {
        if (seen.has(cmd.name))
            continue;
        const { frontmatter, body } = parseFrontmatter(cmd.content, {
            source: cmd.path ?? `workflow-command:${cmd.name}`,
            level: cmd.level === "native" ? "fatal" : "warn",
        });
        // Map capability levels to WorkflowCommand source
        const source = cmd.level === "native" ? "bundled" : cmd.level;
        commands.push({
            name: cmd.name,
            description: getString(frontmatter, "description"),
            instructions: body,
            source,
            filePath: cmd.path,
        });
        seen.add(cmd.name);
    }
    // Add bundled commands if not already present
    for (const cmd of loadBundledCommands()) {
        if (seen.has(cmd.name))
            continue;
        commands.push(cmd);
        seen.add(cmd.name);
    }
    return commands;
}
/**
 * Get a command by name.
 */
export function getCommand(commands, name) {
    return commands.find(c => c.name === name);
}
/**
 * Expand command instructions with task input.
 * Replaces $@ with the provided input.
 */
export function expandCommand(command, input) {
    // Function replacement so `$`-patterns in user input ($$, $&, ...) stay literal.
    return command.instructions.replace(/\$@/g, () => input);
}
/**
 * Clear the bundled commands cache (for testing).
 */
export function clearBundledCommandsCache() {
    bundledCommandsCache = null;
}
