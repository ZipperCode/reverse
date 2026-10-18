import { parseFrontmatter, prompt } from "@rva/utils";
import { slashCommandCapability } from "../capability/slash-command";
import { slashCommandFrontmatterDisplay } from "@rva/tui/overlays/extensions/inspector-model";
import { appendInlineArgsFallback, templateUsesInlineArgPlaceholders } from "../config/prompt-templates";
import { loadCapability } from "../discovery";
import { EMBEDDED_COMMAND_TEMPLATES } from "../task/commands";
import { parseCommandArgs, substituteArgs } from "../utils/command-args";
const EMBEDDED_SLASH_COMMANDS = EMBEDDED_COMMAND_TEMPLATES;
function parseCommandTemplate(content, options) {
    const { frontmatter, body } = parseFrontmatter(content, options);
    const { description: frontmatterDesc, argumentHint } = slashCommandFrontmatterDisplay(frontmatter);
    // Get description from frontmatter or first non-empty line
    let description = frontmatterDesc ?? "";
    if (!description) {
        const firstLine = body.split("\n").find(line => line.trim());
        if (firstLine) {
            description = firstLine.slice(0, 60);
            if (firstLine.length > 60)
                description += "...";
        }
    }
    return { description, body, argumentHint };
}
/**
 * Load all custom slash commands using the capability API.
 * Loads from all registered providers (builtin, user, project).
 */
export async function loadSlashCommands(options = {}) {
    const result = await loadCapability(slashCommandCapability.id, {
        cwd: options.cwd,
        extensionRoots: options.extensionRoots,
    });
    const fileCommands = result.items.map(cmd => {
        const { description, body, argumentHint } = parseCommandTemplate(cmd.content, {
            source: cmd.path ?? `slash-command:${cmd.name}`,
            level: cmd.level === "native" ? "fatal" : "warn",
        });
        // Format source label: "via ProviderName Level"
        const capitalizedLevel = cmd.level.charAt(0).toUpperCase() + cmd.level.slice(1);
        const sourceStr = `via ${cmd._source.providerName} ${capitalizedLevel}`;
        return {
            name: cmd.name,
            description,
            argumentHint: cmd.argumentHint ?? argumentHint,
            content: body,
            source: sourceStr,
            _source: { providerName: cmd._source.providerName, level: cmd.level },
        };
    });
    const seenNames = new Set(fileCommands.map(cmd => cmd.name));
    for (const cmd of EMBEDDED_SLASH_COMMANDS) {
        const name = cmd.name.replace(/\.md$/, "");
        if (seenNames.has(name))
            continue;
        const { description, body, argumentHint } = parseCommandTemplate(cmd.content, {
            source: `embedded:${cmd.name}`,
            level: "fatal",
        });
        fileCommands.push({
            name,
            description,
            argumentHint,
            content: body,
            source: "bundled",
        });
        seenNames.add(name);
    }
    return fileCommands;
}
/**
 * Expand a slash command if it matches a file-based command.
 * Returns the expanded content or the original text if not a slash command.
 */
export function expandSlashCommand(text, fileCommands) {
    if (!text.startsWith("/"))
        return text;
    const spaceIndex = text.indexOf(" ");
    const commandName = spaceIndex === -1 ? text.slice(1) : text.slice(1, spaceIndex);
    const argsString = spaceIndex === -1 ? "" : text.slice(spaceIndex + 1);
    const fileCommand = fileCommands.find(cmd => cmd.name === commandName);
    if (fileCommand) {
        const args = parseCommandArgs(argsString);
        const argsText = args.join(" ");
        const usesInlineArgPlaceholders = templateUsesInlineArgPlaceholders(fileCommand.content);
        const substituted = substituteArgs(fileCommand.content, args);
        const rendered = prompt.render(substituted, { args, ARGUMENTS: argsText, arguments: argsText });
        return appendInlineArgsFallback(rendered, argsText, usesInlineArgPlaceholders);
    }
    return text;
}
