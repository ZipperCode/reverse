import { getSkillSlashCommandName } from "../extensibility/skills";
import { loadSlashCommands } from "../extensibility/slash-commands";
import { ACP_BUILTIN_RESERVED_NAMES, isAcpBuiltinShadowedName } from "./acp-builtins";
import { BUILTIN_SLASH_COMMANDS_INTERNAL } from "./builtin-registry";
export async function buildAvailableSlashCommands(session, loadFileCommands = cwd => loadSlashCommands({ cwd, extensionRoots: session.effectiveExtensionRoots })) {
    const commands = [];
    const seenNames = new Set();
    const appendCommand = (command) => {
        if (seenNames.has(command.name))
            return;
        seenNames.add(command.name);
        commands.push(command);
    };
    for (const command of BUILTIN_SLASH_COMMANDS_INTERNAL) {
        if (!command.handle)
            continue;
        const hint = command.acpInputHint ?? command.inlineHint;
        appendCommand({
            name: command.name,
            aliases: command.aliases,
            description: command.acpDescription ?? command.description,
            input: hint ? { hint } : undefined,
            subcommands: command.subcommands,
            source: "builtin",
        });
        // ACP dispatch resolves builtin aliases before `session.prompt()` sees the
        // input, so a custom/file command sharing an alias would be advertised but
        // never run. Reserve aliases here too; TUI-only builtins are skipped above,
        // so their aliases stay available.
        for (const alias of command.aliases ?? [])
            seenNames.add(alias);
    }
    if (session.skillsSettings?.enableSkillCommands) {
        for (const skill of session.skills) {
            appendCommand({
                name: getSkillSlashCommandName(skill),
                description: skill.description || `Run ${skill.name} skill`,
                input: { hint: "arguments" },
                source: "skill",
            });
        }
    }
    const runner = session.extensionRunner;
    if (runner) {
        for (const command of runner.getRegisteredCommands(ACP_BUILTIN_RESERVED_NAMES)) {
            if (isAcpBuiltinShadowedName(command.name))
                continue;
            appendCommand({
                name: command.name,
                description: command.description ?? "(extension command)",
                input: { hint: "arguments" },
                source: "extension",
            });
        }
    }
    for (const command of session.customCommands) {
        const source = command.path?.startsWith("mcp:") ? "mcp_prompt" : "custom";
        appendCommand({
            name: command.command.name,
            description: command.command.description,
            input: { hint: "arguments" },
            source,
        });
    }
    const fileCommands = await loadFileCommands(session.sessionManager.getCwd());
    session.setSlashCommands(fileCommands);
    for (const command of fileCommands) {
        appendCommand({
            name: command.name,
            description: command.description,
            input: command.argumentHint ? { hint: command.argumentHint } : undefined,
            source: "file",
        });
    }
    return commands;
}
export function toAcpAvailableCommands(commands) {
    return commands.map(command => ({
        name: command.name,
        description: command.description ?? "",
        input: command.input,
    }));
}
