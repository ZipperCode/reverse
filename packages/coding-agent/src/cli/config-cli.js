/**
 * Config CLI command handlers.
 *
 * Handles `omp config <command>` subcommands for managing settings.
 * The settings registry (`config/registry.ts`) is the source of truth for available settings.
 */
import { APP_NAME, getAgentDir, isRecord } from "@rva/utils";
import chalk from "@rva/utils/chalk";
import { orderedSettings } from "../config/all-settings";
import { lookup } from "../config/registry";
import { Settings, settings } from "../config/settings";
import { getEffectiveLocale } from "../config/persisted-locale";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";
function cliText(key, vars) {
    const locale = getEffectiveLocale();
    if (locale === "zh-CN") {
        let text = CLI_TRANSLATIONS_ZH_CN[key] ?? key;
        if (vars) {
            for (const [k, v] of Object.entries(vars)) {
                text = text.replaceAll(`{${k}}`, v);
            }
        }
        return text;
    }
    switch (key) {
        case "cli.config.unknownCommand":
            return `Unknown config command: ${vars?.action ?? ""}`;
        case "cli.config.validCommands":
            return `Valid commands: ${vars?.commands ?? ""}`;
        case "cli.config.usage.get":
            return `Usage: ${vars?.app ?? APP_NAME} config get <key>`;
        case "cli.config.usage.set":
            return `Usage: ${vars?.app ?? APP_NAME} config set <key> <value>`;
        case "cli.config.usage.reset":
            return `Usage: ${vars?.app ?? APP_NAME} config reset <key>`;
        case "cli.config.unknownSetting":
            return `Unknown setting: ${vars?.key ?? ""}`;
        case "cli.config.runListHint":
            return `Run '${vars?.app ?? APP_NAME} config list' to see available keys`;
        case "cli.config.listTitle":
            return "Settings:\n";
        case "cli.config.notSet":
            return "(not set)";
        case "cli.config.setSuccess":
            return `Set ${vars?.path ?? ""} = ${vars?.value ?? ""}`;
        case "cli.config.resetSuccess":
            return `Reset ${vars?.path ?? ""} to ${vars?.value ?? ""}`;
        case "cli.config.shadow.fallback":
            return `$${vars?.name ?? ""} is used as a fallback while the saved value is blank.`;
        case "cli.config.shadow.override":
            return `$${vars?.name ?? ""} overrides this value; unset it for the saved value to apply.`;
        case "cli.config.shadow.project":
            return "Project settings override this value here; edit or remove it there for the saved value to apply.";
        case "cli.config.shadow.overlay":
            return "A --config / PI_CONFIG_FILES overlay overrides this value for this process.";
        case "cli.config.shadow.runtime":
            return "A runtime override supplies the effective value for this process.";
        default:
            return key;
    }
}
import { theme } from "@rva/tui/theme";
import { initXdg } from "./commands/init-xdg";
/** Printed instead of a credential value in human output only. */
const REDACTED = "********";
function toSettingDef(setting) {
    const ui = setting.ui;
    return {
        setting,
        path: setting.id,
        type: setting.type,
        description: ui?.description ?? "",
        tab: ui?.tab ?? "internal",
    };
}
/** Find setting definition by path */
function findSettingDef(path) {
    const setting = lookup(path);
    return setting ? toSettingDef(setting) : undefined;
}
// =============================================================================
// Argument Parser
// =============================================================================
const VALID_ACTIONS = ["list", "get", "set", "reset", "path", "init-xdg"];
/**
 * Parse config subcommand arguments.
 * Returns undefined if not a config command.
 */
export function parseConfigArgs(args) {
    if (args.length === 0 || args[0] !== "config") {
        return undefined;
    }
    if (args.length < 2 || args[1] === "--help" || args[1] === "-h") {
        return { action: "list", flags: {} };
    }
    const action = args[1];
    if (!VALID_ACTIONS.includes(action)) {
        console.error(chalk.red(cliText("cli.config.unknownCommand", { action })));
        console.error(cliText("cli.config.validCommands", { commands: VALID_ACTIONS.join(", ") }));
        process.exit(1);
    }
    const result = {
        action: action,
        flags: {},
    };
    const positionalArgs = [];
    for (let i = 2; i < args.length; i++) {
        const arg = args[i];
        if (arg === "--json") {
            result.flags.json = true;
        }
        else if (!arg.startsWith("-")) {
            positionalArgs.push(arg);
        }
    }
    if (positionalArgs.length > 0) {
        result.key = positionalArgs[0];
    }
    if (positionalArgs.length > 1) {
        result.value = positionalArgs.slice(1).join(" ");
    }
    return result;
}
// =============================================================================
// Value Formatting
// =============================================================================
function formatValue(value) {
    if (value === undefined || value === null) {
        return chalk.dim(cliText("cli.config.notSet"));
    }
    if (typeof value === "boolean") {
        return value ? chalk.green("true") : chalk.red("false");
    }
    if (typeof value === "number") {
        return chalk.cyan(String(value));
    }
    if (typeof value === "string") {
        return chalk.yellow(value);
    }
    if (Array.isArray(value) || typeof value === "object") {
        try {
            return chalk.yellow(JSON.stringify(value));
        }
        catch {
            return chalk.yellow(String(value));
        }
    }
    return chalk.yellow(String(value));
}
function getTypeDisplay(def) {
    const values = def.setting.enumValues;
    if (values && values.length > 0) {
        return `(${values.join("|")})`;
    }
    switch (def.type) {
        case "boolean":
            return "(boolean)";
        case "number":
            return "(number)";
        case "array":
            return "(array)";
        case "record":
            return "(record)";
        default:
            return "(string)";
    }
}
// =============================================================================
// Command Handlers
// =============================================================================
export async function runConfigCommand(cmd) {
    await Settings.init();
    switch (cmd.action) {
        case "list":
            await handleList(cmd.flags);
            break;
        case "get":
            handleGet(cmd.key, cmd.flags);
            break;
        case "set":
            await handleSet(cmd.key, cmd.value, cmd.flags);
            break;
        case "reset":
            await handleReset(cmd.key, cmd.flags);
            break;
        case "path":
            handlePath();
            break;
        case "init-xdg":
            await initXdg();
            break;
    }
}
async function writeStdout(text) {
    const pending = Promise.withResolvers();
    process.stdout.write(text, error => {
        if (error) {
            pending.reject(error);
            return;
        }
        pending.resolve();
    });
    await pending.promise;
}
async function handleList(flags) {
    const defs = orderedSettings().map(toSettingDef);
    if (flags.json) {
        // A redacted entry omits `value` and says so, rather than substituting a
        // placeholder string: a consumer cannot tell a stand-in from a real value
        // and could write it back as the credential.
        //
        // Redaction is driven by the value, not by classification alone. Marking an
        // unset credential as redacted would report every fresh install as having
        // one configured, which leaks the opposite of what redaction is for. A
        // configured "" renders as unset, like in the settings panel (credentials
        // are all strings).
        const result = {};
        for (const def of defs) {
            const value = def.setting.get(settings);
            result[def.path] =
                def.setting.isCredential && value
                    ? { redacted: true, type: def.type, description: def.description }
                    : { value, type: def.type, description: def.description };
        }
        await writeStdout(`${JSON.stringify(result, null, 2)}\n`);
        return;
    }
    console.log(chalk.bold(cliText("cli.config.listTitle")));
    const groups = {};
    for (const def of defs) {
        if (!groups[def.tab]) {
            groups[def.tab] = [];
        }
        groups[def.tab].push(def);
    }
    const sortedGroups = Object.keys(groups).sort((a, b) => {
        if (a === "config")
            return -1;
        if (b === "config")
            return 1;
        return a.localeCompare(b);
    });
    for (const group of sortedGroups) {
        console.log(chalk.bold.blue(`[${group}]`));
        for (const def of groups[group]) {
            // `list` dumps every value without anyone asking for a specific
            // credential, so redact here. `get <path>` stays an explicit
            // single-value request and is left alone. An unset or cleared ("")
            // credential keeps its ordinary rendering: masking it would imply one
            // is configured.
            const value = def.setting.get(settings);
            const valueStr = def.setting.isCredential && value ? REDACTED : formatValue(value);
            const typeStr = getTypeDisplay(def);
            console.log(`  ${chalk.white(def.path)} = ${valueStr} ${chalk.dim(typeStr)}`);
        }
        console.log("");
    }
}
function handleGet(key, flags) {
    if (!key) {
        console.error(chalk.red(cliText("cli.config.usage.get", { app: APP_NAME })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    const def = findSettingDef(key);
    if (!def) {
        console.error(chalk.red(cliText("cli.config.unknownSetting", { key })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    const value = def.setting.get(settings);
    if (flags.json) {
        console.log(JSON.stringify({ key: def.path, value, type: def.type, description: def.description }, null, 2));
        return;
    }
    console.log(formatValue(value));
}
async function handleSet(key, value, flags) {
    if (!key || value === undefined) {
        console.error(chalk.red(cliText("cli.config.usage.set", { app: APP_NAME })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    const def = findSettingDef(key);
    if (!def) {
        console.error(chalk.red(cliText("cli.config.unknownSetting", { key })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    try {
        def.setting.set(settings, def.setting.parse(value));
        await settings.flush();
    }
    catch (err) {
        console.error(chalk.red(String(err)));
        process.exit(1);
    }
    // Report the value written to config.yml. When another layer or an environment variable still
    // supplies the effective value, say which instead of echoing its value as if it had been set.
    const saved = globalValue(def.setting);
    const shadow = shadowingSource(def.setting);
    if (flags.json) {
        console.log(JSON.stringify({ key: def.path, value: saved, ...shadow?.json }));
        return;
    }
    console.log(chalk.green(`${theme.status.success} ${cliText("cli.config.setSuccess", { path: def.path, value: formatValue(saved) })}`));
    if (shadow)
        console.log(chalk.yellow(`${theme.status.warning} ${shadow.message}`));
}
/** Value `setting` holds in the global config layer — what `config set` wrote. */
function globalValue(setting) {
    let value = settings.getGlobalSettings();
    for (const segment of setting.segments)
        value = isRecord(value) ? value[segment] : undefined;
    return value;
}
/** Where the effective value comes from when it is not the global config (or the default), if anywhere. */
function shadowingSource(setting) {
    const provenance = setting.provenance(settings);
    switch (provenance) {
        case "global":
        case "default":
            return undefined;
        case "env": {
            const name = setting.envName;
            if (!name)
                return undefined;
            return setting.envFallback
                ? {
                    json: { fallbackEnv: name },
                    message: cliText("cli.config.shadow.fallback", { name }),
                }
                : {
                    json: { overriddenBy: name },
                    message: cliText("cli.config.shadow.override", { name }),
                };
        }
        case "project":
            return {
                json: { overriddenBy: provenance },
                message: cliText("cli.config.shadow.project"),
            };
        case "overlay":
            return {
                json: { overriddenBy: provenance },
                message: cliText("cli.config.shadow.overlay"),
            };
        case "runtime":
            return {
                json: { overriddenBy: provenance },
                message: cliText("cli.config.shadow.runtime"),
            };
    }
}
async function handleReset(key, flags) {
    if (!key) {
        console.error(chalk.red(cliText("cli.config.usage.reset", { app: APP_NAME })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    const def = findSettingDef(key);
    if (!def) {
        console.error(chalk.red(cliText("cli.config.unknownSetting", { key })));
        console.error(chalk.dim(`\n${cliText("cli.config.runListHint", { app: APP_NAME })}`));
        process.exit(1);
    }
    try {
        // Remove the key rather than writing the default, so later default changes still apply.
        def.setting.unset(settings);
        await settings.flush();
    }
    catch (err) {
        console.error(chalk.red(String(err)));
        process.exit(1);
    }
    // The effective value may now come from another layer or the environment: never echo a credential.
    const value = def.setting.get(settings);
    const redacted = def.setting.isCredential && !!value;
    if (flags.json) {
        console.log(JSON.stringify(redacted ? { key: def.path, redacted: true } : { key: def.path, value }));
    }
    else {
        console.log(chalk.green(`${theme.status.success} ${cliText("cli.config.resetSuccess", { path: def.path, value: redacted ? REDACTED : formatValue(value) })}`));
    }
}
function handlePath() {
    console.log(getAgentDir());
}
