/**
 * Manage configuration settings.
 */

import { Args, Command, Flags } from "@rva/utils/cli";
import { getEffectiveLocale } from "../config/persisted-locale";
import { CLI_TRANSLATIONS_ZH_CN } from "../i18n/zh-CN/cli";
import { configHelp as commandHelp } from "../cli/command-help";
import { type ConfigAction, type ConfigCommandArgs, runConfigCommand } from "../cli/config-cli";
import { initTheme } from "@rva/tui/theme";

function helpStr(key: string, fallback: string): string {
	return getEffectiveLocale() === "zh-CN" ? (CLI_TRANSLATIONS_ZH_CN[key] ?? fallback) : fallback;
}

const ACTIONS: ConfigAction[] = ["list", "get", "set", "reset", "path", "init-xdg"];

export default class Config extends Command {
	static get description() {
		return helpStr("cli.config.description", commandHelp.description);
	}
	static args = {
		action: Args.string({
			get description() {
				return helpStr("cli.config.arg.action", "Config action");
			},
			required: false,
			options: ACTIONS,
		}),
		key: Args.string({
			get description() {
				return helpStr("cli.config.arg.key", "Setting key");
			},
			required: false,
		}),
		value: Args.string({
			get description() {
				return helpStr("cli.config.arg.value", "Value (for set/reset)");
			},
			required: false,
			multiple: true,
		}),
	};

	static flags = {
		json: Flags.boolean({
			get description() {
				return helpStr("cli.config.flag.json", "Output JSON");
			},
		}),
	};

	async run(): Promise<void> {
		const { args, flags } = await this.parse(Config);
		const action = (args.action ?? "list") as ConfigAction;
		const value = Array.isArray(args.value) ? args.value.join(" ") : args.value;

		const cmd: ConfigCommandArgs = {
			action,
			key: args.key,
			value,
			flags: {
				json: flags.json,
			},
		};

		await initTheme();
		await runConfigCommand(cmd);
	}
}
