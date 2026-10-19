/**
 * Run onboarding setup or install dependencies for optional features.
 */

import * as readline from "node:readline";
import { APP_NAME } from "@reverse/utils";
import { Args, CliUsageError, Command, Flags } from "@reverse/utils/cli";
import { parseArgs } from "../cli/args";
import { setupHelp as commandHelp } from "../cli/command-help";
import { runSetupCommand, type SetupCommandArgs, type SetupComponent } from "../cli/setup-cli";
import { getAllLocalizedPanels, SETUP_PANEL_KEYS } from "../cli/setup-panels";
import { getEffectiveLocale } from "../config/persisted-locale";
import { runRootCommand } from "../main";
import { initTheme } from "@reverse/tui/theme";

const COMPONENTS: SetupComponent[] = [...SETUP_PANEL_KEYS];

export interface OnboardingSetupDependencies {
	runRoot?: typeof runRootCommand;
	stdinIsTTY?: boolean;
	stdoutIsTTY?: boolean;
	writeStderr?: (text: string) => void;
	exit?: (code: number) => never;
}

export async function runOnboardingSetup(deps: OnboardingSetupDependencies = {}): Promise<void> {
	const stdinIsTTY = deps.stdinIsTTY ?? process.stdin.isTTY;
	const stdoutIsTTY = deps.stdoutIsTTY ?? process.stdout.isTTY;
	if (!stdinIsTTY || !stdoutIsTTY) {
		(deps.writeStderr ?? (text => process.stderr.write(text)))(`${APP_NAME} setup requires an interactive TTY.\n`);
		(deps.exit ?? process.exit)(1);
		return;
	}
	await (deps.runRoot ?? runRootCommand)(parseArgs([]), [], { forceSetupWizard: true });
}

async function promptSetupMenuIndex(title: string, labels: readonly string[]): Promise<number | undefined> {
	process.stdout.write(`${title}\n\n`);
	for (let i = 0; i < labels.length; i++) {
		process.stdout.write(`  ${i + 1}. ${labels[i]}\n`);
	}
	process.stdout.write("\n");

	const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
	const { promise, resolve } = Promise.withResolvers<number | undefined>();
	let settled = false;
	const finish = (val: number | undefined) => {
		if (settled) return;
		settled = true;
		rl.close();
		process.stdin.pause();
		resolve(val);
	};

	rl.once("SIGINT", () => {
		finish(undefined);
		process.exit(130);
	});

	rl.question(`Enter number (1-${labels.length}): `, answer => {
		const trimmed = answer.trim();
		const index = Number.parseInt(trimmed, 10) - 1;
		if (Number.isNaN(index) || index < 0 || index >= labels.length) {
			finish(undefined);
		} else {
			finish(index);
		}
	});

	return promise;
}

export default class Setup extends Command {
	static description = commandHelp.description;
	static args = {
		component: Args.string({
			description: "Optional component to install",
			required: false,
			options: COMPONENTS,
		}),
		tool: Args.string({
			description: "Optional tool to check or install (for reverse component)",
			required: false,
		}),
	};

	static flags = {
		check: Flags.boolean({ char: "c", description: "Check if dependencies are installed" }),
		json: Flags.boolean({ description: "Output status as JSON" }),
		execute: Flags.boolean({
			char: "x",
			description: "Execute verified installation commands after interactive confirmation (reverse only)",
		}),
	};

	async run(): Promise<void> {
		const { args, flags } = await this.parse(Setup);
		if (!args.component) {
			if (flags.check || flags.json) {
				throw new CliUsageError("setup --check/--json requires a COMPONENT (providers|add|reverse|python|speech)");
			}
			const isTTY = Boolean(process.stdin.isTTY && process.stdout.isTTY);
			if (isTTY) {
				const isZh = getEffectiveLocale() === "zh-CN";
				const panels = getAllLocalizedPanels(isZh);
				const exitLabel = isZh ? "← 退出" : "← Exit";
				const labels = [...panels.map(p => `${p.label} - ${p.description}`), exitLabel];
				const choiceIdx = await promptSetupMenuIndex(
					isZh ? "请选择要配置的设置面板:" : "Select setup panel to configure:",
					labels,
				);
				if (choiceIdx === undefined || choiceIdx === panels.length) {
					process.exit(0);
				}
				const chosen = panels[choiceIdx].key;
				const cmd: SetupCommandArgs = {
					component: chosen,
					flags: {
						json: flags.json,
						check: flags.check,
						execute: flags.execute,
					},
				};
				await initTheme();
				await runSetupCommand(cmd);
				process.exit(0);
			}
			await runOnboardingSetup();
			return;
		}
		const cmd: SetupCommandArgs = {
			component: args.component as SetupComponent,
			tool: args.tool,
			flags: {
				json: flags.json,
				check: flags.check,
				execute: flags.execute,
			},
		};
		await initTheme();
		await runSetupCommand(cmd);
	}
}
