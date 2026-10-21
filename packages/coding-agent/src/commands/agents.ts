/**
 * Manage bundled task agents.
 */

import { Args, Command, Flags, renderCommandHelp } from "@reverse/utils/cli";
import { type AgentsAction, type AgentsCommandArgs, runAgentsCommand } from "../cli/agents-cli";
import { agentsHelp as commandHelp } from "../cli/command-help";
import { initTheme } from "@reverse/tui/theme";

const ACTIONS: AgentsAction[] = ["unpack"];

export default class Agents extends Command {
	static description = commandHelp.description;
	static args = {
		action: Args.string({
			description: "Agents action",
			required: false,
			options: ACTIONS,
		}),
	};

	static flags = {
		force: Flags.boolean({ char: "f", description: "Overwrite existing agent files" }),
		json: Flags.boolean({ description: "Output JSON" }),
		dir: Flags.string({ description: "Output directory (overrides --user/--project)" }),
		user: Flags.boolean({ description: "Write to ~/.reverse/agent/agents (default)" }),
		project: Flags.boolean({ description: "Write to ./.reverse/agents" }),
	};

	static examples = [
		"# Export bundled agents into user config (default)\n  reverse agents unpack",
		"# Export bundled agents into project config\n  reverse agents unpack --project",
		"# Overwrite existing local agent files\n  reverse agents unpack --project --force",
		"# Export into a custom directory\n  reverse agents unpack --dir ./tmp/agents --json",
	];

	async run(): Promise<void> {
		const { args, flags } = await this.parse(Agents);
		if (!args.action) {
			renderCommandHelp("reverse", "agents", Agents);
			return;
		}

		const cmd: AgentsCommandArgs = {
			action: args.action as AgentsAction,
			flags: {
				force: flags.force,
				json: flags.json,
				dir: flags.dir,
				user: flags.user,
				project: flags.project,
			},
		};

		await initTheme();
		await runAgentsCommand(cmd);
	}
}
