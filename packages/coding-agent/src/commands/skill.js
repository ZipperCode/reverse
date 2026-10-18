/**
 * Discover and report skills resolved for a directory.
 */
import { Args, CliUsageError, Command, Flags } from "@rva/utils/cli";
import { skillHelp as commandHelp } from "../cli/command-help";
import { runSkillCommand, SKILL_ACTIONS, SKILL_USAGE } from "../cli/skill-cli";
export default class Skill extends Command {
    static description = commandHelp.description;
    static aliases = ["skills"];
    static args = {
        action: Args.string({ description: "Skill action (list, check)", required: false, options: SKILL_ACTIONS }),
        targets: Args.string({
            description: "Directory to discover skills for (default: cwd)",
            required: false,
            multiple: true,
        }),
    };
    static flags = {
        json: Flags.boolean({ description: "Output JSON (list, check)" }),
    };
    static examples = [
        "rva skill list",
        "rva skill list ./my-project --json",
        "rva skill check",
        "rva skill check ./my-project --json",
    ];
    async run() {
        const { args, flags } = await this.parse(Skill);
        if (!args.action) {
            process.stdout.write(SKILL_USAGE);
            return;
        }
        if (!SKILL_ACTIONS.includes(args.action)) {
            throw new CliUsageError(`unknown skill action "${args.action}"\n\n${SKILL_USAGE}`);
        }
        const exitCode = await runSkillCommand({
            action: args.action,
            args: args.targets ?? [],
            cwd: process.cwd(),
            flags: {
                json: flags.json,
            },
        });
        if (exitCode !== 0)
            process.exitCode = exitCode;
    }
}
