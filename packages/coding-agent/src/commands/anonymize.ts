/**
 * Write a shareable, anonymized copy of a session and its subagent transcripts.
 */
import { Args, Command, Flags } from "@reverse/utils/cli";
import { runAnonymizeCommand } from "../cli/anonymize-cli";
import { reportCliUsageError } from "../cli/args";
import { anonymizeHelp as commandHelp } from "../cli/command-help";

export default class Anonymize extends Command {
	static description = commandHelp.description;
	static args = {
		session: Args.string({ description: "Session file path or id prefix (default: most recent for cwd)" }),
	};
	static flags = {
		out: Flags.string({ char: "o", description: "Output directory (default: ./<session-file>.anon)" }),
	};

	static examples = [
		"reverse anonymize",
		"reverse anonymize 01a0285c -o ./bug-report",
		"reverse anonymize ~/.reverse/agent/sessions/--work-pi--/session.jsonl",
	];

	async run(): Promise<void> {
		const { args, flags } = await this.parse(Anonymize);
		try {
			await runAnonymizeCommand({ session: args.session, out: flags.out });
		} catch (error) {
			if (!reportCliUsageError(error)) throw error;
			process.exitCode = 2;
		}
	}
}
