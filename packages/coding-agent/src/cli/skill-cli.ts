/**
 * CLI handlers for `rva skill`: discover and report local skills resolved for a directory.
 */
import { APP_NAME } from "@rva/utils/dirs";
import { CliUsageError } from "@rva/utils/cli";
import { handleSkillList } from "./skill-list";

export type SkillAction = "list";

export const SKILL_ACTIONS: readonly SkillAction[] = ["list"];

export const SKILL_USAGE = `Usage: ${APP_NAME} skill list [dir] [--json]

Discover:
  list [dir] [--json]   Skills a session in dir resolves, with warnings
`;

export interface SkillCommandArgs {
	action: SkillAction;
	args: string[];
	cwd: string;
	flags: {
		json?: boolean;
	};
}

export async function runSkillCommand(cmd: SkillCommandArgs): Promise<number> {
	if (cmd.action === "list") {
		return handleSkillList(cmd.args, cmd.cwd, cmd.flags.json === true);
	}
	throw new CliUsageError(`unknown skill action "${cmd.action}"\n\n${SKILL_USAGE}`);
}
