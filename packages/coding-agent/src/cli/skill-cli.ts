/**
 * CLI handlers for `reverse skill`: discover skills and check their external tool
 * dependencies for a directory.
 */
import { APP_NAME } from "@reverse/utils/dirs";
import { CliUsageError } from "@reverse/utils/cli";
import { handleSkillCheck } from "./skill-check";
import { handleSkillList } from "./skill-list";

export type SkillAction = "list" | "check";

export const SKILL_ACTIONS: readonly SkillAction[] = ["list", "check"];

export const SKILL_USAGE = `Usage: ${APP_NAME} skill <list|check> [dir] [--json]

Discover:
  list [dir] [--json]    Skills a session in dir resolves, with warnings
  check [dir] [--json]   External tools declared by those skills, with install hints
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
	if (cmd.action === "check") {
		return handleSkillCheck(cmd.args, cmd.cwd, cmd.flags.json === true);
	}
	throw new CliUsageError(`unknown skill action "${cmd.action}"\n\n${SKILL_USAGE}`);
}
