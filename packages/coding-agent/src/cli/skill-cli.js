/**
 * CLI handlers for `rva skill`: discover skills and check their external tool
 * dependencies for a directory.
 */
import { APP_NAME } from "@rva/utils/dirs";
import { CliUsageError } from "@rva/utils/cli";
import { handleSkillCheck } from "./skill-check";
import { handleSkillList } from "./skill-list";
export const SKILL_ACTIONS = ["list", "check"];
export const SKILL_USAGE = `Usage: ${APP_NAME} skill <list|check> [dir] [--json]

Discover:
  list [dir] [--json]    Skills a session in dir resolves, with warnings
  check [dir] [--json]   External tools declared by those skills, with install hints
`;
export async function runSkillCommand(cmd) {
    if (cmd.action === "list") {
        return handleSkillList(cmd.args, cmd.cwd, cmd.flags.json === true);
    }
    if (cmd.action === "check") {
        return handleSkillCheck(cmd.args, cmd.cwd, cmd.flags.json === true);
    }
    throw new CliUsageError(`unknown skill action "${cmd.action}"\n\n${SKILL_USAGE}`);
}
