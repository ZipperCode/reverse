/**
 * Run onboarding setup or install dependencies for optional features.
 */
import { APP_NAME } from "@rva/utils";
import { Args, CliUsageError, Command, Flags } from "@rva/utils/cli";
import { parseArgs } from "../cli/args";
import { setupHelp as commandHelp } from "../cli/command-help";
import { runSetupCommand } from "../cli/setup-cli";
import { runRootCommand } from "../main";
import { initTheme } from "@rva/tui/theme";
const COMPONENTS = ["python", "speech", "reverse"];
export async function runOnboardingSetup(deps = {}) {
    const stdinIsTTY = deps.stdinIsTTY ?? process.stdin.isTTY;
    const stdoutIsTTY = deps.stdoutIsTTY ?? process.stdout.isTTY;
    if (!stdinIsTTY || !stdoutIsTTY) {
        (deps.writeStderr ?? (text => process.stderr.write(text)))(`${APP_NAME} setup requires an interactive TTY.\n`);
        (deps.exit ?? process.exit)(1);
        return;
    }
    await (deps.runRoot ?? runRootCommand)(parseArgs([]), [], { forceSetupWizard: true });
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
    async run() {
        const { args, flags } = await this.parse(Setup);
        if (!args.component) {
            if (flags.check || flags.json) {
                // A check/JSON request with no COMPONENT has nothing to probe. Emit a
                // usage error on stderr (exit 1) rather than printing help to stdout at
                // exit 0, which would mask failures in scripted `--json` health checks.
                throw new CliUsageError("setup --check/--json requires a COMPONENT (python|speech|reverse)");
            }
            await runOnboardingSetup();
            return;
        }
        const cmd = {
            component: args.component,
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
