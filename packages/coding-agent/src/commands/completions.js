/**
 * `omp completions <bash|zsh|fish>` — print a shell completion script.
 *
 * The script is derived entirely from the declarative command/flag metadata
 * (see `cli/completion-gen.ts`), so it never drifts from the actual CLI surface.
 */
import { APP_NAME, postmortem, VERSION } from "@rva/utils";
import { Args, Command } from "@rva/utils/cli";
import { completionsHelp as commandHelp } from "../cli/command-help";
import { buildSpec, generateCompletion } from "../cli/completion-gen";
import { commands } from "../cli-commands";
/** Entry name of the default command whose flags become top-level completions. */
const ROOT_COMMAND = "launch";
const SHELLS = ["bash", "zsh", "fish"];
/** Generate a completion script from the live command registry. */
export async function generateLiveCompletion(shell) {
    const loaded = await Promise.all(commands.map(async (entry) => ({ entry, Cmd: await entry.load() })));
    const map = new Map();
    const aliasMap = new Map();
    for (const { entry, Cmd } of loaded) {
        map.set(entry.name, Cmd);
        const merged = new Set([...(Cmd.aliases ?? []), ...(entry.aliases ?? [])]);
        aliasMap.set(entry.name, [...merged]);
    }
    const config = { bin: APP_NAME, version: VERSION, commands: map };
    return generateCompletion(shell, buildSpec(config, ROOT_COMMAND, aliasMap));
}
export default class Completions extends Command {
    static description = commandHelp.description;
    static args = {
        shell: Args.string({
            description: "Target shell",
            required: true,
            options: SHELLS,
        }),
    };
    static examples = [
        `# zsh — eval at startup, or write to a file in $fpath\n  eval "$(${APP_NAME} completions zsh)"`,
        `# bash\n  eval "$(${APP_NAME} completions bash)"`,
        `# fish\n  ${APP_NAME} completions fish > ~/.config/fish/completions/${APP_NAME}.fish`,
    ];
    async run() {
        const shell = this.argv[0];
        if (!isShell(shell)) {
            process.stderr.write(`Usage: ${APP_NAME} completions <${SHELLS.join("|")}>\n`);
            process.exitCode = 1;
            return;
        }
        await Bun.write(Bun.stdout, await generateLiveCompletion(shell));
        await postmortem.quit(0);
    }
}
function isShell(value) {
    return value === "bash" || value === "zsh" || value === "fish";
}
