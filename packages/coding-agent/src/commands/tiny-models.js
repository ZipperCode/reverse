import { Args, Command, Flags } from "@rva/utils/cli";
import { tinyModelsHelp as commandHelp } from "../cli/command-help";
import { runTinyModelsCommand } from "../cli/tiny-models-cli";
const ACTIONS = ["download", "list"];
export default class TinyModels extends Command {
    static description = commandHelp.description;
    static args = {
        action: Args.string({
            description: "Action to perform",
            required: false,
            options: ACTIONS,
        }),
        model: Args.string({
            description: "Model key (`smollm` = word completion), or all",
            required: false,
        }),
    };
    static flags = {
        json: Flags.boolean({ description: "Output JSON" }),
    };
    async run() {
        const { args, flags } = await this.parse(TinyModels);
        const command = {
            action: (args.action ?? "download"),
            model: args.model,
            flags: {
                json: flags.json,
            },
        };
        await runTinyModelsCommand(command);
    }
}
