/**
 * Test web search models.
 */
import { Args, Command, Flags } from "@rva/utils/cli";
import { searchHelp as commandHelp } from "../cli/command-help";
import { runSearchCommand } from "../cli/web-search-cli";
const RECENCY = ["day", "week", "month", "year"];
export default class Search extends Command {
    static description = commandHelp.description;
    static aliases = ["q", "web-search"];
    static args = {
        query: Args.string({ description: "Search query text", required: false, multiple: true }),
    };
    static flags = {
        model: Flags.string({ description: "Catalog model selector" }),
        recency: Flags.string({ description: "Recency filter", options: RECENCY }),
        limit: Flags.integer({ char: "l", description: "Max results to return" }),
        compact: Flags.boolean({ description: "Render condensed output" }),
    };
    async run() {
        const { args, flags } = await this.parse(Search);
        const query = Array.isArray(args.query) ? args.query.join(" ") : (args.query ?? "");
        const cmd = {
            query,
            model: flags.model,
            recency: flags.recency,
            limit: flags.limit,
            expanded: !flags.compact,
        };
        await runSearchCommand(cmd);
    }
}
