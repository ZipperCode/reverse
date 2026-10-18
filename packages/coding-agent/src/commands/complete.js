/**
 * `omp __complete <kind> [-- <prefix>]` — dynamic completion candidates.
 *
 * Hidden helper invoked by the generated shell completion scripts to resolve
 * values that can't be baked into the script: the live model catalog and
 * on-disk sessions. Output is one `value\tdescription` line per candidate
 * (tab-separated); shells that show descriptions parse the tab, bash uses the
 * first field. The import surface is kept deliberately narrow so a TAB press
 * doesn't pay for the full agent boot.
 */
import { getBundledModels, getBundledProviders } from "@rva/catalog/models";
import { Command } from "@rva/utils/cli";
import { completeHelp as commandHelp } from "../cli/command-help";
import { SessionManager } from "../session/session-manager";
export default class Complete extends Command {
    static hidden = commandHelp.hidden;
    static strict = false;
    async run() {
        const argv = this.argv.filter(token => token !== "--");
        const kind = argv[0];
        const prefix = argv.length > 1 ? argv[argv.length - 1] : "";
        if (kind === "models") {
            completeModels(prefix);
        }
        else if (kind === "sessions") {
            await completeSessions(prefix);
        }
    }
}
/** Strip control chars that would corrupt the tab-separated line protocol. */
function clean(text) {
    return text.replace(/[\t\r\n]+/g, " ").trim();
}
function completeModels(prefix) {
    const needle = prefix.toLowerCase();
    const seen = new Set();
    const lines = [];
    for (const provider of getBundledProviders()) {
        for (const model of getBundledModels(provider)) {
            // Offer both the fully-qualified `provider/id` and the bare `id`
            // (matches the fuzzy resolution `--model` accepts).
            const candidates = [`${model.provider}/${model.id}`, model.id];
            for (const candidate of candidates) {
                if (seen.has(candidate))
                    continue;
                seen.add(candidate);
                if (needle && !candidate.toLowerCase().includes(needle))
                    continue;
                lines.push(`${candidate}\t${model.provider}`);
            }
        }
    }
    lines.sort();
    if (lines.length > 0)
        process.stdout.write(`${lines.join("\n")}\n`);
}
async function completeSessions(prefix) {
    const sessions = await SessionManager.list(process.cwd());
    const lines = [];
    for (const session of sessions) {
        if (prefix && !session.id.startsWith(prefix))
            continue;
        const label = clean(session.title ?? session.firstMessage ?? "").slice(0, 72);
        lines.push(`${session.id}\t${label}`);
    }
    if (lines.length > 0)
        process.stdout.write(`${lines.join("\n")}\n`);
}
