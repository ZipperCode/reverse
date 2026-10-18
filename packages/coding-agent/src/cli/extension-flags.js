import { parseArgs } from "./args";
/**
 * Resolve extension-registered CLI flags from `rawArgs` once the flag set is
 * known, push the resolved values onto the sink, and return the parsed
 * {@link Args} (whose `messages` and `fileArgs` now reflect those flags).
 *
 * The startup parse runs before extensions load, so it cannot recognise their
 * flags: a string flag's value (`--spawn-peer reviewer` or `--spawn-peer=reviewer`)
 * is otherwise left in `messages` and leaks into the initial prompt. Re-parsing
 * here — through the *same* {@link parseArgs} the startup pass uses, now seeded
 * with the registered flags — consumes every flag form (`--flag`, `--flag value`,
 * `--flag=value`).
 *
 * {@link parseArgs} lets a registered flag shadow a same-named built-in, so even
 * a built-in-colliding flag (e.g. plan-mode's boolean `--plan`, which would
 * otherwise hit the built-in plan-model branch) is parsed with the extension's
 * semantics and surfaces in `unknownFlags` — without consuming the following
 * message or overwriting the built-in field. No built-in name list to maintain.
 *
 * Returns `null` only when there is no sink. Once extensions have loaded, the
 * reparse always runs so `--tools` can be validated against their registered
 * tools even when no extension registered CLI flags.
 */
export function applyExtensionFlags(runner, rawArgs) {
    if (!runner)
        return null;
    const parsed = parseArgs(rawArgs, runner.getFlags());
    // `parseArgs` records extension flag values in `unknownFlags`.
    for (const [name, value] of parsed.unknownFlags) {
        runner.setFlagValue(name, value);
    }
    return parsed;
}
