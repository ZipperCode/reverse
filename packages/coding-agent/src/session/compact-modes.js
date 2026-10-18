export const COMPACT_MODES = [
    {
        name: "soft",
        description: "Summarize locally with the active model (skip server compaction)",
        overrides: { methodOrder: ["soft"] },
    },
    {
        name: "remote",
        description: "Summarize via OpenAI-compatible server compaction, then fall back to a local summary",
        overrides: { methodOrder: ["remote", "soft"] },
    },
    {
        name: "snapcompact",
        description: "Archive history onto dense bitmap images the model reads back (no LLM call)",
        overrides: { methodOrder: ["snapcompact"] },
        rejectsFocus: true,
    },
];
/** Resolve a subcommand token (case-insensitive) to its mode definition. */
export function findCompactMode(name) {
    const key = name.trim().toLowerCase();
    return COMPACT_MODES.find(mode => mode.name === key);
}
/**
 * Split `/compact` args into a leading mode subcommand + focus instructions.
 *
 * Backward compatible: when the first token is not a known mode, the entire
 * argument string is treated as focus instructions (the historical behavior).
 * A recognized mode with `rejectsFocus` and trailing text is an error.
 */
export function parseCompactArgs(args) {
    const trimmed = args.trim();
    if (!trimmed)
        return {};
    const spaceIndex = trimmed.search(/\s/);
    const firstToken = spaceIndex === -1 ? trimmed : trimmed.slice(0, spaceIndex);
    const mode = findCompactMode(firstToken);
    if (!mode) {
        // No recognized mode prefix — keep the whole thing as focus instructions.
        return { instructions: trimmed };
    }
    const focus = spaceIndex === -1 ? "" : trimmed.slice(spaceIndex + 1).trim();
    if (mode.rejectsFocus && focus) {
        return {
            error: `/compact ${mode.name} does not take focus instructions (it archives history without an LLM summary).`,
        };
    }
    return { mode: mode.name, instructions: focus || undefined };
}
