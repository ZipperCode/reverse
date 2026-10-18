/**
 * Prompt construction and scoring for `omp if-bench`.
 *
 * Each turn scores two independent contracts from a single reply: the working
 * memory one (the array inside `<...>` must equal the locally computed result)
 * and the instruction-following one (a `nya{1,N}` sound must appear somewhere).
 * The cat directive rotates through the start, middle, and end of the user turn
 * so a model cannot succeed by only attending to the prompt's edges.
 */
import { prompt } from "@rva/utils";
import { encodeAction } from "./actions";
import catDirectiveTemplate from "./prompts/cat-directive.md" with { type: "text" };
import systemTemplate from "./prompts/system.md" with { type: "text" };
import turnTemplate from "./prompts/turn.md" with { type: "text" };
/** Where the cat directive sits inside the turn's user message. */
export const CAT_PLACEMENTS = ["beginning", "middle", "end"];
/** Longest accepted cat sound, i.e. the `N` in `nya{1,N}`. */
export const DEFAULT_NYA_MAX = 8;
const RESULT_BLOCK = /<([^>]*)>/;
/**
 * Matcher for one accepted cat sound.
 *
 * The trailing lookahead rejects both an over-long tail (`nyaaaaaaaaa` with more
 * than `nyaMax` a's) and the literal directive text `nya{1,N}` echoed back from
 * the prompt, so quoting the instruction never counts as following it.
 */
export function catSoundPattern(nyaMax) {
    return new RegExp(`nya{1,${nyaMax}}(?![a{])`);
}
/** System prompt: machine semantics plus the response contract. */
export function buildSystemPrompt(nyaMax) {
    return prompt.render(systemTemplate, { nyaMax }).trim();
}
/**
 * Build the user message for `turn` (1-based).
 *
 * `start` is passed on the first turn only; later turns deliberately omit the
 * array so the model must carry state forward from its own previous reply.
 */
export function buildTurnPrompt(options) {
    const placement = CAT_PLACEMENTS[(options.turn - 1) % CAT_PLACEMENTS.length];
    const tokens = options.actions.map(encodeAction);
    // A mid-prompt directive is only observable when actions surround it, so the
    // action list splits in half around it.
    const split = placement === "middle" ? Math.ceil(tokens.length / 2) : tokens.length;
    const tail = tokens.slice(split);
    const content = prompt
        .render(turnTemplate, {
        catDirective: prompt.render(catDirectiveTemplate, { nyaMax: options.nyaMax }).trim(),
        catBefore: placement === "beginning",
        catMiddle: placement === "middle",
        catAfter: placement === "end",
        start: options.start,
        actionsHead: tokens.slice(0, split).join(" "),
        actionsTail: tail.length > 0 ? tail.join(" ") : undefined,
    })
        .trim();
    return { content, placement };
}
/** Score one reply against the locally computed `expected` array. */
export function assessResponse(response, expected, nyaMax) {
    const cat = catSoundPattern(nyaMax);
    const catPresent = cat.test(response);
    const block = RESULT_BLOCK.exec(response);
    if (!block?.[1])
        return { passed: false, failure: "format" };
    const reported = block[1].replace(cat, "").replace(/\s/g, "");
    if (reported === expected) {
        return catPresent ? { passed: true, reported } : { passed: false, failure: "cat", reported };
    }
    return { passed: false, failure: catPresent ? "result" : "result+cat", reported };
}
