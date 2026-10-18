/**
 * The browser blocks of a Tern window (Tern's `blocks` op) and how
 * `app.target` picks the one an open adopts.
 */
import { isRecord } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
/**
 * What to add about Terns before block adoption, which list only the blocks
 * scripts drive (entries without `driven`): certain when an entry lacks it,
 * a possibility when the list is empty.
 */
function oldTernNote(blocks) {
    if (blocks.some(entry => entry.driven === undefined)) {
        return "\nThis Tern lists only the blocks scripts drive: update Tern to adopt the user's own.";
    }
    if (blocks.length === 0) {
        return "\nIf the user has browser blocks open, this Tern predates block adoption: update Tern.";
    }
    return "";
}
/** The window's blocks as targets, naming the omp tab (`taken`) holding each. */
export function ternTargets(blocks, taken) {
    return blocks.map(entry => {
        const target = {
            target: String(entry.block),
            title: entry.title,
            url: entry.url,
            docked: entry.owner === null,
        };
        if (entry.shown !== undefined)
            target.shown = entry.shown;
        if (entry.driven !== undefined)
            target.driven = entry.driven;
        const tab = taken.get(entry.block);
        if (tab !== undefined)
            target.tab = tab;
        return target;
    });
}
/** The `browser.targets()` listing of a Tern window's blocks. */
export function describeTernTargets(blocks, taken) {
    const update = oldTernNote(blocks);
    if (blocks.length === 0)
        return `This Tern window lists no browser blocks.${update}`;
    const list = blocks.map(entry => `- ${describeTernBlock(entry, taken.get(entry.block))}`).join("\n");
    return `Tern browser blocks (adopt one with app.target set to its id):\n${list}${update}`;
}
/** The window's browser blocks; malformed entries are skipped. */
export async function listTernBlocks(client, opts) {
    const answer = await client.request({ op: "blocks" }, opts);
    if (!isRecord(answer) || !Array.isArray(answer.blocks))
        return [];
    const blocks = [];
    for (const raw of answer.blocks) {
        if (!isRecord(raw) || typeof raw.block !== "number")
            continue;
        blocks.push({
            block: raw.block,
            url: typeof raw.url === "string" ? raw.url : "about:blank",
            title: typeof raw.title === "string" ? raw.title : "",
            owner: typeof raw.owner === "number" ? raw.owner : null,
            shown: typeof raw.shown === "boolean" ? raw.shown : undefined,
            driven: typeof raw.driven === "boolean" ? raw.driven : undefined,
        });
    }
    return blocks;
}
/**
 * The block `target` names: the block whose id it is (all digits), else the
 * blocks whose URL or title contain it (case-insensitive). Among several,
 * one on screen wins, then one scripts do not drive (the user's own), then
 * the first listed. Blocks in `taken` (other omp tabs drive them) never match.
 */
export function pickTernBlock(blocks, target, taken = new Map()) {
    const free = blocks.filter(entry => !taken.has(entry.block));
    const needle = target.trim();
    if (/^\d+$/.test(needle)) {
        const byId = free.find(entry => String(entry.block) === needle);
        if (byId)
            return byId;
    }
    const lower = needle.toLowerCase();
    const rank = (entry) => (entry.shown === true ? 2 : 0) + (entry.driven === false ? 1 : 0);
    let best;
    for (const entry of free) {
        if (!entry.url.toLowerCase().includes(lower) && !entry.title.toLowerCase().includes(lower))
            continue;
        if (!best || rank(entry) > rank(best))
            best = entry;
    }
    return best;
}
/** One block for the agent: `12 "Title" https://… (docked, on screen)`. */
export function describeTernBlock(entry, takenBy) {
    const facts = [entry.owner === null ? "docked" : `picture-in-picture over block ${entry.owner}`];
    if (entry.shown !== undefined)
        facts.push(entry.shown ? "on screen" : "not on screen");
    if (takenBy !== undefined)
        facts.push(`driven by omp tab ${JSON.stringify(takenBy)}`);
    else if (entry.driven === true)
        facts.push("driven by a script");
    return `${entry.block} ${JSON.stringify(entry.title)} ${entry.url} (${facts.join(", ")})`;
}
/** The error of an `app.target` no block matches, listing the window's browser blocks. */
export function noTernBlockError(blocks, target, taken = new Map()) {
    const update = oldTernNote(blocks);
    if (blocks.length === 0) {
        return new ToolError(`No Tern browser block to adopt for app.target ${JSON.stringify(target)}: this Tern window lists no browser blocks. Ask the user to open one, or omit app.target to open a picture-in-picture over this pane. browser.targets() lists the blocks you can adopt.${update}`);
    }
    const list = blocks.map(entry => `- ${describeTernBlock(entry, taken.get(entry.block))}`).join("\n");
    return new ToolError(`No Tern browser block matches app.target ${JSON.stringify(target)} (a block id, or a URL/title substring). Browser blocks in this Tern window:\n${list}\nRetry with app.target set to one of these ids; browser.targets() lists them before adopting.${update}`);
}
