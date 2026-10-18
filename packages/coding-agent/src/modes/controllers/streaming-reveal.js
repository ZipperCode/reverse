import { getSegmenter } from "@rva/tui";
import { LRUCache } from "@rva/utils/lru";
import { formatThinkingForDisplay, hasDisplayableThinking } from "@rva/tui/chat/thinking-display";
export const STREAMING_REVEAL_FRAME_MS = 1000 / 30;
export const MIN_STEP = 3;
export const CATCHUP_FRAMES = 8;
const graphemeCountCache = new LRUCache({ max: 128 });
function countGraphemes(text) {
    if (text.length === 0)
        return 0;
    const cached = graphemeCountCache.get(text);
    if (cached !== undefined)
        return cached;
    let count = 0;
    for (const _segment of getSegmenter().segment(text)) {
        count += 1;
    }
    graphemeCountCache.set(text, count);
    return count;
}
/** Count graphemes of `text` from code-unit offset `start`, also reporting the
 *  start offset of the final grapheme (where an append could extend a cluster). */
function countGraphemesFrom(text, start) {
    let count = 0;
    let tailStart = start;
    for (const seg of getSegmenter().segment(start === 0 ? text : text.slice(start))) {
        count += 1;
        tailStart = start + seg.index;
    }
    return { count, tailStart };
}
/** Segment `text` from code-unit offset `start`, walking up to `clusters`
 *  graphemes. Returns the code-unit END of the final cluster walked, its START
 *  (`lastStart`), and how many clusters were found (`count` may be less than
 *  `clusters` if the suffix is shorter than requested). */
function segmentFrom(text, start, clusters) {
    let count = 0;
    let lastStart = start;
    let end = start;
    for (const seg of getSegmenter().segment(start === 0 ? text : text.slice(start))) {
        count += 1;
        lastStart = start + seg.index;
        end = start + seg.index + seg.segment.length;
        if (count >= clusters)
            break;
    }
    return { end, lastStart, count };
}
/** Memoizes per-block grapheme counts across reveal ticks. Streaming blocks only
 *  grow by appending, and an append can only alter the final grapheme cluster of
 *  the previous text, so only the suffix from that cluster needs re-segmenting. */
export class BlockUnitCounter {
    #entries = new Map();
    #sliceEntries = new Map();
    count(index, text) {
        const entry = this.#entries.get(index);
        if (entry !== undefined) {
            if (entry.text === text)
                return entry.count;
            if (entry.count > 0 && text.length > entry.text.length && text.startsWith(entry.text)) {
                const tail = countGraphemesFrom(text, entry.tailStart);
                const next = { text, count: entry.count - 1 + tail.count, tailStart: tail.tailStart };
                this.#entries.set(index, next);
                return next.count;
            }
        }
        const full = countGraphemesFrom(text, 0);
        this.#entries.set(index, { text, count: full.count, tailStart: full.tailStart });
        return full.count;
    }
    reset() {
        this.#entries.clear();
        this.#sliceEntries.clear();
    }
    /** Slice `text` to its first `units` graphemes. Memoized across reveal ticks:
     *  streaming blocks grow only by appending and the reveal target advances
     *  monotonically, so a previously sliced prefix is reused and only the suffix
     *  from the boundary cluster is re-segmented. Only an exact (text, units) hit
     *  skips segmentation entirely — an append can extend the boundary cluster, so
     *  the incremental path still re-segments from that cluster's start. */
    slice(index, text, units) {
        if (units <= 0 || text.length === 0)
            return "";
        const entry = this.#sliceEntries.get(index);
        if (entry !== undefined && entry.text === text && entry.units === units) {
            return entry.end >= text.length ? text : text.slice(0, entry.end);
        }
        if (entry !== undefined && (entry.text === text || text.startsWith(entry.text)) && units >= entry.units) {
            const extra = units - entry.units + 1;
            const seg = segmentFrom(text, entry.lastStart, extra);
            this.#sliceEntries.set(index, { text, units, end: seg.end, lastStart: seg.lastStart });
            return seg.end >= text.length ? text : text.slice(0, seg.end);
        }
        const seg = segmentFrom(text, 0, units);
        this.#sliceEntries.set(index, { text, units, end: seg.end, lastStart: seg.lastStart });
        return seg.end >= text.length ? text : text.slice(0, seg.end);
    }
}
function sliceGraphemes(text, units) {
    if (units <= 0 || text.length === 0)
        return "";
    let count = 0;
    for (const { index, segment } of getSegmenter().segment(text)) {
        count += 1;
        if (count >= units) {
            const end = index + segment.length;
            return end >= text.length ? text : text.slice(0, end);
        }
    }
    return text;
}
export function visibleUnits(message, hideThinking, proseOnly = true) {
    let total = 0;
    for (const block of message.content) {
        if (block.type === "text") {
            total += countGraphemes(block.text);
        }
        else if (block.type === "thinking" && !hideThinking) {
            const formatted = formatThinkingForDisplay(block.thinking, proseOnly);
            if (hasDisplayableThinking(block.thinking, formatted)) {
                total += countGraphemes(formatted);
            }
        }
    }
    return total;
}
function revealTextBlock(block, remaining, units, index, sliceOf) {
    if (remaining <= 0)
        return block.text.length === 0 ? block : { ...block, text: "" };
    if (remaining >= units)
        return block;
    return { ...block, text: sliceOf(index, block.text, remaining) };
}
function revealThinkingBlock(block, remaining, units, index, sliceOf) {
    if (remaining <= 0)
        return block.thinking.length === 0 ? block : { ...block, thinking: "" };
    if (remaining >= units)
        return block;
    return { ...block, thinking: sliceOf(index, block.thinking, remaining) };
}
export function buildDisplayMessage(target, revealed, hideThinking, proseOnly = true, countOf = (_index, text) => countGraphemes(text), sliceOf = (_index, text, units) => sliceGraphemes(text, units)) {
    let remaining = Math.max(0, Math.floor(revealed));
    const content = [];
    for (let i = 0; i < target.content.length; i++) {
        const block = target.content[i];
        if (block.type === "text") {
            const units = countOf(i, block.text);
            content.push(revealTextBlock(block, remaining, units, i, sliceOf));
            remaining = Math.max(0, remaining - units);
        }
        else if (block.type === "thinking" && !hideThinking) {
            const formatted = formatThinkingForDisplay(block.thinking, proseOnly);
            if (hasDisplayableThinking(block.thinking, formatted)) {
                const units = countOf(i, formatted);
                const displayBlock = {
                    ...block,
                    thinking: formatted,
                    rawThinking: block.thinking,
                };
                content.push(revealThinkingBlock(displayBlock, remaining, units, i, sliceOf));
                remaining = Math.max(0, remaining - units);
            }
            else {
                content.push(block);
            }
        }
        else {
            content.push(block);
        }
    }
    return { ...target, content };
}
/** Record the live blocks and their primitive fields, or undefined when a block
 *  carries a nested object (a later in-place edit to it would be invisible to
 *  a field-identity check, so those snaps compare by value only). */
function snapBlockFields(content) {
    const snapped = [];
    for (const block of content) {
        const fields = Object.entries(block);
        for (const [, value] of fields) {
            if (typeof value === "object" && value !== null)
                return undefined;
        }
        snapped.push({ block, fields });
    }
    return snapped;
}
/** Whether `content` holds the very blocks snapped, each with every field still
 *  `===` its snapped value. Strings are immutable, so an unchanged field is
 *  the same reference and the check is O(fields); an in-place rewrite
 *  (`block.text = …`) swaps the reference and fails it. A `true` proves the
 *  content equals the snap-time clone; a `false` proves nothing. */
function unchangedSinceSnap(snapped, content) {
    if (snapped.length !== content.length)
        return false;
    for (let i = 0; i < snapped.length; i++) {
        const { block, fields } = snapped[i];
        if (content[i] !== block || Object.keys(block).length !== fields.length)
            return false;
        for (const [key, value] of fields) {
            if (Reflect.get(block, key) !== value)
                return false;
        }
    }
    return true;
}
export function nextStep(backlog) {
    return Math.max(MIN_STEP, Math.ceil(Math.max(0, backlog) / CATCHUP_FRAMES));
}
export class StreamingRevealController {
    #getSmoothStreaming;
    #getHideThinkingBlock;
    #getProseOnlyThinking;
    #requestRender;
    #target;
    #component;
    #timer;
    #revealed = 0;
    #targetDirty = false;
    // Immutable deep clone of the leading content snapped at the tool-call
    // boundary. Kept independent of the live message so an in-place provider
    // rewrite of a previously emitted block (e.g. OpenAI Responses replacing
    // streamed text with authoritative terminal content) is still detected —
    // aliasing the live array would make the equality check compare it to itself.
    #snappedToolBoundaryContent;
    // Live blocks + field values recorded with the clone: while the leading
    // content is frozen (every flush of a tool-arg stream) they prove equality
    // in O(blocks) without walking the text; any mismatch defers to the clone.
    #snappedToolBoundaryBlocks;
    #hideThinkingBlock = false;
    #proseOnlyThinking = true;
    #smoothStreaming = true;
    #unitCounter = new BlockUnitCounter();
    #countOf = (index, text) => this.#unitCounter.count(index, text);
    #sliceOf = (index, text, units) => this.#unitCounter.slice(index, text, units);
    constructor(options) {
        this.#getSmoothStreaming = options.getSmoothStreaming;
        this.#getHideThinkingBlock = options.getHideThinkingBlock;
        this.#getProseOnlyThinking = options.getProseOnlyThinking;
        this.#requestRender = options.requestRender;
    }
    #build(target, revealed) {
        return buildDisplayMessage(target, revealed, this.#hideThinkingBlock, this.#proseOnlyThinking, this.#countOf, this.#sliceOf);
    }
    begin(component, message, hasToolCalls) {
        this.stop();
        this.#component = component;
        this.#target = message;
        this.#revealed = 0;
        this.#hideThinkingBlock = this.#getHideThinkingBlock();
        this.#proseOnlyThinking = this.#getProseOnlyThinking();
        this.#smoothStreaming = this.#getSmoothStreaming();
        if (!this.#smoothStreaming) {
            const total = this.#visibleUnits(message);
            component.updateContent(this.#build(message, total), { transient: true });
            return;
        }
        const total = this.#visibleUnits(message);
        if (hasToolCalls) {
            // A tool call is a transcript-order boundary: finish any leading
            // assistant text before EventController renders the separate tool card.
            this.#revealed = total;
            component.updateContent(this.#build(message, this.#revealed), {
                transient: true,
            });
            this.#snapToolBoundary(message.content);
            return;
        }
        this.#renderCurrent();
        this.#syncTimer(total);
    }
    setTarget(message, hasToolCalls) {
        this.#target = message;
        this.#hideThinkingBlock = this.#getHideThinkingBlock();
        this.#proseOnlyThinking = this.#getProseOnlyThinking();
        this.#smoothStreaming = this.#getSmoothStreaming();
        if (!this.#component)
            return;
        if (!this.#smoothStreaming) {
            const total = this.#visibleUnits(message);
            this.#revealed = total;
            this.#targetDirty = false;
            this.#stopTimer();
            this.#component.updateContent(this.#build(message, total), { transient: true });
            return;
        }
        const total = this.#visibleUnits(message);
        if (hasToolCalls) {
            let alreadySnapped = false;
            if (this.#revealed === total && this.#snappedToolBoundaryContent !== undefined) {
                const blocks = this.#snappedToolBoundaryBlocks;
                if (blocks !== undefined && unchangedSinceSnap(blocks, message.content)) {
                    alreadySnapped = true;
                }
                else if (Bun.deepEquals(this.#snappedToolBoundaryContent, message.content)) {
                    alreadySnapped = true;
                    // Equal by value, not by reference (e.g. a block object was
                    // replaced): re-anchor the fast check on the live blocks.
                    this.#snappedToolBoundaryBlocks = snapBlockFields(message.content);
                }
            }
            // A tool call is a transcript-order boundary: finish any leading
            // assistant text before EventController renders the separate tool card.
            this.#revealed = total;
            this.#targetDirty = false;
            this.#stopTimer();
            if (alreadySnapped)
                return;
            this.#component.updateContent(this.#build(message, this.#revealed), {
                transient: true,
            });
            this.#snapToolBoundary(message.content);
            return;
        }
        this.#snappedToolBoundaryContent = undefined;
        this.#snappedToolBoundaryBlocks = undefined;
        if (this.#revealed > total) {
            this.#revealed = total;
        }
        if (this.#revealed < total) {
            // Behind: the running reveal tick renders the newest target at the
            // cadence; skip the redundant per-delta render (the reveal cadence
            // bounds markdown work even when the provider deltas arrive faster).
            this.#targetDirty = false;
            this.#syncTimer(total);
            return;
        }
        // Caught up: defer the render to the next reveal tick so a burst of
        // post-catch-up deltas coalesces into one render instead of one per
        // token. The tick always renders the latest target — nothing is lost.
        if (!this.#timer)
            this.#startTimer();
        this.#targetDirty = true;
    }
    stop() {
        this.#stopTimer();
        this.#target = undefined;
        this.#component = undefined;
        this.#revealed = 0;
        this.#targetDirty = false;
        this.#snappedToolBoundaryContent = undefined;
        this.#snappedToolBoundaryBlocks = undefined;
        this.#unitCounter.reset();
    }
    #snapToolBoundary(content) {
        this.#snappedToolBoundaryContent = structuredClone(content);
        this.#snappedToolBoundaryBlocks = snapBlockFields(content);
    }
    /**
     * Re-read cached visibility flags (hideThinkingBlock, proseOnlyThinking)
     * and re-render the current target. Called when the thinking level changes
     * mid-stream so the reveal controller doesn't keep rendering with stale values.
     */
    resyncVisibility() {
        if (!this.#target || !this.#component)
            return;
        this.#hideThinkingBlock = this.#getHideThinkingBlock();
        this.#proseOnlyThinking = this.#getProseOnlyThinking();
        // Recalculate visible units — hiding thinking blocks may reduce the total,
        // and the reveal position may now exceed it.
        const total = this.#visibleUnits(this.#target);
        this.#revealed = Math.min(this.#revealed, total);
        this.#renderCurrent();
        this.#syncTimer(total);
    }
    /** Total reveal units of `message`, memoized per block across ticks. */
    #visibleUnits(message) {
        let total = 0;
        for (let i = 0; i < message.content.length; i++) {
            const block = message.content[i];
            if (block.type === "text") {
                total += this.#unitCounter.count(i, block.text);
            }
            else if (block.type === "thinking" && !this.#hideThinkingBlock) {
                const formatted = formatThinkingForDisplay(block.thinking, this.#proseOnlyThinking);
                if (hasDisplayableThinking(block.thinking, formatted)) {
                    total += this.#unitCounter.count(i, formatted);
                }
            }
        }
        return total;
    }
    #renderCurrent() {
        if (!this.#target || !this.#component)
            return;
        // Every controller render is an in-flight streaming snapshot, even when
        // smooth reveal has temporarily caught up to the current target. The
        // message_end handler performs the only stable non-transient render.
        this.#component.updateContent(this.#build(this.#target, this.#revealed), { transient: true });
    }
    #syncTimer(total = this.#target ? this.#visibleUnits(this.#target) : 0) {
        if (!this.#target || !this.#component || this.#revealed >= total) {
            this.#stopTimer();
            return;
        }
        this.#startTimer();
    }
    #startTimer() {
        if (this.#timer)
            return;
        this.#timer = setInterval(() => {
            this.#tick();
        }, STREAMING_REVEAL_FRAME_MS);
        this.#timer.unref?.();
    }
    #stopTimer() {
        if (!this.#timer)
            return;
        clearInterval(this.#timer);
        this.#timer = undefined;
    }
    #tick() {
        const target = this.#target;
        const component = this.#component;
        if (!target || !component) {
            this.stop();
            return;
        }
        const total = this.#visibleUnits(target);
        if (this.#revealed >= total) {
            if (this.#targetDirty) {
                this.#targetDirty = false;
                this.#revealed = total;
                this.#renderCurrent();
                this.#requestRender(component);
            }
            this.#stopTimer();
            return;
        }
        this.#revealed = Math.min(total, this.#revealed + nextStep(total - this.#revealed));
        component.updateContent(this.#build(target, this.#revealed), {
            transient: true,
        });
        this.#requestRender(component);
        if (this.#revealed >= total) {
            this.#stopTimer();
        }
    }
}
