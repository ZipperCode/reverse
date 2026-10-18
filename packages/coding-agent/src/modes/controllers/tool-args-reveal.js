import { parseStreamingJson, parseStreamingJsonThrottled, STREAMING_JSON_PARSE_MIN_GROWTH } from "@rva/utils";
import { nextStep, STREAMING_REVEAL_FRAME_MS } from "./streaming-reveal";
// Top-level string args a renderer reads mid-stream. The streamed-args decode
// reads these fields incrementally between throttled full-JSON parses so a
// long payload updates preview args at reveal cadence instead of stalling for
// STREAMING_JSON_PARSE_MIN_GROWTH bytes at a time. Nested-array modes (edit
// patch/replace `edits[].diff`) still fall through to the throttled parse.
const STREAMING_STRING_KEYS_BY_TOOL = {
    // write.content also carries xd:// device args (a JSON string) — the same
    // incremental decode feeds the delegated tool renderer live inner args.
    write: ["content"],
    edit: ["input", "_input"],
    eval: ["code"],
};
/** String fields the streamed-args decode reads incrementally for `toolName`. */
export function streamingStringKeysForTool(toolName, rawInput) {
    if (rawInput)
        return undefined;
    return STREAMING_STRING_KEYS_BY_TOOL[toolName];
}
function decodeJsonStringEscape(ch) {
    switch (ch) {
        case '"':
        case "\\":
        case "/":
            return ch;
        case "b":
            return "\b";
        case "f":
            return "\f";
        case "n":
            return "\n";
        case "r":
            return "\r";
        case "t":
            return "\t";
        default:
            return ch;
    }
}
function isHexDigit(ch) {
    return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F");
}
class StreamingJsonStringExtractor {
    #keys;
    #source = "";
    #offset = 0;
    /** `{`/`[` nesting outside strings. Candidate keys match only at depth 1 —
     *  the top level of the args object — so a nested object's key (e.g.
     *  `{"meta":{"content":…}}`) is never captured as a streamed top-level arg. */
    #depth = 0;
    #state = "scan";
    #candidate = "";
    #candidateEscaped = false;
    #candidateUnicode = "";
    #matchedKey;
    #targetKey;
    #targetEscaped = false;
    #targetUnicode = "";
    #values = {};
    // Chunked accumulation: text runs append into per-key chunk lists joined
    // once per update() instead of one concat + record store per character
    // (~1M ops per 1MB payload). Escapes/\uXXXX still go char-by-char.
    #chunks = {};
    #changed = false;
    constructor(keys) {
        this.#keys = new Set(keys);
    }
    reset() {
        this.#source = "";
        this.#offset = 0;
        this.#depth = 0;
        this.#state = "scan";
        this.#candidate = "";
        this.#candidateEscaped = false;
        this.#candidateUnicode = "";
        this.#matchedKey = undefined;
        this.#targetKey = undefined;
        this.#targetEscaped = false;
        this.#targetUnicode = "";
        this.#values = {};
        this.#chunks = {};
        this.#changed = false;
    }
    /**
     * Advance the decode to `prefix`. A `prefix` that does not extend the
     * previous one restarts from scratch; `knownAppend` lets a caller that
     * already guarantees the extension skip the O(prefix) re-verification
     * (only the length is checked).
     */
    update(prefix, knownAppend = false) {
        if (knownAppend ? prefix.length < this.#source.length : !prefix.startsWith(this.#source)) {
            this.reset();
        }
        this.#source = prefix;
        this.#changed = false;
        while (this.#offset < prefix.length) {
            if (this.#state === "target" && !this.#targetEscaped && !this.#targetUnicode) {
                // Fast run: copy straight text until the next JSON escape,
                // closing quote, or control byte in one slice instead of one
                // state-machine step + concat per character.
                const ch = prefix[this.#offset];
                if (ch !== "\\" && ch !== '"' && ch >= " ") {
                    let end = this.#offset + 1;
                    while (end < prefix.length) {
                        const c = prefix[end];
                        if (c === "\\" || c === '"' || c < " ")
                            break;
                        end++;
                    }
                    this.#appendTarget(prefix.slice(this.#offset, end));
                    this.#offset = end;
                    continue;
                }
            }
            const ch = prefix[this.#offset];
            switch (this.#state) {
                case "scan":
                    this.#scan(ch);
                    break;
                case "candidate":
                    this.#readCandidate(ch);
                    break;
                case "afterCandidate":
                    this.#afterCandidate(ch);
                    break;
                case "beforeValue":
                    this.#beforeValue(ch);
                    break;
                case "target":
                    this.#readTarget(ch);
                    break;
            }
        }
        this.#flushChunks();
        return { values: { ...this.#values }, changed: this.#changed };
    }
    #scan(ch) {
        if (ch === '"') {
            this.#candidate = "";
            this.#candidateEscaped = false;
            this.#candidateUnicode = "";
            this.#state = "candidate";
        }
        else if (ch === "{" || ch === "[") {
            this.#depth++;
        }
        else if (ch === "}" || ch === "]") {
            this.#depth--;
        }
        this.#offset++;
    }
    #readCandidate(ch) {
        if (this.#candidateUnicode) {
            this.#readCandidateUnicode(ch);
            return;
        }
        if (this.#candidateEscaped) {
            if (ch === "u") {
                this.#candidateUnicode = "u";
            }
            else {
                this.#candidate += decodeJsonStringEscape(ch);
                this.#candidateEscaped = false;
            }
            this.#offset++;
            return;
        }
        if (ch === "\\") {
            this.#candidateEscaped = true;
            this.#offset++;
            return;
        }
        if (ch === '"') {
            this.#matchedKey = this.#depth === 1 && this.#keys.has(this.#candidate) ? this.#candidate : undefined;
            this.#state = "afterCandidate";
            this.#offset++;
            return;
        }
        this.#candidate += ch;
        this.#offset++;
    }
    #readCandidateUnicode(ch) {
        if (isHexDigit(ch)) {
            this.#candidateUnicode += ch;
            if (this.#candidateUnicode.length === 5) {
                this.#candidate += String.fromCharCode(Number.parseInt(this.#candidateUnicode.slice(1), 16));
                this.#candidateUnicode = "";
                this.#candidateEscaped = false;
            }
        }
        else {
            this.#candidate += this.#candidateUnicode + ch;
            this.#candidateUnicode = "";
            this.#candidateEscaped = false;
        }
        this.#offset++;
    }
    #afterCandidate(ch) {
        if (/\s/.test(ch)) {
            this.#offset++;
            return;
        }
        const matchedKey = this.#matchedKey;
        this.#matchedKey = undefined;
        if (ch === ":" && matchedKey) {
            this.#targetKey = matchedKey;
            this.#state = "beforeValue";
            this.#offset++;
            return;
        }
        this.#state = "scan";
    }
    #beforeValue(ch) {
        if (/\s/.test(ch)) {
            this.#offset++;
            return;
        }
        if (ch === '"' && this.#targetKey) {
            if (this.#values[this.#targetKey]) {
                this.#values[this.#targetKey] = "";
                this.#changed = true;
            }
            this.#targetEscaped = false;
            this.#targetUnicode = "";
            this.#state = "target";
            this.#offset++;
            return;
        }
        this.#targetKey = undefined;
        this.#state = "scan";
    }
    #readTarget(ch) {
        if (this.#targetUnicode) {
            this.#readTargetUnicode(ch);
            return;
        }
        if (this.#targetEscaped) {
            if (ch === "u") {
                this.#targetUnicode = "u";
            }
            else {
                this.#appendTarget(decodeJsonStringEscape(ch));
                this.#targetEscaped = false;
            }
            this.#offset++;
            return;
        }
        if (ch === "\\") {
            this.#targetEscaped = true;
            this.#offset++;
            return;
        }
        if (ch === '"') {
            this.#targetKey = undefined;
            this.#state = "scan";
            this.#offset++;
            return;
        }
        this.#appendTarget(ch);
        this.#offset++;
    }
    #readTargetUnicode(ch) {
        if (isHexDigit(ch)) {
            this.#targetUnicode += ch;
            if (this.#targetUnicode.length === 5) {
                this.#appendTarget(String.fromCharCode(Number.parseInt(this.#targetUnicode.slice(1), 16)));
                this.#targetUnicode = "";
                this.#targetEscaped = false;
            }
        }
        else {
            this.#appendTarget(this.#targetUnicode + ch);
            this.#targetUnicode = "";
            this.#targetEscaped = false;
        }
        this.#offset++;
    }
    #appendTarget(text) {
        if (!this.#targetKey || text.length === 0)
            return;
        const key = this.#targetKey;
        const list = this.#chunks[key];
        if (list)
            list.push(text);
        else
            this.#chunks[key] = [text];
        this.#changed = true;
    }
    /** Join pending chunks into `#values` once per update, not per character. */
    #flushChunks() {
        for (const key in this.#chunks) {
            const list = this.#chunks[key];
            if (list.length === 0)
                continue;
            this.#values[key] = `${this.#values[key] ?? ""}${list.join("")}`;
            list.length = 0;
        }
    }
}
function createStringExtractor(keys) {
    return keys && keys.length > 0 ? new StreamingJsonStringExtractor(keys) : undefined;
}
function sameStringKeys(a, b) {
    if (a.length !== (b?.length ?? 0))
        return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b?.[i])
            return false;
    }
    return true;
}
/** Clamp a slice end into `text`, never splitting a surrogate pair: a prefix
 *  ending on a high surrogate would feed a lone surrogate into the parsed
 *  preview args (providers decode UTF-8 incrementally, so the raw stream
 *  itself never contains one). */
function clampSliceEnd(text, end) {
    if (end <= 0)
        return 0;
    if (end >= text.length)
        return text.length;
    const code = text.charCodeAt(end - 1);
    return code >= 0xd800 && code <= 0xdbff ? end + 1 : end;
}
function initialDisplayArgs() {
    return { __partialJson: "" };
}
function resetDisplayState(entry) {
    entry.parsedArgs = {};
    entry.parsedLen = 0;
    entry.displayArgs = initialDisplayArgs();
    entry.displayPrefix = "";
    entry.stringExtractor?.reset();
}
/** Display args for a revealed prefix. Function-tool JSON is parsed at the same
 * growth-throttled cadence providers use, so a long `write` payload cannot make
 * the reveal loop re-parse the whole growing buffer every frame. Renderers that
 * read raw JSON directly still receive fresh `__partialJson` prefixes; other
 * renderers get a stable object reference while parsed fields are unchanged. */
function displayArgsForPrefix(entry, prefix, forceParse = false) {
    if (entry.rawInput) {
        if (prefix === entry.displayPrefix)
            return { args: entry.displayArgs, changed: false };
        const args = { input: prefix, __partialJson: prefix };
        entry.displayArgs = args;
        entry.displayPrefix = prefix;
        return { args, changed: true };
    }
    let parsedChanged = false;
    if (forceParse || (prefix.length > 0 && prefix.length < STREAMING_JSON_PARSE_MIN_GROWTH)) {
        entry.parsedArgs = parseStreamingJson(prefix);
        entry.parsedLen = prefix.length;
        parsedChanged = true;
    }
    else {
        const throttled = parseStreamingJsonThrottled(prefix, entry.parsedLen);
        if (throttled) {
            entry.parsedArgs = throttled.value;
            entry.parsedLen = throttled.parsedLen;
            parsedChanged = true;
        }
    }
    // Every prefix handed here extends the extractor's previous one: the entry
    // only ever reveals forward within `target`, and setTarget resets the
    // display state (extractor included) whenever a new target is not an
    // append of the old one.
    const extracted = entry.stringExtractor?.update(prefix, true);
    if (extracted?.changed) {
        entry.parsedArgs = { ...entry.parsedArgs, ...extracted.values };
        parsedChanged = true;
    }
    const rawPrefixChanged = entry.exposeRawPartialJson && prefix !== entry.displayPrefix;
    if (!parsedChanged && !rawPrefixChanged)
        return { args: entry.displayArgs, changed: false };
    const displayPrefix = entry.exposeRawPartialJson || parsedChanged ? prefix : entry.displayPrefix;
    const args = { ...entry.parsedArgs, __partialJson: displayPrefix };
    entry.displayArgs = args;
    entry.displayPrefix = displayPrefix;
    return { args, changed: true };
}
/**
 * One-shot decode of a streamed tool-call argument buffer into display args —
 * the same decode the live reveal applies frame-by-frame, for paths that see
 * the buffer once (transcript rebuilds on theme change, settings, focus
 * replay). Keeps a rebuilt preview identical to the live preview: parsed
 * fields come from a fresh parse of the full buffer, `streamingStringKeys`
 * fields from the incremental string decoder (which also wins ties in the
 * live path), never from the provider's throttled `arguments`.
 */
export function decodeStreamedToolArgs(partialJson, source) {
    if (source.rawInput) {
        return { input: partialJson, __partialJson: partialJson };
    }
    const parsed = parseStreamingJson(partialJson);
    const args = source.fullArgs ? { ...source.fullArgs, ...parsed } : { ...parsed };
    const extracted = createStringExtractor(source.streamingStringKeys)?.update(partialJson);
    if (extracted)
        Object.assign(args, extracted.values);
    args.__partialJson = partialJson;
    return args;
}
/**
 * Paces streamed tool-call arguments the same way StreamingRevealController
 * paces assistant text: providers that deliver `partialJson` in large batches
 * (or throttle their partial parses) would otherwise make write/edit/bash
 * streaming previews jump in chunks. Each pending tool call reveals its raw
 * argument stream at the shared 30fps cadence with the same adaptive
 * catch-up step. JSON prefixes are parsed only when enough new bytes arrive to
 * change renderer-visible fields, while raw-prefix consumers still receive
 * fresh `__partialJson` on every reveal frame.
 *
 * Reveal units are UTF-16 code units of the raw stream, not graphemes —
 * the prefix goes through a JSON parser rather than straight to the screen,
 * so only surrogate-pair integrity matters (see {@link clampSliceEnd}).
 */
export class ToolArgsRevealController {
    #getSmoothStreaming;
    #requestRender;
    #entries = new Map();
    #timer;
    constructor(options) {
        this.#getSmoothStreaming = options.getSmoothStreaming;
        this.#requestRender = options.requestRender;
    }
    /**
     * Record the latest streamed argument text for a tool call and return the
     * args to render right now. With smoothing disabled nothing is paced — the
     * full received buffer decodes in one step — but the entry still runs the
     * incremental string decoder + parse throttle, so streamed text fields
     * (write `content`, edit bodies, eval `code`) stay fresh between the
     * provider's own throttled full-JSON parses instead of lagging up to
     * STREAMING_JSON_PARSE_MIN_GROWTH bytes behind.
     */
    setTarget(id, partialJson, target) {
        const { rawInput, exposeRawPartialJson, streamingStringKeys } = target;
        let entry = this.#entries.get(id);
        if (!entry) {
            entry = {
                component: undefined,
                target: partialJson,
                revealed: clampSliceEnd(partialJson, partialJson.length),
                rawInput,
                exposeRawPartialJson,
                parsedArgs: {},
                parsedLen: 0,
                displayArgs: initialDisplayArgs(),
                displayPrefix: "",
                streamingStringKeys: streamingStringKeys ?? [],
                stringExtractor: createStringExtractor(streamingStringKeys),
            };
            this.#entries.set(id, entry);
        }
        else {
            if (entry.rawInput !== rawInput ||
                entry.exposeRawPartialJson !== exposeRawPartialJson ||
                !sameStringKeys(entry.streamingStringKeys, streamingStringKeys)) {
                entry.rawInput = rawInput;
                entry.exposeRawPartialJson = exposeRawPartialJson;
                resetDisplayState(entry);
                entry.streamingStringKeys = streamingStringKeys ?? [];
                entry.stringExtractor = createStringExtractor(streamingStringKeys);
            }
            // Streams only append; a non-prefix target means a rewind — snap into range.
            if (!partialJson.startsWith(entry.target)) {
                entry.revealed = Math.min(entry.revealed, partialJson.length);
                resetDisplayState(entry);
            }
            entry.target = partialJson;
        }
        // Toggle may flip mid-call: snap the reveal to everything received so
        // pacing stops (and never restarts while the toggle stays off).
        if (!this.#getSmoothStreaming())
            entry.revealed = entry.target.length;
        entry.revealed = clampSliceEnd(entry.target, entry.revealed);
        this.#syncTimer();
        return displayArgsForPrefix(entry, entry.target.slice(0, entry.revealed)).args;
    }
    /** Attach the component future ticks push frames into. */
    bind(id, component) {
        const entry = this.#entries.get(id);
        if (entry)
            entry.component = component;
    }
    /** Final arguments arrived (the JSON closed): drop the reveal so the
     *  caller's final-args render wins immediately, mirroring how assistant
     *  text snaps to the full message at message_end. */
    finish(id) {
        this.#entries.delete(id);
        if (this.#entries.size === 0)
            this.#stopTimer();
    }
    /** Snap every live entry to its full received stream and clear. Used at
     *  message_end (abort/error mid-stream) so sealed components freeze showing
     *  everything that arrived rather than a mid-reveal prefix. */
    flushAll() {
        for (const [id, entry] of this.#entries) {
            if (entry.component && entry.revealed < entry.target.length) {
                entry.component.updateArgs(displayArgsForPrefix(entry, entry.target, true).args, id);
            }
        }
        this.#entries.clear();
        this.#stopTimer();
    }
    /** Clear without pushing (teardown). */
    stop() {
        this.#entries.clear();
        this.#stopTimer();
    }
    #syncTimer() {
        for (const entry of this.#entries.values()) {
            if (entry.revealed < entry.target.length) {
                this.#startTimer();
                return;
            }
        }
        this.#stopTimer();
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
        let advanced = false;
        // Collect components with changed display args; render each subtree once
        // per tick even when multiple entries share a component (they don't
        // today, but the API contract doesn't prevent it).
        const rendered = new Set();
        for (const [id, entry] of this.#entries) {
            const backlog = entry.target.length - entry.revealed;
            if (backlog <= 0 || !entry.component)
                continue;
            entry.revealed = clampSliceEnd(entry.target, entry.revealed + nextStep(backlog));
            const display = displayArgsForPrefix(entry, entry.target.slice(0, entry.revealed));
            if (display.changed) {
                entry.component.updateArgs(display.args, id);
                rendered.add(entry.component);
            }
            advanced = true;
        }
        if (advanced) {
            for (const component of rendered)
                this.#requestRender(component);
        }
        else {
            // Every entry caught up (or unbound); setTarget restarts on growth.
            this.#stopTimer();
        }
    }
}
