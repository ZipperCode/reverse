/** Frameless Bidi model used by Codex Desktop live calls. */
export const LIVE_MODEL = "gpt-live-1-codex";
/** Maximum UTF-8 payload size accepted by each context append. */
export const CONTEXT_CHUNK_BYTES = 500;
function isRecord(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function parsePayload(payload) {
    let parsed = payload;
    if (typeof payload === "string") {
        try {
            parsed = JSON.parse(payload);
        }
        catch {
            return null;
        }
    }
    return isRecord(parsed) ? parsed : null;
}
function parseSessionEvent(type, payload) {
    const session = payload.session;
    if (!isRecord(session) || typeof session.id !== "string")
        return null;
    if (typeof session.instructions === "string") {
        return { type, session: { id: session.id, instructions: session.instructions } };
    }
    return { type, session: { id: session.id } };
}
function parseTranscriptAddedEvent(type, payload) {
    const item = payload.item;
    if (!isRecord(item) || typeof item.text !== "string")
        return null;
    return { type, item: { text: item.text } };
}
function parseTurnDoneEvent(payload) {
    const turn = payload.turn;
    if (!isRecord(turn) || (turn.role !== "user" && turn.role !== "assistant"))
        return null;
    if (typeof turn.transcript !== "string")
        return null;
    return { type: "turn.done", turn: { role: turn.role, transcript: turn.transcript } };
}
function parseDelegationCreatedEvent(payload) {
    const item = payload.item;
    if (!isRecord(item) || item.type !== "delegation" || item.target !== "client" || typeof item.id !== "string") {
        return null;
    }
    if (!Array.isArray(item.content))
        return null;
    const content = [];
    for (const candidate of item.content) {
        if (!isRecord(candidate) || candidate.type !== "input_text" || typeof candidate.text !== "string")
            continue;
        content.push({ type: "input_text", text: candidate.text });
    }
    return {
        type: "delegation.created",
        item: { type: "delegation", target: "client", id: item.id, content },
    };
}
function stringifyErrorValue(value) {
    if (typeof value === "string")
        return value;
    if (value === undefined)
        return null;
    try {
        return JSON.stringify(value) ?? null;
    }
    catch {
        return String(value);
    }
}
function parseErrorEvent(payload) {
    if (typeof payload.message === "string")
        return { type: "error", message: payload.message };
    const error = payload.error;
    if (isRecord(error) && typeof error.message === "string") {
        return { type: "error", message: error.message };
    }
    const message = stringifyErrorValue(error);
    return message === null ? null : { type: "error", message };
}
/** Parse a JSON string or decoded value from the Frameless Bidi data channel. */
export function parseLiveServerEvent(payload) {
    const parsed = parsePayload(payload);
    if (!parsed || typeof parsed.type !== "string")
        return null;
    switch (parsed.type) {
        case "session.started":
        case "session.updated":
            return parseSessionEvent(parsed.type, parsed);
        case "output_audio.delta":
            return typeof parsed.audio === "string" ? { type: parsed.type, audio: parsed.audio } : null;
        case "input_transcript.added":
        case "output_transcript.added":
            return parseTranscriptAddedEvent(parsed.type, parsed);
        case "turn.done":
            return parseTurnDoneEvent(parsed);
        case "delegation.created":
            return parseDelegationCreatedEvent(parsed);
        case "error":
            return parseErrorEvent(parsed);
        default:
            return { type: "unknown", wireType: parsed.type };
    }
}
/** Build the session object posted in the multipart WebRTC call request. */
export function buildLiveSessionPayload(instructions, voice) {
    return {
        model: LIVE_MODEL,
        instructions,
        audio: { output: { voice } },
        delegation: { type: "client" },
    };
}
/** Build a context append associated with a server-created delegation. */
export function buildDelegationContextAppend(delegationItemId, text, channel) {
    return {
        type: "delegation.context.append",
        delegation_item_id: delegationItemId,
        ...(channel === undefined ? {} : { channel }),
        content: [{ type: "input_text", text }],
    };
}
/** Build context appended to the live session outside a delegation. */
export function buildSessionContextAppend(text, channel) {
    return {
        type: "session.context.append",
        ...(channel === undefined ? {} : { channel }),
        content: [{ type: "input_text", text }],
    };
}
/** Build the message that gracefully closes a live session. */
export function buildSessionClose() {
    return { type: "session.close" };
}
function utf8ByteLength(codePoint) {
    if (codePoint <= 0x7f)
        return 1;
    if (codePoint <= 0x7ff)
        return 2;
    if (codePoint <= 0xffff)
        return 3;
    return 4;
}
/** Split context into character-safe chunks of at most 500 UTF-8 bytes. */
export function chunkLiveContext(text) {
    if (text.length === 0)
        return [""];
    const chunks = [];
    let chunkStart = 0;
    let chunkBytes = 0;
    let index = 0;
    while (index < text.length) {
        const codePoint = text.codePointAt(index);
        if (codePoint === undefined)
            break;
        const characterLength = codePoint > 0xffff ? 2 : 1;
        const characterBytes = utf8ByteLength(codePoint);
        if (chunkBytes + characterBytes > CONTEXT_CHUNK_BYTES) {
            chunks.push(text.slice(chunkStart, index));
            chunkStart = index;
            chunkBytes = 0;
        }
        chunkBytes += characterBytes;
        index += characterLength;
    }
    chunks.push(text.slice(chunkStart));
    return chunks;
}
