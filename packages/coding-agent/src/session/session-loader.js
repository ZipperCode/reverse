import { ConcatSink, getBlobsDir, isEisdir, isEnoent, isEnotdir, parseJsonlLenient } from "@rva/utils";
import * as snapcompact from "@rva/snapcompact";
import { Semaphore } from "../task/parallel";
import { BlobStore, isBlobRef, lazyImageDataSync, resolveImageData, resolveImageDataSync, resolveImageDataUrl, resolveImageDataUrlSync, } from "./blob-store";
import { buildSessionContext } from "./session-context";
import { migrateToCurrentVersion } from "./session-migrations";
import { isExternalizableImagePosition, isPersistenceTruncatedString } from "./session-persistence";
import { FileSessionStorage } from "./session-storage";
import { parseTitleSlotFromContent, parseTitleSlotLine, titleUpdateFromSlot, } from "./session-title-slot";
const LF = new Uint8Array([0x0a]);
const STREAM_LOAD_THRESHOLD_BYTES = 8 * 1024 * 1024;
const STREAM_YIELD_BYTES = 1 * 1024 * 1024;
const STREAM_YIELD_ENTRIES = 8192;
const BLOB_READ_CONCURRENCY = 8;
/**
 * Complete optional accounting fields from persisted/imported assistant turns.
 * Complete provider usage is left untouched; missing prices never discard reported tokens.
 */
export function normalizeAssistantUsage(message) {
    const usage = message.usage;
    if (usage &&
        usage.input !== undefined &&
        usage.output !== undefined &&
        usage.cacheRead !== undefined &&
        usage.cacheWrite !== undefined &&
        usage.totalTokens !== undefined &&
        usage.cost?.input !== undefined &&
        usage.cost.output !== undefined &&
        usage.cost.cacheRead !== undefined &&
        usage.cost.cacheWrite !== undefined &&
        usage.cost.total !== undefined) {
        return false;
    }
    const input = usage?.input ?? 0;
    const output = usage?.output ?? 0;
    const cacheRead = usage?.cacheRead ?? 0;
    const cacheWrite = usage?.cacheWrite ?? 0;
    const cost = usage?.cost;
    message.usage = {
        ...usage,
        input,
        output,
        cacheRead,
        cacheWrite,
        totalTokens: usage?.totalTokens ??
            input +
                output +
                cacheRead +
                cacheWrite +
                (usage?.orchestration?.input ?? 0) +
                (usage?.orchestration?.cacheRead ?? 0) +
                (usage?.orchestration?.output ?? 0),
        cost: {
            ...cost,
            input: cost?.input ?? 0,
            output: cost?.output ?? 0,
            cacheRead: cost?.cacheRead ?? 0,
            cacheWrite: cost?.cacheWrite ?? 0,
            total: cost?.total ?? (cost?.input ?? 0) + (cost?.output ?? 0) + (cost?.cacheRead ?? 0) + (cost?.cacheWrite ?? 0),
        },
    };
    return true;
}
function splitTitleSlot(content) {
    const slot = titleUpdateFromSlot(parseTitleSlotFromContent(content));
    if (!slot)
        return { body: content, slot: undefined };
    const newlineIndex = content.indexOf("\n");
    return { body: content.slice(newlineIndex + 1), slot };
}
function isValidSessionHeader(entry) {
    return entry?.type === "session" && typeof entry.id === "string";
}
function applyTitleSlot(entry, slot) {
    if (!slot || !isValidSessionHeader(entry))
        return;
    if (slot.title && slot.title.length > 0) {
        entry.title = slot.title;
    }
    else {
        delete entry.title;
    }
    if (slot.source) {
        entry.titleSource = slot.source;
    }
    else {
        delete entry.titleSource;
    }
}
/** Parse session JSONL while stripping and folding the optional fixed title slot. */
export function parseSessionContent(content) {
    const { body, slot } = splitTitleSlot(content);
    let malformedRecords = 0;
    const entries = parseJsonlLenient(body, {
        onMalformedRecord: () => {
            malformedRecords++;
        },
    });
    applyTitleSlot(entries[0], slot);
    return {
        entries,
        titleSlot: slot,
        malformedRecords,
        sourceSize: Buffer.byteLength(content, "utf8"),
        invalidHeader: entries.length > 0 ? !isValidSessionHeader(entries[0]) : malformedRecords > 0,
    };
}
/** Upper bound on the bytes read to find a header: real headers (and the title slot before them) are far smaller. */
const SESSION_HEADER_READ_LIMIT = 1024 * 1024;
/**
 * The session id in `filePath`'s header, or `undefined` when there is no file
 * there or it does not start with a valid session header. Reads at most one
 * record and {@link SESSION_HEADER_READ_LIMIT} bytes.
 */
export async function readSessionHeaderId(filePath) {
    let id;
    try {
        await visitEntriesFromFileStream(filePath, entry => {
            if (isValidSessionHeader(entry))
                id = entry.id;
            return false;
        }, { maxRecords: 1, maxBytes: SESSION_HEADER_READ_LIMIT });
    }
    catch (err) {
        if (isEnoent(err) || isEnotdir(err) || isEisdir(err))
            return undefined;
        throw err;
    }
    return id;
}
/** Parse session JSONL and visit each entry without retaining prior entries. */
export async function visitEntriesFromFileStream(filePath, visit, options = {}) {
    let titleSlot;
    let sawFirstLine = false;
    let sawFirstEntry = false;
    let bytesSinceYield = 0;
    let entriesSinceYield = 0;
    let recordsSeen = 0;
    const maxRecords = Math.max(0, options.maxRecords ?? Number.POSITIVE_INFINITY);
    let stopped = false;
    let visitorThrew = false;
    const yieldEveryBytes = Math.max(0, options.yieldEveryBytes ?? STREAM_YIELD_BYTES);
    const yieldEveryEntries = Math.max(0, options.yieldEveryEntries ?? STREAM_YIELD_ENTRIES);
    const maxBytes = Math.max(0, options.maxBytes ?? Number.POSITIVE_INFINITY);
    // Bytes, not text: a multibyte UTF-8 sequence straddling a chunk boundary
    // stays intact, and Bun.JSONL.parseChunk takes typed arrays directly. Only
    // the unconsumed remainder is held (≤ one record + a chunk), so the ≥8MiB
    // memory guard holds — the file is never fully loaded.
    const sink = new ConcatSink();
    const decoder = new TextDecoder();
    const yieldToMacrotask = async () => {
        if (yieldEveryBytes === 0 && yieldEveryEntries === 0)
            return;
        const bytesReady = yieldEveryBytes === 0 || bytesSinceYield < yieldEveryBytes;
        const entriesReady = yieldEveryEntries === 0 || entriesSinceYield < yieldEveryEntries;
        if (bytesReady && entriesReady) {
            return;
        }
        bytesSinceYield = 0;
        entriesSinceYield = 0;
        await Bun.sleep(0);
    };
    const hasPayload = (bytes, start, end) => {
        for (let index = start; index < end; index++) {
            const byte = bytes[index];
            if (byte !== 0x09 && byte !== 0x0a && byte !== 0x0d && byte !== 0x20)
                return true;
        }
        return false;
    };
    const drain = async (endOfInput = false) => {
        const view = sink.flush();
        if (!view)
            return;
        // Only newline-terminated bytes may reach the parser: a trailing fragment
        // in the same call turns an end-of-input `done` into a syntax error at the
        // preceding newline, which would then be miscounted as a malformed record.
        const lastNewline = view.lastIndexOf(0x0a);
        if (lastNewline === -1)
            return;
        let buffer = view.subarray(0, lastNewline + 1);
        let consumed = 0;
        const advance = (count) => {
            consumed += count;
            buffer = buffer.subarray(count);
        };
        while (buffer.length > 0 && !stopped) {
            if (recordsSeen >= maxRecords) {
                stopped = true;
                break;
            }
            const { values, error, read, done } = Bun.JSONL.parseChunk(buffer);
            for (const value of values) {
                if (recordsSeen >= maxRecords) {
                    stopped = true;
                    break;
                }
                if (options.shouldContinue && !options.shouldContinue()) {
                    stopped = true;
                    break;
                }
                const entry = value;
                if (!sawFirstEntry) {
                    sawFirstEntry = true;
                    applyTitleSlot(entry, titleSlot);
                }
                try {
                    if (visit(entry) === false) {
                        stopped = true;
                        break;
                    }
                    recordsSeen++;
                    entriesSinceYield++;
                    if (recordsSeen >= maxRecords) {
                        stopped = true;
                        break;
                    }
                }
                catch (err) {
                    visitorThrew = true;
                    throw err;
                }
                await yieldToMacrotask();
            }
            if (stopped)
                break;
            if (error) {
                // Malformed record: skip past the next newline and continue.
                const nextNewline = buffer.indexOf(0x0a, read);
                if (nextNewline === -1)
                    break; // rest of the bad line not yet received
                if (hasPayload(buffer, read, nextNewline))
                    options.onMalformedRecord?.();
                recordsSeen++;
                advance(nextNewline + 1);
                if (recordsSeen >= maxRecords) {
                    stopped = true;
                    break;
                }
                continue;
            }
            if (read === 0) {
                // Incomplete value awaiting more bytes. Once the input has ended nothing more
                // is coming, so it is a truncated record (parseJsonlLenient counts it too).
                if (endOfInput) {
                    if (hasPayload(buffer, 0, buffer.length))
                        options.onMalformedRecord?.();
                    recordsSeen++;
                    advance(buffer.length);
                }
                break;
            }
            advance(read);
            if (done) {
                advance(buffer.length);
                break;
            }
        }
        sink.consume(consumed);
    };
    try {
        const file = Bun.file(filePath);
        const source = Number.isFinite(maxBytes) ? file.slice(0, maxBytes) : file;
        for await (const chunk of source.stream()) {
            if (stopped)
                break;
            bytesSinceYield += chunk.byteLength;
            options.onBytesConsumed?.(chunk.byteLength);
            // Parsing before the chunk closes a line re-scans the unfinished record
            // on every chunk, which is quadratic for large records.
            if (chunk.lastIndexOf(0x0a) === -1) {
                // Skipping drain() also skips the only enforcement of the record cap,
                // so re-check it here: a delimiter-free file would otherwise be read
                // and buffered in full despite an exhausted budget.
                if (recordsSeen >= maxRecords) {
                    stopped = true;
                    break;
                }
                sink.append(chunk);
                await yieldToMacrotask();
                continue;
            }
            sink.append(chunk);
            // The optional fixed-width title slot is a physical first line that is
            // NOT JSON; peel it before the parser would (correctly) reject it. The
            // first line ends at a '\n' byte, so it is a complete UTF-8 sequence and
            // safe to decode. A non-slot first line is a real entry and is left for
            // the parser; a blank first line is left for the parser to skip.
            if (!sawFirstLine) {
                const buffered = sink.flush();
                const newline = buffered.indexOf(0x0a);
                if (newline !== -1) {
                    sawFirstLine = true;
                    const firstLine = decoder.decode(buffered.subarray(0, newline)).trim();
                    if (firstLine) {
                        const slot = parseTitleSlotLine(firstLine);
                        if (slot) {
                            titleSlot = titleUpdateFromSlot(slot);
                            sink.consume(newline + 1);
                        }
                    }
                }
            }
            // parseChunk can leave a value unfinished even after a newline; the
            // sink keeps that remainder for the next chunk.
            await drain();
            await yieldToMacrotask();
        }
        // A trailing record without a final newline: terminate it so the parser
        // can complete it (readline yielded it; parseChunk needs the delimiter).
        if (!stopped && !sink.isEmpty) {
            sink.append(LF);
            await drain(true);
        }
    }
    catch (err) {
        if (visitorThrew)
            throw err;
        if (options.throwIfMissing && (isEnoent(err) || isEnotdir(err))) {
            throw err;
        }
        if (isEnoent(err)) {
            return undefined;
        }
        throw err;
    }
    return titleSlot;
}
/** Exported for testing — the ≥8MiB streaming path (works on any file size). */
export async function loadEntriesFromFileStream(filePath, options) {
    const entries = [];
    let malformedRecords = 0;
    let bytesConsumed = 0;
    const titleSlot = await visitEntriesFromFileStream(filePath, entry => {
        entries.push(entry);
    }, {
        onMalformedRecord: () => {
            malformedRecords++;
        },
        throwIfMissing: options?.throwIfMissing,
        onBytesConsumed: bytes => {
            bytesConsumed += bytes;
        },
    });
    return {
        entries,
        titleSlot,
        malformedRecords,
        sourceSize: bytesConsumed,
        invalidHeader: entries.length > 0 ? !isValidSessionHeader(entries[0]) : malformedRecords > 0,
    };
}
/** Exported for compaction.test.ts */
export function parseSessionEntries(content) {
    return parseSessionContent(content).entries;
}
function shouldStreamEntries(storage, size) {
    return storage instanceof FileSessionStorage && size >= STREAM_LOAD_THRESHOLD_BYTES;
}
async function loadWithKnownSize(filePath, storage, size, options) {
    if (shouldStreamEntries(storage, size)) {
        const loaded = await loadEntriesFromFileStream(filePath, { throwIfMissing: options?.throwIfMissing });
        const sourceSize = loaded.sourceSize ?? 0;
        return { loaded: loaded.invalidHeader ? { ...loaded, entries: [] } : loaded, sourceSize };
    }
    const content = await storage.readText(filePath);
    const loaded = parseSessionContent(content);
    return {
        loaded: loaded.invalidHeader ? { ...loaded, entries: [] } : loaded,
        sourceSize: Buffer.byteLength(content, "utf8"),
    };
}
/** Load and validate a session while retaining malformed-record diagnostics. */
export async function loadSessionFile(filePath, storage = new FileSessionStorage(), options = {}) {
    try {
        const statSize = storage.statSync(filePath).size;
        const { loaded, sourceSize } = await loadWithKnownSize(filePath, storage, statSize, options);
        return { ...loaded, sourceSize };
    }
    catch (err) {
        if (options?.throwIfMissing && (isEnoent(err) || isEnotdir(err))) {
            throw err;
        }
        if (isEnoent(err)) {
            return {
                entries: [],
                titleSlot: undefined,
                malformedRecords: 0,
                sourceSize: null,
                invalidHeader: false,
            };
        }
        throw err;
    }
}
/**
 * Load the valid entries from a session file, skipping malformed records.
 * Each call returns freshly parsed entries owned by the caller.
 */
export async function loadEntriesFromFile(filePath, storage = new FileSessionStorage(), options) {
    return (await loadSessionFile(filePath, storage, options)).entries;
}
/**
 * Visit session entries, using bounded streaming for large file-backed journals.
 * Small files and non-file backends keep the existing full-load path.
 */
export async function visitEntriesFromFile(filePath, visit, storage = new FileSessionStorage()) {
    const size = storage.statSync(filePath).size;
    if (shouldStreamEntries(storage, size)) {
        let sawFirstEntry = false;
        await visitEntriesFromFileStream(filePath, entry => {
            if (!sawFirstEntry) {
                sawFirstEntry = true;
                if (!isValidSessionHeader(entry))
                    return false;
            }
            return visit(entry);
        });
        return;
    }
    for (const entry of (await loadWithKnownSize(filePath, storage, size)).loaded.entries) {
        if (visit(entry) === false)
            return;
    }
}
function hasImageUrl(value) {
    return typeof value === "object" && value !== null && "image_url" in value && typeof value.image_url === "string";
}
/**
 * Collect the blob references in session image blocks and provider image URLs.
 * Snapcompact frames stay as references until context rebuilding selects them.
 */
function collectBlobRefSites(value, sites, key) {
    if (key !== "frames" && isExternalizableImagePosition(value, key) && isBlobRef(value.data)) {
        sites.push({ holder: value, key: "data", ref: value.data, asDataUrl: false });
        return;
    }
    if (Array.isArray(value)) {
        for (const item of value)
            collectBlobRefSites(item, sites, key);
        return;
    }
    if (typeof value !== "object" || value === null)
        return;
    const holder = value;
    if (holder.type === "image_generation_call" && typeof holder.result === "string" && isBlobRef(holder.result)) {
        sites.push({ holder, key: "result", ref: holder.result, asDataUrl: false });
    }
    if (hasImageUrl(value) && isBlobRef(value.image_url)) {
        sites.push({ holder, key: "image_url", ref: value.image_url, asDataUrl: true });
    }
    for (const childKey in holder)
        collectBlobRefSites(holder[childKey], sites, childKey);
}
/**
 * Cheap synchronous precheck: does this value's tree contain any `blob:sha256:` string?
 * Early-exits on the first hit, so blob-free entries skip the
 * {@link collectBlobRefSites} descent entirely. Conservative — a blob ref in a
 * non-resolved position still returns true, which only costs an extra (no-op) walk.
 */
function containsBlobRef(value) {
    if (typeof value === "string")
        return isBlobRef(value);
    if (Array.isArray(value)) {
        for (const item of value) {
            if (containsBlobRef(item))
                return true;
        }
        return false;
    }
    if (typeof value !== "object" || value === null)
        return false;
    for (const key in value) {
        if (containsBlobRef(value[key]))
            return true;
    }
    return false;
}
/**
 * Older persistence versions truncated oversized frame base64 in place. Recover
 * those archives from their retained source text so an already-wedged session
 * resumes as text instead of sending malformed image data to the provider.
 */
function repairTruncatedSnapcompactFrames(entry) {
    if (entry.type !== "compaction")
        return;
    const archive = snapcompact.getPreservedArchive(entry.preserveData);
    if (!archive?.frames.some(frame => isPersistenceTruncatedString(frame.data)))
        return;
    const slot = entry.preserveData?.[snapcompact.PRESERVE_KEY];
    if (typeof slot !== "object" || slot === null)
        return;
    if (archive.text) {
        Object.assign(slot, { frames: [], textHead: archive.text, textTail: "" });
        return;
    }
    Object.assign(slot, {
        frames: archive.frames.filter(frame => !isPersistenceTruncatedString(frame.data)),
    });
}
function blobRefSites(values) {
    const sites = [];
    for (const value of values) {
        if (containsBlobRef(value))
            collectBlobRefSites(value, sites);
    }
    return sites;
}
function blobSiteKey(site) {
    return `${site.asDataUrl ? "url" : "base64"}:${site.ref}`;
}
async function resolveBlobRefs(values, blobStore) {
    const semaphore = new Semaphore(BLOB_READ_CONCURRENCY);
    const resolved = new Map();
    await Promise.all(blobRefSites(values).map(async (site) => {
        const key = blobSiteKey(site);
        let data = resolved.get(key);
        if (!data) {
            data = (async () => {
                await semaphore.acquire();
                try {
                    return await (site.asDataUrl
                        ? resolveImageDataUrl(blobStore, site.ref)
                        : resolveImageData(blobStore, site.ref));
                }
                finally {
                    semaphore.release();
                }
            })();
            resolved.set(key, data);
        }
        site.holder[site.key] = await data;
    }));
}
/** The non-header entries, with legacy truncated snapcompact frames repaired before their blobs resolve. */
function entriesForBlobResolution(entries) {
    const sessionEntries = entries.filter(entry => entry.type !== "session");
    for (const entry of sessionEntries)
        repairTruncatedSnapcompactFrames(entry);
    return sessionEntries;
}
/** Restore the image data that persistence externalized to the blob store, in place. */
export async function resolveBlobRefsInEntries(entries, blobStore) {
    await resolveBlobRefs(entriesForBlobResolution(entries), blobStore);
}
/** Synchronous {@link resolveBlobRefsInEntries}. */
export function resolveBlobRefsInEntriesSync(entries, blobStore) {
    const resolved = new Map();
    for (const site of blobRefSites(entriesForBlobResolution(entries))) {
        const key = blobSiteKey(site);
        let data = resolved.get(key);
        if (data === undefined) {
            data = site.asDataUrl
                ? resolveImageDataUrlSync(blobStore, site.ref)
                : resolveImageDataSync(blobStore, site.ref);
            resolved.set(key, data);
        }
        site.holder[site.key] = data;
    }
}
/**
 * Read-only transcript view of a session file: load entries, migrate to the
 * current version, resolve blob refs, and build the display transcript along
 * the persisted leaf path (last entry). Uses transcript mode (collapsed to the
 * latest compaction) so failed/aborted tail turns stay visible, unlike the
 * provider-context builder which drops them. Does NOT create a writer or take
 * the session lock — safe to call against a file another session is writing.
 */
export async function loadSessionMessagesReadOnly(filePath) {
    const entries = await loadEntriesFromFile(filePath);
    if (entries.length === 0)
        return [];
    migrateToCurrentVersion(entries);
    for (const entry of entries)
        repairTruncatedSnapcompactFrames(entry);
    const blobs = new BlobStore(getBlobsDir());
    const sessionEntries = entries.filter((e) => e.type !== "session");
    const { messages } = buildSessionContext(sessionEntries, undefined, undefined, {
        transcript: true,
        collapseCompactedHistory: true,
        resolveFrameData: data => lazyImageDataSync(blobs, data),
    });
    // A collapsed summary carries the remote-compaction replacement history for
    // provider replay only; this transcript is never replayed, and the renderer
    // reads just the summary. Dropping it keeps hydration off every image blob
    // buried in that hidden history.
    const displayMessages = messages.map(message => message.role === "compactionSummary" && message.providerPayload !== undefined
        ? { ...message, providerPayload: undefined }
        : message);
    await resolveBlobRefs(displayMessages, blobs);
    return displayMessages;
}
