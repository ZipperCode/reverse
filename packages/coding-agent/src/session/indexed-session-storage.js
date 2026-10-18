import * as path from "node:path";
import { toError } from "@rva/utils";
import { directChildKeyName, SessionWriteConflictError, } from "./session-storage";
import { isAssistantMessageLine } from "./session-entries";
import { enoent } from "./session-storage-errors";
import { overlayTitleSlotContent, overlayTitleSlotPrefix, parseTitleSlotFromContent, titleUpdateFromSlot, } from "./session-title-slot";
const RESOLVED = Promise.resolve();
function matchesGlob(name, pattern) {
    if (pattern === "*")
        return true;
    if (pattern.startsWith("*."))
        return name.endsWith(pattern.slice(1));
    return name === pattern;
}
function byteLength(text) {
    return Buffer.byteLength(text, "utf-8");
}
function normalizeByteLimit(maxBytes) {
    if (!(maxBytes > 0))
        return 0;
    return Math.trunc(maxBytes);
}
function uniquePaths(paths) {
    const out = [];
    const seen = new Set();
    for (const path of paths) {
        if (seen.has(path))
            continue;
        seen.add(path);
        out.push(path);
    }
    return out;
}
function titleUpdateForIndex(entry) {
    if (!entry.titleUpdatedAt)
        return undefined;
    return { title: entry.title, source: entry.titleSource, updatedAt: entry.titleUpdatedAt };
}
export class IndexedSessionStorage {
    /**
     * Sync writes only update {@link #index} and queue the remote publish, so a
     * caller tracking a durable byte size must wait for {@link drain}.
     */
    defersSyncPublish = true;
    #backend;
    #index = new Map();
    #writers = new Set();
    #pathTails = new Map();
    #pathPending = new Map();
    #drainPending = new Set();
    /**
     * Live optimistic index frames per path, oldest first. Every synchronous
     * index update whose backend op is still queued pushes a frame; settlement
     * drops it (success) or drops it and every frame queued behind it and
     * restores the earliest dropped frame's entry (failure). Rolling back to
     * the last durable entry instead of the immediately previous one keeps a
     * failed op in a chain from stranding later recovery rewrites on an
     * unreachable CAS token (rJDg).
     */
    #pendingFrames = new Map();
    #nextMtimeMs = 0;
    #firstDrainError;
    #assertExpectedSize(path, expectedSize) {
        if (expectedSize === undefined)
            return;
        const actualSize = this.#index.get(path)?.size ?? null;
        if (actualSize !== expectedSize) {
            throw new SessionWriteConflictError(path, expectedSize, actualSize);
        }
    }
    constructor(backend) {
        this.#backend = backend;
    }
    async initialize() {
        await this.#backend.init();
        await this.refresh();
    }
    async refresh() {
        await this.drain();
        const rows = await this.#backend.loadIndex();
        this.#index.clear();
        for (const row of rows) {
            const title = row.titleUpdatedAt
                ? { title: row.title, source: row.titleSource, updatedAt: row.titleUpdatedAt }
                : null;
            this.#setIndex(row.path, row.size, row.mtimeMs, title);
        }
    }
    async drain() {
        // Quiesce EVERY pending backend operation, not just the drain-tracked
        // fire-and-forget publishes: an atomic write whose commit guard passed
        // just before a terminal seal is still on the wire with
        // `trackDrain: false`, and a graceful shutdown (SessionManager.close)
        // must not return while it can still publish under a reopened path.
        while (this.#drainPending.size > 0 || this.#pathPending.size > 0) {
            await Promise.allSettled([...this.#drainPending, ...this.#pathPending.values()]);
        }
        const error = this.#firstDrainError;
        this.#firstDrainError = undefined;
        if (error)
            throw error;
    }
    ensureDirSync(_dir) {
        // Indexed backends are flat: directories are derived from key prefixes.
    }
    existsSync(path) {
        return this.#index.has(path);
    }
    /**
     * Resolve once the publishes queued for `path` have settled, rejecting when
     * one failed. The path tail is installed synchronously by `#enqueuePaths`,
     * so a caller confirming immediately after `writeTextSync` observes its own
     * write rather than a later one.
     */
    confirmWrites(path) {
        return this.#awaitPath(path);
    }
    writeTextSync(path, content, options) {
        this.#assertExpectedSize(path, options?.expectedSize);
        const previous = this.#index.get(path);
        const mtimeMs = this.#allocMtimeMs();
        const title = titleUpdateFromSlot(parseTitleSlotFromContent(content));
        this.#setIndex(path, byteLength(content), mtimeMs, title ?? null);
        this.#pushFrame(path, { mtimeMs, previous });
        const write = this.#enqueuePath(path, () => this.#backend.writeFull(path, content, mtimeMs, title, options?.expectedSize), { trackDrain: true });
        this.#trackFrame(path, mtimeMs, write);
    }
    async updateSessionTitle(path, title) {
        await this.#awaitPath(path);
        const previous = this.#index.get(path);
        if (!previous)
            throw enoent(path);
        const mtimeMs = this.#allocMtimeMs();
        const next = {
            ...previous,
            title: title.title,
            titleSource: title.source,
            titleUpdatedAt: title.updatedAt,
            mtimeMs,
        };
        this.#index.set(path, next);
        this.#pushFrame(path, { mtimeMs, previous });
        const pending = this.#enqueuePath(path, () => this.#backend.updateSessionTitle(path, title, mtimeMs), {
            trackDrain: false,
        });
        this.#trackFrame(path, mtimeMs, pending);
        try {
            await pending;
        }
        catch (err) {
            throw toError(err);
        }
    }
    statSync(path) {
        const entry = this.#index.get(path);
        if (!entry)
            throw enoent(path);
        return {
            size: entry.size,
            mtimeMs: entry.mtimeMs,
            mtime: new Date(entry.mtimeMs),
        };
    }
    listFilesSync(dir, pattern) {
        const resolvedDir = path.resolve(dir);
        const out = [];
        for (const key of this.#index.keys()) {
            const name = directChildKeyName(resolvedDir, key);
            if (name === undefined || !matchesGlob(name, pattern))
                continue;
            out.push(key);
        }
        return out;
    }
    exists(path) {
        return Promise.resolve(this.existsSync(path));
    }
    async readText(path) {
        const entry = this.#index.get(path);
        if (!entry)
            throw enoent(path);
        await this.#awaitPath(path);
        const content = await this.#backend.readFull(path);
        if (content === null)
            throw enoent(path);
        const title = titleUpdateForIndex(entry);
        return title ? overlayTitleSlotContent(content, title) : content;
    }
    async readTextSlices(path, prefixBytes, suffixBytes) {
        const entry = this.#index.get(path);
        if (!entry)
            throw enoent(path);
        const prefixLimit = normalizeByteLimit(prefixBytes);
        const suffixLimit = normalizeByteLimit(suffixBytes);
        if (prefixLimit === 0 && suffixLimit === 0)
            return ["", ""];
        await this.#awaitPath(path);
        const [prefix, suffix] = await this.#backend.readSlices(path, prefixLimit, suffixLimit);
        const title = titleUpdateForIndex(entry);
        return [title ? overlayTitleSlotPrefix(prefix, prefixLimit, title) : prefix, suffix];
    }
    async hasAssistantTurn(path) {
        for (const line of (await this.readText(path)).split("\n")) {
            if (isAssistantMessageLine(line))
                return true;
        }
        return false;
    }
    async writeText(path, content) {
        await this.#awaitPath(path);
        const previous = this.#index.get(path);
        const mtimeMs = this.#allocMtimeMs();
        const title = titleUpdateFromSlot(parseTitleSlotFromContent(content));
        this.#setIndex(path, byteLength(content), mtimeMs, title ?? null);
        this.#pushFrame(path, { mtimeMs, previous });
        const pending = this.#enqueuePath(path, () => this.#backend.writeFull(path, content, mtimeMs, title), {
            trackDrain: false,
        });
        this.#trackFrame(path, mtimeMs, pending);
        await pending;
    }
    async writeTextAtomic(path, content, options) {
        const commitGuard = options?.commitGuard;
        if (commitGuard && !commitGuard())
            return;
        await this.#awaitPath(path);
        // A concurrent flushSync (writeTextSync) may have taken over during the
        // awaitPath yield and bumped the epoch. Re-check before touching the
        // index or enqueueing the backend publish.
        if (commitGuard && !commitGuard())
            return;
        this.#assertExpectedSize(path, options?.expectedSize);
        const previous = this.#index.get(path);
        const mtimeMs = this.#allocMtimeMs();
        const title = titleUpdateFromSlot(parseTitleSlotFromContent(content));
        this.#setIndex(path, byteLength(content), mtimeMs, title ?? null);
        this.#pushFrame(path, { mtimeMs, previous });
        try {
            await this.#enqueuePath(path, async () => {
                // Final guard immediately before the backend actually publishes.
                // If a concurrent writer has advanced the index past our
                // optimistic entry, leave that newer state alone; otherwise
                // restore the pre-write snapshot so readers do not observe a
                // body we never wrote.
                if (commitGuard && !commitGuard()) {
                    const current = this.#index.get(path);
                    if (current?.mtimeMs === mtimeMs)
                        this.#restoreIndex(path, previous);
                    this.#dropFrame(path, mtimeMs);
                    return;
                }
                await this.#backend.writeFull(path, content, mtimeMs, title, options?.expectedSize);
            }, { trackDrain: false });
            this.#dropFrame(path, mtimeMs);
        }
        catch (err) {
            const error = toError(err);
            try {
                if ((await this.#backend.readFull(path)) === content) {
                    this.#dropFrame(path, mtimeMs);
                    return;
                }
            }
            catch {
                // Preserve the original write failure; verification was unavailable.
            }
            this.#failFrame(path, mtimeMs);
            throw error;
        }
    }
    async rename(src, dst) {
        await this.#awaitPath(src);
        await this.#awaitPath(dst);
        const entry = this.#index.get(src);
        if (!entry)
            throw enoent(src);
        if (src === dst) {
            await this.#enqueuePath(src, () => this.#backend.move(src, dst, entry.mtimeMs), { trackDrain: false });
            return;
        }
        const dstPrevious = this.#index.get(dst);
        this.#index.delete(src);
        this.#index.set(dst, { ...entry });
        this.#pushFrame(src, { mtimeMs: entry.mtimeMs, previous: entry });
        this.#pushFrame(dst, { mtimeMs: entry.mtimeMs, previous: dstPrevious });
        try {
            await this.#enqueuePaths([src, dst], () => this.#backend.move(src, dst, entry.mtimeMs), { trackDrain: false });
            this.#dropFrame(src, entry.mtimeMs);
            this.#dropFrame(dst, entry.mtimeMs);
        }
        catch (err) {
            this.#failFrame(src, entry.mtimeMs);
            this.#failFrame(dst, entry.mtimeMs);
            throw toError(err);
        }
    }
    async unlink(path) {
        await this.#awaitPath(path);
        const previous = this.#index.get(path);
        if (!previous)
            throw enoent(path);
        this.#index.delete(path);
        this.#pushFrame(path, { mtimeMs: previous.mtimeMs, previous });
        try {
            await this.#enqueuePath(path, () => this.#backend.remove([path]), { trackDrain: false });
            this.#dropFrame(path, previous.mtimeMs);
        }
        catch (err) {
            this.#failFrame(path, previous.mtimeMs);
            throw toError(err);
        }
    }
    async deleteSessionWithArtifacts(sessionPath) {
        await this.#awaitPath(sessionPath);
        const sessionEntry = this.#index.get(sessionPath);
        if (!sessionEntry)
            throw enoent(sessionPath);
        const artifactsDir = sessionPath.slice(0, -6);
        const prefix = artifactsDir.endsWith("/") ? artifactsDir : `${artifactsDir}/`;
        const paths = [sessionPath];
        for (const key of this.#index.keys()) {
            if (key.startsWith(prefix))
                paths.push(key);
        }
        for (const path of paths)
            await this.#awaitPath(path);
        const previous = new Map();
        for (const path of paths) {
            const entry = this.#index.get(path);
            if (entry)
                previous.set(path, entry);
            this.#index.delete(path);
        }
        for (const [path, entry] of previous)
            this.#pushFrame(path, { mtimeMs: sessionEntry.mtimeMs, previous: entry });
        try {
            await this.#enqueuePaths(paths, () => this.#backend.remove(paths), { trackDrain: false });
            for (const [path] of previous)
                this.#dropFrame(path, sessionEntry.mtimeMs);
        }
        catch (err) {
            for (const [path] of previous)
                this.#failFrame(path, sessionEntry.mtimeMs);
            throw toError(err);
        }
    }
    openWriter(path, options) {
        const writer = new IndexedSessionStorageWriter(this, path, options);
        this.#writers.add(writer);
        return writer;
    }
    _writerClosed(writer) {
        this.#writers.delete(writer);
    }
    _truncateForWriter(path) {
        const mtimeMs = this.#allocMtimeMs();
        this.#pushFrame(path, { mtimeMs, previous: this.#index.get(path) });
        this.#setIndex(path, 0, mtimeMs, null);
        return mtimeMs;
    }
    _queueTruncate(path, mtimeMs, getError) {
        const tracked = this.#enqueuePath(path, async () => {
            const error = getError?.();
            if (error)
                throw error;
            await this.#backend.truncate(path, mtimeMs);
        }, { trackDrain: true });
        this.#trackFrame(path, mtimeMs, tracked);
        return tracked;
    }
    _appendForWriter(path, line) {
        const mtimeMs = this.#allocMtimeMs();
        const previous = this.#index.get(path);
        const size = (previous?.size ?? 0) + byteLength(line);
        this.#setIndex(path, size, mtimeMs);
        return { mtimeMs, previous };
    }
    _queueAppend(path, line, append, getError) {
        const { mtimeMs } = append;
        this.#pushFrame(path, append);
        const tracked = this.#enqueuePath(path, async () => {
            const error = getError?.();
            if (error)
                throw error;
            await this.#backend.append(path, line, mtimeMs);
        }, { trackDrain: true, abortOnPredecessorFailure: true });
        this.#trackFrame(path, mtimeMs, tracked);
        return tracked;
    }
    #restoreIndex(path, entry) {
        if (entry) {
            this.#index.set(path, entry);
        }
        else {
            this.#index.delete(path);
        }
    }
    #setIndex(path, size, mtimeMs, title = undefined) {
        const current = title === undefined ? this.#index.get(path) : undefined;
        this.#index.set(path, {
            size,
            mtimeMs,
            title: title === undefined ? current?.title : (title?.title ?? undefined),
            titleSource: title === undefined ? current?.titleSource : (title?.source ?? undefined),
            titleUpdatedAt: title === undefined ? current?.titleUpdatedAt : (title?.updatedAt ?? undefined),
        });
        if (mtimeMs > this.#nextMtimeMs)
            this.#nextMtimeMs = mtimeMs;
    }
    #allocMtimeMs() {
        const now = Date.now();
        const next = now > this.#nextMtimeMs ? now : this.#nextMtimeMs + 1;
        this.#nextMtimeMs = next;
        return next;
    }
    #enqueuePath(path, task, options) {
        return this.#enqueuePaths([path], task, options);
    }
    #pushFrame(path, frame) {
        const frames = this.#pendingFrames.get(path);
        if (frames)
            frames.push(frame);
        else
            this.#pendingFrames.set(path, [frame]);
    }
    #dropFrame(path, mtimeMs) {
        const frames = this.#pendingFrames.get(path);
        if (!frames)
            return;
        const index = frames.findIndex(frame => frame.mtimeMs === mtimeMs);
        if (index >= 0)
            frames.splice(index, 1);
        if (frames.length === 0)
            this.#pendingFrames.delete(path);
    }
    /**
     * Settle a failed optimistic frame. The frame drops; when newer frames
     * are still live their publishes will converge the backend past this
     * failure, so the next frame rebases onto this frame's previous instead
     * of restoring it. When no newer frame lives, restore this frame's
     * previous unless a newer mutation committed meanwhile: a failure that
     * settles outside the queue (the atomic write's gated readback) can
     * land after a newer write committed and dropped its frame, and
     * restoring then would clobber newer durable state (F1). Index mtimes
     * are unique per mutation, so a live entry carrying a different mtime
     * proves a newer commit won; an absent entry (unlink/rename-src
     * bookkeeping) or our own optimistic entry still restores. Rebased
     * chains stay exact: the oldest live frame's previous is always
     * durable state.
     */
    #failFrame(path, mtimeMs) {
        const frames = this.#pendingFrames.get(path);
        if (!frames)
            return;
        const index = frames.findIndex(frame => frame.mtimeMs === mtimeMs);
        if (index < 0)
            return;
        const [failed] = frames.splice(index, 1);
        if (failed === undefined)
            return;
        const next = frames[index];
        if (next === undefined) {
            const current = this.#index.get(path);
            if (current === undefined || current.mtimeMs === mtimeMs)
                this.#restoreIndex(path, failed.previous);
        }
        else
            next.previous = failed.previous;
        if (frames.length === 0)
            this.#pendingFrames.delete(path);
    }
    /**
     * Settle an optimistic frame when its queued backend op settles: success
     * drops the frame (its entry is durable), failure folds it via #failFrame.
     */
    #trackFrame(path, mtimeMs, tracked) {
        void tracked.then(() => this.#dropFrame(path, mtimeMs), () => this.#failFrame(path, mtimeMs));
    }
    #enqueuePaths(paths, task, options) {
        const unique = uniquePaths(paths);
        // Predecessor choice (rJDg): a positional publish with no backend CAS
        // token (backend.append) chains on the uncaught pending op so it
        // fail-fasts behind a failed op instead of landing on a body the
        // backend never accepted. Absolute publishes carry their own backend
        // validation and chain on the caught tail, so a superseding publish
        // still runs to converge (e.g. a newer title update over a failed one).
        const previous = unique.map(path => (options.abortOnPredecessorFailure ? this.#pathPending.get(path) : this.#pathTails.get(path)) ?? RESOLVED);
        const operation = Promise.all(previous).then(task);
        const tracked = operation.catch(err => {
            const error = toError(err);
            if (options.trackDrain && !this.#firstDrainError)
                this.#firstDrainError = error;
            throw error;
        });
        const tail = tracked.catch(() => { });
        for (const path of unique) {
            this.#pathTails.set(path, tail);
            this.#pathPending.set(path, tracked);
        }
        tail.finally(() => {
            for (const path of unique) {
                if (this.#pathTails.get(path) === tail)
                    this.#pathTails.delete(path);
            }
        });
        tracked
            .finally(() => {
            for (const path of unique) {
                if (this.#pathPending.get(path) === tracked)
                    this.#pathPending.delete(path);
            }
        })
            .catch(() => { });
        tracked.catch(() => { });
        if (options.trackDrain) {
            this.#drainPending.add(tracked);
            tracked
                .finally(() => {
                this.#drainPending.delete(tracked);
            })
                .catch(() => { });
        }
        return tracked;
    }
    #awaitPath(path) {
        return this.#pathPending.get(path) ?? RESOLVED;
    }
}
class IndexedSessionStorageWriter {
    #storage;
    #path;
    #closed = false;
    #error;
    #onError;
    #pendingChain = Promise.resolve();
    constructor(storage, path, options) {
        this.#storage = storage;
        this.#path = path;
        this.#onError = options?.onError;
        if ((options?.flags ?? "a") === "w") {
            const mtimeMs = storage._truncateForWriter(path);
            this.#trackPromise(storage._queueTruncate(path, mtimeMs, () => this.#error));
        }
    }
    #recordError(err) {
        const error = toError(err);
        if (!this.#error)
            this.#error = error;
        this.#onError?.(error);
        return error;
    }
    #trackPromise(promise) {
        const next = this.#pendingChain.then(async () => {
            if (this.#error)
                throw this.#error;
            try {
                await promise;
            }
            catch (err) {
                throw this.#recordError(err);
            }
        });
        this.#pendingChain = next.catch(() => { });
        return next;
    }
    appendSync(line) {
        if (this.#closed)
            throw new Error("Writer closed");
        if (this.#error)
            throw this.#error;
        // Local index is updated immediately; remote publish stays ordered on the
        // path queue. Callers that need remote durability still await append()/flush().
        const append = this.#storage._appendForWriter(this.#path, line);
        void this.#trackPromise(this.#storage._queueAppend(this.#path, line, append, () => this.#error));
    }
    async append(line) {
        if (this.#closed)
            throw new Error("Writer closed");
        if (this.#error)
            throw this.#error;
        const append = this.#storage._appendForWriter(this.#path, line);
        await this.#trackPromise(this.#storage._queueAppend(this.#path, line, append, () => this.#error));
    }
    async flush() {
        if (this.#error)
            throw this.#error;
        await this.#pendingChain;
        if (this.#error)
            throw this.#error;
    }
    isOpen() {
        return !this.#closed;
    }
    async close() {
        if (this.#closed)
            return;
        this.#closed = true;
        try {
            await this.flush();
        }
        finally {
            this.#storage._writerClosed(this);
        }
    }
    getError() {
        return this.#error;
    }
}
