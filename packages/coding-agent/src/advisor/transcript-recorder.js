import * as fs from "node:fs/promises";
import * as path from "node:path";
import { logger } from "@rva/utils";
import { visitEntriesFromFileStream } from "../session/session-loader";
import { SessionManager } from "../session/session-manager";
import { fingerprintMessage } from "./message-fingerprint";
/**
 * Reserved transcript stem for advisor session files. Chosen so it cannot
 * collide with a task subagent's `<id>.jsonl` (task ids are reserved against
 * this exact stem in {@link AgentOutputManager}).
 */
export const ADVISOR_TRANSCRIPT_STEM = "__advisor";
export const ADVISOR_TRANSCRIPT_FILENAME = `${ADVISOR_TRANSCRIPT_STEM}.jsonl`;
const JSONL_SUFFIX = ".jsonl";
/**
 * Transcript filename for an advisor: `__advisor.jsonl` for the legacy/default
 * advisor (empty slug), `__advisor.<slug>.jsonl` for a named advisor. The `.`
 * separator keeps named files out of the output manager's `-<n>` bump namespace.
 */
export function advisorTranscriptFilename(slug) {
    return slug ? `${ADVISOR_TRANSCRIPT_STEM}.${slug}${JSONL_SUFFIX}` : ADVISOR_TRANSCRIPT_FILENAME;
}
/** Whether a filename is any advisor transcript (`__advisor.jsonl` or `__advisor.<slug>.jsonl`). */
export function isAdvisorTranscriptName(name) {
    return (name === ADVISOR_TRANSCRIPT_FILENAME ||
        (name.startsWith(`${ADVISOR_TRANSCRIPT_STEM}.`) && name.endsWith(JSONL_SUFFIX)));
}
/**
 * Sum advisor spend already persisted next to a primary session transcript,
 * keyed by advisor slug.
 *
 * Each transcript is read only through the byte length captured before
 * `onSnapshot` runs. This fixed prefix lets resume reconcile the persisted
 * total with advisor turns billed while the asynchronous scan is running,
 * without either dropping or double-counting those concurrent turns.
 *
 * Only the session's own advisors count: subagent advisors write to
 * `<session>/<SubId>/__advisor.jsonl`, and their spend belongs to the subagent,
 * not to this roster. Hence the scan stays at the top level of the directory.
 */
export async function loadAdvisorTranscriptCosts(sessionFile, options = {}) {
    await options.beforeSnapshot;
    const snapshots = [];
    if (sessionFile?.endsWith(JSONL_SUFFIX)) {
        const directory = sessionFile.slice(0, -JSONL_SUFFIX.length);
        const dirents = await fs.readdir(directory, { withFileTypes: true }).catch(() => []);
        for (const dirent of dirents) {
            if (options.shouldContinue?.() === false)
                break;
            if (!dirent.isFile() || !isAdvisorTranscriptName(dirent.name))
                continue;
            const file = path.join(directory, dirent.name);
            try {
                snapshots.push({
                    file,
                    slug: dirent.name === ADVISOR_TRANSCRIPT_FILENAME
                        ? ""
                        : dirent.name.slice(`${ADVISOR_TRANSCRIPT_STEM}.`.length, -JSONL_SUFFIX.length),
                    maxBytes: (await fs.stat(file)).size,
                });
            }
            catch { }
        }
    }
    options.onSnapshot?.();
    const costs = new Map();
    for (const snapshot of snapshots) {
        let total = 0;
        const providers = new Set();
        let validHeader;
        try {
            await visitEntriesFromFileStream(snapshot.file, entry => {
                const isObject = typeof entry === "object" && entry !== null;
                if (validHeader === undefined) {
                    validHeader = isObject && entry.type === "session" && typeof entry.id === "string";
                    return;
                }
                // A syntactically valid but non-object entry (e.g. a bare
                // `null` line) must cost only itself, not crash entry.type
                // access and discard everything accumulated for this transcript.
                if (!validHeader || !isObject || entry.type !== "message")
                    return;
                const message = entry.message;
                if (!message || typeof message !== "object" || message.role !== "assistant")
                    return;
                // One malformed usage block must cost that entry only, not the
                // whole transcript's total.
                const total_ = message.usage?.cost?.total;
                if (typeof total_ === "number" && Number.isFinite(total_)) {
                    total += total_;
                    if (total_ > 0 && typeof message.provider === "string" && message.provider) {
                        providers.add(message.provider);
                    }
                }
            }, { maxBytes: snapshot.maxBytes, shouldContinue: options.shouldContinue });
        }
        catch (err) {
            logger.debug("advisor transcript cost read failed", { file: path.basename(snapshot.file), err: String(err) });
            continue;
        }
        if (total > 0) {
            costs.set(snapshot.slug, total);
            if (options.providersBySlug && providers.size > 0)
                options.providersBySlug.set(snapshot.slug, providers);
        }
    }
    return costs;
}
/**
 * Append-only persister for an advisor agent's transcript.
 *
 * The advisor is a passive reviewer with its own model usage, so — like a task
 * subagent — its turns are written to a JSONL inside the owning session's
 * artifacts dir (`<session>/__advisor.jsonl`, `<session>/<SubId>/__advisor.jsonl`
 * for subagent advisors). That single file gives the advisor model proper usage
 * attribution in `omp stats` (the stats parser scans the session dir
 * recursively) and a read-only transcript in the Agent Hub, without making the
 * advisor a registered, messageable peer.
 *
 * The target is derived from the *session file* (`getSessionFile()`), never
 * `getArtifactsDir()` — subagents adopt the parent's artifact manager, so the
 * artifacts dir points at the parent root and every subagent advisor would
 * collide. The file path is resolved synchronously when a message finalizes and
 * captured for the queued write, so a `/new`, resume, or session switch in
 * flight can never misattribute an old advisor turn into the new session's file.
 * On such a switch the previous writer is closed and the new file opened on the
 * next recorded turn. The recorder never truncates: the advisor's in-memory
 * context resets/compacts independently, but every billed turn is appended here.
 */
export class AdvisorTranscriptRecorder {
    resolveSessionFile;
    resolveCwd;
    #manager;
    #file;
    #filename;
    /** Serializes the async open/close against synchronous appends so records land in order. */
    #queue;
    /**
     * Ordered fingerprints of user "session update" deltas persisted since the
     * last committed advisor turn. The advisor re-delivers the identical batch on
     * every retry/overflow/refusal loop (issue #9553), and {@link #rollbackFailedTurn}
     * only cleans the agent's in-memory state — the recorder already wrote the
     * attempt. Matching a re-delivery positionally against this window skips the
     * duplicate while still persisting genuinely new content, including two
     * distinct deltas that happen to render identically (a repeated prompt, or two
     * tool runs with the same output).
     */
    #replayWindow = [];
    /** Cursor into {@link #replayWindow}; reset at each delivery attempt via {@link beginTurn}. */
    #replayCursor = 0;
    /** Target file {@link #replayWindow} belongs to; a switch starts a fresh window. */
    #windowFile;
    /**
     * @param filename Transcript filename within the session dir. Defaults to
     *   `__advisor.jsonl`; named advisors pass `__advisor.<slug>.jsonl` via
     *   {@link advisorTranscriptFilename}.
     * @param after Optional barrier the queue starts behind — used on the advisor
     *   on→off→on toggle so a fresh recorder's first `open` waits for the prior
     *   recorder's `close` and the two never hold the same file at once.
     */
    constructor(resolveSessionFile, resolveCwd, filename = ADVISOR_TRANSCRIPT_FILENAME, after) {
        this.resolveSessionFile = resolveSessionFile;
        this.resolveCwd = resolveCwd;
        this.#filename = filename;
        this.#queue = after
            ? after.then(() => { }, () => { })
            : Promise.resolve();
    }
    /**
     * Persist one finalized advisor message. Assistant turns carry the usage the
     * stats parser reads; tool results round out the Hub transcript; user deltas
     * (the advisor's "session update" prompts) are persisted but flagged
     * `synthetic`/agent-attributed so they never inflate user-message metrics.
     * Non-conversational message kinds are skipped.
     */
    record(message) {
        let persisted;
        switch (message.role) {
            case "assistant":
            case "toolResult":
                persisted = message;
                break;
            case "user":
                // Clone so the live advisor message stays untouched; mark synthetic so
                // stats' user-message metrics skip these agent-internal review prompts.
                persisted = { ...message, synthetic: true, attribution: "agent" };
                break;
            default:
                return;
        }
        const sessionFile = this.resolveSessionFile();
        if (!sessionFile?.endsWith(JSONL_SUFFIX))
            return;
        const file = path.join(sessionFile.slice(0, -JSONL_SUFFIX.length), this.#filename);
        // A new target file starts a fresh replay window: positions from the prior
        // session's turns must never suppress the new file's first delta.
        if (file !== this.#windowFile) {
            this.#windowFile = file;
            this.#replayWindow = [];
            this.#replayCursor = 0;
        }
        // Skip a re-delivered user delta: on retry/overflow/refusal the advisor
        // re-sends the identical batch in the same order, so a positional match
        // against this turn's window is a replay that adds only bytes. New content
        // — including a delta that renders like an earlier one — diverges from the
        // window and is persisted. Assistant/tool turns are billed work: always
        // written, so cost attribution and the Hub transcript stay intact.
        if (message.role === "user") {
            const fingerprint = fingerprintMessage(message);
            if (fingerprint !== undefined) {
                if (this.#replayCursor < this.#replayWindow.length) {
                    if (this.#replayWindow[this.#replayCursor] === fingerprint) {
                        this.#replayCursor++;
                        return;
                    }
                    // Divergent retry (e.g. reasoning stripped after a refusal): the
                    // window no longer matches, so drop its stale tail and record anew.
                    this.#replayWindow.length = this.#replayCursor;
                }
                this.#replayWindow.push(fingerprint);
                this.#replayCursor = this.#replayWindow.length;
            }
        }
        const cwd = this.resolveCwd();
        this.#enqueue(async () => {
            if (file !== this.#file) {
                await this.#closeManager();
                this.#manager = await SessionManager.open(file, undefined, undefined, {
                    initialCwd: cwd,
                    suppressBreadcrumb: true,
                });
                this.#file = file;
            }
            this.#manager?.appendMessage(persisted);
        });
    }
    /**
     * Mark the start of one advisor delivery attempt. Rewinds the replay cursor so
     * a retry that re-sends the same batch matches this turn's window positionally
     * and is skipped, while the window itself (persisted-since-commit) is retained.
     */
    beginTurn() {
        this.#replayCursor = 0;
    }
    /**
     * Mark an advisor turn as committed (its output landed). Clears the replay
     * window so the next turn's deltas are recorded even when they render like a
     * committed one — only re-deliveries of an *uncommitted* turn are replays.
     */
    commitTurn() {
        this.#clearReplayWindow();
    }
    /** Discard replay identity for a failed batch that will not be retried. */
    abandonTurn() {
        this.#clearReplayWindow();
    }
    /**
     * Queue a write barrier after all records accepted so far. Once `ready`
     * resolves, callers may safely snapshot the file length; records accepted
     * after this call remain queued until `release` settles.
     */
    blockWritesUntil(release) {
        const ready = Promise.withResolvers();
        this.#enqueue(async () => {
            ready.resolve();
            await release;
        });
        return ready.promise;
    }
    #clearReplayWindow() {
        this.#replayWindow = [];
        this.#replayCursor = 0;
    }
    /** Flush pending writes (best-effort). */
    flush() {
        return this.#enqueueResult(async () => {
            if (this.#manager)
                await this.#manager.flush();
        });
    }
    /** Flush and close the writer, releasing the session file. */
    close() {
        return this.#enqueueResult(() => this.#closeManager());
    }
    async #closeManager() {
        const manager = this.#manager;
        this.#manager = undefined;
        this.#file = undefined;
        if (!manager)
            return;
        try {
            await manager.close();
        }
        catch (err) {
            logger.debug("advisor transcript close failed", { err: String(err) });
        }
    }
    #enqueue(work) {
        this.#queue = this.#queue.then(work, work).catch(err => {
            logger.debug("advisor transcript record failed", { err: String(err) });
        });
    }
    #enqueueResult(work) {
        const next = this.#queue.then(work, work);
        this.#queue = next.catch(() => { });
        return next;
    }
}
