import * as fs from "node:fs/promises";
import * as path from "node:path";
import { type } from "@rva/omptype";
import { getBtwLatestTurn } from "@rva/tui/overlays/btw-history";
import { acquireFileLock, isEnoent, toError } from "@rva/utils";
import { replaceFileAtomically } from "../utils/atomic-file";
export { getBtwCopyText, getBtwLatestTurn, getBtwTurns, } from "@rva/tui/overlays/btw-history";
const turnFields = {
    question: "string",
    answer: "string",
    status: "'running' | 'complete' | 'cancelled' | 'error' | 'interrupted'",
    createdAt: "0 <= number <= 8640000000000000",
    updatedAt: "0 <= number <= 8640000000000000",
    "error?": "string",
};
const turnSchema = type({ ...turnFields, "+": "reject" });
const recordSchema = type({
    ...turnFields,
    id: "string > 0",
    leafId: "string | null",
    "followUps?": turnSchema.array(),
    "+": "reject",
});
function parseRecord(value) {
    const result = recordSchema(value);
    if (result instanceof type.errors) {
        throw new Error(`Invalid BTW history record: ${result.summary}`);
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(result.id)) {
        throw new Error("Invalid BTW history record id");
    }
    return result;
}
function snapshotRecord(record, recover = false) {
    const snapshotTurn = (turn) => Object.freeze({ ...turn, status: recover && turn.status === "running" ? "interrupted" : turn.status });
    return Object.freeze({
        ...record,
        status: recover && record.status === "running" ? "interrupted" : record.status,
        ...(record.followUps ? { followUps: Object.freeze(record.followUps.map(snapshotTurn)) } : {}),
    });
}
function recordFileName(id) {
    // The prefix also prevents Windows device names (CON, NUL, etc.).
    return `entry-${id}.json`;
}
async function readRecord(filePath) {
    try {
        const stat = await fs.lstat(filePath);
        if (!stat.isFile())
            throw new Error("Expected a regular file");
        const bytes = await fs.readFile(filePath);
        const record = parseRecord(JSON.parse(bytes.toString("utf8")));
        if (path.basename(filePath) !== recordFileName(record.id)) {
            throw new Error("Record id does not match its filename");
        }
        return { record, revision: new Bun.CryptoHasher("sha256").update(bytes).digest("hex") };
    }
    catch (error) {
        if (isEnoent(error))
            return undefined;
        throw new Error(`Failed to read BTW history ${filePath}: ${toError(error).message}`, { cause: error });
    }
}
function historyDirectory(artifactsDir, scope) {
    const root = path.join(artifactsDir, "btw-history");
    if (scope === undefined)
        return root;
    // Session ids come from session headers; never let one escape the history root.
    const segment = /^[\w-]+$/.test(scope) ? scope : new Bun.CryptoHasher("sha256").update(scope).digest("hex");
    return path.join(root, "sessions", segment);
}
/** The topic on disk is missing or was rewritten since this store read it; retrying the same write can never succeed. */
export class BtwHistoryConflictError extends Error {
    recordId;
    constructor(recordId) {
        super(`BTW history conflict for ${recordId}; reopen history before retrying`);
        this.recordId = recordId;
        this.name = "BtwHistoryConflictError";
    }
}
/** Session-local sidecar storage; never reads or writes the main session journal. */
export class BtwHistoryStore {
    #directory;
    #records = new Map();
    #revisions = new Map();
    #leases = new Map();
    #snapshot = Object.freeze([]);
    #pending = Promise.resolve();
    #writeError;
    constructor(directory) {
        this.#directory = directory;
    }
    /**
     * Open the BTW history for an artifacts directory. Subagents share their
     * parent's artifacts directory, so a `scope` (the owning session id) keeps
     * each focused agent's side conversations apart from main and its siblings.
     */
    static async open(artifactsDir, scope) {
        const store = new BtwHistoryStore(artifactsDir === undefined ? undefined : historyDirectory(artifactsDir, scope));
        if (store.#directory === undefined)
            return store;
        let names;
        try {
            names = await fs.readdir(store.#directory);
        }
        catch (error) {
            if (isEnoent(error))
                return store;
            throw error;
        }
        for (const name of names.sort()) {
            if (!name.endsWith(".json"))
                continue;
            const stored = await readRecord(path.join(store.#directory, name));
            if (!stored)
                continue;
            // Recovery is only a view. CAS must compare the original disk bytes,
            // and the live writer's lease prevents a recovered view stealing a turn.
            store.#records.set(stored.record.id, snapshotRecord(stored.record, true));
            store.#revisions.set(stored.record.id, stored.revision);
        }
        store.#refreshSnapshot();
        return store;
    }
    getRecords() {
        return this.#snapshot;
    }
    upsert(record) {
        return this.#upsert(record, false);
    }
    /** Retry a failed checkpoint against the original revision, without rebasing onto disk changes. */
    retry(record) {
        return this.#upsert(record, true);
    }
    async #upsert(record, retry) {
        if (this.#writeError && !retry)
            throw this.#writeError;
        // Capture before yielding: callers may keep mutating their streaming record.
        const snapshot = snapshotRecord(parseRecord(record));
        if (this.#directory === undefined) {
            this.#records.set(snapshot.id, snapshot);
            this.#refreshSnapshot();
            return;
        }
        const directory = this.#directory;
        const content = `${JSON.stringify(snapshot)}\n`;
        const write = this.#pending.then(async () => {
            // Reset only at this queue boundary: earlier attempts and their error
            // handlers must settle before an explicit retry can recover the store.
            if (retry)
                this.#writeError = undefined;
            if (this.#writeError)
                throw this.#writeError;
            await fs.mkdir(directory, { recursive: true, mode: 0o700 });
            if (process.platform !== "win32")
                await fs.chmod(directory, 0o700);
            const filePath = path.join(directory, recordFileName(snapshot.id));
            let lease = this.#leases.get(snapshot.id);
            if (!lease) {
                lease = await acquireFileLock(filePath);
                this.#leases.set(snapshot.id, lease);
            }
            // Compare while holding the topic lease, including on owner checkpoints.
            // Missing records and new-id collisions are conflicts, not blind inserts.
            const stored = await readRecord(filePath);
            if (stored?.revision !== this.#revisions.get(snapshot.id)) {
                throw new BtwHistoryConflictError(snapshot.id);
            }
            const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
            try {
                await fs.writeFile(temporaryPath, content, { encoding: "utf8", mode: 0o600, flag: "wx" });
                await replaceFileAtomically(temporaryPath, filePath);
            }
            finally {
                await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
            }
            this.#revisions.set(snapshot.id, new Bun.CryptoHasher("sha256").update(content).digest("hex"));
            this.#records.set(snapshot.id, snapshot);
            this.#refreshSnapshot();
            if (getBtwLatestTurn(snapshot).status !== "running") {
                lease.release();
                this.#leases.delete(snapshot.id);
            }
        });
        // Keep the queue handled while retaining the original failure for callers
        // and every later flush/upsert until an explicit retry. A successful drain must not hide data loss.
        this.#pending = write.catch(error => {
            this.#writeError ??= toError(error);
            // A sticky failure prevents all later terminal writes, so release every
            // topic this store owns rather than stranding another running lease.
            for (const lease of this.#leases.values())
                lease.release();
            this.#leases.clear();
        });
        await write;
    }
    async flush() {
        let pending;
        do {
            pending = this.#pending;
            await pending;
        } while (pending !== this.#pending);
        if (this.#writeError)
            throw this.#writeError;
    }
    #refreshSnapshot() {
        this.#snapshot = Object.freeze([...this.#records.values()].sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)));
    }
}
