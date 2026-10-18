import * as fs from "node:fs/promises";
import * as path from "node:path";
import { getBlobsDir, isEnoent, logger } from "@rva/utils";
function projectHash(projectDir) {
    return Bun.hash.wyhash(path.resolve(projectDir)).toString(16);
}
/** Deterministic per-project append-only journal path. */
export function blobBrokerSavingsJournalPath(settings, projectDir) {
    return path.join(getBlobsDir(settings.getAgentDir()), `image-savings-${projectHash(projectDir)}.jsonl`);
}
function emptyCounters() {
    return { entries: 0, imageCount: 0, inlineBytes: 0, referenceBytes: 0, savedBytes: 0 };
}
function addRecord(counters, record) {
    return {
        entries: counters.entries + 1,
        imageCount: counters.imageCount + record.imageCount,
        inlineBytes: counters.inlineBytes + record.inlineBytes,
        referenceBytes: counters.referenceBytes + record.referenceBytes,
        savedBytes: counters.savedBytes + record.savedBytes,
    };
}
function isFiniteNonNegativeInteger(value) {
    return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function parseRecord(line) {
    let value;
    try {
        value = JSON.parse(line);
    }
    catch {
        return undefined;
    }
    if (!value || typeof value !== "object")
        return undefined;
    const candidate = value;
    if (!isFiniteNonNegativeInteger(candidate.timestamp) ||
        typeof candidate.provider !== "string" ||
        typeof candidate.model !== "string" ||
        typeof candidate.destination !== "string" ||
        candidate.destination.length === 0 ||
        !isFiniteNonNegativeInteger(candidate.imageCount) ||
        candidate.imageCount === 0 ||
        !isFiniteNonNegativeInteger(candidate.inlineBytes) ||
        !isFiniteNonNegativeInteger(candidate.referenceBytes) ||
        typeof candidate.savedBytes !== "number" ||
        !Number.isSafeInteger(candidate.savedBytes)) {
        return undefined;
    }
    return candidate;
}
/** Aggregate the durable journal in one linear scan; malformed lines are ignored. */
export async function readBlobBrokerSavingsStatus(journalPath) {
    let text;
    try {
        text = await fs.readFile(journalPath, "utf8");
    }
    catch (error) {
        if (isEnoent(error))
            return { journalPath, ...emptyCounters(), byDestination: {} };
        throw error;
    }
    let total = emptyCounters();
    const byDestination = {};
    for (const line of text.split("\n")) {
        if (!line.trim())
            continue;
        const record = parseRecord(line);
        if (!record)
            continue;
        total = addRecord(total, record);
        byDestination[record.destination] = addRecord(byDestination[record.destination] ?? emptyCounters(), record);
    }
    return { journalPath, ...total, byDestination };
}
/** Append-only recorder. Failures are diagnostic-only and never break a provider request. */
export class BlobBrokerSavingsJournal {
    path;
    #dirEnsured = false;
    constructor(journalPath) {
        this.path = journalPath;
    }
    async append(records) {
        if (records.length === 0)
            return;
        try {
            if (!this.#dirEnsured) {
                await fs.mkdir(path.dirname(this.path), { recursive: true });
                this.#dirEnsured = true;
            }
            await fs.appendFile(this.path, `${records.map(record => JSON.stringify(record)).join("\n")}\n`, "utf8");
        }
        catch (error) {
            logger.debug("blob-broker: savings journal append failed", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    status() {
        return readBlobBrokerSavingsStatus(this.path);
    }
}
