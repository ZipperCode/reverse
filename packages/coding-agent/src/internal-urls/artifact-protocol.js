/**
 * Protocol handler for artifact:// URLs.
 *
 * Resolves artifact IDs against the artifacts directories of every active
 * session. Unlike agent://, artifacts are raw text with no JSON extraction.
 *
 * URL form:
 * - artifact://<id> - Full artifact content
 *
 * Pagination is handled by the read tool via offset/limit parameters.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isEnoent } from "@rva/utils";
import { LRUCache } from "@rva/utils/lru";
import artifactDoc from "../prompts/internal-urls/artifact.md" with { type: "text" };
import { artifactsDirsFromRegistry } from "./registry-helpers";
const MAX_INLINE_ARTIFACT_BYTES = 8 * 1024 * 1024;
/**
 * Sorted artifact ids for `complete()`, keyed by the scanned dir set.
 * Completion runs per keystroke; a short reuse window avoids re-reading every
 * artifacts dir on each key.
 */
const completionIds = new LRUCache({ max: 8, ttl: 2000 });
async function scanArtifactIds(dirs) {
    const listings = await Promise.all(dirs.map(async (dir) => {
        try {
            return await fs.readdir(dir);
        }
        catch (err) {
            if (isEnoent(err))
                return [];
            throw err;
        }
    }));
    const ids = new Set();
    for (const files of listings) {
        for (const f of files) {
            const m = f.match(/^(\d+)\./);
            if (m)
                ids.add(m[1]);
        }
    }
    return [...ids].sort((a, b) => Number(a) - Number(b));
}
function artifactIdsForCompletion() {
    const dirs = artifactsDirsFromRegistry();
    const key = dirs.join("\0");
    const cached = completionIds.get(key);
    if (cached)
        return cached;
    const ids = scanArtifactIds(dirs);
    completionIds.set(key, ids);
    ids.catch(() => completionIds.delete(key));
    return ids;
}
function parseArtifactId(url) {
    const id = url.rawHost || url.hostname;
    if (!id) {
        throw new Error("artifact:// URL requires a numeric ID: artifact://0");
    }
    if (!/^\d+$/.test(id)) {
        throw new Error(`artifact:// ID must be numeric, got: ${id}`);
    }
    return id;
}
/** An artifact id no session artifacts dir backs; `locate` maps it to null, `resolve` surfaces it. */
class MissingArtifactError extends Error {
}
/** Resolve an `artifact://` URL to its backing file without reading artifact bytes. */
async function resolveArtifactFile(url, context) {
    const id = parseArtifactId(url);
    // Artifact ids are per-session counters; in multi-session hosts the same
    // id exists in several dirs. Pin resolution to the calling session's
    // artifacts dir first so `artifact://3` means *this* session's #3.
    const dirs = artifactsDirsFromRegistry();
    const pinnedDir = context?.localProtocolOptions?.getArtifactsDir?.() ?? null;
    if (pinnedDir) {
        const pinnedIndex = dirs.indexOf(pinnedDir);
        if (pinnedIndex >= 0)
            dirs.splice(pinnedIndex, 1);
        dirs.unshift(pinnedDir);
    }
    if (dirs.length === 0) {
        throw new MissingArtifactError("No session - artifacts unavailable");
    }
    let foundPath;
    let anyDirExists = false;
    const availableIds = new Set();
    for (const dir of dirs) {
        let files;
        try {
            files = await fs.readdir(dir);
            anyDirExists = true;
        }
        catch (err) {
            if (isEnoent(err))
                continue;
            throw err;
        }
        const match = files.find(f => f.startsWith(`${id}.`));
        if (match) {
            foundPath = path.join(dir, match);
            break;
        }
        for (const f of files) {
            const m = f.match(/^(\d+)\./);
            if (m)
                availableIds.add(m[1]);
        }
    }
    if (!anyDirExists) {
        throw new MissingArtifactError("No artifacts directory found");
    }
    if (!foundPath) {
        const sorted = [...availableIds].sort((a, b) => Number(a) - Number(b));
        const availableStr = sorted.length > 0 ? sorted.join(", ") : "none";
        throw new MissingArtifactError(`Artifact ${id} not found. Available: ${availableStr}`);
    }
    const stat = await Bun.file(foundPath).stat();
    if (stat.isDirectory()) {
        throw new Error(`Artifact ${id} resolved to a directory, not a file`);
    }
    return { id, path: foundPath, size: stat.size };
}
export class ArtifactProtocolHandler {
    scheme = "artifact";
    spec = {
        backing: "file",
        selectors: "lines",
        immutable: true,
        artifactStore: true,
        linkable: true,
    };
    promptDoc() {
        return artifactDoc.trim();
    }
    /** Backing artifact file; null for unknown ids, throws the resolve errors for malformed ones. */
    async locate(url, context) {
        try {
            return (await resolveArtifactFile(url, context)).path;
        }
        catch (error) {
            if (error instanceof MissingArtifactError)
                return null;
            throw error;
        }
    }
    async resolve(url, context) {
        const artifact = await resolveArtifactFile(url, context);
        // Path consumers (search, the shell filesystem) use `locate`, which never
        // reads the bytes; only content materialization is size-gated.
        if (artifact.size > MAX_INLINE_ARTIFACT_BYTES) {
            throw new Error(`Artifact ${artifact.id} is ${artifact.size} bytes; full internal resolution is blocked. Use read selectors such as artifact://${artifact.id}:1-3000 or artifact://${artifact.id}:raw:1-3000, and use the artifact file path for search/copy workflows: ${artifact.path}`);
        }
        const content = await Bun.file(artifact.path).text();
        return {
            url: url.href,
            content,
            contentType: "text/plain",
            size: artifact.size,
            sourcePath: artifact.path,
        };
    }
    async complete() {
        return (await artifactIdsForCompletion()).map(value => ({ value }));
    }
}
