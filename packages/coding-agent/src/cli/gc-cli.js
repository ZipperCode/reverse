var __addDisposableResource = (this && this.__addDisposableResource) || function (env, value, async) {
    if (value !== null && value !== void 0) {
        if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
        var dispose, inner;
        if (async) {
            if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
            dispose = value[Symbol.asyncDispose];
        }
        if (dispose === void 0) {
            if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
            dispose = value[Symbol.dispose];
            if (async) inner = dispose;
        }
        if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
        if (inner) dispose = function() { try { inner.call(this); } catch (e) { return Promise.reject(e); } };
        env.stack.push({ value: value, dispose: dispose, async: async });
    }
    else if (async) {
        env.stack.push({ async: true });
    }
    return value;
};
var __disposeResources = (this && this.__disposeResources) || (function (SuppressedError) {
    return function (env) {
        function fail(e) {
            env.error = env.hasError ? new SuppressedError(e, env.error, "An error was suppressed during disposal.") : e;
            env.hasError = true;
        }
        var r, s = 0;
        function next() {
            while (r = env.stack.pop()) {
                try {
                    if (!r.async && s === 1) return s = 0, env.stack.push(r), Promise.resolve().then(next);
                    if (r.dispose) {
                        var result = r.dispose.call(r.value);
                        if (r.async) return s |= 2, Promise.resolve(result).then(next, function(e) { fail(e); return next(); });
                    }
                    else s |= 1;
                }
                catch (e) {
                    fail(e);
                }
            }
            if (s === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
            if (env.hasError) throw env.error;
        }
        return next();
    };
})(typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
});
import { Database } from "bun:sqlite";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip, createGzip } from "node:zlib";
import { withStatsSyncLock } from "@rva/stats/aggregator";
import { isCompressScratchPath } from "@rva/stats/parser";
import { formatBytes, getAgentDir, getBlobsDir, getConfigRootDir, getCustomSessionFilesDir, getHistoryDbPath, getModelDbPath, getReportsDir, getSessionsDir, getStatsDbPath, getTerminalSessionsDir, hashPath, normalizePathForComparison, readLines, } from "@rva/utils";
import { Settings } from "../config/settings";
import { BLOB_HASH_RE, BLOB_STAGING_RE, blobStagingPath } from "../session/blob-store";
import { listSessionsReadOnly } from "../session/session-listing";
import { parseTerminalBreadcrumb } from "../session/session-paths";
import { readSessionHeaderId } from "../session/session-loader";
import { FileSessionStorage, SESSION_STAGING_RE, tryAcquireSessionLease } from "../session/session-storage";
import { compressCandidate, compressFilesInPlace, compressMethod, sweepCompressScratch, } from "./gc-compress";
import { cfgGcArchive, cfgGcBlobs, cfgGcColdArchiveAfterDays, cfgGcCompress, cfgGcCompressAfterDays, cfgGcRetainNewestGlobal, cfgGcRetainNewestPerCwd, cfgGcStale, cfgGcStaleRetainDays, cfgGcStaleRetainNewest, cfgGcWal, } from "./gc-settings";
const BLOB_FILE_RE = /^([a-f0-9]{64})(?:\.[A-Za-z0-9][A-Za-z0-9._-]{0,31})?$/;
const BLOB_REF_RE = /\bblob:sha256:([a-f0-9]{64})\b/gi;
const JSONL_GLOB = new Bun.Glob("**/*.jsonl");
const JSONL_GZ_GLOB = new Bun.Glob("**/*.jsonl.gz");
const JSONL_BACKUP_GLOB = new Bun.Glob("**/*.jsonl.*.bak");
const SESSION_STAGING_GLOB = new Bun.Glob("**/.*.jsonl.*.tmp");
const ANY_FILE_GLOB = new Bun.Glob("**/*");
const ACTIVE_STATUSES = new Set(["pending", "interrupted", "unknown"]);
const DAY_MS = 86400000;
const GC_WRITE_GRACE_MS = 5 * 60000;
const SESSION_SUFFIX = ".jsonl";
const COMPRESSED_SESSION_SUFFIX = ".jsonl.gz";
const GC_LOCK_BREAKER_SUFFIX = ".break";
/** Bytes sampled to rule out a session header before streaming an artifact. */
const HEADER_SNIFF_BYTES = 4096;
/**
 * Minimum age before a dangling session pointer is pruned. A lazy session's
 * marker and fresh breadcrumb name a transcript that is not on disk until its
 * first turn, so an idle-but-open session must keep them well past the
 * write grace.
 */
const STALE_POINTER_GRACE_MS = DAY_MS;
function normalizeNumberSetting(value, defaultValue) {
    if (typeof value !== "number" || !Number.isFinite(value))
        return defaultValue;
    return Math.max(0, Math.floor(value));
}
function numberSetting(value, fallback, defaultValue) {
    if (value !== undefined && Number.isFinite(value))
        return Math.max(0, Math.floor(value));
    return normalizeNumberSetting(fallback, defaultValue);
}
async function resolveOptions(flags) {
    const agentDir = path.resolve(flags.agentDir ?? getAgentDir());
    const selected = flags.blobs === true ||
        flags.archive === true ||
        flags.wal === true ||
        flags.stale === true ||
        flags.compress === true;
    const archiveSelected = selected && flags.archive === true;
    const staleSelected = selected && flags.stale === true;
    const compressSelected = selected && flags.compress === true;
    const needsArchiveSettings = archiveSelected &&
        (flags.coldArchiveAfterDays === undefined ||
            flags.retainNewestGlobal === undefined ||
            flags.retainNewestPerCwd === undefined);
    const needsStaleSettings = staleSelected && (flags.staleRetainNewest === undefined || flags.staleRetainDays === undefined);
    const needsCompressSettings = compressSelected && flags.compressAfterDays === undefined;
    const settings = !selected || needsArchiveSettings || needsStaleSettings || needsCompressSettings
        ? flags.apply === true
            ? await Settings.loadIsolated({ agentDir })
            : await Settings.loadReadOnly({ agentDir })
        : undefined;
    const read = (setting) => (settings ? setting.get(settings) : setting.default);
    return {
        apply: flags.apply === true,
        json: flags.json === true,
        agentDir,
        runBlobs: selected ? flags.blobs === true : read(cfgGcBlobs),
        runArchive: selected ? flags.archive === true : read(cfgGcArchive),
        runWal: selected ? flags.wal === true : read(cfgGcWal),
        runStale: selected ? flags.stale === true : read(cfgGcStale),
        runCompress: selected ? flags.compress === true : read(cfgGcCompress),
        coldArchiveAfterDays: numberSetting(flags.coldArchiveAfterDays, read(cfgGcColdArchiveAfterDays), cfgGcColdArchiveAfterDays.default),
        retainNewestGlobal: numberSetting(flags.retainNewestGlobal, read(cfgGcRetainNewestGlobal), cfgGcRetainNewestGlobal.default),
        retainNewestPerCwd: numberSetting(flags.retainNewestPerCwd, read(cfgGcRetainNewestPerCwd), cfgGcRetainNewestPerCwd.default),
        staleRetainNewest: numberSetting(flags.staleRetainNewest, read(cfgGcStaleRetainNewest), cfgGcStaleRetainNewest.default),
        staleRetainDays: numberSetting(flags.staleRetainDays, read(cfgGcStaleRetainDays), cfgGcStaleRetainDays.default),
        compressAfterDays: numberSetting(flags.compressAfterDays, read(cfgGcCompressAfterDays), cfgGcCompressAfterDays.default),
    };
}
export function collectGcErrors(result) {
    return [
        ...(result.stale?.errors ?? []).map(error => `stale: ${error}`),
        ...(result.blobs?.errors ?? []).map(error => `blobs: ${error}`),
        ...(result.archive?.errors ?? []).map(error => `archive: ${error}`),
        ...(result.compress?.errors ?? []).map(error => `compress: ${error}`),
    ];
}
function getArchivedSessionsDir(agentDir) {
    return path.join(path.dirname(getSessionsDir(agentDir)), "archive", "sessions");
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
function codeOf(error) {
    return typeof error === "object" && error !== null && "code" in error
        ? String(error.code)
        : undefined;
}
async function pathExists(target) {
    try {
        await fs.stat(target);
        return true;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return false;
        throw error;
    }
}
async function statIfPresent(target) {
    try {
        return await fs.stat(target);
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return null;
        throw error;
    }
}
/** Small registry/breadcrumb marker files; a missing file reads as empty. */
async function readTextIfPresent(file) {
    try {
        return await Bun.file(file).text();
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return "";
        throw error;
    }
}
async function scanSessionLinesIfPresent(file, onLine) {
    // readLines buffers at most the largest record, including malformed records.
    const scan = async (stream) => {
        for await (const line of readLines(stream))
            onLine(line);
    };
    try {
        const stream = Bun.file(file).stream();
        if (file.endsWith(COMPRESSED_SESSION_SUFFIX)) {
            const gunzip = createGunzip();
            await pipeline(stream, gunzip, async (source) => {
                // Match the native stream's byte budget, not one arbitrary chunk or
                // a default queue that counts each potentially large chunk as size 1.
                await scan(Readable.toWeb(source, {
                    strategy: new ByteLengthQueuingStrategy({ highWaterMark: gunzip.readableHighWaterMark }),
                }));
            });
        }
        else {
            await scan(stream);
        }
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return;
        throw error;
    }
}
async function collectJsonlFiles(root) {
    try {
        const files = await Array.fromAsync(JSONL_GLOB.scan(root), name => path.join(root, name));
        files.sort();
        return files;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
}
async function collectCompressedJsonlFiles(root) {
    try {
        const files = await Array.fromAsync(JSONL_GZ_GLOB.scan(root), name => path.join(root, name));
        files.sort();
        return files;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
}
async function collectBackupJsonlFiles(root) {
    try {
        const files = await Array.fromAsync(JSONL_BACKUP_GLOB.scan(root), name => path.join(root, name));
        files.sort();
        return files;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
}
async function collectReferencedBlobHashes(sessionRoots, exactSessionFiles) {
    const files = new Map();
    const decoder = new TextDecoder();
    for (const root of sessionRoots) {
        for (const file of [
            ...(await collectJsonlFiles(root)),
            ...(await collectCompressedJsonlFiles(root)),
            ...(await collectBackupJsonlFiles(root)),
        ]) {
            files.set(normalizePathForComparison(file), file);
        }
    }
    for (const file of exactSessionFiles) {
        files.set(normalizePathForComparison(file), file);
    }
    const hashes = new Set();
    for (const file of files.values()) {
        // Keep raw-text matching: recoverable malformed records can still own blobs.
        await scanSessionLinesIfPresent(file, line => {
            for (const match of decoder.decode(line).matchAll(BLOB_REF_RE)) {
                const hash = match[1]?.toLowerCase();
                if (hash && BLOB_HASH_RE.test(hash))
                    hashes.add(hash);
            }
        });
    }
    return hashes;
}
/**
 * Paths recorded in the persistent registry (`<agentDir>/custom-session-files/*`).
 * A first save may leave only its staging temp, so the target need not exist
 * when reclaiming crash leftovers.
 */
async function collectRegisteredSessionPaths(registryDir) {
    let entries;
    try {
        entries = await fs.readdir(registryDir);
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
    const files = new Map();
    for (const entry of entries) {
        const recorded = (await readTextIfPresent(path.join(registryDir, entry))).trim();
        if (!recorded)
            continue;
        const sessionFile = path.resolve(recorded);
        files.set(normalizePathForComparison(sessionFile), sessionFile);
    }
    return [...files.values()];
}
/**
 * Exact session files recorded in terminal breadcrumbs. Supplements
 * {@link collectRegisteredSessionFiles}: a breadcrumb holds only that
 * terminal's last session, but catches the current transcript even if its
 * persistent marker write failed.
 */
async function collectBreadcrumbSessionFiles(breadcrumbDir) {
    let entries;
    try {
        entries = await fs.readdir(breadcrumbDir);
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
    const files = new Map();
    for (const entry of entries) {
        const text = await readTextIfPresent(path.join(breadcrumbDir, entry));
        const lines = text.split("\n");
        const breadcrumbCwd = lines[0]?.trim();
        const recordedSessionFile = lines[1]?.trim();
        if (!breadcrumbCwd || !recordedSessionFile)
            continue;
        const sessionFile = path.resolve(breadcrumbCwd, recordedSessionFile);
        files.set(normalizePathForComparison(sessionFile), sessionFile);
    }
    return [...files.values()];
}
async function collectBlobCandidates(blobDir) {
    let entries;
    try {
        entries = await fs.readdir(blobDir);
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return { candidates: [], staging: [] };
        throw error;
    }
    const byHash = new Map();
    const staging = [];
    for (const entry of entries) {
        const isStaging = BLOB_STAGING_RE.test(entry);
        const hash = isStaging ? undefined : entry.match(BLOB_FILE_RE)?.[1];
        if (!isStaging && !hash)
            continue;
        const file = path.join(blobDir, entry);
        const stat = await statIfPresent(file);
        if (!stat)
            continue;
        if (!stat.isFile())
            continue;
        if (!hash) {
            staging.push({ path: file, bytes: stat.size, mtimeMs: stat.mtimeMs });
            continue;
        }
        const candidate = byHash.get(hash) ?? { hash, paths: [], bytes: 0, mtimeMs: stat.mtimeMs };
        candidate.paths.push(file);
        candidate.bytes += stat.size;
        candidate.mtimeMs = Math.max(candidate.mtimeMs, stat.mtimeMs);
        byHash.set(hash, candidate);
    }
    return { candidates: [...byHash.values()].sort((a, b) => a.hash.localeCompare(b.hash)), staging };
}
async function unlinkBlobFile(file, result) {
    try {
        await fs.unlink(file);
        result.deleted += 1;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return;
        result.errors.push(`${file}: ${errorMessage(error)}`);
    }
}
/**
 * Delete an unreferenced candidate unless a put reused its blob after the
 * candidate scan. `BlobStore.put` refreshes an old reused blob's mtime before
 * its new reference reaches a session file, and rewrites the blob when that
 * touch finds the path gone. The canonical file is therefore moved to a
 * staging name first: a touch that landed before the move shows on the moved
 * file, which goes back; one that lands after misses the path, so the put
 * writes the blob again. Returns whether the candidate was deleted.
 */
async function deleteBlobCandidate(candidate, deleteBeforeMs, result) {
    const canonical = candidate.paths.find(file => path.basename(file) === candidate.hash);
    const files = candidate.paths.filter(file => file !== canonical);
    if (canonical) {
        const moved = blobStagingPath(canonical);
        try {
            await fs.rename(canonical, moved);
        }
        catch (error) {
            if (codeOf(error) !== "ENOENT") {
                result.errors.push(`${canonical}: ${errorMessage(error)}`);
                return false;
            }
        }
        const stat = await statIfPresent(moved);
        if (stat && stat.mtimeMs > deleteBeforeMs) {
            await restoreReusedBlob(moved, canonical, result);
            return false;
        }
        if (stat)
            files.unshift(moved);
    }
    for (const file of files)
        await unlinkBlobFile(file, result);
    return true;
}
/** Put a blob reused mid-sweep back; a put that already rewrote it wins (same bytes). */
async function restoreReusedBlob(moved, canonical, result) {
    try {
        await fs.rename(moved, canonical);
        return;
    }
    catch (error) {
        if (!(await statIfPresent(canonical))) {
            result.errors.push(`${canonical}: failed to restore reused blob: ${errorMessage(error)}`);
            return;
        }
    }
    try {
        await fs.unlink(moved);
    }
    catch {
        // The rewritten canonical blob stands; a leftover staging copy ages out.
    }
}
async function runBlobGc(options, archiveSessionsRoot) {
    const blobDir = getBlobsDir(options.agentDir);
    const sessionsRoot = getSessionsDir(options.agentDir);
    const defaultRoots = [sessionsRoot, archiveSessionsRoot];
    const exactSessionFiles = new Map();
    for (const file of await collectRegisteredSessionPaths(getCustomSessionFilesDir(options.agentDir))) {
        if (!(await statIfPresent(file))?.isFile())
            continue;
        exactSessionFiles.set(normalizePathForComparison(file), file);
    }
    for (const file of await collectBreadcrumbSessionFiles(getTerminalSessionsDir(options.agentDir))) {
        exactSessionFiles.set(normalizePathForComparison(file), file);
    }
    const referenced = await collectReferencedBlobHashes(defaultRoots, [...exactSessionFiles.values()]);
    const { candidates, staging } = await collectBlobCandidates(blobDir);
    const result = {
        referenced: referenced.size,
        candidates: candidates.length,
        wouldDelete: 0,
        deleted: 0,
        bytes: 0,
        errors: [],
    };
    const deleteBeforeMs = Date.now() - GC_WRITE_GRACE_MS;
    for (const candidate of candidates) {
        if (referenced.has(candidate.hash))
            continue;
        if (candidate.mtimeMs > deleteBeforeMs)
            continue;
        if (options.apply && !(await deleteBlobCandidate(candidate, deleteBeforeMs, result)))
            continue;
        result.wouldDelete += candidate.paths.length;
        result.bytes += candidate.bytes;
    }
    // A live write renames its staging file away within milliseconds; one past
    // the grace was left by a killed or crashed writer and nothing will claim it.
    for (const file of staging) {
        if (file.mtimeMs > deleteBeforeMs)
            continue;
        result.wouldDelete += 1;
        result.bytes += file.bytes;
        if (options.apply)
            await unlinkBlobFile(file.path, result);
    }
    return result;
}
/**
 * Config-root stores (`reports/`, `collab/`) live beside the agent dir, not in
 * it. The default agent dir resolves them through the dirs resolver (XDG-aware);
 * a custom agent dir named `agent` owns its parent as config root; any other
 * custom agent dir has no config root for gc to maintain.
 */
function resolveConfigRootStores(agentDir) {
    const configRoot = getConfigRootDir();
    if (normalizePathForComparison(agentDir) === normalizePathForComparison(path.join(configRoot, "agent"))) {
        return { reportsDir: getReportsDir(), collabDir: path.join(configRoot, "collab") };
    }
    if (path.basename(agentDir) !== "agent")
        return undefined;
    const root = path.dirname(agentDir);
    return { reportsDir: path.join(root, "reports"), collabDir: path.join(root, "collab") };
}
async function listFilesIfPresent(dir) {
    try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        return entries.filter(entry => entry.isFile()).map(entry => path.join(dir, entry.name));
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
}
/** Whether a pointer's target is verifiably gone; unreadable targets count as present. */
async function sessionFileMissing(sessionFile) {
    try {
        return !(await fs.stat(sessionFile)).isFile();
    }
    catch (error) {
        const code = codeOf(error);
        return code === "ENOENT" || code === "ENOTDIR";
    }
}
/**
 * Pointer files (custom-session markers, terminal breadcrumbs) past
 * {@link STALE_POINTER_GRACE_MS} whose recorded session file is gone.
 * `resolveTarget` returns undefined for unparsable pointers, which are kept.
 */
async function collectDanglingPointers(dir, kind, resolveTarget) {
    const deleteBeforeMs = Date.now() - STALE_POINTER_GRACE_MS;
    const candidates = [];
    for (const file of await listFilesIfPresent(dir)) {
        const stat = await statIfPresent(file);
        if (!stat || stat.mtimeMs > deleteBeforeMs)
            continue;
        const target = resolveTarget(await readTextIfPresent(file));
        if (!target || !(await sessionFileMissing(target)))
            continue;
        candidates.push({ kind, paths: [file], bytes: stat.size });
    }
    return candidates;
}
/**
 * Files beyond the newest `retainNewest` that are also older than
 * `retainDays` (and never inside the write grace).
 */
async function collectExpiredFiles(dir, suffix, options) {
    const files = [];
    for (const file of await listFilesIfPresent(dir)) {
        if (!file.endsWith(suffix))
            continue;
        const stat = await statIfPresent(file);
        if (stat)
            files.push({ file, bytes: stat.size, mtimeMs: stat.mtimeMs });
    }
    files.sort((a, b) => b.mtimeMs - a.mtimeMs);
    const deleteBeforeMs = Date.now() - Math.max(options.staleRetainDays * DAY_MS, GC_WRITE_GRACE_MS);
    return files.slice(options.staleRetainNewest).filter(entry => entry.mtimeMs < deleteBeforeMs);
}
async function runStaleGc(options) {
    const markersDir = getCustomSessionFilesDir(options.agentDir);
    const breadcrumbDir = getTerminalSessionsDir(options.agentDir);
    const candidates = [
        ...(await collectDanglingPointers(markersDir, "danglingMarkers", text => {
            const recorded = text.trim();
            return recorded ? path.resolve(recorded) : undefined;
        })),
        ...(await collectDanglingPointers(breadcrumbDir, "staleBreadcrumbs", text => {
            const crumb = parseTerminalBreadcrumb(text);
            // A fresh crumb is a lazy `/new` boundary that `--continue` honors
            // before its transcript exists. It stays until the session materializes
            // (rewriting it non-fresh) or the terminal's next session replaces it.
            if (!crumb || crumb.fresh)
                return undefined;
            const cwd = crumb.cwd.trim();
            const sessionFile = crumb.sessionFile.trim();
            return cwd && sessionFile ? path.resolve(cwd, sessionFile) : undefined;
        })),
    ];
    const stores = resolveConfigRootStores(options.agentDir);
    if (stores) {
        for (const { file, bytes } of await collectExpiredFiles(stores.reportsDir, ".tar.gz", options)) {
            candidates.push({ kind: "expiredReports", paths: [file], bytes });
        }
        // A replica a terminal's breadcrumb points at is what `--continue` resumes
        // there; one a running guest holds is skipped at removal (ownership lease).
        const resumable = new Set((await collectBreadcrumbSessionFiles(breadcrumbDir)).map(file => normalizePathForComparison(file)));
        for (const { file, bytes } of await collectExpiredFiles(stores.collabDir, SESSION_SUFFIX, options)) {
            if (resumable.has(normalizePathForComparison(file)))
                continue;
            candidates.push({
                kind: "expiredReplicas",
                // The replica's custom-session marker would only dangle once it is gone.
                paths: [file, sessionArtifactsPath(file), path.join(markersDir, hashPath(file))],
                bytes,
                ownedSession: file,
            });
        }
    }
    const result = {
        danglingMarkers: 0,
        staleBreadcrumbs: 0,
        expiredReports: 0,
        expiredReplicas: 0,
        wouldDelete: 0,
        deleted: 0,
        bytes: 0,
        errors: [],
    };
    for (const candidate of candidates) {
        const lease = candidate.ownedSession ? await tryAcquireSessionFileLease(candidate.ownedSession) : undefined;
        if (lease === null)
            continue;
        try {
            result[candidate.kind] += 1;
            result.wouldDelete += 1;
            result.bytes += candidate.bytes;
            if (!options.apply)
                continue;
            try {
                for (const target of candidate.paths)
                    await fs.rm(target, { recursive: true, force: true });
                result.deleted += 1;
            }
            catch (error) {
                result.errors.push(`${candidate.paths[0]}: ${errorMessage(error)}`);
            }
        }
        finally {
            // Held through the removal so a guest cannot reopen the replica mid-delete.
            lease?.release();
        }
    }
    return result;
}
/**
 * Take the ownership lease of the session in `sessionFile`, or null while a
 * running process holds it (or the lease cannot be probed: an unknown owner is
 * treated as live). The lease is keyed by the header's session id. Undefined
 * when the file has no session header: omp writes the header with the first
 * bytes of a session, so no running writer owns such a file (and candidates
 * are past the write grace, so none is mid-write).
 */
async function tryAcquireSessionFileLease(sessionFile) {
    try {
        const sessionId = await readSessionHeaderId(sessionFile);
        return sessionId === undefined ? undefined : tryAcquireSessionLease(sessionId);
    }
    catch {
        return null;
    }
}
async function listActiveSessions(sessionsRoot) {
    let entries;
    try {
        entries = await fs.readdir(sessionsRoot, { withFileTypes: true });
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return [];
        throw error;
    }
    const storage = new FileSessionStorage();
    const sessions = [];
    for (const entry of entries) {
        if (!entry.isDirectory())
            continue;
        sessions.push(...(await listSessionsReadOnly(path.join(sessionsRoot, entry.name), storage)));
    }
    sessions.sort((a, b) => b.modified.getTime() - a.modified.getTime());
    return sessions;
}
async function listNestedSessionsReadOnly(artifactsRoot) {
    const files = await collectJsonlFiles(artifactsRoot);
    const dirs = [...new Set(files.map(file => path.dirname(file)))].sort();
    const storage = new FileSessionStorage();
    const sessions = [];
    for (const dir of dirs)
        sessions.push(...(await listSessionsReadOnly(dir, storage)));
    sessions.sort((a, b) => b.modified.getTime() - a.modified.getTime());
    return sessions;
}
async function hasLiveNestedSessions(session, archiveBeforeMs) {
    for (const nested of await listNestedSessionsReadOnly(sessionArtifactsPath(session.path))) {
        if (nested.status && ACTIVE_STATUSES.has(nested.status))
            return true;
        if (nested.modified.getTime() > archiveBeforeMs)
            return true;
    }
    return false;
}
function archiveDestination(archiveRoot, sessionsRoot, session) {
    const sessionPath = session.path;
    const relativePath = path.relative(sessionsRoot, sessionPath);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath))
        return null;
    if (!relativePath.endsWith(SESSION_SUFFIX))
        return null;
    return {
        relativePath,
        destinationPath: path.join(archiveRoot, `${relativePath}.gz`),
    };
}
function sessionCwdKey(sessionsRoot, session) {
    const relativePath = path.relative(sessionsRoot, session.path);
    if (relativePath.startsWith("..") || path.isAbsolute(relativePath))
        return session.cwd || ".";
    const dirname = path.dirname(relativePath);
    return dirname === "." ? session.cwd || "." : dirname;
}
async function movePath(source, destination) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    try {
        await fs.rename(source, destination);
        return;
    }
    catch (error) {
        if (codeOf(error) !== "EXDEV")
            throw error;
    }
    const stat = await fs.stat(source);
    if (stat.isDirectory()) {
        await fs.cp(source, destination, { recursive: true });
        await fs.rm(source, { recursive: true, force: true });
        return;
    }
    await fs.copyFile(source, destination);
    await fs.unlink(source);
}
function sessionArtifactsPath(sessionPath) {
    if (sessionPath.endsWith(COMPRESSED_SESSION_SUFFIX)) {
        return sessionPath.slice(0, -COMPRESSED_SESSION_SUFFIX.length);
    }
    return sessionPath.slice(0, -SESSION_SUFFIX.length);
}
class SessionLineageHeaderReader {
    header;
    done = false;
    #sawTitleSlot = false;
    read(line) {
        if (this.done)
            return;
        line = line.trim();
        if (!line)
            return;
        try {
            const record = JSON.parse(line);
            if (!this.#sawTitleSlot && record.type === "title") {
                this.#sawTitleSlot = true;
                return;
            }
            this.done = true;
            if (record.type !== "session" || typeof record.id !== "string" || record.id.length === 0)
                return;
            this.header = {
                id: record.id,
                parentSession: typeof record.parentSession === "string" ? record.parentSession : undefined,
                previousSessionFiles: Array.isArray(record.previousSessionFiles)
                    ? record.previousSessionFiles.filter((previousSessionFile) => typeof previousSessionFile === "string" && previousSessionFile.length > 0)
                    : [],
            };
        }
        catch {
            this.done = true;
        }
    }
}
async function readSessionLineageHeader(file) {
    const decoder = new TextDecoder();
    const reader = new SessionLineageHeaderReader();
    for await (const line of readLines(Bun.file(file).stream())) {
        reader.read(decoder.decode(line));
        if (reader.done)
            break;
    }
    return reader.header;
}
async function scanArchivedSession(file, identities) {
    const decoder = new TextDecoder();
    const reader = new SessionLineageHeaderReader();
    // Drain even after the header: a late gzip error must invalidate the archive.
    await scanSessionLinesIfPresent(file, line => {
        if (reader.done && !identities)
            return;
        const text = decoder.decode(line);
        reader.read(text);
        if (identities)
            addSessionStatsIdentity(text, identities);
    });
    return reader.header;
}
async function gzipSessionFile(source, destination) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const tempPath = `${destination}.${process.pid}.${Date.now()}.tmp`;
    let renamed = false;
    try {
        await pipeline(Bun.file(source).stream(), createGzip({ level: 9 }), (await fs.open(tempPath, "w")).createWriteStream());
        await fs.rename(tempPath, destination);
        renamed = true;
        await fs.unlink(source);
    }
    catch (error) {
        await fs.rm(tempPath, { force: true });
        if (renamed)
            await fs.rm(destination, { force: true });
        throw error;
    }
}
async function restoreGzipSessionFile(source, destination) {
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const tempPath = `${destination}.${process.pid}.${Date.now()}.tmp`;
    try {
        await pipeline(Bun.file(source).stream(), createGunzip(), (await fs.open(tempPath, "w")).createWriteStream());
        await fs.rename(tempPath, destination);
        await fs.unlink(source);
    }
    catch (error) {
        await fs.rm(tempPath, { force: true });
        throw error;
    }
}
async function moveSessionWithArtifacts(candidate) {
    const sourceSession = candidate.session.path;
    const destSession = candidate.destinationPath;
    const legacyDestSession = destSession.endsWith(".gz") ? destSession.slice(0, -".gz".length) : `${destSession}.gz`;
    const sourceArtifacts = sessionArtifactsPath(sourceSession);
    const destArtifacts = sessionArtifactsPath(destSession);
    if (await pathExists(destSession))
        throw new Error(`archive destination exists: ${destSession}`);
    if (await pathExists(legacyDestSession))
        throw new Error(`archive destination exists: ${legacyDestSession}`);
    if ((await pathExists(sourceArtifacts)) && (await pathExists(destArtifacts))) {
        throw new Error(`archive artifacts destination exists: ${destArtifacts}`);
    }
    const moved = [];
    try {
        await gzipSessionFile(sourceSession, destSession);
        moved.push({ source: sourceSession, destination: destSession, compressed: true });
        if (await pathExists(sourceArtifacts)) {
            await movePath(sourceArtifacts, destArtifacts);
            moved.push({ source: sourceArtifacts, destination: destArtifacts });
        }
    }
    catch (error) {
        for (const move of moved.reverse()) {
            try {
                if (move.compressed) {
                    await restoreGzipSessionFile(move.destination, move.source);
                }
                else {
                    await movePath(move.destination, move.source);
                }
            }
            catch {
                // Preserve the original failure; rollback failure is reported by the next scan.
            }
        }
        throw error;
    }
}
function sqliteNumber(value) {
    if (typeof value === "bigint")
        return Number(value);
    if (typeof value === "number")
        return value;
    return 0;
}
// Every statement below is scoped with `using`: an unfinalized statement keeps the SQLite
// connection (and its db/-wal/-shm files) open after close() until GC, and Windows refuses
// to delete or replace a file that is still open.
function tableExists(db, table) {
    const env_1 = { stack: [], error: void 0, hasError: false };
    try {
        const stmt = __addDisposableResource(env_1, db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type IN ('table','view') AND name = ?"), false);
        const row = stmt.get(table);
        return row?.present === 1;
    }
    catch (e_1) {
        env_1.error = e_1;
        env_1.hasError = true;
    }
    finally {
        __disposeResources(env_1);
    }
}
function deleteHistoryRowsForSessions(dbPath, sessionIds) {
    if (sessionIds.length === 0)
        return { deleted: 0, ftsRebuilt: false };
    const db = new Database(dbPath);
    try {
        const env_2 = { stack: [], error: void 0, hasError: false };
        try {
            db.run("PRAGMA busy_timeout = 5000");
            const hasHistory = tableExists(db, "history") && tableHasColumn(db, "history", "session_id");
            const hasRecaps = tableExists(db, "session_recaps");
            const hasTitles = tableExists(db, "session_titles");
            if (!hasHistory && !hasRecaps && !hasTitles)
                return { deleted: 0, ftsRebuilt: false };
            const hasFts = hasHistory && tableExists(db, "history_fts");
            const deleteStmt = __addDisposableResource(env_2, hasHistory ? db.prepare("DELETE FROM history WHERE session_id = ?") : undefined, false);
            // Recaps and titles are session-scoped side output with no life beyond their session.
            const deleteRecapsStmt = __addDisposableResource(env_2, hasRecaps ? db.prepare("DELETE FROM session_recaps WHERE session_id = ?") : undefined, false);
            const deleteTitlesStmt = __addDisposableResource(env_2, hasTitles ? db.prepare("DELETE FROM session_titles WHERE session_id = ?") : undefined, false);
            let deleted = 0;
            const tx = db.transaction((ids) => {
                for (const id of ids) {
                    deleteRecapsStmt?.run(id);
                    deleteTitlesStmt?.run(id);
                    if (!deleteStmt)
                        continue;
                    const result = deleteStmt.run(id);
                    deleted += sqliteNumber(result.changes);
                }
                if (deleted > 0 && hasFts)
                    db.run("INSERT INTO history_fts(history_fts) VALUES('rebuild')");
            });
            tx(sessionIds);
            return { deleted, ftsRebuilt: deleted > 0 && hasFts };
        }
        catch (e_2) {
            env_2.error = e_2;
            env_2.hasError = true;
        }
        finally {
            __disposeResources(env_2);
        }
    }
    finally {
        db.close();
    }
}
async function collectArchivedSessionIds(archiveRoot) {
    const ids = new Set();
    for (const file of await collectCompressedJsonlFiles(archiveRoot)) {
        const id = (await scanArchivedSession(file))?.id;
        if (id)
            ids.add(id);
    }
    return [...ids].sort();
}
async function cleanupHistoryRowsForArchivedSessions(options, archiveRoot, archivedSessionIds, result) {
    const dbPath = getHistoryDbPath(options.agentDir);
    if (!(await pathExists(dbPath)))
        return;
    const cleanupIds = new Set(archivedSessionIds);
    try {
        for (const id of await collectArchivedSessionIds(archiveRoot))
            cleanupIds.add(id);
    }
    catch (error) {
        result.errors.push(`history cleanup scan: ${errorMessage(error)}`);
    }
    try {
        const cleanup = deleteHistoryRowsForSessions(dbPath, [...cleanupIds]);
        result.historyRowsDeleted = cleanup.deleted;
        result.ftsRebuilt = cleanup.ftsRebuilt;
    }
    catch (error) {
        result.errors.push(`history cleanup: ${errorMessage(error)}`);
    }
}
const STATS_SESSION_TABLES = ["messages", "user_messages", "tool_calls", "file_offsets"];
const STATS_ENTRY_TABLES = ["messages", "user_messages", "tool_calls"];
const STATS_IDENTITY_COLUMNS = {
    messages: ["entry_id", "timestamp"],
    user_messages: ["entry_id", "timestamp"],
    tool_calls: ["entry_id", "timestamp", "tool_call_id"],
};
function createStatsIdentities() {
    return {
        messages: [],
        user_messages: [],
        tool_calls: [],
    };
}
function statsIdentityKey(table, identity) {
    return `${table}\0${identity.entryId}\0${identity.timestamp}\0${identity.toolCallId}`;
}
function statsIdentityKeys(identities) {
    const keys = new Set();
    for (const table of STATS_ENTRY_TABLES) {
        for (const identity of identities[table])
            keys.add(statsIdentityKey(table, identity));
    }
    return keys;
}
function tableHasColumn(db, table, column) {
    const env_3 = { stack: [], error: void 0, hasError: false };
    try {
        const stmt = __addDisposableResource(env_3, db.prepare(`PRAGMA table_info(${table})`), false);
        const rows = stmt.all();
        return rows.some(row => row.name === column);
    }
    catch (e_3) {
        env_3.error = e_3;
        env_3.hasError = true;
    }
    finally {
        __disposeResources(env_3);
    }
}
function collectStoredStatsSessionPaths(db) {
    const sessionPaths = new Set();
    for (const table of STATS_SESSION_TABLES) {
        const env_4 = { stack: [], error: void 0, hasError: false };
        try {
            if (!tableExists(db, table) || !tableHasColumn(db, table, "session_file"))
                continue;
            const stmt = __addDisposableResource(env_4, db.prepare(`SELECT DISTINCT session_file FROM ${table}`), false);
            const rows = stmt.all();
            for (const row of rows) {
                if (typeof row.session_file === "string")
                    sessionPaths.add(row.session_file);
            }
        }
        catch (e_4) {
            env_4.error = e_4;
            env_4.hasError = true;
        }
        finally {
            __disposeResources(env_4);
        }
    }
    return [...sessionPaths];
}
/**
 * `/move` preserves the session filename and artifacts-directory basename.
 * Recover the top-level path represented by any main or nested stats row so
 * one archived logical session can reconcile every historical location.
 */
function logicalSessionRootForStatsPath(statsPath, sessionPath) {
    const sessionFilename = path.basename(sessionPath);
    if (path.basename(statsPath) === sessionFilename)
        return statsPath;
    const artifactsDirname = sessionFilename.slice(0, -SESSION_SUFFIX.length);
    let directory = path.dirname(path.resolve(statsPath));
    while (true) {
        if (path.basename(directory) === artifactsDirname)
            return `${directory}${SESSION_SUFFIX}`;
        const parent = path.dirname(directory);
        if (parent === directory)
            return undefined;
        directory = parent;
    }
}
function sessionPathEncodesId(sessionPath, sessionId) {
    const stem = path.basename(sessionPath, SESSION_SUFFIX);
    return stem === sessionId || stem.endsWith(`_${sessionId}`);
}
function managedHistoricalSessionPaths(header, currentSessionPath, sessionsRoot) {
    const root = path.resolve(sessionsRoot);
    const filename = path.basename(currentSessionPath);
    const paths = new Set();
    for (const previousSessionFile of header.previousSessionFiles) {
        if (!path.isAbsolute(previousSessionFile) || path.basename(previousSessionFile) !== filename)
            continue;
        const resolved = path.resolve(previousSessionFile);
        const relative = path.relative(root, resolved);
        if (!relative ||
            relative === ".." ||
            relative.startsWith(`..${path.sep}`) ||
            path.isAbsolute(relative) ||
            !resolved.endsWith(SESSION_SUFFIX)) {
            continue;
        }
        paths.add(resolved);
    }
    return [...paths];
}
function resolveLogicalSessionMatch(statsPath, nodes) {
    const matches = [];
    for (const node of nodes) {
        const logicalRoot = logicalSessionRootForStatsPath(statsPath, node.path);
        if (logicalRoot)
            matches.push({ node, logicalRoot });
    }
    const exact = matches.filter(match => path.resolve(match.logicalRoot) === path.resolve(match.node.path));
    if (exact.length === 1)
        return exact[0];
    if (exact.length > 1)
        return undefined;
    const known = matches.filter(match => [...match.node.statsPaths].some(statsPath => path.resolve(statsPath) === path.resolve(match.logicalRoot)));
    if (known.length === 1)
        return known[0];
    if (known.length > 1)
        return undefined;
    const idMatches = matches.filter(match => sessionPathEncodesId(match.logicalRoot, match.node.id));
    return idMatches.length === 1 ? idMatches[0] : undefined;
}
/**
 * Resolve retained peers through `parentSession`, which is historically either
 * a session id or an absolute path. Ambiguous aliases are deliberately left
 * unresolved so cleanup fails safe instead of transferring across sessions.
 */
function buildStatsCleanupPlans(archivedSessions, retainedSessions, dbPath) {
    const archivedNodes = archivedSessions.map(session => ({
        ...session,
        statsPaths: new Set([session.path, ...session.historicalPaths]),
        identityKeys: statsIdentityKeys(session.identities),
    }));
    const retainedNodes = retainedSessions.map(session => ({
        ...session,
        statsPaths: new Set([session.path, ...session.historicalPaths]),
        identityKeys: statsIdentityKeys(session.identities),
    }));
    const nodes = [...archivedNodes, ...retainedNodes];
    const db = new Database(dbPath);
    try {
        db.run("PRAGMA busy_timeout = 5000");
        for (const storedPath of collectStoredStatsSessionPaths(db)) {
            const match = resolveLogicalSessionMatch(storedPath, nodes);
            if (match)
                match.node.statsPaths.add(match.logicalRoot);
        }
    }
    finally {
        db.close();
    }
    for (const child of nodes) {
        if (!child.parentSession ||
            (!path.isAbsolute(child.parentSession) && !child.parentSession.endsWith(SESSION_SUFFIX))) {
            continue;
        }
        const match = resolveLogicalSessionMatch(child.parentSession, nodes);
        if (match)
            match.node.statsPaths.add(match.logicalRoot);
    }
    const archivedPathClaimCounts = new Map();
    for (const archived of archivedNodes) {
        for (const statsPath of archived.statsPaths) {
            const key = path.resolve(statsPath);
            archivedPathClaimCounts.set(key, (archivedPathClaimCounts.get(key) ?? 0) + 1);
        }
    }
    const ambiguousArchivedPathKeys = new Set([...archivedPathClaimCounts].filter(([, count]) => count > 1).map(([key]) => key));
    const aliases = new Map();
    const identityKeysByNode = new Map();
    for (const node of nodes) {
        const keys = new Set([
            `id:${node.id}`,
            ...[...node.statsPaths].map(statsPath => `path:${path.resolve(statsPath)}`),
        ]);
        identityKeysByNode.set(node, keys);
        for (const key of keys) {
            if (!aliases.has(key)) {
                aliases.set(key, node);
            }
            else if (aliases.get(key) !== node) {
                aliases.set(key, null);
            }
        }
    }
    const incompleteLineage = new Set();
    const lineageKeysByNode = new Map();
    for (const node of nodes) {
        const lineageKeys = new Set(identityKeysByNode.get(node));
        let current = node;
        const seen = new Set();
        while (current?.parentSession) {
            if (seen.has(current)) {
                incompleteLineage.add(node);
                break;
            }
            seen.add(current);
            const parentReference = current.parentSession;
            const parentKey = path.isAbsolute(parentReference) || parentReference.endsWith(SESSION_SUFFIX)
                ? `path:${path.resolve(parentReference)}`
                : `id:${parentReference}`;
            lineageKeys.add(parentKey);
            const parent = aliases.get(parentKey);
            if (!parent) {
                incompleteLineage.add(node);
                break;
            }
            for (const key of identityKeysByNode.get(parent) ?? [])
                lineageKeys.add(key);
            current = parent;
        }
        lineageKeysByNode.set(node, lineageKeys);
    }
    const retainedPathKeys = new Set(retainedNodes.flatMap(retained => [...retained.statsPaths].map(statsPath => path.resolve(statsPath))));
    const plans = archivedNodes.map(archived => {
        const archivedLineage = lineageKeysByNode.get(archived) ?? new Set();
        return {
            sessionPaths: [...archived.statsPaths].filter(statsPath => {
                const key = path.resolve(statsPath);
                return !retainedPathKeys.has(key) && !ambiguousArchivedPathKeys.has(key);
            }),
            retainedSessions: retainedNodes.filter(retained => {
                if (incompleteLineage.has(retained))
                    return false;
                const retainedLineage = lineageKeysByNode.get(retained);
                return retainedLineage ? [...retainedLineage].some(key => archivedLineage.has(key)) : false;
            }),
            transfers: [],
            archivedIdentityKeys: archived.identityKeys,
            preserveAll: false,
        };
    });
    return {
        plans,
        incompleteRetainedSessions: retainedNodes.filter(retained => incompleteLineage.has(retained)),
    };
}
function addSessionStatsIdentity(line, identities) {
    if (line.length === 0)
        return;
    try {
        const record = JSON.parse(line);
        if (!record ||
            typeof record !== "object" ||
            !("type" in record) ||
            record.type !== "message" ||
            !("id" in record) ||
            typeof record.id !== "string" ||
            record.id.length === 0 ||
            !("message" in record) ||
            !record.message ||
            typeof record.message !== "object") {
            return;
        }
        const message = record.message;
        if (!("role" in message))
            return;
        const parsedEntryTimestamp = "timestamp" in record && typeof record.timestamp === "string" ? Date.parse(record.timestamp) : Number.NaN;
        if (message.role === "user") {
            identities.user_messages.push({
                entryId: record.id,
                timestamp: Number.isFinite(parsedEntryTimestamp) ? parsedEntryTimestamp : 0,
                toolCallId: "",
            });
            return;
        }
        if (message.role !== "assistant")
            return;
        const timestamp = "timestamp" in message && typeof message.timestamp === "number" && Number.isFinite(message.timestamp)
            ? message.timestamp
            : Number.isFinite(parsedEntryTimestamp)
                ? parsedEntryTimestamp
                : 0;
        identities.messages.push({ entryId: record.id, timestamp, toolCallId: "" });
        if (!("content" in message) || !Array.isArray(message.content))
            return;
        for (const block of message.content) {
            if (block &&
                typeof block === "object" &&
                "type" in block &&
                block.type === "toolCall" &&
                "id" in block &&
                typeof block.id === "string") {
                identities.tool_calls.push({ entryId: record.id, timestamp, toolCallId: block.id });
            }
        }
    }
    catch {
        // Stats parsing is also lenient: a malformed line cannot own a retained row.
    }
}
async function collectSessionStatsIdentities(sessionPath) {
    const identities = createStatsIdentities();
    const decoder = new TextDecoder();
    for await (const line of readLines(Bun.file(sessionPath).stream())) {
        addSessionStatsIdentity(decoder.decode(line), identities);
    }
    return identities;
}
async function populateStatsTransferTargets(context) {
    const identitiesBySession = new Map();
    const identitiesFor = (session) => {
        let identities = identitiesBySession.get(session.path);
        if (!identities) {
            identities = collectSessionStatsIdentities(session.path);
            identitiesBySession.set(session.path, identities);
        }
        return identities;
    };
    const incompleteIdentityKeys = new Set();
    let hasUnidentifiableIncompleteSession = false;
    for (const retained of context.incompleteRetainedSessions) {
        const keys = statsIdentityKeys(await identitiesFor(retained));
        if (keys.size === 0)
            hasUnidentifiableIncompleteSession = true;
        for (const key of keys)
            incompleteIdentityKeys.add(key);
    }
    for (const plan of context.plans) {
        if (context.incompleteRetainedSessions.length > 0) {
            plan.preserveAll =
                hasUnidentifiableIncompleteSession ||
                    plan.archivedIdentityKeys.size === 0 ||
                    [...plan.archivedIdentityKeys].some(key => incompleteIdentityKeys.has(key));
        }
        for (const retained of plan.retainedSessions) {
            plan.transfers.push({ path: retained.path, identities: await identitiesFor(retained) });
        }
    }
}
/**
 * Rekey copied entry rows to the newest retained lineage peer before pruning.
 * The retained file's own offset is never rewritten: it already describes that
 * file's byte position, while every archived historical offset is deleted.
 */
function reconcileStatsRowsForSessions(dbPath, plans) {
    if (plans.length === 0)
        return 0;
    const db = new Database(dbPath);
    try {
        const env_5 = { stack: [], error: void 0, hasError: false };
        try {
            db.run("PRAGMA busy_timeout = 5000");
            const sessionTables = STATS_SESSION_TABLES.filter(table => tableExists(db, table) && tableHasColumn(db, table, "session_file"));
            const entryTables = STATS_ENTRY_TABLES.filter(table => sessionTables.includes(table) &&
                STATS_IDENTITY_COLUMNS[table].every(column => tableHasColumn(db, table, column)));
            db.run(`
			CREATE TEMP TABLE gc_retained_entries (
				table_name TEXT NOT NULL,
				entry_id TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				tool_call_id TEXT NOT NULL,
				target_session_file TEXT NOT NULL,
				PRIMARY KEY (table_name, entry_id, timestamp, tool_call_id)
			)
		`);
            const statements = __addDisposableResource(env_5, new DisposableStack(), false);
            const clearRetainedEntries = statements.use(db.prepare("DELETE FROM gc_retained_entries"));
            const insertRetainedEntry = statements.use(db.prepare(`
			INSERT OR IGNORE INTO gc_retained_entries (
				table_name, entry_id, timestamp, tool_call_id, target_session_file
			) VALUES (?, ?, ?, ?, ?)
		`));
            const transferStatements = entryTables.map(table => {
                const toolCallMatch = table === "tool_calls" ? `retained.tool_call_id = ${table}.tool_call_id` : "retained.tool_call_id = ''";
                const identityMatch = `
				retained.table_name = '${table}'
				AND retained.entry_id = ${table}.entry_id
				AND retained.timestamp = ${table}.timestamp
				AND ${toolCallMatch}
			`;
                return statements.use(db.prepare(`
				UPDATE OR IGNORE ${table}
				SET session_file = (
					SELECT retained.target_session_file
					FROM gc_retained_entries AS retained
					WHERE ${identityMatch}
				)
				WHERE session_file = ?
					AND EXISTS (
						SELECT 1
						FROM gc_retained_entries AS retained
						WHERE ${identityMatch}
					)
			`));
            });
            const deletionStatements = sessionTables.map(table => ({
                table,
                statement: statements.use(db.prepare(`DELETE FROM ${table} WHERE session_file = ? OR instr(session_file, ?) = 1`)),
            }));
            let deleted = 0;
            const tx = db.transaction((cleanupPlans) => {
                for (const plan of cleanupPlans) {
                    if (plan.preserveAll)
                        continue;
                    clearRetainedEntries.run();
                    for (const target of plan.transfers) {
                        for (const table of entryTables) {
                            for (const identity of target.identities[table]) {
                                insertRetainedEntry.run(table, identity.entryId, identity.timestamp, identity.toolCallId, target.path);
                            }
                        }
                    }
                    for (const sessionPath of new Set(plan.sessionPaths)) {
                        for (const statement of transferStatements)
                            statement.run(sessionPath);
                    }
                    for (const sessionPath of new Set(plan.sessionPaths)) {
                        const nestedPrefix = `${sessionArtifactsPath(sessionPath)}${path.sep}`;
                        for (const { table, statement } of deletionStatements) {
                            const requiresTransfer = plan.retainedSessions.length > 0 &&
                                table !== "file_offsets" &&
                                !entryTables.some(entryTable => entryTable === table);
                            if (requiresTransfer)
                                continue;
                            const result = statement.run(sessionPath, nestedPrefix);
                            deleted += sqliteNumber(result.changes);
                        }
                    }
                }
            });
            tx(plans);
            return deleted;
        }
        catch (e_5) {
            env_5.error = e_5;
            env_5.hasError = true;
        }
        finally {
            __disposeResources(env_5);
        }
    }
    finally {
        db.close();
    }
}
async function collectArchivedStatsSessions(archiveRoot, sessionsRoot, onError) {
    const sessions = [];
    for (const file of await collectCompressedJsonlFiles(archiveRoot)) {
        const relative = path.relative(archiveRoot, file);
        if (!relative || relative.startsWith("..") || path.isAbsolute(relative))
            continue;
        const sourcePath = path.join(sessionsRoot, relative.slice(0, -".gz".length));
        try {
            const identities = createStatsIdentities();
            const header = await scanArchivedSession(file, identities);
            if (!header)
                throw new Error("archive is missing a valid session header");
            sessions.push({
                path: sourcePath,
                id: header.id,
                parentSession: header.parentSession,
                historicalPaths: managedHistoricalSessionPaths(header, sourcePath, sessionsRoot),
                identities,
            });
        }
        catch (error) {
            onError(file, error);
        }
    }
    return sessions;
}
function statsDbPath(options) {
    return path.resolve(options.agentDir) === path.resolve(getAgentDir())
        ? getStatsDbPath()
        : path.join(options.agentDir, "stats.db");
}
async function cleanupStatsRowsForArchivedSessions(options, archiveRoot, newlyArchivedSessions, result) {
    const dbPath = statsDbPath(options);
    if (!(await pathExists(dbPath)))
        return;
    const sessionsRoot = getSessionsDir(options.agentDir);
    const archivedByPath = new Map();
    for (const session of newlyArchivedSessions) {
        archivedByPath.set(path.resolve(session.path), {
            path: session.path,
            id: session.id,
            parentSession: session.parentSessionPath,
            historicalPaths: [],
            identities: createStatsIdentities(),
        });
    }
    let retainedSessions;
    try {
        for (const session of await collectArchivedStatsSessions(archiveRoot, sessionsRoot, (file, error) => {
            result.errors.push(`stats cleanup scan ${file}: ${errorMessage(error)}`);
        })) {
            archivedByPath.set(path.resolve(session.path), session);
        }
    }
    catch (error) {
        result.errors.push(`stats cleanup scan: ${errorMessage(error)}`);
    }
    try {
        retainedSessions = await listActiveSessions(sessionsRoot);
    }
    catch (error) {
        result.errors.push(`stats cleanup scan: ${errorMessage(error)}`);
        return;
    }
    try {
        await withStatsSyncLock(dbPath, async () => {
            const retainedStatsSessions = await Promise.all(retainedSessions.map(async (session) => {
                const header = await readSessionLineageHeader(session.path);
                if (!header || header.id !== session.id) {
                    throw new Error(`session header changed during stats cleanup: ${session.path}`);
                }
                return {
                    path: session.path,
                    id: session.id,
                    parentSession: header.parentSession,
                    historicalPaths: managedHistoricalSessionPaths(header, session.path, sessionsRoot),
                    identities: createStatsIdentities(),
                };
            }));
            const context = buildStatsCleanupPlans([...archivedByPath.values()], retainedStatsSessions, dbPath);
            await populateStatsTransferTargets(context);
            result.statsRowsDeleted = reconcileStatsRowsForSessions(dbPath, context.plans);
        });
    }
    catch (error) {
        result.errors.push(`stats cleanup: ${errorMessage(error)}`);
    }
}
/**
 * Staging temps ({@link SESSION_STAGING_RE}) of `.jsonl` transcripts under
 * `sessionsRoot`, plus those beside exact session files recorded elsewhere
 * (`--session` paths, collab replicas).
 */
async function collectSessionStagingFiles(sessionsRoot, exactSessionFiles) {
    const files = new Map();
    try {
        for await (const name of SESSION_STAGING_GLOB.scan({ cwd: sessionsRoot, dot: true })) {
            if (!SESSION_STAGING_RE.exec(path.basename(name))?.[1]?.endsWith(SESSION_SUFFIX))
                continue;
            const file = path.join(sessionsRoot, name);
            files.set(normalizePathForComparison(file), file);
        }
    }
    catch (error) {
        if (codeOf(error) !== "ENOENT")
            throw error;
    }
    for (const sessionFile of exactSessionFiles) {
        const target = path.basename(sessionFile);
        for (const file of await listFilesIfPresent(path.dirname(sessionFile))) {
            if (SESSION_STAGING_RE.exec(path.basename(file))?.[1] === target) {
                files.set(normalizePathForComparison(file), file);
            }
        }
    }
    return [...files.values()];
}
/**
 * Count, and with `--apply` delete, session staging temps past the write
 * grace. A live publish renames its temp away within milliseconds, so an
 * older one was left by a killed or crashed writer and nothing will claim it.
 */
async function sweepSessionStagingFiles(options, sessionsRoot, registeredSessionPaths, result) {
    const exactSessionFiles = [
        ...registeredSessionPaths,
        ...(await collectBreadcrumbSessionFiles(getTerminalSessionsDir(options.agentDir))),
    ];
    const deleteBeforeMs = Date.now() - GC_WRITE_GRACE_MS;
    for (const file of await collectSessionStagingFiles(sessionsRoot, exactSessionFiles)) {
        const stat = await statIfPresent(file);
        if (!stat?.isFile() || stat.mtimeMs > deleteBeforeMs)
            continue;
        result.wouldDeleteTemps += 1;
        result.tempBytes += stat.size;
        if (!options.apply)
            continue;
        try {
            await fs.unlink(file);
            result.deletedTemps += 1;
        }
        catch (error) {
            if (codeOf(error) !== "ENOENT")
                result.errors.push(`${file}: ${errorMessage(error)}`);
        }
    }
}
async function runArchiveGc(options, archiveRoot, registeredSessionPaths) {
    const sessionsRoot = getSessionsDir(options.agentDir);
    const sessions = await listActiveSessions(sessionsRoot);
    const cutoffMs = Date.now() - options.coldArchiveAfterDays * DAY_MS;
    const result = {
        scanned: sessions.length,
        skippedActive: 0,
        keptNewestGlobal: 0,
        keptNewestPerCwd: 0,
        wouldArchive: 0,
        archived: 0,
        historyRowsDeleted: 0,
        statsRowsDeleted: 0,
        ftsRebuilt: false,
        wouldDeleteTemps: 0,
        deletedTemps: 0,
        tempBytes: 0,
        errors: [],
    };
    const candidates = [];
    let inactiveSeen = 0;
    const inactiveSeenByCwd = new Map();
    const archiveBeforeMs = Date.now() - GC_WRITE_GRACE_MS;
    for (const session of sessions) {
        if (session.status && ACTIVE_STATUSES.has(session.status)) {
            result.skippedActive += 1;
            continue;
        }
        if (session.modified.getTime() > archiveBeforeMs) {
            result.skippedActive += 1;
            continue;
        }
        if (await hasLiveNestedSessions(session, archiveBeforeMs)) {
            result.skippedActive += 1;
            continue;
        }
        const cwdKey = sessionCwdKey(sessionsRoot, session);
        const cwdSeen = inactiveSeenByCwd.get(cwdKey) ?? 0;
        const keepGlobal = inactiveSeen < options.retainNewestGlobal;
        const keepPerCwd = cwdSeen < options.retainNewestPerCwd;
        inactiveSeen += 1;
        inactiveSeenByCwd.set(cwdKey, cwdSeen + 1);
        if (keepGlobal) {
            result.keptNewestGlobal += 1;
            continue;
        }
        if (keepPerCwd) {
            result.keptNewestPerCwd += 1;
            continue;
        }
        if (options.coldArchiveAfterDays > 0 && session.modified.getTime() > cutoffMs)
            continue;
        const destination = archiveDestination(archiveRoot, sessionsRoot, session);
        if (!destination)
            continue;
        candidates.push({ ...destination, session });
    }
    result.wouldArchive = candidates.length;
    // Before archiving moves transcripts away from the temps staged beside them.
    await sweepSessionStagingFiles(options, sessionsRoot, registeredSessionPaths, result);
    if (!options.apply)
        return result;
    const archivedSessionIds = [];
    const archivedSessions = [];
    for (const candidate of candidates) {
        try {
            await moveSessionWithArtifacts(candidate);
            result.archived += 1;
            archivedSessionIds.push(candidate.session.id);
            archivedSessions.push(candidate.session);
        }
        catch (error) {
            result.errors.push(`${candidate.session.path}: ${errorMessage(error)}`);
        }
    }
    await cleanupHistoryRowsForArchivedSessions(options, archiveRoot, archivedSessionIds, result);
    await cleanupStatsRowsForArchivedSessions(options, archiveRoot, archivedSessions, result);
    return result;
}
/** Every file of a session: its transcript plus its artifact tree (subagent transcripts, tool output). */
async function collectSessionFiles(session) {
    const artifactsDir = sessionArtifactsPath(session.path);
    const files = [session.path];
    try {
        for await (const name of ANY_FILE_GLOB.scan({ cwd: artifactsDir, dot: true, onlyFiles: true })) {
            if (isCompressScratchPath(name))
                continue;
            files.push(path.join(artifactsDir, name));
        }
    }
    catch (error) {
        if (codeOf(error) !== "ENOENT")
            throw error;
    }
    return files;
}
/**
 * Session id in `file`'s header, or undefined when it has none. A file is
 * streamed only when its first byte past JSON whitespace opens a record (the
 * header or the title slot before it), or when its sampled prefix is all
 * whitespace; other binary and plain-text artifacts cost one small read.
 */
async function readArtifactSessionId(file) {
    const prefix = (await Bun.file(file).slice(0, HEADER_SNIFF_BYTES).text()).replace(/^[ \t\r\n]+/, "");
    if (prefix !== "" && prefix[0] !== "{")
        return undefined;
    return readSessionHeaderId(file);
}
/**
 * Leases of every transcript in a session: its own and those nested in its
 * artifact tree (subagent sessions, or any file a process can open with
 * `--session`), found by their session header rather than their name. Each
 * session id is leased once, so a copied transcript that shares an id does
 * not read as live. Null, with every lease taken so far released, when any of
 * them is live or cannot be probed (an unknown owner counts as live).
 */
async function tryAcquireSessionTreeLeases(session, files) {
    const leases = [];
    const leasedIds = new Set();
    const transcripts = new Set([session.path]);
    for (const file of files) {
        let lease;
        try {
            const sessionId = await readArtifactSessionId(file);
            if (sessionId === undefined)
                continue;
            transcripts.add(file);
            if (leasedIds.has(sessionId))
                continue;
            lease = tryAcquireSessionLease(sessionId);
            if (lease)
                leasedIds.add(sessionId);
        }
        catch (error) {
            if (codeOf(error) === "ENOENT")
                continue;
            lease = null;
        }
        if (lease === null) {
            for (const held of leases)
                held.release();
            return null;
        }
        leases.push(lease);
    }
    return { leases, transcripts };
}
/**
 * Store idle sessions compressed in place. A session qualifies once its
 * transcript is `compressAfterDays` old and no running process holds its
 * ownership lease; files written more recently than that are left alone.
 * Unlike archiving, an interrupted last turn does not exclude a session:
 * paths, bytes, and mtimes are unchanged and no history or stats rows are
 * deleted, so it stays resumable. Leftover scratch directories from a killed
 * run are removed first. A session that fails is reported and skipped.
 */
async function runCompressGc(options, archiveRoot) {
    const sessionsRoot = getSessionsDir(options.agentDir);
    const method = await compressMethod(sessionsRoot);
    const result = {
        supported: method !== undefined,
        method,
        scanned: 0,
        skippedLive: 0,
        sessions: 0,
        wouldCompress: 0,
        compressed: 0,
        bytes: 0,
        allocatedBefore: 0,
        allocatedAfter: 0,
        leftoverScratchDirs: 0,
        errors: [],
    };
    if (method === undefined)
        return result;
    if (method === "apfs") {
        // Only the APFS copy-and-swap uses scratch directories. Archiving can carry a
        // leftover inside an artifact tree into the archive root.
        result.leftoverScratchDirs = await sweepCompressScratch([sessionsRoot, archiveRoot], options.apply, result.errors);
    }
    const sessions = await listActiveSessions(sessionsRoot);
    result.scanned = sessions.length;
    const cutoffMs = Date.now() - Math.max(options.compressAfterDays * DAY_MS, GC_WRITE_GRACE_MS);
    for (const session of sessions) {
        if (session.modified.getTime() > cutoffMs)
            continue;
        let files;
        try {
            files = await collectSessionFiles(session);
        }
        catch (error) {
            result.errors.push(`${session.path}: ${errorMessage(error)}`);
            continue;
        }
        const candidates = [];
        for (const file of files) {
            try {
                const candidate = await compressCandidate(file);
                if (candidate && candidate.mtimeMs <= cutoffMs)
                    candidates.push(candidate);
            }
            catch (error) {
                if (codeOf(error) !== "ENOENT")
                    result.errors.push(`${file}: ${errorMessage(error)}`);
            }
        }
        if (candidates.length === 0)
            continue;
        let tree = null;
        try {
            tree = await tryAcquireSessionTreeLeases(session, files);
            if (tree === null) {
                result.skippedLive += 1;
                continue;
            }
            result.sessions += 1;
            result.wouldCompress += candidates.length;
            for (const candidate of candidates) {
                result.bytes += candidate.bytes;
                result.allocatedBefore += candidate.allocated;
            }
            if (!options.apply)
                continue;
            const batch = await compressFilesInPlace(candidates, method, tree.transcripts);
            result.compressed += batch.compressed;
            result.allocatedAfter += batch.allocatedAfter;
            result.errors.push(...batch.errors);
        }
        catch (error) {
            result.errors.push(`${session.path}: ${errorMessage(error)}`);
        }
        finally {
            // Held through the rewrite so no omp process resumes the session mid-swap.
            for (const held of tree?.leases ?? [])
                held.release();
        }
    }
    return result;
}
async function checkpointWal(dbPath, apply) {
    const walPath = `${dbPath}-wal`;
    let walBytes = 0;
    try {
        walBytes = (await fs.stat(walPath)).size;
    }
    catch (error) {
        if (codeOf(error) !== "ENOENT")
            throw error;
    }
    const result = {
        dbPath,
        walBytes,
        wouldCheckpoint: walBytes > 0,
        checkpointed: false,
        busy: 0,
        log: 0,
        checkpointedFrames: 0,
    };
    if (!apply || !(await pathExists(dbPath)))
        return result;
    const db = new Database(dbPath);
    let checkpointAttempted = false;
    try {
        const env_6 = { stack: [], error: void 0, hasError: false };
        try {
            db.run("PRAGMA busy_timeout = 5000");
            const checkpointStmt = __addDisposableResource(env_6, db.prepare("PRAGMA wal_checkpoint(TRUNCATE)"), false);
            const row = checkpointStmt.get();
            checkpointAttempted = true;
            result.busy = sqliteNumber(row?.busy);
            result.log = sqliteNumber(row?.log);
            result.checkpointedFrames = sqliteNumber(row?.checkpointed);
        }
        catch (e_6) {
            env_6.error = e_6;
            env_6.hasError = true;
        }
        finally {
            __disposeResources(env_6);
        }
    }
    finally {
        db.close();
    }
    try {
        result.walBytes = (await fs.stat(walPath)).size;
    }
    catch (error) {
        if (codeOf(error) !== "ENOENT")
            throw error;
        result.walBytes = 0;
    }
    if (checkpointAttempted && (result.busy > 0 || result.walBytes > 0)) {
        throw new Error(`WAL checkpoint failed for ${dbPath}: busy=${result.busy}, walBytes=${result.walBytes}`);
    }
    result.checkpointed = checkpointAttempted;
    return result;
}
async function runWalGc(options) {
    const databases = await Promise.all([getHistoryDbPath(options.agentDir), getModelDbPath(options.agentDir)].map(dbPath => checkpointWal(dbPath, options.apply)));
    return {
        databases,
        walBytes: databases.reduce((total, db) => total + db.walBytes, 0),
        wouldCheckpoint: databases.some(db => db.wouldCheckpoint),
        checkpointed: databases.some(db => db.checkpointed),
    };
}
function gcLockPid(lockText) {
    const pid = Number.parseInt(lockText.split(/\r?\n/, 1)[0] ?? "", 10);
    return Number.isSafeInteger(pid) && pid > 0 ? pid : undefined;
}
function processExists(pid) {
    try {
        process.kill(pid, 0);
        return true;
    }
    catch (error) {
        const code = codeOf(error);
        if (code === "ESRCH" || code === "EINVAL")
            return false;
        return true;
    }
}
function gcLockStatSnapshot(stat) {
    return {
        dev: stat.dev,
        ino: stat.ino,
        size: stat.size,
        mtimeMs: stat.mtimeMs,
        ctimeMs: stat.ctimeMs,
    };
}
function sameGcLockStat(left, right) {
    return (left.dev === right.dev &&
        left.ino === right.ino &&
        left.size === right.size &&
        left.mtimeMs === right.mtimeMs &&
        left.ctimeMs === right.ctimeMs);
}
async function readGcLockSnapshot(lockPath) {
    const stat = await statIfPresent(lockPath);
    if (!stat)
        return null;
    let lockText = "";
    try {
        lockText = await Bun.file(lockPath).text();
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return null;
        throw error;
    }
    const afterStat = await statIfPresent(lockPath);
    if (!afterStat)
        return null;
    const before = gcLockStatSnapshot(stat);
    const after = gcLockStatSnapshot(afterStat);
    if (!sameGcLockStat(before, after))
        return null;
    return { ...after, text: lockText };
}
async function gcLockSnapshotStillCurrent(lockPath, snapshot) {
    const stat = await statIfPresent(lockPath);
    return stat ? sameGcLockStat(snapshot, gcLockStatSnapshot(stat)) : false;
}
function shouldBreakGcLock(snapshot) {
    const pid = gcLockPid(snapshot.text);
    if (pid)
        return !processExists(pid);
    const createdAtMs = Date.parse(snapshot.text.split(/\r?\n/, 2)[1] ?? "");
    const ageFromMs = Number.isFinite(createdAtMs) ? createdAtMs : snapshot.mtimeMs;
    return Date.now() - ageFromMs > GC_WRITE_GRACE_MS;
}
async function removeStaleGcLock(lockPath) {
    const snapshot = await readGcLockSnapshot(lockPath);
    if (!snapshot)
        return false;
    if (!shouldBreakGcLock(snapshot))
        return false;
    if (!(await gcLockSnapshotStillCurrent(lockPath, snapshot)))
        return false;
    try {
        await fs.unlink(lockPath);
        return true;
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return false;
        throw error;
    }
}
async function openNewGcLock(lockPath) {
    try {
        return await fs.open(lockPath, "wx");
    }
    catch (error) {
        if (codeOf(error) === "EEXIST")
            return null;
        throw error;
    }
}
async function releaseGcLockFile(lockPath, handle) {
    try {
        await handle.close();
    }
    catch {
        // Best effort: stale sidecar locks are recoverable by PID/timestamp.
    }
    try {
        await fs.unlink(lockPath);
    }
    catch (error) {
        if (codeOf(error) === "ENOENT")
            return;
    }
}
async function openGcBreakerLock(lockPath) {
    const breakerPath = `${lockPath}${GC_LOCK_BREAKER_SUFFIX}`;
    for (let attempt = 0; attempt < 2; attempt += 1) {
        const handle = await openNewGcLock(breakerPath);
        if (handle) {
            try {
                await handle.writeFile(`${process.pid}\n${new Date().toISOString()}\n`);
                return { path: breakerPath, handle };
            }
            catch (error) {
                await releaseGcLockFile(breakerPath, handle);
                throw error;
            }
        }
        if (!(await removeStaleGcLock(breakerPath)))
            throw new Error(`GC already running: ${lockPath}`);
    }
    throw new Error(`GC already running: ${lockPath}`);
}
async function openGcLock(lockPath) {
    const direct = await openNewGcLock(lockPath);
    if (direct)
        return direct;
    const breaker = await openGcBreakerLock(lockPath);
    try {
        const raced = await openNewGcLock(lockPath);
        if (raced)
            return raced;
        if (!(await removeStaleGcLock(lockPath)))
            throw new Error(`GC already running: ${lockPath}`);
        const takeover = await openNewGcLock(lockPath);
        if (takeover)
            return takeover;
        throw new Error(`GC already running: ${lockPath}`);
    }
    finally {
        await releaseGcLockFile(breaker.path, breaker.handle);
    }
}
async function withGcLock(agentDir, fn) {
    const lockPath = path.join(agentDir, "gc.lock");
    await fs.mkdir(agentDir, { recursive: true });
    const handle = await openGcLock(lockPath);
    let result;
    let runError;
    try {
        await handle.writeFile(`${process.pid}\n${new Date().toISOString()}\n`);
        result = await fn(lockPath);
    }
    catch (error) {
        runError = error;
    }
    let closeError;
    try {
        await handle.close();
    }
    catch (error) {
        closeError = error;
    }
    let unlinkError;
    try {
        await fs.unlink(lockPath);
    }
    catch (error) {
        if (codeOf(error) !== "ENOENT")
            unlinkError = error;
    }
    if (runError)
        throw runError;
    if (closeError)
        throw closeError;
    if (unlinkError)
        throw unlinkError;
    return result;
}
function renderText(result) {
    const lines = [`GC ${result.apply ? "applied" : "dry-run"} (${result.agentDir})`];
    if (result.stale) {
        const stale = result.stale;
        lines.push(`stale: ${stale.deleted}/${stale.wouldDelete} entries, ${formatBytes(stale.bytes)} (${stale.danglingMarkers} session markers, ${stale.staleBreadcrumbs} breadcrumbs, ${stale.expiredReports} reports, ${stale.expiredReplicas} collab replicas)`);
        if (stale.errors.length > 0)
            lines.push(`stale errors: ${stale.errors.length}`);
    }
    if (result.blobs) {
        lines.push(`blobs: ${result.blobs.deleted}/${result.blobs.wouldDelete} files, ${formatBytes(result.blobs.bytes)}, ${result.blobs.referenced} refs`);
        if (result.blobs.errors.length > 0)
            lines.push(`blob errors: ${result.blobs.errors.length}`);
    }
    if (result.archive) {
        lines.push(`sessions: ${result.archive.archived}/${result.archive.wouldArchive} archived, ${result.archive.historyRowsDeleted} history rows and ${result.archive.statsRowsDeleted} stats rows removed`);
        if (result.archive.skippedActive > 0)
            lines.push(`sessions skipped active: ${result.archive.skippedActive}`);
        if (result.archive.wouldDeleteTemps > 0) {
            lines.push(`session staging temps: ${result.archive.deletedTemps}/${result.archive.wouldDeleteTemps} files, ${formatBytes(result.archive.tempBytes)}`);
        }
        if (result.archive.errors.length > 0)
            lines.push(`session errors: ${result.archive.errors.length}`);
    }
    if (result.compress) {
        const compress = result.compress;
        if (!compress.supported) {
            lines.push("compress: unsupported on this filesystem (APFS or NTFS only)");
        }
        else {
            const after = result.apply ? `, ${formatBytes(compress.allocatedAfter)} after` : "";
            lines.push(`compress: ${compress.compressed}/${compress.wouldCompress} files in ${compress.sessions} sessions, ${formatBytes(compress.allocatedBefore)} on disk before${after}`);
            if (compress.skippedLive > 0)
                lines.push(`compress skipped live: ${compress.skippedLive}`);
            if (compress.leftoverScratchDirs > 0) {
                const verb = result.apply ? "removed" : "found";
                lines.push(`compress leftover scratch dirs ${verb}: ${compress.leftoverScratchDirs}`);
            }
            if (compress.errors.length > 0)
                lines.push(`compress errors: ${compress.errors.length}`);
        }
    }
    if (result.wal) {
        const state = result.wal.checkpointed ? "checkpointed" : "checkpoint dry-run";
        lines.push(`wal: ${state}, ${formatBytes(result.wal.walBytes)} across ${result.wal.databases.length} dbs`);
    }
    return `${lines.join("\n")}\n`;
}
export async function runGcCommand(args) {
    const options = await resolveOptions(args.flags);
    const archiveRoot = getArchivedSessionsDir(options.agentDir);
    const result = await withGcLock(options.agentDir, async (lockPath) => {
        const next = { agentDir: options.agentDir, apply: options.apply, lockPath };
        // Stale cleanup may prune a missing first-save target's registry marker.
        const registeredSessionPaths = options.runArchive
            ? await collectRegisteredSessionPaths(getCustomSessionFilesDir(options.agentDir))
            : [];
        // Pruned collab replicas release their blobs to this run's sweep.
        if (options.runStale)
            next.stale = await runStaleGc(options);
        if (options.runBlobs)
            next.blobs = await runBlobGc(options, archiveRoot);
        if (options.runArchive)
            next.archive = await runArchiveGc(options, archiveRoot, registeredSessionPaths);
        if (options.runCompress)
            next.compress = await runCompressGc(options, archiveRoot);
        if (options.runWal)
            next.wal = await runWalGc(options);
        return next;
    });
    const output = options.json ? `${JSON.stringify(result, null, 2)}\n` : renderText(result);
    process.stdout.write(output);
    return result;
}
