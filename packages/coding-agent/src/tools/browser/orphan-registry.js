/**
 * Durable ownership registry for targets in the project-shared broker-owned
 * Chromium (`omp.browser.headless`/`omp.browser.headed`).
 *
 * The shared browser outlives any single omp process, but tab ownership is
 * otherwise tracked only in that process's memory (`tab-supervisor`'s `tabs`
 * map). When a session ends abnormally (crash, SIGKILL, cleanup timeout) its
 * in-process map dies with it and the pages it opened stay open in the shared
 * Chromium forever, accumulating into multi-GB orphan targets (issue #10022).
 *
 * This module records, on disk under the broker runtime dir, which OS process
 * created each shared-browser page target. Any live omp process can then reap
 * targets whose owning process is gone. It only ever touches OMP-owned
 * shared-browser targets — user-owned connected/relay/spawned browsers have no
 * registry and are never scanned.
 *
 * Ownership is authoritative in the safe direction: a target is reaped only
 * when its owner PID reports `ESRCH` (definitively dead). A live PID is never
 * reaped, so a live session's tabs cannot be yanked out from under it; the
 * worst case (recycled PID) leaves an orphan uncollected rather than closing a
 * live page.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { isEnoent, logger } from "@rva/utils";
import { daemonRuntimeDir } from "../../launch/paths";
/**
 * Reap only records whose owner has been dead AND untouched for this long.
 * The PID probe is already authoritative; the grace window is a conservative
 * guard against clock skew and PID reuse races, and keeps a just-crashed
 * process's very fresh records around briefly in case it is being restarted.
 */
const DEFAULT_GRACE_MS = 15000;
/** In-process set of shared-browser targets this process created, keyed by registry dir. */
const ownedByDir = new Map();
/** Per-registry-dir write serialization so concurrent record/forget can't tear the file. */
const writeChains = new Map();
function registryDir(scope) {
    return path.join(daemonRuntimeDir(scope.projectDir), `${scope.daemonName}.targets`);
}
/** Serialize a write against others for the same registry dir. */
function chain(dir, task) {
    const prev = writeChains.get(dir) ?? Promise.resolve();
    const next = prev.then(task, task);
    writeChains.set(dir, next.catch(() => undefined));
    return next;
}
/** Persist (or, when empty, remove) this process's ownership file for a registry dir. */
async function flush(dir) {
    const owned = ownedByDir.get(dir);
    const file = path.join(dir, `${process.pid}.json`);
    if (!owned || owned.size === 0) {
        await fs.rm(file, { force: true }).catch(() => undefined);
        return;
    }
    const record = { pid: process.pid, updatedAt: Date.now(), targets: [...owned] };
    const tmp = `${file}.${process.pid}.tmp`;
    await fs.mkdir(dir, { recursive: true });
    await Bun.write(tmp, JSON.stringify(record));
    await fs.rename(tmp, file);
}
/** Record that this process created `targetId` in the given shared browser. */
export async function recordSharedTarget(scope, targetId) {
    const dir = registryDir(scope);
    let owned = ownedByDir.get(dir);
    if (!owned) {
        owned = new Set();
        ownedByDir.set(dir, owned);
    }
    owned.add(targetId);
    await chain(dir, () => flush(dir)).catch(err => logger.debug("Failed to record shared-browser target ownership", {
        error: err instanceof Error ? err.message : String(err),
    }));
}
/** Drop `targetId` from this process's ownership file (closed the normal way). */
export async function forgetSharedTarget(scope, targetId) {
    const dir = registryDir(scope);
    const owned = ownedByDir.get(dir);
    if (!owned?.delete(targetId))
        return;
    await chain(dir, () => flush(dir)).catch(err => logger.debug("Failed to update shared-browser target ownership", {
        error: err instanceof Error ? err.message : String(err),
    }));
}
/**
 * Drop every target this process still claims in `scope`. For when the whole
 * shared browser is confirmed gone — the broker reported its daemon in a
 * terminal state after a stop — which takes the targets that could not be
 * closed with it; the records are dead weight that would otherwise be
 * rewritten on every later write until this process exits. Only call this on
 * that confirmation: while the browser lives, the records are the only handle
 * a later reap has on its orphaned targets.
 */
export async function forgetSharedTargets(scope) {
    const dir = registryDir(scope);
    const owned = ownedByDir.get(dir);
    if (!owned || owned.size === 0)
        return;
    owned.clear();
    await chain(dir, () => flush(dir)).catch(err => logger.debug("Failed to clear shared-browser target ownership", {
        error: err instanceof Error ? err.message : String(err),
    }));
}
/** True when `pid` names a live process; non-`ESRCH` probe failures are treated as alive (safe direction). */
function isPidAlive(pid) {
    try {
        process.kill(pid, 0);
        return true;
    }
    catch (error) {
        return error.code !== "ESRCH";
    }
}
/**
 * Scan a registry dir for targets whose owning process is gone. Returns one
 * entry per dead owner so a reaper can retain only targets whose CDP closure
 * was not confirmed. This process's own file and every live-owner file are
 * left untouched.
 */
export async function collectOrphanTargets(scope, opts = {}) {
    const now = opts.now ?? Date.now;
    const isAlive = opts.isAlive ?? isPidAlive;
    const graceMs = opts.graceMs ?? DEFAULT_GRACE_MS;
    const dir = registryDir(scope);
    let entries;
    try {
        entries = await fs.readdir(dir);
    }
    catch (err) {
        if (isEnoent(err))
            return { owners: [] };
        throw err;
    }
    const owners = [];
    const nowMs = now();
    for (const entry of entries) {
        if (!entry.endsWith(".json"))
            continue;
        const file = path.join(dir, entry);
        let record;
        try {
            record = (await Bun.file(file).json());
        }
        catch {
            continue; // torn or malformed file; a live owner will rewrite it
        }
        if (typeof record?.pid !== "number" || !Array.isArray(record.targets))
            continue;
        if (record.pid === process.pid)
            continue; // our own file
        if (isAlive(record.pid))
            continue; // owner still running
        if (nowMs - (record.updatedAt ?? 0) < graceMs)
            continue; // conservative grace
        owners.push({
            file,
            pid: record.pid,
            updatedAt: record.updatedAt,
            targetIds: record.targets.filter(id => typeof id === "string"),
        });
    }
    return { owners };
}
/**
 * Close a page target by id through a fresh CDP session. Returns true only
 * when CDP confirms the close or confirms the target no longer exists; a
 * dropped connection or transient protocol failure returns false so durable
 * ownership remains available for a later retry.
 */
export async function closeCdpTarget(browser, targetId) {
    const session = await browser
        .target()
        .createCDPSession()
        .catch(() => null);
    if (!session)
        return false;
    try {
        try {
            const result = await session.send("Target.closeTarget", { targetId });
            if (result.success)
                return true;
        }
        catch {
            // A concurrent reaper or the page itself may already have closed the
            // target. Confirm absence before treating the cleanup as complete.
        }
        try {
            const { targetInfos } = await session.send("Target.getTargets");
            return !targetInfos.some(info => info.targetId === targetId);
        }
        catch {
            return false;
        }
    }
    finally {
        await session.detach().catch(() => undefined);
    }
}
/** Atomically retain unresolved targets, or remove an ownership file once all are resolved. */
async function updateOwnershipFile(owner, targetIds) {
    if (targetIds.length === 0) {
        await fs.rm(owner.file, { force: true });
        return;
    }
    const tmp = `${owner.file}.${process.pid}.tmp`;
    try {
        const record = { pid: owner.pid, updatedAt: owner.updatedAt, targets: targetIds };
        await Bun.write(tmp, JSON.stringify(record));
        await fs.rename(tmp, owner.file);
    }
    catch (error) {
        await fs.rm(tmp, { force: true }).catch(() => undefined);
        throw error;
    }
}
/**
 * Reap shared-browser targets whose owning omp process is gone. Each owner
 * file is removed only after every target is confirmed closed/absent; partial
 * failures atomically retain the unresolved ids for the next attach to retry.
 * Failures are logged, never thrown, so cleanup cannot block browser open.
 */
export async function reapOrphanSharedTargets(browser, scope) {
    let scan;
    try {
        scan = await collectOrphanTargets(scope);
    }
    catch (err) {
        logger.debug("Failed to scan shared-browser target registry", {
            error: err instanceof Error ? err.message : String(err),
        });
        return 0;
    }
    let closed = 0;
    for (const owner of scan.owners) {
        const retained = [];
        for (const targetId of owner.targetIds) {
            if (await closeCdpTarget(browser, targetId)) {
                closed++;
            }
            else {
                retained.push(targetId);
                logger.debug("Retaining orphaned shared-browser target for retry", { targetId, ownerPid: owner.pid });
            }
        }
        if (retained.length === owner.targetIds.length)
            continue;
        try {
            await updateOwnershipFile(owner, retained);
        }
        catch (err) {
            logger.debug("Failed to update shared-browser ownership after reap", {
                ownerPid: owner.pid,
                error: err instanceof Error ? err.message : String(err),
            });
        }
    }
    if (closed > 0)
        logger.debug("Reaped orphaned shared-browser targets", { count: closed, daemon: scope.daemonName });
    return closed;
}
/** Test-only reset of the in-process ownership state. */
export function resetOrphanRegistryForTest() {
    ownedByDir.clear();
    writeChains.clear();
}
