import * as path from "node:path";
import { getRemoteDir } from "@rva/utils";
import { findUniqueWorkspaceSuffix } from "./path-utils";
// Remote mount path prefix (sshfs mounts) - skip fuzzy matching to avoid hangs
const REMOTE_MOUNT_PREFIX = getRemoteDir() + path.sep;
export function isRemoteMountPath(absolutePath) {
    return absolutePath.startsWith(REMOTE_MOUNT_PREFIX);
}
export function isNotFoundError(error) {
    if (!error || typeof error !== "object")
        return false;
    const code = error.code;
    return code === "ENOENT" || code === "ENOTDIR";
}
/**
 * Memoized {@link findUniqueWorkspaceSuffix} for a single read call. A missing
 * path with archive/sqlite extensions probes the workspace once per stage
 * (archive candidates, sqlite candidates, plain path) — each glob carries a
 * 5s timeout, so repeated lookups of the same string stack into a long
 * stall before erroring. The cache collapses repeats within one execute().
 */
export async function findSuffixMatchCached(session, cache, rawPath, signal) {
    const hit = cache.get(rawPath);
    if (hit !== undefined)
        return hit;
    const result = await findUniqueWorkspaceSuffix(rawPath, session.cwd, signal);
    cache.set(rawPath, result);
    return result;
}
