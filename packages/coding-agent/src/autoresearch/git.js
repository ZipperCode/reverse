import * as vcs from "@rva/natives/vcs";
import { slugify } from "@rva/utils";
import { normalizePathSpec } from "./helpers";
const AUTORESEARCH_BRANCH_PREFIX = "autoresearch/";
const BRANCH_NAME_MAX_LENGTH = 48;
export async function getCurrentAutoresearchBranch(_api, workDir) {
    const currentBranch = (await vcs.git(workDir)?.currentBranch()) ?? "";
    return currentBranch.startsWith(AUTORESEARCH_BRANCH_PREFIX) ? currentBranch : null;
}
/**
 * Ensure the working tree is on an `autoresearch/*` branch when possible.
 *
 * If the worktree is dirty and we're not already on an autoresearch branch, this returns
 * `{ ok: true, branchName: null, warning }` rather than failing. The caller surfaces the
 * warning and continues on the current branch — `keep` will skip auto-commits and `discard`
 * will revert only run-modified paths instead of resetting to baseline.
 */
export async function ensureAutoresearchBranch(api, workDir, goal) {
    // Pure-jj check runs first so a jj workspace nested under an unrelated
    // outer Git checkout is rejected at its own root rather than silently
    // creating `autoresearch/*` branches and commits in the surrounding Git
    // tree behind jj's back.
    if (vcs.isPureJj(workDir)) {
        return {
            ok: false,
            error: "Autoresearch needs a Git checkout for branch isolation and baseline commits, but this workspace is pure Jujutsu (`.jj/` without a colocated `.git/`). Run `jj git init --colocate` to add a Git checkout before starting autoresearch.",
        };
    }
    const repository = vcs.git(workDir);
    if (!repository) {
        return {
            ok: true,
            branchName: null,
            created: false,
            warning: "Not in a git repository — autoresearch will run without branch isolation, baseline reset, or auto-commits.",
        };
    }
    let dirtyPathsOutput;
    try {
        dirtyPathsOutput = await repository.statusPorcelain({ untracked: "all", nulTerminated: true });
    }
    catch (err) {
        return {
            ok: false,
            error: `Unable to inspect git status before starting autoresearch: ${err instanceof Error ? err.message : String(err)}`,
        };
    }
    const workDirPrefix = await readGitWorkDirPrefix(api, workDir);
    const dirtyPaths = collectRelativeDirtyPaths(dirtyPathsOutput, workDirPrefix);
    const branch = (await repository.currentBranch()) ?? "";
    const currentBranch = branch.startsWith(AUTORESEARCH_BRANCH_PREFIX) ? branch : null;
    if (currentBranch) {
        return { ok: true, branchName: currentBranch, created: false };
    }
    if (dirtyPaths.length > 0) {
        const preview = formatDirtyPaths(dirtyPaths);
        return {
            ok: false,
            error: `Worktree is dirty (${preview}). Commit or stash these changes before starting autoresearch — a fresh autoresearch/* branch needs a clean baseline.`,
        };
    }
    const branchName = await allocateBranchName(repository, goal);
    try {
        await repository.checkoutNewBranch(branchName);
    }
    catch (err) {
        return {
            ok: false,
            error: `Failed to create autoresearch branch ${branchName}: ${err instanceof Error ? err.message : String(err)}`,
        };
    }
    return { ok: true, branchName, created: true };
}
export function parseWorkDirDirtyPaths(statusOutput, workDirPrefix) {
    const relativePaths = [];
    for (const dirtyPath of parseDirtyPaths(statusOutput)) {
        const relativePath = relativizeGitPathToWorkDir(dirtyPath, workDirPrefix);
        if (relativePath === null)
            continue;
        relativePaths.push(relativePath);
    }
    return relativePaths;
}
export function relativizeGitPathToWorkDir(repoRelativePath, workDirPrefix) {
    const normalizedPath = normalizeStatusPath(repoRelativePath);
    const normalizedPrefix = normalizePathSpec(workDirPrefix);
    if (normalizedPrefix === "" || normalizedPrefix === ".") {
        return normalizedPath;
    }
    if (normalizedPath === normalizedPrefix) {
        return ".";
    }
    if (!normalizedPath.startsWith(`${normalizedPrefix}/`)) {
        return null;
    }
    return normalizePathSpec(normalizedPath.slice(normalizedPrefix.length + 1));
}
async function readGitWorkDirPrefix(api, workDir) {
    void api;
    try {
        return vcs.requireGit(workDir).prefixOf(workDir) ?? "";
    }
    catch {
        return "";
    }
}
export function parseDirtyPaths(statusOutput) {
    if (statusOutput.includes("\0")) {
        return parseDirtyPathsNul(statusOutput);
    }
    return parseDirtyPathsLines(statusOutput);
}
function parseDirtyPathsNul(statusOutput) {
    const unsafePaths = new Set();
    let index = 0;
    while (index + 3 <= statusOutput.length) {
        const statusToken = statusOutput.slice(index, index + 3);
        index += 3;
        const pathEnd = statusOutput.indexOf("\0", index);
        if (pathEnd < 0)
            break;
        const firstPath = statusOutput.slice(index, pathEnd);
        index = pathEnd + 1;
        addDirtyPath(unsafePaths, firstPath);
        if (isRenameOrCopy(statusToken)) {
            const secondPathEnd = statusOutput.indexOf("\0", index);
            if (secondPathEnd < 0)
                break;
            const secondPath = statusOutput.slice(index, secondPathEnd);
            index = secondPathEnd + 1;
            addDirtyPath(unsafePaths, secondPath);
        }
    }
    return [...unsafePaths];
}
function parseDirtyPathsLines(statusOutput) {
    const unsafePaths = new Set();
    for (const line of statusOutput.split("\n")) {
        const trimmedLine = line.trimEnd();
        if (trimmedLine.length < 4)
            continue;
        const rawPath = trimmedLine.slice(3).trim();
        if (rawPath.length === 0)
            continue;
        const renameParts = rawPath.split(" -> ");
        for (const renamePart of renameParts) {
            addDirtyPath(unsafePaths, renamePart);
        }
    }
    return [...unsafePaths];
}
export function normalizeStatusPath(rawPath) {
    let normalized = rawPath.trim();
    if (normalized.startsWith('"') && normalized.endsWith('"')) {
        normalized = normalized.slice(1, -1);
    }
    return normalizePathSpec(normalized);
}
async function allocateBranchName(repository, goal) {
    const goalSlug = slugify(goal ?? "", { maxLength: BRANCH_NAME_MAX_LENGTH }) || "session";
    const baseName = `${AUTORESEARCH_BRANCH_PREFIX}${goalSlug}-${currentDateStamp()}`;
    let candidate = baseName;
    let suffix = 2;
    while (await repository.refExists(`refs/heads/${candidate}`)) {
        candidate = `${baseName}-${suffix}`;
        suffix += 1;
    }
    return candidate;
}
function currentDateStamp() {
    const now = new Date();
    const year = String(now.getFullYear());
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");
    return `${year}${month}${day}`;
}
function addDirtyPath(paths, rawPath) {
    const normalizedPath = normalizeStatusPath(rawPath);
    if (normalizedPath.length === 0)
        return;
    paths.add(normalizedPath);
}
function isRenameOrCopy(statusToken) {
    const trimmed = statusToken.trim();
    return trimmed.startsWith("R") || trimmed.startsWith("C");
}
function collectRelativeDirtyPaths(statusOutput, workDirPrefix) {
    const dirtyPaths = [];
    for (const dirtyPath of parseDirtyPaths(statusOutput)) {
        const relativePath = relativizeGitPathToWorkDir(dirtyPath, workDirPrefix);
        dirtyPaths.push(relativePath ?? normalizeStatusPath(dirtyPath));
    }
    return dirtyPaths;
}
function formatDirtyPaths(paths) {
    const preview = paths.slice(0, 5).join(", ");
    return paths.length > 5 ? `${preview} (+${paths.length - 5} more)` : preview;
}
export function parseDirtyPathsWithStatus(statusOutput) {
    if (statusOutput.includes("\0")) {
        return parseDirtyPathsNulWithStatus(statusOutput);
    }
    return parseDirtyPathsLinesWithStatus(statusOutput);
}
function parseDirtyPathsNulWithStatus(statusOutput) {
    const seen = new Set();
    const results = [];
    let index = 0;
    while (index + 3 <= statusOutput.length) {
        const statusToken = statusOutput.slice(index, index + 3);
        index += 3;
        const pathEnd = statusOutput.indexOf("\0", index);
        if (pathEnd < 0)
            break;
        const firstPath = statusOutput.slice(index, pathEnd);
        index = pathEnd + 1;
        const untracked = statusToken.trim().startsWith("??");
        addDirtyPathEntry(seen, results, firstPath, untracked);
        if (isRenameOrCopy(statusToken)) {
            const secondPathEnd = statusOutput.indexOf("\0", index);
            if (secondPathEnd < 0)
                break;
            const secondPath = statusOutput.slice(index, secondPathEnd);
            index = secondPathEnd + 1;
            addDirtyPathEntry(seen, results, secondPath, false);
        }
    }
    return results;
}
function parseDirtyPathsLinesWithStatus(statusOutput) {
    const seen = new Set();
    const results = [];
    for (const line of statusOutput.split("\n")) {
        const trimmedLine = line.trimEnd();
        if (trimmedLine.length < 4)
            continue;
        const statusToken = trimmedLine.slice(0, 3);
        const rawPath = trimmedLine.slice(3).trim();
        if (rawPath.length === 0)
            continue;
        const untracked = statusToken.trim().startsWith("??");
        const renameParts = rawPath.split(" -> ");
        for (const renamePart of renameParts) {
            addDirtyPathEntry(seen, results, renamePart, untracked);
        }
    }
    return results;
}
function addDirtyPathEntry(seen, results, rawPath, untracked) {
    const normalizedPath = normalizeStatusPath(rawPath);
    if (normalizedPath.length === 0 || seen.has(normalizedPath))
        return;
    seen.add(normalizedPath);
    results.push({ path: normalizedPath, untracked });
}
export function parseWorkDirDirtyPathsWithStatus(statusOutput, workDirPrefix) {
    const results = [];
    for (const entry of parseDirtyPathsWithStatus(statusOutput)) {
        const relativePath = relativizeGitPathToWorkDir(entry.path, workDirPrefix);
        if (relativePath === null)
            continue;
        results.push({ path: relativePath, untracked: entry.untracked });
    }
    return results;
}
export function computeRunModifiedPaths(preRunDirtyPaths, currentStatusOutput, workDirPrefix) {
    const preRunSet = new Set(preRunDirtyPaths);
    const tracked = [];
    const untracked = [];
    for (const entry of parseWorkDirDirtyPathsWithStatus(currentStatusOutput, workDirPrefix)) {
        if (preRunSet.has(entry.path))
            continue;
        if (entry.untracked) {
            untracked.push(entry.path);
        }
        else {
            tracked.push(entry.path);
        }
    }
    return { tracked, untracked };
}
