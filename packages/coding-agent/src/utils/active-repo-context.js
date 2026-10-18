import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import * as vcs from "@rva/natives/vcs";
function compareEntryNames(left, right) {
    if (left.name < right.name)
        return -1;
    if (left.name > right.name)
        return 1;
    return 0;
}
function buildContext(cwd, repoRoot) {
    const resolvedCwd = path.resolve(cwd);
    const resolvedRepoRoot = path.resolve(repoRoot);
    return {
        cwd: resolvedCwd,
        repoRoot: resolvedRepoRoot,
        relativeRepoRoot: path.relative(resolvedCwd, resolvedRepoRoot),
        source: "single-direct-child-repo",
    };
}
/** Whether `cwd` already sits inside a VCS repository. */
function insideRepository(cwd) {
    try {
        return vcs.repo(cwd) !== null;
    }
    catch {
        return false;
    }
}
async function readDirectChildren(cwd) {
    try {
        const entries = await fsPromises.readdir(cwd, { withFileTypes: true });
        entries.sort(compareEntryNames);
        return entries;
    }
    catch {
        return [];
    }
}
function readDirectChildrenSync(cwd) {
    try {
        const entries = fs.readdirSync(cwd, { withFileTypes: true });
        entries.sort(compareEntryNames);
        return entries;
    }
    catch {
        return [];
    }
}
async function resolveDirectChildDirectory(cwd, entry) {
    const childPath = path.join(cwd, entry.name);
    if (entry.isDirectory())
        return childPath;
    if (!entry.isSymbolicLink())
        return null;
    try {
        const stat = await fsPromises.stat(childPath);
        return stat.isDirectory() ? childPath : null;
    }
    catch {
        return null;
    }
}
function resolveDirectChildDirectorySync(cwd, entry) {
    const childPath = path.join(cwd, entry.name);
    if (entry.isDirectory())
        return childPath;
    if (!entry.isSymbolicLink())
        return null;
    try {
        const stat = fs.statSync(childPath);
        return stat.isDirectory() ? childPath : null;
    }
    catch {
        return null;
    }
}
async function hasGitRepository(childPath) {
    try {
        // Skip markerless siblings before native discovery can walk their ancestors.
        const stat = await fsPromises.stat(path.join(childPath, ".git"));
        if (!stat.isDirectory() && !stat.isFile())
            return false;
        const info = vcs.gitInfo(childPath);
        // Resolve gitfiles through the shared parser, but never adopt an ancestor.
        if (!info || path.resolve(info.repoRoot) !== childPath)
            return false;
        return (await fsPromises.stat(info.headPath)).isFile();
    }
    catch {
        return false;
    }
}
function hasGitRepositorySync(childPath) {
    try {
        const stat = fs.statSync(path.join(childPath, ".git"));
        if (!stat.isDirectory() && !stat.isFile())
            return false;
        const info = vcs.gitInfo(childPath);
        if (!info || path.resolve(info.repoRoot) !== childPath)
            return false;
        return fs.statSync(info.headPath).isFile();
    }
    catch {
        return false;
    }
}
async function findSingleDirectChildRepo(cwd) {
    let context = null;
    for (const entry of await readDirectChildren(cwd)) {
        const childPath = await resolveDirectChildDirectory(cwd, entry);
        if (!childPath)
            continue;
        if (!(await hasGitRepository(childPath)))
            continue;
        if (context)
            return null;
        context = buildContext(cwd, childPath);
    }
    return context;
}
function findSingleDirectChildRepoSync(cwd) {
    let context = null;
    for (const entry of readDirectChildrenSync(cwd)) {
        const childPath = resolveDirectChildDirectorySync(cwd, entry);
        if (!childPath)
            continue;
        if (!hasGitRepositorySync(childPath))
            continue;
        if (context)
            return null;
        context = buildContext(cwd, childPath);
    }
    return context;
}
export async function resolveActiveRepoContext(cwd) {
    const resolvedCwd = path.resolve(cwd);
    if (insideRepository(resolvedCwd))
        return null;
    return findSingleDirectChildRepo(resolvedCwd);
}
export function resolveActiveRepoContextSync(cwd) {
    const resolvedCwd = path.resolve(cwd);
    if (insideRepository(resolvedCwd))
        return null;
    return findSingleDirectChildRepoSync(resolvedCwd);
}
