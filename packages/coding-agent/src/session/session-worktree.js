/**
 * `/wt` backing: fork the current checkout into a fresh linked git worktree on
 * a new branch, carrying the uncommitted changes along, so the session can be
 * relocated there without disturbing the original checkout.
 *
 * The worktree is created through the clone-first path (`worktree.clone`,
 * `isolation.backend`) and lands under the agent-managed worktree base
 * (`worktree.base`, default `~/.omp/wt`) next to `github pr_checkout` trees,
 * so `omp worktree list|clear` sees it.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vcs from "@rva/natives/vcs";
import { getWorktreeDir, hashPath, logger } from "@rva/utils";
import { shortenPath } from "@rva/tui/render/render-utils";
import { formatIsolationBackend, parseIsolationBackend } from "../task/worktree";
import { resolveAvailableWorktreePath } from "../tools/gh-pr-checkout";
import { cfgIsolationBackend, cfgWorktreeCleanSource, cfgWorktreeClone } from "../task/settings";
/**
 * Map the `worktree.onExit` policy and the worktree's state to an exit action.
 * `remove` only removes worktrees with nothing to lose; anything else prompts.
 */
export function decideWorktreeExit(policy, state) {
    if (policy === "keep")
        return "keep";
    if (policy === "remove" && !state.dirty && !state.moved && !state.offBranch)
        return "remove";
    return "prompt";
}
/** Reports whether a fresh session in `cwd` may get a worktree: a primary git checkout with commits. */
export async function canAutoCreateWorktree(cwd) {
    const repository = vcs.git(cwd);
    if (!repository || repository.linkedWorktree())
        return false;
    return Boolean(await repository.headSha());
}
/** Default `/wt` branch name: `wt/<yyyymmdd-hhmmss>`. */
export function defaultSessionWorktreeBranch(now = new Date()) {
    const pad = (n) => String(n).padStart(2, "0");
    return `wt/${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}
/** One-line confirmation shown after the session moved into `worktree`. */
export function formatSessionWorktreeSummary(worktree, sourceCleaned = false) {
    const how = worktree.clonedWith === undefined ? "checked out" : `cloned via ${formatIsolationBackend(worktree.clonedWith)}`;
    const changeStatus = !worktree.keptChanges
        ? "started from clean HEAD"
        : sourceCleaned
            ? "uncommitted changes moved, source checkout cleaned"
            : "uncommitted changes carried over";
    return `Moved to worktree ${worktree.path} on branch ${worktree.branch} (${how}, ${changeStatus}).`;
}
/**
 * If `worktree.cleanSource` is enabled, resets and cleans the source checkout.
 * Catches git errors and returns `{ cleaned: true }` on success, or `{ cleaned: false, errorMessage }` on failure.
 */
export async function cleanSourceCheckoutIfConfigured(sourceCwd, settings) {
    if (!cfgWorktreeCleanSource.get(settings)) {
        return { cleaned: false };
    }
    try {
        const repository = vcs.requireGit(sourceCwd);
        await repository.reset("hard", "HEAD");
        await repository.clean({});
        return { cleaned: true };
    }
    catch (error) {
        logger.warn("failed to clean source checkout after /wt", { cwd: sourceCwd, error });
        return {
            cleaned: false,
            errorMessage: error instanceof Error ? error.message : String(error),
        };
    }
}
/**
 * Create the worktree for `/wt`. Throws with a user-facing message when `cwd`
 * is not a git checkout, `branch` already exists, or git refuses.
 */
export async function createSessionWorktree(cwd, settings, branch, options = {}) {
    const keepChanges = options.keepChanges ?? true;
    try {
        await settings.flush();
    }
    catch (err) {
        throw new Error(`Failed to save pending settings: ${err instanceof Error ? err.message : String(err)}`);
    }
    const repository = vcs.git(cwd);
    if (!repository) {
        throw new Error(`Not inside a git repository: ${cwd}`);
    }
    if (!/^[^\s~^:?*[\\]+$/.test(branch) || branch.startsWith("-") || branch.endsWith("/") || branch.includes("..")) {
        throw new Error(`Invalid branch name: ${branch}`);
    }
    const branchRef = `refs/heads/${branch}`;
    if (await repository.refExists(branchRef)) {
        throw new Error(`Branch '${branch}' already exists; pick another name.`);
    }
    const baseCommit = await repository.headSha();
    if (!baseCommit) {
        throw new Error(`Cannot create a worktree: ${cwd} has no commits.`);
    }
    const primaryRoot = repository.primaryRoot() ?? repository.info().repoRoot;
    const slug = branch.replaceAll(/[^A-Za-z0-9._-]+/g, "-");
    const basePath = getWorktreeDir(`${slug}-${hashPath(primaryRoot)}`);
    const worktreePath = await resolveAvailableWorktreePath(basePath, await repository.worktrees());
    await fs.mkdir(path.dirname(worktreePath), { recursive: true });
    await repository.createBranch(branch, baseCommit, false);
    const result = await repository.worktreeAdd(worktreePath, branch, {
        detach: false,
        clone: cfgWorktreeClone.get(settings),
        backend: parseIsolationBackend(cfgIsolationBackend.get(settings)),
        keepChanges,
    });
    return {
        path: await fs.realpath(worktreePath),
        branch,
        clonedWith: result.clonedWith ?? undefined,
        cloneError: result.cloneError ?? undefined,
        sourceCwd: cwd,
        baseCommit,
        keptChanges: keepChanges,
    };
}
async function snapshotSessionWorktree(wt) {
    const sourceRepo = vcs.git(wt.sourceCwd);
    let moved = true;
    let tip;
    if (sourceRepo) {
        tip = await sourceRepo.resolveRef(`refs/heads/${wt.branch}`);
        moved = tip !== null && tip !== undefined && tip !== wt.baseCommit;
    }
    const worktreeExists = await fs.stat(wt.path).then(() => true, () => false);
    const worktreeRepo = worktreeExists ? vcs.git(wt.path) : null;
    if (!worktreeRepo) {
        return { state: { dirty: false, moved, offBranch: false }, fingerprint: `missing\0${tip ?? ""}`, present: false };
    }
    const status = await worktreeRepo.statusPorcelain({ untracked: "all", nulTerminated: true });
    const head = await worktreeRepo.headSha();
    // Porcelain codes do not change when an already-modified file is edited again,
    // so fold in each changed path's size and mtime.
    const parts = [head ?? "", tip ?? "", status];
    const entries = status.split("\0");
    for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        if (entry.length < 4)
            continue;
        // Renames and copies are followed by their source path as a separate entry.
        if (entry[0] === "R" || entry[0] === "C")
            i++;
        const file = entry.slice(3);
        const stat = await fs.stat(path.join(wt.path, file)).catch(() => undefined);
        parts.push(stat ? `${file}:${stat.size}:${stat.mtimeMs}` : `${file}:-`);
    }
    return {
        state: { dirty: status.length > 0, moved, offBranch: Boolean(head) && head !== tip },
        fingerprint: Bun.hash(parts.join("\0")).toString(16),
        present: true,
    };
}
/**
 * Gets the state of `wt`. A missing worktree is not dirty and not off-branch; a
 * deleted branch has not moved; a missing source repo counts as moved so the
 * branch is never deleted.
 */
export async function inspectSessionWorktree(wt) {
    return (await snapshotSessionWorktree(wt)).state;
}
/** Describes what removing a worktree in `state` would lose, for the exit prompt. */
function describeWorktreeRisk(wt, state) {
    const issues = [];
    if (state.dirty)
        issues.push("has uncommitted changes");
    if (state.moved)
        issues.push("has new commits (branch is kept)");
    if (state.offBranch)
        issues.push(`HEAD is not on ${wt.branch}; commits only reachable from HEAD are lost`);
    return issues.join("; ");
}
/**
 * Applies `policy` to `owned` and returns the worktrees to remove, newest first.
 * Calls `confirm` for each worktree that needs a prompt; inspection errors go to
 * `warn` and keep that worktree.
 */
export async function planWorktreeExit(owned, policy, confirm, warn) {
    if (policy === "keep")
        return [];
    const plan = [];
    // Newest first: a `/wt` worktree may have been forked from an older owned one.
    for (const worktree of owned.toReversed()) {
        try {
            const { state, fingerprint } = await snapshotSessionWorktree(worktree);
            const action = decideWorktreeExit(policy, state);
            if (action === "keep")
                continue;
            if (action === "remove") {
                plan.push({ worktree, approvedFingerprint: fingerprint });
                continue;
            }
            const risk = describeWorktreeRisk(worktree, state);
            const message = `${shortenPath(worktree.path)} (${worktree.branch})${risk ? `: ${risk}` : ""}`;
            if (await confirm("Remove worktree?", message))
                plan.push({ worktree, approvedFingerprint: fingerprint });
        }
        catch (err) {
            warn(err instanceof Error ? err.message : String(err));
        }
    }
    return plan;
}
/**
 * Removes the planned worktrees in order, keeping any that changed at all since
 * removal was decided or approved. Returns one message per kept or failed
 * worktree, plus a resume note when the worktree holding the process cwd is removed.
 */
export async function removeExitWorktrees(plan) {
    const messages = [];
    for (const { worktree, approvedFingerprint } of plan) {
        try {
            const { state, fingerprint, present } = await snapshotSessionWorktree(worktree);
            // A vanished worktree holds nothing to lose; `state.moved` still guards the branch.
            if (present && fingerprint !== approvedFingerprint) {
                messages.push(`Kept worktree ${shortenPath(worktree.path)}: it changed while the session was closing.`);
                continue;
            }
            // Git cannot open the source repo while our cwd is the deleted worktree.
            const rel = path.relative(worktree.path, process.cwd());
            const holdsCwd = !rel.startsWith("..") && !path.isAbsolute(rel);
            if (holdsCwd)
                process.chdir(worktree.sourceCwd);
            await removeSessionWorktree(worktree, state.moved);
            if (holdsCwd) {
                const commits = state.moved ? `; its commits are on branch ${worktree.branch}` : "";
                messages.push(`Removed worktree ${shortenPath(worktree.path)}. Resuming opens in the directory you launch omp from${commits}.`);
            }
        }
        catch (err) {
            messages.push(err instanceof Error ? err.message : String(err));
        }
    }
    return messages;
}
/**
 * Force-remove `wt`; also delete its branch unless it `moved` (has new commits).
 * Throws a user-facing error when git refuses either step.
 */
export async function removeSessionWorktree(wt, moved) {
    const repository = vcs.requireGit(wt.sourceCwd);
    if (!(await repository.worktreeRemove(wt.path, true))) {
        throw new Error(`Failed to remove worktree ${wt.path}; branch '${wt.branch}' kept.`);
    }
    if (!moved && !(await repository.deleteBranch(wt.branch, true))) {
        throw new Error(`Removed worktree ${wt.path} but failed to delete branch '${wt.branch}'.`);
    }
}
