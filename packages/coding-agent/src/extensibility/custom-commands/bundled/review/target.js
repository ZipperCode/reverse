import * as vcs from "@rva/natives/vcs";
import { parseReviewDiffSnapshot } from "./diff";
export const LOCAL_REVIEW_CHOICES = [
    { label: "1. Review against a base branch (PR Style)", kind: "base-branch" },
    { label: "2. Review uncommitted changes", kind: "uncommitted" },
    { label: "3. Review a specific commit", kind: "commit" },
];
const GIT_UNCOMMITTED_DIFF_INSTRUCTION = "MUST run both `git diff -- <path>` and `git diff --cached -- <path>` for assigned files";
const JJ_UNCOMMITTED_DIFF_INSTRUCTION = "MUST run `jj --ignore-working-copy diff --git -- <path>` for assigned files";
export function createResolvedReviewTarget(kind, mode, rawDiff, emptyMessage, options = {}) {
    return {
        kind,
        mode,
        rawDiff,
        snapshot: parseReviewDiffSnapshot(rawDiff),
        emptyMessage,
        ...options,
    };
}
export function getReviewTargetIssue(target) {
    if (!target.rawDiff.trim())
        return target.emptyMessage;
    if (target.snapshot.files.length === 0) {
        return target.filteredMessage ?? "No reviewable files (all changes filtered out)";
    }
    return undefined;
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
/** Read staged + unstaged (or jj working-copy) changes; throws when no repository is available. */
export async function readUncommittedReviewTarget(cwd) {
    const repository = vcs.require(cwd);
    const diffText = await repository.uncommittedDiff([]);
    const isJj = repository.kind() === "jj";
    return createResolvedReviewTarget("uncommitted", isJj ? "Reviewing JJ working-copy changes" : "Reviewing uncommitted changes (staged + unstaged)", diffText, isJj || !diffText.trim() ? "No uncommitted changes found" : "No diff content found", { diffInstruction: isJj ? JJ_UNCOMMITTED_DIFF_INSTRUCTION : GIT_UNCOMMITTED_DIFF_INSTRUCTION });
}
async function listGitBranches(cwd) {
    try {
        return await vcs.requireGit(cwd).listBranches(true);
    }
    catch {
        return [];
    }
}
async function currentGitBranch(cwd) {
    try {
        return (await vcs.git(cwd)?.currentBranch()) ?? "HEAD";
    }
    catch {
        return "HEAD";
    }
}
async function recentCommits(cwd, count) {
    try {
        return await vcs.require(cwd).logOnelines(count);
    }
    catch {
        return [];
    }
}
export async function resolveLocalReviewTarget(kind, cwd, ui) {
    switch (kind) {
        case "base-branch": {
            const branches = await listGitBranches(cwd);
            if (branches.length === 0) {
                ui.notify("No git branches found", "error");
                return undefined;
            }
            const baseBranch = await ui.select("Select base branch to compare against", branches);
            if (!baseBranch)
                return undefined;
            const currentBranch = await currentGitBranch(cwd);
            let diffText;
            try {
                const repository = vcs.requireGit(cwd);
                // PR-style review compares the merge base against the current
                // branch (`base...head`), so base-only commits are excluded.
                const mergeBase = await repository.mergeBase(baseBranch, currentBranch);
                if (!mergeBase) {
                    // No common ancestor: `git diff base...head` aborts here
                    // rather than comparing unrelated trees tip-to-tip.
                    ui.notify(`No common history between ${baseBranch} and ${currentBranch}`, "error");
                    return undefined;
                }
                diffText = await repository.diffText({ base: mergeBase, head: currentBranch });
            }
            catch (error) {
                ui.notify(`Failed to get diff: ${errorMessage(error)}`, "error");
                return undefined;
            }
            return createResolvedReviewTarget("base-branch", `Reviewing changes between \`${baseBranch}\` and \`${currentBranch}\` (PR-style)`, diffText, `No changes between ${baseBranch} and ${currentBranch}`);
        }
        case "uncommitted":
            try {
                return await readUncommittedReviewTarget(cwd);
            }
            catch (error) {
                ui.notify(`Failed to get diff: ${errorMessage(error)}`, "error");
                return undefined;
            }
        case "commit": {
            const commits = await recentCommits(cwd, 20);
            if (commits.length === 0) {
                ui.notify("No commits found", "error");
                return undefined;
            }
            const selectedCommit = await ui.select("Select commit to review", commits);
            if (!selectedCommit)
                return undefined;
            const hash = selectedCommit.split(" ")[0];
            let diffText;
            try {
                diffText = (await vcs.requireGit(cwd).showCommit(hash)).data.toString("utf8");
            }
            catch (error) {
                ui.notify(`Failed to get commit: ${errorMessage(error)}`, "error");
                return undefined;
            }
            return createResolvedReviewTarget("commit", `Reviewing commit \`${hash}\``, diffText, "Commit has no diff content", {
                filteredMessage: "No reviewable files in commit (all changes filtered out)",
            });
        }
    }
}
