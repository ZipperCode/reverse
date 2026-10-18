/**
 * Reusable isolation lifecycle for subagent execution.
 *
 * Both `TaskTool` and the eval `agent()` bridge spawn subagents that can run
 * inside a copy-on-write worktree, capture their changes, and (optionally)
 * apply those changes back to the parent repo. The orchestration is identical
 * for both callers; this module hosts the shared lifecycle so eval `agent()`
 * does not need to round-trip through `TaskTool.#runSpawn`.
 *
 * Shape:
 *   1. {@link prepareIsolationContext} — resolve the git root.
 *   2. {@link runIsolatedSubprocess}    — start worktree, capture its
 *                                        baseline, run, capture changes, and
 *                                        transfer cleanup ownership.
 *   3. {@link mergeIsolatedChanges}     — apply captured changes back to the
 *                                        parent repo (skip when the caller
 *                                        opted out).
 *
 * Step 1 happens once per top-level call; steps 2 and 3 are per-spawn.
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vcs from "@rva/natives/vcs";
import { prompt } from "@rva/utils";
import isolationErrorTemplate from "../prompts/tools/isolation-error.md" with { type: "text" };
import isolationSummaryTemplate from "../prompts/tools/isolation-summary.md" with { type: "text" };
import { AgentLifecycleManager } from "../registry/agent-lifecycle";
import { AgentRegistry } from "../registry/agent-registry";
import { generateCommitMessage } from "../utils/commit-message-generator";
import { trackLateCleanup } from "../utils/late-cleanup";
import { runSubprocess } from "./executor";
import { needsNativeTeardown, writeRetainedBackend } from "./isolation-ownership";
import { applyNestedPatches, captureDeltaPatch, captureIsolationBaseline, cleanupIsolation, cleanupTaskBranches, commitToBranch, ensureIsolation, getRepoRoot, mergeTaskBranches, } from "./worktree";
import { cfgTaskIsolationCommits } from "./settings";
/**
 * Render one isolation outcome as the model-facing suffix appended to a task
 * result. Always starts with a blank line so it separates from the output it
 * follows.
 */
export function renderIsolationSummary(context) {
    return `\n\n${prompt.render(isolationSummaryTemplate, { ...context })}`;
}
/** Record artifact locations for `agent://` and mark the result as an isolated run. */
function rememberAgentArtifacts(result) {
    AgentRegistry.global().setHistory(result.id, {
        outputPath: result.outputPath,
        patchPath: result.patchPath,
        branchName: result.branchName,
        nestedPatchPaths: result.nestedPatchPaths,
    });
    return { ...result, isolated: true };
}
/**
 * Decide the fate of a half-built task branch after apply-back threw.
 *
 * Returns the branch name when it carries at least one commit past `baseSha`
 * — the caller must keep it, because the isolation worktree that also held
 * those objects is about to be torn down. Returns `undefined` after deleting
 * a branch that is absent, empty, or still pinned at the baseline, preserving
 * the original stale-branch cleanup for the cases where nothing is at stake.
 *
 * `revList.range` throws when the branch does not exist, which is the common
 * "commitToBranch failed before it created anything" path; that is treated as
 * "nothing to rescue" only after confirming the ref is absent. Other probe
 * failures preserve the branch because deleting it could lose the only reachable
 * copy of the agent's commits.
 */
async function rescueTaskBranch(repoRoot, branchName, baseSha) {
    const repo = vcs.git(repoRoot);
    try {
        const carriedCommits = (await vcs.requireGit(repoRoot).revListRange(baseSha, branchName)).length;
        if (carriedCommits > 0)
            return branchName;
    }
    catch {
        try {
            if (await repo?.refExists(`refs/heads/${branchName}`))
                return branchName;
        }
        catch {
            // An inconclusive recovery probe must never risk deleting the only ref.
            return branchName;
        }
    }
    try {
        await repo?.deleteBranch(branchName, true);
    }
    catch {
        // Best-effort cleanup matches the old façade's tryDelete semantics.
    }
    return undefined;
}
/**
 * Resolve the git repo root isolated spawns are copied from and merged back
 * into. Throws when the cwd is not inside a git repository; callers surface
 * the error as a task-tool failure. Each spawn captures its own baseline from
 * its isolation copy (see {@link captureIsolationBaseline}).
 */
export async function prepareIsolationContext(cwd) {
    return { repoRoot: await getRepoRoot(cwd) };
}
/** Fingerprint of a captured delta, used to skip re-committing an unchanged workspace on release. */
function deltaFingerprint(rootPatch, nestedPatches) {
    let key = rootPatch;
    for (const { relativePath, patch } of nestedPatches)
        key += `\0${relativePath}\0${patch}`;
    return Bun.hash(key);
}
/**
 * Construct the commit-message factory used by isolation branch commits and
 * nested-repo patch commits. Returns a closure that, each time it's called,
 * either yields an AI-backed `(diff) => Promise<string|null>` callback (when
 * `task.isolation.commits === "ai"` and a model registry is available) or
 * `undefined` so the caller falls back to a generic commit message.
 *
 * Centralized so `TaskTool` and the eval `agent()` bridge share one wiring;
 * a drift here previously meant the two callers built subtly different
 * generators for the same setting.
 */
export function makeIsolationCommitMessage(session) {
    return () => {
        const style = cfgTaskIsolationCommits.get(session.settings);
        if (style !== "ai" || !session.modelRegistry)
            return undefined;
        const registry = session.modelRegistry;
        const settings = session.settings;
        const sessionId = session.getSessionId?.() ?? undefined;
        return async (diff) => generateCommitMessage(diff, registry, settings, sessionId);
    };
}
/**
 * Write each nested-repo patch to `${artifactsDir}/${agentId}.nested-<n>-<path>.patch`
 * and return the paths. Throws on the first write failure: the caller must
 * then keep the isolation workspace alive, because it is the only other copy.
 * Every attempted destination is removed best-effort on failure — including
 * the in-progress file, which `Bun.write` may have created or truncated
 * before rejecting — so a half-written set cannot be mistaken for the
 * complete capture by the persisted-agent scanner.
 */
export async function persistNestedPatches(artifactsDir, agentId, nestedPatches) {
    const saved = [];
    try {
        for (const [index, nestedPatch] of nestedPatches.entries()) {
            const destination = path.join(artifactsDir, `${agentId}.nested-${index}-${nestedPatch.relativePath.replace(/[^a-zA-Z0-9._-]/g, "_") || "root"}.patch`);
            // Track before writing: a mid-write failure (ENOSPC, quota) can
            // leave a truncated file behind, and `force: true` makes removing
            // a never-created path a no-op.
            saved.push(destination);
            await Bun.write(destination, nestedPatch.patch);
        }
    }
    catch (error) {
        await Promise.all(saved.map(file => fs.rm(file, { force: true }).catch(() => undefined)));
        throw error;
    }
    return saved;
}
/**
 * Capture the isolation delta and write every part of it to disk — the root
 * patch and one file per nested repo — before the caller tears the workspace
 * down. Throws when any write fails so nothing captured is ever the only copy.
 */
async function writeIsolationPatch(isolationDir, baseline, artifactsDir, agentId) {
    const delta = await captureDeltaPatch(isolationDir, baseline);
    const patchPath = path.join(artifactsDir, `${agentId}.patch`);
    await Bun.write(patchPath, delta.rootPatch);
    const nestedPatchPaths = await persistNestedPatches(artifactsDir, agentId, delta.nestedPatches);
    return {
        artifacts: {
            patchPath,
            hasRootChanges: delta.rootPatch.trim().length > 0,
            nestedPatches: delta.nestedPatches,
            nestedPatchPaths,
        },
        fingerprint: deltaFingerprint(delta.rootPatch, delta.nestedPatches),
    };
}
export async function retainIsolationWorkspace(isolationDir, backend) {
    const baseDir = path.dirname(isolationDir);
    const retainedBase = `${baseDir}.retained-${Date.now().toString(36)}-${Math.floor(Math.random() * 2 ** 32).toString(16)}`;
    const needsSidecar = backend !== undefined && needsNativeTeardown(backend);
    let sidecarOk = !needsSidecar;
    if (needsSidecar && backend !== undefined) {
        try {
            await writeRetainedBackend(baseDir, backend);
            sidecarOk = true;
        }
        catch {
            sidecarOk = false;
        }
    }
    // A valid move can still fail transiently (Windows AV/indexer locks);
    // retry briefly before conceding the deterministic slot.
    for (let attempt = 0; attempt < 3; attempt++) {
        try {
            await fs.rename(baseDir, retainedBase);
            return { dir: path.join(retainedBase, path.basename(isolationDir)), sidecarOk };
        }
        catch {
            if (attempt === 2)
                return { dir: isolationDir, sidecarOk };
            await Bun.sleep(25);
        }
    }
    return { dir: isolationDir, sidecarOk };
}
function renderIsolationError(context) {
    return prompt.render(isolationErrorTemplate, { ...context });
}
/**
 * Run a subagent inside an isolation worktree and capture its changes.
 *
 * Branch mode: on success, commits the diff onto `omp/task/${agentId}` and
 * returns `branchName` + `nestedPatches` (+ `nestedPatchPaths`). On commit
 * failure the still-live isolation diff is written to
 * `${artifactsDir}/${agentId}.patch`, the task branch is kept when it already
 * carries commits (deleted otherwise), and `result.error` carries the
 * merge-failure message plus recovery hint.
 *
 * Patch mode: on success, writes `${artifactsDir}/${agentId}.patch` plus one
 * `${agentId}.nested-<n>-<path>.patch` per nested repo and returns
 * `patchPath` + `nestedPatches` + `nestedPatchPaths`.
 *
 * Failure paths preserve the underlying `SingleResult` whenever possible so
 * the caller can still surface the subagent's output; only isolation setup
 * itself routes through {@link IsolatedRunOptions.buildFailureResult}.
 *
 * Kept-alive runs retain the isolation handle through idle/parked lifecycle
 * transitions, then capture final changes and clean up on release. One-shot
 * and failed startup paths clean up in `finally`. If captured changes cannot
 * be written to disk, the workspace is retained under a unique `.retained-*`
 * sibling and its path is named in the resulting error.
 */
export async function runIsolatedSubprocess(opts) {
    let taskBaseline;
    /** Fingerprint of the delta already handed to the caller at run end; release only re-captures on change. */
    let handedOff;
    let handle;
    let deferredCleanup;
    let retainWorkspace = false;
    let baseReleasePromise;
    let cleanupPromise;
    let releasePromise;
    const releaseBase = () => {
        baseReleasePromise ??= opts.baseOptions.onRelease?.() ?? Promise.resolve();
        return baseReleasePromise;
    };
    const cleanupHandle = () => {
        cleanupPromise ??= (async () => {
            await releaseBase();
            if (handle && !retainWorkspace)
                await cleanupIsolation(handle);
        })();
        return cleanupPromise;
    };
    const releaseIsolation = () => {
        releasePromise ??= (async () => {
            if (!handle || !taskBaseline || retainWorkspace) {
                await cleanupHandle();
                return;
            }
            try {
                let capture;
                try {
                    capture = await writeIsolationPatch(handle.mergedDir, taskBaseline, opts.artifactsDir, opts.agentId);
                }
                catch (captureErr) {
                    retainWorkspace = true;
                    const retained = await retainIsolationWorkspace(handle.mergedDir, handle.backend);
                    throw new Error(renderIsolationError({
                        kind: "patch-capture-failed",
                        message: captureErr instanceof Error ? captureErr.message : String(captureErr),
                        retainedDir: retained.dir,
                        sidecarMissing: !retained.sidecarOk,
                    }));
                }
                const patchResult = capture.artifacts;
                AgentRegistry.global().setHistory(opts.agentId, {
                    patchPath: patchResult.patchPath,
                    nestedPatchPaths: patchResult.nestedPatchPaths,
                });
                // Nothing changed since the run-end capture the caller already
                // merged or applied: a branch now would only duplicate that work.
                if (capture.fingerprint === handedOff)
                    return;
                const commitResult = await commitToBranch(handle.mergedDir, taskBaseline, opts.agentId, opts.description, undefined);
                AgentRegistry.global().setHistory(opts.agentId, {
                    patchPath: patchResult.patchPath,
                    branchName: commitResult?.branchName,
                    nestedPatchPaths: patchResult.nestedPatchPaths,
                });
            }
            finally {
                await cleanupHandle();
            }
        })();
        return releasePromise;
    };
    try {
        handle = await ensureIsolation(opts.context.repoRoot, opts.agentId, opts.preferredBackend);
        const isolationDir = handle.mergedDir;
        const isolationBackend = handle.backend;
        const baseline = await captureIsolationBaseline(isolationDir, opts.context.repoRoot);
        taskBaseline = baseline;
        const result = await runSubprocess({
            ...opts.baseOptions,
            worktree: isolationDir,
            preloadedExtensionPaths: undefined,
            preloadedPreparedExtensions: undefined,
            preloadedCustomToolPaths: undefined,
            onCleanupDeferred: completion => {
                deferredCleanup = completion;
                opts.baseOptions.onCleanupDeferred?.(completion);
            },
            // One-shot runs get `releaseBase` (never touches the worktree): their
            // `finalizeSubagentLifecycle` calls `onRelease` before this function's
            // post-run capture, so the handle must survive until the `finally`
            // below cleans it up. Only kept-alive runs hand full capture+cleanup
            // (`releaseIsolation`) to the agent lifecycle.
            onRelease: opts.baseOptions.keepAlive === false ? releaseBase : releaseIsolation,
        });
        opts.onSubprocessResult?.(result);
        // A successful result cannot be captured while deferred owner jobs or
        // shutdown hooks may still write the worktree. Failed runs skip capture,
        // so their cleanup remains asynchronous.
        if (deferredCleanup && result.exitCode === 0) {
            await deferredCleanup;
        }
        if (opts.mergeMode === "branch" && result.exitCode === 0) {
            let commitResult;
            try {
                commitResult = await commitToBranch(isolationDir, baseline, opts.agentId, opts.description, opts.buildCommitMessage?.());
            }
            catch (mergeErr) {
                // Agent succeeded but the branch commit failed. `commitToBranch`
                // is not atomic: the clean-baseline path fetches the agent's
                // commits into the parent ODB and creates `omp/task/<id>` before
                // it commits the leftover working-tree delta, so a throw from
                // that trailing step leaves behind a branch that already holds
                // every commit the agent made. The isolation worktree — the only
                // other copy of those objects — is destroyed by the `finally`
                // below, so deleting the branch unconditionally turned a
                // recoverable merge conflict into permanent loss of committed
                // work (#8868). Delete only when nothing is at stake.
                const baseSha = baseline.root.headCommit;
                const branchName = `omp/task/${opts.agentId}`;
                const rescueBranch = await rescueTaskBranch(opts.context.repoRoot, branchName, baseSha);
                const msg = mergeErr instanceof Error ? mergeErr.message : String(mergeErr);
                try {
                    const capture = await writeIsolationPatch(isolationDir, baseline, opts.artifactsDir, opts.agentId);
                    return rememberAgentArtifacts({
                        ...result,
                        ...capture.artifacts,
                        error: renderIsolationError({ kind: "merge-failed", message: msg, rescueBranch }),
                    });
                }
                catch (patchErr) {
                    retainWorkspace = true;
                    const retained = await retainIsolationWorkspace(isolationDir, isolationBackend);
                    return rememberAgentArtifacts({
                        ...result,
                        error: renderIsolationError({
                            kind: "merge-failed",
                            message: msg,
                            captureError: patchErr instanceof Error ? patchErr.message : String(patchErr),
                            rescueBranch,
                            retainedDir: retained.dir,
                            sidecarMissing: !retained.sidecarOk,
                        }),
                    });
                }
            }
            handedOff = deltaFingerprint(commitResult?.rootPatch ?? "", commitResult?.nestedPatches ?? []);
            // The branch holds the root-repo work, but nested-repo patches exist
            // only in memory until written; the workspace goes away in `finally`.
            try {
                const nestedPatchPaths = await persistNestedPatches(opts.artifactsDir, opts.agentId, commitResult?.nestedPatches ?? []);
                return rememberAgentArtifacts({
                    ...result,
                    branchName: commitResult?.branchName,
                    branchBaseSha: commitResult?.baseSha,
                    nestedPatches: commitResult?.nestedPatches,
                    nestedPatchPaths,
                });
            }
            catch (persistErr) {
                retainWorkspace = true;
                const retained = await retainIsolationWorkspace(isolationDir, isolationBackend);
                return rememberAgentArtifacts({
                    ...result,
                    branchName: commitResult?.branchName,
                    branchBaseSha: commitResult?.baseSha,
                    nestedPatches: commitResult?.nestedPatches,
                    error: renderIsolationError({
                        kind: "nested-capture-failed",
                        message: persistErr instanceof Error ? persistErr.message : String(persistErr),
                        retainedDir: retained.dir,
                        sidecarMissing: !retained.sidecarOk,
                    }),
                });
            }
        }
        if (result.exitCode === 0) {
            try {
                const capture = await writeIsolationPatch(isolationDir, baseline, opts.artifactsDir, opts.agentId);
                handedOff = capture.fingerprint;
                return rememberAgentArtifacts({ ...result, ...capture.artifacts });
            }
            catch (patchErr) {
                retainWorkspace = true;
                const retained = await retainIsolationWorkspace(isolationDir, isolationBackend);
                return rememberAgentArtifacts({
                    ...result,
                    error: renderIsolationError({
                        kind: "patch-capture-failed",
                        message: patchErr instanceof Error ? patchErr.message : String(patchErr),
                        retainedDir: retained.dir,
                        sidecarMissing: !retained.sidecarOk,
                    }),
                });
            }
        }
        return rememberAgentArtifacts(result);
    }
    catch (err) {
        return rememberAgentArtifacts(opts.buildFailureResult(err));
    }
    finally {
        if (handle &&
            !retainWorkspace &&
            !releasePromise &&
            !(opts.baseOptions.keepAlive !== false && AgentLifecycleManager.global().has(opts.agentId))) {
            if (deferredCleanup) {
                trackLateCleanup(deferredCleanup.then(cleanupHandle), {
                    agentId: opts.agentId,
                    resource: "isolation",
                });
            }
            else {
                await cleanupHandle();
            }
        }
    }
}
/**
 * Apply changes captured by {@link runIsolatedSubprocess} back to the parent
 * repo: patch apply (patch mode) or cherry-pick + cleanup (branch mode).
 *
 * The caller decides whether to run this at all — eval `agent()` with
 * `apply=False` skips this step and surfaces the patch artifact / branch name
 * instead.
 */
export async function mergeIsolatedChanges(opts) {
    const { result, repoRoot, mergeMode } = opts;
    const repo = vcs.requireGit(repoRoot);
    try {
        if (mergeMode === "branch") {
            if (!result.branchName && result.exitCode === 0 && !result.aborted && result.error) {
                return {
                    summary: renderIsolationSummary({
                        kind: "branch-capture-failed",
                        error: result.error,
                        rootPatchPath: result.patchPath,
                        nestedPatchPaths: result.nestedPatchPaths,
                    }),
                    changesApplied: false,
                    hadAnyChanges: false,
                    mergedBranchForNestedPatches: false,
                };
            }
            const canApplyNestedOnly = !result.branchName && result.exitCode === 0 && !result.aborted && (result.nestedPatches?.length ?? 0) > 0;
            if (!result.branchName || result.exitCode !== 0 || result.aborted) {
                return {
                    summary: canApplyNestedOnly
                        ? "\n\nNo root changes to apply; nested repository patches captured."
                        : "\n\nNo changes to apply.",
                    changesApplied: true,
                    hadAnyChanges: canApplyNestedOnly,
                    mergedBranchForNestedPatches: canApplyNestedOnly,
                };
            }
            const mergeResult = await mergeTaskBranches(repoRoot, [
                {
                    branchName: result.branchName,
                    taskId: result.id,
                    description: result.description,
                    baseSha: result.branchBaseSha,
                },
            ]);
            const mergedBranchForNestedPatches = mergeResult.merged.includes(result.branchName);
            const changesApplied = mergeResult.failed.length === 0;
            const hadAnyChanges = changesApplied && mergeResult.merged.length > 0;
            let summary;
            if (changesApplied) {
                summary = hadAnyChanges ? `\n\nMerged branch: ${result.branchName}` : "\n\nNo changes to apply.";
            }
            else {
                // The nested patches are skipped when the branch did not merge; name
                // their files so the parent can recover them alongside the branch.
                summary = renderIsolationSummary({
                    kind: "branch-merge-failed",
                    branchName: result.branchName,
                    conflict: mergeResult.conflict,
                    nestedPatchPaths: result.nestedPatchPaths,
                });
            }
            // Clean up the merged branch (keep failed ones for manual resolution)
            if (changesApplied) {
                await cleanupTaskBranches(repoRoot, [result.branchName]);
            }
            return { summary, changesApplied, hadAnyChanges, mergedBranchForNestedPatches };
        }
        // Patch mode: apply the patch from a successful run. A failed or
        // aborted run has nothing to apply and must not block the result.
        let changesApplied;
        let hadAnyChanges;
        const succeeded = result.exitCode === 0 && !result.error && !result.aborted;
        if (!succeeded) {
            changesApplied = true;
            hadAnyChanges = false;
        }
        else if (!result.patchPath) {
            changesApplied = false;
            hadAnyChanges = false;
        }
        else {
            const patchText = await Bun.file(result.patchPath).text();
            if (!patchText.trim()) {
                changesApplied = true;
                hadAnyChanges = false;
            }
            else {
                const normalized = patchText.endsWith("\n") ? patchText : `${patchText}\n`;
                // Idempotence: declare a no-op only when the reverse patch applies AND
                // the forward patch does not. `--reverse --check` alone can theoretically
                // succeed if the file happens to carry the postimage at another location
                // via git-apply's fuzz factor; requiring the forward check to fail
                // removes that ambiguity while still catching true already-applied
                // runs. Reads only — neither call touches the worktree, unlike
                // `--3way --check`, which exits 0 even when the real apply would
                // leave conflict markers and unmerged index entries.
                const [alreadyApplied, forwardApplies] = await Promise.all([
                    repo.canApplyPatch(normalized, { reverse: true }).catch(() => false),
                    repo.canApplyPatch(normalized, {}).catch(() => false),
                ]);
                hadAnyChanges = false;
                if (alreadyApplied && !forwardApplies) {
                    changesApplied = true;
                }
                else if (forwardApplies) {
                    changesApplied = true;
                    try {
                        await repo.applyPatch(normalized, {});
                        hadAnyChanges = true;
                    }
                    catch {
                        changesApplied = false;
                    }
                }
                else {
                    changesApplied = false;
                }
            }
        }
        let summary;
        if (changesApplied) {
            summary = hadAnyChanges ? "\n\nApplied patches: yes" : "\n\nNo changes to apply.";
        }
        else {
            // Nested apply is skipped when the root patch did not apply; the
            // persisted nested patches are the parent's only pointer to that work.
            summary = renderIsolationSummary({
                kind: "not-applied",
                rootPatchPath: result.patchPath,
                nestedPatchPaths: result.nestedPatchPaths,
            });
        }
        return { summary, changesApplied, hadAnyChanges, mergedBranchForNestedPatches: false };
    }
    catch (mergeErr) {
        return {
            summary: renderIsolationSummary({
                kind: "merge-error",
                error: mergeErr instanceof Error ? mergeErr.message : String(mergeErr),
                branchName: result.branchName,
                rootPatchPath: result.patchPath,
                nestedPatchPaths: result.nestedPatchPaths,
            }),
            changesApplied: false,
            hadAnyChanges: false,
            mergedBranchForNestedPatches: false,
        };
    }
}
/**
 * Apply nested-repo patches after the parent merge phase. Centralizes the
 * three-way gate (exitCode/aborted, patch-mode failed parent, branch-mode
 * branch-merged) and the non-fatal failure handling so `TaskTool` and the
 * eval `agent()` bridge use one implementation.
 *
 * Returns a system-notification suffix to append to the parent merge summary,
 * or an empty string when nothing was applied or the nested apply succeeded.
 */
export async function applyEligibleNestedPatches(opts) {
    const { result, repoRoot, mergeMode, changesApplied, mergedBranchForNestedPatches, commitMessage } = opts;
    if (mergeMode === "patch" && changesApplied === false)
        return "";
    const nestedPatches = result.nestedPatches ?? [];
    const eligible = nestedPatches.length > 0 &&
        result.exitCode === 0 &&
        !result.aborted &&
        (mergeMode !== "branch" || mergedBranchForNestedPatches);
    if (!eligible)
        return "";
    try {
        const warnings = await applyNestedPatches(repoRoot, nestedPatches, commitMessage);
        if (warnings.length === 0)
            return "";
        return `\n\n<system-notification>${warnings.join("\n")}</system-notification>`;
    }
    catch (applyErr) {
        // Nested patch failures are non-fatal to the parent merge, but the patch
        // files are the only surviving copy of that work — name them.
        return renderIsolationSummary({
            kind: "nested-apply-failed",
            error: applyErr instanceof Error ? applyErr.message : String(applyErr),
            nestedPatchPaths: result.nestedPatchPaths,
        });
    }
}
