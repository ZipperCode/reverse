import * as vcs from "@rva/natives/vcs";
import { runGitTui as runView, showGitOverlay as showOverlay, } from "@rva/tui/apps/git/git-tui";
import { generateGitCommit } from "../commit/conventional/service";
import { aiStage } from "./git-tui/ai-stage";
import { AvatarLoader } from "./git-tui/avatar";
import { GitModel } from "./git-tui/state";
async function createHost(options) {
    const cwd = options.cwd ?? process.cwd();
    const repo = vcs.git(cwd);
    const root = repo?.info().repoRoot ?? null;
    if (!root)
        throw new Error(`Not a git repository: ${cwd}`);
    let pinnedSha;
    if (options.revision) {
        pinnedSha = (await repo?.resolveRef(options.revision)) ?? undefined;
        if (!pinnedSha)
            throw new Error(`Cannot resolve revision: ${options.revision}`);
    }
    return {
        model: new GitModel(root, { pinnedSha }),
        createAvatarSource: onReady => new AvatarLoader(onReady),
        aiStage,
        generateCommitMessage: generateGitCommit,
    };
}
/** Open repository review on an existing interactive session. */
export async function showGitOverlay(ui, options = {}) {
    await showOverlay(ui, await createHost(options));
}
/** Run standalone repository review with application-owned capabilities. */
export async function runGitTui(options = {}) {
    await runView(await createHost(options));
}
