import { createAnalyzeFileTool } from "./analyze-file";
import { createGitFileDiffTool } from "./git-file-diff";
import { createGitHunkTool } from "./git-hunk";
import { createGitOverviewTool } from "./git-overview";
import { createProposeChangelogTool } from "./propose-changelog";
import { createProposeCommitTool } from "./propose-commit";
import { createRecentCommitsTool } from "./recent-commits";
import { createSplitCommitTool } from "./split-commit";
export function createCommitTools(options) {
    const tools = [
        createGitOverviewTool(options.cwd, options.state),
        createGitFileDiffTool(options.cwd, options.state),
        createGitHunkTool(options.cwd),
        createRecentCommitsTool(options.cwd),
    ];
    if (options.enableAnalyzeFiles ?? true) {
        tools.push(createAnalyzeFileTool({
            cwd: options.cwd,
            authStorage: options.authStorage,
            modelRegistry: options.modelRegistry,
            settings: options.settings,
            spawns: options.spawns,
            state: options.state,
        }));
    }
    tools.push(createProposeChangelogTool(options.state, options.changelogTargets), createProposeCommitTool(options.cwd, options.state), createSplitCommitTool(options.cwd, options.state, options.changelogTargets));
    return tools;
}
