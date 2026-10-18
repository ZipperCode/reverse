import { type } from "@rva/omptype";
import * as vcs from "@rva/natives/vcs";
import { DEFAULT_CONVENTIONAL_GENERATION_CONFIG } from "../../../commit/conventional/config";
import { extractScopeCandidates } from "../../../commit/conventional/scope";
import { renderStat } from "../../utils";
import { EXCLUDED_LOCK_FILES } from "../lock-files";
function isExcludedFile(path) {
    const basename = path.split("/").pop() ?? path;
    return EXCLUDED_LOCK_FILES.has(basename);
}
function filterExcludedFiles(files) {
    const filtered = [];
    const excluded = [];
    for (const file of files) {
        if (isExcludedFile(file)) {
            excluded.push(file);
        }
        else {
            filtered.push(file);
        }
    }
    return { filtered, excluded };
}
const gitOverviewSchema = type({
    "staged?": type("boolean").describe("use staged changes (default true)"),
    "include_untracked?": type("boolean").describe("include untracked when unstaged"),
});
export function createGitOverviewTool(cwd, state) {
    const repo = vcs.requireGit(cwd);
    return {
        name: "git_overview",
        label: "Git Overview",
        description: "Return staged files, diff stat summary, and numstat entries.",
        parameters: gitOverviewSchema,
        async execute(_toolCallId, params) {
            const staged = params.staged ?? true;
            const allFiles = await repo.changedFiles({ cached: staged });
            const { filtered: files, excluded } = filterExcludedFiles(allFiles);
            const allNumstat = await repo.numstat({ cached: staged });
            const stat = renderStat(allNumstat);
            const numstat = allNumstat
                .filter(entry => !isExcludedFile(entry.path))
                .map(entry => ({ path: entry.path, additions: entry.added ?? 0, deletions: entry.removed ?? 0 }));
            const scopeResult = extractScopeCandidates(numstat, DEFAULT_CONVENTIONAL_GENERATION_CONFIG);
            const untrackedFiles = !staged && params.include_untracked ? await repo.lsFiles(true, true) : undefined;
            const snapshot = {
                files,
                stat,
                numstat,
                scopeCandidates: scopeResult.scopeCandidates,
                isWideScope: scopeResult.isWide,
                untrackedFiles,
                excludedFiles: excluded.length > 0 ? excluded : undefined,
            };
            state.overview = snapshot;
            return {
                content: [{ type: "text", text: JSON.stringify(snapshot, null, 2) }],
                details: snapshot,
            };
        },
    };
}
