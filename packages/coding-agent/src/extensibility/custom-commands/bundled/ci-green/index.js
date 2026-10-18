import * as vcs from "@rva/natives/vcs";
import { prompt } from "@rva/utils";
import ciGreenRequestTemplate from "../../../../prompts/ci-green-request.md" with { type: "text" };
async function getHeadTag(api) {
    try {
        return (await vcs.requireGit(api.cwd).tagsAt("HEAD"))[0];
    }
    catch {
        return undefined;
    }
}
async function getCurrentBranch(api) {
    try {
        return (await vcs.git(api.cwd)?.currentBranch()) ?? "HEAD";
    }
    catch {
        return "HEAD";
    }
}
async function getPushRemote(api, branch) {
    try {
        const repository = vcs.git(api.cwd);
        return ((await repository?.configGet(`branch.${branch}.pushRemote`)) ??
            (await repository?.configGet(`branch.${branch}.remote`)) ??
            undefined);
    }
    catch {
        return undefined;
    }
}
async function getHeadTagContext(api) {
    const branch = await getCurrentBranch(api);
    const [headTag, pushRemote] = await Promise.all([getHeadTag(api), getPushRemote(api, branch)]);
    return {
        headTag,
        branch,
        remote: pushRemote ?? "origin",
    };
}
export class GreenCommand {
    api;
    name = "green";
    description = "Generate a prompt to iterate on CI failures until the branch is green";
    constructor(api) {
        this.api = api;
    }
    async execute(_args, _ctx) {
        const { headTag, branch, remote } = await getHeadTagContext(this.api);
        return prompt.render(ciGreenRequestTemplate, { headTag, branch, remote });
    }
}
