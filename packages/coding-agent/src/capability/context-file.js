/**
 * Context Files Capability
 *
 * System instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, etc.) that provide
 * persistent guidance to the agent.
 */
import * as path from "node:path";
import { defineCapability } from ".";
export const contextFileCapability = defineCapability({
    id: "context-files",
    displayName: "Context Files",
    description: "Persistent instruction files (CLAUDE.md, AGENTS.md, etc.) that guide agent behavior",
    // Deduplicate by scope: one user-level file, and one project-level file per directory depth.
    // Within each depth level, higher-priority providers shadow lower-priority ones.
    // This supports monorepo hierarchies where AGENTS.md exists at multiple ancestor levels.
    // Clamp depth >= 0: files inside config subdirectories of an ancestor (e.g. .claude/, .github/)
    // are same-scope as the ancestor itself.
    key: file => {
        const scope = file.level === "user" ? "user" : `project:${Math.max(0, file.depth ?? 0)}`;
        // Path, not basename: two extra files can share a depth (a walked ancestor and
        // the primary checkout of a sibling worktree) and must both survive.
        return file.additive ? `${scope}:additive:${path.resolve(file.path)}` : scope;
    },
    toExtensionId: file => `context-file:${file.level}:${path.basename(file.path)}`,
    validate: file => {
        if (!file.path)
            return "Missing path";
        if (file.content === undefined)
            return "Missing content";
        if (file.level !== "user" && file.level !== "project")
            return "Invalid level: must be 'user' or 'project'";
        return undefined;
    },
});
