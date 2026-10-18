import { isEnoent } from "@rva/utils";
import { InternalUrlRouter } from "../internal-urls";
/**
 * Load the session's active overall plan for subagent handoff.
 *
 * Returns the plan referenced by `planReferencePath` when it exists on disk with
 * non-empty content, or `undefined` when there is no plan (the file is absent or
 * empty). This mirrors `AgentSession.#buildPlanReferenceMessage`'s gating so a
 * subagent sees exactly the plan the main agent treats as its active reference.
 *
 * Callers MUST skip this during plan mode itself — read-only plan exploration
 * uses a different prompt and a draft plan should not be handed off as approved.
 */
export async function loadOverallPlanReference(planReferencePath, localProtocolOptions) {
    const resolved = await InternalUrlRouter.instance().requireLocal(planReferencePath, "load plan from", { localProtocolOptions }, { create: true });
    let content;
    try {
        content = await Bun.file(resolved).text();
    }
    catch (error) {
        if (isEnoent(error))
            return undefined;
        throw error;
    }
    if (!content.trim())
        return undefined;
    return { path: planReferencePath, content };
}
