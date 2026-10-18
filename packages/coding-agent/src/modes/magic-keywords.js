import { prompt } from "@rva/utils";
import jevifyNotice from "../prompts/system/jevify-notice.md" with { type: "text" };
import orchestrateNotice from "../prompts/system/orchestrate-notice.md" with { type: "text" };
import ultrathinkNotice from "../prompts/system/ultrathink-notice.md" with { type: "text" };
import workflowNotice from "../prompts/system/workflow-notice.md" with { type: "text" };
/** Hidden notice for "ultrathink": careful multi-step reasoning. */
export const ULTRATHINK_NOTICE = ultrathinkNotice.trim();
/** Hidden notice for "jevify": bulk classification through the eval kernel's `judge()`. */
export const JEVIFY_NOTICE = jevifyNotice.trim();
/** Hidden notice for "orchestrate", naming only the tools the session actually exposes. */
export function renderOrchestrateNotice({ tools }) {
    return prompt.render(orchestrateNotice, { tools }).trim();
}
/** Hidden notice for "workflowz", shaped by the active task/eval capabilities. */
export function renderWorkflowNotice({ taskBatch, scoutAvailable, evalTools, }) {
    return prompt.render(workflowNotice, { taskBatch, scoutAvailable, evalTools }).trim();
}
export const MAGIC_KEYWORDS = [
    {
        id: "ultrathink",
        word: "ultrathink",
        hue: [0, 330],
        label: "Ultrathink Keyword",
        description: "Let standalone ultrathink request maximum automatic thinking and append its hidden notice",
        requires: [],
        notice: () => ULTRATHINK_NOTICE,
    },
    {
        id: "orchestrate",
        word: "orchestrate",
        hue: [150, 280],
        label: "Orchestrate Keyword",
        description: "Let standalone orchestrate append its hidden multi-agent orchestration notice",
        // The contract is entirely about `task` subagent dispatch.
        requires: ["task"],
        notice: renderOrchestrateNotice,
    },
    {
        id: "workflow",
        word: "workflowz",
        hue: [30, 150],
        label: "Workflow Keyword",
        description: "Let standalone workflowz append its hidden eval workflow notice",
        requires: ["task", "eval"],
        notice: renderWorkflowNotice,
    },
    {
        id: "jevify",
        word: "jevify",
        hue: [300, 420],
        label: "Jevify Keyword",
        description: "Let standalone jevify append its hidden bulk-judge classification notice",
        // The contract is entirely about the eval kernel's `judge()` helper.
        requires: ["eval"],
        notice: () => JEVIFY_NOTICE,
    },
];
