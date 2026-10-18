import { type } from "@rva/omptype";
import { prompt } from "@rva/utils";
import goalDescription from "../../prompts/tools/goal.md" with { type: "text" };
import { ToolError } from "@rva/tui/tools/tool-errors";
import { completionBudgetReport, remainingTokens } from "../runtime";
const goalSchema = type({
    op: type("'create' | 'get' | 'complete' | 'resume' | 'drop'").describe("goal operation"),
    "objective?": type("string").describe("goal objective"),
    "token_budget?": type("number.integer").describe("token budget"),
});
export function buildGoalToolResponse(goal, options) {
    const resolvedGoal = goal ?? null;
    return {
        goal: resolvedGoal,
        remainingTokens: remainingTokens(resolvedGoal),
        completionBudgetReport: options?.includeCompletionReport && resolvedGoal?.status === "complete"
            ? completionBudgetReport(resolvedGoal)
            : null,
    };
}
function validateCreateParams(params) {
    const objective = params.objective?.trim();
    if (!objective) {
        throw new ToolError("objective is required when op=create");
    }
    const tokenBudget = params.token_budget;
    if (tokenBudget !== undefined && (!Number.isInteger(tokenBudget) || tokenBudget <= 0)) {
        throw new ToolError("token_budget must be a positive integer when provided");
    }
    return { objective, tokenBudget };
}
export class GoalTool {
    name = "goal";
    /** Goal ops touch only session state: `get` reads it; the rest change the goal, so `always-ask` still prompts. */
    approval = (args) => args !== null && typeof args === "object" && "op" in args && args.op === "get" ? "read" : "write";
    label = "Goal";
    description = prompt.render(goalDescription);
    parameters = goalSchema;
    strict = true;
    intent = "omit";
    #session;
    constructor(session) {
        this.#session = session;
    }
    async execute(_toolCallId, params, _signal, _onUpdate, _context) {
        const runtime = this.#session.getGoalRuntime?.();
        if (!runtime) {
            throw new ToolError("Goal mode is not active.");
        }
        let response;
        if (params.op === "create") {
            const created = await runtime.createGoal(validateCreateParams(params));
            response = buildGoalToolResponse(created.goal);
        }
        else if (params.op === "get") {
            const state = this.#session.getGoalModeState?.();
            response = buildGoalToolResponse(state?.goal ?? null);
        }
        else if (params.op === "resume") {
            const resumed = await runtime.resumeGoal();
            response = buildGoalToolResponse(resumed.goal);
        }
        else if (params.op === "drop") {
            const dropped = await runtime.dropGoal();
            response = buildGoalToolResponse(dropped ?? null);
        }
        else {
            const completed = await runtime.completeGoalFromTool();
            response = buildGoalToolResponse(completed, { includeCompletionReport: true });
        }
        let text;
        if (response.goal) {
            text = `Goal: ${response.goal.objective}\nStatus: ${response.goal.status}\nTokens: ${response.goal.tokensUsed} used`;
            if (response.goal.tokenBudget !== undefined) {
                text += ` / ${response.goal.tokenBudget} budget`;
            }
            if (response.remainingTokens !== null) {
                text += `\nRemaining tokens: ${response.remainingTokens}`;
            }
            if (response.completionBudgetReport) {
                text += `\n\n${response.completionBudgetReport}`;
            }
        }
        else {
            text = "No active goal.";
        }
        return {
            content: [{ type: "text", text }],
            details: {
                op: params.op,
                goal: response.goal,
                remainingTokens: response.remainingTokens,
                completionBudgetReport: response.completionBudgetReport,
            },
        };
    }
}
