/** Synthetic bridge name reserved for the `budget` helper across both runtimes. */
export const EVAL_BUDGET_BRIDGE_NAME = "__budget__";
/**
 * Resolve the current token budget snapshot for an eval cell's `budget` helper.
 * The returned object is JSON-passed verbatim by the bridge transport; kernel
 * helpers read `.total`/`.spent`/`.hard` directly.
 */
export async function runEvalBudget(_args, options) {
    const turn = options.session.getTurnBudget?.();
    if (turn && turn.total !== null) {
        return { total: turn.total, spent: turn.spent, hard: turn.hard };
    }
    const goal = options.session.getGoalModeState?.();
    if (goal?.enabled && goal.goal) {
        return {
            total: goal.goal.tokenBudget ?? null,
            spent: goal.goal.tokensUsed ?? 0,
            hard: goal.goal.tokenBudget != null,
        };
    }
    const spent = turn?.spent ?? options.session.getUsageStatistics?.()?.output ?? 0;
    return { total: null, spent, hard: false };
}
