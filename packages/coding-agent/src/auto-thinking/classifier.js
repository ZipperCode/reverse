import { judgeQuestions, renderQuestion } from "@rva/ai";
import { getSupportedEfforts } from "@rva/catalog/model-thinking";
import { resolveJudge, sharedJudgmentCache } from "../judgment";
import questionFile from "../prompts/judge/auto-thinking.json" with { type: "json" };
import { clampAutoThinkingEffort } from "@rva/tui/thinking";
import { preprocessTinyMessage } from "../tiny/message-preproc";
import { cfgProvidersAutoThinkingMaxEffort } from "../session/settings";
const LEVEL_EFFORT = {
    low: "low" /* Effort.Low */,
    medium: "medium" /* Effort.Medium */,
    high: "high" /* Effort.High */,
    xhigh: "xhigh" /* Effort.XHigh */,
    max: "max" /* Effort.Max */,
};
const BUCKET_EFFORT = {
    trivial: "low" /* Effort.Low */,
    moderate: "high" /* Effort.High */,
    hard: "xhigh" /* Effort.XHigh */,
};
/**
 * The on-device bucket question, the effort ladder (levels by how open-ended
 * the problem is, `max` last), and the solution-space instructions, which
 * reuse the ladder's levels.
 */
const QUESTIONS = judgeQuestions(questionFile);
/**
 * Build the question set for one input kind. Only the instructions differ
 * between kinds; every kind shares the ladder's levels and the bucket criteria.
 */
function buildQuestionSet(instructions, bucketInstructions) {
    const ladder = { ...QUESTIONS.level, instructions };
    const { max: _max, ...levels } = ladder.criteria;
    return {
        bucket: { ...QUESTIONS.bucket, instructions: bucketInstructions },
        level: { ...renderQuestion(ladder, {}), criteria: levels },
        levelWithMax: renderQuestion(ladder, { withMax: true }),
    };
}
const REQUEST_QUESTIONS = buildQuestionSet(QUESTIONS.level.instructions, QUESTIONS.bucket.instructions);
const SOLUTION_SPACE_QUESTIONS = buildQuestionSet(QUESTIONS.solutionSpace.instructions, renderQuestion(QUESTIONS.solutionSpace, {}).instructions);
/**
 * Highest effort this turn's classification may resolve to: the configured
 * ceiling, further limited by what the target model actually exposes. The
 * default keeps `auto` one tier below the top, so only an explicit
 * `ultrathink` reaches {@link Effort.Max}.
 */
function autoEffortCeiling(deps) {
    if (cfgProvidersAutoThinkingMaxEffort.get(deps.settings) !== "max" /* Effort.Max */)
        return "xhigh" /* Effort.XHigh */;
    return getSupportedEfforts(deps.model).includes("max" /* Effort.Max */) ? "max" /* Effort.Max */ : "xhigh" /* Effort.XHigh */;
}
/**
 * Classify `input` and return a concrete effort clamped to `deps.model`,
 * or `undefined` when the model has no controllable effort surface (auto has
 * nothing to pick — the caller leaves the prior reasoning level in place).
 * @throws when the backend cannot produce a usable classification.
 */
export async function classifyDifficulty(input, deps) {
    const judge = resolveJudge({
        settings: deps.settings,
        registry: deps.registry,
        sessionModel: deps.model,
        sessionId: deps.sessionId,
        metadataResolver: deps.metadataResolver,
        purpose: "auto-thinking",
        onUsage: deps.onUsage,
        telemetry: deps.telemetry,
        cache: sharedJudgmentCache(),
    });
    const solutionSpace = input.solutionSpace?.trim();
    const state = solutionSpace
        ? { solution_space: preprocessTinyMessage(solutionSpace) }
        : { request: preprocessTinyMessage(input.request) };
    const questions = solutionSpace ? SOLUTION_SPACE_QUESTIONS : REQUEST_QUESTIONS;
    const options = { signal: deps.signal };
    const classified = await judge.withCandidate(async (candidate, kind) => {
        // The 3-bucket local question cannot select `max`, so its ceiling stays at
        // XHigh whatever the setting says — otherwise a sparse ladder would snap its
        // `hard` bucket up to a tier it never chose.
        if (kind === "local") {
            const { answers } = await candidate.judge({ state, questions: { bucket: questions.bucket } }, options);
            return { effort: BUCKET_EFFORT[answers.bucket.choice], ceiling: "xhigh" /* Effort.XHigh */ };
        }
        const ceiling = autoEffortCeiling(deps);
        const level = ceiling === "max" /* Effort.Max */ ? questions.levelWithMax : questions.level;
        const { answers } = await candidate.judge({ state, questions: { level } }, options);
        return { effort: LEVEL_EFFORT[answers.level.choice], ceiling };
    }, options);
    // The successful branch's ceiling goes into the clamp itself: capping the
    // request alone is not enough, because a sparse ladder snaps an excluded
    // request back up.
    return clampAutoThinkingEffort(deps.model, classified.effort, classified.ceiling);
}
