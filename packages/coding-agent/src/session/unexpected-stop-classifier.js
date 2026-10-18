import { judgeQuestions } from "@rva/ai";
import { logger } from "@rva/utils";
import { resolveJudge, sharedJudgmentCache } from "../judgment";
import questionFile from "../prompts/judge/unexpected-stop.json" with { type: "json" };
/**
 * Yes-probability at or above which a turn counts as an unexpected stop.
 * Keyword judges answer exactly 0 or 1; TypeSafe's calibrated probability
 * lands in between, and a coin-flip message must not trigger a retry.
 */
const UNEXPECTED_STOP_THRESHOLD = 0.5;
/**
 * The yes/no `stopped` question. Criteria stay bulleted examples: on
 * lfm2-1.2b / qwen2.5-1.5b, prose criteria cost ~3 points of recall.
 */
const QUESTIONS = judgeQuestions(questionFile);
/**
 * Leading characters of the user's request shown to the judge: enough for the
 * ask and its constraints ("don't change anything") without letting a pasted
 * log crowd a small judge model's context.
 */
const REQUEST_CHARS = 2000;
/** Detects terminal turns eligible for mechanical recovery or smart classification. */
export function isUnexpectedStopCandidate(message) {
    if (message.stopReason !== "stop")
        return false;
    let hasContent = false;
    for (const content of message.content) {
        // A tool call or image is deliverable output; retrying would repeat it.
        if (content.type === "toolCall" || content.type === "image")
            return false;
        if (content.type === "text" && /\S/.test(content.text)) {
            hasContent = true;
        }
        // A signed thinking-only stop is still a candidate: reasoning models can
        // trap the intended response (or a truncated fragment) in a thinking block
        // with no text, or end on a signature-only block whose reasoning text was
        // withheld. #isEmptyAssistantStop treats a non-whitespace signature as
        // terminal (not empty), so such stops bypass the empty-stop path entirely.
        // Match that predicate here — unsigned thinking-only stops stay with the
        // empty-stop retry path (and its cap) rather than being re-handled here.
        if (content.type === "thinking" && /\S/.test(content.thinkingSignature ?? "")) {
            hasContent = true;
        }
    }
    return hasContent;
}
/** `true` for an unexpected stop, `false` for a normal end of turn, `undefined` when no judge could answer. */
export async function classifyUnexpectedStop(stop, deps) {
    try {
        const judge = resolveJudge({
            settings: deps.settings,
            registry: deps.registry,
            sessionModel: deps.model,
            sessionId: deps.sessionId,
            metadataResolver: deps.metadataResolver,
            purpose: "unexpected-stop",
            onUsage: deps.onUsage,
            telemetry: deps.telemetry,
            cache: sharedJudgmentCache(),
        });
        const request = stop.request?.trim().slice(0, REQUEST_CHARS);
        const state = request ? { request, message: stop.message } : { message: stop.message };
        const { answers } = await judge.judge({ state, questions: { stopped: QUESTIONS.stopped } }, { signal: deps.signal });
        return answers.stopped.noul >= UNEXPECTED_STOP_THRESHOLD;
    }
    catch (error) {
        logger.debug("unexpected-stop: classification failed", {
            error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
    }
}
