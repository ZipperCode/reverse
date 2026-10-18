import { logger, prompt, sanitizeText } from "@rva/utils";
import composerPredictionPrompt from "../../prompts/system/composer-prediction-user.md" with { type: "text" };
import { cfgComposerPredictions } from "../settings";
/** Reply the prediction prompt asks for when the model has no confident guess. */
const SKIP_REPLY = "NO_PREDICTION";
/** Longer replies are rambling, not a message the user would type; drop them. */
const MAX_PREDICTION_LENGTH = 500;
/**
 * Output cap for the side turn. Providers key prompt caches on reasoning parameters, so the
 * prediction runs at the lowest effort only where that change rides a per-message control (see
 * `minimizeEffort`), keeps the session's reasoning elsewhere, and sends this cap only where it
 * leaves reasoning unchanged. Leaves room for a short reasoning pass on effort models.
 */
const PREDICTION_MAX_TOKENS = 1024;
/** A prediction that has not arrived by then is no longer worth paying for or showing. */
const PREDICTION_DEADLINE_MS = 15000;
/** Usage-ledger purpose, so session totals and `/stats` include prediction requests. */
const USAGE_PURPOSE = "composer-prediction";
/** One pair of double quotes or backticks around the whole reply. */
const WRAPPING_QUOTES = /^(?:"([^"]*)"|“([^“”]*)”|`([^`]*)`)$/;
/**
 * Normalize a prediction reply to the single line the composer shows, or
 * `undefined` when the model skipped, rambled, or replied with nothing usable.
 */
export function parseComposerPrediction(reply) {
    let text = sanitizeText(reply).replace(/\s+/g, " ").trim();
    const quoted = WRAPPING_QUOTES.exec(text);
    if (quoted)
        text = (quoted[1] ?? quoted[2] ?? quoted[3] ?? "").trim();
    if (!text || text.includes(SKIP_REPLY) || text.length > MAX_PREDICTION_LENGTH)
        return undefined;
    return text;
}
/**
 * Composer predictions: once a turn completes, run an ephemeral side turn on
 * the session's model and context (the same prompt prefix, so it reads the
 * prompt cache) asking for the user's likely next message, then offer it as
 * ghost text in the empty composer. Tab or Right inserts it; nothing is sent.
 */
export class ComposerPredictionController {
    #ctx;
    #deadlineMs;
    #abort;
    #prediction;
    constructor(ctx, options = {}) {
        this.#ctx = ctx;
        this.#deadlineMs = options.deadlineMs ?? PREDICTION_DEADLINE_MS;
    }
    /** The prediction for the conversation as it stands now, if one is ready. */
    get text() {
        const prediction = this.#prediction;
        if (!prediction || !this.#isCurrent(prediction.source))
            return undefined;
        return prediction.text;
    }
    /** Predict the next message for the turn that just completed, superseding any earlier prediction. */
    request() {
        this.cancel();
        if (!cfgComposerPredictions.get(this.#ctx.settings))
            return;
        // A focused subagent's "user" is the parent agent, not the person at the composer.
        if (this.#ctx.focusedAgentId !== undefined)
            return;
        const session = this.#ctx.viewSession;
        // Any draft, even whitespace, keeps the ghost hidden (it shows only over a prefix of the
        // prediction), and a compaction would rewrite the history the prediction reads: skip the
        // billed request either way.
        if (!session.model || session.isStreaming || session.isCompacting || this.#ctx.editor.getText())
            return;
        const abort = new AbortController();
        this.#abort = abort;
        const source = {
            session,
            lastMessage: session.messages.at(-1),
            // The journal id: after `/fresh` or with an SDK provider id, `session.sessionId` is the
            // provider-facing id, which the usage ledger rejects.
            sessionId: session.sessionManager.getSessionId(),
            leafId: session.sessionManager.getLeafId(),
        };
        void this.#run(source, abort);
    }
    /** Abort an in-flight prediction and clear the shown one. */
    cancel() {
        this.#abort?.abort();
        this.#abort = undefined;
        if (!this.#prediction)
            return;
        this.#prediction = undefined;
        this.#ctx.ui.requestRender();
    }
    async #run(source, abort) {
        try {
            const { replyText, assistantMessage } = await source.session.runEphemeralTurn({
                promptText: prompt.render(composerPredictionPrompt, { skip: SKIP_REPLY }),
                maxTokens: source.session.ephemeralMaxTokensPreservesRequest() ? PREDICTION_MAX_TOKENS : undefined,
                minimizeEffort: true,
                signal: AbortSignal.any([abort.signal, AbortSignal.timeout(this.#deadlineMs)]),
            });
            // Paid for even when the reply arrives too late to show.
            this.#recordUsage(source, assistantMessage);
            if (this.#abort !== abort || !this.#isCurrent(source))
                return;
            const text = parseComposerPrediction(replyText);
            if (!text)
                return;
            this.#prediction = { text, source };
            this.#ctx.ui.requestRender();
        }
        catch (error) {
            if (!abort.signal.aborted)
                logger.debug("Composer prediction failed", { error: String(error) });
        }
        finally {
            if (this.#abort === abort)
                this.#abort = undefined;
        }
    }
    #recordUsage(source, message) {
        try {
            source.session.sessionManager.appendModelUsage({
                purpose: USAGE_PURPOSE,
                api: message.api,
                provider: message.provider,
                model: message.model,
                usage: message.usage,
                stopReason: message.stopReason,
            }, { sessionId: source.sessionId, parentId: source.leafId });
        }
        catch (error) {
            logger.debug("Failed to persist composer prediction usage", { error: String(error) });
        }
    }
    #isCurrent(source) {
        return this.#ctx.viewSession === source.session && source.session.messages.at(-1) === source.lastMessage;
    }
}
