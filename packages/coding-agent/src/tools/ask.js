/**
 * Ask Tool - Interactive user prompting during execution
 *
 * Use this tool when you need to ask the user questions during execution.
 * This allows you to:
 *   1. Gather user preferences or requirements
 *   2. Clarify ambiguous instructions
 *   3. Get decisions on implementation choices as you work
 *   4. Offer choices to the user about what direction to take
 *
 * Usage notes:
 *   - Users will always be able to select "Other" to provide custom text input
 *   - Use multi: true to allow multiple answers to be selected for a question
 *   - Use recommended: <index> to mark the default option; "(Recommended)" suffix is added automatically
 *   - Questions may time out and auto-select the recommended option (configurable, disabled in plan mode)
 */
import { type as arkType } from "@rva/omptype";
import { validateToolArguments } from "@rva/ai";
import { replaceTabs, TERMINAL, truncateToWidth } from "@rva/tui";
import { isRecord, logger, prompt, untilAborted } from "@rva/utils";
import { formatKeyHint, formatKeyHints } from "@rva/tui/app-keybindings";
import { editorKey, editorKeys } from "@rva/tui/chrome/keybinding-hints";
import { theme } from "@rva/tui/theme";
import askDescription from "../prompts/tools/ask.md" with { type: "text" };
import { vocalizer } from "../tts/vocalizer";
import { disambiguateDisplayLabels, sanitizeCarriageReturns, TRUNCATE_LENGTHS, } from "@rva/tui/render/render-utils";
import { shiftImageMarkers } from "@rva/tui/prompt/composer-attachments";
import { ToolAbortError } from "./tool-errors";
import { sessionLocalProtocolOptions } from "../internal-urls/context";
import { cfgAskNotify, askTimeoutMs } from "../modes/settings";
import { renderAttachmentSourceNotice } from "../session/attachment-source-notice";
import { cfgSpeechEnabled } from "../tts/settings";
import { describeAttachedImagesForTextModel, shouldDescribeImagesForTextModel } from "../utils/image-vision-fallback";
// =============================================================================
// Types
// =============================================================================
export const OTHER_OPTION = "Other (type your own)";
const CHAT_ABOUT_THIS_OPTION = "Chat about this";
const NEXT_OPTION = "Next →";
const RESERVED_OPTION_LABELS = {
    [OTHER_OPTION]: true,
    [CHAT_ABOUT_THIS_OPTION]: true,
    [NEXT_OPTION]: true,
};
const OptionItem = arkType({
    label: arkType("string"),
    "description?": arkType("string"),
    "preview?": arkType("string").describe("rich preview"),
});
const QuestionItem = arkType({
    id: arkType("string"),
    question: arkType("string"),
    "header?": arkType("string").describe("display chip"),
    options: OptionItem.array(),
    "multi?": arkType("boolean"),
    "recommended?": arkType("number").describe("0-based default index"),
}).narrow((question, ctx) => {
    const reserved = question.options.find(option => RESERVED_OPTION_LABELS[option.label] === true);
    return (reserved === undefined ||
        ctx.mustBe(`defined with option labels that do not collide with reserved runtime labels: ${reserved.label}`));
});
const askSchema = arkType({
    questions: QuestionItem.array().atLeastLength(1),
});
const askRecoveryTool = { name: "ask", description: "", parameters: askSchema };
/**
 * Recover valid questions from a persisted `ask` tool call for `/tree` re-answer.
 * Apply live tool-call normalization first so optional null placeholders in saved
 * arguments do not prevent reopening; malformed questions still fail closed.
 */
export function recoverAskQuestions(toolCallArguments) {
    if (!isRecord(toolCallArguments))
        return undefined;
    let normalized;
    try {
        normalized = validateToolArguments(askRecoveryTool, {
            type: "toolCall",
            id: "",
            name: "ask",
            arguments: toolCallArguments,
        });
    }
    catch {
        return undefined;
    }
    const parsed = askSchema(normalized);
    if (parsed instanceof arkType.errors)
        return undefined;
    return parsed.questions;
}
function getAskOptionLabel(option) {
    return option.label;
}
function getSelectOptionLabel(option) {
    return typeof option === "string" ? option : option.label;
}
function toSelectOption(option, label = option.label) {
    return option.description ? { label, description: option.description } : label;
}
// =============================================================================
// Constants
// =============================================================================
const RECOMMENDED_SUFFIX = " (Recommended)";
// Window after the timeout deadline within which an `undefined` selection is
// attributed to a UI-enforced timeout (for surfaces that close the dialog at
// the deadline but never invoke `onTimeout`). Cancels beyond it are user Esc.
const TIMEOUT_DETECTION_TOLERANCE_MS = 1000;
function getDoneOptionLabel() {
    return `${theme.status.success} Done selecting`;
}
/** Add "(Recommended)" suffix to the option at the given index if not already present */
function addRecommendedSuffix(options, recommendedIndex) {
    if (recommendedIndex === undefined || recommendedIndex < 0 || recommendedIndex >= options.length) {
        return options.map(option => toSelectOption(option));
    }
    return options.map((option, i) => {
        const label = i === recommendedIndex && !option.label.endsWith(RECOMMENDED_SUFFIX)
            ? option.label + RECOMMENDED_SUFFIX
            : option.label;
        return toSelectOption(option, label);
    });
}
function getAutoSelectionOnTimeout(options, recommended) {
    if (options.length === 0)
        return [];
    if (typeof recommended === "number" && recommended >= 0 && recommended < options.length) {
        return [options[recommended].label];
    }
    return [options[0].label];
}
/** Strip "(Recommended)" suffix from a label */
function stripRecommendedSuffix(label) {
    return label.endsWith(RECOMMENDED_SUFFIX) ? label.slice(0, -RECOMMENDED_SUFFIX.length) : label;
}
async function askSingleQuestion(ui, question, questionOptions, multi, options = {}) {
    const { recommended, timeout, signal, initialSelection, navigation } = options;
    const doneLabel = getDoneOptionLabel();
    let selectedOptions = [...(initialSelection?.selectedOptions ?? [])];
    let customInput = initialSelection?.customInput;
    const note = initialSelection?.note;
    let timedOut = false;
    const selectOption = async (prompt, optionsToShow, initialIndex, marker) => {
        let timeoutTriggered = false;
        const onTimeout = () => {
            timeoutTriggered = true;
        };
        let navigationAction;
        const questionHint = navigation ? `${formatKeyHints(["left", "right"])} question  ` : "";
        const helpText = `${editorKeys("tui.select.up", "tui.select.down")} navigate  ${formatKeyHint("enter")} select  ${questionHint}${editorKey("tui.select.cancel")} cancel`;
        const timeoutMs = typeof timeout === "number" && timeout > 0 ? timeout : undefined;
        const timeoutController = timeoutMs === undefined ? undefined : new AbortController();
        const dialogSignal = signal && timeoutController
            ? AbortSignal.any([signal, timeoutController.signal])
            : (timeoutController?.signal ?? signal);
        let timeoutId;
        let timeoutStartedMs = Date.now();
        const armFallbackTimeout = (durationMs) => {
            clearTimeout(timeoutId);
            timeoutStartedMs = Date.now();
            timeoutId = setTimeout(() => {
                timeoutTriggered = true;
                timeoutController?.abort();
            }, durationMs);
        };
        const dialogOptions = {
            initialIndex,
            timeout,
            signal: dialogSignal,
            outline: true,
            onTimeout,
            onTimeoutStart: timeoutMs === undefined ? undefined : () => armFallbackTimeout(timeoutMs),
            onTimeoutReset: timeoutMs === undefined ? undefined : () => armFallbackTimeout(timeoutMs),
            helpText,
            selectionMarker: marker?.selectionMarker,
            checkedIndices: marker?.checkedIndices,
            markableCount: marker?.markableCount,
            onLeft: navigation?.allowBack
                ? () => {
                    navigationAction = "back";
                }
                : undefined,
            onRight: navigation?.allowForward
                ? () => {
                    navigationAction = "forward";
                }
                : undefined,
        };
        try {
            const runSelect = () => {
                const selection = ui.select(prompt, optionsToShow, dialogOptions);
                if (timeoutMs !== undefined && !ui.timeoutStartsOnPresentation) {
                    armFallbackTimeout(timeoutMs);
                }
                return selection;
            };
            const choice = dialogSignal ? await untilAborted(dialogSignal, runSelect) : await runSelect();
            if (!timeoutTriggered && choice === undefined && typeof timeout === "number") {
                // Fallback for UI surfaces that enforce `timeout` without invoking
                // `onTimeout`: their auto-cancel resolves right at the deadline. A
                // cancel arriving well past the deadline is a deliberate user Esc on
                // a surface that kept the dialog open — keep treating it as a cancel.
                const elapsed = Date.now() - timeoutStartedMs;
                timeoutTriggered = elapsed >= timeout && elapsed <= timeout + TIMEOUT_DETECTION_TOLERANCE_MS;
            }
            return { choice, timedOut: timeoutTriggered, navigation: navigationAction };
        }
        catch (error) {
            if (timeoutTriggered && error instanceof Error && error.name === "AbortError") {
                return { choice: undefined, timedOut: true, navigation: navigationAction };
            }
            throw error;
        }
        finally {
            clearTimeout(timeoutId);
        }
    };
    const promptForCustomInput = async (title) => {
        const dialogOptions = signal ? { signal } : undefined;
        const showCustomInput = () => ui.editor(title, undefined, dialogOptions, { promptStyle: true });
        const input = signal ? await untilAborted(signal, showCustomInput) : await showCustomInput();
        return { input };
    };
    const promptWithProgress = navigation?.progressText ? `${question} (${navigation.progressText})` : question;
    if (multi) {
        const selected = new Set(selectedOptions);
        let cursorIndex = Math.min(Math.max(recommended ?? 0, 0), Math.max(questionOptions.length - 1, 0));
        const firstSelected = selectedOptions[0];
        if (firstSelected) {
            const selectedIndex = questionOptions.findIndex(option => option.label === firstSelected);
            if (selectedIndex >= 0)
                cursorIndex = selectedIndex;
        }
        while (true) {
            const opts = questionOptions.map(opt => toSelectOption(opt));
            // Arrow-key forward navigation is TUI-only; RPC clients need the Done row to advance.
            if (selected.size > 0) {
                opts.push(doneLabel);
            }
            opts.push(OTHER_OPTION);
            const checkedIndices = [];
            for (let i = 0; i < questionOptions.length; i++) {
                if (selected.has(questionOptions[i].label))
                    checkedIndices.push(i);
            }
            const prefix = selected.size > 0 ? `(${selected.size} selected) ` : "";
            const { choice, timedOut: selectTimedOut, navigation: arrowNavigation, } = await selectOption(`${prefix}${promptWithProgress}`, opts, cursorIndex, {
                selectionMarker: "checkbox",
                checkedIndices,
                markableCount: questionOptions.length,
            });
            if (arrowNavigation) {
                return { selectedOptions: Array.from(selected), customInput, note, timedOut, navigation: arrowNavigation };
            }
            if (choice === undefined) {
                if (selectTimedOut) {
                    timedOut = true;
                    break;
                }
                return { selectedOptions: Array.from(selected), customInput, note, timedOut, cancelled: true };
            }
            if (choice === doneLabel)
                break;
            if (choice === OTHER_OPTION) {
                if (selectTimedOut) {
                    timedOut = true;
                    break;
                }
                const customResult = await promptForCustomInput(`${prefix}${promptWithProgress}`);
                if (customResult.input === undefined) {
                    continue;
                }
                customInput = customResult.input;
                break;
            }
            const selectedIdx = opts.findIndex(opt => getSelectOptionLabel(opt) === choice);
            if (selectedIdx >= 0) {
                cursorIndex = selectedIdx;
            }
            if (selected.has(choice)) {
                selected.delete(choice);
            }
            else {
                selected.add(choice);
            }
            if (selectTimedOut) {
                timedOut = true;
                break;
            }
        }
        selectedOptions = Array.from(selected);
    }
    else {
        while (true) {
            const baseDisplay = addRecommendedSuffix(questionOptions, recommended);
            // Badging can collide rows (recommended `Retry now` vs a literal
            // `Retry now (Recommended)`); disambiguate display copies like
            // the rich dialog and map the choice back by identity below.
            const displayLabels = disambiguateDisplayLabels(baseDisplay.map(getSelectOptionLabel), [OTHER_OPTION]);
            const displayOptions = baseDisplay.map((option, index) => typeof option === "string" ? displayLabels[index] : { ...option, label: displayLabels[index] });
            const optionsWithNavigation = [...displayOptions, OTHER_OPTION];
            let initialIndex = recommended;
            const previouslySelected = selectedOptions[0];
            if (previouslySelected) {
                const selectedIndex = questionOptions.findIndex(option => option.label === previouslySelected);
                if (selectedIndex >= 0)
                    initialIndex = selectedIndex;
            }
            else if (customInput !== undefined) {
                initialIndex = displayOptions.length;
            }
            if (initialIndex !== undefined) {
                const maxIndex = Math.max(optionsWithNavigation.length - 1, 0);
                initialIndex = Math.max(0, Math.min(initialIndex, maxIndex));
            }
            const { choice, timedOut: selectTimedOut, navigation: arrowNavigation, } = await selectOption(promptWithProgress, optionsWithNavigation, initialIndex, {
                selectionMarker: "radio",
                markableCount: displayOptions.length,
            });
            timedOut = selectTimedOut;
            if (arrowNavigation) {
                return { selectedOptions, customInput, note, timedOut, navigation: arrowNavigation };
            }
            if (choice === undefined) {
                if (!timedOut) {
                    return { selectedOptions, customInput, note, timedOut, cancelled: true };
                }
                break;
            }
            if (choice === OTHER_OPTION) {
                if (selectTimedOut) {
                    break;
                }
                const customResult = await promptForCustomInput(promptWithProgress);
                if (customResult.input === undefined) {
                    continue;
                }
                customInput = customResult.input;
                selectedOptions = [];
                break;
            }
            // Map the displayed choice back to the offered option by identity:
            // the label itself may end with the recommendation suffix
            // (intrinsic or via `\r` normalization), so stripping would
            // corrupt it. First display match wins on identical rows.
            const pickedIndex = displayOptions.findIndex(option => getSelectOptionLabel(option) === choice);
            selectedOptions = [pickedIndex >= 0 ? questionOptions[pickedIndex].label : stripRecommendedSuffix(choice)];
            customInput = undefined;
            break;
        }
        if (timedOut && selectedOptions.length === 0 && customInput === undefined) {
            selectedOptions = getAutoSelectionOnTimeout(questionOptions, recommended);
        }
        if (navigation?.allowForward) {
            return { selectedOptions, customInput, note, timedOut, navigation: "forward" };
        }
    }
    if (timedOut && selectedOptions.length === 0 && customInput === undefined) {
        selectedOptions = getAutoSelectionOnTimeout(questionOptions, recommended);
    }
    return { selectedOptions, customInput, note, timedOut };
}
function formatQuestionResult(result) {
    const noteSuffix = result.note ? ` (note: ${result.note})` : "";
    const custom = result.customInput === undefined ? undefined : `"${result.customInput}"`;
    if (result.selectedOptions.length === 0) {
        if (custom !== undefined)
            return `${result.id}: ${custom}${noteSuffix}`;
        return result.multi ? `${result.id}: []${noteSuffix}` : `${result.id}: (cancelled)${noteSuffix}`;
    }
    const picked = result.multi ? `[${result.selectedOptions.join(", ")}]` : result.selectedOptions[0];
    const answer = custom === undefined ? picked : `${picked} + ${custom}`;
    const timeoutSuffix = result.timedOut ? " (auto-selected after timeout)" : "";
    return `${result.id}: ${answer}${timeoutSuffix}${noteSuffix}`;
}
function formatSingleQuestionResponse(result) {
    const responseParts = [];
    if (result.selectedOptions.length > 0) {
        const selectedText = result.multi
            ? `User selected: ${result.selectedOptions.join(", ")}`
            : `User selected: ${result.selectedOptions[0]}`;
        responseParts.push(result.timedOut ? `${selectedText} (auto-selected after timeout)` : selectedText);
    }
    if (result.customInput !== undefined) {
        responseParts.push(result.customInput.includes("\n")
            ? `User provided custom input:\n${result.customInput
                .split("\n")
                .map(line => `  ${line}`)
                .join("\n")}`
            : `User provided custom input: ${result.customInput}`);
    }
    if (result.note) {
        responseParts.push(result.note.includes("\n")
            ? `User added note:\n${result.note
                .split("\n")
                .map(line => `  ${line}`)
                .join("\n")}`
            : `User added note: ${result.note}`);
    }
    if (responseParts.length > 0)
        return responseParts.join("\n");
    return result.multi ? "User did not select any options" : "User cancelled the selection";
}
/**
 * Ask tool for interactive user prompting during execution.
 *
 * Allows gathering user preferences, clarifying instructions, and getting decisions
 * on implementation choices as the agent works.
 */
export class AskTool {
    session;
    name = "ask";
    approval = "read";
    label = "Ask";
    summary = "Ask the user a clarifying question";
    description;
    parameters = askSchema;
    strict = true;
    examples = [
        {
            caption: "Choice",
            call: {
                questions: [
                    {
                        id: "storage",
                        question: "Database?",
                        options: [{ label: "SQLite" }, { label: "Postgres" }],
                        recommended: 0,
                    },
                ],
            },
        },
    ];
    // Run alone in its tool batch. The interactive selector/editor is a single
    // shared UI surface (`ExtensionUiController.showHookSelector` has no queue and
    // overwrites `ctx.hookSelector` on each call), so two concurrent `ask` calls
    // would clobber each other: the second steals focus and orphans the first,
    // whose promise then hangs until the user aborts the whole turn.
    concurrency = "exclusive";
    loadMode = "discoverable";
    constructor(session) {
        this.session = session;
        this.description = prompt.render(askDescription);
    }
    static createIf(session) {
        return (session.canPromptUser ?? session.hasUI) || session.advertiseHeadlessAsk ? new AskTool(session) : null;
    }
    /** Send terminal notification when ask tool is waiting for input */
    #sendAskNotification() {
        if (!this.session.hasUI)
            return;
        const method = cfgAskNotify.get(this.session.settings);
        if (method === "off")
            return;
        TERMINAL.sendNotification({
            title: "omp",
            body: "Waiting for input",
            type: "ask",
            urgency: "normal",
            actions: "focus",
        });
    }
    /**
     * Blocks for answer images: each image with its source-path notice and, for a text-only model,
     * the vision description a pasted prompt image gets (best effort).
     */
    async #answerImageBlocks(images, signal) {
        if (images.length === 0)
            return [];
        let descriptions;
        const model = this.session.getActiveModel?.();
        const modelRegistry = this.session.modelRegistry;
        if (modelRegistry && shouldDescribeImagesForTextModel(model, this.session.settings)) {
            try {
                descriptions = await describeAttachedImagesForTextModel(images, {
                    activeModel: model,
                    modelRegistry,
                    settings: this.session.settings,
                    localProtocolOptions: sessionLocalProtocolOptions(this.session),
                    activeModelString: this.session.getActiveModelString?.(),
                    telemetryConfig: this.session.getTelemetry?.(),
                    sessionId: this.session.getSessionId?.() ?? undefined,
                }, signal);
            }
            catch (error) {
                logger.warn("ask answer image description failed; image left undescribed", {
                    error: error instanceof Error ? error.message : String(error),
                });
            }
        }
        const blocks = [];
        for (const [index, image] of images.entries()) {
            const notice = renderAttachmentSourceNotice(image, index + 1, { askAnswer: true });
            if (notice)
                blocks.push({ type: "text", text: notice.content });
            // Keep the source tag: `attachment://N` resolves this result's images to their files.
            blocks.push(image);
            const description = descriptions?.[index];
            if (description)
                blocks.push(description);
        }
        return blocks;
    }
    async execute(_toolCallId, params, signal, _onUpdate, context) {
        // Headless fallback
        if (!context?.hasUI || !context.ui) {
            context?.abort();
            throw new ToolAbortError("Ask tool requires interactive mode");
        }
        // Models occasionally inject `\r` runs into string values (observed with
        // GLM via OpenRouter); sanitize before the dialog renders or the answer
        // echoes back into session history.
        params = sanitizeAskParams(params);
        // Sanitizing `\r` runs can collapse a crafted label into a reserved
        // runtime label (`Other\r(type your own)` → `Other (type your own)`),
        // which would hijack the custom-input branch and duplicate the rich
        // dialog row — fail closed like schema validation does.
        const reservedCollision = params.questions
            .flatMap(question => question.options)
            .find(option => RESERVED_OPTION_LABELS[option.label] === true);
        if (reservedCollision !== undefined) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: option labels must not collide with reserved runtime labels: ${formatErrorValue(reservedCollision.label)}`,
                    },
                ],
                details: {},
            };
        }
        // The degraded multi-select completion row is theme-labeled and only
        // appended after an answer exists, but the choice handler matches it
        // unconditionally — a sanitized model label would exit instead of
        // selecting. Fail closed like the other sentinels (multi-select only;
        // single-select has no Done row).
        const doneActionLabel = getDoneOptionLabel();
        const doneCollision = params.questions
            .filter(question => question.multi === true)
            .flatMap(question => question.options)
            .find(option => option.label === doneActionLabel);
        if (doneCollision !== undefined) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error: option labels must not collide with reserved runtime labels: ${formatErrorValue(doneCollision.label)}`,
                    },
                ],
                details: {},
            };
        }
        // Sanitizing `\r` runs can also merge distinct labels (`Retry\rnow` and
        // `Retry now` become one); dialog selection is label-keyed, so one row
        // would check both — fail closed like schema validation does. The same
        // holds for question ids (`deploy\rmode`/`deploy mode`), which the
        // model uses to correlate multi-question answers.
        const seenIds = new Set();
        for (const question of params.questions) {
            if (seenIds.has(question.id)) {
                return {
                    content: [
                        {
                            type: "text",
                            text: `Error: question ids must be unique: ${formatErrorValue(question.id)}`,
                        },
                    ],
                    details: {},
                };
            }
            seenIds.add(question.id);
            const seenLabels = new Set();
            for (const option of question.options) {
                if (seenLabels.has(option.label)) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Error: option labels must be unique within a question: ${formatErrorValue(option.label)}`,
                            },
                        ],
                        details: {},
                    };
                }
                seenLabels.add(option.label);
            }
        }
        const extensionUi = context.ui;
        const ui = {
            timeoutStartsOnPresentation: extensionUi.timeoutStartsOnPresentation,
            select: (prompt, options, dialogOptions) => extensionUi.select(prompt, options, dialogOptions),
            editor: (title, prefill, dialogOptions, editorOptions) => extensionUi.editor(title, prefill, dialogOptions, editorOptions),
        };
        // Determine timeout based on settings and plan mode
        const planModeEnabled = this.session.getPlanModeState?.()?.enabled ?? false;
        const settingsTimeout = askTimeoutMs(this.session.settings) ?? null;
        const timeout = planModeEnabled ? null : settingsTimeout;
        // Send notification if waiting and not suppressed
        this.#sendAskNotification();
        if (params.questions.length === 0) {
            return {
                content: [{ type: "text", text: "Error: questions must not be empty" }],
                details: {},
            };
        }
        // Speak the question(s) aloud before surfacing them. Ask vocalizes in every
        // mode — it's the assistant addressing the user — gated only by speech.enabled
        // (the vocalizer re-checks the setting and no-ops when disabled).
        if (cfgSpeechEnabled.get(this.session.settings)) {
            vocalizer.speak(params.questions.map(q => q.question).join("\n"));
        }
        const richAskDialog = extensionUi.askDialog;
        if (richAskDialog) {
            try {
                const showRichDialog = () => richAskDialog(params.questions.map(q => ({
                    id: q.id,
                    question: q.question,
                    ...(q.header?.trim() ? { header: q.header } : {}),
                    options: q.options.map(option => ({
                        label: option.label,
                        ...(option.description?.trim() ? { description: option.description.trim() } : {}),
                        ...(option.preview?.trim() ? { preview: option.preview } : {}),
                    })),
                    ...(q.multi !== undefined ? { multi: q.multi } : {}),
                    ...(q.recommended !== undefined ? { recommended: q.recommended } : {}),
                })), { timeout: timeout ?? undefined, signal, acceptImages: true });
                const richResult = signal ? await untilAborted(signal, showRichDialog) : await showRichDialog();
                if (!richResult) {
                    context.abort();
                    throw new ToolAbortError("Ask tool was cancelled by the user");
                }
                if (richResult.kind === "chat") {
                    const questionText = params.questions.map(q => q.question).join("\n");
                    return {
                        content: [
                            {
                                type: "text",
                                text: `User chose to chat about this instead of answering.\n\nQuestions asked:\n${questionText}`,
                            },
                        ],
                        details: { chatRedirect: true, questions: params.questions.map(q => q.question) },
                    };
                }
                if (richResult.results.length !== params.questions.length) {
                    throw new Error("Ask dialog returned a result count that does not match the requested questions");
                }
                const results = [];
                // Each prompt numbers markers from 1; shift them so `[Image #N]` indexes all result images.
                const answerImages = [];
                for (let index = 0; index < params.questions.length; index++) {
                    const question = params.questions[index];
                    const result = richResult.results[index];
                    if (!question || !result || result.id !== question.id) {
                        throw new Error("Ask dialog returned results that do not match the requested question order");
                    }
                    const customOffset = answerImages.length;
                    if (result.customInputImages)
                        answerImages.push(...result.customInputImages);
                    const noteOffset = answerImages.length;
                    if (result.noteImages)
                        answerImages.push(...result.noteImages);
                    results.push({
                        id: question.id,
                        question: question.question,
                        options: question.options.map(option => option.label),
                        multi: question.multi ?? false,
                        selectedOptions: result.selectedOptions,
                        customInput: result.customInput === undefined
                            ? undefined
                            : shiftImageMarkers(result.customInput, customOffset, result.customInputImages?.length ?? 0),
                        note: result.note === undefined
                            ? undefined
                            : shiftImageMarkers(result.note, noteOffset, result.noteImages?.length ?? 0),
                        timedOut: result.timedOut,
                    });
                }
                if (params.questions.length === 1) {
                    const result = results[0];
                    // An empty multi-select submission is a valid "select none"
                    // answer (#8265 review); only a truly empty single-select
                    // result counts as cancellation.
                    if (!result ||
                        (!result.timedOut &&
                            !result.multi &&
                            result.selectedOptions.length === 0 &&
                            result.customInput === undefined)) {
                        context.abort();
                        throw new ToolAbortError("Ask tool was cancelled by the user");
                    }
                    const details = {
                        question: result.question,
                        options: result.options,
                        multi: result.multi,
                        selectedOptions: result.selectedOptions,
                        customInput: result.customInput,
                        note: result.note,
                        timedOut: result.timedOut,
                    };
                    const responseText = formatSingleQuestionResponse(result);
                    const imageBlocks = await this.#answerImageBlocks(answerImages, signal);
                    return { content: [{ type: "text", text: responseText }, ...imageBlocks], details };
                }
                const details = { results };
                const responseText = `User answers:\n${results.map(formatQuestionResult).join("\n")}`;
                const imageBlocks = await this.#answerImageBlocks(answerImages, signal);
                return { content: [{ type: "text", text: responseText }, ...imageBlocks], details };
            }
            catch (error) {
                if (error instanceof Error && error.name === "AbortError") {
                    throw new ToolAbortError("Ask input was cancelled");
                }
                throw error;
            }
        }
        const askQuestion = async (q, options) => {
            const questionOptions = q.options.map(option => ({
                label: option.label,
                ...(option.description?.trim() ? { description: option.description.trim() } : {}),
            }));
            const optionLabels = questionOptions.map(getAskOptionLabel);
            try {
                const { selectedOptions, customInput, note, navigation, cancelled, timedOut } = await askSingleQuestion(ui, q.question, questionOptions, q.multi ?? false, {
                    recommended: q.recommended,
                    timeout: timeout ?? undefined,
                    signal,
                    initialSelection: options?.previous,
                    navigation: options?.navigation,
                });
                return { optionLabels, selectedOptions, customInput, note, navigation, cancelled, timedOut };
            }
            catch (error) {
                if (error instanceof Error && error.name === "AbortError") {
                    throw new ToolAbortError("Ask input was cancelled");
                }
                throw error;
            }
        };
        if (params.questions.length === 1) {
            const [q] = params.questions;
            const { optionLabels, selectedOptions, customInput, note, cancelled, timedOut } = await askQuestion(q);
            if (!timedOut && (cancelled || (selectedOptions.length === 0 && customInput === undefined))) {
                context.abort();
                throw new ToolAbortError("Ask tool was cancelled by the user");
            }
            const details = {
                question: q.question,
                options: optionLabels,
                multi: q.multi ?? false,
                selectedOptions,
                customInput,
                note,
                timedOut: timedOut || undefined,
            };
            const responseText = formatSingleQuestionResponse({
                selectedOptions,
                customInput,
                note,
                timedOut: timedOut || undefined,
                multi: q.multi ?? false,
            });
            return { content: [{ type: "text", text: responseText }], details };
        }
        const resultsByIndex = Array.from({ length: params.questions.length });
        let questionIndex = 0;
        while (questionIndex < params.questions.length) {
            const q = params.questions[questionIndex];
            if (!q)
                throw new Error("Ask question index exceeded the requested question list");
            const previous = resultsByIndex[questionIndex];
            const navigation = {
                allowBack: questionIndex > 0,
                allowForward: true,
                progressText: `${questionIndex + 1}/${params.questions.length}`,
            };
            const { optionLabels, selectedOptions, customInput, note, navigation: navAction, cancelled, timedOut, } = await askQuestion(q, { previous, navigation });
            if (cancelled && !timedOut) {
                context.abort();
                throw new ToolAbortError("Ask tool was cancelled by the user");
            }
            resultsByIndex[questionIndex] = {
                id: q.id,
                question: q.question,
                options: optionLabels,
                multi: q.multi ?? false,
                selectedOptions,
                customInput,
                note,
                timedOut: timedOut || undefined,
            };
            if (navAction === "back") {
                questionIndex = Math.max(0, questionIndex - 1);
                continue;
            }
            questionIndex += 1;
        }
        const results = params.questions.map((q, index) => {
            const result = resultsByIndex[index];
            if (result)
                return result;
            return {
                id: q.id,
                question: q.question,
                options: q.options.map(o => o.label),
                multi: q.multi ?? false,
                selectedOptions: [],
            };
        });
        const details = { results };
        const responseLines = results.map(formatQuestionResult);
        const responseText = `User answers:\n${responseLines.join("\n")}`;
        return { content: [{ type: "text", text: responseText }], details };
    }
}
/**
 * Format a model-provided id/label for a validation error. Degenerate input
 * can carry tabs or kilobytes of text, and the error echoes through the
 * plain `Text` fallback renderer — expand tabs FIRST so the width bound
 * applies to displayed cells, then clamp like every other error display
 * path (`formatErrorMessage`).
 */
function formatErrorValue(value) {
    return truncateToWidth(replaceTabs(value), TRUNCATE_LENGTHS.LINE);
}
/** Strip the `\r` runs degenerate models inject, so persisted call args render as prose. */
function sanitizeAskParams(params) {
    return {
        ...params,
        questions: params.questions.map(question => ({
            ...question,
            id: sanitizeCarriageReturns(question.id),
            question: sanitizeCarriageReturns(question.question),
            ...(question.header !== undefined ? { header: sanitizeCarriageReturns(question.header) } : {}),
            options: question.options.map(option => ({
                ...option,
                label: sanitizeCarriageReturns(option.label),
                ...(option.description !== undefined ? { description: sanitizeCarriageReturns(option.description) } : {}),
                ...(option.preview !== undefined ? { preview: sanitizeCarriageReturns(option.preview) } : {}),
            })),
        })),
    };
}
