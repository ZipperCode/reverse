import { prompt } from "@rva/utils";
import { markdownFenceFor } from "../../../../utils/markdown-fence";
import textReviewTemplate from "./prompts/text-review.md" with { type: "text" };
const SHORT_SOURCE_CHARACTER_LIMIT = 1000;
function shouldIncludeSource(source) {
    if (source.kind === "code" || source.kind === "command" || source.kind === "file" || source.kind === "prompt") {
        return true;
    }
    if (source.provenance?.kind === "latest-assistant")
        return false;
    return source.text.length <= SHORT_SOURCE_CHARACTER_LIMIT;
}
export function shouldSummarizeTextReviewSource(source) {
    return source.provenance?.kind === "session" && !shouldIncludeSource(source);
}
export function normalizeTextReviewContextSummary(text) {
    const trimmed = text.trim();
    return trimmed.length > 0 && trimmed.length <= 999 ? trimmed : "";
}
function sanitizePreviewLabel(value, maxLength = 96) {
    const withoutAnsi = value.replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "");
    const oneLine = withoutAnsi
        .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    if (oneLine.length <= maxLength)
        return oneLine;
    return `${oneLine.slice(0, Math.max(0, maxLength - 3))}...`;
}
function exactPlaceholder(label, index, values) {
    let suffix = 0;
    let placeholder = `__OMP_ANNOTATE_${label}_${index}_${suffix}__`;
    while (values.some(value => value.includes(placeholder))) {
        placeholder = `__OMP_ANNOTATE_${label}_${index}_${++suffix}__`;
    }
    return placeholder;
}
/** Restore caller text after the prompt renderer has normalized its static template. */
function restoreExactValues(rendered, replacements) {
    let result = rendered;
    for (const [placeholder, value] of replacements) {
        if (result.includes(placeholder))
            result = result.replace(placeholder, () => value);
    }
    return result;
}
/** Build one paste-only text feedback prompt; empty annotations produce no prompt. */
export function buildTextReviewPrompt(source, annotations, contextSummary) {
    if (annotations.length === 0)
        return undefined;
    const summary = shouldSummarizeTextReviewSource(source)
        ? normalizeTextReviewContextSummary(contextSummary ?? "")
        : "";
    const sourceLabel = source.kind === "message" && source.provenance?.kind === "latest-assistant"
        ? "your last reply"
        : sanitizePreviewLabel(source.label) || `${source.kind} source`;
    const exactValues = [
        source.text,
        summary,
        source.label,
        sourceLabel,
        ...annotations.flatMap(annotation => annotation.scope === "line" ? [annotation.quote, annotation.note] : [annotation.note]),
    ];
    const replacements = [];
    let placeholderIndex = 0;
    const exact = (label, value) => {
        const placeholder = exactPlaceholder(label, placeholderIndex++, exactValues);
        replacements.push([placeholder, value]);
        return placeholder;
    };
    const sourceText = exact("SOURCE", source.text);
    const summaryText = summary ? exact("SUMMARY", summary) : "";
    const renderedAnnotations = annotations.map((annotation, index) => {
        const note = exact("NOTE", annotation.note);
        if (annotation.scope === "text") {
            return { number: index + 1, isLine: false, note };
        }
        const quoteIsInline = !/[\r\n`]/.test(annotation.quote);
        return {
            number: index + 1,
            isLine: true,
            quote: exact("QUOTE", annotation.quote),
            note,
            quoteIsInline,
            quoteFence: quoteIsInline ? undefined : markdownFenceFor(annotation.quote),
        };
    });
    const rendered = prompt.render(textReviewTemplate, {
        sourceLabel,
        includeSource: shouldIncludeSource(source) || (shouldSummarizeTextReviewSource(source) && !summary),
        sourceFence: markdownFenceFor(source.text),
        sourceText,
        contextSummary: summaryText,
        summaryFence: summary ? markdownFenceFor(summary) : "```",
        annotations: renderedAnnotations,
    });
    return restoreExactValues(rendered, replacements);
}
