import { transcriptEntryMessage } from "@rva/tui/chat/transcript-entry";
import { CopySelectorComponent } from "@rva/tui/overlays/copy-selector";
import { assistantText } from "@rva/tui/overlays/copy-targets";
import { isTranscriptEntry } from "../../../../session/session-context";
export const ANNOTATION_SOURCE_CHOICES = [
    {
        kind: "code-review",
        label: "Code review",
        description: "Annotate a local diff before review",
    },
    {
        kind: "last",
        label: "Latest assistant reply",
        description: "Annotate the latest non-empty assistant reply on this branch",
    },
    {
        kind: "session",
        label: "Session message or block",
        description: "Choose a message, code block, quote, or command from this session",
    },
    {
        kind: "file",
        label: "File",
        description: "Read a regular text file from the current working directory",
    },
    {
        kind: "prompt",
        label: "Text prompt",
        description: "Enter text directly for annotation",
    },
];
export async function selectAnnotationSourceKind(ui) {
    const selected = await ui.select("Select content to annotate", ANNOTATION_SOURCE_CHOICES.map(choice => choice.label));
    return ANNOTATION_SOURCE_CHOICES.find(choice => choice.label === selected)?.kind;
}
function latestAssistantEntry(branch) {
    for (let index = branch.length - 1; index >= 0; index--) {
        const entry = branch[index];
        if (entry?.type !== "message")
            continue;
        const text = assistantText(entry.message);
        if (text)
            return { id: entry.id, text };
    }
    return undefined;
}
/** The latest non-empty assistant reply on the active branch, or undefined when none exists. */
export function latestAssistantTextReviewSource(branch, sessionId) {
    const latest = latestAssistantEntry(branch);
    if (!latest)
        return undefined;
    return {
        id: `message:${latest.id}`,
        kind: "message",
        label: "Latest assistant reply",
        text: latest.text,
        provenance: { kind: "latest-assistant", entryId: latest.id },
        sessionId,
    };
}
function sourceKind(selection) {
    if (selection.block?.kind)
        return selection.block.kind;
    switch (transcriptEntryMessage(selection.entry)?.role) {
        case "toolResult":
            return "code";
        case "bashExecution":
        case "pythonExecution":
            return "command";
        default:
            return "message";
    }
}
function sourceFromSelection(ctx, selection, latestAssistantId) {
    const kind = sourceKind(selection);
    const entryId = selection.entry.id;
    const isLatestWholeAssistant = selection.block === undefined &&
        entryId === latestAssistantId &&
        transcriptEntryMessage(selection.entry)?.role === "assistant";
    return {
        id: `${kind}:${entryId}`,
        kind,
        label: selection.label,
        text: selection.content,
        provenance: isLatestWholeAssistant ? { kind: "latest-assistant", entryId } : { kind: "session", entryId },
        sessionId: ctx.sessionManager.getSessionId(),
    };
}
/** Choose exact content through the native copy selector without copying it. */
export async function selectSessionTextReviewSource(ctx, options) {
    const branch = ctx.sessionManager.getBranch();
    if (options?.autoSelect === "latest-assistant") {
        const source = latestAssistantTextReviewSource(branch, ctx.sessionManager.getSessionId());
        if (!source)
            ctx.ui.notify("No non-empty assistant reply is available on the active session branch.", "warning");
        return source;
    }
    const latest = latestAssistantEntry(branch);
    const entries = branch.filter(isTranscriptEntry);
    if (entries.length === 0) {
        ctx.ui.notify("No messages to annotate yet.", "warning");
        return undefined;
    }
    const selection = await ctx.ui.custom((tui, _theme, _keybindings, done) => {
        return new CopySelectorComponent(entries, {
            ui: tui,
            cwd: ctx.sessionManager.getCwd?.() ?? ctx.cwd,
            title: "Select message to annotate",
            actionLabel: "select",
            requestRender: () => tui.requestRender(),
            onPick: (content, label, source) => done({ content, label, ...source }),
            onCancel: () => done(undefined),
        });
    });
    return selection ? sourceFromSelection(ctx, selection, latest?.id) : undefined;
}
