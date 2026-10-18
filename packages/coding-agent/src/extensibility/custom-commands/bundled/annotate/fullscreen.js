import * as path from "node:path";
import * as vcs from "@rva/natives/vcs";
import { AnnotationOverlay } from "@rva/tui/overlays/annotation-overlay";
import { getEditorCommand, openEditorOnPath, openInEditor } from "../../../../utils/external-editor";
const ANNOTATION_OVERLAY_OPTIONS = {
    width: "100%",
    maxHeight: "100%",
    margin: 0,
    fullscreen: true,
    mouseTracking: false,
};
const MISSING_EDITOR = "Set $VISUAL or $EDITOR to edit in an external editor.";
function requireEditor() {
    const editor = getEditorCommand();
    if (!editor)
        throw new Error(MISSING_EDITOR);
    return editor;
}
async function editAnnotationDraft(tui, draft, commit) {
    const editor = requireEditor();
    tui.stop();
    try {
        commit(await openInEditor(editor, draft, { extension: ".md" }));
    }
    finally {
        tui.start();
        tui.requestRender(true);
    }
}
async function editTextSource(tui, ctx, overlay, provenance) {
    const editor = requireEditor();
    const current = overlay.textSourceText() ?? "";
    tui.stop();
    let next;
    let exitCode = 0;
    try {
        if (provenance.kind === "file") {
            exitCode = await openEditorOnPath(editor, provenance.path);
            next = await Bun.file(provenance.path).text();
        }
        else {
            next = await openInEditor(editor, current, { extension: ".txt", trimTrailingNewline: false });
        }
    }
    finally {
        tui.start();
        tui.requestRender(true);
    }
    if (exitCode !== 0)
        ctx.ui.notify(`Editor exited with code ${exitCode}; using what it saved.`, "warning");
    if (next === null || next === current)
        return;
    const dropped = overlay.replaceTextSource(next);
    if (dropped > 0) {
        ctx.ui.notify(dropped === 1
            ? "Dropped 1 line note that no longer matches the edited text."
            : `Dropped ${dropped} line notes that no longer match the edited text.`, "warning");
    }
}
async function editReviewedFile(tui, ctx, overlay) {
    const relative = overlay.reviewFilePath();
    if (!relative)
        throw new Error("No file to open.");
    const editor = requireEditor();
    // Diff paths are repository-relative and exact, so resolve them from the repo root, not the session cwd.
    const cwd = ctx.sessionManager.getCwd?.() ?? ctx.cwd;
    const absolute = path.resolve(vcs.repo(cwd)?.root() ?? cwd, relative);
    if (!(await Bun.file(absolute).exists())) {
        throw new Error(`${relative} is not on disk. The review still uses the frozen diff.`);
    }
    tui.stop();
    let exitCode;
    try {
        exitCode = await openEditorOnPath(editor, absolute);
    }
    finally {
        tui.start();
        tui.requestRender(true);
    }
    if (exitCode !== 0)
        ctx.ui.notify(`Editor exited with code ${exitCode}.`, "warning");
    ctx.ui.notify(`Opened ${relative}. The review still uses the frozen diff.`, "info");
}
/** Mount the frozen diff in the TUI overlay surface owned by the command host. */
export function showCodeReviewOverlay(ctx, target) {
    return ctx.ui.custom((tui, theme, keybindings, done) => {
        const overlay = new AnnotationOverlay(tui, theme, keybindings, target.snapshot.files, target.mode, {
            onComplete: done,
            onWarning: message => ctx.ui.notify(message, "warning"),
            onAnnotationExternalEditor: (draft, commit) => editAnnotationDraft(tui, draft, commit),
            // PR and caller-supplied diffs need not match the local checkout, so only local reviews open the working-tree file.
            onExternalEditor: target.kind === "pr" || target.kind === "patch"
                ? undefined
                : () => editReviewedFile(tui, ctx, overlay),
        });
        return overlay;
    }, { overlay: true, overlayOptions: ANNOTATION_OVERLAY_OPTIONS });
}
/** Mount a frozen text source in the same annotation overlay UX. */
export function showTextReviewOverlay(ctx, source) {
    return ctx.ui.custom((tui, theme, keybindings, done) => {
        const provenance = source.provenance;
        const editable = provenance?.kind === "file" || provenance?.kind === "prompt" ? provenance : undefined;
        const overlay = new AnnotationOverlay(tui, theme, keybindings, source, {
            onComplete: done,
            onWarning: message => ctx.ui.notify(message, "warning"),
            onAnnotationExternalEditor: (draft, commit) => editAnnotationDraft(tui, draft, commit),
            onExternalEditor: editable ? () => editTextSource(tui, ctx, overlay, editable) : undefined,
        });
        return overlay;
    }, { overlay: true, overlayOptions: ANNOTATION_OVERLAY_OPTIONS });
}
