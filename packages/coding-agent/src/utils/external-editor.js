/**
 * Utilities for launching an external text editor ($VISUAL / $EDITOR).
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { $env, $which, Snowflake } from "@rva/utils";
/**
 * Returns the user's preferred editor command, or a platform default.
 *
 * Resolution order:
 *   1. `$VISUAL`
 *   2. `$EDITOR`
 *   3. `notepad` on Windows (always present in `%SystemRoot%\System32`)
 *
 * POSIX returns `undefined` when neither variable is set so the caller can
 * surface a warning that nudges the user to configure one.
 */
export function getEditorCommand() {
    const configured = $env.VISUAL?.trim() || $env.EDITOR?.trim();
    if (configured)
        return configured;
    if (process.platform === "win32")
        return "notepad";
    return undefined;
}
/** Resolves shell argv without letting the host runtime re-quote the editor command. */
export function resolveEditorSpawnCommand(editorCmd, tmpFile, platform = process.platform) {
    const windows = platform === "win32";
    // cmd.exe strips the outer /s /c quote pair; Bun must pass the embedded
    // editor/path quotes verbatim instead of applying argv escaping to them.
    const cmd = windows
        ? ["cmd.exe", "/d", "/s", "/c", `"${editorCmd} "${tmpFile}""`]
        : [$which("sh") ?? "sh", "-c", `${editorCmd} "$1"`, "sh", tmpFile];
    return { cmd, windowsVerbatimArguments: windows };
}
/**
 * Opens `content` in the user's external editor and returns the edited text.
 * Returns `null` if the editor exits with a non-zero code.
 *
 * The caller is responsible for stopping/starting the TUI around this call.
 */
export async function openInEditor(editorCmd, content, options) {
    const ext = options?.extension ?? ".md";
    const tmpFile = path.join(os.tmpdir(), `omp-editor-${Snowflake.next()}${ext}`);
    try {
        await Bun.write(tmpFile, content);
        const exitCode = await openEditorOnPath(editorCmd, tmpFile);
        if (exitCode === 0) {
            const text = await Bun.file(tmpFile).text();
            if (options?.trimTrailingNewline === false) {
                return text;
            }
            return text.replace(/\n$/, "");
        }
        return null;
    }
    finally {
        try {
            await fs.rm(tmpFile, { force: true });
        }
        catch {
            // Ignore cleanup errors
        }
    }
}
/**
 * Opens an existing file in the user's editor, which writes it in place, and
 * returns the editor's exit code. The file may have been saved even when the
 * code is non-zero, so callers that care re-read it.
 *
 * The caller is responsible for stopping/starting the TUI around this call.
 */
export async function openEditorOnPath(editorCmd, filePath) {
    const spawnCommand = resolveEditorSpawnCommand(editorCmd, filePath);
    // Inherit the real pane pty so terminal editors (including emacsclient,
    // which resolves the device via ttyname) render into the visible pane.
    const child = Bun.spawn(spawnCommand.cmd, {
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
        windowsVerbatimArguments: spawnCommand.windowsVerbatimArguments,
    });
    return child.exited;
}
