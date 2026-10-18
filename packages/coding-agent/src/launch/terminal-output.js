import { logger } from "@rva/utils";
import xterm from "@rva/utils/vterm";
import { readTerminalRows } from "@rva/tui/tools/terminal-output";
import { DAEMON_PTY_COLUMNS, DAEMON_PTY_ROWS } from "./protocol";
const VIRTUAL_SCROLLBACK_ROWS = 4096;
function writeTerminal(terminal, output) {
    const { promise, resolve } = Promise.withResolvers();
    terminal.write(output, resolve);
    return promise;
}
/** Replays daemon bytes with the same xterm screen renderer used by PTY mode. */
export async function renderTerminalOutput(output, options) {
    if (!output)
        return [];
    const maxRows = Math.max(1, Math.floor(options.maxRows));
    const terminal = new xterm.Terminal({
        cols: DAEMON_PTY_COLUMNS,
        rows: DAEMON_PTY_ROWS,
        scrollback: Math.max(VIRTUAL_SCROLLBACK_ROWS, maxRows),
        allowProposedApi: true,
    });
    try {
        await writeTerminal(terminal, output);
        const rows = readTerminalRows(terminal, 0, terminal.buffer.active.length);
        while (rows.at(-1) === "")
            rows.pop();
        return options.head ? rows.slice(0, maxRows) : rows.slice(-maxRows);
    }
    catch (error) {
        logger.debug("Failed to render launch terminal output", {
            error: error instanceof Error ? error.message : String(error),
        });
        return undefined;
    }
    finally {
        terminal.dispose();
    }
}
