import * as fs from "node:fs";
import * as path from "node:path";
import { logger } from "@rva/utils";
import { cfgEditBlackboxEnabled } from "./settings";
const EDIT_BLACKBOX_FILE = "edit-blackbox.jsonl";
/** Create the enabled recorder that appends native-detected parse regressions. */
export function createEditBlackboxRecorder(session, variant, arg) {
    if (!cfgEditBlackboxEnabled.get(session.settings))
        return undefined;
    const logPath = path.join(session.settings.getAgentDir(), EDIT_BLACKBOX_FILE);
    const model = session.getActiveModelString?.() ?? "unknown";
    return async ({ prev, next }) => {
        try {
            await fs.promises.appendFile(logPath, `${JSON.stringify({ prev, new: next, model, variant, arg })}\n`);
        }
        catch (error) {
            // Recording is diagnostic only. The edit has already committed, so a
            // telemetry failure must not turn it into a reported edit failure.
            logger.debug("Failed to record edit parse regression", {
                path: logPath,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    };
}
