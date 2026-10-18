import * as prompt from "@rva/utils/prompt";
import screenLockedCaptureNote from "../../prompts/tools/computer-screen-locked-capture.md" with { type: "text" };
import screenStateTemplate from "../../prompts/tools/computer-screen-state.md" with { type: "text" };
export { COMPUTER_WORKER_ARG } from "../../cli/worker-selectors";
/** Appended to a screenshot taken while the macOS lock screen is up. */
export const SCREEN_LOCKED_CAPTURE_NOTE = prompt.render(screenLockedCaptureNote);
/**
 * Tells the model a run ended with the macOS screen locked or the session's
 * display asleep, so lock-screen pixels and failed captures are not taken
 * for the app's state. Input is never refused because of it.
 */
export function screenStateNotice(state) {
    if (!state?.screenLocked && !state?.displayAsleep)
        return undefined;
    return prompt.render(screenStateTemplate, {
        screenLocked: state.screenLocked,
        displayAsleep: state.displayAsleep,
    });
}
