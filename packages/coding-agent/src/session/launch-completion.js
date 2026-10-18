import { prompt } from "@rva/utils";
import launchCompletionTemplate from "../prompts/session/launch-completion.md" with { type: "text" };
import { LAUNCH_COMPLETION_MESSAGE_TYPE } from "@rva/tui/chat/messages";
export { LAUNCH_COMPLETION_MESSAGE_TYPE } from "@rva/tui/chat/messages";
/** Whether a broker completion belongs to the primary session or its advisor. */
export function isLaunchCompletionOwner(owner, sessionId) {
    return owner === sessionId || owner === `${sessionId}-advisor`;
}
/** Build one model-visible notification per terminal supervised process exit. */
export function buildLaunchCompletionBatchMessage(entries) {
    return {
        role: "custom",
        customType: LAUNCH_COMPLETION_MESSAGE_TYPE,
        content: entries
            .map(({ daemon }) => prompt.render(launchCompletionTemplate, {
            name: daemon.name,
            state: daemon.state,
            exitCode: daemon.exitCode,
            hasExitCode: daemon.exitCode !== undefined,
        }))
            .join("\n"),
        display: true,
        attribution: "agent",
        details: { daemons: entries.map(entry => entry.daemon) },
        timestamp: Date.now(),
    };
}
