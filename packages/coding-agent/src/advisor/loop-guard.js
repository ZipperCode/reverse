import { ToolCallLoopGuard } from "@rva/ai/utils/tool-call-loop-guard";
import { logger } from "@rva/utils";
import { renderToolCallLoopRedirect } from "../session/tool-call-loop-redirect";
import { cfgModelToolCallLoopGuardEnabled, cfgModelToolCallLoopGuardExemptTools, cfgModelToolCallLoopGuardThreshold, } from "../session/settings";
/**
 * Bounds repeated identical tool calls inside an advisor's own `Agent` loop.
 *
 * Advisors drive a private loop that never passes through the primary session's
 * `LoopGuards`, so a model reissuing one failing call had no bound at all:
 * `AdvisorRuntime` counts whole-turn provider failures, which a turn that
 * *succeeds* while burning dozens of identical failing tool calls never trips.
 * Reuses the primary's `model.toolCallLoopGuard.*` settings and corrective so
 * one knob governs both loops (issue #9491).
 */
export class AdvisorLoopGuard {
    #host;
    #guard;
    #guardSettingsKey;
    #redirectIssued = false;
    constructor(host) {
        this.#host = host;
    }
    /** Clear detector and escalation state at an advisor update/context boundary. */
    reset() {
        this.#guard = undefined;
        this.#guardSettingsKey = undefined;
        this.#redirectIssued = false;
    }
    /** Records one completed advisor turn and injects a redirect when calls repeat. */
    recordTurn(messages, context) {
        if (context?.message.role !== "assistant")
            return;
        const detection = this.#activeGuard()?.recordTurn({
            message: context.message,
            toolResults: context.toolResults,
        });
        if (!detection)
            return;
        if (this.#redirectIssued) {
            logger.warn("advisor ignored tool-call loop redirect; aborting update", {
                advisor: this.#host.name,
                toolName: detection.toolName,
                count: detection.count,
            });
            this.#host.abort(new Error(`Advisor repeated ${detection.toolName} after a loop redirect`));
            this.reset();
            return;
        }
        logger.warn("advisor tool-call loop detected", {
            advisor: this.#host.name,
            toolName: detection.toolName,
            count: detection.count,
        });
        this.#redirectIssued = true;
        // Re-arm after the first corrective. If it is ignored, the same bound
        // trips again and hard-stops this update instead of running forever.
        this.#guard = undefined;
        this.#guardSettingsKey = undefined;
        // A `user` message, not the primary's custom one: the advisor agent runs
        // the default LLM converter, which keeps only LLM-native roles — a custom
        // message would be dropped before the request and correct nothing.
        const redirect = {
            role: "user",
            content: [{ type: "text", text: renderToolCallLoopRedirect(detection) }],
            synthetic: true,
            attribution: "agent",
            timestamp: Date.now(),
        };
        messages.push(redirect);
        // The loop hands over its live array; a caller passing a detached snapshot
        // still needs the corrective in the context the next request reads.
        if (this.#host.liveMessages() !== messages)
            this.#host.appendMessage(redirect);
    }
    #activeGuard() {
        if (cfgModelToolCallLoopGuardEnabled.get(this.#host.settings) !== true) {
            this.reset();
            return undefined;
        }
        const threshold = cfgModelToolCallLoopGuardThreshold.get(this.#host.settings);
        const exemptTools = cfgModelToolCallLoopGuardExemptTools
            .get(this.#host.settings)
            .filter((tool) => typeof tool === "string" && tool.length > 0);
        const settingsKey = `${threshold}:${JSON.stringify(exemptTools)}`;
        if (!this.#guard || this.#guardSettingsKey !== settingsKey) {
            this.#guard = new ToolCallLoopGuard({ threshold, exemptTools });
            this.#guardSettingsKey = settingsKey;
        }
        return this.#guard;
    }
}
