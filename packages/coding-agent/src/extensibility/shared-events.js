/**
 * Event payload and result shapes shared between the extensions and hooks
 * subsystems.
 *
 * Both subsystems observe the same agent/session lifecycle, so the *event*
 * payloads (what happened) and the simpler *result* shapes (handler return
 * values that don't depend on subsystem-specific identifiers like
 * `AgentMessage` vs `Message`) are intentionally identical.
 *
 * Anything that diverges between the two subsystems — UI context, runtime
 * context, command context, tool-call discrimination, or return shapes that
 * carry subsystem-specific message types — lives in the per-subsystem
 * `types.ts` files and is documented there.
 */
import { isNonBlankContext, joinAdditionalContext } from "@rva/agent";
/**
 * Merge one handler's `tool_call` result into the running aggregation.
 * Non-blank `additionalContext` values accumulate in registration order and
 * join (repeats dropped) at the end; `input` stays last-wins. A `block`
 * result short-circuits the caller, discarding everything collected so far.
 */
export function accumulateToolCallResult(aggregated, handlerResult) {
    if (isNonBlankContext(handlerResult.additionalContext)) {
        aggregated.additionalContext.push(handlerResult.additionalContext);
    }
    if (handlerResult.input !== undefined) {
        aggregated.input = handlerResult.input;
    }
}
/**
 * Build the aggregated `tool_call` result from collected context and input.
 * Returns undefined when there is nothing to carry beyond the control result.
 */
export function buildAggregatedToolCallResult(result, aggregated) {
    const { input } = aggregated;
    const additionalContext = joinAdditionalContext(aggregated.additionalContext);
    if (additionalContext === undefined && input === undefined)
        return result;
    const { additionalContext: _dropped, input: _droppedInput, ...controlResult } = result ?? {};
    return {
        ...controlResult,
        ...(input !== undefined ? { input } : {}),
        ...(additionalContext !== undefined ? { additionalContext } : {}),
    };
}
