import { resolveDelegationBias } from "@rva/catalog/compat/delegation";
/**
 * Delegation bias of the session's active model, for tool descriptions that
 * nudge toward subagents; `eager` before a model is bound.
 */
export function sessionDelegationBias(session) {
    const model = session.getActiveModel?.();
    return model ? resolveDelegationBias(model) : "eager";
}
