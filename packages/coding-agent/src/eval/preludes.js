import { untilAborted } from "@rva/utils";
import { denyError, requestApproval, resolveApproval, resolveApprovalFromContext } from "../tools/approval";
/**
 * Resolve enabled candidates without consulting a session getter (and therefore
 * without recursion). Later definitions replace earlier definitions of the same
 * name, matching extension tool registration precedence.
 */
export function getEnabledEvalPreludes(definitions) {
    const enabledByName = new Map();
    for (const definition of definitions) {
        if (definition.enabled?.() !== false)
            enabledByName.set(definition.name, definition);
    }
    return Array.from(enabledByName.values());
}
/** First documentation line, advertised as the prelude's one-line summary; undefined when undocumented. */
export function evalPreludeSummary(definition) {
    const doc = definition.documentation.trim();
    return doc ? doc.split("\n", 1)[0] : undefined;
}
/** Resolve a prelude from the session's live enabled set. Captured stale VM functions therefore fail closed. */
export function findEnabledEvalPrelude(session, name) {
    const definition = session.getEvalPreludes?.().find(candidate => candidate.name === name);
    return definition?.enabled?.() === false ? undefined : definition;
}
async function approvePreludeInvocation(definition, parameters, context) {
    context.signal?.throwIfAborted();
    // Fourth execute-time site: same helper as wrapper/cursor/mcp so a missing
    // context cannot silently yolo. Empty `context.context` fail-closes;
    // omitting it inherits the live session settings (schema default yolo).
    const { approvalMode: mode, userPolicies: policies } = resolveApprovalFromContext(context.context ?? (context.session.settings ? { settings: context.session.settings } : undefined));
    const subject = { name: definition.name };
    if (definition.approval !== undefined)
        subject.approval = definition.approval;
    const resolved = resolveApproval(subject, parameters, mode, policies);
    if (resolved.policy === "deny")
        throw denyError(resolved, definition.name);
    if (resolved.policy !== "prompt")
        return;
    const ui = context.context?.ui;
    if (!ui || context.context?.hasUI === false) {
        throw new Error(`Eval prelude "${definition.name}" requires approval but no interactive UI is available.\n` +
            `Set tools.approval.${definition.name}: allow or use an interactive UI to approve the call.`);
    }
    const approved = await untilAborted(context.signal, () => requestApproval(ui, subject, parameters, resolved.reason));
    if (!approved)
        throw new Error(`Eval prelude call denied by user: ${definition.name}`);
}
/**
 * Invoke a prelude through the live session registry. Authorization is resolved
 * before the handler runs and repeated when an awaited approval raced with a
 * replacement, so a disabled or replaced captured function cannot retain host
 * access under stale policy.
 */
export async function invokeEvalPrelude(name, parameters, context) {
    context.signal?.throwIfAborted();
    let definition = findEnabledEvalPrelude(context.session, name);
    if (!definition)
        throw new Error(`Eval prelude "${name}" is not enabled in the current session.`);
    await approvePreludeInvocation(definition, parameters, context);
    context.signal?.throwIfAborted();
    const current = findEnabledEvalPrelude(context.session, name);
    if (!current)
        throw new Error(`Eval prelude "${name}" is not enabled in the current session.`);
    if (current !== definition) {
        definition = current;
        await approvePreludeInvocation(definition, parameters, context);
        context.signal?.throwIfAborted();
        if (findEnabledEvalPrelude(context.session, name) !== definition) {
            throw new Error(`Eval prelude "${name}" changed while authorizing the call.`);
        }
    }
    return definition.invoke(parameters, context);
}
