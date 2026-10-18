import { getExperimentalContextSession } from "../tools/context-notes";
import { cfgCompactionExperimentalContextManagement } from "../session/context-settings";
/**
 * The session's `local://` mapping: its pinned {@link LocalProtocolOptions}
 * (subagents and multi-session hosts pin a parent/foreign root) or else its own
 * artifacts dir and session id, so `local://` never falls through to another
 * session's root.
 */
export function sessionLocalProtocolOptions(session) {
    return (session.localProtocolOptions ?? {
        getArtifactsDir: () => session.getArtifactsDir?.() ?? null,
        getSessionId: () => session.getSessionId?.() ?? null,
    });
}
/**
 * Router-facing `local://` mapping: a session with neither pinned options nor
 * its own artifacts dir defers to the process mapping (LocalProtocolHandler
 * override, then the registry's main session) instead of pinning a null root.
 */
export function contextLocalProtocolOptions(session) {
    if (!session.localProtocolOptions && !session.getArtifactsDir)
        return undefined;
    return sessionLocalProtocolOptions(session);
}
/** The single ResolveContext builder for a tool session; replaces per-tool literal assembly. */
export function sessionResolveContext(session, options = {}) {
    return {
        cwd: session.cwd,
        settings: session.settings,
        signal: options.signal,
        sessionFile: session.getSessionFile() ?? undefined,
        experimentalContextManagement: cfgCompactionExperimentalContextManagement.get(session.settings) === true,
        getSessionBranch: () => getExperimentalContextSession(session).getBranch(),
        sessionId: session.sessionManager?.getSessionId?.() ?? session.getSessionId?.() ?? undefined,
        agentRegistry: session.agentRegistry,
        localProtocolOptions: contextLocalProtocolOptions(session),
        skills: session.skills,
        rules: session.activeRules,
        session,
        skipDirectoryListing: options.skipDirectoryListing,
    };
}
/** The single WriteContext builder for a tool session; replaces per-tool literal assembly. */
export function sessionWriteContext(session, options = {}) {
    return {
        cwd: session.cwd,
        signal: options.signal,
        localProtocolOptions: contextLocalProtocolOptions(session),
        session,
        toolCall: options.toolCall,
    };
}
