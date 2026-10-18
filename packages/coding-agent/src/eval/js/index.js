import { resolveEvalUrlRoots, } from "../backend";
import { namespaceSessionId as sharedNamespace, toExecutorBackendResult } from "../backend-helpers";
import { defaultEvalSessionId } from "../session-id";
import { executeJs } from "./executor";
const JS_SESSION_PREFIX = "js:";
export function namespaceSessionId(sessionId) {
    return sharedNamespace(sessionId, JS_SESSION_PREFIX);
}
/** Resolve the retained JavaScript kernel identity owned by a tool session. */
export function resolveJsKernelIdentity(session) {
    return {
        sessionKey: namespaceSessionId(session.getEvalSessionId?.() ?? defaultEvalSessionId(session)),
        ownerId: session.getEvalKernelOwnerId?.() ?? undefined,
    };
}
export default {
    id: "js",
    label: "JavaScript",
    highlightLang: "javascript",
    async isAvailable(_session) {
        return true;
    },
    async execute(code, opts) {
        const identity = resolveJsKernelIdentity(opts.session);
        const result = await executeJs(code, {
            cwd: opts.cwd,
            idleTimeoutMs: opts.idleTimeoutMs,
            signal: opts.signal,
            sessionId: identity.sessionKey,
            kernelOwnerId: identity.ownerId,
            sessionFile: opts.sessionFile,
            filename: opts.filename,
            packages: opts.packages,
            environment: opts.environment,
            reset: opts.reset,
            onChunk: opts.onChunk,
            onStatus: opts.onStatus,
            session: opts.session,
            localRoots: resolveEvalUrlRoots(opts.session),
        });
        return toExecutorBackendResult(result);
    },
};
