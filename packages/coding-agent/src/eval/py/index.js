import { resolveEvalUrlRoots, } from "../backend";
import { namespaceSessionId as sharedNamespace, toExecutorBackendResult } from "../backend-helpers";
import { defaultEvalSessionId } from "../session-id";
import { executePython } from "./executor";
import { checkPythonKernelAvailability } from "./kernel";
import { cfgPythonInterpreter, cfgPythonKernelMode } from "../settings";
const PYTHON_SESSION_PREFIX = "python:";
export function namespaceSessionId(sessionId) {
    return sharedNamespace(sessionId, PYTHON_SESSION_PREFIX);
}
function readInterpreterSetting(session) {
    return cfgPythonInterpreter.get(session)?.trim() || undefined;
}
/** Resolve the retained Python kernel identity owned by a tool session. */
export function resolvePythonKernelIdentity(session) {
    return {
        cwd: session.cwd,
        sessionId: namespaceSessionId(session.getEvalSessionId?.() ?? defaultEvalSessionId(session)),
        interpreter: readInterpreterSetting(session),
        kernelOwnerId: session.getEvalKernelOwnerId?.() ?? undefined,
    };
}
export default {
    id: "python",
    label: "Python",
    highlightLang: "python",
    async isAvailable(session, opts) {
        const availability = await checkPythonKernelAvailability(session.cwd, readInterpreterSetting(session), opts);
        return availability.ok;
    },
    async execute(code, opts) {
        const kernelMode = cfgPythonKernelMode.get(opts.session);
        const identity = resolvePythonKernelIdentity(opts.session);
        const executorOptions = {
            cwd: identity.cwd,
            filename: opts.filename,
            idleTimeoutMs: opts.idleTimeoutMs,
            signal: opts.signal,
            sessionId: identity.sessionId,
            kernelMode,
            interpreter: identity.interpreter,
            sessionFile: opts.sessionFile,
            artifactsDir: opts.session.getArtifactsDir?.() ?? undefined,
            localRoots: resolveEvalUrlRoots(opts.session),
            kernelOwnerId: identity.kernelOwnerId,
            reset: opts.reset,
            onChunk: opts.onChunk,
            onStatus: opts.onStatus,
            toolSession: opts.session,
        };
        const result = await executePython(code, executorOptions);
        return toExecutorBackendResult(result);
    },
};
