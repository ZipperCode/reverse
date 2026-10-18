import * as fs from "node:fs";
import { getProjectDir, logger, Snowflake } from "@rva/utils";
import { buildManagedKernelEnv, buildManagedKernelEnvPatch, createCancelledKernelResult, EvalKernelNotRunningError, executeWithKernelBase, getExecutionDeadlineMs, getRemainingTimeoutMs, isCancellationError, isTimedOutCancellation, waitForPromiseWithCancellation, } from "../executor-base";
import { getEnabledEvalPreludes } from "../preludes";
import { createKernelSessionRegistry, formatSessionKernelTimeoutAnnotation, formatSessionTimeoutAnnotation, normalizeKernelSessionCwd, requireRemainingKernelTimeoutMs, } from "../kernel-session-registry";
import { checkPythonKernelAvailability, PythonKernel, } from "./kernel";
import { resolveExplicitPythonRuntime } from "./runtime";
import { ensurePyToolBridge, registerPyToolBridge } from "./tool-bridge";
function normalizeExplicitInterpreter(cwd, interpreter) {
    if (interpreter === undefined)
        return "";
    const resolved = resolveExplicitPythonRuntime(interpreter, cwd, {}).pythonPath;
    try {
        return fs.realpathSync.native(resolved);
    }
    catch {
        return resolved;
    }
}
// ---------------------------------------------------------------------------
// Cancellation plumbing
// ---------------------------------------------------------------------------
class PythonExecutionCancelledError extends Error {
    timedOut;
    constructor(timedOut) {
        super(timedOut ? "Command timed out" : "Command aborted");
        this.name = "PythonExecutionCancelledError";
        this.timedOut = timedOut;
    }
}
function requireRemainingTimeoutMs(deadlineMs) {
    return requireRemainingKernelTimeoutMs(deadlineMs, PythonExecutionCancelledError);
}
// ---------------------------------------------------------------------------
// Result formatting
// ---------------------------------------------------------------------------
const formatTimeoutAnnotation = formatSessionTimeoutAnnotation;
const formatKernelTimeoutAnnotation = formatSessionKernelTimeoutAnnotation;
function createCancelledPythonResult(timedOut, timeoutMs) {
    const output = timedOut ? (formatTimeoutAnnotation(timeoutMs) ?? "Command timed out") : "";
    return createCancelledKernelResult(output);
}
// ---------------------------------------------------------------------------
// Kernel start helpers
// ---------------------------------------------------------------------------
async function startKernel(cwd, options) {
    requireRemainingTimeoutMs(options.deadlineMs);
    return await PythonKernel.start({
        cwd,
        env: buildManagedKernelEnv(options),
        signal: options.signal,
        deadlineMs: options.deadlineMs,
        interpreter: options.interpreter,
    });
}
async function replaceSessionKernel(session, cwd, options, context) {
    const kernel = session.kernel;
    const generation = session.generation;
    const inFlight = session.replacement;
    if (inFlight?.generation === generation) {
        if (inFlight.deadlineMs !== undefined &&
            (options.deadlineMs === undefined || options.deadlineMs > inFlight.deadlineMs)) {
            inFlight.deadlineMs = options.deadlineMs;
        }
        return await waitForPromiseWithCancellation(inFlight.promise, options, PythonExecutionCancelledError);
    }
    if (context.sessions.get(session.sessionKey) !== session ||
        session.generation !== generation ||
        session.kernel !== kernel) {
        throw new PythonExecutionCancelledError(false);
    }
    const deferred = Promise.withResolvers();
    const replacement = {
        generation,
        deadlineMs: options.deadlineMs,
        promise: deferred.promise,
    };
    session.replacement = replacement;
    void (async () => {
        try {
            const remaining = getRemainingTimeoutMs(options.deadlineMs);
            await kernel
                .shutdown(remaining !== undefined ? { timeoutMs: Math.max(0, remaining) } : undefined)
                .catch(() => undefined);
            if (replacement.deadlineMs !== undefined && replacement.deadlineMs <= Date.now()) {
                throw new PythonExecutionCancelledError(true);
            }
            if (context.sessions.get(session.sessionKey) !== session ||
                session.generation !== generation ||
                session.kernel !== kernel) {
                throw new PythonExecutionCancelledError(false);
            }
            const next = await startKernel(cwd, {
                ...options,
                signal: undefined,
                deadlineMs: undefined,
            });
            if (context.sessions.get(session.sessionKey) !== session ||
                session.generation !== generation ||
                session.kernel !== kernel) {
                await next.shutdown().catch(() => undefined);
                throw new PythonExecutionCancelledError(false);
            }
            session.kernel = next;
            session.generation += 1;
            deferred.resolve(next);
        }
        catch (err) {
            deferred.reject(err);
        }
        finally {
            if (session.replacement === replacement)
                session.replacement = undefined;
        }
    })();
    return await waitForPromiseWithCancellation(deferred.promise, options, PythonExecutionCancelledError);
}
async function shutdownInvalidatedSession(session) {
    const replacement = session.replacement;
    if (replacement)
        await replacement.promise.catch(() => undefined);
    return await session.kernel.shutdown();
}
async function acquireLiveSessionKernel(session, cwd, options, context) {
    while (context.sessions.get(session.sessionKey) === session) {
        const kernel = session.kernel;
        if (kernel.isAlive())
            return kernel;
        await context.replaceSessionKernel(session, cwd, options);
    }
    throw new PythonExecutionCancelledError(false);
}
// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------
function pythonPreludeSources(session) {
    const definitions = getEnabledEvalPreludes(session?.getEvalPreludes?.() ?? []);
    return definitions.flatMap(definition => definition.python.trim().length === 0
        ? []
        : [{ name: definition.name, exports: [...definition.exports], source: definition.python }]);
}
async function executeWithKernel(kernel, code, options) {
    const remainingMs = getRemainingTimeoutMs(options?.deadlineMs);
    await kernel.syncPreludes?.(pythonPreludeSources(options?.toolSession), options?.signal, Math.max(1, remainingMs ?? 10000));
    return executeWithKernelBase({
        kernel,
        code,
        options,
        runIdPrefix: "py",
        errorLogLabel: "Python",
        cancelledErrorClass: PythonExecutionCancelledError,
        buildKernelEnvPatch: buildManagedKernelEnvPatch,
        formatKernelTimeoutAnnotation,
        formatTimeoutAnnotation,
    });
}
async function ensureKernelAvailable(cwd, options) {
    const availability = await waitForPromiseWithCancellation(checkPythonKernelAvailability(cwd, options.interpreter), options, PythonExecutionCancelledError);
    if (!availability.ok) {
        throw new Error(availability.reason ?? "Python kernel unavailable");
    }
}
async function ensureToolBridge(options) {
    if (!options.toolSession || options.bridge)
        return;
    try {
        options.bridge = await ensurePyToolBridge();
    }
    catch (err) {
        logger.warn("Failed to start Python tool bridge", {
            error: err instanceof Error ? err.message : String(err),
        });
    }
}
async function executePerCall(code, cwd, options) {
    if (options.bridge && !options.bridgeSessionId) {
        options.bridgeSessionId = `py-bridge:${crypto.randomUUID()}`;
    }
    const kernel = await startKernel(cwd, options);
    try {
        return await executeWithKernel(kernel, code, { ...options, cwd });
    }
    finally {
        await kernel.shutdown().catch(() => undefined);
    }
}
const sessionRegistry = createKernelSessionRegistry({
    languageLabel: "Python",
    cancelledErrorClass: PythonExecutionCancelledError,
    buildSessionKey: (sessionId, cwd, interpreter) => {
        const normalizedCwd = normalizeKernelSessionCwd(cwd);
        return `${sessionId}\0${normalizedCwd}\0${normalizeExplicitInterpreter(normalizedCwd, interpreter)}`;
    },
    createSession: session => ({ ...session, generation: 0 }),
    startKernel,
    executeWithKernel,
    replaceSessionKernel,
    acquireLiveSessionKernel,
    invalidateSession: session => {
        session.generation += 1;
    },
    shutdownSession: session => shutdownInvalidatedSession(session),
    validateKernel: (session, kernel) => session.kernel === kernel,
});
function isUnknownRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
function pythonToolError(execution) {
    const error = execution.error;
    if (!error)
        return "Python tool request failed";
    return error.value || error.name || "Python tool request failed";
}
async function invokePythonToolRequest(request, options) {
    const cwd = normalizeKernelSessionCwd(options.cwd);
    const kernel = sessionRegistry.peekLiveKernel(cwd, {
        cwd,
        sessionId: options.sessionId,
        interpreter: options.interpreter,
        kernelOwnerId: options.kernelOwnerId,
    });
    if (!kernel)
        throw new EvalKernelNotRunningError("Python");
    const bridgeOptions = {
        cwd,
        sessionId: options.sessionId,
        interpreter: options.interpreter,
        kernelOwnerId: options.kernelOwnerId,
        toolSession: options.toolSession,
        signal: options.signal,
    };
    await ensureToolBridge(bridgeOptions);
    const runId = Snowflake.next();
    const unregister = registerPyToolBridge(options.sessionId, runId, {
        toolSession: options.toolSession,
        signal: options.signal,
        emitStatus: undefined,
    });
    let envelope;
    try {
        const execution = await kernel.invokeTool(request, {
            id: runId,
            signal: options.signal,
            onDisplay: output => {
                if (output.type === "json")
                    envelope = output.data;
            },
        });
        return { execution, envelope };
    }
    finally {
        unregister();
    }
}
/** Describe named tools defined in a retained Python kernel. */
export async function describePythonTools(names, options) {
    const { execution, envelope } = await invokePythonToolRequest({ op: "describe", names }, options);
    if (execution.status === "error")
        throw new Error(pythonToolError(execution));
    if (!isUnknownRecord(envelope) || envelope.ok !== true) {
        throw new Error("Python tool describe request returned an invalid response");
    }
    const rawTools = Array.isArray(envelope.tools) ? envelope.tools : [];
    const tools = [];
    for (const rawTool of rawTools) {
        if (!isUnknownRecord(rawTool))
            continue;
        const { name, description, parameters } = rawTool;
        if (typeof name !== "string" || typeof description !== "string" || !isUnknownRecord(parameters))
            continue;
        tools.push({ name, description, parameters, language: "python" });
    }
    const missing = Array.isArray(envelope.missing)
        ? envelope.missing.filter((name) => typeof name === "string")
        : [];
    return { tools, missing };
}
/** Invoke a named tool defined in a retained Python kernel. */
export async function callPythonTool(name, args, options) {
    const { execution, envelope } = await invokePythonToolRequest({ op: "call", name, args }, options);
    if (execution.status === "error")
        return { ok: false, error: pythonToolError(execution) };
    if (!isUnknownRecord(envelope) || envelope.ok !== true || !("value" in envelope)) {
        return { ok: false, error: "Python tool call returned an invalid response" };
    }
    return { ok: true, value: envelope.value };
}
export async function disposeAllKernelSessions() {
    await sessionRegistry.disposeAll();
}
export async function disposeKernelSessionsByOwner(ownerId) {
    await sessionRegistry.disposeByOwner(ownerId);
}
/** Projects against an already-retained, idle Python session without starting a kernel. */
export async function shadowPlanPythonIfPresent(options) {
    const cwd = normalizeKernelSessionCwd(options.cwd);
    const session = sessionRegistry.getPresentSession(cwd, {
        sessionId: options.sessionId,
        kernelOwnerId: options.kernelOwnerId,
    });
    if (!session?.kernel.isAlive())
        return null;
    return await session.kernel.shadowPlan(options.code, options.timeoutMs);
}
/** Captures the current retained-namespace token without planning or starting a kernel. */
export async function snapshotPythonNamespaceIfPresent(options) {
    const cwd = normalizeKernelSessionCwd(options.cwd);
    const session = sessionRegistry.getPresentSession(cwd, {
        sessionId: options.sessionId,
        kernelOwnerId: options.kernelOwnerId,
    });
    if (!session?.kernel.isAlive())
        return null;
    return await session.kernel.snapshotUserNamespace(options.timeoutMs);
}
export async function executePythonWithKernel(kernel, code, options) {
    return await executeWithKernel(kernel, code, options);
}
export async function executePython(code, options) {
    const cwd = normalizeKernelSessionCwd(options?.cwd ?? getProjectDir());
    const deadlineMs = getExecutionDeadlineMs(options);
    const executionOptions = {
        ...options,
        cwd,
        deadlineMs,
    };
    try {
        requireRemainingTimeoutMs(deadlineMs);
        if (executionOptions.signal?.aborted) {
            throw new PythonExecutionCancelledError(isTimedOutCancellation(executionOptions.signal.reason, PythonExecutionCancelledError, executionOptions.signal));
        }
        await ensureKernelAvailable(cwd, executionOptions);
        await ensureToolBridge(executionOptions);
        const kernelMode = executionOptions.kernelMode ?? "session";
        if (kernelMode === "per-call") {
            return await executePerCall(code, cwd, executionOptions);
        }
        return await sessionRegistry.executeOnSession(code, cwd, executionOptions);
    }
    catch (err) {
        if (isCancellationError(err, PythonExecutionCancelledError) || executionOptions.signal?.aborted) {
            return createCancelledPythonResult(isTimedOutCancellation(err, PythonExecutionCancelledError, executionOptions.signal));
        }
        throw err;
    }
}
