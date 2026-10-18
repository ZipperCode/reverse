import { logger } from "@rva/utils";
import { Settings } from "../config/settings";
import { OutputSink } from "@rva/tui/tools/streaming-output";
import { statusEventKey } from "@rva/tui/tools/eval";
import { resolveOutputMaxColumns, resolveOutputSinkArtifactMaxBytes, resolveOutputSinkHeadBytes, } from "../tools/output-meta";
import { EVAL_TIMEOUT_PAUSE_OP, EVAL_TIMEOUT_RESUME_OP, isEvalTimeoutControlEvent } from "./bridge-timeout";
import { registerPyToolBridge } from "./py/tool-bridge";
import { getActiveEvalShadowCell } from "./speculation/runtime-context";
/** Raised when callers reference kernel-owned state before its retained kernel exists. */
export class EvalKernelNotRunningError extends Error {
    constructor(language) {
        super(`${language} kernel is not running; tools defined with @tool / tool() live in the kernel and must be (re)defined in an eval cell first`);
        this.name = "EvalKernelNotRunningError";
    }
}
/**
 * A cell's display outputs in emission order. Progress snapshots (see
 * `statusEventKey`) replace their earlier snapshot in place, so a long `wait()`
 * over agents keeps one event per handle instead of one per poll tick. Shared
 * by the kernel (Python) and VM (JS) executors.
 */
export class DisplayOutputCollector {
    outputs = [];
    #snapshotIndex = new Map();
    push(output) {
        const display = output;
        const key = display.type === "status" ? statusEventKey(display.event) : undefined;
        if (key !== undefined) {
            const index = this.#snapshotIndex.get(key);
            if (index !== undefined) {
                this.outputs[index] = output;
                return;
            }
            this.#snapshotIndex.set(key, this.outputs.length);
        }
        this.outputs.push(output);
    }
}
// ---------------------------------------------------------------------------
// Cancellation helpers
// ---------------------------------------------------------------------------
export function getExecutionDeadlineMs(options) {
    if (options?.deadlineMs !== undefined)
        return options.deadlineMs;
    if (options?.timeoutMs === undefined)
        return undefined;
    return Date.now() + options.timeoutMs;
}
export function getRemainingTimeoutMs(deadlineMs) {
    if (deadlineMs === undefined)
        return undefined;
    return deadlineMs - Date.now();
}
export function isCancellationError(error, cancelledErrorClass) {
    return (error instanceof cancelledErrorClass ||
        (typeof DOMException !== "undefined" &&
            error instanceof DOMException &&
            (error.name === "AbortError" || error.name === "TimeoutError")) ||
        (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")));
}
export function isTimedOutCancellation(error, cancelledErrorClass, signal) {
    if (error instanceof cancelledErrorClass)
        return error.timedOut;
    if (typeof DOMException !== "undefined" && error instanceof DOMException)
        return error.name === "TimeoutError";
    if (error instanceof Error && error.name === "TimeoutError")
        return true;
    const reason = signal?.reason;
    if (typeof DOMException !== "undefined" && reason instanceof DOMException)
        return reason.name === "TimeoutError";
    return reason instanceof Error ? reason.name === "TimeoutError" : false;
}
export async function waitForPromiseWithCancellation(promise, options, cancelledErrorClass, timedOutResolver) {
    if (options.signal?.aborted) {
        throw new cancelledErrorClass(timedOutResolver?.(options.signal.reason, options.signal) ??
            isTimedOutCancellation(options.signal.reason, cancelledErrorClass, options.signal));
    }
    const remainingMs = getRemainingTimeoutMs(options.deadlineMs);
    if (remainingMs !== undefined && remainingMs <= 0) {
        throw new cancelledErrorClass(true);
    }
    if (!options.signal && remainingMs === undefined) {
        return await promise;
    }
    const { promise: resultPromise, resolve, reject } = Promise.withResolvers();
    const cleanups = [];
    const finish = (cb) => {
        while (cleanups.length > 0)
            cleanups.pop()?.();
        cb();
    };
    if (options.signal) {
        const onAbort = () => finish(() => reject(new cancelledErrorClass(timedOutResolver?.(options.signal?.reason, options.signal) ??
            isTimedOutCancellation(options.signal?.reason, cancelledErrorClass, options.signal))));
        options.signal.addEventListener("abort", onAbort, { once: true });
        cleanups.push(() => options.signal?.removeEventListener("abort", onAbort));
    }
    if (remainingMs !== undefined) {
        const timer = setTimeout(() => finish(() => reject(new cancelledErrorClass(true))), remainingMs);
        timer.unref();
        cleanups.push(() => clearTimeout(timer));
    }
    promise.then(value => finish(() => resolve(value)), err => finish(() => reject(err)));
    return await resultPromise;
}
function createBridgeAbortShield(source) {
    const shield = {
        signal: undefined,
        abortRequested: false,
        timedOut: false,
    };
    if (!source)
        return shield;
    const controller = new AbortController();
    let pauseDepth = 0;
    let abortReason;
    let removeAbortListener;
    const requestAbort = (reason) => {
        shield.abortRequested = true;
        shield.timedOut =
            shield.timedOut ||
                (typeof DOMException !== "undefined" && reason instanceof DOMException
                    ? reason.name === "TimeoutError"
                    : reason instanceof Error && reason.name === "TimeoutError");
        abortReason = reason;
        if (pauseDepth > 0 || controller.signal.aborted)
            return;
        controller.abort(reason);
    };
    const onAbort = () => {
        const reason = source.reason;
        requestAbort(reason);
    };
    shield.signal = controller.signal;
    shield.handleStatus = (event) => {
        if (event.deferExternalAbort !== true)
            return;
        if (event.op === EVAL_TIMEOUT_PAUSE_OP) {
            pauseDepth++;
            return;
        }
        if (event.op !== EVAL_TIMEOUT_RESUME_OP || pauseDepth === 0)
            return;
        pauseDepth--;
        if (shield.abortRequested && !controller.signal.aborted)
            controller.abort(abortReason);
    };
    shield.dispose = () => {
        removeAbortListener?.();
        removeAbortListener = undefined;
    };
    if (source.aborted) {
        requestAbort(source.reason);
    }
    else {
        source.addEventListener("abort", onAbort, { once: true });
        removeAbortListener = () => {
            source.removeEventListener("abort", onAbort);
        };
        if (source.aborted) {
            source.removeEventListener("abort", onAbort);
            removeAbortListener = undefined;
            requestAbort(source.reason);
        }
    }
    return shield;
}
export function createCancelledKernelResult(output) {
    const outputBytes = Buffer.byteLength(output, "utf-8");
    const outputLines = output.length > 0 ? 1 : 0;
    return {
        output,
        exitCode: undefined,
        cancelled: true,
        truncated: false,
        artifactId: undefined,
        totalLines: outputLines,
        totalBytes: outputBytes,
        outputLines,
        outputBytes,
        displayOutputs: [],
        stdinRequested: false,
    };
}
// ---------------------------------------------------------------------------
// Managed environment helpers
// ---------------------------------------------------------------------------
export const MANAGED_KERNEL_ENV_KEYS = [
    "PI_SESSION_FILE",
    "PI_ARTIFACTS_DIR",
    "PI_TOOL_BRIDGE_URL",
    "PI_TOOL_BRIDGE_TOKEN",
    "PI_TOOL_BRIDGE_SESSION",
    "RVA_EVAL_LOCAL_ROOTS",
];
export function buildManagedKernelEnvPatch(options, policy) {
    const localRoots = options.localRoots;
    if (policy?.sparse) {
        const patch = {};
        if (options.sessionFile)
            patch.PI_SESSION_FILE = options.sessionFile;
        if (options.artifactsDir)
            patch.PI_ARTIFACTS_DIR = options.artifactsDir;
        if (options.bridge) {
            patch.PI_TOOL_BRIDGE_URL = options.bridge.url;
            patch.PI_TOOL_BRIDGE_TOKEN = options.bridge.token;
            patch.PI_TOOL_BRIDGE_SESSION = options.bridgeSessionId ?? "";
        }
        if (localRoots)
            patch.RVA_EVAL_LOCAL_ROOTS = JSON.stringify(localRoots);
        return patch;
    }
    return {
        PI_SESSION_FILE: options.sessionFile ?? null,
        PI_ARTIFACTS_DIR: options.artifactsDir ?? null,
        PI_TOOL_BRIDGE_URL: options.bridge?.url ?? null,
        PI_TOOL_BRIDGE_TOKEN: options.bridge?.token ?? null,
        PI_TOOL_BRIDGE_SESSION: options.bridge && options.bridgeSessionId ? options.bridgeSessionId : null,
        RVA_EVAL_LOCAL_ROOTS: localRoots && Object.keys(localRoots).length > 0 ? JSON.stringify(localRoots) : null,
    };
}
export function buildManagedKernelEnv(options, policy) {
    const patch = policy?.sparse
        ? buildManagedKernelEnvPatch(options, { sparse: true })
        : buildManagedKernelEnvPatch(options);
    const env = {};
    let hasKeys = false;
    for (const key of MANAGED_KERNEL_ENV_KEYS) {
        const value = patch[key];
        if (typeof value === "string") {
            env[key] = value;
            hasKeys = true;
        }
    }
    return hasKeys ? env : undefined;
}
export function attachSessionOwner(session, sessionId, ownerId) {
    if (ownerId !== undefined) {
        if (session.hasFallbackOwner) {
            session.ownerIds.delete(sessionId);
            session.hasFallbackOwner = false;
        }
        session.ownerIds.add(ownerId);
        return;
    }
    if (session.hasFallbackOwner || session.ownerIds.size === 0) {
        session.ownerIds.add(sessionId);
        session.hasFallbackOwner = true;
    }
}
export async function executeWithKernelBase(params) {
    const { kernel, code, options, runIdPrefix, errorLogLabel, cancelledErrorClass, buildKernelEnvPatch, formatKernelTimeoutAnnotation, formatTimeoutAnnotation, } = params;
    const settings = await Settings.init();
    const sink = new OutputSink({
        onChunk: options?.onChunk,
        artifactPath: options?.artifactPath,
        artifactId: options?.artifactId,
        headBytes: resolveOutputSinkHeadBytes(settings),
        artifactMaxBytes: resolveOutputSinkArtifactMaxBytes(settings),
        maxColumns: resolveOutputMaxColumns(settings),
    });
    const display = new DisplayOutputCollector();
    const displayOutputs = display.outputs;
    const deadlineMs = getExecutionDeadlineMs(options);
    const remainingMs = getRemainingTimeoutMs(deadlineMs);
    const executionTimeoutMs = remainingMs !== undefined && remainingMs > 0 ? remainingMs : undefined;
    // The wall-clock timeout must abort through the same shield the bridge
    // watches. A kernel-internal timer SIGINTs the runner but leaves in-flight
    // bridge calls (wait() over agent()/completion() handles or tool.*) blocked
    // in urllib worker threads; the runner then wedges waiting for them, never
    // emits `done`, and the SIGINT escalation kills
    // the kernel — losing every variable. Expiring via the shield rejects those
    // bridge calls, so the workers unwind and the cell settles as a clean
    // KeyboardInterrupt. It also inherits critical-phase deferral: a timeout
    // landing mid-merge waits for the resume instead of settling the cell on
    // top of a half-applied git operation.
    const timeoutSignal = executionTimeoutMs !== undefined ? AbortSignal.timeout(executionTimeoutMs) : undefined;
    const abortSource = options?.signal && timeoutSignal
        ? AbortSignal.any([options.signal, timeoutSignal])
        : (timeoutSignal ?? options?.signal);
    const abortShield = createBridgeAbortShield(abortSource);
    const collectDisplay = (output) => {
        if (output.type === "status") {
            abortShield.handleStatus?.(output.event);
            options?.onStatus?.(output.event);
            if (isEvalTimeoutControlEvent(output.event))
                return;
        }
        display.push(output);
    };
    const emitStatus = options?.emitStatus ?? (event => collectDisplay({ type: "status", event }));
    const runId = `${runIdPrefix}-${crypto.randomUUID()}`;
    // Two aborts cross the bridge, and conflating them is what let a cancelled
    // turn keep working. Delegated work (above all the subagents `agent()`
    // spawns) gets the caller's real signal so it dies with the turn — shielding
    // it here made Python fan-outs outlive a cancel indefinitely,
    // while JS cells, which never route through this shield, stopped fine. The
    // shielded signal only governs how long the host waits on a call, holding
    // the cell open across a critical phase (isolation worktree setup,
    // merge/cherry-pick) so a cancel can't settle it on top of a half-applied
    // git operation.
    const unregisterBridge = options?.toolSession && options?.bridgeSessionId
        ? registerPyToolBridge(options.bridgeSessionId, runId, {
            toolSession: options.toolSession,
            signal: options.signal,
            shieldedSignal: abortShield.signal,
            emitStatus,
            shadowCell: getActiveEvalShadowCell(),
            abortRequested: () => {
                return abortShield.abortRequested;
            },
        })
        : null;
    try {
        if (remainingMs !== undefined && remainingMs <= 0) {
            throw new cancelledErrorClass(true);
        }
        const result = await kernel.execute(code, {
            cwd: options?.cwd,
            filename: options?.filename,
            env: buildKernelEnvPatch(options ?? {}),
            id: runId,
            signal: abortShield.signal,
            onChunk: text => sink.push(text),
            onDisplay: output => collectDisplay(output),
        });
        if (result.cancelled || abortShield.abortRequested) {
            const timedOut = result.timedOut || abortShield.timedOut;
            const annotation = timedOut
                ? formatKernelTimeoutAnnotation(executionTimeoutMs ?? options?.idleTimeoutMs, result.kernelKilled ?? false)
                : result.kernelKilled && !abortShield.abortRequested
                    ? "Kernel died during execution; completion is uncertain. The cell was not replayed; check for partial side effects before retrying."
                    : undefined;
            const dumped = await sink.dump(annotation);
            return {
                exitCode: undefined,
                cancelled: true,
                truncated: dumped.truncated,
                output: dumped.output,
                artifactId: dumped.artifactId ?? undefined,
                artifactElidedBytes: dumped.artifactElidedBytes,
                artifactError: dumped.artifactError,
                totalLines: dumped.totalLines,
                totalBytes: dumped.totalBytes,
                outputLines: dumped.outputLines,
                outputBytes: dumped.outputBytes,
                displayOutputs,
                stdinRequested: !!result.stdinRequested,
            };
        }
        if (result.stdinRequested) {
            const dumped = await sink.dump("Kernel requested stdin; interactive input is not supported.");
            return {
                exitCode: 1,
                cancelled: false,
                truncated: dumped.truncated,
                output: dumped.output,
                artifactId: dumped.artifactId ?? undefined,
                artifactElidedBytes: dumped.artifactElidedBytes,
                artifactError: dumped.artifactError,
                totalLines: dumped.totalLines,
                totalBytes: dumped.totalBytes,
                outputLines: dumped.outputLines,
                outputBytes: dumped.outputBytes,
                displayOutputs,
                stdinRequested: true,
            };
        }
        const exitCode = result.status === "ok" ? 0 : 1;
        const dumped = await sink.dump();
        return {
            exitCode,
            cancelled: false,
            truncated: dumped.truncated,
            output: dumped.output,
            artifactId: dumped.artifactId ?? undefined,
            artifactElidedBytes: dumped.artifactElidedBytes,
            artifactError: dumped.artifactError,
            totalLines: dumped.totalLines,
            totalBytes: dumped.totalBytes,
            outputLines: dumped.outputLines,
            outputBytes: dumped.outputBytes,
            displayOutputs,
            stdinRequested: false,
        };
    }
    catch (err) {
        if (isCancellationError(err, cancelledErrorClass) || abortShield.abortRequested || abortShield.signal?.aborted) {
            const timedOut = abortShield.timedOut || isTimedOutCancellation(err, cancelledErrorClass, abortShield.signal);
            const dumped = await sink.dump(timedOut ? formatTimeoutAnnotation(executionTimeoutMs ?? options?.idleTimeoutMs) : undefined);
            return {
                exitCode: undefined,
                cancelled: true,
                truncated: dumped.truncated,
                output: dumped.output,
                artifactId: dumped.artifactId ?? undefined,
                artifactElidedBytes: dumped.artifactElidedBytes,
                artifactError: dumped.artifactError,
                totalLines: dumped.totalLines,
                totalBytes: dumped.totalBytes,
                outputLines: dumped.outputLines,
                outputBytes: dumped.outputBytes,
                displayOutputs,
                stdinRequested: false,
            };
        }
        const error = err instanceof Error ? err : new Error(String(err));
        logger.error(`${errorLogLabel} execution failed`, { error: error.message });
        throw error;
    }
    finally {
        await sink.dispose();
        unregisterBridge?.();
        abortShield.dispose?.();
    }
}
