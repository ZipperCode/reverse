import { MAIN_AGENT_ID } from "../registry/agent-registry";
import { ToolAbortError } from "../tools/tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { withBridgeTimeoutPause } from "./bridge-timeout";
import { getCompletionHandle } from "./completion-bridge";
/** Synthetic bridge name reserved for waiting on eval handles. */
export const EVAL_WAIT_BRIDGE_NAME = "__wait__";
/** Synthetic bridge name reserved for inspecting an eval handle. */
export const EVAL_STATUS_BRIDGE_NAME = "__status__";
/** Synthetic bridge name reserved for cancelling an eval handle. */
export const EVAL_CANCEL_BRIDGE_NAME = "__cancel__";
function isUnknownRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}
function parseRef(value) {
    if (!isUnknownRecord(value))
        throw new ToolError("handle must be an object with kind and id");
    const { kind, id } = value;
    if ((kind !== "agent" && kind !== "completion") || typeof id !== "string" || id.length === 0) {
        throw new ToolError("handle must contain kind agent|completion and a non-empty id");
    }
    return { kind, id };
}
function parseRefs(args) {
    if (!isUnknownRecord(args) || !Array.isArray(args.items)) {
        throw new ToolError("wait() requires an items array");
    }
    const items = args.items.map(parseRef);
    const timeoutMs = args.timeoutMs;
    if (timeoutMs !== undefined && (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs < 0)) {
        throw new ToolError("wait() timeoutMs must be a non-negative finite number");
    }
    return { items, ...(typeof timeoutMs === "number" ? { timeoutMs } : {}) };
}
function parseSingleRef(args) {
    if (!isUnknownRecord(args))
        throw new ToolError("handle request requires an item");
    return parseRef(args.item);
}
function resolveHandle(ref, options) {
    const ownerId = options.session.getAgentId?.() ?? MAIN_AGENT_ID;
    if (ref.kind === "agent") {
        const manager = options.session.asyncJobManager;
        const job = manager?.getJob(ref.id);
        if (!manager || !job || job.ownerId !== ownerId) {
            throw new ToolError(`unknown agent handle ${ref.id}; result expired — read agent://${ref.id}`);
        }
        return { ref, job, manager };
    }
    const completion = getCompletionHandle(ref.id);
    if (!completion || completion.ownerId !== ownerId) {
        throw new ToolError(`unknown completion handle ${ref.id}; result expired`);
    }
    return { ref, completion };
}
function agentSnapshot(ref, job) {
    if (job.status === "running")
        return { ...ref, status: "running" };
    if (job.status === "failed") {
        return { ...ref, status: "failed", error: job.errorText || "Agent failed" };
    }
    if (job.status === "cancelled") {
        return { ...ref, status: "cancelled", error: job.errorText || job.resultText || "Agent cancelled" };
    }
    const snapshot = { ...ref, status: "completed", text: job.resultText ?? "" };
    const evalResult = job.latestDetails?.evalResult;
    if (isUnknownRecord(evalResult)) {
        if (typeof evalResult.text === "string")
            snapshot.text = evalResult.text;
        if (Object.hasOwn(evalResult, "data"))
            snapshot.data = evalResult.data;
    }
    return snapshot;
}
function completionSnapshot(ref, entry) {
    if (!entry.settled)
        return { ...ref, status: "running" };
    if (entry.error) {
        return {
            ...ref,
            status: entry.controller.signal.aborted ? "cancelled" : "failed",
            error: entry.error,
        };
    }
    const snapshot = { ...ref, status: "completed", text: entry.result?.text ?? "" };
    if (entry.result && Object.hasOwn(entry.result, "data"))
        snapshot.data = entry.result.data;
    return snapshot;
}
function snapshot(resolved) {
    return "job" in resolved
        ? agentSnapshot(resolved.ref, resolved.job)
        : completionSnapshot(resolved.ref, resolved.completion);
}
function cancelResolved(resolved, reason) {
    if ("job" in resolved) {
        return resolved.manager.cancel(resolved.job.id, { ownerId: resolved.job.ownerId });
    }
    if (resolved.completion.settled)
        return false;
    resolved.completion.controller.abort(reason);
    return true;
}
function emitProgress(resolved, emitStatus, previousProgress) {
    if (!emitStatus || !("job" in resolved))
        return previousProgress;
    const progress = resolved.job.latestDetails?.progress;
    const first = Array.isArray(progress) ? progress[0] : undefined;
    if (!isUnknownRecord(first) || first === previousProgress)
        return previousProgress;
    const task = typeof first.assignment === "string" ? first.assignment : first.task;
    const taskPreview = typeof task === "string" ? task.split("\n")[0]?.slice(0, 120) : undefined;
    emitStatus({
        ...first,
        op: "agent",
        id: resolved.job.agentId ?? resolved.job.id,
        taskPreview: taskPreview || undefined,
    });
    return first;
}
/** Largest setTimeout delay before 32-bit overflow (Node/Bun warn and fire in ~1ms past this). */
const MAX_TIMER_MS = 2147483647;
async function waitForSettlement(resolved, timeoutMs, signal) {
    const waiting = Promise.allSettled(resolved.map(handle => ("job" in handle ? handle.job.promise : handle.completion.promise))).then(() => "settled");
    const races = [waiting];
    let timeout;
    if (timeoutMs !== undefined) {
        const deferred = Promise.withResolvers();
        // setTimeout overflows past 2^31-1 ms (fires in ~1ms with a
        // TimeoutOverflowWarning): re-arm in max-size chunks (#12375).
        let remaining = timeoutMs;
        const arm = () => {
            timeout = setTimeout(() => {
                remaining -= MAX_TIMER_MS;
                if (remaining > 0)
                    arm();
                else
                    deferred.resolve("timeout");
            }, Math.min(Math.max(0, remaining), MAX_TIMER_MS));
            timeout.unref?.();
        };
        arm();
        races.push(deferred.promise);
    }
    let onAbort;
    if (signal) {
        const deferred = Promise.withResolvers();
        onAbort = () => deferred.resolve("aborted");
        if (signal.aborted)
            onAbort();
        else
            signal.addEventListener("abort", onAbort, { once: true });
        races.push(deferred.promise);
    }
    try {
        return await Promise.race(races);
    }
    finally {
        clearTimeout(timeout);
        if (onAbort)
            signal?.removeEventListener("abort", onAbort);
    }
}
/** Wait for agent/completion handles and consume settled agent job deliveries. */
export async function runEvalWait(args, options) {
    const { items, timeoutMs } = parseRefs(args);
    const resolved = items.map(item => resolveHandle(item, options));
    const emittedProgress = new Map();
    const emitLatestProgress = (handle) => {
        if (!("job" in handle))
            return;
        const progress = emitProgress(handle, options.emitStatus, emittedProgress.get(handle.ref.id));
        if (progress)
            emittedProgress.set(handle.ref.id, progress);
    };
    return await withBridgeTimeoutPause(options.emitStatus, async () => {
        for (const handle of resolved)
            emitLatestProgress(handle);
        const interval = setInterval(() => {
            for (const handle of resolved)
                emitLatestProgress(handle);
        }, 1000);
        interval.unref?.();
        let outcome;
        try {
            outcome = await waitForSettlement(resolved, timeoutMs, options.signal);
        }
        finally {
            clearInterval(interval);
        }
        for (const handle of resolved)
            emitLatestProgress(handle);
        if (outcome === "aborted") {
            for (const handle of resolved)
                cancelResolved(handle, options.signal?.reason);
            await Promise.allSettled(resolved.map(handle => ("job" in handle ? handle.job.promise : handle.completion.promise)));
            throw new ToolAbortError(undefined, { cause: options.signal?.reason });
        }
        const snapshots = resolved.map(snapshot);
        const settledAgentIds = resolved
            .filter(handle => "job" in handle && handle.job.status !== "running")
            .map(handle => handle.ref.id);
        const manager = options.session.asyncJobManager;
        if (manager && settledAgentIds.length > 0)
            manager.consumeJobResults(settledAgentIds);
        return { items: snapshots };
    }, resolved.some(handle => "job" in handle) ? { deferExternalAbort: true } : undefined);
}
/** Return one handle's current state without waiting or consuming it. */
export function runEvalStatus(args, options) {
    return snapshot(resolveHandle(parseSingleRef(args), options));
}
/** Cancel one running eval handle owned by this session. */
export function runEvalCancel(args, options) {
    const resolved = resolveHandle(parseSingleRef(args), options);
    return { cancelled: cancelResolved(resolved, new ToolAbortError("Cancelled by eval handle")) };
}
