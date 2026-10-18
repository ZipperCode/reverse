import { untilAborted } from "@rva/utils";
import { withTimeout } from "@rva/utils/async";
import * as logger from "@rva/utils/logger";
import { Snowflake } from "@rva/utils/snowflake";
import { workerHostEntry } from "@rva/utils/worker-host";
import { ToolAbortError, toWorkerErrorPayload } from "../tool-errors";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { COMPUTER_WORKER_ARG, } from "./protocol";
const START_TIMEOUT_MS = 10000;
const CLOSE_TIMEOUT_MS = 1500;
const GRACE_MS = 750;
const SMOKE_TIMEOUT_MS = 5000;
// A capabilities request only ensures the native session and reads a getter, but
// the first ensure may load the desktop addon, so it shares the start budget.
const CAPABILITIES_TIMEOUT_MS = 10000;
const RESTART_MESSAGE = "computer worker restarted; captures and ax refs were reset";
const DEFAULT_TIMEOUTS = {
    startMs: START_TIMEOUT_MS,
    closeMs: CLOSE_TIMEOUT_MS,
};
function wrapWorker(worker) {
    return {
        send(message) {
            worker.postMessage(message);
        },
        onMessage(handler) {
            const listener = (event) => handler(event.data);
            worker.addEventListener("message", listener);
            return () => worker.removeEventListener("message", listener);
        },
        onError(handler) {
            const onError = (event) => handler(event.error instanceof Error ? event.error : new Error(event.message));
            const onMessageError = (event) => handler(new Error(`Computer worker message error: ${String(event.data)}`));
            const onClose = () => handler(new Error("Computer worker exited"));
            worker.addEventListener("error", onError);
            worker.addEventListener("messageerror", onMessageError);
            worker.addEventListener("close", onClose);
            return () => {
                worker.removeEventListener("error", onError);
                worker.removeEventListener("messageerror", onMessageError);
                worker.removeEventListener("close", onClose);
            };
        },
        async terminate() {
            worker.terminate();
        },
    };
}
/** Spawns the computer worker through the active CLI host when available. */
export function spawnComputerWorker() {
    const hostEntry = workerHostEntry();
    const worker = hostEntry
        ? new Worker(hostEntry, { type: "module", argv: [COMPUTER_WORKER_ARG] })
        : new Worker(new URL("./worker-entry.ts", import.meta.url).href, { type: "module" });
    return wrapWorker(worker);
}
function errorFromPayload(payload) {
    const error = payload.isAbort
        ? new ToolAbortError(payload.message)
        : payload.isToolError
            ? new ToolError(payload.message)
            : new Error(payload.message);
    error.name = payload.name;
    if (payload.stack)
        error.stack = payload.stack;
    return error;
}
/** Supervises one lazy, crash-isolated computer worker per agent session. */
export class ComputerSupervisor {
    #session;
    #createWorker;
    #callSessionTool;
    #timeouts;
    #worker;
    #startPromise;
    #startReject;
    #startResolve;
    #pendingCapabilities = new Map();
    #pending = new Map();
    #revocations = new Map();
    /**
     * Snapshots of runs waiting for the worker to start: a resume the worker gets before their `run` would find
     * nothing to hold, so it moves them to the turn that went on here.
     */
    #startingRuns = new Set();
    #nextId = 0;
    #controlEpoch = 0;
    #closed = false;
    #unsubscribeMessage;
    #unsubscribeError;
    constructor(session, createWorker = spawnComputerWorker, timeouts = DEFAULT_TIMEOUTS, callSessionTool = async () => {
        throw new ToolError("Computer session tool bridge is unavailable");
    }) {
        this.#session = session;
        this.#createWorker = createWorker;
        this.#timeouts = timeouts;
        this.#callSessionTool = callSessionTool;
    }
    async capabilities(snapshot, signal) {
        if (this.#closed)
            throw new ToolError("Computer session is closed");
        if (signal?.aborted)
            throw new ToolAbortError();
        await this.#start();
        if (signal?.aborted)
            throw new ToolAbortError();
        const id = `computer-cap-${++this.#nextId}`;
        const { promise, resolve, reject } = Promise.withResolvers();
        this.#pendingCapabilities.set(id, { resolve, reject });
        const abort = () => reject(signal?.reason instanceof Error ? signal.reason : new ToolAbortError());
        if (signal?.aborted)
            abort();
        else
            signal?.addEventListener("abort", abort, { once: true });
        try {
            this.#safeSend({ type: "capabilities", id, session: snapshot });
            return await withTimeout(promise, CAPABILITIES_TIMEOUT_MS, "Timed out fetching computer capabilities");
        }
        finally {
            signal?.removeEventListener("abort", abort);
            this.#pendingCapabilities.delete(id);
        }
    }
    async run(code, timeoutMs, snapshot, signal, context) {
        if (this.#closed)
            throw new ToolError("Computer session is closed");
        if (signal?.aborted)
            throw new ToolAbortError();
        const epoch = this.#controlEpoch;
        const session = { ...snapshot };
        this.#startingRuns.add(session);
        try {
            await this.#start();
        }
        finally {
            this.#startingRuns.delete(session);
        }
        if (signal?.aborted || epoch !== this.#controlEpoch)
            throw new ToolAbortError();
        const id = `computer-${++this.#nextId}`;
        const { promise, resolve, reject } = Promise.withResolvers();
        const pending = { resolve, reject, signal, context, toolCalls: new Map() };
        this.#pending.set(id, pending);
        const abort = () => {
            this.#safeSend({ type: "abort", id });
            for (const controller of pending.toolCalls.values())
                controller.abort(signal?.reason);
        };
        if (signal?.aborted)
            abort();
        else
            signal?.addEventListener("abort", abort, { once: true });
        try {
            this.#worker?.send({ type: "run", id, code, timeoutMs, session });
            return await this.#raceWithGrace(promise, timeoutMs);
        }
        finally {
            signal?.removeEventListener("abort", abort);
            this.#pending.delete(id);
        }
    }
    #start() {
        if (this.#startPromise)
            return this.#startPromise;
        const started = Promise.withResolvers();
        this.#startReject = started.reject;
        this.#startResolve = started.resolve;
        try {
            logger.debug("Starting computer worker");
            const worker = this.#createWorker();
            this.#worker = worker;
            this.#unsubscribeMessage = worker.onMessage(message => this.#handleMessage(message));
            this.#unsubscribeError = worker.onError(error => {
                void this.#workerFailed(error);
            });
        }
        catch (error) {
            started.reject(error);
        }
        this.#startPromise = withTimeout(started.promise, this.#timeouts.startMs, "Timed out starting computer worker").catch(async (error) => {
            await this.#terminate(error);
            throw error;
        });
        return this.#startPromise;
    }
    #handleMessage(message) {
        if (message.type === "ready") {
            this.#startResolve?.();
            this.#startResolve = undefined;
            this.#startReject = undefined;
            return;
        }
        if (message.type === "control-revoked") {
            this.#revocations.get(message.id)?.();
            this.#revocations.delete(message.id);
            return;
        }
        if (message.type === "result") {
            const pending = this.#pending.get(message.id);
            if (!pending)
                return;
            for (const controller of pending.toolCalls.values())
                controller.abort(new ToolAbortError("Computer run ended"));
            this.#pending.delete(message.id);
            if (message.ok)
                pending.resolve(message.payload);
            else
                pending.reject(errorFromPayload(message.error));
            return;
        }
        if (message.type === "capabilities") {
            const pending = this.#pendingCapabilities.get(message.id);
            if (!pending)
                return;
            this.#pendingCapabilities.delete(message.id);
            if (message.ok)
                pending.resolve(message.capabilities);
            else
                pending.reject(errorFromPayload(message.error));
            return;
        }
        if (message.type === "control-request") {
            void this.#confirmControl(message);
            return;
        }
        if (message.type === "tool-call") {
            void this.#dispatchToolCall(message);
        }
    }
    async #confirmControl(message) {
        const pending = this.#pending.get(message.runId);
        if (!pending)
            return;
        const controller = new AbortController();
        pending.toolCalls.set(message.id, controller);
        const onAbort = () => controller.abort(pending.signal?.reason);
        if (pending.signal?.aborted)
            onAbort();
        else
            pending.signal?.addEventListener("abort", onAbort, { once: true });
        try {
            const context = pending.context ?? this.#session.getToolContext?.();
            let approved = false;
            if (context?.ui && context.hasUI !== false && !controller.signal.aborted) {
                approved =
                    (await untilAborted(controller.signal, () => context.ui.confirm("Allow foreground computer control?", `${message.reason}\n\nFor this task only. Use the host interrupt to stop and revoke control. This does not authorize external side effects.`, { signal: controller.signal }))) === true;
            }
            if (controller.signal.aborted || this.#pending.get(message.runId) !== pending)
                approved = false;
            this.#safeSend({ type: "tool-reply", id: message.id, reply: { ok: true, value: approved } });
        }
        catch (error) {
            this.#safeSend({
                type: "tool-reply",
                id: message.id,
                reply: { ok: false, error: toWorkerErrorPayload(error) },
            });
        }
        finally {
            pending.toolCalls.delete(message.id);
            pending.signal?.removeEventListener("abort", onAbort);
        }
    }
    async revokeControl() {
        this.#controlEpoch += 1;
        for (const pending of this.#pending.values()) {
            for (const controller of pending.toolCalls.values())
                controller.abort(new ToolAbortError());
        }
        if (!this.#worker)
            return;
        const id = `computer-revoke-${++this.#nextId}`;
        const acknowledged = Promise.withResolvers();
        this.#revocations.set(id, acknowledged.resolve);
        this.#safeSend({ type: "revoke-control", id });
        try {
            await withTimeout(acknowledged.promise, CLOSE_TIMEOUT_MS, "Timed out revoking computer control");
        }
        catch (error) {
            await this.#terminate(error);
        }
        finally {
            this.#revocations.delete(id);
        }
    }
    releaseDisplay(turn) {
        this.#safeSend({ type: "release-display", turn });
    }
    resumeDisplay(from, turn) {
        for (const starting of this.#startingRuns)
            if (starting.displayTurn === from)
                starting.displayTurn = turn;
        this.#safeSend({ type: "resume-display", from, turn });
    }
    async #dispatchToolCall(message) {
        const pending = this.#pending.get(message.runId);
        if (!pending) {
            this.#safeSend({
                type: "tool-reply",
                id: message.id,
                reply: {
                    ok: false,
                    error: { name: "ToolError", message: "No active run for tool call", isToolError: true, isAbort: false },
                },
            });
            return;
        }
        const controller = new AbortController();
        pending.toolCalls.set(message.id, controller);
        const onParentAbort = () => controller.abort(pending.signal?.reason);
        if (pending.signal?.aborted)
            onParentAbort();
        else
            pending.signal?.addEventListener("abort", onParentAbort, { once: true });
        try {
            const value = await this.#callSessionTool(message.name, message.args, {
                session: this.#session,
                signal: controller.signal,
                emitStatus: () => { },
            });
            this.#safeSend({ type: "tool-reply", id: message.id, reply: { ok: true, value } });
        }
        catch (error) {
            this.#safeSend({
                type: "tool-reply",
                id: message.id,
                reply: { ok: false, error: toWorkerErrorPayload(error) },
            });
        }
        finally {
            pending.toolCalls.delete(message.id);
            pending.signal?.removeEventListener("abort", onParentAbort);
        }
    }
    #safeSend(message) {
        try {
            this.#worker?.send(message);
        }
        catch (error) {
            logger.debug("Computer worker send failed", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    }
    async #raceWithGrace(promise, timeoutMs) {
        const timeoutSignal = AbortSignal.timeout(timeoutMs + GRACE_MS);
        const timeout = Promise.withResolvers();
        const onTimeout = () => timeout.reject(new ToolError(RESTART_MESSAGE));
        timeoutSignal.addEventListener("abort", onTimeout, { once: true });
        try {
            return await Promise.race([promise, timeout.promise]);
        }
        catch (error) {
            if (error instanceof ToolError && error.message === RESTART_MESSAGE)
                await this.#terminate(error);
            throw error;
        }
        finally {
            timeoutSignal.removeEventListener("abort", onTimeout);
        }
    }
    async #workerFailed(error) {
        logger.warn("Computer worker failed", { error: error.message });
        await this.#terminate(error);
    }
    async #terminate(reason) {
        const worker = this.#worker;
        this.#worker = undefined;
        this.#startPromise = undefined;
        this.#startReject?.(reason);
        this.#startReject = undefined;
        this.#startResolve = undefined;
        this.#unsubscribeMessage?.();
        this.#unsubscribeMessage = undefined;
        this.#unsubscribeError?.();
        this.#unsubscribeError = undefined;
        for (const pending of this.#pending.values()) {
            for (const controller of pending.toolCalls.values())
                controller.abort(reason);
            pending.reject(reason);
        }
        this.#pending.clear();
        for (const pending of this.#pendingCapabilities.values())
            pending.reject(reason);
        this.#pendingCapabilities.clear();
        for (const resolve of this.#revocations.values())
            resolve();
        this.#revocations.clear();
        await worker?.terminate().catch(() => undefined);
    }
    async close() {
        if (this.#closed)
            return;
        this.#closed = true;
        const worker = this.#worker;
        if (!worker)
            return;
        const closed = Promise.withResolvers();
        const unsubscribe = worker.onMessage(message => {
            if (message.type === "closed")
                closed.resolve();
        });
        try {
            worker.send({ type: "close" });
            await withTimeout(closed.promise, this.#timeouts.closeMs, "Timed out closing computer worker");
        }
        catch {
            // Forced termination below is the bounded close fallback.
        }
        finally {
            unsubscribe();
            await this.#terminate(new ToolError("Computer session closed"));
        }
    }
}
const ownedSupervisors = new Map();
/** Per owner with agent turns: the turn in flight, or between turns the one that ended last, counted from 1. */
const ownerTurns = new Map();
/** Registers a controller for owner-scoped session cleanup. */
export function registerComputerController(ownerId, controller) {
    if (!ownerId)
        return () => { };
    const controllers = ownedSupervisors.get(ownerId) ?? new Set();
    controllers.add(controller);
    ownedSupervisors.set(ownerId, controllers);
    return () => {
        controllers.delete(controller);
        if (controllers.size === 0)
            ownedSupervisors.delete(ownerId);
    };
}
/** Revoke task-scoped foreground ownership without resetting frames or the worker. */
export async function revokeComputerControlForOwner(ownerId) {
    if (!ownerId)
        return;
    await Promise.allSettled(Array.from(ownedSupervisors.get(ownerId) ?? [], controller => controller.revokeControl?.()));
}
/**
 * An agent session's turn began, or went on after the user answered a dialog: computer runs keep the display awake
 * until {@link endComputerTurnForOwner}.
 */
export function beginComputerTurnForOwner(ownerId) {
    if (!ownerId)
        return;
    const state = ownerTurns.get(ownerId);
    ownerTurns.set(ownerId, { turn: (state?.turn ?? 0) + 1, inFlight: true });
}
/**
 * The turn ended or stopped to wait for the user's answer: let the display sleep now instead of a grace period later.
 * Nothing else ends with the turn; its next computer request after the answer, or the next turn's first, holds the
 * display again.
 */
export function endComputerTurnForOwner(ownerId) {
    const state = ownerId ? ownerTurns.get(ownerId) : undefined;
    if (!ownerId || !state?.inFlight)
        return;
    state.inFlight = false;
    for (const controller of ownedSupervisors.get(ownerId) ?? [])
        controller.releaseDisplay?.(state.turn);
}
/**
 * The turn went on after the dialog that ended it settled: later runs hold the display until the turn ends, and so
 * does a run of the turn that is still active, such as one whose control confirmation the dialog was.
 */
export function resumeComputerTurnForOwner(ownerId) {
    const state = ownerId ? ownerTurns.get(ownerId) : undefined;
    if (!ownerId || !state || state.inFlight)
        return;
    const from = state.turn;
    state.turn = from + 1;
    state.inFlight = true;
    for (const controller of ownedSupervisors.get(ownerId) ?? [])
        controller.resumeDisplay?.(from, state.turn);
}
/**
 * The owner's agent turn in flight, if any. Without one (between turns, while a dialog waits for the user, in a
 * subagent, or SDK and eval use with no agent session), a computer run keeps the native grace period.
 */
export function computerTurnInFlight(ownerId) {
    const state = ownerId ? ownerTurns.get(ownerId) : undefined;
    return state?.inFlight ? state.turn : undefined;
}
/** Closes every computer session owned by an agent session. */
export async function releaseComputerSessionsForOwner(ownerId) {
    if (!ownerId)
        return;
    ownerTurns.delete(ownerId);
    const controllers = ownedSupervisors.get(ownerId);
    if (!controllers)
        return;
    ownedSupervisors.delete(ownerId);
    await Promise.allSettled(Array.from(controllers, controller => controller.close()));
}
/** Verifies computer worker startup, messaging, and bounded shutdown. */
export async function smokeTestComputerWorker(timeoutMs = SMOKE_TIMEOUT_MS, createWorker = spawnComputerWorker) {
    const worker = createWorker();
    const waitFor = async (expected, failureMessage) => {
        const response = Promise.withResolvers();
        const unsubscribeMessage = worker.onMessage(received => {
            if (received.type === expected)
                response.resolve();
            else if (received.type === "result" && !received.ok)
                response.reject(errorFromPayload(received.error));
        });
        const unsubscribeError = worker.onError(error => response.reject(error));
        try {
            await withTimeout(response.promise, timeoutMs, failureMessage);
        }
        finally {
            unsubscribeMessage();
            unsubscribeError();
        }
    };
    try {
        const pong = waitFor("pong", "Computer worker smoke ping timed out");
        worker.send({ type: "ping", id: `computer-smoke-${Snowflake.next()}` });
        await pong;
        const closed = waitFor("closed", "Computer worker smoke close timed out");
        worker.send({ type: "close" });
        await closed;
    }
    finally {
        await worker.terminate();
    }
}
