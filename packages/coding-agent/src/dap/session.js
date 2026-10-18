import * as path from "node:path";
import * as timers from "node:timers/promises";
import { logger, ptree, untilAborted } from "@rva/utils";
import { NON_INTERACTIVE_ENV } from "../exec/non-interactive-env";
import { DapClient } from "./client";
const IDLE_TIMEOUT_MS = 10 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 30 * 1000;
const HEARTBEAT_INTERVAL_MS = 5 * 1000;
const MAX_OUTPUT_BYTES = 128 * 1024;
const STOP_CAPTURE_TIMEOUT_MS = 5000;
function toErrorMessage(value) {
    if (value instanceof Error)
        return value.message;
    return String(value);
}
function trackDapStartRequest(promise, failure) {
    const tracked = promise.catch(error => {
        failure.rejected = true;
        failure.error = error;
        throw error;
    });
    failure.settled = tracked.then(() => { }, () => { });
    return tracked;
}
function combineDapStartErrors(command, startError, configurationError) {
    const startMessage = toErrorMessage(startError);
    const configurationMessage = toErrorMessage(configurationError);
    if (startMessage === configurationMessage) {
        return startError instanceof Error ? startError : new Error(startMessage);
    }
    return new Error(`DAP ${command} failed: ${startMessage}\nDAP configurationDone also failed: ${configurationMessage}`);
}
async function throwPreferredDapStartError(command, startFailure, configurationError) {
    await Promise.race([startFailure.settled ?? Promise.resolve(), timers.setTimeout(50)]);
    if (startFailure.rejected) {
        throw combineDapStartErrors(command, startFailure.error, configurationError);
    }
    throw configurationError;
}
const DEBUGPY_MISSING_MODULE_RE = /No module named ['"]?debugpy['"]?/;
/**
 * Map a generic adapter-side failure into the targeted `pip install debugpy`
 * hint when the adapter is debugpy and stderr/the wrapping error mentions
 * the missing module. Returns null when the heuristic does not apply, so the
 * caller can rethrow the original error untouched.
 */
function mapDebugpyMissingModule(adapterName, error) {
    if (adapterName !== "debugpy")
        return null;
    if (!DEBUGPY_MISSING_MODULE_RE.test(toErrorMessage(error)))
        return null;
    return new Error("adapter 'debugpy' is not available: install with 'pip install debugpy'");
}
function normalizePath(filePath) {
    return path.resolve(filePath);
}
function truncateOutput(session, output) {
    if (!output)
        return;
    const bytes = Buffer.byteLength(output, "utf-8");
    session.outputChunks.push(output);
    session.outputBytes += bytes;
    session.outputBufferedBytes += bytes;
    // Trim whole chunks from the front, but only while the remainder still
    // holds a full MAX_OUTPUT_BYTES tail — dropping the front chunk whenever
    // the total exceeded the cap could retain far less than the cap (e.g.
    // [120KB, 10KB] would keep only 10KB). Recomputing one big string's byte
    // length per 1KB trim iteration was O(n^2) inside the event dispatch loop.
    while (session.outputChunks.length > 1) {
        const frontBytes = Buffer.byteLength(session.outputChunks[0], "utf-8");
        if (session.outputBufferedBytes - frontBytes < MAX_OUTPUT_BYTES)
            break;
        session.outputChunks.shift();
        session.outputBufferedBytes -= frontBytes;
        session.outputTruncated = true;
    }
    if (session.outputBufferedBytes > MAX_OUTPUT_BYTES) {
        // Byte-slice the front chunk's head so exactly the cap remains (a torn
        // code point at the cut decodes as U+FFFD, acceptable for log output).
        const front = session.outputChunks[0];
        const frontBytes = Buffer.byteLength(front, "utf-8");
        const excess = session.outputBufferedBytes - MAX_OUTPUT_BYTES;
        const kept = Buffer.from(front, "utf-8").subarray(excess).toString("utf-8");
        session.outputChunks[0] = kept;
        session.outputBufferedBytes += Buffer.byteLength(kept, "utf-8") - frontBytes;
        session.outputTruncated = true;
    }
}
/**
 * Drain a `runInTerminal` debuggee's stdout into the session output buffer.
 *
 * `ptree.spawn` always pipes stdout and only eagerly drains stderr; the exposed
 * stdout stream must be consumed or Bun buffers it unboundedly in this process
 * (a chatty debuggee grows omp toward OOM). The reverse-request path has no
 * terminal surface here, so route the child's stdout through {@link
 * truncateOutput}: this bounds memory at `MAX_OUTPUT_BYTES` and surfaces the
 * program's output to the agent, mirroring the adapter's own `output` events.
 * Runs in the background for the child's lifetime; a killed child or closed pipe
 * ends the loop quietly.
 */
async function drainTerminalStdout(stream, session) {
    const decoder = new TextDecoder();
    try {
        for await (const chunk of stream) {
            truncateOutput(session, decoder.decode(chunk, { stream: true }));
        }
        truncateOutput(session, decoder.decode());
    }
    catch {
        // Child killed or pipe closed mid-stream; nothing more to surface.
    }
}
function summarizeBreakpointCount(breakpoints) {
    let total = 0;
    for (const entries of breakpoints.values()) {
        total += entries.length;
    }
    return total;
}
function buildSummary(session) {
    return {
        id: session.id,
        adapter: session.adapter.name,
        cwd: session.cwd,
        program: session.program,
        status: session.status,
        launchedAt: new Date(session.launchedAt).toISOString(),
        lastUsedAt: new Date(session.lastUsedAt).toISOString(),
        threadId: session.stop.threadId,
        frameId: session.stop.frameId,
        stopReason: session.stop.reason,
        stopDescription: session.stop.description ?? session.stop.text,
        frameName: session.stop.frameName,
        instructionPointerReference: session.stop.instructionPointerReference,
        source: session.stop.source,
        line: session.stop.line,
        column: session.stop.column,
        breakpointFiles: session.breakpoints.size,
        breakpointCount: summarizeBreakpointCount(session.breakpoints),
        functionBreakpointCount: session.functionBreakpoints.length,
        outputBytes: session.outputBytes,
        outputTruncated: session.outputTruncated,
        exitCode: session.exitCode,
        needsConfigurationDone: session.needsConfigurationDone && !session.configurationDoneSent,
        parentSessionId: session.parentSessionId,
        childSessionIds: session.childSessionIds.size > 0 ? Array.from(session.childSessionIds) : undefined,
    };
}
export class DapSessionManager {
    #sessions = new Map();
    #activeSessionId = null;
    #cleanupLoopPromise;
    #nextId = 0;
    #treeOutcomeWaiters = new Set();
    constructor() {
        this.#startCleanupTimer();
    }
    getActiveSession() {
        const session = this.#getActiveSessionOrNull();
        return session ? buildSummary(session) : null;
    }
    listSessions() {
        return Array.from(this.#sessions.values()).map(buildSummary);
    }
    getCapabilities() {
        return this.#getActiveSessionOrNull()?.capabilities ?? null;
    }
    async launch(options, signal, timeoutMs = 30000) {
        await this.#ensureLaunchSlot();
        const client = await DapClient.spawn({ adapter: options.adapter, cwd: options.cwd });
        const session = this.#registerSession(client, options.adapter, options.cwd, options.program);
        try {
            session.capabilities = await client.initialize(this.#buildInitializeArguments(options.adapter), signal, timeoutMs);
            session.needsConfigurationDone = session.capabilities.supportsConfigurationDoneRequest === true;
            const launchArguments = {
                ...options.adapter.launchDefaults,
                ...options.extraLaunchArguments,
                program: options.program,
                cwd: options.cwd,
                ...(options.args !== undefined ? { args: options.args } : {}),
            };
            // Subscribe to stop events BEFORE launching so we don't miss
            // stopOnEntry events that arrive before we start listening.
            const initialStopPromise = this.#prepareStopOutcome(session, signal, Math.min(timeoutMs, STOP_CAPTURE_TIMEOUT_MS));
            // DAP spec: many adapters do not respond to launch until after
            // configurationDone. Fire launch, complete the config handshake,
            // then await the launch response.
            const launchFailure = { rejected: false };
            const launchPromise = trackDapStartRequest(client.sendRequest("launch", launchArguments, signal, timeoutMs), launchFailure);
            // Mark handled so a fast error response doesn't become an unhandled
            // rejection while we await the config handshake. The actual error
            // still propagates when we await launchPromise below.
            launchPromise.catch(() => { });
            try {
                await this.#completeConfigurationHandshake(session, signal, timeoutMs);
            }
            catch (error) {
                await throwPreferredDapStartError("launch", launchFailure, error);
            }
            await launchPromise;
            // Try to capture initial stopped state (e.g. stopOnEntry).
            // Timeout is acceptable — the program may simply be running.
            let resultSession = session;
            try {
                await untilAborted(signal, initialStopPromise);
                const active = this.#getActiveSessionOrNull();
                if (active && this.#getRootSession(active).id === session.id) {
                    resultSession = active;
                }
                if (resultSession.status === "stopped") {
                    await this.#fetchTopFrame(resultSession, signal, Math.min(timeoutMs, STOP_CAPTURE_TIMEOUT_MS));
                }
            }
            catch {
                if (session.initializedSeen && session.status === "launching") {
                    session.status = session.configurationDoneSent ? "running" : "configuring";
                }
            }
            return buildSummary(resultSession);
        }
        catch (error) {
            await this.#disposeSession(session);
            const mapped = mapDebugpyMissingModule(options.adapter.name, error);
            if (mapped)
                throw mapped;
            throw error;
        }
    }
    async attach(options, signal, timeoutMs = 30000) {
        await this.#ensureLaunchSlot();
        const client = await DapClient.spawn({ adapter: options.adapter, cwd: options.cwd });
        const session = this.#registerSession(client, options.adapter, options.cwd);
        try {
            session.capabilities = await client.initialize(this.#buildInitializeArguments(options.adapter), signal, timeoutMs);
            session.needsConfigurationDone = session.capabilities.supportsConfigurationDoneRequest === true;
            if (options.adapter.attachDefaults.skipAttachRequest === true) {
                await this.#completeConfigurationHandshake(session, signal, timeoutMs);
                return buildSummary(session);
            }
            const attachArguments = {
                ...options.adapter.attachDefaults,
                cwd: options.cwd,
                ...(options.pid !== undefined ? { pid: options.pid, processId: options.pid } : {}),
                ...(options.port !== undefined ? { port: options.port } : {}),
                ...(options.host ? { host: options.host } : {}),
            };
            const initialStopPromise = this.#prepareStopOutcome(session, signal, Math.min(timeoutMs, STOP_CAPTURE_TIMEOUT_MS));
            const attachFailure = { rejected: false };
            const attachPromise = trackDapStartRequest(client.sendRequest("attach", attachArguments, signal, timeoutMs), attachFailure);
            attachPromise.catch(() => { });
            try {
                await this.#completeConfigurationHandshake(session, signal, timeoutMs);
            }
            catch (error) {
                await throwPreferredDapStartError("attach", attachFailure, error);
            }
            await attachPromise;
            let resultSession = session;
            try {
                await untilAborted(signal, initialStopPromise);
                const active = this.#getActiveSessionOrNull();
                if (active && this.#getRootSession(active).id === session.id) {
                    resultSession = active;
                }
                if (resultSession.status === "stopped") {
                    await this.#fetchTopFrame(resultSession, signal, Math.min(timeoutMs, STOP_CAPTURE_TIMEOUT_MS));
                }
            }
            catch {
                if (session.initializedSeen && session.status === "launching") {
                    session.status = session.configurationDoneSent ? "running" : "configuring";
                }
            }
            return buildSummary(resultSession);
        }
        catch (error) {
            await this.#disposeSession(session);
            const mapped = mapDebugpyMissingModule(options.adapter.name, error);
            if (mapped)
                throw mapped;
            throw error;
        }
    }
    /**
     * Serialize breakpoint mutations per session: every mutator does a
     * read-modify-write of session state around an await, and the adapter-side
     * set*Breakpoints request replaces the whole list — concurrent mutations
     * would silently drop each other's breakpoints on both sides.
     */
    #serializeBreakpointMutation(session, mutate, signal) {
        const run = session.breakpointMutationQueue.then(() => {
            // A mutation can sit behind several queued 30s predecessors; honor a
            // caller abort at dequeue instead of running a request nobody awaits.
            if (signal?.aborted)
                throw signal.reason instanceof Error ? signal.reason : new Error("Aborted");
            return mutate();
        });
        session.breakpointMutationQueue = run.then(() => undefined, () => undefined);
        return run;
    }
    async #syncBreakpointTree(origin, command, args, prepare, apply, signal, timeoutMs = 30000) {
        const sessions = this.#getTreeSessions(origin).filter(session => session.status !== "terminated" && session.client.isAlive());
        for (const session of sessions)
            prepare(session);
        await this.#serializeBreakpointMutation(origin, async () => {
            const response = await this.#sendRequestWithConfig(origin, command, args, signal, timeoutMs);
            apply(origin, response?.breakpoints);
        }, signal);
        await Promise.all(sessions
            .filter(session => session !== origin)
            .map(async (session) => {
            try {
                await this.#serializeBreakpointMutation(session, async () => {
                    const response = await this.#sendRequestWithConfig(session, command, args, signal, timeoutMs);
                    apply(session, response?.breakpoints);
                }, signal);
            }
            catch (error) {
                logger.warn("Failed to synchronize breakpoint request with child debug session", {
                    sessionId: session.id,
                    command,
                    error: toErrorMessage(error),
                });
            }
        }));
    }
    async setBreakpoint(file, line, condition, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const sourcePath = normalizePath(file);
        const root = this.#getRootSession(session);
        const current = Array.from(root.breakpoints.get(sourcePath) ?? []).filter(entry => entry.line !== line);
        current.push({ verified: false, line, condition });
        current.sort((left, right) => left.line - right.line);
        const args = {
            source: { path: sourcePath, name: path.basename(sourcePath) },
            breakpoints: current.map(entry => ({
                line: entry.line,
                ...(entry.condition ? { condition: entry.condition } : {}),
            })),
        };
        await this.#syncBreakpointTree(session, "setBreakpoints", args, target => target.breakpoints.set(sourcePath, current.map(entry => ({ ...entry, verified: false }))), (target, response) => target.breakpoints.set(sourcePath, this.#mapSourceBreakpoints(current, response)), signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: session.breakpoints.get(sourcePath) ?? [],
            sourcePath,
        };
    }
    async removeBreakpoint(file, line, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const sourcePath = normalizePath(file);
        const root = this.#getRootSession(session);
        const current = Array.from(root.breakpoints.get(sourcePath) ?? []).filter(entry => entry.line !== line);
        const args = {
            source: { path: sourcePath, name: path.basename(sourcePath) },
            breakpoints: current.map(entry => ({
                line: entry.line,
                ...(entry.condition ? { condition: entry.condition } : {}),
            })),
        };
        const prepare = (target) => {
            if (current.length === 0)
                target.breakpoints.delete(sourcePath);
            else
                target.breakpoints.set(sourcePath, current.map(entry => ({ ...entry, verified: false })));
        };
        await this.#syncBreakpointTree(session, "setBreakpoints", args, prepare, (target, response) => {
            if (current.length === 0)
                target.breakpoints.delete(sourcePath);
            else
                target.breakpoints.set(sourcePath, this.#mapSourceBreakpoints(current, response));
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: session.breakpoints.get(sourcePath) ?? [],
            sourcePath,
        };
    }
    async setFunctionBreakpoint(name, condition, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).functionBreakpoints.filter(entry => entry.name !== name);
        current.push({ verified: false, name, condition });
        current.sort((left, right) => left.name.localeCompare(right.name));
        const args = {
            breakpoints: current.map(entry => ({
                name: entry.name,
                ...(entry.condition ? { condition: entry.condition } : {}),
            })),
        };
        await this.#syncBreakpointTree(session, "setFunctionBreakpoints", args, target => {
            target.functionBreakpoints = current.map(entry => ({ ...entry, verified: false }));
        }, (target, response) => {
            target.functionBreakpoints = this.#mapFunctionBreakpoints(current, response);
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), breakpoints: session.functionBreakpoints };
    }
    async removeFunctionBreakpoint(name, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).functionBreakpoints.filter(entry => entry.name !== name);
        const args = {
            breakpoints: current.map(entry => ({
                name: entry.name,
                ...(entry.condition ? { condition: entry.condition } : {}),
            })),
        };
        await this.#syncBreakpointTree(session, "setFunctionBreakpoints", args, target => {
            target.functionBreakpoints = current.map(entry => ({ ...entry, verified: false }));
        }, (target, response) => {
            target.functionBreakpoints = this.#mapFunctionBreakpoints(current, response);
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), breakpoints: session.functionBreakpoints };
    }
    async setInstructionBreakpoint(instructionReference, offset, condition, hitCondition, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).instructionBreakpoints.filter(entry => entry.instructionReference !== instructionReference || entry.offset !== offset);
        current.push({ instructionReference, offset, condition, hitCondition });
        current.sort((left, right) => {
            const referenceOrder = left.instructionReference.localeCompare(right.instructionReference);
            return referenceOrder !== 0 ? referenceOrder : (left.offset ?? 0) - (right.offset ?? 0);
        });
        const args = { breakpoints: current };
        let responseBreakpoints;
        await this.#syncBreakpointTree(session, "setInstructionBreakpoints", args, target => {
            target.instructionBreakpoints = current.map(entry => ({ ...entry }));
        }, (target, response) => {
            if (target === session)
                responseBreakpoints = response;
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: this.#mapInstructionBreakpoints(current, responseBreakpoints),
        };
    }
    async removeInstructionBreakpoint(instructionReference, offset, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).instructionBreakpoints.filter(entry => {
            if (entry.instructionReference !== instructionReference)
                return true;
            return offset !== undefined && entry.offset !== offset;
        });
        const args = { breakpoints: current };
        let responseBreakpoints;
        await this.#syncBreakpointTree(session, "setInstructionBreakpoints", args, target => {
            target.instructionBreakpoints = current.map(entry => ({ ...entry }));
        }, (target, response) => {
            if (target === session)
                responseBreakpoints = response;
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: this.#mapInstructionBreakpoints(current, responseBreakpoints),
        };
    }
    async dataBreakpointInfo(name, variablesReference, frameId, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const info = await this.#sendRequestWithConfig(session, "dataBreakpointInfo", {
            name,
            ...(variablesReference !== undefined ? { variablesReference } : {}),
            ...(frameId !== undefined ? { frameId } : {}),
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), info };
    }
    async setDataBreakpoint(dataId, accessType, condition, hitCondition, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).dataBreakpoints.filter(entry => entry.dataId !== dataId);
        current.push({ dataId, accessType, condition, hitCondition });
        current.sort((left, right) => left.dataId.localeCompare(right.dataId));
        const args = { breakpoints: current };
        let responseBreakpoints;
        await this.#syncBreakpointTree(session, "setDataBreakpoints", args, target => {
            target.dataBreakpoints = current.map(entry => ({ ...entry }));
        }, (target, response) => {
            if (target === session)
                responseBreakpoints = response;
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: this.#mapDataBreakpoints(current, responseBreakpoints),
        };
    }
    async removeDataBreakpoint(dataId, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const current = this.#getRootSession(session).dataBreakpoints.filter(entry => entry.dataId !== dataId);
        const args = { breakpoints: current };
        let responseBreakpoints;
        await this.#syncBreakpointTree(session, "setDataBreakpoints", args, target => {
            target.dataBreakpoints = current.map(entry => ({ ...entry }));
        }, (target, response) => {
            if (target === session)
                responseBreakpoints = response;
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            breakpoints: this.#mapDataBreakpoints(current, responseBreakpoints),
        };
    }
    async disassemble(memoryReference, instructionCount, offset, instructionOffset, resolveSymbols, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "disassemble", {
            memoryReference,
            instructionCount,
            ...(offset !== undefined ? { offset } : {}),
            ...(instructionOffset !== undefined ? { instructionOffset } : {}),
            ...(resolveSymbols !== undefined ? { resolveSymbols } : {}),
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), instructions: response?.instructions ?? [] };
    }
    async readMemory(memoryReference, count, offset, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "readMemory", {
            memoryReference,
            count,
            ...(offset !== undefined ? { offset } : {}),
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            address: response?.address ?? memoryReference,
            data: response?.data,
            unreadableBytes: response?.unreadableBytes,
        };
    }
    async writeMemory(memoryReference, data, offset, allowPartial, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "writeMemory", {
            memoryReference,
            data,
            ...(offset !== undefined ? { offset } : {}),
            ...(allowPartial !== undefined ? { allowPartial } : {}),
        }, signal, timeoutMs);
        return {
            snapshot: buildSummary(session),
            offset: response?.offset,
            bytesWritten: response?.bytesWritten,
        };
    }
    async modules(startModule, moduleCount, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "modules", {
            ...(startModule !== undefined ? { startModule } : {}),
            ...(moduleCount !== undefined ? { moduleCount } : {}),
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), modules: response?.modules ?? [] };
    }
    async loadedSources(signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "loadedSources", {}, signal, timeoutMs);
        return { snapshot: buildSummary(session), sources: response?.sources ?? [] };
    }
    async customRequest(command, args, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const body = await this.#sendRequestWithConfig(session, command, args, signal, timeoutMs);
        return { snapshot: buildSummary(session), body };
    }
    async continue(signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const threadId = await this.#resolveThreadId(session, signal, timeoutMs);
        // Reset state and subscribe BEFORE sending continue to avoid missing
        // events that arrive in the same buffer as the response.
        session.stop = {};
        session.lastStackFrames = [];
        session.status = "running";
        const outcomePromise = this.#prepareStopOutcome(session, signal, timeoutMs);
        await this.#sendRequestWithConfig(session, "continue", { threadId }, signal, timeoutMs);
        return this.#awaitStopOutcome(session, outcomePromise, signal, timeoutMs);
    }
    async pause(signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        // status is mutated by the event reader between awaits; check through a
        // closure so TS does not carry stale narrowing from the early return.
        const isStopped = () => session.status === "stopped";
        if (isStopped()) {
            return buildSummary(session);
        }
        const threadId = await this.#resolveThreadId(session, signal, timeoutMs);
        // Subscribe BEFORE sending pause: the stopped event can arrive in the
        // same chunk as the response and would otherwise be dispatched before
        // the waiter subscribes, burning the whole timeout.
        const stoppedPromise = session.client.waitForEvent("stopped", undefined, signal, timeoutMs);
        stoppedPromise.catch(() => { });
        await this.#sendRequestWithConfig(session, "pause", { threadId }, signal, timeoutMs);
        if (!isStopped()) {
            try {
                await untilAborted(signal, stoppedPromise);
            }
            catch {
                // Timeout or abort — report current state regardless
            }
        }
        return buildSummary(session);
    }
    async stepIn(signal, timeoutMs = 30000) {
        return this.#step("stepIn", signal, timeoutMs);
    }
    async stepOut(signal, timeoutMs = 30000) {
        return this.#step("stepOut", signal, timeoutMs);
    }
    async stepOver(signal, timeoutMs = 30000) {
        return this.#step("next", signal, timeoutMs);
    }
    async threads(signal, timeoutMs = 30000) {
        const anchor = this.#touchActiveSession();
        // A js-debug launch is a session tree: the root may be a threadless
        // launcher while each real thread lives in a child (main script,
        // `[worker N]`, …), and other adapters keep every thread on the root.
        // Querying only the active session would surface just one session's
        // threads, so aggregate across the whole live tree. No topology guess:
        // a threadless launcher simply returns no threads (or an error we skip).
        const targets = this.#liveTreeSessions(anchor);
        const merged = [];
        const seen = new Set();
        for (const target of targets) {
            let threads;
            try {
                const response = await this.#sendRequestWithConfig(target, "threads", undefined, signal, timeoutMs);
                threads = response?.threads ?? [];
            }
            catch (error) {
                // Caller cancellation is not an adapter failure: propagate it instead
                // of degrading a cancelled call into a successful partial result.
                if (signal?.aborted)
                    throw error;
                logger.warn("Failed to list threads for debug session", {
                    sessionId: target.id,
                    error: toErrorMessage(error),
                });
                continue;
            }
            target.threads = threads;
            // DAP thread IDs are scoped per client session, so identical IDs from
            // different sessions (e.g. two identical worker scripts) are distinct
            // live threads and MUST be preserved; only collapse an exact repeat
            // within a single session's response.
            for (const thread of threads) {
                const key = `${target.id}\0${thread.id}`;
                if (seen.has(key))
                    continue;
                seen.add(key);
                merged.push(thread);
            }
        }
        return { snapshot: buildSummary(anchor), threads: merged };
    }
    async stackTrace(frameCount, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const threadId = await this.#resolveThreadId(session, signal, timeoutMs);
        const response = await this.#sendRequestWithConfig(session, "stackTrace", {
            threadId,
            ...(frameCount !== undefined ? { levels: frameCount } : {}),
        }, signal, timeoutMs);
        session.lastStackFrames = response?.stackFrames ?? [];
        this.#applyTopFrame(session, session.lastStackFrames[0]);
        return {
            snapshot: buildSummary(session),
            stackFrames: session.lastStackFrames,
            totalFrames: response?.totalFrames,
        };
    }
    async scopes(frameId, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const resolvedFrameId = frameId ?? session.stop.frameId;
        if (resolvedFrameId === undefined) {
            throw new Error("No active stack frame. Run stack_trace first or supply frame_id.");
        }
        const response = await this.#sendRequestWithConfig(session, "scopes", { frameId: resolvedFrameId }, signal, timeoutMs);
        return { snapshot: buildSummary(session), scopes: response?.scopes ?? [] };
    }
    async variables(variableReference, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const response = await this.#sendRequestWithConfig(session, "variables", { variablesReference: variableReference }, signal, timeoutMs);
        return { snapshot: buildSummary(session), variables: response?.variables ?? [] };
    }
    async evaluate(expression, context, frameId, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        // Default to the top stopped frame so callers don't need to pass
        // frame_id explicitly for the common case.
        const effectiveFrameId = frameId ?? session.stop.frameId;
        const response = await this.#sendRequestWithConfig(session, "evaluate", {
            expression,
            context,
            ...(effectiveFrameId !== undefined ? { frameId: effectiveFrameId } : {}),
        }, signal, timeoutMs);
        return { snapshot: buildSummary(session), evaluation: response };
    }
    getOutput(limitBytes) {
        const session = this.#touchActiveSession();
        const output = session.outputChunks.join("");
        if (!limitBytes || limitBytes <= 0 || session.outputBufferedBytes <= limitBytes) {
            return { snapshot: buildSummary(session), output };
        }
        // Byte-slice the tail once; a torn code point at the cut decodes as U+FFFD.
        const buffer = Buffer.from(output, "utf-8");
        if (buffer.length <= limitBytes) {
            return { snapshot: buildSummary(session), output };
        }
        return { snapshot: buildSummary(session), output: buffer.subarray(buffer.length - limitBytes).toString("utf-8") };
    }
    async terminate(signal, timeoutMs = 30000) {
        const session = this.#getActiveSessionOrNull();
        if (!session)
            return null;
        this.#touchSessionAndAncestors(session);
        const root = this.#getRootSession(session);
        const summary = buildSummary(session);
        await this.#terminateSessionTree(root, signal, timeoutMs);
        return summary;
    }
    async #terminateSessionTree(session, signal, timeoutMs = 30000) {
        session.status = "terminated";
        try {
            for (const childId of Array.from(session.childSessionIds)) {
                const child = this.#sessions.get(childId);
                if (child) {
                    await this.#terminateSessionTree(child, signal, timeoutMs);
                }
            }
            if (session.capabilities?.supportsTerminateRequest) {
                await session.client.sendRequest("terminate", undefined, signal, timeoutMs).catch(() => undefined);
            }
            await session.client
                .sendRequest("disconnect", { terminateDebuggee: true }, signal, timeoutMs)
                .catch(() => undefined);
        }
        catch {
            /* Disposal remains mandatory when a caller aborts best-effort DAP shutdown. */
        }
        finally {
            this.#disposeSession(session);
        }
    }
    #startCleanupTimer() {
        if (this.#cleanupLoopPromise)
            return;
        this.#cleanupLoopPromise = this.#runCleanupLoop();
    }
    async #runCleanupLoop() {
        for await (const _ of timers.setInterval(CLEANUP_INTERVAL_MS, null, { ref: false })) {
            try {
                this.#cleanupIdleSessions();
            }
            catch (error) {
                logger.error("DAP idle session cleanup failed", { error: toErrorMessage(error) });
            }
        }
    }
    #cleanupIdleSessions() {
        if (this.#sessions.size === 0)
            return;
        const now = Date.now();
        for (const session of this.#sessions.values()) {
            if (session.status === "terminated" ||
                now - session.lastUsedAt > IDLE_TIMEOUT_MS ||
                !session.client.isAlive()) {
                this.#disposeSession(session);
            }
        }
    }
    async #startChildSession(parent, request, configuration, timeoutMs = 30000) {
        if (parent.adapter.connectMode !== "tcp" || parent.port === undefined) {
            throw new Error(`DAP adapter ${parent.adapter.name} cannot accept child session connections`);
        }
        const cwd = path.resolve(parent.cwd, typeof configuration.cwd === "string" ? configuration.cwd : ".");
        const client = await DapClient.connect({
            adapter: parent.adapter,
            cwd,
            host: "127.0.0.1",
            port: parent.port,
        });
        const child = this.#registerSession(client, parent.adapter, cwd, typeof configuration.program === "string" ? configuration.program : undefined, parent.id);
        try {
            child.capabilities = await client.initialize(this.#buildInitializeArguments(parent.adapter), undefined, timeoutMs);
            child.needsConfigurationDone = child.capabilities.supportsConfigurationDoneRequest === true;
            const startFailure = { rejected: false };
            const startPromise = trackDapStartRequest(client.sendRequest(request, { ...configuration, cwd }, undefined, timeoutMs), startFailure);
            startPromise.catch(() => { });
            try {
                await this.#completeConfigurationHandshake(child, undefined, timeoutMs);
            }
            catch (error) {
                await throwPreferredDapStartError(request, startFailure, error);
            }
            await startPromise;
        }
        catch (error) {
            await this.#disposeSession(child);
            throw error;
        }
    }
    async #applyRootBreakpointsToSession(session, signal, timeoutMs = 30000) {
        const root = this.#getRootSession(session);
        for (const [sourcePath, entries] of root.breakpoints) {
            try {
                const response = await session.client.sendRequest("setBreakpoints", {
                    source: { path: sourcePath, name: path.basename(sourcePath) },
                    breakpoints: entries.map(entry => ({
                        line: entry.line,
                        ...(entry.condition ? { condition: entry.condition } : {}),
                    })),
                }, signal, timeoutMs);
                session.breakpoints.set(sourcePath, this.#mapSourceBreakpoints(entries, response?.breakpoints));
            }
            catch (error) {
                logger.warn("Failed to bind source breakpoints in child debug session", {
                    sessionId: session.id,
                    sourcePath,
                    error: toErrorMessage(error),
                });
            }
        }
        if (root.functionBreakpoints.length > 0) {
            try {
                const response = await session.client.sendRequest("setFunctionBreakpoints", {
                    breakpoints: root.functionBreakpoints.map(entry => ({
                        name: entry.name,
                        ...(entry.condition ? { condition: entry.condition } : {}),
                    })),
                }, signal, timeoutMs);
                session.functionBreakpoints = this.#mapFunctionBreakpoints(root.functionBreakpoints, response?.breakpoints);
            }
            catch (error) {
                logger.warn("Failed to bind function breakpoints in child debug session", {
                    sessionId: session.id,
                    error: toErrorMessage(error),
                });
            }
        }
        if (root.instructionBreakpoints.length > 0) {
            try {
                await session.client.sendRequest("setInstructionBreakpoints", { breakpoints: root.instructionBreakpoints }, signal, timeoutMs);
                session.instructionBreakpoints = root.instructionBreakpoints.map(entry => ({ ...entry }));
            }
            catch (error) {
                logger.warn("Failed to bind instruction breakpoints in child debug session", {
                    sessionId: session.id,
                    error: toErrorMessage(error),
                });
            }
        }
        if (root.dataBreakpoints.length > 0) {
            try {
                await session.client.sendRequest("setDataBreakpoints", { breakpoints: root.dataBreakpoints }, signal, timeoutMs);
                session.dataBreakpoints = root.dataBreakpoints.map(entry => ({ ...entry }));
            }
            catch (error) {
                logger.debug("Failed to bind data breakpoints in child debug session", {
                    sessionId: session.id,
                    error: toErrorMessage(error),
                });
            }
        }
    }
    async #ensureLaunchSlot() {
        for (const session of Array.from(this.#sessions.values())) {
            if (session.status === "terminated" || !session.client.isAlive()) {
                this.#disposeSession(session);
            }
        }
        const root = Array.from(this.#sessions.values()).find(session => !session.parentSessionId);
        if (!root)
            return;
        throw new Error(`Debug session ${root.id} is still active. Terminate it before launching another.`);
    }
    #registerSession(client, adapter, cwd, program, parentSessionId) {
        const session = {
            id: `debug-${++this.#nextId}`,
            adapter,
            cwd,
            program,
            client,
            status: "launching",
            launchedAt: Date.now(),
            lastUsedAt: Date.now(),
            breakpoints: new Map(),
            functionBreakpoints: [],
            instructionBreakpoints: [],
            dataBreakpoints: [],
            breakpointMutationQueue: Promise.resolve(),
            outputChunks: [],
            outputBytes: 0,
            outputBufferedBytes: 0,
            outputTruncated: false,
            stop: {},
            threads: [],
            lastStackFrames: [],
            initializedSeen: false,
            needsConfigurationDone: false,
            configurationDoneSent: false,
            parentSessionId,
            childSessionIds: new Set(),
            port: client.port,
        };
        client.onReverseRequest("runInTerminal", async (rawArgs) => {
            const args = (rawArgs ?? {});
            if (!Array.isArray(args.args) || args.args.length === 0) {
                throw new Error("runInTerminal request did not include a command");
            }
            const env = Object.fromEntries(Object.entries(args.env ?? {}).filter((entry) => entry[1] !== null));
            const proc = ptree.spawn(args.args, {
                cwd: path.resolve(session.cwd, args.cwd ?? "."),
                stdin: "pipe",
                env: {
                    ...Bun.env,
                    ...NON_INTERACTIVE_ENV,
                    ...env,
                },
                detached: true,
            });
            // Consume the child's stdout — ptree pipes it but drains only stderr,
            // so an unconsumed stream buffers unboundedly in this process.
            void drainTerminalStdout(proc.stdout, session);
            return { processId: proc.pid };
        });
        client.onReverseRequest("startDebugging", async (rawArgs) => {
            const startArgs = (rawArgs ?? {});
            const request = startArgs.request === "attach" ? "attach" : "launch";
            const configuration = startArgs.configuration && typeof startArgs.configuration === "object" ? startArgs.configuration : {};
            logger.debug("Adapter requested child debug session", {
                adapter: session.adapter.name,
                sessionId: session.id,
                request,
                name: typeof configuration.name === "string" ? configuration.name : undefined,
            });
            await this.#startChildSession(session, request, configuration);
            return {};
        });
        client.onEvent("output", body => {
            truncateOutput(session, body?.output ?? "");
        });
        client.onEvent("initialized", () => {
            session.initializedSeen = true;
            if (!session.configurationDoneSent && session.status === "launching") {
                session.status = "configuring";
            }
        });
        client.onEvent("stopped", body => {
            this.#handleStoppedEvent(session, body);
            this.#activeSessionId = session.id;
            this.#resolveTreeOutcome(session);
        });
        client.onEvent("continued", body => {
            const continued = body;
            session.status = "running";
            session.stop = { threadId: continued?.threadId };
            session.lastStackFrames = [];
        });
        client.onEvent("exited", body => {
            session.exitCode = body?.exitCode;
            session.status = "terminated";
            this.#reactivateAfterTermination(session);
            this.#resolveTreeOutcome(session);
        });
        client.onEvent("terminated", () => {
            session.status = "terminated";
            this.#reactivateAfterTermination(session);
            this.#resolveTreeOutcome(session);
        });
        this.#sessions.set(session.id, session);
        if (parentSessionId) {
            this.#sessions.get(parentSessionId)?.childSessionIds.add(session.id);
        }
        // Focus follows stops, not registrations: a lazily-attached child (e.g. a
        // js-debug `[worker N]` session) must not steal focus from a sibling that
        // is already stopped at a breakpoint / entry. Only claim focus when no
        // live, stopped session currently holds it.
        if (!this.#hasLiveStoppedActiveSession()) {
            this.#activeSessionId = session.id;
        }
        const heartbeat = setInterval(() => {
            if (!client.isAlive()) {
                session.status = "terminated";
            }
        }, HEARTBEAT_INTERVAL_MS);
        heartbeat.unref?.();
        void client.proc.exited.finally(() => {
            clearInterval(heartbeat);
            session.status = "terminated";
            this.#reactivateAfterTermination(session);
            this.#resolveTreeOutcome(session);
        });
        return session;
    }
    #buildInitializeArguments(adapter) {
        return {
            clientID: "omp",
            clientName: "omp",
            adapterID: adapter.name,
            locale: "en-US",
            linesStartAt1: true,
            columnsStartAt1: true,
            pathFormat: "path",
            supportsRunInTerminalRequest: true,
            supportsStartDebuggingRequest: true,
            supportsMemoryReferences: true,
            supportsVariableType: true,
            supportsInvalidatedEvent: true,
        };
    }
    /**
     * Wait for the adapter's `initialized` event (if not already received),
     * then send `configurationDone`. Many adapters block the `launch`/`attach`
     * response until this handshake completes.
     */
    async #completeConfigurationHandshake(session, signal, timeoutMs = 30000) {
        if (session.configurationDoneSent)
            return;
        if (!session.needsConfigurationDone) {
            if (session.parentSessionId) {
                await this.#applyRootBreakpointsToSession(session, signal, timeoutMs);
            }
            if (session.status === "launching" || session.status === "configuring") {
                session.status = "running";
            }
            return;
        }
        // Wait for the initialized event if we haven't seen it yet.
        if (!session.initializedSeen) {
            try {
                await untilAborted(signal, session.client.waitForEvent("initialized", undefined, signal, timeoutMs));
            }
            catch {
                // Adapter may not send initialized (e.g. it already terminated).
                // Proceed anyway — the launch/attach response will surface any real error.
                return;
            }
        }
        if (session.parentSessionId) {
            await this.#applyRootBreakpointsToSession(session, signal, timeoutMs);
        }
        await session.client.sendRequest("configurationDone", {}, signal, timeoutMs);
        session.configurationDoneSent = true;
        if (session.status === "configuring") {
            session.status = "running";
        }
    }
    #handleStoppedEvent(session, stopped) {
        session.status = "stopped";
        session.stop = {
            threadId: stopped.threadId,
            reason: stopped.reason,
            description: stopped.description,
            text: stopped.text,
        };
        session.lastStackFrames = [];
    }
    #applyTopFrame(session, frame) {
        if (!frame)
            return;
        session.stop.frameId = frame.id;
        session.stop.frameName = frame.name;
        session.stop.instructionPointerReference = frame.instructionPointerReference;
        session.stop.source = frame.source;
        session.stop.line = frame.line;
        session.stop.column = frame.column;
    }
    /**
     * Fetch the top stack frame from the adapter and apply it to the session's
     * stop location. Called outside the event dispatch loop to avoid deadlocking
     * the message reader.
     */
    async #fetchTopFrame(session, signal, timeoutMs = 5000) {
        if (session.stop.threadId === undefined)
            return;
        try {
            const response = await session.client.sendRequest("stackTrace", { threadId: session.stop.threadId, levels: 1 }, signal, timeoutMs);
            session.lastStackFrames = response?.stackFrames ?? [];
            this.#applyTopFrame(session, session.lastStackFrames[0]);
        }
        catch (error) {
            logger.debug("Failed to capture stopped frame", {
                sessionId: session.id,
                error: toErrorMessage(error),
            });
        }
    }
    async #step(command, signal, timeoutMs = 30000) {
        const session = this.#touchActiveSession();
        const threadId = await this.#resolveThreadId(session, signal, timeoutMs);
        // Reset state and subscribe BEFORE sending the step command to avoid
        // missing events that arrive in the same buffer as the response.
        session.stop = {};
        session.lastStackFrames = [];
        session.status = "running";
        const outcomePromise = this.#prepareStopOutcome(session, signal, timeoutMs);
        await this.#sendRequestWithConfig(session, command, { threadId }, signal, timeoutMs);
        return this.#awaitStopOutcome(session, outcomePromise, signal, timeoutMs);
    }
    /**
     * Create a promise that resolves when the session stops, terminates, or exits.
     * MUST be called before the command that triggers the event.
     */
    #prepareStopOutcome(session, signal, timeoutMs = 30000) {
        const { promise, resolve, reject } = Promise.withResolvers();
        const rootSessionId = this.#getRootSession(session).id;
        let abortHandler;
        const cleanup = () => {
            clearTimeout(timeout);
            if (signal && abortHandler)
                signal.removeEventListener("abort", abortHandler);
            this.#treeOutcomeWaiters.delete(waiter);
        };
        const waiter = {
            rootSessionId,
            resolve: value => {
                cleanup();
                resolve(value);
            },
            reject: reason => {
                cleanup();
                reject(reason);
            },
        };
        this.#treeOutcomeWaiters.add(waiter);
        const timeout = setTimeout(() => waiter.reject(new Error(`DAP session tree outcome timed out after ${timeoutMs}ms`)), timeoutMs);
        if (signal) {
            abortHandler = () => waiter.reject(signal.reason instanceof Error ? signal.reason : new Error("Debug operation aborted"));
            if (signal.aborted)
                abortHandler();
            else
                signal.addEventListener("abort", abortHandler, { once: true });
        }
        promise.catch(() => { });
        return promise;
    }
    /**
     * Await a pre-subscribed stop outcome, then fetch the top frame if stopped.
     */
    async #awaitStopOutcome(session, outcomePromise, signal, timeoutMs = 30000) {
        try {
            await untilAborted(signal, outcomePromise);
            const active = this.#getActiveSessionOrNull();
            const resultSession = active && this.#getRootSession(active).id === this.#getRootSession(session).id ? active : session;
            if (resultSession.status === "stopped") {
                await this.#fetchTopFrame(resultSession, signal, Math.min(timeoutMs, 5000));
            }
            const state = resultSession.status === "stopped"
                ? "stopped"
                : resultSession.status === "terminated"
                    ? "terminated"
                    : "running";
            return { snapshot: buildSummary(resultSession), state, timedOut: false };
        }
        catch (error) {
            if (signal?.aborted)
                throw error;
            const active = this.#getActiveSessionOrNull();
            const resultSession = active && this.#getRootSession(active).id === this.#getRootSession(session).id ? active : session;
            return {
                snapshot: buildSummary(resultSession),
                state: "running",
                timedOut: resultSession.status === "running",
            };
        }
    }
    async #resolveThreadId(session, signal, timeoutMs = 30000) {
        if (session.stop.threadId !== undefined) {
            return session.stop.threadId;
        }
        if (session.threads.length > 0) {
            return session.threads[0].id;
        }
        const response = await session.client.sendRequest("threads", undefined, signal, timeoutMs);
        session.threads = response?.threads ?? [];
        const threadId = session.threads[0]?.id;
        if (threadId === undefined) {
            throw new Error("Debugger reported no threads.");
        }
        return threadId;
    }
    async #sendRequestWithConfig(session, command, args, signal, timeoutMs = 30000) {
        await this.#ensureConfigurationDone(session, signal, timeoutMs);
        const body = await session.client.sendRequest(command, args, signal, timeoutMs);
        this.#touchSessionAndAncestors(session);
        return body;
    }
    async #ensureConfigurationDone(session, signal, timeoutMs = 30000) {
        if (!session.needsConfigurationDone || session.configurationDoneSent) {
            return;
        }
        await session.client.sendRequest("configurationDone", {}, signal, timeoutMs);
        session.configurationDoneSent = true;
        if (session.status === "configuring") {
            session.status = "running";
        }
    }
    #mapSourceBreakpoints(input, responseBreakpoints) {
        return input.map((entry, index) => ({
            line: entry.line,
            condition: entry.condition,
            id: responseBreakpoints?.[index]?.id,
            verified: responseBreakpoints?.[index]?.verified ?? false,
            message: responseBreakpoints?.[index]?.message,
        }));
    }
    #mapFunctionBreakpoints(input, responseBreakpoints) {
        return input.map((entry, index) => ({
            name: entry.name,
            condition: entry.condition,
            id: responseBreakpoints?.[index]?.id,
            verified: responseBreakpoints?.[index]?.verified ?? false,
            message: responseBreakpoints?.[index]?.message,
        }));
    }
    #mapInstructionBreakpoints(input, responseBreakpoints) {
        return input.map((entry, index) => ({
            instructionReference: responseBreakpoints?.[index]?.instructionReference ?? entry.instructionReference,
            offset: responseBreakpoints?.[index]?.offset ?? entry.offset,
            condition: entry.condition,
            hitCondition: entry.hitCondition,
            id: responseBreakpoints?.[index]?.id,
            verified: responseBreakpoints?.[index]?.verified ?? false,
            message: responseBreakpoints?.[index]?.message,
        }));
    }
    #mapDataBreakpoints(input, responseBreakpoints) {
        return input.map((entry, index) => ({
            dataId: entry.dataId,
            accessType: entry.accessType,
            condition: entry.condition,
            hitCondition: entry.hitCondition,
            id: responseBreakpoints?.[index]?.id,
            verified: responseBreakpoints?.[index]?.verified ?? false,
            message: responseBreakpoints?.[index]?.message,
        }));
    }
    #touchActiveSession() {
        const session = this.#getActiveSessionOrThrow();
        this.#touchSessionAndAncestors(session);
        if (session.status !== "terminated" && !session.client.isAlive()) {
            session.status = "terminated";
        }
        return session;
    }
    #getActiveSessionOrNull() {
        if (!this.#activeSessionId) {
            return null;
        }
        const session = this.#sessions.get(this.#activeSessionId) ?? null;
        if (!session) {
            this.#activeSessionId = null;
        }
        return session;
    }
    /** True when the current active session is live and paused at a stop. */
    #hasLiveStoppedActiveSession() {
        const active = this.#getActiveSessionOrNull();
        return active !== null && active.status === "stopped" && active.client.isAlive();
    }
    #getActiveSessionOrThrow() {
        const session = this.#getActiveSessionOrNull();
        if (!session) {
            throw new Error("No active debug session. Launch or attach first.");
        }
        return session;
    }
    #getRootSession(session) {
        let root = session;
        while (root.parentSessionId) {
            const parent = this.#sessions.get(root.parentSessionId);
            if (!parent)
                break;
            root = parent;
        }
        return root;
    }
    #getTreeSessions(session) {
        const sessions = [];
        const pending = [this.#getRootSession(session)];
        while (pending.length > 0) {
            const current = pending.pop();
            if (!current)
                continue;
            sessions.push(current);
            for (const childId of current.childSessionIds) {
                const child = this.#sessions.get(childId);
                if (child)
                    pending.push(child);
            }
        }
        return sessions;
    }
    /**
     * Live (non-terminated, connected) sessions in `session`'s tree, or the
     * session itself when the tree has collapsed. Used to fan `threads` out
     * across the whole tree; a threadless session just reports no threads, so
     * this makes no assumption about which node owns them.
     */
    #liveTreeSessions(session) {
        const live = this.#getTreeSessions(session).filter(candidate => candidate.status !== "terminated" && candidate.client.isAlive());
        return live.length > 0 ? live : [session];
    }
    #touchSessionAndAncestors(session) {
        const now = Date.now();
        let current = session;
        while (current) {
            current.lastUsedAt = now;
            current = current.parentSessionId ? this.#sessions.get(current.parentSessionId) : undefined;
        }
    }
    /** Point the active session at a live tree member when the active one terminates. */
    #reactivateAfterTermination(session) {
        if (this.#activeSessionId !== session.id)
            return;
        const live = this.#getTreeSessions(session).filter(candidate => candidate.status !== "terminated" && candidate.client.isAlive());
        if (live.length === 0)
            return;
        const replacement = live.find(candidate => candidate.status === "stopped") ??
            live.find(candidate => candidate.parentSessionId !== undefined) ??
            live[0];
        this.#activeSessionId = replacement.id;
    }
    #resolveTreeOutcome(session) {
        const rootId = this.#getRootSession(session).id;
        for (const waiter of Array.from(this.#treeOutcomeWaiters)) {
            if (waiter.rootSessionId === rootId) {
                waiter.resolve(undefined);
            }
        }
    }
    #disposeSession(session) {
        if (!this.#sessions.has(session.id))
            return;
        for (const childId of Array.from(session.childSessionIds)) {
            const child = this.#sessions.get(childId);
            if (child)
                this.#disposeSession(child);
        }
        this.#sessions.delete(session.id);
        if (session.parentSessionId) {
            this.#sessions.get(session.parentSessionId)?.childSessionIds.delete(session.id);
        }
        if (this.#activeSessionId === session.id) {
            const parent = session.parentSessionId ? this.#sessions.get(session.parentSessionId) : undefined;
            this.#activeSessionId = parent?.id ?? this.#sessions.values().next().value?.id ?? null;
        }
        void session.client.dispose().catch(() => { });
    }
}
export const dapSessionManager = new DapSessionManager();
