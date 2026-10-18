import * as path from "node:path";
import { logger } from "@rva/utils";
import { attachSessionOwner, getRemainingTimeoutMs, isCancellationError, isTimedOutCancellation, waitForPromiseWithCancellation, } from "./executor-base";
export function normalizeKernelSessionCwd(cwd) {
    return path.resolve(cwd);
}
export function requireRemainingKernelTimeoutMs(deadlineMs, cancelledErrorClass) {
    const remainingMs = getRemainingTimeoutMs(deadlineMs);
    if (remainingMs === undefined)
        return undefined;
    if (remainingMs <= 0) {
        throw new cancelledErrorClass(true);
    }
    return remainingMs;
}
export function formatSessionTimeoutAnnotation(timeoutMs) {
    if (timeoutMs === undefined)
        return "Command timed out";
    const secs = Math.max(1, Math.round(timeoutMs / 1000));
    return `Command timed out after ${secs} seconds`;
}
export function formatSessionKernelTimeoutAnnotation(timeoutMs, kernelKilled) {
    const secs = timeoutMs === undefined ? undefined : Math.max(1, Math.round(timeoutMs / 1000));
    if (kernelKilled) {
        return "eval cell timed out and the kernel was unresponsive to interrupt; the kernel has been killed and will be recreated on the next call.";
    }
    const duration = secs === undefined ? "the configured timeout" : `${secs}s`;
    return `eval cell timed out after ${duration}; kernel interrupted but remains running. Reset the kernel via { reset: true } if state appears corrupted.`;
}
export function createKernelSessionRegistry(descriptor) {
    const sessions = new Map();
    const startingSessions = new Map();
    const resettingSessions = new Map();
    const replacingSessionKernels = new Map();
    const context = {
        sessions,
        startKernel: descriptor.startKernel,
        replaceSessionKernel,
    };
    function waitForStartup(promise, options) {
        return descriptor.waitForStartup?.(promise, options) ?? promise;
    }
    function throwIfCallerCancelled(options) {
        if (!options.signal?.aborted)
            return;
        const timedOut = descriptor.isTimedOutCancellation?.(options.signal.reason, options.signal) ??
            isTimedOutCancellation(options.signal.reason, descriptor.cancelledErrorClass, options.signal);
        throw new descriptor.cancelledErrorClass(timedOut);
    }
    function isCurrent(session, kernel) {
        return (sessions.get(session.sessionKey) === session &&
            (kernel === undefined || descriptor.validateKernel?.(session, kernel) !== false));
    }
    async function acquireSession(sessionKey, sessionId, cwd, options) {
        const existing = sessions.get(sessionKey);
        if (existing) {
            attachSessionOwner(existing, sessionId, options.kernelOwnerId);
            return existing;
        }
        const starting = startingSessions.get(sessionKey);
        if (starting) {
            attachSessionOwner(starting, sessionId, options.kernelOwnerId);
            return await waitForStartup(starting.promise, options);
        }
        // oxlint-disable-next-line prefer-const -- captured by the startup closure before assignment
        let startingSession;
        const startup = (async () => {
            const kernel = await descriptor.startKernel(cwd, options);
            const session = descriptor.createSession({
                sessionKey,
                sessionId,
                cwd,
                kernel,
                ownerIds: new Set(startingSession.ownerIds),
                hasFallbackOwner: startingSession.hasFallbackOwner,
            });
            if (startingSessions.get(sessionKey) === startingSession) {
                sessions.set(sessionKey, session);
            }
            return session;
        })();
        startingSession = {
            ownerIds: new Set(),
            hasFallbackOwner: false,
            promise: startup,
        };
        attachSessionOwner(startingSession, sessionId, options.kernelOwnerId);
        startingSessions.set(sessionKey, startingSession);
        try {
            return await waitForStartup(startup, options);
        }
        finally {
            if (startingSessions.get(sessionKey) === startingSession)
                startingSessions.delete(sessionKey);
        }
    }
    async function replaceSessionKernel(session, cwd, options) {
        if (descriptor.replaceSessionKernel) {
            return await descriptor.replaceSessionKernel(session, cwd, options, context);
        }
        if (descriptor.logBeforeReplacement) {
            logger.warn(`${descriptor.languageLabel} subprocess died or is unresponsive; spawning fresh process`, {
                sessionKey: session.sessionKey,
            });
        }
        const old = session.kernel;
        const remaining = getRemainingTimeoutMs(options.deadlineMs);
        await old
            .shutdown(remaining !== undefined ? { timeoutMs: Math.max(0, remaining) } : undefined)
            .catch(() => undefined);
        if (sessions.get(session.sessionKey) !== session) {
            throw new descriptor.cancelledErrorClass(false);
        }
        requireRemainingKernelTimeoutMs(options.deadlineMs, descriptor.cancelledErrorClass);
        const next = await descriptor.startKernel(cwd, options);
        if (sessions.get(session.sessionKey) !== session) {
            await next.shutdown().catch(() => undefined);
            throw new descriptor.cancelledErrorClass(false);
        }
        session.kernel = next;
        return next;
    }
    async function acquireDefaultReplacementKernel(session, kernel, cwd, options) {
        const existing = replacingSessionKernels.get(session);
        if (existing?.kernel === kernel) {
            return await waitForPromiseWithCancellation(existing.promise, options, descriptor.cancelledErrorClass);
        }
        if (!isCurrent(session))
            throw new descriptor.cancelledErrorClass(false);
        if (session.kernel !== kernel) {
            const currentKernel = session.kernel;
            if (currentKernel.isAlive())
                return currentKernel;
            return await acquireDefaultReplacementKernel(session, currentKernel, cwd, options);
        }
        const replacement = {
            kernel,
            promise: replaceSessionKernel(session, cwd, {
                ...options,
                signal: undefined,
                deadlineMs: undefined,
            }),
        };
        replacingSessionKernels.set(session, replacement);
        const release = () => {
            if (replacingSessionKernels.get(session) === replacement) {
                replacingSessionKernels.delete(session);
            }
        };
        void replacement.promise.then(release, release);
        return await waitForPromiseWithCancellation(replacement.promise, options, descriptor.cancelledErrorClass);
    }
    async function acquireLiveSessionKernel(session, cwd, options) {
        if (descriptor.acquireLiveSessionKernel) {
            return await descriptor.acquireLiveSessionKernel(session, cwd, options, context);
        }
        if (!isCurrent(session))
            throw new descriptor.cancelledErrorClass(false);
        const kernel = session.kernel;
        if (!kernel.isAlive())
            await acquireDefaultReplacementKernel(session, kernel, cwd, options);
        if (!isCurrent(session))
            throw new descriptor.cancelledErrorClass(false);
        return session.kernel;
    }
    async function shutdownSession(session, resetting) {
        const replacement = replacingSessionKernels.get(session)?.promise;
        let shutdown;
        try {
            shutdown = descriptor.shutdownSession?.(session, resetting) ?? session.kernel.shutdown();
        }
        catch (error) {
            if (replacement)
                await replacement.catch(() => undefined);
            throw error;
        }
        if (!replacement)
            return await shutdown;
        const [result] = await Promise.allSettled([shutdown, replacement]);
        if (result.status === "rejected")
            throw result.reason;
        return result.value;
    }
    async function settleShutdown(session, resetting) {
        return await shutdownSession(session, resetting).then(value => ({ status: "fulfilled", value }), reason => ({ status: "rejected", reason }));
    }
    async function resetSession(sessionKey) {
        const existing = sessions.get(sessionKey) ?? (await startingSessions.get(sessionKey)?.promise.catch(() => undefined));
        if (!existing)
            return;
        descriptor.invalidateSession?.(existing);
        sessions.delete(sessionKey);
        await shutdownSession(existing, true).catch(() => undefined);
    }
    async function disposeAll() {
        const pending = [...startingSessions.values()].map(starting => starting.promise);
        startingSessions.clear();
        if (descriptor.clearResetsOnDisposeAll)
            resettingSessions.clear();
        const all = [...sessions.entries()];
        for (const [id, session] of all) {
            descriptor.invalidateSession?.(session);
            if (sessions.get(id) === session)
                sessions.delete(id);
        }
        const shutdowns = all.map(([, session]) => settleShutdown(session, false));
        const started = await Promise.allSettled(pending);
        for (const result of started) {
            if (result.status !== "fulfilled")
                continue;
            if (all.some(([, session]) => session === result.value))
                continue;
            const session = result.value;
            all.push([session.sessionKey, session]);
            descriptor.invalidateSession?.(session);
            if (sessions.get(session.sessionKey) === session)
                sessions.delete(session.sessionKey);
            shutdowns.push(settleShutdown(session, false));
        }
        const results = await Promise.all(shutdowns);
        for (let i = 0; i < all.length; i += 1) {
            const [id, session] = all[i];
            const result = results[i];
            if (result.status === "fulfilled" && result.value?.confirmed !== false)
                continue;
            const reason = result.status === "rejected" ? result.reason : "not confirmed";
            logger.warn(`${descriptor.languageLabel} kernel shutdown not confirmed`, {
                sessionId: session.sessionId,
                sessionKey: id,
                cwd: session.cwd,
                reason,
            });
            if (!sessions.has(id))
                sessions.set(id, session);
        }
    }
    async function disposeByOwner(ownerId) {
        const toShutdown = [];
        const startingToShutdown = [];
        for (const session of Array.from(sessions.values())) {
            if (!session.ownerIds.has(ownerId))
                continue;
            if (session.ownerIds.size === 1) {
                toShutdown.push(session);
                continue;
            }
            session.ownerIds.delete(ownerId);
        }
        for (const [sessionKey, starting] of Array.from(startingSessions.entries())) {
            if (sessions.has(sessionKey) || !starting.ownerIds.has(ownerId))
                continue;
            if (starting.ownerIds.size === 1) {
                startingSessions.delete(sessionKey);
                startingToShutdown.push(starting);
                continue;
            }
            starting.ownerIds.delete(ownerId);
        }
        for (const session of toShutdown) {
            descriptor.invalidateSession?.(session);
            if (sessions.get(session.sessionKey) === session)
                sessions.delete(session.sessionKey);
        }
        const shutdowns = toShutdown.map(session => settleShutdown(session, false));
        const started = await Promise.allSettled(startingToShutdown.map(starting => starting.promise));
        for (const result of started) {
            if (result.status !== "fulfilled")
                continue;
            const session = result.value;
            descriptor.invalidateSession?.(session);
            if (sessions.get(session.sessionKey) === session)
                sessions.delete(session.sessionKey);
            toShutdown.push(session);
            shutdowns.push(settleShutdown(session, false));
        }
        const results = await Promise.all(shutdowns);
        for (let i = 0; i < toShutdown.length; i += 1) {
            const session = toShutdown[i];
            const result = results[i];
            if (result.status === "fulfilled" && result.value?.confirmed !== false) {
                session.ownerIds.delete(ownerId);
                continue;
            }
            const reason = result.status === "rejected" ? result.reason : "not confirmed";
            logger.warn(`${descriptor.languageLabel} kernel shutdown not confirmed`, {
                sessionId: session.sessionId,
                sessionKey: session.sessionKey,
                cwd: session.cwd,
                reason,
            });
            if (!sessions.has(session.sessionKey))
                sessions.set(session.sessionKey, session);
        }
    }
    function peekLiveKernel(cwd, options) {
        const sessionId = options.sessionId ?? `session:${cwd}`;
        const sessionKey = descriptor.buildSessionKey(sessionId, cwd, options.interpreter);
        const kernel = sessions.get(sessionKey)?.kernel;
        return kernel?.isAlive() ? kernel : undefined;
    }
    function getPresentSession(cwd, options) {
        const sessionId = options.sessionId ?? `session:${cwd}`;
        return sessions.get(descriptor.buildSessionKey(sessionId, cwd, options.interpreter));
    }
    async function executeOnSession(code, cwd, options) {
        const sessionId = options.sessionId ?? `session:${cwd}`;
        const sessionKey = descriptor.buildSessionKey(sessionId, cwd, options.interpreter);
        if (options.bridge && !options.bridgeSessionId) {
            options.bridgeSessionId = sessionId;
        }
        if (options.reset) {
            const inFlight = resettingSessions.get(sessionKey);
            if (inFlight)
                await inFlight.catch(() => undefined);
            else {
                const resetPromise = resetSession(sessionKey);
                resettingSessions.set(sessionKey, resetPromise.then(() => undefined));
                try {
                    await resetPromise;
                }
                finally {
                    resettingSessions.delete(sessionKey);
                }
            }
        }
        else {
            const inFlight = resettingSessions.get(sessionKey);
            if (inFlight)
                await inFlight.catch(() => undefined);
        }
        const session = await acquireSession(sessionKey, sessionId, cwd, options);
        throwIfCallerCancelled(options);
        const kernel = await acquireLiveSessionKernel(session, cwd, options);
        if (!isCurrent(session, kernel))
            throw new descriptor.cancelledErrorClass(false);
        throwIfCallerCancelled(options);
        const runOptions = { ...options, cwd };
        let result;
        try {
            result = await descriptor.executeWithKernel(kernel, code, runOptions);
        }
        catch (err) {
            if (descriptor.isCancellation?.(err) ||
                isCancellationError(err, descriptor.cancelledErrorClass) ||
                options.signal?.aborted)
                throw err;
            if (kernel.isAlive())
                throw err;
            throw new Error(`${descriptor.languageLabel} kernel died during execution; completion is uncertain and the cell was not replayed. The next call will start a fresh kernel.`, { cause: err });
        }
        return result;
    }
    return { disposeAll, disposeByOwner, executeOnSession, peekLiveKernel, getPresentSession };
}
