import { logger } from "@rva/utils";
import { disposeVmContextsByOwner } from "../eval/js/context-manager";
import { namespaceSessionId as namespacePythonSessionId } from "../eval/py";
import { disposeKernelSessionsByOwner, executePython as executePythonCommand, } from "../eval/py/executor";
import { defaultEvalSessionId } from "../eval/session-id";
import { outputMeta } from "../tools/output-meta";
import { cfgPythonInterpreter, cfgPythonKernelMode } from "../eval/settings";
/** Owns user-initiated Python execution and retained eval-kernel lifecycle. */
export class EvalRunner {
    #host;
    #kernelOwnerId;
    #abortControllers = new Set();
    #pendingMessages = [];
    #activeExecutions = new Set();
    #disposing = false;
    constructor(host, options) {
        this.#host = host;
        this.#kernelOwnerId = options.kernelOwnerId;
    }
    /** Executes Python in the session's shared kernel. */
    async executePython(code, onChunk, options) {
        const excludeFromContext = options?.excludeFromContext === true;
        const cwd = this.#host.sessionManager.getCwd();
        this.assertExecutionAllowed();
        const abortController = new AbortController();
        const execution = (async () => {
            const extensionRunner = this.#host.extensionRunner();
            if (extensionRunner?.hasHandlers("user_python")) {
                const hookResult = await extensionRunner.emitUserPython({
                    type: "user_python",
                    code,
                    excludeFromContext,
                    cwd,
                });
                this.assertExecutionAllowed();
                if (hookResult?.result) {
                    this.recordPythonResult(code, hookResult.result, options);
                    return hookResult.result;
                }
            }
            const result = await executePythonCommand(code, {
                cwd,
                sessionId: namespacePythonSessionId(this.getSessionId()),
                kernelOwnerId: this.#kernelOwnerId,
                kernelMode: cfgPythonKernelMode.get(this.#host.settings),
                interpreter: cfgPythonInterpreter.get(this.#host.settings)?.trim() || undefined,
                onChunk,
                signal: abortController.signal,
                toolSession: this.#host.evalToolSession,
            });
            this.recordPythonResult(code, result, options);
            return result;
        })();
        return await this.trackExecution(execution, abortController);
    }
    /** Rejects new eval work once session disposal begins. */
    assertExecutionAllowed() {
        if (this.#disposing)
            throw new Error("Python execution is unavailable while session disposal is in progress");
    }
    /** Tracks externally started Python work so disposal can await and abort it. */
    trackExecution(execution, abortController) {
        this.#abortControllers.add(abortController);
        this.#activeExecutions.add(execution);
        void execution.then(() => {
            this.#abortControllers.delete(abortController);
            this.#activeExecutions.delete(execution);
        }, () => {
            this.#abortControllers.delete(abortController);
            this.#activeExecutions.delete(execution);
        });
        return execution;
    }
    /** Records a Python execution result in session history. */
    recordPythonResult(code, result, options) {
        const meta = outputMeta().truncationFromSummary(result, { direction: "tail" }).get();
        const message = {
            role: "pythonExecution",
            code,
            output: result.output,
            exitCode: result.exitCode,
            cancelled: result.cancelled,
            truncated: result.truncated,
            meta,
            timestamp: Date.now(),
            excludeFromContext: options?.excludeFromContext,
        };
        if (this.#host.isStreaming()) {
            this.#pendingMessages.push(message);
        }
        else {
            this.#host.appendSessionMessage(message);
        }
    }
    /** Cancels every running Python execution. */
    abort() {
        for (const abortController of this.#abortControllers)
            abortController.abort();
    }
    /** Whether a Python execution is currently running. */
    get isRunning() {
        return this.#abortControllers.size > 0;
    }
    /** Whether Python results are waiting for a safe persistence boundary. */
    get hasPendingMessages() {
        return this.#pendingMessages.length > 0;
    }
    /** Returns the stable owner shared by eval and session-owned tools. */
    getKernelOwnerId() {
        return this.#kernelOwnerId;
    }
    /** Returns this session's eval executor id, shared by the eval tool and user Python shortcuts. */
    getSessionId() {
        return defaultEvalSessionId({
            cwd: this.#host.sessionManager.getCwd(),
            getSessionFile: () => this.#host.sessionManager.getSessionFile() ?? null,
        });
    }
    /** Flushes deferred Python results into agent state and persistence. */
    flushPending() {
        if (this.#pendingMessages.length === 0)
            return;
        for (const message of this.#pendingMessages)
            this.#host.appendSessionMessage(message);
        this.#pendingMessages = [];
    }
    /** Prevents new Python executions before asynchronous disposal starts. */
    beginDispose() {
        this.#disposing = true;
    }
    /** Waits for active work and disposes every retained eval kernel owned by the session. */
    async disposeKernels() {
        const settled = await this.#prepareExecutionsForDispose();
        if (!settled) {
            logger.warn("Detaching retained eval-kernel ownership during dispose while eval execution is still active");
        }
        const results = await Promise.allSettled([
            disposeKernelSessionsByOwner(this.#kernelOwnerId),
            disposeVmContextsByOwner(this.#kernelOwnerId),
        ]);
        const errors = [];
        for (const result of results)
            if (result.status === "rejected")
                errors.push(result.reason);
        if (errors.length > 0)
            throw new AggregateError(errors, "Failed to dispose one or more eval kernels");
    }
    async #waitForExecutionsToSettle(timeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (this.#activeExecutions.size > 0) {
            const remainingMs = deadline - Date.now();
            if (remainingMs <= 0)
                return false;
            const settled = await Promise.race([
                Promise.allSettled(Array.from(this.#activeExecutions)).then(() => true),
                Bun.sleep(remainingMs).then(() => false),
            ]);
            if (!settled && this.#activeExecutions.size > 0)
                return false;
        }
        return true;
    }
    async #prepareExecutionsForDispose() {
        if (!(await this.#waitForExecutionsToSettle(3000))) {
            logger.warn("Aborting active Python execution during dispose before retained kernel cleanup");
            this.abort();
            if (!(await this.#waitForExecutionsToSettle(1000))) {
                logger.warn("Python execution is still active after dispose aborted all active runs; retained kernel ownership will still be detached");
                return false;
            }
        }
        return true;
    }
}
