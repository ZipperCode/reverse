import { DEFAULT_MAX_BYTES, OutputSink } from "@rva/tui/tools/streaming-output";
import { resolveOutputMaxColumns, resolveOutputSinkArtifactMaxBytes, resolveOutputSinkHeadBytes, } from "../../tools/output-meta";
import { isEvalTimeoutControlEvent, withBridgeTimeoutPause } from "../bridge-timeout";
import { DisplayOutputCollector } from "../executor-base";
import { executeInVmContext } from "./context-manager";
import { installJsPackages } from "./package-installer";
import { cfgEvalAutoProvision } from "../settings";
function getExecutionTimeoutMs(options) {
    if (options.deadlineMs !== undefined) {
        return Math.max(1, options.deadlineMs - Date.now());
    }
    return options.timeoutMs;
}
function isAbortError(error) {
    return ((error instanceof DOMException && (error.name === "AbortError" || error.name === "TimeoutError")) ||
        (error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError")));
}
function isTimeoutReason(reason) {
    return ((reason instanceof DOMException && reason.name === "TimeoutError") ||
        (reason instanceof Error && reason.name === "TimeoutError"));
}
const JS_PACKAGE_INSTALL_TIMEOUT_MS = 10 * 60000;
function formatJsTimeoutAnnotation(timeoutMs) {
    // Timeout cancellation force-kills the worker (the only way to interrupt
    // synchronous user code), which discards the persistent VM state. Say so,
    // or the model will keep referencing variables that no longer exist.
    const reset = "The JS worker was force-killed and its VM state was reset; variables from earlier cells are gone.";
    if (timeoutMs === undefined)
        return `Command timed out. ${reset}`;
    const secs = Math.max(1, Math.round(timeoutMs / 1000));
    return `Command timed out after ${secs} seconds. ${reset}`;
}
function formatPackageInstallTimeoutAnnotation(installDeadlineReached) {
    const timing = installDeadlineReached
        ? `timed out after ${Math.round(JS_PACKAGE_INSTALL_TIMEOUT_MS / 1000)} seconds`
        : "was cancelled by the caller's timeout";
    return (`JavaScript package installation ${timing}. ` +
        "Any existing retained JS worker was not restarted; earlier variables, if any, remain available.");
}
export async function executeJs(code, options) {
    const display = new DisplayOutputCollector();
    const displayOutputs = display.outputs;
    const outputSink = new OutputSink({
        artifactPath: options.artifactPath,
        artifactId: options.artifactId,
        spillThreshold: DEFAULT_MAX_BYTES,
        headBytes: resolveOutputSinkHeadBytes(options.session.settings),
        artifactMaxBytes: resolveOutputSinkArtifactMaxBytes(options.session.settings),
        maxColumns: resolveOutputMaxColumns(options.session.settings),
        onChunk: chunk => options.onChunk?.(chunk),
    });
    const legacyTimeoutMs = getExecutionTimeoutMs(options);
    let runtimeTimeoutMs = legacyTimeoutMs;
    let timeoutSignal;
    let signal;
    const packages = options.packages ?? [];
    const packageTimeoutSignal = packages.length > 0 ? AbortSignal.timeout(JS_PACKAGE_INSTALL_TIMEOUT_MS) : undefined;
    const packageSignal = packageTimeoutSignal
        ? options.signal
            ? AbortSignal.any([options.signal, packageTimeoutSignal])
            : packageTimeoutSignal
        : options.signal;
    let packageWorkComplete = false;
    let runtimeEntered = false;
    try {
        const cwd = options.cwd ?? options.session.cwd;
        const installOptions = {
            cwd,
            packages,
            environment: options.environment,
            autoProvision: cfgEvalAutoProvision.get(options.session.settings),
            signal: packageSignal,
        };
        const install = packages.length > 0
            ? await withBridgeTimeoutPause(options.onStatus, () => installJsPackages(installOptions))
            : await installJsPackages(installOptions);
        packageSignal?.throwIfAborted();
        if (install.summary)
            outputSink.push(`${install.summary}\n`);
        packageWorkComplete = true;
        // Start the legacy compute timer only after host-side package work. The
        // eval tool's normal idle watchdog is already paused by the status
        // wrapper above; direct timeoutMs callers need the same semantics.
        runtimeTimeoutMs = options.deadlineMs === undefined ? legacyTimeoutMs : getExecutionTimeoutMs(options);
        timeoutSignal =
            typeof runtimeTimeoutMs === "number" && Number.isFinite(runtimeTimeoutMs) && runtimeTimeoutMs > 0
                ? AbortSignal.timeout(runtimeTimeoutMs)
                : undefined;
        signal =
            options.signal && timeoutSignal
                ? AbortSignal.any([options.signal, timeoutSignal])
                : (options.signal ?? timeoutSignal);
        signal?.throwIfAborted();
        runtimeEntered = true;
        await executeInVmContext({
            sessionKey: options.sessionId,
            sessionId: options.sessionId,
            ownerId: options.kernelOwnerId,
            cwd,
            session: options.session,
            localRoots: options.localRoots,
            packageRoot: install.environment.packageRoot,
            packageEnvironment: install.environment.description,
            reset: options.reset,
            code,
            filename: options.filename ?? `js-cell-${crypto.randomUUID()}.js`,
            timeoutMs: runtimeTimeoutMs ?? options.idleTimeoutMs,
            runState: {
                signal,
                onText: chunk => outputSink.push(chunk),
                onDisplay: output => {
                    if (output.type === "status") {
                        // Timeout-control events drive the eval watchdog only; never
                        // store or render them as cell output.
                        options.onStatus?.(output.event);
                        if (isEvalTimeoutControlEvent(output.event))
                            return;
                    }
                    display.push(output);
                },
            },
        });
        const summary = await outputSink.dump();
        return {
            output: summary.output,
            exitCode: 0,
            cancelled: false,
            truncated: summary.truncated,
            artifactId: summary.artifactId,
            artifactElidedBytes: summary.artifactElidedBytes,
            artifactError: summary.artifactError,
            totalLines: summary.totalLines,
            totalBytes: summary.totalBytes,
            outputLines: summary.outputLines,
            outputBytes: summary.outputBytes,
            displayOutputs,
        };
    }
    catch (error) {
        const activeSignal = packageWorkComplete ? signal : packageSignal;
        if (activeSignal?.aborted || isAbortError(error)) {
            const timedOut = packageWorkComplete
                ? Boolean(timeoutSignal?.aborted) || isTimeoutReason(options.signal?.reason)
                : isTimeoutReason(packageSignal?.reason);
            if (timedOut) {
                const annotation = runtimeEntered
                    ? formatJsTimeoutAnnotation(runtimeTimeoutMs ?? options.idleTimeoutMs)
                    : packageWorkComplete
                        ? "Command timed out before JavaScript execution began. Any existing retained JS worker remains available."
                        : formatPackageInstallTimeoutAnnotation(packageTimeoutSignal?.aborted === true);
                outputSink.push(annotation);
            }
            const summary = await outputSink.dump();
            return {
                output: summary.output,
                exitCode: undefined,
                cancelled: true,
                truncated: summary.truncated,
                artifactId: summary.artifactId,
                artifactElidedBytes: summary.artifactElidedBytes,
                artifactError: summary.artifactError,
                totalLines: summary.totalLines,
                totalBytes: summary.totalBytes,
                outputLines: summary.outputLines,
                outputBytes: summary.outputBytes,
                displayOutputs,
            };
        }
        const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
        outputSink.push(message);
        const summary = await outputSink.dump();
        return {
            output: summary.output,
            exitCode: 1,
            cancelled: false,
            truncated: summary.truncated,
            artifactId: summary.artifactId,
            artifactElidedBytes: summary.artifactElidedBytes,
            artifactError: summary.artifactError,
            totalLines: summary.totalLines,
            totalBytes: summary.totalBytes,
            outputLines: summary.outputLines,
            outputBytes: summary.outputBytes,
            displayOutputs,
        };
    }
    finally {
        await outputSink.dispose();
    }
}
