export function namespaceSessionId(sessionId, prefix) {
    return sessionId.startsWith(prefix) ? sessionId : `${prefix}${sessionId}`;
}
export function toExecutorBackendResult(result) {
    return {
        output: result.output,
        exitCode: result.exitCode,
        cancelled: result.cancelled,
        truncated: result.truncated,
        artifactId: result.artifactId,
        artifactElidedBytes: result.artifactElidedBytes,
        artifactError: result.artifactError,
        totalLines: result.totalLines,
        totalBytes: result.totalBytes,
        outputLines: result.outputLines,
        outputBytes: result.outputBytes,
        displayOutputs: result.displayOutputs,
    };
}
