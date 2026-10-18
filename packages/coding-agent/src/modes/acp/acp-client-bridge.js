export function createAcpClientBridge(connection, sessionId, clientCapabilities) {
    const capabilities = {
        readTextFile: clientCapabilities?.fs?.readTextFile === true,
        writeTextFile: clientCapabilities?.fs?.writeTextFile === true,
        terminal: clientCapabilities?.terminal === true,
        // Permission requests are always usable on the connection; gating is
        // the agent's policy choice rather than a client capability.
        requestPermission: true,
    };
    const bridge = { capabilities, deferAgentInitiatedTurns: true };
    if (capabilities.readTextFile) {
        bridge.readTextFile = async (params) => {
            const response = await connection.readTextFile({
                sessionId,
                path: params.path,
                ...(typeof params.line === "number" ? { line: params.line } : {}),
                ...(typeof params.limit === "number" ? { limit: params.limit } : {}),
            });
            return response.content;
        };
    }
    if (capabilities.writeTextFile) {
        bridge.writeTextFile = async (params) => {
            await connection.writeTextFile({
                sessionId,
                path: params.path,
                content: params.content,
            });
        };
    }
    if (capabilities.terminal) {
        bridge.createTerminal = (params) => createTerminalHandle(connection, sessionId, params);
    }
    bridge.requestPermission = (toolCall, options, signal) => requestPermission(connection, sessionId, toolCall, options, signal);
    return bridge;
}
async function createTerminalHandle(connection, sessionId, params) {
    const handle = await connection.createTerminal({
        sessionId,
        command: params.command,
        ...(params.args ? { args: params.args } : {}),
        ...(params.env ? { env: params.env } : {}),
        ...(params.cwd ? { cwd: params.cwd } : {}),
        ...(typeof params.outputByteLimit === "number" ? { outputByteLimit: params.outputByteLimit } : {}),
    });
    return wrapTerminalHandle(handle);
}
function wrapTerminalHandle(handle) {
    return {
        terminalId: handle.id,
        async currentOutput() {
            const out = await handle.currentOutput();
            return {
                output: out.output,
                truncated: out.truncated,
                exitStatus: out.exitStatus ?? null,
            };
        },
        async waitForExit() {
            const status = await handle.waitForExit();
            return { exitCode: status.exitCode ?? null, signal: status.signal ?? null };
        },
        async kill() {
            await handle.kill();
        },
        async release() {
            await handle.release();
        },
    };
}
async function requestPermission(connection, sessionId, toolCall, options, signal) {
    const update = {
        toolCallId: toolCall.toolCallId,
        title: toolCall.title,
        ...(toolCall.kind ? { kind: toolCall.kind } : {}),
        ...(toolCall.status ? { status: toolCall.status } : {}),
        ...(toolCall.rawInput !== undefined ? { rawInput: toolCall.rawInput } : {}),
        ...(toolCall.content ? { content: toolCall.content } : {}),
        ...(toolCall.locations ? { locations: toolCall.locations } : {}),
    };
    const acpOptions = options.map(option => ({
        optionId: option.optionId,
        name: option.name,
        kind: option.kind,
    }));
    const request = {
        sessionId,
        toolCall: update,
        options: acpOptions,
    };
    if (signal?.aborted) {
        return { outcome: "cancelled" };
    }
    const response = await connection.requestPermission(request);
    const outcome = response.outcome;
    if (outcome.outcome === "cancelled") {
        return { outcome: "cancelled" };
    }
    const matched = options.find(option => option.optionId === outcome.optionId);
    return {
        outcome: "selected",
        optionId: outcome.optionId,
        ...(matched ? { kind: matched.kind } : {}),
    };
}
