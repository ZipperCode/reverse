export const ACP_TERMINAL_AUTH_FLAG = "--acp-terminal-auth";
export function prepareAcpTerminalAuthArgs(rawArgs) {
    const withoutAuthFlag = [];
    let terminalAuth = false;
    for (const arg of rawArgs) {
        if (arg === ACP_TERMINAL_AUTH_FLAG) {
            terminalAuth = true;
            continue;
        }
        withoutAuthFlag.push(arg);
    }
    if (!terminalAuth) {
        return { args: withoutAuthFlag, terminalAuth: false };
    }
    const args = [];
    for (let i = 0; i < withoutAuthFlag.length; i++) {
        const arg = withoutAuthFlag[i];
        if (arg === "--mode") {
            i++;
            continue;
        }
        if (arg.startsWith("--mode=")) {
            continue;
        }
        args.push(arg);
    }
    return { args, terminalAuth: true };
}
