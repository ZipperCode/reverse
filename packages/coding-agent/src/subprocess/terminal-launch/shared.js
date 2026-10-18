import { ptree } from "@rva/utils";
import { TerminalLaunchError, } from "./types";
export const processCli = async (argv, cwd, env) => {
    const result = await ptree.exec([...argv], { cwd, env, allowNonZero: true });
    return { stdout: result.stdout, exitCode: result.exitCode };
};
export function launchError(request, operation, message, exitCode) {
    return new TerminalLaunchError(message, request.multiplexer, request.placement, operation, exitCode);
}
export async function runStep(request, operation, argv, cwd, runCli, env) {
    let result;
    try {
        result = await runCli(argv, cwd, env);
    }
    catch {
        throw launchError(request, operation, `${request.multiplexer} ${operation} could not start its CLI.`);
    }
    if (result.exitCode !== 0) {
        const exit = result.exitCode === null ? "did not exit successfully" : `failed (exit ${result.exitCode})`;
        throw launchError(request, operation, `${request.multiplexer} ${operation} ${exit}.`, result.exitCode);
    }
    return result.stdout;
}
export function oneLineId(request, operation, stdout) {
    const trimmed = stdout.trim();
    if (!trimmed || /[\r\n]/.test(trimmed)) {
        throw launchError(request, operation, `${request.multiplexer} ${operation} did not return a valid ID.`);
    }
    return trimmed;
}
export function parseJson(request, operation, stdout) {
    try {
        const value = JSON.parse(stdout);
        if (typeof value !== "object" || value === null || Array.isArray(value))
            throw new Error();
        return value;
    }
    catch {
        throw launchError(request, operation, `${request.multiplexer} ${operation} returned invalid JSON.`);
    }
}
export function nestedString(value, ...keys) {
    let current = value;
    for (const key of keys) {
        if (typeof current !== "object" || current === null || Array.isArray(current))
            return undefined;
        current = current[key];
    }
    return typeof current === "string" && current.trim() ? current : undefined;
}
