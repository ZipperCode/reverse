/**
 * Shared command execution utilities for hooks and custom tools.
 */
import { ptree } from "@rva/utils";
/**
 * Execute a shell command and return stdout/stderr/code.
 * Supports timeout and abort signal.
 */
export async function execCommand(command, args, cwd, options) {
    const result = await ptree.exec([command, ...args], {
        cwd,
        signal: options?.signal,
        timeout: options?.timeout,
        allowNonZero: true,
        allowAbort: true,
        stderr: "full",
    });
    const killed = Boolean(result.exitError?.aborted);
    return {
        stdout: result.stdout,
        stderr: result.stderr,
        code: killed ? -1 : (result.exitCode ?? -1),
        killed,
    };
}
