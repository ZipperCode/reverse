import { resolveExecutablePath } from "../../subprocess/worker-client";
/**
 * Runs Bun's CLI (`bun <args>`) in `cwd` for plugin install/update/uninstall.
 *
 * Re-enters the running executable with `BUN_BE_BUN=1` instead of resolving
 * `bun` from `$PATH`: source and bundle installs already run under Bun, and the
 * standalone `omp` binary embeds Bun, so plugin installs never require a
 * separately installed Bun (#15480). Same mechanism as
 * `eval/js/package-installer.ts` and `@rva/utils` runtime installs.
 */
export async function runBunCli(args, cwd) {
    const proc = Bun.spawn([resolveExecutablePath(), ...args], {
        cwd,
        env: { ...Bun.env, BUN_BE_BUN: "1" },
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
        windowsHide: true,
    });
    // Drain both pipes concurrently with exit: awaiting `exited` first deadlocks
    // once a chatty install fills the OS pipe buffer.
    const [exitCode, stdout, stderr] = await Promise.all([
        proc.exited,
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
    ]);
    return { exitCode, stdout, stderr };
}
