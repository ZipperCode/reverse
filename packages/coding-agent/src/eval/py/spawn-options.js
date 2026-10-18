/**
 * Subprocess spawn-option helpers for the Python kernel.
 *
 * Pure helpers (`shouldHideKernelWindow`, `consoleAttached`) live here so they
 * can be unit-tested without dragging in the kernel's runtime dependencies.
 * The effectful `hostHasInheritableConsole` combines a Win32 FFI probe with
 * TTY evidence and is the function `kernel.ts` actually calls.
 */
import { dlopen, FFIType } from "bun:ffi";
/**
 * Decide whether the long-lived Python kernel subprocess should be spawned
 * with `windowsHide: true`.
 *
 * On Windows, Bun maps `windowsHide: true` to the `CREATE_NO_WINDOW` flag,
 * which detaches the child from any inherited console. The Python kernel
 * runs user code that imports NumPy/pandas; those native extensions
 * (`numpy/_core/_multiarray_umath.pyd` + bundled OpenBLAS/SLEEF thread-pool
 * init) can deadlock inside `LoadLibraryExW` when no console is attached,
 * and a console-less child cannot receive SIGINT via
 * `GenerateConsoleCtrlEvent` (the recovery path the host relies on). See
 * issue #1960.
 *
 * So on Windows we hide only when the host itself has no console to share.
 * In any launch where a console is attached — even one with every stdio
 * stream redirected — the kernel inherits the parent's console, matching
 * `python.exe` invoked from `cmd.exe`, which keeps native imports and
 * SIGINT recovery working.
 *
 * Short-lived helper subprocesses elsewhere in the codebase (LSP probes,
 * git, plugin installs) keep `windowsHide: true` because they don't load
 * complex native modules and the brief console flash would be user-visible
 * noise.
 */
export function shouldHideKernelWindow(opts) {
    if (opts.platform !== "win32")
        return false;
    return !opts.hostHasInheritableConsole;
}
/**
 * Keep eval kernels outside the host's POSIX terminal session.
 *
 * User code can start an interactive shell which calls `tcsetpgrp(3)`. If the
 * kernel shares OMP's session, that shell can replace OMP as the controlling
 * terminal's foreground process group and the host is then stopped by SIGTTIN
 * on its next stdin read. Bun implements `detached: true` with `setsid(2)` on
 * POSIX, making the kernel a session leader with no controlling terminal.
 */
export function shouldDetachKernel(platform) {
    return platform !== "win32";
}
/**
 * Combine native Win32 and stdio TTY evidence of an inheritable console.
 *
 * `GetConsoleWindow()` detects classic consoles even when every stdio stream
 * is redirected. TTY detection covers ConPTY-backed terminals, where compiled
 * hosts can receive a null HWND despite being attached to Windows Terminal.
 * Either signal must preserve console inheritance: `CREATE_NO_WINDOW` can
 * deadlock NumPy native-extension loading in the Python child.
 */
export function consoleAttached(opts) {
    if (opts.nativeConsole === true)
        return true;
    return opts.stdinIsTTY || opts.stdoutIsTTY || opts.stderrIsTTY;
}
let cachedWindowsConsoleProbe;
function probeWindowsConsoleWindow() {
    if (cachedWindowsConsoleProbe)
        return cachedWindowsConsoleProbe.value;
    let value = null;
    try {
        const lib = dlopen("kernel32.dll", {
            GetConsoleWindow: { args: [], returns: FFIType.ptr },
        });
        try {
            const hwnd = lib.symbols.GetConsoleWindow();
            // FFIType.ptr returns `Pointer | null`; a 0 pointer should also be
            // treated as NULL defensively in case Bun ever returns 0n / 0.
            value = hwnd !== null && hwnd !== 0;
        }
        finally {
            lib.close();
        }
    }
    catch {
        value = null;
    }
    cachedWindowsConsoleProbe = { value };
    return value;
}
/** Reset the cached Win32 probe result. Test-only; not part of the public surface. */
export function __resetWindowsConsoleProbeCache() {
    cachedWindowsConsoleProbe = undefined;
}
/**
 * Whether the host process owns a console its children can inherit.
 *
 * On Windows, `GetConsoleWindow()` detects classic consoles and all-stdio-
 * redirected launches while stdio TTYs detect ConPTY-backed terminals. Either
 * signal is sufficient. Other platforms use the same TTY evidence, although
 * `windowsHide` is a no-op there.
 */
export function hostHasInheritableConsole() {
    const nativeConsole = process.platform === "win32" ? probeWindowsConsoleWindow() : null;
    return consoleAttached({
        nativeConsole,
        stdinIsTTY: !!process.stdin.isTTY,
        stdoutIsTTY: !!process.stdout.isTTY,
        stderrIsTTY: !!process.stderr.isTTY,
    });
}
