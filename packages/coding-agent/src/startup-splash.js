/** Returns true only for explicitly enabled, normal interactive TTY startup. */
export function shouldShowStartupSplash(options) {
    if (!options.configured)
        return false;
    if (!options.isInteractive)
        return false;
    if (options.resuming || options.quiet)
        return false;
    if (options.timing)
        return false;
    return options.stdinIsTTY === true && options.stdoutIsTTY === true;
}
