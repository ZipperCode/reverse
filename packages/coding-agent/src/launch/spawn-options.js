/** Keep launch processes headless without discarding an inheritable Windows console. */
export function resolveDaemonSpawnOptions(opts) {
    if (opts.platform !== "win32")
        return { detached: true };
    return {
        detached: false,
        windowsHide: !opts.hostHasInheritableConsole,
    };
}
