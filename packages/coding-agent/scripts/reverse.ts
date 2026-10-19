/**
 * Bun `--preload` shim for the reverse dev launcher (`scripts/reverse`).
 *
 * Restores the user's real working directory from REVERSE_LAUNCH_CWD.
 */
const launchCwd = process.env.REVERSE_LAUNCH_CWD;
if (launchCwd) {
	delete process.env.REVERSE_LAUNCH_CWD;
	try {
		process.chdir(launchCwd);
	} catch {}
}
