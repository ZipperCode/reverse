/**
 * Bun `--preload` shim for the rva compatibility dev launcher (`scripts/rva`).
 *
 * The launcher starts Bun from an empty, bunfig-free directory so a foreign
 * project's `bunfig.toml` `preload` cannot run inside the CLI.
 * Restores the user's real working directory in time for import-time snapshots.
 */
const launchCwd = process.env.REVERSE_LAUNCH_CWD || process.env.RVA_LAUNCH_CWD;
if (launchCwd) {
	delete process.env.REVERSE_LAUNCH_CWD;
	delete process.env.RVA_LAUNCH_CWD;
	try {
		process.chdir(launchCwd);
	} catch {}
}
