/**
 * Shared test isolation for stats Bun tests.
 *
 * The default profile's stats.db is redirected to `$XDG_DATA_HOME/reverse/stats.db`
 * by {@link DirResolver} whenever `agentDirOverride === defaultAgent`. Tests
 * that only set `REVERSE_CONFIG_DIR` + `setAgentDir(<home>/<config>/agent)` resolve
 * to that default and silently share `stats.db` across files when an XDG
 * variable is set (e.g. CI's `XDG_DATA_HOME`), producing the cross-test row
 * pollution that fails `db-range`, `behavior-backfill`, `priority-premium-*`,
 * and `agent-type` runs.
 *
 * `installStatsTestIsolation` snapshots and clears `XDG_*_HOME` plus
 * `REVERSE_CONFIG_DIR` for the test, points the agent directory at a fresh
 * `TempDir`, closes the stats DB handle, and tears everything back down in the
 * matching `afterEach`.
 */
import { afterEach, beforeEach } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import { closeDb } from "@reverse/stats/db";
import { __resetDirsFromEnvForTests, setAgentDir, TempDir } from "@reverse/utils";

const ISOLATED_ENV_KEYS = [
	"XDG_DATA_HOME",
	"XDG_STATE_HOME",
	"XDG_CACHE_HOME",
	"REVERSE_CONFIG_DIR",
	"REVERSE_CODING_AGENT_DIR",
	"REVERSE_PROFILE",
] as const;

export interface StatsTestIsolation {
	/** Active per-test `TempDir`. Null between tests. */
	current(): TempDir | null;
}

export function installStatsTestIsolation(prefix: string): StatsTestIsolation {
	const originalEnv: Record<string, string | undefined> = {};
	let tempDir: TempDir | null = null;

	beforeEach(() => {
		closeDb();
		tempDir = TempDir.createSync(prefix);
		for (const key of ISOLATED_ENV_KEYS) {
			originalEnv[key] = process.env[key];
			delete process.env[key];
		}
		const configDir = path.relative(os.homedir(), tempDir.join("config"));
		process.env.REVERSE_CONFIG_DIR = configDir;
		setAgentDir(path.join(os.homedir(), configDir, "agent"));
	});

	afterEach(() => {
		closeDb();
		for (const [key, prior] of Object.entries(originalEnv)) {
			if (prior === undefined) delete process.env[key];
			else process.env[key] = prior;
		}
		__resetDirsFromEnvForTests();
		tempDir?.removeSync();
		tempDir = null;
	});

	return {
		current() {
			return tempDir;
		},
	};
}
