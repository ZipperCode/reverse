import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { getActiveProfile, normalizeProfileName } from "@reverse/utils/dirs";

const repoRoot = path.resolve(import.meta.dir, "../../..");

async function fileTreeSnapshot(dir: string): Promise<Record<string, string>> {
	const result: Record<string, string> = {};
	async function walk(current: string): Promise<void> {
		let entries: string[];
		try {
			entries = await fs.readdir(current);
		} catch {
			return;
		}
		for (const entry of entries) {
			const full = path.join(current, entry);
			const stat = await fs.stat(full);
			if (stat.isDirectory()) {
				await walk(full);
			} else {
				const content = await fs.readFile(full);
				const hash = crypto.createHash("sha256").update(content).digest("hex");
				result[path.relative(dir, full)] = hash;
			}
		}
	}
	await walk(dir);
	return result;
}

describe("reverse environment & filesystem isolation", () => {
	let tempRoot: string;
	let isolatedHome: string;
	let isolatedProject: string;

	beforeEach(async () => {
		tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-isolation-test-"));
		isolatedHome = path.join(tempRoot, "home");
		isolatedProject = path.join(tempRoot, "project");
		await fs.mkdir(isolatedHome, { recursive: true });
		await fs.mkdir(isolatedProject, { recursive: true });
	});

	afterEach(async () => {
		await fs.rm(tempRoot, { recursive: true, force: true });
	});

	async function runProbe<T>(
		scriptBody: string,
		envOverrides: Record<string, string | undefined> = {},
		cwd: string = isolatedProject,
	): Promise<T> {
		const script = `
import * as path from "node:path";
import * as fs from "node:fs";
import {
	APP_NAME,
	CONFIG_DIR_NAME,
	getActiveProfile,
	getAgentDbPath,
	getAgentDir,
	getCommitCacheDbPath,
	getConfigRootDir,
	getDaemonRuntimeDir,
	getGlobalDaemonRuntimeDir,
	getLogsDir,
	getNativesDir,
	getProjectAgentDir,
	getSessionsDir,
	getSkillDescriptionsDbPath,
	normalizeProfileName,
	resolveProfileEnv,
	setAgentDir,
	getWorktreesDir,
	setProfile,
} from ${JSON.stringify(path.join(repoRoot, "packages/utils/src/dirs.ts"))};
import { getAddonFilenames, initLoaderContext } from ${JSON.stringify(path.join(repoRoot, "packages/natives/native/loader-state.js"))};
import { Settings } from ${JSON.stringify(path.join(repoRoot, "packages/coding-agent/src/config/settings.ts"))};
import { cfgModelRoles } from ${JSON.stringify(path.join(repoRoot, "packages/coding-agent/src/config/model-settings.ts"))};
import { SqliteAuthCredentialStore } from ${JSON.stringify(path.join(repoRoot, "packages/ai/src/auth/sqlite-credential-store.ts"))};
import { AuthStorage } from ${JSON.stringify(path.join(repoRoot, "packages/ai/src/auth-storage.ts"))};
import { SessionManager } from ${JSON.stringify(path.join(repoRoot, "packages/coding-agent/src/session/session-manager.ts"))};
import { listReverseExtensionRoots } from ${JSON.stringify(path.join(repoRoot, "packages/coding-agent/src/discovery/reverse-extension-roots.ts"))};

${scriptBody}
`;
		const childEnv: Record<string, string | undefined> = {
			PATH: process.env.PATH,
			TMPDIR: tempRoot,
			HOME: isolatedHome,
			USERPROFILE: isolatedHome,
			NO_COLOR: "1",
			REVERSE_NO_TITLE: "1",
			AWS_EC2_METADATA_DISABLED: "true",
			...envOverrides,
		};
		const proc = Bun.spawn([process.execPath, "-e", script], {
			cwd,
			env: childEnv,
			stdout: "pipe",
			stderr: "pipe",
		});
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		if (exitCode !== 0) {
			throw new Error(`Probe failed with exit code ${exitCode}:\n${stderr}`);
		}
		return JSON.parse(stdout) as T;
	}

	it("consumes .reverse configurations, credentials, and sessions via runtime APIs with project precedence, keeping unrelated .legacy-agent trees untouched", async () => {
		// Populate unrelated .legacy-agent trees with distinct sentinels
		const legacyUserDir = path.join(isolatedHome, ".legacy-agent", "agent");
		const legacyProjectDir = path.join(isolatedProject, ".legacy-agent");
		await fs.mkdir(path.join(legacyUserDir, "sessions"), { recursive: true });
		await fs.mkdir(legacyProjectDir, { recursive: true });

		await fs.writeFile(
			path.join(legacyUserDir, "config.yml"),
			"modelRoles:\n  default: legacy-other-user-model\n  fast: legacy-other-fast-model\n",
		);
		await fs.writeFile(
			path.join(legacyProjectDir, "config.yml"),
			"modelRoles:\n  default: legacy-other-project-model\n",
		);

		// Populate active .reverse trees with reverse configurations
		const reverseUserDir = path.join(isolatedHome, ".reverse", "agent");
		const reverseProjectDir = path.join(isolatedProject, ".reverse");
		await fs.mkdir(path.join(reverseUserDir, "sessions"), { recursive: true });
		await fs.mkdir(reverseProjectDir, { recursive: true });

		// Global configuration: sets default and fast roles
		await fs.writeFile(
			path.join(reverseUserDir, "config.yml"),
			"modelRoles:\n  default: anthropic/claude-3-5-sonnet-user\n  fast: anthropic/claude-3-5-haiku-user\n",
		);
		// Project configuration: overrides default role to demonstrate project precedence
		await fs.writeFile(
			path.join(reverseProjectDir, "config.yml"),
			"modelRoles:\n  default: google/gemini-2.5-pro-project\n",
		);

		// Snapshot unrelated .legacy-agent trees before execution
		const userLegacyBefore = await fileTreeSnapshot(path.join(isolatedHome, ".legacy-agent"));
		const projectLegacyBefore = await fileTreeSnapshot(legacyProjectDir);
		expect(Object.keys(userLegacyBefore).length).toBeGreaterThan(0);
		expect(Object.keys(projectLegacyBefore).length).toBeGreaterThan(0);

		// Run probe using real Settings, SqliteAuthCredentialStore, AuthStorage, and SessionManager
		const probeResult = await runProbe<{
			paths: Record<string, string>;
			effectiveDefaultModel: string;
			effectiveFastModel: string;
			projectLayerDefault: string;
			globalLayerDefault: string;
			storedCredentialKey: string | null;
			createdSessionId: string;
			listedSessionIds: string[];
			sessionFilePath: string;
		}>(
			`
const projectDir = ${JSON.stringify(isolatedProject)};

// 1. Real runtime Settings consumption & project precedence
const settings = await Settings.loadReadOnly({ cwd: projectDir });
const modelRoles = cfgModelRoles.get(settings);
const projectSettings = settings.getProjectSettings();
const globalSettings = settings.getGlobalSettings();

// 2. Real AuthStorage & SqliteAuthCredentialStore consumption
const dbPath = getAgentDbPath();
const authStore = await SqliteAuthCredentialStore.open(dbPath);
const authStorage = new AuthStorage(authStore);
await authStore.upsertAuthCredential("anthropic", {
	type: "api_key",
	key: "reverse-actual-credential-key-9999",
});
await authStorage.credentials.reload();
const storedKey = await authStorage.keys.peek("anthropic");
authStore.close();

// 3. Real SessionManager creation and listing
const sessionManager = SessionManager.create(projectDir);
sessionManager.appendMessage({ role: "user", content: [{ type: "text", text: "Real reverse test session message" }] });
await sessionManager.ensureOnDisk();
const createdSessionId = sessionManager.getSessionId();
const sessionFilePath = sessionManager.getSessionFile() ?? "";
await sessionManager.close();

const sessionsList = await SessionManager.list(projectDir);
const listedSessionIds = sessionsList.map(s => s.id);

process.stdout.write(JSON.stringify({
	paths: {
		appName: APP_NAME,
		configDirName: CONFIG_DIR_NAME,
		configRoot: getConfigRootDir(),
		agentDir: getAgentDir(),
		projectAgentDir: getProjectAgentDir(projectDir),
		authDb: dbPath,
		sessionsDir: getSessionsDir(),
		nativesDir: getNativesDir(),
		logsDir: getLogsDir(),
		worktreesDir: getWorktreesDir(),
		globalDaemon: getGlobalDaemonRuntimeDir("text-predict"),
	},
	effectiveDefaultModel: modelRoles.default,
	effectiveFastModel: modelRoles.fast,
	projectLayerDefault: projectSettings?.modelRoles?.default ?? null,
	globalLayerDefault: globalSettings?.modelRoles?.default ?? null,
	storedCredentialKey: storedKey ?? null,
	createdSessionId,
	listedSessionIds,
	sessionFilePath,
}));
`,
			{
				ALT_CONFIG_DIR: ".legacy-agent",
				OTHER_CONFIG_DIR: ".legacy-agent",
				ALT_CODING_AGENT_DIR: legacyUserDir,
				OTHER_CODING_AGENT_DIR: legacyUserDir,
				ALT_PROFILE: "legacy-profile",
				OTHER_PROFILE: "legacy-profile",
				OTHER_WORKTREE_DIR: path.join(isolatedHome, ".legacy-agent", "wt-legacy"),
				ALT_WORKTREE_DIR: path.join(isolatedHome, ".legacy-agent", "wt-legacy"),
			},
		);

		// Assert consumer-visible resolutions land in .reverse, not .legacy-agent
		expect(probeResult.paths.appName).toBe("reverse");
		expect(probeResult.paths.configDirName).toBe(".reverse");
		expect(probeResult.paths.configRoot).toBe(path.join(isolatedHome, ".reverse"));
		expect(probeResult.paths.agentDir).toBe(reverseUserDir);
		expect(probeResult.paths.projectAgentDir).toBe(reverseProjectDir);
		expect(probeResult.paths.authDb).toBe(path.join(reverseUserDir, "agent.db"));
		expect(probeResult.paths.sessionsDir).toBe(path.join(reverseUserDir, "sessions"));
		expect(probeResult.paths.nativesDir).toBe(path.join(isolatedHome, ".reverse", "natives"));
		expect(probeResult.paths.logsDir).toBe(path.join(isolatedHome, ".reverse", "logs"));
		expect(probeResult.paths.worktreesDir).toBe(path.join(isolatedHome, ".reverse", "wt"));
		expect(probeResult.paths.globalDaemon).toBe(
			path.join(isolatedHome, ".reverse", "run", "daemons", "global", "text-predict"),
		);

		// None of the paths contain .legacy-agent
		for (const key of Object.keys(probeResult.paths)) {
			expect(probeResult.paths[key]).not.toContain(".legacy-agent");
		}

		// 1. Settings precedence: project layer overrides global layer
		expect(probeResult.effectiveDefaultModel).toBe("google/gemini-2.5-pro-project");
		// Fallback to global layer for unconfigured keys in project layer
		expect(probeResult.effectiveFastModel).toBe("anthropic/claude-3-5-haiku-user");
		expect(probeResult.projectLayerDefault).toBe("google/gemini-2.5-pro-project");
		expect(probeResult.globalLayerDefault).toBe("anthropic/claude-3-5-sonnet-user");
		expect(probeResult.storedCredentialKey).toBe("reverse-actual-credential-key-9999");

		// 3. Real SessionManager creation, storage path, and listing
		expect(probeResult.sessionFilePath).toContain(path.join(isolatedHome, ".reverse", "agent", "sessions"));
		expect(probeResult.sessionFilePath).not.toContain(".legacy-agent");
		expect(probeResult.listedSessionIds).toContain(probeResult.createdSessionId);
		// Verify explicit REVERSE_WORKTREE_DIR override works and ignores unrelated OTHER_WORKTREE_DIR
		const customWt = path.join(tempRoot, "custom-worktrees");
		const wtResult = await runProbe<{ worktreesDir: string }>(
			`process.stdout.write(JSON.stringify({ worktreesDir: getWorktreesDir() }));`,
			{
				REVERSE_WORKTREE_DIR: customWt,
				OTHER_WORKTREE_DIR: path.join(isolatedHome, ".legacy-agent", "wt-ignored"),
			},
		);
		expect(wtResult.worktreesDir).toBe(customWt);
		expect(wtResult.worktreesDir).not.toContain(".legacy-agent");

		// Negative check: when REVERSE_WORKTREE_DIR is omitted, unrelated OTHER_WORKTREE_DIR is never used
		const defaultWtResult = await runProbe<{ worktreesDir: string }>(
			`process.stdout.write(JSON.stringify({ worktreesDir: getWorktreesDir() }));`,
			{
				OTHER_WORKTREE_DIR: path.join(isolatedHome, ".legacy-agent", "wt-ignored"),
			},
		);
		expect(defaultWtResult.worktreesDir).not.toContain("wt-ignored");
		expect(defaultWtResult.worktreesDir).not.toContain(".legacy-agent");
		// Snapshot unrelated .legacy-agent trees after execution and assert 100% byte-for-byte unchanged
		const userLegacyAfter = await fileTreeSnapshot(path.join(isolatedHome, ".legacy-agent"));
		const projectLegacyAfter = await fileTreeSnapshot(legacyProjectDir);

		expect(userLegacyAfter).toEqual(userLegacyBefore);
		expect(projectLegacyAfter).toEqual(projectLegacyBefore);
	});

	it("discovers extension package roots exclusively from .reverse, never from .legacy-agent", async () => {
		// Set up mock extension packages on disk
		const reverseProjectExt = path.join(isolatedProject, "reverse-proj-ext");
		const otherProjectExt = path.join(isolatedProject, "other-proj-ext");

		for (const dir of [reverseProjectExt, otherProjectExt]) {
			await fs.mkdir(dir, { recursive: true });
			await fs.writeFile(
				path.join(dir, "package.json"),
				JSON.stringify({ name: path.basename(dir), version: "1.0.0" }),
			);
		}

		// Set up project configs in both .reverse and .legacy-agent
		const projectReverse = path.join(isolatedProject, ".reverse");
		const projectOther = path.join(isolatedProject, ".legacy-agent");

		await fs.mkdir(projectReverse, { recursive: true });
		await fs.mkdir(projectOther, { recursive: true });

		await fs.writeFile(path.join(projectReverse, "config.yml"), `extensions:\n  - ${reverseProjectExt}\n`);
		await fs.writeFile(path.join(projectOther, "config.yml"), `extensions:\n  - ${otherProjectExt}\n`);

		// Real discovery call: listReverseExtensionRoots
		const result = await runProbe<{
			discoveredRoots: Array<{ path: string; name: string; level: string }>;
		}>(
			`
const projectDir = ${JSON.stringify(isolatedProject)};
const roots = await listReverseExtensionRoots({ cwd: projectDir, home: ${JSON.stringify(isolatedHome)}, repoRoot: null });

process.stdout.write(JSON.stringify({
	discoveredRoots: roots.map(r => ({ path: r.path, name: r.name, level: r.level })),
}));
`,
		);

		const discoveredPaths = result.discoveredRoots.map(r => r.path);
		expect(discoveredPaths).toContain(reverseProjectExt);
		expect(discoveredPaths).not.toContain(otherProjectExt);
	});

	it("consumes profile-scoped configurations upon profile switch and recovers default", async () => {
		const workAgent = path.join(isolatedHome, ".reverse", "profiles", "work", "agent");
		const defaultAgent = path.join(isolatedHome, ".reverse", "agent");

		await fs.mkdir(workAgent, { recursive: true });
		await fs.mkdir(defaultAgent, { recursive: true });

		await fs.writeFile(path.join(workAgent, "config.yml"), "modelRoles:\n  default: anthropic/work-profile-model\n");
		await fs.writeFile(
			path.join(defaultAgent, "config.yml"),
			"modelRoles:\n  default: anthropic/default-profile-model\n",
		);

		const result = await runProbe<{
			defaultModelInitial: string;
			workModel: string;
			workRoot: string;
			workAgent: string;
			recoveredModel: string;
			recoveredRoot: string;
		}>(`
const projectDir = ${JSON.stringify(isolatedProject)};

const defaultSettings = await Settings.loadReadOnly({ cwd: projectDir });
const defaultModelInitial = cfgModelRoles.get(defaultSettings).default;

setProfile("work");
const workSettings = await Settings.loadReadOnly({ cwd: projectDir });
const workModel = cfgModelRoles.get(workSettings).default;
const workRoot = getConfigRootDir();
const workAgent = getAgentDir();

setProfile(undefined);
const recoveredSettings = await Settings.loadReadOnly({ cwd: projectDir });
const recoveredModel = cfgModelRoles.get(recoveredSettings).default;
const recoveredRoot = getConfigRootDir();

process.stdout.write(JSON.stringify({
	defaultModelInitial,
	workModel,
	workRoot,
	workAgent,
	recoveredModel,
	recoveredRoot,
}));
`);

		expect(result.defaultModelInitial).toBe("anthropic/default-profile-model");
		expect(result.workModel).toBe("anthropic/work-profile-model");
		expect(result.workRoot).toBe(path.join(isolatedHome, ".reverse", "profiles", "work"));
		expect(result.workAgent).toBe(workAgent);
		expect(result.workRoot).not.toContain(".legacy-agent");

		expect(result.recoveredModel).toBe("anthropic/default-profile-model");
		expect(result.recoveredRoot).toBe(path.join(isolatedHome, ".reverse"));

		// Behavior: invalid profile names are rejected and leave active profile unchanged
		expect(() => normalizeProfileName("../bad")).toThrow();
		expect(() => normalizeProfileName("WORK")).toThrow();
		expect(() => normalizeProfileName("CON")).toThrow();
		expect(normalizeProfileName("work")).toBe("work");
		expect(getActiveProfile()).toBeUndefined();
	});

	it("consumes explicit REVERSE_CODING_AGENT_DIR override configuration", async () => {
		const customAgent = path.join(tempRoot, "custom-reverse-agent");
		await fs.mkdir(customAgent, { recursive: true });
		await fs.writeFile(
			path.join(customAgent, "config.yml"),
			"modelRoles:\n  default: anthropic/custom-override-model\n",
		);

		const result = await runProbe<{
			initialAgent: string;
			initialDb: string;
			consumedModel: string;
			tempProfileAgent: string;
			restoredAgent: string;
			restoredModel: string;
		}>(
			`
const projectDir = ${JSON.stringify(isolatedProject)};

const initialAgent = getAgentDir();
const initialDb = getAgentDbPath();
const initialSettings = await Settings.loadReadOnly({ cwd: projectDir });
const consumedModel = cfgModelRoles.get(initialSettings).default;

setProfile("temp");
const tempProfileAgent = getAgentDir();

setProfile(undefined);
const restoredAgent = getAgentDir();
const restoredSettings = await Settings.loadReadOnly({ cwd: projectDir });
const restoredModel = cfgModelRoles.get(restoredSettings).default;

process.stdout.write(JSON.stringify({
	initialAgent,
	initialDb,
	consumedModel,
	tempProfileAgent,
	restoredAgent,
	restoredModel,
}));
`,
			{
				REVERSE_CODING_AGENT_DIR: customAgent,
				OTHER_CODING_AGENT_DIR: path.join(tempRoot, "other-legacy-agent"),
			},
		);

		expect(result.initialAgent).toBe(customAgent);
		expect(result.initialDb).toBe(path.join(customAgent, "agent.db"));
		expect(result.consumedModel).toBe("anthropic/custom-override-model");
		expect(result.tempProfileAgent).toBe(path.join(isolatedHome, ".reverse", "profiles", "temp", "agent"));
		expect(result.restoredAgent).toBe(customAgent);
		expect(result.restoredModel).toBe("anthropic/custom-override-model");
	});

	it("uses XDG subdirectories for reverse and ignores unrelated XDG directories", async () => {
		const xdgData = path.join(tempRoot, "xdg-data");
		const xdgState = path.join(tempRoot, "xdg-state");
		const xdgCache = path.join(tempRoot, "xdg-cache");

		// Create both reverse and unrelated other directories under XDG roots
		await fs.mkdir(path.join(xdgData, "reverse"), { recursive: true });
		await fs.mkdir(path.join(xdgData, "other"), { recursive: true });
		await fs.mkdir(path.join(xdgState, "reverse"), { recursive: true });
		await fs.mkdir(path.join(xdgState, "other"), { recursive: true });
		await fs.mkdir(path.join(xdgCache, "reverse"), { recursive: true });
		await fs.mkdir(path.join(xdgCache, "other"), { recursive: true });

		// Place sentinel in other directories
		await fs.writeFile(path.join(xdgData, "other", "sentinel.txt"), "other-xdg-sentinel");
		const otherXdgBefore = await fileTreeSnapshot(path.join(xdgData, "other"));
		const result = await runProbe<{
			skillDescriptionsDb: string;
			globalDaemon: string;
			commitCacheDb: string;
			nativesDir: string;
		}>(
			`
process.stdout.write(JSON.stringify({
	skillDescriptionsDb: getSkillDescriptionsDbPath(),
	globalDaemon: getGlobalDaemonRuntimeDir("text-predict"),
	commitCacheDb: getCommitCacheDbPath(),
	nativesDir: getNativesDir(),
}));
`,
			{
				XDG_DATA_HOME: xdgData,
				XDG_STATE_HOME: xdgState,
				XDG_CACHE_HOME: xdgCache,
			},
		);

		expect(result.skillDescriptionsDb).toBe(path.join(xdgData, "reverse", "skill-descriptions.db"));
		expect(result.globalDaemon).toBe(path.join(xdgState, "reverse", "run", "daemons", "global", "text-predict"));
		expect(result.commitCacheDb).toBe(path.join(xdgCache, "reverse", "cache", "commit-inference.db"));
		expect(result.nativesDir).toBe(path.join(xdgCache, "reverse", "natives"));

		// None should contain other
		expect(result.skillDescriptionsDb).not.toContain("/other/");
		expect(result.globalDaemon).not.toContain("/other/");
		expect(result.commitCacheDb).not.toContain("/other/");
		expect(result.nativesDir).not.toContain("/other/");

		// Verify unrelated other XDG files were not modified
		const otherXdgAfter = await fileTreeSnapshot(path.join(xdgData, "other"));
		expect(otherXdgAfter).toEqual(otherXdgBefore);
	});

	it("keeps native loader (loader-state.js) and dirs.ts resolution consistent without altering ABI names", async () => {
		const result = await runProbe<{
			defaultDirsNatives: string;
			defaultLoaderNatives: string;
			filenames: string[];
			x64Filenames: string[];
		}>(`
const defaultDirsNatives = getNativesDir();
const defaultLoaderNatives = initLoaderContext().nativesDir;
const filenames = getAddonFilenames({ tag: "darwin-arm64", arch: "arm64" });
const x64Filenames = getAddonFilenames({ tag: "darwin-x64", arch: "x64", variant: "modern" });

process.stdout.write(JSON.stringify({
	defaultDirsNatives,
	defaultLoaderNatives,
	filenames,
	x64Filenames,
}));
`);

		expect(result.defaultDirsNatives).toBe(result.defaultLoaderNatives);
		expect(result.defaultDirsNatives).toBe(path.join(isolatedHome, ".reverse", "natives"));

		// Native ABI names remain unchanged (pi_natives)
		expect(result.filenames).toEqual(["pi_natives.darwin-arm64.node"]);
		expect(result.x64Filenames).toContain("pi_natives.darwin-x64.node");

		// Override consistency
		const customNativesDir = path.join(tempRoot, "custom-natives");
		const overrideResult = await runProbe<{
			dirsNatives: string;
			loaderNatives: string;
		}>(
			`
process.stdout.write(JSON.stringify({
	dirsNatives: getNativesDir(),
	loaderNatives: initLoaderContext().nativesDir,
}));
`,
			{ REVERSE_NATIVES_DIR: customNativesDir },
		);

		expect(overrideResult.dirsNatives).toBe(customNativesDir);
		expect(overrideResult.loaderNatives).toBe(customNativesDir);
	});
});
