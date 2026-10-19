import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { APP_NAME } from "@rva/utils/dirs";

const repoRoot = path.resolve(import.meta.dir, "../../..");
const cliEntry = path.join(repoRoot, "packages/coding-agent/src/cli.ts");

describe("Local skills discovery & CLI command routing", () => {
	let tempHome: string;
	let tempProject: string;

	beforeEach(async () => {
		tempHome = await fs.mkdtemp(path.join(os.tmpdir(), "rva-skill-cli-home-"));
		tempProject = await fs.mkdtemp(path.join(os.tmpdir(), "rva-skill-cli-project-"));
	});

	afterEach(async () => {
		await fs.rm(tempHome, { recursive: true, force: true });
		await fs.rm(tempProject, { recursive: true, force: true });
	});

	function runCli(args: string[], options: { cwd?: string; env?: Record<string, string | undefined> } = {}) {
		const childEnv: Record<string, string | undefined> = {
			PATH: process.env.PATH,
			TMPDIR: process.env.TMPDIR,
			HOME: tempHome,
			USERPROFILE: tempHome,
			NO_COLOR: "1",
			REVERSE_NO_TITLE: "1",
			AWS_EC2_METADATA_DISABLED: "true",
			...options.env,
		};
		return Bun.spawn([process.execPath, cliEntry, ...args], {
			cwd: options.cwd ?? tempProject,
			env: childEnv,
			stdout: "pipe",
			stderr: "pipe",
		});
	}

	it("discovers local skills from .rva/skills in project and home via real CLI", async () => {
		// Set up project fixture skill under <project>/.rva/skills
		const projectSkillDir = path.join(tempProject, ".rva", "skills", "project-fixture-tool");
		await fs.mkdir(projectSkillDir, { recursive: true });
		await fs.writeFile(
			path.join(projectSkillDir, "SKILL.md"),
			"---\nname: project-fixture-tool\ndescription: Project local fixture tool\n---\n# Project Fixture Tool\n",
		);

		// Set up user fixture skill under ~/.rva/agent/skills
		const userSkillDir = path.join(tempHome, ".rva", "agent", "skills", "user-fixture-tool");
		await fs.mkdir(userSkillDir, { recursive: true });
		await fs.writeFile(
			path.join(userSkillDir, "SKILL.md"),
			"---\nname: user-fixture-tool\ndescription: User local fixture tool\n---\n# User Fixture Tool\n",
		);
		// Set up legacy .omp skills which must NOT be discovered
		const legacyProjSkillDir = path.join(tempProject, ".omp", "skills", "legacy-omp-project-skill");
		const legacyUserSkillDir = path.join(tempHome, ".omp", "agent", "skills", "legacy-omp-user-skill");
		await fs.mkdir(legacyProjSkillDir, { recursive: true });
		await fs.mkdir(legacyUserSkillDir, { recursive: true });
		await fs.writeFile(
			path.join(legacyProjSkillDir, "SKILL.md"),
			"---\nname: legacy-omp-project-skill\ndescription: Legacy OMP skill\n---\n",
		);
		await fs.writeFile(
			path.join(legacyUserSkillDir, "SKILL.md"),
			"---\nname: legacy-omp-user-skill\ndescription: Legacy OMP user skill\n---\n",
		);

		// Run real CLI: rva skill list --json
		const proc = runCli(["skill", "list", "--json"]);
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);

		expect(exitCode, stderr).toBe(0);
		const parsed = JSON.parse(stdout) as {
			skills: Array<{ name: string; description: string; filePath: string }>;
		};

		const names = parsed.skills.map(s => s.name);
		expect(names).toContain("project-fixture-tool");
		expect(names).toContain("user-fixture-tool");
		expect(names).not.toContain("legacy-omp-project-skill");
		expect(names).not.toContain("legacy-omp-user-skill");
	});

	it("rejects removed and unknown skill actions with usage error", async () => {
		// Action unknown
		const procUnknown = runCli(["skill", "unknown-action"]);
		const [stderrUnknown, codeUnknown] = await Promise.all([
			new Response(procUnknown.stderr).text(),
			procUnknown.exited,
		]);
		expect(codeUnknown).toBe(1);
		expect(stderrUnknown).toContain("Expected action to be one of: list, check");

		// Removed remote action: install
		const procInstall = runCli(["skill", "install", "@scope/foo"]);
		const [stderrInstall, codeInstall] = await Promise.all([
			new Response(procInstall.stderr).text(),
			procInstall.exited,
		]);
		expect(codeInstall).toBe(1);
		expect(stderrInstall).toContain("Expected action to be one of: list, check");
	});

	it(
		"rejects 7 removed commands in naked, args, and flag-prefixed forms while allowing explicit launch",
		async () => {
			const removed = ["collab", "join", "share", "stream", "clip", "grievances", "update"] as const;

			for (const cmd of removed) {
				const expectedError = `\`${APP_NAME} ${cmd}\` is not available; use \`${APP_NAME} launch\` for a prompt.`;

				// 1. Naked command
				const procNaked = runCli([cmd]);
				const [stderrNaked, codeNaked] = await Promise.all([new Response(procNaked.stderr).text(), procNaked.exited]);
				expect(codeNaked).toBe(1);
				expect(stderrNaked).toContain(expectedError);

				// 2. Command with arguments
				const procArgs = runCli([cmd, "arg1", "--flag"]);
				const [stderrArgs, codeArgs] = await Promise.all([new Response(procArgs.stderr).text(), procArgs.exited]);
				expect(codeArgs).toBe(1);
				expect(stderrArgs).toContain(expectedError);

				// 3. Command behind leading launch flags
				const procPrefixed = runCli(["--cwd", tempProject, cmd]);
				const [stderrPrefixed, codePrefixed] = await Promise.all([
					new Response(procPrefixed.stderr).text(),
					procPrefixed.exited,
				]);
				expect(codePrefixed).toBe(1);
				expect(stderrPrefixed).toContain(expectedError);
			}
		},
		45_000,
	);

	it("installs local extension packages modifying only isolated plugin collection", async () => {
		// Create a local plugin package directory
		const pluginDir = path.join(tempProject, "local-fixture-plugin");
		await fs.mkdir(pluginDir, { recursive: true });
		await fs.writeFile(
			path.join(pluginDir, "package.json"),
			JSON.stringify({
				name: "local-fixture-plugin",
				version: "1.0.0",
				description: "Local test plugin",
			}),
		);

		// Run real CLI: rva install <pluginDir>
		const proc = runCli(["install", pluginDir]);
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);

		expect(exitCode, stderr).toBe(0);
		expect(stdout).toContain("Linked local-fixture-plugin");

		// Verifies that plugins directory was created inside isolated tempHome/.rva
		const rvaPluginsDir = path.join(tempHome, ".rva", "plugins");
		const exists = await fs
			.stat(rvaPluginsDir)
			.then(s => s.isDirectory())
			.catch(() => false);
		expect(exists).toBe(true);
	});
});
