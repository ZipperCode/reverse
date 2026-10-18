import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";

const repoRoot = path.resolve(import.meta.dir, "../../..");
const cliEntry = path.join(repoRoot, "packages/coding-agent/src/cli.ts");

interface CheckOutput {
	ok: boolean;
	skills: Array<{
		name: string;
		filePath: string;
		missingRequired: string[];
		requirements: Array<{
			id: string;
			optional: boolean;
			foundPath: string | null;
			hint?: string;
			unknown?: boolean;
		}>;
	}>;
}

describe("rva skill check", () => {
	let tempHome: string;
	let tempProject: string;

	beforeEach(async () => {
		tempHome = await fs.mkdtemp(path.join(os.tmpdir(), "rva-skill-check-home-"));
		tempProject = await fs.mkdtemp(path.join(os.tmpdir(), "rva-skill-check-project-"));
		const userConfigDir = path.join(tempHome, ".rva", "agent");
		await fs.mkdir(userConfigDir, { recursive: true });
		await Bun.write(
			path.join(userConfigDir, "config.yml"),
			"disabledProviders:\n  - builtin-skills\n",
		);
		const projectConfigDir = path.join(tempProject, ".rva");
		await fs.mkdir(projectConfigDir, { recursive: true });
		await Bun.write(
			path.join(projectConfigDir, "config.yml"),
			"disabledProviders:\n  - builtin-skills\n",
		);
	});

	afterEach(async () => {
		await fs.rm(tempHome, { recursive: true, force: true });
		await fs.rm(tempProject, { recursive: true, force: true });
	});

	function runCli(args: string[], options: { cwd?: string; pathPrefix?: string } = {}) {
		const searchPath = options.pathPrefix
			? `${options.pathPrefix}${path.delimiter}${process.env.PATH ?? ""}`
			: process.env.PATH;
		const childEnv: Record<string, string | undefined> = {
			PATH: searchPath,
			TMPDIR: process.env.TMPDIR,
			HOME: tempHome,
			USERPROFILE: tempHome,
			NO_COLOR: "1",
			RVA_NO_TITLE: "1",
			AWS_EC2_METADATA_DISABLED: "true",
		};
		return Bun.spawn([process.execPath, cliEntry, ...args], {
			cwd: options.cwd ?? tempProject,
			env: childEnv,
			stdout: "pipe",
			stderr: "pipe",
		});
	}

	async function writeSkill(name: string, metadata: string): Promise<void> {
		const dir = path.join(tempProject, ".rva", "skills", name);
		await fs.mkdir(dir, { recursive: true });
		await Bun.write(
			path.join(dir, "SKILL.md"),
			`---\nname: ${name}\ndescription: ${name} fixture\nmetadata:\n${metadata}\n---\n\n# ${name}\n`,
		);
	}

	async function createExecutable(dir: string, name: string): Promise<void> {
		await fs.mkdir(dir, { recursive: true });
		if (process.platform === "win32") {
			await Bun.write(path.join(dir, `${name}.cmd`), "@exit /b 0\r\n");
			return;
		}
		const filePath = path.join(dir, name);
		await Bun.write(filePath, "#!/bin/sh\nexit 0\n");
		await fs.chmod(filePath, 0o755);
	}

	it("exits non-zero and reports missing required tools with no invented hint", async () => {
		await writeSkill("missing-deps", "  requires: rva-cli-absent-fixture");
		const proc = runCli(["skill", "check", "--json"]);
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		expect(exitCode, stderr).toBe(1);
		const parsed = JSON.parse(stdout) as CheckOutput;
		expect(parsed.ok).toBe(false);
		const targetSkill = parsed.skills.find(s => s.name === "missing-deps") ?? parsed.skills[0];
		expect(targetSkill).toBeDefined();
		expect(targetSkill?.name).toBe("missing-deps");
		expect(targetSkill?.missingRequired).toEqual(["rva-cli-absent-fixture"]);
		expect(targetSkill?.requirements[0]).toMatchObject({
			id: "rva-cli-absent-fixture",
			foundPath: null,
			unknown: true,
		});
		expect(targetSkill?.requirements[0].hint).toBeUndefined();
	});

	it("prints a readable missing line in text mode", async () => {
		await writeSkill("missing-text", "  requires: rva-cli-absent-fixture");
		const proc = runCli(["skill", "check"]);
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		expect(exitCode, stderr).toBe(1);
		expect(stdout).toContain("missing-text");
		expect(stdout).toContain("missing rva-cli-absent-fixture");
	});

	it("exits zero when only optional tools are missing", async () => {
		await writeSkill("optional-dep", "  requiresOptional: rva-cli-absent-fixture");
		const proc = runCli(["skill", "check", "--json"]);
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(proc.stdout).text(),
			new Response(proc.stderr).text(),
			proc.exited,
		]);
		expect(exitCode, stderr).toBe(0);
		const parsed = JSON.parse(stdout) as CheckOutput;
		expect(parsed.ok).toBe(true);
		const targetSkill = parsed.skills.find(s => s.name === "optional-dep") ?? parsed.skills[0];
		expect(targetSkill).toBeDefined();
		expect(targetSkill?.missingRequired).toEqual([]);
		expect(targetSkill?.requirements[0]).toMatchObject({ optional: true, foundPath: null });
	});

	it.skipIf(process.platform === "win32")(
		"exits zero and reports the path when required tools are present",
		async () => {
			const binDir = path.join(tempProject, "bin");
			await createExecutable(binDir, "rva-cli-present-fixture");
			await writeSkill("present-dep", "  requires: rva-cli-present-fixture");
			const proc = runCli(["skill", "check", "--json"], { pathPrefix: binDir });
			const [stdout, stderr, exitCode] = await Promise.all([
				new Response(proc.stdout).text(),
				new Response(proc.stderr).text(),
				proc.exited,
			]);
			expect(exitCode, stderr).toBe(0);
			const parsed = JSON.parse(stdout) as CheckOutput;
			expect(parsed.ok).toBe(true);
			const targetSkill = parsed.skills.find(s => s.name === "present-dep") ?? parsed.skills[0];
			expect(targetSkill).toBeDefined();
			expect(targetSkill?.missingRequired).toEqual([]);
			expect(targetSkill?.requirements[0].foundPath).toBeTruthy();
		},
	);
});
