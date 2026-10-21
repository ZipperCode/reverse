import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { Skill } from "@reverse/coding-agent/extensibility/skills";
import { buildSkillPromptMessage, loadSkills } from "@reverse/coding-agent/extensibility/skills";
import type { ToolRequirement } from "@reverse/coding-agent/extensibility/skill-requirements";
import { parseInternalUrl } from "@reverse/coding-agent/internal-urls/parse";
import { SkillProtocolHandler } from "@reverse/coding-agent/internal-urls/skill-protocol";
import { ReadTool } from "@reverse/coding-agent/tools/read";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { restoreEnvValue } from "./helpers/settings-test-state";

const tempDirs: string[] = [];

async function createSkill(
	name: string,
	body: string,
	requirements?: readonly ToolRequirement[],
): Promise<{ dir: string; skill: Skill }> {
	const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), `reverse-skill-req-${name}-`)));
	tempDirs.push(dir);
	const filePath = path.join(dir, "SKILL.md");
	await Bun.write(filePath, `---\nname: ${name}\ndescription: ${name} fixture\n---\n\n${body}\n`);
	const skill: Skill = {
		name,
		description: `${name} fixture`,
		filePath,
		baseDir: dir,
		source: "test:user",
		...(requirements !== undefined && { requirements }),
	};
	return { dir, skill };
}

afterEach(async () => {
	for (const dir of tempDirs) await fs.rm(dir, { recursive: true, force: true });
	tempDirs.length = 0;
});

describe("skill dependency notice injection", () => {
	it("prepends a missing required dependency notice to /skill-style prompts", async () => {
		const { skill } = await createSkill("dep-prompt", "Do the thing.", [{ id: "reverse-injection-absent-fixture" }]);
		const built = await buildSkillPromptMessage(skill, { args: "" }, "user");
		expect(built.message.startsWith("[Missing tool dependencies:")).toBe(true);
		expect(built.message).toContain("reverse-injection-absent-fixture");
		expect(built.message).toContain('[IMPORTANT: User invoked the "dep-prompt" skill');
	});

	it("leaves the prompt untouched when dependencies are absent from the declaration", async () => {
		const { skill } = await createSkill("no-deps", "Do the thing.");
		const built = await buildSkillPromptMessage(skill, { args: "" }, "user");
		expect(built.message.startsWith("[Missing tool dependencies:")).toBe(false);
		expect(built.message.startsWith('[IMPORTANT: User invoked the "no-deps" skill')).toBe(true);
	});

	it("stays silent for missing optional dependencies", async () => {
		const { skill } = await createSkill("optional-dep", "Do the thing.", [
			{ id: "reverse-injection-absent-fixture", optional: true },
		]);
		const built = await buildSkillPromptMessage(skill, { args: "" }, "autoload");
		expect(built.message).not.toContain("Missing tool dependencies");
	});

	it("prepends the notice to skill:// instruction reads but not subpath reads", async () => {
		const { dir, skill } = await createSkill("protocol-dep", "Instruction body.", [
			{ id: "reverse-injection-absent-fixture" },
		]);
		await fs.mkdir(path.join(dir, "references"), { recursive: true });
		await Bun.write(path.join(dir, "references", "notes.md"), "Reference body.\n");

		const handler = new SkillProtocolHandler();
		const instruction = await handler.resolve(parseInternalUrl("skill://protocol-dep"), { skills: [skill] });
		expect(instruction.content.startsWith("[Missing tool dependencies:")).toBe(true);

		// The explicit instruction-file spelling must not bypass the notice.
		const alias = await handler.resolve(parseInternalUrl("skill://protocol-dep/SKILL.md"), { skills: [skill] });
		expect(alias.content.startsWith("[Missing tool dependencies:")).toBe(true);

		const subpath = await handler.resolve(parseInternalUrl("skill://protocol-dep/references/notes.md"), {
			skills: [skill],
		});
		expect(subpath.content).toBe("Reference body.\n");
	});

	it("loads metadata.requires from a real SKILL.md and injects it into prompt and read", async () => {
		const root = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-skill-required-e2e-"));
		tempDirs.push(root);
		const skillDir = path.join(root, "required-deps");
		await fs.mkdir(skillDir, { recursive: true });
		await Bun.write(
			path.join(skillDir, "SKILL.md"),
			"---\nname: required-deps\ndescription: Required dependency fixture\nmetadata:\n  requires: reverse-e2e-absent-fixture\n---\n\nInstruction body.\n",
		);

		const { skills } = await loadSkills({
			cwd: root,
			customDirectories: [root],
			enableCodexUser: false,
			enableClaudeUser: false,
			enableClaudeProject: false,
			enablePiUser: false,
			enablePiProject: false,
			enableAgentsUser: false,
			enableAgentsProject: false,
		});
		const skill = skills.find(candidate => candidate.name === "required-deps");
		expect(skill).toBeDefined();
		expect(skill!.requirements).toEqual([{ id: "reverse-e2e-absent-fixture" }]);

		const built = await buildSkillPromptMessage(skill!, { args: "" }, "user");
		expect(built.message).toContain("[Missing tool dependencies:");
		expect(built.message).toContain("reverse-e2e-absent-fixture");

		const session: ToolSession = {
			cwd: skillDir,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated(),
			skills: [skill!],
		};
		const read = await new ReadTool(session).execute("read-required-e2e", { path: "skill://required-deps" });
		const text = read.content.flatMap(block => (block.type === "text" ? [block.text] : [])).join("\n");
		expect(text).toContain("[Missing tool dependencies:");
		expect(text).toContain("reverse-e2e-absent-fixture");
	});

	it("injects the notice through the real read tool, and not for subpaths or raw reads", async () => {
		const { dir, skill } = await createSkill("read-path-dep", "Instruction body.", [
			{ id: "reverse-injection-absent-fixture" },
		]);
		await fs.mkdir(path.join(dir, "references"), { recursive: true });
		await Bun.write(path.join(dir, "references", "notes.md"), "Reference body.\n");
		const session: ToolSession = {
			cwd: dir,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated(),
			skills: [skill],
		};
		const tool = new ReadTool(session);

		const instruction = await tool.execute("read-dep-instruction", { path: "skill://read-path-dep" });
		const instructionText = instruction.content
			.flatMap(block => (block.type === "text" ? [block.text] : []))
			.join("\n");
		expect(instructionText).toContain("[Missing tool dependencies:");
		expect(instructionText).toContain("reverse-injection-absent-fixture");
		expect(instructionText.indexOf("[Missing tool dependencies:")).toBeLessThan(
			instructionText.indexOf("[Skill file:"),
		);

		const alias = await tool.execute("read-dep-alias", { path: "skill://read-path-dep/SKILL.md" });
		const aliasText = alias.content.flatMap(block => (block.type === "text" ? [block.text] : [])).join("\n");
		expect(aliasText).toContain("[Missing tool dependencies:");

		const subpath = await tool.execute("read-dep-subpath", { path: "skill://read-path-dep/references/notes.md" });
		const subpathText = subpath.content.flatMap(block => (block.type === "text" ? [block.text] : [])).join("\n");
		expect(subpathText).not.toContain("[Missing tool dependencies:");

		const raw = await tool.execute("read-dep-raw", { path: "skill://read-path-dep:raw" });
		const rawText = raw.content.flatMap(block => (block.type === "text" ? [block.text] : [])).join("\n");
		expect(rawText).toBe(await Bun.file(skill.filePath).text());
	});

	it.skipIf(process.platform === "win32")("stays silent when the required executable is on PATH", async () => {
		const binDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-skill-req-bin-"));
		tempDirs.push(binDir);
		const binary = path.join(binDir, "reverse-injection-present-fixture");
		await Bun.write(binary, "#!/bin/sh\nexit 0\n");
		await fs.chmod(binary, 0o755);

		const originalPath = process.env.PATH;
		restoreEnvValue("PATH", `${binDir}${path.delimiter}${originalPath ?? ""}`);
		try {
			const { skill } = await createSkill("present-dep", "Do the thing.", [
				{ id: "reverse-injection-present-fixture" },
			]);
			const built = await buildSkillPromptMessage(skill, { args: "" }, "user");
			expect(built.message).not.toContain("Missing tool dependencies");

			const instruction = await new SkillProtocolHandler().resolve(parseInternalUrl("skill://present-dep"), {
				skills: [skill],
			});
			expect(instruction.content.startsWith("[Missing tool dependencies:")).toBe(false);
		} finally {
			restoreEnvValue("PATH", originalPath);
		}
	});
});
