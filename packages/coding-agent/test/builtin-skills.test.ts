import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getAllProvidersInfo, resetCapabilityForTests, setDisabledProviders } from "@reverse/coding-agent/capability";
import { BUILTIN_SKILL_SOURCES, BUILTIN_SKILLS_PROVIDER_ID } from "@reverse/coding-agent/discovery/builtin-skills";
import { loadSkills, resetActiveSkillsForTests, setActiveSkills } from "@reverse/coding-agent/extensibility/skills";
import { parseInternalUrl } from "@reverse/coding-agent/internal-urls/parse";
import {
	MissingSkillResourceError,
	SkillProtocolHandler,
	StaleSkillMetadataError,
} from "@reverse/coding-agent/internal-urls/skill-protocol";

/** Isolate bundled-skill discovery from every other skill provider. */
function disableOtherSkillProviders(): void {
	const others = getAllProvidersInfo()
		.filter(provider => provider.capabilities.includes("skills") && provider.id !== BUILTIN_SKILLS_PROVIDER_ID)
		.map(provider => provider.id);
	setDisabledProviders(others);
}

afterEach(() => {
	resetCapabilityForTests();
	resetActiveSkillsForTests();
});

describe("bundled reverse skills shipped with the package", () => {
	it("discovers all reverse skills without a project .agents directory", async () => {
		disableOtherSkillProviders();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-bundled-skills-"));
		try {
			const { skills } = await loadSkills({ cwd });
			const discovered = skills.filter(skill => skill._source?.provider === BUILTIN_SKILLS_PROVIDER_ID);
			expect(discovered.length).toBe(BUILTIN_SKILL_SOURCES.length);
			const expectedNames = BUILTIN_SKILL_SOURCES.map(s => s.name).sort();
			expect(discovered.map(s => s.name).sort()).toEqual(expectedNames);
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("serves bundled reference files through skill://", async () => {
		disableOtherSkillProviders();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-bundled-refs-"));
		try {
			const { skills } = await loadSkills({ cwd });
			setActiveSkills(skills);
			const handler = new SkillProtocolHandler();

			const guide = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/"));
			expect(guide.content).toContain("# Reverse Tool Guide");

			const services = await handler.resolve(
				parseInternalUrl("skill://reverse-tool-guide/references/mcp-services.md"),
			);
			expect(services.content).toContain("prerequisitesReady");
			expect(services.content).toContain('`connection` — always `"unknown"`');

			const routing = await handler.resolve(parseInternalUrl("skill://reverse-lab/references/target-routing.md"));
			expect(routing.content.length).toBeGreaterThan(0);
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("reads all shipped skills via both bare and /SKILL.md URIs", async () => {
		disableOtherSkillProviders();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-bundled-all-"));
		try {
			const { skills } = await loadSkills({ cwd });
			setActiveSkills(skills);
			const handler = new SkillProtocolHandler();

			for (const source of BUILTIN_SKILL_SOURCES) {
				const name = source.name;
				const bare = await handler.resolve(parseInternalUrl(`skill://${name}`));
				expect(bare.content.length).toBeGreaterThan(0);
				expect(bare.url).toBe(`skill://${name}`);

				const fileUri = await handler.resolve(parseInternalUrl(`skill://${name}/SKILL.md`));
				expect(fileUri.content.length).toBeGreaterThan(0);
			}
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("diagnoses unknown skill names with available list", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "test-skill",
				description: "test",
				filePath: "/tmp/SKILL.md",
				baseDir: "/tmp",
				source: "custom:user",
			},
		]);

		await expect(handler.resolve(parseInternalUrl("skill://nonexistent"))).rejects.toThrow(
			/Unknown skill: nonexistent\nAvailable: test-skill/,
		);
	});

	it("diagnoses missing subpath resource with actionable error", async () => {
		disableOtherSkillProviders();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-bundled-missing-subpath-"));
		try {
			const { skills } = await loadSkills({ cwd });
			setActiveSkills(skills);
			const handler = new SkillProtocolHandler();

			const error = await handler
				.resolve(parseInternalUrl("skill://reverse-tool-guide/references/nonexistent-ref.md"))
				.catch(e => e);
			expect(error).toBeInstanceOf(MissingSkillResourceError);
			expect(error.code).toBe("ENOENT");
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("diagnoses stale metadata when skill instruction file is missing on disk", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "stale-skill",
				description: "stale skill",
				filePath: path.join(os.tmpdir(), "nonexistent-stale-dir", "SKILL.md"),
				baseDir: path.join(os.tmpdir(), "nonexistent-stale-dir"),
				source: "custom:user",
			},
		]);

		const error = await handler.resolve(parseInternalUrl("skill://stale-skill")).catch(e => e);
		expect(error).toBeInstanceOf(StaleSkillMetadataError);
		expect(error.code).toBe("ENOENT");
	});

	it("resolves bundled skill references via logical asset map", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "reverse-tool-guide",
				description: "Canonical usage guide",
				filePath: "/virtual/reverse-tool-guide/SKILL.md",
				baseDir: "/virtual/reverse-tool-guide",
				source: "builtin-skills:user",
				_source: {
					provider: "builtin-skills",
					providerName: "Bundled Skills",
					path: "/virtual/reverse-tool-guide/SKILL.md",
					level: "user",
				},
			},
		]);

		const guide = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide"));
		expect(guide.content).toContain("# Reverse Tool Guide");

		const cli = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/references/cli-tools.md"));
		expect(cli.content).toContain("CLI");
	});

	it("diagnoses stale metadata when an overriding custom skill is missing without falling back to builtin", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "reverse-tool-guide",
				description: "User overriding guide",
				filePath: path.join(os.tmpdir(), "missing-user-guide", "SKILL.md"),
				baseDir: path.join(os.tmpdir(), "missing-user-guide"),
				source: "custom:user",
				_source: {
					provider: "custom",
					providerName: "Custom",
					path: path.join(os.tmpdir(), "missing-user-guide", "SKILL.md"),
					level: "user",
				},
			},
		]);

		const error = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide")).catch(e => e);
		expect(error).toBeInstanceOf(StaleSkillMetadataError);
		expect(error.code).toBe("ENOENT");
	});

	it("diagnoses missing resource when an overriding custom skill lacks a referenced subpath", async () => {
		const handler = new SkillProtocolHandler();
		const tempDir = mkdtempSync(path.join(os.tmpdir(), "custom-override-"));
		try {
			const skillFile = path.join(tempDir, "SKILL.md");
			await Bun.write(skillFile, "# Custom Override Guide");
			setActiveSkills([
				{
					name: "reverse-tool-guide",
					description: "User overriding guide",
					filePath: skillFile,
					baseDir: tempDir,
					source: "custom:user",
					_source: {
						provider: "custom",
						providerName: "Custom",
						path: skillFile,
						level: "user",
					},
				},
			]);

			const error = await handler
				.resolve(parseInternalUrl("skill://reverse-tool-guide/references/cli-tools.md"))
				.catch(e => e);
			expect(error).toBeInstanceOf(MissingSkillResourceError);
			expect(error.code).toBe("ENOENT");
		} finally {
			rmSync(tempDir, { recursive: true, force: true });
		}
	});

	it("serves displaced namespaced builtin skill through logical asset map", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "builtin-skills/reverse-tool-guide",
				description: "Displaced builtin guide",
				filePath: "/virtual/reverse-tool-guide/SKILL.md",
				baseDir: "/virtual/reverse-tool-guide",
				source: "builtin-skills:user",
				_source: {
					provider: "builtin-skills",
					providerName: "Bundled Skills",
					path: "/virtual/reverse-tool-guide/SKILL.md",
					level: "user",
				},
			},
		]);

		const res = await handler.resolve(parseInternalUrl("skill://builtin-skills/reverse-tool-guide"));
		expect(res.content).toContain("# Reverse Tool Guide");

		const refRes = await handler.resolve(
			parseInternalUrl("skill://builtin-skills/reverse-tool-guide/references/cli-tools.md"),
		);
		expect(refRes.content).toContain("CLI");
	});

	it("preserves directory resolution for locate with directory: true on bare builtin URI", async () => {
		const handler = new SkillProtocolHandler();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-locate-dir-"));
		try {
			const { skills } = await loadSkills({ cwd });
			setActiveSkills(skills);

			const locatedDir = await handler.locate(parseInternalUrl("skill://reverse-tool-guide"), undefined, {
				directory: true,
			});
			expect(locatedDir).not.toBeNull();
			expect(locatedDir?.endsWith("SKILL.md")).toBe(false);

			const locatedFile = await handler.locate(parseInternalUrl("skill://reverse-tool-guide"), undefined, {
				directory: false,
			});
			expect(locatedFile).not.toBeNull();
			expect(locatedFile?.endsWith("SKILL.md")).toBe(true);
		} finally {
			rmSync(cwd, { recursive: true, force: true });
		}
	});

	it("safely rejects prototype property names without TypeError", async () => {
		const handler = new SkillProtocolHandler();
		setActiveSkills([
			{
				name: "reverse-tool-guide",
				description: "Canonical usage guide",
				filePath: "/virtual/reverse-tool-guide/SKILL.md",
				baseDir: "/virtual/reverse-tool-guide",
				source: "builtin-skills:user",
				_source: {
					provider: "builtin-skills",
					providerName: "Bundled Skills",
					path: "/virtual/reverse-tool-guide/SKILL.md",
					level: "user",
				},
			},
		]);

		const errConstructor = await handler
			.resolve(parseInternalUrl("skill://reverse-tool-guide/constructor"))
			.catch(e => e);
		expect(errConstructor).toBeInstanceOf(MissingSkillResourceError);
		expect(errConstructor.code).toBe("ENOENT");

		const errProto = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/__proto__")).catch(e => e);
		expect(errProto).toBeInstanceOf(MissingSkillResourceError);
		expect(errProto.code).toBe("ENOENT");
	});

	it("preserves normal user skills alongside bundled skills", async () => {
		const tempUserDir = mkdtempSync(path.join(os.tmpdir(), "rev-user-skill-"));
		const userSkillDir = path.join(tempUserDir, "user-custom-skill");
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-cwd-"));
		try {
			await Bun.write(
				path.join(userSkillDir, "SKILL.md"),
				"---\nname: user-custom-skill\ndescription: Custom user skill\n---\n# User Custom Skill\nSpecialized instructions.",
			);
			const { skills } = await loadSkills({
				cwd,
				customDirectories: [tempUserDir],
			});
			setActiveSkills(skills);
			const handler = new SkillProtocolHandler();

			const userSkill = await handler.resolve(parseInternalUrl("skill://user-custom-skill"));
			expect(userSkill.content).toContain("# User Custom Skill");

			const bundledSkill = await handler.resolve(parseInternalUrl("skill://reverse-lab"));
			expect(bundledSkill.content).toContain("# Reverse Lab");
		} finally {
			rmSync(tempUserDir, { recursive: true, force: true });
			rmSync(cwd, { recursive: true, force: true });
		}
	});
});
