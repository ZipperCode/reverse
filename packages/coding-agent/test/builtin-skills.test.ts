import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getAllProvidersInfo, resetCapabilityForTests, setDisabledProviders } from "@reverse/coding-agent/capability";
import {
	BUILTIN_SKILL_REFERENCES,
	BUILTIN_SKILL_SOURCES,
	BUILTIN_SKILLS_PROVIDER_ID,
} from "@reverse/coding-agent/discovery/builtin-skills";
import { loadSkills, resetActiveSkillsForTests, setActiveSkills } from "@reverse/coding-agent/extensibility/skills";
import { parseInternalUrl } from "@reverse/coding-agent/internal-urls/parse";
import { SkillProtocolHandler } from "@reverse/coding-agent/internal-urls/skill-protocol";

const repoRoot = path.resolve(import.meta.dir, "../../..");
const bundledRoot = path.join(import.meta.dir, "../src/discovery/builtin-skills");
const projectSkillsRoot = path.join(repoRoot, ".agents", "skills");

const SKILL_NAMES = [
	"android-reverse",
	"native-binary-reverse",
	"reverse-lab",
	"reverse-tool-guide",
	"web-protocol-reverse",
	"windows-reverse",
] as const;

function listFiles(root: string): string[] {
	return [...new Bun.Glob("**/*").scanSync({ cwd: root, onlyFiles: true })].sort();
}

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
	it("keeps the package copies byte-identical to .agents/skills", () => {
		expect(listFiles(bundledRoot)).toEqual(listFiles(projectSkillsRoot));

		for (const name of SKILL_NAMES) {
			const bundled = readFileSync(path.join(bundledRoot, name, "SKILL.md"), "utf8");
			const project = readFileSync(path.join(projectSkillsRoot, name, "SKILL.md"), "utf8");
			expect(bundled).toBe(project);
		}
	});

	it("embeds every skill instruction and reference asset", () => {
		expect(BUILTIN_SKILL_SOURCES.map(source => source.name).sort()).toEqual([...SKILL_NAMES].sort());
		for (const source of BUILTIN_SKILL_SOURCES) {
			expect(readFileSync(source.path, "utf8")).toBe(
				readFileSync(path.join(projectSkillsRoot, source.name, "SKILL.md"), "utf8"),
			);
		}

		expect(BUILTIN_SKILL_REFERENCES.length).toBeGreaterThanOrEqual(8);
		for (const referencePath of BUILTIN_SKILL_REFERENCES) {
			const relative = path.relative(bundledRoot, referencePath);
			expect(readFileSync(referencePath, "utf8")).toBe(readFileSync(path.join(projectSkillsRoot, relative), "utf8"));
		}
	});

	it("discovers all six reverse skills without a project .agents directory", async () => {
		disableOtherSkillProviders();
		const cwd = mkdtempSync(path.join(os.tmpdir(), "rev-bundled-skills-"));
		try {
			const { skills } = await loadSkills({ cwd });
			const names = skills
				.filter(skill => skill._source?.provider === BUILTIN_SKILLS_PROVIDER_ID)
				.map(skill => skill.name)
				.sort();
			expect(names).toEqual([...SKILL_NAMES].sort());
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
});
