import { afterEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { loadSkills, resetActiveSkillsForTests, setActiveSkills } from "@reverse/coding-agent/extensibility/skills";
import {
	checkToolRequirements,
	missingRequirementNotice,
} from "@reverse/coding-agent/extensibility/skill-requirements";
import { parseInternalUrl } from "@reverse/coding-agent/internal-urls/parse";
import { SkillProtocolHandler } from "@reverse/coding-agent/internal-urls/skill-protocol";

const repoRoot = path.resolve(import.meta.dir, "../../..");

describe("reverse-lab suite discovery, requirements and references", () => {
	afterEach(() => {
		resetActiveSkillsForTests();
	});

	it("discovers reverse engineering skills through canonical symlinks without duplicate collisions", async () => {
		const { skills, warnings } = await loadSkills({ cwd: repoRoot });
		const names = skills.map(s => s.name);

		expect(names).toContain("reverse-lab");
		expect(names).toContain("android-reverse");
		expect(names).toContain("native-binary-reverse");
		expect(names).toContain("web-protocol-reverse");
		expect(names).toContain("windows-reverse");
		expect(names).toContain("vmp-reverse");

		// Canonical symlinks must deduplicate cleanly with no collisions
		const reverseSkillNames = [
			"reverse-lab",
			"android-reverse",
			"native-binary-reverse",
			"web-protocol-reverse",
			"windows-reverse",
			"vmp-reverse",
			"reverse-tool-guide",
		];
		for (const name of reverseSkillNames) {
			const matches = skills.filter(s => s.name === name);
			expect(matches.length).toBe(1);
		}
		const warningMessages = warnings.map(w => (typeof w === "string" ? w : w.message));
		expect(warningMessages.filter(msg => reverseSkillNames.some(n => msg.includes(n)))).toEqual([]);
	});

	it("preserves authored custom override priority over builtin skills", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-override-test-"));
		try {
			const customSkillDir = path.join(tempDir, ".agents", "skills", "android-reverse");
			await fs.mkdir(customSkillDir, { recursive: true });
			await fs.writeFile(
				path.join(customSkillDir, "SKILL.md"),
				"---\nname: android-reverse\ndescription: Custom user project override\n---\n# Authored Override\n",
			);

			const { skills, warnings } = await loadSkills({ cwd: tempDir });
			const primary = skills.find(s => s.name === "android-reverse");
			expect(primary).toBeDefined();
			expect(primary?.source).toBe("agents:project");
			expect(primary?.description).toBe("Custom user project override");

			// Displaced builtin should have collision warning
			const warningMessages = warnings.map(w => (typeof w === "string" ? w : w.message));
			expect(warningMessages.some(msg => msg.includes("android-reverse") && msg.includes("name collision"))).toBe(
				true,
			);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("verifies reverse domain skills keep tools optional (silent baseline when missing)", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const domainSkillNames = [
			"reverse-lab",
			"android-reverse",
			"windows-reverse",
			"web-protocol-reverse",
			"native-binary-reverse",
		];

		for (const name of domainSkillNames) {
			const skill = skills.find(s => s.name === name);
			expect(skill).toBeDefined();
			const requirements = skill?.requirements ?? [];
			// All declared tool dependencies must be optional
			expect(requirements.every(r => r.optional === true)).toBe(true);

			// When optional tools are missing on PATH, notice remains undefined (silent baseline)
			const statuses = checkToolRequirements(requirements, { which: () => null });
			expect(missingRequirementNotice(statuses)).toBeUndefined();
		}
	});

	it("verifies generic skill checker flags required dependencies when missing", () => {
		const requirements = [{ id: "jadx", optional: false }];
		const statuses = checkToolRequirements(requirements, {
			platform: "darwin",
			which: () => null,
		});
		const notice = missingRequirementNotice(statuses);
		expect(notice).toBeDefined();
		expect(notice).toContain("jadx not found on PATH");
	});

	it("resolves domain skills and reference guides via skill:// to canonical physical paths", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		setActiveSkills(skills);
		const handler = new SkillProtocolHandler();

		const assertCanonicalSkill = async (uri: string, relativeCanonicalPath: string) => {
			const resolved = await handler.resolve(parseInternalUrl(uri));
			const canonicalFile = path.resolve(repoRoot, relativeCanonicalPath);
			const targetPath = resolved.sourcePath ?? (await handler.locate(parseInternalUrl(uri)));
			expect(targetPath).toBeDefined();
			const [realResolved, realCanonical] = await Promise.all([
				fs.realpath(targetPath!),
				fs.realpath(canonicalFile),
			]);
			expect(realResolved).toBe(realCanonical);
			const canonicalContent = await fs.readFile(canonicalFile, "utf-8");
			expect(resolved.content).toBe(canonicalContent);
		};

		// Domain skills resolve to canonical package sources
		await assertCanonicalSkill(
			"skill://android-reverse/",
			"packages/coding-agent/src/discovery/builtin-skills/android-reverse/SKILL.md",
		);
		await assertCanonicalSkill(
			"skill://windows-reverse/",
			"packages/coding-agent/src/discovery/builtin-skills/windows-reverse/SKILL.md",
		);
		await assertCanonicalSkill(
			"skill://web-protocol-reverse/",
			"packages/coding-agent/src/discovery/builtin-skills/web-protocol-reverse/SKILL.md",
		);
		await assertCanonicalSkill(
			"skill://native-binary-reverse/",
			"packages/coding-agent/src/discovery/builtin-skills/native-binary-reverse/SKILL.md",
		);

		// Reference guides resolve to canonical references
		await assertCanonicalSkill(
			"skill://reverse-lab/references/target-routing.md",
			"packages/coding-agent/src/discovery/builtin-skills/reverse-lab/references/target-routing.md",
		);
		await assertCanonicalSkill(
			"skill://reverse-lab/references/evidence.md",
			"packages/coding-agent/src/discovery/builtin-skills/reverse-lab/references/evidence.md",
		);
		await assertCanonicalSkill(
			"skill://reverse-lab/references/tool-fallback.md",
			"packages/coding-agent/src/discovery/builtin-skills/reverse-lab/references/tool-fallback.md",
		);
	});
});
