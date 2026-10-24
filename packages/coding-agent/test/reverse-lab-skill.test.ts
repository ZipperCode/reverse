import { afterEach, describe, expect, it } from "bun:test";
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

	it("discovers all five reverse engineering domain/orchestrator skills from .agents/skills", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });

		const names = skills.map(s => s.name);
		expect(names).toContain("reverse-lab");
		expect(names).toContain("android-reverse");
		expect(names).toContain("windows-reverse");
		expect(names).toContain("web-protocol-reverse");
		expect(names).toContain("native-binary-reverse");
		const reverseLab = skills.find(s => s.name === "reverse-lab");
		expect(reverseLab!.description).toContain("reverse engineering orchestrator");

		const androidRev = skills.find(s => s.name === "android-reverse");
		expect(androidRev!.description).toContain("Android");

		const windowsRev = skills.find(s => s.name === "windows-reverse");
		expect(windowsRev!.description).toContain("Windows PE");

		const webRev = skills.find(s => s.name === "web-protocol-reverse");
		expect(webRev!.description).toContain("Web");

		const nativeRev = skills.find(s => s.name === "native-binary-reverse");
		expect(nativeRev!.description).toContain("native binary");
	});

	it("verifies reverse-lab orchestrator keeps all tools optional (silent when missing)", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const reverseLab = skills.find(s => s.name === "reverse-lab");
		expect(reverseLab).toBeDefined();

		const requirements = reverseLab!.requirements ?? [];
		expect(requirements.length).toBeGreaterThanOrEqual(7);
		expect(requirements.every(r => r.optional === true)).toBe(true);
		expect(requirements.map(r => r.id)).not.toContain("frida_session");

		// With no tools found, orchestrator notice remains undefined (silent)
		const statuses = checkToolRequirements(requirements, { which: () => null });
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("verifies android-reverse keeps external tools optional (silent baseline check when missing)", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const androidRev = skills.find(s => s.name === "android-reverse");
		expect(androidRev).toBeDefined();

		const requirements = androidRev!.requirements ?? [];
		const jadxReq = requirements.find(r => r.id === "jadx");
		expect(jadxReq).toBeDefined();
		expect(jadxReq!.optional).toBe(true);
		expect(requirements.every(r => r.optional === true)).toBe(true);

		// Optional tools in android-reverse
		const optionalIds = requirements.filter(r => r.optional).map(r => r.id);
		expect(optionalIds).toContain("jadx");
		expect(optionalIds).toContain("apktool");
		expect(optionalIds).toContain("adb");
		expect(optionalIds).toContain("frida");
		expect(optionalIds).toContain("droidasc");

		// When tools are missing on PATH, notice must remain undefined (silent on baseline)
		const statuses = checkToolRequirements(requirements, {
			platform: "darwin",
			which: () => null,
		});
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("verifies windows-reverse keeps external tools optional (silent baseline check when missing)", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const windowsRev = skills.find(s => s.name === "windows-reverse");
		expect(windowsRev).toBeDefined();

		const requirements = windowsRev!.requirements ?? [];
		const r2Req = requirements.find(r => r.id === "radare2");
		expect(r2Req).toBeDefined();
		expect(r2Req!.optional).toBe(true);

		const idaReq = requirements.find(r => r.id === "ida");
		expect(idaReq).toBeDefined();
		expect(idaReq!.optional).toBe(true);
		expect(requirements.every(r => r.optional === true)).toBe(true);

		// When tools are missing on PATH, notice must remain undefined (silent on baseline)
		const statuses = checkToolRequirements(requirements, {
			platform: "linux",
			which: () => null,
		});
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("verifies web-protocol-reverse declares optional tools correctly", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const webRev = skills.find(s => s.name === "web-protocol-reverse");
		expect(webRev).toBeDefined();

		const requirements = webRev!.requirements ?? [];
		const ids = requirements.map(r => r.id);
		expect(ids).toContain("ast-grep");
		expect(ids).toContain("wabt");
		expect(ids).not.toContain("playwright-mcp");
		expect(requirements.every(r => r.optional === true)).toBe(true);
	});

	it("verifies generic skill checker still flags user-authored required dependencies", () => {
		const requirements = [{ id: "jadx" }];
		const statuses = checkToolRequirements(requirements, {
			platform: "darwin",
			which: () => null,
		});
		const notice = missingRequirementNotice(statuses);
		expect(notice).toBeDefined();
		expect(notice).toContain("jadx not found on PATH");
	});

	it("verifies native-binary-reverse declares optional tools correctly", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const nativeRev = skills.find(s => s.name === "native-binary-reverse");
		expect(nativeRev).toBeDefined();

		const requirements = nativeRev!.requirements ?? [];
		const ids = requirements.map(r => r.id);
		expect(ids).toContain("radare2");
		expect(ids).toContain("ida");
		expect(ids).toContain("frida");
		expect(requirements.every(r => r.optional === true)).toBe(true);
	});

	it("resolves domain skills and reference guides via skill://", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		setActiveSkills(skills);
		const handler = new SkillProtocolHandler();

		// Domain skills
		const androidRes = await handler.resolve(parseInternalUrl("skill://android-reverse/"));
		expect(androidRes.content).toContain("# Android Reverse Engineering Specialist");
		expect(androidRes.content).toContain("skill://reverse-lab/references/android.md");

		const windowsRes = await handler.resolve(parseInternalUrl("skill://windows-reverse/"));
		expect(windowsRes.content).toContain("# Windows PE Reverse Engineering Specialist");
		expect(windowsRes.content).toContain("skill://reverse-lab/references/windows.md");

		const webRes = await handler.resolve(parseInternalUrl("skill://web-protocol-reverse/"));
		expect(webRes.content).toContain("# Web & Protocol Forensics Specialist");
		expect(webRes.content).toContain("skill://reverse-lab/references/web-protocol.md");

		const nativeRes = await handler.resolve(parseInternalUrl("skill://native-binary-reverse/"));
		expect(nativeRes.content).toContain("# Native Binary Reverse Engineering Specialist");
		// Reference guides under reverse-lab
		const routingRes = await handler.resolve(parseInternalUrl("skill://reverse-lab/references/target-routing.md"));
		expect(routingRes.content).toContain("# Target-First Routing");

		const evidenceRes = await handler.resolve(parseInternalUrl("skill://reverse-lab/references/evidence.md"));
		expect(evidenceRes.content).toContain("# Evidence Chain");

		const fallbackRes = await handler.resolve(parseInternalUrl("skill://reverse-lab/references/tool-fallback.md"));
		expect(fallbackRes.content).toContain("# Tool Fallback");
	});
});
