import { afterEach, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { loadSkills, resetActiveSkillsForTests, setActiveSkills } from "@reverse/coding-agent/extensibility/skills";
import {
	checkToolRequirements,
	missingRequirementNotice,
} from "@reverse/coding-agent/extensibility/skill-requirements";
import { getMcpServices } from "@reverse/coding-agent/extensibility/mcp-service-catalog";
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

		// With no tools found, orchestrator notice remains undefined (silent)
		const statuses = checkToolRequirements(requirements, { which: () => null });
		expect(missingRequirementNotice(statuses)).toBeUndefined();
	});

	it("verifies android-reverse enforces jadx as required and emits install notice when missing", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const androidRev = skills.find(s => s.name === "android-reverse");
		expect(androidRev).toBeDefined();

		const requirements = androidRev!.requirements ?? [];
		const jadxReq = requirements.find(r => r.id === "jadx");
		expect(jadxReq).toBeDefined();
		expect(jadxReq!.optional).toBeFalsy();

		// Optional tools in android-reverse
		const optionalIds = requirements.filter(r => r.optional).map(r => r.id);
		expect(optionalIds).toContain("apktool");
		expect(optionalIds).toContain("adb");
		expect(optionalIds).toContain("frida");
		expect(optionalIds).toContain("droidasc");

		// When jadx is missing on PATH, notice must be generated with install hint
		const statuses = checkToolRequirements(requirements, {
			platform: "darwin",
			which: () => null,
		});
		const notice = missingRequirementNotice(statuses);
		expect(notice).toBeDefined();
		expect(notice).toContain("jadx not found on PATH");
		expect(notice).toContain("brew install jadx");

		// When jadx and java are present, notice must be undefined (silent)
		const presentStatuses = checkToolRequirements(requirements, {
			platform: "darwin",
			which: cmd => (cmd === "jadx" ? "/usr/local/bin/jadx" : cmd === "java" ? "/usr/bin/java" : null),
		});
		expect(missingRequirementNotice(presentStatuses)).toBeUndefined();
	});

	it("verifies windows-reverse enforces radare2 as required and emits install notice when missing", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const windowsRev = skills.find(s => s.name === "windows-reverse");
		expect(windowsRev).toBeDefined();

		const requirements = windowsRev!.requirements ?? [];
		const r2Req = requirements.find(r => r.id === "radare2");
		expect(r2Req).toBeDefined();
		expect(r2Req!.optional).toBeFalsy();

		const idaReq = requirements.find(r => r.id === "ida");
		expect(idaReq).toBeDefined();
		expect(idaReq!.optional).toBe(true);

		// When radare2 is missing on Linux, notice must recommend apt install radare2
		const statuses = checkToolRequirements(requirements, {
			platform: "linux",
			which: () => null,
		});
		const notice = missingRequirementNotice(statuses);
		expect(notice).toBeDefined();
		expect(notice).toContain("radare2 not found on PATH");
		expect(notice).toContain("apt install radare2");
	});

	it("verifies web-protocol-reverse declares optional tools correctly", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const webRev = skills.find(s => s.name === "web-protocol-reverse");
		expect(webRev).toBeDefined();

		const requirements = webRev!.requirements ?? [];
		const ids = requirements.map(r => r.id);
		expect(ids).toContain("ast-grep");
		expect(ids).toContain("wabt");
		expect(requirements.every(r => r.optional === true)).toBe(true);
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

	it("resolves the on-demand reverse tool guide and its catalog-backed references", async () => {
		const { skills } = await loadSkills({ cwd: repoRoot });
		const guide = skills.find(s => s.name === "reverse-tool-guide");
		expect(guide).toBeDefined();
		expect(guide!.description).toContain("Canonical usage guide");

		setActiveSkills(skills);
		const handler = new SkillProtocolHandler();

		const skillRes = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/"));
		expect(skillRes.content).toContain("# Reverse Tool Guide");
		expect(skillRes.content).toContain("skill://reverse-tool-guide/references/cli-tools.md");
		expect(skillRes.content).toContain("MCP helper services are **not PATH binaries**");

		const cliRes = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/references/cli-tools.md"));
		expect(cliRes.content).toContain('r2 -qc "iI; iS; ii"');
		expect(cliRes.content).toContain("frida-ps -U");
		expect(cliRes.content).toContain("mitmdump -p 8080 -w");

		const mcpRes = await handler.resolve(parseInternalUrl("skill://reverse-tool-guide/references/mcp-services.md"));
		for (const service of getMcpServices()) {
			expect(mcpRes.content).toContain(service.id);
			expect(mcpRes.content).toContain(service.startCommand);
			expect(mcpRes.content).toContain(service.license);
		}
		expect(mcpRes.content).toContain("r2pm -Uci r2mcp");
		expect(mcpRes.content).toContain("They are **not PATH binaries**");
	});

	it("keeps the MCP guide and the catalog in both directions", () => {
		const guide = readFileSync(
			path.join(repoRoot, ".agents/skills/reverse-tool-guide/references/mcp-services.md"),
			"utf8",
		);
		const documentedIds = [...guide.matchAll(/^##\s+\d+\.\s+([a-z0-9-]+)\s+—/gm)].map(match => match[1]).sort();
		const catalogIds = getMcpServices()
			.map(service => service.id)
			.sort();
		expect(documentedIds).toEqual(catalogIds);

		for (const service of getMcpServices()) {
			expect(guide).toContain(`"${service.serverName}": {`);
			expect(guide).toContain(service.startCommand);
			if (service.server.type === "stdio" && "command" in service.server) {
				expect(guide).toContain(`"command": ${JSON.stringify(service.server.command)}`);
			}
			expect(guide).toContain(service.license);
		}
	});
});
