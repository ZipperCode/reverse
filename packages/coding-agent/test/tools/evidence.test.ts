import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, EvidenceTool, type ToolSession, BUILTIN_TOOLS } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string, options: { allocateArtifact?: boolean } = {}): ToolSession {
	const artifactsDir = path.join(cwd, "artifacts");
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		allocateOutputArtifact: options.allocateArtifact
			? async (toolType: string) => {
					await fs.mkdir(artifactsDir, { recursive: true });
					const id = `art-${Date.now()}`;
					return { id, path: path.join(artifactsDir, `${id}.${toolType}.txt`) };
				}
			: undefined,
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

describe("evidence tool registration and canonical naming", () => {
	it("is registered in BUILTIN_TOOL_NAMES", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("evidence");
	});

	it("normalizes evidence_ledger alias to evidence", () => {
		expect(normalizeToolName("evidence_ledger")).toBe("evidence");
		expect(normalizeToolName("EVIDENCE_LEDGER")).toBe("evidence");
		expect(normalizeToolName("evidence")).toBe("evidence");
	});

	it("instantiates via createTools and BUILTIN_TOOLS", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["evidence"]);
			const tool = tools.find(t => t.name === "evidence");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Evidence Ledger");
			expect(tool?.strict).toBe(true);

			const direct = BUILTIN_TOOLS.evidence(session);
			expect(direct).toBeInstanceOf(EvidenceTool);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("declares approval tier: write for add/verify, read for list/show/export", () => {
		const session = createTestSession(os.tmpdir());
		const tool = new EvidenceTool(session);
		expect(tool.approval({ action: "add" })).toBe("write");
		expect(tool.approval({ action: "verify" })).toBe("write");
		expect(tool.approval({ action: "list" })).toBe("read");
		expect(tool.approval({ action: "show" })).toBe("read");
		expect(tool.approval({ action: "export" })).toBe("read");
	});
});

describe("evidence lifecycle: fact -> hypothesis -> verify -> show -> list", () => {
	it("records complete empirical evidence chain without polluting repository", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-lifecycle-proj-"));
		const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-lifecycle-state-"));

		try {
			const sampleFile = path.join(projectDir, "sample.apk");
			await fs.writeFile(sampleFile, "PK\x03\x04synthetic-apk-content-for-testing");

			const session = createTestSession(projectDir);
			const tool = new EvidenceTool(session);

			// 1. Add fact
			const factRes = await tool.execute("call-1", {
				action: "add",
				kind: "fact",
				target: "sample.apk",
				sourceTool: "droidasc",
				locator: "com.example.LicenseValidator.isPro()",
				content: "Decompiled method returns field mIsPro",
				excerpt: "return this.mIsPro;",
				classification: "CWE-602",
				tags: ["license", "android"],
			});

			const factText = textOf(factRes);
			expect(factText).toContain("Recorded new evidence");
			expect(factText).toContain("[FACT]");
			expect(factRes.details?.record?.id).toMatch(/^ev_fact_/);
			const factId = factRes.details!.record!.id;

			// 2. Add hypothesis grounded on fact
			const hypRes = await tool.execute("call-2", {
				action: "add",
				kind: "hypothesis",
				target: "sample.apk",
				claim: "Hooking isPro() to return true bypasses activation dialog",
				verificationPlan: "Deploy Frida script hooking isPro() and check if UI unlocks",
				facts: [factId],
				classification: "CWE-602",
			});

			const hypText = textOf(hypRes);
			expect(hypText).toContain("[HYPOTHESIS]");
			expect(hypRes.details?.record?.id).toMatch(/^ev_hyp_/);
			const hypId = hypRes.details!.record!.id;

			// 3. Verify hypothesis into conclusion
			const verifyRes = await tool.execute("call-3", {
				action: "verify",
				hypothesisId: hypId,
				method: "Frida runtime hook",
				command: "frida -U -f com.example -l hook.js",
				result: "App booted into unlocked dashboard state with License: Active",
				conclusion: "Confirmed: Hooking isPro() completely bypasses client license dialog",
				reproducibility: "100% (5/5 runs)",
			});

			const verifyText = textOf(verifyRes);
			expect(verifyText).toContain("Verified hypothesis and established conclusion");
			expect(verifyText).toContain("[CONCLUSION]");
			expect(verifyRes.details?.record?.id).toMatch(/^ev_conc_/);
			const concId = verifyRes.details!.record!.id;

			// 4. Show conclusion and verify links
			const showConcRes = await tool.execute("call-4", {
				action: "show",
				id: concId,
			});
			const showConcText = textOf(showConcRes);
			expect(showConcText).toContain(concId);
			expect(showConcText).toContain(hypId);
			expect(showConcText).toContain("Frida runtime hook");
			expect(showConcText).toContain("Integrity: Target hash verified");

			// 5. Show hypothesis: status should now be VERIFIED linking to conclusion
			const showHypRes = await tool.execute("call-5", {
				action: "show",
				id: hypId,
			});
			const showHypText = textOf(showHypRes);
			expect(showHypText).toContain("Status: VERIFIED");
			expect(showHypText).toContain(concId);

			// 6. List records
			const listRes = await tool.execute("call-6", { action: "list" });
			const listText = textOf(listRes);
			expect(listText).toContain(factId);
			expect(listText).toContain(hypId);
			expect(listText).toContain(concId);
			expect(listRes.details?.list?.total).toBe(3);

			// 7. Filter list by kind
			const listFacts = await tool.execute("call-7", { action: "list", kind: "fact" });
			expect(listFacts.details?.list?.total).toBe(1);
			expect(listFacts.details?.list?.items[0].id).toBe(factId);

			// Verify source repository was not polluted
			const projectEntries = await fs.readdir(projectDir);
			expect(projectEntries).toEqual(["sample.apk"]);
		} finally {
			await removeWithRetries(projectDir);
			await removeWithRetries(stateDir);
		}
	});
});

describe("rejection of direct conclusion on add", () => {
	it("strictly forbids adding conclusion via action: add", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-forbid-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvidenceTool(session);

			await expect(
				tool.execute("call-err", {
					action: "add",
					kind: "conclusion",
					title: "Forged conclusion",
					conclusion: "Fake verified claim",
				}),
			).rejects.toThrow("Directly adding a 'conclusion' is forbidden");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("hash drift and excerpt integrity detection", () => {
	it("detects modification to target file and excerpt drift", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-drift-proj-"));
		try {
			const targetPath = path.join(projectDir, "target.c");
			const originalContent = "int check_license() {\n    return 0; // target check\n}\n";
			await fs.writeFile(targetPath, originalContent);

			const session = createTestSession(projectDir);
			const tool = new EvidenceTool(session);

			const addRes = await tool.execute("call-1", {
				action: "add",
				kind: "fact",
				target: "target.c",
				sourceTool: "read",
				locator: "line 2",
				content: "check_license returns 0",
				excerpt: "return 0; // target check",
			});
			const factId = addRes.details!.record!.id;

			// Initial show: integrity intact
			const show1 = await tool.execute("call-2", { action: "show", id: factId });
			expect(textOf(show1)).toContain("Integrity: Target hash verified");
			expect(show1.details?.drift?.targetDrift).toBeFalsy();

			// Mutate target file
			await fs.writeFile(targetPath, "int check_license() {\n    return 1; // patched check\n}\n");

			// Show after mutation: target drift & excerpt drift detected
			const show2 = await tool.execute("call-3", { action: "show", id: factId });
			const text2 = textOf(show2);
			expect(text2).toContain("DRIFT WARNINGS");
			expect(text2).toContain("Target file 'target.c' has changed");
			expect(text2).toContain("Excerpt text is no longer found in 'target.c'");
			expect(show2.details?.drift?.targetDrift).toBe(true);
			expect(show2.details?.drift?.excerptDrift).toBe(true);

			// Delete target file: missing target detected
			await fs.unlink(targetPath);
			const show3 = await tool.execute("call-4", { action: "show", id: factId });
			const text3 = textOf(show3);
			expect(text3).toContain("Target file 'target.c' does not exist on disk");
			expect(show3.details?.drift?.targetMissing).toBe(true);
		} finally {
			await removeWithRetries(projectDir);
		}
	});
});

describe("project isolation", () => {
	it("keeps evidence completely isolated between different projects", async () => {
		const projA = await fs.mkdtemp(path.join(os.tmpdir(), "ev-proj-a-"));
		const projB = await fs.mkdtemp(path.join(os.tmpdir(), "ev-proj-b-"));
		try {
			const toolA = new EvidenceTool(createTestSession(projA));
			const toolB = new EvidenceTool(createTestSession(projB));

			await toolA.execute("call-a", {
				action: "add",
				kind: "fact",
				sourceTool: "triage",
				locator: "offset 0x100",
				content: "Observation unique to Project A",
			});

			const listA = await toolA.execute("call-la", { action: "list" });
			const listB = await toolB.execute("call-lb", { action: "list" });

			expect(listA.details?.list?.total).toBe(1);
			expect(listB.details?.list?.total).toBe(0);
		} finally {
			await removeWithRetries(projA);
			await removeWithRetries(projB);
		}
	});
});

describe("concurrency and append-only integrity", () => {
	it("handles concurrent writes safely under file locking", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-concur-"));
		try {
			const session = createTestSession(projectDir);
			const tool = new EvidenceTool(session);

			// Fire 8 concurrent adds
			const promises = Array.from({ length: 8 }, (_, i) =>
				tool.execute(`call-${i}`, {
					action: "add",
					kind: "fact",
					sourceTool: "triage",
					locator: `line ${i}`,
					content: `Concurrent entry #${i}`,
				}),
			);

			const results = await Promise.all(promises);
			expect(results).toHaveLength(8);

			const listRes = await tool.execute("call-check", { action: "list", limit: 50 });
			expect(listRes.details?.list?.total).toBe(8);
		} finally {
			await removeWithRetries(projectDir);
		}
	});
});

describe("credential redaction and boundary checks", () => {
	it("redacts sensitive tokens in recorded content", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-redact-"));
		try {
			const session = createTestSession(projectDir);
			const tool = new EvidenceTool(session);

			const addRes = await tool.execute("call-1", {
				action: "add",
				kind: "fact",
				sourceTool: "strings",
				locator: "offset 0x500",
				content:
					"Found token: ghp_111122223333444455556666777788889999 and https://admin:secretPass123@api.internal/v1",
			});

			const rec = addRes.details!.record!;
			expect(rec.kind).toBe("fact");
			if (rec.kind === "fact") {
				expect(rec.content).not.toContain("ghp_111122223333444455556666777788889999");
				expect(rec.content).not.toContain("secretPass123");
				expect(rec.content).toContain("[REDACTED]");
			}
		} finally {
			await removeWithRetries(projectDir);
		}
	});

	it("rejects invalid input and enforces required fields", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-bounds-"));
		try {
			const session = createTestSession(projectDir);
			const tool = new EvidenceTool(session);

			// Missing kind
			await expect(tool.execute("c1", { action: "add" })).rejects.toThrow("Parameter 'kind' is required");

			// Fact missing locator
			await expect(
				tool.execute("c2", { action: "add", kind: "fact", sourceTool: "read", content: "data" }),
			).rejects.toThrow("Field 'locator' is required");

			// Hypothesis missing verificationPlan
			await expect(tool.execute("c3", { action: "add", kind: "hypothesis", claim: "some claim" })).rejects.toThrow(
				"Field 'verificationPlan' is required",
			);

			// Verify nonexistent hypothesis
			await expect(
				tool.execute("c4", {
					action: "verify",
					hypothesisId: "ev_hyp_nonexistent",
					method: "m",
					command: "c",
					result: "r",
					conclusion: "c",
				}),
			).rejects.toThrow("not found in evidence ledger");
		} finally {
			await removeWithRetries(projectDir);
		}
	});
});

describe("export action", () => {
	it("exports reverse-lab evidence markdown conforming to schema", async () => {
		const projectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ev-export-"));
		try {
			const session = createTestSession(projectDir, { allocateArtifact: true });
			const tool = new EvidenceTool(session);

			const factRes = await tool.execute("c1", {
				action: "add",
				kind: "fact",
				target: "sample.bin",
				sourceTool: "r2_inspect",
				locator: "0x401000",
				content: "XOR decryption loop unrolled",
				excerpt: "xor eax, 0x5a",
			});
			const factId = factRes.details!.record!.id;

			const hypRes = await tool.execute("c2", {
				action: "add",
				kind: "hypothesis",
				target: "sample.bin",
				claim: "Payload decrypted with fixed key 0x5a produces C2 configuration",
				verificationPlan: "Emulate loop with radare2 and verify JSON header in decrypted memory",
				facts: [factId],
			});
			const hypId = hypRes.details!.record!.id;

			await tool.execute("c3", {
				action: "verify",
				hypothesisId: hypId,
				method: "Emulation trace",
				command: "r2 -qc 'aes; aer;' sample.bin",
				result: 'Decrypted buffer starts with {"c2":"https://..."}',
				conclusion: "Confirmed: XOR 0x5a decrypts internal C2 config block",
			});

			// Inline export
			const exportRes = await tool.execute("c4", { action: "export" });
			const exportText = textOf(exportRes);
			expect(exportText).toContain("# Evidence Artifact:");
			expect(exportText).toContain("## Finding 1:");
			expect(exportText).toContain("### 1. Target Metadata");
			expect(exportText).toContain("### 2. Evidence Chain");
			expect(exportText).toContain("#### [FACT] Observable Ground Truth");
			expect(exportText).toContain("#### [HYPOTHESIS] Working Hypothesis");
			expect(exportText).toContain("#### [EXPERIMENT] Verification Procedure");
			expect(exportText).toContain("#### [CONCLUSION] Verified Result");

			// Artifact export
			const artifactRes = await tool.execute("c5", { action: "export", to_artifact: true });
			const artifactText = textOf(artifactRes);
			expect(artifactText).toContain("Exported evidence artifact");
			expect(artifactText).toContain("artifact://");
			expect(artifactRes.details?.artifactId).toBeDefined();
		} finally {
			await removeWithRetries(projectDir);
		}
	});
});
