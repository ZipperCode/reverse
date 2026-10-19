import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { TextContent, ImageContent } from "@reverse/ai";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ReverseKnowledgeTool, ReverseWorkflowTool, EvidenceTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";
import { EvidenceStore } from "@reverse/coding-agent/evidence/store";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow/store";
import { ReverseKnowledgeStore } from "@reverse/coding-agent/reverse-knowledge/store";
import { MnemopiKnowledgeBridge } from "@reverse/coding-agent/reverse-knowledge/bridge";
import type { MnemopiSessionState } from "@reverse/coding-agent/mnemopi/state";

function createTestSession(cwd: string, options: { mnemopi?: boolean } = {}): ToolSession {
	const fakeMnemopiMemories: Array<{ id: string; content: string; metadata?: Record<string, unknown> }> = [];
	let idCounter = 1;

	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		getMnemopiSessionState: options.mnemopi
			? () =>
					({
						rememberInScope: (content: string, opts?: { metadata?: Record<string, unknown> }) => {
							const id = `mem-${idCounter++}`;
							fakeMnemopiMemories.push({ id, content, metadata: opts?.metadata });
							return id;
						},
						recallResultsScoped: async (query: string) => {
							const lower = query.toLowerCase();
							return fakeMnemopiMemories
								.filter(
									m => m.content.toLowerCase().includes(lower) || m.content.includes("[REVERSE_KNOWLEDGE]"),
								)
								.map(m => ({
									id: m.id,
									content: m.content,
									score: 0.85,
									metadata: m.metadata,
								}));
						},
					}) as unknown as MnemopiSessionState
			: undefined,
	};
}

function textOf(result: { content: (TextContent | ImageContent)[] }): string {
	return result.content
		.flatMap(item => (item.type === "text" ? [item.text] : []))
		.join("\n")
		.trim();
}

describe("reverse_knowledge tool registration and contracts", () => {
	it("is registered as a builtin discoverable tool", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("reverse_knowledge");
		expect(normalizeToolName("reverse_knowledge")).toBe("reverse_knowledge");
		expect(normalizeToolName("reverse-knowledge")).toBe("reverse_knowledge");
		expect(normalizeToolName("rev_knowledge")).toBe("reverse_knowledge");
		expect(normalizeToolName("knowledge_store")).toBe("reverse_knowledge");

		const session = createTestSession(process.cwd());
		const tool = new ReverseKnowledgeTool(session);
		expect(tool.name).toBe("reverse_knowledge");
		expect(tool.loadMode).toBe("discoverable");
		expect(tool.strict).toBe(true);
	});
});

describe("reverse_knowledge retain and verification safety", () => {
	it("retains verified conclusions with valid fields", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			const result = await tool.execute("call-1", {
				action: "retain",
				title: "RC4 Encryption Function in PE .text Section",
				kind: "verified_conclusion",
				format: "PE",
				tool: "r2_inspect",
				confidence: "high",
				summary: "sub_140012000 initializes 256-byte S-box array with state permutation matching RC4 KSA.",
				actionable_guidance: "When decrypting C2 payloads, call RC4 with key found at offset 0x3010.",
			});

			const text = textOf(result);
			expect(text).toContain("Retained verified reverse knowledge");
			expect(text).toContain("kn_rev_");
			expect(text).toContain("RC4 Encryption Function in PE .text Section");

			expect(result.details.record).toBeDefined();
			expect(result.details.record?.kind).toBe("verified_conclusion");
			expect(result.details.record?.target_format).toBe("PE");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("retains recovery patterns", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			const result = await tool.execute("call-2", {
				action: "retain",
				title: "Fallback from droidasc to android_package_inspect on corrupted DEX",
				kind: "recovery_pattern",
				format: "APK",
				tool: "droidasc",
				confidence: "high",
				summary:
					"droidasc failed with invalid_format when Dalvik bytecode had non-standard header; android_package_inspect parsed manifests successfully.",
				pattern: "category:invalid_format;previous_tool:droidasc;fallback_tool:android_package_inspect",
				actionable_guidance: "Use android_package_inspect when droidasc crashes on packed APKs.",
			});

			expect(result.details.record?.kind).toBe("recovery_pattern");
			expect(result.details.record?.tool).toBe("droidasc");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("strictly rejects unverified hypotheses and unknowns from being retained as facts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir });
			const tool = new ReverseKnowledgeTool(session);

			// Add unverified hypothesis
			const unverifiedHyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				claim: "Function sub_1000 is likely an authentication bypass",
				verificationPlan: "Hook with frida and trace arguments",
			});

			// Add unverified unknown question
			const unknownEv = await evidenceStore.addUnknown({
				kind: "unknown",
				question: "What encryption key protects payload.dat?",
			});

			// Try to retain knowledge backed by unverified hypothesis -> MUST FAIL
			await expect(
				tool.execute("call-hyp", {
					action: "retain",
					title: "Unverified Hypothesis as Knowledge",
					kind: "verified_conclusion",
					format: "ELF",
					summary: "Suspected bypass logic",
					source_evidence_ids: [unverifiedHyp.id],
				}),
			).rejects.toThrow("Cannot promote unverified hypothesis");

			// Try to retain knowledge backed by unknown question -> MUST FAIL
			await expect(
				tool.execute("call-unk", {
					action: "retain",
					title: "Unknown question as Knowledge",
					kind: "verified_conclusion",
					format: "ELF",
					summary: "Uncertain key details",
					source_evidence_ids: [unknownEv.id],
				}),
			).rejects.toThrow("Cannot retain knowledge derived from unverified unknown question");

			// Try to retain with low confidence -> MUST FAIL
			await expect(
				tool.execute("call-low", {
					action: "retain",
					title: "Low confidence claim",
					kind: "verified_conclusion",
					format: "ELF",
					summary: "Tentative guess without proof",
					confidence: "low",
				}),
			).rejects.toThrow("Cannot retain knowledge with 'low' confidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("allows retention when hypothesis is verified by conclusion in evidence ledger", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir });
			const tool = new ReverseKnowledgeTool(session);

			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				claim: "sub_1000 validates license key",
				verificationPlan: "Hook with frida",
			});

			const conc = await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "Dynamic memory inspection via Frida",
				command: "frida -n target -l hook.js",
				result: "Returning 1 bypassed registration check",
				conclusion: "sub_1000 is confirmed license gate",
				status: "verified",
			});

			// Retain referencing verified conclusion and hypothesis -> SUCCESS
			const res = await tool.execute("call-verified", {
				action: "retain",
				title: "License check bypass at sub_1000",
				kind: "verified_conclusion",
				format: "PE",
				summary: "sub_1000 returns 0 on failure, 1 on valid license.",
				source_evidence_ids: [conc.id, hyp.id],
			});

			expect(res.details.record?.id).toBeDefined();
			expect(res.details.record?.source_evidence_ids).toContain(conc.id);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_knowledge search and apply", () => {
	it("performs bounded search by query, format, and hash", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			// Add multiple records
			for (let i = 1; i <= 8; i++) {
				await tool.execute(`init-${i}`, {
					action: "retain",
					title: `Finding ${i}: AES decryption key in PE sample`,
					kind: "verified_conclusion",
					format: "PE",
					target_hash: "a".repeat(64),
					summary: `Verified AES-256-CBC round key #${i} at offset 0x${(i * 1000).toString(16)}`,
					actionable_guidance: `Use key #${i} to decrypt block ${i}`,
				});
			}

			// Add ELF record
			await tool.execute("init-elf", {
				action: "retain",
				title: "ELF OpenSSL symbol resolution",
				kind: "verified_conclusion",
				format: "ELF",
				summary: "EVP_DecryptInit_ex imported dynamically via dlsym",
			});

			// Default search limit is bounded to 5
			const searchDefault = await tool.execute("search-1", {
				action: "search",
				format: "PE",
			});
			expect(searchDefault.details.records?.length).toBe(5);

			// Search with query filter
			const searchElf = await tool.execute("search-2", {
				action: "search",
				query: "OpenSSL",
			});
			expect(searchElf.details.records?.length).toBe(1);
			expect(searchElf.details.records?.[0].target_format).toBe("ELF");

			// Search with target hash filter
			const searchHash = await tool.execute("search-3", {
				action: "search",
				target_hash: "a".repeat(64),
				limit: 10,
			});
			expect(searchHash.details.records?.length).toBe(8);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("applies matching knowledge and provides actionable recommendations", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			await tool.execute("init-rec", {
				action: "retain",
				title: "Timeout recovery for r2_inspect on stripped binaries",
				kind: "recovery_pattern",
				format: "ELF",
				tool: "r2_inspect",
				summary:
					"r2_inspect timed out during full analysis 'aaa'; scope reduction to 'aa' and targeted function analysis succeeded.",
				actionable_guidance: "Adjust params: use 'aa' instead of 'aaa' when target is > 5MB.",
				params: JSON.stringify({ analysis_level: "aa" }),
			});

			const applyRes = await tool.execute("apply-1", {
				action: "apply",
				format: "ELF",
				tool: "r2_inspect",
				error: "timeout",
			});

			const recs = applyRes.details.apply_result?.recommendations;
			expect(recs).toBeDefined();
			expect(recs?.length).toBeGreaterThan(0);
			expect(recs?.[0].guidance).toContain("Adjust params");
			expect(recs?.[0].suggested_params).toBeDefined();
			expect(applyRes.details.apply_result?.knowledge_refs.length).toBeGreaterThan(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_knowledge learn action", () => {
	it("automatically learns from verified conclusions in EvidenceStore and successful workflow recoveries", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceStore = new EvidenceStore({ repositoryRoot: tempDir });
			const workflowStore = new ReverseWorkflowStore({ repositoryRoot: tempDir });
			const tool = new ReverseKnowledgeTool(session);

			// 1. Add unverified hypothesis (should be skipped)
			await evidenceStore.addHypothesis({
				kind: "hypothesis",
				claim: "Unverified hypothesis claim",
				verificationPlan: "test",
			});

			// 2. Add verified hypothesis + conclusion (should be learned)
			const hyp = await evidenceStore.addHypothesis({
				kind: "hypothesis",
				claim: "AES key is 32 bytes at 0x4020",
				verificationPlan: "dump memory",
			});
			await evidenceStore.verifyHypothesis({
				hypothesisId: hyp.id,
				method: "gdb memory dump",
				command: "x/32bx 0x4020",
				result: "32 bytes matched known AES key",
				conclusion: "AES key confirmed at 0x4020",
				status: "verified",
			});

			// 3. Add workflow with successful recovery audit (should be learned)
			const now = new Date().toISOString();
			await workflowStore.save({
				id: "wf_rw_learn_test",
				target: "sample.apk",
				target_sha256: "b".repeat(64),
				format: "APK",
				status: "completed",
				created_at: now,
				updated_at: now,
				steps: [
					{
						id: "step_1",
						title: "Inspect APK packages",
						tool: "android_package_inspect",
						gate: "G1",
						params_summary: "{}",
						status: "completed",
						attempts: 2,
						max_attempts: 3,
						recovery_metadata: {
							recovery_audit: [
								{
									attempt: 2,
									timestamp: now,
									action: "recover",
									category: "missing_dependency",
									cause: "droidasc binary not found in PATH",
									previous_tool: "droidasc",
									proposed_tool: "android_package_inspect",
									proposed_params: { target: "sample.apk" },
									decision: "Switched to native fallback tool",
									applied: true,
								},
							],
						},
						created_at: now,
						updated_at: now,
					},
				],
			});

			// Run learn
			const learnRes = await tool.execute("learn-1", { action: "learn" });
			const stats = learnRes.details.learn_result;

			expect(stats?.learned_conclusions).toBe(1);
			expect(stats?.learned_recoveries).toBe(1);
			expect(stats?.skipped_unverified).toBeGreaterThanOrEqual(1);
			expect(stats?.created_records.length).toBe(2);

			// Running learn again should not duplicate
			const learnRes2 = await tool.execute("learn-2", { action: "learn" });
			expect(learnRes2.details.learn_result?.created_records.length).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow and reverse_knowledge integration", () => {
	it("reverse_workflow create and plan automatically retrieve and surface prior knowledge", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const knowledgeTool = new ReverseKnowledgeTool(session);
			const workflowTool = new ReverseWorkflowTool(session);

			// Retain prior knowledge for ELF
			await knowledgeTool.execute("pre-retain", {
				action: "retain",
				title: "ELF Stripped Binary Symbol Recovery via DWARF",
				kind: "verified_conclusion",
				format: "ELF",
				summary: "Found separate debug info file .gnu_debuglink matching build ID.",
				actionable_guidance: "Load debug symbols from /usr/lib/debug before disassembling.",
			});

			// Create a dummy ELF target
			const elfPath = path.join(tempDir, "target.elf");
			const elfBuf = Buffer.alloc(128);
			elfBuf[0] = 0x7f;
			elfBuf[1] = 0x45; // E
			elfBuf[2] = 0x4c; // L
			elfBuf[3] = 0x46; // F
			await fs.writeFile(elfPath, elfBuf);

			// Plan workflow: should surface prior knowledge
			const planRes = await workflowTool.execute("plan-1", {
				action: "plan",
				target: "target.elf",
			});
			const planText = textOf(planRes);
			expect(planText).toContain("Prior Knowledge");
			expect(planText).toContain("ELF Stripped Binary Symbol Recovery");
			expect(planRes.details.knowledge_refs?.length).toBeGreaterThan(0);

			// Create workflow: should attach knowledge_refs to workflow
			const createRes = await workflowTool.execute("create-1", {
				action: "create",
				target: "target.elf",
				goal: "Recover symbols",
			});
			const createText = textOf(createRes);
			expect(createText).toContain("Prior Knowledge");
			expect(createRes.details.workflow?.knowledge_refs?.length).toBeGreaterThan(0);

			// Status workflow: should report knowledge references
			const workflow = createRes.details.workflow;
			if (!workflow) throw new Error("workflow missing");
			const wfId = workflow.id;
			const statusRes = await workflowTool.execute("status-1", {
				action: "status",
				workflow_id: wfId,
			});
			const statusText = textOf(statusRes);
			expect(statusText).toContain("Knowledge References");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reverse_workflow record validates and links knowledge_refs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir);
			const knowledgeTool = new ReverseKnowledgeTool(session);
			const workflowTool = new ReverseWorkflowTool(session);

			const knRes = await knowledgeTool.execute("kn-1", {
				action: "retain",
				title: "Confirmed Buffer Overflow in recv_payload",
				kind: "verified_conclusion",
				format: "PE",
				summary: "memcpy at 0x401080 lacks bounds check on packet size parameter.",
			});
			const knRecord = knRes.details.record;
			if (!knRecord) throw new Error("knRecord missing");
			const knId = knRecord.id;

			// Create workflow
			const pePath = path.join(tempDir, "vuln.exe");
			const peBuf = Buffer.alloc(128);
			peBuf[0] = 0x4d; // M
			peBuf[1] = 0x5a; // Z
			peBuf.writeUInt32LE(0x40, 0x3c);
			peBuf[0x40] = 0x50; // P
			peBuf[0x41] = 0x45; // E
			await fs.writeFile(pePath, peBuf);

			const createRes = await workflowTool.execute("create-wf", {
				action: "create",
				target: "vuln.exe",
			});
			const createdWf = createRes.details.workflow;
			if (!createdWf) throw new Error("created workflow missing");
			const wfId = createdWf.id;

			// Record step with invalid knowledge ID format -> should throw
			await expect(
				workflowTool.execute("record-bad-format", {
					action: "record",
					workflow_id: wfId,
					step_id: "pe_step_1",
					status: "completed",
					knowledge_refs: ["bad_id_123"],
				}),
			).rejects.toThrow("Invalid knowledge ID format");

			// Record step with non-existent knowledge ID -> should throw
			await expect(
				workflowTool.execute("record-nonexistent", {
					action: "record",
					workflow_id: wfId,
					step_id: "pe_step_1",
					status: "completed",
					knowledge_refs: ["kn_rev_nonexistent12"],
				}),
			).rejects.toThrow("not found in the project reverse knowledge store");

			// Record step with valid knowledge ID -> should succeed
			const recordRes = await workflowTool.execute("record-valid", {
				action: "record",
				workflow_id: wfId,
				step_id: "pe_step_1",
				status: "completed",
				knowledge_refs: [knId],
			});
			expect(recordRes.details.step?.knowledge_refs).toContain(knId);
			expect(recordRes.details.workflow?.knowledge_refs).toContain(knId);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_knowledge and Mnemopi bridge", () => {
	it("retains to Mnemopi when Mnemopi session state is available", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-test-"));
		try {
			const session = createTestSession(tempDir, { mnemopi: true });
			expect(MnemopiKnowledgeBridge.isAvailable(session)).toBe(true);

			const tool = new ReverseKnowledgeTool(session);
			const retainRes = await tool.execute("retain-mnemopi", {
				action: "retain",
				title: "WASM Exported Table Function Offsets",
				kind: "verified_conclusion",
				format: "WASM",
				summary: "Table 0 index 4 points to cryptographic hash verification function.",
			});

			expect(retainRes.details.record).toBeDefined();

			// Recall from Mnemopi via bridge
			const hits = await MnemopiKnowledgeBridge.recall("WASM Exported Table", session);
			expect(hits.length).toBeGreaterThan(0);
			expect(hits[0].content).toContain("[REVERSE_KNOWLEDGE]");
			expect(hits[0].content).toContain("WASM Exported Table Function Offsets");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_knowledge quality governance and lifecycle", () => {
	it("detects duplicates deterministically with canonical fingerprints during audit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-audit-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			// Create primary record
			const r1 = await tool.execute("r1", {
				action: "retain",
				title: "RC4 Decryption Key Extraction in PE Sample",
				kind: "verified_conclusion",
				format: "PE",
				tool: "r2_inspect",
				target_hash: "abcd".repeat(16),
				summary: "Found hardcoded 16-byte RC4 key at offset 0x401000",
				confidence: "high",
			});
			const r1Record = r1.details.record;
			if (!r1Record) throw new Error("r1 record missing");
			const id1 = r1Record.id;

			// Create duplicate record with identical normalized tokens and properties
			const r2 = await tool.execute("r2", {
				action: "retain",
				title: "RC4 Decryption Key Extraction in PE Sample",
				kind: "verified_conclusion",
				format: "PE",
				tool: "r2_inspect",
				target_hash: "abcd".repeat(16),
				summary: "Duplicate finding: RC4 key at offset 0x401000",
				confidence: "medium",
			});
			const r2Record = r2.details.record;
			if (!r2Record) throw new Error("r2 record missing");
			const id2 = r2Record.id;

			// Create distinct record
			await tool.execute("r3", {
				action: "retain",
				title: "Dynamic TLS Callback Table in PE Sample",
				kind: "verified_conclusion",
				format: "PE",
				tool: "triage",
				summary: "TLS callback entry registered at 0x402000",
				confidence: "high",
			});

			const auditRes = await tool.execute("audit-1", {
				action: "audit",
			});

			const audit = auditRes.details.audit_result;
			expect(audit).toBeDefined();
			expect(audit?.total_records).toBe(3);
			expect(audit?.duplicate_count).toBe(1);
			expect(audit?.duplicate_groups.length).toBe(1);
			const dupGroup = audit?.duplicate_groups[0];
			if (!dupGroup) throw new Error("duplicate group missing");
			expect(dupGroup.primary_id).toBe(id1);
			expect(dupGroup.duplicate_ids).toContain(id2);
			expect(textOf(auditRes)).toContain("Duplicate Groups");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("merges duplicate records into primary target without destructive deletion", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-merge-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			const primary = await tool.execute("r-prim", {
				action: "retain",
				title: "AES key schedule analysis",
				kind: "verified_conclusion",
				format: "ELF",
				tool: "r2_inspect",
				summary: "Primary analysis of AES-128 key schedule at .rodata",
				confidence: "medium",
				source_evidence_ids: ["ev_conc_aaa111"],
			});
			const primaryRecord = primary.details.record;
			if (!primaryRecord) throw new Error("primaryRecord missing");
			const primaryId = primaryRecord.id;

			const duplicate = await tool.execute("r-dup", {
				action: "retain",
				title: "AES key schedule analysis",
				kind: "verified_conclusion",
				format: "ELF",
				tool: "r2_inspect",
				summary: "Corroborating analysis of AES key",
				confidence: "high", // Higher confidence should promote primary
				source_evidence_ids: ["ev_conc_bbb222"],
			});
			const duplicateRecord = duplicate.details.record;
			if (!duplicateRecord) throw new Error("duplicateRecord missing");
			const duplicateId = duplicateRecord.id;

			const mergeRes = await tool.execute("merge-1", {
				action: "merge",
				target_id: primaryId,
				source_ids: [duplicateId],
				reason: "Consolidation of duplicate key analysis findings",
			});

			const mergeResult = mergeRes.details.merge_result;
			if (!mergeResult) throw new Error("merge_result missing");
			expect(mergeResult.target_record.confidence).toBe("high");
			expect(mergeResult.target_record.source_evidence_ids).toContain("ev_conc_aaa111");
			expect(mergeResult.target_record.source_evidence_ids).toContain("ev_conc_bbb222");
			expect(mergeResult.target_record.merged_from).toContain(duplicateId);

			// Verify source record is NOT deleted, but marked merged
			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });
			const dupInStore = await store.get(duplicateId);
			expect(dupInStore).not.toBeNull();
			expect(dupInStore?.status).toBe("merged");
			expect(dupInStore?.merged_into).toBe(primaryId);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports and marks stale records when backing evidence is missing or refuted", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-stale-"));
		try {
			const session = createTestSession(tempDir);
			const evidenceTool = new EvidenceTool(session);
			const knowledgeTool = new ReverseKnowledgeTool(session);

			// Add hypothesis and refuted conclusion in evidence ledger
			const hypRes = await evidenceTool.execute("hyp-1", {
				action: "add",
				kind: "hypothesis",
				title: "Network socket creates plaintext connection",
				claim: "Target sends plaintext telemetry to port 8080",
				verificationPlan: "Check connect() disassembly",
			});
			const hypRecord = hypRes.details?.record;
			if (!hypRecord) throw new Error("hypRecord missing");
			const hypId = hypRecord.id;

			const refRes = await evidenceTool.execute("conc-refuted", {
				action: "verify",
				hypothesisId: hypId,
				method: "Disassembly inspection of connect()",
				command: "r2 -qc 'pdf @ sym.send_telemetry'",
				result: "connect() calls SSL_connect() before writing bytes",
				conclusion: "Connection is encrypted via TLS 1.3, claim refuted",
				reproducibility: "always",
				status: "refuted",
			});
			const refutedRecord = refRes.details?.record;
			if (!refutedRecord) throw new Error("refutedRecord missing");
			const refutedConcId = refutedRecord.id;
			expect(refutedConcId).toBeDefined();

			// Retain knowledge backed by the refuted conclusion
			const knRefuted = await knowledgeTool.execute("kn-ref", {
				action: "retain",
				title: "Plaintext telemetry egress",
				kind: "verified_conclusion",
				format: "ELF",
				summary: "Plaintext telemetry observed",
				source_evidence_ids: [refutedConcId],
			});
			const knRefutedRecord = knRefuted.details.record;
			if (!knRefutedRecord) throw new Error("knRefuted record missing");
			const knRefutedId = knRefutedRecord.id;

			// Retain knowledge backed by a non-existent evidence ID
			const knMissing = await knowledgeTool.execute("kn-missing", {
				action: "retain",
				title: "Database master password in binary",
				kind: "verified_conclusion",
				format: "ELF",
				summary: "Master password string found",
				source_evidence_ids: ["ev_conc_nonexistent_999"],
			});
			const knMissingRecord = knMissing.details.record;
			if (!knMissingRecord) throw new Error("knMissing record missing");
			const knMissingId = knMissingRecord.id;

			// Run audit with mark_stale: true
			const auditRes = await knowledgeTool.execute("audit-stale", {
				action: "audit",
				mark_stale: true,
			});

			const audit = auditRes.details.audit_result;
			expect(audit).toBeDefined();
			expect(audit?.stale_records).toBe(2);

			const refutedFinding = audit?.findings.find(f => f.record_id === knRefutedId);
			expect(refutedFinding).toBeDefined();
			expect(refutedFinding?.type).toBe("stale_evidence");
			expect(refutedFinding?.reason).toContain("refuted");

			const missingFinding = audit?.findings.find(f => f.record_id === knMissingId);
			expect(missingFinding).toBeDefined();
			expect(missingFinding?.type).toBe("invalid_source");

			// Check store persistence of stale flag
			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });
			const recRefuted = await store.get(knRefutedId);
			expect(recRefuted?.stale).toBe(true);
			expect(recRefuted?.stale_reason).toBeDefined();
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports non-destructive expire and disable actions with audit reason", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-lifecycle-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			const r1 = await tool.execute("r1", {
				action: "retain",
				title: "Obsolete packing pattern for UPX 3.0",
				kind: "recovery_pattern",
				format: "PE",
				summary: "Legacy UPX stub recovery",
			});
			const r1Record = r1.details.record;
			if (!r1Record) throw new Error("r1 record missing");
			const id1 = r1Record.id;

			const r2 = await tool.execute("r2", {
				action: "retain",
				title: "Deprecated Frida hook script",
				kind: "recovery_pattern",
				format: "ELF",
				summary: "Hooks older glibc 2.27 symbol",
			});
			const r2Record = r2.details.record;
			if (!r2Record) throw new Error("r2 record missing");
			const id2 = r2Record.id;

			// Expire r1
			const expireRes = await tool.execute("exp-1", {
				action: "expire",
				knowledge_id: id1,
				reason: "Replaced by modern unpacker methodology",
			});
			expect(expireRes.details.expire_result?.expired_ids).toContain(id1);

			// Disable r2
			const disableRes = await tool.execute("dis-1", {
				action: "disable",
				knowledge_id: id2,
				reason: "Flaky hook crashing process",
			});
			expect(disableRes.details.disable_result?.disabled_ids).toContain(id2);

			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });
			const rec1 = await store.get(id1);
			expect(rec1?.status).toBe("expired");
			expect(rec1?.status_reason).toContain("Replaced by modern");

			const rec2 = await store.get(id2);
			expect(rec2?.status).toBe("disabled");
			expect(rec2?.status_reason).toContain("Flaky hook");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("excludes disabled, expired, and merged records during knowledge apply and exposes source/confidence", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-apply-filter-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			// 1. Active record with evidence link
			const rActive = await tool.execute("r-active", {
				action: "retain",
				title: "Active Verified SQLite schema structure",
				kind: "verified_conclusion",
				format: "SQLite",
				summary: "Verified database encryption is disabled; schema is in plaintext",
				confidence: "high",
				source_evidence_ids: ["ev_conc_active_123"],
			});
			const activeRecord = rActive.details.record;
			if (!activeRecord) throw new Error("activeRecord missing");
			const activeId = activeRecord.id;

			// 2. Expired record
			const rExpired = await tool.execute("r-exp", {
				action: "retain",
				title: "Expired SQLite schema notes",
				kind: "verified_conclusion",
				format: "SQLite",
				summary: "Old notes",
				confidence: "low",
			});
			const expiredRecord = rExpired.details.record;
			if (!expiredRecord) throw new Error("expiredRecord missing");
			await tool.execute("do-exp", { action: "expire", knowledge_id: expiredRecord.id });

			// 3. Disabled record
			const rDisabled = await tool.execute("r-dis", {
				action: "retain",
				title: "Disabled SQLite fallback",
				kind: "recovery_pattern",
				format: "SQLite",
				summary: "Disabled pattern",
			});
			const disabledRecord = rDisabled.details.record;
			if (!disabledRecord) throw new Error("disabledRecord missing");
			await tool.execute("do-dis", { action: "disable", knowledge_id: disabledRecord.id });

			// Apply knowledge for SQLite format
			const applyRes = await tool.execute("apply-sqlite", {
				action: "apply",
				format: "SQLite",
			});

			const applyResult = applyRes.details.apply_result;
			if (!applyResult) throw new Error("applyResult missing");
			expect(applyResult.knowledge_refs).toContain(activeId);
			expect(applyResult.knowledge_refs).not.toContain(expiredRecord.id);
			expect(applyResult.knowledge_refs).not.toContain(disabledRecord.id);

			const rec = applyResult?.recommendations.find(r => r.knowledge_id === activeId);
			expect(rec).toBeDefined();
			expect(rec?.source).toBe("evidence_ledger");
			expect(rec?.confidence).toBe("high");
			expect(rec?.status).toBe("active");

			// Check usage metadata increment
			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });
			const activeInStore = await store.get(activeId);
			expect(activeInStore?.usage_count).toBeGreaterThanOrEqual(1);
			expect(activeInStore?.last_used_at).toBeDefined();
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
