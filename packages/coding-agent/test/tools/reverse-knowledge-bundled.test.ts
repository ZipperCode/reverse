import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { TextContent, ImageContent } from "@reverse/ai";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ReverseKnowledgeTool, ReverseWorkflowTool, type ToolSession } from "@reverse/coding-agent/tools";
import { removeWithRetries } from "@reverse/utils";
import { ReverseKnowledgeStore } from "@reverse/coding-agent/reverse-knowledge/store";
import {
	BUNDLED_REVERSE_KNOWLEDGE_SEEDS,
	getBundledReverseKnowledgeRecords,
	getBundledReverseKnowledgeRecord,
	searchBundledReverseKnowledge,
} from "@reverse/coding-agent/reverse-knowledge/bundled";
import { validateKnowledgeIdFormat, type TargetFormat } from "@reverse/coding-agent/reverse-workflow/contracts";
function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function createPEFixture(dir: string, name = "sample.exe"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.alloc(256);
	buf[0] = 0x4d; // M
	buf[1] = 0x5a; // Z
	buf.writeUInt32LE(0x80, 0x3c); // PE header at 0x80
	buf.write("PE\0\0", 0x80, "ascii");
	await fs.writeFile(filePath, buf);
	return filePath;
}

function textOf(result: { content: (TextContent | ImageContent)[] }): string {
	return result.content
		.flatMap(item => (item.type === "text" ? [item.text] : []))
		.join("\n")
		.trim();
}

describe("bundled reverse knowledge seed catalog", () => {
	it("embeds a curated set of high-value baseline patterns across all supported formats", () => {
		expect(BUNDLED_REVERSE_KNOWLEDGE_SEEDS.length).toBeGreaterThanOrEqual(8);
		expect(BUNDLED_REVERSE_KNOWLEDGE_SEEDS.length).toBeLessThanOrEqual(25);

		const expectedFormats: readonly TargetFormat[] = ["PE", "ELF", "Mach-O", "APK", "JS", "WASM", "PCAP", "SQLite"];
		const foundFormats = new Set<TargetFormat>(BUNDLED_REVERSE_KNOWLEDGE_SEEDS.map(s => s.target_format));
		for (const fmt of expectedFormats) {
			expect(foundFormats.has(fmt)).toBe(true);
		}

		for (const seed of BUNDLED_REVERSE_KNOWLEDGE_SEEDS) {
			expect(seed.id.startsWith("kn_rev_")).toBe(true);
			expect(validateKnowledgeIdFormat(seed.id)).toBe(true);
			expect(seed.kind).toBe("recovery_pattern");
			expect(seed.source).toBe("bundled");
			expect(seed.confidence).toBe("medium");
			expect(seed.status).toBe("active");

			// Non-user-verified status
			expect(seed.metadata?.source).toBe("bundled");
			expect(seed.metadata?.user_verified).toBe(false);
			expect(seed.metadata?.baseline).toBe(true);
			expect(typeof seed.metadata?.topic === "string" && seed.metadata.topic.length > 0).toBe(true);

			// Must not claim project evidence IDs
			expect(seed.source_evidence_ids === undefined || seed.source_evidence_ids.length === 0).toBe(true);

			// Actionable guidance and pattern must be non-empty
			expect(seed.actionable_guidance).toBeDefined();
			expect(seed.actionable_guidance?.length ?? 0).toBeGreaterThan(10);
			expect(seed.pattern).toBeDefined();
			expect(seed.pattern?.length ?? 0).toBeGreaterThan(10);
		}
	});

	it("provides getter and search functions for bundled seeds", () => {
		const all = getBundledReverseKnowledgeRecords();
		expect(all.length).toBe(BUNDLED_REVERSE_KNOWLEDGE_SEEDS.length);

		const peSeed = getBundledReverseKnowledgeRecord("kn_rev_seed_pe_tls_anti_debug");
		expect(peSeed).toBeDefined();
		expect(peSeed?.target_format).toBe("PE");
		expect(peSeed?.metadata?.topic).toBe("anti_debug");

		const searched = searchBundledReverseKnowledge({ format: "APK" });
		expect(searched.length).toBeGreaterThanOrEqual(1);
		for (const rec of searched) {
			expect(rec.target_format).toBe("APK");
		}
	});
});

describe("reverse_knowledge tool fallback on fresh store", () => {
	it("falls back to bundled seeds on search when project store has no records", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-fresh-search-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			// 1. Search all on fresh store
			const resAll = await tool.execute("search-all", {
				action: "search",
			});
			const allRecords = resAll.details.records;
			if (!allRecords || allRecords.length === 0) throw new Error("resAll records missing");
			expect(allRecords.length).toBeGreaterThan(0);
			const first = allRecords[0];
			expect(first.source).toBe("bundled");
			expect(first.metadata?.source).toBe("bundled");
			expect(first.metadata?.user_verified).toBe(false);

			const outputText = textOf(resAll);
			expect(outputText).toContain("[BUNDLED SEED - UNVERIFIED]");
			expect(outputText).toContain("`bundled` (baseline template)");

			// 2. Search filtered by format PE
			const resPE = await tool.execute("search-pe", {
				action: "search",
				format: "PE",
			});
			const peRecords = resPE.details.records;
			if (!peRecords) throw new Error("resPE records missing");
			expect(peRecords.length).toBeGreaterThanOrEqual(2);
			for (const r of peRecords) {
				expect(r.target_format).toBe("PE");
				expect(r.source).toBe("bundled");
			}

			// 3. Search filtered by tool and query
			const resTool = await tool.execute("search-tool", {
				action: "search",
				tool: "sourcemap_inspect",
			});
			expect(resTool.details.records?.length).toBeGreaterThanOrEqual(1);
			expect(resTool.details.records?.[0].target_format).toBe("JS");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("falls back to bundled seeds on apply and returns marked recommendations without polluting disk", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-fresh-apply-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			const applyRes = await tool.execute("apply-pe", {
				action: "apply",
				format: "PE",
				tool: "r2_inspect",
			});

			const applyResult = applyRes.details.apply_result;
			expect(applyResult).toBeDefined();
			expect(applyResult?.recommendations.length).toBeGreaterThan(0);

			const rec = applyResult?.recommendations[0];
			expect(rec).toBeDefined();
			expect(rec?.source).toBe("bundled");
			expect(rec?.confidence).toBe("medium");
			expect(rec?.format).toBe("PE");
			expect(rec?.guidance.length).toBeGreaterThan(0);

			const outputText = textOf(applyRes);
			expect(outputText).toContain("[BUNDLED SEED - UNVERIFIED]");
			expect(outputText).toContain("`bundled` (baseline template)");

			// Ensure applying bundled knowledge did NOT create disk files in fresh project
			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });
			const diskRecords = await store.list();
			expect(diskRecords.length).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("prioritizes project records over bundled seeds when project records exist", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-priority-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseKnowledgeTool(session);

			// Retain a verified conclusion for PE in project store
			const retained = await tool.execute("retain-pe", {
				action: "retain",
				title: "Project-specific unpacked OEP for target binary",
				kind: "verified_conclusion",
				format: "PE",
				summary: "Tail jump jumps to 0x140001050; unpacked payload is plaintext",
				confidence: "high",
			});
			const retainedRecord = retained.details.record;
			if (!retainedRecord) throw new Error("retained record missing");
			const projectRecId = retainedRecord.id;

			// Search for PE: must return the project record, not bundled seeds
			const searchPE = await tool.execute("search-pe", {
				action: "search",
				format: "PE",
			});
			expect(searchPE.details.records?.length).toBe(1);
			expect(searchPE.details.records?.[0].id).toBe(projectRecId);
			expect(searchPE.details.records?.[0].confidence).toBe("high");
			expect(searchPE.details.records?.[0].source).not.toBe("bundled");

			// Search for unrepresented format (APK): project store has none for APK -> falls back to bundled seeds
			const searchAPK = await tool.execute("search-apk", {
				action: "search",
				format: "APK",
			});
			expect(searchAPK.details.records?.length).toBeGreaterThanOrEqual(1);
			expect(searchAPK.details.records?.[0].source).toBe("bundled");

			// include_bundled: false suppresses fallback
			const searchSuppressed = await tool.execute("search-suppressed", {
				action: "search",
				format: "APK",
				include_bundled: false,
			});
			expect(searchSuppressed.details.records?.length).toBe(0);

			// include_bundled: true combines project record and bundled seeds
			const searchCombined = await tool.execute("search-combined", {
				action: "search",
				format: "PE",
				include_bundled: true,
			});
			expect(searchCombined.details.records?.length).toBeGreaterThan(1);
			expect(searchCombined.details.records?.[0].id).toBe(projectRecId);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("allows direct store.get lookup of bundled seeds without failing validation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-kn-get-"));
		try {
			const store = new ReverseKnowledgeStore({ repositoryRoot: tempDir });

			// Direct lookup of bundled seed
			const seed = await store.get("kn_rev_seed_pe_tls_anti_debug");
			expect(seed).toBeDefined();
			expect(seed?.title).toContain("TLS Callback");
			expect(seed?.target_format).toBe("PE");
			expect(seed?.metadata?.source).toBe("bundled");

			// Lookup of nonexistent ID
			const missing = await store.get("kn_rev_non_existent_12345");
			expect(missing).toBeNull();
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow integration with bundled knowledge", () => {
	it("automatically queries and surfaces bundled seeds during workflow create on a fresh workspace", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-bundled-create-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);

			const createRes = await workflowTool.execute("wf-create-1", {
				action: "create",
				target,
				goal: "Decompile binary and check for anti-debugging routines",
			});

			expect(createRes.details.action).toBe("create");
			expect(createRes.details.workflow?.format).toBe("PE");

			// Workflow should automatically link matching bundled knowledge references
			const knRefs = createRes.details.knowledge_refs;
			expect(knRefs).toBeDefined();
			expect(knRefs?.length).toBeGreaterThan(0);
			expect(knRefs?.some(id => id.startsWith("kn_rev_seed_pe_"))).toBe(true);

			// Output should indicate bundled template
			const outputText = textOf(createRes);
			expect(outputText).toContain("[bundled template]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("allows workflow advance with bundled knowledge references without not-found errors", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-bundled-advance-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);

			const createRes = await workflowTool.execute("wf-create-2", {
				action: "create",
				target,
				goal: "Inspect PE TLS directory",
			});
			const workflow = createRes.details.workflow;
			if (!workflow || !workflow.steps[0]) throw new Error("workflow step missing");
			const workflowId = workflow.id;
			const firstStepId = workflow.steps[0].id;

			// Advance step with explicit bundled knowledge reference
			const advRes = await workflowTool.execute("wf-adv-1", {
				action: "advance",
				workflow_id: workflowId,
				step_id: firstStepId,
				status: "completed",
				outputs: "Dumped TLS callbacks via r2 'it'; no active debugger checks",
				knowledge_refs: ["kn_rev_seed_pe_tls_anti_debug"],
			});

			expect(advRes.details.advanced).toBe(true);
			expect(advRes.details.workflow?.steps[0].knowledge_refs).toContain("kn_rev_seed_pe_tls_anti_debug");
			expect(advRes.details.workflow?.knowledge_refs).toContain("kn_rev_seed_pe_tls_anti_debug");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("attaches bundled knowledge during auto_advance on low-risk static steps", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-bundled-autoadv-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);

			const createRes = await workflowTool.execute("wf-create-3", {
				action: "create",
				target,
			});
			const createdWf = createRes.details.workflow;
			if (!createdWf) throw new Error("created workflow missing");
			const workflowId = createdWf.id;

			// auto_advance low-risk static step
			const autoRes = await workflowTool.execute("wf-auto-1", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(autoRes.details.advanced).toBe(true);
			// Should query and link bundled prior knowledge
			expect(autoRes.details.knowledge_refs?.length).toBeGreaterThan(0);
			expect(autoRes.details.knowledge_refs?.some(id => id.startsWith("kn_rev_seed_pe_"))).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
