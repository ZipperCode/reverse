import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import {
	createTools,
	ReverseWorkflowTool,
	ReverseKnowledgeTool,
	EvidenceTool,
	type ToolSession,
	BUILTIN_TOOLS,
} from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";
import { ReverseWorkflowStore } from "@reverse/coding-agent/reverse-workflow/store";
import {
	classifyFailure,
	generateRecoveryPlan,
	resolveCapabilityRecovery,
	isBareNativeTarget,
	isApkTarget,
	isExplicitAndroidJniTarget,
} from "@reverse/coding-agent/reverse-workflow/recovery";
import type { ReverseWorkflowRecord, WorkflowStepRecord } from "@reverse/coding-agent/reverse-workflow/contracts";
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

function textOf(result: { content: Array<{ type: string; text?: string } | { type: string }> }): string {
	return result.content
		.map(item => ("text" in item && typeof item.text === "string" ? item.text : ""))
		.join("\n")
		.trim();
}

// ============================================================================
// Fixture Helpers
// ============================================================================

async function createPEFixture(dir: string, name = "sample.exe"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.alloc(256);
	buf[0] = 0x4d; // M
	buf[1] = 0x5a; // Z
	buf.writeUInt32LE(0x80, 0x3c); // PE header at 0x80
	buf[0x80] = 0x50; // P
	buf[0x81] = 0x45; // E
	buf[0x82] = 0x00;
	buf[0x83] = 0x00;
	await fs.writeFile(filePath, buf);
	return filePath;
}

async function createELFFixture(dir: string, name = "sample.elf"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

async function createMachOFixture(dir: string, name = "sample.dylib"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

async function createAPKFixture(dir: string, name = "sample.apk"): Promise<string> {
	const filePath = path.join(dir, name);
	const zipHeader = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
	const manifestContent = Buffer.from("AndroidManifest.xml classes.dex");
	await fs.writeFile(filePath, Buffer.concat([zipHeader, manifestContent]));
	return filePath;
}

async function createJSFixture(dir: string, name = "bundle.js"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, "console.log('App runtime loaded');", "utf8");
	return filePath;
}

async function createWASMFixture(dir: string, name = "module.wasm"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

async function createPCAPFixture(dir: string, name = "traffic.pcap"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

async function createSQLiteFixture(dir: string, name = "data.db"): Promise<string> {
	const filePath = path.join(dir, name);
	const header = Buffer.from("SQLite format 3\0");
	const rest = Buffer.alloc(84);
	await fs.writeFile(filePath, Buffer.concat([header, rest]));
	return filePath;
}

// ============================================================================
// Registration and Discovery
// ============================================================================

describe("reverse_workflow tool registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("reverse_workflow");
	});

	it("normalizes tool aliases to reverse_workflow", () => {
		expect(normalizeToolName("reverse_workflow")).toBe("reverse_workflow");
		expect(normalizeToolName("workflow")).toBe("reverse_workflow");
		expect(normalizeToolName("reverse_orchestrator")).toBe("reverse_workflow");
		expect(normalizeToolName("rev_workflow")).toBe("reverse_workflow");
	});

	it("instantiates via createTools and BUILTIN_TOOLS", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-reg-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["reverse_workflow"]);
			const tool = tools.find(t => t.name === "reverse_workflow");
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Reverse Engineering Workflow Orchestrator");
			expect(tool?.strict).toBe(true);

			const direct = BUILTIN_TOOLS.reverse_workflow(session);
			expect(direct).toBeInstanceOf(ReverseWorkflowTool);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("declares approval tier: write for mutating actions, read for query actions", () => {
		const session = createTestSession("/tmp");
		const tool = new ReverseWorkflowTool(session);
		expect(typeof tool.approval).toBe("function");

		if (typeof tool.approval === "function") {
			expect(tool.approval({ action: "create" })).toBe("write");
			expect(tool.approval({ action: "record" })).toBe("write");
			expect(tool.approval({ action: "retry" })).toBe("write");
			expect(tool.approval({ action: "recover" })).toBe("write");
			expect(tool.approval({ action: "destroy" })).toBe("write");
			expect(tool.approval({ action: "advance" })).toBe("write");
			expect(tool.approval({ action: "auto_advance" })).toBe("write");
			expect(tool.approval({ action: "plan" })).toBe("read");
			expect(tool.approval({ action: "status" })).toBe("read");
			expect(tool.approval({ action: "retry_plan" })).toBe("read");
			expect(tool.approval({ action: "export" })).toBe("read");
			expect(tool.approval({ action: "export", format_type: "markdown" })).toBe("read");
			expect(tool.approval({ action: "export", format_type: "json" })).toBe("read");
			expect(tool.approval({ action: "export", to_artifact: true })).toBe("read");
			expect(tool.approval({ action: "export", to_workspace: false })).toBe("read");
			expect(tool.approval({ action: "export", workspace_path: "" })).toBe("read");

			// Write-tier approval for workspace exports (both to_workspace and workspace_path)
			expect(tool.approval({ action: "export", to_workspace: true })).toBe("write");
			expect(tool.approval({ action: "export", workspace_path: "./custom-ws" })).toBe("write");
			expect(tool.approval({ action: "export", to_workspace: false, workspace_path: "./custom-ws" })).toBe("write");
			expect(tool.approval({ action: "export", to_workspace: true, workspace_path: "./custom-ws" })).toBe("write");
		}
	});
});

// ============================================================================
// Target-First Routing & Plan Generation (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite)
// ============================================================================

describe("reverse_workflow target-first routing and deterministic plans", () => {
	it("sniffs and plans PE binary targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-pe-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.action).toBe("plan");
			expect(res.details.plan?.format).toBe("PE");
			expect(res.details.plan?.steps).toHaveLength(4);

			const toolsUsed = res.details.plan?.steps.map(s => s.tool);
			expect(toolsUsed).toEqual(["triage", "binary_metadata_inspect", "r2_inspect", "evidence"]);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans ELF binary targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-elf-"));
		try {
			const target = await createELFFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("ELF");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("triage");
			expect(res.details.plan?.steps[1]?.tool).toBe("binary_metadata_inspect");
			expect(res.details.plan?.steps[2]?.tool).toBe("r2_inspect");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans Mach-O targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-macho-"));
		try {
			const target = await createMachOFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("Mach-O");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("triage");
			expect(res.details.plan?.steps[2]?.tool).toBe("r2_inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans Android APK targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-apk-"));
		try {
			const target = await createAPKFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("APK");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("android_package_inspect");
			expect(res.details.plan?.steps[1]?.tool).toBe("android_package_inspect");
			expect(res.details.plan?.steps[2]?.tool).toBe("droidasc");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("routes JavaScript and SourceMap targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-js-"));
		try {
			const target = await createJSFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("JS");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("sourcemap_inspect");
			expect(res.details.plan?.steps[1]?.tool).toBe("javascript_application");
			expect(res.details.plan?.steps[2]?.tool).toBe("grep");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans WebAssembly WASM targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-wasm-"));
		try {
			const target = await createWASMFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("WASM");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("wasm_inspect");
			expect(res.details.plan?.steps[1]?.tool).toBe("wasm_inspect");
			expect(res.details.plan?.steps[2]?.tool).toBe("wasm_inspect");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans PCAP packet capture targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-pcap-"));
		try {
			const target = await createPCAPFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("PCAP");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("pcap_inspect");
			expect(res.details.plan?.steps[1]?.tool).toBe("pcap_inspect");
			expect(res.details.plan?.steps[2]?.tool).toBe("pcap_inspect");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("sniffs and plans SQLite database targets", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-sqlite-"));
		try {
			const target = await createSQLiteFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", target });
			expect(res.details.plan?.format).toBe("SQLite");
			expect(res.details.plan?.steps).toHaveLength(4);
			expect(res.details.plan?.steps[0]?.tool).toBe("sqlite_inspect");
			expect(res.details.plan?.steps[1]?.tool).toBe("sqlite_inspect");
			expect(res.details.plan?.steps[2]?.tool).toBe("sqlite_inspect");
			expect(res.details.plan?.steps[3]?.tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports plan preview with explicit format override without target file on disk", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-plan-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const res = await tool.execute("call_plan", { action: "plan", format: "WASM", target: "virtual/app.wasm" });
			expect(res.details.plan?.format).toBe("WASM");
			expect(res.details.plan?.steps).toHaveLength(4);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Workflow Lifecycle: create, status, record, retry, export, destroy
// ============================================================================

describe("reverse_workflow lifecycle management", () => {
	it("executes complete lifecycle: create -> status -> record -> export -> destroy", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-life-"));
		try {
			const target = await createELFFixture(tempDir, "service.bin");
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// 1. Create
			const createRes = await tool.execute("call_create", {
				action: "create",
				target,
				goal: "Verify authentication bypass vulnerability",
			});
			const wf = createRes.details.workflow;
			expect(wf).toBeDefined();
			expect(wf?.status).toBe("active");
			expect(wf?.format).toBe("ELF");
			expect(wf?.steps).toHaveLength(4);
			expect(wf?.steps[0]?.status).toBe("pending");

			const workflowId = wf!.id;

			// 2. Status inspection
			const statusRes = await tool.execute("call_status", { action: "status", workflow_id: workflowId });
			expect(statusRes.details.metrics?.total_steps).toBe(4);
			expect(statusRes.details.metrics?.completed_steps).toBe(0);
			expect(statusRes.details.metrics?.pending_steps).toBe(4);
			expect(statusRes.details.metrics?.next_step?.id).toBe("elf_step_1");

			// 3. Record step 1 completed
			const rec1 = await tool.execute("call_rec1", {
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "completed",
				outputs: "ELF 64-bit LSB executable, x86-64, not stripped, 24 sections",
			});
			expect(rec1.details.step?.status).toBe("completed");
			expect(rec1.details.step?.attempts).toBe(1);
			expect(rec1.details.metrics?.completed_steps).toBe(1);
			expect(rec1.details.metrics?.next_step?.id).toBe("elf_step_2");

			// 4. Record step 2 skipped
			await tool.execute("call_rec2", {
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_2",
				status: "skipped",
				outputs: "No Go or Rust symbols detected; plain C binary",
			});

			// 5. Inspect single step status
			const stepStatus = await tool.execute("call_step_status", {
				action: "status",
				workflow_id: workflowId,
				step_id: "elf_step_1",
			});
			expect(stepStatus.details.step?.id).toBe("elf_step_1");
			expect(stepStatus.details.step?.status).toBe("completed");

			// 6. Export to Markdown
			const exportMd = await tool.execute("call_export_md", {
				action: "export",
				workflow_id: workflowId,
				format_type: "markdown",
			});
			const mdText = textOf(exportMd);
			expect(mdText).toContain(`# Reverse Engineering Workflow: ${workflowId}`);
			expect(mdText).toContain("Total Steps | Completed | Failed | Pending | Skipped");
			expect(mdText).toContain("[COMPLETED] elf_step_1");

			// 7. Export to JSON
			const exportJson = await tool.execute("call_export_json", {
				action: "export",
				workflow_id: workflowId,
				format_type: "json",
			});
			const parsedJson = JSON.parse(textOf(exportJson));
			expect(parsedJson.id).toBe(workflowId);
			expect(parsedJson.metrics.completed_steps).toBe(1);
			expect(parsedJson.metrics.skipped_steps).toBe(1);

			// 8. Destroy
			const destroyRes = await tool.execute("call_destroy", { action: "destroy", workflow_id: workflowId });
			expect(destroyRes.details.destroyed).toBe(true);

			// Confirm deleted
			await expect(tool.execute("call_status_err", { action: "status", workflow_id: workflowId })).rejects.toThrow(
				`Workflow '${workflowId}' not found.`,
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("lists all project workflows when workflow_id is omitted from status", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-list-"));
		try {
			const target1 = await createELFFixture(tempDir, "one.elf");
			const target2 = await createPEFixture(tempDir, "two.exe");
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			await tool.execute("call_create1", { action: "create", target: target1, id: "wf_test_1" });
			await tool.execute("call_create2", { action: "create", target: target2, id: "wf_test_2" });

			const listRes = await tool.execute("call_list", { action: "status" });
			expect(listRes.details.workflows).toHaveLength(2);
			const text = textOf(listRes);
			expect(text).toContain("wf_test_1");
			expect(text).toContain("wf_test_2");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Cross-Tool Evidence Ledger Association
// ============================================================================

describe("reverse_workflow cross-tool evidence association", () => {
	it("links existing evidence ledger records and hydrates them in export", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ev-"));
		try {
			const target = await createAPKFixture(tempDir, "client.apk");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const evidenceTool = new EvidenceTool(session);

			// Add a fact to the project evidence ledger
			const factRes = await evidenceTool.execute("fact-call", {
				action: "add",
				kind: "fact",
				target: "client.apk",
				sourceTool: "android_package_inspect",
				locator: "com.example.AuthActivity",
				content: "Discovered exported activity with android:exported='true'",
			});
			const factId = factRes.details?.record?.id;
			expect(factId).toBeDefined();

			// Create workflow
			const createRes = await workflowTool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Record step with linked evidence ID
			const recordRes = await workflowTool.execute("call_rec", {
				action: "record",
				workflow_id: workflowId,
				step_id: "apk_step_2",
				status: "completed",
				outputs: "Parsed AndroidManifest.xml: 3 exported activities found",
				evidence_ids: [factId!],
			});
			expect(recordRes.details.step?.evidence_ids).toContain(factId!);

			// Export to Markdown and confirm evidence hydration
			const exportRes = await workflowTool.execute("call_export_md", {
				action: "export",
				workflow_id: workflowId,
				format_type: "markdown",
			});
			const exportText = textOf(exportRes);
			expect(exportText).toContain(factId!);
			expect(exportText).toContain("com.example.AuthActivity");
			expect(exportText).toContain("Discovered exported activity");

			// Export to JSON and verify hydrated evidence
			const jsonRes = await workflowTool.execute("call_export_json", {
				action: "export",
				workflow_id: workflowId,
				format_type: "json",
			});
			const parsed = JSON.parse(textOf(jsonRes));
			const step2 = parsed.steps.find((s: { id: string }) => s.id === "apk_step_2");
			expect(step2.hydrated_evidence).toHaveLength(1);
			expect(step2.hydrated_evidence[0].id).toBe(factId);
			expect(step2.hydrated_evidence[0].record.locator).toBe("com.example.AuthActivity");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("strictly rejects linking invalid evidence ID formats", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ev-inv-"));
		try {
			const target = await createELFFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			await expect(
				tool.execute("call_rec_err", {
					action: "record",
					workflow_id: workflowId,
					step_id: "elf_step_1",
					status: "completed",
					evidence_ids: ["invalid_format_id"],
				}),
			).rejects.toThrow("Invalid evidence ID format: 'invalid_format_id'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("strictly rejects linking evidence IDs that do not exist in the evidence ledger", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ev-nonexist-"));
		try {
			const target = await createELFFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			const fakeId = "ev_fact_018f99999999";
			await expect(
				tool.execute("call_rec_err", {
					action: "record",
					workflow_id: workflowId,
					step_id: "elf_step_1",
					status: "completed",
					evidence_ids: [fakeId],
				}),
			).rejects.toThrow(`Evidence ID '${fakeId}' not found in the project evidence ledger.`);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Failure Recovery Metadata & Bounded Retry
// ============================================================================

describe("reverse_workflow bounded failure recovery and retry", () => {
	it("rejects retry when step is not in failed state", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-notfailed-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Step is currently pending
			await expect(
				tool.execute("call_ret_err", {
					action: "retry",
					workflow_id: workflowId,
					step_id: "pe_step_1",
				}),
			).rejects.toThrow("Cannot retry step 'pe_step_1': step is currently in 'pending' state.");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("allows retry on failed step, updates recovery metadata, and resets to pending", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-ok-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Fail step 3
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "r2_inspect analysis timed out on large binary",
			});

			// Retry step 3 with fallback tool and caller-provided parameters
			const retryRes = await tool.execute("call_retry", {
				action: "retry",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				fallback_tool: "ghidra_inspect",
				next_params: '{"action": "decompile", "function": "main"}',
				result: "Radare2 failed; switching to headless Ghidra decompilation",
			});

			const step = retryRes.details.step;
			expect(step).toBeDefined();
			expect(step?.status).toBe("pending");
			expect(step?.tool).toBe("ghidra_inspect");
			expect(step?.error).toBeUndefined();
			expect(step?.recovery_metadata?.failure_reason).toBe("r2_inspect analysis timed out on large binary");
			expect(step?.recovery_metadata?.fallback_tool).toBe("ghidra_inspect");
			expect(step?.recovery_metadata?.retry_history).toHaveLength(1);
			expect(step?.recovery_metadata?.retry_history?.[0]?.caller_result).toBe(
				"Radare2 failed; switching to headless Ghidra decompilation",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces bounded maximum retry attempts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-bound-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// Workflow with max_attempts: 2
			const createRes = await tool.execute("call_create", { action: "create", target, max_attempts: 2 });
			const workflowId = createRes.details.workflow!.id;

			// Attempt 1 fails
			await tool.execute("call_rec1", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "Attempt 1 failed",
			});

			// Retry 1: step goes to pending
			await tool.execute("call_ret1", {
				action: "retry",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				next_params: "{}",
			});

			// Attempt 2 fails
			await tool.execute("call_rec2", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "Attempt 2 failed",
			});

			// Attempt 3 retry should be rejected because attempts (2) >= max_attempts (2)
			await expect(
				tool.execute("call_ret3_err", {
					action: "retry",
					workflow_id: workflowId,
					step_id: "pe_step_1",
				}),
			).rejects.toThrow("Retry attempt limit reached for step 'pe_step_1' (2/2 attempts).");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Failure Attribution, Parameter Correction & Fallback Recovery
// ============================================================================

describe("reverse_workflow failure attribution, parameter correction, and fallback recovery", () => {
	it("classifies failure strings into structured categories", () => {
		const missingDep = classifyFailure("r2: command not found");
		expect(missingDep.category).toBe("missing_dependency");
		expect(missingDep.confidence).toBe("high");
		expect(missingDep.install_hint).toBeDefined();

		const missingDroidasc = classifyFailure("Cannot find module droidasc: not found on PATH");
		expect(missingDroidasc.category).toBe("missing_dependency");

		const invalidFmt = classifyFailure("invalid ELF magic header: 0x504b0304");
		expect(invalidFmt.category).toBe("invalid_format");
		expect(invalidFmt.confidence).toBe("high");

		const timedOut = classifyFailure("Operation timed out after 30000ms");
		expect(timedOut.category).toBe("timeout");
		expect(timedOut.confidence).toBe("high");

		const trunc = classifyFailure("Target file size exceeds maximum triage limit of 52428800 bytes");
		expect(trunc.category).toBe("truncated");
		expect(trunc.confidence).toBe("high");

		const devReq = classifyFailure("Failed to execute adb: No usable Android device was resolved");
		expect(devReq.category).toBe("device_required");
		expect(devReq.confidence).toBe("high");

		const unsupp = classifyFailure("unsupported architecture: arm64e stripped binary");
		expect(unsupp.category).toBe("unsupported");
		expect(unsupp.confidence).toBe("high");

		const unk = classifyFailure("Unexpected memory access at 0x0000");
		expect(unk.category).toBe("unknown");
	});

	it("previews deterministic recovery plan via retry_plan action without mutating step state", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-retryplan-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Fail step 3
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "r2: command not found on PATH",
			});

			// Preview recovery plan with retry_plan
			const planRes = await tool.execute("call_plan", {
				action: "retry_plan",
				workflow_id: workflowId,
				step_id: "pe_step_3",
			});

			expect(planRes.details.action).toBe("retry_plan");
			const recoveryPlan = planRes.details.recovery_plan;
			expect(recoveryPlan).toBeDefined();
			expect(recoveryPlan?.attribution.category).toBe("missing_dependency");
			expect(recoveryPlan?.next_tool).toBeDefined();
			expect(recoveryPlan?.alternatives.length).toBeGreaterThan(0);
			expect(recoveryPlan?.can_retry).toBe(true);

			// Verify step state in store remains 'failed' (retry_plan is read-only)
			const statusRes = await tool.execute("call_status", {
				action: "status",
				workflow_id: workflowId,
				step_id: "pe_step_3",
			});
			expect(statusRes.details.step?.status).toBe("failed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recovers from missing dependency by switching to native fallback tool and corrected parameters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-dep-"));
		try {
			const target = await createAPKFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Step 3 in APK workflow is droidasc
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "apk_step_3",
				status: "failed",
				error: "droidasc: command not found",
			});

			// Execute recover
			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "apk_step_3",
			});

			const step = recoverRes.details.step;
			expect(step).toBeDefined();
			expect(step?.status).toBe("pending");
			expect(step?.tool).toBe("android_package_inspect");
			expect(step?.recovery_metadata?.attribution?.category).toBe("missing_dependency");
			expect(step?.recovery_metadata?.attribution?.missing_tool).toBe("droidasc");
			expect(step?.recovery_metadata?.attribution?.install_hint).toContain("pip install droidasc");

			// Check audit trail
			const audit = step?.recovery_metadata?.recovery_audit;
			expect(audit).toBeDefined();
			expect(audit).toHaveLength(1);
			expect(audit?.[0]?.action).toBe("recover");
			expect(audit?.[0]?.category).toBe("missing_dependency");
			expect(audit?.[0]?.previous_tool).toBe("droidasc");
			expect(audit?.[0]?.proposed_tool).toBe("android_package_inspect");
			expect(audit?.[0]?.applied).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recovers from invalid format by falling back to multi-format triage", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-fmt-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "invalid PE header: bad magic bytes",
			});

			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_1",
			});

			const step = recoverRes.details.step;
			expect(step?.status).toBe("pending");
			expect(step?.tool).toBe("triage");
			expect(step?.recovery_metadata?.attribution?.category).toBe("invalid_format");
			expect(recoverRes.details.recovery_plan?.suggested_action).toBe("fallback");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recovers from timeout by adjusting parameters to reduce scope", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-timeout-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "r2_inspect execution timed out after 30000ms",
			});

			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_3",
			});

			const step = recoverRes.details.step;
			expect(step?.status).toBe("pending");
			expect(step?.recovery_metadata?.attribution?.category).toBe("timeout");
			expect(recoverRes.details.recovery_plan?.suggested_action).toBe("adjust_params");
			const params = step?.params_summary as Record<string, unknown>;
			expect(params.limit).toBeLessThanOrEqual(30);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recovers from truncated output by configuring paging parameters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-trunc-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "buffer limit exceeded: output truncated",
			});

			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_1",
			});

			const step = recoverRes.details.step;
			expect(step?.status).toBe("pending");
			expect(step?.recovery_metadata?.attribution?.category).toBe("truncated");
			const params = step?.params_summary as Record<string, unknown>;
			expect(params.limit).toBe(25);
			expect(params.offset).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("recovers from device_required by degrading to offline static inspection", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-dev-"));
		try {
			const target = await createAPKFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "apk_step_3",
				status: "failed",
				error: "Failed to execute adb: No usable Android device was resolved",
			});

			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "apk_step_3",
			});

			const step = recoverRes.details.step;
			expect(step?.status).toBe("pending");
			expect(step?.tool).toBe("android_package_inspect");
			expect(step?.recovery_metadata?.attribution?.category).toBe("device_required");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("strictly enforces bounded maximum retry attempts in recover action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-bound-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// Max attempts = 2
			const createRes = await tool.execute("call_create", { action: "create", target, max_attempts: 2 });
			const workflowId = createRes.details.workflow!.id;

			// Attempt 1 fails
			await tool.execute("call_rec1", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "Attempt 1 failed",
			});

			// Recover 1: transitions to pending
			await tool.execute("call_recov1", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_1",
			});

			// Attempt 2 fails
			await tool.execute("call_rec2", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "Attempt 2 failed",
			});

			// Now attempts (2) >= max_attempts (2): recover MUST be rejected
			await expect(
				tool.execute("call_recov_err", {
					action: "recover",
					workflow_id: workflowId,
					step_id: "pe_step_1",
				}),
			).rejects.toThrow("Retry attempt limit reached for step 'pe_step_1' (2/2 attempts).");

			// retry_plan should report can_retry: false and exhausted: true
			const planRes = await tool.execute("call_plan", {
				action: "retry_plan",
				workflow_id: workflowId,
				step_id: "pe_step_1",
			});
			expect(planRes.details.recovery_plan?.exhausted).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("records recovery audit trail with evidence ledger association", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-rec-ev-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);
			const evidenceTool = new EvidenceTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Add a diagnostic hypothesis in the evidence ledger
			const evRes = await evidenceTool.execute("hypothesis-call", {
				action: "add",
				kind: "hypothesis",
				claim: "Binary functions require custom base offset after r2 failure",
				verificationPlan: "Run triage and compare the function base offset.",
				target,
			});
			const evId = evRes.details!.record!.id;

			// Fail step 3
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "r2_inspect failed: invalid base address",
			});

			// Recover with linked evidence ID
			const recoverRes = await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				evidence_ids: [evId],
				result: "Linked diagnostic hypothesis to recovery plan",
			});

			const step = recoverRes.details.step;
			expect(step?.evidence_ids).toContain(evId);

			const audit = step?.recovery_metadata?.recovery_audit?.[0];
			expect(audit).toBeDefined();
			expect(audit?.evidence_ids).toContain(evId);
			expect(audit?.caller_result).toBe("Linked diagnostic hypothesis to recovery plan");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("status and export actions include recovery audit and hydrated evidence", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-status-rec-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);
			const evidenceTool = new EvidenceTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			const evRes = await evidenceTool.execute("fact-call", {
				action: "add",
				kind: "fact",
				locator: "0x140001000",
				sourceTool: "triage",
				content: "MZ header verified",
				target,
			});
			const evId = evRes.details!.record!.id;

			// Fail step 3
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "r2: command not found",
			});

			// Recover with evidence
			await tool.execute("call_recover", {
				action: "recover",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				evidence_ids: [evId],
			});

			// Status with step_id
			const statusRes = await tool.execute("call_status", {
				action: "status",
				workflow_id: workflowId,
				step_id: "pe_step_3",
			});
			const statusText = textOf(statusRes);
			expect(statusText).toContain("Recovery Audit Trail");
			expect(statusText).toContain("MISSING_DEPENDENCY");
			expect(statusText).toContain(evId);

			// Export to markdown
			const mdRes = await tool.execute("call_export_md", {
				action: "export",
				workflow_id: workflowId,
				format_type: "markdown",
			});
			const mdText = textOf(mdRes);
			expect(mdText).toContain("Recovery Audit Trail");
			expect(mdText).toContain("Attribution: [MISSING_DEPENDENCY]");
			expect(mdText).toContain(evId);

			// Export to JSON
			const jsonRes = await tool.execute("call_export_json", {
				action: "export",
				workflow_id: workflowId,
				format_type: "json",
			});
			const parsedJson = JSON.parse(textOf(jsonRes));
			const exportedStep = parsedJson.steps.find((s: { id: string }) => s.id === "pe_step_3");
			expect(exportedStep.recovery_metadata.recovery_audit).toHaveLength(1);
			expect(exportedStep.recovery_metadata.recovery_audit[0].category).toBe("missing_dependency");
			expect(exportedStep.hydrated_evidence).toBeDefined();
			expect(exportedStep.hydrated_evidence.some((e: { id: string }) => e.id === evId)).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("routes missing decompiler for manifest extraction to native AXML manifest", () => {
		const mockWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_apk",
			target: "app.apk",
			target_abs_path: "/tmp/app.apk",
			format: "APK",
			goal: "Audit permissions and exported components",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const manifestStep: WorkflowStepRecord = {
			id: "apk_step_manifest",
			title: "G0: Extract Android manifest and verify components",
			tool: "apktool",
			gate: "G0",
			params_summary: { path: "/tmp/app.apk" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};

		const plan = generateRecoveryPlan(manifestStep, mockWorkflow, {
			error: "apktool: command not found",
		});

		expect(plan.suggested_action).toBe("fallback");
		expect(plan.next_tool).toBe("android_package_inspect");
		const nextParams = plan.next_params as Record<string, unknown>;
		expect(nextParams.action).toBe("manifest");
		expect(nextParams.path).toBe("/tmp/app.apk");
		expect(plan.capability_depth).toBe("static");
		expect(plan.verification_boundary).toBeDefined();
		expect(plan.remaining_acceptance).toBeDefined();
		expect(plan.prerequisites).toContain("target_apk_present");
		expect(plan.discovery_guidance?.tool_doc).toBe("read xd://android_package_inspect");
	});

	it("ensures no-device JNI fallback remains observation-only and does not complete JNI experiment", () => {
		const mockWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_jni",
			target: "libnative-crypto.so",
			target_abs_path: "/tmp/libnative-crypto.so",
			format: "ELF",
			goal: "Analyze JNI encryption routine",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const jniStep: WorkflowStepRecord = {
			id: "jni_step_exec",
			title: "G3: Emulate JNI Encrypt Method in unidbg",
			tool: "unidbg",
			gate: "G3",
			params_summary: { path: "/tmp/libnative-crypto.so", method: "encryptPayload" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};

		const plan = generateRecoveryPlan(jniStep, mockWorkflow, {
			error: "unidbg: command not found on PATH (requires JDK 8)",
		});

		expect(plan.suggested_action).toBe("fallback");
		expect(plan.next_tool).toBe("android_native_workflow");
		const nextParams = plan.next_params as Record<string, unknown>;
		expect(nextParams.action).toBe("inspect");
		expect(plan.verification_boundary).toBeDefined();
		expect(plan.remaining_acceptance).toBeDefined();
		expect(plan.remaining_acceptance).toContain("Dynamic JNI execution");
		expect(plan.alternatives).not.toContain("android_package_inspect");
	});

	it("distinguishes bare native targets and requires explicit JNI context for Android routing", () => {
		expect(isBareNativeTarget("libsample.so")).toBe(true);
		expect(isBareNativeTarget("sample.dll")).toBe(true);
		expect(isBareNativeTarget("sample.apk")).toBe(false);
		expect(isApkTarget("libsample.so")).toBe(false);
		expect(isApkTarget("sample.apk")).toBe(true);

		// .so extension alone is generic ELF and NOT proof of Android without explicit JNI context
		expect(isExplicitAndroidJniTarget({ targetPath: "libsample.so" })).toBe(false);
		expect(isExplicitAndroidJniTarget({ targetPath: "libsample.so", intent: "jni" })).toBe(true);
		expect(isExplicitAndroidJniTarget({ tool: "unidbg", targetPath: "libsample.so" })).toBe(true);
		expect(
			isExplicitAndroidJniTarget({ params: { method: "Java_com_sample_run" }, targetPath: "libsample.so" }),
		).toBe(true);

		// 1. Android native .so with explicit JNI method context routes to android_native_workflow
		const jniWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_jni_so",
			target: "libnative.so",
			target_abs_path: "/tmp/libnative.so",
			format: "ELF",
			goal: "Analyze Android JNI crypto methods",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const jniStep: WorkflowStepRecord = {
			id: "so_step_1",
			title: "G1: Decompile Android JNI native functions",
			tool: "jadx",
			gate: "G1",
			params_summary: { path: "/tmp/libnative.so", method: "nativeInit" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		const jniPlan = generateRecoveryPlan(jniStep, jniWorkflow, {
			error: "jadx: command not found",
		});
		expect(jniPlan.next_tool).toBe("android_native_workflow");
		expect(jniPlan.alternatives).not.toContain("android_package_inspect");
		expect(jniPlan.verification_boundary).toBeDefined();

		// 2. Generic standalone Linux .so WITHOUT JNI context routes to triage, NOT android_native_workflow
		const genericSoWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_gen_so",
			target: "libcrypto.so",
			target_abs_path: "/tmp/libcrypto.so",
			format: "ELF",
			goal: "Analyze generic Linux shared library",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const genericSoStep: WorkflowStepRecord = {
			id: "so_step_gen",
			title: "G1: Analyze ELF sections",
			tool: "jadx",
			gate: "G1",
			params_summary: { path: "/tmp/libcrypto.so" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		const genericSoPlan = generateRecoveryPlan(genericSoStep, genericSoWorkflow, {
			error: "jadx: command not found",
		});
		expect(genericSoPlan.next_tool).toBe("triage");
		expect(genericSoPlan.capability_depth).toBe("triage");
		expect(genericSoPlan.verification_boundary).toBeDefined();

		// 3. Generic native binary (DLL) must route to triage, NOT android_native_workflow
		const dllWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_dll",
			target: "plugin.dll",
			target_abs_path: "/tmp/plugin.dll",
			format: "PE",
			goal: "Analyze Windows native plugin",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const dllStep: WorkflowStepRecord = {
			id: "dll_step_1",
			title: "G1: Decompile DLL",
			tool: "jadx",
			gate: "G1",
			params_summary: { path: "/tmp/plugin.dll" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		const dllPlan = generateRecoveryPlan(dllStep, dllWorkflow, {
			error: "jadx: command not found",
		});
		expect(dllPlan.next_tool).toBe("triage");
		expect(dllPlan.capability_depth).toBe("triage");
		expect(dllPlan.verification_boundary).toBeDefined();
	});

	it("prohibits silent unsupported-target fallbacks and demarcates exploratory limits", () => {
		const mockWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_unsupp",
			target: "firmware.blob",
			target_abs_path: "/tmp/firmware.blob",
			format: "unknown",
			goal: "Analyze proprietary firmware",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};
		const unsuppStep: WorkflowStepRecord = {
			id: "step_unsupp_1",
			title: "G0: Triage unknown format",
			tool: "r2_inspect",
			gate: "G0",
			params_summary: { path: "/tmp/firmware.blob" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};

		const plan = generateRecoveryPlan(unsuppStep, mockWorkflow, {
			error: "unsupported architecture: proprietary 16-bit ASIC",
		});

		expect(plan.suggested_action).toBe("abort");
		expect(plan.can_retry).toBe(false);
		expect(plan.verification_boundary).toBeDefined();
		expect(plan.remaining_acceptance).toBeDefined();
	});

	it("corrects tool-schema aliases for binary_diff, pcap_inspect, and android_package_inspect", () => {
		const mockWorkflow: ReverseWorkflowRecord = {
			id: "wf_test_schemas",
			target: "app.apk",
			target_abs_path: "/tmp/app.apk",
			format: "APK",
			goal: "Schema validation test",
			status: "active",
			steps: [],
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
			metadata: {},
		};

		// 1. vbindiff -> binary_diff schema (path_a, path_b, action)
		const diffStep: WorkflowStepRecord = {
			id: "step_diff",
			title: "G2: Binary diff files",
			tool: "vbindiff",
			gate: "G2",
			params_summary: { fileA: "/tmp/orig.bin", fileB: "/tmp/mod.bin", mode: "summary" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		const diffPlan = generateRecoveryPlan(diffStep, mockWorkflow, {
			error: "vbindiff: command not found",
		});
		expect(diffPlan.next_tool).toBe("binary_diff");
		const diffParams = diffPlan.next_params as Record<string, unknown>;
		expect(diffParams.path_a).toBe("/tmp/orig.bin");
		expect(diffParams.path_b).toBe("/tmp/mod.bin");
		expect(diffParams.action).toBe("summary");
		expect(diffParams.fileA).toBeUndefined();
		expect(diffParams.fileB).toBeUndefined();
		expect(diffParams.mode).toBeUndefined();

		// 2. device_required on APK -> android_package_inspect with info or manifest (never 'inspect')
		const devStep: WorkflowStepRecord = {
			id: "step_dev",
			title: "G2: Dynamic device check",
			tool: "adb",
			gate: "G2",
			params_summary: { path: "/tmp/app.apk" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		const devPlan = generateRecoveryPlan(devStep, mockWorkflow, {
			error: "device not found",
		});
		expect(devPlan.next_tool).toBe("android_package_inspect");
		const devParams = devPlan.next_params as Record<string, unknown>;
		expect(["info", "manifest"]).toContain(devParams.action as string);
		expect(devParams.action).not.toBe("inspect");

		// 3. tshark -> pcap_inspect schema
		const pcapStep: WorkflowStepRecord = {
			id: "step_pcap",
			title: "G2: Network capture analysis",
			tool: "tshark",
			gate: "G2",
			params_summary: { artifact_path: "/tmp/capture.pcap", action: "endpoints" },
			status: "failed",
			attempts: 1,
			max_attempts: 3,
			created_at: new Date().toISOString(),
			updated_at: new Date().toISOString(),
		};
		// Workflow target is app.apk, but step specifies artifact_path /tmp/capture.pcap
		const pcapPlan = generateRecoveryPlan(pcapStep, mockWorkflow, {
			error: "tshark: command not found",
		});
		expect(pcapPlan.next_tool).toBe("pcap_inspect");
		const pcapParams = pcapPlan.next_params as Record<string, unknown>;
		expect(pcapParams.path).toBe("/tmp/capture.pcap");
		expect(pcapParams.action).toBe("endpoints");
	});

	it("resolves canonical capability recovery suggestions via resolveCapabilityRecovery", () => {
		const manifestRec = resolveCapabilityRecovery("apk_unpacking", {
			targetPath: "/tmp/app.apk",
			action: "manifest",
		});
		expect(manifestRec?.nextTool).toBe("android_package_inspect");
		expect(manifestRec?.nextParams.action).toBe("manifest");
		expect(manifestRec?.capabilityDepth).toBe("static");

		// Generic native binary without JNI intent routes to triage, NOT android_native_workflow
		const soRec = resolveCapabilityRecovery("apk_unpacking", {
			targetPath: "/tmp/libfoo.so",
		});
		expect(soRec?.nextTool).toBe("triage");
		expect(soRec?.capabilityDepth).toBe("triage");

		// Native binary WITH explicit JNI intent routes to android_native_workflow
		const jniSoRec = resolveCapabilityRecovery("apk_unpacking", {
			targetPath: "/tmp/libfoo.so",
			intent: "jni",
		});
		expect(jniSoRec?.nextTool).toBe("android_native_workflow");
		expect(jniSoRec?.nextParams.action).toBe("inspect");
		// Generic native binary routes to triage, NOT android_native_workflow
		const dllRec = resolveCapabilityRecovery("apk_unpacking", {
			targetPath: "/tmp/plugin.dll",
			targetFormat: "PE",
		});
		expect(dllRec?.nextTool).toBe("triage");
		expect(dllRec?.capabilityDepth).toBe("triage");

		const jniRec = resolveCapabilityRecovery("android_native_emulation", {
			targetPath: "/tmp/libfoo.so",
		});
		expect(jniRec?.nextTool).toBe("android_native_workflow");
		expect(jniRec?.capabilityDepth).toBe("static");
		expect(jniRec?.verificationBoundary).toBeDefined();

		// native_debugger routes to zero-prep triage (or r2_inspect when radare2 installed)
		const dbgRec = resolveCapabilityRecovery("native_debugger", {
			targetPath: "/tmp/server.elf",
		});
		expect(dbgRec?.nextTool).toBe("triage");
		expect(dbgRec?.capabilityDepth).toBe("triage");
		expect(dbgRec?.alternatives).toContain("r2_inspect");

		// signing verification boundary notes v1/v2/v3/v3.1 presence and external v4
		const signRec = resolveCapabilityRecovery("apk_unpacking", {
			targetPath: "/tmp/app.apk",
			action: "signing",
		});
		expect(signRec?.nextTool).toBe("android_package_inspect");
		expect(signRec?.verificationBoundary).toBeDefined();

		const diffRec = resolveCapabilityRecovery("binary_diff", {
			params: { path_a: "old.bin", path_b: "new.bin" },
		});
		expect(diffRec?.nextTool).toBe("binary_diff");
		expect(diffRec?.nextParams.action).toBe("summary");
	});

	it("normalizes reverse_recovery and retry_plan tool name aliases", () => {
		expect(normalizeToolName("reverse_recovery")).toBe("reverse_workflow");
		expect(normalizeToolName("retry_plan")).toBe("reverse_workflow");
		expect(normalizeToolName("workflow_recovery")).toBe("reverse_workflow");
	});
});

// ============================================================================
// Path Validation & Safety
// ============================================================================

describe("reverse_workflow path validation and safety", () => {
	it("rejects create when target file does not exist", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-val-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			await expect(
				tool.execute("call_create_err", { action: "create", target: "nonexistent_file.bin" }),
			).rejects.toThrow("Target file not found: nonexistent_file.bin");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects create when target is a directory", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-val-dir-"));
		try {
			const subDir = path.join(tempDir, "subfolder");
			await fs.mkdir(subDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			await expect(tool.execute("call_create_err", { action: "create", target: subDir })).rejects.toThrow(
				"Target path must be a file, not a directory",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("spills to session artifact when to_artifact: true is requested", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-art-"));
		try {
			const target = await createELFFixture(tempDir);
			const session = createTestSession(tempDir, { allocateArtifact: true });
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			const exportRes = await tool.execute("call_export", {
				action: "export",
				workflow_id: workflowId,
				to_artifact: true,
			});
			expect(exportRes.details.artifactId).toBeDefined();
			expect(exportRes.details.artifactPath).toBeDefined();
			const text = textOf(exportRes);
			expect(text).toContain(`artifact://${exportRes.details.artifactId}`);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow runtime session association and export", () => {
	it("associates runtime_session_id with a workflow step and exports it in markdown and json", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-runt-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;
			const firstStep = createRes.details.workflow!.steps[0];

			// Record step with runtime_session_id
			const runtimeSessionId = "runt_frida_018f921ab39c";
			const recordRes = await tool.execute("call_rec", {
				action: "record",
				workflow_id: workflowId,
				step_id: firstStep.id,
				status: "completed",
				runtime_session_id: runtimeSessionId,
				outputs: "Enumerated modules successfully",
			});

			expect(recordRes.details.step?.runtime_session_id).toBe(runtimeSessionId);
			expect(textOf(recordRes)).toContain(`- Associated Runtime Session: \`${runtimeSessionId}\``);

			// Check status displays runtime session
			const statusStepRes = await tool.execute("call_status_step", {
				action: "status",
				workflow_id: workflowId,
				step_id: firstStep.id,
			});
			expect(textOf(statusStepRes)).toContain(`- **Runtime Session**: \`${runtimeSessionId}\``);

			// Check Markdown export contains runtime session
			const mdExportRes = await tool.execute("call_export_md", {
				action: "export",
				workflow_id: workflowId,
				format_type: "markdown",
			});
			const mdText = textOf(mdExportRes);
			expect(mdText).toContain(`- **Runtime Session**: \`${runtimeSessionId}\``);

			// Check JSON export contains runtime session
			const jsonExportRes = await tool.execute("call_export_json", {
				action: "export",
				workflow_id: workflowId,
				format_type: "json",
			});
			const jsonText = textOf(jsonExportRes);
			const parsed = JSON.parse(jsonText);
			const exportedStep = parsed.steps.find((s: { id: string }) => s.id === firstStep.id);
			expect(exportedStep.runtime_session_id).toBe(runtimeSessionId);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow low-risk auto progression and guardrails", () => {
	it("advances only allowlisted low-risk static tools and records progression audit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-progression-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// 1. Create workflow
			const createRes = await tool.execute("call_create", {
				action: "create",
				target,
				goal: "Static audit of PE sample",
			});
			const workflowId = createRes.details.workflow!.id;
			expect(workflowId).toBeDefined();

			// 2. Auto advance first pending step (pe_step_1: triage)
			const adv1 = await tool.execute("call_adv1", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(adv1.details.progression_status).toBe("proposed");
			expect(adv1.details.step?.id).toBe("pe_step_1");
			expect(adv1.details.step?.tool).toBe("triage");
			expect(adv1.details.progression_audit).toBeDefined();
			expect(adv1.details.progression_audit?.[0].is_low_risk).toBe(true);

			// 3. Record completion of step 1 via advance
			const rec1 = await tool.execute("call_rec1", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "completed",
				outputs: "PE32+ executable, 4 sections, entrypoint 0x140001000",
			});

			expect(rec1.details.progression_status).toBe("recorded");
			expect(rec1.details.step?.status).toBe("completed");

			// 4. Auto advance next step (pe_step_2: binary_metadata_inspect)
			const adv2 = await tool.execute("call_adv2", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(adv2.details.progression_status).toBe("proposed");
			expect(adv2.details.step?.id).toBe("pe_step_2");
			expect(adv2.details.step?.tool).toBe("binary_metadata_inspect");

			// 5. Record completion of step 2
			const rec2 = await tool.execute("call_rec2", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "pe_step_2",
				status: "completed",
				outputs: "Compiler: MSVC 2019, Subsystem: Windows CUI",
			});
			expect(rec2.details.step?.status).toBe("completed");

			// 6. Check workflow status displays recent progression decisions
			const statusRes = await tool.execute("call_status", {
				action: "status",
				workflow_id: workflowId,
			});
			expect(textOf(statusRes)).toContain("Recent Progression Decisions");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("halts auto progression on dynamic or high-risk tools and keeps them pending decision", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-dynamic-halt-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", {
				action: "create",
				target,
			});
			const workflowId = createRes.details.workflow!.id;

			// Complete step 1 and step 2 to reach step 3 (r2_inspect)
			await tool.execute("call_adv_step1", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "completed",
				outputs: "Triage complete",
			});
			await tool.execute("call_adv_step2", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "pe_step_2",
				status: "completed",
				outputs: "Metadata complete",
			});

			// Now next pending step is pe_step_3 (tool: r2_inspect)
			const adv3 = await tool.execute("call_adv3", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(adv3.details.progression_status).toBe("held_pending_decision");
			expect(adv3.details.step?.id).toBe("pe_step_3");
			expect(adv3.details.step?.status).toBe("pending"); // MUST remain pending!
			expect(adv3.details.decision_reason).toContain("r2_inspect");
			expect(textOf(adv3)).toContain("requires dynamic or high-risk tool");

			// Verify in persistent store that step is still pending
			const store = new ReverseWorkflowStore({ repositoryRoot: tempDir });
			const wfInStore = await store.get(workflowId);
			const step3 = wfInStore?.steps.find(s => s.id === "pe_step_3");
			expect(step3?.status).toBe("pending");
			expect(step3?.progression_status).toBe("held_pending_decision");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("stops auto progression on ambiguous target file or unknown format", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ambiguous-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", {
				action: "create",
				target,
			});
			const workflowId = createRes.details.workflow!.id;

			// Delete target file to make target ambiguous/inaccessible
			await fs.unlink(target);

			const advRes = await tool.execute("call_adv", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(advRes.details.progression_status).toBe("stopped_ambiguous_target");
			expect(advRes.details.decision_reason).toContain("cannot be accessed or resolved on disk");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("attaches verified knowledge references during progression and exports decisions in markdown and json", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-knowledge-export-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const knowledgeTool = new ReverseKnowledgeTool(session);

			// Pre-retain verified knowledge matching triage tool and PE format
			const knRes = await knowledgeTool.execute("kn-pe", {
				action: "retain",
				title: "Entropy threshold for packed PE headers",
				kind: "verified_conclusion",
				format: "PE",
				tool: "triage",
				summary: "Entropy > 7.2 in .text section indicates runtime packer packing",
				confidence: "high",
			});
			const knId = knRes.details!.record!.id;

			// Create workflow
			const createRes = await workflowTool.execute("call_create", {
				action: "create",
				target,
			});
			const workflowId = createRes.details.workflow!.id;

			// Auto advance attaches the active prior knowledge
			const advRes = await workflowTool.execute("call_adv", {
				action: "auto_advance",
				workflow_id: workflowId,
			});
			expect(advRes.details.knowledge_refs).toContain(knId);

			// Record step completion with knowledge ref
			await workflowTool.execute("call_adv_step1", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "completed",
				outputs: "Entropy is 6.1 (unpacked)",
				knowledge_refs: [knId],
			});

			// Markdown export contains decisions and knowledge references
			const mdRes = await workflowTool.execute("call_export_md", {
				action: "export",
				workflow_id: workflowId,
				format_type: "markdown",
			});
			const mdText = textOf(mdRes);
			expect(mdText).toContain("Auto Progression & Governance Decisions");
			expect(mdText).toContain("pe_step_1");
			expect(mdText).toContain(knId);

			// JSON export contains progression audit and knowledge references
			const jsonRes = await workflowTool.execute("call_export_json", {
				action: "export",
				workflow_id: workflowId,
				format_type: "json",
			});
			const jsonText = textOf(jsonRes);
			const parsed = JSON.parse(jsonText);
			expect(parsed.progression_audit).toBeDefined();
			expect(parsed.progression_audit.length).toBeGreaterThan(0);
			expect(parsed.knowledge_refs).toContain(knId);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Full-File Target Hashing (>64KiB Differing Tails) & Workspace Metadata
// ============================================================================

describe("reverse_workflow full-file hashing for >64KiB targets", () => {
	it("hashes complete file when size exceeds 64KiB prefix and associates knowledge and workspace metadata", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-hash-tail-"));
		try {
			// Construct two binary targets >64KiB that share identical 64KiB prefix but differ at the tail
			const prefixLen = 65536; // 64 KiB
			const tailLen = 6144; // 6 KiB
			const totalSize = prefixLen + tailLen; // 71680 bytes (>64KiB)

			// Valid ELF header in the first bytes
			const prefix = Buffer.alloc(prefixLen, 0);
			prefix[0] = 0x7f;
			prefix[1] = 0x45; // E
			prefix[2] = 0x4c; // L
			prefix[3] = 0x46; // F
			prefix[4] = 2; // 64-bit
			prefix[5] = 1; // little endian
			prefix[6] = 1; // version

			const tailA = Buffer.alloc(tailLen, 0xaa);
			const tailB = Buffer.alloc(tailLen, 0xbb);

			const fileBufA = Buffer.concat([prefix, tailA]);
			const fileBufB = Buffer.concat([prefix, tailB]);

			const targetPathA = path.join(tempDir, "sampleA.elf");
			const targetPathB = path.join(tempDir, "sampleB.elf");

			await fs.writeFile(targetPathA, fileBufA);
			await fs.writeFile(targetPathB, fileBufB);

			const expectedHashA = createHash("sha256").update(fileBufA).digest("hex");
			const expectedHashB = createHash("sha256").update(fileBufB).digest("hex");
			const prefixHash = createHash("sha256").update(prefix).digest("hex");

			expect(expectedHashA).not.toBe(expectedHashB);
			expect(expectedHashA).not.toBe(prefixHash);
			expect(expectedHashB).not.toBe(prefixHash);

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const knowledgeTool = new ReverseKnowledgeTool(session);

			// Pre-retain verified knowledge keyed specifically to Target A's full hash
			const knRes = await knowledgeTool.execute("kn-tail-a", {
				action: "retain",
				title: "Specific entry point and tail layout for Target A",
				kind: "verified_conclusion",
				format: "ELF",
				target_hash: expectedHashA,
				summary: "Verified 70KiB binary structure with tail layout pattern A",
			});
			const knId = knRes.details!.record?.id;
			expect(knId).toBeDefined();

			// 1. Create workflow for Target A
			const createResA = await workflowTool.execute("call_create_a", {
				action: "create",
				target: targetPathA,
				goal: "Analyze Target A with full hash verification",
			});
			const wfA = createResA.details.workflow;
			expect(wfA).toBeDefined();
			// Complete file hash must be stored (not 64KiB prefix hash)
			expect(wfA?.target_sha256).toBe(expectedHashA);
			expect(wfA?.target_sha256).not.toBe(prefixHash);
			// Format sniffing remained bounded to 64KiB header and correctly identified ELF
			expect(wfA?.format).toBe("ELF");
			// Knowledge lookup matched Target A's full hash
			expect(wfA?.knowledge_refs).toContain(knId!);

			// 2. Create workflow for Target B
			const createResB = await workflowTool.execute("call_create_b", {
				action: "create",
				target: targetPathB,
				goal: "Analyze Target B with different tail",
			});
			const wfB = createResB.details.workflow;
			expect(wfB).toBeDefined();
			// Complete file hash for Target B
			expect(wfB?.target_sha256).toBe(expectedHashB);
			expect(wfB?.target_sha256).not.toBe(prefixHash);
			expect(wfB?.target_sha256).not.toBe(expectedHashA);
			expect(wfB?.format).toBe("ELF");
			// Knowledge lookup for Target B must not associate Target A's hash-specific knowledge
			expect(wfB?.knowledge_refs ?? []).not.toContain(knId!);

			// 3. Export Target A workflow to custom workspace directory using workspace_path
			const customWsDir = path.join(tempDir, "custom-rea-workspace");
			const exportWsResA = await workflowTool.execute("call_export_ws_a", {
				action: "export",
				workflow_id: wfA!.id,
				workspace_path: customWsDir,
			});
			// Manifest and details target info use the full hash
			expect(exportWsResA.details.workspace_manifest?.target.sha256).toBe(expectedHashA);
			expect(exportWsResA.details.workspace_manifest?.target.sha256).not.toBe(prefixHash);

			// Check disk workspace manifest and target.json
			const diskManifestPath = path.join(customWsDir, "manifest.json");
			const diskManifest = JSON.parse(await fs.readFile(diskManifestPath, "utf8"));
			expect(diskManifest.target.sha256).toBe(expectedHashA);

			const diskTargetJsonPath = path.join(customWsDir, "target", "target.json");
			const diskTargetJson = JSON.parse(await fs.readFile(diskTargetJsonPath, "utf8"));
			expect(diskTargetJson.sha256).toBe(expectedHashA);
			expect(diskTargetJson.size).toBe(totalSize);

			// 4. Export Target B workflow using to_workspace: true
			const exportWsResB = await workflowTool.execute("call_export_ws_b", {
				action: "export",
				workflow_id: wfB!.id,
				to_workspace: true,
			});
			expect(exportWsResB.details.workspace_manifest?.target.sha256).toBe(expectedHashB);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow install-after resume and canonical host verification", () => {
	it("fixes TDZ bug and rejects unverified tool even if verified: true is passed", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-tdz-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Fail step 1
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "Tool non_existent_decomp_tool: command not found",
			});

			// Retry with installed_tool that does NOT exist on PATH
			// Pass verified: true - user assertion must NOT be accepted as proof!
			const retryRes = await tool.execute("call_retry", {
				action: "retry",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				installed_tool: "non_existent_decomp_tool",
				verified: true,
				strategy: "resume_original",
				next_params: '{"action": "disasm"}',
			});
			// Must not throw ReferenceError: proposedParams is not defined
			// Must return structured missing state
			expect(retryRes.details.status).toBe("missing_dependency");
			expect(retryRes.details.verified).toBe(false);
			expect(retryRes.details.missing_tool).toBe("non_existent_decomp_tool");

			const step = retryRes.details.step;
			expect(step).toBeDefined();
			// Step must remain failed and not pending
			expect(step?.status).toBe("failed");
			// Tool must not have been replaced by the unavailable tool
			expect(step?.tool).not.toBe("non_existent_decomp_tool");
			// Resume metadata must record verified: false
			expect(step?.recovery_metadata?.resume?.verified).toBe(false);
			expect(step?.recovery_metadata?.resume?.installed_tool).toBe("non_existent_decomp_tool");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("accepts verified resume when installed_tool is present on host", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-ver-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Fail step 1
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "failed",
				error: "strings command failed",
			});

			// Retry with 'strings' which is present on PATH
			const retryRes = await tool.execute("call_retry", {
				action: "retry",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				installed_tool: "strings",
				verified: false, // even if user says false, host check verifies it
				strategy: "resume_original",
				next_params: '{"min_length": 6}',
			});
			expect(retryRes.details.resume?.verified).toBe(true);
			const step = retryRes.details.step;
			expect(step?.status).toBe("pending");
			expect(step?.tool).toBe("triage");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
	it("preserves original adapter step tool when resuming via installed dependency (r2_inspect stays r2_inspect)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-ret-adapt-"));
		try {
			const target = await createPEFixture(tempDir);
			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", { action: "create", target });
			const workflowId = createRes.details.workflow!.id;

			// Fail step 3 (r2_inspect)
			await tool.execute("call_rec_fail", {
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				status: "failed",
				error: "radare2: command not found",
			});

			// Retry step 3 indicating radare2 dependency was installed
			// In resume_original, step.tool MUST remain 'r2_inspect' rather than being overwritten with 'radare2'
			const retryRes = await tool.execute("call_retry", {
				action: "retry",
				workflow_id: workflowId,
				step_id: "pe_step_3",
				installed_tool: "radare2",
				strategy: "resume_original",
			});

			const step = retryRes.details.step;
			// Step tool must remain the adapter tool r2_inspect!
			expect(step?.tool).toBe("r2_inspect");
			expect(step?.recovery_metadata?.resume?.installed_tool).toBe("radare2");
			expect(step?.recovery_metadata?.resume?.strategy).toBe("resume_original");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("reverse_workflow native SO and JNI planning and progression", () => {
	it("plans native SO target with elf_inspect, unidbg probe and ghidra_enrich", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-so-plan-"));
		try {
			const soPath = path.join(tempDir, "libnative.so");
			await fs.writeFile(soPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create_so", {
				action: "create",
				target: soPath,
				goal: "Reverse JNI native registration and verify encryption keys",
			});

			expect(createRes.details.workflow?.format).toBe("ELF");
			const steps = createRes.details.workflow?.steps ?? [];
			expect(steps).toHaveLength(6);

			expect(steps[0].tool).toBe("triage");
			expect(steps[1].tool).toBe("elf_inspect");
			expect(steps[2].tool).toBe("unidbg");
			expect(steps[3].tool).toBe("ghidra_inspect");
			expect(steps[4].tool).toBe("frida");
			expect(steps[5].tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("halts progression on unidbg emulation step and holds pending decision", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-so-auto-"));
		try {
			const soPath = path.join(tempDir, "libtarget.so");
			await fs.writeFile(soPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			const createRes = await tool.execute("call_create", {
				action: "create",
				target: soPath,
				goal: "Reverse Android JNI RegisterNatives",
			});
			const workflowId = createRes.details.workflow!.id;

			// Advance step 1 (elf_inspect query)
			await tool.execute("call_step1", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "completed",
				outputs: "ELF AArch64 dynamic shared object",
			});

			// Advance step 2 (elf_inspect constructors query)
			await tool.execute("call_step2", {
				action: "advance",
				workflow_id: workflowId,
				step_id: "elf_step_2",
				status: "completed",
				outputs: "Constructors and relocations triaged",
			});

			// Next step is elf_step_3 (tool: unidbg, action: probe)
			// Auto advance must NOT execute dynamic Unidbg silently
			const advRes = await tool.execute("call_auto_adv", {
				action: "auto_advance",
				workflow_id: workflowId,
			});

			expect(advRes.details.step?.id).toBe("elf_step_3");
			expect(advRes.details.step?.status).toBe("pending");
			expect(advRes.details.step?.progression_status).toBe("held_pending_decision");
			expect(advRes.details.decision_reason).toContain("unidbg");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("plans generic Linux .so target without Android JNI evidence as generic ELF triage", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-linux-so-"));
		try {
			const soPath = path.join(tempDir, "libcrypto.so");
			await fs.writeFile(soPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// Generic Linux goal (no JNI/Android evidence)
			const createRes = await tool.execute("call_create_linux", {
				action: "create",
				target: soPath,
				goal: "Audit OpenSSL crypto library exports on Linux x86_64",
			});

			expect(createRes.details.workflow?.format).toBe("ELF");
			const steps = createRes.details.workflow?.steps ?? [];
			// Generic ELF: 4 steps (triage, binary_metadata_inspect, r2_inspect, evidence), NOT routed to Unidbg
			expect(steps).toHaveLength(4);
			expect(steps[0].tool).toBe("triage");
			expect(steps[1].tool).toBe("binary_metadata_inspect");
			expect(steps[2].tool).toBe("r2_inspect");
			expect(steps[3].tool).toBe("evidence");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("plans Android ABI path fixture (.so inside lib/arm64-v8a/) as native JNI workflow", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rw-arm64-so-"));
		try {
			const abiDir = path.join(tempDir, "lib", "arm64-v8a");
			await fs.mkdir(abiDir, { recursive: true });
			const soPath = path.join(abiDir, "libnative.so");
			await fs.writeFile(soPath, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

			const session = createTestSession(tempDir);
			const tool = new ReverseWorkflowTool(session);

			// Android ABI path provides meaningful Android evidence
			const createRes = await tool.execute("call_create_arm64", {
				action: "create",
				target: soPath,
			});

			expect(createRes.details.workflow?.format).toBe("ELF");
			const steps = createRes.details.workflow?.steps ?? [];
			expect(steps).toHaveLength(6);
			expect(steps[0].tool).toBe("triage");
			expect(steps[1].tool).toBe("elf_inspect");
			expect(steps[2].tool).toBe("unidbg");
			expect(steps[3].tool).toBe("ghidra_inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
