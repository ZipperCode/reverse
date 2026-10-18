import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	ReverseWorkflowTool,
	ReverseWorkspaceTool,
	EvidenceTool,
	type ToolSession,
	BUILTIN_TOOLS,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { EvidenceStore } from "@rva/coding-agent/evidence/store";
import { ReverseWorkflowStore } from "@rva/coding-agent/reverse-workflow/store";
import {
	exportWorkflowToWorkspace,
	inspectWorkspace,
	loadWorkspaceManifest,
	cleanWorkspace,
	DEFAULT_WORKSPACE_DIR,
	WORKSPACE_FILES,
	WORKSPACE_SUBDIRS,
	type ReverseWorkspaceManifest,
} from "@rva/coding-agent/reverse-workspace";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

async function createTargetFixture(dir: string, name = "sample.elf"): Promise<string> {
	const filePath = path.join(dir, name);
	const buf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
	await fs.writeFile(filePath, buf);
	return filePath;
}

describe("Reverse Workspace Tool & Standardized .rea Layout", () => {
	it("registers reverse_workspace in built-in names and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("reverse_workspace");
		expect(normalizeToolName("reverse-workspace")).toBe("reverse_workspace");
		expect(normalizeToolName("workspace")).toBe("reverse_workspace");
		expect(normalizeToolName("rea_workspace")).toBe("reverse_workspace");
		expect(normalizeToolName("REVERSE_WORKSPACE")).toBe("reverse_workspace");
	});

	it("instantiates ReverseWorkspaceTool with read/write approval tiers", () => {
		const session = createTestSession("/tmp");
		const tool = new ReverseWorkspaceTool(session);
		expect(tool.name).toBe("reverse_workspace");
		expect(tool.strict).toBe(true);
		expect(tool.loadMode).toBe("discoverable");

		expect(tool.approval({ action: "status" })).toBe("read");
		expect(tool.approval({ action: "manifest" })).toBe("read");
		expect(tool.approval({ action: "export" })).toBe("write");
		expect(tool.approval({ action: "clean" })).toBe("write");
	});

	it("exports standardized .rea/ workspace via reverse_workflow to_workspace option", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-ws-test-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "server.elf");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const evidenceTool = new EvidenceTool(session);

			// 1. Create workflow
			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "ELF",
				goal: "Reverse auth token mechanism",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			// 2. Add verified evidence
			const factRes = await evidenceTool.execute("fact-call", {
				action: "add",
				kind: "fact",
				target: targetFile,
				locator: "sym.auth_validate:0x4012a0",
				sourceTool: "triage",
				content: "Found HMAC authentication check using key token_secret_1234567890abcdef",
			});
			const factId = factRes.details?.record?.id;
			if (!factId) throw new Error("Fact id missing");

			const conclusionRes = await evidenceTool.execute("conclusion-call", {
				action: "add",
				kind: "hypothesis",
				claim: "Confirmed HMAC authentication bypass by returning 1 from sym.auth_validate",
				verificationPlan: "Run the auth validation path and compare the result.",
				target: targetFile,
				facts: [factId],
			});
			const conclusionId = conclusionRes.details?.record?.id;
			if (!conclusionId) throw new Error("Conclusion id missing");

			// 3. Record step completion with linked evidence
			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "completed",
				outputs: "ELF headers validated. Token check located at 0x4012a0.",
				evidence_ids: [factId, conclusionId],
			});

			// 4. Export with to_workspace: true
			const exportRes = await workflowTool.execute({
				action: "export",
				workflow_id: workflowId,
				to_workspace: true,
			});

			const text = textOf(exportRes);
			expect(text).toContain("Standardized Reverse Workspace Exported");
			expect(exportRes.details.action).toBe("export");
			expect(exportRes.details.workspace_dir).toBeDefined();

			const wsDir = path.join(tempDir, DEFAULT_WORKSPACE_DIR);
			const manifestPath = path.join(wsDir, WORKSPACE_FILES.MANIFEST);

			// Check all standardized files exist
			const manifestExists = await fs.stat(manifestPath).then(s => s.isFile()).catch(() => false);
			expect(manifestExists).toBe(true);

			for (const subdir of WORKSPACE_SUBDIRS) {
				const subdirPath = path.join(wsDir, subdir);
				const isDir = await fs.stat(subdirPath).then(s => s.isDirectory()).catch(() => false);
				expect(isDir).toBe(true);
			}

			// Validate manifest content
			const manifestContent = await fs.readFile(manifestPath, "utf8");
			const manifest = JSON.parse(manifestContent) as ReverseWorkspaceManifest;
			expect(manifest.schema_version).toBe("1.0.0");
			expect(manifest.workflow.id).toBe(workflowId);
			expect(manifest.target.name).toBe("server.elf");
			expect(manifest.target.is_reference).toBe(true);
			expect(manifest.stats.steps_completed).toBeGreaterThanOrEqual(1);
			expect(manifest.stats.conclusions_count).toBe(0);
			expect(manifest.files.length).toBeGreaterThanOrEqual(8);

			// Target profile verification: target binary is NEVER mutated or duplicated
			const targetJsonPath = path.join(wsDir, WORKSPACE_FILES.TARGET_INFO);
			const targetJson = JSON.parse(await fs.readFile(targetJsonPath, "utf8"));
			expect(targetJson.is_reference).toBe(true);
			expect(targetJson.name).toBe("server.elf");
			expect(targetJson.sha256).toBeDefined();

			const originalTargetBytes = await fs.readFile(targetFile);
			expect(originalTargetBytes.length).toBe(16);

			// Findings report verification
			const findingsMdPath = path.join(wsDir, WORKSPACE_FILES.FINDINGS_MD);
			const findingsMd = await fs.readFile(findingsMdPath, "utf8");
			expect(findingsMd).toContain("Reverse Engineering Findings: server.elf");
			expect(findingsMd).toContain("Confirmed HMAC authentication bypass");

			// Secrets redaction verification (token_secret_... must be redacted)
			expect(findingsMd).not.toContain("token_secret_1234567890abcdef");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("handles safe small artifact copying and large artifact safe referencing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-art-test-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "app.bin");

			// Create a small script artifact (< 1 MiB)
			const scriptPath = path.join(tempDir, "hook.js");
			await fs.writeFile(
				scriptPath,
				"// Frida hook script\nInterceptor.attach(ptr('0x401000'), { onEnter: function() {} });\n",
				"utf8",
			);

			// Create a small dump artifact (< 1 MiB)
			const dumpPath = path.join(tempDir, "sections.dump");
			await fs.writeFile(dumpPath, ".text 0x400000 0x1000\n.data 0x401000 0x200\n", "utf8");

			// Create a large binary file (> 1 MiB)
			const largePath = path.join(tempDir, "huge_firmware.bin");
			const largeBuf = Buffer.alloc(1024 * 1024 + 1024, 0x41); // > 1 MiB
			await fs.writeFile(largePath, largeBuf);

			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);

			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "ELF",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "completed",
				artifact_refs: [
					scriptPath,
					dumpPath,
					largePath,
					"artifact://session_virtual_art_123",
				],
			});

			const exportRes = await workflowTool.execute({
				action: "export",
				workflow_id: workflowId,
				to_workspace: true,
			});

			expect(exportRes.details.workspace_manifest).toBeDefined();
			const manifest = exportRes.details.workspace_manifest as ReverseWorkspaceManifest;

			// Check small script was copied
			const scriptArt = manifest.artifacts.find(a => a.id === scriptPath);
			expect(scriptArt?.copied).toBe(true);
			expect(scriptArt?.kind).toBe("script");
			expect(scriptArt?.destination_path).toBe("scripts/hook.js");

			// Check small dump was copied
			const dumpArt = manifest.artifacts.find(a => a.id === dumpPath);
			expect(dumpArt?.copied).toBe(true);
			expect(dumpArt?.kind).toBe("dump");
			expect(dumpArt?.destination_path).toBe("dumps/sections.dump");

			// Check large binary was NOT copied (preserved by reference)
			const largeArt = manifest.artifacts.find(a => a.id === largePath);
			expect(largeArt?.copied).toBe(false);
			expect(largeArt?.reason).toBe("exceeds_safe_size_limit");

			// Check virtual artifact was preserved by reference
			const virtArt = manifest.artifacts.find(a => a.id === "artifact://session_virtual_art_123");
			expect(virtArt?.copied).toBe(false);
			expect(virtArt?.reason).toBe("session_artifact");

			// Verify copied files actually exist on disk in .rea/scripts and .rea/dumps
			const wsDir = path.join(tempDir, DEFAULT_WORKSPACE_DIR);
			const copiedScriptExists = await fs
				.stat(path.join(wsDir, "scripts/hook.js"))
				.then(s => s.isFile())
				.catch(() => false);
			expect(copiedScriptExists).toBe(true);

			const copiedDumpExists = await fs
				.stat(path.join(wsDir, "dumps/sections.dump"))
				.then(s => s.isFile())
				.catch(() => false);
			expect(copiedDumpExists).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes status, manifest, and clean actions using ReverseWorkspaceTool", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-mgmt-test-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "client.exe");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			// Initial status before export: workspace does not exist
			const preStatus = await workspaceTool.execute({
				action: "status",
			});
			expect(preStatus.details.inspection?.exists).toBe(false);

			// Create and export workflow
			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "PE",
				goal: "Analyze client authentication",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			// Add a dump file to test clean
			const dumpFile = path.join(tempDir, "temp_mem.dump");
			await fs.writeFile(dumpFile, "00 01 02 03\n", "utf8");

			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "completed",
				artifact_refs: [dumpFile],
			});

			await workspaceTool.execute({
				action: "export",
				workflow_id: workflowId,
			});

			// Status after export: valid workspace exists
			const postStatus = await workspaceTool.execute({
				action: "status",
			});
			expect(postStatus.details.inspection?.exists).toBe(true);
			expect(postStatus.details.inspection?.valid).toBe(true);
			expect(postStatus.details.manifest?.workflow.id).toBe(workflowId);

			// Read manifest directly
			const manifestRes = await workspaceTool.execute({
				action: "manifest",
			});
			expect(manifestRes.details.manifest?.workflow.id).toBe(workflowId);
			expect(manifestRes.details.manifest?.target.name).toBe("client.exe");

			// Clean workspace dumps
			const cleanRes = await workspaceTool.execute({
				action: "clean",
				clean_dumps_only: true,
			});
			expect(cleanRes.details.clean_result?.removed_files).toContain("dumps/temp_mem.dump");

			// Manifest and reports must still exist after clean
			const postCleanStatus = await workspaceTool.execute({
				action: "status",
			});
			expect(postCleanStatus.details.inspection?.exists).toBe(true);
			expect(postCleanStatus.details.inspection?.valid).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("prevents unexpected workspace writes during normal intermediate workflow steps", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-no-unexp-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "library.so");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);

			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "ELF",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			// Intermediate record step
			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "running",
			});

			// Verify .rea/ was NOT created unexpectedly
			const wsDir = path.join(tempDir, DEFAULT_WORKSPACE_DIR);
			const wsExists = await fs.stat(wsDir).then(() => true).catch(() => false);
			expect(wsExists).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("deterministically avoids artifact basename collisions and preserves all files and manifest refs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-collision-test-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "service.exe");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "PE",
				goal: "Collision avoidance test",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			// Create two different source script files with identical basenames in separate dirs
			const subA = path.join(tempDir, "module_a");
			const subB = path.join(tempDir, "module_b");
			const subC = path.join(tempDir, "module_c");
			await fs.mkdir(subA, { recursive: true });
			await fs.mkdir(subB, { recursive: true });
			await fs.mkdir(subC, { recursive: true });

			const scriptA = path.join(subA, "hook.js");
			const scriptB = path.join(subB, "hook.js");
			const dumpA = path.join(subA, "memory.dump");
			const dumpB = path.join(subB, "memory.dump");
			const dumpC = path.join(subC, "memory.dump");

			await fs.writeFile(scriptA, "console.log('hook A');", "utf8");
			await fs.writeFile(scriptB, "console.log('hook B');", "utf8");
			await fs.writeFile(dumpA, "DUMP_A_DATA", "utf8");
			await fs.writeFile(dumpB, "DUMP_B_DATA", "utf8");
			await fs.writeFile(dumpC, "DUMP_C_DATA", "utf8");

			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_1",
				status: "completed",
				artifact_refs: [scriptA, dumpA],
			});

			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "pe_step_2",
				status: "completed",
				artifact_refs: [scriptB, dumpB, dumpC],
			});

			const exportRes = await workspaceTool.execute({
				action: "export",
				workflow_id: workflowId,
			});

			const manifest = exportRes.details.manifest;
			expect(manifest).toBeDefined();
			if (!manifest) throw new Error("Manifest missing");

			// Check all 5 artifacts were copied with collision-free paths
			const artScriptA = manifest.artifacts.find(a => a.id === scriptA);
			const artScriptB = manifest.artifacts.find(a => a.id === scriptB);
			const artDumpA = manifest.artifacts.find(a => a.id === dumpA);
			const artDumpB = manifest.artifacts.find(a => a.id === dumpB);
			const artDumpC = manifest.artifacts.find(a => a.id === dumpC);

			expect(artScriptA?.destination_path).toBe("scripts/hook.js");
			expect(artScriptB?.destination_path).toBe("scripts/hook_1.js");
			expect(artDumpA?.destination_path).toBe("dumps/memory.dump");
			expect(artDumpB?.destination_path).toBe("dumps/memory_1.dump");
			expect(artDumpC?.destination_path).toBe("dumps/memory_2.dump");

			const wsDir = path.join(tempDir, DEFAULT_WORKSPACE_DIR);

			// Verify all 5 files physically exist on disk and have distinct content
			const contentScriptA = await fs.readFile(path.join(wsDir, "scripts/hook.js"), "utf8");
			const contentScriptB = await fs.readFile(path.join(wsDir, "scripts/hook_1.js"), "utf8");
			const contentDumpA = await fs.readFile(path.join(wsDir, "dumps/memory.dump"), "utf8");
			const contentDumpB = await fs.readFile(path.join(wsDir, "dumps/memory_1.dump"), "utf8");
			const contentDumpC = await fs.readFile(path.join(wsDir, "dumps/memory_2.dump"), "utf8");

			expect(contentScriptA).toBe("console.log('hook A');");
			expect(contentScriptB).toBe("console.log('hook B');");
			expect(contentDumpA).toBe("DUMP_A_DATA");
			expect(contentDumpB).toBe("DUMP_B_DATA");
			expect(contentDumpC).toBe("DUMP_C_DATA");

			// Verify manifest.files has distinct entries for all 5
			const manifestPaths = manifest.files.map(f => f.path);
			expect(manifestPaths).toContain("scripts/hook.js");
			expect(manifestPaths).toContain("scripts/hook_1.js");
			expect(manifestPaths).toContain("dumps/memory.dump");
			expect(manifestPaths).toContain("dumps/memory_1.dump");
			expect(manifestPaths).toContain("dumps/memory_2.dump");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("cleanWorkspace validates manifest ownership and rejects plain dirs, root, and traversal", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-safety-test-"));

		try {
			// 1. Plain directory without manifest
			const plainDir = path.join(tempDir, "plain_folder");
			await fs.mkdir(plainDir, { recursive: true });
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "plain_folder" }),
			).rejects.toThrow();

			// 2. Project root itself
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "." }),
			).rejects.toThrow("project directory itself");

			// 3. Filesystem root
			const root = path.parse(tempDir).root;
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: root }),
			).rejects.toThrow();

			// 4. Path traversal outside project directory
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "../../some_escape" }),
			).rejects.toThrow();

			// 5. Corrupted manifest (missing required ownership fields)
			const fakeWs = path.join(tempDir, "fake_ws");
			await fs.mkdir(fakeWs, { recursive: true });
			await fs.writeFile(
				path.join(fakeWs, WORKSPACE_FILES.MANIFEST),
				JSON.stringify({ schema_version: "1.0.0", not_a_real_manifest: true }),
				"utf8",
			);
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "fake_ws" }),
			).rejects.toThrow();
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("cleanWorkspace rejects symlink escapes with realpath containment", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-symlink-test-"));
		const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-outside-"));

		try {
			// Create a valid workspace in tempDir
			const targetFile = await createTargetFixture(tempDir, "symtarget.elf");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "ELF",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			await workspaceTool.execute({
				action: "export",
				workflow_id: workflowId,
			});

			const realWs = path.join(tempDir, DEFAULT_WORKSPACE_DIR);

			// 1. Workspace dir symlinked to outside directory
			const symlinkedWs = path.join(tempDir, "symlinked_ws");
			await fs.symlink(outsideDir, symlinkedWs);
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "symlinked_ws" }),
			).rejects.toThrow();

			// 2. Subdirectory in workspace symlinked to outside directory
			const dumpSymlinkDir = path.join(tempDir, "escaped_ws");
			await fs.cp(realWs, dumpSymlinkDir, { recursive: true });
			await fs.rm(path.join(dumpSymlinkDir, "dumps"), { recursive: true, force: true });
			await fs.symlink(outsideDir, path.join(dumpSymlinkDir, "dumps"));
			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "escaped_ws" }),
			).rejects.toThrow("Symlink escape detected");

			// 3. Symlink file escaping workspace directory
			const fileSymlinkWs = path.join(tempDir, "file_symlink_ws");
			await fs.cp(realWs, fileSymlinkWs, { recursive: true });
			const outsideFile = path.join(outsideDir, "secret.txt");
			await fs.writeFile(outsideFile, "SECRET", "utf8");
			// Add file symlink inside dumps pointing to outsideFile
			await fs.symlink(outsideFile, path.join(fileSymlinkWs, "dumps/escaped.dump"));
			// Update manifest to index this file
			const manifestPath = path.join(fileSymlinkWs, WORKSPACE_FILES.MANIFEST);
			const mData = JSON.parse(await fs.readFile(manifestPath, "utf8")) as ReverseWorkspaceManifest;
			mData.artifacts.push({
				id: outsideFile,
				destination_path: "dumps/escaped.dump",
				kind: "dump",
				copied: true,
			});
			mData.files.push({
				path: "dumps/escaped.dump",
				size_bytes: 6,
				sha256: "dummy",
			});
			await fs.writeFile(manifestPath, JSON.stringify(mData), "utf8");

			await expect(
				cleanWorkspace({ projectDir: tempDir, workspaceDir: "file_symlink_ws" }),
			).rejects.toThrow("Symlink escape detected");
			// Verify outsideFile was NOT deleted
			expect(await fs.stat(outsideFile).then(() => true).catch(() => false)).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
			await removeWithRetries(outsideDir);
		}
	});

	it("cleanWorkspace only deletes manifest-indexed files and preserves unindexed files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rea-unindexed-test-"));

		try {
			const targetFile = await createTargetFixture(tempDir, "app.bin");
			const session = createTestSession(tempDir);
			const workflowTool = new ReverseWorkflowTool(session);
			const workspaceTool = new ReverseWorkspaceTool(session);

			const createRes = await workflowTool.execute({
				action: "create",
				target: targetFile,
				format: "RawBinary",
			});
			const workflowId = createRes.details.workflow?.id;
			if (!workflowId) throw new Error("Workflow id missing");

			const indexedDump = path.join(tempDir, "indexed.dump");
			const indexedScript = path.join(tempDir, "indexed.js");
			await fs.writeFile(indexedDump, "INDEXED DUMP CONTENT", "utf8");
			await fs.writeFile(indexedScript, "console.log('indexed');", "utf8");

			await workflowTool.execute({
				action: "record",
				workflow_id: workflowId,
				step_id: "elf_step_1",
				status: "completed",
				artifact_refs: [indexedDump, indexedScript],
			});

			await workspaceTool.execute({
				action: "export",
				workflow_id: workflowId,
			});

			const wsDir = path.join(tempDir, DEFAULT_WORKSPACE_DIR);

			// Manually create UNINDEXED files in dumps/ and scripts/
			const unindexedDump = path.join(wsDir, "dumps/user_manual_backup.dump");
			const unindexedScript = path.join(wsDir, "scripts/user_custom_tool.js");
			await fs.writeFile(unindexedDump, "DO NOT DELETE THIS DUMP", "utf8");
			await fs.writeFile(unindexedScript, "DO NOT DELETE THIS SCRIPT", "utf8");

			// Clean workspace (both dumps and scripts)
			const cleanRes = await cleanWorkspace({
				projectDir: tempDir,
				removeDumpsOnly: false,
			});

			// Indexed files must be removed
			expect(cleanRes.removed_files).toContain("dumps/indexed.dump");
			expect(cleanRes.removed_files).toContain("scripts/indexed.js");

			// Unindexed files must NOT be in removed_files
			expect(cleanRes.removed_files).not.toContain("dumps/user_manual_backup.dump");
			expect(cleanRes.removed_files).not.toContain("scripts/user_custom_tool.js");

			// Unindexed files must physically still exist on disk!
			const dumpStillExists = await fs.stat(unindexedDump).then(() => true).catch(() => false);
			const scriptStillExists = await fs.stat(unindexedScript).then(() => true).catch(() => false);
			expect(dumpStillExists).toBe(true);
			expect(scriptStillExists).toBe(true);

			// Core report/manifest files must be preserved
			expect(cleanRes.preserved_files).toContain("target/target.json");
			expect(cleanRes.preserved_files).toContain("reports/workflow_report.md");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
