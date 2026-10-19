import type { AgentToolResult } from "@reverse/agent";
import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, BinaryDiffTool, type ToolSession } from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

function textOf(result: AgentToolResult<unknown>): string {
	return result.content
		.flatMap(item => (item.type === "text" ? [item.text] : []))
		.join("\n")
		.trim();
}

// ============================================================================
// Registration and Discovery
// ============================================================================

describe("binary_diff registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("binary_diff");
		expect(normalizeToolName("binary_diff")).toBe("binary_diff");
		expect(normalizeToolName("bindiff")).toBe("binary_diff");
		expect(normalizeToolName("bin_diff")).toBe("binary_diff");
		expect(normalizeToolName("binary_compare")).toBe("binary_diff");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-disc-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["binary_diff"]);
			const tool = tools.find(t => t.name === "binary_diff") as BinaryDiffTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("binary_diff");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("Binary Diff");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Safety and Validation
// ============================================================================

describe("binary_diff safety and path validation", () => {
	it("rejects when path_a or path_b is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-val-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);
			await expect(tool.execute("call-1", { path_a: "fileA.bin" })).rejects.toThrow(
				"Both 'path_a' (or path1) and 'path_b'",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects identical paths safely", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-same-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);
			const filePath = path.join(tempDir, "sample.bin");
			await fs.writeFile(filePath, Buffer.from([1, 2, 3, 4]));

			await expect(tool.execute("call-1", { path_a: "sample.bin", path_b: "sample.bin" })).rejects.toThrow(
				"identical path provided",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects symlinks resolving to the same underlying file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-symlink-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);
			const original = path.join(tempDir, "real.bin");
			const link = path.join(tempDir, "link.bin");
			await fs.writeFile(original, Buffer.from("test payload"));
			await fs.symlink(original, link);

			await expect(tool.execute("call-1", { path_a: "real.bin", path_b: "link.bin" })).rejects.toThrow(
				"resolve to the exact same file",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-existent file path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-notfound-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);
			const existing = path.join(tempDir, "existing.bin");
			await fs.writeFile(existing, Buffer.from("existing"));

			await expect(tool.execute("call-1", { path_a: "existing.bin", path_b: "nonexistent.bin" })).rejects.toThrow(
				"File B not found",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-dir-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);
			const file = path.join(tempDir, "file.bin");
			await fs.writeFile(file, Buffer.from("payload"));

			await expect(tool.execute("call-1", { path_a: "file.bin", path_b: "." })).rejects.toThrow(
				"Directories are not supported",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Identical and Differing Files
// ============================================================================

describe("binary_diff comparison execution", () => {
	it("detects identical files with 100% similarity and 0 differing bytes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-ident-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);

			const data = Buffer.from("Hello, World! Binary Diff test file content 12345.");
			await fs.writeFile(path.join(tempDir, "copyA.bin"), data);
			await fs.writeFile(path.join(tempDir, "copyB.bin"), data);

			const result = await tool.execute("call-1", { path_a: "copyA.bin", path_b: "copyB.bin" });

			expect(result.details.isIdentical).toBe(true);
			expect(result.details.similarityPercent).toBe(100.0);
			expect(result.details.totalDifferingBytes).toBe(0);
			expect(result.details.fileA.sha256).toBe(result.details.fileB.sha256);
			expect(result.details.fileA.md5).toBe(result.details.fileB.md5);

			const text = textOf(result);
			expect(text).toContain("✅ Identical");
			expect(text).toContain("100.00%");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports deterministic delta, block status, and byte regions for differing files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-diff-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);

			// 64 bytes in file A
			const bufA = Buffer.alloc(64, 0x41); // 'A's
			// File B: differs at offset 10..14 (4 bytes), and has 8 extra bytes
			const bufB = Buffer.alloc(72, 0x41);
			bufB[10] = 0x58; // 'X'
			bufB[11] = 0x59; // 'Y'
			bufB[12] = 0x5a; // 'Z'
			bufB[13] = 0x21; // '!'

			await fs.writeFile(path.join(tempDir, "fileA.bin"), bufA);
			await fs.writeFile(path.join(tempDir, "fileB.bin"), bufB);

			// 1. Summary action
			const summaryResult = await tool.execute("call-summary", {
				path_a: "fileA.bin",
				path_b: "fileB.bin",
				action: "summary",
				block_size: 32,
			});

			expect(summaryResult.details.isIdentical).toBe(false);
			expect(summaryResult.details.sizeDelta).toBe(8);
			expect(summaryResult.details.firstDifferenceOffset).toBe(10);
			expect(summaryResult.details.totalDifferingBytes).toBe(12); // 4 bytes changed + 8 bytes inserted
			expect(summaryResult.details.similarityPercent).toBeLessThan(100.0);

			const sumText = textOf(summaryResult);
			expect(sumText).toContain("Delta: **+8 B**");
			expect(sumText).toContain("0xa (10)");

			// 2. Blocks action
			const blocksResult = await tool.execute("call-blocks", {
				path_a: "fileA.bin",
				path_b: "fileB.bin",
				action: "blocks",
				block_size: 32,
			});
			expect(blocksResult.details.action).toBe("blocks");
			expect(blocksResult.details.blocks?.length).toBeGreaterThan(0);
			const modBlock = blocksResult.details.blocks?.find(b => b.status === "modified");
			expect(modBlock).toBeDefined();
			expect(modBlock?.offset).toBe(0);

			// 3. Bytes action
			const bytesResult = await tool.execute("call-bytes", {
				path_a: "fileA.bin",
				path_b: "fileB.bin",
				action: "bytes",
			});
			expect(bytesResult.details.action).toBe("bytes");
			expect(bytesResult.details.byteDiffs?.length).toBeGreaterThanOrEqual(1);

			const firstDiff = bytesResult.details.byteDiffs?.[0];
			expect(firstDiff?.offset).toBe(10);
			expect(firstDiff?.length).toBe(4);
			expect(firstDiff?.asciiB).toContain("XYZ!");

			const byteText = textOf(bytesResult);
			expect(byteText).toContain("0x00000a");
			expect(byteText).toContain("XYZ!");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("compares executable headers side-by-side in headers action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "diff-hdr-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new BinaryDiffTool(session);

			// File A: ELF64
			const elfA = Buffer.alloc(64, 0);
			elfA[0] = 0x7f;
			elfA[1] = 0x45;
			elfA[2] = 0x4c;
			elfA[3] = 0x46;
			elfA[4] = 2; // 64-bit
			elfA[5] = 1; // LE
			elfA.writeUInt16LE(62, 18); // x86_64
			await fs.writeFile(path.join(tempDir, "elf_x86.bin"), elfA);

			// File B: PE
			const peB = Buffer.alloc(128, 0);
			peB[0] = 0x4d;
			peB[1] = 0x5a;
			peB.writeUInt32LE(64, 0x3c); // e_lfanew = 64
			peB[64] = 0x50; // 'P'
			peB[65] = 0x45; // 'E'
			await fs.writeFile(path.join(tempDir, "win.exe"), peB);

			const hdrResult = await tool.execute("call-headers", {
				path_a: "elf_x86.bin",
				path_b: "win.exe",
				action: "headers",
			});

			expect(hdrResult.details.action).toBe("headers");
			expect(hdrResult.details.fileA.format).toBe("ELF");
			expect(hdrResult.details.fileB.format).toBe("PE");

			const hdrText = textOf(hdrResult);
			expect(hdrText).toContain("Format");
			expect(hdrText).toContain("ELF");
			expect(hdrText).toContain("PE");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
