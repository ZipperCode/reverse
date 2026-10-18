import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@rva/coding-agent/config/settings";
import {
	createTools,
	foldGhidraText,
	GhidraInspectTool,
	type GhidraInspectDetails,
	type GhidraRunResult,
	type GhidraRunner,
	type ToolSession,
} from "@rva/coding-agent/tools";
import { BUILTIN_TOOL_NAMES } from "@rva/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@rva/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

interface CapturedInvocation {
	binary: string;
	args: string[];
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	};
}

function mockRunner(
	stdout: string,
	overrides: Partial<GhidraRunResult> = {},
): { runner: GhidraRunner; calls: CapturedInvocation[] } {
	const calls: CapturedInvocation[] = [];
	const runner: GhidraRunner = async (binary, args, options) => {
		calls.push({ binary, args, options });
		return {
			stdout,
			stderr: "",
			exitCode: 0,
			outputBytes: Buffer.byteLength(stdout),
			truncated: false,
			timedOut: false,
			...overrides,
		};
	};
	return { runner, calls };
}

describe("ghidra_inspect registration", () => {
	it("is registered as a builtin tool", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("ghidra_inspect");
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["ghidra_inspect"]);
			const tool = tools.find(t => t.name === "ghidra_inspect") as GhidraInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("Ghidra Inspect");
			expect(tool?.approval).toBe("read");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("ghidra_inspect path and parameter validation", () => {
	it("rejects non-existent binary path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-missing-file-"));
		try {
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", { action: "info", path: "missing.bin" }),
			).rejects.toThrow("Target file not found");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-dir-"));
		try {
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", { action: "info", path: "." }),
			).rejects.toThrow("is a directory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects invalid symbols containing shell metacharacters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-sym-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", {
					action: "decompile",
					path: "sample.bin",
					symbol: "main; rm -rf /",
				}),
			).rejects.toThrow("Invalid symbol or function identifier");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects invalid address strings", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-addr-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", {
					action: "decompile",
					path: "sample.bin",
					address: "invalid_address_hex",
				}),
			).rejects.toThrow("Invalid virtual address format");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects suspicious script names", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-script-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(
				tool.execute("call-1", {
					action: "analyze",
					path: "sample.bin",
					script: "script.py; calc.exe",
				}),
			).rejects.toThrow("Invalid script name");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("ghidra_inspect missing dependency handling", () => {
	it("returns structured missing dependency notice with catalog install hints and fallbacks", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-dep-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => null,
				ghidraInstallDir: "",
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "main",
			});

			expect(res.details.status).toBe("missing_dependency");
			expect(res.details.dependency?.available).toBe(false);
			expect(res.details.dependency?.binary).toBe("analyzeHeadless");
			expect(res.details.fallback?.primary).toBe("ghidra");
			expect(res.details.fallback?.suggestedFallback).toContain("r2_inspect");
			expect(res.details.fallback?.executed).toBe(false);

			expect(res.content[0].text).toContain("[Notice] Primary tool 'ghidra'");
			expect(res.content[0].text).toContain("r2_inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("ghidra_inspect actions and argv construction", () => {
	it("handles info action without running analyzeHeadless", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-info-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner, calls } = mockRunner("");
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: cmd => (cmd === "analyzeHeadless" ? "/opt/ghidra/support/analyzeHeadless" : null),
				runner,
			});

			const res = await tool.execute("call-1", { action: "info", path: "sample.bin" });

			expect(res.details.status).toBe("ok");
			expect(res.details.dependency?.available).toBe(true);
			expect(calls.length).toBe(0); // Info does not spawn a heavy headless process
			expect(res.content[0].text).toContain("Ghidra Headless Bridge Status:");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("constructs correct argv for analyze action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-analyze-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const fakeOutput = "ANALYSIS COMPLETE: Found 12 functions\n";
			const { runner, calls } = mockRunner(fakeOutput);

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "analyze",
				path: "sample.bin",
			});

			expect(res.details.status).toBe("ok");
			expect(calls.length).toBe(1);
			const call = calls[0];
			expect(call.binary).toBe("/opt/ghidra/support/analyzeHeadless");
			expect(call.args).toContain("-import");
			expect(call.args).toContain(path.resolve(tempDir, "sample.bin"));
			expect(call.args).toContain("-readOnly");
			expect(call.args).toContain("-deleteProject");
			expect(res.content[0].text).toContain("ANALYSIS COMPLETE");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("constructs correct argv for decompile action with post-script", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-decompile-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const fakeDecompile = "int main(int argc, char **argv) {\n    return 0;\n}\n";
			const { runner, calls } = mockRunner(fakeDecompile);

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "main",
				script: "Decompile.java",
			});

			expect(res.details.status).toBe("ok");
			expect(calls.length).toBe(1);
			const call = calls[0];
			expect(call.args).toContain("-postScript");
			expect(call.args).toContain("Decompile.java");
			expect(call.args).toContain("main");
			expect(res.content[0].text).toContain("int main");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports mode: fold to collapse whitespace and ANSI escapes", () => {
		const raw = "\u001b[32mline 1\u001b[0m\n\nline 1\nline 2   \n";
		const folded = foldGhidraText(raw);
		expect(folded).toBe("line 1\nline 2");
	});

	it("supports line pagination via offset and limit", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-page-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const multiLineOutput = Array.from({ length: 50 }, (_, i) => `Line ${i + 1}`).join("\n");
			const { runner } = mockRunner(multiLineOutput);

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "analyze",
				path: "sample.bin",
				offset: 10,
				limit: 5,
			});

			expect(res.details.totalLines).toBe(50);
			expect(res.details.returnedLines).toBe(5);
			expect(res.details.offset).toBe(10);
			expect(res.details.hasMore).toBe(true);
			expect(res.content[0].text).toContain("Line 11");
			expect(res.content[0].text).toContain("Line 15");
			expect(res.content[0].text).not.toContain("Line 10");
			expect(res.content[0].text).not.toContain("Line 16");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports process failure exit codes cleanly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-fail-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner } = mockRunner("", {
				stderr: "ERROR: Out of memory",
				exitCode: 137,
			});

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "analyze",
				path: "sample.bin",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("137");
			expect(res.content[0].text).toContain("ERROR: Out of memory");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
