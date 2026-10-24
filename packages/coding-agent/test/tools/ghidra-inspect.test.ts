import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import {
	GhidraInspectTool,
	ghidraDependency,
	type GhidraRunResult,
	type GhidraRunner,
	type ToolSession,
} from "@reverse/coding-agent/tools";
import { ACTIVE_GHIDRA_PROJECTS } from "../../src/tools/native-mcp-session";
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

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.flatMap(item => (item.type === "text" && item.text ? [item.text] : [])).join("\n");
}

function compactFrame(payload: Record<string, unknown>): string {
	return `<<<REVERSE_GHIDRA_OUTPUT_START>>>${JSON.stringify(payload)}<<<REVERSE_GHIDRA_OUTPUT_END>>>\n`;
}
function mockRunner(
	stdout: string,
	overrides: Partial<GhidraRunResult> = {},
): { runner: GhidraRunner; calls: Array<{ binary: string; args: string[] }> } {
	const calls: Array<{ binary: string; args: string[] }> = [];
	const runner: GhidraRunner = async (binary, args) => {
		calls.push({ binary, args });
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

describe("ghidra_inspect path and parameter validation", () => {
	it("rejects non-existent binary path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-missing-file-"));
		try {
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { action: "info", path: "missing.bin" })).rejects.toThrow(
				"Target file not found",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects directory target", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-dir-"));
		try {
			const tool = new GhidraInspectTool(createTestSession(tempDir));
			await expect(tool.execute("call-1", { action: "info", path: "." })).rejects.toThrow("is a directory");
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
			expect(res.details.fallback?.suggestedFallback).toContain("r2_inspect");

			const text = textOf(res);
			expect(text).toContain("[Notice] Primary tool 'ghidra'");
			expect(text).toContain("reverse setup reverse ghidra");
			expect(text).toContain("r2_inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("ghidra_inspect transport and boundary handling", () => {
	it("isolates result from log pollution and strips bootstrap noise", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-pollute-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const polluted = [
				"INFO  Opening existing project: /tmp/proj (HeadlessAnalyzer)",
				"ReverseGhidraInspect.java> INFO  Starting headless script (GhidraScript)",
				"INFO  Importing file: sample.bin (HeadlessAnalyzer)",
				compactFrame({
					status: "ok",
					action: "decompile",
					target: "main",
					address: "0x00401000",
					signature: "int main(void)",
					output: "int main(void) {\n    return 0;\n}",
				}),
				"INFO  REPORT: Analysis succeeded for file: sample.bin (HeadlessAnalyzer)",
			].join("\n");

			const { runner } = mockRunner(polluted);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "main",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.target).toBe("main");
			expect(res.details.address).toBe("0x00401000");

			const text = textOf(res);
			expect(text).toBe("int main(void) {\n    return 0;\n}");
			expect(text).not.toContain("HeadlessAnalyzer");
			expect(text).not.toContain("ReverseGhidraInspect.java>");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("treats empty pseudocode payload as error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-empty-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const payload = compactFrame({
				status: "ok",
				action: "decompile",
				target: "stub",
				output: "   \n\t  ",
			});

			const { runner } = mockRunner(payload);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "stub",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("empty output");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("treats stream truncation as failure even if markers were seen", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-trunc-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner } = mockRunner(compactFrame({ status: "ok", action: "decompile", output: "int foo" }), {
				truncated: true,
			});
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "foo",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.truncated).toBe(true);
			expect(res.details.error).toContain("truncated");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("treats timeout as failure", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-timeout-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner } = mockRunner("", { timedOut: true });
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "foo",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.timedOut).toBe(true);
			expect(res.details.error).toContain("timed out");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects malformed json between frame markers as error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-badjson-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner } = mockRunner(
				"<<<REVERSE_GHIDRA_OUTPUT_START>>>{not_valid_json}<<<REVERSE_GHIDRA_OUTPUT_END>>>",
			);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "foo",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("without producing decompiler script output");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects payload with mismatched action as error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-wrongaction-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const mismatched = compactFrame({
				status: "ok",
				action: "export",
				output: "# Mismatched export data",
			});

			const { runner } = mockRunner(mismatched);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "foo",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("Script action mismatch");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("propagates structured target-not-found error", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-notfound-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const notFoundPayload = compactFrame({
				status: "error",
				code: "TARGET_NOT_FOUND",
				error: "Function target 'missing_symbol' was not found in binary 'sample.bin'.",
			});

			const { runner } = mockRunner(notFoundPayload);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "missing_symbol",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("missing_symbol");
			expect(textOf(res)).toContain("missing_symbol");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports folding and pagination on envelope lines", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-page-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const envelope = ["Header", "\u001b[31mLine A\u001b[0m", "", "Line A", "Line B", "Line C", "Line D"].join(
				"\n",
			);

			const payload = compactFrame({
				status: "ok",
				action: "export",
				output: envelope,
			});

			const { runner } = mockRunner(payload);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "export",
				path: "sample.bin",
				mode: "fold",
				offset: 1,
				limit: 2,
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.returnedLines).toBe(2);
			expect(res.details.hasMore).toBe(true);

			const text = textOf(res);
			expect(text).toContain("Line A");
			expect(text).toContain("Line B");
			expect(text).not.toContain("Line C");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("fails with error status when engine exits 0 without producing script output", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-nooutput-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const { runner } = mockRunner("INFO  Engine finished without running postScript\n");
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "main",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("without producing decompiler script output");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("parses output containing literal start and end delimiter tokens", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-delim-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-dummy", "utf8");

			const trickyCode = [
				"void check_tokens() {",
				'    const char *a = "<<<REVERSE_GHIDRA_OUTPUT_END>>>";',
				'    const char *b = "<<<REVERSE_GHIDRA_OUTPUT_START>>>";',
				"}",
			].join("\n");

			// Simulate Java script encoding where < is escaped as \u003c and > as \u003e
			const encodedCode = trickyCode.replace(/</g, "\\u003c").replace(/>/g, "\\u003e");
			const jsonString = `{"status":"ok","action":"decompile","target":"check_tokens","output":"${encodedCode.replace(/"/g, '\\"').replace(/\n/g, "\\n")}"}`;
			const frame = `<<<REVERSE_GHIDRA_OUTPUT_START>>>${jsonString}<<<REVERSE_GHIDRA_OUTPUT_END>>>\n`;

			const { runner } = mockRunner(frame);
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				which: () => "/opt/ghidra/support/analyzeHeadless",
				runner,
			});

			const res = await tool.execute("call-1", {
				action: "decompile",
				path: "sample.bin",
				symbol: "check_tokens",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.target).toBe("check_tokens");
			const text = textOf(res);
			expect(text).toContain('const char *a = "<<<REVERSE_GHIDRA_OUTPUT_END>>>";');
			expect(text).toContain('const char *b = "<<<REVERSE_GHIDRA_OUTPUT_START>>>";');
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
describe("ghidra_inspect jni_enrich and findcrypt actions", () => {
	it("previews JNI enrichment from confirmed RegisterNatives event without spawning Ghidra", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-jni-preview-"));
		try {
			const sample = path.join(tempDir, "libnative.so");
			await fs.writeFile(sample, "ELF-mock-content", "utf8");

			const { runner, calls } = mockRunner("");
			const tool = new GhidraInspectTool(createTestSession(tempDir), { runner });

			const res = await tool.execute("call-1", {
				action: "jni_enrich",
				path: "libnative.so",
				events: [
					{
						event: "jni_register_natives",
						status: "confirmed",
						retval: 0,
						class: "com.example.app.NativeAuth",
						methods: [
							{
								name: "verifyToken",
								signature: "(Ljava/lang/String;)Z",
								fnPtr: "0x7f001000",
								base: "0x7f000000",
							},
						],
					},
				],
				preview: true,
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.enrichment?.total).toBe(1);
			expect(res.details.enrichment?.eligible).toBe(1);
			expect(res.details.enrichment?.items[0].targetFunctionName).toBe(
				"Java_com_example_app_NativeAuth_verifyToken",
			);
			expect(textOf(res)).toContain("JNI Registration Enrichment Preview");
			// Preview mode must NOT spawn Ghidra runner
			expect(calls.length).toBe(0);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects JNI writeback (preview: false) without designated project_dir", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-jni-noproj-"));
		try {
			const sample = path.join(tempDir, "libnative.so");
			await fs.writeFile(sample, "ELF-mock-content", "utf8");
			const tool = new GhidraInspectTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "jni_enrich",
					path: "libnative.so",
					records: [
						{
							className: "com/example/Native",
							methodName: "test",
							signature: "()V",
							moduleName: "libnative.so",
							functionAddress: "0x1000",
							status: "confirmed",
							source: "frida",
							isStatic: true,
						},
					],
					preview: false,
				}),
			).rejects.toBeInstanceOf(ToolError);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects JNI writeback when project directory is locked by active native session", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-jni-locked-"));
		try {
			const sample = path.join(tempDir, "libnative.so");
			await fs.writeFile(sample, "ELF-mock-content", "utf8");
			const projDir = path.join(tempDir, "my-ghidra-proj");
			await fs.mkdir(projDir, { recursive: true });

			// Simulate locked project by active session
			ACTIVE_GHIDRA_PROJECTS.set(path.resolve(projDir), {
				projectDir: path.resolve(projDir),
				ownerKey: {},
				sessionId: "native_ghidra_test_lock",
			});

			const tool = new GhidraInspectTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "jni_enrich",
					path: "libnative.so",
					project_dir: "my-ghidra-proj",
					records: [
						{
							className: "com/example/Native",
							methodName: "test",
							signature: "()V",
							moduleName: "libnative.so",
							functionAddress: "0x1000",
							status: "confirmed",
							source: "frida",
							isStatic: true,
						},
					],
					preview: false,
				}),
			).rejects.toBeInstanceOf(ToolError);
		} finally {
			ACTIVE_GHIDRA_PROJECTS.clear();
			await removeWithRetries(tempDir);
		}
	});

	it("rejects JNI writeback when receiver kind is unverified", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-jni-unverified-"));
		try {
			const sample = path.join(tempDir, "libnative.so");
			await fs.writeFile(sample, "ELF-mock-content", "utf8");
			const projDir = path.join(tempDir, "my-ghidra-proj");
			await fs.mkdir(projDir, { recursive: true });

			const tool = new GhidraInspectTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "jni_enrich",
					path: "libnative.so",
					project_dir: "my-ghidra-proj",
					records: [
						{
							className: "com/example/Native",
							methodName: "test",
							signature: "()V",
							moduleName: "libnative.so",
							functionAddress: "0x1000",
							status: "confirmed",
							source: "frida",
							// isStatic undefined: unverified receiver kind!
						},
					],
					preview: false,
				}),
			).rejects.toBeInstanceOf(ToolError);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns missing dependency notice when FindCrypt extension is not installed", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-findcrypt-missing-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-sample", "utf8");

			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				findCryptStatus: {
					available: false,
					ghidraFound: true,
					installHint: "Run 'reverse setup reverse ghidra-findcrypt'",
				},
			});

			const res = await tool.execute("call-1", {
				action: "findcrypt",
				path: "sample.bin",
			});

			expect(res.details.dependency?.available).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("invokes installed FindCrypt and returns candidate constants with heuristic disclaimer", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-findcrypt-ok-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			await fs.writeFile(sample, "ELF-sample", "utf8");

			const mockPayload = {
				status: "ok",
				action: "findcrypt",
				output: JSON.stringify([
					{ address: "0x00014104", algorithm: "AES_Encryption_SBox", matchType: "bookmark" },
					{ address: "0x00014004", algorithm: "AES_Decryption_SBox_Inverse", matchType: "bookmark" },
				]),
			};

			const { runner } = mockRunner(compactFrame(mockPayload));
			const tool = new GhidraInspectTool(createTestSession(tempDir), {
				runner,
				which: () => "/usr/bin/analyzeHeadless",
				findCryptStatus: {
					available: true,
					ghidraFound: true,
					extensionDir: "/opt/ghidra/Ghidra/Extensions/FindCrypt",
					jarPath: "/opt/ghidra/Ghidra/Extensions/FindCrypt/FindCrypt.jar",
				},
			});

			const res = await tool.execute("call-1", {
				action: "findcrypt",
				path: "sample.bin",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.cryptoCandidates?.length).toBe(2);
			expect(res.details.cryptoCandidates?.[0].algorithm).toBe("AES_Encryption_SBox");
			expect(res.details.cryptoCandidates?.[0].address).toBe("0x00014104");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("ghidra_inspect live engine integration", () => {
	const dep = ghidraDependency();
	const liveIt = dep.available ? it : it.skip;

	liveIt("runs actual headless info against host Ghidra", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "ghidra-live-"));
		try {
			const sample = path.join(tempDir, "sample.bin");
			// Tiny valid ELF binary buffer
			const elfHeader = Buffer.from([
				0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
				0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
			]);
			await fs.writeFile(sample, elfHeader);

			const tool = new GhidraInspectTool(createTestSession(tempDir));
			const res = await tool.execute("call-1", {
				action: "info",
				path: "sample.bin",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.dependency?.available).toBe(true);
			expect(textOf(res)).toContain("Ghidra Headless Bridge Status:");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
