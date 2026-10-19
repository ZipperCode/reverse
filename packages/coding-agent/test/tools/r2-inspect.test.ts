import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import {
	buildR2Args,
	buildR2Command,
	createTools,
	foldR2Text,
	R2InspectTool,
	type R2InspectAction,
	type R2InspectDetails,
	type R2RunResult,
	type R2Runner,
	type ToolSession,
} from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES } from "@reverse/coding-agent/tools/builtin-names";
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
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

function detailsOf(result: { details?: R2InspectDetails }): R2InspectDetails {
	return result.details ?? ({} as R2InspectDetails);
}

async function writeTarget(dir: string, name = "sample.bin"): Promise<string> {
	const filePath = path.join(dir, name);
	await fs.writeFile(filePath, "ELF-fake-binary-content", "utf8");
	return filePath;
}

function okRun(stdout: string, overrides: Partial<R2RunResult> = {}): R2RunResult {
	return {
		stdout,
		stderr: "",
		exitCode: 0,
		outputBytes: Buffer.byteLength(stdout),
		truncated: false,
		timedOut: false,
		...overrides,
	};
}

interface Captured {
	binary: string;
	args: string[];
	options: { cwd: string; timeoutMs: number; maxBytes: number; signal?: AbortSignal };
}

function fakeRunner(
	stdoutFor: (args: string[]) => string,
	overrides: Partial<R2RunResult> = {},
): { runner: R2Runner; calls: Captured[] } {
	const calls: Captured[] = [];
	const runner: R2Runner = async (binary, args, options) => {
		calls.push({ binary, args, options });
		return okRun(stdoutFor(args), overrides);
	};
	return { runner, calls };
}

function foundWhich(command: string): string | null {
	if (command === "r2" || command === "radare2") return "/opt/homebrew/bin/r2";
	return null;
}

const SECTIONS_JSON = JSON.stringify([
	{ name: ".text", vaddr: 4198400, paddr: 4096, vsize: 500, size: 500, perm: "r-x", type: "PROGBITS" },
	{ name: ".data", vaddr: 4198912, paddr: 5120, vsize: 64, size: 64, perm: "rw-", type: "PROGBITS" },
	{ name: ".bss", vaddr: 4198976, paddr: 5184, vsize: 32, size: 0, perm: "rw-", type: "NOBITS" },
]);

describe("r2_inspect registration", () => {
	it("is registered as a builtin tool", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("r2_inspect");
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["r2_inspect"]);
			const tool = tools.find(entry => entry.name === "r2_inspect") as R2InspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.label).toBe("R2 Inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.strict).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("r2_inspect missing dependency", () => {
	it("returns catalog install hints and objdump/strings fallbacks without running a process", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-missing-"));
		try {
			const target = await writeTarget(tempDir);
			let called = false;
			const tool = new R2InspectTool(createTestSession(tempDir), {
				which: () => null,
				runner: async () => {
					called = true;
					return okRun("[]");
				},
			});
			const result = await tool.execute("call-1", { action: "sections", path: target });
			expect(called).toBe(false);
			expect(detailsOf(result).status).toBe("missing_dependency");
			expect(detailsOf(result).fallback?.executed).toBe(false);
			expect(detailsOf(result).fallback?.suggestedFallback).toContain("objdump -h");
			expect(detailsOf(result).fallback?.alternatives.join(" ")).toContain("readelf -S");
			expect(detailsOf(result).dependency?.installHint).toContain("radare2");
			const text = textOf(result);
			expect(text).toContain("not found on PATH");
			expect(text).toContain("Install hint");
			expect(text).toContain("was not executed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("uses strings fallback for the strings action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-missing-strings-"));
		try {
			const target = await writeTarget(tempDir);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: () => null });
			const result = await tool.execute("call-2", { action: "strings", path: target });
			expect(detailsOf(result).fallback?.suggestedFallback).toContain("strings -a");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("r2_inspect argv construction", () => {
	it("uses fixed per-action commands and argv arrays", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-argv-"));
		try {
			const target = await writeTarget(tempDir);
			const absolute = path.resolve(target);
			const cases: Array<{
				action: R2InspectAction;
				params: Record<string, unknown>;
				command: string;
				analyzed: boolean;
			}> = [
				{ action: "info", params: {}, command: "ij", analyzed: false },
				{ action: "sections", params: {}, command: "iSj", analyzed: false },
				{ action: "imports", params: {}, command: "iij", analyzed: false },
				{ action: "exports", params: {}, command: "iEj", analyzed: false },
				{ action: "strings", params: {}, command: "izzj", analyzed: false },
				{ action: "functions", params: {}, command: "aflj", analyzed: true },
				{ action: "xrefs", params: { symbol: "sym.main" }, command: "axtj @ sym.main", analyzed: true },
				{ action: "xrefs", params: { address: "0x401000" }, command: "axtj @ 0x401000", analyzed: true },
				{ action: "disasm", params: { symbol: "main", limit: 40 }, command: "pdj 40 @ main", analyzed: true },
				{
					action: "disasm",
					params: { address: "0x401000", limit: 30 },
					command: "pdj 30 @ 0x401000",
					analyzed: true,
				},
				{ action: "decompile", params: { symbol: "main", limit: 20 }, command: "pdc @ main", analyzed: true },
				{ action: "decompile", params: {}, command: "pdc @ entry0", analyzed: true },
			];

			for (const entry of cases) {
				const { runner, calls } = fakeRunner(() =>
					entry.action === "decompile" ? "int main(void) { return 0; }" : "[]",
				);
				const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
				await tool.execute("call", {
					action: entry.action,
					path: target,
					...entry.params,
				} as never);
				expect(calls).toHaveLength(1);
				const call = calls[0]!;
				expect(call.binary).toBe("/opt/homebrew/bin/r2");
				expect(call.args).toEqual([
					"-q",
					"-e",
					"scr.color=0",
					"-e",
					"scr.interactive=false",
					...(entry.analyzed ? ["-c", "aaa"] : []),
					"-c",
					entry.command,
					"-c",
					"q",
					absolute,
				]);
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("builds commands without accepting arbitrary r2 text", () => {
		expect(buildR2Command("info", undefined, 50, 0)).toBe("ij");
		expect(buildR2Command("xrefs", { kind: "symbol", value: "sym.main" }, 50, 0)).toBe("axtj @ sym.main");
		expect(() => buildR2Command("xrefs", undefined, 50, 0)).toThrow("xrefs requires");
		expect(buildR2Args("functions", "aflj", "/tmp/x")).toEqual([
			"-q",
			"-e",
			"scr.color=0",
			"-e",
			"scr.interactive=false",
			"-c",
			"aaa",
			"-c",
			"aflj",
			"-c",
			"q",
			"/tmp/x",
		]);
	});
});

describe("r2_inspect input validation", () => {
	it("rejects invalid addresses", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-addr-"));
		try {
			const target = await writeTarget(tempDir);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich });
			for (const address of ["0x;!rm -rf /", "0x@@@", "main+4", " 0x10 20 "]) {
				await expect(tool.execute("call", { action: "xrefs", path: target, address })).rejects.toThrow(
					/Invalid address/,
				);
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects invalid symbols and command-injection attempts", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-sym-"));
		try {
			const target = await writeTarget(tempDir);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich });
			for (const symbol of ["main; pd 1000", "main|!sh", "sym.main @ 0x0", "`id`", "a b", "main\nq"]) {
				await expect(tool.execute("call", { action: "xrefs", path: target, symbol })).rejects.toThrow(
					/Invalid symbol/,
				);
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects combined symbol and address", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-both-"));
		try {
			const target = await writeTarget(tempDir);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich });
			await expect(
				tool.execute("call", { action: "disasm", path: target, symbol: "main", address: "0x401000" }),
			).rejects.toThrow(/not both/);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("requires a target for xrefs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-xref-missing-"));
		try {
			const target = await writeTarget(tempDir);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich });
			await expect(tool.execute("call", { action: "xrefs", path: target })).rejects.toThrow("requires a target");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects missing paths and directories", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-path-"));
		try {
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich });
			await expect(tool.execute("call", { action: "info", path: "nope.bin" })).rejects.toThrow(
				"Target file not found",
			);
			await expect(tool.execute("call", { action: "info", path: tempDir })).rejects.toThrow("Not a regular file");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("honors an already-aborted signal before spawning", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-abort-"));
		try {
			const target = await writeTarget(tempDir);
			let called = false;
			const tool = new R2InspectTool(createTestSession(tempDir), {
				which: foundWhich,
				runner: async () => {
					called = true;
					return okRun("[]");
				},
			});
			const controller = new AbortController();
			controller.abort();
			await expect(tool.execute("call", { action: "info", path: target }, controller.signal)).rejects.toThrow(
				"Operation aborted",
			);
			expect(called).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("r2_inspect parsing and pagination", () => {
	it("normalizes sections into stable details", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-sections-"));
		try {
			const target = await writeTarget(tempDir);
			const { runner } = fakeRunner(() => SECTIONS_JSON);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "sections", path: target });
			expect(detailsOf(result).status).toBe("ok");
			expect(detailsOf(result).format).toBe("json");
			expect(detailsOf(result).total).toBe(3);
			expect(detailsOf(result).count).toBe(3);
			expect(detailsOf(result).hasMore).toBe(false);
			expect(detailsOf(result).sections).toEqual([
				{
					name: ".text",
					vaddr: "0x401000",
					paddr: "0x1000",
					vsize: 500,
					size: 500,
					perm: "r-x",
					type: "PROGBITS",
				},
				{
					name: ".data",
					vaddr: "0x401200",
					paddr: "0x1400",
					vsize: 64,
					size: 64,
					perm: "rw-",
					type: "PROGBITS",
				},
				{
					name: ".bss",
					vaddr: "0x401240",
					paddr: "0x1440",
					vsize: 32,
					size: 0,
					perm: "rw-",
					type: "NOBITS",
				},
			]);
			expect(textOf(result)).toContain(".text");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("pages xrefs with offset/limit and reports hasMore", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-xrefs-"));
		try {
			const target = await writeTarget(tempDir);
			const xrefs = Array.from({ length: 5 }, (_, index) => ({
				from: 0x401000 + index * 4,
				to: 0x402000,
				type: "CALL",
				opcode: `call ${index}`,
			}));
			const { runner } = fakeRunner(() => JSON.stringify(xrefs));
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", {
				action: "xrefs",
				path: target,
				symbol: "sym.main",
				offset: 1,
				limit: 2,
			});
			expect(detailsOf(result).status).toBe("ok");
			expect(detailsOf(result).total).toBe(5);
			expect(detailsOf(result).count).toBe(2);
			expect(detailsOf(result).offset).toBe(1);
			expect(detailsOf(result).hasMore).toBe(true);
			expect(detailsOf(result).xrefs).toEqual([
				{ from: "0x401004", to: "0x402000", type: "CALL", opcode: "call 1" },
				{ from: "0x401008", to: "0x402000", type: "CALL", opcode: "call 2" },
			]);
			expect(textOf(result)).toContain("offset=3");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("normalizes info and strings", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-info-"));
		try {
			const target = await writeTarget(tempDir);
			const infoJson = JSON.stringify({
				core: { format: "elf64", size: 1024 },
				bin: {
					arch: "x86",
					bits: 64,
					endian: "little",
					os: "linux",
					machine: "AMD x86-64",
					type: "DYN",
					baddr: 4194304,
					stripped: true,
				},
			});
			const infoRunner = fakeRunner(() => infoJson);
			const infoTool = new R2InspectTool(createTestSession(tempDir), {
				which: foundWhich,
				runner: infoRunner.runner,
			});
			const infoResult = await infoTool.execute("call", { action: "info", path: target });
			expect(detailsOf(infoResult).info).toEqual({
				arch: "x86",
				bits: 64,
				endian: "little",
				os: "linux",
				machine: "AMD x86-64",
				type: "DYN",
				format: "elf64",
				baddr: "0x400000",
				size: 1024,
				stripped: true,
			});

			const stringsJson = JSON.stringify([
				{ vaddr: 0x402000, length: 11, section: ".rodata", type: "ascii", string: "hello world" },
				{ vaddr: 0x402010, length: 5, section: ".rodata", type: "ascii", string: "token" },
				{ vaddr: 0x402020, length: 6, section: ".rodata", type: "utf8", string: "secret" },
			]);
			const stringsRunner = fakeRunner(() => stringsJson);
			const stringsTool = new R2InspectTool(createTestSession(tempDir), {
				which: foundWhich,
				runner: stringsRunner.runner,
			});
			const stringsResult = await stringsTool.execute("call", {
				action: "strings",
				path: target,
				offset: 1,
				limit: 1,
			});
			expect(detailsOf(stringsResult).strings).toEqual([
				{ vaddr: "0x402010", length: 5, section: ".rodata", type: "ascii", string: "token" },
			]);
			expect(detailsOf(stringsResult).total).toBe(3);
			expect(detailsOf(stringsResult).hasMore).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns a bounded raw preview when JSON parsing fails", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-badjson-"));
		try {
			const target = await writeTarget(tempDir);
			const { runner } = fakeRunner(() => "WARNING: noisy line\nnot-json-at-all");
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "functions", path: target });
			expect(detailsOf(result).status).toBe("error");
			expect(detailsOf(result).parseError).toBeDefined();
			expect(detailsOf(result).raw).toContain("not-json-at-all");
			expect(textOf(result)).toContain("could not be parsed");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("r2_inspect runner outcomes", () => {
	it("reports timeout without throwing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-timeout-"));
		try {
			const target = await writeTarget(tempDir);
			const { runner, calls } = fakeRunner(() => "", { timedOut: true, exitCode: 137, outputBytes: 0 });
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "functions", path: target });
			expect(calls[0]?.options.timeoutMs).toBe(30_000);
			expect(detailsOf(result).status).toBe("error");
			expect(detailsOf(result).timedOut).toBe(true);
			expect(textOf(result)).toContain("timed out");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("marks truncated output as ok when usable JSON was captured", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-trunc-"));
		try {
			const target = await writeTarget(tempDir);
			const json = JSON.stringify([{ name: "main", offset: 0x401000, size: 32 }]);
			const { runner, calls } = fakeRunner(() => json, { truncated: true, killedOnOverflow: true });
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "functions", path: target, max_bytes: 1024 });
			expect(calls[0]?.options.maxBytes).toBe(1024);
			expect(detailsOf(result).status).toBe("ok");
			expect(detailsOf(result).truncated).toBe(true);
			expect(detailsOf(result).functions?.[0]?.name).toBe("main");
			expect(textOf(result)).toContain("output truncated");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports a non-zero exit with stderr", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-exit-"));
		try {
			const target = await writeTarget(tempDir);
			const { runner } = fakeRunner(() => "", {
				exitCode: 1,
				stderr: "Fatal error: cannot open file",
			});
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "info", path: target });
			expect(detailsOf(result).status).toBe("error");
			expect(detailsOf(result).error).toContain("exit 1");
			expect(detailsOf(result).error).toContain("cannot open file");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("r2_inspect mode folding and decompilation", () => {
	it("folds ANSI, blank and duplicate lines conservatively", () => {
		const folded = foldR2Text("\u001b[31m0x1  mov eax, ebx\u001b[0m\n\n0x1  mov eax, ebx\n0x2  ret   \n");
		expect(folded).toBe("0x1  mov eax, ebx\n0x2  ret");
	});

	it("reports summary counts and marks the result unverified", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-summary-"));
		try {
			const target = await writeTarget(tempDir);
			const functions = Array.from({ length: 30 }, (_, index) => ({
				name: `fcn.${index.toString(16).padStart(6, "0")}`,
				offset: 0x401000 + index * 0x10,
				size: 16,
			}));
			const { runner } = fakeRunner(() => JSON.stringify(functions));
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "functions", path: target, mode: "summary" });
			expect(detailsOf(result).unverified).toBe(true);
			expect(detailsOf(result).total).toBe(30);
			const text = textOf(result);
			expect(text).toContain("total: 30");
			expect(text).toContain("not verified exhaustive");
			expect(text.split("\n").filter(line => line.includes("fcn.")).length).toBe(10);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("pages and folds decompiler text", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-decomp-"));
		try {
			const target = await writeTarget(tempDir);
			const decompiled = "int main(void)\n\n{\n  int x = 1;\n  int x = 1;\n  return x;\n}\n";
			const { runner, calls } = fakeRunner(() => decompiled);
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", {
				action: "decompile",
				path: target,
				symbol: "main",
				mode: "fold",
				offset: 2,
				limit: 4,
			});
			expect(calls[0]?.args).toContain("pdc @ main");
			expect(detailsOf(result).status).toBe("ok");
			expect(detailsOf(result).format).toBe("text");
			expect(detailsOf(result).decompile?.text).toContain("int x = 1;");
			expect(detailsOf(result).decompile?.lineCount).toBe(8);
			expect(detailsOf(result).unverified).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns a plugin hint when the decompiler command is unavailable", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "r2-nopdc-"));
		try {
			const target = await writeTarget(tempDir);
			const { runner } = fakeRunner(() => "", { stderr: "ERROR: Invalid command 'pdc'", exitCode: 0 });
			const tool = new R2InspectTool(createTestSession(tempDir), { which: foundWhich, runner });
			const result = await tool.execute("call", { action: "decompile", path: target, symbol: "main" });
			expect(detailsOf(result).status).toBe("error");
			expect(detailsOf(result).error).toContain("r2pm -ci r2dec");
			expect(textOf(result)).toContain("action=disasm");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
