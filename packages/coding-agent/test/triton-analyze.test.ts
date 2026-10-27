/**
 * Contract and semantic invariant tests for TritonAnalyzeTool and Triton worker.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../src/config/settings";
import { resolveVmpTool } from "../src/extensibility/vmp-toolchain";
import type { ToolSession } from "../src/tools";
import { TritonAnalyzeTool } from "../src/tools/triton-analyze";

function createMockSession(cwd: string, options?: { planMode?: boolean }): ToolSession {
	return {
		cwd,
		hasUI: false,
		settings: Settings.isolated({}),
		getPlanModeState: () => ({ enabled: options?.planMode ?? false }),
	} as unknown as ToolSession;
}

const tritonPython = resolveVmpTool("triton", {
	env: process.env,
	platform: process.platform,
});
const hasTriton = tritonPython !== null;

describe("TritonAnalyzeTool plan mode and approval gates", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "triton-tool-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("blocks replay action under plan mode while permitting status", async () => {
		const session = createMockSession(tempDir, { planMode: true });
		const tool = new TritonAnalyzeTool(session);

		await expect(
			tool.execute("call-1", {
				action: "replay",
				trace: "test.trace",
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(/Plan mode: triton trace replay executes symbolic emulation/);

		const statusRes = await tool.execute("call-2", { action: "status" });
		expect(statusRes.details.action).toBe("status");
		if (!hasTriton) {
			expect(statusRes.details.installed).toBe(false);
			await expect(tool.execute("call-3", { action: "arch_info", arch: "aarch64" })).rejects.toThrow(
				/Triton is not installed or configured in this environment/,
			);
		}
	});

	it.skipIf(!hasTriton)("permits arch_info action under plan mode when Triton is installed", async () => {
		const session = createMockSession(tempDir, { planMode: true });
		const tool = new TritonAnalyzeTool(session);

		const archRes = await tool.execute("call-3", { action: "arch_info", arch: "aarch64" });
		expect(archRes.details.action).toBe("arch_info");
	});
	it.skipIf(!hasTriton)("fails with specific missing file message when trace file does not exist", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		const nonExistentPath = path.join(tempDir, "absent_execution.trace");
		await expect(
			tool.execute("call-missing", {
				action: "replay",
				trace: nonExistentPath,
				output: { kind: "register", target: "rax" },
			}),
		).rejects.toThrow(`Trace file not found: ${nonExistentPath}`);
	});
});

describe("Triton worker semantic invariants", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "triton-worker-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it.skipIf(!hasTriton)("rejects uninitialized memory read with explicit missing memory state error", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// Trace with instruction: mov eax, [0x2000] (opcode 8b 04 25 00 20 00 00)
		// Memory 0x2000 was never defined in initial_memory or mr: entry
		const tracePath = path.join(tempDir, "uninit_mem.trace");
		await fs.promises.writeFile(
			tracePath,
			[
				"r:0x401000:0x0:0x0:0x0:0x0:0x0:0x0:0x7ffffff0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0",
				"i:0x401000:7:8b042500200000",
			].join("\n"),
		);

		await expect(
			tool.execute("test-uninit-mem", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(/Missing memory state at line 2/);
	});

	it.skipIf(!hasTriton)("rejects RMW memory read on uninitialized address (add [0x2000], 1)", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// Instruction: add dword ptr [0x2000], 1 (83 04 25 00 20 00 00 01)
		const tracePath = path.join(tempDir, "rmw_uninit.trace");
		await fs.promises.writeFile(
			tracePath,
			[
				"r:0x401000:0x0:0x0:0x0:0x0:0x0:0x0:0x7ffffff0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0",
				"i:0x401000:8:8304250020000001",
			].join("\n"),
		);

		await expect(
			tool.execute("test-rmw-uninit", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(/Missing memory state at line 2/);
	});

	it.skipIf(!hasTriton)("rejects uninitialized GPR read with explicit missing register state error", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// Instruction: mov eax, ebx (opcode 89 d8)
		// EBX was never initialized in initial_registers or r: line
		const tracePath = path.join(tempDir, "uninit_reg.trace");
		await fs.promises.writeFile(tracePath, "i:0x401000:2:89d8\n");

		await expect(
			tool.execute("test-uninit-reg", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000" },
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(
			/Missing register state at line 1: instruction at 0x401000 .* reads uninitialized register 'ebx'/,
		);
	});

	it.skipIf(!hasTriton)(
		"rejects partial register read when only sub-register was initialized (AL vs RAX)",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new TritonAnalyzeTool(session);

			// Instruction: mov rbx, rax (48 89 c3)
			// Only AL is initialized; bits 8..63 of RAX are uninitialized
			const tracePath = path.join(tempDir, "partial_reg.trace");
			await fs.promises.writeFile(tracePath, "i:0x401000:3:4889c3\n");

			await expect(
				tool.execute("test-partial-reg", {
					action: "replay",
					arch: "x86_64",
					trace: tracePath,
					initial_registers: { rip: "0x401000", al: "0x42" },
					output: { kind: "register", target: "rbx" },
				}),
			).rejects.toThrow(
				/Missing register state at line 1: instruction at 0x401000 .* reads uninitialized register 'rax'/,
			);
		},
	);

	it.skipIf(!hasTriton)("rejects uninitialized flag read on arithmetic instruction (ADC reading CF)", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// Instruction: adc eax, ebx (11 d8)
		// CF flag was never initialized
		const tracePath = path.join(tempDir, "adc_uninit_cf.trace");
		await fs.promises.writeFile(tracePath, "i:0x401000:2:11d8\n");

		await expect(
			tool.execute("test-adc-cf", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000", eax: "1", ebx: "2" },
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(/Missing flag state at line 1: instruction at 0x401000 .* reads uninitialized flag 'cf'/);
	});

	it.skipIf(!hasTriton)("rejects malformed trace record with exact line number error", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		const tracePath = path.join(tempDir, "malformed.trace");
		await fs.promises.writeFile(tracePath, "i:0x401000:not_a_number:89d8\n");

		await expect(
			tool.execute("test-malformed", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000" },
				output: { kind: "register", target: "eax" },
			}),
		).rejects.toThrow(/Invalid decimal instruction size 'not_a_number' at line 1/);
	});

	it.skipIf(!hasTriton)("executes symbolic arithmetic and preserves AST expression across snapshots", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// Instructions:
		// 0x401000: mov eax, edi (89 f8)
		// snapshot r: matching state
		// 0x401002: xor eax, esi (31 f0)
		const tracePath = path.join(tempDir, "sym_calc.trace");
		await fs.promises.writeFile(
			tracePath,
			[
				"i:0x401000:2:89f8",
				"r:0x10:0x0:0x0:0x0:0x10:0x20:0x0:0x7ffffff0:0x0:0x0:0x0:0x0:0x0:0x0:0x0:0x0",
				"i:0x401002:2:31f0",
			].join("\n"),
		);

		const result = await tool.execute("test-sym-calc", {
			action: "replay",
			arch: "x86_64",
			trace: tracePath,
			initial_registers: {
				rip: "0x401000",
				rdi: "0x10",
				rsi: "0x20",
				rsp: "0x7ffffff0",
			},
			symbolic_registers: [
				{ name: "rdi", alias: "x" },
				{ name: "rsi", alias: "y" },
			],
			output: { kind: "register", target: "eax" },
		});

		expect(result.details.concrete_return).toBe("0x30");
		expect(result.details.devirt_expr_preview).toBeDefined();
		expect(result.details.devirt_expr_preview).toContain("bvxor");
	});

	it.skipIf(!hasTriton)("replays AArch64 trace with Wn zero-extension into Xn and zero register support", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// AArch64 instructions:
		// 0x401000: mov w0, #42 (40 05 80 52) - writes 32-bit W0, zero-extends into X0
		// 0x401004: add x0, x0, xzr (00 00 1f 8b) - reads xzr (hardware zero register)
		const tracePath = path.join(tempDir, "aarch64_test.trace");
		await fs.promises.writeFile(tracePath, ["i:0x401000:4:40058052", "i:0x401004:4:00001f8b"].join("\n"));

		const result = await tool.execute("test-aarch64", {
			action: "replay",
			arch: "aarch64",
			trace: tracePath,
			initial_registers: {
				pc: "0x401000",
				sp: "0x7ffffff0",
			},
			output: { kind: "register", target: "x0" },
		});

		expect(result.details.concrete_return).toBe("0x2a");
	});

	it.skipIf(!hasTriton)(
		"rejects uninitialized AArch64 register read (add x0, x0, xzr without initialization)",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new TritonAnalyzeTool(session);

			// AArch64 instructions:
			// 0x401000: mov w2, #42 (42 05 80 52) - writes W2, leaving X0 uninitialized
			// 0x401004: add x0, x0, xzr (00 00 1f 8b) - reads uninitialized X0
			const tracePath = path.join(tempDir, "aarch64_uninit.trace");
			await fs.promises.writeFile(tracePath, ["i:0x401000:4:42058052", "i:0x401004:4:00001f8b"].join("\n"));

			await expect(
				tool.execute("test-aarch64-uninit", {
					action: "replay",
					arch: "aarch64",
					trace: tracePath,
					initial_registers: {
						pc: "0x401000",
						sp: "0x7ffffff0",
					},
					output: { kind: "register", target: "x0" },
				}),
			).rejects.toThrow();
		},
	);

	it.skipIf(!hasTriton)("replays ARM32 trace in Thumb mode", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// ARM32 Thumb instructions:
		// 0x401000: movs r0, #42 (2a 20)
		// 0x401002: nop (00 bf)
		const tracePath = path.join(tempDir, "arm32_thumb.trace");
		await fs.promises.writeFile(tracePath, ["i:0x401000:2:2a20", "i:0x401002:2:00bf"].join("\n"));

		const result = await tool.execute("test-arm32-thumb", {
			action: "replay",
			arch: "arm32",
			thumb: true,
			trace: tracePath,
			initial_registers: {
				pc: "0x401000",
				sp: "0x7ffffff0",
			},
			output: { kind: "register", target: "r0" },
		});

		expect(result.details.concrete_return).toBe("0x2a");
	});

	it.skipIf(!hasTriton)("rejects uninitialized vector register read with explicit error", async () => {
		const session = createMockSession(tempDir);
		const tool = new TritonAnalyzeTool(session);

		// x86_64 instruction reading uninitialized XMM1:
		// 0x401000: movaps xmm0, xmm1 (0f 28 c1)
		const tracePath = path.join(tempDir, "uninit_xmm.trace");
		await fs.promises.writeFile(tracePath, "i:0x401000:3:0f28c1\n");

		await expect(
			tool.execute("test-uninit-vector", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				initial_registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				output: { kind: "register", target: "rax" },
			}),
		).rejects.toThrow(/reads uninitialized vector register 'xmm1'/);
	});

	it.skipIf(!hasTriton)(
		"supports structured JSONL records for instructions, registers, and memory reads",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new TritonAnalyzeTool(session);

			const tracePath = path.join(tempDir, "structured.jsonl");
			await fs.promises.writeFile(
				tracePath,
				[
					JSON.stringify({ type: "registers", values: { rip: "0x401000", rdi: "0x7", rsp: "0x7ffffff0" } }),
					JSON.stringify({
						type: "instruction",
						address: "0x401000",
						bytes: "89f8",
						size: 2,
						disasm: "mov eax, edi",
					}),
				].join("\n"),
			);

			const result = await tool.execute("test-jsonl-trace", {
				action: "replay",
				arch: "x86_64",
				trace: tracePath,
				symbolic_registers: [{ name: "rdi", alias: "x", seed: "0x7" }],
				output: { kind: "register", target: "eax" },
			});

			expect(result.details.concrete_return).toBe("0x7");
		},
	);
});
