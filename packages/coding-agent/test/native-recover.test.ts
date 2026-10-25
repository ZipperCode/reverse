/**
 * Contract and semantic verification tests for NativeRecoverTool.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../src/config/settings";
import { resolveVmpTool } from "../src/extensibility/vmp-toolchain";
import type { ToolSession } from "../src/tools";
import { NativeRecoverTool } from "../src/tools/native-recover";

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

import {
	X86_64_FIXTURE_SNAPSHOT,
	AARCH64_FIXTURE_SNAPSHOT,
	ARM32_FIXTURE_SNAPSHOT,
	X86_64_NESTED_4PATH_SNAPSHOT,
} from "./fixtures/native-recovery-fixtures";

describe("NativeRecoverTool plan mode and approval tiers", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-recover-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("permits status under plan mode but blocks execution actions", async () => {
		const session = createMockSession(tempDir, { planMode: true });
		const tool = new NativeRecoverTool(session);

		const statusRes = await tool.execute("call-status", { action: "status" });
		expect(statusRes.details.action).toBe("status");

		await expect(
			tool.execute("call-explore", {
				action: "explore",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000" },
					segments: [{ address: "0x401000", bytes: "c3" }],
					symbolic_inputs: [{ name: "rdi", seed: "0x1" }],
					output: { kind: "register", target: "rax" },
				},
			}),
		).rejects.toThrow(/Plan mode: native recovery actions/);
	});
});

describe("NativeRecoverTool concolic exploration and recovery", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-recover-dse-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it.skipIf(!hasTriton)(
		"explores x86_64 branching machine function, inverts branch dynamically, and records memory side effects",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const result = await tool.execute("test-x64-dse", {
				action: "explore",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: {
						rip: "0x401000",
						rsp: "0x7ffffff0",
					},
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [
						{
							name: "rdi",
							alias: "x",
							seed: "0x5", // initial seed: 5 <= 10 (Branch A)
						},
					],
					output: {
						kind: "register",
						target: "rax",
					},
				},
				bounds: {
					branch_budget: 10,
					max_instructions: 200,
				},
			});

			expect(result.details.action).toBe("explore");
			expect(result.details.discovered_paths_count).toBe(2);

			const paths = result.details.discovered_paths || [];
			expect(paths.length).toBeGreaterThanOrEqual(2);

			for (const p of paths) {
				expect(p.status).toBe("complete");
				const xVal = typeof p.seed.x === "string" ? parseInt(p.seed.x, 16) : Number(p.seed.x);
				const expected = X86_64_FIXTURE_SNAPSHOT.expected_eval(xVal);
				expect(BigInt(p.concrete_return!)).toBe(BigInt(expected.ret));
				if (p.memory_writes && p.memory_writes.length > 0) {
					expect(BigInt(p.memory_writes[0].value)).toBe(BigInt(expected.mem));
				}
			}
			// Check coverage statistics
			const cov = result.details.coverage;
			expect(cov).toBeDefined();
			expect(cov?.branches_seen).toBeGreaterThanOrEqual(1);
			expect(cov?.branches_inverted).toBeGreaterThanOrEqual(1);
		},
	);

	it.skipIf(!hasTriton)(
		"explores AArch64 branching machine function and discovers both execution branches",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const result = await tool.execute("test-aarch64-dse", {
				action: "explore",
				snapshot: {
					arch: "aarch64",
					entry: "0x401000",
					stop_addresses: ["0x401030"],
					registers: {
						pc: "0x401000",
						sp: "0x7ffffff0",
					},
					segments: AARCH64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [
						{
							name: "x0",
							alias: "x",
							seed: "0x3", // initial seed: 3 <= 10
						},
					],
					output: {
						kind: "register",
						target: "x0",
					},
				},
				bounds: {
					branch_budget: 10,
				},
			});

			expect(result.details.action).toBe("explore");
			expect(result.details.discovered_paths_count).toBe(2);

			const paths = result.details.discovered_paths || [];
			expect(paths.length).toBeGreaterThanOrEqual(2);
			for (const p of paths) {
				expect(p.status).toBe("complete");
				const xVal = BigInt(p.seed.x);
				const expected = AARCH64_FIXTURE_SNAPSHOT.expected_eval(xVal);
				expect(BigInt(p.concrete_return!)).toBe(BigInt(expected.ret));
			}
		},
	);

	it.skipIf(!hasTriton)("explores ARM32 branching machine function across branches", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		const result = await tool.execute("test-arm32-dse", {
			action: "explore",
			snapshot: {
				arch: "arm32",
				entry: "0x401000",
				stop_addresses: ["0x401030"],
				registers: ARM32_FIXTURE_SNAPSHOT.registers,
				segments: ARM32_FIXTURE_SNAPSHOT.segments,
				symbolic_inputs: [
					{
						name: "r0",
						alias: "x",
						seed: "0x4", // initial seed: 4 <= 10
					},
				],
				output: {
					kind: "register",
					target: "r0",
				},
			},
			bounds: {
				branch_budget: 10,
			},
		});

		expect(result.details.action).toBe("explore");
		expect(result.details.discovered_paths_count).toBe(2);

		const paths = result.details.discovered_paths || [];
		expect(paths.length).toBeGreaterThanOrEqual(2);
		for (const p of paths) {
			expect(p.status).toBe("complete");
			const xVal = typeof p.seed.x === "string" ? parseInt(p.seed.x, 16) : Number(p.seed.x);
			const expected = ARM32_FIXTURE_SNAPSHOT.expected_eval(xVal);
			expect(BigInt(p.concrete_return!)).toBe(BigInt(expected.ret));
		}
	});

	it.skipIf(!hasTriton)(
		"slices handler semantics and extracts data dependencies and memory side effects",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const result = await tool.execute("test-handler-slice", {
				action: "handlers",
				arch: "x86_64",
				range: {
					start: "0x401000",
					stop: "0x401025",
				},
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x5" }],
					output: { kind: "register", target: "rax" },
				},
				inputs: [{ name: "rdi", alias: "x", seed: "0x5" }],
				output: { kind: "register", target: "rax" },
			});

			expect(result.details.action).toBe("handlers");
			expect(result.details.data_dependencies).toContain("x");
			expect(result.details.memory_side_effects?.length).toBeGreaterThan(0);
		},
	);

	it.skipIf(!hasTriton)(
		"merges path predicates, validates domain coverage, and lifts to verified LLVM IR",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const result = await tool.execute("test-path-merge", {
				action: "merge",
				arch: "x86_64",
				inputs: [{ name: "x", size_bits: 32 }],
				output_size_bits: 32,
				paths: [
					{
						predicate: "(bvule x (_ bv10 32))",
						output_ast: "(bvadd x (_ bv5 32))",
					},
					{
						predicate: "(bvugt x (_ bv10 32))",
						output_ast: "(bvadd (bvmul x (_ bv2 32)) (_ bv1 32))",
					},
				],
			});

			expect(result.details.action).toBe("merge");
			expect(result.details.merged_paths_count).toBe(2);
			expect(result.details.is_total_domain).toBe(true);
			expect(result.details.conflicts?.length).toBe(0);
			expect(result.details.llvm?.available).toBe(true);
			expect(result.details.smt2_formula_artifact_id || result.details.smt2_formula_file_path).toBeDefined();
		},
	);

	it.skipIf(!hasTriton)(
		"detects incomplete domain coverage during merge and exports explicit uncovered sample",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Only path x <= 10 provided; x > 10 is uncovered
			const result = await tool.execute("test-incomplete-merge", {
				action: "merge",
				arch: "x86_64",
				inputs: [{ name: "x", size_bits: 32 }],
				output_size_bits: 32,
				paths: [
					{
						predicate: "(bvule x (_ bv10 32))",
						output_ast: "(bvadd x (_ bv5 32))",
					},
				],
			});

			expect(result.details.is_total_domain).toBe(false);
			expect(result.details.coverage_guard?.is_total).toBe(false);
			expect(result.details.coverage_guard?.uncovered_sample).toBeDefined();
		},
	);

	it.skipIf(!hasTriton)(
		"performs differential verification between machine snapshot and recovered expression",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Correct recovered formula with bidirectional memory side effects
			const verifiedRes = await tool.execute("test-differential-pass", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x5" }],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "smt2",
					expression: "(ite (bvugt x (_ bv10 32)) (bvadd (bvmul x (_ bv2 32)) (_ bv1 32)) (bvadd x (_ bv5 32)))",
					inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
					output: { kind: "register", target: "rax" },
					memory_side_effects: [
						{
							address: "0x2000",
							size: 4,
							condition: "(bvugt x (_ bv10 32))",
							value: "0xbeef",
							else_value: "0xcafe",
						},
					],
					strict_memory_check: true,
				},
				test_generation: {
					boundary: true,
					random_count: 10,
					seed: 12345,
				},
				proof_mode: "both",
			});

			expect(verifiedRes.details.action).toBe("verify");
			expect(verifiedRes.details.agreement_pct).toBe(100.0);
			expect(verifiedRes.details.counterexamples?.length).toBe(0);
			expect(verifiedRes.details.assurance_level_recommendation).toBe("algorithm_recovery");

			// Negative test: Mutated expression produces counterexamples
			const failingRes = await tool.execute("test-differential-fail", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x5" }],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "smt2",
					// Intentional bug: (x + 6) instead of (x + 5)
					expression: "(ite (bvugt x (_ bv10 32)) (bvadd (bvmul x (_ bv2 32)) (_ bv1 32)) (bvadd x (_ bv6 32)))",
					inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
					output: { kind: "register", target: "rax" },
					memory_side_effects: [
						{
							address: "0x2000",
							size: 4,
							condition: "(bvugt x (_ bv10 32))",
							value: "0xbeef",
							else_value: "0xcafe",
						},
					],
				},
				test_generation: {
					boundary: true,
					random_count: 5,
					seed: 12345,
				},
			});

			expect(failingRes.details.agreement_pct).toBeLessThan(100.0);
			expect(failingRes.details.counterexamples?.length).toBeGreaterThan(0);
			expect(failingRes.details.assurance_level_recommendation).toBe("unverified");
		},
	);

	it.skipIf(!hasTriton)(
		"performs differential verification against candidate LLVM IR executed via MCJIT",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const mergeRes = await tool.execute("merge-for-jit", {
				action: "merge",
				arch: "x86_64",
				inputs: [{ name: "x", size_bits: 32 }],
				output_size_bits: 32,
				paths: [
					{
						predicate: "(bvule x (_ bv10 32))",
						output_ast: "(bvadd x (_ bv5 32))",
					},
					{
						predicate: "(bvugt x (_ bv10 32))",
						output_ast: "(bvadd (bvmul x (_ bv2 32)) (_ bv1 32))",
					},
				],
			});

			expect(mergeRes.details.llvm?.available).toBe(true);
			const llvmPath = mergeRes.details.llvm_ir_file_path;
			expect(llvmPath).toBeDefined();
			// Candidate LLVM IR implementing branching arithmetic return and isolated snapshot memory side-effects:
			// Address 0x2000 is 8192 in decimal.
			// When x <= 10: stores 0xcafe (51966) at [0x2000], returns x + 5
			// When x > 10:  stores 0xbeef (48879) at [0x2000], returns x * 2 + 1
			const candidateLlvmIr = `
				define i64 @candidate_func(i32 %x) {
				entry:
					%cond = icmp ugt i32 %x, 10
					br i1 %cond, label %branch_gt, label %branch_le

				branch_le:
					%ptr_le = inttoptr i64 8192 to i32*
					store i32 51966, i32* %ptr_le, align 4
					%res_le = add i32 %x, 5
					%ret_le = zext i32 %res_le to i64
					ret i64 %ret_le

				branch_gt:
					%ptr_gt = inttoptr i64 8192 to i32*
					store i32 48879, i32* %ptr_gt, align 4
					%mul_gt = mul i32 %x, 2
					%res_gt = add i32 %mul_gt, 1
					%ret_gt = zext i32 %res_gt to i64
					ret i64 %ret_gt
				}
			`;

			const verifyRes = await tool.execute("test-llvm-jit-verify", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x5" }],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "llvm_ir",
					llvm_ir: candidateLlvmIr,
					inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
					output: { kind: "register", target: "rax" },
					memory_side_effects: [
						{
							address: "0x2000",
							size: 4,
							condition: "(bvugt x (_ bv10 32))",
							value: "0xbeef",
							else_value: "0xcafe",
						},
					],
				},
				vectors: [{ x: 5 }, { x: 10 }, { x: 12 }, { x: 20 }],
			});

			expect(verifyRes.details.action).toBe("verify");
			expect(verifyRes.details.agreement_pct).toBe(100.0);
			expect(verifyRes.details.smt_formal_proved).toBe(false);
			expect(verifyRes.details.side_effects_proved).toBe(false);
			expect(verifyRes.details.formal_proof_scope).not.toBe("full_algorithm");
			expect(verifyRes.details.assurance_level_recommendation).toBe("dynamic_call_observation");
		},
	);

	it.skipIf(!hasTriton)("explores all 4 paths for nested branching machine function", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		const result = await tool.execute("test-nested-4path", {
			action: "explore",
			snapshot: X86_64_NESTED_4PATH_SNAPSHOT,
			bounds: {
				branch_budget: 10,
			},
		});

		expect(result.details.action).toBe("explore");
		expect(result.details.discovered_paths_count).toBe(4);

		const paths = result.details.discovered_paths || [];
		expect(paths.length).toBe(4);
		for (const p of paths) {
			expect(p.status).toBe("complete");
			const xVal = typeof p.seed.x === "string" ? parseInt(p.seed.x, 16) : Number(p.seed.x);
			const yVal = typeof p.seed.y === "string" ? parseInt(p.seed.y, 16) : Number(p.seed.y);
			const expected = X86_64_NESTED_4PATH_SNAPSHOT.expected_eval(xVal, yVal);
			expect(parseInt(p.concrete_return!, 16)).toBe(expected);
		}
		const observedReturns = paths.map(p => parseInt(p.concrete_return!, 16)).sort((a, b) => a - b);
		expect(observedReturns).toEqual([10, 20, 30, 40]);
	});

	it.skipIf(!hasTriton)(
		"enforces max_depth=1 bound and records skipped alternative in incomplete_frontier",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			const result = await tool.execute("test-max-depth-1", {
				action: "explore",
				snapshot: X86_64_NESTED_4PATH_SNAPSHOT,
				bounds: {
					branch_budget: 10,
					max_depth: 1,
				},
			});

			expect(result.details.action).toBe("explore");
			const frontier = result.details.coverage?.incomplete_frontier || [];
			expect(frontier.length).toBeGreaterThan(0);
			expect(String(frontier[0].reason)).toContain("max_depth");
		},
	);

	it.skipIf(!hasTriton)("preserves exact >2^53 integer seeds in hex representation", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		const bigSeedHex = "0x8000000000000001";
		const result = await tool.execute("test-big-seed", {
			action: "explore",
			snapshot: {
				arch: "x86_64",
				entry: "0x401000",
				stop_addresses: ["0x401025"],
				registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				segments: X86_64_FIXTURE_SNAPSHOT.segments,
				symbolic_inputs: [{ name: "rdi", alias: "x", seed: bigSeedHex }],
				output: { kind: "register", target: "rax" },
			},
			bounds: { branch_budget: 2 },
		});

		const paths = result.details.discovered_paths || [];
		expect(paths.length).toBeGreaterThanOrEqual(1);
		expect(paths[0].seed.x).toBe(bigSeedHex);
	});
});
