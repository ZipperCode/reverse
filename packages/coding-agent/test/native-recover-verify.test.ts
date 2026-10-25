/**
 * Comprehensive differential verification and formal SMT equivalence regression tests
 * for NativeRecoverTool (native-recover-verify.py).
 *
 * Disciplines verified:
 * 1. Independent dual execution: machine snapshot in Triton vs llvmlite MCJIT / Z3.
 * 2. Strict input vectors & widths: missing inputs and malformed vectors rejected, never defaulted to 0.
 * 3. Machine execution completion: stop address reached; infinite loops & faults fail.
 * 4. Bidirectional memory verification: store widths, extra stores, and values checked at byte granularity.
 * 5. LLVM IR MCJIT execution: candidate LLVM IR executed; companion expression never used as proxy.
 * 6. Explicit proof mode separation: finite_vectors vs smt_formal epistemic assurance ratings.
 * 7. Explicit domain guarding: min/max bounds and out_of_domain_vectors tracking.
 * 8. Symbolic memory input bindings: memory inputs in snapshot correctly updated from test vectors.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../src/config/settings";
import { resolveVmpTool } from "../src/extensibility/vmp-toolchain";
import type { ToolSession } from "../src/tools";
import { NativeRecoverTool } from "../src/tools/native-recover";
import { X86_64_FIXTURE_SNAPSHOT } from "./fixtures/native-recovery-fixtures";

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

describe("NativeRecoverTool Differential Verification and SMT Prover", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-verify-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it.skipIf(!hasTriton)("verifies equivalent branching function and proves formal SMT equivalence", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Correct candidate SMT2 formula with matching bidirectional memory side effects
		const res = await tool.execute("test-verify-pass", {
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
			vectors: [{ x: "0x1" }, { x: "0xa" }, { x: "0xb" }, { x: "0x20" }],
			test_generation: {
				boundary: true,
				random_count: 5,
				seed: 12345,
			},
			proof_mode: "both",
		});

		expect(res.details.action).toBe("verify");
		expect(res.details.agreement_pct).toBe(100.0);
		expect(res.details.counterexamples?.length).toBe(0);
		expect(res.details.assurance_level_recommendation).toBe("algorithm_recovery");
		expect(res.details.smt_formal_proved).toBe(true);
		expect(res.details.formal_proof_scope).toBe("full_algorithm");
		expect(res.details.side_effects_proved).toBe(true);
	});

	it.skipIf(!hasTriton)("reports counterexample when candidate produces wrong branch return", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Mutated formula: x + 6 instead of x + 5 on the else branch (x <= 10)
		const res = await tool.execute("test-wrong-branch-return", {
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
			vectors: [{ x: 5 }, { x: 10 }, { x: 15 }],
			proof_mode: "both",
		});

		expect(res.details.action).toBe("verify");
		expect(res.details.agreement_pct).toBeLessThan(100.0);
		expect(res.details.counterexamples?.length).toBeGreaterThan(0);
		expect(res.details.assurance_level_recommendation).toBe("unverified");
	});

	it.skipIf(!hasTriton)(
		"reports counterexample when memory store width does not match concrete store access",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Original snapshot stores 4 bytes at 0x2000; candidate declares size: 1 byte
			const res = await tool.execute("test-wrong-store-width", {
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
							size: 1, // Intentional bug: 1 byte declared instead of 4 bytes
							condition: "(bvugt x (_ bv10 32))",
							value: "0xef",
							else_value: "0xfe",
						},
					],
				},
				vectors: [{ x: 5 }, { x: 15 }],
			});

			expect(res.details.agreement_pct).toBe(0.0);
			expect(res.details.counterexamples?.length).toBeGreaterThan(0);
			expect(res.details.counterexamples![0].mismatch_reason).toBe("wrong_store_width");
			expect(res.details.assurance_level_recommendation).toBe("unverified");
		},
	);

	it.skipIf(!hasTriton)(
		"reports counterexample when original snapshot performs unexpected unmodeled memory store",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Original snapshot stores to 0x2000, but candidate declares no memory side effects
			const res = await tool.execute("test-extra-unmodeled-store", {
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
					memory_side_effects: [], // Omitted side effects
				},
				vectors: [{ x: 5 }, { x: 15 }],
			});

			expect(res.details.agreement_pct).toBe(0.0);
			expect(res.details.counterexamples?.length).toBeGreaterThan(0);
			expect(res.details.counterexamples![0].mismatch_reason).toBe("unexpected_store");
			expect(res.details.assurance_level_recommendation).toBe("unverified");
		},
	);

	it.skipIf(!hasTriton)(
		"rejects test vectors with missing required input fields instead of defaulting to zero",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Vector is missing required input 'x'
			await expect(
				tool.execute("test-missing-vector-field", {
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
						expression: "(bvadd x (_ bv5 32))",
						inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
						output: { kind: "register", target: "rax" },
					},
					vectors: [{ wrong_field: 5 } as Record<string, string | number>],
					test_generation: { boundary: false, random_count: 0 },
				}),
			).rejects.toThrow(/missing required input 'x'/i);
		},
	);

	it.skipIf(!hasTriton)("rejects snapshot with infinite loop that never reaches declared stop address", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Machine code: jmp $ (0xeb, 0xfe) - infinite loop at 0x401000
		const res = await tool.execute("test-infinite-loop-rejection", {
			action: "verify",
			snapshot: {
				arch: "x86_64",
				entry: "0x401000",
				stop_addresses: ["0x401010"], // Stop address never reached
				registers: { rip: "0x401000", rsp: "0x7ffffff0", rax: "0x0" },
				segments: [
					{
						address: "0x401000",
						bytes: "ebfe", // jmp .
						permissions: "r-x",
					},
				],
				symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x1" }],
				output: { kind: "register", target: "rax" },
			},
			recovered: {
				kind: "smt2",
				expression: "(_ bv0 64)", // Constant 0 candidate matches rax initial register
				inputs: [{ name: "x", size_bits: 64, reg: "rdi" }],
				output: { kind: "register", target: "rax" },
			},
			vectors: [{ x: 1 }],
			test_generation: { boundary: false, random_count: 0 },
			proof_mode: "finite_vectors",
		});

		expect(res.details.agreement_pct).toBe(0.0);
		expect(res.details.counterexamples?.length).toBeGreaterThan(0);
		expect(res.details.counterexamples![0].mismatch_reason).toContain("without reaching declared stop address");
		expect(res.details.assurance_level_recommendation).toBe("unverified");
	});

	it.skipIf(!hasTriton)(
		"executes actual LLVM IR via MCJIT and rejects candidate when LLVM is incorrect despite correct companion expression",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Companion expression is correct, but actual submitted LLVM IR returns incorrect constant 999
			const buggyLlvmIr = `
				define i64 @faulty_func(i32 %x) {
				entry:
					ret i64 999
				}
			`;

			const res = await tool.execute("test-incorrect-llvm-rejection", {
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
					llvm_ir: buggyLlvmIr,
					// Companion expression that is correct, but MUST NOT be used as proxy for LLVM IR
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
				},
				vectors: [{ x: 5 }, { x: 15 }],
			});

			expect(res.details.action).toBe("verify");
			expect(res.details.agreement_pct).toBe(0.0);
			expect(res.details.counterexamples?.length).toBeGreaterThan(0);
			// 999 in hex is 0x3e7
			expect(res.details.counterexamples![0].recovered_return).toBe("0x3e7");
			expect(res.details.assurance_level_recommendation).toBe("unverified");
			expect(res.details.smt_formal_proved).toBe(false);
			expect(res.details.side_effects_proved).toBe(false);
			expect(res.details.formal_proof_scope).not.toBe("full_algorithm");
		},
	);

	it.skipIf(!hasTriton)("separates finite_vectors and smt_formal outcomes accurately", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// 1. In 'finite_vectors' mode: 100% agreement awards 'dynamic_call_observation', not 'algorithm_recovery'
		const finiteRes = await tool.execute("test-finite-mode", {
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
			},
			vectors: [{ x: 5 }, { x: 10 }, { x: 12 }],
			proof_mode: "finite_vectors",
		});

		expect(finiteRes.details.agreement_pct).toBe(100.0);
		expect(finiteRes.details.assurance_level_recommendation).toBe("dynamic_call_observation");
		expect(finiteRes.details.smt_formal_proved).toBe(false);

		// 2. In 'smt_formal' mode: Z3 formal equivalence proof awards 'algorithm_recovery'
		const formalRes = await tool.execute("test-formal-mode", {
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
			},
			vectors: [{ x: 5 }, { x: 12 }],
			proof_mode: "smt_formal",
		});

		expect(formalRes.details.agreement_pct).toBe(100.0);
		expect(formalRes.details.assurance_level_recommendation).toBe("algorithm_recovery");
		expect(formalRes.details.smt_formal_proved).toBe(true);
		expect(formalRes.details.formal_proof_scope).toBe("full_algorithm");
		expect(formalRes.details.side_effects_proved).toBe(true);
	});

	it.skipIf(!hasTriton)("tracks out_of_domain_vectors when inputs exceed declared domain bounds", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Domain bound: x between 0 and 10
		const res = await tool.execute("test-domain-tracking", {
			action: "verify",
			snapshot: {
				arch: "x86_64",
				entry: "0x401000",
				stop_addresses: ["0x401025"],
				registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				segments: X86_64_FIXTURE_SNAPSHOT.segments,
				symbolic_inputs: [
					{
						name: "rdi",
						alias: "x",
						seed: "0x5",
						min: "0",
						max: "10",
					},
				],
				output: { kind: "register", target: "rax" },
			},
			recovered: {
				kind: "smt2",
				expression: "(bvadd x (_ bv5 32))", // Valid formula only for x <= 10
				inputs: [{ name: "x", size_bits: 32, reg: "rdi", min: "0", max: "10" }],
				output: { kind: "register", target: "rax" },
				memory_side_effects: [
					{
						address: "0x2000",
						size: 4,
						value: "0xcafe",
					},
				],
			},
			// Vectors: x=2, x=8 (in-domain); x=15, x=20 (out-of-domain)
			vectors: [{ x: 2 }, { x: 8 }, { x: 15 }, { x: 20 }],
			test_generation: { boundary: false, random_count: 0 },
			proof_mode: "finite_vectors",
		});

		expect(res.details.total_count).toBe(2);
		expect(res.details.passed_count).toBe(2);
		expect(res.details.agreement_pct).toBe(100.0);
		expect(res.details.out_of_domain_vectors?.length).toBe(2);
		expect(res.details.out_of_domain_vectors).toEqual([{ x: 15 }, { x: 20 }]);
	});

	it.skipIf(!hasTriton)(
		"supports symbolic memory-input bindings and updates concrete memory per test vector",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Machine code:
			//   0x401000: mov eax, dword ptr [0x2000] (8b 04 25 00 20 00 00)
			//   0x401007: add eax, 10                (83 c0 0a)
			//   0x40100a: ret                        (c3)
			const res = await tool.execute("test-memory-input-binding", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x40100a"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: [
						{
							address: "0x401000",
							bytes: "8b04250020000083c00ac3",
							permissions: "r-x",
						},
						{
							address: "0x2000",
							bytes: "00000000",
							permissions: "rw-",
						},
					],
					symbolic_inputs: [
						{
							kind: "memory",
							address: "0x2000",
							size: 4,
							alias: "mem_val",
							seed: "0x5",
						},
					],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "smt2",
					expression: "(bvadd mem_val (_ bv10 32))",
					inputs: [
						{
							name: "mem_val",
							size_bits: 32,
						},
					],
					output: { kind: "register", target: "rax" },
				},
				vectors: [{ mem_val: 1 }, { mem_val: 20 }, { mem_val: 100 }],
				test_generation: { boundary: false, random_count: 0 },
				proof_mode: "finite_vectors",
			});

			expect(res.details.action).toBe("verify");
			expect(res.details.passed_count).toBe(3);
			expect(res.details.total_count).toBe(3);
			expect(res.details.agreement_pct).toBe(100.0);
			expect(res.details.counterexamples?.length).toBe(0);
		},
	);

	it.skipIf(!hasTriton)(
		"verifies candidate with real asymmetric domain guard restricted to specific path",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// Candidate formula is only valid for x > 10, declared with explicit domain_predicate
			const res = await tool.execute("test-asymmetric-domain-guard", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0xc" }],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "smt2",
					expression: "(bvadd (bvmul x (_ bv2 32)) (_ bv1 32))",
					domain_predicate: "(bvugt x (_ bv10 32))",
					inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
					output: { kind: "register", target: "rax" },
					memory_side_effects: [
						{
							address: "0x2000",
							size: 4,
							value: "0xbeef",
						},
					],
					strict_memory_check: true,
				},
				// x=5 and x=8 are out-of-domain (<= 10); x=12 and x=20 are in-domain (> 10)
				vectors: [{ x: 5 }, { x: 8 }, { x: 12 }, { x: 20 }],
				test_generation: { boundary: false, random_count: 0 },
				proof_mode: "both",
			});

			expect(res.details.action).toBe("verify");
			expect(res.details.total_count).toBe(2);
			expect(res.details.passed_count).toBe(2);
			expect(res.details.agreement_pct).toBe(100.0);
			expect(res.details.out_of_domain_vectors?.length).toBe(2);
			expect(res.details.out_of_domain_vectors).toEqual([{ x: 5 }, { x: 8 }]);
			expect(res.details.assurance_level_recommendation).toBe("algorithm_recovery");
		},
	);

	it.skipIf(!hasTriton)("filters out-of-domain vectors accurately with top-level negated domain guard", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Negated domain guard: (not (= x 10)) - excludes only x = 10
		const res = await tool.execute("test-negated-domain-guard", {
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
				domain_predicate: "(not (= x (_ bv10 32)))",
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
			// x=10 should be filtered out into out_of_domain_vectors
			vectors: [{ x: 5 }, { x: 10 }, { x: 15 }],
			test_generation: { boundary: false, random_count: 0 },
			proof_mode: "finite_vectors",
		});

		expect(res.details.action).toBe("verify");
		expect(res.details.total_count).toBe(2);
		expect(res.details.passed_count).toBe(2);
		expect(res.details.agreement_pct).toBe(100.0);
		expect(res.details.out_of_domain_vectors?.length).toBe(1);
		expect(res.details.out_of_domain_vectors).toEqual([{ x: 10 }]);
	});

	it.skipIf(!hasTriton)(
		"correctly validates unsigned high-bit domain [0x80000000, 0xffffffff] and reports counterexample for incorrect candidate",
		async () => {
			const session = createMockSession(tempDir);
			const tool = new NativeRecoverTool(session);

			// High-bit unsigned domain: min=0x80000000, max=0xffffffff (values with MSB set)
			// Wrong candidate: returns (x + 1) instead of (x * 2 + 1)
			const res = await tool.execute("test-highbit-domain-rejection", {
				action: "verify",
				snapshot: {
					arch: "x86_64",
					entry: "0x401000",
					stop_addresses: ["0x401025"],
					registers: { rip: "0x401000", rsp: "0x7ffffff0" },
					segments: X86_64_FIXTURE_SNAPSHOT.segments,
					symbolic_inputs: [
						{
							name: "rdi",
							alias: "x",
							seed: "0x80000005",
							min: "0x80000000",
							max: "0xffffffff",
						},
					],
					output: { kind: "register", target: "rax" },
				},
				recovered: {
					kind: "smt2",
					expression: "(bvadd x (_ bv1 32))", // Wrong candidate on x > 10 branch
					inputs: [{ name: "x", size_bits: 32, reg: "rdi", min: "0x80000000", max: "0xffffffff" }],
					output: { kind: "register", target: "rax" },
					memory_side_effects: [
						{
							address: "0x2000",
							size: 4,
							value: "0xbeef",
						},
					],
				},
				vectors: [{ x: "0x80000001" }, { x: "0x90000000" }],
				test_generation: { boundary: false, random_count: 0 },
				proof_mode: "both",
			});

			expect(res.details.action).toBe("verify");
			expect(res.details.agreement_pct).toBe(0.0);
			expect(res.details.smt_formal_proved).toBe(false);
			expect(res.details.counterexamples?.length).toBeGreaterThan(0);
			expect(res.details.assurance_level_recommendation).toBe("unverified");
		},
	);

	it.skipIf(!hasTriton)("rejects snapshot reading uninitialized register during differential execution", async () => {
		const session = createMockSession(tempDir);
		const tool = new NativeRecoverTool(session);

		// Instruction: mov eax, ebx (89 d8), ebx is uninitialized
		const res = await tool.execute("test-uninit-register-rejection", {
			action: "verify",
			snapshot: {
				arch: "x86_64",
				entry: "0x401000",
				stop_addresses: ["0x401002"],
				registers: { rip: "0x401000", rsp: "0x7ffffff0" },
				segments: [
					{
						address: "0x401000",
						bytes: "89d8",
						permissions: "r-x",
					},
				],
				symbolic_inputs: [{ name: "rdi", alias: "x", seed: "0x1" }],
				output: { kind: "register", target: "rax" },
			},
			recovered: {
				kind: "smt2",
				expression: "(_ bv0 32)",
				inputs: [{ name: "x", size_bits: 32, reg: "rdi" }],
				output: { kind: "register", target: "rax" },
			},
			vectors: [{ x: 1 }],
			test_generation: { boundary: false, random_count: 0 },
			proof_mode: "finite_vectors",
		});

		expect(res.details.action).toBe("verify");
		expect(res.details.agreement_pct).toBe(0.0);
		expect(res.details.counterexamples?.length).toBeGreaterThan(0);
		expect(res.details.assurance_level_recommendation).toBe("unverified");
	});
});
