/**
 * Deterministic branching function fixtures for native recovery and differential verification.
 *
 * Ground-truth specification (C reference):
 * ```c
 * // Input: x (uint32_t)
 * // Side effect: *(uint32_t*)0x2000 (or 0x200) = (x > 10) ? 0xbeef : 0xcafe;
 * // Return value: (x > 10) ? (x * 2 + 1) : (x + 5);
 * uint32_t branching_target(uint32_t x) {
 *     if (x > 10) {
 *         *(volatile uint32_t*)0x2000 = 0xbeef;
 *         return x * 2 + 1;
 *     } else {
 *         *(volatile uint32_t*)0x2000 = 0xcafe;
 *         return x + 5;
 *     }
 * }
 * ```
 */

export interface RecoveryFixtureSnapshot {
	arch: "x86_64" | "aarch64" | "arm32";
	entry: string;
	stop_addresses: string[];
	registers: Record<string, string>;
	segments: Array<{ address: string; bytes: string; permissions?: string }>;
	symbolic_inputs: Array<{ name: string; alias: string; seed: string }>;
	output: { kind: "register"; target: string };
	memory_side_effect_addr: string;
	expected_memory_side_effect: {
		branch_a: string; // when x <= 10: 0xcafe
		branch_b: string; // when x > 10:  0xbeef
	};
	expected_eval: (x: number | bigint | string) => { ret: number | bigint; mem: number | bigint };
}

/**
 * 1. x86_64 Branching Machine Function:
 * Disassembly:
 *   0x401000: cmp rdi, 10
 *   0x401004: jg 0x401016
 *   0x401006: mov dword ptr [0x2000], 0xcafe
 *   0x401011: lea eax, [rdi + 5]
 *   0x401014: jmp 0x401025
 *   0x401016: mov dword ptr [0x2000], 0xbeef
 *   0x401021: lea eax, [rdi + rdi + 1]
 *   0x401025: ret
 */
export const X86_64_FIXTURE_SNAPSHOT: RecoveryFixtureSnapshot = {
	arch: "x86_64",
	entry: "0x401000",
	stop_addresses: ["0x401025"],
	registers: {
		rip: "0x401000",
		rsp: "0x7ffffff0",
	},
	segments: [
		{
			address: "0x401000",
			bytes: "4883ff0a7710c7042500200000feca00008d4705eb0fc7042500200000efbe00008d443f01c3",
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
			name: "rdi",
			alias: "x",
			seed: "0x5",
		},
	],
	output: {
		kind: "register",
		target: "rax",
	},
	memory_side_effect_addr: "0x2000",
	expected_memory_side_effect: {
		branch_a: "0xcafe",
		branch_b: "0xbeef",
	},
	expected_eval: (x: number | bigint | string) => {
		const xBig = typeof x === "bigint" ? x : typeof x === "string" ? BigInt(x) : BigInt(Math.trunc(x));
		const isBranchB = xBig > 10n;
		return {
			ret: Number(isBranchB ? (xBig * 2n + 1n) & 0xffffffffn : (xBig + 5n) & 0xffffffffn),
			mem: isBranchB ? 0xbeef : 0xcafe,
		};
	},
};

/**
 * 2. AArch64 Branching Machine Function:
 * Disassembly:
 *   0x401000: cmp x0, #10
 *   0x401004: b.gt #0x40101c
 *   0x401008: mov w1, #0xcafe
 *   0x40100c: mov x2, #0x200
 *   0x401010: str w1, [x2]
 *   0x401014: add x0, x0, #5
 *   0x401018: b #0x401030
 *   0x40101c: mov w1, #0xbeef
 *   0x401020: mov x2, #0x200
 *   0x401024: str w1, [x2]
 *   0x401028: add x1, x0, x0
 *   0x40102c: add x0, x1, #1
 *   0x401030: ret
 */
export const AARCH64_FIXTURE_SNAPSHOT: RecoveryFixtureSnapshot = {
	arch: "aarch64",
	entry: "0x401000",
	stop_addresses: ["0x401030"],
	registers: {
		pc: "0x401000",
		sp: "0x7ffffff0",
	},
	segments: [
		{
			address: "0x401000",
			bytes: "1f2800f1c8000054c15f9952024080d2410000b90014009106000014e1dd9752024080d2410000b90100008b20040091c0035fd6",
			permissions: "r-x",
		},
		{
			address: "0x200",
			bytes: "00000000",
			permissions: "rw-",
		},
	],
	symbolic_inputs: [
		{
			name: "x0",
			alias: "x",
			seed: "0x3",
		},
	],
	output: {
		kind: "register",
		target: "x0",
	},
	memory_side_effect_addr: "0x200",
	expected_memory_side_effect: {
		branch_a: "0xcafe",
		branch_b: "0xbeef",
	},
	expected_eval: (x: number | bigint | string) => {
		const xBig = typeof x === "bigint" ? x : typeof x === "string" ? BigInt(x) : BigInt(Math.trunc(x));
		const mask64 = 0xffffffffffffffffn;
		const isBranchB = xBig > 10n;
		return {
			ret: isBranchB ? (xBig * 2n + 1n) & mask64 : (xBig + 5n) & mask64,
			mem: isBranchB ? 0xbeef : 0xcafe,
		};
	},
};

/**
 * 3. ARM32 Branching Machine Function:
 * Disassembly:
 *   0x401000: cmp r0, #10
 *   0x401004: bgt #0x40101c
 *   0x401008: movw r1, #0xcafe
 *   0x40100c: mov r2, #0x200
 *   0x401010: str r1, [r2]
 *   0x401014: add r0, r0, #5
 *   0x401018: b #0x401030
 *   0x40101c: movw r1, #0xbeef
 *   0x401020: mov r2, #0x200
 *   0x401024: str r1, [r2]
 *   0x401028: add r1, r0, r0
 *   0x40102c: add r0, r1, #1
 *   0x401030: bx lr
 */
export const ARM32_FIXTURE_SNAPSHOT: RecoveryFixtureSnapshot = {
	arch: "arm32",
	entry: "0x401000",
	stop_addresses: ["0x401030"],
	registers: {
		pc: "0x401000",
		sp: "0x7ffffff0",
		r14: "0x401030", // lr = stop
		r1: "0x0",
		r2: "0x0",
	},
	segments: [
		{
			address: "0x401000",
			bytes: "0a0050e30400008afe1a0ce3022ca0e3001082e5050080e2040000eaef1e0be3022ca0e3001082e5001080e0010081e21eff2fe1",
			permissions: "r-x",
		},
		{
			address: "0x200",
			bytes: "00000000",
			permissions: "rw-",
		},
	],
	symbolic_inputs: [
		{
			name: "r0",
			alias: "x",
			seed: "0x4",
		},
	],
	output: {
		kind: "register",
		target: "r0",
	},
	memory_side_effect_addr: "0x200",
	expected_memory_side_effect: {
		branch_a: "0xcafe",
		branch_b: "0xbeef",
	},
	expected_eval: (x: number | bigint | string) => {
		const xBig = typeof x === "bigint" ? x : typeof x === "string" ? BigInt(x) : BigInt(Math.trunc(x));
		const isBranchB = xBig > 10n;
		return {
			ret: Number(isBranchB ? (xBig * 2n + 1n) & 0xffffffffn : (xBig + 5n) & 0xffffffffn),
			mem: isBranchB ? 0xbeef : 0xcafe,
		};
	},
};

/**
 * Standard test vectors spanning boundary values and representative range:
 */
export const DETERMINISTIC_TEST_VECTORS = [
	{ x: 0 },
	{ x: 1 },
	{ x: 9 },
	{ x: 10 }, // Boundary: <= 10 -> branch A
	{ x: 11 }, // Boundary: > 10  -> branch B
	{ x: 12 },
	{ x: 50 },
	{ x: 255 },
	{ x: 65535 },
	{ x: 0x7fffffff },
	{ x: 0xffffffff },
];

/**
 * 4. x86_64 Nested 4-Path Branching Function (Sequential Reconverging Branches)
 */
export const X86_64_NESTED_4PATH_SNAPSHOT = {
	arch: "x86_64" as const,
	entry: "0x401000",
	stop_addresses: ["0x40102c"],
	registers: {
		rip: "0x401000",
		rsp: "0x7ffffff0",
	},
	segments: [
		{
			address: "0x401000",
			bytes: "4883ff0a77144883fe147707b80a000000eb19b814000000eb124883fe147707b81e000000eb05b828000000c3",
			permissions: "r-x",
		},
	],
	symbolic_inputs: [
		{ name: "rdi", alias: "x", seed: "0x5" },
		{ name: "rsi", alias: "y", seed: "0x5" },
	],
	output: {
		kind: "register" as const,
		target: "rax",
	},
	expected_eval: (x: number, y: number) => {
		if (x > 10) {
			return y > 20 ? 40 : 30;
		} else {
			return y > 20 ? 20 : 10;
		}
	},
};
