import type { AgentToolResult } from "@reverse/agent";
import { describe, expect, it } from "bun:test";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { Settings } from "@reverse/coding-agent/config/settings";
import { createTools, EvmInspectTool, type ToolSession } from "@reverse/coding-agent/tools";
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

/**
 * Builds synthetic EVM bytecode with standard Solidity dispatcher and CBOR metadata.
 */
function createSyntheticSolidityBytecode(): string {
	// 1. Storage setup: PUSH1 0x80, PUSH1 0x40, MSTORE
	// 2. Calldata load: PUSH1 0x04, CALLDATASIZE, LT, PUSH1 0x22, JUMPI
	// 3. Extract 4-byte selector: PUSH1 0x00, CALLDATALOAD, PUSH1 0xe0, SHR
	// 4. Dispatcher:
	//    DUP1, PUSH4 0xa9059cbb, EQ, PUSH1 0x27, JUMPI  (transfer)
	//    DUP1, PUSH4 0x70a08231, EQ, PUSH1 0x30, JUMPI  (balanceOf)
	//    PUSH0, PUSH0, REVERT
	// 5. Jumpdest targets:
	//    PC 0x22: JUMPDEST, STOP
	//    PC 0x27: JUMPDEST, PUSH1 0x01, STOP
	//    PC 0x30: JUMPDEST, PUSH1 0x02, STOP
	const opcodesHex =
		"6080604052" + // PC 0..4
		"60043610602257" + // PC 5..11
		"60003560e01c" + // PC 12..17
		"8063a9059cbb14602757" + // PC 18..27: selector transfer(address,uint256)
		"806370a0823114603057" + // PC 28..37: selector balanceOf(address)
		"5f5ffd" + // PC 38..40: PUSH0, PUSH0, REVERT
		"5b00" + // PC 41 (0x29? let's make real jumpdests match): JUMPDEST, STOP
		"5b600100" + // JUMPDEST, PUSH1 0x01, STOP
		"5b600200"; // JUMPDEST, PUSH1 0x02, STOP

	// Add synthetic CBOR metadata trailer:
	// CBOR map with solc 0.8.20 and ipfs hash:
	// a2 (map 2)
	// 64 73 6f 6c 63 (text "solc")
	// 43 00 08 14 (bytes 3: 0.8.20)
	// 64 69 70 66 73 (text "ipfs")
	// 58 22 (bytes 34) + 34 dummy bytes
	// length 2 bytes
	const cborBody =
		"a2" +
		"64736f6c63" +
		"43000814" +
		"6469706673" +
		"5822122011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff";
	const cborLen = cborBody.length / 2;
	const lenHex = cborLen.toString(16).padStart(4, "0");

	return `0x${opcodesHex}${cborBody}${lenHex}`;
}

// ============================================================================
// Registration and Discovery
// ============================================================================

describe("evm_inspect registration and discovery", () => {
	it("registers in BUILTIN_TOOL_NAMES and normalizes aliases", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("evm_inspect");
		expect(normalizeToolName("evm_inspect")).toBe("evm_inspect");
		expect(normalizeToolName("evm")).toBe("evm_inspect");
		expect(normalizeToolName("evm_disasm")).toBe("evm_inspect");
		expect(normalizeToolName("bytecode_inspect")).toBe("evm_inspect");
	});

	it("creates tool instance with discoverable loadMode and read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-disc-"));
		try {
			const session = createTestSession(tempDir);
			const tools = await createTools(session, ["evm_inspect"]);
			const tool = tools.find(t => t.name === "evm_inspect") as EvmInspectTool | undefined;
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("evm_inspect");
			expect(tool?.approval).toBe("read");
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.label).toBe("EVM Bytecode Inspect");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Input Validation and Error Handling
// ============================================================================

describe("evm_inspect input validation", () => {
	it("rejects call when neither code nor path is provided", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);
			await expect(tool.execute("call-1", { action: "info" })).rejects.toThrow(
				"Either 'code' (raw hex string) or 'path'",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects invalid hex characters in code", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-hex-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);
			await expect(tool.execute("call-1", { action: "info", code: "0x6080ZZZZinvalid" })).rejects.toThrow(
				"Invalid hex string",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects non-existent file path", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-path-err-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);
			await expect(tool.execute("call-1", { action: "info", path: "nonexistent.bin" })).rejects.toThrow(
				"File not found",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Opcode Disassembly
// ============================================================================

describe("evm_inspect opcode disassembly", () => {
	it("disassembles standard EVM instructions with decoded push values", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-disasm-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			// PUSH1 0x80, PUSH1 0x40, MSTORE, PUSH0, STOP
			const bytecode = "0x60806040525f00";
			const result = await tool.execute("call-1", { action: "disasm", code: bytecode });

			expect(result.details.action).toBe("disasm");
			expect(result.details.instructionCount).toBe(5);
			const instrs = result.details.instructions!;
			expect(instrs[0].mnemonic).toBe("PUSH1");
			expect(instrs[0].pushBytes).toBe("0x80");
			expect(instrs[0].pushValue).toBe(128);

			expect(instrs[1].mnemonic).toBe("PUSH1");
			expect(instrs[1].pushBytes).toBe("0x40");
			expect(instrs[1].pushValue).toBe(64);

			expect(instrs[2].mnemonic).toBe("MSTORE");
			expect(instrs[3].mnemonic).toBe("PUSH0");
			expect(instrs[4].mnemonic).toBe("STOP");

			const text = textOf(result);
			expect(text).toContain("PUSH1");
			expect(text).toContain("MSTORE");
			expect(text).toContain("PUSH0");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("supports filter and pagination on disassembly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-page-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			const code = createSyntheticSolidityBytecode();
			const pagedResult = await tool.execute("call-page", {
				action: "disasm",
				code,
				limit: 3,
				offset: 2,
			});
			expect(pagedResult.details.instructions?.length).toBe(3);

			const filteredResult = await tool.execute("call-filter", {
				action: "disasm",
				code,
				filter: "JUMP",
			});
			expect(filteredResult.details.instructions?.length).toBeGreaterThan(0);
			for (const instr of filteredResult.details.instructions!) {
				expect(instr.mnemonic.includes("JUMP") || (instr.pushBytes && instr.pushBytes.includes("jump"))).toBe(true);
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// Function Selector & Interface Extraction
// ============================================================================

describe("evm_inspect function selector extraction", () => {
	it("extracts 4-byte selectors and resolves ERC-20 interface signatures", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-sel-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			const code = createSyntheticSolidityBytecode();
			const result = await tool.execute("call-selectors", { action: "selectors", code });

			expect(result.details.selectors?.length).toBeGreaterThanOrEqual(2);
			const transferSel = result.details.selectors?.find(s => s.selector === "0xa9059cbb");
			expect(transferSel).toBeDefined();
			expect(transferSel?.signature).toBe("transfer(address,uint256)");
			expect(transferSel?.standard).toBe("ERC-20");

			const balanceSel = result.details.selectors?.find(s => s.selector === "0x70a08231");
			expect(balanceSel).toBeDefined();
			expect(balanceSel?.signature).toBe("balanceOf(address)");
			expect(balanceSel?.standard).toBe("ERC-20");

			const text = textOf(result);
			expect(text).toContain("0xa9059cbb");
			expect(text).toContain("transfer(address,uint256)");
			expect(text).toContain("ERC-20");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

// ============================================================================
// CBOR Metadata and Proxy Detection
// ============================================================================

describe("evm_inspect CBOR metadata and proxy forensics", () => {
	it("decodes Solidity compiler version from CBOR trailer", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-cbor-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			const code = createSyntheticSolidityBytecode();
			const result = await tool.execute("call-metadata", { action: "metadata", code });

			expect(result.details.metadata).toBeDefined();
			expect(result.details.metadata?.compiler).toBe("solc");
			expect(result.details.metadata?.version).toBe("0.8.20");
			expect(result.details.metadata?.ipfs).toBeDefined();

			const text = textOf(result);
			expect(text).toContain("solc");
			expect(text).toContain("0.8.20");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("detects ERC-1167 Minimal Proxy Clone and extracts implementation address", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-clone-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			// ERC-1167 minimal proxy clone targeting 0x1122334455667788990011223344556677889900
			const cloneBytecode =
				"363d3d373d3d3d363d7311223344556677889900112233445566778899005af43d82803e903d91602b57fd5bf3";
			const result = await tool.execute("call-info", { action: "info", code: cloneBytecode });

			expect(result.details.proxyPattern).toContain("ERC-1167 Minimal Proxy");
			expect(result.details.proxyPattern).toContain("0x1122334455667788990011223344556677889900");

			const text = textOf(result);
			expect(text).toContain("ERC-1167 Minimal Proxy");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reads bytecode from local hex text file", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "evm-file-"));
		try {
			const session = createTestSession(tempDir);
			const tool = new EvmInspectTool(session);

			const filePath = path.join(tempDir, "contract.hex");
			await fs.writeFile(filePath, "0x6080604052348015600f57600080fd5b00\n");

			const result = await tool.execute("call-file", { action: "info", path: "contract.hex" });
			expect(result.details.source).toBe("file");
			expect(result.details.bytecodeSize).toBe(17);
			expect(result.details.instructionCount).toBeGreaterThan(5);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
