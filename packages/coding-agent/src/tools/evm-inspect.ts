import * as fs from "node:fs/promises";
import { createHash } from "node:crypto";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback, ToolTier } from "@reverse/agent";
import { type } from "@reverse/omptype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { formatBytes } from "@reverse/utils";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import evmInspectDescription from "../prompts/tools/evm-inspect.md" with { type: "text" };

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 500;

// ============================================================================
// Parameter Schema
// ============================================================================

const evmInspectSchema = type({
	action: type
		.enumerated("info", "disasm", "selectors", "metadata")
		.describe(
			"Inspection action: info (bytecode summary, proxy/contract detection, instruction metrics), disasm (paginated opcode disassembly with decoded push data), selectors (extracted Solidity function selectors and matched interfaces), or metadata (decoded compiler CBOR metadata)",
		),
	"code?": type("string").describe(
		"Raw hex bytecode string (with or without '0x' prefix; optional if path is provided)",
	),
	"path?": type("string").describe(
		"Path to local file containing hex bytecode or raw binary (optional if code is provided)",
	),
	"filter?": type("string").describe(
		"Optional case-insensitive substring filter for mnemonics or selector signatures",
	),
	"limit?": type("number.integer >= 1").describe("Maximum instructions or selectors to return (default 50, max 500)"),
	"offset?": type("number.integer >= 0").describe("Pagination offset (default 0)"),
});

export type EvmInspectParams = typeof evmInspectSchema.infer;
export type EvmInspectAction = EvmInspectParams["action"];

// ============================================================================
// Data Models
// ============================================================================

export interface EvmInstruction {
	pc: number;
	opcode: number;
	mnemonic: string;
	pushBytes?: string;
	pushValue?: number;
}

export interface EvmSelectorEntry {
	selector: string;
	pc: number;
	jumpDest?: number;
	verifiedJumpDest: boolean;
	signature?: string;
	standard?: string;
}

export interface EvmCborMetadata {
	compiler?: string;
	version?: string;
	ipfs?: string;
	bzzr?: string;
	rawHex: string;
}

export interface EvmInspectDetails {
	action: EvmInspectAction;
	source: "code" | "file";
	sourcePath?: string;
	bytecodeSize: number;
	sha256: string;
	instructionCount: number;
	jumpDestCount: number;
	bytecodeType: "runtime" | "deployment" | "empty";
	proxyPattern?: string;
	detectedStandards: string[];
	metadata?: EvmCborMetadata;
	instructions?: EvmInstruction[];
	selectors?: EvmSelectorEntry[];
	totalInstructions?: number;
	totalSelectors?: number;
}

// ============================================================================
// EVM Opcode Definitions
// ============================================================================

interface OpcodeMeta {
	mnemonic: string;
	pushLength: number;
}

const OPCODES: Record<number, OpcodeMeta> = {
	0x00: { mnemonic: "STOP", pushLength: 0 },
	0x01: { mnemonic: "ADD", pushLength: 0 },
	0x02: { mnemonic: "MUL", pushLength: 0 },
	0x03: { mnemonic: "SUB", pushLength: 0 },
	0x04: { mnemonic: "DIV", pushLength: 0 },
	0x05: { mnemonic: "SDIV", pushLength: 0 },
	0x06: { mnemonic: "MOD", pushLength: 0 },
	0x07: { mnemonic: "SMOD", pushLength: 0 },
	0x08: { mnemonic: "ADDMOD", pushLength: 0 },
	0x09: { mnemonic: "MULMOD", pushLength: 0 },
	0x0a: { mnemonic: "EXP", pushLength: 0 },
	0x0b: { mnemonic: "SIGNEXTEND", pushLength: 0 },

	0x10: { mnemonic: "LT", pushLength: 0 },
	0x11: { mnemonic: "GT", pushLength: 0 },
	0x12: { mnemonic: "SLT", pushLength: 0 },
	0x13: { mnemonic: "SGT", pushLength: 0 },
	0x14: { mnemonic: "EQ", pushLength: 0 },
	0x15: { mnemonic: "ISZERO", pushLength: 0 },
	0x16: { mnemonic: "AND", pushLength: 0 },
	0x17: { mnemonic: "OR", pushLength: 0 },
	0x18: { mnemonic: "XOR", pushLength: 0 },
	0x19: { mnemonic: "NOT", pushLength: 0 },
	0x1a: { mnemonic: "BYTE", pushLength: 0 },
	0x1b: { mnemonic: "SHL", pushLength: 0 },
	0x1c: { mnemonic: "SHR", pushLength: 0 },
	0x1d: { mnemonic: "SAR", pushLength: 0 },

	0x20: { mnemonic: "KECCAK256", pushLength: 0 },

	0x30: { mnemonic: "ADDRESS", pushLength: 0 },
	0x31: { mnemonic: "BALANCE", pushLength: 0 },
	0x32: { mnemonic: "ORIGIN", pushLength: 0 },
	0x33: { mnemonic: "CALLER", pushLength: 0 },
	0x34: { mnemonic: "CALLVALUE", pushLength: 0 },
	0x35: { mnemonic: "CALLDATALOAD", pushLength: 0 },
	0x36: { mnemonic: "CALLDATASIZE", pushLength: 0 },
	0x37: { mnemonic: "CALLDATACOPY", pushLength: 0 },
	0x38: { mnemonic: "CODESIZE", pushLength: 0 },
	0x39: { mnemonic: "CODECOPY", pushLength: 0 },
	0x3a: { mnemonic: "GASPRICE", pushLength: 0 },
	0x3b: { mnemonic: "EXTCODESIZE", pushLength: 0 },
	0x3c: { mnemonic: "EXTCODECOPY", pushLength: 0 },
	0x3d: { mnemonic: "RETURNDATASIZE", pushLength: 0 },
	0x3e: { mnemonic: "RETURNDATACOPY", pushLength: 0 },
	0x3f: { mnemonic: "EXTCODEHASH", pushLength: 0 },

	0x40: { mnemonic: "BLOCKHASH", pushLength: 0 },
	0x41: { mnemonic: "COINBASE", pushLength: 0 },
	0x42: { mnemonic: "TIMESTAMP", pushLength: 0 },
	0x43: { mnemonic: "NUMBER", pushLength: 0 },
	0x44: { mnemonic: "PREVRANDAO", pushLength: 0 },
	0x45: { mnemonic: "GASLIMIT", pushLength: 0 },
	0x46: { mnemonic: "CHAINID", pushLength: 0 },
	0x47: { mnemonic: "SELFBALANCE", pushLength: 0 },
	0x48: { mnemonic: "BASEFEE", pushLength: 0 },
	0x49: { mnemonic: "BLOBHASH", pushLength: 0 },
	0x4a: { mnemonic: "BLOBBASEFEE", pushLength: 0 },

	0x50: { mnemonic: "POP", pushLength: 0 },
	0x51: { mnemonic: "MLOAD", pushLength: 0 },
	0x52: { mnemonic: "MSTORE", pushLength: 0 },
	0x53: { mnemonic: "MSTORE8", pushLength: 0 },
	0x54: { mnemonic: "SLOAD", pushLength: 0 },
	0x55: { mnemonic: "SSTORE", pushLength: 0 },
	0x56: { mnemonic: "JUMP", pushLength: 0 },
	0x57: { mnemonic: "JUMPI", pushLength: 0 },
	0x58: { mnemonic: "PC", pushLength: 0 },
	0x59: { mnemonic: "MSIZE", pushLength: 0 },
	0x5a: { mnemonic: "GAS", pushLength: 0 },
	0x5b: { mnemonic: "JUMPDEST", pushLength: 0 },
	0x5c: { mnemonic: "TLOAD", pushLength: 0 },
	0x5d: { mnemonic: "TSTORE", pushLength: 0 },
	0x5e: { mnemonic: "MCOPY", pushLength: 0 },
	0x5f: { mnemonic: "PUSH0", pushLength: 0 },

	0xa0: { mnemonic: "LOG0", pushLength: 0 },
	0xa1: { mnemonic: "LOG1", pushLength: 0 },
	0xa2: { mnemonic: "LOG2", pushLength: 0 },
	0xa3: { mnemonic: "LOG3", pushLength: 0 },
	0xa4: { mnemonic: "LOG4", pushLength: 0 },

	0xf0: { mnemonic: "CREATE", pushLength: 0 },
	0xf1: { mnemonic: "CALL", pushLength: 0 },
	0xf2: { mnemonic: "CALLCODE", pushLength: 0 },
	0xf3: { mnemonic: "RETURN", pushLength: 0 },
	0xf4: { mnemonic: "DELEGATECALL", pushLength: 0 },
	0xf5: { mnemonic: "CREATE2", pushLength: 0 },
	0xfa: { mnemonic: "STATICCALL", pushLength: 0 },
	0xfd: { mnemonic: "REVERT", pushLength: 0 },
	0xfe: { mnemonic: "INVALID", pushLength: 0 },
	0xff: { mnemonic: "SELFDESTRUCT", pushLength: 0 },
};

// Populate PUSH1 through PUSH32 (0x60..0x7f)
for (let i = 1; i <= 32; i++) {
	OPCODES[0x60 + i - 1] = { mnemonic: `PUSH${i}`, pushLength: i };
}

// Populate DUP1 through DUP16 (0x80..0x8f)
for (let i = 1; i <= 16; i++) {
	OPCODES[0x80 + i - 1] = { mnemonic: `DUP${i}`, pushLength: 0 };
}

// Populate SWAP1 through SWAP16 (0x90..0x9f)
for (let i = 1; i <= 16; i++) {
	OPCODES[0x90 + i - 1] = { mnemonic: `SWAP${i}`, pushLength: 0 };
}

// ============================================================================
// Known Standard Function Selectors
// ============================================================================

const KNOWN_SELECTORS: Record<string, { signature: string; standard: string }> = {
	// ERC-20
	"0xa9059cbb": { signature: "transfer(address,uint256)", standard: "ERC-20" },
	"0x70a08231": { signature: "balanceOf(address)", standard: "ERC-20" },
	"0x095ea7b3": { signature: "approve(address,uint256)", standard: "ERC-20" },
	"0x23b872dd": { signature: "transferFrom(address,address,uint256)", standard: "ERC-20" },
	"0x18160ddd": { signature: "totalSupply()", standard: "ERC-20" },
	"0xdd62ed3e": { signature: "allowance(address,address)", standard: "ERC-20" },
	"0x06fdde03": { signature: "name()", standard: "ERC-20" },
	"0x95d89b41": { signature: "symbol()", standard: "ERC-20" },
	"0x313ce567": { signature: "decimals()", standard: "ERC-20" },

	// ERC-721
	"0x6352211e": { signature: "ownerOf(uint256)", standard: "ERC-721" },
	"0x42842e0e": { signature: "safeTransferFrom(address,address,uint256)", standard: "ERC-721" },
	"0xb88d4fde": { signature: "safeTransferFrom(address,address,uint256,bytes)", standard: "ERC-721" },
	"0x081812fc": { signature: "getApproved(uint256)", standard: "ERC-721" },
	"0xa22cb465": { signature: "setApprovalForAll(address,bool)", standard: "ERC-721" },
	"0xe985e9c5": { signature: "isApprovedForAll(address,address)", standard: "ERC-721" },
	"0xc87b56dd": { signature: "tokenURI(uint256)", standard: "ERC-721" },

	// ERC-1155
	"0xf242432a": { signature: "safeTransferFrom(address,address,uint256,uint256,bytes)", standard: "ERC-1155" },
	"0x2eb2c2d6": {
		signature: "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
		standard: "ERC-1155",
	},
	"0x00fdd58e": { signature: "balanceOf(address,uint256)", standard: "ERC-1155" },
	"0x4e1273f4": { signature: "balanceOfBatch(address[],uint256[])", standard: "ERC-1155" },
	"0x0e89341c": { signature: "uri(uint256)", standard: "ERC-1155" },

	// ERC-165
	"0x01ffc9a7": { signature: "supportsInterface(bytes4)", standard: "ERC-165" },

	// Ownable / AccessControl
	"0x8da5cb5b": { signature: "owner()", standard: "Ownable" },
	"0xf2fde38b": { signature: "transferOwnership(address)", standard: "Ownable" },
	"0x715018a6": { signature: "renounceOwnership()", standard: "Ownable" },
	"0x248a944d": { signature: "hasRole(bytes32,address)", standard: "AccessControl" },
	"0x2f2ff15d": { signature: "grantRole(bytes32,address)", standard: "AccessControl" },
	"0xd547741f": { signature: "revokeRole(bytes32,address)", standard: "AccessControl" },
	"0x36569e13": { signature: "getRoleAdmin(bytes32)", standard: "AccessControl" },

	// Upgradeability / Proxy
	"0x5c60d14f": { signature: "implementation()", standard: "Proxy" },
	"0x3659cfe6": { signature: "upgradeTo(address)", standard: "Proxy" },
	"0x4f1f5451": { signature: "upgradeToAndCall(address,bytes)", standard: "Proxy" },
	"0xf851a440": { signature: "admin()", standard: "Proxy" },
	"0x8f32d59b": { signature: "changeAdmin(address)", standard: "Proxy" },

	// Pausable / Multicall / Vault
	"0x8456cb59": { signature: "pause()", standard: "Pausable" },
	"0x3f4ba83a": { signature: "unpause()", standard: "Pausable" },
	"0x5c975abb": { signature: "paused()", standard: "Pausable" },
	"0xac9650d8": { signature: "multicall(bytes[])", standard: "Multicall" },
	"0x2e1a7d4d": { signature: "withdraw(uint256)", standard: "WETH/Vault" },
	"0xd0e30db0": { signature: "deposit()", standard: "WETH/Vault" },
};

// ============================================================================
// Disassembler & Forensics
// ============================================================================

export function disassembleBytecode(buffer: Buffer): {
	instructions: EvmInstruction[];
	jumpDests: Set<number>;
} {
	const instructions: EvmInstruction[] = [];
	const jumpDests = new Set<number>();
	let pc = 0;

	while (pc < buffer.length) {
		const curPc = pc;
		const opcode = buffer[pc];
		const meta = OPCODES[opcode] ?? { mnemonic: `UNKNOWN_0x${opcode.toString(16).padStart(2, "0")}`, pushLength: 0 };

		let pushBytes: string | undefined;
		let pushValue: number | undefined;

		if (meta.pushLength > 0) {
			const start = pc + 1;
			const end = Math.min(buffer.length, start + meta.pushLength);
			const slice = buffer.subarray(start, end);
			pushBytes = `0x${slice.toString("hex")}`;
			if (slice.length <= 6) {
				pushValue = Number(BigInt(pushBytes));
			}
			pc = end;
		} else {
			pc += 1;
		}

		if (opcode === 0x5b) {
			jumpDests.add(curPc);
		}

		instructions.push({
			pc: curPc,
			opcode,
			mnemonic: meta.mnemonic,
			pushBytes,
			pushValue,
		});
	}

	return { instructions, jumpDests };
}

export function extractSelectors(instructions: EvmInstruction[], jumpDests: Set<number>): EvmSelectorEntry[] {
	const selectors: EvmSelectorEntry[] = [];
	const seen = new Set<string>();

	for (let i = 0; i < instructions.length; i++) {
		const instr = instructions[i];
		// Pattern: PUSH4 <selector> followed by EQ / GT (or DUP2; EQ) and PUSH <dest>; JUMPI
		if (instr.pushBytes && (instr.opcode === 0x63 || (instr.opcode >= 0x60 && instr.opcode <= 0x63))) {
			// Normalise selector to 4 bytes: 0xXXXXXXXX
			let rawHex = instr.pushBytes.slice(2);
			if (rawHex.length < 8) {
				rawHex = rawHex.padStart(8, "0");
			}
			if (rawHex.length === 8) {
				const selectorHex = `0x${rawHex.toLowerCase()}`;

				// Lookahead up to 6 instructions for dispatcher jump
				let targetPc: number | undefined;
				let isDispatcher = false;

				for (let j = i + 1; j < Math.min(instructions.length, i + 6); j++) {
					const next = instructions[j];
					if (next.mnemonic === "EQ" || next.mnemonic === "GT") {
						isDispatcher = true;
					}
					if (isDispatcher && next.pushValue !== undefined) {
						targetPc = next.pushValue;
					}
					if (isDispatcher && next.mnemonic === "JUMPI") {
						break;
					}
				}

				if (isDispatcher && !seen.has(selectorHex)) {
					seen.add(selectorHex);
					const known = KNOWN_SELECTORS[selectorHex];
					const verifiedJumpDest = targetPc !== undefined ? jumpDests.has(targetPc) : false;

					selectors.push({
						selector: selectorHex,
						pc: instr.pc,
						jumpDest: targetPc,
						verifiedJumpDest,
						signature: known?.signature,
						standard: known?.standard,
					});
				}
			}
		}
	}

	return selectors;
}

export function parseCborMetadata(buffer: Buffer): EvmCborMetadata | undefined {
	if (buffer.length < 4) return undefined;
	const len = (buffer[buffer.length - 2] << 8) | buffer[buffer.length - 1];
	if (len <= 0 || len + 2 > buffer.length || len > 512) return undefined;

	const cborSlice = buffer.subarray(buffer.length - 2 - len, buffer.length - 2);
	const rawHex = `0x${cborSlice.toString("hex")}`;

	let compiler: string | undefined;
	let version: string | undefined;
	let ipfs: string | undefined;
	let bzzr: string | undefined;

	// Search for solc marker in CBOR: "solc" (0x64 0x73 0x6f 0x6c 0x63)
	const solcMarker = Buffer.from([0x64, 0x73, 0x6f, 0x6c, 0x63]);
	const solcIdx = cborSlice.indexOf(solcMarker);
	if (solcIdx !== -1) {
		compiler = "solc";
		// Usually followed by 3 bytes version: major, minor, patch (0x43 XX YY ZZ)
		const vOffset = solcIdx + 5;
		if (vOffset + 3 <= cborSlice.length) {
			const b0 = cborSlice[vOffset];
			if (b0 === 0x43 && vOffset + 4 <= cborSlice.length) {
				version = `${cborSlice[vOffset + 1]}.${cborSlice[vOffset + 2]}.${cborSlice[vOffset + 3]}`;
			} else if (vOffset + 3 <= cborSlice.length) {
				version = `${cborSlice[vOffset]}.${cborSlice[vOffset + 1]}.${cborSlice[vOffset + 2]}`;
			}
		}
	}

	// Search for ipfs marker: "ipfs" (0x64 0x69 0x70 0x66 0x73)
	const ipfsMarker = Buffer.from([0x64, 0x69, 0x70, 0x66, 0x73]);
	const ipfsIdx = cborSlice.indexOf(ipfsMarker);
	if (ipfsIdx !== -1) {
		// Followed by byte string (0x58 0x22 or 0x58 0x20)
		const vOffset = ipfsIdx + 5;
		if (vOffset + 2 <= cborSlice.length && cborSlice[vOffset] === 0x58) {
			const hashLen = cborSlice[vOffset + 1];
			const hashData = cborSlice.subarray(vOffset + 2, vOffset + 2 + hashLen);
			ipfs = `0x${hashData.toString("hex")}`;
		}
	}

	// Search for bzzr0 / bzzr1 marker
	const bzzr0Marker = Buffer.from("bzzr0");
	const bzzr1Marker = Buffer.from("bzzr1");
	const bzzrIdx =
		cborSlice.indexOf(bzzr0Marker) !== -1 ? cborSlice.indexOf(bzzr0Marker) : cborSlice.indexOf(bzzr1Marker);
	if (bzzrIdx !== -1) {
		const vOffset = bzzrIdx + 5;
		if (vOffset + 32 <= cborSlice.length) {
			bzzr = `0x${cborSlice.subarray(vOffset, vOffset + 32).toString("hex")}`;
		}
	}

	if (!compiler && !version && !ipfs && !bzzr) {
		return undefined;
	}

	return {
		compiler,
		version,
		ipfs,
		bzzr,
		rawHex,
	};
}

export function detectProxyPatterns(buffer: Buffer): string | undefined {
	const hex = buffer.toString("hex");

	// 1. ERC-1167 Minimal Proxy Clone:
	// 363d3d373d3d3d363d73 <20-byte-address> 5af43d82803e903d91602b57fd5bf3
	const eip1167Regex = /363d3d373d3d3d363d73([0-9a-fA-F]{40})5af43d82803e903d91602b57fd5bf3/i;
	const match1167 = hex.match(eip1167Regex);
	if (match1167) {
		return `ERC-1167 Minimal Proxy (Target implementation: 0x${match1167[1]})`;
	}

	// 2. EIP-1967 Transparent / UUPS Proxy slots
	// Implementation slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
	if (hex.includes("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")) {
		return "EIP-1967 Transparent/UUPS Upgradeable Proxy";
	}

	// Admin slot: 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
	if (hex.includes("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")) {
		return "EIP-1967 Admin Proxy";
	}

	return undefined;
}

// ============================================================================
// Tool Class
// ============================================================================

export class EvmInspectTool implements AgentTool<typeof evmInspectSchema, EvmInspectDetails> {
	readonly name = "evm_inspect";
	readonly approval: ToolTier = "read";
	readonly label = "EVM Bytecode Inspect";
	readonly summary =
		"Native offline read-only EVM bytecode inspection, disassembly, and function selector extraction.";
	readonly description = evmInspectDescription;
	readonly parameters = evmInspectSchema;
	readonly loadMode = "discoverable";
	readonly strict = true;

	constructor(private readonly session: ToolSession) {}

	async execute(
		_toolCallId: string,
		params: EvmInspectParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<EvmInspectDetails>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<EvmInspectDetails> & { details: EvmInspectDetails }> {
		throwIfAborted(signal);

		let buffer: Buffer;
		let source: "code" | "file";
		let sourcePath: string | undefined;

		if (params.code !== undefined && params.code.trim().length > 0) {
			source = "code";
			const cleanHex = params.code
				.trim()
				.replace(/^0x/i, "")
				.replace(/[\s\r\n]+/g, "");
			if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
				throw new ToolError(`Invalid hex string in 'code': contains non-hexadecimal characters.`);
			}
			buffer = Buffer.from(cleanHex, "hex");
		} else if (params.path !== undefined && params.path.trim().length > 0) {
			source = "file";
			sourcePath = resolveReadPath(params.path, this.session.cwd);
			let fileData: Buffer;
			try {
				fileData = await fs.readFile(sourcePath);
			} catch (err) {
				throw new ToolError(`File not found: ${params.path} (${err instanceof Error ? err.message : String(err)})`);
			}

			// Check if file content is ASCII hex representation
			const textContent = fileData.toString("utf8").trim();
			const cleanHex = textContent.replace(/^0x/i, "").replace(/[\s\r\n]+/g, "");
			if (cleanHex.length > 0 && /^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length % 2 === 0) {
				buffer = Buffer.from(cleanHex, "hex");
			} else {
				buffer = fileData;
			}
		} else {
			throw new ToolError("Either 'code' (raw hex string) or 'path' (path to bytecode file) must be provided.");
		}

		throwIfAborted(signal);

		const sha256 = createHash("sha256").update(buffer).digest("hex");
		const { instructions, jumpDests } = disassembleBytecode(buffer);
		const selectors = extractSelectors(instructions, jumpDests);
		const metadata = parseCborMetadata(buffer);
		const proxyPattern = detectProxyPatterns(buffer);

		// Bytecode type heuristic: check for CODECOPY -> RETURN sequence (deployment code)
		let bytecodeType: "runtime" | "deployment" | "empty" = "runtime";
		if (buffer.length === 0) {
			bytecodeType = "empty";
		} else {
			const hasCodecopy = instructions.some(i => i.mnemonic === "CODECOPY");
			const hasReturn = instructions.some(i => i.mnemonic === "RETURN");
			if (
				hasCodecopy &&
				hasReturn &&
				instructions.length > 5 &&
				instructions[instructions.length - 1].mnemonic !== "RETURN"
			) {
				bytecodeType = "deployment";
			}
		}

		// Contract standards detection from selectors
		const standardsSet = new Set<string>();
		for (const sel of selectors) {
			if (sel.standard) standardsSet.add(sel.standard);
		}
		const detectedStandards = Array.from(standardsSet).sort();

		const action = params.action;
		const limit = Math.min(params.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
		const offset = params.offset ?? 0;
		const filter = params.filter?.toLowerCase();

		// ------------------------------------------------------------------------
		// Action: info
		// ------------------------------------------------------------------------
		if (action === "info") {
			const lines = [
				`# EVM Bytecode Inspection: ${source === "file" ? `\`${sourcePath}\`` : "Raw Code Input"}`,
				"",
				`| Property | Value |`,
				`|---|---|`,
				`| **Bytecode Size** | ${formatBytes(buffer.length)} (${buffer.length} bytes) |`,
				`| **SHA-256** | \`${sha256}\` |`,
				`| **Bytecode Classification** | **${bytecodeType.toUpperCase()}** |`,
				`| **Instruction Count** | ${instructions.length} |`,
				`| **JUMPDEST Targets** | ${jumpDests.size} |`,
				`| **Detected Selectors** | ${selectors.length} |`,
				`| **Identified Standards** | ${detectedStandards.length > 0 ? detectedStandards.join(", ") : "none"} |`,
			];

			if (proxyPattern) {
				lines.push(`| **Proxy Architecture** | **${proxyPattern}** |`);
			}

			if (metadata) {
				lines.push(
					"",
					"## Compiler Metadata (CBOR)",
					`| Metadata Key | Decoded Value |`,
					`|---|---|`,
					`| **Compiler** | \`${metadata.compiler ?? "solc"}\` |`,
					`| **Solidity Version** | \`${metadata.version ?? "unknown"}\` |`,
					`| **IPFS Hash** | \`${metadata.ipfs ?? "none"}\` |`,
					`| **Swarm Hash (bzzr)** | \`${metadata.bzzr ?? "none"}\` |`,
				);
			}

			if (selectors.length > 0) {
				lines.push(
					"",
					"## Function Selectors Preview",
					"| Selector | Function Signature | Interface Standard | Jump PC |",
					"|---|---|---|---|",
				);
				for (const sel of selectors.slice(0, 10)) {
					const sig = sel.signature ? `\`${sel.signature}\`` : "*Unknown function*";
					const std = sel.standard ? `**${sel.standard}**` : "-";
					const jmp = sel.jumpDest !== undefined ? `\`0x${sel.jumpDest.toString(16)}\`` : "-";
					lines.push(`| \`${sel.selector}\` | ${sig} | ${std} | ${jmp} |`);
				}
				if (selectors.length > 10) {
					lines.push(`*...and ${selectors.length - 10} more selectors (use \`action: "selectors"\` to view all)*`);
				}
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "info",
					source,
					sourcePath,
					bytecodeSize: buffer.length,
					sha256,
					instructionCount: instructions.length,
					jumpDestCount: jumpDests.size,
					bytecodeType,
					proxyPattern,
					detectedStandards,
					metadata,
					totalInstructions: instructions.length,
					totalSelectors: selectors.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: disasm
		// ------------------------------------------------------------------------
		if (action === "disasm") {
			let filtered = instructions;
			if (filter) {
				filtered = filtered.filter(
					i =>
						i.mnemonic.toLowerCase().includes(filter) ||
						(i.pushBytes && i.pushBytes.toLowerCase().includes(filter)),
				);
			}
			const paged = filtered.slice(offset, offset + limit);

			const lines = [
				`# EVM Disassembly: ${source === "file" ? `\`${sourcePath}\`` : "Raw Code"} (${instructions.length} instructions, showing ${paged.length})`,
				"",
				`| PC | Opcode | Mnemonic | Immediate Push Data | Decimal |`,
				`|---|---|---|---|---|`,
			];

			for (const instr of paged) {
				const pcHex = `0x${instr.pc.toString(16).padStart(4, "0")}`;
				const opHex = `0x${instr.opcode.toString(16).padStart(2, "0")}`;
				const pushStr = instr.pushBytes ? `\`${instr.pushBytes}\`` : "-";
				const valStr = instr.pushValue !== undefined ? String(instr.pushValue) : "-";
				lines.push(`| \`${pcHex}\` | \`${opHex}\` | **${instr.mnemonic}** | ${pushStr} | ${valStr} |`);
			}

			if (filtered.length > offset + limit) {
				lines.push(`*...and ${filtered.length - (offset + limit)} more instructions (use \`offset\` to paginate)*`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "disasm",
					source,
					sourcePath,
					bytecodeSize: buffer.length,
					sha256,
					instructionCount: instructions.length,
					jumpDestCount: jumpDests.size,
					bytecodeType,
					detectedStandards,
					instructions: paged,
					totalInstructions: instructions.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: selectors
		// ------------------------------------------------------------------------
		if (action === "selectors") {
			let filtered = selectors;
			if (filter) {
				filtered = filtered.filter(
					s =>
						s.selector.toLowerCase().includes(filter) ||
						(s.signature && s.signature.toLowerCase().includes(filter)) ||
						(s.standard && s.standard.toLowerCase().includes(filter)),
				);
			}
			const paged = filtered.slice(offset, offset + limit);

			const lines = [
				`# EVM Function Selectors: ${source === "file" ? `\`${sourcePath}\`` : "Raw Code"} (${selectors.length} total, showing ${paged.length})`,
				"",
				`| Selector | Function Signature | Interface Standard | Dispatcher PC | Target Jumpdest |`,
				`|---|---|---|---|---|`,
			];

			for (const sel of paged) {
				const sig = sel.signature ? `\`${sel.signature}\`` : "*Unknown signature*";
				const std = sel.standard ? `**${sel.standard}**` : "-";
				const dispPc = `0x${sel.pc.toString(16)}`;
				const jmp =
					sel.jumpDest !== undefined
						? `0x${sel.jumpDest.toString(16)} ${sel.verifiedJumpDest ? "✅" : "⚠️"}`
						: "-";
				lines.push(`| \`${sel.selector}\` | ${sig} | ${std} | \`${dispPc}\` | \`${jmp}\` |`);
			}

			if (filtered.length > offset + limit) {
				lines.push(`*...and ${filtered.length - (offset + limit)} more selectors (use \`offset\` to paginate)*`);
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "selectors",
					source,
					sourcePath,
					bytecodeSize: buffer.length,
					sha256,
					instructionCount: instructions.length,
					jumpDestCount: jumpDests.size,
					bytecodeType,
					detectedStandards,
					selectors: paged,
					totalSelectors: selectors.length,
				},
			};
		}

		// ------------------------------------------------------------------------
		// Action: metadata
		// ------------------------------------------------------------------------
		if (action === "metadata") {
			const lines = [`# EVM Compiler CBOR Metadata: ${source === "file" ? `\`${sourcePath}\`` : "Raw Code"}`, ""];

			if (metadata) {
				lines.push(
					`| Property | Value |`,
					`|---|---|`,
					`| **Compiler** | \`${metadata.compiler ?? "solc"}\` |`,
					`| **Compiler Version** | \`${metadata.version ?? "unknown"}\` |`,
					`| **IPFS Multihash** | \`${metadata.ipfs ?? "none"}\` |`,
					`| **Swarm bzzr Hash** | \`${metadata.bzzr ?? "none"}\` |`,
					`| **Raw CBOR Hex** | \`${metadata.rawHex}\` |`,
				);
			} else {
				lines.push("> **No compiler CBOR metadata found** in bytecode trailer.");
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "metadata",
					source,
					sourcePath,
					bytecodeSize: buffer.length,
					sha256,
					instructionCount: instructions.length,
					jumpDestCount: jumpDests.size,
					bytecodeType,
					detectedStandards,
					metadata,
				},
			};
		}

		throw new ToolError(`Unsupported action: ${String(action)}`);
	}
}
