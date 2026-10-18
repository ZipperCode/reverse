Native offline read-only Ethereum Virtual Machine (EVM) bytecode inspection, bounded opcode disassembly, function selector extraction, and compiler metadata analysis.

Capabilities:
- **Bytecode Forensics & Classification (`info`)**:
  - Accepts raw hex bytecode strings (`0x...` or un-prefixed) or local file paths (hex text or raw binary).
  - Summarizes bytecode size, SHA-256 hash, total instruction count, and JUMPDEST targets.
  - Distinguishes deployment/creation bytecode (containing `CODECOPY` -> `RETURN` constructor logic) from runtime execution bytecode.
  - Detects standard proxy patterns: ERC-1167 Minimal Proxy (clones) with target implementation address extraction, EIP-1967 Transparent/UUPS implementation and admin storage slots.
  - Detects token and contract standards based on function selectors (ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-165, Ownable, Pausable).
- **Bounded Opcode Disassembly (`disasm`)**:
  - Full EVM instruction decoding (0x00 to 0xff) including recent opcodes: PUSH0, MCOPY, TLOAD, TSTORE, BLOBHASH, BLOBBASEFEE.
  - Decodes immediate push data for PUSH1 through PUSH32 with both hex and integer values.
  - Paged with `limit` and `offset`, filterable with mnemonic `filter` (e.g. `JUMP`, `SLOAD`, `LOG`).
- **Function Selector & Dispatcher Extraction (`selectors`)**:
  - Identifies Solidity function selector dispatchers (linear comparison loops and binary search trees checking calldata `CALLDATALOAD(0) SHR 0xe0`).
  - Extracts 4-byte function selectors (`0xXXXXXXXX`) and dispatcher jump destinations (`JUMPDEST` PC).
  - Resolves selectors against built-in database of standard interfaces (ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-165, Ownable, AccessControl, Proxy).
- **Solidity / Vyper CBOR Metadata (`metadata`)**:
  - Decodes compiler CBOR auxiliary data appended at the end of bytecode.
  - Extracts compiler family (`solc`, `vyper`), semantic version (e.g. `0.8.24`), IPFS multihash, and Swarm bzzr hash.

Inputs:
- `action`: `"info"`, `"disasm"`, `"selectors"`, or `"metadata"` (default `"info"`).
- `code`: Raw hex bytecode string (optional if `path` is provided).
- `path`: Path to file containing bytecode hex or raw binary (optional if `code` is provided).
- `filter`: Optional case-insensitive filter for mnemonics or selector signatures.
- `limit`: Maximum instructions or selectors to return (default 50, max 500).
- `offset`: Pagination offset (default 0).

<examples>
```
evm_inspect(action: "info", code: "0x608060405234801561001057600080fd5b50...")
evm_inspect(action: "disasm", path: "contract.bin", limit: 30)
evm_inspect(action: "selectors", code: "0x6080604052600436106100225760003560e01c63a9059cbb1461002757...")
evm_inspect(action: "metadata", path: "contract.hex")
```
</examples>
