# evm_inspect

> Native offline read-only Ethereum Virtual Machine (EVM) bytecode inspection, bounded opcode disassembly, function selector extraction, and compiler metadata analysis.

## Source
- Entry: `packages/coding-agent/src/tools/evm-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/evm-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "disasm" \| "selectors" \| "metadata"` | Yes | `info` catalogs bytecode summary, opcode statistics, and contract/proxy heuristics; `disasm` returns paginated EVM instruction disassembly; `selectors` extracts function selectors and matches standard interfaces; `metadata` decodes compiler CBOR metadata. Default is `"info"`. |
| `code` | `string` | No | Raw hex bytecode string (with or without `0x` prefix). |
| `path` | `string` | No | Path to file containing bytecode hex or raw binary. Either `code` or `path` must be provided. |
| `filter` | `string` | No | Optional case-insensitive substring filter for mnemonics or selector signatures. |
| `limit` | `number >= 1` | No | Maximum instructions or selectors to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |

## Capabilities & Analysis
- **Bytecode Forensics & Classification (`info`)**:
  - Accepts raw hex bytecode strings (`0x...` or un-prefixed) or local file paths (hex text or raw binary).
  - Summarizes bytecode size, SHA-256 hash, total instruction count, and JUMPDEST targets.
  - Distinguishes deployment/creation bytecode (containing constructor codecopy/return sequence) from runtime execution bytecode.
  - Detects standard proxy patterns: ERC-1167 Minimal Proxy (clones) with target implementation address extraction, EIP-1967 Transparent/UUPS implementation and admin storage slots.
  - Detects contract interfaces based on selector analysis (ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-165, Ownable, Pausable).
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

## Security & Operational Boundaries
- **Strictly Offline & Read-Only**: Does not connect to Ethereum nodes, RPC endpoints, or network services.
- **No Transaction Execution**: Does not simulate or execute state-modifying EVM calls.
- **Bounded Output**: Paginates disassembly and selector tables to prevent prompt bloat.

## Registration Details
- `name`: `evm_inspect`
- `approval`: `read`
- `loadMode`: `discoverable`
- `strict`: `true`
