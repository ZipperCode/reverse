# binary_diff

> Native offline read-only binary diffing between two local files with deterministic hashes, sizes, similarity calculation, block-level changes, and byte-level differences.

## Source
- Entry: `packages/coding-agent/src/tools/binary-diff.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/binary-diff.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `path_a` | `string` | Yes | Path to first file (or alias `path1`). |
| `path_b` | `string` | Yes | Path to second file (or alias `path2`). |
| `action` | `"summary" \| "blocks" \| "bytes" \| "headers"` | Yes | `summary` reports overall hashes, sizes, delta, and similarity; `blocks` details changed chunks; `bytes` details contiguous byte diffs; `headers` compares parsed executable headers. Default is `"summary"`. |
| `block_size` | `number >= 64` | No | Block chunk size in bytes for block comparison (default 4096, min 64, max 65536). |
| `limit` | `number >= 1` | No | Maximum blocks, byte ranges, or entries to return (default 50, max 200). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum file bytes to read for diffing (default 64MB, max 256MB). |

## Capabilities & Analysis
- **Comparison Summary & Hashes (`summary`)**:
  - Safely rejects identical paths or files resolving to the exact same canonical realpath.
  - Computes deterministic SHA-256 and MD5 hashes for both artifacts.
  - Reports exact byte sizes, size delta, total differing bytes, and percentage similarity.
  - Summarizes identical, modified, inserted, and deleted blocks.
- **Block-Level Differencing (`blocks`)**:
  - Segments files into configurable chunks (`block_size`, default 4096 bytes).
  - Catalogs modified, identical, inserted, and deleted blocks with offsets and hashes.
  - Paged with `limit` and `offset` for granular difference navigation.
- **Byte-Level Region Diffs (`bytes`)**:
  - Identifies contiguous spans of differing bytes with offset, length, hex dump, and printable ASCII representation.
  - Paged with `limit` and `offset` to manage context windows.
- **Binary Header Comparison (`headers`)**:
  - Sniffs file format (ELF, PE, Mach-O, ZIP, etc.) for both artifacts.
  - Compares headers side-by-side (architecture, bitness, endianness, entry points, section counts).

## Security & Operational Boundaries
- **Strictly Read-Only**: Performs memory-bounded buffer reading and diffing; never modifies or patches files.
- **Path Separation**: Rejects identical paths and self-comparisons to prevent redundant execution.
- **Bounded Resource Consumption**: Limits maximum read bytes (up to 256MB) and paginates lists.

## Registration Details
- `name`: `binary_diff`
- `approval`: `read`
- `loadMode`: `discoverable`
- `strict`: `true`
