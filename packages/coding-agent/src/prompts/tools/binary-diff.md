Native offline read-only binary diffing between two local files with deterministic hashes, sizes, similarity calculation, block-level changes, and byte-level differences.

Capabilities:
- **Comparison Summary & Hashes (`summary`)**:
  - Validates that `path_a` and `path_b` point to distinct files.
  - Computes deterministic SHA-256 and MD5 hashes for both files.
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

Inputs:
- `path_a`: Path to first file (or alias `path1`).
- `path_b`: Path to second file (or alias `path2`).
- `action`: `"summary"`, `"blocks"`, `"bytes"`, or `"headers"` (default `"summary"`).
- `block_size`: Block chunk size in bytes for block comparison (default 4096, min 64, max 65536).
- `limit`: Maximum blocks, byte ranges, or entries to return (default 50, max 200).
- `offset`: Pagination offset (default 0).
- `max_bytes`: Maximum file bytes to read for diffing (default 64MB, max 256MB).

<examples>
```
binary_diff(path_a: "v1/app", path_b: "v2/app")
binary_diff(path_a: "original.bin", path_b: "patched.bin", action: "blocks", block_size: 1024)
binary_diff(path_a: "firmware_a.rom", path_b: "firmware_b.rom", action: "bytes", limit: 20)
binary_diff(path_a: "target.exe", path_b: "target_mod.exe", action: "headers")
```
</examples>
