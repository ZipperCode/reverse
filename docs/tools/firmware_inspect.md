# firmware_inspect

> Native offline read-only firmware image, ROM, and embedded filesystem inspection without extraction or execution.

## Source
- Entry: `packages/coding-agent/src/tools/firmware-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/firmware-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "regions" \| "entries" \| "entropy"` | Yes | `info` catalogs format, size, hashes, entropy, and regions summary; `regions` lists detected partitions, filesystem superblocks, and bootloaders with offsets; `entries` inventories files inside embedded archives/filesystems; `entropy` computes block-by-block Shannon entropy. |
| `path` | `string` | Yes | Path to target firmware image, ROM, or container file. |
| `limit` | `number >= 1` | No | Maximum regions, entries, or entropy blocks to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `block_size` | `number >= 512` | No | Block size in bytes for entropy scanning (default 65536, min 512, max 1048576). |
| `path_filter` | `string` | No | Optional substring or filename filter for file entries (used with `entries` action). |
| `max_bytes` | `number >= 1` | No | Maximum image bytes to read and scan (default 100MB, max 500MB). |

## Capabilities & Analysis
- **Firmware Overview & Cryptographic Hashing (`info`)**:
  - Pure TypeScript/JavaScript binary parser requiring no native compilation or external binaries.
  - Automatically identifies container formats and embedded bootloader/filesystem headers (uImage, FIT/DTB, SquashFS, CPIO, TAR, ZIP, CramFS, JFFS2, ARM zImage, ELF).
  - Calculates cryptographic hashes (SHA-256 and MD5) and overall Shannon entropy across the image.
  - Provides concise high-level architecture, OS, compression algorithm, and image timestamp information.
- **Embedded Regions & Partition Detection (`regions`)**:
  - Scans image for embedded headers, bootloader segments, and filesystem superblocks (e.g. uImage kernel, SquashFS rootfs, CPIO initramfs, Device Tree blobs, compressed streams).
  - Reports exact byte offsets (hex and decimal), partition size, compression algorithm, and per-region Shannon entropy.
  - Validates superblock headers to eliminate false positives in random data.
- **Archive & Filesystem Member Inventory (`entries`)**:
  - Safely parses member file listings within embedded archives and containers (CPIO, TAR, ZIP) without extracting files to disk.
  - Displays file paths, sizes, compressed sizes, types (file, dir, symlink), modification timestamps, and permissions.
  - Supports `path_filter` to search for specific scripts, binaries, or config files (e.g. `/etc/shadow`, `init`, `.sh`).
  - Bounded retrieval with `limit` (default 50, max 500) and `offset` pagination to protect context window.
- **Block-by-Block Shannon Entropy Analysis (`entropy`)**:
  - Computes sliding Shannon entropy across consecutive blocks (configurable `block_size`, default 64 KiB).
  - Classifies blocks into sparse/padding, text/config, executable code, or compressed/encrypted partitions.
  - Generates ASCII visual bar indicators for immediate identification of encrypted or compressed stages.

## Security & Operational Boundaries
- **Strictly Read-Only**: Performs memory-bounded buffer reading and stream inspection.
- **No File Extraction**: Never writes extracted files or scripts to the filesystem.
- **No Arbitrary Shell**: Does not execute `binwalk`, `unsquashfs`, `tar`, `cpio`, or shell utilities.
- **Bounded Resource Consumption**: Limits maximum read bytes (up to 500MB) and bounds table rows.

## Registration Details
- `name`: `firmware_inspect`
- `approval`: `read`
- `loadMode`: `discoverable`
- `strict`: `true`
