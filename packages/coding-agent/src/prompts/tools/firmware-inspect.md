Native offline read-only firmware image, ROM, and embedded filesystem inspection without extraction or execution.

Capabilities:
- **Firmware Overview & Hash Forensics (`info`)**:
  - Detects container formats and embedded bootloader/filesystem headers (uImage, FIT/DTB, SquashFS, CPIO, TAR, ZIP, CramFS, JFFS2, ARM zImage, ELF).
  - Calculates cryptographic hashes (SHA-256 and MD5) and overall Shannon entropy.
  - Identifies primary format, embedded partitions/regions summary, and archive entry counts.
- **Embedded Regions & Superblocks (`regions`)**:
  - Scans image for embedded headers, bootloader segments, and filesystem superblocks (e.g. uImage kernel, SquashFS rootfs, CPIO initramfs, Device Tree blobs, compressed streams).
  - Reports exact byte offsets (hex and decimal), partition size, compression algorithm, and per-region Shannon entropy.
- **Archive & Filesystem Inventory (`entries`)**:
  - Safely parses member file listings within embedded archives and containers (CPIO, TAR, ZIP) without writing files to disk.
  - Displays file paths, sizes, compressed sizes, types (file, dir, symlink), modification timestamps, and permissions.
  - Supports `path_filter` to search for specific scripts, binaries, or config files (e.g. `/etc/shadow`, `init`, `.sh`).
- **Block-by-Block Entropy Analysis (`entropy`)**:
  - Computes sliding Shannon entropy across consecutive blocks (configurable `block_size`, default 64 KiB).
  - Classifies blocks into sparse/padding, text/config, executable code, or compressed/encrypted partitions.

Inputs:
- `action`: `"info"`, `"regions"`, `"entries"`, or `"entropy"`.
- `path`: Path to target firmware image, ROM, or container file.
- `limit`: Maximum regions, entries, or entropy blocks to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `block_size`: Block size in bytes for entropy scanning (default 65536, min 512, max 1048576).
- `path_filter`: Optional substring or filename filter for file entries (used with `entries` action).
- `max_bytes`: Maximum file bytes to read and scan (default 100MB, max 500MB).

<examples>
```
firmware_inspect(action: "info", path: "router_firmware.bin")
firmware_inspect(action: "regions", path: "openwrt.img")
firmware_inspect(action: "entries", path: "firmware.bin", path_filter: "etc")
firmware_inspect(action: "entries", path: "initramfs.cpio", limit: 30)
firmware_inspect(action: "entropy", path: "firmware.bin", block_size: 32768)
```
</examples>
