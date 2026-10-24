Native ELF deep inspection, controlled runtime memory dumping, and SoFixer reconstruction tool.

Capabilities:
- **Environment Status (`status`)**:
  - Probes LIEF Python 3.9+ library and external SoFixer tool availability.
  - Reports detected binary paths, architecture support (32-bit and 64-bit), and setup guidance.
- **Deep ELF Querying (`query`)**:
  - Analyzes local ELF binaries (shared libraries `.so`, executables, core dumps) without modifying them.
  - `info`: ELF header, bitness (32/64), endianness, machine architecture (ARM, AARCH64, x86, x86_64), interpreter, soname, and structure summary.
  - `segments`: Program headers / PT_LOAD segments, memory protections (R/W/X), virtual addresses, offsets, sizes, alignments, and section containment.
  - `dynamic`: Dynamic table entries (`DT_NEEDED`, `DT_SONAME`, `DT_INIT`, `DT_INIT_ARRAY`, `DT_FINI`, `DT_FINI_ARRAY`, `DT_REL`/`DT_RELA`, `DT_FLAGS`).
  - `constructors`: In-depth initialization function inspection (`ctor_functions`, `DT_INIT`, `.init_array` section pointers and resolved symbol names).
  - `relocations`: Dynamic and PLT/GOT relocation tables with type breakdown, target VAs, addends, relative flags, and symbol names (paged and filterable).
  - `sections`: Section headers with type, flags, virtual address, file offset, size, alignment, and entropy.
  - `symbols`: Exported and imported symbol tables with binding, visibility, and addresses.
  - `address_map`: Translates link-time virtual addresses (Link-time VA / RVA) to file offsets and vice versa (subtract runtime base if ASLR is active), reporting enclosing segment and section details.
  - `all`: Comprehensive analysis combining header, constructors, segments, dynamic entries, and relocations.
- **Controlled Runtime Memory Dump (`dump`)**:
  - Attaches to target process via Frida and executes read-only memory extraction.
  - Preserves exact virtual address layout and PT_LOAD alignment: unreadable memory holes/gaps are zero-filled rather than contiguous-read, preventing crashes and preserving relative offsets for reconstructors.
  - Streams chunks up to bounded maximum module size (`max_bytes`, default 64MB).
  - Generates an immutable original dump artifact with companion provenance manifest (`.manifest.json`) recording PID, base address, captured ranges, and SHA-256 hash.
- **SoFixer ELF Reconstruction (`repair`)**:
  - Reconstructs memory-dumped `.so` files using the external SoFixer tool (`SoFixer32` / `SoFixer64`).
  - Strictly limited to Android ARM (armeabi-v7a) and ARM64 (arm64-v8a) little-endian (LSB) shared libraries with lowest PT_LOAD starting at virtual offset 0x0.
  - Retains the original memory dump completely immutable; writes candidate output to an exclusive artifact file.
  - Structurally validates the reconstructed candidate with LIEF:
    - Verifies ELF header, PT_LOAD segments, dynamic table, and relocation tables.
    - Surfaces page-layout risks (e.g. 4KB vs 16KB alignment risks on Android 15 ARM64).
    - Flags any out-of-bounds relocations or corrupted section mappings.
    - Explicitly marks output as an "analyzable candidate", NOT certified runnable.
- **Combined Pipeline (`dump_and_repair`)**:
  - Executes dump followed immediately by SoFixer repair and structural validation (output_path reserved exclusively for repaired candidate).

Inputs:
- `action`: `"status"`, `"query"`, `"dump"`, `"repair"`, or `"dump_and_repair"`.
- `path`: Path to target ELF file (required for `"query"`).
- `query_type`: `"info"`, `"segments"`, `"dynamic"`, `"constructors"`, `"relocations"`, `"sections"`, `"symbols"`, `"address_map"`, or `"all"` (default `"info"`).
- `filter`: Optional case-insensitive substring filter for symbols, sections, or relocations.
- `limit`: Maximum records to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `address`: Virtual address for address-to-file conversion (hex string or number).
- `file_offset`: File offset for file-to-address conversion (hex string or number).
- `pid`: Target process ID for memory dump (required for `"dump"` and `"dump_and_repair"`).
- `module`: Target module name (e.g. `"libnative-lib.so"`, required for `"dump"` and `"dump_and_repair"`).
- `device`: Target Frida device identifier or serial.
- `usb`: Shorthand for USB device / emulator.
- `host`: Target remote Frida server host (e.g. `"192.168.1.5:27042"`).
- `max_bytes`: Maximum memory bytes to dump (default 64MB, max 256MB).
- `chunk_size`: Read chunk size in bytes (default 64KB, max 1MB).
- `dump_path`: Path to dumped memory image (required for `"repair"`).
- `base_address`: Memory base address where module was loaded (hex string or number, required for `"repair"`).
- `arch`: Target architecture (`"arm"`, `"arm64"`, `"32"`, `"64"`).
- `output_path`: Optional destination path for safe exclusive output.

<examples>
```
# Probe tool environment status
elf_inspect(action: "status")

# Query ELF constructors and initialization routines
elf_inspect(action: "query", path: "target.so", query_type: "constructors")

# Query dynamic relocations with filter
elf_inspect(action: "query", path: "libfoo.so", query_type: "relocations", filter: "RELATIVE")

# Translate virtual address to file offset
elf_inspect(action: "query", path: "libfoo.so", query_type: "address_map", address: "0x123450")

# Dump module memory from running process
elf_inspect(action: "dump", pid: 1234, module: "libtarget.so")

# Reconstruct dumped memory using SoFixer and validate with LIEF
elf_inspect(action: "repair", dump_path: "artifacts/dump.so", base_address: "0x7f12000000", arch: "arm64")

# Combined dump and repair pipeline
elf_inspect(action: "dump_and_repair", pid: 1234, module: "libtarget.so", arch: "arm64")
```
</examples>
