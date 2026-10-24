Native VMProtect devirtualization, symbolic bytecode lifting, and deobfuscation tool for 64-bit Windows PE binaries.

Backends:
- **`mergen` (NaC-L/Mergen)**:
  - Function-level x64 PE to LLVM Intermediate Representation (IR) symbolic lifter.
  - Tested against VMProtect 3.4–3.6 and 3.8.1 routines.
  - Requires function starting Virtual Address (`start_address`, VA >= ImageBase).
  - Emits `output.ll` (optimized LLVM IR), `output_no_opts.ll` (unoptimized LLVM IR), and `output_diagnostics.json`.
  - Supports `--outline` for function addresses that should be outlined rather than inlined.
- **`novmp` (can1357/NoVmp)**:
  - VMProtect 3.X x64 routine lifter to Virtual Tool Intermediate Language (VTIL).
  - Performs constant deobfuscation and VTIL-level profile optimizations.
  - Requires entry Relative Virtual Addresses (`vms`, RVA < SizeOfImage).
  - Produces `.premature.vtil` and `.optimized.vtil` artifacts.
  - Supports optional `-experimental:recompile` generating a `.devirt.<ext>` PE section patch.

Safety and Isolation Invariants:
- **Isolated Staging**: Input PE files are copied into a unique, temporary per-run staging directory. Original binaries are never modified in-place.
- **Strict Format Validation**: Only genuine x64 PE binaries (AMD64 machine `0x8664`, PE32+ optional header `0x20b`) are accepted. 32-bit x86, ARM, and non-PE files are rejected with exact diagnostics.
- **Coordinate Precision**: VA and RVA parameters are validated against PE header boundaries (`imageBase`, `sizeOfImage`) using BigInt precision. Mergen strictly requires VA; NoVmp strictly requires RVA.
- **Execution Sandboxing**: Subprocesses are spawned directly without shell interpolation, stream-budgeted, and monitored with process-tree cancellation.
- **Scope Limitations**: Labeled as function-level or VM-routine symbolic lifters. Devirtualization does NOT claim whole-function equivalence or complete binary deprotection. Self-modifying code, unrolled loops, and indirect jumps with more than two dynamic targets remain known theoretical limits.
- **Plan Mode Guard**: The `lift` action modifies files and is blocked while plan mode is active.

Parameters:
- `action`: `"status"` or `"lift"` (required).
- `backend`: `"mergen"` or `"novmp"`. Required for `lift`; optional for `status`.
- `path`: Path to target x64 PE binary on disk. Required for `lift`.
- `start_address`: (Mergen only) Function entry Virtual Address in hex or decimal (e.g. `"0x140001000"`). Must be `>= ImageBase`. Required for Mergen `lift`.
- `outline_addresses`: (Mergen only) Array of function VAs that should be outlined (treated as external call targets) rather than inlined.
- `enable_debug`: (Mergen only) Enable verbose lifter debug logging (`--enable-debug`).
- `vms`: (NoVmp only) Array of VM entry Relative Virtual Addresses in hex (e.g. `["0x1000", "0x2500"]`). Must be RVAs.
- `sections`: (NoVmp only) Array of section name prefixes to scan for VM entry stubs (e.g. `[".vmp0", ".vmp1"]`).
- `image_base`: (NoVmp only) Optional ImageBase override in hex passed to `-base`.
- `no_opt`: (NoVmp only) Disable VTIL optimization passes (`-noopt`).
- `strip_constant_obfuscation`: (NoVmp only) Enable constant obfuscation stripping (`-opt:constant`).
- `experimental_recompile`: (NoVmp only) Attempt experimental recompilation of lifted VTIL routines back into a `.devirt.<ext>` PE binary.
- `output_dir`: Optional directory path to copy generated artifacts (`.ll`, `.vtil`, `.json`, `.devirt.exe`).
- `timeout`: Execution timeout in seconds (default `120`, max `600`).

<examples>
```
// Check availability and platform support for both backends
native_devirtualize(action: "status")

// Lift a protected function to LLVM IR using Mergen
native_devirtualize(
  action: "lift",
  backend: "mergen",
  path: "sample.exe",
  start_address: "0x140001000",
  outline_addresses: ["0x140002500", "0x140003100"],
  output_dir: "analysis/devirt_ir"
)

// Devirtualize VMProtect routines into VTIL using NoVmp
native_devirtualize(
  action: "lift",
  backend: "novmp",
  path: "unpacked_dump.exe",
  vms: ["0x15a0", "0x22c0"],
  strip_constant_obfuscation: true,
  output_dir: "analysis/vtil_routines"
)
```
</examples>
