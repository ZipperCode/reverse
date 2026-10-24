Windows x64 dynamic VMProtect 3.X process memory dumper and Import Address Table (IAT) reconstruction tool (powered by upstream VMPDump / VTIL).

Capabilities:
- **Environment Status Inspection (`status`)**:
  - Probes host platform compatibility (Windows x64 / Win32 debugging APIs).
  - Verifies presence and executable status of the `vmpdump` binary.
  - Returns setup guidance and dependency resolution without requiring target parameters.
  - Safe for read-only triage and plan mode inspection.
- **Process Memory Dump and Import Reconstruction (`dump`)**:
  - Attaches to target process by Process ID (`pid`).
  - Scans executable sections for VMProtect import dispatch stubs.
  - Lifts stubs to VTIL intermediate representation via VTIL x64 lifter to decode obfuscated call targets.
  - Reconstructs a clean import table, appends thunks to the IAT, and replaces stub calls with direct thunk calls.
  - Generates a fixed, dump-repaired PE executable: `<module_dir>/<module_name>.VMPDump.<ext>`.
  - Verifies the generated artifact is genuine, non-stale, and structurally valid x64 PE (MZ/PE signatures, AMD64 machine 0x8664, PE32+ optional header 0x20b).
  - Optionally transfers the verified dump to a custom destination (`output_path`).

Safety and Invariant Guards:
- **Observed OEP Evidence Required**: VMProtect unpacking must be complete before running VMPDump. The caller must explicitly provide `observed_oep: true` acknowledging observed execution at or past the Original Entry Point (OEP).
- **No Automatic Process Launch**: Target processes and malware samples are never spawned automatically.
- **Module Path Verification**: Requires `module_path` on disk to verify the target image and locate the generated `<module>.VMPDump.<ext>` file.
- **Stale Output Protection**: Compares pre-existing file mtime and hash to guarantee the returned artifact was newly produced during this run.
- **Plan Mode Guard**: The `dump` action is invasive and blocked while plan mode is active.

Parameters:
- `action`: `"status"` or `"dump"` (required).
- `pid`: Target process ID in decimal or hex (e.g. `1234` or `"0x4d2"`). Required for `dump`.
- `module`: Target module name (e.g. `"sample.exe"`, `"lib.dll"`). Use empty string `""` for main process image module (default `""`).
- `module_path`: Path to target module file on disk. Required for `dump` to verify and locate the produced artifact.
- `entry_point`: Optional Entry Point RVA in hex (e.g. `"0x1000"`). Overwrites the AddressOfEntryPoint in the optional header.
- `disable_reloc`: Optional boolean. Marks relocations stripped in the output PE, forcing it to load at dumped ImageBase.
- `observed_oep`: Required boolean (`true`) for `dump`. Confirms that unpacking has finished and execution reached OEP.
- `output_path`: Optional destination path to copy the verified dumped artifact.
- `timeout`: Execution timeout in seconds (default `60`, max `300`).

<examples>
```
// Check VMPDump availability and host platform readiness
vmp_dump(action: "status")

// Dump main executable of an unpacked process after reaching OEP
vmp_dump(
  action: "dump",
  pid: 4812,
  module_path: "C:\\targets\\sample.exe",
  observed_oep: true
)

// Dump a specific DLL module with custom entry point RVA and relocations disabled
vmp_dump(
  action: "dump",
  pid: "0x12c0",
  module: "core.dll",
  module_path: "C:\\targets\\core.dll",
  entry_point: "0x1540",
  disable_reloc: true,
  observed_oep: true,
  output_path: "C:\\output\\core.fixed.dll"
)
```
</examples>
