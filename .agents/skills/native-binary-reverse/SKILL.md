---
name: native-binary-reverse
description: Universal native binary reverse engineering specialist for ELF, Mach-O, Fat universal binaries, PE foundations, shared libraries, and raw firmware objects. Guides format triage, section and segment analysis, symbol and relocation inspection, PIE/ASLR/stripped mitigation auditing, disassembly, dynamic verification, and structured evidence chains.
metadata:
  requiresOptional: radare2, ida, frida, ghidra
  capabilities: native_debugger
---

# Native Binary Reverse Engineering Specialist

`native-binary-reverse` is the universal domain skill for reverse engineering compiled native executables, shared libraries (`.so`, `.dylib`, `.dll`), relocatable object files (`.o`, `.obj`), Apple Universal / Fat Mach-O binaries, and raw firmware or memory blobs across Linux, POSIX, Apple Darwin, and cross-compiled embedded environments. It handles foundational format inspection, binary structure auditing, and disassembler navigation, coordinating with `windows-reverse` for Windows-specific PE subsystems/APIs and `android-reverse` for Android JNI/APK-packaged libraries.

For overarching multi-platform orchestration and evidence chains, consult `skill://reverse-lab/SKILL.md`.

---

## 1. Operating Contract & Evidence Standards

- **Target Authorization & Environment**: Operators MUST analyze binaries, execute unpacking, and attach debuggers exclusively within explicitly authorized laboratory environments or isolated hypervisor/container sandboxes.
- **Sample Integrity & Artifact Isolation**: Original sample binaries MUST remain strictly read-only. Thin architecture slices, unpacked payloads, patches, disassembly listings, and scripts MUST be saved under dedicated `./artifacts/`.
- **Concrete Evidence Coordinates**: Every recorded fact MUST cite exact coordinates:
  - Architecture and slice identifier (e.g. `arm64` slice in Fat Mach-O, `x86_64` ELF)
  - Section/segment name and file offset / virtual address (e.g. `.text` at file offset `0x1000`, VA `0x401000`)
  - Symbol name or relocation entry (e.g. dynamic symbol `malloc@@GLIBC_2.2.5`, relocation `R_X86_64_JUMP_SLOT`)
  - Verbatim assembly opcode or decompiled snippet
- **Positive Verification**: Hypotheses regarding algorithms, cryptographic keys, or validation logic remain `[HYPOTHESIS]` until confirmed by dynamic breakpoint, Frida trace, or reproducible test harness.

Read `skill://reverse-lab/references/evidence.md` for artifact formats and schema.

---

## 2. Toolchain & Tool Priority Ladder

Follow the positive triage-to-evidence progression:
```
[1. Triage (Built-in)] ──> triage(path: ...) (format, arch, endian, stripped, entropy, sections)
         │
         ▼
[2. Deep Static Analysis] ──> reverse_capability(action: "resolve", capability: "native_debugger")
         │                    ├─ Ready: rea read-binary (IDA) or r2_inspect / radare2 CLI
         │                    └─ Missing: rea setup reverse radare2 ➔ refresh ➔ dispatch
         ▼
[3. Dynamic Verification] ──> frida (memory hook / trace) or native debugger (GDB / LLDB / DAP)
         │
         ▼
[4. Evidence Formulation] ──> evidence(action: "add" | "verify", ...)
```

1. **Lightweight Triage (`triage`)**: Built-in, zero-dependency. Quickly determines magic bytes, architecture, bitness (32/64-bit), endianness, entrypoint, sections/segments, Shannon entropy, stripped status, and Fat Mach-O slices without spawning external processes.
2. **Deep Static Analysis**:
   - **`read-binary` (IDA Pro integration)**: High-performance virtual URLs via `read` (`:overview`, `:imports`, `:exports`, `:functions`, `:strings`, `:xrefs:<sym>`, `:decompile:<func>`, and Mach-O slice selector `:@<arch>`).
   - **`r2_inspect` (Built-in tool)**: Read-only radare2 queries with fixed bounded actions (`info`, `sections`, `imports`, `exports`, `strings`, `functions`, `xrefs`, `disasm`, `decompile`).
   - **`radare2` (`r2` CLI)**: Headless CLI fallback (`r2 -qc "iI; iS; ii; is"`).
   - **POSIX / LLVM Binutils**: `readelf -h -S -s -r`, `objdump -d`, `llvm-objdump`, `nm -D`, `strings -a -n 8`.
3. **Dynamic Verification (`frida`, debuggers)**:
   - Built-in `frida` tool for one-shot process attachment, function tracing, and memory inspection; built-in `frida_session` tool for persistent multi-turn dynamic analysis sessions with active child/target persistence.
   - LLDB / GDB for single-controller stepping and register audits.
4. **Evidence Tracking (`evidence`)**:
   - Record discovered offsets, symbols, and behaviors using `evidence(action: "add", kind: "fact", ...)` and confirm hypotheses with `evidence(action: "verify", ...)`.

### Canonical Capability Mapping

| Canonical Capability ID | Analytical Scenario | Recommended Native Tool | Optional External Tools | Trusted Setup Command | Fallback Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`native_debugger`** | Dynamic runtime debugging, breakpoint inspection, register state analysis, memory mapping, and execution trace of native ELF, PE, and Mach-O binaries | `r2_inspect` / `triage` (built-in) | `radare2`, `ida`, `frida`, `ghidra` | `rea setup reverse radare2` | `binary_metadata_inspect`, `readelf`, `objdump`, `strings`, `file` |

### Capability Resolution Protocol

When disassembling complex functions, decompiling control flow, or attaching debuggers, execute the Discover-Before-Stop / Install-Then-Dispatch lifecycle via `reverse_capability`:

1. **Resolve Capability (`reverse_capability`)**:
   Query capability status before tool invocation or declaring a blocker:
   ```json
   reverse_capability({ action: "resolve", capability: "native_debugger" })
   ```
2. **Evaluate Native Baseline First**:
   Inspect `recommendedNativeTool` (`r2_inspect`) and native built-in `triage`. For initial format detection, architecture, bitness, endianness, entropy, and symbol headers, use `triage` and `r2_inspect` immediately without installation delays.
3. **Present Setup Notice & Request Approval**:
   When deep decompilation or headless CLI disassembly requires `radare2` or `ghidra` and the binary is not present on PATH:
   - Formulate the structured capability notice:
     ```text
     [Capability Notice] Required capability: native_debugger ('Native Binary Debugger & Dynamic Tracing')
       -> Recommended tool: 'radare2' (Status: missing)
       -> Why: Dynamic runtime debugging, breakpoint inspection, register state analysis, memory mapping, and execution trace of native binaries
       -> Prerequisites: none
       -> Trusted setup: rea setup reverse radare2 (Requires operator approval)
       -> Post-install invocation: r2 -d <binary_path> or query via r2_inspect(action: "decompile", symbol: "<func>")
       -> Fallback if declined: 'triage' + 'readelf' / 'objdump -d' / POSIX 'strings'
     ```
   - Request explicit operator approval before executing setup. Do not execute unapproved setup commands.
4. **Re-Resolve Post-Install**:
   After the operator executes `rea setup reverse radare2`, verify readiness:
   ```json
   reverse_capability({ action: "resolve", capability: "native_debugger", refresh: true })
   ```
   Confirm that `status` transitioned to `"ready"` and `radare2` is available on PATH.
5. **Dispatch & Workflow Resumption / Audit**:
   - Dispatch the tool command (e.g. `r2_inspect(action: "decompile", path: "<sample>", symbol: "<func>")` or headless `r2 -qc "..." <sample>`).
   - When recovering or resuming a workflow step following tool setup, record the canonical install-after resume metadata in `reverse_workflow`:
     - `capability_id`: `"native_debugger"`
     - `installed_tool`: Catalog tool installed (e.g. `"radare2"`, `"ghidra"`)
     - `setup_command`: Setup command executed (e.g. `"rea setup reverse radare2"`)
     - `verified`: `true` (readiness confirmed via `refresh: true`)
     - `strategy`: `"resume_original"` or `"install_recovery"`
     - `resumed_at`: ISO 8601 timestamp
6. **Graceful Fallback Degradation**:
   If the operator declines setup or the tool is unavailable, smoothly step down the ladder to native `triage`, `readelf -h -S -s`, `objdump -d`, or POSIX `strings -a -n 8` and record the fallback in `reverse_workflow`.

---

## 3. Recommended Workflow: Triage ➔ Deep Static ➔ Dynamic ➔ Evidence

### Step 1: Rapid Triage & Format Identification (`triage`)
Run the built-in triage tool before opening heavy disassemblers:
```
triage(path: "sample.bin", strings: false)
```
- **ELF**: Determine whether it is an executable (`ET_EXEC`), shared object (`ET_DYN`), or relocatable object (`ET_REL`). Note endianness, architecture (x86_64, aarch64, arm, mips, riscv), and whether symbols are stripped.
- **Mach-O Thin & Universal / Fat**: Check whether the file is a Universal binary containing multiple architecture slices (e.g. `x86_64` + `arm64`). If multi-architecture, note each slice offset and target architecture.
- **PE Foundations**: Detect COFF machine type, subsystem, and section layout. (For deep Windows API/IAT workflows, route to `windows-reverse`).
- **Raw / Firmware / Object Blobs**: Note Shannon entropy (> 7.2 bits/byte indicates compression or encryption), absence of known headers, and look for embedded strings or section signatures.
- **Go / Rust Binaries**: Run `binary_metadata_inspect(action: "info", path: "sample.bin")` to recover embedded Go module dependencies (`dep`), runtime version (`go1.x`), CGO flags, and Rust `cargo-auditable` (`.dep-v0`) package graphs without disassembling stripped code.
- **Binary Comparison / Revisions**: When analyzing patches or variant builds, use `binary_diff(path_a: "v1.bin", path_b: "v2.bin")` to obtain deterministic hashes, similarity score, and block/byte diff regions.

### Step 2: Architecture & Universal Slice Handling
For multi-architecture Apple binaries:
- With `read-binary`: Access specific architecture slices directly via slice suffix:
  `sample.dylib:@arm64:overview`, `sample.dylib:@arm64:exports`, `sample.dylib:@arm64:main`
- With CLI `lipo`: Extract a thin slice to `./artifacts/`:
  `lipo sample.dylib -thin arm64 -output ./artifacts/sample_arm64.dylib`
- Inspect thin slices independently to avoid architecture ambiguity.

### Step 3: Sections, Segments, Symbols & Mitigations
Examine binary structure to pinpoint program logic:
1. **Mitigation Profiling**:
   - **PIE / ASLR**: Position-independent executables require relative offset tracking rather than absolute virtual addresses.
   - **Stack Canaries / NX**: Check for `__stack_chk_fail` in imports and executable stack segments (`GNU_STACK` with `RWE` permissions).
   - **RELRO**: Partial vs Full RELRO (determines if Global Offset Table `.got.plt` is read-only).
2. **Sections & Segments**:
   - Executable code: `.text` (ELF/PE) or `__TEXT,__text` (Mach-O).
   - Read-only data & strings: `.rodata` (ELF), `.rdata` (PE), `__TEXT,__cstring` (Mach-O).
   - Relocations and Import Tables:
     - ELF: `.dynsym`, `.dynstr`, `.rel.*`, `.rela.*`, `.plt`, `.got`.
     - Mach-O: `LC_LOAD_DYLIB`, `__DATA,__la_symbol_ptr`, `__DATA,__got`.
     - PE: `.idata`, Import Directory Table.
3. **Stripped vs. Non-Stripped Binaries**:
   - If non-stripped (`.symtab` present), extract full symbol table (`r2_inspect(action: "functions")` or `nm -a`).
   - If stripped (`.symtab` absent), rely on exported functions (`.dynsym`), library import call sites, string xrefs, or identify entrypoint (`_start`) and reconstruct `main(argc, argv, envp)`.

### Step 4: Disassembly, Cross-References & Decompilation (`native_debugger`)
Focus on high-value logic gates:
1. **Capability Check**: Query `reverse_capability({ action: "resolve", capability: "native_debugger" })`.
   - If `read-binary` (IDA Pro) or `r2_inspect` is ready, proceed immediately.
   - If deep decompilation requires `radare2` or `ghidra` and neither is on PATH, present the setup notice (`rea setup reverse radare2`). Upon operator installation, re-resolve with `refresh: true`, dispatch `r2_inspect(action: "decompile", ...)` or `r2`, and record install-after resume metadata (`capability_id`, `installed_tool`, `setup_command`, `verified`, `strategy`, `resumed_at`) in `reverse_workflow`.
   - If setup is declined, engage the fallback tier (`objdump -d`, `readelf`, `strings`).
2. **String Cross-References**: Locate references to cryptographic markers, URL endpoints, license flags, or diagnostic messages:
   `r2_inspect(action: "xrefs", path: "sample.bin", address: "0x402010")`
   Or with IDA: `read path: "sample.bin:xrefs:aInvalidLicense"`
3. **Targeted Disassembly**: Disassemble specific routines without flooding context:
   `r2_inspect(action: "disasm", path: "sample.bin", symbol: "main", limit: 60)`
   Or with IDA: `read path: "sample.bin:main:asm"`
4. **Decompilation**: Decompile identified candidate functions:
   `r2_inspect(action: "decompile", path: "sample.bin", symbol: "validate_key")`
   Or with IDA: `read path: "sample.bin:validate_key"`

### Step 5: Dynamic Verification & Instrumentation (`native_debugger`)
When static analysis yields a candidate hypothesis:
1. **Capability Check**: Query `reverse_capability({ action: "resolve", capability: "native_debugger" })`.
2. **Frida Dynamic Instrumentation**:
   - Trace function arguments and return values:
     `frida(action: "execute", target: "sample_process", script: "Interceptor.attach(Module.getGlobalExportByName('target_fn'), { onEnter(args) { console.log('arg0:', args[0]); }, onLeave(retval) { console.log('ret:', retval); } });")`
   - Use `frida_session` for persistent multi-turn dynamic analysis sessions with active target persistence.
3. **Debugger Confirmation**:
   - Use LLDB or GDB with a single stateful session controller to set breakpoints on target RVAs, inspect registers, and verify branch conditions.
4. **Patch Verification**:
   - For offline hypothesis testing, generate a patched binary in `./artifacts/` (e.g. flipping a conditional jump opcode or NOPing a check) and compare behavior against original sample.

### Step 6: Evidence & Proof Recording
Record every confirmed finding into the empirical evidence chain:
- File ground truth: `evidence(action: "add", kind: "fact", sourceTool: "r2_inspect", locator: "0x4012A0", content: "Key check compares hash at offset 0x4012A0 with SHA-256 digest")`
- Formulate hypothesis: `evidence(action: "add", kind: "hypothesis", claim: "Setting register rax to 1 bypasses signature check", verificationPlan: "Patch opcode at 0x4012C4 to mov rax, 1; ret or use Frida onLeave hook")`
- Close loop with verified conclusion: `evidence(action: "verify", hypothesisId: "<id>", conclusion: "Bypass confirmed via Frida trace; return value 1 allows full initialization")`

---

## 4. Boundary & Domain Dispatch Rules

To avoid duplication across specialized skills:
- **Standalone Linux / BSD ELF binaries & shared libraries**: Handle entirely within `native-binary-reverse`.
- **macOS / iOS Mach-O & Universal binaries (`.dylib`, thin/fat executables)**: Handle entirely within `native-binary-reverse`.
- **Android JNI `.so` libraries**: If embedded in an APK or interacting with Java JNI (`JNIEnv*`, `Java_*`, `JNI_OnLoad`), route to `android-reverse` for full APK-to-native integration context. If analyzed purely as an isolated ELF shared library, use `native-binary-reverse`.
- **Windows PE `.exe`, `.dll`, `.sys`**: Foundational header/section analysis can use `native-binary-reverse`; deep Windows subsystem, Win32 API auditing, ETW/API Monitor traces, and PE-specific anti-debug MUST route to `windows-reverse`.
- **Raw firmware & micro-controller objects**: Use `native-binary-reverse` for entropy checks, architecture sniffing, and base address location before code disassembly.
