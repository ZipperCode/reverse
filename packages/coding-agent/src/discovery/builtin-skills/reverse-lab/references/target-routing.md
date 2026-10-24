# Target-First Routing & Classification Guide

This reference guides the rapid classification and triage of reverse engineering targets. Always identify the format, architecture, and packaging before launching resource-heavy disassemblers.

---

## 1. Five-Gate Decision Tree (G0 – G4)

Follow the decision gates sequentially:

```
[Target Artifact]
       │
       ▼
[Gate G0: Format & Magic Detection] ──> Identify Container / Executable format
       │
       ▼
[Gate G1: Architecture & Packer Audit] ──> Detect Architecture, Entropy & Protections
       │
       ▼
[Gate G2: Domain Route Selection] ──> Route to Android, Windows, Web, or Protocol
       │
       ▼
[Gate G3: Tool Availability & Fallback] ──> Select optimal available toolchain
       │
       ▼
[Gate G4: Execution Boundary & Strategy] ──> Formulate Static/Dynamic Closed Loop
```

### Gate G0: Format & Magic Bytes Detection
Inspect file headers and magic bytes to confirm the true binary container independently of the file extension:
| Format / Subsystem | Magic Bytes / Header Signature | Typical Extensions |
| :--- | :--- | :--- |
| **ZIP / JAR / APK** | `50 4B 03 04` (`PK..`) | `.apk`, `.aab`, `.zip`, `.jar` |
| **DEX (Dalvik Exec)** | `64 65 78 0A 30 33 35 00` (`dex\n035\0`) | `.dex` |
| **ELF (Linux / BSD / Embedded Native)** | `7F 45 4C 46` (`\x7FELF`) | `.so`, `.bin`, `.o`, ELF executables |
| **Mach-O Thin (macOS / iOS)** | `CF FA ED FE` (64-bit LE) / `CE FA ED FE` (32-bit LE) | Mach-O binaries, `.dylib`, `.o` |
| **Mach-O Universal / Fat Binary** | `CA FE BA BE` (Fat BE) / `BE BA FE CA` (Fat LE) / `CA FE BA BF` (Fat 64) | Multi-arch Universal binaries |
| **Windows PE (Portable Executable)** | `4D 5A` (`MZ`), followed by `50 45 00 00` at PE offset | `.exe`, `.dll`, `.sys`, `.node`, `.ocx` |
| **WebAssembly** | `00 61 73 6D` (`\0asm`) | `.wasm` |
| **Java Class** | `CA FE BA BE` (verify class version bytes vs Mach-O fat count) | `.class` |
| **Hermes Bytecode (RN)** | `C6 1F BC 03` | `.hbc`, `index.android.bundle` |
| **uImage (U-Boot Header)** | `27 05 19 56` | `.uImage`, `.bin`, `.img` |
| **SquashFS Filesystem** | `73 71 73 68` (`sqsh`) / `68 73 71 73` (`hsqs`) | `.squashfs`, `.sqsh`, firmware blobs |
| **CPIO Archive** | `30 37 30 37 30 31` (`070701`) / `070702` | `.cpio`, initramfs, initrd |
| **FIT / Device Tree Blob** | `D0 0D FE ED` | `.dtb`, `.fit` |
| **Linux ELF Core Dump** | `7F 45 4C 46` with `e_type = 4` (`ET_CORE`) | `core`, `core.*`, `.dump` |
| **Microsoft Minidump** | `4D 44 4D 50` (`MDMP`) | `.dmp`, `.mdmp` |
| **Raw / Firmware / Memory Dump** | No container magic; inspect Shannon entropy and byte signatures | `.bin`, `.rom`, `.raw`, firmware blobs |
Quick triage command:
```bash
file <target-path>
# Or read first 16 bytes in hex
head -c 16 <target-path> | xxd -p
```

---

## 2. Gate G1: Architecture, Packing & Container Audit

Check for binary protection, obfuscation, and runtime layers:

1. **Packers & Envelopes**:
   - **UPX**: Look for `UPX0`, `UPX1`, `UPX!` section names in PE/ELF. Unpack with `upx -d <file>`.
   - **Commercial Protectors (Themida, VMProtect, VMP)**: High entropy sections (> 7.2 bits/byte), non-standard section names (`.vmp0`, `.themida`), mutated entrypoint code. Route to **Route V (`vmp-reverse`)**.
   - **Android Reinforcement / Hardening**: Look for known packer stubs in APK `lib/` (e.g. `libjiagu.so` [Qihoo 360], `libsecmain.so` [Bangcle], `libtup.so` [Tencent Legu]).
2. **Hybrid & Multi-Runtime Containers**:
   - **Electron**: Contains `resources/app.asar`. Inspect directly with native `javascript_application(path: "app.asar" | "resources/app")` for package metadata, entrypoints, IPC channels, roles, and native addons without extraction. Extract with `npx @electron/asar extract app.asar ./unpacked` only if manual modification or patching is required.
   - **React Native**: Contains `assets/index.android.bundle`. Check magic: text JS bundle vs binary Hermes bytecode (`.hbc`). Hermes analysis requires `hermes-dec` or `hbctool`.
   - **Flutter**: Contains `libapp.so` and `libflutter.so`. Native Dart snapshot (AOT compiled). Route to native ELF triage.
   - **Unity**: Contains `libil2cpp.so` and `assets/bin/Data/Managed/Metadata/global-metadata.dat`. Requires Il2CppDumper before decompilation.

---

## 3. Gate G2: Domain Route Selection

Once the format and packing status are determined, dispatch to the corresponding reference:

### Route N: Native Binaries (Linux ELF, Apple Mach-O & Universal, Firmware)
- **Artifacts**: Linux/POSIX ELF (`.so`, executables, `.o`), Apple Mach-O (`.dylib`, executables, Universal Fat binaries), cross-compiled embedded binaries, raw firmware/memory blobs.
- **Core Strategy**: Start with zero-dependency built-in `triage` to profile format, architecture, bitness, endianness, section table, stripped status, and Fat slices. Proceed to `read-binary` (IDA Pro) or `r2_inspect` / `radare2` for deep symbol, section, relocation, and decompilation analysis. Use `frida` (one-shot hooks/traces) or `frida_session` (persistent multi-turn analysis sessions) or LLDB/GDB for dynamic verification.
- **Reference**: `skill://native-binary-reverse`.

### Route A: Android Applications & JNI Libraries
- **Artifacts**: Android application packages (`.apk`, `.aab`), Dalvik bytecode (`.dex`), and JNI native libraries embedded inside or coupled to an Android app (`lib/<abi>/*.so`).
- **Routing Guard**: Standalone Linux/POSIX ELF binaries or general shared libraries MUST route to **Route N (`native-binary-reverse`)**, NOT Android. Only route to Route A when analyzing an Android package, Dalvik bytecode, or JNI bindings (`Java_*`, `JNI_OnLoad`). Prioritize zero-prep on-demand queries with `droidasc`. Fall back to targeted `jadx` or `apktool`. For dynamic confirmation, use `frida` for one-shot tests and `frida_session` for stateful multi-step hooking against running or spawned apps.
- **Reference**: `skill://reverse-lab/references/android.md`.

### Route B: Windows Native Executables & Libraries
- **Artifacts**: PE32 / PE32+ `.exe`, `.dll`, `.sys`, `.node` addons.
- **Core Strategy**: For foundational format and section triage, `triage` or `native-binary-reverse` provides baseline inspection. When Windows subsystem specifics, Win32 IAT auditing, ETW/API Monitor traces (`windows_observe`), or Windows anti-debug techniques are required, dispatch to `windows-reverse`.
- **Reference**: `skill://reverse-lab/references/windows.md`.

### Route V: VMProtect & Virtualized Native Code
- **Artifacts**: PE binaries protected with VMProtect (VMP 2.x, 3.x) or custom virtual machines, unpacked process memory dumps, offline instruction execution traces.
- **Core Strategy**: Triage VM entry dispatcher stubs with `triage` and `r2_inspect`. Reconstruct process memory and IAT past OEP using `vmp_dump`. Lift individual x64 PE functions to LLVM IR with `native_devirtualize(backend: "mergen")` or legacy VMP 3.0–3.5 routines to VTIL with `native_devirtualize(backend: "novmp")`. Simplify MBA expressions and branch predicates from traces using `triton_analyze`. Enforce dual-execution differential verification before accepting deobfuscated models.
- **Reference**: `skill://vmp-reverse`.

### Route C: Web Frontends & Protocol Payloads
- **Artifacts**: Bundled JavaScript (`.js`, `.mjs`), WebAssembly (`.wasm`), network HTTP/WebSocket traffic (HAR, JSON).
- **Core Strategy**: Apply search-first token discipline. Extract endpoints, auth headers, and crypto primitives using native `ast_grep` or `grep` before reading full files. Reconstruct original source via SourceMaps when available.
- **Reference**: `skill://reverse-lab/references/web-protocol.md`.

### Route F: Firmware Images, Flash ROMs & Embedded Filesystems
- **Artifacts**: Multi-partition firmware blobs (`.bin`, `.rom`, `.img`), U-Boot uImages, SquashFS root filesystems, CPIO initramfs, Device Tree blobs (DTB/FIT).
- **Core Strategy**: Use native `firmware_inspect(action: "info")` to discover container boundaries, architecture, cryptographic hashes, and Shannon entropy. Use `action: "regions"` to map partition layouts and compressed stages without unpacking. Use `action: "entries"` to search filesystems for configuration files (`/etc/shadow`, `passwd`), credentials, or shell scripts. Use `action: "entropy"` to isolate encrypted vs. compressed vs. executable regions.
- **Fallback**: Fall back to `binwalk -B` or `unsquashfs` / `7z` when physical carve extraction is authorized.

### Route D: Crash Dumps & Post-Mortem Diagnostics
- **Artifacts**: Linux ELF Core dumps (`ET_CORE`), Windows Minidumps (`.dmp`), Apple Mach-O Core dumps (`MH_CORE`).
- **Core Strategy**: Use native `crashdump_inspect(action: "info")` to obtain crash diagnostics: architecture, termination signal (SIGSEGV, SIGABRT) or Windows exception code (`0xC0000005 STATUS_ACCESS_VIOLATION`), faulting thread ID, and instruction pointer. Use `action: "threads"` and `action: "registers"` to inspect crashed state, and `action: "mappings"` to identify loaded libraries and memory segment boundaries without launching GDB/LLDB.
- **Fallback**: Fall back to `gdb --core <dump>`, `lldb -c <dump>`, or `readelf -n <core>`.

### Route G: Go & Rust Compiled Binaries
- **Artifacts**: Go executables (`\xff Go buildinf:`, `.gopclntab`, runtime symbols), Rust executables (`.dep-v0`, `rustc` paths, cargo auditable metadata).
- **Core Strategy**: Use native `binary_metadata_inspect(action: "info")` to detect compiler family, Go runtime version, main module path, and Rust cargo-auditable status. Use `action: "go"` to inspect compiled Go dependencies (`dep`), module paths, and build settings (`CGO_ENABLED`, `vcs.revision`). Use `action: "rust"` to decode the full cargo dependency tree from `.dep-v0`, rustc commit hash, and allocator/panic runtime flags without decompilation.
- **Fallback**: Fall back to `go version -m <bin>`, `cargo auditable`, or `readelf -p .dep-v0`.

### Route H: EVM Bytecode & Smart Contracts
- **Artifacts**: Raw EVM bytecode (`0x...` hex strings, `.bin`, `.hex`), Solidity/Vyper deployment code, runtime code, proxy clones.
- **Core Strategy**: Use native `evm_inspect(action: "info")` to categorize bytecode (runtime vs deployment), detect proxy patterns (ERC-1167 Minimal Proxy, EIP-1967 Transparent/UUPS implementation and admin slots), and decode compiler CBOR metadata (solc version, IPFS/bzzr hash). Use `action: "selectors"` to extract Solidity function selector dispatchers and identify supported interfaces (ERC-20, ERC-721, ERC-1155, Ownable). Use `action: "disasm"` for bounded opcode disassembly with decoded push values.
- **Fallback**: Fall back to Foundry `cast disasm`, `hevm`, or offline Python disassemblers.

### Route I: Binary Diffing & Variant Comparison
- **Artifacts**: Two versions of a binary, patch revisions, firmware updates, compiler optimization variations.
- **Core Strategy**: Use native `binary_diff(path_a: "...", path_b: "...")` for deterministic SHA-256/MD5 hashing, byte size delta, similarity percentage, and total differing bytes. Use `action: "blocks"` to isolate changed chunks with block-level hashes. Use `action: "bytes"` for exact hex/ASCII diff offsets, and `action: "headers"` to compare executable headers side-by-side without patching.
- **Fallback**: Fall back to `vbindiff`, `radiff2`, or `cmp -l`.

### Route W: Reverse Engineering Workflow Orchestration
- **Artifacts**: Multi-step reverse engineering investigations across PE, ELF, Mach-O, APK, JS, WASM, PCAP, or SQLite targets.
- **Core Strategy**: Use native `reverse_workflow(action: "create", target: "...")` to generate deterministic, gate-aligned (G0 -> G4) execution plans using native tools. Use `action: "record"` to track step progress, outputs, and verified evidence ledger IDs (`ev_fact_...`). Use `action: "retry"` to safely recover failed steps with bounded attempt caps and caller diagnostic parameters without running arbitrary shell commands. Use `action: "export"` to produce bounded Markdown/JSON reports.
- **Fallback**: Manual multi-tool invocation with direct `evidence` ledger tracking.
---

## 4. Gate G3: Capability Discovery, Tool Availability & Dispatch Selection

Before executing resource-heavy tools or disassemblers, evaluate required capabilities and tool readiness through the concrete `reverse_capability` protocol:

1. **Map to Canonical Capability**:
   Identify the underlying analytical requirement:
   - Android JNI emulation ➔ `android_native_emulation`
   - Android package decompilation & Dalvik analysis ➔ `apk_unpacking`
   - Android DEX bytecode inspection & semantic patching ➔ `dex_patching`
   - Android APK container repacking, alignment & signing ➔ `apk_artifact_generation`
   - Dynamic Web & DOM inspection ➔ `browser_debugger`
   - Native binary disassembly & dynamic stepping ➔ `native_debugger`
   - WebSocket real-time frame inspection ➔ `websocket_capture`
   - JavaScript AST deobfuscation ➔ `js_deobfuscation`
   - Network traffic & HTTPS interception ➔ `traffic_interception`
   - Windows VMProtect process memory dump & IAT repair ➔ `vmp_dump_repair`
   - Native x64 PE function lifting to LLVM IR ➔ `native_function_lifting`
   - Legacy VMProtect 3.0–3.5 VTIL devirtualization ➔ `vmp_legacy_devirtualization`
   - Symbolic trace execution & MBA simplification ➔ `symbolic_trace_analysis`

2. **Query Capability Readiness via `reverse_capability`**:
   Always check readiness through the capability resolver before tool invocation:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>" })
   ```

3. **Native Tool Baseline First**:
   Inspect `recommendedNativeTool` and `status`. When a zero-dependency built-in tool fulfills the analytical question (e.g. `android_package_inspect` for APK/DEX/manifest, `triage` for binary headers, `browser_reverse_session` for CDP eval, `pcap_inspect` for packet flows, `sourcemap_inspect` for JS maps), dispatch the native tool first without unnecessary installation pauses.

4. **Structured Notice & Operator Setup Approval**:
   If deeper external analysis is required or the primary tool is absent from PATH:
   - Present the structured notice with technical rationale (`why`), required host runtimes (`prerequisites`), client-vetted setup command (`reverse setup reverse <tool-id>`), and post-install invocation syntax (`postInstallInvocation`).
   - Request explicit operator approval before executing any setup command.

5. **Setup Execution & Post-Install Re-Resolution**:
   - Upon operator approval, the operator executes `reverse setup reverse <tool-id>`.
   - Immediately re-resolve capability status with refresh enabled:
     ```json
     reverse_capability({ action: "resolve", capability: "<capability_id>", refresh: true })
     ```
   - Confirm `status` is `"ready"` and dispatch the tool using its canonical `postInstallInvocation` syntax or native CLI wrapper.

6. **Workflow Audit & Degradation Recording**:
   - On successful dispatch: record tool results and link evidence via `reverse_workflow({ action: "record", status: "completed", evidence_ids: [...] })`.
   - On refusal or missing prerequisite: immediately engage the active fallback from the degradation ladder (`skill://reverse-lab/references/tool-fallback.md`) and audit the refusal and fallback engagement via `reverse_workflow({ action: "record", fallback_tool: "...", outputs: "..." })` or `reverse_workflow({ action: "recover", ... })` to maintain uninterrupted analytical progress.
## 5. Gate G4: Static vs. Dynamic Closed Loop

Determine the verification strategy based on available execution boundaries:

```
           [Static Analysis]
         (Locate check / offset)
                 │
                 ▼
         [Form Hypothesis]
  ("At offset 0x1400: rax != 0 -> pass")
                 │
                 ▼
     [Select Verification Path]
       ┌─────────┴─────────┐
       ▼                   ▼
[Dynamic Observation]  [Static Binary Patch]
 (Frida / Debugger /   (Flip branch opcode /
   Network capture)     mock return value)
       │                   │
       └─────────┬─────────┘
                 ▼
       [Empirical Proof]
 (Observed runtime confirmation)
```

1. **Static Analysis**: Identifies logic boundaries, function signatures, encryption constants, and validation routines.
2. **Dynamic Observation**: Verifies assumptions in real time without executing fragile manual emulation.
3. **Static Binary Patch / Mock**: Proves hypothesis when dynamic runtime is unavailable by modifying single bytes (e.g., `JZ` to `JNZ`, smali `if-eqz` to `if-nez`) and verifying altered execution behavior.
