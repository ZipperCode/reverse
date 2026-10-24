# Tool Fallback & Graceful Degradation Guide

This reference defines the degradation ladders, tool detection mechanisms, and installation hints for the `reverse-lab` toolchain. When an advanced analysis tool is unavailable, `reverse` degrades smoothly to available alternatives without blocking progress.

---

## 1. Degradation Principles

1. **Zero-Friction When Ready**: If the primary tool is installed, proceed silently without prompting or emitting environment checks.
2. **Discover Before Stop / Install Then Dispatch**: When an investigative step requires specialized capabilities or an external engine is absent from PATH, never halt or abort. Query the capability state via `reverse_capability({ action: "resolve", capability: "<id>" })`. Check the recommended native tool first; if an optional external tool is needed, present the structured notice with technical justification, prerequisites, trusted setup command (`reverse setup reverse <tool>`), and post-install invocation. After the operator runs setup, re-resolve with `refresh: true`, dispatch immediately, and record the outcome or active fallback in `reverse_workflow`.
3. **Setup Integrity & Controlled Execution**: Only execute client-vetted installation recipes via `reverse setup reverse <tool>` after explicit user confirmation. Arbitrary shell commands, uncontrolled package scripts, or untrusted network downloads remain strictly prohibited.
4. **Maintain Continuous Progress**: Basic POSIX utilities (`strings`, `file`, `unzip`, `hexdump`, `grep`, `xxd`) and reverse native built-ins can always extract actionable ground truth from manifests, headers, and code without external dependencies.

## 2. Tool Degradation Matrix

| Capability / Analysis Domain | Tier 1 (Native Baseline) | Tier 2 (Optional Catalog) | Tier 3 (Secondary Fallback) | Tier 4 (POSIX Baseline) |
| :--- | :--- | :--- | :--- | :--- |
| **`apk_unpacking`** (APK/DEX) | native `android_package_inspect` | `jadx` / `apktool` | `droidasc` / `dexdump` | `unzip -p <apk> AndroidManifest.xml` / `strings` |
| **`dex_patching`** (DEX Patching) | native `dex_patch` | `python` (stdlib runner) / `jadx` | `droidasc` / `dexdump` | `apktool d` smali patch |
| **`apk_artifact_generation`** (APK Repack/Sign) | native `apk_artifact` | `zipalign` + `apksigner` | `apktool b` + `zip` | `unzip` / Python zipfile |
| **`android_native_emulation`** | native `android_native_workflow` | `unidbg` (host JNI emulation) | `frida_session` / `frida` on device | Static `ghidra_inspect` / `r2_inspect` / `readelf` |
| **Android Dynamic** | `frida_session` / `frida -U` | `adb_observe` / `adb logcat` | Static smali patch + rebuild | Smali control flow trace |
| **`native_debugger`** (ELF/PE/Mach-O) | native `triage` + `r2_inspect` | `ghidra_inspect` / `radare2` | `objdump -d` / `readelf` | `strings -a -n 8` + `xxd` / `hexdump` |
| **`js_deobfuscation`** (Web JS) | native `ast_grep` + `sourcemap_inspect` | `ast-grep` CLI / `webcoder` | `grep` / ripgrep | Python/JS custom parser / `strings` |
| **`browser_debugger`** (Web Dynamic) | `browser_reverse_session` / `js_hook_preset` | `playwright-mcp` (MCP) | Headless HTTP / curl | Static network HAR trace |
| **`websocket_capture`** (WebSockets) | native `websocket_observe` (offline) | `mitmproxy` / `tshark` | Browser DevTools HAR export | strings / xxd on raw stream |
| **`traffic_interception`** (Network) | native `pcap_inspect` (offline) | `mitmproxy` (`mitmdump`) | `tshark -r` / `tcpdump -r` | `curl -v` / raw scripts |
| **Database & SQLite** | native `sqlite_inspect` (info/schema/rows/wal) | `sqlite3 -readonly <db>` CLI | Python `sqlite3` script | strings / grep on db file |
| **Firmware & ROMs** | native `firmware_inspect` (info/regions/entries/entropy) | `binwalk -B <firmware>` | `7z l` / `unsquashfs -s` | strings / xxd on raw image |
| **Crash & Core Dumps** | native `crashdump_inspect` (info/threads/mappings/registers/notes) | `gdb --core <dump>` / `lldb -c <dump>` | `readelf -n <core>` | strings on dump |
| **Go/Rust Metadata** | native `binary_metadata_inspect` (info/go/rust/sections) | `go version -m` / `cargo auditable` | `readelf -p .dep-v0` / `objdump` | strings / grep on binary |
| **Smart Contracts / EVM** | native `evm_inspect` (info/disasm/selectors/metadata) | `cast disasm` / `hevm` | `pyevmasm` / python disasm | raw hex / manual opcode lookup |
| **Binary Diffing** | native `binary_diff` (summary/blocks/bytes/headers) | `vbindiff <f1> <f2>` / `radiff2` | `cmp -l <f1> <f2>` | `diff` / `xxd` + diff |
| **Workflow Orchestration** | native `reverse_workflow` (create/plan/status/record/retry) | subagent delegation | manual tool chaining | one-off execution |
| **Runtime Session Registry** | native `reverse_runtime_session` (register/list/status/restore) | tool-native session status | process inspection (`ps`) | manual re-connection |
| **Dynamic Evidence & Closure**| native `reverse_dynamic_evidence` (ingest/events/verify/status) | tool-native evidence export | manual `evidence` facts | raw notes |
---

## 3. Platform Tool Catalog & Installation Matrix

When an optional tool is absent, consult this catalog for platform-appropriate package manager commands:

### 1. Android Toolchain
- **`android_package_inspect`** (Built-in tool): Zero-dependency native inspection of Android containers (.apk, .aab, .apks) and bare .dex files. Parses container layout, DEX headers/classes, binary XML manifest, signing schemes v1/v2/v3/v3.1, and resource trees. Always available.
- **`droidasc`** (Lightweight zero-prep on-demand decompiler):
  - All Platforms: `pip install droidasc` (or `pipx install droidasc`)
- **`jadx`** (Dex to Java decompiler, requires `java`):
  - macOS: `brew install jadx`
  - Linux: `apt install jadx` (Debian/Ubuntu) or download GitHub release
  - Windows: `choco install jadx` (or `scoop install jadx`)
- **`apktool`** (Smali & resource decompiler, requires `java`):
  - macOS: `brew install apktool`
  - Linux: `apt install apktool`
  - Windows: `choco install apktool`
- **`adb`** (Android Debug Bridge):
  - macOS: `brew install --cask android-platform-tools`
  - Linux: `apt install android-tools-adb`
  - Windows: `choco install adb`
- **`frida` / `frida_session`** (Dynamic instrumentation toolkit & persistent analysis sessions):
  - macOS / Linux: `pipx install frida-tools`
  - Windows: `py -m pip install --user frida-tools`

- **`unidbg`** (Host JVM ARM32/ARM64 CPU emulation & JNI invoker):
  - Requires `java` (JDK 8 / OpenJDK 8)
  - Install / Setup: `reverse setup reverse unidbg`
  - Invocation: Custom target Java harness (must exist in project; obtain actual invocation from project; no standalone CLI binary exists)
  - Fallback: `android_native_workflow` library inspection + `ghidra_inspect` / `r2_inspect` static analysis.
### 2. Native Binary Toolchain
- **`triage`** (Built-in tool): Zero-dependency format sniffing, header parsing, architecture/bitness, section table, stripped status, Shannon entropy, and Mach-O Universal slices. Always available.
- **`dotnet_inspect`** (Built-in tool): Zero-dependency native inspection of .NET assemblies and CIL bytecode. Parses PE/COFF headers, CLR runtime metadata, streams, types, methods, and CIL instructions directly. Always available.
- **`ghidra_inspect`** (Ghidra headless bridge wrapper): Headless analysis and function decompilation via `analyzeHeadless`. Emits structured catalog hints when Ghidra is missing.
  - macOS: `brew install --cask ghidra`
  - Linux: `apt install ghidra` or download from https://ghidra-sre.org/ and set `GHIDRA_INSTALL_DIR`
  - Windows: `choco install ghidra`
- **`r2_inspect`** (Built-in tool): Bounded read-only radare2 inspection (`info`, `sections`, `imports`, `exports`, `strings`, `functions`, `xrefs`, `disasm`, `decompile`). Automatically emits catalog install hints when radare2 is missing.
- **`radare2`** (`r2` CLI disassembler/analyzer):
  - macOS: `brew install radare2`
  - Linux: `apt install radare2`
  - Windows: `choco install radare2`
- **`ida`** (IDA Pro with `idalib`):
  - Commercial engine; install IDA Pro, then configure `ida.installDir` in settings or set `IDADIR` environment variable.
  - Automatically verified via reverse's native `locateIdaInstall`. When absent, fallback directly to `radare2`.
### 3. Web & WASM Toolchain
- **Native built-ins**: `ast_grep`, `wasm_inspect`, `javascript_application`, `sourcemap_inspect`, and `js_hook_preset` require no installation.
  - Use `sourcemap_inspect` for zero-prep inspection of `.map` files or inline `sourceMappingURL`, VLQ coordinate lookup, and recovering original source trees.
  - Use `js_hook_preset` to generate safe runtime hook templates for fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, or custom targets.
  - Use `javascript_application` for zero-prep analysis of Electron `.asar` files or packaged JS/Node projects (extracts package metadata, process roles, IPC channels, and native addons).
  - Use `wasm_inspect` `info`, `strings`, and `search` before reaching for external WAT tooling.
- **`wabt`** (`wasm2wat`, `wat2wasm`) — optional, only needed for full WAT output:
  - macOS: `brew install wabt`
  - Linux: `apt install wabt`
  - Windows: `scoop install wabt` or `reverse setup reverse wabt`
- **`ast-grep`** (external CLI fallback when native `ast_grep` is unavailable):
  - macOS / Linux: `brew install ast-grep` (or `cargo install ast-grep`)
  - Windows: `cargo install ast-grep`

### 4. Network & Database Toolchain
- **`pcap_inspect`** (Built-in tool): Zero-dependency native offline inspection of PCAP and PCAPNG captures. Parses global/section headers, packet lists, protocol breakdowns (TCP, UDP, TLS, HTTP, DNS, ICMP, ARP), endpoints, conversations, and DNS records. Always available.
- **`sqlite_inspect`** (Built-in tool): Zero-dependency native read-only SQLite database inspection. Safely catalogs schema, tables, columns, indexes, foreign keys, bounded table rows, and WAL metadata without mutation or arbitrary SQL execution. Always available.
- **`tshark`** (CLI packet analyzer for live captures or advanced dissectors):
  - macOS: `brew install wireshark`
  - Linux: `apt install tshark`
  - Windows: `choco install wireshark`
- **`sqlite3`** (SQLite CLI utility):
  - macOS: `brew install sqlite`
  - Linux: `apt install sqlite3`
  - Windows: `winget install SQLite.SQLite`

- **`mitmproxy`** (`mitmdump` / `mitmweb` HTTPS & WebSocket interception proxy):
  - macOS: `brew install mitmproxy` (or `reverse setup reverse mitmproxy`)
  - Linux: `apt install mitmproxy` (or `pipx install mitmproxy`)
  - Windows: `choco install mitmproxy` (or `winget install mitmproxy.mitmproxy`)
  - Invocation: `mitmdump -p 8080 -w ./artifacts/flows.mitm`
  - Fallback: `pcap_inspect` for offline captures, browser DevTools HAR, or `curl -v`.
### 5. Firmware & Post-Mortem Toolchain
- **`firmware_inspect`** (Built-in tool): Zero-dependency native offline firmware inspection. Detects uImage, SquashFS, CPIO, TAR, ZIP, FIT/DTB, CramFS, JFFS2 headers, partition boundaries, Shannon entropy, and archive inventories without file extraction or execution. Always available.
- **`crashdump_inspect`** (Built-in tool): Zero-dependency native offline crash dump analysis. Parses Linux ELF core dumps (`ET_CORE`) and Windows Minidumps (`MDMP`), decoding registers, termination signals, exception codes, faulting thread/IP, loaded modules, and note segments. Always available.
- **`binwalk`** (CLI firmware analysis and extraction carver):
  - macOS: `brew install binwalk`
  - Linux: `apt install binwalk`
  - Windows: `cargo install binwalk`

### 6. Go/Rust Metadata, EVM & Binary Diff Toolchain
- **`binary_metadata_inspect`** (Built-in tool): Zero-dependency native offline Go runtime build info (`\xff Go buildinf:`, module dependencies, flags) and Rust `cargo-auditable` (`.dep-v0`, rustc commit/version, panic strategy, allocator) inspection. Always available.
- **`evm_inspect`** (Built-in tool): Zero-dependency native offline Ethereum Virtual Machine bytecode disassembler, function selector dispatcher extractor, proxy pattern detector, and CBOR compiler metadata parser. Always available.
- **`binary_diff`** (Built-in tool): Zero-dependency native offline deterministic binary diffing tool with SHA-256/MD5 hashing, block-level delta, similarity scoring, and byte-level diff regions. Always available.
- **`vbindiff`** (Visual binary diff):
  - macOS: `brew install vbindiff`
  - Linux: `apt install vbindiff`
  - Windows: `reverse setup reverse vbindiff`
- **`cast`** (Foundry EVM CLI):
  - All Platforms: `curl -L https://foundry.paradigm.xyz | bash && foundryup`

### 7. Workflow Orchestration Toolchain
- **`reverse_workflow`** (Built-in tool): Zero-dependency native offline workflow orchestrator with target-first routing (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite), state store persistence, verified cross-tool evidence association, deterministic failure attribution, and bounded fallback recovery without arbitrary command execution. Always available.

### 8. Runtime Session Registry
- **`reverse_runtime_session`** (Built-in tool): Zero-dependency native unified reverse runtime session registry across Frida, browser, IDA, and Ghidra. Manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans without unsafe arbitrary process control. Always available.

### 9. Dynamic Evidence & Closure Toolchain
- **`reverse_dynamic_evidence`** (Built-in tool): Zero-dependency native normalizer and closure engine for dynamic reverse events across Frida, browser CDP, DAP, and Unidbg. Transforms telemetry into Evidence ledger facts with deterministic session locators (`session:<id>:seq:<seq>`), verifies hypotheses, promotes verified outcomes into `reverse_knowledge`, and updates workflow progression gates. Always available.
---

## 4. Capability Discovery, Setup & Immediate Dispatch Protocol

When an analytical step requires tools that may not be installed or configured, execute this machine-actionable protocol:

```
[Step Needs Tool] ──> [1. reverse_capability resolve]
                               │
         ┌─────────────────────┴─────────────────────┐
         ▼ (Native Baseline Ready)                    ▼ (Missing / External Needed)
[2. Dispatch Native Tool First]              [3. Show Structured Notice & Ask Approval]
  (Zero-prep built-in tool)                    (why, prereqs, setupCommand, postInstall)
                                                     │
                      ┌──────────────────────────────┴──────────────────────────────┐
                      ▼ (Operator Approves)                                         ▼ (Operator Declines / Prereq Missing)
[4. User Executes Setup]                                                    [7. Engage Active Fallback Tool]
  (`reverse setup reverse <id>`)                                                   (Run next ladder tier)
                      │                                                             │
                      ▼                                                             ▼
[5. Re-Resolve Capability]                                                  [8. Record Fallback in Workflow]
  (`reverse_capability(refresh: true)`)                                        (`reverse_workflow(action: "record", ...)`
                      │                                                         or action: "recover")
                      ▼                                                             │
[6. Immediate Tool Dispatch]                                                        ▼
  (Execute postInstallInvocation or wrapper)                                [9. Continue Investigation Seamlessly]
                      │
                      ▼
[10. Record Step Completion in Workflow]
  (`reverse_workflow(action: "record", status: "completed", evidence_ids: [...])`)
```

### Protocol Steps

1. **Step 1: Query Capability Status (`reverse_capability`)**:
   Before attempting tool invocation or falling back, query capability readiness:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>" })
   ```
   Inspect the returned payload:
   - `status`: `"ready"` | `"available_with_fallbacks"` | `"missing"`
   - `ready`: boolean
   - `recommendedNativeTool`: name of zero-prep native tool if available
   - `optionalExternalTools`: list of external tools with individual install statuses
   - `prerequisites`: required system runtimes (e.g. `java`, `node`)
   - `setupCommand`: client-vetted installation command
   - `postInstallInvocation`: command template for immediate execution post-install
   - `availableFallbacks`: list of fallbacks currently available on this host

2. **Step 2: Check Native Baseline Tool**:
   If `recommendedNativeTool` is defined and provides the required analytical depth (e.g. `android_package_inspect` for container triage, `r2_inspect` for disassembly, `browser_reverse_session` for CDP debugging, `pcap_inspect` for network packets), proceed directly with the native tool.

3. **Step 3: Present Capability Notice & Request Operator Approval**:
   If the task specifically benefits from an optional external tool or the native tool lacks required depth:
   ```text
   [Capability Notice] Required capability: <capability_id> ('<capability_name>')
     -> Recommended tool: '<tool>' (Status: <missing|installed>)
     -> Why: <why>
     -> Prerequisites: <prerequisites or none>
     -> Trusted setup: <setupCommand> (Requires operator approval)
     -> Post-install invocation: <postInstallInvocation>
     -> Fallback if declined: '<fallback_tool>'
   ```
   Prompt the user for confirmation to run the trusted setup command.

4. **Step 4: User Executes Setup Command**:
   The operator executes the setup command (`reverse setup reverse <tool_id>`).

5. **Step 5: Re-Resolve Capability Post-Install**:
   Verify tool readiness by querying with `refresh: true`:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>", refresh: true })
   ```
   Confirm `status` is `"ready"` and the tool is available on PATH.

6. **Step 6: Immediate Dispatch**:
   Execute the newly available tool using its `postInstallInvocation` syntax with bounded arguments, or dispatch the native wrapper (e.g. `r2_inspect` / `ghidra_inspect`) which dynamically locates the installed binary.

7. **Step 7: Workflow Recording & Fallback Audit**:
   Record the step outcome in `reverse_workflow`:
   - *Successful Install & Run*:
     ```json
     reverse_workflow({
       action: "record",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       status: "completed",
       outputs: "<bounded tool execution summary>",
       evidence_ids: ["ev_fact_<id>"]
     })
     ```
   - *Refusal or Missing Prerequisite*:
     Immediately engage the fallback tier, and audit the refusal and active fallback in the workflow:
     ```json
     reverse_workflow({
       action: "record",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       status: "completed",
       outputs: "Operator declined setup for <tool>; engaged fallback <fallback_tool>",
       fallback_tool: "<fallback_tool>",
       evidence_ids: ["ev_fact_<id>"]
     })
     ```

---

## 5. Concrete End-to-End Scenarios

### 1. `android_native_emulation` (Headless JNI ARM Emulation)
- **Analytical Need**: Execute an obfuscated JNI signature function (`Java_com_example_Security_signToken`) inside a 64-bit ARM library (`libnative.so`) headlessly without a physical device or emulator.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "android_native_emulation" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "android_package_inspect"` inventories ELF symbols and container structure, but dynamic JNI instruction emulation requires `unidbg`.
- **Step 3 (Notice & Approval)**:
  ```text
  [Capability Notice] Required capability: android_native_emulation ('Android Native Library Emulation (JNI / ARM)')
    -> Recommended tool: 'unidbg' (Status: missing)
    -> Why: Simulates Dalvik/ART JVM runtime and Linux ARM CPU environment to execute exported or obfuscated JNI native methods directly from local .so binaries
    -> Prerequisites: java (JDK 8 / OpenJDK 8)
    -> Trusted setup: reverse setup reverse unidbg (Requires operator approval)
    -> Post-install invocation: Custom target Java harness (must exist in project; obtain actual invocation from project)
    -> Fallback if declined: 'android_native_workflow' + 'r2_inspect' static disassembly
  ```
- **Step 4 (Setup)**: User executes `reverse setup reverse unidbg`.
- **Step 5 (Re-resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "android_native_emulation", refresh: true })
  ```
- **Step 6 (Dispatch)**:
  A custom target Java harness must exist in the project; obtain its actual invocation from the project:
  ```bash
  # Execute custom target Java harness (must exist in project; obtain actual invocation from project build/test configuration)
  ```
- **Step 7 (Workflow Record)**:
  - *On Success*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "apk_step_3",
      status: "completed",
      outputs: "Unidbg emulated JNI return value: 0x4a9b21f8",
      evidence_ids: ["ev_fact_jni_output"]
    })
    ```
  - *On Refusal*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "apk_step_3",
      status: "completed",
      outputs: "Operator declined unidbg setup; engaged fallback r2_inspect static disassembly",
      fallback_tool: "r2_inspect",
      evidence_ids: ["ev_fact_r2_sym"]
    })
    ```

### 2. `apk_unpacking` (APK Decompilation & Class Recovery)
- **Analytical Need**: Recover high-level Java source code from Dalvik bytecode for class `com.example.AuthService` in `target.apk`.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "apk_unpacking" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "android_package_inspect"` is ready for container layout, DEX headers, binary manifest, and signatures. High-level Java decompilation requires `jadx`.
- **Step 3 (Notice & Approval)**:
  ```text
  [Capability Notice] Required capability: apk_unpacking ('APK / AAB Package Decompilation & Unpacking')
    -> Recommended tool: 'jadx' (Status: missing)
    -> Why: Transforms opaque binary APK packages and optimized DEX files into structured project trees and intelligible Java source code
    -> Prerequisites: java
    -> Trusted setup: reverse setup reverse jadx (macOS: brew install jadx)
    -> Post-install invocation: jadx -d ./artifacts/jadx_out --single-class com.example.AuthService target.apk
    -> Fallback if declined: 'droidasc' (on-demand DEX class query) / 'android_package_inspect'
  ```
- **Step 4 (Setup)**: User executes `reverse setup reverse jadx`.
- **Step 5 (Re-resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "apk_unpacking", refresh: true })
  ```
- **Step 6 (Dispatch)**:
  ```bash
  jadx -d ./artifacts/jadx_out --single-class com.example.AuthService target.apk
  ```
- **Step 7 (Workflow Record)**:
  - *On Success*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "apk_step_2",
      status: "completed",
      outputs: "Decompiled AuthService.java to ./artifacts/jadx_out; extracted validateToken method",
      evidence_ids: ["ev_fact_auth_method"]
    })
    ```
  - *On Refusal*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "apk_step_2",
      status: "completed",
      outputs: "Operator declined jadx setup; engaged fallback droidasc(op: 'getclass')",
      fallback_tool: "droidasc",
      evidence_ids: ["ev_fact_droidasc_cls"]
    })
    ```

### 2b. `dex_patching` (DEX Structural Validation & Bytecode Patching)
- **Analytical Need**: Modify Dalvik conditional branch logic in `classes.dex` without decompiling to smali or reassembling the APK.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "dex_patching" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "dex_patch"` validates DEX headers, checksums, and instruction boundaries in-process using Python 3.9+ runtime.
- **Step 3 (Dispatch)**:
  ```json
  dex_patch({ action: "inspect", path: "sample.apk", entry: "classes.dex", class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z" })
  dex_patch({ action: "patch", path: "classes.dex", out: "./artifacts/classes_patched.dex", dry_run: false, specs: [{ class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z", match: { kind: "const4", literal: 1 }, replace: { kind: "bytes", bytes: "1230" } }] })
  ```
- **Step 4 (Lineage Record)**:
  ```json
  reverse_workflow({ action: "register_derivative", workflow_id: "wf_rw_1", step_id: "dex_step_1", build_id: "bld_patch1", derivative_path: "./artifacts/classes_patched.dex", original_sha256: "<orig_sha>", output_sha256: "<output_sha>", signature_status: "unsigned" })
  ```

### 2c. `apk_artifact_generation` (APK Container Repack, Alignment & Signing)
- **Analytical Need**: Assemble patched `classes.dex` into target APK, enforce 4-byte/16KiB page alignment, and apply cryptographic signatures.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "apk_artifact_generation" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "apk_artifact"` performs entry diff and container repacking offline; signing pipeline requires `python`, `zipalign`, `apksigner`, and `java`.
- **Step 3 (Repack & Diff)**:
  ```json
  apk_artifact({ action: "repack", path: "target.apk", output_path: "./artifacts/repacked_unsigned.apk", dex_files: { "classes.dex": "./artifacts/classes_patched.dex" }, strip_signatures: true, page_align_so: true })
  apk_artifact({ action: "diff", original_path: "target.apk", modified_path: "./artifacts/repacked_unsigned.apk" })
  ```
- **Step 4 (Sign & Verify)**:
  ```json
  apk_artifact({ action: "sign", path: "./artifacts/repacked_unsigned.apk", output_path: "./artifacts/target_signed.apk", keystore_path: "~/.android/debug.keystore", key_alias: "androiddebugkey", ks_pass_env: "KEYSTORE_PASS", page_align_so: true })
  apk_artifact({ action: "verify", path: "./artifacts/target_signed.apk" })
  ```

### 3. `browser_debugger` (Browser CDP Dynamic Inspection)
- **Analytical Need**: Intercept dynamic JavaScript crypto state (`window.__AUTH_STATE__`) and monitor network requests in a single-page web app.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "browser_debugger" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "browser_reverse_session"` + `js_hook_preset` is ready immediately for local CDP evaluation. If multi-tab persistent headless automation via MCP is requested, evaluate `playwright-mcp`.
- **Step 3 (Notice & Approval)**:
  ```text
  [Capability Notice] Required capability: browser_debugger ('Browser Debugger & CDP Dynamic Inspection')
    -> Recommended tool: 'playwright-mcp' (Status: missing)
    -> Why: Enables runtime inspection of complex minified JavaScript code, single-page application state, and dynamic crypto/signature generation
    -> Prerequisites: node
    -> Trusted setup: reverse setup reverse playwright-mcp (Requires operator approval)
    -> Post-install invocation: configure .reverse/mcp.json playwright entry or launch browser_reverse_session
    -> Fallback if declined: 'browser_reverse_session' (native CDP)
  ```
- **Step 4 (Setup)**: User executes setup or opts for native session.
- **Step 5 (Re-resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "browser_debugger", refresh: true })
  ```
- **Step 6 (Dispatch)**:
  Dispatch native `browser_reverse_session`:
  ```json
  browser_reverse_session({ action: "eval", expression: "JSON.stringify(window.__AUTH_STATE__)" })
  ```
- **Step 7 (Workflow Record)**:
  ```json
  reverse_workflow({
    action: "record",
    workflow_id: "wf_rw_1",
    step_id: "web_step_2",
    status: "completed",
    outputs: "Extracted window.__AUTH_STATE__ tokens and session seed",
    evidence_ids: ["ev_fact_auth_seed"]
  })
  ```

### 4. `native_debugger` (Native Binary Disassembly & Dynamic Debugging)
- **Analytical Need**: Decompile validation function `validate_key` and inspect control flow branches in native ELF binary `target_bin`.
- **Step 1 (Resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "native_debugger" })
  ```
- **Step 2 (Native Evaluation)**: `recommendedNativeTool: "r2_inspect"` (and `triage`). Ready for bounded disassembly, section entropy, and xrefs. For deep decompilation or dynamic stepping, evaluate `radare2` / `ghidra`.
- **Step 3 (Notice & Approval)**:
  ```text
  [Capability Notice] Required capability: native_debugger ('Native Binary Debugger & Dynamic Tracing')
    -> Recommended tool: 'radare2' (Status: missing)
    -> Why: Analyzes packing routines, anti-debugging mechanisms, runtime decryption keys, and dynamically generated control flow
    -> Prerequisites: none
    -> Trusted setup: reverse setup reverse radare2 (macOS: brew install radare2)
    -> Post-install invocation: r2 -d <binary_path> or query via r2_inspect(action: "decompile")
    -> Fallback if declined: 'triage' + 'objdump -d' / POSIX 'strings'
  ```
- **Step 4 (Setup)**: User executes `reverse setup reverse radare2`.
- **Step 5 (Re-resolve)**:
  ```json
  reverse_capability({ action: "resolve", capability: "native_debugger", refresh: true })
  ```
- **Step 6 (Dispatch)**:
  Invoke native `r2_inspect` (which now uses the newly installed `radare2`):
  ```json
  r2_inspect({ action: "decompile", path: "./target_bin", symbol: "validate_key" })
  ```
- **Step 7 (Workflow Record)**:
  - *On Success*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "native_step_2",
      status: "completed",
      outputs: "Decompiled validate_key: detected XOR decryption with hardcoded key '0x5A'",
      evidence_ids: ["ev_fact_key_xor"]
    })
    ```
  - *On Refusal*:
    ```json
    reverse_workflow({
      action: "record",
      workflow_id: "wf_rw_1",
      step_id: "native_step_2",
      status: "completed",
      outputs: "Operator declined radare2 setup; engaged fallback objdump -d disassembly",
      fallback_tool: "objdump",
      evidence_ids: ["ev_fact_objdump_asm"]
    })
    ```
