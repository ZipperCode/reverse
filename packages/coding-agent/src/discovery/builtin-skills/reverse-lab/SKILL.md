---
name: reverse-lab
description: Multi-platform reverse engineering orchestrator for reverse. Enforces skill-first investigation, target-first triage, structured evidence chains (Fact/Hypothesis/Conclusion), capability discovery before stopping, trusted setup installation with user approval, immediate dispatch, and graceful tool degradation.
metadata:
  requiresOptional: droidasc, jadx, apktool, adb, frida, radare2, ida, unidbg, mitmproxy
---

# Reverse Lab Orchestrator

`reverse-lab` is the multi-platform reverse engineering and authorization audit orchestrator for `reverse`. It enforces a **skill-first, tool-selective** architecture: the skill governs investigation methodology, target routing, hypothesis formation, and empirical proof, while native and external tools serve as controlled single-action executors. It guarantees continuous progress via the **Discover-Before-Stop / Install-Then-Dispatch** workflow and seamless degradation when specialized disassemblers are absent.
---

## 1. Safety, Setup Integrity & Authorized Lab Environment Gate

Reverse engineering operations follow strict authorization and safety boundaries:
1. **Authorization & Scope**: Focus exclusively on designated test targets, local laboratory sandboxes, and explicitly authorized audit scopes.
2. **Sample Integrity**: Record SHA-256 and initial file attributes before any mutation or dynamic execution.
3. **Isolation**: Perform dynamic observation in sandboxes, isolated emulator instances, or loopback network interfaces.
4. **Non-Destructive Defaults**: Preserve original sample binaries read-only; write all patches, unpacked payloads, and scripts to dedicated artifact directories (`./artifacts/`).
5. **Setup Integrity Invariant**: The agent MUST NEVER run arbitrary shell commands, inject untrusted registry packages, or run uncontrolled `curl | sh` scripts. External tools are only installed via structured recipes from `skill-tool-catalog` and ONLY after explicit operator confirmation via `reverse setup reverse <tool-id>`.
---

## 2. Six-Stage Reverse Working Flow

Reverse engineering in `reverse` follows the positive scientific verification workflow:

```
[1. 目标明确化] ──> [2. 环境与样本确认] ──> [3. 事实收集] ──> [4. 假设形成] ──> [5. 实验验证] ──> [6. 铁证结论]
 (Clarify Goal)     (Env & Sample Spec)    (Gather Facts)     (Form Hypothesis)   (Experimental Proof)   (State Conclusion)
```

1. **Clarify the Goal (`目标明确化`)**: State the precise question (e.g. "Identify how the auth token signature is calculated", "Locate client-side license verification check", "Map protocol payload encryption scheme").
2. **Confirm Environment & Sample (`环境与样本确认`)**: Verify target architecture, operating system, runtime dependencies, and sample SHA-256 hash.
3. **Gather Evidence (`事实收集`)**: Collect ground truth (exported functions, string references, decompiled blocks, packet traces). If a specialized capability is unconfirmed or missing, invoke `reverse_capability` to inspect native baselines and catalog recipes, recommend optional tools with install paths, ask approval, run setup, re-resolve, or immediately engage the fallback tier and record progress in `reverse_workflow`. Every fact must cite exact offsets or line numbers.
4. **Form a Hypothesis (`假设形成`)**: Hypothesize the mechanism (e.g., "Function `sub_1400021A0` returns 0 on signature mismatch"). Tag clearly as `[HYPOTHESIS]`.
5. **Verify Experimentally (`实验验证`)**: Conduct closed-loop verification (patch test, dynamic breakpoint observation, Frida hook argument trace, mock server response). When dynamic execution requires tools (e.g., Unidbg host emulation or Frida runtime hooks), verify readiness or install via trusted setup before execution; if declined, verify via static patch/mock proofs.
6. **State the Conclusion (`铁证结论`)**: Emit findings with reproducible proof artifacts. Untested claims remain marked as unverified hypotheses.

Read `skill://reverse-lab/references/evidence.md` for artifact formats and evidence standards.

---

## 3. Target-First Routing Matrix

Classify the artifact before invoking heavy tools:

| Target Category | Signature / Extension | Initial Inspection | Reference Guide |
| :--- | :--- | :--- | :--- |
| **Native Binary** | ELF (`\x7fELF`), Mach-O (`\xcf\xfa\xed\xfe`, `\xce\xfa\xed\xfe`), Fat Mach-O (`\xca\xfe\xba\xbe`), `.so`, `.dylib`, `.o`, raw/firmware | `triage` / `read-binary` (IDA) / `r2_inspect` | `skill://native-binary-reverse` |
| **Android** | `.apk`, `.aab`, `.dex`, JNI `.so` in APK context, `AndroidManifest.xml` | `android_package_inspect` (native container/DEX/manifest/signing/resources) / `droidasc getmanifest` / `jadx` / `apktool` | `skill://reverse-lab/references/android.md` |
| **Windows PE / .NET** | `MZ` header, `.exe`, `.dll`, `.sys`, `.node` (PE32/PE32+) | `dotnet_inspect` (.NET) / `triage` / `read-binary` (IDA) / `ghidra_inspect` / `r2_inspect` | `skill://reverse-lab/references/windows.md` |
| **Virtualized / Packed (VMP)** | High entropy sections (> 7.2), `.vmp0`/`.vmp1`, VM entry dispatcher calls | `triage` / `vmp_dump` (at OEP) / `native_devirtualize` / `triton_analyze` | `skill://vmp-reverse` |
| **Web & JS** | `.js`, `.mjs`, `.wasm`, `.html`, SourceMaps, HAR/JSON | `browser_reverse_session` / `sourcemap_inspect` / `js_hook_preset` / `ast_grep` / `wasm_inspect` / `javascript_application` / `browser-relay` | `skill://reverse-lab/references/web-protocol.md` |
| **Protocol & Network** | Raw TCP/TLS, `.pcap`, `.pcapng`, WebSocket frames, HTTP API payloads | `pcap_inspect` (native PCAP/PCAPNG) / `websocket_observe` / Network interception | `skill://reverse-lab/references/web-protocol.md` |
| **Database / Storage** | `.db`, `.sqlite`, `.sqlite3`, SQLite format 3, WAL files | `sqlite_inspect` (native schema/tables/rows/WAL) | `skill://reverse-lab/references/web-protocol.md` |
| **Firmware & Embedded** | uImage, SquashFS, CPIO, TAR, FIT/DTB, raw flash/ROM | `firmware_inspect` (native containers/regions/entries/entropy) | `skill://reverse-lab/references/target-routing.md` |
| **Crash & Core Dumps** | Linux ELF core (`ET_CORE`), Microsoft Minidump (`MDMP`), Mach-O core | `crashdump_inspect` (native registers/signals/threads/mappings) | `skill://reverse-lab/references/target-routing.md` |
| **Go / Rust Binaries** | Go runtime build info (`\xff Go buildinf:`), Rust cargo-auditable (`.dep-v0`), stripped Go/Rust symbols | `binary_metadata_inspect` (native Go version/modules/flags, Rust auditable crates/rustc) | `skill://reverse-lab/references/target-routing.md` |
| **Smart Contracts / EVM** | EVM bytecode (`.bin`, `.hex`, `0x60806040...`), Solidity/Vyper deployment & runtime code | `evm_inspect` (native disasm/selectors/CBOR/proxies) | `skill://reverse-lab/references/target-routing.md` |
| **Binary Diffing** | Firmware revisions, patched binaries, compiler variants, two file paths | `binary_diff` (deterministic hashes/blocks/bytes/headers) | `skill://reverse-lab/references/target-routing.md` |
| **Workflow Orchestration** | PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite targets | `reverse_workflow` (deterministic tool plans, state persistence, bounded retry, evidence linking) | `skill://reverse-lab/references/target-routing.md` |
| **Multi-runtime** | React Native (`.hbc`), Electron (`app.asar`), Flutter, Unity | `javascript_application` (Electron/ASAR) / De-pack container -> route components | `skill://reverse-lab/references/target-routing.md` |
For detailed gate decision trees and magic byte classification, read `skill://reverse-lab/references/target-routing.md`.

---

## 4. Context Budget & Search-First Control

Preserve conversation token budget through structured three-tier inspection:
- **Tier 1: Overview & Metadata (~90% Token Reduction)**: Inspect manifest, headers, exported symbols, section table, or string lists before decompiling code.
- **Tier 2: Search-First & Folded View (~60% Token Reduction)**: Use cross-reference searches (`xrefs`), native `ast_grep` or grep on symbol names, or API keywords (`encrypt`, `verify`, `license`, `token`, `sign`).
- **Tier 3: Bounded Focus**: Read only the target function, single class, or discrete disassembly block using line ranges (`:50-120`) or specific symbol queries.

---

## 5. Capability Discovery, Setup & Immediate Dispatch Lifecycle

When an investigative step requires an external tool or when a preferred engine is not found on PATH, `reverse-lab` executes the mandatory **Discover-Before-Stop / Install-Then-Dispatch** lifecycle using the native `reverse_capability` tool instead of halting:

```
[Need Detected] ──> [1. Resolve Capability (`reverse_capability`)]
                            │
      ┌─────────────────────┴─────────────────────┐
      ▼ (Recommended Native Tool Ready)           ▼ (External Tool Needed / Missing)
[2. Dispatch Native Baseline First]          [3. Present Notice & Ask Approval]
  (Zero-prep built-in tool)                    (why, prereqs, setupCommand, postInstall)
                                                  │
                   ┌──────────────────────────────┴──────────────────────────────┐
                   ▼ (Approved)                                                  ▼ (Declined / Missing Prereq)
[4. User Executes Setup Command]                                            [7. Engage Degradation Ladder]
  (`reverse setup reverse <id>`)                                                   (Run active fallback tool)
                   │                                                             │
                   ▼                                                             ▼
[5. Re-Resolve Capability (`refresh: true`)]                                [8. Record Fallback in Workflow]
  (Verify status transitioned to ready)                                        (`reverse_workflow(action: "record", ...)`
                   │                                                            or action: "recover")
                   ▼                                                             │
[6. Dispatch Tool Post-Install]                                                 ▼
  (Execute postInstallInvocation with bounded limits)                       [9. Continue Continuous Investigation]
                   │
                   ▼
[10. Record Step Completion in Workflow]
  (`reverse_workflow(action: "record", status: "completed", evidence_ids: [...])`)
```

### Concrete Capability Protocol

1. **Discover & Query Capability (`reverse_capability`)**:
   Query capability availability before attempting tool dispatch or halting:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>" })
   ```
   Or inspect catalog details and operational rationale:
   ```json
   reverse_capability({ action: "get", capability: "<capability_id>" })
   ```

2. **Prefer Recommended Native Tool First**:
   Inspect `recommendedNativeTool` and readiness `status` in the resolution payload. When the native built-in tool is ready (`ready: true` or zero-prep native alternative available, such as `android_package_inspect` for APK/DEX/manifest inspection, `triage` / `r2_inspect` for native binaries, `browser_reverse_session` / `js_hook_preset` for web dynamic inspection), prefer and dispatch the native tool first without unnecessary installation pauses.

3. **Present Capability Notice & Request Operator Approval**:
   When the native tool is insufficient for the analytical depth required or an optional external tool is requested/missing, formulate the structured capability notice from the catalog descriptor:
   ```text
   [Capability Notice] Required capability: <capability_id> ('<capability_name>')
     -> Recommended tool: '<tool>' (Status: <missing|installed>)
     -> Why: <why>
     -> Prerequisites: <prerequisites or none>
     -> Trusted setup: <setupCommand> (Requires operator approval)
     -> Post-install invocation: <postInstallInvocation>
     -> Fallback if declined: '<fallback_tool>'
   ```
   Request explicit operator confirmation before executing any setup command.

4. **User Executes Trusted Setup**:
   The operator executes the trusted setup command (`reverse setup reverse <tool_id>`) in the terminal or setup panel.

5. **Re-Resolve Capability Post-Install**:
   Immediately verify tool availability by re-resolving with refresh enabled:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>", refresh: true })
   ```
   Confirm that `status` transitioned to `"ready"` and the tool is available on PATH.

6. **Immediate Dispatch**:
   Invoke the external tool using its canonical `postInstallInvocation` syntax with bounded limits (e.g. targeted class decompilation, symbol disassembly, or headless transport) or invoke the native CLI wrapper (e.g. `r2_inspect` or `ghidra_inspect` which dynamically resolves the newly installed binary on PATH).

7. **Workflow Audit & Degradation Recording**:
   Record the operational outcome and verified evidence into `reverse_workflow`:
   - **When Setup Succeeded & Dispatched**:
     ```json
     reverse_workflow({
       action: "record",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       status: "completed",
       outputs: "<bounded tool output summary>",
       evidence_ids: ["ev_fact_<id>"]
     })
     ```
   - **When Setup Was Declined or Prerequisite Missing**:
     Immediately engage the active fallback tier from the degradation ladder, and record the refusal and active fallback into the workflow record:
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
     Or when recovering a failed step:
     ```json
     reverse_workflow({
       action: "recover",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       fallback_tool: "<fallback_tool>",
       result: "Operator declined install of <tool>; switched execution to fallback <fallback_tool>"
     })
     ```
   - **When Setup Succeeded & Resuming Step (Install-After Resumption)**:
     When an external tool is installed following a `missing_dependency` failure, record canonical install-after resume metadata to re-bind and resume the original planned tool rather than forcing a fallback:
     ```json
     reverse_workflow({
       action: "recover",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       capability_id: "<capability_id>",
       installed_tool: "<tool>",
       setup_command: "reverse setup reverse <tool>",
       verified: true,
       strategy: "resume_original"
     })
     ```
     Or when retrying directly:
     ```json
     reverse_workflow({
       action: "retry",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       capability_id: "<capability_id>",
       installed_tool: "<tool>",
       setup_command: "reverse setup reverse <tool>",
       verified: true,
       strategy: "resume_original"
     })
     ```

### Concrete Capability Scenarios

1. **`android_native_emulation` (Android JNI Cryptography)**:
   - *Scenario*: Analyzing obfuscated JNI cryptographic algorithms in `.so` without a physical Android device or emulator.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "android_native_emulation" })`.
   - *Step 2 (Native Check)*: `recommendedNativeTool: "android_package_inspect"` inventories libraries and maps symbols; headless ARM CPU instruction execution requires `unidbg`.
   - *Step 3 (Notice & Approval)*: Present notice: Tool `'unidbg'`, Why *"Simulates Dalvik/ART JVM runtime and Linux ARM CPU environment to execute exported or obfuscated JNI native methods directly from local .so binaries"*, Prerequisites `["java"]`, Setup `reverse setup reverse unidbg`, Post-install `mvn test -Dtest=<HarnessTest> or custom Java McpToolkit harness`, Fallback `android_native_workflow` + `r2_inspect`. Request operator approval.
   - *Step 4 (Setup)*: User runs `reverse setup reverse unidbg`.
   - *Step 5 (Re-resolve)*: `reverse_capability({ action: "resolve", capability: "android_native_emulation", refresh: true })`.
   - *Step 6 (Dispatch)*: Execute Maven Java test harness or McpToolkit runner against target `.so` with bounded test vectors.
   - *Step 7 (Workflow Record)*: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "apk_step_3", status: "completed", outputs: "Unidbg emulated JNI return: hash=0x3f1a...", evidence_ids: ["ev_fact_jni_hash"] })`. If declined: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "apk_step_3", status: "completed", outputs: "Operator declined unidbg setup; engaged fallback r2_inspect static disassembly", fallback_tool: "r2_inspect", evidence_ids: ["ev_fact_r2_sym"] })`.

2. **`apk_unpacking` (Android Decompilation & Resources)**:
   - *Scenario*: Recovering human-readable Java source, smali bytecode, and decoded AndroidManifest.xml from an APK/AAB package.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "apk_unpacking" })`.
   - *Step 2 (Native Check)*: `recommendedNativeTool: "android_package_inspect"` extracts container structures, DEX headers, binary manifest, and signatures immediately with zero external dependencies. When high-level Java decompilation of entire classes is requested, evaluate optional external tools `jadx` / `apktool`.
   - *Step 3 (Notice & Approval)*: Present notice: Tool `'jadx'`, Why *"Transforms Dalvik DEX bytecode into readable Java source code for vulnerability and protocol analysis"*, Prerequisites `["java"]`, Setup `reverse setup reverse jadx`, Post-install `jadx -d ./artifacts/jadx_out --single-class <class> <target.apk>`, Fallback `droidasc` / `android_package_inspect`. Request operator approval.
   - *Step 4 (Setup)*: User runs `reverse setup reverse jadx`.
   - *Step 5 (Re-resolve)*: `reverse_capability({ action: "resolve", capability: "apk_unpacking", refresh: true })`.
   - *Step 6 (Dispatch)*: Invoke `jadx -d ./artifacts/jadx_out --single-class com.example.AuthService target.apk`.
   - *Step 7 (Workflow Record)*: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "apk_step_2", status: "completed", outputs: "Decompiled target class to ./artifacts/jadx_out", evidence_ids: ["ev_fact_apk_class"] })`. If declined: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "apk_step_2", status: "completed", outputs: "Operator declined jadx setup; engaged fallback droidasc", fallback_tool: "droidasc" })`.

3. **`dex_patching` (Dalvik Bytecode Semantic Patching)**:
   - *Scenario*: Directly modifying Dalvik bytecode instructions (inverting conditional branches, overriding boolean returns, nop-padding checks) without decompiling to smali or reassembling the entire APK.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "dex_patching" })`.
   - *Step 2 (Native Check)*: `recommendedNativeTool: "dex_patch"`. Verifies DEX structures, Adler32 checksums, SHA-1 signatures, and method instruction boundaries. If Python 3.9+ runtime is missing, present setup notice for `reverse setup reverse python`.
   - *Step 3 (Inspect & Dry-Run)*: `dex_patch({ action: "inspect", path: "sample.apk", entry: "classes.dex", class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z" })` followed by dry-run patch.
   - *Step 4 (Patch Execution)*: `dex_patch({ action: "patch", path: "classes.dex", out: "./artifacts/classes_patched.dex", dry_run: false, specs: [{ class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z", match: { kind: "const4", literal: 1 }, replace: { kind: "bytes", bytes: "1230" } }] })`.
   - *Step 5 (Lineage Record)*: Register derivative via `reverse_workflow({ action: "register_derivative", workflow_id: "<wf_id>", step_id: "<step_id>", build_id: "bld_patch1", derivative_path: "./artifacts/classes_patched.dex", original_sha256: "<orig_sha>", output_sha256: "<output_sha>", signature_status: "unsigned" })`.

4. **`apk_artifact_generation` (APK Container Repackaging & Signing)**:
   - *Scenario*: Assembling modified DEX bytecode into a valid APK container, enforcing 4-byte/16KiB page alignments, applying v1-v3 APK signatures, and verifying container integrity.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "apk_artifact_generation" })`. Check readiness: offline repack/diff uses Python stdlib; signed pipeline requires `python`, `zipalign`, `apksigner`, and `java`.
   - *Step 2 (Repack & Diff)*: `apk_artifact({ action: "repack", path: "target.apk", output_path: "./artifacts/repacked_unsigned.apk", dex_files: { "classes.dex": "./artifacts/classes_patched.dex" }, strip_signatures: true, page_align_so: true })` followed by `apk_artifact({ action: "diff", original_path: "target.apk", modified_path: "./artifacts/repacked_unsigned.apk" })` for zero-change control. Pass the unmodified original package through the identical repackaging and signing pipeline as an experimental control baseline before evaluating semantic modifications.
   - *Step 3 (Signing & Verification)*: `apk_artifact({ action: "sign", path: "./artifacts/repacked_unsigned.apk", output_path: "./artifacts/target_signed.apk", keystore_path: "~/.android/debug.keystore", key_alias: "androiddebugkey", ks_pass_env: "KEYSTORE_PASS", page_align_so: true })` followed by `apk_artifact({ action: "verify", path: "./artifacts/target_signed.apk" })`.
   - *Step 4 (Install Verification)*: When device/emulator is connected: `apk_artifact({ action: "install_verify", path: "./artifacts/target_signed.apk", package_name: "com.example.app", activity: ".MainActivity", serial: "<device_serial>", output_dir: "./artifacts/install_verify_run" })`. Note: Launch stability confirms container validity, but discrete feature verification remains mandatory before declaring success.

5. **`browser_debugger` (Web Runtime JS Debugging)**:
   - *Scenario*: Dynamic Web application inspection, DOM inspection, script debugging, source-map recovery, and automated Chrome DevTools Protocol control.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "browser_debugger" })`.
   - *Step 2 (Native Check)*: `recommendedNativeTool: "browser_reverse_session"` + `js_hook_preset` is ready immediately for CDP evaluation and script injection. If persistent multi-session browser orchestration is requested via MCP, evaluate `playwright-mcp`.
   - *Step 3 (Notice & Approval)*: Present notice: Tool `'playwright-mcp'`, Why *"Dynamic Web application inspection, DOM inspection, script debugging, and automated Chrome DevTools Protocol control"*, Prerequisites `["node"]`, Setup `reverse setup reverse playwright-mcp`, Post-install configure `.reverse/mcp.json` playwright entry, Fallback `browser_reverse_session`. Request operator approval.
   - *Step 4 (Setup)*: User runs `reverse setup reverse playwright-mcp` (or proceeds with native session).
   - *Step 5 (Re-resolve)*: `reverse_capability({ action: "resolve", capability: "browser_debugger", refresh: true })`.
   - *Step 6 (Dispatch)*: Execute browser session commands or dispatch native `browser_reverse_session({ action: "eval", expression: "window.__CONFIG__" })`.
   - *Step 7 (Workflow Record)*: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "web_step_2", status: "completed", outputs: "Captured runtime crypto state", evidence_ids: ["ev_fact_web_crypto"] })`. If declined: record fallback `browser_reverse_session` in `reverse_workflow`.

6. **`native_debugger` (Binary Runtime Tracing & Stepping)**:
   - *Scenario*: Dynamic instruction tracing, hardware breakpoints, register state analysis, and memory inspection on native ELF, PE, and Mach-O binaries.
   - *Step 1 (Resolve)*: `reverse_capability({ action: "resolve", capability: "native_debugger" })`.
   - *Step 2 (Native Check)*: `recommendedNativeTool: "triage"` (or `"debug"` when DAP adapter is present, `"r2_inspect"` when radare2 is installed). Ready for baseline header and section entropy triage. For dynamic stepping or deep decompilation, evaluate `debug` (DAP adapter) or `radare2` / `ghidra`.
   - *Step 3 (Notice & Approval)*: Present notice: Tool `'radare2'`, Why *"Dynamic runtime debugging, breakpoint inspection, register state analysis, memory mapping, and execution trace of native binaries"*, Prerequisites none, Setup `reverse setup reverse radare2`, Post-install `r2 -d <binary_path>` or query via `r2_inspect(action: "decompile", symbol: "<func>")`, Fallback `triage` + `readelf` / `objdump -d` / POSIX `strings`. Request operator approval.
   - *Step 4 (Setup)*: User runs `reverse setup reverse radare2`.
   - *Step 5 (Re-resolve)*: `reverse_capability({ action: "resolve", capability: "native_debugger", refresh: true })`.
   - *Step 6 (Dispatch)*: Invoke `r2_inspect({ action: "decompile", path: "<sample>", symbol: "auth_check" })` or `r2 -qc "aaa; s sym.auth_check; pdf" <sample>`.
   - *Step 7 (Workflow Record)*: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "native_step_2", status: "completed", outputs: "Decompiled auth_check: identified license validation logic", evidence_ids: ["ev_fact_auth_logic"] })`. If declined: `reverse_workflow({ action: "record", workflow_id: "wf_rw_1", step_id: "native_step_2", status: "completed", outputs: "Operator declined radare2 setup; engaged fallback objdump -d", fallback_tool: "objdump" })`.

7. **`websocket_capture` (Real-Time WebSocket Forensics)**:
   - *Scenario*: Capturing and auditing live WebSocket frames when no pre-recorded capture file exists.
   - *Protocol Trace*: Query `reverse_capability({ action: "resolve", capability: "websocket_capture" })` -> prefer native `websocket_observe` for offline captures -> recommend `reverse setup reverse mitmproxy` for live capture -> ask approval -> post-install run `mitmdump -s ws_dump.py` -> record in `reverse_workflow`.

8. **`js_deobfuscation` (AST JavaScript Un-packing)**:
   - *Scenario*: De-obfuscating mangled JavaScript variables, control-flow flattening, and string arrays in web bundles.
   - *Protocol Trace*: Query `reverse_capability({ action: "resolve", capability: "js_deobfuscation" })` -> prefer native `ast_grep` + `sourcemap_inspect` -> recommend external `ast-grep` CLI / `hbctool` if React Native Hermes bytecode is present -> ask approval -> dispatch -> record in `reverse_workflow`.

9. **`traffic_interception` (Dynamic Network & API Forensics)**:
   - *Scenario*: Intercepting live HTTPS traffic, analyzing API signatures, and replaying modified requests.
   - *Protocol Trace*: Query `reverse_capability({ action: "resolve", capability: "traffic_interception" })` -> prefer native `pcap_inspect` (offline PCAP) + `curl` -> recommend `reverse setup reverse mitmproxy` for live interception -> ask approval -> dispatch -> record in `reverse_workflow`.
### Graceful Tool Degradation Ladders
When an external tool is declined or unavailable, smoothly step down the ladder without halting:
- **Android**: reverse native `android_package_inspect` (container/DEX/manifest/signing/resources) ➔ `droidasc` (instant on-demand) ➔ `jadx` ➔ `apktool` (smali) ➔ `unzip`/`dexdump`.
- **Native / ELF / Mach-O / PE**: reverse native `triage` (built-in headers/entropy) ➔ native `dotnet_inspect` (.NET PE/CIL) ➔ `read-binary` (IDA Pro) / `ghidra_inspect` (Ghidra headless) / `r2_inspect` (radare2) ➔ `radare2` (`r2`) ➔ `objdump`/`readelf`/`nm`/`strings`/posix binutils.
- **Web / JS**: `browser_reverse_session` (live tab, preset injection, network/WebSocket/console capture) ➔ native `js_hook_preset` (safe instrumentation) ➔ `browser-relay` / CDP ➔ Headless HTTP / curl + native `ast_grep` + native `wasm_inspect` (`info`/`strings`/`search`) + native `javascript_application` (Electron/ASAR) + native `sourcemap_inspect` (VLQ/sourcesContent); `wasm2wat` only for full WAT.
- **Protocol & Network**: reverse native `pcap_inspect` (PCAP/PCAPNG headers/packets/endpoints/DNS) + `websocket_observe` (WebSocket capture) ➔ `tshark` / `tcpdump` ➔ `mitmproxy` / `mitmdump` ➔ curl/raw scripts.
- **Database & Storage**: reverse native `sqlite_inspect` (schema/tables/rows/WAL) ➔ `sqlite3` CLI (read-only) ➔ Python/Node `sqlite3` scripts.
- **Firmware & Embedded**: reverse native `firmware_inspect` (containers/regions/entries/entropy) ➔ `binwalk` ➔ `7z` / `unsquashfs` / `cpio` ➔ `strings` / `xxd`.
- **Crash & Core Dumps**: reverse native `crashdump_inspect` (ELF core / Minidump headers/threads/mappings/registers/notes) ➔ `gdb` / `lldb` / `cdb` ➔ `readelf -n` / strings.
- **Go / Rust Metadata**: reverse native `binary_metadata_inspect` (Go build info, cargo-auditable dependency graph, rustc commit/version, sections) ➔ `go version -m` / `cargo auditable` ➔ `readelf -p .dep-v0` / `strings`.
- **Smart Contracts / EVM**: reverse native `evm_inspect` (offline opcode disasm, function selectors, CBOR metadata, proxy detection) ➔ Foundry `cast disasm` / `hevm` ➔ Python `pyevmasm` / offline scripts.
- **Binary Diffing**: reverse native `binary_diff` (deterministic SHA-256/MD5, block-level delta, similarity score, contiguous byte diffs) ➔ `vbindiff` / `radiff2` ➔ `cmp -l` / `diff`.
- **Workflow Orchestration**: reverse native `reverse_workflow` (deterministic target-routed plans, state store, failure recovery metadata, evidence ledger links) ➔ manual multi-tool execution.
- **Runtime Session Registry**: reverse native `reverse_runtime_session` (unified session registry across Frida, browser, IDA, Ghidra, stale heartbeat tracking, deterministic restore plan) ➔ tool-native session tracking ➔ manual re-attachment.
- **Dynamic Evidence & Closure**: reverse native `reverse_dynamic_evidence` (normalizes bounded Frida, browser CDP, DAP, and Unidbg events into FactEvidence with verifiable session locators, verifies hypotheses, promotes verified outcomes into reusable knowledge, and closes workflow steps) ➔ manual evidence ledger entry.

Read `skill://reverse-lab/references/tool-fallback.md` for exact CLI invocation syntax, operator notices, and installation hints.

---

## 6. Subagent Delegation & Session Governance

Complex audits benefit from coordinating specialized subagents under the main orchestrator:
- **Main Agent (Orchestrator)**: Maintains overall session state, records the evidence chain, routes targets, and validates findings against the initial goal.
- **`scout` Subagent (Read-Only Reconnaissance)**: Specializes in rapid read-only symbol searches, string catalog extraction, archive structure scanning, and identifying crypto constants across large codebases.
- **`task` Subagent (Execution & Generation)**: Focuses on developing standalone PoCs, AST deobfuscation scripts, or candidate patch generation.
- **Single Stateful Controller Rule**: Assign dynamic instrumentation and interactive debuggers (GDB, DAP, Frida spawn via `frida_session`, CDP live relay) to a single stateful session runner to ensure deterministic port and state management.

---

## 7. Modular References

Load specific reference manuals and domain skills on-demand via `skill://`:
- `skill://native-binary-reverse`: Universal native binary workflow (ELF, Mach-O, Fat universal, shared objects, raw/firmware).
- `skill://reverse-lab/references/target-routing.md`: Target classification decision tree and multi-format discriminator.
- `skill://reverse-lab/references/evidence.md`: Fact-Hypothesis-Conclusion standards and proof artifact schema.
- `skill://reverse-lab/references/android.md`: Android workflow (`droidasc`, `jadx`, `apktool`, `adb`, `frida`).
- `skill://reverse-lab/references/windows.md`: Windows PE workflow (PE headers, IDA Pro `:overview/:xrefs`, `radare2`).
- `skill://reverse-lab/references/web-protocol.md`: Web and protocol forensics (Browser relay, JS search-first, WASM).
- `skill://reverse-lab/references/tool-fallback.md`: Tool availability detection, degradation chains, and package manager hints.
- `skill://vmp-reverse`: VMProtect memory dump, IAT repair, function lifting (Mergen/NoVmp), and Triton symbolic trace analysis.
- `skill://reverse-tool-guide/SKILL.md`: Capability discovery contract, base vs. optional tool policies, and trusted catalog reference.
