---
name: reverse-lab
description: Multi-platform reverse engineering orchestrator for rea. Guides target-first triage (Android, Windows PE, Web/JS, Protocol), structured evidence chains (Fact/Hypothesis/Conclusion), static-dynamic verification loops, and graceful tool degradation.
metadata:
  requiresOptional: droidasc, jadx, apktool, adb, frida, frida_session, radare2, ida
---

# Reverse Lab Orchestrator

`reverse-lab` is the multi-platform reverse engineering and authorization audit orchestrator for `rea`. It routes analysis targets to modular domain workflows, maintains rigorous empirical evidence chains, manages context token budgets, and ensures seamless toolchain degradation when specialized disassemblers are absent.

---

## 1. Safety & Authorized Lab Environment Gate

Reverse engineering operations follow verified authorization boundaries:
1. **Authorization & Scope**: Focus exclusively on designated test targets, local laboratory sandboxes, and explicitly authorized audit scopes.
2. **Sample Integrity**: Record SHA-256 and initial file attributes before any mutation or dynamic execution.
3. **Isolation**: Perform dynamic observation in sandboxes, isolated emulator instances, or loopback network interfaces.
4. **Non-Destructive Defaults**: Preserve original sample binaries read-only; write all patches, unpacked payloads, and scripts to dedicated artifact directories.

---

## 2. Six-Stage Rea Working Flow

Reverse engineering in `rea` follows the positive scientific verification workflow:

```
[1. 目标明确化] ──> [2. 环境与样本确认] ──> [3. 事实收集] ──> [4. 假设形成] ──> [5. 实验验证] ──> [6. 铁证结论]
 (Clarify Goal)     (Env & Sample Spec)    (Gather Facts)     (Form Hypothesis)   (Experimental Proof)   (State Conclusion)
```

1. **Clarify the Goal (`目标明确化`)**: State the precise question (e.g. "Identify how the auth token signature is calculated", "Locate client-side license verification check", "Map protocol payload encryption scheme").
2. **Confirm Environment & Sample (`环境与样本确认`)**: Verify target architecture, operating system, runtime dependencies, and sample SHA-256 hash.
3. **Gather Evidence (`事实收集`)**: Collect ground truth (exported functions, string references, decompiled blocks, packet traces). Every fact must cite exact offsets or line numbers.
4. **Form a Hypothesis (`假设形成`)**: Hypothesize the mechanism (e.g., "Function `sub_1400021A0` returns 0 on signature mismatch"). Tag clearly as `[HYPOTHESIS]`.
5. **Verify Experimentally (`实验验证`)**: Conduct closed-loop verification (patch test, dynamic breakpoint observation, Frida hook argument trace, mock server response).
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
| **Web & JS** | `.js`, `.mjs`, `.wasm`, `.html`, SourceMaps, HAR/JSON | `sourcemap_inspect` / `js_hook_preset` / `ast_grep` / `wasm_inspect` / `javascript_application` / `browser-relay` | `skill://reverse-lab/references/web-protocol.md` |
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

## 5. Tool Degradation Strategy

When primary tools are absent, smoothly step down the toolchain ladder without halting the task:
- **Android**: rea native `android_package_inspect` (container/DEX/manifest/signing/resources) ➔ `droidasc` (instant on-demand) ➔ `jadx` ➔ `apktool` (smali) ➔ `unzip`/`dexdump`.
- **Native / ELF / Mach-O / PE**: rea native `triage` (built-in headers/entropy) ➔ native `dotnet_inspect` (.NET PE/CIL) ➔ `read-binary` (IDA Pro) / `ghidra_inspect` (Ghidra headless) / `r2_inspect` (radare2) ➔ `radare2` (`r2`) ➔ `objdump`/`readelf`/`nm`/`strings`/posix binutils.
- **Web / JS**: `browser-relay` / CDP ➔ Headless HTTP / curl + native `ast_grep` + native `wasm_inspect` (`info`/`strings`/`search`) + native `javascript_application` (Electron/ASAR) + native `sourcemap_inspect` (VLQ/sourcesContent) + native `js_hook_preset` (safe instrumentation); `wasm2wat` only for full WAT.
- **Protocol & Network**: rea native `pcap_inspect` (PCAP/PCAPNG headers/packets/endpoints/DNS) + `websocket_observe` (WebSocket capture) ➔ `tshark` / `tcpdump` ➔ `mitmproxy` / `mitmdump` ➔ curl/raw scripts.
- **Database & Storage**: rea native `sqlite_inspect` (schema/tables/rows/WAL) ➔ `sqlite3` CLI (read-only) ➔ Python/Node `sqlite3` scripts.
- **Firmware & Embedded**: rea native `firmware_inspect` (containers/regions/entries/entropy) ➔ `binwalk` ➔ `7z` / `unsquashfs` / `cpio` ➔ `strings` / `xxd`.
- **Crash & Core Dumps**: rea native `crashdump_inspect` (ELF core / Minidump headers/threads/mappings/registers/notes) ➔ `gdb` / `lldb` / `cdb` ➔ `readelf -n` / strings.
- **Go / Rust Metadata**: rea native `binary_metadata_inspect` (Go build info, cargo-auditable dependency graph, rustc commit/version, sections) ➔ `go version -m` / `cargo auditable` ➔ `readelf -p .dep-v0` / `strings`.
- **Smart Contracts / EVM**: rea native `evm_inspect` (offline opcode disasm, function selectors, CBOR metadata, proxy detection) ➔ Foundry `cast disasm` / `hevm` ➔ Python `pyevmasm` / offline scripts.
- **Binary Diffing**: rea native `binary_diff` (deterministic SHA-256/MD5, block-level delta, similarity score, contiguous byte diffs) ➔ `vbindiff` / `radiff2` ➔ `cmp -l` / `diff`.
- **Workflow Orchestration**: rea native `reverse_workflow` (deterministic target-routed plans, state store, failure recovery metadata, evidence ledger links) ➔ manual multi-tool execution.
- **Runtime Session Registry**: rea native `reverse_runtime_session` (unified session registry across Frida, browser, IDA, Ghidra, stale heartbeat tracking, deterministic restore plan) ➔ tool-native session tracking ➔ manual re-attachment.
Read `skill://reverse-lab/references/tool-fallback.md` for exact CLI invocation syntax and installation hints.

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
