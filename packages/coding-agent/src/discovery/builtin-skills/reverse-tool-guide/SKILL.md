---
name: reverse-tool-guide
description: Canonical usage guide and capability discovery manual for reverse's reverse-engineering tools. Defines base vs. optional tool policies, the discover-before-stop / install-then-dispatch workflow, trusted catalog setup paths, and graceful degradation ladders.
---


MCP helper services are **not PATH binaries**; configure them through the trusted setup catalog.
# Reverse Tool Guide

This skill is the canonical capability discovery and operating manual for reverse-engineering tools in `reverse`. It enforces a **skill-first, tool-selective** architecture: skills drive investigation goals, hypothesis generation, and evidence verification, while tools act as modular, single-action executors.

### Tool Invocation & Schema Discovery
Tools in `reverse` are invoked via `write` to `xd://<tool>` with JSON arguments. Prior to dispatch, inspect tool schema, parameter constraints, and required fields using `read xd://<tool>`.

### Five-Tier Readiness Model
Capabilities evaluate five readiness tiers:
1. `installed`: Binary or package is present on PATH.
2. `compatible`: Runtime and version compatibility verified (e.g. JDK8 for Unidbg).
3. `canStart`: Operational prerequisites satisfied for the selected step; baseline container/manifest/DEX extraction starts immediately.
4. `runtimeReady`: Active background runner, session, or MCP transport connection is active.
5. `targetMatched`: Target loaded and verified. No circular gate requiring a live device before tool discovery.

---

## 1. Trusted Sources & Security Boundary

| Question | Canonical Source |
| :--- | :--- |
| Which capabilities and tools are present? | `reverse setup reverse --json` |
| What installation command is permitted? | The structured `installCommands` inside the catalog / setup JSON |
| What does a skill require? | `reverse skill check --json` |
| Which native tool to invoke first? | The tool's own prompt under `docs/tools/` and `packages/coding-agent/src/prompts/tools/` |

### Strict Security Invariant
The agent and skills MUST NEVER execute arbitrary shell scripts, inject untrusted registry URLs, or invoke `curl | sh` / `powershell -c` installers. External tools may only be installed via the structured, client-vetted recipes in `skill-tool-catalog` and ONLY after explicit confirmation in the interactive setup panel or via `reverse setup reverse <tool-id>`.

---

## 2. Base vs. Optional Tool Policy

`reverse` classifies reverse engineering tools into two distinct categories:

### Base / Native Tools (Built-in, Zero Setup Friction)
Always present in every `reverse` installation without external package managers, compilers, or PATH binaries. Always consult and prefer native tools first before reaching for external dependencies:

- **`android_package_inspect`**: Complete offline inspection of Android packages (`.apk`, `.aab`, `.apks`) and bare `.dex` files. Parses container trees, DEX headers/classes, binary XML manifests, signing schemes (v1/v2/v3/v3.1), and resources.
- **`app_experiment`**: Bounded mobile application laboratory experiments via ADB backend (device preflight, benign component invocation, read-only content provider query, run-as sandbox data extract, webview debug, loopback network replay, mitm capture, pinning diagnose).
- **`runtime_analyze`**: Mobile framework and multi-runtime analyzer (framework inventory, Hermes bytecode disassembly, Unity IL2CPP dumping, Flutter Dart AOT symbol extraction).
- **`triage`**: Instant binary format identification, header parsing (ELF, PE, Mach-O Thin & Universal), section layouts, stripped status, and Shannon entropy.
- **`dotnet_inspect`**: Zero-dependency PE/COFF, CLR metadata, streams, types, methods, and CIL bytecode inspection.
- **`evm_inspect`**: EVM bytecode disassembly, function selector extraction, ERC interface detection, and CBOR metadata parsing.
- **`sourcemap_inspect`**: Offline SourceMap parsing, VLQ coordinate translation, and original source tree extraction.
- **`pcap_inspect`**: Read-only PCAP and PCAPNG header, packet, protocol breakdown, endpoint, conversation, and DNS analysis.
- **`sqlite_inspect`**: Read-only SQLite database inspection (schema, tables, columns, indexes, foreign keys, bounded rows, WAL frames).
- **`firmware_inspect`**: Multi-region firmware blob, flash ROM, uImage, SquashFS/CPIO/TAR container mapping and entropy profiling.
- **`crashdump_inspect`**: Linux ELF core (`ET_CORE`) and Windows Minidump (`MDMP`) diagnostic parser (registers, threads, memory mappings, notes).
- **`binary_diff`**: Deterministic binary diffing with block-level deltas, similarity percentage, and contiguous byte diffs.
- **`binary_metadata_inspect`**: Go runtime build info (`\xff Go buildinf:`) and Rust cargo-auditable (`.dep-v0`) dependency trees.
- **`js_hook_preset`**: Safe, hardened client-side hook templates (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `contextBridge`).
- **`wasm_inspect`**: WebAssembly section enumeration, imports/exports, data segment strings, and keyword search.
- **`reverse_workflow`**: Deterministic target-first workflow orchestration, persistence, and failure recovery.
- **`reverse_runtime_session`**: Unified dynamic session registry across Frida, browser, IDA, and Ghidra.
- **`reverse_dynamic_evidence`**: Dynamic event normalization, hypothesis confirmation, and knowledge promotion.
- **`native_mcp_session`**: Persistent native reverse engineering MCP session manager across x64dbg, Ghidra, and radare2. Handles connection bootstrap, target verification, dynamic upstream tool discovery, safe detachment, and high-precision BigInt runtime-to-static address mapping.
- **`triton_analyze`**: Offline dynamic symbolic execution, taint tracking, MBA expression synthesis, and optional LLVM IR lifting using Python `triton-library`.
- **`vmp_dump`**: Windows x64 process memory dumping and Import Address Table (IAT) reconstruction for VMProtect-packed modules past OEP.
- **`native_devirtualize`**: Function-level x64 PE lifting and devirtualization supporting `mergen` (LLVM IR lifting) and `novmp` (VTIL devirtualization) backends.
- **`dex_unpack`**: Runtime DEX memory extractor recovering packed or dynamically loaded Dalvik executables via `frida-dexdump` or `blackdex`.
- **`dex_repair`**: Offline FART CodeItem restorer reconstructing empty-code stub methods from dumped `.bin` records.
- **`dex_search`**: DEX/APK structural code search engine querying classes, methods, and cross-references via LuckyPray DexKit.
- **`instruction_trace`**: Controlled instruction tracer capturing executed machine instructions, register states, and pre-instruction memory reads via QBDI/Stalker into JSONL/Salwan trace files.
- **`native_recover`**: Bounded multi-path Dynamic Symbolic Execution (DSE) worklist engine for branching machine snapshots, handler semantic extraction, guarded ITE merging, and differential verification.
- **`deobfuscate`**: Pluggable deobfuscation framework supporting `jadx` (jadx-string-decrypt), `d810-ng` (IDA 9+ CFG unflattening), `simplify` (Dalvik VM execution), and `msynth` (MBA expression synthesis).

### Optional External Tools (Catalog-Vetted, Installed On-Demand)
Specialized third-party disassemblers, decompilers, emulators, debuggers, and devirtualizers that provide deep decompilation, process dumping, or symbolic execution (e.g. `jadx`, `apktool`, `unidbg`, `radare2`, `ghidra`, `ida`, `frida`, `mitmproxy`, `tshark`, `triton`, `vmpdump`, `mergen`, `novmp`). They are NOT installed by default; the agent discovers the need, explains the benefit, requests confirmation, and installs them via `reverse setup reverse`.

- **`r2_inspect` vs `ida` vs `frida` Selection Criteria**:
  - **`r2_inspect`**: Rapid, headless binary triage and bounded disassembly windows. Requires `radare2`. Accepts strictly canonical target selectors (`symbol`, `target`, `address`); parameter aliases like `function` are rejected. Defaults to `entry0` only when omitted (`details.referenceDefaulted: true`), and fails truthfully if a requested symbol is missing.
  - **`ida`**: Decompilation and type recovery across 4 distinct backends: IDA GUI desktop application, headless `idalib` SDK (required for virtual reads and the `ida` tool), local database files (`.idb`/`.i64`), and optional MCP bridge (`ida-mcp`). An unconfigured or disconnected MCP bridge does NOT mark the entire IDA install absent when GUI or `idalib` exists.
  - **`frida`**: Dynamic runtime instrumentation, memory inspection, and function trace.
  - **JNI recovery**: Compose DEX native declarations, successful Frida/Unidbg registration events and `jni_enrich` in the existing Ghidra tool/session. Preview symbol and type changes first; keep event provenance, target hash and receiver kind with the binding.
  - **`elf_inspect`**: Use optional LIEF for deep ELF structure queries. Use explicit runtime dump and external SoFixer repair only for memory-unpacked targets; keep original, dump metadata and repaired candidate separate. Dependency setup IDs are `lief` and `sofixer`.
  - **FindCrypt**: Install optional `ghidra-findcrypt` for the selected Ghidra version, invoke `ghidra_inspect(action: "findcrypt")`, and verify constant-match candidates through runtime inputs/outputs.
  - **JNI API trace**: Prefer `jni_register` for method discovery; select bounded `jni_trace` in the existing Frida session when API arguments, return values or missing environment callbacks matter. The reused engine ships with reverse, while Frida remains optional.
  - **No Mandatory Tool Counts**: Reverse workflows never demand arbitrary mandatory counts of external engines or connected MCP servers; built-in zero-dependency tools (`triage`, binutils) serve as sufficient baseline fallbacks on constrained or sandbox hosts.
---

## 3. Discover-Before-Stop / Install-Then-Dispatch Workflow

When an analytical scenario requires a capability that is either uninstalled or needs a specialized external engine, the agent MUST NOT halt, guess installation commands, or fail silently. Instead, follow this mandatory 8-step lifecycle:

```
[Scenario Need] 
       │
       ▼
1. Discover Capability ──> Map scenario to canonical capability ID
       │
       ▼
2. Recommend Tool ───────> Contrast native baseline vs. optional external tool; explain WHY
       │
       ▼
3. Explain Install ──────> State prerequisites, catalog package command, and setup path
       │
       ▼
4. Ask Approval ─────────> Explicit user confirmation gate (NEVER auto-install)
       │
       ├─────────────────────────────────┐
       ▼ (Approved)                      ▼ (Declined / Unavailable)
5. Install via Setup              8. Graceful Fallback
   (`reverse setup reverse <id>`)         (Engage native tool or POSIX baseline
       │                               immediately; maintain progress)
       ▼
6. Verify Availability
   (`reverse setup reverse --json`)
       │
       ▼
7. Dispatch Immediately
   (Execute step with bounded limits)
```

### Step-by-Step Execution Rules

1. **Discover Capability (`发现能力`)**:
   Identify the underlying reverse engineering capability required for the current investigation step (e.g. `android_native_emulation`, `apk_unpacking`, `browser_debugger`, `websocket_capture`, `native_debugger`, `js_deobfuscation`, `traffic_interception`).
2. **Recommend Optional Tool (`推荐工具`)**:
   Examine whether a native tool covers the baseline (e.g., `android_package_inspect` for APK structure). If the task requires specialized capabilities (e.g., full Java source decompilation or host JNI execution), recommend the catalog tool and clearly explain the technical benefit over the baseline.
3. **Explain Installation (`说明安装路径与前提`)**:
   Detail companion prerequisites (e.g., Java JRE 17+ for JADX, JDK 8 for Unidbg) and display the official catalog installation path:
   `reverse setup reverse <tool-id>` (or guided interactive TUI).
4. **Ask User Approval (`请求显式确认`)**:
   Present the structured decision to the operator:
   - Capability: `<capability-name>`
   - Recommended Tool: `<tool-name>`
   - Why: `<technical reason for requiring this tool>`
   - Install Action: `reverse setup reverse <tool-id>` (executes e.g. `brew install <tool>`)
   - Fallback: `<what tool will be used if declined>`
   *Never proceed with installation without operator consent.*
5. **Install via Setup (`通过受信 Setup 安装`)**:
   When approved, guide or run the installation using `reverse setup reverse <tool-id>`.
6. **Verify Availability (`验证可用性`)**:
   Query `reverse setup reverse --json` or check binary detection on PATH. Verify that companion binaries (e.g. `java`) are present.
7. **Dispatch Immediately (`立即分发执行`)**:
   Once verified, immediately execute the planned command with strict bounded limits (e.g., `--single-class`, `-qc`, filtered tags, saving large outputs to `./artifacts/`).
8. **Graceful Fallback (`拒绝时平滑降级`)**:
   If the operator declines, or if the environment cannot satisfy prerequisites (e.g., lack of root/package manager), immediately switch to the fallback tool (native built-in or POSIX baseline). Emit the degradation notice and continue analysis without blocking.

---

## 4. Capability Discovery Contract

The table below defines the canonical mapping between investigative scenarios, capability IDs, native baselines, optional catalog tools, and setup commands:

| Capability ID | Scenario / Analytical Need | Recommended Native Tool | Optional External Tools | Trusted Setup Command | Graceful Fallback Path | Post-Install Canonical Invocation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`android_native_emulation`** | Headless ARM32/ARM64 CPU emulation and JNI invocation of native `.so` crypto algorithms without an Android device | `android_native_workflow` (library inventory & JNI mapping) | `unidbg` | `reverse setup reverse unidbg` | Static Ghidra/r2 decompilation or live device Frida hook | Custom target Java harness (must exist in project; obtain actual invocation from project) |
| **`apk_unpacking`** | Recovering human-readable Java source, smali bytecode, and XML resources from APK/AAB | `android_package_inspect` (container/DEX/manifest/signing) | `jadx`, `apktool` | `reverse setup reverse jadx` / `reverse setup reverse apktool` | `droidasc(op: "getclass")` or `unzip -p <apk> AndroidManifest.xml` | `jadx -d ./artifacts/jadx_out --single-class "<class>" <apk>` / `apktool d <apk> -o ./artifacts/apk_src` |
| **`dex_patching`** | Direct Dalvik bytecode inspection, DEX header validation, and semantic byte patching | `dex_patch` (DEX structure & opcode patching) | `python`, `jadx`, `baksmali` | `reverse setup reverse python` | `droidasc(op: "getclass")` or `dexdump -d` | `dex_patch(action: "inspect" / "validate" / "patch")` |
| **`apk_artifact_generation`** | Container entry diff, archive repackaging, 4-byte/16KiB page alignment, v1-v3 signing | `apk_artifact` (archive repack, align, sign, verify) | `python`, `zipalign`, `apksigner`, `java`, `adb` | `reverse setup reverse apksigner` | `apktool b` + `zipalign` / `unzip` | `apk_artifact(action: "diff" / "repack" / "sign" / "verify")` |
| **`browser_debugger`** | Interactive JS breakpointing, call stack inspection, and runtime scope variable evaluation in web targets | `browser_reverse_session` / `js_hook_preset` | `playwright-mcp` (MCP) | `reverse setup reverse playwright-mcp` | Bounded CDP script evaluation via `browser_reverse_session` | Connect MCP session or attach via CDP debugger |
| **`websocket_capture`** | Capturing and inspecting live WebSocket frames when no offline capture file exists | `websocket_observe` (offline HAR/JSON/NDJSON review) | `mitmproxy`, `tshark` | `reverse setup reverse mitmproxy` / `reverse setup reverse wireshark` | Browser DevTools HAR export + `websocket_observe` | `mitmdump -p 8080 -w ./artifacts/ws_flows.mitm` / `tshark -r <file> -Y websocket` |
| **`native_debugger`** | Dynamic instruction tracing, register inspection, hardware breakpoints, and anti-debug bypass in native binaries | `debug` (DAP) / `triage` (built-in) / `native_mcp_session` | `radare2`, `ghidra` (headless), `ida`, `x64dbg-mcp`, `ghidra-mcp`, `r2mcp` | `reverse setup reverse radare2` / `reverse setup reverse x64dbg-mcp` / `reverse setup reverse ghidra-mcp` / `reverse setup reverse r2mcp` | Static section and xref analysis (`triage`, POSIX `objdump`, `strings`) | `native_mcp_session(action: "connect", service: "ghidra" / "x64dbg" / "radare2", target: "<sample>")` / `debug(action: "launch", program: "<sample>")` / `r2 -d <sample>` |
| **`js_deobfuscation`** | AST restructuring, constant folding, and string un-packing of minified/obfuscated JavaScript bundles | `ast_grep` (structural pattern matching) + `sourcemap_inspect` | `ast-grep` CLI, `webcoder` | `reverse setup reverse ast-grep` | Offline JS parsing script + regex / strings inspection | `ast_grep(pattern: "<template>", path: "<file>")` |
| **`traffic_interception`** | Live HTTPS traffic interception, TLS certificate unpinning, and request/response modification | `pcap_inspect` (offline PCAP) + `curl` | `mitmproxy` (`mitmdump`) | `reverse setup reverse mitmproxy` | Browser Network HAR export or static API endpoint grep | `mitmdump -p 8080 -w ./artifacts/flows.mitm` |
| **`vmp_dump_repair`** | Dumping an already unpacked VMProtect x64 module and rebuilding protected imports on Windows | `vmp_dump` | `vmpdump` | `reverse setup reverse vmpdump --execute` | Debugger memory dump via `native_mcp_session` (x64dbg) or Scylla; manual import fix | `vmp_dump(action: "status")`, then `vmp_dump(action: "dump", pid: <pid>, module_path: <path>, observed_oep: true)` |
| **`native_function_lifting`** | Recovering LLVM IR for an individual obfuscated x64 PE function | `native_devirtualize` | `mergen` | `reverse setup reverse mergen --execute` | Symbolic trace replay (`triton_analyze`) or static disassembly via `r2_inspect` / IDA | `native_devirtualize(action: "status", backend: "mergen")`, then `native_devirtualize(action: "lift", backend: "mergen", path: <pe>, start_address: <va>)` |
| **`vmp_legacy_devirtualization`** | Static devirtualization of unpacked legacy VMProtect 3.0–3.5 x64 routines into VTIL | `native_devirtualize` | `novmp` | `reverse setup reverse novmp --execute` | `native_function_lifting` (Mergen) or `symbolic_trace_analysis` (Triton) | `native_devirtualize(action: "status", backend: "novmp")`, then `native_devirtualize(action: "lift", backend: "novmp", path: <pe>, vms: [<rva>])` |
| **`symbolic_trace_analysis`** | Recovering symbolic input/output relations from captured x86/x64 execution traces | `triton_analyze` | `triton` | `reverse setup reverse triton --execute` | Static section and pattern analysis (`triage`, `r2_inspect`, IDA Pro) | `triton_analyze(action: "status")`, then `triton_analyze(action: "replay", trace: <file>, initial_registers: {...}, symbolic_registers: [...], output: { kind: "register", target: "eax" })` |
| **`dex_runtime_unpacking`** | In-memory extraction of packed DEX from running ART runtime | `dex_unpack` | `frida-dexdump`, `blackdex` | `reverse setup reverse frida-dexdump --execute` | `android_package_inspect` (static) / `dex_repair` | `dex_unpack(action: "status")`, then `dex_unpack(action: "dump", package: <pkg>, device: <dev>)` |
| **`dex_codeitem_repair`** | Offline reconstruction of empty-code stub methods from FART CodeItem records | `dex_repair` | Python runtime; FART records supplied by caller | `reverse setup reverse python --execute` | `dex_patch(dry_run: true)` | `dex_repair(action: "status", path: <dex>)`, then `dex_repair(action: "repair", path: <dex>, records: <bins>, dry_run: false)` |
| **`dex_structural_search`** | High-performance structural query of classes, methods, and cross-references | `dex_search` | `dexkit` | `reverse setup reverse dexkit --execute` | `droidasc(op: "getclass")` / `android_package_inspect` | `dex_search(target: <apk>, type: "method", using_strings: [...])` |
| **`instruction_trace_capture`** | Controlled instruction execution tracing with synchronized register and memory access | `instruction_trace` | `qbdi`, `frida` | `reverse setup reverse qbdi --execute` | `frida` / `frida_session` / `triage` | `instruction_trace(action: "status")`, then `instruction_trace(action: "capture", process: <proc>, module: <mod>, function: <fn>)` |
| **`native_path_recovery`** | Bounded multi-path DSE exploration, handler extraction, guarded ITE merge, and differential verification | `native_recover` | `triton` | `reverse setup reverse triton --execute` | `triton_analyze` / `r2_inspect` | `native_recover(action: "status")`, then `native_recover(action: "explore" / "handlers" / "merge" / "verify", ...)` |
| **`native_cfg_deobfuscation`** | Control-flow unflattening, opaque predicate removal, and OLLVM normalization | `deobfuscate(backend: "d810-ng")` | `d810-ng`, `ida` | `reverse setup reverse d810-ng --execute` | `r2_inspect` / `ghidra_inspect` / `triage` | `deobfuscate(action: "status", backend: "d810-ng")`, then `deobfuscate(action: "analyze", backend: "d810-ng", path: <bin>, function: <addr>)` |
| **`mba_simplification`** | Mixed Boolean-Arithmetic (MBA) algebraic expression synthesis and SMT equivalence checking | `deobfuscate(backend: "msynth")` | `msynth` | `reverse setup reverse msynth --execute` | `triton_analyze(synthesize: true)` / `r2_inspect` | `deobfuscate(action: "status", backend: "msynth")`, then `deobfuscate(action: "analyze", backend: "msynth", expression: <expr>, bit_width: 32)` |
| **`bytecode_deobfuscation`** | Dalvik bytecode deobfuscation, string decryption, and reflection unrolling | `deobfuscate(backend: "jadx")` | `jadx` (`jadx-string-decrypt`), `simplify` | `reverse setup reverse jadx-string-decrypt --execute` | `android_package_inspect` / `dex_patch` | `deobfuscate(action: "status", backend: "jadx")`, then `deobfuscate(action: "analyze", backend: "jadx", path: <apk>)` |

---

## 5. Model-Usable Setup Output Schema

When the agent or operator executes `reverse setup reverse --json`, the output conforms to a machine-readable schema designed for structured reasoning:

```json
{
  "capabilities": [
    {
      "id": "android_native_emulation",
      "name": "Android Native JNI Emulation",
      "scenario": "Emulating ARM32/ARM64 native shared libraries and JNI functions headlessly",
      "ready": false,
      "recommendedNativeTool": "android_native_workflow",
      "optionalExternalTools": ["unidbg"],
      "why": "Executes cryptographic JNI functions without requiring an Android phone or emulator",
      "prerequisites": ["java"],
      "setupCommand": "reverse setup reverse unidbg",
      "fallbacks": ["android_native_workflow", "ghidra_inspect", "r2_inspect"],
      "nextInvocation": "Custom target Java harness (must exist in project; obtain actual invocation from project)"
    }
  ],
  "tools": [
    {
      "id": "jadx",
      "name": "Jadx Decompiler",
      "ready": true,
      "binary": "/opt/homebrew/bin/jadx",
      "installCommands": {
        "darwin": [{"manager": "brew", "command": "brew install jadx", "argv": ["brew", "install", "jadx"]}]
      },
      "usage": {
        "canonical": "jadx -d ./artifacts/jadx_out --single-class <class> <apk>",
        "outputLimits": "Always use --single-class to protect token budget"
      }
    }
  ]
}
```

### Model Decision Policy on Setup Output
- If `ready: true`: dispatch the canonical command immediately.
- If `ready: false`:
  1. Evaluate if `recommendedNativeTool` can achieve the analytical goal. If yes, run the native tool immediately.
  2. If the user goal requires the external tool, formulate the approval prompt citing `why`, `prerequisites`, and `setupCommand`.
  3. If declined, invoke the first ready tool in `fallbacks`.

---

## 6. Output Discipline & Context Budget

Every tool call consumes context tokens. Follow these three rules:
1. **Metadata & Symbol First**: Never dump full files or decompilation trees into context. Query class lists, exported symbols, or string tables first.
2. **Bounded Invocations**: Use single-target arguments (`jadx --single-class`, `r2 pd 40 @ <sym>`, `websocket_observe list --limit 20`).
3. **Artifact Isolation**: Direct bulk outputs (full decompilations, packet flows, dumps) to `./artifacts/` and reference the specific line number, symbol, or hex offset in evidence.

---

## 7. References

- `skill://reverse-tool-guide/references/cli-tools.md`: Canonical operations, bounds, and fallbacks for external CLI tools.
- `skill://reverse-tool-guide/references/mcp-services.md`: MCP helper services, configuration snippets, and persistent session lifecycles.
- `skill://reverse-lab/references/tool-fallback.md`: Complete degradation matrices and notice formats.

