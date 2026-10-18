# Tool Fallback & Graceful Degradation Guide

This reference defines the degradation ladders, tool detection mechanisms, and installation hints for the `reverse-lab` toolchain. When an advanced analysis tool is unavailable, `rea` degrades smoothly to available alternatives without blocking progress.

---

## 1. Degradation Principles

1. **Zero-Friction When Ready**: If the primary tool is installed, proceed silently without prompting or emitting environment checks.
2. **Actionable Non-Blocking Degradation**: When a tool is missing, select the next tier on the ladder, notify the operator with the active fallback, and provide a single clean package-manager installation hint.
3. **Maintain Continuous Progress**: When specialized disassemblers are missing, basic POSIX utilities (`strings`, `file`, `unzip`, `hexdump`, `grep`, `xxd`) can extract significant findings from strings, manifests, and file headers.

---

## 2. Tool Degradation Matrix

| Analysis Domain | Tier 1 (Primary) | Tier 2 (Secondary) | Tier 3 (Tertiary) | Tier 4 (POSIX Baseline) |
| :--- | :--- | :--- | :--- | :--- |
| **Android Recon** | native `android_package_inspect` / `droidasc getmanifest` | `aapt2 dump badging` | `apktool d -s` (manifest only) | `unzip -p <apk> AndroidManifest.xml` (AXML) |
| **Android DEX & Package** | native `android_package_inspect` (info/dex/manifest/signing/resources) | `droidasc getclass` / `findrefs` | `jadx --single-class` | `dexdump -d <dex>` / `unzip` |
| **Android Dynamic** | `frida_session` / `frida -U` (live hooks) | `adb logcat` / `jdwp` | Static smali patch + rebuild | Offline logic trace in smali |
| **Native ELF / Mach-O / PE** | `triage` (built-in) + rea `read-binary` (IDA Pro) | `dotnet_inspect` (built-in .NET) / `ghidra_inspect` / `r2_inspect` (`radare2`) | `objdump -d` / `llvm-objdump` / `readelf` | `strings -a -n 8` + `xxd` / `hexdump` |
| **Web JS Search** | native `ast_grep` (AST pattern) | `ast-grep` CLI | `grep` / ripgrep | Python/JS custom parser |
| **Web SourceMap** | native `sourcemap_inspect` (`info`/`lookup`/`extract`) | `source-map` CLI | `jq` on `.sourcesContent` / base64 | manual VLQ / raw bundle inspection |
| **Web JS Hooking** | native `js_hook_preset` (safe templates) | DevTools snippet / Tampermonkey | browser-relay console eval | manual function wrapping |
| **WebAssembly** | native `wasm_inspect` (`info`/`strings`/`search`) | `wasm_inspect` `wat` / `wasm2wat` (WABT) | `wasm-objdump` | `strings` on WASM data segments / raw bytes |
| **Web Dynamic** | `browser-relay` / CDP | Headless Playwright / Puppeteer | `curl -v` / `fetch` script | Static network trace inspection |
| **Network & PCAP** | native `pcap_inspect` (info/list/endpoints/dns) | `tshark -r <pcap>` / `tcpdump -r` | `mitmdump` / `wireshark` | strings / xxd on raw pcap |
| **Database & SQLite** | native `sqlite_inspect` (info/schema/rows/wal) | `sqlite3 -readonly <db>` CLI | Python `sqlite3` script | strings / grep on db file |
| **Firmware & ROMs** | native `firmware_inspect` (info/regions/entries/entropy) | `binwalk -B <firmware>` | `7z l` / `unsquashfs -s` | strings / xxd on raw image |
| **Crash & Core Dumps** | native `crashdump_inspect` (info/threads/mappings/registers/notes) | `gdb --core <dump>` / `lldb -c <dump>` | `readelf -n <core>` | strings on dump |
| **Go/Rust Metadata** | native `binary_metadata_inspect` (info/go/rust/sections) | `go version -m` / `cargo auditable` | `readelf -p .dep-v0` / `objdump` | strings / grep on binary |
| **Smart Contracts / EVM** | native `evm_inspect` (info/disasm/selectors/metadata) | `cast disasm` / `hevm` | `pyevmasm` / python disasm | raw hex / manual opcode lookup |
| **Binary Diffing** | native `binary_diff` (summary/blocks/bytes/headers) | `vbindiff <f1> <f2>` / `radiff2` | `cmp -l <f1> <f2>` | `diff` / `xxd` + diff |
| **Workflow Orchestration** | native `reverse_workflow` (create/plan/status/record/retry/recover/retry_plan/export) | structured subagent delegation | manual toolchain chaining | one-off CLI execution |
| **Runtime Session Registry** | native `reverse_runtime_session` (register/list/status/restore/unregister/heartbeat) | tool-native session status (`frida_session`, `browser tabs`, `ida list`) | process inspection (`ps`, `jps`) | manual re-connection |

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
  - Automatically verified via rea's native `locateIdaInstall`. When absent, fallback directly to `radare2`.
### 3. Web & WASM Toolchain
- **Native built-ins**: `ast_grep`, `wasm_inspect`, `javascript_application`, `sourcemap_inspect`, and `js_hook_preset` require no installation.
  - Use `sourcemap_inspect` for zero-prep inspection of `.map` files or inline `sourceMappingURL`, VLQ coordinate lookup, and recovering original source trees.
  - Use `js_hook_preset` to generate safe runtime hook templates for fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, or custom targets.
  - Use `javascript_application` for zero-prep analysis of Electron `.asar` files or packaged JS/Node projects (extracts package metadata, process roles, IPC channels, and native addons).
  - Use `wasm_inspect` `info`, `strings`, and `search` before reaching for external WAT tooling.
- **`wabt`** (`wasm2wat`, `wat2wasm`) — optional, only needed for full WAT output:
  - macOS: `brew install wabt`
  - Linux: `apt install wabt`
  - Windows: `choco install wabt`
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

### 5. Firmware & Post-Mortem Toolchain
- **`firmware_inspect`** (Built-in tool): Zero-dependency native offline firmware inspection. Detects uImage, SquashFS, CPIO, TAR, ZIP, FIT/DTB, CramFS, JFFS2 headers, partition boundaries, Shannon entropy, and archive inventories without file extraction or execution. Always available.
- **`crashdump_inspect`** (Built-in tool): Zero-dependency native offline crash dump analysis. Parses Linux ELF core dumps (`ET_CORE`) and Windows Minidumps (`MDMP`), decoding registers, termination signals, exception codes, faulting thread/IP, loaded modules, and note segments. Always available.
- **`binwalk`** (CLI firmware analysis and extraction carver):
  - macOS: `brew install binwalk`
  - Linux: `apt install binwalk`
  - Windows: `pip install binwalk`

### 6. Go/Rust Metadata, EVM & Binary Diff Toolchain
- **`binary_metadata_inspect`** (Built-in tool): Zero-dependency native offline Go runtime build info (`\xff Go buildinf:`, module dependencies, flags) and Rust `cargo-auditable` (`.dep-v0`, rustc commit/version, panic strategy, allocator) inspection. Always available.
- **`evm_inspect`** (Built-in tool): Zero-dependency native offline Ethereum Virtual Machine bytecode disassembler, function selector dispatcher extractor, proxy pattern detector, and CBOR compiler metadata parser. Always available.
- **`binary_diff`** (Built-in tool): Zero-dependency native offline deterministic binary diffing tool with SHA-256/MD5 hashing, block-level delta, similarity scoring, and byte-level diff regions. Always available.
- **`vbindiff`** (Visual binary diff):
  - macOS: `brew install vbindiff`
  - Linux: `apt install vbindiff`
  - Windows: `choco install vbindiff`
- **`cast`** (Foundry EVM CLI):
  - All Platforms: `curl -L https://foundry.paradigm.xyz | bash && foundryup`

### 7. Workflow Orchestration Toolchain
- **`reverse_workflow`** (Built-in tool): Zero-dependency native offline workflow orchestrator with target-first routing (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite), state store persistence, verified cross-tool evidence association, deterministic failure attribution, and bounded fallback recovery without arbitrary command execution. Always available.

### 8. Runtime Session Registry
- **`reverse_runtime_session`** (Built-in tool): Zero-dependency native unified reverse runtime session registry across Frida, browser, IDA, and Ghidra. Manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans without unsafe arbitrary process control. Always available.
---

## 4. Operator Degradation Notice Format

When a preferred tool is missing and a fallback is engaged, notify the operator using this concise format:

```text
[Notice] Primary tool '<missing-tool>' not found on PATH.
  -> Engaged fallback: '<fallback-tool>'
  -> Hint to restore primary capability: <install-command>
```

**Example in practice**:
```text
[Notice] Primary tool 'jadx' not found on PATH.
  -> Engaged fallback: 'droidasc' (on-demand DEX query)
  -> Hint to restore primary capability: brew install jadx
```

After emitting the notice, continue immediately with the fallback tool to ensure the analysis completes without delay.
