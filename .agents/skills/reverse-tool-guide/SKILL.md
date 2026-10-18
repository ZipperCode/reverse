---
name: reverse-tool-guide
description: Canonical usage guide for rea's reverse-engineering CLI tools and optional MCP helper services. Read before choosing a tool, running an unfamiliar operation, or wiring an MCP server, so commands, prerequisites, output limits, and fallbacks come from the trusted catalog instead of guesswork.
---

# Reverse Tool Guide

This skill is the on-demand operating manual for the external tools that `reverse-lab` may hand off to. It complements the native tools (`droidasc`, `adb_observe`, `websocket_observe`, `wasm_inspect`, `ast_grep`, `read-binary`, browser relay) rather than replacing their own tool prompts.

Read this skill when you need to:

- decide which CLI tool or MCP service fits an analysis step;
- run a tool whose flags you do not remember;
- explain why a tool is unavailable and what to use instead;
- add or review an MCP helper-service configuration.

## 1. Trusted sources

| Question | Canonical source |
| :--- | :--- |
| Is a tool or service present? | `rva setup reverse --json` |
| What install command is allowed? | the same JSON `tools[]` / `services[]` entries |
| What does a skill require? | `rva skill check --json` |
| Which native tool to use? | the tool's own prompt under `docs/tools/` and `packages/coding-agent/src/prompts/tools/` |

The setup JSON is authoritative for availability. Do not infer installation from a package name, and do not invent an installation argv: only entries from the trusted catalog may be executed, and only after explicit confirmation in the setup panel.

## 2. Choosing a tier

1. Prefer a native tool when it already covers the question: `android_package_inspect` for native Android APK/AAB/DEX container, manifest, DEX headers, signing schemes, and resource inspection, `droidasc` for DEX/manifest, `adb_observe` for read-only device state and screenshots, `frida` for open dynamic script execution, hooks, spawn/attach, process/module listing, and trace observation, `frida_session` for persistent multi-turn dynamic analysis sessions with stateful child and target management, `websocket_observe` for offline WebSocket captures, `windows_observe` for offline Windows API / ETW / API Monitor captures, `dotnet_inspect` for native .NET assembly and CIL bytecode inspection, `ghidra_inspect` for Ghidra headless analysis and decompilation, `r2_inspect` for radare2 inspection, `wasm_inspect` for WebAssembly, `javascript_application` for Electron/ASAR and JavaScript applications, `sourcemap_inspect` for SourceMap inspection and recovery, `js_hook_preset` for JavaScript hook preset generation, `ast_grep` for JavaScript/TypeScript patterns, `pcap_inspect` for offline PCAP and PCAPNG network capture analysis, `sqlite_inspect` for offline read-only SQLite schema, rows, and WAL inspection, `firmware_inspect` for offline firmware, partition, container, and entropy inspection, `crashdump_inspect` for offline ELF core and Windows Minidump crash analysis, `binary_metadata_inspect` for Go and Rust binary metadata inspection, `evm_inspect` for offline EVM bytecode disassembly and function selector extraction, `binary_diff` for deterministic binary diffing, `reverse_workflow` for orchestrating target-routed tool execution plans with evidence linking and failure recovery metadata, `reverse_runtime_session` for unified reverse runtime session registry across Frida, browser, IDA, and Ghidra, `read-binary` for IDA-backed binaries.
2. Prefer a CLI tool for one-shot, bounded queries: `r2`, `jadx`, `apktool`, `strings`, `file`, `mitmdump`.
3. Use an MCP service only when persistent session state is the point: repeated seeks/xrefs (`r2mcp`), interactive decompilation (`ida-mcp`, `pyghidra-mcp`), scripted instrumentation (`frida-mcp`), browser state (`playwright-mcp`).
4. When the preferred tier is absent, follow the fallback in the matching reference instead of stopping the analysis.

**WebSocket frame review.** `websocket_observe` reads an existing HAR, structured JSON capture, or CDP `Network.webSocket*` NDJSON file. `inspect` summarizes connections/opcodes/time range; `list`/`search` page frames with `url`, `direction`, `opcode`, `filter`, and `regex`; `export` writes sanitized JSON or NDJSON to an artifact. Previews are bounded and credentials are redacted. The tool is offline and read-only: it never records live traffic, connects to a target, replays frames, or executes scripts. Produce the capture first with the browser relay or an authorized proxy (`mitmdump`), and perform any authorized replay separately with `curl` or a purpose-built client.

**Windows API trace review.** `windows_observe` reads an existing ETW, API Monitor, or structured JSON/NDJSON capture file. `inspect` summarizes processes, modules, API categories, and time range; `list`/`search` page API call events with `pid`, `module`, `api`, `category`, `start_time`, `end_time`, `filter`, and `regex`; `export` writes sanitized JSON or NDJSON to an artifact. Parameters are summarized and credentials/tokens are redacted. The tool is offline and read-only: it never injects into or controls processes, executes scripts or commands, replays API calls, or connects to remote paths. Produce the capture first using API Monitor, Procmon, or ETW tracing in an authorized environment.

**PCAP / PCAPNG packet capture review.** `pcap_inspect` reads an existing `.pcap` or `.pcapng` file. `info` summarizes capture format, duration, packet count, protocol breakdown, and top endpoints; `list` pages packets with `protocol`, `ip`, `port`, and `packet_number`; `endpoints` aggregates traffic stats; `conversations` groups 2-party bidirectional flows; `dns` decodes queries and responses. The tool is offline and read-only: it never captures live packets, replays traffic, or binds to network interfaces.

**SQLite database review.** `sqlite_inspect` reads an existing `.db`, `.sqlite`, or `.sqlite3` file. `info` inspects format version, page size, encoding, journal mode, and entity counts; `tables` lists all tables and views; `schema` inspects DDL, columns, indexes, and foreign keys; `rows` reads bounded table rows with column and sort options; `wal` decodes WAL headers and frame counts. The tool is offline and strictly read-only: it never modifies databases, executes arbitrary SQL, or accepts write queries.

**Firmware image review.** `firmware_inspect` reads an existing firmware blob, flash ROM, or container file (`.bin`, `.rom`, `.img`, `.uImage`, `.squashfs`). `info` summarizes format, size, SHA-256/MD5 hashes, overall entropy, and detected regions; `regions` catalogs embedded superblocks, bootloaders (uImage), filesystems (SquashFS, CPIO, TAR, ZIP, CramFS, JFFS2), and compressed streams with exact offsets and entropy; `entries` inventories files inside embedded archives without extraction; `entropy` maps block-by-block Shannon entropy to detect encrypted or compressed stages. The tool is offline and read-only: it never writes extracted files to disk or executes shell carvers.

**Crash dump & core file review.** `crashdump_inspect` reads an existing crash dump file (`.dmp`, `.dump`, `core`, `core.*`). `info` identifies dump format (Linux ELF Core ET_CORE, Windows Minidump MDMP, Mach-O Core MH_CORE), architecture, OS, termination signal / exception code, faulting thread ID, and instruction pointer; `threads` enumerates all threads with IP, SP, FP pointers and fault status; `mappings` catalogs loaded modules and virtual memory ranges with permissions; `registers` dumps general-purpose CPU registers; `notes` lists raw ELF note segments or Minidump streams. Non-crash binaries safely return structured unsupported status. The tool is offline and read-only: it never launches GDB, LLDB, or debuggers.

**Go & Rust binary metadata review.** `binary_metadata_inspect` reads an existing executable (`ELF`, `PE`, `Mach-O`, or raw binary). `info` summarizes binary format, architecture, compiler family, Go runtime version, main module path, and Rust cargo-auditable status; `go` inspects compiled Go dependencies (`dep`), module paths, and build settings (`CGO_ENABLED`, `vcs.revision`); `rust` decodes embedded cargo dependency graphs from `.dep-v0`, rustc commit hashes, panic handler markers, and allocator heuristics; `sections` highlights binary section layouts and runtime markers without execution.

**Smart contract EVM bytecode review.** `evm_inspect` reads EVM bytecode from a raw hex string (`code`) or local file (`path`). `info` classifies runtime vs deployment bytecode, detects proxy patterns (ERC-1167 Minimal Proxy, EIP-1967 Transparent/UUPS), and lists detected interface standards; `disasm` performs bounded opcode disassembly with decoded push values; `selectors` extracts 4-byte Solidity dispatcher function selectors and maps them to standard ERC interfaces (ERC-20, ERC-721, ERC-1155, Ownable); `metadata` decodes CBOR compiler metadata (solc version, IPFS/bzzr hash) offline without RPC calls.

**Binary diff & patch review.** `binary_diff` compares two local binary files (`path_a`, `path_b`). `summary` computes deterministic SHA-256 and MD5 hashes, byte size delta, percentage similarity, and total differing bytes; `blocks` segments files into configurable chunks to locate changed, inserted, and deleted blocks; `bytes` extracts contiguous differing byte spans with hex and printable ASCII representation; `headers` compares parsed executable headers side-by-side without patching.

**Workflow orchestration.** `reverse_workflow` coordinates multi-step investigations across PE, ELF, Mach-O, APK, JS, WASM, PCAP, and SQLite targets without executing arbitrary commands. `create` initializes a target-routed workflow plan; `plan` previews deterministic tool sequences; `status` inspects step progress, attempt metrics, and linked evidence IDs; `record` saves step status, outputs, artifact refs, and verified evidence ledger IDs; `retry` recovers structured failed steps with bounded attempts and caller-provided parameters; `export` generates bounded Markdown or JSON reports; `destroy` removes workflow state.

**Runtime session registry.** `reverse_runtime_session` manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans across Frida, browser, IDA, and Ghidra without unsafe arbitrary process control. `register` saves sanitized target and connection details; `list` enumerates active and stale sessions; `status` performs safe opt-in metadata probes or records caller facts; `heartbeat` refreshes active state; `restore` formulates deterministic tool restore plans; `unregister` cleans up session records.

## 3. Output discipline

Every tool call spends context. Keep the first pass at metadata or symbol level, then read only the function, class, packet, or range that answers the question. Write bulk output (decompilation trees, full traces, flow files) to `./artifacts/` and cite the path plus the exact offset/symbol/line in the conclusion.

## 4. References

- `skill://reverse-tool-guide/references/cli-tools.md` — canonical commands, limits, and fallbacks for the CLI toolchain.
- `skill://reverse-tool-guide/references/mcp-services.md` — MCP helper services, prerequisites, launch commands, config snippets, and canonical operations.

## 5. MCP boundary

MCP helper services are **not PATH binaries**. Readiness means their prerequisite CLI tools were found; it does not mean the server is configured or running. `rva setup reverse --json` also reports whether an `mcpServers` entry exists (`configured`, `configuredScopes`, `enabled`) but never verifies a connection (`connection: "unknown"`). Configuration lives in `.rva/mcp.json` (project) or the resolved user `mcp.json` (`~/.rva/agent/mcp.json` by default), and the server is launched by the MCP client. Skills and servers never inject executable argv into the installation path.
