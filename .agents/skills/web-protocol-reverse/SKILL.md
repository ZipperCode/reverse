---
name: web-protocol-reverse
description: Web frontend bundle, JavaScript deobfuscation, WebAssembly, and network API protocol reverse engineering specialist. Focuses on search-first bundle exploration, SourceMap recovery, and network protocol replay.
metadata:
  requiresOptional: ast-grep, wabt
---

# Web & Protocol Forensics Specialist

`web-protocol-reverse` is the specialized domain skill for auditing Web frontend applications, obfuscated JavaScript bundles, WebAssembly modules, and network API communication protocols.

For full multi-platform routing, consult `skill://reverse-lab/SKILL.md`.

---

## 1. Operating Contract & Evidence Standards

- **Scope & Environment**: Operators MUST execute dynamic analysis, request replay, and CDP console hooks exclusively against explicitly authorized staging domains, local loopback services, or designated test applications.
- **Immutability & Artifact Isolation**: Operators MUST preserve original production bundles strictly read-only. Recovered source trees, AST queries, and protocol replay logs MUST be saved to separate dedicated artifact paths (`./artifacts/`).
- **Search-First Discipline**: Operators SHOULD apply search-first keyword filtering before loading minified assets to preserve token budget. Full multi-megabyte bundle dumps MUST NEVER be submitted into conversation context.
- **Evidence Precision**: Findings MUST cite reproducible locations:
  - Normalized URL endpoint, HTTP method, and exact parameter payload schema
  - Original source path and line number recovered from SourceMap
  - AST pattern match or verbatim token offset in bundle
  - WebAssembly exported function symbol or WAT instruction sequence

Read `skill://reverse-lab/references/evidence.md` for report schemas.

---

## 2. Toolchain & Dependencies

- **POSIX Baseline (`grep`, `curl`, `node`)**: Standard tools for string extraction, bundle splitting, and standalone protocol replay.
- **Structural Syntax Search (`ast_grep`)**: Native built-in. Matches AST code patterns across minified JavaScript regardless of variable renaming. No external CLI is required; the optional `ast-grep` CLI remains a fallback.
- **SourceMap Inspection & Recovery (`sourcemap_inspect`)**: Native built-in. Decodes Base64 VLQ mappings, resolves minified bundle positions to original file/line/column/symbol names, inspects embedded `sourcesContent`, and extracts original source files without external dependencies.
- **JS Hook Preset Generation (`js_hook_preset`)**: Native built-in. Generates bounded, non-executing hook templates (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, `custom`) for authorized browser, Electron, or Node runtime tracing.
- **WebAssembly Inspection (`wasm_inspect`)**: Native built-in. Reports sections, imports/exports, function names, data/custom strings, and bounded byte matches without external tools. The optional `wabt` toolkit (`wasm2wat`) is only needed for full WAT disassembly.
- **WebSocket Capture Analysis (`websocket_observe`)**: Native read-only built-in. Parses an existing HAR, structured JSON capture, or CDP `Network.webSocket*` NDJSON file and offers `inspect`, paged `list`/`search`, and sanitized `export`. It never records live traffic, connects to a target, replays frames, or runs scripts; obtain the capture with the browser relay or an authorized proxy first.
- **Browser Relay / CDP**: Captures authorized live traffic into HAR/NDJSON and evaluates console state. Hand the resulting file to `websocket_observe` for offline frame review, and keep the original capture read-only.
- **PCAP / PCAPNG Network Analysis (`pcap_inspect`)**: Native built-in. Zero-dependency offline analysis of network packet captures: packet lists, protocol breakdowns (TCP, UDP, TLS with SNI, HTTP, DNS, ICMP, ARP), IP endpoints, conversations, and DNS queries without live packet capture or network replay.
- **SQLite Database Inspection (`sqlite_inspect`)**: Native built-in. Zero-dependency offline read-only database analysis: schema, tables, columns, indexes, foreign keys, bounded table rows, and WAL metadata without mutation or arbitrary SQL execution.

---

## 3. Recommended Workflow

1. **Search-First Keyword Reconnaissance**:
   - Locate endpoints, headers, and crypto primitives with targeted regex before reading code:
     `grep -E -o -n "https?://[^\"'\` ]+|/api/v[0-9]/[a-zA-Z0-9_/]+" bundle.js`
2. **SourceMap Recovery & Source Reconstruction**:
   - Use `sourcemap_inspect(action: "info", path: "...")` to inspect map metadata and embedded `sourcesContent`.
   - Use `sourcemap_inspect(action: "lookup", ...)` to map minified bundle coordinates back to original source lines and symbol names.
   - Use `sourcemap_inspect(action: "extract", ...)` to unpack embedded original source files.
3. **Runtime Instrumentation & Hook Templates**:
   - Generate safe, non-executing hook presets with `js_hook_preset(action: "generate", preset: "...")` for `fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, or Electron `contextBridge`.
4. **WebAssembly Deconstruction**:
   - Start with `wasm_inspect(action: "info")` for imports, exports, signatures, and name-section functions; use `strings` and `search` before requesting WAT.
   - Use `wasm_inspect(action: "wat")` when `wabt` is installed, or `wasm2wat module.wasm -o module.wat` directly, and analyze exported crypto routines.
5. **Protocol Capture & Frame Analysis (Authorized Targets Only)**:
   - Record WebSocket traffic to a HAR or CDP NDJSON file with the browser relay or an authorized proxy; keep the original capture read-only.
   - Start with `websocket_observe(action: "inspect", path: "...")` for connections, opcodes, direction counts, and time range.
   - Use `list`/`search` with `url`, `direction`, `opcode`, `filter`, and `regex` to isolate the handshake, subscribe, or signing frames; payload previews are bounded and credentials are redacted.
   - Use `export` with `export_format: "ndjson"` when full redacted payloads are needed, then cite the artifact id and frame index.
6. **Protocol Verification & Replay (Authorized Targets Only)**:
   - Replay captured requests with exact headers and signatures via `curl` against authorized endpoints to verify parameter validation behavior, saving response traces to `./artifacts/`.
   - `websocket_observe` itself is analysis-only: it never connects or replays; any live replay is a separate, explicitly authorized step.

7. **Network Capture Forensics**:
   - Use `pcap_inspect(action: "info", path: "...")` for capture metadata, duration, and protocol breakdown.
   - Use `pcap_inspect(action: "list", ...)` with `protocol`, `ip`, or `port` filters to inspect traffic.
   - Use `pcap_inspect(action: "endpoints", ...)` and `conversations` to isolate high-volume talkers and hosts.
   - Use `pcap_inspect(action: "dns", ...)` to extract domain resolution queries and answers.
8. **Storage & Local State Forensics**:
   - Use `sqlite_inspect(action: "info", path: "...")` to inspect headers, storage parameters, and WAL status.
   - Use `sqlite_inspect(action: "schema", path: "...")` to map database structure, columns, and foreign keys.
   - Use `sqlite_inspect(action: "rows", path: "...", table: "...")` to inspect bounded records safely without arbitrary SQL or write operations.
Read `skill://reverse-lab/references/web-protocol.md` for complete technical walkthroughs.
