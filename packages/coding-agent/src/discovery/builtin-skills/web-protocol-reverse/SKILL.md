---
name: web-protocol-reverse
description: Web frontend bundle, JavaScript deobfuscation, WebAssembly, and network API protocol reverse engineering specialist. Focuses on search-first bundle exploration, SourceMap recovery, and network protocol replay.
metadata:
  requiresOptional: ast-grep, wabt, mitmproxy, hbctool, tshark
  capabilities: browser_debugger, websocket_capture, js_deobfuscation, traffic_interception
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
- **jshook MCP Service (`jshookmcp`)**: OPTIONAL independent local service for stateful browser debugging, script collection, deobfuscation with `webcrack`, protocol experiments, and WASM workflows. Install through `reverse setup reverse jshookmcp --execute` or, with user authorization, `reverse_capability(action: "install", service: "jshookmcp")`. Setup verifies the MCP handshake and writes configuration; agent/TUI installation also connects tools in the current session. Use `search_tools` → `describe_tool` → `call_tool`, with one browser controller per target.
- **Playwright MCP Service (`playwright-mcp`)**: OPTIONAL (MCP Service). Automated multi-session browser control and DOM inspection for authorized dynamic web analysis. Configured as an MCP service via capability resolver (`browser_debugger`) rather than CLI PATH dependencies.
- **PCAP / PCAPNG Network Analysis (`pcap_inspect`)**: Native built-in. Zero-dependency offline analysis of network packet captures: packet lists, protocol breakdowns (TCP, UDP, TLS with SNI, HTTP, DNS, ICMP, ARP), IP endpoints, conversations, and DNS queries without live packet capture or network replay.
- **SQLite Database Inspection (`sqlite_inspect`)**: Native built-in. Zero-dependency offline read-only database analysis: schema, tables, columns, indexes, foreign keys, bounded table rows, and WAL metadata without mutation or arbitrary SQL execution.

### Canonical Capability Mapping

| Canonical Capability ID | Analytical Scenario | Recommended Native Tool | Optional External Tools | Trusted Setup Command | Fallback Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`browser_debugger`** | Dynamic Web application inspection, DOM inspection, script debugging, source-map recovery, and automated CDP control | `browser_reverse_session` / `js_hook_preset` (native) | `jshookmcp`, `playwright-mcp` (MCP), `node` | `reverse setup reverse jshookmcp --execute` | `curl`, `file` |
| **`websocket_capture`** | Intercept, monitor, record, decode, and analyze WebSocket frames and bidirectional streaming protocols | `websocket_observe` (native offline) | `mitmproxy`, `tshark` | `reverse setup reverse mitmproxy` | `pcap_inspect`, `strings`, `curl` |
| **`js_deobfuscation`** | De-obfuscate minified/packed JavaScript, reconstruct AST, recover source maps, disassemble React Native Hermes bytecode | `sourcemap_inspect` / `ast_grep` (native) | `jshookmcp`, `hbctool`, `node`, `ast-grep` | `reverse setup reverse jshookmcp --execute` (`hbctool` for Hermes) | `strings`, `file` |
| **`traffic_interception`** | Transparent network proxying, SSL/TLS decryption, request/response tampering, and API endpoint mapping | `pcap_inspect` (native offline) / `curl` | `mitmproxy`, `tshark` | `reverse setup reverse mitmproxy` | `curl`, `strings` |

### Capability Resolution Protocol

When dynamic instrumentation, live proxying, automated browser orchestration, or Hermes decompilation is needed, execute the Discover-Before-Stop / Install-Then-Dispatch lifecycle via `reverse_capability`:

1. **Resolve Capability (`reverse_capability`)**:
   Query availability before tool dispatch or declaring a blocker:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>" })
   ```
2. **Evaluate Native Baseline First**:
   Inspect `recommendedNativeTool` and readiness `status` in the resolution payload. Prioritize zero-prep native built-ins first:
   - For `browser_debugger`: Use native `browser_reverse_session` and `js_hook_preset` for direct in-process CDP evaluation and hook template generation.
   - For `websocket_capture`: Use native `websocket_observe` for zero-prep offline analysis of pre-captured HAR or CDP NDJSON frames.
   - For `js_deobfuscation`: Use native `sourcemap_inspect` for decoding/extracting source maps and `ast_grep` for structural AST pattern matching across minified JS.
   - For `traffic_interception`: Use native `pcap_inspect` for offline packet analysis and `curl` for bounded endpoint replays.
3. **Present Setup Notice & Request Approval**:
   When an external engine is required (e.g. `jshookmcp` for browser debugging or JavaScript deobfuscation, `mitmproxy` for live SSL decryption and proxying, or `hbctool` for React Native Hermes bytecode disassembly), present the structured notice:
   ```text
   [Capability Notice] Required capability: <capability_id> ('<capability_name>')
     -> Recommended tool: '<tool>' (Status: <missing|installed>)
     -> Why: <why>
     -> Prerequisites: <prerequisites or none>
     -> Trusted setup: <setupCommand> (Requires operator approval)
     -> Post-install invocation: <postInstallInvocation>
     -> Fallback if declined: '<fallback_tool>'
   ```
   Obtain operator authorization before installation. For jshookmcp, the agent can execute `reverse_capability(action: "install", service: "jshookmcp")` through the write approval boundary; the CLI/TUI setup path offers interactive confirmation.
4. **Re-Resolve Post-Install**:
   After the operator executes the trusted setup command (`reverse setup reverse <tool>`), verify readiness:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>", refresh: true })
   ```
   For CLI tools, confirm PATH readiness. For MCP services, confirm managed installation, configuration, enablement, and a live connection; Node alone is insufficient.
5. **Dispatch & Workflow Resumption / Audit**:
   - Dispatch the tool command using bounded options or canonical `postInstallInvocation`.
   - When recovering or resuming a workflow step following tool setup, record the canonical install-after resume metadata in `reverse_workflow`:
     - `capability_id`: Canonical capability ID (e.g. `"browser_debugger"`, `"websocket_capture"`, `"js_deobfuscation"`, `"traffic_interception"`).
     - `installed_tool`: Catalog tool installed (e.g. `"playwright-mcp"`, `"mitmproxy"`, `"hbctool"`).
     - `setup_command`: Exact setup command executed (e.g. `"reverse setup reverse playwright-mcp"`).
     - `verified`: `true` (readiness confirmed via `refresh: true`).
     - `strategy`: `"resume_original"` or `"install_recovery"`.
     - `resumed_at`: ISO 8601 timestamp.
6. **Graceful Fallback Degradation**:
   If the operator declines setup or a prerequisite is missing, immediately step down to the native fallback tier (`browser_reverse_session`, `websocket_observe`, `ast_grep`, `sourcemap_inspect`, `pcap_inspect`, `curl`, `strings`) and record the fallback in `reverse_workflow`.

---

## 3. Recommended Workflow

1. **Search-First Keyword Reconnaissance (`ast_grep` & POSIX)**:
   - Locate endpoints, headers, and crypto primitives with targeted regex before reading code:
     `grep -E -o -n "https?://[^\"'\` ]+|/api/v[0-9]/[a-zA-Z0-9_/]+" bundle.js`
   - Use `ast_grep` for structural AST code patterns across minified JavaScript regardless of variable renaming.
2. **SourceMap Recovery & Source Reconstruction (`js_deobfuscation`)**:
   - Resolve capability: `reverse_capability({ action: "resolve", capability: "js_deobfuscation" })`.
   - Use `sourcemap_inspect(action: "info", path: "...")` to inspect map metadata and embedded `sourcesContent`.
   - Use `sourcemap_inspect(action: "lookup", ...)` to map minified bundle coordinates back to original source lines and symbol names.
   - Use `sourcemap_inspect(action: "extract", ...)` to unpack embedded original source files.
   - Fallback: `strings` / `file`.
3. **Runtime Instrumentation & Hook Templates (`browser_debugger`)**:
   - Resolve capability: `reverse_capability({ action: "resolve", capability: "browser_debugger" })`.
   - Prefer native built-ins first: generate safe, non-executing hook presets with `js_hook_preset(action: "generate", preset: "...")` for `fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, or Electron `contextBridge`.
   - For live page evaluation and CDP control, dispatch native `browser_reverse_session({ action: "eval", expression: "..." })`.
   - When automated multi-session browser control via Playwright is required, present setup notice for `playwright-mcp` (`reverse setup reverse playwright-mcp`). Upon install, re-resolve with `refresh: true`, dispatch, and record resume metadata (`capability_id`, `installed_tool`, `setup_command`, `verified`, `strategy`, `resumed_at`) in `reverse_workflow`.
   - Fallback: `browser_reverse_session` / `curl` / `file`.
4. **WebAssembly & Bytecode Deconstruction (`js_deobfuscation`)**:
   - For WebAssembly: Start with `wasm_inspect(action: "info")` for imports, exports, signatures, and name-section functions; use `strings` and `search` before requesting WAT. Use `wasm_inspect(action: "wat")` when `wabt` is installed, or `wasm2wat module.wasm -o module.wat` directly, and analyze exported crypto routines.
   - For React Native Hermes bytecode (`.hbc`): Resolve capability `reverse_capability({ action: "resolve", capability: "js_deobfuscation" })`. If `hbctool` is missing, present setup notice (`reverse setup reverse hbctool`). Upon install, re-resolve with `refresh: true`, dispatch `hbctool disasm <index.android.bundle> <out_dir>`, and record resume metadata (`capability_id`, `installed_tool`, `setup_command`, `verified`, `strategy`, `resumed_at`) in `reverse_workflow`. Fallback: `strings` / `file`.
5. **Protocol Capture & Frame Analysis (`websocket_capture`) (Authorized Targets Only)**:
   - Resolve capability: `reverse_capability({ action: "resolve", capability: "websocket_capture" })`.
   - For offline capture analysis (zero external dependency): Record WebSocket traffic to a HAR or CDP NDJSON file with the browser relay or an authorized proxy; keep the original capture read-only.
   - Start with `websocket_observe(action: "inspect", path: "...")` for connections, opcodes, direction counts, and time range.
   - Use `list`/`search` with `url`, `direction`, `opcode`, `filter`, and `regex` to isolate the handshake, subscribe, or signing frames; payload previews are bounded and credentials are redacted.
   - Use `export` with `export_format: "ndjson"` when full redacted payloads are needed, then cite the artifact id and frame index.
   - When live capture or proxy decryption is required and no capture file exists, present setup notice for `mitmproxy` (`reverse setup reverse mitmproxy`) or `tshark`. Upon install, re-resolve with `refresh: true`, dispatch `mitmweb --web-port 8081` or `tshark -Y websocket -i any`, and record resume metadata (`capability_id`, `installed_tool`, `setup_command`, `verified`, `strategy`, `resumed_at`) in `reverse_workflow`.
   - Fallback: native `websocket_observe` / `pcap_inspect` / `strings` / `curl`.
6. **Protocol Verification, Replay & Traffic Interception (`traffic_interception`) (Authorized Targets Only)**:
   - Resolve capability: `reverse_capability({ action: "resolve", capability: "traffic_interception" })`.
   - For bounded replay: Replay captured requests with exact headers and signatures via `curl` against authorized endpoints to verify parameter validation behavior, saving response traces to `./artifacts/`. Note that `websocket_observe` itself is analysis-only: it never connects or replays; any live replay is a separate, explicitly authorized step.
   - For live HTTPS traffic interception and API contract mapping: Present setup notice for `mitmproxy` (`reverse setup reverse mitmproxy`) or `tshark`. Upon install, re-resolve with `refresh: true`, dispatch `mitmproxy -p 8080` or `mitmdump -s filter.py`, and record resume metadata (`capability_id`, `installed_tool`, `setup_command`, `verified`, `strategy`, `resumed_at`) in `reverse_workflow`.
   - Fallback: `curl` / `strings` / offline `pcap_inspect`.

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
