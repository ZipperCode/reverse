# Web & Protocol Forensics Guide

This reference outlines the workflow for analyzing Web frontend bundles, JavaScript obfuscation, WebAssembly modules, and network API protocols. It incorporates search-first context control to prevent token explosion on multi-megabyte minified assets.

---

## 1. Search-First Token Discipline for JavaScript Assets

Minified production bundles (`app.min.js`, `vendor.js`, `bundle.chunk.js`) often exceed 5MB to 30MB. Preserve conversation context by applying a search-first approach: inspect discrete endpoints, tokens, and cryptographic routines before reading code blocks:

```
[Minified Bundle (5-20 MB)]
           │
           ▼
[Tier 1: Keyword & Endpoint Recon] ──> native ast_grep / grep for routes, auth, crypto
           │
           ▼
[Tier 2: SourceMap & AST Extraction] ──> Reconstruct original sources or isolate functions
           │
           ▼
[Tier 3: Targeted Reading] ──> Read only relevant 20-50 line modules via :range
```

### 1. High-Value Keyword Search Filters
Query sensitive logic boundaries without loading the file:
```bash
# Locate API endpoints and routes
grep -E -o -n "https?://[^\"'\` ]+|/api/v[0-9]/[a-zA-Z0-9_/]+" bundle.js | head -n 50

# Locate authentication & signature headers
grep -n -E "Authorization|Bearer|X-Signature|X-Timestamp|X-Nonce" bundle.js

# Locate Web Crypto API & hashing primitives
grep -n -E "crypto\.subtle|createHmac|createHash|CryptoJS|AES|RSA|PBKDF2|SHA256" bundle.js
```

### 2. AST-Based Structural Search (`ast_grep`)
When variable names are minified (e.g. `function(e,t,n)`), match code patterns structurally with rea's native `ast_grep` tool (no external CLI required; the optional `ast-grep` CLI is a fallback):
```
ast_grep(pat: "crypto.subtle.sign($$$)", path: "bundle.js")
ast_grep(pat: "new Hmac($$$)", path: "bundle.js")

# Locate Axios / Fetch interceptors setting headers
ast_grep(pat: "axios.interceptors.request.use($$$)", path: "bundle.js")
ast_grep(pat: "fetch($URL, { headers: { $$$ } })", path: "bundle.js")
```

---

## 2. SourceMap Recovery & Source Tree Reconstruction

When developer SourceMaps are present (.map file or inline `sourceMappingURL` in `.js`), use rea's native `sourcemap_inspect` tool to inspect metadata, map minified line/column coordinates back to original source code, and extract unminified TypeScript/JavaScript source trees without external CLI dependencies:

### 1. Inspect SourceMap Metadata & File List
```text
sourcemap_inspect(action: "info", path: "dist/bundle.js")
# Or directly on .map file:
sourcemap_inspect(action: "info", path: "dist/bundle.js.map")
```
Reports format version, source root, total source files, sample symbol names, and whether original source code is embedded in `sourcesContent`. Supports inline base64, relative map references, and adjacent `.map` files.

### 2. VLQ Coordinate Reverse Lookup
When debugging a crash, finding an error location, or reverse-engineering a minified function at a specific line and column:
```text
sourcemap_inspect(action: "lookup", path: "dist/bundle.min.js", line: 1, column: 14250)
```
Performs VLQ coordinate decoding and outputs the original TypeScript/JavaScript source file, 1-based original line number, column offset, symbol name, and code snippet with contextual lines.

### 3. Extract Original Source Code
When `sourcesContent` is embedded:
```text
# Extract specific file inline:
sourcemap_inspect(action: "extract", path: "dist/bundle.js.map", source_path: "authService.ts")

# Recover and save embedded source files into a safe local directory:
sourcemap_inspect(action: "extract", path: "dist/bundle.js.map", destination_dir: "./artifacts/recovered-src")
```

---

## 3. Dynamic JavaScript Hook Presets (`js_hook_preset`)

For authorized browser, Electron, or Node.js runtime debugging, use rea's native `js_hook_preset` tool to generate safe, non-executing hook templates (fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, custom):

```text
# List available hook presets and options:
js_hook_preset(action: "list")

# Generate Fetch API interceptor with endpoint filtering:
js_hook_preset(action: "generate", preset: "fetch", filter: "/api/v1/")

# Generate Web Crypto API subtle monitor (encrypt/decrypt/digest/sign):
js_hook_preset(action: "generate", preset: "crypto", format: "devtools")

# Generate Electron preload contextBridge IPC tracer:
js_hook_preset(action: "generate", preset: "contextBridge")

# Generate allowlisted custom function or property trap:
js_hook_preset(action: "generate", preset: "custom", target: "window.appService.signPayload")
```
All templates are returned as text data and are NEVER executed automatically.

## 4. WebAssembly (WASM) Reverse Engineering

WebAssembly modules (`.wasm`) are binary format. Start with rea's native `wasm_inspect` tool, which reads imports, exports, signatures, names, and strings without external dependencies. Request WAT only when instruction-level analysis is needed.

### 1. Inspect Structure, Imports & Exports
```text
wasm_inspect(action: "info", path: "module.wasm")
```
Reports sections, type signatures, imports (including module/name and signatures), exports with resolved function signatures, function counts, memories, globals, data segments, custom sections, and `name`-section function symbols.

### 2. String & Data Segment Recovery
WASM strings and constants are stored in data segments and custom sections:
```text
wasm_inspect(action: "strings", path: "module.wasm", min_length: 8, limit: 50)
```
Use `search` for a bounded raw-byte or regex keyword sweep before requesting WAT:
```text
wasm_inspect(action: "search", path: "module.wasm", pattern: "https?://[^\\x00\\s]+", regex: true)
```

### 3. Disassemble WASM to WAT
```text
# Native action; requires wabt on PATH
wasm_inspect(action: "wat", path: "module.wasm", max_bytes: 262144)
```
```bash
# Equivalent direct CLI from WABT (WebAssembly Binary Toolkit)
wasm2wat module.wasm -o module.wat
```
Then inspect WAT for instruction-level patterns:
```bash
grep -E '\(import |\(export |\(data ' module.wat
```

---

## 5. Browser Relay & CDP Dynamic Forensics

Execute browser console hooks, DOM evaluations, and network frame captures exclusively against explicitly authorized staging domains, local loopback services, or designated test targets. Save all HAR captures, console outputs, and session logs to dedicated artifact paths (`./artifacts/`).

When analyzing live Web sessions, use Chrome DevTools Protocol (CDP) or rea's `browser-relay`:

### 1. Network Traffic Capture
- **HAR Export**: Save complete network waterfalls including request payloads, response bodies, and TLS certificates.
- **WebSocket Interception**: Capture continuous duplex frame messages for proprietary real-time binary protocols.

### 2. Console Evaluation & Breakpoint Trapping
Attach script breakpoints on cryptographic APIs:
```javascript
// Hook Web Crypto API in browser console to capture raw keys and cleartext
(function () {
    const originalImportKey = window.crypto.subtle.importKey;
    window.crypto.subtle.importKey = async function (format, keyData, algorithm, extractable, keyUsages) {
        console.log("[CDP Hook] crypto.subtle.importKey called!");
        console.log("  Format:", format);
        console.log("  Algorithm:", algorithm);
        console.log("  KeyData (hex):", Array.from(new Uint8Array(keyData)).map(b => b.toString(16).padStart(2, '0')).join(''));
        return originalImportKey.apply(this, arguments);
    };

    const originalSign = window.crypto.subtle.sign;
    window.crypto.subtle.sign = async function (algorithm, key, data) {
        console.log("[CDP Hook] crypto.subtle.sign called!");
        console.log("  Algorithm:", algorithm);
        console.log("  Plaintext Data:", new TextDecoder().decode(data));
        const signature = await originalSign.apply(this, arguments);
        console.log("  Generated Signature:", Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join(''));
        return signature;
    };
})();
```

---

## 6. Protocol Verification & Replay

Execute protocol request replays and parameter mutations exclusively against authorized test endpoints or local staging instances. Preserve original production payloads read-only, documenting replay requests, response headers, and observed status deltas in dedicated evidence artifacts.

To verify an auth or encryption hypothesis, construct a standalone replay script:
```bash
# Replay captured HTTP API request with exact headers and body
curl -X POST "https://target-service.local/api/v2/auth" \
  -H "Host: target-service.local" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: 1729152000" \
  -H "X-Signature: c8f3a1b4d5e6..." \
  -d '{"client_id":"app_01","grant_type":"device_code"}' \
  -v
```

Document request/response delta in the evidence artifact to establish reproducible conclusion proof.

---

## 7. Native Offline PCAP & PCAPNG Inspection (`pcap_inspect`)

When analyzing offline packet captures (`.pcap`, `.pcapng`), use rea's native, zero-dependency `pcap_inspect` tool to extract headers, packet lists, endpoints, conversations, and DNS queries without live packet capture or network replay:

### 1. Capture Overview & Protocol Breakdown
```text
pcap_inspect(action: "info", path: "traffic.pcap")
```
Reports capture format (classic PCAP / PCAPNG), link layer (Ethernet, Linux Cooked, Raw IP), duration, total packet count, protocol breakdown (TCP, UDP, TLS, HTTP, DNS, ICMP, ARP), and top IP endpoints.

### 2. Wireshark-Style Packet Filtering & Paging
```text
pcap_inspect(action: "list", path: "traffic.pcap", protocol: "http", limit: 25)
pcap_inspect(action: "list", path: "traffic.pcap", ip: "10.0.0.5", port: 443)
pcap_inspect(action: "list", path: "traffic.pcap", packet_number: 42)
```
Returns bounded packet rows with relative timestamps, source/destination endpoints, protocols, frame lengths, and Wireshark-like info summaries. `packet_number` produces full layer-by-layer header decode and bounded hex/ASCII payload preview.

### 3. IP Endpoints & Conversations
```text
pcap_inspect(action: "endpoints", path: "traffic.pcapng")
pcap_inspect(action: "conversations", path: "traffic.pcapng")
```
Aggregates communication partners, directional packet/byte counts, and observed hostnames (via TLS SNI or DNS).

### 4. DNS Forensic Extraction
```text
pcap_inspect(action: "dns", path: "traffic.pcapng")
```
Extracts DNS query domains, record types (A, AAAA, CNAME), and resolved IP addresses.

---

## 8. Native Offline SQLite Database Inspection (`sqlite_inspect`)

When analyzing client-side storage, mobile databases, or browser profiles (`.db`, `.sqlite`, `.sqlite3`), use rea's native `sqlite_inspect` tool for read-only schema, table, row, and WAL inspection without mutation or arbitrary SQL execution:

### 1. Database Header & Storage Overview
```text
sqlite_inspect(action: "info", path: "app_data.db")
```
Validates the `SQLite format 3` header, reports page size, total pages, freelist count, encoding, user_version, journal mode, entity counts, and write-ahead log (WAL) presence.

### 2. Table & View Catalog
```text
sqlite_inspect(action: "tables", path: "app_data.db")
```
Lists all ordinary tables, virtual tables, views, and system tables with row counts and column counts.

### 3. Schema & DDL Inspection
```text
sqlite_inspect(action: "schema", path: "app_data.db", table: "users")
```
Extracts CREATE statements, column types, nullability, default values, primary keys, indexes, and foreign key relationships.

### 4. Safe Bounded Row Inspection
```text
sqlite_inspect(action: "rows", path: "app_data.db", table: "users", limit: 20)
sqlite_inspect(action: "rows", path: "app_data.db", table: "auth_tokens", columns: ["id", "user_id", "expires_at"], order_by: "expires_at", order_desc: true)
```
Safely reads bounded rows from a target table with strict column and table identifier validation. Formats BLOBs and truncates oversized text cells. Arbitrary SQL queries and mutations are strictly rejected.

### 5. Write-Ahead Log (WAL) Metadata
```text
sqlite_inspect(action: "wal", path: "app_data.db")
```
Decodes the 32-byte WAL header, checkpoint sequence numbers, salt values, and uncheckpointed frame counts.
