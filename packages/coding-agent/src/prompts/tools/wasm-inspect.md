Read-only WebAssembly recon. Parses the binary directly, so `info`, `strings`, and `search` work without wabt.

Actions:
- `info`: header, sections, types, imports, exports, functions, memories, globals, data segments, custom sections, and `name`-section function names. Start here.
- `strings`: ASCII strings in data segments and non-`name` custom sections, with file offsets; `source` is `data[<index>]` or `custom:<section>`. `min_length` (default 5), `skip`, `limit`.
- `search`: bounded raw-byte or regex search. `pattern` is required; `regex` switches from literal. `case_sensitive` defaults true; `max_bytes` caps the scanned prefix.
- `wat`: disassembles via `wasm2wat` from wabt when installed. Missing wabt returns an install hint; native actions remain available. `max_bytes` caps output (default 128 KiB), `timeout` defaults 30 s.

Use `info` and `strings` before dumping WAT. Page with `skip`, and narrow `max_bytes` on large modules. Every list is capped; `truncated` in details means results were omitted.

<examples>
```
wasm_inspect(action: "info", path: "auth.wasm")
wasm_inspect(action: "strings", path: "auth.wasm", min_length: 8, limit: 20)
wasm_inspect(action: "search", path: "auth.wasm", pattern: "https?://[^\\x00\\s]+", regex: true, limit: 20)
wasm_inspect(action: "wat", path: "auth.wasm", max_bytes: 262144)
```
</examples>
