Read-only binary triage through radare2 (`r2`) with fixed, bounded actions. It never accepts an arbitrary r2 command, never patches or debugs, and never writes to the target.

Actions:
- `info`: binary format, architecture, bitness, endianness, OS, type, base address, and size (`ij`). Start here.
- `sections`: section names, virtual/physical addresses, sizes, and permissions (`iSj`).
- `imports`: imported symbols and their libraries (`iij`).
- `exports`: exported symbols with addresses and types (`iEj`).
- `strings`: all detected strings with addresses, lengths, and sections (`izzj`).
- `functions`: analyzed function list with offsets, sizes, and instruction counts (`aflj`). Requires analysis.
- `xrefs`: references to one symbol or address (`axtj`). `symbol` or `address` is required. Requires analysis.
- `disasm`: bounded instruction window (`pdj`). Give `symbol`/`address` to seek; otherwise starts at `entry0`. Requires analysis.
- `decompile`: pseudo-C when an r2 decompiler plugin such as r2dec is installed (`pdc`). It is text, not JSON, and is heuristic. Requires analysis.

Selection and paging:
- Prefer `info`, `sections`, `imports`, `exports`, and `strings` before analysis-heavy actions.
- List actions support `offset` and `limit` (default 50, max 500). `xrefs` and large symbol tables must be paged.
- `disasm` accepts a bounded `limit` (default 100, max 2000); seek with `address` or `symbol` instead of using a very large offset.
- `decompile` pages output lines with `offset`/`limit`.
- `mode` controls rendering: `full`, `fold` (collapse blank/duplicate lines and trailing whitespace), or `summary` (counts plus a short preview). `fold` and `summary` are conservative heuristics and are marked unverified.

Input safety:
- `symbol` accepts flag/function names only (`main`, `sym.main`, `sym.imp.malloc`, `fcn.00401000`, `std::vector`).
- `address` accepts decimal or hex (`0x401000`); do not combine it with `symbol`.
- Use `path` for the target file; paths resolve against the session cwd.
- Output is capped by `max_bytes` (default 256 KiB, max 4 MiB) and `timeout` (default 30 s, max 120 s). Truncated output is reported with `truncated: true`.

When `radare2` is not installed, returns `status: "missing_dependency"` with the trusted install hint and suggested `objdump`/`strings` fallback commands. Fallbacks are suggestions only; this tool does not execute them.

<examples>
```
r2_inspect(action: "info", path: "sample.bin")
r2_inspect(action: "sections", path: "sample.bin", limit: 100)
r2_inspect(action: "strings", path: "sample.bin", offset: 100, limit: 50, mode: "summary")
r2_inspect(action: "functions", path: "sample.bin", limit: 100)
r2_inspect(action: "xrefs", path: "sample.bin", symbol: "sym.imp.malloc")
r2_inspect(action: "xrefs", path: "sample.bin", address: "0x401000", limit: 20)
r2_inspect(action: "disasm", path: "sample.bin", symbol: "main", limit: 40)
r2_inspect(action: "decompile", path: "sample.bin", address: "0x401000", limit: 120, mode: "fold")
```
</examples>
