Read-only headless binary analysis and decompilation bridge through Ghidra (`analyzeHeadless`). Dispatches bounded analysis, decompilation, and export queries through structured command line arguments without running arbitrary shell scripts.

Actions:
- `info`: Check Ghidra environment configuration (`GHIDRA_INSTALL_DIR`, `analyzeHeadless` executable) and target file accessibility.
- `analyze`: Run headless analysis on the target binary in a transient or designated project, returning structured analyzer output and status.
- `decompile`: Decompile a function or symbol into C pseudocode using Ghidra's headless decompiler engine. Default invocation resolves target (or standard entry points `main`/`_start` if omitted), returns pure C pseudocode without bootstrap logs, and reports structured errors if the target is missing or ambiguous. Specify `symbol`, `target`, or `address`.
- `export`: Export decompiled functions or structured function/symbol analysis summary, with line pagination and byte caps.

Parameters:
- `path`: Path to target binary; resolves against session cwd.
- `target` / `symbol`: Function or symbol name to decompile (e.g. `main`, `validate_key`, `FUN_00401000`).
- `address`: Hex virtual address (e.g. `0x401000`).
- `script`: Optional name of a trusted Ghidra post-script to execute with `-postScript`.
- `script_args`: Arguments passed to the post-script.
- `project_dir`: Optional directory for the temporary Ghidra project; defaults to an isolated OS temp directory.
- `limit`: Maximum output lines returned (default 100, max 2000).
- `offset`: Zero-based line pagination offset.
- `mode`: Rendering mode: `full`, `fold` (collapse blank/duplicate lines), or `summary`.
- `timeout`: Execution timeout in seconds (default 60, max 300).
- `max_bytes`: Maximum stdout bytes captured (default 256 KiB, max 4 MiB).

Dependency gating:
- When Ghidra (`analyzeHeadless`) is not installed, returns `status: "missing_dependency"` with setup instructions (`reverse setup reverse ghidra`), catalog hints, and suggested fallbacks (`r2_inspect`, `ida`, `triage`).
- This tool never fakes decompilation or simulates results when the engine is missing.
- Arguments are passed as discrete array elements directly to the process runner; shell interpolation is never used.

<examples>
```
ghidra_inspect(action: "info", path: "sample.bin")
ghidra_inspect(action: "analyze", path: "sample.bin", timeout: 120)
ghidra_inspect(action: "decompile", path: "sample.bin", symbol: "main", limit: 80)
ghidra_inspect(action: "decompile", path: "sample.bin", address: "0x401000", mode: "fold")
ghidra_inspect(action: "export", path: "sample.bin", limit: 200)
```
</examples>
