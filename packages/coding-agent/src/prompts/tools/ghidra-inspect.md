Headless binary analysis, decompilation, JNI dynamic registration enrichment, and FindCrypt constants analysis through Ghidra (`analyzeHeadless`). Dispatches bounded analysis, decompilation, export, and symbol enrichment queries through structured arguments without arbitrary shell execution.

Actions:
- `info`: Check Ghidra environment configuration (`GHIDRA_INSTALL_DIR`, `analyzeHeadless` executable) and target file accessibility. [Read tier]
- `analyze`: Run headless analysis on the target binary in a transient or designated project, returning structured analyzer output and status. [Read tier]
- `decompile`: Decompile a function or symbol into C pseudocode using Ghidra's headless decompiler engine. Default invocation resolves target (or standard entry points `main`/`_start` if omitted), returns pure C pseudocode without bootstrap logs, and reports structured errors if the target is missing or ambiguous. Specify `symbol`, `target`, or `address`. [Read tier]
- `export`: Export decompiled functions or structured function/symbol analysis summary, with line pagination and byte caps. [Read tier]
- `jni_enrich`: Enrich Android shared library (`.so`) functions by applying confirmed dynamic JNI `RegisterNatives` symbols and standard C prototypes. Supports dry-run preview (`preview: true`, default, Read tier) and project persistence (`preview: false`, requires explicit `project_dir`, Exec tier).
- `findcrypt`: Run external FindCrypt analyzer plugin (`ghidra-findcrypt` / `FindCryptAnalyzer`) on the target binary, returning structured candidate cryptographic constant addresses and algorithm labels. [Read tier]
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
- `records`: Array of CanonicalJniMethodRecord objects to enrich for `jni_enrich`.
- `events`: Raw RegisterNatives event or array of events from dynamic tracing (e.g. Frida `jni_register` or Unidbg) for `jni_enrich`.
- `preview`: Boolean flag for `jni_enrich` (default `true` for dry-run preview; set `false` to apply changes to designated Ghidra project).
- `load_bias`: Runtime module load bias hex string for `jni_enrich` static address calculation.
- `is_static_map`: Optional mapping from Java method signature to boolean confirming static DEX declaration (`ACC_STATIC`).

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
ghidra_inspect(action: "jni_enrich", path: "libttEncrypt.so", events: [{ event: "jni_register_natives", status: "confirmed", retval: 0, class: "com/example/Native", methods: [{ name: "sign", signature: "(Ljava/lang/String;)Z", fnPtr: "0x7f001001", base: "0x7f000000" }] }], preview: true)
ghidra_inspect(action: "findcrypt", path: "libttEncrypt.so")
</examples>
