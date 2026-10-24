# ghidra_inspect

> Read-only headless binary analysis and decompilation bridge through Ghidra (`analyzeHeadless`).

## Source
- Entry: `packages/coding-agent/src/tools/ghidra-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/ghidra-inspect.md`
- Catalog descriptor: `packages/coding-agent/src/extensibility/skill-tool-catalog.ts` (`ghidra`)

## Overview
`ghidra_inspect` executes headless analysis and function decompilation through Ghidra's `analyzeHeadless` batch interface. All invocations are constructed via discrete argument arrays without arbitrary shell evaluation.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `info \| analyze \| decompile \| export \| jni_enrich \| findcrypt` | Yes | Query action to perform. |
| `path` | `string` | Yes | Path to target binary file, resolved against session cwd. |
| `target` | `string` | No | Function name or address to decompile (alias for `symbol`). |
| `symbol` | `string` | No | Function name or symbol to decompile. |
| `address` | `string` | No | Virtual address in hex (e.g. `0x401000`). |
| `script` | `string` | No | Optional trusted Ghidra post-script name. |
| `script_args` | `string[]` | No | Arguments passed to the post-script. |
| `project_dir` | `string` | No | Optional directory for the temporary Ghidra project; defaults to OS temp directory. |
| `limit` | `number >= 1` | No | Maximum lines returned (default 100, max 2000). |
| `offset` | `number >= 0` | No | Zero-based line pagination offset. |
| `mode` | `full \| fold \| summary` | No | Output rendering mode. |
| `timeout` | `number >= 1` | No | Execution timeout seconds (default 60, max 300). |
| `max_bytes` | `number >= 1` | No | Maximum stdout bytes captured (default 256 KiB, max 4 MiB). |
| `records` | `unknown[]` | No | Array of CanonicalJniMethodRecord objects to enrich (`jni_enrich`). |
| `events` | `unknown` | No | Raw RegisterNatives event or array of events from dynamic tracing (`jni_enrich`). |
| `events_path` | `string` | No | Path to an on-disk JSON artifact containing RegisterNatives events (`jni_enrich`). |
| `preview` | `boolean` | No | When true (default), previews JNI enrichment without modifying project. Set false to persist to project (`jni_enrich`). |
| `load_bias` | `string` | No | Runtime module load bias hex string for address re-basing (`jni_enrich`). |
| `is_static_map` | `unknown` | No | Optional mapping from Java method signature to boolean confirming static DEX declaration (`ACC_STATIC`). |

## Actions
- `info`: Probes the Ghidra installation, resolved `analyzeHeadless` executable, and target binary status.
- `analyze`: Runs headless auto-analysis on the target binary, returning execution logs and analysis summary.
- `decompile`: Decompiles a function or routine to C pseudocode using Ghidra's decompiler engine. Default invocation uses the bundled headless script (`ReverseGhidraInspect.java`) to resolve targets by symbol name or address (falling back to standard entrypoints like `main` or `_start` when omitted), returning pure targeted C pseudocode without bootstrap logs. Missing or ambiguous targets report structured errors (`status: "error"`).
- `export`: Emits bounded decompilation listings or symbol summaries with line bounds and pagination. Default invocation exports program metadata, function inventory, and symbol table, or targeted function decompilation when a target is specified.
- `jni_enrich`: Enriches Android native shared library (`.so`) functions by applying confirmed dynamic JNI `RegisterNatives` symbols and standard C prototypes. Supports dry-run preview (`preview: true`, default, Read tier) and project persistence (`preview: false`, requires explicit `project_dir`, Exec tier). Reopens existing projects via `-process <program>` to preserve prior annotations.
- `findcrypt`: Runs external FindCrypt analyzer plugin (`ghidra-findcrypt` / `FindCryptAnalyzer`) on the target binary, returning structured candidate cryptographic constant addresses and algorithm labels with heuristic candidate disclaimers. [Read tier]
## Dependency Gating
When Ghidra (`analyzeHeadless`) is not found on PATH or configured via `GHIDRA_INSTALL_DIR`, the tool returns `status: "missing_dependency"` with structured metadata:
- Recommended setup route: Run interactive setup via TUI (`reverse setup`) or CLI (`reverse setup reverse ghidra`) to install and configure Ghidra.
- Package manager catalog metadata (`brew install --cask ghidra`, `apt install ghidra`, `choco install ghidra`).
- Active fallbacks: `r2_inspect`, `ida`, or `triage`.
- Never fakes decompilation or simulates results when Ghidra is absent.
