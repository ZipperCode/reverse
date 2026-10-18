# wasm_inspect

> Read-only WebAssembly binary recon: sections, imports/exports, names, data strings, byte search, and optional WAT.

## Source
- Entry: `packages/coding-agent/src/tools/wasm-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/wasm-inspect.md`
- Dependency detector: `packages/coding-agent/src/extensibility/skill-requirements.ts` (`wabt` descriptor in `skill-tool-catalog.ts`)

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `info \| strings \| search \| wat` | Yes | Recon mode. |
| `path` | `string` | Yes | Host path to a `.wasm` binary, resolved against the session cwd. |
| `pattern` | `string` | `search` | Literal or regular expression, capped at 4096 characters. |
| `regex` | `boolean` | No | Treat `pattern` as a JavaScript regular expression. Defaults to literal. |
| `case_sensitive` | `boolean` | No | Defaults to `true`. Applies to literal and regex search. |
| `min_length` | `number >= 1` | No | Minimum extracted string length. Defaults to 5. |
| `limit` | `number >= 1` | No | Per-list result cap, clamped to 500. Defaults to 50. |
| `skip` | `number >= 0` | No | Results to skip for `strings` and `search` paging. |
| `max_bytes` | `number >= 1` | No | `search`: scanned file prefix (default 64 MiB). `wat`: stdout cap clamped to 4 MiB (default 128 KiB). |
| `timeout` | `number > 0` | No | `wasm2wat` timeout seconds, clamped to 120. Defaults to 30. |

## Outputs
- One model-facing text block per call.
- `info`: module size, section table, type signatures, imports/exports with resolved function signatures, function counts, memories, globals, data segments, name-section function names, custom sections, and start function.
- `strings`: `source @0xOFFSET: "text"` lines; `source` is `data[<index>]` or `custom:<section>`.
- `search`: `0xOFFSET (N bytes) context` lines; non-printable context bytes render as `.`.
- `wat`: `wasm2wat` stdout plus a truncation footer when capped.
- `details` carries parsed metadata, dependency status, totals, and `truncated`.

## Flow
1. `execute()` resolves the path with `resolveReadPath()`, stats it, rejects non-files, and enforces the 512 MiB analysis cap.
2. `info`/`strings`/`search` read the file and call `parseWasmModule()`.
3. The parser validates the `\0asm` magic and version 1, then walks length-delimited sections: type, import, function, table, memory, global, export, start, code, data, and custom. Malformed lengths and unsupported type forms raise `ToolError`.
4. The custom `name` section is parsed for module and function names; a damaged name section is ignored so imports/exports remain available.
5. `strings` scans data-segment payloads for printable ASCII runs. `search` scans a bounded prefix with literal `indexOf` or a global `RegExp` over a Latin-1 projection, so match offsets map 1:1 to bytes.
6. `wat` resolves the `wabt` catalog entry through `checkToolRequirements()`; without `wasm2wat` it returns `status: "missing_dependency"` plus the catalog install hint.
7. `wasm2wat` runs with piped stdout/stderr, a byte cap, timeout, abort handling, and a structured error result for nonzero exits.

## Limits & Caps
- `MAX_FILE_BYTES = 512 MiB`.
- `DEFAULT_SEARCH_BYTES = 64 MiB`; search scans at most this prefix unless `max_bytes` changes it.
- `DEFAULT_LIST_LIMIT = 50`, `MAX_LIST_LIMIT = 500`; `info` slices types/imports/exports/globals/data/custom sections.
- `MAX_NAME_ENTRIES = 5000` function names.
- `DEFAULT_WAT_MAX_BYTES = 128 KiB`, `MAX_WAT_MAX_BYTES = 4 MiB`, `MAX_WAT_TIMEOUT_SECONDS = 120`.
- `MAX_PATTERN_LENGTH = 4096` characters.

## Side Effects
- Reads the target file only. Never writes the original binary.
- Spawns `wasm2wat` only for `action: "wat"`, always with `stdin: "ignore"` and piped output; the child is killed on timeout, abort, or stdout overflow.
- No network access, no installation, no session mutation.

## Modes / Variants
- Native-only actions (`info`, `strings`, `search`) work with no external tools.
- `wat` requires `wasm2wat`; the descriptor's install hints come from `skill-tool-catalog.ts` (`brew install wabt`, `apt install wabt`, `choco install wabt`).
- `loadMode: "discoverable"`, `approval: "read"`, `strict: true`; mounts as `xd://wasm_inspect` when `tools.xdev` is on.
