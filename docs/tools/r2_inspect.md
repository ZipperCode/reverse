# r2_inspect

> Read-only radare2 triage with fixed, bounded actions: info, sections, imports, exports, strings, functions, xrefs, disassembly, and optional decompilation.

## Source
- Entry: `packages/coding-agent/src/tools/r2-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/r2-inspect.md`
- Dependency detector: `packages/coding-agent/src/extensibility/skill-tool-catalog.ts` (`radare2` descriptor) via `checkToolRequirements`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `info \| sections \| imports \| exports \| strings \| functions \| xrefs \| disasm \| decompile` | Yes | Fixed analysis action. |
| `path` | `string` | Yes | Target binary/object path, resolved against session cwd. |
| `symbol` | `string` | conditional | Flag/function name (e.g. `main`, `sym.main`, `sym.imp.malloc`). Required for `xrefs`. |
| `target` | `string` | No | Alias for `symbol`. |
| `address` | `string` | conditional | Decimal or hex virtual address (e.g. `0x401000`). Cannot be combined with `symbol`. |
| `offset` | `number >= 0` | No | Pagination offset for lists/decompile lines. Capped at 100000. |
| `limit` | `number >= 1` | No | Page size: default 50 (max 500) for lists, default 100 (max 2000) for `disasm`/`decompile`. |
| `mode` | `full \| fold \| summary` | No | Rendering mode, default `full`. `fold` strips ANSI/blank/duplicate lines; `summary` shows counts plus a short preview. |
| `timeout` | `number >= 1` | No | Execution timeout seconds (default 30, max 120). |
| `max_bytes` | `number >= 1` | No | Maximum stdout bytes captured (default 262144, max 4194304). |

## Outputs
- `details.status`: `ok`, `missing_dependency`, or `error`.
- Parsed list/info fields: `info`, `sections`, `imports`, `exports`, `strings`, `functions`, `xrefs`, `disasm`, or `decompile` (text plus `lineCount`).
- Paging metadata: `total`, `count`, `offset`, `hasMore`.
- Execution metadata: `outputBytes`, `truncated`, `timedOut`, `parseError`, `raw` (bounded preview), `engine`, `dependency`, `reference`, `mode`.
- `status: "ok"` with `truncated: true` means the cap was reached but usable output was returned.
- If radare2 JSON cannot be parsed, returns `status: "error"` with `parseError` and a bounded raw preview instead of throwing.
- `mode: "fold"`/`"summary"` set `unverified: true` and append an explicit heuristic notice.
- `decompile` returns decompiler text rather than JSON; if `pdc` is unavailable it returns an error with the `r2pm -ci r2dec` hint.

## Flow
1. `execute()` validates `path`, expands it with `resolveReadPath()`, stats it, rejects non-files and files over 1 GiB.
2. `symbol`/`address` are strictly validated (`ADDRESS_PATTERN`, `SYMBOL_PATTERN`); combining both is rejected, and `xrefs` requires one.
3. Dependency status uses `checkToolRequirements([{ id: "radare2" }])`, which consults `SKILL_TOOL_CATALOG.radare2`.
4. Missing dependency returns `status: "missing_dependency"` plus catalog install hints and action-specific `objdump`/`strings`/`readelf` fallbacks (`executed: false`).
5. Present dependency runs a fixed argv (`r2 -q -e scr.color=0 ... -c <action-command> -c q <path>`) through `Bun.spawn` with `stdin: "ignore"`, timeout, abort, and output caps.
6. `info`, `sections`, `imports`, `exports`, `strings`, `functions`, `xrefs`, and `disasm` parse r2 JSON into stable, paginated fields; `decompile` pages and folds text.

## Safety
- Only fixed action commands are built; there is no parameter that accepts an arbitrary r2 command.
- Symbol and address inputs are allow-listed so they cannot introduce a second command or `@`/seek operator expression.
- Arguments are passed as an argv array to `Bun.spawn`; no shell string is constructed.
- `stdin` is ignored, the child is killed on timeout, abort, or output overflow.
- Strictly read-only: no patch, write, debug, or command-execution action exists.

## Limits & Caps
- `MAX_FILE_BYTES = 1 GiB`.
- `DEFAULT_LIST_LIMIT = 50`, `MAX_LIST_LIMIT = 500`.
- `DEFAULT_TEXT_LIMIT = 100`, `MAX_TEXT_LIMIT = 2000`.
- `DEFAULT_TIMEOUT_SECONDS = 30`, `MAX_TIMEOUT_SECONDS = 120`.
- `DEFAULT_MAX_BYTES = 256 KiB`, `MAX_OUTPUT_BYTES = 4 MiB`.
- Raw parse-failure previews are capped at 8 KiB.

## Side Effects
- Read-only against the target binary. No files are modified.
