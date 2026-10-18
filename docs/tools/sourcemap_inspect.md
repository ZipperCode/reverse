# sourcemap_inspect

> Static inspection, VLQ mapping lookup, and source code reconstruction from JavaScript SourceMaps (direct `.map` files and inline `sourceMappingURL` directives).

## Source
- Entry: `packages/coding-agent/src/tools/sourcemap-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/sourcemap-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "lookup" \| "extract"` | Yes | `info` catalogs metadata; `lookup` maps line:col back to original source; `extract` unpacks embedded sources. |
| `path` | `string` | Yes | Path to target `.map` file or compiled `.js`/`.ts` bundle file. |
| `line` | `number >= 1` | For `lookup` | 1-based line number in generated file. |
| `column` | `number >= 0` | For `lookup` | Column offset in generated file (default 0-based). |
| `column_zero_based` | `boolean` | No | Whether `column` is 0-based. Defaults to `true`. |
| `source_index` | `number >= 0` | No | Source index to extract (0-based). |
| `source_path` | `string` | No | Substring or extension filter for `extract`. |
| `destination_dir` | `string` | No | Optional local output directory to write extracted files. |
| `limit` | `number >= 1` | No | Maximum items to list or files to extract (default 50, max 500). |
| `skip` | `number >= 0` | No | Pagination offset for sources or names list (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum file bytes to read (default 5MB, hard limit 50MB). |

## Capabilities & Analysis
- **SourceMap Metadata (`info`)**:
  - Parses SourceMap v3 JSON headers, version, `file`, `sourceRoot`, and list of original sources and names.
  - Reports count of files with embedded `sourcesContent` and mapped lines count.
- **VLQ Coordinate Lookup (`lookup`)**:
  - Performs pure Base64 VLQ decoding across mapped lines up to target line/column.
  - Resolves minified column back to original file path, 1-based original line, 0-based column, and original symbol name.
  - Renders syntax-highlighted multi-line original source code snippet (+/- 3 lines) with target line indicator (`>`) when `sourcesContent` is present.
- **Source Code Recovery (`extract`)**:
  - Unpacks original source files stored in `sourcesContent`.
  - Supports inline return or writing to local disk with strict path traversal validation.
- **Directive Resolution**:
  - Supports inline Base64 data URIs (`data:application/json;base64,...`), inline URIs, relative `.map` file paths, and adjacent `${path}.map` files.
  - Remote HTTP/HTTPS URLs are strictly rejected.

## Limits & Caps
- `DEFAULT_LIMIT = 50`, `MAX_LIMIT = 500`: List outputs are bounded to avoid excessive context consumption.
- `DEFAULT_MAX_BYTES = 5 MiB`, `HARD_MAX_BYTES = 50 MiB`: Caps maximum sourcemap file size.

## Side Effects
- Read-only by default; writes to local disk only when `destination_dir` is explicitly specified for `extract`.
- Never executes target JavaScript, loads external network URLs, or starts subprocesses.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
