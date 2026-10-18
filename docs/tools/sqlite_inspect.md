# sqlite_inspect

> Native offline read-only SQLite database inspection without mutation or arbitrary SQL execution.

## Source
- Entry: `packages/coding-agent/src/tools/sqlite-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/sqlite-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "tables" \| "schema" \| "rows" \| "wal"` | Yes | `info` catalogs database headers & metadata; `tables` lists tables & views; `schema` details DDL, columns, indexes, foreign keys; `rows` reads bounded table rows; `wal` decodes WAL headers & frames. |
| `path` | `string` | Yes | Path to target SQLite database file (`.db`, `.sqlite`, `.sqlite3`). |
| `table` | `string` | For `rows` | Target table or view name (required for `rows`, optional filter for `schema`). |
| `columns` | `string[]` | No | Optional list of specific column names to select in `rows`. |
| `order_by` | `string` | No | Optional column name to sort by in `rows`. |
| `order_desc` | `boolean` | No | Whether to sort descending when `order_by` is specified (default `false`). |
| `limit` | `number >= 1` | No | Maximum rows or items to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum database file bytes to read (default 500MB, max 2GB). |

## Capabilities & Analysis
- **Database Header & Storage Inspection (`info`)**:
  - Validates SQLite 3 16-byte magic header (`"SQLite format 3\0"`).
  - Inspects page size, page count, freelist pages, user_version, application_id, text encoding (UTF-8, UTF-16), and journal mode.
  - Summarizes total table, view, index, and trigger counts.
  - Reports write-ahead log (WAL) and shared-memory (SHM) file presence and frame counts.
- **Table & View Catalog (`tables`)**:
  - Lists all ordinary tables, virtual tables, views, and system tables from `sqlite_master` / `sqlite_schema`.
  - Calculates row counts via `SELECT COUNT(*)` and column counts for each table.
- **Schema & DDL Inspection (`schema`)**:
  - Extracts full CREATE statements for tables, views, indexes, and triggers.
  - Decodes table columns via `PRAGMA table_info`: column ID, name, declared type, not-null constraints, default values, primary key status.
  - Inspects indexes via `PRAGMA index_list` and `PRAGMA index_info`: index name, unique constraint, origin, and indexed columns.
  - Inspects foreign keys via `PRAGMA foreign_key_list`: referenced table, from/to column mappings, ON UPDATE / ON DELETE actions.
- **Safe Bounded Row Inspection (`rows`)**:
  - Bounded retrieval with `limit` (default 50, max 500) and `offset` pagination.
  - Validates table name against actual database catalog to guarantee safe queries.
  - Validates `columns` and `order_by` against the table's column definitions.
  - Strictly escapes identifiers (`"table"`, `"column"`).
  - Formats BLOB columns safely as `<BLOB: N bytes, hex:...>` previews.
  - Truncates oversized text values to prevent context window saturation.
  - Rejects any mutation queries or arbitrary SQL input (no raw SQL execution parameter exists).
- **Write-Ahead Log (WAL) Inspection (`wal`)**:
  - Decodes the 32-byte WAL header: magic (`0x377f0682` big-endian or `0x377f0683` little-endian), file format version (3007000), page size, checkpoint sequence number, salt, and checksums.
  - Computes uncheckpointed frame count: `(wal_size - 32) / (page_size + 24)`.
  - Detects shared memory (`-shm`) index file presence.

## Limits & Caps
- `DEFAULT_LIMIT = 50`, `MAX_LIMIT = 500`: Row results and item lists are bounded.
- `DEFAULT_MAX_BYTES = 500 MiB`, `HARD_MAX_BYTES = 2 GiB`: Caps maximum database file size.
- Text cell previews capped at 1,000 characters; BLOB previews capped at 64 hex bytes.

## Side Effects
- Strictly read-only and offline.
- Database opened exclusively with `{ readonly: true }` / `{ readOnly: true }` / `sqlite3 -readonly`.
- Never performs mutations (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `ATTACH`, etc.).
- Does not expose arbitrary SQL execution.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
