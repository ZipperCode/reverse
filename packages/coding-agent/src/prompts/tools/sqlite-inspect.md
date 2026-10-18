Native offline read-only SQLite database inspection without mutation or arbitrary SQL execution.

Capabilities:
- **Database Metadata (`info`)**:
  - Validates SQLite format 3 magic header bytes.
  - Reports database page size, total pages, free/freelist pages, schema cookie, user_version, encoding, and journal mode.
  - Catalogs table, view, index, and trigger counts.
  - Summarizes write-ahead log (WAL) and shared memory (SHM) file presence and frame counts.
- **Table & View Listing (`tables`)**:
  - Lists all ordinary tables, virtual tables, views, and system tables.
  - Reports row counts and column counts for each entity.
- **Schema & DDL Inspection (`schema`)**:
  - Retrieves full CREATE TABLE / VIEW statements from sqlite_master / sqlite_schema.
  - Decodes table columns (column id, name, data type, nullable constraint, default value, primary key).
  - Inspects table indexes (index name, uniqueness, indexed columns).
  - Inspects foreign key constraints (referenced table, local columns, foreign columns, ON UPDATE / ON DELETE actions).
  - Can inspect the whole database or be filtered to a single `table`.
- **Bounded Row Reading (`rows`)**:
  - Safely reads bounded rows from a target table or view with strict pagination (`limit` default 50, max 500, `offset`).
  - Supports specific `columns` selection and `order_by` sorting.
  - Column and table identifiers are strictly validated against the database catalog to guarantee safety.
  - BLOB values are safely rendered as `<BLOB: N bytes, hex:...>` previews, and long text strings are bounded.
  - Arbitrary SQL and mutations (INSERT, UPDATE, DELETE, DROP, ALTER, ATTACH, etc.) are strictly rejected.
- **Write-Ahead Log Metadata (`wal`)**:
  - Decodes WAL header bytes (magic 0x377f0682/0x377f0683, page size, checkpoint sequence number, salt, checksums).
  - Calculates WAL frame counts and inspects shared memory (`-shm`) status.

Inputs:
- `action`: `"info"`, `"tables"`, `"schema"`, `"rows"`, or `"wal"`.
- `path`: Path to target SQLite database file (`.db`, `.sqlite`, `.sqlite3`).
- `table`: Optional table or view name (required for `"rows"`, optional filter for `"schema"`).
- `columns`: Optional list of specific column names to select in `"rows"`.
- `order_by`: Optional column name to sort by in `"rows"`.
- `order_desc`: Whether to sort descending when `order_by` is specified (default `false`).
- `limit`: Maximum rows or items to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `max_bytes`: Maximum file bytes to inspect (default 500MB, max 2GB).

<examples>
```
sqlite_inspect(action: "info", path: "app_data.db")
sqlite_inspect(action: "tables", path: "app_data.db")
sqlite_inspect(action: "schema", path: "app_data.db", table: "users")
sqlite_inspect(action: "rows", path: "app_data.db", table: "users", limit: 20)
sqlite_inspect(action: "rows", path: "app_data.db", table: "sessions", columns: ["id", "user_id", "created_at"], order_by: "created_at", order_desc: true)
sqlite_inspect(action: "wal", path: "app_data.db")
```
</examples>
