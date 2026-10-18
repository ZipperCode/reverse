Native offline read-only Go and Rust binary metadata inspection without execution or external carvers.

Capabilities:
- **Metadata Summary & Language Detection (`info`)**:
  - Automatically identifies executable format (ELF 32/64-bit, PE32/PE32+, Apple Mach-O 32/64-bit, Fat/Universal binaries, or raw executable).
  - Determines compiler/runtime family: Go (`gc`, `gccgo`), Rust (`rustc`), C/C++, or unknown.
  - Go summary: runtime version (e.g. `go1.22.4`), main module path, total dependencies, CGO enabled status, VCS commit/revision.
  - Rust summary: rustc compiler version and commit hash, cargo-auditable dependency tracking status, total crate packages, panic runtime (`unwind` vs `abort`), memory allocator (`jemalloc`, `mimalloc`, `system`).
- **Go Build & Module Inspection (`go`)**:
  - Parses Go build info table and embedded module descriptors (`runtime/debug.BuildInfo`).
  - Catalogs all compiled Go dependencies (`dep`) with module paths, semantic versions, and cryptographic checksums (`h1:...`).
  - Extracts key-value build settings: compiler flags, `CGO_ENABLED`, `GOARCH`, `GOOS`, `vcs.revision`, `vcs.time`, `vcs.modified`, `-ldflags`.
  - Paged with `limit` and `offset`, filterable with substring `filter`.
- **Rust Audit & Crate Inspection (`rust`)**:
  - Decodes `cargo-auditable` dependency metadata embedded in `.dep-v0` sections (zlib-compressed JSON dependency graph).
  - Catalogs all crate packages with crate name, semantic version, source repository (`crates.io`, git, path), and dependency links.
  - Extracts rustc version, commit hash, panic handler markers, and memory allocator heuristics.
  - Paged with `limit` and `offset`, filterable with substring `filter`.
- **Section & Marker Layout (`sections`)**:
  - Catalogs binary sections and highlights Go/Rust specific segments: `.go.buildinfo`, `.gopclntab`, `.gosymtab`, `.note.go.buildid`, `.dep-v0`, `.rustc`, `.rmeta`.

Inputs:
- `action`: `"info"`, `"go"`, `"rust"`, or `"sections"`.
- `path`: Path to target binary file.
- `filter`: Optional case-insensitive substring filter for dependencies, crates, or modules.
- `limit`: Maximum dependency or package records to return (default 50, max 500).
- `offset`: Pagination offset (default 0).
- `max_bytes`: Maximum binary bytes to read (default 64MB, max 256MB).

<examples>
```
binary_metadata_inspect(action: "info", path: "app")
binary_metadata_inspect(action: "go", path: "server", filter: "crypto")
binary_metadata_inspect(action: "rust", path: "cli_tool", limit: 30)
binary_metadata_inspect(action: "sections", path: "libcore.so")
```
</examples>
