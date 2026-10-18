# binary_metadata_inspect

> Native offline read-only Go and Rust binary metadata inspection without execution or external carvers.

## Source
- Entry: `packages/coding-agent/src/tools/binary-metadata-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/binary-metadata-inspect.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"info" \| "go" \| "rust" \| "sections"` | Yes | `info` catalogs metadata summary, format, and detected compiler/language; `go` catalogs Go module path, runtime version, build settings, and dependencies; `rust` catalogs Rust cargo-auditable dependency packages, rustc version, and runtime hints; `sections` catalogs binary sections and metadata markers. |
| `path` | `string` | Yes | Path to target binary (ELF, PE, Mach-O, or raw executable). |
| `filter` | `string` | No | Optional case-insensitive substring filter for dependencies, crates, or modules. |
| `limit` | `number >= 1` | No | Maximum dependency or package records to return (default 50, max 500). |
| `offset` | `number >= 0` | No | Pagination offset (default 0). |
| `max_bytes` | `number >= 1` | No | Maximum binary bytes to inspect (default 64MB, max 256MB). |

## Capabilities & Analysis
- **Binary Format & Language Classification (`info`)**:
  - Automatically identifies container executable format: ELF 32/64-bit, Microsoft PE/PE32+, Apple Mach-O 32/64-bit, universal/fat binaries, or raw executables.
  - Determines compiler and language runtime (Go, Rust, C/C++, or unknown).
  - Summarizes Go runtime version, module name, total dependencies, CGO enabled flag, and VCS commit.
  - Summarizes Rust rustc version, commit hash, cargo-auditable package count, panic strategy, and allocator.
- **Go Build Information & Dependencies (`go`)**:
  - Parses Go build info table and embedded module descriptors (`runtime/debug.BuildInfo`).
  - Catalogs compiled Go dependencies (`dep`) with module paths, semantic versions, and cryptographic checksums (`h1:...`).
  - Extracts key-value build settings: compiler flags, `CGO_ENABLED`, `GOARCH`, `GOOS`, `vcs.revision`, `vcs.time`, `vcs.modified`, `-ldflags`.
  - Paged with `limit` and `offset`, filterable with substring `filter`.
- **Rust Cargo-Auditable & Crate Inspection (`rust`)**:
  - Decodes `cargo-auditable` dependency metadata embedded in `.dep-v0` sections (zlib-compressed JSON dependency graph).
  - Catalogs all crate packages with crate name, semantic version, source repository (`crates.io`, git, path), and dependency links.
  - Extracts rustc version, commit hash, panic handler markers (`unwind` vs `abort`), and memory allocator heuristics (`jemalloc`, `mimalloc`, `system`).
  - Paged with `limit` and `offset`, filterable with substring `filter`.
- **Section & Marker Layout (`sections`)**:
  - Catalogs binary sections and highlights Go/Rust specific segments: `.go.buildinfo`, `.gopclntab`, `.gosymtab`, `.note.go.buildid`, `.dep-v0`, `.rustc`, `.rmeta`.
- **Structured Unknown / Clean Reporting**:
  - When provided a binary without Go or Rust metadata, cleanly reports `language: "unknown"`, `isGo: false`, `isRust: false`, and explanatory notes without throwing exceptions.

## Security & Operational Boundaries
- **Strictly Read-Only**: Performs memory-bounded buffer reading and parsing.
- **No Code Execution**: Does not execute the binary or invoke external compilers/tools.
- **Bounded Resource Consumption**: Limits maximum read bytes (up to 256MB) and paginates lists.

## Registration Details
- `name`: `binary_metadata_inspect`
- `approval`: `read`
- `loadMode`: `discoverable`
- `strict`: `true`
