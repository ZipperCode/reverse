Static inspection, VLQ mapping lookup, and source code reconstruction from JavaScript SourceMaps (both direct `.map` files and inline `sourceMappingURL` directives).

Capabilities:
- **SourceMap Metadata (`info`)**:
  - Parses SourceMap v3 JSON headers, version, sourceRoot, and target compiled file.
  - Catalogs original source file paths (`sources`) and identifier names (`names`).
  - Reports `sourcesContent` embedding status and mapping line counts.
- **VLQ Coordinate Lookup (`lookup`)**:
  - Maps generated compiled positions (`line:column`) in minified JavaScript back to original source file, line number, column offset, and original symbol name.
  - Renders multi-line source code context snippets (+/- 3 lines) around the original target line when `sourcesContent` is embedded.
- **Source Code Recovery (`extract`)**:
  - Reconstructs original unminified JavaScript/TypeScript files embedded inside the `sourcesContent` array.
  - Can return recovered file contents directly in structured output or safely save to a local directory (`destination_dir`) with strict path traversal protections.
- **Directive Resolution**:
  - Automatically locates and extracts SourceMaps referenced in `.js` or `.ts` files via inline Base64 data URIs (`data:application/json;base64,...`), inline URIs, relative `.map` file paths, or adjacent `.map` files.
  - Remote HTTP/HTTPS URLs are strictly rejected to guarantee zero network leakage and completely offline execution.

Inputs:
- `action`: `"info"`, `"lookup"`, or `"extract"`.
- `path`: Path to a `.map` file or compiled `.js`/`.ts` bundle file.
- `line`: 1-based line number in compiled code for `lookup`.
- `column`: Column offset in compiled code for `lookup` (default 0-based).
- `column_zero_based`: Whether the column offset is 0-based (default `true`).
- `source_index`: Specific source index (0-based) for `extract`.
- `source_path`: Substring or extension filter for `extract` (e.g. `authService.ts`).
- `destination_dir`: Optional local directory to save extracted original files.
- `limit`: Maximum items to display or files to extract (default 50, max 500).
- `skip`: Pagination offset for sources or names list (default 0).
- `max_bytes`: Maximum file bytes to read (default 5MB, max 50MB).

<examples>
```
sourcemap_inspect(action: "info", path: "dist/bundle.js.map")
sourcemap_inspect(action: "info", path: "dist/app.min.js")
sourcemap_inspect(action: "lookup", path: "dist/app.min.js", line: 1, column: 15420)
sourcemap_inspect(action: "extract", path: "dist/bundle.js.map", source_path: "auth")
sourcemap_inspect(action: "extract", path: "dist/bundle.js.map", destination_dir: "./recovered-src")
```
</examples>
