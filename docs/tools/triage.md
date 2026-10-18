# triage

> Read-only multi-format binary, archive, and artifact reconnaissance: format detection, architecture, entrypoint, sections, entropy, and optional strings extraction. Operates with pure built-in Node/Bun runtime without requiring IDA Pro, radare2, or other external tools.

## Source
- Entry: `packages/coding-agent/src/tools/triage.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/triage.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `path` | `string` | Yes* | Path to target binary, package, or artifact to triage (*or alias `target`). |
| `target` | `string` | No | Alternative alias for `path`. |
| `strings` | `boolean` | No | Optional printable string extraction. Defaults to `false`. |
| `limit` | `number >= 1` | No | Maximum strings or section entries to display (default 50, capped at 500). |
| `min_length` | `number >= 1` | No | Minimum length of extracted strings (default 6, min 3). |
| `max_bytes` | `number >= 1` | No | Maximum bytes scanned for strings and sampled entropy (default 16 MiB). |

## Supported Formats
- **Windows PE**: PE32 and PE32+ (EXE, DLL, SYS), COFF machine architecture, entrypoint, subsystem, section table with raw/virtual sizes and section entropy.
- **Linux/POSIX ELF**: ELF32 and ELF64, little/big endian, machine architecture, entrypoint, section table and stripped status.
- **Mach-O (Thin)**: 32-bit and 64-bit Mach-O, CPU family/subtype, file type (EXECUTE, DYLIB, etc.), load commands, segment sections.
- **Mach-O (Fat / Universal)**: Multi-architecture universal binaries, slice count, CPU architectures, offsets, and sizes.
- **WebAssembly (WASM)**: Binary module magic, version, section catalog (type, import, function, table, memory, global, export, code, data, custom).
- **Android APK**: Package container recognition, `AndroidManifest.xml` and Dalvik `.dex` components.
- **Android DEX**: Dalvik Executable header, version, class/method/string/field/proto ID table counts.
- **Java Class**: `.class` compiled bytecode, major/minor release versions (Java 1.1 through Java 25+), constant pool size.
- **ZIP / JAR**: Central directory and local file entries, entry name preview, compressed vs uncompressed sizes.
- **Generic / Unknown**: Raw binary fallback reporting file size, SHA-256, Shannon entropy, and byte indicators.

## Outputs
- Single model-facing text block summarizing detected format, architecture, bitness, endianness, file size, SHA-256, entrypoint, entropy, indicators, section/entry table, extracted strings (when requested), and next-step tool hints.
- Structured `details` object containing parsed metadata, status (`"ok" \| "corrupt" \| "unsupported"`), section summaries, entropy metrics, indicators, and string arrays.
- Truncated strings spill to a session output artifact (`artifact://<id>`) when output limits are exceeded.

## Limits & Caps
- `MAX_FILE_BYTES = 512 MiB`: Target files exceeding 512 MiB are rejected with a descriptive `ToolError`.
- `DEFAULT_MAX_BYTES = 16 MiB`: Default prefix scanned for strings and Shannon entropy histogram sampling.
- `DEFAULT_LIST_LIMIT = 50`, `MAX_LIST_LIMIT = 500`: Section and string listings capped to prevent context flooding.
- `HEADER_SNIFF_BYTES = 64 KiB`: Initial header sniff buffer for multi-format magic and table detection.

## Side Effects
- Purely read-only; never creates or mutates target files.
- Uses streaming reads for SHA-256 and entropy computation, with bounded memory allocation.
- Zero external process spawns; zero third-party dependencies.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
