# android_package_inspect

> Native read-only inspection of Android application packages (`.apk`), Android App Bundles (`.aab`), APK sets (`.apks`), and Dalvik executables (`.dex`) without external dependencies.

## Source
- Entry: `packages/coding-agent/src/tools/android-package-inspect.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/android-package-inspect.md`

## Overview
`android_package_inspect` provides comprehensive, in-process static triage and deep inspection for Android containers and binaries. It parses ZIP Central Directory entries, extracts and summarizes multi-DEX Dalvik headers and class definitions, parses Android Binary XML (AXML) manifests into structured metadata, verifies signature scheme evidence (v1 JAR signing, v2, v3, v3.1, and SourceStamp APK Signing Blocks), and categorizes resource structures (including `resources.arsc`). It optionally bridges to external `apksigner` and `aapt2` tools when installed, degrading gracefully to structured missing dependency hints when external tools are absent.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `info \| manifest \| dex \| signing \| resources` | Yes | Inspection action to perform. |
| `path` | `string` | No* | Path to target package or binary (.apk, .aab, .apks, .dex). |
| `target` | `string` | No* | Alias for `path`. (*One of `path` or `target` is required). |
| `dex_index` | `number >= 0` | No | Zero-based index of DEX file to inspect in multi-DEX packages. |
| `dex` | `string` | No | DEX filename filter (e.g. `classes2.dex`). |
| `filter` | `string` | No | Substring filter across class descriptors (`dex`) or resource entries (`resources`). |
| `limit` | `number >= 1` | No | Maximum list entries returned (default 50, max 500). |
| `offset` | `number >= 0` | No | Zero-based pagination offset (default 0). |
| `use_bridge` | `boolean` | No | Whether to invoke installed external tools (`apksigner`/`aapt2`) for bridge output (default `false`). |
| `max_bytes` | `number >= 1` | No | Maximum file bytes to read (default 200 MiB, max 500 MiB). |

## Actions

### `info`
Provides high-level container and binary triage:
- **Package Container (.apk, .aab, .apks)**: Container format, size, SHA-256 digest, total entry count, `AndroidManifest.xml` presence, DEX files list with counts, native libraries grouped by ABI (`lib/<abi>/*.so`), resource breakdown, and signature scheme presence flags.
- **Bare DEX (.dex)**: Dalvik VM header analysis (version, checksum, SHA-1 signature, file size, endianness, class count, method count, field count, prototype count, string count, type count), map offset, and sample class descriptors.

### `manifest`
Extracts bounded metadata from `AndroidManifest.xml`:
- Package name, `versionCode`, `versionName`
- SDK constraints: `minSdkVersion`, `targetSdkVersion`, `compileSdkVersion`
- Permissions: requested (`<uses-permission>`) and declared (`<permission>`)
- Application configuration: label, name, icon, debuggable, allowBackup
- Components: declared Activities, Services, Broadcast Receivers, and Content Providers with exported flags
- Safely decodes Android Binary XML (AXML) and text XML; returns structured `status: "unsupported"` without fake decoded values if manifest is in compiled Protobuf format (common in AAB).
- Not applicable to bare `.dex` files.

### `dex`
Detailed Dalvik header summaries and class descriptor listing:
- Per-DEX header metrics (version, classes count, methods count, fields count, data size/offset)
- Class descriptor listing (e.g. `com.example.app.MainActivity`), access flags (public, final, interface, abstract, etc.), and superclasses
- Supports pagination (`limit`, `offset`) and search filtering (`filter`)
- Works seamlessly on both bare `.dex` binaries and packaged `.apk`/`.aab` containers.

### `signing`
Inspects signing status and scheme evidence:
- **v1 JAR Signing**: Presence of `META-INF/MANIFEST.MF`, signature files (`*.SF`), and signature block files (`*.RSA`, `*.DSA`, `*.EC`).
- **APK Signing Block (v2, v3, v3.1)**: Parses the binary APK Signing Block preceding the ZIP Central Directory, reporting presence of v2 Scheme (`0x7109871a`), v3 Scheme (`0xf05368c0`), v3.1 Scheme (`0x1b93ad61`), and SourceStamp (`0x42726577`).
- **Optional `apksigner` Bridge**: Checks for external `apksigner` CLI tool. When `use_bridge: true` and tool is present, runs `apksigner verify --verbose` to confirm cryptographic validity; when absent, provides structured installation hints.
- Not applicable to bare `.dex` files.

### `resources`
Analyzes package resource trees:
- `resources.arsc` existence, size, header validation, package count, and package identifier
- Categorized breakdown of resource files: Layouts (`res/layout*`), Drawables (`res/drawable*`, `res/mipmap*`), Values (`res/values*`), XML (`res/xml*`), Raw assets (`res/raw*`), and Assets (`assets/*`)
- Supports substring filtering across resource filenames
- Optional `aapt2` bridge status and structured installation hints.
- Not applicable to bare `.dex` files.

## Unsupported Targets & Error Handling
- When pointed at non-Android files (e.g. ELF, PE, Mach-O, plain text), returns structured `status: "unsupported"` explaining the format discrepancy without throwing unhandled exceptions.
- Missing files throw standard `ToolError("Target file not found: ...")`.
- Directory targets throw `ToolError("Target path is a directory, not a file: ...")`.
