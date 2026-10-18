# droidasc

> Fast, zero-prep Android APK recon and queries: manifest dump, class listing, code cross-references (string, type, method, field, extends, impl), and on-demand single class decompilation.

## Source
- Entry: `packages/coding-agent/src/tools/droidasc.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/droidasc.md`
- Dependency detector: `packages/coding-agent/src/extensibility/skill-requirements.ts` (`droidasc` descriptor in `skill-tool-catalog.ts`)
- Upstream source: [MG1937/ASC](https://github.com/MG1937/ASC) (PyPI: `droidasc`)

## Input Scope & Limitations
- **Supported format**: Only Android `.apk` files are directly supported by `droidasc` (it operates on ZIP archives containing top-level `classes*.dex`).
- **Raw `.dex` files**: Not supported directly by `droidasc`. Use `dexdump` (e.g. `dexdump -d <file.dex>`) or `jadx` (e.g. `jadx -d ./artifacts/jadx_out <file.dex>`).
- **Android App Bundles (`.aab`)**: Not supported directly by `droidasc`. Convert to a universal APK via `bundletool` (`bundletool build-apks --bundle=<app.aab> --output=<app.apks> --mode=universal && unzip -p <app.apks> universal.apk > app.apk`) or decompile with `jadx`.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `op` | `manifest \| getmanifest \| findrefs \| getclass \| listclass` | Yes | Query operation to perform. |
| `target` | `string` | Yes | Path to an Android `.apk` file, resolved against session cwd. |
| `kind` | `string \| type \| method \| field \| extends \| impl` | No | Reference kind for `findrefs` (default: `string`). |
| `query` | `string` | conditional | Search keyword/pattern for `findrefs` (`string`, `type`), or method/field name. |
| `pattern` | `string` | No | Alias for `query`. |
| `name` | `string` | No | Method or field name for `findrefs` `method`/`field` search. |
| `class` | `string` | conditional | Target class name for `getclass`, target class/interface for `extends`/`impl`, or class filter for `method`/`field`. |
| `className` | `string` | No | Alias for `class`. |
| `fuzzy_class` | `boolean` | No | Whether to treat `--class` as fuzzy match for `method`/`field` `findrefs`. |
| `prefix` | `string` | No | Optional class/package prefix filter for `listclass` (e.g. `com.example` or `Lcom/example`). |
| `timeout` | `number >= 1` | No | Execution timeout seconds (default 30, clamped to 120). |
| `max_bytes` | `number >= 1` | No | Maximum output stdout bytes to capture before truncation (default 262144, max 4194304). |

## Outputs
- `manifest` / `getmanifest`: Decodes and dumps `AndroidManifest.xml` (package name, permissions, exported components, entrypoints).
- `listclass`: Lists Dalvik class descriptors across all DEX entries (filtered by `--prefix` if provided).
- `findrefs`: Cross-reference occurrences with class and method coordinates for string, type, method, field, extends, or impl.
- `getclass`: Single class Java source decompiled directly to output.
- Missing dependency notice: When `droidasc` CLI is not installed, returns a structured notice with trusted package manager hints and active fallback alternative commands (`jadx`, `apktool`, `aapt2`, `dexdump`).
- Output truncation: When stdout reaches the `max_bytes` cap and child process is terminated, the captured output is returned with `truncated: true` and `status: "ok"`, not treated as a process failure.
- `details` carries parsed metadata, dependency status, fallback information, output bytes, truncation status, and kind.

## Flow
1. `execute()` validates target path: resolves with `resolveReadPath()`, stats the file, rejects non-files, rejects `.dex` and `.aab` with informative guidance, rejects non-`.apk` files, and rejects files exceeding 1 GiB.
2. Operation parameters are validated: `findrefs` enforces requirements based on `kind`, `getclass` requires `class`.
3. Dependency status is checked via `droidascDependency()` (which consults `SKILL_TOOL_CATALOG.droidasc`).
4. If missing, a structured degradation notice with active fallbacks and installation hints is returned without failing the agent loop.
5. If present, runs the `droidasc` CLI subcommand (`getmanifest`, `listclass`, `findrefs`, `getclass`) with piped streams, timeout protection, output truncation cap, and signal cancellation.

## Limits & Caps
- `MAX_FILE_BYTES = 1 GiB`.
- `DEFAULT_TIMEOUT_SECONDS = 30`, `MAX_TIMEOUT_SECONDS = 120`.
- `DEFAULT_MAX_BYTES = 256 KiB`, `MAX_OUTPUT_BYTES = 4 MiB`.

## Side Effects
- Strictly read-only against the target APK file. Never modifies the target binary.
- Invokes `droidasc` CLI as an isolated external process with bounded parameters; no arbitrary shell execution.
