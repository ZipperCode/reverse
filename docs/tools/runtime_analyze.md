# runtime_analyze

> Cross-runtime deep inspection and analysis for Flutter (AOT), React Native / Hermes, and Unity IL2CPP applications. Composes established upstream reverse engineering engines with bounded outputs, version validation, and structured tool handoffs.

## Source
- Entry: `packages/coding-agent/src/tools/runtime-analyze.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/runtime-analyze.md`

## Upstream References & Engines
- **Hermes Bytecode Disassembly**:
  - `hbctool`: [https://github.com/bongtrop/hbctool](https://github.com/bongtrop/hbctool) (supports HBC versions 59, 62, 74, 76)
  - `hermes-dec`: [https://github.com/P1sec/hermes-dec](https://github.com/P1sec/hermes-dec) (supports HBC versions 61–96)
- **Unity IL2CPP Reconstruction**:
  - `Il2CppDumper`: [https://github.com/Perfare/Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (supports Unity 5.3–2022.2, metadata versions 16–29)
- **Flutter Android AOT Disassembly**:
  - `Blutter`: [https://github.com/worawit/blutter](https://github.com/worawit/blutter) (supports Android arm64-v8a AOT snapshots with matching Dart VM builds)

## Overview
Modern mobile and cross-platform applications frequently bundle runtimes that bypass standard Dalvik/DEX execution, compiling logic into framework-specific intermediate bytecode or native AOT snapshot blobs:
1. **React Native**: Uses Hermes Bytecode (`.hbc`) or JavaScript bundles (`index.android.bundle`). Hermes bytecode files begin with magic `0x1F1903C103BC1FC6` (`C6 1F BC 03 C1 03 19 1F`) followed by a 4-byte uint32 LE bytecode version. Plain JavaScript bundles are UTF-8 text and should not be routed to HBC disassemblers.
2. **Unity IL2CPP**: Ahead-of-time compiles C# assemblies into a native shared library (`libil2cpp.so` or `GameAssembly.dll`) paired with a global metadata container (`global-metadata.dat`). Valid metadata containers begin with sanity magic `0xFAB11BAF` (`AF 1B B1 FA` in little endian) followed by an int32 version (e.g. 24, 27, 29).
3. **Flutter**: Compiles Dart source into an AOT snapshot library (`libapp.so`) driven by the Flutter runtime engine (`libflutter.so`). `libapp.so` contains Dart VM instructions and data snapshots, exporting symbols such as `_kDartVmSnapshotData` and `_kDartVmSnapshotInstructions`.

`runtime_analyze` provides unified offline discovery (`inventory`) and targeted decompilation/disassembly adapters (`hermes`, `il2cpp`, `flutter`) that invoke client-installed tools safely under normal execution approval.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `inventory \| hermes \| il2cpp \| flutter` | Yes | Analysis action to execute. |
| `path` | `string` | Yes | Path to target APK, AAB, directory, `.bundle`, `.hbc`, `libapp.so`, `libil2cpp.so`, or `global-metadata.dat`. |
| `target` | `string` | No | Alias for `path`. |
| `metadata_path` | `string` | No | Optional path to `global-metadata.dat` for `il2cpp` if not adjacent to binary. |
| `engine_path` | `string` | No | Optional path to `libflutter.so` for `flutter` if not adjacent to `libapp.so`. |
| `output_dir` | `string` | No | Destination directory for generated artifacts (defaults to `./artifacts/runtime_analyze/<runtime>/<sample>/`). |
| `format` | `markdown \| json` | No | Output formatting (default `markdown`). |
| `limit` | `number >= 1` | No | Maximum items returned in lists (default 50, max 200). |
| `offset` | `number >= 0` | No | Zero-based pagination offset. |
| `timeout` | `number >= 1` | No | Subprocess execution timeout in seconds (default 60, max 300). |
| `max_bytes` | `number >= 1` | No | Maximum subprocess output bytes captured (default 262144, max 4194304). |

## Actions

### `inventory`
Performs zero-external-dependency inspection across packages, directories, or individual files to detect embedded cross-platform runtimes:
- Checks for React Native bundles and tests whether they are binary Hermes bytecode or plain text JavaScript. Reads HBC version directly from header bytes.
- Checks for Flutter AOT artifacts (`libapp.so`, `libflutter.so`, `flutter_assets`). Distinguishes Flutter Dart snapshots from generic ELF libraries.
- Checks for Unity IL2CPP binaries and validates `global-metadata.dat` magic and version.
- Returns target SHA-256 and byte size, detected frameworks, confidence, and recommended next actions.

### `hermes`
Disassembles React Native Hermes bytecode:
- Distinguishes plain JavaScript bundles from binary HBC. If plain JS is passed, returns `status: "unsupported"` and suggests `sourcemap_inspect` or `ast_grep`.
- Reads bytecode version. Checks version compatibility: `hbctool` supports HBC 59, 62, 74, 76; `hermes-dec` supports HBC 61–96.
- If backend is missing, returns structured `missing_dependency` with exact install command (`pipx install hbctool` or `pip install hermes-dec`).
- If backend is installed, executes disassembly into `./artifacts/runtime_analyze/hermes/` and returns bounded artifact summaries.

### `il2cpp`
Extracts and restores Unity IL2CPP definitions:
- Validates `global-metadata.dat` sanity magic (`0xFAB11BAF`) and version.
- Stages the actual Il2CppDumper payload and a private `config.json` with `RequireAnyKey: false`; invokes the staged executable or DLL with non-blocking stdin.
- Generates `dump.cs` (C# dummy classes), `il2cpp.h` (C++ declarations), and `script.json` (symbol offsets).
- Exports Ghidra script (`ghidra.py`) and IDA script (`ida_with_struct.py`) and provides direct execution commands to hand off to `ghidra_inspect` or IDA.

### `flutter`
Disassembles Flutter Android AOT compiled snapshots:
- Verifies ELF architecture: strictly enforces Android `arm64-v8a` (`EM_AARCH64`), reporting structured diagnostics for 32-bit ARM or x86 targets.
- Matches `libapp.so` and `libflutter.so` within the same package module and ABI, validates ELF machine compatibility, and extracts Dart VM version and snapshot flags.
- Invokes the exact matching prebuilt `blutter_dartvm<version>_android_arm64<suffix>` executable directly. Missing builds return `backend_build_required`; analysis does not launch `blutter.py` or silently fetch and compile Dart SDK sources.
- Generates assembly files (`asm/`), object pools (`objs.txt`, `pp.txt`), and Frida hook templates (`blutter_frida.js`).

## Engine Handoff
When `il2cpp` produces Ghidra or IDA helper scripts, the tool returns explicit structured handoff commands:
```text
ghidra_inspect(action: "analyze", path: "libil2cpp.so", script: "./artifacts/runtime_analyze/il2cpp/sample/ghidra.py")
```
This enables seamless static decompilation in Ghidra with recovered type and method names.

## Boundaries & Safety
- **Target Immutability**: Input APKs, bundles, and binaries are never modified in place.
- **Bounded Output**: Large disassembly listings are saved to disk artifacts, returning bounded summaries and metadata to conversation context.
- **Execution Approval**: Read-only `inventory` requires read approval; external backend invocation (`hermes`, `il2cpp`, `flutter`) requires exec approval.
