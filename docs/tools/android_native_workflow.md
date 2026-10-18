# android_native_workflow

> Native zero-dependency reverse engineering inspection, planning, and extraction for Android native shared libraries (`.so`), JNI exports, and Dalvik/DEX native method links (`RegisterNatives`).

## Overview

The `android_native_workflow` tool bridges the gap between high-level Android application packages (`.apk`, `.aab`) and compiled native C/C++ shared libraries (`lib/<abi>/*.so`). It operates without external runtime dependencies for static triage and extraction, and provides deterministic workflow planning for deconstruction, dynamic injection, and headless emulation:

- **Zero-Dependency Native SO & ELF Triage**: In-process TypeScript ELF parser extracting machine architecture (ARM, AArch64, x86, x86_64), bitness, endianness, dynamic symbols, JNI export functions (`Java_*`), `JNI_OnLoad` / `JNI_OnUnload` entrypoints, and `DT_NEEDED` library dependencies.
- **DEX Native Method Cross-Referencing**: Decodes Dalvik `class_data_item` entries across package DEX files to identify methods with the `ACC_NATIVE` flag, derives expected standard JNI symbol names via Oracle JNI specifications, and cross-references whether the method is bound via static symbol export or dynamically through `RegisterNatives`.
- **Anti-Analysis & Packer Detection**: Scans for known commercial Android packers (`libjiagu.so`, `libsecmain.so`, `libtup.so`, `libDexHelper.so`, `libprotectClass.so`) and anti-debugging indicators (`ptrace`, `/proc/self/status` TracerPid, debugger detection strings).
- **Deterministic 6-Stage Workflow Planning**: Formulates structured reverse engineering plans (Unpack ➔ Decompile ➔ Disassemble ➔ Dynamic Inject ➔ Emulate ➔ Record Evidence) with concrete commands, missing dependency identification, and fallback routing (Frida live device vs Unidbg JVM emulation).
- **In-Process SO Extraction**: Decompresses `.so` libraries and manifests from APK archives directly into `./artifacts/extracted_so/` using internal deflate decompression without requiring `unzip`, `apktool`, or command-line subprocesses.
- **Companion Toolchain Status**: Queries system availability for Unidbg, JADX, Apktool, ADB, Frida, Droidasc, AAPT2, Bundletool, Dex2jar, Baksmali, Scrcpy, and Java.

---

## Actions

| Action | Description |
| --- | --- |
| `inspect` | Performs comprehensive static inventory of native libraries, ELF headers, dynamic symbols, DEX native methods, manifest native attributes, and anti-analysis markers. |
| `plan` | Generates a deterministic 6-stage reverse engineering plan with tool statuses, missing dependency detections, and fallback recommendations. |
| `status` | Checks installation status, paths, and capability readiness of the complete Android reverse toolchain. |
| `extract` | Decompresses native `.so` files and manifest from target APK into a designated output directory (`./artifacts/extracted_so/`). |

---

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"inspect" \| "plan" \| "status" \| "extract"` | Yes | Workflow action to execute. |
| `path` / `target` | `string` | Conditional | Path to target Android package (`.apk`, `.aab`, `.zip`) or directory containing native shared libraries. Required for `inspect`, `plan`, and `extract`. |
| `abi` | `string` | No | Optional ABI architecture filter (e.g. `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`). |
| `library` / `so_name` | `string` | No | Optional native library name filter (e.g. `libnative-crypto.so`). |
| `class_filter` | `string` | No | Optional substring filter for Java/Kotlin class names declaring native methods. |
| `output_dir` | `string` | No | Destination directory for `extract` action (default `./artifacts/extracted_so`). |
| `format` | `"markdown" \| "json"` | No | Output representation format (default `markdown`). |
| `limit` | integer `>= 1` | No | Maximum items displayed in tables (default 50, max 200). |
| `offset` | integer `>= 0` | No | Zero-based pagination offset for native method listing (default 0). |

---

## Workflow Integration & Tool Ladder

```
[Target APK]
     │
     ├──> android_native_workflow(action: "inspect")
     │         │
     │         ├──> Inventories lib/<abi>/*.so (ARM32/ARM64 ELF headers, Java_* exports)
     │         ├──> Identifies DEX native declarations & JNI_OnLoad RegisterNatives
     │         └──> Detects anti-analysis / packer markers (ptrace, libjiagu)
     │
     ├──> android_native_workflow(action: "extract")
     │         │
     │         └──> Unpacks lib/<abi>/*.so safely into ./artifacts/extracted_so/
     │
     └──> android_native_workflow(action: "plan")
               │
               ├── Stage 1: Unpack (android_native_workflow)
               ├── Stage 2: Decompile (jadx / droidasc)
               ├── Stage 3: Disassemble (r2_inspect / ghidra_inspect)
               ├── Stage 4: Dynamic Inject (frida_session via adb) [Device Available]
               ├── Stage 5: Headless CPU Emulation (unidbg via JVM) [No Device / Offline]
               └── Stage 6: Record Evidence (evidence ledger)
```

---

## Examples

### 1. Check Toolchain Status
```typescript
android_native_workflow({ action: "status" })
```

### 2. Inspect APK Native Libraries & JNI Declarations
```typescript
android_native_workflow({
  action: "inspect",
  path: "samples/app-release.apk"
})
```

### 3. Generate Reverse Engineering Plan
```typescript
android_native_workflow({
  action: "plan",
  path: "samples/app-release.apk"
})
```

### 4. Extract Specific Native Architecture
```typescript
android_native_workflow({
  action: "extract",
  path: "samples/app-release.apk",
  abi: "arm64-v8a",
  output_dir: "./artifacts/arm64_libs"
})
```

---

## Safety & Licensing Boundary

- **Pure Read-Only Inspection**: In-process analysis operates without executing target binaries, native instructions, or untrusted shell scripts.
- **Artifact Isolation**: Extracted shared libraries are written exclusively to isolated artifact directories (`./artifacts/`), leaving original APK containers immutable.
- **Clean-Room TypeScript**: Native ELF and DEX parsing logic is implemented from public standard specifications under permissive licensing; no copyleft (GPL/AGPL) code is embedded.
