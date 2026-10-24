# android_native_workflow

> Native zero-dependency reverse engineering inspection, planning, and extraction for Android native shared libraries (`.so`), JNI exports, and Dalvik/DEX native method links (`RegisterNatives`).

## Overview

The `android_native_workflow` tool bridges the gap between high-level Android application packages (`.apk`, `.aab`) and compiled native C/C++ shared libraries (`lib/<abi>/*.so`). It operates without external runtime dependencies for static triage and extraction, and provides deterministic workflow planning for deconstruction, dynamic injection, and headless emulation:

- **Zero-Dependency Native SO & ELF Triage**: In-process TypeScript ELF parser extracting machine architecture (ARM, AArch64, x86, x86_64), bitness, endianness, dynamic symbols, verified JNI export functions (`Java_*`), `JNI_OnLoad` / `JNI_OnUnload` entrypoints, and `DT_NEEDED` library dependencies.
- **DEX Native Method Cross-Referencing**: Decodes Dalvik `class_data_item` entries across package DEX files to identify methods with the `ACC_NATIVE` flag, extracts the `isStatic` access flag (`ACC_STATIC`) to differentiate JNI `jclass` from `jobject`, derives expected standard and overloaded JNI symbol names via Oracle JNI specifications, and cross-references whether the method is bound via verified static symbol export or remains unverified with dynamic candidate library hints (`JNI_OnLoad` / `RegisterNatives`).
- **Anti-Analysis & Packer Detection**: Scans for known commercial Android packers (`libjiagu.so`, `libsecmain.so`, `libtup.so`, `libDexHelper.so`, `libprotectClass.so`, `libkwscmm.so`) and anti-debugging indicators (`ptrace`, `/proc/self/status` TracerPid, debugger detection strings).
- **Deterministic Actionable Workflow Planning (6-7 Stages)**: Formulates structured reverse engineering plans (Unpack ➔ Decompile ➔ Disassemble ➔ Dynamic Inject ➔ Emulate & Enrich ➔ Record Evidence) with concrete actionable parameters and artifact linkages (`./artifacts/<lib>_jni_registrations.json`). Routes unresolved dynamic registrations to Frida `jni_register` OR no-device Unidbg probe (`unidbg(action: "probe")`), feeds verified bindings into Ghidra JNI enrichment (`ghidra_inspect(action: "jni_enrich", events_path: "...")`), executes bounded JNI API trace (`frida(template: "jni_trace")`) and replay verification, and schedules memory dump & SoFixer reconstruction (`elf_inspect(action: "dump_and_repair")`) conditionally only when packed payloads require it.
- **In-Process SO Extraction**: Decompresses `.so` libraries and manifests from APK archives directly into `./artifacts/extracted_so/` using internal deflate decompression without requiring `unzip`, `apktool`, or command-line subprocesses.
- **Companion Toolchain Status**: Queries system availability for Unidbg, Ghidra, JADX, Apktool, ADB, Frida, Droidasc, AAPT2, Bundletool, Dex2jar, Baksmali, Scrcpy, Radare2, ElfInspect, and Java.
---

## Actions

| Action | Description |
| --- | --- |
| `inspect` | Performs comprehensive static inventory of native libraries, ELF headers, dynamic symbols, DEX native methods, manifest native attributes, and anti-analysis markers. |
| `plan` | Generates a deterministic reverse engineering plan (6 stages for standard libraries, 7 stages when packed payload reconstruction is required) with tool statuses, missing dependency detections, and fallback recommendations. |
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
[Target APK / .so]
     │
     ├──> android_native_workflow(action: "inspect")
     │         │
     │         ├──> Inventories lib/<abi>/*.so (ARM32/ARM64 ELF headers, Java_* exports)
     │         ├──> Identifies DEX native declarations with isStatic flag (ACC_STATIC)
     │         └──> Detects anti-analysis / packer markers (ptrace, libjiagu)
     │
     ├──> android_native_workflow(action: "extract")
     │         │
     │         └──> Unpacks lib/<abi>/*.so safely into ./artifacts/extracted_so/
     │
     └──> android_native_workflow(action: "plan")
               │
               ├── Stage 1: Unpack (android_native_workflow) -> ./artifacts/extracted_so/
               ├── Stage 2: Decompile Java/Kotlin call sites (jadx / android_package_inspect)
               ├── Stage 3: Disassemble, LIEF constructors & relocations (elf_inspect / r2_inspect)
               │            └── Optional FindCrypt candidate triage if crypto detected
               ├── Stage 4: Dynamic RegisterNatives discovery:
               │            ├── [Device Available] -> frida(action: "trace", template: "jni_register")
               │            └── [Device-Free / Offline] -> unidbg(action: "probe", callOnLoad: true)
               ├── Stage 5: Verified JNI enrichment, bounded trace & replay:
               │            ├── Apply confirmed records to Ghidra -> ghidra_inspect(action: "jni_enrich", events_path: "./artifacts/<lib>_jni_registrations.json")
               │            ├── Bounded JNI API trace -> frida(action: "trace", template: "jni_trace", max_events: 100)
               │            └── Input/output replay verification -> unidbg / replay
               ├── [Conditional] Dump & SoFixer Repair (only if concrete packed payload detected):
               │            └── elf_inspect(action: "dump_and_repair", pid: <target_pid>, module: "<lib>")
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
