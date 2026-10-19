---
name: android-reverse
description: Android application and native library reverse engineering specialist. Focuses on APK/DEX static decompilation, smali patching, JNI native library triage, and ADB/Frida dynamic instrumentation.
metadata:
  requiresOptional: jadx, apktool, adb, frida, droidasc, unidbg, bundletool, dex2jar, baksmali, scrcpy
  capabilities: apk_unpacking, android_native_emulation
---

# Android Reverse Engineering Specialist

`android-reverse` is the specialized domain skill for analyzing Android packages (`.apk`, `.aab`, `.dex`) and JNI native libraries (`.so`). It operates within authorized laboratory environments, applying static-dynamic verification loops and evidence-based reporting.

For full cross-platform routing, consult `skill://reverse-lab/SKILL.md`.

---

## 1. Operating Contract & Evidence Standards

- **Target Authorization & Environment**: Operators MUST execute dynamic analysis, smali modifications, and runtime TLS unpinning exclusively against explicitly authorized test targets in isolated laboratory environments.
- **Sample Immutability & Artifact Isolation**: Operators MUST preserve original APK and DEX binaries strictly read-only. All smali patches, re-signed packages, decompiled sources, and Frida scripts MUST be written to separate dedicated artifact paths (`./artifacts/`).
- **Evidence Verification**: Claims MUST cite concrete coordinates:
  - Class name + method signature (e.g. `com.example.app.auth.TokenValidator.check(Ljava/lang/String;)Z`)
  - Line number in decompiled Java source
  - Smali instruction opcode and offset (e.g. `if-eqz v0, :cond_0` at offset `0x0028`)
  - JNI exported symbol name and ELF offset

Read `skill://reverse-lab/references/evidence.md` for artifact formats.

---

## 2. Toolchain & Canonical Capability Mapping

### Canonical Capabilities

| Canonical Capability ID | Analytical Scenario | Recommended Native Tool | Optional External Tools | Trusted Setup Command | Fallback Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`apk_unpacking`** | Container triage, DEX decompilation, manifest decoding, smali patching | `android_package_inspect` (built-in) / `droidasc` | `jadx`, `apktool`, `baksmali`, `dexdump` | `reverse setup reverse jadx` / `apktool` | `droidasc` ➔ `dexdump` ➔ `unzip -p <apk> AndroidManifest.xml` / `strings` |
| **`android_native_emulation`** | Headless ARM32/ARM64 CPU emulation and JNI invocation of native `.so` crypto algorithms without a device | `android_native_workflow` (built-in triage) | `unidbg` (Maven Java harness) | `reverse setup reverse unidbg` | `frida` / `frida_session` (live device) ➔ static `r2_inspect` / `ghidra_inspect` / `readelf` |

### Core Toolchain & Prerequisites

- **Native Package & DEX Inspector (`android_package_inspect`)**: BUILT-IN (Zero-dependency). Recommended first-stop for native inspection of Android packages (`.apk`, `.aab`, `.apks`) and bare Dalvik executables (`.dex`). Parses container entries, DEX headers/classes, Android Binary XML manifests, signature schemes (v1, v2, v3, v3.1, SourceStamp), and resource trees in-process with optional bridges for `apksigner` and `aapt2`.
- **On-Demand DEX Query Tool (`droidasc`)**: OPTIONAL (Built-in tool). Recommended for instant (<1s) manifest extraction, class listing, code cross-references (string, method, type, field, extends, impl), and single-class decompilation directly against APK packages without JVM memory pressure (for raw `.dex` or `.aab`, use `dexdump` or `jadx`). Model directly calls `droidasc` (returns structured degradation notices and fallbacks when CLI is missing).
- **Primary Decompiler (`jadx`)**: OPTIONAL external decompiler. Used for structured Java decompilation, control flow analysis, and cross-reference mapping.
- **Resource & Smali Engine (`apktool`)**: OPTIONAL external tool. Used for decoding XML resources (`res/values/strings.xml`) and smali bytecode re-assembly.
- **Native SO, JNI & Emulation Orchestration (`android_native_workflow`, `unidbg`)**: OPTIONAL (Built-in tool `android_native_workflow`). Use `android_native_workflow` to inventory native `.so` libraries, parse ELF machine architectures, map JNI exported functions (`Java_*`), link DEX native declarations (`ACC_NATIVE`) to dynamic `RegisterNatives` / `JNI_OnLoad`, and extract libraries directly to `./artifacts/extracted_so/`. When analyzing native cryptography or token algorithms without a connected phone or emulator, invoke `unidbg` to emulate ARM instructions headlessly on the host JVM.
- **Dynamic Instrumentation (`frida`, `frida_session`, `adb_observe`, `adb`)**: OPTIONAL. Use the built-in `frida` tool for open dynamic execution and inspection: execute custom Frida JavaScript scripts (`script` or `script_path`) against processes via attach (`pid`/`process`) or spawn (`spawn`), supporting hook implementation replacement and memory inspection, as well as device discovery, process enumeration, module listing, and trace observation; record dynamic evidence to `./artifacts` and cite in evidence findings. Use the built-in `frida_session` tool for persistent multi-turn dynamic analysis sessions with active child/target persistence (create/run/status/stop/destroy) without re-attaching each turn. Use the built-in `adb_observe` tool for read-only device evidence with fixed commands: device discovery, installed packages, running processes, bounded logcat, system properties, and screenshots saved as artifacts.

### Capability Resolution & Dispatch Protocol (Discover-Before-Stop / Install-Then-Dispatch)

When an analytical task requires decompilation or emulation, operators MUST NOT guess command paths or halt with missing-tool errors. Instead, follow the canonical 5-step lifecycle:

1. **Resolve Capability (`reverse_capability`)**:
   Query capability status before tool invocation:
   ```json
   reverse_capability({ action: "resolve", capability: "apk_unpacking" })
   // or
   reverse_capability({ action: "resolve", capability: "android_native_emulation" })
   ```
2. **Evaluate Native Baseline & Notice**:
   - If the built-in native tool (`android_package_inspect`, `droidasc`, or `android_native_workflow`) provides sufficient evidence for the task, dispatch it immediately without setup delays.
   - When advanced deep-dive analysis requires an external tool (`jadx`, `apktool`, `unidbg`) that is missing from PATH, formulate the structured capability notice:
     ```text
     [Capability Notice] Required capability: <capability_id> ('<capability_name>')
       -> Recommended tool: '<tool>' (Status: missing)
       -> Why: <why>
       -> Prerequisites: <prerequisites>
       -> Trusted setup: <setupCommand> (Requires operator approval)
       -> Post-install invocation: <postInstallInvocation>
       -> Fallback if declined: '<fallback_tool>'
     ```
   - Request operator approval before running setup.
3. **Execute Trusted Setup**:
   The operator runs `reverse setup reverse <tool>` (e.g. `reverse setup reverse jadx`, `reverse setup reverse apktool`, or `reverse setup reverse unidbg`).
4. **Re-Resolve Capability Post-Install**:
   Verify tool readiness by re-resolving with `refresh: true`:
   ```json
   reverse_capability({ action: "resolve", capability: "<capability_id>", refresh: true })
   ```
   Confirm `status: "ready"` before dispatching.
5. **Dispatch Tool or Engage Fallback**:
   - **If installed & verified**: Dispatch the external tool using its canonical post-install syntax (e.g. `jadx -d ./artifacts/jadx_out --single-class "<class>" <target.apk>`). Record the successful install-after resume in `reverse_workflow`:
     ```json
     reverse_workflow({
       action: "record",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       status: "completed",
       outputs: "Decompiled target class with verified jadx",
       evidence_ids: ["ev_fact_<id>"],
       capability_id: "apk_unpacking",
       installed_tool: "jadx",
       setup_command: "reverse setup reverse jadx",
       verified: true,
       strategy: "resume_original",
       resumed_at: "2026-10-18T01:00:00Z"
     })
     ```
   - **If declined or prerequisite missing**: Gracefully engage the active fallback tool (`droidasc`, `dexdump`, `r2_inspect`) without halting the investigation:
     ```json
     reverse_workflow({
       action: "record",
       workflow_id: "<wf_id>",
       step_id: "<step_id>",
       status: "completed",
       outputs: "Operator declined jadx setup; engaged fallback droidasc",
       fallback_tool: "droidasc",
       evidence_ids: ["ev_fact_<id>"],
       capability_id: "apk_unpacking",
       strategy: "fallback"
     })
     ```

When primary tools are absent, operators SHOULD consult `skill://reverse-lab/references/tool-fallback.md` for graceful degradation to alternative tools.

---

## 3. Recommended Workflow

1. **Reconnaissance & Manifest (`apk_unpacking`)**:
   - Perform initial container and binary triage via built-in `android_package_inspect(action: "info", path: "<target.apk>")` (or for bare `.dex` / `.aab`).
   - Verify signing schemes and APK Signing Block presence via `android_package_inspect(action: "signing", path: "<target.apk>")`.
   - Extract package entrypoints, permissions, and exported components using the built-in tool `droidasc(op: "manifest", target: "<target.apk>")` (or fallback CLI `aapt2 dump badging <target.apk>`).
   - Survey defined classes using `droidasc(op: "listclass", target: "<target.apk>", prefix: "<package.prefix>")` (or fallback `dexdump -f <target.apk>`).
2. **Search-First Decompilation (`apk_unpacking`)**:
   - Query target keywords (`api/v2/auth`, `checkLicense`, `SecretKeySpec`) via `droidasc(op: "findrefs", target: "<target.apk>", kind: "string", query: "<keyword>")`.
   - Query method or symbol cross-references via `droidasc(op: "findrefs", target: "<target.apk>", kind: "method", query: "<methodName>", class: "<className>")`.
   - Decompile target classes directly via `droidasc(op: "getclass", target: "<target.apk>", class: "<class.name>")` for instant JVM-free analysis.
   - For full high-level Java source recovery, resolve capability `reverse_capability({ action: "resolve", capability: "apk_unpacking" })` and dispatch `jadx -d ./artifacts/jadx_out --single-class "<class.name>" <target.apk>`.
3. **Native Library (.so) & JNI Emulation (`android_native_emulation`)**:
   - Inventory package native libraries, ABI architectures, and JNI bindings via built-in tool `android_native_workflow(action: "inspect", path: "<target.apk>")`.
   - Extract target `.so` binaries safely into artifacts using `android_native_workflow(action: "extract", path: "<target.apk>", abi: "arm64-v8a")`.
   - Formulate structured analysis steps and verify toolchain availability using `android_native_workflow(action: "plan", path: "<target.apk>")`.
   - When analyzing native cryptography or token algorithms without a physical Android device or emulator, resolve capability `reverse_capability({ action: "resolve", capability: "android_native_emulation" })`. If `unidbg` is missing, present setup notice for `reverse setup reverse unidbg`, re-resolve with `refresh: true`, and dispatch headless JNI emulation; fallback to static disassembly via `r2_inspect` or `ghidra_inspect` if declined.
4. **Smali Modification & Static Patching (Authorized Targets Only) (`apk_unpacking`)**:
   - Resolve capability `apk_unpacking` for resource decoding and smali rebuilding.
   - Decode bytecode with `apktool d <target.apk> -o ./artifacts/apk_src`.
   - Invert conditional branches (`if-eqz` ➔ `if-nez`) or force return values (`const/4 v0, 0x1` / `return v0`).
   - Re-assemble with `apktool b`, align with `zipalign`, and sign with `apksigner`, saving exclusively to `./artifacts/`.
5. **Dynamic Verification (Isolated Runtime Only)**:
   - Start with `adb_observe(action: "devices")`, then pass the target `serial` explicitly whenever more than one device is attached.
   - Confirm the running package and process with `adb_observe(action: "packages", serial: "<serial>", package: "<package>")` and `adb_observe(action: "processes", serial: "<serial>", package: "<package>")`.
   - Inspect build properties with `adb_observe(action: "props", serial: "<serial>", filter: "ro.build")`, and capture bounded runtime evidence with `adb_observe(action: "logcat", serial: "<serial>", filter: "<TAG>:I", lines: 300)`.
   - Save screenshots with `adb_observe(action: "screencap", serial: "<serial>")`; the PNG is written to an artifact (`artifactId`/`artifactPath`) instead of being embedded in context.
   - Trace method parameters and verify TLS validation behavior using isolated Frida hooks via `adb`, saving session logs to `./artifacts/`.
   - When `adb` is unavailable or the device is unauthorized/offline, follow the structured status and fallback notice instead of guessing. `adb_observe` never installs, pushes, reboot, or runs arbitrary shell commands.

Read `skill://reverse-lab/references/android.md` for complete technical walkthroughs and Frida hook templates.
