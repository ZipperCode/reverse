---
name: android-reverse
description: Android application and native library reverse engineering specialist. Focuses on APK/DEX static decompilation, smali patching, JNI native library triage, and ADB/Frida dynamic instrumentation.
metadata:
  requires: jadx
  requiresOptional: apktool, adb, frida, droidasc
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

## 2. Toolchain & Required Dependencies

- **Primary Decompiler (`jadx`)**: REQUIRED. Used for structured Java decompilation, control flow analysis, and cross-reference mapping.
- **Resource & Smali Engine (`apktool`)**: OPTIONAL. Used for decoding XML resources (`res/values/strings.xml`) and smali bytecode re-assembly.
- **On-Demand DEX Query Tool (`droidasc`)**: OPTIONAL (Built-in tool). Recommended for instant (<1s) manifest extraction, class listing, code cross-references (string, method, type, field, extends, impl), and single-class decompilation directly against APK packages without JVM memory pressure (for raw `.dex` or `.aab`, use `dexdump` or `jadx`). Model directly calls `droidasc` (returns structured degradation notices and fallbacks when CLI is missing).
- **Dynamic Instrumentation (`frida`, `frida_session`, `adb_observe`, `adb`)**: OPTIONAL. Use the built-in `frida` tool for open dynamic execution and inspection: execute custom Frida JavaScript scripts (`script` or `script_path`) against processes via attach (`pid`/`process`) or spawn (`spawn`), supporting hook implementation replacement and memory inspection, as well as device discovery, process enumeration, module listing, and trace observation; record dynamic evidence to `./artifacts` and cite in evidence findings. Use the built-in `frida_session` tool for persistent multi-turn dynamic analysis sessions with active child/target persistence (create/run/status/stop/destroy) without re-attaching each turn. Use the built-in `adb_observe` tool for read-only device evidence with fixed commands: device discovery, installed packages, running processes, bounded logcat, system properties, and screenshots saved as artifacts.

When primary tools are absent, operators SHOULD consult `skill://reverse-lab/references/tool-fallback.md` for graceful degradation to alternative tools.

---

## 3. Recommended Workflow

1. **Reconnaissance & Manifest**:
   - Extract package entrypoints, permissions, and exported components using the built-in tool `droidasc(op: "manifest", target: "<target.apk>")` (or fallback CLI `aapt2 dump badging <target.apk>`).
   - Survey defined classes using `droidasc(op: "listclass", target: "<target.apk>", prefix: "<package.prefix>")` (or fallback `dexdump -f <target.apk>`).
2. **Search-First Decompilation**:
   - Query target keywords (`api/v2/auth`, `checkLicense`, `SecretKeySpec`) via `droidasc(op: "findrefs", target: "<target.apk>", kind: "string", query: "<keyword>")`.
   - Query method or symbol cross-references via `droidasc(op: "findrefs", target: "<target.apk>", kind: "method", query: "<methodName>", class: "<className>")`.
   - Decompile target classes directly via `droidasc(op: "getclass", target: "<target.apk>", class: "<class.name>")` or deep-dive using `jadx -d ./jadx_out --single-class "<class.name>" <target.apk>`.
3. **Smali Modification & Static Patching (Authorized Targets Only)**:
   - Decode bytecode with `apktool d <target.apk> -o ./artifacts/apk_src`.
   - Invert conditional branches (`if-eqz` ➔ `if-nez`) or force return values (`const/4 v0, 0x1` / `return v0`).
   - Re-assemble with `apktool b`, align with `zipalign`, and sign with `apksigner`, saving exclusively to `./artifacts/`.
4. **Dynamic Verification (Isolated Runtime Only)**:
   - Start with `adb_observe(action: "devices")`, then pass the target `serial` explicitly whenever more than one device is attached.
   - Confirm the running package and process with `adb_observe(action: "packages", serial: "<serial>", package: "<package>")` and `adb_observe(action: "processes", serial: "<serial>", package: "<package>")`.
   - Inspect build properties with `adb_observe(action: "props", serial: "<serial>", filter: "ro.build")`, and capture bounded runtime evidence with `adb_observe(action: "logcat", serial: "<serial>", filter: "<TAG>:I", lines: 300)`.
   - Save screenshots with `adb_observe(action: "screencap", serial: "<serial>")`; the PNG is written to an artifact (`artifactId`/`artifactPath`) instead of being embedded in context.
   - Trace method parameters and verify TLS validation behavior using isolated Frida hooks via `adb`, saving session logs to `./artifacts/`.
   - When `adb` is unavailable or the device is unauthorized/offline, follow the structured status and fallback notice instead of guessing. `adb_observe` never installs, pushes, reboot, or runs arbitrary shell commands.

Read `skill://reverse-lab/references/android.md` for complete technical walkthroughs and Frida hook templates.
