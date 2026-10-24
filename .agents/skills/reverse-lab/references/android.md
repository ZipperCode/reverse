# Android Reverse Engineering & Audit Guide

This reference outlines the workflow for analyzing Android applications (`.apk`, `.aab`, `.dex`, `.so`). It prioritizes zero-prep on-demand queries on APKs (`droidasc`) over heavyweight whole-application decompilation, followed by targeted static deconstruction (`jadx`, `apktool`) and dynamic instrumentation (`adb`, `frida`). For raw `.dex` or `.aab` artifacts, use `jadx` or `dexdump`/`bundletool` directly as `droidasc` requires standard `.apk` packages.

---

## 1. Tool Hierarchy & Priority Ladder

```
[Level 0: Instant Query] ──> droidasc (Zero-prep sub-second manifest, class list, xrefs, single class on APKs)
       │
[Level 1: Focused Static] ──> jadx-cli (Targeted class/method decompile with --single-class)
       │
[Level 2: Resource/Smali] ──> apktool (Resource decoding, smali bytecode mutation & re-assembly)
       │
[Level 3: Dynamic Runtime] ──> adb & frida (Process observation, method tracing, runtime hooking)
```

1. **`droidasc` (First Priority - Zero Prep for APK)**: Treats the APK as a queryable read-only store, fetching manifests, class listings, cross-references (string, type, method, field, extends, impl), and single-class decompilations in 100ms–1.5s with minimal memory overhead.
2. **`jadx` (Focused Java Decompilation)**: Best for analyzing complex control flow, lambdas, and multi-class relationships once target classes are identified.
3. **`apktool` (Smali & Resources)**: Required for inspecting decoded XML resources (`res/values/strings.xml`) and editing smali bytecode for patch verification.
4. **`adb` & `frida` (Dynamic Closed Loop)**: Provides live confirmation of parameter values, decrypted buffers, and execution flow.

---

## 2. Phase 1: Rapid Reconnaissance (droidasc & lightweight tools)

Always start with lightweight discovery to preserve context budget:

### 1. Instant Manifest Extraction
Extract package name, entrypoint activities, permissions, and exported components without full decompilation:
```typescript
// Primary: reverse built-in droidasc tool
droidasc({ op: "manifest", target: "target.apk" })
```
```bash
# Fallback CLI using aapt2 if droidasc is not installed
aapt2 dump badging target.apk | grep -E "package:|launchable-activity"
```

### 2. Fast Reference Lookup & Class Listing (Search-First)
List classes across DEX entries or query method references, class references, or string constants across all DEX files:
```typescript
// Primary: reverse built-in droidasc tool
droidasc({ op: "listclass", target: "target.apk", prefix: "com.example" })
droidasc({ op: "findrefs", target: "target.apk", kind: "string", query: "api/v2/auth" })
droidasc({ op: "findrefs", target: "target.apk", kind: "method", query: "checkLicense", class: "com.example.LicenseValidator" })
droidasc({ op: "findrefs", target: "target.apk", kind: "string", query: "SecretKeySpec" })
```

### 3. On-Demand Single Class Decompilation
Decompile only the exact class identified by `findrefs`:
```typescript
// Primary: reverse built-in droidasc tool
droidasc({ op: "getclass", target: "target.apk", class: "com/example/app/auth/AuthManager" })
```
```bash
# Fallback CLI using jadx targeted decompilation
jadx -d ./jadx_out --single-class "com.example.app.auth.AuthManager" target.apk
```
---

## 3. Phase 2: Structured Static Analysis (JADX & Native SO)

When deep control-flow or cross-class analysis is needed:

### 1. Targeted JADX Decompilation
Prefer targeted single-class or package-filtered decompilation to preserve memory and token budget:
```bash
# Decompile only a specific class
jadx -d ./jadx_out --single-class "com.example.app.auth.AuthManager" target.apk

# Decompile only classes matching a package prefix
jadx -d ./jadx_out --include-pkg "com.example.app.auth" target.apk

# Show fallback bytecode alongside malformed decompilations
jadx -d ./jadx_out --show-bad-code --single-class "com.example.app.security.Crypto" target.apk
```

### 2. Native JNI Library (`.so`) Triage & Emulation
Android apps often delegate critical cryptography, anti-tamper, or token signing to native C/C++ libraries in `lib/<abi>/`:
```typescript
// Primary: Built-in zero-prep native inspection and JNI export mapping
android_native_workflow({ action: "inspect", path: "target.apk" });

// Extract target architecture (.so) into isolated artifacts folder
android_native_workflow({ action: "extract", path: "target.apk", abi: "arm64-v8a" });

// Generate 6-stage workflow plan with tool readiness
android_native_workflow({ action: "plan", path: "target.apk" });
```
```bash
# Fallback CLI: Inspect native libraries and exports manually
readelf -sW ./artifacts/extracted_so/lib/arm64-v8a/libnative-crypto.so | grep -E "FUNC.*Java_|JNI_OnLoad"
```

#### JNI Binding Resolution Paths:
- **Path A (Static JNI Export)**: Exported symbol matches `Java_<package>_<class>_<method>`. Inspect input parameters (`JNIEnv*`, `jobject/jclass`, plus native args) via `r2_inspect` or `ghidra_inspect`.
- **Path B (Dynamic Registration)**: No `Java_*` export found, but `JNI_OnLoad` exists. Disassemble `JNI_OnLoad`, trace calls to `(*env)->RegisterNatives(...)`, and read the `JNINativeMethod` struct array mapping method names, signatures, and function pointers.
- **Path C (Host CPU Emulation via Unidbg)**: Use reverse's existing `unidbg` tool to generate/build/launch a target harness or probe initialization without a known entry method. Bind the original APK when package metadata matters; use explicit object/array values and JNI callback overrides for observed environment dependencies. Read the current `unidbg` tool schema for invocation fields and retain missing callback signatures rather than substituting silent defaults.
- **Enrichment loop**: Carry confirmed registration events, target hash, ABI and DEX static/instance declarations into `ghidra_inspect(action: "jni_enrich")` or the owned Ghidra native session. Preview first, apply to the matched persistent project, then re-decompile. Use bounded `frida_session(template: "jni_trace")` when JNI argument/return/callback behavior remains unknown.
- **Structural and unpacking branches**: Use LIEF-backed `elf_inspect` for constructors, relocations and address mapping. Select external FindCrypt for algorithm constant candidates. When a library is decrypted in memory, preserve a bounded dump and module mapping manifest, repair a separate candidate with SoFixer, and reanalyze. Finish with independent input/output experiments.
---

## 4. Phase 3: Smali Bytecode Modification & Rebuild (Apktool)

Execute bytecode modifications, package rebuilds, and signing exclusively on explicitly authorized test applications in isolated laboratory environments. Preserve the original APK read-only, directing disassembled source and rebuilt packages to dedicated artifact paths (`./artifacts/`).

When verifying a hypothesis via static patch:
### 1. Decode to Smali
```bash
# Decode only smali and resources (-r prevents resource decoding if only smali is needed)
apktool d target.apk -o apk_disassembled
```

### 2. Patch Smali Logic
Common smali mutation patterns:

- **Invert Boolean Condition**:
  Change `if-eqz v0, :cond_fail` to `if-nez v0, :cond_fail`.
- **Force Return True**:
  ```smali
  # Replace method body with constant true
  .method public static isValid()Z
      .registers 1
      const/4 v0, 0x1
      return v0
  .end method
  ```
- **Bypass Void Check**:
  ```smali
  # Replace method body with immediate return
  .method public static checkSecurity()V
      .registers 0
      return-void
  .end method
  ```

### 3. Rebuild, Align & Sign
```bash
# 1. Rebuild APK
apktool b apk_disassembled -o patched_unaligned.apk

# 2. Zipalign (4-byte alignment)
zipalign -v -p 4 patched_unaligned.apk patched_aligned.apk

# 3. Sign with debug keystore
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android patched_aligned.apk
```

---

## 5. Phase 4: Dynamic Instrumentation (ADB & Frida)

Apply dynamic instrumentation, parameter inspection, and SSL unpinning scripts exclusively to authorized processes running on designated test devices or emulator instances. Save all hook scripts, session traces, and memory dumps to independent artifact files.
### 1. ADB Process Management
Prefer the read-only built-in `adb_observe` for evidence collection; it fixes argv and bounds output:
```text
adb_observe(action: "devices")
adb_observe(action: "packages", serial: "<serial>", package: "com.example.app")
adb_observe(action: "processes", serial: "<serial>", package: "com.example.app")
adb_observe(action: "logcat", serial: "<serial>", filter: "ActivityManager:I", lines: 300)
adb_observe(action: "props", serial: "<serial>", filter: "ro.build")
adb_observe(action: "screencap", serial: "<serial>")
```
It returns structured statuses for missing `adb`, multiple devices without a serial, and unauthorized/offline devices. Use raw `adb` below only for operations `adb_observe` intentionally does not expose, such as installing an authorized test build:
```bash
# Check connected device/emulator
adb devices

# Install patched APK
adb install -r patched_aligned.apk

# Find process ID of target package
adb shell pidof com.example.app

# Filter application logs
adb logcat -v time --pid=$(adb shell pidof com.example.app) | grep -E "Auth|License|Security"
```

### 2. Frida Hooking Patterns
Spawn or attach to the process using single-responsibility scripts:

#### A. Tracing Java Method Arguments & Return Value
```javascript
// hooks/trace_auth.js
Java.perform(function () {
    var AuthClass = Java.use("com.example.app.auth.AuthManager");
    AuthClass.generateSignature.implementation = function (payload, timestamp) {
        console.log("[Frida] generateSignature called!");
        console.log("  Payload: " + payload);
        console.log("  Timestamp: " + timestamp);
        var result = this.generateSignature(payload, timestamp);
        console.log("  Result: " + result);
        return result;
    };
});
```

#### B. Dynamic SSL Certificate Pinning Bypass
```javascript
// hooks/ssl_unpin.js
Java.perform(function () {
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustAll = Java.registerClass({
        name: "com.reverse.TrustAll",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {},
            getAcceptedIssuers: function () { return []; }
        }
    });

    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
        .implementation = function (km, tm, sr) {
            console.log("[Frida] Overriding TrustManager to TrustAll");
            this.init(km, [TrustAll.$new()], sr);
        };
});
```

Run Frida:
```bash
frida -U -f com.example.app -l hooks/trace_auth.js
```
Prefer the built-in `frida` tool for one-shot scripts, or `frida_session` (alias `reverse_dynamic_session`) for persistent multi-turn instrumentation workflows (create/run/events/status/stop/destroy) that retain target process and child state across agent turns:
```text
frida_session(action: "create", spawn: "com.example.app", usb: true, session_id: "android-audit")
frida_session(action: "run", session_id: "android-audit", script_path: "hooks/trace_auth.js")
frida_session(action: "events", session_id: "android-audit", kind: "message", export_evidence: true)
frida_session(action: "status", session_id: "android-audit")
frida_session(action: "stop", session_id: "android-audit")
```

---

## 6. Subagent Delegation Model for Android

When handling complex Android tasks:
- **`scout` subagent**: Runs `droidasc getmanifest` and `droidasc findrefs` to map components, detect obfuscators, and locate relevant class names.
- **Main Agent**: Evaluates the xrefs, checks context budget, reads target classes, and drafts the verification hypothesis.
- **`task` subagent**: Writes the Frida hook script or performs the smali patch and test build.
- **Main Agent**: Executes dynamic verification on the device/emulator to maintain a single stateful session owner.
