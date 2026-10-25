# Android Reverse Engineering & Audit Guide

This reference outlines the workflow for analyzing Android applications (`.apk`, `.aab`, `.dex`, `.so`). It prioritizes zero-dependency native inspection (`android_package_inspect`) for container triage, manifest extraction, signature auditing, and resource analysis, followed by optional on-demand queries (`droidasc`), structured Java/smali decompilation (`jadx`, `apktool`), and dynamic instrumentation (`app_experiment`, `frida`, `adb`).

---

## 1. Tool Hierarchy & Priority Ladder

```
[Level 0: Native Baseline] ──> android_package_inspect (Zero-dependency in-process container triage, AXML manifest decoding, DEX discovery, signatures)
       │
[Level 1: On-Demand Query] ──> droidasc (Optional fast class lists, xrefs, and single-class decompilations when installed)
       │
[Level 2: Focused Static] ──> jadx-cli (Targeted class/method decompile with --single-class)
       │
[Level 3: Resource/Smali] ──> apktool (Resource decoding, smali bytecode mutation & re-assembly)
       │
[Level 4: Dynamic Runtime] ──> app_experiment / adb & frida (Component invocation, method tracing, runtime hooking)
```

1. **`android_package_inspect` (First Priority - Built-in Native Baseline)**: Zero-dependency native inspection of APK/AAB packages and DEX binaries. Extracts container structures, decodes binary XML manifests (permissions, components, intent filters, deep links), parses DEX headers/classes, verifies APK signatures (v1-v3.1), and queries resource trees in-process without external tool installations.
2. **`droidasc` (Optional Query Tool)**: On-demand query tool for APK packages when installed. Fetches class listings, cross-references (string, type, method, field, extends, impl), and single-class decompilations without whole-application JVM memory pressure.
3. **`jadx` (Focused Java Decompilation)**: Best for analyzing complex control flow, lambdas, and multi-class relationships once target classes are identified.
4. **`apktool` (Smali & Resources)**: Required for inspecting decoded XML resources (`res/values/strings.xml`) and editing smali bytecode for patch verification.
5. **`app_experiment` / `adb` & `frida` (Dynamic Closed Loop)**: Provides live confirmation of parameter values, decrypted buffers, and execution flow.

## 2. Phase 1: Rapid Reconnaissance (Native Baseline & Query Tools)

*Tool Execution Guidance*: Built-in tools are dispatched via `write` to `xd://<tool>` with JSON arguments. Query the schema and options before calling using `read xd://<tool>`.

Always start with lightweight native discovery to preserve context budget:

### 1. Instant Manifest Extraction
Extract package name, entrypoint activities, permissions, and exported components via built-in `android_package_inspect` (write to `xd://android_package_inspect`):
```json
{
  "action": "manifest",
  "path": "target.apk"
}
```
Or when optional `droidasc` is installed (write to `xd://droidasc`):
```json
{
  "op": "manifest",
  "target": "target.apk"
}
```
Fallback CLI using `aapt2`:
```bash
aapt2 dump badging target.apk | grep -E "package:|launchable-activity"
```

### 2. Fast Reference Lookup & Class Listing (Search-First)
When `droidasc` is installed, list classes across DEX entries or query method references, class references, or string constants (write to `xd://droidasc`):
```json
{
  "op": "listclass",
  "target": "target.apk",
  "prefix": "com.example"
}
```
```json
{
  "op": "findrefs",
  "target": "target.apk",
  "kind": "string",
  "query": "api/v2/auth"
}
```
```json
{
  "op": "findrefs",
  "target": "target.apk",
  "kind": "method",
  "query": "checkLicense",
  "class": "com.example.LicenseValidator"
}
```

### 3. On-Demand Single Class Decompilation
Decompile only the exact class identified by `findrefs` using `droidasc` (write to `xd://droidasc`):
```json
{
  "op": "getclass",
  "target": "target.apk",
  "class": "com/example/app/auth/AuthManager"
}
```
Fallback CLI using targeted JADX:
```bash
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
Inspect libraries via `android_native_workflow` (write to `xd://android_native_workflow`):
```json
{
  "action": "inspect",
  "path": "target.apk"
}
```
Extract target architecture (`.so`) into isolated artifacts folder:
```json
{
  "action": "extract",
  "path": "target.apk",
  "abi": "arm64-v8a"
}
```
Generate 6-stage workflow plan with tool readiness:
```json
{
  "action": "plan",
  "path": "target.apk"
}
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

## 4. Phase 3: Bytecode Modification, APK Repackaging & Signing (`dex_patch` & `apk_artifact`)

Execute bytecode modifications, package rebuilds, and signing exclusively on explicitly authorized test applications in isolated laboratory environments. Preserve the original APK read-only, directing disassembled source and rebuilt packages to dedicated artifact paths (`./artifacts/`).

### 1. Pre-Patch Layer Triage & Diagnostic Failure Checks
Before attempting bytecode modifications, verify target ownership to prevent wasted investigation cycles:
- **Layer Ownership**: Determine whether the target algorithm lives in Java/Dalvik DEX, Native C/C++ `.so` (JNI), Flutter/Dart (`libapp.so`), or a Server-Side API check. Modifying DEX has zero effect on native cryptography, Flutter compiled AOT code, or server-enforced validation.
- **JNI Dynamic Registration**: When native methods are declared (`native boolean check()`), check whether the native implementation is exported statically as `Java_<pkg>_<cls>_<method>` or dynamically registered inside `JNI_OnLoad` via `RegisterNatives`.
- **Zero-Change Control**: Never trust unverified patches without a baseline. Pass the unmodified original package through the identical repackaging and signing pipeline as an experimental control; verify that this repackaged baseline installs and functions identically before testing semantic patches. Combine this control run with entry-level diffing (`apk_artifact(action: "diff")`) to confirm only intended entries differ.
- **Signature & Alignment Failures**: Re-signed packages will fail to install (`INSTALL_FAILED_INVALID_APK`) or fail runtime dynamic loading if resources are not 4-byte aligned, native `.so` libraries are not aligned to 16KiB (16384-byte) page boundaries in the ZIP container (`page_align_so: true`), or v1-v3 signature schemes are improperly applied. Note that 16KiB container alignment satisfies packaging requirements but cannot fix a native library whose internal ELF `PT_LOAD` segments were linked with incompatible 4KiB page size alignments (both container 16KiB alignment and proper ELF segment linking are required).
- **Stale Cache & Remote Overrides**: If patched bytecode executes but application behavior remains unchanged, investigate cached remote configurations, SharedPreferences flags, or dynamic CDN config TTLs via non-destructive observation (`adb_observe`) rather than issuing destructive data resets. Never invoke `pm clear` by default as it destroys session state and application data; perform an isolated test profile or targeted data reset only after explicit operator approval and preserving necessary credentials.
- **Zero-Event Trace Control**: When dynamic tracing observes no events, do not assume the check passed; verify that the hook was actually installed and that execution reached the target class/method.

### 2. Direct DEX Bytecode Patching (`dex_patch`)
Direct bytecode editing avoids full smali disassembly/reassembly failures on obfuscated or anti-decompilation APKs:
```typescript
// 1. Inspect target method Dalvik instructions and offsets
dex_patch({
  action: "inspect",
  path: "target.apk",
  entry: "classes.dex",
  class: "Lcom/example/Auth;",
  method: "checkLicense",
  desc: "()Z"
});

// 2. Structurally validate DEX headers, Adler32 checksums, and instruction boundaries
dex_patch({ action: "validate", path: "classes.dex" });

// 3. Apply semantic bytecode patch with dry-run safety
dex_patch({
  action: "patch",
  path: "classes.dex",
  out: "./artifacts/classes_patched.dex",
  dry_run: false,
  specs: [
    {
      class: "Lcom/example/Auth;",
      method: "checkLicense",
      desc: "()Z",
      match: { kind: "const4", literal: 1 },
      replace: { kind: "bytes", bytes: "1230" }
    }
  ]
});
```

### 3. Container Repackaging, Alignment & Signing (`apk_artifact`)
Assemble modified DEX files into a valid APK, enforce alignment, and sign:
```typescript
// 1. Repack modified DEX into APK container (preserves resources.arsc alignment, META-INF services, and enforces 16KiB .so alignment)
apk_artifact({
  action: "repack",
  path: "target.apk",
  output_path: "./artifacts/repacked_unsigned.apk",
  dex_files: { "classes.dex": "./artifacts/classes_patched.dex" },
  strip_signatures: true,
  page_align_so: true
});

// 2. Verify zero-change control via entry-level diff
apk_artifact({
  action: "diff",
  original_path: "target.apk",
  modified_path: "./artifacts/repacked_unsigned.apk"
});

// 3. Register derivative lineage in reverse_workflow
reverse_workflow({
  action: "register_derivative",
  workflow_id: "wf_rw_1",
  step_id: "apk_patch_step",
  build_id: "bld_patch1",
  derivative_path: "./artifacts/repacked_unsigned.apk",
  original_sha256: "<orig_sha256>",
  output_sha256: "<output_sha256>",
  signature_status: "unsigned"
});

// 4. Sign container with zipalign (4-byte alignment, 16KiB page alignment for .so) and apksigner (v1-v3 schemes)
apk_artifact({
  action: "sign",
  path: "./artifacts/repacked_unsigned.apk",
  output_path: "./artifacts/target_signed.apk",
  keystore_path: "~/.android/debug.keystore",
  key_alias: "androiddebugkey",
  ks_pass_env: "KEYSTORE_PASS",
  page_align_so: true
});

// 5. Cryptographically verify signature block and alignment
apk_artifact({ action: "verify", path: "./artifacts/target_signed.apk" });

// 6. Install & launch verification on test device/emulator (requires explicit output_dir for artifacts)
apk_artifact({
  action: "install_verify",
  path: "./artifacts/target_signed.apk",
  package_name: "com.example.app",
  activity: ".MainActivity",
  serial: "<device_serial>",
  output_dir: "./artifacts/install_verify_run"
});
```

### 4. Four-Level Verification Distinction
1. **Static Validation**: Verifies DEX header checksums (Adler32, SHA-1), instruction boundary integrity, and ZIP container structure.
2. **Signed Artifact Verification**: Cryptographically validates APK Signing Block v1-v3 signature schemes and archive alignments.
3. **Install & Launch Verification**: Confirms that the APK installs without rejection and the launchable Activity starts without immediate crash.
4. **Exact-Feature Verification**: Discrete operator testing of the specific target feature. Launch stability MUST NEVER be claimed as feature verification.

### 5. Fallback Tier: Smali Bytecode Modification & Rebuild (Apktool)
When direct DEX patching is unsuitable (e.g., complex multi-instruction method restructuring):
```bash
# 1. Decode smali and resources
apktool d target.apk -o ./artifacts/apk_disassembled

# 2. Edit smali logic (invert conditional branch, force return value)
# 3. Rebuild APK
apktool b ./artifacts/apk_disassembled -o ./artifacts/patched_unaligned.apk

# 4. 4-byte zipalign and apksigner
zipalign -v -p 4 ./artifacts/patched_unaligned.apk ./artifacts/patched_aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out ./artifacts/target_signed.apk ./artifacts/patched_aligned.apk
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

## 6. Phase 5: Runtime DEX Unpacking, FART Repair & Structural Search

When auditing hardened or reinforced Android applications where DEX files are encrypted or packed in memory, apply the unpack-then-repair pipeline:

### 1. In-Memory DEX Extraction (`dex_unpack`)
Extract packed DEX files from the running ART runtime:
```json
dex_unpack({
  "action": "dump",
  "backend": "frida-dexdump",
  "package": "com.example.protected",
  "device": "emulator-5554",
  "deep_search": true,
  "out_dir": "./artifacts/unpacked_dex"
})
```
- Requires an explicit `device` serial and target `package` or `pid`.
- Inspects dumped DEX headers and evaluates `incomplete_method_boundary`. If `needs_repair: true` is returned (methods contain empty code stubs from function-level extractors like FART), hand off to `dex_repair`.

### 2. Offline FART CodeItem Repair (`dex_repair`)
Stitch dumped CodeItem records back into the target DEX file:
```json
dex_repair({
  "action": "repair",
  "path": "./artifacts/unpacked_dex/classes.dex",
  "records": "./artifacts/unpacked_dex/123456_ins.bin",
  "dry_run": false,
  "out": "./artifacts/repaired_dex/classes_repaired.dex"
})
```
- Parses method index records, calculates new code item offsets, relocates instructions, updates `class_data` ULEB offsets, and recalculates SHA-1 and Adler32 checksums.
- Verify output with `dry_run: true` before writing.

### 3. Structural Graph Search via DexKit (`dex_search`)
Query classes, methods, and cross-references across multi-DEX applications:
```json
dex_search({
  "target": "target.apk",
  "type": "method",
  "using_strings": ["SECRET_KEY", "AES/CBC"],
  "return_type": "Ljava/lang/String;"
})
```
- Produces stable descriptors for handoff to JADX decompilation or Frida hook targeting.
---

## 7. Subagent Delegation Model for Android

When handling complex Android tasks, follow structured handoffs (`sha256`, `path`, `package`, `abi`, `serial`, `subject`, `evidence_ids`, `allowed_actions`):
- **`scout` subagent**: Runs `droidasc` manifest and xref queries to map components, detect obfuscators, and locate relevant class names.
- **Main Agent**: Evaluates xrefs, checks context budget, reads target classes, and drafts the verification hypothesis.
- **`task` subagent**: Writes Frida hook scripts, performs DEX bytecode patches (`dex_patch`), generates repacked APKs (`apk_artifact`), or runs framework analysis (`runtime_analyze`).
- **Main Agent**: Executes dynamic verification on the device/emulator (or runs bounded tests via `app_experiment`) to maintain a single stateful session owner.
