Native reverse engineering workflow and inspection tool for Android native shared libraries (`.so`), JNI export symbols, and Dalvik/DEX native method links (`RegisterNatives`). Operates without external dependencies for static inspection, extracts target `.so` binaries, plans unpack/decompile/inject/emulate pipelines, and reports structured missing dependency statuses and install hints for JADX, Apktool, Frida, and Unidbg.

Actions:
- `inspect`: High-level native inventory and cross-linking. Inspects APK or directory `.so` binaries across ABIs (arm64-v8a, armeabi-v7a, x86, x86_64), parses ELF architecture/headers/dynamic symbols, extracts verified defined JNI exports (`Java_*`), `JNI_OnLoad`/`RegisterNatives` candidate indicators, crypto/anti-analysis keywords, parses DEX native method declarations (`ACC_NATIVE`), and maps verified static bindings (supporting overloaded signatures) while keeping unverified methods explicit with candidate library hints.
- `plan`: Generates a deterministic, 6-stage reverse engineering workflow plan (unpack, decompile, disassemble, dynamic_inject, emulate, record_evidence) tailored to target native libraries with concrete tool commands, missing dependency detection, and fallback paths (e.g. Frida on-device vs Unidbg JVM emulation).
- `status`: Comprehensive readiness check of the Android reverse companion toolchain (Unidbg, JADX, Apktool, ADB, Frida, Droidasc, AAPT2, Bundletool, Dex2jar, Baksmali, Scrcpy, Java, Python3, Node) with structured missing dependencies, package manager install commands, and workflow capability flags.
- `extract`: Extracts and decompresses target native `.so` libraries and manifest from an APK container to a dedicated output directory (`./artifacts/extracted_so/`) using pure in-process deflation without external unzip/apktool tools.

Parameters:
- `action`: Workflow action (`inspect`, `plan`, `status`, `extract`).
- `path` / `target`: Path to target Android package (`.apk`, `.aab`, `.zip`) or directory containing native shared libraries.
- `abi`: Optional ABI architecture filter (e.g. `arm64-v8a`, `armeabi-v7a`, `x86_64`).
- `library` / `so_name`: Optional filename filter for native library (e.g. `libnative-crypto.so`).
- `class_filter`: Optional substring filter for Java/Kotlin classes declaring native methods.
- `output_dir`: Target directory for `extract` action (default `./artifacts/extracted_so`).
- `format`: Output format (`markdown` or `json`, default `markdown`).
- `limit`: Maximum items returned in lists (default 50, max 200).

Safety & Boundary:
- In-process static inspection runs without executing any external shell or binary.
- Never mutates original APK target; extraction only writes into isolated output directory (`./artifacts/`).
- Reports structured missing dependency statuses and trusted catalog install hints instead of invoking unvetted commands.

<examples>
```
android_native_workflow(action: "status")
android_native_workflow(action: "inspect", path: "app-release.apk")
android_native_workflow(action: "plan", path: "app-release.apk")
android_native_workflow(action: "extract", path: "app-release.apk", abi: "arm64-v8a")
android_native_workflow(action: "inspect", path: "app-release.apk", library: "libcrypto.so")
```
</examples>
