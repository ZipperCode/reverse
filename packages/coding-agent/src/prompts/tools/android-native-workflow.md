Native reverse engineering workflow and inspection tool for Android native shared libraries (`.so`), JNI export symbols, and Dalvik/DEX native method links (`RegisterNatives`). Operates without external dependencies for static inspection, extracts target `.so` binaries, plans unpack/decompile/disassemble/inject/emulate/enrich pipelines, and reports structured missing dependency statuses and install hints for JADX, Apktool, Frida, Unidbg, Ghidra, and ElfInspect.

Actions:
- `inspect`: High-level native inventory and cross-linking. Inspects APK or directory `.so` binaries across ABIs (arm64-v8a, armeabi-v7a, x86, x86_64), parses ELF architecture/headers/dynamic symbols, extracts verified defined JNI exports (`Java_*`), `JNI_OnLoad`/`RegisterNatives` candidate indicators, crypto/anti-analysis keywords, parses DEX native method declarations (`ACC_NATIVE`) including `isStatic` access flags, and maps verified static bindings while keeping unverified methods explicit with candidate library hints without false confirmations.
- `plan`: Generates a deterministic reverse engineering workflow plan (6 stages for standard libraries, 7 stages when packed payload reconstruction is required) tailored to target native libraries with concrete actionable tool parameters and artifact links. Routes unresolved dynamic registrations to Frida `jni_register` on live device OR no-device Unidbg probe (`unidbg(action: "probe")`), followed by verified JNI enrichment via Ghidra (`ghidra_inspect(action: "jni_enrich", events_path: "...")`), bounded JNI API trace (`frida(template: "jni_trace")`), and replay verification. Composes LIEF constructors/relocations via `elf_inspect` and optional FindCrypt candidates only when relevant, and includes memory dump & SoFixer repair (`elf_inspect(action: "dump_and_repair")`) only when concrete commercial packer payloads require it.
- `status`: Comprehensive readiness check of the Android reverse companion toolchain (Unidbg, Ghidra, JADX, Apktool, ADB, Frida, Droidasc, AAPT2, Bundletool, Dex2jar, Baksmali, Scrcpy, Java, Radare2, ElfInspect) with structured missing dependencies, package manager install commands, and workflow capability flags.
- `extract`: Extracts and decompresses target native `.so` libraries and manifest from an APK container (or direct `.so` files) to a dedicated output directory (`./artifacts/extracted_so/`) using pure in-process deflation without external unzip/apktool tools.
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
