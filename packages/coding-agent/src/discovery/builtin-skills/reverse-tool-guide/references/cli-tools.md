# CLI Tool Guide

Canonical operations for the external CLI tools catalogued in `packages/coding-agent/src/extensibility/skill-tool-catalog.ts`. Availability status and trusted installation commands come from `reverse setup reverse --json`. The examples below are the vetted canonical forms to adapt.

When a tool is absent, apply the **Discover-Before-Stop / Install-Then-Dispatch** workflow: identify the capability, explain why to the operator, ask confirmation to run `reverse setup reverse <tool-id>`, verify availability, and dispatch immediately. If declined, use the listed fallback.

## Selection matrix

| Capability / Question | Primary Tool | Fallback Tool |
| :--- | :--- | :--- |
| File type / architecture | `file <sample>` | `xxd -l 64 <sample>` |
| Strings and constants | `strings -a -n 8 <sample>` | bounded hex dump + grep |
| **`native_debugger`** (Native headers / imports) | `r2 -qc "iI; iS; ii" <sample>` | `readelf` / `objdump` / `llvm-objdump` |
| **`native_debugger`** (Function disassembly) | `r2 -qc "aaa; s <sym>; pd 40" <sample>` | `objdump -d --start-address=<addr>` |
| **`native_debugger`** (Callers / xrefs) | `r2 -qc "aaa; axt @ <sym>" <sample>` | symbol search in decompiler output |
| **`apk_unpacking`** (APK manifest / resources) | `android_package_inspect` / `droidasc(op: "manifest")` | `aapt2 dump badging <apk>` / `unzip` |
| **`apk_unpacking`** (DEX decompilation) | `droidasc(op: "getclass")` / `jadx --single-class` | `apktool` smali / `dexdump -d` |
| **`apk_unpacking`** (Smali patch and rebuild) | `apktool d` / `apktool b` | `dexdump -d` for inspection only |
| **`dex_patching`** (DEX validation & patch) | `dex_patch(action: "inspect" / "patch")` | `python3` stdlib / `droidasc` / smali |
| **`apk_artifact_generation`** (APK repack/sign) | `apk_artifact(action: "repack" / "sign")` | `zipalign` + `apksigner` CLI |
| **`android_native_emulation`** (JNI emulation) | custom target Java harness (`unidbg`) / `android_native_workflow` | static `ghidra_inspect` / `r2_inspect` |
| Runtime instrumentation | `frida -U -l hook.js -f <target>` | `adb logcat` + static analysis |
| **`traffic_interception`** (HTTP/S traffic) | `mitmdump -p 8080 -w flows.mitm` | `curl` + browser DevTools HAR |
| **`websocket_capture`** (PCAP / packet detail) | `pcap_inspect` (offline) / `tshark -r <file>` | `tcpdump -r capture.pcap` |
| Packed PE | `upx -d -o ./artifacts/unpacked.exe <pe>` | `r2` section/entropy inspection |
| WebAssembly structure | `wasm_inspect(action: "info")` | `wasm2wat <module> -o module.wat` |
| **`js_deobfuscation`** (AST search & transforms) | `ast_grep(pattern: "...")` | `ast-grep` CLI / `grep` |
| **`vmp_dump_repair`** (VMProtect process dump & IAT) | `vmp_dump(action: "dump", ...)` | `native_mcp_session` (x64dbg) dump |
| **`native_function_lifting`** (x64 PE function to LLVM IR) | `native_devirtualize(backend: "mergen")` | `triton_analyze` / `r2_inspect` |
| **`vmp_legacy_devirtualization`** (VMP 3.0–3.5 VTIL devirt) | `native_devirtualize(backend: "novmp")` | `triton_analyze` |
| **`symbolic_trace_analysis`** (Symbolic replay & MBA simplification) | `triton_analyze(action: "replay", ...)` | `r2_inspect` / IDA Pro |
## 1. Triage: `file`, `strings`, `xxd`

```bash
file sample.bin
strings -a -n 8 sample.bin | head -200
xxd -l 64 sample.bin
```

- Keep `strings` output filtered by keyword when the list is large.
- Record the exact string and offset you rely on.
- Fallback: any POSIX hex/string utility; no external install is required.

## 2. radare2 (`r2`)

Canonical form:

```bash
r2 -qc "iI; iS; ii" ./sample.bin
r2 -qc "aaa; s main; pd 40" ./sample.bin
r2 -qc "aaa; axt @ sym.imp.malloc" ./sample.bin
```

- `iI` = binary info, `iS` = sections, `ii` = imports, `is` = symbols.
- Reuse one analyzed session for many queries when possible; one-shot `-qc` is cheaper for a single question.
- Bound disassembly with `pd <n> @ <addr>`; never dump an entire `.text`.
- Fallback: `objdump` / `llvm-objdump`, then POSIX strings.

## 3. APK / DEX: `android_native_workflow`, `droidasc`, `jadx`, `apktool`, `unidbg`, `bundletool`, `dex2jar`, `baksmali`, `scrcpy`, `aapt2`, `dexdump`

```text
android_native_workflow(action: "inspect", path: "<target.apk>")
android_native_workflow(action: "plan", path: "<target.apk>")
android_native_workflow(action: "extract", path: "<target.apk>", abi: "arm64-v8a")
android_native_workflow(action: "status")
```

```text
droidasc(op: "manifest", target: "<target.apk>")
droidasc(op: "listclass", target: "<target.apk>", prefix: "com.example")
droidasc(op: "findrefs", target: "<target.apk>", kind: "string", query: "SecretKeySpec")
droidasc(op: "findrefs", target: "<target.apk>", kind: "method", query: "onCreate", class: "com.example.Main")
droidasc(op: "getclass", target: "<target.apk>", class: "com.example.Main")
```

```bash
jadx -d ./artifacts/jadx-out --single-class "com.example.Main" target.apk
apktool d target.apk -o ./artifacts/apk_src
apktool b ./artifacts/apk_src -o ./artifacts/patched.apk
aapt2 dump badging target.apk
dexdump -d classes.dex
# unidbg: custom target Java harness must exist in project; obtain actual invocation from project
bundletool build-apks --bundle=app.aab --output=app.apks --mode=universal
d2j-dex2jar classes.dex -o classes.jar
baksmali d classes.dex -o ./smali_out
scrcpy -S
```

```text
dex_patch(action: "inspect", path: "sample.apk", entry: "classes.dex", class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z")
dex_patch(action: "validate", path: "classes.dex")
dex_patch(action: "patch", path: "classes.dex", out: "./artifacts/classes_patched.dex", dry_run: false, specs: [{ class: "Lcom/example/Auth;", method: "checkLicense", desc: "()Z", match: { kind: "const4", literal: 1 }, replace: { kind: "bytes", bytes: "1230" } }])

apk_artifact(action: "diff", original_path: "orig.apk", modified_path: "mod.apk")
apk_artifact(action: "repack", path: "orig.apk", output_path: "./artifacts/repacked.apk", dex_files: { "classes.dex": "./artifacts/classes_patched.dex" }, strip_signatures: true, page_align_so: true)
apk_artifact(action: "sign", path: "./artifacts/repacked.apk", output_path: "./artifacts/signed.apk", keystore_path: "~/.android/debug.keystore", key_alias: "androiddebugkey", ks_pass_env: "KEYSTORE_PASS", page_align_so: true)
apk_artifact(action: "verify", path: "./artifacts/signed.apk")
apk_artifact(action: "install_verify", path: "./artifacts/signed.apk", package_name: "com.example.app", activity: ".MainActivity", serial: "<device_serial>", output_dir: "./artifacts/install_verify_run")
```

```bash
# External Android SDK CLI tools for APK packaging
zipalign -v -p 4 ./artifacts/unaligned.apk ./artifacts/aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --out ./artifacts/signed.apk ./artifacts/aligned.apk
apksigner verify --verbose ./artifacts/signed.apk
```
- Prefer `android_native_workflow` for native `.so` library inventory, ELF parsing, JNI symbol resolution, and workflow planning without external dependencies.
- Prefer `droidasc` for instant single-class, class list, or xref queries against APK files; it degrades with structured notices. For raw `.dex` or `.aab`, use `dexdump`, `bundletool`, or `jadx`.
- Use `unidbg` for host JVM ARM32/ARM64 CPU emulation. A custom target Java harness must exist in the project; obtain its actual invocation from the project (manual integration required; no standalone CLI binary exists).
- `jadx`, `apktool`, `unidbg`, `bundletool`, `dex2jar`, and `baksmali` require `java`.
- Write all decoded trees, extracted shared libraries, and rebuilt APKs to `./artifacts/`.
- Fallback order: `android_native_workflow` / `droidasc` -> `jadx` -> `apktool` smali -> `unzip`/`dexdump` -> `unidbg`.

## 4. Dynamic instrumentation: `frida`, `adb`

Prefer the read-only built-in `adb_observe` before raw `adb`: it builds fixed argv, bounds output, and never installs, pushes, reboots, or runs arbitrary shell commands.

```text
adb_observe(action: "devices")
adb_observe(action: "packages", serial: "<serial>", package: "com.example.app")
adb_observe(action: "processes", serial: "<serial>", package: "com.example.app")
adb_observe(action: "logcat", serial: "<serial>", filter: "ActivityManager:I", lines: 300)
adb_observe(action: "props", serial: "<serial>", filter: "ro.build")
adb_observe(action: "screencap", serial: "<serial>")
```

```bash
frida-ps -U
frida -U -l hook.js -f com.example.app
adb devices
adb logcat -s <TAG>
```

- `serial` is optional with exactly one attached device and required with several; the tool never guesses. Unauthorized, offline, missing, and multiple-device cases return structured statuses.
- `screencap` saves raw PNG bytes to an artifact and returns `artifactId`/`artifactPath`; read that path instead of embedding image bytes in context.
- `package` must be a dotted application id; `filter` accepts one logcat tag (`TAG[:VDIWEF]`) or one property key/prefix. Spaces and shell metacharacters are rejected.
- Keep hook scripts focused: print matched arguments/return values, not whole memory dumps.
- A dynamic session belongs to one stateful controller to avoid port/process collisions.
- Fallback: when `adb` is missing or the device is unauthorized/offline, use static smali or native analysis; `adb_observe` reports the install hint and fallback actions without executing them.

## 5. Network: `mitmproxy`, `tshark`

```bash
mitmdump -p 8080 -w ./artifacts/flows.mitm
mitmdump -p 8080 --flow-filter '~d api.example.com'
tshark -r ./artifacts/capture.pcapng -Y http.request
```

- Capture to disk; query the flow file or filtered output instead of printing every request.
- Install the mitmproxy CA only in an authorized test environment.
- Fallback: `curl -v` replay plus HAR/DevTools capture.

## 6. WebAssembly: native `wasm_inspect`, WABT

```text
wasm_inspect(action: "info", path: "module.wasm")
wasm_inspect(action: "strings", path: "module.wasm")
wasm_inspect(action: "search", path: "module.wasm", query: "encrypt")
```

```bash
wasm2wat module.wasm -o ./artifacts/module.wat
```

- Use `info`/`strings`/`search` before requesting WAT.
- `wabt` is only needed for full WAT output; `wasm-tools` can validate or transform modules.
- Fallback: raw data-segment strings via `strings`.

## 7. Unpacking and ELF helpers

```bash
upx -d -o ./artifacts/unpacked.exe sample.exe
readelf -h -S -s ./sample.elf
```

- Never overwrite the original sample; always write to `./artifacts/`.
- `readelf` may be `greadelf` on macOS or `llvm-readelf` with LLVM tools.

## 8. AST search: native `ast_grep` and contract

```text
ast_grep(pattern: "crypto.createCipheriv($$$)", path: "bundle.js")
```

- Use structural patterns for minified/renamed JavaScript; use `grep` only for literal tokens.
- The external `ast-grep` CLI is a fallback, not a replacement for the native tool.

## 9. Virtualized Code & Devirtualization Tools: `vmp_dump`, `native_devirtualize`, `triton_analyze`

```text
# Status check
vmp_dump(action: "status")
native_devirtualize(action: "status", backend: "mergen")
triton_analyze(action: "status")

# Process dump past OEP (Windows x64)
vmp_dump(action: "dump", pid: 4128, module_path: "target.exe", observed_oep: true, output_path: "./artifacts/dumped.exe")

# Function lifting to LLVM IR (Mergen backend, x64 PE function VA)
native_devirtualize(action: "lift", backend: "mergen", path: "./artifacts/dumped.exe", start_address: "0x1400021A0")

# Legacy VTIL devirtualization (NoVmp backend, VMP 3.0-3.5 VM-entry RVAs)
native_devirtualize(action: "lift", backend: "novmp", path: "./artifacts/dumped.exe", vms: ["0x12050"])

# Symbolic trace execution & MBA simplification (Triton)
triton_analyze(action: "replay", trace: "./artifacts/trace.txt", initial_registers: { rip: "0x140001000", rax: "0x0", rdi: "0x1234", rsi: "0x5678", rsp: "0x7ffffff0" }, symbolic_registers: [{ name: "rdi", alias: "input_key1" }, { name: "rsi", alias: "input_key2" }], output: { kind: "register", target: "eax" })
```

- Always preserve original binaries read-only; output dumps, lifted IR, and VTIL to `./artifacts/`.
- Mergen supports single clean x64 functions without SMC; VMP 3.6 is best effort.
- Triton operates on offline traces in Salwan format (`mr:`, `r:`, `i:`); bounds instruction count and saves large IR to artifacts.
