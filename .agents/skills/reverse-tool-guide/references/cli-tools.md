# CLI Tool Guide

Canonical operations for the external CLI tools in `packages/coding-agent/src/extensibility/skill-tool-catalog.ts`. Availability comes from `rva setup reverse --json`; the examples below are the trusted forms to adapt, not installation instructions.

## Selection matrix

| Question | Primary | Fallback |
| :--- | :--- | :--- |
| File type / architecture | `file <sample>` | `xxd -l 64 <sample>` |
| Strings and constants | `strings -a -n 8 <sample>` | bounded hex dump + grep |
| Native headers / imports | `r2 -qc "iI; iS; ii" <sample>` | `readelf` / `objdump` / `llvm-objdump` |
| Function disassembly | `r2 -qc "aaa; s <sym>; pd 40" <sample>` | `objdump -d --start-address=<addr>` |
| Callers / xrefs | `r2 -qc "aaa; axt @ <sym>" <sample>` | symbol search in decompiler output |
| APK manifest / resources | `droidasc(op: "manifest")` | `aapt2 dump badging <apk>` |
| DEX decompilation | `droidasc(op: "getclass")` | `jadx --single-class` -> `apktool` smali |
| Smali patch and rebuild | `apktool d` / `apktool b` | `dexdump -d` for inspection only |
| Runtime instrumentation | `frida -U -l hook.js -f <target>` | `adb logcat` + static analysis |
| HTTP(S) traffic | `mitmdump -p 8080 -w flows.mitm` | `curl` + browser DevTools HAR |
| PCAP / packet detail | `tshark -r capture.pcapng` | `tcpdump -r capture.pcap` |
| Packed PE | `upx -d -o ./artifacts/unpacked.exe <pe>` | `r2` section/entropy inspection |
| WebAssembly structure | `wasm_inspect(action: "info")` | `wasm2wat <module> -o module.wat` |

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

## 3. APK / DEX: `droidasc`, `jadx`, `apktool`, `aapt2`, `dexdump`

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
```

- Prefer `droidasc` for instant single-class, class list, or xref queries against APK files; it degrades with structured notices. For raw `.dex` or `.aab`, use `dexdump` or `jadx`.
- `jadx` needs `java`; `apktool` needs `java`.
- Write all decoded trees and rebuilt APKs to `./artifacts/`.
- Fallback order: `droidasc` -> `jadx` -> `apktool` smali -> `unzip`/`dexdump`.

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
frida -U -l hook.js -f com.example.app --no-pause
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
