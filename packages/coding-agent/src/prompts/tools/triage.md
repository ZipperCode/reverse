Read-only multi-format binary, archive, and artifact reconnaissance. Quickly inspects targets without requiring IDA Pro or radare2.

Supported formats:
- Windows PE (EXE, DLL, SYS): machine architecture, bits, entrypoint, sections, subsystem, indicators.
- Linux/POSIX ELF: class (32/64-bit), endianness, machine architecture, entrypoint, sections.
- Apple Mach-O & Universal Fat Mach-O: thin architectures (x86_64, arm64, arm64e), universal slices, load commands, sections.
- WebAssembly (WASM): header, version, sections (type, import, export, code, data). Suggests wasm_inspect for deep inspection.
- Android APK & DEX: APK components, manifest presence, Dalvik/ART classes/methods counts. Suggests droidasc or jadx for decompilation.
- Java Class (.class): major/minor versions (Java 8 - 25+), constant pool summary.
- Archives (ZIP/JAR): structure, entry preview, compressed vs raw sizes.
- Generic / Unknown / Raw binaries: SHA-256, Shannon entropy sampling, byte indicators.

Features:
- Streaming SHA-256 computation and Shannon entropy analysis.
- Bounded file reads with 512 MiB maximum file cap (never crashes on malformed/truncated binaries).
- Optional strings scanning (`strings: true`) with configurable `min_length`, `limit`, and `max_bytes`.
- Reports facts and indicators only; does not declare files "malicious" or "packed".

<examples>
```
triage(path: "sample.exe")
triage(path: "target.apk")
triage(path: "libcrypto.so", strings: true, limit: 30)
triage(path: "module.wasm")
triage(path: "UniversalBinary", strings: true, min_length: 8)
```
</examples>
