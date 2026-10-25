Runtime DEX memory extraction and post-dump structural census using external de-packers (frida-dexdump).

Capabilities:
- **Runtime Memory DEX Extraction (`dump`)**:
  - Dumps in-memory Dalvik/ART executable DEX files from running Android applications via external `frida-dexdump` CLI.
  - Requires explicit device ID and package or PID; foreground-implicit dumping is disallowed to prevent accidental target ambiguity.
  - Supports controlled spawn (`spawn: true`) or live attach (`spawn: false`, default).
  - Optional deep search mode (`deep_search: true`) scans memory ranges beyond registered ART ClassLoader tables.
  - Writes dumps into private staging output directories to prevent current working directory pollution.
  - Enforces subprocess ownership, timeouts, and clean process tree termination on cancellation.
- **DEX Header and Incomplete Method Census**:
  - Verifies extracted DEX headers: magic bytes (`dex\n035`, `dex\n037`, `dex\n038`, `dex\n039`), declared file size vs actual disk bytes, Adler-32 checksum, and SHA-1 signature.
  - Analyzes method body boundaries: identifies methods with `code_off == 0` or stub returns indicative of instruction erasure or packer extraction requirements.
  - Computes `incomplete_method_boundary` and recommends next-step tool handoffs:
    - `dex_repair`: To restore method bodies using FART active call instruction dumps.
    - `dex_patch`: For semantic bytecode patching and gate modification.
    - `android_package_inspect`: For static container, manifest, and signature verification.
- **Backend Status and Dependency Check (`status`)**:
  - Probes host availability of `frida-dexdump` and reports managed installation hints (`reverse setup reverse frida-dexdump --execute`).
  - Reports BlackDex APK container availability and handoff options.

Inputs:
- `action`: `"status"` or `"dump"`.
- `backend`: Backend dumper engine (`"frida-dexdump"` default, or `"blackdex"`).
- `device`: Explicit Android device ID / serial (mandatory for `dump`).
- `package`: Target Android package name (e.g. `"com.example.app"`).
- `pid`: Target process ID (alternative to `package`).
- `spawn`: Whether to spawn the application via Frida (`true`) or attach to existing process (`false`, default).
- `deep_search`: Whether to enable deep memory scanning (`-d` flag).
- `out_dir`: Destination directory to receive extracted DEX files.
- `timeout_ms`: Subprocess execution timeout in milliseconds (default 60000).
- `max_files`: Maximum number of dumped DEX files to census (default 50).
- `max_bytes`: Maximum total dumped bytes allowed (default 128 MiB).

<examples>
```
// Query dumper tool readiness
dex_unpack(
  action: "status"
)
```

```
// Attach to process and dump memory DEX files with deep search
dex_unpack(
  action: "dump",
  device: "emulator-5554",
  package: "com.target.app",
  deep_search: true,
  out_dir: "artifacts/dex_dump"
)
```

```
// Spawn application under Frida and extract runtime DEX
dex_unpack(
  action: "dump",
  device: "192.168.1.100:5555",
  package: "com.target.app",
  spawn: true,
  out_dir: "artifacts/dex_spawn"
)
```
</examples>
