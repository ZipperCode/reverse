Multi-engine deobfuscation and program synthesis tool for Android DEX, native binaries, and MBA expressions.

Supported Backends:
- **`jadx` (Arsylk/jadx-string-decrypt)**:
  - Statically folds opaque compile-time numeric/boolean constants and resolves string decryption pipelines in Android APKs and DEX files.
  - De-indirects reflection calls (`Method.invoke(...)` -> direct call) and strips dead reflection scaffolding.
  - Configurable cipher parameters (`AES/ECB/PKCS5Padding`, `DESede`), key tail length, and method comments.
- **`d810-ng` (AGPL-3.0 IDA Pro 9+ Microcode Deobfuscator)**:
  - Headless/batch execution on compiled binaries and IDA databases (.idb/.i64).
  - Activates requested microcode rules: MBA simplification (`Add`, `Sub`, `Xor`, Hacker's Delight, O-LLVM), constant folding, opaque predicate elimination.
  - Control-flow unflattening: `ollvm` (switch/if dispatcher), `tigress` (switch-case jump tables), `approov` (magic state loops), `hodur` (nested while-loops).
  - Emits pre- and post-deobfuscation pseudocode and line counts; validate recovered control flow and semantics independently.
- **`simplify` (CalebFenton/simplify GPL-3.0 Dalvik Virtual Execution)**:
  - Executes Dalvik methods symbolically/virtually inside a headless Android runtime to evaluate obfuscated expressions and dead branch conditionals.
  - Strictly enforces execution bounds (`max_address_visits`, `max_method_visits`, `max_call_depth`) to prevent infinite execution loops.
  - Emits fresh deobfuscated Dalvik DEX files (`.dex`).
- **`msynth` (mrphrazer/msynth GPL-2.0 MBA Simplifier & SMT Equivalence)**:
  - Simplifies complex Mixed Boolean-Arithmetic (MBA) mathematical and bitwise expressions (e.g. `(x ^ y) + 2 * (x & y)` -> `x + y`).
  - AST subtree simplification and stochastic program synthesis over explicit bit-widths (8, 16, 32, 64 bits).
  - Strictly safe tokenized parsing without Python `eval()` or string execution.
  - Formally proves semantic equivalence between original and simplified expressions using the Z3 SMT solver over bitvectors.
- **`blackdex` (ZhengHaiPeng Apache-2.0 Android Dynamic Unpacker)**:
  - Automates installation and execution of the BlackDex ART unpacker APK on an active Android device or emulator via ADB.
  - Monitors and polls the device dump directory (`/sdcard/Android/data/.../files/dump/<package>/`) for unpacked DEX outputs.
  - Automatically pulls dumped DEX files to local artifacts directory and computes cryptographic checksums.

Research References:
- D810G (overkazaf/D810G, based on Quarkslab framework research) and vmp-devirt (experimental native devirtualization) remain research-only prototypes and are intentionally kept separate from production catalog readiness.

Safety and Plan Mode Invariants:
- **Approval Tiers**: `action: "status"` operates under `read` approval and is permitted in Plan Mode. `action: "analyze"` requires `exec` approval and is blocked in Plan Mode.
- **Isolated Artifacts**: Input binaries and APKs are never modified in place. Output files are written to fresh destination paths with conflict prevention.
- **Deterministic Subprocess Limits**: All subprocess invocations (JADX, Java, IDA, ADB, Python) are bounded with strict timeouts, stream byte limits, and process-tree termination.

Parameters:
- `action`: `"status"` or `"analyze"` (required).
- `backend`: `"jadx"`, `"d810-ng"`, `"simplify"`, `"msynth"`, or `"blackdex"`.
- `path`: Path to target APK, DEX, native binary, or IDB database on disk.
- `out`: Output directory or file destination for deobfuscated artifacts and reports.
- `timeout`: Maximum execution timeout in seconds (default 120, max 600).

Backend-Specific Options:
- **msynth**:
  - `expression`: MBA expression string (e.g. `"(x ^ y) + 2 * (x & y)"`). Safe parser, no eval.
  - `bit_width`: Explicit bit-width for variables (8, 16, 32, 64; default 32).
  - `variables`: Array of variable names (e.g. `["x", "y"]`).
  - `mode`: `"ast"` (rule-based subtree simplification) or `"synthesis"` (stochastic synthesis).
  - `verify_smt`: Whether to formally prove semantic equivalence with Z3 (default `true`).
- **d810-ng**:
  - `function`: Target function Virtual Address (hex string e.g. `"0x401000"`) or symbol name.
  - `rules`: Array of rule categories (e.g. `["mba", "ollvm", "cst_simplification", "predicates"]`).
  - `unflattener`: Unflattener type: `"ollvm"`, `"tigress"`, `"approov"`, `"hodur"`, `"generic"`, or `"none"`.
  - `config_json`: Optional JSON configuration override.
- **simplify**:
  - `include_types`: Array of class regexes/prefixes to deobfuscate (e.g. `["Lcom/example/obf/.*"]`).
  - `exclude_types`: Array of class regexes/prefixes to exclude.
  - `max_address_visits`: Maximum visits per instruction address (default 10000).
  - `max_method_visits`: Maximum visits per method (default 1000).
  - `max_call_depth`: Maximum virtual call stack depth (default 50).
- **jadx**:
  - `class_filter`: Specific class name or filter to decompile.
  - `fold_consts`: Fold opaque numeric/boolean constants (default `true`).
  - `fold_helper_calls`: Fold pure static helper calls (default `true`).
  - `decrypt_strings`: Decrypt block-cipher string routines (default `true`).
  - `deindirect_reflection`: Replace reflection calls with direct invocations (default `true`).
  - `cleanup_reflection`: Strip dead reflective scaffolding (default `true`).
  - `comments`: Append method comments with decrypted strings (default `true`).
  - `cipher`: Cipher algorithm (default `"AES/ECB/PKCS5Padding"`).
  - `key_tail_len`: Appended key length in bytes (default 16).
  - `max_table_size`: Maximum static array reconstruction size (default 4000000).
- **blackdex**:
  - `package_name`: Target application package name on device to unpack.
  - `device`: Optional ADB device serial number.
  - `wait_timeout_seconds`: Seconds to poll for dumped DEX outputs (default 60).
  - `auto_launch`: Launch BlackDex/target app via ADB intent (default `true`).
  - `apk_path`: Local BlackDex APK path override for device installation.

<examples>
```js
// 1. Probe availability and versions of all deobfuscation engines
deobfuscate({ action: "status" })

// 2. Simplify an MBA expression and formally prove equivalence with Z3
deobfuscate({
  action: "analyze",
  backend: "msynth",
  expression: "(x ^ y) + 2 * (x & y)",
  bit_width: 32,
  verify_smt: true
})

// 3. Deobfuscate string encryptions in an APK using JADX plugin
deobfuscate({
  action: "analyze",
  backend: "jadx",
  path: "sample.apk",
  out: "artifacts/jadx_out",
  fold_consts: true,
  decrypt_strings: true
})

// 4. Run d810-ng on an obfuscated function in IDA Pro 9+
deobfuscate({
  action: "analyze",
  backend: "d810-ng",
  path: "obfuscated_binary.i64",
  function: "0x140001000",
  unflattener: "ollvm",
  rules: ["mba", "ollvm", "cst_simplification"]
})

// 5. Run virtual execution deobfuscation with bounded visits using Simplify
deobfuscate({
  action: "analyze",
  backend: "simplify",
  path: "classes.dex",
  out: "artifacts/simplified.dex",
  include_types: ["Lcom/target/app/.*"],
  max_address_visits: 5000
})

// 6. Launch and retrieve dynamic DEX dumps via BlackDex on Android device
deobfuscate({
  action: "analyze",
  backend: "blackdex",
  package_name: "com.target.app",
  out: "artifacts/unpacked_dex",
  wait_timeout_seconds: 45
})
```
</examples>
