# dex_search

> High-performance structured Dalvik/ART bytecode search engine powered by LuckyPray/DexKit (C++20 native core + JNI Java bridge). Enables deep queries for classes, methods, and fields matching complex string, signature, modifier, annotation, call graph, and cross-reference constraints directly against Android APK packages and raw DEX files.

## Source
- Entry tool: `packages/coding-agent/src/tools/dex-search.ts`
- Embedded Java bridge source: `packages/coding-agent/src/tools/dex-search/DexSearchBridge.java`; managed installation compiles its bundled text asset in private staging, including from standalone binaries.
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/dex-search.md`
- Dependency resolver: `packages/coding-agent/src/extensibility/protection-toolchain.ts` (`dexkit` tool ID)
- Upstream engine: [LuckyPray/DexKit](https://github.com/LuckyPray/DexKit) (v2.3.0)
- Upstream licenses: Core is LGPL-3.0 (retained as external managed native library); Java wrapper and bridge are Apache-2.0. No LGPL-3.0 Core source is vendored into the repository.

## Input Scope
- **Android APK packages (`.apk`)**: Multi-DEX APKs are parsed across all DEX entries concurrently.
- **Raw Dalvik executables (`.dex`)**: Direct support for raw `.dex` files without requiring an APK container.
- **JAR and ZIP archives (`.jar`, `.zip`)**: Any archive containing top-level `classes*.dex` entries.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `target` | `string` | Yes | Path to target Android `.apk`, `.dex`, or `.jar`/`.zip` archive. |
| `type` / `action` | `string` | No | Search query type: `'class'`, `'method'`, `'field'`, `'callers'`, `'callees'`, `'field_uses'`, `'batch_strings'`, or `'info'` (default: `'class'`). |
| `class` / `className` | `string` | No | Class name or pattern (e.g. `com.example.MainActivity` or `Lcom/example/MainActivity;`). |
| `name` / `methodName` / `fieldName` | `string` | No | Member name to match. |
| `return_type` / `returnType` | `string` | No | Method return type (e.g. `void`, `boolean`, `java.lang.String`). |
| `param_types` / `paramTypes` | `string[]` | No | Parameter type names (e.g. `['java.lang.String', 'int']`). |
| `field_type` / `fieldType` | `string` | No | Field type name (e.g. `java.lang.String`, `int`). |
| `super_class` / `superClass` | `string` | No | Superclass name to match in class queries. |
| `search_packages` / `searchPackages` | `string[]` | No | Package prefixes to restrict the search to (e.g. `['com.example']`). |
| `exclude_packages` / `excludePackages` | `string[]` | No | Package prefixes to exclude from search. |
| `using_strings` / `usingStrings` | `string[]` | No | String literal constants used by the class or method. |
| `using_numbers` / `usingNumbers` | `number[]` | No | Numeric constants used by the method. |
| `string_match_type` / `stringMatchType` | `string` | No | String matching mode: `'contains'` (default), `'equals'`, `'startsWith'`, `'endsWith'`, or `'similarRegex'`. |
| `ignore_case` / `ignoreCase` | `boolean` | No | Case-insensitive matching for string literals (default: `false`). |
| `modifiers` | `string[]` | No | Expected modifiers (e.g. `['public', 'static']`, `['final']`). |
| `target_method` / `method` | `string` | Conditional | Target method descriptor for `'callers'` or `'callees'` queries (e.g. `Lcom/example/Auth;->login(Ljava/lang/String;)Z`). |
| `target_field` / `field` | `string` | Conditional | Target field descriptor for `'field_uses'` queries (e.g. `Lcom/example/Auth;->token:Ljava/lang/String;`). |
| `groups` | `Record<string, string[]>` | Conditional | Search groups dictionary for `'batch_strings'` query. |
| `batch_target` / `batchTarget` | `string` | No | Target entity for `'batch_strings'` (`'class'` or `'method'`, default: `'method'`). |
| `limit` | `number` | No | Maximum results to return per page (default: `50`, max: `200`). |
| `offset` | `number` | No | Pagination offset (default: `0`). |
| `timeout` | `number` | No | Execution timeout seconds (default: `60`, max: `300`). |

## Operations

### 1. `class`
Searches for Dalvik classes matching name, superclass inheritance, implemented interfaces, modifiers, annotations, or string constants referenced anywhere in the class's methods.

### 2. `method`
Searches for Dalvik methods matching declaring class, method name, return type, parameter types (with exact or fuzzy arity), modifiers (static, native, abstract, etc.), annotations, string literals (`usingStrings`), and numeric constants (`usingNumbers`).

### 3. `field`
Searches for Dalvik fields matching declaring class, field name, field type, modifiers (static, final, volatile), and annotations.

### 4. `callers`
Cross-reference search for method callers (xref-to): finds all methods that invoke the specified `target_method`. Essential for locating who triggers a licensing check, cryptographic primitive, or security gate.

### 5. `callees` (or `invokes`)
Call-graph query for method invocations (xref-from): finds all methods called by the specified `target_method`. Useful for identifying dependencies, network requests, and cryptographic operations initiated from an entrypoint.

### 6. `field_uses` (or `field_refs`)
Field cross-reference search: identifies all methods that read (`iget`/`sget`) or write (`iput`/`sput`) the specified `target_field`. Crucial for tracing where sensitive keys, session tokens, or flags are assigned and inspected.

### 7. `batch_strings`
Performs parallel searches for multiple groups of string literal constants in a single pass. Returns results grouped by dictionary category name (e.g. identifying both cryptographic routines and licensing checks in one invocation).

### 8. `info`
Fast inspection of DEX count and DexKit engine version.

## Handoff & Toolchain Interoperability
- **Frida Handoff**: Each returned method includes ready-to-run Frida hook templates with argument logging and implementation interception.
- **JADX Handoff**: Exact class coordinates and smali descriptors enable immediate navigation in JADX GUI or batch decompilation via CLI.
- **Provenance**: Calculates SHA-256 target hash and records exact match coordinates to guarantee repeatable reverse engineering findings.

## Missing Dependency Handling
When the `dexkit` engine components (`dexkit-bridge.jar` or `libdexkit` native library) are not detected in the managed directory (`<agentDir>/tools/dexkit/`), the tool does not fail catastrophically. It returns a structured status:
- `executed: false`
- `status: "missing_dependency"`
- `setupCommand: "reverse setup reverse dexkit --execute"`
- Suggested fallbacks to `droidasc` or `dex_patch`.

## Limitations
- **Static Bytecode Scope**: DexKit performs static indexing and search over Dalvik bytecode. It does not execute instructions or bypass dynamic runtime packers/protectors. Packed or stub APKs should first be unpacked with `dex_unpack` or `fart`.
- **Native Code Boundaries**: Only analyzes Dalvik bytecode classes, methods, and fields. JNI native implementations inside `.so` shared libraries are out of scope; inspect them with `elf_inspect` or `ghidra_inspect`.
- **Dynamic Reflection**: Dynamically computed class/method names or runtime-decrypted strings cannot be statically matched until string decryption or deobfuscation is applied (use `deobfuscate` plugin).
- **Target Size Limits**: Files exceeding 2 GiB are rejected (`DEX_SEARCH_MAX_TARGET_BYTES = 2 GiB`). Results are paged with a maximum of 200 items per query to prevent token context exhaustion.
- **Runtime Dependencies**: Requires host `java` (OpenJDK 11+) and compiled DexKit native core (`libdexkit.dylib` on macOS arm64/x86_64, `libdexkit.so` on Linux). Install via `reverse setup reverse dexkit --execute`.
