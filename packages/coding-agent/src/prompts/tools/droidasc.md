Fast, zero-prep Android reverse engineering queries against APK files (`.apk`). Queries the binary read-only without heavy JVM decompiler startup.

Input scope:
- Only Android `.apk` files are directly supported by `droidasc`.
- For raw `.dex` files, use `dexdump` or `jadx` (e.g. `jadx -d ./artifacts/jadx_out <target.dex>`).
- For `.aab` bundles, convert to universal APK first with `bundletool` or analyze with `jadx`.

Operations:
- `manifest` / `getmanifest`: Dumps decoded `AndroidManifest.xml` (package name, permissions, exported activities/services/receivers, entrypoints). Start here for reconnaissance.
- `listclass`: List Dalvik class descriptors across all DEX entries. Optional `prefix` to filter by package or class prefix (e.g. `com.example` or `Lcom/example`).
- `findrefs`: Global cross-reference search across all DEX files in the APK. Explicit `kind` subcommands:
  - `string`: Search for string literal references (default if `kind` is omitted; `query` required).
  - `type`: Search for class/type references (`query` or `class` required).
  - `method`: Search for method references (`query` method name and/or `class` filter; optional `fuzzy_class: true`).
  - `field`: Search for field references (`query` field name and/or `class` filter; optional `fuzzy_class: true`).
  - `extends`: Search for classes that extend target class (`class` or `query` required, e.g. `android.app.Activity`).
  - `impl`: Search for classes implementing target interface (`class` or `query` required, e.g. `android.os.IInterface`).
- `getclass`: On-demand single class decompilation directly to Java source. `class` is required (e.g. `com/example/app/auth/AuthManager` or `com.example.app.auth.AuthManager`).

When `droidasc` CLI is not found on PATH, returns structured installation hints (`pipx install droidasc` or `pip install droidasc`) and active fallback alternatives (`jadx`, `apktool`, `aapt2`, `dexdump`).

<examples>
```
droidasc(op: "manifest", target: "sample.apk")
droidasc(op: "listclass", target: "sample.apk", prefix: "com.example")
droidasc(op: "findrefs", target: "sample.apk", kind: "string", query: "checkLicense")
droidasc(op: "findrefs", target: "sample.apk", kind: "method", query: "onCreate", class: "com.example.MainActivity")
droidasc(op: "findrefs", target: "sample.apk", kind: "extends", class: "android.app.Activity")
droidasc(op: "getclass", target: "sample.apk", class: "com/example/app/auth/AuthManager")
```
</examples>
