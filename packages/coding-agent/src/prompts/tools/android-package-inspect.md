Native read-only inspection of Android application packages (`.apk`), Android App Bundles (`.aab`), APK sets (`.apks`), and bare Dalvik executable binaries (`.dex`). Parses container entries, DEX headers, Android Binary XML (AXML) manifests, signature schemes (v1/v2/v3/v3.1/SourceStamp), and resource trees in-process with zero external dependencies, plus optional bridges for `apksigner` and `aapt2`.

Actions:
- `info`: High-level container and binary triage. For packages: container entries, manifest presence, DEX file list and header summaries, native libraries grouped by ABI, resource breakdown, and signing presence. For bare DEX: full header fields (version, size, endian, class/method/field/string/type counts) and sample classes.
- `manifest`: Bounded metadata inspection of `AndroidManifest.xml` (package name, versionCode, versionName, minSdkVersion, targetSdkVersion, compileSdkVersion, permissions, application attributes, activities, services, receivers, providers). Safely decodes Android Binary XML (AXML) and text XML; reports structured unsupported status without fake values for compiled protobuf (AAB) or corrupted manifests. Not applicable to bare DEX.
- `dex`: DEX header summaries and class listing across package DEX files or bare DEX. Supports `dex_index` or `dex` name filter, substring `filter` for class descriptors, and pagination (`limit`, `offset`).
- `signing`: Signature scheme verification evidence. Inspects v1 JAR signing files (`META-INF/MANIFEST.MF`, `*.SF`, `*.RSA/DSA/EC`), native APK Signing Block (v2, v3, v3.1, SourceStamp IDs), and reports optional `apksigner` bridge availability or execution status. Not applicable to bare DEX.
- `resources`: Resource hierarchy and metadata. Inspects `resources.arsc` header and package info, categorizes resource entries (layouts, drawables, values, xml, raw, assets), supports filename filtering, and reports optional `aapt2` bridge status. Not applicable to bare DEX.

Parameters:
- `action`: Inspection action (`info`, `manifest`, `dex`, `signing`, `resources`).
- `path` / `target`: Target file path (.apk, .aab, .apks, or .dex).
- `dex_index` / `dex`: Scopes `dex` action to a specific DEX entry by 0-based index or filename.
- `filter`: Substring filter for class descriptors in `dex` action or file names in `resources` action.
- `limit`: Maximum list entries returned (default 50, max 500).
- `offset`: Zero-based pagination offset (default 0).
- `use_bridge`: Set to `true` to invoke installed external tools (`apksigner` or `aapt2`) for deeper verification (default `false`).
- `max_bytes`: Maximum file bytes to read (default 200 MiB).

Safety & Boundary:
- Pure read-only operation: never modifies, unpacks, signs, or installs target files.
- Operates in-process without requiring Java, Android SDK, or third-party tools; optional bridges degrade gracefully with structured hints when tools are missing.
- Non-Android binaries or unsupported file types return structured `status: "unsupported"` without failing agent turns.

<examples>
```
android_package_inspect(action: "info", path: "app-release.apk")
android_package_inspect(action: "manifest", path: "app-release.apk")
android_package_inspect(action: "dex", path: "classes.dex", limit: 30)
android_package_inspect(action: "dex", path: "app-release.apk", filter: "Auth")
android_package_inspect(action: "signing", path: "app-release.apk")
android_package_inspect(action: "resources", path: "bundle.aab", filter: "network")
```
</examples>
