First-class Android APK artifact manipulation, verification, and on-device validation tool. Provides entry-level binary diffing, surgical repacking with DEX replacements and signature preservation, zipalign and apksigner signing, ZIP container integrity and alignment verification, and on-device install-and-launch validation.

Actions:
- `diff`: Entry-level APK diff comparing content hashes (SHA-256), sizes, compression types, and CRC between two builds. Explicitly flags same-size modifications (where byte content and hash changed but size remained identical), entry additions, removals, and signature artifact noise.
- `repack`: Replaces specified existing DEX entries (e.g. `classes.dex`, `classes2.dex`) or adds new ones into a target APK. Strips ONLY actual signature metadata (`META-INF/*.SF`, `*.RSA`, `*.DSA`, `*.EC`, `MANIFEST.MF`) while strictly preserving `META-INF/services/` and all non-signature descriptors. Enforces STORED and 4-byte alignment for `resources.arsc` and 16KiB page alignment for uncompressed native libraries (`lib/**/*.so`) for Android 15+ embedded loading. Ensures UTF-8 entry naming.
- `sign`: Cryptographic APK signing pipeline. Runs `zipalign` BEFORE `apksigner` (load-bearing order), signs with v1, v2, and v3 signature schemes using an existing keystore, verifies the resulting artifact immediately, and reports certificate SHA-256 fingerprints. Never accepts plaintext passwords in parameters; requires an environment variable or protected password file. Supports both executable `apksigner` and `lib/apksigner.jar`.
- `verify`: Structural and cryptographic APK verification. Validates ZIP archive integrity and entry CRCs, validates STORED layout and 4-byte alignment for `resources.arsc` and 16KiB page alignment for native `.so` files, checks APK Signing Block presence, and runs `apksigner verify` with explicit min/max SDK versions. If signature tools are absent, reports unverified status without falsely asserting validity.
- `install_verify`: Automated on-device install and launch stability check over ADB. Installs the APK without destroying device history, pulls the installed base APK from the device to confirm exact SHA-256 build identity, launches the target activity, samples PID twice across a delay interval to detect crash loops, captures process-scoped logs without clearing logcat, and optionally pulls a screenshot. Explicitly separates launch stability from feature behavior: requires manual/targeted testing to verify patched feature functionality.

Parameters:
- `action`: Action to execute (`diff`, `repack`, `sign`, `verify`, `install_verify`).
- `path`: Target APK path for repack, sign, or verify; or original APK for diff.
- `original_path`: Explicit path to original APK for diff (alias for path).
- `modified_path`: Path to modified APK for diff.
- `output_path`: Output path for repacked or signed APK artifact. Required for repack and sign. Existing files are strictly rejected (no overwriting existing outputs).
- `dex_files`: Map of entry names to replacement DEX files on disk (`{"classes.dex": "out/patched.dex"}`).
- `dex_path`: Shorthand replacement path for `classes.dex`.
- `replace_files`: Map of arbitrary APK entry names (e.g. `lib/arm64-v8a/libnative.so`, `assets/config.json`) to replacement file paths on disk for multi-component repack or deterministic replay.
- `workflow_id`: Explicit reverse workflow ID to link this artifact build to (automatically discovered from sample if omitted).
- `register_derivative`: Whether to automatically record and verify the derivative artifact in the active reverse workflow lineage (default `true` when linked to an active workflow).
- `build_id`: Explicit build identifier for the derivative artifact record in the workflow lineage.
- `patches`: Optional list of patch records introduced in this build revision (e.g. `[{ patch_id, member_path, offset, original_bytes, expected_bytes }]`).
- `runtime_evidence_ids`: Optional list of verified runtime evidence IDs bound to this exact artifact output SHA-256.
- `strip_signatures`: Whether to strip signature metadata during repack while preserving `META-INF/services/` (default `true`).
- `sign`: Whether to automatically sign the artifact after repacking (default `false`).
- `page_align_so`: Whether to align uncompressed native `.so` libraries to 16KiB page boundaries for Android 15+ (default `true`).
- `keystore_path`: Path to existing Java/Android keystore file.
- `key_alias`: Key alias inside the keystore.
- `ks_pass_env`: Name of the environment variable holding the keystore password (recommended; no plaintext passwords).
- `ks_pass_file`: Path to protected file containing keystore password.
- `key_pass_env`: Name of the environment variable holding the key password (defaults to keystore password).
- `key_pass_file`: Path to protected file containing key password.
- `min_sdk_version`: Minimum Android SDK version for apksigner (default `21`).
- `max_sdk_version`: Maximum Android SDK version for apksigner.
- `apksigner_path`: Explicit path to apksigner binary, script, or `lib/apksigner.jar`.
- `zipalign_path`: Explicit path to zipalign binary.
- `java_path`: Explicit path to java binary (used when apksigner is a JAR).
- `filter`: Regex pattern to filter entry names in diff action.
- `max_entries`: Maximum entries displayed per section in diff action (default `200`).
- `package` / `package_name`: Package name for install_verify (e.g. `com.example.app`).
- `activity`: Launch activity for install_verify (e.g. `.MainActivity` or full component name).
- `serial`: Explicit ADB device serial. Mandatory for install_verify (no choosing implicit device).
- `output_dir`: Fresh directory to save screenshot and process log artifacts during install_verify.
- `screenshot_path`: Destination path to save on-device screenshot artifact.
- `grant_permissions`: Optional permissions list to grant after installation.
- `wait_seconds`: Seconds between PID samples during launch check (default `10`).

Safety & Security Rules:
- Strict no-overwrite policy: output files and directories must be fresh; existing files are never overwritten.
- Rejects input/output aliasing: output cannot overwrite or link to input.
- Never accepts secret literals or passwords in schema or logs; credentials must come from environment variables or protected files.
- Preserves all non-signature `META-INF` resources (e.g. `META-INF/services/`).
- Writing is atomic through private temporary files; failures clean up temporary files immediately without leaving partial artifacts.
- Absence of signing or verification tools is never reported as verification success.
- On-device testing does not wipe app data or clear system logcat; captures process-scoped logs and strictly avoids assuming root (`su`).
- Launch stability is never conflated with functional correctness; the tool explicitly requires separate manual verification of modified features.
- Cumulative baseline preservation: all active baseline patches in the reverse workflow lineage must be preserved in staged output BEFORE publication or installation. Repacking from clean original base dropping active native or DEX patches is rejected and staged output is discarded without publication. Deterministic replay A+B or explicit patch retirement is supported.
<examples>
```
apk_artifact(action: "diff", original_path: "app-orig.apk", modified_path: "app-mod.apk")
apk_artifact(action: "repack", path: "app-orig.apk", output_path: "app-repacked.apk", dex_files: { "classes.dex": "classes.dex" })
apk_artifact(action: "sign", path: "app-repacked.apk", output_path: "app-signed.apk", keystore_path: "dev.keystore", key_alias: "key0", ks_pass_env: "ANDROID_KS_PASS")
apk_artifact(action: "verify", path: "app-signed.apk")
apk_artifact(action: "install_verify", path: "app-signed.apk", package: "com.example.app", activity: ".MainActivity", serial: "emulator-5554", output_dir: "artifacts/device_run")
```
</examples>
