# apk_artifact

APK entry-level diff, DEX replacement, aligned repacking, signing, verification, and explicit-device installation/launch checks. Adapted from the MIT-licensed apk-reverse toolkit at commit `bd6dd0c59ce1f9af75f1293ef9518fb6f5d28c6c`.

## Source

- Tool: `packages/coding-agent/src/tools/apk-artifact.ts`
- Embedded worker: `packages/coding-agent/src/tools/apk-artifact/worker.py`
- Model guidance: `packages/coding-agent/src/prompts/tools/apk-artifact.md`

## Actions and dependencies

| Action | Required inputs | Dependencies / result |
| --- | --- | --- |
| `diff` | `original_path` (or `path`), `modified_path`; or `original_package_set`, `modified_package_set` | Python 3.9+; SHA-256 entry comparison, content/compression/layout differences, additions/removals across single APKs or split package sets |
| `repack` | `path` & `output_path`; or `package_set` & `output_package_dir` | Python 3.9+; optional `dex_files` map, `replace_files` map, `dex_path`, or `per_member_replacements`; produces aligned APK or split package set with `package-set.json` manifest; explicitly unsigned unless `sign: true` |
| `sign` | `path` & `output_path`; or `package_set` & `output_package_dir`; keystore parameters | Python, zipalign, apksigner, Java; alignment before signing, common signing across package set members, then cryptographic verification |
| `verify` | `path`; or `package_set` | Python for ZIP/CRC/layout checks; apksigner and Java for cryptographic APK verification; validates consistent package name, versionCode, and signer fingerprints across split sets |
| `install_verify` | `path` or `package_set`, `package` (or `package_name`), `activity`, explicit `serial` | Python and adb, authorized device; executes `adb install` or `adb install-multiple -r -t`; validates exact installed APK SHA-256 for all members and checks launch stability |

Use `reverse_capability({ action: "resolve", capability: "apk_artifact_generation" })` for separate offline, signing, and device-host readiness. Catalog readiness does not establish that a device is connected. Missing dependencies use the existing CLI/TUI setup catalog (`reverse setup reverse python`, `zipalign`, `apksigner`, `java`, `adb`). No dependency is installed implicitly.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"diff"`, `"repack"`, `"sign"`, `"verify"`, `"install_verify"`. |
| `path` | `string` | No* | Input target APK file path (alias `original_path`). |
| `original_path` | `string` | No | Alias for `path` in `diff`. |
| `modified_path` | `string` | No | Path to modified APK file in `diff`. |
| `output_path` | `string` | No* | Fresh destination path for repacked or signed APK artifact. |
| `dex_files` | `Record<string, string>` | No | Mapping of DEX entry names to replacement DEX files on disk (e.g. `{"classes.dex": "patched.dex"}`). |
| `dex_path` | `string` | No | Shorthand local path to replace `"classes.dex"`. |
| `replace_files` | `Record<string, string>` | No | Map of arbitrary APK entry names (e.g. `lib/arm64-v8a/libnative.so`, assets) to replacement file paths on disk for multi-component repacks or deterministic replays. Overlapping entries with `dex_files` are strictly rejected. |
| `strip_signatures` | `boolean` | No | Strip direct signature files under `META-INF` (default `true`). |
| `page_align_so` | `boolean` | No | Align stored native shared libraries to 16 KiB (default `true`). |
| `sign` | `boolean` | No | Sign artifact immediately during repack (default `false`). |
| `keystore_path` | `string` | No | Path to Java keystore (`.jks` / `.keystore`) for signing. |
| `key_alias` | `string` | No | Key alias within the keystore. |
| `ks_pass_env` | `string` | No | Environment variable holding the keystore password. |
| `ks_pass_file` | `string` | No | Protected file path holding the keystore password. |
| `min_sdk_version` | `number` | No | Minimum SDK version for alignment and signing (default 21). |
| `package` | `string` | No | Android package name for `install_verify` (alias `package_name`). |
| `activity` | `string` | No | Activity name to launch for `install_verify` (e.g. `".MainActivity"`). |
| `serial` | `string` | No | Explicit device serial identifier for `install_verify`. |
| `package_set` | `Record<string, unknown>` | No | Explicit split APK package set: `{ base: "path/to/base.apk", splits: { "config.arm64_v8a": "path/to/split.apk" } }`. |
| `original_package_set` | `Record<string, unknown>` | No | Original package set for `diff` action. |
| `modified_package_set` | `Record<string, unknown>` | No | Modified package set for `diff` action. |
| `output_package_dir` | `string` | No | Fresh destination directory path for repacked or signed split package set (produces member APKs and `package-set.json` manifest; overwriting existing directories is strictly rejected). |
| `per_member_replacements` | `Record<string, unknown>` | No | Per-member replacement declarations for split package sets: `{ [member_name: string]: { dex_files?: Record<string, string>, dex_path?: string, replace_files?: Record<string, string> } }`. |

## Repack, compare, sign

```typescript
// 1. Repack with both DEX and native .so file replacements
apk_artifact({
  action: "repack",
  path: "original.apk",
  output_path: "artifacts/unsigned.apk",
  dex_files: { "classes.dex": "artifacts/patched.dex" },
  replace_files: { "lib/arm64-v8a/libnative.so": "artifacts/libnative_patched.so" }
});

// 2. Diff entry differences
apk_artifact({
  action: "diff",
  original_path: "original.apk",
  modified_path: "artifacts/unsigned.apk"
});

// 3. Align and sign
apk_artifact({
  action: "sign",
  path: "artifacts/unsigned.apk",
  output_path: "artifacts/signed.apk",
  keystore_path: "keys/lab.jks",
  key_alias: "lab",
  ks_pass_env: "LAB_KEYSTORE_PASSWORD",
  min_sdk_version: 21
});

// 4. Verify cryptographic signature and alignment
apk_artifact({
  action: "verify",
  path: "artifacts/signed.apk",
  min_sdk_version: 21
});
```
## Split APK Package Sets (Base + Splits)

`apk_artifact` supports multi-APK split package sets (base APK + named configuration or dynamic feature splits) as first-class identities across all actions:

1. **Canonical Schema (`package_set`)**:
   - Explicit map with required `base` APK path and optional `splits` map:
     `{ base: "base.apk", splits: { "config.arm64_v8a": "splits/arm64.apk", "config.xxhdpi": "splits/xxhdpi.apk" } }`.
   - Member names must be unique and match `[A-Za-z0-9_.-]`.
   - All input files must exist and be distinct (no duplicate file paths across members).

2. **Per-Member Replacements (`per_member_replacements`)**:
   - Targets specific members for surgical DEX and binary replacements:
     `{ base: { dex_path: "patched.dex" }, "config.arm64_v8a": { replace_files: { "lib/arm64-v8a/libnative.so": "libs/libnative.so" } } }`.
   - Top-level `dex_files` / `replace_files` / `dex_path` applies to `base` when omitted from `per_member_replacements`.

3. **Private Staging and Manifest-Last Publication**:
   - Repacked and signed sets are assembled and checked in private staging directories on the output filesystem.
   - Publication reserves `output_package_dir` exclusively, creates an ownership token, links member APKs, then publishes `package-set.json` last. This is a manifest-marker transaction rather than an atomic directory rename; controlled readers reject token-bearing directories without a manifest.
   - The manifest records package name, versionCode, aggregate `set_sha256`, and per-member metadata (size, SHA-256, alignment, signing state). Every reuse verifies all member hashes and the exact supplied member map, including builds with zero patches.
   - On failure, rollback removes only task-owned files whose inode, device, and hash still match. Concurrent or replaced files are preserved, so an externally modified destination may remain for inspection.

4. **Semantic Consistency & Signer Verification**:
   - Verification and pre-install checks ensure all members declare the exact same Android `package` name and `versionCode`.
   - When signed, all members in the package set must be signed with the same key and yield identical signer certificate fingerprints. Mismatched signers or package metadata cause immediate rejection.
   - Missing verification tools report unverified status without falsely asserting validity.

5. **On-Device Installation & Verification (`install-multiple`)**:
   - Split sets are installed using `adb install-multiple -r -t` (downgrade `-d` is not automatically passed).
   - The tool queries `pm path <package>`, pulls all installed APKs, and validates the exact SHA-256 of every member on device.
   - If device APK members are missing, extra, or have mismatched hashes, verification fails immediately.

```typescript
// Repack split package set with per-member replacements
apk_artifact({
  action: "repack",
  package_set: {
    base: "builds/base.apk",
    splits: {
      "config.arm64_v8a": "builds/split_arm64.apk",
      "config.xxhdpi": "builds/split_xxhdpi.apk"
    }
  },
  output_package_dir: "dist/repacked_set",
  per_member_replacements: {
    base: { dex_path: "out/classes.dex" },
    "config.arm64_v8a": { replace_files: { "lib/arm64-v8a/libnative.so": "out/libnative.so" } }
  }
});

// Install and verify on-device split package set
apk_artifact({
  action: "install_verify",
  package_set: {
    base: "dist/repacked_set/base.apk",
    splits: {
      "config.arm64_v8a": "dist/repacked_set/config.arm64_v8a.apk",
      "config.xxhdpi": "dist/repacked_set/config.xxhdpi.apk"
    }
  },
  package: "com.example.app",
  activity: ".MainActivity",
  serial: "emulator-5554"
});
```

`repack` can also request `sign: true` with the same signing parameters; the final requested path is published only after signing and verification succeed. It strips direct signature metadata under `META-INF` by default and preserves nested services and other runtime resources. `resources.arsc` is STORED and 4-byte aligned; stored native libraries are 16KiB page-aligned by default. This controls APK packaging, not the library's internal ELF segment alignment.

`dex_files` maps entry names to local DEX paths; `replace_files` maps arbitrary entry names (such as native `.so` binaries or asset files) to local replacement files. Replacements are not a full DEX rebuild or ART verification. Use `dex_patch` for method-level inspection and guarded edits. Duplicate replacement definitions overlapping between `dex_files` and `replace_files` are strictly rejected.

## Cumulative Lineage & Staged Publication Rollback

1. **Cumulative Baseline Patchset Preservation (A + B Replay)**:
   - When repacking from a clean original base or earlier derivative, `apk_artifact` consults active workflow lineage.
   - All previously verified active baseline patches must be preserved (deterministic replay A + B) or explicitly retired with an audit trail via `retire_patch` or `retired_patches` carrying a mandatory `retirement_reason`.
   - The tool inspects container member bytes directly prior to publication; dropping verified baseline patches causes immediate rejection, and staged output is discarded without publication.

2. **Private Staging & Exclusive Publication**:
   - Repacked and signed artifacts are assembled in private staging files on the destination filesystem (`.tmp-stage-...`).
   - Publication uses atomic hard linking or exclusive copy (`COPYFILE_EXCL`), ensuring incomplete builds never appear at destination paths.

3. **Ownership Rollback**:
   - If subsequent workflow derivative registration fails, the newly published output file is automatically unlinked and rolled back to maintain strict ownership and build lineage integrity.

## Signing credentials and verification

- Supply `ks_pass_env` or a protected `ks_pass_file`. Separate key passwords use optional `key_pass_env` / `key_pass_file`.
- Password literals are not tool parameters and are not passed as plaintext process arguments. Only explicitly selected environment variables are forwarded to the worker.
- Existing keystores are required; no default key is silently created.
- Optional `apksigner_path` accepts an executable or JAR; `zipalign_path` and `java_path` select explicit installed tools.
- `min_sdk_version` defaults to 21; `max_sdk_version` is optional. Signing enables v1/v2/v3; no v4 delivery is claimed.
- ZIP integrity, alignment, signature-block presence, and actual cryptographic verification are separate result fields. Missing apksigner never produces a verified APK result.

## Device evidence

```typescript
apk_artifact({
  action: "install_verify",
  path: "artifacts/signed.apk",
  package: "com.example.app",
  activity: ".MainActivity",
  serial: "emulator-5554",
  output_dir: "artifacts/device-run"
});
```

Use a fresh `output_dir` for screenshots and process-scoped logs; an explicit `screenshot_path` is also supported. `wait_seconds` controls the interval between PID samples. Installation preserves app data and logcat history; launch checking stops an existing target process before starting the requested Activity. Optional `grant_permissions` explicitly grants listed permissions.

The installed base APK is pulled and hash-compared with the input artifact. A stable process and screenshot are installation/launch evidence only: `feature_verified` remains `false`. Exercise the exact changed feature separately and bind verified evidence to the artifact hash through existing workflow/build-lineage APIs.

## Execution and Verification Boundaries

- **Python Subprocess Boundaries**: Arbitrary Python worker execution uses managed child process trees and numeric PID tracking to handle timeout and termination safely within agent session ownership. This process-level management is not a full OS-level sandbox or hardware container.
- **Runtime Environment Verification**: True physical Android devices and hardware runtimes were not validated on host environments without device connections. Offline tool checks verify packaging and cryptographic signatures, while live device execution requires explicitly specified device serials.
