# apk_artifact

APK entry-level diff, DEX replacement, aligned repacking, signing, verification, and explicit-device installation/launch checks. Adapted from the MIT-licensed apk-reverse toolkit at commit `bd6dd0c59ce1f9af75f1293ef9518fb6f5d28c6c`.

## Source

- Tool: `packages/coding-agent/src/tools/apk-artifact.ts`
- Embedded worker: `packages/coding-agent/src/tools/apk-artifact/worker.py`
- Model guidance: `packages/coding-agent/src/prompts/tools/apk-artifact.md`

## Actions and dependencies

| Action | Required inputs | Dependencies / result |
| --- | --- | --- |
| `diff` | `original_path` (or `path`), `modified_path` | Python 3.9+; SHA-256 entry comparison, content/compression/layout differences, additions/removals |
| `repack` | `path`, fresh `output_path` | Python 3.9+; optional `dex_files` map or `dex_path`; explicitly unsigned unless `sign: true` |
| `sign` | `path`, fresh `output_path`, `keystore_path`, `key_alias`, password reference | Python, zipalign, apksigner, Java; alignment before signing, then cryptographic verification |
| `verify` | `path` | Python for ZIP/CRC/layout checks; apksigner and Java for cryptographic APK verification |
| `install_verify` | `path`, `package` (or `package_name`), `activity`, explicit `serial` | Python and adb, authorized device; exact installed APK hash and two-sample launch stability |

Use `reverse_capability({ action: "resolve", capability: "apk_artifact_generation" })` for separate offline, signing, and device-host readiness. Catalog readiness does not establish that a device is connected. Missing dependencies use the existing CLI/TUI setup catalog (`reverse setup reverse python`, `zipalign`, `apksigner`, `java`, `adb`). No dependency is installed implicitly.

## Repack, compare, sign

```typescript
apk_artifact({
  action: "repack", path: "original.apk",
  output_path: "artifacts/unsigned.apk",
  dex_files: { "classes.dex": "artifacts/patched.dex" }
});
apk_artifact({
  action: "diff", original_path: "original.apk",
  modified_path: "artifacts/unsigned.apk"
});
apk_artifact({
  action: "sign", path: "artifacts/unsigned.apk",
  output_path: "artifacts/signed.apk",
  keystore_path: "keys/lab.jks", key_alias: "lab",
  ks_pass_env: "LAB_KEYSTORE_PASSWORD", min_sdk_version: 21
});
apk_artifact({ action: "verify", path: "artifacts/signed.apk", min_sdk_version: 21 });
```

`repack` can also request `sign: true` with the same signing parameters; the final requested path is published only after signing and verification succeed. It strips direct signature metadata under `META-INF` by default and preserves nested services and other runtime resources. `resources.arsc` is STORED and 4-byte aligned; stored native libraries are 16KiB page-aligned by default. This controls APK packaging, not the library's internal ELF segment alignment.

`dex_files` maps entry names to local DEX paths; new entries can also be supplied. Replacements are not a full DEX rebuild or ART verification. Use `dex_patch` for method-level inspection and guarded edits.

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
  action: "install_verify", path: "artifacts/signed.apk",
  package: "com.example.app", activity: ".MainActivity",
  serial: "emulator-5554", output_dir: "artifacts/device-run"
});
```

Use a fresh `output_dir` for screenshots and process-scoped logs; an explicit `screenshot_path` is also supported. `wait_seconds` controls the interval between PID samples. Installation preserves app data and logcat history; launch checking stops an existing target process before starting the requested Activity. Optional `grant_permissions` explicitly grants listed permissions.

The installed base APK is pulled and hash-compared with the input artifact. A stable process and screenshot are installation/launch evidence only: `feature_verified` remains `false`. Exercise the exact changed feature separately and bind verified evidence to the artifact hash through existing workflow/build-lineage APIs.

## Output safety

Original samples and existing output files are preserved. Repack/sign outputs use private staging on the destination filesystem and exclusive publication. Invalid archives, duplicate entries, encrypted data, and oversized decompressed content are rejected. Diff filtering (`filter`, a regex) limits displayed entries without hiding whether any differences exist; `max_entries` limits each displayed section.
