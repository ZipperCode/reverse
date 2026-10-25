Offline Dalvik CodeItem restoration and DEX reconstruction from FART runtime method dumps.

Capabilities:
- **Offline CodeItem Restoration (`repair`)**:
  - Restores dumped Dalvik method bytecode from FART (FRIDA-ART) runtime extractions (`*_ins.bin` or raw `.bin` dumps).
  - Correlates dumped method indices with target DEX `method_ids` table.
  - Detects and rejects invalid, truncated, or mismatched captures (e.g. name conflict, corrupt instruction payloads).
  - Handles changed-size CodeItems by 4-byte aligned relocation to the DEX data section.
  - Re-encodes `class_data_item` with updated ULEB128 code offsets and updates `class_def.class_data_off`.
  - Updates `file_size`, `data_size`, and Dalvik `map_list` item counts (`TYPE_CODE_ITEM`).
  - Recomputes DEX header signatures in standard order: SHA-1 signature (bytes 32..end) then Adler-32 checksum (bytes 12..end).
  - Dry run by default (`dry_run: true`): Previews matches, relocated offsets, and verifier checks without touching disk.
  - Fresh output enforcement (`dry_run: false`): Writes repaired DEX to an explicit fresh destination path with atomic replace.
- **DEX and Dump Census Status (`status`)**:
  - Inspects target DEX file for methods with empty or stripped code items (`code_off == 0`).
  - Evaluates provided FART record dumps and reports matched indices.

Inputs:
- `action`: `"status"` or `"repair"`.
- `path`: Target Dalvik executable (`.dex`) or Android package (`.apk`, `.zip`, `.xapk`). Alias: `target`.
- `entry`: Archive member when target is APK/ZIP (default `"classes.dex"`).
- `records`: Path to FART `*_ins.bin` file, directory of `.bin` files, or raw dump text. Aliases: `dump`, `bins`.
- `dry_run`: When `action: "repair"`, whether to preview without writing (default `true`).
- `out`: Output path for repaired DEX file (required when `dry_run: false`).

<examples>
```
// Preview FART offline repair for stripped DEX
dex_repair(
  action: "repair",
  path: "classes.dex",
  records: "dump/123456_ins.bin",
  dry_run: true
)
```

```
// Apply FART repair and save repaired DEX
dex_repair(
  action: "repair",
  path: "app.apk",
  entry: "classes.dex",
  records: "dump/123456_ins.bin",
  dry_run: false,
  out: "artifacts/classes_repaired.dex"
)
```
</examples>
