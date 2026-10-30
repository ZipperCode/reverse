# dex_repair

Offline Dalvik CodeItem restoration and DEX reconstruction from FART runtime method dumps. Derived from the Apache-2.0 licensed FART project (`https://github.com/hanbinglengyue/FART`) and Dalvik executable specifications; attribution is preserved in `packages/coding-agent/THIRD-PARTY-NOTICES.txt`.

## Source

- Tool: `packages/coding-agent/src/tools/dex-repair.ts`
- Embedded worker: `packages/coding-agent/src/tools/dex-repair-worker.py`
- Shared DEX utility: `packages/coding-agent/src/tools/dexutil.py`
- Model guidance: `packages/coding-agent/src/prompts/tools/dex-repair.md`

## Dependencies

Python 3.9+ and its standard library. Workers and utilities are embedded text assets in source, bundled, and compiled installations; no third-party pip packages are required. Python environment resolution uses the existing `reverse setup reverse python` installation surface.

## Actions

| Action | Inputs | Result |
| --- | --- | --- |
| `status` | optional `path`, optional `records`, `entry` | Readiness status, DEX empty-method census, and parsed records preview |
| `repair` | `path`, `records`, optional `dry_run`, `out`, `entry` | Relocated CodeItem restoration report, header updates, and repaired DEX output |

`path` accepts a raw `.dex` file or an `.apk`/`.zip` container; `entry` selects its DEX member (default `classes.dex`). `records` accepts a FART `*_ins.bin` file, a directory of dumped `.bin` files, or raw dump text.

## Features

- **Robust Relocation Engine**:
  - Handles changed-size CodeItems by appending new 4-byte aligned CodeItems to the data section.
  - Re-serializes the corresponding class's `class_data_item` with updated ULEB128 code offsets.
  - Updates `class_def.class_data_off` (fixed 4-byte uint32), preserving alignment without in-place collision hazards.
  - Updates Dalvik `map_list` counts (`TYPE_CODE_ITEM`) and file header `file_size` and `data_size`.
- **Integrity Validation**:
  - Validates CodeItem header fields (registers, ins, outs, tries, debug_info, insns_size).
  - Validates instruction opcodes and unit lengths across the entire instruction payload.
  - Correlates `method_idx` with DEX `method_ids` and detects mismatched captures or conflicting class names.
  - Recomputes DEX signatures in standard order: SHA-1 signature (bytes 32..end) then Adler-32 checksum (bytes 12..end).
  - Verifies post-repair structural cleanliness via `Dex.check()`.
- **Safety Enforcement**:
  - `dry_run` defaults to `true`; previewing repairs requires read approval.
  - Writing requires `dry_run: false`, explicit fresh `out` destination, and write approval.
  - Rejecting input/output aliasing and hardlink collision.

## Example

```typescript
// Preview FART offline repair
dex_repair({
  action: "repair",
  path: "sample.apk",
  entry: "classes.dex",
  records: "dumps/722044_ins.bin",
  dry_run: true
});

// Write repaired DEX
dex_repair({
  action: "repair",
  path: "sample.apk",
  entry: "classes.dex",
  records: "dumps/722044_ins.bin",
  dry_run: false,
  out: "artifacts/classes_repaired.dex"
});
```
