# dex_patch

Guarded equal-length Dalvik instruction patching, method inspection, and limited structural validation. Adapted from the MIT-licensed apk-reverse toolkit at commit `bd6dd0c59ce1f9af75f1293ef9518fb6f5d28c6c`; attribution is preserved in `THIRD-PARTY-NOTICES.txt`.

## Source

- Tool: `packages/coding-agent/src/tools/dex-patch.ts`
- Embedded workers: `packages/coding-agent/src/tools/dex-patch-worker.py`, `dexutil.py`
- Model guidance: `packages/coding-agent/src/prompts/tools/dex-patch.md`

## Dependencies

Python 3.9+ and its standard library. Workers are embedded text assets in source, bundled, and compiled installations; no external script checkout or pip package is required. Resolve `dex_patching` through `reverse_capability`; missing Python uses the existing `reverse setup reverse python` installation surface.

## Actions

| Action | Inputs | Result |
| --- | --- | --- |
| `inspect` | `path`, `class`, `method`, optional `desc`, `entry` | Decoded method instructions, byte offsets, branch targets, structural violations |
| `validate` | `path`, optional `class`, `entry` | Header checksum/SHA-1, instruction boundaries, branch/payload and move-result constraints |
| `patch` | `path`, nonempty `specs`, optional `entry`, `dry_run`, `out` | Cumulative patch reports and changed byte spans; raw DEX output for an explicit write |

`path` accepts a raw DEX or an APK/ZIP; `entry` selects its DEX member (default `classes.dex`). `target` is also accepted for the input path. Class descriptors, method names, and an optional prototype locate the method; ambiguous overloads or instruction matches require explicit disambiguation.

## Example

```typescript
dex_patch({
  action: "inspect", path: "sample.apk", entry: "classes.dex",
  class: "Lcom/example/Config;", method: "value", desc: "()I"
});

dex_patch({
  action: "patch", path: "sample.apk", entry: "classes.dex",
  specs: [{
    class: "Lcom/example/Config;", method: "value", desc: "()I",
    match: { kind: "const4", literal: 1 },
    expect_next: { kind: "return" },
    replace: { kind: "bytes", bytes: "1230" }
  }]
});
```

The example first previews changing `const/4 v0, #1` to `const/4 v0, #3`; choose bytes from the inspected instruction, including the actual register. To write, repeat the approved specification with `dry_run: false` and a fresh `out: "artifacts/patched.dex"`.

## Safety and verification

- `dry_run` defaults to `true`; inspection, validation, and preview require read approval. Writing requires write approval.
- Each replacement covers exactly one selected instruction span and preserves byte length. `replace.kind: "nops"` fills that span with NOP instructions; `"bytes"` uses explicit hex.
- `match` supports instruction kind, exact bytes, applicable register/literal/invoke/branch-field criteria, and an optional zero-based `ordinal`. `expect_next` asserts the immediate successor. Inapplicable criteria do not silently match unrelated instructions.
- Source header integrity is checked before mutation. SHA-1 is recomputed before Adler-32 on the final bytes. Multiple specifications operate cumulatively.
- Original samples and existing destinations remain untouched. Output is published with an exclusive atomic link from private staging on the destination filesystem; filesystems without the required operation fail instead of using a partial-output fallback.
- Structural validation is not the full ART type verifier. Repack/sign the DEX using `apk_artifact`, then independently verify installation, launch, and the exact changed behavior. Record build hashes and patch coordinates through the existing evidence/build-lineage tools.
