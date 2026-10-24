Native Dalvik DEX bytecode inspection, structural validation, and guarded equal-length bytecode patching.

Capabilities:
- **Method Bytecode Inspection (`inspect`)**:
  - Locates target method by class (`class`), method name (`method`), and optional descriptor (`desc`).
  - Supports raw DEX files or APK/ZIP containers (`entry`, defaults to `classes.dex`).
  - Decodes Dalvik instructions with exact format and width specifications.
  - Resolves branch targets, registers, parameter counts, and method offsets.
  - Audits control-flow graph for branch-into-move-result verifier violations.
- **Structural Integrity Validation (`validate`)**:
  - Performs limited structural verification (header integrity, instruction boundaries, CFG branch legality).
  - Verifies Adler-32 checksum and SHA-1 signature consistency.
  - Audits method decode cleanliness across all classes in the image.
  - Detects verifier violations (e.g. conditional branches directly targeting `move-result*`).
  - Collects method body census (`empty`, `stub`, `erased`, `minimal`, `real`).
  - Note: Labeled as a limited structural verifier; not a replacement for full Android ART runtime verification or dex2oat compilation.
- **Guarded Byte-Level Patching (`patch`)**:
  - Executes semantic patch specifications (`specs`) matching instructions by kind (`if-test`, `if-testz`, `invoke`, `const4`, `return`, `nop`, opcode name), registers, field references, or raw bytes.
  - Polarity checking (`expect_next`): Verifies the immediate successor instruction to guarantee branches point to the intended path.
  - Cumulative multi-patch correctness: Evaluates multiple patch specifications sequentially, ensuring subsequent matches and CFG checks observe preceding edits.
  - Enforces equal-length replacement and aligned instruction unit boundaries.
  - Enforces verifier legality: Rejects branches targeting `move-result*` instructions.
  - Dry run by default (`dry_run: true`): Reports proposed matches, neighbor instructions, and byte diffs without touching disk.
  - Fresh output enforcement (`dry_run: false`): Requires explicit `out` path, rejects input/output aliasing, and prevents accidental overwrites.
  - Recomputes DEX header signature (SHA-1) first, then checksum (Adler-32), and post-validates the final DEX image.
  - Returns structured byte-diff report. Output is raw DEX suitable for downstream repack.

Inputs:
- `action`: `"inspect"`, `"validate"`, or `"patch"`.
- `path`: Path to Dalvik executable (`.dex`) or Android package (`.apk`, `.zip`, `.xapk`). Alias: `target`.
- `entry`: Optional archive member (e.g. `"classes.dex"` or `"classes2.dex"`).
- `class`: Target class descriptor or FQCN (e.g. `"Lcom/example/License;"` or `"com.example.License"`).
- `method`: Target method name (e.g. `"isLicensed"`).
- `desc`: Optional method prototype descriptor to disambiguate overloads (e.g. `"(Landroid/content/Context;)Z"`).
- `dry_run`: When `action: "patch"`, whether to simulate without writing output (default `true`).
- `out`: Output DEX file path (required when `action: "patch"` and `dry_run: false`). Must be a fresh path.
- `specs`: Array of patch specifications (required for `action: "patch"`):
  - `name`: Human label for the patch.
  - `class`: Target class FQCN.
  - `method`: Target method name.
  - `desc`: Optional descriptor disambiguation.
  - `match`: Match criteria (`kind`, `target_reg`, `target_reads_field_of`, `target_field`, `target_class`, `target_method`, `literal`, `bytes`, `ordinal`).
  - `expect_next`: Polarity assertion on the immediate successor instruction.
  - `replace`: Replacement specification (`{ kind: "nops" }` or `{ kind: "bytes", bytes: "hex" }`).

<examples>
```
// Inspect instructions of a target method
dex_patch(
  action: "inspect",
  path: "app.apk",
  class: "com.example.LicenseCheck",
  method: "verifyLicense",
  desc: "()Z"
)

// Validate structural integrity and verifier rules of a DEX
dex_patch(
  action: "validate",
  path: "classes.dex"
)

// Dry-run patch to preview instruction changes and byte diffs
dex_patch(
  action: "patch",
  path: "classes.dex",
  dry_run: true,
  specs: [
    {
      name: "bypass_license_check",
      class: "Lcom/example/License;",
      method: "isValid",
      desc: "()Z",
      match: { kind: "if-eqz", target_reg: 0 },
      expect_next: { kind: "const4", literal: 0 },
      replace: { kind: "nops" }
    }
  ]
)

// Apply patch and publish to a fresh output DEX file
dex_patch(
  action: "patch",
  path: "classes.dex",
  out: "classes.patched.dex",
  dry_run: false,
  specs: [
    {
      name: "enable_pro_flag",
      class: "Lcom/example/FeatureGate;",
      method: "isPro",
      desc: "()Z",
      match: { kind: "const4", literal: 0 },
      replace: { kind: "bytes", bytes: "12 10" }
    }
  ]
)
```
</examples>
