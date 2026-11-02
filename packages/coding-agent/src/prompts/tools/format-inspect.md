Executable binary format and custom protocol specification tool powered by Kaitai Struct (`kaitai-struct-compiler` with `--read-pos` and Python `kaitaistruct` runtime).

Capabilities:
- **Toolchain Readiness (`status`)**:
  - Probes `kaitai-struct-compiler` (JVM + `--read-pos` support), Python 3.9+ `kaitaistruct` runtime, and compiler/runtime version compatibility.
  - Reports detected paths, versions, missing requirements, and setup commands.
- **Schema Compilation (`compile`)**:
  - Validates `.ksy` YAML schema and transitive `meta.imports` closure against explicit local `import_roots` within the project.
  - Enforces active experiment run input binding (`loadAnalysisExecution`): all `.ksy` files in the import closure must be declared in `begin` `inputs` (or be safe same-run intermediates).
  - Rejects network imports, path traversal, symlink escape, custom processors (`process` other than `zlib`, `xor(...)`, `rol(...)`, `ror(...)`), and opaque external types (`--opaque-types false`).
  - Invokes `kaitai-struct-compiler --target python --read-pos --opaque-types false` with an isolated `KSPATH` (no implicit global/managed format libraries).
  - Writes generated Python parser modules (`0600`) and a hash-bound `FormatInspectManifestV1` JSON (`0600`) inside the active run directory; retains diagnostic failure reports (`0600`) when compilation fails.
- **Single-Sample Parsing (`parse`)**:
  - Loads an explicit `manifest_path` and `sample_path`, verifying active run input binding, KSY closure SHA-256 hashes, on-disk generated Python source SHA-256 hashes, and compiler/runtime version compatibility.
  - Requires both `kaitai-struct-compiler` and Python `kaitaistruct` runtime: privately recompiles the hash-bound `.ksy` closure with fixed verified compiler flags, compares all freshly generated source SHA-256 hashes against the manifest entries, and executes only canonical verified parser sources inside a staged `runReversePython` worker with filtered environment, bounded input size, expansion depth, field count, output size, and execution timeout.
  - Returns flattened fields with `path`, `type`, `value` (64-bit integers as decimal strings, `bytes` as lowercase hex), `stream_id`, 0-based `[start, end)` offsets (`end` exclusive), `file_start`/`file_end`/`file_offset` (mapped only when substream is unprocessed; `null` for `xor`/`zlib`/`rol`/`ror` processed substreams), `error_offset` on parse failures, and `trailing_bytes` / `trailing`.
  - Avoids auto-evaluating lazy `@property` instances or traversing `_parent`/`_root` cycles.
- **Multi-Sample Corpus Validation (`validate`)**:
  - Parses explicit `sample_paths[]` against a verified compiled `manifest_path` (after private canonical recompilation verification), checking per-sample `expect_success` (positive and negative samples) and explicit field assertions (`exists`, `type`, `equals`, `stream_id`, `start`, `end`, `file_start`, `file_end`).
  - Reports only observed corpus expectations and explicit assertion satisfaction rates (`static_candidate` assurance; never fabricates branch coverage or certifies full protocol correctness).
  - Retains negative sample outcomes and produces next-experiment suggestions bound to specific failing field paths and offsets.

Inputs:
- `action`: `"status"`, `"compile"`, `"parse"`, or `"validate"`.
- `workflow_id`, `step_id`, `run_id`: Active analysis experiment run identifiers (required for `"compile"`, `"parse"`, `"validate"`).
- `workspace_path`: Optional workspace directory (defaults to `.reverse`).
- `schema_path`: Path to root `.ksy` specification file (required for `"compile"`).
- `import_roots`: Explicit local directories within the project for resolving `meta.imports` during `"compile"`.
- `manifest_path`: Path to compiled `FormatInspectManifestV1` JSON produced by `"compile"` (required for `"parse"` and `"validate"`).
- `sample_path`: Path to binary sample file (required for `"parse"`).
- `sample_paths`: Non-empty array of binary sample paths (required for `"validate"`).
- `sample_expectations`: Optional per-sample expectations (`sample_path`, `expect_success`, `max_trailing_bytes`, `expected_error_offset`, `expected_error_contains`, `assertions`).
- `field_assertions`: Optional field-level assertions (`sample_path`, `path`, `exists`, `type`, `equals`, `stream_id`, `start`, `end`, `file_start`, `file_end`).
- `output_path`: Optional project-relative or absolute destination path inside the current run's managed subdirectories (`scripts/`, `dumps/`, `reports/`, `tmp/`); defaults to a unique path under the active run's `reports/` subdirectory.
- `max_input_bytes`, `max_depth`, `max_fields`, `max_output_bytes`, `timeout`, `timeout_ms`: Optional execution and resource bounds.

<examples>
```
# Check Kaitai compiler and Python runtime readiness
format_inspect(action: "status")

# Compile a .ksy schema with explicit local import roots inside an active run
format_inspect(
  action: "compile",
  workflow_id: "wf_1",
  step_id: "step_protocol",
  run_id: "run_1",
  schema_path: "schemas/packet.ksy",
  import_roots: ["schemas/common"]
)

# Parse a binary sample using the compiled manifest
format_inspect(
  action: "parse",
  workflow_id: "wf_1",
  step_id: "step_protocol",
  run_id: "run_1",
  manifest_path: ".reverse/analysis/wf_1/runs/run_1/reports/kaitai_packet.manifest.json",
  sample_path: "samples/frame_01.bin"
)

# Validate positive and negative samples with explicit field assertions
format_inspect(
  action: "validate",
  workflow_id: "wf_1",
  step_id: "step_protocol",
  run_id: "run_1",
  manifest_path: ".reverse/analysis/wf_1/runs/run_1/reports/kaitai_packet.manifest.json",
  sample_paths: ["samples/frame_01.bin", "samples/corrupt_magic.bin"],
  sample_expectations: [
    {
      sample_path: "samples/frame_01.bin",
      expect_success: true,
      max_trailing_bytes: 0,
      assertions: [
        { path: "magic", type: "bytes", equals: "52565031", start: 0, end: 4 },
        { path: "session_id", type: "uint64", equals: "18446744073709551615", start: 8, end: 16 }
      ]
    },
    {
      sample_path: "samples/corrupt_magic.bin",
      expect_success: false,
      expected_error_offset: 0
    }
  ]
)
```
</examples>
