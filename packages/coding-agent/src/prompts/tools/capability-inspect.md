Explainable binary capability identification and rule match tree inspection tool powered by Mandiant `capa` (`backend: "capa"`).

Capabilities:
- **Toolchain Readiness (`status`)**:
  - Probes the local `capa` executable (`--version`) and available `.yml`/`.yaml` rule set (`resolveCapa`), reporting detected paths, engine version, rule count, missing requirements, and setup commands.
  - Permitted in read-only Plan mode; `detect` (`exec` tier) and `import` (`write` tier) are blocked in Plan mode before any process execution or artifact write.
- **Static Capability Detection (`detect`)**:
  - Enforces active experiment run input binding (`loadAnalysisExecution`): `sample_path` and every `.yml`/`.yaml` file in an explicit `rules_path` closure must be declared in `reverse_workspace(action: "begin")` `inputs` (or be safe same-run intermediates) before `capa` executes.
  - Invokes local `capa` with fixed `argv` (`-j`, static `-f`/`-b`/`--os`, optional `-r`, `-t`, `--restrict-to-functions`) without shell interpolation, network access, or automatic rule/sample downloads.
  - Enforces bounded `max_sample_bytes`, `max_output_bytes`, execution `timeout`/`timeout_ms`, and `AbortSignal` cancellation with process-group cleanup. Retains both the raw `capa` JSON report (`0600`) and normalized `CapabilityInspectReportV1` JSON (`0600`) on success, or a mode-`0600` diagnostic `CapabilityInspectFailureReportV1` on failure/timeout (never returning an empty match set as a fake success).
  - Verifies external rule manifest SHA-256 both before and after `capa` execution (`verified_unchanged_after_execution`). When `use_embedded_rules: true` is selected, records the `capa` engine distribution binary SHA-256 and version while explicitly marking independent rule content hash as unavailable (`independent_content_hash_available: false`).
- **Offline Capa JSON Report Import (`import`)**:
  - Offline-ingests an existing raw `capa` JSON report (`report_path`) inside an active experiment run without requiring the `capa` executable to be installed.
  - Verifies `report_path` and `sample_path` (or workflow target sample) input hashes via `loadAnalysisExecution` and rejects reports whose `/meta/sample/sha256` does not match the bound sample SHA-256.
  - Preserves historical dynamic reports (`flavor: "dynamic"` with `process`/`thread`/`call` addresses) as `static_candidate` historical context only (`historical_context_only: true`, `can_satisfy_dynamic_call_gate: false`), never fabricating live runtime session locators or `metadata.callsite`.
- **Explainable Match Tree, Lossless 64-Bit Addresses & Evidence Candidates**:
  - Parses raw `capa` JSON through a staged Python worker (`runReversePython`) before TypeScript `JSON.parse`, preserving arbitrary-precision 64-bit+ integers and addresses as lossless `decimal` and `hex` strings across all address kinds: `no_address` (explicit for `file`-scope matches), `absolute` (VA), `relative` (RVA), `file_offset`, `dotnet_token`, `dotnet_token_offset`, `process`, `thread`, and `call`.
  - Retains normalized rule metadata (`rule_name`, `namespace`, `scopes`, `primary_scope`, `attack`, `mbc`, `references`, `source`), full boolean statement match trees (`and`, `or`, `not`, `optional`, `some`, `range`, `subscope` with `success`), leaf features with `locations` and `captures`, `warnings`, `limitations`, and RFC 6901 `json_pointer` / `source_json_pointer`.
  - Separates `FACT` candidates (rule `R` matched at observed location `L`) from `HYPOTHESIS` candidates (program behavior / algorithm execution hypothesis requiring verification), both at `static_candidate` assurance, paired with observed-location next actions for existing decompiler (`ghidra_inspect`, `r2_inspect`, `dotnet_inspect`) and debugger/hook (`debug`, `frida_session`, `instruction_trace`) tools complementary to FindCrypt constant hits.

Inputs:
- `action`: `"status"`, `"detect"`, or `"import"`.
- `backend`: Optional backend identifier, fixed to `"capa"`.
- `workflow_id`, `step_id`, `run_id`: Active analysis experiment run identifiers (required for `"detect"` and `"import"`).
- `workspace_path`: Optional workspace directory (defaults to `.reverse`).
- `sample_path`: Target binary sample path inside project (required for `"detect"`; optional on `"import"` when verifying against workflow target sample, or explicit sample path bound in `begin` `inputs`).
- `report_path`: Raw `capa` JSON report path for offline `"import"` (must be bound in `begin` `inputs` or current run).
- `rules_path`: Optional explicit project-local `capa` rules directory or `.yml`/`.yaml` rule file (all rule files must be bound in `begin` `inputs`).
- `use_embedded_rules`: Optional boolean for `"detect"` to use `capa`'s built-in embedded rules instead of external rule directories.
- `namespace`, `tag`, `tags`: Optional rule namespace / metadata tag filters for `"detect"`.
- `restrict_to_functions`: Optional list of function virtual addresses (hex e.g. `"0x401000"` or decimal) for `"detect"` (`--restrict-to-functions`).
- `format`: Optional static input format for `"detect"` (`"auto"`, `"pe"`, `"elf"`, `"dotnet"`, `"sc32"`, `"sc64"`).
- `capa_backend`: Optional static extractor backend for `"detect"` (`"auto"`, `"vivisect"`, `"pefile"`, `"dotnet"`).
- `os`: Optional target OS override for `"detect"` (`"auto"`, `"linux"`, `"macos"`, `"windows"`).
- `output_path`, `raw_output_path`: Optional unique destination paths inside the active run's managed subdirectories (`reports/`, `dumps/`, `scripts/`, `tmp/`).
- `max_sample_bytes`, `max_output_bytes`, `timeout`, `timeout_ms`: Optional execution and resource bounds.

<examples>
```
# Check capa engine and rules readiness
capability_inspect(action: "status")

# Detect capabilities on a bound PE/ELF sample with project-local rules and function filter
capability_inspect(
  action: "detect",
  backend: "capa",
  workflow_id: "wf_1",
  step_id: "step_static",
  run_id: "run_1",
  sample_path: "samples/target.elf",
  rules_path: "rules/crypto",
  namespace: "data-manipulation/encryption/xor",
  restrict_to_functions: ["0x401000"]
)

# Offline-import a raw capa JSON report and cross-verify sample SHA-256 without requiring capa binary
capability_inspect(
  action: "import",
  backend: "capa",
  workflow_id: "wf_1",
  step_id: "step_static",
  run_id: "run_1",
  sample_path: "samples/target.elf",
  report_path: "captures/capa_raw_report.json"
)
```
</examples>
