# reverse_workflow

> Bounded reverse-engineering workflow orchestrator: target-first routing, deterministic tool plans, cross-tool evidence association, acceptance criteria binding, cumulative build lineage, and failure recovery metadata without arbitrary command execution.

## Source
- Entry: `packages/coding-agent/src/tools/reverse-workflow.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/reverse-workflow.md`
- Core engine: `packages/coding-agent/src/reverse-workflow/`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"create"`, `"plan"`, `"status"`, `"record"`, `"retry"`, `"recover"`, `"retry_plan"`, `"export"`, `"destroy"`, `"advance"`, `"auto_advance"`, `"register_derivative"`, `"verify_lineage"`, `"retire_patch"`, `"waive_acceptance"`, `"approve_dependency"`. |
| `workflow_id` | `string` | No* | Unique workflow identifier (alias `id`). Required for `record`, `retry`, `recover`, `retry_plan`, `export`, `destroy`, `waive_acceptance`, `approve_dependency`; optional for `status`. |
| `id` | `string` | No | Alias for `workflow_id`. |
| `target` | `string` | No* | Target binary, package, capture, or script path relative to project (alias `path`). Required for `create`. |
| `path` | `string` | No | Alias for `target`. |
| `format` | `string` | No | Target format override (`PE`, `ELF`, `Mach-O`, `APK`, `JS`, `WASM`, `PCAP`, `SQLite`). |
| `goal` | `string` | No | Analytical goal or objective for the reverse engineering workflow. |
| `step_id` | `string` | No* | Target step identifier within the workflow (e.g. `pe_step_1`). Required for `record` and `retry`. |
| `status` | `string` | No* | Execution status for `record`: `"completed"`, `"failed"`, `"running"`, `"skipped"`. |
| `outputs` | `string` | No | Output summary, extracted symbols, or execution findings for `record`. |
| `artifact_refs` | `string[]` | No | List of artifact IDs or generated file references produced by the step. |
| `evidence_ids` | `string[]` | No | Array of evidence ledger IDs (`ev_fact_...`, `ev_hyp_...`, `ev_conc_...`, `ev_unk_...`) to link to this step. |
| `knowledge_refs` | `string[]` | No | Array of reverse knowledge IDs (`kn_rev_...`) to link to this step or workflow. |
| `error` | `string` | No | Failure reason or error message when marking step as `"failed"` (alias `failure_reason`). |
| `failure_reason` | `string` | No | Alias for `error`. |
| `next_params` | `string` | No | Caller-provided adjusted parameters for the upcoming retry attempt. |
| `result` | `string` | No | Caller-provided diagnostic result or failure analysis for `retry` (alias `caller_result`). |
| `caller_result` | `string` | No | Alias for `result`. |
| `fallback_tool` | `string` | No | Alternative existing tool to switch to for retry (e.g. `ghidra_inspect` replacing `r2_inspect`). |
| `max_attempts` | `number` | No | Maximum retry attempts per step (default 3, hard limit 10). |
| `format_type` | `string` | No | Export report format: `"markdown"` (default) or `"json"`. |
| `to_artifact` | `boolean` | No | Force exporting full report to session artifact instead of inline response. |
| `limit` | `number` | No | Maximum workflows to list in `status` when `workflow_id` is omitted (default 20). |
| `build_id` | `string` | No | Derivative build identifier (e.g. `'bld_mod1'`). |
| `derivative_path` | `string` | No | Path to modified derivative artifact file (alias for `target` in `register_derivative`). |
| `output_sha256` | `string` | No | Expected SHA-256 hash of the built derivative artifact. |
| `original_sha256` | `string` | No | SHA-256 hash of the clean base target. |
| `parent_sha256` | `string` | No | SHA-256 hash of the immediate parent derivative or base target. |
| `parent_build_id` | `string` | No | Build ID of the immediate parent derivative. |
| `target_version` | `string` | No | Target application version (e.g. `'v9.5.0'`). |
| `abi` | `string` | No | Target ABI or architecture (e.g. `'arm64-v8a'`). |
| `architecture` | `string` | No | Target CPU architecture. |
| `patches` | `unknown` | No | Array of cumulative or new patch records: `[{ patch_id, member_path?, offset, original_bytes, expected_bytes, status?, retirement_reason?, evidence_id? }]`. |
| `retired_patches` | `unknown` | No | Array of patches explicitly retired in this revision: `[{ patch_id, reason }]`. |
| `patch_id` | `string` | No | Patch identifier for `retire_patch` action. |
| `reason` | `string` | No | Mandatory reason when retiring a patch (`retire_patch`), waiving an acceptance criterion (`waive_acceptance`), or approving a delivery dependency (`approve_dependency`). |
| `criterion_id` | `string` | No* | Target acceptance criterion identifier (required for `waive_acceptance`). |
| `dependency_id` | `string` | No* | Target workflow dependency identifier (required for `approve_dependency`). |
| `scope` | `string` | No | Deployment scope or mode: `"experiment"` or `"delivery"`. |
| `delivery_mode` | `string` | No | Delivery packaging mode (e.g. `"standalone_package"`, `"modified_apk"`). |
| `target_device_constraints`| `unknown` | No | Target environment constraints: `{ target_environment?, requires_standalone?, disallowed_dependencies?, allowed_delivery_modes? }`. |
| `acceptance_criteria` | `unknown` | No | Array of acceptance criteria: `[{ id, title?, subject, step_id, required_evidence_types?, min_assurance? }]`. |
| `dependencies` | `unknown` | No | Array of dependencies: `[{ id, name?, kind?, scope, target_host?, approved_for_experiment?, approved_for_delivery?, approval_notes? }]`. |
| `signature_status` | `string` | No | Signature status: `"signed"`, `"unsigned"`, `"unknown"`. |
| `signature_fingerprint` | `string` | No | Certificate or signature fingerprint (SHA-256). |
| `runtime_evidence_ids` | `string[]` | No | Array of evidence IDs bound to this exact derivative output SHA-256. |

## Actions

- **`create`**: Sniffs the target format, queries bounded prior knowledge, generates a deterministic 4-step execution plan aligned with G0–G4 decision gates, initializes `acceptance_criteria` and `dependencies` under reserved metadata, and starts the workflow in `active` state with steps `pending`.
- **`plan`**: Previews an ordered, deterministic tool pipeline without requiring persistence. When `workflow_id` is given, returns the existing plan.
- **`status`**: Reports workflow metrics, gate progression, next recommended pending step, acceptance criteria status, and linked evidence records.
- **`record`**: Updates a step's execution status (`completed`, `failed`, `running`, `skipped`), increments attempt counts, records outputs and generated artifact references, and associates verified evidence ledger IDs. Validates evidence existence in the project evidence ledger.
- **`retry`**: Transitions a failed step back to `pending` with incremented attempt tracking. Enforces bounded attempt caps (`attempts < max_attempts`). Captures `next_params`, diagnostic `result`, and optional `fallback_tool`. Never executes commands itself: returns structured parameters for caller execution.
- **`recover`**: Diagnoses failure category (`missing_dependency`, `invalid_format`, `timeout`, `truncated`, `device_required`, `unsupported`, `unknown`), computes deterministic native tool fallback and parameter corrections, records persistent recovery audit, and transitions the step to `pending`. Bounded by `max_attempts`.
- **`retry_plan`**: Previews failure attribution and deterministic parameter/tool corrections without mutating step status or persistent workflow state.
- **`export`**: Generates a bounded Markdown or JSON report of the entire workflow, hydrated evidence records, and failure recovery history. Spills to a session artifact when requested or when output exceeds inline bounds.
- **`destroy`**: Permanently deletes the workflow JSON file from the project's state store.
- **`advance` / `auto_advance`**: Progresses through decision gates when gate prerequisites and low-risk conditions are satisfied.
- **`register_derivative`**: Registers a modified binary or package derivative into durable build lineage. Strictly validates container member bytes against all expected active patches before registering. Retains cumulative patchset from active baseline (A + B replay). Requires runtime evidence IDs to bind directly to the exact derivative output hash.
- **`verify_lineage`**: Re-verifies an artifact on disk against its registered cumulative patches, source/parent hashes, and container member bytes.
- **`retire_patch`**: Explicitly retires a patch in derivative lineage with a mandatory `reason`, preventing accidental regression without mutating historical records.
- **`waive_acceptance`**: Waives an acceptance criterion with an explicit mandatory `reason`, recording a permanent waiver audit decision. Required to close criteria classified as `proxy_verified` due to subject mismatches. Initial waiver cannot be claimed by callers during workflow creation.
- **`approve_dependency`**: Authorizes a dependency for delivery (`approved_for_delivery: true`) with an explicit mandatory `reason`. Delivery authorization requires explicit user confirmation and cannot be asserted on creation.

## Acceptance Criteria Governance & Subject Binding

1. **Storage under Reserved Metadata**:
   - Acceptance criteria are stored under `workflow.metadata.acceptance` as a dictionary keyed by stable `step_id`.
   - Every criterion must strictly reference an existing step ID within `workflow.steps`; references to unknown steps are rejected with actionable errors.

2. **Immutable Subject & Proxy Observations**:
   - Each criterion specifies a canonical, immutable `subject` (e.g. `"license_check"`).
   - Evidence records evaluate against this subject via `evaluateAcceptanceSatisfaction`.
   - Evidence recorded under a different subject (e.g. `"login_flow"` or general `"ui"`) is classified as `proxy_verified` (`isProxy: true`). **Proxy observations cannot satisfy or close the criterion without an explicit human waiver** (`waive_acceptance`).

3. **Rejection of Initial Caller Satisfaction Claims**:
   - On initial creation (`create`), every acceptance criterion status must be `"pending"`.
   - Callers cannot assert initial satisfaction (`"satisfied"`) or waiver (`"waived"`). Such claims are strictly rejected.

4. **Canonical Evidence Graph Invalidation**:
   - When evidence refutations occur, `cascadeEvidenceRefutation` scans active supporting proof IDs.
   - Refuted or stale supporting evidence reopens completed steps back to `pending` (`held_pending_decision`, `decision: "invalidated_by_evidence"`), clears active proof, sets criteria to pending, fails build lineage runtime verification, and **resets completed workflows back to `active`**. Historical execution records and logs are preserved immutably.

## Dependency Scopes & Target Device Constraints

Workflows distinguish experimental dependencies from delivery dependencies:

- **`scope: "experiment"` vs `scope: "delivery"`**:
  - `experiment`: Temporary runtime helpers, tracing scripts, or lab harnesses (e.g. Frida agent, local proxy, Unidbg runner).
  - `delivery`: Dependencies required by the shipped, standalone binary or package.
- **Target Device Constraints**:
  - When `requires_standalone: true` or `disallowed_dependencies` are configured for the target environment, delivery builds strictly reject experimental helpers (such as external phone oracles, LSPosed runtime, or workstation debug bridges).
  - An experimental authorization in a lab setting does not authorize delivery.
  - Callers cannot pass `approved_for_delivery: true` upon initial creation; delivery approval requires explicit interactive authorization via `approve_dependency`.

## Target-First Deterministic Tool Routing

| Target Format | Gate Sequence | Primary Tool Pipeline | Fallback / Recovery Tools |
| :--- | :--- | :--- | :--- |
| **PE** | G0 -> G1 -> G2 -> G4 | `triage` -> `binary_metadata_inspect` -> `r2_inspect` -> `evidence` | `ghidra_inspect`, `windows_observe`, `dotnet_inspect` |
| **ELF** | G0 -> G1 -> G2 -> G4 | `triage` -> `binary_metadata_inspect` -> `r2_inspect` -> `evidence` | `ghidra_inspect`, `read-binary` (IDA) |
| **Mach-O** | G0 -> G1 -> G2 -> G4 | `triage` -> `binary_metadata_inspect` -> `r2_inspect` -> `evidence` | `ghidra_inspect`, `read-binary` (IDA) |
| **APK** | G0 -> G1 -> G2 -> G4 | `android_package_inspect` -> `android_package_inspect` (manifest) -> `droidasc` -> `evidence` | `jadx`, `apktool` |
| **JS** | G0 -> G1 -> G2 -> G4 | `sourcemap_inspect` -> `javascript_application` -> `grep` -> `evidence` | `ast_grep`, `js_hook_preset` |
| **WASM** | G0 -> G1 -> G2 -> G4 | `wasm_inspect` (info) -> `wasm_inspect` (strings) -> `wasm_inspect` (wat) -> `evidence` | `ast_grep`, `read` |
| **PCAP** | G0 -> G1 -> G2 -> G4 | `pcap_inspect` (info) -> `pcap_inspect` (endpoints) -> `pcap_inspect` (conversations) -> `evidence` | `websocket_observe`, `tshark` |
| **SQLite** | G0 -> G1 -> G2 -> G4 | `sqlite_inspect` (info) -> `sqlite_inspect` (tables) -> `sqlite_inspect` (schema) -> `evidence` | `sqlite3` CLI |

## Security & Storage
- **No Arbitrary Execution**: The orchestrator is a bounded state machine that plans and tracks tool calls; it never silently spawns background shell commands or executes arbitrary scripts.
- **Evidence Ledger Integrity**: Cross-tool evidence associations are strictly verified against existing evidence IDs in the project ledger (`EvidenceStore`). Fake verification or dangling IDs are rejected with actionable errors.
- **Isolated Project State**: Workflows are stored under `~/.reverse/agent/reverse-workflows/<project-key>/<workflow-id>.json`. State never pollutes the workspace repository.
- **Concurrency & Atomicity**: Backed by cross-process advisory file locks (`store.lock`) and atomic temporary-file replacement.
- **Bounded Output**: Markdown and JSON exports enforce a 32 KiB cap with automatic session artifact spilling for large reports.
- **Approval Tiers**: Read actions (`plan`, `status`, `export`, `retry_plan`) use tier `"read"`; state-mutating actions (`create`, `record`, `retry`, `recover`, `destroy`, `advance`, `auto_advance`, `register_derivative`, `verify_lineage`, `retire_patch`, `waive_acceptance`, `approve_dependency`) use tier `"write"`.
