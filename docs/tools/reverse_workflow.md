# reverse_workflow

> Bounded reverse-engineering workflow orchestrator: target-first routing, deterministic tool plans, cross-tool evidence association, and failure recovery metadata without arbitrary command execution.

## Source
- Entry: `packages/coding-agent/src/tools/reverse-workflow.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/reverse-workflow.md`
- Core engine: `packages/coding-agent/src/reverse-workflow/`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"create"`, `"plan"`, `"status"`, `"record"`, `"retry"`, `"recover"`, `"retry_plan"`, `"export"`, `"destroy"`. |
| `workflow_id` | `string` | No* | Unique workflow identifier (alias `id`). Required for `record`, `retry`, `recover`, `retry_plan`, `export`, `destroy`; optional for `status`. |
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

## Actions

- **create**: Sniffs the target file format (or applies an explicit format override), automatically queries bounded prior reverse knowledge for matching target format/hash, generates a deterministic 4-step execution plan aligned with the G0–G4 decision gates using existing native tools, and initializes the persisted workflow record with `status: "active"` and steps in `pending` state.
- **plan**: Previews or generates an ordered, deterministic tool pipeline for a target or format without requiring prior persistence, surfacing relevant prior reverse knowledge entries. When `workflow_id` is given, returns the existing plan.
- **status**: When `workflow_id` is provided, reports overall workflow metrics (completed, failed, pending, skipped, evidence links) and details the next recommended pending step. When `step_id` is also provided, shows detailed step state, parameters, outputs, retry history, and linked evidence IDs. When `workflow_id` is omitted, lists all project workflows.
- **record**: Updates a step's execution status (`completed`, `failed`, `running`, `skipped`), increments attempt counts, records outputs and generated artifact references, and associates verified evidence ledger IDs (`ev_fact_...`, `ev_hyp_...`, `ev_conc_...`, `ev_unk_...`). Validates that all linked evidence IDs exist in the project evidence ledger.
- **retry**: Transitions a failed step back to `pending` with incremented attempt tracking. Strictly requires the step to be in `failed` state and enforces bounded attempt caps (`attempts < max_attempts`). Captures caller-provided `next_params`, diagnostic `result`, and optional `fallback_tool`. Records structured attribution and recovery audit entry. **Never executes arbitrary commands or tools itself**: returns structured parameters for caller execution.
- **recover**: Diagnoses step failure, attributes failure category (`missing_dependency`, `invalid_format`, `timeout`, `truncated`, `device_required`, `unsupported`, `unknown`), computes deterministic native tool fallback and parameter corrections, records a persistent recovery audit entry, links associated evidence ledger records, and transitions the step to `pending` for execution. Bounded by `max_attempts` to strictly prevent infinite recovery loops.
- **retry_plan**: Previews the failure attribution, cause, alternatives, and deterministic parameter/tool corrections without mutating step status or persistent workflow state.
- **export**: Generates a bounded Markdown or JSON report of the entire workflow, step statuses, outputs, failure recovery history, and hydrated evidence ledger records. Spills to a session artifact (`artifact://<id>`) when requested or when output exceeds inline bounds.
- **destroy**: Permanently deletes the workflow JSON file from the project's state store.

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
- **Approval Tiers**: Read actions (`plan`, `status`, `export`) use tier `"read"`; state-mutating actions (`create`, `record`, `retry`, `destroy`) use tier `"write"`.
