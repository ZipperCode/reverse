Bounded reverse-engineering workflow orchestrator with cross-tool evidence association and failure recovery metadata. Coordinates structured reverse engineering investigations without silently executing arbitrary commands.

Actions:
- `create`: Initialize a target-routed workflow plan.
  - Sniffs and confirms target binary/artifact format (PE, ELF, Mach-O, APK, JS, WASM, PCAP, SQLite).
  - Generates a deterministic, gate-aligned (G0 -> G4) execution plan using existing native tools (`triage`, `binary_metadata_inspect`, `r2_inspect`, `android_package_inspect`, `droidasc`, `sourcemap_inspect`, `javascript_application`, `wasm_inspect`, `pcap_inspect`, `sqlite_inspect`, `grep`, `evidence`).
  - Automatically queries bounded prior reverse knowledge from `reverse_knowledge` for matching target format/hash and attaches references.
  - Persists workflow record in isolated project state storage with initial `pending` steps.
- `plan`: Preview or generate a deterministic step plan.
  - Evaluates target file or format override and outputs the ordered tool pipeline without requiring prior persistence.
  - Surfaces relevant prior reverse knowledge entries and recommendations for the target format or goal.
- `status`: Inspect workflow progress, step attempts, and linked evidence items.
  - When `workflow_id` is provided, returns overall metrics, current step, failure reasons, and recovery hints.
  - When `workflow_id` is omitted, lists recent workflows for the current project.
- `record`: Record step execution state, outputs, artifacts, and evidence links.
  - Updates step status (`completed`, `failed`, `running`, `skipped`), increments attempt count, and stores output summaries.
  - Associates verified evidence ledger IDs (`ev_fact_...`, `ev_hyp_...`, `ev_conc_...`, `ev_unk_...`) and reverse knowledge IDs (`kn_rev_...`).
- `retry`: Transition a failed step to pending for recovery.
  - Strictly requires the step to be in `failed` status.
  - Enforces bounded attempt limits (`attempts < max_attempts`).
  - Records caller-provided next parameters (`next_params`), diagnosis/result (`result`), and optional `fallback_tool`.
  - Does NOT execute arbitrary commands or tools itself: prepares structured instructions for the agent to invoke the next tool call.
- `recover`: Diagnose failure, attribute category, propose deterministic fallback/corrected params, record audit trail, and transition step to pending.
  - Classifies failure into structured category: `missing_dependency`, `invalid_format`, `timeout`, `truncated`, `device_required`, `unsupported`, or `unknown`.
  - Computes platform installation hints for missing tools and determines deterministic native fallbacks (`r2_inspect` -> `triage`, `droidasc` -> `android_package_inspect`, `tshark` -> `pcap_inspect`, etc.).
  - Corrects parameters (scope reduction on timeout, pagination on truncation, format check on invalid header).
  - Records a complete recovery audit entry and associates evidence IDs (`evidence_ids`).
  - Strictly enforces bounded retry attempts (`attempts < max_attempts`).
- `retry_plan`: Preview failure attribution and recovery plan without mutating step status.
  - Returns structured diagnosis, attribution, cause, alternatives, and proposed tool & parameters.
- `export`: Produce bounded Markdown/JSON workflow reports or export a standardized `.rea/` workspace.
  - Hydrates linked evidence ledger items (title, kind, locator, content).
  - Captures full failure recovery and retry history.
  - When `to_workspace: true` (or `workspace_path` is specified), exports standardized `.rea/` workspace layout containing `manifest.json`, `target/target.json`, `workflow/`, `evidence/`, `findings/`, `scripts/`, `dumps/`, `reports/`, and safe artifact references.
  - Spills to session artifact when requested (`to_artifact: true`) or when content exceeds inline limits.
- `destroy`: Permanently remove a workflow record from persistent state storage.
- `advance` / `auto_advance`: Safely progress through workflow steps following low-risk static allowlist rules.
  - **Allowlisted Low-Risk Static Tools**: Evaluates read-only triage and static inspection tools (`triage`, `binary_metadata_inspect`, `sourcemap_inspect`, `android_package_inspect`, `pcap_inspect`, `sqlite_inspect`, `wasm_inspect`, `grep`, `evidence`).
  - **Prohibits Silent Dynamic Execution**: Deep analysis, interactive disassembly, debugger, or dynamic runtime tools (`r2_inspect`, `droidasc`, `frida`, `reverse_runtime_session`, `shell`, `patch`, `replay`) **never** run silently; auto-progression halts and marks them `held_pending_decision`.
  - **Target & Dependency Guardrails**: Stops progression immediately (`stopped_ambiguous_target` or `stopped_missing_dependency`) if target file is inaccessible, format is unknown, or required tool dependency is missing.
  - **Decision & Audit Trail**: Records structured `ProgressionAuditEntry` records with decision rationale, risk classification, and attached active knowledge references.
  - **Bounded Execution**: Restricts automatic evaluations to bounded steps (max 5, default 1).

Security & Guardrails:
- Does not execute arbitrary shell commands or launch uncontrolled background processes.
- Target files are accessed strictly read-only.
- Low-risk static auto progression: only allowlisted inspection and triage steps are progressed; dynamic/high-risk actions require explicit decision.
- Bounded retries: prevents infinite failure loops with strict attempt caps.
- Strict cross-tool evidence linking: verifies that linked evidence IDs exist in the project evidence ledger.
- Isolated project storage with advisory file locking and atomic replacement.
- Clean standardized `.rea/` workspace: target binary is accessed strictly read-only and preserved by reference (never mutated or duplicated); only safe small scripts/dumps (<= 1 MiB) are copied with credentials and tokens scrubbed.
- Prior knowledge integration: bounded, verified findings and recovery patterns from `reverse_knowledge` are surfaced without executing unverified hypotheses.
<examples>
```
// 1. Create a workflow for a Linux binary target
reverse_workflow(action: "create", target: "bin/server.elf", goal: "Audit authentication flow and network handlers")

// 2. Preview a plan for an APK target without creating
reverse_workflow(action: "plan", target: "sample.apk")

// 3. Inspect workflow status and next pending step
reverse_workflow(action: "status", workflow_id: "wf_rw_018f...")

// 4. Record step completion with linked evidence ID
reverse_workflow(action: "record", workflow_id: "wf_rw_018f...", step_id: "elf_step_1", status: "completed", outputs: "ELF 64-bit LSB executable, x86-64, not stripped", evidence_ids: ["ev_fact_018f..."])

// 5. Record a step failure
reverse_workflow(action: "record", workflow_id: "wf_rw_018f...", step_id: "elf_step_3", status: "failed", error: "r2_inspect failed: binary requires custom base address")

// 6. Retry the failed step with caller-provided recovery params
reverse_workflow(action: "retry", workflow_id: "wf_rw_018f...", step_id: "elf_step_3", next_params: "{\"action\": \"functions\", \"path\": \"bin/server.elf\", \"base_address\": \"0x400000\"}", result: "Identified base load address from section table")
// 6. Recover a failed step with deterministic failure attribution and fallback
reverse_workflow(action: "recover", workflow_id: "wf_rw_018f...", step_id: "apk_step_3", error: "droidasc not found on PATH")

// 7. Preview a recovery plan without mutating step state
reverse_workflow(action: "retry_plan", workflow_id: "wf_rw_018f...", step_id: "apk_step_3", error: "droidasc not found on PATH")

// 8. Export full workflow report with recovery audit trail to Markdown
reverse_workflow(action: "export", workflow_id: "wf_rw_018f...", format_type: "markdown")

// 9. Export standardized reverse engineering workspace to local .rea/ directory
reverse_workflow(action: "export", workflow_id: "wf_rw_018f...", to_workspace: true)

// 10. Auto-advance the next low-risk static step
reverse_workflow(action: "auto_advance", workflow_id: "wf_rw_018f...")

// 11. Record completion of an allowlisted low-risk step via advance
reverse_workflow(action: "advance", workflow_id: "wf_rw_018f...", step_id: "pe_step_1", status: "completed", outputs: "PE32+ executable for MS Windows (console) x86-64")
</examples>
