Normalizes and ingests bounded dynamic events (Frida, browser CDP, DAP, Unidbg) into the Evidence ledger, links workflow steps, and promotes verified outcomes into reusable reverse knowledge.

Actions:
- `ingest`: Normalizes and ingests bounded dynamic events as FactEvidence records into the project Evidence ledger.
  - Accepts events from a registered runtime session buffer (`session_id`) or an explicit array of structured events (`events`).
  - Only events pulled from an actual runtime session buffer (`session_id` / DAP session) with a valid structured `metadata.callsite` (`url` + 0-based `lineNumber` or `module` + hex `address`) and execution call kind (`network`, `crypto`, `trace`, `breakpoint`, `step`) receive `dynamic_call_observation` assurance. Explicit `events` or non-call kinds (`console`, `storage`, `dom`, `lifecycle`, `error`) are retained as ordinary facts.
  - Supports optional `subject` tagging to bind ingested facts to the research subject.
  - Generates verifiable dynamic locators formatted as `session:<session_id>:seq:<seq>`.
  - Automatically sanitizes/redacts embedded credentials, secrets, tokens, and sensitive URL parameters.
  - Can associate newly ingested facts with a workflow step (`workflow_id`, `step_id`).
- `events`: Queries, filters, and formats buffered dynamic events without writing them to disk.
  - Filter by event `kind` (`stdout`, `stderr`, `message`, `trace`, `network`, `crypto`, `breakpoint`, `step`, `dom`, `storage`, `lifecycle`, `error`), `channel`, or `since_seq`.
  - Returns paginated event summaries with sequence numbers and previews.
- `verify`: Verifies a hypothesis in the Evidence ledger using previously ingested dynamic call observation facts (`ingest` then `verify`), creating a verified ConclusionEvidence record with `dynamic_call_observation` assurance.
  - Requires explicit `session_id` (must exist in runtime session registry; closed sessions with persisted observations are permitted), `hypothesis_id`, non-empty `fact_ids`, `conclusion`, `method`, `command`, and `result`.
  - Validates that all `fact_ids` have dynamic locators matching `session_id` and `source`, meet `dynamic_call_observation` assurance, and match the hypothesis `target`, `subject`, and target SHA-256 hash before writing any conclusion, knowledge, or workflow step update.
  - Promotes only the newly verified conclusion into `reverse_knowledge` when `learn` is enabled.
  - Links to workflow step and optionally marks the step as completed.
- `status`: Returns a summary of dynamic evidence closure for the current workspace.
  - Reports count of dynamic facts, verified conclusions, active sessions, and dynamic knowledge patterns.

Security & Integrity:
- Zero arbitrary execution: ingests and normalizes already observed events; never spawns shell commands or dynamic processes.
- Secrets redaction: automatically scrubs credentials, auth tokens, passwords, and API keys.
- Strict boundedness: paging and buffering bounds ensure telemetry never floods context or memory.

<examples>
```
// 1. Ingest buffered Frida events into Evidence ledger
reverse_dynamic_evidence(action: "ingest", session_id: "runt_frida_019a", source: "frida", target: "com.example.app")

// 2. Query recent crypto events from browser CDP session
reverse_dynamic_evidence(action: "events", session_id: "browser_audit", source: "browser", kind: "crypto", limit: 10)

// 3. Ingest buffered runtime events with subject, then verify hypothesis using ingested fact_ids
reverse_dynamic_evidence(
  action: "ingest",
  session_id: "runt_frida_019a",
  source: "frida",
  target: "bin/target.elf",
  subject: "check_license"
)
reverse_dynamic_evidence(
  action: "verify",
  session_id: "runt_frida_019a",
  source: "frida",
  hypothesis_id: "ev_hyp_check_license",
  fact_ids: ["ev_fact_019a"],
  method: "Frida Interceptor hook on check_license",
  command: "frida -f bin/target.elf -l hook_license.js",
  result: "Observed check_license(0x1) returning 1 at libtarget.so@0x401240",
  conclusion: "License check function at 0x401240 validated via runtime call observation.",
  workflow_id: "wf_elf_019a",
  step_id: "step_g2_bp",
  advance_workflow: true
)

// 4. Inspect overall dynamic evidence closure status
reverse_dynamic_evidence(action: "status", workflow_id: "wf_elf_019a")
```
</examples>
