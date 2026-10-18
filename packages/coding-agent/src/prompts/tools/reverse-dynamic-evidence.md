Normalizes and ingests bounded dynamic events (Frida, browser CDP, DAP, Unidbg) into the Evidence ledger, links workflow steps, and promotes verified outcomes into reusable reverse knowledge.

Actions:
- `ingest`: Normalizes and ingests bounded dynamic events as FactEvidence records into the project Evidence ledger.
  - Accepts events from an active runtime session (`session_id`) or an explicit array of structured events (`events`).
  - Supports sources: `frida`, `browser`, `dap`, `unidbg`, or `custom`.
  - Generates verifiable dynamic locators formatted as `session:<session_id>:seq:<seq>`.
  - Automatically sanitizes/redacts embedded credentials, secrets, tokens, and sensitive URL parameters.
  - Can associate newly ingested facts with a workflow step (`workflow_id`, `step_id`).
  - If `hypothesis_id` and `conclusion` are supplied, automatically verifies the hypothesis, writes a ConclusionEvidence record, and promotes the verified outcome into reusable knowledge (`reverse_knowledge`).
- `events`: Queries, filters, and formats buffered dynamic events without writing them to disk.
  - Filter by event `kind` (`stdout`, `stderr`, `message`, `trace`, `network`, `crypto`, `breakpoint`, `step`, `dom`, `storage`, `lifecycle`, `error`), `channel`, or `since_seq`.
  - Returns paginated event summaries with sequence numbers and previews.
- `verify`: Verifies a hypothesis in the Evidence ledger directly using dynamic evidence, creating a verified ConclusionEvidence record.
  - Promotes verified conclusion to `reverse_knowledge` with dynamic pattern tagging (`dynamic_crypto_verification`, `dynamic_jni_resolution`, `dynamic_auth_observation`).
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

// 3. Ingest DAP breakpoint event, link to workflow step, and verify hypothesis
reverse_dynamic_evidence(
  action: "ingest",
  session_id: "dap_gdb_01",
  source: "dap",
  target: "bin/target.elf",
  events: [{ event: "stopped", body: { reason: "breakpoint", threadId: 1 } }],
  workflow_id: "wf_elf_019a",
  step_id: "step_g2_bp",
  hypothesis_id: "ev_hyp_check_license",
  conclusion: "License check function at 0x401240 validated via DAP instruction breakpoint.",
  advance_workflow: true
)

// 4. Inspect overall dynamic evidence closure status
reverse_dynamic_evidence(action: "status", workflow_id: "wf_elf_019a")
```
</examples>
