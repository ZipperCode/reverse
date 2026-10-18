# reverse_dynamic_evidence

> Normalizes and ingests bounded dynamic events (Frida, browser CDP, DAP, Unidbg) into the Evidence ledger, links workflow steps, and promotes verified outcomes into reusable reverse knowledge.

## Source
- Entry: `packages/coding-agent/src/tools/reverse-dynamic-evidence.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/reverse-dynamic-evidence.md`
- Core dynamic contracts: `packages/coding-agent/src/reverse-runtime-session/dynamic-events.ts`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"ingest"`, `"events"`, `"verify"`, `"status"`. |
| `session_id` | `string` | No | Runtime session ID (Frida, Browser CDP, DAP, Unidbg) to pull buffered events from. |
| `source` | `string` | No | Source platform: `"frida"`, `"browser"`, `"dap"`, `"unidbg"`, `"custom"`. |
| `target` | `string` | No | Target binary, package, process name, or URL associated with these events. |
| `events` | `unknown` | No | Explicit array of raw or structured dynamic events to ingest or query. |
| `kind` | `string` | No | Filter events by kind (`stdout`, `stderr`, `message`, `trace`, `network`, `crypto`, `storage`, `dom`, `breakpoint`, `step`, `lifecycle`, `error`). |
| `channel` | `string` | No | Filter events by channel (`send`, `console`, `websocket`, `crypto`, `fetch`, `xhr`, `stopped`, `output`, etc.). |
| `since_seq` | `number` | No | Filter to events strictly greater than this sequence number. |
| `limit` | `number` | No | Maximum number of events to ingest or return (default 20, max 100). |
| `classification` | `string` | No | Weakness taxonomy, e.g. `'CWE-311'` (crypto) or `'CWE-319'` (cleartext transmission). |
| `tags` | `string[]` | No | Categorization tags to attach to generated evidence facts. |
| `workflow_id` | `string` | No | Reverse workflow ID to link newly ingested dynamic facts and update steps. |
| `step_id` | `string` | No | Specific workflow step ID to link newly ingested dynamic facts to. |
| `advance_workflow` | `boolean` | No | Whether to mark the associated workflow step as completed if backed by verified evidence. |
| `hypothesis_id` | `string` | No | Hypothesis ID in Evidence ledger to verify with these dynamic facts. |
| `conclusion` | `string` | No | Confirmed deductive conclusion text to record when verifying a hypothesis. |
| `method` | `string` | No | Experimental dynamic method used (e.g. `'Frida JNI hook'`, `'CDP network intercept'`). |
| `command` | `string` | No | Exact script, CLI invocation, or expression that produced the dynamic outcome. |
| `result` | `string` | No | Observed empirical result, output string, decrypted buffer, or register delta. |
| `reproducibility` | `string` | No | Reproducibility metric or description, e.g. `'100% (5/5 runs)'`. |
| `learn` | `boolean` | No | Whether to automatically promote verified conclusions into reusable reverse knowledge (default true). |

## Actions

- **ingest**: Normalizes raw or structured dynamic events from an active runtime session or caller parameter into `UniversalDynamicEvent` instances, and records them as `FactEvidence` in the `EvidenceStore`. Generates verifiable dynamic locators (`session:<id>:seq:<seq>`) and redacts credentials. Automatically associates facts with workflow steps and verifies hypotheses when provided.
- **events**: Queries, filters, and displays buffered events from a dynamic runtime session without modifying disk or the evidence ledger.
- **verify**: Directly verifies an existing hypothesis in the Evidence ledger using dynamic facts or session telemetry, creating a `ConclusionEvidence` record and promoting it into `reverse_knowledge`.
- **status**: Summarizes dynamic evidence closure for the current workspace, reporting counts of dynamic facts, verified conclusions, active sessions, and dynamic knowledge patterns.

## Security & Architecture Guardrails

- **Zero Arbitrary Execution**: The tool strictly ingests, normalizes, and audits existing events; it never dispatches child processes or issues network calls.
- **Strict Boundedness**: Event queries and fact creation are capped to 100 items per call.
- **Secrets Redaction**: All event payloads, URLs, headers, and excerpts are filtered through credential and secret scrubbers.
- **Verifiable Dynamic Locators**: Emits `session:<id>:seq:<seq>` locators that deterministically point to specific runtime traces.
