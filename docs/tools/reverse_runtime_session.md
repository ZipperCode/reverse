# reverse_runtime_session

> Unified reverse engineering runtime session registry: manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans across Frida, browser, DAP (debug), IDA, and Ghidra without unsafe arbitrary process control.

## Source
- Entry: `packages/coding-agent/src/tools/reverse-runtime-session.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/reverse-runtime-session.md`
- Core engine: `packages/coding-agent/src/reverse-runtime-session/`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `string` | Yes | Action: `"register"`, `"list"`, `"status"`, `"restore"`, `"unregister"`, `"heartbeat"`, `"events"`. |
| `session_id` | `string` | No* | Unique session identifier (alias `id`). Required for `status`, `restore`, `unregister`, `heartbeat`, and `events`. |
| `id` | `string` | No | Alias for `session_id`. |
| `kind` | `string` | No* | Session kind: `"frida"`, `"browser"`, `"dap"`, `"ida"`, `"ghidra"`, or `"generic"`. Required for `register`. |
| `name` | `string` | No | Friendly label or name for the runtime session. |
| `target` | `string` | No | High-level target identifier (binary path, URL, package name, PID, etc.). |
| `target_details` | `unknown` | No | Detailed target metadata (PID, package, binary path, database locator, URL, display options). |
| `connection` | `unknown` | No | Sanitized connection parameters (host, port, device ID, cdp_url, etc.). |
| `recovery_hints` | `unknown` | No | Optional custom recovery hints or instructions for generic/custom sessions. |
| `workflow_id` | `string` | No | Associated `reverse_workflow` workflow identifier. |
| `step_id` | `string` | No | Associated `reverse_workflow` step identifier. |
| `status` | `string` | No | Initial or updated status: `"active"`, `"idle"`, `"stale"`, `"closed"`, `"failed"`. |
| `caller_status` | `string` | No | Caller-reported session status or observation for `heartbeat` and `status` actions. |
| `probe` | `boolean` | No | Perform safe, opt-in metadata probe (no arbitrary process execution). |
| `probe_result` | `string` | No | Caller-reported probe outcome or observation message. |
| `stale_timeout` | `number` | No | Stale detection threshold in seconds (default 300, min 10). |
| `limit` | `number` | No | Maximum sessions to list in `list` action (default 20, max 100). |
| `filter_kind` | `string` | No | Filter listed sessions by kind (`frida`, `browser`, `dap`, `ida`, `ghidra`, `generic`). |
| `filter_status` | `string` | No | Filter listed sessions by status (`active`, `idle`, `stale`, `closed`, `failed`). |
| `to_artifact` | `boolean` | No | Force exporting full session details to session artifact instead of inline response. |
| `since_seq` | `number` | No | Return buffered events whose sequence is greater than this cursor. |
| `event_kind` | `string` | No | Filter buffered telemetry by event kind. |

## Actions

- **register**: Registers a new or existing runtime session across supported kinds (`frida`, `browser`, `dap`, `ida`, `ghidra`, `generic`). Automatically deep-sanitizes connection parameters (strips passwords, bearer tokens, API keys, credentials) and removes live process handles (sockets, pipes, child process objects). Generates a deterministic session ID (`runt_<kind>_<uuid>`) if omitted, and saves the record in project-scoped storage.
- **list**: Lists registered runtime sessions for the active project. Supports filtering by kind, status, or workflow ID. Detects stale sessions deterministically by evaluating the elapsed duration since the last heartbeat against `stale_timeout`. Bounded output prevents context explosion.
- **events**: Reads bounded normalized telemetry synchronized by Frida, Browser, and DAP controllers. Supports `since_seq`, `event_kind`, and `limit`; does not capture or execute target code. Registry snapshots contain at most the latest 50 controller events and are not a lossless stream.
- **status**: Inspects detailed sanitized metadata, target properties, heartbeat history, and stale status. When `probe: true` or `caller_status` is supplied, performs a non-invasive metadata check (e.g., verifying target database or binary presence on disk for IDA/Ghidra) or incorporates caller-reported facts without unsafe process manipulation.
- **heartbeat**: Updates the session's heartbeat timestamp and increments the heartbeat counter, clearing stale status. Allows caller to report health metrics or note error conditions.
- **restore**: Generates a declarative recovery plan. Explicit controller recovery hints take precedence, including `browser_reverse_session` with `tab_name`. The plan does not execute scripts, restart targets, or bypass tool approval.
- **unregister**: Deletes or marks closed the session record in persistent storage.

## Security & Architecture Guardrails

- **Zero Arbitrary Execution**: Never spawns untrusted shell processes or dispatches OS kill signals during status checks. Probes are strictly opt-in and non-invasive.
- **No Secrets Stored**: All URLs, connection objects, headers, and metadata are scrubbed with credential redaction before atomic file writing.
- **No Live Handles**: Transient handles (PIDs, child processes, sockets) are stripped or reduced to plain primitives; handles are never serialized or treated as live references.
- **Bounded Storage**: The registry caps persistent session count to 100 per project, evicting oldest closed or stale sessions when exceeded.
