# reverse_dynamic_session

> Dynamic reverse engineering experiment session and event ring buffer: stateful target persistence, instrumentation lifecycle, structured message/trace capture, and evidence ledger referencing.

## Overview

The `reverse_dynamic_session` tool (also available as `frida_session`) manages persistent dynamic instrumentation sessions for iterative reverse engineering, runtime hooking, and process inspection:

- **Stateful Target Context**: Persists target parameters (`pid`, `process`, or `spawn`), device settings (`usb`, `device`, `host`), and process status across multiple turns without re-specifying them.
- **Spawn Idempotency (No Re-spawning)**: For `spawn` targets, detects the child PID and automatically attaches via `-p <pid>` on subsequent runs instead of re-spawning a new duplicate process instance.
- **Bounded Event Ring Buffer**: Captures line-by-line stdout (`console.log`), stderr, `send(...)` structured JSON messages, traces, and process lifecycle events into a bounded persistent buffer (default 500 events) that survives across agent turns.
- **Evidence Ledger Integration**: Formats structured `DynamicEvidenceReference` objects (`sourceTool: "reverse_dynamic_session"`, `locator: "session:<id>:seq:<seq>"`) with `export_evidence: true` for direct ingestion into the `evidence` ledger.
- **Lifecycle Management**:
  - `action: "create"`: Start a new analysis session against a target, optionally running an initial script and capturing child process state.
  - `action: "list"`: Enumerate all active and historical sessions within the project scope, reporting target, status, and run counts.
  - `action: "status"`: Inspect session metadata, target liveness, and execution history.
  - `action: "run"`: Execute Frida scripts or built-in commands against the target in the session context, automatically parsing CLI output line-by-line into structured events.
  - `action: "events"`: Query, inspect, filter, or export the bounded persistent event ring buffer (`since_seq`, `kind`, `channel`, `filter`, `limit`, `clear`, `export_evidence`).
  - `action: "stop"`: Stop an active session and terminate running child processes while retaining metadata.
  - `action: "destroy"`: Terminate running child processes and remove persisted session files.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `create \| list \| status \| run \| events \| stop \| destroy` | No | Action to perform (defaults to `run` if script is provided, or `list` if empty). |
| `session_id` | `string` | Conditional | Identifier for the session. Auto-generated on `create` if omitted. |
| `name` | `string` | No | Optional human-readable session name or label. |
| `pid` | integer `>= 1` | Conditional | Target process ID to attach to (for `create`). |
| `process` | `string` | Conditional | Target process name or package name to attach to (for `create`). |
| `spawn` | `string` | Conditional | Target binary path or package name to spawn (for `create`). |
| `usb` | `boolean` | No | Target USB device/emulator (passes `-U`). |
| `device` | `string` | No | Target device identifier or serial (passes `-D <device>`). |
| `host` | `string` | No | Target remote frida-server host (e.g. `192.168.1.5:27042`, passes `-H <host>`). |
| `script` | `string` | Conditional | Inline Frida JavaScript source code to execute. |
| `script_path` | `string` | Conditional | Local path to Frida JavaScript file. |
| `command` | `string` | No | Built-in command: `script` (default), `modules` (enumerate loaded modules), `ps` (list processes), `inspect` (query runtime environment). |
| `script_args` | `unknown` | No | Optional arguments passed to script via `-P` / `--parameters JSON`. |
| `pause` | `boolean` | No | For spawn: leave main thread paused after spawning (passes `--pause`). |
| `no_pause` | `boolean` | No | For spawn: legacy flag (defaults to `true`; `false` keeps paused via `--pause`). |
| `filter` | `string` | No | Filter for `list` or `events` action matching session ID, name, or payload content. |
| `since_seq` | `number` | No | For `events`: return events with sequence numbers strictly greater than this value. |
| `limit` | `number` | No | For `events` or `list`: maximum number of records to return (default 50, max 500). |
| `clear` | `boolean` | No | For `events`: clear all captured events from session event ring buffer. |
| `kind` | `string` | No | For `events`: filter events by kind (`stdout`, `stderr`, `message`, `trace`, `lifecycle`, `error`). |
| `channel` | `string` | No | For `events`: filter events by channel (`console`, `send`, `spawn`, `trace`, `lifecycle`). |
| `export_evidence` | `boolean` | No | For `events` or `run`: format structured evidence references compatible with the `evidence` ledger. |
| `timeout` | number `>= 1` | No | Execution watchdog timeout in seconds (default 30). |
| `max_bytes` | integer `>= 1` | No | Output cap in bytes (default 262144; full output saved if `to_artifact` is true). |
| `to_artifact` | `boolean` | No | Save complete execution output and session metadata to session artifact. |
