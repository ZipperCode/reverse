# frida_session

> Persistent Frida dynamic instrumentation sessions: create, manage, and execute scripts across multiple turns against spawned or attached targets on local, USB, or remote devices. Also available under alias `reverse_dynamic_session`.

## Source

- Entry: `packages/coding-agent/src/tools/frida-session.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/frida-session.md`
- Dependency detector: `packages/coding-agent/src/tools/frida.ts` (`fridaDependency`)

## Capabilities

The `frida_session` tool provides stateful analysis sessions inspired by jshookmcp and Seep:

- **Stateful Target Context**: Remember target parameters (`pid`, `process`, or `spawn`), device settings (`usb`, `device`, `host`), and process status across multiple turns without re-specifying them.
- **Session Lifecycle Management**:
  - `action: "create"`: Start a new analysis session against a target, optionally running an initial script and capturing child process state.
  - `action: "list"`: Enumerate all active and historical sessions within the project scope, reporting target, status, and run counts.
  - `action: "status"`: Inspect session metadata, target liveness, and execution history.
  - `action: "run"`: Execute Frida scripts or built-in commands against the target in the session context, automatically parsing CLI output line-by-line into structured events. Prevents duplicate process spawning for spawned targets when target PID is known.
  - `action: "events"`: Query, inspect, filter, or export the bounded persistent event ring buffer (`since_seq`, `kind`, `channel`, `filter`, `limit`, `clear`, `export_evidence`).
  - `action: "stop"`: Stop an active session and terminate running child processes while retaining metadata.
  - `action: "destroy"`: Terminate running child processes and remove persisted session files.
- **Bounded Event Ring Buffer**: Captures line-by-line stdout (`console.log`), stderr, `send(...)` structured JSON messages, traces, and process lifecycle events into a bounded persistent buffer (default 500 events) that survives across agent turns.
- **Evidence Ledger Integration**: Formats structured `DynamicEvidenceReference` objects (`sourceTool: "frida_session"`, `locator: "session:<id>:seq:<seq>"`) with `export_evidence: true` for direct ingestion into the `evidence` ledger.
- **Spawn Idempotency**: Remembers active child PID and attaches via `-p <pid>` on subsequent runs instead of re-spawning a new duplicate process.
- **Safe State Persistence & Registry Synchronization**: Persists session metadata under the canonical runtime registry state directory. Synchronizes bounded normalized recent events into the unified registry for evidence ingestion and records safe script recovery hints for deterministic recovery without executing scripts during restore planning. All scripts, parameters, and outputs are scrubbed with secret redaction before writing to disk.
- **Structured Error Handling**: Returns structured `missing_dependency` status when Frida tools are absent without throwing uncaught exceptions.

## When to Use `frida_session` vs `frida`

- Use `frida` for one-shot dynamic scripts, quick process enumeration (`ps`), device discovery (`devices`), or standalone verification checks.
- Use `frida_session` for progressive reverse engineering, multi-stage API or cryptographic hooking, tracking a spawned application across multiple interactions, or maintaining stateful analysis sessions across agent turns.

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
| `filter` | `string` | No | Filter for `list` action matching session ID, name, or target. |
| `cli_args` | `string[] \| string` | No | Extra CLI arguments passed directly to Frida. |
| `timeout` | number `>= 1` | No | Execution watchdog timeout in seconds (default 30). |
| `max_bytes` | integer `>= 1` | No | Output cap in bytes (default 262144; full output saved if `to_artifact` is true). |
| `to_artifact` | `boolean` | No | Save complete execution output and session metadata to session artifact. |
| `since_seq` | `number` | No | For `events`: return events with sequence numbers strictly greater than this value. |
| `limit` | `number` | No | For `events` or `list`: maximum number of records to return (default 50, max 500). |
| `clear` | `boolean` | No | For `events`: clear all captured events from session event ring buffer. |
| `kind` | `string` | No | For `events`: filter events by kind (`stdout`, `stderr`, `message`, `trace`, `lifecycle`, `error`). |
| `channel` | `string` | No | For `events`: filter events by channel (`console`, `send`, `spawn`, `trace`, `lifecycle`). |
| `export_evidence` | `boolean` | No | For `events` or `run`: format structured evidence references compatible with the `evidence` ledger. |

## Structured Statuses

- `ok`: Session operation succeeded.
- `missing_dependency`: Frida tools are absent; returns installation hints and suggested alternatives.
- `stopped`: Session is stopped.
- `not_found`: Session ID not found.
- `timeout`: Script execution timed out.
- `error`: Execution or subprocess error.

## Real local validation

Validated on macOS arm64 with Frida 17.24.2 and frida-tools 14.11.0 against a self-authored C executable, without a device or remote service:

- Local PID attachment and spawned-process interception both captured actual function arguments and return values.
- Observed outputs matched `output = input * 7 + 3`; module enumeration found the demo executable.
- `events(kind: "message")` preserved the CLI's Python-repr `send()` payloads as structured data; registry-based ingestion persisted them in the Evidence ledger.
- Installation used a dedicated Python virtual environment; user-level commands were linked under `~/.local/bin`, which catalog detection already searches.

This validates batch CLI instrumentation, not persistent RPC or real-time streaming. Android/USB, remote servers, and protected or hardened targets were not exercised. A successful batch run does not imply its script remains attached after the CLI exits.
