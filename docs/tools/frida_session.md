# frida_session

> Persistent Frida dynamic instrumentation sessions: create, manage, and execute scripts across multiple turns against spawned or attached targets on local, USB, or remote devices.

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
  - `action: "run"`: Execute Frida scripts or built-in commands against the target in the session context.
  - `action: "stop"`: Stop an active session and terminate running child processes while retaining metadata.
  - `action: "destroy"`: Terminate running child processes and remove persisted session files.
- **Child Process & Cleanup**: Manages active child processes and ensures clean shutdown on `stop` or `destroy` as well as session disposal.
- **Safe State Persistence**: Persists session metadata under the agent state directory scoped by project. All scripts, parameters, and outputs are scrubbed with secret redaction before writing to disk.
- **Structured Error Handling**: Returns structured `missing_dependency` status when Frida tools are absent without throwing uncaught exceptions.

## When to Use `frida_session` vs `frida`

- Use `frida` for one-shot dynamic scripts, quick process enumeration (`ps`), device discovery (`devices`), or standalone verification checks.
- Use `frida_session` for progressive reverse engineering, multi-stage API or cryptographic hooking, tracking a spawned application across multiple interactions, or maintaining stateful analysis sessions across agent turns.

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `create \| list \| status \| run \| stop \| destroy` | No | Action to perform (defaults to `run` if script is provided, or `list` if empty). |
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
| `no_pause` | `boolean` | No | For spawn: automatically start main thread (defaults to `true`). |
| `filter` | `string` | No | Filter for `list` action matching session ID, name, or target. |
| `cli_args` | `string[] \| string` | No | Extra CLI arguments passed directly to Frida. |
| `timeout` | number `>= 1` | No | Execution watchdog timeout in seconds (default 30). |
| `max_bytes` | integer `>= 1` | No | Output cap in bytes (default 262144; full output saved if `to_artifact` is true). |
| `to_artifact` | `boolean` | No | Save complete execution output and session metadata to session artifact. |

## Structured Statuses

- `ok`: Session operation succeeded.
- `missing_dependency`: Frida tools are absent; returns installation hints and suggested alternatives.
- `stopped`: Session is stopped.
- `not_found`: Session ID not found.
- `timeout`: Script execution timed out.
- `error`: Execution or subprocess error.
