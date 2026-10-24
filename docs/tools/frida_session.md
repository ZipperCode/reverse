# frida_session

> Persistent Frida dynamic instrumentation sessions: create, manage, and execute scripts across multiple turns against spawned or attached targets on local, USB, or remote devices. Supports both default batch CLI execution and long-lived persistent live sessions with bi-directional RPC, real-time event streaming, and in-place script hot reloading. Also available under alias `reverse_dynamic_session`.

## Source

- Entry: `packages/coding-agent/src/tools/frida-session.ts`
- Live client: `packages/coding-agent/src/tools/frida-live-client.ts`
- Python worker: `packages/coding-agent/src/tools/frida-worker.py`
- Toolchain environment probe: `packages/coding-agent/src/tools/frida-live-env.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/frida-session.md`
- Dependency detector: `packages/coding-agent/src/tools/frida.ts` (`fridaDependency`)

## Capabilities

The `frida_session` tool provides stateful analysis sessions for dynamic binary instrumentation:

- **Dual Operating Modes (`mode` parameter)**:
   - `mode: "batch"` (default): Backwards-compatible one-shot execution. Runs Frida CLI against target, captures line-by-line stdout/stderr, and exits.
   - `mode: "live"`: Persistent background Python worker (`frida-worker.py`) communicating over isolated file descriptors via line-delimited JSON (NDJSON). Retains target process attachment, supports interactive JavaScript RPC exports, provides script hot-reloading (`load`/`unload`) without detaching, and buffers telemetry events eagerly.
- **Python Toolchain Discovery & Verification**:
   - Automatically resolves Python toolchains via canonical reverse path (`~/.local/share/reverse/toolchains/frida/bin/python`), sibling Python binary of the resolved `~/.local/bin/frida` symlink, explicit `REVERSE_FRIDA_PYTHON` environment override, or PATH.
   - Probes `import frida` and queries version before declaring live mode available. Returns structured `missing_dependency` if unavailable.
- **Session Lifecycle Management (`action` parameter)**:
   - `action: "create"`: Initialize a session against a target (`pid`, `process`, or `spawn`). Pass `mode: "live"` for long-lived target attachment and RPC.
   - `action: "load"`: (Live mode) Load or hot-reload a JavaScript script into the attached target. Unloads prior scripts, refreshes Interceptor hooks in-place, and discovers exported `rpc.exports` methods.
   - `action: "unload"`: (Live mode) Unload active script and remove all hooks from target while keeping the session attached.
   - `action: "rpc"`: (Live mode) Invoke exported functions defined in `rpc.exports.<method>` with arbitrary arguments (`rpc_method`, `rpc_args`), returning real serialized results directly.
   - `action: "resume"`: (Live mode) Resume a suspended or paused spawned target.
   - `action: "run"`: Execute scripts or built-in commands. On live sessions, loading a script automatically hot-reloads the active instrumentation. On batch sessions, executes via one-shot CLI.
   - `action: "events"`: Query, inspect, filter, or export the persistent event ring buffer.
   - `action: "status"`: Inspect session state, worker liveness, target attachment, loaded script, and RPC exports.
   - `action: "stop"`: Detach from target and terminate active worker process. Detaches ONLY; attached targets are never killed.
   - `action: "destroy"`: Detach from target, terminate worker, and remove persisted session files.
- **Safe Lifecycle & Target Ownership**:
   - Attached processes (`pid` or `process`) are NEVER terminated when a session is stopped or destroyed. Stopping a live session detaches cleanly.
   - Spawned targets (`spawn`) remain suspended until initial instrumentation scripts are loaded, preventing race conditions that miss early `main` or initialization hooks. Once instrumentation is loaded, target resumes automatically unless `pause: true` was requested.
   - If target process terminates, session updates honest status to `stopped` / `detached`.
   - Process-local live workers do not fake persistence across host restarts. Disconnected sessions report `disconnected` honestly and require an explicit `create` to reconnect.
- **Bounded Event Ring Buffer**: Captures stdout (`console.log`), stderr, `send(...)` structured JSON messages, base64-encoded binary buffers, traces, and process lifecycle events into a bounded persistent buffer (default 500 events).
- **Evidence Ledger Integration**: Formats structured `DynamicEvidenceReference` objects (`sourceTool: "frida_session"`, `locator: "session:<id>:seq:<seq>"`) with `export_evidence: true` for direct ingestion into the `evidence` ledger.

## When to Use `frida_session` vs `frida`

- Use `frida` for one-shot dynamic scripts, quick process enumeration (`ps`), device discovery (`devices`), or standalone verification checks.
- Use `frida_session` with `mode: "live"` for stateful multi-turn investigations, bidirectional RPC invocations, progressive hook refinement, and live event telemetry.

## Inputs

| Field             | Type                                                                                              | Required    | Description                                                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `action`          | `create \| list \| status \| run \| events \| stop \| destroy \| load \| unload \| rpc \| resume` | No          | Action to perform (defaults to `run` if script is provided, or `list` if empty).                                                          |
| `mode`            | `batch \| live`                                                                                   | No          | Session execution mode: `batch` (default one-shot CLI) or `live` (persistent background worker with RPC and hot reload).                  |
| `session_id`      | `string`                                                                                          | Conditional | Identifier for the session. Auto-generated on `create` if omitted.                                                                        |
| `name`            | `string`                                                                                          | No          | Optional human-readable session name or label.                                                                                            |
| `pid`             | integer `>= 1`                                                                                    | Conditional | Target process ID to attach to (for `create`).                                                                                            |
| `process`         | `string`                                                                                          | Conditional | Target process name or package name to attach to (for `create`).                                                                          |
| `spawn`           | `string`                                                                                          | Conditional | Target binary path or package name to spawn (for `create`).                                                                               |
| `usb`             | `boolean`                                                                                         | No          | Target USB device/emulator (passes `-U`).                                                                                                 |
| `device`          | `string`                                                                                          | No          | Target device identifier or serial (passes `-D <device>`).                                                                                |
| `host`            | `string`                                                                                          | No          | Target remote frida-server host (e.g. `192.168.1.5:27042`, passes `-H <host>`).                                                           |
| `script`          | `string`                                                                                          | Conditional | Inline Frida JavaScript source code to execute or load.                                                                                   |
| `script_path`     | `string`                                                                                          | Conditional | Local path to Frida JavaScript file.                                                                                                      |
| `rpc_method`      | `string`                                                                                          | Conditional | For `action: "rpc"`: name of exported RPC function in `rpc.exports`.                                                                      |
| `rpc_args`        | `unknown`                                                                                         | No          | For `action: "rpc"`: arguments passed to the RPC function (scalar, array, or object).                                                     |
| `command`         | `string`                                                                                          | No          | Built-in command: `script` (default), `modules` (enumerate loaded modules), `ps` (list processes), `inspect` (query runtime environment). |
| `template`        | `string`                                                                                          | No          | Built-in template (`jni_register`, `native_functions`, `module_load`, `exports`) automatically resolved when `script` is omitted.         |
| `module`          | `string`                                                                                          | No          | Target module name for templates `exports`, `native_functions`, or `jni_register`.                                                        |
| `symbol`          | `string`                                                                                          | No          | Target function symbol name for template `native_functions` or custom JNI entry point.                                                    |
| `symbols`         | `string[]`                                                                                        | No          | Array of target function symbol names for template `native_functions`.                                                                    |
| `offset`          | `string \| number`                                                                                | No          | Target function offset from module base (e.g. `'0x1234'`) for template `native_functions`.                                                |
| `offsets`         | `Array<string \| number>`                                                                         | No          | Array of target function offsets for template `native_functions`.                                                                         |
| `args_count`      | integer `>= 0`                                                                                    | No          | Number of arguments captured in `native_functions` template (default 4).                                                                  |
| `args_decode`     | `Record<string, string>`                                                                          | No          | Argument decode mapping (e.g. `{"0": "string", "1": "int"}`) for `native_functions` template.                                            |
| `retval`          | `boolean`                                                                                         | No          | Whether to capture return value in `native_functions` template (default true).                                                            |
| `backtrace`       | `boolean \| string`                                                                               | No          | Whether to capture backtrace in `native_functions` template (`true`, `'accurate'`, `'fuzzy'`, or `false`).                               |
| `max_events`      | integer `>= 1`                                                                                    | No          | Maximum events captured before detaching hooks (default 100).                                                                              |
| `max_buffer_bytes`| integer `>= 1`                                                                                    | No          | Maximum string/buffer bytes read per argument in `native_functions` template (default 256).                                              |
| `script_args`     | `unknown`                                                                                         | No          | Optional arguments passed to script via `-P` / `--parameters JSON`.                                                                       |
| `pause`           | `boolean`                                                                                         | No          | For spawn: leave main thread paused after spawning (passes `--pause`).                                                                    |
| `no_pause`        | `boolean`                                                                                         | No          | For spawn: legacy flag (defaults to `true`; `false` keeps paused via `--pause`).                                                          |
| `filter`          | `string`                                                                                          | No          | Filter for `list` action matching session ID, name, or target.                                                                            |
| `cli_args`        | `string[] \| string`                                                                              | No          | Extra CLI arguments passed directly to Frida.                                                                                             |
| `timeout`         | number `>= 1`                                                                                     | No          | Execution watchdog timeout in seconds (default 30).                                                                                       |
| `max_bytes`       | integer `>= 1`                                                                                    | No          | Output cap in bytes (default 262144; full output saved if `to_artifact` is true).                                                         |
| `to_artifact`     | `boolean`                                                                                         | No          | Save complete execution output and session metadata to session artifact.                                                                  |
| `since_seq`       | `number`                                                                                          | No          | For `events`: return events with sequence numbers strictly greater than this value.                                                       |
| `limit`           | `number`                                                                                          | No          | For `events` or `list`: maximum number of records to return (default 50, max 500).                                                        |
| `clear`           | `boolean`                                                                                         | No          | For `events`: clear all captured events from session event ring buffer.                                                                   |
| `kind`            | `string`                                                                                          | No          | For `events`: filter events by kind (`stdout`, `stderr`, `message`, `trace`, `lifecycle`, `error`).                                       |
| `channel`         | `string`                                                                                          | No          | For `events`: filter events by channel (`console`, `send`, `spawn`, `trace`, `lifecycle`).                                                |
| `export_evidence` | `boolean`                                                                                         | No          | For `events` or `run`: format structured evidence references compatible with the `evidence` ledger.                                       |

## Structured Statuses

- `ok`: Session operation succeeded.
- `missing_dependency`: Frida tools or Python bindings are absent; returns installation hints.
- `stopped`: Session is stopped / detached.
- `not_found`: Session ID not found.
- `timeout`: Script execution or RPC timed out.
- `error`: Subprocess or IPC error.

## Real Local Validation

Validated on macOS arm64 with Frida 17.24.2 and frida-tools 14.11.0 against a self-authored C executable:

1. **Persistent Live Session & RPC**:
   - `create(mode: "live", pid: <pid>, script: "...")` attached long-lived Python worker process without detaching.
   - Initial script installed `Interceptor` hook and exported `rpc.exports.transform`.
   - Separate calls to `events()` after real target execution ticks showed event sequence growing continuously.
   - `rpc(rpc_method: "transform", rpc_args: [18])` returned actual evaluated value `18`.
2. **In-Place Hot Script Reloading**:
   - `load(script: "rpc.exports.transform = function(x) { return x * 3; };")` updated the JavaScript runtime without process detachment or re-attachment.
   - Subsequent `rpc(rpc_method: "transform", rpc_args: [9])` returned `27`.
3. **Hook Removal & Detach-Only Lifecycle**:
   - `unload()` cleanly stopped all Interceptor hooks; target process continued running undisturbed.
   - Target process termination reported status as `disconnected` / `detached`.
   - `stop()` cleanly detached from target without killing the user process.
4. **Evidence Integration**:
   - `events(export_evidence: true)` generated canonical `locator: "session:<id>:seq:<seq>"` references and persisted verified dynamic facts directly into the Evidence ledger.
