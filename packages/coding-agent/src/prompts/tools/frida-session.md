Create and manage persistent Frida dynamic instrumentation sessions for iterative reverse engineering, runtime hooking, and process inspection.

Capabilities:

1. Session Modes (`mode` parameter):
   - `mode: "batch"` (default): Backwards-compatible CLI mode. Each `run` executes a one-shot CLI invocation against the target, capturing stdout/stderr and exiting.
   - `mode: "live"`: Persistent long-lived Frida session backed by a dedicated background Python worker. Keeps target process attached, maintains continuous JavaScript runtime context, streams dynamic events in real time, supports RPC invocations (`rpc.exports`), and enables hot script reloading (`load`/`unload`) without detaching or re-spawning.

2. Session Lifecycle Actions (`action` parameter):
   - `action: "create"`: Initialize a session against a target (`pid`, `process`, or `spawn`). Specify `mode: "live"` for long-lived target attachment and RPC/hot reload, or omit for default batch mode.
   - `action: "load"`: (Live mode) Load or hot-reload a JavaScript script file or inline code into the active session. Automatically unloads previous scripts, cleans up prior hooks, attaches new hooks, and discovers exported `rpc.exports` methods.
   - `action: "unload"`: (Live mode) Unload the active script and remove all hooks from the target while keeping the live session attached.
   - `action: "rpc"`: (Live mode) Call an exported JavaScript RPC function defined in `rpc.exports.<method>` with arbitrary JSON arguments (`rpc_method`, `rpc_args`), returning the actual result directly.
   - `action: "run"`: Execute scripts or built-in commands. On live sessions, loading a script automatically hot-reloads the active instrumentation. On batch sessions, executes via one-shot CLI.
   - `action: "events"`: Query, inspect, filter, or export the persistent event ring buffer. Captures `send(...)` messages, `console.log` lines, lifecycle transitions (`detached`), and runtime errors. Supports `filter`, `kind`, `channel`, `since_seq`, `limit`, `clear`, and `export_evidence`.
   - `action: "status"`: Inspect session state, worker liveness, target attachment, loaded script, and RPC exports.
   - `action: "stop"`: Detach from target and terminate active worker or spawned processes while preserving session records.
   - `action: "destroy"`: Terminate target/worker and permanently remove session records.

3. Target Selection (for `create`):
   - Attach to existing process by PID: `pid: <number>`
   - Attach to existing process by name: `process: "<name>"`
   - Launch application or binary: `spawn: "<path_or_package>"` (e.g. `com.example.app` or `/path/to/binary`). Resumes execution automatically; pass `pause: true` (or legacy `no_pause: false`) to leave paused.

4. Transport & Connectivity (for `create`):
   - Local system: default (omit device flags)
   - USB / connected emulator: `usb: true` (passes `-U` or connects to USB device)
   - Specific device ID: `device: "<device_id>"` (passes `-D <device_id>`)
   - Remote frida-server host: `host: "<ip:port>"` (passes `-H <host>`)

5. Scripting, RPC & Hot Reload (for `load` / `rpc` / `run`):
   - Inline script: `script: "rpc.exports = { transform: function(x) { return x.toUpperCase(); } };"`
   - Script file: `script_path: "hooks/trace.js"`
   - RPC execution: `action: "rpc", rpc_method: "transform", rpc_args: ["input_text"]`
   - Built-in commands: `command: "modules"`, `command: "ps"`, `command: "inspect"`

6. Execution Control, Events & Evidence:
   - `timeout`: execution/RPC timeout in seconds (default 30).
   - `export_evidence: true`: return structured evidence references (`sourceTool: "frida_session"`, `locator: "session:<id>:seq:<seq>"`) directly ready for ingestion into the `evidence` ledger.
   - Bounded Ring Buffer: persistent event buffer capped at 500 records per session to prevent unbounded memory growth while retaining complete recent telemetry.

When to use `frida_session` (alias `reverse_dynamic_session`) vs `frida`:
- Use `frida` for one-shot scripts, quick process enumeration, or single verification steps.
- Use `frida_session` with `mode: "live"` for stateful multi-turn investigations, RPC function calling, progressive hook refinement, and live event telemetry.

<examples>
```
// 1. Create a persistent live session attached to a target PID
frida_session(action: "create", mode: "live", pid: 1234, session_id: "live-audit")

// 2. Load instrumentation script with RPC exports and Interceptor hooks
frida_session(action: "load", session_id: "live-audit", script: "rpc.exports = { transform: function(val) { return 'v1:' + val; } }; Interceptor.attach(Module.findGlobalExportByName('target_fn'), { onEnter: function(args) { send({event: 'hit', val: args[0].toInt32()}); } });")

// 3. Call exported RPC method with arguments
frida_session(action: "rpc", session_id: "live-audit", rpc_method: "transform", rpc_args: ["hello"])

// 4. Hot reload with an updated script (updates RPC and hooks in-place without re-attaching)
frida_session(action: "load", session_id: "live-audit", script: "rpc.exports = { transform: function(val) { return 'v2:' + val; } };")

// 5. Query captured telemetry events from the hook and export as evidence
frida_session(action: "events", session_id: "live-audit", kind: "message", export_evidence: true)

// 6. Unload script to stop all active hooks
frida_session(action: "unload", session_id: "live-audit")

// 7. Stop and clean up session
frida_session(action: "stop", session_id: "live-audit")
```
</examples>
