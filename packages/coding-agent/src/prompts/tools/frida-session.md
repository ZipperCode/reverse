Create and manage persistent Frida dynamic instrumentation sessions for iterative reverse engineering, runtime hooking, and process inspection.

Capabilities:

1. Persistent Session Lifecycle (`action` parameter):
   - `action: "create"`: Initialize a persistent analysis session against a target (`pid`, `process`, or `spawn`). Remembers target, transport options, and active state across turns. For `spawn` targets, detects the child PID and prevents duplicate process spawning on subsequent runs.
   - `action: "list"`: Enumerate existing sessions in the current project scope, showing session IDs, targets, status (active/stopped), and execution counts.
   - `action: "status"`: Inspect status, target liveness, and history of a specific session (or active session if omitted).
   - `action: "run"`: Execute Frida scripts or built-in commands against the session target without repeating target or connection flags. Captures CLI output line-by-line into the session's event ring buffer, parsing `console.log`, `send(...)` structured JSON messages, traces, and process events.
   - `action: "events"`: Query, inspect, filter, or export the bounded persistent event ring buffer. Supports `filter`, `kind` (`stdout`, `stderr`, `message`, `trace`, `lifecycle`, `error`), `channel` (`console`, `send`, `spawn`, `trace`), `since_seq` (incremental retrieval), `limit`, `clear`, and `export_evidence`.
   - `action: "stop"`: Stop an active session, terminating any running child processes while preserving session records.
   - `action: "destroy"`: Terminate running child processes and permanently remove session metadata.
2. Target Selection (for `create`):
   - Attach to existing process by PID: `pid: <number>`
   - Attach to existing process by name: `process: "<name>"`
   - Launch application or binary: `spawn: "<path_or_package>"` (e.g. `com.example.app` or `/path/to/binary`). Resumes target execution automatically; pass `pause: true` (or legacy `no_pause: false`) to leave the main thread paused via `--pause`.

3. Transport & Connectivity (for `create`):
   - Local system: default (omit device flags)
   - USB / connected emulator: `usb: true` (passes `-U`)
   - Specific device ID: `device: "<device_id>"` (passes `-D <device_id>`)
   - Remote frida-server host: `host: "<ip:port>"` (passes `-H <host>`)

4. Script & Command Execution (for `run`):
   - Inline script: `script: "Interceptor.attach(...)"`
   - Script file: `script_path: "hooks/trace.js"`
   - Built-in commands: `command: "modules"` (enumerate loaded modules), `command: "ps"` (list processes), `command: "inspect"` (query runtime architecture and process details).
   - Script parameters: `script_args: { key: "value" }` (passed via `-P` / `--parameters JSON`).

5. Execution Control, Events & Evidence:
   - `timeout`: watchdog execution timeout in seconds (default 30, no upper limit).
   - `max_bytes`: maximum stdout bytes captured before truncation (default 262144, no upper limit).
   - `to_artifact`: persist complete execution output and session details to session artifact.
   - `export_evidence: true`: return structured evidence references (`sourceTool: "frida_session"`, `locator: "session:<id>:seq:<seq>"`) directly ready for citing or ingestion into the `evidence` ledger.
   - Bounded Ring Buffer: persistent event buffer capped at 500 records per session to prevent unbounded memory growth while retaining complete recent telemetry across turns.

When to use `frida_session` (alias `reverse_dynamic_session`) vs `frida`:
- Use `frida` for one-shot scripts, quick process enumeration, or single verification steps.
- Use `frida_session` / `reverse_dynamic_session` for multi-step reverse engineering investigations, dynamic event capture, progressive hook refinement, tracking spawned apps without re-spawning, or maintaining persistent instrumentation telemetry across multiple agent turns.

<examples>
```
// Create a persistent session attached to a USB Android application
frida_session(action: "create", process: "com.example.app", usb: true, session_id: "app-auth-test")

// List active and saved sessions
frida_session(action: "list")

// Run an enumeration command against the session target
frida_session(action: "run", session_id: "app-auth-test", command: "modules")

// Run custom hook script in the session
frida_session(action: "run", session_id: "app-auth-test", script_path: "hooks/trace_crypto.js")

// Query captured structured events and generate evidence coordinates
frida_session(action: "events", session_id: "app-auth-test", kind: "message", export_evidence: true)

// Check session status and execution history
frida_session(action: "status", session_id: "app-auth-test")

// Stop the session
frida_session(action: "stop", session_id: "app-auth-test")

// Destroy and clean up session
frida_session(action: "destroy", session_id: "app-auth-test")
```
</examples>
