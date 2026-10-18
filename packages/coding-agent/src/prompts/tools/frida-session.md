Create and manage persistent Frida dynamic instrumentation sessions for iterative reverse engineering, runtime hooking, and process inspection.

Capabilities:

1. Persistent Session Lifecycle (`action` parameter):
   - `action: "create"`: Initialize a persistent analysis session against a target (`pid`, `process`, or `spawn`). Remembers target, transport options, and active state across turns. Optionally runs an initial script.
   - `action: "list"`: Enumerate existing sessions in the current project scope, showing session IDs, targets, status (active/stopped), and execution counts.
   - `action: "status"`: Inspect status, target liveness, and history of a specific session (or active session if omitted).
   - `action: "run"`: Execute Frida scripts or built-in commands against the session target without repeating target or connection flags.
   - `action: "stop"`: Stop an active session, terminating any running child processes while preserving session records.
   - `action: "destroy"`: Terminate running child processes and permanently remove session metadata.

2. Target Selection (for `create`):
   - Attach to existing process by PID: `pid: <number>`
   - Attach to existing process by name: `process: "<name>"`
   - Launch application or binary: `spawn: "<path_or_package>"` (e.g. `com.example.app` or `/path/to/binary`). Supports `no_pause: true` (default) or `false`.

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

5. Execution Control & Bounds:
   - `timeout`: watchdog execution timeout in seconds (default 30, no upper limit).
   - `max_bytes`: maximum stdout bytes captured before truncation (default 262144, no upper limit).
   - `to_artifact`: persist complete execution output and session details to session artifact.

When to use `frida_session` vs `frida`:
- Use `frida` for one-shot scripts, quick process enumeration, or single verification steps.
- Use `frida_session` for multi-step reverse engineering investigations, progressive hook refinement, or maintaining a persistent target context over multiple agent turns.

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

// Check session status and execution history
frida_session(action: "status", session_id: "app-auth-test")

// Stop the session
frida_session(action: "stop", session_id: "app-auth-test")

// Destroy and clean up session
frida_session(action: "destroy", session_id: "app-auth-test")
```
</examples>
