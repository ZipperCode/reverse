Unified reverse engineering runtime session registry: manages sanitized connection metadata, status/heartbeat stale detection, and deterministic recovery/restore plans across Frida, browser, IDA, and Ghidra without unsafe arbitrary process control.

Actions:
- `register`: Register a new or existing reverse runtime session.
  - Accepts session kinds: `frida`, `browser`, `ida`, `ghidra`, or `generic`.
  - Captures target metadata (PID, package name, binary path, database locator, URL, endpoint).
  - Automatically sanitizes connection metadata: strips secrets, passwords, auth tokens, bearer credentials, and non-serializable live process handles.
  - Generates deterministic session identifier (e.g. `runt_frida_...`) or accepts custom `session_id`.
  - Optionally associates with `workflow_id` and `step_id`.
- `list`: List registered runtime sessions for the active project.
  - Supports filtering by `filter_kind` (`frida`, `browser`, `ida`, `ghidra`), `filter_status` (`active`, `idle`, `stale`, `closed`, `failed`), or `workflow_id`.
  - Detects stale sessions deterministically based on heartbeat interval and `stale_timeout` (default: 300 seconds).
  - Output is strictly bounded with pagination limits.
- `status`: Inspect detailed status, metadata, heartbeat history, and health of a session.
  - Reports sanitized connection parameters and target details.
  - Evaluates stale status deterministically without fake live status claims.
  - Status probes are strictly opt-in and safe (`probe: true` or `caller_status`): performs local non-invasive file presence checks (for IDA db/Ghidra binary) or records caller-reported execution facts; never issues unsafe arbitrary process termination or untrusted network packets.
- `heartbeat`: Update session heartbeat timestamp and health metrics.
  - Resets stale timer and marks session state active or idle.
  - Accepts optional caller status updates, error notes, or observation summaries.
- `restore`: Formulate a deterministic restore and recovery plan.
  - Generates exact tool invocation parameters and recovery instructions for the respective runtime tool (`frida_session`, `browser`, `ida`, `ghidra_inspect`).
  - Does NOT launch arbitrary processes automatically: returns structured recovery parameters and pre-conditions for controlled execution.
- `unregister`: Remove or close a runtime session record from persistent storage.

Security & Integrity:
- Secrets redaction: automatically sanitizes API keys, tokens, auth headers, and credential query params.
- No live handles: stores only serializable metadata; drops socket streams and child process handles.
- No arbitrary process execution: status probes never kill or signal external processes.
- Atomic project-scoped persistence: records are stored with secure file permissions (0o600) and atomic file replacement.

<examples>
```
// 1. Register a Frida instrumentation session
reverse_runtime_session(action: "register", kind: "frida", target: "com.example.app", target_details: { process: "com.example.app", usb: true }, connection: { host: "127.0.0.1:27042" })

// 2. Register a browser inspection session
reverse_runtime_session(action: "register", kind: "browser", target: "https://example.com/login", target_details: { name: "auth_audit", url: "https://example.com/login" })

// 3. Register an IDA Pro database session
reverse_runtime_session(action: "register", kind: "ida", target: "bin/target.i64", target_details: { db: "bin/target.i64" })

// 4. Register a Ghidra headless inspection session
reverse_runtime_session(action: "register", kind: "ghidra", target: "bin/target.elf", target_details: { path: "bin/target.elf", project_dir: "build/ghidra_proj" })

// 5. List all active or stale runtime sessions
reverse_runtime_session(action: "list")

// 6. Inspect detailed status with opt-in metadata probe
reverse_runtime_session(action: "status", session_id: "runt_frida_018f...", probe: true)

// 7. Update heartbeat to maintain active session state
reverse_runtime_session(action: "heartbeat", session_id: "runt_frida_018f...")

// 8. Generate deterministic restore plan after disconnect or session loss
reverse_runtime_session(action: "restore", session_id: "runt_frida_018f...")

// 9. Unregister a closed session
reverse_runtime_session(action: "unregister", session_id: "runt_frida_018f...")
```
</examples>
