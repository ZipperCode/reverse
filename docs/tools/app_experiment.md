# app_experiment

The `app_experiment` tool provides controlled, single-action application security investigation and verification loops. It interfaces with connected Android devices over fixed `adb` argument vectors with POSIX-quoted remote operands, conducts credential-safe network request replays against explicit allowlisted origins, manages owned WebView DevTools forwards, and coordinates bounded dynamic instrumentation and proxy captures.

## Design Principles

1. **Explicit Identification**: Device actions require explicit `serial` and target `package`. The tool never guesses target devices or operates unboundedly across arbitrary packages.
2. **Fixed Argument Vectors and Remote Quoting**: Fixed command arrays (`["shell", "am", "start", ...]`) are dispatched with variable operands safely POSIX single-quoted (`quoteShellArg`) to prevent shell word splitting and metacharacter expansion on Android's remote shell (`/system/bin/sh`). Arbitrary shell string execution is prohibited.
3. **Strict Credential Protection**: Inline authorization headers, session cookies, and API keys are rejected in tool arguments to prevent secret leakage into session transcripts and TUI expanders. Authentication tokens must be supplied via environment variable references (`auth_header_env`) or protected local files (`request_file`).
4. **Enforced Scope Boundaries**: ContentProvider queries verify authority ownership against the target package via AOSP `dumpsys package` `ContentProvider Authorities:`. WebView discovery is filtered strictly to the target application's process IDs (never matching PID 0 or arbitrary sockets). HTTP replay rejects unallowlisted origins, runs in `redirect: 'manual'` mode without cross-origin following, and redacts sensitive query parameters and URL fragments from `Location` headers.
5. **No Root Escalation**: Application sandbox extraction strictly uses `run-as`. Non-debuggable packages return structured `unauthorized` statuses; automatic `su`/root escalation is forbidden.
6. **Session-Bound Lifecycle and Cleanup**: Owned forwarded ports, adb reverses, and device proxy settings track session ownership in a session-keyed WeakMap and register with `session.registerDisposeCallback` and `session.registerSessionChangeCallback`. Proxy settings are safely restored only if the current setting strictly matches the owned port.

## Actions

### `preflight`
Checks target device readiness, platform properties, and target package status.
- **Parameters**: `serial`, `package`
- **Output**: Device model, ABI, SDK level, package installation path, UID, debuggable flag (or unknown if dumpsys fails/truncates), and SELinux enforcement status.

### `invoke_component`
Executes benign component and deep link invocations via `am start`, `am startservice`, or `am broadcast`. Scopes implicit intents with `-p <package>`.
- **Parameters**: `serial`, `package`, `component?`, `component_type?`, `intent_action?`, `intent_category?`, `intent_data?`, `intent_extras?`
- **Output**: Command executed, exit code, stdout/stderr, and structured observations (e.g. security exceptions, activity launch confirmation, errors).

### `query_provider`
Performs constrained, read-only queries against Android ContentProviders (`content query --uri <uri>`).
- **Parameters**: `serial`, `package`, `uri`, `projection?` (comma-separated, converted to colon-separated internally), `selection?`, `sort_order?`
- **Output**: Query status, column names, row counts, and preview table with sensitive field values redacted. Validates that the provider authority belongs to the target package.

### `extract_sandbox_data`
Extracts files from private application directories (`shared_prefs`, `databases`, `files`, `cache`) on debuggable builds using `run-as` and `tar -cf - -- <subpath>`.
- **Parameters**: `serial`, `package`, `subpath?`, `max_bytes?`
- **Output**: Artifact ID, artifact path (created with mode 0o600 in private mode 0o700 directory), byte count, and SHA-256 digest. Requires `android:debuggable="true"`. Fails closed if the tar command times out, truncates, or returns non-zero.

### `webview_debug`
Discovers and forwards WebViews running within the target package process.
- **Parameters**: `serial`, `package`, `webview_op` (`discover`, `forward`, `list_forwards`, `cleanup`), `socket_name?`, `forward_port?`
- **Output**: Discovered DevTools unix domain sockets scoped to package PIDs, CDP endpoint URL (`http://127.0.0.1:<port>`), and owned forwarding handles created with `--no-rebind`.

### `network_replay`
Conducts bounded HTTP/API request replay comparisons between baseline requests and variant requests (e.g. unauthorized, role alteration, parameter tampering). Redirects are returned with manual status (3xx) without following or forwarding credentials; Location URLs have query parameters and hash fragments stripped.
- **Parameters**: `allowed_origins`, `baseline_request?`, `variant_requests?`, `auth_header_env?`, `request_file?`, `capture_response_artifacts?`
- **Output**: Per-variant response status codes, safe allowlisted header diffs, response size diffs, and SHA-256 body digests. Replaces prefix matching with exact streaming bounds and marks incomplete comparisons if truncated (`bodyHashMatch: null`). Supports `auth_header_env`, `header_env_map`, `body_file`, and protected `request_file` to prevent credential exposure in tool arguments.
- **Protected `request_file` format** (requires mode `0600` or `0400` private to owner on POSIX):
```json
{
  "baseline_request": {
    "url": "https://api.example.com/v1/profile",
    "method": "POST",
    "body_file": "artifacts/payload.json",
    "header_env_map": { "X-API-Key": "MY_KEY_VAR" },
    "auth_header_env": "ALICE_TOKEN_VAR"
  },
  "variant_requests": [
    { "id": "unauth", "name": "Unauthenticated" },
    { "id": "bob", "name": "Bob Role", "auth_header_env": "BOB_TOKEN_VAR" }
  ]
}
```

### `mitm_capture`
Coordinates an owned `mitmdump` proxy session bound strictly to `--listen-host 127.0.0.1` and `adb reverse tcp:<port> tcp:<port>` to record network traffic into session artifacts.
- **Parameters**: `mitm_op` (`start`, `stop`, `status`), `mitm_port?`, `serial?`, `configure_device_proxy?`, `timeout?` (default 60 seconds, maximum 120), `max_bytes?` (default and maximum 10 MiB).
- **Output**: Proxy status, private flow artifact path, and device proxy restoration result. Startup requires both the owned process's listening log and a live loopback socket. A 200 ms file-size watchdog stops oversized captures; the observed file size may exceed the configured threshold between checks. Stops, timeouts, process exits, and session changes clean up only owned resources; failed device cleanup retains metadata for a later retry.

### `pinning_diagnose`
Analyzes TLS certificate pinning and network security configurations through static config inspection or dynamic Frida diagnostic hooks.
- **Parameters**: `package`, `serial?`, `pinning_mode` (`detect` or `hook_report`), `path?` (required for `detect`), `timeout?`
- **Output**: Confirmed installed hook targets and original TLS check `passed` / `failed` observations without changing return values or swallowing target exceptions. No installed hooks returns an error. A watchdog-ended observation is explicitly marked as limited; all observations remain `pending_verification`.
