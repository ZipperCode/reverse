Bounded application and protocol security experiment and verification laboratory. Provides controlled, single-action investigation loops across general HTTP capture import (`network_import`), offline request/response case diffing (`network_compare`), and origin-allowlisted network API replay (`network_replay`, none requiring an Android device or `adb`), plus Android component invocation, read-only content provider querying, debug-authorized sandbox data extraction, WebView debugging discovery, bounded proxy capture, and TLS pinning diagnosis.

Actions:
- `preflight`: Explicit-serial and explicit-package laboratory readiness check. Queries device connectivity, system properties (SDK version, ABI, device model), package installation state, debuggable flag, UID, and SELinux enforcement without modifying device state.
- `invoke_component`: Benign component and deep link invocation (`am start`, `am startservice`, `am broadcast`) using fixed argument vectors. Requires explicit serial and package. Strict parameter validation prevents command injection. Never claims vulnerability absent verified impact.
- `query_provider`: Constrained, read-only ContentProvider query (`content query --uri <uri>`) with projection and selection validation. Validates that the provider authority belongs to the target package before execution to prevent unauthorized cross-package queries.
- `extract_sandbox_data`: Debug-authorized application sandbox data extraction via `run-as`. Strictly bounded to private application directories (`shared_prefs`, `databases`, `files`, `cache`) with traversal-safe path checks. Writes extracted archive to session artifacts. Prohibits automatic `su`/root escalation; returns structured `unauthorized` status if target is not debuggable.
- `webview_debug`: Discovers active WebView DevTools sockets scoped to the target application's PIDs, manages bounded local port forwarding (`adb forward`), tracks owned forwarding lifecycles, and cleans up only forwards created by the session.
- `network_replay`: Bounded HTTP/API request replay comparison against mandatory explicit `allowed_origins`. Supports `case_file` (`ReplayCase v1` bound to `workflow_id`, `step_id`, `run_id` — mutually exclusive with `baseline_request` and `request_file`) as well as `baseline_request` / protected `request_file`, `auth_header_env`, `header_env_map`, and binary-safe `body_file`. Prevalidates all variants before network requests, rejects blocked prerequisites or ambiguous `Content-Encoding` representations, preserves wire-order duplicate non-singleton headers while rejecting ambiguous duplicate singleton headers, returns redirects without following them, writes private mode-`0600` response/report artifacts in active runs, and reports three-way `recordedResponse`, live `baselineResult`, and live `variantResults` with separate `raw_equal` and `normalized_equal`, explicit `ignore_json_pointers`, `compare_headers`, and `assertions` (`eq`, `type`, `exists`).
- `network_import`: Offline HTTP transaction import from `.har` (native bounded reader) or `.mitm` (official mitmproxy `FlowReader` via `mitmdump --no-server`) into a private `ReplayCase v1` JSON and mode-`0600` request/response byte body files inside an active `reverse_workspace` analysis run directory (`workflow_id`, `step_id`, `run_id`). Requires mutually exclusive `entry_index` or `flow_id`. Preserves duplicate headers in wire order and exact binary body bytes without echoing body contents or secret values into context. Extracts sensitive headers/cookies into `credential_slots` and records sensitive URL/body values or incomplete/missing request bodies in `blocked_prerequisites` (`replay_ready: false`) without silent mutation.
- `network_compare`: Offline structural and byte-level comparison of two canonical `ReplayCase v1` JSON artifacts (`left_case` vs `right_case`, where independent candidate scripts emit the same `ReplayCase v1` schema with `source.format: "generated"` and explicit input provenance) inside an active `reverse_workspace` analysis run (`workflow_id`, `step_id`, `run_id`). Executes zero network requests and zero generator scripts. Compares requests (method, URL/query, wire-order duplicate headers, raw/JSON bodies) and recorded responses with explicit `ignore_json_pointers`, `compare_headers`, and `assertions`, writing a mode-`0600` report into the run directory without automatically certifying `independent_reproduction`.
- `mitm_capture`: Session-owned loopback `mitmdump` capture with a finite timeout and observed file-size watchdog. Device proxy changes require `configure_device_proxy: true`; restoration checks current ownership, and failed cleanup retains metadata for retry.
- `pinning_diagnose`: TLS pinning diagnosis combining static network-security-config analysis (`detect`) and dynamic Frida instrumentation (`hook_report`). Honest reporting of limitations with no universal-bypass claims.

Parameters:
- `action`: Experiment action (`preflight`, `invoke_component`, `query_provider`, `extract_sandbox_data`, `webview_debug`, `network_replay`, `network_import`, `network_compare`, `mitm_capture`, `pinning_diagnose`).
- `serial`: Target device serial (e.g. `emulator-5554` or `192.168.1.5:5555`). Required for device actions.
- `package`: Target Android application id (e.g. `com.example.app`). Required for device and package actions.
- `component`: Component name for invocation (e.g. `com.example.app/.MainActivity`).
- `component_type`: Component invocation type (`activity`, `service`, `broadcast`; default `activity`).
- `intent_action`: Intent action (e.g. `android.intent.action.VIEW`).
- `intent_category`: Intent category (e.g. `android.intent.category.BROWSABLE`).
- `intent_data`: Intent data URI / deep link.
- `intent_extras`: String key-value extras to supply with intent.
- `uri`: ContentProvider URI (must start with `content://`).
- `projection`: Comma-separated list of column names for provider query.
- `selection`: SQL-like WHERE clause for provider query (validated, no shell metacharacters).
- `sort_order`: SQL-like ORDER BY clause for provider query.
- `subpath`: Relative sandbox path to extract (e.g. `shared_prefs`, `databases/app.db`).
- `max_bytes`: Maximum bytes captured before truncation.
- `webview_op`: WebView operation (`discover`, `forward`, `list_forwards`, `cleanup`).
- `socket_name`: Unix domain socket name for forwarding.
- `forward_port`: Local port to bind for `adb forward`.
- `allowed_origins`: Array of allowed origin URLs permitted for HTTP replay (mandatory for `network_replay`).
- `baseline_request`: Baseline request object `{ url, method, headers, body_file, auth_header_env, header_env_map }`.
- `variant_requests`: Array of request variants `{ id, name?, url?, method?, headers?, body_file?, auth_header_env?, header_env_map? }` (max 10).
- `auth_header_env`: Environment variable name holding bearer/auth token for baseline request.
- `header_env_map`: Key-value map of HTTP header names to environment variable names holding credentials for baseline request (e.g. `{"Cookie": "REPLAY_COOKIE"}`).
- `request_file`: Path to protected request JSON file (regular file, max 1 MiB; mutually exclusive with `case_file`).
- `case_file`: Path to `ReplayCase v1` JSON file for `network_replay` (mutually exclusive with `baseline_request` and `request_file`; requires `workflow_id`, `step_id`, `run_id`).
- `left_case`: Path to left (captured/baseline) canonical `ReplayCase v1` JSON file for `network_compare`.
- `right_case`: Path to right (candidate/comparison) canonical `ReplayCase v1` JSON file for `network_compare` (`source.format` may be `"har"`, `"mitm"`, or `"generated"` with `source` bound to the generator input/script file; if no response was recorded yet on a `"generated"` case, set `recorded_response` to `{ status: 0, status_text: "unrecorded", headers: [], body: { path: null, sha256: null, size_bytes: 0, representation: "none", completeness: "missing" } }`).
- `ignore_json_pointers`: Explicit RFC 6901 JSON Pointers to ignore in normalized JSON comparison (e.g. `["/meta/nonce", "/timestamp"]`; no fields are ignored by default).
- `compare_headers`: Explicit list of HTTP header names to compare across requests/responses.
- `assertions`: Explicit RFC 6901 JSON Pointer assertions `[{ pointer, target?, exists?, type?, eq? }]` without implicit type coercion or array sorting.
- `capture_response_artifacts`: Whether to write full captured responses to private session artifacts (default false).
- `mitm_op`: Proxy operation (`start`, `stop`, `status`).
- `mitm_port`: Proxy listening port (default 8080).
- `configure_device_proxy`: Explicit authorization to modify global device HTTP proxy.
- `pinning_mode`: Pinning analysis mode (`detect` or `hook_report`).
- `capture_path`: Path to HTTP traffic capture file (`.har` or `.mitm`) for `network_import` (must be declared in `inputs` at `reverse_workspace(action: "begin")` or be a run-local intermediate file).
- `capture_format`: Capture format (`har` or `mitm`) for `network_import`.
- `entry_index`: Explicit 0-based entry index to import for `network_import` (mutually exclusive with `flow_id`).
- `flow_id`: Explicit flow/entry identifier to import for `network_import` (mutually exclusive with `entry_index`).
- `workflow_id`: Active reverse workflow identifier (required for `network_import`, `network_compare`, and `case_file` `network_replay`).
- `step_id`: Active workflow step identifier (required for `network_import`, `network_compare`, and `case_file` `network_replay`).
- `run_id`: Active analysis run identifier from `reverse_workspace(action: "begin")` (required for `network_import`, `network_compare`, and `case_file` `network_replay`).
- `workspace_path`: Target workspace directory (defaults to `.reverse` in project root).
- `output_path`: Optional project-relative or absolute output path confined within the active run directory's `dumps/` or `reports/` subdirectory (e.g. `.reverse/analysis/wf_1/runs/run_1/reports/diff.json`).
- `timeout`: Execution timeout in seconds (default 30 for replay, 60 for capture; max 120).

Safety & Security Rules:
- Credential Protection: Inline credentials in tool arguments (Authorization, Cookie, API keys) and URL query tokens are rejected to prevent transcript/TUI exposure. Secrets and payloads must be referenced via `auth_header_env`, `header_env_map`, `body_file`, or protected `request_file`.
- Scope Boundaries: Provider queries verify authority ownership against the target package; WebView discovery is scoped to target package PIDs; HTTP replay enforces exact allowlisted origins and returns redirects without following them.
- Privilege Boundaries: Sandbox extraction strictly uses `run-as`; automatic escalation to `su`/root is prohibited.
- Cleanup Guarantee: Owned port forwards and device proxy settings are tracked and restored safely without clobbering concurrent user settings.

<examples>
```
app_experiment(action: "preflight", serial: "emulator-5554", package: "com.example.app")
app_experiment(action: "invoke_component", serial: "emulator-5554", package: "com.example.app", component: "com.example.app/.DeepLinkActivity", intent_action: "android.intent.action.VIEW", intent_data: "myapp://view/item?id=42")
app_experiment(action: "query_provider", serial: "emulator-5554", package: "com.example.app", uri: "content://com.example.app.provider/users", projection: "_id,username,email")
app_experiment(action: "extract_sandbox_data", serial: "emulator-5554", package: "com.example.app", subpath: "shared_prefs")
app_experiment(action: "webview_debug", serial: "emulator-5554", package: "com.example.app", webview_op: "discover")
app_experiment(action: "network_replay", allowed_origins: ["https://api.example.com"], baseline_request: { url: "https://api.example.com/v1/profile", method: "GET", auth_header_env: "USER_A_TOKEN" }, variant_requests: [{ id: "unauth", name: "No Auth Header" }, { id: "user_b", name: "User B Token", auth_header_env: "USER_B_TOKEN" }])
app_experiment(action: "network_import", workflow_id: "wf_1", step_id: "step_1", run_id: "run_1", capture_path: "./traffic.har", capture_format: "har", entry_index: 0)
app_experiment(action: "network_compare", workflow_id: "wf_1", step_id: "step_1", run_id: "run_1", left_case: ".reverse/analysis/wf_1/runs/run_1/dumps/captured.case.json", right_case: ".reverse/analysis/wf_1/runs/run_1/dumps/candidate.case.json", ignore_json_pointers: ["/nonce", "/timestamp"])
app_experiment(action: "network_replay", workflow_id: "wf_1", step_id: "step_1", run_id: "run_1", allowed_origins: ["https://api.example.com"], case_file: ".reverse/analysis/wf_1/runs/run_1/dumps/captured.case.json", auth_header_env: "REPLAY_AUTHORIZATION", ignore_json_pointers: ["/meta/trace_id"], assertions: [{ pointer: "/code", eq: 0, type: "number" }])
app_experiment(action: "pinning_diagnose", package: "com.example.app", pinning_mode: "detect", path: "./sample.apk")
```
</examples>
