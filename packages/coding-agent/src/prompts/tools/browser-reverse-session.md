Manage interactive browser reverse-engineering sessions: open tabs, inject dynamic hook presets, observe network and console traffic, inspect WebSocket frames, and extract verified reverse-engineering evidence.

Capabilities:
- **Session Lifecycle (`open`, `status`, `close`)**: Open or attach to a browser tab, configure initial URL, track active session lifecycle, register in reverse runtime session registry, and release tab when completed.
- **Dynamic Hook Preset Injection (`inject`)**: Inject instrumented hooks (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, `custom`) into the tab via `tab.addInitScript` and `tab.evaluate`.
- **Structured Multi-Source Capture (`capture`, `events`)**: Pull consolidated event streams including hook-captured payloads from `window.__rea_events__`, console outputs, and HTTP/WebSocket network entries into a bounded ring buffer.
- **Evidence Extraction (`export_evidence`)**: Transform observed runtime facts (e.g. decrypted crypto keys, auth tokens, API endpoints, custom function calls) into standardized evidence ledger records.

Inputs:
- `action`: `"open"`, `"inject"`, `"capture"`, `"events"`, `"export_evidence"`, `"status"`, or `"close"`.
- `session_id`: Optional identifier for the reverse runtime session.
- `tab_name`: Tab identifier (default `"main"`).
- `url`: Target URL to navigate to (required for action `"open"`).
- `preset`: Hook preset to inject (`"fetch"`, `"xhr"`, `"websocket"`, `"crypto"`, `"eval"`, `"json_parse"`, `"contextBridge"`, `"custom"`).
- `target`: Target selector for custom preset (e.g. `"window.myApp.sign"`).
- `filter`: Substring filter to selectively record matching traffic or payloads.
- `stack_trace`: Whether to capture call stack traces with events (default `true`).
- `tamper_mode`: Hook mode: `"log"` (default observer), `"debugger"`, or `"stub"`.
- `max_payload_length`: Maximum characters of argument/response to record (default 1024).
- `clear`: Whether to drain/clear the captured event buffer after reading (for `"capture"` or `"events"`).
- `since_seq`: Filter events strictly greater than this sequence number (supports continuous incremental polling without destructive buffer clearing).
- `limit`: Maximum number of events to return or export (default 50).
- `export_target`: Target file or URL identifier to attach to exported evidence facts.
- `evidence_kind`: Kind of evidence to export (`"fact"` or `"hypothesis"`, default `"fact"`).
- `tags`: Array of categorization tags for exported evidence.

<examples>
```
browser_reverse_session(action: "open", tab_name: "main", url: "https://example.com/login", preset: "fetch")
browser_reverse_session(action: "inject", tab_name: "main", preset: "crypto")
browser_reverse_session(action: "capture", tab_name: "main")
browser_reverse_session(action: "export_evidence", tab_name: "main", tags: ["auth", "crypto"])
browser_reverse_session(action: "status", tab_name: "main")
browser_reverse_session(action: "close", tab_name: "main")
```
</examples>
