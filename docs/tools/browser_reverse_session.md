# browser_reverse_session

> Interactive browser reverse-engineering session management: live tab lifecycle, hook preset injection, network/console/WebSocket capture, and bounded evidence extraction.

## Source
- Entry: `packages/coding-agent/src/tools/browser-reverse-session.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/browser-reverse-session.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"open" \| "inject" \| "capture" \| "events" \| "export_evidence" \| "status" \| "close"` | Yes | Session action to execute. |
| `session_id` | `string` | No | Identifier for the reverse session (auto-assigned if omitted). |
| `tab_name` | `string` | No | Target browser tab name (default `"main"`). |
| `url` | `string` | No | Target URL to open (required for `action: "open"`). |
| `preset` | `string` | No | Hook preset: `fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, or `custom`. |
| `target` | `string` | No | Allowlisted target selector for custom preset (e.g. `window.api.login`). |
| `filter` | `string` | No | Substring filter to selectively record matching URLs, methods, or payloads. |
| `stack_trace` | `boolean` | No | Whether to record call stack traces with events. Defaults to `true`. |
| `tamper_mode` | `"log" \| "debugger" \| "stub"` | No | Hook mode: `log` (default observer), `debugger`, or `stub`. |
| `max_payload_length` | `number >= 1` | No | Maximum characters of argument/response payload to record. |
| `clear` | `boolean` | No | Whether to drain/clear captured events from the tab buffer. |
| `since_seq` | `number` | No | Monotonic sequence cutoff: filter events with sequence strictly greater than this value (for non-destructive polling). |
| `limit` | `number >= 1` | No | Maximum events to return or export (default 50, max 500). |
| `export_target` | `string` | No | Target file/URL recorded in exported evidence ledger records. |
| `evidence_kind` | `"fact" \| "hypothesis"` | No | Kind of evidence record to emit (default `"fact"`). |
| `tags` | `string[]` | No | Categorization tags attached to exported evidence. |

## Capabilities
- **Tab Lifecycle**: Opens or attaches to a Chromium browser tab, managing headless display, allowed domains, and registration in the `reverse_runtime_session` registry under kind `"browser"`.
- **Instrumentation**: Injects hook presets (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, `custom`) using `tab.addInitScript` (document start across navigations) and `tab.evaluate` (immediate execution).
- **Consolidated Event Stream**: Pulls together structured events from `window.__rea_events__`, console logs via `tab.console()`, and network traffic via `tab.requests()`.
- **Evidence Ledger Export**: Converts captured runtime events directly into standardized evidence records suitable for the `evidence` tool and the 6-stage scientific reverse engineering workflow.

## Tool Attributes
- `approval`: Dynamic decision (`"read"` for query actions `status`, `events`, `capture`, `export_evidence`; `"write"` for mutating actions `open`, `inject`, `close`)
- `loadMode`: `"discoverable"`
- `strict`: `true`
