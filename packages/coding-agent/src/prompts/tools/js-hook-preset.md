Generate, inject, and capture safe JavaScript hook snippets and debugging presets inspired by reverse-engineering instrumentation workflows (browser DevTools, Tampermonkey, Electron preload, and Frida evaluation).

Capabilities:
- **Preset Catalog (`list`)**: Discovers all supported hook templates with target APIs, configurable parameters, and sample usage.
- **Common API Presets (`generate`, `inject`)**:
  - `fetch`: Intercepts `window.fetch`, extracts URL, method, headers, request payload, and clones responses for status and body inspection.
  - `xhr`: Intercepts `XMLHttpRequest` (`open`, `setRequestHeader`, `send`) and lifecycle events (`readystatechange`, `load`) to log HTTP traffic.
  - `websocket`: Wraps `window.WebSocket`, intercepting connection URLs, protocols, `send()` frames, and `message` event payloads.
  - `crypto`: Intercepts `window.crypto.subtle` operations (`encrypt`, `decrypt`, `digest`, `sign`, `verify`, `importKey`, `exportKey`) and `getRandomValues`, formatting binary buffers into hex.
  - `eval`: Intercepts `window.eval`, `Function` constructors, and string-based `setTimeout`/`setInterval` to reveal obfuscated unpackers and dynamically generated code.
  - `json_parse`: Intercepts `JSON.parse` (and `JSON.stringify`) to trace deserialization of tokens, credentials, and configuration payloads.
  - `contextBridge`: Hooks Electron `contextBridge.exposeInMainWorld` to catalog and trace desktop IPC methods between renderer and main processes.
  - `custom`: Hooks allowlisted dotted property paths (e.g. `window.myService.login` or `document.cookie`) with function wrappers or getter/setter traps.
- **Live Tab Injection (`inject`)**: Injects hook preset directly into a live browser tab via `tab.addInitScript` (for future navigations) and `tab.evaluate` (for current page).
- **Structured Event Capture (`capture`)**: Drains structured events recorded in `window.__rea_events__` along with console logs and network requests from the active tab.
- **Event Buffer Reset (`clear`)**: Clears the in-page hook event ring buffer and console messages.
- **Output Formats**: Supports `snippet` (default console IIFE), `userscript` (Tampermonkey metadata), `devtools` (styled console groups), and `frida` (Chromium/WebView evaluation template).

Inputs:
- `action`: `"list"`, `"generate"`, `"inject"`, `"capture"`, or `"clear"`.
- `preset`: Preset identifier (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, `custom`).
- `target`: Allowlisted dotted identifier for custom preset (e.g. `"window.api.getToken"`).
- `format`: Output format (`"snippet"`, `"userscript"`, `"devtools"`, `"frida"`). Default is `"snippet"`.
- `tab_name`: Browser tab identifier for inject/capture/clear (default `"main"`).
- `url`: Optional URL to open if tab does not exist yet (for action `"inject"`).
- `filter`: Substring filter to selectively log matching endpoints, methods, or payloads.
- `stack_trace`: Whether to capture and log call stacks (default `true`).
- `tamper_mode`: `"log"` (default read-only observer), `"debugger"` (trigger debugger statement), or `"stub"` (dummy return).
- `max_payload_length`: Maximum characters of argument/response payload to log (default 1024).
- `clear`: Whether to drain/clear captured events after reading (for action `"capture"`).
- `export_evidence`: Whether to format captured events as structured evidence records (for action `"capture"`).
- `limit`: Maximum number of captured events to return (default 50).

<examples>
```
js_hook_preset(action: "list")
js_hook_preset(action: "generate", preset: "fetch", filter: "/api/")
js_hook_preset(action: "generate", preset: "crypto", format: "devtools")
js_hook_preset(action: "inject", tab_name: "main", preset: "fetch", filter: "/auth")
js_hook_preset(action: "inject", tab_name: "main", preset: "crypto")
js_hook_preset(action: "capture", tab_name: "main", export_evidence: true)
js_hook_preset(action: "clear", tab_name: "main")
```
</examples>
