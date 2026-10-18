Generate safe, non-executing JavaScript hook snippets and debugging presets inspired by reverse-engineering instrumentation workflows (browser DevTools, Tampermonkey, Electron preload, and Frida evaluation).

Capabilities:
- **Preset Catalog (`list`)**: Discovers all supported hook templates with target APIs, configurable parameters, and sample usage.
- **Common API Presets (`generate`)**:
  - `fetch`: Intercepts `window.fetch`, extracts URL, method, headers, request payload, and clones responses for status and body inspection.
  - `xhr`: Intercepts `XMLHttpRequest` (`open`, `setRequestHeader`, `send`) and lifecycle events (`readystatechange`, `load`) to log HTTP traffic.
  - `websocket`: Wraps `window.WebSocket`, intercepting connection URLs, protocols, `send()` frames, and `message` event payloads.
  - `crypto`: Intercepts `window.crypto.subtle` operations (`encrypt`, `decrypt`, `digest`, `sign`, `verify`, `importKey`, `exportKey`) and `getRandomValues`, formatting binary buffers into hex.
  - `eval`: Intercepts `window.eval`, `Function` constructors, and string-based `setTimeout`/`setInterval` to reveal obfuscated unpackers and dynamically generated code.
  - `json_parse`: Intercepts `JSON.parse` (and `JSON.stringify`) to trace deserialization of tokens, credentials, and configuration payloads.
  - `contextBridge`: Hooks Electron `contextBridge.exposeInMainWorld` to catalog and trace desktop IPC methods between renderer and main processes.
  - `custom`: Hooks allowlisted dotted property paths (e.g. `window.myService.login` or `document.cookie`) with function wrappers or getter/setter traps.
- **Output Formats**: Supports `snippet` (default console IIFE), `userscript` (Tampermonkey metadata), `devtools` (styled console groups), and `frida` (Chromium/WebView evaluation template).
- **Safety**: Generated templates are purely text data and are NEVER executed or injected automatically. Custom target selectors must match an allowlisted dotted identifier path.

Inputs:
- `action`: `"list"` to view presets or `"generate"` to generate a hook template.
- `preset`: Preset identifier (`fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, `custom`).
- `target`: Allowlisted dotted identifier for custom preset (e.g. `"window.api.getToken"`).
- `format`: Output format (`"snippet"`, `"userscript"`, `"devtools"`, `"frida"`). Default is `"snippet"`.
- `filter`: Substring filter to selectively log matching endpoints, methods, or payloads.
- `stack_trace`: Whether to capture and log call stacks (default `true`).
- `tamper_mode`: `"log"` (default read-only observer), `"debugger"` (trigger debugger statement), or `"stub"` (dummy return).
- `max_payload_length`: Maximum characters of argument/response payload to log (default 1024).

<examples>
```
js_hook_preset(action: "list")
js_hook_preset(action: "generate", preset: "fetch", filter: "/api/")
js_hook_preset(action: "generate", preset: "crypto", format: "devtools")
js_hook_preset(action: "generate", preset: "xhr", tamper_mode: "debugger")
js_hook_preset(action: "generate", preset: "contextBridge")
js_hook_preset(action: "generate", preset: "custom", target: "window.app.cryptoSign")
```
</examples>
