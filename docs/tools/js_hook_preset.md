# js_hook_preset

> Static generation of JavaScript hook templates and debugging presets (fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, custom) for authorized browser, Electron, and Node.js reverse-engineering investigations.

## Source
- Entry: `packages/coding-agent/src/tools/js-hook-preset.ts`
- Model-facing prompt: `packages/coding-agent/src/prompts/tools/js-hook-preset.md`

## Inputs

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | `"list" \| "generate"` | Yes | `list` catalogs available presets; `generate` produces a hook template. |
| `preset` | `string` | No | Hook preset: `fetch`, `xhr`, `websocket`, `crypto`, `eval`, `json_parse`, `contextBridge`, or `custom`. |
| `target` | `string` | No | Allowlisted target selector (e.g. `window.myService.login` or `document.cookie`) for custom preset. |
| `format` | `"snippet" \| "userscript" \| "devtools" \| "frida"` | No | Output format: `snippet` (default console IIFE), `userscript` (Tampermonkey), `devtools`, or `frida`. |
| `filter` | `string` | No | Substring filter to selectively log matching endpoints, methods, or payloads. |
| `stack_trace` | `boolean` | No | Whether to capture and log call stacks. Defaults to `true`. |
| `tamper_mode` | `"log" \| "debugger" \| "stub"` | No | Hook mode: `log` (default read-only observer), `debugger` (trigger debugger statement), or `stub` (dummy return). |
| `max_payload_length` | `number >= 1` | No | Maximum characters of argument/response payload to log (default 1024, max 32768). |

## Capabilities & Presets
- **fetch**: Intercepts `window.fetch`, extracts request URL, method, headers, request body, and clones responses to read status, response headers, and body previews.
- **xhr**: Intercepts `XMLHttpRequest.prototype.open`, `setRequestHeader`, and `send`, tracking request lifecycles and logging responses.
- **websocket**: Wraps `window.WebSocket`, tracking connection handshakes, sent frames, and received frames (supporting text, ArrayBuffer, and Blob previews).
- **crypto**: Hooks `window.crypto.subtle` cryptographic primitives (`encrypt`, `decrypt`, `digest`, `sign`, `verify`, `importKey`, `exportKey`) and `getRandomValues`, formatting binary keys and payloads into hex.
- **eval**: Hooks `window.eval`, `Function` constructors, and string-based timer evaluations to surface dynamic unpackers and runtime eval obfuscation.
- **json_parse**: Hooks `JSON.parse` (and `JSON.stringify`) to trace deserialization of authentication tokens, API configs, and response objects.
- **contextBridge**: Hooks Electron `contextBridge.exposeInMainWorld` to discover and trace inter-process communication between renderer and main processes.
- **custom**: Intercepts allowlisted custom dotted properties or methods with function wrappers or getter/setter traps.

## Safety & Allowlisting
- **Templates Only**: Generated scripts are returned as text data. The tool **never executes, evaluates, or injects** target code automatically.
- **Target Allowlisting**: Custom targets must strictly match the regex `^[a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$` and cannot target prototype chains (`__proto__`, `prototype`, `constructor`).
- **Bounded Output**: Generated script templates are bounded in size and string literals are safely escaped using `JSON.stringify`.

## Tool Attributes
- `approval`: `"read"`
- `loadMode`: `"discoverable"`
- `strict`: `true`
