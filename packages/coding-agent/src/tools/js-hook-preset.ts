import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { type } from "@rva/omptype";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { prompt } from "@rva/utils";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";
import jsHookPresetDescription from "../prompts/tools/js-hook-preset.md" with { type: "text" };

export const HOOK_PRESETS = [
	"fetch",
	"xhr",
	"websocket",
	"crypto",
	"eval",
	"json_parse",
	"contextBridge",
	"custom",
] as const;

export type HookPresetKind = (typeof HOOK_PRESETS)[number];

export const HOOK_FORMATS = ["snippet", "userscript", "devtools", "frida"] as const;
export type HookFormatKind = (typeof HOOK_FORMATS)[number];

export const HOOK_TAMPER_MODES = ["log", "debugger", "stub"] as const;
export type HookTamperMode = (typeof HOOK_TAMPER_MODES)[number];

const SAFE_IDENTIFIER_PATH_REGEX = /^[a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$/;
const DISALLOWED_TARGET_SEGMENTS: Record<string, true> = {
	__proto__: true,
	prototype: true,
	constructor: true,
};

const jsHookPresetSchema = type({
	action: type.enumerated("list", "generate"),
	"preset?": type.enumerated(...HOOK_PRESETS).describe(
		"Hook preset: fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, or custom",
	),
	"target?": type("string").describe(
		"Allowlisted target selector (e.g. 'window.myService.login' or 'document.cookie') for custom preset",
	),
	"format?": type.enumerated(...HOOK_FORMATS).describe(
		"Output script format: snippet (default IIFE), userscript (Tampermonkey), devtools (Console snippet), or frida",
	),
	"filter?": type("string").describe("Substring filter to log only matching URLs, methods, or payloads"),
	"stack_trace?": type("boolean").describe("Whether to capture and log call stack traces (default true)"),
	"tamper_mode?": type.enumerated(...HOOK_TAMPER_MODES).describe(
		"Hook mode: 'log' (read-only observer, default), 'debugger' (trigger debugger statement), or 'stub' (dummy return)",
	),
	"max_payload_length?": type("number.integer >= 1").describe(
		"Maximum characters of argument/response payload to log (default 1024, max 32768)",
	),
});

export type JsHookPresetParams = typeof jsHookPresetSchema.infer;

export interface PresetCatalogEntry {
	preset: HookPresetKind;
	name: string;
	description: string;
	targetApis: string[];
	configurableOptions: string[];
	example: string;
}

export interface JsHookPresetDetails {
	action: "list" | "generate";
	preset?: HookPresetKind;
	target?: string;
	format?: HookFormatKind;
	script?: string;
	scriptLength?: number;
	options?: {
		filter?: string;
		stackTrace?: boolean;
		tamperMode?: HookTamperMode;
		maxPayloadLength?: number;
	};
	catalog?: PresetCatalogEntry[];
	isTemplateOnly: boolean;
	executed: boolean;
	safetyNote: string;
}

const PRESET_CATALOG: PresetCatalogEntry[] = [
	{
		preset: "fetch",
		name: "Fetch API Interceptor",
		description:
			"Intercepts window.fetch calls; captures URL, HTTP method, headers, request body, and clones response to inspect status and payload.",
		targetApis: ["window.fetch"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "fetch", filter: "/api/v1/")',
	},
	{
		preset: "xhr",
		name: "XMLHttpRequest Interceptor",
		description:
			"Intercepts XMLHttpRequest.prototype.open, setRequestHeader, and send; tracks lifecycle and logs request details and response text.",
		targetApis: ["XMLHttpRequest.prototype.open", "setRequestHeader", "send"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "xhr", tamper_mode: "debugger")',
	},
	{
		preset: "websocket",
		name: "WebSocket Frame Monitor",
		description:
			"Wraps window.WebSocket constructor and hooks send() and message events to monitor duplex framed network communication.",
		targetApis: ["window.WebSocket", "WebSocket.prototype.send", "WebSocket.prototype.addEventListener"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "websocket")',
	},
	{
		preset: "crypto",
		name: "Web Crypto Subsystem Monitor",
		description:
			"Intercepts window.crypto.subtle (encrypt, decrypt, digest, importKey, exportKey, sign, verify) and getRandomValues, formatting binary buffers into hex.",
		targetApis: [
			"crypto.subtle.encrypt",
			"crypto.subtle.decrypt",
			"crypto.subtle.digest",
			"crypto.subtle.importKey",
			"crypto.subtle.exportKey",
			"crypto.subtle.sign",
			"crypto.subtle.verify",
			"crypto.getRandomValues",
		],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "crypto")',
	},
	{
		preset: "eval",
		name: "Dynamic Code Evaluation Monitor",
		description:
			"Intercepts window.eval, Function constructor, and string-based setTimeout/setInterval to detect dynamic unpackers and runtime code generation.",
		targetApis: ["window.eval", "window.Function", "setTimeout (string code)", "setInterval (string code)"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "eval", tamper_mode: "debugger")',
	},
	{
		preset: "json_parse",
		name: "JSON Serialization Observer",
		description:
			"Intercepts JSON.parse (and JSON.stringify); logs deserialized inputs and stack traces to locate decoding of sensitive tokens and responses.",
		targetApis: ["JSON.parse", "JSON.stringify"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "json_parse", filter: "token")',
	},
	{
		preset: "contextBridge",
		name: "Electron ContextBridge & IPC Monitor",
		description:
			"Hooks Electron contextBridge.exposeInMainWorld to discover and wrap all exposed desktop IPC bridge methods between renderer and main process.",
		targetApis: ["contextBridge.exposeInMainWorld", "window[apiKey]"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "contextBridge")',
	},
	{
		preset: "custom",
		name: "Allowlisted Custom Target Selector Hook",
		description:
			"Generates a wrapper around an allowlisted dotted identifier (e.g. 'window.App.sign' or 'document.cookie') with function or property interception.",
		targetApis: ["User specified dotted property path"],
		configurableOptions: ["target", "filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "custom", target: "window.api.generateSignature")',
	},
];

export function validateCustomTargetSelector(target: string): void {
	const trimmed = target.trim();
	if (!trimmed) {
		throw new ToolError("target is required when preset is 'custom'");
	}
	if (trimmed.length > 128) {
		throw new ToolError(`target selector is too long (${trimmed.length} chars, max 128)`);
	}
	if (!SAFE_IDENTIFIER_PATH_REGEX.test(trimmed)) {
		throw new ToolError(
			`Invalid target selector "${trimmed}". Target must be an allowlisted dotted identifier matching ^[a-zA-Z_$][a-zA-Z0-9_$]*(?:\\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$ (e.g. 'window.myService.login') without operators, brackets, quotes, or expressions.`,
		);
	}
	const segments = trimmed.split(".");
	for (const seg of segments) {
		if (DISALLOWED_TARGET_SEGMENTS[seg]) {
			throw new ToolError(
				`Disallowed property accessor "${seg}" in target "${trimmed}". Prototype and constructor chains cannot be targeted directly.`,
			);
		}
	}
}

function buildHeaderBanner(preset: string, format: string, target?: string): string {
	const lines = [
		"// ============================================================================",
		`// REA JS HOOK PRESET: ${preset.toUpperCase()}${target ? ` (${target})` : ""}`,
		`// Format: ${format}`,
		"// Statically generated template. THIS SCRIPT HAS NOT BEEN EXECUTED OR INJECTED.",
		"// To use: Paste into browser DevTools Console, Tampermonkey, or Electron preload.",
		"// ============================================================================",
	];
	return lines.join("\n");
}

function buildUserscriptHeader(preset: string, target?: string): string {
	return [
		"// ==UserScript==",
		`// @name         REA JS Hook - ${preset}${target ? ` (${target})` : ""}`,
		"// @namespace    https://rev.agent/hooks",
		"// @version      1.0.0",
		`// @description  Statically generated hook preset for ${preset}`,
		"// @match        *://*/*",
		"// @run-at       document-start",
		"// @grant        none",
		"// ==/UserScript==",
		"",
	].join("\n");
}

function generateFetchHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  if (typeof window === "undefined" || !window.fetch) {
    console.warn("[REA HOOK] window.fetch is not available in this environment.");
    return;
  }
  const _origFetch = window.fetch;
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  window.fetch = async function(...args) {
    const input = args[0];
    const init = args[1] || {};
    const url = typeof input === "string" ? input : (input && input.url ? input.url : String(input));
    const method = (init.method || (input && input.method) || "GET").toUpperCase();

    if (_filter && !url.includes(_filter) && !method.includes(_filter)) {
      return _origFetch.apply(this, args);
    }

    const reqId = Math.random().toString(36).slice(2, 8);
    const startTime = performance.now();
    let bodyPreview = "[no body]";
    try {
      if (init.body) {
        bodyPreview = typeof init.body === "string" ? init.body : Object.prototype.toString.call(init.body);
        if (bodyPreview.length > _maxLen) bodyPreview = bodyPreview.slice(0, _maxLen) + "...[truncated]";
      }
    } catch {}

    console.groupCollapsed(\`%c[FETCH REQ #\${reqId}]%c \${method} \${url}\`, "color:#3b82f6;font-weight:bold;", "color:inherit;");
    console.log("URL:", url);
    console.log("Method:", method);
    console.log("Headers:", init.headers || "[none]");
    console.log("Body:", bodyPreview);
    if (_includeStack) console.log("Call Stack:", new Error().stack);
    console.groupEnd();

    if (_mode === "debugger") {
      debugger;
    }

    try {
      const response = await _origFetch.apply(this, args);
      const duration = (performance.now() - startTime).toFixed(1);
      const clone = response.clone();
      clone.text().then(text => {
        let resPreview = text;
        if (resPreview.length > _maxLen) resPreview = resPreview.slice(0, _maxLen) + "...[truncated]";
        console.groupCollapsed(\`%c[FETCH RES #\${reqId}]%c \${response.status} \${response.statusText} (\${duration}ms) - \${url}\`, "color:#10b981;font-weight:bold;", "color:inherit;");
        console.log("Status:", response.status, response.statusText);
        console.log("Response URL:", response.url);
        console.log("Response Preview:", resPreview);
        console.groupEnd();
      }).catch(e => {
        console.warn(\`[FETCH RES #\${reqId}] Failed to clone text:\`, e);
      });
      return response;
    } catch (err) {
      console.error(\`%c[FETCH ERR #\${reqId}]%c \${method} \${url}\`, "color:#ef4444;font-weight:bold;", "color:inherit;", err);
      throw err;
    }
  };
  console.log("%c[REA HOOK]%c fetch hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateXhrHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  if (typeof XMLHttpRequest === "undefined") {
    console.warn("[REA HOOK] XMLHttpRequest is not available in this environment.");
    return;
  }
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  const _origOpen = XMLHttpRequest.prototype.open;
  const _origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  const _origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._rea_hook = {
      id: Math.random().toString(36).slice(2, 8),
      method: String(method).toUpperCase(),
      url: String(url),
      headers: {},
      startTime: 0,
    };
    return _origOpen.call(this, method, url, ...rest);
  };

  XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
    if (this._rea_hook && this._rea_hook.headers) {
      this._rea_hook.headers[header] = value;
    }
    return _origSetRequestHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    const hook = this._rea_hook;
    if (hook) {
      const shouldLog = !_filter || hook.url.includes(_filter) || hook.method.includes(_filter);
      if (shouldLog) {
        hook.startTime = performance.now();
        let bodyPreview = "[no body]";
        if (body != null) {
          bodyPreview = typeof body === "string" ? body : Object.prototype.toString.call(body);
          if (bodyPreview.length > _maxLen) bodyPreview = bodyPreview.slice(0, _maxLen) + "...[truncated]";
        }
        console.groupCollapsed(\`%c[XHR REQ #\${hook.id}]%c \${hook.method} \${hook.url}\`, "color:#3b82f6;font-weight:bold;", "color:inherit;");
        console.log("URL:", hook.url);
        console.log("Method:", hook.method);
        console.log("Headers:", hook.headers);
        console.log("Body:", bodyPreview);
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }

        this.addEventListener("load", function() {
          const duration = (performance.now() - hook.startTime).toFixed(1);
          let resPreview = "";
          try {
            resPreview = typeof this.responseText === "string" ? this.responseText : String(this.response);
            if (resPreview.length > _maxLen) resPreview = resPreview.slice(0, _maxLen) + "...[truncated]";
          } catch {}
          console.groupCollapsed(\`%c[XHR RES #\${hook.id}]%c \${this.status} (\${duration}ms) - \${hook.url}\`, "color:#10b981;font-weight:bold;", "color:inherit;");
          console.log("Status:", this.status, this.statusText);
          console.log("Response URL:", this.responseURL);
          console.log("Response Preview:", resPreview);
          console.groupEnd();
        });
      }
    }
    return _origSend.apply(this, arguments);
  };
  console.log("%c[REA HOOK]%c XHR hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateWebSocketHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  if (typeof WebSocket === "undefined") {
    console.warn("[REA HOOK] WebSocket is not available in this environment.");
    return;
  }
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};
  const _OrigWebSocket = window.WebSocket;

  window.WebSocket = function(url, protocols) {
    const ws = protocols !== undefined ? new _OrigWebSocket(url, protocols) : new _OrigWebSocket(url);
    const wsId = Math.random().toString(36).slice(2, 8);
    const wsUrl = String(url);
    const shouldTrack = !_filter || wsUrl.includes(_filter);

    if (shouldTrack) {
      console.groupCollapsed(\`%c[WS OPEN #\${wsId}]%c \${wsUrl}\`, "color:#8b5cf6;font-weight:bold;", "color:inherit;");
      console.log("URL:", wsUrl);
      console.log("Protocols:", protocols || "[none]");
      if (_includeStack) console.log("Call Stack:", new Error().stack);
      console.groupEnd();

      const origSend = ws.send;
      ws.send = function(data) {
        let preview = "[unknown data]";
        if (typeof data === "string") {
          preview = data.length > _maxLen ? data.slice(0, _maxLen) + "...[truncated]" : data;
        } else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
          preview = \`[Binary: \${data.byteLength} bytes]\`;
        } else if (typeof Blob !== "undefined" && data instanceof Blob) {
          preview = \`[Blob: \${data.size} bytes, type=\${data.type}]\`;
        }
        console.groupCollapsed(\`%c[WS SEND #\${wsId}]%c \${preview.slice(0, 80)}\`, "color:#3b82f6;font-weight:bold;", "color:inherit;");
        console.log("Data:", preview);
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }
        return origSend.apply(this, arguments);
      };

      ws.addEventListener("message", function(event) {
        let preview = "[unknown data]";
        if (typeof event.data === "string") {
          preview = event.data.length > _maxLen ? event.data.slice(0, _maxLen) + "...[truncated]" : event.data;
        } else if (event.data instanceof ArrayBuffer || ArrayBuffer.isView(event.data)) {
          preview = \`[Binary: \${event.data.byteLength} bytes]\`;
        } else if (typeof Blob !== "undefined" && event.data instanceof Blob) {
          preview = \`[Blob: \${event.data.size} bytes]\`;
        }
        console.groupCollapsed(\`%c[WS RECV #\${wsId}]%c \${preview.slice(0, 80)}\`, "color:#10b981;font-weight:bold;", "color:inherit;");
        console.log("Data:", preview);
        console.groupEnd();
      });
    }
    return ws;
  };
  window.WebSocket.prototype = _OrigWebSocket.prototype;
  console.log("%c[REA HOOK]%c WebSocket hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateCryptoHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    console.warn("[REA HOOK] crypto.subtle is not available in this environment.");
    return;
  }
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  function toHex(buffer) {
    if (!buffer) return "[null]";
    const view = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : (ArrayBuffer.isView(buffer) ? new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength) : null);
    if (!view) return String(buffer);
    const limit = Math.min(view.length, Math.floor(_maxLen / 2));
    let hex = "";
    for (let i = 0; i < limit; i++) hex += view[i].toString(16).padStart(2, "0");
    if (view.length > limit) hex += "...[+" + (view.length - limit) + " bytes]";
    return hex;
  }

  const methods = ["encrypt", "decrypt", "digest", "importKey", "exportKey", "sign", "verify"];
  for (const method of methods) {
    if (typeof crypto.subtle[method] !== "function") continue;
    const origMethod = crypto.subtle[method];
    crypto.subtle[method] = async function(...args) {
      const callId = Math.random().toString(36).slice(2, 8);
      const algo = args[0] ? (typeof args[0] === "string" ? args[0] : (args[0].name || JSON.stringify(args[0]))) : "[unknown]";
      const shouldLog = !_filter || String(algo).includes(_filter) || method.includes(_filter);

      if (shouldLog) {
        console.groupCollapsed(\`%c[CRYPTO \${method.toUpperCase()} #\${callId}]%c \${algo}\`, "color:#ec4899;font-weight:bold;", "color:inherit;");
        console.log("Method:", method);
        console.log("Algorithm:", args[0]);
        if (args[1]) console.log("Key / Arg1:", args[1]);
        if (args[2]) console.log("Data Hex / Arg2:", toHex(args[2]));
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }
      }

      try {
        const result = await origMethod.apply(this, args);
        if (shouldLog) {
          console.groupCollapsed(\`%c[CRYPTO \${method.toUpperCase()} RES #\${callId}]%c Result\`, "color:#10b981;font-weight:bold;", "color:inherit;");
          console.log("Result Hex/Summary:", toHex(result));
          console.groupEnd();
        }
        return result;
      } catch (err) {
        if (shouldLog) {
          console.error(\`[CRYPTO \${method.toUpperCase()} ERR #\${callId}]\`, err);
        }
        throw err;
      }
    };
  }

  if (typeof crypto.getRandomValues === "function") {
    const origGetRandomValues = crypto.getRandomValues.bind(crypto);
    crypto.getRandomValues = function(array) {
      const res = origGetRandomValues(array);
      if (!_filter || "getRandomValues".includes(_filter)) {
        console.log(\`%c[CRYPTO getRandomValues]%c \${array.byteLength} bytes -> \${toHex(array)}\`, "color:#ec4899;font-weight:bold;", "color:inherit;");
      }
      return res;
    };
  }

  console.log("%c[REA HOOK]%c crypto.subtle hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateEvalHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  if (typeof window !== "undefined" && window.eval) {
    const _origEval = window.eval;
    window.eval = function(code) {
      const codeStr = String(code);
      if (!_filter || codeStr.includes(_filter)) {
        const preview = codeStr.length > _maxLen ? codeStr.slice(0, _maxLen) + "...[truncated]" : codeStr;
        console.groupCollapsed(\`%c[EVAL HOOK]%c \${preview.slice(0, 60)}\`, "color:#f59e0b;font-weight:bold;", "color:inherit;");
        console.log("Code:", preview);
        console.log("Code Length:", codeStr.length);
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }
      }
      return _origEval.apply(this, arguments);
    };
  }

  const _OrigFunction = Function;
  const FunctionHook = function(...args) {
    const body = args.length > 0 ? String(args[args.length - 1]) : "";
    if (!_filter || body.includes(_filter)) {
      const preview = body.length > _maxLen ? body.slice(0, _maxLen) + "...[truncated]" : body;
      console.groupCollapsed(\`%c[FUNCTION CONSTRUCTOR HOOK]%c \${preview.slice(0, 60)}\`, "color:#f59e0b;font-weight:bold;", "color:inherit;");
      console.log("Args:", args.slice(0, -1));
      console.log("Body:", preview);
      if (_includeStack) console.log("Call Stack:", new Error().stack);
      console.groupEnd();

      if (_mode === "debugger") {
        debugger;
      }
    }
    return _OrigFunction.apply(this, args);
  };
  FunctionHook.prototype = _OrigFunction.prototype;
  window.Function = FunctionHook;

  console.log("%c[REA HOOK]%c eval & Function hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateJsonParseHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  const _origParse = JSON.parse;
  JSON.parse = function(text, reviver) {
    const textStr = String(text);
    if (!_filter || textStr.includes(_filter)) {
      const preview = textStr.length > _maxLen ? textStr.slice(0, _maxLen) + "...[truncated]" : textStr;
      console.groupCollapsed(\`%c[JSON.parse HOOK]%c \${preview.slice(0, 60)}\`, "color:#06b6d4;font-weight:bold;", "color:inherit;");
      console.log("Input:", preview);
      console.log("Length:", textStr.length);
      if (_includeStack) console.log("Call Stack:", new Error().stack);
      console.groupEnd();

      if (_mode === "debugger") {
        debugger;
      }
    }
    return _origParse.apply(this, arguments);
  };

  console.log("%c[REA HOOK]%c JSON.parse hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
})();`;
}

function generateContextBridgeHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  function truncate(val) {
    try {
      const s = typeof val === "string" ? val : JSON.stringify(val);
      return s && s.length > _maxLen ? s.slice(0, _maxLen) + "...[truncated]" : s;
    } catch {}
      return String(val);
    }
  }

  function wrapObject(apiKey, target, path = "") {
    if (!target || typeof target !== "object") return target;
    const wrapped = {};
    for (const key of Object.keys(target)) {
      const val = target[key];
      const memberPath = path ? \`\${path}.\${key}\` : key;
      if (typeof val === "function") {
        wrapped[key] = function(...args) {
          const callId = Math.random().toString(36).slice(2, 8);
          const fullName = \`\${apiKey}.\${memberPath}\`;
          const shouldLog = !_filter || fullName.includes(_filter) || JSON.stringify(args).includes(_filter);
          if (shouldLog) {
            console.groupCollapsed(\`%c[ELECTRON IPC #\${callId}]%c \${fullName}()\`, "color:#6366f1;font-weight:bold;", "color:inherit;");
            console.log("API:", fullName);
            console.log("Arguments:", args.map(truncate));
            if (_includeStack) console.log("Call Stack:", new Error().stack);
            console.groupEnd();

            if (_mode === "debugger") {
              debugger;
            }
          }
          const res = val.apply(this, args);
          if (res && typeof res.then === "function") {
            res.then(ret => {
              if (shouldLog) {
                console.groupCollapsed(\`%c[ELECTRON IPC RES #\${callId}]%c \${fullName} -> Resolved\`, "color:#10b981;font-weight:bold;", "color:inherit;");
                console.log("Return Value:", truncate(ret));
                console.groupEnd();
              }
            }).catch(err => {
              if (shouldLog) {
                console.error(\`[ELECTRON IPC ERR #\${callId}] \${fullName}\`, err);
              }
            });
          }
          return res;
        };
      } else if (val && typeof val === "object") {
        wrapped[key] = wrapObject(apiKey, val, memberPath);
      } else {
        wrapped[key] = val;
      }
    }
    return wrapped;
  }

  try {
    const electron = typeof require !== "undefined" ? require("electron") : null;
    const bridge = electron ? electron.contextBridge : (typeof contextBridge !== "undefined" ? contextBridge : null);
    if (bridge && typeof bridge.exposeInMainWorld === "function") {
      const origExpose = bridge.exposeInMainWorld.bind(bridge);
      bridge.exposeInMainWorld = function(apiKey, api) {
        console.log(\`%c[ELECTRON PRELOAD]%c Exposing \${apiKey} to Main World (Hooked)\`, "color:#8b5cf6;font-weight:bold;", "color:inherit;");
        const wrappedApi = wrapObject(apiKey, api);
        return origExpose(apiKey, wrappedApi);
      };
      console.log("%c[REA HOOK]%c Electron contextBridge.exposeInMainWorld hooked successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
    } else {
      console.warn("[REA HOOK] contextBridge not directly accessible. If in Renderer, inspect window APIs directly.");
    }
  } catch (err) {
    console.warn("[REA HOOK] Electron contextBridge setup notice:", err);
  }
})();`;
}

function generateCustomHook(
	target: string,
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	validateCustomTargetSelector(target);
	const targetJson = JSON.stringify(target);
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);

	return `(() => {
  const _targetPath = ${targetJson};
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};

  function truncate(val) {
    try {
      const s = typeof val === "string" ? val : JSON.stringify(val);
      return s && s.length > _maxLen ? s.slice(0, _maxLen) + "...[truncated]" : s;
    } catch {}
      return String(val);
    }
  }

  const parts = _targetPath.split(".");
  let parent = typeof window !== "undefined" ? window : globalThis;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (parent[part] == null) {
      console.warn(\`[REA HOOK] Target path segment "\${part}" not found while navigating \${_targetPath}\`);
      return;
    }
    parent = parent[part];
  }

  const propName = parts[parts.length - 1];
  const original = parent[propName];

  if (typeof original === "function") {
    parent[propName] = function(...args) {
      const callId = Math.random().toString(36).slice(2, 8);
      const shouldLog = !_filter || _targetPath.includes(_filter) || JSON.stringify(args).includes(_filter);
      if (shouldLog) {
        console.groupCollapsed(\`%c[CUSTOM HOOK #\${callId}]%c \${_targetPath}()\`, "color:#f97316;font-weight:bold;", "color:inherit;");
        console.log("Target:", _targetPath);
        console.log("This:", this);
        console.log("Arguments:", args.map(truncate));
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }
      }

      if (_mode === "stub") {
        console.warn(\`[CUSTOM HOOK #\${callId}] Stub mode active; returning undefined.\`);
        return undefined;
      }

      const res = original.apply(this, args);
      if (res && typeof res.then === "function") {
        res.then(ret => {
          if (shouldLog) {
            console.groupCollapsed(\`%c[CUSTOM HOOK RES #\${callId}]%c \${_targetPath} -> Resolved\`, "color:#10b981;font-weight:bold;", "color:inherit;");
            console.log("Return:", truncate(ret));
            console.groupEnd();
          }
        }).catch(err => {
          if (shouldLog) {
            console.error(\`[CUSTOM HOOK ERR #\${callId}] \${_targetPath}\`, err);
          }
        });
      } else if (shouldLog) {
        console.log(\`[CUSTOM HOOK RES #\${callId}] Return:\`, truncate(res));
      }
      return res;
    };
    console.log(\`%c[REA HOOK]%c Custom method \${_targetPath} hooked successfully.\`, "color:#6366f1;font-weight:bold;", "color:inherit;");
  } else {
    let currentVal = original;
    Object.defineProperty(parent, propName, {
      configurable: true,
      enumerable: true,
      get() {
        if (!_filter || _targetPath.includes(_filter)) {
          console.log(\`%c[CUSTOM GET]%c \${_targetPath} ->\`, "color:#f97316;font-weight:bold;", "color:inherit;", truncate(currentVal));
        }
        return currentVal;
      },
      set(newVal) {
        if (!_filter || _targetPath.includes(_filter)) {
          console.log(\`%c[CUSTOM SET]%c \${_targetPath} =\`, "color:#f97316;font-weight:bold;", "color:inherit;", truncate(newVal));
          if (_includeStack) console.log("Call Stack:", new Error().stack);
          if (_mode === "debugger") debugger;
        }
        currentVal = newVal;
      },
    });
    console.log(\`%c[REA HOOK]%c Custom property \${_targetPath} accessor hooked successfully.\`, "color:#6366f1;font-weight:bold;", "color:inherit;");
  }
})();`;
}

function formatScript(body: string, preset: string, format: HookFormatKind, target?: string): string {
	const header = buildHeaderBanner(preset, format, target);
	switch (format) {
		case "userscript": {
			const userscriptMeta = buildUserscriptHeader(preset, target);
			return `${userscriptMeta}${header}\n\n${body}`;
		}
		case "frida": {
			const fridaWrapper = [
				header,
				"// Target: Chromium / WebView / Node.js evaluate context via CDP or Frida Java.perform",
				"(() => {",
				"  const script = `" + body.replace(/`/g, "\\`").replace(/\${/g, "\\${") + "`;",
				"  if (typeof Java !== 'undefined' && Java.available) {",
				"    console.log('[Frida] Note: Inject script string into WebView using evaluateJavascript()');",
				"  } else {",
				"    console.log('[Frida] Injecting hook script template into current JS context...');",
				"  }",
				"  // Standalone template payload below:",
				"})();",
				"",
				body,
			].join("\n");
			return fridaWrapper;
		}
		case "devtools":
		case "snippet":
		default:
			return `${header}\n\n${body}`;
	}
}

export class JsHookPresetTool
	implements AgentTool<typeof jsHookPresetSchema, JsHookPresetDetails>
{
	readonly name = "js_hook_preset";
	readonly approval: ToolTier = "read";
	readonly label = "JS Hook Preset";
	readonly summary =
		"Generate safe JavaScript hook snippets and debugging presets (fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, custom)";
	readonly description: string;
	readonly parameters = jsHookPresetSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(private readonly session: ToolSession) {
		this.description = prompt.render(jsHookPresetDescription);
	}

	async execute(
		_toolCallId: string,
		params: JsHookPresetParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<JsHookPresetDetails>> {
		throwIfAborted(signal);

		const action = params.action;
		if (action === "list") {
			const lines = [
				"# JavaScript Hook Presets Catalog",
				"",
				"Statically generated runtime inspection and tracing templates for browsers, Electron, and Node.js.",
				"All scripts are returned as safe templates and are NEVER executed automatically.",
				"",
			];
			for (const item of PRESET_CATALOG) {
				lines.push(`### \`${item.preset}\`: ${item.name}`);
				lines.push(`- **Description**: ${item.description}`);
				lines.push(`- **Target APIs**: \`${item.targetApis.join("`, `")}\``);
				lines.push(`- **Configurable Options**: \`${item.configurableOptions.join("`, `")}\``);
				lines.push(`- **Example**: \`${item.example}\``);
				lines.push("");
			}
			return {
				content: [{ type: "text", text: lines.join("\n").trim() }],
				details: {
					action: "list",
					catalog: PRESET_CATALOG,
					isTemplateOnly: true,
					executed: false,
					safetyNote: "Templates are statically generated and have not been executed.",
				},
			};
		}

		// Action: generate
		const preset = (params.preset || (params.target ? "custom" : "fetch")) as HookPresetKind;
		const format: HookFormatKind = params.format || "snippet";
		const filter = params.filter ? params.filter.trim() : null;
		const stackTrace = params.stack_trace !== false;
		const tamperMode: HookTamperMode = params.tamper_mode || "log";
		const maxLen = Math.min(32768, Math.max(64, Math.floor(params.max_payload_length ?? 1024)));
		const target = params.target ? params.target.trim() : undefined;

		let rawScript = "";
		switch (preset) {
			case "fetch":
				rawScript = generateFetchHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "xhr":
				rawScript = generateXhrHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "websocket":
				rawScript = generateWebSocketHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "crypto":
				rawScript = generateCryptoHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "eval":
				rawScript = generateEvalHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "json_parse":
				rawScript = generateJsonParseHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "contextBridge":
				rawScript = generateContextBridgeHook(filter, stackTrace, tamperMode, maxLen);
				break;
			case "custom":
				if (!target) {
					throw new ToolError("target parameter is required when preset is 'custom'");
				}
				rawScript = generateCustomHook(target, filter, stackTrace, tamperMode, maxLen);
				break;
			default:
				throw new ToolError(`Unsupported hook preset: ${preset}`);
		}

		const finalScript = formatScript(rawScript, preset, format, target);

		const summaryLines = [
			`# Generated JS Hook Preset: ${preset.toUpperCase()}${target ? ` (${target})` : ""}`,
			`- **Format**: ${format}`,
			`- **Tamper Mode**: ${tamperMode}`,
			`- **Filter**: ${filter ? `"${filter}"` : "[none]"}`,
			`- **Stack Traces**: ${stackTrace ? "enabled" : "disabled"}`,
			`- **Max Payload Log Length**: ${maxLen} characters`,
			`- **Script Size**: ${finalScript.length} bytes`,
			`- **Status**: Statically generated template (NOT EXECUTED)`,
			"",
			"```javascript",
			finalScript,
			"```",
		];

		return {
			content: [{ type: "text", text: summaryLines.join("\n") }],
			details: {
				action: "generate",
				preset,
				target,
				format,
				script: finalScript,
				scriptLength: finalScript.length,
				options: {
					filter: filter ?? undefined,
					stackTrace,
					tamperMode,
					maxPayloadLength: maxLen,
				},
				isTemplateOnly: true,
				executed: false,
				safetyNote: "Template is statically generated and has not been executed.",
			},
		};
	}
}
