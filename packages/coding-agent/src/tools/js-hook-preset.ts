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
	"console",
] as const;

export type HookPresetKind = (typeof HOOK_PRESETS)[number];

export const HOOK_ACTIONS = ["list", "generate", "inject", "capture", "clear"] as const;
export type HookActionKind = (typeof HOOK_ACTIONS)[number];

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

export interface BrowserReverseEvent {
	timestamp: number;
	type: string;
	id?: string;
	method?: string;
	url?: string;
	status?: number;
	statusText?: string;
	duration?: string;
	data?: unknown;
	body?: unknown;
	headers?: unknown;
	algorithm?: unknown;
	key?: unknown;
	dataHex?: string;
	resultHex?: string;
	target?: string;
	args?: unknown[];
	result?: unknown;
	code?: string;
	stack?: string;
	[key: string]: unknown;
}

export interface BrowserTabSummary {
	name: string;
	state: "alive" | "dead" | "unknown";
	url?: string;
	title?: string;
}

export interface BrowserReverseRunner {
	getTab(name: string): BrowserTabSummary | undefined;
	openTab(name: string, url: string, signal?: AbortSignal): Promise<{ name: string; url: string }>;
	runInTab(name: string, opts: { code: string; timeoutMs?: number; signal?: AbortSignal }): Promise<{
		returnValue?: unknown;
		displays?: Array<{ type: string; text?: string }>;
	}>;
	closeTab?(name: string, signal?: AbortSignal): Promise<boolean>;
}

export function createDefaultBrowserReverseRunner(session: ToolSession): BrowserReverseRunner {
	return {
		getTab(name: string): BrowserTabSummary | undefined {
			try {
				const { getTab } = require("./browser/tab-supervisor");
				const tab = getTab(name);
				if (!tab) return undefined;
				return {
					name: tab.name,
					state: tab.state,
					url: tab.info?.url,
					title: tab.info?.title,
				};
			} catch {
				return undefined;
			}
		},
		async openTab(name: string, url: string, signal?: AbortSignal): Promise<{ name: string; url: string }> {
			const { createBrowserPrelude } = require("./browser");
			const prelude = session.getEvalPreludes?.()?.find((p: { name: string }) => p.name === "browser") ?? createBrowserPrelude(session);
			const result = await prelude.invoke(
				{ action: "open", name, url, headed: false },
				{ signal: signal ?? new AbortController().signal },
			);
			const details = (result && typeof result === "object" && "details" in result ? result.details : undefined) as
				| Record<string, unknown>
				| undefined;
			const finalUrl = (typeof details?.url === "string" && details.url) || url;
			return { name, url: finalUrl };
		},
		async runInTab(
			name: string,
			opts: { code: string; timeoutMs?: number; signal?: AbortSignal },
		): Promise<{
			returnValue?: unknown;
			displays?: Array<{ type: string; text?: string }>;
		}> {
			const { runInTab } = require("./browser/tab-supervisor");
			const result = await runInTab(name, {
				code: opts.code,
				timeoutMs: opts.timeoutMs ?? 30000,
				signal: opts.signal,
				session,
			});
			return {
				returnValue: result.returnValue,
				displays: result.displays,
			};
		},
		async closeTab(name: string, signal?: AbortSignal): Promise<boolean> {
			try {
				const { releaseTab } = require("./browser/tab-supervisor");
				return await releaseTab(name, { timeoutMs: 5000 });
			} catch {
				return false;
			}
		},
	};
}

const jsHookPresetSchema = type({
	action: type.enumerated("list", "generate", "inject", "capture", "clear"),
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
	"tab_name?": type("string").describe("Browser tab name to target for inject/capture/clear (default 'main')"),
	"url?": type("string").describe("Target URL to open if tab does not exist yet (for action 'inject')"),
	"clear?": type("boolean").describe("Whether to clear captured events after reading (for action 'capture')"),
	"export_evidence?": type("boolean").describe(
		"Whether to format captured events as structured evidence records (for action 'capture')",
	),
	"limit?": type("number.integer >= 1").describe(
		"Maximum number of captured events to return (default 50, max 500)",
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
	action: "list" | "generate" | "inject" | "capture" | "clear";
	preset?: HookPresetKind;
	target?: string;
	format?: HookFormatKind;
	script?: string;
	scriptLength?: number;
	tab_name?: string;
	url?: string;
	init_script_id?: string;
	evaluated?: boolean;
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
	events?: BrowserReverseEvent[];
	eventCount?: number;
	consoleLogs?: unknown[];
	requests?: unknown[];
	evidence?: Array<{
		sourceTool: string;
		kind: "fact";
		target: string;
		locator: string;
		content: string;
		tags: string[];
	}>;
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
		name: "Dynamic Execution & Eval Detector",
		description:
			"Traps window.eval, Function constructor, and dynamic script execution to expose obfuscated runtime unpackers.",
		targetApis: ["window.eval", "Function.prototype.constructor", "window.Function"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "eval", tamper_mode: "debugger")',
	},
	{
		preset: "json_parse",
		name: "JSON Serialization Observer",
		description:
			"Intercepts JSON.parse (and optional stringify) to inspect credential, token, and API state transformations in transit.",
		targetApis: ["JSON.parse"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "json_parse", filter: "token")',
	},
	{
		preset: "contextBridge",
		name: "Electron ContextBridge",
		description:
			"Traps Electron contextBridge.exposeInMainWorld invocations, wrapping exposed API methods to log cross-boundary IPC traffic.",
		targetApis: ["contextBridge.exposeInMainWorld"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "contextBridge")',
	},
	{
		preset: "custom",
		name: "Custom Dotted Property / Method Trap",
		description:
			"Generates function wrapper or getter/setter trap for an allowlisted dotted target path on window or globalThis.",
		targetApis: ["User specified allowlisted path"],
		configurableOptions: ["target", "filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "custom", target: "window.api.generateSignature")',
	},
	{
		preset: "console",
		name: "Console Logging Interceptor",
		description:
			"Intercepts window.console methods (log, info, warn, error, debug) to capture runtime diagnostic logs and debug prints into the structured event ring buffer.",
		targetApis: ["console.log", "console.info", "console.warn", "console.error", "console.debug"],
		configurableOptions: ["filter", "stack_trace", "tamper_mode", "max_payload_length", "format"],
		example: 'js_hook_preset(action: "generate", preset: "console")',
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

const REA_EVENT_RECORDER_SNIPPET = `
  const _reaRecord = (ev) => {
    try {
      if (typeof window !== "undefined") {
        window.__rea_events__ = window.__rea_events__ || [];
        if (window.__rea_events__.length >= 1000) {
          window.__rea_events__.shift();
        }
        window.__rea_events__.push(ev);
      }
    } catch {}
  };`;

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
${REA_EVENT_RECORDER_SNIPPET}

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

    _reaRecord({
      timestamp: Date.now(),
      type: "fetch_request",
      id: reqId,
      method,
      url,
      headers: init.headers || null,
      body: bodyPreview,
    });

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
      const clone = response.clone();
      const duration = (performance.now() - startTime).toFixed(1);

      clone.text().then(text => {
        let resPreview = text;
        if (resPreview.length > _maxLen) resPreview = resPreview.slice(0, _maxLen) + "...[truncated]";
        _reaRecord({
          timestamp: Date.now(),
          type: "fetch_response",
          id: reqId,
          method,
          url,
          status: response.status,
          statusText: response.statusText,
          duration,
          body: resPreview,
        });
        console.groupCollapsed(\`%c[FETCH RES #\${reqId}]%c \${response.status} \${response.statusText} (\${duration}ms) - \${url}\`, "color:#10b981;font-weight:bold;", "color:inherit;");
        console.log("Status:", response.status, response.statusText);
        console.log("Headers:", Object.fromEntries(response.headers.entries()));
        console.log("Body Preview:", resPreview);
        console.groupEnd();
      }).catch(() => {});

      return response;
    } catch (err) {
      console.error(\`[FETCH ERR #\${reqId}] \${method} \${url}\`, err);
      _reaRecord({
        timestamp: Date.now(),
        type: "fetch_error",
        id: reqId,
        method,
        url,
        error: String(err),
      });
      throw err;
    }
  };
  console.log("%c[REA HOOK]%c window.fetch hook installed successfully.", "color:#6366f1;font-weight:bold;", "color:inherit;");
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
${REA_EVENT_RECORDER_SNIPPET}

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
        _reaRecord({
          timestamp: Date.now(),
          type: "xhr_request",
          id: hook.id,
          method: hook.method,
          url: hook.url,
          headers: hook.headers,
          body: bodyPreview,
        });
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
          _reaRecord({
            timestamp: Date.now(),
            type: "xhr_response",
            id: hook.id,
            method: hook.method,
            url: hook.url,
            status: this.status,
            statusText: this.statusText,
            duration,
            body: resPreview,
          });
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
${REA_EVENT_RECORDER_SNIPPET}

  const _OrigWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const ws = protocols !== undefined ? new _OrigWebSocket(url, protocols) : new _OrigWebSocket(url);
    const wsId = Math.random().toString(36).slice(2, 8);
    const wsUrl = String(url);
    const shouldTrack = !_filter || wsUrl.includes(_filter);

    if (shouldTrack) {
      _reaRecord({
        timestamp: Date.now(),
        type: "websocket_open",
        id: wsId,
        url: wsUrl,
        protocols: protocols || null,
      });
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
        _reaRecord({
          timestamp: Date.now(),
          type: "websocket_send",
          id: wsId,
          url: wsUrl,
          data: preview,
        });
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
        _reaRecord({
          timestamp: Date.now(),
          type: "websocket_message",
          id: wsId,
          url: wsUrl,
          data: preview,
        });
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
${REA_EVENT_RECORDER_SNIPPET}

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
        _reaRecord({
          timestamp: Date.now(),
          type: "crypto_call",
          id: callId,
          method,
          algorithm: algo,
          keyPreview: args[1] ? String(args[1]) : null,
          dataHex: toHex(args[2]),
        });
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
          _reaRecord({
            timestamp: Date.now(),
            type: "crypto_result",
            id: callId,
            method,
            resultHex: toHex(result),
          });
          console.groupCollapsed(\`%c[CRYPTO \${method.toUpperCase()} RES #\${callId}]%c Result\`, "color:#10b981;font-weight:bold;", "color:inherit;");
          console.log("Result Hex/Summary:", toHex(result));
          console.groupEnd();
        }
        return result;
      } catch (err) {
        if (shouldLog) {
          _reaRecord({
            timestamp: Date.now(),
            type: "crypto_error",
            id: callId,
            method,
            error: String(err),
          });
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
        _reaRecord({
          timestamp: Date.now(),
          type: "crypto_random",
          byteLength: array.byteLength,
          dataHex: toHex(array),
        });
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
${REA_EVENT_RECORDER_SNIPPET}

  if (typeof window !== "undefined" && window.eval) {
    const _origEval = window.eval;
    window.eval = function(code) {
      const codeStr = String(code);
      if (!_filter || codeStr.includes(_filter)) {
        const preview = codeStr.length > _maxLen ? codeStr.slice(0, _maxLen) + "...[truncated]" : codeStr;
        _reaRecord({
          timestamp: Date.now(),
          type: "eval",
          code: preview,
          length: codeStr.length,
          stack: _includeStack ? new Error().stack : undefined,
        });
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
      _reaRecord({
        timestamp: Date.now(),
        type: "function_constructor",
        args: args.slice(0, -1).map(String),
        body: preview,
        stack: _includeStack ? new Error().stack : undefined,
      });
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
${REA_EVENT_RECORDER_SNIPPET}

  const _origParse = JSON.parse;
  JSON.parse = function(text, reviver) {
    const textStr = String(text);
    if (!_filter || textStr.includes(_filter)) {
      const preview = textStr.length > _maxLen ? textStr.slice(0, _maxLen) + "...[truncated]" : textStr;
      _reaRecord({
        timestamp: Date.now(),
        type: "json_parse",
        input: preview,
        length: textStr.length,
      });
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
${REA_EVENT_RECORDER_SNIPPET}

  function truncate(val) {
    try {
      const s = typeof val === "string" ? val : JSON.stringify(val);
      return s && s.length > _maxLen ? s.slice(0, _maxLen) + "...[truncated]" : s;
    } catch {}
    return String(val);
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
            _reaRecord({
              timestamp: Date.now(),
              type: "contextBridge_call",
              id: callId,
              api: fullName,
              args: args.map(truncate),
            });
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
                _reaRecord({
                  timestamp: Date.now(),
                  type: "contextBridge_result",
                  id: callId,
                  api: fullName,
                  result: truncate(ret),
                });
                console.groupCollapsed(\`%c[ELECTRON IPC RES #\${callId}]%c \${fullName} -> Resolved\`, "color:#10b981;font-weight:bold;", "color:inherit;");
                console.log("Return Value:", truncate(ret));
                console.groupEnd();
              }
            }).catch(err => {
              if (shouldLog) {
                _reaRecord({
                  timestamp: Date.now(),
                  type: "contextBridge_error",
                  id: callId,
                  api: fullName,
                  error: String(err),
                });
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
${REA_EVENT_RECORDER_SNIPPET}

  function truncate(val) {
    try {
      const s = typeof val === "string" ? val : JSON.stringify(val);
      return s && s.length > _maxLen ? s.slice(0, _maxLen) + "...[truncated]" : s;
    } catch {}
    return String(val);
  }

  const parts = _targetPath.split(".");
  let parent = typeof window !== "undefined" ? window : globalThis;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!parent || !(part in parent)) {
      console.warn(\`[REA HOOK] Target path segment "\${part}" not found while navigating \${_targetPath}\`);
      return;
    }
    parent = parent[part];
  }

  const leafProp = parts[parts.length - 1];
  const origVal = parent[leafProp];

  if (typeof origVal === "function") {
    parent[leafProp] = function(...args) {
      const shouldLog = !_filter || _targetPath.includes(_filter) || JSON.stringify(args).includes(_filter);
      if (shouldLog) {
        _reaRecord({
          timestamp: Date.now(),
          type: "custom_call",
          target: _targetPath,
          args: args.map(truncate),
        });
        console.groupCollapsed(\`%c[CUSTOM HOOK]%c \${_targetPath}()\`, "color:#f43f5e;font-weight:bold;", "color:inherit;");
        console.log("Target:", _targetPath);
        console.log("Arguments:", args.map(truncate));
        if (_includeStack) console.log("Call Stack:", new Error().stack);
        console.groupEnd();

        if (_mode === "debugger") {
          debugger;
        }
        if (_mode === "stub") {
          return undefined;
        }
      }
      const res = origVal.apply(this, args);
      if (shouldLog) {
        _reaRecord({
          timestamp: Date.now(),
          type: "custom_result",
          target: _targetPath,
          result: truncate(res),
        });
      }
      return res;
    };
    console.log(\`%c[REA HOOK]%c Function trap placed on \${_targetPath}\`, "color:#6366f1;font-weight:bold;", "color:inherit;");
  } else {
    let currentVal = origVal;
    Object.defineProperty(parent, leafProp, {
      configurable: true,
      enumerable: true,
      get() {
        if (!_filter || _targetPath.includes(_filter)) {
          _reaRecord({
            timestamp: Date.now(),
            type: "custom_get",
            target: _targetPath,
            value: truncate(currentVal),
          });
          console.log(\`%c[CUSTOM GET]%c \${_targetPath} => \${truncate(currentVal)}\`, "color:#f43f5e;font-weight:bold;", "color:inherit;");
        }
        return currentVal;
      },
      set(newVal) {
        if (!_filter || _targetPath.includes(_filter) || String(newVal).includes(_filter)) {
          _reaRecord({
            timestamp: Date.now(),
            type: "custom_set",
            target: _targetPath,
            value: truncate(newVal),
          });
          console.groupCollapsed(\`%c[CUSTOM SET]%c \${_targetPath} = \${truncate(newVal)}\`, "color:#f43f5e;font-weight:bold;", "color:inherit;");
          console.log("Old Value:", truncate(currentVal));
          console.log("New Value:", truncate(newVal));
          if (_includeStack) console.log("Call Stack:", new Error().stack);
          console.groupEnd();
          if (_mode === "debugger") {
            debugger;
          }
        }
        currentVal = newVal;
      },
    });
    console.log(\`%c[REA HOOK]%c Property getter/setter trap placed on \${_targetPath}\`, "color:#6366f1;font-weight:bold;", "color:inherit;");
  }
})();`;
}

function generateConsoleHook(
	filter: string | null,
	stackTrace: boolean,
	tamperMode: HookTamperMode,
	maxLen: number,
): string {
	const filterJson = JSON.stringify(filter);
	const modeJson = JSON.stringify(tamperMode);
	return `(() => {
  if (typeof window === "undefined" || !window.console) {
    return;
  }
  const _orig = {
    log: window.console.log,
    info: window.console.info,
    warn: window.console.warn,
    error: window.console.error,
    debug: window.console.debug,
  };
  const _filter = ${filterJson};
  const _maxLen = ${maxLen};
  const _includeStack = ${stackTrace};
  const _mode = ${modeJson};
${REA_EVENT_RECORDER_SNIPPET}

  const methods = ["log", "info", "warn", "error", "debug"];
  methods.forEach(method => {
    const origFn = _orig[method];
    if (typeof origFn !== "function") return;
    window.console[method] = function(...args) {
      try {
        const text = args.map(a => {
          try {
            return typeof a === "string" ? a : JSON.stringify(a);
          } catch {
            return String(a);
          }
        }).join(" ").slice(0, _maxLen);

        if (!_filter || text.includes(_filter)) {
          if (_mode === "debugger") {
            debugger;
          }
          _reaRecord({
            timestamp: Date.now(),
            type: "console",
            method,
            text,
            args: args.map(a => {
              try {
                return typeof a === "string" ? a : JSON.parse(JSON.stringify(a));
              } catch {
                return String(a);
              }
            }).slice(0, 10),
            stack: _includeStack ? new Error().stack : undefined,
          });
        }
      } catch {}
      if (_mode !== "stub") {
        return origFn.apply(this, args);
      }
    };
  });
})();`;
}

function formatScript(body: string, preset: string, format: HookFormatKind, target?: string): string {
	switch (format) {
		case "userscript":
			return `${buildUserscriptHeader(preset, target)}\n${body}`;
		case "devtools":
			return `${buildHeaderBanner(preset, format, target)}\n// Tip: Run directly in DevTools Console to activate instrumentation.\n${body}`;
		case "frida":
			return `// [Frida] Injected Web View / Chromium Script Evaluator
Java.perform(function() {
  // If target WebView is available, evaluate via evaluateJavascript
  const hookSource = ${JSON.stringify(body)};
  console.log("[REA Frida] Injecting Web Hook preset '${preset}' into active WebView context...");
  // Standard Android WebView evaluate pattern:
  // webView.evaluateJavascript(hookSource, null);
});`;
		case "snippet":
		default:
			return `${buildHeaderBanner(preset, format, target)}\n${body}`;
	}
}

export class JsHookPresetTool
	implements AgentTool<typeof jsHookPresetSchema, JsHookPresetDetails>
{
	readonly name = "js_hook_preset";
	readonly approval: ToolTier = "read";
	readonly label = "JS Hook Preset";
	readonly summary =
		"Generate, inject, and capture safe JavaScript hook snippets and debugging presets (fetch, xhr, websocket, crypto, eval, json_parse, contextBridge, custom)";
	readonly description: string;
	readonly parameters = jsHookPresetSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly runner?: BrowserReverseRunner,
	) {
		this.description = prompt.render(jsHookPresetDescription);
	}

	private getRunner(): BrowserReverseRunner {
		return this.runner ?? createDefaultBrowserReverseRunner(this.session);
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
				"All scripts are returned as safe templates and are NEVER executed automatically unless 'inject' action is called.",
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
					safetyNote: "Templates are statically cataloged and have not been executed.",
				},
			};
		}

		if (action === "generate") {
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
				case "console":
					rawScript = generateConsoleHook(filter, stackTrace, tamperMode, maxLen);
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

		if (action === "inject") {
			const preset = (params.preset || (params.target ? "custom" : "fetch")) as HookPresetKind;
			const format: HookFormatKind = params.format || "snippet";
			const filter = params.filter ? params.filter.trim() : null;
			const stackTrace = params.stack_trace !== false;
			const tamperMode: HookTamperMode = params.tamper_mode || "log";
			const maxLen = Math.min(32768, Math.max(64, Math.floor(params.max_payload_length ?? 1024)));
			const target = params.target ? params.target.trim() : undefined;
			const tabName = params.tab_name?.trim() || "main";

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
				case "console":
					rawScript = generateConsoleHook(filter, stackTrace, tamperMode, maxLen);
					break;
				default:
					throw new ToolError(`Unsupported hook preset: ${preset}`);
			}

			const finalScript = formatScript(rawScript, preset, format, target);
			const runner = this.getRunner();
			let tab = runner.getTab(tabName);

			if (!tab || tab.state !== "alive") {
				if (params.url) {
					const opened = await runner.openTab(tabName, params.url, signal);
					tab = { name: opened.name, state: "alive", url: opened.url };
				} else {
					throw new ToolError(
						`Browser tab "${tabName}" is not open or alive. Provide 'url' to open a new tab, or use browser(action: "open", name: "${tabName}", url: "...") first.`,
					);
				}
			}

			const injectionCode = `(async () => {
  let initId = "";
  try {
    const res = await tab.addInitScript(${JSON.stringify(finalScript)});
    initId = res ? res.id : "";
  } catch (err) {
    initId = "";
  }
  let evaluated = false;
  try {
    await tab.evaluate(${JSON.stringify(finalScript)});
    evaluated = true;
  } catch (err) {
    evaluated = false;
  }
  return { initScriptId: initId, evaluated };
})()`;

			const runRes = await runner.runInTab(tabName, { code: injectionCode, signal });
			const runValue = (runRes && typeof runRes.returnValue === "object" ? runRes.returnValue : {}) as {
				initScriptId?: string;
				evaluated?: boolean;
			};

			const summaryLines = [
				`# Injected JS Hook Preset: ${preset.toUpperCase()}${target ? ` (${target})` : ""}`,
				`- **Tab**: \`${tabName}\``,
				`- **URL**: ${tab.url || "[blank]"}`,
				`- **Format**: ${format}`,
				`- **Tamper Mode**: ${tamperMode}`,
				`- **Filter**: ${filter ? `"${filter}"` : "[none]"}`,
				`- **Stack Traces**: ${stackTrace ? "enabled" : "disabled"}`,
				`- **Init Script Registered**: ${runValue.initScriptId ? `yes (${runValue.initScriptId})` : "no"}`,
				`- **Immediate Page Evaluated**: ${runValue.evaluated ? "yes" : "no"}`,
				`- **Status**: Active instrumentation verified on tab \`${tabName}\``,
			];

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "inject",
					preset,
					target,
					format,
					script: finalScript,
					scriptLength: finalScript.length,
					tab_name: tabName,
					url: tab.url,
					init_script_id: runValue.initScriptId,
					evaluated: runValue.evaluated,
					options: {
						filter: filter ?? undefined,
						stackTrace,
						tamperMode,
						maxPayloadLength: maxLen,
					},
					isTemplateOnly: false,
					executed: true,
					safetyNote: "Hook script was injected into the active browser session.",
				},
			};
		}

		if (action === "capture") {
			const tabName = params.tab_name?.trim() || "main";
			const filter = params.filter ? params.filter.trim() : null;
			const clear = params.clear === true;
			const limit = Math.min(500, Math.max(1, Math.floor(params.limit ?? 50)));
			const exportEvidence = params.export_evidence === true;

			const runner = this.getRunner();
			const tab = runner.getTab(tabName);
			if (!tab || tab.state !== "alive") {
				throw new ToolError(
					`Browser tab "${tabName}" is not open or alive. Cannot capture events from a missing tab.`,
				);
			}

			const captureCode = `(async () => {
  let events = [];
  try {
    events = await tab.evaluate((filterStr, clearFlag) => {
      let evs = Array.isArray(window.__rea_events__) ? window.__rea_events__ : [];
      if (filterStr) {
        const query = filterStr.toLowerCase().trim();
        evs = evs.filter(e => {
          const typeLower = (e.type || "").toLowerCase();
          if (query === "ws" && typeLower.startsWith("websocket")) return true;
          if (query === "send" && (typeLower.includes("send") || typeLower.includes("request"))) return true;
          if (query === "console" && typeLower.includes("console")) return true;
          if (query === "crypto" && typeLower.startsWith("crypto")) return true;
          try {
            return JSON.stringify(e).toLowerCase().includes(query);
          } catch {
            return false;
          }
        });
      }
      if (clearFlag) {
        window.__rea_events__ = [];
      }
      return evs;
    }, ${JSON.stringify(filter)}, ${JSON.stringify(clear)});
  } catch (err) {}

  let consoleLogs = [];
  try {
    consoleLogs = await tab.console({ since: 0 });
  } catch (err) {}

  let requests = [];
  try {
    requests = await tab.requests();
  } catch (err) {}

  return { events, consoleLogs, requests };
})()`;

			const runRes = await runner.runInTab(tabName, { code: captureCode, signal });
			const val = (runRes && typeof runRes.returnValue === "object" ? runRes.returnValue : {}) as {
				events?: BrowserReverseEvent[];
				consoleLogs?: unknown[];
				requests?: unknown[];
			};

			const rawEvents = Array.isArray(val.events) ? val.events : [];
			const pagedEvents = rawEvents.slice(0, limit);
			const consoleLogs = Array.isArray(val.consoleLogs) ? val.consoleLogs : [];
			const requests = Array.isArray(val.requests) ? val.requests : [];

			const typeCounts: Record<string, number> = {};
			for (const ev of rawEvents) {
				const t = ev.type || "unknown";
				typeCounts[t] = (typeCounts[t] || 0) + 1;
			}

			const evidenceItems = exportEvidence
				? pagedEvents.map(ev => ({
						sourceTool: "js_hook_preset",
						kind: "fact" as const,
						target: tab.url || tabName,
						locator: `tab:${tabName}:${ev.type}${ev.id ? `:${ev.id}` : ""}`,
						content: `Captured ${ev.type} event on ${tab.url || tabName}: ${JSON.stringify(ev).slice(0, 500)}`,
						tags: ["browser", "js_hook", ev.type],
					}))
				: undefined;

			const summaryLines = [
				`# Browser Captured Events: Tab \`${tabName}\``,
				`- **Total Events Captured**: ${rawEvents.length}${rawEvents.length > limit ? ` (showing first ${limit})` : ""}`,
				`- **Event Types Breakdown**: ${Object.keys(typeCounts).length > 0 ? Object.entries(typeCounts).map(([k, v]) => `${k}=${v}`).join(", ") : "[none]"}`,
				`- **Captured Console Messages**: ${consoleLogs.length}`,
				`- **Captured Network Requests**: ${requests.length}`,
				`- **Buffer Cleared**: ${clear ? "yes" : "no"}`,
				"",
			];

			if (pagedEvents.length > 0) {
				summaryLines.push("### Recent Hook Events:");
				for (let i = 0; i < Math.min(pagedEvents.length, 10); i++) {
					const ev = pagedEvents[i];
					summaryLines.push(`- **[${new Date(ev.timestamp).toISOString()}] ${ev.type}** ${ev.url || ev.method || ev.target || ""}`);
				}
				if (pagedEvents.length > 10) {
					summaryLines.push(`... and ${pagedEvents.length - 10} more events.`);
				}
			} else {
				summaryLines.push("_No hook events captured in buffer._");
			}

			return {
				content: [{ type: "text", text: summaryLines.join("\n") }],
				details: {
					action: "capture",
					tab_name: tabName,
					url: tab.url,
					events: pagedEvents,
					eventCount: rawEvents.length,
					consoleLogs,
					requests,
					evidence: evidenceItems,
					isTemplateOnly: false,
					executed: true,
					safetyNote: "Structured events captured from live browser tab.",
				},
			};
		}

		if (action === "clear") {
			const tabName = params.tab_name?.trim() || "main";
			const runner = this.getRunner();
			const tab = runner.getTab(tabName);
			if (!tab || tab.state !== "alive") {
				throw new ToolError(
					`Browser tab "${tabName}" is not open or alive. Cannot clear events from a missing tab.`,
				);
			}

			const clearCode = `(async () => {
  try {
    await tab.evaluate(() => {
      window.__rea_events__ = [];
    });
  } catch (err) {}
  try {
    await tab.clearConsole();
  } catch (err) {}
  return { cleared: true };
})()`;

			await runner.runInTab(tabName, { code: clearCode, signal });

			return {
				content: [{ type: "text", text: `Cleared event buffer and console for tab \`${tabName}\`.` }],
				details: {
					action: "clear",
					tab_name: tabName,
					url: tab.url,
					isTemplateOnly: false,
					executed: true,
					safetyNote: "Browser event buffer cleared.",
				},
			};
		}

		throw new ToolError(`Unsupported action: ${action}`);
	}
}
