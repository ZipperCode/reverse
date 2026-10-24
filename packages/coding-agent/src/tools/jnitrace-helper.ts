/**
 * JNI API tracing helper using bundled jnitrace-engine (MIT).
 *
 * Integrates real jnitrace-engine v1.1.1 (Copyright (c) 2019 chame1eon)
 * with Frida 16/17 global export resolution polyfill, owned-hook lifecycle
 * cleanup (Interceptor.attach for dlopen rather than replace), pre-existing
 * module scanning, and normalized universal event output.
 */

import { ToolError } from "@reverse/tui/tools/tool-errors";
import { ALL_JNI_APIS, JNITRACE_ENGINE_BUNDLE, JNITRACE_ENGINE_PIN } from "./jnitrace-engine-asset";

export { ALL_JNI_APIS };

export const DEFAULT_SAFE_JNI_APIS = ["FindClass", "GetMethodID", "GetStaticMethodID", "RegisterNatives"] as const;

export interface JniTraceOptions {
	module?: string;
	libraries?: string[];
	jniApis?: string[];
	includeExports?: string[];
	excludeExports?: string[];
	maxEvents?: number;
	maxBufferBytes?: number;
	backtrace?: boolean | "fuzzy" | "accurate";
	timeout?: number;
}

/**
 * Generates an isolated Frida JavaScript script embedding the patched
 * jnitrace-engine to intercept, decode, and report bounded JNI API telemetry.
 */
export function buildJniTraceScript(options: JniTraceOptions = {}): string {
	// 1. Validate targeted module / libraries: prevent unbounded global overhead
	let libraries: string[] = [];
	if (options.libraries && options.libraries.length > 0) {
		libraries = options.libraries;
	} else if (options.module && options.module.trim().length > 0) {
		libraries = [options.module.trim()];
	} else {
		throw new ToolError(
			"Must provide 'module' (e.g. 'libnative-lib.so') or 'libraries' for template 'jni_trace' to avoid unbounded global tracing overhead",
		);
	}

	// 2. Validate JNI APIs: safe performant default, strict validation of requested names
	let apisToIntercept: string[];
	if (!options.jniApis || options.jniApis.length === 0) {
		apisToIntercept = [...DEFAULT_SAFE_JNI_APIS];
	} else if (options.jniApis.includes("*")) {
		apisToIntercept = [...ALL_JNI_APIS];
	} else {
		for (const api of options.jniApis) {
			if (!ALL_JNI_APIS.includes(api)) {
				throw new ToolError(
					`Unknown JNI API '${api}'. Choose from valid JNI APIs (e.g. FindClass, GetMethodID, CallVoidMethod, RegisterNatives) or pass '*' for all.`,
				);
			}
		}
		apisToIntercept = options.jniApis;
	}

	// 3. Enforce hard caps on limits to bound resource consumption
	const rawMaxEvents = options.maxEvents ?? 100;
	const maxEvents =
		Number.isFinite(rawMaxEvents) && rawMaxEvents > 0 ? Math.min(Math.max(Math.round(rawMaxEvents), 1), 1000) : 100;

	const rawBufferBytes = options.maxBufferBytes ?? 256;
	const maxBufferBytes =
		Number.isFinite(rawBufferBytes) && rawBufferBytes > 0
			? Math.min(Math.max(Math.round(rawBufferBytes), 16), 4096)
			: 256;

	const rawTimeout = options.timeout ?? 30;
	const timeoutSeconds =
		Number.isFinite(rawTimeout) && rawTimeout > 0 ? Math.min(Math.max(Math.round(rawTimeout), 1), 300) : 30;

	const safeLibraries = JSON.stringify(libraries);
	const safeIncludeExports = JSON.stringify(options.includeExports ?? []);
	const safeExcludeExports = JSON.stringify(options.excludeExports ?? []);

	let backtraceVal = "none";
	if (options.backtrace === "fuzzy") {
		backtraceVal = "fuzzy";
	} else if (options.backtrace === "accurate" || options.backtrace === true) {
		backtraceVal = "accurate";
	}
	const safeBacktrace = JSON.stringify(backtraceVal);
	const safeJniApis = JSON.stringify(apisToIntercept);

	return `(function() {
  try {
    // --- Embedded jnitrace-engine v1.1.1 (${JNITRACE_ENGINE_PIN.license}, ${JNITRACE_ENGINE_PIN.copyright}) ---
    var engineExports = {};
    var engineModule = { exports: engineExports };
    (function(module, exports) {
      ${JNITRACE_ENGINE_BUNDLE}
    })(engineModule, engineExports);

    var engine = (engineModule.exports && Object.keys(engineModule.exports).length > 0)
      ? engineModule.exports
      : (engineExports.default || engineExports);

    var JNIInterceptor = engine.JNIInterceptor;
    var ConfigBuilder = engine.ConfigBuilder;
    var teardownEngine = engine.teardown;

    // --- Configuration ---
    if (ConfigBuilder) {
      var builder = new ConfigBuilder();
      builder.libraries = ${safeLibraries};
      builder.backtrace = ${safeBacktrace};
      builder.includeExports = ${safeIncludeExports};
      builder.excludeExports = ${safeExcludeExports};
      builder.env = true;
      builder.vm = true;
      builder.build();
    }

    // --- State & Boundaries ---
    var maxEvents = ${maxEvents};
    var maxBufferBytes = ${maxBufferBytes};
    var eventCount = 0;
    var isStopped = false;
    var attachedListeners = [];

    var classMap = {};
    var methodMap = {};
    var fieldMap = {};
    var stringMap = {};

    function safeReadCString(p, maxBytes) {
      if (!p || p.isNull()) return null;
      try {
        var s = p.readCString();
        if (s !== null && maxBytes > 0 && s.length > maxBytes) {
          return s.slice(0, maxBytes) + "...[truncated]";
        }
        return s;
      } catch(e) {
        return null;
      }
    }

    function teardown() {
      if (isStopped) return;
      isStopped = true;
      for (var i = 0; i < attachedListeners.length; i++) {
        try { attachedListeners[i].detach(); } catch(e) {}
      }
      attachedListeners = [];
      if (typeof teardownEngine === "function") {
        try { teardownEngine(); } catch(e) {}
      }
      if (JNIInterceptor && typeof JNIInterceptor.detatchAll === "function") {
        try { JNIInterceptor.detatchAll(); } catch(e) {}
      }
    }

    function emitTraceEvent(record) {
      if (maxEvents > 0 && eventCount >= maxEvents) return;
      eventCount++;
      try { send(record); } catch(e) {}
      try { console.log("__FRIDA_TRACE_START__" + JSON.stringify(record) + "__FRIDA_TRACE_END__"); } catch(e) {}
      if (maxEvents > 0 && eventCount >= maxEvents) {
        teardown();
      }
    }

    function getApiCategory(name) {
      if (name.indexOf("Method") !== -1) return "method";
      if (name.indexOf("Field") !== -1) return "field";
      if (name.indexOf("Class") !== -1) return "class";
      if (name.indexOf("String") !== -1) return "string";
      if (name.indexOf("Array") !== -1) return "array";
      if (name.indexOf("Ref") !== -1) return "reference";
      if (name.indexOf("JavaVM") !== -1 || name === "GetEnv") return "vm";
      if (name.indexOf("Exception") !== -1 || name === "Throw" || name === "ThrowNew" || name === "FatalError") return "exception";
      return "general";
    }

    // --- Unified JNI Callback ---
    var jniCallback = {
      onEnter: function(args) {
        this.capturedArgs = [].slice.call(args);
      },
      onLeave: function(retval) {
        if (isStopped) return;
        var ret = retval.get();
        var def = this.methodDef;
        if (!def) return;
        var name = def.name;
        var args = this.capturedArgs || [];
        var threadId = this.threadId;
        var backtrace = this.backtrace ? this.backtrace.map(function(addr) { return addr.toString(); }) : undefined;

        var resolvedClass = null;
        var resolvedMethod = null;
        var resolvedSig = null;
        var resolvedField = null;
        var extraPayload = {};

        if (name === "FindClass" && args.length > 1) {
          resolvedClass = safeReadCString(args[1], maxBufferBytes);
          if (resolvedClass && ret && !ret.isNull()) {
            classMap[ret.toString()] = resolvedClass;
          }
        } else if ((name === "GetMethodID" || name === "GetStaticMethodID") && args.length > 3) {
          resolvedClass = classMap[args[1].toString()] || null;
          resolvedMethod = safeReadCString(args[2], maxBufferBytes);
          resolvedSig = safeReadCString(args[3], maxBufferBytes);
          if (ret && !ret.isNull()) {
            methodMap[ret.toString()] = { name: resolvedMethod, sig: resolvedSig, className: resolvedClass };
          }
        } else if ((name === "GetFieldID" || name === "GetStaticFieldID") && args.length > 3) {
          resolvedClass = classMap[args[1].toString()] || null;
          resolvedField = safeReadCString(args[2], maxBufferBytes);
          resolvedSig = safeReadCString(args[3], maxBufferBytes);
          if (ret && !ret.isNull()) {
            fieldMap[ret.toString()] = { name: resolvedField, sig: resolvedSig, className: resolvedClass };
          }
        } else if (name === "NewStringUTF" && args.length > 1) {
          var strVal = safeReadCString(args[1], maxBufferBytes);
          if (strVal && ret && !ret.isNull()) {
            stringMap[ret.toString()] = strVal;
          }
          extraPayload.value = strVal;
        } else if (name === "GetStringUTFChars" && args.length > 1) {
          var strVal = safeReadCString(ret, maxBufferBytes);
          var strPtr = args[1].toString();
          if (strVal) {
            stringMap[strPtr] = strVal;
          }
          extraPayload.value = strVal;
        } else if (name === "RegisterNatives" && args.length > 3) {
          resolvedClass = classMap[args[1].toString()] || "unknown";
          var methodsPtr = args[2];
          var nMethods = (typeof args[3] === "number") ? args[3] : (args[3] && typeof args[3].toInt32 === "function") ? args[3].toInt32() : Number(args[3]) || 0;
          var retValInt = (typeof ret === "number") ? ret : (ret && typeof ret.toInt32 === "function") ? ret.toInt32() : 0;
          var isSuccess = (retValInt === 0);
          var methodsList = [];

          try {
            var count = Math.min(Math.max(0, nMethods), 500);
            for (var i = 0; i < count; i++) {
              var entryPtr = methodsPtr.add(i * 3 * Process.pointerSize);
              var nPtr = entryPtr.readPointer();
              var sPtr = entryPtr.add(Process.pointerSize).readPointer();
              var fnPtr = entryPtr.add(Process.pointerSize * 2).readPointer();
              var mN = safeReadCString(nPtr, maxBufferBytes);
              var mS = safeReadCString(sPtr, maxBufferBytes);
              var mod = null;
              try { mod = Process.findModuleByAddress(fnPtr); } catch(e) {}
              var offsetHex = null;
              if (mod && mod.base) {
                offsetHex = "0x" + fnPtr.sub(mod.base).toString(16);
              }
              methodsList.push({
                name: mN,
                signature: mS,
                fnPtr: fnPtr.toString(),
                module: mod ? mod.name : null,
                modulePath: mod ? mod.path : null,
                base: mod ? mod.base.toString() : null,
                offset: offsetHex
              });
            }
          } catch(e) {}

          var regEvent = {
            event: "jni_register_natives",
            status: isSuccess ? "confirmed" : "rejected",
            retval: retValInt,
            class: resolvedClass,
            nMethods: nMethods,
            methods: methodsList,
            source: "frida",
            timestamp: Date.now()
          };
          emitTraceEvent(regEvent);
          return;
        } else if (name.indexOf("Call") === 0 && name.indexOf("Method") !== -1) {
          var mId = args.length > 2 ? args[2].toString() : null;
          var mInfo = mId ? methodMap[mId] : null;
          if (mInfo) {
            resolvedClass = mInfo.className;
            resolvedMethod = mInfo.name;
            resolvedSig = mInfo.sig;
          } else if (this.javaMethod) {
            resolvedSig = this.javaMethod._;
          }
        }

        var record = {
          event: "jni_trace",
          api: name,
          category: getApiCategory(name),
          class: resolvedClass,
          method: resolvedMethod,
          signature: resolvedSig,
          field: resolvedField,
          retval: (ret && typeof ret.toString === "function") ? ret.toString() : ret,
          threadId: threadId,
          backtrace: backtrace,
          details: Object.keys(extraPayload).length > 0 ? extraPayload : undefined,
          timestamp: Date.now()
        };
        emitTraceEvent(record);
      }
    };

    // --- Attach APIs ---
    var apisToAttach = ${safeJniApis};
    if (JNIInterceptor && typeof JNIInterceptor.attach === "function") {
      for (var i = 0; i < apisToAttach.length; i++) {
        try {
          var listener = JNIInterceptor.attach(apisToAttach[i], jniCallback);
          if (listener) attachedListeners.push(listener);
        } catch(e) {}
      }
    }

    // --- Watchdog timeout ---
    if (${timeoutSeconds} > 0) {
      setTimeout(function() {
        teardown();
      }, ${timeoutSeconds} * 1000);
    }

    // --- Live session RPC exports ---
    rpc.exports = {
      dispose: function() {
        teardown();
        return true;
      },
      status: function() {
        return {
          eventCount: eventCount,
          maxEvents: maxEvents,
          stopped: isStopped
        };
      }
    };
  } catch(initErr) {
    var errPayload = {
      event: "error",
      error: "initialization_failed",
      detail: initErr && (initErr.stack || initErr.message) ? String(initErr.stack || initErr.message) : String(initErr),
      timestamp: Date.now()
    };
    try { send(errPayload); } catch(_) {}
    try { console.log("__FRIDA_TRACE_START__" + JSON.stringify(errPayload) + "__FRIDA_TRACE_END__"); } catch(_) {}
  }
})();`;
}
