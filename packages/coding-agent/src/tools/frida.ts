import { Process } from "@reverse/natives";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type } from "@reverse/reversetype";
import type { AgentTool, AgentToolContext, AgentToolResult, AgentToolUpdateCallback } from "@reverse/agent";
import { logger, prompt, $which } from "@reverse/utils";
import { redactMemorySecrets } from "../memory-backend/redact";
import fridaDescription from "../prompts/tools/frida.md" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import type { ToolSession } from "./index";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
export const fridaSchema = type({
	"action?": type
		.enumerated("exec", "devices", "ps", "modules", "inspect", "trace")
		.describe(
			"Action to perform: 'exec' (execute script/hook, default if script provided), 'devices' (enumerate devices), 'ps' (list processes), 'modules' or 'inspect' (list loaded modules), 'trace' (trace module load or exports)",
		),
	"script?": type("string").describe(
		"Inline Frida JavaScript source code to execute. Mutually exclusive with script_path. Supports hooks, Interceptor, Java/ObjC runtime, and Memory read/write",
	),
	"script_path?": type("string").describe(
		"Local path to a Frida JavaScript script file to execute. Mutually exclusive with script",
	),
	"pid?": type("number").describe(
		"Target process ID (PID) to attach to or inspect. Mutually exclusive with process and spawn",
	),
	"process?": type("string").describe(
		"Target process name or application identifier to attach to or inspect. Mutually exclusive with pid and spawn",
	),
	"spawn?": type("string").describe(
		"Target binary path or package name to spawn as a new process. Mutually exclusive with pid and process",
	),
	"usb?": type("boolean").describe("Target USB device/emulator (shorthand for frida -U / frida-ps -U)"),
	"device?": type("string").describe("Target device identifier or serial (passes -D <device>)"),
	"host?": type("string").describe("Target remote frida-server host (e.g. '192.168.1.5:27042', passes -H <host>)"),
	"script_args?": type("unknown").describe("Optional arguments passed to the Frida script via -P / --parameters JSON"),
	"pause?": type("boolean").describe("For spawn mode: leave main thread paused after spawning (passes --pause)"),
	"no_pause?": type("boolean").describe(
		"For spawn mode: legacy flag for starting main thread immediately (defaults to true; pass false to keep paused via --pause)",
	),
	"filter?": type("string").describe(
		"Text filter: for 'ps' matches process name/identifier; for 'modules' matches module name/path; for 'trace' matches event names",
	),
	"applications?": type("boolean").describe("For action 'ps': list only installed application processes (-a)"),
	"module?": type("string").describe(
		"Target module name (e.g. 'libnative-lib.so', 'libc.so') for trace template 'exports' or module filtering",
	),
	"template?": type
		.enumerated("module_load", "exports", "jni_register", "native_functions")
		.describe(
			"Optional trace template: 'module_load' (trace module loads), 'exports' (trace exported functions), 'jni_register' (trace JNI RegisterNatives mappings), or 'native_functions' (trace native function invocations)",
		),
	"symbol?": type("string").describe(
		"Target function symbol name for template 'native_functions' or custom JNI entry",
	),
	"symbols?": type("unknown").describe("Array of target function symbol names for template 'native_functions'"),
	"offset?": type("unknown").describe(
		"Target function offset from module base (hex string e.g. '0x1234' or number) for template 'native_functions'",
	),
	"offsets?": type("unknown").describe("Array of target function offsets for template 'native_functions'"),
	"args_count?": type("number").describe("Number of arguments to capture in native_functions template (default 4)"),
	"args_decode?": type("unknown").describe(
		"Map or array specifying argument decoding types (e.g. {'0': 'int', '1': 'string'}) for native_functions template",
	),
	"retval?": type("boolean").describe("Whether to capture return value in native_functions template (default true)"),
	"backtrace?": type("unknown").describe(
		"Whether to capture backtrace in native_functions template (true, 'accurate', 'fuzzy', or false; default false)",
	),
	"max_buffer_bytes?": type("number").describe(
		"Maximum buffer/string bytes to read per argument in native_functions template (default 256)",
	),
	"max_events?": type("number").describe(
		"Maximum trace events to capture or display in trace summary (default 100, no artificial limit)",
	),
	"cli_args?": type("unknown").describe(
		"Optional array of extra CLI arguments passed directly to the frida/frida-ps/frida-ls-devices command",
	),
	"timeout?": type("number").describe("Execution watchdog timeout in seconds (default 30, no upper limit)"),
	"max_bytes?": type("number").describe(
		"Maximum stdout bytes captured before truncation (default 262144, no upper limit)",
	),
	"to_artifact?": type("boolean").describe(
		"Save complete output and execution record to a session artifact (recommended for large outputs)",
	),
});

export type FridaParams = typeof fridaSchema.infer;
export type FridaAction = "exec" | "devices" | "ps" | "modules" | "inspect" | "trace";
export type FridaTraceTemplate = "module_load" | "exports" | "jni_register" | "native_functions" | string;

export type FridaStatus =
	| "ok"
	| "missing_dependency"
	| "device_required"
	| "device_not_found"
	| "device_unauthorized"
	| "device_offline"
	| "device_unavailable"
	| "version_mismatch"
	| "timeout"
	| "error";

export interface FridaDeviceInfo {
	id: string;
	type: "local" | "usb" | "remote" | string;
	name: string;
}

export interface FridaProcessInfo {
	pid: number;
	name: string;
	identifier?: string;
}

export interface FridaModuleInfo {
	name: string;
	base: string;
	size: number;
	path: string;
}

export interface FridaTraceEvent {
	event: "module_load" | "export" | "jni_register_natives" | "native_call" | string;
	timestamp?: number;
	module?: string;
	modulePath?: string;
	name?: string;
	type?: string;
	address?: string;
	base?: string;
	size?: number;
	path?: string;
	status?: "confirmed" | "rejected" | string;
	retval?: unknown;
	class?: string;
	target?: string;
	offset?: string;
	threadId?: number;
	nMethods?: number;
	methods?: Array<{
		name?: string | null;
		signature?: string | null;
		fnPtr?: string;
		module?: string | null;
		modulePath?: string | null;
		base?: string | null;
		offset?: string | null;
		error?: string;
		index?: number;
	}>;
	truncated?: boolean;
	source?: string;
	javaBridgeAvailable?: boolean;
	args?: unknown[];
	backtrace?: string[];
	details?: Record<string, unknown>;
	redacted?: boolean;
}

export interface FridaTraceSummary {
	template?: FridaTraceTemplate;
	target: string;
	totalEvents: number;
	returnedEvents: number;
	capped: boolean;
	redactions?: number;
	module?: string;
	base?: string;
}

export interface FridaDependencyStatus {
	id: "frida";
	available: boolean;
	path?: string;
	fridaPsPath?: string;
	fridaLsDevicesPath?: string;
	installHint?: string;
	manualUrl?: string;
}

export interface FridaFallbackInfo {
	primary: "frida";
	action: FridaAction;
	suggestedFallback: string;
	activeFallback: string;
	alternatives: string[];
	executed: false;
}

export interface FridaCleanupInfo {
	attempted: boolean;
	completed: boolean;
	treeKilled?: boolean;
	error?: string;
}

export interface FridaDetails {
	action: FridaAction;
	status: FridaStatus;
	dependency?: FridaDependencyStatus;
	fallback?: FridaFallbackInfo;
	target?: string;
	targetMode?: "attach_pid" | "attach_process" | "spawn" | "none";
	device?: string;
	host?: string;
	usb?: boolean;
	devices?: FridaDeviceInfo[];
	processes?: FridaProcessInfo[];
	modules?: FridaModuleInfo[];
	events?: FridaTraceEvent[];
	traceSummary?: FridaTraceSummary;
	scriptSource?: "inline" | "file";
	scriptPath?: string;
	exitCode?: number | null;
	stdout?: string;
	stderr?: string;
	outputBytes?: number;
	truncated?: boolean;
	timedOut?: boolean;
	artifactId?: string;
	artifactPath?: string;
	redactions?: number;
	error?: string;
	timeout?: number;
	command?: string[];
	pid?: number;
	reason?: string;
	cleanup?: FridaCleanupInfo;
}

export interface FridaRunResult {
	stdout: Uint8Array;
	stderr: string;
	exitCode: number | null;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
	killedOnOverflow?: boolean;
	pid?: number;
	command?: string[];
	timeoutMs?: number;
	reason?: string;
	cleanup?: FridaCleanupInfo;
}

export type FridaRunner = (
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs?: number;
		maxBytes?: number;
		signal?: AbortSignal;
	},
) => Promise<FridaRunResult>;

export interface FridaToolOptions {
	which?: SkillRequirementWhich;
	runner?: FridaRunner;
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const DEFAULT_MAX_BYTES = 256 * 1024;
const DEFAULT_MAX_EVENTS = 100;

/**
 * 约束并规范化超时秒数。
 * 未显式传入 timeout 时，必须回退至 DEFAULT_TIMEOUT_SECONDS (30秒) 默认看门狗，
 * 严禁返回 undefined 导致底层执行陷入无期限挂起。
 */
function clampTimeout(timeout?: number): number {
	if (timeout === undefined) return DEFAULT_TIMEOUT_SECONDS;
	if (Number.isNaN(timeout) || timeout <= 0) return DEFAULT_TIMEOUT_SECONDS;
	if (!Number.isFinite(timeout)) throw new ToolError("timeout must be a finite positive number");
	return Math.max(1, Math.round(timeout));
}

function clampMaxBytes(maxBytes?: number): number {
	if (maxBytes === undefined || Number.isNaN(maxBytes) || maxBytes <= 0) return DEFAULT_MAX_BYTES;
	if (!Number.isFinite(maxBytes)) throw new ToolError("max_bytes must be a finite positive number");
	return Math.max(1, Math.round(maxBytes));
}

function clampMaxEvents(maxEvents?: number): number {
	if (maxEvents === undefined || Number.isNaN(maxEvents) || maxEvents <= 0) return DEFAULT_MAX_EVENTS;
	if (!Number.isFinite(maxEvents)) throw new ToolError("max_events must be a finite positive number");
	return Math.round(maxEvents);
}

/** JavaScript evaluated by frida to enumerate loaded modules. */
export const FIXED_ENUMERATE_MODULES_SCRIPT =
	"console.log('__FRIDA_MODULES_START__' + JSON.stringify(Process.enumerateModules().map(function(m){return {name:m.name,base:m.base.toString(),size:m.size,path:m.path};})) + '__FRIDA_MODULES_END__');";

/** JavaScript evaluated by frida for module_load trace template. */
export const FIXED_TRACE_MODULE_LOAD_SCRIPT =
	"(function(){try{var mods=Process.enumerateModules();var res=[];for(var i=0;i<mods.length;i++){var m=mods[i];res.push({event:'module_load',timestamp:Date.now(),name:m.name,base:m.base.toString(),size:m.size,path:m.path});}console.log('__FRIDA_TRACE_START__'+JSON.stringify({totalModules:mods.length,events:res})+'__FRIDA_TRACE_END__');}catch(e){console.log('__FRIDA_TRACE_START__'+JSON.stringify({error:e.message||String(e)})+'__FRIDA_TRACE_END__');}})();";

/** JavaScript evaluated by frida for exports trace template. */
export function buildTraceExportsScript(moduleName: string, maxEvents?: number): string {
	const safeMod = JSON.stringify(moduleName);
	const limitCheck = maxEvents && maxEvents > 0 ? `&& j < ${Math.round(maxEvents)}` : "";
	return `(function(){try{var m=Process.findModuleByName(${safeMod});if(!m){var all=Process.enumerateModules();for(var i=0;i<all.length;i++){if(all[i].name.toLowerCase()===${safeMod}.toLowerCase()){m=all[i];break;}}}if(!m){console.log('__FRIDA_TRACE_START__'+JSON.stringify({error:'module_not_found',module:${safeMod}})+'__FRIDA_TRACE_END__');return;}var exps=m.enumerateExports();var res=[];for(var j=0;j<exps.length${limitCheck};j++){res.push({event:'export',module:m.name,name:exps[j].name,type:exps[j].type,address:exps[j].address.toString()});}console.log('__FRIDA_TRACE_START__'+JSON.stringify({module:m.name,base:m.base.toString(),totalExports:exps.length,events:res})+'__FRIDA_TRACE_END__');}catch(e){console.log('__FRIDA_TRACE_START__'+JSON.stringify({error:e.message||String(e)})+'__FRIDA_TRACE_END__');}})();`;
}
export interface JniRegisterNativesOptions {
	maxEvents?: number;
	maxMethods?: number;
	module?: string;
	symbol?: string;
}

/**
 * 构造用于拦截 Android JNI RegisterNatives 注册过程的 Frida 脚本。
 *
 * 核心设计准则：
 * 1. 采用 JNIEnv 函数表（table index 215）与 libart 符号双重寻址与去重；
 * 2. 优先验证 Frida 17 Java bridge 可用性；若 Java 全局不可用，直接通过 JNIEnv 虚表（NativeFunction）
 *    调用 GetObjectClass(31)、GetMethodID(33)、CallObjectMethodA(36)、GetStringUTFChars(169) 获取真实类名；
 * 3. 严格保护 JNI 异常状态：仅在 ExceptionCheck(228) 为 0 时执行反射，且仅清除自身类名探测产生的异常，不泄露 LocalRef；
 * 4. 仅在 RegisterNatives 返回值确认成功（retval === 0）时标记为 confirmed；非 0 返回值标记为 rejected；
 * 5. 避免使用全局 Interceptor.detachAll()，达到 max_events 后仅安全注销自身监听器。
 */
export function buildJniRegisterNativesScript(options: JniRegisterNativesOptions = {}): string {
	const maxEvents = clampMaxEvents(options.maxEvents);
	const maxMethods =
		options.maxMethods !== undefined && Number.isFinite(options.maxMethods) && options.maxMethods > 0
			? Math.round(options.maxMethods)
			: 500;
	const safeModule = options.module ? JSON.stringify(options.module.trim()) : "null";
	const safeSymbol = options.symbol ? JSON.stringify(options.symbol.trim()) : "null";

	return `(function() {
  var listeners = [];
  var hookedAddresses = {};
  var eventCount = 0;
  var maxEvents = ${maxEvents};
  var maxMethods = ${maxMethods};
  var explicitModule = ${safeModule};
  var explicitSymbol = ${safeSymbol};

  function cleanup() {
    for (var i = 0; i < listeners.length; i++) {
      try { listeners[i].detach(); } catch (e) {}
    }
    listeners = [];
  }

  function hookRegisterNatives(targetAddr, source) {
    if (!targetAddr || targetAddr.isNull()) return;
    var key = targetAddr.toString();
    if (hookedAddresses[key]) return;
    hookedAddresses[key] = true;

    try {
      var listener = Interceptor.attach(targetAddr, {
        onEnter: function(args) {
          if (maxEvents > 0 && eventCount >= maxEvents) return;

          var env = args[0];
          var clazz = args[1];
          var methodsPtr = args[2];
          var nMethods = args[3].toInt32();

          this.env = env;
          this.clazz = clazz;
          this.methodsPtr = methodsPtr;
          this.nMethods = nMethods;
          this.source = source;

          var className = "unknown";
          var ptrSize = Process.pointerSize;
          var javaBridgeAvailable = false;

          // 1. 优先尝试 Java bridge（如果当前运行时已加载）
          try {
            if (typeof Java !== "undefined" && Java.available) {
              javaBridgeAvailable = true;
              if (Java.vm && typeof Java.vm.getEnv === "function") {
                var jenv = Java.vm.getEnv();
                if (jenv && typeof jenv.getClassName === "function") {
                  className = jenv.getClassName(clazz);
                }
              }
            }
          } catch (e) {}

          // 2. 若无 Java bridge，直接利用 JNIEnv 函数表反射（支持纯 C / 未绑定环境）
          if (className === "unknown" && env && !env.isNull()) {
            try {
              var vtable = env.readPointer();
              var exceptionCheckPtr = vtable.add(228 * ptrSize).readPointer();
              var exceptionClearPtr = vtable.add(17 * ptrSize).readPointer();
              var getObjectClassPtr = vtable.add(31 * ptrSize).readPointer();
              var getMethodIdPtr = vtable.add(33 * ptrSize).readPointer();
              var callObjectMethodAPtr = vtable.add(36 * ptrSize).readPointer();
              var getStringUtfCharsPtr = vtable.add(169 * ptrSize).readPointer();
              var releaseStringUtfCharsPtr = vtable.add(170 * ptrSize).readPointer();
              var deleteLocalRefPtr = vtable.add(23 * ptrSize).readPointer();

              var ExceptionCheck = new NativeFunction(exceptionCheckPtr, 'uint8', ['pointer']);
              var ExceptionClear = new NativeFunction(exceptionClearPtr, 'void', ['pointer']);

              // 保留原目标挂起异常：仅当无异常时才安全调用反射 JNI
              if (ExceptionCheck(env) === 0) {
                var GetObjectClass = new NativeFunction(getObjectClassPtr, 'pointer', ['pointer', 'pointer']);
                var GetMethodID = new NativeFunction(getMethodIdPtr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
                var CallObjectMethodA = new NativeFunction(callObjectMethodAPtr, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
                var GetStringUTFChars = new NativeFunction(getStringUtfCharsPtr, 'pointer', ['pointer', 'pointer', 'pointer']);
                var ReleaseStringUTFChars = new NativeFunction(releaseStringUtfCharsPtr, 'void', ['pointer', 'pointer', 'pointer']);
                var DeleteLocalRef = new NativeFunction(deleteLocalRefPtr, 'void', ['pointer', 'pointer']);

                var classOfClass = GetObjectClass(env, clazz);
                if (classOfClass && !classOfClass.isNull()) {
                  var mName = Memory.allocUtf8String("getName");
                  var mSig = Memory.allocUtf8String("()Ljava/lang/String;");
                  var getNameMid = GetMethodID(env, classOfClass, mName, mSig);
                  if (getNameMid && !getNameMid.isNull()) {
                    var nameStr = CallObjectMethodA(env, clazz, getNameMid, ptr(0));
                    if (nameStr && !nameStr.isNull()) {
                      var isCopy = Memory.alloc(ptrSize);
                      var utfChars = GetStringUTFChars(env, nameStr, isCopy);
                      if (utfChars && !utfChars.isNull()) {
                        className = utfChars.readCString();
                        ReleaseStringUTFChars(env, nameStr, utfChars);
                      }
                      DeleteLocalRef(env, nameStr);
                    }
                  }
                  DeleteLocalRef(env, classOfClass);
                }

                // 仅清除自身反射产生的异常，避免污染目标 JNI 环境
                if (ExceptionCheck(env) !== 0) {
                  ExceptionClear(env);
                }
              } else {
                className = "pending_exception";
              }
            } catch (err) {
              // 失败降级保持 unknown
            }
          }

          // 3. 解析 JNINativeMethod 数组：包含方法名、签名、函数指针与模块偏移
          var methods = [];
          var readCount = Math.min(Math.max(0, nMethods), maxMethods);
          var truncated = nMethods > maxMethods;

          if (methodsPtr && !methodsPtr.isNull()) {
            for (var i = 0; i < readCount; i++) {
              var entryOffset = i * 3 * ptrSize;
              try {
                var namePtr = methodsPtr.add(entryOffset).readPointer();
                var sigPtr = methodsPtr.add(entryOffset + ptrSize).readPointer();
                var fnPtr = methodsPtr.add(entryOffset + 2 * ptrSize).readPointer();

                var methodName = null;
                var signature = null;
                try { if (namePtr && !namePtr.isNull()) methodName = namePtr.readCString(); } catch (e) {}
                try { if (sigPtr && !sigPtr.isNull()) signature = sigPtr.readCString(); } catch (e) {}

                var mod = null;
                try { mod = Process.findModuleByAddress(fnPtr); } catch (e) {}

                var offsetHex = null;
                if (mod && mod.base) {
                  offsetHex = "0x" + fnPtr.sub(mod.base).toString(16);
                }

                methods.push({
                  name: methodName,
                  signature: signature,
                  fnPtr: fnPtr.toString(),
                  module: mod ? mod.name : null,
                  modulePath: mod ? mod.path : null,
                  base: mod ? mod.base.toString() : null,
                  offset: offsetHex
                });
              } catch (e) {
                methods.push({ error: String(e), index: i });
              }
            }
          }

          this.parsedData = {
            className: className,
            methods: methods,
            nMethods: nMethods,
            truncated: truncated,
            javaBridgeAvailable: javaBridgeAvailable
          };
        },
        onLeave: function(retval) {
          if (!this.parsedData) return;
          if (maxEvents > 0 && eventCount >= maxEvents) return;

          eventCount++;
          var ret = retval.toInt32();
          var isSuccess = (ret === 0);

          var record = {
            event: "jni_register_natives",
            status: isSuccess ? "confirmed" : "rejected",
            retval: ret,
            class: this.parsedData.className,
            nMethods: this.parsedData.nMethods,
            methods: this.parsedData.methods,
            truncated: this.parsedData.truncated,
            source: this.source,
            javaBridgeAvailable: this.parsedData.javaBridgeAvailable,
            timestamp: Date.now()
          };

          send(record);
          console.log("__FRIDA_TRACE_START__" + JSON.stringify(record) + "__FRIDA_TRACE_END__");

          if (maxEvents > 0 && eventCount >= maxEvents) {
            cleanup();
          }
        }
      });
      listeners.push(listener);
    } catch (e) {
      console.log("__FRIDA_TRACE_START__" + JSON.stringify({ error: "attach_failed", address: targetAddr.toString(), detail: String(e) }) + "__FRIDA_TRACE_END__");
    }
  }

  function findExportAddress(modName, symName) {
    var addr = null;
    if (modName) {
      var m = Process.findModuleByName(modName);
      if (m) {
        if (typeof m.findExportByName === "function") {
          try { addr = m.findExportByName(symName); } catch (e) {}
        }
        if (!addr && typeof m.enumerateExports === "function") {
          try {
            var exps = m.enumerateExports();
            for (var i = 0; i < exps.length; i++) {
              if (exps[i].name === symName) { addr = exps[i].address; break; }
            }
          } catch (e) {}
        }
      }
      if (addr) return addr;
    }
    if (typeof Process.findExportByName === "function") {
      try { addr = Process.findExportByName(symName); } catch (e) {}
    }
    if (!addr && typeof Module !== "undefined") {
      if (modName && typeof Module.findExportByName === "function") {
        try { addr = Module.findExportByName(modName, symName); } catch (e) {}
      }
      if (!addr && typeof Module.findGlobalExportByName === "function") {
        try { addr = Module.findGlobalExportByName(symName); } catch (e) {}
      }
    }
    return addr;
  }

  function scanAndHook() {
    var candidates = [];

    // 1. 显式配置目标符号
    if (explicitSymbol) {
      var explicitAddr = findExportAddress(explicitModule, explicitSymbol);
      if (explicitAddr) {
        candidates.push({ addr: explicitAddr, source: (explicitModule || "global") + ":" + explicitSymbol });
      }
    }

    // 2. 扫描 libart.so 导出与符号（过滤 CheckJNI 重复拦截）
    var libart = Process.findModuleByName("libart.so");
    if (libart) {
      try {
        var exports = libart.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
          var exp = exports[i];
          if (exp.name === "RegisterNatives" || exp.name === "art_jni_RegisterNatives") {
            candidates.push({ addr: exp.address, source: "libart:export:" + exp.name });
          }
        }
      } catch (e) {}

      try {
        var symbols = libart.enumerateSymbols();
        for (var j = 0; j < symbols.length; j++) {
          var sym = symbols[j];
          var symName = sym.name;
          if (symName.indexOf("RegisterNatives") !== -1 &&
              symName.indexOf("CheckJNI") === -1 &&
              symName.indexOf("checkJNI") === -1 &&
              symName.indexOf("check_jni") === -1) {
            candidates.push({ addr: sym.address, source: "libart:symbol:" + symName });
          }
        }
      } catch (e) {}

      // 通过 JNI_GetCreatedJavaVMs 定位 JNIEnv 虚表 index 215
      try {
        var getCreatedVMs = findExportAddress("libart.so", "JNI_GetCreatedJavaVMs");
        if (getCreatedVMs) {
          var vmBuf = Memory.alloc(Process.pointerSize * 2);
          var nVMs = Memory.alloc(Process.pointerSize);
          var fn = new NativeFunction(getCreatedVMs, 'int', ['pointer', 'int', 'pointer']);
          var res = fn(vmBuf, 1, nVMs);
          if (res === 0) {
            var vm = vmBuf.readPointer();
            if (vm && !vm.isNull()) {
              var vmVtable = vm.readPointer();
              var getEnvFnPtr = vmVtable.add(6 * Process.pointerSize).readPointer();
              var getEnvFn = new NativeFunction(getEnvFnPtr, 'int', ['pointer', 'pointer', 'int']);
              var envBuf = Memory.alloc(Process.pointerSize);
              var envRes = getEnvFn(vm, envBuf, 0x00010006);
              if (envRes === 0 && !envBuf.readPointer().isNull()) {
                var env = envBuf.readPointer();
                var jniVtable = env.readPointer();
                var regNativesFromTable = jniVtable.add(215 * Process.pointerSize).readPointer();
                if (regNativesFromTable && !regNativesFromTable.isNull()) {
                  candidates.push({ addr: regNativesFromTable, source: "jni_env_vtable:215" });
                }
              }
            }
          }
        }
      } catch (e) {}
    }

    // 3. 显式模块导出回退
    if (explicitModule && !explicitSymbol) {
      var modReg = findExportAddress(explicitModule, "RegisterNatives");
      if (modReg) {
        candidates.push({ addr: modReg, source: explicitModule + ":RegisterNatives" });
      }
    }

    // 4. 全局导出回退
    if (!explicitSymbol) {
      var globalReg = findExportAddress(null, "RegisterNatives");
      if (globalReg) {
        candidates.push({ addr: globalReg, source: "global:RegisterNatives" });
      }
    }

    // 去重挂载拦截器
    for (var k = 0; k < candidates.length; k++) {
      hookRegisterNatives(candidates[k].addr, candidates[k].source);
    }
  }

  scanAndHook();

  // 监控动态链接器以支持延迟加载模块
  var dlopenNames = ["android_dlopen_ext", "dlopen"];
  for (var d = 0; d < dlopenNames.length; d++) {
    var dlAddr = findExportAddress(null, dlopenNames[d]);
    if (dlAddr) {
      try {
        var dlListener = Interceptor.attach(dlAddr, {
          onLeave: function() {
            scanAndHook();
          }
        });
        listeners.push(dlListener);
      } catch (e) {}
    }
  }

  rpc.exports = {
    getStatus: function() {
      return {
        eventCount: eventCount,
        maxEvents: maxEvents,
        attachedCount: listeners.length
      };
    },
    detachAll: function() {
      cleanup();
      return true;
    }
  };
})();`;
}

export interface NativeHookOptions {
	module?: string;
	symbol?: string;
	symbols?: string[];
	offset?: string | number;
	offsets?: Array<string | number>;
	argsCount?: number;
	argsDecode?: Record<string, string> | Array<{ index: number; type: string; maxBytes?: number }>;
	retval?: boolean;
	backtrace?: boolean | "accurate" | "fuzzy";
	maxEvents?: number;
	maxBufferBytes?: number;
}

/**
 * 构造用于原生函数拦截与有界参数解码的 Frida 脚本。
 *
 * 核心设计准则：
 * 1. 参数解码在各参数内独立 try/catch，防止非法指针读取中断监听器；
 * 2. 未声明类型参数使用指针十六进制表示，绝不臆造未验证类型；
 * 3. 严格计算相对于模块基址的十六进制偏移以防 64 位整型精度丢失；
 * 4. 严禁使用全局 Interceptor.detachAll()，仅注销自身注册的 listener 句柄。
 */
export function buildNativeHookScript(options: NativeHookOptions): string {
	const maxEvents = clampMaxEvents(options.maxEvents);
	const maxBufferBytes =
		options.maxBufferBytes !== undefined && Number.isFinite(options.maxBufferBytes) && options.maxBufferBytes > 0
			? Math.round(options.maxBufferBytes)
			: 256;
	const argsCount =
		options.argsCount !== undefined && Number.isFinite(options.argsCount) && options.argsCount >= 0
			? Math.round(options.argsCount)
			: 4;
	const captureRetval = options.retval !== false;
	const captureBacktrace =
		options.backtrace === true || options.backtrace === "accurate"
			? "'accurate'"
			: options.backtrace === "fuzzy"
				? "'fuzzy'"
				: "false";

	const symbols: string[] = [];
	if (options.symbol && options.symbol.trim().length > 0) symbols.push(options.symbol.trim());
	if (Array.isArray(options.symbols)) {
		for (const s of options.symbols) {
			if (typeof s === "string" && s.trim().length > 0 && !symbols.includes(s.trim())) {
				symbols.push(s.trim());
			}
		}
	}

	const offsets: string[] = [];
	if (options.offset !== undefined) {
		const s = String(options.offset).trim();
		if (s.length > 0 && !offsets.includes(s)) offsets.push(s);
	}
	if (Array.isArray(options.offsets)) {
		for (const o of options.offsets) {
			const s = String(o).trim();
			if (s.length > 0 && !offsets.includes(s)) offsets.push(s);
		}
	}

	const argsDecodeMap: Record<string, string> = {};
	if (options.argsDecode && typeof options.argsDecode === "object") {
		if (Array.isArray(options.argsDecode)) {
			for (const item of options.argsDecode) {
				if (item && typeof item === "object" && typeof item.index === "number" && typeof item.type === "string") {
					argsDecodeMap[String(item.index)] = item.type;
				}
			}
		} else {
			for (const [k, v] of Object.entries(options.argsDecode)) {
				if (typeof v === "string") {
					argsDecodeMap[k] = v;
				}
			}
		}
	}

	const safeModule = options.module ? JSON.stringify(options.module.trim()) : "null";
	const safeSymbols = JSON.stringify(symbols);
	const safeOffsets = JSON.stringify(offsets);
	const safeDecode = JSON.stringify(argsDecodeMap);

	return `(function() {
  var listeners = [];
  var hookedAddresses = {};
  var eventCount = 0;
  var maxEvents = ${maxEvents};
  var maxBufferBytes = ${maxBufferBytes};
  var argsCount = ${argsCount};
  var captureRetval = ${captureRetval};
  var backtraceMode = ${captureBacktrace};
  var targetModule = ${safeModule};
  var targetSymbols = ${safeSymbols};
  var targetOffsets = ${safeOffsets};
  var argsDecode = ${safeDecode};

  function cleanup() {
    for (var i = 0; i < listeners.length; i++) {
      try { listeners[i].detach(); } catch (e) {}
    }
    listeners = [];
  }

  function hookTarget(targetAddr, targetName) {
    if (!targetAddr || targetAddr.isNull()) return;
    var key = targetAddr.toString();
    if (hookedAddresses[key]) return;
    hookedAddresses[key] = true;

    try {
      var listener = Interceptor.attach(targetAddr, {
        onEnter: function(args) {
          if (maxEvents > 0 && eventCount >= maxEvents) return;

          var capturedArgs = [];
          for (var i = 0; i < argsCount; i++) {
            var val = args[i];
            var type = argsDecode[String(i)] || "pointer";
            var decoded = null;

            try {
              if (!val) {
                decoded = "0x0";
              } else if (type === "int") {
                decoded = val.toInt32();
              } else if (type === "uint") {
                decoded = val.toUInt32();
              } else if (type === "int64" || type === "uint64") {
                decoded = val.toString();
              } else if (type === "string" || type === "utf8") {
                if (val.isNull()) {
                  decoded = null;
                } else {
                  decoded = val.readUtf8String(maxBufferBytes);
                }
              } else if (type === "utf16") {
                if (val.isNull()) {
                  decoded = null;
                } else {
                  decoded = val.readUtf16String(maxBufferBytes);
                }
              } else if (type === "buffer" || type === "hexdump") {
                if (val.isNull()) {
                  decoded = null;
                } else {
                  var bufLen = Math.min(maxBufferBytes, 64);
                  decoded = {
                    pointer: val.toString(),
                    hexdump: hexdump(val, { length: bufLen, header: false })
                  };
                }
              } else {
                decoded = val.toString();
              }
            } catch (err) {
              decoded = {
                error: String(err),
                raw: val ? val.toString() : "0x0"
              };
            }
            capturedArgs.push(decoded);
          }

          var bt = [];
          if (backtraceMode && backtraceMode !== 'false') {
            try {
              var mode = (backtraceMode === "fuzzy") ? Backtracer.FUZZY : Backtracer.ACCURATE;
              bt = Thread.backtrace(this.context, mode).map(DebugSymbol.fromAddress).map(function(s) {
                return s.toString();
              });
            } catch (e) {}
          }

          var mod = null;
          try { mod = Process.findModuleByAddress(targetAddr); } catch (e) {}
          var offsetHex = null;
          if (mod && mod.base) {
            offsetHex = "0x" + targetAddr.sub(mod.base).toString(16);
          }

          this.callData = {
            target: targetName,
            address: targetAddr.toString(),
            module: mod ? mod.name : null,
            modulePath: mod ? mod.path : null,
            base: mod ? mod.base.toString() : null,
            offset: offsetHex,
            threadId: Process.getCurrentThreadId(),
            timestamp: Date.now(),
            args: capturedArgs,
            backtrace: bt
          };
        },
        onLeave: function(retval) {
          if (!this.callData) return;
          if (maxEvents > 0 && eventCount >= maxEvents) return;

          eventCount++;
          var retStr = null;
          if (captureRetval && retval) {
            try {
              retStr = retval.toString();
            } catch (e) {
              retStr = "unknown";
            }
          }

          var record = {
            event: "native_call",
            target: this.callData.target,
            address: this.callData.address,
            module: this.callData.module,
            modulePath: this.callData.modulePath,
            base: this.callData.base,
            offset: this.callData.offset,
            threadId: this.callData.threadId,
            timestamp: this.callData.timestamp,
            args: this.callData.args,
            retval: retStr,
            backtrace: this.callData.backtrace
          };

          send(record);
          console.log("__FRIDA_TRACE_START__" + JSON.stringify(record) + "__FRIDA_TRACE_END__");

          if (maxEvents > 0 && eventCount >= maxEvents) {
            cleanup();
          }
        }
      });
      listeners.push(listener);
    } catch (e) {
      console.log("__FRIDA_TRACE_START__" + JSON.stringify({ error: "attach_failed", target: targetName, address: targetAddr.toString(), detail: String(e) }) + "__FRIDA_TRACE_END__");
    }
  }

  function findExportAddress(modName, symName) {
    var addr = null;
    if (modName) {
      var m = Process.findModuleByName(modName);
      if (m) {
        if (typeof m.findExportByName === "function") {
          try { addr = m.findExportByName(symName); } catch (e) {}
        }
        if (!addr && typeof m.enumerateExports === "function") {
          try {
            var exps = m.enumerateExports();
            for (var i = 0; i < exps.length; i++) {
              if (exps[i].name === symName) { addr = exps[i].address; break; }
            }
          } catch (e) {}
        }
      }
      if (addr) return addr;
    }
    if (typeof Process.findExportByName === "function") {
      try { addr = Process.findExportByName(symName); } catch (e) {}
    }
    if (!addr && typeof Module !== "undefined") {
      if (modName && typeof Module.findExportByName === "function") {
        try { addr = Module.findExportByName(modName, symName); } catch (e) {}
      }
      if (!addr && typeof Module.findGlobalExportByName === "function") {
        try { addr = Module.findGlobalExportByName(symName); } catch (e) {}
      }
    }
    return addr;
  }

  function scanAndHook() {
    var mod = targetModule ? Process.findModuleByName(targetModule) : null;

    // 1. 拦截符号
    for (var s = 0; s < targetSymbols.length; s++) {
      var symName = targetSymbols[s];
      var symAddr = findExportAddress(targetModule, symName);
      if (symAddr) {
        hookTarget(symAddr, symName);
      }
    }

    // 2. 拦截偏移（要求模块已解析）
    if (mod && mod.base) {
      for (var o = 0; o < targetOffsets.length; o++) {
        var offVal = targetOffsets[o];
        try {
          var offNum = offVal.startsWith("0x") ? parseInt(offVal, 16) : parseInt(offVal, 10);
          if (!isNaN(offNum)) {
            var targetAddr = mod.base.add(offNum);
            hookTarget(targetAddr, mod.name + "+" + offVal);
          }
        } catch (e) {}
      }
    }
  }

  scanAndHook();

  // 监控动态链接器以支持延迟加载模块
  var dlopenNames = ["android_dlopen_ext", "dlopen"];
  for (var d = 0; d < dlopenNames.length; d++) {
    var dlAddr = findExportAddress(null, dlopenNames[d]);
    if (dlAddr) {
      try {
        var dlListener = Interceptor.attach(dlAddr, {
          onLeave: function() {
            scanAndHook();
          }
        });
        listeners.push(dlListener);
      } catch (e) {}
    }
  }

  rpc.exports = {
    getStatus: function() {
      return {
        eventCount: eventCount,
        maxEvents: maxEvents,
        attachedCount: listeners.length
      };
    },
    detachAll: function() {
      cleanup();
      return true;
    }
  };
})();`;
}

/**
 * 根据统一的模板参数解析生成的 Frida 脚本源码。
 */
export function resolveTemplateScript(params: {
	template?: string;
	module?: string;
	symbol?: string;
	symbols?: unknown;
	offset?: unknown;
	offsets?: unknown;
	args_count?: number;
	args_decode?: unknown;
	retval?: boolean;
	backtrace?: unknown;
	max_events?: number;
	max_buffer_bytes?: number;
}): string {
	const template = params.template;
	if (template === "jni_register") {
		return buildJniRegisterNativesScript({
			maxEvents: params.max_events,
			module: params.module,
			symbol: params.symbol,
		});
	}
	if (template === "native_functions") {
		return buildNativeHookScript({
			module: params.module,
			symbol: params.symbol,
			symbols: Array.isArray(params.symbols) ? (params.symbols as string[]) : undefined,
			offset: params.offset as string | number | undefined,
			offsets: Array.isArray(params.offsets) ? (params.offsets as Array<string | number>) : undefined,
			argsCount: params.args_count,
			argsDecode: params.args_decode as Record<string, string> | undefined,
			retval: params.retval,
			backtrace: params.backtrace as boolean | "accurate" | "fuzzy" | undefined,
			maxEvents: params.max_events,
			maxBufferBytes: params.max_buffer_bytes,
		});
	}
	if (template === "exports") {
		if (params.module) {
			return buildTraceExportsScript(params.module.trim(), params.max_events);
		}
		return FIXED_ENUMERATE_MODULES_SCRIPT;
	}
	if (template === "module_load") {
		return FIXED_TRACE_MODULE_LOAD_SCRIPT;
	}
	throw new ToolError(
		`Unknown template '${template}'. Choose from: 'module_load', 'exports', 'jni_register', 'native_functions'`,
	);
}

export function splitCliArgs(str: string): string[] {
	const matches = str.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g);
	if (!matches) return [];
	return matches.map(arg => {
		if ((arg.startsWith('"') && arg.endsWith('"')) || (arg.startsWith("'") && arg.endsWith("'"))) {
			return arg.slice(1, -1);
		}
		return arg;
	});
}

/**
 * Safely parses a Python literal value (dict, list, tuple, string, number, bool, None)
 * or JSON value without code execution/eval.
 */
export function parsePythonLiteral(
	input: string,
	startIndex = 0,
	options: { requireEnd?: boolean; maxDepth?: number } = {},
): { value: unknown; end: number } {
	const maxDepth = options.maxDepth ?? 64;
	let depth = 0;
	let i = startIndex;
	const len = input.length;

	if (len > 1024 * 1024) {
		throw new SyntaxError("Input exceeds maximum length limit");
	}

	function skipWhitespace() {
		while (i < len) {
			const c = input.charCodeAt(i);
			if (c === 32 || c === 9 || c === 10 || c === 13 || c === 0x2028 || c === 0x2029) {
				i++;
			} else {
				break;
			}
		}
	}

	function parseValue(): unknown {
		skipWhitespace();
		if (i >= len) throw new SyntaxError("Unexpected end of input");

		const ch = input[i];

		if (ch === "{") return parseDict();
		if (ch === "[") return parseList();
		if (ch === "(") return parseTuple();
		if (ch === "'" || ch === '"') return parseString();

		// Number check: digit, or leading sign followed by digit or dot
		if (
			(ch >= "0" && ch <= "9") ||
			((ch === "-" || ch === "+") &&
				i + 1 < len &&
				((input[i + 1] >= "0" && input[i + 1] <= "9") || input[i + 1] === ".")) ||
			(ch === "." && i + 1 < len && input[i + 1] >= "0" && input[i + 1] <= "9")
		) {
			return parseNumber();
		}

		// String prefix: b', r', u', etc.
		if (
			(ch === "b" || ch === "B" || ch === "r" || ch === "R" || ch === "u" || ch === "U") &&
			i + 1 < len &&
			(input[i + 1] === "'" || input[i + 1] === '"')
		) {
			const isRaw = ch === "r" || ch === "R";
			i++;
			return parseString(isRaw);
		}

		// Identifier / Constant
		const idStart = i;
		while (i < len && /[a-zA-Z0-9_$]/.test(input[i])) {
			i++;
		}
		const id = input.slice(idStart, i);
		if (id === "True" || id === "true") return true;
		if (id === "False" || id === "false") return false;
		if (id === "None" || id === "null") return null;
		if (id === "undefined") return undefined;
		if (id === "nan" || id === "NaN") return Number.NaN;
		if (id === "inf" || id === "Infinity") return Number.POSITIVE_INFINITY;

		throw new SyntaxError(`Unexpected token '${id || ch}' at position ${idStart}`);
	}

	function parseString(isRaw = false): string {
		const quote = input[i];
		// Check for triple quotes
		let isTriple = false;
		if (i + 2 < len && input[i + 1] === quote && input[i + 2] === quote) {
			isTriple = true;
			i += 3;
		} else {
			i++;
		}

		let res = "";
		while (i < len) {
			if (isTriple) {
				if (input[i] === quote && i + 2 < len && input[i + 1] === quote && input[i + 2] === quote) {
					i += 3;
					return res;
				}
			} else if (input[i] === quote) {
				i++;
				return res;
			}

			if (input[i] === "\\") {
				if (isRaw) {
					res += "\\";
					i++;
					if (i < len && input[i] === quote) {
						res += quote;
						i++;
					}
					continue;
				}
				i++;
				if (i >= len) throw new SyntaxError("Unterminated string escape sequence");
				const esc = input[i++];
				switch (esc) {
					case "'":
						res += "'";
						break;
					case '"':
						res += '"';
						break;
					case "\\":
						res += "\\";
						break;
					case "/":
						res += "/";
						break;
					case "n":
						res += "\n";
						break;
					case "r":
						res += "\r";
						break;
					case "t":
						res += "\t";
						break;
					case "b":
						res += "\b";
						break;
					case "f":
						res += "\f";
						break;
					case "v":
						res += "\v";
						break;
					case "0":
						res += "\0";
						break;
					case "x": {
						const hex = input.slice(i, i + 2);
						if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new SyntaxError(`Invalid hex escape \\x${hex}`);
						i += 2;
						res += String.fromCharCode(Number.parseInt(hex, 16));
						break;
					}
					case "u": {
						const hex = input.slice(i, i + 4);
						if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new SyntaxError(`Invalid unicode escape \\u${hex}`);
						i += 4;
						res += String.fromCharCode(Number.parseInt(hex, 16));
						break;
					}
					case "U": {
						const hex = input.slice(i, i + 8);
						if (!/^[0-9a-fA-F]{8}$/.test(hex)) throw new SyntaxError(`Invalid unicode escape \\U${hex}`);
						i += 8;
						const codePoint = Number.parseInt(hex, 16);
						if (codePoint < 0 || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
							throw new SyntaxError(`Invalid unicode code point \\U${hex}`);
						}
						res += String.fromCodePoint(codePoint);
						break;
					}
					default:
						res += esc;
				}
			} else {
				res += input[i++];
			}
		}
		throw new SyntaxError("Unterminated string");
	}

	function parseNumber(): number {
		const start = i;
		if (input[i] === "-" || input[i] === "+") i++;

		// Hex, Octal, Binary
		if (input[i] === "0" && i + 1 < len) {
			const next = input[i + 1].toLowerCase();
			if (next === "x") {
				i += 2;
				const hexStart = i;
				while (i < len && /[0-9a-fA-F]/.test(input[i])) i++;
				if (i === hexStart) throw new SyntaxError("Invalid hex number");
				const sign = input[start] === "-" ? -1 : 1;
				return sign * Number.parseInt(input.slice(hexStart, i), 16);
			}
			if (next === "o") {
				i += 2;
				const octStart = i;
				while (i < len && /[0-7]/.test(input[i])) i++;
				if (i === octStart) throw new SyntaxError("Invalid octal number");
				const sign = input[start] === "-" ? -1 : 1;
				return sign * Number.parseInt(input.slice(octStart, i), 8);
			}
			if (next === "b") {
				i += 2;
				const binStart = i;
				while (i < len && (input[i] === "0" || input[i] === "1")) i++;
				if (i === binStart) throw new SyntaxError("Invalid binary number");
				const sign = input[start] === "-" ? -1 : 1;
				return sign * Number.parseInt(input.slice(binStart, i), 2);
			}
		}

		while (i < len && input[i] >= "0" && input[i] <= "9") i++;
		if (i < len && input[i] === ".") {
			i++;
			while (i < len && input[i] >= "0" && input[i] <= "9") i++;
		}
		if (i < len && (input[i] === "e" || input[i] === "E")) {
			i++;
			if (i < len && (input[i] === "+" || input[i] === "-")) i++;
			while (i < len && input[i] >= "0" && input[i] <= "9") i++;
		}
		const numStr = input.slice(start, i);
		const num = Number(numStr);
		if (Number.isNaN(num)) throw new SyntaxError(`Invalid number: ${numStr}`);
		return num;
	}

	function parseDict(): Record<string, unknown> {
		depth++;
		if (depth > maxDepth) throw new SyntaxError("Maximum recursion depth exceeded");
		try {
			i++; // skip '{'
			const obj: Record<string, unknown> = Object.create(null);
			skipWhitespace();
			if (i < len && input[i] === "}") {
				i++;
				return obj;
			}

			while (i < len) {
				skipWhitespace();
				if (input[i] === "}") {
					i++;
					return obj;
				}
				// Parse key: string, identifier, or scalar primitive
				let key: string;
				if (input[i] === "'" || input[i] === '"') {
					key = parseString();
				} else if (input[i] === "{" || input[i] === "[" || input[i] === "(") {
					// Compound keys are rejected outright to prevent prototype/amplification attacks
					throw new SyntaxError("Dictionary keys must be scalar primitives");
				} else if (/[a-zA-Z_$]/.test(input[i])) {
					const idStart = i;
					while (i < len && /[a-zA-Z0-9_$]/.test(input[i])) i++;
					const id = input.slice(idStart, i);
					if (id === "True" || id === "true") key = "true";
					else if (id === "False" || id === "false") key = "false";
					else if (id === "None" || id === "null") key = "null";
					else key = id;
				} else {
					const rawKey = parseValue();
					if (rawKey !== null && typeof rawKey === "object") {
						throw new SyntaxError("Dictionary keys must be scalar primitives");
					}
					key = String(rawKey);
				}

				skipWhitespace();
				if (i >= len || input[i] !== ":") {
					throw new SyntaxError(`Expected ':' at position ${i}, got '${input[i] ?? ""}'`);
				}
				i++; // skip ':'

				const val = parseValue();
				Object.defineProperty(obj, key, {
					value: val,
					writable: true,
					enumerable: true,
					configurable: true,
				});

				skipWhitespace();
				if (input[i] === ",") {
					i++;
					skipWhitespace();
				} else if (input[i] === "}") {
					i++;
					return obj;
				} else {
					throw new SyntaxError(`Expected ',' or '}' at position ${i}, got '${input[i] ?? ""}'`);
				}
			}
			throw new SyntaxError("Unterminated dictionary");
		} finally {
			depth--;
		}
	}

	function parseList(): unknown[] {
		depth++;
		if (depth > maxDepth) throw new SyntaxError("Maximum recursion depth exceeded");
		try {
			i++; // skip '['
			const arr: unknown[] = [];
			skipWhitespace();
			if (i < len && input[i] === "]") {
				i++;
				return arr;
			}

			while (i < len) {
				skipWhitespace();
				if (input[i] === "]") {
					i++;
					return arr;
				}
				const val = parseValue();
				arr.push(val);

				skipWhitespace();
				if (input[i] === ",") {
					i++;
					skipWhitespace();
				} else if (input[i] === "]") {
					i++;
					return arr;
				} else {
					throw new SyntaxError(`Expected ',' or ']' at position ${i}, got '${input[i] ?? ""}'`);
				}
			}
			throw new SyntaxError("Unterminated list");
		} finally {
			depth--;
		}
	}

	function parseTuple(): unknown[] {
		depth++;
		if (depth > maxDepth) throw new SyntaxError("Maximum recursion depth exceeded");
		try {
			i++; // skip '('
			const arr: unknown[] = [];
			skipWhitespace();
			if (i < len && input[i] === ")") {
				i++;
				return arr;
			}

			while (i < len) {
				skipWhitespace();
				if (input[i] === ")") {
					i++;
					return arr;
				}
				const val = parseValue();
				arr.push(val);

				skipWhitespace();
				if (input[i] === ",") {
					i++;
					skipWhitespace();
				} else if (input[i] === ")") {
					i++;
					return arr;
				} else {
					throw new SyntaxError(`Expected ',' or ')' at position ${i}, got '${input[i] ?? ""}'`);
				}
			}
			throw new SyntaxError("Unterminated tuple");
		} finally {
			depth--;
		}
	}

	const value = parseValue();
	if (options.requireEnd) {
		skipWhitespace();
		if (i < len) {
			throw new SyntaxError(`Unexpected trailing text at position ${i}: '${input.slice(i, i + 30)}'`);
		}
	}
	return { value, end: i };
}
function redactTraceValue(val: unknown): { value: unknown; redactions: number } {
	if (typeof val === "string") {
		const redacted = redactMemorySecrets(val);
		return { value: redacted, redactions: redacted !== val ? 1 : 0 };
	}
	if (Array.isArray(val)) {
		let total = 0;
		const out = val.map(item => {
			const res = redactTraceValue(item);
			total += res.redactions;
			return res.value;
		});
		return { value: out, redactions: total };
	}
	if (val && typeof val === "object") {
		let total = 0;
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(val)) {
			const res = redactTraceValue(v);
			total += res.redactions;
			out[k] = res.value;
		}
		return { value: out, redactions: total };
	}
	return { value: val, redactions: 0 };
}

export function redactTraceEvent(event: FridaTraceEvent): { event: FridaTraceEvent; redactions: number } {
	let totalRedactions = 0;
	const cloned: FridaTraceEvent = { ...event };

	const stringKeys = ["name", "path", "address", "base", "class", "target", "offset", "type"] as const;
	for (const key of stringKeys) {
		const val = cloned[key];
		if (typeof val === "string") {
			const redacted = redactMemorySecrets(val);
			if (redacted !== val) {
				totalRedactions++;
				cloned[key] = redacted;
			}
		}
	}

	if (cloned.details) {
		const res = redactTraceValue(cloned.details);
		cloned.details = res.value as unknown as Record<string, unknown>;
		totalRedactions += res.redactions;
	}

	if (cloned.methods) {
		const res = redactTraceValue(cloned.methods);
		cloned.methods = res.value as unknown as FridaTraceEvent["methods"];
		totalRedactions += res.redactions;
	}

	if (cloned.args) {
		const res = redactTraceValue(cloned.args);
		cloned.args = res.value as unknown as unknown[];
		totalRedactions += res.redactions;
	}

	if (totalRedactions > 0) {
		cloned.redacted = true;
	}

	return { event: cloned, redactions: totalRedactions };
}

export function redactTraceEvents(events: FridaTraceEvent[]): { events: FridaTraceEvent[]; redactions: number } {
	let totalRedactions = 0;
	const redactedList = events.map(ev => {
		const res = redactTraceEvent(ev);
		totalRedactions += res.redactions;
		return res.event;
	});
	return { events: redactedList, redactions: totalRedactions };
}
export function resolveScriptPath(rawPath: string, cwd: string): string {
	let expanded = rawPath.trim();
	if (expanded.startsWith("~/") || expanded === "~") {
		expanded = path.join(os.homedir(), expanded.slice(1));
	}
	return path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(cwd, expanded);
}

/**
 * 针对本次调用拥有的完整子进程树执行有界回收清理。
 *
 * 说明：
 * 1. Windows 下 exe 包装器（如 frida-ls-devices.exe）衍生出的 python.exe 会继承 stdio 管道句柄，
 *    若只杀外层，python.exe 残留且管道不关闭会导致读取 EOF 无限阻塞；
 * 2. Windows 严格利用派生初期持有的 rootProcess 原生稳定句柄（Toolhelp32 快照）执行递归整树终结，
 *    绝不重新解析原始 PID，避免 Windows 内核重用 PID 导致误伤无关进程；
 * 3. 严格限定在本次调用拥有的 child 进程树范围，不波及 reverse 宿主、ADB server 或模拟器；
 * 4. POSIX 下子进程以 detached: true 派生，拥有独立进程组（PGID == pid）。无论根进程是否已先退出，
 *    无条件向 -pid 发送 SIGKILL 终结由继承管道孤儿维持活跃的完整会话组，辅以原生句柄兜底。
 */
export async function cleanupChildProcessTree(pid: number, rootProcess?: Process): Promise<FridaCleanupInfo> {
	let completed = false;
	let treeKilled = false;
	let cleanupError: string | undefined;

	try {
		if (process.platform === "win32") {
			// Windows: 利用派生时锁定的 Process 原生稳定句柄递归终结整棵子进程树
			if (rootProcess) {
				try {
					// 1. rootProcess.killTree() 即使根进程已退出，也会通过底层 Toolhelp 快照信号整棵子树
					const count = rootProcess.killTree();
					if (count > 0) treeKilled = true;
				} catch {}
				try {
					// 2. 根进程已退出时，terminate 会早退；但 rootProcess.children() 带有 creationTime 保护，
					// 可以安全枚举孤儿后代，针对每个存活的直接子节点递归调用 terminate
					const children = rootProcess.children();
					if (children.length > 0) {
						await Promise.allSettled(children.map(child => child.terminate({ gracefulMs: -1, timeoutMs: 1000 })));
						treeKilled = true;
					}
				} catch {}
				try {
					// 3. 根节点 terminate 兜底
					completed = await rootProcess.terminate({
						gracefulMs: -1,
						timeoutMs: 1000,
					});
					treeKilled = true;
				} catch (err: unknown) {
					cleanupError = String(err);
				}
			}
		} else {
			// POSIX: 子进程以 detached 独立进程组派生，即便根进程已死，继承管道的孤儿后代依然归属该 PGID。
			// 无条件向 -pid 发送 SIGKILL 彻底清空整个进程组
			try {
				process.kill(-pid, "SIGKILL");
				treeKilled = true;
				completed = true;
			} catch (err: unknown) {
				if (typeof err === "object" && err !== null && "code" in err && err.code !== "ESRCH") {
					cleanupError = String(err);
				}
			}
			if (rootProcess) {
				try {
					const children = rootProcess.children();
					if (children.length > 0) {
						await Promise.allSettled(
							children.map(child => child.terminate({ gracefulMs: -1, timeoutMs: 1000, group: true })),
						);
						treeKilled = true;
					}
				} catch {}
				try {
					await rootProcess.terminate({
						gracefulMs: -1,
						timeoutMs: 1000,
						group: true,
					});
					treeKilled = true;
					completed = true;
				} catch {}
			}
			try {
				process.kill(pid, "SIGKILL");
				treeKilled = true;
			} catch {}
		}
	} catch (err) {
		cleanupError = String(err);
	}

	return {
		attempted: true,
		completed,
		treeKilled,
		...(cleanupError ? { error: cleanupError } : {}),
	};
}

export async function defaultFridaRunner(
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs?: number;
		maxBytes?: number;
		signal?: AbortSignal;
	},
): Promise<FridaRunResult> {
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const maxStderrBytes = Math.min(maxBytes, 64 * 1024);
	const isWindows = process.platform === "win32";
	// 未传 timeoutMs 时默认使用文档约定的 30 秒看门狗
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_SECONDS * 1000;

	// 派生子进程：POSIX 下使用 detached: true 建立独立会话组便于整组清理
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
		windowsHide: true,
		detached: !isWindows,
	});

	const pid = child.pid;
	// Windows 下立即通过 Process.fromPid 锁定原生句柄保留 PID 标识，防止启动器提前退出后无法枚举子树
	const rootProcess = Process.fromPid(pid) ?? undefined;

	let timedOut = false;
	let aborted = false;
	let isCutoff = false;
	let cleanupInfo: FridaCleanupInfo | undefined;

	const stdoutChunks: Uint8Array[] = [];
	const stderrChunks: Uint8Array[] = [];
	let stdoutBytes = 0;
	let stderrBytes = 0;
	let truncated = false;

	const stdoutReader = child.stdout.getReader();
	const stderrReader = child.stderr.getReader();

	// 管道切断：使用 150ms 超时竞态，防止 Windows 管道被锁死时 reader.cancel 无限挂起
	const cutOffPipes = async () => {
		isCutoff = true;
		try {
			await Promise.race([
				Promise.allSettled([stdoutReader.cancel().catch(() => {}), stderrReader.cancel().catch(() => {})]),
				Bun.sleep(150),
			]);
		} catch {}
	};

	// 幂等的有界清理：并行/先杀死进程树以促使内核关闭写端句柄，再取消读取器
	let cleanupPromise: Promise<FridaCleanupInfo> | undefined;
	const performCleanup = (): Promise<FridaCleanupInfo> => {
		if (!cleanupPromise) {
			cleanupPromise = (async () => {
				const cleanupP = cleanupChildProcessTree(pid, rootProcess);
				const cutoffP = cutOffPipes();
				const [info] = await Promise.all([cleanupP, cutoffP]);
				cleanupInfo = info;
				return info;
			})();
		}
		return cleanupPromise;
	};

	let timer: NodeJS.Timeout | undefined;
	const { promise: watchdogPromise, resolve: triggerWatchdog } = Promise.withResolvers<"timeout" | "abort">();

	if (timeoutMs > 0) {
		timer = setTimeout(() => {
			timedOut = true;
			triggerWatchdog("timeout");
		}, timeoutMs);
		timer.unref?.();
	}

	const onAbort = () => {
		aborted = true;
		triggerWatchdog("abort");
	};

	if (options.signal) {
		if (options.signal.aborted) {
			aborted = true;
			triggerWatchdog("abort");
		} else {
			options.signal.addEventListener("abort", onAbort, { once: true });
		}
	}

	// 增量收集 stdout，遇到 cutoff 立即退出循环
	const readStdout = (async () => {
		try {
			while (!isCutoff) {
				const { done, value } = await stdoutReader.read();
				if (done || !value) break;
				stdoutBytes += value.byteLength;
				if (stdoutBytes <= maxBytes * 2) {
					stdoutChunks.push(value);
				} else {
					truncated = true;
				}
			}
		} catch {
		} finally {
			try {
				stdoutReader.releaseLock();
			} catch {}
		}
	})();

	// 增量收集 stderr，上限约束在 maxStderrBytes
	const readStderr = (async () => {
		try {
			while (!isCutoff) {
				const { done, value } = await stderrReader.read();
				if (done || !value) break;
				stderrBytes += value.byteLength;
				if (stderrBytes <= maxStderrBytes) {
					stderrChunks.push(value);
				}
			}
		} catch {
		} finally {
			try {
				stderrReader.releaseLock();
			} catch {}
		}
	})();

	// 监控子进程正常退出与管道释放；若子进程已退出但子代孤儿进程残留管道，给 500ms 宽限后清理整树
	const exitPromise = child.exited
		.catch(() => null)
		.then(async code => {
			const pipesSettled = await Promise.race([
				Promise.all([readStdout, readStderr]).then(() => true),
				Bun.sleep(500).then(() => false),
			]);
			if (!pipesSettled) {
				await performCleanup();
			}
			return code;
		});

	// 竞态调度：正常完成 vs 看门狗超时 vs 用户取消
	const outcome = await Promise.race([
		exitPromise.then(code => ({ type: "exit" as const, code })),
		watchdogPromise.then(type => ({ type })),
	]);

	clearTimeout(timer);
	if (options.signal) options.signal.removeEventListener("abort", onAbort);

	let exitCode: number | null = null;

	if (outcome.type === "exit") {
		exitCode = outcome.code;
	} else {
		// 超时或被取消，执行有界清理
		await performCleanup();
		const raced = await Promise.race([child.exited.catch(() => null), Bun.sleep(500).then(() => null)]);
		exitCode = typeof raced === "number" ? raced : null;
	}

	// 组装收集到的全部输出
	const stdoutTotalLength = stdoutChunks.reduce((acc, c) => acc + c.byteLength, 0);
	const stdout = new Uint8Array(stdoutTotalLength);
	let offset = 0;
	for (const chunk of stdoutChunks) {
		stdout.set(chunk, offset);
		offset += chunk.byteLength;
	}

	const stderrBuffer = Buffer.concat(stderrChunks);
	const stderr = stderrBuffer.toString("utf8");

	// 用户取消时清理完毕后抛出 ToolError，附带取消上下文与诊断
	if (aborted || options.signal?.aborted) {
		const cancelContext: Record<string, unknown> = {
			command: [binary, ...args],
			pid,
			timeoutMs,
			stdout: Buffer.from(stdout).toString("utf8"),
			stderr,
			outputBytes: stdoutBytes,
			cleanup: cleanupInfo,
			reason: "Operation cancelled",
		};
		logger.info("Frida execution cancelled", cancelContext);
		throwIfAborted(options.signal);
		throw new ToolError("Execution cancelled by caller", cancelContext);
	}
	return {
		stdout,
		stderr,
		exitCode,
		outputBytes: stdoutBytes,
		truncated: truncated || stdoutBytes > maxBytes,
		timedOut,
		pid,
		command: [binary, ...args],
		timeoutMs,
		reason: timedOut ? `Execution watchdog timed out after ${Math.round(timeoutMs / 1000)}s` : undefined,
		cleanup: cleanupInfo,
	};
}

export function fridaDependency(which?: SkillRequirementWhich): FridaDependencyStatus {
	const resolveWhich: SkillRequirementWhich = which ?? $which;
	const requirements: ToolRequirement[] = [{ id: "frida" }];
	const [status] = checkToolRequirements(requirements, { which: resolveWhich });
	let found = status?.foundPath ?? null;
	const fridaPsPath = resolveWhich("frida-ps") ?? (found?.endsWith("frida-ps") ? found : undefined);
	const fridaLsDevicesPath =
		resolveWhich("frida-ls-devices") ?? (found?.endsWith("frida-ls-devices") ? found : undefined);
	const fridaBinary = resolveWhich("frida") ?? undefined;
	const fridaPath =
		fridaBinary ?? (found && !found.endsWith("frida-ps") && !found.endsWith("frida-ls-devices") ? found : undefined);
	if (!found) {
		found = fridaPath ?? fridaPsPath ?? fridaLsDevicesPath ?? null;
	}
	const available = found !== null;
	const platform: SkillToolPlatform =
		process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
	const catalogHint = SKILL_TOOL_CATALOG.frida?.installHints?.[platform]?.join(" or ");
	const installHint = status?.hint ?? (available ? undefined : catalogHint);

	return {
		id: "frida",
		available,
		...(available && fridaPath ? { path: fridaPath } : {}),
		...(fridaPsPath ? { fridaPsPath } : {}),
		...(fridaLsDevicesPath ? { fridaLsDevicesPath } : {}),
		...(installHint && !available ? { installHint } : {}),
		...(SKILL_TOOL_CATALOG.frida?.manualUrl ? { manualUrl: SKILL_TOOL_CATALOG.frida.manualUrl } : {}),
	};
}

export function resolveFridaFallback(
	action: FridaAction,
	_options: { process?: string; pid?: number; filter?: string } = {},
): FridaFallbackInfo {
	switch (action) {
		case "devices":
			return {
				primary: "frida",
				action,
				suggestedFallback: "adb devices -l",
				activeFallback: "adb devices -l",
				alternatives: ["adb_observe(action: 'devices')", "adb devices -l"],
				executed: false,
			};
		case "ps":
			return {
				primary: "frida",
				action,
				suggestedFallback: "adb shell ps -ef",
				activeFallback: "adb shell ps -ef",
				alternatives: ["adb shell ps -ef", "ps -ef"],
				executed: false,
			};
		case "modules":
		case "inspect":
		case "trace":
		case "exec":
		default:
			return {
				primary: "frida",
				action,
				suggestedFallback: "r2_inspect or static analysis via droidasc",
				activeFallback: "droidasc",
				alternatives: [
					"adb logcat",
					"r2_inspect(action: 'info', path: '<target_binary>')",
					"droidasc(action: 'class_list', apk: '<target_apk>')",
				],
				executed: false,
			};
	}
}

export function parseFridaDevices(raw: string): FridaDeviceInfo[] {
	const trimmed = raw.trim();
	if (trimmed.length === 0) return [];
	if (trimmed.startsWith("[")) {
		try {
			let parsed: unknown;
			try {
				parsed = JSON.parse(trimmed);
			} catch {
				parsed = parsePythonLiteral(trimmed, 0, { requireEnd: true }).value;
			}
			if (Array.isArray(parsed)) {
				return (parsed as unknown[])
					.filter(item => item && typeof item === "object")
					.map(item => ({
						id: String((item as Record<string, unknown>).id ?? ""),
						type: String((item as Record<string, unknown>).type ?? "unknown"),
						name: String((item as Record<string, unknown>).name ?? ""),
					}))
					.filter(item => item.id.length > 0);
			}
		} catch {
			// Fall back to tabular parsing
		}
	}

	const lines = raw
		.split(/\r?\n/)
		.map(line => line.trim())
		.filter(line => line.length > 0);
	const devices: FridaDeviceInfo[] = [];

	for (const line of lines) {
		if (/^Id\s+Type\s+Name/i.test(line) || /^[- ]+$/.test(line)) {
			continue;
		}
		const parts = line.split(/\s{2,}/);
		if (parts.length >= 3) {
			devices.push({
				id: parts[0].trim(),
				type: parts[1].trim(),
				name: parts.slice(2).join(" ").trim(),
			});
		} else {
			const match = /^(\S+)\s+(local|usb|remote)\s+(.+)$/i.exec(line);
			if (match) {
				devices.push({
					id: match[1],
					type: match[2].toLowerCase(),
					name: match[3].trim(),
				});
			}
		}
	}
	return devices;
}

export function parseFridaProcesses(raw: string): FridaProcessInfo[] {
	const trimmed = raw.trim();
	if (trimmed.length === 0) return [];
	if (trimmed.startsWith("[")) {
		try {
			let parsed: unknown;
			try {
				parsed = JSON.parse(trimmed);
			} catch {
				parsed = parsePythonLiteral(trimmed, 0, { requireEnd: true }).value;
			}
			if (Array.isArray(parsed)) {
				return (parsed as unknown[])
					.filter(item => item && typeof item === "object")
					.map(item => {
						const r = item as Record<string, unknown>;
						const p = r.parameters as Record<string, unknown> | undefined;
						return {
							pid: Number(r.pid ?? 0),
							name: String(r.name ?? ""),
							...(p?.identifier || r.identifier ? { identifier: String(p?.identifier ?? r.identifier) } : {}),
						};
					})
					.filter(item => item.pid > 0);
			}
		} catch {
			// Fall back to tabular parsing
		}
	}

	const lines = raw
		.split(/\r?\n/)
		.map(line => line.trim())
		.filter(line => line.length > 0);
	const processes: FridaProcessInfo[] = [];

	for (const line of lines) {
		if (/^PID\s+Name/i.test(line) || /^[- ]+$/.test(line)) {
			continue;
		}
		const parts = line.split(/\s{2,}/);
		if (parts.length >= 2) {
			const pid = Number.parseInt(parts[0], 10);
			if (Number.isInteger(pid) && pid > 0) {
				processes.push({
					pid,
					name: parts[1].trim(),
					...(parts[2] ? { identifier: parts[2].trim() } : {}),
				});
				continue;
			}
		}
		const match = /^\s*(\d+)\s+([^\s]+(?:\s+[^\s]+)*?)(?:\s{2,}([A-Za-z0-9._-]+))?\s*$/.exec(line);
		if (match) {
			const pid = Number.parseInt(match[1], 10);
			if (Number.isInteger(pid) && pid > 0) {
				processes.push({
					pid,
					name: match[2].trim(),
					...(match[3] ? { identifier: match[3].trim() } : {}),
				});
			}
		}
	}
	return processes;
}

export function parseFridaModules(raw: string): FridaModuleInfo[] {
	const startIdx = raw.indexOf("__FRIDA_MODULES_START__");
	const endIdx = raw.indexOf("__FRIDA_MODULES_END__");
	let jsonText = raw.trim();

	if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
		jsonText = raw.slice(startIdx + "__FRIDA_MODULES_START__".length, endIdx).trim();
	}

	try {
		let parsed: unknown;
		try {
			parsed = JSON.parse(jsonText);
		} catch {
			parsed = parsePythonLiteral(jsonText, 0, { requireEnd: true }).value;
		}
		if (Array.isArray(parsed)) {
			return (parsed as unknown[])
				.filter(item => item && typeof item === "object")
				.map(item => {
					const m = item as Record<string, unknown>;
					return {
						name: String(m.name ?? ""),
						base: String(m.base ?? ""),
						size: Number(m.size ?? 0),
						path: String(m.path ?? ""),
					};
				})
				.filter(item => item.name.length > 0);
		}
	} catch {
		// Not json
	}
	return [];
}

export function parseFridaTrace(raw: string): {
	events: FridaTraceEvent[];
	totalEvents?: number;
	module?: string;
	base?: string;
	error?: string;
} {
	const startIdx = raw.indexOf("__FRIDA_TRACE_START__");
	const endIdx = raw.indexOf("__FRIDA_TRACE_END__");
	let jsonText = raw.trim();

	if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
		jsonText = raw.slice(startIdx + "__FRIDA_TRACE_START__".length, endIdx).trim();
	}

	try {
		let parsed: unknown;
		try {
			parsed = JSON.parse(jsonText);
		} catch {
			parsed = parsePythonLiteral(jsonText, 0, { requireEnd: true }).value;
		}
		if (parsed && typeof parsed === "object") {
			const obj = parsed as Record<string, unknown>;
			if (typeof obj.error === "string") {
				return { events: [], error: obj.error };
			}
			const rawEvents = Array.isArray(obj.events)
				? obj.events
				: typeof obj.event === "string"
					? [obj]
					: Array.isArray(parsed)
						? parsed
						: [];
			const events: FridaTraceEvent[] = rawEvents
				.filter(item => item && typeof item === "object")
				.map(item => {
					const r = item as Record<string, unknown>;
					return {
						event: String(r.event ?? "trace"),
						...(r.timestamp !== undefined ? { timestamp: Number(r.timestamp) } : {}),
						...(r.name ? { name: String(r.name) } : {}),
						...(r.module ? { module: String(r.module) } : {}),
						...(r.modulePath ? { modulePath: String(r.modulePath) } : {}),
						...(r.type ? { type: String(r.type) } : {}),
						...(r.address ? { address: String(r.address) } : {}),
						...(r.base ? { base: String(r.base) } : {}),
						...(r.size !== undefined ? { size: Number(r.size) } : {}),
						...(r.path ? { path: String(r.path) } : {}),
						...(r.status ? { status: String(r.status) } : {}),
						...(r.retval !== undefined ? { retval: r.retval } : {}),
						...(r.class ? { class: String(r.class) } : {}),
						...(r.target ? { target: String(r.target) } : {}),
						...(r.offset ? { offset: String(r.offset) } : {}),
						...(r.threadId !== undefined ? { threadId: Number(r.threadId) } : {}),
						...(r.nMethods !== undefined ? { nMethods: Number(r.nMethods) } : {}),
						...(Array.isArray(r.methods) ? { methods: r.methods as unknown as FridaTraceEvent["methods"] } : {}),
						...(r.truncated !== undefined ? { truncated: Boolean(r.truncated) } : {}),
						...(r.source ? { source: String(r.source) } : {}),
						...(r.javaBridgeAvailable !== undefined
							? { javaBridgeAvailable: Boolean(r.javaBridgeAvailable) }
							: {}),
						...(Array.isArray(r.args) ? { args: r.args } : {}),
						...(Array.isArray(r.backtrace) ? { backtrace: r.backtrace as string[] } : {}),
						...(r.details && typeof r.details === "object"
							? { details: r.details as Record<string, unknown> }
							: {}),
					};
				});
			return {
				events,
				totalEvents:
					typeof obj.totalEvents === "number"
						? obj.totalEvents
						: typeof obj.totalModules === "number"
							? obj.totalModules
							: typeof obj.totalExports === "number"
								? obj.totalExports
								: events.length,
				...(typeof obj.module === "string" ? { module: obj.module } : {}),
				...(typeof obj.base === "string" ? { base: obj.base } : {}),
			};
		}
	} catch {
		// Not json
	}
	return { events: [] };
}

export function detectFridaDeviceIssue(
	output: string,
	stderr: string,
	requested?: string,
): { status: FridaStatus; reason: string } | null {
	const combined = `${stderr}\n${output}`.toLowerCase();
	if (
		combined.includes("major versions match") ||
		combined.includes("version mismatch") ||
		combined.includes("incompatible frida-server") ||
		(combined.includes("server is running") && combined.includes("client is running"))
	) {
		return {
			status: "version_mismatch",
			reason: "Frida client and frida-server version mismatch. Ensure major versions match on client and target.",
		};
	}
	if (combined.includes("device unauthorized") || combined.includes("unauthorized")) {
		return {
			status: "device_unauthorized",
			reason: requested
				? `Device "${requested}" is unauthorized. Accept USB debugging prompt on the device.`
				: "Device is unauthorized. Accept USB debugging prompt on the device.",
		};
	}
	if (combined.includes("device offline") || combined.includes("offline")) {
		return {
			status: "device_offline",
			reason: requested ? `Device "${requested}" is offline.` : "Target device is offline.",
		};
	}
	if (
		combined.includes("device not found") ||
		combined.includes("waiting for usb device") ||
		combined.includes("no device found") ||
		combined.includes("unable to find device")
	) {
		return {
			status: "device_not_found",
			reason: requested ? `Device "${requested}" was not found.` : "No target device was found.",
		};
	}
	if (
		combined.includes("multiple devices") ||
		combined.includes("more than one device") ||
		combined.includes("need a device")
	) {
		return {
			status: "device_required",
			reason: "Multiple devices are attached; specify 'device' or 'usb'.",
		};
	}
	if (
		combined.includes("unable to connect to remote frida-server") ||
		combined.includes("connection refused") ||
		combined.includes("frida-server is not running") ||
		combined.includes("failed to connect to")
	) {
		return {
			status: "device_unavailable",
			reason: "Unable to connect to frida-server on target device.",
		};
	}
	return null;
}

export class FridaTool implements AgentTool<typeof fridaSchema, FridaDetails> {
	readonly name = "frida";
	readonly label = "Frida";
	readonly summary =
		"Execute custom Frida JavaScript scripts, hooks, dynamic inspection, process spawning, device discovery, process listing, and module enumeration";
	readonly description: string;
	readonly parameters = fridaSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: FridaToolOptions = {},
	) {
		this.description = prompt.render(fridaDescription);
	}

	async execute(
		_toolCallId: string,
		params: FridaParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<FridaDetails, typeof fridaSchema>,
		_ctx?: AgentToolContext,
	): Promise<AgentToolResult<FridaDetails>> {
		throwIfAborted(signal);

		// 1. Determine effective action
		let action: FridaAction = params.action ?? "exec";
		const hasScript = typeof params.script === "string" && params.script.length > 0;
		const hasScriptPath = typeof params.script_path === "string" && params.script_path.trim().length > 0;
		const hasSpawn = typeof params.spawn === "string" && params.spawn.trim().length > 0;
		const hasPid = params.pid !== undefined;
		const hasProcess = typeof params.process === "string" && params.process.trim().length > 0;

		if (!params.action) {
			if (hasScript || hasScriptPath || hasSpawn) {
				action = "exec";
			} else if (params.template !== undefined) {
				action = "trace";
			} else if (params.applications === true) {
				action = "ps";
			} else if (hasPid || hasProcess) {
				action = "modules";
			} else {
				action = "devices";
			}
		}

		// 2. Validate script options
		if (hasScript && hasScriptPath) {
			throw new ToolError("Cannot provide both 'script' and 'script_path'. Choose exactly one.");
		}

		let resolvedScriptPath: string | undefined;
		let scriptContent: string | undefined;
		if (hasScriptPath) {
			resolvedScriptPath = resolveScriptPath(params.script_path!, this.session.cwd);
			if (!fs.existsSync(resolvedScriptPath)) {
				throw new ToolError(`Frida script file does not exist: ${params.script_path}`);
			}
			try {
				scriptContent = fs.readFileSync(resolvedScriptPath, "utf8");
			} catch {
				// Script exists; frida will read it directly
			}
		} else if (hasScript) {
			scriptContent = params.script;
		}

		// 3. Validate target options (pid, process, spawn)
		const targetCount = (hasPid ? 1 : 0) + (hasProcess ? 1 : 0) + (hasSpawn ? 1 : 0);
		if (action === "exec") {
			if (targetCount === 0 && !params.cli_args) {
				throw new ToolError(
					"Must specify a target: either attach to an existing process ('pid' or 'process') or spawn a new process ('spawn').",
				);
			}
			if (targetCount > 1) {
				throw new ToolError(
					"Cannot combine multiple target modes. Specify exactly one of 'pid', 'process', or 'spawn'.",
				);
			}
			if (!hasScript && !hasScriptPath && !params.cli_args) {
				throw new ToolError("Must provide either 'script' or 'script_path'.");
			}
		} else if (action === "modules" || action === "inspect") {
			if (targetCount === 0) {
				throw new ToolError(`action '${action}' requires either 'pid' or 'process' to identify the target process`);
			}
			if (targetCount > 1) {
				throw new ToolError(`action '${action}' accepts only one target mode ('pid' or 'process')`);
			}
		} else if (action === "trace") {
			if (targetCount === 0 && !params.cli_args) {
				throw new ToolError(
					"action 'trace' requires a target: either attach ('pid' or 'process') or spawn ('spawn').",
				);
			}
			if (targetCount > 1) {
				throw new ToolError(
					"Cannot combine multiple target modes. Specify exactly one of 'pid', 'process', or 'spawn'.",
				);
			}
		}

		if (hasPid && (!Number.isInteger(params.pid) || params.pid! <= 0)) {
			throw new ToolError(`Target PID must be a positive integer (got ${params.pid}).`);
		}

		let targetLabel = "";
		let targetMode: "attach_pid" | "attach_process" | "spawn" | "none" = "none";
		if (hasPid) {
			targetMode = "attach_pid";
			targetLabel = `pid ${params.pid}`;
		} else if (hasProcess) {
			targetMode = "attach_process";
			targetLabel = `process ${params.process!.trim()}`;
		} else if (hasSpawn) {
			targetMode = "spawn";
			targetLabel = `spawn ${params.spawn!.trim()}`;
		}

		// 4. Validate transport options (usb, device, host)
		const hasUsb = params.usb === true;
		const hasDevice = typeof params.device === "string" && params.device.trim().length > 0;
		const hasHost = typeof params.host === "string" && params.host.trim().length > 0;

		const transportCount = (hasUsb ? 1 : 0) + (hasDevice ? 1 : 0) + (hasHost ? 1 : 0);
		if (transportCount > 1) {
			throw new ToolError("Cannot specify more than one of 'usb', 'device', and 'host'.");
		}

		const timeoutSeconds = clampTimeout(params.timeout);
		const maxBytes = clampMaxBytes(params.max_bytes);
		const maxEvents = clampMaxEvents(params.max_events);
		const runner = this.options.runner ?? defaultFridaRunner;
		const dependency = fridaDependency(this.options.which);

		// 5. Check dependency availability
		const needsLsDevices = action === "devices";
		const needsPs = action === "ps";
		const binary = needsLsDevices
			? (dependency.fridaLsDevicesPath ?? dependency.fridaPsPath ?? dependency.path)
			: needsPs
				? (dependency.fridaPsPath ?? dependency.path)
				: dependency.path;

		if (!dependency.available || !binary) {
			const fallback = resolveFridaFallback(action, {
				process: params.process,
				pid: params.pid,
				filter: params.filter,
			});
			const installHint =
				dependency.installHint ?? "pipx install frida-tools (or python3 -m pip install --user frida-tools)";
			const manualUrl = dependency.manualUrl ?? "https://frida.re/docs/installation/";
			return {
				content: [
					{
						type: "text",
						text: [
							`frida: Frida tools are not available on this machine.`,
							`Install: ${installHint}`,
							`Documentation: ${manualUrl}`,
							"",
							`Suggested fallback: ${fallback.suggestedFallback}`,
							"Alternative approaches:",
							...fallback.alternatives.map(a => `  - ${a}`),
						].join("\n"),
					},
				],
				details: {
					action,
					status: "missing_dependency",
					dependency,
					fallback,
					error: "Frida CLI binary not found in PATH",
				},
			};
		}

		// 6. Build argv array
		const args: string[] = [];

		if (hasUsb) {
			args.push("-U");
		} else if (hasDevice) {
			args.push("-D", params.device!.trim());
		} else if (hasHost) {
			args.push("-H", params.host!.trim());
		}

		if (action === "devices") {
			// frida-ls-devices takes no specific flags, or passes extra cli_args
		} else if (action === "ps") {
			if (params.applications === true) {
				args.push("-a");
			}
		} else if (action === "modules" || action === "inspect") {
			if (hasSpawn) {
				args.push("-f", params.spawn!.trim());
				if (params.pause === true || params.no_pause === false) {
					args.push("--pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
			}
			args.push("-q");
			if (hasScriptPath) {
				args.push("-l", resolvedScriptPath!);
			} else if (hasScript) {
				args.push("-e", params.script!);
			} else {
				args.push("-e", FIXED_ENUMERATE_MODULES_SCRIPT);
			}
		} else if (action === "trace") {
			if (hasSpawn) {
				args.push("-f", params.spawn!.trim());
				if (params.pause === true || params.no_pause === false) {
					args.push("--pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
			}
			args.push("-q");
			if (hasScriptPath) {
				args.push("-l", resolvedScriptPath!);
			} else if (hasScript) {
				args.push("-e", params.script!);
			} else if (params.template === "exports") {
				if (params.module) {
					args.push("-e", buildTraceExportsScript(params.module.trim(), params.max_events));
				} else {
					args.push("-e", FIXED_ENUMERATE_MODULES_SCRIPT);
				}
			} else if (params.template === "jni_register") {
				args.push(
					"-e",
					buildJniRegisterNativesScript({
						maxEvents: params.max_events,
						module: params.module,
						symbol: params.symbol,
					}),
				);
			} else if (params.template === "native_functions") {
				args.push(
					"-e",
					buildNativeHookScript({
						module: params.module,
						symbol: params.symbol,
						symbols: Array.isArray(params.symbols) ? (params.symbols as string[]) : undefined,
						offset: params.offset as string | number | undefined,
						offsets: Array.isArray(params.offsets) ? (params.offsets as Array<string | number>) : undefined,
						argsCount: params.args_count,
						argsDecode: params.args_decode as Record<string, string> | undefined,
						retval: params.retval,
						backtrace: params.backtrace as boolean | "accurate" | "fuzzy" | undefined,
						maxEvents: params.max_events,
						maxBufferBytes: params.max_buffer_bytes,
					}),
				);
			} else {
				args.push("-e", FIXED_TRACE_MODULE_LOAD_SCRIPT);
			}
		} else {
			// action === "exec"
			if (hasSpawn) {
				args.push("-f", params.spawn!.trim());
				if (params.pause === true || params.no_pause === false) {
					args.push("--pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
			}

			if (hasScriptPath) {
				args.push("-l", resolvedScriptPath!);
			} else if (hasScript) {
				args.push("-e", params.script!);
			}

			if (params.script_args !== undefined) {
				let paramJson: string;
				if (typeof params.script_args === "string") {
					try {
						const parsed = JSON.parse(params.script_args);
						paramJson =
							typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
								? params.script_args
								: JSON.stringify({ args: parsed });
					} catch {
						paramJson = JSON.stringify({ arg: params.script_args });
					}
				} else if (Array.isArray(params.script_args)) {
					paramJson = JSON.stringify({ argv: params.script_args });
				} else if (typeof params.script_args === "object" && params.script_args !== null) {
					paramJson = JSON.stringify(params.script_args);
				} else {
					paramJson = JSON.stringify({ arg: params.script_args });
				}
				args.push("-P", paramJson);
			}

			args.push("-q");
			if (timeoutSeconds !== undefined) {
				args.push("-t", String(timeoutSeconds));
			}
		}

		// Append optional extra cli_args (accepts string[] or string)
		if (Array.isArray(params.cli_args)) {
			for (const arg of params.cli_args) {
				if (typeof arg === "string" && arg.trim().length > 0) {
					args.push(arg.trim());
				}
			}
		} else if (typeof params.cli_args === "string" && params.cli_args.trim().length > 0) {
			args.push(...splitCliArgs(params.cli_args.trim()));
		}

		// 7. Execute bounded runner
		// 对于 action: "devices" 与 "ps"，CLI 工具（frida-ls-devices/frida-ps）本身不支持 -t 参数，
		// 完全由宿主看门狗直接在 timeoutSeconds 期限内管控并终结；
		// 对于 action: "exec"，CLI 自身有 -t 内部超时，宿主看门狗附加 3 秒宽限期
		const hasCliTimeout = action === "exec";
		const timeoutMs = hasCliTimeout ? (timeoutSeconds + 3) * 1000 : timeoutSeconds * 1000;
		let run: FridaRunResult;
		try {
			run = await runner(binary, args, {
				cwd: this.session.cwd,
				timeoutMs,
				maxBytes,
				signal,
			});
		} catch (error) {
			if (signal?.aborted) {
				const cancelContext: Record<string, unknown> = {
					action,
					command: [binary, ...args],
					timeout: timeoutSeconds,
					reason: "Execution cancelled by caller",
					...(error instanceof ToolError && error.context ? error.context : {}),
				};
				logger.info("Frida action cancelled", cancelContext);
				throwIfAborted(signal);
				throw new ToolError("Execution cancelled by caller", cancelContext);
			}
			throw new ToolError(`Failed to execute Frida: ${error instanceof Error ? error.message : String(error)}`);
		}

		const rawOutput = Buffer.from(run.stdout).toString("utf8");
		const targetDevice = hasUsb ? "usb" : (params.device?.trim() ?? params.host?.trim());

		// 8. Detect device/connectivity issue
		const issue = detectFridaDeviceIssue(rawOutput, run.stderr, targetDevice);
		if (issue) {
			return {
				content: [{ type: "text", text: `frida ${issue.status}: ${issue.reason}` }],
				details: {
					action,
					status: issue.status,
					target: targetLabel,
					targetMode,
					...(targetDevice ? { device: targetDevice } : {}),
					timeout: timeoutSeconds,
					command: [binary, ...args],
					...(run.pid ? { pid: run.pid } : {}),
					exitCode: run.exitCode,
					stderr: run.stderr,
					stdout: rawOutput,
					error: issue.reason,
					...(run.cleanup ? { cleanup: run.cleanup } : {}),
				},
			};
		}

		// 9. Artifact allocation when requested or for large outputs
		const shouldArtifact = params.to_artifact === true || run.outputBytes > 8192;
		let artifactId: string | undefined;
		let artifactPath: string | undefined;

		if (shouldArtifact && this.session.allocateOutputArtifact) {
			try {
				const allocation = await this.session.allocateOutputArtifact("frida");
				if (allocation?.path && allocation.id) {
					const artifactContent = JSON.stringify(
						{
							action,
							target: targetLabel,
							targetMode,
							scriptSource: hasScriptPath ? "file" : hasScript ? "inline" : undefined,
							scriptPath: resolvedScriptPath,
							script: scriptContent,
							timeout: timeoutSeconds,
							command: [binary, ...args],
							...(run.pid ? { pid: run.pid } : {}),
							exitCode: run.exitCode,
							stdout: rawOutput,
							stderr: run.stderr,
							outputBytes: run.outputBytes,
							truncated: false,
							timedOut: run.timedOut,
							...(run.timedOut ? { reason: `Execution watchdog timed out after ${timeoutSeconds}s` } : {}),
							...(run.cleanup ? { cleanup: run.cleanup } : {}),
						},
						null,
						2,
					);
					await Bun.write(allocation.path, artifactContent);
					artifactId = allocation.id;
					artifactPath = allocation.path;
				}
			} catch {
				// Allocation failure non-fatal
			}
		}

		const status: FridaStatus = run.timedOut ? "timeout" : run.exitCode === 0 ? "ok" : "error";
		const lines: string[] = [];
		const isTruncated = rawOutput.length > maxBytes;
		const displayOutput = isTruncated ? rawOutput.slice(0, maxBytes) : rawOutput;

		// Format output by action
		if (action === "devices") {
			if (status === "timeout") {
				lines.push(`frida devices timed out after ${timeoutSeconds}s:`);
				lines.push(`- command: ${[binary, ...args].join(" ")}`);
				if (run.pid) lines.push(`- PID: ${run.pid}`);
				lines.push(`- reason: Execution watchdog timed out after ${timeoutSeconds}s; process tree cleaned up`);
				if (displayOutput.trim().length > 0) {
					lines.push(`- partial output:\n${displayOutput.trimEnd()}`);
				}
				if (run.stderr.trim().length > 0) {
					lines.push(`- stderr:\n${run.stderr.trimEnd()}`);
				}
			} else if (status === "ok") {
				const devices = parseFridaDevices(rawOutput);
				lines.push(`frida devices (${devices.length} attached):`);
				for (const dev of devices) {
					lines.push(`  - [${dev.type}] ${dev.id} (${dev.name})`);
				}
			} else {
				lines.push(
					`frida devices failed${run.exitCode !== null && run.exitCode !== undefined ? ` (exit code ${run.exitCode})` : ""}:`,
				);
				if (displayOutput.trim().length > 0) lines.push(displayOutput.trimEnd());
				if (run.stderr.trim().length > 0) lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					...(status === "ok" ? { devices: parseFridaDevices(rawOutput) } : {}),
					timeout: timeoutSeconds,
					command: [binary, ...args],
					...(run.pid ? { pid: run.pid } : {}),
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
					stderr: run.stderr,
					timedOut: run.timedOut,
					...(status === "timeout" ? { reason: `Execution watchdog timed out after ${timeoutSeconds}s` } : {}),
					...(run.cleanup ? { cleanup: run.cleanup } : {}),
					...(status === "error" && run.stderr ? { error: run.stderr.trim() } : {}),
				},
			};
		}

		if (action === "ps") {
			const targetTransport = hasUsb ? "usb" : (params.device ?? params.host ?? "local");
			let processes: FridaProcessInfo[] = [];
			if (status === "timeout") {
				lines.push(`frida ps timed out on ${targetTransport} after ${timeoutSeconds}s:`);
				lines.push(`- command: ${[binary, ...args].join(" ")}`);
				if (run.pid) lines.push(`- PID: ${run.pid}`);
				lines.push(`- reason: Execution watchdog timed out after ${timeoutSeconds}s; process tree cleaned up`);
				if (displayOutput.trim().length > 0) lines.push(`- partial output:\n${displayOutput.trimEnd()}`);
				if (run.stderr.trim().length > 0) lines.push(`- stderr:\n${run.stderr.trimEnd()}`);
			} else if (status === "ok") {
				processes = parseFridaProcesses(rawOutput);
				if (params.filter) {
					const q = params.filter.toLowerCase();
					processes = processes.filter(
						p => p.name.toLowerCase().includes(q) || (p.identifier && p.identifier.toLowerCase().includes(q)),
					);
				}
				lines.push(`frida ps: ${targetTransport} (${processes.length} processes):`);
				for (const p of processes) {
					lines.push(`  - PID ${p.pid}: ${p.name}${p.identifier ? ` (${p.identifier})` : ""}`);
				}
			} else {
				lines.push(
					`frida ps failed${run.exitCode !== null && run.exitCode !== undefined ? ` (exit code ${run.exitCode})` : ""}:`,
				);
				if (displayOutput.trim().length > 0) lines.push(displayOutput.trimEnd());
				if (run.stderr.trim().length > 0) lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					...(status === "ok" ? { processes } : {}),
					timeout: timeoutSeconds,
					command: [binary, ...args],
					...(run.pid ? { pid: run.pid } : {}),
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
					stderr: run.stderr,
					timedOut: run.timedOut,
					...(status === "timeout" ? { reason: `Execution watchdog timed out after ${timeoutSeconds}s` } : {}),
					...(run.cleanup ? { cleanup: run.cleanup } : {}),
					...(status === "error" && run.stderr ? { error: run.stderr.trim() } : {}),
				},
			};
		}

		if (action === "modules" || action === "inspect") {
			let modules: FridaModuleInfo[] = [];
			if (status === "timeout") {
				lines.push(`frida modules timed out on ${targetLabel} after ${timeoutSeconds}s:`);
				lines.push(`- command: ${[binary, ...args].join(" ")}`);
				if (run.pid) lines.push(`- PID: ${run.pid}`);
				lines.push(`- reason: Execution watchdog timed out after ${timeoutSeconds}s; process tree cleaned up`);
				if (displayOutput.trim().length > 0) lines.push(`- partial output:\n${displayOutput.trimEnd()}`);
				if (run.stderr.trim().length > 0) lines.push(`- stderr:\n${run.stderr.trimEnd()}`);
			} else {
				modules = parseFridaModules(rawOutput);
				if (params.filter) {
					const q = params.filter.toLowerCase();
					modules = modules.filter(m => m.name.toLowerCase().includes(q) || m.path.toLowerCase().includes(q));
				}
				if (params.module) {
					const q = params.module.toLowerCase();
					modules = modules.filter(m => m.name.toLowerCase().includes(q));
				}
				if (modules.length > 0) {
					lines.push(`frida modules: ${targetLabel} (${modules.length} modules):`);
					for (const m of modules) {
						lines.push(`  - ${m.name} (base: ${m.base}, size: ${m.size}, path: ${m.path})`);
					}
				} else {
					if (status === "ok") {
						lines.push(`frida modules completed on ${targetLabel}:`);
					} else {
						lines.push(
							`frida modules failed on ${targetLabel}${run.exitCode !== null && run.exitCode !== undefined ? ` (exit code ${run.exitCode})` : ""}:`,
						);
					}
					if (rawOutput.length > 0) lines.push(rawOutput.trimEnd());
					if (run.stderr.length > 0) lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
				}
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					target: targetLabel,
					targetMode,
					...(status === "ok" ? { modules } : {}),
					timeout: timeoutSeconds,
					command: [binary, ...args],
					...(run.pid ? { pid: run.pid } : {}),
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
					stderr: run.stderr,
					timedOut: run.timedOut,
					...(status === "timeout" ? { reason: `Execution watchdog timed out after ${timeoutSeconds}s` } : {}),
					...(run.cleanup ? { cleanup: run.cleanup } : {}),
					...(status === "error" && run.stderr ? { error: run.stderr.trim() } : {}),
				},
			};
		}

		if (action === "trace") {
			if (status === "timeout") {
				lines.push(`frida trace timed out on ${targetLabel} after ${timeoutSeconds}s:`);
				lines.push(`- command: ${[binary, ...args].join(" ")}`);
				if (run.pid) lines.push(`- PID: ${run.pid}`);
				lines.push(`- reason: Execution watchdog timed out after ${timeoutSeconds}s; process tree cleaned up`);
				if (displayOutput.trim().length > 0) lines.push(`- partial output:\n${displayOutput.trimEnd()}`);
				if (run.stderr.trim().length > 0) lines.push(`- stderr:\n${run.stderr.trimEnd()}`);
				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action,
						status,
						target: targetLabel,
						targetMode,
						timeout: timeoutSeconds,
						command: [binary, ...args],
						...(run.pid ? { pid: run.pid } : {}),
						stdout: rawOutput,
						stderr: run.stderr,
						outputBytes: run.outputBytes,
						truncated: run.truncated,
						exitCode: run.exitCode,
						timedOut: run.timedOut,
						reason: `Execution watchdog timed out after ${timeoutSeconds}s`,
						...(run.cleanup ? { cleanup: run.cleanup } : {}),
					},
				};
			}
			const traceResult = parseFridaTrace(rawOutput);
			if (traceResult.events.length === 0) {
				if (status === "ok") {
					lines.push(`frida trace completed on ${targetLabel}:`);
				} else {
					lines.push(
						`frida trace failed on ${targetLabel}${run.exitCode !== null && run.exitCode !== undefined ? ` (exit code ${run.exitCode})` : ""}:`,
					);
				}
				if (rawOutput.length > 0) lines.push(rawOutput.trimEnd());
				if (run.stderr.length > 0) lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action,
						status,
						target: targetLabel,
						targetMode,
						timeout: timeoutSeconds,
						command: [binary, ...args],
						...(run.pid ? { pid: run.pid } : {}),
						stdout: rawOutput,
						stderr: run.stderr,
						outputBytes: run.outputBytes,
						truncated: run.truncated,
						exitCode: run.exitCode,
						timedOut: run.timedOut,
						...(status === "error" && run.stderr ? { error: run.stderr.trim() } : {}),
					},
				};
			}

			const eventsToReturn =
				params.max_events !== undefined ? traceResult.events.slice(0, maxEvents) : traceResult.events;
			const template = params.template ?? (hasScript || hasScriptPath ? "custom_script" : "module_load");

			const traceSummary: FridaTraceSummary = {
				template,
				target: targetLabel,
				totalEvents: traceResult.totalEvents ?? traceResult.events.length,
				returnedEvents: eventsToReturn.length,
				capped: params.max_events !== undefined && traceResult.events.length > eventsToReturn.length,
				redactions: 0,
				...(traceResult.module ? { module: traceResult.module } : {}),
				...(traceResult.base ? { base: traceResult.base } : {}),
			};

			lines.push(`frida trace (${template}): ${targetLabel} (${eventsToReturn.length} events):`);
			for (const e of eventsToReturn) {
				if (e.event === "export") {
					lines.push(`  - export: ${e.name} (${e.type ?? "func"} @ ${e.address})`);
				} else {
					lines.push(`  - ${e.event}: ${e.name ?? e.module ?? "unknown"}`);
				}
			}

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					target: targetLabel,
					targetMode,
					timeout: timeoutSeconds,
					command: [binary, ...args],
					...(run.pid ? { pid: run.pid } : {}),
					events: eventsToReturn,
					traceSummary,
					redactions: 0,
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
					stderr: run.stderr,
					timedOut: run.timedOut,
				},
			};
		}

		// action === "exec"
		if (status === "ok") {
			lines.push(`frida completed successfully on ${targetLabel} (exit code 0):`);
		} else if (status === "timeout") {
			lines.push(`frida timed out on ${targetLabel} after ${timeoutSeconds}s:`);
			lines.push(`- command: ${[binary, ...args].join(" ")}`);
			if (run.pid) lines.push(`- PID: ${run.pid}`);
			lines.push(`- reason: Execution watchdog timed out after ${timeoutSeconds}s; process tree cleaned up`);
		} else {
			lines.push(
				`frida failed on ${targetLabel}${run.exitCode !== null && run.exitCode !== undefined ? ` (exit code ${run.exitCode})` : ""}:`,
			);
		}

		if (displayOutput.length > 0) {
			lines.push(displayOutput.trimEnd());
		}
		if (run.stderr.length > 0) {
			if (displayOutput.length > 0) lines.push("");
			lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
		}
		if (isTruncated) {
			lines.push(
				`\n… output truncated at ${maxBytes} bytes for display; full record preserved in session artifact.`,
			);
		}
		if (artifactId) {
			lines.push(`\nFull execution record saved to artifact: ${artifactId}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action,
				status,
				target: targetLabel,
				targetMode,
				...(params.pid !== undefined ? { pid: params.pid } : {}),
				...(params.process ? { process: params.process.trim() } : {}),
				...(params.spawn ? { spawn: params.spawn.trim() } : {}),
				...(params.device ? { device: params.device.trim() } : {}),
				...(params.host ? { host: params.host.trim() } : {}),
				...(params.usb ? { usb: true } : {}),
				scriptSource: hasScriptPath ? "file" : hasScript ? "inline" : undefined,
				...(resolvedScriptPath ? { scriptPath: resolvedScriptPath } : {}),
				timeout: timeoutSeconds,
				command: [binary, ...args],
				...(!params.pid && run.pid ? { pid: run.pid } : {}),
				exitCode: run.exitCode,
				stdout: rawOutput,
				stderr: run.stderr,
				outputBytes: run.outputBytes,
				truncated: isTruncated,
				timedOut: run.timedOut,
				...(status === "timeout" ? { reason: `Execution watchdog timed out after ${timeoutSeconds}s` } : {}),
				...(run.cleanup ? { cleanup: run.cleanup } : {}),
				...(artifactId ? { artifactId } : {}),
				...(artifactPath ? { artifactPath } : {}),
				...(status === "error" && run.exitCode !== 0
					? {
							error:
								run.stderr.trim() ||
								(run.exitCode !== null ? `Exit code ${run.exitCode}` : "Process terminated"),
						}
					: {}),
			},
		};
	}
}

// Backward compatibility aliases
export type FridaObserveTool = FridaTool;
export const FridaObserveTool = FridaTool;
export type FridaExecTool = FridaTool;
export const FridaExecTool = FridaTool;
export type FridaObserveParams = FridaParams;
export type FridaExecParams = FridaParams;
export type FridaObserveDetails = FridaDetails;
export type FridaExecDetails = FridaDetails;
export type FridaObserveStatus = FridaStatus;
export type FridaExecStatus = FridaStatus;
