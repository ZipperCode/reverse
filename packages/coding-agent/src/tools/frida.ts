import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type } from "@rva/omptype";
import type { AgentTool, AgentToolResult } from "@rva/agent";
import { prompt, $which } from "@rva/utils";
import fridaDescription from "../prompts/tools/frida.md" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import type { ToolSession } from "./index";
import { ToolError } from "@rva/tui/tools/tool-errors";
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
	"no_pause?": type("boolean").describe(
		"For spawn mode: automatically start the main thread after spawning (defaults to true; pass false to keep paused)",
	),
	"filter?": type("string").describe(
		"Text filter: for 'ps' matches process name/identifier; for 'modules' matches module name/path; for 'trace' matches event names",
	),
	"applications?": type("boolean").describe("For action 'ps': list only installed application processes (-a)"),
	"module?": type("string").describe(
		"Target module name (e.g. 'libnative-lib.so', 'libc.so') for trace template 'exports' or module filtering",
	),
	"template?": type("string").describe(
		"Optional trace template ('module_load' or 'exports') or custom template name. Custom scripts can also be passed via script or script_path",
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
export type FridaTraceTemplate = "module_load" | "exports" | string;

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
	event: "module_load" | "export" | string;
	timestamp?: number;
	module?: string;
	name?: string;
	type?: string;
	address?: string;
	base?: string;
	size?: number;
	path?: string;
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
	exitCode?: number;
	stdout?: string;
	stderr?: string;
	outputBytes?: number;
	truncated?: boolean;
	timedOut?: boolean;
	artifactId?: string;
	artifactPath?: string;
	redactions?: number;
	error?: string;
}

export interface FridaRunResult {
	stdout: Uint8Array;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
	killedOnOverflow?: boolean;
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

function clampTimeout(timeout?: number): number | undefined {
	if (timeout === undefined) return undefined;
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

export function redactTraceEvent(event: FridaTraceEvent): { event: FridaTraceEvent; redactions: number } {
	return { event, redactions: 0 };
}

export function redactTraceEvents(events: FridaTraceEvent[]): { events: FridaTraceEvent[]; redactions: number } {
	return { events, redactions: 0 };
}
export function resolveScriptPath(rawPath: string, cwd: string): string {
	let expanded = rawPath.trim();
	if (expanded.startsWith("~/") || expanded === "~") {
		expanded = path.join(os.homedir(), expanded.slice(1));
	}
	return path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(cwd, expanded);
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
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});
	let timedOut = false;
	let timer: NodeJS.Timeout | undefined;
	if (options.timeoutMs !== undefined && options.timeoutMs > 0) {
		timer = setTimeout(() => {
			timedOut = true;
			child.kill();
		}, options.timeoutMs);
	}
	const onAbort = () => {
		child.kill();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });
	if (options.signal?.aborted) child.kill();
	try {
		const [stdoutBuffer, stderrBuffer, exitCode] = await Promise.all([
			new Response(child.stdout).arrayBuffer(),
			new Response(child.stderr).arrayBuffer(),
			child.exited,
		]);
		const stdout = new Uint8Array(stdoutBuffer);
		const stderr = Buffer.from(stderrBuffer).toString("utf8");
		return {
			stdout,
			stderr,
			exitCode,
			outputBytes: stdout.length,
			truncated: false,
			timedOut,
		};
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
	}
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
			const parsed = JSON.parse(trimmed) as unknown;
			if (Array.isArray(parsed)) {
				return parsed
					.filter(item => item && typeof item === "object")
					.map(item => ({
						id: String(item.id ?? ""),
						type: String(item.type ?? "unknown"),
						name: String(item.name ?? ""),
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
			const parsed = JSON.parse(trimmed) as unknown;
			if (Array.isArray(parsed)) {
				return parsed
					.filter(item => item && typeof item === "object")
					.map(item => ({
						pid: Number(item.pid ?? 0),
						name: String(item.name ?? ""),
						...(item.parameters?.identifier || item.identifier
							? { identifier: String(item.parameters?.identifier ?? item.identifier) }
							: {}),
					}))
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
		const parsed = JSON.parse(jsonText) as unknown;
		if (Array.isArray(parsed)) {
			return parsed
				.filter(item => item && typeof item === "object")
				.map(item => ({
					name: String(item.name ?? ""),
					base: String(item.base ?? ""),
					size: Number(item.size ?? 0),
					path: String(item.path ?? ""),
				}))
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
		const parsed = JSON.parse(jsonText) as unknown;
		if (parsed && typeof parsed === "object") {
			const obj = parsed as Record<string, unknown>;
			if (typeof obj.error === "string") {
				return { events: [], error: obj.error };
			}
			const rawEvents = Array.isArray(obj.events) ? obj.events : Array.isArray(parsed) ? parsed : [];
			const events: FridaTraceEvent[] = rawEvents
				.filter(item => item && typeof item === "object")
				.map(item => {
					const r = item as Record<string, unknown>;
					return {
						event: String(r.event ?? "trace"),
						...(r.timestamp !== undefined ? { timestamp: Number(r.timestamp) } : {}),
						...(r.name ? { name: String(r.name) } : {}),
						...(r.module ? { module: String(r.module) } : {}),
						...(r.type ? { type: String(r.type) } : {}),
						...(r.address ? { address: String(r.address) } : {}),
						...(r.base ? { base: String(r.base) } : {}),
						...(r.size !== undefined ? { size: Number(r.size) } : {}),
						...(r.path ? { path: String(r.path) } : {}),
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
				if (params.no_pause !== false) {
					args.push("--no-pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
			}
			args.push("-q");
			if (hasScriptPath) {
				args.push("-l", resolvedScriptPath!);
			} else if (hasScript) {
				args.push("-e", params.script!);
			} else {
				args.push("--no-pause", "-e", FIXED_ENUMERATE_MODULES_SCRIPT);
			}
		} else if (action === "trace") {
			if (hasSpawn) {
				args.push("-f", params.spawn!.trim());
				if (params.no_pause !== false) {
					args.push("--no-pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
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
			} else {
				args.push("-e", FIXED_TRACE_MODULE_LOAD_SCRIPT);
			}
		} else {
			// action === "exec"
			if (hasSpawn) {
				args.push("-f", params.spawn!.trim());
				if (params.no_pause !== false) {
					args.push("--no-pause");
				}
			} else if (hasPid) {
				args.push("-p", String(params.pid));
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
			} else if (hasProcess) {
				args.push("-n", params.process!.trim());
				if (params.no_pause === true) {
					args.push("--no-pause");
				}
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
		const timeoutMs = timeoutSeconds !== undefined ? (timeoutSeconds + 2) * 1000 : undefined;
		let run: FridaRunResult;
		try {
			run = await runner(binary, args, {
				cwd: this.session.cwd,
				timeoutMs,
				maxBytes,
				signal,
			});
		} catch (error) {
			throwIfAborted(signal);
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
					exitCode: run.exitCode,
					stderr: run.stderr,
					stdout: rawOutput,
					error: issue.reason,
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
							exitCode: run.exitCode,
							stdout: rawOutput,
							stderr: run.stderr,
							outputBytes: run.outputBytes,
							truncated: false,
							timedOut: run.timedOut,
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
			const devices = parseFridaDevices(rawOutput);
			lines.push(`frida devices (${devices.length} attached):`);
			for (const dev of devices) {
				lines.push(`  - [${dev.type}] ${dev.id} (${dev.name})`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					devices,
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
				},
			};
		}

		if (action === "ps") {
			let processes = parseFridaProcesses(rawOutput);
			if (params.filter) {
				const q = params.filter.toLowerCase();
				processes = processes.filter(
					p => p.name.toLowerCase().includes(q) || (p.identifier && p.identifier.toLowerCase().includes(q)),
				);
			}
			const targetTransport = hasUsb ? "usb" : (params.device ?? params.host ?? "local");
			lines.push(`frida ps: ${targetTransport} (${processes.length} processes):`);
			for (const p of processes) {
				lines.push(`  - PID ${p.pid}: ${p.name}${p.identifier ? ` (${p.identifier})` : ""}`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					processes,
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
				},
			};
		}

		if (action === "modules" || action === "inspect") {
			let modules = parseFridaModules(rawOutput);
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
					lines.push(`frida modules failed on ${targetLabel} (exit code ${run.exitCode}):`);
				}
				if (rawOutput.length > 0) lines.push(rawOutput.trimEnd());
				if (run.stderr.length > 0) lines.push(`[stderr]\n${run.stderr.trimEnd()}`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action,
					status,
					target: targetLabel,
					targetMode,
					...(modules.length > 0 ? { modules } : {}),
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
					stderr: run.stderr,
				},
			};
		}
		if (action === "trace") {
			const traceResult = parseFridaTrace(rawOutput);
			if (traceResult.events.length === 0) {
				if (status === "ok") {
					lines.push(`frida trace completed on ${targetLabel}:`);
				} else {
					lines.push(`frida trace failed on ${targetLabel} (exit code ${run.exitCode}):`);
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
						stdout: rawOutput,
						stderr: run.stderr,
						outputBytes: run.outputBytes,
						truncated: run.truncated,
						exitCode: run.exitCode,
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
					events: eventsToReturn,
					traceSummary,
					redactions: 0,
					outputBytes: run.outputBytes,
					truncated: run.truncated,
					exitCode: run.exitCode,
					stdout: rawOutput,
				},
			};
		}

		// action === "exec"
		if (status === "ok") {
			lines.push(`frida completed successfully on ${targetLabel} (exit code 0):`);
		} else if (status === "timeout") {
			lines.push(
				`frida timed out on ${targetLabel}${timeoutSeconds !== undefined ? ` after ${timeoutSeconds}s` : ""}:`,
			);
		} else {
			lines.push(`frida failed on ${targetLabel} (exit code ${run.exitCode}):`);
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
				exitCode: run.exitCode,
				stdout: rawOutput,
				stderr: run.stderr,
				outputBytes: run.outputBytes,
				truncated: isTruncated,
				timedOut: run.timedOut,
				...(artifactId ? { artifactId } : {}),
				...(artifactPath ? { artifactPath } : {}),
				...(run.exitCode !== 0 ? { error: run.stderr.trim() || `Exit code ${run.exitCode}` } : {}),
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
