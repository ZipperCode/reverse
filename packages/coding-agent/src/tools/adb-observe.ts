import { type } from "@rva/omptype";
import type { AgentTool, AgentToolResult, ToolTier } from "@rva/agent";
import { prompt } from "@rva/utils";
import adbObserveDescription from "../prompts/tools/adb-observe.md" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import { SKILL_TOOL_CATALOG, type SkillToolPlatform } from "../extensibility/skill-tool-catalog";
import type { ToolSession } from "./index";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";

const adbObserveSchema = type({
	action: type
		.enumerated("devices", "packages", "processes", "logcat", "props", "screencap")
		.describe(
			"Read-only observation: devices (adb devices -l), packages (pm list packages -f), processes (ps -A), logcat (dumped ring buffer), props (getprop), or screencap (PNG saved to an artifact)",
		),
	"serial?": type("string").describe(
		"Target device serial (e.g. emulator-5554 or 192.168.1.5:5555). Optional when exactly one device is attached; required when several are attached",
	),
	"package?": type("string").describe(
		"Optional Android application id filter for packages/processes (e.g. com.example.app). Validated locally; never passed as an arbitrary shell argument",
	),
	"filter?": type("string").describe(
		"For logcat: one tag with an optional priority (e.g. ActivityManager or ActivityManager:I); for props: a property key or prefix (e.g. ro.build)",
	),
	"lines?": type("number").describe("For logcat: maximum trailing lines to dump (default 200, max 2000)"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 30, max 120)"),
	"max_bytes?": type("number").describe(
		"Maximum stdout bytes captured before truncation (default 262144, max 4194304; screencap defaults to 16777216, max 67108864)",
	),
});

export type AdbObserveParams = typeof adbObserveSchema.infer;
export type AdbObserveAction = AdbObserveParams["action"];
export type AdbObserveStatus =
	| "ok"
	| "missing_dependency"
	| "device_required"
	| "device_not_found"
	| "device_unauthorized"
	| "device_offline"
	| "device_unavailable"
	| "error";

export interface AdbDependencyStatus {
	id: "adb";
	available: boolean;
	path?: string;
	installHint?: string;
	manualUrl?: string;
}

export interface AdbFallbackInfo {
	primary: "adb";
	action: AdbObserveAction;
	suggestedFallback: string;
	/** Alias for suggestedFallback. */
	activeFallback: string;
	alternatives: string[];
	/** Fallback commands are suggestions only and are never executed by this tool. */
	executed: false;
}

export interface AdbDeviceInfo {
	serial: string;
	state: string;
	details?: Record<string, string>;
}

export interface AdbObserveDetails {
	action: AdbObserveAction;
	status: AdbObserveStatus;
	dependency?: AdbDependencyStatus;
	fallback?: AdbFallbackInfo;
	serial?: string;
	deviceState?: string;
	devices?: AdbDeviceInfo[];
	outputBytes?: number;
	truncated?: boolean;
	package?: string;
	filter?: string;
	lines?: number;
	/** Artifact id for screencap bytes (artifact://<id>). */
	artifactId?: string;
	/** Absolute path of the saved screenshot artifact. */
	artifactPath?: string;
	/** Raw screenshot size in bytes. */
	bytes?: number;
	format?: "png";
	mimeType?: "image/png";
	error?: string;
}

export interface AdbRunResult {
	stdout: Uint8Array;
	stderr: string;
	exitCode: number;
	outputBytes: number;
	truncated: boolean;
	timedOut: boolean;
	killedOnOverflow?: boolean;
}

export type AdbRunner = (
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
) => Promise<AdbRunResult>;

export interface AdbObserveToolOptions {
	which?: SkillRequirementWhich;
	runner?: AdbRunner;
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const MAX_TIMEOUT_SECONDS = 120;
const DEFAULT_MAX_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const DEFAULT_SCREENCAP_MAX_BYTES = 16 * 1024 * 1024;
const MAX_SCREENCAP_BYTES = 64 * 1024 * 1024;
const DEFAULT_LOGCAT_LINES = 200;
const MAX_LOGCAT_LINES = 2000;
const STDERR_BYTES = 16 * 1024;

const SERIAL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const PACKAGE_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const LOGCAT_FILTER_PATTERN = /^[A-Za-z0-9_.-]{1,64}(:[VDIWEF])?$/;
const PROP_FILTER_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;

interface CappedBytes {
	bytes: Uint8Array;
	length: number;
	truncated: boolean;
}

async function readCapped(
	stream: ReadableStream<Uint8Array>,
	cap: number,
	onOverflow?: () => void,
): Promise<CappedBytes> {
	const reader = stream.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	let truncated = false;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			const remaining = cap - length;
			if (value.byteLength >= remaining) {
				if (remaining > 0) chunks.push(value.subarray(0, remaining));
				length += Math.max(0, remaining);
				truncated = true;
				onOverflow?.();
				break;
			}
			chunks.push(value);
			length += value.byteLength;
		}
	} finally {
		if (truncated) await reader.cancel().catch(() => {});
	}
	return { bytes: Buffer.concat(chunks.map(chunk => Buffer.from(chunk))), length, truncated };
}

export async function defaultAdbRunner(
	binary: string,
	args: string[],
	options: {
		cwd: string;
		timeoutMs: number;
		maxBytes: number;
		signal?: AbortSignal;
	},
): Promise<AdbRunResult> {
	const child = Bun.spawn([binary, ...args], {
		cwd: options.cwd,
		stdout: "pipe",
		stderr: "pipe",
		stdin: "ignore",
	});
	let timedOut = false;
	let killedOnOverflow = false;
	const timer = setTimeout(() => {
		timedOut = true;
		child.kill();
	}, options.timeoutMs);
	const onAbort = () => {
		child.kill();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });
	if (options.signal?.aborted) child.kill();
	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			readCapped(child.stdout, options.maxBytes, () => {
				killedOnOverflow = true;
				child.kill();
			}),
			readCapped(child.stderr, STDERR_BYTES),
			child.exited,
		]);
		return {
			stdout: stdout.bytes,
			stderr: Buffer.from(stderr.bytes).toString("utf8"),
			exitCode,
			outputBytes: stdout.length,
			truncated: stdout.truncated,
			timedOut,
			killedOnOverflow,
		};
	} finally {
		clearTimeout(timer);
		options.signal?.removeEventListener("abort", onAbort);
	}
}

export function adbDependency(which?: SkillRequirementWhich): AdbDependencyStatus {
	const requirements: ToolRequirement[] = [{ id: "adb" }];
	const [status] = checkToolRequirements(requirements, which ? { which } : undefined);
	const found = status?.foundPath ?? null;
	const available = found !== null;
	const platform: SkillToolPlatform =
		process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";
	const catalogHint = SKILL_TOOL_CATALOG.adb?.installHints?.[platform]?.join(" or ");
	const installHint = status?.hint ?? (available ? undefined : catalogHint);
	return {
		id: "adb",
		available,
		...(available && found ? { path: found } : {}),
		...(installHint && !available ? { installHint } : {}),
		...(SKILL_TOOL_CATALOG.adb?.manualUrl ? { manualUrl: SKILL_TOOL_CATALOG.adb.manualUrl } : {}),
	};
}

export function resolveAdbFallback(
	action: AdbObserveAction,
	options: { package?: string; filter?: string } = {},
): AdbFallbackInfo {
	const apk = "<target.apk>";
	switch (action) {
		case "devices": {
			const suggested = "adb devices -l (from Android SDK Platform-Tools)";
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					"Install platform-tools using the catalog install hint, then enable USB debugging on the device",
					"Start the target AVD from Android Studio and retry",
				],
				executed: false,
			};
		}
		case "packages": {
			const pkg = options.package ? `filter "${options.package}"` : "list declared packages";
			const suggested = `aapt2 dump badging "${apk}"`;
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					`droidasc(op: "manifest", target: "${apk}") to inspect the application id and ${pkg}`,
					"Install Android SDK Platform-Tools to query packages on a live device",
				],
				executed: false,
			};
		}
		case "processes": {
			const suggested = "Use an on-device shell (ps -A) or Android Studio's running-process view";
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					"Install Android SDK Platform-Tools to restore adb shell access",
					"Static analysis cannot enumerate runtime processes; use droidasc/jadx for code-level evidence",
				],
				executed: false,
			};
		}
		case "logcat": {
			const suggested = "Android Studio Logcat or an on-device bug report";
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					"Install Android SDK Platform-Tools to restore adb logcat",
					"Search the APK statically with droidasc findrefs for the same tag or message",
				],
				executed: false,
			};
		}
		case "props": {
			const suggested = `droidasc(op: "manifest", target: "${apk}")`;
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					"Install Android SDK Platform-Tools to read device properties with getprop",
					`Inspect build-related values statically in "${apk}" resources and native libraries`,
				],
				executed: false,
			};
		}
		case "screencap": {
			const suggested = "Capture a screenshot on the device manually and read it with the read tool";
			return {
				primary: "adb",
				action,
				suggestedFallback: suggested,
				activeFallback: suggested,
				alternatives: [
					suggested,
					"Install Android SDK Platform-Tools to restore adb exec-out screencap -p",
					"Use the emulator's screenshot control and save the PNG to the workspace",
				],
				executed: false,
			};
		}
	}
}

function formatMissingNotice(dependency: AdbDependencyStatus, fallback: AdbFallbackInfo): string {
	const hint = dependency.installHint ?? "Install Android SDK Platform-Tools and add platform-tools to PATH";
	const lines = [
		`[Notice] Primary tool 'adb' not found on PATH.`,
		`  -> Install hint: ${hint}`,
		...(dependency.manualUrl ? [`  -> Download: ${dependency.manualUrl}`] : []),
		`  -> Suggested fallback: ${fallback.suggestedFallback}`,
		`  -> Alternative fallback options:`,
		...fallback.alternatives.map(alt => `     • ${alt}`),
		`  (Note: Fallback actions were not executed automatically.)`,
	];
	return lines.join("\n");
}

function firstLine(value: string): string {
	const trimmed = value.trim();
	const newline = trimmed.indexOf("\n");
	return newline === -1 ? trimmed : trimmed.slice(0, newline).trim();
}

/** Parse `adb devices -l` output. Skips daemon banner lines and malformed rows. */
export function parseAdbDevices(output: string): AdbDeviceInfo[] {
	const devices: AdbDeviceInfo[] = [];
	for (const rawLine of output.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (line.length === 0) continue;
		if (line.startsWith("List of devices")) continue;
		if (line.startsWith("*")) continue;
		if (line.startsWith("adb server")) continue;
		const tokens = line.split(/\s+/);
		if (tokens.length < 2) continue;
		const serial = tokens[0];
		const state = tokens[1].toLowerCase();
		if (!SERIAL_PATTERN.test(serial)) continue;
		const details: Record<string, string> = {};
		for (const token of tokens.slice(2)) {
			const separator = token.indexOf(":");
			if (separator <= 0) continue;
			const key = token.slice(0, separator);
			const value = token.slice(separator + 1);
			if (key.length > 0 && value.length > 0) details[key] = value;
		}
		devices.push({
			serial,
			state,
			...(Object.keys(details).length > 0 ? { details } : {}),
		});
	}
	return devices;
}

function formatDeviceList(devices: readonly AdbDeviceInfo[]): string {
	if (devices.length === 0) return "  (none)";
	return devices.map(device => `  - ${device.serial} (${device.state})`).join("\n");
}

function validatePackage(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	if (trimmed.length === 0) throw new ToolError("package must not be empty when provided");
	if (!PACKAGE_PATTERN.test(trimmed)) {
		throw new ToolError(
			`Invalid package name "${value}": expected a dotted Android application id such as com.example.app (letters, digits, and underscores; each segment starts with a letter)`,
		);
	}
	return trimmed;
}

function validateLogcatFilter(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	if (trimmed.length === 0) throw new ToolError("filter must not be empty when provided");
	if (!LOGCAT_FILTER_PATTERN.test(trimmed)) {
		throw new ToolError(
			`Invalid logcat filter "${value}": expected one tag such as ActivityManager, optionally with a priority suffix (:V, :D, :I, :W, :E, or :F)`,
		);
	}
	return trimmed;
}

function validatePropFilter(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	if (trimmed.length === 0) throw new ToolError("filter must not be empty when provided");
	if (!PROP_FILTER_PATTERN.test(trimmed)) {
		throw new ToolError(
			`Invalid property filter "${value}": expected a property key or prefix such as ro.build.version.sdk (letters, digits, dots, underscores, and hyphens)`,
		);
	}
	return trimmed;
}

function validateSerial(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	if (trimmed.length === 0) throw new ToolError("serial must not be empty when provided");
	if (!SERIAL_PATTERN.test(trimmed)) {
		throw new ToolError(
			`Invalid serial "${value}": expected a device serial such as emulator-5554 or 192.168.1.5:5555`,
		);
	}
	return trimmed;
}

function validateLines(value: number | undefined): number {
	if (value === undefined) return DEFAULT_LOGCAT_LINES;
	if (!Number.isFinite(value) || !Number.isInteger(value) || value < 1 || value > MAX_LOGCAT_LINES) {
		throw new ToolError(`lines must be an integer between 1 and ${MAX_LOGCAT_LINES}`);
	}
	return value;
}

function clampTimeout(value: number | undefined): number {
	if (value === undefined) return DEFAULT_TIMEOUT_SECONDS;
	if (!Number.isFinite(value) || value < 1) throw new ToolError("timeout must be a number of seconds >= 1");
	return Math.min(MAX_TIMEOUT_SECONDS, Math.floor(value));
}

function clampMaxBytes(value: number | undefined, action: AdbObserveAction): number {
	const isScreencap = action === "screencap";
	const fallback = isScreencap ? DEFAULT_SCREENCAP_MAX_BYTES : DEFAULT_MAX_BYTES;
	const maximum = isScreencap ? MAX_SCREENCAP_BYTES : MAX_OUTPUT_BYTES;
	if (value === undefined) return fallback;
	if (!Number.isFinite(value) || value < 1) throw new ToolError("max_bytes must be a byte count >= 1");
	return Math.min(maximum, Math.floor(value));
}

function actionArgv(
	action: Exclude<AdbObserveAction, "devices">,
	serial: string,
	options: { filter?: string; lines: number },
): string[] {
	const prefix = ["-s", serial];
	switch (action) {
		case "packages":
			return [...prefix, "shell", "pm", "list", "packages", "-f"];
		case "processes":
			return [...prefix, "shell", "ps", "-A", "-o", "PID,USER,NAME"];
		case "logcat":
			return [
				...prefix,
				"logcat",
				"-d",
				"-v",
				"threadtime",
				"-t",
				String(options.lines),
				...(options.filter ? ["-s", options.filter] : []),
			];
		case "props":
			return [...prefix, "shell", "getprop"];
		case "screencap":
			return [...prefix, "exec-out", "screencap", "-p"];
	}
}

function filterOutput(
	action: AdbObserveAction,
	output: string,
	options: { package?: string; filter?: string },
): string {
	if (action === "packages" && options.package) {
		return output
			.split(/\r?\n/)
			.filter(line => line.trim().endsWith(`=${options.package}`))
			.join("\n");
	}
	if (action === "processes" && options.package) {
		return output
			.split(/\r?\n/)
			.filter(line => line.includes(options.package!))
			.join("\n");
	}
	if (action === "props" && options.filter) {
		return output
			.split(/\r?\n/)
			.filter(line => {
				const match = /^\[([^\]]+)\]: \[(.*)\]$/.exec(line.trim());
				return match ? match[1].startsWith(options.filter!) : false;
			})
			.join("\n");
	}
	return output;
}

function deviceIssueDetails(
	action: AdbObserveAction,
	status: AdbObserveStatus,
	requested: string | undefined,
	devices: readonly AdbDeviceInfo[],
	state?: string,
): AdbObserveDetails {
	return {
		action,
		status,
		...(requested ? { serial: requested } : {}),
		...(state ? { deviceState: state } : {}),
		devices: devices.map(device => ({ ...device })),
	};
}

function deviceIssueNotice(
	action: AdbObserveAction,
	status: AdbObserveStatus,
	requested: string | undefined,
	devices: readonly AdbDeviceInfo[],
	state?: string,
): string {
	switch (status) {
		case "device_not_found":
			return [
				`adb_observe ${action}: device "${requested}" is not attached.`,
				"Attached devices:",
				formatDeviceList(devices),
				requested ? `Pass serial: "<one of the serials above>" to select a device.` : "",
			]
				.filter(Boolean)
				.join("\n");
		case "device_unauthorized":
			return [
				`adb_observe ${action}: device "${requested}" is unauthorized.`,
				"Accept the USB debugging authorization prompt on the device (or revoke/authorize USB debugging in Developer options), then retry.",
				"Attached devices:",
				formatDeviceList(devices),
			].join("\n");
		case "device_offline":
			return [
				`adb_observe ${action}: device "${requested}" is offline.`,
				"Reconnect the USB cable or restart the emulator, then retry.",
				"Attached devices:",
				formatDeviceList(devices),
			].join("\n");
		case "device_unavailable":
			return [
				`adb_observe ${action}: device "${requested ?? "<auto>"}" is in state "${state ?? "unknown"}", which does not accept shell observation.`,
				"Wait for the device to finish booting or reconnect it, then retry.",
				"Attached devices:",
				formatDeviceList(devices),
			].join("\n");
		case "device_required":
			if (devices.length === 0) {
				return [
					`adb_observe ${action}: no Android device or emulator is attached.`,
					"Connect a device with USB debugging enabled, authorize this host, then retry.",
				].join("\n");
			}
			return [
				`adb_observe ${action}: multiple devices are attached, so an explicit serial is required.`,
				"Attached devices:",
				formatDeviceList(devices),
				`Pass serial: "<serial>" to select one (the tool never guesses between devices).`,
			].join("\n");
		default:
			return "";
	}
}

function resolveDevice(
	action: AdbObserveAction,
	devices: readonly AdbDeviceInfo[],
	requested: string | undefined,
): { serial?: string; details?: AdbObserveDetails; notice?: string } {
	if (requested) {
		const match = devices.find(device => device.serial === requested);
		if (!match) {
			const status: AdbObserveStatus = "device_not_found";
			return {
				details: deviceIssueDetails(action, status, requested, devices),
				notice: deviceIssueNotice(action, status, requested, devices),
			};
		}
		if (match.state === "unauthorized") {
			const status: AdbObserveStatus = "device_unauthorized";
			return {
				details: deviceIssueDetails(action, status, requested, devices, match.state),
				notice: deviceIssueNotice(action, status, requested, devices, match.state),
			};
		}
		if (match.state === "offline") {
			const status: AdbObserveStatus = "device_offline";
			return {
				details: deviceIssueDetails(action, status, requested, devices, match.state),
				notice: deviceIssueNotice(action, status, requested, devices, match.state),
			};
		}
		if (match.state !== "device") {
			const status: AdbObserveStatus = "device_unavailable";
			return {
				details: deviceIssueDetails(action, status, requested, devices, match.state),
				notice: deviceIssueNotice(action, status, requested, devices, match.state),
			};
		}
		return { serial: match.serial };
	}

	if (devices.length !== 1) {
		const status: AdbObserveStatus = "device_required";
		return {
			details: deviceIssueDetails(action, status, undefined, devices),
			notice: deviceIssueNotice(action, status, undefined, devices),
		};
	}

	const device = devices[0];
	if (device.state === "unauthorized") {
		const status: AdbObserveStatus = "device_unauthorized";
		return {
			details: deviceIssueDetails(action, status, device.serial, devices, device.state),
			notice: deviceIssueNotice(action, status, device.serial, devices, device.state),
		};
	}
	if (device.state === "offline") {
		const status: AdbObserveStatus = "device_offline";
		return {
			details: deviceIssueDetails(action, status, device.serial, devices, device.state),
			notice: deviceIssueNotice(action, status, device.serial, devices, device.state),
		};
	}
	if (device.state !== "device") {
		const status: AdbObserveStatus = "device_unavailable";
		return {
			details: deviceIssueDetails(action, status, device.serial, devices, device.state),
			notice: deviceIssueNotice(action, status, device.serial, devices, device.state),
		};
	}
	return { serial: device.serial };
}

export class AdbObserveTool implements AgentTool<typeof adbObserveSchema, AdbObserveDetails> {
	readonly name = "adb_observe";
	readonly approval: ToolTier = "read";
	readonly label = "ADB Observe";
	readonly summary =
		"Read-only Android device observation over fixed adb commands: devices, packages, processes, logcat, props, and screencap artifacts";
	readonly description: string;
	readonly parameters = adbObserveSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	constructor(
		private readonly session: ToolSession,
		private readonly options: AdbObserveToolOptions = {},
	) {
		this.description = prompt.render(adbObserveDescription);
	}

	async execute(
		_toolCallId: string,
		params: AdbObserveParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AdbObserveDetails>> {
		throwIfAborted(signal);
		const action = params.action;

		const packageName = validatePackage(params.package);
		const serial = validateSerial(params.serial);
		const lines = validateLines(params.lines);
		let filter: string | undefined;
		if (action === "logcat") {
			filter = validateLogcatFilter(params.filter);
		} else if (action === "props") {
			filter = validatePropFilter(params.filter);
		} else if (params.filter !== undefined) {
			throw new ToolError(`filter is not supported by action "${action}"`);
		}
		if (packageName !== undefined && action !== "packages" && action !== "processes") {
			throw new ToolError(`package is not supported by action "${action}"`);
		}
		if (params.lines !== undefined && action !== "logcat") {
			throw new ToolError(`lines is not supported by action "${action}"`);
		}
		if (serial !== undefined && action === "devices") {
			throw new ToolError(`serial is not supported by action "devices"; omit it to list every attached device`);
		}

		const timeoutSeconds = clampTimeout(params.timeout);
		const maxBytes = clampMaxBytes(params.max_bytes, action);
		const runner = this.options.runner ?? defaultAdbRunner;

		const dependency = adbDependency(this.options.which);
		if (!dependency.available || !dependency.path) {
			const fallback = resolveAdbFallback(action, {
				package: packageName,
				filter,
			});
			return {
				content: [{ type: "text", text: formatMissingNotice(dependency, fallback) }],
				details: {
					action,
					status: "missing_dependency",
					dependency,
					fallback,
					...(packageName ? { package: packageName } : {}),
					...(filter ? { filter } : {}),
					...(action === "logcat" ? { lines } : {}),
				},
			};
		}

		const runOptions = {
			cwd: this.session.cwd,
			timeoutMs: timeoutSeconds * 1000,
			maxBytes,
			signal,
		};

		let preflight: AdbRunResult | undefined;
		let devices: AdbDeviceInfo[] = [];
		if (action !== "devices") {
			try {
				preflight = await runner(dependency.path, ["devices", "-l"], {
					cwd: this.session.cwd,
					timeoutMs: timeoutSeconds * 1000,
					maxBytes: DEFAULT_MAX_BYTES,
					signal,
				});
			} catch (error) {
				throwIfAborted(signal);
				throw new ToolError(`Failed to execute adb: ${error instanceof Error ? error.message : String(error)}`);
			}
			throwIfAborted(signal);

			if (preflight.timedOut) {
				const text = `adb_observe ${action} timed out after ${timeoutSeconds}s while listing devices.`;
				return {
					content: [{ type: "text", text }],
					details: {
						action,
						status: "error",
						dependency,
						error: `device listing timed out after ${timeoutSeconds}s`,
					},
				};
			}
			if (preflight.exitCode !== 0 && preflight.stdout.byteLength === 0) {
				const stderr = firstLine(preflight.stderr).slice(0, 400);
				const text = `adb_observe ${action} failed to list devices${stderr ? `: ${stderr}` : ""}`;
				return {
					content: [{ type: "text", text }],
					details: {
						action,
						status: "error",
						dependency,
						error: `adb devices exited ${preflight.exitCode}${stderr ? `: ${stderr}` : ""}`,
					},
				};
			}
			devices = parseAdbDevices(new TextDecoder().decode(preflight.stdout));
			const resolved = resolveDevice(action, devices, serial);
			if (resolved.notice && resolved.details) {
				return {
					content: [{ type: "text", text: resolved.notice }],
					details: {
						...resolved.details,
						dependency,
					},
				};
			}
			if (!resolved.serial) {
				throw new ToolError("No usable Android device was resolved");
			}
			const serialArg = resolved.serial;

			let raw: AdbRunResult;
			try {
				raw = await runner(dependency.path, actionArgv(action, serialArg, { filter, lines }), runOptions);
			} catch (error) {
				throwIfAborted(signal);
				throw new ToolError(`Failed to execute adb: ${error instanceof Error ? error.message : String(error)}`);
			}
			throwIfAborted(signal);

			return this.formatResult(action, serialArg, raw, {
				dependency,
				packageName,
				filter,
				lines,
				maxBytes,
				timeoutSeconds,
			});
		}

		let raw: AdbRunResult;
		try {
			raw = await runner(dependency.path, ["devices", "-l"], runOptions);
		} catch (error) {
			throwIfAborted(signal);
			throw new ToolError(`Failed to execute adb: ${error instanceof Error ? error.message : String(error)}`);
		}
		throwIfAborted(signal);

		if (raw.timedOut) {
			const text = `adb_observe devices timed out after ${timeoutSeconds}s.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action,
					status: "error",
					dependency,
					error: `timed out after ${timeoutSeconds}s`,
				},
			};
		}
		if (raw.exitCode !== 0 && raw.stdout.byteLength === 0) {
			const stderr = firstLine(raw.stderr).slice(0, 400);
			return {
				content: [
					{
						type: "text",
						text: `adb_observe devices failed (exit ${raw.exitCode})${stderr ? `: ${stderr}` : ""}`,
					},
				],
				details: {
					action,
					status: "error",
					dependency,
					outputBytes: raw.outputBytes,
					error: `exit ${raw.exitCode}${stderr ? `: ${stderr}` : ""}`,
				},
			};
		}

		const body = new TextDecoder().decode(raw.stdout).trim() || "(no devices attached)";
		devices = parseAdbDevices(body);
		const header = `adb_observe devices (${devices.length} attached${raw.truncated ? ", truncated" : ""})`;
		return {
			content: [{ type: "text", text: `${header}\n${body}${truncationFooter(raw, maxBytes)}` }],
			details: {
				action,
				status: "ok",
				dependency,
				devices,
				outputBytes: raw.outputBytes,
				truncated: raw.truncated,
				...(raw.stderr.trim().length > 0 ? { error: firstLine(raw.stderr).slice(0, 400) } : {}),
			},
		};
	}

	private async formatResult(
		action: Exclude<AdbObserveAction, "devices">,
		serial: string,
		run: AdbRunResult,
		context: {
			dependency: AdbDependencyStatus;
			packageName?: string;
			filter?: string;
			lines: number;
			maxBytes: number;
			timeoutSeconds: number;
		},
	): Promise<AgentToolResult<AdbObserveDetails>> {
		if (run.timedOut) {
			const text = `adb_observe ${action} timed out after ${context.timeoutSeconds}s on ${serial}.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action,
					status: "error",
					dependency: context.dependency,
					serial,
					error: `timed out after ${context.timeoutSeconds}s`,
				},
			};
		}

		if (action === "screencap") {
			return this.saveScreencap(serial, run, context);
		}

		const cappedSuccess = run.truncated && run.outputBytes > 0;
		if (run.exitCode !== 0 && !cappedSuccess) {
			const stderr = firstLine(run.stderr).slice(0, 400);
			const text = `adb_observe ${action} failed (exit ${run.exitCode}) on ${serial}${stderr ? `: ${stderr}` : ""}`;
			return {
				content: [{ type: "text", text }],
				details: {
					action,
					status: "error",
					dependency: context.dependency,
					serial,
					outputBytes: run.outputBytes,
					error: `exit ${run.exitCode}${stderr ? `: ${stderr}` : ""}`,
				},
			};
		}

		const decoded = new TextDecoder().decode(run.stdout);
		const filtered = filterOutput(action, decoded, {
			package: context.packageName,
			filter: context.filter,
		});
		const body = filtered.trim().length > 0 ? filtered : "(no matching output)";
		const outputBytes = Buffer.byteLength(filtered, "utf8");
		const header = `adb_observe ${action}: ${serial} (${outputBytes} bytes${run.truncated ? ", truncated" : ""})`;
		return {
			content: [{ type: "text", text: `${header}\n${body}${truncationFooter(run, context.maxBytes)}` }],
			details: {
				action,
				status: "ok",
				dependency: context.dependency,
				serial,
				outputBytes,
				truncated: run.truncated,
				...(context.packageName ? { package: context.packageName } : {}),
				...(context.filter ? { filter: context.filter } : {}),
				...(action === "logcat" ? { lines: context.lines } : {}),
				...(run.stderr.trim().length > 0 ? { error: firstLine(run.stderr).slice(0, 400) } : {}),
			},
		};
	}

	private async saveScreencap(
		serial: string,
		run: AdbRunResult,
		context: {
			dependency: AdbDependencyStatus;
			maxBytes: number;
		},
	): Promise<AgentToolResult<AdbObserveDetails>> {
		if (run.truncated || run.killedOnOverflow) {
			const text = `adb_observe screencap on ${serial} exceeded the ${context.maxBytes}-byte cap; the partial PNG was not saved. Raise max_bytes (up to ${MAX_SCREENCAP_BYTES}) and retry.`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "screencap",
					status: "error",
					dependency: context.dependency,
					serial,
					outputBytes: run.outputBytes,
					truncated: true,
					error: `screencap output exceeded ${context.maxBytes} bytes`,
				},
			};
		}

		const stderr = firstLine(run.stderr).slice(0, 400);
		if (run.exitCode !== 0 || run.stdout.byteLength === 0) {
			const text = `adb_observe screencap failed (exit ${run.exitCode}) on ${serial}${stderr ? `: ${stderr}` : ": no image bytes returned"}`;
			return {
				content: [{ type: "text", text }],
				details: {
					action: "screencap",
					status: "error",
					dependency: context.dependency,
					serial,
					outputBytes: run.outputBytes,
					error: `exit ${run.exitCode}${stderr ? `: ${stderr}` : ": no image bytes returned"}`,
				},
			};
		}

		const allocation = await this.session.allocateOutputArtifact?.("adb_observe");
		if (!allocation?.path || !allocation.id) {
			return {
				content: [
					{
						type: "text",
						text: `adb_observe screencap captured ${run.stdout.byteLength} bytes on ${serial}, but artifact storage is unavailable in this session; the bytes were discarded.`,
					},
				],
				details: {
					action: "screencap",
					status: "error",
					dependency: context.dependency,
					serial,
					outputBytes: run.outputBytes,
					error: "artifact storage unavailable",
				},
			};
		}

		try {
			await Bun.write(allocation.path, run.stdout);
		} catch (error) {
			return {
				content: [
					{
						type: "text",
						text: `adb_observe screencap captured ${run.stdout.byteLength} bytes on ${serial}, but writing the artifact failed: ${error instanceof Error ? error.message : String(error)}`,
					},
				],
				details: {
					action: "screencap",
					status: "error",
					dependency: context.dependency,
					serial,
					outputBytes: run.outputBytes,
					error: `failed to write artifact: ${error instanceof Error ? error.message : String(error)}`,
				},
			};
		}
		return {
			content: [
				{
					type: "text",
					text: [
						`adb_observe screencap: ${serial} (${run.stdout.byteLength} bytes, image/png)`,
						`Saved artifact: artifact://${allocation.id}`,
						`Path: ${allocation.path}`,
					].join("\n"),
				},
			],
			details: {
				action: "screencap",
				status: "ok",
				dependency: context.dependency,
				serial,
				outputBytes: run.outputBytes,
				bytes: run.stdout.byteLength,
				artifactId: allocation.id,
				artifactPath: allocation.path,
				format: "png",
				mimeType: "image/png",
				...(stderr.length > 0 ? { error: stderr } : {}),
			},
		};
	}
}

function truncationFooter(run: AdbRunResult, maxBytes: number): string {
	if (!run.truncated) return "";
	const maximum = maxBytes >= DEFAULT_SCREENCAP_MAX_BYTES ? MAX_SCREENCAP_BYTES : MAX_OUTPUT_BYTES;
	return `\n… output truncated at ${maxBytes} bytes; raise max_bytes (up to ${maximum}) or narrow the filter for more.`;
}
