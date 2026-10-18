import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { type } from "@rva/omptype";
import type { AgentTool, AgentToolResult } from "@rva/agent";
import { $which, getFridaSessionsDir, isEnoent, logger } from "@rva/utils";
import fridaSessionDescription from "../prompts/tools/frida-session.md" with { type: "text" };
import { redactMemorySecrets } from "../memory-backend/redact";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import { replaceFileAtomically } from "../utils/atomic-file";
import type { ToolSession } from "./index";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { throwIfAborted } from "./tool-errors";
import {
	defaultFridaRunner,
	FIXED_ENUMERATE_MODULES_SCRIPT,
	fridaDependency,
	type FridaDependencyStatus,
	type FridaFallbackInfo,
	type FridaRunResult,
	type FridaRunner,
	resolveFridaFallback,
	resolveScriptPath,
	splitCliArgs,
} from "./frida";

export const fridaSessionSchema = type({
	"action?": type
		.enumerated("create", "list", "status", "run", "stop", "destroy")
		.describe(
			"Action to perform: 'create' (start/initialize new analysis session), 'list' (list saved sessions), 'status' (inspect session state and target status), 'run' (execute script or enumeration in session context), 'stop' (suspend/stop session and active child), 'destroy' (terminate and remove session)",
		),
	"session_id?": type("string").describe(
		"Identifier for the session. Auto-generated on create if omitted. Required for run/status/stop/destroy when multiple sessions exist",
	),
	"name?": type("string").describe("Optional friendly name or label for the session"),
	"pid?": type("number").describe(
		"Target process ID (PID) to attach to. Mutually exclusive with process and spawn",
	),
	"process?": type("string").describe(
		"Target process name or application package to attach to. Mutually exclusive with pid and spawn",
	),
	"spawn?": type("string").describe(
		"Target application identifier or binary path to spawn as a persistent session. Mutually exclusive with pid and process",
	),
	"usb?": type("boolean").describe("Target USB device/emulator (shorthand for frida -U)"),
	"device?": type("string").describe("Target device serial or ID (passes -D <device>)"),
	"host?": type("string").describe("Target remote frida-server host (e.g. '192.168.1.5:27042', passes -H <host>)"),
	"script?": type("string").describe("Inline Frida JavaScript source code to execute"),
	"script_path?": type("string").describe("Local path to a Frida JavaScript script file to execute"),
	"command?": type("string").describe(
		"Builtin evaluation command: 'script' (default), 'modules' (list loaded modules), 'ps' (list processes), 'inspect' (inspect target environment)",
	),
	"script_args?": type("unknown").describe("Optional arguments passed to the script via -P / --parameters JSON"),
	"no_pause?": type("boolean").describe("For spawn mode: start main thread immediately (default: true)"),
	"filter?": type("string").describe("Optional text filter for list action or output inspection"),
	"cli_args?": type("unknown").describe("Optional array of extra CLI arguments passed directly to Frida"),
	"timeout?": type("number").describe("Watchdog execution timeout in seconds (default: 30)"),
	"max_bytes?": type("number").describe("Maximum stdout bytes captured before truncation (default: 262144)"),
	"to_artifact?": type("boolean").describe("Save complete output and session records to session artifact"),
});

export type FridaSessionParams = typeof fridaSessionSchema.infer;
export type FridaSessionAction = "create" | "list" | "status" | "run" | "stop" | "destroy";
export type FridaSessionStatus = "ok" | "missing_dependency" | "stopped" | "not_found" | "timeout" | "error";

export interface FridaSessionTarget {
	type: "pid" | "process" | "spawn";
	value: string | number;
	pid?: number;
	process?: string;
	spawn?: string;
	usb?: boolean;
	device?: string;
	host?: string;
	noPause?: boolean;
}

export interface FridaSessionRunEntry {
	id: string;
	timestamp: string;
	command?: string;
	scriptSnippet?: string;
	scriptSource?: "inline" | "file";
	scriptPath?: string;
	exitCode?: number;
	outputBytes?: number;
	truncated?: boolean;
	error?: string;
}

export interface FridaSessionRecord {
	id: string;
	name?: string;
	target: FridaSessionTarget;
	status: "active" | "stopped" | "failed" | "error";
	createdAt: string;
	updatedAt: string;
	lastRunAt?: string;
	runsCount: number;
	history: FridaSessionRunEntry[];
	activeChildPid?: number;
	lastScript?: string;
	metadata?: Record<string, unknown>;
}

export interface FridaSessionDetails {
	action: FridaSessionAction;
	status: FridaSessionStatus;
	sessionId?: string;
	session?: FridaSessionRecord;
	sessions?: FridaSessionRecord[];
	target?: string;
	targetMode?: string;
	exitCode?: number;
	stdout?: string;
	stderr?: string;
	outputBytes?: number;
	truncated?: boolean;
	timedOut?: boolean;
	dependency?: FridaDependencyStatus;
	fallback?: FridaFallbackInfo;
	error?: string;
	artifactId?: string;
	artifactPath?: string;
}

export interface FridaSessionToolOptions {
	which?: SkillRequirementWhich;
	runner?: FridaRunner;
	stateRoot?: string;
}

const DEFAULT_TIMEOUT_SECONDS = 30;
const DEFAULT_MAX_BYTES = 256 * 1024;
const INSPECT_TARGET_SCRIPT =
	"(function(){try{return JSON.stringify({pid:Process.id,arch:Process.arch,platform:Process.platform,pageSize:Process.pageSize,pointerSize:Process.pointerSize});}catch(e){return JSON.stringify({error:e.message||String(e)});}})();";

interface ActiveChild {
	sessionId: string;
	pid?: number;
	child?: {
		kill: (signal?: number | string) => void;
		exited: Promise<number>;
		pid?: number;
	};
	abortController?: AbortController;
	startedAt: number;
}

const ACTIVE_CHILDREN = new Map<string, ActiveChild>();

let exitHookInstalled = false;
function ensureExitHook(): void {
	if (exitHookInstalled) return;
	exitHookInstalled = true;
	process.once("exit", () => {
		for (const [, active] of ACTIVE_CHILDREN) {
			try {
				active.abortController?.abort();
				active.child?.kill();
			} catch {
				// Best effort on exit
			}
		}
		ACTIVE_CHILDREN.clear();
	});
}

export function isProcessAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (error: unknown) {
		if (error && typeof error === "object" && "code" in error) {
			return error.code === "EPERM";
		}
		return false;
	}
}

function stopActiveChild(sessionId: string, targetPid?: number): boolean {
	let stopped = false;
	const active = ACTIVE_CHILDREN.get(sessionId);
	if (active) {
		try {
			active.abortController?.abort();
			active.child?.kill();
			stopped = true;
		} catch {
			// ignore
		}
		ACTIVE_CHILDREN.delete(sessionId);
	}
	if (targetPid && isProcessAlive(targetPid)) {
		try {
			process.kill(targetPid, "SIGTERM");
			stopped = true;
		} catch {
			// ignore
		}
	}
	return stopped;
}

export function encodeProjectKey(repositoryRoot: string): string {
	const normalized = repositoryRoot.replaceAll("\\", "/").replace(/\/$/, "");
	const readable = normalized
		.replace(/^\//, "")
		.replace(/[^a-zA-Z0-9._-]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(-80);
	return `${readable || "project"}-${Bun.SHA256.hash(normalized, "hex").slice(0, 12)}`;
}

function sanitizeSessionText(value: string): string {
	let redacted = redactMemorySecrets(value);
	redacted = redacted.replace(/(\b(?:bearer|basic)\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[REDACTED]");
	redacted = redacted.replace(/(\b(?:password|secret|token)\s*[:=]\s*['"]?)[^\s,'"`;}]+/gi, "$1[REDACTED]");
	return redacted;
}

export function sanitizeRecordSecrets(record: FridaSessionRecord): FridaSessionRecord {
	return {
		...record,
		lastScript: record.lastScript ? sanitizeSessionText(record.lastScript) : undefined,
		history: record.history.map(entry => ({
			...entry,
			scriptSnippet: entry.scriptSnippet ? sanitizeSessionText(entry.scriptSnippet) : undefined,
			error: entry.error ? sanitizeSessionText(entry.error) : undefined,
		})),
		metadata: record.metadata
			? (JSON.parse(sanitizeSessionText(JSON.stringify(record.metadata))) as Record<string, unknown>)
			: undefined,
	};
}

export class FridaSessionStore {
	readonly projectDirectory: string;

	constructor(projectDirectory: string) {
		this.projectDirectory = projectDirectory;
	}

	async ensureDir(): Promise<void> {
		await fs.mkdir(this.projectDirectory, { recursive: true, mode: 0o700 });
		if (process.platform !== "win32") {
			await fs.chmod(this.projectDirectory, 0o700).catch(() => undefined);
		}
	}

	filePath(sessionId: string): string {
		const safeId = sessionId.replace(/[^a-zA-Z0-9._-]/g, "_");
		return path.join(this.projectDirectory, `${safeId}.json`);
	}

	async save(record: FridaSessionRecord): Promise<void> {
		await this.ensureDir();
		const targetPath = this.filePath(record.id);
		const tempPath = `${targetPath}.${process.pid}.${Bun.randomUUIDv7().slice(0, 8)}.tmp`;
		const sanitized = sanitizeRecordSecrets(record);
		const json = JSON.stringify(sanitized, null, 2);
		await Bun.write(tempPath, json);
		if (process.platform !== "win32") {
			await fs.chmod(tempPath, 0o600).catch(() => undefined);
		}
		await replaceFileAtomically(tempPath, targetPath);
	}

	async get(sessionId: string): Promise<FridaSessionRecord | null> {
		const targetPath = this.filePath(sessionId);
		try {
			const text = await Bun.file(targetPath).text();
			return JSON.parse(text) as FridaSessionRecord;
		} catch (error) {
			if (isEnoent(error)) return null;
			throw error;
		}
	}

	async delete(sessionId: string): Promise<boolean> {
		const targetPath = this.filePath(sessionId);
		try {
			await fs.unlink(targetPath);
			return true;
		} catch (error) {
			if (isEnoent(error)) return false;
			throw error;
		}
	}

	async list(): Promise<FridaSessionRecord[]> {
		await this.ensureDir();
		try {
			const entries = await fs.readdir(this.projectDirectory, { withFileTypes: true });
			const records: FridaSessionRecord[] = [];
			for (const entry of entries) {
				if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
				try {
					const text = await Bun.file(path.join(this.projectDirectory, entry.name)).text();
					records.push(JSON.parse(text) as FridaSessionRecord);
				} catch {
					// Skip damaged entry
				}
			}
			records.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
			return records;
		} catch (error) {
			if (isEnoent(error)) return [];
			throw error;
		}
	}
}

export class FridaSessionTool implements AgentTool<typeof fridaSessionSchema, FridaSessionDetails> {
	readonly name = "frida_session";
	readonly description = fridaSessionDescription;
	readonly schema = fridaSessionSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	private readonly which: SkillRequirementWhich;
	private readonly runner: FridaRunner;
	private readonly stateRoot?: string;

	constructor(
		private readonly session: ToolSession,
		options: FridaSessionToolOptions = {},
	) {
		this.which = options.which ?? $which;
		this.runner = options.runner ?? defaultFridaRunner;
		this.stateRoot = options.stateRoot;
		ensureExitHook();
	}

	private getStore(): FridaSessionStore {
		const projectKey = encodeProjectKey(this.session.cwd);
		const baseDir = this.stateRoot ? path.resolve(this.stateRoot) : getFridaSessionsDir();
		const projectDir = path.join(baseDir, projectKey);
		return new FridaSessionStore(projectDir);
	}

	async execute(
		toolCallId: string,
		params: FridaSessionParams,
		_onUpdate?: (result: AgentToolResult<FridaSessionDetails>) => void,
		_ctx?: unknown,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		throwIfAborted(signal);

		const action: FridaSessionAction =
			params.action ?? (params.script || params.script_path || params.command ? "run" : "list");
		const store = this.getStore();

		switch (action) {
			case "create":
				return this.handleCreate(params, store, signal);
			case "list":
				return this.handleList(params, store);
			case "status":
				return this.handleStatus(params, store);
			case "run":
				return this.handleRun(params, store, signal);
			case "stop":
				return this.handleStop(params, store);
			case "destroy":
				return this.handleDestroy(params, store);
			default:
				throw new ToolError(`Unsupported action: ${action}`);
		}
	}

	private async handleCreate(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const targetCount = [params.pid !== undefined, Boolean(params.process), Boolean(params.spawn)].filter(
			Boolean,
		).length;
		if (targetCount === 0) {
			throw new ToolError("Must specify target: 'pid', 'process', or 'spawn'");
		}
		if (targetCount > 1) {
			throw new ToolError("Mutually exclusive: cannot provide more than one of 'pid', 'process', or 'spawn'");
		}

		const transportCount = [Boolean(params.usb), Boolean(params.device), Boolean(params.host)].filter(Boolean).length;
		if (transportCount > 1) {
			throw new ToolError("Mutually exclusive: cannot combine 'usb', 'device', or 'host'");
		}

		const dependency = fridaDependency(this.which);
		if (!dependency.available) {
			const fallback = resolveFridaFallback("exec", {
				process: params.process,
				pid: params.pid,
			});
			const installHint =
				dependency.installHint ?? "pipx install frida-tools (or python3 -m pip install --user frida-tools)";
			return {
				content: [
					{
						type: "text",
						text: [
							"frida_session: Frida tools are not available on this machine.",
							`Install: ${installHint}`,
							`Documentation: ${dependency.manualUrl ?? "https://frida.re/docs/installation/"}`,
							"",
							`Suggested fallback: ${fallback.suggestedFallback}`,
							"Alternative approaches:",
							...fallback.alternatives.map(a => `  - ${a}`),
						].join("\n"),
					},
				],
				details: {
					action: "create",
					status: "missing_dependency",
					dependency,
					fallback,
					error: "Frida CLI binary not found in PATH",
				},
			};
		}

		const sessionId = params.session_id?.trim() || `frida_sess_${Bun.randomUUIDv7().slice(0, 12)}`;
		const existing = await store.get(sessionId);
		if (existing && existing.status === "active") {
			return {
				content: [
					{
						type: "text",
						text: `Frida session '${sessionId}' is already active for target ${existing.target.type}:${existing.target.value}.`,
					},
				],
				details: {
					action: "create",
					status: "ok",
					sessionId,
					session: existing,
					target: String(existing.target.value),
					targetMode: existing.target.type,
				},
			};
		}

		const targetType: "pid" | "process" | "spawn" =
			params.pid !== undefined ? "pid" : params.process ? "process" : "spawn";
		const targetValue: string | number =
			params.pid !== undefined ? params.pid : params.process ? params.process.trim() : params.spawn!.trim();

		const target: FridaSessionTarget = {
			type: targetType,
			value: targetValue,
			...(params.pid !== undefined ? { pid: params.pid } : {}),
			...(params.process ? { process: params.process.trim() } : {}),
			...(params.spawn ? { spawn: params.spawn.trim() } : {}),
			...(params.usb ? { usb: true } : {}),
			...(params.device ? { device: params.device.trim() } : {}),
			...(params.host ? { host: params.host.trim() } : {}),
			...(params.no_pause !== undefined ? { noPause: params.no_pause } : {}),
		};

		let initialStdout = "";
		let initialStderr = "";
		let initialExitCode = 0;
		let initialHistory: FridaSessionRunEntry[] = [];
		let activeChildPid: number | undefined;

		const hasInitialScript = Boolean(params.script || params.script_path);
		if (hasInitialScript) {
			const runResult = await this.executeFridaRun(
				target,
				{
					script: params.script,
					script_path: params.script_path,
					script_args: params.script_args,
					cli_args: params.cli_args,
					timeout: params.timeout,
					max_bytes: params.max_bytes,
				},
				signal,
			);
			initialStdout = runResult.stdout;
			initialStderr = runResult.stderr;
			initialExitCode = runResult.exitCode;
			initialHistory.push({
				id: Bun.randomUUIDv7().slice(0, 8),
				timestamp: new Date().toISOString(),
				command: "initial_script",
				scriptSnippet: (params.script ?? params.script_path ?? "").slice(0, 200),
				scriptSource: params.script_path ? "file" : "inline",
				scriptPath: params.script_path ? resolveScriptPath(params.script_path, this.session.cwd) : undefined,
				exitCode: runResult.exitCode,
				outputBytes: runResult.outputBytes,
				truncated: runResult.truncated,
				error: runResult.exitCode !== 0 ? runResult.stderr.trim() : undefined,
			});
		} else if (targetType === "spawn") {
			// Probe spawn target
			const probeResult = await this.executeFridaRun(
				target,
				{
					script: "console.log('__FRIDA_SPAWN_OK__:' + Process.id);",
					timeout: params.timeout ?? 10,
					max_bytes: params.max_bytes,
				},
				signal,
			);
			initialStdout = probeResult.stdout;
			initialStderr = probeResult.stderr;
			initialExitCode = probeResult.exitCode;
			const match = probeResult.stdout.match(/__FRIDA_SPAWN_OK__:(\d+)/);
			if (match) {
				activeChildPid = Number.parseInt(match[1], 10);
			}
		}

		const now = new Date().toISOString();
		const record: FridaSessionRecord = {
			id: sessionId,
			...(params.name ? { name: params.name.trim() } : {}),
			target,
			status: initialExitCode === 0 ? "active" : "failed",
			createdAt: now,
			updatedAt: now,
			...(hasInitialScript ? { lastRunAt: now } : {}),
			runsCount: initialHistory.length,
			history: initialHistory,
			...(activeChildPid !== undefined ? { activeChildPid } : {}),
			...(hasInitialScript ? { lastScript: (params.script ?? params.script_path ?? "").slice(0, 500) } : {}),
		};

		await store.save(record);

		const lines: string[] = [
			`Frida session '${sessionId}' created for target ${targetType}:${targetValue} (status: ${record.status}).`,
		];
		if (params.name) lines.push(`Name: ${params.name}`);
		if (target.usb) lines.push("Transport: USB / emulator");
		else if (target.device) lines.push(`Transport: device (${target.device})`);
		else if (target.host) lines.push(`Transport: remote host (${target.host})`);

		if (initialStdout.length > 0) {
			lines.push("", initialStdout.trimEnd());
		}
		if (initialStderr.length > 0) {
			lines.push(`[stderr]\n${initialStderr.trimEnd()}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "create",
				status: record.status === "active" ? "ok" : "error",
				sessionId,
				session: record,
				target: String(targetValue),
				targetMode: targetType,
				exitCode: initialExitCode,
				stdout: initialStdout,
				stderr: initialStderr,
			},
		};
	}

	private async handleList(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const records = await store.list();
		const updatedRecords: FridaSessionRecord[] = [];

		for (const record of records) {
			if (record.status === "active" && record.activeChildPid) {
				if (!isProcessAlive(record.activeChildPid)) {
					record.status = "stopped";
					record.updatedAt = new Date().toISOString();
					await store.save(record);
				}
			}
			updatedRecords.push(record);
		}

		const filterText = params.filter?.toLowerCase().trim();
		const filtered = updatedRecords.filter(r => {
			if (!filterText) return true;
			return (
				r.id.toLowerCase().includes(filterText) ||
				r.name?.toLowerCase().includes(filterText) ||
				String(r.target.value).toLowerCase().includes(filterText) ||
				r.status.toLowerCase().includes(filterText)
			);
		});

		if (filtered.length === 0) {
			return {
				content: [{ type: "text", text: "No Frida sessions found." }],
				details: {
					action: "list",
					status: "ok",
					sessions: [],
				},
			};
		}

		const lines: string[] = [`Frida sessions (${filtered.length} found):`];
		for (const s of filtered) {
			const label = s.name ? `${s.id} (${s.name})` : s.id;
			const transport = s.target.usb ? " [USB]" : s.target.host ? ` [${s.target.host}]` : "";
			lines.push(
				`  - ${label}: ${s.target.type}=${s.target.value}${transport} | status=${s.status} | runs=${s.runsCount} | updated=${s.updatedAt}`,
			);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "list",
				status: "ok",
				sessions: filtered,
			},
		};
	}

	private async handleStatus(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [
					{
						type: "text",
						text: params.session_id
							? `Frida session '${params.session_id}' not found.`
							: "No active or existing Frida sessions found.",
					},
				],
				details: {
					action: "status",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}

		if (session.status === "active" && session.activeChildPid) {
			if (!isProcessAlive(session.activeChildPid)) {
				session.status = "stopped";
				session.updatedAt = new Date().toISOString();
				await store.save(session);
			}
		}

		const lines: string[] = [
			`Frida session status: ${session.id}`,
			`Target: ${session.target.type}:${session.target.value}`,
			`Status: ${session.status}`,
			`Runs executed: ${session.runsCount}`,
			`Created: ${session.createdAt}`,
			`Updated: ${session.updatedAt}`,
		];
		if (session.name) lines.push(`Name: ${session.name}`);
		if (session.activeChildPid) lines.push(`Active PID: ${session.activeChildPid}`);
		if (session.lastRunAt) lines.push(`Last run: ${session.lastRunAt}`);
		if (session.lastScript) lines.push(`Last script snippet:\n  ${session.lastScript.replace(/\n/g, "\n  ")}`);

		if (session.history.length > 0) {
			lines.push("", `Recent history (${Math.min(session.history.length, 5)} runs):`);
			for (const h of session.history.slice(-5)) {
				lines.push(`  - [${h.timestamp}] exitCode=${h.exitCode ?? 0} bytes=${h.outputBytes ?? 0}: ${h.command ?? h.scriptSnippet?.slice(0, 60)}`);
			}
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "status",
				status: "ok",
				sessionId: session.id,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
			},
		};
	}

	private async handleRun(
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			throw new ToolError(
				params.session_id
					? `Frida session '${params.session_id}' not found.`
					: "No Frida session found. Create a session first using action: 'create'",
			);
		}

		const dependency = fridaDependency(this.which);
		if (!dependency.available) {
			const fallback = resolveFridaFallback("exec", {
				process: session.target.process,
				pid: session.target.pid,
			});
			return {
				content: [
					{
						type: "text",
						text: [
							"frida_session: Frida tools are not available on this machine.",
							`Install: ${dependency.installHint ?? "pipx install frida-tools"}`,
							`Suggested fallback: ${fallback.suggestedFallback}`,
						].join("\n"),
					},
				],
				details: {
					action: "run",
					status: "missing_dependency",
					sessionId: session.id,
					session,
					dependency,
					fallback,
					error: "Frida CLI binary not found in PATH",
				},
			};
		}

		const command = params.command ?? (params.script || params.script_path ? "script" : "inspect");
		let scriptToRun: string | undefined = params.script;
		let scriptPathToRun: string | undefined = params.script_path;

		if (command === "modules") {
			scriptToRun = FIXED_ENUMERATE_MODULES_SCRIPT;
			scriptPathToRun = undefined;
		} else if (command === "inspect") {
			scriptToRun = INSPECT_TARGET_SCRIPT;
			scriptPathToRun = undefined;
		} else if (command === "ps") {
			// run frida-ps against session target device
			return this.handleRunPs(session, params, store, signal);
		} else if (!scriptToRun && !scriptPathToRun) {
			throw new ToolError("Must provide 'script', 'script_path', or 'command' for run action");
		}

		const maxBytes = params.max_bytes ?? DEFAULT_MAX_BYTES;
		const runResult = await this.executeFridaRun(
			session.target,
			{
				script: scriptToRun,
				script_path: scriptPathToRun,
				script_args: params.script_args,
				cli_args: params.cli_args,
				timeout: params.timeout,
				max_bytes: maxBytes,
			},
			signal,
		);

		const now = new Date().toISOString();
		const snippet = (scriptToRun ?? scriptPathToRun ?? command).slice(0, 300);
		const historyEntry: FridaSessionRunEntry = {
			id: Bun.randomUUIDv7().slice(0, 8),
			timestamp: now,
			command,
			scriptSnippet: snippet,
			scriptSource: scriptPathToRun ? "file" : "inline",
			scriptPath: scriptPathToRun ? resolveScriptPath(scriptPathToRun, this.session.cwd) : undefined,
			exitCode: runResult.exitCode,
			outputBytes: runResult.outputBytes,
			truncated: runResult.truncated,
			error: runResult.exitCode !== 0 ? runResult.stderr.trim() : undefined,
		};

		session.history.push(historyEntry);
		session.runsCount++;
		session.lastRunAt = now;
		session.updatedAt = now;
		session.lastScript = snippet;
		if (runResult.exitCode === 0 && session.status !== "active") {
			session.status = "active";
		}
		await store.save(session);

		let artifactId: string | undefined;
		let artifactPath: string | undefined;
		if (params.to_artifact && this.session.allocateOutputArtifact) {
			try {
				const allocation = await this.session.allocateOutputArtifact("frida_session");
				if (allocation) {
					artifactId = allocation.id;
					artifactPath = allocation.path;
					const recordToSave = {
						sessionId: session.id,
						target: session.target,
						command,
						stdout: runResult.stdout,
						stderr: runResult.stderr,
						exitCode: runResult.exitCode,
						executedAt: now,
					};
					await Bun.write(artifactPath, JSON.stringify(recordToSave, null, 2));
				}
			} catch (err) {
				logger.warn(`Failed to allocate artifact: ${err}`);
			}
		}

		const lines: string[] = [];
		if (runResult.exitCode === 0) {
			lines.push(`frida_session run succeeded on ${session.id} (${session.target.type}:${session.target.value}):`);
		} else if (runResult.timedOut) {
			lines.push(`frida_session run timed out on ${session.id}:`);
		} else {
			lines.push(`frida_session run failed on ${session.id} (exit code ${runResult.exitCode}):`);
		}

		if (runResult.stdout.length > 0) {
			lines.push(runResult.stdout.trimEnd());
		}
		if (runResult.stderr.length > 0) {
			lines.push(`[stderr]\n${runResult.stderr.trimEnd()}`);
		}
		if (runResult.truncated) {
			lines.push(`\n… output truncated at ${maxBytes} bytes; full record preserved in session.`);
		}
		if (artifactId) {
			lines.push(`Full execution record saved to artifact: ${artifactId}`);
		}

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "run",
				status: runResult.exitCode === 0 ? "ok" : runResult.timedOut ? "timeout" : "error",
				sessionId: session.id,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
				exitCode: runResult.exitCode,
				stdout: runResult.stdout,
				stderr: runResult.stderr,
				outputBytes: runResult.outputBytes,
				truncated: runResult.truncated,
				timedOut: runResult.timedOut,
				...(artifactId ? { artifactId } : {}),
				...(artifactPath ? { artifactPath } : {}),
			},
		};
	}

	private async handleRunPs(
		session: FridaSessionRecord,
		params: FridaSessionParams,
		store: FridaSessionStore,
		signal?: AbortSignal,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const dependency = fridaDependency(this.which);
		const binary = dependency.fridaPsPath ?? dependency.path ?? "frida-ps";
		const args: string[] = [];
		if (session.target.usb) args.push("-U");
		else if (session.target.device) args.push("-D", session.target.device);
		else if (session.target.host) args.push("-H", session.target.host);

		if (params.cli_args) {
			const extra = Array.isArray(params.cli_args)
				? params.cli_args.map(String)
				: splitCliArgs(String(params.cli_args));
			args.push(...extra);
		}

		const maxBytes = params.max_bytes ?? DEFAULT_MAX_BYTES;
		const result = await this.runner(binary, args, {
			cwd: this.session.cwd,
			timeoutMs: (params.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000,
			maxBytes,
			signal,
		});

		const rawOutput = Buffer.from(result.stdout).toString("utf8");
		const now = new Date().toISOString();
		session.history.push({
			id: Bun.randomUUIDv7().slice(0, 8),
			timestamp: now,
			command: "ps",
			exitCode: result.exitCode,
			outputBytes: result.outputBytes,
		});
		session.runsCount++;
		session.lastRunAt = now;
		session.updatedAt = now;
		await store.save(session);

		return {
			content: [{ type: "text", text: rawOutput.trimEnd() }],
			details: {
				action: "run",
				status: result.exitCode === 0 ? "ok" : "error",
				sessionId: session.id,
				session,
				target: String(session.target.value),
				targetMode: session.target.type,
				exitCode: result.exitCode,
				stdout: rawOutput,
				stderr: result.stderr,
				outputBytes: result.outputBytes,
				truncated: result.truncated,
				timedOut: result.timedOut,
			},
		};
	}

	private async handleStop(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [{ type: "text", text: `Frida session '${params.session_id ?? "unknown"}' not found.` }],
				details: {
					action: "stop",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}

		stopActiveChild(session.id, session.activeChildPid);
		session.status = "stopped";
		session.updatedAt = new Date().toISOString();
		await store.save(session);

		return {
			content: [{ type: "text", text: `Frida session '${session.id}' stopped.` }],
			details: {
				action: "stop",
				status: "ok",
				sessionId: session.id,
				session,
			},
		};
	}

	private async handleDestroy(
		params: FridaSessionParams,
		store: FridaSessionStore,
	): Promise<AgentToolResult<FridaSessionDetails>> {
		const session = await this.resolveTargetSession(params.session_id, store);
		if (!session) {
			return {
				content: [{ type: "text", text: `Frida session '${params.session_id ?? "unknown"}' not found.` }],
				details: {
					action: "destroy",
					status: "not_found",
					sessionId: params.session_id,
				},
			};
		}

		stopActiveChild(session.id, session.activeChildPid);
		await store.delete(session.id);

		return {
			content: [{ type: "text", text: `Frida session '${session.id}' destroyed and removed.` }],
			details: {
				action: "destroy",
				status: "ok",
				sessionId: session.id,
			},
		};
	}

	private async resolveTargetSession(
		sessionId: string | undefined,
		store: FridaSessionStore,
	): Promise<FridaSessionRecord | null> {
		if (sessionId && sessionId.trim().length > 0) {
			return store.get(sessionId.trim());
		}
		const all = await store.list();
		if (all.length === 0) return null;
		const active = all.find(s => s.status === "active");
		return active ?? all[0];
	}

	private async executeFridaRun(
		target: FridaSessionTarget,
		options: {
			script?: string;
			script_path?: string;
			script_args?: unknown;
			cli_args?: unknown;
			timeout?: number;
			max_bytes?: number;
		},
		signal?: AbortSignal,
	): Promise<{
		stdout: string;
		stderr: string;
		exitCode: number;
		outputBytes: number;
		truncated: boolean;
		timedOut: boolean;
	}> {
		const dependency = fridaDependency(this.which);
		const binary = dependency.path ?? "frida";
		const args: string[] = [];

		if (target.usb) {
			args.push("-U");
		} else if (target.device) {
			args.push("-D", target.device);
		} else if (target.host) {
			args.push("-H", target.host);
		}

		if (target.type === "pid") {
			args.push("-p", String(target.pid));
		} else if (target.type === "process") {
			args.push("-n", target.process!);
		} else if (target.type === "spawn") {
			args.push("-f", target.spawn!);
			if (target.noPause !== false) {
				args.push("--no-pause");
			}
		}

		if (options.script_path) {
			const resolved = resolveScriptPath(options.script_path, this.session.cwd);
			args.push("-l", resolved);
		} else if (options.script) {
			args.push("-e", options.script);
		}

		if (options.script_args !== undefined) {
			const json =
				typeof options.script_args === "string" ? options.script_args : JSON.stringify(options.script_args);
			args.push("-P", json);
		}

		args.push("-q");
		const timeout = options.timeout ?? DEFAULT_TIMEOUT_SECONDS;
		if (timeout > 0) {
			args.push("-t", String(timeout));
		}

		if (options.cli_args) {
			const extra = Array.isArray(options.cli_args)
				? options.cli_args.map(String)
				: splitCliArgs(String(options.cli_args));
			args.push(...extra);
		}

		const maxBytes = options.max_bytes ?? DEFAULT_MAX_BYTES;
		const result = await this.runner(binary, args, {
			cwd: this.session.cwd,
			timeoutMs: timeout * 1000,
			maxBytes,
			signal,
		});

		const rawOutput = Buffer.from(result.stdout).toString("utf8");
		const isTruncated = result.truncated || rawOutput.length > maxBytes;
		const displayOutput = isTruncated ? rawOutput.slice(0, maxBytes) : rawOutput;

		return {
			stdout: displayOutput,
			stderr: result.stderr,
			exitCode: result.exitCode,
			outputBytes: result.outputBytes,
			truncated: isTruncated,
			timedOut: result.timedOut,
		};
	}
}
