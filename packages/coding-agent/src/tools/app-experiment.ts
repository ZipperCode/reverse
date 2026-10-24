import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import * as fs from "node:fs/promises";
import { constants } from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import { prompt } from "@reverse/utils";
import appExperimentDescription from "../prompts/tools/app-experiment.md" with { type: "text" };
import {
	checkToolRequirements,
	type SkillRequirementWhich,
	type ToolRequirement,
} from "../extensibility/skill-requirements";
import type { ToolSession } from "./index";
import { resolveReadPath } from "./path-utils";
import { throwIfAborted } from "./tool-errors";
import { trackLateCleanup } from "../utils/late-cleanup";
import { defaultAdbRunner, adbDependency, parseAdbDevices, type AdbRunner, type AdbRunResult } from "./adb-observe";
import { AndroidPackageInspectTool } from "./android-package-inspect";
import { FridaTool, parseFridaTrace } from "./frida";

// ============================================================================
// Parameter Schema
// ============================================================================

const replayVariantRequestSchema = type({
	id: "string",
	"name?": "string",
	"url?": "string",
	"method?": type.enumerated("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"),
	"headers?": type("Record<string, string>"),
	"body_file?": "string",
	"auth_header_env?": "string",
	"header_env_map?": type("Record<string, string>"),
});

const appExperimentSchema = type({
	action: type
		.enumerated(
			"preflight",
			"invoke_component",
			"query_provider",
			"extract_sandbox_data",
			"webview_debug",
			"network_replay",
			"mitm_capture",
			"pinning_diagnose",
		)
		.describe("Application experiment action"),
	"serial?": type("string").describe("Target device serial (e.g. emulator-5554). Required for device actions"),
	"package?": type("string").describe("Target Android application id (e.g. com.example.app)"),
	"path?": type("string").describe("Path to target APK file (.apk) for static pinning diagnosis"),
	"allowed_authorities?": type("string[]").describe(
		"Explicit list of allowed provider authorities for query_provider if package verification is bypassed",
	),
	"component?": type("string").describe("Component name for invocation (e.g. com.example.app/.MainActivity)"),
	"component_type?": type
		.enumerated("activity", "service", "broadcast")
		.describe("Component invocation type (default activity)"),
	"intent_action?": type("string").describe("Intent action (e.g. android.intent.action.VIEW)"),
	"intent_category?": type("string").describe("Intent category (e.g. android.intent.category.BROWSABLE)"),
	"intent_data?": type("string").describe("Intent data URI or deep link"),
	"intent_extras?": type("Record<string, string>").describe("String key-value extras to supply with intent"),
	"uri?": type("string").describe("ContentProvider URI (must start with content://)"),
	"projection?": type("string").describe("Comma-separated list of column names for provider query"),
	"selection?": type("string").describe("Validated WHERE clause for provider query"),
	"sort_order?": type("string").describe("Validated ORDER BY clause for provider query"),
	"subpath?": type("string").describe("Relative sandbox path to extract (e.g. shared_prefs, databases/app.db)"),
	"max_bytes?": type("number").describe("Maximum bytes captured before truncation (default 524288, max 10485760)"),
	"webview_op?": type
		.enumerated("discover", "forward", "list_forwards", "cleanup")
		.describe("WebView debugging operation"),
	"socket_name?": type("string").describe("Unix domain socket name for forwarding"),
	"forward_port?": type("number").describe("Local port to bind for adb forward"),
	"allowed_origins?": type("string[]").describe(
		"Mandatory allowlist of origins permitted for HTTP replay (e.g. ['https://api.example.com'])",
	),
	"baseline_request?": type({
		"url?": "string",
		"method?": type.enumerated("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"),
		"headers?": type("Record<string, string>"),
		"body_file?": "string",
		"auth_header_env?": "string",
		"header_env_map?": type("Record<string, string>"),
	}).describe("Baseline HTTP request definition"),
	"variant_requests?": type.array(replayVariantRequestSchema).describe("Request variants for comparison (max 10)"),
	"auth_header_env?": type("string").describe("Environment variable name holding auth token for baseline request"),
	"request_file?": type("string").describe("Path to protected request JSON file"),
	"capture_response_artifacts?": type("boolean").describe(
		"Whether to write full captured responses to session artifacts for private forensic review (default false)",
	),
	"mitm_op?": type.enumerated("start", "stop", "status").describe("mitmdump proxy operation"),
	"mitm_port?": type("number").describe("Proxy listening port (default 8080)"),
	"configure_device_proxy?": type("boolean").describe("Explicit authorization to modify global device HTTP proxy"),
	"pinning_mode?": type.enumerated("detect", "hook_report").describe("Pinning analysis mode (detect or hook_report)"),
	"timeout?": type("number").describe("Execution timeout in seconds (default 30, max 120)"),
});

export type AppExperimentParams = typeof appExperimentSchema.infer;
export type AppExperimentAction = AppExperimentParams["action"];

export type AppExperimentStatus =
	| "ok"
	| "missing_dependency"
	| "device_required"
	| "device_not_found"
	| "device_unauthorized"
	| "device_offline"
	| "device_unavailable"
	| "package_not_found"
	| "unauthorized"
	| "invalid_argument"
	| "error";

export interface AppExperimentDetails {
	action: AppExperimentAction;
	status: AppExperimentStatus;
	serial?: string;
	package?: string;
	error?: string;
	observations?: string[];
	acceptance?: "pending_verification" | "verified";
	reproducibleParams?: Record<string, unknown>;
	// preflight:
	installed?: boolean;
	apkPath?: string;
	debuggable?: boolean;
	uid?: string;
	versionCode?: number | string;
	versionName?: string;
	targetSdkVersion?: number | string;
	selinux?: "Enforcing" | "Permissive" | "Disabled" | "Unknown";
	deviceModel?: string;
	abi?: string;
	sdkLevel?: string;
	// invoke_component:
	commandExecuted?: string[];
	exitCode?: number;
	output?: string;
	component?: string;
	// query_provider:
	uri?: string;
	columns?: string[];
	rowCount?: number;
	rowsPreview?: Array<Record<string, string>>;
	// extract_sandbox_data:
	artifactId?: string;
	artifactPath?: string;
	bytes?: number;
	sha256?: string;
	// webview_debug:
	webviewOp?: "discover" | "forward" | "list_forwards" | "cleanup";
	discoveredSockets?: Array<{ pid: number; package: string; socketName: string }>;
	cdpEndpoint?: string;
	forwardPort?: number;
	cleanupHandle?: string;
	ownedForwards?: Array<{ port: number; serial: string; socketName: string; pid?: number }>;
	// network_replay:
	baselineResult?: {
		status: number;
		statusText: string;
		headers: Record<string, string>;
		bodyBytes: number;
		bodySha256: string;
		bodyHashScope?: "complete" | "truncated_prefix";
		bodyTruncated?: boolean;
		artifactId?: string;
		artifactPath?: string;
	};
	variantResults?: Array<{
		id: string;
		name?: string;
		status: number;
		statusText: string;
		headers: Record<string, string>;
		bodyBytes: number;
		bodySha256: string;
		bodyHashScope?: "complete" | "truncated_prefix";
		bodyTruncated?: boolean;
		artifactId?: string;
		artifactPath?: string;
		diffAgainstBaseline?: {
			statusMatch: boolean;
			bodyHashMatch: boolean | null;
			statusDelta?: string;
			lengthDelta?: number;
		};
	}>;
	// mitm_capture:
	mitmOp?: "start" | "stop" | "status";
	mitmPort?: number;
	mitmFlowArtifact?: string;
	proxyConfigured?: boolean;
	proxyRestored?: boolean;
	// pinning_diagnose:
	pinningMode?: "detect" | "hook_report";
	findings?: Record<string, unknown>;
	limitations?: string[];
}

export interface AppExperimentToolOptions {
	which?: SkillRequirementWhich;
	runner?: AdbRunner;
	fetcher?: typeof fetch;
}

const SERIAL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const PACKAGE_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
const COMPONENT_PATTERN = /^[A-Za-z0-9_$./]+$/;
const PROVIDER_URI_PATTERN = /^content:\/\/[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.~%!$&'()*+,;=:@/-]*)?$/;
const SAFE_SQL_IDENT_PATTERN = /^[A-Za-z0-9_]+$/;
const SENSITIVE_KEY_PATTERN = /(authorization|cookie|proxy-authorization|x-api-key|apikey|token|secret|password)/i;
const SAFE_RESPONSE_HEADERS: Record<string, true> = {
	"content-type": true,
	"content-length": true,
	"content-encoding": true,
	"cache-control": true,
	date: true,
	etag: true,
	expires: true,
	"last-modified": true,
	location: true,
	server: true,
	vary: true,
	"x-content-type-options": true,
	"x-frame-options": true,
	pragma: true,
	age: true,
	"access-control-allow-origin": true,
	"strict-transport-security": true,
	allow: true,
};
const ALLOWED_HTTP_METHODS: Record<string, true> = {
	GET: true,
	POST: true,
	PUT: true,
	DELETE: true,
	PATCH: true,
	HEAD: true,
	OPTIONS: true,
};

// 解析 adb forward --list 输出：每行通常为 <serial> <local> <remote>
function parseForwardList(output: string): Array<{ serial: string; local: string; remote: string }> {
	const entries: Array<{ serial: string; local: string; remote: string }> = [];
	for (const line of output.split("\n")) {
		const tokens = line.trim().split(/\s+/);
		if (tokens.length >= 3) {
			entries.push({ serial: tokens[0], local: tokens[1], remote: tokens[2] });
		}
	}
	return entries;
}

// 解析 adb reverse --list 输出：每行最后两个 token 为 local 与 remote（根据 AOSP adb_listeners.cpp，reverse 条目无 serial，首列为 transport 标识如 (reverse)）
function parseReverseList(output: string): Array<{ local: string; remote: string }> {
	const entries: Array<{ local: string; remote: string }> = [];
	for (const line of output.split("\n")) {
		const tokens = line.trim().split(/\s+/);
		if (tokens.length >= 2) {
			const remote = tokens[tokens.length - 1];
			const local = tokens[tokens.length - 2];
			entries.push({ local, remote });
		}
	}
	return entries;
}

interface OwnedForward {
	serial: string;
	port: number;
	socketName: string;
	pid: number;
	package: string;
	createdAt: number;
}

interface SavedProxy {
	serial: string;
	previousValue: string;
	port: number;
	reverseOwned: boolean;
	lastError?: string;
}

interface ActiveMitmProcess {
	id: number;
	pid: number;
	port: number;
	flowPath: string;
	startTime: number;
	timeoutMs: number;
	maxBytes: number;
	observedLimitExceeded?: boolean;
	kill: () => void;
	child?: ChildProcess;
	cleanupWatchdog?: () => void;
}

function quoteShellArg(arg: string): string {
	return "'" + arg.replace(/'/g, "'\\''") + "'";
}

function validatePort(port: unknown, name: string): number {
	if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
		throw new ToolError(`${name} must be a valid TCP port integer between 1 and 65535`);
	}
	return port;
}

// 安全终结进程及其独立进程组（仅针对自身派生且未退出的 ChildProcess，禁止通过原始 PID 盲目发信号，防止 PID 复用误杀）
function killChildProcessGroup(child: ChildProcess | undefined, force = false): void {
	if (!child || child.pid === undefined || child.pid <= 0) return;
	// 校验进程当前是否已退出或已接收信号
	if (child.exitCode !== null || child.signalCode !== null) return;

	const pid = child.pid;
	const sig: NodeJS.Signals = force ? "SIGKILL" : "SIGTERM";
	try {
		process.kill(-pid, sig);
	} catch {
		try {
			process.kill(pid, sig);
		} catch {}
	}

	if (!force) {
		let escalationTimer: NodeJS.Timeout | undefined;
		const onChildExit = () => {
			if (escalationTimer) {
				clearTimeout(escalationTimer);
				escalationTimer = undefined;
			}
		};
		child.once("exit", onChildExit);

		escalationTimer = setTimeout(() => {
			child.off("exit", onChildExit);
			if (child.exitCode === null && child.signalCode === null) {
				try {
					process.kill(-pid, "SIGKILL");
				} catch {
					try {
						process.kill(pid, "SIGKILL");
					} catch {}
				}
			}
		}, 300);
		escalationTimer.unref?.();
	}
}

// 安全终结子进程及其独立进程组，等待底层进程真实退出并释放端口与系统资源
async function terminateChildProcess(child: ChildProcess | undefined, timeoutMs = 2000): Promise<void> {
	if (!child || child.pid === undefined || child.pid <= 0) return;
	if (child.exitCode !== null || child.signalCode !== null) return;

	const pid = child.pid;
	const { promise: exitPromise, resolve: exitResolve } = Promise.withResolvers<void>();

	const onExit = () => exitResolve();
	child.once("exit", onExit);
	child.once("close", onExit);

	try {
		process.kill(-pid, "SIGTERM");
	} catch {
		try {
			process.kill(pid, "SIGTERM");
		} catch {}
	}

	// 宽限期后若尚未退出，发送 SIGKILL 强制终结
	const escalationTimer = setTimeout(() => {
		if (child.exitCode === null && child.signalCode === null) {
			try {
				process.kill(-pid, "SIGKILL");
			} catch {
				try {
					process.kill(pid, "SIGKILL");
				} catch {}
			}
		}
	}, 200);
	escalationTimer.unref?.();

	const timeoutTimer = setTimeout(() => exitResolve(), timeoutMs);
	timeoutTimer.unref?.();

	try {
		await exitPromise;
	} finally {
		clearTimeout(escalationTimer);
		clearTimeout(timeoutTimer);
		child.off("exit", onExit);
		child.off("close", onExit);
	}
}

// 检查指定本地端口是否被外部占用（独占监听测试并立即释放）
function checkPortAvailable(port: number, host = "127.0.0.1"): Promise<boolean> {
	const { promise, resolve } = Promise.withResolvers<boolean>();
	const server = net.createServer();
	server.unref();
	server.once("error", () => resolve(false));
	server.listen({ host, port, exclusive: true }, () => {
		server.close(() => resolve(true));
	});
	return promise;
}

interface SessionExperimentState {
	generation: number;
	ownedForwards: Map<number, OwnedForward>;
	activeMitmProcess: ActiveMitmProcess | null;
	savedDeviceProxy: SavedProxy | null;
	startingMitm: boolean;
	runner?: AdbRunner;
	which?: SkillRequirementWhich;
	cleanupInFlight?: Promise<void>;
	startupInFlight?: Promise<unknown>;
}

const EXPERIMENT_SESSION_STATES = new WeakMap<ToolSession, SessionExperimentState>();

// 统一的会话状态安全异步清理函数：所有 dispose / sessionChange / stop / timeout / exit 路径均走此逻辑
async function cleanupSessionExperimentState(
	state: SessionExperimentState,
	runner?: AdbRunner,
	which?: SkillRequirementWhich,
): Promise<void> {
	// 每次清理开始时递增 generation 并重置 starting 预留标记，废弃并回滚所有处于启动过程中的并发任务
	state.generation++;
	state.startingMitm = false;

	// 若当前有启动流程在执行中，等待其在各自步骤感知到 generation 变化并完成原子回滚
	if (state.startupInFlight) {
		try {
			await state.startupInFlight;
		} catch {}
	}

	// 1. 杀死活跃的 mitmdump 进程并清理看门狗
	if (state.activeMitmProcess) {
		const active = state.activeMitmProcess;
		active.cleanupWatchdog?.();
		await terminateChildProcess(active.child);
		if (state.activeMitmProcess === active) state.activeMitmProcess = null;
	}

	const effectiveRunner = runner ?? state.runner ?? defaultAdbRunner;
	const dep = adbDependency(which ?? state.which);
	if (!dep.available || !dep.path) {
		// dep 不可用时不盲目清空 ownedForwards，保留记录以便后续重试或元数据检视
		return;
	}

	// 2. 清理拥有的 WebView 端口转发：查询 forward --list 且仅在完全匹配时移除
	if (state.ownedForwards.size > 0) {
		try {
			const serials = new Set<string>();
			for (const f of state.ownedForwards.values()) {
				serials.add(f.serial);
			}
			for (const serial of serials) {
				const listRun = await effectiveRunner(dep.path, ["-s", serial, "forward", "--list"], {
					cwd: process.cwd(),
					timeoutMs: 5000,
					maxBytes: 32768,
				}).catch(() => null);
				if (!listRun || listRun.exitCode !== 0 || listRun.timedOut || listRun.truncated) continue;

				const activeList = parseForwardList(new TextDecoder().decode(listRun.stdout));
				for (const [port, forward] of Array.from(state.ownedForwards.entries())) {
					if (forward.serial !== serial) continue;
					const cleanRemote = `localabstract:${forward.socketName.replace(/^@/, "")}`;
					const activeMatch = activeList.find(
						e => (e.serial === serial || !e.serial) && e.local === `tcp:${port}` && e.remote === cleanRemote,
					);
					if (activeMatch) {
						const remRun = await effectiveRunner(dep.path, ["-s", serial, "forward", "--remove", `tcp:${port}`], {
							cwd: process.cwd(),
							timeoutMs: 5000,
							maxBytes: 1024,
						}).catch(() => null);
						if (remRun && remRun.exitCode === 0) {
							state.ownedForwards.delete(port);
						}
					} else {
						// 若已被外部修改为其他映射或已不在设备列表中，不盲目移除外部映射，仅清理自身记录
						state.ownedForwards.delete(port);
					}
				}
			}
		} catch {}
	}

	// 3. 清理保存的设备反向代理与全局代理设置（统一通过 cleanupDeviceProxyState 执行）
	if (state.savedDeviceProxy) {
		await cleanupDeviceProxyState(state, effectiveRunner, which ?? state.which);
	}
}

// 统一的设备代理与反向代理清理函数：同时服务于 session dispose 与 mitm_capture stop，防止逻辑分叉
async function cleanupDeviceProxyState(
	state: SessionExperimentState,
	runner?: AdbRunner,
	which?: SkillRequirementWhich,
): Promise<{ proxyRestored: boolean }> {
	let proxyRestored = false;
	if (!state.savedDeviceProxy) {
		return { proxyRestored: false };
	}

	const saved = state.savedDeviceProxy;
	const effectiveRunner = runner ?? state.runner ?? defaultAdbRunner;
	const dep = adbDependency(which ?? state.which);
	if (!dep.available || !dep.path) {
		return { proxyRestored: false };
	}

	try {
		// 1. 独立执行反向代理移除（无论 global http_proxy 是否被外部修改均需解除）；但在查询失败或超时截断时遵循 fail-closed，不盲目移除
		if (saved.reverseOwned) {
			const revListRun = await effectiveRunner(dep.path, ["-s", saved.serial, "reverse", "--list"], {
				cwd: process.cwd(),
				timeoutMs: 10_000,
				maxBytes: 32768,
			}).catch(() => null);

			if (!revListRun || revListRun.exitCode !== 0 || revListRun.timedOut || revListRun.truncated) {
				saved.lastError = revListRun
					? `reverse --list failed (exit ${revListRun.exitCode})`
					: "reverse --list timed out or unavailable";
			} else {
				const revEntries = parseReverseList(new TextDecoder().decode(revListRun.stdout));
				// adb -s 已经限定目标设备；首字段为 transport 标识符（如 (reverse)），精准比对 local 与 remote
				const match = revEntries.find(e => e.local === `tcp:${saved.port}` && e.remote === `tcp:${saved.port}`);
				if (match) {
					const revRemoveRun = await effectiveRunner(
						dep.path,
						["-s", saved.serial, "reverse", "--remove", `tcp:${saved.port}`],
						{ cwd: process.cwd(), timeoutMs: 10_000, maxBytes: 1024 },
					).catch(() => null);
					if (revRemoveRun && revRemoveRun.exitCode === 0) {
						saved.reverseOwned = false;
					} else {
						saved.lastError = revRemoveRun ? revRemoveRun.stderr : "reverse remove failed";
					}
				} else {
					// 列表中已不存在该端口映射，视为已清理
					saved.reverseOwned = false;
				}
			}
		}

		// 2. 检查当前 global http_proxy 设置：仅当与预期自身值完全相同时才恢复，避免冲掉用户在会话期间修改的配置
		const curRun = await effectiveRunner(
			dep.path,
			["-s", saved.serial, "shell", "settings", "get", "global", "http_proxy"],
			{ cwd: process.cwd(), timeoutMs: 10_000, maxBytes: 1024 },
		).catch(() => null);

		let proxyCleaned = false;
		if (curRun && curRun.exitCode === 0) {
			const currentVal = new TextDecoder().decode(curRun.stdout).trim();
			const expectedVal = `127.0.0.1:${saved.port}`;
			if (currentVal === expectedVal) {
				const restoreVal = saved.previousValue;
				let restoreRun: AdbRunResult | null = null;
				if (restoreVal && restoreVal !== "null" && restoreVal !== ":0") {
					restoreRun = await effectiveRunner(
						dep.path,
						["-s", saved.serial, "shell", "settings", "put", "global", "http_proxy", quoteShellArg(restoreVal)],
						{ cwd: process.cwd(), timeoutMs: 10_000, maxBytes: 1024 },
					).catch(() => null);
				} else {
					restoreRun = await effectiveRunner(
						dep.path,
						["-s", saved.serial, "shell", "settings", "delete", "global", "http_proxy"],
						{ cwd: process.cwd(), timeoutMs: 10_000, maxBytes: 1024 },
					).catch(() => null);
				}
				if (restoreRun && restoreRun.exitCode === 0) {
					proxyRestored = true;
					proxyCleaned = true;
				} else {
					saved.lastError = restoreRun ? restoreRun.stderr : "proxy restore failed";
				}
			} else {
				// 代理已被外部修改，保留外部设置，不执行覆盖
				proxyRestored = false;
				proxyCleaned = true;
			}
		}

		// 若反向代理已解除且代理无需进一步恢复，释放 savedDeviceProxy；否则保留元数据便于后续重试
		if (!saved.reverseOwned && proxyCleaned) {
			state.savedDeviceProxy = null;
		}
	} catch (err) {
		saved.lastError = err instanceof Error ? err.message : String(err);
	}

	return { proxyRestored };
}

// 专门针对局部快照执行防漏回滚（即使并发清理已置空全局引用，局部快照依然保证精准回滚）
async function rollbackSavedProxy(
	saved: SavedProxy,
	effectiveRunner: AdbRunner,
	which?: SkillRequirementWhich,
): Promise<void> {
	const dep = adbDependency(which);
	if (!dep.available || !dep.path) return;
	try {
		if (saved.reverseOwned) {
			await effectiveRunner(dep.path, ["-s", saved.serial, "reverse", "--remove", `tcp:${saved.port}`], {
				cwd: process.cwd(),
				timeoutMs: 5000,
				maxBytes: 1024,
			}).catch(() => null);
			saved.reverseOwned = false;
		}

		const curRun = await effectiveRunner(
			dep.path,
			["-s", saved.serial, "shell", "settings", "get", "global", "http_proxy"],
			{ cwd: process.cwd(), timeoutMs: 5000, maxBytes: 1024 },
		).catch(() => null);

		if (curRun && curRun.exitCode === 0) {
			const currentVal = new TextDecoder().decode(curRun.stdout).trim();
			if (currentVal === `127.0.0.1:${saved.port}`) {
				if (saved.previousValue && saved.previousValue !== "null" && saved.previousValue !== ":0") {
					await effectiveRunner(
						dep.path,
						[
							"-s",
							saved.serial,
							"shell",
							"settings",
							"put",
							"global",
							"http_proxy",
							quoteShellArg(saved.previousValue),
						],
						{ cwd: process.cwd(), timeoutMs: 5000, maxBytes: 1024 },
					).catch(() => null);
				} else {
					await effectiveRunner(
						dep.path,
						["-s", saved.serial, "shell", "settings", "delete", "global", "http_proxy"],
						{ cwd: process.cwd(), timeoutMs: 5000, maxBytes: 1024 },
					).catch(() => null);
				}
			}
		}
	} catch {}
}

// 调度异步会话清理，防止并发冲突
function triggerSessionCleanup(
	state: SessionExperimentState,
	runner?: AdbRunner,
	which?: SkillRequirementWhich,
): Promise<void> {
	if (state.cleanupInFlight) {
		return state.cleanupInFlight;
	}
	const p = (async () => {
		try {
			await cleanupSessionExperimentState(state, runner, which);
		} finally {
			state.cleanupInFlight = undefined;
		}
	})();
	state.cleanupInFlight = p;
	return p;
}

function getSessionExperimentState(
	session: ToolSession,
	runner?: AdbRunner,
	which?: SkillRequirementWhich,
): SessionExperimentState {
	let state = EXPERIMENT_SESSION_STATES.get(session);
	if (!state) {
		state = {
			generation: 0,
			ownedForwards: new Map<number, OwnedForward>(),
			activeMitmProcess: null,
			savedDeviceProxy: null,
			startingMitm: false,
			runner: runner ?? defaultAdbRunner,
			which,
		};
		EXPERIMENT_SESSION_STATES.set(session, state);

		// 注册 dispose 与 sessionChange 回调，共享同一个安全异步清理函数
		const cleanup = () => {
			const p = triggerSessionCleanup(state!);
			trackLateCleanup(p, { resource: "app-experiment-session-cleanup" });
		};
		session.registerDisposeCallback?.(cleanup);
		session.registerSessionChangeCallback?.(cleanup);
	} else {
		if (runner) state.runner = runner;
		if (which) state.which = which;
	}
	return state;
}

async function probeTcpPort(port: number, timeoutMs = 3000): Promise<boolean> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		const { promise, resolve } = Promise.withResolvers<boolean>();
		const socket = new net.Socket();
		socket.setTimeout(300);
		socket.once("connect", () => {
			socket.destroy();
			resolve(true);
		});
		socket.once("error", () => {
			socket.destroy();
			resolve(false);
		});
		socket.once("timeout", () => {
			socket.destroy();
			resolve(false);
		});
		socket.connect(port, "127.0.0.1");
		const connected = await promise;
		if (connected) return true;

		const { promise: sleepPromise, resolve: sleepResolve } = Promise.withResolvers<void>();
		setTimeout(sleepResolve, 100);
		await sleepPromise;
	}
	return false;
}
export class AppExperimentTool implements AgentTool<typeof appExperimentSchema, AppExperimentDetails> {
	readonly name = "app_experiment";
	readonly label = "App Experiment";
	readonly summary =
		"Application security experiment and verification laboratory: benign component invocation, read-only provider queries, debug-authorized run-as extraction, WebView forwarding, origin-allowlisted network replay, and TLS pinning diagnosis.";
	readonly description: string;
	readonly parameters = appExperimentSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";

	/**
	 * ApprovalGates alignment:
	 * - preflight: read tier (host/static inventory and fixed readonly device preflight)
	 * - extract_sandbox_data: write tier (writes persistent session artifact)
	 * - mitm_capture: exec tier (starts proxy listener and configures device settings)
	 * - invoke_component / query_provider / webview_debug / network_replay: exec tier
	 * - pinning_diagnose: read tier for detect, exec tier for hook_report
	 * - unknown: exec tier (fail closed)
	 */
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args) {
			const action = args.action;
			if (action === "preflight") return "read";
			if (action === "extract_sandbox_data") return "write";
			if (action === "mitm_capture") return "exec";
			if (action === "invoke_component") return "exec";
			if (action === "query_provider") return "exec";
			if (action === "webview_debug") return "exec";
			if (action === "network_replay") return "exec";
			if (action === "pinning_diagnose") {
				if ("pinning_mode" in args && args.pinning_mode === "detect") return "read";
				return "exec";
			}
		}
		return "exec";
	};

	private get state(): SessionExperimentState {
		return getSessionExperimentState(this.session, this.options.runner, this.options.which);
	}
	private get ownedForwards(): Map<number, OwnedForward> {
		return this.state.ownedForwards;
	}
	private get activeMitmProcess() {
		return this.state.activeMitmProcess;
	}
	private set activeMitmProcess(val) {
		this.state.activeMitmProcess = val;
	}
	private get savedDeviceProxy() {
		return this.state.savedDeviceProxy;
	}
	private set savedDeviceProxy(val) {
		this.state.savedDeviceProxy = val;
	}
	constructor(
		private readonly session: ToolSession,
		private readonly options: AppExperimentToolOptions = {},
	) {
		this.description = prompt.render(appExperimentDescription);
		// 确保 session 状态初始化并关联 runner 与 which
		getSessionExperimentState(this.session, this.options.runner, this.options.which);
	}

	async execute(
		_toolCallId: string,
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		throwIfAborted(signal);
		const action = params.action;

		switch (action) {
			case "preflight":
				return this.handlePreflight(params, signal);
			case "invoke_component":
				return this.handleInvokeComponent(params, signal);
			case "query_provider":
				return this.handleQueryProvider(params, signal);
			case "extract_sandbox_data":
				return this.handleExtractSandboxData(params, signal);
			case "webview_debug":
				return this.handleWebviewDebug(params, signal);
			case "network_replay":
				return this.handleNetworkReplay(params, signal);
			case "mitm_capture":
				return this.handleMitmCapture(params, signal);
			case "pinning_diagnose":
				return this.handlePinningDiagnose(params, signal);
			default:
				throw new ToolError(`Unrecognized action: ${String(action)}`);
		}
	}

	// --------------------------------------------------------------------------
	// Action: preflight
	// --------------------------------------------------------------------------

	private async handlePreflight(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const serial = this.requireSerial(params.serial);
		const packageName = this.requirePackage(params.package);
		const runner = this.options.runner ?? defaultAdbRunner;

		const dep = adbDependency(this.options.which);
		if (!dep.available || !dep.path) {
			return {
				content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
				details: {
					action: "preflight",
					status: "missing_dependency",
					serial,
					package: packageName,
					error: "adb not found on PATH",
				},
			};
		}

		const deviceCheck = await this.verifyDevice(serial, runner, signal);
		if (deviceCheck.status !== "ok") {
			return {
				content: [{ type: "text", text: deviceCheck.message }],
				details: {
					action: "preflight",
					status: deviceCheck.status,
					serial,
					package: packageName,
					error: deviceCheck.message,
				},
			};
		}

		// Check if package is installed: pm path <pkg>
		const pmPathRun = await runner(dep.path, ["-s", serial, "shell", "pm", "path", packageName], {
			cwd: this.session.cwd,
			timeoutMs: 15_000,
			maxBytes: 65536,
			signal,
		});
		const pmPathOut = new TextDecoder().decode(pmPathRun.stdout).trim();
		if (pmPathRun.exitCode !== 0 || !pmPathOut.startsWith("package:")) {
			return {
				content: [
					{
						type: "text",
						text: `[Package Not Installed] Package '${packageName}' is not installed on device '${serial}'.`,
					},
				],
				details: {
					action: "preflight",
					status: "package_not_found",
					serial,
					package: packageName,
					installed: false,
					error: `Package '${packageName}' not found on device`,
				},
			};
		}
		const apkPath = pmPathOut
			.split("\n")[0]
			.replace(/^package:/, "")
			.trim();

		// Query dumpsys package <pkg>
		const dumpRun = await runner(
			dep.path,
			["-s", serial, "shell", "dumpsys", "package", quoteShellArg(packageName)],
			{ cwd: this.session.cwd, timeoutMs: 20_000, maxBytes: 262144, signal },
		);

		let debuggable: boolean | undefined;
		let uid: string | undefined;
		let versionCode: string | undefined;
		let versionName: string | undefined;
		let targetSdkVersion: string | undefined;

		if (dumpRun.exitCode === 0 && !dumpRun.timedOut && !dumpRun.truncated) {
			const dumpText = new TextDecoder().decode(dumpRun.stdout);
			const flagsMatch = dumpText.match(/pkgFlags=\[\s*([^\]]+)\]/i) ?? dumpText.match(/flags=\[\s*([^\]]+)\]/i);
			if (flagsMatch) {
				debuggable = flagsMatch[1].includes("DEBUGGABLE");
			}
			const uidMatch = dumpText.match(/userId=(\d+)/i) ?? dumpText.match(/appId=(\d+)/i);
			if (uidMatch) uid = uidMatch[1];
			const vcMatch = dumpText.match(/versionCode=(\d+)/i);
			if (vcMatch) versionCode = vcMatch[1];
			const vnMatch = dumpText.match(/versionName=([^\s]+)/i);
			if (vnMatch) versionName = vnMatch[1];
			const targetSdkMatch = dumpText.match(/targetSdk=(\d+)/i);
			if (targetSdkMatch) targetSdkVersion = targetSdkMatch[1];
		}
		const propsRun = await runner(dep.path, ["-s", serial, "shell", "getprop"], {
			cwd: this.session.cwd,
			timeoutMs: 15_000,
			maxBytes: 131072,
			signal,
		});
		const propsText = new TextDecoder().decode(propsRun.stdout);
		const sdkMatch = propsText.match(/\[ro\.build\.version\.sdk\]:\s*\[(\d+)\]/);
		const modelMatch = propsText.match(/\[ro\.product\.model\]:\s*\[([^\]]+)\]/);
		const abiMatch = propsText.match(/\[ro\.product\.cpu\.abi\]:\s*\[([^\]]+)\]/);

		const sdkLevel = sdkMatch ? sdkMatch[1] : undefined;
		const deviceModel = modelMatch ? modelMatch[1] : undefined;
		const abi = abiMatch ? abiMatch[1] : undefined;

		const selinuxRun = await runner(dep.path, ["-s", serial, "shell", "getenforce"], {
			cwd: this.session.cwd,
			timeoutMs: 10_000,
			maxBytes: 1024,
			signal,
		});
		const selinuxText = new TextDecoder().decode(selinuxRun.stdout).trim();
		const selinux =
			selinuxText === "Enforcing" || selinuxText === "Permissive" || selinuxText === "Disabled"
				? selinuxText
				: "Unknown";

		const observations: string[] = [
			`Package '${packageName}' is installed at ${apkPath}`,
			`Debuggable build flag: ${debuggable}`,
			`SELinux enforcement mode: ${selinux}`,
			`Target SDK: ${targetSdkVersion ?? "unknown"}, Device SDK: ${sdkLevel ?? "unknown"}`,
		];

		const lines = [
			`// Application Experiment Preflight`,
			`Device: ${serial} (${deviceModel ?? "unknown model"}, ABI: ${abi ?? "unknown"})`,
			`Package: ${packageName}`,
			`Installed APK: ${apkPath}`,
			`UID: ${uid ?? "unknown"}, Version: ${versionName ?? "none"} (code: ${versionCode ?? "none"})`,
			`Debuggable: ${debuggable}`,
			`SELinux: ${selinux}`,
			`Observations:`,
			...observations.map(o => `  • ${o}`),
			`Status: Laboratory target verified. Pending experiment verification via Evidence.`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "preflight",
				status: "ok",
				serial,
				package: packageName,
				installed: true,
				apkPath,
				debuggable,
				uid,
				versionCode,
				versionName,
				targetSdkVersion,
				selinux,
				deviceModel,
				abi,
				sdkLevel,
				observations,
				acceptance: "pending_verification",
				reproducibleParams: { action: "preflight", serial, package: packageName },
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: invoke_component
	// --------------------------------------------------------------------------

	private async handleInvokeComponent(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const serial = this.requireSerial(params.serial);
		const packageName = this.requirePackage(params.package);
		const runner = this.options.runner ?? defaultAdbRunner;
		const dep = adbDependency(this.options.which);

		if (!dep.available || !dep.path) {
			return {
				content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
				details: {
					action: "invoke_component",
					status: "missing_dependency",
					serial,
					package: packageName,
					error: "adb not found on PATH",
				},
			};
		}

		const deviceCheck = await this.verifyDevice(serial, runner, signal);
		if (deviceCheck.status !== "ok") {
			return {
				content: [{ type: "text", text: deviceCheck.message }],
				details: {
					action: "invoke_component",
					status: deviceCheck.status,
					serial,
					package: packageName,
					error: deviceCheck.message,
				},
			};
		}

		const compType = params.component_type ?? "activity";
		const component = params.component ? this.validateComponent(params.component, packageName) : undefined;
		const intentData = params.intent_data ? this.validateIntentData(params.intent_data) : undefined;

		const subcmd = compType === "service" ? "startservice" : compType === "broadcast" ? "broadcast" : "start";
		const amArgs = ["am", subcmd];

		if (component) {
			const fullComp = component.includes("/") ? component : `${packageName}/${component}`;
			amArgs.push("-n", fullComp);
		} else {
			amArgs.push("-p", packageName);
		}
		if (params.intent_action) {
			amArgs.push("-a", params.intent_action.trim());
		}
		if (params.intent_category) {
			amArgs.push("-c", params.intent_category.trim());
		}
		if (intentData) {
			amArgs.push("-d", intentData);
		}
		if (params.intent_extras) {
			for (const [k, v] of Object.entries(params.intent_extras)) {
				if (!/^[A-Za-z0-9_.-]+$/.test(k)) {
					throw new ToolError(
						`Invalid intent extra key '${k}': must contain only alphanumeric characters, dots, underscores, and hyphens`,
					);
				}
				if (v.includes("\0")) {
					throw new ToolError(`Intent extra value for '${k}' must not contain null bytes`);
				}
				amArgs.push("--es", k, v);
			}
		}

		const cmd = ["-s", serial, "shell", ...amArgs.map(quoteShellArg)];

		const timeoutSeconds = Math.min(120, Math.max(5, params.timeout ?? 30));
		const runResult = await runner(dep.path, cmd, {
			cwd: this.session.cwd,
			timeoutMs: timeoutSeconds * 1000,
			maxBytes: 131072,
			signal,
		});

		const stdout = new TextDecoder().decode(runResult.stdout).trim();
		const stderr = runResult.stderr.trim();
		const output = stdout + (stderr ? `\nSTDERR: ${stderr}` : "");

		const hasError =
			runResult.exitCode !== 0 ||
			output.includes("Error:") ||
			output.includes("SecurityException") ||
			output.includes("ActivityNotFoundException");

		const observations: string[] = [];
		if (output.includes("SecurityException")) {
			observations.push(
				"SecurityException: Component invocation denied due to missing permission or exported=false boundary",
			);
		} else if (output.includes("ActivityNotFoundException")) {
			observations.push("ActivityNotFoundException: Target component or intent filter not found in package");
		} else if (output.includes("Warning: Activity not started")) {
			observations.push("Activity not started: Component launch warning returned by ActivityManager");
		} else if (output.includes("Error:")) {
			observations.push(`Invocation error: ${output.split("\n")[0]}`);
		} else if (runResult.exitCode === 0) {
			observations.push(`Component invocation dispatched successfully via 'am ${subcmd}'`);
		} else {
			observations.push(`Invocation completed with exit code ${runResult.exitCode}`);
		}

		const lines = [
			`// Component Invocation Result`,
			`Target: ${serial} (${packageName})`,
			`Action: ${subcmd} on ${component ?? "(intent filter match)"}`,
			`Command: adb ${cmd.join(" ")}`,
			`Exit Code: ${runResult.exitCode}`,
			`Output:`,
			output || "(no stdout/stderr returned)",
			`Observations:`,
			...observations.map(o => `  • ${o}`),
			`Notice: Invocation outcome represents operational response; concrete authorization vulnerability requires verified privilege impact.`,
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "invoke_component",
				status: hasError ? "error" : "ok",
				serial,
				package: packageName,
				component,
				commandExecuted: cmd,
				exitCode: runResult.exitCode,
				output,
				observations,
				acceptance: "pending_verification",
				reproducibleParams: {
					action: "invoke_component",
					serial,
					package: packageName,
					component,
					component_type: compType,
					intent_action: params.intent_action,
					intent_data: intentData,
				},
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: query_provider
	// --------------------------------------------------------------------------

	private async handleQueryProvider(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const serial = this.requireSerial(params.serial);
		const packageName = this.requirePackage(params.package);
		if (!params.uri) {
			throw new ToolError("query_provider requires 'uri' starting with 'content://'");
		}
		const uri = params.uri.trim();
		if (!PROVIDER_URI_PATTERN.test(uri)) {
			throw new ToolError(
				`Invalid ContentProvider URI '${uri}': must start with content:// and contain a valid authority/path`,
			);
		}

		const authority = uri.slice(10).split("/")[0].split("?")[0];
		const runner = this.options.runner ?? defaultAdbRunner;
		const dep = adbDependency(this.options.which);

		if (!dep.available || !dep.path) {
			return {
				content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
				details: {
					action: "query_provider",
					status: "missing_dependency",
					serial,
					package: packageName,
					uri,
					error: "adb not found on PATH",
				},
			};
		}

		const deviceCheck = await this.verifyDevice(serial, runner, signal);
		if (deviceCheck.status !== "ok") {
			return {
				content: [{ type: "text", text: deviceCheck.message }],
				details: {
					action: "query_provider",
					status: deviceCheck.status,
					serial,
					package: packageName,
					uri,
					error: deviceCheck.message,
				},
			};
		}
		let authorityAllowed = false;
		if (params.allowed_authorities && params.allowed_authorities.includes(authority)) {
			authorityAllowed = true;
		} else {
			// Real AOSP command: dumpsys package <pkg> -> verify in ContentProvider Authorities or Registered ContentProviders section
			const dumpRun = await runner(
				dep.path,
				["-s", serial, "shell", "dumpsys", "package", quoteShellArg(packageName)],
				{ cwd: this.session.cwd, timeoutMs: 20_000, maxBytes: 262144, signal },
			);
			if (dumpRun.exitCode === 0 && !dumpRun.timedOut) {
				const dumpText = new TextDecoder().decode(dumpRun.stdout);
				const escapedAuth = authority.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
				const escapedPkg = packageName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
				const authRegex = new RegExp(`\\[${escapedAuth}\\]:\\s*\\r?\\n\\s*Provider\\{[^}]*\\s+${escapedPkg}/`, "i");
				const fallbackAuthRegex = new RegExp(`(?:authority\\s*[:=]\\s*|\\[)${escapedAuth}(?:\\s|\\]|:)`, "i");
				if (authRegex.test(dumpText) || (fallbackAuthRegex.test(dumpText) && dumpText.includes(packageName))) {
					authorityAllowed = true;
				}
			}
		}

		if (!authorityAllowed) {
			throw new ToolError(
				`Authority '${authority}' does not resolve to target package '${packageName}'. Querying arbitrary ContentProviders outside the authorized package boundary is prohibited.`,
			);
		}

		let colonProjection: string | undefined;
		if (params.projection) {
			const cols: string[] = [];
			for (const col of params.projection.split(",")) {
				const trimmed = col.trim();
				if (!SAFE_SQL_IDENT_PATTERN.test(trimmed)) {
					throw new ToolError(`Invalid column in projection '${col}': must be an alphanumeric identifier`);
				}
				cols.push(trimmed);
			}
			colonProjection = cols.join(":");
		}
		if (params.selection && /[;&|$`><\n\r\t]/.test(params.selection)) {
			throw new ToolError("selection clause contains prohibited shell metacharacters");
		}
		if (params.sort_order && /[;&|$`><\n\r\t]/.test(params.sort_order)) {
			throw new ToolError("sort_order clause contains prohibited shell metacharacters");
		}

		const qArgs = ["content", "query", "--uri", uri];
		if (colonProjection) qArgs.push("--projection", colonProjection);
		if (params.selection) qArgs.push("--where", params.selection.trim());
		if (params.sort_order) qArgs.push("--sort", params.sort_order.trim());

		const cmd = ["-s", serial, "shell", ...qArgs.map(quoteShellArg)];

		const runResult = await runner(dep.path, cmd, {
			cwd: this.session.cwd,
			timeoutMs: 25_000,
			maxBytes: 262144,
			signal,
		});

		const stdout = new TextDecoder().decode(runResult.stdout).trim();
		const stderr = runResult.stderr.trim();
		const observations: string[] = [];

		if (runResult.exitCode !== 0 || runResult.timedOut) {
			const err =
				stderr ||
				stdout ||
				`Command exited with code ${runResult.exitCode}${runResult.timedOut ? " (timed out)" : ""}`;
			return {
				content: [{ type: "text", text: `[Provider Query Failed] ${err}` }],
				details: {
					action: "query_provider",
					status: "error",
					serial,
					package: packageName,
					uri,
					error: err,
				},
			};
		}

		if (
			stdout.includes("SecurityException") ||
			stderr.includes("SecurityException") ||
			stdout.includes("Permission Denial")
		) {
			observations.push("Permission denial: Provider query threw SecurityException");
			return {
				content: [
					{
						type: "text",
						text: `[Permission Denied] ContentProvider query on '${uri}' was denied: ${stderr || stdout}`,
					},
				],
				details: {
					action: "query_provider",
					status: "unauthorized",
					serial,
					package: packageName,
					uri,
					error: stderr || stdout,
					observations,
				},
			};
		}

		if (
			stdout.includes("Error while accessing provider:") ||
			stdout.includes("SQLiteException") ||
			stdout.includes("IllegalArgumentException") ||
			stderr.length > 0
		) {
			const err = stderr || stdout;
			return {
				content: [{ type: "text", text: `[Provider Error] ${err}` }],
				details: {
					action: "query_provider",
					status: "error",
					serial,
					package: packageName,
					uri,
					error: err,
				},
			};
		}

		const rows: Array<Record<string, string>> = [];
		const columns = new Set<string>();
		for (const line of stdout.split("\n")) {
			const rowMatch = line.match(/^Row:\s*\d+\s+(.*)$/);
			if (rowMatch) {
				const rowObj: Record<string, string> = {};
				const pairs = rowMatch[1].split(/,\s*(?=[A-Za-z0-9_]+=)/);
				for (const pair of pairs) {
					const eqIdx = pair.indexOf("=");
					if (eqIdx !== -1) {
						const k = pair.slice(0, eqIdx).trim();
						let v = pair.slice(eqIdx + 1).trim();
						if (SENSITIVE_KEY_PATTERN.test(k)) {
							v = "[REDACTED]";
						}
						columns.add(k);
						rowObj[k] = v;
					}
				}
				if (Object.keys(rowObj).length > 0) rows.push(rowObj);
			}
		}

		observations.push(`Query returned ${rows.length} rows across ${columns.size} columns`);

		const lines = [
			`// ContentProvider Query Result`,
			`Target: ${serial} (${packageName})`,
			`URI: ${uri}`,
			`Rows: ${rows.length}, Columns: [${Array.from(columns).join(", ")}]`,
			`Preview (first 10 rows):`,
			...rows.slice(0, 10).map((r, i) => `  Row ${i}: ${JSON.stringify(r)}`),
			rows.length > 10 ? `  ... (${rows.length - 10} more rows omitted)` : "",
			`Observations:`,
			...observations.map(o => `  • ${o}`),
		].filter(Boolean);

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "query_provider",
				status: "ok",
				serial,
				package: packageName,
				uri,
				columns: Array.from(columns),
				rowCount: rows.length,
				rowsPreview: rows.slice(0, 20),
				observations,
				acceptance: "pending_verification",
				reproducibleParams: {
					action: "query_provider",
					serial,
					package: packageName,
					uri,
					projection: params.projection,
					selection: params.selection,
				},
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: extract_sandbox_data
	// --------------------------------------------------------------------------

	private async handleExtractSandboxData(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const serial = this.requireSerial(params.serial);
		const packageName = this.requirePackage(params.package);

		const subpath = params.subpath?.trim() ?? "shared_prefs";
		if (
			subpath.startsWith("/") ||
			subpath.startsWith("\\") ||
			subpath.startsWith("-") ||
			subpath.includes("..") ||
			!/^[A-Za-z0-9_./-]+$/.test(subpath)
		) {
			throw new ToolError(
				`Invalid subpath '${subpath}': path traversal, absolute paths, leading hyphens, and shell characters are prohibited`,
			);
		}

		const runner = this.options.runner ?? defaultAdbRunner;
		const dep = adbDependency(this.options.which);

		if (!dep.available || !dep.path) {
			return {
				content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
				details: {
					action: "extract_sandbox_data",
					status: "missing_dependency",
					serial,
					package: packageName,
					error: "adb not found on PATH",
				},
			};
		}

		const deviceCheck = await this.verifyDevice(serial, runner, signal);
		if (deviceCheck.status !== "ok") {
			return {
				content: [{ type: "text", text: deviceCheck.message }],
				details: {
					action: "extract_sandbox_data",
					status: deviceCheck.status,
					serial,
					package: packageName,
					error: deviceCheck.message,
				},
			};
		}

		// Verify debuggable authorization: run-as id
		const runAsCheck = await runner(dep.path, ["-s", serial, "shell", "run-as", quoteShellArg(packageName), "id"], {
			cwd: this.session.cwd,
			timeoutMs: 15_000,
			maxBytes: 1024,
			signal,
		});
		const checkOut = new TextDecoder().decode(runAsCheck.stdout);
		if (runAsCheck.exitCode !== 0 || checkOut.includes("not debuggable") || checkOut.includes("exec failed")) {
			return {
				content: [
					{
						type: "text",
						text: `[Extraction Refused] Package '${packageName}' is not debuggable. run-as sandbox extraction strictly requires android:debuggable="true" in package manifest. Automatic su/root escalation is prohibited by policy.`,
					},
				],
				details: {
					action: "extract_sandbox_data",
					status: "unauthorized",
					serial,
					package: packageName,
					error: "Package not debuggable; run-as unauthorized",
				},
			};
		}

		const maxBytes = Math.min(10 * 1024 * 1024, Math.max(1024, params.max_bytes ?? 524288));

		const tarRun = await runner(
			dep.path,
			// shell-v2 保留远端退出码并分离 stderr，exec-out 无法证明 tar 完整成功。
			[
				"-s",
				serial,
				"shell",
				"-T",
				"run-as",
				quoteShellArg(packageName),
				"tar",
				"-cf",
				"-",
				"--",
				quoteShellArg(subpath),
			],
			{ cwd: this.session.cwd, timeoutMs: 30_000, maxBytes, signal },
		);

		if (
			tarRun.exitCode !== 0 ||
			tarRun.timedOut ||
			tarRun.truncated ||
			tarRun.killedOnOverflow ||
			tarRun.stdout.byteLength === 0
		) {
			const err =
				tarRun.stderr.trim() ||
				`tar failed with exit code ${tarRun.exitCode}${tarRun.timedOut ? " (timed out)" : ""}${tarRun.truncated ? " (truncated, incomplete archive)" : ""}`;
			return {
				content: [{ type: "text", text: `[Extraction Failed] Incomplete or failed tar extraction: ${err}` }],
				details: {
					action: "extract_sandbox_data",
					status: "error",
					serial,
					package: packageName,
					error: err,
				},
			};
		}

		const allocation = await this.session.allocateOutputArtifact?.("app_experiment");
		let artifactPath: string;
		let artifactId: string;

		if (allocation?.path && allocation.id) {
			artifactPath = allocation.path;
			artifactId = allocation.id;
		} else {
			const artDir = path.join(this.session.cwd, "artifacts", "sandbox");
			await fs.mkdir(artDir, { recursive: true, mode: 0o700 });
			const runDir = await fs.mkdtemp(path.join(artDir, "extract-"));
			artifactPath = path.join(runDir, `${packageName}.tar`);
			artifactId = path.basename(runDir);
		}

		await fs.writeFile(artifactPath, tarRun.stdout, { mode: 0o600, flag: "wx" });
		const hash = createHash("sha256").update(tarRun.stdout).digest("hex");

		const observations: string[] = [
			`Extracted ${tarRun.stdout.byteLength} bytes from sandbox path '${subpath}' via run-as`,
			`Saved persistent artifact at ${artifactPath} (SHA-256: ${hash})`,
		];

		const lines = [
			`// Sandbox Extraction Complete`,
			`Target: ${serial} (${packageName})`,
			`Subpath: ${subpath}`,
			`Artifact ID: ${artifactId}`,
			`Artifact Path: ${artifactPath}`,
			`Bytes: ${tarRun.stdout.byteLength} (SHA-256: ${hash})`,
			`Observations:`,
			...observations.map(o => `  • ${o}`),
		];

		return {
			content: [{ type: "text", text: lines.join("\n") }],
			details: {
				action: "extract_sandbox_data",
				status: "ok",
				serial,
				package: packageName,
				artifactId,
				artifactPath,
				bytes: tarRun.stdout.byteLength,
				sha256: hash,
				observations,
				acceptance: "pending_verification",
				reproducibleParams: { action: "extract_sandbox_data", serial, package: packageName, subpath },
			},
		};
	}

	// --------------------------------------------------------------------------
	// Action: webview_debug
	// --------------------------------------------------------------------------

	private async handleWebviewDebug(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const serial = this.requireSerial(params.serial);
		const packageName = this.requirePackage(params.package);
		const webviewOp = params.webview_op ?? "discover";
		const runner = this.options.runner ?? defaultAdbRunner;
		const dep = adbDependency(this.options.which);

		if (!dep.available || !dep.path) {
			return {
				content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
				details: {
					action: "webview_debug",
					status: "missing_dependency",
					serial,
					package: packageName,
					webviewOp,
					error: "adb not found on PATH",
				},
			};
		}

		const deviceCheck = await this.verifyDevice(serial, runner, signal);
		if (deviceCheck.status !== "ok") {
			return {
				content: [{ type: "text", text: deviceCheck.message }],
				details: {
					action: "webview_debug",
					status: deviceCheck.status,
					serial,
					package: packageName,
					webviewOp,
					error: deviceCheck.message,
				},
			};
		}

		if (webviewOp === "list_forwards") {
			const forwards = Array.from(this.ownedForwards.values()).filter(
				f => f.serial === serial && f.package === packageName,
			);
			return {
				content: [
					{
						type: "text",
						text: `Owned WebView forwards on ${serial} for ${packageName} (${forwards.length}):\n${forwards.map(f => `  • tcp:${f.port} -> ${f.socketName} (PID: ${f.pid})`).join("\n") || "  (none)"}`,
					},
				],
				details: {
					action: "webview_debug",
					status: "ok",
					serial,
					package: packageName,
					webviewOp,
					ownedForwards: forwards,
				},
			};
		}
		if (webviewOp === "cleanup") {
			const port = params.forward_port;
			const removed: number[] = [];

			const listRun = await runner(dep.path, ["-s", serial, "forward", "--list"], {
				cwd: this.session.cwd,
				timeoutMs: 10_000,
				maxBytes: 32768,
				signal,
			});
			if (listRun.exitCode !== 0) {
				return {
					content: [
						{
							type: "text",
							text: `[ADB Forward List Failed] Failed to query forwards on ${serial}: ${listRun.stderr || "exit " + listRun.exitCode}`,
						},
					],
					details: {
						action: "webview_debug",
						status: "error",
						serial,
						package: packageName,
						webviewOp,
						error: listRun.stderr || `adb forward --list failed (exit ${listRun.exitCode})`,
					},
				};
			}
			const listText = new TextDecoder().decode(listRun.stdout);
			const activeList = parseForwardList(listText);
			if (port) {
				const match = this.ownedForwards.get(port);
				if (match && match.serial === serial && match.package === packageName) {
					const cleanRemote = `localabstract:${match.socketName.replace(/^@/, "")}`;
					const activeMatch = activeList.find(
						e => (e.serial === serial || !e.serial) && e.local === `tcp:${port}` && e.remote === cleanRemote,
					);
					if (activeMatch) {
						const removeRun = await runner(dep.path, ["-s", serial, "forward", "--remove", `tcp:${port}`], {
							cwd: this.session.cwd,
							timeoutMs: 10_000,
							maxBytes: 1024,
							signal,
						});
						if (removeRun.exitCode === 0) {
							this.ownedForwards.delete(port);
							removed.push(port);
						}
					} else {
						// 映射已在外部被变更或已解除，不移除外部映射，仅清理自身记录且不计入 removed
						this.ownedForwards.delete(port);
					}
				}
			} else {
				for (const [p, f] of Array.from(this.ownedForwards.entries())) {
					if (f.serial === serial && f.package === packageName) {
						const cleanRemote = `localabstract:${f.socketName.replace(/^@/, "")}`;
						const activeMatch = activeList.find(
							e => (e.serial === serial || !e.serial) && e.local === `tcp:${p}` && e.remote === cleanRemote,
						);
						if (activeMatch) {
							const removeRun = await runner(dep.path, ["-s", serial, "forward", "--remove", `tcp:${p}`], {
								cwd: this.session.cwd,
								timeoutMs: 10_000,
								maxBytes: 1024,
								signal,
							});
							if (removeRun.exitCode === 0) {
								this.ownedForwards.delete(p);
								removed.push(p);
							}
						} else {
							// 映射已在外部被变更或已解除，不移除外部映射，仅清理自身记录且不计入 removed
							this.ownedForwards.delete(p);
						}
					}
				}
			}
			return {
				content: [
					{
						type: "text",
						text: `Cleaned up ${removed.length} owned forward(s) on ${serial}: [${removed.join(", ")}]`,
					},
				],
				details: {
					action: "webview_debug",
					status: "ok",
					serial,
					package: packageName,
					webviewOp,
					forwardPort: port,
				},
			};
		}

		// Find target package PIDs
		const psRun = await runner(dep.path, ["-s", serial, "shell", "ps", "-A"], {
			cwd: this.session.cwd,
			timeoutMs: 15_000,
			maxBytes: 262144,
			signal,
		});
		const psText = new TextDecoder().decode(psRun.stdout);
		const targetPids = new Set<number>();
		for (const line of psText.split("\n")) {
			const tokens = line.trim().split(/\s+/);
			if (tokens.length >= 2) {
				const procName = tokens[tokens.length - 1];
				if (procName === packageName || procName.startsWith(`${packageName}:`)) {
					const pid = parseInt(tokens[1], 10);
					if (!Number.isNaN(pid) && pid > 0) targetPids.add(pid);
				}
			}
		}

		// Read unix domain sockets: cat /proc/net/unix
		const unixRun = await runner(dep.path, ["-s", serial, "shell", "cat", "/proc/net/unix"], {
			cwd: this.session.cwd,
			timeoutMs: 15_000,
			maxBytes: 262144,
			signal,
		});
		const unixText = new TextDecoder().decode(unixRun.stdout);

		const discoveredSockets: Array<{ pid: number; package: string; socketName: string }> = [];
		for (const line of unixText.split("\n")) {
			const match = line.match(/@.*devtools_remote.*$/);
			if (match) {
				const socketName = match[0];
				const pidMatch = socketName.match(/_(\d+)$/);
				const pid = pidMatch ? parseInt(pidMatch[1], 10) : -1;
				// Must strictly match an identified target package PID (never match pid 0 or arbitrary sockets)
				if (pid > 0 && targetPids.has(pid)) {
					discoveredSockets.push({ pid, package: packageName, socketName });
				}
			}
		}

		if (webviewOp === "discover") {
			const lines = [
				`// Discovered WebViews for ${packageName} on ${serial}`,
				`Target PIDs: [${Array.from(targetPids).join(", ")}]`,
				`Found Sockets (${discoveredSockets.length}):`,
				...discoveredSockets.map(s => `  • ${s.socketName} (PID: ${s.pid})`),
			];
			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "webview_debug",
					status: "ok",
					serial,
					package: packageName,
					webviewOp,
					discoveredSockets,
				},
			};
		}

		if (webviewOp === "forward") {
			if (!params.socket_name) {
				throw new ToolError("webview_debug forward requires 'socket_name'");
			}
			const socketName = params.socket_name.trim();

			// Validate socket membership: must be in discovered sockets for target package
			const matchedSocket = discoveredSockets.find(s => s.socketName === socketName);
			if (!matchedSocket) {
				throw new ToolError(
					`socket_name '${socketName}' is not a discovered DevTools socket for package '${packageName}' (PIDs: [${Array.from(targetPids).join(", ")}]). Forwarding unverified sockets is prohibited.`,
				);
			}
			const port =
				params.forward_port !== undefined
					? validatePort(params.forward_port, "forward_port")
					: 9222 + (matchedSocket.pid % 1000);
			const cleanSocket = socketName.replace(/^@/, "");

			// Use --no-rebind to avoid clobbering existing binds
			const forwardRun = await runner(
				dep.path,
				["-s", serial, "forward", "--no-rebind", `tcp:${port}`, `localabstract:${cleanSocket}`],
				{
					cwd: this.session.cwd,
					timeoutMs: 15_000,
					maxBytes: 4096,
					signal,
				},
			);

			if (forwardRun.exitCode !== 0) {
				const err =
					forwardRun.stderr.trim() || `adb forward --no-rebind failed with exit code ${forwardRun.exitCode}`;
				return {
					content: [{ type: "text", text: `[Forward Failed] Failed to bind tcp:${port}: ${err}` }],
					details: {
						action: "webview_debug",
						status: "error",
						serial,
						package: packageName,
						webviewOp,
						error: err,
					},
				};
			}

			const forwardInfo: OwnedForward = {
				serial,
				port,
				socketName,
				pid: matchedSocket.pid,
				package: packageName,
				createdAt: Date.now(),
			};
			this.ownedForwards.set(port, forwardInfo);

			const cdpEndpoint = `http://127.0.0.1:${port}`;
			const cleanupHandle = `tcp:${port}`;

			const lines = [
				`// WebView DevTools Forward Created`,
				`Device: ${serial} (${packageName})`,
				`Socket: ${socketName} (PID: ${matchedSocket.pid})`,
				`CDP Endpoint: ${cdpEndpoint}`,
				`Cleanup Handle: ${cleanupHandle}`,
				`Guidance: Connect using existing browser reverse controllers to ${cdpEndpoint}/json/list.`,
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "webview_debug",
					status: "ok",
					serial,
					package: packageName,
					webviewOp,
					forwardPort: port,
					cdpEndpoint,
					cleanupHandle,
					discoveredSockets,
				},
			};
		}

		throw new ToolError(`Unrecognized webview_op: ${String(webviewOp)}`);
	}

	// 打开并以受控方式读取安全文件（request_file 与 body_file）：
	// 使用 O_RDONLY | O_NOFOLLOW | O_NONBLOCK 持有句柄，杜绝软链接劫持与 FIFO 命名管道挂起；
	// 并在句柄上通过 fstat 校验常规文件、非公共可写权限及属主与尺寸，彻底杜绝 TOCTOU 竞争与超大文件溢出。
	private async readSafeFile(resolvedPath: string, maxSize: number, label: string): Promise<string> {
		let fh: fs.FileHandle;
		try {
			fh = await fs.open(resolvedPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
		} catch (err) {
			throw new ToolError(
				`Failed to open ${label} '${resolvedPath}': ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		try {
			const st = await fh.stat();
			if (!st.isFile()) {
				throw new ToolError(`${label} '${resolvedPath}' is not a regular file`);
			}
			// POSIX 权限与属主校验：保护机密文件隐私，拒绝 Group 或 Others 具有任何读/写/执行权限（要求 mode 0o600 或 0o400）
			if (process.platform !== "win32") {
				if ((st.mode & 0o077) !== 0) {
					throw new ToolError(
						`${label} '${resolvedPath}' has insecure permissions (mode 0o${(st.mode & 0o777).toString(8)}). Protected files must be private to owner only (e.g. mode 0o600 or 0o400)`,
					);
				}
				if (typeof process.getuid === "function") {
					const currentUid = process.getuid();
					if (st.uid !== 0 && st.uid !== currentUid) {
						throw new ToolError(
							`${label} '${resolvedPath}' is not owned by the current user (uid ${st.uid} !== ${currentUid})`,
						);
					}
				}
			}

			if (st.size > maxSize) {
				throw new ToolError(`${label} '${resolvedPath}' exceeds maximum allowed size (${maxSize} bytes)`);
			}

			// 以有界定长 Buffer 读取至多 maxSize + 1 字节
			const buffer = Buffer.alloc(maxSize + 1);
			const { bytesRead } = await fh.read(buffer, 0, maxSize + 1, 0);
			if (bytesRead > maxSize) {
				throw new ToolError(`${label} '${resolvedPath}' exceeds maximum allowed size (${maxSize} bytes)`);
			}

			return buffer.toString("utf8", 0, bytesRead);
		} finally {
			await fh.close().catch(() => {});
		}
	}

	// --------------------------------------------------------------------------
	// Action: network_replay
	// --------------------------------------------------------------------------

	private async handleNetworkReplay(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		// 1. 严格校验并规范化 allowed_origins
		if (!params.allowed_origins || !Array.isArray(params.allowed_origins) || params.allowed_origins.length === 0) {
			throw new ToolError(
				"network_replay strictly requires non-empty 'allowed_origins' (e.g. ['https://api.example.com'])",
			);
		}

		const allowedOrigins: string[] = [];
		const allowedOriginsSet = new Set<string>();
		for (const rawOrigin of params.allowed_origins) {
			let parsed: URL;
			try {
				parsed = new URL(rawOrigin);
			} catch {
				throw new ToolError(`Invalid allowed_origin URL: '${rawOrigin}'`);
			}
			// 必须限制为 http 或 https 协议，禁止 null、file:、ftp: 等伪源
			if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
				throw new ToolError(`allowed_origins must use http or https scheme: '${rawOrigin}'`);
			}
			const normOrigin = parsed.origin.toLowerCase();
			if (!allowedOriginsSet.has(normOrigin)) {
				allowedOriginsSet.add(normOrigin);
				allowedOrigins.push(normOrigin);
			}
		}

		// 2. 解析受控请求定义文件（request_file，仅支持单一标准 baseline_request 结构，无平铺别名）
		interface RawRequestDef {
			url?: string;
			method?: string;
			headers?: Record<string, string>;
			body?: string;
			body_file?: string;
			auth_header_env?: string;
			header_env_map?: Record<string, string>;
			id?: string;
			name?: string;
		}

		let baseline: RawRequestDef | undefined = params.baseline_request;
		let fileVariants: RawRequestDef[] | undefined;
		if (params.request_file) {
			const resolvedPath = resolveReadPath(params.request_file, this.session.cwd);
			// 校验 request_file 为不超过 1 MiB 的受控常规文件
			const fileData = await this.readSafeFile(resolvedPath, 1024 * 1024, "request_file");
			let parsed: unknown;
			try {
				parsed = JSON.parse(fileData);
			} catch {
				throw new ToolError(`Failed to parse request_file '${params.request_file}': Invalid JSON syntax`);
			}

			if (
				typeof parsed !== "object" ||
				parsed === null ||
				!("baseline_request" in parsed) ||
				typeof (parsed as Record<string, unknown>).baseline_request !== "object" ||
				(parsed as Record<string, unknown>).baseline_request === null
			) {
				throw new ToolError(`request_file '${params.request_file}' must contain a 'baseline_request' object`);
			}

			const obj = parsed as Record<string, unknown>;
			const fileBase = obj.baseline_request as RawRequestDef;
			baseline = {
				url: fileBase.url ?? baseline?.url,
				method: fileBase.method ?? baseline?.method,
				headers: fileBase.headers ?? baseline?.headers,
				body: fileBase.body,
				body_file: fileBase.body_file ?? baseline?.body_file,
				auth_header_env: fileBase.auth_header_env ?? baseline?.auth_header_env,
				header_env_map: fileBase.header_env_map ?? baseline?.header_env_map,
			};

			if (Array.isArray(obj.variant_requests)) {
				fileVariants = obj.variant_requests as RawRequestDef[];
			}
		}

		if (!baseline || !baseline.url) {
			throw new ToolError("network_replay requires 'baseline_request.url' or a valid 'request_file'");
		}

		// 合并 variants 列表，并限制最多 10 个 variant 请求
		const rawVariants: RawRequestDef[] = params.variant_requests ?? fileVariants ?? [];
		if (rawVariants.length > 10) {
			throw new ToolError("Maximum 10 variant requests allowed per replay run");
		}

		// 4. 统一安全预构建器：在发送任何请求之前，构造并严格校验全量请求的规范化方法、URL、Header与凭据映射
		interface PreparedReplayRequest {
			id: string;
			name?: string;
			url: string;
			method: string;
			finalHeaders: Record<string, string>;
			body?: string;
		}

		const preconstructAndValidate = async (
			label: string,
			id: string,
			name: string | undefined,
			urlStr: string,
			rawMethod: string | undefined,
			headers: Record<string, string> | undefined,
			authEnv: string | undefined,
			headerEnvMap: Record<string, string> | undefined,
			rawBody: string | undefined,
			bodyFile: string | undefined,
			inheritedBody: string | undefined,
			inheritedHeaders: Record<string, string>,
			isFromArgs: boolean,
		): Promise<PreparedReplayRequest> => {
			// 规范化并校验 HTTP 方法
			const method = String(rawMethod ?? "GET").toUpperCase();
			if (!Object.hasOwn(ALLOWED_HTTP_METHODS, method)) {
				throw new ToolError(
					`Invalid HTTP method in ${label}. Allowed methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS`,
				);
			}

			// 校验 URL（无原始 urlStr 回显）
			let parsed: URL;
			try {
				parsed = new URL(urlStr);
			} catch {
				throw new ToolError(`Invalid request URL in ${label}`);
			}

			if (parsed.username || parsed.password) {
				throw new ToolError("Embedded username or password in URL is prohibited to prevent transcript leakage");
			}

			if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
				throw new ToolError(`Request URL must use http or https in ${label}`);
			}

			const origin = parsed.origin.toLowerCase();
			if (!allowedOriginsSet.has(origin)) {
				throw new ToolError(
					`URL origin '${origin}' is not in allowed_origins [${allowedOrigins.join(", ")}]. Replay prohibited.`,
				);
			}

			for (const [k] of parsed.searchParams) {
				if (/(token|access_token|key|api[-_]?key|auth|secret|password)/i.test(k)) {
					throw new ToolError(
						`Inline sensitive credential query parameter '${k}' is prohibited. Use auth_header_env.`,
					);
				}
			}

			// 预构建最终请求头映射（统一小写键以支持大小写不敏感覆盖与去重）
			const finalHeaders: Record<string, string> = { ...inheritedHeaders };

			if (headers) {
				if (typeof headers !== "object" || headers === null || Array.isArray(headers)) {
					throw new ToolError(`Invalid headers object in ${label}: headers must be a key-value mapping`);
				}
				for (const [k, v] of Object.entries(headers)) {
					if (typeof k !== "string" || typeof v !== "string") {
						throw new ToolError(`Header names and values in ${label} must be strings`);
					}
					if (/[\r\n]/.test(k) || /[\r\n]/.test(v)) {
						throw new ToolError(`CRLF characters detected in header '${k}' in ${label}: prohibited`);
					}
					if (isFromArgs && SENSITIVE_KEY_PATTERN.test(k)) {
						throw new ToolError(
							`Inline credential header '${k}' in tool arguments is prohibited to prevent secret exposure. Use auth_header_env, header_env_map, or request_file.`,
						);
					}
					finalHeaders[k.toLowerCase()] = v;
				}
			}

			// 预校验并合并环境变量凭据（校验是否存在换行符或非法凭据注入）
			if (authEnv) {
				const envVal = process.env[authEnv];
				if (!envVal || envVal.trim() === "") {
					throw new ToolError(
						`Environment variable '${authEnv}' specified in auth_header_env is not set or empty`,
					);
				}
				const token = envVal.trim();
				if (/[\r\n]/.test(token)) {
					throw new ToolError(`CRLF characters detected in environment variable '${authEnv}': prohibited`);
				}
				finalHeaders["authorization"] =
					token.startsWith("Bearer ") || token.startsWith("Basic ") ? token : `Bearer ${token}`;
			}

			if (headerEnvMap) {
				if (typeof headerEnvMap !== "object" || headerEnvMap === null || Array.isArray(headerEnvMap)) {
					throw new ToolError(`Invalid header_env_map in ${label}: must be a key-value mapping`);
				}
				for (const [headerName, envVarName] of Object.entries(headerEnvMap)) {
					if (typeof headerName !== "string" || typeof envVarName !== "string") {
						throw new ToolError(`header_env_map keys and values in ${label} must be strings`);
					}
					if (/[\r\n]/.test(headerName)) {
						throw new ToolError(`CRLF characters detected in header name '${headerName}': prohibited`);
					}
					const envVal = process.env[envVarName];
					if (!envVal || envVal.trim() === "") {
						throw new ToolError(
							`Environment variable '${envVarName}' specified for header '${headerName}' in header_env_map is not set or empty`,
						);
					}
					const headerVal = envVal.trim();
					if (/[\r\n]/.test(headerVal)) {
						throw new ToolError(`CRLF characters detected in environment variable '${envVarName}': prohibited`);
					}
					finalHeaders[headerName.toLowerCase()] = headerVal;
				}
			}

			// 通过 new Headers 预测试构造合法性，若存在非法字符在任何网络动作发生前直接抛错
			try {
				new Headers(finalHeaders);
			} catch {
				throw new ToolError(`Invalid header name or value in ${label}: header validation failed`);
			}
			if (finalHeaders.host && finalHeaders.host.toLowerCase() !== parsed.host.toLowerCase()) {
				throw new ToolError(`Host header must match the request URL origin in ${label}`);
			}

			// 解析 Body
			let resolvedBody: string | undefined;
			if (bodyFile) {
				const resolvedBodyPath = resolveReadPath(bodyFile, this.session.cwd);
				resolvedBody = await this.readSafeFile(resolvedBodyPath, 1024 * 1024, `${label} body_file`);
			} else if (rawBody !== undefined) {
				resolvedBody = rawBody;
			} else {
				resolvedBody = inheritedBody;
			}
			if (resolvedBody && Buffer.byteLength(resolvedBody, "utf8") > 1024 * 1024) {
				throw new ToolError(`${label} request body exceeds maximum allowed size (1 MiB)`);
			}

			return {
				id,
				name,
				url: urlStr,
				method,
				finalHeaders,
				body: method !== "GET" && method !== "HEAD" ? resolvedBody : undefined,
			};
		};

		// 预构建 Baseline 请求
		const baselineHasInlineHeaders = !!params.baseline_request?.headers;
		const baselineAuthEnv = baseline.auth_header_env ?? params.auth_header_env;
		const preparedBaseline = await preconstructAndValidate(
			"baseline request",
			"baseline",
			undefined,
			baseline.url,
			baseline.method,
			baseline.headers,
			baselineAuthEnv,
			baseline.header_env_map,
			baseline.body,
			baseline.body_file,
			undefined,
			{},
			baselineHasInlineHeaders,
		);

		// 提取 baseline 中明确非凭据的安全静态 Header（剔除敏感特征头与全部 env-mapped 凭据头）
		const baselineEnvHeaderNames = new Set<string>();
		if (baseline.auth_header_env || params.auth_header_env) {
			baselineEnvHeaderNames.add("authorization");
		}
		if (baseline.header_env_map) {
			for (const hName of Object.keys(baseline.header_env_map)) {
				baselineEnvHeaderNames.add(hName.toLowerCase());
			}
		}

		const safeInheritedBaselineHeaders: Record<string, string> = {};
		if (baseline.headers) {
			for (const [k, v] of Object.entries(baseline.headers)) {
				const lowerK = k.toLowerCase();
				if (!SENSITIVE_KEY_PATTERN.test(lowerK) && !baselineEnvHeaderNames.has(lowerK)) {
					safeInheritedBaselineHeaders[lowerK] = v;
				}
			}
		}

		// 预构建全部 Variant 请求：任何一个 variant 的错误都会在此阶段抛错，确保 0 个网络请求发生
		const preparedVariants: PreparedReplayRequest[] = [];
		const variantsFromArgs = !!params.variant_requests;
		for (let i = 0; i < rawVariants.length; i++) {
			const v = rawVariants[i];
			const variantId = v.id || `variant-${i + 1}`;
			const pv = await preconstructAndValidate(
				`variant '${variantId}'`,
				variantId,
				v.name,
				v.url ?? baseline.url,
				v.method ?? baseline.method,
				v.headers,
				v.auth_header_env,
				v.header_env_map,
				v.body,
				v.body_file,
				preparedBaseline.body,
				safeInheritedBaselineHeaders,
				variantsFromArgs,
			);
			preparedVariants.push(pv);
		}

		// 5. 超时与取消控制：结合 caller signal、总体超时与单请求超时
		const timeoutSeconds = Math.min(Math.max(params.timeout ?? 30, 5), 120);
		const overallController = new AbortController();
		const onParentAbort = () => overallController.abort(signal?.reason);
		if (signal) {
			if (signal.aborted) {
				throw new ToolError("Operation aborted before network replay execution");
			}
			signal.addEventListener("abort", onParentAbort, { once: true });
		}
		const overallTimeoutTimer = setTimeout(
			() => overallController.abort(new Error(`network_replay execution timed out (${timeoutSeconds}s)`)),
			timeoutSeconds * 1000,
		);

		const maxCapBytes = Math.min(Math.max(params.max_bytes ?? 524288, 1024), 10 * 1024 * 1024);
		const fetchFn = this.options.fetcher ?? fetch;

		// 6. 执行单个请求的核心安全封装
		const executeRequest = async (req: PreparedReplayRequest) => {
			if (overallController.signal.aborted) {
				throw new ToolError(
					`network_replay aborted or timed out: ${overallController.signal.reason?.message ?? "Operation cancelled"}`,
				);
			}

			// 单请求超时控制（上限 30 秒或总体剩余时间）
			const reqController = new AbortController();
			const onOverallAbort = () => reqController.abort(overallController.signal.reason);
			overallController.signal.addEventListener("abort", onOverallAbort, { once: true });
			const perReqTimer = setTimeout(
				() => reqController.abort(new Error("Single request timed out")),
				Math.min(timeoutSeconds * 1000, 30_000),
			);

			try {
				// 执行 fetch：强制 redirect: "manual"，禁止跨源重定向泄露凭据；保持默认安全 TLS 校验
				const res = await fetchFn(req.url, {
					method: req.method,
					headers: req.finalHeaders,
					body: req.body,
					redirect: "manual",
					signal: reqController.signal,
				});

				// 流式读取响应流：增量计数与截断，避免 O(n²) 频繁拼接与哈希计算
				const chunks: Uint8Array[] = [];
				let capturedBytes = 0;
				let totalBytes = 0;
				let truncated = false;

				if (res.body) {
					const reader = res.body.getReader();
					try {
						while (true) {
							const { done, value } = await reader.read();
							if (done) break;
							totalBytes += value.byteLength;
							const remaining = maxCapBytes - capturedBytes;
							if (remaining > 0) {
								if (value.byteLength <= remaining) {
									chunks.push(value);
									capturedBytes += value.byteLength;
								} else {
									chunks.push(value.subarray(0, remaining));
									capturedBytes += remaining;
									truncated = true;
									await reader.cancel().catch(() => {});
									break;
								}
							} else {
								truncated = true;
								await reader.cancel().catch(() => {});
								break;
							}
						}
					} finally {
						reader.releaseLock();
					}
				}

				const receivedBuffer = Buffer.concat(chunks);
				const hash = createHash("sha256").update(receivedBuffer).digest("hex");
				const bodyHashScope = truncated ? ("truncated_prefix" as const) : ("complete" as const);

				// 响应头安全过滤：仅允许安全响应头白名单（使用 Object.hasOwn 防止原型污染），并限制单值长度
				const safeHeaders: Record<string, string> = {};
				res.headers.forEach((v, k) => {
					const lowerKey = k.toLowerCase();
					if (SENSITIVE_KEY_PATTERN.test(lowerKey)) return;
					if (!Object.hasOwn(SAFE_RESPONSE_HEADERS, lowerKey)) return;

					if (lowerKey === "location") {
						// Location 头脱敏：严格剔除 search query 参数与 hash 锚点（防止 OAuth code/access_token 泄露）
						try {
							const locUrl = new URL(v, req.url);
							locUrl.search = "";
							locUrl.hash = "";
							locUrl.username = "";
							locUrl.password = "";
							safeHeaders[lowerKey] = locUrl.toString().slice(0, 512);
						} catch {
							safeHeaders[lowerKey] = "[REDACTED LOCATION]";
						}
					} else {
						safeHeaders[lowerKey] = v.slice(0, 512);
					}
				});

				// 若显式配置 capture_response_artifacts: true，则受控持久化至 private artifact
				let artifactId: string | undefined;
				let artifactPath: string | undefined;
				if (params.capture_response_artifacts) {
					try {
						const allocation = await this.session.allocateOutputArtifact?.("app_experiment");
						let outputPath: string;
						let outputId: string;
						if (allocation?.path && allocation.id) {
							outputPath = allocation.path;
							outputId = allocation.id;
						} else {
							const artDir = path.join(this.session.cwd, "artifacts", "replay");
							await fs.mkdir(artDir, { recursive: true, mode: 0o700 });
							const runDir = await fs.mkdtemp(path.join(artDir, "response-"));
							outputPath = path.join(runDir, "body.bin");
							outputId = path.basename(runDir);
						}
						await fs.writeFile(outputPath, receivedBuffer, { mode: 0o600, flag: "wx" });
						artifactPath = outputPath;
						artifactId = outputId;
					} catch {
						throw new ToolError(
							"Response received but private artifact publication failed; no evidence artifact was recorded",
						);
					}
				}

				return {
					status: res.status,
					statusText: res.statusText,
					headers: safeHeaders,
					bodyBytes: totalBytes,
					bodySha256: hash,
					bodyHashScope,
					bodyTruncated: truncated,
					artifactId,
					artifactPath,
				};
			} catch (err) {
				if (overallController.signal.aborted) {
					throw new ToolError(
						`network_replay aborted or timed out: ${overallController.signal.reason?.message ?? "Operation timed out"}`,
					);
				}
				throw err;
			} finally {
				clearTimeout(perReqTimer);
				overallController.signal.removeEventListener("abort", onOverallAbort);
			}
		};

		try {
			// 7. 发起 Baseline 请求
			const baselineRes = await executeRequest(preparedBaseline);

			// 8. 依次执行 Variant 请求并对比差异
			const variantResults: NonNullable<AppExperimentDetails["variantResults"]> = [];
			for (const pv of preparedVariants) {
				const vRes = await executeRequest(pv);

				const statusMatch = vRes.status === baselineRes.status;
				// 若任一响应被截断，哈希无法证明完整内容一致性，bodyHashMatch 显式标记为 null（unknown）
				const isTruncated = vRes.bodyTruncated === true || baselineRes.bodyTruncated === true;
				const bodyHashMatch = isTruncated ? null : vRes.bodySha256 === baselineRes.bodySha256;

				let statusDelta = `${baselineRes.status} -> ${vRes.status}`;
				if (isTruncated) {
					statusDelta += " (body truncated; hash match unknown)";
				}

				variantResults.push({
					id: pv.id,
					name: pv.name,
					status: vRes.status,
					statusText: vRes.statusText,
					headers: vRes.headers,
					bodyBytes: vRes.bodyBytes,
					bodySha256: vRes.bodySha256,
					bodyHashScope: vRes.bodyHashScope,
					bodyTruncated: vRes.bodyTruncated,
					artifactId: vRes.artifactId,
					artifactPath: vRes.artifactPath,
					diffAgainstBaseline: {
						statusMatch,
						bodyHashMatch,
						statusDelta,
						lengthDelta: vRes.bodyBytes - baselineRes.bodyBytes,
					},
				});
			}

			// 9. 格式化输出文本（安全渲染 URL，剔除 search 与 hash 锚点）
			let sanitizedBaselineUrl = preparedBaseline.url;
			try {
				const u = new URL(preparedBaseline.url);
				sanitizedBaselineUrl = `${u.origin}${u.pathname}`;
			} catch {
				sanitizedBaselineUrl = "[INVALID URL]";
			}

			const lines = [
				`// Network API Replay Comparison`,
				`Allowed Origins: [${allowedOrigins.join(", ")}]`,
				`Baseline: ${preparedBaseline.method} ${sanitizedBaselineUrl} (Status: ${baselineRes.status} ${baselineRes.statusText}, Length: ${baselineRes.bodyBytes} bytes, SHA-256: ${baselineRes.bodySha256.slice(0, 16)}... [${baselineRes.bodyHashScope}])`,
				`Variants Evaluated (${variantResults.length}):`,
				...variantResults.map(
					v =>
						`  • [${v.id}] ${v.name ?? "variant"}: Status ${v.status}, Delta: ${v.diffAgainstBaseline?.statusDelta}, Body delta: ${v.diffAgainstBaseline?.lengthDelta}b, Hash match: ${v.diffAgainstBaseline?.bodyHashMatch === null ? "unknown (truncated)" : v.diffAgainstBaseline?.bodyHashMatch}`,
				),
				`Notice: Status code variations alone do not prove authorization flaws; verification of business response data is required.`,
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "network_replay",
					status: "ok",
					baselineResult: baselineRes,
					variantResults,
					observations: [
						`Replayed baseline and ${variantResults.length} variant requests against ${allowedOrigins.join(", ")}`,
					],
					acceptance: "pending_verification",
					reproducibleParams: {
						action: "network_replay",
						allowed_origins: allowedOrigins,
					},
				},
			};
		} finally {
			clearTimeout(overallTimeoutTimer);
			if (signal) {
				signal.removeEventListener("abort", onParentAbort);
			}
		}
	}

	// --------------------------------------------------------------------------
	// Action: mitm_capture
	// --------------------------------------------------------------------------

	private async handleMitmCapture(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const mitmOp = params.mitm_op ?? "status";
		const port = params.mitm_port !== undefined ? validatePort(params.mitm_port, "mitm_port") : 8080;
		const serial = params.serial;
		const runner = this.options.runner ?? defaultAdbRunner;
		const dep = adbDependency(this.options.which);

		if (mitmOp === "status") {
			const active = this.activeMitmProcess;
			let isLive = false;
			if (active) {
				if (active.child) {
					isLive = active.child.exitCode === null && active.child.signalCode === null;
				} else {
					try {
						process.kill(active.pid, 0);
						isLive = true;
					} catch {
						isLive = false;
					}
				}
				if (!isLive) {
					this.activeMitmProcess = null;
				}
			}
			return {
				content: [
					{
						type: "text",
						text: `mitm_capture status: ${isLive ? `running (PID: ${active!.pid}, port: ${active!.port})` : "idle"}`,
					},
				],
				details: {
					action: "mitm_capture",
					status: "ok",
					mitmOp,
					mitmPort: isLive ? active?.port : undefined,
					mitmFlowArtifact: isLive ? active?.flowPath : undefined,
				},
			};
		}

		if (mitmOp === "stop") {
			// 使任何并发启动步骤失效，并等待正在执行的启动完成回滚
			this.state.generation++;
			if (this.state.startupInFlight) {
				try {
					await this.state.startupInFlight;
				} catch {}
			}
			this.state.startingMitm = false;
			const active = this.activeMitmProcess;
			if (active) {
				active.cleanupWatchdog?.();
				await terminateChildProcess(active.child);
				this.activeMitmProcess = null;
			}
			const { proxyRestored } = await cleanupDeviceProxyState(this.state, runner, this.options.which);
			const lastError = this.state.savedDeviceProxy?.lastError;
			const isError = Boolean(lastError);
			return {
				content: [
					{
						type: "text",
						text: isError
							? `mitmdump stopped with warning: device proxy/reverse cleanup incomplete: ${lastError}`
							: `mitmdump session stopped. Device proxy restored: ${proxyRestored}`,
					},
				],
				details: {
					action: "mitm_capture",
					status: isError ? "error" : "ok",
					mitmOp,
					proxyRestored,
					error: lastError,
				},
			};
		}

		if (mitmOp === "start") {
			// 若存在进行中的会话清理或并发启动，阻塞等待其完成
			if (this.state.cleanupInFlight) {
				await this.state.cleanupInFlight;
			}
			if (this.state.startupInFlight) {
				await this.state.startupInFlight;
			}

			// 同步抢占 startingMitm 状态，防止并发 start 穿透
			if (this.activeMitmProcess || this.state.startingMitm) {
				return {
					content: [
						{
							type: "text",
							text: `[Active Capture Exists] An active mitmdump capture is already running or starting. Stop the active session first before starting a new capture.`,
						},
					],
					details: {
						action: "mitm_capture",
						status: "error",
						error: "Active mitmdump capture already running or starting",
					},
				};
			}

			this.state.startingMitm = true;
			const startingGen = ++this.state.generation;

			const runStart = async (): Promise<
				AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }
			> => {
				// 确认获得预留后，若存在上次未完全释放的遗留 savedDeviceProxy，尝试重试清理
				if (this.state.savedDeviceProxy) {
					await cleanupDeviceProxyState(this.state, runner, this.options.which);
					if (this.state.savedDeviceProxy) {
						return {
							content: [
								{
									type: "text",
									text: `[Device Proxy Incomplete] Cannot start capture while previous device proxy/reverse cleanup is pending: ${this.state.savedDeviceProxy.lastError || "cleanup failed"}`,
								},
							],
							details: {
								action: "mitm_capture",
								status: "error",
								error: `Previous device proxy cleanup incomplete: ${this.state.savedDeviceProxy.lastError || "cleanup failed"}`,
							},
						};
					}
				}

				let child: ChildProcess | undefined;
				let flowPath = "";
				let localSavedProxy: SavedProxy | undefined;
				try {
					// 参数校验：在产生任何外部副作用前执行
					if (params.timeout !== undefined) {
						if (
							typeof params.timeout !== "number" ||
							!Number.isFinite(params.timeout) ||
							params.timeout < 1 ||
							params.timeout > 120
						) {
							throw new ToolError("timeout must be a positive number between 1 and 120 seconds");
						}
					}
					const durationSec = Math.min(Math.max(params.timeout ?? 60, 1), 120);

					const MAX_FLOW_BYTES = 10 * 1024 * 1024; // 10 MiB 上限
					if (params.max_bytes !== undefined) {
						if (
							typeof params.max_bytes !== "number" ||
							!Number.isSafeInteger(params.max_bytes) ||
							params.max_bytes < 1 ||
							params.max_bytes > MAX_FLOW_BYTES
						) {
							throw new ToolError(
								`max_bytes must be a positive integer between 1 and ${MAX_FLOW_BYTES} (10 MiB)`,
							);
						}
					}
					const maxByteCap = params.max_bytes ?? MAX_FLOW_BYTES;

					// 前置校验：若请求配置设备代理，必须提供 serial 且设备处于可用状态
					if (params.configure_device_proxy) {
						if (!serial) {
							return {
								content: [
									{
										type: "text",
										text: "[Target Device Required] configure_device_proxy requires an explicit 'serial' parameter.",
									},
								],
								details: {
									action: "mitm_capture",
									status: "device_required",
									error: "configure_device_proxy requires explicit serial",
								},
							};
						}
						if (!dep.available || !dep.path) {
							return {
								content: [{ type: "text", text: "[Notice] Primary tool 'adb' not found on PATH." }],
								details: {
									action: "mitm_capture",
									status: "missing_dependency",
									serial,
									error: "adb not found on PATH",
								},
							};
						}
						const deviceCheck = await this.verifyDevice(serial, runner, signal);
						if (this.state.generation !== startingGen) {
							return {
								content: [
									{ type: "text", text: "[Aborted] Session was reset or disposed during device preflight." },
								],
								details: {
									action: "mitm_capture",
									status: "error",
									error: "Session disposed during preflight",
								},
							};
						}
						if (deviceCheck.status !== "ok") {
							return {
								content: [{ type: "text", text: deviceCheck.message }],
								details: {
									action: "mitm_capture",
									status: deviceCheck.status,
									serial,
									error: deviceCheck.message,
								},
							};
						}
					}

					let dumpPath: string | null = null;
					if (this.options.which) {
						dumpPath = this.options.which("mitmdump");
					} else if (typeof Bun !== "undefined" && typeof Bun.which === "function") {
						dumpPath = Bun.which("mitmdump");
					}
					if (!dumpPath) {
						return {
							content: [
								{ type: "text", text: `[Missing Dependency] 'mitmdump' binary is not available on PATH.` },
							],
							details: {
								action: "mitm_capture",
								status: "missing_dependency",
								error: "mitmdump not found on PATH",
							},
						};
					}

					// 端口可用性检查：确保端口当前未被外部程序占用
					const isAvailable = await checkPortAvailable(port, "127.0.0.1");
					if (this.state.generation !== startingGen) {
						return {
							content: [{ type: "text", text: "[Aborted] Session was reset or disposed during port check." }],
							details: { action: "mitm_capture", status: "error", error: "Session disposed during port check" },
						};
					}
					if (!isAvailable) {
						return {
							content: [
								{
									type: "text",
									text: `[Port Already Occupied] Port ${port} on 127.0.0.1 is already in use by another process.`,
								},
							],
							details: {
								action: "mitm_capture",
								status: "error",
								error: `Port ${port} is already in use on 127.0.0.1`,
							},
						};
					}

					const flowDir = path.join(this.session.cwd, "artifacts", "mitm");
					await fs.mkdir(flowDir, { recursive: true, mode: 0o700 });
					flowPath = path.join(flowDir, `capture_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.mitm`);
					await fs.writeFile(flowPath, "", { mode: 0o600, flag: "wx" });

					try {
						child = spawn(
							dumpPath,
							[
								"--listen-host",
								"127.0.0.1",
								"-p",
								String(port),
								"-w",
								flowPath,
								"--set",
								"flow_detail=0",
								"--set",
								`body_size_limit=${maxByteCap}`,
								"--set",
								`stream_large_bodies=${maxByteCap}`,
							],
							{
								detached: true,
								stdio: ["ignore", "pipe", "pipe"],
								env: { ...process.env, PYTHONUNBUFFERED: "1" },
							},
						);
					} catch (err) {
						await fs.unlink(flowPath).catch(() => {});
						return {
							content: [
								{
									type: "text",
									text: `[mitmdump Spawn Failed] ${err instanceof Error ? err.message : String(err)}`,
								},
							],
							details: {
								action: "mitm_capture",
								status: "error",
								error: String(err),
							},
						};
					}

					const pid = child.pid!;
					const durationMs = durationSec * 1000;
					let timeoutTimer: NodeJS.Timeout | undefined;
					let statInterval: NodeJS.Timeout | undefined;

					const onCallerAbort = () => {
						void triggerSessionCleanup(this.state, this.options.runner, this.options.which);
					};
					signal?.addEventListener("abort", onCallerAbort, { once: true });

					const clearWatchdogs = () => {
						signal?.removeEventListener("abort", onCallerAbort);
						if (timeoutTimer) {
							clearTimeout(timeoutTimer);
							timeoutTimer = undefined;
						}
						if (statInterval) {
							clearInterval(statInterval);
							statInterval = undefined;
						}
					};

					const activeProcess: ActiveMitmProcess = {
						id: startingGen,
						pid,
						port,
						flowPath,
						startTime: Date.now(),
						timeoutMs: durationMs,
						maxBytes: maxByteCap,
						observedLimitExceeded: false,
						kill: () => {
							clearWatchdogs();
							killChildProcessGroup(child);
						},
						child,
						cleanupWatchdog: clearWatchdogs,
					};

					// 派生后立即登记活跃进程，确保任何并发 abort 或 session dispose 均能将其纳入受控清理范围
					this.state.activeMitmProcess = activeProcess;

					let procLogs = "";
					let exited = false;
					let exitCode: number | null = null;
					child.stdout?.setEncoding("utf8");
					child.stdout?.on("data", (chunk: string) => {
						procLogs = (procLogs + chunk).slice(-16384);
					});
					child.stderr?.setEncoding("utf8");
					child.stderr?.on("data", (chunk: string) => {
						procLogs = (procLogs + chunk).slice(-16384);
					});
					child.on("exit", code => {
						exited = true;
						exitCode = code;
						clearWatchdogs();
						if (this.state.activeMitmProcess?.id === startingGen) {
							this.state.activeMitmProcess = null;
							void triggerSessionCleanup(this.state, this.options.runner, this.options.which);
						}
					});
					child.on("error", err => {
						procLogs = (procLogs + `\n${err.message}`).slice(-16384);
					});

					// 就绪特征与端口绑定冲突特征（包含 stdout 与 stderr）
					const LISTENING_REGEX =
						/(?:Proxy server listening at|listening at|Proxy listening|Proxy server listening)/i;
					const EADDR_REGEX = /(?:Address already in use|EADDRINUSE|cannot bind|error: unable to bind)/i;
					const startWait = Date.now();
					const readinessTimeout = 5000;
					let isReady = false;

					while (Date.now() - startWait < readinessTimeout) {
						if (this.state.generation !== startingGen) break;
						if (exited) break;
						if (EADDR_REGEX.test(procLogs)) break;
						if (signal?.aborted) break;

						if (LISTENING_REGEX.test(procLogs)) {
							const canConnect = await probeTcpPort(port, 300);
							if (canConnect && !exited && this.state.generation === startingGen) {
								isReady = true;
								break;
							}
						}
						const { promise: delayPromise, resolve: delayResolve } = Promise.withResolvers<void>();
						setTimeout(delayResolve, 50);
						await delayPromise;
					}

					if (this.state.generation !== startingGen || !isReady || exited || child.pid === undefined) {
						killChildProcessGroup(child, true);
						this.state.activeMitmProcess = null;
						await fs.unlink(flowPath).catch(() => {});
						const errReason =
							this.state.generation !== startingGen
								? "Session was reset or disposed during startup"
								: signal?.aborted
									? "Aborted by caller signal"
									: exited
										? `mitmdump exited prematurely with code ${exitCode}: ${procLogs || "(no output)"}`
										: `mitmdump readiness check timed out or port ${port} not open: ${procLogs || "(timeout)"}`;
						return {
							content: [{ type: "text", text: `[mitmdump Failed to Listen] ${errReason}` }],
							details: {
								action: "mitm_capture",
								status: "error",
								error: errReason,
							},
						};
					}

					let proxyConfigured = false;
					if (params.configure_device_proxy && serial && dep.available && dep.path) {
						// 读取原代理配置，并严格校验执行结果与未被截断/超时
						const curRun = await runner(
							dep.path,
							["-s", serial, "shell", "settings", "get", "global", "http_proxy"],
							{ cwd: this.session.cwd, timeoutMs: 10_000, maxBytes: 1024 },
						);
						if (
							curRun.exitCode !== 0 ||
							curRun.timedOut ||
							curRun.truncated ||
							this.state.generation !== startingGen
						) {
							killChildProcessGroup(child, true);
							this.state.activeMitmProcess = null;
							await fs.unlink(flowPath).catch(() => {});
							const msg =
								this.state.generation !== startingGen
									? "Session disposed during proxy setup"
									: `Failed to query current http_proxy (exit ${curRun.exitCode})`;
							return {
								content: [{ type: "text", text: `[Get Proxy Failed] ${msg}` }],
								details: { action: "mitm_capture", status: "error", error: msg },
							};
						}
						const prevVal = new TextDecoder().decode(curRun.stdout).trim();

						// (1) 反向代理：将设备 127.0.0.1:port 流量转发至宿主机 port
						const revRun = await runner(
							dep.path,
							["-s", serial, "reverse", "--no-rebind", `tcp:${port}`, `tcp:${port}`],
							{ cwd: this.session.cwd, timeoutMs: 10_000, maxBytes: 1024 },
						);
						if (revRun.exitCode !== 0) {
							killChildProcessGroup(child, true);
							this.state.activeMitmProcess = null;
							await fs.unlink(flowPath).catch(() => {});
							return {
								content: [
									{
										type: "text",
										text: `[ADB Reverse Failed] Failed to reverse port ${port}: ${revRun.stderr || "exit " + revRun.exitCode}`,
									},
								],
								details: {
									action: "mitm_capture",
									status: "error",
									error: revRun.stderr || `adb reverse failed (exit ${revRun.exitCode})`,
								},
							};
						}

						// 反向代理建立成功后立即记录所有权，确保即使后续操作中发生 abort/dispose，清理逻辑也能准确解除反向代理
						localSavedProxy = {
							serial,
							previousValue: prevVal,
							port,
							reverseOwned: true,
						};
						this.savedDeviceProxy = localSavedProxy;

						if (this.state.generation !== startingGen) {
							await rollbackSavedProxy(localSavedProxy, runner, this.options.which);
							if (this.state.savedDeviceProxy === localSavedProxy) {
								this.state.savedDeviceProxy = null;
							}
							killChildProcessGroup(child, true);
							this.state.activeMitmProcess = null;
							await fs.unlink(flowPath).catch(() => {});
							return {
								content: [
									{ type: "text", text: "[Aborted] Session was reset during device proxy configuration." },
								],
								details: {
									action: "mitm_capture",
									status: "error",
									error: "Session disposed during proxy setup",
								},
							};
						}

						// (2) 全局代理：设置设备 HTTP 代理
						const proxyRun = await runner(
							dep.path,
							["-s", serial, "shell", "settings", "put", "global", "http_proxy", `127.0.0.1:${port}`],
							{ cwd: this.session.cwd, timeoutMs: 10_000, maxBytes: 1024 },
						);
						if (proxyRun.exitCode !== 0 || this.state.generation !== startingGen) {
							// 失败时统一通过 rollbackSavedProxy 恢复/回滚已建立的配置
							await rollbackSavedProxy(localSavedProxy, runner, this.options.which);
							if (this.state.savedDeviceProxy === localSavedProxy) {
								this.state.savedDeviceProxy = null;
							}
							killChildProcessGroup(child, true);
							this.state.activeMitmProcess = null;
							await fs.unlink(flowPath).catch(() => {});
							return {
								content: [
									{
										type: "text",
										text: `[Set Proxy Failed] Failed to configure device http_proxy: ${proxyRun.stderr || "exit " + proxyRun.exitCode}`,
									},
								],
								details: {
									action: "mitm_capture",
									status: "error",
									error: proxyRun.stderr || `settings put failed (exit ${proxyRun.exitCode})`,
								},
							};
						}

						proxyConfigured = true;
					}

					// 超时自动清理看门狗
					timeoutTimer = setTimeout(async () => {
						if (this.state.activeMitmProcess?.id === startingGen) {
							clearWatchdogs();
							await terminateChildProcess(child);
							this.state.activeMitmProcess = null;
							void triggerSessionCleanup(this.state, this.options.runner, this.options.which);
						}
					}, durationMs);

					// 流量大小上限看门狗：周期性检查 flow 文件大小，超过限制立即终止并等待退出
					statInterval = setInterval(async () => {
						if (this.state.activeMitmProcess?.id !== startingGen) {
							clearWatchdogs();
							return;
						}
						try {
							const stat = await fs.stat(flowPath);
							if (stat.size > maxByteCap) {
								activeProcess.observedLimitExceeded = true;
								clearWatchdogs();
								await terminateChildProcess(child, 1000);
								this.state.activeMitmProcess = null;
								void triggerSessionCleanup(this.state, this.options.runner, this.options.which);
							}
						} catch {}
					}, 200);

					// 启动成功并转入后台会话生命周期管理，注销本次调用专属的 AbortSignal 监听器，避免 turn 结束误杀
					signal?.removeEventListener("abort", onCallerAbort);

					return {
						content: [
							{
								type: "text",
								text: `mitmdump active (PID: ${pid}, port: ${port}).\nFlow file: ${flowPath}\nDevice proxy configured: ${proxyConfigured}`,
							},
						],
						details: {
							action: "mitm_capture",
							status: "ok",
							mitmOp,
							mitmPort: port,
							mitmFlowArtifact: flowPath,
							proxyConfigured,
						},
					};
				} catch (err) {
					if (localSavedProxy) {
						await rollbackSavedProxy(localSavedProxy, runner, this.options.which);
						if (this.state.savedDeviceProxy === localSavedProxy) {
							this.state.savedDeviceProxy = null;
						}
					}
					if (this.state.activeMitmProcess?.id === startingGen) {
						this.state.activeMitmProcess.kill();
						this.state.activeMitmProcess = null;
					}
					if (flowPath) {
						await fs.unlink(flowPath).catch(() => {});
					}
					throw err;
				}
			};

			const startupPromise = runStart();
			this.state.startupInFlight = startupPromise;
			try {
				return await startupPromise;
			} finally {
				this.state.startingMitm = false;
				if (this.state.startupInFlight === startupPromise) {
					this.state.startupInFlight = undefined;
				}
			}
		}

		throw new ToolError(`Unrecognized mitm_op: ${String(mitmOp)}`);
	}

	// --------------------------------------------------------------------------
	// Action: pinning_diagnose
	// --------------------------------------------------------------------------

	private async handlePinningDiagnose(
		params: AppExperimentParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
		const packageName = params.package?.trim() ?? "";
		const mode = params.pinning_mode ?? "detect";

		const limitations = [
			"Dynamic instrumentation only captures TLS implementations routed through Java TrustManager or OkHttp CertificatePinner.",
			"Native TLS stacks (BoringSSL/Cronet/Flutter/Rust) or obfuscated custom pinners bypass these standard hooks.",
			"Observation of bypassed or failed checks does not guarantee universal bypass or absence of secondary pinning mechanisms.",
		];

		if (mode === "detect") {
			const targetPath = params.path;
			if (!targetPath) {
				throw new ToolError(
					"pinning_diagnose in 'detect' mode requires 'path' to target APK (.apk) to parse network security config and manifest pinning declarations.",
				);
			}

			// Real invocation of AndroidPackageInspectTool
			const inspectTool = new AndroidPackageInspectTool(this.session);
			const inspectRes = await inspectTool.execute(
				"detect-manifest",
				{ action: "manifest", path: targetPath },
				signal,
			);

			if (inspectRes.details.status !== "ok" || !inspectRes.details.manifest) {
				const err = inspectRes.details.error ?? "Failed to inspect APK manifest";
				return {
					content: [{ type: "text", text: `[Inspection Failed] ${err}` }],
					details: {
						action: "pinning_diagnose",
						status: "error",
						package: packageName || undefined,
						limitations,
					},
				};
			}

			const manifest = inspectRes.details.manifest;
			if (packageName && manifest.package && manifest.package !== packageName) {
				throw new ToolError(
					`Package '${manifest.package}' in APK '${targetPath}' does not match requested package '${packageName}'.`,
				);
			}

			const netConfig = manifest.networkSecurityConfig;
			const findings: Record<string, unknown> = {
				package: manifest.package,
				mode: "detect",
				usesCleartextTraffic: manifest.application.usesCleartextTraffic,
				networkSecurityConfigRef: manifest.application.networkSecurityConfig,
				domainConfigsCount: netConfig?.domainConfigs?.length ?? 0,
				domainConfigs: netConfig?.domainConfigs,
				unresolvedResourceId: netConfig?.unresolvedResourceId,
				resolvedFile: netConfig?.resolvedFile,
			};

			const lines = [
				`// TLS Pinning Static Diagnosis`,
				`Target: ${targetPath}`,
				`Package: ${manifest.package}`,
				`Mode: detect`,
				`Findings: ${JSON.stringify(findings, null, 2)}`,
				`Limitations:`,
				...limitations.map(l => `  • ${l}`),
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "pinning_diagnose",
					status: "ok",
					package: manifest.package,
					pinningMode: mode,
					findings,
					limitations,
				},
			};
		}

		if (mode === "hook_report") {
			const serial = this.requireSerial(params.serial);
			if (!packageName) {
				throw new ToolError("pinning_diagnose in 'hook_report' mode requires explicit 'package'");
			}

			const fridaReq: ToolRequirement[] = [{ id: "frida" }];
			const [fridaStatus] = checkToolRequirements(
				fridaReq,
				this.options.which ? { which: this.options.which } : undefined,
			);

			if (!fridaStatus?.foundPath) {
				return {
					content: [
						{
							type: "text",
							text: `[Missing Dependency] 'frida' is not available on PATH for hook_report mode. Use pinning_mode: 'detect' with an APK path for static network-security-config analysis.`,
						},
					],
					details: {
						action: "pinning_diagnose",
						status: "missing_dependency",
						serial,
						package: packageName,
						pinningMode: mode,
						error: "frida not found on PATH",
						limitations,
					},
				};
			}
			const runner = this.options.runner ?? defaultAdbRunner;
			const dep = adbDependency(this.options.which);
			if (!dep.available || !dep.path) {
				return {
					content: [{ type: "text", text: `[Notice] Primary tool 'adb' not found on PATH.` }],
					details: {
						action: "pinning_diagnose",
						status: "missing_dependency",
						serial,
						package: packageName,
						pinningMode: mode,
						error: "adb not found on PATH",
						limitations,
					},
				};
			}

			const deviceCheck = await this.verifyDevice(serial, runner, signal);
			if (deviceCheck.status !== "ok") {
				return {
					content: [{ type: "text", text: deviceCheck.message }],
					details: {
						action: "pinning_diagnose",
						status: deviceCheck.status,
						serial,
						package: packageName,
						pinningMode: mode,
						error: deviceCheck.message,
						limitations,
					},
				};
			}

			const psRun = await runner(dep.path, ["-s", serial, "shell", "ps", "-A"], {
				cwd: this.session.cwd,
				timeoutMs: 15_000,
				maxBytes: 262144,
				signal,
			});
			if (psRun.exitCode !== 0 || psRun.truncated || psRun.timedOut) {
				throw new ToolError("Unable to obtain a complete target process inventory");
			}
			const psText = new TextDecoder().decode(psRun.stdout);
			let targetPid: number | undefined;
			let childPid: number | undefined;
			for (const line of psText.split("\n")) {
				const tokens = line.trim().split(/\s+/);
				const procName = tokens[tokens.length - 1];
				const pid = Number(tokens[1]);
				if (!Number.isInteger(pid) || pid <= 0) continue;
				if (procName === packageName) {
					targetPid = pid;
					break;
				}
				if (procName?.startsWith(`${packageName}:`)) childPid ??= pid;
			}
			targetPid ??= childPid;

			if (!targetPid) {
				return {
					content: [
						{
							type: "text",
							text: `[Process Not Running] Package '${packageName}' is not currently running on device '${serial}'. Launch the application or invoke a component first before dynamic diagnostic hooking.`,
						},
					],
					details: {
						action: "pinning_diagnose",
						status: "error",
						serial,
						package: packageName,
						pinningMode: mode,
						error: `Package '${packageName}' is not currently running on device`,
						limitations,
					},
				};
			}

			const fridaTool = new FridaTool(this.session);
			// 只记录安装状态与原始校验的通过/失败；保留原方法返回值和异常，不实施绕过。
			const diagnosticScript = `
Java.perform(function() {
    var events = 0;
    function emit(event) {
        if (events++ < 200) console.log('__FRIDA_TRACE_START__' + JSON.stringify({events: [event]}) + '__FRIDA_TRACE_END__');
    }
    function install(className, methodName) {
        var count = 0;
        try {
            var methods = Java.use(className)[methodName].overloads;
            methods.forEach(function(method) {
                method.implementation = function() {
                    try {
                        var result = method.apply(this, arguments);
                        emit({event: 'tls_check', name: className + '.' + methodName, status: 'passed'});
                        return result;
                    } catch (error) {
                        emit({event: 'tls_check', name: className + '.' + methodName, status: 'failed'});
                        throw error;
                    }
                };
                count++;
            });
        } catch (error) {}
        emit({event: 'tls_hooks', name: className + '.' + methodName, status: count > 0 ? 'installed' : 'unavailable', details: {overloadsHooked: count}});
    }
    install('com.android.org.conscrypt.TrustManagerImpl', 'checkTrusted');
    install('org.conscrypt.TrustManagerImpl', 'checkTrusted');
    install('okhttp3.CertificatePinner', 'check');
});
`;

			let fridaRes;
			try {
				fridaRes = await fridaTool.execute(
					"pinning-call",
					{
						action: "exec",
						pid: targetPid,
						device: serial,
						script: diagnosticScript,
						timeout: Math.min(30, params.timeout ?? 15),
					},
					signal,
				);
			} catch (err) {
				return {
					content: [
						{
							type: "text",
							text: `[Frida Hook Diagnostic Failed] ${err instanceof Error ? err.message : String(err)}`,
						},
					],
					details: {
						action: "pinning_diagnose",
						status: "error",
						serial,
						package: packageName,
						pinningMode: mode,
						error: String(err),
						limitations,
					},
				};
			}
			const fridaDetails = fridaRes.details;
			if (!fridaDetails) throw new ToolError("Frida returned no diagnostic execution record");
			const diagnosticEvents = parseFridaTrace(fridaDetails.stdout ?? "").events;
			const hookCount = diagnosticEvents.filter(
				event => event.event === "tls_hooks" && event.status === "installed",
			).length;
			const checks = diagnosticEvents.filter(event => event.event === "tls_check");
			const boundedObservation =
				fridaDetails.status === "timeout" && fridaDetails.timedOut && fridaDetails.cleanup?.completed;
			const diagnosticOk = hookCount > 0 && (fridaDetails.status === "ok" || boundedObservation === true);

			const lines = [
				`// Dynamic Pinning Diagnostic Report`,
				`Target: ${packageName} on ${serial}`,
				`Frida Execution Status: ${fridaDetails.status}${boundedObservation ? " (observation window ended; owned process cleanup completed)" : ""}`,
				`Hook targets installed: ${hookCount}; TLS checks observed: ${checks.length}`,
				JSON.stringify(diagnosticEvents),
				`Limitations:`,
				...limitations.map(l => `  • ${l}`),
			];

			return {
				content: [{ type: "text", text: lines.join("\n") }],
				details: {
					action: "pinning_diagnose",
					status: diagnosticOk ? "ok" : "error",
					serial,
					package: packageName,
					pinningMode: mode,
					findings: {
						hooksInstalled: hookCount,
						checks,
						events: diagnosticEvents,
						artifactPath: fridaDetails.artifactPath,
						observationLimited: Boolean(boundedObservation),
					},
					acceptance: "pending_verification",
					...(!diagnosticOk
						? { error: "No diagnostic hooks were confirmed installed, or Frida execution failed" }
						: {}),
					limitations,
				},
			};
		}

		throw new ToolError(`Unrecognized pinning_mode: ${String(mode)}`);
	}

	// --------------------------------------------------------------------------
	// Helpers & Validation
	// --------------------------------------------------------------------------

	private requireSerial(serial: string | undefined): string {
		if (!serial) throw new ToolError("Action requires explicit 'serial' (e.g. emulator-5554)");
		const trimmed = serial.trim();
		if (!SERIAL_PATTERN.test(trimmed)) {
			throw new ToolError(
				`Invalid serial '${serial}': must contain only alphanumeric characters, dots, underscores, hyphens, and colons`,
			);
		}
		return trimmed;
	}

	private requirePackage(pkg: string | undefined): string {
		if (!pkg) throw new ToolError("Action requires explicit 'package' (e.g. com.example.app)");
		const trimmed = pkg.trim();
		if (!PACKAGE_PATTERN.test(trimmed)) {
			throw new ToolError(`Invalid package name '${pkg}': expected dotted application ID such as com.example.app`);
		}
		return trimmed;
	}

	private validateComponent(comp: string, expectedPkg: string): string {
		const trimmed = comp.trim();
		if (!COMPONENT_PATTERN.test(trimmed)) {
			throw new ToolError(`Invalid component name '${comp}': contains invalid characters`);
		}
		if (trimmed.includes("/") && !trimmed.startsWith(`${expectedPkg}/`)) {
			throw new ToolError(`Component '${trimmed}' must belong to package '${expectedPkg}'`);
		}
		return trimmed;
	}

	private validateIntentData(data: string): string {
		const trimmed = data.trim();
		if (/[;\s'"$`\\]/.test(trimmed)) {
			throw new ToolError("intent_data contains prohibited whitespace, quotes, or shell characters");
		}
		return trimmed;
	}

	private async verifyDevice(
		serial: string,
		runner: AdbRunner,
		signal?: AbortSignal,
	): Promise<{ status: AppExperimentStatus; message: string }> {
		const dep = adbDependency(this.options.which);
		if (!dep.available || !dep.path) {
			return { status: "missing_dependency", message: "adb not found on PATH" };
		}

		const runResult = await runner(dep.path, ["devices", "-l"], {
			cwd: this.session.cwd,
			timeoutMs: 10_000,
			maxBytes: 32768,
			signal,
		});

		const devices = parseAdbDevices(new TextDecoder().decode(runResult.stdout));
		const match = devices.find(d => d.serial === serial);
		if (!match) {
			return {
				status: "device_not_found",
				message: `Device '${serial}' not found in attached devices list: [${devices.map(d => d.serial).join(", ") || "none"}]`,
			};
		}
		if (match.state === "unauthorized") {
			return {
				status: "device_unauthorized",
				message: `Device '${serial}' is unauthorized. Confirm USB debugging on device screen.`,
			};
		}
		if (match.state === "offline") {
			return { status: "device_offline", message: `Device '${serial}' is offline.` };
		}
		if (match.state !== "device") {
			return {
				status: "device_unavailable",
				message: `Device '${serial}' is in state '${match.state}' (not 'device').`,
			};
		}

		return { status: "ok", message: "Device verified online and authorized" };
	}
}

// ============================================================================
// Device Scenario Exercise Entrypoint
// ============================================================================

export interface DeviceExerciseScenarioOptions {
	serial: string;
	package: string;
	action:
		| "preflight"
		| "invoke_component"
		| "query_provider"
		| "extract_sandbox_data"
		| "webview_debug"
		| "pinning_diagnose";
	component?: string;
	intent_data?: string;
	provider_uri?: string;
	subpath?: string;
	timeout?: number;
}

/**
 * Explicit device scenario runner entrypoint accepting explicit serial and target package.
 * Never auto-run in automated test suites; designed for explicit live device testing.
 */
export async function runAndroidLabExercise(
	session: ToolSession,
	options: DeviceExerciseScenarioOptions,
): Promise<AgentToolResult<AppExperimentDetails> & { details: AppExperimentDetails }> {
	const tool = new AppExperimentTool(session);
	return tool.execute("scenario-call", {
		action: options.action,
		serial: options.serial,
		package: options.package,
		component: options.component,
		intent_data: options.intent_data,
		uri: options.provider_uri,
		subpath: options.subpath,
		timeout: options.timeout,
	});
}
