/**
 * 异步等待与无进展轮询门禁（Issue #16）。
 *
 * 约束边界：
 * - 等待态仅由当前调用方实际拥有的未完成异步工作（AsyncJobManager 运行中/待投递任务、
 *   当前会话拥有的后台服务、当前调用方派生且仍在运行的子代理）决定，严禁解析 thinking 或依赖 intent 文本。
 * - 当存在上述待完成异步工作时，拦截裸 shell 空操作（精确解析 `true`、`:` 或空命令，绝不拦截
 *   `cmd || true` 等复合命令或带参命令），阻止派生无意义子进程；无待完成异步工作时，独立 `true` 保持合法。
 * - 对 `agent://<id>` 的同一运行代次与进度快照（status + generation + yield sections + 最新文本）
 *   最多允许读取观测 1 次；在快照未变化、代次未结束且用户未发起新提问前，后续重复读取直接短路并引导调用 `wait`
 *   或结束当前回合等待事件注入。
 * - 连续无进展轮询计数跨 `read agent://` 与 `bash true` 共享，交替调用不会重置计数。
 */
import type {
	AfterToolCallContext,
	AfterToolCallResult,
	AgentTool,
	AgentToolContext,
	AgentToolResult,
	BeforeToolCallContext,
	BeforeToolCallResult,
} from "@reverse/agent";
import { undeliveredJobs } from "../async/job-control";
import type { AsyncJobManager } from "../async/job-manager";
import { hasLiveOwnedService } from "../launch/services";
import { type AgentRef, AgentRegistry, type AgentStatus, MAIN_AGENT_ID } from "../registry/agent-registry";
import type { ToolSession } from "../tools";
import { lexShellCommand } from "../tools/shell-tokenize";
import { hasWaitTool } from "../tools/wait";
import type { SessionManager } from "./session-manager";

/** 触发强制工具选择重定向（`wait` 或 `"none"`）的连续无进展轮询阈值。 */
export const WAIT_POLL_FORCE_REDIRECT_THRESHOLD = 2;

const WAIT_POLL_TOOL_CHOICE_LABEL = "wait-poll-guard";

/**
 * `agent://<id>` 运行态进度结构化指纹。
 *
 * 仅对影响模型可见实质进度的结构化字段（代理状态、运行代次、已接受的增量 yield 节、
 * 最新 assistant 文本、是否处于旧产物被新回合覆盖状态）计算确定性指纹，忽略随墙钟变化的展示年龄文本。
 */
export interface AgentProgressFingerprint {
	readonly agentId: string;
	readonly status: AgentStatus;
	readonly generationKey: string;
	readonly sectionCount: number;
	readonly sectionsHash: string;
	readonly lastTextHash: string;
	readonly superseded: boolean;
	readonly digest: string;
}

/** 计算 `AgentProgressFingerprint` 的输入。 */
export interface AgentProgressFingerprintInput {
	readonly agentId: string;
	readonly status: AgentStatus;
	readonly createdAt?: number;
	readonly runStartedAt?: number;
	readonly acceptedAt?: number;
	readonly terminalAt?: number;
	readonly sessionFile?: string | null;
	readonly sections?: ReadonlyArray<{ labels?: string; data: string }>;
	readonly lastText?: string;
	readonly superseded?: boolean;
}

/** 拦截结果附加在 `result.details.waitPollGuard` 上的结构化元数据。 */
export interface WaitPollGuardInterceptMeta {
	readonly intercepted: true;
	readonly kind: "noop_bash" | "unchanged_agent_progress";
	readonly count: number;
	readonly preventedNoopBashCount: number;
	readonly unchangedAgentReadCount: number;
	readonly reason: string;
	readonly guidance: string;
	readonly command?: string;
	readonly targetAgentId?: string;
	readonly progressDigest?: string;
}

/** 从工具结果 `details` 中安全提取 `waitPollGuard` 拦截元数据。 */
export function extractWaitPollGuardMeta(details: unknown): WaitPollGuardInterceptMeta | undefined {
	if (!details || typeof details !== "object" || !("waitPollGuard" in details)) return undefined;
	const candidate = details.waitPollGuard;
	if (!candidate || typeof candidate !== "object" || !("intercepted" in candidate) || candidate.intercepted !== true) {
		return undefined;
	}
	return candidate as WaitPollGuardInterceptMeta;
}

/** `WaitPollGuard` 宿主能力接口。支持从 `AgentSession` 或工具侧 `ToolSession` 构造。 */
export interface WaitPollGuardHost {
	/** 显式提供宿主当前是否存在运行中异步工作的回调（可选，与 `session` 自动推导组合生效）。 */
	hasRunningAsyncWork?(): boolean;
	/** 关联的 `ToolSession`（工具侧及 `sessionResolveContext` 默认携带）。 */
	session?: ToolSession;
	/** 获取当前会话的 `AsyncJobManager`。 */
	asyncJobManager?: () => AsyncJobManager | undefined;
	/** 获取当前会话关联的 `AgentRegistry`。 */
	agentRegistry?: () => AgentRegistry | undefined;
	/** 获取当前代理在注册表中的 ID（如 `"Main"`、`"Worker"`）。 */
	agentId?: () => string | null | undefined;
	/** 会话分支管理器，用于低开销检测用户新提问边界。 */
	sessionManager?: Pick<SessionManager, "getBranch" | "getEntries"> &
		Partial<Pick<SessionManager, "getLeafId" | "getSessionId">>;
	/** 单调递增的用户提问序号（当宿主直接提供时优先使用）。 */
	promptSequence?: () => number;
}

/**
 * 为运行中或未发布最终产物的子代理构建结构化进度指纹。
 */
export function computeAgentProgressFingerprint(input: AgentProgressFingerprintInput): AgentProgressFingerprint {
	const generationKey = [
		input.createdAt ?? 0,
		input.runStartedAt ?? 0,
		input.acceptedAt ?? 0,
		input.terminalAt ?? 0,
		input.sessionFile ?? "",
	].join(":");
	const sections = input.sections ?? [];
	const serializedSections = sections.map(section => `${section.labels ?? ""}\0${section.data}`).join("\u0001");
	const sectionsHash = Bun.hash.wyhash(serializedSections).toString(16);
	const lastTextHash = Bun.hash.wyhash(input.lastText ?? "").toString(16);
	const superseded = input.superseded === true;
	const digest = Bun.hash
		.wyhash(
			`${input.agentId}\0${input.status}\0${generationKey}\0${sections.length}\0${sectionsHash}\0${lastTextHash}\0${superseded ? 1 : 0}`,
		)
		.toString(16);
	return {
		agentId: input.agentId,
		status: input.status,
		generationKey,
		sectionCount: sections.length,
		sectionsHash,
		lastTextHash,
		superseded,
		digest,
	};
}

/**
 * 从 `AgentRef` 提取运行代次元数据并构建结构化进度指纹。
 */
export function buildAgentRefProgressFingerprint(
	ref: AgentRef,
	options: {
		sections?: ReadonlyArray<{ labels?: string; data: string }>;
		lastText?: string;
		superseded?: boolean;
	} = {},
): AgentProgressFingerprint {
	return computeAgentProgressFingerprint({
		agentId: ref.id,
		status: ref.status,
		createdAt: ref.createdAt,
		runStartedAt: ref.session?.runStartedAt,
		acceptedAt: ref.lifecycle?.acceptedAt,
		terminalAt: ref.lifecycle?.terminalAt,
		sessionFile: ref.sessionFile,
		sections: options.sections,
		lastText: options.lastText,
		superseded: options.superseded,
	});
}

/**
 * 精确判定命令是否为纯 shell 空操作（仅限独立的 `true`、`:` 或空白命令）。
 *
 * 任何包含管道、逻辑连接符（`||`、`&&`、`;`、`&`）、重定向、命令替换、变量展开、
 * 子 shell、注释、环境变量赋值或附加参数的命令均返回 `false`，确保绝不误伤 `cmd || true` 等合法复合命令。
 */
export function isPureShellNoopCommand(rawCommand: string): boolean {
	const trimmed = rawCommand.trim();
	if (trimmed.length === 0) return true;
	// 排除任何包含控制符、换行、操作符、引号、转义、展开或重定向的命令文本
	if (/[\r\n;&|()<>`$#'"\\]/u.test(trimmed)) return false;
	const tokens = lexShellCommand(trimmed);
	const words: string[] = [];
	for (const token of tokens) {
		if (token.kind === "separator") {
			if (!/^[ \t]+$/u.test(token.raw)) return false;
			continue;
		}
		words.push(token.value);
		if (words.length > 1) return false;
	}
	if (words.length !== 1) return false;
	const cmd = words[0];
	return cmd === "true" || cmd === ":";
}

/**
 * 解析 `agent://<id>`（以及可选 `:selector` 后缀）中的目标代理 ID。
 * 若包含 JSON 路径提取（`agent://<id>/<json-path>`）或 `agent://all`，返回 `undefined`。
 */
export function parseBareAgentProgressUrlId(rawPath: string): string | undefined {
	const trimmed = rawPath.trim();
	if (!trimmed.startsWith("agent://")) return undefined;
	const rest = trimmed.slice("agent://".length);
	if (!rest) return undefined;
	// Strip line selectors such as `agent://Worker:1-20` or `agent://Worker:raw`
	const colonIndex = rest.indexOf(":");
	const withoutSelector = colonIndex >= 0 ? rest.slice(0, colonIndex) : rest;
	if (!withoutSelector || withoutSelector.includes("/") || withoutSelector.includes("?")) {
		return undefined;
	}
	if (withoutSelector === "all") return undefined;
	return withoutSelector;
}

interface ObservedAgentProgressState {
	fingerprint: AgentProgressFingerprint;
	observations: number;
}

/**
 * 会话级异步等待与防空转门禁。
 */
export class WaitPollGuard {
	readonly #host: WaitPollGuardHost;
	readonly #observedAgentProgress = new Map<string, ObservedAgentProgressState>();
	readonly #interceptedByToolCallId = new Map<string, WaitPollGuardInterceptMeta>();
	#consecutiveNoProgressPolls = 0;
	#preventedNoopBashCount = 0;
	#unchangedAgentReadCount = 0;
	#lastPromptBoundaryKey: string | undefined;
	#cachedLeafId: string | null | undefined = undefined;
	#cachedLatestUserEntryId: string | undefined;

	constructor(host: WaitPollGuardHost = {}) {
		this.#host = host;
	}

	/** 当前连续无进展轮询次数（跨 `bash true` 与未变化的 `read agent://` 共享）。 */
	get consecutiveNoProgressPolls(): number {
		this.#syncPromptBoundary();
		return this.#consecutiveNoProgressPolls;
	}

	/** 当前会话累计被拦截的纯 shell 空操作（`true` / `:`）次数。 */
	get preventedNoopBashCount(): number {
		return this.#preventedNoopBashCount;
	}

	/** 当前会话累计被拦截的未变化 `agent://<id>` 重复进度读取次数。 */
	get unchangedAgentReadCount(): number {
		return this.#unchangedAgentReadCount;
	}

	/** 当用户发起新提问时重置门禁状态，使运行中代理在新提问轮次可重新观测一次。 */
	onUserPrompt(): void {
		this.#observedAgentProgress.clear();
		this.#consecutiveNoProgressPolls = 0;
	}

	/** 重置门禁的轮询状态（保留累计统计或按需全清）。 */
	reset(options?: { clearTotals?: boolean }): void {
		this.#observedAgentProgress.clear();
		this.#interceptedByToolCallId.clear();
		this.#consecutiveNoProgressPolls = 0;
		if (options?.clearTotals) {
			this.#preventedNoopBashCount = 0;
			this.#unchangedAgentReadCount = 0;
		}
	}

	#resolveOwnerId(): string | undefined {
		const raw = this.#host.agentId ? this.#host.agentId() : this.#host.session?.getAgentId?.();
		return raw && raw.length > 0 ? raw : undefined;
	}

	#syncPromptBoundary(): void {
		const seq = this.#host.promptSequence?.();
		const sm = this.#host.sessionManager ?? this.#host.session?.sessionManager;
		let userEntryKey = "";
		if (sm) {
			const leafId = typeof sm.getLeafId === "function" ? sm.getLeafId() : undefined;
			if (leafId !== undefined && leafId === this.#cachedLeafId) {
				userEntryKey = this.#cachedLatestUserEntryId ?? "";
			} else {
				this.#cachedLeafId = leafId;
				let latestUserId = "";
				try {
					const branch = sm.getBranch?.() ?? [];
					for (let i = branch.length - 1; i >= 0; i--) {
						const entry: unknown = branch[i];
						if (!entry || typeof entry !== "object" || !("type" in entry) || entry.type !== "message") continue;
						const msg = "message" in entry ? entry.message : undefined;
						if (msg && typeof msg === "object" && "role" in msg && msg.role === "user") {
							latestUserId = "id" in entry && typeof entry.id === "string" ? entry.id : `idx-${i}`;
							break;
						}
					}
				} catch {
					// Ignore branch inspection failures on minimal test stubs
				}
				this.#cachedLatestUserEntryId = latestUserId;
				userEntryKey = latestUserId;
			}
		}
		const key = `${seq ?? ""}:${userEntryKey}`;
		if (this.#lastPromptBoundaryKey === undefined) {
			this.#lastPromptBoundaryKey = key;
			return;
		}
		if (this.#lastPromptBoundaryKey !== key) {
			this.#lastPromptBoundaryKey = key;
			this.#observedAgentProgress.clear();
			this.#consecutiveNoProgressPolls = 0;
		}
	}

	/**
	 * 检查当前调用方是否拥有正在运行或待投递的异步工作（后台任务、后台服务、或自身派生的运行中子代理）。
	 * 严禁将其他代理拥有的任务算作当前调用方的等待态。
	 */
	hasOwnedPendingAsyncWork(options?: { registry?: AgentRegistry; targetAgentId?: string }): boolean {
		const session = this.#host.session;
		// Seance 历史只读回溯会话不处于实时等待态
		if (session?.seanceSourceArtifactsDir) return false;
		if (this.#host.hasRunningAsyncWork?.() === true) return true;

		const ownerId = this.#resolveOwnerId();
		const isTopLevelImplicitMain = ownerId === undefined && (session?.taskDepth ?? 0) === 0;
		const manager = this.#host.asyncJobManager ? this.#host.asyncJobManager() : session?.asyncJobManager;
		if (manager) {
			if (manager.getRunningJobs({ ownerId }).length > 0 || undeliveredJobs(manager, ownerId).length > 0) {
				return true;
			}
			if (
				isTopLevelImplicitMain &&
				(manager.getRunningJobs({ ownerId: MAIN_AGENT_ID }).length > 0 ||
					undeliveredJobs(manager, MAIN_AGENT_ID).length > 0)
			) {
				return true;
			}
		}

		if (session && hasLiveOwnedService(session)) {
			return true;
		}

		const registry =
			options?.registry ?? (this.#host.agentRegistry ? this.#host.agentRegistry() : session?.agentRegistry);
		if (registry) {
			const callerSessionFile = session?.getSessionFile?.() ?? undefined;
			const ownsRef = (ref: AgentRef): boolean => {
				if (ref.kind !== "sub" || ref.status !== "running") return false;
				if (ownerId !== undefined) {
					return ref.parentId === ownerId;
				}
				if (!isTopLevelImplicitMain || ref.parentId !== MAIN_AGENT_ID) return false;
				if (!callerSessionFile) return true;
				const mainRef = registry.get(MAIN_AGENT_ID);
				return !mainRef?.sessionFile || mainRef.sessionFile === callerSessionFile;
			};
			if (options?.targetAgentId) {
				const targetRef = registry.get(options.targetAgentId);
				if (targetRef && ownsRef(targetRef)) return true;
			}
			for (const ref of registry.list()) {
				if (ownsRef(ref)) return true;
			}
		}

		return false;
	}

	/**
	 * 严格按注册表 `parentId` 祖先链检查目标 `AgentRef` 是否隶属于当前调用方（同一根会话），绝不拦截其他代理的子任务。
	 */
	#canGuardAgentRef(ref: AgentRef, registry: AgentRegistry): boolean {
		const session = this.#host.session;
		if (session?.seanceSourceArtifactsDir) return false;
		if (ref.kind === "advisor" || ref.status !== "running") return false;
		const ownerId = this.#resolveOwnerId();
		const targetOwner = ownerId ?? ((session?.taskDepth ?? 0) === 0 ? MAIN_AGENT_ID : undefined);
		if (!targetOwner || ref.id === targetOwner) return false;
		if (ownerId === undefined) {
			const callerSessionFile = session?.getSessionFile?.() ?? undefined;
			const mainRef = registry.get(MAIN_AGENT_ID);
			if (callerSessionFile && mainRef?.sessionFile && mainRef.sessionFile !== callerSessionFile) {
				return false;
			}
		}
		let current: AgentRef | undefined = ref;
		const visited = new Set<string>();
		while (current?.parentId && !visited.has(current.id)) {
			if (current.parentId === targetOwner) return true;
			visited.add(current.id);
			current = registry.get(current.parentId);
		}
		return ownerId === undefined && targetOwner === MAIN_AGENT_ID && ref.id.includes(".");
	}

	#queueWaitToolChoiceIfSupported(): void {
		if (this.#consecutiveNoProgressPolls < WAIT_POLL_FORCE_REDIRECT_THRESHOLD) return;
		const session = this.#host.session;
		if (!session) return;
		const queue = session.getToolChoiceQueue?.();
		if (!queue || queue.inspect().includes(WAIT_POLL_TOOL_CHOICE_LABEL)) return;
		if (hasWaitTool(session) && session.buildToolChoice) {
			const waitChoice = session.buildToolChoice("wait");
			if (waitChoice) {
				queue.pushOnce(waitChoice, { label: WAIT_POLL_TOOL_CHOICE_LABEL });
				return;
			}
		}
		queue.pushOnce("none", { label: WAIT_POLL_TOOL_CHOICE_LABEL });
	}

	/**
	 * 在 `bash` 执行前检查是否为等待态下的裸 shell 空操作（`true` / `:` / 空命令）。
	 * 若被拦截，返回结构化重定向信息且绝不派生子进程；若为合法命令，返回 `undefined`。
	 */
	checkBashCommand(toolCallId: string | undefined, rawCommand: string): WaitPollGuardInterceptMeta | undefined {
		this.#syncPromptBoundary();
		if (toolCallId && this.#interceptedByToolCallId.has(toolCallId)) {
			return this.#interceptedByToolCallId.get(toolCallId);
		}
		if (!isPureShellNoopCommand(rawCommand)) {
			if (!this.hasOwnedPendingAsyncWork()) {
				this.#consecutiveNoProgressPolls = 0;
			}
			return undefined;
		}
		if (!this.hasOwnedPendingAsyncWork()) {
			return undefined;
		}

		this.#consecutiveNoProgressPolls += 1;
		this.#preventedNoopBashCount += 1;
		this.#queueWaitToolChoiceIfSupported();

		const displayCmd = rawCommand.trim() || "(empty)";
		const guidance =
			"Call `wait` to block until your running background job, service, or subagent settles, or end your turn without tool calls so scheduled completion events can be delivered.";
		const reason = `Command '${displayCmd}' is a pure shell no-op while background work you started is still pending (poll #${this.#consecutiveNoProgressPolls}). ${guidance}`;
		const meta: WaitPollGuardInterceptMeta = {
			intercepted: true,
			kind: "noop_bash",
			count: this.#consecutiveNoProgressPolls,
			preventedNoopBashCount: this.#preventedNoopBashCount,
			unchangedAgentReadCount: this.#unchangedAgentReadCount,
			reason,
			guidance,
			command: displayCmd,
		};
		if (toolCallId) {
			this.#interceptedByToolCallId.set(toolCallId, meta);
		}
		return meta;
	}

	/**
	 * 在 `agent://<id>` 解析到运行中（未发布终态产物或旧产物被新回合覆盖）代理时记录并校验进度指纹。
	 * - 同一运行代次与进度快照首次观测：返回 `{ allowed: true, fingerprint }`；
	 * - 进度发生实质变化（新 yield 节、新 assistant 文本、新运行代次）：重置该代理重复计数并返回 `{ allowed: true, fingerprint }`；
	 * - 状态与进度完全未变化且再次读取：返回 `{ allowed: false, fingerprint, meta }` 并短路为等待指引。
	 */
	observeAgentProgress(
		ref: AgentRef,
		fingerprint: AgentProgressFingerprint,
		options?: { registry?: AgentRegistry; toolCallId?: string },
	):
		| { allowed: true; fingerprint: AgentProgressFingerprint }
		| { allowed: false; fingerprint: AgentProgressFingerprint; meta: WaitPollGuardInterceptMeta } {
		this.#syncPromptBoundary();
		if (options?.toolCallId) {
			const existing = this.#interceptedByToolCallId.get(options.toolCallId);
			if (existing && existing.kind === "unchanged_agent_progress") {
				return { allowed: false, fingerprint, meta: existing };
			}
		}

		const registry =
			options?.registry ??
			(this.#host.agentRegistry ? this.#host.agentRegistry() : this.#host.session?.agentRegistry) ??
			AgentRegistry.global();
		if (!this.#canGuardAgentRef(ref, registry)) {
			return { allowed: true, fingerprint };
		}

		const previous = this.#observedAgentProgress.get(ref.id);
		if (!previous || previous.fingerprint.digest !== fingerprint.digest) {
			this.#observedAgentProgress.set(ref.id, {
				fingerprint,
				observations: 1,
			});
			// 观测到实质新进展时重置连续空轮询计数
			if (previous && previous.fingerprint.digest !== fingerprint.digest) {
				this.#consecutiveNoProgressPolls = 0;
			}
			return { allowed: true, fingerprint };
		}

		previous.observations += 1;
		this.#consecutiveNoProgressPolls += 1;
		this.#unchangedAgentReadCount += 1;
		this.#queueWaitToolChoiceIfSupported();

		const guidance =
			"Call `wait` to block until background results arrive, or end your turn without tool calls so completion events can be delivered.";
		const reason = `Subagent '${ref.id}' is still ${ref.status} with no new progress since your previous read (poll #${this.#consecutiveNoProgressPolls}). ${guidance}`;
		const meta: WaitPollGuardInterceptMeta = {
			intercepted: true,
			kind: "unchanged_agent_progress",
			count: this.#consecutiveNoProgressPolls,
			preventedNoopBashCount: this.#preventedNoopBashCount,
			unchangedAgentReadCount: this.#unchangedAgentReadCount,
			reason,
			guidance,
			targetAgentId: ref.id,
			progressDigest: fingerprint.digest,
		};
		if (options?.toolCallId) {
			this.#interceptedByToolCallId.set(options.toolCallId, meta);
		}
		return { allowed: false, fingerprint, meta };
	}

	/** 当 `agent://<id>` 已发布当前代次终态产物时清除其运行态指纹记录，确保完成态结果始终可读。 */
	recordAgentPublishedOutput(agentId: string): void {
		this.#observedAgentProgress.delete(agentId);
	}

	/** 当调用真正的 `wait` 工具时重置连续空轮询计数。 */
	recordWaitInvocation(): void {
		this.#consecutiveNoProgressPolls = 0;
	}

	/**
	 * 供 `AgentSession.#beforeToolCall` 接入的可选前置钩子（与工具内拦截幂等协同）。
	 */
	async beforeToolCall(ctx: BeforeToolCallContext): Promise<BeforeToolCallResult | undefined> {
		this.#syncPromptBoundary();
		const toolName = ctx.tool.name;
		if (toolName === "wait") {
			this.recordWaitInvocation();
			return undefined;
		}
		if (toolName === "bash") {
			const rawCommand =
				ctx.args && typeof ctx.args === "object" && "command" in ctx.args && typeof ctx.args.command === "string"
					? ctx.args.command
					: "";
			const intercepted = this.checkBashCommand(ctx.toolCall.id, rawCommand);
			if (intercepted) {
				return { block: true, reason: intercepted.reason };
			}
			return undefined;
		}
		if (toolName === "read") {
			const rawPath =
				ctx.args && typeof ctx.args === "object" && "path" in ctx.args && typeof ctx.args.path === "string"
					? ctx.args.path
					: "";
			const targetId = parseBareAgentProgressUrlId(rawPath);
			if (!targetId) return undefined;
			const previous = this.#observedAgentProgress.get(targetId);
			if (!previous) return undefined;
			const registry =
				(this.#host.agentRegistry ? this.#host.agentRegistry() : this.#host.session?.agentRegistry) ??
				AgentRegistry.global();
			const ref = registry.get(targetId);
			if (!ref || ref.status !== "running") {
				this.#observedAgentProgress.delete(targetId);
				return undefined;
			}
		}
		return undefined;
	}

	/**
	 * 供 `AgentSession.#afterToolCall` 接入的可选后置钩子：
	 * 将 `beforeToolCall` 拦截的空转调用归一化为非错误（`isError: false, useless: true`）且附带结构化 `waitPollGuard` 元数据。
	 */
	afterToolCall(ctx: AfterToolCallContext): AfterToolCallResult | undefined {
		if (ctx.toolCall.name === "wait") {
			this.recordWaitInvocation();
			return undefined;
		}
		const existingDetails =
			ctx.result.details && typeof ctx.result.details === "object"
				? (ctx.result.details as Record<string, unknown>)
				: {};
		const intercepted = this.#interceptedByToolCallId.get(ctx.toolCall.id);
		if (!intercepted) {
			if (extractWaitPollGuardMeta(existingDetails)) {
				return { isError: false, useless: true };
			}
			return undefined;
		}
		this.#interceptedByToolCallId.delete(ctx.toolCall.id);
		return {
			content: [{ type: "text", text: intercepted.reason }],
			details: {
				...existingDetails,
				...(intercepted.kind === "noop_bash" ? { unexecuted: true } : {}),
				blockedReason: intercepted.reason,
				guidance: intercepted.guidance,
				waitPollGuard: intercepted,
			},
			isError: false,
			useless: true,
		};
	}
	/** 供 `ExtensionRunner.setToolCallPreflight` 桥接调用的前置检查。 */
	async beforeBridgedToolCall(
		toolCallId: string,
		tool: AgentTool,
		args: unknown,
		_context?: AgentToolContext,
	): Promise<{ block?: boolean; reason?: string } | undefined> {
		this.#syncPromptBoundary();
		if (tool.name === "wait") {
			this.recordWaitInvocation();
			return undefined;
		}
		if (tool.name === "bash") {
			const rawCommand =
				args && typeof args === "object" && "command" in args && typeof args.command === "string"
					? args.command
					: "";
			const intercepted = this.checkBashCommand(toolCallId, rawCommand);
			if (intercepted) {
				return { block: true, reason: intercepted.reason };
			}
		}
		return undefined;
	}

	/** 供 `ExtensionRunner.setToolCallPreflight` 桥接调用的后置归一化。 */
	async afterBridgedToolCall(
		toolCallId: string,
		result: AgentToolResult,
		_context?: AgentToolContext,
	): Promise<AgentToolResult | undefined> {
		const existingDetails =
			result.details && typeof result.details === "object" ? (result.details as Record<string, unknown>) : {};
		const intercepted = this.#interceptedByToolCallId.get(toolCallId);
		if (!intercepted) {
			if (extractWaitPollGuardMeta(existingDetails)) {
				return { ...result, isError: false, useless: true };
			}
			return undefined;
		}
		this.#interceptedByToolCallId.delete(toolCallId);
		return {
			content: [{ type: "text", text: intercepted.reason }],
			details: {
				...existingDetails,
				...(intercepted.kind === "noop_bash" ? { unexecuted: true } : {}),
				blockedReason: intercepted.reason,
				guidance: intercepted.guidance,
				waitPollGuard: intercepted,
			},
			isError: false,
			useless: true,
		};
	}

	cancelBridgedToolCall(toolCallId: string): void {
		this.#interceptedByToolCallId.delete(toolCallId);
	}
}

const guardsByToolSession = new WeakMap<object, WaitPollGuard>();
const guardsBySessionManager = new WeakMap<object, WaitPollGuard>();

/**
 * 获取或创建与 `ToolSession` 绑定的 `WaitPollGuard` 实例。
 * 若同一会话的 `sessionManager` 已关联门禁实例，则自动复用同一实例以保证直接调用、桥接调用与会话钩子共享状态。
 */
export function getWaitPollGuard(session: ToolSession): WaitPollGuard {
	let guard = guardsByToolSession.get(session);
	if (guard) return guard;
	const sm = session.sessionManager;
	if (sm && typeof sm === "object") {
		const shared = guardsBySessionManager.get(sm);
		if (shared) {
			guardsByToolSession.set(session, shared);
			return shared;
		}
	}
	guard = new WaitPollGuard({ session });
	guardsByToolSession.set(session, guard);
	if (sm && typeof sm === "object") {
		guardsBySessionManager.set(sm, guard);
	}
	return guard;
}

/**
 * 将外部创建的 `WaitPollGuard` 绑定到指定 `ToolSession` / `SessionManager`，供 `AgentSession` 组装时共享同一实例。
 */
export function registerWaitPollGuard(
	guard: WaitPollGuard,
	targets: { session?: ToolSession; sessionManager?: object },
): WaitPollGuard {
	if (targets.session) {
		guardsByToolSession.set(targets.session, guard);
	}
	if (targets.sessionManager) {
		guardsBySessionManager.set(targets.sessionManager, guard);
	}
	return guard;
}
