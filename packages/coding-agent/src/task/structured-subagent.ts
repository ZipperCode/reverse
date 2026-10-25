/**
 * Shared policy resolution and execution for task and eval subagents.
 *
 * The two public frontends deliberately retain their presentation concerns, but
 * every decision that affects what a child may run lives here.
 */
import * as fs from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";
import { $env, prompt, Snowflake } from "@reverse/utils";
import { shortenPath } from "@reverse/tui/render/render-utils";
import { resolveAgentModelSelection, resolveConfiguredModelPatterns } from "../config/model-resolver";
import { type OAuthAccountPools, validateAgentAccountPools } from "../config/account-pools";
import {
	type CompactionThresholdPair,
	validateAgentCompactionThresholdOverrides,
} from "../config/compaction-threshold";
import { type ServiceTierInheritSettingValue, validateAgentServiceTierOverrides } from "../config/service-tier";
import { isProviderEnabled, isUserSourceEnabled } from "../capability";
import type { EffectiveExtensionRoots } from "../capability/types";
import type { CustomTool } from "../extensibility/custom-tools/types";
import type { Skill } from "../extensibility/skills";
import { sessionLocalProtocolOptions } from "../internal-urls/context";
import { registerArtifactsDir } from "../internal-urls/registry-helpers";
import { MCPManager } from "../mcp/manager";
import { loadOverallPlanReference } from "../plan-mode/plan-handoff";
import planModeSubagentPrompt from "../prompts/system/plan-mode-subagent.md" with { type: "text" };
import subagentUserPromptTemplate from "../prompts/system/subagent-user-prompt.md" with { type: "text" };
import isolationRecoveryHintTemplate from "../prompts/tools/isolation-recovery-hint.md" with { type: "text" };
import salvagedChildHintTemplate from "../prompts/tools/salvaged-child-hint.md" with { type: "text" };
import { MAIN_AGENT_ID } from "../registry/agent-registry";
import type { TaskEffort } from "@reverse/tui/thinking";
import type { ToolSession } from "../tools";
import { isIrcEnabled } from "../irc/messaging";
import { buildOutputValidator } from "../tools/output-schema-validator";
import { trackLateCleanup } from "../utils/late-cleanup";
import { type DiscoveryResult, discoverAgents, getAgent } from "./discovery";
import { type ExecutorOptions, runSubprocess } from "./executor";
import {
	applyEligibleNestedPatches,
	type IsolationContext,
	makeIsolationCommitMessage,
	mergeIsolatedChanges,
	persistNestedPatches,
	prepareIsolationContext,
	renderIsolationSummary,
	runIsolatedSubprocess,
} from "./isolation-runner";
import { generateTaskName, sanitizeAgentId } from "./name-generator";
import { AgentOutputManager } from "./output-manager";
import { resolveSpawnPolicy } from "./spawn-policy";
import { type AgentDefinition, canSpawnAtDepth } from "./types";
import type {
	AgentProgress,
	SingleResult,
	StructuredSubagentOutput,
	StructuredSubagentSchemaMode,
	StructuredSubagentSchemaSource,
} from "@reverse/tui/tools/task";
import type { WorkPoolYieldItem } from "./workpool-yield";
import { parseIsolationBackend } from "./worktree";

import {
	cfgIsolationBackend,
	cfgTaskAgentAccountPools,
	cfgTaskAgentCompactionThresholdOverrides,
	cfgTaskAgentModelOverrides,
	cfgTaskAgentServiceTierOverrides,
	cfgTaskDisabledAgents,
	cfgTaskEnableLsp,
	cfgTaskIsolationApply,
	cfgTaskIsolationEnabled,
	cfgTaskIsolationMerge,
	cfgTaskMaxRecursionDepth,
} from "./settings";

/** Final structured completion metadata returned for a schema-bearing run. */
export type StructuredSubagentSchemaResult = StructuredSubagentOutput;

/** A schema validation or extraction error attached to structured completion metadata. */
export type StructuredSubagentSchemaError = NonNullable<StructuredSubagentOutput["error"]>;

/** A selected schema paired with its source and enforcement mode. */
export interface StructuredSubagentSchemaResolution {
	schema: unknown;
	source: StructuredSubagentSchemaSource;
	mode: StructuredSubagentSchemaMode;
	outputSchemaOverridesAgent: boolean;
}

/** Isolation controls shared by the task and eval surfaces. */
export interface StructuredSubagentIsolationControls {
	requested?: boolean;
	merge?: "patch" | "branch";
	apply?: boolean;
}

/** Identity and presentation metadata supplied by the calling surface. */
export interface StructuredSubagentIdentity {
	/** A previously reserved output/registry id. */
	id?: string;
	/** Stable user-facing label used when allocating a new id. */
	label?: string;
}

/** One normalized child invocation. */
export interface StructuredSubagentRequest {
	session: ToolSession;
	invocationKind: "task" | "eval";
	assignment: string;
	context?: string;
	agent?: string;
	model?: string | string[];
	/** Skills to autoload into the subagent before the first prompt. */
	autoloadSkills?: string[];
	/** Presence, rather than truthiness, makes this the highest-priority schema. */
	outputSchema?: unknown;
	schemaMode?: StructuredSubagentSchemaMode;
	/**
	 * `false` = no output schema (caller, agent, or session) and no `yield` tool:
	 * the child's final assistant message is its result. An agent declaring
	 * `structured: true` keeps both, resolved as if this were `true`. Default `true`.
	 */
	structured?: boolean;
	/** Per-spawn thinking effort mapped onto the resolved model's supported range; overrides the agent's default selector. */
	effort?: TaskEffort;
	/** Caller's description of how open-ended the work is; steers the child's `auto` thinking classification. */
	solutionSpace?: string;
	identity?: StructuredSubagentIdentity;
	index?: number;
	parentToolCallId?: string;
	detached?: boolean;
	invokedAt?: number;
	acquiredAt?: number;
	isolation?: StructuredSubagentIsolationControls;
	/** The parent agent name forbidden from recursively spawning itself. */
	blockedAgent?: string;
	/** Preserve a completed temporary artifacts directory for an agent:// handle. */
	retainArtifacts?: boolean;
	/**
	 * Invoked instead of immediate cleanup when a temporary artifacts
	 * directory is retained (`retainArtifacts`). Callers that outlive this
	 * call — e.g. an async job body — take ownership of the returned
	 * disposal closure and MUST eventually run it once the retained handle
	 * is no longer needed, or the directory leaks for the process lifetime.
	 */
	onArtifactsRetained?: (cleanup: () => Promise<void>) => void;
	/** Task UI agents keep live registry references; eval one-shots normally do not. */
	keepAlive?: boolean;
	/** Task frontends may inherit LSP; eval frontends normally set this false. */
	enableLsp?: boolean;
	/** Explicitly pass false for plan mode or invocation kinds that must not use IRC. */
	enableIrc?: boolean;
	/** `0` disables executor wall-clock timeout. Undefined inherits settings. */
	maxRuntimeMs?: number;
	/** Kernel-defined tools explicitly exposed to this child. */
	customTools?: CustomTool[];
	/** Workpool items accepted by the child yield tool during this turn. */
	workPoolYieldItems?: WorkPoolYieldItem[];
	signal?: AbortSignal;
	onProgress?: (progress: AgentProgress) => void;
}

/** A normalized preflight result, reusable by tests and adapters. */
export interface EffectiveSubagentPolicy {
	discovery: DiscoveryResult;
	agentName: string;
	agent: AgentDefinition;
	effectiveAgent: AgentDefinition;
	modelOverride?: string[];
	/** Explicit pre-expansion model role alias selected for this run. */
	modelRole?: string;
	/** Extension routing note explaining a `before_subagent_spawn` model replacement. */
	modelRoute?: string;
	/** Exact-name `task.agentServiceTierOverrides` entry for this agent, applied after model resolution. */
	serviceTierOverride?: ServiceTierInheritSettingValue;
	/** Exact-name entry normalized to both child compaction threshold fields. */
	compactionThresholdOverride?: CompactionThresholdPair;
	/** Exact-name `task.agentAccountPools` entry: the only OAuth accounts the child may use, per listed provider. */
	oauthAccountPools?: OAuthAccountPools;
	parentActiveModelPattern?: string;
	/** Whether the child gets the `yield` tool; see {@link StructuredSubagentRequest.structured}. */
	structured: boolean;
	schema: StructuredSubagentSchemaResolution;
	planMode: boolean;
	isIsolated: boolean;
	mergeMode: "patch" | "branch";
	applyChanges: boolean;
	enableLsp: boolean;
	enableIrc: boolean;
}

/** Settled child execution plus data needed by the frontends' own rendering. */
export interface StructuredSubagentResult {
	result: SingleResult;
	policy: EffectiveSubagentPolicy;
	mergeSummary: string;
	changesApplied: boolean | null;
	artifactsDir: string;
	temporaryArtifacts: boolean;
}

/** Machine-readable failure category so adapters can retain their native errors. */
export class StructuredSubagentError extends Error {
	readonly kind: "preflight" | "isolation" | "execution";
	/** The child's settled result, when the child finished before a later step failed. */
	readonly result?: SingleResult;

	constructor(
		kind: "preflight" | "isolation" | "execution",
		message: string,
		options?: ErrorOptions & { result?: SingleResult },
	) {
		super(message, options);
		this.name = "StructuredSubagentError";
		this.kind = kind;
		this.result = options?.result;
	}
}

const PLAN_MODE_TOOLS = ["read", "grep", "glob", "web_search"] as const;

function renderSubagentPrompt(assignment: string): string {
	return prompt.render(subagentUserPromptTemplate, { assignment: assignment.trim() });
}

function trimToUndefined(value: string | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed || undefined;
}

function resolveSchema(
	request: StructuredSubagentRequest,
	agent: AgentDefinition,
	structured: boolean,
): StructuredSubagentSchemaResolution {
	const mode = request.schemaMode ?? request.session.outputSchemaMode ?? "permissive";
	if (!structured) {
		return { schema: undefined, source: "none", mode, outputSchemaOverridesAgent: false };
	}
	if (Object.hasOwn(request, "outputSchema")) {
		return { schema: request.outputSchema, source: "caller", mode, outputSchemaOverridesAgent: true };
	}
	if (agent.output !== undefined) {
		return { schema: agent.output, source: "agent", mode, outputSchemaOverridesAgent: false };
	}
	if (request.session.outputSchema !== undefined) {
		return { schema: request.session.outputSchema, source: "session", mode, outputSchemaOverridesAgent: false };
	}
	return { schema: undefined, source: "none", mode, outputSchemaOverridesAgent: false };
}

function createPlanModeAgent(agent: AgentDefinition): AgentDefinition {
	const tools = [...PLAN_MODE_TOOLS, ...(agent.tools ?? []).filter(tool => tool === "ast_grep")];
	return {
		...agent,
		systemPrompt: `${planModeSubagentPrompt}\n\n${agent.systemPrompt}`,
		tools,
		spawns: undefined,
		prewalk: undefined,
	};
}

function assertPlanControlsAllowed(request: StructuredSubagentRequest, planMode: boolean): void {
	if (!planMode) return;
	if (request.customTools?.length) {
		throw new StructuredSubagentError("preflight", "Eval-defined tools are unavailable in plan mode.");
	}
	const isolation = request.isolation;
	if (
		isolation &&
		(Object.hasOwn(isolation, "requested") || Object.hasOwn(isolation, "apply") || Object.hasOwn(isolation, "merge"))
	) {
		throw new StructuredSubagentError(
			"preflight",
			"Subagent isolation, apply, and merge controls are unavailable in plan mode.",
		);
	}
}

function assertDepthAndSpawnAllowed(request: StructuredSubagentRequest, agentName: string): void {
	const taskDepth = request.session.taskDepth ?? 0;
	const maxDepth = cfgTaskMaxRecursionDepth.get(request.session.settings);
	if (!canSpawnAtDepth(maxDepth, taskDepth)) {
		throw new StructuredSubagentError(
			"preflight",
			`Cannot spawn another agent at task depth ${taskDepth}; maximum depth is ${maxDepth}.`,
		);
	}
	const blockedAgent = request.blockedAgent ?? $env.PI_BLOCKED_AGENT;
	if (blockedAgent && blockedAgent === agentName) {
		throw new StructuredSubagentError(
			"preflight",
			`Cannot spawn ${blockedAgent} agent from within itself (recursion prevention). Use a different agent type.`,
		);
	}
	const spawnPolicy = resolveSpawnPolicy(request.session.getSessionSpawns());
	if (!spawnPolicy.enabled || (spawnPolicy.allowedAgents !== null && !spawnPolicy.allowedAgents.includes(agentName))) {
		throw new StructuredSubagentError(
			"preflight",
			`Cannot spawn '${agentName}'. Allowed: ${spawnPolicy.allowedErrorText}`,
		);
	}
}

/**
 * In-flight agent discovery, keyed by resolved cwd, the effective extension
 * roots and the provider/source toggles `discoverAgents` consults. Concurrent
 * preflights (task batch items, eval `agent()` fan-out) share one disk scan;
 * the entry is dropped when the scan settles, so any later call rescans and
 * policy resolution stays as fresh as before. A toggle flipped mid-scan changes
 * the key, so later callers rescan under the new policy. The live
 * `discoverAgents` binding is part of the entry so spies swapped mid-flight
 * never receive a stale result.
 */
const inflightDiscovery = new Map<string, { fn: typeof discoverAgents; promise: Promise<DiscoveryResult> }>();

function discoverAgentsShared(cwd: string, extensionRoots?: EffectiveExtensionRoots): Promise<DiscoveryResult> {
	const fn = discoverAgents;
	const policy = [
		isProviderEnabled("reverse-plugins"),
		isProviderEnabled("claude-plugins"),
		isUserSourceEnabled("claude-plugins"),
		isUserSourceEnabled("claude"),
	].join(",");
	const key = `${path.resolve(cwd)}\0${policy}\0${JSON.stringify(extensionRoots ?? null)}`;
	const existing = inflightDiscovery.get(key);
	if (existing && existing.fn === fn) return existing.promise;
	const promise = fn(cwd, undefined, extensionRoots);
	const entry = { fn, promise };
	inflightDiscovery.set(key, entry);
	const clear = () => {
		if (inflightDiscovery.get(key) === entry) inflightDiscovery.delete(key);
	};
	promise.then(clear, clear);
	return promise;
}

/**
 * Resolve every policy shared by task and eval before allocating artifacts or
 * dispatching work. Callers translate {@link StructuredSubagentError} into
 * their own wire-level error surface.
 */
export async function resolveEffectiveSubagentPolicy(
	request: StructuredSubagentRequest,
): Promise<EffectiveSubagentPolicy> {
	await request.session.settings.reloadFromDisk();
	const spawnPolicy = resolveSpawnPolicy(request.session.getSessionSpawns());
	const agentName = request.agent?.trim() || spawnPolicy.defaultAgent;
	const planMode = request.session.getPlanModeState?.()?.enabled === true;
	assertPlanControlsAllowed(request, planMode);
	assertDepthAndSpawnAllowed(request, agentName);

	const discovery = await discoverAgentsShared(request.session.cwd, request.session.effectiveExtensionRoots?.());
	const agents = [...discovery.agents, ...(request.session.getSessionAgents?.() ?? [])];
	const agent = getAgent(agents, agentName);
	if (!agent) {
		const available = agents.map(candidate => candidate.name).join(", ") || "none";
		const searched = discovery.searchedDirs?.map(dir => shortenPath(dir)).join(", ") || "none";
		throw new StructuredSubagentError(
			"preflight",
			`Unknown agent "${agentName}". Available: ${available}. Searched: ${searched}`,
		);
	}
	const disabledAgents = cfgTaskDisabledAgents.get(request.session.settings);
	if (disabledAgents.includes(agentName)) {
		const enabled = agents
			.filter(candidate => !disabledAgents.includes(candidate.name))
			.map(candidate => candidate.name);
		throw new StructuredSubagentError(
			"preflight",
			`Agent "${agentName}" is disabled in settings. Enable it via /agents, or use a different agent type.${enabled.length > 0 ? ` Available: ${enabled.join(", ")}` : ""}`,
		);
	}

	const effectiveAgent = planMode ? createPlanModeAgent(agent) : agent;
	// An agent declaring `structured: true` keeps its result contract when the caller opts out (`task.structured` off).
	const structured = request.structured !== false || effectiveAgent.structured === true;
	const schema = resolveSchema(request, effectiveAgent, structured);
	if (schema.source === "caller" || (schema.source !== "none" && schema.mode === "strict")) {
		const { error } = buildOutputValidator(schema.schema);
		if (error) {
			const scope =
				schema.source === "caller" ? (schema.mode === "strict" ? "strict caller" : "caller") : "strict effective";
			throw new StructuredSubagentError("preflight", `Invalid ${scope} output schema: ${error}`);
		}
	}
	const agentModelOverrides = cfgTaskAgentModelOverrides.get(request.session.settings);
	const agentServiceTierOverrides = validateAgentServiceTierOverrides(
		cfgTaskAgentServiceTierOverrides.get(request.session.settings),
	);
	const serviceTierOverride = Object.hasOwn(agentServiceTierOverrides, agentName)
		? agentServiceTierOverrides[agentName]
		: undefined;
	const compactionThresholdOverrides = validateAgentCompactionThresholdOverrides(
		cfgTaskAgentCompactionThresholdOverrides.get(request.session.settings),
	);
	const compactionThresholdOverride = Object.hasOwn(compactionThresholdOverrides, agentName)
		? compactionThresholdOverrides[agentName]
		: undefined;
	const agentAccountPools = validateAgentAccountPools(cfgTaskAgentAccountPools.get(request.session.settings));
	const oauthAccountPools = Object.hasOwn(agentAccountPools, agentName) ? agentAccountPools[agentName] : undefined;
	const parentActiveModelPattern = request.session.getActiveModelString?.();
	const modelResolution = {
		requestModel: request.model,
		settingsOverride: agentModelOverrides[agentName],
		agentModel: effectiveAgent.model,
		settings: request.session.settings,
		activeModelPattern: parentActiveModelPattern,
		fallbackModelPattern: request.session.getModelString?.(),
	};
	// Role identity and patterns come from one call so they cannot be derived
	// from different sources: the expansion below discards the alias, and the
	// child's inherited retry-fallback chain is keyed off the role.
	const { patterns: modelOverride, role: modelRole } = resolveAgentModelSelection(modelResolution);
	const isolationEnabled = cfgTaskIsolationEnabled.get(request.session.settings);
	const isIsolated = request.isolation?.requested === true;
	if (isIsolated && !isolationEnabled) {
		throw new StructuredSubagentError(
			"preflight",
			"Subagent isolated execution requires task.isolation.enabled; it is currently false.",
		);
	}
	return {
		discovery,
		agentName,
		agent,
		effectiveAgent,
		modelOverride,
		modelRole,
		serviceTierOverride,
		compactionThresholdOverride,
		oauthAccountPools,
		parentActiveModelPattern,
		structured,
		schema,
		planMode,
		isIsolated,
		mergeMode: request.isolation?.merge ?? cfgTaskIsolationMerge.get(request.session.settings),
		applyChanges:
			request.isolation?.apply ??
			(request.invocationKind === "task" ? cfgTaskIsolationApply.get(request.session.settings) : true),
		enableLsp:
			!planMode &&
			(request.enableLsp ?? ((request.session.enableLsp ?? true) && cfgTaskEnableLsp.get(request.session.settings))),
		enableIrc:
			!planMode &&
			(request.enableIrc ??
				(request.session.enableIrc !== false &&
					isIrcEnabled(request.session.settings, request.session.taskDepth ?? 0))),
	};
}

/**
 * Fire `before_subagent_spawn` for an actual child dispatch. Kept out of
 * {@link resolveEffectiveSubagentPolicy} because frontends run that as a
 * side-effect-free preflight too; stateful routing handlers must see exactly
 * one event per spawned child.
 */
async function applySpawnHook(
	request: StructuredSubagentRequest,
	policy: EffectiveSubagentPolicy,
): Promise<EffectiveSubagentPolicy> {
	const emit = request.session.emitBeforeSubagentSpawn;
	if (!emit) return policy;
	const spawnKey =
		request.identity?.id ??
		request.identity?.label ??
		(request.parentToolCallId !== undefined ? `${request.parentToolCallId}:${request.index ?? 0}` : undefined);
	const spawnResult = await emit(
		{
			type: "before_subagent_spawn",
			agent: policy.agentName,
			invocationKind: request.invocationKind,
			modelRole: policy.modelRole,
			patterns: policy.modelOverride ?? [],
			spawnKey,
		},
		request.signal,
	);
	if (spawnResult?.block) {
		throw new StructuredSubagentError("preflight", spawnResult.reason ?? "Subagent spawn blocked by extension.");
	}
	if (spawnResult?.model === undefined) return policy;
	const replacement = resolveConfiguredModelPatterns(spawnResult.model, request.session.settings);
	if (replacement.length === 0) return policy;
	return { ...policy, modelOverride: replacement, modelRoute: spawnResult.note };
}

/** Reserve a session-global agent id only after preflight has succeeded. */
export async function reserveStructuredSubagentId(
	session: ToolSession,
	identity: StructuredSubagentIdentity | undefined,
): Promise<string> {
	if (identity?.id) return identity.id;
	const manager = session.agentOutputManager ?? new AgentOutputManager(session.getArtifactsDir ?? (() => null));
	session.agentOutputManager ??= manager;
	return manager.allocate(sanitizeAgentId(identity?.label) ?? generateTaskName());
}

interface ArtifactLease {
	sessionFile: string | null;
	artifactsDir: string;
	temporary: boolean;
	unregister: (() => void) | undefined;
}

async function leaseArtifacts(
	session: ToolSession,
	invocationKind: StructuredSubagentRequest["invocationKind"],
): Promise<ArtifactLease> {
	const sessionFile = session.getSessionFile();
	if (sessionFile) {
		const artifactsDir = sessionFile.slice(0, -6);
		await fs.mkdir(artifactsDir, { recursive: true });
		return { sessionFile, artifactsDir, temporary: false, unregister: undefined };
	}
	const artifactsDir = path.join(
		os.tmpdir(),
		`${invocationKind === "eval" ? "reverse-eval-agent" : "reverse-task"}-${Snowflake.next()}`,
	);
	await fs.mkdir(artifactsDir, { recursive: true });
	return { sessionFile: null, artifactsDir, temporary: true, unregister: registerArtifactsDir(artifactsDir) };
}

export const REVERSE_TASK_AUTOLOAD_SKILLS = ["reverse-lab"] as const;

const REVERSE_TASK_PATTERNS = [
	/\b(?:reverse(?:[-_\s]?engineer(?:ing|ed|s)?|[-_\s]?eng)\b|\breversing\b|decompil(?:e|ation|ed|er|ing|es)?|disassembl(?:e|y|ed|er|ing|es)?)\b/i,
	/\b(?:apktool|jadx|droidasc|android_package_inspect|dex_patch|apk_artifact|app_experiment|runtime_analyze|network_replay|mitm_capture|radare2|r2mcp|ghidra|ghidra_inspect|analyzeHeadless|ida-?pro|idapro|idalib|r2_inspect|dotnet_inspect|r2pipe|frida|pcap_inspect|sqlite_inspect|firmware_inspect|crashdump_inspect|binary_metadata_inspect|evm_inspect|binary_diff|reverse_workflow|reverse_runtime_session|reverse_knowledge|reverse_dynamic_evidence|reverse_capability|native_mcp_session|x64dbg|binwalk|vbindiff|triton_analyze|vmp_dump|native_devirtualize|vmprotect|vmpdump|novmp|mergen|blutter|il2cppdumper|dex_unpack|dex_repair|dex_search|deobfuscate|instruction_trace|native_recover|ollvm|flattening|d810|simplify|msynth|blackdex|dexkit)\b/i,
	/\b(?:mach-o|macho|fat\s+binary|pe32\+?|elf(?:32|64)?|minidump|coredump|uimage|squashfs|bytecode|evm)\b/i,
	/\b\w+\.(?:apk|dex|dylib|so|dll|exe|ipa|aab|pcap|pcapng|sqlite|sqlite3|db|dmp|dump|bin|rom|img|evm|har)\b/i,
	/AndroidManifest(?:\.xml)?/i,
	/\b(?:har\b.*?\b(?:authz|api|token|traffic|request|header|trace)|(?:api|token|session|header)\b.*?\bhar\b|api[-_\s]?authz|authz[-_\s]?token)\b/i,
	/(?:逆向|反编译|反汇编|脱壳|抓包|抓包分析|协议逆向|协议分析|接口逆向|鉴权分析|固件|崩溃转储|转储|字节码|二进制(?:逆向|分析|审计|破解|漏洞|安全|静态分析|动态分析|差异|比对))/,
];

export function isReverseTask(assignment?: string, context?: string): boolean {
	const text = `${context ?? ""}\n${assignment ?? ""}`;
	if (!text.trim()) return false;
	return REVERSE_TASK_PATTERNS.some(re => re.test(text));
}

/**
 * Resolves method- and target-aware reverse skills based on task context and assignment.
 * - Base reverse tasks always receive `reverse-lab` as the common orchestrator.
 * - APK / DEX / Android targets route `android-reverse`.
 * - Native binary / SO / JNI / ELF / PE / Mach-O targets route `native-binary-reverse`.
 *   (APK tasks do NOT load native unless explicit SO/JNI/native evidence is present)
 * - Web / HAR / HTTP / API authz / PCAP protocol targets route `web-protocol-reverse`.
 * - VMP / VMProtect / devirtualization targets route `vmp-reverse`.
 * - Windows PE / minidump targets route `windows-reverse`.
 */
export function resolveTargetReverseSkills(assignment?: string, context?: string): string[] {
	const text = `${context ?? ""}\n${assignment ?? ""}`;
	if (!text.trim() || !isReverseTask(assignment, context)) {
		return [];
	}

	const selected = new Set<string>();
	// 基础逆向通用编排技能
	selected.add("reverse-lab");

	// Android / DEX / APK 路由
	const isAndroid =
		/\b(?:android|apk|dex|aab|smali|dalvik|jadx|apktool|droidasc|android_package_inspect|dex_patch|apk_artifact|dex_unpack|dex_repair|dex_search|frida[-_]dexdump|blackdex|fart|dexkit|simplify)\b/i.test(
			text,
		) ||
		/\b\w+\.(?:apk|dex|aab)\b/i.test(text) ||
		/AndroidManifest(?:\.xml)?/i.test(text) ||
		/(?:安卓|安卓应用|安卓逆向|脱壳)/.test(text) ||
		(/\bapp_experiment\b/i.test(text) && /\b(?:device|adb|package|serial|component|android)\b/i.test(text));
	if (isAndroid) {
		selected.add("android-reverse");
	}

	// Native 路由：SO、JNI、ELF、Mach-O、PE、DLL、Ghidra、IDA 等
	// 对于 Android 任务，仅当出现明确的 SO / JNI / 原生层证据时才加载 native-binary-reverse
	const hasNativeEvidence =
		/\b(?:jni|lib[a-zA-Z0-9_-]+\.so|\.so\b|\.dylib\b|\.dll\b|native[-_\s]?librar(?:y|ies)|native[-_\s]?method|elf(?:32|64)?|mach-o|macho|radare2|r2mcp|ghidra|ghidra_inspect|ida-?pro|idapro|idalib|r2_inspect|r2pipe|unidbg|readelf|objdump|vbindiff|native_mcp_session|native_recover|instruction_trace|qbdi|d810(?:-ng)?|msynth|ollvm|control[-_\s]?flow[-_\s]?flattening|cff\b|flattening|mba\b|mixed[-_\s]?boolean[-_\s]?arithmetic)\b/i.test(
			text,
		) || /(?:jni|动态链接库|\.so\b|原生库|反汇编|控制流平坦化|不透明谓词|虚假控制流)/i.test(text);

	const isPureNativeTarget =
		!isAndroid &&
		(/\b(?:native|binary|elf(?:32|64)?|mach-o|macho|disassembl(?:y|e|er)|ghidra|radare2|ida|r2_inspect|ghidra_inspect|native_recover|instruction_trace|deobfuscate|ollvm|control[-_\s]?flow[-_\s]?flattening|cff\b|flattening|mba\b|mixed[-_\s]?boolean[-_\s]?arithmetic|d810(?:-ng)?|msynth)\b/i.test(
			text,
		) ||
			/\b\w+\.(?:so|dylib|dll|exe|bin|elf)\b/i.test(text) ||
			/(?:二进制|动态库|原生|机器码|混淆还原)/.test(text));

	if (hasNativeEvidence || isPureNativeTarget) {
		selected.add("native-binary-reverse");
	}
	// Web / HAR / 接口鉴权 / 协议抓包路由
	const isWebProtocol =
		/\b(?:har\b|pcap|pcapng|http\b|https\b|websocket\b|mitm|mitmproxy|authz|api[-_\s]?authz|token\b|bearer|jwt|cookie\b|rest[-_\s]?api|graphql|network[-_\s]?replay|sourcemap|wasm_inspect)\b/i.test(
			text,
		) ||
		/\b\w+\.(?:har|pcap|pcapng)\b/i.test(text) ||
		/(?:抓包|协议逆向|协议分析|接口逆向|鉴权|网络流)/.test(text);

	if (isWebProtocol) {
		selected.add("web-protocol-reverse");
	}

	// VMP 虚拟化逆向路由
	const isVmp =
		/\b(?:vmp\b|vmprotect|devirtualiz(?:e|ation)|vmp_dump|vmpdump|triton|triton_analyze|novmp|bytecode\s+virtual\s+machine|native_recover|instruction_trace|ollvm|control[-_\s]?flow[-_\s]?flattening|cff\b|flattening|mba\b|mixed[-_\s]?boolean[-_\s]?arithmetic|custom[-_\s]?vmp|android[-_\s]?vmp)\b/i.test(
			text,
		) || /(?:虚拟化保护|虚拟机脱壳|指令还原|自定义vmp|混淆还原|符号执行)/.test(text);

	if (isVmp) {
		selected.add("vmp-reverse");
	}

	// Windows PE 逆向路由
	const isWindows =
		/\b(?:windows|pe32\+?|pe64|\.sys\b|x64dbg|win32|minidump)\b/i.test(text) || /\b\w+\.(?:exe|sys)\b/i.test(text);

	if (isWindows) {
		selected.add("windows-reverse");
	}

	return Array.from(selected);
}

export function getTargetAutoloadSkillNames(agent: AgentDefinition, request?: StructuredSubagentRequest): Set<string> {
	const names = new Set<string>(agent.autoloadSkills ?? []);
	if (request?.autoloadSkills) {
		for (const name of request.autoloadSkills) names.add(name);
	}
	if (agent.name === "task" && request && isReverseTask(request.assignment, request.context)) {
		for (const name of resolveTargetReverseSkills(request.assignment, request.context)) {
			names.add(name);
		}
	}
	return names;
}

/**
 * Agents are rediscovered on every spawn, but the session's skill list is
 * fixed at startup. Rediscover skills once when an agent autoloads a skill the
 * session has not seen, so a skill added after startup is not silently dropped.
 */
async function refreshSkillsForAutoload(
	session: ToolSession,
	agent: AgentDefinition,
	request?: StructuredSubagentRequest,
): Promise<void> {
	const names = getTargetAutoloadSkillNames(agent, request);
	if (names.size === 0 || !session.refreshSkills) return;
	const known = new Set((session.skills ?? []).map(skill => skill.name));
	if (Array.from(names).every(name => known.has(name))) return;
	await session.refreshSkills();
}

export function resolveAutoloadSkills(
	session: ToolSession,
	agent: AgentDefinition,
	request?: StructuredSubagentRequest,
) {
	const skills = [...(session.skills ?? [])];
	const names = getTargetAutoloadSkillNames(agent, request);
	const autoloadSkills =
		names.size > 0
			? Array.from(names)
					.map(name => skills.find(skill => skill.name === name))
					.filter((skill): skill is Skill => skill !== undefined)
			: [];
	return { skills, autoloadSkills };
}

function buildExecutorOptions(
	request: StructuredSubagentRequest,
	policy: EffectiveSubagentPolicy,
	lease: ArtifactLease,
	id: string,
): ExecutorOptions {
	const { session } = request;
	const { skills, autoloadSkills } = resolveAutoloadSkills(session, policy.agent, request);
	const localProtocolOptions = sessionLocalProtocolOptions(session);
	const restrictToolNames = policy.planMode || session.restrictToolNames === true;
	const enableMCP = !restrictToolNames && (session.enableMCP ?? true);
	return {
		cwd: session.cwd,
		additionalDirectories: session.additionalDirectories,
		getApiKey: session.getApiKey,
		credentialSourceSessionId: session.getCredentialSourceSessionId?.(),
		agent: policy.effectiveAgent,
		task: renderSubagentPrompt(request.assignment),
		assignment: request.assignment.trim(),
		context: request.context?.trim() || undefined,
		planReference: undefined,
		// Task `name` is the spawn handle (id allocation). Eval `label` is a
		// real UI description. Copy it only for eval so generateTaskLabel can run.
		description: request.invocationKind === "eval" ? trimToUndefined(request.identity?.label) : undefined,
		index: request.index ?? 0,
		parentToolCallId: request.parentToolCallId,
		detached: request.detached,
		id,
		taskDepth: session.taskDepth ?? 0,
		invokedAt: request.invokedAt,
		acquiredAt: request.acquiredAt,
		modelOverride: policy.modelOverride,
		modelRole: policy.modelRole,
		modelRoute: policy.modelRoute,
		serviceTierOverride: policy.serviceTierOverride,
		compactionThresholdOverride: policy.compactionThresholdOverride,
		oauthAccountPools: policy.oauthAccountPools,
		parentActiveModelPattern: policy.parentActiveModelPattern,
		thinkingLevel: policy.effectiveAgent.thinkingLevel,
		effort: request.effort,
		solutionSpace: request.solutionSpace?.trim() || undefined,
		structured: policy.structured,
		...(policy.schema.source === "none"
			? {}
			: {
					outputSchemaSource: policy.schema.source,
					outputSchema: policy.schema.schema,
					outputSchemaOverridesAgent: policy.schema.outputSchemaOverridesAgent,
					outputSchemaMode: policy.schema.mode,
				}),
		sessionFile: lease.sessionFile,
		persistArtifacts: !lease.temporary,
		artifactsDir: lease.artifactsDir,
		enableLsp: policy.enableLsp,
		enableIrc: policy.enableIrc,
		maxRuntimeMs: request.maxRuntimeMs,
		restrictToolNames,
		keepAlive: request.keepAlive,
		signal: request.signal,
		eventBus: session.eventBus,
		subagentEventBus: session.subagentEventBus,
		onProgress: request.onProgress,
		authStorage: session.authStorage,
		modelRegistry: session.modelRegistry,
		settings: session.settings,
		asyncJobManager: session.asyncJobManager,
		inheritedSessionAgents: session.getSessionAgents?.(),
		mcpManager: enableMCP ? (session.mcpManager ?? MCPManager.instance()) : undefined,
		enableMCP,
		customTools: request.customTools,
		workPoolYieldItems: request.workPoolYieldItems,
		contextFiles: session.contextFiles?.filter(file => path.basename(file.path).toLowerCase() !== "agents.md"),
		skills,
		autoloadSkills,
		workspaceTree: session.workspaceTree,
		promptTemplates: session.promptTemplates,
		rules: session.rules,
		// Root policy and module paths have separate jobs: the live policy drives
		// recursive sub-discovery; preloaded paths only avoid re-scanning/reusing
		// parent-bound extension instances while constructing the child.
		extensionRoots: session.effectiveExtensionRoots?.bind(session),
		preloadedExtensionPaths: restrictToolNames ? [] : session.extensionPaths,
		preloadedPreparedExtensions: session.preparedExtensions,
		preloadedCustomToolPaths: restrictToolNames ? [] : session.customToolPaths,
		localProtocolOptions,
		parentArtifactManager: session.getArtifactManager?.() ?? undefined,
		parentHindsightSessionState: session.getHindsightSessionState?.(),
		parentMnemopiSessionState: session.getMnemopiSessionState?.(),
		parentTelemetry: session.getTelemetry?.(),
		parentAgentId: session.getAgentId?.() ?? MAIN_AGENT_ID,
		parentPromptCacheKey: session.getPromptCacheKey?.(),
		parentServiceTier: session.getServiceTierByFamily ? (session.getServiceTierByFamily() ?? null) : undefined,
	};
}

async function loadPlanReference(
	request: StructuredSubagentRequest,
	policy: EffectiveSubagentPolicy,
): Promise<{ path: string; content: string } | undefined> {
	if (policy.planMode) return undefined;
	return loadOverallPlanReference(
		request.session.getPlanReferencePath?.() ?? "local://PLAN.md",
		sessionLocalProtocolOptions(request.session),
	);
}

function buildFailureResult(
	request: StructuredSubagentRequest,
	policy: EffectiveSubagentPolicy,
	id: string,
	startedAt: number,
) {
	return (error: unknown): SingleResult => {
		const message = error instanceof Error ? error.message : String(error);
		return {
			index: request.index ?? 0,
			id,
			agent: policy.agent.name,
			agentSource: policy.agent.source,
			task: renderSubagentPrompt(request.assignment),
			assignment: request.assignment.trim(),
			description: request.invocationKind === "eval" ? trimToUndefined(request.identity?.label) : undefined,
			exitCode: 1,
			output: "",
			stderr: message,
			truncated: false,
			durationMs: Date.now() - startedAt,
			tokens: 0,
			requests: 0,
			modelOverride: policy.modelOverride,
			modelRole: policy.modelRole,
			error: message,
		};
	};
}

/**
 * Paths of the on-disk nested patches for `result`. The isolation runner
 * writes them before tearing the workspace down; a result that carries
 * `nestedPatches` without paths (older producers, direct callers) is written
 * here as a fallback. Returns the paths and a note when that fallback failed.
 */
async function resolveNestedPatchPaths(
	result: SingleResult,
	artifactsDir: string,
): Promise<{ paths: string[]; failure?: string }> {
	if (result.nestedPatchPaths) return { paths: result.nestedPatchPaths };
	try {
		return { paths: await persistNestedPatches(artifactsDir, result.id, result.nestedPatches ?? []) };
	} catch (error) {
		return { paths: [], failure: error instanceof Error ? error.message : String(error) };
	}
}

/** Recovery hint appended to an isolated run's failure: every preserved artifact, and the nested-persist fallback failure when there is one. */
async function isolationRecoveryHint(result: SingleResult, artifactsDir: string): Promise<string> {
	const nested = await resolveNestedPatchPaths(result, artifactsDir);
	const hint = prompt.render(isolationRecoveryHintTemplate, {
		patchPath: result.patchPath,
		nestedPatchPaths: nested.paths,
		nestedFailure: nested.failure,
		branchName: result.branchName,
	});
	return hint ? ` ${hint}` : "";
}

/**
 * Summary for an isolated run whose changes are captured but deliberately not
 * applied (`task.isolation.apply=false`). Every captured artifact is named:
 * the root patch only when it holds changes, and each nested-repo patch file,
 * so the parent knows exactly where the work lives.
 */
function describeCapturedChanges(result: SingleResult): string {
	const nestedPatchPaths = result.nestedPatchPaths ?? [];
	return renderIsolationSummary({
		kind: "captured",
		branchName: result.branchName,
		rootPatchPath: result.hasRootChanges === false ? undefined : result.patchPath,
		nestedCount: nestedPatchPaths.length || (result.nestedPatches?.length ?? 0),
		nestedPatchPaths,
	});
}

function attachStructuredOutputMetadata(result: SingleResult, schema: StructuredSubagentSchemaResolution): void {
	if (schema.source === "none") {
		delete result.structuredOutput;
		return;
	}
	if (result.structuredOutput) return;
	// The executor attaches metadata for every payload it validated, so a
	// failed run reaching here never submitted one: the model stream died, the
	// run was cancelled, or the agent exited without yielding. That is not a
	// schema verdict — `result.output` is partial prose, not a payload — and
	// labelling it "invalid" reported provider errors as schema failures with
	// the half-streamed text as the offending data (production 2026-09-21).
	if (result.exitCode !== 0) {
		result.structuredOutput = {
			source: schema.source,
			mode: schema.mode,
			status: "unavailable",
			...(result.error ? { error: result.error } : {}),
		};
		return;
	}
	let fallbackData: unknown = result.output;
	try {
		fallbackData = JSON.parse(result.output);
	} catch {}
	result.structuredOutput = {
		source: schema.source,
		mode: schema.mode,
		status: "valid",
		data: fallbackData,
		...(result.error ? { error: result.error } : {}),
	};
}

/** Name a settled child's exit status and artifact for a post-settle failure message. */
function describeSalvagedWork(result: SingleResult): string {
	const hint = prompt.render(salvagedChildHintTemplate, {
		aborted: result.aborted,
		abortReason: result.abortReason,
		exitCode: result.exitCode,
		error: result.error,
		id: result.id,
		outputPath: result.outputPath,
	});
	return `\n${hint.trim()}`;
}

/**
 * Execute a validated subagent. Preflight errors occur before any artifact
 * lease or child dispatch; callers keep responsibility for their result text.
 */
export async function runStructuredSubagent(request: StructuredSubagentRequest): Promise<StructuredSubagentResult> {
	const policy = await applySpawnHook(request, await resolveEffectiveSubagentPolicy(request));
	const lease = await leaseArtifacts(request.session, request.invocationKind);
	let changesApplied: boolean | null = null;
	let mergeSummary = "";
	let requiresRecoveryArtifacts = false;
	let completedSuccessfully = false;
	let hasValidStructuredOutput = false;
	let deferredCleanup: Promise<void> | undefined;
	// Set once the child returns: every later step (structured-output
	// metadata, isolation merge, nested patch apply) can still throw, and the
	// failure must carry the exit status and artifact the child produced.
	let settled: SingleResult | undefined;
	let retainSalvagedArtifact = false;
	const onSubprocessResult =
		request.invocationKind === "eval"
			? (result: SingleResult) => request.session.recordEvalSubagentUsage?.(result.usage?.output ?? 0)
			: undefined;
	try {
		const id = await reserveStructuredSubagentId(request.session, {
			...request.identity,
			label: request.identity?.label ?? (request.invocationKind === "eval" ? "EvalAgent" : undefined),
		});
		await refreshSkillsForAutoload(request.session, policy.agent, request);
		const baseOptions = buildExecutorOptions(request, policy, lease, id);
		baseOptions.onCleanupDeferred = completion => {
			deferredCleanup = completion;
		};
		baseOptions.planReference = await loadPlanReference(request, policy);
		let isolationContext: IsolationContext | null = null;
		if (policy.isIsolated) {
			try {
				isolationContext = await prepareIsolationContext(request.session.cwd);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				throw new StructuredSubagentError(
					"isolation",
					`Isolated subagent execution could not be prepared: ${message}`,
					{ cause: error },
				);
			}
		}
		let result: SingleResult;
		if (!isolationContext) {
			result = await runSubprocess(baseOptions);
			onSubprocessResult?.(result);
		} else {
			result = await runIsolatedSubprocess({
				baseOptions,
				context: isolationContext,
				preferredBackend: parseIsolationBackend(cfgIsolationBackend.get(request.session.settings)),
				agentId: id,
				mergeMode: policy.mergeMode,
				artifactsDir: lease.artifactsDir,
				description: trimToUndefined(request.identity?.label),
				buildCommitMessage: makeIsolationCommitMessage(request.session),
				buildFailureResult: buildFailureResult(request, policy, id, Date.now()),
				onSubprocessResult,
			});
		}
		settled = result;
		attachStructuredOutputMetadata(result, policy.schema);
		hasValidStructuredOutput = result.structuredOutput?.status === "valid";
		requiresRecoveryArtifacts =
			policy.isIsolated &&
			(result.exitCode !== 0 || result.error !== undefined || result.aborted === true) &&
			(result.patchPath !== undefined || result.branchName !== undefined || (result.nestedPatches?.length ?? 0) > 0);

		if (
			policy.isIsolated &&
			isolationContext &&
			policy.applyChanges &&
			result.exitCode === 0 &&
			!result.error &&
			!result.aborted
		) {
			const outcome = await mergeIsolatedChanges({
				result,
				repoRoot: isolationContext.repoRoot,
				mergeMode: policy.mergeMode,
			});
			mergeSummary = outcome.summary;
			changesApplied = outcome.changesApplied;
			if (outcome.changesApplied !== false) {
				const nestedPatchSummary = await applyEligibleNestedPatches({
					result,
					repoRoot: isolationContext.repoRoot,
					mergeMode: policy.mergeMode,
					changesApplied: outcome.changesApplied,
					mergedBranchForNestedPatches: outcome.mergedBranchForNestedPatches,
					commitMessage: makeIsolationCommitMessage(request.session)(),
				});
				mergeSummary += nestedPatchSummary;
				requiresRecoveryArtifacts ||=
					nestedPatchSummary.includes("<system-notification>") && (result.nestedPatches?.length ?? 0) > 0;
			}
		} else if (policy.isIsolated && isolationContext && result.exitCode === 0 && result.error && !result.aborted) {
			// The agent finished but the runner could not capture, persist, or
			// commit its changes. `result.error` names the recovery route (retained
			// workspace, rescued branch); it is the parent's only way to find it.
			mergeSummary = renderIsolationSummary({
				kind: "capture-error",
				error: result.error,
				branchName: result.branchName,
				rootPatchPath: result.hasRootChanges === false ? undefined : result.patchPath,
				nestedPatchPaths: result.nestedPatchPaths ?? [],
			});
		} else if (policy.isIsolated && isolationContext && !policy.applyChanges) {
			mergeSummary = describeCapturedChanges(result);
		}

		completedSuccessfully = result.exitCode === 0 && !result.error && !result.aborted;
		return {
			result,
			policy,
			mergeSummary,
			changesApplied,
			artifactsDir: lease.artifactsDir,
			temporaryArtifacts: lease.temporary,
		};
	} catch (error) {
		if (error instanceof StructuredSubagentError) throw error;
		// The failure message points the parent at the artifact, so it must
		// survive the cleanup below.
		retainSalvagedArtifact = settled?.outputPath !== undefined;
		throw new StructuredSubagentError(
			"execution",
			`Subagent execution failed: ${error instanceof Error ? error.message : String(error)}${settled ? describeSalvagedWork(settled) : ""}`,
			{ cause: error, result: settled },
		);
	} finally {
		const shouldRetainArtifacts =
			request.detached === true ||
			retainSalvagedArtifact ||
			(request.retainArtifacts && (completedSuccessfully || hasValidStructuredOutput)) ||
			(policy.isIsolated && (!policy.applyChanges || changesApplied === false || requiresRecoveryArtifacts));
		const shouldCleanup = lease.temporary && !shouldRetainArtifacts;
		const cleanupArtifacts = async (): Promise<void> => {
			await fs.rm(lease.artifactsDir, { recursive: true, force: true });
			lease.unregister?.();
		};
		if (shouldCleanup) {
			if (deferredCleanup) {
				trackLateCleanup(deferredCleanup.then(cleanupArtifacts), {
					resource: "artifacts",
					artifactsDir: lease.artifactsDir,
				});
			} else {
				await cleanupArtifacts();
			}
		} else if (lease.temporary && request.onArtifactsRetained) {
			// Retained rather than cleaned up now: the caller (e.g. an async
			// job body) owns disposing it once the retained handle is no
			// longer needed, instead of it leaking for the process lifetime.
			request.onArtifactsRetained(cleanupArtifacts);
		}
	}
}

/** Build the recovery suffix used by adapters after an isolated failure. */
export async function buildStructuredSubagentRecoveryHint(result: SingleResult, artifactsDir: string): Promise<string> {
	return isolationRecoveryHint(result, artifactsDir);
}
