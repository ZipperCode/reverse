import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { Agent, type AgentTool, type BeforeToolCallContext } from "@reverse/agent";
import type { ToolResultMessage } from "@reverse/ai";
import { createMockModel } from "@reverse/ai/providers/mock";
import { AsyncJobManager } from "@reverse/coding-agent/async/job-manager";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { callSessionTool } from "@reverse/coding-agent/eval/js/tool-bridge";
import { InternalUrlRouter } from "@reverse/coding-agent/internal-urls";
import { resetRegisteredArtifactDirsForTests } from "@reverse/coding-agent/internal-urls/registry-helpers";
import { IrcBus } from "@reverse/coding-agent/irc/bus";
import { AgentRegistry } from "@reverse/coding-agent/registry/agent-registry";
import { AgentSession } from "@reverse/coding-agent/session/agent-session";
import { AuthStorage } from "@reverse/coding-agent/session/auth-storage";
import { convertToLlm } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import { ToolChoiceQueue } from "@reverse/coding-agent/session/tool-choice-queue";
import {
	detectExplicitTurnStopDeclaration,
	extractWaitPollGuardMeta,
	getWaitPollGuard,
	isPureShellNoopCommand,
} from "@reverse/coding-agent/session/wait-poll-guard";
import type { Tool, ToolSession } from "@reverse/coding-agent/tools";
import { BashTool } from "@reverse/coding-agent/tools/bash";
import { ReadTool } from "@reverse/coding-agent/tools/read";
import { WaitTool } from "@reverse/coding-agent/tools/wait";
import { WriteTool } from "@reverse/coding-agent/tools/write";
import { resolveXdevTool, type XdevState } from "@reverse/coding-agent/tools/xdev";
import { Shell } from "@reverse/natives";
import { type } from "@reverse/reversetype";
import { TempDir } from "@reverse/utils";

let tempDir: TempDir;
let rootSessionFile: string;
let artifactsDir: string;

function makeLiveAgentSession(
	messages: unknown[],
	options?: { isStreaming?: boolean; runStartedAt?: number },
): AgentSession {
	return {
		messages,
		isStreaming: options?.isStreaming ?? true,
		runStartedAt: options?.runStartedAt ?? 1000,
		sessionManager: { getArtifactsDir: () => artifactsDir },
	} as unknown as AgentSession;
}

function assistantText(text: string): unknown {
	return { role: "assistant", content: [{ type: "text", text }], timestamp: 1 };
}

function yieldSectionResult(type: string | string[] | undefined, data: unknown): unknown {
	return {
		role: "toolResult",
		toolCallId: `yield-${JSON.stringify(type)}-${JSON.stringify(data)}`,
		toolName: "yield",
		content: [{ type: "text", text: "Result submitted." }],
		details: { data, status: "success", type },
		isError: false,
		timestamp: 2,
	};
}

function makeToolSession(options: {
	manager?: AsyncJobManager;
	agentId?: string;
	branchEntries?: Array<{ id: string; type: string; message?: { role: string } }>;
	toolChoiceQueue?: ToolChoiceQueue;
}): ToolSession {
	const toolsByName = new Map<string, Tool>();
	const xdev: XdevState = {
		tools: toolsByName,
		mountedNames: new Set(["bash"]),
		builtInNames: new Set(["bash", "read", "wait", "write"]),
		isActive: () => true,
		resolve: name => resolveXdevTool(xdev, name),
	};
	const session: ToolSession = {
		cwd: tempDir.path(),
		hasUI: false,
		skills: [],
		agentRegistry: AgentRegistry.global(),
		asyncJobManager: options.manager,
		getAgentId: () => options.agentId ?? "Main",
		getSessionFile: () => rootSessionFile,
		getSessionSpawns: () => "*",
		getArtifactsDir: () => artifactsDir,
		allocateOutputArtifact: async toolType => ({
			id: `artifact-${toolType}`,
			path: path.join(artifactsDir, `artifact.${toolType}.log`),
		}),
		settings: Settings.isolated({
			"async.enabled": true,
			"bash.autoBackground.enabled": false,
			"bashInterceptor.enabled": false,
			"launch.enabled": false,
		}),
		getClientBridge: () => undefined,
		sessionManager: {
			appendCustomEntry: () => "custom-1",
			ensureOnDisk: async () => {},
			flush: async () => {},
			getBranch: () => (options.branchEntries ?? []) as never,
			getEntries: () => (options.branchEntries ?? []) as never,
			getLeafId: () => options.branchEntries?.at(-1)?.id ?? null,
			getSessionId: () => "session-main",
		},
		getToolChoiceQueue: () => options.toolChoiceQueue ?? new ToolChoiceQueue(),
		buildToolChoice: toolName => ({ type: "function", name: toolName }),
		isToolActive: () => true,
		xdev,
		getToolByName: name => toolsByName.get(name),
		getToolForEvalBridge: name => toolsByName.get(name),
	};
	toolsByName.set("bash", new BashTool(session) as unknown as Tool);
	toolsByName.set("read", new ReadTool(session) as unknown as Tool);
	toolsByName.set("wait", new WaitTool(session) as unknown as Tool);
	toolsByName.set("write", new WriteTool(session) as unknown as Tool);
	return session;
}

/**
 * `WaitPollGuard.beforeToolCall` only reads the assistant message, tool name,
 * tool-call id and args; the rest of the loop context is irrelevant here.
 */
function waitGuardContext(
	assistantMessage: unknown,
	toolCallId: string,
	toolName: string,
	args: Record<string, unknown>,
): BeforeToolCallContext {
	return {
		assistantMessage,
		toolCall: { type: "toolCall", id: toolCallId, name: toolName, arguments: args },
		tool: { name: toolName },
		args,
		context: { messages: [], tools: [] },
	} as unknown as BeforeToolCallContext;
}

describe("WaitPollGuard (#16)", () => {
	beforeEach(async () => {
		AgentRegistry.resetGlobalForTests();
		InternalUrlRouter.resetForTests();
		resetRegisteredArtifactDirsForTests();
		IrcBus.resetGlobalForTests();
		tempDir = TempDir.createSync("@reverse-wait-poll-guard-");
		rootSessionFile = path.join(tempDir.path(), "session.jsonl");
		artifactsDir = rootSessionFile.slice(0, -6);
		await fs.mkdir(artifactsDir, { recursive: true });
		AgentRegistry.global().register({
			id: "Main",
			displayName: "Main",
			kind: "main",
			session: makeLiveAgentSession([]),
			sessionFile: rootSessionFile,
			status: "running",
		});
	});

	afterEach(() => {
		InternalUrlRouter.resetForTests();
		AgentRegistry.resetGlobalForTests();
		resetRegisteredArtifactDirsForTests();
		IrcBus.resetGlobalForTests();
		tempDir.removeSync();
	});

	it("parses only exact bare shell no-ops (`true`, `:`, empty) and never matches compound commands", () => {
		expect(isPureShellNoopCommand("true")).toBe(true);
		expect(isPureShellNoopCommand("  true \t ")).toBe(true);
		expect(isPureShellNoopCommand(":")).toBe(true);
		expect(isPureShellNoopCommand("   ")).toBe(true);

		expect(isPureShellNoopCommand("cmd || true")).toBe(false);
		expect(isPureShellNoopCommand("false || :")).toBe(false);
		expect(isPureShellNoopCommand("true && echo ok")).toBe(false);
		expect(isPureShellNoopCommand("echo true")).toBe(false);
		expect(isPureShellNoopCommand("true --version")).toBe(false);
		expect(isPureShellNoopCommand("FOO=1 true")).toBe(false);
		expect(isPureShellNoopCommand("true > /dev/null")).toBe(false);
	});

	it("slow child with no output: allows max 1 progress read, spawns no `true` child, and real `wait` settles", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const slowChild = Promise.withResolvers<string>();
		const jobId = manager.register("task", "InterpreterDecode", () => slowChild.promise, {
			id: "InterpreterDecode",
			agentId: "InterpreterDecode",
			ownerId: "Main",
		});
		const childMessages: unknown[] = [];
		AgentRegistry.global().register({
			id: "InterpreterDecode",
			displayName: "InterpreterDecode",
			kind: "sub",
			parentId: "Main",
			session: makeLiveAgentSession(childMessages),
			sessionFile: path.join(artifactsDir, "InterpreterDecode.jsonl"),
			status: "running",
		});

		const queue = new ToolChoiceQueue();
		const session = makeToolSession({ manager, toolChoiceQueue: queue });
		const readTool = new ReadTool(session);
		const bashTool = new BashTool(session);
		const waitTool = new WaitTool(session);
		const guard = getWaitPollGuard(session);

		// 1. First progress read of running child with no output is allowed.
		const firstRead = await readTool.execute("read-1", { path: "agent://InterpreterDecode" });
		const firstText = firstRead.content.find(c => c.type === "text")?.text ?? "";
		expect(firstText).toContain("InterpreterDecode (running)");
		expect(extractWaitPollGuardMeta(firstRead.details)).toBeUndefined();
		expect(guard.unchangedAgentReadCount).toBe(0);

		// 2. Second progress read with unchanged state short-circuits with wait guidance.
		const secondRead = await readTool.execute("read-2", { path: "agent://InterpreterDecode" });
		const secondGuard = extractWaitPollGuardMeta(secondRead.details);
		expect(secondGuard).toMatchObject({
			intercepted: true,
			kind: "unchanged_agent_progress",
			targetAgentId: "InterpreterDecode",
			count: 1,
			unchangedAgentReadCount: 1,
		});

		// 3. Bare `bash true` (including service/async variants) never spawns a shell run while child is pending.
		const shellRunSpy = spyOn(Shell.prototype, "run");
		try {
			const noopPlain = await bashTool.execute("bash-noop-1", { command: "true" });
			expect(shellRunSpy).not.toHaveBeenCalled();
			expect(noopPlain.isError).toBeUndefined();
			expect(noopPlain.useless).toBe(true);
			expect(noopPlain.details?.unexecuted).toBe(true);
			expect(extractWaitPollGuardMeta(noopPlain.details)).toMatchObject({
				intercepted: true,
				kind: "noop_bash",
				command: "true",
				count: 2,
				preventedNoopBashCount: 1,
			});

			// Alternating read and bash no-op did not reset counter; threshold >= 2 queued forced `wait` choice.
			expect(queue.inspect()).toContain("wait-poll-guard");
			expect(queue.nextToolChoice()).toEqual({ type: "function", name: "wait" });
			queue.resolve();

			const noopAsync = await bashTool.execute("bash-noop-async", {
				command: "true",
				async: true,
				timeout: 0,
			});
			expect(shellRunSpy).not.toHaveBeenCalled();
			expect(noopAsync.details?.unexecuted).toBe(true);
			expect(manager.getRunningJobs({ ownerId: "Main" }).map(j => j.id)).toEqual(["InterpreterDecode"]);
		} finally {
			shellRunSpy.mockRestore();
		}

		// 4. Real `wait` blocks until the slow child job settles and returns its completion.
		const waiting = waitTool.execute("wait-real", {});
		slowChild.resolve("decoded 38 opcodes");
		const waitResult = await waiting;
		expect(waitResult.details?.jobs?.[0]).toMatchObject({
			id: jobId,
			status: "completed",
			resultText: "decoded 38 opcodes",
		});
	});

	it("allows re-reading agent://<id> when meaningful progress arrives, when generation finishes, or on a new user prompt", async () => {
		const childMessages: unknown[] = [];
		const branchEntries: Array<{ id: string; type: string; message?: { role: string } }> = [
			{ id: "u1", type: "message", message: { role: "user" } },
		];
		AgentRegistry.global().register({
			id: "Worker",
			displayName: "Worker",
			kind: "sub",
			parentId: "Main",
			session: makeLiveAgentSession(childMessages),
			sessionFile: path.join(artifactsDir, "Worker.jsonl"),
			status: "running",
		});

		const session = makeToolSession({ branchEntries });
		const readTool = new ReadTool(session);

		// Observation #1 (empty running progress) -> allowed
		const obs1 = await readTool.execute("r1", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(obs1.details)).toBeUndefined();

		// Duplicate observation -> intercepted
		const dup1 = await readTool.execute("r2", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(dup1.details)?.intercepted).toBe(true);

		// Meaningful progress #1: incremental yield section arrives -> readable once
		childMessages.push(yieldSectionResult(["section-1"], { step: "parsed header" }));
		const obs2 = await readTool.execute("r3", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(obs2.details)).toBeUndefined();
		expect(obs2.content.find(c => c.type === "text")?.text).toContain("parsed header");

		// Duplicate of section-1 state -> intercepted
		const dup2 = await readTool.execute("r4", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(dup2.details)?.intercepted).toBe(true);

		// Meaningful progress #2: assistant text updates -> readable once
		childMessages.push(assistantText("analyzing relocation table"));
		const obs3 = await readTool.execute("r5", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(obs3.details)).toBeUndefined();
		expect(obs3.content.find(c => c.type === "text")?.text).toContain("analyzing relocation table");

		// User sends a new prompt -> running progress can be rechecked once even without new child messages
		branchEntries.push({ id: "u2", type: "message", message: { role: "user" } });
		const obsAfterPrompt = await readTool.execute("r6", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(obsAfterPrompt.details)).toBeUndefined();

		// Finished generation publishes Worker.md -> always readable without restriction
		await Bun.write(path.join(artifactsDir, "Worker.md"), "# Final Worker Output\nDone.");
		AgentRegistry.global().setStatus("Worker", "idle");
		const final1 = await readTool.execute("r7", { path: "agent://Worker" });
		const final2 = await readTool.execute("r8", { path: "agent://Worker" });
		expect(extractWaitPollGuardMeta(final1.details)).toBeUndefined();
		expect(extractWaitPollGuardMeta(final2.details)).toBeUndefined();
		expect(final2.content.find(c => c.type === "text")?.text).toContain("Final Worker Output");
	});

	it("does not reset poll counter on alternating read/bash/ordinary file reads, and never blocks ordinary duplicate reads", async () => {
		const sampleFile = path.join(tempDir.path(), "notes.txt");
		await Bun.write(sampleFile, "line one\nline two\n");

		AgentRegistry.global().register({
			id: "SlowSub",
			displayName: "SlowSub",
			kind: "sub",
			parentId: "Main",
			session: makeLiveAgentSession([]),
			sessionFile: path.join(artifactsDir, "SlowSub.jsonl"),
			status: "running",
		});

		const session = makeToolSession({});
		const readTool = new ReadTool(session);
		const bashTool = new BashTool(session);
		const guard = getWaitPollGuard(session);

		// Initial progress read allowed
		await readTool.execute("init-read", { path: "agent://SlowSub" });
		expect(guard.consecutiveNoProgressPolls).toBe(0);

		// Poll #1: bash true
		await bashTool.execute("p1", { command: "true" });
		expect(guard.consecutiveNoProgressPolls).toBe(1);

		// Ordinary file read twice in a row -> both succeed and do NOT reset the wait-poll counter
		const fileRead1 = await readTool.execute("f1", { path: sampleFile });
		const fileRead2 = await readTool.execute("f2", { path: sampleFile });
		expect(fileRead1.content.find(c => c.type === "text")?.text).toContain("line one");
		expect(fileRead2.content.find(c => c.type === "text")?.text).toContain("line one");
		expect(guard.consecutiveNoProgressPolls).toBe(1);

		// Poll #2: unchanged read agent://SlowSub -> increments to 2
		const subPoll2 = await readTool.execute("p2", { path: "agent://SlowSub" });
		expect(extractWaitPollGuardMeta(subPoll2.details)?.count).toBe(2);
		expect(guard.consecutiveNoProgressPolls).toBe(2);

		// Poll #3: bash `:` -> increments to 3
		const bashPoll3 = await bashTool.execute("p3", { command: ":" });
		expect(extractWaitPollGuardMeta(bashPoll3.details)?.count).toBe(3);
		expect(guard.preventedNoopBashCount).toBe(2);
		expect(guard.unchangedAgentReadCount).toBe(1);
	});

	it("allows standalone `true` when no owned work is pending, allows `cmd || true` while pending, and never blocks another agent's jobs", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const sessionMain = makeToolSession({ manager, agentId: "Main" });
		const bashMain = new BashTool(sessionMain);

		// 1. No pending async work -> standalone `true` executes normally.
		const standaloneTrue = await bashMain.execute("standalone-true", { command: "true" });
		expect(standaloneTrue.details?.unexecuted).toBeUndefined();
		expect(getWaitPollGuard(sessionMain).preventedNoopBashCount).toBe(0);

		// 2. Register a running job owned by `Main`.
		const mainJob = Promise.withResolvers<string>();
		manager.register("bash", "main-bg", () => mainJob.promise, { ownerId: "Main" });

		// Compound command `false || true` on `Main` executes normally while `Main` has pending work.
		const compoundRes = await bashMain.execute("compound-true", { command: "printf 'compound-ok' || true" });
		expect(compoundRes.details?.unexecuted).toBeUndefined();
		expect(compoundRes.content.find(c => c.type === "text")?.text).toContain("compound-ok");

		// 3. Peer agent `Child` owns no jobs/subagents -> `Child` running `true` is never blocked by `Main`'s job.
		AgentRegistry.global().register({
			id: "Child",
			displayName: "Child",
			kind: "sub",
			parentId: "Main",
			session: makeLiveAgentSession([]),
			status: "running",
		});
		const sessionChild = makeToolSession({ manager, agentId: "Child" });
		const bashChild = new BashTool(sessionChild);
		const childTrue = await bashChild.execute("child-true", { command: "true" });
		expect(childTrue.details?.unexecuted).toBeUndefined();
		expect(getWaitPollGuard(sessionChild).preventedNoopBashCount).toBe(0);

		mainJob.resolve("done");
		await manager.waitForAll();
	});

	it("enforces the guard across `xd://bash` device writes and the `eval` tool bridge", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const pending = Promise.withResolvers<string>();
		manager.register("task", "BridgeSub", () => pending.promise, {
			id: "BridgeSub",
			agentId: "BridgeSub",
			ownerId: "Main",
		});
		AgentRegistry.global().register({
			id: "BridgeSub",
			displayName: "BridgeSub",
			kind: "sub",
			parentId: "Main",
			session: makeLiveAgentSession([]),
			sessionFile: path.join(artifactsDir, "BridgeSub.jsonl"),
			status: "running",
		});

		const session = makeToolSession({ manager, agentId: "Main" });
		const writeTool = session.getToolByName!("write") as AgentTool;
		const guard = getWaitPollGuard(session);

		// 1. Nested `write xd://bash` with `{"command":"true"}` is intercepted.
		const xdResult = await writeTool.execute("xd-bash-noop", {
			path: "xd://bash",
			content: JSON.stringify({ command: "true" }),
		});
		expect(xdResult.useless).toBe(true);
		expect(guard.preventedNoopBashCount).toBe(1);

		// 2. Eval bridge `callSessionTool("bash", { command: ":" })` is intercepted.
		const bridgedBash = await callSessionTool("bash", { command: ":" }, { session });
		const bridgedBashDetails =
			bridgedBash && typeof bridgedBash === "object" && "details" in bridgedBash ? bridgedBash.details : undefined;
		expect(
			bridgedBashDetails && typeof bridgedBashDetails === "object" && "unexecuted" in bridgedBashDetails
				? bridgedBashDetails.unexecuted
				: undefined,
		).toBe(true);
		expect(extractWaitPollGuardMeta(bridgedBashDetails)?.preventedNoopBashCount).toBe(2);

		// 3. Eval bridge `callSessionTool("read", { path: "agent://BridgeSub" })`: 1st allowed, 2nd intercepted.
		const bridgedRead1 = await callSessionTool("read", { path: "agent://BridgeSub" }, { session });
		const bridgedRead1Details =
			bridgedRead1 && typeof bridgedRead1 === "object" && "details" in bridgedRead1
				? bridgedRead1.details
				: undefined;
		expect(extractWaitPollGuardMeta(bridgedRead1Details)).toBeUndefined();

		const bridgedRead2 = await callSessionTool("read", { path: "agent://BridgeSub" }, { session });
		const bridgedRead2Details =
			bridgedRead2 && typeof bridgedRead2 === "object" && "details" in bridgedRead2
				? bridgedRead2.details
				: undefined;
		expect(extractWaitPollGuardMeta(bridgedRead2Details)?.intercepted).toBe(true);
		expect(guard.unchangedAgentReadCount).toBe(1);

		pending.resolve("done");
		await manager.waitForAll();
	});

	it("detects only explicit current-assistant stop declarations, rejecting quoted, code, negated, conditional and historical copies", () => {
		const stopWithStop = "We must stop. End reply with no tool call. I'll do that.";
		const stopWithEnd = "I must end reply without tool call. Let's do that.";

		expect(
			detectExplicitTurnStopDeclaration({
				role: "assistant",
				content: [{ type: "thinking", thinking: stopWithStop }],
			}),
		).toEqual({ sentence: "We must stop", directive: "End reply with no tool call" });
		expect(
			detectExplicitTurnStopDeclaration({
				role: "assistant",
				content: [{ type: "text", text: stopWithEnd }],
			}),
		).toEqual({
			sentence: "I must end reply without tool call",
			directive: "I must end reply without tool call",
		});
		expect(
			detectExplicitTurnStopDeclaration({
				role: "assistant",
				content: [{ type: "text", text: "我必须结束回复，不带工具调用。" }],
			}),
		).toMatchObject({ sentence: expect.stringContaining("结束回复") });

		const rejected = [
			// 引号、行内代码与引用块中的同文属于引用/展示，不是本轮声明。
			`The report says "${stopWithStop}" but the child is still running.`,
			`\`${stopWithStop}\``,
			`> ${stopWithStop}`,
			// 历史转述框架之后的内容同样是引用。
			`Earlier I wrote: ${stopWithStop}`,
			"The issue text quoted: We must stop. End reply with no tool call. I'll do that.",
			// 否定、条件与单纯的“不要轮询”都不算结束声明。
			"We must not stop. End reply with no tool call.",
			"If we must stop, end the reply without tool calls.",
			"I should not poll for the child.",
		];
		for (const thinking of rejected) {
			expect(
				detectExplicitTurnStopDeclaration({ role: "assistant", content: [{ type: "thinking", thinking }] }),
			).toBeUndefined();
		}
		// 用户消息或其它角色即使逐字包含原句也不会终止回合。
		expect(
			detectExplicitTurnStopDeclaration({ role: "user", content: [{ type: "text", text: stopWithStop }] }),
		).toBeUndefined();
		expect(
			detectExplicitTurnStopDeclaration({
				role: "assistant",
				content: [{ type: "text", text: "Done." }],
			}),
		).toBeUndefined();
	});

	it("declares the whole batch stopped for owned pending work while leaving legitimate concurrent work alone", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const gate = Promise.withResolvers<string>();
		manager.register("task", "OwnedChild", async () => await gate.promise, { id: "OwnedChild", ownerId: "Main" });
		const session = makeToolSession({ manager, agentId: "Main" });
		const guard = getWaitPollGuard(session);

		// 普通等待措辞不构成结束声明：write/todo 与 wait 同批照常放行。
		const normalMessage = {
			role: "assistant",
			content: [{ type: "text", text: "I'll write the results and then wait for OwnedChild." }],
		};
		expect(
			await guard.beforeToolCall(
				waitGuardContext(normalMessage, "write-ok", "write", { path: "ok.txt", content: "hi" }),
			),
		).toBeUndefined();
		expect(await guard.beforeToolCall(waitGuardContext(normalMessage, "wait-ok", "wait", {}))).toBeUndefined();

		const assistantMessage = {
			role: "assistant",
			content: [
				{ type: "thinking", thinking: "We must stop. End reply with no tool call. I'll do that." },
				{ type: "toolCall", id: "bash-stop", name: "bash", arguments: { command: "printf blocked" } },
				{ type: "toolCall", id: "read-stop", name: "read", arguments: { path: "agent://OwnedChild" } },
			],
		};
		const bashContext = waitGuardContext(assistantMessage, "bash-stop", "bash", { command: "printf blocked" });
		const readContext = waitGuardContext(assistantMessage, "read-stop", "read", { path: "agent://OwnedChild" });
		const bashBlock = await guard.beforeToolCall(bashContext);
		expect(bashBlock).toMatchObject({ block: true, stopTurn: true });
		expect(await guard.beforeToolCall(readContext)).toMatchObject({ block: true, stopTurn: true });

		// 每个被整批停下的调用都由后置钩子归一化为非错误、未执行的结果。
		const normalized = guard.afterToolCall({
			...bashContext,
			result: { content: [{ type: "text", text: bashBlock?.reason ?? "" }], details: {} },
			isError: true,
		});
		expect(normalized).toMatchObject({ isError: false, useless: true });
		expect(normalized?.details).toMatchObject({
			unexecuted: true,
			waitPollGuard: { intercepted: true, kind: "turn_stop_declared" },
		});

		gate.resolve("done");
		await manager.waitForAll();
	});

	it("does not declare a stop without owned pending work or for another agent's job", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const gate = Promise.withResolvers<string>();
		manager.register("task", "OtherChild", async () => await gate.promise, { id: "OtherChild", ownerId: "Child" });
		const session = makeToolSession({ manager, agentId: "Main" });
		const guard = getWaitPollGuard(session);
		const message = {
			role: "assistant",
			content: [{ type: "thinking", thinking: "We must stop. End reply with no tool call. I'll do that." }],
		};
		expect(
			await guard.beforeToolCall(
				waitGuardContext(message, "write-other", "write", { path: "x.txt", content: "hi" }),
			),
		).toBeUndefined();

		// 没有任何自有异步工作时，同一句声明也不构成停条件（普通 true 仍合法）。
		const idleGuard = getWaitPollGuard(makeToolSession({ agentId: "Main" }));
		expect(
			await idleGuard.beforeToolCall(waitGuardContext(message, "true-idle", "bash", { command: "true" })),
		).toBeUndefined();

		gate.resolve("done");
		await manager.waitForAll();
	});

	it("historical stop declarations leave the real loop batch unexecuted while an owned job is pending", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const jobGate = Promise.withResolvers<string>();
		manager.register("task", "InterpreterDecode", async () => await jobGate.promise, {
			id: "InterpreterDecode",
			ownerId: "Main",
		});
		const authStorage = await AuthStorage.create(path.join(tempDir.path(), "auth.db"));
		// Prompt admission resolves the key through ModelRegistry, not Agent's
		// getApiKey, so the mock provider needs a runtime key here.
		authStorage.keys.setRuntime("openai", "openai-test-key");
		const sessions: AgentSession[] = [];
		try {
			const runScenario = async (phrase: string) => {
				const markerPath = path.join(tempDir.path(), `forbidden-${sessions.length}.txt`);
				const toolSession = makeToolSession({ manager, agentId: "Main" });
				const writeSchema = type({ path: "string", content: "string" });
				const writeTool: AgentTool<typeof writeSchema> = {
					name: "write",
					label: "Write",
					description: "Test-only write tool",
					parameters: writeSchema,
					async execute(_toolCallId, args) {
						await Bun.write(path.join(tempDir.path(), args.path), args.content);
						return { content: [{ type: "text" as const, text: "written" }], details: {} };
					},
				};
				const tools = [new BashTool(toolSession), new ReadTool(toolSession), writeTool] as unknown as AgentTool[];
				const mock = createMockModel({
					provider: "openai",
					id: "gpt-test",
					responses: [
						{
							content: [
								{ type: "thinking", thinking: phrase },
								{
									type: "toolCall",
									id: `stop-bash-${sessions.length}`,
									name: "bash",
									arguments: { command: `printf blocked > ${markerPath}` },
								},
								{
									type: "toolCall",
									id: `stop-read-${sessions.length}`,
									name: "read",
									arguments: { path: "agent://InterpreterDecode" },
								},
							],
						},
						{
							content: [
								{
									type: "toolCall",
									id: "legit-write",
									name: "write",
									arguments: { path: "next.txt", content: "ok" },
								},
							],
						},
						{ content: ["Next turn answered."] },
					],
					handler: { content: ["Unexpected extra model call"] },
				});
				const settings = Settings.isolated({
					"compaction.enabled": false,
					"retry.enabled": false,
					"todo.enabled": false,
					"todo.reminders": false,
				});
				settings.setModelRole("default", `${mock.model.provider}/${mock.model.id}`);
				const agent = new Agent({
					getApiKey: () => "test-key",
					initialState: { model: mock.model, systemPrompt: ["Test"], tools, messages: [] },
					convertToLlm,
					streamFn: mock.stream,
				});
				const session = new AgentSession({
					agent,
					sessionManager: SessionManager.create(tempDir.path(), path.join(tempDir.path(), "sessions")),
					settings,
					modelRegistry: new ModelRegistry(authStorage),
					toolRegistry: new Map(tools.map(tool => [tool.name, tool] as [string, AgentTool])),
					agentId: "Main",
					asyncJobManager: manager,
				});
				sessions.push(session);
				const starts: string[] = [];
				session.subscribe(event => {
					if (event.type === "tool_execution_start") starts.push(event.toolName);
				});

				await session.prompt("Wait for InterpreterDecode");
				await session.waitForIdle();
				await session.sessionManager.flush();
				const sessionFile = session.sessionManager.getSessionFile();
				if (!sessionFile) throw new Error("Expected a persisted session file");
				// 原始 JSONL 消费口径：自定义记录 `tool_execution_start` 必须为零。
				const journalStartEntries = (await Bun.file(sessionFile).text())
					.split("\n")
					.filter(line => line.trim().length > 0)
					.filter(line => {
						const entry: unknown = JSON.parse(line);
						return (
							typeof entry === "object" &&
							entry !== null &&
							"customType" in entry &&
							entry.customType === "tool_execution_start"
						);
					});
				const toolResults = session.messages.filter(
					(message): message is ToolResultMessage => message.role === "toolResult",
				);
				return { mock, session, starts, journalStartEntries, toolResults, markerPath };
			};

			for (const phrase of [
				"We must stop. End reply with no tool call. I'll do that.",
				"I must end reply without tool call. Let's do that.",
			]) {
				const { mock, session, starts, journalStartEntries, toolResults, markerPath } = await runScenario(phrase);
				// 停条件真的让出回合：没有第二次 provider 请求。
				expect(mock.calls).toHaveLength(1);
				// 原始执行起点为零（事件流与落盘 journal 双口径）：bash 未派生、read 未读取。
				expect(starts).toEqual([]);
				expect(journalStartEntries).toEqual([]);
				expect(await Bun.file(markerPath).exists()).toBe(false);
				// 历史仍成对保留，且全部归一化为未执行的合成结果。
				expect(toolResults).toHaveLength(2);
				for (const result of toolResults) {
					expect(result.isError).toBe(false);
					expect(result.useless).toBe(true);
					expect(result.details).toMatchObject({
						unexecuted: true,
						waitPollGuard: { intercepted: true, kind: "turn_stop_declared" },
					});
				}
				// 下一次用户提问正常解除等待；同批合法的 write 在自有任务仍在运行时照常执行。
				await session.prompt("Next request");
				await session.waitForIdle();
				expect(mock.calls).toHaveLength(3);
				expect(starts).toEqual(["write"]);
				expect(await Bun.file(path.join(tempDir.path(), "next.txt")).text()).toBe("ok");
			}
		} finally {
			for (const session of sessions) await session.dispose();
			jobGate.resolve("released");
			await manager.waitForAll();
			authStorage.close();
		}
	});

	it("a sole wait in the real loop starts once and receives the actual child result", async () => {
		const manager = new AsyncJobManager({ onJobComplete: () => {} });
		const jobGate = Promise.withResolvers<string>();
		const jobId = manager.register("task", "SlowChild", async () => await jobGate.promise, {
			id: "SlowChild",
			ownerId: "Main",
		});
		// The wait snapshot is the consumer of this child's result: suppressing its
		// separate async delivery keeps the wait un-interrupted, so the result it
		// returns is the job's own completion rather than a queued notice.
		manager.acknowledgeDeliveries([jobId]);
		const authStorage = await AuthStorage.create(path.join(tempDir.path(), "auth.db"));
		authStorage.keys.setRuntime("openai", "openai-test-key");
		let session: AgentSession | undefined;
		try {
			const toolSession = makeToolSession({ manager, agentId: "Main" });
			const waitTool = new WaitTool(toolSession);
			const mock = createMockModel({
				provider: "openai",
				id: "gpt-test",
				responses: [
					{ content: [{ type: "toolCall", id: "wait-only", name: "wait", arguments: {} }] },
					{ content: ["Settled."] },
				],
				handler: { content: ["Settled."] },
			});
			const settings = Settings.isolated({
				"compaction.enabled": false,
				"retry.enabled": false,
				"todo.enabled": false,
				"launch.enabled": false,
			});
			settings.setModelRole("default", `${mock.model.provider}/${mock.model.id}`);
			const tools = [waitTool] as unknown as AgentTool[];
			const agent = new Agent({
				getApiKey: () => "test-key",
				initialState: { model: mock.model, systemPrompt: ["Test"], tools, messages: [] },
				convertToLlm,
				streamFn: mock.stream,
			});
			session = new AgentSession({
				agent,
				sessionManager: SessionManager.inMemory(tempDir.path()),
				settings,
				modelRegistry: new ModelRegistry(authStorage),
				toolRegistry: new Map([[waitTool.name, waitTool as unknown as AgentTool]]),
				agentId: "Main",
				asyncJobManager: manager,
			});
			const starts: string[] = [];
			const waitResults: unknown[] = [];
			session.subscribe(event => {
				if (event.type !== "tool_execution_start" && event.type !== "tool_execution_end") return;
				if (event.toolName !== "wait") return;
				if (event.type === "tool_execution_start") {
					starts.push(event.toolName);
					// 让真实子任务在 wait 阻塞期间结束，验证它收到实际结果。
					jobGate.resolve("decoded 38 opcodes");
				} else {
					waitResults.push(event.result.details);
				}
			});

			await session.prompt("Wait for SlowChild");
			await session.waitForIdle();
			expect(starts).toEqual(["wait"]);
			expect(mock.calls).toHaveLength(2);
			expect(waitResults).toHaveLength(1);
			expect(waitResults[0]).toMatchObject({
				jobs: [{ id: "SlowChild", status: "completed", resultText: "decoded 38 opcodes" }],
			});
		} finally {
			jobGate.resolve("released");
			await manager.waitForAll();
			await session?.dispose();
			authStorage.close();
		}
	});
});
