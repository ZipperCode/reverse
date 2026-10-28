import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import type { AgentToolContext } from "@reverse/agent";
import type { Context, ToolResultMessage } from "@reverse/ai";
import { createMockModel, type MockModel, type MockResponse } from "@reverse/ai/providers/mock";
import { ModelRegistry } from "@reverse/coding-agent/config/model-registry";
import { Settings } from "@reverse/coding-agent/config/settings";
import { callSessionTool } from "@reverse/coding-agent/eval/js/tool-bridge";
import type { ExtensionFactory } from "@reverse/coding-agent/extensibility/extensions";
import { AgentLifecycleManager } from "@reverse/coding-agent/registry/agent-lifecycle";
import { AgentRegistry } from "@reverse/coding-agent/registry/agent-registry";
import { createAgentSession } from "@reverse/coding-agent/sdk";
import type { AgentSession } from "@reverse/coding-agent/session/agent-session";
import type { CustomMessage } from "@reverse/coding-agent/session/messages";
import { SessionManager } from "@reverse/coding-agent/session/session-manager";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { type } from "@reverse/reversetype";
import { TempDir } from "@reverse/utils";
import { createInMemoryAuthStorage } from "./helpers/agent-session-setup";

/** The semantic precondition every ordinary spawn carrying a reserved `model` fails. */
const reservedModelFailure = { code: "task.seance", key: "task.seance:reserved-model" };

/**
 * `task.batch` with speculative launch off keeps these calls flat and rejects
 * them during local planning, so neither route can start a child.
 */
const baseSettings: Readonly<Record<string, unknown>> = {
	"compaction.enabled": false,
	"retry.enabled": false,
	"todo.enabled": false,
	"todo.reminders": false,
	"async.enabled": false,
	"tools.xdev": true,
	"model.toolCallLoopGuard.enabled": true,
	"model.toolCallLoopGuard.threshold": 5,
	"model.toolCallLoopGuard.exemptTools": ["wait"],
	"task.batch": true,
	"task.speculativeLaunch": false,
	"task.isolation.enabled": false,
};

interface SessionHarness {
	session: AgentSession;
	root: TempDir;
	registry: ModelRegistry;
	model: MockModel;
	requests: Context[];
	starts: Array<{ toolCallId: string; toolName: string }>;
}

interface HarnessOptions {
	turns: MockResponse[];
	toolNames: string[];
	extensions?: ExtensionFactory[];
}

const sessions: AgentSession[] = [];
const registries: ModelRegistry[] = [];
const roots: TempDir[] = [];

beforeEach(() => {
	AgentRegistry.resetGlobalForTests();
	AgentLifecycleManager.resetGlobalForTests();
});

afterEach(async () => {
	for (const session of sessions.splice(0)) {
		await Promise.all(session.asyncJobManager?.getAllJobs().map(job => job.promise) ?? []);
		await session.dispose();
	}
	for (const registry of registries.splice(0)) registry.authStorage.close();
	for (const root of roots.splice(0)) root.removeSync();
	AgentLifecycleManager.resetGlobalForTests();
	AgentRegistry.resetGlobalForTests();
});

function recordOf(value: unknown): Record<string, unknown> | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	// Narrowed above: object-like records are the only detail containers these tests read.
	return value as Record<string, unknown>;
}

function textOf(message: Pick<ToolResultMessage, "content">): string {
	return message.content
		.filter(part => part.type === "text")
		.map(part => part.text)
		.join("");
}

function dispatchFailureFrom(details: unknown): { code: string; key: string } | undefined {
	const failure = recordOf(recordOf(details)?.dispatchFailure);
	const code = failure?.code;
	const key = failure?.key;
	return typeof code === "string" && typeof key === "string" ? { code, key } : undefined;
}

function toolResultsOf(session: AgentSession): ToolResultMessage[] {
	return session.agent.state.messages.filter((message): message is ToolResultMessage => message.role === "toolResult");
}

function redirectsOf(session: AgentSession): CustomMessage[] {
	return session.agent.state.messages.filter(
		(message): message is CustomMessage =>
			message.role === "custom" && message.customType === "tool-call-loop-dispatch-failure",
	);
}

/** `write xd://<tool>` wraps the dispatched tool's own details under `details.xdev.inner`. */
function xdevInnerOf(result: ToolResultMessage): Record<string, unknown> | undefined {
	return recordOf(recordOf(recordOf(result.details)?.xdev)?.inner);
}

/** The eval runtime serializes a bridge value into its output text, never into its own details. */
function bridgeValueOf(result: ToolResultMessage): Record<string, unknown> {
	return JSON.parse(textOf(result)) as Record<string, unknown>;
}

/** Ids of spawned child sessions; a local rejection or a blocked bridge never registers one. */
function childAgentIds(): string[] {
	return AgentRegistry.global()
		.list()
		.filter(ref => ref.kind === "sub")
		.map(ref => ref.id);
}

function startsOf(harness: SessionHarness, toolName: string): Array<{ toolCallId: string; toolName: string }> {
	return harness.starts.filter(start => start.toolName === toolName);
}

function activeJobs(harness: SessionHarness): number {
	return harness.session.asyncJobManager?.getAllJobs().length ?? 0;
}

/**
 * A flat ordinary spawn that carries the reserved `model` selector. `name`,
 * `task`, and `context` change per attempt; the semantic defect does not.
 */
function reservedModelArgs(prefix: string, index: number): Record<string, unknown> {
	return {
		name: `${prefix}_${index}`,
		agent: "scout",
		task: `Investigate reworded variant ${index}.`,
		context: `Shared background for attempt ${index}.`,
		model: "forbidden",
	};
}

function xdTaskWriteTurn(index: number): MockResponse {
	return {
		content: [
			{
				type: "toolCall",
				id: `xd-${index}`,
				name: "write",
				arguments: { path: "xd://task", content: JSON.stringify(reservedModelArgs("xd_probe", index)) },
			},
		],
		stopReason: "toolUse",
	};
}

function bridgeProbeTurn(index: number): MockResponse {
	return {
		content: [
			{
				type: "toolCall",
				id: `probe-${index}`,
				name: "bridge_probe",
				arguments: reservedModelArgs("bridge_probe", index),
			},
		],
		stopReason: "toolUse",
	};
}

async function createHarness(options: HarnessOptions): Promise<SessionHarness> {
	const root = TempDir.createSync("@pi-task-dispatch-bridges-");
	roots.push(root);
	const auth = createInMemoryAuthStorage();
	auth.keys.setRuntime("mock", "test-key");
	const registry = new ModelRegistry(auth);
	registries.push(registry);
	const model = createMockModel({ responses: options.turns });
	const settings = Settings.isolated(baseSettings);
	settings.setModelRole("default", `${model.provider}/${model.id}`);
	const { session } = await createAgentSession({
		cwd: root.path(),
		agentDir: root.path(),
		modelRegistry: registry,
		model,
		sessionManager: SessionManager.inMemory(root.path()),
		settings,
		disableExtensionDiscovery: true,
		skills: [],
		contextFiles: [],
		promptTemplates: [],
		slashCommands: [],
		enableMCP: false,
		enableLsp: false,
		skipPythonPreflight: true,
		toolNames: options.toolNames,
		...(options.extensions === undefined ? {} : { extensions: options.extensions }),
	});
	sessions.push(session);
	const requests: Context[] = [];
	session.agent.streamFn = (activeModel, context, streamOptions) => {
		requests.push(context);
		return model.stream(activeModel, context, streamOptions);
	};
	const starts: Array<{ toolCallId: string; toolName: string }> = [];
	session.subscribe(event => {
		if (event.type === "tool_execution_start") {
			starts.push({ toolCallId: event.toolCallId, toolName: event.toolName });
		}
	});
	return { session, root, registry, model, requests, starts };
}

async function promptSession(session: AgentSession, text: string): Promise<void> {
	await session.prompt(text);
	await session.waitForIdle();
}

interface BridgeProbeHolder {
	session: ToolSession | undefined;
}

/** Two-call batch whose second call an extension repairs on one chosen round. */
function batchProbeTurn(round: number): MockResponse {
	return {
		content: [
			{
				type: "toolCall",
				id: `r${round}-first`,
				name: "batch_probe",
				arguments: { slot: "first", value: "original" },
			},
			{
				type: "toolCall",
				id: `r${round}-second`,
				name: "batch_probe",
				arguments: { slot: "second", value: "original" },
			},
		],
		stopReason: "toolUse",
	};
}

interface BatchProbeHolder {
	/** Raw `tool_call` inputs the extension handler observed, before its revision. */
	events: Array<{ toolCallId: string; value: string }>;
	/** Arguments the tool actually executed with. */
	runs: Array<{ toolCallId: string; slot: string; value: string }>;
}

/**
 * Real SDK extension: a recording tool plus a `tool_call` handler that repairs
 * only the sixth round's second call. A hard stop decided before that repair is
 * known would block the batch even though its final arguments changed.
 */
function batchProbeExtension(holder: BatchProbeHolder): ExtensionFactory {
	const parameters = type({ slot: "string", value: "string" });
	return pi => {
		pi.registerTool({
			name: "batch_probe",
			label: "Batch probe",
			description: "Records the arguments it actually executes with.",
			loadMode: "essential",
			parameters,
			async execute(toolCallId, params) {
				const input = parameters.assert(params);
				holder.runs.push({ toolCallId, slot: input.slot, value: input.value });
				return {
					content: [{ type: "text" as const, text: `${input.slot}:${input.value}` }],
					details: { slot: input.slot, value: input.value },
				};
			},
		});
		pi.on("tool_call", event => {
			if (event.toolName !== "batch_probe") return;
			holder.events.push({
				toolCallId: event.toolCallId,
				value: typeof event.input.value === "string" ? event.input.value : "",
			});
			if (event.toolCallId !== "r6-second") return;
			return { input: { ...event.input, value: "repaired" } };
		});
	};
}

/** Tool-call arguments persisted on the assistant turn that issued `toolCallId`. */
function assistantToolArgsOf(session: AgentSession, toolCallId: string): Record<string, unknown> | undefined {
	for (const message of session.agent.state.messages) {
		if (message.role !== "assistant") continue;
		for (const part of message.content) {
			if (part.type === "toolCall" && part.id === toolCallId) return recordOf(part.arguments);
		}
	}
	return undefined;
}

/**
 * Host stand-in for the eval tool: each execution forwards one `task(...)` call
 * through the real `callSessionTool` bridge and returns the serialized bridge
 * value the way the eval runtime does — as output text with a success status.
 */
function bridgeProbeExtension(holder: BridgeProbeHolder): ExtensionFactory {
	return pi => {
		pi.registerTool({
			name: "bridge_probe",
			label: "Bridge probe",
			description: "Runs one eval-style bridged `task` call and returns its serialized value.",
			loadMode: "essential",
			parameters: type({
				name: "string",
				agent: "string",
				task: "string",
				context: "string",
				model: "string",
			}),
			async execute(_toolCallId, params) {
				const bridgeSession = holder.session;
				if (!bridgeSession) throw new Error("bridge fixture is not ready");
				const value = await callSessionTool("task", params, { session: bridgeSession });
				return { content: [{ type: "text" as const, text: JSON.stringify(value) }], details: {} };
			},
		});
	};
}

describe("TaskTool dispatch failures through real bridges", () => {
	it("blocks the sixth write xd://task dispatch without another model request", async () => {
		const harness = await createHarness({
			toolNames: ["task", "write"],
			turns: [
				...Array.from({ length: 6 }, (_unused, index) => xdTaskWriteTurn(index)),
				xdTaskWriteTurn(6),
				{ content: [{ type: "text", text: "done" }], stopReason: "stop" },
			],
		});

		await promptSession(harness.session, "delegate the investigation");

		// Six announced turns reach the device; the sixth dispatch is blocked
		// inside the write call, so the run stops before a seventh provider request.
		expect(harness.requests).toHaveLength(6);
		expect(startsOf(harness, "write")).toHaveLength(6);
		expect(startsOf(harness, "write").some(start => start.toolCallId === "xd-5")).toBe(true);
		expect(startsOf(harness, "task")).toHaveLength(0);

		const writes = toolResultsOf(harness.session).filter(result => result.toolName === "write");
		expect(writes).toHaveLength(6);
		const failed = writes.filter(result => result.toolCallId !== "xd-5");
		expect(failed).toHaveLength(5);
		for (const result of failed) {
			// The authoritative metadata is the wrapped tool's own, under xdev.inner.
			const inner = xdevInnerOf(result);
			expect(inner).toBeDefined();
			expect(dispatchFailureFrom(inner)).toEqual(reservedModelFailure);
			expect(inner?.executed).toBe(false);
			expect(inner?.unexecuted).toBe(true);
			expect(inner?.results).toEqual([]);
			expect(inner?.projectAgentsDir).toBeNull();
			expect(inner?.toolCallLoopGuard).toBeUndefined();
			expect(result.isError).toBe(true);
		}

		const blocked = writes.find(result => result.toolCallId === "xd-5");
		expect(blocked).toBeDefined();
		const blockedInner = xdevInnerOf(blocked!);
		expect(blockedInner?.unexecuted).toBe(true);
		expect(blockedInner?.executed).toBe(false);
		expect(recordOf(blockedInner?.toolCallLoopGuard)?.blocked).toBe(true);
		expect(recordOf(blockedInner)?.dispatchFailure).toBeUndefined();
		expect(blocked!.isError).toBe(true);

		expect(redirectsOf(harness.session)).toHaveLength(1);
		expect(childAgentIds()).toHaveLength(0);
		expect(activeJobs(harness)).toBe(0);

		// A new user prompt is a boundary: the same defect may dispatch again
		// instead of being blocked by the previous prompt's history.
		await promptSession(harness.session, "retry the delegation");

		expect(harness.requests).toHaveLength(8);
		expect(startsOf(harness, "write")).toHaveLength(7);
		expect(startsOf(harness, "task")).toHaveLength(0);

		const writesAfter = toolResultsOf(harness.session).filter(result => result.toolName === "write");
		expect(writesAfter).toHaveLength(7);
		const repeated = writesAfter.find(result => result.toolCallId === "xd-6");
		expect(repeated).toBeDefined();
		const repeatedInner = xdevInnerOf(repeated!);
		expect(dispatchFailureFrom(repeatedInner)).toEqual(reservedModelFailure);
		expect(repeatedInner?.toolCallLoopGuard).toBeUndefined();
		expect(repeatedInner?.executed).toBe(false);
		expect(repeatedInner?.unexecuted).toBe(true);
		expect(redirectsOf(harness.session)).toHaveLength(1);
		expect(childAgentIds()).toHaveLength(0);
		expect(activeJobs(harness)).toBe(0);
	});

	it("blocks an ownerless eval-bridge dispatch and stops after the result is recorded", async () => {
		const holder: BridgeProbeHolder = { session: undefined };
		const harness = await createHarness({
			toolNames: ["task"],
			extensions: [bridgeProbeExtension(holder)],
			turns: [
				...Array.from({ length: 6 }, (_unused, index) => bridgeProbeTurn(index)),
				bridgeProbeTurn(6),
				{ content: [{ type: "text", text: "done" }], stopReason: "stop" },
			],
		});
		// Same wrapper the eval bridge resolves at runtime; its calls carry no outer
		// tool context, so the host must stop at the turn boundary instead of aborting
		// the enclosing (ownerless) call.
		const wrappedTask = harness.session.getToolByName("task");
		if (!wrappedTask) throw new Error("task tool missing from the SDK registry");
		holder.session = {
			getToolForEvalBridge: (name: string) => (name === "task" ? wrappedTask : undefined),
			getToolContext: () => ({ settings: harness.session.settings }) as unknown as AgentToolContext,
		} as unknown as ToolSession;

		await promptSession(harness.session, "delegate through the bridge");

		// Five bridge failures warn; the sixth is blocked before the inner task runs,
		// and the turn-boundary gate stops the run before a seventh provider request.
		expect(harness.requests).toHaveLength(6);
		expect(startsOf(harness, "bridge_probe")).toHaveLength(6);
		expect(startsOf(harness, "task")).toHaveLength(0);

		const probes = toolResultsOf(harness.session).filter(result => result.toolName === "bridge_probe");
		expect(probes).toHaveLength(6);
		const failed = probes.filter(result => result.toolCallId !== "probe-5");
		expect(failed).toHaveLength(5);
		for (const result of failed) {
			// The eval turn itself succeeds; only the bridge value reports the failure.
			expect(result.isError).not.toBe(true);
			const value = bridgeValueOf(result);
			expect(value.hasError).toBe(true);
			const details = recordOf(value.details);
			expect(dispatchFailureFrom(details)).toEqual(reservedModelFailure);
			expect(details?.executed).toBe(false);
			expect(details?.unexecuted).toBe(true);
			expect(details?.results).toEqual([]);
			expect(details?.projectAgentsDir).toBeNull();
			// A success-shaped outer result must not carry the inner dispatch failure.
			expect(recordOf(result.details)?.dispatchFailure).toBeUndefined();
		}

		const blocked = probes.find(result => result.toolCallId === "probe-5");
		expect(blocked).toBeDefined();
		// The blocked metadata survives: the ownerless call is never aborted mid-flight,
		// so the loop has no synthetic "aborted" result to substitute.
		expect(blocked!.isError).not.toBe(true);
		const blockedValue = bridgeValueOf(blocked!);
		expect(blockedValue.hasError).toBe(true);
		const blockedDetails = recordOf(blockedValue.details);
		expect(blockedDetails?.unexecuted).toBe(true);
		expect(blockedDetails?.executed).toBe(false);
		expect(recordOf(blockedDetails?.toolCallLoopGuard)?.blocked).toBe(true);
		expect(recordOf(blockedDetails)?.dispatchFailure).toBeUndefined();
		expect(textOf(blocked!)).not.toMatch(/aborted|cancelled/i);
		expect(redirectsOf(harness.session)).toHaveLength(1);
		expect(childAgentIds()).toHaveLength(0);
		expect(activeJobs(harness)).toBe(0);

		// A fresh prompt resets the semantic bucket: the next bridged failure is
		// observed normally instead of being blocked by stale history.
		await promptSession(harness.session, "retry through the bridge");

		expect(harness.requests).toHaveLength(8);
		expect(startsOf(harness, "bridge_probe")).toHaveLength(7);
		expect(startsOf(harness, "task")).toHaveLength(0);

		const probesAfter = toolResultsOf(harness.session).filter(result => result.toolName === "bridge_probe");
		expect(probesAfter).toHaveLength(7);
		const repeated = probesAfter.find(result => result.toolCallId === "probe-6");
		expect(repeated).toBeDefined();
		const repeatedValue = bridgeValueOf(repeated!);
		expect(repeatedValue.hasError).toBe(true);
		const repeatedDetails = recordOf(repeatedValue.details);
		expect(dispatchFailureFrom(repeatedDetails)).toEqual(reservedModelFailure);
		expect(repeatedDetails?.toolCallLoopGuard).toBeUndefined();
		expect(repeatedDetails?.executed).toBe(false);
		expect(repeatedDetails?.unexecuted).toBe(true);
		expect(redirectsOf(harness.session)).toHaveLength(1);
		expect(childAgentIds()).toHaveLength(0);
		expect(activeJobs(harness)).toBe(0);
	});

	it("defers the exact-batch hard stop until every prepared argument is known", async () => {
		const holder: BatchProbeHolder = { events: [], runs: [] };
		const harness = await createHarness({
			toolNames: ["read"],
			extensions: [batchProbeExtension(holder)],
			turns: [
				...Array.from({ length: 6 }, (_unused, index) => batchProbeTurn(index + 1)),
				{ content: [{ type: "text", text: "done" }], stopReason: "stop" },
			],
		});

		await promptSession(harness.session, "run the probe batches");

		// The fifth identical batch earns the warning; the sixth is reworded by the
		// extension before it dispatches, so it must actually run — both calls —
		// instead of being hard-stopped as the previously warned identical batch.
		expect(harness.requests).toHaveLength(7);
		expect(startsOf(harness, "batch_probe")).toHaveLength(12);

		expect(holder.runs).toHaveLength(12);
		const runValue = (toolCallId: string) => holder.runs.find(run => run.toolCallId === toolCallId)?.value;
		for (let round = 1; round <= 5; round++) {
			expect(runValue(`r${round}-first`)).toBe("original");
			expect(runValue(`r${round}-second`)).toBe("original");
		}
		expect(runValue("r6-first")).toBe("original");
		expect(runValue("r6-second")).toBe("repaired");
		expect(holder.runs.filter(run => run.slot === "first")).toHaveLength(6);
		expect(holder.runs.filter(run => run.slot === "second")).toHaveLength(6);

		// The raw event the handler saw still carried the model's original value:
		// the repair came from the extension, not from rewritten model input.
		expect(holder.events).toHaveLength(12);
		const rawValue = (toolCallId: string) => holder.events.find(event => event.toolCallId === toolCallId)?.value;
		expect(rawValue("r6-second")).toBe("original");
		expect(rawValue("r6-first")).toBe("original");

		// The revision is what the loop persisted and what the tool recorded, and
		// no call in the sixth batch carries a blocked marker or an error.
		expect(assistantToolArgsOf(harness.session, "r6-second")).toMatchObject({
			slot: "second",
			value: "repaired",
		});
		expect(assistantToolArgsOf(harness.session, "r6-first")).toMatchObject({
			slot: "first",
			value: "original",
		});
		const results = toolResultsOf(harness.session).filter(result => result.toolName === "batch_probe");
		expect(results).toHaveLength(12);
		expect(results.every(result => result.isError !== true)).toBe(true);
		expect(results.every(result => recordOf(result.details)?.toolCallLoopGuard === undefined)).toBe(true);
		const repairedResult = results.find(result => result.toolCallId === "r6-second");
		expect(repairedResult).toBeDefined();
		expect(recordOf(repairedResult!.details)).toMatchObject({ slot: "second", value: "repaired" });
	});
});
