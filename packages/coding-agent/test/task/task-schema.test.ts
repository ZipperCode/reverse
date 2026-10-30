import { afterEach, describe, expect, it, vi } from "bun:test";
import {
	adaptSchemaForStrict,
	normalizeSchemaForCCA,
	normalizeSchemaForGoogle,
	toolWireSchema,
	validateSchemaCompatibility,
	validateStrictSchemaEnforcement,
} from "@reverse/ai/utils/schema";
import { type AgentTool, validateAgentToolArguments } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { Settings } from "@reverse/coding-agent/config/settings";
import { TaskTool, taskSchema } from "@reverse/coding-agent/task";
import { loadBundledAgents, parseAgent } from "@reverse/coding-agent/task/agents";
import * as discoveryModule from "@reverse/coding-agent/task/discovery";
import * as executorModule from "@reverse/coding-agent/task/executor";
import { getTaskSchema } from "@reverse/coding-agent/task/types";
import { isBundledSeance, seanceTaskSchemaFields } from "@reverse/coding-agent/task/seance";
import type { AgentDefinition } from "@reverse/coding-agent/task/types";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { isRecord } from "@reverse/utils";

let taskSchemaSessionIndex = 0;

function createSession(
	options: { parentSpawns?: string; disabledAgents?: string[]; planMode?: boolean; batchEnabled?: boolean } = {},
): ToolSession {
	return {
		cwd: `/tmp/task-schema-${taskSchemaSessionIndex++}`,
		hasUI: false,
		settings: Settings.isolated({
			"task.isolation.enabled": false,
			"task.batch": options.batchEnabled ?? false,
			"task.disabledAgents": options.disabledAgents ?? [],
		}),
		getSessionFile: () => null,
		getSessionSpawns: () => options.parentSpawns ?? "*",
		getPlanModeState: () => (options.planMode ? { enabled: true } : undefined),
	} as unknown as ToolSession;
}

const bundledSeance = loadBundledAgents().find(agent => agent.name === "seance")!;
// Contract: the single-spawn schema (`task.batch: false`; the exported
// `taskSchema` instance) carries no batch fields, and accepts a caller
// `outputSchema` plus its validation mode. The batch shape (`tasks[]` + shared
// `context`) is gated by the `task.batch` setting (default on, covered by
// test/task/task-batch.test.ts). The bundled seance agent adds a discriminated
// `agent: "seance"` branch that owns `sourceSession`/`model`; ordinary calls
// never advertise them and blank placeholders normalize to absence at the
// planning boundary.

describe("task schema (single-spawn)", () => {
	it("requires task", () => {
		const parsed = taskSchema({ agent: "scout", solutionSpace: "c" });
		expect(parsed instanceof type.errors).toBe(true);
	});

	it.each([false, true])("advertises taskFile only while task.file is on (batch=%s)", batchEnabled => {
		// Enabled first: the disabled schema must not reuse the enabled one from the cache.
		for (const file of [true, false]) {
			const schema = getTaskSchema({ batchEnabled, isolationEnabled: false, structured: false, file });
			const item = { taskFile: "local://assignment.md", solutionSpace: "one defined change" };
			const parsed = schema(batchEnabled ? { context: "shared context", tasks: [item] } : item);
			const wire = schema.toJsonSchema();
			const tasks = isRecord(wire.properties) ? wire.properties.tasks : undefined;
			const itemWire = batchEnabled && isRecord(tasks) ? tasks.items : wire;
			if (!isRecord(itemWire)) throw new Error("Expected an object schema for task input");
			if (file) {
				if (parsed instanceof type.errors) throw new Error(parsed.summary);
				expect(parsed).toMatchObject(
					batchEnabled ? { tasks: [{ taskFile: item.taskFile }] } : { taskFile: item.taskFile },
				);
				expect(itemWire.required).not.toContain("task");
			} else {
				expect(parsed instanceof type.errors).toBe(true);
				expect(itemWire.properties).not.toHaveProperty("taskFile");
				expect(itemWire.required).toContain("task");
			}
		}
	});

	it("removes eval tool names from the wire shape when eval.tools.enabled is off", () => {
		const schema = getTaskSchema({
			isolationEnabled: false,
			batchEnabled: false,
			evalToolsEnabled: false,
		});
		const parsed = schema({
			agent: "scout",
			task: "Map the auth module.",
			solutionSpace: "c",
			tools: ["word_count"],
		});
		expect(parsed instanceof type.errors).toBe(false);
		if (parsed && typeof parsed === "object" && !(parsed instanceof type.errors)) {
			expect("tools" in parsed).toBe(false);
		}
	});

	it("retains caller outputSchema, schemaMode, and eval tool names while stripping stale keys", () => {
		const outputSchema = { type: "object", properties: { answer: { type: "string" } } };
		const parsed = taskSchema({
			agent: "scout",
			task: "Map the auth module.",
			solutionSpace: "c",
			outputSchema,
			schemaMode: "strict",
			tools: ["word_count"],
			context: "shared background",
			tasks: [{ name: "A", task: "..." }],
			schema: '{"properties":{}}',
		});
		expect(parsed instanceof type.errors).toBe(false);
		if (!(parsed instanceof type.errors)) {
			expect(parsed.outputSchema).toEqual(outputSchema);
			expect(parsed.schemaMode).toBe("strict");
			expect(parsed.tools).toEqual(["word_count"]);
			expect("tasks" in parsed).toBe(false);
			expect("context" in parsed).toBe(false);
			expect("schema" in parsed).toBe(false);
		}
	});
});

describe("task schema seance fields", () => {
	it("accepts source and model selectors in every flat/batch isolation mode", () => {
		for (const batchEnabled of [false, true]) {
			for (const isolationEnabled of [false, true]) {
				const schema = getTaskSchema({
					batchEnabled,
					isolationEnabled,
					evalToolsEnabled: false,
					seanceFields: seanceTaskSchemaFields,
				});
				const modelSelector = batchEnabled
					? ["anthropic/claude-sonnet-4-6", "anthropic/claude-sonnet-4-5"]
					: "anthropic/claude-sonnet-4-5";
				const item = {
					agent: "seance",
					task: "Read historical context.",
					solutionSpace: "focused read-only inspection",
					sourceSession: "/sessions/source.jsonl",
					model: modelSelector,
					...(isolationEnabled ? { isolated: false } : {}),
				};
				const parsed = schema(batchEnabled ? { context: "shared context", tasks: [item] } : { ...item });
				expect(parsed instanceof type.errors).toBe(false);
				if (parsed instanceof type.errors) continue;
				if (!parsed || typeof parsed !== "object") {
					expect(parsed).toBeTruthy();
					continue;
				}
				let parsedItem: unknown = parsed;
				if (batchEnabled) {
					if (!("tasks" in parsed) || !Array.isArray(parsed.tasks)) {
						expect(parsed).toHaveProperty("tasks");
						continue;
					}
					parsedItem = parsed.tasks[0];
				}
				expect(parsedItem).toMatchObject({
					sourceSession: "/sessions/source.jsonl",
					model: modelSelector,
				});
			}
		}
	});
	it("discriminates the ordinary and seance branches in every flat/batch isolation mode", () => {
		for (const batchEnabled of [false, true]) {
			for (const isolationEnabled of [false, true]) {
				const schema = getTaskSchema({
					batchEnabled,
					isolationEnabled,
					effortEnabled: true,
					seanceFields: seanceTaskSchemaFields,
				});
				const wire = schema.toJsonSchema() as Record<string, any>;
				const branches = (batchEnabled ? wire.properties?.tasks?.items?.anyOf : wire.anyOf) as
					| Array<Record<string, any>>
					| undefined;
				expect(Array.isArray(branches)).toBe(true);
				expect(branches).toHaveLength(2);
				const [ordinary, seance] = branches!;
				// The ordinary branch owns no reserved selector and cannot claim the
				// seance agent; the exclusion is stated portably, not as a bare string.
				expect(ordinary!.properties).not.toHaveProperty("sourceSession");
				expect(ordinary!.properties).not.toHaveProperty("model");
				expect(ordinary!.properties?.agent).toMatchObject({ type: "string", not: { const: "seance" } });
				expect(ordinary!.additionalProperties).toBe(false);
				// The seance branch pins the agent and requires its source session.
				expect(seance!.properties?.agent).toEqual({ const: "seance" });
				expect(seance!.required).toContain("sourceSession");
				// Provider-shaped: a union of object branches, no `oneOf`/`$ref`.
				expect(wire.oneOf).toBeUndefined();
				expect(JSON.stringify(wire)).not.toContain('"$ref"');

				const wrap = (item: Record<string, unknown>): Record<string, unknown> =>
					batchEnabled ? { context: "ctx", tasks: [item] } : item;
				const accepts = (item: Record<string, unknown>): boolean => !(schema(wrap(item)) instanceof type.errors);
				expect(accepts({ task: "x", solutionSpace: "s" })).toBe(true);
				expect(accepts({ agent: "custom-auditor", task: "x", solutionSpace: "s" })).toBe(true);
				expect(accepts({ agent: "seance", task: "x", solutionSpace: "s", sourceSession: "/s.jsonl" })).toBe(true);
				// A seance agent without its source is not an ordinary call...
				expect(accepts({ agent: "seance", task: "x", solutionSpace: "s" })).toBe(false);
				// ...its source and model selectors carry real values only...
				expect(accepts({ agent: "seance", task: "x", solutionSpace: "s", sourceSession: "  " })).toBe(false);
				expect(
					accepts({
						agent: "seance",
						task: "x",
						solutionSpace: "s",
						sourceSession: "/s.jsonl",
						model: [],
					}),
				).toBe(false);
				// ...and ordinary calls cannot smuggle the reserved fields.
				expect(accepts({ agent: "custom-auditor", task: "x", solutionSpace: "s", sourceSession: "/s.jsonl" })).toBe(
					false,
				);
			}
		}
	});

	it("keeps the flat union callable under the provider schema constraints", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [bundledSeance],
			projectAgentsDir: null,
		});
		const tool = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		const wire = toolWireSchema(tool) as Record<string, unknown>;
		expect(Array.isArray(wire.anyOf)).toBe(true);
		// The tool ships non-strict; the union still survives strict enforcement as
		// a compatible (loosened) schema, and both stripping providers accept it.
		expect(adaptSchemaForStrict(wire, tool.strict !== false).strict).toBe(false);
		expect(validateStrictSchemaEnforcement(wire, adaptSchemaForStrict(wire, true)).compatible).toBe(true);
		expect(validateSchemaCompatibility(normalizeSchemaForGoogle(wire), "google").compatible).toBe(true);
		expect(validateSchemaCompatibility(normalizeSchemaForCCA(wire), "cloud-code-assist-claude").compatible).toBe(
			true,
		);
	});

	it("omits seance fields when they are not enabled", () => {
		for (const batchEnabled of [false, true]) {
			for (const isolationEnabled of [false, true]) {
				const schema = getTaskSchema({ batchEnabled, isolationEnabled });
				const wireSchema = JSON.stringify(schema.toJsonSchema());
				expect(wireSchema).not.toContain('"sourceSession"');
				expect(wireSchema).not.toContain('"model"');
			}
		}
	});

	it("advertises fields only when bundled seance is spawnable", async () => {
		const discovery = vi
			.spyOn(discoveryModule, "discoverAgents")
			.mockResolvedValue({ agents: [bundledSeance], projectAgentsDir: null });

		const allowed = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		expect(JSON.stringify(allowed.parameters.toJsonSchema())).toContain('"sourceSession"');

		const policyDenied = await TaskTool.create(createSession({ parentSpawns: "task" }));
		expect(JSON.stringify(policyDenied.parameters.toJsonSchema())).not.toContain('"sourceSession"');

		const agentDisabled = await TaskTool.create(
			createSession({ parentSpawns: "task,seance", disabledAgents: ["seance"] }),
		);
		expect(JSON.stringify(agentDisabled.parameters.toJsonSchema())).not.toContain('"sourceSession"');

		discovery.mockResolvedValue({ agents: [], projectAgentsDir: null });
		const absentFromCatalogue = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		expect(JSON.stringify(absentFromCatalogue.parameters.toJsonSchema())).not.toContain('"sourceSession"');

		const customSeance = parseAgent(
			"project-seance.md",
			`---
name: seance
description: Custom historical agent.
---
Custom prompt.`,
			"project",
		);
		expect(isBundledSeance(customSeance)).toBe(false);
		discovery.mockResolvedValue({ agents: [customSeance], projectAgentsDir: null });
		const overridden = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		expect(JSON.stringify(overridden.parameters.toJsonSchema())).not.toContain('"sourceSession"');
	});

	it("hides seance fields, listing, and guidance in plan mode", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [bundledSeance],
			projectAgentsDir: null,
		});
		const planMode = await TaskTool.create(createSession({ parentSpawns: "task,seance", planMode: true }));
		const planSchema = JSON.stringify(planMode.parameters.toJsonSchema());
		expect(planSchema).not.toContain('"sourceSession"');
		expect(planSchema).not.toContain("seance");
		expect(planSchema).not.toContain('"model"');
		expect(planMode.description).not.toContain("seance");
		expect(planMode.description).not.toContain("Historical consults");

		const ordinary = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		const ordinarySchema = JSON.stringify(ordinary.parameters.toJsonSchema());
		expect(ordinarySchema).toContain('"sourceSession"');
		expect(ordinarySchema).toContain('"model"');
		expect(ordinary.description).toContain("`seance`");
		expect(ordinary.description).toContain("Historical consults");
	});
	afterEach(() => vi.restoreAllMocks());
});

describe("task spawn validation", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	async function makeTool(
		agents: AgentDefinition[] = [],
		options: { parentSpawns?: string; batchEnabled?: boolean } = {},
	): Promise<TaskTool> {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents, projectAgentsDir: null });
		return TaskTool.create(createSession(options));
	}

	function firstText(result: { content: Array<{ type: string; text?: string }> }): string {
		return result.content.find(part => part.type === "text")?.text ?? "";
	}

	async function executeText(
		params: unknown,
		agents: AgentDefinition[] = [],
		options: { parentSpawns?: string; batchEnabled?: boolean } = {},
	): Promise<string> {
		const tool = await makeTool(agents, options);
		return firstText(await tool.execute("tool-call", params));
	}

	it("defaults a missing agent to `task`", async () => {
		// With no `agent`, execute() normalizes to the `task` default, so the
		// failure is unknown-agent (none discovered), not missing-agent.
		const text = await executeText({ task: "..." });
		expect(text).toContain('Unknown agent "task"');
	});

	it("rejects a missing task", async () => {
		const text = await executeText({ agent: "scout" });
		expect(text).toContain("Missing `task`");
	});

	it("dispatches ordinary blank sourceSession/model placeholders exactly like omitted fields", async () => {
		// The raw call form internal callers and lenient validation produce: the
		// schema heals nothing, so the planning boundary must treat `""`/`[]` as
		// absence for an ordinary agent instead of reporting a reserved field.
		const flat = await executeText({
			agent: "scout",
			task: "Map the auth module.",
			solutionSpace: "focused inspection",
			sourceSession: "",
			model: [],
		});
		expect(flat).toContain('Unknown agent "scout"');
		expect(flat).not.toContain("reserved");

		const batch = await executeText(
			{
				context: "shared context",
				tasks: [{ agent: "scout", task: "Map the auth module.", solutionSpace: "focused inspection", model: "" }],
			},
			[],
			{ batchEnabled: true },
		);
		expect(batch).toContain('Unknown agent "scout"');
		expect(batch).not.toContain("reserved");
	});

	it("rejects a populated reserved seance field on an ordinary task with the correction", async () => {
		const params = { agent: "scout", task: "x", solutionSpace: "s", model: "anthropic/x" };
		const tool = await makeTool([bundledSeance]);
		const result = await tool.execute("tool-call", params);
		expect(firstText(result)).toContain("`model` is reserved for the `seance` agent");
		expect(result.isError).toBe(true);
		expect(result.details?.executed).toBe(false);
		expect(result.details?.unexecuted).toBe(true);
		expect(result.details?.dispatchFailure).toEqual(tool.getDispatchFailure(params));
		expect(result.details?.dispatchFailure).toMatchObject({
			code: "task.seance",
			key: "task.seance:reserved-model",
		});
	});

	it("rejects a populated reserved selector inside a seance-disabled batch before any child spawns", async () => {
		const run = vi.spyOn(executorModule, "runSubprocess");
		// The spawn policy hides the bundled seance agent, so the plain batch item
		// shape is active. That wire used to erase a nested reserved selector before
		// the planning boundary could see it, silently dropping the caller's intent.
		const tool = await makeTool([bundledSeance], { parentSpawns: "task", batchEnabled: true });
		for (const [field, key] of [
			["model", "task.seance:reserved-model"],
			["sourceSession", "task.seance:reserved-source-session"],
		] as const) {
			const id = `call-${field}`;
			const validated = validateAgentToolArguments(
				tool as unknown as AgentTool,
				{
					type: "toolCall",
					id,
					name: "task",
					arguments: {
						context: "Shared background.",
						tasks: [{ task: "Map the auth module.", solutionSpace: "focused inspection", [field]: "non-empty" }],
					},
				},
				"payload",
			);
			const result = await tool.execute(id, validated);
			expect(result.isError).toBe(true);
			expect(result.details?.unexecuted).toBe(true);
			expect(result.details?.dispatchFailure).toMatchObject({ code: "task.seance", key });
		}
		expect(run).not.toHaveBeenCalled();
	});

	it("keeps a valid seance call on the seance path and reports a missing source actionably", async () => {
		// A resolvable-shaped seance call reaches real preparation; the failure is
		// about the source file, not about the shape.
		const valid = await executeText(
			{ agent: "seance", task: "x", solutionSpace: "s", sourceSession: "/missing/seance-source.jsonl" },
			[bundledSeance],
		);
		expect(valid).toContain("could not be accessed");
		expect(valid).not.toContain("requires a non-empty `sourceSession`");

		const missing = await executeText({ agent: "seance", task: "x", solutionSpace: "s" }, [bundledSeance]);
		expect(missing).toContain("requires a non-empty `sourceSession`");
	});

	it("reports a stable dispatch failure key across reworded and reindexed calls", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [bundledSeance],
			projectAgentsDir: null,
		});
		const tool = await TaskTool.create(createSession({ parentSpawns: "task,seance" }));
		const first = tool.getDispatchFailure({
			agent: "scout",
			task: "Map the auth module.",
			solutionSpace: "s",
			model: "m",
		});
		const reworded = tool.getDispatchFailure({
			agent: "scout",
			name: "Renamed",
			task: "An entirely different assignment.",
			solutionSpace: "some other space",
			model: "m",
		});
		expect(first?.key).toBe("task.seance:reserved-model");
		expect(reworded).toEqual(first);
		expect(
			tool.getDispatchFailure({ agent: "scout", task: "Map the auth module.", solutionSpace: "s" }),
		).toBeUndefined();

		const batch = await TaskTool.create(createSession({ parentSpawns: "task,seance", batchEnabled: true }));
		const indexed = batch.getDispatchFailure({ context: "c", tasks: [{ task: "" }] });
		const reindexed = batch.getDispatchFailure({
			context: "other",
			tasks: [
				{ task: "ok", solutionSpace: "s" },
				{ name: "N", task: "" },
			],
		});
		expect(indexed?.key).toBe("task.shape:item-task");
		expect(reindexed?.key).toBe("task.shape:item-task");
		expect(indexed?.message).not.toBe(reindexed?.message);
	});
});
