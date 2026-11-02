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
import type { Model } from "@reverse/ai";
import { createMockModel } from "@reverse/ai/providers/mock";
import { Settings } from "@reverse/coding-agent/config/settings";
import { TaskTool, taskSchema } from "@reverse/coding-agent/task";
import { loadBundledAgents, parseAgent } from "@reverse/coding-agent/task/agents";
import * as discoveryModule from "@reverse/coding-agent/task/discovery";
import * as executorModule from "@reverse/coding-agent/task/executor";
import { cfgTaskPerCallModel, cfgTaskPerCallModelAllow } from "@reverse/coding-agent/task/settings";
import { getTaskSchema } from "@reverse/coding-agent/task/types";
import { isBundledSeance, seanceTaskSchemaFields } from "@reverse/coding-agent/task/seance";
import * as seanceModule from "@reverse/coding-agent/task/seance";
import type { AgentDefinition } from "@reverse/coding-agent/task/types";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { isRecord } from "@reverse/utils";

let taskSchemaSessionIndex = 0;

function createSession(
	options: {
		parentSpawns?: string;
		disabledAgents?: string[];
		planMode?: boolean;
		batchEnabled?: boolean;
		settings?: Record<string, unknown>;
	} = {},
): ToolSession {
	return {
		cwd: `/tmp/task-schema-${taskSchemaSessionIndex++}`,
		hasUI: false,
		settings: Settings.isolated({
			"task.isolation.enabled": false,
			"task.batch": options.batchEnabled ?? false,
			"task.disabledAgents": options.disabledAgents ?? [],
			...options.settings,
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
			const item = {
				taskFile: "local://assignment.md",
				model: "mock/file-worker",
				solutionSpace: "one defined change",
			};
			const parsed = schema(batchEnabled ? { context: "shared context", tasks: [item] } : item);
			const wire = schema.toJsonSchema();
			const tasks = isRecord(wire.properties) ? wire.properties.tasks : undefined;
			const itemWire = batchEnabled && isRecord(tasks) ? tasks.items : wire;
			if (!isRecord(itemWire)) throw new Error("Expected an object schema for task input");
			if (file) {
				if (parsed instanceof type.errors) throw new Error(parsed.summary);
				expect(parsed).toMatchObject(
					batchEnabled
						? { tasks: [{ taskFile: item.taskFile, model: item.model }] }
						: { taskFile: item.taskFile, model: item.model },
				);
				expect(itemWire.required).not.toContain("task");
				expect(itemWire.properties).toHaveProperty("model");
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
				// The ordinary branch owns no reserved sourceSession, restricts model
				// to one string selector, and cannot claim the seance agent.
				expect(ordinary!.properties).not.toHaveProperty("sourceSession");
				expect(ordinary!.properties?.model).toEqual({ type: "string" });
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
				// Only the per-call `model` remains: one string, never the seance selector list.
				expect(wireSchema).toContain('"model":{"type":"string"}');
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
		expect(planSchema).toContain('"model":{"type":"string"}');
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

	it("rejects a model override for an ordinary task while task.perCallModel is off", async () => {
		const schema = getTaskSchema({
			isolationEnabled: false,
			batchEnabled: false,
			seanceFields: seanceTaskSchemaFields,
		});
		const params = {
			agent: "scout",
			task: "Map the auth module.",
			solutionSpace: "focused inspection",
			model: "anthropic/claude-sonnet-4-5",
		};
		expect(schema(params) instanceof type.errors).toBe(false);
		const scout = loadBundledAgents().find(agent => agent.name === "scout");
		if (!scout) throw new Error("Expected the bundled scout agent");
		const tool = await makeTool([bundledSeance, scout]);
		const result = await tool.execute("tool-call", params);
		expect(firstText(result)).toContain("task.perCallModel: off");
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

	it("advertises approved selectors only while task.perCallModel is on", async () => {
		const description = async (mode: string) => {
			vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
			return (
				await TaskTool.create(
					createSession({
						settings: {
							"task.perCallModel": mode,
							modelRoles: { smol: "anthropic/claude-haiku-4-5", slow: "openai/gpt-5.5" },
							"task.perCallModelAllow": ["openai/gpt-5.5"],
						},
					}),
				)
			).description;
		};
		for (const mode of ["off", "eval"]) {
			const text = await description(mode);
			for (const guidance of ["`model`: one exact", "anthropic/claude-haiku-4-5", "openai/gpt-5.5"]) {
				expect(text).not.toContain(guidance);
			}
		}
		const text = await description("on");
		expect(text).toContain("`model`: one exact");
		// The allowlist admits only slow's model; smol's would be refused at dispatch.
		expect(text).toContain("`openai/gpt-5.5` (slow)");
		expect(text).not.toContain("anthropic/claude-haiku-4-5");
	});

	it("omits kind roles, role aliases, and default/inherit selectors from approved models", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
		const tool = await TaskTool.create(
			createSession({
				settings: {
					"task.perCallModel": "on",
					modelRoles: {
						smol: "anthropic/claude-haiku-4-5",
						image: "hidden/image",
						judge: "hidden/judge",
						alias: "@smol",
						legacyAlias: "pi/slow",
						wildcardAlias: "*",
						useDefault: "default",
						inherited: "inherit",
						slow: "openai/gpt-5.5",
					},
				},
			}),
		);
		const text = tool.description;
		for (const advertised of ["anthropic/claude-haiku-4-5", "openai/gpt-5.5"]) expect(text).toContain(advertised);
		for (const omitted of ["hidden/image", "hidden/judge", "`@smol`", "`pi/slow`", "`*`", "`default`", "`inherit`"]) {
			expect(text).not.toContain(omitted);
		}
	});

	it("advertises provider-qualified role values as written and omits globs, without consulting the model registry", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
		const session = createSession({
			settings: {
				"task.perCallModel": "on",
				modelRoles: { review: " mock/second:high, mock/*, mock/first, mock/* " },
			},
		});
		const catalogLookup = vi.fn(() => [{ provider: "mock", id: "registry-expanded" }]);
		Object.assign(session, { modelRegistry: { getAll: catalogLookup, getAvailable: catalogLookup } });
		const text = (await TaskTool.create(session)).description;
		expect(text).toContain("`mock/second:high`, `mock/first` (review)");
		expect(text).not.toContain("mock/*");
		expect(catalogLookup).not.toHaveBeenCalled();
	});

	it("advertises a bare role's resolved exact model selector", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
		const model = createMockModel({ id: "target" });
		const session = createSession({
			settings: { "task.perCallModel": "on", modelRoles: { review: "target" } },
		});
		Object.assign(session, { modelRegistry: { getAll: () => [model], getAvailable: () => [model] } });
		const text = (await TaskTool.create(session)).description;
		expect(text).toContain("`mock/target` (review)");
		expect(text).not.toContain("`target` (review)");
	});

	it("offers the caller's own model only when one selector can name it", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
		const ownModel = createMockModel({ id: "own" });
		// Several `only` upstreams: no single selector names this route.
		const multiRouteModel = {
			...ownModel,
			compat: { openRouterRouting: { only: ["anthropic", "google-vertex"] } },
		} as unknown as Model;
		const description = async (activeModel: Model) => {
			// No roles grant a model; the allowlist entry shows the advertisement still renders when the clause is withheld.
			const session = createSession({
				settings: { "task.perCallModel": "on", modelRoles: {}, "task.perCallModelAllow": ["mock/own"] },
			});
			Object.assign(session, { getActiveModel: () => activeModel });
			return (await TaskTool.create(session)).description;
		};
		const offered = await description(ownModel);
		expect(offered).toContain("your own current model");
		expect(offered).toContain("mock/own");
		const withheld = await description(multiRouteModel);
		expect(withheld).not.toContain("your own current model");
		expect(withheld).toContain("mock/own");
	});

	it("refreshes approved selectors and their allowlist from current settings", async () => {
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [], projectAgentsDir: null });
		// Distinct role and allowlist text, so each check proves its own refresh.
		const session = createSession({
			settings: {
				"task.perCallModel": "on",
				modelRoles: { smol: "mock/original-role" },
				"task.perCallModelAllow": ["mock/original-role", "mock/original-allowed"],
			},
		});
		const tool = await TaskTool.create(session);
		expect(tool.description).toContain("`mock/original-role` (smol)");
		expect(tool.description).toContain("mock/original-allowed");

		session.settings.overrideModelRoles({ smol: "mock/replacement-role" });
		cfgTaskPerCallModelAllow.override(session.settings, ["mock/replacement-role", "mock/replacement-allowed"]);
		const refreshed = tool.description;
		expect(refreshed).toContain("`mock/replacement-role` (smol)");
		expect(refreshed).toContain("mock/replacement-allowed");
		expect(refreshed).not.toContain("mock/original");

		cfgTaskPerCallModel.override(session.settings, "off");
		expect(tool.description).not.toContain("mock/replacement");
	});

	it("keys the seance model exemption on the resolved agent, not the raw `agent` value", async () => {
		const seen: unknown[] = [];
		vi.spyOn(seanceModule, "prepareSeance").mockImplementation(async context => {
			seen.push(context.model);
			throw new Error("stop after seance received its selectors");
		});
		vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({
			agents: [bundledSeance],
			projectAgentsDir: null,
		});
		const selectors = ["anthropic/claude-sonnet-4-5", "openai/gpt-5"];
		const run = async (batch: boolean, params: Record<string, unknown>) => {
			const tool = await TaskTool.create(
				createSession({ parentSpawns: "seance", settings: { "task.perCallModel": "off", "task.batch": batch } }),
			);
			const result = await tool.execute("tool-call", params);
			return result.content.find(part => part.type === "text")?.text ?? "";
		};
		const flat = { task: "What was decided?", sourceSession: "/tmp/source.jsonl", model: selectors };
		const item = { task: "What was decided?", sourceSession: "/tmp/source.jsonl", model: selectors };
		const texts = [
			await run(false, flat),
			await run(false, { ...flat, agent: " seance " }),
			await run(true, { context: "c", tasks: [item] }),
			await run(true, { context: "c", tasks: [{ ...item, agent: " seance " }] }),
		];
		for (const text of texts) expect(text).not.toContain("invalid `model` value");
		expect(seen).toEqual([selectors, selectors, selectors, selectors]);
	});
});
