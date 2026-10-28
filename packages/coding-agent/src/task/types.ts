import type { AgentSource } from "@reverse/tui/tools/task";
export {
	TASK_SUBAGENT_PROGRESS_CHANNEL,
	TASK_SUBAGENT_LIFECYCLE_CHANNEL,
} from "@reverse/tui/overlays/session-observer-registry";
export type {
	SubagentProgressPayload,
	SubagentLifecyclePayload,
} from "@reverse/tui/overlays/session-observer-registry";
import type { DeterministicDispatchFailure } from "@reverse/ai";
import { type BaseType, type Type, type } from "@reverse/reversetype";
import { $env } from "@reverse/utils";

import type { AgentSessionEvent } from "../session/agent-session";
import type { ConfiguredThinkingLevel } from "@reverse/tui/thinking";
import { SEANCE_AGENT_NAME } from "./seance-policy";

const parseNumber = (value: string | undefined, defaultValue: number): number => {
	if (value) {
		try {
			const number = Number.parseInt(value, 10);
			if (!Number.isNaN(number) && number > 0) {
				return number;
			}
		} catch {}
	}
	return defaultValue;
};

/** Maximum output bytes per agent */
export const MAX_OUTPUT_BYTES = parseNumber($env.PI_TASK_MAX_OUTPUT_BYTES, 500_000);

/** Maximum output lines per agent */
export const MAX_OUTPUT_LINES = parseNumber($env.PI_TASK_MAX_OUTPUT_LINES, 5000);

/** EventBus channel for raw subagent events */
export const TASK_SUBAGENT_EVENT_CHANNEL = "task:subagent:event";

/** Payload emitted on TASK_SUBAGENT_EVENT_CHANNEL */
export interface SubagentEventPayload {
	id: string;
	event: AgentSessionEvent;
}

// Keep this explicit: ArkType serializes `unknown` as a boolean subschema, which llama.cpp grammars reject.
const outputSchemaInputSchema = type("object | boolean | string | null");
// Coarse per-spawn thinking effort; must stay in sync with TASK_EFFORTS in ../thinking.
const effortRule = '"lo" | "med" | "hi"' as const;

/** Kinds of deterministic local rejection the task tool reports before dispatch. */
export type TaskPlanFailureCode = "task.shape" | "task.effort" | "task.seance";

/**
 * A deterministic local rejection of a task call, produced by the same plan
 * validation dispatch uses. `key` names the semantic precondition — never task
 * prose, a caller-chosen name, or an item index — so a reworded call with the
 * same defect keeps its identity while a corrected call changes it. `message`
 * states the correction.
 */
export interface TaskPlanFailure extends DeterministicDispatchFailure {
	readonly code: TaskPlanFailureCode;
}

// Batch items are validated inside an array, where the argument validator's
// root-key preservation does not reach: a deleting item (`"+": "delete"`) would
// erase a caller's reserved `sourceSession`/`model` (or a blank placeholder)
// before the planning boundary could judge it, silently changing the intent. An
// open index signature keeps every undeclared key instead, so `planSpawns`
// decides; it also leaves them out of the advertised property list. Spawn
// planning ignores them, so a stale key stays inert rather than rejecting the call.
export const taskItemSchema = type({
	"name?": "string",
	agent: "string = 'task'",
	task: "string",
	solutionSpace: "string",
	"outputSchema?": outputSchemaInputSchema,
	"schemaMode?": '"permissive" | "strict"',
	"tools?": "string[]",
	"[string]": "unknown",
});
const taskItemSchemaIsolated = type({
	"name?": "string",
	agent: "string = 'task'",
	task: "string",
	solutionSpace: "string",
	"outputSchema?": outputSchemaInputSchema,
	"schemaMode?": '"permissive" | "strict"',
	"tools?": "string[]",
	"isolated?": "boolean",
	"[string]": "unknown",
});

export const taskSchema = type({
	"name?": "string",
	agent: "string = 'task'",
	task: "string",
	solutionSpace: "string",
	"outputSchema?": outputSchemaInputSchema,
	"schemaMode?": '"permissive" | "strict"',
	"tools?": "string[]",
	"isolated?": "boolean",
	"+": "delete",
});
const taskSchemaNoIsolation = type({
	"name?": "string",
	agent: "string = 'task'",
	task: "string",
	solutionSpace: "string",
	"outputSchema?": outputSchemaInputSchema,
	"schemaMode?": '"permissive" | "strict"',
	"tools?": "string[]",
	"+": "delete",
});
function guardBatchAgent(schema: BaseType): BaseType {
	// Inspect the input before undeclared-key deletion can erase the requested agent.
	return schema.in
		.narrow((params, ctx) => {
			if (params !== null && typeof params === "object" && Object.hasOwn(params, "agent")) {
				return ctx.reject("a batch with `agent` specified in `tasks[].agent`, not at the top level");
			}
			return true;
		})
		.pipe(schema);
}

const taskSchemaBatch = guardBatchAgent(
	type.raw({
		context: "string",
		tasks: taskItemSchemaIsolated.array(),
		"+": "delete",
	}),
);
const taskSchemaBatchNoIsolation = guardBatchAgent(
	type.raw({
		context: "string",
		tasks: taskItemSchema.array(),
		"+": "delete",
	}),
);
const ALL_TASK_SCHEMAS = [taskSchema, taskSchemaNoIsolation, taskSchemaBatch, taskSchemaBatchNoIsolation] as const;

type DynamicTaskSchema = (typeof ALL_TASK_SCHEMAS)[number];
export type TaskSchema = typeof taskSchema;
/** Active task tool parameter schema for the current isolation / batch flags */
export type TaskToolSchemaInstance = DynamicTaskSchema | BaseType;

const TASK_AGENT_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;
const taskSchemaCache = new Map<string, BaseType>();

function taskAgentSchemaRule(defaultAgent: string): string {
	const trimmed = defaultAgent.trim();
	if (TASK_AGENT_NAME_PATTERN.test(trimmed)) {
		return `string = '${trimmed}'`;
	}
	return "string";
}

type SeanceTaskSchemaFields = {
	readonly sourceSession: Type;
	readonly model?: Type;
};

const SEANCE_AGENT_SCHEMA = type(`'${SEANCE_AGENT_NAME}'`);
// Mirrors the seance branch's literal so the exclusion cannot drift from it.
const NON_SEANCE_AGENT_SCHEMA = type("string").matching(new RegExp(`^(?!${SEANCE_AGENT_NAME}$)`));

/**
 * Build the wire schema for one settings combination.
 *
 * When the bundled seance agent is spawnable (`seanceFields` present) the shape
 * is a discriminated union:
 * - the ordinary branch advertises no `sourceSession`/`model` and excludes
 *   `agent: "seance"`, so a seance call can never read as an ordinary spawn;
 * - the seance branch pins `agent: "seance"` and requires a non-blank
 *   `sourceSession` plus non-blank model selectors.
 *
 * Both branches are closed, so a call carrying a reserved field for the wrong
 * agent fails validation instead of being healed into a different intent; the
 * tool's lenient argument handling hands such a call to `planSpawns`, which
 * reports the actionable reason. Without a seance branch, flat schemas delete
 * unknown keys; batch items retain them for the same planning boundary.
 */
function createTaskSchema(options: {
	isolationEnabled: boolean;
	batchEnabled: boolean;
	defaultAgent: string;
	effortEnabled: boolean;
	evalToolsEnabled: boolean;
	structured: boolean;
	seanceFields?: SeanceTaskSchemaFields;
}): BaseType {
	const effortField = options.effortEnabled ? { "effort?": effortRule } : {};
	const schemaFields = options.structured
		? { "outputSchema?": outputSchemaInputSchema, "schemaMode?": '"permissive" | "strict"' }
		: {};
	const toolsField = options.evalToolsEnabled ? { "tools?": "string[]" } : {};
	const isolatedField = options.isolationEnabled ? { "isolated?": "boolean" } : {};
	const commonFields = {
		"name?": "string",
		task: "string",
		solutionSpace: "string",
		...effortField,
		...schemaFields,
		...toolsField,
		...isolatedField,
	};
	const seanceFields = options.seanceFields;
	let items: BaseType;
	if (!seanceFields) {
		items = type.raw({
			...commonFields,
			agent: taskAgentSchemaRule(options.defaultAgent),
			// Batch items only: the flat root's undeclared keys already survive validation.
			...(options.batchEnabled ? { "[string]": "unknown" } : { "+": "delete" }),
		});
	} else {
		// A session whose spawn policy defaults to seance resolves an omitted
		// `agent` to seance, so both branches must name the agent explicitly there.
		const seanceIsDefault = options.defaultAgent === SEANCE_AGENT_NAME;
		const advertisedDefault =
			!seanceIsDefault && TASK_AGENT_NAME_PATTERN.test(options.defaultAgent.trim())
				? options.defaultAgent.trim()
				: undefined;
		// Validation excludes the seance agent; the wire states the same exclusion
		// portably (`not`/`const`) instead of leaking the predicate as a plain string.
		const ordinaryAgent = type.withJsonSchema(NON_SEANCE_AGENT_SCHEMA, {
			type: "string",
			not: { const: SEANCE_AGENT_NAME },
			...(advertisedDefault !== undefined ? { default: advertisedDefault } : {}),
		});
		const ordinary = type.raw({
			...commonFields,
			...(seanceIsDefault ? { agent: ordinaryAgent } : { "agent?": ordinaryAgent }),
			"+": "reject",
		});
		const seance = type.raw({
			...commonFields,
			...(seanceIsDefault ? { "agent?": SEANCE_AGENT_SCHEMA } : { agent: SEANCE_AGENT_SCHEMA }),
			sourceSession: seanceFields.sourceSession,
			...(seanceFields.model ? { "model?": seanceFields.model } : {}),
			"+": "reject",
		});
		items = ordinary.or(seance);
	}
	if (!options.batchEnabled) return items;
	return guardBatchAgent(
		type.raw({
			context: "string",
			tasks: items.array(),
			"+": "delete",
		}),
	);
}

/** Build the task wire schema for the current settings and spawn policy. */
export function getTaskSchema(options: {
	isolationEnabled: boolean;
	batchEnabled: boolean;
	effortEnabled?: boolean;
	/** Advertise the `tools` field for eval-defined tools (`eval.tools.enabled`, default on). */
	evalToolsEnabled?: boolean;
	/** Advertise `outputSchema`/`schemaMode` (`task.structured`); default on. */
	structured?: boolean;
	defaultAgent?: string;
	/** Advertise the historical seance branch: `agent: "seance"` plus its source/model selectors. */
	seanceFields?: SeanceTaskSchemaFields;
}): TaskToolSchemaInstance {
	const defaultAgent = options.defaultAgent ?? "task";
	const effortEnabled = options.effortEnabled ?? false;
	const evalToolsEnabled = options.evalToolsEnabled ?? true;
	const structured = options.structured ?? true;
	if (defaultAgent === "task" && !effortEnabled && evalToolsEnabled && structured && !options.seanceFields) {
		if (options.batchEnabled) return options.isolationEnabled ? taskSchemaBatch : taskSchemaBatchNoIsolation;
		return options.isolationEnabled ? taskSchema : taskSchemaNoIsolation;
	}
	const key = `${options.isolationEnabled ? "iso" : "flat"}:${options.batchEnabled ? "batch" : "single"}:${effortEnabled ? "effort" : "default"}:${evalToolsEnabled ? "tools" : "notools"}:${structured ? "structured" : "prose"}:${options.seanceFields ? "seance" : "plain"}:${defaultAgent}`;
	const cached = taskSchemaCache.get(key);
	if (cached) return cached;
	const schema = createTaskSchema({
		...options,
		effortEnabled,
		evalToolsEnabled,
		structured,
		defaultAgent,
	});
	taskSchemaCache.set(key, schema);
	return schema;
}

/**
 * Whether an agent at `taskDepth` may still spawn children — i.e. it currently
 * holds the `task` tool. Mirrors the task-tool availability gate;
 * `maxRecursionDepth < 0` disables the cap entirely.
 */
export function canSpawnAtDepth(maxRecursionDepth: number, taskDepth: number): boolean {
	return maxRecursionDepth < 0 || taskDepth < maxRecursionDepth;
}

/** Agent definition (bundled or discovered) */
export interface AgentDefinition {
	name: string;
	description: string;
	systemPrompt: string;
	tools?: string[];
	spawns?: string[] | "*";
	model?: string[];
	thinkingLevel?: ConfiguredThinkingLevel;
	output?: unknown;
	blocking?: boolean;
	/** `true` = task spawns keep the `yield` tool and this agent's `output` schema even when `task.structured` is off. */
	structured?: boolean;
	autoloadSkills?: string[];
	/** When `false`, the agent's `read` tool returns verbatim file content instead of structural summaries. */
	readSummarize?: boolean;
	/** Prewalk hand-off for the spawned session: `true` = switch to the default prewalk target at the first edit/write, string = custom target model pattern. */
	prewalk?: boolean | string;
	/** Advisor for spawned sessions of this agent: `true` = advise with the default advisor-role model, string = advise with that model pattern (optional `:level` suffix). Absent/`false` = no advisor. */
	advisor?: boolean | string;
	source: AgentSource;
	filePath?: string;
}
