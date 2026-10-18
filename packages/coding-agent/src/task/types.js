export { TASK_SUBAGENT_PROGRESS_CHANNEL, TASK_SUBAGENT_LIFECYCLE_CHANNEL, } from "@rva/tui/overlays/session-observer-registry";
import { type } from "@rva/omptype";
import { $env } from "@rva/utils";
const parseNumber = (value, defaultValue) => {
    if (value) {
        try {
            const number = Number.parseInt(value, 10);
            if (!Number.isNaN(number) && number > 0) {
                return number;
            }
        }
        catch { }
    }
    return defaultValue;
};
/** Maximum output bytes per agent */
export const MAX_OUTPUT_BYTES = parseNumber($env.PI_TASK_MAX_OUTPUT_BYTES, 500000);
/** Maximum output lines per agent */
export const MAX_OUTPUT_LINES = parseNumber($env.PI_TASK_MAX_OUTPUT_LINES, 5000);
/** EventBus channel for raw subagent events */
export const TASK_SUBAGENT_EVENT_CHANNEL = "task:subagent:event";
// Keep this explicit: ArkType serializes `unknown` as a boolean subschema, which llama.cpp grammars reject.
const outputSchemaInputSchema = type("object | boolean | string | null");
// Coarse per-spawn thinking effort; must stay in sync with TASK_EFFORTS in ../thinking.
const effortRule = '"lo" | "med" | "hi"';
export const taskItemSchema = type({
    "name?": "string",
    agent: "string = 'task'",
    task: "string",
    solutionSpace: "string",
    "outputSchema?": outputSchemaInputSchema,
    "schemaMode?": '"permissive" | "strict"',
    "tools?": "string[]",
    "+": "delete",
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
    "+": "delete",
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
const taskSchemaBatch = type({
    context: "string",
    tasks: taskItemSchemaIsolated.array(),
    "+": "delete",
});
const taskSchemaBatchNoIsolation = type({
    context: "string",
    tasks: taskItemSchema.array(),
    "+": "delete",
});
const ALL_TASK_SCHEMAS = [taskSchema, taskSchemaNoIsolation, taskSchemaBatch, taskSchemaBatchNoIsolation];
const TASK_AGENT_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;
const taskSchemaCache = new Map();
function taskAgentSchemaRule(defaultAgent) {
    const trimmed = defaultAgent.trim();
    if (TASK_AGENT_NAME_PATTERN.test(trimmed)) {
        return `string = '${trimmed}'`;
    }
    return "string";
}
function createTaskSchema(options) {
    const agent = taskAgentSchemaRule(options.defaultAgent);
    const effortField = options.effortEnabled ? { "effort?": effortRule } : {};
    const schemaFields = options.structured
        ? { "outputSchema?": outputSchemaInputSchema, "schemaMode?": '"permissive" | "strict"' }
        : {};
    const toolsField = options.evalToolsEnabled ? { "tools?": "string[]" } : {};
    if (options.batchEnabled) {
        if (options.isolationEnabled) {
            const item = type.raw({
                "name?": "string",
                agent,
                task: "string",
                solutionSpace: "string",
                ...effortField,
                ...schemaFields,
                ...toolsField,
                "isolated?": "boolean",
                "+": "delete",
            });
            return type.raw({
                context: "string",
                tasks: item.array(),
                "+": "delete",
            });
        }
        const item = type.raw({
            "name?": "string",
            agent,
            task: "string",
            solutionSpace: "string",
            ...effortField,
            ...schemaFields,
            ...toolsField,
            "+": "delete",
        });
        return type.raw({
            context: "string",
            tasks: item.array(),
            "+": "delete",
        });
    }
    if (options.isolationEnabled) {
        return type.raw({
            "name?": "string",
            agent,
            task: "string",
            solutionSpace: "string",
            ...effortField,
            ...schemaFields,
            ...toolsField,
            "isolated?": "boolean",
            "+": "delete",
        });
    }
    return type.raw({
        "name?": "string",
        agent,
        task: "string",
        solutionSpace: "string",
        ...effortField,
        ...schemaFields,
        ...toolsField,
        "+": "delete",
    });
}
/** Build the task wire schema for the current settings and spawn policy. */
export function getTaskSchema(options) {
    const defaultAgent = options.defaultAgent ?? "task";
    const effortEnabled = options.effortEnabled ?? false;
    const evalToolsEnabled = options.evalToolsEnabled ?? true;
    const structured = options.structured ?? true;
    if (defaultAgent === "task" && !effortEnabled && evalToolsEnabled && structured) {
        if (options.batchEnabled)
            return options.isolationEnabled ? taskSchemaBatch : taskSchemaBatchNoIsolation;
        return options.isolationEnabled ? taskSchema : taskSchemaNoIsolation;
    }
    const key = `${options.isolationEnabled ? "iso" : "flat"}:${options.batchEnabled ? "batch" : "single"}:${effortEnabled ? "effort" : "default"}:${evalToolsEnabled ? "tools" : "notools"}:${structured ? "structured" : "prose"}:${defaultAgent}`;
    const cached = taskSchemaCache.get(key);
    if (cached)
        return cached;
    const schema = createTaskSchema({ ...options, effortEnabled, evalToolsEnabled, structured, defaultAgent });
    taskSchemaCache.set(key, schema);
    return schema;
}
/**
 * Whether an agent at `taskDepth` may still spawn children — i.e. it currently
 * holds the `task` tool. Mirrors the task-tool availability gate;
 * `maxRecursionDepth < 0` disables the cap entirely.
 */
export function canSpawnAtDepth(maxRecursionDepth, taskDepth) {
    return maxRecursionDepth < 0 || taskDepth < maxRecursionDepth;
}
