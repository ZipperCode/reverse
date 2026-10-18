import { parseFrontmatter, prompt } from "@rva/utils";
import { parseAgentFields } from "../discovery/helpers";
// Embed agent markdown files at build time
import agentFrontmatterTemplate from "../prompts/agents/frontmatter.md" with { type: "text" };
import reviewerMd from "../prompts/agents/reviewer.md" with { type: "text" };
import scoutMd from "../prompts/agents/scout.md" with { type: "text" };
import securityReviewerMd from "../prompts/agents/security-reviewer.md" with { type: "text" };
import taskMd from "../prompts/agents/task.md" with { type: "text" };
import { AUTO_THINKING } from "@rva/tui/thinking";
function buildAgentContent(def) {
    const body = prompt.render(def.template);
    if (!def.frontmatter)
        return body;
    return prompt.render(agentFrontmatterTemplate, { ...def.frontmatter, body });
}
const EMBEDDED_AGENT_DEFS = [
    { fileName: "scout.md", template: scoutMd },
    { fileName: "reviewer.md", template: reviewerMd },
    { fileName: "security-reviewer.md", template: securityReviewerMd },
    {
        fileName: "task.md",
        frontmatter: {
            name: "task",
            description: "General-purpose subagent with full capabilities for delegated multi-step tasks",
            spawns: "*",
            model: "@task",
            thinkingLevel: AUTO_THINKING,
            // No `prewalk` frontmatter: the generic task hand-off (strong model
            // plans, then hands off to the smol role) is armed by the
            // `task.prewalk` setting (default off) or per agent via /agents
            // (task.agentPrewalk).
        },
        template: taskMd,
    },
    {
        fileName: "sonic.md",
        frontmatter: {
            name: "sonic",
            description: "Low-reasoning agent for strictly mechanical updates or data collection only",
            model: "@smol",
            thinkingLevel: "medium" /* Effort.Medium */,
        },
        template: taskMd,
    },
];
// Computed lazily on first loadBundledAgents() call to avoid eager prompt.render at module load.
export class AgentParsingError extends Error {
    source;
    constructor(error, source) {
        super(`Failed to parse agent: ${error.message}`, { cause: error });
        this.source = source;
        this.name = "AgentParsingError";
    }
    toString() {
        const details = [this.message];
        if (this.source !== undefined) {
            details.push(`Source: ${JSON.stringify(this.source)}`);
        }
        if (this.cause && typeof this.cause === "object" && "stack" in this.cause && this.cause.stack) {
            details.push(`Stack:\n${this.cause.stack}`);
        }
        else if (this.stack) {
            details.push(`Stack:\n${this.stack}`);
        }
        return details.join("\n\n");
    }
}
/**
 * Parse an agent from embedded content.
 */
export function parseAgent(filePath, content, source, level = "fatal") {
    const { frontmatter, body } = parseFrontmatter(content, {
        location: filePath,
        level,
    });
    const fields = parseAgentFields(frontmatter);
    if (!fields) {
        throw new AgentParsingError(new Error(`Invalid agent field: ${filePath}\n${content}`), filePath);
    }
    return {
        ...fields,
        systemPrompt: body,
        source,
        filePath,
    };
}
/** Cache for bundled agents */
let bundledAgentsCache = null;
/**
 * Load all bundled agents from embedded content.
 * Results are cached after first load.
 */
export function loadBundledAgents() {
    if (bundledAgentsCache !== null) {
        return bundledAgentsCache;
    }
    bundledAgentsCache = EMBEDDED_AGENT_DEFS.map(def => parseAgent(`embedded:${def.fileName}`, buildAgentContent(def), "bundled"));
    return bundledAgentsCache;
}
/**
 * Get a bundled agent by name.
 */
export function getBundledAgent(name) {
    return loadBundledAgents().find(a => a.name === name);
}
/**
 * Get all bundled agents as a map keyed by name.
 */
export function getBundledAgentsMap() {
    const map = new Map();
    for (const agent of loadBundledAgents()) {
        map.set(agent.name, agent);
    }
    return map;
}
/**
 * Clear the bundled agents cache (for testing).
 */
export function clearBundledAgentsCache() {
    bundledAgentsCache = null;
}
// Re-export for backward compatibility
export const BUNDLED_AGENTS = loadBundledAgents;
