/** Default agent used when a session has unrestricted spawning. */
export const DEFAULT_SPAWN_AGENT = "task";
/** Resolves spawn frontmatter into the default and prompt/error surfaces. */
export function resolveSpawnPolicy(parentSpawns) {
    let normalized;
    if (parentSpawns === false) {
        normalized = "";
    }
    else if (parentSpawns === true || parentSpawns === null || parentSpawns === undefined) {
        normalized = "*";
    }
    else {
        normalized = parentSpawns.trim();
    }
    if (normalized === "*") {
        return {
            enabled: true,
            defaultAgent: DEFAULT_SPAWN_AGENT,
            allowedAgents: null,
            allowedErrorText: "*",
        };
    }
    const allowedAgents = normalized
        .split(",")
        .map(spawn => spawn.trim())
        .filter(Boolean);
    if (allowedAgents.length === 0) {
        return {
            enabled: false,
            defaultAgent: DEFAULT_SPAWN_AGENT,
            allowedAgents,
            allowedErrorText: "none (spawns disabled for this agent)",
        };
    }
    return {
        enabled: true,
        defaultAgent: allowedAgents[0] ?? DEFAULT_SPAWN_AGENT,
        allowedAgents,
        allowedErrorText: allowedAgents.join(","),
        allowedPromptText: allowedAgents.map(agent => `\`${agent}\``).join(", "),
    };
}
/**
 * Whether the `scout` agent is spawnable in a session: not disabled via
 * `task.disabledAgents`, and permitted by the session spawn policy.
 */
export function isScoutSpawnable(disabledAgents, spawns) {
    if (disabledAgents?.includes("scout"))
        return false;
    const policy = resolveSpawnPolicy(spawns);
    if (!policy.enabled)
        return false;
    return policy.allowedAgents === null || policy.allowedAgents.includes("scout");
}
