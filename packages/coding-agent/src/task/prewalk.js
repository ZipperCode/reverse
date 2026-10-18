/** Resolve an agent's prewalk default, including the bundled task opt-in. */
export function resolveAgentPrewalkDefault(agent, taskPrewalk) {
    return agent.prewalk ?? (taskPrewalk && agent.source === "bundled" && agent.name === "task" ? true : undefined);
}
