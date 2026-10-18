/**
 * Built-in tool names whose classes declare `loadMode = "essential"`. Kept in
 * sync with the tool classes by `essential-tools.test.ts` (drift guard).
 */
export const ESSENTIAL_BUILTIN_TOOL_NAMES = {
    read: true,
    write: true,
    bash: true,
    edit: true,
    glob: true,
    find: true,
    eval: true,
    task: true,
    wait: true,
    learn: true,
    manage_skill: true,
    context_notes: true,
    new_context: true,
};
/**
 * Resolve a tool's presentation mode at an adapter boundary. An explicit
 * `declared` mode always wins. When omitted, known essential built-in names
 * default to `"essential"` (so a re-register never demotes them); everything
 * else defaults to `"discoverable"`.
 */
export function defaultLoadModeForToolName(name, declared) {
    if (declared)
        return declared;
    return name in ESSENTIAL_BUILTIN_TOOL_NAMES ? "essential" : "discoverable";
}
