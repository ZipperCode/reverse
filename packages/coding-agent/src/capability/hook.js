/**
 * Hooks Capability
 *
 * Pre/post tool execution hooks defined as shell scripts.
 */
import { defineCapability } from ".";
export const hookCapability = defineCapability({
    id: "hooks",
    displayName: "Hooks",
    description: "Pre/post tool execution hooks",
    key: hook => `${hook.type}:${hook.tool}:${hook.name}`,
    toExtensionId: hook => `hook:${hook.type}:${hook.tool}:${hook.name}`,
    validate: hook => {
        if (!hook.name)
            return "Missing name";
        if (!hook.path)
            return "Missing path";
        if (hook.type !== "pre" && hook.type !== "post")
            return "Invalid type (must be 'pre' or 'post')";
        if (!hook.tool)
            return "Missing tool";
        return undefined;
    },
});
