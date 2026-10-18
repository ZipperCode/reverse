/**
 * Custom Tools Capability
 *
 * User-defined tools that extend agent capabilities.
 */
import { defineCapability } from ".";
export const toolCapability = defineCapability({
    id: "tools",
    displayName: "Custom Tools",
    description: "User-defined tools that extend agent capabilities",
    key: tool => tool.name,
    toExtensionId: tool => `tool:${tool.name}`,
    validate: tool => {
        if (!tool.name)
            return "Missing name";
        if (!tool.path)
            return "Missing path";
        return undefined;
    },
});
