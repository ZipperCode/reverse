/**
 * Prompts Capability
 *
 * Reusable prompt templates (Codex format) available via /prompts: menu.
 */
import { defineCapability } from ".";
export const promptCapability = defineCapability({
    id: "prompts",
    displayName: "Prompts",
    description: "Reusable prompt templates available via /prompts: menu",
    key: prompt => prompt.name,
    toExtensionId: prompt => `prompt:${prompt.name}`,
    validate: prompt => {
        if (!prompt.name)
            return "Missing name";
        if (!prompt.path)
            return "Missing path";
        if (prompt.content === undefined)
            return "Missing content";
        return undefined;
    },
});
