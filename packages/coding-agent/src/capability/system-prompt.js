/**
 * System Prompt Capability
 *
 * Custom system prompt files (SYSTEM.md) and raw Handlebars template overrides
 * (SYSTEM_TEMPLATE.md) that modify the agent's base system prompt.
 * Distinct from context-files which are user instructions shown in conversation.
 */
import { defineCapability } from ".";
export const systemPromptCapability = defineCapability({
    id: "system-prompt",
    displayName: "System Prompt",
    description: "Custom system prompt files (SYSTEM.md, SYSTEM_TEMPLATE.md) that modify agent behavior",
    key: sp => `${sp.level}:${sp.kind ?? "text"}`,
    validate: sp => {
        if (!sp.path)
            return "Missing path";
        if (sp.content === undefined)
            return "Missing content";
        return undefined;
    },
});
