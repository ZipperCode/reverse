/**
 * Extensions Capability
 *
 * Gemini-style extensions that provide MCP servers, tools, and context.
 */
import { defineCapability } from ".";
export const extensionCapability = defineCapability({
    id: "extensions",
    displayName: "Extensions",
    description: "Gemini-style extensions providing MCP servers, tools, and context",
    key: ext => ext.name,
    validate: ext => {
        if (!ext.name)
            return "Missing extension name";
        if (!ext.path)
            return "Missing extension path";
        return undefined;
    },
});
