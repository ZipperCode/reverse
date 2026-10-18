/**
 * Instructions Capability
 *
 * GitHub Copilot-style instructions with optional file pattern matching.
 */
import { defineCapability } from ".";
export const instructionCapability = defineCapability({
    id: "instructions",
    displayName: "Instructions",
    description: "File-specific instructions with glob pattern matching (GitHub Copilot format)",
    key: inst => inst.name,
    toExtensionId: inst => `instruction:${inst.name}`,
    validate: inst => {
        if (!inst.name)
            return "Missing name";
        if (!inst.path)
            return "Missing path";
        if (inst.content === undefined)
            return "Missing content";
        return undefined;
    },
});
