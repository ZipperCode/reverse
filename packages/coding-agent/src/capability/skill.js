/**
 * Skills Capability
 *
 * Skills provide specialized knowledge or workflows that extend agent capabilities.
 */
import { defineCapability } from ".";
export const skillCapability = defineCapability({
    id: "skills",
    displayName: "Skills",
    description: "Specialized knowledge and workflow files that extend agent capabilities",
    key: skill => skill.name,
    toExtensionId: skill => `skill:${skill.name}`,
    validate: skill => {
        if (!skill.name)
            return "Missing skill name";
        if (!skill.path)
            return "Missing skill path";
        return undefined;
    },
});
