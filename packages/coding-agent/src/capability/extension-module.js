/**
 * Extension Modules Capability
 *
 * TypeScript/JavaScript extension modules loaded by the extension system.
 */
import { defineCapability } from ".";
export const extensionModuleCapability = defineCapability({
    id: "extension-modules",
    displayName: "Extension Modules",
    description: "TypeScript/JavaScript extension modules loaded by the extension system",
    key: ext => ext.name,
    toExtensionId: ext => `extension-module:${ext.name}`,
    validate: ext => {
        if (!ext.name)
            return "Missing name";
        if (!ext.path)
            return "Missing path";
        return undefined;
    },
});
