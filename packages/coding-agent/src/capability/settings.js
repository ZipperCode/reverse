/**
 * Settings Capability
 *
 * Configuration settings from various sources (JSON, TOML, etc.)
 */
import { defineCapability } from ".";
export const settingsCapability = defineCapability({
    id: "settings",
    displayName: "Settings",
    description: "Configuration settings from various sources",
    // Settings are merged, not deduplicated by key
    key: () => undefined,
    validate: settings => {
        if (!settings.path)
            return "Missing path";
        if (!settings.data || typeof settings.data !== "object")
            return "Missing or invalid data";
        return undefined;
    },
});
