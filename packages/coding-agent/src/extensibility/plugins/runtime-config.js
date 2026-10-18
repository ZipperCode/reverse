/** Normalizes persisted plugin runtime config across legacy lockfile shapes. */
export function normalizePluginRuntimeConfig(config) {
    return {
        plugins: config.plugins ?? {},
        settings: config.settings ?? {},
    };
}
