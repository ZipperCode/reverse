/**
 * No-op memory backend.
 *
 * Selected when `memory.backend` is `"off"`.
 */
export const offBackend = {
    id: "off",
    async start() { },
    async buildDeveloperInstructions() {
        return undefined;
    },
    async clear() { },
    async enqueue() { },
    async status() {
        return {
            backend: "off",
            active: false,
            writable: false,
            searchable: false,
            message: "Memory backend is off.",
        };
    },
};
