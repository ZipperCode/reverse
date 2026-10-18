import { resolveMemoryBackend } from "./resolve";
export function createMemoryRuntimeContext(context) {
    const settings = context.session?.settings;
    return {
        async status() {
            if (!settings) {
                return {
                    backend: "off",
                    active: false,
                    writable: false,
                    searchable: false,
                    message: "No active agent session.",
                };
            }
            const backend = await resolveMemoryBackend(settings);
            return backend.status
                ? await backend.status(context)
                : {
                    backend: backend.id,
                    active: backend.id !== "off",
                    writable: false,
                    searchable: false,
                    message: "This memory backend does not expose structured status.",
                };
        },
        async search(query, options) {
            if (!settings)
                return unavailableSearch("off", query, "No active agent session.");
            const backend = await resolveMemoryBackend(settings);
            return backend.search
                ? await backend.search(context, query, options)
                : unavailableSearch(backend.id, query, `Memory search is not available for the ${backend.id} backend.`);
        },
        async save(input) {
            if (!settings)
                return unavailableSave("off", "No active agent session.");
            const backend = await resolveMemoryBackend(settings);
            const normalized = typeof input === "string" ? { content: input } : input;
            return backend.save
                ? await backend.save(context, normalized)
                : unavailableSave(backend.id, `Memory save is not available for the ${backend.id} backend.`);
        },
    };
}
export function createSessionMemoryRuntimeContext(session, agentDir, cwd) {
    return createMemoryRuntimeContext({ agentDir, cwd, session });
}
function unavailableSearch(backend, query, message) {
    return { backend, query, count: 0, items: [], message };
}
function unavailableSave(backend, message) {
    return { backend, stored: 0, message };
}
