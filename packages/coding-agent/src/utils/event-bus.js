import { logger } from "@rva/utils";
export class EventBus {
    #listeners = new Map();
    emit(channel, data) {
        const handlers = this.#listeners.get(channel);
        if (handlers) {
            for (const handler of handlers) {
                handler(data);
            }
        }
    }
    on(channel, handler) {
        if (!this.#listeners.has(channel)) {
            this.#listeners.set(channel, new Set());
        }
        const safeHandler = async (data) => {
            try {
                await handler(data);
            }
            catch (err) {
                logger.error("Event handler error", { channel, error: String(err) });
            }
        };
        this.#listeners.get(channel).add(safeHandler);
        return () => this.#listeners.get(channel)?.delete(safeHandler);
    }
    clear() {
        this.#listeners.clear();
    }
}
/**
 * Publishes a subagent frame on the session bus and the observability bus.
 * SDK embedders may pass the same EventBus for both slots; the identity check
 * skips the aliased re-emit so listeners never see duplicate frames.
 */
export function emitSubagentFrame(eventBus, subagentEventBus, channel, payload) {
    eventBus?.emit(channel, payload);
    if (subagentEventBus && subagentEventBus !== eventBus) {
        subagentEventBus.emit(channel, payload);
    }
}
