/**
 * Registry for handling tool events from subprocess agents.
 *
 * Tools can register handlers to:
 * - Extract structured data from their execution results
 * - Trigger subprocess termination on completion
 * - Provide custom rendering for realtime/final display
 */
import { registerSubprocessToolRenderer } from "@rva/tui/tools/subprocess";
/** Registry for subprocess tool handlers */
class SubprocessToolRegistryImpl {
    #handlers = new Map();
    /**
     * Register a handler for a tool's subprocess events.
     */
    register(toolName, handler) {
        this.#handlers.set(toolName, handler);
        registerSubprocessToolRenderer(toolName, {
            renderInline: handler.renderInline,
            renderFinal: handler.renderFinal,
        });
    }
    /**
     * Get the handler for a tool, if registered.
     */
    getHandler(toolName) {
        return this.#handlers.get(toolName);
    }
    /**
     * Check if a tool has a registered handler.
     */
    hasHandler(toolName) {
        return this.#handlers.has(toolName);
    }
    /**
     * Get all registered tool names.
     */
    getRegisteredTools() {
        return Array.from(this.#handlers.keys());
    }
}
/** Singleton registry instance */
export const subprocessToolRegistry = new SubprocessToolRegistryImpl();
