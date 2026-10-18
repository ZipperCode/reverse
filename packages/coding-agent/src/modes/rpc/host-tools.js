import { Snowflake } from "@rva/utils";
import { applyToolProxy } from "../../extensibility/tool-proxy";
import { defaultLoadModeForToolName } from "../../tools/essential-tools";
function isAgentToolResult(value) {
    if (!value || typeof value !== "object")
        return false;
    const content = value.content;
    return Array.isArray(content);
}
export function isRpcHostToolResult(value) {
    if (!value || typeof value !== "object")
        return false;
    const frame = value;
    return frame.type === "host_tool_result" && typeof frame.id === "string" && isAgentToolResult(frame.result);
}
export function isRpcHostToolUpdate(value) {
    if (!value || typeof value !== "object")
        return false;
    const frame = value;
    return frame.type === "host_tool_update" && typeof frame.id === "string" && isAgentToolResult(frame.partialResult);
}
class RpcHostToolAdapter {
    strict = true;
    concurrency = "shared";
    loadMode;
    #bridge;
    #definition;
    constructor(definition, bridge) {
        this.#definition = definition;
        this.#bridge = bridge;
        applyToolProxy(definition, this);
        this.loadMode = defaultLoadModeForToolName(definition.name, definition.loadMode);
    }
    execute(toolCallId, params, signal, onUpdate) {
        return this.#bridge.requestExecution(this.#definition, toolCallId, params, signal, onUpdate);
    }
}
export class RpcHostToolBridge {
    #output;
    #definitions = new Map();
    #pendingCalls = new Map();
    #closedError;
    constructor(output) {
        this.#output = output;
    }
    getToolNames() {
        return Array.from(this.#definitions.keys());
    }
    setTools(tools) {
        this.#definitions = new Map(tools.map(tool => [tool.name, tool]));
        return tools.map(tool => new RpcHostToolAdapter(tool, this));
    }
    handleResult(frame) {
        const pending = this.#pendingCalls.get(frame.id);
        if (!pending)
            return false;
        this.#pendingCalls.delete(frame.id);
        if (frame.isError) {
            const text = frame.result.content
                .filter((item) => item.type === "text" && typeof item.text === "string")
                .map(item => item.text)
                .join("\n")
                .trim();
            pending.reject(new Error(text || "Host tool execution failed"));
            return true;
        }
        pending.resolve(frame.result);
        return true;
    }
    handleUpdate(frame) {
        const pending = this.#pendingCalls.get(frame.id);
        if (!pending)
            return false;
        pending.onUpdate?.(frame.partialResult);
        return true;
    }
    requestExecution(definition, toolCallId, args, signal, onUpdate) {
        if (signal?.aborted) {
            return Promise.reject(new Error(`Host tool "${definition.name}" was aborted`));
        }
        if (this.#closedError) {
            return Promise.reject(this.#closedError);
        }
        const id = Snowflake.next();
        const { promise, resolve, reject } = Promise.withResolvers();
        let settled = false;
        const cleanup = () => {
            signal?.removeEventListener("abort", onAbort);
            this.#pendingCalls.delete(id);
        };
        const onAbort = () => {
            if (settled)
                return;
            settled = true;
            cleanup();
            this.#output({
                type: "host_tool_cancel",
                id: Snowflake.next(),
                targetId: id,
            });
            reject(new Error(`Host tool "${definition.name}" was aborted`));
        };
        signal?.addEventListener("abort", onAbort, { once: true });
        this.#pendingCalls.set(id, {
            resolve: result => {
                if (settled)
                    return;
                settled = true;
                cleanup();
                resolve(result);
            },
            reject: error => {
                if (settled)
                    return;
                settled = true;
                cleanup();
                reject(error);
            },
            onUpdate,
        });
        this.#output({
            type: "host_tool_call",
            id,
            toolCallId,
            toolName: definition.name,
            arguments: args,
        });
        return promise;
    }
    rejectAllPending(message) {
        const error = new Error(message);
        const pendingCalls = Array.from(this.#pendingCalls.values());
        this.#pendingCalls.clear();
        for (const pending of pendingCalls) {
            pending.reject(error);
        }
    }
    /** Reject active and future host tool requests after the RPC client disconnects. */
    close(message) {
        if (!this.#closedError)
            this.#closedError = new Error(message);
        const pendingCalls = Array.from(this.#pendingCalls.values());
        this.#pendingCalls.clear();
        for (const pending of pendingCalls) {
            pending.reject(this.#closedError);
        }
    }
}
