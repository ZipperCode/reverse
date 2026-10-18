/**
 * MCP Client.
 *
 * Handles connection initialization, tool listing, and tool calling.
 */
import * as path from "node:path";
import * as url from "node:url";
import { getProjectDir, logger, untilAborted, withTimeout } from "@rva/utils";
import { describeMCPTimeout, isMCPTimeoutEnabled, resolveMCPTimeoutMs } from "./timeout";
import { createHttpTransport } from "./transports/http";
import { LegacySseConnectionTimeoutError, createSseTransport } from "./transports/sse";
import { createStdioTransport } from "./transports/stdio";
import { MCP_PROTOCOL_VERSION } from "./types";
/** Client info sent during initialization */
const CLIENT_INFO = {
    name: "omp-coding-agent",
    version: "1.0.0",
};
/**
 * Default handler for standard MCP server-to-client requests.
 * Handles `ping` and `roots/list`; rejects unknown methods with -32601.
 * Reads getProjectDir() at call time so the root stays stable even if
 * the process cwd changes during tool execution.
 */
async function defaultRequestHandler(method, _params) {
    switch (method) {
        case "ping":
            return {};
        case "roots/list": {
            const cwd = getProjectDir();
            return {
                roots: [{ uri: url.pathToFileURL(cwd).href, name: path.basename(cwd) }],
            };
        }
        default:
            throw Object.assign(new Error(`Unsupported server request: ${method}`), { code: -32601 });
    }
}
/**
 * Create a transport for the given server config.
 */
async function createTransport(config, signal) {
    const serverType = config.type ?? "stdio";
    switch (serverType) {
        case "stdio":
            return createStdioTransport(config);
        case "http":
            return createHttpTransport(config);
        case "sse":
            return createSseTransport(config, signal);
        default:
            throw new Error(`Unknown server type: ${serverType}`);
    }
}
/**
 * Initialize connection with MCP server.
 */
async function initializeConnection(transport, options) {
    const params = {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {
            roots: { listChanged: false },
        },
        clientInfo: CLIENT_INFO,
    };
    const result = await transport.request("initialize", params, { signal: options?.signal });
    if (options?.signal?.aborted) {
        throw options.signal.reason instanceof Error ? options.signal.reason : new Error("Aborted");
    }
    // Echo the negotiated protocol version on every subsequent request. The MCP
    // Streamable HTTP spec requires the MCP-Protocol-Version header after
    // initialize; transports that don't need it ignore this.
    transport.setProtocolVersion?.(result.protocolVersion);
    // Send initialized before opening the optional GET SSE stream. Servers may
    // reject or terminate sessions that receive session traffic before this
    // notification; POST response streams already carry messages during setup.
    await transport.notify("notifications/initialized");
    await options?.onInitialized?.();
    return result;
}
/** Identifies an MCP server whose initial handshake exceeded its configured timeout. */
export class MCPConnectionTimeoutError extends Error {
    serverName;
    timeoutMs;
    constructor(serverName, timeoutMs) {
        super(`Connection to MCP server "${serverName}" timed out after ${describeMCPTimeout(timeoutMs)}`);
        this.name = "MCPConnectionTimeoutError";
        this.serverName = serverName;
        this.timeoutMs = timeoutMs;
    }
}
/**
 * Connect to an MCP server.
 * Has a 30 second timeout by default to prevent blocking startup.
 * Set OMP_MCP_TIMEOUT_MS=0 to disable MCP client-side timeouts.
 */
export async function connectToServer(name, config, options) {
    // `withTimeout` rejects a pre-aborted signal without observing `connect()`; never start one.
    options?.signal?.throwIfAborted();
    const timeoutMs = resolveMCPTimeoutMs(config.timeout);
    const timeoutError = new MCPConnectionTimeoutError(name, timeoutMs);
    let transport;
    const connect = async () => {
        transport = await createTransport(config, options?.signal);
        if (options?.onNotification) {
            transport.onNotification = options.onNotification;
        }
        // Always handle standard MCP server-to-client requests (ping, roots/list).
        // The initialize request declares roots capability, so we must respond to
        // roots/list — even for short-lived test connections.
        transport.onRequest = options?.onRequest ?? defaultRequestHandler;
        try {
            const initResult = await initializeConnection(transport, {
                signal: options?.signal,
                async onInitialized() {
                    // Open the optional GET SSE stream only after the initialized
                    // notification makes the session ready for further traffic.
                    if ("startSSEListener" in transport && typeof transport.startSSEListener === "function") {
                        await transport.startSSEListener();
                    }
                },
            });
            return {
                name,
                config,
                transport,
                serverInfo: initResult.serverInfo,
                capabilities: initResult.capabilities,
                instructions: initResult.instructions,
            };
        }
        catch (error) {
            await transport.close();
            throw error;
        }
    };
    try {
        // Race the whole handshake against the signal: the steps after `initialize` (the
        // initialized notification, the SSE listener) do not observe it themselves.
        if (!isMCPTimeoutEnabled(timeoutMs)) {
            return await untilAborted(options?.signal, connect());
        }
        return await withTimeout(connect(), timeoutMs, timeoutError, options?.signal);
    }
    catch (error) {
        // If the timeout or the signal won while connect() was still pending,
        // the transport may be alive with an open SSE listener. Close it.
        if (transport) {
            void transport.close().catch(() => { });
        }
        throw error instanceof LegacySseConnectionTimeoutError ? timeoutError : error;
    }
}
/**
 * List tools from a connected server.
 */
export async function listTools(connection, options) {
    // Check if server supports tools
    if (!connection.capabilities.tools) {
        return [];
    }
    // Return cached tools if available
    if (connection.tools) {
        return connection.tools;
    }
    const allTools = [];
    let cursor;
    do {
        const params = {};
        if (cursor) {
            params.cursor = cursor;
        }
        const result = await connection.transport.request("tools/list", params, options);
        allTools.push(...result.tools);
        cursor = result.nextCursor;
    } while (cursor);
    // Cache tools
    connection.tools = allTools;
    return allTools;
}
/**
 * Call a tool on a connected server.
 */
export async function callTool(connection, toolName, args = {}, options) {
    const params = {
        name: toolName,
        arguments: args,
    };
    return connection.transport.request("tools/call", params, options);
}
/**
 * Disconnect from a server.
 */
export async function disconnectServer(connection) {
    await connection.transport.close();
}
/**
 * Check if a server supports tools.
 */
export function serverSupportsTools(capabilities) {
    return capabilities.tools !== undefined;
}
/**
 * List resources from a connected server.
 */
export async function listResources(connection, options) {
    if (!connection.capabilities.resources) {
        return [];
    }
    if (connection.resources) {
        return connection.resources;
    }
    const allResources = [];
    let cursor;
    do {
        const params = {};
        if (cursor) {
            params.cursor = cursor;
        }
        const result = await connection.transport.request("resources/list", params, options);
        allResources.push(...result.resources);
        cursor = result.nextCursor;
    } while (cursor);
    connection.resources = allResources;
    return allResources;
}
/** True when an error is a JSON-RPC "method not found" (-32601) response. */
function isMethodNotFoundError(error) {
    const message = error instanceof Error ? error.message : String(error);
    return message.includes("-32601") || /method not found/i.test(message);
}
/**
 * List resource templates from a connected server.
 *
 * A server MAY advertise the `resources` capability without implementing the
 * optional `resources/templates/list` method (it is optional in the MCP spec).
 * Such servers reject the request with JSON-RPC -32601 ("Method not found").
 * Treat that as "no templates" and return `[]` rather than throwing — otherwise
 * a caller that loads resources and templates together (see `MCPManager`'s
 * `Promise.all([listResources, listResourceTemplates])`) would discard the
 * server's concrete resources too. Any other error still propagates.
 */
export async function listResourceTemplates(connection, options) {
    if (!connection.capabilities.resources) {
        return [];
    }
    if (connection.resourceTemplates) {
        return connection.resourceTemplates;
    }
    const allTemplates = [];
    let cursor;
    try {
        do {
            const params = {};
            if (cursor) {
                params.cursor = cursor;
            }
            const result = await connection.transport.request("resources/templates/list", params, options);
            allTemplates.push(...result.resourceTemplates);
            cursor = result.nextCursor;
        } while (cursor);
    }
    catch (error) {
        // A server that doesn't implement the optional templates method answers
        // -32601; cache an empty list so we neither retry nor let the failure
        // bubble up and discard the server's concrete resources.
        if (isMethodNotFoundError(error)) {
            connection.resourceTemplates = [];
            return [];
        }
        throw error;
    }
    connection.resourceTemplates = allTemplates;
    return allTemplates;
}
/**
 * Read a resource from a connected server.
 */
export async function readResource(connection, uri, options) {
    const params = { uri };
    return connection.transport.request("resources/read", params, options);
}
/**
 * Subscribe to resource update notifications.
 */
export async function subscribeToResources(connection, uris, options) {
    if (uris.length === 0 || !connection.capabilities.resources?.subscribe)
        return;
    const results = await Promise.allSettled(uris.map(uri => {
        const params = { uri };
        return connection.transport.request("resources/subscribe", params, options);
    }));
    for (const result of results) {
        if (result.status === "rejected") {
            logger.warn("Failed to subscribe to MCP resource", { error: result.reason });
        }
    }
}
/**
 * Unsubscribe from resource update notifications.
 */
export async function unsubscribeFromResources(connection, uris, options) {
    if (uris.length === 0 || !connection.capabilities.resources?.subscribe)
        return;
    const results = await Promise.allSettled(uris.map(uri => {
        const params = { uri };
        return connection.transport.request("resources/unsubscribe", params, options);
    }));
    for (const result of results) {
        if (result.status === "rejected") {
            logger.warn("Failed to unsubscribe from MCP resource", { error: result.reason });
        }
    }
}
/**
 * Check if a server supports resource subscriptions.
 */
export function serverSupportsResourceSubscriptions(capabilities) {
    return capabilities.resources?.subscribe === true;
}
/**
 * Check if a server supports resources.
 */
export function serverSupportsResources(capabilities) {
    return capabilities.resources !== undefined;
}
/**
 * List prompts from a connected server.
 */
export async function listPrompts(connection, options) {
    if (!connection.capabilities.prompts) {
        return [];
    }
    if (connection.prompts) {
        return connection.prompts;
    }
    const allPrompts = [];
    let cursor;
    do {
        const params = {};
        if (cursor) {
            params.cursor = cursor;
        }
        const result = await connection.transport.request("prompts/list", params, options);
        allPrompts.push(...result.prompts);
        cursor = result.nextCursor;
    } while (cursor);
    connection.prompts = allPrompts;
    return allPrompts;
}
/**
 * Get a specific prompt from a connected server.
 */
export async function getPrompt(connection, name, args, options) {
    const params = { name };
    if (args && Object.keys(args).length > 0) {
        params.arguments = args;
    }
    return connection.transport.request("prompts/get", params, options);
}
/**
 * Check if a server supports prompts.
 */
export function serverSupportsPrompts(capabilities) {
    return capabilities.prompts !== undefined;
}
