export const MCP_CONFIG_SCHEMA_URL = "https://raw.githubusercontent.com/can1357/oh-my-pi/main/packages/coding-agent/src/config/mcp-schema.json";
// =============================================================================
// MCP Protocol Types
// =============================================================================
/**
 * Latest MCP protocol revision this client negotiates.
 *
 * Sent as `protocolVersion` in the `initialize` request and, for Streamable
 * HTTP, echoed back to the server in the `MCP-Protocol-Version` header on every
 * subsequent request (per the MCP HTTP transport spec). Must track the current
 * stable revision: AWS Bedrock AgentCore Gateway refuses tool calls on an
 * outbound per-user OAuth (`AUTHORIZATION_CODE`) target below `2025-11-25`, and
 * it checks the version *before* consulting its token vault, so an older client
 * is refused even for a caller whose consent is already stored.
 */
export const MCP_PROTOCOL_VERSION = "2025-11-25";
// =============================================================================
// MCP Notification Method Names
// =============================================================================
/** MCP server notification method names */
export const MCPNotificationMethods = {
    TOOLS_LIST_CHANGED: "notifications/tools/list_changed",
    RESOURCES_LIST_CHANGED: "notifications/resources/list_changed",
    RESOURCES_UPDATED: "notifications/resources/updated",
    PROMPTS_LIST_CHANGED: "notifications/prompts/list_changed",
};
/** Extract a JsonRpcError from a thrown value. Preserves `.code` and `.message` from Error instances or plain objects. */
export function toJsonRpcError(error) {
    if (error instanceof Error) {
        const code = "code" in error && typeof error.code === "number" ? error.code : -32603;
        return { code, message: error.message };
    }
    if (typeof error === "object" && error !== null) {
        const obj = error;
        if (typeof obj.code === "number" && typeof obj.message === "string") {
            return { code: obj.code, message: obj.message };
        }
    }
    return { code: -32603, message: "Internal error" };
}
