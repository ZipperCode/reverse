/**
 * MCP (Model Context Protocol) Servers Capability
 *
 * Canonical shape for MCP server configurations, regardless of source format.
 * All providers translate their native format to this shape.
 */
import { defineCapability } from ".";
/** Compare the transport inputs that determine which MCP endpoint gets connected. */
export function isSameMCPConnection(left, right) {
    if (!Bun.deepEquals(left.auth, right.auth) || !Bun.deepEquals(left.oauth, right.oauth))
        return false;
    // Normalize against the allocator's own default so an explicit "number" is
    // equivalent to leaving the option unset, not a distinct connection.
    if ((left.requestIdFormat ?? "number") !== (right.requestIdFormat ?? "number"))
        return false;
    const leftTransport = left.transport ?? (left.command ? "stdio" : left.url ? "http" : "stdio");
    const rightTransport = right.transport ?? (right.command ? "stdio" : right.url ? "http" : "stdio");
    if (leftTransport !== rightTransport)
        return false;
    if (leftTransport === "stdio") {
        // Effective literal keys: `envPolicy: "literal"` makes every env value
        // literal (equivalent to an envLiteralKeys set covering all keys), and an
        // inert policy on an env-less server must not distinguish otherwise
        // identical connections. Insertion order is irrelevant; compare as sets.
        const literalKeysOf = (server) => server.envPolicy === "literal"
            ? Object.keys(server.env ?? {}).sort()
            : [...(server.envLiteralKeys ?? [])].sort();
        return (left.command === right.command &&
            Bun.deepEquals(left.args, right.args) &&
            Bun.deepEquals(left.env, right.env) &&
            Bun.deepEquals(literalKeysOf(left), literalKeysOf(right)) &&
            left.cwd === right.cwd);
    }
    return left.url === right.url && Bun.deepEquals(left.headers, right.headers);
}
export const mcpCapability = defineCapability({
    id: "mcps",
    displayName: "MCP Servers",
    description: "Model Context Protocol server configurations for external tool integrations",
    key: server => server.name,
    equivalent: isSameMCPConnection,
    toExtensionId: server => `mcp:${server.name}`,
    validate: server => {
        if (!server.name)
            return "Missing server name";
        if (!server.command && !server.url)
            return "Must have command or url";
        // Validate transport-endpoint pairing
        if (server.transport === "stdio" && !server.command) {
            return "stdio transport requires command field";
        }
        if ((server.transport === "http" || server.transport === "sse") && !server.url) {
            return "http/sse transport requires url field";
        }
        return undefined;
    },
});
