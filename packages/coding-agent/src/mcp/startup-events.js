import { isRecord, sanitizeText } from "@rva/utils";
import { replaceTabs, shortenEmbeddedPaths, shortenPath, TRUNCATE_LENGTHS, truncateToWidth, } from "@rva/tui/render/render-utils";
export const MCP_CONNECTION_STATUS_EVENT_CHANNEL = "mcp:connection-status";
function sanitizeMcpStatusText(value, maxWidth) {
    const text = shortenEmbeddedPaths(replaceTabs(sanitizeText(value))
        .replace(/[\r\n]+/g, " ")
        .trim());
    return truncateToWidth(text.length > 0 ? text : "(unnamed)", maxWidth);
}
function sanitizeMcpServerName(serverName) {
    return sanitizeMcpStatusText(serverName, TRUNCATE_LENGTHS.SHORT);
}
function formatServerList(serverNames) {
    return serverNames.map(sanitizeMcpServerName).join(", ");
}
function formatServerCount(count) {
    return count === 1 ? "server" : "servers";
}
function sanitizeMcpStatusError(error) {
    return sanitizeMcpStatusText(error, TRUNCATE_LENGTHS.CONTENT);
}
export function formatMCPConnectingMessage(serverNames) {
    return `Connecting to MCP servers: ${formatServerList(serverNames)}…`;
}
function formatFailedServer({ serverName, error, sourcePath }) {
    const source = sourcePath
        ? ` [config: ${sanitizeMcpStatusText(shortenPath(sourcePath), TRUNCATE_LENGTHS.CONTENT)}]`
        : "";
    return `${sanitizeMcpServerName(serverName)}${source}: ${sanitizeMcpStatusError(error)}`;
}
export function formatMCPConnectionStatusMessage(snapshot) {
    const { pendingServers, connectedServers, failedServers } = snapshot;
    if (pendingServers.length > 0) {
        if (connectedServers.length === 0 && failedServers.length === 0) {
            return formatMCPConnectingMessage(pendingServers);
        }
        const parts = [];
        if (connectedServers.length > 0) {
            parts.push(`Connected: ${formatServerList(connectedServers)}.`);
        }
        if (failedServers.length > 0) {
            parts.push(`Failed: ${failedServers.map(formatFailedServer).join("; ")}.`);
        }
        parts.push(`Still connecting: ${formatServerList(pendingServers)}…`);
        return parts.join(" ");
    }
    if (failedServers.length > 0) {
        const failureText = failedServers.map(formatFailedServer).join("; ");
        if (connectedServers.length === 0) {
            return `MCP ${formatServerCount(failedServers.length)} failed to connect: ${failureText}`;
        }
        return `MCP finished with failures. Connected: ${formatServerList(connectedServers)}. Failed: ${failureText}`;
    }
    if (connectedServers.length > 0) {
        return `Connected to MCP ${formatServerCount(connectedServers.length)}: ${formatServerList(connectedServers)}.`;
    }
    return "";
}
function isStringArray(data) {
    return Array.isArray(data) && data.every(item => typeof item === "string");
}
/**
 * Runtime validator for the cross-module event payload. The event bus is
 * untyped at runtime, so the subscriber verifies the shape before formatting
 * rather than trusting a cast — a malformed emit is ignored instead of throwing.
 */
export function isMcpConnectionStatusEvent(data) {
    if (!isRecord(data) || typeof data.type !== "string")
        return false;
    switch (data.type) {
        case "connecting":
            return isStringArray(data.serverNames);
        case "reconnecting":
            return typeof data.serverName === "string";
        case "connected":
            return typeof data.serverName === "string";
        case "failed":
            return (typeof data.serverName === "string" &&
                typeof data.error === "string" &&
                (data.sourcePath === undefined || typeof data.sourcePath === "string"));
        default:
            return false;
    }
}
