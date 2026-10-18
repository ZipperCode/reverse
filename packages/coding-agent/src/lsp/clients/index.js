import { LspLinterClient } from "./lsp-linter-client";
/**
 * Linter client implementations.
 *
 * The LinterClient interface provides a common API for formatters and linters.
 * Different implementations can use LSP protocol, CLI tools, or other mechanisms.
 */
export { BiomeClient } from "./biome-client";
export { LspLinterClient } from "./lsp-linter-client";
export { SwiftLintClient } from "./swiftlint-client";
// Cache of linter clients by server name + cwd
const clientCache = new Map();
/**
 * Get or create a linter client for a server configuration.
 * Uses the server's custom factory if provided, otherwise falls back to LSP.
 */
export function getLinterClient(serverName, config, cwd) {
    const key = `${serverName}:${cwd}`;
    let client = clientCache.get(key);
    if (client) {
        return client;
    }
    // Use custom factory if provided
    if (config.createClient) {
        client = config.createClient(config, cwd);
    }
    else {
        // Default to LSP
        client = LspLinterClient.create(config, cwd);
    }
    clientCache.set(key, client);
    return client;
}
/**
 * Clear all cached linter clients.
 */
export function clearLinterClientCache() {
    for (const client of clientCache.values()) {
        client.dispose?.();
    }
    clientCache.clear();
}
