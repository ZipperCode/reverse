/**
 * ClientBridge — abstraction over capabilities provided by an external client
 * (e.g. ACP editor host) that the agent can route through instead of operating
 * directly on the local filesystem / spawning local subprocesses.
 *
 * When `undefined`, tools fall back to local IO. When populated (currently
 * only by `AcpAgent`), tools route requests through the client so it can
 * surface unsaved buffer state, render terminals in the IDE, or gate
 * destructive operations behind user permission prompts.
 */
export {};
