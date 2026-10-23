/**
 * Runtime capability and MCP lifecycle state tracking.
 *
 * Tracks independent, verifiable facts per session:
 * - configured (from config)
 * - connected (from active transport)
 * - discovered (tools exposed by server)
 * - targetMatched (server bound to specific target)
 * - executions (concrete tool executions with envelope and inner results)
 * - skillLoads (skill body reads with loaded/failure facts)
 *
 * Strictly session-scoped via WeakMap. No process-global fallback.
 */

export interface SkillLoadRecord {
	name: string;
	loaded: boolean;
	timestamp: number;
	error?: string;
	fallback?: string;
}

export interface McpToolExecutionRecord {
	tool: string;
	timestamp: number;
	isError: boolean;
	innerSuccess: boolean | null;
	target?: string;
	error?: string;
}

export interface McpServerRuntimeState {
	connection?: object;
	targetMatched: boolean;
	target?: string;
	executionCount: number;
	lastExecution?: McpToolExecutionRecord;
}

export interface SessionCapabilityState {
	skills: Map<string, SkillLoadRecord>;
	mcpServers: Map<string, McpServerRuntimeState>;
}

interface SessionScope {
	sessionId?: string;
	state: SessionCapabilityState;
}

const sessionScopes = new WeakMap<object, SessionScope>();

function extractSessionId(key: object): string | undefined {
	if ("getSessionId" in key && typeof (key as { getSessionId?: () => unknown }).getSessionId === "function") {
		const id = (key as { getSessionId: () => unknown }).getSessionId();
		if (typeof id === "string") return id;
	}
	if ("sessionManager" in key && key.sessionManager && typeof key.sessionManager === "object") {
		const sm = key.sessionManager as { getSessionId?: () => unknown };
		if (typeof sm.getSessionId === "function") {
			const id = sm.getSessionId();
			if (typeof id === "string") return id;
		}
	}
	return undefined;
}

export function getSessionCapabilityState(sessionKey: object): SessionCapabilityState {
	const currentId = extractSessionId(sessionKey);
	let scope = sessionScopes.get(sessionKey);
	if (!scope || (currentId !== undefined && scope.sessionId !== currentId)) {
		scope = {
			sessionId: currentId,
			state: {
				skills: new Map<string, SkillLoadRecord>(),
				mcpServers: new Map<string, McpServerRuntimeState>(),
			},
		};
		sessionScopes.set(sessionKey, scope);
	}
	return scope.state;
}

export function recordSkillLoad(
	name: string,
	details: { loaded: boolean; error?: string; fallback?: string },
	sessionKey: object,
): SkillLoadRecord {
	const normalized = name.trim().toLowerCase();
	const state = getSessionCapabilityState(sessionKey);
	const record: SkillLoadRecord = {
		name: normalized,
		loaded: details.loaded,
		timestamp: Date.now(),
		error: details.error,
		fallback: details.fallback,
	};
	state.skills.set(normalized, record);
	return record;
}

export function getRecordedSkillLoads(sessionKey: object): SkillLoadRecord[] {
	const state = getSessionCapabilityState(sessionKey);
	return Array.from(state.skills.values()).sort((a, b) => a.timestamp - b.timestamp);
}

export function setMcpTargetBinding(
	serverName: string,
	binding: { targetMatched: boolean; target?: string },
	sessionKey: object,
	connection?: object,
): McpServerRuntimeState {
	const key = serverName.trim().toLowerCase();
	const state = getSessionCapabilityState(sessionKey);
	let serverState = state.mcpServers.get(key);
	if (!serverState) {
		serverState = { connection, targetMatched: false, executionCount: 0 };
		state.mcpServers.set(key, serverState);
	}
	// Connection change invalidates previous connection's state
	if (connection && serverState.connection && serverState.connection !== connection) {
		serverState.executionCount = 0;
		serverState.lastExecution = undefined;
		serverState.target = undefined;
		serverState.targetMatched = false;
	}
	if (connection) {
		serverState.connection = connection;
	}
	// Rebinding to a different target or unbinding clears old execution records
	const isTargetChange = Boolean(binding.target && serverState.target && serverState.target !== binding.target);
	const isUnbinding = serverState.targetMatched && !binding.targetMatched;
	if (isTargetChange || isUnbinding) {
		serverState.executionCount = 0;
		serverState.lastExecution = undefined;
	}
	serverState.targetMatched = binding.targetMatched;
	if (binding.target) {
		serverState.target = binding.target;
	} else if (!binding.targetMatched) {
		serverState.target = undefined;
	}
	return serverState;
}

export function recordMcpToolExecution(
	serverName: string,
	execution: McpToolExecutionRecord,
	sessionKey: object,
	connection?: object,
): McpServerRuntimeState {
	const key = serverName.trim().toLowerCase();
	const state = getSessionCapabilityState(sessionKey);
	let serverState = state.mcpServers.get(key);
	if (!serverState) {
		serverState = { connection, targetMatched: false, executionCount: 0 };
		state.mcpServers.set(key, serverState);
	}
	// Connection change invalidates previous connection's state
	if (connection && serverState.connection && serverState.connection !== connection) {
		serverState.executionCount = 0;
		serverState.lastExecution = undefined;
		serverState.target = undefined;
		serverState.targetMatched = false;
	}
	if (connection) {
		serverState.connection = connection;
	}
	serverState.lastExecution = execution;
	serverState.executionCount += 1;
	return serverState;
}

export function getMcpServerRuntimeState(
	serverName: string,
	sessionKey: object,
): McpServerRuntimeState | undefined {
	const state = getSessionCapabilityState(sessionKey);
	return state.mcpServers.get(serverName.trim().toLowerCase());
}

export function resetSessionCapabilityState(sessionKey: object): void {
	sessionScopes.delete(sessionKey);
}
