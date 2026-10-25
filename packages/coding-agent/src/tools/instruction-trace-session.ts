import { ToolError } from "@reverse/tui/tools/tool-errors";
import { resolveFridaSessionTarget, type ResolvedFridaSessionTarget } from "./frida-session";

export interface ResolveTraceTargetParams {
	cwd: string;
	sessionId?: string;
	pid?: number;
	process?: string;
	spawn?: string;
	device?: string;
	usb?: boolean;
	host?: string;
	stateRoot?: string;
}

export interface TraceTargetResolution {
	pid?: number;
	process?: string;
	spawn?: string;
	device?: string;
	usb?: boolean;
	host?: string;
	sessionId?: string;
	isLiveActive: boolean;
	activeChildPid?: number;
	resolvedFromSession: boolean;
	sessionResolution?: ResolvedFridaSessionTarget;
}

/**
 * Resolves target parameters for instruction trace capture.
 * If `sessionId` is provided, queries the active live session registry (in-memory)
 * and persisted session store on disk.
 *
 * For spawned targets where an `activeChildPid` exists (running live or recorded),
 * maps the child PID directly to `pid` and omits `spawn` so that the tracer
 * creates an independent Frida attachment to the running child process instead
 * of spawning a duplicate instance with `-f`.
 *
 * User-specified explicit overrides (e.g. pid, process, spawn, device) take precedence.
 */
export async function resolveInstructionTraceTarget(params: ResolveTraceTargetParams): Promise<TraceTargetResolution> {
	let targetPid = params.pid;
	let targetProcess = params.process;
	let targetSpawn = params.spawn;
	let targetDevice = params.device;
	let targetUsb = params.usb;
	let targetHost = params.host;
	let isLiveActive = false;
	let activeChildPid: number | undefined;
	let resolvedFromSession = false;
	let sessionResolution: ResolvedFridaSessionTarget | undefined;

	if (params.sessionId && params.sessionId.trim().length > 0) {
		const resolved = await resolveFridaSessionTarget(params.cwd, params.sessionId, params.stateRoot);
		if (!resolved) {
			throw new ToolError(`Frida session '${params.sessionId}' not found`);
		}

		resolvedFromSession = true;
		sessionResolution = resolved;
		isLiveActive = resolved.isLiveActive;
		activeChildPid = resolved.activeChildPid;

		if (targetPid === undefined) {
			targetPid = resolved.pid;
		}
		if (targetProcess === undefined) {
			targetProcess = resolved.process;
		}
		if (targetSpawn === undefined) {
			targetSpawn = resolved.spawn;
		}
		if (targetDevice === undefined && resolved.device) {
			targetDevice = resolved.device;
		}
		if (targetUsb === undefined && resolved.usb !== undefined) {
			targetUsb = resolved.usb;
		}
		if (targetHost === undefined && resolved.host) {
			targetHost = resolved.host;
		}
	}

	const hasTarget =
		targetPid !== undefined ||
		Boolean(targetProcess && targetProcess.trim().length > 0) ||
		Boolean(targetSpawn && targetSpawn.trim().length > 0);

	if (!hasTarget) {
		throw new ToolError("Must specify a target: 'pid', 'process', 'spawn', or valid 'session_id'");
	}

	return {
		pid: targetPid,
		process: targetProcess,
		spawn: targetSpawn,
		device: targetDevice,
		usb: targetUsb,
		host: targetHost,
		sessionId: params.sessionId,
		isLiveActive,
		activeChildPid,
		resolvedFromSession,
		sessionResolution,
	};
}
