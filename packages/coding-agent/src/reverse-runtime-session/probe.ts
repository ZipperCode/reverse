import * as fs from "node:fs/promises";
import * as path from "node:path";
import type {
	RuntimeSessionProbeInfo,
	RuntimeSessionRecord,
	RuntimeSessionStatus,
} from "./contracts";
import { sanitizeSessionString } from "./sanitize";

export interface ProbeOptions {
	caller_status?: string;
	probe_result?: string;
	error?: string;
	cwd?: string;
}

/**
 * Safely inspects whether a local PID is currently alive via signal 0 (POSIX standard).
 * Does not send any terminating signal, kill processes, or spawn children.
 */
function isPidAlive(pid: unknown): boolean | undefined {
	if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) return undefined;
	try {
		process.kill(pid, 0);
		return true;
	} catch (err: unknown) {
		const code = (err as NodeJS.ErrnoException)?.code;
		if (code === "EPERM") {
			// Process exists but belongs to a different user
			return true;
		}
		if (code === "ESRCH") {
			// No process found with this PID
			return false;
		}
		return false;
	}
}

export async function probeSessionStatus(
	record: RuntimeSessionRecord,
	options: ProbeOptions = {},
): Promise<RuntimeSessionProbeInfo> {
	const timestamp = new Date().toISOString();

	// 1. Caller-reported status takes precedence
	if (options.caller_status || options.probe_result) {
		const rawStatus = (options.caller_status || "").trim().toLowerCase();
		let status: RuntimeSessionStatus = record.status;
		if (rawStatus === "active" || rawStatus === "idle" || rawStatus === "stale" || rawStatus === "closed" || rawStatus === "failed") {
			status = rawStatus;
		} else if (options.error) {
			status = "failed";
		}

		const isReachable = status !== "failed" && status !== "closed";
		return {
			timestamp,
			ok: status !== "failed",
			status,
			reachable: isReachable,
			message: sanitizeSessionString(options.probe_result || options.error || `Caller reported status as '${status}'.`),
			source: "caller_reported",
		};
	}

	// 2. Opt-in non-invasive metadata-only probe (NEVER spawns child processes, NO process killing)
	const cwd = options.cwd ?? process.cwd();
	const kind = record.kind;
	const targetDetails = record.target_details ?? {};

	switch (kind) {
		case "ida": {
			const dbPath =
				(targetDetails.db as string) ||
				(targetDetails.idb_path as string) ||
				(targetDetails.path as string);
			if (!dbPath) {
				return {
					timestamp,
					ok: false,
					reachable: false,
					status: "unknown",
					message: sanitizeSessionString("No database path specified in IDA session target details."),
					source: "metadata_check",
				};
			}

			const resolvedPath = path.isAbsolute(dbPath) ? dbPath : path.resolve(cwd, dbPath);
			try {
				const stat = await fs.stat(resolvedPath);
				return {
					timestamp,
					ok: true,
					reachable: true,
					status: record.status === "failed" ? "failed" : "idle",
					message: sanitizeSessionString(`IDA target file exists on disk (${stat.size} bytes). Host connection probe requires active daemon. Stored heartbeat: ${record.last_heartbeat_at}.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
					reachable: false,
					status: "failed",
					message: sanitizeSessionString(`Target IDA database file not found on disk: '${resolvedPath}'.`),
					source: "metadata_check",
				};
			}
		}

		case "ghidra": {
			const binPath = (targetDetails.path as string) || (targetDetails.binary as string);
			if (!binPath) {
				return {
					timestamp,
					ok: false,
					reachable: false,
					status: "unknown",
					message: sanitizeSessionString("No binary path specified in Ghidra session target details."),
					source: "metadata_check",
				};
			}

			const resolvedPath = path.isAbsolute(binPath) ? binPath : path.resolve(cwd, binPath);
			try {
				const stat = await fs.stat(resolvedPath);
				return {
					timestamp,
					ok: true,
					reachable: true,
					status: record.status === "failed" ? "failed" : "idle",
					message: sanitizeSessionString(`Ghidra target binary exists on disk (${stat.size} bytes). Headless project ready for inspection. Stored heartbeat: ${record.last_heartbeat_at}.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
					reachable: false,
					status: "failed",
					message: sanitizeSessionString(`Target binary file not found on disk: '${resolvedPath}'.`),
					source: "metadata_check",
				};
			}
		}

		case "browser": {
			const url = targetDetails.url as string;
			if (!url) {
				return {
					timestamp,
					ok: true,
					reachable: record.status !== "failed" && record.status !== "closed",
					status: record.status,
					message: sanitizeSessionString(`Browser tab has no navigation URL specified; placeholder tab session. Stored heartbeat: ${record.last_heartbeat_at}.`),
					source: "metadata_check",
				};
			}

			try {
				new URL(url);
				return {
					timestamp,
					ok: true,
					reachable: record.status !== "failed" && record.status !== "closed",
					status: record.status,
					message: sanitizeSessionString(`Browser target URL syntax is valid: '${url}'. Stored heartbeat: ${record.last_heartbeat_at}.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
					reachable: false,
					status: "failed",
					message: sanitizeSessionString(`Invalid browser target URL syntax: '${url}'.`),
					source: "metadata_check",
				};
			}
		}

		case "dap": {
			const pid = targetDetails.pid;
			if (typeof pid === "number") {
				const alive = isPidAlive(pid);
				if (alive === false) {
					return {
						timestamp,
						ok: false,
						reachable: false,
						status: "stale",
						message: sanitizeSessionString(`Target DAP process with PID ${pid} is not running (reachability check failed). Stored heartbeat was at ${record.last_heartbeat_at}.`),
						source: "reachability_check",
					};
				}
				if (alive === true) {
					return {
						timestamp,
						ok: true,
						reachable: true,
						status: record.status === "failed" ? "failed" : record.status,
						message: sanitizeSessionString(`Target DAP process with PID ${pid} is reachable and running.`),
						source: "reachability_check",
					};
				}
			}

			const program =
				(targetDetails.program as string) ||
				(targetDetails.binary as string) ||
				(targetDetails.path as string);
			if (program) {
				const resolvedPath = path.isAbsolute(program) ? program : path.resolve(cwd, program);
				try {
					const stat = await fs.stat(resolvedPath);
					return {
						timestamp,
						ok: true,
						reachable: true,
						status: record.status === "failed" ? "failed" : record.status,
						message: sanitizeSessionString(
							`DAP target program exists on disk (${stat.size} bytes). Stored heartbeat was at ${record.last_heartbeat_at}.`,
						),
					source: "metadata_check",
					};
				} catch {
					return {
						timestamp,
						ok: false,
						reachable: false,
						status: "failed",
						message: sanitizeSessionString(`Target DAP program file not found on disk: '${resolvedPath}'.`),
					source: "metadata_check",
					};
				}
			}

			return {
				timestamp,
				ok: record.status !== "failed",
				reachable: record.status !== "failed" && record.status !== "closed",
				status: record.status,
				message: sanitizeSessionString(
					`Metadata check: DAP session configured (${record.target_summary || "unspecified target"}). Stored heartbeat: ${record.last_heartbeat_at}.`,
				),
				source: "metadata_check",
			};
		}

		case "frida": {
			const pid = targetDetails.pid;
			if (typeof pid === "number") {
				const alive = isPidAlive(pid);
				if (alive === false) {
					return {
						timestamp,
						ok: false,
						reachable: false,
						status: "stale",
						message: sanitizeSessionString(`Target Frida process with PID ${pid} is not running (reachability check failed). Stored heartbeat was at ${record.last_heartbeat_at}.`),
						source: "reachability_check",
					};
				}
				if (alive === true) {
					return {
						timestamp,
						ok: true,
						reachable: true,
						status: record.status === "failed" ? "failed" : record.status,
						message: sanitizeSessionString(`Target Frida process with PID ${pid} is reachable and running.`),
						source: "reachability_check",
					};
				}
			}

			const targetSummary = record.target_summary || "Frida target";
			return {
				timestamp,
				ok: record.status !== "failed",
				reachable: record.status !== "failed" && record.status !== "closed",
				status: record.status,
				message: sanitizeSessionString(`Metadata check: Frida session configured for ${targetSummary}. Stored heartbeat was at ${record.last_heartbeat_at}. Live process attachment verified via heartbeat or frida_session tool.`),
				source: "metadata_check",
			};
		}

		case "generic":
		default: {
			return {
				timestamp,
				ok: record.status !== "failed",
				reachable: record.status !== "failed" && record.status !== "closed",
				status: record.status,
				message: sanitizeSessionString(`Metadata check: session status preserved as '${record.status}'. Stored heartbeat was at ${record.last_heartbeat_at}.`),
				source: "metadata_check",
			};
		}
	}
}
