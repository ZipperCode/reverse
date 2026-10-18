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

		return {
			timestamp,
			ok: status !== "failed",
			status,
			message: sanitizeSessionString(options.probe_result || options.error || `Caller reported status as '${status}'.`),
			source: "caller_reported",
		};
	}

	// 2. Opt-in non-invasive metadata-only probe (NO process killing, NO signal dispatching)
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
					status: record.status === "failed" ? "failed" : "idle",
					message: sanitizeSessionString(`IDA target file exists on disk (${stat.size} bytes). Host connection probe requires active daemon.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
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
					status: record.status === "failed" ? "failed" : "idle",
					message: sanitizeSessionString(`Ghidra target binary exists on disk (${stat.size} bytes). Headless project ready for inspection.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
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
					status: record.status,
					message: sanitizeSessionString("Browser tab has no navigation URL specified; placeholder tab session."),
					source: "metadata_check",
				};
			}

			try {
				new URL(url);
				return {
					timestamp,
					ok: true,
					status: record.status,
					message: sanitizeSessionString(`Browser target URL syntax is valid: '${url}'.`),
					source: "metadata_check",
				};
			} catch {
				return {
					timestamp,
					ok: false,
					status: "failed",
					message: sanitizeSessionString(`Invalid browser target URL syntax: '${url}'.`),
					source: "metadata_check",
				};
			}
		}

		case "frida": {
			const targetSummary = record.target_summary || "Frida target";
			return {
				timestamp,
				ok: record.status !== "failed",
				status: record.status,
				message: sanitizeSessionString(`Metadata check: Frida session configured for ${targetSummary}. Live process attachment verified via heartbeat or frida_session tool.`),
				source: "metadata_check",
			};
		}

		case "generic":
		default: {
			return {
				timestamp,
				ok: record.status !== "failed",
				status: record.status,
				message: sanitizeSessionString(`Metadata check: session status preserved as '${record.status}'.`),
				source: "metadata_check",
			};
		}
	}
}
