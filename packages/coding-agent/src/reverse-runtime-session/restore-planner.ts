import type {
	RestorePlan,
	RuntimeSessionKind,
	RuntimeSessionRecord,
} from "./contracts";

export function generateRestorePlan(record: RuntimeSessionRecord): RestorePlan {
	const kind = record.kind;
	const targetDetails = record.target_details ?? {};
	const connection = record.connection ?? {};
	const customHints = record.recovery_hints;

	switch (kind) {
		case "frida": {
			const restoreParams: Record<string, unknown> = {};
			if (typeof targetDetails.pid === "number") restoreParams.pid = targetDetails.pid;
			if (typeof targetDetails.process === "string") restoreParams.process = targetDetails.process;
			if (typeof targetDetails.spawn === "string") restoreParams.spawn = targetDetails.spawn;
			if (typeof targetDetails.device === "string") restoreParams.device = targetDetails.device;
			if (typeof targetDetails.usb === "boolean") restoreParams.usb = targetDetails.usb;
			if (typeof connection.host === "string") restoreParams.host = connection.host;
			if (typeof targetDetails.script_path === "string") restoreParams.script_path = targetDetails.script_path;

			const instructions = [
				"1. Verify target process or application package is running or installable on the target host/device.",
				"2. Invoke frida_session(action: 'create', ...) with the preserved target parameters.",
				"3. Once connected, reload instrumentation scripts via frida_session(action: 'run', ...).",
				"4. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" + record.id + "') to mark session active.",
			];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Object.keys(restoreParams).length > 0,
				restore_tool: "frida_session",
				restore_action: "create",
				restore_params: restoreParams,
				instructions,
				prerequisites: ["frida-tools installed on PATH", "Target process or device reachable"],
				reasoning: "Re-attaches or respawns target instrumentation session via native frida_session tool using preserved target parameters.",
			};
		}

		case "browser": {
			const restoreParams: Record<string, unknown> = {};
			const nameVal = typeof targetDetails.name === "string" ? targetDetails.name : undefined;
			const tabNameVal = typeof targetDetails.tab_name === "string" ? targetDetails.tab_name : undefined;
			const tabName = nameVal || tabNameVal || "main";
			restoreParams.name = tabName;
			if (typeof targetDetails.url === "string") restoreParams.url = targetDetails.url;
			if (typeof targetDetails.headed === "boolean") restoreParams.headed = targetDetails.headed;
			if (typeof connection.cdp_url === "string") {
				restoreParams.app = { cdp_url: connection.cdp_url };
			}

			const urlStr = typeof restoreParams.url === "string" ? restoreParams.url : "";
			const instructions = [
				`1. Invoke browser(action: 'open', name: '${tabName}', url: '${urlStr}') to restore tab context.`,
				"2. Wait for initial page DOM and network state to settle before issuing further interactions.",
				"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" + record.id + "') to mark session active.",
			];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(restoreParams.url || connection.cdp_url),
				restore_tool: "browser",
				restore_action: "open",
				restore_params: restoreParams,
				instructions,
				prerequisites: ["Chromium executable available", "Target URL reachable"],
				reasoning: "Re-opens managed browser tab with preserved URL and display configuration.",
			};
		}

		case "ida": {
			const restoreParams: Record<string, unknown> = {};
			let dbPath: string | undefined;
			if (typeof targetDetails.db === "string") dbPath = targetDetails.db;
			else if (typeof targetDetails.idb_path === "string") dbPath = targetDetails.idb_path;
			else if (typeof targetDetails.path === "string") dbPath = targetDetails.path;
			else if (typeof connection.db === "string") dbPath = connection.db;
			if (dbPath) restoreParams.db = dbPath;

			const instructions = [
				`1. Verify target database (.i64/.idb) or binary exists on disk at '${dbPath || "(unspecified)"}'.`,
				"2. Invoke ida(action: 'list') to check active databases, or ida(action: 'open', db: '...') to re-attach.",
				"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" + record.id + "') to mark session active.",
			];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(dbPath),
				restore_tool: "ida",
				restore_action: "open",
				restore_params: restoreParams,
				instructions,
				prerequisites: ["IDA Pro host daemon available", "Target database file intact on disk"],
				reasoning: "Re-attaches to IDA Pro database session using preserved database locator.",
			};
		}

		case "ghidra": {
			const restoreParams: Record<string, unknown> = {};
			let binPath: string | undefined;
			if (typeof targetDetails.path === "string") binPath = targetDetails.path;
			else if (typeof targetDetails.binary === "string") binPath = targetDetails.binary;
			if (binPath) restoreParams.path = binPath;
			if (typeof targetDetails.project_dir === "string") restoreParams.project_dir = targetDetails.project_dir;

			const instructions = [
				`1. Verify target binary exists on disk at '${binPath || "(unspecified)"}'.`,
				"2. Invoke ghidra_inspect(action: 'info', path: '...') to re-initialize Ghidra headless analysis project.",
				"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" + record.id + "') to mark session active.",
			];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(binPath),
				restore_tool: "ghidra_inspect",
				restore_action: "info",
				restore_params: restoreParams,
				instructions,
				prerequisites: ["Ghidra analyzeHeadless script on PATH", "Java 17+ installed", "Target binary intact"],
				reasoning: "Re-initiates Ghidra headless inspection project using target binary path.",
			};
		}

		case "generic":
		default: {
			const hasCustom = customHints && customHints.restore_tool && customHints.restore_action;
			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(hasCustom),
				restore_tool: customHints?.restore_tool || "unknown",
				restore_action: customHints?.restore_action || "restore",
				restore_params: customHints?.restore_params || targetDetails,
				instructions: customHints?.instructions?.length
					? customHints.instructions
					: [
							"1. Verify session target prerequisites and network/process connectivity.",
							"2. Re-instantiate session using the respective runtime tool.",
							"3. Send a heartbeat to reverse_runtime_session to mark session active.",
						],
				prerequisites: customHints?.prerequisites ?? [],
				reasoning: hasCustom
					? "Executes caller-specified recovery hints for generic runtime session."
					: "Generic session without specific recovery hints; manual re-initialization required.",
			};
		}
	}
}
