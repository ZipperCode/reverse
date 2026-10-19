import type { RestorePlan, RuntimeSessionRecord } from "./contracts";

export function generateRestorePlan(record: RuntimeSessionRecord): RestorePlan {
	const kind = record.kind;
	const targetDetails = record.target_details ?? {};
	const connection = record.connection ?? {};
	const customHints = record.recovery_hints;

	switch (kind) {
		case "frida": {
			const restoreTool = customHints?.restore_tool || "frida_session";
			const restoreAction = customHints?.restore_action || "create";
			const restoreParams: Record<string, unknown> = {
				...customHints?.restore_params,
			};
			if (typeof targetDetails.pid === "number" && restoreParams.pid === undefined)
				restoreParams.pid = targetDetails.pid;
			if (typeof targetDetails.process === "string" && restoreParams.process === undefined)
				restoreParams.process = targetDetails.process;
			if (typeof targetDetails.spawn === "string" && restoreParams.spawn === undefined)
				restoreParams.spawn = targetDetails.spawn;
			if (typeof targetDetails.device === "string" && restoreParams.device === undefined)
				restoreParams.device = targetDetails.device;
			if (typeof targetDetails.usb === "boolean" && restoreParams.usb === undefined)
				restoreParams.usb = targetDetails.usb;
			if (typeof connection.host === "string" && restoreParams.host === undefined)
				restoreParams.host = connection.host;
			if (typeof targetDetails.script_path === "string" && restoreParams.script_path === undefined)
				restoreParams.script_path = targetDetails.script_path;

			const instructions = customHints?.instructions?.length
				? customHints.instructions
				: [
						"1. Verify target process or application package is running or installable on the target host/device.",
						`2. Invoke ${restoreTool}(action: '${restoreAction}', ...) with the preserved target parameters.`,
						`3. Once connected, reload instrumentation scripts via ${restoreTool}(action: 'run', ...).`,
						"4. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" +
							record.id +
							"') to mark session active.",
					];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Object.keys(restoreParams).length > 0,
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
				instructions,
				prerequisites: customHints?.prerequisites ?? [
					"frida-tools installed on PATH",
					"Target process or device reachable",
				],
				reasoning: customHints?.restore_tool
					? "Restores Frida instrumentation session using caller-specified recovery hints."
					: "Re-attaches or respawns target instrumentation session via native frida_session tool using preserved target parameters.",
			};
		}

		case "browser": {
			const hasExplicitTool = typeof customHints?.restore_tool === "string" && customHints.restore_tool.length > 0;
			const isBrowserReverse =
				(hasExplicitTool && customHints.restore_tool === "browser_reverse_session") ||
				(!hasExplicitTool &&
					(typeof targetDetails.tab_name === "string" ||
						typeof targetDetails.tabName === "string" ||
						typeof customHints?.restore_params?.tab_name === "string"));

			const restoreTool = hasExplicitTool
				? customHints.restore_tool
				: isBrowserReverse
					? "browser_reverse_session"
					: "browser";

			const restoreAction = customHints?.restore_action || "open";

			const tabName =
				(typeof customHints?.restore_params?.tab_name === "string" && customHints.restore_params.tab_name) ||
				(typeof targetDetails.tab_name === "string" && targetDetails.tab_name) ||
				(typeof targetDetails.tabName === "string" && targetDetails.tabName) ||
				(typeof customHints?.restore_params?.name === "string" && customHints.restore_params.name) ||
				(typeof targetDetails.name === "string" && targetDetails.name) ||
				"main";

			const restoreParams: Record<string, unknown> = {
				...customHints?.restore_params,
			};

			if (restoreTool === "browser_reverse_session") {
				restoreParams.tab_name = tabName;
			} else {
				restoreParams.name = tabName;
			}

			if (typeof targetDetails.url === "string" && restoreParams.url === undefined) {
				restoreParams.url = targetDetails.url;
			}
			if (typeof targetDetails.headed === "boolean" && restoreParams.headed === undefined) {
				restoreParams.headed = targetDetails.headed;
			}
			if (typeof connection.cdp_url === "string" && restoreParams.app === undefined) {
				restoreParams.app = { cdp_url: connection.cdp_url };
			}

			const urlStr = typeof restoreParams.url === "string" ? restoreParams.url : "";
			const tabArg = restoreTool === "browser_reverse_session" ? `tab_name: '${tabName}'` : `name: '${tabName}'`;
			const instructions = customHints?.instructions?.length
				? customHints.instructions
				: [
						`1. Invoke ${restoreTool}(action: '${restoreAction}', ${tabArg}, url: '${urlStr}') to restore tab context.`,
						"2. Wait for initial page DOM and network state to settle before issuing further interactions.",
						"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" +
							record.id +
							"') to mark session active.",
					];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(
					restoreParams.url || connection.cdp_url || restoreParams.tab_name || restoreParams.name,
				),
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
				instructions,
				prerequisites: customHints?.prerequisites ?? ["Chromium executable available", "Target URL reachable"],
				reasoning: hasExplicitTool
					? "Restores browser session using explicit recovery hints."
					: restoreTool === "browser_reverse_session"
						? "Re-opens managed browser tab with preserved tab_name and reverse engineering hooks."
						: "Re-opens managed browser tab with preserved URL and display configuration.",
			};
		}

		case "dap": {
			const restoreTool = customHints?.restore_tool || "debug";
			const adapter =
				(typeof customHints?.restore_params?.adapter === "string" && customHints.restore_params.adapter) ||
				(typeof targetDetails.adapter === "string" && targetDetails.adapter) ||
				(typeof connection.adapter === "string" && connection.adapter) ||
				"lldb-dap";

			const isAttach = typeof targetDetails.pid === "number" || targetDetails.mode === "attach";
			const restoreAction = customHints?.restore_action || (isAttach ? "attach" : "launch");

			const restoreParams: Record<string, unknown> = {
				adapter,
				...customHints?.restore_params,
			};

			if (restoreParams.program === undefined) {
				if (typeof targetDetails.program === "string") restoreParams.program = targetDetails.program;
				else if (typeof targetDetails.binary === "string") restoreParams.program = targetDetails.binary;
			}

			if (typeof targetDetails.pid === "number" && restoreParams.pid === undefined)
				restoreParams.pid = targetDetails.pid;
			if (typeof targetDetails.mode === "string" && restoreParams.mode === undefined)
				restoreParams.mode = targetDetails.mode;
			if (Array.isArray(targetDetails.args) && restoreParams.args === undefined)
				restoreParams.args = targetDetails.args;
			if (typeof targetDetails.cwd === "string" && restoreParams.cwd === undefined)
				restoreParams.cwd = targetDetails.cwd;

			if (typeof connection.host === "string" && restoreParams.host === undefined)
				restoreParams.host = connection.host;
			if (typeof connection.port === "number" && restoreParams.port === undefined)
				restoreParams.port = connection.port;

			const targetDesc =
				(restoreParams.program as string) || (restoreParams.pid ? `PID ${restoreParams.pid}` : "(unspecified)");
			const instructions = customHints?.instructions?.length
				? customHints.instructions
				: [
						`1. Ensure DAP adapter '${adapter}' is installed on PATH or accessible on configured port.`,
						`2. Verify target program binary or attachable PID exists: '${targetDesc}'.`,
						`3. Invoke ${restoreTool}(action: '${restoreAction}', adapter: '${adapter}', ...) with preserved session parameters.`,
						"4. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" +
							record.id +
							"') to mark session active.",
					];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(restoreParams.program || restoreParams.pid || connection.port || restoreParams.port),
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
				instructions,
				prerequisites: customHints?.prerequisites ?? [
					`DAP adapter '${adapter}' available on PATH`,
					"Target program or process reachable",
				],
				reasoning: customHints?.restore_tool
					? "Restores interactive debugging session using explicit recovery hints."
					: "Restores interactive debugging session using the native DAP debug tool with preserved adapter and target parameters.",
			};
		}

		case "ida": {
			const restoreTool = customHints?.restore_tool || "ida";
			const restoreAction = customHints?.restore_action || "open";
			const restoreParams: Record<string, unknown> = {
				...customHints?.restore_params,
			};
			let dbPath: string | undefined;
			if (typeof targetDetails.db === "string") dbPath = targetDetails.db;
			else if (typeof targetDetails.idb_path === "string") dbPath = targetDetails.idb_path;
			else if (typeof targetDetails.path === "string") dbPath = targetDetails.path;
			else if (typeof connection.db === "string") dbPath = connection.db;
			if (dbPath && restoreParams.db === undefined) restoreParams.db = dbPath;

			const instructions = customHints?.instructions?.length
				? customHints.instructions
				: [
						`1. Verify target database (.i64/.idb) or binary exists on disk at '${dbPath || "(unspecified)"}'.`,
						`2. Invoke ${restoreTool}(action: 'list') to check active databases, or ${restoreTool}(action: '${restoreAction}', db: '...') to re-attach.`,
						"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" +
							record.id +
							"') to mark session active.",
					];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(dbPath),
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
				instructions,
				prerequisites: customHints?.prerequisites ?? [
					"IDA Pro host daemon available",
					"Target database file intact on disk",
				],
				reasoning: customHints?.restore_tool
					? "Restores IDA Pro session using explicit recovery hints."
					: "Re-attaches to IDA Pro database session using preserved database locator.",
			};
		}

		case "ghidra": {
			const restoreTool = customHints?.restore_tool || "ghidra_inspect";
			const restoreAction = customHints?.restore_action || "info";
			const restoreParams: Record<string, unknown> = {
				...customHints?.restore_params,
			};
			let binPath: string | undefined;
			if (typeof targetDetails.path === "string") binPath = targetDetails.path;
			else if (typeof targetDetails.binary === "string") binPath = targetDetails.binary;
			else if (typeof connection.path === "string") binPath = connection.path;
			if (binPath && restoreParams.path === undefined) restoreParams.path = binPath;
			if (typeof targetDetails.project_dir === "string" && restoreParams.project_dir === undefined) {
				restoreParams.project_dir = targetDetails.project_dir;
			}

			const instructions = customHints?.instructions?.length
				? customHints.instructions
				: [
						`1. Verify target binary exists on disk at '${binPath || "(unspecified)"}'.`,
						`2. Invoke ${restoreTool}(action: '${restoreAction}', path: '...') to re-initialize Ghidra headless analysis project.`,
						"3. Send a heartbeat to reverse_runtime_session(action: 'heartbeat', session_id: '" +
							record.id +
							"') to mark session active.",
					];

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(binPath),
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
				instructions,
				prerequisites: customHints?.prerequisites ?? [
					"Ghidra analyzeHeadless script on PATH",
					"Java 17+ installed",
					"Target binary intact",
				],
				reasoning: customHints?.restore_tool
					? "Restores Ghidra analysis session using explicit recovery hints."
					: "Re-initiates Ghidra headless inspection project using target binary path.",
			};
		}

		case "generic":
		default: {
			const hasCustom = Boolean(customHints && (customHints.restore_tool || customHints.restore_action));
			const restoreTool = customHints?.restore_tool || "unknown";
			const restoreAction = customHints?.restore_action || "restore";
			const restoreParams: Record<string, unknown> = {
				...(customHints?.restore_params ?? targetDetails),
			};

			return {
				session_id: record.id,
				kind,
				status: record.status,
				can_restore: Boolean(hasCustom),
				restore_tool: restoreTool,
				restore_action: restoreAction,
				restore_params: restoreParams,
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
