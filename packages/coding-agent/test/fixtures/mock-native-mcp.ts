#!/usr/bin/env bun
/**
 * Test fixture: a mock stdio MCP server simulating native debugger / decompiler
 * backends (x64dbg, Ghidra, radare2) for unit and smoke testing of NativeMcpSessionTool.
 */
import * as readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin });

type JsonRpcRequest = {
	jsonrpc: "2.0";
	id?: string | number;
	method: string;
	params?: Record<string, unknown>;
};

function handleRequest(req: JsonRpcRequest): Record<string, unknown> | null {
	const mode = process.env.MOCK_NATIVE_MODE ?? "x64dbg";

	switch (req.method) {
		case "initialize":
			return {
				protocolVersion: "2025-03-26",
				serverInfo: { name: `mock-${mode}-mcp`, version: "1.0.0" },
				capabilities: { tools: {} },
			};

		case "tools/list": {
			if (mode === "ghidra") {
				return {
					tools: [
						{
							name: "get_program_info",
							description: "Get program information",
							inputSchema: { type: "object", properties: {} },
						},
						{
							name: "list_functions",
							description: "List functions",
							inputSchema: { type: "object", properties: {} },
						},
					],
				};
			}
			if (mode === "radare2") {
				return {
					tools: [
						{
							name: "open_file",
							description: "Open binary file",
							inputSchema: { type: "object", properties: { file_path: { type: "string" } } },
						},
						{
							name: "show_info",
							description: "Show binary info",
							inputSchema: { type: "object", properties: {} },
						},
					],
				};
			}
			// default: x64dbg
			return {
				tools: [
					{
						name: "start_session",
						description: "Start x64dbg session",
						inputSchema: { type: "object", properties: { target_exe: { type: "string" } } },
					},
					{
						name: "connect_to_session",
						description: "Connect to session by PID",
						inputSchema: { type: "object", properties: { session_pid: { type: "number" } } },
					},
					{
						name: "connect_remote",
						description: "Connect to remote x64dbg instance",
						inputSchema: {
							type: "object",
							properties: { host: { type: "string" }, req_rep_port: { type: "number" } },
						},
					},
					{
						name: "get_debugger_status",
						description: "Get debugger consolidated status",
						inputSchema: { type: "object", properties: {} },
					},
					{
						name: "get_memory_map",
						description: "Get memory regions map",
						inputSchema: { type: "object", properties: {} },
					},
					{
						name: "disconnect",
						description: "Detach debugger session",
						inputSchema: { type: "object", properties: {} },
					},
				],
			};
		}

		case "tools/call": {
			const toolName = String(req.params?.name ?? "");

			if (toolName === "get_debugger_status") {
				if (process.env.MOCK_DEBUGGEE_DEAD === "1") {
					return {
						content: [
							{
								type: "text",
								text: "Has debuggee: False\nState: no debuggee (not started, or exited/terminated)\nDebuggee PID: n/a\nBitness: n/a\nElevated: False",
							},
						],
					};
				}
				return {
					content: [
						{
							type: "text",
							text: "Has debuggee: True\nState: paused\nDebuggee PID: 4321\nBitness: 64\nElevated: False",
						},
					],
				};
			}

			if (toolName === "get_memory_map") {
				const target = process.env.MOCK_TARGET_PATH ?? "test_binary.exe";
				return {
					content: [
						{
							type: "text",
							text: `0x7FF6A0000000  Size: 0x20000  R-X  commit  image  ${target}`,
						},
					],
				};
			}

			if (toolName === "start_session") {
				if (process.env.MOCK_BOOTSTRAP_FAIL === "1") {
					return {
						content: [{ type: "text", text: "Error: Failed to launch executable: file not found" }],
					};
				}
				return {
					content: [{ type: "text", text: "Session started with x64dbg.exe. Debugger PID: 1234" }],
				};
			}

			if (toolName === "disconnect") {
				return {
					content: [{ type: "text", text: "Disconnected." }],
				};
			}

			if (toolName === "get_program_info") {
				const sha256 =
					process.env.MOCK_GHIDRA_SHA256 ?? "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
				return {
					content: [
						{
							type: "text",
							text: JSON.stringify({
								name: "sample.bin",
								executable_path: process.env.MOCK_TARGET_PATH ?? "/mock/sample.bin",
								sha256,
								image_base: "0x140000000",
							}),
						},
					],
				};
			}

			if (toolName === "open_file") {
				if (process.env.MOCK_R2_FAIL === "1") {
					return {
						content: [{ type: "text", text: "Failed to open file." }],
					};
				}
				return {
					content: [{ type: "text", text: "File opened successfully." }],
				};
			}

			if (toolName === "show_info") {
				return {
					content: [{ type: "text", text: "format: elf64\narch: x86\nbits: 64" }],
				};
			}

			return {
				content: [{ type: "text", text: "OK" }],
			};
		}

		default:
			return {};
	}
}

rl.on("line", line => {
	const trimmed = line.trim();
	if (!trimmed) return;
	try {
		const req = JSON.parse(trimmed) as JsonRpcRequest;
		if (req.id === undefined) return; // Notification, do not respond
		const res = handleRequest(req);
		const response = {
			jsonrpc: "2.0",
			id: req.id,
			result: res,
		};
		process.stdout.write(`${JSON.stringify(response)}\n`);
	} catch (err) {
		const errResponse = {
			jsonrpc: "2.0",
			id: null,
			error: { code: -32603, message: String(err) },
		};
		process.stdout.write(`${JSON.stringify(errResponse)}\n`);
	}
});
