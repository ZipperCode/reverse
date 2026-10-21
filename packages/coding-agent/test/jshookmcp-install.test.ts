import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
	JSHOOK_ENTRY_RELATIVE_PATH,
	JSHOOK_MCP_SERVER_NAME,
	WEBCRACK_DIR_RELATIVE_PATH,
	checkNodeCompatibility,
	getJshookMcpServer,
	inspectJshookMcp,
	installJshookMcp,
} from "../src/extensibility/jshookmcp-install";
import { readMCPConfigFile, writeMCPConfigFile } from "../src/mcp/config-writer";
import type {
	MCPServerConfig,
	MCPServerConnection,
	MCPStdioServerConfig,
	MCPToolCallResult,
	MCPToolDefinition,
	MCPTransport,
} from "../src/mcp/types";

function createMockConnection(name: string, config: MCPServerConfig): MCPServerConnection {
	const transport: MCPTransport = {
		connected: true,
		request: async <T = unknown>() => ({}) as T,
		notify: async () => {},
		close: async () => {},
	};
	return {
		name,
		config,
		transport,
		serverInfo: {
			name: "jshookmcp",
			version: "0.4.2",
		},
		capabilities: {
			tools: {},
		},
	};
}

const mockSearchProfileTools: MCPToolDefinition[] = [
	{ name: "search_tools", description: "Search tools", inputSchema: { type: "object" } },
	{ name: "describe_tool", description: "Describe tool", inputSchema: { type: "object" } },
	{ name: "call_tool", description: "Call tool", inputSchema: { type: "object" } },
];

const mockDeobfuscationSuccess: MCPToolCallResult = {
	content: [
		{
			type: "text",
			text: JSON.stringify({
				success: true,
				code: "globalThis.__reverseInstallProbe = 3;",
			}),
		},
	],
};

describe("jshook MCP filesystem probe (inspectJshookMcp)", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "jshook-probe-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("returns installed: false when directory is empty or missing components", () => {
		const result = inspectJshookMcp({ installDir: tmpDir });
		expect(result.installed).toBe(false);
		expect(result.installDir).toBe(tmpDir);
		expect(result.version).toBeUndefined();
	});

	it("returns installed: true and reads version when exact pinned dependencies exist", async () => {
		const entryPath = path.join(tmpDir, JSHOOK_ENTRY_RELATIVE_PATH);
		const jshookPkgPath = path.join(tmpDir, "node_modules", "@jshookmcp", "jshook", "package.json");
		const webcrackDir = path.join(tmpDir, WEBCRACK_DIR_RELATIVE_PATH);
		const webcrackPkgPath = path.join(tmpDir, "node_modules", "webcrack", "package.json");

		await fs.promises.mkdir(path.dirname(entryPath), { recursive: true });
		await fs.promises.mkdir(webcrackDir, { recursive: true });
		await fs.promises.writeFile(entryPath, "export default {};");
		await fs.promises.writeFile(jshookPkgPath, JSON.stringify({ version: "0.4.2" }));
		await fs.promises.writeFile(webcrackPkgPath, JSON.stringify({ version: "2.16.0" }));

		const result = inspectJshookMcp({ installDir: tmpDir });
		expect(result.installed).toBe(true);
		expect(result.version).toBe("0.4.2");
	});

	it("returns installed: false when package versions do not match or JSON is invalid", async () => {
		const entryPath = path.join(tmpDir, JSHOOK_ENTRY_RELATIVE_PATH);
		const jshookPkgPath = path.join(tmpDir, "node_modules", "@jshookmcp", "jshook", "package.json");
		const webcrackDir = path.join(tmpDir, WEBCRACK_DIR_RELATIVE_PATH);
		const webcrackPkgPath = path.join(tmpDir, "node_modules", "webcrack", "package.json");

		await fs.promises.mkdir(path.dirname(entryPath), { recursive: true });
		await fs.promises.mkdir(webcrackDir, { recursive: true });
		await fs.promises.writeFile(entryPath, "export default {};");
		await fs.promises.writeFile(jshookPkgPath, "{ invalid json");
		await fs.promises.writeFile(webcrackPkgPath, JSON.stringify({ version: "2.16.0" }));

		expect(inspectJshookMcp({ installDir: tmpDir }).installed).toBe(false);

		// Version mismatch
		await fs.promises.writeFile(jshookPkgPath, JSON.stringify({ version: "0.3.0" }));
		expect(inspectJshookMcp({ installDir: tmpDir }).installed).toBe(false);
	});
});

describe("Node.js compatibility checker", () => {
	it("accepts supported intersection (Node >= 24.15.0 or Node >= 22.22.2)", () => {
		expect(checkNodeCompatibility("v24.21.0").compatible).toBe(true);
		expect(checkNodeCompatibility("v24.15.0").compatible).toBe(true);
		expect(checkNodeCompatibility("v22.22.2").compatible).toBe(true);
		expect(checkNodeCompatibility("v22.23.0").compatible).toBe(true);
	});

	it("rejects versions outside the intersection", () => {
		expect(checkNodeCompatibility("v24.14.0").compatible).toBe(false);
		expect(checkNodeCompatibility("v22.22.1").compatible).toBe(false);
		expect(checkNodeCompatibility("v22.12.0").compatible).toBe(false);
		expect(checkNodeCompatibility("v20.18.0").compatible).toBe(false);
		expect(checkNodeCompatibility("v26.0.0").compatible).toBe(false);
	});
});

describe("getJshookMcpServer configuration", () => {
	it("generates stdio config with search profile, disabled vector, and cwd=installDir", () => {
		const server = getJshookMcpServer({
			installDir: "/test/tools/jshookmcp",
			nodePath: "/custom/bin/node",
		});
		expect(server.type).toBe("stdio");
		expect(server.command).toBe("/custom/bin/node");
		expect(server.cwd).toBe("/test/tools/jshookmcp");
		expect(server.env?.MCP_TRANSPORT).toBe("stdio");
		expect(server.env?.MCP_TOOL_PROFILE).toBe("search");
		expect(server.env?.SEARCH_VECTOR_ENABLED).toBe("false");
		expect(server.args?.[0]).toContain("dist/index.mjs");
	});
});

describe("installJshookMcp installer lifecycle", () => {
	let agentDir: string;
	let projectDir: string;
	let installDir: string;

	beforeEach(async () => {
		agentDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "rev-agent-"));
		projectDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "rev-proj-"));
		installDir = path.join(agentDir, "tools", "jshookmcp");
	});

	afterEach(async () => {
		await fs.promises.rm(agentDir, { recursive: true, force: true }).catch(() => {});
		await fs.promises.rm(projectDir, { recursive: true, force: true }).catch(() => {});
	});

	it("refuses to install if server is listed in disabledServers", async () => {
		const configPath = path.join(agentDir, "mcp.json");
		await writeMCPConfigFile(configPath, {
			mcpServers: {},
			disabledServers: [JSHOOK_MCP_SERVER_NAME],
		});

		await expect(
			installJshookMcp({
				cwd: projectDir,
				agentDir,
				installDir,
			}),
		).rejects.toThrow(/disabled/i);
	});

	it("refuses to overwrite conflicting existing server configuration", async () => {
		const configPath = path.join(agentDir, "mcp.json");
		await writeMCPConfigFile(configPath, {
			mcpServers: {
				[JSHOOK_MCP_SERVER_NAME]: {
					type: "stdio",
					command: "python3",
					args: ["some_unrelated_script.py"],
				},
			},
		});

		await expect(
			installJshookMcp({
				cwd: projectDir,
				agentDir,
				installDir,
			}),
		).rejects.toThrow(/different configuration/i);
	});

	it("fails with clear error when Node version is unsupported", async () => {
		await expect(
			installJshookMcp({
				cwd: projectDir,
				agentDir,
				installDir,
				execCommand: async (_cmd, args) => {
					if (args[0] === "-v") {
						return { exitCode: 0, stdout: "v20.10.0\n", stderr: "" };
					}
					return { exitCode: 0, stdout: "", stderr: "" };
				},
			}),
		).rejects.toThrow(/not supported/i);
	});

	it("fails and writes no config when verification call_tool returns isError: true", async () => {
		const configPath = path.join(agentDir, "mcp.json");
		await expect(
			installJshookMcp({
				cwd: projectDir,
				agentDir,
				installDir,
				execCommand: async (_cmd, args) => {
					if (args[0] === "-v") {
						return { exitCode: 0, stdout: "v24.21.0\n", stderr: "" };
					}
					if (args[0] === "install") {
						const entry = path.join(installDir, JSHOOK_ENTRY_RELATIVE_PATH);
						const jshookPkg = path.join(installDir, "node_modules", "@jshookmcp", "jshook", "package.json");
						const webcrackDir = path.join(installDir, WEBCRACK_DIR_RELATIVE_PATH);
						const webcrackPkg = path.join(installDir, "node_modules", "webcrack", "package.json");
						await fs.promises.mkdir(path.dirname(entry), { recursive: true });
						await fs.promises.mkdir(webcrackDir, { recursive: true });
						await fs.promises.writeFile(entry, "// entry");
						await fs.promises.writeFile(jshookPkg, JSON.stringify({ version: "0.4.2" }));
						await fs.promises.writeFile(webcrackPkg, JSON.stringify({ version: "2.16.0" }));
						return { exitCode: 0, stdout: "added 425 packages\n", stderr: "" };
					}
					return { exitCode: 0, stdout: "", stderr: "" };
				},
				mcpConnect: async (name, cfg) => createMockConnection(name, cfg),
				mcpListTools: async () => mockSearchProfileTools,
				mcpCallTool: async () => ({
					isError: true,
					content: [
						{
							type: "text",
							text: JSON.stringify({ success: false, error: "native isolated-vm binding missing" }),
						},
					],
				}),
				mcpDisconnect: async () => {},
			}),
		).rejects.toThrow(/verification failed/i);

		// Assert no config was written
		const config = await readMCPConfigFile(configPath);
		expect(config.mcpServers?.[JSHOOK_MCP_SERVER_NAME]).toBeUndefined();
	});

	it("completes installation, executes handshake, and preserves existing unrelated configs", async () => {
		const configPath = path.join(agentDir, "mcp.json");
		const otherServer: MCPServerConfig = {
			type: "stdio",
			command: "r2pm",
			args: ["-r", "r2mcp"],
		};
		await writeMCPConfigFile(configPath, {
			mcpServers: {
				radare2: otherServer,
			},
		});

		let npmInstalled = false;

		const result = await installJshookMcp({
			cwd: projectDir,
			agentDir,
			installDir,
			execCommand: async (_cmd, args) => {
				if (args[0] === "-v") {
					return { exitCode: 0, stdout: "v24.21.0\n", stderr: "" };
				}
				if (args[0] === "install") {
					npmInstalled = true;
					const entry = path.join(installDir, JSHOOK_ENTRY_RELATIVE_PATH);
					const jshookPkg = path.join(installDir, "node_modules", "@jshookmcp", "jshook", "package.json");
					const webcrackDir = path.join(installDir, WEBCRACK_DIR_RELATIVE_PATH);
					const webcrackPkg = path.join(installDir, "node_modules", "webcrack", "package.json");
					await fs.promises.mkdir(path.dirname(entry), { recursive: true });
					await fs.promises.mkdir(webcrackDir, { recursive: true });
					await fs.promises.writeFile(entry, "// entry");
					await fs.promises.writeFile(jshookPkg, JSON.stringify({ version: "0.4.2" }));
					await fs.promises.writeFile(webcrackPkg, JSON.stringify({ version: "2.16.0" }));
					return { exitCode: 0, stdout: "added 425 packages\n", stderr: "" };
				}
				return { exitCode: 0, stdout: "", stderr: "" };
			},
			mcpConnect: async (name, cfg) => createMockConnection(name, cfg),
			mcpListTools: async () => mockSearchProfileTools,
			mcpCallTool: async () => mockDeobfuscationSuccess,
			mcpDisconnect: async () => {},
		});

		expect(npmInstalled).toBe(true);
		expect(result.installed).toBe(true);
		expect(result.serverName).toBe("jshook");
		expect(result.tools).toEqual(["search_tools", "describe_tool", "call_tool"]);

		// Verify config file: radare2 is preserved, jshook is added
		const updatedConfig = await readMCPConfigFile(configPath);
		expect(updatedConfig.mcpServers?.radare2).toEqual(otherServer);
		expect(updatedConfig.mcpServers?.jshook).toBeDefined();
		const jshookServer = updatedConfig.mcpServers?.jshook as MCPStdioServerConfig;
		expect(jshookServer?.cwd).toBe(installDir);

		// Idempotent repeat: repeating install against already installed jshook skips npm install
		let repeatedNpmCalled = false;
		const repeatResult = await installJshookMcp({
			cwd: projectDir,
			agentDir,
			installDir,
			execCommand: async (_cmd, args) => {
				if (args[0] === "-v") {
					return { exitCode: 0, stdout: "v24.21.0\n", stderr: "" };
				}
				if (args[0] === "install") {
					repeatedNpmCalled = true;
				}
				return { exitCode: 0, stdout: "", stderr: "" };
			},
			mcpConnect: async (name, cfg) => createMockConnection(name, cfg),
			mcpListTools: async () => mockSearchProfileTools,
			mcpCallTool: async () => mockDeobfuscationSuccess,
			mcpDisconnect: async () => {},
		});

		expect(repeatResult.installed).toBe(true);
		expect(repeatedNpmCalled).toBe(false);
	});
});
