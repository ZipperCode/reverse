import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
	GHIDRA_MCP_VERSION,
	X64DBG_AUTOMATE_VERSION,
	checkPythonCompatibility,
	getGhidraMcpInstallDir,
	getNativeMcpServer,
	getServiceVenvDir,
	getVenvBinaryPath,
	getVenvPythonPath,
	inspectNativeMcp,
	installNativeMcpService,
	isServerConfigIdentical,
	parsePythonVersion,
	verifySha256,
} from "../src/extensibility/native-mcp-install";
import { checkReverseTools } from "../src/cli/setup-reverse";
import { writeMCPConfigFile } from "../src/mcp/config-writer";
import { getReverseInstallPlan } from "../src/extensibility/reverse-tool-install";
import type { MCPServerConfig, MCPServerConnection, MCPTransport } from "../src/mcp/types";

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
			name,
			version: "1.0.0",
		},
		capabilities: {
			tools: {},
		},
	};
}

describe("native MCP Python compatibility check", () => {
	it("parses valid python version output strings", () => {
		expect(parsePythonVersion("Python 3.11.4")).toEqual({ major: 3, minor: 11, micro: 4 });
		expect(parsePythonVersion("Python 3.12.0rc1")).toEqual({ major: 3, minor: 12, micro: 0 });
		expect(parsePythonVersion("3.10.9")).toEqual({ major: 3, minor: 10, micro: 9 });
		expect(parsePythonVersion("invalid text")).toBeNull();
	});

	it("accepts supported Python >= 3.10 runtimes", () => {
		expect(checkPythonCompatibility("Python 3.10.12").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.11.8").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.12.3").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.13.0").compatible).toBe(true);
		expect(checkPythonCompatibility("Python 3.14.0a1").compatible).toBe(true);
	});

	it("rejects unsupported Python versions (< 3.10)", () => {
		const oldPy = checkPythonCompatibility("Python 3.9.18");
		expect(oldPy.compatible).toBe(false);
		expect(oldPy.error).toContain(">= 3.10");

		const ancientPy = checkPythonCompatibility("Python 2.7.18");
		expect(ancientPy.compatible).toBe(false);
	});
});

describe("native MCP filesystem inspection (inspectNativeMcp)", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-mcp-test-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("returns installed: false when agent directory has no managed tools", () => {
		const x64Result = inspectNativeMcp("x64dbg", { agentDir: tmpDir });
		expect(x64Result.installed).toBe(false);
		expect(x64Result.missing).toContain("x64dbg_automate[mcp]");
		expect(x64Result.command).toBeUndefined();

		const ghidraResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(ghidraResult.installed).toBe(false);
		expect(ghidraResult.missing).toContain("ghidra_mcp");
		expect(ghidraResult.missing).toContain("GhidraMCP.jar");
		expect(ghidraResult.extensionJar).toBeUndefined();
	});

	it("detects installed x64dbg bridge when entrypoint exists in managed venv", async () => {
		const venvDir = getServiceVenvDir("x64dbg", tmpDir);
		const venvPy = getVenvPythonPath(venvDir);
		const binPath = getVenvBinaryPath(venvDir, "x64dbg-automate-mcp");
		await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
		await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		const result = inspectNativeMcp("x64dbg", { agentDir: tmpDir });
		expect(result.installed).toBe(true);
		expect(result.version).toBe(X64DBG_AUTOMATE_VERSION);
		expect(result.command).toBe(binPath);
		expect(result.missing.length).toBe(0);
	});

	it("requires both bridge executable and extension JAR for Ghidra MCP installation", async () => {
		const venvDir = getServiceVenvDir("ghidra", tmpDir);
		const venvPy = getVenvPythonPath(venvDir);
		const binPath = getVenvBinaryPath(venvDir, "ghidra-mcp");
		await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
		await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
		const partialResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(partialResult.installed).toBe(false);
		expect(partialResult.missing).toContain("GhidraMCP.jar");

		// Add extension JAR
		const ghidraDir = getGhidraMcpInstallDir(tmpDir);
		const jarPath = path.join(ghidraDir, "extension", "GhidraMCP.jar");
		await fs.promises.mkdir(path.dirname(jarPath), { recursive: true });
		await fs.promises.writeFile(jarPath, Buffer.from("PK\x03\x04mockjar"));

		const fullResult = inspectNativeMcp("ghidra", { agentDir: tmpDir });
		expect(fullResult.installed).toBe(true);
		expect(fullResult.version).toBe(GHIDRA_MCP_VERSION);
		expect(fullResult.extensionJar).toBe(jarPath);
		expect(fullResult.missing.length).toBe(0);
	});
});

describe("checksum verification", () => {
	it("correctly verifies SHA256 hash match", () => {
		const data = Buffer.from("test payload for sha256");
		const hash = crypto.createHash("sha256").update(data).digest("hex");
		expect(verifySha256(data, hash)).toBe(true);
		expect(verifySha256(data, hash.toUpperCase())).toBe(true);
		expect(verifySha256(data, "0000000000000000000000000000000000000000000000000000000000000000")).toBe(false);
	});
});

describe("native MCP installation flow guards", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-install-guard-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("aborts immediately when AbortSignal is pre-triggered without downloading", async () => {
		const controller = new AbortController();
		controller.abort(new Error("Operation cancelled by user"));

		let fetchCalled = false;
		await expect(
			installNativeMcpService("ghidra", {
				agentDir: tmpDir,
				signal: controller.signal,
				fetch: async () => {
					fetchCalled = true;
					throw new Error("Should not fetch when aborted");
				},
			}),
		).rejects.toThrow("Operation cancelled by user");

		expect(fetchCalled).toBe(false);
	});

	it("rejects installation if server name is disabled in disabledServers", async () => {
		const mcpJsonPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(mcpJsonPath, {
			mcpServers: {},
			disabledServers: ["x64dbg"],
		});

		await expect(
			installNativeMcpService("x64dbg", {
				agentDir: tmpDir,
			}),
		).rejects.toThrow('MCP server "x64dbg" is currently disabled');
	});

	it("rejects installation if conflicting server configuration already exists", async () => {
		const mcpJsonPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(mcpJsonPath, {
			mcpServers: {
				ghidra: {
					type: "stdio",
					command: "/custom/unrelated/ghidra_mcp",
					args: ["--custom"],
				},
			},
		});

		await expect(
			installNativeMcpService("ghidra", {
				agentDir: tmpDir,
			}),
		).rejects.toThrow('Server "ghidra" already exists in');
	});

	it("fails installation if verification handshake returns zero tools", async () => {
		const mockExec = async (cmd: string, args: string[]) => {
			if (args.includes("-V")) {
				return { exitCode: 0, stdout: "Python 3.12.2\n", stderr: "" };
			}
			// Simulate venv creation and entrypoint in service-isolated venv
			const venvDir = getServiceVenvDir("x64dbg", tmpDir);
			const venvPy = getVenvPythonPath(venvDir);
			const binPath = getVenvBinaryPath(venvDir, "x64dbg-automate-mcp");
			await fs.promises.mkdir(path.dirname(venvPy), { recursive: true });
			await fs.promises.writeFile(venvPy, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
			await fs.promises.writeFile(binPath, "#!/bin/sh\nexit 0;\n", { mode: 0o755 });
			return { exitCode: 0, stdout: "Successfully installed\n", stderr: "" };
		};

		await expect(
			installNativeMcpService("x64dbg", {
				agentDir: tmpDir,
				execCommand: mockExec,
				mcpConnect: async (name, config) => createMockConnection(name, config),
				mcpListTools: async () => [], // Empty tools array
				mcpDisconnect: async () => {},
			}),
		).rejects.toThrow("exposed zero tools");

		// Config file should NOT be written if handshake failed
		const configExists = fs.existsSync(path.join(tmpDir, "mcp.json"));
		expect(configExists).toBe(false);
	});
});

describe("isServerConfigIdentical normalization and conflict detection", () => {
	it("treats active config with enabled: true identical to default omitted enabled", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const persistedConfig = {
			...targetConfig,
			enabled: true,
		};

		expect(isServerConfigIdentical(persistedConfig, targetConfig)).toBe(true);
		expect(isServerConfigIdentical(targetConfig, persistedConfig)).toBe(true);
	});

	it("detects conflict when command or arguments differ", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const conflictingCommand = {
			...targetConfig,
			command: "/different/python",
		};
		const conflictingArgs = {
			...targetConfig,
			args: ["-c", "from malicious import exploit"],
		};

		expect(isServerConfigIdentical(conflictingCommand, targetConfig)).toBe(false);
		expect(isServerConfigIdentical(conflictingArgs, targetConfig)).toBe(false);
	});

	it("detects conflict when environment variables differ", () => {
		const targetConfig = getNativeMcpServer("x64dbg", { agentDir: "/mock/agent" });
		const withCustomEnv = {
			...targetConfig,
			env: {
				X64DBG_PATH: "C:\\custom\\x64dbg.exe",
			},
		};

		expect(isServerConfigIdentical(withCustomEnv, targetConfig)).toBe(false);
	});
});

describe("checkReverseTools inspection for native MCP", () => {
	it("checkReverseTools reports truthful read-only inspection for native services without spawning network", () => {
		const report = checkReverseTools({ agentDir: "/nonexistent/test/agent/dir" });
		const x64dbgStatus = report.services.find(s => s.id === "x64dbg-mcp");
		const ghidraStatus = report.services.find(s => s.id === "ghidra-mcp");
		const r2mcpStatus = report.services.find(s => s.id === "r2mcp");

		expect(x64dbgStatus).toBeDefined();
		expect(x64dbgStatus?.installed).toBe(false);
		expect(x64dbgStatus?.connection).toBe("unknown");

		expect(ghidraStatus).toBeDefined();
		expect(ghidraStatus?.installed).toBe(false);
		expect(ghidraStatus?.connection).toBe("unknown");

		expect(r2mcpStatus).toBeDefined();
		expect(r2mcpStatus?.connection).toBe("unknown");
	});
});
describe("Reverse Install Planner preflight checks for native MCP", () => {
	let tmpDir: string;

	beforeEach(async () => {
		tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "native-plan-preflight-"));
	});

	afterEach(async () => {
		await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
	});

	it("preflight catches disabled server in config before downloading dependencies", async () => {
		const userConfigPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(userConfigPath, {
			mcpServers: {},
			disabledServers: ["x64dbg"],
		});

		const report = checkReverseTools({ agentDir: tmpDir });
		const serviceItem = report.services.find(s => s.id === "x64dbg-mcp")!;
		const plan = getReverseInstallPlan(serviceItem, { agentDir: tmpDir });

		expect(plan.canInstall).toBe(false);
		expect(plan.reason).toContain("disabled in MCP config");
		expect(plan.steps.length).toBe(0);
	});

	it("preflight catches conflicting existing configuration before planning install steps", async () => {
		const userConfigPath = path.join(tmpDir, "mcp.json");
		await writeMCPConfigFile(userConfigPath, {
			mcpServers: {
				ghidra: {
					type: "stdio",
					command: "/conflicting/path/to/ghidra",
					args: ["--foreign"],
				},
			},
		});

		const report = checkReverseTools({ agentDir: tmpDir });
		const serviceItem = report.services.find(s => s.id === "ghidra-mcp")!;
		const plan = getReverseInstallPlan(serviceItem, { agentDir: tmpDir });

		expect(plan.canInstall).toBe(false);
		expect(plan.reason).toContain("conflicting configuration");
		expect(plan.steps.length).toBe(0);
	});
});
