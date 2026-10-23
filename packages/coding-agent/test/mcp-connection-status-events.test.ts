import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { MCPManager } from "@reverse/coding-agent/mcp/manager";
import type { McpConnectionStatusEvent } from "@reverse/coding-agent/mcp/startup-events";
import type { MCPServerConfig } from "@reverse/coding-agent/mcp/types";
import { removeSyncWithRetries } from "@reverse/utils";

const FIXTURE_PATH = path.join(import.meta.dir, "fixtures", "many-tools-mcp.ts");
const BUN_EXEC = process.execPath;

describe("MCPManager connection status events", () => {
	let workDir: string;

	beforeEach(() => {
		workDir = fs.mkdtempSync(path.join(os.tmpdir(), "reverse-mcp-status-"));
	});

	afterEach(() => {
		removeSyncWithRetries(workDir);
	});

	it("emits connecting, connected, and failed updates for startup status", async () => {
		const manager = new MCPManager(workDir);
		const events: McpConnectionStatusEvent[] = [];
		const success: MCPServerConfig = {
			type: "stdio",
			command: BUN_EXEC,
			args: [FIXTURE_PATH],
		};
		const invalid: MCPServerConfig = { type: "stdio", command: "" };

		try {
			// Window 0 waits for every server to settle; the default 250ms window
			// races the fixture's process spawn and flakes on loaded CI runners.
			const result = await manager.connectServers(
				{ alpha: success, broken: invalid },
				{},
				event => events.push(event),
				0,
			);

			expect(result.connectedServers).toContain("alpha");
			expect(result.errors.get("broken")).toBe('Server "broken": stdio server requires "command" field');
			expect(events).toEqual([
				{ type: "connecting", serverNames: ["alpha", "broken"] },
				{ type: "failed", serverName: "broken", error: 'Server "broken": stdio server requires "command" field' },
				{ type: "connected", serverName: "alpha" },
			]);
		} finally {
			await manager.disconnectAll();
		}
	});

	it("includes the originating config path when a discovered server fails to start", async () => {
		const manager = new MCPManager(workDir);
		const events: McpConnectionStatusEvent[] = [];
		const missingCommand = path.join(workDir, "missing-mcp-server");
		const configPath = path.join(os.homedir(), ".codex", "config.toml");

		try {
			const result = await manager.connectServers(
				{
					broken: {
						type: "stdio",
						command: missingCommand,
					},
				},
				{
					broken: {
						provider: "codex",
						providerName: "Codex",
						path: configPath,
						level: "user",
					},
				},
				event => events.push(event),
				0,
			);

			const message = result.errors.get("broken") ?? "";
			expect(message).toMatch(/ENOENT|No such file|not found/i);
			expect(events[0]).toEqual({ type: "connecting", serverNames: ["broken"] });
			expect(events[1]).toMatchObject({
				type: "failed",
				serverName: "broken",
				error: message,
				sourcePath: configPath,
			});
		} finally {
			await manager.disconnectAll();
		}
	});

	it("retains exit code, stderr, phase and degraded status when a stdio server fails early", async () => {
		const manager = new MCPManager(workDir);
		const events: McpConnectionStatusEvent[] = [];
		const workingServer: MCPServerConfig = {
			type: "stdio",
			command: BUN_EXEC,
			args: [FIXTURE_PATH],
		};
		const failingServer: MCPServerConfig = {
			type: "stdio",
			command: BUN_EXEC,
			args: [
				"-e",
				"process.stderr.write('r2mcp: cannot open shared object r_core.dll\\n'); process.exit(42)",
			],
		};

		try {
			const result = await manager.connectServers(
				{ radare2: failingServer, helper: workingServer },
				{},
				event => events.push(event),
				0,
			);

			// Working server connected
			expect(result.connectedServers).toContain("helper");
			expect(manager.getConnectionStatus("helper")).toBe("connected");

			// Failing server failed with rich diagnostic
			expect(result.connectedServers).not.toContain("radare2");
			expect(manager.getConnectionStatus("radare2")).toBe("disconnected");
			const failureMsg = result.errors.get("radare2") ?? "";
			expect(failureMsg).toContain("42");
			expect(failureMsg).toContain('"initialize"');
			expect(failureMsg).toContain("cannot open shared object r_core.dll");

			// Failed event has structured diagnostic metadata
			const failedEvent = events.find(e => e.type === "failed" && e.serverName === "radare2");
			expect(failedEvent).toBeDefined();
			if (failedEvent && failedEvent.type === "failed") {
				expect(failedEvent.exitCode).toBe(42);
				expect(failedEvent.phase).toBe("initialize");
				expect(failedEvent.stderr).toContain("cannot open shared object r_core.dll");
			}

			// Host stays degraded: manager.getServerFailure returns the diagnostic
			expect(manager.getServerFailure("radare2")).toBe(failureMsg);
		} finally {
			await manager.disconnectAll();
		}
	});

	it("captures phase initialize and stderr when a server times out during initial connection", async () => {
		const manager = new MCPManager(workDir);
		const events: McpConnectionStatusEvent[] = [];
		const hangingServer: MCPServerConfig = {
			type: "stdio",
			command: BUN_EXEC,
			args: [
				"-e",
				"process.stderr.write('r2mcp: loading symbols slowly...\\n'); await Bun.sleep(60_000)",
			],
			timeout: 150,
		};

		try {
			const result = await manager.connectServers(
				{ slow: hangingServer },
				{},
				event => events.push(event),
				0,
			);

			expect(result.connectedServers).not.toContain("slow");
			expect(manager.getConnectionStatus("slow")).toBe("connecting");
			await manager.disconnectServer("slow");
			expect(manager.getConnectionStatus("slow")).toBe("disconnected");

			const failureMsg = result.errors.get("slow") ?? "";
			expect(failureMsg).toContain('"initialize"');
			expect(failureMsg).toContain("timed out");
			expect(failureMsg).toContain("loading symbols slowly...");

			const failedEvent = events.find(e => e.type === "failed" && e.serverName === "slow");
			expect(failedEvent).toBeDefined();
			if (failedEvent && failedEvent.type === "failed") {
				expect(failedEvent.phase).toBe("initialize");
				expect(failedEvent.stderr).toContain("loading symbols slowly...");
			}
		} finally {
			await manager.disconnectAll();
		}
	});
});
