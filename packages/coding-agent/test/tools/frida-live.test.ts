import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import type { ToolSession } from "@reverse/coding-agent/tools";
import { FridaSessionTool, probeFridaLiveDependency, isProcessAlive, FridaLiveClient } from "../../src/tools";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

async function removeTestDir(dirPath: string): Promise<void> {
	await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
}

describe("FridaLiveClient subprocess IPC lifecycle", () => {
	it("starts worker and responds to status query", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-ipc-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			const status = await client.status(5000);
			expect(status.status).toBe("ok");
			expect(status.alive).toBe(false);
			expect(status.hasScript).toBe(false);
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});

	it("handles malformed IPC and safe error rejection", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-err-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			await expect(client.rpc("nonExistent", [])).rejects.toThrow("No script loaded");
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});

	it("terminates worker cleanly on AbortSignal cancellation", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-live-abort-"));
		const client = new FridaLiveClient({ pythonPath: dep.pythonPath, cwd: tempDir });
		try {
			await client.start();
			const controller = new AbortController();
			const pending = client.status(5000, controller.signal);
			controller.abort();
			await expect(pending).rejects.toThrow("Request aborted");
		} finally {
			await client.stop();
			await removeTestDir(tempDir);
		}
	});
});

describe("FridaSessionTool persistent live sessions", () => {
	it("rejects live mode create if target is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-live-val-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), { stateRoot: tempDir });
			await expect(tool.execute("call-1", { action: "create", mode: "live" })).rejects.toThrow(
				"Must specify target: 'pid', 'process', or 'spawn'",
			);
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("rejects action: 'load' on batch mode sessions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-batch-load-"));
		try {
			const tool = new FridaSessionTool(createTestSession(tempDir), {
				stateRoot: tempDir,
				runner: async () => ({
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				}),
			});
			await tool.execute("c1", { action: "create", pid: 99999, session_id: "batch-test" });
			await expect(
				tool.execute("c2", { action: "load", session_id: "batch-test", script: "console.log('hi')" }),
			).rejects.toThrow("Action 'load' is only supported on live mode sessions");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("manages live session attachment, RPC invocation, hot reloading, and stop without killing target", async () => {
		const dep = await probeFridaLiveDependency();
		if (!dep.available || !dep.pythonPath) {
			return;
		}

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-sess-live-e2e-"));
		const targetBin = path.join(tempDir, "live_target");

		const sourceCode = `
#include <stdio.h>
#include <unistd.h>

__attribute__((visibility("default")))
int calc(int a) {
    return a * 10;
}

int main() {
    printf("READY\\n");
    fflush(stdout);
    for (int i = 0; i < 60; i++) {
        calc(i);
        sleep(1);
    }
    return 0;
}
`;
		await fs.writeFile(path.join(tempDir, "target.c"), sourceCode);

		const compile = Bun.spawn(["clang", "-Wl,-export_dynamic", "-o", targetBin, path.join(tempDir, "target.c")], {
			cwd: tempDir,
		});
		const compileCode = await compile.exited;
		if (compileCode !== 0) {
			await removeTestDir(tempDir);
			return;
		}

		const targetChild = Bun.spawn([targetBin], {
			cwd: tempDir,
			stdout: "pipe",
			stderr: "pipe",
		});
		const targetPid = targetChild.pid;

		try {
			const reader = targetChild.stdout.getReader();
			let targetOutput = "";
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				targetOutput += Buffer.from(value).toString("utf8");
				if (targetOutput.includes("READY")) break;
			}
			reader.releaseLock();

			const tool = new FridaSessionTool(createTestSession(tempDir), { stateRoot: tempDir });
			const sessionId = "live-audit-test";

			// 1. Create live session and load initial script with RPC and hook
			const createRes = await tool.execute("c1", {
				action: "create",
				mode: "live",
				pid: targetPid,
				session_id: sessionId,
				script: `
rpc.exports = {
    transform: function(val) {
        return "transformed:" + val;
    }
};
var calcAddr = Module.findGlobalExportByName("calc");
if (calcAddr) {
    Interceptor.attach(calcAddr, {
        onEnter: function(args) {
            send({ event: "calc_called", arg: args[0].toInt32() });
        }
    });
}
`,
			});

			expect(createRes.details?.status).toBe("ok");
			expect(createRes.details?.mode).toBe("live");
			expect(createRes.details?.exports).toContain("transform");

			// 2. Call RPC method
			const rpcRes1 = await tool.execute("c2", {
				action: "rpc",
				session_id: sessionId,
				rpc_method: "transform",
				rpc_args: ["sample_input"],
			});

			expect(rpcRes1.details?.status).toBe("ok");
			expect(rpcRes1.details?.rpcResult).toBe("transformed:sample_input");

			// 3. Hot reload script: update transform logic
			const loadRes2 = await tool.execute("c3", {
				action: "load",
				session_id: sessionId,
				script: `
rpc.exports = {
    transform: function(val) {
        return "v2_transformed:" + val;
    }
};
`,
			});

			expect(loadRes2.details?.status).toBe("ok");
			expect(loadRes2.details?.exports).toContain("transform");

			// 4. Verify RPC returns updated v2 result
			const rpcRes2 = await tool.execute("c4", {
				action: "rpc",
				session_id: sessionId,
				rpc_method: "transform",
				rpc_args: ["sample_input"],
			});

			expect(rpcRes2.details?.status).toBe("ok");
			expect(rpcRes2.details?.rpcResult).toBe("v2_transformed:sample_input");

			// 5. Query status
			const statusRes = await tool.execute("c5", {
				action: "status",
				session_id: sessionId,
			});

			expect(statusRes.details?.status).toBe("ok");
			expect(statusRes.details?.mode).toBe("live");
			expect(statusRes.details?.liveStatus).toBe("connected");

			// 6. Unload script
			const unloadRes = await tool.execute("c6", {
				action: "unload",
				session_id: sessionId,
			});
			expect(unloadRes.details?.status).toBe("ok");

			// 7. Stop session: verifies clean detach without killing user target process
			const stopRes = await tool.execute("c7", {
				action: "stop",
				session_id: sessionId,
			});
			expect(stopRes.details?.status).toBe("ok");
			expect(stopRes.details?.action).toBe("stop");
			expect(isProcessAlive(targetPid)).toBe(true);
		} finally {
			try {
				targetChild.kill();
			} catch {}
			await removeTestDir(tempDir);
		}
	});
});
