import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "../../src/config/settings";
import { AppExperimentTool } from "../../src/tools/app-experiment";
import type { ToolSession } from "../../src/tools";
import type { AdbRunner } from "../../src/tools/adb-observe";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";
import { removeWithRetries } from "@reverse/utils";

interface TestSessionWithHooks extends ToolSession {
	triggerDispose: () => void;
	triggerSessionChange: () => void;
}

function createLifecycleTestSession(cwd: string): TestSessionWithHooks {
	const disposeHooks = new Set<() => void>();
	const changeHooks = new Set<() => void>();
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		registerDisposeCallback: (cb: () => void) => {
			disposeHooks.add(cb);
			return () => disposeHooks.delete(cb);
		},
		registerSessionChangeCallback: (cb: () => void) => {
			changeHooks.add(cb);
			return () => changeHooks.delete(cb);
		},
		triggerDispose: () => {
			for (const hook of disposeHooks) hook();
		},
		triggerSessionChange: () => {
			for (const hook of changeHooks) hook();
		},
	};
}

function getFreePort(): Promise<number> {
	const { promise, resolve } = Promise.withResolvers<number>();
	const server = net.createServer();
	server.listen(0, "127.0.0.1", () => {
		const port = (server.address() as net.AddressInfo).port;
		server.close(() => resolve(port));
	});
	return promise;
}

async function createFakeMitmdumpScript(dir: string, floodBytes = 0): Promise<string> {
	const scriptPath = path.join(dir, `fake-mitmdump-${Date.now()}-${Math.random().toString(36).slice(2, 6)}.mjs`);
	const scriptContent = `#!/usr/bin/env node
import * as http from "node:http";
import * as fs from "node:fs";

const args = process.argv.slice(2);
let port = 8080;
let flowPath = "";

for (let i = 0; i < args.length; i++) {
	if (args[i] === "-p" && args[i + 1]) {
		port = parseInt(args[i + 1], 10);
	}
	if (args[i] === "-w" && args[i + 1]) {
		flowPath = args[i + 1];
	}
}

const server = http.createServer((req, res) => {
	res.writeHead(200);
	res.end("OK");
});
server.listen(port, "127.0.0.1", () => {
	process.stdout.write(\`Proxy server listening at http://127.0.0.1:\${port}\\n\`);
	process.stderr.write(\`Proxy server listening at http://127.0.0.1:\${port}\\n\`);
	if (${floodBytes} > 0 && flowPath) {
		const chunk = Buffer.alloc(1024 * 1024, 0x58);
		const count = Math.ceil(${floodBytes} / (1024 * 1024));
		for (let j = 0; j < count; j++) {
			fs.appendFileSync(flowPath, chunk);
		}
	}
});
process.on("SIGTERM", () => {
	server.close(() => process.exit(0));
});
`;
	await fs.writeFile(scriptPath, scriptContent, { mode: 0o755 });
	await fs.chmod(scriptPath, 0o755);
	return scriptPath;
}

// 基于状态轮询与事件循环 tick 等待真实子进程与看门狗状态转换，避免硬编码时钟延迟
async function pollUntilCondition(fn: () => Promise<boolean>, timeoutMs = 4000): Promise<boolean> {
	const start = Date.now();
	while (Date.now() - start < timeoutMs) {
		if (await fn()) return true;
		const { promise, resolve } = Promise.withResolvers<void>();
		setImmediate(resolve);
		await promise;
	}
	return false;
}

function getContentText(res: { content?: Array<{ type: string; text?: string }> }): string {
	const first = res.content?.[0];
	return first && first.type === "text" && first.text ? first.text : "";
}

describe("app_experiment lifecycle, MITM capture, and state ownership", () => {
	it("retains changed proxy and changed forward on session dispose without clobbering", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-retained-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			const recordedCommands: string[][] = [];
			let currentDeviceProxy = "null";
			let activeForwards = `emulator-5554 tcp:9223 localabstract:webview_devtools_remote_1001\n`;
			const activeReverses = `(device) tcp:${port} tcp:${port}\n`;
			const mockRunner: AdbRunner = async (_bin, args) => {
				recordedCommands.push([...args]);
				if (args.includes("devices")) {
					const out = "List of devices attached\nemulator-5554\tdevice\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("ps") && args.includes("-A")) {
					const out = "u0_a100 1001 1000 10000 5000 0 0 S com.example.app\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("cat") && args.includes("/proc/net/unix")) {
					const out = "0000: 0002 0000 00010000 0001 01 @webview_devtools_remote_1001\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("forward") && args.includes("--list")) {
					return {
						stdout: new TextEncoder().encode(activeForwards),
						stderr: "",
						exitCode: 0,
						outputBytes: activeForwards.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--list")) {
					return {
						stdout: new TextEncoder().encode(activeReverses),
						stderr: "",
						exitCode: 0,
						outputBytes: activeReverses.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("get")) {
					return {
						stdout: new TextEncoder().encode(currentDeviceProxy + "\n"),
						stderr: "",
						exitCode: 0,
						outputBytes: currentDeviceProxy.length + 1,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("put")) {
					currentDeviceProxy = args[args.length - 1];
					return {
						stdout: new Uint8Array(),
						stderr: "",
						exitCode: 0,
						outputBytes: 0,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("delete")) {
					currentDeviceProxy = "null";
					return {
						stdout: new Uint8Array(),
						stderr: "",
						exitCode: 0,
						outputBytes: 0,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const mockWhich: SkillRequirementWhich = binary => {
				if (binary === "mitmdump") return fakeProxy;
				if (binary === "adb") return "/usr/bin/adb";
				return null;
			};

			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, {
				runner: mockRunner,
				which: mockWhich,
			});

			// 1. 建立真实的 WebView forward
			const fwRes = await tool.execute("wv-forward", {
				action: "webview_debug",
				webview_op: "forward",
				serial: "emulator-5554",
				package: "com.example.app",
				socket_name: "@webview_devtools_remote_1001",
				forward_port: 9223,
			});
			expect(fwRes.details.status).toBe("ok");

			// 2. 启动 MITM 并配置设备代理
			const startRes = await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				serial: "emulator-5554",
				configure_device_proxy: true,
			});
			expect(startRes.details.status).toBe("ok");
			expect(startRes.details.proxyConfigured).toBe(true);

			// 3. 模拟外部进程改变了设备端口转发和全局代理
			activeForwards = `emulator-5554 tcp:9223 localabstract:foreign_hijacked_remote_9999\n`;
			currentDeviceProxy = "corp.proxy.internal:8080";

			const cmdCountBeforeDispose = recordedCommands.length;

			// 4. 触发会话销毁回调
			session.triggerDispose();

			// 轮询等待反向代理移除命令执行完成
			const settled = await pollUntilCondition(async () => {
				return recordedCommands.some(cmd => cmd.includes("reverse") && cmd.includes("--remove"));
			});
			expect(settled).toBe(true);

			// 5. 验证：由于外部代理和转发目标已变更，清理逻辑不会执行覆写或删除
			const cmdsAfterDispose = recordedCommands.slice(cmdCountBeforeDispose);

			// 不得调用 settings put / delete 冲掉用户的 corp.proxy.internal:8080
			const proxyClobberCmd = cmdsAfterDispose.find(
				cmd => cmd.includes("settings") && (cmd.includes("put") || cmd.includes("delete")),
			);
			expect(proxyClobberCmd).toBeUndefined();

			// 不得调用 forward --remove 移除已被外部重绑的 9223 端口
			const forwardRemoveCmd = cmdsAfterDispose.find(
				cmd => cmd.includes("forward") && cmd.includes("--remove") && cmd.includes("tcp:9223"),
			);
			expect(forwardRemoveCmd).toBeUndefined();

			// 但自身拥有的 reverse 应当解除
			const reverseRemoveCmd = cmdsAfterDispose.find(cmd => cmd.includes("reverse") && cmd.includes("--remove"));
			expect(reverseRemoveCmd).toBeDefined();
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("removes owned reverse on stop even if device proxy was changed externally", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-rev-rem-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			const recordedCommands: string[][] = [];
			let currentDeviceProxy = "null";
			const activeReverses = `(device) tcp:${port} tcp:${port}\n`;

			const mockRunner: AdbRunner = async (_bin, args) => {
				recordedCommands.push([...args]);
				if (args.includes("devices")) {
					const out = "List of devices attached\nemulator-5554\tdevice\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--list")) {
					return {
						stdout: new TextEncoder().encode(activeReverses),
						stderr: "",
						exitCode: 0,
						outputBytes: activeReverses.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("get")) {
					return {
						stdout: new TextEncoder().encode(currentDeviceProxy + "\n"),
						stderr: "",
						exitCode: 0,
						outputBytes: currentDeviceProxy.length + 1,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("put")) {
					currentDeviceProxy = args[args.length - 1];
					return {
						stdout: new Uint8Array(),
						stderr: "",
						exitCode: 0,
						outputBytes: 0,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("delete")) {
					currentDeviceProxy = "null";
					return {
						stdout: new Uint8Array(),
						stderr: "",
						exitCode: 0,
						outputBytes: 0,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const mockWhich: SkillRequirementWhich = binary =>
				binary === "mitmdump" ? fakeProxy : binary === "adb" ? "/usr/bin/adb" : null;

			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, {
				runner: mockRunner,
				which: mockWhich,
			});

			await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				serial: "emulator-5554",
				configure_device_proxy: true,
			});

			// 外部变更代理
			currentDeviceProxy = "custom.proxy:3128";

			// 停止 MITM
			const stopRes = await tool.execute("stop-call", {
				action: "mitm_capture",
				mitm_op: "stop",
			});

			expect(stopRes.details.status).toBe("ok");
			expect(stopRes.details.proxyRestored).toBe(false);

			// 验证 reverse --remove 被成功调用
			const revRemoveCalled = recordedCommands.some(
				cmd => cmd.includes("reverse") && cmd.includes("--remove") && cmd.includes(`tcp:${port}`),
			);
			expect(revRemoveCalled).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("terminates process and releases host listener when timeout fires", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-timeout-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			const mockWhich: SkillRequirementWhich = binary => (binary === "mitmdump" ? fakeProxy : null);
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			// 启动 MITM，配置 1 秒超时
			const startRes = await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				timeout: 1,
			});
			expect(startRes.details.status).toBe("ok");

			// 验证初始状态为 running
			const statusRes1 = await tool.execute("status-1", { action: "mitm_capture", mitm_op: "status" });
			expect(getContentText(statusRes1)).toContain("running");

			// 真实平台时钟集成测试：轮询等待看门狗超时终结真实子进程
			const timedOut = await pollUntilCondition(async () => {
				const s = await tool.execute("status-2", { action: "mitm_capture", mitm_op: "status" });
				return getContentText(s).includes("idle");
			}, 3000);
			expect(timedOut).toBe(true);

			// 验证本地端口已被完全释放
			const { promise: probePromise, resolve: probeResolve } = Promise.withResolvers<boolean>();
			const server = net.createServer();
			server.once("error", () => probeResolve(false));
			server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
				server.close(() => probeResolve(true));
			});
			const isPortFree = await probePromise;
			expect(isPortFree).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects starting on an already occupied listener without claiming ownership", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-occupied-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		// 先占用该本地端口
		const { promise: listenPromise, resolve: listenResolve } = Promise.withResolvers<net.Server>();
		const occupyingServer = net.createServer();
		occupyingServer.listen({ host: "127.0.0.1", port, exclusive: true }, () => listenResolve(occupyingServer));
		const server = await listenPromise;

		try {
			const mockWhich: SkillRequirementWhich = binary => (binary === "mitmdump" ? fakeProxy : null);
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			const startRes = await tool.execute("start-occupied", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
			});

			expect(startRes.details.status).toBe("error");
			expect(startRes.details.error).toContain("already in use");

			// 验证 tool 状态未被修改为 running
			const statusRes = await tool.execute("status-occupied", { action: "mitm_capture", mitm_op: "status" });
			expect(getContentText(statusRes)).toContain("idle");
		} finally {
			const { promise: closePromise, resolve: closeResolve } = Promise.withResolvers<void>();
			server.close(() => closeResolve());
			await closePromise;
			await removeWithRetries(tempDir);
		}
	});

	it("kills capture process when flow byte growth exceeds cap", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-growth-"));
		// 产出 12MB 数据，超过 10MB 上限
		const fakeProxy = await createFakeMitmdumpScript(tempDir, 12 * 1024 * 1024);
		const port = await getFreePort();

		try {
			const mockWhich: SkillRequirementWhich = binary => (binary === "mitmdump" ? fakeProxy : null);
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			const startRes = await tool.execute("start-flood", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
			});
			expect(startRes.details.status).toBe("ok");

			// 轮询等待字节上限看门狗检测超限并终止子进程
			const killed = await pollUntilCondition(async () => {
				const s = await tool.execute("status-flood", { action: "mitm_capture", mitm_op: "status" });
				return getContentText(s).includes("idle");
			}, 3000);
			expect(killed).toBe(true);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("prevents repeated start from overwriting existing running process", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-repeat-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port1 = await getFreePort();
		const port2 = await getFreePort();

		try {
			const mockWhich: SkillRequirementWhich = binary => (binary === "mitmdump" ? fakeProxy : null);
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			// 首次启动
			const startRes1 = await tool.execute("start-1", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port1,
			});
			expect(startRes1.details.status).toBe("ok");
			expect(startRes1.details.mitmPort).toBe(port1);

			// 第二次启动尝试应当被拦截
			const startRes2 = await tool.execute("start-2", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port2,
			});
			expect(startRes2.details.status).toBe("error");
			expect(startRes2.details.error).toContain("already running or starting");

			// 验证原始进程仍在运行且端口仍为 port1
			const statusRes = await tool.execute("status-check", { action: "mitm_capture", mitm_op: "status" });
			expect(statusRes.details.mitmPort).toBe(port1);

			// 正常停止
			const stopRes = await tool.execute("stop-check", { action: "mitm_capture", mitm_op: "stop" });
			expect(stopRes.details.status).toBe("ok");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("preserves reverse ownership when reverse --list fails (fail-closed)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-rev-fail-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			let listShouldFail = false;
			const recordedCommands: string[][] = [];

			const mockRunner: AdbRunner = async (_bin, args) => {
				recordedCommands.push([...args]);
				if (args.includes("devices")) {
					const out = "List of devices attached\nemulator-5554\tdevice\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--list")) {
					if (listShouldFail) {
						return {
							stdout: new Uint8Array(),
							stderr: "device offline",
							exitCode: 1,
							outputBytes: 0,
							truncated: false,
							timedOut: false,
						};
					}
					const out = `(reverse) tcp:${port} tcp:${port}\n`;
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("get")) {
					return {
						stdout: new TextEncoder().encode("null\n"),
						stderr: "",
						exitCode: 0,
						outputBytes: 5,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const mockWhich: SkillRequirementWhich = binary =>
				binary === "mitmdump" ? fakeProxy : binary === "adb" ? "/usr/bin/adb" : null;
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { runner: mockRunner, which: mockWhich });

			await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				serial: "emulator-5554",
				configure_device_proxy: true,
			});

			// 模拟 reverse --list 查询故障
			listShouldFail = true;
			const preCount = recordedCommands.length;

			const stopRes = await tool.execute("stop-call", {
				action: "mitm_capture",
				mitm_op: "stop",
			});

			// 失败闭环：查询失败时不执行盲目反向代理移除，并上报 error
			expect(stopRes.details.status).toBe("error");
			expect(stopRes.details.error).toContain("reverse --list failed");
			const cmdsAfterStop = recordedCommands.slice(preCount);
			const removeCmd = cmdsAfterStop.find(cmd => cmd.includes("reverse") && cmd.includes("--remove"));
			expect(removeCmd).toBeUndefined();
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("correctly parses AOSP (reverse) format and removes reverse mapping", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-aosp-rev-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			const recordedCommands: string[][] = [];
			const mockRunner: AdbRunner = async (_bin, args) => {
				recordedCommands.push([...args]);
				if (args.includes("devices")) {
					const out = "List of devices attached\nemulator-5554\tdevice\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--list")) {
					// 真实 AOSP adb reverse --list 输出首字段为 (reverse)
					const out = `(reverse) tcp:${port} tcp:${port}\n`;
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("get")) {
					return {
						stdout: new TextEncoder().encode(`127.0.0.1:${port}\n`),
						stderr: "",
						exitCode: 0,
						outputBytes: 15,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const mockWhich: SkillRequirementWhich = binary =>
				binary === "mitmdump" ? fakeProxy : binary === "adb" ? "/usr/bin/adb" : null;
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { runner: mockRunner, which: mockWhich });

			await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				serial: "emulator-5554",
				configure_device_proxy: true,
			});

			const stopRes = await tool.execute("stop-call", { action: "mitm_capture", mitm_op: "stop" });
			expect(stopRes.details.status).toBe("ok");
			expect(stopRes.details.proxyRestored).toBe(true);

			const removeCmd = recordedCommands.find(
				cmd => cmd.includes("reverse") && cmd.includes("--remove") && cmd.includes(`tcp:${port}`),
			);
			expect(removeCmd).toBeDefined();
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("retains failure metadata when reverse --remove execution fails", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-rem-fail-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			let removeShouldFail = false;
			const mockRunner: AdbRunner = async (_bin, args) => {
				if (args.includes("devices")) {
					const out = "List of devices attached\nemulator-5554\tdevice\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--list")) {
					const out = `(reverse) tcp:${port} tcp:${port}\n`;
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("reverse") && args.includes("--remove")) {
					if (removeShouldFail) {
						return {
							stdout: new Uint8Array(),
							stderr: "closed connection",
							exitCode: 1,
							outputBytes: 0,
							truncated: false,
							timedOut: false,
						};
					}
					return {
						stdout: new Uint8Array(),
						stderr: "",
						exitCode: 0,
						outputBytes: 0,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.includes("settings") && args.includes("get")) {
					return {
						stdout: new TextEncoder().encode(`127.0.0.1:${port}\n`),
						stderr: "",
						exitCode: 0,
						outputBytes: 15,
						truncated: false,
						timedOut: false,
					};
				}
				return {
					stdout: new Uint8Array(),
					stderr: "",
					exitCode: 0,
					outputBytes: 0,
					truncated: false,
					timedOut: false,
				};
			};

			const mockWhich: SkillRequirementWhich = binary =>
				binary === "mitmdump" ? fakeProxy : binary === "adb" ? "/usr/bin/adb" : null;
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { runner: mockRunner, which: mockWhich });

			await tool.execute("start-call", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
				serial: "emulator-5554",
				configure_device_proxy: true,
			});

			removeShouldFail = true;
			const stopRes = await tool.execute("stop-call", { action: "mitm_capture", mitm_op: "stop" });
			expect(stopRes.details.status).toBe("error");
			expect(stopRes.details.error).toContain("closed connection");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("clears reservation when startup fails so next start is not wedged", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-wedge-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port = await getFreePort();

		try {
			// which 首次缺失 mitmdump
			let hasMitm = false;
			const mockWhich: SkillRequirementWhich = binary =>
				binary === "mitmdump" ? (hasMitm ? fakeProxy : null) : null;
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			const failRes = await tool.execute("start-fail", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
			});
			expect(failRes.details.status).toBe("missing_dependency");

			// 验证失败后 startingMitm 已重置，后续安装依赖后启动不会报 already starting
			hasMitm = true;
			const succRes = await tool.execute("start-succ", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port,
			});
			expect(succRes.details.status).toBe("ok");

			const stopRes = await tool.execute("stop-succ", { action: "mitm_capture", mitm_op: "stop" });
			expect(stopRes.details.status).toBe("ok");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("cancels in-flight startup when stop is called and allows subsequent start to succeed", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-inflight-stop-"));
		const fakeProxy = await createFakeMitmdumpScript(tempDir);
		const port1 = await getFreePort();
		const port2 = await getFreePort();

		try {
			const mockWhich: SkillRequirementWhich = binary => (binary === "mitmdump" ? fakeProxy : null);
			const session = createLifecycleTestSession(tempDir);
			const tool = new AppExperimentTool(session, { which: mockWhich });

			// 并发发起启动与停止
			const startPromise = tool.execute("start-1", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port1,
			});

			// 稍作让步后立即调用 stop 中断正在进行的 start
			const { promise: yieldPromise, resolve: yieldResolve } = Promise.withResolvers<void>();
			setImmediate(yieldResolve);
			await yieldPromise;

			const stopRes = await tool.execute("stop-intervene", {
				action: "mitm_capture",
				mitm_op: "stop",
			});
			expect(stopRes.details.status).toBe("ok");

			const startRes = await startPromise;
			// 启动应被感知为被中止或错误
			expect(startRes.details.status).toBe("error");

			// 验证在中止后，重新发起新的正常启动能够成功（未死锁或处于永久 starting 状态）
			const nextStartRes = await tool.execute("start-2", {
				action: "mitm_capture",
				mitm_op: "start",
				mitm_port: port2,
			});
			expect(nextStartRes.details.status).toBe("ok");
			expect(nextStartRes.details.mitmPort).toBe(port2);

			const finalStop = await tool.execute("stop-final", { action: "mitm_capture", mitm_op: "stop" });
			expect(finalStop.details.status).toBe("ok");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
