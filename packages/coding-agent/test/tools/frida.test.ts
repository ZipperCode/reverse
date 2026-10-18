import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@rva/coding-agent/tools/builtin-names";
import {
	createTools,
	type ToolSession,
	FridaTool,
	type FridaDetails,
	type FridaRunner,
	FIXED_ENUMERATE_MODULES_SCRIPT,
} from "@rva/coding-agent/tools";
import { Settings } from "@rva/coding-agent/config/settings";

function createTestSession(
	cwd: string,
	options: {
		allocateArtifact?: boolean;
	} = {},
): ToolSession {
	let artifactCounter = 0;
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...(options.allocateArtifact
			? {
					allocateOutputArtifact: async (prefix: string) => {
						artifactCounter++;
						const id = `${prefix}_test_artifact_${artifactCounter}`;
						const artifactPath = path.join(cwd, `${id}.json`);
						return { id, path: artifactPath };
					},
				}
			: {}),
	};
}

async function removeTestDir(dirPath: string): Promise<void> {
	await fs.rm(dirPath, { recursive: true, force: true }).catch(() => {});
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.filter(c => c.type === "text" && c.text)
		.map(c => c.text!)
		.join("\n");
}

const SAMPLE_DEVICES_OUTPUT = `
Id              Type    Name
--------------  ------  ----------------------
local           local   Local System
emulator-5554   usb     Android Emulator 5554
`;

const SAMPLE_PS_OUTPUT = `
 PID  Name                  Identifier
----  --------------------  --------------------
 123  system_server
 456  com.android.phone     com.android.phone
 789  Example App           com.example.app
1001  target_daemon
`;

const SAMPLE_MODULES_OUTPUT =
	'__FRIDA_MODULES_START__[{"name":"libnative-lib.so","base":"0x7f12340000","size":65536,"path":"/data/app/lib/arm64/libnative-lib.so"},{"name":"libc.so","base":"0x7f00000000","size":1048576,"path":"/apex/com.android.runtime/lib64/bionic/libc.so"}]__FRIDA_MODULES_END__';

describe("frida registration and normalization", () => {
	it("is a discoverable builtin with canonical name and exec tier", async () => {
		expect(BUILTIN_TOOL_NAMES).toContain("frida");
		expect(BUILTIN_TOOL_NAMES).not.toContain("frida_observe");
		expect(BUILTIN_TOOL_NAMES).not.toContain("frida_exec");

		expect(normalizeToolName("frida")).toBe("frida");
		expect(normalizeToolName("FRIDA")).toBe("frida");
		expect(normalizeToolName("frida_observe")).toBe("frida");
		expect(normalizeToolName("FRIDA_OBSERVE")).toBe("frida");
		expect(normalizeToolName("frida_exec")).toBe("frida");
		expect(normalizeToolName("FRIDA_EXEC")).toBe("frida");

		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["frida"]);
			const tool = tools.find(c => c.name === "frida");
			expect(tool).toBeDefined();
			expect(tool?.strict).toBe(true);
			expect(tool?.loadMode).toBe("discoverable");
			expect(tool?.approval).toBeUndefined();
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("legacy tool requests resolve to frida through createTools", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-legacy-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["frida_observe"]);
			const tool = tools.find(c => c.name === "frida");
			expect(tool).toBeDefined();
			expect(tool?.name).toBe("frida");
		} finally {
			await removeTestDir(tempDir);
		}
	});
});

describe("frida parameter validation", () => {
	it("requires script or script_path in exec mode", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-val-1-"));
		try {
			const tool = new FridaTool(createTestSession(tempDir));
			await expect(tool.execute("c1", { action: "exec", pid: 1234 })).rejects.toThrow(
				"Must provide either 'script' or 'script_path'",
			);
			await expect(
				tool.execute("c2", {
					action: "exec",
					pid: 1234,
					script: "console.log(1)",
					script_path: "foo.js",
				}),
			).rejects.toThrow("Cannot provide both 'script' and 'script_path'");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("validates target count and pid", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-val-2-"));
		try {
			const tool = new FridaTool(createTestSession(tempDir));
			await expect(tool.execute("c1", { script: "console.log(1)" })).rejects.toThrow("Must specify a target");
			await expect(
				tool.execute("c2", {
					script: "console.log(1)",
					pid: 1234,
					process: "target",
				}),
			).rejects.toThrow("Cannot combine multiple target modes");
			await expect(
				tool.execute("c3", {
					script: "console.log(1)",
					pid: -10,
				}),
			).rejects.toThrow("Target PID must be a positive integer");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("validates transport mutual exclusivity", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-val-3-"));
		try {
			const tool = new FridaTool(createTestSession(tempDir));
			await expect(
				tool.execute("c1", {
					pid: 123,
					script: "console.log(1)",
					usb: true,
					device: "emu-5554",
				}),
			).rejects.toThrow("Cannot specify more than one of 'usb', 'device', and 'host'");
		} finally {
			await removeTestDir(tempDir);
		}
	});
	it("rejects non-finite Infinity for timeout, max_bytes, and max_events", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-val-inf-"));
		try {
			const tool = new FridaTool(createTestSession(tempDir));
			await expect(
				tool.execute("c1", {
					pid: 123,
					script: "console.log(1)",
					timeout: Number.POSITIVE_INFINITY,
				}),
			).rejects.toThrow("timeout must be a finite positive number");
			await expect(
				tool.execute("c2", {
					pid: 123,
					script: "console.log(1)",
					max_bytes: Number.POSITIVE_INFINITY,
				}),
			).rejects.toThrow("max_bytes must be a finite positive number");
			await expect(
				tool.execute("c3", {
					action: "trace",
					pid: 123,
					max_events: Number.POSITIVE_INFINITY,
				}),
			).rejects.toThrow("max_events must be a finite positive number");
		} finally {
			await removeTestDir(tempDir);
		}
	});
});

describe("frida execution and action modes", () => {
	it("executes action 'devices' with frida-ls-devices", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-dev-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from(SAMPLE_DEVICES_OUTPUT),
					stderr: "",
					exitCode: 0,
					outputBytes: SAMPLE_DEVICES_OUTPUT.length,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida-ls-devices" ? "/usr/local/bin/frida-ls-devices" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-1", { action: "devices" });
			expect(calls).toHaveLength(1);
			expect(calls[0].binary).toBe("/usr/local/bin/frida-ls-devices");

			const details = result.details as FridaDetails;
			expect(details.status).toBe("ok");
			expect(details.devices).toHaveLength(2);
			expect(details.devices?.[0].id).toBe("local");
			expect(details.devices?.[1].id).toBe("emulator-5554");
			expect(textOf(result)).toContain("frida devices (2 attached):");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("executes action 'ps' on USB device with applications filter", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-ps-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from(SAMPLE_PS_OUTPUT),
					stderr: "",
					exitCode: 0,
					outputBytes: SAMPLE_PS_OUTPUT.length,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida-ps" ? "/usr/local/bin/frida-ps" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-1", {
				action: "ps",
				usb: true,
				applications: true,
				filter: "Example",
			});
			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-U");
			expect(calls[0].args).toContain("-a");

			const details = result.details as FridaDetails;
			expect(details.status).toBe("ok");
			expect(details.processes).toHaveLength(1);
			expect(details.processes?.[0].pid).toBe(789);
			expect(textOf(result)).toContain("frida ps: usb (1 processes):");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("executes action 'modules' on target PID", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-mods-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from(SAMPLE_MODULES_OUTPUT),
					stderr: "",
					exitCode: 0,
					outputBytes: SAMPLE_MODULES_OUTPUT.length,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-1", { action: "modules", pid: 789 });
			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-p");
			expect(calls[0].args).toContain("789");
			expect(calls[0].args).toContain(FIXED_ENUMERATE_MODULES_SCRIPT);

			const details = result.details as FridaDetails;
			expect(details.status).toBe("ok");
			expect(details.modules).toHaveLength(2);
			expect(details.modules?.[0].name).toBe("libnative-lib.so");
			expect(textOf(result)).toContain("frida modules: pid 789 (2 modules):");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("executes action 'exec' with custom script and remote host", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-host-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("Hook executed successfully on remote server"),
					stderr: "",
					exitCode: 0,
					outputBytes: 42,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-1", {
				spawn: "com.example.app",
				host: "192.168.1.100:27042",
				script: "Java.perform(function() { console.log('Attached'); });",
				script_args: { secretKey: "abc" },
				cli_args: ["--runtime=v8"],
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-H");
			expect(calls[0].args).toContain("192.168.1.100:27042");
			expect(calls[0].args).toContain("-f");
			expect(calls[0].args).toContain("com.example.app");
			expect(calls[0].args).toContain("--no-pause");
			expect(calls[0].args).toContain("-e");
			expect(calls[0].args).toContain("-P");
			expect(calls[0].args).toContain('{"secretKey":"abc"}');
			expect(calls[0].args).toContain("--runtime=v8");

			const details = result.details as FridaDetails;
			expect(details.status).toBe("ok");
			expect(details.targetMode).toBe("spawn");
			expect(textOf(result)).toContain("frida completed successfully on spawn com.example.app");
			expect(textOf(result)).toContain("Hook executed successfully on remote server");
		} finally {
			await removeTestDir(tempDir);
		}
	});
	it("executes action 'trace' with custom script, spawn, and large max_events", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-trace-cust-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("Custom trace output: function sub_1400 entered"),
					stderr: "",
					exitCode: 0,
					outputBytes: 46,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-trace", {
				action: "trace",
				spawn: "com.example.app",
				script: "Interceptor.attach(ptr('0x1400'), { onEnter() { console.log('sub_1400'); } });",
				max_events: 50000,
				cli_args: "--realm=native",
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-f");
			expect(calls[0].args).toContain("com.example.app");
			expect(calls[0].args).toContain("-e");
			expect(calls[0].args).toContain("--realm=native");

			const details = result.details as FridaDetails;
			expect(details.status).toBe("ok");
			expect(details.action).toBe("trace");
			expect(textOf(result)).toContain("Custom trace output: function sub_1400 entered");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("saves large outputs to artifact and handles failure exit codes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-art-"));
		try {
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from(""),
				stderr: "Error: Process crashed",
				exitCode: 1,
				outputBytes: 21,
				truncated: false,
				timedOut: false,
			});

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir, { allocateArtifact: true }), { runner, which });

			const result = await tool.execute("call-1", {
				pid: 1234,
				script: "console.log(1)",
				to_artifact: true,
			});

			const details = result.details as FridaDetails;
			expect(details.status).toBe("error");
			expect(details.exitCode).toBe(1);
			expect(details.artifactId).toBeDefined();
			expect(textOf(result)).toContain("frida failed on pid 1234 (exit code 1)");
			expect(textOf(result)).toContain("Error: Process crashed");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("gracefully detects device offline and missing dependency", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-err-"));
		try {
			const noFridaTool = new FridaTool(createTestSession(tempDir), { which: () => null });
			const missingResult = await noFridaTool.execute("c1", { action: "devices" });
			const missingDetails = missingResult.details as FridaDetails;
			expect(missingDetails.status).toBe("missing_dependency");
			expect(textOf(missingResult)).toContain("Frida tools are not available");

			const runner: FridaRunner = async () => ({
				stdout: Buffer.from(""),
				stderr: "Failed to enumerate devices: device offline",
				exitCode: 1,
				outputBytes: 0,
				truncated: false,
				timedOut: false,
			});
			const which = (cmd: string) => (cmd === "frida-ls-devices" ? "/usr/local/bin/frida-ls-devices" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });
			const offlineResult = await tool.execute("c2", { action: "devices" });
			const offlineDetails = offlineResult.details as FridaDetails;
			expect(offlineDetails.status).toBe("device_offline");
		} finally {
			await removeTestDir(tempDir);
		}
	});
	it("executes action 'modules' with custom script instead of fixed template", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-mods-cust-"));
		try {
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("Custom module scanner output"),
					stderr: "",
					exitCode: 0,
					outputBytes: 28,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-mod-cust", {
				action: "modules",
				pid: 789,
				script: "console.log('custom module logic');",
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-p");
			expect(calls[0].args).toContain("789");
			expect(calls[0].args).toContain("console.log('custom module logic');");
			expect(calls[0].args).not.toContain(FIXED_ENUMERATE_MODULES_SCRIPT);
			expect(textOf(result)).toContain("Custom module scanner output");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("preserves authentic raw output without redacting sensitive tokens or credentials", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-unredacted-"));
		try {
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from("auth_token=super_secret_token_12345 password=mypassword"),
				stderr: "",
				exitCode: 0,
				outputBytes: 54,
				truncated: false,
				timedOut: false,
			});

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-unredacted", {
				action: "trace",
				pid: 1234,
				script: "console.log(Memory.readUtf8String(ptr('0x1234')))",
			});

			expect(textOf(result)).toContain("auth_token=super_secret_token_12345");
			expect(textOf(result)).toContain("password=mypassword");
			expect(textOf(result)).not.toContain("[redacted]");
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("supports string cli_args and uncapped timeout/max_bytes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-uncapped-"));
		try {
			let capturedTimeoutMs = 0;
			let capturedMaxBytes = 0;
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args, opts) => {
				calls.push({ binary, args });
				capturedTimeoutMs = opts.timeoutMs ?? 0;
				capturedMaxBytes = opts.maxBytes ?? 0;
				return {
					stdout: Buffer.from("Uncapped execution success"),
					stderr: "",
					exitCode: 0,
					outputBytes: 26,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-uncapped", {
				pid: 1234,
				script: "console.log(1)",
				cli_args: '--runtime=v8 -o "log path.txt" --realm=native',
				timeout: 1000,
				max_bytes: 10 * 1024 * 1024,
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("--runtime=v8");
			expect(calls[0].args).toContain("-o");
			expect(calls[0].args).toContain("log path.txt");
			expect(calls[0].args).toContain("--realm=native");
			expect(calls[0].args).toContain("-t");
			expect(calls[0].args).toContain("1000");
			expect(capturedTimeoutMs).toBe(1002 * 1000);
			expect(capturedMaxBytes).toBe(10 * 1024 * 1024);
			expect(textOf(result)).toContain("Uncapped execution success");
		} finally {
			await removeTestDir(tempDir);
		}
	});
	it("omits -t flag and timeout watchdog when timeout is not passed", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-no-timeout-"));
		try {
			let capturedOpts: { timeoutMs?: number } | undefined;
			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args, opts) => {
				calls.push({ binary, args });
				capturedOpts = opts;
				return {
					stdout: Buffer.from("No timeout execution"),
					stderr: "",
					exitCode: 0,
					outputBytes: 20,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			await tool.execute("call-no-t", {
				pid: 1234,
				script: "console.log(1)",
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).not.toContain("-t");
			expect(capturedOpts?.timeoutMs).toBeUndefined();
		} finally {
			await removeTestDir(tempDir);
		}
	});

	it("allows absolute script_path outside workspace directory", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-ws-"));
		const externalDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-ext-"));
		try {
			const scriptFile = path.join(externalDir, "external_hook.js");
			await fs.writeFile(scriptFile, "console.log('external hook loaded');");

			const calls: Array<{ binary: string; args: string[] }> = [];
			const runner: FridaRunner = async (binary, args) => {
				calls.push({ binary, args });
				return {
					stdout: Buffer.from("external hook success"),
					stderr: "",
					exitCode: 0,
					outputBytes: 21,
					truncated: false,
					timedOut: false,
				};
			};

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir), { runner, which });

			const result = await tool.execute("call-abs-path", {
				pid: 1234,
				script_path: scriptFile,
			});

			expect(calls).toHaveLength(1);
			expect(calls[0].args).toContain("-l");
			expect(calls[0].args).toContain(scriptFile);
			expect(textOf(result)).toContain("external hook success");
		} finally {
			await removeTestDir(tempDir);
			await removeTestDir(externalDir);
		}
	});

	it("stores complete stdout/stderr in artifact even when prompt display text is truncated", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "frida-full-art-"));
		try {
			const fullStdout = "A".repeat(1000);
			const runner: FridaRunner = async () => ({
				stdout: Buffer.from(fullStdout),
				stderr: "some stderr text",
				exitCode: 0,
				outputBytes: fullStdout.length,
				truncated: false,
				timedOut: false,
			});

			const which = (cmd: string) => (cmd === "frida" ? "/usr/local/bin/frida" : null);
			const tool = new FridaTool(createTestSession(tempDir, { allocateArtifact: true }), { runner, which });

			const result = await tool.execute("call-art-trunc", {
				pid: 1234,
				script: "console.log(1)",
				max_bytes: 100, // display cap at 100 bytes
				to_artifact: true,
			});

			const details = result.details as FridaDetails;
			expect(details.truncated).toBe(true);
			expect(details.outputBytes).toBe(1000);
			expect(details.stdout).toBe(fullStdout); // memory details are complete
			expect(textOf(result)).toContain("output truncated at 100 bytes for display");

			// Verify artifact on disk contains the full 1000-byte output
			expect(details.artifactPath).toBeDefined();
			const savedJson = JSON.parse(await fs.readFile(details.artifactPath!, "utf8"));
			expect(savedJson.stdout).toBe(fullStdout);
			expect(savedJson.truncated).toBe(false);
		} finally {
			await removeTestDir(tempDir);
		}
	});
});
