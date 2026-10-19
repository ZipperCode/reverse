import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@reverse/coding-agent/config/settings";
import {
	AdbObserveTool,
	type AdbObserveDetails,
	type AdbRunResult,
	type AdbRunner,
	createTools,
	parseAdbDevices,
	type ToolSession,
} from "@reverse/coding-agent/tools";
import { BUILTIN_TOOL_NAMES, normalizeToolName } from "@reverse/coding-agent/tools/builtin-names";
import { removeWithRetries } from "@reverse/utils";

const PNG_BYTES = Buffer.from([
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89,
]);

interface RunnerCall {
	binary: string;
	args: string[];
	options: { cwd: string; timeoutMs: number; maxBytes: number; signal?: AbortSignal };
}

function createTestSession(
	cwd: string,
	allocateOutputArtifact?: (toolType: string) => Promise<{ id?: string; path?: string }>,
): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
		...(allocateOutputArtifact ? { allocateOutputArtifact } : {}),
	};
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content
		.map(item => item.text ?? "")
		.join("\n")
		.trim();
}

function makeRun(stdout: string | Uint8Array, overrides: Partial<AdbRunResult> = {}): AdbRunResult {
	const bytes = typeof stdout === "string" ? Buffer.from(stdout, "utf8") : stdout;
	return {
		stdout: bytes,
		stderr: "",
		exitCode: 0,
		outputBytes: bytes.byteLength,
		truncated: false,
		timedOut: false,
		...overrides,
	};
}

function createFakeRunner(handler: (args: string[], callIndex: number) => AdbRunResult | Promise<AdbRunResult>): {
	runner: AdbRunner;
	calls: RunnerCall[];
} {
	const calls: RunnerCall[] = [];
	const runner: AdbRunner = async (binary, args, options) => {
		calls.push({ binary, args, options });
		return handler(args, calls.length - 1);
	};
	return { runner, calls };
}

const SINGLE_DEVICE =
	"List of devices attached\nemulator-5554\tdevice product:sdk_gphone64 model:Pixel_6 device:emu64a transport_id:1\n";
const TWO_DEVICES =
	"List of devices attached\nemulator-5554\tdevice product:sdk_gphone64 model:Pixel_6 transport_id:1\nR58M123ABC\tdevice product:o1s model:SM_G991B transport_id:2\n";

describe("adb_observe registration", () => {
	it("is a discoverable builtin with a canonical name", () => {
		expect(BUILTIN_TOOL_NAMES).toContain("adb_observe");
		expect(normalizeToolName("adb_observe")).toBe("adb_observe");
		expect(normalizeToolName("ADB_OBSERVE")).toBe("adb_observe");
	});

	it("instantiates via createTools with read approval", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-reg-"));
		try {
			const tools = await createTools(createTestSession(tempDir), ["adb_observe"]);
			const tool = tools.find(candidate => candidate.name === "adb_observe");
			expect(tool).toBeDefined();
			expect(tool?.approval).toBe("read");
			expect(tool?.strict).toBe(true);
			expect(tool?.loadMode).toBe("discoverable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb device parsing", () => {
	it("parses serial, state, and labeled transport details", () => {
		const devices = parseAdbDevices(
			[
				"* daemon not running; starting now at tcp:5037",
				"List of devices attached",
				"emulator-5554\tdevice product:sdk_gphone64 model:Pixel_6 device:emu64a transport_id:1",
				"R58M123ABC\toffline",
				"192.168.1.5:5555\tunauthorized",
				"",
			].join("\n"),
		);
		expect(devices).toEqual([
			{
				serial: "emulator-5554",
				state: "device",
				details: {
					product: "sdk_gphone64",
					model: "Pixel_6",
					device: "emu64a",
					transport_id: "1",
				},
			},
			{ serial: "R58M123ABC", state: "offline" },
			{ serial: "192.168.1.5:5555", state: "unauthorized" },
		]);
	});
});

describe("adb_observe devices", () => {
	it("runs adb devices -l and returns parsed devices", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-devices-"));
		try {
			const { runner, calls } = createFakeRunner(() => makeRun(TWO_DEVICES));
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-devices", { action: "devices" });
			expect(calls.map(call => call.args)).toEqual([["devices", "-l"]]);
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("ok");
			expect(details.devices).toHaveLength(2);
			expect(details.devices?.[1].serial).toBe("R58M123ABC");
			expect(textOf(result)).toContain("adb_observe devices (2 attached)");
			expect(textOf(result)).toContain("emulator-5554");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects serial for the devices action", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-devices-serial-"));
		try {
			const tool = new AdbObserveTool(createTestSession(tempDir), { which: () => "/usr/bin/adb" });
			await expect(
				tool.execute("call-devices-serial", { action: "devices", serial: "emulator-5554" }),
			).rejects.toThrow('serial is not supported by action "devices"');
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe fixed command argv", () => {
	it("lists packages with -s and filters locally by exact package", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-packages-"));
		try {
			const { runner, calls } = createFakeRunner((args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				expect(args).toEqual(["-s", "emulator-5554", "shell", "pm", "list", "packages", "-f"]);
				return makeRun(
					[
						"package:/data/app/~~abc==/com.example.app-xyz==/base.apk=com.example.app",
						"package:/data/app/other/base.apk=com.other.app",
						"",
					].join("\n"),
				);
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-packages", {
				action: "packages",
				package: "com.example.app",
			});
			expect(calls).toHaveLength(2);
			expect(calls[1].options).toMatchObject({ timeoutMs: 30000, maxBytes: 262144 });
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("ok");
			expect(details.serial).toBe("emulator-5554");
			expect(details.package).toBe("com.example.app");
			expect(textOf(result)).toContain("com.example.app-xyz");
			expect(textOf(result)).not.toContain("com.other.app");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("uses fixed ps argv and filters processes locally", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-processes-"));
		try {
			const { runner, calls } = createFakeRunner((args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun(
					["PID USER NAME", "1234 u0_a123 com.example.app", "5678 u0_a456 com.android.systemui", ""].join("\n"),
				);
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-processes", {
				action: "processes",
				serial: "emulator-5554",
				package: "com.example.app",
			});
			expect(calls[1].args).toEqual(["-s", "emulator-5554", "shell", "ps", "-A", "-o", "PID,USER,NAME"]);
			expect(textOf(result)).toContain("com.example.app");
			expect(textOf(result)).not.toContain("com.android.systemui");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reads props with getprop and filters by key prefix", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-props-"));
		try {
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun(
					[
						"[ro.build.version.sdk]: [34]",
						"[ro.build.version.release]: [14]",
						"[ro.product.model]: [Pixel 6]",
						"",
					].join("\n"),
				);
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-props", {
				action: "props",
				serial: "emulator-5554",
				filter: "ro.build",
			});
			expect(calls[1].args).toEqual(["-s", "emulator-5554", "shell", "getprop"]);
			expect(textOf(result)).toContain("ro.build.version.sdk");
			expect(textOf(result)).not.toContain("ro.product.model");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("builds bounded logcat argv with filter and lines", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-logcat-"));
		try {
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun("10-17 20:00:00.000  1234  1234 I ActivityManager: started\n");
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-logcat", {
				action: "logcat",
				serial: "emulator-5554",
				filter: "ActivityManager:I",
				lines: 300,
			});
			expect(calls[1].args).toEqual([
				"-s",
				"emulator-5554",
				"logcat",
				"-d",
				"-v",
				"threadtime",
				"-t",
				"300",
				"-s",
				"ActivityManager:I",
			]);
			const details = result.details as AdbObserveDetails;
			expect(details.lines).toBe(300);
			expect(details.filter).toBe("ActivityManager:I");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe device selection", () => {
	it("requires a serial when several devices are attached", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-multi-"));
		try {
			const { runner, calls } = createFakeRunner(() => makeRun(TWO_DEVICES));
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-multi", { action: "packages" });
			expect(calls).toHaveLength(1);
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("device_required");
			expect(details.devices).toHaveLength(2);
			expect(textOf(result)).toContain("multiple devices are attached");
			expect(textOf(result)).toContain("R58M123ABC");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("selects an explicit serial among several devices", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-multi-serial-"));
		try {
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(TWO_DEVICES);
				return makeRun("package:/data/app/base.apk=com.other.app\n");
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-multi-serial", {
				action: "packages",
				serial: "R58M123ABC",
			});
			expect(calls[1].args[0]).toBe("-s");
			expect(calls[1].args[1]).toBe("R58M123ABC");
			expect((result.details as AdbObserveDetails).serial).toBe("R58M123ABC");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("auto-selects the only attached device", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-single-"));
		try {
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun("[ro.product.model]: [Pixel 6]\n");
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-single", { action: "props" });
			expect(calls[1].args).toEqual(["-s", "emulator-5554", "shell", "getprop"]);
			expect((result.details as AdbObserveDetails).serial).toBe("emulator-5554");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("reports unauthorized, offline, unavailable, and missing devices as structured states", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-states-"));
		try {
			const cases = [
				{
					output: "List of devices attached\nemulator-5554\tunauthorized\n",
					serial: "emulator-5554",
					status: "device_unauthorized",
				},
				{
					output: "List of devices attached\nemulator-5554\toffline\n",
					serial: "emulator-5554",
					status: "device_offline",
				},
				{
					output: "List of devices attached\nemulator-5554\trecovery\n",
					serial: "emulator-5554",
					status: "device_unavailable",
				},
				{
					output: SINGLE_DEVICE,
					serial: "does-not-exist",
					status: "device_not_found",
				},
			] as const;

			for (const item of cases) {
				const { runner, calls } = createFakeRunner(() => makeRun(item.output));
				const tool = new AdbObserveTool(createTestSession(tempDir), {
					which: () => "/usr/bin/adb",
					runner,
				});
				const result = await tool.execute("call-state", { action: "props", serial: item.serial });
				const details = result.details as AdbObserveDetails;
				expect(details.status).toBe(item.status);
				expect(details.serial).toBe(item.serial);
				expect(calls).toHaveLength(1);
				expect(textOf(result)).toContain(item.serial);
			}
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe parameter validation", () => {
	it("rejects malformed package names", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-invalid-package-"));
		try {
			const tool = new AdbObserveTool(createTestSession(tempDir), { which: () => "/usr/bin/adb" });
			await expect(
				tool.execute("call-bad-package", { action: "packages", package: "com.example; rm -rf /" }),
			).rejects.toThrow("Invalid package name");
			await expect(tool.execute("call-bad-package-2", { action: "packages", package: "   " })).rejects.toThrow(
				"package must not be empty",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects malformed logcat filters and out-of-range lines", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-invalid-logcat-"));
		try {
			const tool = new AdbObserveTool(createTestSession(tempDir), { which: () => "/usr/bin/adb" });
			await expect(
				tool.execute("call-bad-filter", { action: "logcat", filter: "ActivityManager:I *:S" }),
			).rejects.toThrow("Invalid logcat filter");
			await expect(tool.execute("call-bad-lines", { action: "logcat", lines: 0 })).rejects.toThrow(
				"lines must be an integer between 1 and 2000",
			);
			await expect(tool.execute("call-bad-lines-2", { action: "logcat", lines: 2001 })).rejects.toThrow(
				"lines must be an integer between 1 and 2000",
			);
			await expect(tool.execute("call-frac-lines", { action: "logcat", lines: 10.5 })).rejects.toThrow(
				"lines must be an integer between 1 and 2000",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects malformed property filters and serials", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-invalid-prop-"));
		try {
			const tool = new AdbObserveTool(createTestSession(tempDir), { which: () => "/usr/bin/adb" });
			await expect(tool.execute("call-bad-prop", { action: "props", filter: "ro.build;id" })).rejects.toThrow(
				"Invalid property filter",
			);
			await expect(
				tool.execute("call-bad-serial", { action: "props", serial: "emulator-5554;reboot" }),
			).rejects.toThrow("Invalid serial");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects action-inapplicable fields", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-inapplicable-"));
		try {
			const tool = new AdbObserveTool(createTestSession(tempDir), { which: () => "/usr/bin/adb" });
			await expect(
				tool.execute("call-pkg-logcat", { action: "logcat", package: "com.example.app" }),
			).rejects.toThrow('package is not supported by action "logcat"');
			await expect(
				tool.execute("call-filter-packages", { action: "packages", filter: "ActivityManager" }),
			).rejects.toThrow('filter is not supported by action "packages"');
			await expect(tool.execute("call-lines-props", { action: "props", lines: 10 })).rejects.toThrow(
				'lines is not supported by action "props"',
			);
			await expect(tool.execute("call-bad-timeout", { action: "props", timeout: 0 })).rejects.toThrow(
				"timeout must be a number of seconds >= 1",
			);
			await expect(tool.execute("call-bad-max-bytes", { action: "props", max_bytes: 0 })).rejects.toThrow(
				"max_bytes must be a byte count >= 1",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe missing dependency", () => {
	it("returns structured install hint and fallback without running adb", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-missing-"));
		try {
			let called = false;
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => null,
				runner: async () => {
					called = true;
					return makeRun("");
				},
			});
			const result = await tool.execute("call-missing", {
				action: "packages",
				package: "com.example.app",
			});
			expect(called).toBe(false);
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("missing_dependency");
			expect(details.dependency?.available).toBe(false);
			expect(details.dependency?.installHint).toBeTruthy();
			expect(details.dependency?.manualUrl).toContain("developer.android.com");
			expect(details.fallback?.executed).toBe(false);
			expect(details.fallback?.suggestedFallback).toContain("aapt2");
			const text = textOf(result);
			expect(text).toContain("Primary tool 'adb' not found on PATH");
			expect(text).toContain("Install hint:");
			expect(text).toContain("com.example.app");
			expect(text).toContain("Fallback actions were not executed automatically");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe output caps and timeouts", () => {
	it("reports truncated logcat output at max_bytes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-cap-"));
		try {
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun("I/ActivityManager: truncated-line\n", {
					truncated: true,
					outputBytes: 256,
				});
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-cap", {
				action: "logcat",
				max_bytes: 256,
			});
			expect(calls[1].options.maxBytes).toBe(256);
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("ok");
			expect(details.truncated).toBe(true);
			expect(textOf(result)).toContain("truncated at 256 bytes");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("returns a structured error when device listing times out", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-timeout-"));
		try {
			const { runner } = createFakeRunner(() => makeRun("", { timedOut: true, exitCode: 143 }));
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			const result = await tool.execute("call-timeout", { action: "props", timeout: 5 });
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("error");
			expect(details.error).toContain("timed out after 5s");
			expect(textOf(result)).toContain("timed out after 5s");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("aborts before spawning when the signal is already aborted", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-abort-"));
		try {
			let called = false;
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner: async () => {
					called = true;
					return makeRun("");
				},
			});
			const controller = new AbortController();
			controller.abort();
			await expect(tool.execute("call-abort", { action: "devices" }, controller.signal)).rejects.toThrow(
				"Operation aborted",
			);
			expect(called).toBe(false);
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("aborts when the signal fires during a run", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-abort-mid-"));
		try {
			const controller = new AbortController();
			const { runner } = createFakeRunner(() => {
				controller.abort();
				return makeRun(SINGLE_DEVICE);
			});
			const tool = new AdbObserveTool(createTestSession(tempDir), {
				which: () => "/usr/bin/adb",
				runner,
			});
			await expect(tool.execute("call-abort-mid", { action: "props" }, controller.signal)).rejects.toThrow(
				"Operation aborted",
			);
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("adb_observe screencap artifacts", () => {
	it("writes raw PNG bytes to an artifact and returns id/path without embedding bytes", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-screencap-"));
		try {
			const artifactPath = path.join(tempDir, "screenshot.png");
			const allocations: string[] = [];
			const { runner, calls } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun(PNG_BYTES);
			});
			const tool = new AdbObserveTool(
				createTestSession(tempDir, async toolType => {
					allocations.push(toolType);
					return { id: "shot-1", path: artifactPath };
				}),
				{ which: () => "/usr/bin/adb", runner },
			);

			const result = await tool.execute("call-screencap", { action: "screencap", serial: "emulator-5554" });
			expect(calls[1].args).toEqual(["-s", "emulator-5554", "exec-out", "screencap", "-p"]);
			expect(allocations).toEqual(["adb_observe"]);
			expect(new Uint8Array(await Bun.file(artifactPath).arrayBuffer())).toEqual(new Uint8Array(PNG_BYTES));

			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("ok");
			expect(details.artifactId).toBe("shot-1");
			expect(details.artifactPath).toBe(artifactPath);
			expect(details.bytes).toBe(PNG_BYTES.byteLength);
			expect(details.format).toBe("png");
			expect(details.mimeType).toBe("image/png");

			const text = textOf(result);
			expect(text).toContain("artifact://shot-1");
			expect(text).toContain(artifactPath);
			expect(text).not.toContain(PNG_BYTES.toString("binary"));
			expect(text).not.toContain("IHDR");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("discards a truncated screenshot instead of saving a corrupt PNG", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "adb-screencap-cap-"));
		try {
			const artifactPath = path.join(tempDir, "screenshot.png");
			let allocated = false;
			const { runner } = createFakeRunner((_args, index) => {
				if (index === 0) return makeRun(SINGLE_DEVICE);
				return makeRun(PNG_BYTES.subarray(0, 8), {
					truncated: true,
					killedOnOverflow: true,
					outputBytes: 8,
				});
			});
			const tool = new AdbObserveTool(
				createTestSession(tempDir, async () => {
					allocated = true;
					return { id: "shot-truncated", path: artifactPath };
				}),
				{ which: () => "/usr/bin/adb", runner },
			);
			const result = await tool.execute("call-screencap-cap", {
				action: "screencap",
				max_bytes: 8,
			});
			const details = result.details as AdbObserveDetails;
			expect(details.status).toBe("error");
			expect(details.truncated).toBe(true);
			expect(allocated).toBe(false);
			expect(await Bun.file(artifactPath).exists()).toBe(false);
			expect(textOf(result)).toContain("partial PNG was not saved");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
