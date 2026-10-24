import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Settings } from "../src/config/settings";
import {
	generateAndroidJniHarness,
	parseHarnessParams,
	parseJniSignatureParams,
	resolveCustomToolName,
} from "../src/extensibility/unidbg-harness";
import {
	normalizeDynamicEvent,
	dynamicEventToFactInput,
	filterDynamicEvents,
} from "../src/reverse-runtime-session/dynamic-events";
import { validateJdk8 } from "../src/extensibility/unidbg-builder";
import { UnidbgTool } from "../src/tools/unidbg";
import type { ToolSession } from "../src/tools";
import { stopHarnessProcess } from "../src/commands/unidbg";

describe("Issue #2 Regression Tests: Unidbg Automation & Lifecycle", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "unidbg-regression-test-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	describe("1. Parameter & Signature Contract Validation", () => {
		it("explicitly rejects unsupported floating point JNI return types", () => {
			expect(() => {
				generateAndroidJniHarness({
					type: "jni",
					targetPath: "libsample.so",
					className: "com/example/Math",
					entry: "getFloat",
					methodSignature: "()F",
				});
			}).toThrow(/Floating point JNI return types/);

			expect(() => {
				generateAndroidJniHarness({
					type: "jni",
					targetPath: "libsample.so",
					className: "com/example/Math",
					entry: "getDouble",
					methodSignature: "()D",
				});
			}).toThrow(/Floating point JNI return types/);
		});

		it("auto-parses signature parameter types when params is omitted", () => {
			const params = parseJniSignatureParams("([BILjava/lang/String;JZ)V");
			expect(params).toEqual([
				{ name: "bytesParam0", type: "bytes" },
				{ name: "intParam1", type: "int" },
				{ name: "strParam2", type: "string" },
				{ name: "longParam3", type: "long" },
				{ name: "boolParam4", type: "boolean" },
			]);
		});

		it("parses primitive array int[] and Context object parameters", () => {
			const params = parseJniSignatureParams("(Landroid/content/Context;[I[S[Ljava/lang/String;)V");
			expect(params).toEqual([
				{ name: "contextParam0", type: "context", className: "android/content/Context" },
				{ name: "intArrayParam1", type: "int[]" },
				{ name: "shortArrayParam2", type: "short[]" },
				{ name: "stringArrayParam3", type: "string[]" },
			]);
		});

		it("rejects primitive arrays unsupported by upstream Unidbg ([Z, [J, [C)", () => {
			expect(() => {
				parseJniSignatureParams("([Z)V");
			}).toThrow(/Unsupported JNI primitive array parameter descriptor '\[Z'/);

			expect(() => {
				parseJniSignatureParams("([J)V");
			}).toThrow(/Unsupported JNI primitive array parameter descriptor '\[J'/);
		});

		it("normalizes Unidbg dynamic event preserving source, seq, and executionBinding", () => {
			const rawEvent = {
				source: "unidbg",
				seq: 42,
				event: "jni_register_natives",
				status: "confirmed",
				retval: 0,
				class: "com.example.Native",
				methods: [
					{
						name: "calculateHash",
						signature: "([I)Ljava/lang/String;",
						fnPtr: "0x7f001000",
						module: "libnative.so",
						offset: "0x1000",
					},
				],
				metadata: {
					artifactSha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
					arch: "64",
				},
			};
			const norm = normalizeDynamicEvent(rawEvent, "unidbg", "test-session");
			expect(norm.source).toBe("unidbg");
			expect(norm.seq).toBe(42);
			expect(norm.kind).toBe("trace");

			const fact = dynamicEventToFactInput(norm);
			expect(fact.sourceTool).toBe("unidbg");
			expect(fact.executionBinding?.artifactSha256).toBe(
				"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			);
			expect(fact.executionBinding?.deviceAbi).toBe("arm64");
		});
		it("parses structured param array and JSON string param declarations", () => {
			const structured = parseHarnessParams([
				{ name: "ctx", type: "context", className: "android/content/Context" },
				{ name: "buf", type: "bytes" },
				{ name: "counts", type: "int[]" },
			]);
			expect(structured).toEqual([
				{ name: "ctx", type: "context", className: "android/content/Context" },
				{ name: "buf", type: "bytes" },
				{ name: "counts", type: "int[]" },
			]);

			const fromJson = parseHarnessParams('[{"name":"target","type":"object","className":"com/example/Target"}]');
			expect(fromJson).toEqual([{ name: "target", type: "object", className: "com/example/Target" }]);
		});

		it("filters dynamic events by source unidbg correctly", () => {
			const events = [
				normalizeDynamicEvent({ source: "frida", seq: 1 }, "frida", "s1"),
				normalizeDynamicEvent({ source: "unidbg", seq: 2, event: "jni_register_natives" }, "unidbg", "s1"),
			];
			const filtered = filterDynamicEvents(events, { query: "jni_register_natives" });
			expect(filtered.length).toBe(1);
			expect(filtered[0].source).toBe("unidbg");
		});

		it("guards custom tool names against upstream built-in collisions", () => {
			expect(resolveCustomToolName("read_memory")).toBe("invoke_read_memory");
			expect(resolveCustomToolName("check_connection")).toBe("invoke_check_connection");
			expect(resolveCustomToolName("dumpClass")).toBe("invoke_dumpClass");
			expect(resolveCustomToolName("my_crypto_calc")).toBe("my_crypto_calc");
		});
	});

	describe("2. JDK 8 Strict Validation", () => {
		it("rejects non-existent explicit javaHome without silent fallback", () => {
			const res = validateJdk8(path.join(tempDir, "nonexistent-jdk"));
			expect(res.valid).toBe(false);
			expect(res.error).toContain("does not contain a valid Java executable");
		});

		it("strict priority: explicit options.dir overrides ambient env.UNIDBG_HOME", async () => {
			const { inspectUnidbg } = await import("../src/extensibility/unidbg-detect");
			const dirA = path.join(tempDir, "checkout-a");
			const dirB = path.join(tempDir, "checkout-b");
			fs.mkdirSync(path.join(dirA, "unidbg-api"), { recursive: true });
			fs.mkdirSync(path.join(dirB, "unidbg-api"), { recursive: true });
			fs.writeFileSync(
				path.join(dirA, "pom.xml"),
				"<project><groupId>com.github.zhkl0228</groupId><artifactId>unidbg</artifactId></project>",
			);
			fs.writeFileSync(
				path.join(dirB, "pom.xml"),
				"<project><groupId>com.github.zhkl0228</groupId><artifactId>unidbg</artifactId></project>",
			);

			const res = inspectUnidbg({
				dir: dirB,
				env: { UNIDBG_HOME: dirA },
			});
			expect(res.unidbgDir).toBe(dirB);
			expect(res.sourceRoot).toBe(dirB);
		});
	});

	describe("3. UnidbgTool Session Disposal & Abort Guard", () => {
		it("registers disposal callback and stops on session dispose", async () => {
			let disposeHook: (() => void) | undefined;
			let isDisposedState = false;

			const mockSession = {
				cwd: tempDir,
				hasUI: false,
				settings: Settings.isolated({}),
				getSessionFile: () => null,
				getSessionSpawns: () => "*",
				isDisposed: () => isDisposedState,
				registerDisposeCallback: (cb: () => void) => {
					disposeHook = cb;
					return () => {};
				},
			} as unknown as ToolSession;

			const tool = new UnidbgTool(mockSession);
			expect(disposeHook).toBeDefined();

			// Calling status before dispose succeeds
			const statusRes = await tool.execute("call-1", { action: "status" });
			expect(statusRes.details?.success).toBe(true);

			// Trigger session disposal
			isDisposedState = true;
			disposeHook!();

			// Further calls must throw session disposed error
			await expect(tool.execute("call-2", { action: "status" })).rejects.toThrow("Session is already disposed");
		});

		it("rejects scaffold without target binary path", async () => {
			const mockSession = {
				cwd: tempDir,
				hasUI: false,
				settings: Settings.isolated({}),
				getSessionFile: () => null,
				getSessionSpawns: () => "*",
			} as unknown as ToolSession;

			const tool = new UnidbgTool(mockSession);
			await expect(tool.execute("call-3", { action: "scaffold" })).rejects.toThrow("target path is required");
		});
	});

	describe("4. Cross-Process Presence & Control Safety", () => {
		it("forged or stale presence record pointing to unrelated PID does not kill process", async () => {
			const savedAgentDir = process.env.REVERSE_CODING_AGENT_DIR;
			process.env.REVERSE_CODING_AGENT_DIR = tempDir;

			const { spawn } = await import("node:child_process");
			const unrelatedChild = spawn(
				process.execPath,
				["-e", "process.stdout.write('ready\\n'); setInterval(()=>{}, 1000);"],
				{ stdio: ["ignore", "pipe", "ignore"] },
			);

			const { promise: readyPromise, resolve: resolveReady } = Promise.withResolvers<void>();
			unrelatedChild.stdout?.once("data", () => resolveReady());
			await readyPromise;

			const http = await import("node:http");
			const controlServer = http.createServer((req, res) => {
				res.writeHead(403);
				res.end("Forbidden");
			});

			const { promise: portPromise, resolve: resolvePort } = Promise.withResolvers<number>();
			controlServer.listen(0, "127.0.0.1", () => {
				const addr = controlServer.address() as { port: number };
				resolvePort(addr.port);
			});
			const ephemeralPort = await portPromise;

			try {
				expect(unrelatedChild.pid).toBeDefined();

				const harnessesDir = path.join(tempDir, "unidbg-harnesses");
				fs.mkdirSync(harnessesDir, { recursive: true, mode: 0o700 });
				const recordPath = path.join(harnessesDir, "19439.json");

				fs.writeFileSync(
					recordPath,
					JSON.stringify(
						{
							pid: unrelatedChild.pid,
							port: 19439,
							controlPort: ephemeralPort,
							token: "forged-secret-token",
							serverName: "unidbg-mcp-19439",
							sseUrl: "http://localhost:19439/sse",
							ready: true,
							startTime: Date.now(),
						},
						null,
						2,
					),
					{ encoding: "utf8", mode: 0o600 },
				);

				const stopped = await stopHarnessProcess(19439);
				expect(stopped).toBe(false);

				let isStillAlive = false;
				try {
					process.kill(unrelatedChild.pid!, 0);
					isStillAlive = true;
				} catch {
					isStillAlive = false;
				}
				expect(isStillAlive).toBe(true);
			} finally {
				controlServer.close();
				unrelatedChild.kill("SIGKILL");
				if (savedAgentDir !== undefined) {
					process.env.REVERSE_CODING_AGENT_DIR = savedAgentDir;
				} else {
					delete process.env.REVERSE_CODING_AGENT_DIR;
				}
			}
		});
	});
});
