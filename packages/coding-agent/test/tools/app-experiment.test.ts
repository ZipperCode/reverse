import { describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as http from "node:http";
import type { AddressInfo } from "node:net";

import { Settings } from "../../src/config/settings";
import { AppExperimentTool } from "../../src/tools/app-experiment";
import type { ToolSession } from "../../src/tools";
import type { AdbRunner } from "../../src/tools/adb-observe";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";
import { removeWithRetries } from "@reverse/utils";

function createTestSession(cwd: string): ToolSession {
	return {
		cwd,
		hasUI: true,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "tools.xdev": false }),
	};
}

interface TestLoopbackServer {
	origin: string;
	close: () => Promise<void>;
}

function createLoopbackServer(
	handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<TestLoopbackServer> {
	const { promise, resolve, reject } = Promise.withResolvers<TestLoopbackServer>();
	const server = http.createServer(handler);
	server.listen(0, "127.0.0.1", () => {
		const addr = server.address() as AddressInfo;
		const origin = `http://127.0.0.1:${addr.port}`;
		resolve({
			origin,
			close: () => {
				const closeRes = Promise.withResolvers<void>();
				server.close(err => (err ? closeRes.reject(err) : closeRes.resolve()));
				return closeRes.promise;
			},
		});
	});
	server.on("error", reject);
	return promise;
}

const SYNC_WHICH_ADB: SkillRequirementWhich = (binary: string) => (binary === "adb" ? "/usr/bin/adb" : null);

describe("app_experiment ApprovalGates tier enforcement", () => {
	it("enforces ApprovalGates per-action tiers and fails closed for unknown actions", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-approval-"));
		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));
			expect(tool.approval({ action: "preflight" })).toBe("read");
			expect(tool.approval({ action: "extract_sandbox_data" })).toBe("write");
			expect(tool.approval({ action: "mitm_capture" })).toBe("exec");
			expect(tool.approval({ action: "invoke_component" })).toBe("exec");
			expect(tool.approval({ action: "query_provider" })).toBe("exec");
			expect(tool.approval({ action: "webview_debug" })).toBe("exec");
			expect(tool.approval({ action: "network_replay" })).toBe("exec");
			expect(tool.approval({ action: "pinning_diagnose", pinning_mode: "detect" })).toBe("read");
			expect(tool.approval({ action: "pinning_diagnose", pinning_mode: "hook_report" })).toBe("exec");
			expect(tool.approval({ action: "unknown_future_action" })).toBe("exec");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment safety boundaries and parameter validation", () => {
	it("rejects missing serial and invalid package names upfront", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-val-"));
		try {
			const tool = new AppExperimentTool(createTestSession(tempDir), { which: SYNC_WHICH_ADB });
			await expect(tool.execute("call-1", { action: "preflight", package: "com.example.app" })).rejects.toThrow(
				"requires explicit 'serial'",
			);

			await expect(
				tool.execute("call-2", { action: "preflight", serial: "emulator-5554", package: "invalid;package&name" }),
			).rejects.toThrow("Invalid package name");

			await expect(
				tool.execute("call-3", { action: "preflight", serial: "serial;rm -rf /", package: "com.example.app" }),
			).rejects.toThrow("Invalid serial");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects path traversal, leading hyphens, and shell characters in sandbox extraction", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-trav-"));
		try {
			const tool = new AppExperimentTool(createTestSession(tempDir), { which: SYNC_WHICH_ADB });
			await expect(
				tool.execute("call-1", {
					action: "extract_sandbox_data",
					serial: "emulator-5554",
					package: "com.example.app",
					subpath: "../../etc/passwd",
				}),
			).rejects.toThrow("path traversal, absolute paths");

			await expect(
				tool.execute("call-2", {
					action: "extract_sandbox_data",
					serial: "emulator-5554",
					package: "com.example.app",
					subpath: "/data/system/users",
				}),
			).rejects.toThrow("path traversal, absolute paths");

			await expect(
				tool.execute("call-3", {
					action: "extract_sandbox_data",
					serial: "emulator-5554",
					package: "com.example.app",
					subpath: "-option_injection",
				}),
			).rejects.toThrow("leading hyphens");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects inline sensitive credential headers and URL tokens in network_replay", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-sec-"));
		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			// 1. Rejects inline Authorization header to prevent transcript/TUI exposure
			await expect(
				tool.execute("call-1", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: {
						url: "https://api.example.com/v1/profile",
						headers: { Authorization: "Bearer secret-token-12345" },
					},
				}),
			).rejects.toThrow("Inline credential header 'Authorization' in tool arguments is prohibited");

			// 2. Rejects inline Cookie header
			await expect(
				tool.execute("call-2", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: {
						url: "https://api.example.com/v1/profile",
						headers: { Cookie: "session=abcdef" },
					},
				}),
			).rejects.toThrow("Inline credential header 'Cookie' in tool arguments is prohibited");

			// 3. Rejects sensitive token query parameters in URL
			await expect(
				tool.execute("call-3", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: {
						url: "https://api.example.com/v1/profile?access_token=secret123",
					},
				}),
			).rejects.toThrow("Inline sensitive credential query parameter 'access_token' is prohibited");

			// 4. Rejects embedded username/password in URL
			await expect(
				tool.execute("call-4", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: {
						url: "https://user:password@api.example.com/v1/profile",
					},
				}),
			).rejects.toThrow("Embedded username or password in URL is prohibited");

			// 5. Fails closed if auth_header_env references a missing environment variable
			await expect(
				tool.execute("call-5", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: {
						url: "https://api.example.com/v1/profile",
						auth_header_env: "NONEXISTENT_AUTH_ENV_VAR_12345",
					},
				}),
			).rejects.toThrow("NONEXISTENT_AUTH_ENV_VAR_12345' specified in auth_header_env is not set or empty");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("enforces allowed_origins boundary in network_replay", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-origin-"));
		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "network_replay",
					allowed_origins: [],
					baseline_request: { url: "https://api.example.com/test" },
				}),
			).rejects.toThrow("strictly requires non-empty 'allowed_origins'");

			await expect(
				tool.execute("call-2", {
					action: "network_replay",
					allowed_origins: ["https://api.example.com"],
					baseline_request: { url: "https://malicious.attacker.com/steal" },
				}),
			).rejects.toThrow("is not in allowed_origins [https://api.example.com]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment device state classification", () => {
	it("classifies device_not_found, device_unauthorized, device_offline accurately", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-dev-states-"));
		try {
			const mockRunner: AdbRunner = async (_bin, args) => {
				if (args.includes("devices")) {
					const out =
						"List of devices attached\nemulator-5554\tdevice\nemulator-5556\tunauthorized\nemulator-5558\toffline\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			const notFound = await tool.execute("call-1", {
				action: "preflight",
				serial: "emulator-9999",
				package: "com.example.app",
			});
			expect(notFound.details.status).toBe("device_not_found");

			const unauth = await tool.execute("call-2", {
				action: "preflight",
				serial: "emulator-5556",
				package: "com.example.app",
			});
			expect(unauth.details.status).toBe("device_unauthorized");

			const offline = await tool.execute("call-3", {
				action: "preflight",
				serial: "emulator-5558",
				package: "com.example.app",
			});
			expect(offline.details.status).toBe("device_offline");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("refuses sandbox extraction on non-debuggable build without root escalation", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-runas-"));
		try {
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
				if (args.includes("run-as") && args.includes("id")) {
					const err = "run-as: package not debuggable: com.example.release\n";
					return {
						stdout: new TextEncoder().encode(err),
						stderr: err,
						exitCode: 1,
						outputBytes: err.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			const res = await tool.execute("call-1", {
				action: "extract_sandbox_data",
				serial: "emulator-5554",
				package: "com.example.release",
			});

			expect(res.details.status).toBe("unauthorized");
			expect(res.details.error).toContain("Package not debuggable");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment ContentProvider authority boundary and error handling", () => {
	it("rejects ContentProvider queries when authority belongs to another package in dumpsys", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-prov-auth-"));
		try {
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
				if (args.includes("dumpsys") && args.includes("package")) {
					const out =
						"Package [com.example.targetapp] (33bca2c):\n  userId=10123\n  ContentProvider Authorities:\n    [com.example.targetapp.provider]:\n      Provider{45e7aa com.example.targetapp/.AppProvider}\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			await expect(
				tool.execute("call-1", {
					action: "query_provider",
					serial: "emulator-5554",
					package: "com.example.targetapp",
					uri: "content://telephony/siminfo",
				}),
			).rejects.toThrow("does not resolve to target package 'com.example.targetapp'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("executes valid provider query with colon projection and redacts sensitive columns", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-prov-query-"));
		try {
			let executedCmd: string[] = [];
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
				if (args.includes("dumpsys") && args.includes("package")) {
					const out =
						"Package [com.example.app] (33bca2c):\n  ContentProvider Authorities:\n    [com.example.app.provider]:\n      Provider{45e7aa com.example.app/.UserProvider}\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.some(a => a.includes("content")) && args.some(a => a.includes("query"))) {
					executedCmd = args;
					const out =
						"Row: 0 _id=1, username=alice, password=plaintext_secret, token=xyz123\nRow: 1 _id=2, username=bob, password=hunter2, token=abc456\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			const res = await tool.execute("call-1", {
				action: "query_provider",
				serial: "emulator-5554",
				package: "com.example.app",
				uri: "content://com.example.app.provider/users",
				projection: "_id, username, password, token",
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.rowCount).toBe(2);

			// Verify projection was mapped to colon-separated representation in command
			const joined = executedCmd.join(" ");
			expect(joined).toContain("--projection");
			expect(joined).toContain("_id:username:password:token");

			// Verify sensitive columns were redacted in rows preview
			const rows = res.details.rowsPreview!;
			expect(rows.length).toBe(2);
			expect(rows[0].username).toBe("alice");
			expect(rows[0].password).toBe("[REDACTED]");
			expect(rows[0].token).toBe("[REDACTED]");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("classifies AOSP content query exception output as error instead of ok", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-prov-err-"));
		try {
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
				if (args.includes("dumpsys") && args.includes("package")) {
					const out =
						"Package [com.example.app] (33bca2c):\n  ContentProvider Authorities:\n    [com.example.app.provider]:\n      Provider{45e7aa com.example.app/.UserProvider}\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
						truncated: false,
						timedOut: false,
					};
				}
				if (args.some(a => a.includes("content")) && args.some(a => a.includes("query"))) {
					// Real AOSP Content.java output on SQLite exception (exit code is 0)
					const out =
						"Error while accessing provider:com.example.app.provider\nandroid.database.sqlite.SQLiteException: no such table: unknown_table\n";
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			const res = await tool.execute("call-1", {
				action: "query_provider",
				serial: "emulator-5554",
				package: "com.example.app",
				uri: "content://com.example.app.provider/unknown_table",
			});

			expect(res.details.status).toBe("error");
			expect(res.details.error).toContain("Error while accessing provider");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment command quoting and deep link scoping", () => {
	it("adds -p packageName and quotes shell arguments with $ and special characters", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-cmd-quote-"));
		try {
			let capturedArgs: string[] = [];
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
				capturedArgs = args;
				return {
					stdout: new TextEncoder().encode("Starting: Intent { ... }\n"),
					stderr: "",
					exitCode: 0,
					outputBytes: 25,
					truncated: false,
					timedOut: false,
				};
			};

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			// Invocation with inner class name containing $ and deep link with query parameters
			await tool.execute("call-1", {
				action: "invoke_component",
				serial: "emulator-5554",
				package: "com.example.app",
				component: "com.example.app/.MainActivity$InnerActivity",
				intent_action: "android.intent.action.VIEW",
				intent_data: "myapp://view/item?id=123&sort=asc",
			});

			// Verify POSIX single quoting protected the $ and & from device shell expansion
			const joined = capturedArgs.join(" ");
			expect(joined).toContain("'com.example.app/.MainActivity$InnerActivity'");
			expect(joined).toContain("'myapp://view/item?id=123&sort=asc'");

			// Deep link without component must include -p com.example.app to prevent resolving random apps
			await tool.execute("call-2", {
				action: "invoke_component",
				serial: "emulator-5554",
				package: "com.example.app",
				intent_action: "android.intent.action.VIEW",
				intent_data: "https://example.com/verify",
			});

			const joined2 = capturedArgs.join(" ");
			expect(joined2).toContain("'-p' 'com.example.app'");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment network replay comparison", () => {
	it("executes loopback baseline POST with body inherited and unauth variant 403 with different body hash (pending verification)", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-smoke-"));
		const receivedRequests: Array<{ method?: string; url?: string; authorization?: string; body: string }> = [];

		const server = await createLoopbackServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", c => chunks.push(c));
			req.on("end", () => {
				const body = Buffer.concat(chunks).toString("utf8");
				receivedRequests.push({
					method: req.method,
					url: req.url,
					authorization: req.headers["authorization"],
					body,
				});

				if (req.headers["authorization"] === "Bearer test_alice_token") {
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ status: "ok", role: "admin" }));
				} else {
					res.writeHead(403, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "forbidden" }));
				}
			});
		});

		try {
			process.env["TEST_ALICE_TOKEN"] = "test_alice_token";
			const itemBodyPath = path.join(tempDir, "item.json");
			await fs.writeFile(itemBodyPath, '{"item":"widget"}', { encoding: "utf8", mode: 0o600 });

			const tool = new AppExperimentTool(createTestSession(tempDir));

			const res = await tool.execute("call-1", {
				action: "network_replay",
				allowed_origins: [server.origin],
				baseline_request: {
					url: `${server.origin}/api/items`,
					method: "POST",
					body_file: itemBodyPath,
					auth_header_env: "TEST_ALICE_TOKEN",
				},
				variant_requests: [
					{
						id: "unauth_variant",
						name: "Unauthenticated Variant",
					},
				],
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.acceptance).toBe("pending_verification");
			expect(res.details.baselineResult?.status).toBe(200);
			expect(res.details.baselineResult?.bodyBytes).toBeGreaterThan(0);

			const variants = res.details.variantResults!;
			expect(variants.length).toBe(1);

			const v0 = variants[0];
			expect(v0.status).toBe(403);
			expect(v0.diffAgainstBaseline?.statusMatch).toBe(false);
			expect(v0.diffAgainstBaseline?.bodyHashMatch).toBe(false);

			// Verify server observed requests: baseline with auth, variant unauthenticated but inheriting POST and body
			expect(receivedRequests.length).toBe(2);
			expect(receivedRequests[0].method).toBe("POST");
			expect(receivedRequests[0].body).toBe('{"item":"widget"}');
			expect(receivedRequests[0].authorization).toBe("Bearer test_alice_token");

			expect(receivedRequests[1].method).toBe("POST");
			expect(receivedRequests[1].body).toBe('{"item":"widget"}');
			expect(receivedRequests[1].authorization).toBeUndefined();
		} finally {
			delete process.env["TEST_ALICE_TOKEN"];
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("aborts before making any network calls if a later variant is invalid", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-invalid-"));
		let requestCount = 0;
		const server = await createLoopbackServer((_req, res) => {
			requestCount++;
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end('{"ok":true}');
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "network_replay",
					allowed_origins: [server.origin],
					baseline_request: {
						url: `${server.origin}/api/data`,
						method: "GET",
					},
					variant_requests: [
						{
							id: "v1_valid",
							url: `${server.origin}/api/data`,
						},
						{
							id: "v2_invalid_query",
							url: `${server.origin}/api/data?access_token=leaked_secret`,
						},
					],
				}),
			).rejects.toThrow("Inline sensitive credential query parameter 'access_token' is prohibited");

			// Ensure ZERO network requests were dispatched because prevalidation rejected all variants upfront
			expect(requestCount).toBe(0);
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("aborts before making any network calls if referenced credential environment variable is missing", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-missing-env-"));
		let requestCount = 0;
		const server = await createLoopbackServer((_req, res) => {
			requestCount++;
			res.writeHead(200, { "Content-Type": "application/json" });
			res.end('{"ok":true}');
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			await expect(
				tool.execute("call-1", {
					action: "network_replay",
					allowed_origins: [server.origin],
					baseline_request: {
						url: `${server.origin}/api/data`,
						method: "GET",
					},
					variant_requests: [
						{
							id: "v1_missing_env",
							auth_header_env: "DEFINITELY_UNSET_AUTH_ENV_9999",
						},
					],
				}),
			).rejects.toThrow("DEFINITELY_UNSET_AUTH_ENV_9999' specified in auth_header_env is not set or empty");

			// Ensure ZERO network requests were dispatched
			expect(requestCount).toBe(0);
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("handles timeout and abort signal cancellation cleanly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-abort-"));
		const abortController = new AbortController();
		let requestReceived = false;

		const server = await createLoopbackServer((_req, _res) => {
			requestReceived = true;
			// Abort in-flight after the request has reached the server
			abortController.abort("user_cancelled");
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			await expect(
				tool.execute(
					"call-1",
					{
						action: "network_replay",
						allowed_origins: [server.origin],
						baseline_request: {
							url: `${server.origin}/api/hang`,
							method: "GET",
						},
					},
					abortController.signal,
				),
			).rejects.toThrow();

			expect(requestReceived).toBe(true);
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("does not follow redirects and redacts query and fragment from Location header", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-redirect-redact-"));
		let redirectFollowed = false;

		const server = await createLoopbackServer((req, res) => {
			if (req.url?.startsWith("/login")) {
				res.writeHead(302, {
					Location: "/callback?code=sensitive_code_secret&state=123#access_token=fragment_token_secret",
				});
				res.end();
			} else if (req.url?.startsWith("/callback")) {
				redirectFollowed = true;
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end('{"callback":true}');
			} else {
				res.writeHead(404);
				res.end();
			}
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			const res = await tool.execute("call-1", {
				action: "network_replay",
				allowed_origins: [server.origin],
				baseline_request: { url: `${server.origin}/login` },
			});

			expect(res.details.status).toBe("ok");
			// Manual redirect: 302 received, redirect was NOT followed
			expect(res.details.baselineResult?.status).toBe(302);
			expect(redirectFollowed).toBe(false);

			const locationHeader = res.details.baselineResult?.headers["location"];
			expect(locationHeader).toBeDefined();
			expect(locationHeader).toBe(`${server.origin}/callback`);
			expect(locationHeader).not.toContain("sensitive_code_secret");
			expect(locationHeader).not.toContain("fragment_token_secret");
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("marks bodyHashMatch as null when responses are truncated to prevent false common-prefix matches", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-trunc-"));
		// Prefix is identical 1500 bytes (exceeding min cap 1024), but tail differs
		const commonPrefix = "A".repeat(1500);
		const baselinePayload = commonPrefix + "_BASELINE_TAIL_UNIQUE_12345";
		const variantPayload = commonPrefix + "_VARIANT_TAIL_DIFFERENT_67890";

		const server = await createLoopbackServer((req, res) => {
			res.writeHead(200, { "Content-Type": "text/plain" });
			if (req.url?.includes("variant")) {
				res.end(variantPayload);
			} else {
				res.end(baselinePayload);
			}
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			const res = await tool.execute("call-1", {
				action: "network_replay",
				allowed_origins: [server.origin],
				max_bytes: 1024, // Exact min cap boundary
				baseline_request: {
					url: `${server.origin}/baseline`,
					method: "GET",
				},
				variant_requests: [
					{
						id: "var_trunc",
						url: `${server.origin}/variant`,
					},
				],
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.baselineResult?.bodyTruncated).toBe(true);
			expect(res.details.baselineResult?.bodyHashScope).toBe("truncated_prefix");

			const v0 = res.details.variantResults![0];
			expect(v0.bodyTruncated).toBe(true);
			expect(v0.bodyHashScope).toBe("truncated_prefix");

			// Truncated responses cannot prove complete content equality: must be null, not true
			expect(v0.diffAgainstBaseline?.bodyHashMatch).toBeNull();
			expect(v0.diffAgainstBaseline?.statusDelta).toContain("(body truncated; hash match unknown)");
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});

	it("supports protected request_file and body_file, rejecting non-regular files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-replay-files-"));
		const subDir = path.join(tempDir, "directory_not_file");
		await fs.mkdir(subDir);

		let serverReceivedBody = "";
		const server = await createLoopbackServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", c => chunks.push(c));
			req.on("end", () => {
				serverReceivedBody = Buffer.concat(chunks).toString("utf8");
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end('{"file_replay":true}');
			});
		});

		try {
			const tool = new AppExperimentTool(createTestSession(tempDir));

			// 1. Rejects directory as request_file
			await expect(
				tool.execute("call-1", {
					action: "network_replay",
					allowed_origins: [server.origin],
					request_file: subDir,
				}),
			).rejects.toThrow("is not a regular file");

			// 2. Loads body from protected body_file and executes replay
			const bodyFilePath = path.join(tempDir, "payload.json");
			await fs.writeFile(bodyFilePath, JSON.stringify({ protected: "credentials_in_file" }), {
				encoding: "utf8",
				mode: 0o600,
			});

			const reqFilePath = path.join(tempDir, "request.json");
			await fs.writeFile(
				reqFilePath,
				JSON.stringify({
					baseline_request: {
						url: `${server.origin}/api/file_test`,
						method: "POST",
						body_file: bodyFilePath,
					},
				}),
				{ encoding: "utf8", mode: 0o600 },
			);

			// 3. Rejects world/group-readable files on POSIX
			if (process.platform !== "win32") {
				const publicFilePath = path.join(tempDir, "public_req.json");
				await fs.writeFile(
					publicFilePath,
					JSON.stringify({
						baseline_request: {
							url: `${server.origin}/api/file_test`,
							method: "GET",
						},
					}),
					{ encoding: "utf8", mode: 0o644 },
				);
				await expect(
					tool.execute("call-insecure", {
						action: "network_replay",
						allowed_origins: [server.origin],
						request_file: publicFilePath,
					}),
				).rejects.toThrow("has insecure permissions");
			}

			const res = await tool.execute("call-2", {
				action: "network_replay",
				allowed_origins: [server.origin],
				request_file: reqFilePath,
			});

			expect(res.details.status).toBe("ok");
			expect(res.details.baselineResult?.status).toBe(200);
			expect(JSON.parse(serverReceivedBody)).toEqual({ protected: "credentials_in_file" });
		} finally {
			await server.close();
			await removeWithRetries(tempDir);
		}
	});
});

describe("app_experiment webview debugging scoping and forwards", () => {
	it("scopes DevTools socket discovery strictly to exact package PIDs", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-wv-scope-"));
		try {
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
				if (args.includes("ps") && args.includes("-A")) {
					// Multiple apps: com.example.app (PID 1001), com.example.app2 (PID 2002), com.other (PID 3003)
					const out = `
USER      PID  PPID  VSZ   RSS WCHAN   ADDR S NAME
u0_a100  1001  1000 10000 5000 0          0 S com.example.app
u0_a101  2002  1000 10000 5000 0          0 S com.example.app2
u0_a102  3003  1000 10000 5000 0          0 S com.other.service
`;
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
					const out = `
Num       RefCount Protocol Flags    Type St Path
00000000: 00000002 00000000 00010000 0001 01 @webview_devtools_remote_1001
00000001: 00000002 00000000 00010000 0001 01 @webview_devtools_remote_2002
00000002: 00000002 00000000 00010000 0001 01 @webview_devtools_remote_0
`;
					return {
						stdout: new TextEncoder().encode(out),
						stderr: "",
						exitCode: 0,
						outputBytes: out.length,
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			const res = await tool.execute("call-1", {
				action: "webview_debug",
				serial: "emulator-5554",
				package: "com.example.app",
				webview_op: "discover",
			});

			expect(res.details.status).toBe("ok");
			const sockets = res.details.discoveredSockets!;
			// Must match ONLY PID 1001 (com.example.app). Must NOT match PID 2002 (com.example.app2) or PID 0!
			expect(sockets.length).toBe(1);
			expect(sockets[0].pid).toBe(1001);
			expect(sockets[0].socketName).toBe("@webview_devtools_remote_1001");
		} finally {
			await removeWithRetries(tempDir);
		}
	});

	it("rejects unverified socket forwarding and uses --no-rebind", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "app-exp-wv-rebind-"));
		try {
			let forwardArgs: string[] = [];
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
				if (args.includes("ps")) {
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
				if (args.includes("cat")) {
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
				if (args.includes("forward")) {
					forwardArgs = args;
					return {
						stdout: new TextEncoder().encode("9223\n"),
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

			const tool = new AppExperimentTool(createTestSession(tempDir), {
				runner: mockRunner,
				which: SYNC_WHICH_ADB,
			});

			// Rejects forwarding socket not belonging to target app
			await expect(
				tool.execute("call-1", {
					action: "webview_debug",
					serial: "emulator-5554",
					package: "com.example.app",
					webview_op: "forward",
					socket_name: "@arbitrary_unverified_socket_9999",
				}),
			).rejects.toThrow("Forwarding unverified sockets is prohibited");

			// Forwards verified socket using --no-rebind
			const res = await tool.execute("call-2", {
				action: "webview_debug",
				serial: "emulator-5554",
				package: "com.example.app",
				webview_op: "forward",
				socket_name: "@webview_devtools_remote_1001",
				forward_port: 9223,
			});

			expect(res.details.status).toBe("ok");
			expect(forwardArgs).toContain("--no-rebind");
			expect(res.details.cdpEndpoint).toBe("http://127.0.0.1:9223");
			expect(res.details.cleanupHandle).toBe("tcp:9223");
		} finally {
			await removeWithRetries(tempDir);
		}
	});
});
