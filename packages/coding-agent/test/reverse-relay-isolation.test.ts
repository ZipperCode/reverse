import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "bun:test";
import { probeRelayServer } from "../src/tools/browser/relay/daemon";
import { startRelayServer } from "../src/tools/browser/relay/server";

const repoRoot = path.resolve(import.meta.dir, "../../..");
const cliEntry = path.join(repoRoot, "packages/coding-agent/src/cli.ts");
describe("reverse relay isolation & fingerprint verification", () => {
	const serversToClose: Array<{ stop(closeActiveConnections?: boolean): void | Promise<void> }> = [];

	afterEach(async () => {
		for (const s of serversToClose) {
			try {
				await s.stop(true);
			} catch {}
		}
		serversToClose.length = 0;
	});

	it("probeRelayServer returns false for unrelated relay 503 JSON, regular Chrome 200 JSON, bad JSON; true for reverse 503/200 JSON", async () => {
		let mockResponse: { status: number; body: string } = { status: 503, body: "{}" };

		const mockServer = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const url = new URL(req.url);
				if (url.pathname === "/json/version") {
					return new Response(mockResponse.body, {
						status: mockResponse.status,
						headers: { "content-type": "application/json" },
					});
				}
				return new Response("Not found", { status: 404 });
			},
		});
		serversToClose.push(mockServer);
		const cdpUrl = `http://127.0.0.1:${mockServer.port}`;

		// 1. Unrelated relay 503 JSON (has otherRelayVersion, no reverseRelayVersion)
		mockResponse = {
			status: 503,
			body: JSON.stringify({
				error: "Extension not connected",
				extensionSeen: false,
				uptimeMs: 1000,
				otherRelayVersion: "18.11.2",
				otherRelayCdpClients: 0,
			}),
		};
		expect(await probeRelayServer(cdpUrl)).toBeFalse();

		// 2. Regular Chrome 200 JSON (standard CDP fields only, no reverseRelayVersion)
		mockResponse = {
			status: 200,
			body: JSON.stringify({
				Browser: "Chrome/136.0.0.0",
				"Protocol-Version": "1.3",
				"User-Agent": "Mozilla/5.0",
				"V8-Version": "13.6.0",
				webSocketDebuggerUrl: `ws://127.0.0.1:${mockServer.port}/devtools/browser/abc`,
			}),
		};
		expect(await probeRelayServer(cdpUrl)).toBeFalse();

		// 3. Bad JSON
		mockResponse = {
			status: 503,
			body: "<html><body>503 Service Unavailable</body></html>",
		};
		expect(await probeRelayServer(cdpUrl)).toBeFalse();

		// 4. New reverse 503 JSON (waiting for extension, has reverseRelayVersion)
		mockResponse = {
			status: 503,
			body: JSON.stringify({
				error: "Extension not connected",
				extensionSeen: false,
				uptimeMs: 1000,
				reverseRelayVersion: "18.11.2",
				reverseRelayCdpClients: 0,
			}),
		};
		expect(await probeRelayServer(cdpUrl)).toBeTrue();

		// 5. New reverse 200 JSON (extension connected, has reverseRelayVersion)
		mockResponse = {
			status: 200,
			body: JSON.stringify({
				Browser: "Chrome/136.0.0.0",
				reverseRelayVersion: "18.11.2",
				reverseRelayCdpClients: 1,
				webSocketDebuggerUrl: `ws://127.0.0.1:${mockServer.port}/cdp`,
			}),
		};
		expect(await probeRelayServer(cdpUrl)).toBeTrue();
	});

	it("verifies real reverse relay reports 503 when no extension connected, and unrelated relay response is rejected", async () => {
		// Start a real reverse relay on a dynamic port
		const realRelay = startRelayServer({ port: 0 });
		serversToClose.push(realRelay);

		const relayUrl = `http://127.0.0.1:${realRelay.port}`;

		// Verify that without extension, real relay responds with 503 and reverseRelayVersion
		const resp = await fetch(`${relayUrl}/json/version`);
		expect(resp.status).toBe(503);
		const body = (await resp.json()) as Record<string, unknown>;
		expect(body.reverseRelayVersion).toBeDefined();
		expect(body.otherRelayVersion).toBeUndefined();

		// probeRelayServer against real reverse relay must return true
		expect(await probeRelayServer(relayUrl)).toBeTrue();

		// Occupied old relay refusal:
		// When a port is occupied by a unrelated relay relay (returning otherRelayVersion),
		// browser-relay refuses to reuse it and fails cleanly without reuse.
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "reverse-relay-isolation-"));
		try {
			const occupiedOtherServer = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req) {
					const url = new URL(req.url);
					if (url.pathname === "/json/version") {
						return new Response(
							JSON.stringify({
								error: "Extension not connected",
								extensionSeen: false,
								uptimeMs: 1200,
								otherRelayVersion: "18.11.2",
								otherRelayCdpClients: 0,
							}),
							{
								status: 503,
								headers: { "content-type": "application/json" },
							},
						);
					}
					return new Response("Not found", { status: 404 });
				},
			});
			serversToClose.push(occupiedOtherServer);
			const occupiedPort = occupiedOtherServer.port;

			// Low-level probe against legacy occupied port must be false
			expect(await probeRelayServer(`http://127.0.0.1:${occupiedPort}`)).toBeFalse();

			// Subprocess running browser-relay against the legacy occupied port must refuse and exit 1
			const proc = Bun.spawn([process.execPath, cliEntry, "browser-relay", "-p", String(occupiedPort)], {
				cwd: tempDir,
				env: {
					PATH: process.env.PATH,
					TMPDIR: process.env.TMPDIR,
					HOME: tempDir,
					USERPROFILE: tempDir,
					NO_COLOR: "1",
				},
				stdout: "pipe",
				stderr: "pipe",
			});
			const [exitCode, stdout, stderr] = await Promise.all([
				proc.exited,
				new Response(proc.stdout).text(),
				new Response(proc.stderr).text(),
			]);

			expect(exitCode).toBe(1);
			expect(stderr).toContain(`Port ${occupiedPort} is in use by something that is not an reverse browser relay.`);
			expect(stdout).not.toContain("already running");

			// In contrast, running browser-relay against the real reverse relay port must detect it and exit 0
			const procOk = Bun.spawn([process.execPath, cliEntry, "browser-relay", "-p", String(realRelay.port)], {
				cwd: tempDir,
				env: {
					PATH: process.env.PATH,
					TMPDIR: process.env.TMPDIR,
					HOME: tempDir,
					USERPROFILE: tempDir,
					NO_COLOR: "1",
				},
				stdout: "pipe",
				stderr: "pipe",
			});
			const [exitCodeOk, stdoutOk] = await Promise.all([
				procOk.exited,
				new Response(procOk.stdout).text(),
				new Response(procOk.stderr).text(),
			]);

			expect(exitCodeOk).toBe(0);
			expect(stdoutOk).toContain(
				`reverse browser relay already running on http://127.0.0.1:${realRelay.port}; nothing to do.`,
			);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	it("probes default relay port without colliding with ambient services", async () => {
		const DEFAULT_RELAY_URL = "http://127.0.0.1:9234";
		// Probe default relay port: should either return true (if a reverse relay is already running)
		// or false (if inactive, foreign service, or unrelated relay relay), without throwing.
		const result = await probeRelayServer(DEFAULT_RELAY_URL);
		expect(typeof result).toBe("boolean");
	});
});
