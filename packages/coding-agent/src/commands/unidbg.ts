/**
 * Unidbg CLI command
 *
 * Provides subcommands to build Unidbg from source with validated JDK 8,
 * scaffold parameterized Android JNI and iOS IPA harnesses, launch harnesses
 * with live SSE MCP server endpoints, and supervise running emulation lifecycles across terminal sessions.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { APP_NAME, getAgentDir, postmortem } from "@reverse/utils";
import { Args, Command, Flags, CliUsageError } from "@reverse/utils/cli";
import { unidbgHelp as commandHelp } from "../cli/command-help";
import { buildUnidbg, validateJdk8 } from "../extensibility/unidbg-builder";
import { inspectUnidbg } from "../extensibility/unidbg-detect";
import {
	generateUnidbgHarness,
	type UnidbgHarnessOptions,
	type UnidbgEnvProfile,
	type UnidbgHarnessParam,
} from "../extensibility/unidbg-harness";
import { launchUnidbgHarness, stopUnidbgHarness, probeUnidbgRegisterNatives } from "../extensibility/unidbg-runner";
function resolveEnvProfileInput(rawProfile: unknown, cwd: string): UnidbgEnvProfile | string | undefined {
	if (!rawProfile) return undefined;
	if (typeof rawProfile === "object") {
		return rawProfile as UnidbgEnvProfile;
	}
	if (typeof rawProfile === "string") {
		const trimmed = rawProfile.trim();
		if (trimmed.startsWith("{")) {
			try {
				return JSON.parse(trimmed) as UnidbgEnvProfile;
			} catch {
				return trimmed;
			}
		}
		const resolved = path.isAbsolute(trimmed) ? trimmed : path.resolve(cwd, trimmed);
		if (fs.existsSync(resolved)) {
			try {
				const content = fs.readFileSync(resolved, "utf8");
				return JSON.parse(content) as UnidbgEnvProfile;
			} catch {
				return resolved;
			}
		}
		return trimmed;
	}
	return undefined;
}

export interface HarnessPresenceMeta {
	pid: number;
	port: number;
	controlPort: number;
	token: string;
	serverName: string;
	type?: "jni" | "ipa";
	targetPath?: string;
	arch: 32 | 64;
	backend: string;
	harnessClass?: string;
	sseUrl: string;
	ready: boolean;
	startTime: number;
	lastOutput?: string;
}

function getHarnessPresenceDir(): string {
	const dir = path.join(getAgentDir(), "unidbg-harnesses");
	fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
	return dir;
}

function recordHarnessPresence(meta: HarnessPresenceMeta): void {
	const file = path.join(getHarnessPresenceDir(), `${meta.port}.json`);
	fs.writeFileSync(file, JSON.stringify(meta, null, 2), { encoding: "utf8", mode: 0o600 });
}

function removeHarnessPresence(port: number, expectedToken?: string): boolean {
	const file = path.join(getHarnessPresenceDir(), `${port}.json`);
	if (!fs.existsSync(file)) return false;
	if (expectedToken !== undefined) {
		try {
			const current: HarnessPresenceMeta = JSON.parse(fs.readFileSync(file, "utf8"));
			if (current.token !== expectedToken) {
				return false;
			}
		} catch {
			return false;
		}
	}
	try {
		fs.unlinkSync(file);
		return true;
	} catch {
		return false;
	}
}

export async function listActiveHarnessPresences(): Promise<HarnessPresenceMeta[]> {
	const dir = getHarnessPresenceDir();
	const active: HarnessPresenceMeta[] = [];
	try {
		const files = fs.readdirSync(dir);
		for (const f of files) {
			if (!f.endsWith(".json")) continue;
			const p = path.join(dir, f);
			let snapshotRaw: string | undefined;
			let meta: HarnessPresenceMeta | undefined;
			try {
				snapshotRaw = fs.readFileSync(p, "utf8");
				meta = JSON.parse(snapshotRaw);
			} catch {
				if (snapshotRaw !== undefined) {
					try {
						if (fs.readFileSync(p, "utf8") === snapshotRaw) {
							fs.unlinkSync(p);
						}
					} catch {}
				}
				continue;
			}

			if (!meta) continue;

			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), 2000);
			try {
				const resp = await fetch(`http://127.0.0.1:${meta.controlPort}/status`, {
					headers: { Authorization: `Bearer ${meta.token}` },
					signal: controller.signal,
				});
				if (resp.status === 200) {
					const liveData = (await resp.json()) as Partial<HarnessPresenceMeta>;
					active.push({ ...meta, ...liveData });
				} else {
					removeHarnessPresence(meta.port, meta.token);
				}
			} catch {
				removeHarnessPresence(meta.port, meta.token);
			} finally {
				clearTimeout(timer);
			}
		}
	} catch {}
	return active;
}

export async function stopHarnessProcess(port?: number): Promise<boolean> {
	let stoppedAny = await stopUnidbgHarness(undefined, port);
	const presences = await listActiveHarnessPresences();
	const targets = port !== undefined ? presences.filter(p => p.port === port) : presences;

	for (const meta of targets) {
		let confirmedStopped = false;
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), 6000);
		try {
			const resp = await fetch(`http://127.0.0.1:${meta.controlPort}/stop`, {
				method: "POST",
				headers: { Authorization: `Bearer ${meta.token}` },
				signal: controller.signal,
			});
			if (resp.status === 200) {
				stoppedAny = true;
				confirmedStopped = true;
			}
		} catch {
			// Failure or timeout does not confirm stopped
		} finally {
			clearTimeout(timer);
		}
		if (confirmedStopped) {
			removeHarnessPresence(meta.port, meta.token);
		}
	}
	return stoppedAny;
}

export default class Unidbg extends Command {
	static description = commandHelp.description;

	static args = {
		subcommand: Args.string({
			description: "Unidbg action: build, scaffold, launch, stop, status, probe",
			required: false,
			options: ["build", "scaffold", "launch", "stop", "status", "probe"],
		}),
		target: Args.string({
			description: "Target binary path, harness class/file, source directory, or port for stop",
			required: false,
		}),
	};

	static flags = {
		"java-home": Flags.string({ description: "Path to JDK 8 home directory" }),
		"unidbg-home": Flags.string({ description: "Path to Unidbg source checkout or directory" }),
		mirror: Flags.string({ description: "Maven mirror ('aliyun' or 'default')", options: ["aliyun", "default"] }),
		"skip-tests": Flags.boolean({ description: "Skip unit tests during build", default: true }),
		type: Flags.string({ description: "Harness emulation type ('jni' or 'ipa')", options: ["jni", "ipa"] }),
		entry: Flags.string({ description: "Target entry point function or JNI method name" }),
		class: Flags.string({ description: "JNI Java class name (e.g. 'org/telegram/messenger/Utilities')" }),
		signature: Flags.string({ description: "JNI method signature (e.g. '([BI)[B')" }),
		arch: Flags.string({ description: "CPU architecture ('32' or '64')", options: ["32", "64"], default: "64" }),
		backend: Flags.string({
			description: "Emulation backend ('unicorn2' or 'dynarmic')",
			options: ["unicorn2", "dynarmic"],
			default: "unicorn2",
		}),
		port: Flags.integer({ description: "Port number for the McpServer SSE endpoint", default: 9239 }),
		out: Flags.string({ description: "Output file path for generated harness Java source code" }),
		params: Flags.string({ description: "Comma-separated parameter types (e.g. 'bytes,int')" }),
		"is-static": Flags.boolean({
			description: "Invoke JNI method as static (default: true)",
			default: true,
			allowNegative: true,
		}),
		instance: Flags.boolean({ description: "Invoke JNI method as instance instead of static", default: false }),
		"skip-on-load": Flags.boolean({ description: "Skip calling JNI_OnLoad upon library load", default: false }),
		overwrite: Flags.boolean({ description: "Overwrite existing scaffold output file", default: false }),
		json: Flags.boolean({ description: "Output JSON result", default: false }),
		apk: Flags.string({ description: "Path to APK file for package/context binding and manifest metadata" }),
		"api-level": Flags.integer({ description: "Android API level for AndroidResolver (default: 23)" }),
		"env-profile": Flags.string({
			description: "JSON string or file path for explicit environment profile / custom JNI overrides",
		}),
	};

	static examples = [
		`${APP_NAME} unidbg build /path/to/unidbg --java-home /path/to/jdk8 --mirror aliyun`,
		`${APP_NAME} unidbg scaffold libnative.so --type jni --class com/example/Crypto --entry calculateToken --out Harness.java`,
		`${APP_NAME} unidbg scaffold app.ipa --type ipa --entry dumpClass --out IpaHarness.java`,
		`${APP_NAME} unidbg launch Harness.java --port 9239 --java-home /path/to/jdk8`,
		`${APP_NAME} unidbg status`,
		`${APP_NAME} unidbg stop 9239`,
		`${APP_NAME} unidbg probe libnative.so --apk app.apk --api-level 23`,
	];
	async run(): Promise<void> {
		const { args, flags } = await this.parse(Unidbg);
		const subcommand = args.subcommand ?? "status";
		const cwd = process.cwd();

		const resolvePath = (p?: string): string | undefined => {
			if (!p) return undefined;
			return path.isAbsolute(p) ? p : path.resolve(cwd, p);
		};

		switch (subcommand) {
			case "build": {
				const targetDir = resolvePath(args.target) ?? resolvePath(flags["unidbg-home"]);
				const javaHome = resolvePath(flags["java-home"]);

				if (!flags.json) {
					process.stdout.write(`Building Unidbg with validated JDK 8...\n`);
				}
				const res = await buildUnidbg({
					unidbgDir: targetDir,
					javaHome,
					mirror: flags.mirror as "aliyun" | "default" | undefined,
					skipTests: flags["skip-tests"],
					onLog: chunk => {
						if (!flags.json) process.stdout.write(chunk);
						else process.stderr.write(chunk);
					},
				});

				if (flags.json) {
					process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
					await postmortem.quit(res.success ? 0 : 1);
					return;
				}

				if (!res.success) {
					process.stderr.write(`\nError: Unidbg build failed: ${res.error}\n`);
					await postmortem.quit(1);
					return;
				}

				process.stdout.write(
					`\nUnidbg build completed successfully!\n` +
						`- Directory: ${res.unidbgDir}\n` +
						`- Built JARs (${res.jarPaths.length}):\n` +
						res.jarPaths.map(j => `  * ${j}`).join("\n") +
						"\n",
				);
				await postmortem.quit(0);
				return;
			}

			case "scaffold": {
				if (!args.target) {
					throw new CliUsageError("scaffold requires a target binary path (.so or .ipa)");
				}
				const targetPath = resolvePath(args.target)!;
				const resolvedOut = resolvePath(flags.out);

				if (resolvedOut && fs.existsSync(resolvedOut) && !flags.overwrite) {
					throw new CliUsageError(`Output file already exists at ${resolvedOut}. Use --overwrite to replace.`);
				}

				const harnessOpts: UnidbgHarnessOptions = {
					type: (flags.type ?? "jni") as "jni" | "ipa",
					targetPath,
					entry: flags.entry,
					className: flags.class,
					methodSignature: flags.signature,
					arch: flags.arch as "32" | "64",
					backend: flags.backend as "unicorn2" | "dynarmic",
					port: flags.port,
					params:
						typeof flags.params === "string" && flags.params.trim().startsWith("[")
							? (() => {
									try {
										return JSON.parse(flags.params) as UnidbgHarnessParam[];
									} catch {
										return flags.params;
									}
								})()
							: flags.params,
					isStatic: flags.instance ? false : flags["is-static"],
					callOnLoad: !flags["skip-on-load"],
					outPath: resolvedOut,
					apkPath: resolvePath(flags.apk),
					apiLevel: flags["api-level"],
					envProfile: resolveEnvProfileInput(flags["env-profile"], cwd),
				};

				const code = generateUnidbgHarness(harnessOpts);

				if (resolvedOut) {
					fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
					fs.writeFileSync(resolvedOut, code, "utf8");
					if (flags.json) {
						process.stdout.write(
							JSON.stringify({ success: true, outputPath: resolvedOut, code }, null, 2) + "\n",
						);
					} else {
						process.stdout.write(`Generated harness saved to ${resolvedOut}\n`);
					}
				} else {
					if (flags.json) {
						process.stdout.write(JSON.stringify({ success: true, code }, null, 2) + "\n");
					} else {
						process.stdout.write(code + "\n");
					}
				}
				await postmortem.quit(0);
				return;
			}

			case "launch": {
				const harnessArg = args.target;
				if (!harnessArg) {
					throw new CliUsageError("launch requires a harness source path (.java) or class name");
				}

				const resolvedHarness = resolvePath(harnessArg);
				const isJavaFile = resolvedHarness && (resolvedHarness.endsWith(".java") || fs.existsSync(resolvedHarness));

				if (!flags.json) {
					process.stdout.write(`Launching Unidbg harness on port ${flags.port}...\n`);
				}
				const info = await launchUnidbgHarness({
					type: flags.type as "jni" | "ipa" | undefined,
					harnessPath: isJavaFile ? resolvedHarness : undefined,
					harnessClass: !isJavaFile ? harnessArg : undefined,
					port: flags.port,
					arch: flags.arch as "32" | "64",
					backend: flags.backend as "unicorn2" | "dynarmic",
					unidbgHome: resolvePath(flags["unidbg-home"]),
					javaHome: resolvePath(flags["java-home"]),
					onLog: chunk => {
						if (!flags.json) process.stdout.write(chunk);
						else process.stderr.write(chunk);
					},
				});

				// Start token-authenticated loopback HTTP control server for cross-process management
				const token = crypto.randomUUID();
				const { promise: stopRequestedPromise, resolve: resolveStopRequested } = Promise.withResolvers<void>();
				let controlServer: http.Server | undefined;
				const cleanup = () => {
					if (controlServer) {
						try {
							controlServer.close();
						} catch {}
					}
					removeHarnessPresence(info.port, token);
				};

				try {
					controlServer = http.createServer((req, res) => {
						const remote = req.socket.remoteAddress;
						if (!remote || !["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(remote)) {
							res.writeHead(403);
							res.end("Forbidden");
							return;
						}
						const auth = req.headers.authorization;
						if (auth !== `Bearer ${token}`) {
							res.writeHead(403);
							res.end("Unauthorized");
							return;
						}
						if (req.url === "/status" && req.method === "GET") {
							res.writeHead(200, { "Content-Type": "application/json" });
							res.end(
								JSON.stringify({
									pid: info.pid,
									port: info.port,
									serverName: info.serverName,
									sseUrl: info.sseUrl,
									ready: info.ready,
									lastOutput: info.lastOutput,
								}),
							);
							return;
						}
						if (req.url === "/stop" && req.method === "POST") {
							cleanup();
							void stopUnidbgHarness(undefined, info.port)
								.then(() => {
									try {
										res.writeHead(200, { "Content-Type": "application/json" });
										res.end(JSON.stringify({ success: true }));
									} catch {}
									resolveStopRequested();
								})
								.catch(err => {
									try {
										res.writeHead(500, { "Content-Type": "application/json" });
										res.end(JSON.stringify({ success: false, error: String(err) }));
									} catch {}
									resolveStopRequested();
								});
							return;
						}
						res.writeHead(404);
						res.end();
					});

					const {
						promise: listenPromise,
						resolve: resolveListen,
						reject: rejectListen,
					} = Promise.withResolvers<number>();
					controlServer.once("error", rejectListen);
					controlServer.listen(0, "127.0.0.1", () => {
						const addr = controlServer?.address() as { port: number } | null;
						if (addr) resolveListen(addr.port);
						else rejectListen(new Error("Control server failed to bind"));
					});
					const controlPort = await listenPromise;

					recordHarnessPresence({
						pid: info.pid,
						port: info.port,
						controlPort,
						token,
						serverName: info.serverName,
						type: info.type,
						targetPath: info.targetPath,
						arch: info.arch,
						backend: info.backend,
						harnessClass: info.harnessClass,
						sseUrl: info.sseUrl,
						ready: info.ready,
						startTime: info.startTime,
						lastOutput: info.lastOutput,
					});

					if (flags.json) {
						process.stdout.write(
							JSON.stringify(
								{
									success: true,
									pid: info.pid,
									port: info.port,
									serverName: info.serverName,
									sseUrl: info.sseUrl,
									ready: info.ready,
									harnessClass: info.harnessClass,
								},
								null,
								2,
							) + "\n",
						);
					} else {
						process.stdout.write(
							`\nUnidbg harness running (PID: ${info.pid})\n` +
								`- Port: ${info.port}\n` +
								`- Server: ${info.serverName}\n` +
								`- SSE URL: ${info.sseUrl}\n` +
								`- Status: ready\n` +
								`Press Ctrl+C to stop.\n`,
						);
					}

					const onSignal = () => {
						if (!flags.json) process.stdout.write("\nStopping Unidbg harness...\n");
						cleanup();
						void stopUnidbgHarness(undefined, info.port);
					};

					process.once("SIGINT", onSignal);
					process.once("SIGTERM", onSignal);

					void stopRequestedPromise.then(() => {
						cleanup();
						void stopUnidbgHarness(undefined, info.port);
					});

					if (info.process.exitCode !== null || info.process.signalCode !== null) {
						cleanup();
						await postmortem.quit(info.process.exitCode ?? 1);
						return;
					}

					const exitCode = await new Promise<number>(resolve => {
						info.process.once("close", (code, signal) => {
							cleanup();
							resolve(code ?? (signal ? 1 : 0));
						});
					});

					process.removeListener("SIGINT", onSignal);
					process.removeListener("SIGTERM", onSignal);
					await postmortem.quit(exitCode);
					return;
				} finally {
					cleanup();
					void stopUnidbgHarness(undefined, info.port);
				}
			}

			case "stop": {
				const portNum = args.target ? Number.parseInt(args.target, 10) : flags.port;
				const targetPort = Number.isNaN(portNum) ? flags.port : portNum;
				const stopped = await stopHarnessProcess(targetPort);

				if (flags.json) {
					process.stdout.write(JSON.stringify({ success: stopped, port: targetPort }, null, 2) + "\n");
				} else {
					process.stdout.write(
						stopped
							? `Unidbg harness on port ${targetPort} stopped.\n`
							: `No active Unidbg harness found on port ${targetPort}.\n`,
					);
				}
				await postmortem.quit(stopped ? 0 : 1);
				return;
			}

			case "status": {
				const javaHome = resolvePath(flags["java-home"]);
				const jdkCheck = validateJdk8(javaHome);
				const inspected = inspectUnidbg({ dir: resolvePath(flags["unidbg-home"]) });
				const active = await listActiveHarnessPresences();
				const publicActive = active.map(h => ({
					pid: h.pid,
					port: h.port,
					serverName: h.serverName,
					type: h.type,
					targetPath: h.targetPath,
					arch: h.arch,
					backend: h.backend,
					harnessClass: h.harnessClass,
					sseUrl: h.sseUrl,
					ready: h.ready,
					startTime: h.startTime,
					lastOutput: h.lastOutput,
				}));

				if (flags.json) {
					process.stdout.write(
						JSON.stringify(
							{
								jdkCheck: {
									valid: jdkCheck.valid,
									version: jdkCheck.version,
									javaBin: jdkCheck.javaBin,
									error: jdkCheck.error,
								},
								inspected: {
									unidbgDir: inspected.unidbgDir,
									hasPom: inspected.hasPom,
									built: inspected.built,
									jars: inspected.jars,
								},
								active: publicActive,
							},
							null,
							2,
						) + "\n",
					);
				} else {
					process.stdout.write(`=== Unidbg Status ===\n`);
					process.stdout.write(
						`- JDK 8: ${jdkCheck.valid ? `Valid (${jdkCheck.version}) at ${jdkCheck.javaBin}` : `Missing/Invalid: ${jdkCheck.error}`}\n`,
					);
					process.stdout.write(
						`- Unidbg: ${inspected.unidbgDir ? `${inspected.unidbgDir} (Built: ${inspected.built ? "yes" : "no"}, JARs: ${inspected.jars.length})` : "Not found"}\n`,
					);
					process.stdout.write(`- Active Harnesses: ${publicActive.length}\n`);
					for (const h of publicActive) {
						process.stdout.write(
							`  * PID ${h.pid} on port ${h.port}: ARM${h.arch} ${h.backend} -> ${h.sseUrl} [Ready: ${h.ready}]\n`,
						);
						if (h.lastOutput) {
							process.stdout.write(`    Last output: ${h.lastOutput}\n`);
						}
					}
				}
				await postmortem.quit(0);
				return;
			}

			case "probe": {
				if (!args.target) {
					throw new CliUsageError("probe requires a target binary path (.so)");
				}
				const targetPath = resolvePath(args.target)!;
				const resolvedApk = resolvePath(flags.apk);
				const resolvedOut = resolvePath(flags.out);
				const resolvedEnvProfile = resolveEnvProfileInput(flags["env-profile"], cwd);

				if (!flags.json) {
					process.stdout.write(`Probing JNI RegisterNatives dynamic registrations for ${targetPath}...\n`);
				}

				const res = await probeUnidbgRegisterNatives({
					targetPath,
					apkPath: resolvedApk,
					apiLevel: flags["api-level"],
					arch: flags.arch as "32" | "64",
					backend: flags.backend as "unicorn2" | "dynarmic",
					callOnLoad: !flags["skip-on-load"],
					envProfile: resolvedEnvProfile,
					outPath: resolvedOut,
					unidbgHome: resolvePath(flags["unidbg-home"]),
					javaHome: resolvePath(flags["java-home"]),
					onLog: chunk => {
						if (!flags.json) process.stdout.write(chunk);
					},
				});

				if (flags.json) {
					process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
					await postmortem.quit(res.success ? 0 : 1);
					return;
				}

				if (!res.success) {
					process.stderr.write(`\nError: RegisterNatives probe failed: ${res.error}\n`);
					await postmortem.quit(1);
					return;
				}

				process.stdout.write(
					`\nRegisterNatives probe completed!\n` +
						`- Target: ${res.targetPath}\n` +
						`- SHA-256: ${res.sampleSha256 || "unknown"}\n` +
						`- Captured Events: ${res.totalEvents}\n` +
						`- Confirmed Dynamic Methods: ${res.records.length}\n` +
						(res.artifactPath ? `- Artifact: ${res.artifactPath}\n` : "") +
						"\n",
				);
				if (res.records.length > 0) {
					process.stdout.write("Discovered Dynamic Registrations:\n");
					for (const r of res.records) {
						const offset = r.moduleOffset ? ` (offset ${r.moduleOffset})` : "";
						process.stdout.write(
							`  * ${r.className}->${r.methodName}${r.signature} => ${r.functionAddress}${offset}\n`,
						);
					}
				}
				await postmortem.quit(0);
				return;
			}
		}
	}
}
