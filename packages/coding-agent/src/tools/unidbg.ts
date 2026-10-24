/**
 * Unidbg Agent Tool
 *
 * Exposes Unidbg harness scaffolding, source building, SSE process lifecycle supervision,
 * and dynamic session MCP registration to the agent.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AgentTool, AgentToolResult, ToolTier } from "@reverse/agent";
import { type } from "@reverse/reversetype";
import { ToolError } from "@reverse/tui/tools/tool-errors";
import type { ToolSession } from "./index";
import { throwIfAborted } from "./tool-errors";
import {
	generateUnidbgHarness,
	type UnidbgHarnessOptions,
	type UnidbgHarnessParam,
	type UnidbgEnvProfile,
} from "../extensibility/unidbg-harness";
import { buildUnidbg, validateJdk8 } from "../extensibility/unidbg-builder";
import { inspectUnidbg } from "../extensibility/unidbg-detect";
import {
	getActiveUnidbgHarnesses,
	launchUnidbgHarness,
	stopUnidbgHarness,
	probeUnidbgRegisterNatives,
} from "../extensibility/unidbg-runner";

const unidbgSchema = type({
	action: type
		.enumerated("scaffold", "build", "launch", "stop", "status", "probe")
		.describe(
			"Action to execute: 'scaffold' to generate harness Java code, 'build' to compile Unidbg source, 'launch' to run harness and attach MCP in-memory, 'stop' to terminate harness and detach MCP, 'status' to inspect active harnesses, 'probe' to discover JNI RegisterNatives dynamic methods without device",
		),
	"type?": type
		.enumerated("jni", "ipa")
		.describe("Harness emulation type: 'jni' for Android native libraries, 'ipa' for iOS packages (default: 'jni')"),
	"target?": type("string").describe("Path to target binary (.so file or .ipa package)"),
	"entry?": type("string").describe("Target entry point function or JNI method name"),
	"class?": type("string").describe("JNI Java class name (e.g. 'org/telegram/messenger/Utilities')"),
	"signature?": type("string").describe("JNI method signature (e.g. '([BI)[B')"),
	"arch?": type.enumerated("32", "64").describe("CPU architecture: '32' or '64' bit (default: '64')"),
	"backend?": type
		.enumerated("unicorn2", "dynarmic")
		.describe("Emulation backend engine: 'unicorn2' or 'dynarmic' (default: 'unicorn2')"),
	"port?": type("number").describe("Port number for the McpServer SSE endpoint (default: 9239)"),
	"out?": type("string").describe("Output file path for generated harness Java source code"),
	"overwrite?": type("boolean").describe("Overwrite existing output file during scaffold (default: false)"),
	"params?": type("string")
		.or(
			type({
				name: type("string"),
				type: type("string"),
				"className?": type("string"),
				"defaultValue?": type("string"),
			}).array(),
		)
		.describe(
			"Parameter specifications: comma-separated string (e.g. 'bytes,int' or 'ctx:android/content/Context,arr:int[]') or structured array of parameter objects",
		),
	"isStatic?": type("boolean").describe("Whether the target JNI method is static (default: true)"),
	"unidbgHome?": type("string").describe("Path to Unidbg source checkout or installation directory"),
	"javaHome?": type("string").describe("Path to JDK 8 home directory"),
	"mirror?": type.enumerated("aliyun", "default").describe("Maven repository mirror ('aliyun' or 'default')"),
	"skipTests?": type("boolean").describe("Skip unit tests during Unidbg build (default: true)"),
	"harness?": type("string").describe("Path to harness Java source (.java) or class name to launch"),
	"timeoutMs?": type("number").describe("Timeout in milliseconds for SSE health check (default: 30000)"),
	"apk?": type("string").describe("Optional path to APK file for package/context binding and manifest metadata"),
	"apiLevel?": type("number").describe("Android API level for AndroidResolver (default: 23)"),
	"envProfile?": type("string").describe(
		"JSON string or file path for explicit environment profile / custom JNI overrides",
	),
	"callOnLoad?": type("boolean").describe("Whether to execute JNI_OnLoad during probe/harness (default: true)"),
});

export type UnidbgToolParams = typeof unidbgSchema.infer;

export interface UnidbgToolDetails {
	action: "scaffold" | "build" | "launch" | "stop" | "status" | "probe";
	success: boolean;
	code?: string;
	outputPath?: string;
	unidbgDir?: string;
	jars?: string[];
	activeHarnesses?: Array<{
		pid: number;
		port: number;
		targetPath?: string;
		arch: number;
		backend: string;
		ready: boolean;
		sseUrl: string;
		lastOutput?: string;
	}>;
	launched?: {
		pid: number;
		port: number;
		serverName: string;
		sseUrl: string;
		ready: boolean;
		harnessClass?: string;
	};
	probe?: {
		targetPath: string;
		sampleSha256?: string;
		events: Array<Record<string, unknown>>;
		records: Array<{
			className: string;
			methodName: string;
			signature: string;
			moduleName: string;
			moduleBase?: string;
			functionAddress: string;
			moduleOffset?: string;
			status: "confirmed";
			source: "unidbg";
			sampleSha256?: string;
		}>;
		artifactPath?: string;
		totalEvents: number;
	};
	error?: string;
}
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

export class UnidbgTool implements AgentTool<typeof unidbgSchema, UnidbgToolDetails> {
	readonly name = "unidbg";
	readonly label = "Unidbg Native Emulation Orchestrator";
	readonly summary =
		"ARM32/ARM64 Android JNI and iOS IPA headless emulation tool: scaffold compilable Java harnesses, build upstream Unidbg via Maven and JDK 8, launch harnesses with session-scoped in-memory MCP tools, and control process lifecycles.";
	readonly description =
		"Manages Unidbg emulation harnesses and MCP debuggers. Use 'scaffold' to generate parameterized Java harness code for native .so libraries or iOS IPAs; use 'build' to build Unidbg from source with verified JDK 8; use 'launch' to run a harness and dynamically attach its debugger tools (registers, memory, disassembly, stepping, custom tools) into this session via SSE; use 'status' and 'stop' to monitor or terminate running harnesses.";
	readonly parameters = unidbgSchema;
	readonly strict = true;
	readonly loadMode = "discoverable";
	readonly approval = (args: unknown): ToolTier => {
		if (args && typeof args === "object" && "action" in args && typeof args.action === "string") {
			const action = args.action;
			if (action === "status") {
				return "read";
			}
			if (action === "scaffold") {
				return "write";
			}
			if (action === "build" || action === "launch" || action === "probe" || action === "stop") {
				return "exec";
			}
		}
		return "exec";
	};

	private readonly sessionAbort = new AbortController();
	private readonly unregisterDisposal?: (() => void) | void;

	constructor(private readonly session: ToolSession) {
		this.unregisterDisposal = session.registerDisposeCallback?.(() => {
			this.sessionAbort.abort();
			void stopUnidbgHarness(session);
		});
	}

	async execute(
		callId: string,
		params: UnidbgToolParams,
		signal?: AbortSignal,
	): Promise<AgentToolResult<UnidbgToolDetails>> {
		if (this.session.isDisposed?.() || this.sessionAbort.signal.aborted) {
			throw new ToolError("Session is already disposed.");
		}
		const effectiveSignal = signal ? AbortSignal.any([signal, this.sessionAbort.signal]) : this.sessionAbort.signal;
		throwIfAborted(effectiveSignal);
		const cwd = this.session.cwd ?? process.cwd();
		const resolvePath = (p?: string): string | undefined => {
			if (!p) return undefined;
			return path.isAbsolute(p) ? p : path.resolve(cwd, p);
		};

		switch (params.action) {
			case "scaffold": {
				if (!params.target) {
					throw new ToolError("target path is required for scaffolding");
				}
				const target = resolvePath(params.target)!;
				const resolvedOut = resolvePath(params.out);

				if (resolvedOut && fs.existsSync(resolvedOut) && !params.overwrite) {
					throw new ToolError(`Output file already exists at ${resolvedOut}. Use overwrite: true to replace.`);
				}

				const harnessOpts: UnidbgHarnessOptions = {
					type: params.type ?? "jni",
					targetPath: target,
					entry: params.entry,
					className: params.class,
					methodSignature: params.signature,
					arch: params.arch ?? "64",
					backend: params.backend ?? "unicorn2",
					port: params.port ?? 9239,
					params: params.params as string | UnidbgHarnessParam[] | undefined,
					isStatic: params.isStatic ?? true,
					outPath: resolvedOut,
					apkPath: resolvePath(params.apk),
					apiLevel: params.apiLevel,
					envProfile: resolveEnvProfileInput(params.envProfile, cwd),
					callOnLoad: params.callOnLoad !== false,
				};

				const code = generateUnidbgHarness(harnessOpts);
				let outputPath: string | undefined;

				if (resolvedOut) {
					fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
					fs.writeFileSync(resolvedOut, code, "utf8");
					outputPath = resolvedOut;
				}

				return {
					content: [
						{
							type: "text",
							text: outputPath
								? `Harness source generated and saved to ${outputPath}.\n\nTarget: ${target} (${harnessOpts.arch}-bit, ${harnessOpts.backend})\nPort: ${harnessOpts.port}\nClass: ${harnessOpts.className || "(direct native export)"}\nEntry: ${harnessOpts.entry || "(default)"}`
								: `Generated Unidbg harness source code:\n\n\`\`\`java\n${code}\n\`\`\``,
						},
					],
					details: {
						action: "scaffold",
						success: true,
						code,
						outputPath,
					},
				};
			}

			case "build": {
				const buildRes = await buildUnidbg({
					unidbgDir: resolvePath(params.unidbgHome),
					javaHome: resolvePath(params.javaHome),
					mirror: params.mirror,
					skipTests: params.skipTests !== false,
					signal,
				});

				if (!buildRes.success) {
					throw new ToolError(`Unidbg build failed: ${buildRes.error}\nOutput:\n${buildRes.output.slice(-2000)}`);
				}

				return {
					content: [
						{
							type: "text",
							text: `Unidbg build successful!\nDirectory: ${buildRes.unidbgDir}\nCompiled JARs (${buildRes.jarPaths.length}):\n${buildRes.jarPaths.map(j => `  - ${j}`).join("\n")}`,
						},
					],
					details: {
						action: "build",
						success: true,
						unidbgDir: buildRes.unidbgDir,
						jars: buildRes.jarPaths,
					},
				};
			}

			case "launch": {
				const port = params.port ?? 9239;
				const resolvedHarness = resolvePath(params.harness);
				const isJavaFile = resolvedHarness && (resolvedHarness.endsWith(".java") || fs.existsSync(resolvedHarness));
				const harnessPath = isJavaFile ? resolvedHarness : undefined;
				const harnessClass = !isJavaFile ? params.harness || undefined : undefined;

				const harnessInfo = await launchUnidbgHarness({
					type: params.type,
					harnessPath,
					harnessClass,
					targetPath: resolvePath(params.target),
					port,
					arch: params.arch ?? "64",
					backend: params.backend ?? "unicorn2",
					unidbgHome: resolvePath(params.unidbgHome),
					javaHome: resolvePath(params.javaHome),
					mcpManager: this.session.mcpManager,
					owner: this.session,
					timeoutMs: params.timeoutMs ?? 30_000,
					signal: effectiveSignal,
				});

				if (this.session.isDisposed?.() || this.sessionAbort.signal.aborted) {
					await stopUnidbgHarness(this.session, harnessInfo.port);
					throw new ToolError("Session was disposed during harness launch.");
				}
				return {
					content: [
						{
							type: "text",
							text:
								`Unidbg harness launched successfully!\n` +
								`- PID: ${harnessInfo.pid}\n` +
								`- Port: ${harnessInfo.port}\n` +
								`- Server: ${harnessInfo.serverName}\n` +
								`- SSE URL: ${harnessInfo.sseUrl}\n` +
								`- Architecture: ARM${harnessInfo.arch}\n` +
								`- Backend: ${harnessInfo.backend}\n` +
								`- Status: ready\n` +
								`- MCP tools registered in-memory under '${harnessInfo.serverName}' (auto-cleans on session exit).`,
						},
					],
					details: {
						action: "launch",
						success: true,
						launched: {
							pid: harnessInfo.pid,
							port: harnessInfo.port,
							serverName: harnessInfo.serverName,
							sseUrl: harnessInfo.sseUrl,
							ready: harnessInfo.ready,
							harnessClass: harnessInfo.harnessClass,
						},
					},
				};
			}

			case "stop": {
				const stopped = await stopUnidbgHarness(this.session, params.port);
				return {
					content: [
						{
							type: "text",
							text: stopped
								? `Unidbg harness${params.port ? ` on port ${params.port}` : "es"} stopped and detached.`
								: `No active Unidbg harness found${params.port ? ` on port ${params.port}` : ""}.`,
						},
					],
					details: {
						action: "stop",
						success: stopped,
					},
				};
			}

			case "status": {
				const active = getActiveUnidbgHarnesses(this.session).map(h => ({
					pid: h.pid,
					port: h.port,
					targetPath: h.targetPath,
					arch: h.arch,
					backend: h.backend,
					ready: h.ready,
					sseUrl: h.sseUrl,
					lastOutput: h.lastOutput,
				}));

				const inspected = inspectUnidbg({ dir: resolvePath(params.unidbgHome) });
				const jdkCheck = validateJdk8(resolvePath(params.javaHome));

				const lines: string[] = [
					"### Unidbg Emulation Environment Status",
					`- **JDK 8 Status**: ${jdkCheck.valid ? `Valid (${jdkCheck.version}) at ${jdkCheck.javaBin}` : `Invalid / Missing: ${jdkCheck.error}`}`,
					`- **Unidbg Checkout**: ${inspected.unidbgDir ? `${inspected.unidbgDir} (Built: ${inspected.built ? "yes" : "no"}, JARs: ${inspected.jars.length})` : "Not found"}`,
					`- **Active Running Harnesses**: ${active.length}`,
				];

				for (const h of active) {
					lines.push(
						`  * Port ${h.port} (PID ${h.pid}): ARM${h.arch} ${h.backend} -> ${h.sseUrl} [Ready: ${h.ready}]`,
					);
					if (h.targetPath) lines.push(`    Target: ${h.targetPath}`);
					if (h.lastOutput) lines.push(`    Last Output: ${h.lastOutput}`);
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "status",
						success: true,
						activeHarnesses: active,
						unidbgDir: inspected.unidbgDir,
						jars: inspected.jars,
					},
				};
			}

			case "probe": {
				if (!params.target) {
					throw new ToolError("target binary (.so) path is required for RegisterNatives probe");
				}
				const target = resolvePath(params.target)!;
				const resolvedApk = resolvePath(params.apk);
				const resolvedOut = resolvePath(params.out);
				const resolvedEnvProfile = resolveEnvProfileInput(params.envProfile, cwd);

				const probeRes = await probeUnidbgRegisterNatives({
					targetPath: target,
					apkPath: resolvedApk,
					apiLevel: params.apiLevel,
					arch: params.arch ?? "64",
					backend: params.backend ?? "unicorn2",
					callOnLoad: params.callOnLoad !== false,
					envProfile: resolvedEnvProfile,
					outPath: resolvedOut,
					unidbgHome: resolvePath(params.unidbgHome),
					javaHome: resolvePath(params.javaHome),
					timeoutMs: params.timeoutMs ?? 60_000,
					signal: effectiveSignal,
				});

				if (!probeRes.success) {
					throw new ToolError(
						`Unidbg RegisterNatives probe failed: ${probeRes.error}\nOutput:\n${probeRes.output.slice(-2000)}`,
					);
				}

				const confirmedCount = probeRes.records.length;
				const lines = [
					"### Unidbg RegisterNatives Probe Results",
					`- **Target**: ${target}`,
					`- **SHA-256**: ${probeRes.sampleSha256 || "unknown"}`,
					`- **Total Events Captured**: ${probeRes.totalEvents}`,
					`- **Confirmed Dynamic Methods**: ${confirmedCount}`,
				];
				if (probeRes.artifactPath) {
					lines.push(`- **Artifact Saved**: ${probeRes.artifactPath}`);
				}
				if (confirmedCount > 0) {
					lines.push("\n**Discovered Dynamic Registrations:**");
					const DISPLAY_CAP = 25;
					const displayed = probeRes.records.slice(0, DISPLAY_CAP);
					for (const r of displayed) {
						const offsetInfo = r.moduleOffset ? ` (offset: ${r.moduleOffset})` : "";
						lines.push(
							`  * \`${r.className}->${r.methodName}${r.signature}\` => \`${r.functionAddress}\`${offsetInfo} in \`${r.moduleName}\``,
						);
					}
					if (confirmedCount > DISPLAY_CAP) {
						lines.push(
							`  * ... and ${confirmedCount - DISPLAY_CAP} more methods (see full artifact at ${probeRes.artifactPath})`,
						);
					}
				} else {
					lines.push("\nNo dynamic native method registrations were recorded during execution.");
				}

				return {
					content: [{ type: "text", text: lines.join("\n") }],
					details: {
						action: "probe",
						success: true,
						probe: {
							targetPath: probeRes.targetPath,
							sampleSha256: probeRes.sampleSha256,
							events: probeRes.events,
							records: probeRes.records,
							artifactPath: probeRes.artifactPath,
							totalEvents: probeRes.totalEvents,
						},
					},
				};
			}
		}
	}
}
