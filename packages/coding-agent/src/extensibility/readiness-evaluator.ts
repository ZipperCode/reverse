/**
 * Unified reverse readiness evaluation and diagnostics.
 *
 * Distinguishes five independent facts:
 * 1. `installed`: binary, JAR, or package is physically present on disk or PATH.
 * 2. `compatible`: required runtime/toolchain version constraints are satisfied
 *    (e.g. Unidbg strictly requires JDK 8 due to java.lang.Module conflict in JDK 9+;
 *    generic Java 9-25 presence does NOT suffice).
 * 3. `canStart`: all static execution prerequisites are met so scaffolding,
 *    decompilation, or probing can be initiated without crashing on missing prerequisites.
 * 4. `runtimeReady` / `connected`: a background harness, MCP service, or live debugger
 *    is actively running and connected in the current session (e.g. Unidbg harness type === 'jni'
 *    with verified connection status).
 * 5. `targetMatched` / `executedVerified`: concrete target path/URL is bound and verified
 *    with observable execution evidence; remains unknown/unverified without session records.
 */

import { inspectUnidbg } from "./unidbg-detect";
import { validateJdk8 } from "./unidbg-builder";
import { getActiveUnidbgHarnesses, checkUnidbgLaunchPrerequisites } from "./unidbg-runner";
import { getMcpServerRuntimeState } from "./capability-state";
import type { ToolSession } from "../tools/index";

export interface UnidbgHarnessSummary {
	serverName: string;
	port?: number;
	pid?: number;
	type?: string;
	ready: boolean;
	connected: boolean;
	targetPath?: string;
}

export interface UnidbgReadiness {
	/** Unidbg framework/JAR/repo physically detected on disk */
	installed: boolean;
	foundPath: string | null;
	/** Java runtime strictly validated to be JDK 8 (1.8) */
	compatible: boolean;
	jdkVersion?: string;
	javaBin?: string | null;
	javaHome?: string | null;
	/** All launch prerequisites met so launch/scaffold/probe can run */
	canStart: boolean;
	/** An active Unidbg SSE harness (type === 'jni') is currently connected in this session */
	runtimeReady: boolean;
	activeHarnessCount: number;
	activeHarnesses: readonly UnidbgHarnessSummary[];
	connectedHarness?: UnidbgHarnessSummary;
	/** Observable target match state: true if verified against session binding, unknown if unprobed */
	targetMatched: boolean | "unknown";
	/** Concrete execution success evidence from session records; unknown if unrecorded */
	executedVerified: boolean | "unknown";
	/** Precise diagnostic error when prerequisites or compatibility checks fail */
	error?: string;
	/** Concrete remediation command or instructions */
	remedy?: string;
}

export interface EvaluateUnidbgOptions {
	cwd?: string;
	unidbgHome?: string;
	jar?: string;
	env?: Record<string, string | undefined>;
	javaHome?: string;
	session?: ToolSession | object;
	target?: string;
}

/**
 * Shared evaluator for Unidbg emulation environment readiness.
 * Used consistently across Android workflow, reverse capability resolver, and CLI setup.
 */
export function evaluateUnidbgReadiness(options: EvaluateUnidbgOptions = {}): UnidbgReadiness {
	const env: Record<string, string | undefined> = {
		...(options.env ?? process.env),
		...(options.jar ? { UNIDBG_JAR: options.jar } : {}),
		...(options.unidbgHome ? { UNIDBG_HOME: options.unidbgHome } : {}),
	};
	const inspected = inspectUnidbg({
		cwd: options.cwd,
		dir: options.unidbgHome ?? env.UNIDBG_HOME ?? env.UNIDBG_ROOT ?? env.UNIDBG_DIR,
		env,
	});
	const installed = inspected.foundPath !== null;

	const jdkCheck = validateJdk8(options.javaHome, env);
	const compatible = jdkCheck.valid;

	let canStart = false;
	let error: string | undefined;
	let remedy: string | undefined;

	if (!installed) {
		canStart = false;
		error = "Unidbg framework not found on host. Pinned JAR or source repository is required.";
		remedy =
			"Clone https://github.com/zhkl0228/unidbg and compile with JDK 8 ('./mvnw -DskipTests package'), or run 'reverse setup reverse unidbg'.";
	} else if (!compatible) {
		canStart = false;
		error =
			jdkCheck.error ??
			"JDK 8 (1.8) is strictly required for Unidbg. JDK 9+ introduces java.lang.Module which conflicts with Unidbg compilation/runtime.";
		remedy =
			"Install Eclipse Adoptium Temurin 8 or OpenJDK 8 ('brew install --cask temurin@8' on macOS or 'winget install EclipseAdoptium.Temurin.8.JDK' on Windows) and set UNIDBG_JAVA_HOME (or JAVA_HOME).";
	} else if (inspected.unidbgDir) {
		const launchPrereqs = checkUnidbgLaunchPrerequisites(inspected.unidbgDir, false, env);
		if (!launchPrereqs.ok) {
			canStart = false;
			error = launchPrereqs.reason;
			remedy = `Compile Unidbg with JDK 8: cd "${inspected.unidbgDir}" && ./mvnw -DskipTests package.`;
		} else {
			canStart = true;
		}
	} else {
		canStart = false;
		error = "Standalone Unidbg jar found, but launcher requires complete multi-module reactor tree.";
		remedy = "Clone https://github.com/zhkl0228/unidbg and compile with './mvnw -DskipTests package' using JDK 8.";
	}
	// Runtime session check: strictly verify type === 'jni' AND connection === 'connected'
	let activeHarnesses: UnidbgHarnessSummary[] = [];
	let runtimeReady = false;
	let targetMatched: boolean | "unknown" = "unknown";
	let executedVerified: boolean | "unknown" = "unknown";

	let connectedHarness: UnidbgHarnessSummary | undefined;
	if (options.session) {
		const rawHarnesses = getActiveUnidbgHarnesses(options.session);
		const manager =
			"mcpManager" in options.session
				? (options.session.mcpManager as
						| {
								getConnectionStatus?: (name: string) => string;
								getConnection?: (name: string) => object | undefined;
						  }
						| undefined)
				: undefined;

		activeHarnesses = rawHarnesses.map(h => ({
			serverName: h.serverName,
			port: h.port,
			pid: h.pid,
			type: h.type,
			ready: h.ready,
			connected: manager ? manager.getConnectionStatus?.(h.serverName) === "connected" : false,
			targetPath: h.targetPath,
		}));

		const connectedJniHarnesses = activeHarnesses.filter(h => h.ready && h.type === "jni" && h.connected);
		runtimeReady = connectedJniHarnesses.length > 0;
		connectedHarness = options.target
			? (connectedJniHarnesses.find(h => h.targetPath === options.target) ?? connectedJniHarnesses[0])
			: connectedJniHarnesses[0];
		let sessionKey: object = options.session as object;
		if (
			typeof options.session === "object" &&
			options.session !== null &&
			"sessionManager" in options.session &&
			options.session.sessionManager &&
			typeof options.session.sessionManager === "object"
		) {
			sessionKey = options.session.sessionManager;
		}

		if (options.target && connectedHarness) {
			const currentConn = manager?.getConnection?.(connectedHarness.serverName);
			const state = getMcpServerRuntimeState(connectedHarness.serverName, sessionKey);
			// 连接重建后，旧目标绑定与执行记录均不再作为当前会话的证据。
			if (state && currentConn && state.connection === currentConn) {
				targetMatched = state.targetMatched && state.target ? state.target === options.target : "unknown";
				const execution = state.lastExecution;
				if (targetMatched === true && state.executionCount > 0 && execution && execution.innerSuccess !== null) {
					executedVerified =
						!execution.isError &&
						execution.innerSuccess &&
						(!execution.target || execution.target === options.target);
				}
			} else {
				targetMatched = "unknown";
				executedVerified = "unknown";
			}
		} else if (options.target) {
			targetMatched = "unknown";
			executedVerified = "unknown";
		}
	}

	return {
		installed,
		foundPath: inspected.foundPath,
		compatible,
		jdkVersion: jdkCheck.version,
		javaBin: jdkCheck.javaBin ?? null,
		javaHome: jdkCheck.javaHome ?? null,
		canStart,
		runtimeReady,
		activeHarnessCount: activeHarnesses.length,
		activeHarnesses,
		connectedHarness,
		targetMatched,
		executedVerified,
		...(error ? { error } : {}),
		...(remedy ? { remedy } : {}),
	};
}

export interface StageReadiness {
	ready: boolean;
	canStart: boolean;
	requiredTools: readonly string[];
	missingTools: readonly string[];
	description: string;
}

export interface ApkUnpackingStages {
	/** Baseline container extraction, binary manifest, and DEX discovery (zero external dependencies) */
	baseline: StageReadiness;
	/** High-level Java source reconstruction from Dalvik bytecode (JADX+Java or DroidASC) */
	javaDecompile: StageReadiness;
	/** Smali assembly disassembly and binary resources decoding/rebuilding (Apktool+Java) */
	smali: StageReadiness;
}

export interface ApkUnpackingReadiness {
	/** Baseline container extraction, binary manifest, and DEX discovery can start immediately */
	canStart: boolean;
	/** Whether all decompile and smali stages are fully ready */
	ready: boolean;
	/** Whether at least one high-level decompilation route (java or smali) is available */
	partialReady: boolean;
	stages: ApkUnpackingStages;
}

export interface EvaluateApkUnpackingOptions {
	installedTools?: Record<string, boolean>;
	toolStatuses?: readonly { id: string; status: "installed" | "missing" }[];
}

/**
 * Shared evaluator for APK unpacking capability readiness.
 * Distinguishes zero-dependency baseline extraction from high-level Java reconstruction
 * (JADX/DroidASC + Java) and smali resource disassembly (Apktool + Java).
 */
export function evaluateApkUnpackingReadiness(options: EvaluateApkUnpackingOptions = {}): ApkUnpackingReadiness {
	let jadxInstalled = false;
	let droidascInstalled = false;
	let apktoolInstalled = false;
	let javaInstalled = false;

	if (options.installedTools) {
		jadxInstalled = Boolean(options.installedTools.jadx);
		droidascInstalled = Boolean(options.installedTools.droidasc);
		apktoolInstalled = Boolean(options.installedTools.apktool);
		javaInstalled = Boolean(options.installedTools.java);
	} else if (options.toolStatuses) {
		for (const t of options.toolStatuses) {
			const lower = t.id.toLowerCase();
			if (lower === "jadx" && t.status === "installed") jadxInstalled = true;
			if (lower === "droidasc" && t.status === "installed") droidascInstalled = true;
			if (lower === "apktool" && t.status === "installed") apktoolInstalled = true;
			if (lower === "java" && t.status === "installed") javaInstalled = true;
		}
	}

	const javaDecompileReady = (jadxInstalled && javaInstalled) || droidascInstalled;
	const missingJavaDecompile: string[] = [];
	if (!jadxInstalled && !droidascInstalled) missingJavaDecompile.push("jadx");
	if (jadxInstalled && !javaInstalled && !droidascInstalled) missingJavaDecompile.push("java");

	const smaliReady = apktoolInstalled && javaInstalled;
	const missingSmali: string[] = [];
	if (!apktoolInstalled) missingSmali.push("apktool");
	if (!javaInstalled) missingSmali.push("java");

	const ready = javaDecompileReady && smaliReady;
	const partialReady = javaDecompileReady || smaliReady;

	return {
		canStart: true, // Baseline extraction is always executable via built-in tooling
		ready,
		partialReady,
		stages: {
			baseline: {
				ready: true,
				canStart: true,
				requiredTools: [],
				missingTools: [],
				description:
					"Built-in container triage, binary AndroidManifest.xml decoding, and DEX discovery (zero external dependencies).",
			},
			javaDecompile: {
				ready: javaDecompileReady,
				canStart: javaDecompileReady,
				requiredTools: droidascInstalled ? ["droidasc"] : ["jadx", "java"],
				missingTools: missingJavaDecompile,
				description:
					"High-level Java source reconstruction from Dalvik DEX bytecode (requires JADX+Java or DroidASC).",
			},
			smali: {
				ready: smaliReady,
				canStart: smaliReady,
				requiredTools: ["apktool", "java"],
				missingTools: missingSmali,
				description:
					"Smali assembly disassembly and binary resources decoding/rebuilding (requires Apktool and Java runtime).",
			},
		},
	};
}
