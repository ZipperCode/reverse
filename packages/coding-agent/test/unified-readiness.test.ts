import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { evaluateUnidbgReadiness, evaluateApkUnpackingReadiness } from "../src/extensibility/readiness-evaluator";
import { resolveReverseCapabilities } from "../src/extensibility/skill-tool-catalog";
import { checkReverseTools } from "../src/cli/setup-reverse";
import { Settings } from "../src/config/settings";

const isWindows = process.platform === "win32";

describe("Unified Reverse Readiness & Diagnostics", () => {
	let tempDir: string;
	let jdk8Dir: string;
	let jdk25Dir: string;
	let unicornDepPath: string;
	let apiDepPath: string;

	function createFakeJdk(baseDir: string, name: string, versionString: string): string {
		const jdkDir = path.join(baseDir, name);
		const binDir = path.join(jdkDir, "bin");
		fs.mkdirSync(binDir, { recursive: true });

		const javaPath = path.join(binDir, "java");
		const javacPath = path.join(binDir, "javac");

		// Output Java version to stderr as real JVM does
		fs.writeFileSync(
			javaPath,
			`#!/bin/sh\necho 'openjdk version "${versionString}"' >&2\necho 'OpenJDK Runtime Environment' >&2\nexit 0\n`,
		);
		fs.chmodSync(javaPath, 0o755);

		fs.writeFileSync(javacPath, `#!/bin/sh\nexit 0\n`);
		fs.chmodSync(javacPath, 0o755);

		return jdkDir;
	}

	function createFakeUnidbgRepo(baseDir: string): string {
		const unidbgDir = path.join(baseDir, "unidbg");
		const depsDir = path.join(baseDir, "deps");
		fs.mkdirSync(depsDir, { recursive: true });
		fs.mkdirSync(path.join(unidbgDir, "unidbg-api", "target", "classes"), { recursive: true });
		fs.mkdirSync(path.join(unidbgDir, "unidbg-android", "target", "classes"), { recursive: true });
		fs.mkdirSync(path.join(unidbgDir, "backend", "unicorn2", "target", "classes"), { recursive: true });

		unicornDepPath = path.join(depsDir, "unicorn2-cached.jar");
		apiDepPath = path.join(depsDir, "api-cached.jar");
		fs.writeFileSync(unicornDepPath, "PK");
		fs.writeFileSync(apiDepPath, "PK");

		fs.writeFileSync(
			path.join(unidbgDir, "pom.xml"),
			`<project><groupId>com.github.zhkl0228</groupId><artifactId>unidbg</artifactId></project>`,
		);
		fs.writeFileSync(
			path.join(unidbgDir, "unidbg-android", "pom.xml"),
			`<project><artifactId>unidbg-android</artifactId></project>`,
		);
		fs.writeFileSync(
			path.join(unidbgDir, "unidbg-android", "target", "unidbg-classpath.txt"),
			`${unicornDepPath}${path.delimiter}${apiDepPath}\n`,
		);

		return unidbgDir;
	}

	beforeAll(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "unified-readiness-"));
		if (!isWindows) {
			jdk8Dir = createFakeJdk(tempDir, "jdk8", "1.8.0_392");
			jdk25Dir = createFakeJdk(tempDir, "jdk25", "25.0.1");
			createFakeUnidbgRepo(tempDir);
		}
	});

	afterAll(() => {
		try {
			fs.rmSync(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it("evaluates APK unpacking readiness across zero-dependency baseline, Python DroidASC, and Java JADX/Apktool gates", () => {
		// Offline / missing external tools: baseline container triage can ALWAYS start
		const offline = evaluateApkUnpackingReadiness({
			toolStatuses: [
				{ id: "jadx", status: "missing" },
				{ id: "droidasc", status: "missing" },
				{ id: "apktool", status: "missing" },
				{ id: "java", status: "missing" },
			],
		});

		expect(offline.canStart).toBe(true);
		expect(offline.ready).toBe(false);
		expect(offline.partialReady).toBe(false);
		expect(offline.stages.baseline.ready).toBe(true);
		expect(offline.stages.baseline.canStart).toBe(true);
		expect(offline.stages.javaDecompile.ready).toBe(false);
		expect(offline.stages.javaDecompile.canStart).toBe(false);
		expect(offline.stages.smali.ready).toBe(false);
		expect(offline.stages.smali.canStart).toBe(false);

		// With DroidASC only (Python-based, no JVM required): javaDecompile is ready independently
		const droidascOnly = evaluateApkUnpackingReadiness({
			toolStatuses: [
				{ id: "jadx", status: "missing" },
				{ id: "droidasc", status: "installed" },
				{ id: "apktool", status: "missing" },
				{ id: "java", status: "missing" },
			],
		});
		expect(droidascOnly.stages.javaDecompile.ready).toBe(true);
		expect(droidascOnly.stages.javaDecompile.canStart).toBe(true);
		expect(droidascOnly.stages.smali.ready).toBe(false);
		expect(droidascOnly.partialReady).toBe(true);
		expect(droidascOnly.ready).toBe(false);

		// With JADX installed but Java missing: javaDecompile blocked on Java prerequisite
		const jadxNoJava = evaluateApkUnpackingReadiness({
			toolStatuses: [
				{ id: "jadx", status: "installed" },
				{ id: "droidasc", status: "missing" },
				{ id: "apktool", status: "missing" },
				{ id: "java", status: "missing" },
			],
		});
		expect(jadxNoJava.stages.javaDecompile.ready).toBe(false);
		expect(jadxNoJava.stages.javaDecompile.missingTools).toContain("java");

		// With JADX and Java: javaDecompile ready, smali blocked
		const jadxReady = evaluateApkUnpackingReadiness({
			toolStatuses: [
				{ id: "jadx", status: "installed" },
				{ id: "droidasc", status: "missing" },
				{ id: "apktool", status: "missing" },
				{ id: "java", status: "installed" },
			],
		});
		expect(jadxReady.canStart).toBe(true);
		expect(jadxReady.stages.baseline.ready).toBe(true);
		expect(jadxReady.stages.javaDecompile.ready).toBe(true);
		expect(jadxReady.stages.smali.ready).toBe(false);
		expect(jadxReady.partialReady).toBe(true);
		expect(jadxReady.ready).toBe(false);

		// Full readiness: both JADX, Apktool, and Java installed
		const fullReady = evaluateApkUnpackingReadiness({
			toolStatuses: [
				{ id: "jadx", status: "installed" },
				{ id: "droidasc", status: "missing" },
				{ id: "apktool", status: "installed" },
				{ id: "java", status: "installed" },
			],
		});
		expect(fullReady.ready).toBe(true);
		expect(fullReady.partialReady).toBe(true);
		expect(fullReady.stages.javaDecompile.ready).toBe(true);
		expect(fullReady.stages.smali.ready).toBe(true);
	});

	it("supports scoped capability and category discovery in resolveReverseCapabilities with disconnected binding preservation", () => {
		const scopedApk = resolveReverseCapabilities({
			filterCapability: "apk_unpacking",
			toolStatuses: [],
			serviceStatuses: [],
		});
		expect(scopedApk.length).toBe(1);
		expect(scopedApk[0].id).toBe("apk_unpacking");
		expect(scopedApk[0].canStart).toBe(true);
		expect(scopedApk[0].unpackingStages).toBeDefined();
		expect(scopedApk[0].unpackingStages?.baseline.ready).toBe(true);
		expect(scopedApk[0].unpackingStages?.javaDecompile.ready).toBe(false);

		const scopedAndroid = resolveReverseCapabilities({
			filterCategory: "android",
			toolStatuses: [],
			serviceStatuses: [],
		});
		expect(scopedAndroid.length).toBeGreaterThan(0);
		for (const cap of scopedAndroid) {
			expect(cap.category).toBe("android");
		}
		expect(scopedAndroid.some(c => c.id === "native_debugger")).toBe(false);

		// Disconnected target binding preserves 'unknown' status without host session mixing
		const scopedEmulation = resolveReverseCapabilities({
			filterCapability: "android_native_emulation",
			target: "/path/to/target.so",
			env: { PATH: "" },
			toolStatuses: [],
			serviceStatuses: [],
		});
		expect(scopedEmulation.length).toBe(1);
		expect(scopedEmulation[0].id).toBe("android_native_emulation");
		expect(scopedEmulation[0].runtimeReady).toBe(false);
		expect(scopedEmulation[0].targetMatched).toBe("unknown");
		expect(scopedEmulation[0].executedVerified).toBe("unknown");
	});

	it.skipIf(isWindows)(
		"evaluates Unidbg readiness with actual fixture executables: rejects JDK 25 and accepts JDK 8 with cached reactor dependencies",
		() => {
			const unidbgDir = path.join(tempDir, "unidbg");

			// JDK 25: incompatible due to java.lang.Module conflict, cannot start
			const res25 = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk25Dir,
				env: { PATH: "" },
			});
			expect(res25.installed).toBe(true);
			expect(res25.compatible).toBe(false);
			expect(res25.canStart).toBe(false);
			expect(res25.jdkVersion).toBe("25.0.1");
			expect(res25.error).toBeDefined();

			// JDK 8: compatible, canStart with class tree cached dependencies
			const res8 = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(res8.installed).toBe(true);
			expect(res8.compatible).toBe(true);
			expect(res8.canStart).toBe(true);
			expect(res8.jdkVersion).toBe("1.8.0_392");
			expect(res8.error).toBeUndefined();
			expect(res8.remedy).toBeUndefined();

			// Preserves disconnected target binding state as unknown without ambient host mixing
			const res8WithTarget = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				target: "/path/to/target.so",
				env: { PATH: "" },
			});
			expect(res8WithTarget.canStart).toBe(true);
			expect(res8WithTarget.runtimeReady).toBe(false);
			expect(res8WithTarget.targetMatched).toBe("unknown");
			expect(res8WithTarget.executedVerified).toBe("unknown");
		},
	);

	it.skipIf(isWindows)(
		"blocks Unidbg launch when cached classpath is empty or missing and Maven is unavailable",
		() => {
			const unidbgDir = path.join(tempDir, "unidbg");
			const classpathFile = path.join(unidbgDir, "unidbg-android", "target", "unidbg-classpath.txt");

			// Empty out the cached classpath file
			fs.writeFileSync(classpathFile, "");

			const blockedRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});

			expect(blockedRes.installed).toBe(true);
			expect(blockedRes.compatible).toBe(true);
			expect(blockedRes.canStart).toBe(false);
			expect(blockedRes.error).toBeDefined();

			// Once valid classpath with existing on-disk entries is populated, launch becomes runnable
			fs.writeFileSync(classpathFile, `${unicornDepPath}${path.delimiter}${apiDepPath}\n`);

			const unblockedRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});

			expect(unblockedRes.canStart).toBe(true);
			expect(unblockedRes.error).toBeUndefined();
		},
	);

	it.skipIf(isWindows)(
		"dynamically re-evaluates launch prerequisites without stale cache when reactor artifacts change",
		() => {
			const unidbgDir = path.join(tempDir, "unidbg");
			const apiClassesDir = path.join(unidbgDir, "unidbg-api", "target", "classes");
			const androidClassesDir = path.join(unidbgDir, "unidbg-android", "target", "classes");

			// 1. Initial valid state: canStart is true
			const initialRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(initialRes.canStart).toBe(true);

			// 2. Remove compiled classes for unidbg-api: canStart must immediately drop to false
			fs.rmSync(apiClassesDir, { recursive: true, force: true });

			const brokenApiRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(brokenApiRes.canStart).toBe(false);
			expect(brokenApiRes.error).toBeDefined();

			// 3. Restore unidbg-api compiled classes: canStart must immediately recover to true
			fs.mkdirSync(apiClassesDir, { recursive: true });

			const recoveredApiRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(recoveredApiRes.canStart).toBe(true);

			// 4. Remove compiled classes for unidbg-android target module: canStart must drop to false
			fs.rmSync(androidClassesDir, { recursive: true, force: true });

			const brokenAndroidRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(brokenAndroidRes.canStart).toBe(false);
			expect(brokenAndroidRes.error).toBeDefined();

			// 5. Restore unidbg-android compiled classes: canStart recovers
			fs.mkdirSync(androidClassesDir, { recursive: true });

			const recoveredAndroidRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(recoveredAndroidRes.canStart).toBe(true);

			// 6. Delete actual cached dependency artifact: launch without Maven blocks
			fs.rmSync(unicornDepPath, { force: true });

			const brokenDepRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(brokenDepRes.canStart).toBe(false);
			expect(brokenDepRes.error).toBeDefined();

			// Restore cached dependency artifact
			fs.writeFileSync(unicornDepPath, "PK");

			const recoveredDepRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk8Dir,
				env: { PATH: "" },
			});
			expect(recoveredDepRes.canStart).toBe(true);

			// 7. Switch javaHome to JDK 25: compatible drops to false without stale cache
			const jdk25Res = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				javaHome: jdk25Dir,
				env: { PATH: "" },
			});
			expect(jdk25Res.compatible).toBe(false);
			expect(jdk25Res.canStart).toBe(false);
		},
	);

	it.skipIf(isWindows)(
		"respects explicit isolated env for JAVA_HOME without mutating global process.env or reading ambient host Java",
		() => {
			const unidbgDir = path.join(tempDir, "unidbg");
			const originalJavaHome = process.env.JAVA_HOME;

			// Explicit invalid JAVA_HOME via env option
			const invalidEnvRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				env: {
					JAVA_HOME: path.join(tempDir, "nonexistent-jdk-dir"),
					PATH: "",
				},
			});

			expect(invalidEnvRes.compatible).toBe(false);
			expect(invalidEnvRes.canStart).toBe(false);
			expect(invalidEnvRes.error).toBeDefined();
			expect(process.env.JAVA_HOME).toBe(originalJavaHome);

			// Explicit valid JDK 8 via env option
			const validEnvRes = evaluateUnidbgReadiness({
				unidbgHome: unidbgDir,
				env: {
					JAVA_HOME: jdk8Dir,
					PATH: "",
				},
			});

			expect(validEnvRes.compatible).toBe(true);
			expect(validEnvRes.canStart).toBe(true);
			expect(validEnvRes.jdkVersion).toBe("1.8.0_392");
			expect(validEnvRes.javaHome).toBe(jdk8Dir);
			expect(process.env.JAVA_HOME).toBe(originalJavaHome);
		},
	);

	it("scopes checkReverseTools discovery strictly: records which calls without probing unrelated tools and projects Java dependencies", () => {
		const probedCommands: string[] = [];
		const whichRecorder = (cmd: string) => {
			probedCommands.push(cmd);
			return null;
		};

		const isolatedSettings = Settings.isolated({});

		// 1. Scoped check for capability: apk_unpacking
		const capReport = checkReverseTools({
			filter: { capability: "apk_unpacking" },
			which: whichRecorder,
			env: {},
			settings: isolatedSettings,
			platform: "linux",
		});

		expect(capReport.capabilities.length).toBe(1);
		expect(capReport.capabilities[0].id).toBe("apk_unpacking");
		expect(capReport.capabilities[0].unpackingStages).toBeDefined();
		expect(capReport.capabilities[0].unpackingStages?.baseline.ready).toBe(true);
		expect(capReport.capabilities[0].unpackingStages?.javaDecompile.ready).toBe(false);

		const capToolIds = capReport.tools.map(t => t.id.toLowerCase());
		expect(capToolIds).toContain("jadx");
		expect(capToolIds).toContain("apktool");
		expect(capToolIds).not.toContain("ida");
		expect(capToolIds).not.toContain("unidbg");
		expect(capToolIds).not.toContain("ghidra");

		const probedLower = probedCommands.map(c => c.toLowerCase());
		expect(probedLower.includes("ida")).toBe(false);
		expect(probedLower.includes("ida64")).toBe(false);
		expect(probedLower.includes("unidbg")).toBe(false);
		expect(probedLower.includes("ghidra")).toBe(false);
		expect(probedLower.includes("radare2")).toBe(false);

		// 2. Scoped check for tool: jadx
		const jadxProbed: string[] = [];
		const jadxReport = checkReverseTools({
			filter: { tool: "jadx" },
			which: (cmd: string) => {
				jadxProbed.push(cmd);
				return null;
			},
			env: {},
			settings: isolatedSettings,
			platform: "linux",
		});

		const jadxToolIds = jadxReport.tools.map(t => t.id.toLowerCase());
		expect(jadxToolIds).toContain("jadx");
		expect(jadxToolIds).not.toContain("ida");
		expect(jadxToolIds).not.toContain("unidbg");

		// Java dependency projection: jadx requires java runtime, so java must be probed in closure
		const jadxProbedLower = jadxProbed.map(c => c.toLowerCase());
		expect(jadxProbedLower.includes("jadx")).toBe(true);
		expect(jadxProbedLower.includes("java")).toBe(true);
		expect(jadxProbedLower.includes("ida")).toBe(false);
		expect(jadxProbedLower.includes("unidbg")).toBe(false);

		// 3. Error guard on unknown capability
		expect(() => {
			checkReverseTools({
				filter: { capability: "non_existent_capability" },
				settings: isolatedSettings,
			});
		}).toThrow();
	});
});
