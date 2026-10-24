/**
 * Unidbg Source Build Automation & JDK 8 Validation
 *
 * Enforces strict JDK 8 validation (JDK 9+ fails due to java.lang.Module collision with com.github.unidbg.Module),
 * handles Maven wrapper execution, supports Aliyun mirrors for central plugins,
 * and tracks compiled artifacts.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { $which } from "@reverse/utils";
import { resolveStdioSpawnCommand } from "../mcp/transports/stdio";
import { inspectUnidbg } from "./unidbg-detect";

export interface JdkValidationResult {
	valid: boolean;
	version?: string;
	javaBin?: string;
	javaHome?: string;
	error?: string;
}

export interface UnidbgBuildOptions {
	unidbgDir?: string;
	javaHome?: string;
	mirror?: "aliyun" | "default";
	skipTests?: boolean;
	repoUrl?: string;
	mavenPath?: string;
	onLog?: (chunk: string) => void;
	signal?: AbortSignal;
}

export interface UnidbgBuildResult {
	success: boolean;
	unidbgDir: string;
	exitCode: number;
	output: string;
	jarPaths: string[];
	error?: string;
}

/**
 * Validate that the specified or ambient Java installation is strictly JDK 8 (1.8).
 * Rejects JDK 9+ with explicit explanation of the java.lang.Module collision.
 * If explicit javaHome is provided, it must be validated directly and never silently fallback to PATH.
 */
export function validateJdk8(javaHome?: string): JdkValidationResult {
	let javaBin: string | null = null;
	let targetHome = javaHome;

	if (targetHome !== undefined) {
		const exeName = process.platform === "win32" ? "java.exe" : "java";
		const candidate = path.join(targetHome, "bin", exeName);
		if (!fs.existsSync(candidate)) {
			return {
				valid: false,
				javaHome: targetHome,
				error: `Explicit javaHome does not contain a valid Java executable at ${candidate}.`,
			};
		}
		javaBin = candidate;
	} else if (process.env.JAVA_HOME) {
		targetHome = process.env.JAVA_HOME;
		const exeName = process.platform === "win32" ? "java.exe" : "java";
		const candidate = path.join(targetHome, "bin", exeName);
		if (fs.existsSync(candidate)) {
			javaBin = candidate;
		}
	}

	if (!javaBin && !targetHome) {
		javaBin = $which("java");
	}

	if (!javaBin || !fs.existsSync(javaBin)) {
		return {
			valid: false,
			javaHome: targetHome,
			error: "Java executable not found. JDK 8 is required for Unidbg. Please install JDK 8 and set JAVA_HOME.",
		};
	}

	const javacName = process.platform === "win32" ? "javac.exe" : "javac";
	const javacCandidate = path.join(path.dirname(javaBin), javacName);
	if (!fs.existsSync(javacCandidate)) {
		return {
			valid: false,
			javaBin,
			error: `Java compiler (${javacName}) not found alongside ${javaBin}. A full JDK 8 installation is required (found JRE only).`,
		};
	}

	const res = spawnSync(javaBin, ["-version"], { encoding: "utf8" });
	const rawOutput = (res.stderr || "") + "\n" + (res.stdout || "");
	const match =
		rawOutput.match(/(?:java|openjdk)\s+version\s+"([^"]+)"/i) || rawOutput.match(/(?:java|openjdk)\s+([0-9._]+)/i);

	if (!match) {
		return {
			valid: false,
			javaBin,
			error: `Could not parse Java version from: ${rawOutput.trim()}`,
		};
	}

	const versionStr = match[1];
	const isJdk8 = versionStr.startsWith("1.8.") || versionStr.startsWith("8.") || versionStr === "8";

	if (!isJdk8) {
		return {
			valid: false,
			version: versionStr,
			javaBin,
			error:
				`JDK 8 (1.8) is strictly required for Unidbg (found Java ${versionStr}). ` +
				`JDK 9+ introduces java.lang.Module which conflicts with Unidbg's com.github.unidbg.Module during compilation. ` +
				`Please set JAVA_HOME to a JDK 8 installation.`,
		};
	}

	const validatedHome =
		targetHome && fs.existsSync(path.join(targetHome, "bin", javacName))
			? targetHome
			: path.dirname(path.dirname(javaBin));

	return {
		valid: true,
		version: versionStr,
		javaBin,
		javaHome: validatedHome,
	};
}

/**
 * Automate clone and build of upstream Unidbg using Maven wrapper and validated JDK 8.
 */
export async function buildUnidbg(options: UnidbgBuildOptions = {}): Promise<UnidbgBuildResult> {
	if (options.signal?.aborted) {
		return {
			success: false,
			unidbgDir: options.unidbgDir ?? "",
			exitCode: 1,
			output: "",
			jarPaths: [],
			error: "Operation cancelled",
		};
	}

	const jdkCheck = validateJdk8(options.javaHome);
	if (!jdkCheck.valid) {
		return {
			success: false,
			unidbgDir: options.unidbgDir ?? "",
			exitCode: 1,
			output: "",
			jarPaths: [],
			error: jdkCheck.error ?? "Invalid JDK version",
		};
	}

	let targetDir = options.unidbgDir ? path.resolve(options.unidbgDir) : undefined;
	if (!targetDir) {
		const inspected = inspectUnidbg();
		targetDir = inspected.sourceRoot ? path.resolve(inspected.sourceRoot) : path.resolve(process.cwd(), "unidbg");
	}

	if (!fs.existsSync(targetDir) || !fs.existsSync(path.join(targetDir, "pom.xml"))) {
		const repoUrl = options.repoUrl ?? "https://github.com/zhkl0228/unidbg.git";
		options.onLog?.(`Cloning Unidbg from ${repoUrl} to ${targetDir}...\n`);

		const { promise: clonePromise, resolve: resolveClone } = Promise.withResolvers<{
			status: number;
			output: string;
		}>();
		let cloneOutput = "";
		const gitChild = spawn("git", ["clone", repoUrl, targetDir], {
			stdio: ["ignore", "pipe", "pipe"],
		});

		const onAbortClone = () => gitChild.kill("SIGTERM");
		options.signal?.addEventListener("abort", onAbortClone, { once: true });

		gitChild.stdout.on("data", d => {
			const s = d.toString("utf8");
			cloneOutput += s;
			options.onLog?.(s);
		});
		gitChild.stderr.on("data", d => {
			const s = d.toString("utf8");
			cloneOutput += s;
			options.onLog?.(s);
		});

		gitChild.on("close", code => {
			options.signal?.removeEventListener("abort", onAbortClone);
			resolveClone({ status: code ?? 1, output: cloneOutput });
		});
		gitChild.on("error", err => {
			options.signal?.removeEventListener("abort", onAbortClone);
			resolveClone({ status: 1, output: err.message });
		});

		const cloneResult = await clonePromise;
		if (cloneResult.status !== 0) {
			return {
				success: false,
				unidbgDir: targetDir,
				exitCode: cloneResult.status,
				output: cloneResult.output,
				jarPaths: [],
				error: `git clone failed: ${cloneResult.output}`,
			};
		}
	}

	let mavenBin: string;
	const isWin = process.platform === "win32";
	const wrapperName = isWin ? "mvnw.cmd" : "mvnw";
	const localWrapper = path.resolve(targetDir, wrapperName);

	if (options.mavenPath && fs.existsSync(options.mavenPath)) {
		mavenBin = path.resolve(options.mavenPath);
	} else if (fs.existsSync(localWrapper)) {
		mavenBin = localWrapper;
		if (!isWin) {
			try {
				fs.chmodSync(localWrapper, 0o755);
			} catch {}
		}
	} else {
		mavenBin = $which("mvn") || "mvn";
	}

	const args: string[] = [];
	const env: NodeJS.ProcessEnv = {
		...process.env,
		JAVA_HOME: jdkCheck.javaHome,
		PATH: jdkCheck.javaHome
			? `${path.join(jdkCheck.javaHome, "bin")}${path.delimiter}${process.env.PATH || ""}`
			: process.env.PATH,
	};

	const proxyUrl =
		process.env.https_proxy || process.env.HTTPS_PROXY || process.env.http_proxy || process.env.HTTP_PROXY;
	if (proxyUrl) {
		try {
			const parsed = new URL(proxyUrl);
			if (parsed.hostname) {
				args.push(`-Dhttp.proxyHost=${parsed.hostname}`, `-Dhttps.proxyHost=${parsed.hostname}`);
			}
			if (parsed.port) {
				args.push(`-Dhttp.proxyPort=${parsed.port}`, `-Dhttps.proxyPort=${parsed.port}`);
			}
		} catch {}
	}

	let tempDir: string | null = null;
	let tempSettingsPath: string | null = null;
	if (options.mirror === "aliyun") {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "unidbg-maven-"));
		tempSettingsPath = path.join(tempDir, "settings.xml");
		const content = `<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <mirrors>
    <mirror>
      <id>aliyunmaven</id>
      <mirrorOf>central</mirrorOf>
      <name>Aliyun Central Mirror</name>
      <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
  </mirrors>
</settings>
`;
		fs.writeFileSync(tempSettingsPath, content, "utf8");
		args.push("-s", tempSettingsPath);
		env.MVNW_REPOURL = "https://maven.aliyun.com/repository/public";
	}

	args.push("-Dgpg.skip=true");
	if (options.skipTests !== false) {
		args.push("-DskipTests", "-Dmaven.test.skip=true");
	} else {
		args.push("-DskipTests=false", "-Dmaven.test.skip=false");
	}
	// Use install so reactor SNAPSHOT modules are available in local Maven repository,
	// and generate dependency classpath for deterministic test harness compilation.
	args.push(
		"install",
		"dependency:build-classpath",
		"-DincludeScope=test",
		"-Dmdep.outputFile=target/unidbg-classpath.txt",
	);
	options.onLog?.(`Building Unidbg via ${mavenBin} ${args.join(" ")} (JDK: ${jdkCheck.version})...\n`);

	const resolvedCmd = await resolveStdioSpawnCommand(
		{ type: "stdio", command: mavenBin, args },
		{ cwd: targetDir, env, platform: process.platform },
	);

	if (options.signal?.aborted) {
		if (tempDir && fs.existsSync(tempDir)) {
			try {
				fs.rmSync(tempDir, { recursive: true, force: true });
			} catch {}
		}
		return {
			success: false,
			unidbgDir: targetDir!,
			exitCode: 1,
			output: "",
			jarPaths: [],
			error: "Operation cancelled",
		};
	}
	const { promise, resolve } = Promise.withResolvers<UnidbgBuildResult>();
	let output = "";

	const child = spawn(resolvedCmd.cmd[0], resolvedCmd.cmd.slice(1), {
		cwd: targetDir,
		env,
		windowsVerbatimArguments: resolvedCmd.windowsVerbatimArguments,
		windowsHide: resolvedCmd.windowsHide,
		stdio: ["ignore", "pipe", "pipe"],
	});

	const cleanup = () => {
		if (tempDir && fs.existsSync(tempDir)) {
			try {
				fs.rmSync(tempDir, { recursive: true, force: true });
			} catch {}
		}
	};

	const onAbort = () => {
		child.kill("SIGTERM");
		cleanup();
	};
	options.signal?.addEventListener("abort", onAbort, { once: true });

	const onData = (chunk: Buffer) => {
		const text = chunk.toString("utf8");
		output += text;
		options.onLog?.(text);
	};

	child.stdout.on("data", onData);
	child.stderr.on("data", onData);

	child.on("close", code => {
		options.signal?.removeEventListener("abort", onAbort);
		cleanup();
		const findJars = (sub: string) => {
			const d = path.join(targetDir!, sub, "target");
			if (!fs.existsSync(d)) return [];
			try {
				return fs
					.readdirSync(d)
					.filter(f => f.endsWith(".jar") && !f.endsWith("-sources.jar") && !f.endsWith("-javadoc.jar"))
					.map(f => path.join(d, f));
			} catch {
				return [];
			}
		};
		const builtJars = [
			...findJars("unidbg-api"),
			...findJars("unidbg-android"),
			...findJars("unidbg-ios"),
			...findJars(path.join("backend", "unicorn2")),
			...findJars(path.join("backend", "dynarmic")),
		];
		const success = code === 0;
		resolve({
			success,
			unidbgDir: targetDir!,
			exitCode: code ?? 1,
			output,
			jarPaths: builtJars,
			error: success ? undefined : `Maven build failed with exit code ${code}`,
		});
	});

	child.on("error", err => {
		options.signal?.removeEventListener("abort", onAbort);
		cleanup();
		resolve({
			success: false,
			unidbgDir: targetDir!,
			exitCode: 1,
			output,
			jarPaths: [],
			error: err.message,
		});
	});

	return promise;
}
