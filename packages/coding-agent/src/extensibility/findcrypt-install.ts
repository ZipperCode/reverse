/**
 * Ghidra FindCrypt Analyzer Resolver and Installer.
 *
 * Upstream: TorgoTorgo/ghidra-findcrypt (tag v2.1.4, commit 5c2fd5b, GPL-3.0).
 * Detects and builds the FindCrypt Ghidra auto-analyzer extension:
 * - Matches the exact installed Ghidra version (no fabricated compatibility across major Ghidra versions)
 * - Probes <ghidra_install>/Ghidra/Extensions, <ghidra_install>/Extensions/Ghidra, and user extension directory
 * - Verifies genuine extension.properties and FindCryptAnalyzer module jar
 * - Requires existing Ghidra, Java (JDK 17+/21+), and Gradle to build from upstream source
 * - Streams build output via runSubprocess with AbortSignal cancellation support
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which, WhichCachePolicy } from "@reverse/utils";
import { extractArchive } from "@reverse/utils/ar";
import { runSubprocess } from "./triton-source-install";
import type { SkillRequirementWhich } from "./skill-requirements";
import type { SkillToolPlatform } from "./skill-tool-catalog";

export const FINDCRYPT_VERSION = "2.1.4";
export const FINDCRYPT_RELEASE_TAG = "v2.1.4";
export const FINDCRYPT_COMMIT = "5c2fd5bb50d13a4092da136dc7004becd8129c7b";
export const FINDCRYPT_REPO_URL = "https://github.com/TorgoTorgo/ghidra-findcrypt.git";
export const FINDCRYPT_TAR_URL = `https://github.com/TorgoTorgo/ghidra-findcrypt/archive/${FINDCRYPT_COMMIT}.tar.gz`;
export const FINDCRYPT_LICENSE = "GPL-3.0";
export const FINDCRYPT_ANALYZER_NAME = "Find Crypt";
export const FINDCRYPT_ANALYZER_CLASS = "FindCryptAnalyzer";

export interface GhidraFindCryptStatus {
	available: boolean;
	ghidraFound: boolean;
	ghidraPath?: string;
	ghidraVersion?: string;
	extensionDir?: string;
	jarPath?: string;
	version?: string;
	analyzerClass?: string;
	installHint?: string;
	missingPrerequisites?: string[];
}

export interface GhidraFindCryptResolveOptions {
	ghidraPath?: string;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	homeDir?: string;
}

export interface GhidraFindCryptInstallOptions {
	ghidraPath?: string;
	sourceDir?: string;
	onLog?: (message: string) => void;
	signal?: AbortSignal;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
	which?: SkillRequirementWhich;
	timeoutMs?: number;
}

export interface GhidraFindCryptInstallResult {
	success: boolean;
	extensionDir: string;
	jarPath?: string;
	ghidraVersion?: string;
	error?: string;
}

/** Read and parse a Java .properties file into a key-value record. */
function parsePropertiesFile(content: string): Record<string, string> {
	const result: Record<string, string> = {};
	for (const line of content.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) continue;
		const eqIndex = trimmed.indexOf("=");
		if (eqIndex > 0) {
			const key = trimmed.slice(0, eqIndex).trim();
			const val = trimmed.slice(eqIndex + 1).trim();
			result[key] = val;
		}
	}
	return result;
}

/** Extract application.version from a Ghidra root directory. */
export function readGhidraVersion(ghidraDir: string): string | null {
	const candidates = [
		path.join(ghidraDir, "Ghidra", "application.properties"),
		path.join(ghidraDir, "application.properties"),
	];
	for (const cand of candidates) {
		try {
			if (fs.existsSync(cand)) {
				const props = parsePropertiesFile(fs.readFileSync(cand, "utf8"));
				if (props["application.version"]) return props["application.version"];
			}
		} catch {}
	}
	return null;
}

/** Resolve base installation directory of Ghidra. */
export function resolveGhidraInstallDir(options?: GhidraFindCryptResolveOptions): string | null {
	if (options?.ghidraPath && fs.existsSync(options.ghidraPath)) {
		return path.resolve(options.ghidraPath);
	}

	const envDir =
		options?.env?.GHIDRA_INSTALL_DIR ??
		options?.env?.GHIDRA_HOME ??
		process.env.GHIDRA_INSTALL_DIR ??
		process.env.GHIDRA_HOME;
	if (envDir && fs.existsSync(envDir)) {
		return path.resolve(envDir);
	}

	const whichFn = options?.which ?? $which;
	try {
		const whichOpts = { PATH: options?.env?.PATH, cache: WhichCachePolicy.Bypass };
		const headless = whichFn("analyzeHeadless", whichOpts);
		if (headless) {
			const parent = path.dirname(headless);
			if (path.basename(parent) === "support") {
				return path.resolve(parent, "..");
			}
			return path.resolve(parent);
		}
	} catch {}

	// Well-known system search paths
	const commonPaths = ["/opt/ghidra", "/usr/share/ghidra", "/Applications/ghidra", "C:/ghidra", "D:/ghidra"];
	for (const p of commonPaths) {
		try {
			if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
				return path.resolve(p);
			}
		} catch {}
	}

	// Homebrew cask search on macOS
	if (process.platform === "darwin") {
		const brewCaskBase = "/opt/homebrew/Caskroom/ghidra";
		try {
			if (fs.existsSync(brewCaskBase)) {
				const vers = fs.readdirSync(brewCaskBase);
				for (const v of vers) {
					const vDir = path.join(brewCaskBase, v);
					if (!fs.statSync(vDir).isDirectory()) continue;
					const sub = fs.readdirSync(vDir);
					for (const s of sub) {
						const cand = path.join(vDir, s);
						if (fs.existsSync(path.join(cand, "support", "analyzeHeadless"))) {
							return cand;
						}
					}
				}
			}
		} catch {}
	}

	return null;
}

/**
 * Resolve Ghidra FindCrypt extension status.
 *
 * Verifies that Ghidra is present, reads its version, and inspects extension
 * directories for genuine FindCrypt extension properties and analyzer JAR.
 */
export function resolveGhidraFindCrypt(options?: GhidraFindCryptResolveOptions): GhidraFindCryptStatus {
	const ghidraDir = resolveGhidraInstallDir(options);
	if (!ghidraDir) {
		return {
			available: false,
			ghidraFound: false,
			installHint: "Ghidra must be installed first (run 'reverse setup reverse ghidra').",
			missingPrerequisites: ["ghidra"],
		};
	}

	const ghidraVersion = readGhidraVersion(ghidraDir) ?? undefined;
	const home = options?.homeDir ?? os.homedir();

	const candidateExtensionDirs: string[] = [
		path.join(ghidraDir, "Ghidra", "Extensions", "FindCrypt"),
		path.join(ghidraDir, "Ghidra", "Extensions", "ghidra-findcrypt"),
		path.join(ghidraDir, "Extensions", "Ghidra", "FindCrypt"),
		path.join(ghidraDir, "Extensions", "Ghidra", "ghidra-findcrypt"),
		path.join(ghidraDir, "Extensions", "FindCrypt"),
	];

	if (ghidraVersion) {
		candidateExtensionDirs.push(
			path.join(home, ".ghidra", `.ghidra_${ghidraVersion}`, "Extensions", "FindCrypt"),
			path.join(home, ".ghidra", `.ghidra_${ghidraVersion}`, "Extensions", "ghidra-findcrypt"),
			path.join(home, ".ghidra", `.ghidra_${ghidraVersion}_PUBLIC`, "Extensions", "FindCrypt"),
			path.join(home, ".ghidra", `.ghidra_${ghidraVersion}_PUBLIC`, "Extensions", "ghidra-findcrypt"),
		);
	}

	for (const candDir of candidateExtensionDirs) {
		try {
			if (!fs.existsSync(candDir) || !fs.statSync(candDir).isDirectory()) {
				continue;
			}
			const extPropsPath = path.join(candDir, "extension.properties");
			if (!fs.existsSync(extPropsPath)) continue;

			const props = parsePropertiesFile(fs.readFileSync(extPropsPath, "utf8"));
			const extName = (props.name ?? "").toLowerCase();
			if (!extName.includes("findcrypt")) continue;

			// Look for jar in candDir or candDir/lib
			let matchedJar: string | undefined;
			const jarDirs = [candDir, path.join(candDir, "lib")];
			for (const jd of jarDirs) {
				if (!fs.existsSync(jd)) continue;
				const files = fs.readdirSync(jd);
				for (const f of files) {
					if (f.endsWith(".jar") && !f.endsWith("-sources.jar") && !f.endsWith("-javadoc.jar")) {
						matchedJar = path.join(jd, f);
						break;
					}
				}
				if (matchedJar) break;
			}

			if (matchedJar) {
				return {
					available: true,
					ghidraFound: true,
					ghidraPath: ghidraDir,
					ghidraVersion,
					extensionDir: candDir,
					jarPath: matchedJar,
					version: props.version ?? FINDCRYPT_VERSION,
					analyzerClass: FINDCRYPT_ANALYZER_CLASS,
				};
			}
		} catch {}
	}

	return {
		available: false,
		ghidraFound: true,
		ghidraPath: ghidraDir,
		ghidraVersion,
		installHint: `Build and install FindCrypt extension for Ghidra ${ghidraVersion ?? ""} (run 'reverse setup reverse ghidra-findcrypt').`,
		missingPrerequisites: ["ghidra-findcrypt"],
	};
}

/** Check build prerequisites for Ghidra FindCrypt (Ghidra, JDK, Gradle). */
export function canBuildGhidraFindCrypt(deps?: {
	ghidraPath?: string;
	which?: SkillRequirementWhich;
	env?: Record<string, string | undefined>;
	platform?: SkillToolPlatform;
}): {
	supported: boolean;
	missingPrereqs: string[];
	ghidraDir: string | null;
	ghidraVersion: string | null;
} {
	const whichFn = deps?.which ?? $which;
	const whichOpts = { PATH: deps?.env?.PATH, cache: WhichCachePolicy.Bypass };
	const ghidraDir = resolveGhidraInstallDir(deps);
	const ghidraVersion = ghidraDir ? readGhidraVersion(ghidraDir) : null;
	const java = whichFn("java", whichOpts);
	const gradle = whichFn("gradle", whichOpts);
	const missing: string[] = [];
	if (!ghidraDir) missing.push("ghidra (target Ghidra installation)");
	if (!ghidraVersion) missing.push("ghidra version (missing or invalid application.properties)");
	if (!java) missing.push("java (JDK 17+ or 21+)");
	if (!gradle) missing.push("gradle");

	return {
		supported: missing.length === 0,
		missingPrereqs: missing,
		ghidraDir,
		ghidraVersion,
	};
}

/**
 * Build Ghidra FindCrypt extension matching the target Ghidra version and install it.
 */
export async function buildAndInstallGhidraFindCrypt(
	options: GhidraFindCryptInstallOptions,
): Promise<GhidraFindCryptInstallResult> {
	const prereqs = canBuildGhidraFindCrypt({
		ghidraPath: options.ghidraPath,
		which: options.which,
		env: options.env,
		platform: options.platform,
	});

	if (!prereqs.supported || !prereqs.ghidraDir) {
		return {
			success: false,
			extensionDir: "",
			error: `Cannot build FindCrypt: missing prerequisites: ${prereqs.missingPrereqs.join(", ")}.`,
		};
	}

	const ghidraDir = prereqs.ghidraDir;
	const ghidraVersion = prereqs.ghidraVersion ?? readGhidraVersion(ghidraDir);
	if (!ghidraVersion) {
		return {
			success: false,
			extensionDir: "",
			error: `Cannot determine Ghidra version from application.properties in ${ghidraDir}. Valid Ghidra installation required.`,
		};
	}

	const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), "reverse-findcrypt-build-"));
	const stageSourceDir = path.join(stageDir, "source");

	try {
		if (options.sourceDir && fs.existsSync(options.sourceDir)) {
			// Copy user-provided source into private stage to avoid mutating user files
			options.onLog?.(`[findcrypt] Staging source from ${options.sourceDir}...\n`);
			fs.cpSync(options.sourceDir, stageSourceDir, { recursive: true });
		} else {
			options.onLog?.(`[findcrypt] Cloning upstream TorgoTorgo/ghidra-findcrypt...\n`);
			const cloneRes = await runSubprocess(["git", "clone", FINDCRYPT_REPO_URL, stageSourceDir], {
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 60000,
			});
			if (cloneRes.exitCode !== 0) {
				return {
					success: false,
					extensionDir: "",
					error: `Failed to clone ghidra-findcrypt: ${cloneRes.stderr || cloneRes.stdout}`,
				};
			}

			options.onLog?.(`[findcrypt] Checking out pinned commit ${FINDCRYPT_COMMIT.slice(0, 8)}...\n`);
			const checkoutRes = await runSubprocess(["git", "checkout", FINDCRYPT_COMMIT], {
				cwd: stageSourceDir,
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: 15000,
			});
			if (checkoutRes.exitCode !== 0) {
				return {
					success: false,
					extensionDir: "",
					error: `Failed to checkout FindCrypt commit ${FINDCRYPT_COMMIT}: ${checkoutRes.stderr || checkoutRes.stdout}`,
				};
			}
		}

		const buildCwd = fs.existsSync(path.join(stageSourceDir, "FindCrypt", "build.gradle"))
			? path.join(stageSourceDir, "FindCrypt")
			: stageSourceDir;

		// Modern Ghidra 12+ API compatibility patch
		const analyzerJavaCandidates = [
			path.join(stageSourceDir, "FindCrypt", "src", "main", "java", "findcrypt", "FindCryptAnalyzer.java"),
			path.join(stageSourceDir, "src", "main", "java", "findcrypt", "FindCryptAnalyzer.java"),
		];
		for (const ajc of analyzerJavaCandidates) {
			if (fs.existsSync(ajc)) {
				let javaCode = fs.readFileSync(ajc, "utf8");
				const majorVer = Number.parseInt(ghidraVersion.split(".")[0] ?? "11", 10);
				if (majorVer >= 12 || javaCode.includes("DataTypeConflictException")) {
					javaCode = javaCode.replace("import ghidra.program.model.data.DataTypeConflictException;\n", "");
					javaCode = javaCode.replace(/monitor\.checkCanceled\(\);/g, "monitor.checkCancelled();");
					javaCode = javaCode.replace(
						"CodeUnitInsertionException | DataTypeConflictException",
						"CodeUnitInsertionException",
					);
					fs.writeFileSync(ajc, javaCode, "utf8");
				}
				break;
			}
		}

		// Look for gradle wrapper or system gradle
		const isWin = process.platform === "win32";
		const wrapper = path.join(stageSourceDir, isWin ? "gradlew.bat" : "gradlew");
		const gradleBin = fs.existsSync(wrapper) ? wrapper : "gradle";

		options.onLog?.(`[findcrypt] Building extension against Ghidra ${ghidraVersion} at ${ghidraDir}...\n`);
		const buildRes = await runSubprocess(
			[gradleBin, `-PGHIDRA_INSTALL_DIR=${ghidraDir}`, "-x", "buildModuleHelp", "--no-daemon"],
			{
				cwd: buildCwd,
				env: {
					...(options.env ?? process.env),
					GHIDRA_INSTALL_DIR: ghidraDir,
				},
				onChunk: options.onLog,
				signal: options.signal,
				timeoutMs: options.timeoutMs ?? 300000,
			},
		);

		if (buildRes.exitCode !== 0) {
			return {
				success: false,
				extensionDir: "",
				error: `Gradle build failed with exit code ${buildRes.exitCode}: ${buildRes.stderr || buildRes.stdout}`,
			};
		}

		// Find output zip in buildCwd/dist, stageSourceDir/dist, or FindCrypt/dist
		const candidateDistDirs = [
			path.join(buildCwd, "dist"),
			path.join(stageSourceDir, "FindCrypt", "dist"),
			path.join(stageSourceDir, "dist"),
		];
		let outputZip: string | undefined;
		for (const distDir of candidateDistDirs) {
			if (fs.existsSync(distDir)) {
				const distFiles = fs.readdirSync(distDir);
				for (const f of distFiles) {
					if (f.endsWith(".zip") && f.toLowerCase().includes("findcrypt")) {
						outputZip = path.join(distDir, f);
						break;
					}
				}
				if (outputZip) break;
			}
		}

		if (!outputZip) {
			return {
				success: false,
				extensionDir: "",
				error: `Build succeeded but extension zip not found in candidate dist directories: ${candidateDistDirs.join(", ")}`,
			};
		}

		// Target extension directory: prefer <ghidraDir>/Ghidra/Extensions/FindCrypt
		let targetExtDir = path.join(ghidraDir, "Ghidra", "Extensions", "FindCrypt");
		try {
			fs.mkdirSync(path.dirname(targetExtDir), { recursive: true });
		} catch {
			targetExtDir = path.join(os.homedir(), ".ghidra", `.ghidra_${ghidraVersion}`, "Extensions", "FindCrypt");
			fs.mkdirSync(path.dirname(targetExtDir), { recursive: true });
		}

		const tempExtractDir = path.join(stageDir, "extracted");
		fs.mkdirSync(tempExtractDir, { recursive: true });
		options.onLog?.(`[findcrypt] Extracting extension zip...\n`);
		await extractArchive(outputZip, tempExtractDir);

		// If zip created a nested FindCrypt directory, flatten it into targetExtDir
		const nestedDir = path.join(tempExtractDir, "FindCrypt");
		const sourceExtContentDir =
			fs.existsSync(nestedDir) && fs.existsSync(path.join(nestedDir, "extension.properties"))
				? nestedDir
				: tempExtractDir;

		fs.mkdirSync(targetExtDir, { recursive: true });
		fs.cpSync(sourceExtContentDir, targetExtDir, { recursive: true });
		// Verify probe
		const verified = resolveGhidraFindCrypt({
			ghidraPath: ghidraDir,
			env: options.env,
			platform: options.platform,
			which: options.which,
		});

		if (!verified.available) {
			return {
				success: false,
				extensionDir: targetExtDir,
				error: "Extension extracted but verification probe failed to locate FindCryptAnalyzer.",
			};
		}

		options.onLog?.(`[findcrypt] Successfully installed FindCrypt to ${targetExtDir}\n`);

		return {
			success: true,
			extensionDir: verified.extensionDir ?? targetExtDir,
			jarPath: verified.jarPath,
			ghidraVersion,
		};
	} catch (err: unknown) {
		return {
			success: false,
			extensionDir: "",
			error: err instanceof Error ? err.message : String(err),
		};
	} finally {
		try {
			fs.rmSync(stageDir, { recursive: true, force: true });
		} catch {}
	}
}
