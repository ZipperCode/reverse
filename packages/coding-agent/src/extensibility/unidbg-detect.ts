/**
 * Unidbg library and source tree detector.
 *
 * Checks for:
 * 1. UNIDBG_HOME, UNIDBG_ROOT, UNIDBG_DIR, UNIDBG_JAR environment variables.
 * 2. Unidbg project directory (contains `unidbg-api` and verified `pom.xml`, or built targets).
 * 3. Prebuilt jar files (`unidbg-api-*.jar`, `unidbg-android-*.jar`, `unidbg-all-*.jar`) with
 *    ZIP class identity verification (`com/github/unidbg/`).
 * 4. Local Maven cache repository (`~/.m2/repository/com/github/zhkl0228/unidbg-api` or `unidbg-android`).
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import type { WhichOptions } from "@reverse/utils";

export interface UnidbgInspectionResult {
	foundPath: string | null;
	unidbgDir?: string;
	sourceRoot?: string;
	hasPom: boolean;
	hasWrapper: boolean;
	built: boolean;
	jars: string[];
}

export interface LocateUnidbgOptions {
	dir?: string;
	sourceRoot?: string;
	env?: Record<string, string | undefined>;
	cwd?: string;
	which?: (cmd: string, options?: WhichOptions) => string | null;
	platform?: NodeJS.Platform;
}

/** Verify file has ZIP magic header and contains genuine unidbg class files. */
export function isUnidbgJar(filePath: string): boolean {
	try {
		if (!filePath.endsWith(".jar") || filePath.endsWith("-sources.jar") || filePath.endsWith("-javadoc.jar")) {
			return false;
		}
		const stat = fs.statSync(filePath);
		if (!stat.isFile() || stat.size < 64) return false;

		const buf = fs.readFileSync(filePath);
		if (buf.length < 22) return false;

		// Search backwards for End of Central Directory (EOCD signature 0x06054b50)
		let eocd = -1;
		const maxSearch = Math.min(buf.length, 65557);
		for (let i = buf.length - 22; i >= buf.length - maxSearch; i--) {
			if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) {
				eocd = i;
				break;
			}
		}
		if (eocd === -1) return false;

		const cdOffset = buf.readUInt32LE(eocd + 16);
		const cdSize = buf.readUInt32LE(eocd + 12);
		let ptr = cdOffset;
		const cdEnd = Math.min(buf.length, cdOffset + cdSize);

		while (ptr + 46 <= cdEnd) {
			const sig = buf.readUInt32LE(ptr);
			if (sig !== 0x02014b50) break;

			const fnLen = buf.readUInt16LE(ptr + 28);
			const extraLen = buf.readUInt16LE(ptr + 30);
			const commentLen = buf.readUInt16LE(ptr + 32);

			if (ptr + 46 + fnLen > buf.length) break;
			const name = buf.toString("utf8", ptr + 46, ptr + 46 + fnLen);
			if (name.startsWith("com/github/unidbg/") && name.endsWith(".class")) {
				const compMethod = buf.readUInt16LE(ptr + 10);
				const compSize = buf.readUInt32LE(ptr + 20);
				const uncompSize = buf.readUInt32LE(ptr + 24);
				const localHeaderOffset = buf.readUInt32LE(ptr + 42);

				if (uncompSize >= 4 && localHeaderOffset + 30 <= cdOffset) {
					const localSig = buf.readUInt32LE(localHeaderOffset);
					if (localSig === 0x04034b50) {
						const nameLen = buf.readUInt16LE(localHeaderOffset + 26);
						const extraLen = buf.readUInt16LE(localHeaderOffset + 28);
						const dataStart = localHeaderOffset + 30 + nameLen + extraLen;
						const dataEnd = dataStart + compSize;

						if (dataEnd <= cdOffset && dataEnd <= buf.length) {
							if (compMethod === 0) {
								if (buf.readUInt32BE(dataStart) === 0xcafebabe) {
									return true;
								}
							} else if (compMethod === 8) {
								try {
									const decompressed = zlib.inflateRawSync(buf.subarray(dataStart, dataEnd));
									if (decompressed.length >= 4 && decompressed.readUInt32BE(0) === 0xcafebabe) {
										return true;
									}
								} catch {}
							}
						}
					}
				}
			}
			ptr += 46 + fnLen + extraLen + commentLen;
		}
		return false;
	} catch {
		return false;
	}
}

function findJarInDir(dir: string, pattern: RegExp): string | null {
	try {
		const entries = fs.readdirSync(dir);
		for (const entry of entries) {
			if (pattern.test(entry) && !entry.includes("-sources") && !entry.includes("-javadoc")) {
				const full = path.join(dir, entry);
				if (isUnidbgJar(full)) {
					return full;
				}
			}
		}
	} catch {}
	return null;
}

export function findUnidbgJar(targetDir: string): string | null {
	if (isUnidbgJar(targetDir)) return targetDir;

	const candidates = [
		path.join(targetDir, "unidbg-api", "target"),
		path.join(targetDir, "unidbg-android", "target"),
		path.join(targetDir, "target"),
		targetDir,
	];
	for (const d of candidates) {
		const found = findJarInDir(d, /^unidbg(-.*)?\.jar$/i);
		if (found) return found;
	}
	return null;
}

/** Checks whether a directory is a genuine unidbg repository or container. */
export function isUnidbgDir(targetDir: string): boolean {
	try {
		if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) return false;
		if (findUnidbgJar(targetDir) !== null) return true;

		const pomPath = path.join(targetDir, "pom.xml");
		const apiDir = path.join(targetDir, "unidbg-api");
		if (fs.existsSync(pomPath) && fs.existsSync(apiDir) && fs.statSync(apiDir).isDirectory()) {
			const pomContent = fs.readFileSync(pomPath, "utf8");
			if (pomContent.includes("com.github.zhkl0228") || pomContent.includes("<artifactId>unidbg")) {
				return true;
			}
		}
	} catch {}
	return false;
}

function scanMavenRepo(homeDir: string): string | null {
	const m2Bases = [
		path.join(homeDir, ".m2", "repository", "com", "github", "zhkl0228", "unidbg-api"),
		path.join(homeDir, ".m2", "repository", "com", "github", "zhkl0228", "unidbg-android"),
	];
	for (const base of m2Bases) {
		try {
			if (!fs.existsSync(base)) continue;
			const versions = fs.readdirSync(base);
			for (const ver of versions) {
				const verDir = path.join(base, ver);
				const jar = findJarInDir(verDir, /^unidbg(-.*)?\.jar$/i);
				if (jar) return jar;
			}
		} catch {}
	}
	return null;
}

export function inspectUnidbg(options: LocateUnidbgOptions = {}): UnidbgInspectionResult {
	const env = options.env ?? process.env;
	const homedir = env.HOME ?? env.USERPROFILE ?? os.homedir();
	const cwd = options.cwd ?? process.cwd();
	const isWin = (options.platform ?? process.platform) === "win32";
	const wrapperName = isWin ? "mvnw.cmd" : "mvnw";

	const assessDir = (dir: string): UnidbgInspectionResult | null => {
		if (!isUnidbgDir(dir)) return null;
		const pomPath = path.join(dir, "pom.xml");
		const hasPom = fs.existsSync(pomPath);
		const hasWrapper = fs.existsSync(path.join(dir, wrapperName)) || fs.existsSync(path.join(dir, "mvnw"));
		const jars: string[] = [];
		const primaryJar = findUnidbgJar(dir);
		if (primaryJar) jars.push(primaryJar);

		const submodules = ["unidbg-api", "unidbg-android", "unidbg-ios"];
		for (const sub of submodules) {
			const targetDir = path.join(dir, sub, "target");
			const jar = findJarInDir(targetDir, /^unidbg-.*\.jar$/i);
			if (jar && !jars.includes(jar)) jars.push(jar);
		}

		const built = jars.length > 0;
		return {
			foundPath: primaryJar ?? dir,
			unidbgDir: dir,
			sourceRoot: hasPom ? dir : undefined,
			hasPom,
			hasWrapper,
			built,
			jars,
		};
	};

	// 0. Explicit direct path or sourceRoot input (highest priority, strict)
	const explicitTarget = options.sourceRoot ?? options.dir;
	if (explicitTarget) {
		return assessDir(explicitTarget) ?? {
			foundPath: null,
			hasPom: false,
			hasWrapper: false,
			built: false,
			jars: [],
		};
	}

	// 1. Explicit env variables
	if (env.UNIDBG_JAR && isUnidbgJar(env.UNIDBG_JAR)) {
		return {
			foundPath: env.UNIDBG_JAR,
			unidbgDir: path.dirname(env.UNIDBG_JAR),
			hasPom: false,
			hasWrapper: false,
			built: true,
			jars: [env.UNIDBG_JAR],
		};
	}

	const envDirs = [env.UNIDBG_HOME, env.UNIDBG_ROOT, env.UNIDBG_DIR];
	for (const envDir of envDirs) {
		if (envDir) {
			const res = assessDir(envDir);
			if (res) return res;
		}
	}

	// 2. Assess cwd directly if it is a unidbg dir (e.g. custom-named checkout)
	if (isUnidbgDir(cwd)) {
		const res = assessDir(cwd);
		if (res) return res;
	}

	// 2. Local workspace and sibling paths
	const localDirs = [
		path.join(cwd, "unidbg"),
		path.resolve(cwd, "..", "unidbg"),
	];
	for (const d of localDirs) {
		const res = assessDir(d);
		if (res) return res;
	}
	// 3. User profile / standard install locations
	const userDirs = [
		path.join(homedir, "unidbg"),
		path.join(homedir, ".unidbg"),
		"/opt/unidbg",
		"/usr/local/share/unidbg",
		"C:\\unidbg",
		"D:\\unidbg",
	];
	if (env.ProgramFiles) {
		userDirs.push(path.join(env.ProgramFiles, "unidbg"));
	}
	for (const d of userDirs) {
		const res = assessDir(d);
		if (res) return res;
	}

	// 4. Maven local repository
	const m2Jar = scanMavenRepo(homedir);
	if (m2Jar) {
		return {
			foundPath: m2Jar,
			unidbgDir: path.dirname(m2Jar),
			hasPom: false,
			hasWrapper: false,
			built: true,
			jars: [m2Jar],
		};
	}

	return {
		foundPath: null,
		hasPom: false,
		hasWrapper: false,
		built: false,
		jars: [],
	};
}

export function locateUnidbg(options: LocateUnidbgOptions = {}): string | null {
	return inspectUnidbg(options).foundPath;
}
