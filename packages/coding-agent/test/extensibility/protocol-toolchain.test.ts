import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { encodeArchive } from "@reverse/utils/ar";
import { checkReverseTools } from "../../src/cli/setup-reverse";
import {
	checkKaitaiVersionCompatibility,
	computeCapaRulesManifest,
	evaluateProtocolToolActionDependencies,
	installCapa,
	installKaitaiCompiler,
	installKaitaiStructVenv,
	probeCapaRequirement,
	probeKaitaiCompilerRequirement,
	probeKaitaiStructRequirement,
	resolveCapa,
	resolveKaitaiCompiler,
	resolveKaitaiStructPythonDetailed,
	resolveKaitaiToolchainReadiness,
	validateCapaRulesDir,
} from "../../src/extensibility/protocol-toolchain";
import { getReverseInstallPlan, installReverseItem } from "../../src/extensibility/reverse-tool-install";
import type { SkillRequirementWhich } from "../../src/extensibility/skill-requirements";

const isWindows = process.platform === "win32";

const VALID_CAPA_RULE_YML = [
	"rule:",
	"  meta:",
	"    name: encrypt data using AES",
	"    namespace: data-manipulation/encryption/aes",
	"    scopes:",
	"      static: function",
	"      dynamic: span of calls",
	"  features:",
	"    - or:",
	"      - number: 0x637c777b",
	"",
].join("\n");

function writeExecutableScript(filePath: string, body: string): void {
	fs.mkdirSync(path.dirname(filePath), { recursive: true });
	fs.writeFileSync(filePath, body, { mode: 0o755 });
	if (!isWindows) {
		fs.chmodSync(filePath, 0o755);
	}
}

function sha256Hex(bytes: Uint8Array): string {
	return crypto.createHash("sha256").update(bytes).digest("hex");
}

describe("protocol-toolchain probes, installers, and action-scoped dependency evaluation", () => {
	let tempDir: string;

	beforeEach(async () => {
		tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "rev-protocol-toolchain-"));
	});

	afterEach(async () => {
		try {
			await fs.promises.rm(tempDir, { recursive: true, force: true });
		} catch {}
	});

	it.skipIf(isWindows)(
		"checks kaitai-struct-compiler truthfully: binary existence alone is insufficient without Java, >=0.9 version, and --read-pos",
		() => {
			const emptyAgentDir = path.join(tempDir, "empty-agent");
			const binDir = path.join(tempDir, "bin");
			const javaBin = path.join(tempDir, "jdk", "bin", "java");
			writeExecutableScript(javaBin, "#!/bin/sh\necho 'openjdk version \"21.0.2\"' >&2\nexit 0\n");

			// 1. Compiler script exists, but Java is missing
			const kscPath = path.join(binDir, "kaitai-struct-compiler");
			writeExecutableScript(
				kscPath,
				'#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'kaitai-struct-compiler 0.11\'; exit 0; fi\nif [ "$1" = "--help" ]; then echo \'Usage: kaitai-struct-compiler --read-pos\'; exit 0; fi\nexit 0\n',
			);
			const noJavaWhich: SkillRequirementWhich = cmd => (cmd === "kaitai-struct-compiler" ? kscPath : null);
			const noJavaRes = resolveKaitaiCompiler({
				which: noJavaWhich,
				agentDir: emptyAgentDir,
				platform: "darwin",
				env: { PATH: binDir, HOME: tempDir },
			});
			expect(noJavaRes.available).toBe(false);
			expect(noJavaRes.binaryFound).toBe(true);
			expect(noJavaRes.javaReady).toBe(false);
			expect(noJavaRes.secondaryMissing).toContain("java");

			// 2. Stub binary that exits 0 without reporting kaitai-struct-compiler version -> rejected
			const stubKsc = path.join(binDir, "stub-ksc");
			writeExecutableScript(stubKsc, "#!/bin/sh\nexit 0\n");
			const stubWhich: SkillRequirementWhich = cmd => {
				if (cmd === "kaitai-struct-compiler") return stubKsc;
				if (cmd === "java") return javaBin;
				return null;
			};
			const stubRes = resolveKaitaiCompiler({
				which: stubWhich,
				agentDir: emptyAgentDir,
				platform: "darwin",
				env: { PATH: binDir, HOME: tempDir },
			});
			expect(stubRes.available).toBe(false);
			expect(stubRes.compatible).toBe(false);
			expect(
				probeKaitaiCompilerRequirement({
					which: stubWhich,
					agentDir: emptyAgentDir,
					platform: "darwin",
					env: { PATH: binDir, HOME: tempDir },
				}),
			).toMatchObject({
				path: stubKsc,
				secondaryMissing: ["kaitai-compiler-compatible"],
			});

			// 3. Compiler lacking --read-pos -> rejected
			const noReadPosKsc = path.join(binDir, "noreadpos-ksc");
			writeExecutableScript(
				noReadPosKsc,
				'#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'kaitai-struct-compiler 0.10\'; exit 0; fi\nif [ "$1" = "--help" ]; then echo \'Usage: kaitai-struct-compiler -t python\'; exit 0; fi\nexit 0\n',
			);
			const noReadPosWhich: SkillRequirementWhich = cmd => {
				if (cmd === "kaitai-struct-compiler") return noReadPosKsc;
				if (cmd === "java") return javaBin;
				return null;
			};
			const noReadPosRes = resolveKaitaiCompiler({
				which: noReadPosWhich,
				agentDir: emptyAgentDir,
				platform: "darwin",
				env: { PATH: binDir, HOME: tempDir },
			});
			expect(noReadPosRes.available).toBe(false);
			expect(noReadPosRes.supportsReadPos).toBe(false);

			// 4. Genuine compatible compiler with Java + --read-pos -> available
			const validWhich: SkillRequirementWhich = cmd => {
				if (cmd === "kaitai-struct-compiler") return kscPath;
				if (cmd === "java") return javaBin;
				return null;
			};
			const validRes = resolveKaitaiCompiler({
				which: validWhich,
				agentDir: emptyAgentDir,
				platform: "darwin",
				env: { PATH: binDir, HOME: tempDir },
			});
			expect(validRes.available).toBe(true);
			expect(validRes.compatible).toBe(true);
			expect(validRes.supportsReadPos).toBe(true);
			expect(validRes.version).toBe("0.11");
		},
	);

	it.skipIf(isWindows)(
		"probes kaitaistruct strictly in the actual selected Python environment and enforces compiler/runtime version compatibility",
		() => {
			const pyWithoutKaitai = path.join(tempDir, "py-no-ks", "bin", "python3");
			writeExecutableScript(
				pyWithoutKaitai,
				[
					"#!/bin/sh",
					'for arg in "$@"; do',
					'  case "$arg" in',
					"    *KAITAI_MISSING_MODULE*) echo \"KAITAI_MISSING_MODULE:No module named 'kaitaistruct'\"; exit 42 ;;",
					"  esac",
					"done",
					"exit 0",
					"",
				].join("\n"),
			);

			const pyWithKaitai010 = path.join(tempDir, "py-ks-010", "bin", "python3");
			writeExecutableScript(
				pyWithKaitai010,
				[
					"#!/bin/sh",
					'for arg in "$@"; do',
					'  case "$arg" in',
					"    *KAITAI_OK*) printf 'KAITAI_OK\\n0.10\\n0.10\\n/site-packages/kaitaistruct.py\\n'; exit 0 ;;",
					"  esac",
					"done",
					"exit 0",
					"",
				].join("\n"),
			);

			const pyWithKaitai011 = path.join(tempDir, "py-ks-011", "bin", "python");
			writeExecutableScript(
				pyWithKaitai011,
				[
					"#!/bin/sh",
					'for arg in "$@"; do',
					'  case "$arg" in',
					"    *KAITAI_OK*) printf 'KAITAI_OK\\n0.11\\n0.11\\n/venv/site-packages/kaitaistruct.py\\n'; exit 0 ;;",
					"  esac",
					"done",
					"exit 0",
					"",
				].join("\n"),
			);

			// Even when managed kaitaistruct-venv exists, explicitly selecting pyWithoutKaitai MUST probe ONLY pyWithoutKaitai
			const managedVenvBin = path.join(tempDir, "agent", "tools", "kaitaistruct-venv", "bin", "python");
			fs.mkdirSync(path.dirname(managedVenvBin), { recursive: true });
			fs.copyFileSync(pyWithKaitai011, managedVenvBin);
			fs.chmodSync(managedVenvBin, 0o755);

			const selectedMissing = resolveKaitaiStructPythonDetailed({
				pythonPath: pyWithoutKaitai,
				agentDir: path.join(tempDir, "agent"),
				platform: "darwin",
				env: { PATH: "", HOME: tempDir },
			});
			expect(selectedMissing.available).toBe(false);
			expect(selectedMissing.status).toBe("missing_module");
			expect(selectedMissing.checkedCandidates).toEqual([path.resolve(pyWithoutKaitai)]);

			// Default resolution picks managed kaitaistruct-venv 0.11
			const managedFound = resolveKaitaiStructPythonDetailed({
				agentDir: path.join(tempDir, "agent"),
				platform: "darwin",
				which: () => pyWithoutKaitai,
				env: { PATH: "", HOME: tempDir },
			});
			expect(managedFound.available).toBe(true);
			expect(managedFound.pythonBin).toBe(managedVenvBin);
			expect(managedFound.version).toBe("0.11");

			// Compiler 0.11 + Runtime 0.10 must fail cross-version compatibility
			expect(checkKaitaiVersionCompatibility("0.11", "0.10", "0.10").compatible).toBe(false);
			expect(checkKaitaiVersionCompatibility("0.11", "0.11", "0.11").compatible).toBe(true);
			expect(checkKaitaiVersionCompatibility("0.10", "0.11", "0.11").compatible).toBe(true);

			const javaBin = path.join(tempDir, "jdk", "bin", "java");
			writeExecutableScript(javaBin, "#!/bin/sh\nexit 0\n");
			const ksc011 = path.join(tempDir, "bin", "kaitai-struct-compiler");
			writeExecutableScript(
				ksc011,
				"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'kaitai-struct-compiler 0.11'; exit 0; fi\necho '--read-pos'\nexit 0\n",
			);
			const which011: SkillRequirementWhich = cmd => {
				if (cmd === "kaitai-struct-compiler") return ksc011;
				if (cmd === "java") return javaBin;
				if (cmd === "python3") return pyWithKaitai010;
				return null;
			};

			const mismatchedReadiness = resolveKaitaiToolchainReadiness({
				pythonPath: pyWithKaitai010,
				which: which011,
				agentDir: path.join(tempDir, "empty-agent"),
				platform: "darwin",
				env: { PATH: path.dirname(ksc011), HOME: tempDir },
			});
			expect(mismatchedReadiness.compiler.available).toBe(true);
			expect(mismatchedReadiness.runtime.available).toBe(true);
			expect(mismatchedReadiness.compatible).toBe(false);
			expect(mismatchedReadiness.ready).toBe(false);
			expect(mismatchedReadiness.missingRequirements).toContain("kaitai-version-compatible");

			const probeMismatch = probeKaitaiStructRequirement({
				pythonPath: pyWithKaitai010,
				which: which011,
				agentDir: path.join(tempDir, "empty-agent"),
				platform: "darwin",
				env: { PATH: path.dirname(ksc011), HOME: tempDir },
			});
			expect(probeMismatch?.secondaryMissing).toContain("kaitai-version-compatible");
		},
	);

	it.skipIf(isWindows)(
		"checks capa engine + rules truthfully: capa binary without valid rules is NOT marked installed",
		() => {
			const agentDir = path.join(tempDir, "agent-capa");
			const binDir = path.join(tempDir, "capa-only-bin");
			const capaBin = path.join(binDir, "capa");
			writeExecutableScript(
				capaBin,
				'#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'capa v10.0.0\'; exit 0; fi\nexit 0\n',
			);

			const whichCapaOnly: SkillRequirementWhich = cmd => {
				if (cmd === "capa") return capaBin;
				if (cmd === "strings") return "/usr/bin/strings";
				if (cmd === "file") return "/usr/bin/file";
				return null;
			};

			// 1. Binary works, but no rules exist -> available: false, secondaryMissing: ["capa-rules"]
			const noRules = resolveCapa({ which: whichCapaOnly, agentDir, platform: "darwin", env: { PATH: binDir } });
			expect(noRules.engineReady).toBe(true);
			expect(noRules.rulesReady).toBe(false);
			expect(noRules.available).toBe(false);
			expect(noRules.secondaryMissing).toEqual(["capa-rules"]);
			expect(
				probeCapaRequirement({ which: whichCapaOnly, agentDir, platform: "darwin", env: { PATH: binDir } }),
			).toMatchObject({
				path: capaBin,
				secondaryMissing: ["capa-rules"],
			});

			const reportWithoutRules = checkReverseTools({
				platform: "darwin",
				which: whichCapaOnly,
				agentDir,
				env: { PATH: binDir },
			});
			const capaStatusWithoutRules = reportWithoutRules.tools.find(t => t.id === "capa");
			expect(capaStatusWithoutRules?.status).toBe("missing");
			expect(capaStatusWithoutRules?.secondaryMissing).toContain("capa-rules");

			// 2. Non-capa YAML files in rules dir -> still rejected
			const bogusRulesDir = path.join(tempDir, "bogus-rules");
			fs.mkdirSync(bogusRulesDir, { recursive: true });
			fs.writeFileSync(path.join(bogusRulesDir, "not-a-capa-rule.yml"), "name: hello\nitems:\n  - a\n");
			expect(validateCapaRulesDir(bogusRulesDir).valid).toBe(false);

			// 3. Valid capa rule file -> rulesReady: true, deterministic manifest hash, tool status installed
			const validRulesDir = path.join(agentDir, "tools", "capa", "rules", "crypto");
			fs.mkdirSync(validRulesDir, { recursive: true });
			fs.writeFileSync(path.join(validRulesDir, "aes.yml"), VALID_CAPA_RULE_YML);

			const manifest = computeCapaRulesManifest(path.join(agentDir, "tools", "capa", "rules"));
			expect(manifest).not.toBeNull();
			expect(manifest?.ruleCount).toBe(1);
			expect(manifest?.manifestSha256).toMatch(/^[0-9a-f]{64}$/);

			const withRules = resolveCapa({ which: whichCapaOnly, agentDir, platform: "darwin", env: { PATH: binDir } });
			expect(withRules.available).toBe(true);
			expect(withRules.engineReady).toBe(true);
			expect(withRules.rulesReady).toBe(true);
			expect(withRules.ruleCount).toBe(1);

			const reportWithRules = checkReverseTools({
				platform: "darwin",
				which: whichCapaOnly,
				agentDir,
				env: { PATH: binDir },
			});
			expect(reportWithRules.tools.find(t => t.id === "capa")?.status).toBe("installed");

			// 4. Deep nested rules (depth 6 > old limit 4) and companion .yml files are included in full closure
			const deepRuleDir = path.join(agentDir, "tools", "capa", "rules", "a", "b", "c", "d", "e", "f");
			fs.mkdirSync(deepRuleDir, { recursive: true });
			fs.writeFileSync(path.join(deepRuleDir, "deep-aes.yml"), VALID_CAPA_RULE_YML);
			fs.writeFileSync(
				path.join(validRulesDir, "custom-formatted.yaml"),
				"# custom rule loaded by capa\nrule: # inline comment\n  meta: # meta\n    name: custom\n  features: # features\n    - number: 1\n",
			);

			const rulesRoot = path.join(agentDir, "tools", "capa", "rules");
			const fullManifest = computeCapaRulesManifest(rulesRoot);
			expect(fullManifest).not.toBeNull();
			expect(fullManifest?.ruleCount).toBe(3);
			expect(fullManifest?.files.map(f => f.path)).toEqual([
				"a/b/c/d/e/f/deep-aes.yml",
				"crypto/aes.yml",
				"crypto/custom-formatted.yaml",
			]);

			// 5. Depth / file-count / byte-size overflow fails closed rather than silently returning partial manifest
			const depthOverflowCheck = validateCapaRulesDir(rulesRoot, { maxDepth: 3 });
			expect(depthOverflowCheck.valid).toBe(false);
			expect(depthOverflowCheck.error).toContain("exceeds maximum nesting depth");
			expect(computeCapaRulesManifest(rulesRoot, { maxDepth: 3 })).toBeNull();

			const fileCountOverflowCheck = validateCapaRulesDir(rulesRoot, { maxFiles: 2 });
			expect(fileCountOverflowCheck.valid).toBe(false);
			expect(fileCountOverflowCheck.error).toContain("exceeds maximum rule file count");
			expect(computeCapaRulesManifest(rulesRoot, { maxFiles: 2 })).toBeNull();

			const byteOverflowCheck = validateCapaRulesDir(rulesRoot, { maxFileBytes: 10 });
			expect(byteOverflowCheck.valid).toBe(false);
			expect(byteOverflowCheck.error).toContain("exceeds per-file limit");
			expect(computeCapaRulesManifest(rulesRoot, { maxFileBytes: 10 })).toBeNull();

			// 6. Symlinks inside rulesDir or as rulesDir root are rejected rather than silently skipped
			const symlinkRulesRoot = path.join(tempDir, "symlink-rules-root");
			fs.symlinkSync(rulesRoot, symlinkRulesRoot);
			expect(validateCapaRulesDir(symlinkRulesRoot).valid).toBe(false);
			expect(computeCapaRulesManifest(symlinkRulesRoot)).toBeNull();

			const outsideRule = path.join(tempDir, "outside-rule.yml");
			fs.writeFileSync(outsideRule, VALID_CAPA_RULE_YML);
			const innerSymlink = path.join(validRulesDir, "linked-rule.yml");
			fs.symlinkSync(outsideRule, innerSymlink);
			const symlinkInsideCheck = validateCapaRulesDir(rulesRoot);
			expect(symlinkInsideCheck.valid).toBe(false);
			expect(symlinkInsideCheck.error).toContain("Symbolic link is not allowed");
			expect(computeCapaRulesManifest(rulesRoot)).toBeNull();
			fs.unlinkSync(innerSymlink);
		},
	);

	it.skipIf(isWindows)(
		"plans Java prerequisite, enforces SHA-256 even with custom fetch, executes staged installs, and rolls back on failure",
		async () => {
			const agentDir = path.join(tempDir, "managed-agent");
			const jdkBinDir = path.join(tempDir, "fake-jdk", "bin");
			const javaBin = path.join(jdkBinDir, "java");
			writeExecutableScript(javaBin, "#!/bin/sh\necho 'openjdk version \"21.0.2\"' >&2\nexit 0\n");

			// 1. Planning kaitai-struct-compiler without Java and without package manager fails truthfully
			const missingJavaReport = checkReverseTools({
				platform: "darwin",
				agentDir,
				which: () => null,
				env: { PATH: "" },
			});
			const kscMissingStatus = missingJavaReport.tools.find(t => t.id === "kaitai-struct-compiler")!;
			const blockedPlan = getReverseInstallPlan(kscMissingStatus, {
				report: missingJavaReport,
				platform: "darwin",
				agentDir,
				which: () => null,
				env: { PATH: "" },
			});
			expect(blockedPlan.canInstall).toBe(false);
			expect(blockedPlan.missingDependencies).toContain("java");

			// 2. Planning kaitai-struct-compiler without Java when brew is present orders java before kaitai-struct-compiler
			const brewOnlyWhich: SkillRequirementWhich = cmd => (cmd === "brew" ? "/opt/homebrew/bin/brew" : null);
			const brewReport = checkReverseTools({
				platform: "darwin",
				agentDir,
				which: brewOnlyWhich,
				env: { PATH: "/opt/homebrew/bin" },
			});
			const orderedPlan = getReverseInstallPlan(
				brewReport.tools.find(t => t.id === "kaitai-struct-compiler")!,
				{
					report: brewReport,
					platform: "darwin",
					agentDir,
					which: brewOnlyWhich,
					env: { PATH: "/opt/homebrew/bin" },
				},
			);
			expect(orderedPlan.canInstall).toBe(true);
			expect(orderedPlan.steps.map(s => s.id)).toEqual(["java", "kaitai-struct-compiler"]);
			expect(orderedPlan.steps[0].isDependency).toBe(true);

			// 3. Staged installKaitaiCompiler enforces SHA-256 even when fetch is injected
			const kscLauncherScript =
				'#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'kaitai-struct-compiler 0.11\'; exit 0; fi\nif [ "$1" = "--help" ]; then echo \'Usage: kaitai-struct-compiler --read-pos\'; exit 0; fi\nexit 0\n';
			const kscZipBytes = await encodeArchive("zip", [
				["kaitai-struct-compiler-0.11/bin/kaitai-struct-compiler", kscLauncherScript],
				["kaitai-struct-compiler-0.11/lib/kaitai-struct-compiler-0.11.jar", Buffer.from([0x50, 0x4b, 0x03, 0x04])],
			]);

			// Without matching expectedSha256, production pinned digest check rejects synthetic archive
			const kscDigestMismatch = await installKaitaiCompiler({
				agentDir,
				platform: "darwin",
				which: cmd => (cmd === "java" ? javaBin : null),
				env: { PATH: jdkBinDir },
				fetch: (async () => new Response(kscZipBytes, { status: 200 })) as unknown as typeof globalThis.fetch,
			});
			expect(kscDigestMismatch.success).toBe(false);
			expect(kscDigestMismatch.error).toContain("Checksum verification failed");

			// With explicit fixture digest, staged install succeeds and verifies --read-pos
			const kscInstallRes = await installKaitaiCompiler({
				agentDir,
				platform: "darwin",
				which: cmd => (cmd === "java" ? javaBin : null),
				env: { PATH: jdkBinDir },
				expectedSha256: sha256Hex(kscZipBytes),
				fetch: (async () => new Response(kscZipBytes, { status: 200 })) as unknown as typeof globalThis.fetch,
			});
			expect(kscInstallRes.success).toBe(true);
			expect(kscInstallRes.version).toBe("0.11");
			expect(
				fs.existsSync(path.join(agentDir, "tools", "kaitai-struct-compiler", "bin", "kaitai-struct-compiler")),
			).toBe(true);

			// Malformed archive without bin/lib leaves no partial directory
			const brokenZipBytes = await encodeArchive("zip", [["broken/readme.txt", "no bin or jar"]]);
			const failedInstall = await installKaitaiCompiler({
				agentDir: path.join(tempDir, "rollback-agent"),
				platform: "darwin",
				which: cmd => (cmd === "java" ? javaBin : null),
				env: { PATH: jdkBinDir },
				expectedSha256: sha256Hex(brokenZipBytes),
				fetch: (async () => new Response(brokenZipBytes, { status: 200 })) as unknown as typeof globalThis.fetch,
			});
			expect(failedInstall.success).toBe(false);
			expect(fs.existsSync(path.join(tempDir, "rollback-agent", "tools", "kaitai-struct-compiler"))).toBe(false);

			// 4. Staged installCapa enforces SHA-256 even when fetch is injected, then installs engine + rules
			const rulesTarGz = await encodeArchive("tar.gz", [
				["capa-rules-10.0.0/data-manipulation/encryption/aes/encrypt-aes.yml", VALID_CAPA_RULE_YML],
			]);
			const capaZip = await encodeArchive("zip", [
				["capa", '#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'capa v10.0.0\'; exit 0; fi\nexit 0\n'],
			]);
			const mockCapaFetch = (async (input: string | URL | Request) => {
				const url = String(input);
				if (url.includes("capa-rules")) {
					return new Response(rulesTarGz, { status: 200 });
				}
				return new Response(capaZip, { status: 200 });
			}) as unknown as typeof globalThis.fetch;

			const capaDigestMismatch = await installCapa({
				agentDir,
				platform: "darwin",
				env: { PATH: "" },
				which: () => null,
				fetch: mockCapaFetch,
			});
			expect(capaDigestMismatch.success).toBe(false);
			expect(capaDigestMismatch.error).toContain("Checksum verification failed");

			const capaInstallRes = await installCapa({
				agentDir,
				platform: "darwin",
				env: { PATH: "" },
				which: () => null,
				expectedEngineSha256: sha256Hex(capaZip),
				expectedRulesSha256: sha256Hex(rulesTarGz),
				fetch: mockCapaFetch,
			});
			expect(capaInstallRes.success).toBe(true);
			expect(capaInstallRes.ruleCount).toBe(1);
			expect(capaInstallRes.rulesSha256).toMatch(/^[0-9a-f]{64}$/);

			// 5. installKaitaiStructVenv provisions managed venv and verifies import
			const hostPython = path.join(tempDir, "host-py", "bin", "python3");
			writeExecutableScript(hostPython, "#!/bin/sh\nexit 0\n");
			const ksRes = await installKaitaiStructVenv({
				agentDir,
				platform: "darwin",
				which: cmd => (cmd === "python3" ? hostPython : null),
				env: { PATH: path.dirname(hostPython) },
				executor: async argv => {
					if (argv[1] === "-m" && argv[2] === "venv") {
						const targetVenv = argv[3];
						writeExecutableScript(
							path.join(targetVenv, "bin", "python"),
							"#!/bin/sh\nprintf 'KAITAI_OK\\n0.11\\n0.11\\n/venv/kaitaistruct.py\\n'\nexit 0\n",
						);
					}
					return { exitCode: 0, stdout: "ok", stderr: "" };
				},
			});
			expect(ksRes.success).toBe(true);
			expect(ksRes.version).toBe("0.11");

			// 6. installReverseItem rejects tampered plan argv even on managed capa step
			const capaStatus = missingJavaReport.tools.find(t => t.id === "capa")!;
			const tamperedRes = await installReverseItem(capaStatus, {
				agentDir,
				platform: "darwin",
				plan: {
					item: capaStatus,
					canInstall: true,
					missingDependencies: [],
					steps: [
						{
							id: "capa",
							name: "capa",
							kind: "cli",
							packageManager: "managed",
							installer: "capa",
							command: "sh -c evil",
							argv: ["sh", "-c", "evil"],
						},
					],
				},
			});
			expect(tamperedRes.success).toBe(false);
			expect(tamperedRes.message).toContain("Untrusted installation command");
		},
	);

	it("evaluates action-scoped dependencies without blanket missing-dependency blocks for offline imports or status", () => {
		const emptyWhich: SkillRequirementWhich = () => null;
		const emptyAgentDir = path.join(tempDir, "empty-agent");
		const baseDeps = {
			which: emptyWhich,
			agentDir: emptyAgentDir,
			platform: "darwin" as const,
			env: { PATH: "", HOME: tempDir },
		};

		for (const toolName of ["format_inspect", "capability_inspect", "app_experiment"] as const) {
			const st = evaluateProtocolToolActionDependencies({ ...baseDeps, toolName, action: "status" });
			expect(st.ready).toBe(true);
			expect(st.missingTools).toEqual([]);
		}

		expect(
			evaluateProtocolToolActionDependencies({
				...baseDeps,
				toolName: "app_experiment",
				action: "network_import",
				captureFormat: "har",
				capturePath: "traffic.har",
			}).ready,
		).toBe(true);
		expect(
			evaluateProtocolToolActionDependencies({
				...baseDeps,
				toolName: "app_experiment",
				action: "network_compare",
			}).ready,
		).toBe(true);
		expect(
			evaluateProtocolToolActionDependencies({
				...baseDeps,
				toolName: "app_experiment",
				action: "network_replay",
			}).ready,
		).toBe(true);

		const mitmImport = evaluateProtocolToolActionDependencies({
			...baseDeps,
			toolName: "app_experiment",
			action: "network_import",
			captureFormat: "mitm",
		});
		expect(mitmImport.ready).toBe(false);
		expect(mitmImport.missingTools).toEqual(["mitmproxy"]);

		expect(
			evaluateProtocolToolActionDependencies({
				...baseDeps,
				toolName: "capability_inspect",
				action: "import",
			}).ready,
		).toBe(true);
		const capaDetect = evaluateProtocolToolActionDependencies({
			...baseDeps,
			toolName: "capability_inspect",
			action: "detect",
		});
		expect(capaDetect.ready).toBe(false);
		expect(capaDetect.missingTools).toContain("capa");

		const fmtCompile = evaluateProtocolToolActionDependencies({
			...baseDeps,
			toolName: "format_inspect",
			action: "compile",
		});
		expect(fmtCompile.ready).toBe(false);
		expect(fmtCompile.missingTools).toEqual(["java", "kaitai-struct-compiler"]);

		const fmtParse = evaluateProtocolToolActionDependencies({
			...baseDeps,
			toolName: "format_inspect",
			action: "parse",
		});
		expect(fmtParse.ready).toBe(false);
		expect(fmtParse.missingTools).toEqual(["python", "kaitaistruct"]);
	});

	it.skipIf(isWindows)(
		"never leaks ambient REVERSE_TOOL_PATHS or real user agentDir when mocked which or isolated agentDir is used",
		() => {
			const fakeHomeAgent = path.join(tempDir, "fake-home-agent");
			const fakeKscBin = path.join(
				fakeHomeAgent,
				"tools",
				"kaitai-struct-compiler",
				"bin",
				"kaitai-struct-compiler",
			);
			const fakeCapaBin = path.join(fakeHomeAgent, "tools", "capa", "bin", "capa");
			const fakeCapaRule = path.join(fakeHomeAgent, "tools", "capa", "rules", "aes.yml");
			writeExecutableScript(
				fakeKscBin,
				"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'kaitai-struct-compiler 0.11'; exit 0; fi\necho '--read-pos'\nexit 0\n",
			);
			writeExecutableScript(
				fakeCapaBin,
				'#!/bin/sh\nif [ "$1" = "--version" ]; then echo \'capa v10.0.0\'; exit 0; fi\nexit 0\n',
			);
			fs.mkdirSync(path.dirname(fakeCapaRule), { recursive: true });
			fs.writeFileSync(fakeCapaRule, VALID_CAPA_RULE_YML);

			const prevToolPaths = process.env.REVERSE_TOOL_PATHS;
			try {
				process.env.REVERSE_TOOL_PATHS = [path.dirname(fakeKscBin), path.dirname(fakeCapaBin)].join(path.delimiter);
				const emptyWhich: SkillRequirementWhich = () => null;

				// Mocked which without explicit env/agentDir must NOT read ambient REVERSE_TOOL_PATHS or getAgentDir()
				expect(resolveKaitaiCompiler({ which: emptyWhich, platform: "darwin" }).available).toBe(false);
				expect(resolveCapa({ which: emptyWhich, platform: "darwin" }).available).toBe(false);
				expect(resolveKaitaiStructPythonDetailed({ which: emptyWhich, platform: "darwin" }).available).toBe(false);

				// Isolated agentDir must NOT inherit ambient REVERSE_TOOL_PATHS
				const emptyAgent = path.join(tempDir, "clean-agent");
				expect(
					resolveKaitaiCompiler({ which: emptyWhich, agentDir: emptyAgent, platform: "darwin" }).available,
				).toBe(false);
				expect(resolveCapa({ which: emptyWhich, agentDir: emptyAgent, platform: "darwin" }).available).toBe(false);
			} finally {
				if (prevToolPaths !== undefined) {
					process.env.REVERSE_TOOL_PATHS = prevToolPaths;
				} else {
					delete process.env.REVERSE_TOOL_PATHS;
				}
			}
		},
	);
});
