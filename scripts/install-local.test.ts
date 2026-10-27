import type { Subprocess } from "bun";
import { describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	parseCliArgs,
	resolveBinaryName,
	resolveTargetBinDir,
	runLocalInstall,
	validateBinaryVersionOutput,
} from "./install-local";

describe("install-local: version validation", () => {
	test("accepts valid reverse version output formats", () => {
		expect(validateBinaryVersionOutput("reverse/18.11.2\n")).toEqual({ ok: true, version: "18.11.2" });
		expect(validateBinaryVersionOutput("reverse v18.11.2\n")).toEqual({ ok: true, version: "18.11.2" });
		expect(validateBinaryVersionOutput("reverse 1.0.0-rc.1")).toEqual({ ok: true, version: "1.0.0-rc.1" });
		expect(validateBinaryVersionOutput("reverse/0.1.0\nextra info\n")).toEqual({ ok: true, version: "0.1.0" });
	});

	test("rejects arbitrary and non-reverse binary outputs", () => {
		expect(validateBinaryVersionOutput("other-agent/18.11.2").ok).toBe(false);
		expect(validateBinaryVersionOutput("node v20.10.0").ok).toBe(false);
		expect(validateBinaryVersionOutput("GNU bash, version 5.2").ok).toBe(false);
		expect(validateBinaryVersionOutput("").ok).toBe(false);
		expect(validateBinaryVersionOutput("error: unknown flag").ok).toBe(false);
	});
});

describe("install-local: path resolution", () => {
	test("resolves custom --bin-dir directly without touching home", () => {
		const resolved = resolveTargetBinDir({ binDir: "/tmp/custom-bin" });
		expect(resolved).toBe(path.resolve("/tmp/custom-bin"));
	});

	test("resolves custom --prefix to <prefix>/bin", () => {
		const resolved = resolveTargetBinDir({ prefix: "/opt/reverse" });
		expect(resolved).toBe(path.resolve("/opt/reverse/bin"));
	});

	test("resolves platform default when neither binDir nor prefix provided", () => {
		const unixDir = resolveTargetBinDir({ platform: "darwin" });
		expect(unixDir).toBe(path.join(os.homedir(), ".local", "bin"));

		const linuxDir = resolveTargetBinDir({ platform: "linux" });
		expect(linuxDir).toBe(path.join(os.homedir(), ".local", "bin"));
	});

	test("resolves binary name by platform", () => {
		expect(resolveBinaryName("win32")).toBe("reverse.exe");
		expect(resolveBinaryName("darwin")).toBe("reverse");
		expect(resolveBinaryName("linux")).toBe("reverse");
	});
});

describe("install-local: cli argument parsing", () => {
	test("parses flags correctly", () => {
		const parsed = parseCliArgs(["--binary=/tmp/rev", "--bin-dir", "/tmp/bin", "--dry-run", "--no-backup"]);
		expect(parsed.binary).toBe("/tmp/rev");
		expect(parsed.binDir).toBe("/tmp/bin");
		expect(parsed.dryRun).toBe(true);
		expect(parsed.backup).toBe(false);
	});
});

describe("install-local: installation lifecycle", () => {
	test("rejects a binary that fails the reverse version check", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-test-"));
		const fakeBinary = path.join(tempDir, "fake-tool");
		const destDir = path.join(tempDir, "dest");

		try {
			await Bun.write(fakeBinary, "#!/bin/sh\necho 'not-reverse 1.0.0'\n");
			await fs.chmod(fakeBinary, 0o755);

			const result = await runLocalInstall({
				binary: fakeBinary,
				binDir: destDir,
				platform: "darwin",
			});

			expect(result.success).toBe(false);
			expect(result.message).toContain("validation failed");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("installs valid binary, creates backup on re-install, validates via --check, and uninstalls cleanly", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-lifecycle-"));
		const sourceBinary = path.join(tempDir, "mock-reverse");
		const destDir = path.join(tempDir, "bin");
		const targetBinary = path.join(destDir, "reverse");

		try {
			// 1. Create a valid mock reverse binary
			await Bun.write(
				sourceBinary,
				"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'reverse/18.11.2'; exit 0; fi\necho 'running reverse'\n",
			);
			await fs.chmod(sourceBinary, 0o755);

			// 2. Dry run does not copy files
			const dryResult = await runLocalInstall({
				binary: sourceBinary,
				binDir: destDir,
				dryRun: true,
				platform: "darwin",
			});
			expect(dryResult.success).toBe(true);
			expect(await fs.exists(targetBinary)).toBe(false);

			// 3. Real install copies and sets executable
			const installResult = await runLocalInstall({
				binary: sourceBinary,
				binDir: destDir,
				platform: "darwin",
			});
			expect(installResult.success).toBe(true);
			expect(await fs.exists(targetBinary)).toBe(true);
			const stat = await fs.stat(targetBinary);
			expect(stat.mode & 0o111).not.toBe(0); // executable

			// 4. Verify via --check
			const checkResult = await runLocalInstall({
				binDir: destDir,
				check: true,
				platform: "darwin",
			});
			expect(checkResult.success).toBe(true);
			expect(checkResult.version).toBe("18.11.2");

			// 5. Re-install creates backup file
			const reinstallResult = await runLocalInstall({
				binary: sourceBinary,
				binDir: destDir,
				platform: "darwin",
			});
			expect(reinstallResult.success).toBe(true);
			expect(reinstallResult.backupPath).toBeDefined();
			expect(await fs.exists(reinstallResult.backupPath!)).toBe(true);

			// 6. Uninstall removes the target binary
			const uninstallResult = await runLocalInstall({
				binDir: destDir,
				uninstall: true,
				platform: "darwin",
			});
			expect(uninstallResult.success).toBe(true);
			expect(await fs.exists(targetBinary)).toBe(false);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("rejects hanging binary via timeout", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-hang-"));
		const hangingBinary = path.join(tempDir, "hanging-tool");
		const destDir = path.join(tempDir, "dest");

		try {
			await Bun.write(hangingBinary, "#!/bin/sh\nsleep 10\n");
			await fs.chmod(hangingBinary, 0o755);

			const result = await runLocalInstall({
				binary: hangingBinary,
				binDir: destDir,
				verifyTimeoutMs: 200,
				platform: "darwin",
			});

			expect(result.success).toBe(false);
			expect(result.message).toContain("timed out");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("handles unbounded output without crashing and rejects invalid signature", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-flood-"));
		const floodBinary = path.join(tempDir, "flood-tool");
		const destDir = path.join(tempDir, "dest");

		try {
			await Bun.write(floodBinary, "#!/bin/sh\nhead -c 131072 /dev/zero | tr '\\0' 'x'\n");
			await fs.chmod(floodBinary, 0o755);

			const result = await runLocalInstall({
				binary: floodBinary,
				binDir: destDir,
				platform: "darwin",
			});

			expect(result.success).toBe(false);
			expect(result.message).toContain("validation failed");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("preserves prior backups on repeated reinstalls without overwriting", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-backup-"));
		const sourceBinary = path.join(tempDir, "mock-reverse");
		const destDir = path.join(tempDir, "bin");

		try {
			await Bun.write(sourceBinary, "#!/bin/sh\necho 'reverse/18.11.2'\n");
			await fs.chmod(sourceBinary, 0o755);

			// Initial install
			await runLocalInstall({ binary: sourceBinary, binDir: destDir, platform: "darwin" });

			// First re-install creates a backup
			const firstInstall = await runLocalInstall({ binary: sourceBinary, binDir: destDir, platform: "darwin" });
			const firstBackup = firstInstall.backupPath!;
			expect(await fs.exists(firstBackup)).toBe(true);
			await Bun.write(firstBackup, "first-backup-content");

			// Second re-install creates another backup
			const secondInstall = await runLocalInstall({ binary: sourceBinary, binDir: destDir, platform: "darwin" });
			const secondBackup = secondInstall.backupPath!;
			expect(await fs.exists(secondBackup)).toBe(true);

			// First backup content must remain untouched
			const firstContent = await Bun.file(firstBackup).text();
			expect(firstContent).toBe("first-backup-content");
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test.skipIf(process.platform !== "win32")(
		"Windows 同源同目标重装保留原程序备份",
		async () => {
			const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-same-path-"));
			try {
				const source = path.join(tempDir, "fixture.ts");
				const target = path.join(tempDir, "reverse.exe");
				await fs.writeFile(source, 'console.log("reverse/18.11.2");\n');
				const build = await Bun.build({ entrypoints: [source], compile: { outfile: target } });
				if (!build.success) throw new Error("无法编译安装验证程序");
				const expected = await Bun.file(target).bytes();
				const result = await runLocalInstall({ binary: target, binDir: tempDir });
				expect(result.success).toBe(true);
				expect(result.version).toBe("18.11.2");
				expect(result.backupPath).toBeDefined();
				expect(await Bun.file(target).bytes()).toEqual(expected);
				expect(await Bun.file(result.backupPath!).bytes()).toEqual(expected);
			} finally {
				await fs.rm(tempDir, { recursive: true, force: true });
			}
		},
		30_000,
	);

	test.skipIf(process.platform !== "win32")(
		"Windows 运行中 reverse.exe 持锁时默认备份与 --no-backup 覆盖安装均成功且保持原进程存活",
		async () => {
			const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-win-held-"));
			let heldProc1: Subprocess | undefined;
			let heldProc2: Subprocess | undefined;
			try {
				const sourceV1 = path.join(tempDir, "fixture-v1.ts");
				const sourceV2 = path.join(tempDir, "fixture-v2.ts");
				const target = path.join(tempDir, "reverse.exe");
				const stagedV2 = path.join(tempDir, "reverse-v2.exe");
				await fs.writeFile(
					sourceV1,
					'if (process.argv.includes("--version")) { console.log("reverse/18.11.1"); process.exit(0); }\nconsole.log("READY");\nsetInterval(() => {}, 1000);\n',
				);
				await fs.writeFile(
					sourceV2,
					'if (process.argv.includes("--version")) { console.log("reverse/18.11.2"); process.exit(0); }\nconsole.log("READY");\nsetInterval(() => {}, 1000);\n',
				);
				const build1 = await Bun.build({ entrypoints: [sourceV1], compile: { outfile: target } });
				const build2 = await Bun.build({ entrypoints: [sourceV2], compile: { outfile: stagedV2 } });
				if (!build1.success || !build2.success) throw new Error("无法编译 Windows 持锁验证程序");

				// 1. Hold target reverse.exe open in a running subprocess
				heldProc1 = Bun.spawn([target, "--hold"], { stdout: "pipe", stderr: "pipe" });
				const reader1 = (heldProc1.stdout as ReadableStream<Uint8Array>).getReader();
				await reader1.read();
				reader1.releaseLock();
				expect(heldProc1.exitCode).toBeNull();

				// Default install with backup while target is held running
				const withBackup = await runLocalInstall({ binary: stagedV2, binDir: tempDir });
				expect(withBackup.success).toBe(true);
				expect(withBackup.version).toBe("18.11.2");
				expect(withBackup.backupPath).toBeDefined();
				expect(await fs.exists(withBackup.backupPath!)).toBe(true);
				expect(heldProc1.exitCode).toBeNull();

				// 2. Hold newly installed reverse.exe open and reinstall with --no-backup
				heldProc2 = Bun.spawn([target, "--hold"], { stdout: "pipe", stderr: "pipe" });
				const reader2 = (heldProc2.stdout as ReadableStream<Uint8Array>).getReader();
				await reader2.read();
				reader2.releaseLock();
				expect(heldProc2.exitCode).toBeNull();

				const noBackup = await runLocalInstall({ binary: stagedV2, binDir: tempDir, backup: false });
				expect(noBackup.success).toBe(true);
				expect(noBackup.version).toBe("18.11.2");
				expect(noBackup.backupPath).toBeUndefined();
				expect(heldProc2.exitCode).toBeNull();

				// 3. Release held process and verify unlocked --no-backup cleans up its .retired.* file
				heldProc2.kill();
				await heldProc2.exited;
				const beforeUnlocked = new Set(await fs.readdir(tempDir));
				const unlockedNoBackup = await runLocalInstall({ binary: stagedV2, binDir: tempDir, backup: false });
				expect(unlockedNoBackup.success).toBe(true);
				const afterUnlocked = await fs.readdir(tempDir);
				const addedRetired = afterUnlocked.filter(name => name.includes(".retired.") && !beforeUnlocked.has(name));
				expect(addedRetired).toEqual([]);
			} finally {
				for (const proc of [heldProc1, heldProc2]) {
					if (proc && proc.exitCode === null) {
						try {
							proc.kill();
							await proc.exited;
						} catch {}
					}
				}
				await fs.rm(tempDir, { recursive: true, force: true });
			}
		},
		60_000,
	);

	test("preserves target binary on same-source reinstall and honors --no-backup without leaving staging files", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-same-source-"));
		const targetBinary = path.join(tempDir, "reverse");

		try {
			const scriptContent = "#!/bin/sh\necho 'reverse/18.11.2'\n";
			await Bun.write(targetBinary, scriptContent);
			await fs.chmod(targetBinary, 0o755);

			// Same-source + same-target with backup enabled
			const withBackup = await runLocalInstall({
				binary: targetBinary,
				binDir: tempDir,
				platform: "darwin",
			});
			expect(withBackup.success).toBe(true);
			expect(withBackup.backupPath).toBeDefined();
			expect(await Bun.file(targetBinary).text()).toBe(scriptContent);
			expect(await Bun.file(withBackup.backupPath!).text()).toBe(scriptContent);

			// Same-source + same-target with --no-backup
			const noBackup = await runLocalInstall({
				binary: targetBinary,
				binDir: tempDir,
				backup: false,
				platform: "darwin",
			});
			expect(noBackup.success).toBe(true);
			expect(noBackup.backupPath).toBeUndefined();
			expect(await Bun.file(targetBinary).text()).toBe(scriptContent);
			const entries = await fs.readdir(tempDir);
			expect(entries.some(name => name.includes(".tmp."))).toBe(false);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("restores previous target binary when in-place verification fails after replacement", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-inplace-rollback-"));
		const sourceBinary = path.join(tempDir, "source-reverse");
		const destDir = path.join(tempDir, "bin");
		const targetBinary = path.join(destDir, "reverse");

		try {
			await fs.mkdir(destDir, { recursive: true });
			const originalScript = "#!/bin/sh\necho 'reverse/18.11.1'\n";
			await Bun.write(targetBinary, originalScript);
			await fs.chmod(targetBinary, 0o755);

			// Script passes when executed from sourceBinary path, fails when executed from targetBinary path
			const locationSensitiveScript =
				"#!/bin/sh\ncase \"$0\" in\n  *source-reverse) echo 'reverse/18.11.2'; exit 0 ;;\n  *) echo 'corrupted in target' >&2; exit 1 ;;\nesac\n";
			await Bun.write(sourceBinary, locationSensitiveScript);
			await fs.chmod(sourceBinary, 0o755);

			const result = await runLocalInstall({
				binary: sourceBinary,
				binDir: destDir,
				platform: "darwin",
			});
			expect(result.success).toBe(false);
			expect(result.message).toContain("failed in-place verification");
			expect(result.message).toContain("Restored previous binary");
			expect(await Bun.file(targetBinary).text()).toBe(originalScript);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});

	test("refuses to uninstall an unverified binary unless force is set", async () => {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "rev-install-uninstall-"));
		const destDir = path.join(tempDir, "bin");
		const targetBinary = path.join(destDir, "reverse");

		try {
			await fs.mkdir(destDir, { recursive: true });
			await Bun.write(targetBinary, "#!/bin/sh\necho 'foreign-tool 1.0.0'\n");
			await fs.chmod(targetBinary, 0o755);

			// Without force: should fail and preserve file
			const safeResult = await runLocalInstall({
				binDir: destDir,
				uninstall: true,
				platform: "darwin",
			});
			expect(safeResult.success).toBe(false);
			expect(safeResult.message).toContain("Refusing to uninstall");
			expect(await fs.exists(targetBinary)).toBe(true);

			// With force: should remove
			const forceResult = await runLocalInstall({
				binDir: destDir,
				uninstall: true,
				force: true,
				platform: "darwin",
			});
			expect(forceResult.success).toBe(true);
			expect(await fs.exists(targetBinary)).toBe(false);
		} finally {
			await fs.rm(tempDir, { recursive: true, force: true });
		}
	});
});
