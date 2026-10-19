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
		expect(validateBinaryVersionOutput("omp/18.11.2").ok).toBe(false);
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
