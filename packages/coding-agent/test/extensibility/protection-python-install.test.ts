import { describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	findManagedTritonSitePackages,
	installFridaDexdump,
	installMsynth,
	installProtectionPythonTool,
} from "../../src/extensibility/protection-python-install";

const rejectingFetch: typeof globalThis.fetch = Object.assign(
	async () => {
		throw new Error("Network disabled in tests");
	},
	{ preconnect: globalThis.fetch.preconnect },
);

describe("protection-python-install authoritative pins & installer contracts", () => {
	it("transactional staging rolls back on failure without leaving corrupt artifacts", async () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_rollback_"));
		const targetDir = path.join(tempRoot, "tools", "frida-dexdump");
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "marker.txt"), "original-install-intact");

		// Simulate an executor that fails during pip install
		const failingExecutor = async (argv: readonly string[]) => {
			if (argv.some(a => a.includes("pip")) && argv.includes("install")) {
				return { exitCode: 1, stdout: "", stderr: "Network error fetching wheel" };
			}
			return { exitCode: 0, stdout: "ok", stderr: "" };
		};

		const result = await installFridaDexdump({
			agentDir: tempRoot,
			executor: failingExecutor,
			which: () => "/usr/bin/python3",
			fetch: rejectingFetch,
		});

		expect(result.success).toBe(false);
		expect(result.error).toContain("Network error fetching wheel");
		// Ensure staging cleanup and original install intact
		expect(fs.existsSync(targetDir)).toBe(true);
		expect(fs.readFileSync(path.join(targetDir, "marker.txt"), "utf-8")).toBe("original-install-intact");

		// Also verify fresh install failure cleans up targetDir without leaving corrupt artifacts
		const freshRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_rollback_fresh_"));
		const freshTarget = path.join(freshRoot, "tools", "frida-dexdump");
		const freshResult = await installFridaDexdump({
			agentDir: freshRoot,
			executor: failingExecutor,
			which: () => "/usr/bin/python3",
			fetch: rejectingFetch,
		});
		expect(freshResult.success).toBe(false);
		expect(fs.existsSync(freshTarget)).toBe(false);

		fs.rmSync(freshRoot, { recursive: true, force: true });
		fs.rmSync(tempRoot, { recursive: true, force: true });
	});
	it("preserves existing functional install when update fails", async () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_preserve_"));
		const targetDir = path.join(tempRoot, "tools", "frida-dexdump");
		fs.mkdirSync(targetDir, { recursive: true });
		fs.writeFileSync(path.join(targetDir, "marker.txt"), "original-version-intact");

		const failingExecutor = async () => {
			return { exitCode: 1, stdout: "", stderr: "Synthetic build error" };
		};

		const result = await installFridaDexdump({
			agentDir: tempRoot,
			executor: failingExecutor,
			which: () => "/usr/bin/python3",
			fetch: rejectingFetch,
		});

		expect(result.success).toBe(false);
		expect(fs.existsSync(targetDir)).toBe(true);
		expect(fs.readFileSync(path.join(targetDir, "marker.txt"), "utf-8")).toBe("original-version-intact");

		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("msynth non-git fallback handles download failure cleanly without crashes", async () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_msynth_fallback_"));
		const targetDir = path.join(tempRoot, "tools", "msynth");

		const mockExecutor = async (argv: readonly string[]) => {
			if (argv[0] === "git") {
				return { exitCode: 1, stdout: "", stderr: "git: command not found" };
			}
			return { exitCode: 0, stdout: "ok\n", stderr: "" };
		};
		const failingFetch = async () => new Response("Not found", { status: 404, statusText: "Not Found" });

		const result = await installMsynth({
			agentDir: tempRoot,
			executor: mockExecutor,
			which: (bin: string) => (bin === "git" ? null : "/usr/bin/python3"),
			fetch: failingFetch as unknown as typeof globalThis.fetch,
		});

		expect(result.success).toBe(false);
		expect(result.error).toBeDefined();
		// Assert failed, not ready, and no published artifacts
		expect(fs.existsSync(targetDir)).toBe(false);

		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("validates managed Triton site-packages ABI matching", () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_abi_"));
		const vmpBase = path.join(tempRoot, "tools", "vmp", "triton-venv", "lib");

		// Case 1: python3.11 with cpython-311 extension
		const py311Sp = path.join(vmpBase, "python3.11", "site-packages");
		fs.mkdirSync(py311Sp, { recursive: true });
		fs.mkdirSync(path.join(py311Sp, "triton_library-1.0.0rc4.dist-info"), { recursive: true });
		fs.writeFileSync(path.join(py311Sp, "triton.cpython-311-darwin.so"), "mock-311");

		// Requesting python3.12 should reject python3.11 site-packages
		const mismatched = findManagedTritonSitePackages(tempRoot, "python3.12");
		expect(mismatched).toBeNull();

		// Requesting python3.11 should accept it
		const matched = findManagedTritonSitePackages(tempRoot, "python3.11");
		expect(matched).toBe(py311Sp);

		// Case 2: python3.12 with matching cpython-312 extension
		const py312Sp = path.join(vmpBase, "python3.12", "site-packages");
		fs.mkdirSync(py312Sp, { recursive: true });
		fs.mkdirSync(path.join(py312Sp, "triton_library-1.0.0rc4.dist-info"), { recursive: true });
		fs.writeFileSync(path.join(py312Sp, "triton.cpython-312-darwin.so"), "mock-312");

		const matched312 = findManagedTritonSitePackages(tempRoot, "python3.12");
		expect(matched312).toBe(py312Sp);

		fs.rmSync(tempRoot, { recursive: true, force: true });
	});

	it("dispatcher supports all approved python tools", async () => {
		const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rev_test_dispatch_"));
		const unsupported = await installProtectionPythonTool("unknown-tool", { agentDir: tempRoot });
		expect(unsupported.success).toBe(false);
		expect(unsupported.error).toContain("Unsupported Python protection tool");

		fs.rmSync(tempRoot, { recursive: true, force: true });
	});
});
