import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { buildSubprocessEnv, canBuildTritonFromSource } from "../src/extensibility/triton-source-install";

describe("Triton native source-build helper", () => {
	let originalEnv: NodeJS.ProcessEnv;

	beforeEach(() => {
		originalEnv = { ...process.env };
	});

	afterEach(() => {
		for (const key of Object.keys(process.env)) {
			if (!(key in originalEnv)) {
				delete process.env[key];
			}
		}
		for (const [key, value] of Object.entries(originalEnv)) {
			if (value !== undefined) {
				process.env[key] = value;
			}
		}
	});

	describe("canBuildTritonFromSource prerequisite detection", () => {
		it("detects missing build tools and produces actionable diagnostics", () => {
			const mockWhich = (bin: string): string | null => {
				if (bin === "cmake") return null;
				if (bin === "ninja") return "/usr/bin/ninja";
				if (bin === "clang++") return "/usr/bin/clang++";
				if (bin === "python3") return "/usr/bin/python3";
				return null;
			};

			const check = canBuildTritonFromSource("darwin", "arm64", mockWhich);
			expect(check.supported).toBe(false);
			expect(check.missingPrereqs).toContain("cmake");
			expect(check.reason).toContain("Missing required build toolchain components");
		});

		it("reports supported with diagnostic guidance on complete macOS arm64 environment", () => {
			const mockWhich = (bin: string): string | null => {
				if (bin === "cmake") return "/opt/homebrew/bin/cmake";
				if (bin === "ninja") return "/opt/homebrew/bin/ninja";
				if (bin === "clang++") return "/usr/bin/clang++";
				if (bin === "python3") return "/opt/homebrew/bin/python3.12";
				return null;
			};

			const check = canBuildTritonFromSource("darwin", "arm64", mockWhich);
			expect(check.supported).toBe(true);
			expect(check.missingPrereqs).toHaveLength(0);
			expect(check.reason).toContain("macOS arm64");
			expect(check.tools.cmake).toBe("/opt/homebrew/bin/cmake");
			expect(check.tools.ninja).toBe("/opt/homebrew/bin/ninja");
			expect(check.tools.compiler).toBe("/usr/bin/clang++");
		});
	});

	describe("buildSubprocessEnv isolation", () => {
		it("cleans dangerous python variables and enforces PYTHONNOUSERSITE", () => {
			process.env.PYTHONPATH = "/some/poisoned/path";
			process.env.PYTHONHOME = "/some/other/home";
			process.env.SECRET_TOKEN = "supersecret";

			const sanitized = buildSubprocessEnv({ CC: "clang", CXX: "clang++" });
			expect(sanitized.PYTHONPATH).toBeUndefined();
			expect(sanitized.PYTHONHOME).toBeUndefined();
			expect(sanitized.PYTHONNOUSERSITE).toBe("1");
			expect(sanitized.CC).toBe("clang");
			expect(sanitized.CXX).toBe("clang++");
			expect(sanitized.SECRET_TOKEN).toBeUndefined();
		});
	});
});
