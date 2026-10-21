import { afterEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { TempDir } from "@reverse/utils";
import { checkPythonSetup } from "../src/cli/setup-cli";
import { Settings } from "../src/config/settings";
import { restoreEnvValue } from "./helpers/settings-test-state";
const cliEntry = path.join(import.meta.dir, "..", "src", "cli.ts");

// An activated venv/conda env legitimately outranks the project `.venv`
// (docs/environment-variables.md: VIRTUAL_ENV, then CONDA_PREFIX, then
// `<cwd>/.venv`), so probes that assert on the project venv must not see one.
const ACTIVE_PYTHON_ENV_VARS = ["VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV"] as const;

interface CliProcessResult {
	exitCode: number;
	output: string;
	error: string;
}

async function runSetupPython(cwd: string): Promise<CliProcessResult> {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		NO_COLOR: "1",
		REVERSE_CODING_AGENT_DIR: path.join(cwd, "agent"),
	};
	delete env.VIRTUAL_ENV;
	delete env.CONDA_DEFAULT_ENV;
	delete env.CONDA_PREFIX;
	const proc = Bun.spawn([process.execPath, cliEntry, "setup", "python", "--json"], {
		cwd,
		stdout: "pipe",
		stderr: "pipe",
		env,
	});
	const output = new Response(proc.stdout).text();
	const error = new Response(proc.stderr).text();
	const [exitCode, stdout, stderr] = await Promise.all([proc.exited, output, error]);
	return { exitCode, output: stdout, error: stderr };
}

async function runSetup(cwd: string, ...setupArgs: string[]): Promise<CliProcessResult> {
	return runSetupWithEnv(cwd, {}, ...setupArgs);
}

async function runSetupWithEnv(
	cwd: string,
	extraEnv: NodeJS.ProcessEnv,
	...setupArgs: string[]
): Promise<CliProcessResult> {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		NO_COLOR: "1",
		REVERSE_CODING_AGENT_DIR: path.join(cwd, "agent"),
		...extraEnv,
	};
	const proc = Bun.spawn([process.execPath, cliEntry, "setup", ...setupArgs], {
		cwd,
		stdout: "pipe",
		stderr: "pipe",
		env,
	});
	const output = new Response(proc.stdout).text();
	const error = new Response(proc.stderr).text();
	const [exitCode, stdout, stderr] = await Promise.all([proc.exited, output, error]);
	return { exitCode, output: stdout, error: stderr };
}

/**
 * Hide any activated Python environment from the in-process probe for the
 * duration of a test. The resolver reads the live env (`resolveVenvPath`) and
 * the process-wide cached shell env (`Settings#getShellConfig().env`), so both
 * are covered. Returns the restore function; the spy is undone by
 * `vi.restoreAllMocks()` in `afterEach`.
 */
function hideActivePythonEnv(): () => void {
	const previous = new Map<string, string | undefined>(ACTIVE_PYTHON_ENV_VARS.map(name => [name, process.env[name]]));
	for (const name of ACTIVE_PYTHON_ENV_VARS) delete process.env[name];
	vi.spyOn(Settings.prototype, "getShellConfig").mockReturnValue({
		shell: "/bin/sh",
		args: ["-c"],
		env: { PATH: Bun.env.PATH ?? "", HOME: Bun.env.HOME ?? "" },
		prefix: undefined,
	});
	return () => {
		for (const [name, value] of previous) restoreEnvValue(name, value);
	};
}

describe("reverse setup python", () => {
	let projectDir: TempDir | undefined;

	afterEach(async () => {
		vi.restoreAllMocks();
		await projectDir?.remove();
		projectDir = undefined;
	});

	it.skipIf(process.platform === "win32")(
		"probes the project-configured interpreter instead of the PATH interpreter",
		async () => {
			projectDir = TempDir.createSync("@reverse-setup-python-");
			const cwd = projectDir.path();
			const interpreter = path.join(cwd, "configured-python");
			await Bun.write(interpreter, "#!/bin/sh\nexit 0\n");
			await fs.chmod(interpreter, 0o755);
			await Bun.write(path.join(cwd, ".reverse", "config.yml"), `python:\n  interpreter: ${interpreter}\n`);

			const result = await runSetupPython(cwd);

			expect(result.error).toBe("");
			expect(result.exitCode).toBe(0);
			expect(JSON.parse(result.output)).toMatchObject({
				available: true,
				pythonPath: interpreter,
				usingManagedEnv: false,
			});
		},
	);
	it.skipIf(process.platform === "win32")("prefers the project venv over the PATH interpreter", async () => {
		projectDir = TempDir.createSync("@reverse-setup-python-");
		const cwd = projectDir.path();
		const interpreter = path.join(cwd, ".venv", "bin", "python");
		await Bun.write(interpreter, "#!/bin/sh\nexit 0\n");
		await fs.chmod(interpreter, 0o755);

		const restoreEnv = hideActivePythonEnv();
		try {
			const result = await checkPythonSetup(cwd);

			expect(result).toMatchObject({
				available: true,
				pythonPath: interpreter,
				usingManagedEnv: false,
			});
		} finally {
			restoreEnv();
		}
	});
	it.skipIf(process.platform === "win32")("does not let the global probe bypass skip setup validation", async () => {
		projectDir = TempDir.createSync("@reverse-setup-python-");
		const cwd = projectDir.path();
		const interpreter = path.join(cwd, "configured-python");
		await Bun.write(interpreter, "#!/bin/sh\nexit 23\n");
		await fs.chmod(interpreter, 0o755);

		const previousSkipCheck = process.env.PI_PYTHON_SKIP_CHECK;
		process.env.PI_PYTHON_SKIP_CHECK = "1";
		try {
			const result = await checkPythonSetup(cwd, interpreter);
			expect(result).toMatchObject({
				available: false,
				pythonPath: interpreter,
				usingManagedEnv: false,
			});
		} finally {
			if (previousSkipCheck === undefined) delete process.env.PI_PYTHON_SKIP_CHECK;
			else process.env.PI_PYTHON_SKIP_CHECK = previousSkipCheck;
		}
	});
});

describe("reverse setup without a component", () => {
	let projectDir: TempDir | undefined;

	afterEach(async () => {
		await projectDir?.remove();
		projectDir = undefined;
	});

	// Regression: `setup --check --json` with no COMPONENT used to print USAGE to
	// stdout and exit 0, silently succeeding a machine-readable check and breaking
	// scripted `--json` health checks. It must now fail loudly on stderr.
	for (const flags of [["--check"], ["--json"]]) {
		it(`fails on stderr with a non-zero exit for ${["setup", ...flags].join(" ")}`, async () => {
			projectDir = TempDir.createSync("@reverse-setup-noarg-");
			const result = await runSetup(projectDir.path(), ...flags);

			expect(result.exitCode).not.toBe(0);
			expect(result.output).toBe("");
			expect(result.error).toContain("requires a COMPONENT");
		});
	}
});

describe("reverse setup unified 5-panel components", () => {
	let projectDir: TempDir | undefined;

	afterEach(async () => {
		await projectDir?.remove();
		projectDir = undefined;
	});

	it("handles setup providers --json", async () => {
		projectDir = TempDir.createSync("@reverse-setup-providers-");
		const result = await runSetup(projectDir.path(), "providers", "--json");
		expect(result.exitCode).toBe(0);
		const parsed = JSON.parse(result.output);
		expect(parsed.status).toBe("ok");
		expect(Array.isArray(parsed.providers)).toBe(true);
	});

	it("handles setup providers --check", async () => {
		projectDir = TempDir.createSync("@reverse-setup-providers-check-");
		const result = await runSetup(projectDir.path(), "providers", "--check");
		expect(result.exitCode).toBe(0);
		expect(result.output).toContain("Model Providers Setup Status");
	});

	it("handles setup add --json", async () => {
		projectDir = TempDir.createSync("@reverse-setup-add-");
		const result = await runSetup(projectDir.path(), "add", "--json");
		expect(result.exitCode).toBe(0);
		const parsed = JSON.parse(result.output);
		expect(typeof parsed.customProvidersCount).toBe("number");
		expect(Array.isArray(parsed.models)).toBe(true);
	});

	it("handles setup add --check", async () => {
		projectDir = TempDir.createSync("@reverse-setup-add-check-");
		const result = await runSetup(projectDir.path(), "add", "--check");
		expect(result.exitCode).toBe(0);
		expect(result.output).toContain("Custom Providers Setup Status");
	});

	it("fails on unknown component with error", async () => {
		projectDir = TempDir.createSync("@reverse-setup-invalid-");
		const result = await runSetup(projectDir.path(), "nonexistent_component");
		expect(result.exitCode).not.toBe(0);
	});
});
describe("reverse setup persisted locale in child process", () => {
	let projectDir: TempDir | undefined;

	afterEach(async () => {
		await projectDir?.remove();
		projectDir = undefined;
	});

	it("honors persisted language zh-CN without REVERSE_LANG in CLI subcommand", async () => {
		projectDir = TempDir.createSync("@reverse-setup-zh-");
		const cwd = projectDir.path();
		await Bun.write(path.join(cwd, ".reverse", "config.yml"), "language: zh-CN\n");

		const result = await runSetupWithEnv(cwd, { REVERSE_LANG: "" }, "reverse", "--check");
		expect(result.exitCode).toBe(0);
		expect(result.output).toContain("逆向工程工具链");
	});

	it("preserves explicit REVERSE_LANG override over persisted config in CLI subcommand", async () => {
		projectDir = TempDir.createSync("@reverse-setup-override-");
		const cwd = projectDir.path();
		await Bun.write(path.join(cwd, ".reverse", "config.yml"), "language: zh-CN\n");

		const result = await runSetupWithEnv(cwd, { REVERSE_LANG: "en" }, "reverse", "--check");
		expect(result.exitCode).toBe(0);
		expect(result.output).toContain("Reverse engineering toolchain");
	});
});
