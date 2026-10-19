import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { $which } from "@reverse/utils";
import type { SkillRequirementWhich } from "../extensibility/skill-requirements";
import { fridaDependency } from "./frida";

export interface FridaLiveDependencyStatus {
	id: "frida_live";
	available: boolean;
	pythonPath?: string;
	fridaVersion?: string;
	fridaCliPath?: string;
	installHint?: string;
	manualUrl?: string;
	error?: string;
}

let cachedDependencyStatus: FridaLiveDependencyStatus | null = null;

/**
 * Resolve candidate Python executable path for Frida.
 *
 * Precedence:
 * 1. Explicit env REVERSE_FRIDA_PYTHON or FRIDA_PYTHON
 * 2. Sibling Python in the directory of the resolved frida CLI / symlink
 * 3. Canonical reverse toolchain path (~/.local/share/reverse/toolchains/frida/bin/python)
 * 4. Generic PATH python3 / python
 */
export function resolveFridaPythonCandidates(which?: SkillRequirementWhich): string[] {
	const candidates: string[] = [];
	const resolveWhich = which ?? $which;

	// 1. Explicit environment variable
	const envPython = process.env.REVERSE_FRIDA_PYTHON || process.env.FRIDA_PYTHON;
	if (envPython && envPython.trim().length > 0) {
		candidates.push(path.resolve(envPython.trim()));
	}

	// 2. Sibling of resolved frida binary / symlink
	const dep = fridaDependency(resolveWhich);
	const fridaCli = dep.path ?? resolveWhich("frida");
	if (fridaCli) {
		try {
			const realCli = fs.realpathSync(fridaCli);
			const binDir = path.dirname(realCli);
			candidates.push(path.join(binDir, "python"));
			candidates.push(path.join(binDir, "python3"));
			if (process.platform === "win32") {
				candidates.push(path.join(binDir, "python.exe"));
			}
		} catch {
			// Ignore resolution failure
		}
	}

	// Also inspect ~/.local/bin/frida symlink directly if not already covered
	const localBinFrida = path.join(os.homedir(), ".local", "bin", "frida");
	if (fs.existsSync(localBinFrida)) {
		try {
			const realLocal = fs.realpathSync(localBinFrida);
			const binDir = path.dirname(realLocal);
			candidates.push(path.join(binDir, "python"));
			candidates.push(path.join(binDir, "python3"));
			if (process.platform === "win32") {
				candidates.push(path.join(binDir, "python.exe"));
			}
		} catch {
			// Ignore resolution failure
		}
	}

	// 3. Canonical reverse toolchain venv path
	const home = os.homedir();
	const isWin = process.platform === "win32";
	const pyName = isWin ? "python.exe" : "python";
	const binSub = isWin ? "Scripts" : "bin";

	candidates.push(path.join(home, ".local", "share", "reverse", "toolchains", "frida", binSub, pyName));
	candidates.push(path.join(home, ".local", "bin", pyName));

	// 4. Generic PATH pythons
	const pathPy3 = resolveWhich("python3");
	if (pathPy3) candidates.push(pathPy3);
	const pathPy = resolveWhich("python");
	if (pathPy) candidates.push(pathPy);

	// Filter unique non-empty existing paths or candidates
	const seen = new Set<string>();
	const result: string[] = [];
	for (const cand of candidates) {
		const normalized = path.normalize(cand);
		if (!seen.has(normalized)) {
			seen.add(normalized);
			result.push(normalized);
		}
	}
	return result;
}

/**
 * Probe Python candidate to verify `import frida` succeeds and retrieve version.
 */
async function probeCandidatePython(
	pythonPath: string,
	timeoutMs = 5000,
): Promise<{ ok: boolean; version?: string; error?: string }> {
	if (!fs.existsSync(pythonPath)) {
		return { ok: false, error: `File not found: ${pythonPath}` };
	}

	try {
		const child = Bun.spawn([pythonPath, "-c", "import frida; print(frida.__version__)"], {
			stdout: "pipe",
			stderr: "pipe",
			stdin: "ignore",
		});

		let timedOut = false;
		const timer = setTimeout(() => {
			timedOut = true;
			try {
				child.kill();
			} catch {}
		}, timeoutMs);

		const [stdoutBuf, stderrBuf, exitCode] = await Promise.all([
			new Response(child.stdout).arrayBuffer(),
			new Response(child.stderr).arrayBuffer(),
			child.exited,
		]);
		clearTimeout(timer);

		if (timedOut) {
			return { ok: false, error: `Probe timed out after ${timeoutMs}ms` };
		}

		const stdoutText = Buffer.from(stdoutBuf).toString("utf8").trim();
		const stderrText = Buffer.from(stderrBuf).toString("utf8").trim();

		if (exitCode === 0 && stdoutText.length > 0) {
			return { ok: true, version: stdoutText };
		}

		return {
			ok: false,
			error: stderrText || stdoutText || `Python exited with code ${exitCode}`,
		};
	} catch (err) {
		return { ok: false, error: String(err) };
	}
}

/**
 * Probe environment for Frida Python live worker capabilities.
 */
export async function probeFridaLiveDependency(
	which?: SkillRequirementWhich,
	options: { forceProbe?: boolean; timeoutMs?: number } = {},
): Promise<FridaLiveDependencyStatus> {
	if (!options.forceProbe && cachedDependencyStatus && cachedDependencyStatus.available) {
		return cachedDependencyStatus;
	}

	const resolveWhich = which ?? $which;
	const dep = fridaDependency(resolveWhich);
	const fridaCli = dep.path ?? resolveWhich("frida");
	const candidates = resolveFridaPythonCandidates(which);

	let lastError: string | undefined;

	for (const cand of candidates) {
		const probe = await probeCandidatePython(cand, options.timeoutMs ?? 5000);
		if (probe.ok && probe.version) {
			const status: FridaLiveDependencyStatus = {
				id: "frida_live",
				available: true,
				pythonPath: cand,
				fridaVersion: probe.version,
				...(fridaCli ? { fridaCliPath: fridaCli } : {}),
				manualUrl: "https://frida.re/docs/installation/",
			};
			cachedDependencyStatus = status;
			return status;
		}
		if (probe.error) {
			lastError = probe.error;
		}
	}

	const installHint =
		process.platform === "win32"
			? "py -m pip install --user frida frida-tools"
			: "pipx install frida-tools (or python3 -m pip install --user frida)";

	const failedStatus: FridaLiveDependencyStatus = {
		id: "frida_live",
		available: false,
		error: lastError || "No Python interpreter with the 'frida' package installed was found",
		installHint,
		manualUrl: "https://frida.re/docs/installation/",
		...(fridaCli ? { fridaCliPath: fridaCli } : {}),
	};
	cachedDependencyStatus = failedStatus;
	return failedStatus;
}
