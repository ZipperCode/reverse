import { ToolError } from "@reverse/tui/tools/tool-errors";
import { Settings } from "../config/settings";
import type { ToolSession } from "../tools";
import { cfgIdaInstall, probeIdaPythonEnvironment } from "./install";
import { filterEnv } from "../eval/py/runtime";
import { cfgIdaPython } from "./settings";
/** Raised when no Python interpreter can load idalib (`ida_domain` + `idapro`). */
export class IdaUnavailableError extends ToolError {
	constructor(message: string) {
		super(message);
		this.name = "IdaUnavailableError";
	}
}

/** Interpreter and environment used to spawn IDA worker processes. */
export interface IdaRuntime {
	pythonPath: string;
	env: Record<string, string>;
}

const runtimes = new Map<string, Promise<IdaRuntime>>();

export function clearIdaRuntimeCache(): void {
	runtimes.clear();
}

/**
 * Resolve the Python interpreter that can import `ida_domain` and `idapro`, memoized per
 * (`ida.python`, install dir, cwd, worker environment). Throws {@link IdaUnavailableError} when IDA is disabled,
 * no install is found, or no interpreter qualifies.
 */
export async function resolveIdaRuntime(session: ToolSession): Promise<IdaRuntime> {
	const installDir = cfgIdaInstall.get(session.settings);
	if (!installDir) {
		return Promise.reject(
			new IdaUnavailableError("IDA unavailable: disabled (ida.enabled) or no IDA install with idalib found."),
		);
	}
	const python = cfgIdaPython.get(session.settings)?.trim() || undefined;
	const effectiveSettings = session.settings ?? (await Settings.init());
	const env = filterEnv(effectiveSettings.getShellConfig().env);
	const key = JSON.stringify([python, installDir, session.cwd, env]);
	const cached = runtimes.get(key);
	if (cached) return cached;
	const promise = probeIdaRuntime(python, installDir, session.cwd, effectiveSettings);
	runtimes.set(key, promise);
	promise.catch(() => {
		if (runtimes.get(key) === promise) runtimes.delete(key);
	});
	return promise;
}

async function probeIdaRuntime(
	python: string | undefined,
	installDir: string,
	cwd: string,
	settings?: Settings,
): Promise<IdaRuntime> {
	const shellConfig = (settings ?? (await Settings.init())).getShellConfig();
	const baseEnv = shellConfig.env;

	const probeRes = probeIdaPythonEnvironment({
		python,
		installDir,
		cwd,
		env: baseEnv,
		settings,
	});

	if (probeRes.success && probeRes.runtime) {
		return probeRes.runtime;
	}

	const selected = probeRes.selectedCandidate;
	const targetPython = selected?.pythonPath ?? (probeRes.candidates[0]?.pythonPath || "python");

	if (selected?.errorType === "missing_package" && probeRes.repairCommand) {
		const missing = selected.missingPackages?.join(", ") ?? "ida-domain";
		throw new IdaUnavailableError(
			`IDA unavailable: Python interpreter at "${targetPython}" is missing required packages (${missing}). Run "${probeRes.repairCommand.command}" to install ida-domain==0.5.1 into the Python runtime used by IDA, or set ida.python.`,
		);
	}

	if (selected?.errorType === "unsupported_python") {
		throw new IdaUnavailableError(
			`IDA unavailable: Python interpreter at "${targetPython}" (version ${selected.version ?? "unknown"}) is unsupported. ida-domain requires Python >= 3.10 and IDA >= 9.1. Set ida.python to a compatible Python >= 3.10 virtual environment or run idapyswitch.`,
		);
	}

	if (selected?.errorType === "import_error") {
		throw new IdaUnavailableError(
			`IDA unavailable: Python interpreter at "${targetPython}" encountered an error loading idalib: ${selected.error}. Verify IDA license, IDADIR, system runtime libraries, and idapyswitch configuration.`,
		);
	}
	if (selected?.errorType === "interpreter_unavailable") {
		throw new IdaUnavailableError(
			`IDA unavailable: Python interpreter at "${targetPython}" could not run the adapter probe: ${selected.error}. Verify ida.python and interpreter startup.`,
		);
	}

	const paths = probeRes.candidates.length > 0 ? probeRes.candidates.map(c => c.pythonPath).join(", ") : "none";
	throw new IdaUnavailableError(
		`IDA unavailable: no Python interpreter can import ida_domain and idapro (tried: ${paths}). Install ida-domain into the Python targeted by IDA's idapyswitch, or set ida.python.`,
	);
}
