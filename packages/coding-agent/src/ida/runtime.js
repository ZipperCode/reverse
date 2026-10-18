import { $env, logger } from "@rva/utils";
import { ToolError } from "@rva/tui/tools/tool-errors";
import { $ } from "bun";
import { Settings } from "../config/settings";
import { enumeratePythonRuntimes, filterEnv, resolveExplicitPythonRuntime, } from "../eval/py/runtime";
import { cfgIdaInstall } from "./install";
import { cfgIdaPython } from "./settings";
/** Raised when no Python interpreter can load idalib (`ida_domain` + `idapro`). */
export class IdaUnavailableError extends ToolError {
    constructor(message) {
        super(message);
        this.name = "IdaUnavailableError";
    }
}
const PROBE = "import importlib.util as u,sys;sys.exit(0 if u.find_spec('ida_domain') and u.find_spec('idapro') else 3)";
const runtimes = new Map();
/**
 * Resolve the Python interpreter that can import `ida_domain` and `idapro`, memoized per
 * (`ida.python`, install dir, cwd). Throws {@link IdaUnavailableError} when IDA is disabled,
 * no install is found, or no interpreter qualifies.
 */
export function resolveIdaRuntime(session) {
    const installDir = cfgIdaInstall.get(session.settings);
    if (!installDir) {
        return Promise.reject(new IdaUnavailableError("IDA unavailable: disabled (ida.enabled) or no IDA install with idalib found."));
    }
    const python = cfgIdaPython.get(session.settings)?.trim() || undefined;
    const key = `${python ?? ""}\0${installDir}\0${session.cwd}`;
    const cached = runtimes.get(key);
    if (cached)
        return cached;
    const promise = probeIdaRuntime(python, installDir, session.cwd);
    runtimes.set(key, promise);
    promise.catch(() => {
        if (runtimes.get(key) === promise)
            runtimes.delete(key);
    });
    return promise;
}
async function probeIdaRuntime(python, installDir, cwd) {
    const baseEnv = filterEnv((await Settings.init()).getShellConfig().env);
    const candidates = python
        ? [resolveExplicitPythonRuntime(python, cwd, baseEnv)]
        : enumeratePythonRuntimes(cwd, baseEnv);
    for (const candidate of candidates) {
        if (await probeCandidate(candidate))
            return buildRuntime(candidate, installDir);
    }
    const paths = candidates.length > 0 ? candidates.map(c => c.pythonPath).join(", ") : "none";
    throw new IdaUnavailableError(`IDA unavailable: no Python interpreter can import ida_domain and idapro (tried: ${paths}). Install ida-domain into the Python targeted by IDA's idapyswitch, or set ida.python.`);
}
async function probeCandidate(candidate) {
    try {
        const result = await $ `${candidate.pythonPath} -c ${PROBE}`.env(candidate.env).quiet().nothrow();
        return result.exitCode === 0;
    }
    catch (error) {
        logger.debug("IDA python probe failed", { pythonPath: candidate.pythonPath, error });
        return false;
    }
}
function buildRuntime(candidate, installDir) {
    const env = {};
    for (const key in candidate.env) {
        const value = candidate.env[key];
        if (typeof value === "string")
            env[key] = value;
    }
    env.PYTHONUNBUFFERED = "1";
    env.PYTHONIOENCODING = "utf-8";
    env.IDADIR = installDir;
    const idaUsr = $env.IDAUSR;
    if (idaUsr)
        env.IDAUSR = idaUsr;
    return { pythonPath: candidate.pythonPath, env };
}
