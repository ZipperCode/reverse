/**
 * Tern mode: when omp runs inside a Tern pane (Tern exports `TERN_PANE_SOCKET`
 * and `TERN_PANE` into every pane), browser tabs open as browser
 * picture-in-pictures floating over omp's own pane and every tab helper drives
 * that PiP's native web view through the Tern daemon (`wire.ts`).
 */
import { parseFlag } from "@rva/utils";
/** The Tern pane omp runs in, or null outside Tern (`TERN_PANE_SOCKET` unset or `TERN_PANE` not a block id). */
export function resolveTernPane(env = process.env) {
    const socketPath = env.TERN_PANE_SOCKET?.trim();
    const pane = env.TERN_PANE?.trim();
    if (!socketPath || !pane || !/^\d+$/.test(pane))
        return null;
    const id = Number(pane);
    if (!Number.isSafeInteger(id))
        return null;
    return { socketPath, pane: id };
}
/**
 * Resolve the Tern browser kind, or null when omp is not in a Tern pane or
 * Tern mode is off. Mirrors `resolveCmuxKind`: the setting opts in, the env
 * var is the final override in both directions.
 */
export function resolveTernKind(options, env = process.env) {
    if (!parseFlag(env.PI_BROWSER_TERN, options?.settingEnabled ?? true))
        return null;
    const pane = resolveTernPane(env);
    return pane && { kind: "tern", ...pane };
}
