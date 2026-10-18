/**
 * Browser relay mode: drive the user's own Chrome tabs through the local CDP
 * relay served by `omp browser-relay` (sibling `server.ts`/`bridge.ts`) plus
 * its companion extension (`packages/browser-relay`, installed via
 * `omp browser-relay install`). The relay impersonates Chrome's CDP discovery
 * endpoint, so beyond kind resolution the entire connected-browser machinery
 * (registry, tab supervisor, tab workers) applies unchanged.
 */
import { parseFlag } from "@rva/utils";
/** Default endpoint of the `omp-browser-relay` CLI. */
export const DEFAULT_RELAY_URL = "http://127.0.0.1:9234";
/**
 * Resolve the relay browser kind, or null when relay mode is disabled.
 * Mirrors `resolveCmuxKind`: the setting opts in, the env var is the final
 * override in both directions.
 */
export function resolveRelayKind(options, env = process.env) {
    if (!parseFlag(env.RVA_BROWSER_RELAY, options?.settingEnabled ?? false)) {
        return null;
    }
    const url = options?.url?.trim() || DEFAULT_RELAY_URL;
    return { kind: "relay", cdpUrl: url.replace(/\/+$/, "") };
}
