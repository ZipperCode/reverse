import { buildEvalUrlRoots, LocalProtocolHandler } from "../internal-urls";
import { contextLocalProtocolOptions } from "../internal-urls/context";
/**
 * Resolve the on-disk roots that the eval helpers substitute for internal-URL
 * schemes from {@link contextLocalProtocolOptions}, resolved the way the
 * protocol handlers do, so an eval `write("local://x")` and a later
 * `read local://x` agree on the location. `local://` maps to its root;
 * `artifact://` maps to the session's artifacts dir, the dir `read artifact://<id>`
 * searches first, so `read("artifact://<id>")` returns the artifact's text.
 * A scheme is absent when its root does not resolve (read would fail the same way).
 */
export function resolveEvalUrlRoots(session) {
    const protocolOptions = contextLocalProtocolOptions(session);
    const options = LocalProtocolHandler.resolveOptions({ localProtocolOptions: protocolOptions });
    const roots = options ? buildEvalUrlRoots(options) : {};
    const artifactsDir = protocolOptions?.getArtifactsDir?.();
    if (artifactsDir)
        roots.artifact = artifactsDir;
    return roots;
}
