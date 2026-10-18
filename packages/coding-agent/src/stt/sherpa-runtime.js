import { createRequire } from "node:module";
import * as os from "node:os";
import { resolveRuntimeModule } from "@rva/utils";
const SHERPA_PACKAGE = "sherpa-onnx-node";
/** Loads the nearest working source-workspace sherpa wrapper, including hoisted fallbacks. */
export function loadSourceSherpaRuntime(sourceUrl) {
    const sourceRequire = createRequire(sourceUrl);
    const nearestEntry = sourceRequire.resolve(SHERPA_PACKAGE);
    try {
        return createRequire(nearestEntry)(nearestEntry);
    }
    catch (error) {
        if (!(error instanceof Error && error.message.startsWith("Could not find sherpa-onnx-node. Tried"))) {
            throw error;
        }
        const platform = os.platform();
        const platformPackage = `sherpa-onnx-${platform === "win32" ? "win" : platform}-${os.arch()}`;
        for (const nodeModules of sourceRequire.resolve.paths(SHERPA_PACKAGE) ?? []) {
            if (!resolveRuntimeModule(nodeModules, platformPackage))
                continue;
            const entry = resolveRuntimeModule(nodeModules, SHERPA_PACKAGE);
            if (!entry || entry === nearestEntry)
                continue;
            try {
                return createRequire(entry)(entry);
            }
            catch (candidateError) {
                if (!(candidateError instanceof Error &&
                    candidateError.message.startsWith("Could not find sherpa-onnx-node. Tried"))) {
                    throw candidateError;
                }
            }
        }
        throw error;
    }
}
