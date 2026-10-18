import { terminalLaunchProviders } from "./terminal-launch/providers";
import { processCli } from "./terminal-launch/shared";
import { validateRequest } from "./terminal-launch/validate";
export { terminalLaunchCapabilities } from "./terminal-launch/providers";
export * from "./terminal-launch/types";
export { createDefaultTerminalLaunchRequest, getTerminalLaunchPlacement } from "./terminal-launch/request";
/** Every supported provider's backend, keyed so a missing provider is a type error. */
const backends = terminalLaunchProviders;
function launchWith(multiplexer, request, context) {
    return backends[multiplexer].launch(request, context);
}
/**
 * Create a terminal pane or multiplexer group and run a command in it.
 * Provider-specific execution, targeting, environment, focus, and shell-input
 * behavior are described by the canonical capability map and in docs/extensions.md.
 */
export function createTerminalLauncher(dependencies = {}) {
    const runCli = dependencies.runCli ?? processCli;
    const environment = dependencies.environment ?? (() => process.env);
    const platform = dependencies.platform ?? process.platform;
    return async (request) => {
        validateRequest(request);
        return launchWith(request.multiplexer, request, { environment: environment(), platform, runCli });
    };
}
export const launchTerminal = createTerminalLauncher();
