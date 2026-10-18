import { $env } from "@rva/utils/env";
/** Return whether a bash tool call should use the local interactive PTY overlay. */
export function canUseInteractiveBashPty(pty, ctx) {
    if (!pty)
        return false;
    if ($env.RVA_NO_PTY === "1" || $env.PI_NO_PTY === "1")
        return false;
    return ctx?.hasUI === true && ctx.ui !== undefined;
}
