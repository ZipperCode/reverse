import { logger } from "@rva/utils";
import { runSharpshooterConsolidation } from "./consolidate";
import { readSharpshooterState, sharpshooterBankDir } from "./paths";
import { sharpshooterQueueDepth } from "./queue";
import { cfgSharpshooterIntervalMinutes } from "./settings";
const SCHEDULER_TICK_MS = 60000;
const schedulers = new Map();
export function startSharpshooterScheduler(options) {
    const bankDir = sharpshooterBankDir(options.agentDir, options.cwd);
    const existing = schedulers.get(bankDir);
    if (existing) {
        existing.refCount += 1;
        return createDisposer(bankDir, existing);
    }
    const tick = async () => {
        try {
            const [depth, state] = await Promise.all([
                sharpshooterQueueDepth(options.agentDir, options.cwd),
                readSharpshooterState(options.agentDir, options.cwd),
            ]);
            const intervalMinutes = cfgSharpshooterIntervalMinutes.get(options.settings);
            const due = Date.now() - state.lastConsolidatedAt >= intervalMinutes * 60000;
            if (depth === 0 && !due)
                return;
            await runSharpshooterConsolidation(options);
        }
        catch (error) {
            logger.debug("sharpshooter scheduler tick failed", {
                error: error instanceof Error ? error.message : String(error),
            });
        }
    };
    const timer = setInterval(() => void tick(), SCHEDULER_TICK_MS);
    timer.unref();
    const entry = { timer, refCount: 1 };
    schedulers.set(bankDir, entry);
    void tick();
    return createDisposer(bankDir, entry);
}
function createDisposer(bankDir, entry) {
    let disposed = false;
    return () => {
        if (disposed)
            return;
        disposed = true;
        const current = schedulers.get(bankDir);
        if (current !== entry)
            return;
        current.refCount -= 1;
        if (current.refCount > 0)
            return;
        clearInterval(current.timer);
        schedulers.delete(bankDir);
    };
}
